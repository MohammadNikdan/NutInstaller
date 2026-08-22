#include "SharedState.h"
#include "Constants.h"
#include <bcrypt.h>
#include <sddl.h>
#include <cstring>
#include <cwchar>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace
{
    // Not a defense against a fully capable local reverse engineer (nothing
    // embedded in this DLL can be - see the design note in SharedState.h).
    // Scoped purpose only: stop naive/accidental corruption of the shared
    // memory section from being silently trusted as a real refresh state.
    const unsigned char kIntegrityKey[32] = {
        0x4E, 0x75, 0x74, 0x72, 0x69, 0x63, 0x75, 0x6C,
        0x61, 0x2D, 0x52, 0x65, 0x66, 0x72, 0x65, 0x73,
        0x68, 0x2D, 0x43, 0x6F, 0x6F, 0x72, 0x64, 0x2D,
        0x76, 0x31, 0xA3, 0x5C, 0x91, 0x2E, 0x08, 0xF7
    };

    // Builds a DACL granting full control to the current process's own
    // user SID and to the local Administrators group only - deliberately
    // NOT world-writable, even though the object lives in the Global\
    // namespace (which only affects visibility across sessions, not who
    // may access it).
    bool BuildRestrictedSecurityAttributes(SECURITY_ATTRIBUTES& sa, PSECURITY_DESCRIPTOR& outSd)
    {
        outSd = nullptr;
        ZeroMemory(&sa, sizeof(sa));
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = FALSE;

        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;

        DWORD needed = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
        if (needed == 0) { CloseHandle(token); return false; }

        BYTE* buffer = new BYTE[needed];
        bool ok = GetTokenInformation(token, TokenUser, buffer, needed, &needed) != 0;
        CloseHandle(token);
        if (!ok) { delete[] buffer; return false; }

        PTOKEN_USER tokenUser = reinterpret_cast<PTOKEN_USER>(buffer);
        LPWSTR sidString = nullptr;
        bool sidOk = ConvertSidToStringSidW(tokenUser->User.Sid, &sidString) != 0;
        delete[] buffer;
        if (!sidOk) return false;

        wchar_t sddl[512];
        // D: DACL. (A;;GA;;;<user SID>) grants Generic All to this user.
        // (A;;GA;;;BA) grants Generic All to Built-in Administrators too,
        // so an elevated troubleshooting/support session can also inspect
        // or reset the state if ever genuinely necessary.
        int written = swprintf(sddl, _countof(sddl), L"D:(A;;GA;;;%ls)(A;;GA;;;BA)", sidString);
        if (written < 0) { LocalFree(sidString); return false; }
        LocalFree(sidString);

        ULONG sdSize = 0;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &outSd, &sdSize))
            return false;

        sa.lpSecurityDescriptor = outSd;
        return true;
    }
}

SharedCoordinator::SharedCoordinator()
    : m_mutex(nullptr), m_mapping(nullptr), m_event(nullptr), m_state(nullptr), m_initialized(false)
{
}

SharedCoordinator::~SharedCoordinator()
{
    if (m_state) UnmapViewOfFile(m_state);
    if (m_mapping) CloseHandle(m_mapping);
    if (m_event) CloseHandle(m_event);
    if (m_mutex) CloseHandle(m_mutex);
}

bool SharedCoordinator::Initialize()
{
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR sd = nullptr;
    bool haveSa = BuildRestrictedSecurityAttributes(sa, sd);
    SECURITY_ATTRIBUTES* saPtr = haveSa ? &sa : nullptr;

    m_mutex = CreateMutexW(saPtr, FALSE, SHARED_MUTEX_NAME);
    if (!m_mutex && GetLastError() == ERROR_ACCESS_DENIED)
    {
        // Another instance (possibly running as a different, already-
        // running user context) created it first with different security -
        // fall back to opening with synchronize+modify rights only.
        m_mutex = OpenMutexW(SYNCHRONIZE | MUTEX_MODIFY_STATE, FALSE, SHARED_MUTEX_NAME);
    }

    if (m_mutex)
    {
        m_mapping = CreateFileMappingW(
            INVALID_HANDLE_VALUE, saPtr, PAGE_READWRITE,
            0, sizeof(GlobalRefreshState), SHARED_MEMORY_NAME);
        if (!m_mapping && GetLastError() == ERROR_ACCESS_DENIED)
        {
            m_mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, SHARED_MEMORY_NAME);
        }
    }

    if (m_mapping)
    {
        m_state = reinterpret_cast<GlobalRefreshState*>(
            MapViewOfFile(m_mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(GlobalRefreshState)));
    }

    if (m_mutex && m_mapping && m_state)
    {
        m_event = CreateEventW(saPtr, TRUE /*manual reset*/, FALSE, SHARED_EVENT_NAME);
        if (!m_event && GetLastError() == ERROR_ACCESS_DENIED)
        {
            m_event = OpenEventW(EVENT_ALL_ACCESS, FALSE, SHARED_EVENT_NAME);
        }
    }

    if (sd) LocalFree(sd);

    m_initialized = (m_mutex != nullptr && m_mapping != nullptr && m_state != nullptr && m_event != nullptr);

    if (m_initialized)
    {
        // First-ever creator initializes the section to a well-formed IDLE
        // state (a freshly created file mapping is zero-filled, which is
        // NOT a valid magic/version, so without this every instance would
        // otherwise treat a brand new segment as "corrupt" - harmless, but
        // this way we start clean).
        if (AcquireMutex(5000))
        {
            GlobalRefreshState snapshot;
            if (!ReadStateSafely(snapshot))
            {
                GlobalRefreshState fresh;
                ZeroMemory(&fresh, sizeof(fresh));
                fresh.magic = SHARED_STATE_MAGIC;
                fresh.version = SHARED_STATE_VERSION;
                fresh.state = REFRESH_STATE_IDLE;
                fresh.generation = NowUnixSeconds();
                WriteStateSafely(fresh);
            }
            ReleaseMutexHandle();
        }
    }

    return m_initialized;
}

bool SharedCoordinator::AcquireMutex(DWORD timeoutMs)
{
    if (!m_mutex) return false;
    DWORD result = WaitForSingleObject(m_mutex, timeoutMs);
    // WAIT_ABANDONED means a previous owner crashed while holding the
    // mutex - the mutex itself is still perfectly valid to use going
    // forward (this is normal, documented Win32 behavior), we simply also
    // know to treat whatever state we find with extra suspicion, which
    // ReadStateSafely + VerifyOwnerAlive already does unconditionally.
    return result == WAIT_OBJECT_0 || result == WAIT_ABANDONED;
}

void SharedCoordinator::ReleaseMutexHandle()
{
    if (m_mutex) ReleaseMutex(m_mutex);
}

void SharedCoordinator::ComputeIntegrity(const GlobalRefreshState& s, uint8_t out[32])
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0)
    {
        ZeroMemory(out, 32);
        return;
    }

    BCRYPT_HASH_HANDLE hash = nullptr;
    size_t dataLen = offsetof(GlobalRefreshState, integrity); // everything before the integrity field itself
    if (BCryptCreateHash(alg, &hash, nullptr, 0,
        const_cast<PUCHAR>(kIntegrityKey), sizeof(kIntegrityKey), 0) >= 0)
    {
        BCryptHashData(hash, const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(&s)), static_cast<ULONG>(dataLen), 0);
        ULONG outLen = 32;
        BCryptFinishHash(hash, out, 32, 0);
        BCryptDestroyHash(hash);
    }
    else
    {
        ZeroMemory(out, 32);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
}

bool SharedCoordinator::ReadStateSafely(GlobalRefreshState& out)
{
    if (!m_state) return false;
    GlobalRefreshState snapshot;
    memcpy(&snapshot, m_state, sizeof(GlobalRefreshState)); // caller holds the mutex, so this is a clean read

    if (snapshot.magic != SHARED_STATE_MAGIC) return false;
    if (snapshot.version != SHARED_STATE_VERSION) return false;

    uint8_t expected[32];
    ComputeIntegrity(snapshot, expected);
    // Constant-time-ish compare - not strictly necessary here (this isn't a
    // remote timing-attack surface), but costs nothing to do properly.
    unsigned char diff = 0;
    for (int i = 0; i < 32; i++) diff |= (expected[i] ^ snapshot.integrity[i]);
    if (diff != 0) return false;

    out = snapshot;
    return true;
}

void SharedCoordinator::WriteStateSafely(GlobalRefreshState& state)
{
    if (!m_state) return;
    state.magic = SHARED_STATE_MAGIC;
    state.version = SHARED_STATE_VERSION;
    state.stateSequence += 1;
    ComputeIntegrity(state, state.integrity);
    memcpy(m_state, &state, sizeof(GlobalRefreshState)); // caller holds the mutex
}

bool SharedCoordinator::VerifyOwnerAlive(const GlobalRefreshState& s)
{
    if (s.state != REFRESH_STATE_IN_PROGRESS) return false;

    // Absolute lease/watchdog cap - regardless of anything else, a refresh
    // claimed longer ago than this is stale (spec section 17).
    uint64_t nowUnix = NowUnixSeconds();
    if (s.refreshStartedAtUnix == 0 || nowUnix < s.refreshStartedAtUnix) return false; // clock sanity
    if ((nowUnix - s.refreshStartedAtUnix) * 1000ULL > static_cast<uint64_t>(REFRESH_LEASE_MS)) return false;

    // Heartbeat freshness (monotonic tick count - immune to wall-clock
    // adjustments, unlike Unix time).
    uint64_t nowTick = NowTickMs();
    if (s.heartbeatTickMs == 0) return false;
    // GetTickCount64 can wrap only after ~584 million years, so no wraparound handling needed.
    if (nowTick < s.heartbeatTickMs) return false; // clock went backwards somehow - don't trust
    if ((nowTick - s.heartbeatTickMs) > static_cast<uint64_t>(OWNER_STALE_AFTER_MS)) return false;

    // Owner process identity: PID must exist AND its creation time must
    // match exactly what was recorded at claim time - this is what stops
    // an unrelated process that later reused the same PID from being
    // mistaken for the genuine owner.
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, s.ownerPid);
    if (!proc) return false; // process no longer exists (or we can't even query it) - treat as gone

    FILETIME creation, exitTime, kernelTime, userTime;
    bool timesOk = GetProcessTimes(proc, &creation, &exitTime, &kernelTime, &userTime) != 0;
    CloseHandle(proc);
    if (!timesOk) return false;

    ULARGE_INTEGER creationInt;
    creationInt.LowPart = creation.dwLowDateTime;
    creationInt.HighPart = creation.dwHighDateTime;
    if (creationInt.QuadPart != s.ownerProcessStartTimeFileTime) return false;

    return true;
}

bool SharedCoordinator::IsGenuineRefreshInProgress()
{
    if (!m_initialized) return false; // no cross-process coordination available - caller proceeds locally
    if (!AcquireMutex(5000)) return false; // could not even get the mutex - do not block on an unknown state

    GlobalRefreshState snapshot;
    bool valid = ReadStateSafely(snapshot);
    bool genuine = valid && VerifyOwnerAlive(snapshot);

    ReleaseMutexHandle();
    return genuine;
}

bool SharedCoordinator::TryClaimRefresh(uint64_t& outGeneration, uint64_t& outOwnerNonce)
{
    outGeneration = 0;
    outOwnerNonce = 0;
    if (!m_initialized) return false;
    if (!AcquireMutex(5000)) return false;

    GlobalRefreshState snapshot;
    bool valid = ReadStateSafely(snapshot);
    if (valid && VerifyOwnerAlive(snapshot))
    {
        // A different instance genuinely already owns this - do not claim.
        ReleaseMutexHandle();
        return false;
    }

    // Either idle, or the previous state was stale/corrupt/fake - claim it.
    GlobalRefreshState fresh;
    ZeroMemory(&fresh, sizeof(fresh));
    fresh.generation = valid ? (snapshot.generation + 1) : NowUnixSeconds();
    fresh.ownerPid = GetCurrentProcessId();
    fresh.ownerProcessStartTimeFileTime = GetOwnProcessStartTimeFileTime();
    fresh.ownerNonce = SecureRandom64();
    fresh.refreshStartedAtUnix = NowUnixSeconds();
    fresh.lastAttemptStartedAtUnix = fresh.refreshStartedAtUnix;
    fresh.attemptNumber = 0;
    fresh.state = REFRESH_STATE_IN_PROGRESS;
    fresh.heartbeatTickMs = NowTickMs();
    fresh.stateSequence = valid ? snapshot.stateSequence : 0;

    WriteStateSafely(fresh);
    ReleaseMutexHandle();

    if (m_event) { SetEvent(m_event); ResetEvent(m_event); } // pulse: wake anyone currently waiting to re-check

    outGeneration = fresh.generation;
    outOwnerNonce = fresh.ownerNonce;
    return true;
}

void SharedCoordinator::Heartbeat(uint64_t generation, uint64_t ownerNonce, uint32_t attemptNumber)
{
    if (!m_initialized) return;
    if (!AcquireMutex(2000)) return;

    GlobalRefreshState snapshot;
    if (ReadStateSafely(snapshot) &&
        snapshot.state == REFRESH_STATE_IN_PROGRESS &&
        snapshot.generation == generation &&
        snapshot.ownerNonce == ownerNonce &&
        snapshot.ownerPid == GetCurrentProcessId())
    {
        snapshot.heartbeatTickMs = NowTickMs();
        snapshot.lastAttemptStartedAtUnix = NowUnixSeconds();
        snapshot.attemptNumber = attemptNumber;
        WriteStateSafely(snapshot);
    }
    // If we're no longer recognized as the owner (e.g. another instance's
    // Recovery logic decided we were stale and reclaimed), silently do
    // nothing - our own retry loop will discover this via TryClaimRefresh
    // failing or the published state no longer matching us, and stop.

    ReleaseMutexHandle();
}

void SharedCoordinator::PublishCompletion(uint64_t generation, uint64_t ownerNonce)
{
    if (!m_initialized) return;
    if (!AcquireMutex(5000)) return;

    GlobalRefreshState snapshot;
    if (ReadStateSafely(snapshot) &&
        snapshot.generation == generation &&
        snapshot.ownerNonce == ownerNonce &&
        snapshot.ownerPid == GetCurrentProcessId())
    {
        snapshot.state = REFRESH_STATE_IDLE;
        snapshot.heartbeatTickMs = NowTickMs();
        WriteStateSafely(snapshot);
    }

    ReleaseMutexHandle();

    if (m_event) { SetEvent(m_event); ResetEvent(m_event); }
}

void SharedCoordinator::WaitForChange(DWORD timeoutMs)
{
    if (!m_initialized || !m_event)
    {
        Sleep(timeoutMs < WAITER_POLL_INTERVAL_MS ? timeoutMs : static_cast<DWORD>(WAITER_POLL_INTERVAL_MS));
        return;
    }
    WaitForSingleObject(m_event, timeoutMs);
}

uint64_t SharedCoordinator::GetOwnProcessStartTimeFileTime()
{
    FILETIME creation, exitTime, kernelTime, userTime;
    if (!GetProcessTimes(GetCurrentProcess(), &creation, &exitTime, &kernelTime, &userTime)) return 0;
    ULARGE_INTEGER v;
    v.LowPart = creation.dwLowDateTime;
    v.HighPart = creation.dwHighDateTime;
    return v.QuadPart;
}

uint64_t SharedCoordinator::NowUnixSeconds()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER v;
    v.LowPart = ft.dwLowDateTime;
    v.HighPart = ft.dwHighDateTime;
    // FILETIME is 100ns intervals since 1601-01-01; Unix epoch is 1970-01-01.
    const uint64_t EPOCH_DIFF_100NS = 116444736000000000ULL;
    return (v.QuadPart - EPOCH_DIFF_100NS) / 10000000ULL;
}

uint64_t SharedCoordinator::NowTickMs()
{
    return GetTickCount64();
}

uint64_t SharedCoordinator::SecureRandom64()
{
    uint64_t value = 0;
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RNG_ALGORITHM, nullptr, 0) >= 0)
    {
        BCryptGenRandom(alg, reinterpret_cast<PUCHAR>(&value), sizeof(value), 0);
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return value;
}
