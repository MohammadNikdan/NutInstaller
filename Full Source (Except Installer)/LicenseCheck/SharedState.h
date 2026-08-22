#pragma once
//
// SharedState.h - Cross-process, cross-bitness (32/64-bit) coordination so
// that only ONE instance among many MT4/MT5 charts/terminals ever performs
// a real network refresh at a time. See Constants.h for the exact object
// names shared across all instances.
//
// Security model (spec sections 6, 15, 16, 38-45, 55, 60):
//   - The named Mutex is the ONLY thing that provides real atomicity.
//   - The shared-memory structure is integrity-protected (HMAC-SHA256) so a
//     process that bypasses the mutex and writes raw bytes into the section
//     cannot make its forged state be silently trusted.
//   - Even a fully valid-looking "refresh in progress" is independently
//     re-checked against the OS (does the owner PID/process-start-time
//     still exist? has its heartbeat lapsed? has the absolute lease
//     expired?) before any other instance agrees to wait on it - a stale or
//     fake owner is never trusted, and Recovery (re-claiming) is always
//     possible instead of infinite blocking.
//   - This shared state is NEVER used to grant a license tier. It only
//     answers "is a real refresh happening right now" - the actual Tier is
//     always independently derived by each instance from the local,
//     server-signed license file (see LicenseProtocol.h).
//   - The HMAC key embedded in this DLL is not a defense against a fully
//     capable local reverse engineer (nothing at this privilege level can
//     be) - its purpose is to stop casual/accidental corruption and naive
//     tampering from being silently trusted, exactly as scoped in the spec.
//

#include <windows.h>
#include <cstdint>

#pragma pack(push, 1)
struct GlobalRefreshState
{
    uint32_t magic;
    uint32_t version;

    uint64_t generation;

    uint32_t ownerPid;
    uint64_t ownerProcessStartTimeFileTime; // raw FILETIME (100ns since 1601), for exact re-comparison

    uint64_t ownerNonce;

    uint64_t refreshStartedAtUnix;
    uint64_t lastAttemptStartedAtUnix;

    uint32_t attemptNumber;

    uint32_t state; // RefreshState

    uint64_t heartbeatTickMs; // GetTickCount64() at last heartbeat - monotonic, immune to wall-clock changes

    uint64_t stateSequence;

    uint8_t integrity[32]; // HMAC-SHA256 over every field above, in declaration order
};
#pragma pack(pop)

enum RefreshState : uint32_t
{
    REFRESH_STATE_IDLE        = 0,
    REFRESH_STATE_IN_PROGRESS = 1
};

class SharedCoordinator
{
public:
    SharedCoordinator();
    ~SharedCoordinator();

    // Creates/opens the mutex, shared memory section, and event. Returns
    // false only on unrecoverable OS-level failure (e.g. cannot create
    // shared memory at all) - callers should fall back to a local-only,
    // conservative behavior (still correct, just without cross-process
    // coordination) rather than fail the whole license check.
    bool Initialize();

    // Attempts to atomically claim ownership of a refresh, after first
    // confirming no OTHER instance genuinely already owns one. On success,
    // returns true and fills outGeneration/outOwnerNonce (used by
    // Heartbeat/PublishCompletion to prove continued ownership).
    bool TryClaimRefresh(uint64_t& outGeneration, uint64_t& outOwnerNonce);

    // Must be called periodically (see HEARTBEAT_INTERVAL_MS) by the
    // current owner while a refresh is genuinely in progress.
    void Heartbeat(uint64_t generation, uint64_t ownerNonce, uint32_t attemptNumber);

    // Releases ownership and wakes any waiters. Must be called exactly once
    // when a refresh concludes, success or final failure alike.
    void PublishCompletion(uint64_t generation, uint64_t ownerNonce);

    // True only if a DIFFERENT instance holds a state that passes every
    // liveness/identity/integrity check - i.e. genuinely safe to wait on.
    // False (including on any corrupt/stale/fake state) means the caller
    // should attempt TryClaimRefresh itself instead of waiting.
    bool IsGenuineRefreshInProgress();

    // Bounded wait for a change notification (new claim or completion).
    // Always returns after at most timeoutMs even with no signal.
    void WaitForChange(DWORD timeoutMs);

private:
    HANDLE m_mutex;
    HANDLE m_mapping;
    HANDLE m_event;
    GlobalRefreshState* m_state;
    bool m_initialized;

    bool AcquireMutex(DWORD timeoutMs);
    void ReleaseMutexHandle();

    // Returns false if magic/version/size/integrity don't check out - in
    // which case 'out' must not be trusted for anything.
    bool ReadStateSafely(GlobalRefreshState& out);
    void WriteStateSafely(GlobalRefreshState& state); // computes integrity + bumps sequence internally

    void ComputeIntegrity(const GlobalRefreshState& s, uint8_t out[32]);
    bool VerifyOwnerAlive(const GlobalRefreshState& s);

    static uint64_t GetOwnProcessStartTimeFileTime();
    static uint64_t NowUnixSeconds();
    static uint64_t NowTickMs();
    static uint64_t SecureRandom64();
};
