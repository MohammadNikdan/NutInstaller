#define NUTRICULA_LICENSE_CHECK_EXPORTS
#include "NutriculaLicenseCheck.h"
#include "Constants.h"
#include "SharedState.h"
#include "LicenseProtocol.h"
#include "MachineIdBridge.h"
#include "Transport.h"

#include <windows.h>
#include <process.h>
#include <fstream>
#include <vector>
#include <atomic>
#include <thread>
#include <string>
#include <cstdio>

namespace
{
    // ---- The two state-machine variables (spec sections 1-4). Always
    //      accessed atomically; never any value outside the documented set. ----
    std::atomic<long> g_tier(TIER_FREE);       // default is always 1 (spec section 51)
    std::atomic<long> g_pending(PENDING_IDLE);

    std::atomic<bool> g_initialized(false);
    std::atomic<bool> g_workerRunning(false);
    HANDLE g_workerThread = nullptr;
    CRITICAL_SECTION g_workerLock;

    std::wstring g_dllDirectory;
    SharedCoordinator g_coordinator;

    // Best-effort, non-critical, in-process-only cooldown for the Tier-1
    // "stats ping" (spec's final paragraph) - deliberately NOT part of the
    // heavyweight cross-process coordination used for real license
    // refreshes, since duplicate stats pings from sibling processes are
    // harmless (they just each independently hit license_not_found
    // server-side, which is exactly the intended stats signal).
    std::atomic<long long> g_lastStatsPingUnix(0);

    void SetPending(long value)
    {
        g_pending.store(value);
    }

    // The ONLY place PENDING is ever copied to MAIN - enforces spec section
    // 3's exact transition table (only 1, 2, -10 may ever reach MAIN).
    void PublishStable(long stableValue)
    {
        if (stableValue == TIER_FREE || stableValue == TIER_LICENSED || stableValue == TIER_FAILED)
        {
            g_tier.store(stableValue);
        }
        // else: programming error elsewhere if reached - MAIN is left
        // untouched (spec section 52: MAIN must retain its previous stable
        // value if this ever happened, rather than corrupt it).
        SetPending(PENDING_IDLE);
    }

    std::wstring GetOwnModuleDirectory()
    {
        wchar_t path[MAX_PATH];
        HMODULE hModule = nullptr;
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&GetOwnModuleDirectory), &hModule);
        DWORD len = GetModuleFileNameW(hModule, path, MAX_PATH);
        if (len == 0 || len >= MAX_PATH) return L".";
        std::wstring full(path, len);
        size_t slash = full.find_last_of(L'\\');
        return (slash == std::wstring::npos) ? L"." : full.substr(0, slash);
    }

    bool ReadFileBytes(const std::wstring& path, std::string& outContent)
    {
        std::ifstream file(path.c_str(), std::ios::binary);
        if (!file) return false;
        outContent.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
        return !outContent.empty();
    }

    // Atomic replace (spec sections 46-47): write to a temp file in the
    // SAME directory, flush, close, then MoveFileExW with
    // MOVEFILE_REPLACE_EXISTING - which performs an atomic rename on the
    // same volume. The original file is only ever touched by this final
    // atomic step, so a failure at any earlier point leaves it fully intact.
    bool WriteFileAtomic(const std::wstring& path, const std::string& content)
    {
        std::wstring tempPath = path + L".nutricula_tmp";
        {
            std::ofstream out(tempPath.c_str(), std::ios::binary | std::ios::trunc);
            if (!out) return false;
            out.write(content.data(), static_cast<std::streamsize>(content.size()));
            out.flush();
            if (!out) return false;
        }
        // FlushFileBuffers for real durability (not just C++ stream flush).
        HANDLE h = CreateFileW(tempPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) { FlushFileBuffers(h); CloseHandle(h); }

        bool ok = MoveFileExW(tempPath.c_str(), path.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
        if (!ok) DeleteFileW(tempPath.c_str()); // best-effort cleanup; original file is untouched either way
        return ok;
    }

    long long NowUnix()
    {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER v;
        v.LowPart = ft.dwLowDateTime;
        v.HighPart = ft.dwHighDateTime;
        const unsigned long long EPOCH_DIFF_100NS = 116444736000000000ULL;
        return static_cast<long long>((v.QuadPart - EPOCH_DIFF_100NS) / 10000000ULL);
    }

    unsigned long long SecureRandomBelow(unsigned long long bound)
    {
        // Spec section 13/22: unpredictable delay must use a real CSPRNG,
        // never rand()/srand()/time-seeded pseudo-random.
        BCRYPT_ALG_HANDLE alg = nullptr;
        unsigned long long value = 0;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RNG_ALGORITHM, nullptr, 0) >= 0)
        {
            BCryptGenRandom(alg, reinterpret_cast<PUCHAR>(&value), sizeof(value), 0);
            BCryptCloseAlgorithmProvider(alg, 0);
        }
        return bound == 0 ? 0 : (value % bound);
    }

    std::string GenerateRandomNumberField()
    {
        // 32-digit decimal random number, matching the installer's
        // rnd_number convention for this same protocol.
        std::string s;
        s.reserve(32);
        for (int i = 0; i < 32; i++) s.push_back(static_cast<char>('0' + SecureRandomBelow(10)));
        return s;
    }

    // ---- Local file evaluation result ----
    struct LocalFileState
    {
        bool fileExists = false;
        bool fileValid = false;       // decrypted + signature-verified successfully
        bool hasLease = false;        // valid AND contains a real Tier-2 lease (not just a reject reason on file)
        VerifiedLease lease;
        long long requestedAt = 0;    // from the verified content, whatever kind it was
        bool licenseCurrentlyExpired = false;
    };

    LocalFileState EvaluateLocalFile()
    {
        LocalFileState state;
        std::wstring path;
        if (!MachineIdBridge::GetLicenseFilePath(path)) return state;

        std::string raw;
        if (!ReadFileBytes(path, raw)) return state;
        state.fileExists = true;

        ParsedResponse parsed = LicenseProtocol::DecryptAndVerify(raw);
        if (parsed.kind == ResponseKind::Invalid) return state; // spec section 36: not trusted

        // Spec section 34: the file may exist and be perfectly VALID/
        // signed, yet still not contain a Tier-2 lease (e.g. it holds a
        // signed record of a past license_not_found/too_early/etc). Only a
        // genuine ResponseKind::Lease counts as "has a license".
        if (parsed.kind == ResponseKind::Lease)
        {
            state.fileValid = true;
            state.hasLease = true;
            state.lease = parsed.lease;
            state.requestedAt = static_cast<long long>(parsed.lease.requestedAt);
            long long nowUnix = NowUnix();
            state.licenseCurrentlyExpired = (static_cast<long long>(parsed.lease.licenseExpiresAt) <= nowUnix);
        }
        else
        {
            // A validly-signed rejection/no-lease record - still tells us
            // WHEN the last request happened, just not a license.
            state.fileValid = true;
            state.hasLease = false;
            // No requestedAt available from a plain "no"/reject envelope in
            // general (only structured lease responses carry it in this
            // protocol) - treat as "unknown, assume refresh is due" by
            // leaving requestedAt at 0.
        }
        return state;
    }

    // SECURITY/RELIABILITY FIX (Phase 1, confirmed by direct inspection):
    // OWNER_STALE_AFTER_MS (20000) is SHORTER than the HTTP timeout used for
    // each challenge/verify call (30000). Heartbeat() was previously only
    // called right before starting an HTTP call, never during one - so a
    // genuinely healthy request that legitimately takes close to 30s could
    // make a waiting instance decide the real owner is stale and attempt
    // takeover, even though nothing is actually wrong. This RAII helper
    // keeps heartbeating on a background thread for the entire lifetime of
    // an owned refresh (construction to destruction), including while an
    // HTTP call is in flight, so the watchdog's staleness check always sees
    // a live owner during normal operation. This is a self-contained fix
    // that does not depend on the larger Service/Broker migration.
    class HeartbeatPump
    {
    public:
        HeartbeatPump(uint64_t generation, uint64_t ownerNonce, std::atomic<uint32_t>& attemptRef)
            : m_generation(generation), m_ownerNonce(ownerNonce), m_attempt(attemptRef), m_stop(false)
        {
            m_thread = std::thread([this]() {
                // Beat at roughly half the configured interval so a
                // scheduling delay on this thread never by itself pushes a
                // gap past HEARTBEAT_INTERVAL_MS.
                const DWORD sliceMs = static_cast<DWORD>(HEARTBEAT_INTERVAL_MS / 2);
                while (!m_stop.load())
                {
                    g_coordinator.Heartbeat(m_generation, m_ownerNonce, m_attempt.load());
                    for (DWORD waited = 0; waited < sliceMs && !m_stop.load(); waited += 50)
                        Sleep(50);
                }
            });
        }
        ~HeartbeatPump()
        {
            m_stop.store(true);
            if (m_thread.joinable()) m_thread.join();
        }
        HeartbeatPump(const HeartbeatPump&) = delete;
        HeartbeatPump& operator=(const HeartbeatPump&) = delete;
    private:
        uint64_t m_generation;
        uint64_t m_ownerNonce;
        std::atomic<uint32_t>& m_attempt;
        std::atomic<bool> m_stop;
        std::thread m_thread;
    };

    // ---- The full background refresh (owner path): retry loop, atomic
    //      save, re-verification, publish. Runs ONLY after this instance
    //      has genuinely claimed the global refresh. Persists the RAW
    //      server envelope bytes to disk (not a locally reconstructed
    //      approximation), so any future reader always re-verifies exactly
    //      what the server actually signed (spec sections 32-33, 46-48). ----
    void RunOwnedRefresh(uint64_t generation, uint64_t ownerNonce, const std::string& licenseIdForRequest)
    {
        std::string machineId, deviceKeyHash;
        if (!MachineIdBridge::GenerateMachineId(machineId) || !MachineIdBridge::GetDeviceKeyHash(deviceKeyHash))
        {
            g_coordinator.PublishCompletion(generation, ownerNonce);
            PublishStable(TIER_FAILED);
            return;
        }

        const std::wstring host = L"nutriculaexpert.com";
        const std::wstring urlPath = L"/license_validator_phps/license_check.php";
        long finalStable = TIER_FAILED;

        std::atomic<uint32_t> currentAttempt(0);
        HeartbeatPump heartbeatPump(generation, ownerNonce, currentAttempt); // beats continuously until this goes out of scope, including during in-flight HTTP calls

        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++)
        {
            SetPending(PENDING_COMM_FAIL_RETRYING);
            currentAttempt.store(static_cast<uint32_t>(attempt));

            // --- challenge ---
            std::map<std::string, std::string> challengeFields;
            challengeFields["v"] = "3";
            challengeFields["stage"] = "challenge";
            challengeFields["license_id"] = licenseIdForRequest;
            challengeFields["machine_id"] = machineId;
            challengeFields["device_key_hash"] = deviceKeyHash;
            std::string challengeEnvelope = LicenseProtocol::BuildRequestEnvelope(challengeFields);

            bool advance = true;
            ParsedResponse challengeParsed;
            if (challengeEnvelope.empty()) advance = false;
            if (advance)
            {
                TransportResponse r = Transport::PostEnvelope(host, urlPath, challengeEnvelope, 30000);
                if (r.result != TransportResult::Ok) advance = false;
                else
                {
                    challengeParsed = LicenseProtocol::DecryptAndVerify(r.body);
                    if (challengeParsed.kind == ResponseKind::Invalid || challengeParsed.kind == ResponseKind::LegacyNo)
                        advance = false;
                }
            }

            if (advance && challengeParsed.kind == ResponseKind::Rejected)
            {
                finalStable = TIER_FREE;
                break;
            }
            if (advance && challengeParsed.kind != ResponseKind::Challenge) advance = false;

            if (!advance)
            {
                if (attempt < MAX_ATTEMPTS) Sleep(2000);
                continue;
            }

            // --- sign + verify ---
            std::string message =
                "NUTRICULA-RUNTIME-V3|challenge_id=" + challengeParsed.challenge.challengeId +
                "|nonce=" + challengeParsed.challenge.nonceB64 +
                "|license_id=" + licenseIdForRequest +
                "|machine_id=" + machineId;

            std::string signatureB64;
            if (!MachineIdBridge::SignChallenge(message, signatureB64))
            {
                if (attempt < MAX_ATTEMPTS) Sleep(2000);
                continue;
            }

            std::map<std::string, std::string> verifyFields;
            verifyFields["v"] = "3";
            verifyFields["stage"] = "verify";
            verifyFields["license_id"] = licenseIdForRequest;
            verifyFields["machine_id"] = machineId;
            verifyFields["device_key_hash"] = deviceKeyHash;
            verifyFields["challenge_id"] = challengeParsed.challenge.challengeId;
            verifyFields["signature"] = signatureB64;
            std::string verifyEnvelope = LicenseProtocol::BuildRequestEnvelope(verifyFields);

            TransportResponse verifyResp = Transport::PostEnvelope(host, urlPath, verifyEnvelope, 30000);
            if (verifyResp.result != TransportResult::Ok)
            {
                if (attempt < MAX_ATTEMPTS) Sleep(2000);
                continue;
            }

            ParsedResponse verifyParsed = LicenseProtocol::DecryptAndVerify(verifyResp.body);
            if (verifyParsed.kind == ResponseKind::Invalid || verifyParsed.kind == ResponseKind::LegacyNo)
            {
                if (attempt < MAX_ATTEMPTS) Sleep(2000);
                continue;
            }
            if (verifyParsed.kind == ResponseKind::Rejected)
            {
                finalStable = TIER_FREE;
                break;
            }
            if (verifyParsed.kind != ResponseKind::Lease)
            {
                if (attempt < MAX_ATTEMPTS) Sleep(2000);
                continue;
            }

            // Got a genuine Tier-2 lease. Persist the RAW server bytes
            // (verifyResp.body is exactly the "N3:..." envelope the server
            // sent - already proven, above, to decrypt+verify successfully)
            // atomically, then re-read/re-verify from disk before trusting
            // Tier 2 (spec section 48's full chain).
            std::wstring path;
            if (!MachineIdBridge::GetLicenseFilePath(path))
            {
                if (attempt < MAX_ATTEMPTS) Sleep(2000);
                continue;
            }
            if (!WriteFileAtomic(path, verifyResp.body))
            {
                // Spec section 47: failure to save must never corrupt the
                // PREVIOUS file - WriteFileAtomic only ever touches the
                // original via one atomic rename, so it's already safe;
                // just retry the cycle.
                if (attempt < MAX_ATTEMPTS) Sleep(2000);
                continue;
            }

            std::string reReadRaw;
            if (!ReadFileBytes(path, reReadRaw))
            {
                if (attempt < MAX_ATTEMPTS) Sleep(2000);
                continue;
            }
            ParsedResponse reVerified = LicenseProtocol::DecryptAndVerify(reReadRaw);
            if (reVerified.kind != ResponseKind::Lease)
            {
                if (attempt < MAX_ATTEMPTS) Sleep(2000);
                continue;
            }

            finalStable = TIER_LICENSED;
            break;
        }

        g_coordinator.PublishCompletion(generation, ownerNonce);
        PublishStable(finalStable);
    }

    // ---- Best-effort, non-blocking Tier-1 usage stats ping (spec's final
    //      paragraph). Never affects timing/coordination of real refreshes,
    //      never blocks, failure is silently ignored - this is purely
    //      informational on the server side (see nutricula_unlicensed_checkins). ----
    void MaybeSendStatsPing()
    {
        long long now = NowUnix();
        long long last = g_lastStatsPingUnix.load();
        if (last != 0 && (now - last) < MIN_REQUEST_INTERVAL_SEC) return;
        g_lastStatsPingUnix.store(now);

        std::string machineId, deviceKeyHash;
        if (!MachineIdBridge::GenerateMachineId(machineId)) return;
        if (!MachineIdBridge::GetDeviceKeyHash(deviceKeyHash)) return;

        // A syntactically-valid but never-real UUID, purely to satisfy the
        // protocol's required license_id field for this endpoint - the
        // expected (and only possible) outcome is reason=license_not_found,
        // which is exactly what drives the server-side stats table. The
        // response itself is discarded either way; Tier is already 1
        // regardless of what comes back.
        const std::string placeholderLicenseId = "00000000-0000-4000-8000-000000000000";

        std::map<std::string, std::string> fields;
        fields["v"] = "3";
        fields["stage"] = "challenge";
        fields["license_id"] = placeholderLicenseId;
        fields["machine_id"] = machineId;
        fields["device_key_hash"] = deviceKeyHash;

        std::string envelope = LicenseProtocol::BuildRequestEnvelope(fields);
        if (envelope.empty()) return;

        Transport::PostEnvelope(L"nutriculaexpert.com", L"/license_validator_phps/license_check.php", envelope, 15000);
        // Response deliberately ignored - see comment above.
    }

    unsigned __stdcall WorkerThreadProc(void*)
    {
        LocalFileState local = EvaluateLocalFile();
        long long now = NowUnix();

        bool withinCooldown = local.fileValid && local.hasLease &&
            !local.licenseCurrentlyExpired &&
            local.requestedAt != 0 &&
            (now - local.requestedAt) < MIN_REQUEST_INTERVAL_SEC;

        if (withinCooldown)
        {
            SetPending(TIER_LICENSED);
            PublishStable(TIER_LICENSED);
            g_workerRunning.store(false);
            return 0;
        }

        if (local.fileValid && !local.hasLease && !local.fileExists == false)
        {
            // A validly-signed record exists but holds no lease (e.g. a
            // saved rejection) - spec section 49 second paragraph: still
            // Tier 1 immediately, no refresh needed for THIS specific
            // sub-case if we don't have independent timing to check against.
            // (In practice this local-file shape is rare given the
            // installer now only ever writes genuine leases - see the
            // earlier hardening round - but handled here for completeness.)
        }

        if (local.hasLease && local.licenseCurrentlyExpired)
        {
            // Spec section 34/51: overall license expiry -> Tier 1,
            // regardless of the lease cycle timing.
            SetPending(TIER_FREE);
            PublishStable(TIER_FREE);
            MaybeSendStatsPing();
            g_workerRunning.store(false);
            return 0;
        }

        if (!local.fileExists || !local.fileValid)
        {
            // No usable identity to refresh against at all - Tier 1, plus
            // the best-effort stats ping. No point attempting a real
            // challenge/verify cycle without a license_id from a
            // previously-issued lease.
            SetPending(TIER_FREE);
            PublishStable(TIER_FREE);
            MaybeSendStatsPing();
            g_workerRunning.store(false);
            return 0;
        }

        // A refresh is genuinely due. Check global coordination first.
        for (;;)
        {
            if (g_coordinator.IsGenuineRefreshInProgress())
            {
                SetPending(PENDING_REFRESH_IN_PROGRESS);
                g_coordinator.WaitForChange(static_cast<DWORD>(WAITER_POLL_INTERVAL_MS));

                LocalFileState reCheck = EvaluateLocalFile();
                long long nowInner = NowUnix();
                if (reCheck.hasLease && !reCheck.licenseCurrentlyExpired &&
                    reCheck.requestedAt != 0 && (nowInner - reCheck.requestedAt) < MIN_REQUEST_INTERVAL_SEC)
                {
                    SetPending(TIER_LICENSED);
                    PublishStable(TIER_LICENSED);
                    g_workerRunning.store(false);
                    return 0;
                }
                continue; // still not resolved - loop: re-check coordination state
            }

            uint64_t generation = 0, ownerNonce = 0;
            if (g_coordinator.TryClaimRefresh(generation, ownerNonce))
            {
                SetPending(PENDING_REFRESH_IN_PROGRESS);

                // Random delay so this exact instant isn't identical across
                // every waiting instance the moment they're all released
                // together (spec section 22/24) - measured from THIS
                // license's own last known request time, not from "now",
                // so the schedule is anchored to the real cycle.
                long long anchor = local.hasLease ? local.requestedAt : now;
                long long target = anchor + MIN_REQUEST_INTERVAL_SEC + static_cast<long long>(SecureRandomBelow(RANDOM_DELAY_MAX_SEC + 1));
                long long waitSeconds = target - NowUnix();
                if (waitSeconds > 0)
                {
                    // Wait in small slices, heartbeating throughout, so a
                    // long wait doesn't look like a stalled/stale owner to
                    // sibling instances.
                    long long remainingMs = waitSeconds * 1000;
                    while (remainingMs > 0)
                    {
                        DWORD slice = static_cast<DWORD>(remainingMs > HEARTBEAT_INTERVAL_MS ? HEARTBEAT_INTERVAL_MS : remainingMs);
                        Sleep(slice);
                        remainingMs -= slice;
                        g_coordinator.Heartbeat(generation, ownerNonce, 0);
                    }
                }

                std::string licenseIdForRequest = local.hasLease ? local.lease.licenseId : std::string();
                if (licenseIdForRequest.empty())
                {
                    // Should not normally happen here (we only reach this
                    // branch when local.hasLease was true), but guard
                    // anyway rather than send a malformed request.
                    g_coordinator.PublishCompletion(generation, ownerNonce);
                    PublishStable(TIER_FAILED);
                    g_workerRunning.store(false);
                    return 0;
                }

                RunOwnedRefresh(generation, ownerNonce, licenseIdForRequest);
                g_workerRunning.store(false);
                return 0;
            }
            // Lost the race between IsGenuineRefreshInProgress() and
            // TryClaimRefresh() (another instance claimed it in between) -
            // loop back and wait on it properly instead.
        }
    }
}

int __cdecl Nutricula_Initialize(const wchar_t* dllDirectory)
{
    if (g_initialized.load()) return 1;

    InitializeCriticalSection(&g_workerLock);

    g_dllDirectory = (dllDirectory && dllDirectory[0]) ? std::wstring(dllDirectory) : GetOwnModuleDirectory();

    bool bridgeOk = MachineIdBridge::Load(g_dllDirectory);
    bool keyOk = LicenseProtocol::LoadServerPublicKey(g_dllDirectory);
    bool coordOk = g_coordinator.Initialize();
    // coordOk failing is non-fatal (falls back to local-only, still-correct
    // behavior - see SharedCoordinator's own documentation); bridgeOk/keyOk
    // failing IS fatal, since without them nothing can ever be trusted.

    (void)coordOk;
    g_initialized.store(bridgeOk && keyOk);
    return g_initialized.load() ? 1 : 0;
}

int __cdecl Nutricula_GetLicenseTier()
{
    return static_cast<int>(g_tier.load());
}

int __cdecl Nutricula_GetLicensePending()
{
    return static_cast<int>(g_pending.load());
}

void __cdecl Nutricula_Poll()
{
    if (!g_initialized.load())
    {
        if (!Nutricula_Initialize(nullptr)) return; // stay at default Tier=1 until this succeeds
    }

    EnterCriticalSection(&g_workerLock);
    bool alreadyRunning = g_workerRunning.load();
    if (!alreadyRunning)
    {
        if (g_workerThread)
        {
            // Previous run finished - reclaim the handle.
            WaitForSingleObject(g_workerThread, 0);
            CloseHandle(g_workerThread);
            g_workerThread = nullptr;
        }
        g_workerRunning.store(true);
        // _beginthreadex (not raw CreateThread) is required here so the C
        // runtime is properly initialized for this new thread - without it,
        // CRT-dependent calls made from the worker thread (file I/O among
        // them) silently fail. Confirmed by direct testing during
        // development: CreateThread returned a valid handle either way, but
        // only _beginthreadex actually let the thread body run.
        g_workerThread = reinterpret_cast<HANDLE>(_beginthreadex(nullptr, 0, WorkerThreadProc, nullptr, 0, nullptr));
        if (!g_workerThread) g_workerRunning.store(false);
    }
    LeaveCriticalSection(&g_workerLock);
}
