//
// NutriculaLicenseCheckThin.cpp - the DLL, post-refactor. Everything that
// used to live here (SharedState's cross-process coordination, Transport's
// HTTP, LicenseProtocol's request-building, MachineIdBridge's device
// signing, the TRANSPORT_KEY secret) has moved to the Coordinator
// (Broker/Service) - see the architecture mapping table from this session.
//
// What stays here, per architecture point 97/108:
//   - INTERNAL_LICENSE_TIER / INTERNAL_LICENSE_TIER_PENDING (local, atomic,
//     hot-path, no IPC/file I/O/signature check on every read - point 3)
//   - The 4 MQL exports (point 98)
//   - Independent RSA signature verification (point 15) - the ONE piece of
//     LicenseProtocol logic kept here, specifically so a compromised or
//     fake Coordinator cannot hand this DLL a forged Tier 2 by simply
//     asserting it - every Lease/Rejected result received over IPC is
//     re-verified against the same server public key before being trusted,
//     exactly as strictly as the Coordinator itself verified it.
//   - The IPC client (Named Pipe + Coordinator identity handshake)
//
// Point 15 continued: this still doesn't make the Coordinator itself
// untrusted for AVAILABILITY (if it never responds, no Tier 2 is possible -
// architecture point 100 - no direct-to-server fallback exists), only for
// AUTHENTICITY (it cannot forge what a real Tier 2 needs).
//

#include "../Coordinator/CoordinatorProtocol.h"
#include "../Coordinator/CoordinatorIdentity.h"
#include "../Coordinator/NamedPipeIpc.h"
#include "../Coordinator/EcdsaHelpers.h"
#include "ServerSignatureVerify.h"
#include <windows.h>
#include <process.h>
#include <atomic>
#include <mutex>
#include <string>

namespace {

constexpr int TIER_FREE = 1;
constexpr int TIER_LICENSED = 2;
constexpr int TIER_FAILED = -10;
constexpr int TIER_UPDATE_REQUIRED = -50; // "please update the EA" - see CoordinatorCore.h's comment for the full explanation
constexpr int PENDING_IDLE = -1;
constexpr int PENDING_COMM_FAIL = -2;
constexpr int PENDING_REFRESH_IN_PROGRESS = -3;

// Hot-path state (architecture point 3): plain atomics, no locks, no IPC,
// no file I/O, no signature check on every read - only Poll() ever touches
// the Coordinator, and only occasionally.
std::atomic<int> g_tier{TIER_FREE};
std::atomic<int> g_pending{PENDING_IDLE};

// ============================================================================
// PLACEMENT NOTE FOR THE ~700 CALCULATION FUNCTIONS (added later by the
// project owner, not part of this delivery):
//
// This is the correct location for them, per the decision made earlier in
// this project: co-located with the License DLL itself (not a separate
// MathUtils-style DLL), specifically so that patching around the license
// check and patching around the calculations are the SAME attack surface,
// not two independent ones an attacker could defeat separately.
//
// Each function should read g_tier.load() directly (it's already a plain
// std::atomic<int>, immediately above) - never introduce a second copy of
// the tier value, never re-derive it from IPC/file/anything else inside
// these functions. g_tier is always exactly 1, 2, -10, -50, or -100
// (architecture point 3/68, extended by the update-required and
// clone-detection-block additions) - the existing convention throughout this codebase (e.g. the
// examples given earlier: `if (INTERNAL_LICENSE_TIER >= 1)` /
// `if (INTERNAL_LICENSE_TIER == 2)`) maps directly to `g_tier.load()`.
//
// Export each with the same `extern "C" __declspec(dllexport) ... __stdcall`
// convention already used for the four MQL exports above, so MQL can import
// them from this same DLL without any additional configuration.
//
// Do NOT add any new IPC calls, file reads, or network calls inside these
// functions - they must stay exactly as fast as a plain atomic load, since
// they run in MQL's OnTick() hot path (architecture point 3: "هیچ IPC برای
// خواندن آن نداشته باشد... هیچ File I/O... هیچ Signature Verification").
// ============================================================================


std::atomic<bool> g_pollInFlight{false};
std::mutex g_initMutex;
std::atomic<bool> g_publicKeyLoaded{false};

// Tracks the last time g_tier was set to TIER_LICENSED via a genuinely,
// independently verified signature (never just "Coordinator said so").
// Used to degrade gracefully if the Coordinator becomes unreachable for an
// extended period (e.g. its Service failed to restart after a reboot, or
// was somehow disabled) - a brief unavailability (seconds to a few
// minutes, e.g. during a normal Service startup after boot) must NOT lose
// the license state, but an extended one must eventually fall back to
// TIER_FREE rather than trusting a Tier 2 that can no longer be
// re-confirmed at all. Chosen window: comfortably longer than the new
// WORST-CASE refresh cycle (MAX_RANDOM_OFFSET_SEC = 50:00 in
// CoordinatorCore, replacing the old fixed 54:00+random(0-60s) - see the
// 2026 rotating-refresh-token migration) so a single missed cycle never
// falsely degrades the license, but short enough that a genuinely
// broken/disabled Coordinator is noticed well within one billing period.
// Recomputed with the same ~1.4x safety margin used before (was 50*1.4=70
// for the old 50-minute worst case; now 15*1.4=21 for the new 15-minute
// worst case - see the CoordinatorCore.cpp verify-window shrink from
// 10:01-50:00 down to 4:00-15:00, part of the same 2026 clock-tampering
// hardening work).
//
// Tracked via GetTickCount64() (system-boot-relative milliseconds), NOT
// NowUnixSeconds() (the ordinary, settable wall clock) - g_lastVerifiedTierTime
// is a plain in-process variable that naturally resets to 0 on every fresh
// MT4/MT5 launch anyway, so it needs no disk persistence the way the
// Coordinator's own ClockAnchor does, but comparing it against a
// wall-clock timestamp would have the exact same tampering weakness this
// whole feature exists to close: freezing/rewinding the system clock
// would make g_lastVerifiedTierTime never look stale, so a broken/disabled
// Coordinator's last-known tier would be trusted forever instead of
// degrading to TIER_FREE within a bounded window.
constexpr long long STALE_COORDINATOR_DEGRADE_SECONDS = 21 * 60; // 21 minutes
std::atomic<unsigned long long> g_lastVerifiedTierTickMs{0};

// ============================================================================
// Anti-debug / anti-tamper (2026 hardening).
//
// HONEST SCOPE: none of this defeats a sufficiently determined attacker with
// kernel-level tooling, a hardware debugger, or the willingness to patch
// this very code out of the binary - no purely software, source-level
// technique can. What this DOES meaningfully raise the bar against is the
// common case: attaching an ordinary user-mode debugger (x64dbg, OllyDbg,
// Cheat Engine, WinDbg) to this process and editing g_tier directly in
// memory, or single-stepping through Poll() to watch/redirect its logic.
// Multiple independent detection methods are used because each can be
// individually patched around once found - requiring an attacker to find
// and defeat all of them raises the effort needed well above "flip one
// byte", even though it still doesn't reach "impossible".
// ============================================================================

using NtQueryInformationProcessFn = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

bool IsDebuggerAttached()
{
    // Method 1: the standard, well-known API - trivially patched around by
    // itself, but still catches naive attach attempts and unmodified tools.
    if (IsDebuggerPresent()) return true;

    // Method 2: remote debugger check - catches some debuggers Method 1 misses
    // (e.g. certain kernel-assisted or "stealth" debuggers).
    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger) return true;

    // Method 3: NtQueryInformationProcess(ProcessDebugPort) - reads a lower-
    // level kernel structure than the two API calls above, so a debugger
    // that hides itself from IsDebuggerPresent (a common evasion trick)
    // often still shows up here. Resolved via GetProcAddress rather than
    // linking ntdll.lib directly, matching this project's existing pattern
    // for undocumented ntdll exports (see DetectWineHostOS in the
    // MachineID DLL).
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll)
    {
        auto ntQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessFn>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));
        if (ntQueryInformationProcess)
        {
            const ULONG ProcessDebugPort = 7;
            DWORD_PTR debugPort = 0;
            ULONG returned = 0;
            if (ntQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort,
                &debugPort, sizeof(debugPort), &returned) == 0 && debugPort != 0)
            {
                return true;
            }
        }
    }

    // Method 4: a coarse timing check - single-stepping or breakpointing
    // through this exact sequence of instructions takes drastically longer
    // in wall-clock time than executing it normally, even though each
    // individual API call above is fast. A generous threshold (50ms) is
    // used deliberately: this must never produce a false positive on a
    // slow/loaded but otherwise legitimate machine, since a false positive
    // here means denying a paying customer their license.
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    volatile int dummy = 0;
    for (int i = 0; i < 1000; i++) dummy += i;
    QueryPerformanceCounter(&end);
    double elapsedMs = static_cast<double>(end.QuadPart - start.QuadPart) * 1000.0 / static_cast<double>(freq.QuadPart);
    if (elapsedMs > 50.0) return true;

    return false;
}

// Cache of the last genuinely, independently signature-verified canonical +
// its signature (NOT just the resulting tier int) - see GetLicenseTier's own
// comment below for why this, rather than trusting g_tier alone, is the
// actual point of this whole section.
std::mutex g_verifiedCacheMutex;
std::string g_verifiedCanonical;
std::string g_verifiedSignatureB64;
int g_verifiedTierClaim = TIER_FREE;
unsigned long long g_verifiedLicenseExpiresAt = 0; // parsed from canonical, 0 = not a Lease (no expiry field)

// Pulls "license_expires_at=" out of a pipe-delimited canonical string - a
// minimal, local parse (not the full LicenseProtocol parser, which lives in
// the Coordinator) just so a replayed OLD-but-genuinely-signed canonical
// (see GetLicenseTier) can be caught even without contacting the server
// again. Returns 0 if the field isn't present (e.g. a Reject canonical,
// which has no license_expires_at at all).
unsigned long long ParseLicenseExpiresAt(const std::string& canonical)
{
    const std::string key = "|license_expires_at=";
    size_t pos = canonical.find(key);
    if (pos == std::string::npos) return 0;
    pos += key.size();
    unsigned long long value = 0;
    while (pos < canonical.size() && canonical[pos] >= '0' && canonical[pos] <= '9')
    {
        value = value * 10 + static_cast<unsigned long long>(canonical[pos] - '0');
        pos++;
    }
    return value;
}

// Plain wall-clock read, deliberately NOT the full ClockAnchor treatment
// (that lives in the Coordinator, which is what actually gates whether a
// Lease gets issued in the first place). This is only a defense-in-depth
// sanity check against a directly-injected, OLD-but-genuinely-signed
// canonical being replayed into this DLL's memory - even a raw,
// tamperable wall-clock read is strictly better here than no check at all,
// since the alternative is trusting the replayed value forever.
unsigned long long ThinDllNowUnixSeconds()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER v;
    v.LowPart = ft.dwLowDateTime;
    v.HighPart = ft.dwHighDateTime;
    const unsigned long long EPOCH_DIFF_100NS = 116444736000000000ULL;
    return (v.QuadPart - EPOCH_DIFF_100NS) / 10000000ULL;
}

bool EnsurePublicKeyLoaded()
{
    if (g_publicKeyLoaded.load()) return true;
    std::lock_guard<std::mutex> lock(g_initMutex);
    if (g_publicKeyLoaded.load()) return true;

    wchar_t modulePath[MAX_PATH] = {};
    HMODULE hSelf = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&EnsurePublicKeyLoaded), &hSelf);
    GetModuleFileNameW(hSelf, modulePath, MAX_PATH);
    std::wstring dir(modulePath);
    size_t slash = dir.find_last_of(L'\\');
    if (slash != std::wstring::npos) dir = dir.substr(0, slash);

    bool ok = ServerSignatureVerify::LoadServerPublicKey(dir);
    g_publicKeyLoaded.store(ok);
    return ok;
}

// One IPC round-trip: connect, verify the Coordinator's identity, ask for
// status, disconnect. Returns false if the Coordinator is unavailable OR
// failed the identity handshake - both cases are handled identically by
// the caller (architecture point 100: no fallback either way).
bool QueryCoordinatorStatus(CoordinatorProtocol::StatusReplyMsg& outStatus)
{
    HANDLE pipe = NamedPipeIpc::ConnectAndVerify(CoordinatorIdentity::PublicKeyXY(), 2000);
    if (pipe == INVALID_HANDLE_VALUE) return false;

    CoordinatorProtocol::GetStatusMsg req;
    DWORD written = 0;
    bool ok = WriteFile(pipe, &req, sizeof(req), &written, nullptr) && written == sizeof(req);
    if (ok)
    {
        DWORD read = 0;
        ok = ReadFile(pipe, &outStatus, sizeof(outStatus), &read, nullptr) &&
             read == sizeof(outStatus) &&
             outStatus.type == CoordinatorProtocol::MessageType::StatusReply;
    }
    CloseHandle(pipe);
    return ok;
}

void SendRefreshRequest()
{
    HANDLE pipe = NamedPipeIpc::ConnectAndVerify(CoordinatorIdentity::PublicKeyXY(), 2000);
    if (pipe == INVALID_HANDLE_VALUE) return; // Coordinator unavailable - no fallback, just try again next Poll
    CoordinatorProtocol::RequestRefreshMsg req;
    DWORD written = 0;
    WriteFile(pipe, &req, sizeof(req), &written, nullptr);
    CoordinatorProtocol::RefreshAckMsg ack;
    DWORD read = 0;
    ReadFile(pipe, &ack, sizeof(ack), &read, nullptr); // best-effort; don't care about the ack's content, just draining the reply
    CloseHandle(pipe);
}

} // namespace

extern "C" __declspec(dllexport) int __cdecl Nutricula_Initialize()
{
    return EnsurePublicKeyLoaded() ? 1 : 0;
}

// How often GetLicenseTier actually re-runs the real cryptographic
// re-verification, rather than every single call - this function runs in
// MQL's OnTick hot path (architecture point 3), which can fire hundreds or
// thousands of times per second on an active chart; a full RSA signature
// verification on every single call would be far too slow to be practical
// there. An attacker who patches g_tier in memory now only gets away with
// it for at most this long before the next real re-verification catches
// and reverts it - not "never checked" (the original gap), and not
// "checked every microsecond" (too slow to ship).
constexpr unsigned long long TIER_REVERIFY_INTERVAL_MS = 3000; // 3 seconds
std::atomic<unsigned long long> g_lastReverifyTickMs{0};
std::atomic<bool> g_lastReverifyResult{true}; // cached outcome between real re-verifications

extern "C" __declspec(dllexport) int __cdecl Nutricula_GetLicenseTier()
{
    int cached = g_tier.load();
    if (cached != TIER_LICENSED) return cached;

    unsigned long long nowTick = GetTickCount64();
    unsigned long long lastTick = g_lastReverifyTickMs.load();
    if (lastTick != 0 && (nowTick - lastTick) < TIER_REVERIFY_INTERVAL_MS)
    {
        // Within the rate-limit window - use the last real result rather
        // than re-running expensive crypto on every hot-path call.
        return g_lastReverifyResult.load() ? TIER_LICENSED : TIER_FREE;
    }

    // Time for a real re-verification. The actual anti-tamper point: g_tier
    // alone is NOT trusted for a TIER_LICENSED claim, no matter what value
    // it currently holds - it is cross-checked against an independent
    // re-verification of the last genuinely signed canonical this process
    // itself received and already verified once (in Poll). Patching g_tier
    // directly in memory (e.g. via a debugger or Cheat-Engine-style tool)
    // no longer has unlimited effect: it is caught and reverted within
    // TIER_REVERIFY_INTERVAL_MS at the latest.
    bool ok = !IsDebuggerAttached();
    if (ok)
    {
        std::lock_guard<std::mutex> lock(g_verifiedCacheMutex);
        ok = (g_verifiedTierClaim == TIER_LICENSED) &&
             ServerSignatureVerify::Verify(g_verifiedCanonical, g_verifiedSignatureB64) &&
             (g_verifiedLicenseExpiresAt == 0 || g_verifiedLicenseExpiresAt > ThinDllNowUnixSeconds());
    }
    g_lastReverifyResult.store(ok);
    g_lastReverifyTickMs.store(nowTick);
    return ok ? TIER_LICENSED : TIER_FREE;
}

extern "C" __declspec(dllexport) int __cdecl Nutricula_GetLicensePending()
{
    return g_pending.load();
}

// Called periodically by MQL (e.g. OnTimer). Cheap and idempotent
// (architecture point 99): concurrent calls from many charts collapse into
// at most one in-flight IPC round-trip at a time via g_pollInFlight - this
// is purely a client-side de-dup to avoid flooding the pipe with redundant
// simultaneous GetStatus calls, NOT what prevents duplicate server
// requests (that guarantee comes entirely from the Coordinator being a
// singleton - see architecture point 63).
extern "C" __declspec(dllexport) void __cdecl Nutricula_Poll()
{
    bool expected = false;
    if (!g_pollInFlight.compare_exchange_strong(expected, true)) return;

    if (!EnsurePublicKeyLoaded())
    {
        // Cannot verify anything without the server public key - stay at
        // whatever the last known-good state was; do not guess.
        g_pollInFlight.store(false);
        return;
    }

    CoordinatorProtocol::StatusReplyMsg status;
    if (!QueryCoordinatorStatus(status))
    {
        // Coordinator unavailable or failed identity verification.
        // Architecture point 100/6: absolutely no direct-to-server
        // fallback here. Keep the last published Tier untouched for a
        // BOUNDED grace period (see STALE_COORDINATOR_DEGRADE_SECONDS) -
        // long enough to survive a normal reboot/Service-restart delay,
        // but not indefinitely: if the Coordinator has genuinely been gone
        // for an extended time (disabled, uninstalled, crashing
        // repeatedly, or - the case explicitly worth suspecting - someone
        // deliberately tampering with it), the license state degrades to
        // TIER_FREE rather than staying licensed forever on stale trust.
        unsigned long long lastVerifiedTick = g_lastVerifiedTierTickMs.load();
        if (lastVerifiedTick != 0 && (GetTickCount64() - lastVerifiedTick) > static_cast<unsigned long long>(STALE_COORDINATOR_DEGRADE_SECONDS) * 1000ULL)
        {
            g_tier.store(TIER_FREE);
        }
        g_pending.store(PENDING_COMM_FAIL);
        g_pollInFlight.store(false);
        return;
    }

    // Ask the Coordinator to ensure a refresh happens if one is due - a
    // no-op if one is already active or not yet due (architecture point 99).
    if (status.pending == PENDING_IDLE)
    {
        // Only nudge when idle; no point re-asking while it's already mid-refresh.
    }
    SendRefreshRequest();

    // Independent verification (architecture point 15) - the actual
    // security-critical step. The Coordinator's own tier/pending numbers
    // are NOT trusted directly for Tier 2; only a genuinely re-verified
    // signature can move g_tier to TIER_LICENSED.
    if (status.canonicalLen > 0 && status.signatureLen > 0)
    {
        std::string canonical(status.canonical, status.canonicalLen);
        std::string signatureB64(status.signatureB64, status.signatureLen);
        bool sigOk = ServerSignatureVerify::Verify(canonical, signatureB64);

        if (sigOk && status.tier == TIER_LICENSED)
        {
            g_tier.store(TIER_LICENSED);
            g_lastVerifiedTierTickMs.store(GetTickCount64());
            {
                std::lock_guard<std::mutex> lock(g_verifiedCacheMutex);
                g_verifiedCanonical = canonical;
                g_verifiedSignatureB64 = signatureB64;
                g_verifiedTierClaim = TIER_LICENSED;
                g_verifiedLicenseExpiresAt = ParseLicenseExpiresAt(canonical);
            }
            // Force GetLicenseTier's own rate-limited cache to re-check
            // immediately on the next call rather than serving a stale
            // cached result from before this fresh verification.
            g_lastReverifyTickMs.store(0);
        }
        else if (sigOk && status.tier == TIER_FREE)
        {
            g_tier.store(TIER_FREE);
            std::lock_guard<std::mutex> lock(g_verifiedCacheMutex);
            g_verifiedTierClaim = TIER_FREE;
        }
        else if (sigOk && status.tier == TIER_UPDATE_REQUIRED)
        {
            g_tier.store(TIER_UPDATE_REQUIRED);
            std::lock_guard<std::mutex> lock(g_verifiedCacheMutex);
            g_verifiedTierClaim = TIER_UPDATE_REQUIRED;
        }
        else if (!sigOk)
        {
            // The Coordinator asserted a result but its accompanying
            // signature does not verify - treat as untrustworthy rather
            // than adopting the Coordinator's claimed tier at face value.
            // Deliberately does NOT force TIER_FAILED here (a transient
            // glitch forwarding the signature shouldn't nuke a
            // previously-good Tier 2 the DLL already independently
            // verified on an earlier Poll) - it just skips updating g_tier
            // this cycle.
        }
    }
    else if (status.tier == TIER_FAILED)
    {
        // TIER_FAILED (10 attempts exhausted) carries no signature to
        // verify by design - it's an absence-of-proof state, not a
        // positive claim requiring authentication.
        g_tier.store(TIER_FAILED);
    }

    g_pending.store(status.pending);
    g_pollInFlight.store(false);
}
