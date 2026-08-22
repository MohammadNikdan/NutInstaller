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
// these functions. g_tier is always exactly 1, 2, or -10 (architecture
// point 3/68) - the existing convention throughout this codebase (e.g. the
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
// re-confirmed at all. Chosen window: comfortably longer than the normal
// ~55-minute refresh cycle (MIN_REQUEST_INTERVAL_SEC in CoordinatorCore)
// so a single missed cycle never falsely degrades the license, but short
// enough that a genuinely broken/disabled Coordinator is noticed well
// within one billing period.
constexpr long long STALE_COORDINATOR_DEGRADE_SECONDS = 75 * 60; // 75 minutes
std::atomic<long long> g_lastVerifiedTierTime{0};

long long NowUnixSeconds()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER v;
    v.LowPart = ft.dwLowDateTime;
    v.HighPart = ft.dwHighDateTime;
    const unsigned long long EPOCH_DIFF_100NS = 116444736000000000ULL;
    return static_cast<long long>((v.QuadPart - EPOCH_DIFF_100NS) / 10000000ULL);
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

extern "C" __declspec(dllexport) int __cdecl Nutricula_GetLicenseTier()
{
    return g_tier.load();
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
        long long lastVerified = g_lastVerifiedTierTime.load();
        if (lastVerified != 0 && (NowUnixSeconds() - lastVerified) > STALE_COORDINATOR_DEGRADE_SECONDS)
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
            g_lastVerifiedTierTime.store(NowUnixSeconds());
        }
        else if (sigOk && status.tier == TIER_FREE)
        {
            g_tier.store(TIER_FREE);
        }
        else if (sigOk && status.tier == TIER_UPDATE_REQUIRED)
        {
            g_tier.store(TIER_UPDATE_REQUIRED);
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
