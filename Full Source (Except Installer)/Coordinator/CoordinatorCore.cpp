#include "CoordinatorCore.h"
#include "ManifestVerify.h"
#include "CoordinatorProtocol.h"
#include "../LicenseCheck/LicenseProtocol.h"
#include "../LicenseCheck/MachineIdBridge.h"
#include "../LicenseCheck/Transport.h"

#include <bcrypt.h>
#include <map>
#include <vector>
#include <cstdio>

namespace Coordinator {

namespace {

constexpr int MAX_ATTEMPTS = 10;
// Rotating refresh-token model (replaces the old fixed 53:00/54:00
// interval): after every successful lease, the NEXT request time is
// requested_at + a random offset in [MIN_RANDOM_OFFSET_SEC,
// MAX_RANDOM_OFFSET_SEC] - a genuinely different, unpredictable moment
// every single cycle, anywhere across a wide ~40-minute window (not just
// a +/-60s jitter on a fixed anchor). This offset is deliberately NOT
// stored anywhere separately - it is derived deterministically from the
// lease's own refresh_token (SHA-256(token) mod range), so it survives
// Terminal/Service restarts without any new persisted state, and cannot
// be "re-rolled" by restarting (the token itself only changes when a
// genuine new lease is issued).
constexpr long long MIN_RANDOM_OFFSET_SEC = 240;   // 4:00
constexpr long long MAX_RANDOM_OFFSET_SEC = 900;   // 15:00

// Deterministically derives the next-request offset from a lease's
// refresh token - same token always yields the same offset (so a
// restart never changes it), but the value is unpredictable to anyone
// without the token itself.
long long DeriveRandomOffsetFromToken(const std::string& refreshToken)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    unsigned char digest[32] = {};
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0)
    {
        BCRYPT_HASH_HANDLE hash = nullptr;
        if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) >= 0)
        {
            BCryptHashData(hash, (PUCHAR)refreshToken.data(), (ULONG)refreshToken.size(), 0);
            BCryptFinishHash(hash, digest, 32, 0);
            BCryptDestroyHash(hash);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    unsigned long long v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | digest[i];
    long long span = MAX_RANDOM_OFFSET_SEC - MIN_RANDOM_OFFSET_SEC + 1;
    return MIN_RANDOM_OFFSET_SEC + static_cast<long long>(v % static_cast<unsigned long long>(span));
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
    std::string s;
    s.reserve(32);
    for (int i = 0; i < 32; i++) s.push_back(static_cast<char>('0' + SecureRandomBelow(10)));
    return s;
}

struct LocalFileState
{
    bool fileExists = false;
    bool fileValid = false;
    bool hasLease = false;
    VerifiedLease lease;
    long long requestedAt = 0;
    bool licenseCurrentlyExpired = false;
    std::string canonical;      // NEW: kept so it can be forwarded to IPC clients for independent verification
    std::string signatureB64;   // NEW: same
};

std::wstring GetLicenseFilePathW()
{
    std::wstring path;
    if (!MachineIdBridge::GetLicenseFilePath(path)) return L"";
    return path;
}

std::wstring GetOwnModuleDirectory()
{
    wchar_t modulePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    std::wstring dir(modulePath);
    size_t slash = dir.find_last_of(L'\\');
    if (slash != std::wstring::npos) dir = dir.substr(0, slash);
    return dir;
}

// Atomic replacement (architecture point 72): temp file in the same
// directory, full write, flush, close, atomic rename - never truncates the
// real file directly. Matches the already-tested logic previously in
// NutriculaLicenseCheck.cpp's WorkerThreadProc, moved here since the
// Coordinator is now the sole writer of the license file (architecture
// point 73).
bool WriteLicenseFileAtomic(const std::wstring& path, const std::string& content)
{
    std::wstring tempPath = path + L".nutricula_tmp_" + std::to_wstring(GetCurrentProcessId()) + L"_" + std::to_wstring(GetTickCount64());
    {
        HANDLE h = CreateFileW(tempPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        DWORD written = 0;
        bool ok = WriteFile(h, content.data(), (DWORD)content.size(), &written, nullptr) && written == content.size();
        if (ok) FlushFileBuffers(h);
        CloseHandle(h);
        if (!ok) { DeleteFileW(tempPath.c_str()); return false; }
    }
    bool ok = MoveFileExW(tempPath.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
    if (!ok) DeleteFileW(tempPath.c_str());
    return ok;
}

// ============================================================================
// Clock Anchor (2026) - defense against wall-clock manipulation.
//
// PROBLEM: NowUnix() above is GetSystemTimeAsFileTime() - the ordinary
// Windows system clock, changeable by anyone with rights to right-click the
// taskbar clock and pick a different date. Comparing it directly against a
// cached lease's requested_at/license_expires_at (as this code used to)
// meant freezing or rewinding the system clock could make a cached lease
// look perpetually fresh and perpetually unexpired - forever, with a
// single genuinely-once-valid lease.
//
// FIX: never trust NowUnix() alone for a security decision. Instead, anchor
// "what time is it" to the LAST cryptographically-verified timestamp this
// machine actually received FROM THE SERVER (every Reject and every Lease
// carries requested_at inside its RSA-signed canonical - the attacker
// cannot forge this without the server's private key), then track elapsed
// time since that anchor using GetTickCount64() - a counter that runs from
// system BOOT, not from any settable calendar date, and has no standard
// Windows API to "set" it backward the way the wall clock can be set.
//
// This does NOT claim to be unbreakable (see the accompanying design
// discussion - a sufficiently privileged attacker could in principle patch
// kernel-level tick sources too) - it raises the bar from "change the date
// in Settings" to something meaningfully harder, while the real security
// backbone remains requiring FREQUENT genuine server round-trips (the
// shrunk 4:00-15:00 window below) rather than trusting any local
// elapsed-time judgment for long.
// ============================================================================
struct ClockAnchor
{
    long long wallClockUnix = 0;      // last server-verified "now", in Unix seconds
    unsigned long long tickCountMs = 0; // GetTickCount64() at the moment that was recorded
};

std::wstring GetClockAnchorFilePathW()
{
    std::wstring licensePath = GetLicenseFilePathW();
    if (licensePath.empty()) return L"";
    return licensePath + L".clockanchor";
}

// Deliberately plain (not signed/encrypted) - this file's purpose is
// raising the bar against casual wall-clock tampering, not protecting a
// secret. A sophisticated attacker who locates and hand-edits this exact
// file to match a spoofed clock is a meaningfully higher bar than the
// trivial "change the date" attack this exists to close, and even a
// tampered anchor file can only ever DELAY the moment this machine's
// estimated time catches up to reality (see EstimatedNow's "never go
// backward past the wall clock's own forward progress" logic below) -
// it cannot be used to push the estimate further ahead than the real
// wall clock already independently shows.
bool LoadClockAnchor(ClockAnchor& out)
{
    std::wstring path = GetClockAnchorFilePathW();
    if (path.empty()) return false;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    char buf[64] = {};
    DWORD readBytes = 0;
    bool ok = ReadFile(h, buf, sizeof(buf) - 1, &readBytes, nullptr) != 0;
    CloseHandle(h);
    if (!ok || readBytes == 0) return false;
    long long w = 0; unsigned long long t = 0;
    if (sscanf_s(buf, "%lld|%llu", &w, &t) != 2) return false;
    out.wallClockUnix = w;
    out.tickCountMs = t;
    return true;
}

void SaveClockAnchor(const ClockAnchor& anchor)
{
    std::wstring path = GetClockAnchorFilePathW();
    if (path.empty()) return;
    char buf[64] = {};
    int len = sprintf_s(buf, "%lld|%llu", anchor.wallClockUnix, anchor.tickCountMs);
    if (len <= 0) return;
    WriteLicenseFileAtomic(path, std::string(buf, buf + len));
}

// Called after every genuinely signature-verified server response
// (Reject or Lease - both carry an authentic, server-signed requested_at).
// Only ever moves the anchor FORWARD - never accepts a serverWallClock
// value older than the currently-stored anchor, which would otherwise let
// a malicious/misconfigured intermediary (or a genuinely stale cached
// response somehow replayed) push the anchor backward.
void UpdateClockAnchor(long long serverWallClock)
{
    ClockAnchor existing;
    bool hadExisting = LoadClockAnchor(existing);
    if (hadExisting && serverWallClock <= existing.wallClockUnix) return;

    ClockAnchor fresh;
    fresh.wallClockUnix = serverWallClock;
    fresh.tickCountMs = GetTickCount64();
    SaveClockAnchor(fresh);
}

// The actual replacement for "what time is it" in every security-relevant
// comparison below (license expiry, cooldown scheduling). See the block
// comment above ClockAnchor for the full reasoning.
long long EstimatedNow()
{
    long long wallNow = NowUnix();

    ClockAnchor anchor;
    if (!LoadClockAnchor(anchor))
    {
        // No anchor yet at all (e.g. very first run, before any server
        // contact has ever succeeded) - nothing to compare against yet,
        // fall back to the raw system clock. This is the SAME trust level
        // every fresh install already had before this feature existed;
        // the protection only engages once a real anchor exists, which
        // happens on the very first successful server exchange.
        return wallNow;
    }

    unsigned long long currentTick = GetTickCount64();
    long long estimated;
    if (currentTick < anchor.tickCountMs)
    {
        // GetTickCount64() only ever goes backward across a genuine
        // reboot (it counts from system boot, so it resets to a small
        // value then) - the tick-delta math below (against the OLD boot
        // session's tick) is no longer valid. But currentTick itself is
        // now milliseconds elapsed since THIS boot - a genuine,
        // unfakeable lower bound on real elapsed time, since the reboot
        // necessarily happened strictly after the anchor was recorded (in
        // the previous boot session). Add it to the anchor rather than
        // discarding it - this keeps the estimate advancing continuously
        // through the new boot session (starting from the last
        // known-good point, not from zero) instead of freezing solid at
        // the anchor value forever, which was the actual bug here: an
        // attacker who both rebooted AND rolled the wall clock back past
        // the anchor could otherwise freeze time indefinitely by
        // repeating "reboot, roll clock back" before every scheduled
        // check-in, since no genuinely forced progress ever occurred.
        long long minGuaranteedElapsedThisBoot = static_cast<long long>(currentTick / 1000ULL);
        long long rebootAdjustedEstimate = anchor.wallClockUnix + minGuaranteedElapsedThisBoot;
        estimated = (wallNow > rebootAdjustedEstimate) ? wallNow : rebootAdjustedEstimate;
    }
    else
    {
        long long elapsedSec = static_cast<long long>((currentTick - anchor.tickCountMs) / 1000ULL);
        long long tickBasedEstimate = anchor.wallClockUnix + elapsedSec;
        // If the wall clock is AHEAD of the tick-based estimate, real time
        // has genuinely progressed further than our last anchor accounted
        // for (completely normal - e.g. it's simply been a while since the
        // last server contact) - prefer the more precise wall clock. If the
        // wall clock is BEHIND the tick-based estimate, someone rewound or
        // froze it - trust the tick-based estimate instead, since it can
        // only move forward from a genuine server-verified starting point.
        estimated = (wallNow > tickBasedEstimate) ? wallNow : tickBasedEstimate;
    }
    return estimated;
}

LocalFileState EvaluateLocalFile()
{
    LocalFileState state;
    std::wstring path = GetLicenseFilePathW();
    if (path.empty()) return state;

    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return state;
    std::vector<char> buf(65536);
    DWORD readBytes = 0;
    std::string raw;
    if (ReadFile(h, buf.data(), (DWORD)buf.size(), &readBytes, nullptr) && readBytes > 0)
        raw.assign(buf.data(), readBytes);
    CloseHandle(h);
    if (raw.empty()) return state;
    state.fileExists = true;

    ParsedResponse parsed = LicenseProtocol::DecryptAndVerify(raw);
    if (parsed.kind == ResponseKind::Invalid) return state;

    state.fileValid = true;
    if (parsed.kind == ResponseKind::Lease)
    {
        state.hasLease = true;
        state.lease = parsed.lease;
        state.requestedAt = static_cast<long long>(parsed.lease.requestedAt);
        state.licenseCurrentlyExpired = (static_cast<long long>(parsed.lease.licenseExpiresAt) <= EstimatedNow());
        state.canonical = parsed.rawCanonical;
        state.signatureB64 = parsed.rawSignatureB64;
    }
    else if (parsed.kind == ResponseKind::Rejected)
    {
        state.requestedAt = static_cast<long long>(parsed.requestedAt);
        state.canonical = parsed.rawCanonical;
        state.signatureB64 = parsed.rawSignatureB64;
    }
    return state;
}

} // anonymous namespace

void CoordinatorCore::Start(const std::wstring& coordinatorFileName)
{
    bool expected = false;
    if (!m_started.compare_exchange_strong(expected, true)) return;
    m_coordinatorFileName = coordinatorFileName;

    std::wstring dir = GetOwnModuleDirectory();
    MachineIdBridge::Load(dir); // best-effort; if this fails, EvaluateLocalFile/refresh calls below simply keep failing gracefully rather than crashing
    if (!LicenseProtocol::LoadServerPublicKey(dir))
    {
        // Cannot verify anything without this - every DecryptAndVerify call
        // will correctly keep returning Invalid rather than silently
        // trusting unverified data, but log-worthy since it means the
        // Coordinator can never reach Tier 2 until this is fixed (missing
        // license-signing-public.pem next to the Coordinator binary).
        printf("WARNING: failed to load license-signing-public.pem - no response will ever verify.\n");
    }

    m_wakeEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    m_worker = std::thread([this]() { WorkerLoop(); });
    m_worker.detach();
}

void CoordinatorCore::RequestRefreshIfDue()
{
    if (m_wakeEvent) SetEvent(m_wakeEvent);
}

void CoordinatorCore::GetPublished(int& outTier, int& outPending, std::string& outCanonical, std::string& outSignatureB64)
{
    outTier = m_state.tier.load();
    outPending = m_state.pending.load();
    std::lock_guard<std::mutex> lock(m_state.resultMutex);
    outCanonical = m_state.lastCanonical;
    outSignatureB64 = m_state.lastSignatureB64;
}

void CoordinatorCore::WorkerLoop()
{
    for (;;)
    {
        LocalFileState local = EvaluateLocalFile();
        long long now = EstimatedNow();

        // Layer 1 (cheap, local-only clone/copy detection - see the
        // accompanying design discussion): before trusting a locally
        // cached lease AT ALL, confirm it was actually issued for THIS
        // machine AND this device key. A naively copied license file
        // (machine_id/device_key spoofing not involved) fails this
        // immediately and is treated exactly like "no valid local lease" -
        // i.e. this machine behaves like a fresh install and must
        // complete a real network verify before it can ever be trusted,
        // which is also when Layer 2 (VPS IP-binding, server-side) and the
        // rotating refresh token mechanism get their chance to catch a
        // deeper clone.
        //
        // IMPORTANT LIMITATION, stated plainly rather than left implicit:
        // checking device_key_hash here does NOT add any real protection
        // against a genuine full VM/disk clone (e.g. a VPS provider's
        // self-service "Clone"/"Create Image" feature applied to an
        // ALREADY Nutricula-activated instance) - in that scenario the
        // device key file itself is copied byte-for-byte along with
        // everything else on disk, so the clone's own freshly-computed
        // device key hash is IDENTICAL to what's in the lease, same as
        // machine_id above. This check exists for the SEPARATE, simpler
        // case of someone copying just the lease file (or just the lease
        // file + a mismatched/regenerated device key) without also
        // copying the device key file - a real, if narrower, scenario
        // this closes for free, since both values were already being
        // read/computed anyway. It is deliberate defense-in-depth, not a
        // solution to full-clone detection - that remains Layer 2's job.
        std::string localMachineIdForCheck, localMachineIdAltForCheck, localDeviceKeyHashForCheck;
        bool machineMatches = false;
        if (local.hasLease)
        {
            bool gotMachineId = MachineIdBridge::GenerateMachineId(localMachineIdForCheck);
            bool gotMachineIdAlt = MachineIdBridge::GenerateMachineIdWithGuid(localMachineIdAltForCheck);
            bool gotDeviceKeyHash = MachineIdBridge::GetDeviceKeyHash(localDeviceKeyHashForCheck);
            // 2026 hardening: check against EITHER variant, not just the
            // primary one - a computer legitimately activated via the
            // WithGuid fallback (see the server's own machine_requires_
            // confirmation flow) has local.lease.machineId equal to the
            // WithGuid variant, not the primary one; without this OR, this
            // exact same, legitimately-licensed computer would fail its
            // own Layer 1 check every single time and be treated as if it
            // were a clone.
            machineMatches = gotDeviceKeyHash && (local.lease.deviceKeyHash == localDeviceKeyHashForCheck) &&
                ((gotMachineId && local.lease.machineId == localMachineIdForCheck) ||
                 (gotMachineIdAlt && local.lease.machineId == localMachineIdAltForCheck));
        }

        // Layer 2 scheduling: the next request time is requested_at + a
        // random offset in [MIN_RANDOM_OFFSET_SEC, MAX_RANDOM_OFFSET_SEC],
        // deterministically derived from this lease's own refresh token
        // (see DeriveRandomOffsetFromToken) - not a fixed interval, and not
        // separately persisted (so it can't be reset by restarting).
        long long randomOffset = local.hasLease
            ? DeriveRandomOffsetFromToken(local.lease.refreshToken)
            : MIN_RANDOM_OFFSET_SEC;

        bool withinCooldown = local.fileValid && local.hasLease && machineMatches &&
            !local.licenseCurrentlyExpired && local.requestedAt != 0 &&
            (now - local.requestedAt) < randomOffset;

        if (withinCooldown)
        {
            m_state.tier.store(TIER_LICENSED);
            m_state.pending.store(PENDING_IDLE);
            std::lock_guard<std::mutex> lock(m_state.resultMutex);
            m_state.lastCanonical = local.canonical;
            m_state.lastSignatureB64 = local.signatureB64;
        }
        else
        {
            // This process is the ONLY Coordinator (architecture point 6/63)
            // - no claim/heartbeat/stale-owner logic needed at all, unlike
            // the old multi-process DLL design. Just do the refresh.
            m_state.pending.store(PENDING_REFRESH_IN_PROGRESS);

            // If we have a locally cached lease whose machine_id doesn't
            // match (Layer 1 catch), anchor from "now" instead of the
            // stale/foreign requested_at - this machine has no legitimate
            // claim to that lease's schedule at all, so it should behave
            // exactly like a fresh install (wait one fresh random window
            // from right now, same as never having had a lease).
            long long anchor = (local.hasLease && machineMatches) ? local.requestedAt : now;
            long long offsetToUse = (local.hasLease && machineMatches) ? randomOffset : MIN_RANDOM_OFFSET_SEC;
            long long target = anchor + offsetToUse;
            long long waitSeconds = target - EstimatedNow();
            if (waitSeconds > 0)
            {
                // Wait, but wake up early (and re-evaluate from the top) if
                // RequestRefreshIfDue() signals us - architecture point 99:
                // this does NOT itself start an extra request, it only
                // shortens how long we wait before the SAME single-owner
                // loop re-checks whether a refresh is genuinely due yet.
                ResetEvent(m_wakeEvent);
                WaitForSingleObject(m_wakeEvent, static_cast<DWORD>(waitSeconds * 1000));
                continue;
            }

            // Artifact integrity check (architecture points 45/51/96/112) -
            // performed as close to the actual network request as possible,
            // BEFORE any request is sent. A failure here means "no lease
            // should be issued this cycle" - it is explicitly NOT the same
            // condition as TIER_FAILED (-10, which means specifically "10
            // attempts, no trustworthy server response" - point 113). An
            // integrity failure simply skips this refresh attempt entirely
            // (no network call made at all) and leaves whatever tier was
            // already published untouched, defaulting to TIER_FREE only if
            // nothing was ever published.
            std::wstring ownDir = GetOwnModuleDirectory();
            ManifestVerify::ManifestData manifest = ManifestVerify::LoadAndVerifyManifest(ownDir);
            bool isService = (m_coordinatorFileName == CoordinatorProtocol::COORDINATOR_SERVICE_FILE_NAME);
            // Both 32-bit and 64-bit builds of the Coordinator genuinely
            // ship to customers now (32-bit Windows tablets are a real,
            // supported case), so the manifest carries a separate expected
            // hash per architecture. This exact compiled binary is only
            // ever ONE architecture - #ifdef _WIN64 is resolved once, at
            // compile time, by the compiler itself (defined by both MSVC
            // and MinGW-w64 for 64-bit targets) - never a runtime guess.
#ifdef _WIN64
            const std::string& expectedServiceHash = manifest.service64Sha256;
            const std::string& expectedBrokerHash = manifest.broker64Sha256;
#else
            const std::string& expectedServiceHash = manifest.service32Sha256;
            const std::string& expectedBrokerHash = manifest.broker32Sha256;
#endif
            bool artifactsOk = manifest.valid && ManifestVerify::VerifyArtifactsMatchManifest(
                manifest, ownDir,
                CoordinatorProtocol::ARTIFACT_EX5_NAME,
                CoordinatorProtocol::ARTIFACT_EX4_NAME,
                CoordinatorProtocol::ARTIFACT_DLL32_NAME,
                CoordinatorProtocol::ARTIFACT_DLL64_NAME,
                isService ? m_coordinatorFileName : L"", expectedServiceHash,   // only check whichever of Service/Broker this actually is
                isService ? L"" : m_coordinatorFileName, expectedBrokerHash);
            if (!artifactsOk)
            {
                // Do NOT touch m_state.tier here - an already-published
                // Tier 2 from a prior, genuinely verified cycle remains
                // valid until it naturally expires; this only prevents
                // ISSUING A NEW one while integrity is broken. If
                // nothing was ever published, tier stays at its
                // constructor default (TIER_FREE), which is correct.
                m_state.pending.store(PENDING_COMM_FAIL_RETRYING);
                Sleep(5000);
                continue;
            }
            // manifest.* (the verified, actual hashes just measured above)
            // stays in scope for building the Artifact Evidence below - the
            // whole point of point 88: "Evidence باید به... fresh challenge
            // Bind شده باشد", so the SAME measurement used to gate this
            // refresh attempt is exactly what gets reported to the server,
            // never a separately (and therefore potentially stale/replay-
            // able) computed value.

            std::string primaryMachineId, altMachineId, deviceKeyHash;
            if (!MachineIdBridge::GenerateMachineId(primaryMachineId) ||
                !MachineIdBridge::GenerateMachineIdWithGuid(altMachineId) ||
                !MachineIdBridge::GetDeviceKeyHash(deviceKeyHash))
            {
                m_state.tier.store(TIER_FAILED);
                m_state.pending.store(PENDING_IDLE);
                Sleep(5000);
                continue;
            }

            // 2026 hardening - dual machine_id (physical Windows only; on
            // every other platform primaryMachineId==altMachineId already,
            // see Nutricula_GenerateMachineIdWithGuid's own comment, so
            // this reduces to a no-op there). If the local lease already
            // knows which variant this license is actually stored under
            // (from a previous successful verify or the original
            // signup/transfer), put THAT value in the primary "machine_id"
            // field - this is what the server's own matched-value logic
            // expects (see license_check.php's $matchedRawMachineId) and
            // what this Coordinator signs the Challenge message with
            // below, so the two must agree. Falls back to
            // primary-first (the common case) when there is no local
            // lease yet to consult.
            std::string machineId = primaryMachineId;
            std::string machineIdAlt = altMachineId;
            if (local.hasLease && local.lease.machineId == altMachineId && local.lease.machineId != primaryMachineId)
            {
                machineId = altMachineId;
                machineIdAlt = primaryMachineId;
            }

            std::string licenseIdForRequest = local.hasLease ? local.lease.licenseId : std::string();

            if (licenseIdForRequest.empty())
            {
                // Free-tier telemetry (2026): there is no license_id at all
                // to attempt a real challenge/verify with (no lease file,
                // a corrupt/incomplete one, or one whose signature didn't
                // even verify) - previously this meant the Coordinator
                // made NO network contact whatsoever while sitting at
                // TIER_FREE, silently, forever. Send a lightweight,
                // unauthenticated "I am a free-tier install and still
                // running" ping instead, so the vendor can actually see
                // free-tier usage exists. Fire-and-forget: no retry loop,
                // the response (if any) is not even inspected - this is
                // pure telemetry, not something that gates tier or any
                // other behavior below.
                //
                // Free installs always use the WithGuid variant (altMachineId),
                // never the dual-machine_id complexity Premium needs - see
                // Nutricula_GenerateMachineIdWithGuid's own comment, point 2.
                // machine_id_alt is deliberately NOT sent here at all (this
                // is the one stage where the server treats it as fully
                // optional and never needs a fallback candidate).
                std::map<std::string, std::string> checkinFields;
                checkinFields["v"] = "3";
                checkinFields["stage"] = "free_checkin";
                checkinFields["machine_id"] = altMachineId;
                checkinFields["device_key_hash"] = deviceKeyHash;
                std::string checkinEnvelope = LicenseProtocol::BuildRequestEnvelope(checkinFields);
                if (!checkinEnvelope.empty())
                {
                    const std::wstring checkinHost = L"nutriculaexpert.com";
                    const std::wstring checkinPath = L"/license_validator_phps/license_check.php";
                    Transport::PostEnvelope(checkinHost, checkinPath, checkinEnvelope, 15000);
                }
                m_state.tier.store(TIER_FREE);
                m_state.pending.store(PENDING_IDLE);
                continue;
            }

            const std::wstring host = L"nutriculaexpert.com";
            const std::wstring urlPath = L"/license_validator_phps/license_check.php";
            // BUG FIX (found via code review): previously defaulted to
            // TIER_FAILED with an EMPTY canonical/signature here, meaning
            // that if every single network attempt below failed purely due
            // to a transient outage (DNS hiccup, brief firewall blip, WiFi
            // drop) - NOT an actual reject from the server - a perfectly
            // valid, unexpired, already-signature-verified local lease got
            // silently replaced with an unauthenticated TIER_FAILED after
            // only ~20 seconds (MAX_ATTEMPTS=10 x 2s Sleep). The thin DLL
            // accepts TIER_FAILED with NO signature check at all (see its
            // own comment: "carries no signature to verify by design"), so
            // this collapsed trading within 20 seconds of a brief network
            // blip - nowhere near the 21-minute STALE_COORDINATOR_DEGRADE_
            // SECONDS grace period the whole design elsewhere promises.
            // Fix: default to what we already know is valid (the existing
            // local lease, already signature-verified moments ago by
            // EvaluateLocalFile's own DecryptAndVerify call) rather than an
            // empty failure state - an actual reject or a fresh lease from
            // the server can still override this via a real break below;
            // only genuine network SILENCE now correctly means "keep
            // trusting what we already verified," not "assume the worst."
            bool localLeaseStillGood = local.hasLease && !local.licenseCurrentlyExpired;
            long finalStable = localLeaseStillGood ? TIER_LICENSED : TIER_FAILED;
            std::string finalCanonical = localLeaseStillGood ? local.canonical : std::string();
            std::string finalSignatureB64 = localLeaseStillGood ? local.signatureB64 : std::string();

            for (int attempt = 1; attempt <= MAX_ATTEMPTS && !licenseIdForRequest.empty(); attempt++)
            {
                std::map<std::string, std::string> challengeFields;
                challengeFields["v"] = "3";
                challengeFields["stage"] = "challenge";
                challengeFields["license_id"] = licenseIdForRequest;
                challengeFields["machine_id"] = machineId;
                challengeFields["machine_id_alt"] = machineIdAlt;
                challengeFields["device_key_hash"] = deviceKeyHash;
                std::string challengeEnvelope = LicenseProtocol::BuildRequestEnvelope(challengeFields);

                bool advance = !challengeEnvelope.empty();
                ParsedResponse challengeParsed;
                if (advance)
                {
                    TransportResponse r = Transport::PostEnvelope(host, urlPath, challengeEnvelope, 30000);
                    advance = (r.result == TransportResult::Ok);
                    if (advance)
                    {
                        challengeParsed = LicenseProtocol::DecryptAndVerify(r.body);
                        advance = (challengeParsed.kind != ResponseKind::Invalid && challengeParsed.kind != ResponseKind::LegacyNo);
                    }
                }
                if (advance && challengeParsed.kind == ResponseKind::Rejected)
                {
                    // "update_required" (architecture extension - see
                    // CoordinatorCore.h's TIER_UPDATE_REQUIRED comment) maps
                    // to a distinct tier, not the ordinary TIER_FREE - still
                    // arrives via the exact same signed Reject path as any
                    // other rejection reason, so it's just as authenticated.
                    finalStable = (challengeParsed.rejectReason == "update_required") ? TIER_UPDATE_REQUIRED
                        : (challengeParsed.rejectReason == "blocked") ? TIER_BLOCKED
                        : TIER_FREE;
                    finalCanonical = challengeParsed.rawCanonical;
                    finalSignatureB64 = challengeParsed.rawSignatureB64;
                    // Clock Anchor: this Reject's own requestedAt is authentic
                    // (RSA-signature-verified by DecryptAndVerify before
                    // kind==Rejected was ever set) server time.
                    UpdateClockAnchor(static_cast<long long>(challengeParsed.requestedAt));
                    break;
                }
                if (advance && challengeParsed.kind != ResponseKind::Challenge) advance = false;
                if (!advance) { if (attempt < MAX_ATTEMPTS) Sleep(2000); continue; }

                // Artifact Evidence (architecture points 47-49/88): the
                // SAME hashes just measured above are bound into the
                // signed message alongside the server's fresh challenge_id/
                // nonce, so this Evidence can never be replayed against a
                // different challenge, and the server can verify it was the
                // device key - not a network attacker - that vouches for
                // these specific hash values.
                std::string message =
                    "NUTRICULA-RUNTIME-V3|challenge_id=" + challengeParsed.challenge.challengeId +
                    "|nonce=" + challengeParsed.challenge.nonceB64 +
                    "|license_id=" + licenseIdForRequest + "|machine_id=" + machineId +
                    "|build_id=" + manifest.buildId +
                    "|ex5_hash=" + manifest.ex5Sha256 +
                    "|ex4_hash=" + manifest.ex4Sha256 +
                    "|dll32_hash=" + manifest.dll32Sha256 +
                    "|dll64_hash=" + manifest.dll64Sha256 +
                    "|service_hash=" + expectedServiceHash +
                    "|broker_hash=" + expectedBrokerHash;
                std::string signatureB64;
                if (!MachineIdBridge::SignChallenge(message, signatureB64)) { if (attempt < MAX_ATTEMPTS) Sleep(2000); continue; }

                std::map<std::string, std::string> verifyFields;
                verifyFields["v"] = "3";
                verifyFields["stage"] = "verify";
                verifyFields["license_id"] = licenseIdForRequest;
                verifyFields["machine_id"] = machineId;
                verifyFields["machine_id_alt"] = machineIdAlt;
                verifyFields["device_key_hash"] = deviceKeyHash;
                verifyFields["challenge_id"] = challengeParsed.challenge.challengeId;
                verifyFields["build_id"] = manifest.buildId;
                verifyFields["ex5_hash"] = manifest.ex5Sha256;
                verifyFields["ex4_hash"] = manifest.ex4Sha256;
                verifyFields["dll32_hash"] = manifest.dll32Sha256;
                verifyFields["dll64_hash"] = manifest.dll64Sha256;
                verifyFields["service_hash"] = expectedServiceHash;
                verifyFields["broker_hash"] = expectedBrokerHash;
                verifyFields["signature"] = signatureB64;
                // Send whatever refresh token we currently have locally
                // (empty if we've never had one, e.g. very first ever
                // request) - the server treats anything other than its
                // own current stored token as stale, regardless of
                // generation distance. See the clone-detection design.
                verifyFields["refresh_token"] = local.hasLease ? local.lease.refreshToken : std::string();
                std::string verifyEnvelope = LicenseProtocol::BuildRequestEnvelope(verifyFields);

                TransportResponse verifyResp = Transport::PostEnvelope(host, urlPath, verifyEnvelope, 30000);
                if (verifyResp.result != TransportResult::Ok) { if (attempt < MAX_ATTEMPTS) Sleep(2000); continue; }

                ParsedResponse verifyParsed = LicenseProtocol::DecryptAndVerify(verifyResp.body);
                if (verifyParsed.kind == ResponseKind::Invalid || verifyParsed.kind == ResponseKind::LegacyNo)
                { if (attempt < MAX_ATTEMPTS) Sleep(2000); continue; }
                if (verifyParsed.kind == ResponseKind::Rejected)
                {
                    finalStable = (verifyParsed.rejectReason == "update_required") ? TIER_UPDATE_REQUIRED
                        : (verifyParsed.rejectReason == "blocked") ? TIER_BLOCKED
                        : TIER_FREE;
                    finalCanonical = verifyParsed.rawCanonical;
                    finalSignatureB64 = verifyParsed.rawSignatureB64;
                    // Clock Anchor: same reasoning as the challenge-stage
                    // Reject above - this is an authentic, signature-verified
                    // server timestamp.
                    UpdateClockAnchor(static_cast<long long>(verifyParsed.requestedAt));
                    break;
                }
                if (verifyParsed.kind != ResponseKind::Lease) { if (attempt < MAX_ATTEMPTS) Sleep(2000); continue; }

                if (!WriteLicenseFileAtomic(GetLicenseFilePathW(), verifyResp.body)) { if (attempt < MAX_ATTEMPTS) Sleep(2000); continue; }
                LocalFileState reReadCheck = EvaluateLocalFile();
                if (!reReadCheck.hasLease) { if (attempt < MAX_ATTEMPTS) Sleep(2000); continue; }

                finalStable = TIER_LICENSED;
                finalCanonical = reReadCheck.canonical;
                finalSignatureB64 = reReadCheck.signatureB64;
                // Clock Anchor: a freshly-issued, re-parsed-from-disk
                // (and therefore signature-re-verified via EvaluateLocalFile's
                // own DecryptAndVerify call) Lease's requestedAt is authentic
                // server time.
                UpdateClockAnchor(reReadCheck.requestedAt);
                break;
            }

            m_state.tier.store(finalStable);
            m_state.pending.store(PENDING_IDLE);
            {
                std::lock_guard<std::mutex> lock(m_state.resultMutex);
                m_state.lastCanonical = finalCanonical;
                m_state.lastSignatureB64 = finalSignatureB64;
            }
        }

        Sleep(5000); // brief pause before re-evaluating, avoids a tight loop when e.g. machine ID generation keeps failing
    }
}

} // namespace Coordinator
