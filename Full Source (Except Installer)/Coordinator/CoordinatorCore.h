#pragma once
//
// CoordinatorCore.h - the Coordinator's own internal state machine. This
// REPLACES the old SharedState.cpp cross-process claim/heartbeat/stale-
// owner-recovery machinery entirely (architecture point 61) - that
// complexity only existed because multiple DLL instances (one per
// MT4/MT5 process) used to compete for a single global refresh. Now there
// is exactly one Coordinator process per machine, so "who owns the
// refresh" is simply "this process, always" - a plain mutex-protected
// in-process state, not a cross-process protocol.
//
// Still preserves everything that was never about cross-process ownership:
//   - the same PENDING/MAIN semantics (-1/-2/-3/1/2/-10)
//   - the same 54:00 + random(0..60s) scheduling anchored to the server's
//     own requested_at (never the local clock alone)
//   - the same atomic local-file replacement and re-verification
//   - the same 10-attempt retry budget
//

#include <windows.h>
#include <atomic>
#include <mutex>
#include <string>
#include <thread>

namespace Coordinator {

// Mirrors Constants.h's PENDING values exactly - duplicated here rather
// than shared via a header both DLL and Coordinator include, since after
// this refactor the DLL and Coordinator are separate binaries with
// deliberately minimal shared surface (only CoordinatorProtocol.h and the
// identity key are shared).
constexpr int TIER_LICENSED = 2;
constexpr int TIER_FREE = 1;
constexpr int TIER_FAILED = -10;
// Extends the otherwise-strict {1,2,-10} Main Tier set from the original
// architecture spec (point 3/68) - a deliberate, explicit addition, not an
// oversight. Means "a newer EA build is required" - the server refuses to
// issue a Tier 2 lease at all for an outdated build, regardless of whether
// the license itself is otherwise valid, until the customer updates. Still
// goes through the exact same server-signature verification as every other
// Reject (architecture point 15/101) - this is not a special unauthenticated
// path.
constexpr int TIER_UPDATE_REQUIRED = -50;
// Applied when the server detects two CONSECUTIVE stale rotating-refresh-
// token presentations for this license (see the clone-detection design) -
// means "this license's identity appears to be active on two machines at
// once; both are blocked from obtaining a new lease for clone_block_hours
// (24h by default), regardless of which one is actually legitimate,
// because the server genuinely cannot tell them apart once machine_id and
// device key are both cloned." Goes through the same server-signature
// verification as every other Reject.
constexpr int TIER_BLOCKED = -100;
constexpr int PENDING_IDLE = -1;
constexpr int PENDING_COMM_FAIL_RETRYING = -2;
constexpr int PENDING_REFRESH_IN_PROGRESS = -3;

struct PublishedState
{
    std::atomic<int> tier{TIER_FREE};
    std::atomic<int> pending{PENDING_IDLE};
    std::mutex resultMutex; // protects the two strings below only
    std::string lastCanonical;    // most recent verified response's canonical string (Lease or Rejected)
    std::string lastSignatureB64; // its RSA signature, so the DLL client can independently re-verify
};

class CoordinatorCore
{
public:
    // Starts the background worker thread. Idempotent - calling twice has
    // no additional effect. coordinatorFileName is this Coordinator's OWN
    // binary file name (always "NutriculaLicenseBroker.exe" - the Broker is
    // the sole Coordinator host since the Windows Service was removed) -
    // used for its own artifact integrity self-check (architecture point
    // 92/38), separate from the EX5/DLL names.
    void Start(const std::wstring& coordinatorFileName);

    // Called when a client (via IPC) asks for a refresh. This is
    // idempotent BY DESIGN (architecture point 99): if a refresh is not yet
    // due, or one is already in progress, this call has no additional
    // effect beyond waking the worker to re-evaluate sooner than its next
    // scheduled poll - it never itself triggers a second, parallel HTTP
    // request.
    void RequestRefreshIfDue();

    // Snapshot read for IPC StatusReplyMsg construction.
    void GetPublished(int& outTier, int& outPending, std::string& outCanonical, std::string& outSignatureB64);

    // Called from ServeOneClient (both the Service's and the Broker's own
    // copies) whenever the EA/DLL genuinely talks to us over the pipe -
    // GetStatus or RequestRefresh, either counts (see WorkerLoop's own
    // comment for why). This is the ONLY signal the Coordinator has that
    // an EA is actually attached to a running MetaTrader right now, as
    // opposed to merely being installed on this machine - WorkerLoop uses
    // it to skip its own periodic network activity entirely (no
    // free_checkin telemetry, no license verify) when nobody has asked in
    // a while, so an installed-but-unused copy generates zero server
    // traffic instead of running forever in the background.
    void NoteEaActivity();

private:
    void WorkerLoop();

    PublishedState m_state;
    std::thread m_worker;
    std::atomic<bool> m_started{false};
    HANDLE m_wakeEvent = nullptr; // signaled by RequestRefreshIfDue to interrupt an idle wait early
    std::wstring m_coordinatorFileName;
    // Free-tier telemetry (see WorkerLoop): the local "do I have a lease at
    // all" check stays fast (same MIN_RANDOM_OFFSET_SEC cycle as everything
    // else), but the actual network free_checkin call is independently
    // rate-limited to roughly every 30 minutes via this timestamp - this is
    // pure statistics, not a security-relevant check, so there is no need
    // to burden the server with it as often as real license verification.
    long long m_lastFreeCheckinSentAt = 0;
    // Last time (EstimatedNow(), i.e. clock-anchor-protected, not raw wall
    // clock) the EA/DLL was heard from over the pipe - see NoteEaActivity.
    // 0 means "never" (covers both a fresh install where the EA hasn't
    // been opened yet, and a just-restarted Coordinator process, since
    // this is in-memory only and intentionally not persisted to disk).
    // Atomic because it's written from whichever short-lived
    // ServeOneClient thread happens to be handling the current pipe
    // connection, and read from the separate WorkerLoop thread.
    std::atomic<long long> m_lastEaActivityAt{0};
    // EstimatedNow() at the moment Start() launched WorkerLoop - the idle-
    // self-exit basis (see WorkerLoop) for a freshly (re)started process
    // that hasn't heard from any EA yet, so a brand-new Coordinator always
    // gets one full idle window to actually be used before it can exit,
    // instead of measuring idleness from the Unix epoch (0).
    long long m_processStartedAt = 0;
};

} // namespace Coordinator
