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
    // binary file name (e.g. "NutriculaLicenseService.exe" or
    // "NutriculaLicenseBroker.exe") - used for its own artifact integrity
    // self-check (architecture point 92/38), separate from the EX5/DLL
    // names which are always the same regardless of which Coordinator
    // variant is running.
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

private:
    void WorkerLoop();

    PublishedState m_state;
    std::thread m_worker;
    std::atomic<bool> m_started{false};
    HANDLE m_wakeEvent = nullptr; // signaled by RequestRefreshIfDue to interrupt an idle wait early
    std::wstring m_coordinatorFileName;
};

} // namespace Coordinator
