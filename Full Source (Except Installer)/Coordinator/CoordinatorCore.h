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
// The local license file EXISTS but cannot be opened/read right now because
// something holds or blocks it (sharing/lock violation, access denied, or an
// antivirus verdict such as ERROR_VIRUS_INFECTED). Unlike TIER_FAILED (-2) this
// is NOT a verdict about the license or the install's integrity - the Broker
// simply cannot see the file - so it gets its own code, which the thin DLL
// latches for the rest of that EA's lifetime (a final state: the EA shows an
// alert and removes itself). Carries no signature, like TIER_FAILED. A missing
// file is NOT this case (that is an ordinary free install), and neither is a
// readable file whose content is invalid (that file is ignored as if absent).
constexpr int TIER_FILE_LOCKED = -5;
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
    // Free-tier verification schedule (see WorkerLoop / runFreeCheckin): the
    // earliest EstimatedNow() at which the next network free_checkin ROUND may
    // start. 0 = never run yet in this process (due immediately). After a
    // genuine, request-bound, signed answer it is pushed out by
    // FREE_CHECKIN_INTERVAL_SEC (30:00); after a FAILED round (offline, 'no',
    // HTTP error, forged/unbound answer) only by FREE_RETRY_INTERVAL_SEC
    // (2:00), so a failure is retried soon but never hammers the server.
    // This is purely the ATTEMPT clock. The TRUST clock - how long this install
    // may keep running without a genuine answer - is the persisted Clock Anchor
    // (last signature-verified server response), which only a genuine answer
    // can advance, so neither a failed attempt nor a Broker restart buys time.
    long long m_freeNextAttemptAt = 0;
    // Consecutive failed free rounds (in memory) - drives the doubling retry
    // back-off; reset by any genuine answer.
    int m_freeFailStreak = 0;
    // Back-off after an ordinary (non-soft) signed Reject of a LICENSED
    // install (2026). Before this, a Reject changed nothing the loop looks at,
    // so e.g. license_inactive was re-challenged every ~5 s forever. Set to
    // EstimatedNow() + 30 min when the Reject leaves the install at
    // TIER_FREE / -50 / -100, + 5 min when it ends at -2. It only applies while
    // the local lease is still the one the Reject was about
    // (m_rejectForLeaseRequestedAt) - a freshly activated/renewed lease is
    // tried immediately. In memory on purpose: restarting the Broker only buys
    // one fresh attempt, never a different verdict.
    long long m_rejectRetryNotBefore = 0;
    long long m_rejectForLeaseRequestedAt = 0;
    // Last time (EstimatedNow(), i.e. clock-anchor-protected, not raw wall
    // clock) the EA/DLL was heard from over the pipe - see NoteEaActivity.
    // 0 means "never" (covers both a fresh install where the EA hasn't
    // been opened yet, and a just-restarted Coordinator process, since
    // this is in-memory only and intentionally not persisted to disk).
    // Atomic because it's written from whichever short-lived
    // ServeOneClient thread happens to be handling the current pipe
    // connection, and read from the separate WorkerLoop thread.
    std::atomic<long long> m_lastEaActivityAt{0};
    // 2026 hardening: the free-tier branch's own persisted verdict
    // (TIER_FREE or TIER_UPDATE_REQUIRED - see WorkerLoop's free_checkin
    // handling). The actual network check-in only happens every
    // FREE_CHECKIN_INTERVAL_SEC (30:00) (or every FREE_RETRY_INTERVAL_SEC while
    // failing), but the outer loop re-publishes a
    // tier far more often than that (every ~MIN_RANDOM_OFFSET_SEC) - without
    // this, a confirmed TIER_UPDATE_REQUIRED would flicker back to
    // TIER_FREE within minutes on every cycle that skips the network call,
    // not just the ones that make it. Sticky across cycles; only a fresh,
    // verified, request-bound server answer (signed free_ok / banned /
    // update_required / artifact_mismatch) changes it, or - 2026 rule - the
    // absence of any genuine answer for longer than FREE_MAX_SERVER_SILENCE_SEC
    // (or on the very first contact), which sets TIER_FAILED (-2), exactly like
    // the licensed path's silence cap. Short silences keep the last verdict.
    std::atomic<int> m_freeTierOutcome{TIER_FREE};
    // EstimatedNow() at the moment Start() launched WorkerLoop - the idle-
    // self-exit basis (see WorkerLoop) for a freshly (re)started process
    // that hasn't heard from any EA yet, so a brand-new Coordinator always
    // gets one full idle window to actually be used before it can exit,
    // instead of measuring idleness from the Unix epoch (0).
    long long m_processStartedAt = 0;
    // 2026 hardening: throttles ReportFailureBestEffort (see
    // CoordinatorCore.cpp) so a sustained local failure (e.g. a real,
    // ongoing network outage) reports itself to nutricula_failure_report.php
    // at most once per FAILURE_REPORT_INTERVAL_SEC, not once per WorkerLoop
    // cycle - same cadence/throttle pattern as the free check-in schedule
    // above, for the same reason (this is diagnostic telemetry, not a
    // security check).
    long long m_lastFailureReportSentAt = 0;
    // 2026: soft handling of the server's "too_early" Reject (see
    // CoordinatorCore.cpp, verify-stage Reject branch). m_softRetryNotBefore
    // is the earliest wall-clock moment (EstimatedNow() domain) at which the
    // next refresh attempt may be sent after such a Reject; it is in-memory
    // only on purpose (the persisted lease schedule is the real timer - this
    // only adds a short back-off on top of it). m_softRejectStreak bounds how
    // many too_early answers in a row are absorbed this way before the
    // ordinary Reject handling takes over again.
    long long m_softRetryNotBefore = 0;
    int m_softRejectStreak = 0;
};

} // namespace Coordinator
