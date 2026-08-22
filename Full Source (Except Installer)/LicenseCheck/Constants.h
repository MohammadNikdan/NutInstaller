#pragma once
//
// Constants.h - The fixed semantics of this DLL. Every value in this file
// is either explicitly mandated by the specification ("must never change")
// or a direct, load-bearing consequence of one that is. Nothing here should
// be edited without re-reading the corresponding section of the spec.
//

// ---------------------------------------------------------------------
// INTERNAL_LICENSE_TIER - the ONLY three values this may ever hold.
// Never -1, -2, -3, or 0. Exposed to MQL via Nutricula_GetLicenseTier().
// ---------------------------------------------------------------------
const long TIER_FREE     = 1;   // License 1 / Free Mode
const long TIER_LICENSED = 2;   // License 2 / Valid Lease
const long TIER_FAILED   = -10; // 10 attempts exhausted, no trustworthy response

// ---------------------------------------------------------------------
// INTERNAL_LICENSE_TIER_PENDING - transient state of the current
// operation. Exposed to MQL via Nutricula_GetLicensePending().
// Idle value is ALWAYS -1. Never 0, ever, anywhere in this state.
// ---------------------------------------------------------------------
const long PENDING_IDLE                = -1; // Idle
const long PENDING_COMM_FAIL_RETRYING  = -2; // Last attempt failed, retry continues
const long PENDING_REFRESH_IN_PROGRESS = -3; // Another instance owns a real refresh; wait
// PENDING_* may also transiently equal TIER_FREE (1), TIER_LICENSED (2), or
// TIER_FAILED (-10) - these are the three "stable result about to be
// published to MAIN" values, reusing the same three numbers by design
// (see spec section 3: the only allowed PENDING->MAIN transitions are
// 1->1, 2->2, -10->-10).

// ---------------------------------------------------------------------
// Timing (spec sections 21-23, 76). PHP's own enforced minimum is 53:00;
// this client-side schedule (54:00 base + up to 60s random) is what keeps
// every legitimate request comfortably clear of that server-side floor,
// and this ordering must never be changed independently of the PHP side.
// ---------------------------------------------------------------------
const long long MIN_REQUEST_INTERVAL_SEC = 54LL * 60LL; // 54:00
const long long RANDOM_DELAY_MAX_SEC     = 60LL;         // up to +60s -> ceiling 55:00
const long long LICENSE_CYCLE_SEC        = 55LL * 60LL;  // informational, matches server's TTL concept

// ---------------------------------------------------------------------
// Retry (spec section 29).
// ---------------------------------------------------------------------
const int MAX_ATTEMPTS = 10;

// ---------------------------------------------------------------------
// Cross-process coordination timing. Not mandated by an exact number in
// the spec, but bounded per section 17/37 ("must be detected as stale
// after an appropriate timeout"). Chosen conservatively relative to how
// long one full attempt (challenge + verify, including network latency)
// can plausibly take, with real margin for a slow/congested connection.
// ---------------------------------------------------------------------
const long long HEARTBEAT_INTERVAL_MS   = 3000;   // owner refreshes heartbeat every 3s
const long long OWNER_STALE_AFTER_MS    = 20000;  // no heartbeat for 20s -> stale
const long long REFRESH_LEASE_MS        = 180000; // absolute cap: 3 minutes for one full owned refresh (10 attempts + delays)
const long long WAITER_POLL_INTERVAL_MS = 250;    // waiters re-check state (also woken by event)
const long long WAITER_MAX_WAIT_MS      = 200000; // a waiter never blocks longer than this before re-evaluating from scratch

// ---------------------------------------------------------------------
// Shared object names (Global\ namespace - spans sessions/terminals).
// Deliberately identical across the 32-bit and 64-bit builds of this DLL,
// and across MT4/MT5, so all instances - regardless of bitness - share
// exactly one coordination domain (spec: "must not be split into separate
// groups where 32-bit DLLs synchronize independently from 64-bit DLLs").
// ---------------------------------------------------------------------
#define SHARED_MUTEX_NAME   L"Global\\NutriculaLicenseRefreshMutex"
#define SHARED_MEMORY_NAME  L"Global\\NutriculaLicenseRefreshState"
#define SHARED_EVENT_NAME   L"Global\\NutriculaLicenseRefreshEvent"

#define SHARED_STATE_MAGIC   0x4E55544Cu // 'NUTL'
#define SHARED_STATE_VERSION 1u
