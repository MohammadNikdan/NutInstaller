//
// NutriculaLicenseBroker.cpp - the user-session Coordinator process, and the
// SOLE Coordinator host on every platform (Windows and Wine alike). Runs as
// a plain per-user background process with NO dependency on the Windows
// Service Control Manager and NO elevation. Running in the SAME session as
// the EA is exactly what this product's per-user identity model requires:
// the device key (DPAPI user-scoped) and license file live under the user's
// own profile, and the IPC handshake requires the connecting EA to share the
// Coordinator's user SID - all of which only hold when the Coordinator runs
// as the user, i.e. as this Broker. (The Windows Service host was removed in
// 2026 after it was found structurally incompatible with that model - see
// InstallerService.InstallCoordinatorAsync's own comment.)
//

#include "CoordinatorCore.h"
#include "CoordinatorProtocol.h"
#include "CoordinatorIdentityPrivate.h"
#include "NamedPipeIpc.h"
#include "EcdsaHelpers.h"
#include "VMProtectMarkers.h"

#include <windows.h>
#include <process.h>
#include <atomic>
#include <cstdio>
#include <cstring>

namespace {

Coordinator::CoordinatorCore g_core;

bool SignWithCoordinatorKey(const unsigned char nonce[32], unsigned char outSignature[64])
{
    return EcdsaHelpers::SignP256(
        CoordinatorIdentity::PrivateKeyD(),
        CoordinatorIdentity::PrivateKeyPublicXY(),
        nonce, 32, outSignature);
}

// Handles exactly one client connection end-to-end: handshake, then a
// single request/response, then closes. A fresh handshake per connection
// (rather than a long-lived session) keeps the protocol simple and matches
// how MT4/MT5 charts call Nutricula_Poll() - infrequent, short-lived asks,
// not a persistent stream.
unsigned __stdcall ServeOneClient(void* param)
{
    HANDLE pipe = static_cast<HANDLE>(param);

    CoordinatorProtocol::GetStatusMsg requestBuf;
    DWORD read = 0;
    if (!ReadFile(pipe, &requestBuf, sizeof(requestBuf), &read, nullptr) || read < sizeof(CoordinatorProtocol::MessageType))
    {
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        return 0;
    }

    // The EA/DLL just genuinely talked to us over the pipe - either
    // message type counts as "the EA is actually attached to a running
    // MetaTrader right now" (see CoordinatorCore::NoteEaActivity's own
    // comment for why WorkerLoop needs this signal).
    //
    // The pipe handle is passed in because it is the one trustworthy way to
    // learn which process this is: GetNamedPipeClientProcessId cannot be
    // influenced by the client, and from that process the Coordinator reads
    // the real paths of the Nutricula modules loaded inside it. That is what
    // the integrity check measures - see RuntimeMeasure.h.
    g_core.NoteEaActivity(pipe);

    if (requestBuf.type == CoordinatorProtocol::MessageType::GetStatus)
    {
        CoordinatorProtocol::StatusReplyMsg reply;
        int tier = 0, pending = -1;
        std::string canonical, signatureB64;
        g_core.GetPublished(tier, pending, canonical, signatureB64);

        reply.tier = tier;
        reply.pending = pending;
        reply.canonicalLen = static_cast<uint32_t>(canonical.size() < sizeof(reply.canonical) ? canonical.size() : sizeof(reply.canonical) - 1);
        memcpy(reply.canonical, canonical.data(), reply.canonicalLen);
        reply.canonical[reply.canonicalLen] = 0;
        reply.signatureLen = static_cast<uint32_t>(signatureB64.size() < sizeof(reply.signatureB64) ? signatureB64.size() : sizeof(reply.signatureB64) - 1);
        memcpy(reply.signatureB64, signatureB64.data(), reply.signatureLen);
        reply.signatureB64[reply.signatureLen] = 0;

        DWORD written = 0;
        WriteFile(pipe, &reply, sizeof(reply), &written, nullptr);
        FlushFileBuffers(pipe);
    }
    else if (requestBuf.type == CoordinatorProtocol::MessageType::RequestRefresh)
    {
        g_core.RequestRefreshIfDue();
        CoordinatorProtocol::RefreshAckMsg ack;
        DWORD written = 0;
        WriteFile(pipe, &ack, sizeof(ack), &written, nullptr);
        FlushFileBuffers(pipe);
    }

    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    return 0;
}

// =========================================================================
// 2026 hardening (project owner's explicit request, after confirming via
// code audit that a debugger attached directly to THIS process - not the
// MetaTrader terminal - could still read/live-patch the Broker's own
// in-memory state, e.g. its ClockAnchor/withinCooldown logic, even though
// such tampering alone cannot forge a Tier 2 claim from nothing or break
// the DLL's independent ~1-hour replay ceiling, both already verified by
// tracing the exact canonical/signature format: a Reject canonical has no
// machine_id field at all, so IsCanonicalBoundToThisMachine rejects it
// outright, and the DLL computes its own forward-only "now" rather than
// trusting anything the Broker reports).
//
// Same technique as the DLL's own self-debug gate (NutriculaLicenseCheckThin.cpp,
// Vela_Boot_84/NUT_SelfDebugLoopThreadProc) - see that function's long
// comment for the full mechanics and the real, accepted risk (a bug in
// this event loop can hang or crash this process; DebugSetProcessKillOnExit
// (FALSE) is what stops a problem here from doing anything worse than
// that to THIS process alone).
//
// THE TRADEOFF, stated as plainly here as it was to the project owner
// before this was written: unlike the DLL (where a fail-closed self-debug
// check only blocks the ONE EA that calls it), this Broker is a single
// shared background service - EVERY EA/chart in this Windows user session
// gets its licensing answers through it. If self-debugging fails here and
// this function refuses to start the Broker, NO EA using it gets any
// fresh license answer at all until the Broker is relaunched (each EA's
// own DLL-side pipe-fail tolerance/90-second cap and cached lease still
// apply as they always did - this does not change what happens on the EA
// side, only that the Broker will not come up to serve them while in this
// state). This is the project owner's deliberate, informed choice,
// prioritizing "never run unprotected" over "always be available."
std::atomic<bool> g_brokerSelfDebugActive{false};
std::atomic<bool> g_brokerSelfDebugAttachDone{false};

unsigned __stdcall BrokerSelfDebugLoopThreadProc(void*)
{
    // Marked (2026 hardening, project owner's explicit request): this is
    // the attach decision itself, mirroring the DLL's own
    // NUT_SelfDebugLoopThreadProc_Attach marker exactly - the highest-
    // value STATIC patch target (nopping out DebugActiveProcess or the
    // store(true) below in the shipped exe, offline, with no live
    // debugger ever attached). Deliberately scoped to just this decision,
    // not the WaitForDebugEvent loop below, for the same reason given at
    // the DLL's own marker: that loop is required boilerplate with no
    // decision worth protecting, and is unbounded/blocking.
    //
    // Must happen before DebugActiveProcess - see this block's own
    // comment above for exactly why.
    NUT_VMP_BEGIN_ULTRA("BrokerSelfDebugLoopThreadProc_Attach");
    DebugSetProcessKillOnExit(FALSE);

    if (!DebugActiveProcess(GetCurrentProcessId()))
    {
        g_brokerSelfDebugAttachDone.store(true); // decided: failed
        NUT_VMP_END();
        return 0;
    }
    g_brokerSelfDebugActive.store(true);
    g_brokerSelfDebugAttachDone.store(true); // decided: succeeded
    NUT_VMP_END();

    for (;;)
    {
        DEBUG_EVENT ev{};
        if (!WaitForDebugEvent(&ev, INFINITE))
        {
            break; // should not happen while actively self-debugging; stop cleanly rather than spin
        }

        DWORD continueStatus = DBG_CONTINUE;
        if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        {
            // Never claim to have handled an exception - pass it through
            // exactly as it would behave with no debugger present, so
            // none of this process's own exception handling is ever
            // silently altered by this self-debug session existing.
            continueStatus = DBG_EXCEPTION_NOT_HANDLED;
        }

        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, continueStatus);

        if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
        {
            break; // this process (itself) is exiting normally
        }
    }

    g_brokerSelfDebugActive.store(false);
    return 0;
}

// Runtime watchdog (defense-in-depth for AFTER the boot-time gate below
// has already confirmed self-debugging is active): if that self-debug
// session ever ends on its own later for any reason, external attachment
// becomes possible again - this notices that specific condition
// (g_brokerSelfDebugActive having gone back to false after genuinely
// having been true) and ends the process rather than silently continuing
// to run unprotected.
unsigned __stdcall BrokerDebugWatchdogThreadProc(void*)
{
    bool wasActive = false;
    for (;;)
    {
        Sleep(1000);
        // Marked (2026 hardening): the whole per-iteration check-and-react
        // body, mirroring NUT_WatchdogThreadProc_Check in the DLL. Runs
        // once a second - never hot-path - so ULTRA costs nothing
        // meaningful here.
        NUT_VMP_BEGIN_ULTRA("BrokerDebugWatchdogThreadProc_Check");
        const bool isActive = g_brokerSelfDebugActive.load();
        if (wasActive && !isActive)
        {
            printf("Self-debug session ended unexpectedly - exiting rather than running unprotected.\n");
            NUT_VMP_END();
            TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
        }
        NUT_VMP_END();
        wasActive = isActive;
    }
}

} // namespace

int main()
{
    // Singleton enforcement (architecture point 7/63): a second Broker
    // instance must never coordinate independently - CreateMutexW's
    // ERROR_ALREADY_EXISTS is the standard, simple way to detect this.
    HANDLE singletonMutex = CreateMutexW(nullptr, TRUE, L"Local\\NutriculaLicenseBrokerSingleton");
    if (!singletonMutex || GetLastError() == ERROR_ALREADY_EXISTS)
    {
        printf("Another Broker instance is already running - exiting.\n");
        return 1;
    }

    // 2026 hardening: fail closed if this process cannot become its own
    // debugger - see the long comment above BrokerSelfDebugLoopThreadProc
    // for the full mechanics and the explicit availability tradeoff this
    // accepts. DebugActiveProcess itself resolves almost immediately; this
    // bounded ~1 second spin only covers ordinary thread-scheduling delay.
    {
        // Marked (2026 hardening): the fail-closed check itself, mirroring
        // Vela_Boot_84_SelfDebugGate in the DLL - forcing
        // g_brokerSelfDebugActive to read true here, or deleting this
        // block, silently reverts to fail-open.
        NUT_VMP_BEGIN_ULTRA("BrokerMain_SelfDebugGate");
        HANDLE selfDebugThread = (HANDLE)_beginthreadex(nullptr, 0, BrokerSelfDebugLoopThreadProc, nullptr, 0, nullptr);
        if (selfDebugThread) CloseHandle(selfDebugThread);

        for (int i = 0; i < 100 && !g_brokerSelfDebugAttachDone.load(); ++i)
        {
            Sleep(10);
        }

        if (!g_brokerSelfDebugActive.load())
        {
            printf("Could not establish exclusive debug access to this process (a debugger may already be attached) - refusing to start.\n");
            NUT_VMP_END();
            return 1;
        }
        NUT_VMP_END();
    }
    {
        HANDLE watchdogThread = (HANDLE)_beginthreadex(nullptr, 0, BrokerDebugWatchdogThreadProc, nullptr, 0, nullptr);
        if (watchdogThread) CloseHandle(watchdogThread);
    }

    g_core.Start();
    printf("Nutricula License Broker started. Waiting for client connections...\n");

    for (;;)
    {
        HANDLE pipe = NamedPipeIpc::AcceptAndHandshake(SignWithCoordinatorKey);
        if (pipe == INVALID_HANDLE_VALUE)
        {
            Sleep(500);
            continue;
        }
        // One thread per connection - connections are brief (a single
        // request/response), so this is simple and adequate; a thread pool
        // would only matter under far higher concurrency than N MT4/MT5
        // charts polling every few seconds.
        HANDLE t = (HANDLE)_beginthreadex(nullptr, 0, ServeOneClient, pipe, 0, nullptr);
        if (t)
        {
            CloseHandle(t);
        }
        else
        {
            // Thread spawn failed: ServeOneClient (which normally owns and
            // closes this pipe) will never run, so disconnect and close it
            // here - otherwise this pipe instance is leaked for the life of
            // the process and the connected client hangs waiting for a reply
            // that will never come.
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
        }
    }
}
