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
        bool everCompletedFreeCheckin = false;
        g_core.GetPublished(tier, pending, canonical, signatureB64, everCompletedFreeCheckin);

        reply.tier = tier;
        reply.pending = pending;
        reply.canonicalLen = static_cast<uint32_t>(canonical.size() < sizeof(reply.canonical) ? canonical.size() : sizeof(reply.canonical) - 1);
        memcpy(reply.canonical, canonical.data(), reply.canonicalLen);
        reply.canonical[reply.canonicalLen] = 0;
        reply.signatureLen = static_cast<uint32_t>(signatureB64.size() < sizeof(reply.signatureB64) ? signatureB64.size() : sizeof(reply.signatureB64) - 1);
        memcpy(reply.signatureB64, signatureB64.data(), reply.signatureLen);
        reply.signatureB64[reply.signatureLen] = 0;
        reply.everCompletedFreeCheckin = everCompletedFreeCheckin ? 1u : 0u;

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
// REMOVED (previously in this exact spot): a self-debug gate using the
// same technique the DLL used to have (NutriculaLicenseCheckThin.cpp,
// Vela_Boot_84/NUT_SelfDebugLoopThreadProc - see the comment left in its
// place there for the full story). Removed for the identical reason:
// DebugActiveProcess(GetCurrentProcessId()) can never succeed on any
// version of Windows - NtDebugActiveProcess hard-codes a same-PID check
// and unconditionally returns STATUS_ACCESS_DENIED whenever the target
// PID equals the caller's own PID. This means the Broker's own
// self-debug gate in main() (below) was, in effect, always refusing to
// start from the moment it was added - printf() output that would have
// shown this is a silent no-op in this -mwindows build with no console
// attached, which is why it went unnoticed.
//
// IsDebuggerAttached() below replaces it with the same four-method
// user-mode check the DLL already uses (IsDebuggerPresent,
// CheckRemoteDebuggerPresent, the ProcessDebugPort query, and a coarse
// timing check) - the Broker never had one of its own before; it relied
// entirely on self-debug for user-mode coverage.
//
// THE TRADEOFF, stated as plainly here as it was to the project owner
// before the original self-debug gate was written, and equally true of
// this check: unlike the DLL (where a fail-closed check only blocks the
// ONE EA that calls it), this Broker is a single shared background
// service - EVERY EA/chart in this Windows user session gets its
// licensing answers through it. If this check finds a debugger already
// attached and refuses to start the Broker, NO EA using it gets any
// fresh license answer at all until the Broker is relaunched (each EA's
// own DLL-side pipe-fail tolerance/90-second cap and cached lease still
// apply as they always did - this does not change what happens on the EA
// side, only that the Broker will not come up to serve them while in this
// state). This is the project owner's deliberate, informed choice,
// prioritizing "never run unprotected" over "always be available."
using NtQueryInformationProcessFn = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

// Mirrors NutriculaLicenseCheckThin.cpp's IsDebuggerAttached exactly - see
// that function's own comment for the full rationale of each method.
__attribute__((noinline)) bool IsDebuggerAttached()
{
    NUT_VMP_BEGIN_ULTRA("IsDebuggerAttached");
    if (IsDebuggerPresent()) { NUT_VMP_END(); return true; }

    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger) { NUT_VMP_END(); return true; }

    HMODULE ntdllForDebugPort = GetModuleHandleA("ntdll.dll");
    if (ntdllForDebugPort)
    {
        auto ntQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessFn>(
            GetProcAddress(ntdllForDebugPort, "NtQueryInformationProcess"));
        if (ntQueryInformationProcess)
        {
            const ULONG ProcessDebugPort = 7;
            DWORD_PTR debugPort = 0;
            ULONG returned = 0;
            if (ntQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort,
                &debugPort, sizeof(debugPort), &returned) == 0 && debugPort != 0)
            {
                NUT_VMP_END();
                return true;
            }
        }
    }
    NUT_VMP_END();

    // FIX (2026 hardening): this timing check used to sit inside the
    // NUT_VMP_BEGIN_ULTRA/_END block above - see the identical fix and its
    // full explanation in NutriculaLicenseCheckThin.cpp's own copy of this
    // function. VM-interpreted code is inherently much slower than native
    // code, so this loop routinely exceeded the 50ms threshold on its own
    // once actually run through real Ultra virtualization, with no
    // debugger involved. Left outside any marker now, so it measures
    // genuine native wall-clock time.
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

// =========================================================================
// Kernel-mode debugger detection (2026 hardening, project owner's explicit
// request, mirroring NutriculaLicenseCheckThin.cpp's IsKernelDebuggerActive
// exactly - see that function's own comment for the full rationale).
// VMProtect's own built-in debugger detection was deliberately left OFF
// for this build while the Broker's self-debug gate above was still
// active (it would have conflicted with it); now that self-debug has
// been removed, VMProtect's built-in detection (user-mode + kernel-mode
// together) can safely be enabled, and this function stays regardless as
// an independent, non-VMProtect-dependent layer.
//
// SystemKernelDebuggerInformation (class 35) is the standard, long-stable
// NtQuerySystemInformation class for this - identical to the DLL's own
// copy of this function, resolved via GetProcAddress rather than linking
// ntdll.lib directly.
using NtQuerySystemInformationFn = LONG(WINAPI*)(ULONG, PVOID, ULONG, PULONG);

struct NUT_SystemKernelDebuggerInformation
{
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
};

// __attribute__((noinline)) (2026 fix, same reasoning as the DLL's own
// copy of this function in NutriculaLicenseCheckThin.cpp): called from
// inside BrokerDebugWatchdogThreadProc_Check's and BrokerMain_
// KernelDebugGate's own marked regions below. Left inlinable, GCC's -O2
// could fold this function's body - and its own "IsKernelDebuggerActive"
// Begin/End marker pair - directly into one of those callers, the same
// "address already used" hazard already found and fixed elsewhere in
// this project this session. Not yet seen in a VMProtect run (this
// function is large enough that GCC likely never actually chose to
// inline it), but it is the identical hazard, fixed pre-emptively.
__attribute__((noinline)) bool IsKernelDebuggerActive()
{
    // Marked (2026 hardening, found during a re-check of marker coverage):
    // called from two already-marked decision points
    // (BrokerMain_KernelDebugGate and BrokerDebugWatchdogThreadProc_Check)
    // - a single static patch to this shared function alone, forcing it to
    // always return false, would defeat both at once. Four linear exits,
    // each covered by its own END below. Mirrors the DLL's own
    // IsKernelDebuggerActive marker exactly.
    NUT_VMP_BEGIN_ULTRA("IsKernelDebuggerActive");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) { NUT_VMP_END(); return false; }

    auto ntQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!ntQuerySystemInformation) { NUT_VMP_END(); return false; }

    const ULONG SystemKernelDebuggerInformation = 35;
    NUT_SystemKernelDebuggerInformation info{};
    ULONG returned = 0;
    if (ntQuerySystemInformation(SystemKernelDebuggerInformation, &info, sizeof(info), &returned) != 0)
    {
        // Fail open on the QUERY only (not on a detected debugger) - a
        // failed query is not evidence of a kernel debugger, and a false
        // positive here would deny every EA in this session their license
        // for no real reason.
        NUT_VMP_END();
        return false;
    }

    // KernelDebuggerEnabled alone only means kernel-debugging support is
    // switched on; KernelDebuggerNotPresent == FALSE is what confirms a
    // kernel debugger is actually attached right now. Both are required.
    auto __nut_vmp_r = info.KernelDebuggerEnabled && !info.KernelDebuggerNotPresent;
    NUT_VMP_END();
    return __nut_vmp_r;
}

// REMOVED (previously in this exact spot): BrokerSelfDebugLoopThreadProc,
// the Broker's own copy of the same self-debug mechanism the DLL used to
// have - see the comment left in NutriculaLicenseCheckThin.cpp where
// NUT_SelfDebugLoopThreadProc used to be for the full story. Because
// DebugActiveProcess(GetCurrentProcessId()) can never succeed, this
// function's attach always failed, which in turn means main()'s
// self-debug gate below was always refusing to start the Broker - see
// that gate's own comment for why this went unnoticed.

// Runtime watchdog (defense-in-depth for AFTER the boot-time gates below
// have already passed): polls for a debugger attaching later and ends the
// process rather than silently continuing to run unprotected.
unsigned __stdcall BrokerDebugWatchdogThreadProc(void*)
{
    for (;;)
    {
        Sleep(1000);
        // Marked (2026 hardening): only the decision itself (the two
        // boolean checks) - mirroring NUT_WatchdogThreadProc_Check in the
        // DLL after its own 2026 fix. The reaction (log, printf,
        // TerminateProcess) is deliberately native, outside the marker -
        // see the DLL's own copy of this fix for the full rationale
        // (blocking/IO code has no place inside a virtualized region).
        NUT_VMP_BEGIN_ULTRA("BrokerDebugWatchdogThreadProc_Check");
        const bool userModeHit = IsDebuggerAttached();
        // Independent of the user-mode check entirely - see
        // IsKernelDebuggerActive's own comment for why.
        const bool kernelModeHit = !userModeHit && IsKernelDebuggerActive();
        NUT_VMP_END();

        if (userModeHit || kernelModeHit)
        {
            printf("%s - exiting rather than running unprotected.\n",
                kernelModeHit ? "Kernel-mode debugger detected" : "User-mode debugger detected");
            TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
        }
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

    // 2026 hardening: fail closed if a user-mode debugger is already
    // attached at startup. This used to be enforced via a self-debug gate
    // (BrokerSelfDebugLoopThreadProc, removed - see its own comment
    // above for why: DebugActiveProcess(GetCurrentProcessId()) can never
    // succeed, which meant this gate was always refusing to start the
    // Broker, silently, since -mwindows gives this exe no console for
    // the printf below to actually reach anyone). This gate now reuses
    // IsDebuggerAttached() directly instead.
    {
        // Marked (2026 hardening): the fail-closed check itself - forcing
        // this condition to always read false, or deleting this block,
        // silently reverts to fail-open.
        NUT_VMP_BEGIN_ULTRA("BrokerMain_DebuggerGate");
        if (IsDebuggerAttached())
        {
            printf("Could not establish exclusive debug access to this process (a debugger may already be attached) - refusing to start.\n");
            NUT_VMP_END();
            return 1;
        }
        NUT_VMP_END();
    }
    {
        // Kernel-mode fail-closed check (2026 hardening, project owner's
        // explicit request): self-debugging above only ever covers user-
        // mode debuggers - see IsKernelDebuggerActive's own comment for
        // why a kernel debugger needs this completely separate check.
        // Same policy as the self-debug gate just above: refuse to start
        // at all rather than run with a kernel debugger already attached.
        NUT_VMP_BEGIN_ULTRA("BrokerMain_KernelDebugGate");
        if (IsKernelDebuggerActive())
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
