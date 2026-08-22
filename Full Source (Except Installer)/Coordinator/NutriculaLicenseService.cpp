//
// NutriculaLicenseService.cpp - Windows Service host for the SAME
// CoordinatorCore and wire protocol the Broker uses (architecture point
// 60: only the hosting mechanism differs between Windows and Wine, never
// the coordination logic or protocol itself). Runs as a real Windows
// Service (SCM-managed), started once with elevation at install time,
// requiring no further elevation for normal operation afterward.
//
// HONESTY NOTE (per architecture point 129/57): this file is compile-
// checked but has NOT been runtime-tested end-to-end against a real
// Windows Service Control Manager - Wine's SCM emulation is not a reliable
// substitute for testing actual service install/start/stop lifecycle
// behavior. This needs verification on real Windows before production use
// - see the "things that must be tested" list.
//

#include "CoordinatorCore.h"
#include "CoordinatorProtocol.h"
#include "CoordinatorIdentityPrivate.h"
#include "NamedPipeIpc.h"
#include "EcdsaHelpers.h"

#include <windows.h>
#include <process.h>
#include <cstdio>
#include <cstring>

namespace {

const wchar_t* SERVICE_NAME = L"NutriculaLicenseService";

Coordinator::CoordinatorCore g_core;
SERVICE_STATUS g_status = {};
SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
HANDLE g_stopEvent = nullptr;

bool SignWithCoordinatorKey(const unsigned char nonce[32], unsigned char outSignature[96])
{
    return EcdsaHelpers::SignP384(
        CoordinatorIdentity::PrivateKeyD(),
        CoordinatorIdentity::PrivateKeyPublicXY(),
        nonce, 32, outSignature);
}

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

unsigned __stdcall PipeAcceptLoop(void*)
{
    for (;;)
    {
        if (WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0) break;

        HANDLE pipe = NamedPipeIpc::AcceptAndHandshake(SignWithCoordinatorKey);
        if (pipe == INVALID_HANDLE_VALUE)
        {
            Sleep(500);
            continue;
        }
        HANDLE t = (HANDLE)_beginthreadex(nullptr, 0, ServeOneClient, pipe, 0, nullptr);
        if (t) CloseHandle(t);
    }
    return 0;
}

void WINAPI ServiceCtrlHandler(DWORD ctrl)
{
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN)
    {
        g_status.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_statusHandle, &g_status);
        if (g_stopEvent) SetEvent(g_stopEvent);
    }
}

void WINAPI ServiceMain(DWORD, LPWSTR*)
{
    g_statusHandle = RegisterServiceCtrlHandlerW(SERVICE_NAME, ServiceCtrlHandler);
    if (!g_statusHandle) return;

    ZeroMemory(&g_status, sizeof(g_status));
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = SERVICE_START_PENDING;
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_statusHandle, &g_status);

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    // Singleton enforcement, same as the Broker - a second Service instance
    // (or a rogue Broker fallback also running) must never coordinate
    // independently (architecture point 7/63).
    HANDLE singletonMutex = CreateMutexW(nullptr, TRUE, L"Local\\NutriculaLicenseCoordinatorSingleton");
    if (!singletonMutex || GetLastError() == ERROR_ALREADY_EXISTS)
    {
        g_status.dwCurrentState = SERVICE_STOPPED;
        g_status.dwWin32ExitCode = ERROR_SERVICE_ALREADY_RUNNING;
        SetServiceStatus(g_statusHandle, &g_status);
        return;
    }

    g_core.Start(CoordinatorProtocol::COORDINATOR_SERVICE_FILE_NAME);

    HANDLE acceptThread = (HANDLE)_beginthreadex(nullptr, 0, PipeAcceptLoop, nullptr, 0, nullptr);

    g_status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_statusHandle, &g_status);

    WaitForSingleObject(g_stopEvent, INFINITE);

    if (acceptThread)
    {
        WaitForSingleObject(acceptThread, 5000);
        CloseHandle(acceptThread);
    }

    g_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_statusHandle, &g_status);
}

} // namespace

int main(int argc, char** argv)
{
    // Support --install / --uninstall for setup convenience (still requires
    // the calling process to already be elevated - this does not itself
    // grant elevation, it just wraps the SCM calls). Actual elevation
    // prompting is the Installer's responsibility.
    if (argc > 1 && strcmp(argv[1], "--install") == 0)
    {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!scm) { printf("OpenSCManager failed: %lu (are you elevated?)\n", GetLastError()); return 1; }
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        // Least-privilege: LocalService is sufficient - the Coordinator
        // needs no special system privileges beyond its own file/registry/
        // network access, all of which LocalService already has.
        SC_HANDLE svc = CreateServiceW(scm, SERVICE_NAME, SERVICE_NAME,
            SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL, path, nullptr, nullptr, nullptr,
            L"NT AUTHORITY\\LocalService", nullptr);
        if (!svc) { printf("CreateService failed: %lu\n", GetLastError()); CloseServiceHandle(scm); return 1; }
        printf("Service installed.\n");
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--uninstall") == 0)
    {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) { printf("OpenSCManager failed: %lu\n", GetLastError()); return 1; }
        SC_HANDLE svc = OpenServiceW(scm, SERVICE_NAME, DELETE | SERVICE_STOP);
        if (svc) { ControlService(svc, SERVICE_CONTROL_STOP, nullptr); DeleteService(svc); CloseServiceHandle(svc); }
        CloseServiceHandle(scm);
        printf("Service uninstalled.\n");
        return 0;
    }

    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(SERVICE_NAME), ServiceMain },
        { nullptr, nullptr }
    };
    if (!StartServiceCtrlDispatcherW(table))
    {
        printf("StartServiceCtrlDispatcherW failed: %lu (run with --install first, or run as a Service, not directly)\n", GetLastError());
        return 1;
    }
    return 0;
}
