//
// NutriculaLicenseBroker.cpp - user-level Coordinator process. Runs as a
// plain background process, with NO dependency on the Windows Service
// Control Manager - this is what runs on Wine (architecture point 59/60),
// and is also the fallback on Windows when installing a real Service isn't
// possible (locked-down VPS, corporate policy, etc. - see the session's
// architecture discussion). The actual coordination logic (CoordinatorCore)
// and the wire protocol (CoordinatorProtocol.h) are IDENTICAL to what
// NutriculaLicenseService.exe uses - only the hosting/startup mechanism
// differs, per architecture point 60: "Wine نباید معماری Windows را خراب
// کند... فقط Layer hosting... تفاوت داشته باشد."
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

Coordinator::CoordinatorCore g_core;

bool SignWithCoordinatorKey(const unsigned char nonce[32], unsigned char outSignature[96])
{
    return EcdsaHelpers::SignP384(
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

    g_core.Start(CoordinatorProtocol::COORDINATOR_BROKER_FILE_NAME);
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
        if (t) CloseHandle(t);
    }
}
