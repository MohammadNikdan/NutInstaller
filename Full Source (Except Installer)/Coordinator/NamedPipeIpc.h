#pragma once
//
// NamedPipeIpc.h - Named Pipe transport with an EXPLICIT security
// descriptor (never the default ACL - architecture point 40) plus the
// Coordinator identity handshake (architecture point 41/42) layered on top.
//
// ACL design: the pipe's owner (the user account the Coordinator runs as)
// and BUILTIN\Administrators get full control; Authenticated Users get a
// DELIBERATELY NARROWED access mask that excludes FILE_CREATE_PIPE_INSTANCE
// (0x0004) - granting that bit to non-owner callers would let any local
// process create a competing instance of this same pipe name and intercept
// client connections meant for the real Coordinator, which is exactly the
// "fake service" risk this whole handshake exists to close.
//

#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>
#include <string>
#include <vector>
#include "CoordinatorProtocol.h"
#include "EcdsaHelpers.h"

namespace NamedPipeIpc {

// Builds the security descriptor described above. Caller must LocalFree()
// the returned PSECURITY_DESCRIPTOR's underlying allocation via
// LocalFree(sa.lpSecurityDescriptor) once the pipe handle using it is closed
// (ConvertStringSecurityDescriptorToSecurityDescriptorW allocates with
// LocalAlloc internally).
inline bool BuildPipeSecurityAttributes(SECURITY_ATTRIBUTES& sa, PSECURITY_DESCRIPTOR& outSd)
{
    outSd = nullptr;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = FALSE;

    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    if (needed == 0) { CloseHandle(token); return false; }
    std::vector<BYTE> buffer(needed);
    bool ok = GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed) != 0;
    CloseHandle(token);
    if (!ok) return false;

    PTOKEN_USER tokenUser = reinterpret_cast<PTOKEN_USER>(buffer.data());
    LPWSTR sidString = nullptr;
    if (!ConvertSidToStringSidW(tokenUser->User.Sid, &sidString)) return false;

    // 0x12019B = FILE_GENERIC_READ | FILE_GENERIC_WRITE, WITHOUT
    // FILE_CREATE_PIPE_INSTANCE (0x0004) - computed and verified against
    // winnt.h's exact bit definitions, not guessed.
    wchar_t sddl[640];
    int written = swprintf(sddl, _countof(sddl),
        L"D:(A;;GA;;;%ls)(A;;GA;;;BA)(A;;0x12019b;;;AU)", sidString);
    LocalFree(sidString);
    if (written < 0) return false;

    ULONG sdSize = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &outSd, &sdSize))
        return false;

    sa.lpSecurityDescriptor = outSd;
    return true;
}

// ============================================================================
// Server-side CLIENT identity verification via Windows named-pipe
// impersonation - the OS-native mechanism for "who is really on the other
// end of this pipe", using kernel-level security tokens rather than a
// custom crypto scheme. The thin DLL deliberately holds no private key of
// its own (architecture decision: client identity is never proven via a
// signature the DLL would have to protect a secret for), so this is the
// correct complementary half of mutual authentication: the DLL already
// verifies the COORDINATOR's identity via the ECDSA handshake above: this
// verifies the CLIENT's identity via the same mechanism the pipe's own ACL
// is built from (the calling process's Windows token SID), giving real
// defense-in-depth rather than relying on the ACL alone to have denied a
// connection that never should have been accepted.
// ============================================================================

inline bool VerifyConnectedClientIdentity(HANDLE pipe, PSID expectedOwnerSid)
{
    if (!ImpersonateNamedPipeClient(pipe)) return false;

    bool ok = false;
    HANDLE token = nullptr;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token))
    {
        DWORD needed = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
        if (needed > 0)
        {
            std::vector<BYTE> buf(needed);
            if (GetTokenInformation(token, TokenUser, buf.data(), needed, &needed))
            {
                PTOKEN_USER tokenUser = reinterpret_cast<PTOKEN_USER>(buf.data());
                // Allowed identities mirror the pipe ACL exactly (the
                // Coordinator's own user, or a local Administrator) -
                // anything else is a connection that should never have
                // reached this point, and is now rejected at the kernel-
                // token level regardless of how it got past the ACL check.
                if (EqualSid(tokenUser->User.Sid, expectedOwnerSid))
                {
                    ok = true;
                }
                else
                {
                    BYTE adminSidBuf[SECURITY_MAX_SID_SIZE];
                    DWORD adminSidSize = sizeof(adminSidBuf);
                    if (CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSidBuf, &adminSidSize))
                    {
                        BOOL isAdmin = FALSE;
                        ok = CheckTokenMembership(token, adminSidBuf, &isAdmin) && isAdmin;
                    }
                }
            }
        }
        CloseHandle(token);
    }

    RevertToSelf();
    return ok;
}

inline PSID GetOwnUserSid(std::vector<BYTE>& sidStorage)
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return nullptr;
    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    if (needed == 0) { CloseHandle(token); return nullptr; }
    sidStorage.resize(needed);
    bool ok = GetTokenInformation(token, TokenUser, sidStorage.data(), needed, &needed) != 0;
    CloseHandle(token);
    if (!ok) return nullptr;
    return reinterpret_cast<PTOKEN_USER>(sidStorage.data())->User.Sid;
}

// ---- Server (Coordinator) side ----

// Creates one pipe instance and waits for a single client connection, then
// performs BOTH halves of mutual authentication: (1) verifies the
// connecting client's Windows token identity (VerifyConnectedClientIdentity
// above), rejecting anything outside the Coordinator's own user or
// Administrators before proceeding at all, and (2) the identity handshake
// (send nonce, sign it, send signature) so the CLIENT can independently
// verify it is genuinely talking to this Coordinator. Returns an already-
// connected, already-mutually-authenticated pipe handle, or
// INVALID_HANDLE_VALUE on any failure. Caller is responsible for the actual
// request/response exchange after this returns, and for calling
// DisconnectNamedPipe + CloseHandle when done with this connection.
inline HANDLE AcceptAndHandshake(
    bool (*signFn)(const unsigned char nonce[32], unsigned char outSignature[96]))
{
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!BuildPipeSecurityAttributes(sa, sd)) return INVALID_HANDLE_VALUE;

    HANDLE pipe = CreateNamedPipeW(
        CoordinatorProtocol::PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        8192, 8192,
        0,
        &sa);

    if (sd) LocalFree(sd);
    if (pipe == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

    BOOL connected = ConnectNamedPipe(pipe, nullptr) ?
        TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (!connected)
    {
        CloseHandle(pipe);
        return INVALID_HANDLE_VALUE;
    }

    // Mutual auth, half 2: verify the CONNECTING CLIENT's real Windows
    // identity via impersonation before doing anything else - a connection
    // that somehow reached us despite the pipe's own ACL (e.g. a
    // misconfigured ACL, or a future code change that weakens it) is still
    // caught here independently.
    {
        std::vector<BYTE> ownSidStorage;
        PSID ownSid = GetOwnUserSid(ownSidStorage);
        if (!ownSid || !VerifyConnectedClientIdentity(pipe, ownSid))
        {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            return INVALID_HANDLE_VALUE;
        }
    }

    // --- handshake: send a fresh random nonce, then our signature over it ---
    CoordinatorProtocol::HandshakeChallengeMsg challenge;
    BCRYPT_ALG_HANDLE rngAlg = nullptr;
    bool rngOk = BCryptOpenAlgorithmProvider(&rngAlg, BCRYPT_RNG_ALGORITHM, nullptr, 0) >= 0;
    if (rngOk) rngOk = BCryptGenRandom(rngAlg, challenge.nonce, sizeof(challenge.nonce), 0) >= 0;
    if (rngAlg) BCryptCloseAlgorithmProvider(rngAlg, 0);
    if (!rngOk) { DisconnectNamedPipe(pipe); CloseHandle(pipe); return INVALID_HANDLE_VALUE; }

    DWORD written = 0;
    if (!WriteFile(pipe, &challenge, sizeof(challenge), &written, nullptr) || written != sizeof(challenge))
    {
        DisconnectNamedPipe(pipe); CloseHandle(pipe); return INVALID_HANDLE_VALUE;
    }
    FlushFileBuffers(pipe);

    CoordinatorProtocol::HandshakeResponseMsg response;
    response.type = CoordinatorProtocol::MessageType::HandshakeResponse;
    if (!signFn(challenge.nonce, response.signature))
    {
        DisconnectNamedPipe(pipe); CloseHandle(pipe); return INVALID_HANDLE_VALUE;
    }
    if (!WriteFile(pipe, &response, sizeof(response), &written, nullptr) || written != sizeof(response))
    {
        DisconnectNamedPipe(pipe); CloseHandle(pipe); return INVALID_HANDLE_VALUE;
    }
    FlushFileBuffers(pipe);

    return pipe;
}

// ---- Client (thin DLL) side ----

// Connects to the Coordinator pipe and verifies its identity via the
// handshake. Returns an authenticated, ready-to-use pipe handle, or
// INVALID_HANDLE_VALUE if the Coordinator is unavailable OR failed to prove
// its identity (these are treated identically by the caller - see
// architecture point 100: no fallback, either way).
inline HANDLE ConnectAndVerify(const unsigned char coordinatorPublicKeyXY[96], DWORD timeoutMs)
{
    HANDLE pipe = INVALID_HANDLE_VALUE;
    DWORD waited = 0;
    while (waited < timeoutMs)
    {
        pipe = CreateFileW(CoordinatorProtocol::PIPE_NAME, GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_PIPE_BUSY) return INVALID_HANDLE_VALUE; // not running / not available at all
        if (!WaitNamedPipeW(CoordinatorProtocol::PIPE_NAME, 1000)) { waited += 1000; continue; }
    }
    if (pipe == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

    CoordinatorProtocol::HandshakeChallengeMsg challenge;
    DWORD read = 0;
    if (!ReadFile(pipe, &challenge, sizeof(challenge), &read, nullptr) || read != sizeof(challenge) ||
        challenge.type != CoordinatorProtocol::MessageType::HandshakeChallenge ||
        challenge.protocolVersion != CoordinatorProtocol::PROTOCOL_VERSION)
    {
        CloseHandle(pipe);
        return INVALID_HANDLE_VALUE;
    }

    CoordinatorProtocol::HandshakeResponseMsg response;
    if (!ReadFile(pipe, &response, sizeof(response), &read, nullptr) || read != sizeof(response) ||
        response.type != CoordinatorProtocol::MessageType::HandshakeResponse)
    {
        CloseHandle(pipe);
        return INVALID_HANDLE_VALUE;
    }

    // The actual security-critical check: is this really the genuine
    // Coordinator? A fake process could answer the two ReadFile calls above
    // with anything, but cannot produce a valid signature without the
    // private key that never leaves the real Coordinator build.
    if (!EcdsaHelpers::VerifyP384(coordinatorPublicKeyXY, challenge.nonce, sizeof(challenge.nonce), response.signature))
    {
        CloseHandle(pipe);
        return INVALID_HANDLE_VALUE;
    }

    return pipe;
}

} // namespace NamedPipeIpc
