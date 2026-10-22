#pragma once
//
// CoordinatorProtocol.h - the wire format for the Named Pipe conversation
// between the thin License DLL (client) and the Coordinator (Service on
// Windows, Broker on Wine). Shared verbatim by both sides so the message
// layout can never drift between client and server builds.
//
// Handshake (every connection, before any request is honored):
//   1. Client connects to the pipe.
//   2. Server sends a HandshakeChallenge (random 32-byte nonce).
//   3. Client does not need to prove anything back (this is server-to-client
//      authentication only - the client is proving to ITSELF that it is
//      really talking to the genuine Coordinator, not a fake one). The
//      client verifies HandshakeResponse.signature against the Coordinator
//      Identity public key compiled into the DLL (see CoordinatorIdentity.h).
//      If verification fails, the client disconnects immediately and treats
//      the Coordinator as unavailable - see Nutricula_Poll's "no fallback"
//      rule.
//   4. Only after a verified handshake does the client send a real request.
//
// Everything is fixed-size, POD, no pointers - safe to memcpy across the
// pipe boundary directly.
//

#include <cstdint>
#include <string>

namespace CoordinatorProtocol {

constexpr uint32_t PROTOCOL_VERSION = 1;

// The shipped artifacts' file names, defined once here so NutriculaSignTool
// (which hashes the build outputs into the signed manifest) and the
// Coordinator (which looks for these modules inside a running MetaTrader -
// see RuntimeMeasure.cpp) can never disagree about a name.
//
// 2026: these are no longer "files expected to sit next to the Coordinator".
// The Coordinator stopped keeping private copies of the EA and the DLLs to
// hash, because hashing a copy proves nothing about the file that is
// actually running - see RuntimeMeasure.h. EX4/EX5 therefore appear here
// only as build-output names for the signing tool; the Coordinator finds the
// EA by scanning the terminal's own Experts tree, where it may legitimately
// carry any name at all.
inline const wchar_t* ARTIFACT_EX5_NAME = L"Nutricula.ex5";
inline const wchar_t* ARTIFACT_EX4_NAME = L"Nutricula.ex4";
// Matched against the base names in a MetaTrader process's real module list
// to find the License Check DLL that is genuinely loaded there, and to tell
// its architecture apart.
inline const wchar_t* ARTIFACT_DLL32_NAME = L"NutriculaLicenseCheck32.dll";
inline const wchar_t* ARTIFACT_DLL64_NAME = L"NutriculaLicenseCheck64.dll";
// The Machine ID DLL. A patched copy that silently spoofs or freezes
// machine_id would defeat the entire anti-clone design without touching any
// other file, so wherever one is genuinely LOADED it is measured: inside the
// Coordinator (which loads it through MachineIdBridge) always, and inside a
// MetaTrader process whenever that process turns out to have one loaded.
// A copy that merely sits on disk unloaded is not measured, because it
// cannot influence anything.
inline const wchar_t* ARTIFACT_MACHINEID32_NAME = L"MachineId32.dll";
inline const wchar_t* ARTIFACT_MACHINEID64_NAME = L"MachineId64.dll";

// The Coordinator pipe name - identical on every platform (the host process
// is always the Broker; only WHERE it is launched from differs between
// Windows and Wine, never the protocol). See point 60 of the architecture
// notes: "Wine نباید معماری Windows را خراب کند."
//
// Obfuscated at rest (2026 hardening): unlike the ARTIFACT_*_NAME constants
// above (which name files an attacker can already see with a plain `dir` -
// obfuscating those would buy nothing), this pipe name is NOT otherwise
// visible anywhere - it only ever exists as a literal in the compiled
// binary, where a single `strings.exe` pass used to hand it over for free
// to anyone looking for which named pipe to connect to or spy on. It is now
// stored XOR-encoded against a fixed per-build byte and decoded once, into
// a function-local static std::wstring, the first time PIPE_NAME is
// touched - every existing call site keeps using `PIPE_NAME` exactly as
// before (still a plain `const wchar_t*`), so nothing else in this header
// or its callers needs to change.
namespace detail {
    constexpr wchar_t PIPE_NAME_KEY = 0x37;
    constexpr wchar_t PIPE_NAME_ENCODED[] = {
        0x006B, 0x006B, 0x0019, 0x006B, 0x0047, 0x005E, 0x0047, 0x0052,
        0x006B, 0x0079, 0x0042, 0x0043, 0x0045, 0x005E, 0x0054, 0x0042,
        0x005B, 0x0056, 0x007B, 0x005E, 0x0054, 0x0052, 0x0059, 0x0044,
        0x0052, 0x0074, 0x0058, 0x0058, 0x0045, 0x0053, 0x005E, 0x0059,
        0x0056, 0x0043, 0x0058, 0x0045
    }; // decodes to L"\\.\pipe\NutriculaLicenseCoordinator" (36 chars, no change in meaning)

    inline const wchar_t* DecodedPipeName()
    {
        static const std::wstring decoded = [] {
            std::wstring s;
            s.reserve(sizeof(PIPE_NAME_ENCODED) / sizeof(wchar_t));
            for (wchar_t c : PIPE_NAME_ENCODED) s.push_back(static_cast<wchar_t>(c ^ PIPE_NAME_KEY));
            return s;
        }();
        return decoded.c_str();
    }
}
inline const wchar_t* PIPE_NAME = detail::DecodedPipeName();

enum class MessageType : uint32_t {
    HandshakeChallenge = 1,   // server -> client
    HandshakeResponse  = 2,   // server -> client (signed nonce)
    GetStatus          = 10,  // client -> server: "what's the current published state"
    StatusReply         = 11,  // server -> client
    RequestRefresh      = 12,  // client -> server: "please ensure a refresh is happening/scheduled"
    RefreshAck           = 13,  // server -> client: idempotent ack, not a promise of immediate action
};

#pragma pack(push, 1)

struct HandshakeChallengeMsg {
    MessageType type = MessageType::HandshakeChallenge;
    uint32_t protocolVersion = PROTOCOL_VERSION;
    unsigned char nonce[32];
};

struct HandshakeResponseMsg {
    MessageType type = MessageType::HandshakeResponse;
    // Raw P-256 ECDSA signature (r||s, 64 bytes) over the exact 32-byte
    // nonce from HandshakeChallengeMsg, made with the Coordinator's private
    // identity key. Verified by the client against the public key compiled
    // into the DLL - see CoordinatorIdentity.h.
    // MIGRATED FROM P-384 TO P-256 (2026) - see EcdsaHelpers.h.
    unsigned char signature[64];
};

// Client -> Server: ask for the current published Tier/Pending, and the
// license identity this client believes it's asking about (so multiple
// different licenses on the same machine, e.g. different products, could in
// principle be distinguished in a future revision - currently informational
// only, the Coordinator tracks exactly one license per machine).
struct GetStatusMsg {
    MessageType type = MessageType::GetStatus;
};

// Server -> Client: the Coordinator's own view of Tier/Pending, PLUS the
// most-recently-verified server response as PLAINTEXT canonical-string +
// RSA signature (already GCM-decrypted by the Coordinator, which alone
// holds TRANSPORT_KEY - see architecture point 77) so the CLIENT can
// independently re-verify the RSA signature itself rather than trusting the
// Coordinator's word for it - see architecture point 15. GCM confidentiality
// only ever protected the payload in transit over the network; once it's
// been received locally, forwarding the decrypted-but-still-signed canonical
// string over the ACL-protected local pipe loses nothing, and lets the DLL
// hold no transport secret at all while still doing real, independent
// signature verification. signatureLen==0/canonicalLen==0 means "no
// verified response available yet" (e.g. still Idle).
struct StatusReplyMsg {
    MessageType type = MessageType::StatusReply;
    int32_t tier = 0;           // INTERNAL_LICENSE_TIER - only ever 1, 2, -5, -10, -50, or -100 when meaningful (-5 = license file locked/blocked, unsigned, latched by the DLL)
    int32_t pending = -1;       // INTERNAL_LICENSE_TIER_PENDING
    uint32_t canonicalLen = 0;
    char canonical[4096];       // e.g. "v=3|reason=...|requested_at=..." or the lease canonical - NUL-padded
    uint32_t signatureLen = 0;
    char signatureB64[800];     // base64 RSA-SHA256 signature over `canonical` exactly as received from the server - NUL-padded. RSA-4096 (the key now in use) produces a 512-byte raw signature = 684 base64 chars; 800 leaves comfortable margin.
};

struct RequestRefreshMsg {
    MessageType type = MessageType::RequestRefresh;
};

struct RefreshAckMsg {
    MessageType type = MessageType::RefreshAck;
};

#pragma pack(pop)

} // namespace CoordinatorProtocol
