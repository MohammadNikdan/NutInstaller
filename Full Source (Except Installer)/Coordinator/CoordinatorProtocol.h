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

namespace CoordinatorProtocol {

constexpr uint32_t PROTOCOL_VERSION = 1;

// Standard artifact file names, expected to sit next to the Coordinator
// binary (Service or Broker) - the Installer places all of these in the
// same directory as part of Phase 6. Defined once here so the Coordinator's
// integrity check (ManifestVerify), NutriculaSignTool, and the Installer
// all agree on exact names without needing to duplicate the constants.
inline const wchar_t* ARTIFACT_EX5_NAME = L"Nutricula.ex5";
inline const wchar_t* ARTIFACT_EX4_NAME = L"Nutricula.ex4";
inline const wchar_t* ARTIFACT_DLL32_NAME = L"NutriculaLicenseCheck32.dll";
inline const wchar_t* ARTIFACT_DLL64_NAME = L"NutriculaLicenseCheck64.dll";
// The Machine ID DLL is loaded by BOTH the thin License Check DLL
// (NutriculaLicenseCheck32/64.dll, inside MT4/MT5) and by the Coordinator
// itself (MachineIdBridge) - a patched MachineId DLL that silently spoofs
// or freezes machine_id would defeat the entire anti-clone design without
// touching any other file, so it must be covered by the same manifest
// integrity check as everything else. Checked unconditionally (both
// architectures, every cycle) - like DLL32/64 above, not like the
// Service/Broker pair below - because a 32-bit MT4 and a 64-bit MT5 could
// both be talking to this one Coordinator instance at the same time, each
// needing its own matching MachineId DLL to be genuine.
inline const wchar_t* ARTIFACT_MACHINEID32_NAME = L"MachineId32.dll";
inline const wchar_t* ARTIFACT_MACHINEID64_NAME = L"MachineId64.dll";
// The Coordinator's own file name - the Broker is the sole Coordinator host
// on every platform (Windows and Wine alike; the Windows Service host was
// removed in 2026). It passes this name to ManifestVerify so the integrity
// check measures the exact binary that is actually running.
inline const wchar_t* COORDINATOR_BROKER_FILE_NAME = L"NutriculaLicenseBroker.exe";

// The Coordinator pipe name - identical on every platform (the host process
// is always the Broker; only WHERE it is launched from differs between
// Windows and Wine, never the protocol). See point 60 of the architecture
// notes: "Wine نباید معماری Windows را خراب کند."
inline const wchar_t* PIPE_NAME = L"\\\\.\\pipe\\NutriculaLicenseCoordinator";

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
