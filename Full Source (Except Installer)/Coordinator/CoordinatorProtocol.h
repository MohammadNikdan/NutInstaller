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
// The Coordinator's own file name differs between the Windows Service and
// the Wine/fallback Broker - each binary should pass its OWN file name to
// ManifestVerify, not a shared constant, since a Service checking a
// Broker's hash (or vice versa) would never match.
inline const wchar_t* COORDINATOR_SERVICE_FILE_NAME = L"NutriculaLicenseService.exe";
inline const wchar_t* COORDINATOR_BROKER_FILE_NAME = L"NutriculaLicenseBroker.exe";

// Must match the pipe name used by both the Windows Service and the Wine
// Broker - this is intentionally the SAME name on both platforms (the
// hosting mechanism differs, the protocol does not). See point 60 of the
// architecture notes: "Wine نباید معماری Windows را خراب کند."
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
    int32_t tier = 0;           // INTERNAL_LICENSE_TIER - only ever 1, 2, -10, -50, or -100 when meaningful
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
