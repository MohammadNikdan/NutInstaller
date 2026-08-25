#pragma once
//
// LicenseProtocol.h - Everything about turning raw bytes (the local license
// file, or a server response) into a trusted, parsed result, and nothing
// else. Per spec sections 32-33: decrypt -> parse -> verify signature ->
// THEN validate/use. Nothing here ever acts on unverified data.
//

#include <string>
#include <cstdint>
#include <map>

// A fully verified NL3 lease (either from the local file or a fresh server
// response) - only ever constructed after signature verification succeeds.
struct VerifiedLease
{
    std::string licenseId;
    long productId;
    std::string machineId;
    std::string deviceKeyHash;
    uint64_t licenseExpiresAt;
    uint64_t requestedAt;
    // The rotating single-use refresh token this lease was issued with -
    // MUST be sent back verbatim on the NEXT verify request, and is
    // replaced entirely by whatever new token that next response contains
    // (never reused). See the clone-detection design: a request presenting
    // anything other than the server's currently-stored token for this
    // license - regardless of how many generations old it is - is treated
    // as a stale/cloned-identity signal.
    std::string refreshToken;
};

// A verified challenge issuance from license_check.php's stage=challenge.
struct VerifiedChallenge
{
    std::string challengeId;
    std::string nonceB64;
    uint64_t expiresAt;
};

enum class ResponseKind
{
    Invalid,        // could not decrypt/parse/verify at all - treat as a
                    // transport failure (spec section 28)
    LegacyNo,       // decrypted to the literal "no"
    Rejected,       // NL3-REJECT|...|server_signature=... - verified valid
    Lease,          // NL3|...|server_signature=... - verified valid
    Challenge       // NL3-CHALLENGE|...|server_signature=... - verified valid
};

struct ParsedResponse
{
    ResponseKind kind = ResponseKind::Invalid;
    std::string rejectReason;         // valid only if kind == Rejected
    long long retryAfterSeconds = 0;  // valid only if kind == Rejected
    // Server-issued, signature-verified timestamp - present for BOTH
    // Rejected and Lease (Lease also carries its own copy inside
    // VerifiedLease.requestedAt for backward-compat with existing callers).
    // Fixes the confirmed gap where a Rejected response previously had no
    // verifiable timestamp at all, meaning a "valid license file, no Tier 2"
    // outcome could not be scheduled from safely (see the architecture notes).
    uint64_t requestedAt = 0;         // valid if kind == Rejected or Lease
    // The EXACT canonical string that was signed, and its RSA-SHA256
    // signature (base64) - valid for Rejected and Lease (never Challenge,
    // which the DLL never needs to re-verify itself). This is what lets the
    // Coordinator forward a re-verifiable result to the DLL over IPC instead
    // of the DLL having to trust the Coordinator's word for the outcome -
    // architecture point 15/101: "DLL باید بتواند نتیجهٔ License 2 را با یک
    // Server Signature قابل اعتبارسنجی... verify کند."
    std::string rawCanonical;         // valid if kind == Rejected or Lease
    std::string rawSignatureB64;      // valid if kind == Rejected or Lease
    VerifiedLease lease;               // valid only if kind == Lease
    VerifiedChallenge challenge;       // valid only if kind == Challenge
};

class LicenseProtocol
{
public:
    // Loads the RSA public key used to verify server_signature, from a PEM
    // file (X.509 SubjectPublicKeyInfo format, i.e. exactly what
    // `openssl rsa -pubout` produces) located next to this DLL. Must be
    // called once before any Verify*/Decrypt* call. Returns false if the
    // file is missing or malformed - callers must treat that as "cannot
    // trust anything", never as "trust anyway".
    static bool LoadServerPublicKey(const std::wstring& dllDirectory);

    // Decrypts a raw "N3:<base64>" envelope (as sent by the server or as
    // stored in the local license file) using the fixed transport key,
    // parses the plaintext's protocol framing, and - for a "NL3|...|
    // server_signature=..." payload - verifies the RSA-SHA256 signature
    // before ever returning ResponseKind::Lease. A ciphertext that fails to
    // decrypt/authenticate (wrong key, corrupted, tampered) always yields
    // ResponseKind::Invalid, never a guess at the content.
    static ParsedResponse DecryptAndVerify(const std::string& rawEnvelope);

    // Builds the "data=" POST body for a request: URL-encodes each field in
    // insertion order and GCM-encrypts the whole thing, returning the
    // "N3:<base64>" envelope ready to send as-is.
    static std::string BuildRequestEnvelope(const std::map<std::string, std::string>& fields);

    // Raw AES-256-GCM primitives, exposed for BuildRequestEnvelope/
    // DecryptAndVerify and for signing (ECDSA device-key signing still
    // lives in the neighboring Machine ID DLL for now - see MachineIdBridge.h).
    static bool GcmEncrypt(const std::string& plaintext, std::string& outEnvelope);
    static bool GcmDecrypt(const std::string& envelope, std::string& outPlaintext);

private:
    static bool VerifyRsaSha256(const std::string& canonicalMessage, const std::string& signatureB64);
    static ParsedResponse ParseLeaseOrChallenge(const std::string& plaintext, bool isChallenge);
};
