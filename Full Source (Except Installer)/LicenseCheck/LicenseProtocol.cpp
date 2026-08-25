#include "LicenseProtocol.h"
#include "ServerSignatureVerify.h"
#include "TransportKeyPrivate.h"
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <vector>
#include <sstream>
#include <fstream>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace
{
    using LicenseProtocolInternal::TRANSPORT_KEY;

    BCRYPT_KEY_HANDLE g_rsaPublicKey = nullptr;

    // ---- Base64 ----
    bool Base64Encode(const std::vector<unsigned char>& data, std::string& out)
    {
        DWORD outLen = 0;
        if (!CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &outLen)) return false;
        out.resize(outLen);
        if (!CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &out[0], &outLen)) return false;
        out.resize(strnlen(out.c_str(), outLen)); // strip the trailing NUL CryptBinaryToStringA counts
        return true;
    }

    bool Base64Decode(const std::string& b64, std::vector<unsigned char>& out)
    {
        DWORD outLen = 0;
        if (!CryptStringToBinaryA(b64.c_str(), static_cast<DWORD>(b64.size()),
            CRYPT_STRING_BASE64, nullptr, &outLen, nullptr, nullptr)) return false;
        out.resize(outLen);
        return CryptStringToBinaryA(b64.c_str(), static_cast<DWORD>(b64.size()),
            CRYPT_STRING_BASE64, out.data(), &outLen, nullptr, nullptr) != 0;
    }

    // ---- URL encode/decode (RFC 3986, matching Uri.EscapeDataString /
    //      PHP rawurlencode - the same convention already used throughout
    //      the rest of this protocol) ----
    std::string UrlEncode(const std::string& s)
    {
        static const char* hex = "0123456789ABCDEF";
        std::string out;
        out.reserve(s.size() * 3);
        for (unsigned char c : s)
        {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
                out.push_back(static_cast<char>(c));
            else
            {
                out.push_back('%');
                out.push_back(hex[(c >> 4) & 0xF]);
                out.push_back(hex[c & 0xF]);
            }
        }
        return out;
    }

    bool UrlDecode(const std::string& s, std::string& out)
    {
        out.clear();
        out.reserve(s.size());
        for (size_t i = 0; i < s.size(); i++)
        {
            if (s[i] == '%')
            {
                if (i + 2 >= s.size()) return false;
                auto hexVal = [](char c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                    return -1;
                };
                int hi = hexVal(s[i + 1]);
                int lo = hexVal(s[i + 2]);
                if (hi < 0 || lo < 0) return false; // malformed percent-encoding - reject, don't guess
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
            }
            else
            {
                out.push_back(s[i]);
            }
        }
        return true;
    }

    // Response formats (NL3|, NL3-REJECT|, NL3-CHALLENGE|) use "|" as the
    // field delimiter and are NOT URL-encoded - this is a different wire
    // convention from the "&"-delimited, URL-encoded REQUEST body that
    // ParseFields (above) is for. Mixing these up silently breaks field
    // extraction without necessarily breaking signature verification
    // itself, so this distinction matters even though both "look similar".
    std::map<std::string, std::string> ParsePipeDelimitedFields(const std::string& body)
    {
        std::map<std::string, std::string> fields;
        std::stringstream ss(body);
        std::string pair;
        while (std::getline(ss, pair, '|'))
        {
            if (pair.empty()) continue;
            size_t eq = pair.find('=');
            if (eq == std::string::npos) continue;
            fields[pair.substr(0, eq)] = pair.substr(eq + 1);
        }
        return fields;
    }
    std::map<std::string, std::string> ParseFields(const std::string& body)
    {
        std::map<std::string, std::string> fields;
        std::stringstream ss(body);
        std::string pair;
        while (std::getline(ss, pair, '&'))
        {
            if (pair.empty()) continue;
            size_t eq = pair.find('=');
            if (eq == std::string::npos) continue;
            std::string key, value;
            if (!UrlDecode(pair.substr(0, eq), key)) continue;
            if (!UrlDecode(pair.substr(eq + 1), value)) continue;
            fields[key] = value;
        }
        return fields;
    }

    unsigned long long ParseU64(const std::string& s)
    {
        unsigned long long v = 0;
        for (char c : s) { if (c < '0' || c > '9') return 0; v = v * 10 + (c - '0'); }
        return v;
    }

    // ---- AES-256-GCM ----
    bool AesGcmEncrypt(const unsigned char* plaintext, size_t plaintextLen,
        std::vector<unsigned char>& outNonceTagCipher)
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0) return false;
        if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0)
        {
            BCryptCloseAlgorithmProvider(alg, 0); return false;
        }

        BCRYPT_KEY_HANDLE key = nullptr;
        if (BCryptGenerateSymmetricKey(alg, &key, nullptr, 0,
            (PUCHAR)TRANSPORT_KEY, sizeof(TRANSPORT_KEY), 0) < 0)
        {
            BCryptCloseAlgorithmProvider(alg, 0); return false;
        }

        unsigned char nonce[12];
        BCRYPT_ALG_HANDLE rngAlg = nullptr;
        BCryptOpenAlgorithmProvider(&rngAlg, BCRYPT_RNG_ALGORITHM, nullptr, 0);
        BCryptGenRandom(rngAlg, nonce, sizeof(nonce), 0);
        BCryptCloseAlgorithmProvider(rngAlg, 0);

        std::vector<unsigned char> cipher(plaintextLen);
        unsigned char tag[16];

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = nonce;
        info.cbNonce = sizeof(nonce);
        info.pbTag = tag;
        info.cbTag = sizeof(tag);

        ULONG resultLen = 0;
        NTSTATUS status = BCryptEncrypt(key, const_cast<PUCHAR>(plaintext), static_cast<ULONG>(plaintextLen),
            &info, nullptr, 0, cipher.data(), static_cast<ULONG>(cipher.size()), &resultLen, 0);

        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);
        if (status < 0) return false;

        outNonceTagCipher.clear();
        outNonceTagCipher.insert(outNonceTagCipher.end(), nonce, nonce + sizeof(nonce));
        outNonceTagCipher.insert(outNonceTagCipher.end(), tag, tag + sizeof(tag));
        outNonceTagCipher.insert(outNonceTagCipher.end(), cipher.begin(), cipher.begin() + resultLen);
        return true;
    }

    bool AesGcmDecrypt(const unsigned char* nonceTagCipher, size_t len, std::string& outPlaintext)
    {
        if (len < 28) return false; // 12 nonce + 16 tag minimum, even for empty ciphertext
        const unsigned char* nonce = nonceTagCipher;
        const unsigned char* tag = nonceTagCipher + 12;
        const unsigned char* cipher = nonceTagCipher + 28;
        size_t cipherLen = len - 28;

        BCRYPT_ALG_HANDLE alg = nullptr;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0) return false;
        if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0)
        {
            BCryptCloseAlgorithmProvider(alg, 0); return false;
        }

        BCRYPT_KEY_HANDLE key = nullptr;
        if (BCryptGenerateSymmetricKey(alg, &key, nullptr, 0,
            (PUCHAR)TRANSPORT_KEY, sizeof(TRANSPORT_KEY), 0) < 0)
        {
            BCryptCloseAlgorithmProvider(alg, 0); return false;
        }

        std::vector<unsigned char> plain(cipherLen > 0 ? cipherLen : 1);

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = const_cast<PUCHAR>(nonce);
        info.cbNonce = 12;
        info.pbTag = const_cast<PUCHAR>(tag);
        info.cbTag = 16;

        ULONG resultLen = 0;
        NTSTATUS status = BCryptDecrypt(key, const_cast<PUCHAR>(cipher), static_cast<ULONG>(cipherLen),
            &info, nullptr, 0, plain.data(), static_cast<ULONG>(plain.size()), &resultLen, 0);

        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);
        if (status < 0) return false; // includes GCM authentication failure - never trust on failure

        outPlaintext.assign(reinterpret_cast<char*>(plain.data()), resultLen);
        return true;
    }
} // end anonymous namespace

bool LicenseProtocol::LoadServerPublicKey(const std::wstring& dllDirectory)
{
    return ServerSignatureVerify::LoadServerPublicKey(dllDirectory);
}

bool LicenseProtocol::VerifyRsaSha256(const std::string& canonicalMessage, const std::string& signatureB64)
{
    return ServerSignatureVerify::Verify(canonicalMessage, signatureB64);
}

bool LicenseProtocol::GcmEncrypt(const std::string& plaintext, std::string& outEnvelope)
{
    std::vector<unsigned char> nonceTagCipher;
    if (!AesGcmEncrypt(reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(), nonceTagCipher))
        return false;
    std::string b64;
    if (!Base64Encode(nonceTagCipher, b64)) return false;
    outEnvelope = "N3:" + b64;
    return true;
}

bool LicenseProtocol::GcmDecrypt(const std::string& envelope, std::string& outPlaintext)
{
    if (envelope.size() < 4 || envelope.compare(0, 3, "N3:") != 0) return false;
    std::vector<unsigned char> packed;
    if (!Base64Decode(envelope.substr(3), packed)) return false;
    return AesGcmDecrypt(packed.data(), packed.size(), outPlaintext);
}

std::string LicenseProtocol::BuildRequestEnvelope(const std::map<std::string, std::string>& fields)
{
    std::string body;
    bool first = true;
    for (const auto& kv : fields)
    {
        if (!first) body += '&';
        first = false;
        body += UrlEncode(kv.first);
        body += '=';
        body += UrlEncode(kv.second);
    }
    std::string envelope;
    if (!GcmEncrypt(body, envelope)) return std::string();
    return envelope;
}

ParsedResponse LicenseProtocol::ParseLeaseOrChallenge(const std::string& plaintext, bool isChallenge)
{
    ParsedResponse result;

    if (plaintext == "no")
    {
        result.kind = ResponseKind::LegacyNo;
        return result;
    }

    // SECURITY FIX: previously Rejected and Challenge were trusted from
    // their pipe-delimited fields ALONE, with no signature check at all -
    // only Lease went through VerifyRsaSha256. That meant anyone who could
    // produce syntactically-valid plaintext inside a correctly-encrypted
    // GCM envelope (e.g. by compromising only the shared transport key,
    // without ever touching the RSA private key) could forge a Reject or a
    // Challenge. Every response type that feeds into license state must be
    // authenticated the same way (matches the identical fix applied
    // server-side in nutricula_reject() and the challenge-stage handler).
    //
    // Both now follow the exact same decrypt -> locate signature -> verify
    // -> THEN parse fields pattern already used for Lease below.

    const std::string rejectPrefix = "NL3-REJECT|";
    if (plaintext.compare(0, rejectPrefix.size(), rejectPrefix) == 0)
    {
        size_t sigFieldPos = plaintext.rfind("|server_signature=");
        if (sigFieldPos == std::string::npos) return result; // Invalid - unsigned, no longer accepted

        std::string signedCanonical = plaintext.substr(rejectPrefix.size(), sigFieldPos - rejectPrefix.size());
        std::string signatureB64 = plaintext.substr(sigFieldPos + std::string("|server_signature=").size());
        if (!VerifyRsaSha256(signedCanonical, signatureB64)) return result; // Invalid

        auto fields = ParsePipeDelimitedFields(signedCanonical);
        if (!fields.count("reason") || !fields.count("requested_at")) return result; // Invalid - incomplete, even though signed

        result.kind = ResponseKind::Rejected;
        result.rejectReason = fields["reason"];
        result.retryAfterSeconds = fields.count("retry_after_seconds")
            ? static_cast<long long>(ParseU64(fields["retry_after_seconds"])) : 0;
        result.requestedAt = ParseU64(fields["requested_at"]);
        result.rawCanonical = signedCanonical;
        result.rawSignatureB64 = signatureB64;
        return result;
    }

    const std::string challengePrefix = "NL3-CHALLENGE|";
    if (isChallenge && plaintext.compare(0, challengePrefix.size(), challengePrefix) == 0)
    {
        size_t sigFieldPos = plaintext.rfind("|server_signature=");
        if (sigFieldPos == std::string::npos) return result; // Invalid - unsigned, no longer accepted

        std::string signedCanonical = plaintext.substr(challengePrefix.size(), sigFieldPos - challengePrefix.size());
        std::string signatureB64 = plaintext.substr(sigFieldPos + std::string("|server_signature=").size());
        if (!VerifyRsaSha256(signedCanonical, signatureB64)) return result; // Invalid

        auto fields = ParsePipeDelimitedFields(signedCanonical);
        if (!fields.count("challenge_id") || !fields.count("nonce") || !fields.count("expires_at"))
            return result; // Invalid - incomplete, even though signed
        result.kind = ResponseKind::Challenge;
        result.challenge.challengeId = fields["challenge_id"];
        result.challenge.nonceB64 = fields["nonce"];
        result.challenge.expiresAt = ParseU64(fields["expires_at"]);
        return result;
    }

    const std::string leasePrefix = "NL3|";
    if (!isChallenge && plaintext.compare(0, leasePrefix.size(), leasePrefix) == 0)
    {
        size_t sigFieldPos = plaintext.rfind("|server_signature=");
        if (sigFieldPos == std::string::npos) return result; // Invalid - not properly formed

        // IMPORTANT: PHP signs the canonical string WITHOUT the "NL3|"
        // prefix (nutricula_server_sign($canonical, ...) is called before
        // "NL3|" is prepended for transmission - see license_check.php /
        // nutricula_computer_based_signup.php). Verifying against a
        // canonical that still includes "NL3|" would never match a
        // genuinely valid signature.
        std::string signedCanonical = plaintext.substr(leasePrefix.size(), sigFieldPos - leasePrefix.size());
        std::string signatureB64 = plaintext.substr(sigFieldPos + std::string("|server_signature=").size());

        // Signature verification happens BEFORE any field is trusted or
        // used (spec sections 32-33) - only construct/return a Lease after
        // this passes.
        if (!VerifyRsaSha256(signedCanonical, signatureB64)) return result; // Invalid

        auto fields = ParsePipeDelimitedFields(signedCanonical);
        if (!fields.count("license_id") || !fields.count("product_id") ||
            !fields.count("machine_id") || !fields.count("device_key_hash") ||
            !fields.count("license_expires_at") || !fields.count("requested_at") ||
            !fields.count("refresh_token"))
        {
            return result; // Invalid - incomplete lease, even though signed
        }

        result.kind = ResponseKind::Lease;
        result.requestedAt = ParseU64(fields["requested_at"]);
        result.rawCanonical = signedCanonical;
        result.rawSignatureB64 = signatureB64;
        result.lease.licenseId = fields["license_id"];
        result.lease.productId = static_cast<long>(ParseU64(fields["product_id"]));
        result.lease.machineId = fields["machine_id"];
        result.lease.deviceKeyHash = fields["device_key_hash"];
        result.lease.licenseExpiresAt = ParseU64(fields["license_expires_at"]);
        result.lease.requestedAt = ParseU64(fields["requested_at"]);
        result.lease.refreshToken = fields["refresh_token"];
        return result;
    }

    return result; // Invalid - unrecognized format entirely
}

ParsedResponse LicenseProtocol::DecryptAndVerify(const std::string& rawEnvelope)
{
    std::string plaintext;
    if (!GcmDecrypt(rawEnvelope, plaintext))
    {
        ParsedResponse invalid;
        invalid.kind = ResponseKind::Invalid;
        return invalid;
    }
    // Try both a lease/reject/no interpretation and a challenge
    // interpretation - the caller knows which stage it asked for and should
    // treat an unexpected kind (e.g. a Challenge showing up when a Lease was
    // expected) as Invalid too; ParseLeaseOrChallenge(..., false) already
    // only recognizes NL3|/NL3-REJECT|/"no", never NL3-CHALLENGE|.
    ParsedResponse asVerify = ParseLeaseOrChallenge(plaintext, false);
    if (asVerify.kind != ResponseKind::Invalid) return asVerify;
    return ParseLeaseOrChallenge(plaintext, true);
}
