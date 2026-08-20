#include "LicenseProtocol.h"
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
    // Byte-for-byte identical to license_config.php's transport_key_hex and
    // MachineId32.dll's TRANSPORT_KEY - independently re-verified here
    // against the exact same hex string (23194cf5337966ecae618441f65ef7c1b
    // 12ebb02e2cf91ab79c8da029e74b4df) already confirmed matching in the
    // earlier build. Do not change this without changing it identically in
    // BOTH the PHP config and the Machine ID DLL - a mismatch here is a
    // silent, total protocol break.
    const unsigned char TRANSPORT_KEY[32] = {
        0x23,0x19,0x4C,0xF5,0x33,0x79,0x66,0xEC,
        0xAE,0x61,0x84,0x41,0xF6,0x5E,0xF7,0xC1,
        0xB1,0x2E,0xBB,0x02,0xE2,0xCF,0x91,0xAB,
        0x79,0xC8,0xDA,0x02,0x9E,0x74,0xB4,0xDF
    };

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

    // ---- Minimal DER parser, just enough for an X.509 SubjectPublicKeyInfo
    //      wrapping an RSA public key (exactly what `openssl rsa -pubout`
    //      produces) - not a general-purpose ASN.1 library. ----
    struct DerCursor
    {
        const unsigned char* p;
        const unsigned char* end;
    };

    bool DerReadTlv(DerCursor& c, unsigned char expectedTag, const unsigned char*& outValue, size_t& outLen)
    {
        if (c.p >= c.end) return false;
        if (*c.p != expectedTag) return false;
        c.p++;
        if (c.p >= c.end) return false;
        size_t len;
        if ((*c.p & 0x80) == 0) { len = *c.p; c.p++; }
        else
        {
            int numBytes = *c.p & 0x7F;
            c.p++;
            if (numBytes == 0 || numBytes > 4 || c.p + numBytes > c.end) return false;
            len = 0;
            for (int i = 0; i < numBytes; i++) { len = (len << 8) | *c.p; c.p++; }
        }
        if (c.p + len > c.end) return false;
        outValue = c.p;
        outLen = len;
        c.p += len;
        return true;
    }

    // Strips a leading 0x00 sign-padding byte from a DER INTEGER's content,
    // if present (standard ASN.1 INTEGER encoding for positive values whose
    // high bit would otherwise look like a sign bit).
    void StripLeadingZero(const unsigned char*& data, size_t& len)
    {
        while (len > 1 && data[0] == 0x00) { data++; len--; }
    }
}

bool LicenseProtocol::LoadServerPublicKey(const std::wstring& dllDirectory)
{
    std::wstring path = dllDirectory;
    if (!path.empty() && path.back() != L'\\') path += L'\\';
    path += L"license-signing-public.pem";

    std::ifstream file(path.c_str(), std::ios::binary);
    if (!file) return false;
    std::string pem((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (pem.empty()) return false;

    const std::string beginMarker = "-----BEGIN PUBLIC KEY-----";
    const std::string endMarker = "-----END PUBLIC KEY-----";
    size_t begin = pem.find(beginMarker);
    size_t end = pem.find(endMarker);
    if (begin == std::string::npos || end == std::string::npos || end <= begin) return false;
    std::string b64 = pem.substr(begin + beginMarker.size(), end - (begin + beginMarker.size()));
    // Strip whitespace/newlines from the PEM body before decoding.
    std::string clean;
    clean.reserve(b64.size());
    for (char c : b64) if (!isspace(static_cast<unsigned char>(c))) clean.push_back(c);

    std::vector<unsigned char> der;
    if (!Base64Decode(clean, der) || der.empty()) return false;

    // Parse SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }
    DerCursor outer{ der.data(), der.data() + der.size() };
    const unsigned char* spkiBody; size_t spkiLen;
    if (!DerReadTlv(outer, 0x30, spkiBody, spkiLen)) return false;

    DerCursor inner{ spkiBody, spkiBody + spkiLen };
    const unsigned char* algBody; size_t algLen;
    if (!DerReadTlv(inner, 0x30, algBody, algLen)) return false; // AlgorithmIdentifier - not deeply validated

    const unsigned char* bitStringBody; size_t bitStringLen;
    if (!DerReadTlv(inner, 0x03, bitStringBody, bitStringLen)) return false;
    if (bitStringLen < 1 || bitStringBody[0] != 0x00) return false; // must be byte-aligned (0 unused bits)
    const unsigned char* rsaKeyDer = bitStringBody + 1;
    size_t rsaKeyDerLen = bitStringLen - 1;

    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    DerCursor rsaCursor{ rsaKeyDer, rsaKeyDer + rsaKeyDerLen };
    const unsigned char* rsaSeqBody; size_t rsaSeqLen;
    if (!DerReadTlv(rsaCursor, 0x30, rsaSeqBody, rsaSeqLen)) return false;

    DerCursor fieldsCursor{ rsaSeqBody, rsaSeqBody + rsaSeqLen };
    const unsigned char* modulus; size_t modulusLen;
    if (!DerReadTlv(fieldsCursor, 0x02, modulus, modulusLen)) return false;
    const unsigned char* exponent; size_t exponentLen;
    if (!DerReadTlv(fieldsCursor, 0x02, exponent, exponentLen)) return false;

    StripLeadingZero(modulus, modulusLen);
    StripLeadingZero(exponent, exponentLen);
    if (modulusLen < 64 || modulusLen > 1024) return false; // sanity bound (512 bytes = 4096-bit RSA ceiling)

    // Build a BCRYPT_RSAPUBLIC_BLOB: header, then exponent bytes, then
    // modulus bytes, both big-endian - exactly the byte order DER already
    // gives us, no reversal needed (unlike the legacy CryptoAPI convention).
    std::vector<unsigned char> blob(sizeof(BCRYPT_RSAKEY_BLOB) + exponentLen + modulusLen);
    BCRYPT_RSAKEY_BLOB* header = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(blob.data());
    header->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    header->BitLength = static_cast<ULONG>(modulusLen * 8);
    header->cbPublicExp = static_cast<ULONG>(exponentLen);
    header->cbModulus = static_cast<ULONG>(modulusLen);
    header->cbPrime1 = 0;
    header->cbPrime2 = 0;

    unsigned char* writePtr = blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
    memcpy(writePtr, exponent, exponentLen); writePtr += exponentLen;
    memcpy(writePtr, modulus, modulusLen);

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, nullptr, 0) < 0) return false;

    if (g_rsaPublicKey) { BCryptDestroyKey(g_rsaPublicKey); g_rsaPublicKey = nullptr; }
    NTSTATUS status = BCryptImportKeyPair(alg, nullptr, BCRYPT_RSAPUBLIC_BLOB,
        &g_rsaPublicKey, blob.data(), static_cast<ULONG>(blob.size()), 0);
    BCryptCloseAlgorithmProvider(alg, 0);

    return status >= 0 && g_rsaPublicKey != nullptr;
}

bool LicenseProtocol::VerifyRsaSha256(const std::string& canonicalMessage, const std::string& signatureB64)
{
    if (!g_rsaPublicKey) return false; // key was never loaded - never treat as valid by default

    std::vector<unsigned char> signature;
    if (!Base64Decode(signatureB64, signature) || signature.empty()) return false;

    BCRYPT_ALG_HANDLE hashAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hashAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
    BCRYPT_HASH_HANDLE hash = nullptr;
    unsigned char digest[32];
    bool hashOk = false;
    if (BCryptCreateHash(hashAlg, &hash, nullptr, 0, nullptr, 0, 0) >= 0)
    {
        BCryptHashData(hash, (PUCHAR)canonicalMessage.data(), static_cast<ULONG>(canonicalMessage.size()), 0);
        hashOk = BCryptFinishHash(hash, digest, sizeof(digest), 0) >= 0;
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(hashAlg, 0);
    if (!hashOk) return false;

    BCRYPT_PKCS1_PADDING_INFO padInfo;
    padInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    NTSTATUS status = BCryptVerifySignature(
        g_rsaPublicKey, &padInfo, digest, sizeof(digest),
        signature.data(), static_cast<ULONG>(signature.size()), BCRYPT_PAD_PKCS1);

    return status >= 0; // STATUS_SUCCESS only on a genuinely valid signature
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

    const std::string rejectPrefix = "NL3-REJECT|";
    if (plaintext.compare(0, rejectPrefix.size(), rejectPrefix) == 0)
    {
        auto fields = ParsePipeDelimitedFields(plaintext.substr(rejectPrefix.size()));
        result.kind = ResponseKind::Rejected;
        result.rejectReason = fields.count("reason") ? fields["reason"] : "";
        result.retryAfterSeconds = fields.count("retry_after_seconds")
            ? static_cast<long long>(ParseU64(fields["retry_after_seconds"])) : 0;
        return result;
    }

    const std::string challengePrefix = "NL3-CHALLENGE|";
    if (isChallenge && plaintext.compare(0, challengePrefix.size(), challengePrefix) == 0)
    {
        auto fields = ParsePipeDelimitedFields(plaintext.substr(challengePrefix.size()));
        if (!fields.count("challenge_id") || !fields.count("nonce") || !fields.count("expires_at"))
            return result; // Invalid - incomplete challenge
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
            !fields.count("license_expires_at") || !fields.count("requested_at"))
        {
            return result; // Invalid - incomplete lease, even though signed
        }

        result.kind = ResponseKind::Lease;
        result.lease.licenseId = fields["license_id"];
        result.lease.productId = static_cast<long>(ParseU64(fields["product_id"]));
        result.lease.machineId = fields["machine_id"];
        result.lease.deviceKeyHash = fields["device_key_hash"];
        result.lease.licenseExpiresAt = ParseU64(fields["license_expires_at"]);
        result.lease.requestedAt = ParseU64(fields["requested_at"]);
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
