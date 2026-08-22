#pragma once
//
// EcdsaPemParser.h - parses genuine, unmodified openssl-generated PEM text
// for P-384 EC keys (SEC1 private key format and SPKI public key format)
// into the raw byte form (D scalar / X||Y point) that EcdsaHelpers.h's
// Sign/Verify functions need. This lets the person managing this project
// drop the EXACT PEM file openssl produces directly into the Keys/ folder
// - no manual byte-array conversion by hand ever again.
//
// Uses the same minimal DER-walking approach already proven correct in
// ServerSignatureVerify.cpp's RSA public-key parser, extended here for the
// EC SEC1/SPKI structures. Parsing happens once, lazily, at first use
// (cached in a static local) - not at every Sign/Verify call.
//

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <cstring>

#pragma comment(lib, "crypt32.lib")

namespace EcdsaPemParser {

namespace detail {

    inline bool Base64Decode(const std::string& b64, std::vector<unsigned char>& out)
    {
        DWORD outLen = 0;
        if (!CryptStringToBinaryA(b64.c_str(), static_cast<DWORD>(b64.size()),
            CRYPT_STRING_BASE64, nullptr, &outLen, nullptr, nullptr)) return false;
        out.resize(outLen);
        return CryptStringToBinaryA(b64.c_str(), static_cast<DWORD>(b64.size()),
            CRYPT_STRING_BASE64, out.data(), &outLen, nullptr, nullptr) != 0;
    }

    struct DerCursor { const unsigned char* p; const unsigned char* end; };

    inline bool DerReadTlv(DerCursor& c, unsigned char expectedTag, const unsigned char*& outValue, size_t& outLen)
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

    // Extracts the base64 body between BEGIN/END markers (any label -
    // "EC PRIVATE KEY" or "PUBLIC KEY") and decodes it to raw DER bytes.
    inline bool ExtractDerFromPem(const std::string& pem, std::vector<unsigned char>& der)
    {
        size_t begin = pem.find("-----BEGIN");
        if (begin == std::string::npos) return false;
        size_t beginEol = pem.find('\n', begin);
        if (beginEol == std::string::npos) return false;
        size_t end = pem.find("-----END", beginEol);
        if (end == std::string::npos) return false;

        std::string b64 = pem.substr(beginEol + 1, end - (beginEol + 1));
        std::string clean;
        clean.reserve(b64.size());
        for (char c : b64) if (!isspace(static_cast<unsigned char>(c))) clean.push_back(c);
        return Base64Decode(clean, der);
    }

} // namespace detail

// Parses a genuine SEC1 "EC PRIVATE KEY" PEM (exactly what
// `openssl ecparam -genkey` / `openssl ec -in ... ` outputs) for a P-384
// key, extracting both the 48-byte private scalar D and the 96-byte public
// point X||Y (SEC1 private keys always carry the matching public point
// alongside the private scalar, per RFC 5915).
//
// Structure walked: SEQUENCE { INTEGER version, OCTET STRING privateKey,
//   [0] parameters (curve OID, ignored - caller already knows it's P-384),
//   [1] EXPLICIT BIT STRING publicKey }
inline bool ParseSec1PrivateKeyPem(const std::string& pem,
    unsigned char outD[48], unsigned char outXY[96])
{
    std::vector<unsigned char> der;
    if (!detail::ExtractDerFromPem(pem, der)) return false;

    detail::DerCursor outer{ der.data(), der.data() + der.size() };
    const unsigned char* seqBody; size_t seqLen;
    if (!detail::DerReadTlv(outer, 0x30, seqBody, seqLen)) return false;

    detail::DerCursor c{ seqBody, seqBody + seqLen };
    const unsigned char* versionBytes; size_t versionLen;
    if (!detail::DerReadTlv(c, 0x02, versionBytes, versionLen)) return false;

    const unsigned char* dBytes; size_t dLen;
    if (!detail::DerReadTlv(c, 0x04, dBytes, dLen)) return false;
    if (dLen == 49 && dBytes[0] == 0x00) { dBytes++; dLen--; } // rare zero-padded scalar
    if (dLen != 48) return false;
    memcpy(outD, dBytes, 48);

    // [0] parameters - optional, skip if present (tag 0xA0, context-constructed)
    if (c.p < c.end && *c.p == 0xA0)
    {
        const unsigned char* paramsBody; size_t paramsLen;
        if (!detail::DerReadTlv(c, 0xA0, paramsBody, paramsLen)) return false;
    }

    // [1] EXPLICIT BIT STRING publicKey (tag 0xA1, context-constructed)
    const unsigned char* pubWrapperBody; size_t pubWrapperLen;
    if (!detail::DerReadTlv(c, 0xA1, pubWrapperBody, pubWrapperLen)) return false;

    detail::DerCursor pubCursor{ pubWrapperBody, pubWrapperBody + pubWrapperLen };
    const unsigned char* bitStringBody; size_t bitStringLen;
    if (!detail::DerReadTlv(pubCursor, 0x03, bitStringBody, bitStringLen)) return false;
    // bitStringBody[0] is the "unused bits" count (always 0 here), then
    // 0x04 (uncompressed point marker), then 96 bytes of X||Y.
    if (bitStringLen != 1 + 1 + 96) return false;
    if (bitStringBody[0] != 0x00 || bitStringBody[1] != 0x04) return false;
    memcpy(outXY, bitStringBody + 2, 96);

    return true;
}

// Parses a genuine SPKI "PUBLIC KEY" PEM (exactly what
// `openssl ec -pubout` outputs) for a P-384 key, extracting the 96-byte
// public point X||Y.
//
// Structure walked: SEQUENCE { SEQUENCE { OID, OID }, BIT STRING { 0x00 0x04 <XY> } }
inline bool ParseSpkiPublicKeyPem(const std::string& pem, unsigned char outXY[96])
{
    std::vector<unsigned char> der;
    if (!detail::ExtractDerFromPem(pem, der)) return false;

    detail::DerCursor outer{ der.data(), der.data() + der.size() };
    const unsigned char* seqBody; size_t seqLen;
    if (!detail::DerReadTlv(outer, 0x30, seqBody, seqLen)) return false;

    detail::DerCursor c{ seqBody, seqBody + seqLen };
    const unsigned char* algBody; size_t algLen;
    if (!detail::DerReadTlv(c, 0x30, algBody, algLen)) return false; // AlgorithmIdentifier - not deeply validated

    const unsigned char* bitStringBody; size_t bitStringLen;
    if (!detail::DerReadTlv(c, 0x03, bitStringBody, bitStringLen)) return false;
    if (bitStringLen != 1 + 1 + 96) return false;
    if (bitStringBody[0] != 0x00 || bitStringBody[1] != 0x04) return false;
    memcpy(outXY, bitStringBody + 2, 96);

    return true;
}

} // namespace EcdsaPemParser
