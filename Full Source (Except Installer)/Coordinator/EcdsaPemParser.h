#pragma once
//
// EcdsaPemParser.h - parses genuine, unmodified openssl-generated PEM text
// for P-256 EC keys (SEC1 private key format and SPKI public key format)
// into the raw byte form (D scalar / X||Y point) that EcdsaHelpers.h's
// Sign/Verify functions need. This lets the person managing this project
// drop the EXACT PEM file openssl produces directly into the Keys/ folder
// - no manual byte-array conversion by hand ever again.
//
// MIGRATED FROM P-384 TO P-256 (2026): confirmed via direct testing under
// real Wine that BCryptImportKeyPair fails for P-384 PRIVATE keys
// specifically (NTSTATUS=0xC00000BB), while the SAME operation for P-256
// private keys succeeds (this is exactly what the existing Device Key -
// always P-256 - already relies on, and it has always worked correctly
// under Wine). Both the Vendor Signing Key and the Coordinator/IPC
// Identity Key move to P-256 to fix this. Sizes: D is 32 bytes (was 48),
// XY is 64 bytes (was 96).
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

// Parses a genuine SEC1 "EC PRIVATE KEY" PEM for a P-256 key, extracting
// both the 32-byte private scalar D and the 64-byte public point X||Y.
inline bool ParseSec1PrivateKeyPem(const std::string& pem,
    unsigned char outD[32], unsigned char outXY[64])
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
    if (dLen == 33 && dBytes[0] == 0x00) { dBytes++; dLen--; }
    if (dLen != 32) return false;
    memcpy(outD, dBytes, 32);

    if (c.p < c.end && *c.p == 0xA0)
    {
        const unsigned char* paramsBody; size_t paramsLen;
        if (!detail::DerReadTlv(c, 0xA0, paramsBody, paramsLen)) return false;
    }

    const unsigned char* pubWrapperBody; size_t pubWrapperLen;
    if (!detail::DerReadTlv(c, 0xA1, pubWrapperBody, pubWrapperLen)) return false;

    detail::DerCursor pubCursor{ pubWrapperBody, pubWrapperBody + pubWrapperLen };
    const unsigned char* bitStringBody; size_t bitStringLen;
    if (!detail::DerReadTlv(pubCursor, 0x03, bitStringBody, bitStringLen)) return false;
    if (bitStringLen != 1 + 1 + 64) return false;
    if (bitStringBody[0] != 0x00 || bitStringBody[1] != 0x04) return false;
    memcpy(outXY, bitStringBody + 2, 64);

    return true;
}

// Parses a genuine SPKI "PUBLIC KEY" PEM for a P-256 key, extracting the
// 64-byte public point X||Y.
inline bool ParseSpkiPublicKeyPem(const std::string& pem, unsigned char outXY[64])
{
    std::vector<unsigned char> der;
    if (!detail::ExtractDerFromPem(pem, der)) return false;

    detail::DerCursor outer{ der.data(), der.data() + der.size() };
    const unsigned char* seqBody; size_t seqLen;
    if (!detail::DerReadTlv(outer, 0x30, seqBody, seqLen)) return false;

    detail::DerCursor c{ seqBody, seqBody + seqLen };
    const unsigned char* algBody; size_t algLen;
    if (!detail::DerReadTlv(c, 0x30, algBody, algLen)) return false;

    const unsigned char* bitStringBody; size_t bitStringLen;
    if (!detail::DerReadTlv(c, 0x03, bitStringBody, bitStringLen)) return false;
    if (bitStringLen != 1 + 1 + 64) return false;
    if (bitStringBody[0] != 0x00 || bitStringBody[1] != 0x04) return false;
    memcpy(outXY, bitStringBody + 2, 64);

    return true;
}

} // namespace EcdsaPemParser
