#include "ServerSignatureVerify.h"
#include "ServerPublicKeyEmbedded.h"
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <vector>
#include <fstream>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace
{
    BCRYPT_KEY_HANDLE g_rsaPublicKey = nullptr;

    bool Base64Decode(const std::string& b64, std::vector<unsigned char>& out)
    {
        DWORD outLen = 0;
        if (!CryptStringToBinaryA(b64.c_str(), static_cast<DWORD>(b64.size()),
            CRYPT_STRING_BASE64, nullptr, &outLen, nullptr, nullptr)) return false;
        out.resize(outLen);
        return CryptStringToBinaryA(b64.c_str(), static_cast<DWORD>(b64.size()),
            CRYPT_STRING_BASE64, out.data(), &outLen, nullptr, nullptr) != 0;
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

namespace {
    // Shared by both the compiled-in key and the file-fallback path - takes
    // raw PEM text (with headers) and imports it as g_rsaPublicKey.
    bool ImportPemPublicKey(const std::string& pem)
    {
        const std::string beginMarker = "-----BEGIN PUBLIC KEY-----";
        const std::string endMarker = "-----END PUBLIC KEY-----";
        size_t begin = pem.find(beginMarker);
        size_t end = pem.find(endMarker);
        if (begin == std::string::npos || end == std::string::npos || end <= begin) return false;
        std::string b64 = pem.substr(begin + beginMarker.size(), end - (begin + beginMarker.size()));
        std::string clean;
        clean.reserve(b64.size());
        for (char c : b64) if (!isspace(static_cast<unsigned char>(c))) clean.push_back(c);

        std::vector<unsigned char> der;
        if (!Base64Decode(clean, der) || der.empty()) return false;

        DerCursor outer{ der.data(), der.data() + der.size() };
        const unsigned char* spkiBody; size_t spkiLen;
        if (!DerReadTlv(outer, 0x30, spkiBody, spkiLen)) return false;

        DerCursor inner{ spkiBody, spkiBody + spkiLen };
        const unsigned char* algBody; size_t algLen;
        if (!DerReadTlv(inner, 0x30, algBody, algLen)) return false;

        const unsigned char* bitStringBody; size_t bitStringLen;
        if (!DerReadTlv(inner, 0x03, bitStringBody, bitStringLen)) return false;
        if (bitStringLen < 1 || bitStringBody[0] != 0x00) return false; // unused-bits byte must be 0
        const unsigned char* rsaKeyBody = bitStringBody + 1;
        size_t rsaKeyLen = bitStringLen - 1;

        DerCursor rsaCursor{ rsaKeyBody, rsaKeyBody + rsaKeyLen };
        const unsigned char* rsaSeqBody; size_t rsaSeqLen;
        if (!DerReadTlv(rsaCursor, 0x30, rsaSeqBody, rsaSeqLen)) return false;

        DerCursor rsaInner{ rsaSeqBody, rsaSeqBody + rsaSeqLen };
        const unsigned char* modulusBytes; size_t modulusLen;
        if (!DerReadTlv(rsaInner, 0x02, modulusBytes, modulusLen)) return false;
        const unsigned char* exponentBytes; size_t exponentLen;
        if (!DerReadTlv(rsaInner, 0x02, exponentBytes, exponentLen)) return false;

        StripLeadingZero(modulusBytes, modulusLen);
        StripLeadingZero(exponentBytes, exponentLen);

        std::vector<unsigned char> blob;
        BCRYPT_RSAKEY_BLOB header{};
        header.Magic = BCRYPT_RSAPUBLIC_MAGIC;
        header.BitLength = static_cast<ULONG>(modulusLen * 8);
        header.cbPublicExp = static_cast<ULONG>(exponentLen);
        header.cbModulus = static_cast<ULONG>(modulusLen);
        blob.insert(blob.end(), reinterpret_cast<unsigned char*>(&header), reinterpret_cast<unsigned char*>(&header) + sizeof(header));
        blob.insert(blob.end(), exponentBytes, exponentBytes + exponentLen);
        blob.insert(blob.end(), modulusBytes, modulusBytes + modulusLen);

        BCRYPT_ALG_HANDLE alg = nullptr;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, nullptr, 0) < 0) return false;
        BCRYPT_KEY_HANDLE key = nullptr;
        NTSTATUS st = BCryptImportKeyPair(alg, nullptr, BCRYPT_RSAPUBLIC_BLOB, &key,
            blob.data(), static_cast<ULONG>(blob.size()), 0);
        BCryptCloseAlgorithmProvider(alg, 0);
        if (st < 0) return false;

        if (g_rsaPublicKey) BCryptDestroyKey(g_rsaPublicKey);
        g_rsaPublicKey = key;
        return true;
    }
}

bool ServerSignatureVerify::LoadServerPublicKey(const std::wstring& dllDirectory)
{
    // Prefer the compiled-in key (architecture point 78) - only falls
    // through to the loose file if the compiled-in constant is still the
    // unfilled development placeholder (contains the literal marker text
    // that will never appear in a real PEM-encoded key), so the system
    // keeps working exactly as before until the real production key is
    // substituted into ServerPublicKeyEmbedded.h and everything is rebuilt.
    std::string embedded = SERVER_PUBLIC_KEY_PEM;
    bool isPlaceholder = embedded.find("REPLACE_WITH_REAL_PRODUCTION") != std::string::npos;
    if (!isPlaceholder && ImportPemPublicKey(embedded))
    {
        return true;
    }

    std::wstring path = dllDirectory;
    if (!path.empty() && path.back() != L'\\') path += L'\\';
    path += L"license-signing-public.pem";

    std::ifstream file(path.c_str(), std::ios::binary);
    if (!file) return false;
    std::string pem((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (pem.empty()) return false;
    return ImportPemPublicKey(pem);
}

bool ServerSignatureVerify::Verify(const std::string& canonicalMessage, const std::string& signatureB64)
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

