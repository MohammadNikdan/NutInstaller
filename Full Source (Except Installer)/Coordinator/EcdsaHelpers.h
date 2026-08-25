#pragma once
//
// EcdsaHelpers.h - minimal raw-P256-key ECDSA sign/verify via Windows CNG
// (BCrypt), shared by the Coordinator (signs the IPC handshake nonce, and
// NutriculaSignTool signs the Manifest) and the thin DLL/Coordinator
// (verifies both). All ECDSA identities in this project (Vendor Signing
// Key, Coordinator/IPC Identity Key) now use P-256 - the per-installation
// Device Key was ALREADY P-256 all along (a separate, unrelated key
// managed entirely inside MachineIdBridge/NutriculaMachineId.cpp).
//
// MIGRATED FROM P-384 TO P-256 (2026): confirmed by direct diagnostic
// testing under real Wine (not just this sandbox) that
// BCryptImportKeyPair fails for P-384 PRIVATE key import specifically
// (NTSTATUS=0xC00000BB / STATUS_NOT_SUPPORTED), while the exact same
// operation for P-256 private keys - proven by the Device Key's
// SignChallenge, which has ALWAYS used this same import+sign pattern -
// succeeds on the identical Wine environment. This file now uses P-256 +
// SHA-256 throughout, matching the Device Key's already-working pattern
// exactly. Raw sizes: private scalar d = 32 bytes, public point X||Y = 64
// bytes, signature r||s = 64 bytes, digest = 32 bytes.
//

#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")

namespace EcdsaHelpers {

inline bool Sha256(const unsigned char* data, size_t dataLen, unsigned char outDigest[32])
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) >= 0;
    if (ok) ok = BCryptHashData(hash, const_cast<PUCHAR>(data), static_cast<ULONG>(dataLen), 0) >= 0;
    if (ok) ok = BCryptFinishHash(hash, outDigest, 32, 0) >= 0;
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

// Verifies a raw P-256 signature (r||s, 64 bytes) over SHA-256(data), using
// a raw public key point (X||Y, 64 bytes). Returns false on any failure -
// malformed key, malformed signature, or genuine verification failure are
// all treated identically as "not verified".
inline bool VerifyP256(const unsigned char publicKeyXY[64],
    const unsigned char* data, size_t dataLen,
    const unsigned char signatureRS[64])
{
    unsigned char digest[32];
    if (!Sha256(data, dataLen, digest)) return false;

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) < 0) return false;

    struct { BCRYPT_ECCKEY_BLOB header; unsigned char xy[64]; } blob;
    blob.header.dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    blob.header.cbKey = 32;
    memcpy(blob.xy, publicKeyXY, 64);

    BCRYPT_KEY_HANDLE key = nullptr;
    NTSTATUS st = BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLIC_BLOB,
        &key, reinterpret_cast<PUCHAR>(&blob), sizeof(blob), 0);
    if (st < 0)
    {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    NTSTATUS verifyStatus = BCryptVerifySignature(key, nullptr,
        digest, 32, const_cast<PUCHAR>(signatureRS), 64, 0);

    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return verifyStatus >= 0;
}

// Signs SHA-256(data) with a raw P-256 private key (32-byte scalar `d`,
// plus its matching public point `publicKeyXY` X||Y, 64 bytes), producing a
// raw 64-byte (r||s) signature. Returns false on any failure.
inline bool SignP256(const unsigned char privateKeyD[32], const unsigned char publicKeyXY[64],
    const unsigned char* data, size_t dataLen,
    unsigned char outSignatureRS[64])
{
    unsigned char digest[32];
    if (!Sha256(data, dataLen, digest)) return false;

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) < 0) return false;

    struct { BCRYPT_ECCKEY_BLOB header; unsigned char x[32]; unsigned char y[32]; unsigned char d[32]; } blob;
    blob.header.dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
    blob.header.cbKey = 32;
    memcpy(blob.x, publicKeyXY, 32);
    memcpy(blob.y, publicKeyXY + 32, 32);
    memcpy(blob.d, privateKeyD, 32);

    BCRYPT_KEY_HANDLE key = nullptr;
    NTSTATUS st = BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPRIVATE_BLOB,
        &key, reinterpret_cast<PUCHAR>(&blob), sizeof(blob), 0);
    if (st < 0)
    {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    ULONG sigLen = 0;
    NTSTATUS signStatus = BCryptSignHash(key, nullptr,
        digest, 32, outSignatureRS, 64, &sigLen, 0);

    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return signStatus >= 0 && sigLen == 64;
}

} // namespace EcdsaHelpers
