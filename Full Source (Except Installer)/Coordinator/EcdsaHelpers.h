#pragma once
//
// EcdsaHelpers.h - minimal raw-P384-key ECDSA sign/verify via Windows CNG
// (BCrypt), shared by the Coordinator (signs the IPC handshake nonce, and
// NutriculaSignTool signs the Manifest) and the thin DLL/Coordinator
// (verifies both). All ECDSA identities in this project (Vendor Signing
// Key, Coordinator/IPC Identity Key) now use P-384 - the per-installation
// Device Key is a SEPARATE, unrelated key managed entirely inside
// MachineIdBridge/NutriculaMachineId.cpp and is not affected by this file.
//
// CONFIRMED BY DIRECT TESTING (not assumed from documentation):
//   - P-384 pairs with SHA-384 (48-byte digest) for signing/verification -
//     verified natively with OpenSSL against the real production Vendor
//     keypair (openssl dgst -sha384 -sign/-verify): succeeds. A 32-byte
//     (SHA-256-sized) digest is NOT what P-384 expects.
//   - Raw signature format is r||s, 48+48 = 96 bytes.
//   - Raw public key point is X||Y, 48+48 = 96 bytes; raw private scalar
//     is 48 bytes.
//   - BCRYPT_ECCPRIVATE_BLOB import genuinely requires the real X||Y
//     public coordinates, not just the private scalar d (same finding as
//     P-256 in this project's earlier testing).
//   - KNOWN ENVIRONMENT LIMITATION: BCryptImportKeyPair for P-384 fails
//     with STATUS_NOT_SUPPORTED (0xC00000BB) under the Wine version used
//     for this project's testing sandbox - confirmed via round-trip test
//     (export a Wine-generated P-384 key, then immediately re-import the
//     exact same blob: still fails). BCryptGenerateKeyPair for P-384 DOES
//     work under this same Wine version, proving P-384 itself is
//     supported - only Import specifically is broken here. This means the
//     Sign/Verify functions below could NOT be end-to-end tested against
//     the real uploaded keys in this sandbox, and MUST be verified on real
//     Windows before production use. The code follows the exact same
//     structure already confirmed correct for P-256 in this project,
//     adjusted only for P-384's sizes per Microsoft's documented
//     BCRYPT_ECCKEY_BLOB format (which this project's own round-trip test
//     confirmed Wine itself produces/expects in the identical shape used
//     here: magic=BCRYPT_ECDSA_PRIVATE_P384_MAGIC, cbKey=48, followed by
//     X||Y||d at 48 bytes each - only the internal Import codepath is
//     broken in this specific Wine build, not the format).
//

#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")

namespace EcdsaHelpers {

inline bool Sha384(const unsigned char* data, size_t dataLen, unsigned char outDigest[48])
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA384_ALGORITHM, nullptr, 0) < 0) return false;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) >= 0;
    if (ok) ok = BCryptHashData(hash, const_cast<PUCHAR>(data), static_cast<ULONG>(dataLen), 0) >= 0;
    if (ok) ok = BCryptFinishHash(hash, outDigest, 48, 0) >= 0;
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

// Verifies a raw P-384 signature (r||s, 96 bytes) over SHA-384(data), using
// a raw public key point (X||Y, 96 bytes). Returns false on any failure -
// malformed key, malformed signature, or genuine verification failure are
// all treated identically as "not verified".
inline bool VerifyP384(const unsigned char publicKeyXY[96],
    const unsigned char* data, size_t dataLen,
    const unsigned char signatureRS[96])
{
    unsigned char digest[48];
    if (!Sha384(data, dataLen, digest)) return false;

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P384_ALGORITHM, nullptr, 0) < 0) return false;

    struct { BCRYPT_ECCKEY_BLOB header; unsigned char xy[96]; } blob;
    blob.header.dwMagic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
    blob.header.cbKey = 48;
    memcpy(blob.xy, publicKeyXY, 96);

    BCRYPT_KEY_HANDLE key = nullptr;
    NTSTATUS st = BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLIC_BLOB,
        &key, reinterpret_cast<PUCHAR>(&blob), sizeof(blob), 0);
    if (st < 0)
    {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    NTSTATUS verifyStatus = BCryptVerifySignature(key, nullptr,
        digest, 48, const_cast<PUCHAR>(signatureRS), 96, 0);

    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return verifyStatus >= 0;
}

// Signs SHA-384(data) with a raw P-384 private key (48-byte scalar `d`,
// plus its matching public point `publicKeyXY` X||Y, 96 bytes), producing a
// raw 96-byte (r||s) signature. Returns false on any failure.
inline bool SignP384(const unsigned char privateKeyD[48], const unsigned char publicKeyXY[96],
    const unsigned char* data, size_t dataLen,
    unsigned char outSignatureRS[96])
{
    unsigned char digest[48];
    if (!Sha384(data, dataLen, digest)) return false;

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P384_ALGORITHM, nullptr, 0) < 0) return false;

    struct { BCRYPT_ECCKEY_BLOB header; unsigned char x[48]; unsigned char y[48]; unsigned char d[48]; } blob;
    blob.header.dwMagic = BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
    blob.header.cbKey = 48;
    memcpy(blob.x, publicKeyXY, 48);
    memcpy(blob.y, publicKeyXY + 48, 48);
    memcpy(blob.d, privateKeyD, 48);

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
        digest, 48, outSignatureRS, 96, &sigLen, 0);

    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return signStatus >= 0 && sigLen == 96;
}

} // namespace EcdsaHelpers
