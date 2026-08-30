//
// NutriculaSignInstaller.cpp - build-time tool that produces the
// "<Installer.exe>.sig" file SelfIntegrityCheck.cs (in the Installer
// project) verifies at startup. Run ONLY on the secure build machine,
// AFTER the final Installer.exe has been fully built - never distributed
// to customers, never committed anywhere the Installer itself is built
// from (it links VendorIdentityPrivate.h, which must never ship).
//
// Usage:
//   NutriculaSignInstaller.exe <path_to_Installer.exe>
//
// Produces <path_to_Installer.exe>.sig next to it - a single line
// containing the Base64-encoded raw (r||s) P-256 signature over the
// SHA-256 hash of the exe's own bytes, signed with the Vendor private key.
// This is the exact format SelfIntegrityCheck.Verify() (Installer project,
// C#) expects: it independently recomputes SHA-256 over the exe it is
// currently running as, reads this .sig file, and verifies the signature
// against the SAME Vendor public key baked into VendorPublicKeyEmbedded.cs
// (see KeyBaker.exe, which generates that file from the same
// VendorSigningKey_Public.pem this tool's private counterpart pairs with).
//
// IMPORTANT: this MUST be re-run (producing a fresh .sig) every single
// time Installer.exe is rebuilt for any reason - even a change that seems
// unrelated to licensing (a UI tweak, a typo fix) changes the exe's bytes,
// which changes its SHA-256 hash, which invalidates any existing .sig.
// Shipping a stale .sig with a newer .exe means SelfIntegrityCheck will
// always fail for every customer.
//

#include "../Coordinator/VendorIdentityPrivate.h"
#include "../Coordinator/EcdsaHelpers.h"

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace {

std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

std::string Base64Encode(const unsigned char* data, size_t len)
{
    DWORD outLen = 0;
    CryptBinaryToStringA(data, (DWORD)len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &outLen);
    std::string out(outLen, '\0');
    CryptBinaryToStringA(data, (DWORD)len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &out[0], &outLen);
    while (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

// Reads an entire file's raw bytes into memory - Installer.exe is a small
// enough file (a few MB at most) that this is fine; SignP256 below hashes
// these bytes internally with SHA-256 exactly once, matching precisely
// what SelfIntegrityCheck.cs does on the C# side (SHA256.ComputeHash over
// the exe's raw bytes, then ecdsa.VerifyHash against that single digest) -
// passing an already-computed digest here instead would double-hash and
// never match.
bool ReadFileBytes(const std::wstring& path, std::vector<unsigned char>& outBytes)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size)) { CloseHandle(h); return false; }
    outBytes.resize(static_cast<size_t>(size.QuadPart));
    DWORD totalRead = 0;
    bool ok = true;
    while (ok && totalRead < outBytes.size())
    {
        DWORD chunk = 0;
        ok = ReadFile(h, outBytes.data() + totalRead, static_cast<DWORD>(outBytes.size() - totalRead), &chunk, nullptr) != 0;
        if (chunk == 0) break;
        totalRead += chunk;
    }
    CloseHandle(h);
    return ok && totalRead == outBytes.size();
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("Usage: %s <path_to_Installer.exe>\n", argv[0]);
        printf("  Produces <path_to_Installer.exe>.sig next to the given file.\n");
        return 1;
    }

    std::wstring exePath = Utf8ToWide(argv[1]);

    std::vector<unsigned char> exeBytes;
    if (!ReadFileBytes(exePath, exeBytes))
    {
        printf("ERROR: could not read %s\n", argv[1]);
        return 1;
    }

    // Raw (r||s) P-256 signature - exactly 64 bytes, same convention used
    // everywhere else in this project (manifest signatures, device key
    // signatures, server lease signatures). SignP256 hashes exeBytes with
    // SHA-256 internally exactly once - see ReadFileBytes's own comment on
    // why nothing pre-hashes this data first.
    unsigned char signature[64];
    bool signOk = EcdsaHelpers::SignP256(
        VendorIdentity::PrivateKeyD(), VendorIdentity::PrivateKeyPublicXY(),
        exeBytes.data(), exeBytes.size(),
        signature);
    if (!signOk)
    {
        printf("ERROR: signing failed.\n");
        return 1;
    }

    std::string sigB64 = Base64Encode(signature, 64);

    std::wstring sigPath = exePath + L".sig";
    HANDLE h = CreateFileW(sigPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        printf("ERROR: could not write %ls\n", sigPath.c_str());
        return 1;
    }
    DWORD written = 0;
    WriteFile(h, sigB64.data(), (DWORD)sigB64.size(), &written, nullptr);
    CloseHandle(h);

    printf("OK: signed %s\n", argv[1]);
    printf("  -> %ls\n", sigPath.c_str());
    printf("  signature (Base64, %zu chars): %s\n", sigB64.size(), sigB64.c_str());
    return 0;
}
