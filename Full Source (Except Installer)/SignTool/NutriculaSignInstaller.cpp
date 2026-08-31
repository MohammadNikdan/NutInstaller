//
// NutriculaSignInstaller.cpp - build-time tool that signs the FINAL,
// already-built Installer.exe by APPENDING a small signed trailer directly
// onto the end of the same file - no separate file to distribute, ever.
// Run ONLY on the secure build machine, AFTER the final Installer.exe has
// been fully built - never distributed to customers, never committed
// anywhere the Installer itself is built from (it links
// VendorIdentityPrivate.h, which must never ship).
//
// Usage:
//   NutriculaSignInstaller.exe <path_to_Installer.exe>
//
// Modifies the given exe IN PLACE (writes to a temp file then atomically
// replaces it - same pattern used elsewhere in this project for the
// license file). Safe to re-run on an already-signed exe: any existing
// trailer is stripped first, so the file is re-signed fresh each time
// rather than growing a new trailer on top of the old one.
//
// TRAILER FORMAT (appended after the exe's normal content):
//   [64 bytes]  raw (r||s) P-256 signature, over the SHA-256 of every byte
//               of the file BEFORE this trailer
//   [8 bytes]   ASCII magic marker "NUTRSIG1" - how both this tool and
//               SelfIntegrityCheck.cs recognize a trailer is present at all
//
// WHY APPENDING WORKS: Windows' PE loader (and the .NET CLR's own PE/
// metadata reader) only ever reads bytes described by the file's own
// section table / metadata size fields - never "read until end of file".
// Bytes appended after the last section are simply never touched by
// either loader. This is the same principle self-extracting archives and
// many single-file .NET publishing tools already rely on. Verified
// empirically for this project: a compiled test .exe with 72 arbitrary
// bytes appended ran identically before and after.
//

#include "../Coordinator/VendorIdentityPrivate.h"
#include "../Coordinator/EcdsaHelpers.h"

#include <windows.h>
#include <wincrypt.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "crypt32.lib")

namespace {

const char* MAGIC = "NUTRSIG1";
constexpr size_t MAGIC_LEN = 8;
constexpr size_t SIGNATURE_LEN = 64;
constexpr size_t TRAILER_LEN = SIGNATURE_LEN + MAGIC_LEN;

std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

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

void StripExistingTrailerIfPresent(std::vector<unsigned char>& bytes)
{
    if (bytes.size() < TRAILER_LEN) return;
    const unsigned char* magicStart = bytes.data() + bytes.size() - MAGIC_LEN;
    if (memcmp(magicStart, MAGIC, MAGIC_LEN) == 0)
    {
        bytes.resize(bytes.size() - TRAILER_LEN);
    }
}

bool WriteFileBytesAtomic(const std::wstring& path, const std::vector<unsigned char>& bytes)
{
    std::wstring tempPath = path + L".signing_tmp";
    HANDLE h = CreateFileW(tempPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    bool ok = WriteFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) != 0
        && written == bytes.size();
    FlushFileBuffers(h);
    CloseHandle(h);
    if (!ok) { DeleteFileW(tempPath.c_str()); return false; }
    ok = MoveFileExW(tempPath.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
    if (!ok) DeleteFileW(tempPath.c_str());
    return ok;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("Usage: %s <path_to_Installer.exe>\n", argv[0]);
        printf("  Signs the exe IN PLACE by appending a trailer - the exe stays a single file.\n");
        printf("  Safe to re-run: re-signs fresh instead of stacking trailers.\n");
        return 1;
    }

    std::wstring exePath = Utf8ToWide(argv[1]);

    std::vector<unsigned char> exeBytes;
    if (!ReadFileBytes(exePath, exeBytes))
    {
        printf("ERROR: could not read %s\n", argv[1]);
        return 1;
    }

    StripExistingTrailerIfPresent(exeBytes);

    unsigned char signature[SIGNATURE_LEN];
    bool signOk = EcdsaHelpers::SignP256(
        VendorIdentity::PrivateKeyD(), VendorIdentity::PrivateKeyPublicXY(),
        exeBytes.data(), exeBytes.size(),
        signature);
    if (!signOk)
    {
        printf("ERROR: signing failed.\n");
        return 1;
    }

    exeBytes.insert(exeBytes.end(), signature, signature + SIGNATURE_LEN);
    exeBytes.insert(exeBytes.end(), MAGIC, MAGIC + MAGIC_LEN);

    if (!WriteFileBytesAtomic(exePath, exeBytes))
    {
        printf("ERROR: could not write signed output to %s\n", argv[1]);
        return 1;
    }

    printf("OK: %s signed successfully (trailer appended, %zu bytes added).\n", argv[1], TRAILER_LEN);
    printf("This is now the FINAL file to distribute to customers - nothing else needed.\n");
    return 0;
}
