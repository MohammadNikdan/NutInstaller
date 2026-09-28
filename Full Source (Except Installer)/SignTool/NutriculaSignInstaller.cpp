//
// NutriculaSignInstaller.cpp - build-time tool that signs the FINAL,
// already-built Installer.exe by APPENDING a small signed trailer directly
// onto the end of the same file - no separate file to distribute, ever.
// Run ONLY on the secure build machine, AFTER the final Installer.exe has
// been fully built - never distributed to customers, never committed
// anywhere the Installer itself is built from (it links
// VendorIdentityPrivate.h, which must never ship).
//
// TWO WAYS TO RUN IT:
//
//   1) Interactive (recommended, default) - just place the Installer.exe
//      produced by the GitHub Actions build (named exactly
//      "NutriculaExpertInstaller.exe") in the SAME folder as
//      NutriculaSignInstaller.exe, then run NutriculaSignInstaller.exe
//      with NO arguments (e.g. double-click it). It looks for that file
//      next to itself, tells you if it's missing, otherwise asks you to
//      confirm before signing. After a successful sign, the file is
//      renamed to end in "-Signed" (e.g. "NutriculaExpertInstaller-
//      Signed.exe") so it's obvious at a glance that this exact file has
//      already been signed - that renamed file is the one and only thing
//      you give to customers.
//
//   2) Scripted (for automation) - the original argument form:
//        NutriculaSignInstaller.exe <path_to_Installer.exe>
//      Still fully supported, and also renames the file to add the
//      "-Signed" suffix after signing, same as interactive mode.
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
// Safe to re-run on an already-signed exe: any existing trailer is
// stripped first, so the file is re-signed fresh each time rather than
// growing a new trailer on top of the old one. If the file's name already
// ends in "-Signed", it is re-signed in place and NOT renamed again (so
// re-running this tool never produces "-Signed-Signed").
//

#include "../Coordinator/VendorIdentityPrivate.h"
#include "../Coordinator/EcdsaHelpers.h"

#include <windows.h>
#include <wincrypt.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>

#pragma comment(lib, "crypt32.lib")

namespace {

const char* MAGIC = "NUTRSIG1";
constexpr size_t MAGIC_LEN = 8;
constexpr size_t SIGNATURE_LEN = 64;
constexpr size_t TRAILER_LEN = SIGNATURE_LEN + MAGIC_LEN;

// The exact file name the GitHub Actions build produces (AssemblyName in
// NutriculaInstaller.csproj) - interactive mode looks for exactly this,
// next to NutriculaSignInstaller.exe itself.
const wchar_t* EXPECTED_INSTALLER_NAME = L"NutriculaExpertInstaller.exe";
const wchar_t* SIGNED_SUFFIX = L"-Signed";

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

// The folder NutriculaSignInstaller.exe itself is running from, with a
// trailing backslash.
std::wstring GetExeDirectory()
{
    wchar_t buf[MAX_PATH];
    DWORD len = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return L".\\";
    std::wstring path(buf, len);
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return L".\\";
    return path.substr(0, pos + 1);
}

bool FileExistsAndIsFile(const std::wstring& path)
{
    DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

// -1 if the size could not be read.
long long GetFileSizeQuick(const std::wstring& path)
{
    WIN32_FILE_ATTRIBUTE_DATA data;
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) return -1;
    LARGE_INTEGER size;
    size.HighPart = data.nFileSizeHigh;
    size.LowPart = data.nFileSizeLow;
    return static_cast<long long>(size.QuadPart);
}

bool PromptYesNo(const char* prompt)
{
    std::string line;
    printf("%s", prompt);
    fflush(stdout);
    if (!std::getline(std::cin, line)) return false;
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
    for (char& c : line) c = (char)tolower((unsigned char)c);
    return line == "y" || line == "yes";
}

// Inserts "-Signed" right before the file extension, e.g.
// "NutriculaExpertInstaller.exe" -> "NutriculaExpertInstaller-Signed.exe".
// If the name (without extension) already ends in "-Signed", the path is
// returned unchanged - re-signing an already-renamed file never stacks a
// second suffix.
std::wstring BuildSignedName(const std::wstring& path)
{
    size_t slashPos = path.find_last_of(L"\\/");
    size_t dirEnd = (slashPos == std::wstring::npos) ? 0 : slashPos + 1;
    std::wstring dir = path.substr(0, dirEnd);
    std::wstring fileName = path.substr(dirEnd);

    size_t dotPos = fileName.find_last_of(L'.');
    std::wstring stem = (dotPos == std::wstring::npos) ? fileName : fileName.substr(0, dotPos);
    std::wstring ext = (dotPos == std::wstring::npos) ? L"" : fileName.substr(dotPos);

    size_t suffixLen = wcslen(SIGNED_SUFFIX);
    if (stem.size() >= suffixLen && stem.compare(stem.size() - suffixLen, suffixLen, SIGNED_SUFFIX) == 0)
    {
        return path; // already ends in "-Signed" - leave the name as-is
    }
    return dir + stem + SIGNED_SUFFIX + ext;
}

// Shared by both interactive and scripted mode: reads exePath, strips any
// existing trailer, signs, writes back in place, then renames to add the
// "-Signed" suffix (unless it already has one). Prints its own
// success/error messages. Returns 0 on success, 1 on failure.
int SignExeAndRename(const std::wstring& exePath)
{
    std::vector<unsigned char> exeBytes;
    if (!ReadFileBytes(exePath, exeBytes))
    {
        printf("ERROR: could not read the installer file.\n");
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
        printf("ERROR: signing failed - is Keys\\VendorSigningKey_Private.pem populated with a real key?\n");
        return 1;
    }

    exeBytes.insert(exeBytes.end(), signature, signature + SIGNATURE_LEN);
    exeBytes.insert(exeBytes.end(), MAGIC, MAGIC + MAGIC_LEN);

    if (!WriteFileBytesAtomic(exePath, exeBytes))
    {
        printf("ERROR: could not write signed output.\n");
        return 1;
    }

    std::wstring finalPath = BuildSignedName(exePath);
    if (finalPath != exePath)
    {
        if (!MoveFileExW(exePath.c_str(), finalPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            printf("OK: signed successfully, but the file could not be renamed to add \"-Signed\".\n");
            wprintf(L"It is still fully signed under its original name: %ls\n", exePath.c_str());
            printf("You can rename it yourself, or run this tool again.\n");
            return 0;
        }
    }

    printf("OK: signed successfully (trailer appended, %zu bytes added).\n", TRAILER_LEN);
    wprintf(L"Final file: %ls\n", finalPath.c_str());
    printf("This is now the FINAL file to distribute to customers - nothing else needed.\n");
    return 0;
}

int RunInteractive()
{
    std::wstring dir = GetExeDirectory();
    std::wstring targetPath = dir + EXPECTED_INSTALLER_NAME;

    wprintf(L"Looking for %ls next to NutriculaSignInstaller.exe...\n", EXPECTED_INSTALLER_NAME);

    if (!FileExistsAndIsFile(targetPath))
    {
        wprintf(L"ERROR: %ls was not found next to NutriculaSignInstaller.exe.\n", EXPECTED_INSTALLER_NAME);
        printf("Place the Installer .exe built by GitHub Actions in the SAME folder as\n");
        wprintf(L"NutriculaSignInstaller.exe, named exactly \"%ls\", and run this again.\n", EXPECTED_INSTALLER_NAME);
        return 1;
    }

    long long size = GetFileSizeQuick(targetPath);
    if (size >= 0)
        wprintf(L"Found %ls (%lld bytes).\n", EXPECTED_INSTALLER_NAME, size);
    else
        wprintf(L"Found %ls.\n", EXPECTED_INSTALLER_NAME);

    if (!PromptYesNo("Sign this file now? (y/n): "))
    {
        printf("ERROR: cancelled - you answered no, nothing was signed.\n");
        return 1;
    }
    printf("\n");

    return SignExeAndRename(targetPath);
}

} // namespace

int main(int argc, char** argv)
{
    if (argc == 1)
    {
        return RunInteractive();
    }
    if (argc == 2)
    {
        return SignExeAndRename(Utf8ToWide(argv[1]));
    }

    std::wstring exeName = Utf8ToWide(argv[0]);
    printf("Interactive mode (recommended): place the GitHub-built installer .exe, named\n");
    wprintf(L"exactly \"%ls\", next to %ls with no arguments.\n\n", EXPECTED_INSTALLER_NAME, exeName.c_str());
    printf("Scripted mode: %s <path_to_Installer.exe>\n", argv[0]);
    return 1;
}
