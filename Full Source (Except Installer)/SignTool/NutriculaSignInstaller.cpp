//
// NutriculaSignInstaller.cpp - build-time tool that signs the FINAL,
// already-built installer .exe files by APPENDING a small signed trailer
// directly onto the end of each file - no separate file to distribute, ever.
// Run ONLY on the secure build machine, AFTER the final installer .exe files
// have been fully built (and run through ConfuserEx) - never distributed to
// customers, never committed anywhere the Installer itself is built from (it
// links VendorIdentityPrivate.h, which must never ship).
//
// THERE ARE TWO INSTALLER FLAVOURS (built by two separate GitHub Actions
// workflows from the same source):
//
//   "Windows - 32bit"  ->  Nutricula-Unsigned-32bit.exe  ->  Nutricula-32bit.exe
//   "Windows - 64bit"  ->  Nutricula-Unsigned-64bit.exe  ->  Nutricula-64bit.exe
//
//   (left: workflow name, middle: the file name the workflow outputs and
//   ConfuserEx keeps, right: the file name this tool produces.) This tool
//   recognises a file as the 32-bit or the 64-bit flavour purely by that
//   "32" / "64" in its file name, signs it, and gives it the clean final
//   name on the right - NO "-Signed" suffix any more.
//
// TWO WAYS TO RUN IT:
//
//   1) Interactive (recommended, default) - place the ConfuserEx'd
//      Nutricula-Unsigned-32bit.exe and/or Nutricula-Unsigned-64bit.exe in
//      the SAME folder as NutriculaSignInstaller.exe, then run
//      NutriculaSignInstaller.exe with NO arguments (e.g. double-click it).
//      It looks for BOTH names next to itself, tells you which one(s) it
//      found, then asks you to confirm before signing every file it found.
//      Having only one of the two is fine - only that one is signed.
//      Each file is signed in place and then renamed to its final name, so
//      only the finished file is left.
//
//   2) Scripted (for automation) - one file at a time:
//        NutriculaSignInstaller.exe <path_to_installer.exe>
//      The 32/64 flavour is read from the file's NAME (not its folder).
//      The file is signed in place and then renamed (next to where it is) to
//      the final name above. If the name has neither or both of "32" / "64",
//      the file is signed in place and keeps its name (nothing is guessed).
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
// bytes appended ran identically before and after. The signature covers the
// file's bytes only, never its name, so renaming a signed file is harmless.
//
// Safe to re-run: any existing trailer is stripped first, so a file is
// re-signed fresh each time rather than growing a new trailer on top of the
// old one. If a final file with the target name already exists (for
// example from an earlier build), it is replaced by the new one.
//

#include "../Coordinator/VendorIdentityPrivate.h"
#include "../Coordinator/EcdsaHelpers.h"

#include <windows.h>
#include <wincrypt.h>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <string>
#include <vector>
#include <iostream>

#pragma comment(lib, "crypt32.lib")

namespace {

const char* MAGIC = "NUTRSIG1";
constexpr size_t MAGIC_LEN = 8;
constexpr size_t SIGNATURE_LEN = 64;
constexpr size_t TRAILER_LEN = SIGNATURE_LEN + MAGIC_LEN;

// The file names the two GitHub Actions workflows output (and ConfuserEx
// keeps) and the clean names this tool gives them once signed. (The two
// flavours are told apart by "32" / "64" in the file name.)
struct InstallerKind
{
    const wchar_t* unsignedName;
    const wchar_t* finalName;
    const wchar_t* label;
    bool isWindowsRelease; // true: this is the file Windows users download
};

const InstallerKind KINDS[] = {
    { L"Nutricula-Unsigned-32bit.exe", L"Nutricula-32bit.exe", L"32-bit", true  },
    { L"Nutricula-Unsigned-64bit.exe", L"Nutricula-64bit.exe", L"64-bit", false },
};
constexpr size_t KIND_COUNT = sizeof(KINDS) / sizeof(KINDS[0]);

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

// Decides which flavour a file is from its NAME alone (never its folder):
// contains "64" only -> 64-bit, contains "32" only -> 32-bit. Neither, or
// both, is ambiguous and returns nullptr - the caller must not guess.
const InstallerKind* DetectKindFromFileName(const std::wstring& path)
{
    size_t slashPos = path.find_last_of(L"\\/");
    std::wstring name = (slashPos == std::wstring::npos) ? path : path.substr(slashPos + 1);
    for (wchar_t& c : name) c = (wchar_t)towlower(c);

    bool has32 = name.find(L"32") != std::wstring::npos;
    bool has64 = name.find(L"64") != std::wstring::npos;
    if (has32 == has64) return nullptr;
    return has64 ? &KINDS[1] : &KINDS[0];
}

std::wstring DirectoryOf(const std::wstring& path)
{
    size_t slashPos = path.find_last_of(L"\\/");
    return (slashPos == std::wstring::npos) ? std::wstring() : path.substr(0, slashPos + 1);
}

bool PathsEqualIgnoreCase(const std::wstring& a, const std::wstring& b)
{
    return _wcsicmp(a.c_str(), b.c_str()) == 0;
}

// Shared by both interactive and scripted mode: reads sourcePath, strips any
// existing trailer, signs, writes the signed bytes back in place (atomically),
// then renames the file to finalPath (unless that is the same name already).
// Same flow as before the 32/64-bit split - only the target name differs.
// Prints its own success/error messages. Returns 0 on success, 1 on failure
// (including the case where signing worked but the final rename did not).
int SignInstallerFile(const std::wstring& sourcePath, const std::wstring& finalPath)
{
    std::vector<unsigned char> exeBytes;
    if (!ReadFileBytes(sourcePath, exeBytes))
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

    if (!WriteFileBytesAtomic(sourcePath, exeBytes))
    {
        printf("ERROR: could not write signed output.\n");
        return 1;
    }

    if (!PathsEqualIgnoreCase(sourcePath, finalPath))
    {
        if (!MoveFileExW(sourcePath.c_str(), finalPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            printf("WARNING: signed successfully, but the file could not be renamed to its final name\n");
            printf("(is a file with the final name open in another program?).\n");
            wprintf(L"It is still fully signed under its original name: %ls\n", sourcePath.c_str());
            wprintf(L"Rename it yourself to: %ls\n", finalPath.c_str());
            return 1;
        }
    }

    printf("OK: signed successfully (trailer appended, %zu bytes added).\n", TRAILER_LEN);
    wprintf(L"Final file: %ls\n", finalPath.c_str());
    return 0;
}

// Prints what to do with a finished file, based on its flavour.
void PrintNextStep(const InstallerKind* kind)
{
    if (kind == nullptr) return;
    if (kind->isWindowsRelease)
    {
        wprintf(L"  %ls: publish this one for Windows users, AND copy it into the repo's dist\\ folder\n", kind->finalName);
        printf("  (the Mac and Linux workflows bundle it).\n");
    }
    else
    {
        wprintf(L"  %ls: copy it into the repo's dist\\ folder (the Mac and Linux workflows bundle it).\n", kind->finalName);
        printf("  It is NOT for Windows users.\n");
    }
}

int RunInteractive()
{
    std::wstring dir = GetExeDirectory();

    printf("Looking for the installer file(s) next to NutriculaSignInstaller.exe...\n\n");

    std::vector<const InstallerKind*> foundKinds;
    for (size_t i = 0; i < KIND_COUNT; ++i)
    {
        const InstallerKind& kind = KINDS[i];
        std::wstring path = dir + kind.unsignedName;
        if (FileExistsAndIsFile(path))
        {
            long long size = GetFileSizeQuick(path);
            if (size >= 0)
                wprintf(L"  FOUND      %ls (%lld bytes) - %ls\n", kind.unsignedName, size, kind.label);
            else
                wprintf(L"  FOUND      %ls - %ls\n", kind.unsignedName, kind.label);
            foundKinds.push_back(&kind);
        }
        else
        {
            wprintf(L"  not found  %ls - %ls (skipped)\n", kind.unsignedName, kind.label);
        }
    }
    printf("\n");

    if (foundKinds.empty())
    {
        printf("ERROR: no installer file was found next to NutriculaSignInstaller.exe.\n");
        printf("Place the ConfuserEx'd installer(s) in the SAME folder as\n");
        printf("NutriculaSignInstaller.exe, named exactly:\n");
        for (size_t i = 0; i < KIND_COUNT; ++i)
            wprintf(L"  %ls\n", KINDS[i].unsignedName);
        printf("and run this again (one of the two is enough).\n");
        return 1;
    }

    if (!PromptYesNo(foundKinds.size() == 1 ? "Sign this file now? (y/n): " : "Sign these files now? (y/n): "))
    {
        printf("ERROR: cancelled - you answered no, nothing was signed.\n");
        return 1;
    }

    int failures = 0;
    std::vector<const InstallerKind*> signedKinds;
    for (const InstallerKind* kind : foundKinds)
    {
        printf("\n");
        wprintf(L"--- %ls -> %ls ---\n", kind->unsignedName, kind->finalName);
        int rc = SignInstallerFile(dir + kind->unsignedName, dir + kind->finalName);
        if (rc == 0) signedKinds.push_back(kind);
        else ++failures;
    }

    printf("\n");
    if (!signedKinds.empty())
    {
        printf("Next steps:\n");
        for (const InstallerKind* kind : signedKinds) PrintNextStep(kind);
    }
    if (failures > 0)
    {
        printf("\nERROR: %d file(s) could not be completed - see the messages above.\n", failures);
        return 1;
    }
    return 0;
}

int RunScripted(const std::wstring& sourcePath)
{
    const InstallerKind* kind = DetectKindFromFileName(sourcePath);
    std::wstring finalPath;
    if (kind != nullptr)
    {
        finalPath = DirectoryOf(sourcePath) + kind->finalName;
    }
    else
    {
        finalPath = sourcePath;
        printf("NOTE: the file name has neither (or both of) \"32\" and \"64\", so the 32/64-bit\n");
        printf("flavour cannot be told from it - signing in place, name left unchanged.\n\n");
    }

    int rc = SignInstallerFile(sourcePath, finalPath);
    if (rc == 0 && kind != nullptr)
    {
        printf("\nNext step:\n");
        PrintNextStep(kind);
    }
    return rc;
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
        return RunScripted(Utf8ToWide(argv[1]));
    }

    std::wstring exeName = Utf8ToWide(argv[0]);
    printf("Interactive mode (recommended): place the ConfuserEx'd installer(s), named exactly\n");
    for (size_t i = 0; i < KIND_COUNT; ++i)
        wprintf(L"  %ls\n", KINDS[i].unsignedName);
    wprintf(L"next to %ls with no arguments (one of the two is enough).\n\n", exeName.c_str());
    printf("Scripted mode: %s <path_to_installer.exe>\n", argv[0]);
    return 1;
}
