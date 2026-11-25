//
// NutriculaSignInstaller.cpp - build-time tool that signs the FINAL,
// already-built installer .exe files by APPENDING a small signed trailer
// directly onto the end of each file - no separate file to distribute, ever.
// Run ONLY on the secure build machine, AFTER the final installer file(s)
// have been fully built AND protected - never distributed to customers,
// never committed anywhere the Installer itself is built from (it links
// VendorIdentityPrivate.h, which must never ship). The protection differs
// by flavour (see below): ConfuserEx for the Windows installer, .NET
// Reactor for the two self-contained Mac/Linux-only builds - this tool
// only cares about the final .exe each one produces, never how it got
// there.
//
// THERE ARE THREE INSTALLER FLAVOURS (built by three separate GitHub Actions
// workflows from the same source). Both interactive mode (no arguments) and
// scripted mode (one path argument) handle ALL THREE - one by file NAME
// (workflow 1, unchanged from before), the other two by reading the exe's
// own PE header (never a name or a folder name):
//
//   "1. Windows - 32bit"
//        -> Nutricula-Unsigned-32bit.exe -> (ConfuserEx) -> Nutricula-32bit.exe
//           The installer for ALL Windows users (a 32-bit exe runs on both
//           32-bit and 64-bit Windows). Not bundled into Mac/Linux packages.
//           Recognised BY NAME and renamed (see KINDS[] below) - this path
//           through the tool is completely unchanged from before.
//
//   "2. Windows - 32bit (for Mac/Linux)" and
//   "3. Windows - 64bit (for Mac/Linux)"
//        -> Nutricula-Unsigned-{32,64}bit-SC.zip
//           Each is a zip of a whole self-contained PUBLISH FOLDER (the
//           native "NutriculaExpertInstaller.exe" apphost, the managed
//           "NutriculaExpertInstaller.dll" beside it, its ".deps.json" and
//           ".runtimeconfig.json", and dozens of .NET runtime files) - NOT a
//           single finished exe. ConfuserEx cannot touch these at all (it
//           only understands one plain managed assembly, never a
//           self-contained apphost or a whole publish folder), and neither
//           can .NET Reactor's own merge/embed features: those only operate
//           on managed .NET assemblies, never on the native runtime files
//           (coreclr.dll, hostfxr.dll, ...) that make up most of the folder.
//           So for these two, the FOLDER itself is what ships, unchanged
//           apart from its one managed .dll:
//             1) Extract the zip.
//             2) Run ONLY "NutriculaExpertInstaller.dll" (inside the
//                extracted folder) through .NET Reactor, with
//                "-target_runtime dotnet" - see README-GITHUB-BUILD.md for
//                the exact settings. Overwrite the plain .dll in the folder
//                with Reactor's protected output. Every other file in the
//                folder (the apphost exe, the runtime's own native/managed
//                files) is left exactly as dotnet publish produced it.
//             3) Run this tool on "NutriculaExpertInstaller.exe" INSIDE that
//                same extracted folder (see "TWO WAYS TO RUN IT" below for
//                exactly how for each mode). Its generic name carries no
//                "32"/"64", so instead of matching a name, this tool reads
//                the exe's own PE header directly to tell 32-bit from
//                64-bit - never a guess, never dependent on what the folder
//                happens to be called. It then signs the exe AND renames it,
//                AND its three same-named companions (.dll/.deps.json/
//                .runtimeconfig.json), ALL TOGETHER, to
//                "Nutricula-{32,64}bit-SC.*" - renaming only the exe and
//                leaving the others would break the self-contained app,
//                because a self-contained apphost finds its companion files
//                by matching its OWN file name exactly.
//             4) Place the WHOLE FOLDER (protected .dll + signed/renamed exe
//                + every untouched runtime file) into the repo's dist/
//                folder, one subfolder per architecture, for workflows
//                "4. Mac" and "5. Linux" to pick up. See
//                README-GITHUB-BUILD.md for the exact folder names expected
//                there.
//
//           This self-contained detection (step 3) is based purely on
//           CONTENT, never on a name: an exe is treated as a self-contained
//           apphost whenever a ".dll", ".deps.json" and ".runtimeconfig.json"
//           all exist right beside it under its EXACT same base name - three
//           files only ever produced together by a modern (.NET Core/5+)
//           self-contained "dotnet publish", never by the classic .NET
//           Framework 4.8 single EXE that workflow 1 produces. So this can
//           never misfire on the Windows-installer flavour, in either mode.
//
// TWO WAYS TO RUN IT (both now handle all three flavours):
//
//   1) Interactive (recommended, default, no arguments) - e.g. double-click
//      it. For the Windows-installer flavour: place
//      "Nutricula-Unsigned-32bit.exe" (already run through ConfuserEx) in
//      the SAME folder as NutriculaSignInstaller.exe. For a self-contained
//      Mac/Linux flavour: copy NutriculaSignInstaller.exe INTO the extracted,
//      Reactor-protected publish folder itself (right beside
//      "NutriculaExpertInstaller.exe"). Either way (or both at once, if you
//      happen to run it from a folder with both), it looks for all of them
//      next to itself, tells you what it found, then asks you to confirm
//      before signing.
//
//   2) Scripted (for automation) - one file at a time:
//        NutriculaSignInstaller.exe <path_to_an_exe>
//      Works the same for either flavour - pass the Windows installer's path,
//      or the path to the self-contained folder's "NutriculaExpertInstaller.exe".
//      Detection (by name for the Windows flavour, by PE header + companion
//      files for the self-contained one) is identical to interactive mode.
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
// bytes appended ran identically before and after (and the same was checked
// for a .NET single-file bundle, which the self-contained flavours are:
// appended bytes after the bundle do not disturb its start-up). The signature covers the
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

// The ONLY flavour this tool still recognises and renames by file name: the
// plain Windows installer (workflow 1). The two self-contained Mac/Linux
// flavours are never named like this any more (see the header comment) -
// their apphost exe keeps its generic dotnet-generated name and is always
// signed in place via scripted mode, which DetectKindFromFileName already
// falls back to below whenever a name matches no entry here.
struct InstallerKind
{
    const wchar_t* unsignedName;
    const wchar_t* finalName;
    const wchar_t* label;
    int  bits;             // 32 or 64
    bool isWindowsRelease; // true: this is the file Windows users download
};

const InstallerKind KINDS[] = {
    { L"Nutricula-Unsigned-32bit.exe", L"Nutricula-32bit.exe", L"32-bit (Windows)", 32, true },
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
// exactly one of "32" / "64" must be present AND match a known entry in
// KINDS[] (today, only the plain Windows installer). Neither or both of
// 32/64, or a bit count with no matching entry, returns nullptr - the caller
// must not guess. This is also what correctly handles the self-contained
// Mac/Linux apphost exe (a generic name such as "NutriculaExpertInstaller.exe"
// with neither "32" nor "64" in it): it always falls through to nullptr here,
// so the caller signs it in place and leaves its name untouched, which is
// exactly right for that flavour (see the header comment).
const InstallerKind* DetectKindFromFileName(const std::wstring& path)
{
    size_t slashPos = path.find_last_of(L"\\/");
    std::wstring name = (slashPos == std::wstring::npos) ? path : path.substr(slashPos + 1);
    for (wchar_t& c : name) c = (wchar_t)towlower(c);

    bool has32 = name.find(L"32") != std::wstring::npos;
    bool has64 = name.find(L"64") != std::wstring::npos;
    if (has32 == has64) return nullptr;
    int bits = has64 ? 64 : 32;

    for (size_t i = 0; i < KIND_COUNT; ++i)
    {
        if (KINDS[i].bits == bits)
            return &KINDS[i];
    }
    return nullptr;
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

// Reads the PE header's "Machine" field directly from an exe's own bytes
// (same check the build-mac.yml / build-linux.yml workflows already run on
// these files). Returns 0x014C for 32-bit (x86), 0x8664 for 64-bit (x64), or
// 0 if the file is not a readable, valid PE executable.
unsigned short ReadPEMachineField(const std::wstring& path)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0;
    unsigned char head[4096] = {0};
    DWORD readBytes = 0;
    BOOL ok = ReadFile(h, head, sizeof(head), &readBytes, nullptr);
    CloseHandle(h);
    if (!ok || readBytes < 0x40) return 0;
    if (head[0] != 'M' || head[1] != 'Z') return 0;

    unsigned int peOffset;
    memcpy(&peOffset, head + 0x3C, sizeof(peOffset));
    if ((size_t)peOffset + 6 > readBytes) return 0;
    if (memcmp(head + peOffset, "PE\0\0", 4) != 0) return 0;

    unsigned short machine;
    memcpy(&machine, head + peOffset + 4, sizeof(machine));
    return machine;
}

// An exe is treated as a self-contained Mac/Linux-only apphost - never the
// plain Windows installer - whenever ALL THREE of these exist right beside
// it, sharing its EXACT base name (case-insensitively): ".dll",
// ".deps.json", ".runtimeconfig.json". Those three are only ever produced
// together by a modern self-contained "dotnet publish" (see the header
// comment) - the classic .NET Framework 4.8 single EXE that workflow 1
// produces never has them, so this can never misfire on that flavour.
// On success, outBaseNoExt receives exePath with its trailing ".exe"
// removed (same casing/path as given).
bool LooksLikeSelfContainedApphost(const std::wstring& exePath, std::wstring& outBaseNoExt)
{
    if (!FileExistsAndIsFile(exePath)) return false;
    if (exePath.size() < 4) return false;
    std::wstring lower4 = exePath.substr(exePath.size() - 4);
    for (wchar_t& c : lower4) c = (wchar_t)towlower(c);
    if (lower4 != L".exe") return false;

    std::wstring baseNoExt = exePath.substr(0, exePath.size() - 4);
    const wchar_t* companionSuffixes[] = { L".dll", L".deps.json", L".runtimeconfig.json" };
    for (const wchar_t* suffix : companionSuffixes)
    {
        if (!FileExistsAndIsFile(baseNoExt + suffix)) return false;
    }

    outBaseNoExt = baseNoExt;
    return true;
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

// Signs and renames a self-contained Mac/Linux apphost exe found via
// LooksLikeSelfContainedApphost: architecture (32 vs 64-bit) is read
// directly from the exe's OWN PE header, never guessed from any name, so
// this works regardless of what the enclosing folder happens to be called.
// Only the exe's bytes are signed (the trailer belongs on the apphost that
// actually starts; its .dll was already protected separately by .NET
// Reactor, and .deps.json/.runtimeconfig.json are plain config, never
// signed). All four same-named files are then renamed TOGETHER to
// "Nutricula-{bits}bit-SC.*" in the same folder - never just the exe alone,
// since a self-contained apphost finds its companions by matching its own
// file name exactly. Prints its own messages; returns 0 on success.
int SignSelfContainedApphost(const std::wstring& exePath, const std::wstring& baseNoExt)
{
    unsigned short machine = ReadPEMachineField(exePath);
    int bits;
    if (machine == 0x014C) bits = 32;
    else if (machine == 0x8664) bits = 64;
    else
    {
        printf("ERROR: could not read a valid PE header from the apphost exe, or its\n");
        printf("architecture is neither 32-bit (x86) nor 64-bit (x64).\n");
        return 1;
    }
    wprintf(L"Detected: %d-bit self-contained apphost (read from its own PE header).\n", bits);

    int rc = SignInstallerFile(exePath, exePath); // sign in place; rename happens below
    if (rc != 0) return rc;

    std::wstring dir = DirectoryOf(exePath);
    std::wstring finalBase = dir + L"Nutricula-" + std::to_wstring(bits) + L"bit-SC";

    struct { const wchar_t* suffix; } parts[] = { {L".exe"}, {L".dll"}, {L".deps.json"}, {L".runtimeconfig.json"} };
    int renameFailures = 0;
    for (const auto& part : parts)
    {
        std::wstring from = baseNoExt + part.suffix;
        std::wstring to = finalBase + part.suffix;
        if (PathsEqualIgnoreCase(from, to)) continue;
        if (!MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            wprintf(L"WARNING: could not rename %ls to %ls (is it open elsewhere?).\n", from.c_str(), to.c_str());
            ++renameFailures;
        }
    }

    if (renameFailures > 0)
    {
        printf("\nERROR: signed successfully, but %d of the 4 companion file(s) could not be\n", renameFailures);
        printf("renamed - see the warning(s) above. Rename them all yourself, to the same\n");
        wprintf(L"base name (%ls), before using this folder.\n", finalBase.c_str());
        return 1;
    }

    printf("\n");
    wprintf(L"OK: signed and renamed to %ls.exe / .dll / .deps.json / .runtimeconfig.json\n", finalBase.c_str());
    printf("Next step:\n");
    wprintf(L"  Copy the WHOLE folder (not just these 4 files) into the repo's dist\\Nutricula-%dbit-SC\\\n", bits);
    printf("  folder (the Mac and Linux workflows bundle it). It is NOT for Windows users.\n");
    return 0;
}

int RunInteractive()
{
    std::wstring dir = GetExeDirectory();

    printf("Looking for the installer file(s) next to NutriculaSignInstaller.exe...\n\n");

    // Self-contained Mac/Linux apphost candidate: checked independently of
    // KINDS[] below, since its architecture comes from its own PE header,
    // never from a name. This is unaffected by, and does not affect, the
    // Windows-installer detection loop right after it.
    std::wstring scCandidate = dir + L"NutriculaExpertInstaller.exe";
    std::wstring scBaseNoExt;
    bool scFound = LooksLikeSelfContainedApphost(scCandidate, scBaseNoExt);
    if (scFound)
    {
        long long size = GetFileSizeQuick(scCandidate);
        if (size >= 0)
            wprintf(L"  FOUND      NutriculaExpertInstaller.exe (%lld bytes) - self-contained apphost (Mac/Linux)\n", size);
        else
            printf("  FOUND      NutriculaExpertInstaller.exe - self-contained apphost (Mac/Linux)\n");
    }
    else
    {
        printf("  not found  NutriculaExpertInstaller.exe - self-contained apphost (Mac/Linux) (skipped)\n");
    }

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

    if (foundKinds.empty() && !scFound)
    {
        printf("ERROR: no installer file was found next to NutriculaSignInstaller.exe.\n");
        printf("Place the already-obfuscated Windows installer in the SAME folder as\n");
        printf("NutriculaSignInstaller.exe, named exactly:\n");
        for (size_t i = 0; i < KIND_COUNT; ++i)
            wprintf(L"  %ls\n", KINDS[i].unsignedName);
        printf("- or, for a self-contained Mac/Linux build, copy NutriculaSignInstaller.exe\n");
        printf("INTO the extracted, Reactor-protected publish folder itself (next to its own\n");
        printf("NutriculaExpertInstaller.exe), and run it again there.\n");
        return 1;
    }

    int totalFound = (int)foundKinds.size() + (scFound ? 1 : 0);
    if (!PromptYesNo(totalFound == 1 ? "Sign this file now? (y/n): " : "Sign these files now? (y/n): "))
    {
        printf("ERROR: cancelled - you answered no, nothing was signed.\n");
        return 1;
    }

    int failures = 0;

    if (scFound)
    {
        printf("\n--- NutriculaExpertInstaller.exe (self-contained apphost) ---\n");
        if (SignSelfContainedApphost(scCandidate, scBaseNoExt) != 0) ++failures;
    }

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
    // Self-contained Mac/Linux apphost (detected purely by content - its
    // three companion files - never by name): checked FIRST, before the
    // Windows-installer name match below, since this check can never
    // misfire on that flavour (see the header comment).
    std::wstring scBaseNoExt;
    if (LooksLikeSelfContainedApphost(sourcePath, scBaseNoExt))
    {
        return SignSelfContainedApphost(sourcePath, scBaseNoExt);
    }

    const InstallerKind* kind = DetectKindFromFileName(sourcePath);
    std::wstring finalPath;
    if (kind != nullptr)
    {
        finalPath = DirectoryOf(sourcePath) + kind->finalName;
    }
    else
    {
        finalPath = sourcePath;
        printf("NOTE: the file name does not identify the Windows-installer flavour (it needs\n");
        printf("exactly one of \"32\" / \"64\"), and it is not a self-contained apphost either\n");
        printf("(no matching .dll/.deps.json/.runtimeconfig.json beside it) - signing in\n");
        printf("place, name left unchanged.\n\n");
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
    printf("Interactive mode (recommended): run with no arguments from either\n");
    printf(" - the folder containing the already-obfuscated Windows installer, named exactly\n");
    for (size_t i = 0; i < KIND_COUNT; ++i)
        wprintf(L"     %ls\n", KINDS[i].unsignedName);
    printf(" - or the extracted, Reactor-protected self-contained publish folder itself\n");
    printf("   (next to its own NutriculaExpertInstaller.exe)\n\n");
    wprintf(L"  %ls\n\n", exeName.c_str());
    printf("Scripted mode (either flavour, one file at a time):\n");
    printf("  %s <path_to_an_exe>\n", argv[0]);
    return 1;
}
