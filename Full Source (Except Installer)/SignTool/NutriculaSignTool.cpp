//
// NutriculaSignTool.cpp - offline build-signing tool (architecture point
// 32/117). Run ONLY on the secure build machine, never distributed to
// customers, never committed anywhere the DLL/Service/Broker are built
// from (it links VendorIdentityPrivate.h, which must never ship).
//
// TWO WAYS TO RUN IT:
//
//   1) Interactive (recommended, default) - just run NutriculaSignTool.exe
//      with NO arguments, e.g. by double-clicking it or typing its name
//      alone in Command Prompt. It expects all 10 required build artifacts
//      (see RequiredArtifacts() below) to already be sitting in the SAME
//      folder as NutriculaSignTool.exe itself - it checks for each one by
//      name, tells you which (if any) are missing, and if all 10 are
//      present it asks you for build_id/version/protocol_version one at a
//      time, then writes manifest.txt AND database_insert.sql into that
//      same folder. This avoids ever having to type or paste a long
//      multi-line command into Command Prompt.
//
//   2) Scripted (for automation/CI) - the original argument form:
//        NutriculaSignTool.exe <build_id> <version> <protocol_version>
//            <path_to_ex5> <path_to_ex4> <path_to_dll32> <path_to_dll64>
//            <path_to_machineid32> <path_to_machineid64>
//            <path_to_service32> <path_to_service64>
//            <path_to_broker32> <path_to_broker64>
//            <output_manifest_path>
//      Still fully supported, unchanged, for anyone scripting a build.
//
// Both ways produce manifest.txt in the exact field=value\n... +
// signature=<base64> format ManifestVerify.cpp expects, AND a
// database_insert.sql file with a ready-to-run INSERT statement for
// nutricula_build_manifests (see BuildDbInsertSql below) written right
// next to manifest.txt - so the only manual step left is pasting that SQL
// into your database client.
//
// Both architectures of Service/Broker are hashed and included in one
// manifest, since a single build/release genuinely ships both 32-bit and
// 64-bit Coordinator binaries now (32-bit Windows hosts are a real,
// supported case) - the Installer picks which one to actually install
// based on the CUSTOMER's OS bitness, and whichever one gets installed
// must be independently verifiable against its own hash, not a hash for
// the other architecture.
//
// MachineId32.dll/MachineId64.dll are hashed and included the same way as
// dll32/dll64 above (both architectures, unconditionally, BOTH always
// required) - this DLL is loaded by both the thin License Check DLL and
// the Coordinator itself (MachineIdBridge), and a tampered copy could
// spoof or freeze machine_id without touching any other file, so it must
// be covered by this same manifest just like every other shipped
// artifact. Unlike Service/Broker (where only ONE architecture is ever
// actually installed on a given customer machine, so either one matching
// is accepted), a 32-bit MT4 and a 64-bit MT5 can both be talking to the
// SAME Coordinator at once, each needing its own genuine MachineId DLL -
// so, like dll32/dll64, BOTH architectures must always be present and
// BOTH hashes must always match, never an either/or check.
//

#include "../Coordinator/ManifestVerify.h"
#include "../Coordinator/VendorIdentityPrivate.h"
#include "../Coordinator/EcdsaHelpers.h"
#include "../Coordinator/CoordinatorProtocol.h"

#include <windows.h>
#include <wincrypt.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <sstream>
#include <iostream>
#include <vector>

#pragma comment(lib, "crypt32.lib")

namespace {

// ----------------------------------------------------------------------
// Shared helpers (used by both the interactive and the scripted path)
// ----------------------------------------------------------------------

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

// All 10 artifact hashes a manifest needs, gathered in one place so both
// the interactive and scripted paths build/sign/write the exact same way.
struct HashSet
{
    std::string ex5, ex4, dll32, dll64, machineid32, machineid64;
    std::string service32, service64, broker32, broker64;
};

// Hashes all 10 artifacts. Returns true only if every single one hashed
// successfully; on the first failure, firstFailureLabel is set to a short
// name identifying which artifact failed (e.g. "MachineId32.dll") so the
// caller can report exactly what went wrong - never silently skipped.
bool HashAllArtifacts(
    const std::wstring& ex5Path, const std::wstring& ex4Path,
    const std::wstring& dll32Path, const std::wstring& dll64Path,
    const std::wstring& machineid32Path, const std::wstring& machineid64Path,
    const std::wstring& service32Path, const std::wstring& service64Path,
    const std::wstring& broker32Path, const std::wstring& broker64Path,
    HashSet& out, std::vector<std::string>& failedLabels)
{
    struct Item { const std::wstring* path; std::string HashSet::* field; const char* label; };
    Item items[] = {
        { &ex5Path,         &HashSet::ex5,         "Nutricula.ex5" },
        { &ex4Path,         &HashSet::ex4,         "Nutricula.ex4" },
        { &dll32Path,       &HashSet::dll32,       "NutriculaLicenseCheck32.dll" },
        { &dll64Path,       &HashSet::dll64,       "NutriculaLicenseCheck64.dll" },
        { &machineid32Path, &HashSet::machineid32, "MachineId32.dll" },
        { &machineid64Path, &HashSet::machineid64, "MachineId64.dll" },
        { &service32Path,   &HashSet::service32,   "NutriculaLicenseService32.exe" },
        { &service64Path,   &HashSet::service64,   "NutriculaLicenseService64.exe" },
        { &broker32Path,    &HashSet::broker32,    "NutriculaLicenseBroker32.exe" },
        { &broker64Path,    &HashSet::broker64,    "NutriculaLicenseBroker64.exe" },
    };
    bool allOk = true;
    for (const Item& it : items)
    {
        std::string h = ManifestVerify::HashFileSha256(*it.path);
        out.*(it.field) = h;
        if (h.empty())
        {
            allOk = false;
            failedLabels.push_back(it.label);
        }
    }
    return allOk;
}

// Builds the exact field=value\n... text ManifestVerify.cpp expects, signs
// it with the Vendor private key, and appends the final signature= line.
// Returns "" (with signOk=false) if signing itself failed - the caller
// must check signOk, not just emptiness, since an empty manifest is never
// otherwise produced.
std::string BuildSignedManifestText(
    const std::string& buildId, const std::string& version, const std::string& protocolVersion,
    const HashSet& h, bool& signOk)
{
    std::ostringstream ss;
    ss << "build_id=" << buildId << "\n";
    ss << "version=" << version << "\n";
    ss << "protocol_version=" << protocolVersion << "\n";
    ss << "ex5_sha256=" << h.ex5 << "\n";
    ss << "ex4_sha256=" << h.ex4 << "\n";
    ss << "dll32_sha256=" << h.dll32 << "\n";
    ss << "dll64_sha256=" << h.dll64 << "\n";
    ss << "machineid32_sha256=" << h.machineid32 << "\n";
    ss << "machineid64_sha256=" << h.machineid64 << "\n";
    ss << "service32_sha256=" << h.service32 << "\n";
    ss << "service64_sha256=" << h.service64 << "\n";
    ss << "broker32_sha256=" << h.broker32 << "\n";
    ss << "broker64_sha256=" << h.broker64 << "\n";
    std::string signedPortion = ss.str();

    unsigned char signature[64];
    signOk = EcdsaHelpers::SignP256(
        VendorIdentity::PrivateKeyD(), VendorIdentity::PrivateKeyPublicXY(),
        reinterpret_cast<const unsigned char*>(signedPortion.data()), signedPortion.size(),
        signature);
    if (!signOk) return "";
    return signedPortion + "signature=" + Base64Encode(signature, 64) + "\n";
}

// A single quote inside build_id/version/protocol_version would otherwise
// break out of the SQL string literal it's embedded in below - escape it
// the standard SQL way (doubled) rather than assuming operators will never
// type one. The hash values themselves are always hex digits and never
// need this.
std::string SqlEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s)
    {
        if (c == '\'') out += "''";
        else out += c;
    }
    return out;
}

// The one manual step left after this tool runs: a ready-to-paste INSERT
// for nutricula_build_manifests, using the exact same values just signed
// into manifest.txt - see "Instruction (ReadMe)/How to use SignTool and
// make the manifest.txt file.html" for what this is for and why it must
// always be an INSERT (a new row), never an UPDATE.
std::string BuildDbInsertSql(
    const std::string& buildId, const std::string& version, const std::string& protocolVersion,
    const HashSet& h)
{
    std::ostringstream ss;
    ss << "-- Auto-generated by NutriculaSignTool alongside manifest.txt for build_id="
       << buildId << ".\n";
    ss << "-- Paste this directly into your SQL client. Always INSERT a NEW row - never\n";
    ss << "-- UPDATE an existing build_id's row (see the SignTool README for why).\n";
    ss << "INSERT INTO nutricula_build_manifests\n";
    ss << "    (build_id, version, protocol_version,\n";
    ss << "     ex5_sha256, ex4_sha256, dll32_sha256, dll64_sha256,\n";
    ss << "     machineid32_sha256, machineid64_sha256,\n";
    ss << "     service32_sha256, service64_sha256, broker32_sha256, broker64_sha256,\n";
    ss << "     created_at)\n";
    ss << "VALUES\n";
    ss << "    ('" << SqlEscape(buildId) << "', '" << SqlEscape(version) << "', '"
       << SqlEscape(protocolVersion) << "',\n";
    ss << "     '" << h.ex5 << "',\n";
    ss << "     '" << h.ex4 << "',\n";
    ss << "     '" << h.dll32 << "',\n";
    ss << "     '" << h.dll64 << "',\n";
    ss << "     '" << h.machineid32 << "',\n";
    ss << "     '" << h.machineid64 << "',\n";
    ss << "     '" << h.service32 << "',\n";
    ss << "     '" << h.service64 << "',\n";
    ss << "     '" << h.broker32 << "',\n";
    ss << "     '" << h.broker64 << "',\n";
    ss << "     NOW());\n";
    return ss.str();
}

bool WriteAllBytes(const std::wstring& path, const std::string& data)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    BOOL ok = WriteFile(h, data.data(), (DWORD)data.size(), &written, nullptr);
    CloseHandle(h);
    return ok && written == data.size();
}

// ----------------------------------------------------------------------
// Interactive mode helpers
// ----------------------------------------------------------------------

// The folder NutriculaSignTool.exe itself is running from, with a
// trailing backslash - interactive mode looks for all 10 required
// artifacts here, and writes manifest.txt/database_insert.sql here too.
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

std::string PromptNonEmptyLine(const char* prompt)
{
    std::string line;
    for (;;)
    {
        printf("%s", prompt);
        fflush(stdout);
        if (!std::getline(std::cin, line))
        {
            printf("\nERROR: could not read input (input stream closed).\n");
            std::exit(1);
        }
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        size_t start = line.find_first_not_of(" \t");
        size_t end = line.find_last_not_of(" \t");
        line = (start == std::string::npos) ? "" : line.substr(start, end - start + 1);
        if (!line.empty()) return line;
        printf("This value cannot be empty - please try again.\n");
    }
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

// The 10 build artifacts, in the exact order they're hashed/signed in -
// ex5/ex4/dll32/dll64/machineid32/machineid64 reuse the SAME name
// constants CoordinatorProtocol.h, ManifestVerify and the Coordinator's
// own runtime check all agree on, so these names can never drift apart
// from what the Coordinator will actually look for on a customer's
// machine. service32/64 and broker32/64 are build-output names only (the
// Installer later places whichever ONE matches the customer's OS bitness
// under the Coordinator's fixed single running name) - so those 4 stay as
// plain literals here, not shared constants.
struct RequiredFile { const wchar_t* name; };
const RequiredFile* RequiredArtifacts(size_t& count)
{
    static const RequiredFile files[] = {
        { CoordinatorProtocol::ARTIFACT_EX5_NAME },
        { CoordinatorProtocol::ARTIFACT_EX4_NAME },
        { CoordinatorProtocol::ARTIFACT_DLL32_NAME },
        { CoordinatorProtocol::ARTIFACT_DLL64_NAME },
        { CoordinatorProtocol::ARTIFACT_MACHINEID32_NAME },
        { CoordinatorProtocol::ARTIFACT_MACHINEID64_NAME },
        { L"NutriculaLicenseService32.exe" },
        { L"NutriculaLicenseService64.exe" },
        { L"NutriculaLicenseBroker32.exe" },
        { L"NutriculaLicenseBroker64.exe" },
    };
    count = sizeof(files) / sizeof(files[0]);
    return files;
}

int RunInteractive()
{
    std::wstring dir = GetExeDirectory();

    size_t count = 0;
    const RequiredFile* required = RequiredArtifacts(count);

    printf("Checking for the %zu required build artifacts next to NutriculaSignTool.exe:\n", count);
    std::vector<std::wstring> missing;
    for (size_t i = 0; i < count; i++)
    {
        std::wstring path = dir + required[i].name;
        bool exists = FileExistsAndIsFile(path);
        wprintf(L"  [%ls]  %ls\n", exists ? L"OK     " : L"MISSING", required[i].name);
        if (!exists) missing.push_back(required[i].name);
    }
    printf("\n");

    if (!missing.empty())
    {
        printf("ERROR: %zu required file(s) are missing next to NutriculaSignTool.exe:\n", missing.size());
        for (const std::wstring& m : missing) wprintf(L"  - %ls\n", m.c_str());
        printf("Place the missing file(s) in the SAME folder as NutriculaSignTool.exe and run it again.\n");
        return 1;
    }

    printf("All %zu required files were found next to NutriculaSignTool.exe.\n", count);
    if (!PromptYesNo("Continue and build manifest.txt now? (y/n): "))
    {
        printf("Cancelled - nothing was written.\n");
        return 0;
    }
    printf("\n");

    std::string buildId = PromptNonEmptyLine("Enter build_id (must be new/unique, e.g. build-2026-09-01-001): ");
    std::string version = PromptNonEmptyLine("Enter version (e.g. 3.2): ");
    std::string protocolVersion = PromptNonEmptyLine("Enter protocol_version (usually 1): ");
    printf("\n");

    HashSet hashes;
    std::vector<std::string> failedLabels;
    bool allHashed = HashAllArtifacts(
        dir + CoordinatorProtocol::ARTIFACT_EX5_NAME, dir + CoordinatorProtocol::ARTIFACT_EX4_NAME,
        dir + CoordinatorProtocol::ARTIFACT_DLL32_NAME, dir + CoordinatorProtocol::ARTIFACT_DLL64_NAME,
        dir + CoordinatorProtocol::ARTIFACT_MACHINEID32_NAME, dir + CoordinatorProtocol::ARTIFACT_MACHINEID64_NAME,
        dir + L"NutriculaLicenseService32.exe", dir + L"NutriculaLicenseService64.exe",
        dir + L"NutriculaLicenseBroker32.exe", dir + L"NutriculaLicenseBroker64.exe",
        hashes, failedLabels);
    if (!allHashed)
    {
        printf("ERROR: failed to read/hash the following file(s) even though they were found above\n"
            "(they may be locked by another program, or you may lack permission to read them):\n");
        for (const std::string& f : failedLabels) printf("  - %s\n", f.c_str());
        return 1;
    }

    bool signOk = false;
    std::string fullManifest = BuildSignedManifestText(buildId, version, protocolVersion, hashes, signOk);
    if (!signOk)
    {
        printf("ERROR: signing failed - is Keys\\VendorSigningKey_Private.pem populated with a real key?\n");
        return 1;
    }

    std::wstring manifestPath = dir + L"manifest.txt";
    if (!WriteAllBytes(manifestPath, fullManifest))
    {
        printf("ERROR: could not write manifest.txt next to NutriculaSignTool.exe.\n");
        return 1;
    }

    std::string dbInsertSql = BuildDbInsertSql(buildId, version, protocolVersion, hashes);
    std::wstring dbInsertPath = dir + L"database_insert.sql";
    if (!WriteAllBytes(dbInsertPath, dbInsertSql))
    {
        printf("ERROR: manifest.txt was written, but could not write database_insert.sql next to it.\n");
        return 1;
    }

    printf("Manifest written successfully:\n%s\n", fullManifest.c_str());
    wprintf(L"Wrote: %ls\n", manifestPath.c_str());
    wprintf(L"Wrote: %ls\n", dbInsertPath.c_str());
    printf("\nNext steps: copy manifest.txt into the Installer's Assets\\ folder, and run the\n"
        "contents of database_insert.sql against your license database.\n");
    return 0;
}

// ----------------------------------------------------------------------
// Scripted mode (original CLI form, unchanged behavior - see header
// comment for the full usage line)
// ----------------------------------------------------------------------

int RunFromArguments(char** argv)
{
    std::string buildId = argv[1], version = argv[2], protocolVersion = argv[3];
    std::wstring ex5Path = Utf8ToWide(argv[4]);
    std::wstring ex4Path = Utf8ToWide(argv[5]);
    std::wstring dll32Path = Utf8ToWide(argv[6]);
    std::wstring dll64Path = Utf8ToWide(argv[7]);
    std::wstring machineid32Path = Utf8ToWide(argv[8]);
    std::wstring machineid64Path = Utf8ToWide(argv[9]);
    std::wstring service32Path = Utf8ToWide(argv[10]);
    std::wstring service64Path = Utf8ToWide(argv[11]);
    std::wstring broker32Path = Utf8ToWide(argv[12]);
    std::wstring broker64Path = Utf8ToWide(argv[13]);
    std::wstring outPath = Utf8ToWide(argv[14]);

    HashSet hashes;
    std::vector<std::string> failedLabels;
    bool allHashed = HashAllArtifacts(
        ex5Path, ex4Path, dll32Path, dll64Path, machineid32Path, machineid64Path,
        service32Path, service64Path, broker32Path, broker64Path,
        hashes, failedLabels);
    if (!allHashed)
    {
        printf("ERROR: failed to hash one or more artifacts - check the paths given.\n");
        printf("  failed:");
        for (const std::string& f : failedLabels) printf(" %s", f.c_str());
        printf("\n");
        return 1;
    }

    bool signOk = false;
    std::string fullManifest = BuildSignedManifestText(buildId, version, protocolVersion, hashes, signOk);
    if (!signOk)
    {
        printf("ERROR: signing failed.\n");
        return 1;
    }

    if (!WriteAllBytes(outPath, fullManifest))
    {
        printf("ERROR: could not write output manifest.\n");
        return 1;
    }

    // database_insert.sql is written next to the manifest (same directory,
    // fixed file name) so the scripted path gets the same ready-to-run SQL
    // as interactive mode, without needing a 16th argument.
    std::wstring dbInsertPath = outPath;
    size_t slashPos = dbInsertPath.find_last_of(L"\\/");
    dbInsertPath = (slashPos == std::wstring::npos) ? L"" : dbInsertPath.substr(0, slashPos + 1);
    dbInsertPath += L"database_insert.sql";
    std::string dbInsertSql = BuildDbInsertSql(buildId, version, protocolVersion, hashes);
    if (!WriteAllBytes(dbInsertPath, dbInsertSql))
    {
        printf("WARNING: manifest was written, but failed to write database_insert.sql next to it.\n");
    }

    printf("Manifest written successfully:\n%s", fullManifest.c_str());
    wprintf(L"Wrote: %ls\n", dbInsertPath.c_str());
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc == 15)
    {
        return RunFromArguments(argv);
    }
    if (argc == 1)
    {
        return RunInteractive();
    }

    printf("Interactive mode (recommended): run %s with NO arguments. It looks for all 10\n"
        "required build artifacts next to itself and asks for build_id/version/\n"
        "protocol_version one at a time.\n\n", argv[0]);
    printf("Scripted mode: %s <build_id> <version> <protocol_version> "
        "<ex5_path> <ex4_path> <dll32_path> <dll64_path> "
        "<machineid32_path> <machineid64_path> "
        "<service32_path> <service64_path> <broker32_path> <broker64_path> "
        "<output_manifest_path>\n", argv[0]);
    return 1;
}
