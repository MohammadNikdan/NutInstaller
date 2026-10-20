#include "RuntimeMeasure.h"
#include "ManifestVerify.h"
#include "CoordinatorProtocol.h"
#include "MachineIdBridge.h"

#include <windows.h>
#include <psapi.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstring>

namespace RuntimeMeasure {

namespace {

// ---------------------------------------------------------------------------
// Bounds. A real Experts tree is a few dozen files and a few megabytes, and a
// real Libraries folder is a handful; these caps exist so a pathological or
// deliberately bloated folder can never turn one refresh cycle into minutes
// of hashing. Chosen generously enough that no genuine install reaches them.
// ---------------------------------------------------------------------------
constexpr int MAX_SCAN_DEPTH = 16;
constexpr int MAX_SCAN_FILES = 2000;
constexpr unsigned long long MAX_SCAN_FILE_BYTES = 32ull * 1024 * 1024;
constexpr unsigned long long MAX_SCAN_TOTAL_BYTES = 192ull * 1024 * 1024;

constexpr int MAX_LIB_DEPTH = 8;
constexpr int MAX_LIB_FILES = 200;
constexpr unsigned long long MAX_LIB_FILE_BYTES = 24ull * 1024 * 1024;

// Loaded modules we are willing to hash while looking for our own. A
// MetaTrader process loads plenty of libraries - including its own
// multi-megabyte executable - so the candidate list is bounded both in count
// and in per-file size. The size cap is comfortably above our own DLLs
// (hundreds of KB) and below anything like terminal64.exe, which keeps a
// re-discovery in the low milliseconds without excluding anywhere a user can
// actually write a module.
constexpr size_t MAX_CANDIDATE_MODULES = 64;
constexpr unsigned long long MAX_MODULE_BYTES = 8ull * 1024 * 1024;

// Size of a file without opening it for reading. Returns false when it cannot
// be determined, which keeps the file out of the candidate list rather than
// hashing something of unknown size.
bool FileSizeOf(const std::wstring& path, unsigned long long& outSize)
{
    outSize = 0;
    WIN32_FILE_ATTRIBUTE_DATA data;
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) return false;
    outSize = (static_cast<unsigned long long>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
    return true;
}

// An explicit build marker placed in the EA source. Kept purely as
// redundancy - it is trivially removable from a patched copy, which is
// exactly why recognition does not rest on it (see RuntimeMeasure.h). To use
// it, add to the EA:
//     const string Nut_Mark = "NTRCLA-EA-MARK-7F3A91C4";
// and reference it once so the compiler cannot drop it.
const char* const EA_BUILD_MARKER = "NTRCLA-EA-MARK-7F3A91C4";

// ---------------------------------------------------------------------------
// The License Check DLL's own exported entry-point names, and the Machine ID
// DLL's. These are what make a loaded module recognisable as OURS even when
// it has been renamed AND modified, so its hash matches nothing.
//
// They cannot be removed, which is the whole point: MQL's #import resolves a
// function by NAME, never by ordinal, so any modified DLL an EA can actually
// call must still export these names - and an exported name is present in
// the binary as a plain ASCII string. The same holds for a wrapper DLL that
// forwards to ours by name. (A wrapper that resolves them by ordinal through
// GetProcAddress would not carry the strings; that case is noted as open in
// RuntimeMeasure.h.)
//
// NxD and NxW are deliberately left out: at two and three characters they
// would match arbitrary bytes in unrelated files constantly.
//
// KEEP IN SYNC with the same list in the Installer's NutriculaSweeper.cs,
// which uses it to find stale or modified copies before installing.
const char* const LICENSE_DLL_ENTRY_POINTS[] = {
    "Vela_Boot_84", "Pavo_Sync_85", "Indus_Auth_86",
    "Phoenix_State_87", "Dorado_Flag_88", "Carina_Span_89",
};
const char* const MACHINEID_ENTRY_POINTS[] = {
    "Nutricula_GenerateMachineId", "Nutricula_GetDeviceKeyHash",
    "Nutricula_SignChallenge", "Nutricula_GetLicensePath",
};

inline unsigned char FoldByte(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') ? static_cast<unsigned char>(c - 'A' + 'a') : c;
}

// Both byte encodings of a literal, folded to lower case: MQL stores strings
// as UTF-16, but some literals end up in a compiled program as plain bytes,
// and which one happens is not something to guess at.
void AppendPatternForms(const std::string& literal,
    std::vector<std::vector<unsigned char>>& out)
{
    if (literal.empty()) return;
    std::vector<unsigned char> ascii;
    std::vector<unsigned char> utf16;
    ascii.reserve(literal.size());
    utf16.reserve(literal.size() * 2);
    for (char ch : literal)
    {
        const unsigned char folded = FoldByte(static_cast<unsigned char>(ch));
        ascii.push_back(folded);
        utf16.push_back(folded);
        utf16.push_back(0);
    }
    out.push_back(std::move(ascii));
    out.push_back(std::move(utf16));
}

// Both entry-point lists, built once. Used to spot a module that is one of
// ours despite matching no expected hash - i.e. a modified one.
const std::vector<std::vector<unsigned char>>& EntryPointPatterns()
{
    static const std::vector<std::vector<unsigned char>> patterns = []() {
        std::vector<std::vector<unsigned char>> out;
        for (const char* name : LICENSE_DLL_ENTRY_POINTS) AppendPatternForms(name, out);
        for (const char* name : MACHINEID_ENTRY_POINTS) AppendPatternForms(name, out);
        return out;
    }();
    return patterns;
}

// The License Check DLL's names alone - only used on the failure path, to say
// WHICH of the two DLLs a suspicious module appears to be.
const std::vector<std::vector<unsigned char>>& LicenseEntryPointPatterns()
{
    static const std::vector<std::vector<unsigned char>> patterns = []() {
        std::vector<std::vector<unsigned char>> out;
        for (const char* name : LICENSE_DLL_ENTRY_POINTS) AppendPatternForms(name, out);
        return out;
    }();
    return patterns;
}

size_t LongestPattern(const std::vector<std::vector<unsigned char>>& patterns)
{
    size_t longest = 0;
    for (const std::vector<unsigned char>& p : patterns) longest = (p.size() > longest) ? p.size() : longest;
    return longest;
}

bool ContainsPattern(const std::vector<unsigned char>& haystack, size_t haystackLen,
    const std::vector<unsigned char>& needle)
{
    if (needle.empty() || needle.size() > haystackLen) return false;
    const size_t last = haystackLen - needle.size();
    for (size_t i = 0; i <= last; i++)
    {
        if (std::memcmp(haystack.data() + i, needle.data(), needle.size()) == 0) return true;
    }
    return false;
}

std::string ToHexLower(const unsigned char digest[32])
{
    static const char* hexDigits = "0123456789abcdef";
    std::string hex(64, '0');
    for (int i = 0; i < 32; i++)
    {
        hex[i * 2] = hexDigits[(digest[i] >> 4) & 0xF];
        hex[i * 2 + 1] = hexDigits[digest[i] & 0xF];
    }
    return hex;
}

// One read pass that both hashes a file and looks for any of `patterns`. The
// hash covers the RAW bytes; the search runs over a folded copy of the same
// bytes, with a carry-over tail so a pattern straddling two chunk boundaries
// is still found. Pass an empty pattern list to hash only.
//
// Returns false if the file could not be read at all - never a silent "no
// match, empty hash" pass; every caller handles that case explicitly.
bool HashAndScanFile(const std::wstring& path,
    const std::vector<std::vector<unsigned char>>& patterns,
    std::string& outHash, bool& outMatched, unsigned long long& outSize)
{
    outHash.clear();
    outMatched = false;
    outSize = 0;

    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size) || size.QuadPart < 0)
    {
        CloseHandle(h);
        return false;
    }
    outSize = static_cast<unsigned long long>(size.QuadPart);

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
    {
        CloseHandle(h);
        return false;
    }
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) >= 0;

    const size_t longest = LongestPattern(patterns);
    const size_t carryLen = (longest > 0) ? longest - 1 : 0;
    std::vector<unsigned char> raw(65536);
    std::vector<unsigned char> folded(patterns.empty() ? 0 : carryLen + raw.size());
    size_t carryHeld = 0;

    DWORD read = 0;
    while (ok && ReadFile(h, raw.data(), static_cast<DWORD>(raw.size()), &read, nullptr) && read > 0)
    {
        ok = BCryptHashData(hash, raw.data(), read, 0) >= 0;
        if (!ok) break;

        if (!patterns.empty() && !outMatched)
        {
            for (DWORD i = 0; i < read; i++) folded[carryHeld + i] = FoldByte(raw[i]);
            const size_t total = carryHeld + read;
            for (const std::vector<unsigned char>& p : patterns)
            {
                if (ContainsPattern(folded, total, p)) { outMatched = true; break; }
            }
            const size_t keep = (total < carryLen) ? total : carryLen;
            if (keep > 0) std::memmove(folded.data(), folded.data() + (total - keep), keep);
            carryHeld = keep;
        }
    }

    unsigned char digest[32];
    if (ok) ok = BCryptFinishHash(hash, digest, sizeof(digest), 0) >= 0;

    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(h);
    if (!ok) return false;

    outHash = ToHexLower(digest);
    return true;
}

std::string HashOnly(const std::wstring& path)
{
    static const std::vector<std::vector<unsigned char>> none;
    std::string hash;
    bool matched = false;
    unsigned long long size = 0;
    if (!HashAndScanFile(path, none, hash, matched, size)) return std::string();
    return hash;
}

std::wstring BaseNameOf(const std::wstring& path)
{
    size_t slash = path.find_last_of(L"\\/");
    return (slash == std::wstring::npos) ? path : path.substr(slash + 1);
}

bool EqualsNoCase(const std::wstring& a, const std::wstring& b)
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
    {
        wchar_t ca = a[i], cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca = static_cast<wchar_t>(ca - L'A' + L'a');
        if (cb >= L'A' && cb <= L'Z') cb = static_cast<wchar_t>(cb - L'A' + L'a');
        if (ca != cb) return false;
    }
    return true;
}

bool EndsWithNoCase(const std::wstring& value, const std::wstring& suffix)
{
    if (suffix.size() > value.size()) return false;
    return EqualsNoCase(value.substr(value.size() - suffix.size()), suffix);
}

bool StartsWithNoCase(const std::wstring& value, const std::wstring& prefix)
{
    if (prefix.size() > value.size()) return false;
    return EqualsNoCase(value.substr(0, prefix.size()), prefix);
}

std::string NarrowForLog(const std::wstring& w)
{
    // Only ever used for the diagnostic detail string that accompanies a -2
    // report. Non-ASCII characters in a path become '?' rather than risking a
    // malformed UTF-8 field; the path is for support, not for parsing.
    std::string out;
    out.reserve(w.size());
    for (wchar_t c : w) out.push_back((c >= 32 && c < 127) ? static_cast<char>(c) : '?');
    return out;
}

bool IsValidSha256Hex(const std::string& v)
{
    if (v.size() != 64) return false;
    for (char c : v)
    {
        const bool isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!isHex) return false;
    }
    return true;
}

std::string ToLowerHex(std::string v)
{
    for (char& c : v) if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
    return v;
}

bool IsOneOfOurShippedNames(const std::wstring& baseName)
{
    return EqualsNoCase(baseName, CoordinatorProtocol::ARTIFACT_DLL32_NAME) ||
           EqualsNoCase(baseName, CoordinatorProtocol::ARTIFACT_DLL64_NAME) ||
           EqualsNoCase(baseName, CoordinatorProtocol::ARTIFACT_MACHINEID32_NAME) ||
           EqualsNoCase(baseName, CoordinatorProtocol::ARTIFACT_MACHINEID64_NAME);
}

// Modules under the Windows directory are OS files: a user cannot replace one
// without administrator rights, and hashing the whole of system32 on every
// discovery would be absurd. Everything else a process has loaded is fair
// game, wherever it came from - which is deliberate, so that importing a
// renamed copy of our DLL from an unusual folder is still seen.
const std::wstring& WindowsDirectory()
{
    static const std::wstring dir = []() {
        wchar_t buf[MAX_PATH] = {};
        const UINT len = GetWindowsDirectoryW(buf, MAX_PATH);
        if (len == 0 || len >= MAX_PATH) return std::wstring();
        std::wstring value(buf, len);
        if (!value.empty() && value.back() != L'\\') value += L'\\';
        return value;
    }();
    return dir;
}

bool IsSystemModule(const std::wstring& path)
{
    const std::wstring& winDir = WindowsDirectory();
    if (winDir.empty()) return false; // cannot tell - then do not exclude it
    return StartsWithNoCase(path, winDir);
}

// From the resolved License Check DLL's own real loaded path, derive the
// terminal's data folder and which MQL generation this terminal is. MQL only
// imports libraries from <dataDir>\MQL4|5\Libraries, so a genuine install
// always has this shape - and this is read off the OS-reported path of the
// actual module, not from anything the client said.
bool DeriveTerminalLayout(const std::wstring& dllPath, std::wstring& outDataDir, int& outMqlMajor)
{
    outDataDir.clear();
    outMqlMajor = 0;

    size_t slash = dllPath.find_last_of(L'\\');
    if (slash == std::wstring::npos) return false;
    std::wstring librariesDir = dllPath.substr(0, slash);           // <dataDir>\MQL?\Libraries
    if (!EndsWithNoCase(librariesDir, L"\\Libraries")) return false;

    std::wstring mqlDir = librariesDir.substr(0, librariesDir.size() - std::wstring(L"\\Libraries").size());
    if (EndsWithNoCase(mqlDir, L"\\MQL4")) outMqlMajor = 4;
    else if (EndsWithNoCase(mqlDir, L"\\MQL5")) outMqlMajor = 5;
    else return false;

    outDataDir = mqlDir.substr(0, mqlDir.size() - 5); // strip "\MQL4" / "\MQL5"
    return !outDataDir.empty();
}

unsigned long long ProcessCreationTime(HANDLE process)
{
    FILETIME creation, exit, kernel, user;
    if (!GetProcessTimes(process, &creation, &exit, &kernel, &user)) return 0;
    ULARGE_INTEGER v;
    v.LowPart = creation.dwLowDateTime;
    v.HighPart = creation.dwHighDateTime;
    return v.QuadPart;
}

// The two access masks worth trying, most capable first. Module enumeration
// documents PROCESS_QUERY_INFORMATION | PROCESS_VM_READ; the LIMITED variant
// is accepted too on current Windows and is what succeeds when a hardened
// policy denies the full right. The Broker runs as the same user as the
// terminal, so one of the two always works in practice - and if neither
// does, that is reported as a failure rather than quietly skipped.
HANDLE OpenClientProcess(DWORD pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (h) return h;
    return OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
}

// ---------------------------------------------------------------------------
// Scanning the terminal's Libraries tree for every file that IS our License
// Check DLL, whatever it has been named. Those names are what a patched
// program must contain in order to import it (see RuntimeMeasure.h), so they
// become the thing the program scan recognises - a marker an attacker cannot
// delete without breaking their own import.
// ---------------------------------------------------------------------------
void CollectDllAliasNames(const std::wstring& dir, int depth,
    const std::string& expectedDll32, const std::string& expectedDll64,
    int& filesSeen, std::vector<std::string>& outNames)
{
    if (depth > MAX_LIB_DEPTH || filesSeen >= MAX_LIB_FILES) return;

    WIN32_FIND_DATAW find;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &find);
    if (h == INVALID_HANDLE_VALUE) return;

    std::vector<std::wstring> subdirs;
    do
    {
        const std::wstring name = find.cFileName;
        if (name == L"." || name == L"..") continue;
        if ((find.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) continue;
        if ((find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            subdirs.push_back(dir + L"\\" + name);
            continue;
        }
        if (filesSeen >= MAX_LIB_FILES) break;

        const unsigned long long fileSize =
            (static_cast<unsigned long long>(find.nFileSizeHigh) << 32) | find.nFileSizeLow;
        if (fileSize > MAX_LIB_FILE_BYTES) continue;
        filesSeen++;

        const std::string hash = HashOnly(dir + L"\\" + name);
        if (hash.empty()) continue;
        if (hash != expectedDll32 && hash != expectedDll64) continue;

        // A file byte-identical to our License Check DLL. Its name is what an
        // importing program has to spell out, so record it.
        std::string narrow;
        narrow.reserve(name.size());
        bool printable = true;
        for (wchar_t c : name)
        {
            if (c < 32 || c >= 127) { printable = false; break; }
            narrow.push_back(static_cast<char>(c));
        }
        if (printable && !narrow.empty() &&
            std::find(outNames.begin(), outNames.end(), narrow) == outNames.end())
        {
            outNames.push_back(narrow);
        }
    } while (FindNextFileW(h, &find));
    FindClose(h);

    for (const std::wstring& sub : subdirs)
    {
        CollectDllAliasNames(sub, depth + 1, expectedDll32, expectedDll64, filesSeen, outNames);
    }
}

// ---------------------------------------------------------------------------
// The program trees. All three places MetaTrader will load a compiled MQL
// program from, each walked recursively - a program may legitimately sit in a
// subfolder (MQL5\Experts\newcodes\Nutricula.ex5), which is an ordinary
// install and must not be treated as anything unusual.
//
// Indicators and Scripts are included even though Nutricula ships only as an
// Expert Advisor: a modified build dropped there would still be something the
// terminal can run. This assumes ONE shipped program per MQL generation,
// which is also what manifest.txt assumes (a single ex4_sha256 / ex5_sha256).
// Shipping a second .ex4/.ex5 program would need its own manifest column,
// otherwise the second one looks exactly like a modified copy of the first.
// ---------------------------------------------------------------------------
const wchar_t* const PROGRAM_SUBFOLDERS[] = { L"Experts", L"Indicators", L"Scripts" };

struct TreeScanResult
{
    bool readable = true;        // false only if none of the three folders exists
    bool genuineFound = false;
    std::string genuineHash;     // the hash actually measured for the genuine file
    bool modifiedFound = false;
    std::wstring modifiedPath;
    int filesExamined = 0;
    int unreadableFiles = 0;
    bool truncated = false;      // a cap above was reached
};

void ScanDirectory(const std::wstring& dir, const std::wstring& extension,
    const std::string& expectedEaHash,
    const std::vector<std::vector<unsigned char>>& patterns,
    int depth, unsigned long long& totalBytes, TreeScanResult& result)
{
    if (result.modifiedFound) return;                 // one modified copy is already a verdict
    if (depth > MAX_SCAN_DEPTH) { result.truncated = true; return; }
    if (result.filesExamined >= MAX_SCAN_FILES) { result.truncated = true; return; }

    WIN32_FIND_DATAW find;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &find);
    if (h == INVALID_HANDLE_VALUE) return;

    std::vector<std::wstring> subdirs;
    do
    {
        const std::wstring name = find.cFileName;
        if (name == L"." || name == L"..") continue;
        // Never follow a junction/symlink: it can point back up the tree (an
        // endless walk) or out of the terminal entirely.
        if ((find.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) continue;

        if ((find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            subdirs.push_back(dir + L"\\" + name);
            continue;
        }

        if (!EndsWithNoCase(name, extension)) continue;

        const unsigned long long fileSize =
            (static_cast<unsigned long long>(find.nFileSizeHigh) << 32) | find.nFileSizeLow;
        if (fileSize > MAX_SCAN_FILE_BYTES) { result.truncated = true; continue; }
        if (totalBytes + fileSize > MAX_SCAN_TOTAL_BYTES) { result.truncated = true; break; }
        if (result.filesExamined >= MAX_SCAN_FILES) { result.truncated = true; break; }

        const std::wstring full = dir + L"\\" + name;
        std::string hash;
        bool recognised = false;
        unsigned long long actualSize = 0;
        if (!HashAndScanFile(full, patterns, hash, recognised, actualSize))
        {
            // Could not read this candidate. It is NOT treated as a match and
            // NOT treated as tampering: a file nobody can read is also a file
            // MetaTrader cannot load, so it cannot be the program that is
            // running. Counted so the reason shows up in a failure report.
            result.unreadableFiles++;
            continue;
        }
        result.filesExamined++;
        totalBytes += actualSize;

        if (hash == expectedEaHash)
        {
            result.genuineFound = true;
            result.genuineHash = hash;
            continue;
        }
        if (recognised)
        {
            result.modifiedFound = true;
            result.modifiedPath = full;
            break;
        }
    } while (FindNextFileW(h, &find));
    FindClose(h);

    for (const std::wstring& sub : subdirs)
    {
        if (result.modifiedFound) break;
        ScanDirectory(sub, extension, expectedEaHash, patterns, depth + 1, totalBytes, result);
    }
}

TreeScanResult ScanProgramTrees(const std::wstring& dataDir, int mqlMajor,
    const std::string& expectedEaHash,
    const std::vector<std::vector<unsigned char>>& patterns)
{
    TreeScanResult result;
    const std::wstring mqlRoot = dataDir + ((mqlMajor == 4) ? L"\\MQL4\\" : L"\\MQL5\\");
    const std::wstring extension = (mqlMajor == 4) ? L".ex4" : L".ex5";

    unsigned long long totalBytes = 0;
    int rootsFound = 0;
    for (const wchar_t* subfolder : PROGRAM_SUBFOLDERS)
    {
        const std::wstring dir = mqlRoot + subfolder;
        const DWORD attrs = GetFileAttributesW(dir.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;
        rootsFound++;
        ScanDirectory(dir, extension, expectedEaHash, patterns, 0, totalBytes, result);
        if (result.modifiedFound) break;
    }

    // Only "none of the three folders exists at all" counts as unreadable - a
    // terminal with no Scripts folder is perfectly normal.
    if (rootsFound == 0) result.readable = false;
    return result;
}

bool ExpectationsUsable(const ManifestExpectations& e)
{
    return IsValidSha256Hex(e.ex4Sha256) && IsValidSha256Hex(e.ex5Sha256) &&
           IsValidSha256Hex(e.dll32Sha256) && IsValidSha256Hex(e.dll64Sha256) &&
           IsValidSha256Hex(e.machineid32Sha256) && IsValidSha256Hex(e.machineid64Sha256);
}

} // anonymous namespace

bool DiscoverSessionFromPipe(HANDLE pipe, const ManifestExpectations& expected,
    TerminalSession& out, std::string& outDetail)
{
    out = TerminalSession();
    outDetail.clear();

    ULONG pid = 0;
    if (!GetNamedPipeClientProcessId(pipe, &pid) || pid == 0)
    {
        outDetail = "could not identify the process on the other end of the Coordinator pipe";
        return false;
    }

    HANDLE process = OpenClientProcess(static_cast<DWORD>(pid));
    if (!process)
    {
        outDetail = "could not open the connecting process to read its loaded modules";
        return false;
    }

    out.pid = static_cast<DWORD>(pid);
    out.createdAt100ns = ProcessCreationTime(process);

    // LIST_MODULES_ALL so a 64-bit Broker can also enumerate a 32-bit
    // (WOW64) MT4 process. A 32-bit Broker only ever runs on 32-bit Windows,
    // where every process is 32-bit anyway.
    std::vector<HMODULE> modules(1024);
    DWORD needed = 0;
    bool enumerated = EnumProcessModulesEx(process, modules.data(),
        static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &needed, LIST_MODULES_ALL) != 0;
    if (enumerated && needed > modules.size() * sizeof(HMODULE))
    {
        modules.resize(needed / sizeof(HMODULE) + 16);
        enumerated = EnumProcessModulesEx(process, modules.data(),
            static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &needed, LIST_MODULES_ALL) != 0;
    }
    if (!enumerated)
    {
        CloseHandle(process);
        outDetail = "could not read the module list of the connecting process";
        return false;
    }

    const size_t count = (std::min)(static_cast<size_t>(needed / sizeof(HMODULE)), modules.size());
    for (size_t i = 0; i < count; i++)
    {
        const DWORD MODULE_PATH_CHARS = MAX_PATH * 2;
        wchar_t buf[MODULE_PATH_CHARS] = {};
        DWORD len = GetModuleFileNameExW(process, modules[i], buf, MODULE_PATH_CHARS);
        if (len == 0 || len >= MODULE_PATH_CHARS) continue;
        const std::wstring path(buf, len);

        if (IsOneOfOurShippedNames(BaseNameOf(path)))
        {
            out.nameMatchedModules.push_back(path);
        }
        if (IsSystemModule(path)) continue;
        if (out.candidateModules.size() >= MAX_CANDIDATE_MODULES) continue;
        // Anything bigger than our own DLLs could ever be is not a candidate
        // for "is this file ours", so it is never hashed.
        unsigned long long moduleSize = 0;
        if (!FileSizeOf(path, moduleSize) || moduleSize > MAX_MODULE_BYTES) continue;
        out.candidateModules.push_back(path);
    }
    CloseHandle(process);

    // Is this actually a MetaTrader process running Nutricula? Decided by
    // hash where possible, so a renamed copy of our DLL still counts; by our
    // shipped names only as a fallback, for the very first contact before the
    // worker has loaded the manifest.
    // A module that carries our entry-point names counts too, even when its
    // hash matches nothing: that is precisely the renamed-AND-modified DLL
    // case. Without this it would be dismissed as "not ours", the session
    // would go untracked, and a patched terminal could ride along on a clean
    // one's published tier. It is tracked here and then fails in
    // MeasureSession, which is where verdicts belong.
    bool looksLikeOurs = false;
    if (ExpectationsUsable(expected))
    {
        const std::string want32 = ToLowerHex(expected.dll32Sha256);
        const std::string want64 = ToLowerHex(expected.dll64Sha256);
        for (const std::wstring& modulePath : out.candidateModules)
        {
            std::string hash;
            bool hasEntryPoints = false;
            unsigned long long size = 0;
            if (!HashAndScanFile(modulePath, EntryPointPatterns(), hash, hasEntryPoints, size)) continue;
            if (hash == want32 || hash == want64 || hasEntryPoints) { looksLikeOurs = true; break; }
        }
    }
    if (!looksLikeOurs && !out.nameMatchedModules.empty()) looksLikeOurs = true;

    if (!looksLikeOurs)
    {
        // Something local connected to the pipe without any Nutricula module
        // in it - a diagnostic tool, for instance. Not tracked at all, rather
        // than tracked as a terminal that then fails every measurement, so
        // one stray connection cannot put the whole machine at -2.
        outDetail = "the connecting process contains no Nutricula module";
        return false;
    }

    out.noticedTickMs = GetTickCount64();
    return true;
}

bool IsSessionProcessAlive(const TerminalSession& session)
{
    if (session.pid == 0) return false;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, session.pid);
    if (!process) process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, session.pid);
    if (!process) return false;

    DWORD exitCode = 0;
    const bool running = GetExitCodeProcess(process, &exitCode) && exitCode == STILL_ACTIVE;
    // Same PID, different process: Windows reused the number after the real
    // terminal exited, so this is NOT the session we measured.
    const bool sameProcess = (session.createdAt100ns == 0) ||
        (ProcessCreationTime(process) == session.createdAt100ns);
    CloseHandle(process);
    return running && sameProcess;
}

SessionEvidence MeasureSession(const TerminalSession& session, const ManifestExpectations& expected)
{
    SessionEvidence ev;

    if (!ExpectationsUsable(expected))
    {
        ev.detail = "the signed manifest does not carry a usable expected hash for this terminal's artifacts";
        return ev;
    }
    const std::string wantDll32 = ToLowerHex(expected.dll32Sha256);
    const std::string wantDll64 = ToLowerHex(expected.dll64Sha256);
    const std::string wantMid32 = ToLowerHex(expected.machineid32Sha256);
    const std::string wantMid64 = ToLowerHex(expected.machineid64Sha256);

    // ---- which loaded module IS our License Check DLL (by hash) ----------
    std::wstring resolvedDllPath;
    std::wstring resolvedMachineIdPath;
    std::string resolvedMachineIdHash;
    int dllBits = 0;
    int machineIdBits = 0;
    // A loaded module that carries our exported entry-point names but matches
    // no expected hash. One read pass per candidate does both jobs.
    std::wstring modifiedModulePath;
    for (const std::wstring& modulePath : session.candidateModules)
    {
        std::string hash;
        bool hasEntryPoints = false;
        unsigned long long size = 0;
        if (!HashAndScanFile(modulePath, EntryPointPatterns(), hash, hasEntryPoints, size)) continue;

        if (resolvedDllPath.empty() && (hash == wantDll32 || hash == wantDll64))
        {
            resolvedDllPath = modulePath;
            dllBits = (hash == wantDll32) ? 32 : 64;
            ev.dllHash = hash;
            continue;
        }
        if (resolvedMachineIdPath.empty() && (hash == wantMid32 || hash == wantMid64))
        {
            resolvedMachineIdPath = modulePath;
            machineIdBits = (hash == wantMid32) ? 32 : 64;
            resolvedMachineIdHash = hash;
            continue;
        }
        if (hasEntryPoints && modifiedModulePath.empty()) modifiedModulePath = modulePath;
    }

    // Checked before anything else, including before "no DLL was identified":
    // a modified build of one of our DLLs being loaded is both the more
    // serious finding and the more useful one to report, and it fails the
    // session whether or not a genuine DLL is loaded alongside it.
    if (!modifiedModulePath.empty())
    {
        std::string ignoredHash;
        bool isLicenseDll = false;
        unsigned long long ignoredSize = 0;
        HashAndScanFile(modifiedModulePath, LicenseEntryPointPatterns(),
            ignoredHash, isLicenseDll, ignoredSize);
        ev.detail = std::string("a modified Nutricula ") +
            (isLicenseDll ? "License Check DLL" : "Machine ID DLL") +
            " is loaded in MetaTrader: " + NarrowForLog(modifiedModulePath);
        return ev;
    }

    if (resolvedDllPath.empty())
    {
        // Nothing loaded in that process is our DLL. If something is loaded
        // under our DLL's name, say so precisely - that is the "a patched DLL
        // is installed" case and the most useful -2 detail there is.
        std::wstring suspect;
        for (const std::wstring& modulePath : session.nameMatchedModules)
        {
            const std::wstring base = BaseNameOf(modulePath);
            if (EqualsNoCase(base, CoordinatorProtocol::ARTIFACT_DLL32_NAME) ||
                EqualsNoCase(base, CoordinatorProtocol::ARTIFACT_DLL64_NAME))
            {
                suspect = modulePath;
                break;
            }
        }
        ev.detail = suspect.empty()
            ? std::string("no Nutricula License Check DLL could be identified in the MetaTrader process")
            : ("the License Check DLL loaded in MetaTrader does not match the signed manifest: " +
               NarrowForLog(suspect));
        return ev;
    }

    // ---- the terminal layout, derived from that module's own path ---------
    std::wstring dataDir;
    int mqlMajor = 0;
    if (!DeriveTerminalLayout(resolvedDllPath, dataDir, mqlMajor))
    {
        ev.detail = "the loaded License Check DLL is not in a MetaTrader MQL4/MQL5 Libraries folder: " +
            NarrowForLog(resolvedDllPath);
        return ev;
    }

    // MQL4 terminals are 32-bit and MQL5 terminals are 64-bit, which is what
    // the Installer relies on when it picks which DLL to place in each
    // terminal. Enforcing the pairing means any install that somehow broke
    // that assumption becomes a detected failure instead of silently being
    // compared against the wrong manifest column.
    const int expectedBits = (mqlMajor == 4) ? 32 : 64;
    if (dllBits != expectedBits)
    {
        ev.detail = "a " + std::to_string(dllBits) + "-bit License Check DLL is loaded from an MQL" +
            std::to_string(mqlMajor) + " terminal, which never happens in a genuine install";
        return ev;
    }
    ev.mqlMajor = mqlMajor;
    ev.dllBits = dllBits;

    // ---- the MachineId DLL, only if that process really loaded one --------
    if (!resolvedMachineIdPath.empty())
    {
        if (machineIdBits != expectedBits)
        {
            ev.detail = "the wrong architecture of the Machine ID DLL is loaded inside MetaTrader";
            return ev;
        }
        ev.terminalMachineIdHash = resolvedMachineIdHash;
    }
    else
    {
        // Nothing loaded matched a genuine MachineId DLL. If a module is
        // loaded under that name anyway, it is a modified one.
        std::wstring suspect;
        for (const std::wstring& modulePath : session.nameMatchedModules)
        {
            const std::wstring base = BaseNameOf(modulePath);
            if (EqualsNoCase(base, CoordinatorProtocol::ARTIFACT_MACHINEID32_NAME) ||
                EqualsNoCase(base, CoordinatorProtocol::ARTIFACT_MACHINEID64_NAME))
            {
                suspect = modulePath;
                break;
            }
        }
        if (!suspect.empty())
        {
            ev.detail = "the Machine ID DLL loaded in MetaTrader does not match the signed manifest: " +
                NarrowForLog(suspect);
            return ev;
        }
        ev.terminalMachineIdHash = "-"; // genuinely not loaded - nothing to measure
    }

    // ---- what makes a compiled program recognisably Nutricula ------------
    // The names that resolve to our License Check DLL in THIS terminal are
    // the important ones: a patched program has to import the DLL to reach
    // the real calculations, and to import it the compiled file must contain
    // the name as a literal. Renaming the DLL does not help, because the copy
    // is byte-identical and so its name is collected here too.
    // The imported FUNCTION names belong here for the same reason as the
    // library name, and are if anything harder to avoid: MQL resolves an
    // imported function by name at run time, so every one the program calls
    // is present in the compiled file as a literal. A patched EA that still
    // reaches the real calculations therefore still carries them.
    std::vector<std::string> recognitionLiterals;
    recognitionLiterals.push_back("NutriculaLicenseCheck32.dll");
    recognitionLiterals.push_back("NutriculaLicenseCheck64.dll");
    recognitionLiterals.push_back(EA_BUILD_MARKER);
    for (const char* name : LICENSE_DLL_ENTRY_POINTS) recognitionLiterals.push_back(name);
    {
        int libFilesSeen = 0;
        CollectDllAliasNames(dataDir + ((mqlMajor == 4) ? L"\\MQL4\\Libraries" : L"\\MQL5\\Libraries"),
            0, wantDll32, wantDll64, libFilesSeen, recognitionLiterals);
    }
    // The resolved module's own name, in case it was loaded from outside the
    // Libraries tree and the walk above therefore never saw it.
    {
        const std::wstring base = BaseNameOf(resolvedDllPath);
        std::string narrow;
        bool printable = true;
        for (wchar_t c : base)
        {
            if (c < 32 || c >= 127) { printable = false; break; }
            narrow.push_back(static_cast<char>(c));
        }
        if (printable && !narrow.empty() &&
            std::find(recognitionLiterals.begin(), recognitionLiterals.end(), narrow) == recognitionLiterals.end())
        {
            recognitionLiterals.push_back(narrow);
        }
    }

    std::vector<std::vector<unsigned char>> patterns;
    for (const std::string& literal : recognitionLiterals) AppendPatternForms(literal, patterns);

    // ---- the program itself, in the trees MetaTrader can run one from ----
    //
    // Two independent rules, and BOTH must hold:
    //   1. EVERY recognisable Nutricula file must hash to the expectation.
    //      One that does not is tampering, full stop - it makes no difference
    //      whether a genuine copy is also present, nor how many files there
    //      are.
    //   2. At least one file matching that expectation must exist. Without
    //      this, deleting the genuine program and running a modified build
    //      whose markers had been scrubbed would leave nothing for rule 1 to
    //      catch; with it, the genuine file's absence is itself the failure.
    const std::string wantEa = ToLowerHex((mqlMajor == 4) ? expected.ex4Sha256 : expected.ex5Sha256);
    const TreeScanResult scan = ScanProgramTrees(dataDir, mqlMajor, wantEa, patterns);
    if (!scan.readable)
    {
        ev.detail = "this terminal has no readable MQL" + std::to_string(mqlMajor) +
            " Experts/Indicators/Scripts folder: " + NarrowForLog(dataDir);
        return ev;
    }
    if (scan.modifiedFound)
    {
        ev.detail = "a modified copy of the Nutricula program is present in this terminal: " +
            NarrowForLog(scan.modifiedPath);
        return ev;
    }
    if (!scan.genuineFound)
    {
        ev.detail = "the genuine Nutricula program is not present in this terminal (" +
            std::to_string(scan.filesExamined) + " file(s) examined, " +
            std::to_string(scan.unreadableFiles) + " unreadable" +
            (scan.truncated ? ", scan limit reached" : "") + ")";
        return ev;
    }

    ev.eaHash = scan.genuineHash; // the hash measured from the file found above, not the expectation
    ev.ok = true;
    return ev;
}

HostEvidence MeasureHost(
    const std::string& expectedBrokerHash,
    const std::string& expectedMachineIdHash)
{
    HostEvidence host;

    const std::string wantBroker = ToLowerHex(expectedBrokerHash);
    const std::string wantMid = ToLowerHex(expectedMachineIdHash);
    if (!IsValidSha256Hex(wantBroker) || !IsValidSha256Hex(wantMid))
    {
        host.detail = "the signed manifest does not carry a usable expected hash for this Coordinator";
        return host;
    }

    // This process's own running image - not a copy of it kept anywhere.
    const DWORD OWN_PATH_CHARS = MAX_PATH * 2;
    wchar_t ownPath[OWN_PATH_CHARS] = {};
    const DWORD len = GetModuleFileNameW(nullptr, ownPath, OWN_PATH_CHARS);
    if (len == 0 || len >= OWN_PATH_CHARS)
    {
        host.detail = "could not determine the Coordinator's own running image path";
        return host;
    }
    host.brokerHash = HashOnly(std::wstring(ownPath, len));
    if (host.brokerHash.empty())
    {
        host.detail = "could not read the Coordinator's own running image";
        return host;
    }
    if (host.brokerHash != wantBroker)
    {
        host.detail = "the running Coordinator image does not match the signed manifest";
        return host;
    }

    // The MachineId DLL this process actually loaded, taken from the live
    // module handle MachineIdBridge holds - never from a path we assume.
    std::wstring machineIdPath;
    if (!MachineIdBridge::GetLoadedModulePath(machineIdPath) || machineIdPath.empty())
    {
        host.detail = "the Machine ID DLL is not loaded in the Coordinator process";
        return host;
    }
    host.machineIdHash = HashOnly(machineIdPath);
    if (host.machineIdHash.empty())
    {
        host.detail = "could not read the Machine ID DLL loaded by the Coordinator: " +
            NarrowForLog(machineIdPath);
        return host;
    }
    if (host.machineIdHash != wantMid)
    {
        host.detail = "the Machine ID DLL loaded by the Coordinator does not match the signed manifest";
        return host;
    }

    host.ok = true;
    return host;
}

} // namespace RuntimeMeasure
