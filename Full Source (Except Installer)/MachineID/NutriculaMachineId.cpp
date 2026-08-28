#define _WIN32_DCOM
#define NUTRICULA_MACHINE_ID_EXPORTS

#include "NutriculaMachineId.h"

#include <windows.h>
#include <wbemidl.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cwctype>
#include <sstream>
#include <iomanip>
#include <memory>
#include <mutex>
#include <cstring>
#include <cstdlib>
#include <cstdio>

#ifndef WC_ERR_INVALID_CHARS
#define WC_ERR_INVALID_CHARS 0x00000080
#endif

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winhttp.lib")

namespace {

thread_local int g_lastStatus = 0;
thread_local std::string g_lastPlatformProfile;
std::mutex g_keyMutex;

// TRANSPORT_KEY was REMOVED from this file - see the note near where
// GcmProtect/GcmUnprotect used to be defined for the full explanation.
// This DLL no longer needs it at all.

const wchar_t* KEY_MAGIC = L"NUTDKEY3";
const BYTE KEY_VERSION = 3;
const BYTE KEY_MODE_DPAPI = 1;
const BYTE KEY_MODE_PORTABLE = 2;
const ULONG P256_BYTES = 32;
const ULONG GCM_NONCE_BYTES = 12;
const ULONG GCM_TAG_BYTES = 16;

struct Signal {
    std::wstring name;
    std::wstring value;
    bool valid = false;
};

// Which environment this machine was identified in - determines both which
// signals are collected and which acceptance rule (HasAtLeastCoreIdentity)
// and canonical string layout (Canonicalize) apply.
enum class PlatformKind {
    WindowsPhysical,  // real Windows hardware - existing WMI logic, unchanged
    WindowsVM,        // Windows detected running on a hypervisor
    WineMacOS,        // Wine, host OS is macOS (CrossOver or plain Wine on Mac)
    WineLinux         // Wine, host OS is Linux
};

struct IdentityRecord {
    PlatformKind platform = PlatformKind::WindowsPhysical;

    // ---- Windows (WMI-sourced) signals - unchanged. Used for
    //      WindowsPhysical and WindowsVM. ----
    Signal systemUuid;
    Signal systemSerial;
    Signal baseboardSerial;
    Signal biosSerial;
    Signal cpuId;
    Signal diskSerial;
    Signal machineGuid;
    // macAddress REMOVED (2026): QueryFirstEnabledMac() returned whichever
    // IPEnabled=TRUE network adapter WMI's own internal enumeration
    // happened to list first - not guaranteed stable across reboots if
    // more than one adapter is active simultaneously (very common:
    // Ethernet + Wi-Fi, or a VPN virtual adapter, both enabled at once).
    // Independently, Windows 10/11's own "Random hardware addresses"
    // Wi-Fi privacy feature can rotate the MAC address itself regardless
    // of enumeration order. Neither problem can be fixed with certainty,
    // so removed entirely rather than papered over - same reasoning as
    // the macOS/Linux MAC removals above.
    Signal manufacturer;
    Signal family;
    Signal product;
    Signal sku;
    bool isVirtualMachine = false;

    // ---- macOS-under-Wine signals (see CollectMacIdentity) ----
    Signal macPlatformUuid;      // IOPlatformUUID - closest Mac equivalent of System UUID
    Signal macPlatformSerial;    // IOPlatformSerialNumber
    // macPrimaryMac REMOVED (2026): MAC address is not a stable identity
    // signal - beyond the interface-enumeration-order bug that motivated
    // this whole review, macOS's own "Private Wi-Fi Address" feature
    // (default-on since Monterey) actively rotates the MAC address that
    // en0 reports for Wi-Fi, independent of any ordering fix. No amount
    // of code here can make a randomized value stable, so it is removed
    // rather than papered over.
    Signal macModel;             // hw.model - corroboration only
    Signal macCpuBrand;          // machdep.cpu.brand_string - corroboration only

    // ---- Linux-under-Wine signals (see CollectLinuxIdentity) ----
    Signal linuxMachineId;       // /etc/machine-id - world-readable, but CAN be cloned in VM templates
    Signal linuxProductUuid;     // /sys/class/dmi/id/product_uuid - strong, usually root-only
    // linuxPrimaryMac REMOVED (2026): was selected via directory-listing
    // enumeration order of /sys/class/net/* (FindFirstFileW/FindNextFileW),
    // which is NOT guaranteed stable across reboots - network interface
    // discovery/registration order can change with kernel/udev/driver
    // timing, causing the "first" interface found to differ from one boot
    // to the next and silently changing the whole machine_id. Even a
    // fixed, order-independent interface selection would not fully solve
    // this either, since many modern Linux distros randomize MAC
    // addresses for Wi-Fi by default (NetworkManager's MAC randomization,
    // widely enabled) - a second, independent source of instability that
    // has nothing to do with enumeration order. Removed entirely rather
    // than replaced with a still-imperfect fix.
    Signal linuxBoardVendor;     // VM/cloud-provider detection hint only

    // ---- Cloud metadata (WindowsVM, WineMacOS, WineLinux) - the strongest
    //      possible VM/VPS signal when available: reported live by the
    //      provider's own control-plane API for the CURRENTLY RUNNING
    //      instance, so cloning a disk image cannot clone this answer. ----
    Signal cloudInstanceId;
};

struct ComInitGuard {
    HRESULT hr;
    ComInitGuard() : hr(CoInitializeEx(nullptr, COINIT_MULTITHREADED)) {}
    ~ComInitGuard() { if (SUCCEEDED(hr)) CoUninitialize(); }
    bool ok() const { return SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE; }
};

static std::wstring Trim(const std::wstring& s) {
    size_t begin = 0, end = s.size();
    while (begin < end && std::iswspace(s[begin])) ++begin;
    while (end > begin && std::iswspace(s[end - 1])) --end;
    return s.substr(begin, end - begin);
}

static std::wstring CollapseWhitespace(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    bool inWs = false;
    for (wchar_t ch : s) {
        if (std::iswspace(ch)) {
            if (!inWs) out.push_back(L' ');
            inWs = true;
        } else {
            out.push_back(ch);
            inWs = false;
        }
    }
    return out;
}

static std::wstring UpperInvariant(const std::wstring& s) {
    std::wstring out = s;
    if (!out.empty()) {
        LCMapStringW(LOCALE_INVARIANT, LCMAP_UPPERCASE, &out[0],
                     static_cast<int>(out.size()), &out[0],
                     static_cast<int>(out.size()));
    }
    return out;
}

static std::wstring Normalize(const std::wstring& raw) {
    std::wstring s = UpperInvariant(CollapseWhitespace(Trim(raw)));
    if (s.empty()) return L"";

    static const wchar_t* invalidTokens[] = {
        L"UNKNOWN", L"UNAVAILABLE", L"UNDEFINED", L"NONE", L"N/A", L"NA",
        L"NOT AVAILABLE", L"NOT SPECIFIED", L"NOT PROVIDED", L"NOT PRESENT",
        L"DEFAULT", L"DEFAULT STRING", L"TO BE FILLED BY O.E.M.",
        L"TO BE FILLED BY OEM", L"TO BE SET BY O.E.M.", L"TO BE SET BY OEM",
        L"SYSTEM SERIAL NUMBER", L"SERIAL NUMBER", L"OEM", L"OEM DEFAULT",
        L"NULL", L"INVALID", L"NOT SET", L"NOT KNOWN"
    };

    for (const auto* token : invalidTokens) {
        if (s == token) return L"";
    }

    std::wstring compact = s;
    compact.erase(std::remove(compact.begin(), compact.end(), L'-'), compact.end());
    if (compact.size() == 32 && compact.find_first_not_of(L'0') == std::wstring::npos) return L"";
    if (compact == L"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") return L"";

    if (s.size() >= 6) {
        bool allZero = true;
        bool hasDigit = false;
        for (wchar_t ch : s) {
            if (ch == L'0') hasDigit = true;
            else if (ch != L' ' && ch != L'-') allZero = false;
        }
        if (allZero && hasDigit) return L"";
    }

    return s;
}

static bool IsPlausibleUuid(const std::wstring& s) {
    if (s.empty()) return false;
    std::wstring n = Normalize(s);
    if (n.empty()) return false;
    return n.size() == 36 || n.size() == 32;
}

class WmiReader {
public:
    bool Initialize() {
        HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                      IID_IWbemLocator, reinterpret_cast<LPVOID*>(&locator_));
        if (FAILED(hr)) return false;
        BSTR ns = SysAllocString(L"ROOT\\CIMV2");
        if (!ns) return false;
        hr = locator_->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services_);
        SysFreeString(ns);
        if (FAILED(hr) || !services_) return false;
        hr = CoSetProxyBlanket(services_, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                               RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                               nullptr, EOAC_NONE);
        return SUCCEEDED(hr);
    }

    ~WmiReader() {
        if (services_) services_->Release();
        if (locator_) locator_->Release();
    }

    std::wstring QueryFirst(const wchar_t* className, const wchar_t* propertyName) {
        if (!services_) return L"";
        std::wstring query = L"SELECT " + std::wstring(propertyName) + L" FROM " + className;
        return QueryFirstInternal(query, propertyName, false);
    }


    std::wstring QueryFirstEnabledIp() {
        if (!services_) return L"";
        std::wstring query = L"SELECT IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE";
        IEnumWbemClassObject* enumerator = nullptr;
        if (!ExecQuery(query, &enumerator)) return L"";
        IWbemClassObject* obj = nullptr;
        ULONG returned = 0;
        HRESULT hr = enumerator->Next(WBEM_INFINITE, 1, &obj, &returned);
        if (FAILED(hr) || returned == 0 || !obj) {
            enumerator->Release();
            return L"";
        }
        VARIANT vt; VariantInit(&vt);
        std::wstring result;
        if (SUCCEEDED(obj->Get(L"IPAddress", 0, &vt, nullptr, nullptr))) {
            if ((vt.vt & VT_ARRAY) && vt.parray) {
                LONG lb = 0, ub = -1;
                if (SUCCEEDED(SafeArrayGetLBound(vt.parray, 1, &lb)) &&
                    SUCCEEDED(SafeArrayGetUBound(vt.parray, 1, &ub)) && ub >= lb) {
                    BSTR item = nullptr;
                    LONG idx = lb;
                    if (SUCCEEDED(SafeArrayGetElement(vt.parray, &idx, &item)) && item) {
                        result = item;
                        SysFreeString(item);
                    }
                }
            }
        }
        VariantClear(&vt);
        obj->Release();
        enumerator->Release();
        return result;
    }

private:
    IWbemLocator* locator_ = nullptr;
    IWbemServices* services_ = nullptr;

    bool ExecQuery(const std::wstring& query, IEnumWbemClassObject** out) {
        if (!services_ || !out) return false;
        *out = nullptr;
        BSTR language = SysAllocString(L"WQL");
        BSTR queryBstr = SysAllocString(query.c_str());
        if (!language || !queryBstr) {
            if (language) SysFreeString(language);
            if (queryBstr) SysFreeString(queryBstr);
            return false;
        }
        HRESULT hr = services_->ExecQuery(language, queryBstr,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr, out);
        SysFreeString(language);
        SysFreeString(queryBstr);
        return SUCCEEDED(hr) && *out != nullptr;
    }

    std::wstring QueryFirstInternal(const std::wstring& query, const wchar_t* propertyName, bool arrayFirst) {
        IEnumWbemClassObject* enumerator = nullptr;
        if (!ExecQuery(query, &enumerator)) return L"";
        IWbemClassObject* obj = nullptr;
        ULONG returned = 0;
        HRESULT hr = enumerator->Next(WBEM_INFINITE, 1, &obj, &returned);
        if (FAILED(hr) || returned == 0 || !obj) {
            enumerator->Release();
            return L"";
        }
        VARIANT vt; VariantInit(&vt);
        std::wstring result;
        if (SUCCEEDED(obj->Get(propertyName, 0, &vt, nullptr, nullptr))) {
            if (vt.vt == VT_BSTR && vt.bstrVal) result = vt.bstrVal;
            else if (vt.vt == VT_I4) result = std::to_wstring(vt.lVal);
            else if (vt.vt == VT_UI4) result = std::to_wstring(vt.ulVal);
        }
        VariantClear(&vt);
        obj->Release();
        enumerator->Release();
        return result;
    }

    // Finds the SerialNumber of the PHYSICAL disk that actually contains
    // the Windows system volume (%SystemDrive%, e.g. "C:"), via the
    // standard WMI associator chain: Win32_LogicalDisk (the drive letter)
    // -> Win32_DiskPartition (via Win32_LogicalDiskToPartition) ->
    // Win32_DiskDrive (via Win32_DiskDriveToDiskPartition). This is
    // deliberately NOT "just take the first Win32_DiskDrive result" - on
    // a multi-disk machine, WMI's own enumeration order for
    // Win32_DiskDrive is not guaranteed stable across reboots, so
    // "whichever disk happened to be listed first" could silently point
    // at a different physical disk (and therefore a different serial
    // number, and therefore a different machine_id) after a reboot. The
    // serial number itself (Win32_DiskDrive.SerialNumber) is a genuinely
    // good per-device identity value - the manufacturer's own physical
    // media identifier - the only real problem was ever WHICH disk got
    // selected, never the value once correctly selected.
public:
    std::wstring QuerySystemDiskSerial() {
        if (!services_) return L"";

        wchar_t sysDrive[16] = {};
        DWORD len = GetEnvironmentVariableW(L"SystemDrive", sysDrive, 16);
        std::wstring driveLetter = (len > 0 && len < 16) ? sysDrive : L"C:";
        // Normalize to exactly "C:" form (no trailing backslash) to match
        // Win32_LogicalDisk.DeviceID's format exactly.
        if (!driveLetter.empty() && driveLetter.back() == L'\\') driveLetter.pop_back();

        std::wstring partitionQuery =
            L"ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='" + driveLetter + L"'} "
            L"WHERE AssocClass=Win32_LogicalDiskToPartition ResultClass=Win32_DiskPartition";
        std::wstring partitionDeviceId = QueryFirstInternal(partitionQuery, L"DeviceID", false);
        if (partitionDeviceId.empty()) return L"";

        // DeviceID values like "Disk #0, Partition #1" contain characters
        // (#, comma, space) that are valid inside WQL string literals as-is
        // - no escaping needed for this specific associator syntax.
        std::wstring diskQuery =
            L"ASSOCIATORS OF {Win32_DiskPartition.DeviceID='" + partitionDeviceId + L"'} "
            L"WHERE AssocClass=Win32_DiskDriveToDiskPartition ResultClass=Win32_DiskDrive";
        return QueryFirstInternal(diskQuery, L"SerialNumber", false);
    }
private:
};

static std::wstring ReadMachineGuid() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography",
                      0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography",
                          0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return L"";
    }
    wchar_t buffer[512] = {};
    DWORD type = 0, size = sizeof(buffer);
    LONG rc = RegQueryValueExW(key, L"MachineGuid", nullptr, &type,
                               reinterpret_cast<BYTE*>(buffer), &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) return L"";
    return std::wstring(buffer);
}

static std::wstring GetSystemDrive() {
    wchar_t windowsDir[MAX_PATH] = {};
    UINT n = GetWindowsDirectoryW(windowsDir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L"";
    wchar_t root[4] = { windowsDir[0], L':', L'\\', L'\0' };
    return root;
}

static std::wstring ReadVolumeSerial() {
    std::wstring root = GetSystemDrive();
    if (root.empty()) return L"";
    DWORD serial = 0;
    if (!GetVolumeInformationW(root.c_str(), nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) return L"";
    std::wstringstream ss;
    ss << std::uppercase << std::hex << std::setw(8) << std::setfill(L'0') << serial;
    return ss.str();
}

static bool ContainsCaseInsensitive(const std::wstring& haystack, const wchar_t* needle) {
    std::wstring h = UpperInvariant(haystack);
    std::wstring n = UpperInvariant(needle ? std::wstring(needle) : L"");
    return h.find(n) != std::wstring::npos;
}

static bool IsVirtualMachine(WmiReader& wmi) {
    std::wstring sysManufacturer = wmi.QueryFirst(L"Win32_ComputerSystem", L"Manufacturer");
    std::wstring sysModel = wmi.QueryFirst(L"Win32_ComputerSystem", L"Model");
    std::wstring biosVendor = wmi.QueryFirst(L"Win32_BIOS", L"Manufacturer");
    const wchar_t* markers[] = {
        L"VMWARE", L"VIRTUALBOX", L"INNOTEK", L"VIRTUAL MACHINE",
        L"QEMU", L"KVM", L"XEN", L"BOCHS", L"PARALLELS", L"HYPER-V"
    };
    for (const wchar_t* marker : markers) {
        if (ContainsCaseInsensitive(sysManufacturer, marker) ||
            ContainsCaseInsensitive(sysModel, marker) ||
            ContainsCaseInsensitive(biosVendor, marker)) return true;
    }
    if (ContainsCaseInsensitive(sysManufacturer, L"MICROSOFT CORPORATION") &&
        ContainsCaseInsensitive(sysModel, L"VIRTUAL MACHINE")) return true;
    return false;
}

static Signal MakeSignal(const wchar_t* name, const std::wstring& raw) {
    Signal s;
    s.name = name;
    s.value = Normalize(raw);
    s.valid = !s.value.empty();
    return s;
}

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int chars = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (chars <= 0) return L"";
    std::wstring out(chars, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &out[0], chars);
    return out;
}

static Signal MakeSignalUtf8(const wchar_t* name, const std::string& raw) {
    return MakeSignal(name, Utf8ToWide(raw));
}

// ============================================================================
// Running a real host-OS command from inside Wine, and reading its output.
//
// CONFIRMED BY DIRECT TESTING (not assumed from documentation):
//   - CRT popen()/system() do NOT reach the real host shell - they go
//     through Wine's own emulated cmd.exe, which cannot run Unix commands.
//   - CreateProcessW with a direct Unix path (e.g. L"Z:\\bin\\sh") DOES
//     launch the genuine host binary and returns its real output - also
//     independently confirmed by the WineHQ project itself
//     (forum.winehq.org/viewtopic.php?t=3179: "Native *NIX processes won't
//     have process handle - they are run outside Wine").
//   - WaitForSingleObject and GetExitCodeProcess are UNRELIABLE for a
//     process started this way - relying on either can make a fast command
//     appear to take the ENTIRE timeout, or hang.
//   - The reliable technique, confirmed by direct testing: redirect output
//     to a file, have the command touch a SEPARATE marker file as its very
//     last step, and poll only for the marker file's existence.
//   - IMPORTANT: GetTempPathW() returns a Windows-side path (typically
//     under C:\...\Temp) which does NOT correspond to the same physical
//     file a shell command (addressing paths in Unix form) would write to
//     - confirmed by direct testing, this mismatch silently breaks the
//     marker-file wait. Z:\tmp\ is Wine's own standard mapping of the
//     host's real /tmp, so both sides agree on the same physical file.
// ============================================================================

static bool RunHostShellCommand(const std::string& shellCommand, std::string& output, DWORD maxWaitMs) {
    output.clear();

    const wchar_t* tempDir = L"Z:\\tmp\\";

    static volatile LONG counter = 0;
    LONG id = InterlockedIncrement(&counter);
    DWORD pid = GetCurrentProcessId();

    wchar_t outPathW[MAX_PATH + 64];
    wchar_t markerPathW[MAX_PATH + 64];
    wsprintfW(outPathW, L"%snutid_out_%lu_%ld.tmp", tempDir, pid, id);
    wsprintfW(markerPathW, L"%snutid_done_%lu_%ld.tmp", tempDir, pid, id);

    DeleteFileW(outPathW);
    DeleteFileW(markerPathW);

    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE outFile = CreateFileW(outPathW, GENERIC_WRITE, FILE_SHARE_READ,
        &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (outFile == INVALID_HANDLE_VALUE) return false;

    char markerUnixPath[MAX_PATH + 64];
    sprintf(markerUnixPath, "/tmp/nutid_done_%lu_%ld.tmp", (unsigned long)pid, (long)id);

    std::string fullCmd = "sh -c \"" + shellCommand + "; touch " + markerUnixPath + "\" ";
    std::wstring wCmd = Utf8ToWide(fullCmd);
    std::vector<wchar_t> mutableCmd(wCmd.begin(), wCmd.end());
    mutableCmd.push_back(0);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = outFile;
    si.hStdError = outFile;
    PROCESS_INFORMATION pi = {};

    BOOL ok = CreateProcessW(L"Z:\\bin\\sh", mutableCmd.data(), nullptr, nullptr, TRUE,
        0, nullptr, nullptr, &si, &pi);
    CloseHandle(outFile);
    if (!ok) {
        DeleteFileW(outPathW);
        return false;
    }

    DWORD waited = 0;
    while (waited < maxWaitMs) {
        if (GetFileAttributesW(markerPathW) != INVALID_FILE_ATTRIBUTES) break;
        Sleep(20);
        waited += 20;
    }
    bool completed = (waited < maxWaitMs);

    HANDLE readHandle = CreateFileW(outPathW, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (readHandle != INVALID_HANDLE_VALUE) {
        char buf[8192];
        DWORD read = 0;
        if (ReadFile(readHandle, buf, sizeof(buf) - 1, &read, nullptr)) {
            buf[read] = '\0';
            output.assign(buf, read);
        }
        CloseHandle(readHandle);
    }

    DeleteFileW(outPathW);
    DeleteFileW(markerPathW);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);

    return completed;
}

// Parses "===KEY===\nvalue\n===KEY2===\n..." batched-command output.
static std::map<std::string, std::string> ParseMarkedSections(const std::string& raw) {
    std::map<std::string, std::string> result;
    std::string currentKey, currentValue;
    std::istringstream ss(raw);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.size() > 6 && line.compare(0, 3, "===") == 0 &&
            line.compare(line.size() - 3, 3, "===") == 0) {
            if (!currentKey.empty()) result[currentKey] = currentValue;
            currentKey = line.substr(3, line.size() - 6);
            currentValue.clear();
        } else if (!currentKey.empty()) {
            if (!currentValue.empty()) currentValue += "\n";
            currentValue += line;
        }
    }
    if (!currentKey.empty()) result[currentKey] = currentValue;
    return result;
}

// Returns "Darwin", "Linux", or "" if undetermined.
// Detects the Wine host OS via Wine's own official ntdll.dll export
// wine_get_host_version(const char** sysname, const char** release) -
// documented by Wine as a thin wrapper over the host's own uname(), and
// exactly what wine_get_host_version reports as "Darwin" on macOS. This
// replaces an earlier implementation that shelled out to run `uname -s`
// as a separate process - using the exported function directly is faster
// (no process spawn), and more reliable (no dependency on the shell/PATH
// environment being sane). Follows the identical
// GetModuleHandleA+GetProcAddress pattern already used by IsWine() below.
static std::string DetectWineHostOS() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return "";
    typedef void (__cdecl *WineGetHostVersionFn)(const char** sysname, const char** release);
    auto fn = reinterpret_cast<WineGetHostVersionFn>(GetProcAddress(ntdll, "wine_get_host_version"));
    if (!fn) return "";
    const char* sysname = nullptr;
    const char* release = nullptr;
    fn(&sysname, &release);
    return sysname ? std::string(sysname) : "";
}

// ============================================================================
// Direct file reads for Linux (no process spawn needed - confirmed by direct
// testing that Wine's mapped Z:\ drive lets ordinary WinAPI file calls read
// real host files directly, including virtual filesystems like /proc and /sys).
// ============================================================================

static std::string ReadUnixFileDirect(const std::wstring& zPath) {
    HANDLE h = CreateFileW(zPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return "";
    char buf[4096];
    DWORD read = 0;
    std::string result;
    if (ReadFile(h, buf, sizeof(buf) - 1, &read, nullptr) && read > 0) {
        buf[read] = '\0';
        result.assign(buf, read);
    }
    CloseHandle(h);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r' || result.back() == ' '))
        result.pop_back();
    return result;
}

// Enumerates /sys/class/net/* (world-readable, no process spawn needed) to
// find the first real (non-loopback, non-zero) interface's MAC address.
// ReadPrimaryLinuxMac() REMOVED (2026) - was reading /sys/class/net/*
// via FindFirstFileW/FindNextFileW directory enumeration and taking
// whichever non-loopback interface happened to appear FIRST in that
// listing order. That order is not guaranteed stable across reboots
// (kernel/udev/driver interface-registration timing can vary), so the
// whole machine_id could silently change on reboot. See the
// linuxPrimaryMac field removal note above for the full reasoning
// (including MAC randomization as a second, independent problem).

// ============================================================================
// Cloud provider metadata service (AWS/Azure/GCP) - the strongest possible
// VM/VPS identity signal: reported live by the provider's own control-plane
// API for the CURRENTLY RUNNING instance, not read from anything on disk.
// 169.254.169.254 is link-local and unroutable outside an actual cloud VM -
// confirmed by direct testing that a failing query with an explicit short
// timeout returns well under the timeout, never hangs.
// ============================================================================

struct CloudMetadataResult {
    bool available = false;
    std::string provider;
    std::string instanceId;
};

static bool HttpGetMetadata(const wchar_t* host, const wchar_t* path,
    const wchar_t* method, const wchar_t* extraHeaders,
    std::string& outBody, DWORD timeoutMs) {
    outBody.clear();
    HINTERNET session = WinHttpOpen(L"NutriculaMachineId/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return false;
    WinHttpSetTimeouts(session, (int)timeoutMs, (int)timeoutMs, (int)timeoutMs, (int)timeoutMs);

    HINTERNET connect = WinHttpConnect(session, host, 80, 0);
    if (!connect) { WinHttpCloseHandle(session); return false; }

    HINTERNET request = WinHttpOpenRequest(connect, method, path, nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!request) { WinHttpCloseHandle(connect); WinHttpCloseHandle(session); return false; }

    BOOL sent = WinHttpSendRequest(request,
        extraHeaders ? extraHeaders : WINHTTP_NO_ADDITIONAL_HEADERS,
        extraHeaders ? (DWORD)-1 : 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    bool ok = sent && WinHttpReceiveResponse(request, nullptr);

    if (ok) {
        DWORD statusCode = 0, statusSize = sizeof(statusCode);
        WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
        if (statusCode != 200) ok = false;
    }
    if (ok) {
        DWORD available = 0;
        while (WinHttpQueryDataAvailable(request, &available) && available > 0) {
            std::vector<char> buf(available);
            DWORD read = 0;
            if (!WinHttpReadData(request, buf.data(), available, &read)) break;
            outBody.append(buf.data(), read);
            if (outBody.size() > 8192) break;
        }
    }
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return ok && !outBody.empty();
}

static std::string ExtractJsonStringField(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return "";
    pos = json.find('"', pos);
    if (pos == std::string::npos) return "";
    size_t end = json.find('"', pos + 1);
    if (end == std::string::npos) return "";
    return json.substr(pos + 1, end - pos - 1);
}

static CloudMetadataResult QueryCloudMetadataAWS(DWORD timeoutMs) {
    CloudMetadataResult result;
    std::string token;
    HttpGetMetadata(L"169.254.169.254", L"/latest/api/token", L"PUT",
        L"X-aws-ec2-metadata-token-ttl-seconds: 21600\r\n", token, timeoutMs);
    std::wstring authHeader;
    if (!token.empty()) authHeader = L"X-aws-ec2-metadata-token: " + Utf8ToWide(token) + L"\r\n";
    std::string instanceId;
    bool ok = HttpGetMetadata(L"169.254.169.254", L"/latest/meta-data/instance-id", L"GET",
        token.empty() ? nullptr : authHeader.c_str(), instanceId, timeoutMs);
    if (ok && !instanceId.empty() && instanceId.compare(0, 2, "i-") == 0) {
        result.available = true;
        result.provider = "AWS";
        result.instanceId = instanceId;
    }
    return result;
}

static CloudMetadataResult QueryCloudMetadataAzure(DWORD timeoutMs) {
    CloudMetadataResult result;
    std::string body;
    bool ok = HttpGetMetadata(L"169.254.169.254",
        L"/metadata/instance?api-version=2021-02-01", L"GET",
        L"Metadata: true\r\n", body, timeoutMs);
    if (ok) {
        std::string vmId = ExtractJsonStringField(body, "vmId");
        if (!vmId.empty()) {
            result.available = true;
            result.provider = "AZURE";
            result.instanceId = vmId;
        }
    }
    return result;
}

static CloudMetadataResult QueryCloudMetadataGCP(DWORD timeoutMs) {
    CloudMetadataResult result;
    std::string body;
    bool ok = HttpGetMetadata(L"metadata.google.internal",
        L"/computeMetadata/v1/instance/id", L"GET",
        L"Metadata-Flavor: Google\r\n", body, timeoutMs);
    if (ok && !body.empty()) {
        result.available = true;
        result.provider = "GCP";
        result.instanceId = body;
    }
    return result;
}

static CloudMetadataResult QueryCloudMetadata() {
    const DWORD timeoutMs = 700;
    CloudMetadataResult r = QueryCloudMetadataAWS(timeoutMs);
    if (r.available) return r;
    r = QueryCloudMetadataAzure(timeoutMs);
    if (r.available) return r;
    r = QueryCloudMetadataGCP(timeoutMs);
    return r;
}

// ============================================================================
// macOS-under-Wine identity collection
// ============================================================================

static IdentityRecord CollectMacIdentity(bool* gotAny) {
    IdentityRecord r;
    r.platform = PlatformKind::WineMacOS;
    if (gotAny) *gotAny = false;

    const char* cmd =
        "echo ===UUID===; "
        "/usr/sbin/ioreg -d2 -c IOPlatformExpertDevice 2>/dev/null | awk -F'\\\"' '/IOPlatformUUID/{print $(NF-1)}'; "
        "echo ===SERIAL===; "
        "/usr/sbin/ioreg -d2 -c IOPlatformExpertDevice 2>/dev/null | awk -F'\\\"' '/IOPlatformSerialNumber/{print $(NF-1)}'; "
        "echo ===MODEL===; "
        "/usr/sbin/sysctl -n hw.model 2>/dev/null; "
        "echo ===CPU===; "
        "/usr/sbin/sysctl -n machdep.cpu.brand_string 2>/dev/null";

    std::string raw;
    if (!RunHostShellCommand(cmd, raw, 3000)) return r;
    auto parsed = ParseMarkedSections(raw);

    r.macPlatformUuid = MakeSignalUtf8(L"MAC_PLATFORM_UUID", parsed.count("UUID") ? parsed["UUID"] : "");
    r.macPlatformSerial = MakeSignalUtf8(L"MAC_PLATFORM_SERIAL", parsed.count("SERIAL") ? parsed["SERIAL"] : "");
    // MAC_PRIMARY_MAC removed - see field declaration comment above.
    r.macModel = MakeSignalUtf8(L"MAC_MODEL", parsed.count("MODEL") ? parsed["MODEL"] : "");
    r.macCpuBrand = MakeSignalUtf8(L"MAC_CPU_BRAND", parsed.count("CPU") ? parsed["CPU"] : "");

    CloudMetadataResult cloud = QueryCloudMetadata();
    if (cloud.available) {
        r.cloudInstanceId = MakeSignalUtf8(L"CLOUD_INSTANCE_ID", cloud.provider + ":" + cloud.instanceId);
    }

    if (gotAny) *gotAny = true;
    return r;
}

// ============================================================================
// Linux-under-Wine identity collection
// ============================================================================

static IdentityRecord CollectLinuxIdentity(bool* gotAny) {
    IdentityRecord r;
    r.platform = PlatformKind::WineLinux;
    if (gotAny) *gotAny = false;

    r.linuxMachineId = MakeSignalUtf8(L"LINUX_MACHINE_ID", ReadUnixFileDirect(L"Z:\\etc\\machine-id"));
    r.linuxProductUuid = MakeSignalUtf8(L"LINUX_PRODUCT_UUID", ReadUnixFileDirect(L"Z:\\sys\\class\\dmi\\id\\product_uuid"));
    // LINUX_PRIMARY_MAC removed - see field declaration comment above.
    r.linuxBoardVendor = MakeSignalUtf8(L"LINUX_BOARD_VENDOR", ReadUnixFileDirect(L"Z:\\sys\\class\\dmi\\id\\board_vendor"));

    CloudMetadataResult cloud = QueryCloudMetadata();
    if (cloud.available) {
        r.cloudInstanceId = MakeSignalUtf8(L"CLOUD_INSTANCE_ID", cloud.provider + ":" + cloud.instanceId);
    }

    if (gotAny) *gotAny = true;
    return r;
}

static bool HasAtLeastCoreIdentity(const IdentityRecord& r) {
    switch (r.platform) {
        case PlatformKind::WindowsPhysical: {
            const bool uuid = IsPlausibleUuid(r.systemUuid.value);
            const bool systemSerial = r.systemSerial.valid;
            const bool board = r.baseboardSerial.valid;
            const bool bios = r.biosSerial.valid;
            const bool cpu = r.cpuId.valid;
            const bool disk = r.diskSerial.valid;
            const bool guid = r.machineGuid.valid;
            // macAddress removed - see field declaration comment above.
            if (uuid && (board || bios || disk || systemSerial)) return true;
            if (systemSerial && (board || bios || disk)) return true;
            if (board && (bios || disk || uuid || systemSerial)) return true;
            if (bios && (board || uuid || systemSerial || disk)) return true;
            if (guid && (uuid || systemSerial || board || bios || disk || cpu)) return true;
            return false;
        }

        case PlatformKind::WindowsVM: {
            // Tier 1: a cloud provider metadata answer is, on its own,
            // sufficient - it cannot be produced by cloning a disk image.
            if (r.cloudInstanceId.valid) return true;

            // Tier 2: no metadata service available - require at least TWO
            // independent hypervisor-level signals, since SMBIOS UUID alone
            // is documented to be duplicated across clones by mainstream
            // platforms (e.g. VMware Cloud Director's CloneBiosUuidOnVmCopy
            // defaults to keeping the UUID identical across every VM
            // deployed from one template).
            //
            // Extended to include diskSerial/machineGuid/cpuId alongside
            // the original five - these were ALREADY being folded into the
            // actual machine_id hash in Canonicalize() below (so they
            // already contributed to distinguishing genuinely different,
            // non-cloned VMs from each other), but were not being counted
            // toward this acceptance threshold at all. A VM lacking most of
            // the original five signals but genuinely possessing a unique
            // disk serial, Windows install GUID, or CPU identifier was
            // being rejected outright despite having real distinguishing
            // data available - this was overly strict, not a security gap
            // (the reverse: it only ever caused false rejections, never
            // false acceptances). No single one of these three is treated
            // as strong as the original five on its own - they are still
            // documented to be sometimes duplicated across clones/templates
            // on their own (particularly machineGuid, which many
            // sysprep/cloning workflows regenerate but not all do
            // reliably) - so they only ever ADD to the count alongside
            // whatever else is present, never substitute for needing two
            // signals in total.
            int strongSignals = 0;
            if (IsPlausibleUuid(r.systemUuid.value)) strongSignals++;
            // macAddress removed - see field declaration comment above.
            if (r.systemSerial.valid) strongSignals++;
            if (r.baseboardSerial.valid) strongSignals++;
            if (r.biosSerial.valid) strongSignals++;
            if (r.diskSerial.valid) strongSignals++;
            if (r.machineGuid.valid) strongSignals++;
            if (r.cpuId.valid) strongSignals++;
            return strongSignals >= 2;
        }

        case PlatformKind::WineMacOS: {
            if (r.cloudInstanceId.valid) return true;
            // MAC (formerly used as corroboration alongside uuid/serial)
            // removed - see field declaration comment. IOPlatformUUID and
            // IOPlatformSerialNumber are each independently strong,
            // per-device signals in their own right, so either one alone
            // is now sufficient.
            if (r.macPlatformUuid.valid) return true;
            if (r.macPlatformSerial.valid) return true;
            // NOTE: macModel/macCpuBrand are deliberately NOT used here,
            // on reflection - same reasoning as WineLinux's
            // linuxBoardVendor below. hw.model (e.g. "MacBookPro18,3") and
            // machdep.cpu.brand_string (e.g. "Apple M1 Pro") each identify
            // a MODEL/CHIP shared across every device of that
            // model/generation - potentially millions of physically
            // different Macs report the IDENTICAL pair. This differs from
            // the WindowsVM extension above (diskSerial/machineGuid/cpuId
            // ARE genuinely per-instance values, not per-model) - using a
            // model/chip pair to lower the acceptance bar here would risk
            // FALSE acceptance (two different physical Macs treated as the
            // same machine), not just fix false rejection. Both signals
            // remain in Canonicalize() below (still contribute to the
            // final hash), just never used to lower this bar.
            return false;
        }

        case PlatformKind::WineLinux: {
            if (r.cloudInstanceId.valid) return true;
            // MAC removed (see above). Both remaining signals are now
            // independently sufficient - CORRECTED after direct Wine
            // testing showed requiring linuxProductUuid+linuxMachineId
            // paired together left common real-world cases (product_uuid
            // is very often root-only or entirely absent, e.g. inside
            // containers) with NO valid acceptance path at all, which is
            // a worse outcome than the documented VM-template-cloning
            // risk of trusting machine_id alone - that risk is
            // scenario-specific (only affects VMs deployed from a shared
            // template), while the previous requirement broke the common
            // case (an ordinary non-root Linux install) entirely.
            if (r.linuxProductUuid.valid) return true;
            if (r.linuxMachineId.valid) return true;
            // NOTE: linuxBoardVendor is deliberately NOT used here, unlike
            // the analogous extensions above for WindowsVM/WineMacOS. It is
            // too coarse to safely count toward acceptance even as
            // corroboration - it identifies a HYPERVISOR VENDOR (e.g.
            // "QEMU", "VMware", "Xen"), which is IDENTICAL across every
            // single VM running under that same hypervisor, not a
            // machine-specific value. Loosening acceptance based on it
            // would risk the opposite failure mode from what this section
            // exists to fix: FALSE acceptance (two genuinely different VMs
            // wrongly treated as the same machine), not just false
            // rejection. It remains in Canonicalize() below (still
            // contributes to the final hash, still helps distinguish
            // machines that already passed acceptance on other grounds),
            // just never used to lower this bar.
            return false;
        }
    }
    return false;
}

static std::string ToUtf8(const std::wstring& s) {
    if (s.empty()) return {};
    int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) return {};
    std::string out(bytes, '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), (int)s.size(), &out[0], bytes, nullptr, nullptr) != bytes) return {};
    return out;
}

static void AppendSignal(std::wstringstream& ss, const Signal& s) {
    ss << s.name << L"=" << (s.valid ? s.value : L"<MISSING>") << L"\n";
}

static std::wstring Canonicalize(const IdentityRecord& r) {
    std::wstringstream ss;

    switch (r.platform) {
        case PlatformKind::WindowsPhysical: {
            ss << L"PROFILE=WINDOWS\nVERSION=2\n";
            const Signal* signals[] = {
                &r.systemUuid, &r.systemSerial, &r.baseboardSerial, &r.biosSerial,
                &r.cpuId, &r.diskSerial, &r.machineGuid,
                &r.manufacturer, &r.family, &r.product, &r.sku
            };
            for (const Signal* s : signals) AppendSignal(ss, *s);
            break;
        }

        case PlatformKind::WindowsVM: {
            // Deliberately a DIFFERENT profile tag/version than
            // WindowsPhysical, AND deliberately different from what this
            // profile used to be (which folded in hostname/username/local
            // IP - unstable and provided no real anti-cloning benefit, see
            // the accompanying research notes). Any license activated
            // under the OLD VM canonical format will need one-time
            // re-activation after this change.
            ss << L"PROFILE=WINDOWS_VM\nVERSION=3\n";
            const Signal* signals[] = {
                &r.systemUuid, &r.systemSerial, &r.baseboardSerial, &r.biosSerial,
                &r.cpuId, &r.diskSerial, &r.machineGuid,
                &r.manufacturer, &r.family, &r.product, &r.sku
            };
            for (const Signal* s : signals) AppendSignal(ss, *s);
            AppendSignal(ss, r.cloudInstanceId);
            break;
        }

        case PlatformKind::WineMacOS: {
            ss << L"PROFILE=MACOS_WINE\nVERSION=2\n";
            AppendSignal(ss, r.macPlatformUuid);
            AppendSignal(ss, r.macPlatformSerial);
            // macPrimaryMac removed - see field declaration comment.
            AppendSignal(ss, r.macModel);
            AppendSignal(ss, r.macCpuBrand);
            AppendSignal(ss, r.cloudInstanceId);
            break;
        }

        case PlatformKind::WineLinux: {
            ss << L"PROFILE=LINUX_WINE\nVERSION=2\n";
            AppendSignal(ss, r.linuxMachineId);
            AppendSignal(ss, r.linuxProductUuid);
            // linuxPrimaryMac removed - see field declaration comment.
            AppendSignal(ss, r.linuxBoardVendor);
            AppendSignal(ss, r.cloudInstanceId);
            break;
        }
    }

    return ss.str();
}

static bool Sha256Bytes(const std::vector<unsigned char>& data, std::vector<unsigned char>& digest) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0, result = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
    bool ok = false;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &result, 0) >= 0) {
        std::vector<unsigned char> object(objectSize);
        if (BCryptCreateHash(alg, &hash, object.data(), objectSize, nullptr, 0, 0) >= 0 &&
            BCryptHashData(hash, const_cast<PUCHAR>(data.data()), (ULONG)data.size(), 0) >= 0) {
            digest.resize(32);
            ok = BCryptFinishHash(hash, digest.data(), 32, 0) >= 0;
        }
    }
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

static bool Sha256String(const std::string& text, std::vector<unsigned char>& digest) {
    std::vector<unsigned char> data(text.begin(), text.end());
    return Sha256Bytes(data, digest);
}


static bool RandomBytes(unsigned char* output, DWORD count);
static std::string GetEnvA(const char* name);
static std::wstring AnsiToWide(const std::string& s);

static bool IsWine() {
    // Primary, reliable check: Wine implements an internal-only export,
    // "wine_get_version", in ntdll.dll that genuine Windows never has. This is
    // the standard, widely-documented technique (WineHQ forums and multiple
    // independent sources) and does not depend on environment variables being
    // correctly propagated - which is NOT guaranteed, especially under
    // CrossOver, which manages "bottles" differently from raw Wine and does
    // not always set WINEPREFIX in the process environment block the same way.
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll && GetProcAddress(ntdll, "wine_get_version") != nullptr) {
        return true;
    }

    // Fallback signal only, in case a future Wine/CrossOver build ever removes
    // that export: environment variables Wine typically sets.
    char buffer[2] = {};
    return GetEnvironmentVariableA("WINEPREFIX", buffer, sizeof(buffer)) > 0 ||
           GetEnvironmentVariableA("WINELOADERNOEXEC", buffer, sizeof(buffer)) > 0 ||
           GetEnvironmentVariableA("WINELOADER", buffer, sizeof(buffer)) > 0;
}

static std::string GetEnvA(const char* name) {
    char buf[4096] = {};
    DWORD n = GetEnvironmentVariableA(name, buf, sizeof(buf));
    if (n == 0 || n >= sizeof(buf)) return {};
    return std::string(buf, n);
}

static std::wstring AnsiToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (n <= 0) n = MultiByteToWideChar(CP_ACP, 0, s.data(), (int)s.size(), nullptr, 0);
    if (n <= 0) return L"";
    std::wstring out(n, L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &out[0], n) != n)
        MultiByteToWideChar(CP_ACP, 0, s.data(), (int)s.size(), &out[0], n);
    return out;
}

// IMPORTANT FIX, found and confirmed by direct testing: the "HOME"
// environment variable is NEVER visible to a Windows-side process running
// under Wine, even when explicitly exported before launching wine itself -
// GetEnvironmentVariableA("HOME", ...) always returns empty. This broke
// device key persistence (and would have broken the license file path)
// under Wine entirely: every call would silently fail to find/create the
// key, forcing a brand new key to be regenerated - and any previously
// issued license bound to the old key would stop matching.
//
// The actual, working mechanism (confirmed by direct testing): Wine
// exposes the real Unix home directory to Windows-side processes via the
// WINEHOMEDIR environment variable, in NT object-namespace form
// (e.g. "\??\Z:\root") - stripping the "\??\" prefix yields a normal,
// directly usable Win32 path ("Z:\root") that CreateFileW/CreateDirectoryW
// accept exactly like any other path.
static std::wstring GetWineHomeDirWindowsPath() {
    std::string raw = GetEnvA("WINEHOMEDIR");
    if (raw.empty()) return L"";
    const std::string ntPrefix = "\\??\\";
    if (raw.compare(0, ntPrefix.size(), ntPrefix) == 0) {
        raw = raw.substr(ntPrefix.size());
    }
    if (raw.empty()) return L"";
    return AnsiToWide(raw);
}

static std::wstring GetDeviceKeyPath() {
    if (IsWine()) {
        std::wstring home = GetWineHomeDirWindowsPath();
        if (home.empty()) return L"";
        return home + L"\\.nutricula\\DeviceKey.bin";
    }
    std::string appData = GetEnvA("APPDATA");
    if (appData.empty()) return L"";
    return AnsiToWide(appData) + L"\\Nutricula\\DeviceKey.bin";
}

static bool RandomBytes(unsigned char* output, DWORD count) {
    if (!output || count == 0) return false;
    return BCryptGenRandom(nullptr, output, count, BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
}

static bool Base64Encode(const std::vector<unsigned char>& data, std::string& out) {
    DWORD chars = 0;
    if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &chars)) return false;
    std::string temp(chars, '\0');
    if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &temp[0], &chars)) return false;
    while (!temp.empty() && (temp.back() == '\0' || temp.back() == '\r' || temp.back() == '\n')) temp.pop_back();
    out.swap(temp);
    return true;
}

static bool Base64Decode(const std::string& text, std::vector<unsigned char>& out) {
    DWORD bytes = 0;
    if (!CryptStringToBinaryA(text.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &bytes, nullptr, nullptr)) return false;
    out.resize(bytes);
    if (!CryptStringToBinaryA(text.c_str(), 0, CRYPT_STRING_BASE64, out.data(), &bytes, nullptr, nullptr)) return false;
    out.resize(bytes);
    return true;
}

static bool GcmCrypt(const unsigned char* key, const unsigned char* nonce, const unsigned char* input, ULONG inputLen,
                     unsigned char* output, unsigned char* tag, bool encrypt) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE keyHandle = nullptr;
    DWORD objectSize = 0, result = 0, outputLen = 0;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0) goto cleanup;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                          reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                          (ULONG)(sizeof(BCRYPT_CHAIN_MODE_GCM)), 0) < 0) goto cleanup;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &result, 0) < 0) goto cleanup;
    {
        std::vector<unsigned char> object(objectSize);
        if (BCryptGenerateSymmetricKey(alg, &keyHandle, object.data(), objectSize,
                                       const_cast<PUCHAR>(key), 32, 0) < 0) goto cleanup;
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
        BCRYPT_INIT_AUTH_MODE_INFO(auth);
        auth.pbNonce = const_cast<PUCHAR>(nonce);
        auth.cbNonce = GCM_NONCE_BYTES;
        auth.pbTag = tag;
        auth.cbTag = GCM_TAG_BYTES;
        NTSTATUS st;
        if (encrypt) {
            st = BCryptEncrypt(keyHandle, const_cast<PUCHAR>(input), inputLen,
                               &auth, nullptr, 0, output, inputLen, &outputLen, 0);
        } else {
            st = BCryptDecrypt(keyHandle, const_cast<PUCHAR>(input), inputLen,
                               &auth, nullptr, 0, output, inputLen, &outputLen, 0);
        }
        ok = st >= 0 && outputLen == inputLen;
    }
cleanup:
    if (keyHandle) BCryptDestroyKey(keyHandle);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

// TRANSPORT_KEY: restored here (2026-08-22) after being mistakenly removed
// as presumed dead code - it was NOT dead code. Nutricula_ProtectPayloadGcm/
// UnprotectPayloadGcm below are actively called by the Installer
// (MachineIdService.cs -> CryptoService.cs) to encrypt the ENTIRE POST
// payload (not just machine_id) sent to nutricula_computer_based_signup.php
// and nutricula_computer_based_signup_transfer.php, and to decrypt the
// server's response. Removing these broke license activation/transfer via
// the Installer. Lesson: before removing an export, checking only the C++
// side (MachineIdBridge.cpp) was insufficient - the C# Installer side
// (MachineIdService.cs) also links against this DLL's exports and was not
// checked at the time.
//
// Per the Keys/ folder architecture: the value now comes from
// ../Keys/TransportKey.txt via #include, not a hardcoded array - must
// match TransportKeyPrivate.h's value (used by the Coordinator) and
// license_config.php's transport_key_hex (used by the server) byte-for-
// byte, since all three independently encrypt/decrypt against the same
// value.
static const unsigned char TRANSPORT_KEY[32] = {
#include "../LicenseCheck/TransportKey_Generated.h"
};

static bool GcmProtect(const std::vector<unsigned char>& plaintext, std::string& envelope) {
    unsigned char nonce[GCM_NONCE_BYTES] = {};
    unsigned char tag[GCM_TAG_BYTES] = {};
    if (!RandomBytes(nonce, sizeof(nonce))) return false;
    std::vector<unsigned char> ciphertext(plaintext.size());
    if (!GcmCrypt(TRANSPORT_KEY, nonce, plaintext.data(), (ULONG)plaintext.size(), ciphertext.data(), tag, true)) return false;

    std::vector<unsigned char> packed;
    packed.reserve(sizeof(nonce) + sizeof(tag) + ciphertext.size());
    packed.insert(packed.end(), nonce, nonce + sizeof(nonce));
    packed.insert(packed.end(), tag, tag + sizeof(tag));
    packed.insert(packed.end(), ciphertext.begin(), ciphertext.end());

    std::string b64;
    if (!Base64Encode(packed, b64)) return false;
    envelope = "N3:" + b64;
    return true;
}

static bool GcmUnprotect(const std::string& envelope, std::vector<unsigned char>& plaintext) {
    if (envelope.size() < 4 || envelope.compare(0, 3, "N3:") != 0) return false;
    std::vector<unsigned char> packed;
    if (!Base64Decode(envelope.substr(3), packed)) return false;
    if (packed.size() < GCM_NONCE_BYTES + GCM_TAG_BYTES) return false;

    const unsigned char* nonce = packed.data();
    const unsigned char* tag = packed.data() + GCM_NONCE_BYTES;
    const unsigned char* ciphertext = packed.data() + GCM_NONCE_BYTES + GCM_TAG_BYTES;
    ULONG cipherLen = (ULONG)(packed.size() - GCM_NONCE_BYTES - GCM_TAG_BYTES);
    plaintext.resize(cipherLen);
    std::vector<unsigned char> tagCopy(tag, tag + GCM_TAG_BYTES);
    bool ok = GcmCrypt(TRANSPORT_KEY, nonce, ciphertext, cipherLen, plaintext.data(), tagCopy.data(), false);
    if (!ok) plaintext.clear();
    return ok;
}

static bool ProtectWithDpapi(const std::vector<unsigned char>& plain, std::vector<unsigned char>& wrapped) {
    DATA_BLOB in = { (DWORD)plain.size(), const_cast<BYTE*>(plain.data()) };
    DATA_BLOB out = { 0, nullptr };
    if (!CryptProtectData(&in, L"Nutricula Device Key", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) return false;
    wrapped.assign(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return true;
}

static bool UnprotectWithDpapi(const std::vector<unsigned char>& wrapped, std::vector<unsigned char>& plain) {
    DATA_BLOB in = { (DWORD)wrapped.size(), const_cast<BYTE*>(wrapped.data()) };
    DATA_BLOB out = { 0, nullptr };
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) return false;
    plain.assign(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return true;
}

static bool DeriveWineWrapKey(unsigned char key[32]) {
    std::wstring homeW = GetWineHomeDirWindowsPath();
    std::string home = ToUtf8(homeW);
    std::string user = GetEnvA("USER");
    if (user.empty()) user = GetEnvA("USERNAME");
    if (home.empty()) return false;
    std::string material = "Nutricula/WineDeviceKey/V3|" + home + "|" + user;
    std::vector<unsigned char> digest;
    if (!Sha256String(material, digest) || digest.size() != 32) return false;
    std::memcpy(key, digest.data(), 32);
    return true;
}

static bool SaveDeviceKeyBlob(const std::vector<unsigned char>& privateBlob) {
    std::lock_guard<std::mutex> lock(g_keyMutex);
    std::wstring path = GetDeviceKeyPath();
    if (path.empty()) return false;
    size_t slash = path.find_last_of(L'\\');
    if (slash == std::wstring::npos) return false;
    std::wstring dir = path.substr(0, slash);
    CreateDirectoryW(dir.c_str(), nullptr);

    BYTE mode = IsWine() ? KEY_MODE_PORTABLE : KEY_MODE_DPAPI;
    std::vector<unsigned char> wrapped;
    unsigned char nonce[GCM_NONCE_BYTES] = {};
    unsigned char tag[GCM_TAG_BYTES] = {};

    if (mode == KEY_MODE_DPAPI && !ProtectWithDpapi(privateBlob, wrapped)) {
        mode = KEY_MODE_PORTABLE;
    }

    if (mode == KEY_MODE_PORTABLE) {
        unsigned char wrapKey[32] = {};
        if (!DeriveWineWrapKey(wrapKey) || !RandomBytes(nonce, sizeof(nonce))) return false;
        wrapped.resize(privateBlob.size());
        if (!GcmCrypt(wrapKey, nonce, privateBlob.data(), (ULONG)privateBlob.size(), wrapped.data(), tag, true)) return false;
        SecureZeroMemory(wrapKey, sizeof(wrapKey));
    }

    std::wstring temp = path + L".tmp";
    HANDLE h = CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    char magic[] = "NUTDKEY3";
    DWORD wrappedLen = (DWORD)wrapped.size();
    bool ok = WriteFile(h, magic, 8, &written, nullptr) && written == 8;
    BYTE header[4] = { KEY_VERSION, mode, 0, 0 };
    if (ok) ok = WriteFile(h, header, 4, &written, nullptr) && written == 4;
    if (ok) ok = WriteFile(h, nonce, sizeof(nonce), &written, nullptr) && written == sizeof(nonce);
    if (ok) ok = WriteFile(h, tag, sizeof(tag), &written, nullptr) && written == sizeof(tag);
    if (ok) ok = WriteFile(h, &wrappedLen, sizeof(wrappedLen), &written, nullptr) && written == sizeof(wrappedLen);
    if (ok && wrappedLen) ok = WriteFile(h, wrapped.data(), wrappedLen, &written, nullptr) && written == wrappedLen;
    CloseHandle(h);
    if (!ok) { DeleteFileW(temp.c_str()); return false; }
    DeleteFileW(path.c_str());
    return MoveFileW(temp.c_str(), path.c_str()) != 0;
}

static bool LoadDeviceKeyBlob(std::vector<unsigned char>& privateBlob) {
    std::lock_guard<std::mutex> lock(g_keyMutex);
    std::wstring path = GetDeviceKeyPath();
    if (path.empty()) return false;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD read = 0;
    char magic[8] = {};
    BYTE header[4] = {};
    BYTE nonce[GCM_NONCE_BYTES] = {};
    BYTE tag[GCM_TAG_BYTES] = {};
    DWORD wrappedLen = 0;
    bool ok = ReadFile(h, magic, 8, &read, nullptr) && read == 8 && std::memcmp(magic, "NUTDKEY3", 8) == 0;
    if (ok) ok = ReadFile(h, header, 4, &read, nullptr) && read == 4 && header[0] == KEY_VERSION;
    if (ok) ok = ReadFile(h, nonce, sizeof(nonce), &read, nullptr) && read == sizeof(nonce);
    if (ok) ok = ReadFile(h, tag, sizeof(tag), &read, nullptr) && read == sizeof(tag);
    if (ok) ok = ReadFile(h, &wrappedLen, sizeof(wrappedLen), &read, nullptr) && read == sizeof(wrappedLen) && wrappedLen > 0 && wrappedLen < 65536;
    std::vector<unsigned char> wrapped(wrappedLen);
    if (ok) ok = ReadFile(h, wrapped.data(), wrappedLen, &read, nullptr) && read == wrappedLen;
    CloseHandle(h);
    if (!ok) return false;

    if (header[1] == KEY_MODE_DPAPI) return UnprotectWithDpapi(wrapped, privateBlob);
    if (header[1] == KEY_MODE_PORTABLE) {
        unsigned char wrapKey[32] = {};
        if (!DeriveWineWrapKey(wrapKey)) return false;
        privateBlob.resize(wrapped.size());
        bool result = GcmCrypt(wrapKey, nonce, wrapped.data(), wrappedLen, privateBlob.data(), tag, false);
        SecureZeroMemory(wrapKey, sizeof(wrapKey));
        if (!result) privateBlob.clear();
        return result;
    }
    return false;
}

static bool CreateOrLoadDeviceKey(BCRYPT_KEY_HANDLE& keyHandle) {
    std::vector<unsigned char> privateBlob;
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) < 0) return false;

    bool ok = false;
    if (LoadDeviceKeyBlob(privateBlob)) {
        if (BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPRIVATE_BLOB, &keyHandle,
                                privateBlob.data(), (ULONG)privateBlob.size(), 0) >= 0) ok = true;
    } else {
        BCRYPT_KEY_HANDLE generated = nullptr;
        if (BCryptGenerateKeyPair(alg, &generated, 256, 0) >= 0 &&
            BCryptFinalizeKeyPair(generated, 0) >= 0) {
            DWORD size = 0, result = 0;
            if (BCryptExportKey(generated, nullptr, BCRYPT_ECCPRIVATE_BLOB, nullptr, 0, &size, 0) >= 0) {
                privateBlob.resize(size);
                if (BCryptExportKey(generated, nullptr, BCRYPT_ECCPRIVATE_BLOB, privateBlob.data(), size, &result, 0) >= 0 &&
                    SaveDeviceKeyBlob(privateBlob)) {
                    keyHandle = generated;
                    ok = true;
                }
            }
            if (!ok && generated) BCryptDestroyKey(generated);
        }
    }

    SecureZeroMemory(privateBlob.data(), privateBlob.size());
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

static bool ExportPublicKeyRaw(std::vector<unsigned char>& raw) {
    BCRYPT_KEY_HANDLE key = nullptr;
    if (!CreateOrLoadDeviceKey(key)) return false;
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) < 0) {
        BCryptDestroyKey(key); return false;
    }
    DWORD size = 0, result = 0;
    bool ok = false;
    if (BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &size, 0) >= 0) {
        std::vector<unsigned char> blob(size);
        if (BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB, blob.data(), size, &result, 0) >= 0 &&
            size >= sizeof(BCRYPT_ECCKEY_BLOB) + 64) {
            const BCRYPT_ECCKEY_BLOB* hdr = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(blob.data());
            if (hdr->cbKey == 32) {
                raw.assign(blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB), blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB) + 64);
                ok = true;
            }
        }
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    BCryptDestroyKey(key);
    return ok;
}

static IdentityRecord CollectIdentity(bool* wmiOk) {
    IdentityRecord r;
    if (wmiOk) *wmiOk = false;
    ComInitGuard com;
    if (!com.ok()) return r;
    WmiReader wmi;
    if (!wmi.Initialize()) return r;
    if (wmiOk) *wmiOk = true;

    r.systemUuid = MakeSignal(L"SYSTEM_UUID", wmi.QueryFirst(L"Win32_ComputerSystemProduct", L"UUID"));
    r.systemSerial = MakeSignal(L"SYSTEM_SERIAL", wmi.QueryFirst(L"Win32_ComputerSystemProduct", L"IdentifyingNumber"));
    r.baseboardSerial = MakeSignal(L"BASEBOARD_SERIAL", wmi.QueryFirst(L"Win32_BaseBoard", L"SerialNumber"));
    r.biosSerial = MakeSignal(L"BIOS_SERIAL", wmi.QueryFirst(L"Win32_BIOS", L"SerialNumber"));
    r.cpuId = MakeSignal(L"CPU_ID", wmi.QueryFirst(L"Win32_Processor", L"ProcessorId"));
    r.diskSerial = MakeSignal(L"DISK_SERIAL", wmi.QuerySystemDiskSerial());
    r.machineGuid = MakeSignal(L"MACHINE_GUID", ReadMachineGuid());
    // MAC_ADDRESS removed - see field declaration comment above.
    r.manufacturer = MakeSignal(L"MANUFACTURER", wmi.QueryFirst(L"Win32_ComputerSystemProduct", L"Vendor"));
    r.family = MakeSignal(L"FAMILY", wmi.QueryFirst(L"Win32_ComputerSystem", L"SystemFamily"));
    r.product = MakeSignal(L"PRODUCT", wmi.QueryFirst(L"Win32_ComputerSystemProduct", L"Name"));
    r.sku = MakeSignal(L"SKU", wmi.QueryFirst(L"Win32_ComputerSystem", L"SystemSKUNumber"));

    // IMPORTANT FIX: this used to fold hostname/username/local-IP directly
    // into the identity hash for VMs, making machine_id UNSTABLE (it
    // changed whenever the VM's IP changed - routine on most VPS
    // providers) while providing no real anti-cloning benefit (IP does not
    // prove hardware uniqueness). Replaced with: tag the platform as
    // WindowsVM (so the stricter, multi-signal WindowsVM acceptance rule in
    // HasAtLeastCoreIdentity applies), and attempt a live cloud-provider
    // metadata lookup, which - unlike IP - genuinely cannot be produced by
    // cloning a disk image.
    r.isVirtualMachine = IsVirtualMachine(wmi);
    if (r.isVirtualMachine) {
        r.platform = PlatformKind::WindowsVM;
        CloudMetadataResult cloud = QueryCloudMetadata();
        if (cloud.available) {
            r.cloudInstanceId = MakeSignalUtf8(L"CLOUD_INSTANCE_ID", cloud.provider + ":" + cloud.instanceId);
        }
    }
    return r;
}

} // anonymous namespace

NUTRICULA_API int __cdecl Nutricula_GenerateMachineId(char* output, int outputCapacity) {
    g_lastStatus = 0;
    g_lastPlatformProfile.clear();
    if (!output || outputCapacity < 65) { g_lastStatus = 4; return -1; }
    output[0] = '\0';

    IdentityRecord r;
    bool collected = false;

    // REPLACED: GenerateWineHostMachineId() used to produce a random,
    // file-persisted seed with no connection to real hardware at all - the
    // exact "weak/generic ID" problem being fixed. Now uses real,
    // multi-signal hardware/cloud identity collection specific to the
    // detected host OS, matching the same rigor as the Windows WMI path.
    if (IsWine()) {
        std::string hostOs = DetectWineHostOS();
        if (hostOs == "Darwin") {
            r = CollectMacIdentity(&collected);
        } else if (hostOs == "Linux") {
            r = CollectLinuxIdentity(&collected);
        } else {
            // Host OS could not be determined - no safe platform-specific
            // path to fall back to; treated as insufficient identity data
            // rather than guessing.
            g_lastStatus = 2;
            return -2;
        }
    } else {
        bool wmiOk = false;
        r = CollectIdentity(&wmiOk);
        collected = wmiOk;
        if (!wmiOk) { g_lastStatus = 2; return -2; }
    }

    if (!collected) { g_lastStatus = 2; return -2; }
    if (!HasAtLeastCoreIdentity(r)) { g_lastStatus = 1; return 0; }

    std::wstring canonical = Canonicalize(r);
    std::string utf8 = ToUtf8(canonical);
    if (utf8.empty()) { g_lastStatus = 3; return -2; }

    std::vector<unsigned char> data(utf8.begin(), utf8.end()), digest;
    if (!Sha256Bytes(data, digest) || digest.size() != 32) { g_lastStatus = 3; return -2; }

    static const char* digits = "0123456789ABCDEF";
    for (size_t i = 0; i < digest.size(); ++i) {
        output[i * 2] = digits[(digest[i] >> 4) & 0xF];
        output[i * 2 + 1] = digits[digest[i] & 0xF];
    }
    output[64] = '\0';
    g_lastStatus = 0;

    switch (r.platform) {
        case PlatformKind::WindowsPhysical: g_lastPlatformProfile = "WINDOWS"; break;
        case PlatformKind::WindowsVM:       g_lastPlatformProfile = "WINDOWS_VM"; break;
        case PlatformKind::WineMacOS:       g_lastPlatformProfile = "MACOS_WINE"; break;
        case PlatformKind::WineLinux:       g_lastPlatformProfile = "LINUX_WINE"; break;
    }

    return 1;
}

NUTRICULA_API int __cdecl Nutricula_GetLastStatus() {
    return g_lastStatus;
}

NUTRICULA_API int __cdecl Nutricula_IsWineEnvironment() {
    return IsWine() ? 1 : 0;
}

// Nutricula_ProtectPayloadGcm/UnprotectPayloadGcm - RESTORED 2026-08-22
// after being mistakenly removed as presumed dead code. These ARE actively
// used - by the Installer (MachineIdService.cs's ProtectPayloadGcm/
// UnprotectPayloadGcm, called from CryptoService.cs's BuildPostData/
// DecryptServerResponse) to encrypt the entire signup/transfer POST
// payload sent to nutricula_computer_based_signup.php and
// nutricula_computer_based_signup_transfer.php, and to decrypt those
// endpoints' responses. See GcmProtect/GcmUnprotect above (and
// TRANSPORT_KEY, now read from ../Keys/TransportKey.txt) for the
// underlying implementation.
NUTRICULA_API int __cdecl Nutricula_ProtectPayloadGcm(const char* plaintext, int plaintextLength, char* output, int outputCapacity) {
    if (!plaintext || plaintextLength < 0 || !output || outputCapacity < 4) return -1;
    std::vector<unsigned char> data((const unsigned char*)plaintext, (const unsigned char*)plaintext + plaintextLength);
    std::string envelope;
    if (!GcmProtect(data, envelope)) return 0;
    if ((int)envelope.size() + 1 > outputCapacity) return -1;
    memcpy(output, envelope.data(), envelope.size());
    output[envelope.size()] = '\0';
    return (int)envelope.size();
}

NUTRICULA_API int __cdecl Nutricula_UnprotectPayloadGcm(const char* envelope, int envelopeLength, char* output, int outputCapacity) {
    if (!envelope || envelopeLength <= 0 || !output || outputCapacity < 1) return -1;
    std::string text(envelope, envelope + envelopeLength);
    std::vector<unsigned char> plaintext;
    if (!GcmUnprotect(text, plaintext)) return 0;
    if ((int)plaintext.size() > outputCapacity) return -1;
    if (!plaintext.empty()) memcpy(output, plaintext.data(), plaintext.size());
    return (int)plaintext.size();
}

// Nutricula_GetLastClientIp was REMOVED here - confirmed dead code:
// g_lastClientIp was never assigned anywhere in this file (IP was
// deliberately dropped as a machine_id signal earlier in this project for
// being unstable/unreliable), so this export always returned empty.
// Confirmed unused by MachineIdBridge.cpp/.h before removal.

// Short, generic category label for the most recent Nutricula_GenerateMachineId
// call: "WINDOWS", "WINDOWS_VM", "MACOS_WINE", or "LINUX_WINE" (empty if the
// last call did not succeed). Carries no raw hardware data or IP - safe to
// send to the server for device_type classification and risk scoring
// without needing IP at all.
NUTRICULA_API int __cdecl Nutricula_GetLastPlatformProfile(char* output, int outputCapacity) {
    if (!output || outputCapacity < 1) return -1;
    output[0] = '\0';
    if (g_lastPlatformProfile.empty()) return 0;
    if ((int)g_lastPlatformProfile.size() + 1 > outputCapacity) return -1;
    memcpy(output, g_lastPlatformProfile.data(), g_lastPlatformProfile.size());
    output[g_lastPlatformProfile.size()] = '\0';
    return 1;
}

NUTRICULA_API int __cdecl Nutricula_GetDevicePublicKey(char* output, int outputCapacity) {
    if (!output || outputCapacity < 89) return -1;
    output[0] = '\0';
    std::vector<unsigned char> raw;
    if (!ExportPublicKeyRaw(raw) || raw.size() != 64) return 0;
    std::string b64;
    if (!Base64Encode(raw, b64) || b64.size() + 1 > (size_t)outputCapacity) return -1;
    memcpy(output, b64.data(), b64.size());
    output[b64.size()] = '\0';
    return 1;
}


NUTRICULA_API int __cdecl Nutricula_GetDeviceKeyHash(char* output, int outputCapacity) {
    if (!output || outputCapacity < 65) return -1;
    output[0] = '\0';
    std::vector<unsigned char> raw;
    if (!ExportPublicKeyRaw(raw) || raw.size() != 64) return 0;
    std::vector<unsigned char> digest;
    if (!Sha256Bytes(raw, digest) || digest.size() != 32) return 0;
    static const char* digits = "0123456789ABCDEF";
    for (size_t i = 0; i < digest.size(); ++i) {
        output[i * 2] = digits[(digest[i] >> 4) & 0xF];
        output[i * 2 + 1] = digits[digest[i] & 0xF];
    }
    output[64] = '\0';
    return 1;
}

NUTRICULA_API int __cdecl Nutricula_GetLicensePath(char* output, int outputCapacity) {
    if (!output || outputCapacity < 2) return -1;
    output[0] = '\0';
    std::wstring path;
    if (IsWine()) {
        std::wstring home = GetWineHomeDirWindowsPath();
        if (home.empty()) return 0;
        path = home + L"\\.nutricula\\NutriculaLicense.txt";
    } else {
        std::string appData = GetEnvA("APPDATA");
        if (appData.empty()) return 0;
        path = AnsiToWide(appData) + L"\\MetaQuotes\\Terminal\\Common\\Files\\NutriculaLicense.txt";
    }
    std::string utf8 = ToUtf8(path);
    if (utf8.empty() || (int)utf8.size() + 1 > outputCapacity) return -1;
    memcpy(output, utf8.data(), utf8.size());
    output[utf8.size()] = '\0';
    return 1;
}

NUTRICULA_API int __cdecl Nutricula_SignChallenge(const char* message, int messageLength, char* signatureOutput, int signatureCapacity) {
    if (!message || messageLength < 0 || !signatureOutput || signatureCapacity < 64) return -1;
    std::vector<unsigned char> data(message, message + messageLength), digest;
    if (!Sha256Bytes(data, digest)) return 0;

    BCRYPT_KEY_HANDLE key = nullptr;
    if (!CreateOrLoadDeviceKey(key)) return 0;

    DWORD sigSize = 0, result = 0;
    int rc = 0;
    if (BCryptSignHash(key, nullptr, digest.data(), (ULONG)digest.size(), nullptr, 0, &sigSize, 0) >= 0 && sigSize <= (DWORD)signatureCapacity) {
        if (BCryptSignHash(key, nullptr, digest.data(), (ULONG)digest.size(), reinterpret_cast<PUCHAR>(signatureOutput), (ULONG)signatureCapacity, &result, 0) >= 0) rc = (int)result;
    }
    BCryptDestroyKey(key);
    return rc > 0 ? rc : 0;
}

// NOTE: Nutricula_ProtectPayloadGcm/UnprotectPayloadGcm (and their
// TRANSPORT_KEY-based implementation) were REMOVED here as part of the
// Coordinator architecture migration - these exports let this DLL directly
// encrypt/decrypt payloads for the server using TRANSPORT_KEY, from a
// design where the DLL itself talked to license_check.php. In the current
// architecture, ALL server-facing encryption happens exclusively inside
// LicenseProtocol.cpp on the Coordinator (Service/Broker) side - this
// MachineId DLL never needs to encrypt anything for the server itself.
// Keeping TRANSPORT_KEY hardcoded here would have meant it shipped inside
// a DLL installed directly into every customer's MQL4/MQL5 Libraries
// folder, which defeats the entire point of having moved that secret out
// of client-distributed binaries in the first place (architecture point 77).
