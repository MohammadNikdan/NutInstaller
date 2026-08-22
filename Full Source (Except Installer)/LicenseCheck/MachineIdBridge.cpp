#include "MachineIdBridge.h"
#include <windows.h>
#include <vector>
#include <cstring>

//
// ASSUMPTIONS ON THE NEIGHBOR DLL'S EXACT SIGNATURES - PLEASE VERIFY
// --------------------------------------------------------------------
// Per the project's own established convention (matching
// Nutricula_GenerateMachineId's confirmed signature: __cdecl, a char*
// output buffer + an int capacity, returning 1 on success), the other
// exports are assumed to follow the identical (buffer, capacity) -> int
// pattern. This bridge is explicitly temporary (per your instruction, this
// logic moves into this same DLL later), so getting a buffer-size constant
// slightly wrong here is a one-file fix, not a structural problem - but
// please double check these exact signatures against the actual DLL header
// before relying on this in production, since I'm working from this
// project's established convention rather than the literal current header
// file (which I don't have in front of me right now).
//
namespace
{
    typedef int (__cdecl* GenerateMachineIdFn)(char* output, int outputCapacity);
    typedef int (__cdecl* GetDevicePublicKeyFn)(char* output, int outputCapacity);
    typedef int (__cdecl* GetDeviceKeyHashFn)(char* output, int outputCapacity);
    typedef int (__cdecl* GetLicensePathFn)(wchar_t* output, int outputCapacityChars);
    typedef int (__cdecl* SignChallengeFn)(const char* message, char* outputSignatureB64, int outputCapacity);
    typedef int (__cdecl* IsWineEnvironmentFn)();

    HMODULE g_module = nullptr;
    GenerateMachineIdFn g_generateMachineId = nullptr;
    GetDevicePublicKeyFn g_getDevicePublicKey = nullptr;
    GetDeviceKeyHashFn g_getDeviceKeyHash = nullptr;
    GetLicensePathFn g_getLicensePath = nullptr;
    SignChallengeFn g_signChallenge = nullptr;
    IsWineEnvironmentFn g_isWineEnvironment = nullptr;

    const int MACHINE_ID_CAPACITY = 65;   // 64 hex chars + NUL
    const int PUBLIC_KEY_CAPACITY = 128;  // Base64 of 64 raw bytes (~88 chars) + margin
    const int KEY_HASH_CAPACITY = 65;     // 64 hex chars + NUL
    const int SIGNATURE_CAPACITY = 128;   // Base64 of 64 raw bytes (~88 chars) + margin
    const int LICENSE_PATH_CAPACITY_CHARS = 1024;
}

bool MachineIdBridge::Load(const std::wstring& dllDirectory)
{
    if (g_module) return true; // already loaded

    std::wstring path = dllDirectory;
    if (!path.empty() && path.back() != L'\\') path += L'\\';
#if defined(_WIN64)
    path += L"MachineId64.dll";
#else
    path += L"MachineId32.dll";
#endif

    g_module = LoadLibraryW(path.c_str());
    if (!g_module) return false;

    g_generateMachineId = reinterpret_cast<GenerateMachineIdFn>(GetProcAddress(g_module, "Nutricula_GenerateMachineId"));
    g_getDevicePublicKey = reinterpret_cast<GetDevicePublicKeyFn>(GetProcAddress(g_module, "Nutricula_GetDevicePublicKey"));
    g_getDeviceKeyHash = reinterpret_cast<GetDeviceKeyHashFn>(GetProcAddress(g_module, "Nutricula_GetDeviceKeyHash"));
    g_getLicensePath = reinterpret_cast<GetLicensePathFn>(GetProcAddress(g_module, "Nutricula_GetLicensePath"));
    g_signChallenge = reinterpret_cast<SignChallengeFn>(GetProcAddress(g_module, "Nutricula_SignChallenge"));
    g_isWineEnvironment = reinterpret_cast<IsWineEnvironmentFn>(GetProcAddress(g_module, "Nutricula_IsWineEnvironment"));

    bool allFound = g_generateMachineId && g_getDevicePublicKey && g_getDeviceKeyHash &&
        g_getLicensePath && g_signChallenge && g_isWineEnvironment;

    if (!allFound)
    {
        FreeLibrary(g_module);
        g_module = nullptr;
        return false;
    }
    return true;
}

bool MachineIdBridge::GenerateMachineId(std::string& outMachineIdHex)
{
    if (!g_generateMachineId) return false;
    std::vector<char> buffer(MACHINE_ID_CAPACITY, 0);
    int result = g_generateMachineId(buffer.data(), MACHINE_ID_CAPACITY);
    if (result != 1) return false;
    buffer[MACHINE_ID_CAPACITY - 1] = '\0';
    outMachineIdHex.assign(buffer.data());
    return outMachineIdHex.size() == 64;
}

bool MachineIdBridge::GetDevicePublicKeyB64(std::string& outPublicKeyB64)
{
    if (!g_getDevicePublicKey) return false;
    std::vector<char> buffer(PUBLIC_KEY_CAPACITY, 0);
    int result = g_getDevicePublicKey(buffer.data(), PUBLIC_KEY_CAPACITY);
    if (result != 1) return false;
    buffer[PUBLIC_KEY_CAPACITY - 1] = '\0';
    outPublicKeyB64.assign(buffer.data());
    return !outPublicKeyB64.empty();
}

bool MachineIdBridge::GetDeviceKeyHash(std::string& outHashHex)
{
    if (!g_getDeviceKeyHash) return false;
    std::vector<char> buffer(KEY_HASH_CAPACITY, 0);
    int result = g_getDeviceKeyHash(buffer.data(), KEY_HASH_CAPACITY);
    if (result != 1) return false;
    buffer[KEY_HASH_CAPACITY - 1] = '\0';
    outHashHex.assign(buffer.data());
    return outHashHex.size() == 64;
}

bool MachineIdBridge::GetLicenseFilePath(std::wstring& outPath)
{
    if (!g_getLicensePath) return false;
    std::vector<wchar_t> buffer(LICENSE_PATH_CAPACITY_CHARS, 0);
    int result = g_getLicensePath(buffer.data(), LICENSE_PATH_CAPACITY_CHARS);
    if (result != 1) return false;
    buffer[LICENSE_PATH_CAPACITY_CHARS - 1] = L'\0';
    outPath.assign(buffer.data());
    return !outPath.empty();
}

bool MachineIdBridge::IsWineEnvironment()
{
    if (!g_isWineEnvironment) return false;
    return g_isWineEnvironment() == 1;
}

bool MachineIdBridge::SignChallenge(const std::string& message, std::string& outSignatureB64)
{
    if (!g_signChallenge) return false;
    std::vector<char> buffer(SIGNATURE_CAPACITY, 0);
    int result = g_signChallenge(message.c_str(), buffer.data(), SIGNATURE_CAPACITY);
    if (result != 1) return false;
    buffer[SIGNATURE_CAPACITY - 1] = '\0';
    outSignatureB64.assign(buffer.data());
    return !outSignatureB64.empty();
}

void MachineIdBridge::Unload()
{
    if (g_module)
    {
        FreeLibrary(g_module);
        g_module = nullptr;
        g_generateMachineId = nullptr;
        g_getDevicePublicKey = nullptr;
        g_getDeviceKeyHash = nullptr;
        g_getLicensePath = nullptr;
        g_signChallenge = nullptr;
        g_isWineEnvironment = nullptr;
    }
}
