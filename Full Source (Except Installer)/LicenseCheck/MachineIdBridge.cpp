#include "MachineIdBridge.h"
#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <cstring>
#pragma comment(lib, "crypt32.lib")

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
    typedef int (__cdecl* GenerateMachineIdWithGuidFn)(char* output, int outputCapacity);
    typedef int (__cdecl* GetDevicePublicKeyFn)(char* output, int outputCapacity);
    typedef int (__cdecl* GetDeviceKeyHashFn)(char* output, int outputCapacity);
    // BUG FIX: Nutricula_GetLicensePath's real, confirmed signature (see
    // NutriculaMachineId.h) is (char* output, int outputCapacity) - a UTF-8
    // byte buffer, exactly like every other export here, NOT (wchar_t*,
    // int). GetProcAddress resolves by name only; it cannot catch a
    // signature mismatch, so this previously compiled and linked "fine"
    // while silently corrupting every license file path computed at
    // runtime (a wchar_t buffer's raw bytes reinterpreted as if they were
    // already UTF-16, when the callee actually wrote UTF-8 into them).
    typedef int (__cdecl* GetLicensePathFn)(char* output, int outputCapacity);
    // BUG FIX: Nutricula_SignChallenge's real, confirmed signature takes an
    // explicit messageLength parameter (message is treated as a raw byte
    // buffer, not assumed NUL-terminated) - the bridge's typedef was
    // missing this 2nd parameter entirely. Every call previously shifted
    // every subsequent argument one slot early: what should have been the
    // signature output buffer pointer was read as messageLength (an int),
    // and what should have been outputCapacity was read as the
    // signatureOutput pointer - i.e. the real function would have
    // attempted to write the signature through a pointer value that was
    // actually meant to be the capacity integer.
    typedef int (__cdecl* SignChallengeFn)(const char* message, int messageLength, char* outputSignatureB64, int outputCapacity);
    typedef int (__cdecl* IsWineEnvironmentFn)();

    HMODULE g_module = nullptr;
    GenerateMachineIdFn g_generateMachineId = nullptr;
    GenerateMachineIdWithGuidFn g_generateMachineIdWithGuid = nullptr;
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
    g_generateMachineIdWithGuid = reinterpret_cast<GenerateMachineIdWithGuidFn>(GetProcAddress(g_module, "Nutricula_GenerateMachineIdWithGuid"));
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

// Secondary machine_id variant (2026 hardening) - see
// Nutricula_GenerateMachineIdWithGuid's own comment in
// NutriculaMachineId.cpp. Falls back to the primary variant's own value if
// the export isn't found at all (an older MachineId DLL predating this
// feature) - callers then simply send the same value twice, which the
// server already treats as "no secondary variant available", exactly the
// same as it does for every non-Windows-physical client today.
bool MachineIdBridge::GenerateMachineIdWithGuid(std::string& outMachineIdHex)
{
    if (!g_generateMachineIdWithGuid) return GenerateMachineId(outMachineIdHex);
    std::vector<char> buffer(MACHINE_ID_CAPACITY, 0);
    int result = g_generateMachineIdWithGuid(buffer.data(), MACHINE_ID_CAPACITY);
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
    std::vector<char> buffer(LICENSE_PATH_CAPACITY_CHARS, 0);
    int result = g_getLicensePath(buffer.data(), LICENSE_PATH_CAPACITY_CHARS);
    if (result != 1) return false;
    buffer[LICENSE_PATH_CAPACITY_CHARS - 1] = '\0';
    // The callee writes UTF-8 bytes (see Nutricula_GetLicensePath's own
    // ToUtf8() call) - convert properly rather than widening byte-for-byte.
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, buffer.data(), -1, nullptr, 0);
    if (wideLen <= 0) return false;
    std::vector<wchar_t> wideBuffer(wideLen);
    if (MultiByteToWideChar(CP_UTF8, 0, buffer.data(), -1, wideBuffer.data(), wideLen) <= 0) return false;
    outPath.assign(wideBuffer.data());
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
    std::vector<char> rawSigBuffer(SIGNATURE_CAPACITY, 0);
    // BUG FIX: Nutricula_SignChallenge's real, confirmed implementation
    // returns the actual byte length of the raw ECDSA signature it wrote
    // (64 for P-256 - see its own "return rc > 0 ? rc : 0" and the
    // BCryptSignHash call above it) on success, and 0/negative on failure -
    // NOT a simple boolean 1. The previous "result != 1" check here meant
    // this always evaluated as failure (result was always 64, never
    // exactly 1), so no Challenge could ever be signed and no verify could
    // ever succeed past this point, on any license, ever.
    int rawSigLen = g_signChallenge(message.data(), static_cast<int>(message.size()), rawSigBuffer.data(), SIGNATURE_CAPACITY);
    if (rawSigLen <= 0) return false;

    // BUG FIX (second, related): the buffer the callee writes into holds
    // RAW signature bytes (arbitrary binary, not NUL-terminated, not
    // already Base64 - see the same BCryptSignHash call), but this was
    // previously being assigned directly into outSignatureB64 as if it
    // were already a Base64 C-string. The server's "signature" field
    // expects Base64 (see CoordinatorCore.cpp sending it directly as
    // verifyFields["signature"]), so encode it here.
    DWORD b64Len = 0;
    if (!CryptBinaryToStringA(reinterpret_cast<const BYTE*>(rawSigBuffer.data()), static_cast<DWORD>(rawSigLen),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &b64Len)) return false;
    std::vector<char> b64Buffer(b64Len);
    if (!CryptBinaryToStringA(reinterpret_cast<const BYTE*>(rawSigBuffer.data()), static_cast<DWORD>(rawSigLen),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64Buffer.data(), &b64Len)) return false;
    outSignatureB64.assign(b64Buffer.data(), strnlen(b64Buffer.data(), b64Len));
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
