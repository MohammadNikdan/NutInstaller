#pragma once
//
// MachineIdBridge.h - Temporary bridge to the existing, separate Machine
// ID DLL (MachineId32.dll / its 64-bit counterpart), per your explicit
// instruction: for now it sits next to this DLL; later its logic moves
// directly into this DLL and this bridge goes away. Isolating it behind
// this one header means that merge, when it happens, only touches this
// file plus whichever CMake/build-script wiring names the DLL.
//
// Exported names assumed to match the existing DLL exactly (verified
// earlier in this project, cdecl, undecorated):
//   Nutricula_GenerateMachineId
//   Nutricula_GetDevicePublicKey
//   Nutricula_GetDeviceKeyHash
//   Nutricula_SignChallenge
//   Nutricula_GetLicensePath
//   Nutricula_IsWineEnvironment
// If the actual exported names/signatures differ, only this file needs to
// change - nothing else in this DLL references the neighbor DLL directly.
//

#include <string>

class MachineIdBridge
{
public:
    // Loads the neighboring DLL (same directory as this DLL). Must succeed
    // before any other method here is called. Returns false if the DLL or
    // any required export is missing - callers must treat that as a hard
    // failure of the whole license check, not proceed with defaults.
    static bool Load(const std::wstring& dllDirectory);

    static bool GenerateMachineId(std::string& outMachineIdHex);
    static bool GenerateMachineIdWithGuid(std::string& outMachineIdHex);
    static bool GetDevicePublicKeyB64(std::string& outPublicKeyB64);
    static bool GetDeviceKeyHash(std::string& outHashHex);
    static bool GetLicenseFilePath(std::wstring& outPath);
    static bool IsWineEnvironment();

    // message is the exact UTF-8 canonical string to sign (e.g.
    // "NUTRICULA-RUNTIME-V3|challenge_id=...|nonce=...|license_id=...|
    // machine_id=..."). outSignatureB64 receives the Base64 of the raw
    // 64-byte r||s ECDSA signature, matching exactly what
    // nutricula_verify_device_signature() on the server expects.
    static bool SignChallenge(const std::string& message, std::string& outSignatureB64);

    static void Unload();
};
