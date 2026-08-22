#pragma once

#ifdef NUTRICULA_MACHINE_ID_EXPORTS
#define NUTRICULA_API __declspec(dllexport)
#else
#define NUTRICULA_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

NUTRICULA_API int __cdecl Nutricula_GenerateMachineId(char* output, int outputCapacity);
NUTRICULA_API int __cdecl Nutricula_GetLastStatus();
NUTRICULA_API int __cdecl Nutricula_IsWineEnvironment();
// Nutricula_ProtectPayloadGcm/UnprotectPayloadGcm - RESTORED, actively
// used by the Installer (MachineIdService.cs) - see .cpp for full history.
NUTRICULA_API int __cdecl Nutricula_ProtectPayloadGcm(const char* plaintext, int plaintextLength, char* output, int outputCapacity);
NUTRICULA_API int __cdecl Nutricula_UnprotectPayloadGcm(const char* envelope, int envelopeLength, char* output, int outputCapacity);

/* New: short, generic platform category label ("WINDOWS", "WINDOWS_VM",
   "MACOS_WINE", "LINUX_WINE") for the most recent GenerateMachineId call -
   lets the server classify device_type without needing IP or any raw
   hardware identifiers. */
NUTRICULA_API int __cdecl Nutricula_GetLastPlatformProfile(char* output, int outputCapacity);

/* New security protocol exports. */
NUTRICULA_API int __cdecl Nutricula_GetDevicePublicKey(char* output, int outputCapacity);
NUTRICULA_API int __cdecl Nutricula_GetDeviceKeyHash(char* output, int outputCapacity);
NUTRICULA_API int __cdecl Nutricula_GetLicensePath(char* output, int outputCapacity);
NUTRICULA_API int __cdecl Nutricula_SignChallenge(const char* message, int messageLength, char* signatureOutput, int signatureCapacity);

#ifdef __cplusplus
}
#endif
