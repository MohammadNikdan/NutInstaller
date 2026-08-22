#pragma once
//
// ServerPublicKeyEmbedded.h - the server's RSA license-signing PUBLIC key,
// compiled directly into the binary - architecture point 78.
//
// The actual key comes from Keys/ServerLicenseSigningKey_Public.pem - a
// GENUINE, unmodified PEM file exactly as it's provided/regenerated.
// KeyBaker.exe generates ServerLicenseSigningKey_Public_Generated.h from
// it automatically as the first step of every build_*.bat.
//
// After any future key rotation, every NutriculaLicenseCheck32/64.dll,
// NutriculaLicenseService.exe, and NutriculaLicenseBroker.exe must be
// rebuilt and redistributed - this is a compile-time constant, not a file
// that can be swapped post-build.
//

namespace ServerSignatureVerify {

inline const char* SERVER_PUBLIC_KEY_PEM =
#include "ServerLicenseSigningKey_Public_Generated.h"
;

} // namespace ServerSignatureVerify
