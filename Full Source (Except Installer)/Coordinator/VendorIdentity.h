#pragma once
//
// VendorIdentity.h - the Vendor Build Signing PUBLIC key, ECDSA P-256.
// Used only to verify the Manifest (architecture points 31-38).
//
// MIGRATED FROM P-384 TO P-256 (2026) - see EcdsaHelpers.h for the full
// reasoning (confirmed Wine BCryptImportKeyPair failure for P-384 private
// keys). This is the PUBLIC half only, so it was never the failing side,
// but both halves of a keypair must obviously use the same curve.
//
// The actual key comes from Keys/VendorSigningKey_Public.pem - a GENUINE,
// unmodified PEM file exactly as `openssl ec -pubout` produces it.
// KeyBaker.exe (run automatically as the first step of every build_*.bat)
// reads that file and generates VendorSigningKey_Public_Generated.h,
// which this file #includes. To rotate this key: just replace the .pem
// file in Keys/ - no manual conversion, ever.
//
// This key's matching PRIVATE key lives ONLY on the secure build machine
// (see VendorIdentityPrivate.h, and NutriculaSignTool which links it).
//

#include "EcdsaPemParser.h"

namespace VendorIdentity {

inline const char* PUBLIC_KEY_PEM =
#include "VendorSigningKey_Public_Generated.h"
;

inline const unsigned char* PublicKeyXY()
{
    static unsigned char xy[64];
    static bool parsed = EcdsaPemParser::ParseSpkiPublicKeyPem(PUBLIC_KEY_PEM, xy);
    (void)parsed; // if this ever fails, xy stays zeroed and every signature check against it will simply fail closed - never silently "pass"
    return xy;
}

} // namespace VendorIdentity
