#pragma once
//
// VendorIdentityPrivate.h - the private counterpart of VendorIdentity.h's
// public key. ECDSA P-384.
//
// !!! MUST NEVER BE COMPILED INTO ANY DISTRIBUTED BINARY !!!
// Used ONLY by NutriculaSignTool.exe, built and run exclusively on a
// secure/offline build machine.
//
// The actual key comes from Keys/VendorSigningKey_Private.pem - a
// GENUINE, unmodified PEM file exactly as openssl produces it.
// KeyBaker.exe (run automatically as the first step of every relevant
// build_*.bat) reads that file and generates
// VendorSigningKey_Private_Generated.h, which this file #includes.
//

#include "EcdsaPemParser.h"

namespace VendorIdentity {

inline const char* PRIVATE_KEY_PEM =
#include "VendorSigningKey_Private_Generated.h"
;

namespace detail {
    // Single shared parsed-key cache - D and its matching public XY are
    // always parsed together, exactly once, from the same SEC1 structure.
    struct ParsedKey { unsigned char d[48]; unsigned char xy[96]; bool ok; };
    inline const ParsedKey& Get()
    {
        static ParsedKey key = [] {
            ParsedKey k{};
            k.ok = EcdsaPemParser::ParseSec1PrivateKeyPem(PRIVATE_KEY_PEM, k.d, k.xy);
            return k;
        }();
        return key;
    }
}

// On parse failure, d/xy stay zeroed - SignP384 will simply fail closed,
// never silently sign with garbage key material.
inline const unsigned char* PrivateKeyD() { return detail::Get().d; }
inline const unsigned char* PrivateKeyPublicXY() { return detail::Get().xy; }

} // namespace VendorIdentity
