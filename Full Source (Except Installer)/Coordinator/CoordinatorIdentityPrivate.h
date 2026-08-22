#pragma once
//
// CoordinatorIdentityPrivate.h - the private counterpart of
// CoordinatorIdentity.h's public key. ECDSA P-384.
//
// !!! MUST NEVER BE INCLUDED IN, OR SHIPPED AS PART OF, THE CLIENT DLL !!!
// Compiled ONLY into NutriculaLicenseService.exe / NutriculaLicenseBroker.exe.
//
// The actual key comes from Keys/CoordinatorIdentityKey_Private.pem - a
// GENUINE, unmodified PEM file exactly as openssl produces it.
// KeyBaker.exe generates CoordinatorIdentityKey_Private_Generated.h from
// it automatically as the first step of every build_Service_*/Broker_*.bat.
//
// SECURITY NOTE ON THIS KEY'S SCOPE: unlike the Vendor Signing Key (never
// leaves the build machine) or the Server Signing Key (never leaves the
// server), THIS private key genuinely does ship inside every customer's
// Coordinator binary, because its whole purpose is proving Coordinator
// identity locally to the DLL on that same machine. If extracted via
// reverse engineering, impact is limited to defense-in-depth only - see
// architecture point 15/101 for why Tier 2 still cannot be forged even
// with this key alone.
//

#include "EcdsaPemParser.h"

namespace CoordinatorIdentity {

inline const char* PRIVATE_KEY_PEM =
#include "CoordinatorIdentityKey_Private_Generated.h"
;

namespace detail {
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

inline const unsigned char* PrivateKeyD() { return detail::Get().d; }
inline const unsigned char* PrivateKeyPublicXY() { return detail::Get().xy; }

} // namespace CoordinatorIdentity
