#pragma once
//
// CoordinatorIdentity.h - the Coordinator's public identity key, ECDSA
// P-256. Compiled directly into every client DLL AND every Coordinator
// (Service/Broker) binary.
//
// The actual key comes from Keys/CoordinatorIdentityKey_Public.pem - a
// GENUINE, unmodified PEM file exactly as `openssl ec -pubout` produces
// it. KeyBaker.exe generates CoordinatorIdentityKey_Public_Generated.h
// from it automatically as the first step of every build_*.bat.
//
// This key's ONLY purpose is the IPC handshake (see CoordinatorProtocol.h).
// Matching private key: CoordinatorIdentityPrivate.h.
//

// MIGRATED FROM P-384 TO P-256 (2026) - see EcdsaHelpers.h.

#include "EcdsaPemParser.h"

namespace CoordinatorIdentity {

inline const char* PUBLIC_KEY_PEM =
#include "CoordinatorIdentityKey_Public_Generated.h"
;

inline const unsigned char* PublicKeyXY()
{
    static unsigned char xy[64];
    static bool parsed = EcdsaPemParser::ParseSpkiPublicKeyPem(PUBLIC_KEY_PEM, xy);
    (void)parsed;
    return xy;
}

} // namespace CoordinatorIdentity
