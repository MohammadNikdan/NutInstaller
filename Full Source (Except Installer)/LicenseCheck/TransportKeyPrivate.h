#pragma once
//
// TransportKeyPrivate.h - the AES-256-GCM transport key shared between the
// Coordinator (Service/Broker) and license_config.php.
//
// !!! MUST NEVER BE COMMITTED TO ANY GITHUB REPOSITORY, PUBLIC OR PRIVATE !!!
//
// The actual key comes from Keys/TransportKey.txt - just a raw 64-hex-
// character string, EXACTLY what `openssl rand -hex 32` outputs directly
// (no manual formatting needed). KeyBaker.exe (run automatically as the
// first step of every build_Service_*/Broker_*.bat) reads that file and
// generates TransportKey_Generated.h, which this file #includes.
//
// Must also match license_config.php's transport_key_hex on the server -
// a mismatch is a silent, total protocol break.
//

namespace LicenseProtocolInternal {

inline constexpr unsigned char TRANSPORT_KEY[32] = {
#include "TransportKey_Generated.h"
};

} // namespace LicenseProtocolInternal
