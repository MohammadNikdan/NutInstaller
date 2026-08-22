#pragma once
//
// ServerSignatureVerify.h - the ONE piece of LicenseProtocol logic the thin
// DLL is allowed to link, deliberately split out into its own translation
// unit specifically so TRANSPORT_KEY (which lives in LicenseProtocol.cpp,
// alongside GCM encrypt/decrypt) never ends up compiled into the DLL binary
// at all - not just "unused", genuinely absent from the binary. Matches
// architecture point 77: "این کلید نباید در... DLL... باقی بماند."
//
// Used by:
//   - LicenseProtocol.cpp itself (the Coordinator side) - re-exports these
//     same functions so existing callers there are unaffected.
//   - NutriculaLicenseCheckThin.cpp (the DLL side) - links ONLY this file
//     plus its own IPC code, never LicenseProtocol.cpp/Transport.cpp/
//     MachineIdBridge.cpp.
//

#include <string>

namespace ServerSignatureVerify {

// Loads the RSA public key (PEM, X.509 SubjectPublicKeyInfo) from a file
// next to the caller's own module. Must succeed before Verify() is called.
bool LoadServerPublicKey(const std::wstring& dllDirectory);

// Verifies an RSA-SHA256 signature (base64) over the exact canonical
// message string. Returns false for any malformed input or genuine
// verification failure - never throws, never partially trusts.
bool Verify(const std::string& canonicalMessage, const std::string& signatureB64);

} // namespace ServerSignatureVerify
