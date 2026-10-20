#pragma once
//
// ManifestVerify.h - the Vendor-signed EXPECTATIONS (architecture points
// 30-38, 92-96): loads manifest.txt, verifies its signature against the
// compiled-in Vendor public key, and parses the per-artifact SHA-256 values
// it declares. Also offers the file-hashing primitive those comparisons use.
//
// It does not decide anything by itself any more. What gets measured, and
// compared against these expectations, now lives in RuntimeMeasure.h, which
// hashes the running image and the genuinely loaded modules rather than
// copies of them. The rule that produced this split is unchanged
// (architecture point 46/122: "Client نباید بتواند Expected Hash را تعریف
// کند") - a hash a client reports is never allowed to become an
// expectation; expectations only ever come from this signed file and from
// the server's own build registry.
//
// Trust domain: this uses VendorIdentity's public key, a COMPLETELY
// SEPARATE key from the server license-signing key (architecture point 81) -
// compromising one does not automatically compromise the other.
//

#include <string>
#include <map>

namespace ManifestVerify {

struct ManifestData
{
    bool valid = false; // true only if signature verification passed AND all required fields present
    std::string buildId;
    std::string version;
    std::string protocolVersion;
    std::string ex5Sha256;
    std::string ex4Sha256;
    std::string dll32Sha256;
    std::string dll64Sha256;
    // MachineId32.dll / MachineId64.dll - loaded by BOTH the thin License
    // Check DLL and the Coordinator itself (MachineIdBridge). Both always
    // required, both always checked - see the comment on
    // CoordinatorProtocol::ARTIFACT_MACHINEID32_NAME for why.
    std::string machineid32Sha256;
    std::string machineid64Sha256;
    // Both architectures of the Coordinator (the Broker) genuinely ship to
    // customers (32-bit Windows tablets are a real, supported case - see the
    // Installer's OS-bitness-based selection logic) - so each needs its own
    // separately verifiable hash, not one shared value. (The Windows Service
    // host was removed in 2026 - the Broker is the sole Coordinator - so
    // there are no longer any service32/64 hashes.)
    std::string broker32Sha256;  // NutriculaLicenseBroker32.exe
    std::string broker64Sha256;  // NutriculaLicenseBroker64.exe
};

// Loads manifest.json (+ its detached manifest.json.sig, or an inline
// signature= line - see NutriculaSignTool for the exact format written) from
// the given directory, verifies its signature against the compiled-in
// Vendor public key, and parses its fields. Returns valid=false for any
// failure - missing file, bad signature, or incomplete fields - never
// partially trusts a manifest that fails any check.
ManifestData LoadAndVerifyManifest(const std::wstring& directory);

// Computes the SHA-256 of an entire file on disk (architecture point 30:
// full file hash, never random chunk sampling). Returns empty string on
// any read failure - callers must treat that as a failure, never as a skip.
std::string HashFileSha256(const std::wstring& path);

// REMOVED (2026): VerifyArtifactsMatchManifest, which hashed the EX4/EX5/DLL
// copies the Installer had left in the Coordinator's own folder and compared
// those against this manifest. It could never catch the attack it existed
// for - a patched EA or DLL runs from wherever MetaTrader loads it, while
// those private copies stay pristine and keep matching forever. The
// integrity decision now measures the running image and the real loaded
// modules instead; see RuntimeMeasure.h. This header's job is narrower now:
// load and verify the signed manifest (the EXPECTATIONS), and hash a file.

} // namespace ManifestVerify
