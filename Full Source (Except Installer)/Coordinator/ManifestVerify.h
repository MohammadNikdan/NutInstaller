#pragma once
//
// ManifestVerify.h - Coordinator-side artifact integrity verification
// (architecture points 30-38, 92-96). Verifies a Vendor-signed manifest
// file, then hashes the ACTUAL artifacts on disk and compares against the
// manifest's expected values - never trusts a client-reported hash
// (architecture point 46/122: "Client نباید بتواند Expected Hash را
// تعریف کند").
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
    // Both architectures of the Coordinator genuinely ship to customers now
    // (32-bit Windows tablets are a real, supported case - see the
    // Installer's OS-bitness-based selection logic) - so each needs its
    // own separately verifiable hash, not one shared value.
    std::string service32Sha256; // NutriculaLicenseService32.exe
    std::string service64Sha256; // NutriculaLicenseService64.exe
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
// any read failure.
std::string HashFileSha256(const std::wstring& path);

// The actual integrity decision: given a verified manifest and the
// Coordinator's own directory (where it expects to find the EX4/EX5/DLL/
// Service/Broker artifacts alongside itself), measure each actual file and
// compare against the expected hash. Returns true only if EVERY artifact
// whose file name is non-empty is present AND its hash matches exactly.
// Deliberately does NOT special-case "file missing" as a pass - a missing
// artifact that the manifest expected to exist is itself a failure. Pass
// an empty wstring for any file name parameter to skip checking that
// particular artifact this call.
//
// expectedServiceSha256/expectedBrokerSha256 are passed explicitly (not
// read from manifest.service32Sha256/64/broker32Sha256/64 internally)
// because the CALLER must pick which one is correct for ITS OWN
// architecture, via #ifdef _WIN64 at compile time - see CoordinatorCore.cpp.
// A given running Coordinator binary only ever needs to verify the single
// file actually sitting next to it, never the other architecture's file
// (which may not even be present on this machine).
bool VerifyArtifactsMatchManifest(const ManifestData& manifest, const std::wstring& artifactDirectory,
    const std::wstring& ex5FileName, const std::wstring& ex4FileName,
    const std::wstring& dll32FileName, const std::wstring& dll64FileName,
    const std::wstring& serviceFileName, const std::string& expectedServiceSha256,
    const std::wstring& brokerFileName, const std::string& expectedBrokerSha256);

} // namespace ManifestVerify
