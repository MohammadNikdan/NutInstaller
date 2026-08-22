#include "ManifestVerify.h"
#include "VendorIdentity.h"
#include "EcdsaHelpers.h"

#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <sstream>

#pragma comment(lib, "crypt32.lib")

namespace ManifestVerify {

namespace {

std::string ReadFileUtf8(const std::wstring& path)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return "";
    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size) || size.QuadPart <= 0 || size.QuadPart > 1024 * 1024)
    {
        CloseHandle(h);
        return ""; // a manifest larger than 1MB is not something we ever produce - reject rather than allocate unboundedly
    }
    std::vector<char> buf(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    bool ok = ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()), &read, nullptr) != 0;
    CloseHandle(h);
    if (!ok || read != buf.size()) return "";
    return std::string(buf.data(), buf.size());
}

std::map<std::string, std::string> ParseLines(const std::string& text)
{
    std::map<std::string, std::string> fields;
    std::istringstream ss(text);
    std::string line;
    while (std::getline(ss, line))
    {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        fields[line.substr(0, eq)] = line.substr(eq + 1);
    }
    return fields;
}

bool Base64Decode(const std::string& b64, std::vector<unsigned char>& out)
{
    DWORD outLen = 0;
    if (!CryptStringToBinaryA(b64.c_str(), static_cast<DWORD>(b64.size()),
        CRYPT_STRING_BASE64, nullptr, &outLen, nullptr, nullptr)) return false;
    out.resize(outLen);
    return CryptStringToBinaryA(b64.c_str(), static_cast<DWORD>(b64.size()),
        CRYPT_STRING_BASE64, out.data(), &outLen, nullptr, nullptr) != 0;
}

} // anonymous namespace

std::string HashFileSha256(const std::wstring& path)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return "";

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) { CloseHandle(h); return ""; }
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) >= 0;

    // Stream in chunks (architecture point 30: full-file hash is fine since
    // it only runs once per refresh cycle, ~54 minutes apart - but still
    // read in bounded chunks rather than loading an arbitrarily large file
    // fully into memory at once).
    char buf[65536];
    DWORD read = 0;
    while (ok && ReadFile(h, buf, sizeof(buf), &read, nullptr) && read > 0)
    {
        ok = BCryptHashData(hash, reinterpret_cast<PUCHAR>(buf), read, 0) >= 0;
    }

    unsigned char digest[32];
    if (ok) ok = BCryptFinishHash(hash, digest, sizeof(digest), 0) >= 0;

    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(h);
    if (!ok) return "";

    static const char* hexDigits = "0123456789abcdef";
    std::string hex(64, '0');
    for (int i = 0; i < 32; i++)
    {
        hex[i * 2] = hexDigits[(digest[i] >> 4) & 0xF];
        hex[i * 2 + 1] = hexDigits[digest[i] & 0xF];
    }
    return hex;
}

ManifestData LoadAndVerifyManifest(const std::wstring& directory)
{
    ManifestData result;

    std::wstring path = directory;
    if (!path.empty() && path.back() != L'\\') path += L'\\';
    path += L"manifest.txt";

    std::string content = ReadFileUtf8(path);
    if (content.empty()) return result; // invalid - missing/unreadable manifest

    // Format written by NutriculaSignTool: all fields, one per line, THEN a
    // final "signature=<base64>" line. The signature covers every byte
    // before that final line (including its own trailing newline) - never
    // signs itself.
    size_t sigLinePos = content.rfind("\nsignature=");
    if (sigLinePos == std::string::npos) return result;

    std::string signedPortion = content.substr(0, sigLinePos + 1); // include the trailing \n before "signature="
    std::string sigLine = content.substr(sigLinePos + 1);
    if (sigLine.compare(0, 10, "signature=") != 0) return result;
    std::string signatureB64 = sigLine.substr(10);
    while (!signatureB64.empty() && (signatureB64.back() == '\n' || signatureB64.back() == '\r')) signatureB64.pop_back();

    std::vector<unsigned char> signatureBytes;
    if (!Base64Decode(signatureB64, signatureBytes) || signatureBytes.size() != 96) return result;

    if (!EcdsaHelpers::VerifyP384(VendorIdentity::PublicKeyXY(),
        reinterpret_cast<const unsigned char*>(signedPortion.data()), signedPortion.size(),
        signatureBytes.data()))
    {
        return result; // signature genuinely does not verify - reject, do not partially trust any field
    }

    auto fields = ParseLines(signedPortion);
    if (!fields.count("build_id") || !fields.count("version") || !fields.count("protocol_version") ||
        !fields.count("ex5_sha256") || !fields.count("ex4_sha256") || !fields.count("dll32_sha256") ||
        !fields.count("dll64_sha256") || !fields.count("service32_sha256") || !fields.count("service64_sha256") ||
        !fields.count("broker32_sha256") || !fields.count("broker64_sha256"))
    {
        return result; // signature verified but the manifest is incomplete - still not trusted
    }

    result.buildId = fields["build_id"];
    result.version = fields["version"];
    result.protocolVersion = fields["protocol_version"];
    result.ex5Sha256 = fields["ex5_sha256"];
    result.ex4Sha256 = fields["ex4_sha256"];
    result.dll32Sha256 = fields["dll32_sha256"];
    result.dll64Sha256 = fields["dll64_sha256"];
    result.service32Sha256 = fields["service32_sha256"];
    result.service64Sha256 = fields["service64_sha256"];
    result.broker32Sha256 = fields["broker32_sha256"];
    result.broker64Sha256 = fields["broker64_sha256"];
    result.valid = true;
    return result;
}

bool VerifyArtifactsMatchManifest(const ManifestData& manifest, const std::wstring& artifactDirectory,
    const std::wstring& ex5FileName, const std::wstring& ex4FileName,
    const std::wstring& dll32FileName, const std::wstring& dll64FileName,
    const std::wstring& serviceFileName, const std::string& expectedServiceSha256,
    const std::wstring& brokerFileName, const std::string& expectedBrokerSha256)
{
    if (!manifest.valid) return false;

    std::wstring dir = artifactDirectory;
    if (!dir.empty() && dir.back() != L'\\') dir += L'\\';

    struct Check { const std::wstring& fileName; const std::string& expected; };
    Check checks[] = {
        { ex5FileName, manifest.ex5Sha256 },
        { ex4FileName, manifest.ex4Sha256 },
        { dll32FileName, manifest.dll32Sha256 },
        { dll64FileName, manifest.dll64Sha256 },
        { serviceFileName, expectedServiceSha256 },
        { brokerFileName, expectedBrokerSha256 },
    };

    for (const Check& c : checks)
    {
        if (c.fileName.empty()) continue; // caller may skip a slot it doesn't care about verifying right now
        std::string actual = HashFileSha256(dir + c.fileName);
        // A missing/unreadable file (actual=="") never silently passes -
        // deliberately compared as a plain (guaranteed-mismatching) string,
        // not treated as "skip this check".
        if (actual.empty() || actual != c.expected) return false;
    }
    return true;
}

} // namespace ManifestVerify
