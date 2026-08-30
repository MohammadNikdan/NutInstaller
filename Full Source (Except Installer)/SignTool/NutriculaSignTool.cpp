//
// NutriculaSignTool.cpp - offline build-signing tool (architecture point
// 32/117). Run ONLY on the secure build machine, never distributed to
// customers, never committed anywhere the DLL/Service/Broker are built
// from (it links VendorIdentityPrivate.h, which must never ship).
//
// Usage:
//   NutriculaSignTool.exe <build_id> <version> <protocol_version> \
//       <path_to_ex5> <path_to_ex4> <path_to_dll32> <path_to_dll64> \
//       <path_to_service32> <path_to_service64> \
//       <path_to_broker32> <path_to_broker64> \
//       <output_manifest_path>
//
// Produces manifest.txt in the exact field=value\n... + signature=<base64>
// format ManifestVerify.cpp expects. Both architectures of Service/Broker
// are hashed and included in one manifest, since a single build/release
// genuinely ships both 32-bit and 64-bit Coordinator binaries now (32-bit
// Windows hosts are a real, supported case) - the Installer picks which
// one to actually install based on the CUSTOMER's OS bitness, and whichever
// one gets installed must be independently verifiable against its own
// hash, not a hash for the other architecture.
//

#include "../Coordinator/ManifestVerify.h"
#include "../Coordinator/VendorIdentityPrivate.h"
#include "../Coordinator/EcdsaHelpers.h"

#include <windows.h>
#include <wincrypt.h>
#include <cstdio>
#include <string>
#include <sstream>

#pragma comment(lib, "crypt32.lib")

namespace {

std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

std::string Base64Encode(const unsigned char* data, size_t len)
{
    DWORD outLen = 0;
    CryptBinaryToStringA(data, (DWORD)len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &outLen);
    std::string out(outLen, '\0');
    CryptBinaryToStringA(data, (DWORD)len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &out[0], &outLen);
    while (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 13)
    {
        printf("Usage: %s <build_id> <version> <protocol_version> "
            "<ex5_path> <ex4_path> <dll32_path> <dll64_path> "
            "<service32_path> <service64_path> <broker32_path> <broker64_path> "
            "<output_manifest_path>\n", argv[0]);
        return 1;
    }

    std::string buildId = argv[1], version = argv[2], protocolVersion = argv[3];
    std::wstring ex5Path = Utf8ToWide(argv[4]);
    std::wstring ex4Path = Utf8ToWide(argv[5]);
    std::wstring dll32Path = Utf8ToWide(argv[6]);
    std::wstring dll64Path = Utf8ToWide(argv[7]);
    std::wstring service32Path = Utf8ToWide(argv[8]);
    std::wstring service64Path = Utf8ToWide(argv[9]);
    std::wstring broker32Path = Utf8ToWide(argv[10]);
    std::wstring broker64Path = Utf8ToWide(argv[11]);
    std::wstring outPath = Utf8ToWide(argv[12]);

    std::string ex5Hash = ManifestVerify::HashFileSha256(ex5Path);
    std::string ex4Hash = ManifestVerify::HashFileSha256(ex4Path);
    std::string dll32Hash = ManifestVerify::HashFileSha256(dll32Path);
    std::string dll64Hash = ManifestVerify::HashFileSha256(dll64Path);
    std::string service32Hash = ManifestVerify::HashFileSha256(service32Path);
    std::string service64Hash = ManifestVerify::HashFileSha256(service64Path);
    std::string broker32Hash = ManifestVerify::HashFileSha256(broker32Path);
    std::string broker64Hash = ManifestVerify::HashFileSha256(broker64Path);

    if (ex5Hash.empty() || ex4Hash.empty() || dll32Hash.empty() || dll64Hash.empty() ||
        service32Hash.empty() || service64Hash.empty() || broker32Hash.empty() || broker64Hash.empty())
    {
        printf("ERROR: failed to hash one or more artifacts - check the paths given.\n");
        printf("  ex5=%s ex4=%s dll32=%s dll64=%s service32=%s service64=%s broker32=%s broker64=%s\n",
            ex5Hash.empty() ? "FAILED" : "ok", ex4Hash.empty() ? "FAILED" : "ok",
            dll32Hash.empty() ? "FAILED" : "ok", dll64Hash.empty() ? "FAILED" : "ok",
            service32Hash.empty() ? "FAILED" : "ok", service64Hash.empty() ? "FAILED" : "ok",
            broker32Hash.empty() ? "FAILED" : "ok", broker64Hash.empty() ? "FAILED" : "ok");
        return 1;
    }

    std::ostringstream ss;
    ss << "build_id=" << buildId << "\n";
    ss << "version=" << version << "\n";
    ss << "protocol_version=" << protocolVersion << "\n";
    ss << "ex5_sha256=" << ex5Hash << "\n";
    ss << "ex4_sha256=" << ex4Hash << "\n";
    ss << "dll32_sha256=" << dll32Hash << "\n";
    ss << "dll64_sha256=" << dll64Hash << "\n";
    ss << "service32_sha256=" << service32Hash << "\n";
    ss << "service64_sha256=" << service64Hash << "\n";
    ss << "broker32_sha256=" << broker32Hash << "\n";
    ss << "broker64_sha256=" << broker64Hash << "\n";
    std::string signedPortion = ss.str();

    unsigned char signature[64];
    bool signOk = EcdsaHelpers::SignP256(
        VendorIdentity::PrivateKeyD(), VendorIdentity::PrivateKeyPublicXY(),
        reinterpret_cast<const unsigned char*>(signedPortion.data()), signedPortion.size(),
        signature);
    if (!signOk)
    {
        printf("ERROR: signing failed.\n");
        return 1;
    }

    std::string fullManifest = signedPortion + "signature=" + Base64Encode(signature, 64) + "\n";

    HANDLE h = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        printf("ERROR: could not write output manifest.\n");
        return 1;
    }
    DWORD written = 0;
    WriteFile(h, fullManifest.data(), (DWORD)fullManifest.size(), &written, nullptr);
    CloseHandle(h);

    printf("Manifest written successfully:\n%s", fullManifest.c_str());
    return 0;
}
