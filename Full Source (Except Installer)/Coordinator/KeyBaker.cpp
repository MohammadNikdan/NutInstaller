//
// KeyBaker.cpp - build-time tool that reads GENUINE, unmodified PEM key
// files from Keys/ and generates the small "_Generated.h" header files
// that the rest of the codebase #includes. This is the mechanism that
// lets you drop the exact PEM file openssl produces directly into Keys/
// - no manual byte-array or quoted-string conversion by hand, ever.
//
// Run this ONCE before every build (already wired into every build_*.bat
// as the first step) - it regenerates the *_Generated.h files from
// whatever is currently in Keys/*.pem.
//
// Usage: KeyBaker.exe <path-to-Keys-folder>
//
// For each of the 5 keys, reads Keys/<Name>.pem and writes
// <OutputPath>/<Name>_Generated.h containing:
//   inline const char* <VarName> =
//   "-----BEGIN ...-----\n"
//   "<base64 line>\n"
//   ...
//   ;
//
// If a .pem file is EMPTY (the security convention this project uses:
// sensitive private key files are kept empty except during an actual
// build), KeyBaker reports a clear error naming exactly which file needs
// a value, and the calling batch script stops before ever invoking g++.
//

#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstdio>

namespace {

struct KeySpec {
    const char* pemFileName;      // inside Keys/
    const char* outputRelPath;    // relative to Keys/, where the generated .h goes
    const char* varName;          // C++ variable name to emit
    bool required;                // if the .pem is missing entirely (not just empty), is that an error?
};

// All 5 keys this project uses (Server Signing Key's private half is
// intentionally absent - it never lives in this project at all).
const KeySpec KEYS[] = {
    { "TransportKey.pem",                  "../LicenseCheck/TransportKey_Generated.h",              "LicenseProtocolInternal::TRANSPORT_KEY_HEX_PEM_UNUSED", false },
    { "VendorSigningKey_Public.pem",       "../Coordinator/VendorSigningKey_Public_Generated.h",     "VendorIdentity::PUBLIC_KEY_PEM", true },
    { "VendorSigningKey_Private.pem",      "../Coordinator/VendorSigningKey_Private_Generated.h",    "VendorIdentity::PRIVATE_KEY_PEM", true },
    { "CoordinatorIdentityKey_Public.pem", "../Coordinator/CoordinatorIdentityKey_Public_Generated.h","CoordinatorIdentity::PUBLIC_KEY_PEM", true },
    { "CoordinatorIdentityKey_Private.pem","../Coordinator/CoordinatorIdentityKey_Private_Generated.h","CoordinatorIdentity::PRIVATE_KEY_PEM", true },
    { "ServerLicenseSigningKey_Public.pem","../LicenseCheck/ServerLicenseSigningKey_Public_Generated.h","ServerSignatureVerify::SERVER_PUBLIC_KEY_PEM", true },
};

std::string ReadFile(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Converts raw PEM text into quoted C-string literal lines, exactly what
// the consuming .h files expect via #include inside an initializer.
std::string ToCStringLines(const std::string& text)
{
    std::string out;
    std::istringstream iss(text);
    std::string line;
    while (std::getline(iss, line))
    {
        if (!line.empty() && line.back() == '\r') line.pop_back(); // normalize CRLF
        if (line.empty()) continue;
        out += "\"" + line + "\\n\"\n";
    }
    return out;
}

bool IsEffectivelyEmpty(const std::string& content)
{
    for (char c : content) if (!isspace(static_cast<unsigned char>(c))) return false;
    return true;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("Usage: %s <path-to-Keys-folder>\n", argv[0]);
        return 1;
    }
    std::string keysDir = argv[1];
    if (!keysDir.empty() && keysDir.back() != '\\' && keysDir.back() != '/') keysDir += "\\";

    bool anyError = false;

    for (const KeySpec& spec : KEYS)
    {
        // TransportKey is handled separately (it's raw hex, not PEM) - skip here.
        if (std::string(spec.pemFileName) == "TransportKey.pem") continue;

        std::string pemPath = keysDir + spec.pemFileName;
        std::string content = ReadFile(pemPath);

        if (content.empty())
        {
            printf("ERROR: %s is missing or could not be read.\n", pemPath.c_str());
            anyError = true;
            continue;
        }
        if (IsEffectivelyEmpty(content))
        {
            printf("ERROR: %s is EMPTY.\n", pemPath.c_str());
            printf("  This key was intentionally emptied for security - restore its real\n");
            printf("  value from your secure storage before building, then empty it again\n");
            printf("  afterward.\n");
            anyError = true;
            continue;
        }
        if (content.find("BEGIN") == std::string::npos)
        {
            printf("ERROR: %s does not look like a PEM file (no BEGIN marker found).\n", pemPath.c_str());
            anyError = true;
            continue;
        }

        std::string outPath = keysDir + spec.outputRelPath;
        std::ofstream out(outPath, std::ios::binary);
        if (!out)
        {
            printf("ERROR: could not write %s\n", outPath.c_str());
            anyError = true;
            continue;
        }
        out << "// AUTO-GENERATED by KeyBaker.exe from " << spec.pemFileName << " - do not edit by hand.\n";
        out << ToCStringLines(content);
        out.close();
        printf("OK: %s -> %s\n", spec.pemFileName, spec.outputRelPath);
    }

    // TransportKey: raw hex text file (not PEM), converted to a comma-
    // separated byte-array initializer directly - no PEM parsing needed
    // for a symmetric key.
    {
        std::string hexPath = keysDir + "TransportKey.txt";
        std::string hexContent = ReadFile(hexPath);
        std::string cleanHex;
        for (char c : hexContent) if (isxdigit(static_cast<unsigned char>(c))) cleanHex.push_back(c);

        if (cleanHex.empty())
        {
            printf("ERROR: %sTransportKey.txt is missing or empty.\n", keysDir.c_str());
            printf("  Restore its real 64-hex-character value before building.\n");
            anyError = true;
        }
        else if (cleanHex.size() != 64)
        {
            printf("ERROR: %sTransportKey.txt does not contain exactly 32 bytes (64 hex chars).\n", keysDir.c_str());
            anyError = true;
        }
        else
        {
            std::string outPath = keysDir + "../LicenseCheck/TransportKey_Generated.h";
            std::ofstream out(outPath, std::ios::binary);
            out << "// AUTO-GENERATED by KeyBaker.exe from TransportKey.txt - do not edit by hand.\n";
            for (size_t i = 0; i < 64; i += 2)
            {
                out << "0x" << (char)toupper(cleanHex[i]) << (char)toupper(cleanHex[i+1]) << ",";
                if ((i / 2 + 1) % 16 == 0) out << "\n"; else out << " ";
            }
            out << "\n";
            printf("OK: TransportKey.txt -> ../LicenseCheck/TransportKey_Generated.h\n");
        }
    }

    if (anyError)
    {
        printf("\nKeyBaker FAILED - one or more keys need attention before building. See errors above.\n");
        return 1;
    }
    printf("\nKeyBaker: all keys baked successfully.\n");
    return 0;
}
