#pragma once
//
// Transport.h - WinHTTP POST to license_check.php. Deliberately minimal:
// this layer only moves bytes. All trust decisions happen in
// LicenseProtocol (decrypt/verify), never here.
//

#include <string>
#include <windows.h>

enum class TransportResult
{
    Ok,                 // HTTP 200 with a non-empty body - body may still
                         // turn out invalid once decrypted/verified, that's
                         // for the caller (via LicenseProtocol) to decide.
    ConnectionFailed,    // DNS/TCP/TLS-level failure, or a timeout
    HttpError,           // Got a response, but not HTTP 200
    EmptyResponse
};

struct TransportResponse
{
    TransportResult result = TransportResult::ConnectionFailed;
    int httpStatusCode = 0;
    std::string body; // the raw "N3:..." envelope, when result == Ok
};

class Transport
{
public:
    // urlPath e.g. L"/login2/license_check.php". postBody is the exact
    // "data=<url-encoded N3 envelope>" content (this function does the
    // final "data=" wrapping + URL-encoding of the envelope itself).
    static TransportResponse PostEnvelope(
        const std::wstring& host,
        const std::wstring& urlPath,
        const std::string& envelope,
        DWORD timeoutMs);
};
