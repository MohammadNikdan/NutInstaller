#include "Transport.h"
#include <windows.h>
#include <winhttp.h>
#include <vector>

#pragma comment(lib, "winhttp.lib")

namespace
{
    std::string UrlEncodeAscii(const std::string& s)
    {
        static const char* hex = "0123456789ABCDEF";
        std::string out;
        out.reserve(s.size() * 3);
        for (unsigned char c : s)
        {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
                out.push_back(static_cast<char>(c));
            else
            {
                out.push_back('%');
                out.push_back(hex[(c >> 4) & 0xF]);
                out.push_back(hex[c & 0xF]);
            }
        }
        return out;
    }
}

TransportResponse Transport::PostEnvelope(
    const std::wstring& host,
    const std::wstring& urlPath,
    const std::string& envelope,
    DWORD timeoutMs)
{
    TransportResponse response;

    HINTERNET session = WinHttpOpen(
        L"NutriculaLicenseCheck/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) { response.result = TransportResult::ConnectionFailed; return response; }

    WinHttpSetTimeouts(session, static_cast<int>(timeoutMs), static_cast<int>(timeoutMs),
        static_cast<int>(timeoutMs), static_cast<int>(timeoutMs));

    HINTERNET connect = WinHttpConnect(session, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!connect)
    {
        WinHttpCloseHandle(session);
        response.result = TransportResult::ConnectionFailed;
        return response;
    }

    HINTERNET request = WinHttpOpenRequest(
        connect, L"POST", urlPath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!request)
    {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        response.result = TransportResult::ConnectionFailed;
        return response;
    }

    // Enforce modern TLS only.
    DWORD tlsFlags = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
#ifdef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
    tlsFlags |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
#endif
    WinHttpSetOption(request, WINHTTP_OPTION_SECURE_PROTOCOLS, &tlsFlags, sizeof(tlsFlags));

    std::string postBody = "data=" + UrlEncodeAscii(envelope);
    const wchar_t* headers = L"Content-Type: application/x-www-form-urlencoded\r\n";

    BOOL sent = WinHttpSendRequest(
        request, headers, static_cast<DWORD>(-1),
        const_cast<char*>(postBody.data()), static_cast<DWORD>(postBody.size()),
        static_cast<DWORD>(postBody.size()), 0);

    bool ok = sent && WinHttpReceiveResponse(request, nullptr);

    if (ok)
    {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        WinHttpQueryHeaders(request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
        response.httpStatusCode = static_cast<int>(statusCode);

        if (statusCode == 200)
        {
            std::string body;
            DWORD available = 0;
            while (WinHttpQueryDataAvailable(request, &available) && available > 0)
            {
                std::vector<char> buffer(available);
                DWORD read = 0;
                if (!WinHttpReadData(request, buffer.data(), available, &read)) break;
                body.append(buffer.data(), read);
                // Bound the response size - a licensing endpoint has no
                // legitimate reason to return more than a few KB.
                if (body.size() > 65536) break;
            }

            if (body.empty())
            {
                response.result = TransportResult::EmptyResponse;
            }
            else
            {
                response.result = TransportResult::Ok;
                response.body = body;
            }
        }
        else
        {
            response.result = TransportResult::HttpError;
        }
    }
    else
    {
        response.result = TransportResult::ConnectionFailed;
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return response;
}
