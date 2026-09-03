#include "http_client.h"

#include <windows.h>
#include <winhttp.h>

namespace tray {
namespace {

struct WinHttpHandle {
    HINTERNET handle{};
    ~WinHttpHandle() {
        if (handle != nullptr) {
            WinHttpCloseHandle(handle);
        }
    }
};

}  // namespace

bool SendJsonHttpsRequest(const std::wstring& method, const std::wstring& url, const std::string& body, const std::wstring& bearerToken, HttpResponse* response) {
    URL_COMPONENTS components{};
    components.dwStructSize = sizeof(components);

    wchar_t host_name[256]{};
    wchar_t url_path[1024]{};
    components.lpszHostName = host_name;
    components.dwHostNameLength = ARRAYSIZE(host_name);
    components.lpszUrlPath = url_path;
    components.dwUrlPathLength = ARRAYSIZE(url_path);

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &components)) {
        return false;
    }

    WinHttpHandle session{WinHttpOpen(L"TrayApp/3.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)};
    if (session.handle == nullptr) {
        return false;
    }

    WinHttpHandle connection{WinHttpConnect(session.handle, std::wstring(components.lpszHostName, components.dwHostNameLength).c_str(), components.nPort, 0)};
    if (connection.handle == nullptr) {
        return false;
    }

    const DWORD flags = components.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    WinHttpHandle request{WinHttpOpenRequest(connection.handle, method.c_str(), std::wstring(components.lpszUrlPath, components.dwUrlPathLength).c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags)};
    if (request.handle == nullptr) {
        return false;
    }

    const std::wstring host(components.lpszHostName, components.dwHostNameLength);
    if (components.nScheme == INTERNET_SCHEME_HTTPS &&
        (_wcsicmp(host.c_str(), L"localhost") == 0 || _wcsicmp(host.c_str(), L"127.0.0.1") == 0)) {
        DWORD security_flags =
            SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(request.handle, WINHTTP_OPTION_SECURITY_FLAGS, &security_flags, sizeof(security_flags));
    }

    std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    if (!bearerToken.empty()) {
        headers += L"Authorization: Bearer ";
        headers += bearerToken;
        headers += L"\r\n";
    }

    if (!WinHttpSendRequest(request.handle, headers.c_str(), static_cast<DWORD>(headers.size()), body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()), static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0)) {
        return false;
    }
    if (!WinHttpReceiveResponse(request.handle, nullptr)) {
        return false;
    }

    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    if (!WinHttpQueryHeaders(request.handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_size, WINHTTP_NO_HEADER_INDEX)) {
        return false;
    }

    std::string response_body;
    while (true) {
        DWORD bytes_available = 0;
        if (!WinHttpQueryDataAvailable(request.handle, &bytes_available)) {
            return false;
        }
        if (bytes_available == 0) {
            break;
        }

        std::string chunk(bytes_available, '\0');
        DWORD bytes_read = 0;
        if (!WinHttpReadData(request.handle, chunk.data(), bytes_available, &bytes_read)) {
            return false;
        }
        chunk.resize(bytes_read);
        response_body += chunk;
    }

    if (response != nullptr) {
        response->statusCode = status_code;
        response->body = std::move(response_body);
    }
    return true;
}

}  // namespace tray
