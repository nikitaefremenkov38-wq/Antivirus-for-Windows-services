#pragma once

#include <string>

namespace tray {

struct HttpResponse {
    unsigned long statusCode{};
    std::string body;
};

bool SendJsonHttpsRequest(
    const std::wstring& method,
    const std::wstring& url,
    const std::string& body,
    const std::wstring& bearerToken,
    HttpResponse* response
);

}  // namespace tray
