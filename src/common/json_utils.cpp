#include "json_utils.h"

#include <windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <cctype>
#include <vector>

namespace tray {
namespace {

size_t SkipWhitespace(std::string_view text, size_t position) {
    while (position < text.size() && (text[position] == ' ' || text[position] == '\n' || text[position] == '\r' || text[position] == '\t')) {
        ++position;
    }
    return position;
}

std::optional<size_t> FindJsonKey(std::string_view json, std::string_view key) {
    const std::string pattern = "\"" + std::string(key) + "\"";
    const size_t key_position = json.find(pattern);
    if (key_position == std::string_view::npos) {
        return std::nullopt;
    }

    size_t colon_position = json.find(':', key_position + pattern.size());
    if (colon_position == std::string_view::npos) {
        return std::nullopt;
    }

    return SkipWhitespace(json, colon_position + 1);
}

std::string Base64UrlToBase64(std::string_view input) {
    std::string output(input);
    std::replace(output.begin(), output.end(), '-', '+');
    std::replace(output.begin(), output.end(), '_', '/');
    while ((output.size() % 4) != 0) {
        output.push_back('=');
    }
    return output;
}

std::optional<std::string> DecodeBase64(std::string_view input) {
    DWORD decoded_size = 0;
    const std::string owned(input);
    if (!CryptStringToBinaryA(owned.c_str(), static_cast<DWORD>(owned.size()), CRYPT_STRING_BASE64, nullptr, &decoded_size, nullptr, nullptr)) {
        return std::nullopt;
    }

    std::vector<BYTE> buffer(decoded_size);
    if (!CryptStringToBinaryA(owned.c_str(), static_cast<DWORD>(owned.size()), CRYPT_STRING_BASE64, buffer.data(), &decoded_size, nullptr, nullptr)) {
        return std::nullopt;
    }

    return std::string(reinterpret_cast<char*>(buffer.data()), decoded_size);
}

std::optional<std::string> DecodeJwtPayload(std::string_view token) {
    const size_t first_dot = token.find('.');
    if (first_dot == std::string_view::npos) {
        return std::nullopt;
    }
    const size_t second_dot = token.find('.', first_dot + 1);
    if (second_dot == std::string_view::npos || second_dot <= first_dot + 1) {
        return std::nullopt;
    }

    const std::string base64 = Base64UrlToBase64(token.substr(first_dot + 1, second_dot - first_dot - 1));
    return DecodeBase64(base64);
}

}  // namespace

std::string WideToUtf8(std::wstring_view text) {
    if (text.empty()) {
        return {};
    }

    const int required = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string result(required, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), required, nullptr, nullptr);
    return result;
}

std::wstring Utf8ToWide(std::string_view text) {
    if (text.empty()) {
        return {};
    }

    const int required = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring result(required, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), required);
    return result;
}

std::string EscapeJson(std::string_view text) {
    std::string result;
    result.reserve(text.size() + 8);
    for (char ch : text) {
        switch (ch) {
            case '\\': result += "\\\\"; break;
            case '"': result += "\\\""; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result.push_back(ch); break;
        }
    }
    return result;
}

std::optional<std::string> TryGetJsonString(std::string_view json, std::string_view key) {
    const auto position = FindJsonKey(json, key);
    if (!position || *position >= json.size() || json[*position] != '"') {
        return std::nullopt;
    }

    std::string result;
    for (size_t index = *position + 1; index < json.size(); ++index) {
        const char ch = json[index];
        if (ch == '\\' && index + 1 < json.size()) {
            result.push_back(json[++index]);
            continue;
        }
        if (ch == '"') {
            return result;
        }
        result.push_back(ch);
    }
    return std::nullopt;
}

std::optional<uint64_t> TryGetJsonUint64(std::string_view json, std::string_view key) {
    const auto position = FindJsonKey(json, key);
    if (!position || *position >= json.size()) {
        return std::nullopt;
    }
    size_t end = *position;
    while (end < json.size() && std::isdigit(static_cast<unsigned char>(json[end]))) {
        ++end;
    }
    if (end == *position) {
        return std::nullopt;
    }
    return std::stoull(std::string(json.substr(*position, end - *position)));
}

std::optional<bool> TryGetJsonBool(std::string_view json, std::string_view key) {
    const auto position = FindJsonKey(json, key);
    if (!position) {
        return std::nullopt;
    }
    if (json.substr(*position, 4) == "true") {
        return true;
    }
    if (json.substr(*position, 5) == "false") {
        return false;
    }
    return std::nullopt;
}

std::optional<std::string> TryGetJwtClaimString(std::string_view token, std::string_view key) {
    const auto payload = DecodeJwtPayload(token);
    return payload ? TryGetJsonString(*payload, key) : std::nullopt;
}

std::optional<uint64_t> TryGetJwtClaimUint64(std::string_view token, std::string_view key) {
    const auto payload = DecodeJwtPayload(token);
    return payload ? TryGetJsonUint64(*payload, key) : std::nullopt;
}

}  // namespace tray
