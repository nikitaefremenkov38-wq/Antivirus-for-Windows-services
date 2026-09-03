#pragma once

#include <string>
#include <string_view>
#include <optional>

namespace tray {

std::string WideToUtf8(std::wstring_view text);
std::wstring Utf8ToWide(std::string_view text);
std::string EscapeJson(std::string_view text);

std::optional<std::string> TryGetJsonString(std::string_view json, std::string_view key);
std::optional<uint64_t> TryGetJsonUint64(std::string_view json, std::string_view key);
std::optional<bool> TryGetJsonBool(std::string_view json, std::string_view key);

std::optional<std::string> TryGetJwtClaimString(std::string_view token, std::string_view key);
std::optional<uint64_t> TryGetJwtClaimUint64(std::string_view token, std::string_view key);

}  // namespace tray
