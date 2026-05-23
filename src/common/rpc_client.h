#pragma once

#include <string>

namespace tray {

struct RemoteUserInfo {
    bool authenticated{false};
    std::wstring userName;
};

struct RemoteLicenseInfo {
    bool hasLicense{false};
    uint64_t expiresAtUnix{};
};

bool RequestServiceStop();
bool GetRemoteUserInfo(RemoteUserInfo* info);
bool LoginRemoteUser(const std::wstring& userName, const std::wstring& password);
bool LogoutRemoteUser();
bool GetRemoteLicenseInfo(RemoteLicenseInfo* info, bool* noLicense = nullptr);
bool ActivateRemoteProduct(const std::wstring& activationCode);

}  // namespace tray
