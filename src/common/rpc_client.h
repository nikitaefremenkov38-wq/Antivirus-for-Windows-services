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

struct RemoteAvBasesInfo {
    bool loaded{false};
    uint64_t releaseDateUnix{};
    uint32_t recordCount{};
};

struct RemoteScanResult {
    bool malicious{false};
    uint32_t scannedObjects{};
    uint32_t maliciousObjects{};
    uint32_t failedObjects{};
    std::wstring details;
};

struct RemoteScanProgress {
    bool running{false};
    bool hasResult{false};
    uint32_t totalObjects{};
    uint32_t completedObjects{};
    uint32_t maliciousObjects{};
    uint32_t failedObjects{};
    std::wstring currentPath;
    std::wstring details;
};

struct RemoteScheduleInfo {
    bool enabled{false};
    uint32_t intervalMinutes{};
    uint64_t nextRunUnix{};
};

bool RequestServiceStop();
bool GetRemoteUserInfo(RemoteUserInfo* info);
bool LoginRemoteUser(const std::wstring& userName, const std::wstring& password);
bool LogoutRemoteUser();
bool GetRemoteLicenseInfo(RemoteLicenseInfo* info, bool* noLicense = nullptr);
bool ActivateRemoteProduct(const std::wstring& activationCode);
bool GetRemoteAvBasesInfo(RemoteAvBasesInfo* info);
bool ScanRemoteFile(const std::wstring& path, RemoteScanResult* result);
bool ScanRemoteDirectory(const std::wstring& path, RemoteScanResult* result);
bool ScanRemoteFixedDrives(RemoteScanResult* result);
bool StartRemoteDirectoryScan(const std::wstring& path, unsigned long* rpcStatus = nullptr);
bool StartRemoteFixedDrivesScan(unsigned long* rpcStatus = nullptr);
bool GetRemoteScanProgress(RemoteScanProgress* info, unsigned long* rpcStatus = nullptr);
bool SetRemoteScheduledScan(bool enabled, uint32_t intervalMinutes);
bool GetRemoteScheduledScan(RemoteScheduleInfo* info);
bool AddRemoteMonitorDirectory(const std::wstring& path);
bool ClearRemoteMonitorDirectories();
bool GetRemoteMonitorDirectories(std::wstring* directories);

}  // namespace tray
