#pragma once

namespace tray {

inline constexpr wchar_t kServiceName[] = L"TrayAppService";
inline constexpr wchar_t kServiceDisplayName[] = L"Tray App Service";
inline constexpr wchar_t kServiceProcessName[] = L"tray-service.exe";
inline constexpr wchar_t kTrayAppProcessName[] = L"tray-app.exe";
inline constexpr wchar_t kRpcEndpoint[] = L"TrayAppServiceRpc";
inline constexpr wchar_t kSingleInstanceMutexName[] = L"Local\\TrayAppSingleInstanceMutex";
inline constexpr wchar_t kHiddenArgument[] = L"--hidden";
inline constexpr wchar_t kServiceLaunchArgument[] = L"--service-launch";
inline constexpr wchar_t kLoginUrl[] = L"https://localhost:8443/api/v1/auth/login";
inline constexpr wchar_t kRefreshUrl[] = L"https://localhost:8443/api/v1/auth/refresh";
inline constexpr wchar_t kLicenseStatusUrl[] = L"https://localhost:8443/api/v1/license/status";
inline constexpr wchar_t kLicenseActivateUrl[] = L"https://localhost:8443/api/v1/license/activate";

}  // namespace tray
