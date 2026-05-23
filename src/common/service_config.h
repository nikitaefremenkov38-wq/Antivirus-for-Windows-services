#pragma once

namespace tray {

inline constexpr wchar_t kServiceName[] = L"TrayAppService";
inline constexpr wchar_t kServiceDisplayName[] = L"Tray App Service";
inline constexpr wchar_t kServiceProcessName[] = L"tray-service.exe";
inline constexpr wchar_t kTrayAppProcessName[] = L"tray-app.exe";
inline constexpr wchar_t kRpcEndpoint[] = L"TrayAppServiceRpc";
inline constexpr wchar_t kSingleInstanceMutexName[] = L"Local\\TrayAppSingleInstanceMutex";
inline constexpr wchar_t kHiddenArgument[] = L"--hidden";

}  // namespace tray
