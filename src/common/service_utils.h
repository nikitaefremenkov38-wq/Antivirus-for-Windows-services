#pragma once

#include <windows.h>

#include <string>

namespace tray {

enum class ServiceBootResult {
    kRunningAlready,
    kStartedOrWaited,
    kFailed,
};

ServiceBootResult EnsureServiceRunning(DWORD timeout_ms);
bool IsParentProcessService();
std::wstring GetExecutableDirectory();

}  // namespace tray
