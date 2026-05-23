#include "service_utils.h"

#include "service_config.h"

#include <tlhelp32.h>
#include <winsvc.h>

namespace tray {
namespace {

bool QueryServiceState(SC_HANDLE service, DWORD* state) {
    SERVICE_STATUS_PROCESS status{};
    DWORD bytes_needed = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytes_needed)) {
        return false;
    }
    *state = status.dwCurrentState;
    return true;
}

bool WaitForServiceState(SC_HANDLE service, DWORD target_state, DWORD timeout_ms) {
    const DWORD start_tick = GetTickCount();
    DWORD current_state = SERVICE_STOPPED;
    while (true) {
        if (!QueryServiceState(service, &current_state)) {
            return false;
        }
        if (current_state == target_state) {
            return true;
        }
        if (GetTickCount() - start_tick >= timeout_ms) {
            return false;
        }
        Sleep(250);
    }
}

std::wstring GetProcessBaseName(DWORD process_id) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id);
    if (process == nullptr) {
        return {};
    }

    std::wstring path(MAX_PATH, L'\0');
    DWORD size = static_cast<DWORD>(path.size());
    if (!QueryFullProcessImageNameW(process, 0, path.data(), &size)) {
        CloseHandle(process);
        return {};
    }

    CloseHandle(process);
    path.resize(size);
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

DWORD GetParentProcessId() {
    const DWORD current_process_id = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        return 0;
    }

    DWORD parent_process_id = 0;
    do {
        if (entry.th32ProcessID == current_process_id) {
            parent_process_id = entry.th32ParentProcessID;
            break;
        }
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return parent_process_id;
}

}  // namespace

ServiceBootResult EnsureServiceRunning(DWORD timeout_ms) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm == nullptr) {
        return ServiceBootResult::kFailed;
    }

    SC_HANDLE service = OpenServiceW(scm, kServiceName, SERVICE_QUERY_STATUS);
    if (service == nullptr) {
        CloseServiceHandle(scm);
        return ServiceBootResult::kFailed;
    }

    DWORD state = SERVICE_STOPPED;
    if (!QueryServiceState(service, &state)) {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return ServiceBootResult::kFailed;
    }

    ServiceBootResult result = ServiceBootResult::kFailed;
    if (state == SERVICE_RUNNING) {
        result = ServiceBootResult::kRunningAlready;
    } else {
        CloseServiceHandle(service);
        service = OpenServiceW(scm, kServiceName, SERVICE_QUERY_STATUS | SERVICE_START);
        if (service == nullptr) {
            CloseServiceHandle(scm);
            return ServiceBootResult::kFailed;
        }

        if (state == SERVICE_STOPPED) {
            StartServiceW(service, 0, nullptr);
        }

        if (WaitForServiceState(service, SERVICE_RUNNING, timeout_ms)) {
            result = ServiceBootResult::kStartedOrWaited;
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return result;
}

bool IsParentProcessService() {
    const DWORD parent_process_id = GetParentProcessId();
    if (parent_process_id == 0) {
        return false;
    }
    const std::wstring parent_name = GetProcessBaseName(parent_process_id);
    return _wcsicmp(parent_name.c_str(), kServiceProcessName) == 0;
}

std::wstring GetExecutableDirectory() {
    std::wstring path(MAX_PATH, L'\0');
    DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    while (length >= path.size() - 1) {
        path.resize(path.size() * 2);
        length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    }

    path.resize(length);
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring() : path.substr(0, slash);
}

}  // namespace tray
