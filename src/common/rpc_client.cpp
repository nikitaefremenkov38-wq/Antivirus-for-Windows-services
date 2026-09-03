#include "rpc_client.h"

#include "service_config.h"
#include "tray_service_rpc.h"

#include <rpc.h>

namespace tray {
namespace {

template <typename Callable>
bool InvokeRpc(const Callable& callable, unsigned long* rpc_status = nullptr) {
    RPC_WSTR string_binding = nullptr;
    RPC_BINDING_HANDLE binding = nullptr;
    unsigned long status = RPC_S_OK;
    bool success = false;

    status = RpcStringBindingComposeW(nullptr, reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")), nullptr, reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)), nullptr, &string_binding);
    if (status != RPC_S_OK) {
        if (rpc_status != nullptr) {
            *rpc_status = status;
        }
        return false;
    }

    status = RpcBindingFromStringBindingW(string_binding, &binding);
    RpcStringFreeW(&string_binding);
    if (status != RPC_S_OK) {
        if (rpc_status != nullptr) {
            *rpc_status = status;
        }
        return false;
    }

    tray_service_binding = binding;
    RpcTryExcept {
        status = callable();
        success = true;
    }
    RpcExcept(1) {
        status = RpcExceptionCode();
        success = false;
    }
    RpcEndExcept

    tray_service_binding = nullptr;
    RpcBindingFree(&binding);

    if (rpc_status != nullptr) {
        *rpc_status = status;
    }
    return success && status == ERROR_SUCCESS;
}

}  // namespace

bool RequestServiceStop() {
    return InvokeRpc([] { return StopService(); });
}

bool GetRemoteUserInfo(RemoteUserInfo* info) {
    if (info == nullptr) {
        return false;
    }

    int authenticated = 0;
    wchar_t user_name[128]{};
    const bool success = InvokeRpc([&] { return GetCurrentUserInfo(&authenticated, user_name, ARRAYSIZE(user_name)); });
    if (!success) {
        return false;
    }

    info->authenticated = authenticated != 0;
    info->userName = user_name;
    return true;
}

bool LoginRemoteUser(const std::wstring& userName, const std::wstring& password) {
    return InvokeRpc([&] { return LoginUser(const_cast<wchar_t*>(userName.c_str()), const_cast<wchar_t*>(password.c_str())); });
}

bool LogoutRemoteUser() {
    return InvokeRpc([] { return LogoutUser(); });
}

bool GetRemoteLicenseInfo(RemoteLicenseInfo* info, bool* noLicense) {
    if (info == nullptr) {
        return false;
    }

    int has_license = 0;
    hyper expires_at = 0;
    unsigned long status = ERROR_SUCCESS;
    const bool success = InvokeRpc([&] { return GetLicenseInfo(&has_license, &expires_at); }, &status);
    if (!success) {
        if (noLicense != nullptr) {
            *noLicense = status == ERROR_NOT_FOUND;
        }
        return false;
    }

    info->hasLicense = has_license != 0;
    info->expiresAtUnix = static_cast<uint64_t>(expires_at);
    if (noLicense != nullptr) {
        *noLicense = false;
    }
    return true;
}

bool ActivateRemoteProduct(const std::wstring& activationCode) {
    return InvokeRpc([&] { return ActivateProduct(const_cast<wchar_t*>(activationCode.c_str())); });
}

bool GetRemoteAvBasesInfo(RemoteAvBasesInfo* info) {
    if (info == nullptr) {
        return false;
    }

    int loaded = 0;
    unsigned long recordCount = 0;
    hyper releaseDate = 0;
    if (!InvokeRpc([&] { return GetAvBasesInfo(&loaded, &releaseDate, &recordCount); })) {
        return false;
    }

    info->loaded = loaded != 0;
    info->releaseDateUnix = static_cast<uint64_t>(releaseDate);
    info->recordCount = static_cast<uint32_t>(recordCount);
    return true;
}

bool ScanRemoteFile(const std::wstring& path, RemoteScanResult* result) {
    if (result == nullptr) {
        return false;
    }

    wchar_t details[4096]{};
    int malicious = 0;
    unsigned long scanned = 0;
    unsigned long bad = 0;
    unsigned long failed = 0;
    if (!InvokeRpc([&] { return ScanFile(const_cast<wchar_t*>(path.c_str()), &malicious, &scanned, &bad, &failed, details, ARRAYSIZE(details)); })) {
        return false;
    }

    result->malicious = malicious != 0;
    result->scannedObjects = scanned;
    result->maliciousObjects = bad;
    result->failedObjects = failed;
    result->details = details;
    return true;
}

bool ScanRemoteDirectory(const std::wstring& path, RemoteScanResult* result) {
    if (result == nullptr) {
        return false;
    }

    wchar_t details[4096]{};
    unsigned long scanned = 0;
    unsigned long bad = 0;
    unsigned long failed = 0;
    if (!InvokeRpc([&] { return ScanDirectory(const_cast<wchar_t*>(path.c_str()), &scanned, &bad, &failed, details, ARRAYSIZE(details)); })) {
        return false;
    }

    result->malicious = bad != 0;
    result->scannedObjects = scanned;
    result->maliciousObjects = bad;
    result->failedObjects = failed;
    result->details = details;
    return true;
}

bool ScanRemoteFixedDrives(RemoteScanResult* result) {
    if (result == nullptr) {
        return false;
    }

    wchar_t details[4096]{};
    unsigned long scanned = 0;
    unsigned long bad = 0;
    unsigned long failed = 0;
    if (!InvokeRpc([&] { return ScanFixedDrives(&scanned, &bad, &failed, details, ARRAYSIZE(details)); })) {
        return false;
    }

    result->malicious = bad != 0;
    result->scannedObjects = scanned;
    result->maliciousObjects = bad;
    result->failedObjects = failed;
    result->details = details;
    return true;
}

bool StartRemoteDirectoryScan(const std::wstring& path, unsigned long* rpcStatus) {
    return InvokeRpc([&] { return StartScanDirectory(const_cast<wchar_t*>(path.c_str())); }, rpcStatus);
}

bool StartRemoteFixedDrivesScan(unsigned long* rpcStatus) {
    return InvokeRpc([] { return StartScanFixedDrives(); }, rpcStatus);
}

bool GetRemoteScanProgress(RemoteScanProgress* info, unsigned long* rpcStatus) {
    if (info == nullptr) {
        return false;
    }

    int running = 0;
    int hasResult = 0;
    unsigned long total = 0;
    unsigned long completed = 0;
    unsigned long bad = 0;
    unsigned long failed = 0;
    wchar_t currentPath[512]{};
    wchar_t details[4096]{};
    if (!InvokeRpc([&] {
            return GetScanProgress(&running, &hasResult, &total, &completed, &bad, &failed,
                                   currentPath, ARRAYSIZE(currentPath), details, ARRAYSIZE(details));
        }, rpcStatus)) {
        return false;
    }

    info->running = running != 0;
    info->hasResult = hasResult != 0;
    info->totalObjects = total;
    info->completedObjects = completed;
    info->maliciousObjects = bad;
    info->failedObjects = failed;
    info->currentPath = currentPath;
    info->details = details;
    return true;
}

bool SetRemoteScheduledScan(bool enabled, uint32_t intervalMinutes) {
    return InvokeRpc([&] { return SetScheduledScan(enabled ? 1 : 0, intervalMinutes); });
}

bool GetRemoteScheduledScan(RemoteScheduleInfo* info) {
    if (info == nullptr) {
        return false;
    }

    int enabled = 0;
    unsigned long interval = 0;
    hyper nextRun = 0;
    if (!InvokeRpc([&] { return GetScheduledScan(&enabled, &interval, &nextRun); })) {
        return false;
    }

    info->enabled = enabled != 0;
    info->intervalMinutes = interval;
    info->nextRunUnix = static_cast<uint64_t>(nextRun);
    return true;
}

bool AddRemoteMonitorDirectory(const std::wstring& path) {
    return InvokeRpc([&] { return AddMonitorDirectory(const_cast<wchar_t*>(path.c_str())); });
}

bool ClearRemoteMonitorDirectories() {
    return InvokeRpc([] { return ClearMonitorDirectories(); });
}

bool GetRemoteMonitorDirectories(std::wstring* directories) {
    if (directories == nullptr) {
        return false;
    }

    wchar_t buffer[4096]{};
    if (!InvokeRpc([&] { return GetMonitorDirectories(buffer, ARRAYSIZE(buffer)); })) {
        return false;
    }
    *directories = buffer;
    return true;
}

}  // namespace tray
