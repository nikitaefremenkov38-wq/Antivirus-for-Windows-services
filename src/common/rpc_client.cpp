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

}  // namespace tray
