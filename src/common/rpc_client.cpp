#include "rpc_client.h"

#include "service_config.h"
#include "tray_service_rpc.h"

#include <rpc.h>

namespace tray {

bool RequestServiceStop() {
    RPC_WSTR string_binding = nullptr;
    RPC_BINDING_HANDLE binding = nullptr;

    const RPC_STATUS compose_status = RpcStringBindingComposeW(
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
        nullptr,
        &string_binding
    );

    if (compose_status != RPC_S_OK) {
        return false;
    }

    const RPC_STATUS binding_status = RpcBindingFromStringBindingW(string_binding, &binding);
    RpcStringFreeW(&string_binding);
    if (binding_status != RPC_S_OK) {
        return false;
    }

    tray_service_binding = binding;
    RPC_STATUS rpc_call_status = RPC_S_OK;
    bool success = false;

    RpcTryExcept {
        success = StopService() == RPC_S_OK;
    }
    RpcExcept(1) {
        rpc_call_status = RpcExceptionCode();
        success = false;
    }
    RpcEndExcept

    tray_service_binding = nullptr;
    RpcBindingFree(&binding);
    return success && rpc_call_status == RPC_S_OK;
}

}  // namespace tray
