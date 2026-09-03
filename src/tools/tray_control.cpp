#include <windows.h>

#include "../common/rpc_client.h"
#include "../common/service_config.h"

#include <string>

namespace {

bool QueryServiceState(SC_HANDLE service, DWORD* state) {
    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)) {
        return false;
    }
    *state = status.dwCurrentState;
    return true;
}

bool WaitForServiceState(DWORD targetState, DWORD timeoutMs) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm == nullptr) {
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, tray::kServiceName, SERVICE_QUERY_STATUS);
    if (service == nullptr) {
        CloseServiceHandle(scm);
        return targetState == SERVICE_STOPPED;
    }

    const DWORD startTick = GetTickCount();
    DWORD currentState = SERVICE_STOPPED;
    while (true) {
        if (!QueryServiceState(service, &currentState)) {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return false;
        }

        if (currentState == targetState) {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return true;
        }

        if (GetTickCount() - startTick >= timeoutMs) {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return false;
        }

        Sleep(250);
    }
}

int StopServiceCommand() {
    if (!tray::RequestServiceStop()) {
        return 1;
    }
    return WaitForServiceState(SERVICE_STOPPED, 15000) ? 0 : 2;
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
    if (argc >= 2 && lstrcmpiW(argv[1], L"--stop-service") == 0) {
        return StopServiceCommand();
    }

    MessageBoxW(nullptr,
                L"Usage:\n  tray-control.exe --stop-service",
                L"Tray Control",
                MB_ICONINFORMATION | MB_OK);
    return 64;
}
