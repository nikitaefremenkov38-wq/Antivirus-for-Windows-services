#include <windows.h>

#include "service_config.h"
#include "service_utils.h"
#include "tray_service_rpc.h"

#include <rpc.h>
#include <userenv.h>
#include <wtsapi32.h>

#include <string>
#include <vector>

namespace {

struct LaunchedProcess {
    DWORD session_id{};
    DWORD process_id{};
    HANDLE process_handle{};
};

SERVICE_STATUS_HANDLE g_service_status_handle = nullptr;
SERVICE_STATUS g_service_status{};
std::vector<LaunchedProcess> g_launched_processes;
CRITICAL_SECTION g_process_lock{};
HANDLE g_stop_event = nullptr;
HANDLE g_session_watch_thread = nullptr;

void SetServiceState(DWORD state, DWORD win32_exit_code = NO_ERROR, DWORD wait_hint = 0) {
    g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_service_status.dwCurrentState = state;
    g_service_status.dwWin32ExitCode = win32_exit_code;
    g_service_status.dwWaitHint = wait_hint;
    g_service_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_SESSIONCHANGE : 0;

    static DWORD checkpoint = 1;
    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) {
        g_service_status.dwCheckPoint = checkpoint++;
    } else {
        g_service_status.dwCheckPoint = 0;
        checkpoint = 1;
    }

    SetServiceStatus(g_service_status_handle, &g_service_status);
}

std::wstring BuildTrayAppPath() {
    std::wstring path = tray::GetExecutableDirectory();
    if (!path.empty()) {
        path.append(L"\\");
    }
    path.append(tray::kTrayAppProcessName);
    return path;
}

std::wstring BuildWorkingDirectory() {
    return tray::GetExecutableDirectory();
}

void CleanupDeadProcessesLocked() {
    std::vector<LaunchedProcess> still_running;
    still_running.reserve(g_launched_processes.size());

    for (LaunchedProcess& process : g_launched_processes) {
        if (process.process_handle == nullptr) {
            continue;
        }

        if (WaitForSingleObject(process.process_handle, 0) == WAIT_TIMEOUT) {
            still_running.push_back(process);
        } else {
            CloseHandle(process.process_handle);
        }
    }

    g_launched_processes.swap(still_running);
}

bool HasLiveProcessForSessionLocked(DWORD session_id) {
    CleanupDeadProcessesLocked();
    for (const LaunchedProcess& process : g_launched_processes) {
        if (process.session_id == session_id) {
            return true;
        }
    }

    return false;
}

bool LaunchTrayAppInSession(DWORD session_id) {
    if (session_id == 0) {
        return false;
    }

    HANDLE user_token = nullptr;
    if (!WTSQueryUserToken(session_id, &user_token)) {
        return false;
    }

    HANDLE primary_token = nullptr;
    const BOOL duplicated = DuplicateTokenEx(
        user_token,
        TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
        nullptr,
        SecurityIdentification,
        TokenPrimary,
        &primary_token
    );
    CloseHandle(user_token);

    if (!duplicated) {
        return false;
    }

    LPVOID environment = nullptr;
    CreateEnvironmentBlock(&environment, primary_token, FALSE);

    std::wstring app_path = BuildTrayAppPath();
    std::wstring command_line = L"\"" + app_path + L"\" " + tray::kHiddenArgument;
    std::wstring working_directory = BuildWorkingDirectory();

    STARTUPINFOEXW startup_info{};
    startup_info.StartupInfo.cb = sizeof(startup_info);
    startup_info.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startup_info.StartupInfo.wShowWindow = SW_HIDE;

    SIZE_T attribute_size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size);
    std::vector<std::byte> attribute_buffer(attribute_size);
    startup_info.lpAttributeList =
        reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(attribute_buffer.data());

    const HANDLE parent_process = GetCurrentProcess();
    BOOL created = FALSE;
    PROCESS_INFORMATION process_info{};

    if (InitializeProcThreadAttributeList(startup_info.lpAttributeList, 1, 0, &attribute_size) &&
        UpdateProcThreadAttribute(
            startup_info.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            const_cast<HANDLE*>(&parent_process),
            sizeof(parent_process),
            nullptr,
            nullptr)) {
        created = CreateProcessAsUserW(
            primary_token,
            app_path.c_str(),
            command_line.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            environment,
            working_directory.empty() ? nullptr : working_directory.c_str(),
            &startup_info.StartupInfo,
            &process_info
        );
    }

    DeleteProcThreadAttributeList(startup_info.lpAttributeList);

    if (environment != nullptr) {
        DestroyEnvironmentBlock(environment);
    }

    CloseHandle(primary_token);

    if (!created) {
        return false;
    }

    CloseHandle(process_info.hThread);

    EnterCriticalSection(&g_process_lock);
    CleanupDeadProcessesLocked();
    g_launched_processes.push_back({session_id, process_info.dwProcessId, process_info.hProcess});
    LeaveCriticalSection(&g_process_lock);
    return true;
}

void LaunchTrayAppInKnownSessions() {
    PWTS_SESSION_INFOW sessions = nullptr;
    DWORD session_count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &session_count)) {
        return;
    }

    for (DWORD i = 0; i < session_count; ++i) {
        const DWORD session_id = sessions[i].SessionId;
        if (session_id == 0) {
            continue;
        }

        EnterCriticalSection(&g_process_lock);
        const bool already_running = HasLiveProcessForSessionLocked(session_id);
        LeaveCriticalSection(&g_process_lock);

        if (!already_running) {
            LaunchTrayAppInSession(session_id);
        }
    }

    WTSFreeMemory(sessions);
}

DWORD WINAPI SessionWatchThreadProc(LPVOID) {
    while (WaitForSingleObject(g_stop_event, 3000) == WAIT_TIMEOUT) {
        LaunchTrayAppInKnownSessions();
    }

    return 0;
}

void TerminateLaunchedProcesses() {
    EnterCriticalSection(&g_process_lock);
    for (LaunchedProcess& process : g_launched_processes) {
        if (process.process_handle != nullptr && WaitForSingleObject(process.process_handle, 0) == WAIT_TIMEOUT) {
            TerminateProcess(process.process_handle, 0);
            WaitForSingleObject(process.process_handle, 5000);
        }

        if (process.process_handle != nullptr) {
            CloseHandle(process.process_handle);
            process.process_handle = nullptr;
        }
    }
    g_launched_processes.clear();
    LeaveCriticalSection(&g_process_lock);
}

extern "C" error_status_t StopService() {
    RpcMgmtStopServerListening(nullptr);
    return RPC_S_OK;
}

DWORD WINAPI ServiceControlHandler(
    DWORD control,
    DWORD event_type,
    LPVOID event_data,
    LPVOID
) {
    if (control == SERVICE_CONTROL_SESSIONCHANGE && event_data != nullptr) {
        const auto* notification = static_cast<WTSSESSION_NOTIFICATION*>(event_data);
        switch (event_type) {
            case WTS_CONSOLE_CONNECT:
            case WTS_REMOTE_CONNECT:
            case WTS_SESSION_LOGON:
            case WTS_SESSION_UNLOCK: {
                EnterCriticalSection(&g_process_lock);
                const bool already_running = HasLiveProcessForSessionLocked(notification->dwSessionId);
                LeaveCriticalSection(&g_process_lock);

                if (!already_running) {
                    LaunchTrayAppInSession(notification->dwSessionId);
                }
                break;
            }
            case WTS_SESSION_LOGOFF: {
                EnterCriticalSection(&g_process_lock);
                CleanupDeadProcessesLocked();
                LeaveCriticalSection(&g_process_lock);
                break;
            }
            default:
                break;
        }
    }

    return NO_ERROR;
}

RPC_STATUS StartRpcServer() {
    RPC_STATUS status = RpcServerUseProtseqEpW(
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(tray::kRpcEndpoint)),
        nullptr
    );

    if (status != RPC_S_OK) {
        return status;
    }

    status = RpcServerRegisterIf2(
        TrayServiceRpc_v1_0_s_ifspec,
        nullptr,
        nullptr,
        RPC_IF_ALLOW_LOCAL_ONLY,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        static_cast<unsigned int>(-1),
        nullptr
    );

    if (status != RPC_S_OK) {
        return status;
    }

    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    if (status != RPC_S_OK && status != RPC_S_ALREADY_LISTENING) {
        return status;
    }

    return RPC_S_OK;
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_service_status_handle = RegisterServiceCtrlHandlerExW(tray::kServiceName, ServiceControlHandler, nullptr);
    if (g_service_status_handle == nullptr) {
        return;
    }

    InitializeCriticalSection(&g_process_lock);
    g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    SetServiceState(SERVICE_START_PENDING, NO_ERROR, 3000);
    const RPC_STATUS rpc_status = StartRpcServer();
    if (rpc_status != RPC_S_OK) {
        SetServiceState(SERVICE_STOPPED, rpc_status, 0);
        if (g_stop_event != nullptr) {
            CloseHandle(g_stop_event);
            g_stop_event = nullptr;
        }
        DeleteCriticalSection(&g_process_lock);
        return;
    }

    LaunchTrayAppInKnownSessions();
    g_session_watch_thread = CreateThread(nullptr, 0, SessionWatchThreadProc, nullptr, 0, nullptr);
    SetServiceState(SERVICE_RUNNING);

    RpcMgmtWaitServerListen();

    SetServiceState(SERVICE_STOP_PENDING, NO_ERROR, 3000);
    if (g_stop_event != nullptr) {
        SetEvent(g_stop_event);
    }
    if (g_session_watch_thread != nullptr) {
        WaitForSingleObject(g_session_watch_thread, 5000);
        CloseHandle(g_session_watch_thread);
        g_session_watch_thread = nullptr;
    }
    TerminateLaunchedProcesses();
    RpcServerUnregisterIf(TrayServiceRpc_v1_0_s_ifspec, nullptr, FALSE);
    if (g_stop_event != nullptr) {
        CloseHandle(g_stop_event);
        g_stop_event = nullptr;
    }
    DeleteCriticalSection(&g_process_lock);
    SetServiceState(SERVICE_STOPPED);
}

}  // namespace

int wmain() {
    SERVICE_TABLE_ENTRYW service_table[] = {
        {const_cast<LPWSTR>(tray::kServiceName), ServiceMain},
        {nullptr, nullptr},
    };

    if (!StartServiceCtrlDispatcherW(service_table)) {
        return static_cast<int>(GetLastError());
    }

    return 0;
}
