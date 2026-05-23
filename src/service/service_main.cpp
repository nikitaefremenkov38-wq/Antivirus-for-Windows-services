#include <windows.h>

#include "json_utils.h"
#include "http_client.h"
#include "service_config.h"
#include "service_utils.h"
#include "tray_service_rpc.h"

#include <rpc.h>
#include <userenv.h>
#include <wtsapi32.h>

#include <string>
#include <vector>

namespace {

struct AuthState {
    bool authenticated{false};
    std::wstring userName;
    std::string accessToken;
    std::string refreshToken;
    uint64_t accessExpiresAt{};
    uint64_t refreshExpiresAt{};
    uint64_t nextRefreshAttemptAt{};
};

struct LicenseState {
    bool hasLicense{false};
    std::string ticket;
    uint64_t expiresAtUnix{};
    uint64_t nextRefreshAttemptAt{};
};

enum class LicenseFetchResult {
    kSuccess,
    kNoLicense,
    kFailed,
};

struct LaunchedProcess {
    DWORD sessionId{};
    HANDLE processHandle{};
};

SERVICE_STATUS_HANDLE g_serviceStatusHandle = nullptr;
SERVICE_STATUS g_serviceStatus{};
CRITICAL_SECTION g_processLock{};
CRITICAL_SECTION g_stateLock{};
HANDLE g_stopEvent = nullptr;
HANDLE g_sessionWatchThread = nullptr;
HANDLE g_stateWatchThread = nullptr;
std::vector<LaunchedProcess> g_launchedProcesses;
AuthState g_authState;
LicenseState g_licenseState;

uint64_t NowUnix() {
    FILETIME file_time{};
    GetSystemTimeAsFileTime(&file_time);
    ULARGE_INTEGER value{};
    value.LowPart = file_time.dwLowDateTime;
    value.HighPart = file_time.dwHighDateTime;
    return (value.QuadPart - 116444736000000000ULL) / 10000000ULL;
}

uint64_t CalculateRefreshMoment(uint64_t expiresAt) {
    const uint64_t now = NowUnix();
    if (expiresAt <= now + 60) {
        return now + 5;
    }
    return expiresAt - 60;
}

void ClearLicenseLocked() {
    g_licenseState = {};
}

void ClearAuthLocked() {
    g_authState = {};
    ClearLicenseLocked();
}

void SetServiceState(DWORD state, DWORD win32ExitCode = NO_ERROR, DWORD waitHint = 0) {
    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwCurrentState = state;
    g_serviceStatus.dwWin32ExitCode = win32ExitCode;
    g_serviceStatus.dwWaitHint = waitHint;
    g_serviceStatus.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_SESSIONCHANGE : 0;

    static DWORD checkpoint = 1;
    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) {
        g_serviceStatus.dwCheckPoint = checkpoint++;
    } else {
        g_serviceStatus.dwCheckPoint = 0;
        checkpoint = 1;
    }

    SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
}

std::wstring BuildTrayAppPath() {
    std::wstring path = tray::GetExecutableDirectory();
    if (!path.empty()) {
        path += L"\\";
    }
    path += tray::kTrayAppProcessName;
    return path;
}

bool StoreTokens(const std::string& body, const std::wstring* explicitUserName = nullptr) {
    const auto access = tray::TryGetJsonString(body, "accessToken");
    const auto refresh = tray::TryGetJsonString(body, "refreshToken");
    if (!access || !refresh) {
        return false;
    }

    const auto accessExp = tray::TryGetJwtClaimUint64(*access, "exp");
    const auto refreshExp = tray::TryGetJwtClaimUint64(*refresh, "exp");
    if (!accessExp || !refreshExp) {
        return false;
    }

    std::wstring userName = explicitUserName != nullptr ? *explicitUserName : tray::Utf8ToWide(tray::TryGetJsonString(body, "userName").value_or(""));
    if (userName.empty()) {
        const auto sub = tray::TryGetJwtClaimString(*access, "sub");
        if (sub) {
            userName = tray::Utf8ToWide(*sub);
        }
    }

    EnterCriticalSection(&g_stateLock);
    g_authState.authenticated = true;
    g_authState.userName = userName;
    g_authState.accessToken = *access;
    g_authState.refreshToken = *refresh;
    g_authState.accessExpiresAt = *accessExp;
    g_authState.refreshExpiresAt = *refreshExp;
    g_authState.nextRefreshAttemptAt = CalculateRefreshMoment(*accessExp);
    LeaveCriticalSection(&g_stateLock);
    return true;
}

bool StoreLicense(const std::string& body) {
    const auto ticket = tray::TryGetJsonString(body, "licenseTicket");
    const auto expires = tray::TryGetJsonUint64(body, "expiresAtUnix");
    if (!ticket || !expires) {
        return false;
    }

    EnterCriticalSection(&g_stateLock);
    g_licenseState.hasLicense = true;
    g_licenseState.ticket = *ticket;
    g_licenseState.expiresAtUnix = *expires;
    g_licenseState.nextRefreshAttemptAt = CalculateRefreshMoment(*expires);
    LeaveCriticalSection(&g_stateLock);
    return true;
}

bool LoginAgainstWeb(const std::wstring& userName, const std::wstring& password) {
    const std::string body = "{\"username\":\"" + tray::EscapeJson(tray::WideToUtf8(userName)) +
        "\",\"password\":\"" + tray::EscapeJson(tray::WideToUtf8(password)) + "\"}";

    tray::HttpResponse response;
    if (!tray::SendJsonHttpsRequest(L"POST", tray::kLoginUrl, body, L"", &response) || response.statusCode != 200) {
        return false;
    }

    return StoreTokens(response.body, &userName);
}

bool RefreshTokens() {
    EnterCriticalSection(&g_stateLock);
    if (!g_authState.authenticated || g_authState.refreshToken.empty()) {
        LeaveCriticalSection(&g_stateLock);
        return false;
    }
    const std::wstring refreshToken = tray::Utf8ToWide(g_authState.refreshToken);
    const uint64_t refreshExpiresAt = g_authState.refreshExpiresAt;
    LeaveCriticalSection(&g_stateLock);

    const std::string body = "{\"refreshToken\":\"" + tray::EscapeJson(tray::WideToUtf8(refreshToken)) + "\"}";
    tray::HttpResponse response;
    if (!tray::SendJsonHttpsRequest(L"POST", tray::kRefreshUrl, body, L"", &response) || response.statusCode != 200) {
        EnterCriticalSection(&g_stateLock);
        const uint64_t now = NowUnix();
        if (refreshExpiresAt <= now) {
            ClearAuthLocked();
        } else {
            g_authState.nextRefreshAttemptAt = now + 15;
        }
        LeaveCriticalSection(&g_stateLock);
        return false;
    }

    return StoreTokens(response.body);
}

LicenseFetchResult FetchLicenseStatus() {
    EnterCriticalSection(&g_stateLock);
    if (!g_authState.authenticated || g_authState.accessToken.empty()) {
        LeaveCriticalSection(&g_stateLock);
        return LicenseFetchResult::kFailed;
    }
    const std::wstring bearer = tray::Utf8ToWide(g_authState.accessToken);
    LeaveCriticalSection(&g_stateLock);

    tray::HttpResponse response;
    if (!tray::SendJsonHttpsRequest(L"GET", tray::kLicenseStatusUrl, "", bearer, &response)) {
        return LicenseFetchResult::kFailed;
    }

    if (response.statusCode == 404) {
        EnterCriticalSection(&g_stateLock);
        ClearLicenseLocked();
        LeaveCriticalSection(&g_stateLock);
        return LicenseFetchResult::kNoLicense;
    }
    if (response.statusCode != 200) {
        return LicenseFetchResult::kFailed;
    }

    return StoreLicense(response.body) ? LicenseFetchResult::kSuccess : LicenseFetchResult::kFailed;
}

bool ActivateLicense(const std::wstring& code) {
    EnterCriticalSection(&g_stateLock);
    if (!g_authState.authenticated || g_authState.accessToken.empty()) {
        LeaveCriticalSection(&g_stateLock);
        return false;
    }
    const std::wstring bearer = tray::Utf8ToWide(g_authState.accessToken);
    LeaveCriticalSection(&g_stateLock);

    const std::string body = "{\"activationCode\":\"" + tray::EscapeJson(tray::WideToUtf8(code)) + "\"}";
    tray::HttpResponse response;
    if (!tray::SendJsonHttpsRequest(L"POST", tray::kLicenseActivateUrl, body, bearer, &response)) {
        return false;
    }
    if (response.statusCode != 200 && response.statusCode != 204) {
        return false;
    }
    if (response.statusCode == 200 && !response.body.empty() && StoreLicense(response.body)) {
        return true;
    }
    return FetchLicenseStatus() == LicenseFetchResult::kSuccess;
}

void CleanupDeadProcessesLocked() {
    std::vector<LaunchedProcess> alive;
    alive.reserve(g_launchedProcesses.size());
    for (auto& process : g_launchedProcesses) {
        if (process.processHandle != nullptr && WaitForSingleObject(process.processHandle, 0) == WAIT_TIMEOUT) {
            alive.push_back(process);
        } else if (process.processHandle != nullptr) {
            CloseHandle(process.processHandle);
        }
    }
    g_launchedProcesses.swap(alive);
}

bool HasLiveProcessForSessionLocked(DWORD sessionId) {
    CleanupDeadProcessesLocked();
    for (const auto& process : g_launchedProcesses) {
        if (process.sessionId == sessionId) {
            return true;
        }
    }
    return false;
}

bool LaunchTrayAppInSession(DWORD sessionId) {
    if (sessionId == 0) {
        return false;
    }

    HANDLE userToken = nullptr;
    if (!WTSQueryUserToken(sessionId, &userToken)) {
        return false;
    }

    HANDLE primaryToken = nullptr;
    const BOOL duplicated = DuplicateTokenEx(userToken, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, nullptr, SecurityIdentification, TokenPrimary, &primaryToken);
    CloseHandle(userToken);
    if (!duplicated) {
        return false;
    }

    LPVOID environment = nullptr;
    CreateEnvironmentBlock(&environment, primaryToken, FALSE);

    std::wstring appPath = BuildTrayAppPath();
    std::wstring commandLine = L"\"" + appPath + L"\" " + tray::kHiddenArgument + L" " + tray::kServiceLaunchArgument;
    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_HIDE;
    startupInfo.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

    PROCESS_INFORMATION processInfo{};
    const BOOL created = CreateProcessAsUserW(primaryToken, appPath.c_str(), commandLine.data(), nullptr, nullptr, FALSE, CREATE_UNICODE_ENVIRONMENT, environment, tray::GetExecutableDirectory().c_str(), &startupInfo, &processInfo);

    if (environment != nullptr) {
        DestroyEnvironmentBlock(environment);
    }
    CloseHandle(primaryToken);
    if (!created) {
        return false;
    }

    CloseHandle(processInfo.hThread);
    EnterCriticalSection(&g_processLock);
    CleanupDeadProcessesLocked();
    g_launchedProcesses.push_back({sessionId, processInfo.hProcess});
    LeaveCriticalSection(&g_processLock);
    return true;
}

void LaunchTrayAppInKnownSessions() {
    PWTS_SESSION_INFOW sessions = nullptr;
    DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
        return;
    }
    for (DWORD i = 0; i < count; ++i) {
        const DWORD sessionId = sessions[i].SessionId;
        if (sessionId == 0) {
            continue;
        }
        EnterCriticalSection(&g_processLock);
        const bool alive = HasLiveProcessForSessionLocked(sessionId);
        LeaveCriticalSection(&g_processLock);
        if (!alive) {
            LaunchTrayAppInSession(sessionId);
        }
    }
    WTSFreeMemory(sessions);
}

void TerminateLaunchedProcesses() {
    EnterCriticalSection(&g_processLock);
    for (auto& process : g_launchedProcesses) {
        if (process.processHandle != nullptr && WaitForSingleObject(process.processHandle, 0) == WAIT_TIMEOUT) {
            TerminateProcess(process.processHandle, 0);
            WaitForSingleObject(process.processHandle, 5000);
        }
        if (process.processHandle != nullptr) {
            CloseHandle(process.processHandle);
        }
    }
    g_launchedProcesses.clear();
    LeaveCriticalSection(&g_processLock);
}

DWORD WINAPI SessionWatchThreadProc(LPVOID) {
    while (WaitForSingleObject(g_stopEvent, 3000) == WAIT_TIMEOUT) {
        LaunchTrayAppInKnownSessions();
    }
    return 0;
}

DWORD WINAPI StateWatchThreadProc(LPVOID) {
    while (WaitForSingleObject(g_stopEvent, 2000) == WAIT_TIMEOUT) {
        const uint64_t now = NowUnix();
        bool refreshTokensNow = false;
        bool refreshLicenseNow = false;

        EnterCriticalSection(&g_stateLock);
        refreshTokensNow = g_authState.authenticated && now >= g_authState.nextRefreshAttemptAt;
        refreshLicenseNow = g_authState.authenticated && g_licenseState.hasLicense && now >= g_licenseState.nextRefreshAttemptAt;
        LeaveCriticalSection(&g_stateLock);

        if (refreshTokensNow) {
            RefreshTokens();
        }
        if (refreshLicenseNow) {
            FetchLicenseStatus();
        }
    }
    return 0;
}

extern "C" error_status_t StopService() {
    RpcMgmtStopServerListening(nullptr);
    return ERROR_SUCCESS;
}

extern "C" error_status_t GetCurrentUserInfo(int* authenticated, wchar_t* userName, unsigned long userNameCapacity) {
    if (authenticated == nullptr || userName == nullptr || userNameCapacity == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&g_stateLock);
    *authenticated = g_authState.authenticated ? 1 : 0;
    wcsncpy_s(userName, userNameCapacity, g_authState.userName.c_str(), _TRUNCATE);
    LeaveCriticalSection(&g_stateLock);
    return ERROR_SUCCESS;
}

extern "C" error_status_t LoginUser(const wchar_t* userName, const wchar_t* password) {
    if (userName == nullptr || password == nullptr || userName[0] == L'\0' || password[0] == L'\0') {
        return ERROR_INVALID_PARAMETER;
    }
    return LoginAgainstWeb(userName, password) ? ERROR_SUCCESS : ERROR_LOGON_FAILURE;
}

extern "C" error_status_t LogoutUser() {
    EnterCriticalSection(&g_stateLock);
    ClearAuthLocked();
    LeaveCriticalSection(&g_stateLock);
    return ERROR_SUCCESS;
}

extern "C" error_status_t GetLicenseInfo(int* hasLicense, hyper* expiresAtUnix) {
    if (hasLicense == nullptr || expiresAtUnix == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&g_stateLock);
    const bool authenticated = g_authState.authenticated;
    const bool hasCachedLicense = g_licenseState.hasLicense;
    const uint64_t cachedExpiration = g_licenseState.expiresAtUnix;
    LeaveCriticalSection(&g_stateLock);

    if (!authenticated) {
        return ERROR_ACCESS_DENIED;
    }

    if (!hasCachedLicense) {
        const LicenseFetchResult fetchResult = FetchLicenseStatus();
        if (fetchResult == LicenseFetchResult::kNoLicense) {
            *hasLicense = 0;
            *expiresAtUnix = 0;
            return ERROR_NOT_FOUND;
        }
        if (fetchResult == LicenseFetchResult::kFailed) {
            *hasLicense = 0;
            *expiresAtUnix = 0;
            return ERROR_GEN_FAILURE;
        }
    }

    EnterCriticalSection(&g_stateLock);
    const bool final_has_license = g_licenseState.hasLicense;
    const uint64_t final_expiration = g_licenseState.expiresAtUnix;
    LeaveCriticalSection(&g_stateLock);

    if (!final_has_license) {
        *hasLicense = 0;
        *expiresAtUnix = 0;
        return ERROR_NOT_FOUND;
    }

    *hasLicense = 1;
    *expiresAtUnix = static_cast<hyper>(hasCachedLicense ? cachedExpiration : final_expiration);
    return ERROR_SUCCESS;
}

extern "C" error_status_t ActivateProduct(const wchar_t* activationCode) {
    if (activationCode == nullptr || activationCode[0] == L'\0') {
        return ERROR_INVALID_PARAMETER;
    }
    return ActivateLicense(activationCode) ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

DWORD WINAPI ServiceControlHandler(DWORD control, DWORD eventType, LPVOID eventData, LPVOID) {
    if (control == SERVICE_CONTROL_SESSIONCHANGE && eventData != nullptr) {
        const auto* notification = static_cast<WTSSESSION_NOTIFICATION*>(eventData);
        switch (eventType) {
            case WTS_CONSOLE_CONNECT:
            case WTS_REMOTE_CONNECT:
            case WTS_SESSION_LOGON:
            case WTS_SESSION_UNLOCK: {
                EnterCriticalSection(&g_processLock);
                const bool alive = HasLiveProcessForSessionLocked(notification->dwSessionId);
                LeaveCriticalSection(&g_processLock);
                if (!alive) {
                    LaunchTrayAppInSession(notification->dwSessionId);
                }
                break;
            }
            case WTS_SESSION_LOGOFF:
                EnterCriticalSection(&g_processLock);
                CleanupDeadProcessesLocked();
                LeaveCriticalSection(&g_processLock);
                break;
            default:
                break;
        }
    }
    return NO_ERROR;
}

RPC_STATUS StartRpcServer() {
    RPC_STATUS status = RpcServerUseProtseqEpW(reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")), RPC_C_PROTSEQ_MAX_REQS_DEFAULT, reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(tray::kRpcEndpoint)), nullptr);
    if (status != RPC_S_OK) {
        return status;
    }
    status = RpcServerRegisterIf2(TrayServiceRpc_v1_0_s_ifspec, nullptr, nullptr, RPC_IF_ALLOW_LOCAL_ONLY, RPC_C_LISTEN_MAX_CALLS_DEFAULT, static_cast<unsigned int>(-1), nullptr);
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
    g_serviceStatusHandle = RegisterServiceCtrlHandlerExW(tray::kServiceName, ServiceControlHandler, nullptr);
    if (g_serviceStatusHandle == nullptr) {
        return;
    }

    InitializeCriticalSection(&g_processLock);
    InitializeCriticalSection(&g_stateLock);
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    SetServiceState(SERVICE_START_PENDING, NO_ERROR, 3000);
    const RPC_STATUS rpcStatus = StartRpcServer();
    if (rpcStatus != RPC_S_OK) {
        SetServiceState(SERVICE_STOPPED, rpcStatus, 0);
        if (g_stopEvent != nullptr) {
            CloseHandle(g_stopEvent);
        }
        DeleteCriticalSection(&g_stateLock);
        DeleteCriticalSection(&g_processLock);
        return;
    }

    LaunchTrayAppInKnownSessions();
    g_sessionWatchThread = CreateThread(nullptr, 0, SessionWatchThreadProc, nullptr, 0, nullptr);
    g_stateWatchThread = CreateThread(nullptr, 0, StateWatchThreadProc, nullptr, 0, nullptr);
    SetServiceState(SERVICE_RUNNING);

    RpcMgmtWaitServerListen();

    SetServiceState(SERVICE_STOP_PENDING, NO_ERROR, 3000);
    if (g_stopEvent != nullptr) {
        SetEvent(g_stopEvent);
    }
    if (g_sessionWatchThread != nullptr) {
        WaitForSingleObject(g_sessionWatchThread, 5000);
        CloseHandle(g_sessionWatchThread);
    }
    if (g_stateWatchThread != nullptr) {
        WaitForSingleObject(g_stateWatchThread, 5000);
        CloseHandle(g_stateWatchThread);
    }
    TerminateLaunchedProcesses();
    RpcServerUnregisterIf(TrayServiceRpc_v1_0_s_ifspec, nullptr, FALSE);
    if (g_stopEvent != nullptr) {
        CloseHandle(g_stopEvent);
    }
    DeleteCriticalSection(&g_stateLock);
    DeleteCriticalSection(&g_processLock);
    SetServiceState(SERVICE_STOPPED);
}

}  // namespace

int wmain() {
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        {const_cast<LPWSTR>(tray::kServiceName), ServiceMain},
        {nullptr, nullptr},
    };
    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        return static_cast<int>(GetLastError());
    }
    return 0;
}
