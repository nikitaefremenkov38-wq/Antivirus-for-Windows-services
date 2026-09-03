#include <windows.h>

#include "av_engine.h"
#include "json_utils.h"
#include "http_client.h"
#include "service_config.h"
#include "service_utils.h"
#include "tray_service_rpc.h"

#include <rpc.h>
#include <userenv.h>
#include <wtsapi32.h>

#include <algorithm>
#include <filesystem>
#include <map>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

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

struct ScanSummaryInternal {
    uint32_t scannedObjects{};
    uint32_t maliciousObjects{};
    uint32_t failedObjects{};
    std::wstring details;
};

struct ScheduledScanState {
    bool enabled{false};
    uint32_t intervalMinutes{60};
    uint64_t nextRunUnix{};
    std::wstring lastSummary;
};

struct MonitorState {
    std::vector<std::wstring> directories;
    std::map<std::wstring, uint64_t> knownWriteTimes;
    std::wstring lastSummary;
};

enum class ScanJobKind {
    None,
    Directory,
    FixedDrives,
};

struct ScanJobState {
    bool running{false};
    bool hasResult{false};
    ScanJobKind kind{ScanJobKind::None};
    std::wstring targetPath;
    uint32_t totalObjects{};
    uint32_t completedObjects{};
    uint32_t maliciousObjects{};
    uint32_t failedObjects{};
    std::wstring currentPath;
    std::wstring details;
};

SERVICE_STATUS_HANDLE g_serviceStatusHandle = nullptr;
SERVICE_STATUS g_serviceStatus{};
CRITICAL_SECTION g_processLock{};
CRITICAL_SECTION g_stateLock{};
CRITICAL_SECTION g_avLock{};
CRITICAL_SECTION g_scanLock{};
HANDLE g_stopEvent = nullptr;
HANDLE g_sessionWatchThread = nullptr;
HANDLE g_stateWatchThread = nullptr;
HANDLE g_scanJobThread = nullptr;
std::vector<LaunchedProcess> g_launchedProcesses;
AuthState g_authState;
LicenseState g_licenseState;
tray::AvEngine g_avEngine;
ScheduledScanState g_scheduleState;
MonitorState g_monitorState;
ScanJobState g_scanJobState;

constexpr unsigned long kScanDetailsCapacity = 4096;
constexpr size_t kMaxReportedScanLines = 40;
constexpr wchar_t kPrimaryBasesFileName[] = L"avbases.bin";
constexpr wchar_t kBackupBasesFileName[] = L"avbases.bin.bak";
constexpr wchar_t kDefaultBasesFileName[] = L"default_avbases.bin";

std::wstring ToLowerCopy(std::wstring text) {
    std::transform(text.begin(), text.end(), text.begin(), towlower);
    return text;
}

bool HasTargetExtension(const std::wstring& path) {
    const std::wstring extension = ToLowerCopy(fs::path(path).extension().wstring());
    return extension == L".exe" || extension == L".dll" || extension == L".sys" || extension == L".scr" ||
           extension == L".com" || extension == L".ps1" || extension == L".psm1" || extension == L".psd1" ||
           extension == L".bat" || extension == L".cmd" || extension == L".js" || extension == L".jse" ||
           extension == L".vbs" || extension == L".vbe" || extension == L".wsf" || extension == L".wsh" ||
           extension == L".py" || extension == L".pyw" || extension == L".jar" || extension == L".class" ||
           extension == L".txt";
}

bool IsReparsePoint(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

bool ShouldSkipDirectory(const std::wstring& path, bool fixedDriveMode) {
    const std::wstring name = ToLowerCopy(fs::path(path).filename().wstring());
    if (name == L"appdata" || name == L"node_modules" || name == L".git" || name == L".vs" ||
        name == L"build" || name == L"cmake-build-debug" || name == L"cmake-build-release") {
        return true;
    }
    if (fixedDriveMode && (name == L"windows" || name == L"program files" || name == L"program files (x86)" ||
                           name == L"programdata" || name == L"$recycle.bin" || name == L"system volume information" ||
                           name == L"recovery")) {
        return true;
    }
    return IsReparsePoint(path);
}

uint64_t NowUnix() {
    FILETIME fileTime{};
    GetSystemTimeAsFileTime(&fileTime);
    ULARGE_INTEGER value{};
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;
    return (value.QuadPart - 116444736000000000ULL) / 10000000ULL;
}

uint64_t CalculateRefreshMoment(uint64_t expiresAt) {
    const uint64_t now = NowUnix();
    if (expiresAt <= now + 60) {
        return now + 5;
    }
    return expiresAt - 60;
}

void AppendSummaryLine(std::wstring* target, const std::wstring& line) {
    if (target == nullptr || line.empty()) {
        return;
    }
    if (!target->empty()) {
        *target += L"\r\n";
    }
    *target += line;
}

void ClearAvStateLocked() {
    g_avEngine.Clear();
    g_scheduleState.nextRunUnix = 0;
    g_scheduleState.lastSummary.clear();
    g_monitorState.knownWriteTimes.clear();
    g_monitorState.lastSummary.clear();
}

void ClearLicenseLocked() {
    g_licenseState = {};
}

void ClearAuthLocked() {
    g_authState = {};
    ClearLicenseLocked();
}

void ClearAuthAndAvState() {
    EnterCriticalSection(&g_stateLock);
    ClearAuthLocked();
    LeaveCriticalSection(&g_stateLock);

    EnterCriticalSection(&g_avLock);
    ClearAvStateLocked();
    LeaveCriticalSection(&g_avLock);
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

std::wstring BuildBasesDirectoryPath() {
    std::wstring path = tray::GetExecutableDirectory();
    if (!path.empty()) {
        path += L"\\";
    }
    path += L"bases";
    return path;
}

std::wstring BuildBasesFilePath(const std::wstring& directory, const wchar_t* fileName) {
    std::wstring path = directory;
    if (!path.empty() && path.back() != L'\\') {
        path += L"\\";
    }
    path += fileName;
    return path;
}

void EnsureDirectoryRecursive(const std::wstring& directory) {
    if (directory.empty()) {
        return;
    }
    std::error_code ignored;
    fs::create_directories(directory, ignored);
}

bool CopyFileOverwrite(const std::wstring& source, const std::wstring& target) {
    EnsureDirectoryRecursive(fs::path(target).parent_path().wstring());
    if (!CopyFileW(source.c_str(), target.c_str(), FALSE)) {
        return false;
    }
    return true;
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

bool LoadAvBases() {
    EnterCriticalSection(&g_avLock);
    const std::wstring basesDirectory = BuildBasesDirectoryPath();
    EnsureDirectoryRecursive(basesDirectory);

    const std::wstring primaryPath = BuildBasesFilePath(basesDirectory, kPrimaryBasesFileName);
    const std::wstring backupPath = BuildBasesFilePath(basesDirectory, kBackupBasesFileName);
    const std::wstring defaultPath = BuildBasesFilePath(basesDirectory, kDefaultBasesFileName);

    if (!fs::exists(defaultPath)) {
        g_avEngine.SaveDefaultBasesToFile(defaultPath);
    }

    tray::AvLoadStats loadStats{};
    tray::AvLoadResult loadResult = g_avEngine.LoadBasesFromFile(primaryPath, &loadStats);
    bool loaded = loadResult == tray::AvLoadResult::Success;

    if (!loaded) {
        loadResult = g_avEngine.LoadBasesFromFile(backupPath, &loadStats);
        loaded = loadResult == tray::AvLoadResult::Success;
        if (loaded) {
            CopyFileOverwrite(backupPath, primaryPath);
        }
    }

    if (!loaded) {
        loadResult = g_avEngine.LoadBasesFromFile(defaultPath, &loadStats);
        loaded = loadResult == tray::AvLoadResult::Success;
        if (loaded) {
            CopyFileOverwrite(defaultPath, primaryPath);
        }
    }

    if (loaded && fs::exists(primaryPath)) {
        CopyFileOverwrite(primaryPath, backupPath);
    }

    if (loaded && g_scheduleState.enabled && g_scheduleState.nextRunUnix == 0) {
        g_scheduleState.nextRunUnix = NowUnix() + static_cast<uint64_t>(g_scheduleState.intervalMinutes) * 60;
    }
    LeaveCriticalSection(&g_avLock);
    return loaded;
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

    bool activated = false;
    if (response.statusCode == 200 && !response.body.empty()) {
        activated = StoreLicense(response.body);
    } else {
        activated = FetchLicenseStatus() == LicenseFetchResult::kSuccess;
    }
    if (!activated) {
        return false;
    }
    return LoadAvBases();
}

bool ReadFileBytes(const std::wstring& path, std::vector<uint8_t>* bytes) {
    bytes->clear();
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > static_cast<LONGLONG>(64 * 1024 * 1024)) {
        CloseHandle(file);
        return false;
    }

    bytes->resize(static_cast<size_t>(size.QuadPart));
    DWORD readBytes = 0;
    const BOOL readOk = bytes->empty() || ReadFile(file, bytes->data(), static_cast<DWORD>(bytes->size()), &readBytes, nullptr);
    CloseHandle(file);
    if (!readOk || readBytes != bytes->size()) {
        bytes->clear();
        return false;
    }
    return true;
}

uint64_t GetFileWriteTimeStamp(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) {
        return 0;
    }
    ULARGE_INTEGER value{};
    value.LowPart = data.ftLastWriteTime.dwLowDateTime;
    value.HighPart = data.ftLastWriteTime.dwHighDateTime;
    return value.QuadPart;
}

bool CanUseAvFeatures() {
    EnterCriticalSection(&g_stateLock);
    const bool hasLicense = g_authState.authenticated && g_licenseState.hasLicense;
    LeaveCriticalSection(&g_stateLock);
    if (!hasLicense) {
        return false;
    }

    EnterCriticalSection(&g_avLock);
    const bool hasBases = g_avEngine.HasBases();
    LeaveCriticalSection(&g_avLock);
    return hasBases;
}

void AppendScanFinding(ScanSummaryInternal* summary, const std::wstring& line) {
    if (summary == nullptr) {
        return;
    }
    size_t lines = 0;
    for (wchar_t ch : summary->details) {
        if (ch == L'\n') {
            ++lines;
        }
    }
    if (lines >= kMaxReportedScanLines) {
        return;
    }
    AppendSummaryLine(&summary->details, line);
}

std::wstring BuildScanSummaryText(const std::wstring& caption, const ScanSummaryInternal& summary) {
    std::wstring text = caption + L"\r\n";
    text += L"Проверено объектов: " + std::to_wstring(summary.scannedObjects) + L"\r\n";
    text += L"Обнаружено угроз: " + std::to_wstring(summary.maliciousObjects) + L"\r\n";
    text += L"Ошибок чтения: " + std::to_wstring(summary.failedObjects);
    if (!summary.details.empty()) {
        text += L"\r\n\r\nПодробности:\r\n" + summary.details;
    }
    return text;
}

void ScanSingleFileInternal(const std::wstring& path, ScanSummaryInternal* summary) {
    summary->scannedObjects += 1;

    if (!HasTargetExtension(path)) {
        return;
    }

    std::vector<uint8_t> bytes;
    if (!ReadFileBytes(path, &bytes)) {
        summary->failedObjects += 1;
        AppendScanFinding(summary, path + L" -> ошибка чтения");
        return;
    }

    const auto objectType = tray::AvEngine::DetectObjectType(path, bytes);
    tray::ScanMatchInfo match;
    EnterCriticalSection(&g_avLock);
    match = g_avEngine.ScanBytes(bytes, objectType);
    LeaveCriticalSection(&g_avLock);

    if (match.malicious) {
        summary->maliciousObjects += 1;
        AppendScanFinding(summary, path + L" -> вредоносный объект: " + match.threatName + L" (" + tray::AvEngine::ObjectTypeToText(match.objectType) + L")");
    }
}

void CollectScannableFiles(const std::wstring& rootPath, bool fixedDriveMode, std::vector<std::wstring>* files, ScanSummaryInternal* summary) {
    std::error_code error;
    if (!fs::exists(rootPath, error) || !fs::is_directory(rootPath, error)) {
        summary->failedObjects += 1;
        AppendScanFinding(summary, rootPath + L" -> директория недоступна");
        return;
    }

    fs::recursive_directory_iterator iterator(rootPath, fs::directory_options::skip_permission_denied, error);
    fs::recursive_directory_iterator end;
    while (iterator != end) {
        if (error) {
            error.clear();
            ++iterator;
            continue;
        }

        const fs::directory_entry entry = *iterator;
        const std::wstring currentPath = entry.path().wstring();
        std::error_code entryError;
        if (entry.is_directory(entryError)) {
            if (ShouldSkipDirectory(currentPath, fixedDriveMode)) {
                iterator.disable_recursion_pending();
            }
        } else if (!entryError && entry.is_regular_file(entryError)) {
            if (HasTargetExtension(currentPath)) {
                files->push_back(currentPath);
            }
        }
        ++iterator;
    }
}

void UpdateScanJobProgress(const std::wstring& currentPath, const ScanSummaryInternal& summary, uint32_t totalObjects, uint32_t completedObjects) {
    EnterCriticalSection(&g_scanLock);
    g_scanJobState.totalObjects = totalObjects;
    g_scanJobState.completedObjects = completedObjects;
    g_scanJobState.maliciousObjects = summary.maliciousObjects;
    g_scanJobState.failedObjects = summary.failedObjects;
    g_scanJobState.currentPath = currentPath;
    LeaveCriticalSection(&g_scanLock);
}

void ScanFileListInternal(const std::vector<std::wstring>& files, ScanSummaryInternal* summary) {
    const uint32_t total = static_cast<uint32_t>(files.size());
    for (uint32_t index = 0; index < total; ++index) {
        UpdateScanJobProgress(files[index], *summary, total, index);
        ScanSingleFileInternal(files[index], summary);
        UpdateScanJobProgress(files[index], *summary, total, index + 1);
        if (WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0) {
            break;
        }
    }
}

void ScanDirectoryInternal(const std::wstring& path, ScanSummaryInternal* summary) {
    std::error_code error;
    if (!fs::exists(path, error) || !fs::is_directory(path, error)) {
        summary->failedObjects += 1;
        AppendScanFinding(summary, path + L" -> директория недоступна");
        return;
    }

    std::vector<std::wstring> files;
    CollectScannableFiles(path, false, &files, summary);
    ScanFileListInternal(files, summary);
}

void ScanFixedDrivesInternal(ScanSummaryInternal* summary) {
    std::vector<std::wstring> files;
    const DWORD drives = GetLogicalDrives();
    for (int index = 0; index < 26; ++index) {
        if ((drives & (1u << index)) == 0) {
            continue;
        }
        wchar_t root[] = {static_cast<wchar_t>(L'A' + index), L':', L'\\', L'\0'};
        if (GetDriveTypeW(root) == DRIVE_FIXED) {
            CollectScannableFiles(root, true, &files, summary);
        }
    }
    ScanFileListInternal(files, summary);
}
std::wstring JoinDirectories(const std::vector<std::wstring>& directories) {
    std::wstring result;
    for (size_t index = 0; index < directories.size(); ++index) {
        if (!result.empty()) {
            result += L";";
        }
        result += directories[index];
    }
    return result;
}

void PollMonitoredDirectories() {
    if (!CanUseAvFeatures()) {
        return;
    }

    std::vector<std::wstring> directories;
    std::map<std::wstring, uint64_t> knownWriteTimes;
    EnterCriticalSection(&g_avLock);
    directories = g_monitorState.directories;
    knownWriteTimes = g_monitorState.knownWriteTimes;
    LeaveCriticalSection(&g_avLock);

    ScanSummaryInternal summary;
    std::map<std::wstring, uint64_t> updatedWriteTimes = knownWriteTimes;

    for (const auto& directory : directories) {
        std::error_code error;
        if (!fs::exists(directory, error) || !fs::is_directory(directory, error)) {
            continue;
        }

        for (const auto& entry : fs::recursive_directory_iterator(directory, fs::directory_options::skip_permission_denied, error)) {
            if (error || !entry.is_regular_file(error)) {
                continue;
            }
            const std::wstring path = entry.path().wstring();
            const uint64_t writeTime = GetFileWriteTimeStamp(path);
            const auto it = updatedWriteTimes.find(path);
            if (it == updatedWriteTimes.end() || it->second != writeTime) {
                ScanSingleFileInternal(path, &summary);
                updatedWriteTimes[path] = writeTime;
            }
        }
    }

    EnterCriticalSection(&g_avLock);
    g_monitorState.knownWriteTimes.swap(updatedWriteTimes);
    if (!summary.details.empty()) {
        g_monitorState.lastSummary = summary.details;
    }
    LeaveCriticalSection(&g_avLock);
}

void ResetScanJobStateLocked(ScanJobKind kind, const std::wstring& targetPath) {
    g_scanJobState = {};
    g_scanJobState.kind = kind;
    g_scanJobState.targetPath = targetPath;
    g_scanJobState.running = true;
    g_scanJobState.currentPath = L"Подготовка списка файлов...";
}

void FinishScanJob(ScanSummaryInternal* summary, const std::wstring& caption) {
    EnterCriticalSection(&g_scanLock);
    g_scanJobState.running = false;
    g_scanJobState.hasResult = true;
    g_scanJobState.completedObjects = g_scanJobState.totalObjects;
    g_scanJobState.maliciousObjects = summary->maliciousObjects;
    g_scanJobState.failedObjects = summary->failedObjects;
    g_scanJobState.currentPath.clear();
    g_scanJobState.details = BuildScanSummaryText(caption, *summary);
    LeaveCriticalSection(&g_scanLock);
}

struct ScanThreadContext {
    ScanJobKind kind{ScanJobKind::None};
    std::wstring path;
};

DWORD WINAPI ScanJobThreadProc(LPVOID parameter) {
    std::unique_ptr<ScanThreadContext> context(reinterpret_cast<ScanThreadContext*>(parameter));
    ScanSummaryInternal summary;

    if (context->kind == ScanJobKind::Directory) {
        ScanDirectoryInternal(context->path, &summary);
        FinishScanJob(&summary, L"Сканирование папки завершено.");
    } else if (context->kind == ScanJobKind::FixedDrives) {
        ScanFixedDrivesInternal(&summary);
        FinishScanJob(&summary, L"Сканирование дисков завершено.");
    }

    return 0;
}

error_status_t StartAsyncScanJob(ScanJobKind kind, const std::wstring& path) {
    if (!CanUseAvFeatures()) {
        return ERROR_NOT_FOUND;
    }
    if (kind == ScanJobKind::Directory) {
        std::error_code error;
        if (path.empty() || !fs::exists(path, error) || !fs::is_directory(path, error)) {
            return ERROR_PATH_NOT_FOUND;
        }
    }

    EnterCriticalSection(&g_scanLock);
    if (g_scanJobState.running) {
        LeaveCriticalSection(&g_scanLock);
        return ERROR_BUSY;
    }
    if (g_scanJobThread != nullptr) {
        CloseHandle(g_scanJobThread);
        g_scanJobThread = nullptr;
    }
    ResetScanJobStateLocked(kind, path);
    auto* context = new ScanThreadContext();
    context->kind = kind;
    context->path = path;
    g_scanJobThread = CreateThread(nullptr, 0, ScanJobThreadProc, context, 0, nullptr);
    if (g_scanJobThread == nullptr) {
        delete context;
        g_scanJobState = {};
        LeaveCriticalSection(&g_scanLock);
        return ERROR_GEN_FAILURE;
    }
    LeaveCriticalSection(&g_scanLock);
    return ERROR_SUCCESS;
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
        bool shouldLoadBases = false;
        bool shouldRunScheduledScan = false;

        EnterCriticalSection(&g_stateLock);
        refreshTokensNow = g_authState.authenticated && now >= g_authState.nextRefreshAttemptAt;
        refreshLicenseNow = g_authState.authenticated && g_licenseState.hasLicense && now >= g_licenseState.nextRefreshAttemptAt;
        const bool licensed = g_authState.authenticated && g_licenseState.hasLicense;
        LeaveCriticalSection(&g_stateLock);

        EnterCriticalSection(&g_avLock);
        shouldLoadBases = licensed && !g_avEngine.HasBases();
        shouldRunScheduledScan = licensed && g_avEngine.HasBases() && g_scheduleState.enabled && g_scheduleState.nextRunUnix != 0 && now >= g_scheduleState.nextRunUnix;
        LeaveCriticalSection(&g_avLock);

        if (refreshTokensNow) {
            RefreshTokens();
        }
        if (refreshLicenseNow) {
            const LicenseFetchResult result = FetchLicenseStatus();
            if (result == LicenseFetchResult::kNoLicense) {
                EnterCriticalSection(&g_avLock);
                ClearAvStateLocked();
                LeaveCriticalSection(&g_avLock);
            }
        }
        if (shouldLoadBases) {
            LoadAvBases();
        }
        if (shouldRunScheduledScan) {
            ScanSummaryInternal summary;
            ScanFixedDrivesInternal(&summary);
            EnterCriticalSection(&g_avLock);
            g_scheduleState.lastSummary = summary.details;
            g_scheduleState.nextRunUnix = NowUnix() + static_cast<uint64_t>(g_scheduleState.intervalMinutes) * 60;
            LeaveCriticalSection(&g_avLock);
        }
        PollMonitoredDirectories();
    }
    return 0;
}

bool FillDetailsBuffer(const std::wstring& text, wchar_t* details, unsigned long capacity) {
    if (details == nullptr || capacity == 0) {
        return false;
    }
    wcsncpy_s(details, capacity, text.c_str(), _TRUNCATE);
    return true;
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
    ClearAuthAndAvState();
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
    const bool finalHasLicense = g_licenseState.hasLicense;
    const uint64_t finalExpiration = g_licenseState.expiresAtUnix;
    LeaveCriticalSection(&g_stateLock);

    if (!finalHasLicense) {
        *hasLicense = 0;
        *expiresAtUnix = 0;
        return ERROR_NOT_FOUND;
    }

    *hasLicense = 1;
    *expiresAtUnix = static_cast<hyper>(hasCachedLicense ? cachedExpiration : finalExpiration);
    return ERROR_SUCCESS;
}

extern "C" error_status_t ActivateProduct(const wchar_t* activationCode) {
    if (activationCode == nullptr || activationCode[0] == L'\0') {
        return ERROR_INVALID_PARAMETER;
    }
    return ActivateLicense(activationCode) ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

extern "C" error_status_t GetAvBasesInfo(int* loaded, hyper* releaseDateUnix, unsigned long* recordCount) {
    if (loaded == nullptr || releaseDateUnix == nullptr || recordCount == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&g_stateLock);
    const bool authenticated = g_authState.authenticated;
    LeaveCriticalSection(&g_stateLock);
    if (!authenticated) {
        return ERROR_ACCESS_DENIED;
    }

    EnterCriticalSection(&g_avLock);
    const tray::AvBasesInfo info = g_avEngine.GetBasesInfo();
    LeaveCriticalSection(&g_avLock);

    *loaded = info.loaded ? 1 : 0;
    *releaseDateUnix = static_cast<hyper>(info.releaseDateUnix);
    *recordCount = info.recordCount;
    return ERROR_SUCCESS;
}

extern "C" error_status_t ScanFile(const wchar_t* path,
                                   int* malicious,
                                   unsigned long* scannedObjects,
                                   unsigned long* maliciousObjects,
                                   unsigned long* failedObjects,
                                   wchar_t* details,
                                   unsigned long detailsCapacity) {
    if (path == nullptr || malicious == nullptr || scannedObjects == nullptr || maliciousObjects == nullptr || failedObjects == nullptr || details == nullptr || detailsCapacity == 0) {
        return ERROR_INVALID_PARAMETER;
    }
    if (!CanUseAvFeatures()) {
        return ERROR_NOT_FOUND;
    }

    ScanSummaryInternal summary;
    ScanSingleFileInternal(path, &summary);
    *malicious = summary.maliciousObjects != 0 ? 1 : 0;
    *scannedObjects = summary.scannedObjects;
    *maliciousObjects = summary.maliciousObjects;
    *failedObjects = summary.failedObjects;
    const std::wstring text = summary.failedObjects != 0
        ? BuildScanSummaryText(L"Сканирование файла завершено.", summary)
        : (summary.maliciousObjects != 0
            ? BuildScanSummaryText(L"Сканирование файла завершено.", summary)
            : (std::wstring(path) + L" -> чисто"));
    FillDetailsBuffer(text, details, detailsCapacity);
    return ERROR_SUCCESS;
}

extern "C" error_status_t ScanDirectory(const wchar_t* path,
                                        unsigned long* scannedObjects,
                                        unsigned long* maliciousObjects,
                                        unsigned long* failedObjects,
                                        wchar_t* details,
                                        unsigned long detailsCapacity) {
    if (path == nullptr || scannedObjects == nullptr || maliciousObjects == nullptr || failedObjects == nullptr || details == nullptr || detailsCapacity == 0) {
        return ERROR_INVALID_PARAMETER;
    }
    if (!CanUseAvFeatures()) {
        return ERROR_NOT_FOUND;
    }

    ScanSummaryInternal summary;
    ScanDirectoryInternal(path, &summary);
    *scannedObjects = summary.scannedObjects;
    *maliciousObjects = summary.maliciousObjects;
    *failedObjects = summary.failedObjects;
    FillDetailsBuffer(BuildScanSummaryText(L"Сканирование папки завершено.", summary), details, detailsCapacity);
    return ERROR_SUCCESS;
}

extern "C" error_status_t ScanFixedDrives(unsigned long* scannedObjects,
                                          unsigned long* maliciousObjects,
                                          unsigned long* failedObjects,
                                          wchar_t* details,
                                          unsigned long detailsCapacity) {
    if (scannedObjects == nullptr || maliciousObjects == nullptr || failedObjects == nullptr || details == nullptr || detailsCapacity == 0) {
        return ERROR_INVALID_PARAMETER;
    }
    if (!CanUseAvFeatures()) {
        return ERROR_NOT_FOUND;
    }

    ScanSummaryInternal summary;
    ScanFixedDrivesInternal(&summary);
    *scannedObjects = summary.scannedObjects;
    *maliciousObjects = summary.maliciousObjects;
    *failedObjects = summary.failedObjects;
    FillDetailsBuffer(BuildScanSummaryText(L"Сканирование дисков завершено.", summary), details, detailsCapacity);
    return ERROR_SUCCESS;
}

extern "C" error_status_t StartScanDirectory(const wchar_t* path) {
    if (path == nullptr || path[0] == L'\0') {
        return ERROR_INVALID_PARAMETER;
    }
    return StartAsyncScanJob(ScanJobKind::Directory, path);
}

extern "C" error_status_t StartScanFixedDrives() {
    return StartAsyncScanJob(ScanJobKind::FixedDrives, L"");
}

extern "C" error_status_t GetScanProgress(int* running,
                                          int* hasResult,
                                          unsigned long* totalObjects,
                                          unsigned long* completedObjects,
                                          unsigned long* maliciousObjects,
                                          unsigned long* failedObjects,
                                          wchar_t* currentPath,
                                          unsigned long currentPathCapacity,
                                          wchar_t* details,
                                          unsigned long detailsCapacity) {
    if (running == nullptr || hasResult == nullptr || totalObjects == nullptr || completedObjects == nullptr ||
        maliciousObjects == nullptr || failedObjects == nullptr || currentPath == nullptr || currentPathCapacity == 0 ||
        details == nullptr || detailsCapacity == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&g_scanLock);
    *running = g_scanJobState.running ? 1 : 0;
    *hasResult = g_scanJobState.hasResult ? 1 : 0;
    *totalObjects = g_scanJobState.totalObjects;
    *completedObjects = g_scanJobState.completedObjects;
    *maliciousObjects = g_scanJobState.maliciousObjects;
    *failedObjects = g_scanJobState.failedObjects;
    wcsncpy_s(currentPath, currentPathCapacity, g_scanJobState.currentPath.c_str(), _TRUNCATE);
    wcsncpy_s(details, detailsCapacity, g_scanJobState.details.c_str(), _TRUNCATE);
    LeaveCriticalSection(&g_scanLock);
    return ERROR_SUCCESS;
}

extern "C" error_status_t SetScheduledScan(int enabled, unsigned long intervalMinutes) {
    if (intervalMinutes == 0) {
        intervalMinutes = 1;
    }

    EnterCriticalSection(&g_avLock);
    g_scheduleState.enabled = enabled != 0;
    g_scheduleState.intervalMinutes = intervalMinutes;
    g_scheduleState.nextRunUnix = g_scheduleState.enabled ? NowUnix() + static_cast<uint64_t>(intervalMinutes) * 60 : 0;
    LeaveCriticalSection(&g_avLock);
    return ERROR_SUCCESS;
}

extern "C" error_status_t GetScheduledScan(int* enabled, unsigned long* intervalMinutes, hyper* nextRunUnix) {
    if (enabled == nullptr || intervalMinutes == nullptr || nextRunUnix == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&g_avLock);
    *enabled = g_scheduleState.enabled ? 1 : 0;
    *intervalMinutes = g_scheduleState.intervalMinutes;
    *nextRunUnix = static_cast<hyper>(g_scheduleState.nextRunUnix);
    LeaveCriticalSection(&g_avLock);
    return ERROR_SUCCESS;
}

extern "C" error_status_t AddMonitorDirectory(const wchar_t* path) {
    if (path == nullptr || path[0] == L'\0') {
        return ERROR_INVALID_PARAMETER;
    }
    std::error_code error;
    if (!fs::exists(path, error) || !fs::is_directory(path, error)) {
        return ERROR_PATH_NOT_FOUND;
    }

    EnterCriticalSection(&g_avLock);
    const std::wstring directory = path;
    if (std::find(g_monitorState.directories.begin(), g_monitorState.directories.end(), directory) == g_monitorState.directories.end()) {
        g_monitorState.directories.push_back(directory);
    }
    LeaveCriticalSection(&g_avLock);
    return ERROR_SUCCESS;
}

extern "C" error_status_t ClearMonitorDirectories() {
    EnterCriticalSection(&g_avLock);
    g_monitorState.directories.clear();
    g_monitorState.knownWriteTimes.clear();
    g_monitorState.lastSummary.clear();
    LeaveCriticalSection(&g_avLock);
    return ERROR_SUCCESS;
}

extern "C" error_status_t GetMonitorDirectories(wchar_t* buffer, unsigned long bufferCapacity) {
    if (buffer == nullptr || bufferCapacity == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&g_avLock);
    const std::wstring joined = JoinDirectories(g_monitorState.directories);
    LeaveCriticalSection(&g_avLock);
    wcsncpy_s(buffer, bufferCapacity, joined.c_str(), _TRUNCATE);
    return ERROR_SUCCESS;
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
    InitializeCriticalSection(&g_avLock);
    InitializeCriticalSection(&g_scanLock);
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    SetServiceState(SERVICE_START_PENDING, NO_ERROR, 3000);
    const RPC_STATUS rpcStatus = StartRpcServer();
    if (rpcStatus != RPC_S_OK) {
        SetServiceState(SERVICE_STOPPED, rpcStatus, 0);
        if (g_stopEvent != nullptr) {
            CloseHandle(g_stopEvent);
        }
        DeleteCriticalSection(&g_avLock);
        DeleteCriticalSection(&g_scanLock);
        DeleteCriticalSection(&g_stateLock);
        DeleteCriticalSection(&g_processLock);
        return;
    }

    LoadAvBases();
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
    EnterCriticalSection(&g_scanLock);
    HANDLE scanThread = g_scanJobThread;
    LeaveCriticalSection(&g_scanLock);
    if (scanThread != nullptr) {
        WaitForSingleObject(scanThread, 5000);
        CloseHandle(scanThread);
        EnterCriticalSection(&g_scanLock);
        if (g_scanJobThread == scanThread) {
            g_scanJobThread = nullptr;
        }
        LeaveCriticalSection(&g_scanLock);
    }
    TerminateLaunchedProcesses();
    RpcServerUnregisterIf(TrayServiceRpc_v1_0_s_ifspec, nullptr, FALSE);
    if (g_stopEvent != nullptr) {
        CloseHandle(g_stopEvent);
    }
    DeleteCriticalSection(&g_avLock);
    DeleteCriticalSection(&g_scanLock);
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

