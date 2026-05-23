#include <windows.h>
#include <shellapi.h>

#include "rpc_client.h"
#include "service_config.h"
#include "service_utils.h"

#include <string>

namespace {

struct UiMetrics {
    static constexpr int kWindowWidth = 760;
    static constexpr int kWindowHeight = 580;
    static constexpr int kCardTop = 108;
    static constexpr int kCardHeight = 170;
    static constexpr int kLeftCardX = 24;
    static constexpr int kLeftCardWidth = 340;
    static constexpr int kRightCardX = 392;
    static constexpr int kRightCardWidth = 340;
    static constexpr int kBottomCardTop = 302;
    static constexpr int kBottomCardHeight = 210;
};

constexpr wchar_t kWindowClassName[] = L"TrayAppMainWindowClass";
constexpr wchar_t kWindowTitle[] = L"Tray App";
constexpr wchar_t kFileMenuText[] = L"\x0424\x0430\x0439\x043B";
constexpr wchar_t kOpenText[] = L"\x041E\x0442\x043A\x0440\x044B\x0442\x044C";
constexpr wchar_t kExitText[] = L"\x0412\x044B\x0445\x043E\x0434";
constexpr wchar_t kLogoutText[] = L"\x0412\x044B\x0439\x0442\x0438 \x0438\x0437 \x0430\x043A\x043A\x0430\x0443\x043D\x0442\x0430";
constexpr UINT kTrayIconId = 1;
constexpr UINT kTrayMessage = WM_APP + 1;
constexpr UINT kMenuOpenId = 1001;
constexpr UINT kMenuExitId = 1002;
constexpr UINT kWindowMenuExitId = 2001;
constexpr UINT kWindowMenuLogoutId = 2002;
constexpr UINT kPollTimerId = 1;

constexpr int kControlLoginLabel = 3001;
constexpr int kControlLoginEdit = 3002;
constexpr int kControlPasswordLabel = 3003;
constexpr int kControlPasswordEdit = 3004;
constexpr int kControlLoginButton = 3005;
constexpr int kControlLoginError = 3006;
constexpr int kControlActivationLabel = 3007;
constexpr int kControlActivationEdit = 3008;
constexpr int kControlActivationButton = 3009;
constexpr int kControlActivationError = 3010;
constexpr int kControlUserInfo = 3011;
constexpr int kControlLicenseInfo = 3012;
constexpr int kControlAvStatus = 3013;
constexpr int kControlLogoutButton = 3014;
constexpr int kControlBottomInfo = 3015;

struct AppState {
    HINSTANCE instance{};
    HWND window{};
    HMENU mainMenu{};
    HMENU trayMenu{};
    HANDLE mutex{};
    UINT taskbarCreatedMessage{};
    bool trayAdded{false};
    bool serviceLaunchFlag{false};
    bool authenticated{false};
    bool licensed{false};
    bool licenseStatusUnavailable{false};
    std::wstring userName;
    uint64_t expiresAtUnix{};
    HFONT titleFont{};
    HFONT sectionFont{};
    HFONT bodyFont{};
    HFONT smallFont{};
    HBRUSH windowBrush{};
    HBRUSH cardBrush{};
};

AppState g_app;

HMENU ControlIdToMenu(int id) {
    return reinterpret_cast<HMENU>(static_cast<INT_PTR>(id));
}

bool HasCommandFlag(const wchar_t* flag) {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == nullptr) {
        return false;
    }
    bool found = false;
    for (int i = 1; i < argc; ++i) {
        if (lstrcmpiW(argv[i], flag) == 0) {
            found = true;
            break;
        }
    }
    LocalFree(argv);
    return found;
}

bool HasHiddenFlag() {
    return HasCommandFlag(tray::kHiddenArgument) || HasCommandFlag(L"/hidden");
}

std::wstring UnixToLocalDateText(uint64_t unixTime) {
    if (unixTime == 0) {
        return L"-";
    }
    const ULONGLONG ticks = unixTime * 10000000ULL + 116444736000000000ULL;
    FILETIME utc{};
    utc.dwLowDateTime = static_cast<DWORD>(ticks);
    utc.dwHighDateTime = static_cast<DWORD>(ticks >> 32);
    FILETIME local{};
    FileTimeToLocalFileTime(&utc, &local);
    SYSTEMTIME st{};
    FileTimeToSystemTime(&local, &st);
    wchar_t buffer[64]{};
    swprintf_s(buffer, L"%02u.%02u.%04u %02u:%02u", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute);
    return buffer;
}

void SetControlText(int id, const std::wstring& text) {
    SetWindowTextW(GetDlgItem(g_app.window, id), text.c_str());
}

void SetControlVisibility(int id, bool visible) {
    ShowWindow(GetDlgItem(g_app.window, id), visible ? SW_SHOW : SW_HIDE);
}

std::wstring GetControlText(int id) {
    HWND control = GetDlgItem(g_app.window, id);
    const int length = GetWindowTextLengthW(control);
    std::wstring text(length, L'\0');
    GetWindowTextW(control, text.data(), length + 1);
    return text;
}

void ApplyFontToControl(int id, HFONT font) {
    SendMessageW(GetDlgItem(g_app.window, id), WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
}

COLORREF GetStatusColor() {
    if (!g_app.authenticated || !g_app.licensed) {
        return RGB(176, 64, 42);
    }
    return RGB(27, 116, 64);
}

bool CreateUiResources() {
    g_app.windowBrush = CreateSolidBrush(RGB(243, 246, 250));
    g_app.cardBrush = CreateSolidBrush(RGB(255, 255, 255));
    g_app.titleFont = CreateFontW(
        -28, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    g_app.sectionFont = CreateFontW(
        -18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    g_app.bodyFont = CreateFontW(
        -18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    g_app.smallFont = CreateFontW(
        -16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    return g_app.windowBrush != nullptr && g_app.cardBrush != nullptr && g_app.titleFont != nullptr &&
           g_app.sectionFont != nullptr && g_app.bodyFont != nullptr && g_app.smallFont != nullptr;
}

void DeleteUiResources() {
    if (g_app.titleFont != nullptr) DeleteObject(g_app.titleFont);
    if (g_app.sectionFont != nullptr) DeleteObject(g_app.sectionFont);
    if (g_app.bodyFont != nullptr) DeleteObject(g_app.bodyFont);
    if (g_app.smallFont != nullptr) DeleteObject(g_app.smallFont);
    if (g_app.windowBrush != nullptr) DeleteObject(g_app.windowBrush);
    if (g_app.cardBrush != nullptr) DeleteObject(g_app.cardBrush);
    g_app.titleFont = nullptr;
    g_app.sectionFont = nullptr;
    g_app.bodyFont = nullptr;
    g_app.smallFont = nullptr;
    g_app.windowBrush = nullptr;
    g_app.cardBrush = nullptr;
}

void PaintCard(HDC dc, const RECT& rect, const wchar_t* title) {
    HPEN border = CreatePen(PS_SOLID, 1, RGB(220, 227, 234));
    HGDIOBJ oldBrush = SelectObject(dc, g_app.cardBrush);
    HGDIOBJ oldPen = SelectObject(dc, border);
    RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 18, 18);
    SelectObject(dc, g_app.sectionFont);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(35, 47, 62));
    RECT titleRect{rect.left + 20, rect.top + 16, rect.right - 20, rect.top + 48};
    DrawTextW(dc, title, -1, &titleRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    DeleteObject(border);
}

void PaintWindow(HWND hwnd) {
    PAINTSTRUCT ps{};
    HDC dc = BeginPaint(hwnd, &ps);
    RECT client{};
    GetClientRect(hwnd, &client);
    FillRect(dc, &client, g_app.windowBrush);
    SetBkMode(dc, TRANSPARENT);

    RECT hero{0, 0, client.right, 88};
    HBRUSH heroBrush = CreateSolidBrush(RGB(28, 77, 136));
    FillRect(dc, &hero, heroBrush);
    DeleteObject(heroBrush);

    SelectObject(dc, g_app.titleFont);
    SetTextColor(dc, RGB(255, 255, 255));
    RECT titleRect{24, 18, client.right - 24, 52};
    DrawTextW(dc, L"Tray App Security Center", -1, &titleRect, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    SelectObject(dc, g_app.smallFont);
    SetTextColor(dc, RGB(224, 234, 248));
    const wchar_t* subtitle = g_app.authenticated
                                  ? (g_app.licensed ? L"Аккаунт и лицензия активны." : L"Аккаунт подключен, требуется активация.")
                                  : L"Для работы антивируса войдите в аккаунт.";
    RECT subtitleRect{24, 54, client.right - 24, 78};
    DrawTextW(dc, subtitle, -1, &subtitleRect, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    RECT leftCard{UiMetrics::kLeftCardX, UiMetrics::kCardTop, UiMetrics::kLeftCardX + UiMetrics::kLeftCardWidth,
                  UiMetrics::kCardTop + UiMetrics::kCardHeight};
    RECT rightCard{UiMetrics::kRightCardX, UiMetrics::kCardTop, UiMetrics::kRightCardX + UiMetrics::kRightCardWidth,
                   UiMetrics::kCardTop + UiMetrics::kCardHeight};
    RECT bottomCard{UiMetrics::kLeftCardX, UiMetrics::kBottomCardTop, UiMetrics::kRightCardX + UiMetrics::kRightCardWidth,
                    UiMetrics::kBottomCardTop + UiMetrics::kBottomCardHeight};
    PaintCard(dc, leftCard, L"Доступ");
    PaintCard(dc, rightCard, L"Состояние");
    PaintCard(dc, bottomCard, L"Лицензия и защита");
    EndPaint(hwnd, &ps);
}

void ShowMainWindow() {
    ShowWindow(g_app.window, SW_SHOWNORMAL);
    UpdateWindow(g_app.window);
    SetForegroundWindow(g_app.window);
}

void HideMainWindow() {
    ShowWindow(g_app.window, SW_HIDE);
}

bool AddTrayIcon() {
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_app.window;
    nid.uID = kTrayIconId;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = kTrayMessage;
    nid.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    lstrcpynW(nid.szTip, kWindowTitle, ARRAYSIZE(nid.szTip));
    g_app.trayAdded = Shell_NotifyIconW(NIM_ADD, &nid) == TRUE;
    if (g_app.trayAdded) {
        nid.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &nid);
    }
    return g_app.trayAdded;
}

void RemoveTrayIcon() {
    if (!g_app.trayAdded) return;
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_app.window;
    nid.uID = kTrayIconId;
    Shell_NotifyIconW(NIM_DELETE, &nid);
    g_app.trayAdded = false;
}

void ShowTrayMenu() {
    POINT cursor{};
    GetCursorPos(&cursor);
    SetForegroundWindow(g_app.window);
    TrackPopupMenu(g_app.trayMenu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN, cursor.x, cursor.y, 0, g_app.window, nullptr);
    PostMessageW(g_app.window, WM_NULL, 0, 0);
}

void RequestServiceShutdown() {
    if (!tray::RequestServiceStop()) {
        MessageBoxW(g_app.window, L"\x041D\x0435 \x0443\x0434\x0430\x043B\x043E\x0441\x044C \x043E\x0441\x0442\x0430\x043D\x043E\x0432\x0438\x0442\x044C \x0441\x043B\x0443\x0436\x0431\x0443.", kWindowTitle, MB_ICONERROR | MB_OK);
    }
}

void ApplyUiState(const std::wstring& loginError = L"", const std::wstring& activationError = L"") {
    const bool showLogin = !g_app.authenticated;
    const bool showActivation = g_app.authenticated && !g_app.licensed && !g_app.licenseStatusUnavailable;

    SetControlVisibility(kControlLoginLabel, showLogin);
    SetControlVisibility(kControlLoginEdit, showLogin);
    SetControlVisibility(kControlPasswordLabel, showLogin);
    SetControlVisibility(kControlPasswordEdit, showLogin);
    SetControlVisibility(kControlLoginButton, showLogin);
    SetControlVisibility(kControlLoginError, showLogin);

    SetControlVisibility(kControlActivationLabel, showActivation);
    SetControlVisibility(kControlActivationEdit, showActivation);
    SetControlVisibility(kControlActivationButton, showActivation);
    SetControlVisibility(kControlActivationError, showActivation);
    SetControlVisibility(kControlLogoutButton, g_app.authenticated);

    SetControlText(kControlLoginError, loginError);
    SetControlText(kControlActivationError, activationError);

    if (!g_app.authenticated) {
        SetControlText(kControlUserInfo, L"\x041F\x043E\x043B\x044C\x0437\x043E\x0432\x0430\x0442\x0435\x043B\x044C: \x0432\x0445\x043E\x0434 \x043D\x0435 \x0432\x044B\x043F\x043E\x043B\x043D\x0435\x043D");
        SetControlText(kControlLicenseInfo, L"\x041B\x0438\x0446\x0435\x043D\x0437\x0438\x044F: \x043D\x0435\x0442");
        SetControlText(kControlAvStatus, L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441: \x0437\x0430\x0431\x043B\x043E\x043A\x0438\x0440\x043E\x0432\x0430\x043D");
    } else if (g_app.licenseStatusUnavailable) {
        SetControlText(kControlUserInfo, L"\x041F\x043E\x043B\x044C\x0437\x043E\x0432\x0430\x0442\x0435\x043B\x044C: " + g_app.userName);
        SetControlText(kControlLicenseInfo, L"\x041B\x0438\x0446\x0435\x043D\x0437\x0438\x044F: \x0441\x0442\x0430\x0442\x0443\x0441 \x0432\x0440\x0435\x043C\x0435\x043D\x043D\x043E \x043D\x0435\x0434\x043E\x0441\x0442\x0443\x043F\x0435\x043D");
        SetControlText(kControlAvStatus, L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441: \x0437\x0430\x0431\x043B\x043E\x043A\x0438\x0440\x043E\x0432\x0430\x043D");
    } else if (!g_app.licensed) {
        SetControlText(kControlUserInfo, L"\x041F\x043E\x043B\x044C\x0437\x043E\x0432\x0430\x0442\x0435\x043B\x044C: " + g_app.userName);
        SetControlText(kControlLicenseInfo, L"\x041B\x0438\x0446\x0435\x043D\x0437\x0438\x044F: \x043D\x0435 \x0430\x043A\x0442\x0438\x0432\x0438\x0440\x043E\x0432\x0430\x043D\x0430");
        SetControlText(kControlAvStatus, L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441: \x0437\x0430\x0431\x043B\x043E\x043A\x0438\x0440\x043E\x0432\x0430\x043D");
    } else {
        SetControlText(kControlUserInfo, L"\x041F\x043E\x043B\x044C\x0437\x043E\x0432\x0430\x0442\x0435\x043B\x044C: " + g_app.userName);
        SetControlText(kControlLicenseInfo, L"\x041B\x0438\x0446\x0435\x043D\x0437\x0438\x044F \x0434\x043E: " + UnixToLocalDateText(g_app.expiresAtUnix));
        SetControlText(kControlAvStatus, L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441: \x0440\x0430\x0437\x0431\x043B\x043E\x043A\x0438\x0440\x043E\x0432\x0430\x043D");
    }
}

void RefreshStateFromService(const std::wstring& loginError = L"", const std::wstring& activationError = L"") {
    tray::RemoteUserInfo userInfo;
    if (!tray::GetRemoteUserInfo(&userInfo)) {
        g_app.authenticated = false;
        g_app.licensed = false;
        g_app.licenseStatusUnavailable = false;
        g_app.userName.clear();
        g_app.expiresAtUnix = 0;
        ApplyUiState(L"\x041D\x0435 \x0443\x0434\x0430\x043B\x043E\x0441\x044C \x043F\x043E\x043B\x0443\x0447\x0438\x0442\x044C \x0441\x043E\x0441\x0442\x043E\x044F\x043D\x0438\x0435 \x0441\x043B\x0443\x0436\x0431\x044B.", activationError);
        return;
    }

    g_app.authenticated = userInfo.authenticated;
    g_app.userName = userInfo.userName;
    g_app.licensed = false;
    g_app.licenseStatusUnavailable = false;
    g_app.expiresAtUnix = 0;

    if (g_app.authenticated) {
        tray::RemoteLicenseInfo licenseInfo;
        bool noLicense = false;
        if (tray::GetRemoteLicenseInfo(&licenseInfo, &noLicense) && licenseInfo.hasLicense) {
            g_app.licensed = true;
            g_app.expiresAtUnix = licenseInfo.expiresAtUnix;
        } else if (!noLicense) {
            g_app.licenseStatusUnavailable = true;
        }
    }

    const std::wstring finalActivationError =
        g_app.licenseStatusUnavailable
            ? L"\x041D\x0435 \x0443\x0434\x0430\x043B\x043E\x0441\x044C \x043F\x043E\x043B\x0443\x0447\x0438\x0442\x044C \x0441\x0442\x0430\x0442\x0443\x0441 \x043B\x0438\x0446\x0435\x043D\x0437\x0438\x0438."
            : activationError;
    ApplyUiState(loginError, finalActivationError);
}

void HandleLogin() {
    const std::wstring userName = GetControlText(kControlLoginEdit);
    const std::wstring password = GetControlText(kControlPasswordEdit);
    if (!tray::LoginRemoteUser(userName, password)) {
        RefreshStateFromService(L"\x041E\x0448\x0438\x0431\x043A\x0430 \x0430\x0443\x0442\x0435\x043D\x0442\x0438\x0444\x0438\x043A\x0430\x0446\x0438\x0438.", L"");
        return;
    }
    RefreshStateFromService();
}

void HandleActivation() {
    const std::wstring code = GetControlText(kControlActivationEdit);
    if (!tray::ActivateRemoteProduct(code)) {
        RefreshStateFromService(L"", L"\x041E\x0448\x0438\x0431\x043A\x0430 \x0430\x043A\x0442\x0438\x0432\x0430\x0446\x0438\x0438.");
        return;
    }
    RefreshStateFromService();
}

void HandleLogout() {
    tray::LogoutRemoteUser();
    RefreshStateFromService();
}

void CreateControls(HWND hwnd) {
    CreateWindowW(L"STATIC", L"\x041B\x043E\x0433\x0438\x043D", WS_CHILD | WS_VISIBLE, 48, 154, 120, 20, hwnd, ControlIdToMenu(kControlLoginLabel), g_app.instance, nullptr);
    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 48, 178, 200, 28, hwnd, ControlIdToMenu(kControlLoginEdit), g_app.instance, nullptr);
    CreateWindowW(L"STATIC", L"\x041F\x0430\x0440\x043E\x043B\x044C", WS_CHILD | WS_VISIBLE, 48, 214, 120, 20, hwnd, ControlIdToMenu(kControlPasswordLabel), g_app.instance, nullptr);
    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL, 48, 238, 200, 28, hwnd, ControlIdToMenu(kControlPasswordEdit), g_app.instance, nullptr);
    CreateWindowW(L"BUTTON", L"\x0412\x043E\x0439\x0442\x0438", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 264, 178, 76, 30, hwnd, ControlIdToMenu(kControlLoginButton), g_app.instance, nullptr);
    CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 48, 270, 292, 22, hwnd, ControlIdToMenu(kControlLoginError), g_app.instance, nullptr);

    CreateWindowW(L"STATIC", L"\x041A\x043E\x0434 \x0430\x043A\x0442\x0438\x0432\x0430\x0446\x0438\x0438", WS_CHILD | WS_VISIBLE, 48, 352, 180, 20, hwnd, ControlIdToMenu(kControlActivationLabel), g_app.instance, nullptr);
    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 48, 378, 200, 28, hwnd, ControlIdToMenu(kControlActivationEdit), g_app.instance, nullptr);
    CreateWindowW(L"BUTTON", L"\x0410\x043A\x0442\x0438\x0432\x0438\x0440\x043E\x0432\x0430\x0442\x044C", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 264, 378, 112, 30, hwnd, ControlIdToMenu(kControlActivationButton), g_app.instance, nullptr);
    CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 48, 414, 328, 22, hwnd, ControlIdToMenu(kControlActivationError), g_app.instance, nullptr);

    CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 420, 154, 292, 30, hwnd, ControlIdToMenu(kControlUserInfo), g_app.instance, nullptr);
    CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 420, 194, 292, 30, hwnd, ControlIdToMenu(kControlLicenseInfo), g_app.instance, nullptr);
    CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 420, 234, 292, 30, hwnd, ControlIdToMenu(kControlAvStatus), g_app.instance, nullptr);
    CreateWindowW(L"STATIC",
                  L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441\x043D\x0430\x044F \x0444\x0443\x043D\x043A\x0446\x0438\x043E\x043D\x0430\x043B\x044C\x043D\x043E\x0441\x0442\x044C "
                  L"\x0430\x0432\x0442\x043E\x043C\x0430\x0442\x0438\x0447\x0435\x0441\x043A\x0438 \x0431\x043B\x043E\x043A\x0438\x0440\x0443\x0435\x0442\x0441\x044F \x0431\x0435\x0437 "
                  L"\x0430\x0432\x0442\x043E\x0440\x0438\x0437\x0430\x0446\x0438\x0438 \x0438\x043B\x0438 \x043B\x0438\x0446\x0435\x043D\x0437\x0438\x0438.",
                  WS_CHILD | WS_VISIBLE, 48, 454, 660, 54, hwnd, ControlIdToMenu(kControlBottomInfo), g_app.instance, nullptr);
    CreateWindowW(L"BUTTON", kLogoutText, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 556, 36, 176, 34, hwnd, ControlIdToMenu(kControlLogoutButton), g_app.instance, nullptr);

    ApplyFontToControl(kControlLoginLabel, g_app.smallFont);
    ApplyFontToControl(kControlLoginEdit, g_app.bodyFont);
    ApplyFontToControl(kControlPasswordLabel, g_app.smallFont);
    ApplyFontToControl(kControlPasswordEdit, g_app.bodyFont);
    ApplyFontToControl(kControlLoginButton, g_app.smallFont);
    ApplyFontToControl(kControlLoginError, g_app.smallFont);
    ApplyFontToControl(kControlActivationLabel, g_app.smallFont);
    ApplyFontToControl(kControlActivationEdit, g_app.bodyFont);
    ApplyFontToControl(kControlActivationButton, g_app.smallFont);
    ApplyFontToControl(kControlActivationError, g_app.smallFont);
    ApplyFontToControl(kControlUserInfo, g_app.bodyFont);
    ApplyFontToControl(kControlLicenseInfo, g_app.bodyFont);
    ApplyFontToControl(kControlAvStatus, g_app.bodyFont);
    ApplyFontToControl(kControlBottomInfo, g_app.smallFont);
    ApplyFontToControl(kControlLogoutButton, g_app.smallFont);
}

bool CreateMenus() {
    g_app.mainMenu = CreateMenu();
    HMENU fileMenu = CreatePopupMenu();
    g_app.trayMenu = CreatePopupMenu();
    if (g_app.mainMenu == nullptr || fileMenu == nullptr || g_app.trayMenu == nullptr) {
        return false;
    }
    AppendMenuW(fileMenu, MF_STRING, kWindowMenuLogoutId, kLogoutText);
    AppendMenuW(fileMenu, MF_STRING, kWindowMenuExitId, kExitText);
    AppendMenuW(g_app.mainMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), kFileMenuText);
    AppendMenuW(g_app.trayMenu, MF_STRING, kMenuOpenId, kOpenText);
    AppendMenuW(g_app.trayMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(g_app.trayMenu, MF_STRING, kMenuExitId, kExitText);
    return true;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == g_app.taskbarCreatedMessage) {
        AddTrayIcon();
        return 0;
    }

    switch (message) {
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case kMenuOpenId:
                    ShowMainWindow();
                    return 0;
                case kMenuExitId:
                case kWindowMenuExitId:
                    RequestServiceShutdown();
                    return 0;
                case kWindowMenuLogoutId:
                case kControlLogoutButton:
                    HandleLogout();
                    return 0;
                case kControlLoginButton:
                    HandleLogin();
                    return 0;
                case kControlActivationButton:
                    HandleActivation();
                    return 0;
                default:
                    return DefWindowProcW(hwnd, message, wParam, lParam);
            }
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            HWND control = reinterpret_cast<HWND>(lParam);
            const int id = GetDlgCtrlID(control);
            SetBkMode(dc, TRANSPARENT);
            if (id == kControlLoginError || id == kControlActivationError) {
                SetTextColor(dc, RGB(186, 51, 51));
            } else if (id == kControlAvStatus) {
                SetTextColor(dc, GetStatusColor());
            } else if (id == kControlUserInfo || id == kControlLicenseInfo) {
                SetTextColor(dc, RGB(43, 55, 72));
            } else if (id == kControlBottomInfo) {
                SetTextColor(dc, RGB(97, 110, 125));
            } else {
                SetTextColor(dc, RGB(89, 101, 118));
            }
            return reinterpret_cast<LRESULT>(g_app.cardBrush);
        }
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT:
            PaintWindow(hwnd);
            return 0;
        case WM_TIMER:
            if (wParam == kPollTimerId) {
                RefreshStateFromService();
                return 0;
            }
            break;
        case kTrayMessage:
            switch (LOWORD(lParam)) {
                case WM_LBUTTONUP:
                    ShowMainWindow();
                    return 0;
                case WM_RBUTTONUP:
                case WM_CONTEXTMENU:
                    ShowTrayMenu();
                    return 0;
                default:
                    return 0;
            }
        case WM_CLOSE:
            HideMainWindow();
            return 0;
        case WM_DESTROY:
            KillTimer(hwnd, kPollTimerId);
            RemoveTrayIcon();
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(hwnd, message, wParam, lParam);
    }
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

bool RegisterWindowClass() {
    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.lpfnWndProc = WindowProc;
    windowClass.hInstance = g_app.instance;
    windowClass.lpszClassName = kWindowClassName;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    windowClass.hIconSm = LoadIconW(nullptr, IDI_APPLICATION);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(NULL_BRUSH));
    return RegisterClassExW(&windowClass) != 0;
}

bool CreateMainWindow() {
    g_app.window = CreateWindowExW(0, kWindowClassName, kWindowTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                                   UiMetrics::kWindowWidth, UiMetrics::kWindowHeight, nullptr, nullptr, g_app.instance, nullptr);
    if (g_app.window == nullptr) {
        return false;
    }
    SetMenu(g_app.window, g_app.mainMenu);
    CreateControls(g_app.window);
    SetTimer(g_app.window, kPollTimerId, 5000, nullptr);
    return true;
}

bool CreateSingleInstanceMutex() {
    g_app.mutex = CreateMutexW(nullptr, FALSE, tray::kSingleInstanceMutexName);
    if (g_app.mutex == nullptr) {
        return false;
    }
    return GetLastError() != ERROR_ALREADY_EXISTS;
}

void ReleaseResources() {
    if (g_app.mainMenu != nullptr) {
        DestroyMenu(g_app.mainMenu);
        g_app.mainMenu = nullptr;
    }
    DeleteUiResources();
    if (g_app.mutex != nullptr) {
        CloseHandle(g_app.mutex);
        g_app.mutex = nullptr;
    }
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    g_app.serviceLaunchFlag = HasCommandFlag(tray::kServiceLaunchArgument);
    const tray::ServiceBootResult bootResult = tray::EnsureServiceRunning(30000);
    if (bootResult == tray::ServiceBootResult::kFailed) {
        MessageBoxW(nullptr, L"\x041D\x0435 \x0443\x0434\x0430\x043B\x043E\x0441\x044C \x0437\x0430\x043F\x0443\x0441\x0442\x0438\x0442\x044C \x0441\x043B\x0443\x0436\x0431\x0443.", kWindowTitle, MB_ICONERROR | MB_OK);
        return 1;
    }
    if (bootResult == tray::ServiceBootResult::kStartedOrWaited) {
        return 0;
    }
    if (!g_app.serviceLaunchFlag && !tray::IsParentProcessService()) {
        return 0;
    }

    g_app.instance = instance;
    g_app.taskbarCreatedMessage = RegisterWindowMessageW(L"TaskbarCreated");

    if (!CreateSingleInstanceMutex() || !CreateUiResources() || !CreateMenus() || !RegisterWindowClass() || !CreateMainWindow() || !AddTrayIcon()) {
        ReleaseResources();
        return 1;
    }

    RefreshStateFromService();
    if (!HasHiddenFlag()) {
        ShowMainWindow();
    }

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    ReleaseResources();
    return static_cast<int>(message.wParam);
}
