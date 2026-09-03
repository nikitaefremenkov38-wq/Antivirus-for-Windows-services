#include <windows.h>
#include <commdlg.h>
#include <shlobj.h>
#include <shellapi.h>

#include "rpc_client.h"
#include "service_config.h"
#include "service_utils.h"

#include <memory>
#include <string>

namespace {

struct UiMetrics {
    static constexpr int kWindowWidth = 860;
    static constexpr int kWindowHeight = 900;
    static constexpr int kCardTop = 108;
    static constexpr int kCardHeight = 170;
    static constexpr int kLeftCardX = 24;
    static constexpr int kLeftCardWidth = 390;
    static constexpr int kRightCardX = 442;
    static constexpr int kRightCardWidth = 390;
    static constexpr int kBottomCardTop = 302;
    static constexpr int kBottomCardHeight = 520;
};

constexpr wchar_t kWindowClassName[] = L"TrayAppMainWindowClass";
constexpr wchar_t kWindowTitle[] = L"Tray App";
constexpr wchar_t kFileMenuText[] = L"\x0424\x0430\x0439\x043B";
constexpr wchar_t kOpenText[] = L"\x041E\x0442\x043A\x0440\x044B\x0442\x044C";
constexpr wchar_t kExitText[] = L"\x0412\x044B\x0445\x043E\x0434";
constexpr wchar_t kLogoutText[] = L"\x0412\x044B\x0439\x0442\x0438 \x0438\x0437 \x0430\x043A\x043A\x0430\x0443\x043D\x0442\x0430";
constexpr UINT kTrayIconId = 1;
constexpr UINT kTrayMessage = WM_APP + 1;
constexpr UINT kScanFinishedMessage = WM_APP + 20;
constexpr UINT kScanProgressTimerId = 2;
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
constexpr int kControlBasesInfo = 3016;
constexpr int kControlScanFileEdit = 3017;
constexpr int kControlScanFileBrowse = 3018;
constexpr int kControlScanFileButton = 3019;
constexpr int kControlScanDirectoryEdit = 3020;
constexpr int kControlScanDirectoryBrowse = 3021;
constexpr int kControlScanDirectoryButton = 3022;
constexpr int kControlScanAllDrivesButton = 3023;
constexpr int kControlScheduleEdit = 3024;
constexpr int kControlScheduleButton = 3025;
constexpr int kControlScheduleInfo = 3026;
constexpr int kControlMonitorEdit = 3027;
constexpr int kControlMonitorBrowse = 3028;
constexpr int kControlMonitorAdd = 3029;
constexpr int kControlMonitorClear = 3030;
constexpr int kControlMonitorInfo = 3031;
constexpr int kControlScanResult = 3032;
constexpr int kControlScanFileLabel = 3033;
constexpr int kControlScanDirectoryLabel = 3034;
constexpr int kControlScheduleLabel = 3035;
constexpr int kControlMonitorLabel = 3036;
constexpr int kConfirmStopButton = 4001;
constexpr int kConfirmCancelButton = 4002;

constexpr wchar_t kSecureDesktopName[] = L"TrayAppSecureDesktop";
constexpr wchar_t kSecureDialogClassName[] = L"TrayAppSecureDialogClass";

struct SecureDialogContext {
    HANDLE readyEvent{};
    HANDLE doneEvent{};
    HDESK secureDesktop{};
    bool confirmed{false};
    HFONT titleFont{};
    HFONT bodyFont{};
    HFONT buttonFont{};
};

struct AppState {
    enum class ScanMode {
        None,
        File,
        Directory,
        FixedDrives,
    };

    HINSTANCE instance{};
    HWND window{};
    HMENU mainMenu{};
    HMENU trayMenu{};
    HANDLE mutex{};
    UINT taskbarCreatedMessage{};
    bool trayAdded{false};
    bool serviceLaunchFlag{false};
    bool modalUiActive{false};
    bool scanInProgress{false};
    ScanMode scanMode{ScanMode::None};
    bool authenticated{false};
    bool licensed{false};
    bool licenseStatusUnavailable{false};
    bool avBasesLoaded{false};
    std::wstring userName;
    uint64_t expiresAtUnix{};
    uint64_t avBasesReleaseDateUnix{};
    uint32_t avRecordCount{};
    bool scheduledScanEnabled{false};
    uint32_t scheduledScanIntervalMinutes{};
    uint64_t scheduledScanNextRunUnix{};
    std::wstring monitoredDirectories;
    HFONT titleFont{};
    HFONT sectionFont{};
    HFONT bodyFont{};
    HFONT smallFont{};
    HBRUSH windowBrush{};
    HBRUSH cardBrush{};
};

AppState g_app;

struct AsyncScanContext {
    std::wstring path;
};

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

void SetControlEnabled(int id, bool enabled) {
    EnableWindow(GetDlgItem(g_app.window, id), enabled ? TRUE : FALSE);
}

std::wstring GetControlText(int id) {
    HWND control = GetDlgItem(g_app.window, id);
    const int length = GetWindowTextLengthW(control);
    if (length <= 0) {
        return {};
    }
    std::wstring text(length, L'\0');
    GetWindowTextW(control, text.data(), length + 1);
    return text;
}

void ApplyFontToControl(int id, HFONT font) {
    SendMessageW(GetDlgItem(g_app.window, id), WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
}

COLORREF GetStatusColor() {
    if (!g_app.authenticated || !g_app.licensed || !g_app.avBasesLoaded) {
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
                                  ? (g_app.licensed ? L"Аккаунт, лицензия и антивирусные базы активны." : L"Аккаунт подключен, требуется активация продукта.")
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
    PaintCard(dc, bottomCard, L"Сканирование и базы");
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

void PaintSecureDialog(HWND hwnd) {
    PAINTSTRUCT ps{};
    HDC dc = BeginPaint(hwnd, &ps);
    RECT client{};
    GetClientRect(hwnd, &client);

    HBRUSH backgroundBrush = CreateSolidBrush(RGB(0, 0, 0));
    FillRect(dc, &client, backgroundBrush);
    DeleteObject(backgroundBrush);

    RECT panel{0, 0, 620, 260};
    HBRUSH panelBrush = CreateSolidBrush(RGB(255, 255, 255));
    HPEN borderPen = CreatePen(PS_SOLID, 1, RGB(208, 216, 226));
    HGDIOBJ oldBrush = SelectObject(dc, panelBrush);
    HGDIOBJ oldPen = SelectObject(dc, borderPen);
    RoundRect(dc, panel.left, panel.top, panel.right, panel.bottom, 18, 18);
    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    DeleteObject(panelBrush);
    DeleteObject(borderPen);

    auto* context = reinterpret_cast<SecureDialogContext*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    SetBkMode(dc, TRANSPARENT);

    if (context != nullptr && context->titleFont != nullptr) {
        SelectObject(dc, context->titleFont);
    }
    SetTextColor(dc, RGB(25, 39, 56));
    RECT titleRect{32, 36, panel.right - 32, 76};
    DrawTextW(dc, L"Подтверждение остановки службы", -1, &titleRect, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    if (context != nullptr && context->bodyFont != nullptr) {
        SelectObject(dc, context->bodyFont);
    }
    SetTextColor(dc, RGB(89, 101, 118));
    RECT bodyRect{32, 90, panel.right - 32, 168};
    DrawTextW(dc,
              L"Вы действительно хотите остановить службу Tray App? "
              L"Антивирусная защита и фоновые процессы будут остановлены.",
              -1, &bodyRect, DT_LEFT | DT_WORDBREAK);
    EndPaint(hwnd, &ps);
}

LRESULT CALLBACK SecureDialogProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_NCCREATE: {
            const auto* createStruct = reinterpret_cast<CREATESTRUCTW*>(lParam);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(createStruct->lpCreateParams));
            return TRUE;
        }
        case WM_CREATE: {
            auto* context = reinterpret_cast<SecureDialogContext*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
            CreateWindowW(L"BUTTON", L"\x041E\x0441\x0442\x0430\x043D\x043E\x0432\x0438\x0442\x044C",
                          WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 138, 198, 150, 36, hwnd,
                          ControlIdToMenu(kConfirmStopButton), g_app.instance, nullptr);
            CreateWindowW(L"BUTTON", L"\x041E\x0442\x043C\x0435\x043D\x0430",
                          WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 308, 198, 120, 36, hwnd,
                          ControlIdToMenu(kConfirmCancelButton), g_app.instance, nullptr);
            if (context != nullptr) {
                SendMessageW(GetDlgItem(hwnd, kConfirmStopButton), WM_SETFONT, reinterpret_cast<WPARAM>(context->buttonFont), TRUE);
                SendMessageW(GetDlgItem(hwnd, kConfirmCancelButton), WM_SETFONT, reinterpret_cast<WPARAM>(context->buttonFont), TRUE);
                SetEvent(context->readyEvent);
            }
            return 0;
        }
        case WM_COMMAND: {
            auto* context = reinterpret_cast<SecureDialogContext*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
            if (LOWORD(wParam) == kConfirmStopButton) {
                if (context != nullptr) {
                    context->confirmed = true;
                }
                DestroyWindow(hwnd);
                return 0;
            }
            if (LOWORD(wParam) == kConfirmCancelButton) {
                DestroyWindow(hwnd);
                return 0;
            }
            break;
        }
        case WM_CTLCOLORBTN:
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            SetBkMode(dc, TRANSPARENT);
            if (message == WM_CTLCOLORSTATIC) {
                SetTextColor(dc, RGB(89, 101, 118));
            }
            return reinterpret_cast<LRESULT>(GetStockObject(WHITE_BRUSH));
        }
        case WM_KEYDOWN:
            if (wParam == VK_ESCAPE) {
                DestroyWindow(hwnd);
                return 0;
            }
            break;
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_PAINT:
            PaintSecureDialog(hwnd);
            return 0;
        case WM_DESTROY: {
            auto* context = reinterpret_cast<SecureDialogContext*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
            if (context != nullptr) {
                SetEvent(context->doneEvent);
            }
            PostQuitMessage(0);
            return 0;
        }
        default:
            break;
    }
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

DWORD WINAPI SecureDialogThreadProc(LPVOID parameter) {
    auto* context = reinterpret_cast<SecureDialogContext*>(parameter);
    if (context == nullptr || context->secureDesktop == nullptr) {
        return 1;
    }

    if (!SetThreadDesktop(context->secureDesktop)) {
        SetEvent(context->readyEvent);
        SetEvent(context->doneEvent);
        return 1;
    }

    context->titleFont = CreateFontW(-24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                     CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    context->bodyFont = CreateFontW(-18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                    CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    context->buttonFont = CreateFontW(-18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                      CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.lpfnWndProc = SecureDialogProc;
    windowClass.hInstance = g_app.instance;
    windowClass.lpszClassName = kSecureDialogClassName;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    RegisterClassExW(&windowClass);

    const int width = 620;
    const int height = 260;
    const int x = (GetSystemMetrics(SM_CXSCREEN) - width) / 2;
    const int y = (GetSystemMetrics(SM_CYSCREEN) - height) / 2;
    HWND window = CreateWindowExW(WS_EX_TOPMOST, kSecureDialogClassName, L"", WS_POPUP | WS_VISIBLE, x, y, width, height,
                                  nullptr, nullptr, g_app.instance, context);
    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    if (context->titleFont != nullptr) DeleteObject(context->titleFont);
    if (context->bodyFont != nullptr) DeleteObject(context->bodyFont);
    if (context->buttonFont != nullptr) DeleteObject(context->buttonFont);
    return 0;
}

bool ShowSecureStopConfirmation() {
    HDESK originalDesktop = OpenInputDesktop(0, FALSE, DESKTOP_SWITCHDESKTOP);
    if (originalDesktop == nullptr) {
        return false;
    }

    HDESK secureDesktop = CreateDesktopW(kSecureDesktopName, nullptr, nullptr, 0, GENERIC_ALL, nullptr);
    if (secureDesktop == nullptr) {
        CloseDesktop(originalDesktop);
        return false;
    }

    SecureDialogContext context{};
    context.readyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    context.doneEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    context.secureDesktop = secureDesktop;

    HANDLE thread = CreateThread(nullptr, 0, SecureDialogThreadProc, &context, 0, nullptr);
    if (thread == nullptr) {
        CloseHandle(context.readyEvent);
        CloseHandle(context.doneEvent);
        CloseDesktop(secureDesktop);
        CloseDesktop(originalDesktop);
        return false;
    }

    WaitForSingleObject(context.readyEvent, 5000);
    SwitchDesktop(secureDesktop);
    WaitForSingleObject(context.doneEvent, INFINITE);
    SwitchDesktop(originalDesktop);

    WaitForSingleObject(thread, 5000);
    CloseHandle(thread);
    CloseHandle(context.readyEvent);
    CloseHandle(context.doneEvent);
    CloseDesktop(secureDesktop);
    CloseDesktop(originalDesktop);
    return context.confirmed;
}

void RequestServiceShutdown() {
    if (!ShowSecureStopConfirmation()) {
        return;
    }
    if (!tray::RequestServiceStop()) {
        MessageBoxW(g_app.window, L"\x041D\x0435 \x0443\x0434\x0430\x043B\x043E\x0441\x044C \x043E\x0441\x0442\x0430\x043D\x043E\x0432\x0438\x0442\x044C \x0441\x043B\x0443\x0436\x0431\x0443.", kWindowTitle, MB_ICONERROR | MB_OK);
    }
}

void SetScanDetails(const std::wstring& text) {
    SetControlText(kControlScanResult, text.empty() ? L"\x0420\x0435\x0437\x0443\x043B\x044C\x0442\x0430\x0442\x044B \x0441\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x043D\x0438\x044F \x043F\x043E\x044F\x0432\x044F\x0442\x0441\x044F \x0437\x0434\x0435\x0441\x044C." : text);
}

std::wstring ChooseFilePath(HWND owner) {
    g_app.modalUiActive = true;
    wchar_t buffer[MAX_PATH]{};
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = owner;
    dialog.lpstrFile = buffer;
    dialog.nMaxFile = ARRAYSIZE(buffer);
    dialog.lpstrFilter = L"\x0412\x0441\x0435 \x0444\x0430\x0439\x043B\x044B\0*.*\0";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&dialog)) {
        g_app.modalUiActive = false;
        return {};
    }
    g_app.modalUiActive = false;
    return buffer;
}

std::wstring ChooseFolderPath(HWND owner) {
    g_app.modalUiActive = true;
    BROWSEINFOW browse{};
    browse.hwndOwner = owner;
    browse.lpszTitle = L"\x0412\x044B\x0431\x0435\x0440\x0438\x0442\x0435 \x043F\x0430\x043F\x043A\x0443";
    browse.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE item = SHBrowseForFolderW(&browse);
    if (item == nullptr) {
        g_app.modalUiActive = false;
        return {};
    }
    wchar_t buffer[MAX_PATH]{};
    SHGetPathFromIDListW(item, buffer);
    CoTaskMemFree(item);
    g_app.modalUiActive = false;
    return buffer;
}

void SetAvControlsEnabled(bool enabled) {
    const int ids[] = {
        kControlScanFileEdit, kControlScanFileBrowse, kControlScanFileButton,
        kControlScanDirectoryEdit, kControlScanDirectoryBrowse, kControlScanDirectoryButton,
        kControlScanAllDrivesButton, kControlScheduleEdit, kControlScheduleButton,
        kControlMonitorEdit, kControlMonitorBrowse, kControlMonitorAdd, kControlMonitorClear
    };
    for (int id : ids) {
        SetControlEnabled(id, enabled);
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
        SetControlText(kControlBasesInfo, L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441\x043D\x044B\x0435 \x0431\x0430\x0437\x044B \x0431\x0443\x0434\x0443\x0442 \x0437\x0430\x0433\x0440\x0443\x0436\x0435\x043D\x044B \x043F\x043E\x0441\x043B\x0435 \x0430\x043A\x0442\x0438\x0432\x0430\x0446\x0438\x0438 \x043B\x0438\x0446\x0435\x043D\x0437\x0438\x0438.");
    } else if (g_app.licenseStatusUnavailable) {
        SetControlText(kControlUserInfo, L"\x041F\x043E\x043B\x044C\x0437\x043E\x0432\x0430\x0442\x0435\x043B\x044C: " + g_app.userName);
        SetControlText(kControlLicenseInfo, L"\x041B\x0438\x0446\x0435\x043D\x0437\x0438\x044F: \x0441\x0442\x0430\x0442\x0443\x0441 \x0432\x0440\x0435\x043C\x0435\x043D\x043D\x043E \x043D\x0435\x0434\x043E\x0441\x0442\x0443\x043F\x0435\x043D");
        SetControlText(kControlAvStatus, L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441: \x0437\x0430\x0431\x043B\x043E\x043A\x0438\x0440\x043E\x0432\x0430\x043D");
        SetControlText(kControlBasesInfo, L"\x0421\x0442\x0430\x0442\x0443\x0441 \x0431\x0430\x0437 \x0432\x0440\x0435\x043C\x0435\x043D\x043D\x043E \x043D\x0435\x0434\x043E\x0441\x0442\x0443\x043F\x0435\x043D \x0438\x0437-\x0437\x0430 \x043E\x0448\x0438\x0431\x043A\x0438 \x043B\x0438\x0446\x0435\x043D\x0437\x0438\x0438.");
    } else if (!g_app.licensed) {
        SetControlText(kControlUserInfo, L"\x041F\x043E\x043B\x044C\x0437\x043E\x0432\x0430\x0442\x0435\x043B\x044C: " + g_app.userName);
        SetControlText(kControlLicenseInfo, L"\x041B\x0438\x0446\x0435\x043D\x0437\x0438\x044F: \x043D\x0435 \x0430\x043A\x0442\x0438\x0432\x0438\x0440\x043E\x0432\x0430\x043D\x0430");
        SetControlText(kControlAvStatus, L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441: \x0437\x0430\x0431\x043B\x043E\x043A\x0438\x0440\x043E\x0432\x0430\x043D");
        SetControlText(kControlBasesInfo, L"\x041F\x043E\x0441\x043B\x0435 \x0443\x0441\x043F\x0435\x0448\x043D\x043E\x0439 \x0430\x043A\x0442\x0438\x0432\x0430\x0446\x0438\x0438 \x0441\x043B\x0443\x0436\x0431\x0430 \x0437\x0430\x0433\x0440\x0443\x0437\x0438\x0442 \x0430\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441\x043D\x044B\x0435 \x0431\x0430\x0437\x044B \x0432 \x043F\x0430\x043C\x044F\x0442\x044C.");
    } else {
        SetControlText(kControlUserInfo, L"\x041F\x043E\x043B\x044C\x0437\x043E\x0432\x0430\x0442\x0435\x043B\x044C: " + g_app.userName);
        SetControlText(kControlLicenseInfo, L"\x041B\x0438\x0446\x0435\x043D\x0437\x0438\x044F \x0434\x043E: " + UnixToLocalDateText(g_app.expiresAtUnix));
        SetControlText(kControlAvStatus, g_app.avBasesLoaded ? L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441: \x0430\x043A\x0442\x0438\x0432\x0435\x043D" : L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441: \x0431\x0430\x0437\x044B \x0437\x0430\x0433\x0440\x0443\x0436\x0430\x044E\x0442\x0441\x044F");
        if (g_app.avBasesLoaded) {
            SetControlText(kControlBasesInfo,
                L"\x0411\x0430\x0437\x044B: \x0432\x044B\x043F\x0443\x0441\x043A " + UnixToLocalDateText(g_app.avBasesReleaseDateUnix) +
                L", \x0437\x0430\x043F\x0438\x0441\x0435\x0439: " + std::to_wstring(g_app.avRecordCount));
        } else {
            SetControlText(kControlBasesInfo, L"\x0411\x0430\x0437\x044B \x0435\x0449\x0435 \x043D\x0435 \x0437\x0430\x0433\x0440\x0443\x0436\x0435\x043D\x044B.");
        }
    }

    std::wstring scheduleText = g_app.scheduledScanEnabled
        ? (L"\x0420\x0430\x0441\x043F\x0438\x0441\x0430\x043D\x0438\x0435: \x043A\x0430\x0436\x0434\x044B\x0435 " + std::to_wstring(g_app.scheduledScanIntervalMinutes) + L" \x043C\x0438\x043D., \x0441\x043B\x0435\x0434\x0443\x044E\x0449\x0438\x0439 \x0437\x0430\x043F\x0443\x0441\x043A: " + UnixToLocalDateText(g_app.scheduledScanNextRunUnix))
        : L"\x0420\x0430\x0441\x043F\x0438\x0441\x0430\x043D\x0438\x0435: \x0432\x044B\x043A\x043B\x044E\x0447\x0435\x043D\x043E";
    SetControlText(kControlScheduleInfo, scheduleText);
    SetControlText(kControlMonitorInfo, g_app.monitoredDirectories.empty() ? L"\x041C\x043E\x043D\x0438\x0442\x043E\x0440\x0438\x043D\x0433: \x043F\x0430\x043F\x043A\x0438 \x043D\x0435 \x0432\x044B\x0431\x0440\x0430\x043D\x044B" : L"\x041C\x043E\x043D\x0438\x0442\x043E\x0440\x0438\x043D\x0433: " + g_app.monitoredDirectories);
    SetControlText(kControlBottomInfo,
        L"\x0414\x0432\x0438\x0436\x043E\x043A \x0441\x043A\x0430\x043D\x0438\x0440\x0443\x0435\x0442 \x0444\x0430\x0439\x043B\x044B \x0438 \x0434\x0438\x0440\x0435\x043A\x0442\x043E\x0440\x0438\x0438, \x0438\x0441\x043F\x043E\x043B\x044C\x0437\x0443\x0435\x0442 in-memory \x0431\x0430\x0437\x044B \x0438 \x043E\x0431\x043D\x043E\x0432\x043B\x044F\x0435\x0442 \x0441\x043E\x0441\x0442\x043E\x044F\x043D\x0438\x0435 \x043F\x043E RPC. \x0411\x043E\x043D\x0443\x0441\x043D\x044B\x0435 \x0441\x0446\x0435\x043D\x0430\x0440\x0438\x0438 \x0442\x043E\x0436\x0435 \x0434\x043E\x0441\x0442\x0443\x043F\x043D\x044B.");

    SetAvControlsEnabled(g_app.authenticated && g_app.licensed && g_app.avBasesLoaded && !g_app.licenseStatusUnavailable);
}

void RefreshStateFromService(const std::wstring& loginError = L"", const std::wstring& activationError = L"") {
    tray::RemoteUserInfo userInfo;
    if (!tray::GetRemoteUserInfo(&userInfo)) {
        g_app.authenticated = false;
        g_app.licensed = false;
        g_app.licenseStatusUnavailable = false;
        g_app.avBasesLoaded = false;
        g_app.userName.clear();
        g_app.expiresAtUnix = 0;
        g_app.avBasesReleaseDateUnix = 0;
        g_app.avRecordCount = 0;
        ApplyUiState(L"\x041D\x0435 \x0443\x0434\x0430\x043B\x043E\x0441\x044C \x043F\x043E\x043B\x0443\x0447\x0438\x0442\x044C \x0441\x043E\x0441\x0442\x043E\x044F\x043D\x0438\x0435 \x0441\x043B\x0443\x0436\x0431\x044B.", activationError);
        return;
    }

    g_app.authenticated = userInfo.authenticated;
    g_app.userName = userInfo.userName;
    g_app.licensed = false;
    g_app.licenseStatusUnavailable = false;
    g_app.avBasesLoaded = false;
    g_app.expiresAtUnix = 0;
    g_app.avBasesReleaseDateUnix = 0;
    g_app.avRecordCount = 0;
    g_app.scheduledScanEnabled = false;
    g_app.scheduledScanIntervalMinutes = 0;
    g_app.scheduledScanNextRunUnix = 0;
    g_app.monitoredDirectories.clear();

    if (g_app.authenticated) {
        tray::RemoteLicenseInfo licenseInfo;
        bool noLicense = false;
        if (tray::GetRemoteLicenseInfo(&licenseInfo, &noLicense) && licenseInfo.hasLicense) {
            g_app.licensed = true;
            g_app.expiresAtUnix = licenseInfo.expiresAtUnix;

            tray::RemoteAvBasesInfo basesInfo;
            if (tray::GetRemoteAvBasesInfo(&basesInfo)) {
                g_app.avBasesLoaded = basesInfo.loaded;
                g_app.avBasesReleaseDateUnix = basesInfo.releaseDateUnix;
                g_app.avRecordCount = basesInfo.recordCount;
            }

            tray::RemoteScheduleInfo scheduleInfo;
            if (tray::GetRemoteScheduledScan(&scheduleInfo)) {
                g_app.scheduledScanEnabled = scheduleInfo.enabled;
                g_app.scheduledScanIntervalMinutes = scheduleInfo.intervalMinutes;
                g_app.scheduledScanNextRunUnix = scheduleInfo.nextRunUnix;
            }

            std::wstring monitorDirectories;
            if (tray::GetRemoteMonitorDirectories(&monitorDirectories)) {
                g_app.monitoredDirectories = monitorDirectories;
            }
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
    SetScanDetails(L"\x0420\x0435\x0437\x0443\x043B\x044C\x0442\x0430\x0442\x044B \x0441\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x043D\x0438\x044F \x043F\x043E\x044F\x0432\x044F\x0442\x0441\x044F \x0437\x0434\x0435\x0441\x044C.");
}

DWORD WINAPI AsyncScanThreadProc(LPVOID parameter) {
    std::unique_ptr<AsyncScanContext> context(reinterpret_cast<AsyncScanContext*>(parameter));
    auto* result = new std::wstring();
    tray::RemoteScanResult scanResult;
    const bool ok = tray::ScanRemoteFile(context->path, &scanResult);
    if (!ok) {
        *result = L"\x041D\x0435 \x0443\x0434\x0430\x043B\x043E\x0441\x044C \x0437\x0430\x043F\x0443\x0441\x0442\x0438\x0442\x044C \x0441\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x043D\x0438\x0435 \x0444\x0430\x0439\x043B\x0430.";
    }

    if (ok) {
        *result = scanResult.details;
    }

    PostMessageW(g_app.window, kScanFinishedMessage, 0, reinterpret_cast<LPARAM>(result));
    return 0;
}

void StartAsyncFileScan(const std::wstring& path) {
    if (g_app.scanInProgress) {
        SetScanDetails(L"\x0421\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x043D\x0438\x0435 \x0443\x0436\x0435 \x0432\x044B\x043F\x043E\x043B\x043D\x044F\x0435\x0442\x0441\x044F.");
        return;
    }
    auto* context = new AsyncScanContext();
    context->path = path;

    g_app.scanInProgress = true;
    g_app.scanMode = AppState::ScanMode::File;
    SetScanDetails(L"\x0421\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x043D\x0438\x0435 \x0437\x0430\x043F\x0443\x0449\x0435\x043D\x043E, \x043F\x043E\x0434\x043E\x0436\x0434\x0438\x0442\x0435...");

    HANDLE thread = CreateThread(nullptr, 0, AsyncScanThreadProc, context, 0, nullptr);
    if (thread == nullptr) {
        g_app.scanInProgress = false;
        g_app.scanMode = AppState::ScanMode::None;
        delete context;
        SetScanDetails(L"\x041D\x0435 \x0443\x0434\x0430\x043B\x043E\x0441\x044C \x0437\x0430\x043F\x0443\x0441\x0442\x0438\x0442\x044C \x0444\x043E\x043D\x043E\x0432\x043E\x0435 \x0441\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x043D\x0438\x0435.");
        return;
    }
    CloseHandle(thread);
}

void UpdateRemoteScanProgress() {
    tray::RemoteScanProgress progress;
    if (!tray::GetRemoteScanProgress(&progress)) {
        SetScanDetails(L"Не удалось получить прогресс сканирования.");
        g_app.scanInProgress = false;
        g_app.scanMode = AppState::ScanMode::None;
        KillTimer(g_app.window, kScanProgressTimerId);
        return;
    }

    if (progress.running) {
        const uint32_t total = progress.totalObjects;
        const uint32_t completed = progress.completedObjects;
        const uint32_t percent = total == 0 ? 0u : static_cast<uint32_t>((static_cast<uint64_t>(completed) * 100ULL) / total);
        std::wstring text = L"Идет сканирование: " + std::to_wstring(percent) + L"%\r\n";
        text += L"Проверено файлов: " + std::to_wstring(completed) + L" из " + std::to_wstring(total) + L"\r\n";
        text += L"Угроз: " + std::to_wstring(progress.maliciousObjects) + L", ошибок: " + std::to_wstring(progress.failedObjects);
        if (!progress.currentPath.empty()) {
            text += L"\r\nТекущий объект: " + progress.currentPath;
        }
        SetScanDetails(text);
        return;
    }

    if (progress.hasResult) {
        SetScanDetails(progress.details);
    } else {
        SetScanDetails(L"Сканирование завершилось без результата.");
    }
    g_app.scanInProgress = false;
    g_app.scanMode = AppState::ScanMode::None;
    KillTimer(g_app.window, kScanProgressTimerId);
    RefreshStateFromService();
}

void HandleScanFile() {
    StartAsyncFileScan(GetControlText(kControlScanFileEdit));
}

void HandleScanDirectory() {
    if (g_app.scanInProgress) {
        SetScanDetails(L"Сканирование уже выполняется.");
        return;
    }
    const std::wstring path = GetControlText(kControlScanDirectoryEdit);
    unsigned long status = ERROR_SUCCESS;
    if (!tray::StartRemoteDirectoryScan(path, &status)) {
        SetScanDetails(status == ERROR_BUSY ? L"Дождитесь завершения текущего сканирования."
                                           : L"Не удалось запустить сканирование папки.");
        return;
    }
    g_app.scanInProgress = true;
    g_app.scanMode = AppState::ScanMode::Directory;
    SetScanDetails(L"Подготовка списка файлов для сканирования папки...");
    SetTimer(g_app.window, kScanProgressTimerId, 500, nullptr);
}

void HandleScanAllDrives() {
    if (g_app.scanInProgress) {
        SetScanDetails(L"Сканирование уже выполняется.");
        return;
    }
    unsigned long status = ERROR_SUCCESS;
    if (!tray::StartRemoteFixedDrivesScan(&status)) {
        SetScanDetails(status == ERROR_BUSY ? L"Дождитесь завершения текущего сканирования."
                                           : L"Не удалось запустить сканирование дисков.");
        return;
    }
    g_app.scanInProgress = true;
    g_app.scanMode = AppState::ScanMode::FixedDrives;
    SetScanDetails(L"Подготовка списка файлов на дисках...");
    SetTimer(g_app.window, kScanProgressTimerId, 500, nullptr);
}

void HandleToggleSchedule() {
    const std::wstring intervalText = GetControlText(kControlScheduleEdit);
    const uint32_t interval = intervalText.empty() ? 1u : static_cast<uint32_t>(_wtoi(intervalText.c_str()));
    if (!tray::SetRemoteScheduledScan(!g_app.scheduledScanEnabled, interval == 0 ? 1u : interval)) {
        SetScanDetails(L"\x041D\x0435 \x0443\x0434\x0430\x043B\x043E\x0441\x044C \x043E\x0431\x043D\x043E\x0432\x0438\x0442\x044C \x0440\x0430\x0441\x043F\x0438\x0441\x0430\x043D\x0438\x0435 \x0441\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x043D\x0438\x044F.");
        return;
    }
    RefreshStateFromService();
}

void HandleAddMonitorDirectory() {
    const std::wstring path = GetControlText(kControlMonitorEdit);
    if (!tray::AddRemoteMonitorDirectory(path)) {
        SetScanDetails(L"\x041D\x0435 \x0443\x0434\x0430\x043B\x043E\x0441\x044C \x0434\x043E\x0431\x0430\x0432\x0438\x0442\x044C \x043F\x0430\x043F\x043A\x0443 \x0432 \x043C\x043E\x043D\x0438\x0442\x043E\x0440\x0438\x043D\x0433.");
        return;
    }
    RefreshStateFromService();
}

void HandleClearMonitorDirectories() {
    if (!tray::ClearRemoteMonitorDirectories()) {
        SetScanDetails(L"\x041D\x0435 \x0443\x0434\x0430\x043B\x043E\x0441\x044C \x043E\x0447\x0438\x0441\x0442\x0438\x0442\x044C \x0441\x043F\x0438\x0441\x043E\x043A \x043C\x043E\x043D\x0438\x0442\x043E\x0440\x0438\x043D\x0433\x0430.");
        return;
    }
    RefreshStateFromService();
}

void CreateControls(HWND hwnd) {
    CreateWindowW(L"STATIC", L"\x041B\x043E\x0433\x0438\x043D", WS_CHILD | WS_VISIBLE, 48, 154, 120, 20, hwnd, ControlIdToMenu(kControlLoginLabel), g_app.instance, nullptr);
    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 48, 178, 220, 28, hwnd, ControlIdToMenu(kControlLoginEdit), g_app.instance, nullptr);
    CreateWindowW(L"STATIC", L"\x041F\x0430\x0440\x043E\x043B\x044C", WS_CHILD | WS_VISIBLE, 48, 214, 120, 20, hwnd, ControlIdToMenu(kControlPasswordLabel), g_app.instance, nullptr);
    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL, 48, 238, 220, 28, hwnd, ControlIdToMenu(kControlPasswordEdit), g_app.instance, nullptr);
    CreateWindowW(L"BUTTON", L"\x0412\x043E\x0439\x0442\x0438", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 284, 178, 88, 30, hwnd, ControlIdToMenu(kControlLoginButton), g_app.instance, nullptr);
    CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 48, 270, 324, 22, hwnd, ControlIdToMenu(kControlLoginError), g_app.instance, nullptr);

    CreateWindowW(L"STATIC", L"\x041A\x043E\x0434 \x0430\x043A\x0442\x0438\x0432\x0430\x0446\x0438\x0438", WS_CHILD | WS_VISIBLE, 48, 154, 180, 20, hwnd, ControlIdToMenu(kControlActivationLabel), g_app.instance, nullptr);
    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 48, 178, 220, 28, hwnd, ControlIdToMenu(kControlActivationEdit), g_app.instance, nullptr);
    CreateWindowW(L"BUTTON", L"\x0410\x043A\x0442\x0438\x0432\x0438\x0440\x043E\x0432\x0430\x0442\x044C", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 284, 178, 120, 30, hwnd, ControlIdToMenu(kControlActivationButton), g_app.instance, nullptr);
    CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 48, 214, 356, 22, hwnd, ControlIdToMenu(kControlActivationError), g_app.instance, nullptr);

    CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 470, 154, 324, 30, hwnd, ControlIdToMenu(kControlUserInfo), g_app.instance, nullptr);
    CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 470, 194, 324, 30, hwnd, ControlIdToMenu(kControlLicenseInfo), g_app.instance, nullptr);
    CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 470, 234, 324, 30, hwnd, ControlIdToMenu(kControlAvStatus), g_app.instance, nullptr);
    CreateWindowW(L"BUTTON", kLogoutText, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 628, 36, 204, 34, hwnd, ControlIdToMenu(kControlLogoutButton), g_app.instance, nullptr);

    CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 48, 348, 760, 24, hwnd, ControlIdToMenu(kControlBasesInfo), g_app.instance, nullptr);
    CreateWindowW(L"STATIC", L"\x0424\x0430\x0439\x043B \x0434\x043B\x044F \x0441\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x043D\x0438\x044F", WS_CHILD | WS_VISIBLE, 48, 386, 200, 20, hwnd, ControlIdToMenu(kControlScanFileLabel), g_app.instance, nullptr);
    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 48, 410, 520, 28, hwnd, ControlIdToMenu(kControlScanFileEdit), g_app.instance, nullptr);
    CreateWindowW(L"BUTTON", L"\x041E\x0431\x0437\x043E\x0440", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 580, 410, 90, 28, hwnd, ControlIdToMenu(kControlScanFileBrowse), g_app.instance, nullptr);
    CreateWindowW(L"BUTTON", L"\x0421\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x0442\x044C \x0444\x0430\x0439\x043B", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 682, 410, 126, 28, hwnd, ControlIdToMenu(kControlScanFileButton), g_app.instance, nullptr);

    CreateWindowW(L"STATIC", L"\x041F\x0430\x043F\x043A\x0430 \x0434\x043B\x044F \x0441\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x043D\x0438\x044F", WS_CHILD | WS_VISIBLE, 48, 452, 220, 20, hwnd, ControlIdToMenu(kControlScanDirectoryLabel), g_app.instance, nullptr);
    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 48, 476, 520, 28, hwnd, ControlIdToMenu(kControlScanDirectoryEdit), g_app.instance, nullptr);
    CreateWindowW(L"BUTTON", L"\x041E\x0431\x0437\x043E\x0440", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 580, 476, 90, 28, hwnd, ControlIdToMenu(kControlScanDirectoryBrowse), g_app.instance, nullptr);
    CreateWindowW(L"BUTTON", L"\x0421\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x0442\x044C \x043F\x0430\x043F\x043A\x0443", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 682, 476, 126, 28, hwnd, ControlIdToMenu(kControlScanDirectoryButton), g_app.instance, nullptr);

    CreateWindowW(L"BUTTON", L"\x0421\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x0442\x044C \x0432\x0441\x0435 \x0434\x0438\x0441\x043A\x0438", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 48, 522, 220, 30, hwnd, ControlIdToMenu(kControlScanAllDrivesButton), g_app.instance, nullptr);

    CreateWindowW(L"STATIC", L"\x0420\x0430\x0441\x043F\x0438\x0441\x0430\x043D\x0438\x0435 (\x043C\x0438\x043D\x0443\x0442\x044B)", WS_CHILD | WS_VISIBLE, 48, 568, 170, 20, hwnd, ControlIdToMenu(kControlScheduleLabel), g_app.instance, nullptr);
    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"15", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 220, 566, 70, 28, hwnd, ControlIdToMenu(kControlScheduleEdit), g_app.instance, nullptr);
    CreateWindowW(L"BUTTON", L"\x0412\x043A\x043B/\x0432\x044B\x043A\x043B", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 304, 566, 100, 28, hwnd, ControlIdToMenu(kControlScheduleButton), g_app.instance, nullptr);
    CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 420, 568, 388, 30, hwnd, ControlIdToMenu(kControlScheduleInfo), g_app.instance, nullptr);

    CreateWindowW(L"STATIC", L"\x041C\x043E\x043D\x0438\x0442\x043E\x0440\x0438\x043D\x0433 \x043F\x0430\x043F\x043A\x0438", WS_CHILD | WS_VISIBLE, 48, 614, 170, 20, hwnd, ControlIdToMenu(kControlMonitorLabel), g_app.instance, nullptr);
    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 48, 638, 520, 28, hwnd, ControlIdToMenu(kControlMonitorEdit), g_app.instance, nullptr);
    CreateWindowW(L"BUTTON", L"\x041E\x0431\x0437\x043E\x0440", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 580, 638, 90, 28, hwnd, ControlIdToMenu(kControlMonitorBrowse), g_app.instance, nullptr);
    CreateWindowW(L"BUTTON", L"\x0414\x043E\x0431\x0430\x0432\x0438\x0442\x044C", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 682, 638, 126, 28, hwnd, ControlIdToMenu(kControlMonitorAdd), g_app.instance, nullptr);
    CreateWindowW(L"BUTTON", L"\x041E\x0447\x0438\x0441\x0442\x0438\x0442\x044C", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 682, 674, 126, 28, hwnd, ControlIdToMenu(kControlMonitorClear), g_app.instance, nullptr);
    CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 48, 676, 620, 36, hwnd, ControlIdToMenu(kControlMonitorInfo), g_app.instance, nullptr);

    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"\x0420\x0435\x0437\x0443\x043B\x044C\x0442\x0430\x0442\x044B \x0441\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x043D\x0438\x044F \x043F\x043E\x044F\x0432\x044F\x0442\x0441\x044F \x0437\x0434\x0435\x0441\x044C.",
                    WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                    48, 722, 760, 112, hwnd, ControlIdToMenu(kControlScanResult), g_app.instance, nullptr);
    CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 48, 846, 760, 40, hwnd, ControlIdToMenu(kControlBottomInfo), g_app.instance, nullptr);

    const int ids[] = {
        kControlLoginLabel, kControlLoginEdit, kControlPasswordLabel, kControlPasswordEdit,
        kControlLoginButton, kControlLoginError, kControlActivationLabel, kControlActivationEdit,
        kControlActivationButton, kControlActivationError, kControlUserInfo, kControlLicenseInfo,
        kControlAvStatus, kControlLogoutButton, kControlBottomInfo, kControlBasesInfo,
        kControlScanFileEdit, kControlScanFileBrowse, kControlScanFileButton, kControlScanDirectoryEdit,
        kControlScanDirectoryBrowse, kControlScanDirectoryButton, kControlScanAllDrivesButton,
        kControlScheduleEdit, kControlScheduleButton, kControlScheduleInfo, kControlMonitorEdit,
        kControlMonitorBrowse, kControlMonitorAdd, kControlMonitorClear, kControlMonitorInfo,
        kControlScanResult, kControlScanFileLabel, kControlScanDirectoryLabel, kControlScheduleLabel,
        kControlMonitorLabel
    };
    for (int id : ids) {
        ApplyFontToControl(id, id == kControlScanResult ? g_app.smallFont : g_app.bodyFont);
    }

    const HWND scanResult = GetDlgItem(hwnd, kControlScanResult);
    SendMessageW(scanResult, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(10, 10));
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
                case kControlScanFileBrowse:
                    SetControlText(kControlScanFileEdit, ChooseFilePath(hwnd));
                    return 0;
                case kControlScanDirectoryBrowse:
                    SetControlText(kControlScanDirectoryEdit, ChooseFolderPath(hwnd));
                    return 0;
                case kControlMonitorBrowse:
                    SetControlText(kControlMonitorEdit, ChooseFolderPath(hwnd));
                    return 0;
                case kControlScanFileButton:
                    HandleScanFile();
                    return 0;
                case kControlScanDirectoryButton:
                    HandleScanDirectory();
                    return 0;
                case kControlScanAllDrivesButton:
                    HandleScanAllDrives();
                    return 0;
                case kControlScheduleButton:
                    HandleToggleSchedule();
                    return 0;
                case kControlMonitorAdd:
                    HandleAddMonitorDirectory();
                    return 0;
                case kControlMonitorClear:
                    HandleClearMonitorDirectories();
                    return 0;
                default:
                    return DefWindowProcW(hwnd, message, wParam, lParam);
            }
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            HWND control = reinterpret_cast<HWND>(lParam);
            const int id = GetDlgCtrlID(control);
            if (id == kControlScanResult) {
                SetBkMode(dc, OPAQUE);
                SetBkColor(dc, RGB(255, 255, 255));
                SetTextColor(dc, RGB(55, 65, 81));
                return reinterpret_cast<LRESULT>(GetStockObject(WHITE_BRUSH));
            }

            SetBkMode(dc, TRANSPARENT);
            if (id == kControlLoginError || id == kControlActivationError) {
                SetTextColor(dc, RGB(186, 51, 51));
            } else if (id == kControlAvStatus) {
                SetTextColor(dc, GetStatusColor());
            } else if (id == kControlUserInfo || id == kControlLicenseInfo || id == kControlBasesInfo || id == kControlScheduleInfo || id == kControlMonitorInfo) {
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
                if (!g_app.modalUiActive && !g_app.scanInProgress) {
                    RefreshStateFromService();
                }
                return 0;
            }
            if (wParam == kScanProgressTimerId) {
                if (!g_app.modalUiActive && g_app.scanInProgress &&
                    (g_app.scanMode == AppState::ScanMode::Directory || g_app.scanMode == AppState::ScanMode::FixedDrives)) {
                    UpdateRemoteScanProgress();
                }
                return 0;
            }
            break;
        case kScanFinishedMessage: {
            std::unique_ptr<std::wstring> result(reinterpret_cast<std::wstring*>(lParam));
            g_app.scanInProgress = false;
            g_app.scanMode = AppState::ScanMode::None;
            if (result) {
                SetScanDetails(*result);
            }
            if (!g_app.modalUiActive) {
                RefreshStateFromService();
            }
            return 0;
        }
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
            KillTimer(hwnd, kScanProgressTimerId);
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
    tray::ProtectCurrentProcessFromTermination();
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
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    if (!CreateSingleInstanceMutex() || !CreateUiResources() || !CreateMenus() || !RegisterWindowClass() || !CreateMainWindow() || !AddTrayIcon()) {
        ReleaseResources();
        CoUninitialize();
        return 1;
    }

    RefreshStateFromService();
    SetScanDetails(L"\x0420\x0435\x0437\x0443\x043B\x044C\x0442\x0430\x0442\x044B \x0441\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x043D\x0438\x044F \x043F\x043E\x044F\x0432\x044F\x0442\x0441\x044F \x0437\x0434\x0435\x0441\x044C.");
    if (!HasHiddenFlag()) {
        ShowMainWindow();
    }

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    ReleaseResources();
    CoUninitialize();
    return static_cast<int>(message.wParam);
}
