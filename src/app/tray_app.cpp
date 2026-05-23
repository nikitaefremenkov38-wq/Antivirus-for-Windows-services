#include <windows.h>
#include <shellapi.h>

#include "rpc_client.h"
#include "service_config.h"
#include "service_utils.h"

namespace {

constexpr wchar_t kWindowClassName[] = L"TrayAppMainWindowClass";
constexpr wchar_t kWindowTitle[] = L"Tray App";
constexpr wchar_t kStatusText[] =
    L"\x041F\x0440\x0438\x043B\x043E\x0436\x0435\x043D\x0438\x0435 \x0437\x0430\x043F\x0443\x0449\x0435\x043D\x043E "
    L"\x0441\x043B\x0443\x0436\x0431\x043E\x0439. \x0417\x0430\x043A\x0440\x044B\x0442\x0438\x0435 \x043E\x043A\x043D\x0430 "
    L"\x0441\x0432\x043E\x0440\x0430\x0447\x0438\x0432\x0430\x0435\x0442 \x043F\x0440\x0438\x043B\x043E\x0436\x0435\x043D\x0438\x0435 "
    L"\x0432 \x0442\x0440\x0435\x0439.";
constexpr wchar_t kFileMenuText[] = L"\x0424\x0430\x0439\x043B";
constexpr wchar_t kOpenText[] = L"\x041E\x0442\x043A\x0440\x044B\x0442\x044C";
constexpr wchar_t kExitText[] = L"\x0412\x044B\x0445\x043E\x0434";
constexpr UINT kTrayIconId = 1;
constexpr UINT kTrayMessage = WM_APP + 1;
constexpr UINT kMenuOpenId = 1001;
constexpr UINT kMenuExitId = 1002;
constexpr UINT kWindowMenuExitId = 2001;

struct AppState {
    HINSTANCE instance{};
    HWND window{};
    HMENU mainMenu{};
    HMENU trayMenu{};
    HANDLE mutex{};
    UINT taskbarCreatedMessage{};
    bool trayAdded{false};
};

AppState g_app;

bool HasHiddenFlag() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == nullptr) {
        return false;
    }

    bool hidden = false;
    for (int i = 1; i < argc; ++i) {
        if (lstrcmpiW(argv[i], tray::kHiddenArgument) == 0 || lstrcmpiW(argv[i], L"/hidden") == 0) {
            hidden = true;
            break;
        }
    }

    LocalFree(argv);
    return hidden;
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
    if (!g_app.trayAdded) {
        return;
    }

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
    TrackPopupMenu(
        g_app.trayMenu,
        TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
        cursor.x,
        cursor.y,
        0,
        g_app.window,
        nullptr
    );
    PostMessageW(g_app.window, WM_NULL, 0, 0);
}

void RequestServiceShutdown() {
    if (!tray::RequestServiceStop()) {
        MessageBoxW(
            g_app.window,
            L"\x041D\x0435 \x0443\x0434\x0430\x043B\x043E\x0441\x044C \x043E\x0441\x0442\x0430\x043D\x043E\x0432\x0438\x0442\x044C \x0441\x043B\x0443\x0436\x0431\x0443.",
            kWindowTitle,
            MB_ICONERROR | MB_OK
        );
    }
}

void PaintWindow(HWND hwnd) {
    PAINTSTRUCT ps{};
    HDC dc = BeginPaint(hwnd, &ps);

    RECT client_rect{};
    GetClientRect(hwnd, &client_rect);

    SetBkMode(dc, TRANSPARENT);
    DrawTextW(dc, kStatusText, -1, &client_rect, DT_LEFT | DT_TOP | DT_WORDBREAK);

    EndPaint(hwnd, &ps);
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
                default:
                    return DefWindowProcW(hwnd, message, wParam, lParam);
            }
        case WM_PAINT:
            PaintWindow(hwnd);
            return 0;
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
            RemoveTrayIcon();
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(hwnd, message, wParam, lParam);
    }
}

bool CreateMenus() {
    g_app.mainMenu = CreateMenu();
    HMENU file_menu = CreatePopupMenu();
    g_app.trayMenu = CreatePopupMenu();

    if (g_app.mainMenu == nullptr || file_menu == nullptr || g_app.trayMenu == nullptr) {
        return false;
    }

    AppendMenuW(file_menu, MF_STRING, kWindowMenuExitId, kExitText);
    AppendMenuW(g_app.mainMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(file_menu), kFileMenuText);

    AppendMenuW(g_app.trayMenu, MF_STRING, kMenuOpenId, kOpenText);
    AppendMenuW(g_app.trayMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(g_app.trayMenu, MF_STRING, kMenuExitId, kExitText);

    return true;
}

bool RegisterWindowClass() {
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.lpfnWndProc = WindowProc;
    window_class.hInstance = g_app.instance;
    window_class.lpszClassName = kWindowClassName;
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    window_class.hIconSm = LoadIconW(nullptr, IDI_APPLICATION);
    window_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);

    return RegisterClassExW(&window_class) != 0;
}

bool CreateMainWindow() {
    g_app.window = CreateWindowExW(
        0,
        kWindowClassName,
        kWindowTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        800,
        600,
        nullptr,
        nullptr,
        g_app.instance,
        nullptr
    );

    if (g_app.window == nullptr) {
        return false;
    }

    SetMenu(g_app.window, g_app.mainMenu);
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

    g_app.trayMenu = nullptr;

    if (g_app.mutex != nullptr) {
        CloseHandle(g_app.mutex);
        g_app.mutex = nullptr;
    }
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    const tray::ServiceBootResult boot_result = tray::EnsureServiceRunning(30000);
    if (boot_result == tray::ServiceBootResult::kFailed) {
        MessageBoxW(
            nullptr,
            L"\x041D\x0435 \x0443\x0434\x0430\x043B\x043E\x0441\x044C \x0437\x0430\x043F\x0443\x0441\x0442\x0438\x0442\x044C \x0441\x043B\x0443\x0436\x0431\x0443.",
            kWindowTitle,
            MB_ICONERROR | MB_OK
        );
        return 1;
    }

    if (boot_result == tray::ServiceBootResult::kStartedOrWaited) {
        return 0;
    }

    if (!tray::IsParentProcessService()) {
        return 0;
    }

    g_app.instance = instance;
    g_app.taskbarCreatedMessage = RegisterWindowMessageW(L"TaskbarCreated");

    if (!CreateSingleInstanceMutex()) {
        ReleaseResources();
        return 0;
    }

    if (!CreateMenus() || !RegisterWindowClass() || !CreateMainWindow() || !AddTrayIcon()) {
        ReleaseResources();
        return 1;
    }

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
