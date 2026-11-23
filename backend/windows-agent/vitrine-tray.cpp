#include "vitrine-common.hpp"
#include <objidl.h>
#include <gdiplus.h>
#include <winsvc.h>

using namespace vitrine;

#define WM_TRAY_CALLBACK (WM_APP + 1)
#define ID_TRAY_TIMER 1001
#define ID_MENU_BASE 2000
#define ID_CHAT_EDIT 3001
#define ID_CHAT_SEND 3002
#define ID_CHAT_CANCEL 3003
#define ID_INFO_BODY 3101
#define ID_INFO_OK 3102
#define ID_INFO_COPY 3103
#define ID_REBOOT_NOW 3201
#define ID_REBOOT_SNOOZE 3202

enum class AgentConnState {
  Online,
  Connecting,
  Offline
};

struct AgentStatusSnapshot {
  AgentConnState state = AgentConnState::Connecting;
  int64_t lastCheckinEpoch = 0;
};

struct TrayMenuEntry {
  std::string label;
  std::string type;
  std::string target;
  bool enabled = true;
};

struct ActivePopupMenuItem {
  std::string text;
  bool isHeader = false;
  bool isSeparator = false;
};

struct TrayState {
  HINSTANCE hInst = nullptr;
  HWND hMainWnd = nullptr;
  NOTIFYICONDATAW nid{};
  UINT wmTaskbarCreated = 0;
  HICON currentIcon = nullptr;
  FILETIME cfgMtime{};
  std::string brandName = "Vitrine RMM";
  std::string serviceName = "VitrineAgent";
  std::string themeMode = "system";
  bool useDarkTheme = false;
  bool popupDark = false;
  AgentConnState popupConnState = AgentConnState::Connecting;
  bool modalOpen = false;
  std::string tooltip = "Vitrine RMM Support";
  std::string supportUrl;
  std::string supportPhone;
  std::string supportEmail;
  bool trayEnabled = true;
  bool allowSelfSigned = false;
  std::vector<TrayMenuEntry> menuItems;
  std::vector<ActivePopupMenuItem> activePopupItems;
  std::string loadedIconUrl;
  ULONG_PTR gdiplusToken = 0;
};

static TrayState* g_tray = nullptr;

static bool isQuickSupportUserModeDir(const std::wstring& selfDir) {
  std::wstring localApp = getEnvVar(L"LOCALAPPDATA");
  return !localApp.empty() && selfDir.size() >= localApp.size() &&
      _wcsnicmp(selfDir.c_str(), localApp.c_str(), localApp.size()) == 0;
}

static std::wstring getTrayDataDir(const std::wstring& selfDir) {
  std::wstring dir;
  if (isQuickSupportUserModeDir(selfDir)) {
    dir = joinPath(selfDir, L"tray");
  } else {
    std::wstring progData = getEnvVar(L"ProgramData");
    if (progData.empty()) progData = L"C:\\ProgramData";
    std::string svcName = g_tray ? g_tray->serviceName : "VitrineAgent";
    dir = joinPath(joinPath(progData, utf8ToWide(svcName)), L"tray");
  }
  ensureDirRecursive(dir);
  return dir;
}

static bool isCompanionServiceRunning(const std::string& svcName, bool& outServiceFound) {
  outServiceFound = false;
  SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!hScm) return false;
  std::wstring compName = utf8ToWide(svcName) + L"-Companion";
  SC_HANDLE hSvc = OpenServiceW(hScm, compName.c_str(), SERVICE_QUERY_STATUS);
  if (!hSvc) {
    CloseServiceHandle(hScm);
    return false;
  }
  outServiceFound = true;
  SERVICE_STATUS ss{};
  bool running = QueryServiceStatus(hSvc, &ss) != 0 && ss.dwCurrentState == SERVICE_RUNNING;
  CloseServiceHandle(hSvc);
  CloseServiceHandle(hScm);
  return running;
}

static AgentStatusSnapshot queryAgentStatus(const std::wstring& selfDir) {
  AgentStatusSnapshot snap{};
  std::string svcName = g_tray ? g_tray->serviceName : "VitrineAgent";
  bool isQs = isQuickSupportUserModeDir(selfDir);
  bool svcFound = false;
  bool svcRunning = false;
  if (!isQs) {
    svcRunning = isCompanionServiceRunning(svcName, svcFound);
  }

  JsonVal stJson;
  bool hasStatusFile = parseJson(readTextFile(joinPath(getTrayDataDir(selfDir), L"agent-status.json")), stJson);
  if (hasStatusFile) {
    snap.lastCheckinEpoch = stJson.getInt("lastCheckinEpoch", 0);
  }

  if (!isQs && svcFound && !svcRunning) {
    snap.state = AgentConnState::Offline;
    return snap;
  }

  if (hasStatusFile) {
    bool online = stJson.getBool("online", false);
    int64_t intervalSec = std::max<int64_t>(10, stJson.getInt("intervalSec", 25));
    int64_t now = getCurrentUnixEpochSec();
    int64_t maxStale = std::max<int64_t>(90, intervalSec * 3 + 15);
    if (online && snap.lastCheckinEpoch > 0 && (now - snap.lastCheckinEpoch) <= maxStale && (now - snap.lastCheckinEpoch) >= -300) {
      snap.state = AgentConnState::Online;
    } else {
      snap.state = AgentConnState::Offline;
    }
    return snap;
  }

  if (fileExists(joinPath(selfDir, L"agent-identity.json")) && (isQs || svcRunning || !svcFound)) {
    snap.state = AgentConnState::Connecting;
  } else {
    snap.state = AgentConnState::Offline;
  }
  return snap;
}

static HICON loadCustomIconFromFile(const std::wstring& imgPath, int targetW, int targetH) {
  Gdiplus::Bitmap bmp(imgPath.c_str());
  if (bmp.GetLastStatus() != Gdiplus::Ok) return nullptr;
  int w = targetW > 0 ? targetW : 32;
  int h = targetH > 0 ? targetH : 32;
  Gdiplus::Bitmap scaled(w, h, PixelFormat32bppARGB);
  {
    Gdiplus::Graphics g(&scaled);
    g.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
    g.DrawImage(&bmp, 0, 0, w, h);
  }
  HICON hIcon = nullptr;
  scaled.GetHICON(&hIcon);
  return hIcon;
}

static void copyUtf8ToClipboard(HWND owner, const std::string& text) {
  std::wstring wText = utf8ToWide(text);
  if (OpenClipboard(owner)) {
    EmptyClipboard();
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (wText.size() + 1) * sizeof(wchar_t));
    if (hMem) {
      void* p = GlobalLock(hMem);
      if (p) {
        std::memcpy(p, wText.c_str(), (wText.size() + 1) * sizeof(wchar_t));
        GlobalUnlock(hMem);
        SetClipboardData(CF_UNICODETEXT, hMem);
      }
    }
    CloseClipboard();
  }
}

static HFONT createUiFont(int heightPx, int weight = FW_NORMAL) {
  NONCLIENTMETRICSW ncm{};
  ncm.cbSize = sizeof(ncm);
  SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
  if (heightPx != 0) ncm.lfMessageFont.lfHeight = heightPx;
  ncm.lfMessageFont.lfWeight = weight;
  return CreateFontIndirectW(&ncm.lfMessageFont);
}

static void refreshThemePalette(bool& outDark, WinThemePalette& outPal, HBRUSH& hBgBrush, HBRUSH* hAuxBrush = nullptr, bool auxIsSurface = false) {
  std::string tm = g_tray ? g_tray->themeMode : "system";
  outDark = resolveUseDarkTheme(tm);
  outPal = getWinThemePalette(outDark);
  if (hBgBrush) DeleteObject(hBgBrush);
  hBgBrush = CreateSolidBrush(outPal.bg);
  if (hAuxBrush) {
    if (*hAuxBrush) DeleteObject(*hAuxBrush);
    *hAuxBrush = CreateSolidBrush(auxIsSurface ? outPal.surface : outPal.inputBg);
  }
}

static void applyTrayConfig(bool forceAddIcon) {
  if (!g_tray) return;
  std::wstring selfDir = getSelfDir();
  std::wstring cfgPath = joinPath(selfDir, L"companion-config.json");
  std::string raw = readTextFile(cfgPath);
  if (raw.empty()) raw = readEmbeddedConfigJson();

  JsonVal cfg;
  if (parseJson(raw, cfg)) {
    std::string b = cfg.getStr("BrandName");
    if (!b.empty()) g_tray->brandName = b;
    std::string s = sanitizeIdentifier(cfg.getStr("ServiceName"), "", 40);
    if (!s.empty()) g_tray->serviceName = s;
    std::string tm = cfg.getStr("ThemeMode");
    if (tm.empty()) tm = cfg.getStr("trayThemeMode", "system");
    g_tray->themeMode = tm.empty() ? "system" : tm;
    g_tray->useDarkTheme = resolveUseDarkTheme(g_tray->themeMode);
    g_tray->trayEnabled = cfg.getBool("TrayEnabled", true);
    g_tray->allowSelfSigned = cfg.getBool("AllowSelfSignedTls", false);
    g_tray->tooltip = cfg.getStr("Tooltip");
    if (g_tray->tooltip.empty()) g_tray->tooltip = g_tray->brandName + " Support";
    g_tray->supportUrl = cfg.getStr("SupportUrl");
    g_tray->supportPhone = cfg.getStr("SupportPhone");
    g_tray->supportEmail = cfg.getStr("SupportEmail");

    g_tray->menuItems.clear();
    if (const JsonVal* mi = cfg.get("MenuItems")) {
      if (mi->type == JsonVal::J_ARR) {
        for (const auto& item : mi->arrVal) {
          TrayMenuEntry e;
          e.label = item.getStr("label");
          e.type = item.getStr("type");
          e.target = item.getStr("target");
          e.enabled = item.getBool("enabled", true);
          if (e.enabled && (!e.label.empty() || e.type == "separator")) {
            g_tray->menuItems.push_back(e);
          }
        }
      }
    }
    if (g_tray->menuItems.empty()) {
      g_tray->menuItems.push_back({"Message IT Support", "message_support", "", true});
      g_tray->menuItems.push_back({"Endpoint Status", "endpoint_status", "", true});
    }

    int cxSm = GetSystemMetrics(SM_CXSMICON);
    int cySm = GetSystemMetrics(SM_CYSMICON);
    if (cxSm <= 0) cxSm = 16;
    if (cySm <= 0) cySm = 16;

    HICON nextIcon = nullptr;
    std::string iconUrl = cfg.getStr("IconUrl");
    std::string embIconUrl = cfg.getStr("EmbeddedIconUrl");
    std::string srvUrl = cfg.getStr("VitrineServerUrl");
    if (!iconUrl.empty() && iconUrl != embIconUrl && !srvUrl.empty()) {
      if (iconUrl == g_tray->loadedIconUrl && g_tray->currentIcon) {
        nextIcon = g_tray->currentIcon;
      } else {
        std::string fullUrl = iconUrl;
        if (fullUrl.rfind("http://", 0) != 0 && fullUrl.rfind("https://", 0) != 0) {
          while (!srvUrl.empty() && srvUrl.back() == '/') srvUrl.pop_back();
          while (!fullUrl.empty() && fullUrl.front() == '/') fullUrl.erase(fullUrl.begin());
          fullUrl = srvUrl + "/" + fullUrl;
        }
        std::wstring cachePath = joinPath(getTrayDataDir(selfDir), L"tray-icon.img");
        std::string dlErr;
        if (httpDownloadToFile(fullUrl, cachePath, g_tray->allowSelfSigned, dlErr, 10000)) {
          nextIcon = loadCustomIconFromFile(cachePath, cxSm, cySm);
          if (nextIcon) g_tray->loadedIconUrl = iconUrl;
        }
      }
    } else if (!iconUrl.empty() && iconUrl == embIconUrl) {
      g_tray->loadedIconUrl = embIconUrl;
    }
    if (!nextIcon) {
      nextIcon = static_cast<HICON>(LoadImageW(g_tray->hInst, MAKEINTRESOURCEW(1), IMAGE_ICON, cxSm, cySm, LR_DEFAULTCOLOR));
    }
    if (!nextIcon) nextIcon = LoadIconW(nullptr, IDI_SHIELD);
    if (g_tray->currentIcon && g_tray->currentIcon != nextIcon) DestroyIcon(g_tray->currentIcon);
    g_tray->currentIcon = nextIcon;
  } else {
    g_tray->useDarkTheme = resolveUseDarkTheme(g_tray->themeMode);
  }

  g_tray->nid.cbSize = sizeof(g_tray->nid);
  g_tray->nid.hWnd = g_tray->hMainWnd;
  g_tray->nid.uID = 1;
  g_tray->nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
  g_tray->nid.uCallbackMessage = WM_TRAY_CALLBACK;
  g_tray->nid.hIcon = g_tray->currentIcon ? g_tray->currentIcon : LoadIconW(nullptr, IDI_SHIELD);
  std::wstring wTip = utf8ToWide(g_tray->tooltip);
  if (wTip.size() > 127) wTip.resize(127);
  wcsncpy(g_tray->nid.szTip, wTip.c_str(), 127);

  if (g_tray->trayEnabled) {
    if (forceAddIcon) Shell_NotifyIconW(NIM_ADD, &g_tray->nid);
    else if (!Shell_NotifyIconW(NIM_MODIFY, &g_tray->nid)) Shell_NotifyIconW(NIM_ADD, &g_tray->nid);
  } else {
    Shell_NotifyIconW(NIM_DELETE, &g_tray->nid);
  }
}

static void showBalloon(const std::string& title, const std::string& text) {
  if (!g_tray || !g_tray->trayEnabled) return;
  NOTIFYICONDATAW b = g_tray->nid;
  b.uFlags = NIF_INFO;
  b.dwInfoFlags = NIIF_INFO;
  std::wstring wt = utf8ToWide(title.empty() ? g_tray->brandName : title);
  std::wstring wm = utf8ToWide(text.empty() ? "IT Support Notification" : text);
  if (wt.size() > 63) wt.resize(63);
  if (wm.size() > 255) wm.resize(255);
  wcsncpy(b.szInfoTitle, wt.c_str(), 63);
  wcsncpy(b.szInfo, wm.c_str(), 255);
  Shell_NotifyIconW(NIM_MODIFY, &b);
}

static void submitSupportChatMessage(const std::string& userMsg) {
  if (!g_tray || trimAscii(userMsg).empty()) return;
  std::wstring selfDir = getSelfDir();
  std::string userName = wideToUtf8(getEnvVar(L"USERNAME"));
  if (userName.empty()) userName = "Desktop User";

  JsonVal id;
  if (parseJson(readTextFile(joinPath(selfDir, L"agent-identity.json")), id)) {
    std::string tok = id.getStr("agentToken");
    if (tok.empty()) tok = id.getStr("agentAuthToken");
    std::string srv = id.getStr("vitrineServerUrl");
    std::string devId = id.getStr("deviceId");
    if (!tok.empty() && !srv.empty() && !devId.empty()) {
      while (!srv.empty() && srv.back() == '/') srv.pop_back();
      std::string body = "{\"deviceId\":\"" + jsonEscape(devId) + "\",\"sender\":\"" + jsonEscape(userName) + "\",\"message\":\"" + jsonEscape(userMsg) + "\"}";
      HttpResponse r = httpRequest(srv + "/api/agent/chat", "POST", body,
          {{"Content-Type", "application/json"}, {"x-vitrine-agent-token", tok}}, g_tray->allowSelfSigned, 10000);
      if (r.statusCode >= 200 && r.statusCode < 300) {
        showBalloon(g_tray->brandName, "Your message has been sent to IT Support.");
        return;
      }
    }
  }

  std::wstring trayDir = getTrayDataDir(selfDir);
  std::wstring tmpPath = joinPath(trayDir, L"tray-outbox.json.tmp");
  std::wstring outPath = joinPath(trayDir, L"tray-outbox.json");
  std::string body = "{\"sender\":\"" + jsonEscape(userName) + "\",\"message\":\"" + jsonEscape(userMsg) + "\"}";
  writeTextFile(tmpPath, body);
  MoveFileExW(tmpPath.c_str(), outPath.c_str(), MOVEFILE_REPLACE_EXISTING);
  showBalloon(g_tray->brandName, "Your message has been queued for IT Support.");
}

// ============================================================================
// Sub-Tray GUI #1: Themed Message IT Support Modal
// ============================================================================
struct ChatDialogState {
  HWND hEdit = nullptr;
  HWND hLbl = nullptr;
  HWND hSend = nullptr;
  HWND hCancel = nullptr;
  HFONT hFont = nullptr;
  HBRUSH hBgBrush = nullptr;
  HBRUSH hEditBrush = nullptr;
  WinThemePalette pal{};
  bool isDark = false;
  bool done = false;
  std::string submittedText;
};

static LRESULT CALLBACK chatDlgProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
  auto* st = reinterpret_cast<ChatDialogState*>(GetWindowLongPtrW(hWnd, GWLP_USERDATA));
  switch (msg) {
    case WM_CREATE: {
      auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
      SetWindowLongPtrW(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
      return 0;
    }
    case WM_ERASEBKGND: {
      if (st && st->hBgBrush) {
        RECT rc{};
        GetClientRect(hWnd, &rc);
        FillRect(reinterpret_cast<HDC>(wp), &rc, st->hBgBrush);
        return 1;
      }
      break;
    }
    case WM_PAINT: {
      if (st) {
        PAINTSTRUCT ps{};
        HDC hdc = BeginPaint(hWnd, &ps);
        RECT box{15, 39, 417, 137};
        HPEN pen = CreatePen(PS_SOLID, 1, st->pal.border);
        HBRUSH br = CreateSolidBrush(st->pal.inputBg);
        HGDIOBJ oldPen = SelectObject(hdc, pen);
        HGDIOBJ oldBr = SelectObject(hdc, br);
        RoundRect(hdc, box.left, box.top, box.right, box.bottom, 6, 6);
        SelectObject(hdc, oldBr);
        SelectObject(hdc, oldPen);
        DeleteObject(br);
        DeleteObject(pen);
        EndPaint(hWnd, &ps);
        return 0;
      }
      break;
    }
    case WM_CTLCOLORSTATIC: {
      if (st) {
        HDC hdc = reinterpret_cast<HDC>(wp);
        SetBkMode(hdc, OPAQUE);
        SetBkColor(hdc, st->pal.bg);
        SetTextColor(hdc, st->pal.text);
        return reinterpret_cast<LRESULT>(st->hBgBrush);
      }
      break;
    }
    case WM_CTLCOLOREDIT: {
      if (st) {
        HDC hdc = reinterpret_cast<HDC>(wp);
        SetBkMode(hdc, OPAQUE);
        SetBkColor(hdc, st->pal.inputBg);
        SetTextColor(hdc, st->pal.text);
        return reinterpret_cast<LRESULT>(st->hEditBrush);
      }
      break;
    }
    case WM_DRAWITEM: {
      if (st) {
        auto* dis = reinterpret_cast<const DRAWITEMSTRUCT*>(lp);
        if (dis && dis->CtlType == ODT_BUTTON) {
          drawThemedButton(dis, st->pal, dis->CtlID == ID_CHAT_SEND);
          return TRUE;
        }
      }
      break;
    }
    case WM_SETTINGCHANGE: {
      if (st && isThemeSettingChange(lp)) {
        refreshThemePalette(st->isDark, st->pal, st->hBgBrush, &st->hEditBrush);
        applyWindowTitleBarTheme(hWnd, st->isDark);
        InvalidateRect(hWnd, nullptr, TRUE);
        if (st->hLbl) InvalidateRect(st->hLbl, nullptr, TRUE);
        if (st->hEdit) InvalidateRect(st->hEdit, nullptr, TRUE);
        if (st->hSend) InvalidateRect(st->hSend, nullptr, TRUE);
        if (st->hCancel) InvalidateRect(st->hCancel, nullptr, TRUE);
      }
      return 0;
    }
    case WM_COMMAND: {
      WORD cmdId = LOWORD(wp);
      if (cmdId == ID_CHAT_SEND && st) {
        int len = GetWindowTextLengthW(st->hEdit);
        if (len > 0) {
          std::wstring buf(static_cast<size_t>(len) + 1, L'\0');
          GetWindowTextW(st->hEdit, &buf[0], len + 1);
          buf.resize(static_cast<size_t>(len));
          st->submittedText = wideToUtf8(buf);
        }
        st->done = true;
        DestroyWindow(hWnd);
      } else if (cmdId == ID_CHAT_CANCEL && st) {
        st->done = true;
        DestroyWindow(hWnd);
      }
      return 0;
    }
    case WM_CLOSE:
      if (st) st->done = true;
      DestroyWindow(hWnd);
      return 0;
  }
  return DefWindowProcW(hWnd, msg, wp, lp);
}

static void openSupportChatModal() {
  if (!g_tray || g_tray->modalOpen) return;
  g_tray->modalOpen = true;
  static bool reg = false;
  if (!reg) {
    WNDCLASSW wc{};
    wc.lpfnWndProc = chatDlgProc;
    wc.hInstance = g_tray->hInst;
    wc.hbrBackground = nullptr;
    wc.lpszClassName = L"VitrineChatModalWnd";
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    RegisterClassW(&wc);
    reg = true;
  }

  ChatDialogState state;
  refreshThemePalette(state.isDark, state.pal, state.hBgBrush, &state.hEditBrush);
  std::wstring title = utf8ToWide(g_tray->brandName + " - Message IT Support");
  HWND hDlg = CreateWindowExW(
      WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
      L"VitrineChatModalWnd",
      title.c_str(),
      WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
      CW_USEDEFAULT, CW_USEDEFAULT, 448, 236,
      nullptr, nullptr, g_tray->hInst, &state);
  if (!hDlg) {
    if (state.hBgBrush) DeleteObject(state.hBgBrush);
    if (state.hEditBrush) DeleteObject(state.hEditBrush);
    g_tray->modalOpen = false;
    return;
  }
  applyWindowTitleBarTheme(hDlg, state.isDark);
  HICON hChatIcon = static_cast<HICON>(LoadImageW(g_tray->hInst, MAKEINTRESOURCEW(1), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
  if (hChatIcon) SendMessageW(hDlg, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(hChatIcon));

  state.hFont = createUiFont(0, FW_NORMAL);
  state.hLbl = CreateWindowW(L"STATIC", L"Describe your IT issue or request:", WS_CHILD | WS_VISIBLE | SS_NOPREFIX,
      16, 14, 398, 20, hDlg, nullptr, g_tray->hInst, nullptr);
  state.hEdit = CreateWindowExW(0, L"EDIT", L"",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
      18, 42, 396, 92, hDlg, reinterpret_cast<HMENU>(ID_CHAT_EDIT), g_tray->hInst, nullptr);
  state.hCancel = CreateWindowW(L"BUTTON", L"Cancel",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
      154, 148, 88, 30, hDlg, reinterpret_cast<HMENU>(ID_CHAT_CANCEL), g_tray->hInst, nullptr);
  state.hSend = CreateWindowW(L"BUTTON", L"Send to IT Support",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW | BS_DEFPUSHBUTTON,
      250, 148, 166, 30, hDlg, reinterpret_cast<HMENU>(ID_CHAT_SEND), g_tray->hInst, nullptr);

  SendMessageW(state.hLbl, WM_SETFONT, reinterpret_cast<WPARAM>(state.hFont), TRUE);
  SendMessageW(state.hEdit, WM_SETFONT, reinterpret_cast<WPARAM>(state.hFont), TRUE);
  SendMessageW(state.hSend, WM_SETFONT, reinterpret_cast<WPARAM>(state.hFont), TRUE);
  SendMessageW(state.hCancel, WM_SETFONT, reinterpret_cast<WPARAM>(state.hFont), TRUE);

  RECT rc{};
  GetWindowRect(hDlg, &rc);
  int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
  SetWindowPos(hDlg, HWND_TOPMOST, (sw - (rc.right - rc.left)) / 2, (sh - (rc.bottom - rc.top)) / 2, 0, 0, SWP_NOSIZE);
  ShowWindow(hDlg, SW_SHOW);
  SetForegroundWindow(hDlg);
  SetFocus(state.hEdit);

  MSG m{};
  while (!state.done && GetMessageW(&m, nullptr, 0, 0) > 0) {
    TranslateMessage(&m);
    DispatchMessageW(&m);
  }
  if (state.hFont) DeleteObject(state.hFont);
  if (state.hBgBrush) DeleteObject(state.hBgBrush);
  if (state.hEditBrush) DeleteObject(state.hEditBrush);
  if (hChatIcon) DestroyIcon(hChatIcon);
  g_tray->modalOpen = false;
  if (!trimAscii(state.submittedText).empty()) {
    submitSupportChatMessage(state.submittedText);
  }
}

// ============================================================================
// Sub-Tray GUI #2 & #3: Themed Info / Endpoint Status & Reboot Prompt Modals
// ============================================================================
struct InfoModalState {
  HWND hHeading = nullptr;
  HWND hBody = nullptr;
  HWND hOk = nullptr;
  HWND hCopy = nullptr;
  HFONT hTitleFont = nullptr;
  HFONT hBodyFont = nullptr;
  HBRUSH hBgBrush = nullptr;
  HBRUSH hSurfaceBrush = nullptr;
  WinThemePalette pal{};
  bool isDark = false;
  bool done = false;
  bool isRebootPrompt = false;
  bool restartTriggered = false;
  std::string copyText;
};

static LRESULT CALLBACK infoModalProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
  auto* st = reinterpret_cast<InfoModalState*>(GetWindowLongPtrW(hWnd, GWLP_USERDATA));
  switch (msg) {
    case WM_CREATE: {
      auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
      SetWindowLongPtrW(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
      return 0;
    }
    case WM_ERASEBKGND: {
      if (st && st->hBgBrush) {
        RECT rc{};
        GetClientRect(hWnd, &rc);
        FillRect(reinterpret_cast<HDC>(wp), &rc, st->hBgBrush);
        return 1;
      }
      break;
    }
    case WM_PAINT: {
      if (st) {
        PAINTSTRUCT ps{};
        HDC hdc = BeginPaint(hWnd, &ps);
        RECT rc{};
        GetClientRect(hWnd, &rc);
        RECT card{16, 48, rc.right - 16, rc.bottom - 56};
        HBRUSH sBr = CreateSolidBrush(st->pal.surface);
        HPEN pen = CreatePen(PS_SOLID, 1, st->pal.border);
        HGDIOBJ oldBr = SelectObject(hdc, sBr);
        HGDIOBJ oldPen = SelectObject(hdc, pen);
        RoundRect(hdc, card.left, card.top, card.right, card.bottom, 8, 8);
        SelectObject(hdc, oldBr);
        SelectObject(hdc, oldPen);
        DeleteObject(sBr);
        DeleteObject(pen);
        EndPaint(hWnd, &ps);
        return 0;
      }
      break;
    }
    case WM_CTLCOLORSTATIC: {
      if (st) {
        HDC hdc = reinterpret_cast<HDC>(wp);
        HWND ctl = reinterpret_cast<HWND>(lp);
        if (ctl == st->hBody && st->hSurfaceBrush) {
          SetBkMode(hdc, OPAQUE);
          SetBkColor(hdc, st->pal.surface);
          SetTextColor(hdc, st->pal.text);
          return reinterpret_cast<LRESULT>(st->hSurfaceBrush);
        }
        SetBkMode(hdc, OPAQUE);
        SetBkColor(hdc, st->pal.bg);
        SetTextColor(hdc, st->isRebootPrompt ? st->pal.danger : st->pal.text);
        return reinterpret_cast<LRESULT>(st->hBgBrush);
      }
      break;
    }
    case WM_DRAWITEM: {
      if (st) {
        auto* dis = reinterpret_cast<const DRAWITEMSTRUCT*>(lp);
        if (dis && dis->CtlType == ODT_BUTTON) {
          if (st->isRebootPrompt) {
            drawThemedButton(dis, st->pal, false, dis->CtlID == ID_REBOOT_NOW);
          } else {
            drawThemedButton(dis, st->pal, dis->CtlID == ID_INFO_OK);
          }
          return TRUE;
        }
      }
      break;
    }
    case WM_SETTINGCHANGE: {
      if (st && isThemeSettingChange(lp)) {
        refreshThemePalette(st->isDark, st->pal, st->hBgBrush, &st->hSurfaceBrush, true);
        applyWindowTitleBarTheme(hWnd, st->isDark);
        InvalidateRect(hWnd, nullptr, TRUE);
        if (st->hHeading) InvalidateRect(st->hHeading, nullptr, TRUE);
        if (st->hBody) InvalidateRect(st->hBody, nullptr, TRUE);
        if (st->hOk) InvalidateRect(st->hOk, nullptr, TRUE);
        if (st->hCopy) InvalidateRect(st->hCopy, nullptr, TRUE);
      }
      return 0;
    }
    case WM_COMMAND: {
      WORD cmdId = LOWORD(wp);
      if (cmdId == ID_INFO_COPY && st && !st->copyText.empty()) {
        copyUtf8ToClipboard(hWnd, st->copyText);
        showBalloon(g_tray ? g_tray->brandName : "Vitrine RMM", "Endpoint details copied to clipboard.");
      } else if (cmdId == ID_REBOOT_NOW && st) {
        st->restartTriggered = true;
        st->done = true;
        DestroyWindow(hWnd);
      } else if ((cmdId == ID_INFO_OK || cmdId == ID_REBOOT_SNOOZE) && st) {
        st->done = true;
        DestroyWindow(hWnd);
      }
      return 0;
    }
    case WM_CLOSE:
      if (st) st->done = true;
      DestroyWindow(hWnd);
      return 0;
  }
  return DefWindowProcW(hWnd, msg, wp, lp);
}

static void openThemedInfoModal(
    const std::string& caption,
    const std::string& heading,
    const std::string& bodyText,
    const std::string& copyPayload = "",
    bool isRebootPrompt = false) {
  if (!g_tray || g_tray->modalOpen) return;
  g_tray->modalOpen = true;

  static bool reg = false;
  if (!reg) {
    WNDCLASSW wc{};
    wc.lpfnWndProc = infoModalProc;
    wc.hInstance = g_tray->hInst;
    wc.hbrBackground = nullptr;
    wc.lpszClassName = L"VitrineThemedInfoWnd";
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    RegisterClassW(&wc);
    reg = true;
  }

  // Convert LF to CRLF for clean Win32 STATIC multiline rendering
  std::string winBody;
  winBody.reserve(bodyText.size() + 32);
  int lines = 1;
  for (size_t i = 0; i < bodyText.size(); i++) {
    if (bodyText[i] == '\n') {
      if (i == 0 || bodyText[i - 1] != '\r') winBody += "\r\n";
      else winBody.push_back('\n');
      lines++;
    } else {
      winBody.push_back(bodyText[i]);
    }
  }
  int bodyH = std::max(84, std::min(240, lines * 20 + 20));
  int winH = bodyH + 150;
  int winW = 450;

  InfoModalState state;
  state.isRebootPrompt = isRebootPrompt;
  state.copyText = copyPayload;
  refreshThemePalette(state.isDark, state.pal, state.hBgBrush, &state.hSurfaceBrush, true);

  HWND hDlg = CreateWindowExW(
      WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
      L"VitrineThemedInfoWnd",
      utf8ToWide(caption).c_str(),
      WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
      CW_USEDEFAULT, CW_USEDEFAULT, winW, winH,
      nullptr, nullptr, g_tray->hInst, &state);
  if (!hDlg) {
    if (state.hBgBrush) DeleteObject(state.hBgBrush);
    if (state.hSurfaceBrush) DeleteObject(state.hSurfaceBrush);
    g_tray->modalOpen = false;
    return;
  }
  applyWindowTitleBarTheme(hDlg, state.isDark);
  HICON hIcon = static_cast<HICON>(LoadImageW(g_tray->hInst, MAKEINTRESOURCEW(1), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
  if (hIcon) SendMessageW(hDlg, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(hIcon));

  RECT clientRc{};
  GetClientRect(hDlg, &clientRc);
  int cw = clientRc.right - clientRc.left;
  int ch = clientRc.bottom - clientRc.top;

  state.hTitleFont = createUiFont(-18, FW_BOLD);
  state.hBodyFont = createUiFont(0, FW_NORMAL);

  state.hHeading = CreateWindowW(L"STATIC", utf8ToWide(heading).c_str(),
      WS_CHILD | WS_VISIBLE | SS_NOPREFIX,
      16, 14, cw - 32, 26, hDlg, nullptr, g_tray->hInst, nullptr);
  state.hBody = CreateWindowW(L"STATIC", utf8ToWide(winBody).c_str(),
      WS_CHILD | WS_VISIBLE | SS_NOPREFIX,
      28, 58, cw - 56, ch - 124, hDlg, reinterpret_cast<HMENU>(ID_INFO_BODY), g_tray->hInst, nullptr);

  if (isRebootPrompt) {
    state.hCopy = CreateWindowW(L"BUTTON", L"Snooze",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
        cw - 248, ch - 44, 102, 30, hDlg, reinterpret_cast<HMENU>(ID_REBOOT_SNOOZE), g_tray->hInst, nullptr);
    state.hOk = CreateWindowW(L"BUTTON", L"Restart Now",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
        cw - 138, ch - 44, 122, 30, hDlg, reinterpret_cast<HMENU>(ID_REBOOT_NOW), g_tray->hInst, nullptr);
  } else {
    if (!copyPayload.empty()) {
      state.hCopy = CreateWindowW(L"BUTTON", L"Copy Details",
          WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
          cw - 222, ch - 44, 112, 30, hDlg, reinterpret_cast<HMENU>(ID_INFO_COPY), g_tray->hInst, nullptr);
    }
    state.hOk = CreateWindowW(L"BUTTON", L"OK",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW | BS_DEFPUSHBUTTON,
        cw - 102, ch - 44, 86, 30, hDlg, reinterpret_cast<HMENU>(ID_INFO_OK), g_tray->hInst, nullptr);
  }

  SendMessageW(state.hHeading, WM_SETFONT, reinterpret_cast<WPARAM>(state.hTitleFont), TRUE);
  SendMessageW(state.hBody, WM_SETFONT, reinterpret_cast<WPARAM>(state.hBodyFont), TRUE);
  SendMessageW(state.hOk, WM_SETFONT, reinterpret_cast<WPARAM>(state.hBodyFont), TRUE);
  if (state.hCopy) SendMessageW(state.hCopy, WM_SETFONT, reinterpret_cast<WPARAM>(state.hBodyFont), TRUE);

  RECT rc{};
  GetWindowRect(hDlg, &rc);
  int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
  SetWindowPos(hDlg, HWND_TOPMOST, (sw - (rc.right - rc.left)) / 2, (sh - (rc.bottom - rc.top)) / 2, 0, 0, SWP_NOSIZE);
  ShowWindow(hDlg, SW_SHOW);
  SetForegroundWindow(hDlg);

  MSG m{};
  while (!state.done && GetMessageW(&m, nullptr, 0, 0) > 0) {
    TranslateMessage(&m);
    DispatchMessageW(&m);
  }
  if (state.hTitleFont) DeleteObject(state.hTitleFont);
  if (state.hBodyFont) DeleteObject(state.hBodyFont);
  if (state.hBgBrush) DeleteObject(state.hBgBrush);
  if (state.hSurfaceBrush) DeleteObject(state.hSurfaceBrush);
  if (hIcon) DestroyIcon(hIcon);
  g_tray->modalOpen = false;

  if (isRebootPrompt) {
    if (state.restartTriggered) {
      runProcessCapture(L"shutdown.exe /r /t 5 /c \"Restart approved via IT Support prompt\"", false);
    } else {
      showBalloon(g_tray->brandName, "Restart snoozed. Save your work before your IT reboot window closes.");
    }
  }
}

static void handleMenuSelection(size_t idx) {
  if (!g_tray || idx >= g_tray->menuItems.size()) return;
  const TrayMenuEntry& item = g_tray->menuItems[idx];
  if (item.type == "message_support") {
    openSupportChatModal();
  } else if (item.type == "open_url") {
    std::string target = item.target.empty() ? g_tray->supportUrl : item.target;
    if (target.rfind("http://", 0) == 0 || target.rfind("https://", 0) == 0) {
      ShellExecuteW(nullptr, L"open", utf8ToWide(target).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    }
  } else if (item.type == "copy_hostname_ip") {
    std::string dummyMac;
    std::string info = getHostnameStr() + " (" + getPrimaryIpv4AndMac(dummyMac) + ")";
    copyUtf8ToClipboard(g_tray->hMainWnd, info);
    showBalloon(g_tray->brandName, "Copied: " + info);
  } else if (item.type == "custom_info") {
    openThemedInfoModal(g_tray->brandName, item.label.empty() ? g_tray->brandName : item.label, item.target, item.target, false);
  } else {
    std::string dummyMac;
    std::string host = getHostnameStr();
    std::string ip = getPrimaryIpv4AndMac(dummyMac);
    AgentStatusSnapshot snap = queryAgentStatus(getSelfDir());
    std::string statusLabel = "Connecting";
    if (snap.state == AgentConnState::Online) statusLabel = "Online";
    else if (snap.state == AgentConnState::Offline) statusLabel = "Offline";
    std::string msg = "Managed by: " + g_tray->brandName + "\nStatus: " + statusLabel;
    if (snap.lastCheckinEpoch > 0) {
      int64_t ago = getCurrentUnixEpochSec() - snap.lastCheckinEpoch;
      if (ago < 0) ago = 0;
      msg += "\nLast Check-in: " + (ago <= 2 ? std::string("just now") : (fmtInt(ago) + "s ago"));
    }
    msg += "\nHostname: " + host + "\nIP Address: " + ip;
    if (!g_tray->supportPhone.empty()) msg += "\nSupport Phone: " + g_tray->supportPhone;
    if (!g_tray->supportEmail.empty()) msg += "\nSupport Email: " + g_tray->supportEmail;
    if (!g_tray->supportUrl.empty()) msg += "\nSupport Portal: " + g_tray->supportUrl;
    openThemedInfoModal(g_tray->brandName + " - Endpoint Status", "Endpoint Status", msg, msg, false);
  }
}

static void processTrayInboxFile(const std::wstring& filePath) {
  std::string raw = readTextFile(filePath);
  DeleteFileW(filePath.c_str());
  if (raw.empty()) return;
  JsonVal m;
  if (!parseJson(raw, m)) return;
  if (const JsonVal* msgs = m.get("messages"); msgs && msgs->type == JsonVal::J_ARR) {
    for (const auto& item : msgs->arrVal) {
      std::string title = item.getStr("title", "IT Support");
      std::string msg = item.getStr("message");
      if (!msg.empty()) showBalloon(title, msg);
    }
    return;
  }
  std::string ttype = m.getStr("type");
  if (ttype.empty()) ttype = m.getStr("task_type");
  JsonVal p;
  if (const JsonVal* pv = m.get("payload"); pv && pv->type == JsonVal::J_OBJ) p = *pv;
  else if (!m.getStr("payload_json").empty()) parseJson(m.getStr("payload_json"), p);
  else p = m;

  std::string title = p.getStr("title", "IT Support");
  std::string msg = p.getStr("message", "IT Support Notification");
  if (ttype == "reboot_prompt") {
    openThemedInfoModal(
        (g_tray ? g_tray->brandName : "Vitrine RMM") + " - System Restart",
        title.empty() ? "System Restart Required" : title,
        msg.empty() ? "Your IT administrator scheduled an important restart to complete updates." : msg,
        "",
        true);
    return;
  }
  showBalloon(title, msg);
}

static LRESULT CALLBACK mainWndProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
  if (g_tray && g_tray->wmTaskbarCreated && msg == g_tray->wmTaskbarCreated) {
    applyTrayConfig(true);
    return 0;
  }
  switch (msg) {
    case WM_SETTINGCHANGE: {
      if (g_tray && isThemeSettingChange(lp)) {
        g_tray->useDarkTheme = resolveUseDarkTheme(g_tray->themeMode);
      }
      return 0;
    }
    case WM_MEASUREITEM: {
      if (g_tray && wp == 0) {
        auto* mis = reinterpret_cast<MEASUREITEMSTRUCT*>(lp);
        if (mis && mis->CtlType == ODT_MENU) {
          size_t idx = static_cast<size_t>(mis->itemData);
          if (idx < g_tray->activePopupItems.size()) {
            const ActivePopupMenuItem& entry = g_tray->activePopupItems[idx];
            if (entry.isSeparator) {
              mis->itemWidth = 220;
              mis->itemHeight = 11;
              return TRUE;
            }
            HDC hdc = GetDC(hWnd);
            HFONT hF = createUiFont(0, entry.isHeader ? FW_BOLD : FW_NORMAL);
            HGDIOBJ oldF = SelectObject(hdc, hF);
            std::wstring wTxt = utf8ToWide(entry.text);
            RECT trc{0, 0, 0, 0};
            DrawTextW(hdc, wTxt.c_str(), -1, &trc, DT_CALCRECT | DT_SINGLELINE);
            SelectObject(hdc, oldF);
            DeleteObject(hF);
            ReleaseDC(hWnd, hdc);
            int pad = entry.isHeader ? 44 : 32;
            mis->itemWidth = static_cast<UINT>(std::max<int>(220, (trc.right - trc.left) + pad));
            mis->itemHeight = entry.isHeader ? 34 : 30;
            return TRUE;
          }
        }
      }
      break;
    }
    case WM_DRAWITEM: {
      if (g_tray && wp == 0) {
        auto* dis = reinterpret_cast<DRAWITEMSTRUCT*>(lp);
        if (dis && dis->CtlType == ODT_MENU) {
          size_t idx = static_cast<size_t>(dis->itemData);
          if (idx < g_tray->activePopupItems.size()) {
            const ActivePopupMenuItem& entry = g_tray->activePopupItems[idx];
            WinThemePalette pal = getWinThemePalette(g_tray->popupDark);
            HDC hdc = dis->hDC;
            RECT rc = dis->rcItem;

            HBRUSH bgBr = CreateSolidBrush(pal.menuBg);
            FillRect(hdc, &rc, bgBr);
            DeleteObject(bgBr);

            if (entry.isSeparator) {
              int cy = (rc.top + rc.bottom) / 2;
              HPEN pen = CreatePen(PS_SOLID, 1, pal.menuSep);
              HGDIOBJ oldP = SelectObject(hdc, pen);
              MoveToEx(hdc, rc.left + 10, cy, nullptr);
              LineTo(hdc, rc.right - 10, cy);
              SelectObject(hdc, oldP);
              DeleteObject(pen);
              return TRUE;
            }

            if (entry.isHeader) {
              HBRUSH hdrBr = CreateSolidBrush(pal.surface);
              FillRect(hdc, &rc, hdrBr);
              DeleteObject(hdrBr);
              {
                Gdiplus::Graphics g(hdc);
                g.SetSmoothingMode(Gdiplus::SmoothingModeHighQuality);
                g.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHighQuality);
                Gdiplus::Color dotColor(255, 16, 185, 129);
                if (g_tray->popupConnState == AgentConnState::Connecting) {
                  dotColor = Gdiplus::Color(255, 245, 158, 11);
                } else if (g_tray->popupConnState == AgentConnState::Offline) {
                  dotColor = Gdiplus::Color(255, 239, 68, 68);
                }
                Gdiplus::SolidBrush dotBrush(dotColor);
                const float dotSize = 9.0f;
                const float dx = static_cast<float>(rc.left) + 12.0f;
                const float dy = static_cast<float>(rc.top) + (static_cast<float>(rc.bottom - rc.top) - dotSize) * 0.5f;
                g.FillEllipse(&dotBrush, dx, dy, dotSize, dotSize);
              }

              HFONT hF = createUiFont(0, FW_BOLD);
              HGDIOBJ oldF = SelectObject(hdc, hF);
              SetBkMode(hdc, TRANSPARENT);
              SetTextColor(hdc, pal.text);
              RECT txtRc{rc.left + 28, rc.top, rc.right - 10, rc.bottom};
              DrawTextW(hdc, utf8ToWide(entry.text).c_str(), -1, &txtRc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
              SelectObject(hdc, oldF);
              DeleteObject(hF);
              return TRUE;
            }

            bool hov = (dis->itemState & ODS_SELECTED) != 0 && !(dis->itemState & ODS_DISABLED);
            if (hov) {
              RECT hrc{rc.left + 3, rc.top + 2, rc.right - 3, rc.bottom - 2};
              HBRUSH hBr = CreateSolidBrush(pal.menuHover);
              HPEN hPen = CreatePen(PS_SOLID, 1, pal.menuHover);
              HGDIOBJ oldB = SelectObject(hdc, hBr);
              HGDIOBJ oldP = SelectObject(hdc, hPen);
              RoundRect(hdc, hrc.left, hrc.top, hrc.right, hrc.bottom, 6, 6);
              SelectObject(hdc, oldB);
              SelectObject(hdc, oldP);
              DeleteObject(hBr);
              DeleteObject(hPen);
            }
            HFONT hF = createUiFont(0, FW_NORMAL);
            HGDIOBJ oldF = SelectObject(hdc, hF);
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, (dis->itemState & ODS_DISABLED) ? pal.muted : pal.text);
            RECT txtRc{rc.left + 14, rc.top, rc.right - 12, rc.bottom};
            DrawTextW(hdc, utf8ToWide(entry.text).c_str(), -1, &txtRc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            SelectObject(hdc, oldF);
            DeleteObject(hF);
            return TRUE;
          }
        }
      }
      break;
    }
    case WM_TRAY_CALLBACK: {
      if (g_tray && (LOWORD(lp) == WM_RBUTTONUP || LOWORD(lp) == WM_CONTEXTMENU || LOWORD(lp) == WM_LBUTTONUP)) {
        g_tray->useDarkTheme = resolveUseDarkTheme(g_tray->themeMode);
        g_tray->popupDark = g_tray->useDarkTheme;
        WinThemePalette pal = getWinThemePalette(g_tray->popupDark);

        g_tray->activePopupItems.clear();
        AgentStatusSnapshot snap = queryAgentStatus(getSelfDir());
        g_tray->popupConnState = snap.state;
        std::string statusSuffix = " Connecting...";
        if (snap.state == AgentConnState::Online) statusSuffix = " Online";
        else if (snap.state == AgentConnState::Offline) statusSuffix = " Offline";

        HMENU hMenu = CreatePopupMenu();
        HBRUSH hMenuBg = CreateSolidBrush(pal.menuBg);
        MENUINFO mi{};
        mi.cbSize = sizeof(mi);
        mi.fMask = MIM_BACKGROUND | MIM_APPLYTOSUBMENUS;
        mi.hbrBack = hMenuBg;
        SetMenuInfo(hMenu, &mi);

        g_tray->activePopupItems.push_back({g_tray->brandName + statusSuffix, true, false});
        AppendMenuW(hMenu, MF_OWNERDRAW | MF_DISABLED, 0, reinterpret_cast<LPCWSTR>(static_cast<ULONG_PTR>(0)));
        g_tray->activePopupItems.push_back({"", false, true});
        AppendMenuW(hMenu, MF_OWNERDRAW | MF_DISABLED, 0, reinterpret_cast<LPCWSTR>(static_cast<ULONG_PTR>(1)));

        for (size_t i = 0; i < g_tray->menuItems.size(); i++) {
          size_t popupIdx = g_tray->activePopupItems.size();
          if (g_tray->menuItems[i].type == "separator") {
            g_tray->activePopupItems.push_back({"", false, true});
            AppendMenuW(hMenu, MF_OWNERDRAW | MF_DISABLED, 0, reinterpret_cast<LPCWSTR>(static_cast<ULONG_PTR>(popupIdx)));
          } else {
            g_tray->activePopupItems.push_back({g_tray->menuItems[i].label, false, false});
            AppendMenuW(hMenu, MF_OWNERDRAW, ID_MENU_BASE + i, reinterpret_cast<LPCWSTR>(static_cast<ULONG_PTR>(popupIdx)));
          }
        }
        POINT pt{};
        GetCursorPos(&pt);
        SetForegroundWindow(hWnd);
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, 0, hWnd, nullptr);
        PostMessageW(hWnd, WM_NULL, 0, 0);
        DestroyMenu(hMenu);
        DeleteObject(hMenuBg);
      }
      return 0;
    }
    case WM_COMMAND: {
      UINT id = LOWORD(wp);
      if (g_tray && id >= ID_MENU_BASE && id < ID_MENU_BASE + g_tray->menuItems.size()) {
        handleMenuSelection(id - ID_MENU_BASE);
      }
      return 0;
    }
    case WM_TIMER: {
      if (wp == ID_TRAY_TIMER && g_tray) {
        std::wstring selfDir = getSelfDir();
        std::wstring cfgPath = joinPath(selfDir, L"companion-config.json");
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (GetFileAttributesExW(cfgPath.c_str(), GetFileExInfoStandard, &fad)) {
          if (CompareFileTime(&fad.ftLastWriteTime, &g_tray->cfgMtime) != 0) {
            g_tray->cfgMtime = fad.ftLastWriteTime;
            applyTrayConfig(false);
          }
        }
        std::wstring trayDir = getTrayDataDir(selfDir);
        std::wstring legacyInboxPath = joinPath(trayDir, L"tray-inbox.json");
        if (fileExists(legacyInboxPath)) {
          processTrayInboxFile(legacyInboxPath);
        }
        WIN32_FIND_DATAW ffd{};
        HANDLE hFind = FindFirstFileW(joinPath(trayDir, L"inbox-*.json").c_str(), &ffd);
        if (hFind != INVALID_HANDLE_VALUE) {
          std::vector<std::wstring> files;
          do {
            if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
              files.push_back(joinPath(trayDir, ffd.cFileName));
            }
          } while (FindNextFileW(hFind, &ffd));
          FindClose(hFind);
          std::sort(files.begin(), files.end());
          for (const auto& fp : files) {
            processTrayInboxFile(fp);
          }
        }
      }
      return 0;
    }
    case WM_DESTROY:
      if (g_tray) Shell_NotifyIconW(NIM_DELETE, &g_tray->nid);
      PostQuitMessage(0);
      return 0;
  }
  return DefWindowProcW(hWnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
  TrayState st{};
  g_tray = &st;
  st.hInst = hInst;
  std::wstring selfDir = getSelfDir();
  JsonVal cfg;
  if (parseJson(readTextFile(joinPath(selfDir, L"companion-config.json")), cfg)) {
    st.serviceName = sanitizeIdentifier(cfg.getStr("ServiceName"), "VitrineAgent", 40);
  }
  std::wstring mutexName = L"Local\\VitrineTray-" + utf8ToWide(st.serviceName);
  HANDLE hMutex = CreateMutexW(nullptr, FALSE, mutexName.c_str());
  if (hMutex && GetLastError() == ERROR_ALREADY_EXISTS) {
    CloseHandle(hMutex);
    g_tray = nullptr;
    return 0;
  }

  Gdiplus::GdiplusStartupInput gdiInput;
  Gdiplus::GdiplusStartup(&st.gdiplusToken, &gdiInput, nullptr);
  st.wmTaskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");

  WNDCLASSW wc{};
  wc.lpfnWndProc = mainWndProc;
  wc.hInstance = hInst;
  wc.lpszClassName = L"VitrineTrayMsgWnd";
  RegisterClassW(&wc);

  st.hMainWnd = CreateWindowW(L"VitrineTrayMsgWnd", L"Vitrine Tray", 0, 0, 0, 0, 0, nullptr, nullptr, hInst, nullptr);
  WIN32_FILE_ATTRIBUTE_DATA fad{};
  if (GetFileAttributesExW(joinPath(selfDir, L"companion-config.json").c_str(), GetFileExInfoStandard, &fad)) {
    st.cfgMtime = fad.ftLastWriteTime;
  }
  applyTrayConfig(true);
  SetTimer(st.hMainWnd, ID_TRAY_TIMER, 4000, nullptr);

  MSG msg{};
  while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }

  if (st.currentIcon) DestroyIcon(st.currentIcon);
  if (st.gdiplusToken) Gdiplus::GdiplusShutdown(st.gdiplusToken);
  if (hMutex) CloseHandle(hMutex);
  g_tray = nullptr;
  return 0;
}
