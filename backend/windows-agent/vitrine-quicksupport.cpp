#include "vitrine-common.hpp"
#include <commctrl.h>

using namespace vitrine;

#define WM_QS_PROGRESS (WM_APP + 20)
#define WM_QS_READY (WM_APP + 21)
#define ID_BTN_DISCONNECT 201
#define ID_QS_TITLE 202
#define ID_QS_CODE 203
#define ID_QS_STATUS 204

struct QsState {
  HWND hWnd = nullptr;
  HWND hTitleLbl = nullptr;
  HWND hCodeLbl = nullptr;
  HWND hStatus = nullptr;
  HWND hDisconnectBtn = nullptr;
  HFONT hFontTitle = nullptr;
  HFONT hFontCode = nullptr;
  HFONT hFontBody = nullptr;
  HBRUSH hBgBrush = nullptr;
  std::string themeMode = "system";
  bool useDarkTheme = false;
  WinThemePalette palette{};
  int progressPct = 0;
  HANDLE hJob = nullptr;
  std::wstring stagingDir;
  JsonVal cfg;
  bool cleaningUp = false;
  bool connected = false;
};

static QsState* g_qs = nullptr;

static void launchTrackedChild(const std::wstring& exePath, const std::wstring& args, HANDLE hJob) {
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION pi{};
  std::wstring cmd = L"\"" + exePath + L"\"" + (args.empty() ? L"" : (L" " + args));
  if (CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
    if (hJob) AssignProcessToJobObject(hJob, pi.hProcess);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  }
}

static void cleanupQuickSupportSession(QsState* st) {
  if (!st || st->cleaningUp) return;
  st->cleaningUp = true;
  if (st->hJob) {
    TerminateJobObject(st->hJob, 0);
    CloseHandle(st->hJob);
    st->hJob = nullptr;
  }
  if (!st->stagingDir.empty()) {
    Sleep(250);
    deleteDirectoryTreeNative(st->stagingDir, true);
  }
}

static DWORD WINAPI qsWorkerThread(LPVOID param) {
  QsState* st = reinterpret_cast<QsState*>(param);
  const JsonVal& cfg = st->cfg;

  auto postProg = [&](int pct, const std::string& msg) {
    auto* copy = new std::string(msg);
    PostMessageW(st->hWnd, WM_QS_PROGRESS, static_cast<WPARAM>(pct), reinterpret_cast<LPARAM>(copy));
  };
  auto fail = [&](const std::string& msg) -> DWORD {
    auto* copy = new std::string(msg);
    PostMessageW(st->hWnd, WM_QS_READY, 0, reinterpret_cast<LPARAM>(copy));
    return 1;
  };

  std::string brandName = cfg.getStr("brandName", "Vitrine RMM");
  std::string svcName = sanitizeIdentifier(cfg.getStr("serviceName"), "VitrineAgent", 40);
  std::string meshServerUrl = cfg.getStr("meshServerUrl");
  std::string vitrineServerUrl = cfg.getStr("vitrineServerUrl");
  std::string meshGroupId = cfg.getStr("meshGroupId");
  std::string sessionCode = cfg.getStr("sessionCode");
  std::string enrollmentToken = cfg.getStr("enrollmentToken");
  std::string tenantId = cfg.getStr("tenantId", "quicksupport");
  bool allowSelfSigned = cfg.getBool("allowSelfSignedTls", false);
  bool strictVerify = cfg.getBool("strictAuthenticodeVerify", false);
  while (!meshServerUrl.empty() && meshServerUrl.back() == '/') meshServerUrl.pop_back();
  while (!vitrineServerUrl.empty() && vitrineServerUrl.back() == '/') vitrineServerUrl.pop_back();

  std::string authToken = !sessionCode.empty() ? sessionCode : enrollmentToken;
  if (vitrineServerUrl.empty() || authToken.empty()) {
    return fail("Missing QuickSupport session code or server configuration.");
  }

  std::wstring localApp = getEnvVar(L"LOCALAPPDATA");
  if (localApp.empty()) localApp = getEnvVar(L"TEMP");
  std::wstring wSvc = utf8ToWide(svcName);
  st->stagingDir = joinPath(localApp, wSvc + L"-QuickSupport");
  ensureDirRecursive(st->stagingDir);

  std::string archKey = detectWindowsArch();
  postProg(20, "Downloading verified remote support session engine (" + archKey + ")...");

  std::wstring agentExe = joinPath(st->stagingDir, wSvc + L".exe");
  std::wstring agentMsh = joinPath(st->stagingDir, wSvc + L".msh");
  if (!meshGroupId.empty() && !meshServerUrl.empty()) {
    std::string gid = meshGroupId;
    if (gid.rfind("mesh//", 0) == 0) gid = gid.substr(6);
    std::string dummy;
    httpDownloadToFile(meshServerUrl + "/meshsettings?id=" + urlEncodeAscii(gid), agentMsh, allowSelfSigned, dummy, 15000);
  }

  std::string errMesh;
  if (!httpDownloadToFile(vitrineServerUrl + "/api/agent/mesh-binary?arch=" + archKey + "&token=" + urlEncodeAscii(authToken), agentExe, allowSelfSigned, errMesh, 30000)) {
    std::string archNum = (archKey == "arm64") ? "43" : (archKey == "x86") ? "3" : "4";
    httpDownloadToFile(meshServerUrl + "/meshagents?id=" + archNum, agentExe, allowSelfSigned, errMesh, 30000);
  }
  if (fileExists(agentExe) && strictVerify) {
    std::string sigStatus;
    if (!verifyAuthenticodeSignature(agentExe, sigStatus)) {
      DeleteFileW(agentExe.c_str());
      return fail("Authenticode verification failed for QuickSupport relay binary: " + sigStatus);
    }
  }

  postProg(55, "Downloading signed QuickSupport companion & tray utilities...");
  std::wstring companionExe = joinPath(st->stagingDir, L"vitrine-companion.exe");
  std::wstring trayExe = joinPath(st->stagingDir, L"vitrine-tray.exe");
  std::string errC, errT;
  if (!httpDownloadToFile(vitrineServerUrl + "/api/agent/binary?component=companion&token=" + urlEncodeAscii(authToken), companionExe, allowSelfSigned, errC, 30000)) {
    return fail("Failed to download QuickSupport companion: " + errC);
  }
  if (!httpDownloadToFile(vitrineServerUrl + "/api/agent/binary?component=tray&token=" + urlEncodeAscii(authToken), trayExe, allowSelfSigned, errT, 30000)) {
    return fail("Failed to download QuickSupport tray: " + errT);
  }
  if (strictVerify) {
    std::string cs, ts;
    if (!verifyAuthenticodeSignature(companionExe, cs)) return fail("Strict signature check failed (companion): " + cs);
    if (!verifyAuthenticodeSignature(trayExe, ts)) return fail("Strict signature check failed (tray): " + ts);
  }

  postProg(80, "Registering temporary support session with " + brandName + "...");
  std::string macAddr;
  std::string ipAddr = getPrimaryIpv4AndMac(macAddr);
  SmbiosInfo smbios = readSmbiosInfo();
  WindowsFormFactor ff = collectWindowsFormFactor(smbios);
  std::string body = "{"
      "\"token\":\"" + jsonEscape(authToken) + "\","
      "\"sessionCode\":\"" + jsonEscape(sessionCode) + "\","
      "\"tenantId\":\"" + jsonEscape(tenantId) + "\","
      "\"hostname\":\"" + jsonEscape(getHostnameStr()) + "\","
      "\"osType\":\"windows\","
      "\"osVersion\":\"" + jsonEscape(getWindowsVersionCaption()) + "\","
      "\"ipAddress\":\"" + jsonEscape(ipAddr) + "\","
      "\"macAddress\":\"" + jsonEscape(macAddr) + "\","
      "\"serialNumber\":\"" + jsonEscape(smbios.serialNumber) + "\","
      "\"manufacturer\":\"" + jsonEscape(smbios.manufacturer) + "\","
      "\"model\":\"" + jsonEscape(smbios.model) + "\","
      "\"hardwareDetails\":{\"system\":{"
        "\"manufacturer\":\"" + jsonEscape(smbios.manufacturer) + "\","
        "\"model\":\"" + jsonEscape(smbios.model) + "\","
        "\"serialNumber\":\"" + jsonEscape(smbios.serialNumber) + "\","
        "\"chassisType\":" + fmtInt(ff.chassisType) + ","
        "\"chassisLabel\":\"" + jsonEscape(ff.chassisLabel) + "\","
        "\"hasBattery\":" + std::string(ff.hasBattery ? "true" : "false") + ","
        "\"isVirtualMachine\":" + std::string(ff.isVirtualMachine ? "true" : "false") + ","
        "\"hypervisorVendor\":\"" + jsonEscape(ff.hypervisorVendor) + "\","
        "\"osProductType\":\"" + jsonEscape(ff.osProductType) + "\""
      "}}"
      "}";
  HttpResponse er = httpRequest(vitrineServerUrl + "/api/agent/enroll", "POST", body, {{"Content-Type", "application/json"}}, allowSelfSigned, 15000);
  JsonVal enrollJson;
  if (er.statusCode < 200 || er.statusCode >= 300 || !parseJson(er.body, enrollJson)) {
    return fail("QuickSupport session registration failed (HTTP " + fmtInt(er.statusCode) + ")");
  }
  std::string devId = enrollJson.getStr("deviceId");
  std::string agTok = enrollJson.getStr("agentToken");
  if (agTok.empty()) agTok = enrollJson.getStr("agentAuthToken");
  if (devId.empty() || agTok.empty()) return fail("Enrollment response missing temporary session token.");

  std::string idOut = "{\"deviceId\":\"" + jsonEscape(devId) + "\",\"agentToken\":\"" + jsonEscape(agTok) +
      "\",\"agentAuthToken\":\"" + jsonEscape(agTok) + "\",\"vitrineServerUrl\":\"" + jsonEscape(vitrineServerUrl) +
      "\",\"tenantId\":\"" + jsonEscape(tenantId) + "\",\"serviceName\":\"" + jsonEscape(svcName) + "\"}";
  writeTextFile(joinPath(st->stagingDir, L"agent-identity.json"), idOut);

  std::string compCfgStr = "{}";
  if (const JsonVal* cc = cfg.get("companionConfig"); cc && cc->type == JsonVal::J_OBJ) {
    compCfgStr = serializeJson(*cc);
  }
  writeTextFile(joinPath(st->stagingDir, L"companion-config.json"), compCfgStr);

  if (fileExists(agentExe)) launchTrackedChild(agentExe, L"-connect", st->hJob);
  launchTrackedChild(companionExe, L"--user-mode", st->hJob);
  if (cfg.getBool("trayEnabled", true)) launchTrackedChild(trayExe, L"", st->hJob);

  auto* okMsg = new std::string("Connected cleanly. Share session code " + authToken + " with your technician.");
  PostMessageW(st->hWnd, WM_QS_READY, 1, reinterpret_cast<LPARAM>(okMsg));
  return 0;
}

static void refreshQsTheme(QsState* st) {
  if (!st) return;
  st->useDarkTheme = resolveUseDarkTheme(st->themeMode);
  st->palette = getWinThemePalette(st->useDarkTheme);
  if (st->hBgBrush) DeleteObject(st->hBgBrush);
  st->hBgBrush = CreateSolidBrush(st->palette.bg);
  if (st->hWnd && IsWindow(st->hWnd)) {
    applyWindowTitleBarTheme(st->hWnd, st->useDarkTheme);
    InvalidateRect(st->hWnd, nullptr, TRUE);
    if (st->hTitleLbl) InvalidateRect(st->hTitleLbl, nullptr, TRUE);
    if (st->hCodeLbl) InvalidateRect(st->hCodeLbl, nullptr, TRUE);
    if (st->hStatus) InvalidateRect(st->hStatus, nullptr, TRUE);
    if (st->hDisconnectBtn) InvalidateRect(st->hDisconnectBtn, nullptr, TRUE);
  }
}

static LRESULT CALLBACK qsWndProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_CTLCOLORSTATIC: {
      HDC hdc = reinterpret_cast<HDC>(wp);
      HWND ctl = reinterpret_cast<HWND>(lp);
      WinThemePalette pal = g_qs ? g_qs->palette : getWinThemePalette(true);
      SetBkMode(hdc, OPAQUE);
      SetBkColor(hdc, pal.bg);
      if (g_qs && ctl == g_qs->hCodeLbl) {
        SetTextColor(hdc, pal.accent);
      } else if (g_qs && ctl == g_qs->hTitleLbl) {
        SetTextColor(hdc, pal.text);
      } else {
        SetTextColor(hdc, pal.muted);
      }
      return reinterpret_cast<LRESULT>(g_qs && g_qs->hBgBrush ? g_qs->hBgBrush : GetStockObject(BLACK_BRUSH));
    }
    case WM_ERASEBKGND: {
      HDC hdc = reinterpret_cast<HDC>(wp);
      RECT rc{};
      GetClientRect(hWnd, &rc);
      if (g_qs && g_qs->hBgBrush) {
        FillRect(hdc, &rc, g_qs->hBgBrush);
      } else {
        HBRUSH br = CreateSolidBrush(RGB(15, 23, 42));
        FillRect(hdc, &rc, br);
        DeleteObject(br);
      }
      return 1;
    }
    case WM_PAINT: {
      PAINTSTRUCT ps{};
      HDC hdc = BeginPaint(hWnd, &ps);
      if (g_qs) {
        RECT pRc{24, 102, 440, 120};
        drawThemedProgressBar(hdc, pRc, g_qs->progressPct, g_qs->palette);
      }
      EndPaint(hWnd, &ps);
      return 0;
    }
    case WM_DRAWITEM: {
      auto* dis = reinterpret_cast<const DRAWITEMSTRUCT*>(lp);
      if (g_qs && dis && dis->CtlType == ODT_BUTTON) {
        drawThemedButton(dis, g_qs->palette, !g_qs->connected, g_qs->connected);
        return TRUE;
      }
      break;
    }
    case WM_SETTINGCHANGE: {
      if (g_qs && isThemeSettingChange(lp)) {
        refreshQsTheme(g_qs);
      }
      return 0;
    }
    case WM_QS_PROGRESS: {
      std::string* txt = reinterpret_cast<std::string*>(lp);
      if (g_qs) {
        g_qs->progressPct = static_cast<int>(wp);
        RECT pRc{24, 102, 440, 120};
        InvalidateRect(hWnd, &pRc, FALSE);
        if (txt) SetWindowTextW(g_qs->hStatus, utf8ToWide(*txt).c_str());
      }
      delete txt;
      return 0;
    }
    case WM_QS_READY: {
      std::string* txt = reinterpret_cast<std::string*>(lp);
      if (g_qs) {
        g_qs->connected = (wp != 0);
        g_qs->progressPct = wp ? 100 : 0;
        RECT pRc{24, 102, 440, 120};
        InvalidateRect(hWnd, &pRc, FALSE);
        if (txt) SetWindowTextW(g_qs->hStatus, utf8ToWide(*txt).c_str());
        SetWindowTextW(g_qs->hDisconnectBtn, wp ? L"Disconnect & End Session" : L"Close");
        InvalidateRect(g_qs->hDisconnectBtn, nullptr, TRUE);
      }
      delete txt;
      return 0;
    }
    case WM_COMMAND:
      if (LOWORD(wp) == ID_BTN_DISCONNECT) {
        cleanupQuickSupportSession(g_qs);
        DestroyWindow(hWnd);
      }
      return 0;
    case WM_CLOSE:
      cleanupQuickSupportSession(g_qs);
      DestroyWindow(hWnd);
      return 0;
    case WM_DESTROY:
      PostQuitMessage(0);
      return 0;
  }
  return DefWindowProcW(hWnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nCmdShow) {
  QsState st;
  g_qs = &st;

  if (!parseJson(readEmbeddedConfigJson(), st.cfg)) {
    MessageBoxW(nullptr, L"Invalid embedded QuickSupport configuration.", L"Vitrine QuickSupport", MB_OK | MB_ICONERROR);
    return 1;
  }

  st.themeMode = st.cfg.getStr("trayThemeMode");
  if (st.themeMode.empty()) {
    if (const JsonVal* cc = st.cfg.get("companionConfig"); cc && cc->type == JsonVal::J_OBJ) {
      st.themeMode = cc->getStr("ThemeMode", "system");
    }
  }
  if (st.themeMode.empty()) st.themeMode = "system";

  st.hJob = CreateJobObjectW(nullptr, nullptr);
  if (st.hJob) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(st.hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
  }

  st.useDarkTheme = resolveUseDarkTheme(st.themeMode);
  st.palette = getWinThemePalette(st.useDarkTheme);
  st.hBgBrush = CreateSolidBrush(st.palette.bg);

  WNDCLASSW wc{};
  wc.lpfnWndProc = qsWndProc;
  wc.hInstance = hInst;
  wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(1));
  wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  wc.lpszClassName = L"VitrineQuickSupportWnd";
  RegisterClassW(&wc);

  std::string brandName = st.cfg.getStr("brandName", "Vitrine RMM");
  std::string sessionCode = st.cfg.getStr("sessionCode");
  if (sessionCode.empty()) sessionCode = st.cfg.getStr("enrollmentToken", "SUPPORT");
  std::wstring wTitle = utf8ToWide(brandName + " - QuickSupport");

  st.hWnd = CreateWindowExW(
      0, L"VitrineQuickSupportWnd", wTitle.c_str(),
      WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
      CW_USEDEFAULT, CW_USEDEFAULT, 480, 275,
      nullptr, nullptr, hInst, nullptr);
  applyWindowTitleBarTheme(st.hWnd, st.useDarkTheme);

  HICON hAppIconBig = static_cast<HICON>(LoadImageW(hInst, MAKEINTRESOURCEW(1), IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR));
  HICON hAppIconSmall = static_cast<HICON>(LoadImageW(hInst, MAKEINTRESOURCEW(1), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
  if (hAppIconBig) SendMessageW(st.hWnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(hAppIconBig));
  if (hAppIconSmall) SendMessageW(st.hWnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(hAppIconSmall));

  NONCLIENTMETRICSW ncm{};
  ncm.cbSize = sizeof(ncm);
  SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
  st.hFontBody = CreateFontIndirectW(&ncm.lfMessageFont);
  LOGFONTW lfTitle = ncm.lfMessageFont;
  lfTitle.lfHeight = -20;
  lfTitle.lfWeight = FW_BOLD;
  st.hFontTitle = CreateFontIndirectW(&lfTitle);
  LOGFONTW lfCode = ncm.lfMessageFont;
  lfCode.lfHeight = -28;
  lfCode.lfWeight = FW_BOLD;
  st.hFontCode = CreateFontIndirectW(&lfCode);

  HWND hIconCtl = CreateWindowW(L"STATIC", nullptr, WS_CHILD | WS_VISIBLE | SS_ICON | SS_CENTERIMAGE, 24, 20, 40, 40, st.hWnd, nullptr, hInst, nullptr);
  if (hIconCtl && hAppIconBig) SendMessageW(hIconCtl, STM_SETICON, reinterpret_cast<WPARAM>(hAppIconBig), 0);
  st.hTitleLbl = CreateWindowW(L"STATIC", utf8ToWide(brandName + " QuickSupport").c_str(), WS_CHILD | WS_VISIBLE | SS_NOPREFIX, 74, 18, 366, 28, st.hWnd, reinterpret_cast<HMENU>(ID_QS_TITLE), hInst, nullptr);
  st.hCodeLbl = CreateWindowW(L"STATIC", utf8ToWide("Session Code: " + sessionCode).c_str(), WS_CHILD | WS_VISIBLE | SS_NOPREFIX, 74, 50, 366, 36, st.hWnd, reinterpret_cast<HMENU>(ID_QS_CODE), hInst, nullptr);
  st.hStatus = CreateWindowW(L"STATIC", L"Establishing encrypted support tunnel...", WS_CHILD | WS_VISIBLE | SS_NOPREFIX, 24, 134, 416, 36, st.hWnd, reinterpret_cast<HMENU>(ID_QS_STATUS), hInst, nullptr);
  st.hDisconnectBtn = CreateWindowW(L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 240, 184, 200, 32, st.hWnd, reinterpret_cast<HMENU>(ID_BTN_DISCONNECT), hInst, nullptr);

  SendMessageW(st.hTitleLbl, WM_SETFONT, reinterpret_cast<WPARAM>(st.hFontTitle), TRUE);
  SendMessageW(st.hCodeLbl, WM_SETFONT, reinterpret_cast<WPARAM>(st.hFontCode), TRUE);
  SendMessageW(st.hStatus, WM_SETFONT, reinterpret_cast<WPARAM>(st.hFontBody), TRUE);
  SendMessageW(st.hDisconnectBtn, WM_SETFONT, reinterpret_cast<WPARAM>(st.hFontBody), TRUE);

  RECT rc{};
  GetWindowRect(st.hWnd, &rc);
  int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
  SetWindowPos(st.hWnd, nullptr, (sw - (rc.right - rc.left)) / 2, (sh - (rc.bottom - rc.top)) / 2, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
  ShowWindow(st.hWnd, nCmdShow);

  HANDLE hWorker = CreateThread(nullptr, 0, qsWorkerThread, &st, 0, nullptr);
  MSG msg{};
  while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
  cleanupQuickSupportSession(&st);
  if (hWorker) {
    WaitForSingleObject(hWorker, 2000);
    CloseHandle(hWorker);
  }
  if (st.hFontTitle) DeleteObject(st.hFontTitle);
  if (st.hFontCode) DeleteObject(st.hFontCode);
  if (st.hFontBody) DeleteObject(st.hFontBody);
  if (st.hBgBrush) DeleteObject(st.hBgBrush);
  if (hAppIconBig) DestroyIcon(hAppIconBig);
  if (hAppIconSmall) DestroyIcon(hAppIconSmall);
  return 0;
}

