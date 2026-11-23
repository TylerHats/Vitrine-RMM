#include "vitrine-common.hpp"
#include <commctrl.h>
#include <bcrypt.h>

using namespace vitrine;

#define WM_INSTALL_PROGRESS (WM_APP + 10)
#define WM_INSTALL_FINISHED (WM_APP + 11)
#define ID_BTN_CLOSE 101
#define ID_TITLE_LBL 102
#define ID_WELCOME_LBL 103
#define ID_STATUS_LBL 104

struct InstallerState {
  HWND hWnd = nullptr;
  HWND hTitle = nullptr;
  HWND hWelcome = nullptr;
  HWND hStatus = nullptr;
  HWND hCloseBtn = nullptr;
  HFONT hFontTitle = nullptr;
  HFONT hFontBody = nullptr;
  HICON hAppIcon = nullptr;
  HBRUSH hBgBrush = nullptr;
  std::string themeMode = "system";
  bool useDarkTheme = false;
  WinThemePalette palette{};
  int progressPct = 0;
  bool silent = false;
  bool finished = false;
  bool success = false;
  std::string errMsg;
  JsonVal cfg;
  std::wstring logPath;
};

static InstallerState* g_state = nullptr;

static void writeInstallLog(const std::wstring& logPath, const std::string& msg) {
  if (logPath.empty()) return;
  HANDLE h = CreateFileW(logPath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return;
  SYSTEMTIME st{};
  GetLocalTime(&st);
  char ts[48];
  std::snprintf(ts, sizeof(ts), "[%04d-%02d-%02d %02d:%02d:%02d] ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
  std::string line = std::string(ts) + msg + "\r\n";
  DWORD written = 0;
  WriteFile(h, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
  CloseHandle(h);
}

static void postUiProgress(InstallerState* st, int pct, const std::string& statusText) {
  writeInstallLog(st->logPath, statusText);
  if (!st->silent && st->hWnd) {
    auto* copy = new std::string(statusText);
    PostMessageW(st->hWnd, WM_INSTALL_PROGRESS, static_cast<WPARAM>(pct), reinterpret_cast<LPARAM>(copy));
  }
}

static std::string generateCsprngPassword() {
  static const char chars[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-";
  uint8_t rnd[22]{};
  if (BCryptGenRandom(nullptr, rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
    for (size_t i = 0; i < sizeof(rnd); i++) rnd[i] = static_cast<uint8_t>((GetTickCount64() + i * 37) & 0xFF);
  }
  std::string pw;
  for (size_t i = 0; i < sizeof(rnd); i++) pw.push_back(chars[rnd[i] % (sizeof(chars) - 1)]);
  pw += "!9vR";
  return pw;
}

static DWORD WINAPI installerWorkerThread(LPVOID param) {
  InstallerState* st = reinterpret_cast<InstallerState*>(param);
  const JsonVal& cfg = st->cfg;

  std::string brandName = cfg.getStr("brandName", "Vitrine RMM");
  std::string svcName = sanitizeIdentifier(cfg.getStr("serviceName"), "VitrineAgent", 40);
  std::string meshServerUrl = cfg.getStr("meshServerUrl");
  std::string vitrineServerUrl = cfg.getStr("vitrineServerUrl");
  std::string meshGroupId = cfg.getStr("meshGroupId");
  std::string enrollmentToken = cfg.getStr("enrollmentToken");
  std::string tenantId = cfg.getStr("tenantId", "default");
  std::string targetDeviceId = cfg.getStr("targetDeviceId");
  bool allowSelfSigned = cfg.getBool("allowSelfSignedTls", false);
  bool strictVerify = cfg.getBool("strictAuthenticodeVerify", false);
#ifdef VITRINE_COMPANION_ONLY_DEFAULT
  bool companionOnly = cfg.getBool("companionOnly", true);
#else
  bool companionOnly = cfg.getBool("companionOnly", false);
#endif
  bool lapsAutoCreate = cfg.getBool("lapsAutoCreate", true);
  std::string lapsAccountName = sanitizeIdentifier(cfg.getStr("lapsAccountName"), "LocalAdmin", 20);

  while (!meshServerUrl.empty() && meshServerUrl.back() == '/') meshServerUrl.pop_back();
  while (!vitrineServerUrl.empty() && vitrineServerUrl.back() == '/') vitrineServerUrl.pop_back();

  std::wstring wSvc = utf8ToWide(svcName);
  std::wstring progFiles = getEnvVar(L"ProgramFiles");
  if (progFiles.empty()) progFiles = L"C:\\Program Files";
  std::wstring installDir = joinPath(progFiles, wSvc);

  std::wstring progData = getEnvVar(L"ProgramData");
  if (progData.empty()) progData = L"C:\\ProgramData";
  std::wstring logDir = joinPath(progData, wSvc);
  ensureDirRecursive(logDir);
  st->logPath = joinPath(logDir, L"install.log");

  auto failWith = [&](const std::string& msg) -> DWORD {
    st->success = false;
    st->errMsg = msg;
    writeInstallLog(st->logPath, "ERROR: " + msg);
    if (!st->silent && st->hWnd) PostMessageW(st->hWnd, WM_INSTALL_FINISHED, 0, 0);
    return 1;
  };

  if (vitrineServerUrl.empty() || enrollmentToken.empty()) {
    return failWith("Missing Vitrine Server URL or provisioning token in executable configuration.");
  }

  postUiProgress(st, 10, "Preparing installation directory & stopping previous companion service...");
  ensureDirRecursive(installDir);
  stopAndDeleteServiceNative(wSvc + L"-Companion");
  killProcessesByExeName(L"vitrine-companion.exe");
  killProcessesByExeName(L"vitrine-tray.exe");

  std::string archKey = detectWindowsArch();
  if (!companionOnly && !meshServerUrl.empty()) {
    // Stop and unregister any previous `wSvc` service entry cleanly (preserving `<wSvc>.db`) so
    // MeshAgent's `-install` always registers `<installDir>\<wSvc>.exe` cleanly instead of its
    // existing-service `MeshAgent.exe` fallback branch, and never touches unrelated services.
    stopAndDeleteServiceNative(wSvc);
    killProcessesByExeName(wSvc + L".exe");
    Sleep(500);
    DeleteFileW(joinPath(installDir, L"MeshAgent.exe").c_str());
    DeleteFileW(joinPath(installDir, L"MeshAgent.db").c_str());

    postUiProgress(st, 28, "Downloading EV-signed MeshCentral core agent binary (" + archKey + ")...");
    std::wstring agentExe = joinPath(installDir, wSvc + L".exe");
    std::wstring agentMsh = joinPath(installDir, wSvc + L".msh");

    if (!meshGroupId.empty()) {
      std::string gid = meshGroupId;
      if (gid.rfind("mesh//", 0) == 0) gid = gid.substr(6);
      std::string dummyErr;
      httpDownloadToFile(meshServerUrl + "/meshsettings?id=" + urlEncodeAscii(gid), agentMsh, allowSelfSigned, dummyErr, 15000);
    }

    std::string dlErr;
    std::string meshBinUrl = vitrineServerUrl + "/api/agent/mesh-binary?arch=" + archKey + "&token=" + urlEncodeAscii(enrollmentToken);
    if (!httpDownloadToFile(meshBinUrl, agentExe, allowSelfSigned, dlErr, 30000)) {
      writeInstallLog(st->logPath, "Primary mesh-binary failed (" + dlErr + "), falling back to MeshCentral direct binary...");
      std::string archNum = (archKey == "arm64") ? "43" : (archKey == "x86") ? "3" : "4";
      if (!httpDownloadToFile(meshServerUrl + "/meshagents?id=" + archNum, agentExe, allowSelfSigned, dlErr, 30000)) {
        writeInstallLog(st->logPath, "WARNING: MeshAgent download failed: " + dlErr);
      }
    }

    if (fileExists(agentExe)) {
      std::string sigStatus;
      if (strictVerify && !verifyAuthenticodeSignature(agentExe, sigStatus)) {
        DeleteFileW(agentExe.c_str());
        return failWith("Strict Authenticode verification failed for " + svcName + ".exe: " + sigStatus);
      }
      postUiProgress(st, 45, "Installing MeshCentral Windows service...");
      runProcessCapture(L"\"" + agentExe + L"\" -install --meshServiceName=\"" + wSvc + L"\"", true, 30000);
    }
  }

  if (!companionOnly && lapsAutoCreate) {
    postUiProgress(st, 55, "Configuring managed local administrator account (" + lapsAccountName + ")...");
    createOrUpdateLocalAdminAccount(utf8ToWide(lapsAccountName), utf8ToWide(generateCsprngPassword()));
  }

  postUiProgress(st, 65, "Downloading signed Vitrine Companion & Desktop Tray executables...");
  std::wstring companionExe = joinPath(installDir, L"vitrine-companion.exe");
  std::wstring trayExe = joinPath(installDir, L"vitrine-tray.exe");
  std::string dlCompErr, dlTrayErr;
  std::string binQuerySuffix = "&token=" + urlEncodeAscii(enrollmentToken);
  if (!targetDeviceId.empty()) {
    binQuerySuffix += "&deviceId=" + urlEncodeAscii(targetDeviceId);
  }

  if (!httpDownloadToFile(vitrineServerUrl + "/api/agent/binary?component=companion" + binQuerySuffix, companionExe, allowSelfSigned, dlCompErr, 30000)) {
    return failWith("Failed to download vitrine-companion.exe: " + dlCompErr);
  }
  if (!httpDownloadToFile(vitrineServerUrl + "/api/agent/binary?component=tray" + binQuerySuffix, trayExe, allowSelfSigned, dlTrayErr, 30000)) {
    return failWith("Failed to download vitrine-tray.exe: " + dlTrayErr);
  }

  if (strictVerify) {
    std::string cs, ts;
    if (!verifyAuthenticodeSignature(companionExe, cs)) {
      DeleteFileW(companionExe.c_str());
      return failWith("Strict Authenticode check failed for vitrine-companion.exe: " + cs);
    }
    if (!verifyAuthenticodeSignature(trayExe, ts)) {
      DeleteFileW(trayExe.c_str());
      return failWith("Strict Authenticode check failed for vitrine-tray.exe: " + ts);
    }
  }

  postUiProgress(st, 80, "Enrolling endpoint with " + brandName + " control plane...");
  std::string macAddr;
  std::string ipAddr = getPrimaryIpv4AndMac(macAddr);
  SmbiosInfo smbios = readSmbiosInfo();
  WindowsFormFactor ff = collectWindowsFormFactor(smbios);
  std::string cpuModel;
  uint32_t cpuMhz = 0;
  readCpuRegistryInfo(cpuModel, cpuMhz);
  SYSTEM_INFO sysInfo{};
  GetNativeSystemInfo(&sysInfo);

  std::string enrollBody = "{"
      "\"token\":\"" + jsonEscape(enrollmentToken) + "\","
      "\"tenantId\":\"" + jsonEscape(tenantId) + "\","
      "\"hostname\":\"" + jsonEscape(getHostnameStr()) + "\","
      "\"osType\":\"windows\","
      "\"osVersion\":\"" + jsonEscape(getWindowsVersionCaption()) + "\","
      "\"deviceRole\":\"" + jsonEscape(ff.inferredRole) + "\","
      "\"ipAddress\":\"" + jsonEscape(ipAddr) + "\","
      "\"macAddress\":\"" + jsonEscape(macAddr) + "\","
      "\"serialNumber\":\"" + jsonEscape(smbios.serialNumber) + "\","
      "\"manufacturer\":\"" + jsonEscape(smbios.manufacturer) + "\","
      "\"model\":\"" + jsonEscape(smbios.model) + "\","
      "\"biosVersion\":\"" + jsonEscape(smbios.biosVersion) + "\","
      "\"cpuModel\":\"" + jsonEscape(cpuModel) + "\","
      "\"cpuCores\":" + fmtInt(sysInfo.dwNumberOfProcessors) + ","
      "\"hardwareDetails\":{\"system\":{"
        "\"manufacturer\":\"" + jsonEscape(smbios.manufacturer) + "\","
        "\"model\":\"" + jsonEscape(smbios.model) + "\","
        "\"serialNumber\":\"" + jsonEscape(smbios.serialNumber) + "\","
        "\"biosVersion\":\"" + jsonEscape(smbios.biosVersion) + "\","
        "\"chassisType\":" + fmtInt(ff.chassisType) + ","
        "\"chassisLabel\":\"" + jsonEscape(ff.chassisLabel) + "\","
        "\"hasBattery\":" + std::string(ff.hasBattery ? "true" : "false") + ","
        "\"isVirtualMachine\":" + std::string(ff.isVirtualMachine ? "true" : "false") + ","
        "\"isHypervisorHost\":" + std::string(ff.isHypervisorHost ? "true" : "false") + ","
        "\"hypervisorVendor\":\"" + jsonEscape(ff.hypervisorVendor) + "\","
        "\"osProductType\":\"" + jsonEscape(ff.osProductType) + "\""
      "}}";
  if (!targetDeviceId.empty()) enrollBody += ",\"deviceId\":\"" + jsonEscape(targetDeviceId) + "\"";
  enrollBody += "}";

  HttpResponse er = httpRequest(
      vitrineServerUrl + "/api/agent/enroll",
      "POST",
      enrollBody,
      {{"Content-Type", "application/json"}},
      allowSelfSigned,
      15000);
  JsonVal enrollJson;
  if (er.statusCode < 200 || er.statusCode >= 300 || !parseJson(er.body, enrollJson)) {
    return failWith("Endpoint enrollment failed (HTTP " + fmtInt(er.statusCode) + "): " + er.body);
  }
  std::string devId = enrollJson.getStr("deviceId");
  std::string agTok = enrollJson.getStr("agentToken");
  if (agTok.empty()) agTok = enrollJson.getStr("agentAuthToken");
  if (devId.empty() || agTok.empty()) {
    return failWith("Enrollment response missing deviceId or agentToken.");
  }

  std::wstring idPath = joinPath(installDir, L"agent-identity.json");
  std::string idOut = "{"
      "\"deviceId\":\"" + jsonEscape(devId) + "\","
      "\"agentToken\":\"" + jsonEscape(agTok) + "\","
      "\"agentAuthToken\":\"" + jsonEscape(agTok) + "\","
      "\"vitrineServerUrl\":\"" + jsonEscape(vitrineServerUrl) + "\","
      "\"tenantId\":\"" + jsonEscape(tenantId) + "\","
      "\"serviceName\":\"" + jsonEscape(svcName) + "\""
      "}";
  writeTextFile(idPath, idOut);
  hardenAdminOnlyAcl(idPath);

  std::wstring trayDir = joinPath(joinPath(progData, wSvc), L"tray");
  ensureDirRecursive(trayDir);
  grantUsersModifyAcl(trayDir);

  std::string compCfgStr = "{}";
  if (const JsonVal* cc = cfg.get("companionConfig"); cc && cc->type == JsonVal::J_OBJ) {
    compCfgStr = serializeJson(*cc);
  }
  writeTextFile(joinPath(installDir, L"companion-config.json"), compCfgStr);

  // Clean up any legacy .ps1 files from earlier PS1 installations
  DeleteFileW(joinPath(installDir, L"vitrine-companion.ps1").c_str());
  DeleteFileW(joinPath(installDir, L"vitrine-tray.ps1").c_str());

  postUiProgress(st, 92, "Registering & starting " + svcName + "-Companion Windows Service...");
  std::string svcErr;
  if (!installAndStartServiceNative(
          wSvc + L"-Companion",
          utf8ToWide(brandName + " Companion Service"),
          utf8ToWide("Telemetry, policy enforcement, and automated remediation service for " + brandName),
          companionExe,
          svcErr)) {
    return failWith("Failed to start Companion service: " + svcErr);
  }

  setRegistryRunValue(wSvc + L"-Tray", L"\"" + trayExe + L"\"");
  registerUninstallEntry(
      wSvc,
      utf8ToWide(brandName + " Endpoint Agent"),
      utf8ToWide(brandName),
      L"\"" + companionExe + L"\" --uninstall",
      installDir,
      companionExe);

  if (!st->silent && cfg.getBool("trayEnabled", true)) {
    runProcessCapture(L"\"" + trayExe + L"\"", false);
  }

  postUiProgress(st, 100, brandName + " installed successfully (" + devId + ").");
  st->success = true;
  if (!st->silent && st->hWnd) PostMessageW(st->hWnd, WM_INSTALL_FINISHED, 1, 0);
  return 0;
}

static void refreshInstallerTheme(InstallerState* st) {
  if (!st) return;
  st->useDarkTheme = resolveUseDarkTheme(st->themeMode);
  st->palette = getWinThemePalette(st->useDarkTheme);
  if (st->hBgBrush) DeleteObject(st->hBgBrush);
  st->hBgBrush = CreateSolidBrush(st->palette.bg);
  if (st->hWnd && IsWindow(st->hWnd)) {
    applyWindowTitleBarTheme(st->hWnd, st->useDarkTheme);
    InvalidateRect(st->hWnd, nullptr, TRUE);
    if (st->hTitle) InvalidateRect(st->hTitle, nullptr, TRUE);
    if (st->hWelcome) InvalidateRect(st->hWelcome, nullptr, TRUE);
    if (st->hStatus) InvalidateRect(st->hStatus, nullptr, TRUE);
    if (st->hCloseBtn) InvalidateRect(st->hCloseBtn, nullptr, TRUE);
  }
}

static LRESULT CALLBACK installerWndProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_CTLCOLORSTATIC: {
      HDC hdc = reinterpret_cast<HDC>(wp);
      HWND ctl = reinterpret_cast<HWND>(lp);
      WinThemePalette pal = g_state ? g_state->palette : getWinThemePalette(true);
      SetBkMode(hdc, OPAQUE);
      SetBkColor(hdc, pal.bg);
      if (g_state && ctl == g_state->hTitle) {
        SetTextColor(hdc, pal.text);
      } else if (g_state && ctl == g_state->hStatus && g_state->finished && !g_state->success) {
        SetTextColor(hdc, pal.danger);
      } else {
        SetTextColor(hdc, pal.muted);
      }
      return reinterpret_cast<LRESULT>(g_state && g_state->hBgBrush ? g_state->hBgBrush : GetStockObject(BLACK_BRUSH));
    }
    case WM_ERASEBKGND: {
      HDC hdc = reinterpret_cast<HDC>(wp);
      RECT rc{};
      GetClientRect(hWnd, &rc);
      if (g_state && g_state->hBgBrush) {
        FillRect(hdc, &rc, g_state->hBgBrush);
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
      if (g_state) {
        RECT pRc{24, 94, 480, 114};
        drawThemedProgressBar(hdc, pRc, g_state->progressPct, g_state->palette);
      }
      EndPaint(hWnd, &ps);
      return 0;
    }
    case WM_DRAWITEM: {
      auto* dis = reinterpret_cast<const DRAWITEMSTRUCT*>(lp);
      if (g_state && dis && dis->CtlType == ODT_BUTTON) {
        drawThemedButton(dis, g_state->palette, true, g_state->finished && !g_state->success);
        return TRUE;
      }
      break;
    }
    case WM_SETTINGCHANGE: {
      if (g_state && isThemeSettingChange(lp)) {
        refreshInstallerTheme(g_state);
      }
      return 0;
    }
    case WM_INSTALL_PROGRESS: {
      std::string* txt = reinterpret_cast<std::string*>(lp);
      if (g_state) {
        g_state->progressPct = static_cast<int>(wp);
        RECT pRc{24, 94, 480, 114};
        InvalidateRect(hWnd, &pRc, FALSE);
        if (txt) SetWindowTextW(g_state->hStatus, utf8ToWide(*txt).c_str());
      }
      delete txt;
      return 0;
    }
    case WM_INSTALL_FINISHED: {
      if (g_state) {
        g_state->finished = true;
        EnableWindow(g_state->hCloseBtn, TRUE);
        SetWindowTextW(g_state->hCloseBtn, wp ? L"Finish" : L"Close");
        InvalidateRect(g_state->hCloseBtn, nullptr, TRUE);
        if (!wp && !g_state->errMsg.empty()) {
          SetWindowTextW(g_state->hStatus, utf8ToWide("Installation failed: " + g_state->errMsg).c_str());
        }
      }
      return 0;
    }
    case WM_COMMAND:
      if (LOWORD(wp) == ID_BTN_CLOSE && g_state && g_state->finished) {
        DestroyWindow(hWnd);
      }
      return 0;
    case WM_CLOSE:
      if (g_state && g_state->finished) DestroyWindow(hWnd);
      return 0;
    case WM_DESTROY:
      PostQuitMessage(0);
      return 0;
  }
  return DefWindowProcW(hWnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nCmdShow) {
  int argc = 0;
  LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  bool silent = false;
  for (int i = 1; i < argc; i++) {
    if (_wcsicmp(argv[i], L"/S") == 0 || _wcsicmp(argv[i], L"--silent") == 0 || _wcsicmp(argv[i], L"/quiet") == 0 || _wcsicmp(argv[i], L"-Silent") == 0) {
      silent = true;
    }
  }
  if (argv) LocalFree(argv);

  InstallerState st;
  st.silent = silent;
  g_state = &st;

  std::string emb = readEmbeddedConfigJson();
  if (!parseJson(emb, st.cfg)) {
    if (!silent) MessageBoxW(nullptr, L"Invalid embedded configuration resource.", L"Vitrine RMM Installer", MB_OK | MB_ICONERROR);
    return 1;
  }
  if (st.cfg.getStr("guiStyle") == "silent_headless") st.silent = true;

  st.themeMode = st.cfg.getStr("trayThemeMode");
  if (st.themeMode.empty()) {
    if (const JsonVal* cc = st.cfg.get("companionConfig"); cc && cc->type == JsonVal::J_OBJ) {
      st.themeMode = cc->getStr("ThemeMode", "system");
    }
  }
  if (st.themeMode.empty()) st.themeMode = "system";

  if (st.silent) {
    HANDLE hThread = CreateThread(nullptr, 0, installerWorkerThread, &st, 0, nullptr);
    if (hThread) {
      WaitForSingleObject(hThread, 180000);
      CloseHandle(hThread);
    }
    return st.success ? 0 : 1;
  }

  st.useDarkTheme = resolveUseDarkTheme(st.themeMode);
  st.palette = getWinThemePalette(st.useDarkTheme);
  st.hBgBrush = CreateSolidBrush(st.palette.bg);

  WNDCLASSW wc{};
  wc.lpfnWndProc = installerWndProc;
  wc.hInstance = hInst;
  wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(1));
  wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  wc.lpszClassName = L"VitrineInstallerWnd";
  RegisterClassW(&wc);

  std::string brandName = st.cfg.getStr("brandName", "Vitrine RMM");
  std::string welcomeText = st.cfg.getStr("welcomeText", "Installing Enterprise IT Support & Endpoint Protection");
  std::wstring wTitle = utf8ToWide(brandName + " Installer");

  st.hWnd = CreateWindowExW(
      0, L"VitrineInstallerWnd", wTitle.c_str(),
      WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
      CW_USEDEFAULT, CW_USEDEFAULT, 520, 250,
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
  lfTitle.lfHeight = -22;
  lfTitle.lfWeight = FW_BOLD;
  st.hFontTitle = CreateFontIndirectW(&lfTitle);

  HWND hIconCtl = CreateWindowW(L"STATIC", nullptr, WS_CHILD | WS_VISIBLE | SS_ICON | SS_CENTERIMAGE, 24, 22, 40, 40, st.hWnd, nullptr, hInst, nullptr);
  if (hIconCtl && hAppIconBig) SendMessageW(hIconCtl, STM_SETICON, reinterpret_cast<WPARAM>(hAppIconBig), 0);
  st.hTitle = CreateWindowW(L"STATIC", utf8ToWide(brandName).c_str(), WS_CHILD | WS_VISIBLE | SS_NOPREFIX, 74, 20, 406, 30, st.hWnd, reinterpret_cast<HMENU>(ID_TITLE_LBL), hInst, nullptr);
  st.hWelcome = CreateWindowW(L"STATIC", utf8ToWide(welcomeText).c_str(), WS_CHILD | WS_VISIBLE | SS_NOPREFIX, 74, 52, 406, 26, st.hWnd, reinterpret_cast<HMENU>(ID_WELCOME_LBL), hInst, nullptr);
  st.hStatus = CreateWindowW(L"STATIC", L"Initializing setup...", WS_CHILD | WS_VISIBLE | SS_NOPREFIX, 24, 126, 456, 36, st.hWnd, reinterpret_cast<HMENU>(ID_STATUS_LBL), hInst, nullptr);
  st.hCloseBtn = CreateWindowW(L"BUTTON", L"Installing...", WS_CHILD | WS_VISIBLE | WS_DISABLED | BS_OWNERDRAW, 372, 172, 108, 30, st.hWnd, reinterpret_cast<HMENU>(ID_BTN_CLOSE), hInst, nullptr);

  SendMessageW(st.hTitle, WM_SETFONT, reinterpret_cast<WPARAM>(st.hFontTitle), TRUE);
  SendMessageW(st.hWelcome, WM_SETFONT, reinterpret_cast<WPARAM>(st.hFontBody), TRUE);
  SendMessageW(st.hStatus, WM_SETFONT, reinterpret_cast<WPARAM>(st.hFontBody), TRUE);
  SendMessageW(st.hCloseBtn, WM_SETFONT, reinterpret_cast<WPARAM>(st.hFontBody), TRUE);

  RECT rc{};
  GetWindowRect(st.hWnd, &rc);
  int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
  SetWindowPos(st.hWnd, nullptr, (sw - (rc.right - rc.left)) / 2, (sh - (rc.bottom - rc.top)) / 2, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
  ShowWindow(st.hWnd, nCmdShow);

  HANDLE hWorker = CreateThread(nullptr, 0, installerWorkerThread, &st, 0, nullptr);
  MSG msg{};
  while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
  if (hWorker) {
    WaitForSingleObject(hWorker, 2000);
    CloseHandle(hWorker);
  }
  if (st.hFontTitle) DeleteObject(st.hFontTitle);
  if (st.hFontBody) DeleteObject(st.hFontBody);
  if (st.hBgBrush) DeleteObject(st.hBgBrush);
  if (hAppIconBig) DestroyIcon(hAppIconBig);
  if (hAppIconSmall) DestroyIcon(hAppIconSmall);
  return st.success ? 0 : 1;
}

