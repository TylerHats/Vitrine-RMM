#include "vitrine-common.hpp"

using namespace vitrine;

static SERVICE_STATUS_HANDLE g_svcStatusHandle = nullptr;
static SERVICE_STATUS g_svcStatus{};
static HANDLE g_stopEvent = nullptr;
static wchar_t g_serviceName[80] = L"VitrineAgent";

static void setGlobalServiceName(const std::wstring& name) {
  size_t len = name.size();
  if (len >= sizeof(g_serviceName) / sizeof(g_serviceName[0])) {
    len = (sizeof(g_serviceName) / sizeof(g_serviceName[0])) - 1;
  }
  for (size_t i = 0; i < len; ++i) g_serviceName[i] = name[i];
  g_serviceName[len] = L'\0';
}

static void reportServiceState(DWORD state, DWORD exitCode = NO_ERROR, DWORD waitHint = 0) {
  if (!g_svcStatusHandle) return;
  static DWORD checkPoint = 1;
  g_svcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_svcStatus.dwCurrentState = state;
  g_svcStatus.dwWin32ExitCode = exitCode;
  g_svcStatus.dwWaitHint = waitHint;
  g_svcStatus.dwControlsAccepted = (state == SERVICE_START_PENDING) ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
  g_svcStatus.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkPoint++;
  SetServiceStatus(g_svcStatusHandle, &g_svcStatus);
}

static DWORD WINAPI serviceCtrlHandler(DWORD ctrl, DWORD, LPVOID, LPVOID) {
  if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
    reportServiceState(SERVICE_STOP_PENDING, NO_ERROR, 5000);
    if (g_stopEvent) SetEvent(g_stopEvent);
    return NO_ERROR;
  }
  return ERROR_CALL_NOT_IMPLEMENTED;
}

static std::string getConfiguredServiceName(const std::wstring& selfDir) {
  JsonVal cfg;
  std::string cfgRaw = readTextFile(joinPath(selfDir, L"companion-config.json"));
  if (parseJson(cfgRaw, cfg)) {
    std::string s = sanitizeIdentifier(cfg.getStr("ServiceName"), "", 40);
    if (!s.empty()) return s;
  }
  JsonVal id;
  std::string idRaw = readTextFile(joinPath(selfDir, L"agent-identity.json"));
  if (parseJson(idRaw, id)) {
    std::string s = sanitizeIdentifier(id.getStr("serviceName"), "", 40);
    if (!s.empty()) return s;
  }
  std::string emb = readEmbeddedConfigJson();
  if (parseJson(emb, cfg)) {
    std::string s = sanitizeIdentifier(cfg.getStr("ServiceName"), "", 40);
    if (!s.empty()) return s;
  }
  return "VitrineAgent";
}

static std::wstring getTrayDataDir(const std::wstring& selfDir, const std::string& svcName) {
  std::wstring localApp = getEnvVar(L"LOCALAPPDATA");
  bool isQs = false;
  if (!localApp.empty() && selfDir.size() >= localApp.size()) {
    isQs = (_wcsnicmp(selfDir.c_str(), localApp.c_str(), localApp.size()) == 0);
  }
  std::wstring dir;
  if (isQs) {
    dir = joinPath(selfDir, L"tray");
  } else {
    std::wstring progData = getEnvVar(L"ProgramData");
    if (progData.empty()) progData = L"C:\\ProgramData";
    dir = joinPath(joinPath(progData, utf8ToWide(svcName)), L"tray");
  }
  ensureDirRecursive(dir);
  return dir;
}

static void performSelfUninstall(const std::wstring& selfDir, const std::string& defaultSvc, const JsonVal* payload, bool companionOnlyForced) {
  std::string svc = defaultSvc;
  if (payload) {
    std::string pSvc = sanitizeIdentifier(payload->getStr("serviceName"), "", 40);
    if (!pSvc.empty()) svc = pSvc;
  }
  std::wstring wSvc = utf8ToWide(svc);

  deleteRegistryRunValue(wSvc + L"-Tray");
  deleteRegistryRunValue(L"VitrineAgent-Tray");
  deleteUninstallEntry(wSvc);
  deleteUninstallEntry(L"VitrineAgent");
  stopAndDeleteServiceNative(wSvc + L"-Companion");
  stopAndDeleteServiceNative(L"VitrineAgent-Companion");

  if (payload) {
    std::string lapsAcc = payload->getStr("lapsAccountName");
    std::string lapsAct = payload->getStr("lapsAction");
    if (!lapsAcc.empty() && (lapsAct == "remove_account" || lapsAct == "disable_account")) {
      std::wstring wAcc = utf8ToWide(lapsAcc);
      if (lapsAct == "remove_account") removeLocalUserAccount(wAcc);
      else disableLocalUserAccount(wAcc);
    }
  }

  killProcessesByExeName(L"vitrine-tray.exe");

  std::wstring progData = getEnvVar(L"ProgramData");
  if (progData.empty()) progData = L"C:\\ProgramData";
  std::wstring trayDir1 = joinPath(joinPath(progData, wSvc), L"tray");
  std::wstring trayDir2 = L"C:\\ProgramData\\VitrineAgent\\tray";

  bool preserveMesh = companionOnlyForced || (payload && payload->getBool("preserveMeshAgent", false));
  if (!preserveMesh) {
    std::wstring localMesh = joinPath(selfDir, wSvc + L".exe");
    if (fileExists(localMesh)) {
      runProcessCapture(L"\"" + localMesh + L"\" -fulluninstall", true, 15000);
    }
    std::wstring defaultMesh = L"C:\\Program Files\\Mesh Agent\\MeshAgent.exe";
    if (fileExists(defaultMesh)) {
      runProcessCapture(L"\"" + defaultMesh + L"\" -fulluninstall", true, 15000);
    }
    deleteDirectoryTreeNative(trayDir1, true);
    deleteDirectoryTreeNative(trayDir2, true);
    deleteDirectoryTreeNative(selfDir, true);
  } else {
    DeleteFileW(joinPath(selfDir, L"vitrine-tray.exe").c_str());
    DeleteFileW(joinPath(selfDir, L"agent-identity.json").c_str());
    DeleteFileW(joinPath(selfDir, L"companion-config.json").c_str());
    DeleteFileW(joinPath(selfDir, L"vitrine-companion.ps1").c_str());
    DeleteFileW(joinPath(selfDir, L"vitrine-tray.ps1").c_str());
    deleteDirectoryTreeNative(trayDir1, true);
    deleteDirectoryTreeNative(trayDir2, true);
    std::wstring compExe = joinPath(selfDir, L"vitrine-companion.exe");
    if (!DeleteFileW(compExe.c_str())) {
      MoveFileExW(compExe.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
  }
}

static bool relayWolMagicPacket(const std::string& macRaw, const std::string& bcastIp, int port, std::string& outErr) {
  std::string hex;
  for (char c : macRaw) {
    if (std::isxdigit(static_cast<unsigned char>(c))) hex.push_back(c);
  }
  if (hex.size() != 12) {
    outErr = "Invalid MAC address";
    return false;
  }
  uint8_t mac[6]{};
  for (int i = 0; i < 6; i++) {
    mac[i] = static_cast<uint8_t>(std::strtoul(hex.substr(i * 2, 2).c_str(), nullptr, 16));
  }
  uint8_t pkt[102]{};
  std::memset(pkt, 0xFF, 6);
  for (int i = 1; i <= 16; i++) std::memcpy(pkt + i * 6, mac, 6);

  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    outErr = "WSAStartup failed";
    return false;
  }
  SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (s == INVALID_SOCKET) {
    WSACleanup();
    outErr = "UDP socket creation failed";
    return false;
  }
  BOOL bcast = TRUE;
  setsockopt(s, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&bcast), sizeof(bcast));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<u_short>(port > 0 ? port : 9));
  std::string targetIp = bcastIp.empty() ? "255.255.255.255" : bcastIp;
  if (InetPtonA(AF_INET, targetIp.c_str(), &addr.sin_addr) != 1) {
    addr.sin_addr.s_addr = INADDR_BROADCAST;
  }
  int sent = sendto(s, reinterpret_cast<const char*>(pkt), sizeof(pkt), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  closesocket(s);
  WSACleanup();
  if (sent != sizeof(pkt)) {
    outErr = "UDP WoL sendto failed";
    return false;
  }
  return true;
}

static void postTaskResult(
    const std::string& serverUrl,
    const std::string& token,
    const std::string& deviceId,
    const std::string& taskId,
    int exitCode,
    const std::string& stdoutStr,
    const std::string& stderrStr,
    const std::string& backupJobId,
    bool allowSelfSigned) {
  std::string url = serverUrl + "/api/agent/tasks/" + taskId + "/result";
  std::string body = "{\"deviceId\":\"" + jsonEscape(deviceId) + "\","
      "\"exitCode\":" + fmtInt(exitCode) + ","
      "\"stdout\":\"" + jsonEscape(stdoutStr) + "\","
      "\"stderr\":\"" + jsonEscape(stderrStr) + "\"";
  if (!backupJobId.empty()) body += ",\"backupJobId\":\"" + jsonEscape(backupJobId) + "\"";
  body += "}";
  httpRequest(url, "POST", body,
      {{"Content-Type", "application/json"}, {"x-vitrine-agent-token", token}},
      allowSelfSigned, 15000);
}

static void flushTrayOutbox(const std::wstring& trayDir, const std::string& serverUrl, const std::string& token, const std::string& deviceId, bool allowSelfSigned) {
  std::wstring outboxPath = joinPath(trayDir, L"tray-outbox.json");
  if (!fileExists(outboxPath)) return;
  std::string raw = readTextFile(outboxPath);
  DeleteFileW(outboxPath.c_str());
  if (raw.empty()) return;
  JsonVal j;
  if (!parseJson(raw, j)) return;
  std::string msg = j.getStr("message");
  std::string sender = j.getStr("sender", "Desktop User");
  if (msg.empty()) return;
  std::string body = "{\"deviceId\":\"" + jsonEscape(deviceId) + "\",\"sender\":\"" + jsonEscape(sender) + "\",\"message\":\"" + jsonEscape(msg) + "\"}";
  httpRequest(serverUrl + "/api/agent/chat", "POST", body,
      {{"Content-Type", "application/json"}, {"x-vitrine-agent-token", token}},
      allowSelfSigned, 10000);
}

static void enqueueTrayInboxItem(const std::wstring& trayDir, uint64_t seq, const std::string& jsonPayload) {
  std::wstring name = L"inbox-" + utf8ToWide(fmtUint64(GetTickCount64())) + L"-" + utf8ToWide(fmtUint64(seq)) + L".json";
  std::wstring tmpPath = joinPath(trayDir, name + L".tmp");
  std::wstring finalPath = joinPath(trayDir, name);
  writeTextFile(tmpPath, jsonPayload);
  MoveFileExW(tmpPath.c_str(), finalPath.c_str(), MOVEFILE_REPLACE_EXISTING);
}

static void writeAgentStatusFile(
    const std::wstring& trayDir,
    bool online,
    int64_t lastOkEpoch,
    int64_t lastAttemptEpoch,
    int64_t intervalSec,
    int httpStatus) {
  std::string body = "{\"online\":" + std::string(online ? "true" : "false") +
      ",\"lastCheckinEpoch\":" + fmtInt(lastOkEpoch) +
      ",\"lastAttemptEpoch\":" + fmtInt(lastAttemptEpoch) +
      ",\"intervalSec\":" + fmtInt(intervalSec) +
      ",\"httpStatus\":" + fmtInt(httpStatus) + "}";
  std::wstring tmpPath = joinPath(trayDir, L"agent-status.json.tmp");
  std::wstring finalPath = joinPath(trayDir, L"agent-status.json");
  if (writeTextFile(tmpPath, body)) {
    MoveFileExW(tmpPath.c_str(), finalPath.c_str(), MOVEFILE_REPLACE_EXISTING);
  }
}

static std::string buildWsUrlWin(const std::string& srvUrl, const std::string& tok, const std::string& devId) {
  std::string base = srvUrl;
  while (!base.empty() && base.back() == '/') base.pop_back();
  std::string wsBase;
  if (base.rfind("https://", 0) == 0) wsBase = "wss://" + base.substr(8);
  else if (base.rfind("http://", 0) == 0) wsBase = "ws://" + base.substr(7);
  else wsBase = "wss://" + base;
  return wsBase + "/ws/agent?token=" + tok + "&deviceId=" + devId + "&variant=windows-native";
}

static bool hasSeenOrAddTaskId(std::vector<std::string>& cache, const std::string& id) {
  if (id.empty()) return false;
  for (const auto& s : cache) {
    if (s == id) return true;
  }
  cache.push_back(id);
  if (cache.size() > 128) cache.erase(cache.begin());
  return false;
}

static void sendTaskResultDual(
    const std::string& serverUrl,
    const std::string& token,
    const std::string& deviceId,
    const std::string& taskId,
    int exitCode,
    const std::string& stdoutStr,
    const std::string& stderrStr,
    const std::string& backupJobId,
    bool allowSelfSigned,
    WinHttpWsClient* ws) {
  if (ws && ws->isConnected()) {
    std::string body = "{\"type\":\"task_result\",\"taskId\":\"" + jsonEscape(taskId) + "\","
        "\"deviceId\":\"" + jsonEscape(deviceId) + "\","
        "\"exitCode\":" + fmtInt(exitCode) + ","
        "\"stdout\":\"" + jsonEscape(stdoutStr) + "\","
        "\"stderr\":\"" + jsonEscape(stderrStr) + "\"";
    if (!backupJobId.empty()) body += ",\"backupJobId\":\"" + jsonEscape(backupJobId) + "\"";
    body += "}";
    if (ws->sendText(body)) return;
  }
  postTaskResult(serverUrl, token, deviceId, taskId, exitCode, stdoutStr, stderrStr, backupJobId, allowSelfSigned);
}

static ExecResult runWindowsScriptObject(
    const std::wstring& selfDir,
    const std::string& safeTaskId,
    const JsonVal& pObj,
    const std::string& body) {
  std::string lang = pObj.getStr("language");
  std::string sh = pObj.getStr("shell");
  bool isPy = (sh == "python" || lang == "python");
  bool isCmd = (sh == "cmd" || lang == "cmd");

  std::wstring tmpDir = getEnvVar(L"TEMP");
  if (tmpDir.empty()) tmpDir = selfDir;
  std::wstring tmpFile = joinPath(tmpDir, L"vitrine-task-" + utf8ToWide(safeTaskId) + (isPy ? L".py" : isCmd ? L".bat" : L".ps1"));

  std::vector<std::wstring> setVars;
  if (const JsonVal* envObj = pObj.get("env")) {
    if (envObj->type == JsonVal::J_OBJ) {
      for (const auto& kv : envObj->objVal) {
        if (kv.first.rfind("VITRINE_PARAM_", 0) == 0 && kv.second.type == JsonVal::J_STR) {
          std::wstring wk = utf8ToWide(kv.first);
          SetEnvironmentVariableW(wk.c_str(), utf8ToWide(kv.second.strVal).c_str());
          setVars.push_back(wk);
        }
      }
    }
  }

  writeTextFile(tmpFile, body);
  DWORD tOutMs = static_cast<DWORD>(std::max<int64_t>(5000, std::min<int64_t>(1800000, pObj.getInt("timeoutSec", 180) * 1000)));
  ExecResult er{};
  if (isPy) {
    er = runProcessCapture(L"python.exe \"" + tmpFile + L"\"", true, tOutMs);
    if (!er.launched) er = runProcessCapture(L"python3.exe \"" + tmpFile + L"\"", true, tOutMs);
    if (!er.launched) er = runProcessCapture(L"py.exe -3 \"" + tmpFile + L"\"", true, tOutMs);
  } else if (isCmd) {
    er = runProcessCapture(L"cmd.exe /c \"" + tmpFile + L"\"", true, tOutMs);
  } else {
    wchar_t sysDir[MAX_PATH]{};
    UINT sysLen = GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring psExe = (sysLen > 0 && sysLen < MAX_PATH)
        ? joinPath(std::wstring(sysDir, sysLen), L"WindowsPowerShell\\v1.0\\powershell.exe")
        : L"powershell.exe";
    if (!fileExists(psExe)) psExe = L"powershell.exe";

    std::string execPol = pObj.getStr("executionPolicy");
    bool allowExplicitBypass = execPol.size() == 6 &&
        execPol[0] == 'B' && execPol[1] == 'y' && execPol[2] == 'p' &&
        execPol[3] == 'a' && execPol[4] == 's' && execPol[5] == 's';
    std::wstring wExecPol = L"RemoteSigned";
    if (execPol == "AllSigned" || execPol == "RemoteSigned" || execPol == "Unrestricted" ||
        execPol == "Default" || allowExplicitBypass) {
      wExecPol = utf8ToWide(execPol);
    }
    std::wstring cmd = L"\"" + psExe + L"\" -NoProfile -NonInteractive -ExecutionPolicy " + wExecPol + L" -File \"" + tmpFile + L"\"";
    er = runProcessCapture(cmd, true, tOutMs);
  }
  DeleteFileW(tmpFile.c_str());
  for (const auto& wk : setVars) SetEnvironmentVariableW(wk.c_str(), nullptr);
  return er;
}

static bool executeSingleAgentTask(
    const std::wstring& selfDir,
    const std::string& svcName,
    const std::wstring& trayDir,
    const std::string& srv,
    const std::string& tok,
    const std::string& devId,
    bool allowSelfSigned,
    const JsonVal& t,
    uint64_t& traySeq,
    WinHttpWsClient* ws) {
  std::string taskId = t.getStr("id");
  std::string safeTaskId = sanitizeIdentifier(taskId, "task", 64);
  std::string ttype = t.getStr("type");
  if (ttype.empty()) ttype = t.getStr("task_type");

  JsonVal pObj;
  if (const JsonVal* pv = t.get("payload")) {
    if (pv->type == JsonVal::J_OBJ) pObj = *pv;
  }
  if (pObj.type != JsonVal::J_OBJ) {
    std::string pj = t.getStr("payload_json");
    if (!pj.empty()) parseJson(pj, pObj);
  }

  if (ttype == "tray_notify" || ttype == "reboot_prompt") {
    enqueueTrayInboxItem(trayDir, ++traySeq, serializeJson(t));
    sendTaskResultDual(srv, tok, devId, taskId, 0, "Delivered to user tray", "", "", allowSelfSigned, ws);
    return true;
  } else if (ttype == "wol_relay") {
    std::string wErr;
    int bPort = static_cast<int>(pObj.getInt("port", 9));
    bool ok = relayWolMagicPacket(pObj.getStr("mac"), pObj.getStr("broadcastIp"), bPort, wErr);
    sendTaskResultDual(srv, tok, devId, taskId, ok ? 0 : 1,
        ok ? ("Magic packet relayed to " + pObj.getStr("mac")) : "", wErr, "", allowSelfSigned, ws);
    return true;
  } else if (ttype == "self_uninstall") {
    sendTaskResultDual(srv, tok, devId, taskId, 0, "Self-uninstall initiated", "", "", allowSelfSigned, ws);
    performSelfUninstall(selfDir, svcName, &pObj, false);
    return false;
  } else if (ttype == "script" || ttype == "run_script" || ttype == "patch_scan" ||
             ttype == "patch_install" || ttype == "software_deploy" || ttype == "backup_job") {
    std::string body = pObj.getStr("code");
    if (body.empty()) body = pObj.getStr("command");
    if (body.empty() && ttype == "software_deploy") {
      std::string pkgId = sanitizeIdentifier(pObj.getStr("packageId"), "", 128);
      if (!pkgId.empty()) body = "winget install --id " + pkgId + " --silent --accept-package-agreements --accept-source-agreements";
    }
    if (body.empty() && ttype == "backup_job") {
      sendTaskResultDual(srv, tok, devId, taskId, 1, "", "No backup script command provided in task payload",
          pObj.getStr("backupJobId"), allowSelfSigned, ws);
      return true;
    }
    if (body.empty()) body = "Write-Output ok";

    ExecResult er = runWindowsScriptObject(selfDir, safeTaskId, pObj, body);
    sendTaskResultDual(srv, tok, devId, taskId, static_cast<int>(er.exitCode),
        er.output, er.launched ? "" : "Failed to launch script runtime",
        pObj.getStr("backupJobId"), allowSelfSigned, ws);
  }
  return true;
}

static bool applyCheckinResponsePayload(
    const JsonVal& rJson,
    JsonVal& cfg,
    const std::wstring& cfgPath,
    const std::wstring& selfDir,
    const std::string& svcName,
    const std::wstring& trayDir,
    const std::string& srv,
    const std::string& tok,
    const std::string& devId,
    bool allowSelfSigned,
    uint64_t& traySeq,
    std::vector<std::string>& seenTaskIds,
    WinHttpWsClient* ws) {
  const JsonVal* tc = rJson.get("trayConfig");
  if (tc && tc->type == JsonVal::J_OBJ && cfg.type == JsonVal::J_OBJ) {
    JsonVal nextCfg = cfg;
    if (!tc->getStr("brandName").empty()) {
      JsonVal bn; bn.type = JsonVal::J_STR; bn.strVal = tc->getStr("brandName");
      nextCfg.setObj("BrandName", std::move(bn));
    }
    if (const JsonVal* v = tc->get("iconUrl")) nextCfg.setObj("IconUrl", *v);
    if (const JsonVal* v = tc->get("themeMode")) nextCfg.setObj("ThemeMode", *v);
    if (const JsonVal* v = tc->get("enabled")) nextCfg.setObj("TrayEnabled", *v);
    if (const JsonVal* v = tc->get("tooltip")) nextCfg.setObj("Tooltip", *v);
    if (const JsonVal* v = tc->get("supportUrl")) nextCfg.setObj("SupportUrl", *v);
    if (const JsonVal* v = tc->get("supportPhone")) nextCfg.setObj("SupportPhone", *v);
    if (const JsonVal* v = tc->get("supportEmail")) nextCfg.setObj("SupportEmail", *v);
    if (const JsonVal* v = tc->get("menuItems")) nextCfg.setObj("MenuItems", *v);
    std::string nextStr = serializeJson(nextCfg);
    if (trimAscii(nextStr) != trimAscii(readTextFile(cfgPath))) {
      writeTextFile(cfgPath, nextStr);
      cfg = std::move(nextCfg);
    }
  }

  const JsonVal* chats = rJson.get("unreadChats");
  if (chats && chats->type == JsonVal::J_ARR) {
    for (const auto& ch : chats->arrVal) {
      std::string sender = ch.getStr("sender", "IT Support");
      std::string msg = ch.getStr("message");
      if (msg.empty()) continue;
      std::string noteJson = "{\"title\":\"" + jsonEscape("Message from " + sender) + "\",\"message\":\"" + jsonEscape(msg) + "\"}";
      enqueueTrayInboxItem(trayDir, ++traySeq, noteJson);
    }
  }

  const JsonVal* tasks = rJson.get("tasks");
  if (tasks && tasks->type == JsonVal::J_ARR) {
    for (const auto& t : tasks->arrVal) {
      std::string tid = t.getStr("id");
      if (hasSeenOrAddTaskId(seenTaskIds, tid)) continue;
      if (!executeSingleAgentTask(selfDir, svcName, trayDir, srv, tok, devId, allowSelfSigned, t, traySeq, ws)) {
        return false;
      }
    }
  }
  return true;
}

static void handleRpcExecWin(WinHttpWsClient& ws, const std::wstring& selfDir, const JsonVal& msg) {
  std::string reqId = msg.getStr("reqId");
  std::string cmd = msg.getStr("command");
  if (reqId.empty()) return;
  ExecResult er = runWindowsScriptObject(selfDir, sanitizeIdentifier(reqId, "rpc", 48), msg, cmd.empty() ? "Write-Output ok" : cmd);
  std::string resp = "{\"type\":\"rpc_response\",\"reqId\":\"" + jsonEscape(reqId) + "\","
      "\"exitCode\":" + fmtInt(static_cast<int>(er.exitCode)) + ","
      "\"stdout\":\"" + jsonEscape(er.output) + "\","
      "\"stderr\":\"" + jsonEscape(er.launched ? "" : "Failed to launch script runtime") + "\"}";
  ws.sendText(resp);
}

static void runWorkerLoop() {
  std::wstring selfDir = getSelfDir();
  TelemetrySampler sampler;
  sampler.sampleJson();  // Warm CPU/network baseline counters

  uint64_t checkinCount = 0;
  uint64_t traySeq = 0;
  int64_t sleepSec = 25;
  int64_t lastOkEpoch = 0;
  std::wstring lastTrayDir;
  int64_t lastIntervalSec = 25;
  int64_t wsBackoffSec = 5;
  int64_t nextWsRetryEpoch = 0;
  std::vector<std::string> seenTaskIds;

  while (true) {
    if (g_stopEvent && WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0) break;

    std::wstring cfgPath = joinPath(selfDir, L"companion-config.json");
    std::wstring idPath = joinPath(selfDir, L"agent-identity.json");
    JsonVal cfg;
    bool hasCfg = parseJson(readTextFile(cfgPath), cfg);
    bool allowSelfSigned = hasCfg ? cfg.getBool("AllowSelfSignedTls", false) : false;
    if (hasCfg) {
      int64_t iv = cfg.getInt("TelemetryIntervalSec", 25);
      sleepSec = std::max<int64_t>(10, std::min<int64_t>(3600, iv));
    }
    std::string svcName = getConfiguredServiceName(selfDir);
    std::wstring trayDir = getTrayDataDir(selfDir, svcName);
    lastTrayDir = trayDir;
    lastIntervalSec = sleepSec;

    JsonVal id;
    if (parseJson(readTextFile(idPath), id)) {
      std::string tok = id.getStr("agentToken");
      if (tok.empty()) tok = id.getStr("agentAuthToken");
      std::string srv = id.getStr("vitrineServerUrl");
      std::string devId = id.getStr("deviceId");
      while (!srv.empty() && srv.back() == '/') srv.pop_back();

      if (!tok.empty() && !srv.empty() && !devId.empty()) {
        int64_t nowEpoch = getCurrentUnixEpochSec();

        // 1. Primary Persistent WinHTTP WSS WebSocket Session
        if (nowEpoch >= nextWsRetryEpoch) {
          WinHttpWsClient ws;
          std::string wsUrl = buildWsUrlWin(srv, tok, devId);
          if (ws.connect(wsUrl, {{"x-vitrine-agent-token", tok}}, allowSelfSigned, 10000)) {
            int64_t sessStart = getCurrentUnixEpochSec();
            lastOkEpoch = sessStart;
            writeAgentStatusFile(trayDir, true, lastOkEpoch, sessStart, sleepSec, 101);
            ws.sendText("{\"type\":\"hello\",\"variant\":\"windows-native\",\"osType\":\"windows\",\"version\":\"3.0.0\"}");

            bool fullInv = (checkinCount % 24 == 0);
            checkinCount++;
            std::string initTel = collectCheckinPayloadJson(devId, sampler, fullInv);
            ws.sendText("{\"type\":\"telemetry\",\"payload\":" + initTel + "}");
            int64_t lastSentEpoch = getCurrentUnixEpochSec();

            while (ws.isConnected()) {
              if (g_stopEvent && WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0) break;
              flushTrayOutbox(trayDir, srv, tok, devId, allowSelfSigned);

              std::string inbound;
              while (ws.popMessage(inbound)) {
                JsonVal msg;
                if (parseJson(inbound, msg) && msg.type == JsonVal::J_OBJ) {
                  std::string mtype = msg.getStr("type");
                  if (mtype == "ping") {
                    ws.sendText("{\"type\":\"pong\"}");
                  } else if (mtype == "task") {
                    if (const JsonVal* tv = msg.get("task"); tv && tv->type == JsonVal::J_OBJ) {
                      if (!hasSeenOrAddTaskId(seenTaskIds, tv->getStr("id"))) {
                        if (!executeSingleAgentTask(selfDir, svcName, trayDir, srv, tok, devId, allowSelfSigned, *tv, traySeq, &ws)) {
                          ws.close();
                          return;
                        }
                      }
                    }
                  } else if (mtype == "rpc_exec") {
                    handleRpcExecWin(ws, selfDir, msg);
                  } else if (mtype == "chat") {
                    std::string cmsg = msg.getStr("message");
                    if (!cmsg.empty()) {
                      std::string sender = msg.getStr("sender", "IT Support");
                      std::string noteJson = "{\"title\":\"" + jsonEscape("Message from " + sender) + "\",\"message\":\"" + jsonEscape(cmsg) + "\"}";
                      enqueueTrayInboxItem(trayDir, ++traySeq, noteJson);
                    }
                  } else if (mtype == "checkin_ack") {
                    lastOkEpoch = getCurrentUnixEpochSec();
                    writeAgentStatusFile(trayDir, true, lastOkEpoch, lastOkEpoch, sleepSec, 200);
                    if (!applyCheckinResponsePayload(
                            msg, cfg, cfgPath, selfDir, svcName, trayDir, srv, tok, devId, allowSelfSigned, traySeq, seenTaskIds, &ws)) {
                      ws.close();
                      return;
                    }
                  }
                }
              }

              int64_t curEp = getCurrentUnixEpochSec();
              if (curEp - lastSentEpoch >= sleepSec) {
                if (parseJson(readTextFile(cfgPath), cfg)) {
                  sleepSec = std::max<int64_t>(10, std::min<int64_t>(3600, cfg.getInt("TelemetryIntervalSec", 25)));
                }
                bool doFull = (checkinCount % 24 == 0);
                checkinCount++;
                std::string payload = collectCheckinPayloadJson(devId, sampler, doFull);
                if (!ws.sendText("{\"type\":\"telemetry\",\"payload\":" + payload + "}")) break;
                lastSentEpoch = curEp;
                lastOkEpoch = curEp;
                writeAgentStatusFile(trayDir, true, lastOkEpoch, curEp, sleepSec, 200);
              }

              if (g_stopEvent && ws.msgEvent) {
                HANDLE handles[2] = {g_stopEvent, ws.msgEvent};
                if (WaitForMultipleObjects(2, handles, FALSE, 1500) == WAIT_OBJECT_0) break;
              } else if (ws.msgEvent) {
                WaitForSingleObject(ws.msgEvent, 1500);
              } else {
                Sleep(1500);
              }
            }

            ws.close();
            if (getCurrentUnixEpochSec() - sessStart >= 15) {
              wsBackoffSec = 5;
            } else {
              wsBackoffSec = std::min<int64_t>(60, wsBackoffSec * 2);
            }
            nextWsRetryEpoch = getCurrentUnixEpochSec() + wsBackoffSec;
          } else {
            wsBackoffSec = std::min<int64_t>(60, wsBackoffSec * 2);
            nextWsRetryEpoch = getCurrentUnixEpochSec() + wsBackoffSec;
          }
          if (g_stopEvent && WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0) break;
        }

        // 2. Automatic HTTP Fallback Check-in
        flushTrayOutbox(trayDir, srv, tok, devId, allowSelfSigned);

        bool includeFullInventory = (checkinCount % 24 == 0);
        checkinCount++;
        std::string payload = collectCheckinPayloadJson(devId, sampler, includeFullInventory);
        HttpResponse resp = httpRequest(
            srv + "/api/agent/checkin",
            "POST",
            payload,
            {{"Content-Type", "application/json"}, {"x-vitrine-agent-token", tok}},
            allowSelfSigned,
            20000);

        nowEpoch = getCurrentUnixEpochSec();
        JsonVal rJson;
        if (resp.statusCode >= 200 && resp.statusCode < 300 && parseJson(resp.body, rJson)) {
          lastOkEpoch = nowEpoch;
          writeAgentStatusFile(trayDir, true, lastOkEpoch, nowEpoch, sleepSec, resp.statusCode);
          if (!applyCheckinResponsePayload(
                  rJson, cfg, cfgPath, selfDir, svcName, trayDir, srv, tok, devId, allowSelfSigned, traySeq, seenTaskIds, nullptr)) {
            return;
          }
        } else {
          writeAgentStatusFile(trayDir, false, lastOkEpoch, nowEpoch, sleepSec, resp.statusCode);
        }
      } else {
        writeAgentStatusFile(trayDir, false, lastOkEpoch, getCurrentUnixEpochSec(), sleepSec, 0);
      }
    } else {
      writeAgentStatusFile(trayDir, false, lastOkEpoch, getCurrentUnixEpochSec(), sleepSec, 0);
    }

    DWORD waitMs = static_cast<DWORD>(sleepSec * 1000);
    if (g_stopEvent) {
      if (WaitForSingleObject(g_stopEvent, waitMs) == WAIT_OBJECT_0) break;
    } else {
      Sleep(waitMs);
    }
  }
  if (!lastTrayDir.empty()) {
    writeAgentStatusFile(lastTrayDir, false, lastOkEpoch, getCurrentUnixEpochSec(), lastIntervalSec, 0);
  }
}

static void WINAPI serviceMain(DWORD, LPWSTR*) {
  g_svcStatusHandle = RegisterServiceCtrlHandlerExW(g_serviceName, serviceCtrlHandler, nullptr);
  if (!g_svcStatusHandle) return;
  g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  reportServiceState(SERVICE_RUNNING);
  runWorkerLoop();
  if (g_stopEvent) CloseHandle(g_stopEvent);
  reportServiceState(SERVICE_STOPPED);
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
  int argc = 0;
  LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  bool userMode = false;
  bool uninstallAll = false;
  bool uninstallCompOnly = false;
  for (int i = 1; i < argc; i++) {
    if (_wcsicmp(argv[i], L"--user-mode") == 0) userMode = true;
    else if (_wcsicmp(argv[i], L"--uninstall") == 0) uninstallAll = true;
    else if (_wcsicmp(argv[i], L"--remove-companion-only") == 0) uninstallCompOnly = true;
  }
  if (argv) LocalFree(argv);

  std::wstring selfDir = getSelfDir();
  std::string svcStr = getConfiguredServiceName(selfDir);
  setGlobalServiceName(utf8ToWide(svcStr));

  if (uninstallAll || uninstallCompOnly) {
    performSelfUninstall(selfDir, svcStr, nullptr, uninstallCompOnly);
    return 0;
  }

  if (userMode) {
    runWorkerLoop();
    return 0;
  }

  std::wstring fullSvcName = utf8ToWide(svcStr) + L"-Companion";
  setGlobalServiceName(fullSvcName);
  SERVICE_TABLE_ENTRYW table[] = {
    { g_serviceName, serviceMain },
    { nullptr, nullptr }
  };
  if (!StartServiceCtrlDispatcherW(table)) {
    if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
      // Launched manually outside SCM
      runWorkerLoop();
    }
  }
  return 0;
}

