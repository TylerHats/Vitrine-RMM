#pragma once

#include "posix_common.hpp"
#include "posix_telemetry.hpp"

#include <dirent.h>
#include <signal.h>
#include <sys/wait.h>

namespace vitrine_posix {

inline bool isSafeParamKey(const std::string& k) {
  if (k.rfind("VITRINE_PARAM_", 0) != 0 || k.size() > 80) return false;
  for (size_t i = 14; i < k.size(); i++) {
    unsigned char uc = static_cast<unsigned char>(k[i]);
    if (!std::isalnum(uc) && k[i] != '_') return false;
  }
  return k.size() > 14;
}

inline bool isSafePkgName(const std::string& pkg) {
  if (pkg.empty() || pkg.size() > 128) return false;
  for (char c : pkg) {
    unsigned char uc = static_cast<unsigned char>(c);
    if (!std::isalnum(uc) && c != '.' && c != '_' && c != '+' && c != '-' && c != ':' && c != '/') return false;
  }
  return true;
}

inline std::string getServiceSlug(const JsonVal& cfg, const JsonVal& ident) {
  std::string raw = ident.getStr("serviceSlug");
  if (raw.empty()) raw = cfg.getStr("ServiceName");
  return toLowerAscii(sanitizeId(raw, "vitrineagent", 48));
}

inline std::string getTrayDir(const JsonVal& cfg, const JsonVal& ident, const std::string& baseDir) {
  if (cfg.getBool("isQuickSupport", false) || baseDir.find("/.local") != std::string::npos ||
      baseDir.find("Application Support") != std::string::npos) {
    return baseDir + "/tray";
  }
  return "/var/lib/" + getServiceSlug(cfg, ident) + "/tray";
}

inline void writeAgentStatusFile(
    const std::string& trayDir,
    bool online,
    int64_t lastOkEpoch,
    int64_t lastAttemptEpoch,
    int64_t intervalSec,
    int statusCode,
    const std::string& transport) {
#ifdef VITRINE_HEADLESS_ONLY
  (void)trayDir; (void)online; (void)lastOkEpoch; (void)lastAttemptEpoch; (void)intervalSec; (void)statusCode; (void)transport;
  return;
#else
  if (trayDir.empty()) return;
  ensureDir(trayDir, 0755);
  std::ostringstream js;
  js << "{\"online\":" << (online ? "true" : "false")
     << ",\"lastOkEpoch\":" << lastOkEpoch
     << ",\"lastAttemptEpoch\":" << lastAttemptEpoch
     << ",\"intervalSec\":" << intervalSec
     << ",\"statusCode\":" << statusCode
     << ",\"transport\":\"" << jsonEscape(transport) << "\"}";
  writeTextFileAtomic(trayDir + "/agent-status.json", js.str(), 0644);
#endif
}

inline void enqueueTrayInboxItem(const std::string& trayDir, uint64_t seq, const std::string& itemJson, bool headlessMode) {
#ifdef VITRINE_HEADLESS_ONLY
  (void)trayDir; (void)seq; (void)itemJson; (void)headlessMode;
  return;
#else
  if (headlessMode || trayDir.empty()) return;
  std::string inboxDir = trayDir + "/inbox";
  ensureDir(inboxDir, 0755);
  char name[128];
  std::snprintf(name, sizeof(name), "%s/inbox-%lld-%llu.json",
                inboxDir.c_str(),
                static_cast<long long>(std::time(nullptr)),
                static_cast<unsigned long long>(seq));
  writeTextFileAtomic(name, itemJson, 0644);
#endif
}

inline void flushTrayOutbox(
    const std::string& trayDir,
    const std::string& srvUrl,
    const std::string& token,
    const std::string& deviceId,
    bool allowSelfSigned,
    WsClient* ws,
    bool headlessMode) {
#ifdef VITRINE_HEADLESS_ONLY
  (void)trayDir; (void)srvUrl; (void)token; (void)deviceId; (void)allowSelfSigned; (void)ws; (void)headlessMode;
  return;
#else
  if (headlessMode || trayDir.empty()) return;
  std::string outboxDir = trayDir + "/outbox";
  DIR* d = ::opendir(outboxDir.c_str());
  if (!d) return;

  std::vector<std::string> files;
  struct dirent* ent;
  while ((ent = ::readdir(d)) != nullptr) {
    std::string fn = ent->d_name;
    if (fn.rfind("outbox-", 0) == 0 && fn.size() > 12 && fn.compare(fn.size() - 5, 5, ".json") == 0) {
      files.push_back(outboxDir + "/" + fn);
    }
  }
  ::closedir(d);
  std::sort(files.begin(), files.end());

  for (const std::string& fp : files) {
    struct stat lst{};
    if (::lstat(fp.c_str(), &lst) != 0 || S_ISLNK(lst.st_mode)) continue;
    std::string raw = readTextFile(fp);
    ::unlink(fp.c_str());
    JsonVal item;
    if (!parseJson(raw, item) || item.type != JsonVal::J_OBJ) continue;
    std::string act = item.getStr("action", "chat");
    if (act == "reboot") {
      if (::fork() == 0) {
        ::execl("/sbin/shutdown", "shutdown", "-r", "+0", "Restart approved via IT Support prompt", nullptr);
        ::_exit(1);
      }
    } else if (act == "chat" && !srvUrl.empty() && !token.empty()) {
      std::string msg = trimStr(item.getStr("message"));
      std::string sender = trimStr(item.getStr("sender", "Desktop User"));
      if (msg.empty()) continue;
      if (ws && ws->connected) {
        ws->sendText("{\"type\":\"chat\",\"sender\":\"" + jsonEscape(sender) + "\",\"message\":\"" + jsonEscape(msg) + "\"}");
      } else {
        std::string body = "{\"deviceId\":\"" + jsonEscape(deviceId) + "\",\"sender\":\"" + jsonEscape(sender) + "\",\"message\":\"" + jsonEscape(msg) + "\"}";
        httpPostJson(srvUrl + "/api/agent/chat", body, {{"x-vitrine-agent-token", token}}, allowSelfSigned, 8000);
      }
    }
  }
#endif
}

inline void syncTrayConfigFromResp(
    const JsonVal& resp,
    JsonVal& cfg,
    const std::string& cfgPath,
    bool headlessMode) {
#ifdef VITRINE_HEADLESS_ONLY
  (void)resp; (void)cfg; (void)cfgPath; (void)headlessMode;
  return;
#else
  if (headlessMode) return;
  const JsonVal* tc = resp.get("trayConfig");
  if (!tc || tc->type != JsonVal::J_OBJ) return;
  if (cfg.type != JsonVal::J_OBJ) cfg.type = JsonVal::J_OBJ;
  JsonVal nextCfg = cfg;
  static const std::pair<const char*, const char*> kMap[] = {
    {"brandName", "BrandName"}, {"iconUrl", "IconUrl"}, {"themeMode", "ThemeMode"},
    {"enabled", "TrayEnabled"}, {"tooltip", "Tooltip"}, {"supportUrl", "SupportUrl"},
    {"supportPhone", "SupportPhone"}, {"supportEmail", "SupportEmail"}, {"menuItems", "MenuItems"}
  };
  for (const auto& kv : kMap) {
    if (const JsonVal* v = tc->get(kv.first)) {
      nextCfg.setObj(kv.second, *v);
    }
  }
  std::string before = serializeJson(cfg);
  std::string after = serializeJson(nextCfg);
  if (before != after) {
    writeTextFileAtomic(cfgPath, after, 0644);
    cfg = std::move(nextCfg);
  }
#endif
}

inline bool relayWolMagicPacket(
    const std::string& macRaw,
    const std::string& bcastIp,
    int port,
    std::string& outErr) {
  std::string hex;
  for (char c : macRaw) {
    if (std::isxdigit(static_cast<unsigned char>(c))) hex.push_back(c);
  }
  if (hex.size() != 12) {
    outErr = "Invalid MAC address";
    return false;
  }
  uint8_t mac[6];
  for (int i = 0; i < 6; i++) {
    mac[i] = static_cast<uint8_t>(std::strtoul(hex.substr(i * 2, 2).c_str(), nullptr, 16));
  }
  uint8_t pkt[102];
  std::memset(pkt, 0xFF, 6);
  for (int i = 0; i < 16; i++) std::memcpy(pkt + 6 + i * 6, mac, 6);

  int s = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) {
    outErr = "Socket creation failed";
    return false;
  }
  int yes = 1;
  ::setsockopt(s, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));
  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port > 0 ? port : 9));
  std::string dst = bcastIp.empty() ? "255.255.255.255" : bcastIp;
  if (::inet_pton(AF_INET, dst.c_str(), &addr.sin_addr) != 1) {
    ::close(s);
    outErr = "Invalid broadcast IP";
    return false;
  }
  ssize_t sent = ::sendto(s, pkt, sizeof(pkt), 0, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
  ::close(s);
  if (sent != static_cast<ssize_t>(sizeof(pkt))) {
    outErr = "UDP sendto failed";
    return false;
  }
  return true;
}

inline void runCommandWithTimeout(
    const std::string& cmd,
    const std::string& shellOrLang,
    const std::map<std::string, std::string>& envVars,
    int timeoutSec,
    int& outExitCode,
    std::string& outStdout,
    std::string& outStderr) {
  outExitCode = 1;
  outStdout.clear();
  outStderr.clear();
  int clampSec = std::max(5, std::min(3600, timeoutSec));

  int outPipe[2] = {-1, -1};
  int errPipe[2] = {-1, -1};
  if (::pipe(outPipe) != 0 || ::pipe(errPipe) != 0) {
    if (outPipe[0] >= 0) { ::close(outPipe[0]); ::close(outPipe[1]); }
    if (errPipe[0] >= 0) { ::close(errPipe[0]); ::close(errPipe[1]); }
    outStderr = "pipe() failed";
    return;
  }

  pid_t pid = ::fork();
  if (pid < 0) {
    ::close(outPipe[0]); ::close(outPipe[1]);
    ::close(errPipe[0]); ::close(errPipe[1]);
    outStderr = "fork() failed";
    return;
  }

  if (pid == 0) {
    ::setsid();
    ::dup2(outPipe[1], STDOUT_FILENO);
    ::dup2(errPipe[1], STDERR_FILENO);
    ::close(outPipe[0]); ::close(outPipe[1]);
    ::close(errPipe[0]); ::close(errPipe[1]);

    for (const auto& kv : envVars) {
      if (isSafeParamKey(kv.first)) {
        ::setenv(kv.first.c_str(), kv.second.c_str(), 1);
      }
    }

    if (shellOrLang == "python") {
      ::execlp("python3", "python3", "-c", cmd.c_str(), nullptr);
      ::execlp("python", "python", "-c", cmd.c_str(), nullptr);
      ::_exit(127);
    } else {
      std::string shBin = "/bin/bash";
#ifdef __APPLE__
      if (shellOrLang == "zsh" || (shellOrLang != "bash" && pathExists("/bin/zsh"))) shBin = "/bin/zsh";
#else
      if (!pathExists("/bin/bash")) shBin = "/bin/sh";
#endif
      ::execl(shBin.c_str(), shBin.c_str(), "-c", cmd.c_str(), nullptr);
      ::execl("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
      ::_exit(127);
    }
  }

  ::close(outPipe[1]);
  ::close(errPipe[1]);
  ::fcntl(outPipe[0], F_SETFL, O_NONBLOCK);
  ::fcntl(errPipe[0], F_SETFL, O_NONBLOCK);

  std::time_t deadline = std::time(nullptr) + clampSec;
  bool timedOut = false;
  bool outOpen = true, errOpen = true;
  char buf[4096];

  while (outOpen || errOpen) {
    std::time_t now = std::time(nullptr);
    if (now >= deadline) {
      timedOut = true;
      ::kill(-pid, SIGKILL);
      ::kill(pid, SIGKILL);
      break;
    }
    struct pollfd pfds[2];
    nfds_t nfds = 0;
    if (outOpen) { pfds[nfds++] = {outPipe[0], POLLIN, 0}; }
    if (errOpen) { pfds[nfds++] = {errPipe[0], POLLIN, 0}; }
    int remMs = static_cast<int>(std::min<int64_t>(1000, (deadline - now) * 1000));
    ::poll(pfds, nfds, std::max(50, remMs));

    if (outOpen) {
      while (true) {
        ssize_t n = ::read(outPipe[0], buf, sizeof(buf));
        if (n > 0) {
          outStdout.append(buf, static_cast<size_t>(n));
          if (outStdout.size() > 64000) outStdout.erase(0, outStdout.size() - 32000);
        } else if (n == 0) {
          outOpen = false;
          break;
        } else {
          if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) outOpen = false;
          break;
        }
      }
    }
    if (errOpen) {
      while (true) {
        ssize_t n = ::read(errPipe[0], buf, sizeof(buf));
        if (n > 0) {
          outStderr.append(buf, static_cast<size_t>(n));
          if (outStderr.size() > 32000) outStderr.erase(0, outStderr.size() - 16000);
        } else if (n == 0) {
          errOpen = false;
          break;
        } else {
          if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) errOpen = false;
          break;
        }
      }
    }
  }

  ::close(outPipe[0]);
  ::close(errPipe[0]);

  int status = 0;
  ::waitpid(pid, &status, 0);
  if (timedOut) {
    outExitCode = 124;
    if (!outStderr.empty()) outStderr += "\n";
    outStderr += "Command execution timed out";
  } else if (WIFEXITED(status)) {
    outExitCode = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    outExitCode = 128 + WTERMSIG(status);
  }
  if (outStdout.size() > 32000) outStdout = outStdout.substr(outStdout.size() - 32000);
  if (outStderr.size() > 16000) outStderr = outStderr.substr(outStderr.size() - 16000);
}

inline void performSelfUninstall(
    const std::string& baseDir,
    const std::string& slug,
    const JsonVal* payload) {
  std::string safeSlug = sanitizeId(payload ? payload->getStr("serviceName", slug) : slug, slug, 48);
  std::string acc = payload ? sanitizeId(payload->getStr("lapsAccountName"), "", 20) : "";
  std::string act = payload ? payload->getStr("lapsAction") : "";
  bool preserveMesh = payload ? payload->getBool("preserveMeshAgent", false) : false;

  if (!acc.empty()) {
    int ec = 0; std::string o, e;
#ifdef __APPLE__
    if (act == "remove_account") runCommandWithTimeout("sysadminctl -deleteUser '" + acc + "'", "bash", {}, 15, ec, o, e);
    else if (act == "disable_account") runCommandWithTimeout("pwpolicy -u '" + acc + "' -disableuser", "bash", {}, 15, ec, o, e);
#else
    if (act == "remove_account") runCommandWithTimeout("userdel -r '" + acc + "' && rm -f /etc/sudoers.d/90-vitrine-laps", "bash", {}, 15, ec, o, e);
    else if (act == "disable_account") runCommandWithTimeout("usermod -L '" + acc + "'", "bash", {}, 15, ec, o, e);
#endif
  }

  std::ostringstream cleanup;
#ifdef __APPLE__
  cleanup << "(sleep 1; "
          << (preserveMesh ? "" : "if [ -x '" + baseDir + "/meshagent' ]; then '" + baseDir + "/meshagent' -uninstall; fi; ")
          << "PLIST='/Library/LaunchDaemons/com." << safeSlug << ".companion.plist'; "
          << "launchctl bootout system \"$PLIST\" 2>/dev/null || launchctl unload -w \"$PLIST\" 2>/dev/null || true; "
          << "rm -f \"$PLIST\"; rm -rf '" << baseDir << "') >/dev/null 2>&1 &";
#else
  cleanup << "(sleep 1; pkill -f '" << baseDir << "/vitrine-tray.py' || true; "
          << (preserveMesh ? "" : "if [ -x '" + baseDir + "/meshagent' ]; then '" + baseDir + "/meshagent' -uninstall; fi; ")
          << "systemctl disable --now '" << safeSlug << "-companion.service' 2>/dev/null || true; "
          << "rm -f '/etc/systemd/system/" << safeSlug << "-companion.service' '/etc/xdg/autostart/" << safeSlug << "-tray.desktop'; "
          << "systemctl daemon-reload 2>/dev/null || true; rm -rf '" << baseDir << "') >/dev/null 2>&1 &";
#endif
  int ec = 0; std::string o, e;
  runCommandWithTimeout(cleanup.str(), "bash", {}, 10, ec, o, e);
}

inline std::string resolveDefaultPkgTaskCmd(const std::string& ttype, const JsonVal& payload) {
  std::string pkg = trimStr(payload.getStr("packageId"));
  if (!pkg.empty() && !isSafePkgName(pkg)) return "";
#ifdef __APPLE__
  (void)ttype;
  return "echo ok";
#else
  std::string osRel = toLowerAscii(readTextFile("/etc/os-release"));
  bool isDeb = osRel.find("debian") != std::string::npos || osRel.find("ubuntu") != std::string::npos;
  bool isRhel = osRel.find("rhel") != std::string::npos || osRel.find("fedora") != std::string::npos ||
                osRel.find("almalinux") != std::string::npos || osRel.find("rocky") != std::string::npos;
  bool isArch = osRel.find("arch") != std::string::npos;
  if (ttype == "patch_scan") {
    if (isDeb) return "apt-get update -qq >/dev/null 2>&1 || true; apt list --upgradable 2>/dev/null";
    if (isRhel) return "(command -v dnf >/dev/null && dnf check-update || yum check-update); rc=$?; if [ $rc -eq 100 ]; then exit 0; fi; exit $rc";
    if (isArch) return "pacman -Qu 2>/dev/null || true";
  } else if (ttype == "patch_install") {
    if (isDeb) return "DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y";
    if (isRhel) return "if command -v dnf >/dev/null; then dnf upgrade -y; else yum update -y; fi";
    if (isArch) return "pacman -Syu --noconfirm";
  } else if (ttype == "software_deploy" && !pkg.empty()) {
    if (isDeb) return "DEBIAN_FRONTEND=noninteractive apt-get install -y -- " + pkg;
    if (isRhel) return "if command -v dnf >/dev/null; then dnf install -y -- " + pkg + "; else yum install -y -- " + pkg + "; fi";
    if (isArch) return "pacman -S --noconfirm --needed -- " + pkg;
  }
  return "echo ok";
#endif
}

inline void sendTaskResult(
    const std::string& srvUrl,
    const std::string& token,
    const std::string& deviceId,
    const std::string& taskId,
    int exitCode,
    const std::string& stdoutStr,
    const std::string& stderrStr,
    const std::string& backupJobId,
    bool allowSelfSigned,
    WsClient* ws) {
  std::ostringstream js;
  js << "{\"type\":\"task_result\""
     << ",\"taskId\":\"" << jsonEscape(taskId) << "\""
     << ",\"deviceId\":\"" << jsonEscape(deviceId) << "\""
     << ",\"exitCode\":" << exitCode
     << ",\"stdout\":\"" << jsonEscape(stdoutStr) << "\""
     << ",\"stderr\":\"" << jsonEscape(stderrStr) << "\"";
  if (!backupJobId.empty()) js << ",\"backupJobId\":\"" << jsonEscape(backupJobId) << "\"";
  js << "}";

  if (ws && ws->connected && ws->sendText(js.str())) {
    return;
  }

  std::ostringstream hjs;
  hjs << "{\"deviceId\":\"" << jsonEscape(deviceId) << "\""
      << ",\"exitCode\":" << exitCode
      << ",\"stdout\":\"" << jsonEscape(stdoutStr) << "\""
      << ",\"stderr\":\"" << jsonEscape(stderrStr) << "\"";
  if (!backupJobId.empty()) hjs << ",\"backupJobId\":\"" << jsonEscape(backupJobId) << "\"";
  hjs << "}";
  httpPostJson(
      srvUrl + "/api/agent/tasks/" + urlEncodeParam(taskId) + "/result",
      hjs.str(),
      {{"Content-Type", "application/json"}, {"x-vitrine-agent-token", token}},
      allowSelfSigned,
      15000);
}

inline bool executeAgentTask(
    const std::string& baseDir,
    const std::string& trayDir,
    const std::string& slug,
    const std::string& srvUrl,
    const std::string& token,
    const std::string& deviceId,
    bool allowSelfSigned,
    bool headlessMode,
    const JsonVal& taskVal,
    WsClient* ws,
    uint64_t& traySeq) {
  std::string taskId = taskVal.getStr("id");
  std::string ttype = taskVal.getStr("type");
  if (ttype.empty()) ttype = taskVal.getStr("task_type");

  JsonVal payload;
  if (const JsonVal* pv = taskVal.get("payload"); pv && pv->type == JsonVal::J_OBJ) {
    payload = *pv;
  } else {
    std::string pj = taskVal.getStr("payload_json");
    if (!pj.empty()) parseJson(pj, payload);
  }

  if (ttype == "tray_notify" || ttype == "reboot_prompt") {
    enqueueTrayInboxItem(trayDir, ++traySeq, serializeJson(taskVal), headlessMode);
    sendTaskResult(srvUrl, token, deviceId, taskId, 0,
        headlessMode ? "Headless agent ignored desktop prompt" : "Delivered to Linux desktop tray inbox",
        "", "", allowSelfSigned, ws);
    return true;
  }

  if (ttype == "wol_relay") {
    std::string err;
    bool ok = relayWolMagicPacket(payload.getStr("mac"), payload.getStr("broadcastIp"),
                                  static_cast<int>(payload.getInt("port", 9)), err);
    sendTaskResult(srvUrl, token, deviceId, taskId, ok ? 0 : 1,
        ok ? ("Magic packet relayed to " + payload.getStr("mac")) : "", err, "", allowSelfSigned, ws);
    return true;
  }

  if (ttype == "self_uninstall") {
    sendTaskResult(srvUrl, token, deviceId, taskId, 0, "Self-uninstall initiated", "", "", allowSelfSigned, ws);
    performSelfUninstall(baseDir, slug, &payload);
    return false;
  }

  if (ttype == "script" || ttype == "run_script" || ttype == "patch_scan" ||
      ttype == "patch_install" || ttype == "software_deploy" || ttype == "backup_job") {
    std::string code = payload.getStr("code");
    if (code.empty()) code = payload.getStr("command");
    if (code.empty()) code = resolveDefaultPkgTaskCmd(ttype, payload);
    if (code.empty()) {
      sendTaskResult(srvUrl, token, deviceId, taskId, 1, "", "Invalid package identifier",
          payload.getStr("backupJobId"), allowSelfSigned, ws);
      return true;
    }

    std::map<std::string, std::string> envVars;
    if (const JsonVal* eObj = payload.get("env"); eObj && eObj->type == JsonVal::J_OBJ) {
      for (const auto& kv : eObj->objVal) {
        if (isSafeParamKey(kv.first)) {
          envVars[kv.first] = (kv.second.type == JsonVal::J_STR) ? kv.second.strVal : serializeJson(kv.second);
        }
      }
    }
    std::string sh = payload.getStr("shell");
    if (sh.empty()) sh = payload.getStr("language", "bash");
    int timeoutSec = static_cast<int>(payload.getInt("timeoutSec", 120));
    int ec = 1;
    std::string so, se;
    runCommandWithTimeout(code, sh, envVars, timeoutSec, ec, so, se);
    sendTaskResult(srvUrl, token, deviceId, taskId, ec, so, se,
        payload.getStr("backupJobId"), allowSelfSigned, ws);
    return true;
  }

  sendTaskResult(srvUrl, token, deviceId, taskId, 0, "Task acknowledged", "", "", allowSelfSigned, ws);
  return true;
}

inline void handleRpcExec(WsClient& ws, const JsonVal& msg) {
  std::string reqId = msg.getStr("reqId");
  std::string cmd = msg.getStr("command");
  std::string sh = msg.getStr("shell", "bash");
  int timeoutSec = static_cast<int>(msg.getInt("timeoutSec", 20));
  if (reqId.empty()) return;

  int ec = 1;
  std::string so, se;
  if (!cmd.empty()) {
    runCommandWithTimeout(cmd, sh, {}, timeoutSec, ec, so, se);
  } else {
    se = "Empty RPC command";
  }

  std::ostringstream resp;
  resp << "{\"type\":\"rpc_response\""
       << ",\"reqId\":\"" << jsonEscape(reqId) << "\""
       << ",\"exitCode\":" << ec
       << ",\"stdout\":\"" << jsonEscape(so) << "\""
       << ",\"stderr\":\"" << jsonEscape(se) << "\"}";
  ws.sendText(resp.str());
}

}  // namespace vitrine_posix

