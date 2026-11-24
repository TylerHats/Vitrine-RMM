#include "posix_common.hpp"
#include "posix_telemetry.hpp"
#include "posix_tasks.hpp"

#include <deque>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <unordered_set>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

namespace {

volatile sig_atomic_t g_stopRequested = 0;

void handleSignal(int) {
  g_stopRequested = 1;
}

std::string getExecutableDir(const char* argv0) {
  char buf[PATH_MAX] = {0};
#ifdef __APPLE__
  uint32_t sz = sizeof(buf);
  if (_NSGetExecutablePath(buf, &sz) == 0) {
    char real[PATH_MAX] = {0};
    if (::realpath(buf, real)) {
      std::string s(real);
      size_t sl = s.rfind('/');
      if (sl != std::string::npos) return s.substr(0, sl);
    }
  }
#else
  ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n > 0) {
    buf[n] = '\0';
    std::string s(buf);
    size_t sl = s.rfind('/');
    if (sl != std::string::npos) return s.substr(0, sl);
  }
#endif
  if (argv0) {
    char tmp[PATH_MAX] = {0};
    if (::realpath(argv0, tmp)) {
      std::string s(tmp);
      size_t sl = s.rfind('/');
      if (sl != std::string::npos) return s.substr(0, sl);
    }
  }
  return ".";
}

std::string buildWsUrl(
    const std::string& httpBaseUrl,
    const std::string& token,
    const std::string& deviceId,
    const std::string& variant) {
  std::string base = vitrine_posix::trimStr(httpBaseUrl);
  while (!base.empty() && base.back() == '/') base.pop_back();
  std::string wsBase;
  if (base.rfind("https://", 0) == 0) {
    wsBase = "wss://" + base.substr(8);
  } else if (base.rfind("http://", 0) == 0) {
    wsBase = "ws://" + base.substr(7);
  } else {
    wsBase = "wss://" + base;
  }
  return wsBase + "/ws/agent?token=" + vitrine_posix::urlEncodeParam(token) +
         "&deviceId=" + vitrine_posix::urlEncodeParam(deviceId) +
         "&variant=" + vitrine_posix::urlEncodeParam(variant);
}

class SeenTasksCache {
 public:
  bool seenOrAdd(const std::string& id) {
    if (id.empty()) return false;
    if (set_.count(id) > 0) return true;
    order_.push_back(id);
    set_.insert(id);
    if (order_.size() > 128) {
      set_.erase(order_.front());
      order_.pop_front();
    }
    return false;
  }

 private:
  std::deque<std::string> order_;
  std::unordered_set<std::string> set_;
};

bool applyInboundResponsePayload(
    const vitrine_posix::JsonVal& rJson,
    vitrine_posix::JsonVal& cfg,
    const std::string& cfgPath,
    const std::string& baseDir,
    const std::string& trayDir,
    const std::string& slug,
    const std::string& srvUrl,
    const std::string& token,
    const std::string& deviceId,
    bool allowSelfSigned,
    bool headlessMode,
    vitrine_posix::WsClient* ws,
    uint64_t& traySeq,
    SeenTasksCache& seenTasks) {
  vitrine_posix::syncTrayConfigFromResp(rJson, cfg, cfgPath, headlessMode);

  if (const vitrine_posix::JsonVal* chats = rJson.get("unreadChats"); chats && chats->type == vitrine_posix::JsonVal::J_ARR) {
    for (const auto& ch : chats->arrVal) {
      std::string msg = vitrine_posix::trimStr(ch.getStr("message"));
      if (msg.empty()) continue;
      std::string sender = ch.getStr("sender", "IT Support");
      std::string noteJson = "{\"title\":\"Message from " + vitrine_posix::jsonEscape(sender) +
                             "\",\"message\":\"" + vitrine_posix::jsonEscape(msg) + "\"}";
      vitrine_posix::enqueueTrayInboxItem(trayDir, ++traySeq, noteJson, headlessMode);
    }
  }

  if (const vitrine_posix::JsonVal* tasks = rJson.get("tasks"); tasks && tasks->type == vitrine_posix::JsonVal::J_ARR) {
    for (const auto& t : tasks->arrVal) {
      std::string tid = t.getStr("id");
      if (seenTasks.seenOrAdd(tid)) continue;
      bool keepRunning = vitrine_posix::executeAgentTask(
          baseDir, trayDir, slug, srvUrl, token, deviceId, allowSelfSigned, headlessMode, t, ws, traySeq);
      if (!keepRunning) return false;
    }
  }
  return true;
}

}  // namespace

int main(int argc, char* argv[]) {
  ::signal(SIGPIPE, SIG_IGN);
  ::signal(SIGINT, handleSignal);
  ::signal(SIGTERM, handleSignal);

  bool headlessFlag = false;
  bool onceFlag = false;
  bool printEnrollHw = false;
  bool printVersion = false;
  bool doUninstall = false;
  std::string chatMsg;
  std::string configDirOverride;

  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    if (a == "--headless") headlessFlag = true;
    else if (a == "--once") onceFlag = true;
    else if (a == "--print-enroll-hw") printEnrollHw = true;
    else if (a == "--version" || a == "-v") printVersion = true;
    else if (a == "--uninstall") doUninstall = true;
    else if (a == "--chat" && i + 1 < argc) chatMsg = argv[++i];
    else if (a == "--config-dir" && i + 1 < argc) configDirOverride = argv[++i];
  }

#ifdef VITRINE_HEADLESS_ONLY
  headlessFlag = true;
#endif

  if (printVersion) {
    std::printf("vitrine-posix-agent 3.0.0 (%s)\n", headlessFlag ? "headless" : "desktop");
    return 0;
  }

  vitrine_posix::TelemetrySampler sampler;
  sampler.warm();

  if (printEnrollHw) {
    std::string hwJson = vitrine_posix::collectTelemetryPayload(sampler, "", true, headlessFlag, true);
    std::printf("%s\n", hwJson.c_str());
    return 0;
  }

  std::string baseDir = configDirOverride.empty() ? getExecutableDir(argv[0]) : configDirOverride;
  std::string cfgPath = baseDir + "/companion-config.json";
  std::string idPath = baseDir + "/agent-identity.json";

  if (doUninstall) {
    vitrine_posix::JsonVal cfg, ident;
    vitrine_posix::parseJson(vitrine_posix::readTextFile(cfgPath), cfg);
    vitrine_posix::parseJson(vitrine_posix::readTextFile(idPath), ident);
    vitrine_posix::performSelfUninstall(baseDir, vitrine_posix::getServiceSlug(cfg, ident), nullptr);
    return 0;
  }

  if (!chatMsg.empty()) {
    vitrine_posix::JsonVal cfg, ident;
    vitrine_posix::parseJson(vitrine_posix::readTextFile(cfgPath), cfg);
    vitrine_posix::parseJson(vitrine_posix::readTextFile(idPath), ident);
    std::string srv = vitrine_posix::trimStr(ident.getStr("vitrineServerUrl"));
    while (!srv.empty() && srv.back() == '/') srv.pop_back();
    std::string tok = ident.getStr("agentToken");
    if (tok.empty()) tok = ident.getStr("agentAuthToken");
    std::string devId = ident.getStr("deviceId");
    bool insecure = ident.getBool("insecureTls", false) || cfg.getBool("AllowSelfSignedTls", false);
    const char* userEnv = std::getenv("USER");
    std::string sender = (userEnv && userEnv[0]) ? userEnv : "Desktop User";
    if (!srv.empty() && !tok.empty() && !devId.empty()) {
      std::string body = "{\"deviceId\":\"" + vitrine_posix::jsonEscape(devId) +
                         "\",\"sender\":\"" + vitrine_posix::jsonEscape(sender) +
                         "\",\"message\":\"" + vitrine_posix::jsonEscape(chatMsg) + "\"}";
      vitrine_posix::httpPostJson(srv + "/api/agent/chat", body, {{"x-vitrine-agent-token", tok}}, insecure, 8000);
    }
    return 0;
  }

  uint64_t checkinCount = 0;
  uint64_t traySeq = 0;
  int64_t lastOkEpoch = 0;
  int wsBackoffSec = 5;
  std::time_t nextWsRetryAt = 0;
  SeenTasksCache seenTasks;

  std::string variantStr = headlessFlag ? "posix-headless" :
#ifdef __APPLE__
    "macos-native";
#else
    "posix-desktop";
#endif

  while (!g_stopRequested) {
    vitrine_posix::JsonVal cfg, ident;
    vitrine_posix::parseJson(vitrine_posix::readTextFile(cfgPath), cfg);
    bool hasIdent = vitrine_posix::parseJson(vitrine_posix::readTextFile(idPath), ident);

    std::string slug = vitrine_posix::getServiceSlug(cfg, ident);
    std::string trayDir = vitrine_posix::getTrayDir(cfg, ident, baseDir);
    int64_t iv = cfg.getInt("TelemetryIntervalSec", 25);
    int64_t sleepSec = std::max<int64_t>(10, std::min<int64_t>(3600, iv));

    std::string srv = vitrine_posix::trimStr(ident.getStr("vitrineServerUrl"));
    while (!srv.empty() && srv.back() == '/') srv.pop_back();
    std::string tok = ident.getStr("agentToken");
    if (tok.empty()) tok = ident.getStr("agentAuthToken");
    std::string devId = ident.getStr("deviceId");
    bool insecure = ident.getBool("insecureTls", false) || cfg.getBool("AllowSelfSignedTls", false);

    if (hasIdent && !srv.empty() && !tok.empty() && !devId.empty()) {
      std::time_t nowSec = std::time(nullptr);

      // 1. Primary Persistent WSS / WS WebSocket Session (unless inside exponential backoff window)
      if (!onceFlag && nowSec >= nextWsRetryAt) {
        vitrine_posix::WsClient ws;
        std::string wsUrl = buildWsUrl(srv, tok, devId, variantStr);
        if (ws.connect(wsUrl, {{"x-vitrine-agent-token", tok}}, insecure, 8000)) {
          std::time_t sessionStart = std::time(nullptr);
          lastOkEpoch = static_cast<int64_t>(sessionStart);
          vitrine_posix::writeAgentStatusFile(trayDir, true, lastOkEpoch, lastOkEpoch, sleepSec, 101, "wss");

          std::string osTag =
#ifdef __APPLE__
            "macos";
#else
            "linux";
#endif
          ws.sendText("{\"type\":\"hello\",\"variant\":\"" + vitrine_posix::jsonEscape(variantStr) +
                      "\",\"osType\":\"" + osTag + "\",\"version\":\"3.0.0-posix\"}");

          bool fullInv = (checkinCount % 24 == 0);
          checkinCount++;
          std::string initTel = vitrine_posix::collectTelemetryPayload(sampler, devId, fullInv, headlessFlag, false);
          ws.sendText("{\"type\":\"telemetry\",\"payload\":" + initTel + "}");
          std::time_t lastTelemetrySent = std::time(nullptr);

          while (!g_stopRequested && ws.connected) {
            vitrine_posix::flushTrayOutbox(trayDir, srv, tok, devId, insecure, &ws, headlessFlag);

            std::string frameText;
            int pr = ws.pollMessage(1000, frameText);
            if (pr < 0) break;
            if (pr > 0) {
              vitrine_posix::JsonVal msg;
              if (vitrine_posix::parseJson(frameText, msg) && msg.type == vitrine_posix::JsonVal::J_OBJ) {
                std::string mtype = msg.getStr("type");
                if (mtype == "ping") {
                  ws.sendText("{\"type\":\"pong\"}");
                } else if (mtype == "task") {
                  if (const vitrine_posix::JsonVal* tv = msg.get("task"); tv && tv->type == vitrine_posix::JsonVal::J_OBJ) {
                    std::string tid = tv->getStr("id");
                    if (!seenTasks.seenOrAdd(tid)) {
                      if (!vitrine_posix::executeAgentTask(
                              baseDir, trayDir, slug, srv, tok, devId, insecure, headlessFlag, *tv, &ws, traySeq)) {
                        return 0;
                      }
                    }
                  }
                } else if (mtype == "rpc_exec") {
                  vitrine_posix::handleRpcExec(ws, msg);
                } else if (mtype == "chat") {
                  std::string cmsg = vitrine_posix::trimStr(msg.getStr("message"));
                  if (!cmsg.empty()) {
                    std::string sender = msg.getStr("sender", "IT Support");
                    std::string noteJson = "{\"title\":\"Message from " + vitrine_posix::jsonEscape(sender) +
                                           "\",\"message\":\"" + vitrine_posix::jsonEscape(cmsg) + "\"}";
                    vitrine_posix::enqueueTrayInboxItem(trayDir, ++traySeq, noteJson, headlessFlag);
                  }
                } else if (mtype == "checkin_ack") {
                  lastOkEpoch = static_cast<int64_t>(std::time(nullptr));
                  vitrine_posix::writeAgentStatusFile(trayDir, true, lastOkEpoch, lastOkEpoch, sleepSec, 200, "wss");
                  if (!applyInboundResponsePayload(
                          msg, cfg, cfgPath, baseDir, trayDir, slug, srv, tok, devId, insecure, headlessFlag, &ws, traySeq, seenTasks)) {
                    return 0;
                  }
                }
              }
            }

            std::time_t curNow = std::time(nullptr);
            if (curNow - lastTelemetrySent >= sleepSec) {
              vitrine_posix::parseJson(vitrine_posix::readTextFile(cfgPath), cfg);
              sleepSec = std::max<int64_t>(10, std::min<int64_t>(3600, cfg.getInt("TelemetryIntervalSec", 25)));
              bool doFull = (checkinCount % 24 == 0);
              checkinCount++;
              std::string telJson = vitrine_posix::collectTelemetryPayload(sampler, devId, doFull, headlessFlag, false);
              if (!ws.sendText("{\"type\":\"telemetry\",\"payload\":" + telJson + "}")) break;
              lastTelemetrySent = curNow;
              lastOkEpoch = static_cast<int64_t>(curNow);
              vitrine_posix::writeAgentStatusFile(trayDir, true, lastOkEpoch, lastOkEpoch, sleepSec, 200, "wss");
            }
          }

          ws.close();
          if (std::time(nullptr) - sessionStart >= 15) {
            wsBackoffSec = 5;
          } else {
            wsBackoffSec = std::min(60, wsBackoffSec * 2);
          }
          nextWsRetryAt = std::time(nullptr) + wsBackoffSec;
        } else {
          wsBackoffSec = std::min(60, wsBackoffSec * 2);
          nextWsRetryAt = std::time(nullptr) + wsBackoffSec;
        }
        if (g_stopRequested) break;
      }

      // 2. Automatic HTTP Fallback Check-in when WSS is unavailable or disconnected
      vitrine_posix::flushTrayOutbox(trayDir, srv, tok, devId, insecure, nullptr, headlessFlag);
      bool fullInv = (checkinCount % 24 == 0);
      checkinCount++;
      std::string metricsJson = vitrine_posix::collectTelemetryPayload(sampler, devId, fullInv, headlessFlag, false);
      vitrine_posix::HttpResponse hresp = vitrine_posix::httpPostJson(
          srv + "/api/agent/checkin",
          metricsJson,
          {{"x-vitrine-agent-token", tok}},
          insecure,
          15000);
      int64_t attemptEpoch = static_cast<int64_t>(std::time(nullptr));
      vitrine_posix::JsonVal rJson;
      if (hresp.statusCode >= 200 && hresp.statusCode < 300 && vitrine_posix::parseJson(hresp.body, rJson)) {
        lastOkEpoch = attemptEpoch;
        vitrine_posix::writeAgentStatusFile(trayDir, true, lastOkEpoch, attemptEpoch, sleepSec, hresp.statusCode, "http");
        if (!applyInboundResponsePayload(
                rJson, cfg, cfgPath, baseDir, trayDir, slug, srv, tok, devId, insecure, headlessFlag, nullptr, traySeq, seenTasks)) {
          return 0;
        }
      } else {
        vitrine_posix::writeAgentStatusFile(trayDir, false, lastOkEpoch, attemptEpoch, sleepSec, hresp.statusCode, "http");
      }
    } else {
      vitrine_posix::writeAgentStatusFile(trayDir, false, lastOkEpoch, static_cast<int64_t>(std::time(nullptr)), sleepSec, 0, "offline");
    }

    if (onceFlag) break;

    int64_t slept = 0;
    while (slept < sleepSec && !g_stopRequested) {
      if (hasIdent && !srv.empty() && !tok.empty() && !devId.empty()) {
        vitrine_posix::flushTrayOutbox(trayDir, srv, tok, devId, insecure, nullptr, headlessFlag);
      }
      ::sleep(2);
      slept += 2;
    }
  }

  return 0;
}

