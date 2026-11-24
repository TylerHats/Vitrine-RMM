#pragma once

#include <arpa/inet.h>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace vitrine_posix {

inline std::string trimStr(const std::string& s) {
  size_t a = 0;
  while (a < s.size() && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) a++;
  size_t b = s.size();
  while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) b--;
  return s.substr(a, b - a);
}

inline std::string toLowerAscii(std::string s) {
  for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

inline std::string sanitizeId(const std::string& raw, const std::string& fallback, size_t maxLen = 64) {
  std::string out;
  out.reserve(std::min(raw.size(), maxLen));
  for (char c : raw) {
    unsigned char uc = static_cast<unsigned char>(c);
    if (std::isalnum(uc) || c == '_' || c == '-' || c == '.') {
      out.push_back(c);
      if (out.size() >= maxLen) break;
    }
  }
  return out.empty() ? fallback : out;
}

inline std::string jsonEscape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 16);
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
        break;
    }
  }
  return out;
}

struct JsonVal {
  enum Kind { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } type = J_NULL;
  bool boolVal = false;
  double numVal = 0.0;
  std::string strVal;
  std::vector<JsonVal> arrVal;
  std::vector<std::pair<std::string, JsonVal>> objVal;

  const JsonVal* get(const std::string& key) const {
    if (type != J_OBJ) return nullptr;
    for (const auto& kv : objVal) {
      if (kv.first == key) return &kv.second;
    }
    return nullptr;
  }

  std::string getStr(const std::string& key, const std::string& def = "") const {
    const JsonVal* v = get(key);
    if (!v) return def;
    if (v->type == J_STR) return v->strVal;
    if (v->type == J_NUM) {
      std::ostringstream oss;
      oss << v->numVal;
      return oss.str();
    }
    if (v->type == J_BOOL) return v->boolVal ? "true" : "false";
    return def;
  }

  int64_t getInt(const std::string& key, int64_t def = 0) const {
    const JsonVal* v = get(key);
    if (!v) return def;
    if (v->type == J_NUM) return static_cast<int64_t>(v->numVal);
    if (v->type == J_BOOL) return v->boolVal ? 1 : 0;
    if (v->type == J_STR && !v->strVal.empty()) return std::strtoll(v->strVal.c_str(), nullptr, 10);
    return def;
  }

  bool getBool(const std::string& key, bool def = false) const {
    const JsonVal* v = get(key);
    if (!v) return def;
    if (v->type == J_BOOL) return v->boolVal;
    if (v->type == J_NUM) return v->numVal != 0.0;
    if (v->type == J_STR) {
      std::string lo = toLowerAscii(v->strVal);
      if (lo == "true" || lo == "1") return true;
      if (lo == "false" || lo == "0") return false;
    }
    return def;
  }

  void setObj(const std::string& key, JsonVal val) {
    if (type != J_OBJ) {
      type = J_OBJ;
      objVal.clear();
    }
    for (auto& kv : objVal) {
      if (kv.first == key) {
        kv.second = std::move(val);
        return;
      }
    }
    objVal.emplace_back(key, std::move(val));
  }
};

inline std::string serializeJson(const JsonVal& v) {
  switch (v.type) {
    case JsonVal::J_NULL: return "null";
    case JsonVal::J_BOOL: return v.boolVal ? "true" : "false";
    case JsonVal::J_NUM: {
      std::ostringstream oss;
      oss << v.numVal;
      return oss.str();
    }
    case JsonVal::J_STR: return "\"" + jsonEscape(v.strVal) + "\"";
    case JsonVal::J_ARR: {
      std::string out = "[";
      for (size_t i = 0; i < v.arrVal.size(); i++) {
        if (i > 0) out += ",";
        out += serializeJson(v.arrVal[i]);
      }
      out += "]";
      return out;
    }
    case JsonVal::J_OBJ: {
      std::string out = "{";
      for (size_t i = 0; i < v.objVal.size(); i++) {
        if (i > 0) out += ",";
        out += "\"" + jsonEscape(v.objVal[i].first) + "\":" + serializeJson(v.objVal[i].second);
      }
      out += "}";
      return out;
    }
  }
  return "null";
}

class JsonParser {
 public:
  explicit JsonParser(const std::string& src) : s_(src), pos_(0) {}
  bool parse(JsonVal& out) {
    skipWs();
    if (!parseValue(out, 0)) return false;
    skipWs();
    return true;
  }

 private:
  const std::string& s_;
  size_t pos_;

  void skipWs() {
    while (pos_ < s_.size() && (s_[pos_] == ' ' || s_[pos_] == '\t' || s_[pos_] == '\r' || s_[pos_] == '\n')) pos_++;
  }

  bool parseString(std::string& out) {
    if (pos_ >= s_.size() || s_[pos_] != '"') return false;
    pos_++;
    out.clear();
    while (pos_ < s_.size()) {
      char c = s_[pos_++];
      if (c == '"') return true;
      if (c == '\\') {
        if (pos_ >= s_.size()) return false;
        char e = s_[pos_++];
        switch (e) {
          case '"': out.push_back('"'); break;
          case '\\': out.push_back('\\'); break;
          case '/': out.push_back('/'); break;
          case 'b': out.push_back('\b'); break;
          case 'f': out.push_back('\f'); break;
          case 'n': out.push_back('\n'); break;
          case 'r': out.push_back('\r'); break;
          case 't': out.push_back('\t'); break;
          case 'u': {
            if (pos_ + 4 > s_.size()) return false;
            unsigned int cp = 0;
            for (int i = 0; i < 4; i++) {
              char h = s_[pos_++];
              cp <<= 4;
              if (h >= '0' && h <= '9') cp |= (h - '0');
              else if (h >= 'a' && h <= 'f') cp |= (10 + h - 'a');
              else if (h >= 'A' && h <= 'F') cp |= (10 + h - 'A');
              else return false;
            }
            if (cp < 0x80) {
              out.push_back(static_cast<char>(cp));
            } else if (cp < 0x800) {
              out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
              out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            } else {
              out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
              out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
              out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            }
            break;
          }
          default: out.push_back(e); break;
        }
      } else {
        out.push_back(c);
      }
    }
    return false;
  }

  bool parseValue(JsonVal& out, int depth) {
    if (depth > 32) return false;
    skipWs();
    if (pos_ >= s_.size()) return false;
    char c = s_[pos_];
    if (c == '"') {
      out.type = JsonVal::J_STR;
      return parseString(out.strVal);
    }
    if (c == '{') {
      pos_++;
      out.type = JsonVal::J_OBJ;
      out.objVal.clear();
      skipWs();
      if (pos_ < s_.size() && s_[pos_] == '}') { pos_++; return true; }
      while (pos_ < s_.size()) {
        skipWs();
        std::string key;
        if (!parseString(key)) return false;
        skipWs();
        if (pos_ >= s_.size() || s_[pos_] != ':') return false;
        pos_++;
        JsonVal val;
        if (!parseValue(val, depth + 1)) return false;
        out.objVal.emplace_back(std::move(key), std::move(val));
        skipWs();
        if (pos_ >= s_.size()) return false;
        if (s_[pos_] == '}') { pos_++; return true; }
        if (s_[pos_] != ',') return false;
        pos_++;
      }
      return false;
    }
    if (c == '[') {
      pos_++;
      out.type = JsonVal::J_ARR;
      out.arrVal.clear();
      skipWs();
      if (pos_ < s_.size() && s_[pos_] == ']') { pos_++; return true; }
      while (pos_ < s_.size()) {
        JsonVal elem;
        if (!parseValue(elem, depth + 1)) return false;
        out.arrVal.push_back(std::move(elem));
        skipWs();
        if (pos_ >= s_.size()) return false;
        if (s_[pos_] == ']') { pos_++; return true; }
        if (s_[pos_] != ',') return false;
        pos_++;
      }
      return false;
    }
    if (s_.compare(pos_, 4, "true") == 0) {
      pos_ += 4;
      out.type = JsonVal::J_BOOL;
      out.boolVal = true;
      return true;
    }
    if (s_.compare(pos_, 5, "false") == 0) {
      pos_ += 5;
      out.type = JsonVal::J_BOOL;
      out.boolVal = false;
      return true;
    }
    if (s_.compare(pos_, 4, "null") == 0) {
      pos_ += 4;
      out.type = JsonVal::J_NULL;
      return true;
    }
    if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) {
      char* endPtr = nullptr;
      double n = std::strtod(s_.c_str() + pos_, &endPtr);
      if (endPtr == s_.c_str() + pos_) return false;
      pos_ = static_cast<size_t>(endPtr - s_.c_str());
      out.type = JsonVal::J_NUM;
      out.numVal = n;
      return true;
    }
    return false;
  }
};

inline bool parseJson(const std::string& src, JsonVal& out) {
  JsonParser p(src);
  return p.parse(out);
}

inline std::string readTextFile(const std::string& path) {
  std::ifstream ifs(path, std::ios::in | std::ios::binary);
  if (!ifs.is_open()) return "";
  std::ostringstream oss;
  oss << ifs.rdbuf();
  return oss.str();
}

inline bool writeTextFileAtomic(const std::string& path, const std::string& content, mode_t mode = 0644) {
  std::string tmp = path + ".tmp." + std::to_string(::getpid());
  int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, mode);
  if (fd < 0) return false;
  size_t off = 0;
  while (off < content.size()) {
    ssize_t w = ::write(fd, content.data() + off, content.size() - off);
    if (w <= 0) {
      if (errno == EINTR) continue;
      ::close(fd);
      ::unlink(tmp.c_str());
      return false;
    }
    off += static_cast<size_t>(w);
  }
  ::fchmod(fd, mode);
  ::close(fd);
  if (::rename(tmp.c_str(), path.c_str()) != 0) {
    ::unlink(tmp.c_str());
    return false;
  }
  return true;
}

inline void ensureDir(const std::string& dirPath, mode_t mode = 0755) {
  std::string cur;
  for (size_t i = 0; i < dirPath.size(); i++) {
    cur.push_back(dirPath[i]);
    if (dirPath[i] == '/' || i + 1 == dirPath.size()) {
      if (!cur.empty() && cur != "/") {
        ::mkdir(cur.c_str(), mode);
      }
    }
  }
}

inline std::string base64Encode(const uint8_t* data, size_t len) {
  static const char* kTbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  for (size_t i = 0; i < len; i += 3) {
    uint32_t b = static_cast<uint32_t>(data[i]) << 16;
    if (i + 1 < len) b |= static_cast<uint32_t>(data[i + 1]) << 8;
    if (i + 2 < len) b |= static_cast<uint32_t>(data[i + 2]);
    out.push_back(kTbl[(b >> 18) & 0x3F]);
    out.push_back(kTbl[(b >> 12) & 0x3F]);
    out.push_back((i + 1 < len) ? kTbl[(b >> 6) & 0x3F] : '=');
    out.push_back((i + 2 < len) ? kTbl[b & 0x3F] : '=');
  }
  return out;
}

inline std::string urlEncodeParam(const std::string& v) {
  std::ostringstream oss;
  for (unsigned char c : v) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      oss << static_cast<char>(c);
    } else {
      char buf[4];
      std::snprintf(buf, sizeof(buf), "%%%02X", c);
      oss << buf;
    }
  }
  return oss.str();
}

struct ParsedUrl {
  bool valid = false;
  bool useTls = false;
  bool isWs = false;
  std::string host;
  uint16_t port = 80;
  std::string path = "/";
};

inline ParsedUrl parseUrl(const std::string& rawUrl) {
  ParsedUrl res;
  std::string u = trimStr(rawUrl);
  size_t pos = 0;
  if (u.compare(0, 8, "https://") == 0) {
    res.useTls = true;
    res.port = 443;
    pos = 8;
  } else if (u.compare(0, 7, "http://") == 0) {
    res.useTls = false;
    res.port = 80;
    pos = 7;
  } else if (u.compare(0, 6, "wss://") == 0) {
    res.useTls = true;
    res.isWs = true;
    res.port = 443;
    pos = 6;
  } else if (u.compare(0, 5, "ws://") == 0) {
    res.useTls = false;
    res.isWs = true;
    res.port = 80;
    pos = 5;
  } else {
    return res;
  }

  size_t slashPos = u.find('/', pos);
  std::string hostPort = (slashPos == std::string::npos) ? u.substr(pos) : u.substr(pos, slashPos - pos);
  res.path = (slashPos == std::string::npos) ? "/" : u.substr(slashPos);
  if (!hostPort.empty() && hostPort[0] == '[') {
    size_t closeBr = hostPort.find(']');
    if (closeBr == std::string::npos) return res;
    res.host = hostPort.substr(1, closeBr - 1);
    if (closeBr + 1 < hostPort.size() && hostPort[closeBr + 1] == ':') {
      res.port = static_cast<uint16_t>(std::atoi(hostPort.substr(closeBr + 2).c_str()));
    }
  } else {
    size_t colonPos = hostPort.rfind(':');
    if (colonPos != std::string::npos) {
      res.host = hostPort.substr(0, colonPos);
      res.port = static_cast<uint16_t>(std::atoi(hostPort.substr(colonPos + 1).c_str()));
    } else {
      res.host = hostPort;
    }
  }
  res.valid = !res.host.empty() && res.port > 0;
  return res;
}

class OpenSslLoader {
 public:
  using FnTlsClientMethod = const void* (*)();
  using FnCtxNew = void* (*)(const void*);
  using FnCtxFree = void (*)(void*);
  using FnCtxSetVerify = void (*)(void*, int, void*);
  using FnCtxSetDefPaths = int (*)(void*);
  using FnSslNew = void* (*)(void*);
  using FnSslFree = void (*)(void*);
  using FnSslSetFd = int (*)(void*, int);
  using FnSslCtrl = long (*)(void*, int, long, void*);
  using FnSslSet1Host = int (*)(void*, const char*);
  using FnSslConnect = int (*)(void*);
  using FnSslRead = int (*)(void*, void*, int);
  using FnSslWrite = int (*)(void*, const void*, int);
  using FnSslShutdown = int (*)(void*);
  using FnSslPending = int (*)(const void*);

  bool loaded = false;
  FnTlsClientMethod TLS_client_method = nullptr;
  FnCtxNew SSL_CTX_new = nullptr;
  FnCtxFree SSL_CTX_free = nullptr;
  FnCtxSetVerify SSL_CTX_set_verify = nullptr;
  FnCtxSetDefPaths SSL_CTX_set_default_verify_paths = nullptr;
  FnSslNew SSL_new = nullptr;
  FnSslFree SSL_free = nullptr;
  FnSslSetFd SSL_set_fd = nullptr;
  FnSslCtrl SSL_ctrl = nullptr;
  FnSslSet1Host SSL_set1_host = nullptr;
  FnSslConnect SSL_connect = nullptr;
  FnSslRead SSL_read = nullptr;
  FnSslWrite SSL_write = nullptr;
  FnSslShutdown SSL_shutdown = nullptr;
  FnSslPending SSL_pending = nullptr;

  static OpenSslLoader& instance() {
    static OpenSslLoader inst;
    return inst;
  }

 private:
  OpenSslLoader() {
    const char* cryptoLibs[] = {
#ifdef __APPLE__
      "libcrypto.dylib", "libcrypto.3.dylib", "/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib", "/usr/local/opt/openssl/lib/libcrypto.dylib",
#else
      "libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so",
#endif
      nullptr
    };
    const char* sslLibs[] = {
#ifdef __APPLE__
      "libssl.dylib", "libssl.3.dylib", "/opt/homebrew/opt/openssl@3/lib/libssl.dylib", "/usr/local/opt/openssl/lib/libssl.dylib",
#else
      "libssl.so.3", "libssl.so.1.1", "libssl.so",
#endif
      nullptr
    };

    for (int i = 0; cryptoLibs[i]; i++) {
      if (::dlopen(cryptoLibs[i], RTLD_LAZY | RTLD_GLOBAL)) break;
    }
    void* sslHandle = nullptr;
    for (int i = 0; sslLibs[i]; i++) {
      sslHandle = ::dlopen(sslLibs[i], RTLD_LAZY | RTLD_LOCAL);
      if (sslHandle) break;
    }
    if (!sslHandle) return;

    TLS_client_method = reinterpret_cast<FnTlsClientMethod>(::dlsym(sslHandle, "TLS_client_method"));
    if (!TLS_client_method) {
      TLS_client_method = reinterpret_cast<FnTlsClientMethod>(::dlsym(sslHandle, "SSLv23_client_method"));
    }
    SSL_CTX_new = reinterpret_cast<FnCtxNew>(::dlsym(sslHandle, "SSL_CTX_new"));
    SSL_CTX_free = reinterpret_cast<FnCtxFree>(::dlsym(sslHandle, "SSL_CTX_free"));
    SSL_CTX_set_verify = reinterpret_cast<FnCtxSetVerify>(::dlsym(sslHandle, "SSL_CTX_set_verify"));
    SSL_CTX_set_default_verify_paths = reinterpret_cast<FnCtxSetDefPaths>(::dlsym(sslHandle, "SSL_CTX_set_default_verify_paths"));
    SSL_new = reinterpret_cast<FnSslNew>(::dlsym(sslHandle, "SSL_new"));
    SSL_free = reinterpret_cast<FnSslFree>(::dlsym(sslHandle, "SSL_free"));
    SSL_set_fd = reinterpret_cast<FnSslSetFd>(::dlsym(sslHandle, "SSL_set_fd"));
    SSL_ctrl = reinterpret_cast<FnSslCtrl>(::dlsym(sslHandle, "SSL_ctrl"));
    SSL_set1_host = reinterpret_cast<FnSslSet1Host>(::dlsym(sslHandle, "SSL_set1_host"));
    SSL_connect = reinterpret_cast<FnSslConnect>(::dlsym(sslHandle, "SSL_connect"));
    SSL_read = reinterpret_cast<FnSslRead>(::dlsym(sslHandle, "SSL_read"));
    SSL_write = reinterpret_cast<FnSslWrite>(::dlsym(sslHandle, "SSL_write"));
    SSL_shutdown = reinterpret_cast<FnSslShutdown>(::dlsym(sslHandle, "SSL_shutdown"));
    SSL_pending = reinterpret_cast<FnSslPending>(::dlsym(sslHandle, "SSL_pending"));

    loaded = TLS_client_method && SSL_CTX_new && SSL_CTX_free && SSL_new && SSL_free && SSL_set_fd &&
             SSL_connect && SSL_read && SSL_write;
  }
};

class SocketStream {
 public:
  int fd = -1;
  void* ctx = nullptr;
  void* ssl = nullptr;

  ~SocketStream() { close(); }

  void close() {
    auto& ossl = OpenSslLoader::instance();
    if (ssl && ossl.loaded) {
      if (ossl.SSL_shutdown) ossl.SSL_shutdown(ssl);
      ossl.SSL_free(ssl);
      ssl = nullptr;
    }
    if (ctx && ossl.loaded) {
      ossl.SSL_CTX_free(ctx);
      ctx = nullptr;
    }
    if (fd >= 0) {
      ::close(fd);
      fd = -1;
    }
  }

  bool connectTo(const std::string& host, uint16_t port, bool useTls, bool allowSelfSigned, int timeoutMs = 10000) {
    close();
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    std::string portStr = std::to_string(port);
    if (::getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) {
      return false;
    }

    int connectedFd = -1;
    for (struct addrinfo* p = res; p; p = p->ai_next) {
      int s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
      if (s < 0) continue;

      int flags = ::fcntl(s, F_GETFL, 0);
      ::fcntl(s, F_SETFL, flags | O_NONBLOCK);
      int rc = ::connect(s, p->ai_addr, p->ai_addrlen);
      if (rc != 0 && errno != EINPROGRESS) {
        ::close(s);
        continue;
      }
      if (rc != 0) {
        struct pollfd pfd{s, POLLOUT, 0};
        int pr = ::poll(&pfd, 1, timeoutMs);
        int soErr = 0;
        socklen_t soLen = sizeof(soErr);
        if (pr <= 0 || ::getsockopt(s, SOL_SOCKET, SO_ERROR, &soErr, &soLen) != 0 || soErr != 0) {
          ::close(s);
          continue;
        }
      }
      ::fcntl(s, F_SETFL, flags & ~O_NONBLOCK);
      int one = 1;
      ::setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
      struct timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
      ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
      connectedFd = s;
      break;
    }
    ::freeaddrinfo(res);
    if (connectedFd < 0) return false;
    fd = connectedFd;

    if (useTls) {
      auto& ossl = OpenSslLoader::instance();
      if (!ossl.loaded) {
        close();
        return false;
      }
      ctx = ossl.SSL_CTX_new(ossl.TLS_client_method());
      if (!ctx) {
        close();
        return false;
      }
      if (!allowSelfSigned && ossl.SSL_CTX_set_default_verify_paths && ossl.SSL_CTX_set_verify) {
        ossl.SSL_CTX_set_default_verify_paths(ctx);
        ossl.SSL_CTX_set_verify(ctx, 1 /* SSL_VERIFY_PEER */, nullptr);
      } else if (ossl.SSL_CTX_set_verify) {
        ossl.SSL_CTX_set_verify(ctx, 0 /* SSL_VERIFY_NONE */, nullptr);
      }
      ssl = ossl.SSL_new(ctx);
      if (!ssl) {
        close();
        return false;
      }
      ossl.SSL_set_fd(ssl, fd);
      if (ossl.SSL_ctrl) {
        ossl.SSL_ctrl(ssl, 55 /* SSL_CTRL_SET_TLSEXT_HOSTNAME */, 0, const_cast<char*>(host.c_str()));
      }
      if (!allowSelfSigned && ossl.SSL_set1_host) {
        ossl.SSL_set1_host(ssl, host.c_str());
      }
      if (ossl.SSL_connect(ssl) != 1) {
        close();
        return false;
      }
    }
    return true;
  }

  bool sendAll(const void* buf, size_t len) {
    const uint8_t* ptr = static_cast<const uint8_t*>(buf);
    size_t off = 0;
    auto& ossl = OpenSslLoader::instance();
    while (off < len) {
      ssize_t w = ssl ? ossl.SSL_write(ssl, ptr + off, static_cast<int>(len - off))
                      : ::send(fd, ptr + off, len - off, 0);
      if (w <= 0) return false;
      off += static_cast<size_t>(w);
    }
    return true;
  }

  bool hasBufferedTlsData() const {
    auto& ossl = OpenSslLoader::instance();
    return ssl && ossl.SSL_pending && ossl.SSL_pending(ssl) > 0;
  }

  int waitReadable(int timeoutMs) const {
    if (hasBufferedTlsData()) return 1;
    struct pollfd pfd{fd, POLLIN, 0};
    int r = ::poll(&pfd, 1, timeoutMs);
    if (r < 0) return (errno == EINTR) ? 0 : -1;
    if (r == 0) return 0;
    return (pfd.revents & (POLLIN | POLLHUP | POLLERR)) ? 1 : 0;
  }

  ssize_t recvSome(void* buf, size_t cap) {
    auto& ossl = OpenSslLoader::instance();
    return ssl ? ossl.SSL_read(ssl, buf, static_cast<int>(cap)) : ::recv(fd, buf, cap, 0);
  }
};

struct HttpResponse {
  int statusCode = 0;
  std::string body;
};

inline HttpResponse httpPostJson(
    const std::string& urlStr,
    const std::string& jsonBody,
    const std::map<std::string, std::string>& extraHeaders,
    bool allowSelfSigned,
    int timeoutMs = 15000) {
  HttpResponse resp;
  ParsedUrl u = parseUrl(urlStr);
  if (!u.valid) return resp;

  SocketStream sock;
  if (!sock.connectTo(u.host, u.port, u.useTls, allowSelfSigned, timeoutMs)) {
    return resp;
  }

  std::ostringstream req;
  req << "POST " << u.path << " HTTP/1.1\r\n"
      << "Host: " << u.host << ":" << u.port << "\r\n"
      << "User-Agent: VitrinePosixAgent/3.0\r\n"
      << "Connection: close\r\n"
      << "Content-Type: application/json\r\n"
      << "Content-Length: " << jsonBody.size() << "\r\n";
  for (const auto& kv : extraHeaders) {
    req << kv.first << ": " << kv.second << "\r\n";
  }
  req << "\r\n" << jsonBody;
  std::string rawReq = req.str();
  if (!sock.sendAll(rawReq.data(), rawReq.size())) {
    return resp;
  }

  std::string raw;
  char buf[4096];
  while (raw.size() < 4 * 1024 * 1024) {
    ssize_t n = sock.recvSome(buf, sizeof(buf));
    if (n <= 0) break;
    raw.append(buf, static_cast<size_t>(n));
  }

  size_t hdrEnd = raw.find("\r\n\r\n");
  if (hdrEnd == std::string::npos) return resp;
  std::string hdrs = raw.substr(0, hdrEnd);
  std::string body = raw.substr(hdrEnd + 4);

  size_t lineEnd = hdrs.find("\r\n");
  std::string statusLine = (lineEnd == std::string::npos) ? hdrs : hdrs.substr(0, lineEnd);
  size_t sp1 = statusLine.find(' ');
  if (sp1 != std::string::npos) {
    resp.statusCode = std::atoi(statusLine.c_str() + sp1 + 1);
  }

  if (toLowerAscii(hdrs).find("transfer-encoding: chunked") != std::string::npos) {
    std::string decoded;
    size_t p = 0;
    while (p < body.size()) {
      size_t crlf = body.find("\r\n", p);
      if (crlf == std::string::npos) break;
      size_t chunkSz = static_cast<size_t>(std::strtoul(body.substr(p, crlf - p).c_str(), nullptr, 16));
      p = crlf + 2;
      if (chunkSz == 0 || p + chunkSz > body.size()) break;
      decoded.append(body, p, chunkSz);
      p += chunkSz + 2;
    }
    resp.body = std::move(decoded);
  } else {
    resp.body = std::move(body);
  }
  return resp;
}

class WsClient {
 public:
  SocketStream stream;
  std::string rxBuf;
  bool connected = false;

  void close() {
    if (connected) {
      sendFrame(0x8, "\x03\xe8");
      connected = false;
    }
    stream.close();
    rxBuf.clear();
  }

  bool connect(
      const std::string& wsUrl,
      const std::map<std::string, std::string>& extraHeaders,
      bool allowSelfSigned,
      int timeoutMs = 10000) {
    close();
    ParsedUrl u = parseUrl(wsUrl);
    if (!u.valid) return false;

    if (!stream.connectTo(u.host, u.port, u.useTls, allowSelfSigned, timeoutMs)) {
      return false;
    }

    uint8_t nonce[16];
    int urnd = ::open("/dev/urandom", O_RDONLY);
    if (urnd >= 0) {
      ssize_t r = ::read(urnd, nonce, sizeof(nonce));
      (void)r;
      ::close(urnd);
    } else {
      for (int i = 0; i < 16; i++) nonce[i] = static_cast<uint8_t>(std::time(nullptr) + i * 37);
    }
    std::string wsKey = base64Encode(nonce, sizeof(nonce));

    std::ostringstream req;
    req << "GET " << u.path << " HTTP/1.1\r\n"
        << "Host: " << u.host << ":" << u.port << "\r\n"
        << "Upgrade: websocket\r\n"
        << "Connection: Upgrade\r\n"
        << "Sec-WebSocket-Key: " << wsKey << "\r\n"
        << "Sec-WebSocket-Version: 13\r\n";
    for (const auto& kv : extraHeaders) {
      req << kv.first << ": " << kv.second << "\r\n";
    }
    req << "\r\n";

    std::string rawReq = req.str();
    if (!stream.sendAll(rawReq.data(), rawReq.size())) {
      close();
      return false;
    }

    char tmp[2048];
    size_t hdrEnd = std::string::npos;
    while (rxBuf.size() < 32768) {
      int wr = stream.waitReadable(timeoutMs);
      if (wr <= 0) {
        close();
        return false;
      }
      ssize_t n = stream.recvSome(tmp, sizeof(tmp));
      if (n <= 0) {
        close();
        return false;
      }
      rxBuf.append(tmp, static_cast<size_t>(n));
      hdrEnd = rxBuf.find("\r\n\r\n");
      if (hdrEnd != std::string::npos) break;
    }
    if (hdrEnd == std::string::npos) {
      close();
      return false;
    }

    std::string hdrs = rxBuf.substr(0, hdrEnd);
    rxBuf.erase(0, hdrEnd + 4);
    if (hdrs.find("101") == std::string::npos) {
      close();
      return false;
    }
    connected = true;
    return true;
  }

  bool sendFrame(uint8_t opcode, const std::string& payload) {
    if (stream.fd < 0) return false;
    std::vector<uint8_t> frame;
    frame.reserve(payload.size() + 16);
    frame.push_back(static_cast<uint8_t>(0x80 | (opcode & 0x0F)));

    size_t plen = payload.size();
    if (plen <= 125) {
      frame.push_back(static_cast<uint8_t>(0x80 | plen));
    } else if (plen <= 65535) {
      frame.push_back(static_cast<uint8_t>(0x80 | 126));
      frame.push_back(static_cast<uint8_t>((plen >> 8) & 0xFF));
      frame.push_back(static_cast<uint8_t>(plen & 0xFF));
    } else {
      frame.push_back(static_cast<uint8_t>(0x80 | 127));
      for (int s = 56; s >= 0; s -= 8) {
        frame.push_back(static_cast<uint8_t>((static_cast<uint64_t>(plen) >> s) & 0xFF));
      }
    }

    uint8_t mask[4] = {0x3A, 0x71, 0xC9, 0x54};
    uint32_t rnd = static_cast<uint32_t>(std::time(nullptr)) ^ static_cast<uint32_t>(::getpid());
    mask[0] ^= static_cast<uint8_t>(rnd & 0xFF);
    mask[1] ^= static_cast<uint8_t>((rnd >> 8) & 0xFF);
    frame.insert(frame.end(), mask, mask + 4);

    for (size_t i = 0; i < plen; i++) {
      frame.push_back(static_cast<uint8_t>(payload[i]) ^ mask[i & 3]);
    }
    return stream.sendAll(frame.data(), frame.size());
  }

  bool sendText(const std::string& text) {
    return connected && sendFrame(0x1, text);
  }

  // Returns 1 if message decoded, 0 on timeout, -1 on close/error
  int pollMessage(int timeoutMs, std::string& outText) {
    outText.clear();
    if (!connected) return -1;

    std::string assembled;
    int assembledOpcode = 0;

    while (true) {
      while (rxBuf.size() >= 2) {
        const uint8_t b0 = static_cast<uint8_t>(rxBuf[0]);
        const uint8_t b1 = static_cast<uint8_t>(rxBuf[1]);
        const bool fin = (b0 & 0x80) != 0;
        const uint8_t opcode = b0 & 0x0F;
        const bool masked = (b1 & 0x80) != 0;
        uint64_t plen = b1 & 0x7F;
        size_t hdrLen = 2;
        if (plen == 126) {
          if (rxBuf.size() < 4) break;
          plen = (static_cast<uint64_t>(static_cast<uint8_t>(rxBuf[2])) << 8) |
                 static_cast<uint64_t>(static_cast<uint8_t>(rxBuf[3]));
          hdrLen = 4;
        } else if (plen == 127) {
          if (rxBuf.size() < 10) break;
          plen = 0;
          for (int i = 0; i < 8; i++) {
            plen = (plen << 8) | static_cast<uint64_t>(static_cast<uint8_t>(rxBuf[2 + i]));
          }
          hdrLen = 10;
        }
        if (masked) hdrLen += 4;
        if (plen > 4 * 1024 * 1024) {
          close();
          return -1;
        }
        if (rxBuf.size() < hdrLen + plen) break;

        std::string payload = rxBuf.substr(hdrLen, static_cast<size_t>(plen));
        if (masked) {
          const uint8_t* m = reinterpret_cast<const uint8_t*>(rxBuf.data() + hdrLen - 4);
          for (size_t i = 0; i < payload.size(); i++) {
            payload[i] = static_cast<char>(static_cast<uint8_t>(payload[i]) ^ m[i & 3]);
          }
        }
        rxBuf.erase(0, hdrLen + static_cast<size_t>(plen));

        if (opcode == 0x8) {
          connected = false;
          stream.close();
          return -1;
        }
        if (opcode == 0x9) {
          sendFrame(0xA, payload);
          continue;
        }
        if (opcode == 0xA) {
          continue;
        }
        if (opcode != 0x0) {
          assembledOpcode = opcode;
          assembled = std::move(payload);
        } else {
          assembled += payload;
        }
        if (fin && (assembledOpcode == 0x1 || assembledOpcode == 0x2)) {
          outText = std::move(assembled);
          return 1;
        }
      }

      int wr = stream.waitReadable(timeoutMs);
      if (wr < 0) {
        close();
        return -1;
      }
      if (wr == 0) {
        return 0;
      }
      char tmp[8192];
      ssize_t n = stream.recvSome(tmp, sizeof(tmp));
      if (n <= 0) {
        close();
        return -1;
      }
      rxBuf.append(tmp, static_cast<size_t>(n));
    }
  }
};

}  // namespace vitrine_posix

