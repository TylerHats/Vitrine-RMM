#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <wintrust.h>
#include <softpub.h>
#include <sddl.h>
#include <aclapi.h>
#include <lm.h>
#include <iphlpapi.h>
#include <wtsapi32.h>
#include <tlhelp32.h>
#include <shellapi.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 0x00000800
#endif
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 0x00002000
#endif

namespace vitrine {

inline std::wstring utf8ToWide(const std::string& str) {
  if (str.empty()) return L"";
  int len = MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), nullptr, 0);
  if (len <= 0) return L"";
  std::wstring out(static_cast<size_t>(len), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), &out[0], len);
  return out;
}

inline std::string wideToUtf8(const std::wstring& wstr) {
  if (wstr.empty()) return "";
  int len = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
  if (len <= 0) return "";
  std::string out(static_cast<size_t>(len), '\0');
  WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), &out[0], len, nullptr, nullptr);
  return out;
}

inline std::string trimAscii(const std::string& s) {
  size_t a = 0;
  while (a < s.size() && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) a++;
  size_t b = s.size();
  while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) b--;
  return s.substr(a, b - a);
}

inline std::string toLowerAscii(const std::string& s) {
  std::string out = s;
  for (char& ch : out) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  return out;
}

inline std::string sanitizeIdentifier(const std::string& raw, const std::string& fallback, size_t maxLen = 48) {
  std::string out;
  for (unsigned char ch : raw) {
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-') {
      out.push_back(static_cast<char>(ch));
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
          std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned int>(c));
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
        break;
    }
  }
  return out;
}

inline std::string fmtInt(int64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(v));
  return std::string(buf);
}

inline std::string fmtUint64(uint64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(v));
  return std::string(buf);
}

inline std::string fmtDouble(double v) {
  char buf[48];
  std::snprintf(buf, sizeof(buf), "%.6g", v);
  return std::string(buf);
}

inline std::string urlEncodeAscii(const std::string& raw) {
  std::string out;
  out.reserve(raw.size() + 16);
  for (unsigned char c : raw) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
      out.push_back(static_cast<char>(c));
    } else {
      char buf[8];
      std::snprintf(buf, sizeof(buf), "%%%02X", static_cast<unsigned int>(c));
      out += buf;
    }
  }
  return out;
}

// ============================================================================
// Recursive-Descent Lightweight JSON Value Parser & Serializer Helpers
// ============================================================================
struct JsonVal {
  enum Type { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ };
  Type type = J_NULL;
  bool boolVal = false;
  double numVal = 0.0;
  std::string strVal;
  std::vector<JsonVal> arrVal;
  std::vector<std::pair<std::string, JsonVal>> objVal;

  const JsonVal* get(const std::string& k) const {
    if (type != J_OBJ) return nullptr;
    for (const auto& kv : objVal) {
      if (kv.first == k) return &kv.second;
    }
    return nullptr;
  }

  void setObj(const std::string& k, JsonVal v) {
    type = J_OBJ;
    for (auto& kv : objVal) {
      if (kv.first == k) {
        kv.second = std::move(v);
        return;
      }
    }
    objVal.emplace_back(k, std::move(v));
  }

  std::string getStr(const std::string& k, const std::string& def = "") const {
    const JsonVal* v = get(k);
    if (!v) return def;
    if (v->type == J_STR) return v->strVal;
    if (v->type == J_NUM) return fmtDouble(v->numVal);
    return def;
  }

  bool getBool(const std::string& k, bool def = false) const {
    const JsonVal* v = get(k);
    if (!v) return def;
    if (v->type == J_BOOL) return v->boolVal;
    if (v->type == J_NUM) return v->numVal != 0.0;
    if (v->type == J_STR) return v->strVal == "true" || v->strVal == "1";
    return def;
  }

  int64_t getInt(const std::string& k, int64_t def = 0) const {
    const JsonVal* v = get(k);
    if (!v) return def;
    if (v->type == J_NUM) return static_cast<int64_t>(v->numVal);
    if (v->type == J_BOOL) return v->boolVal ? 1 : 0;
    if (v->type == J_STR && !v->strVal.empty()) return std::strtoll(v->strVal.c_str(), nullptr, 10);
    return def;
  }
};

class JsonParser {
 public:
  explicit JsonParser(const std::string& src) : s_(src), pos_(0) {}

  bool parse(JsonVal& out) {
    skipWs();
    if (pos_ >= s_.size()) return false;
    return parseValue(out);
  }

 private:
  const std::string& s_;
  size_t pos_;

  void skipWs() {
    while (pos_ < s_.size() && (s_[pos_] == ' ' || s_[pos_] == '\t' || s_[pos_] == '\r' || s_[pos_] == '\n')) {
      pos_++;
    }
  }

  static void appendUtf8(std::string& out, uint32_t cp) {
    if (cp <= 0x7F) {
      out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
      out.push_back(static_cast<char>(0xC0 | ((cp >> 6) & 0x1F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
      out.push_back(static_cast<char>(0xE0 | ((cp >> 12) & 0x0F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | ((cp >> 18) & 0x07)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
  }

  bool parseHex4(uint32_t& out) {
    if (pos_ + 4 > s_.size()) return false;
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
      char c = s_[pos_++];
      v <<= 4;
      if (c >= '0' && c <= '9') v |= static_cast<uint32_t>(c - '0');
      else if (c >= 'a' && c <= 'f') v |= static_cast<uint32_t>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') v |= static_cast<uint32_t>(c - 'A' + 10);
      else return false;
    }
    out = v;
    return true;
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
            uint32_t cp = 0;
            if (!parseHex4(cp)) return false;
            if (cp >= 0xD800 && cp <= 0xDBFF && pos_ + 2 <= s_.size() && s_[pos_] == '\\' && s_[pos_ + 1] == 'u') {
              size_t save = pos_;
              pos_ += 2;
              uint32_t low = 0;
              if (parseHex4(low) && low >= 0xDC00 && low <= 0xDFFF) {
                cp = 0x10000 + (((cp - 0xD800) << 10) | (low - 0xDC00));
              } else {
                pos_ = save;
              }
            }
            appendUtf8(out, cp);
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

  bool parseValue(JsonVal& out) {
    skipWs();
    if (pos_ >= s_.size()) return false;
    char c = s_[pos_];
    if (c == '{') {
      out = JsonVal{};
      out.type = JsonVal::J_OBJ;
      pos_++;
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
        if (!parseValue(val)) return false;
        out.setObj(key, std::move(val));
        skipWs();
        if (pos_ < s_.size() && s_[pos_] == ',') { pos_++; continue; }
        if (pos_ < s_.size() && s_[pos_] == '}') { pos_++; return true; }
        return false;
      }
      return false;
    }
    if (c == '[') {
      out = JsonVal{};
      out.type = JsonVal::J_ARR;
      pos_++;
      skipWs();
      if (pos_ < s_.size() && s_[pos_] == ']') { pos_++; return true; }
      while (pos_ < s_.size()) {
        JsonVal elem;
        if (!parseValue(elem)) return false;
        out.arrVal.push_back(std::move(elem));
        skipWs();
        if (pos_ < s_.size() && s_[pos_] == ',') { pos_++; continue; }
        if (pos_ < s_.size() && s_[pos_] == ']') { pos_++; return true; }
        return false;
      }
      return false;
    }
    if (c == '"') {
      out = JsonVal{};
      out.type = JsonVal::J_STR;
      return parseString(out.strVal);
    }
    if (s_.compare(pos_, 4, "true") == 0) {
      out = JsonVal{}; out.type = JsonVal::J_BOOL; out.boolVal = true; pos_ += 4; return true;
    }
    if (s_.compare(pos_, 5, "false") == 0) {
      out = JsonVal{}; out.type = JsonVal::J_BOOL; out.boolVal = false; pos_ += 5; return true;
    }
    if (s_.compare(pos_, 4, "null") == 0) {
      out = JsonVal{}; out.type = JsonVal::J_NULL; pos_ += 4; return true;
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
      char* endPtr = nullptr;
      double val = std::strtod(s_.c_str() + pos_, &endPtr);
      if (endPtr == s_.c_str() + pos_) return false;
      out = JsonVal{};
      out.type = JsonVal::J_NUM;
      out.numVal = val;
      pos_ = static_cast<size_t>(endPtr - s_.c_str());
      return true;
    }
    return false;
  }
};

inline bool parseJson(const std::string& text, JsonVal& out) {
  std::string s = text;
  if (s.size() >= 3 && static_cast<unsigned char>(s[0]) == 0xEF && static_cast<unsigned char>(s[1]) == 0xBB && static_cast<unsigned char>(s[2]) == 0xBF) {
    s = s.substr(3);
  }
  JsonParser p(s);
  return p.parse(out);
}

inline std::string serializeJson(const JsonVal& v) {
  switch (v.type) {
    case JsonVal::J_NULL: return "null";
    case JsonVal::J_BOOL: return v.boolVal ? "true" : "false";
    case JsonVal::J_NUM: return fmtDouble(v.numVal);
    case JsonVal::J_STR: return "\"" + jsonEscape(v.strVal) + "\"";
    case JsonVal::J_ARR: {
      std::string out = "[";
      for (size_t i = 0; i < v.arrVal.size(); i++) {
        if (i > 0) out += ",";
        out += serializeJson(v.arrVal[i]);
      }
      return out + "]";
    }
    case JsonVal::J_OBJ: {
      std::string out = "{";
      for (size_t i = 0; i < v.objVal.size(); i++) {
        if (i > 0) out += ",";
        out += "\"" + jsonEscape(v.objVal[i].first) + "\":" + serializeJson(v.objVal[i].second);
      }
      return out + "}";
    }
  }
  return "null";
}

// ============================================================================
// Filesystem & PE Embedded Resource Config Helpers
// ============================================================================
inline std::wstring getSelfExePath() {
  std::vector<wchar_t> buf(32768, L'\0');
  DWORD len = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
  return std::wstring(buf.data(), len);
}

inline std::wstring getSelfDir() {
  std::wstring p = getSelfExePath();
  size_t pos = p.find_last_of(L"\\/");
  return (pos == std::wstring::npos) ? L"." : p.substr(0, pos);
}

inline std::wstring joinPath(const std::wstring& a, const std::wstring& b) {
  if (a.empty()) return b;
  if (a.back() == L'\\' || a.back() == L'/') return a + b;
  return a + L"\\" + b;
}

inline bool fileExists(const std::wstring& path) {
  DWORD attr = GetFileAttributesW(path.c_str());
  return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

inline bool dirExists(const std::wstring& path) {
  DWORD attr = GetFileAttributesW(path.c_str());
  return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

inline bool ensureDirRecursive(const std::wstring& path) {
  if (path.empty()) return false;
  if (dirExists(path)) return true;
  size_t start = 0;
  if (path.size() >= 2 && path[1] == L':') start = 2;
  for (size_t i = start; i <= path.size(); i++) {
    if (i == path.size() || path[i] == L'\\' || path[i] == L'/') {
      std::wstring sub = path.substr(0, i);
      if (!sub.empty() && sub.back() != L':') {
        CreateDirectoryW(sub.c_str(), nullptr);
      }
    }
  }
  return dirExists(path);
}

inline void deleteDirectoryTreeNative(const std::wstring& dirPath, bool scheduleLockedOnReboot = true) {
  if (dirPath.empty()) return;
  DWORD attr = GetFileAttributesW(dirPath.c_str());
  if (attr == INVALID_FILE_ATTRIBUTES) return;
  if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
    if (attr & FILE_ATTRIBUTE_READONLY) SetFileAttributesW(dirPath.c_str(), FILE_ATTRIBUTE_NORMAL);
    if (!DeleteFileW(dirPath.c_str()) && scheduleLockedOnReboot) {
      MoveFileExW(dirPath.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
    return;
  }
  WIN32_FIND_DATAW ffd{};
  std::wstring pattern = joinPath(dirPath, L"*");
  HANDLE hFind = FindFirstFileW(pattern.c_str(), &ffd);
  if (hFind != INVALID_HANDLE_VALUE) {
    do {
      if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) continue;
      std::wstring child = joinPath(dirPath, ffd.cFileName);
      if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        deleteDirectoryTreeNative(child, scheduleLockedOnReboot);
      } else {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_READONLY) {
          SetFileAttributesW(child.c_str(), FILE_ATTRIBUTE_NORMAL);
        }
        if (!DeleteFileW(child.c_str()) && scheduleLockedOnReboot) {
          MoveFileExW(child.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        }
      }
    } while (FindNextFileW(hFind, &ffd));
    FindClose(hFind);
  }
  if (!RemoveDirectoryW(dirPath.c_str()) && scheduleLockedOnReboot) {
    MoveFileExW(dirPath.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
  }
}

inline std::string readTextFile(const std::wstring& path) {
  HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return "";
  LARGE_INTEGER sz{};
  if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 32 * 1024 * 1024) {
    CloseHandle(h);
    return "";
  }
  std::string out(static_cast<size_t>(sz.QuadPart), '\0');
  DWORD total = 0;
  while (total < static_cast<DWORD>(sz.QuadPart)) {
    DWORD chunk = 0;
    if (!ReadFile(h, &out[total], static_cast<DWORD>(sz.QuadPart) - total, &chunk, nullptr) || chunk == 0) break;
    total += chunk;
  }
  CloseHandle(h);
  out.resize(total);
  return out;
}

inline bool writeBytesFile(const std::wstring& path, const void* data, size_t len) {
  HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return false;
  size_t written = 0;
  const uint8_t* ptr = static_cast<const uint8_t*>(data);
  while (written < len) {
    DWORD chunk = static_cast<DWORD>(std::min<size_t>(len - written, 65536));
    DWORD got = 0;
    if (!WriteFile(h, ptr + written, chunk, &got, nullptr) || got == 0) {
      CloseHandle(h);
      return false;
    }
    written += got;
  }
  CloseHandle(h);
  return true;
}

inline bool writeTextFile(const std::wstring& path, const std::string& content) {
  return writeBytesFile(path, content.data(), content.size());
}

inline int64_t getCurrentUnixEpochSec() {
  FILETIME ft{};
  GetSystemTimeAsFileTime(&ft);
  ULARGE_INTEGER ui{};
  ui.LowPart = ft.dwLowDateTime;
  ui.HighPart = ft.dwHighDateTime;
  constexpr uint64_t kEpochDiff100ns = 116444736000000000ULL;
  if (ui.QuadPart < kEpochDiff100ns) return 0;
  return static_cast<int64_t>((ui.QuadPart - kEpochDiff100ns) / 10000000ULL);
}

inline std::wstring getEnvVar(const wchar_t* name) {
  DWORD len = GetEnvironmentVariableW(name, nullptr, 0);
  if (len == 0) return L"";
  std::wstring buf(len, L'\0');
  DWORD got = GetEnvironmentVariableW(name, &buf[0], len);
  buf.resize(got);
  return buf;
}

inline std::string readEmbeddedConfigJson() {
  HMODULE mod = GetModuleHandleW(nullptr);
  HRSRC res = FindResourceExW(mod, RT_RCDATA, MAKEINTRESOURCEW(101), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US));
  if (!res) res = FindResourceW(mod, MAKEINTRESOURCEW(101), RT_RCDATA);
  if (!res) return "";
  DWORD sz = SizeofResource(mod, res);
  if (sz == 0 || sz > 4 * 1024 * 1024) return "";
  HGLOBAL hData = LoadResource(mod, res);
  if (!hData) return "";
  const char* ptr = static_cast<const char*>(LockResource(hData));
  if (!ptr) return "";
  return std::string(ptr, sz);
}

// ============================================================================
// Native WinHTTP Client (No curl / Invoke-WebRequest)
// ============================================================================
struct HttpResponse {
  int statusCode = 0;
  std::string body;
  std::string error;
};

struct ParsedUrl {
  bool valid = false;
  bool isHttps = false;
  std::wstring host;
  INTERNET_PORT port = 0;
  std::wstring pathAndQuery;
};

inline ParsedUrl crackHttpUrl(const std::string& url) {
  ParsedUrl out;
  std::wstring wurl = utf8ToWide(url);
  if (wurl.empty()) return out;
  URL_COMPONENTS uc{};
  uc.dwStructSize = sizeof(uc);
  wchar_t hostBuf[512]{};
  wchar_t pathBuf[2048]{};
  wchar_t extraBuf[2048]{};
  uc.lpszHostName = hostBuf;
  uc.dwHostNameLength = 512;
  uc.lpszUrlPath = pathBuf;
  uc.dwUrlPathLength = 2048;
  uc.lpszExtraInfo = extraBuf;
  uc.dwExtraInfoLength = 2048;
  if (!WinHttpCrackUrl(wurl.c_str(), static_cast<DWORD>(wurl.size()), 0, &uc)) return out;
  if (uc.nScheme != INTERNET_SCHEME_HTTPS && uc.nScheme != INTERNET_SCHEME_HTTP) return out;
  out.valid = true;
  out.isHttps = (uc.nScheme == INTERNET_SCHEME_HTTPS);
  out.host = std::wstring(hostBuf, uc.dwHostNameLength);
  out.port = uc.nPort;
  out.pathAndQuery = std::wstring(pathBuf, uc.dwUrlPathLength) + std::wstring(extraBuf, uc.dwExtraInfoLength);
  if (out.pathAndQuery.empty()) out.pathAndQuery = L"/";
  return out;
}

inline HttpResponse httpRequest(
    const std::string& url,
    const std::string& method,
    const std::string& body,
    const std::vector<std::pair<std::string, std::string>>& headers,
    bool allowSelfSignedTls,
    DWORD timeoutMs = 15000) {
  HttpResponse resp;
  ParsedUrl u = crackHttpUrl(url);
  if (!u.valid) {
    resp.error = "Invalid URL: " + url;
    return resp;
  }

  HINTERNET hSession = WinHttpOpen(L"VitrineRMM-Agent/2.7.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSession) hSession = WinHttpOpen(L"VitrineRMM-Agent/2.7.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSession) {
    resp.error = "WinHttpOpen failed";
    return resp;
  }

  WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);
  DWORD secProto = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
  WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &secProto, sizeof(secProto));

  HINTERNET hConn = WinHttpConnect(hSession, u.host.c_str(), u.port, 0);
  if (!hConn) {
    resp.error = "WinHttpConnect failed";
    WinHttpCloseHandle(hSession);
    return resp;
  }

  std::wstring wMethod = utf8ToWide(method);
  DWORD flags = u.isHttps ? WINHTTP_FLAG_SECURE : 0;
  HINTERNET hReq = WinHttpOpenRequest(hConn, wMethod.c_str(), u.pathAndQuery.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
  if (!hReq) {
    resp.error = "WinHttpOpenRequest failed";
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSession);
    return resp;
  }

  if (u.isHttps && allowSelfSignedTls) {
    DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
  }

  std::wstring hdrBlock;
  for (const auto& kv : headers) {
    hdrBlock += utf8ToWide(kv.first) + L": " + utf8ToWide(kv.second) + L"\r\n";
  }

  BOOL ok = WinHttpSendRequest(
      hReq,
      hdrBlock.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : hdrBlock.c_str(),
      hdrBlock.empty() ? 0 : static_cast<DWORD>(hdrBlock.size()),
      body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
      static_cast<DWORD>(body.size()),
      static_cast<DWORD>(body.size()),
      0);

  if (ok && WinHttpReceiveResponse(hReq, nullptr)) {
    DWORD code = 0, codeSz = sizeof(code);
    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &code, &codeSz, WINHTTP_NO_HEADER_INDEX);
    resp.statusCode = static_cast<int>(code);

    DWORD avail = 0;
    const size_t kMaxBytes = 64 * 1024 * 1024;
    while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
      if (resp.body.size() + avail > kMaxBytes) break;
      size_t cur = resp.body.size();
      resp.body.resize(cur + avail);
      DWORD readGot = 0;
      if (!WinHttpReadData(hReq, &resp.body[cur], avail, &readGot) || readGot == 0) {
        resp.body.resize(cur);
        break;
      }
      resp.body.resize(cur + readGot);
    }
  } else {
    resp.error = "WinHttp request failed (err=" + fmtInt(GetLastError()) + ")";
  }

  WinHttpCloseHandle(hReq);
  WinHttpCloseHandle(hConn);
  WinHttpCloseHandle(hSession);
  return resp;
}

inline bool httpDownloadToFile(const std::string& url, const std::wstring& destPath, bool allowSelfSignedTls, std::string& outErr, DWORD timeoutMs = 30000) {
  HttpResponse res = httpRequest(url, "GET", "", {}, allowSelfSignedTls, timeoutMs);
  if (res.statusCode < 200 || res.statusCode >= 300 || res.body.empty()) {
    outErr = res.error.empty() ? ("HTTP " + fmtInt(res.statusCode) + " downloading " + url) : res.error;
    return false;
  }
  std::wstring tmp = destPath + L".tmp";
  if (!writeBytesFile(tmp, res.body.data(), res.body.size())) {
    outErr = "Failed to write temporary download file";
    return false;
  }
  if (!MoveFileExW(tmp.c_str(), destPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    DeleteFileW(tmp.c_str());
    outErr = "Failed to finalize downloaded file";
    return false;
  }
  return true;
}

// ============================================================================
// Native Authenticode Verification via WinVerifyTrust (wintrust.dll)
// ============================================================================
inline bool verifyAuthenticodeSignature(const std::wstring& filePath, std::string& outStatusMsg) {
  WINTRUST_FILE_INFO fileInfo{};
  fileInfo.cbStruct = sizeof(fileInfo);
  fileInfo.pcwszFilePath = filePath.c_str();

  GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  WINTRUST_DATA wt{};
  wt.cbStruct = sizeof(wt);
  wt.dwUIChoice = WTD_UI_NONE;
  wt.fdwRevocationChecks = WTD_REVOKE_NONE;
  wt.dwUnionChoice = WTD_CHOICE_FILE;
  wt.pFile = &fileInfo;
  wt.dwStateAction = WTD_STATEACTION_VERIFY;
  wt.dwProvFlags = WTD_SAFER_FLAG;

  LONG st = WinVerifyTrust(nullptr, &policyGuid, &wt);
  wt.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(nullptr, &policyGuid, &wt);

  if (st == ERROR_SUCCESS) {
    outStatusMsg = "Valid";
    return true;
  }
  char hex[32];
  std::snprintf(hex, sizeof(hex), "0x%08lX", static_cast<unsigned long>(st));
  outStatusMsg = std::string("WinVerifyTrust failed (") + hex + ")";
  return false;
}

// ============================================================================
// Native NTFS ACL, Process, Registry, Service & LAPS Helpers
// ============================================================================
inline void applySddlToPath(const std::wstring& path, const wchar_t* sddl) {
  PSECURITY_DESCRIPTOR pSd = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSd, nullptr) || !pSd) return;
  PACL pDacl = nullptr;
  BOOL daclPresent = FALSE;
  BOOL daclDefaulted = FALSE;
  if (GetSecurityDescriptorDacl(pSd, &daclPresent, &pDacl, &daclDefaulted) && daclPresent && pDacl) {
    SetNamedSecurityInfoW(
        const_cast<LPWSTR>(path.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, pDacl, nullptr);
  }
  LocalFree(pSd);
}

inline void hardenAdminOnlyAcl(const std::wstring& path) {
  applySddlToPath(path, L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
}

inline void grantUsersModifyAcl(const std::wstring& path) {
  applySddlToPath(path, L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301BF;;;BU)");
}

inline void killProcessesByExeName(const std::wstring& exeName) {
  DWORD selfPid = GetCurrentProcessId();
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return;
  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);
  if (Process32FirstW(snap, &pe)) {
    do {
      if (pe.th32ProcessID != selfPid && _wcsicmp(pe.szExeFile, exeName.c_str()) == 0) {
        HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
        if (hp) {
          TerminateProcess(hp, 0);
          WaitForSingleObject(hp, 3000);
          CloseHandle(hp);
        }
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
}

inline bool setRegistryRunValue(const std::wstring& name, const std::wstring& cmdLine) {
  HKEY hKey = nullptr;
  if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr) != ERROR_SUCCESS) {
    return false;
  }
  LONG r = RegSetValueExW(hKey, name.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(cmdLine.c_str()), static_cast<DWORD>((cmdLine.size() + 1) * sizeof(wchar_t)));
  RegCloseKey(hKey);
  return r == ERROR_SUCCESS;
}

inline void deleteRegistryRunValue(const std::wstring& name) {
  HKEY hKey = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
    RegDeleteValueW(hKey, name.c_str());
    RegCloseKey(hKey);
  }
}

inline void registerUninstallEntry(const std::wstring& keyName, const std::wstring& displayName, const std::wstring& publisher, const std::wstring& uninstallCmd, const std::wstring& installDir, const std::wstring& iconPath) {
  std::wstring subKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + keyName;
  HKEY hKey = nullptr;
  if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr) != ERROR_SUCCESS) return;
  auto putSz = [&](const wchar_t* valName, const std::wstring& val) {
    RegSetValueExW(hKey, valName, 0, REG_SZ, reinterpret_cast<const BYTE*>(val.c_str()), static_cast<DWORD>((val.size() + 1) * sizeof(wchar_t)));
  };
  putSz(L"DisplayName", displayName);
  putSz(L"Publisher", publisher);
  putSz(L"DisplayVersion", L"2.7.0");
  putSz(L"UninstallString", uninstallCmd);
  putSz(L"QuietUninstallString", uninstallCmd);
  putSz(L"InstallLocation", installDir);
  putSz(L"DisplayIcon", iconPath);
  DWORD one = 1;
  RegSetValueExW(hKey, L"NoModify", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&one), sizeof(one));
  RegSetValueExW(hKey, L"NoRepair", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&one), sizeof(one));
  RegCloseKey(hKey);
}

inline void deleteUninstallEntry(const std::wstring& keyName) {
  std::wstring subKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + keyName;
  RegDeleteKeyW(HKEY_LOCAL_MACHINE, subKey.c_str());
}

inline bool stopAndDeleteServiceNative(const std::wstring& svcName) {
  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!scm) return false;
  SC_HANDLE svc = OpenServiceW(scm, svcName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
  if (!svc) {
    CloseServiceHandle(scm);
    return false;
  }
  SERVICE_STATUS_PROCESS ssp{};
  DWORD bytesNeeded = 0;
  ControlService(svc, SERVICE_CONTROL_STOP, reinterpret_cast<LPSERVICE_STATUS>(&ssp));
  for (int i = 0; i < 20; i++) {
    if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded)) break;
    if (ssp.dwCurrentState == SERVICE_STOPPED) break;
    Sleep(250);
  }
  BOOL delOk = DeleteService(svc);
  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  return delOk != FALSE;
}

inline bool installAndStartServiceNative(const std::wstring& svcName, const std::wstring& displayName, const std::wstring& desc, const std::wstring& binPath, std::string& outErr) {
  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
  if (!scm) {
    outErr = "OpenSCManagerW failed (err=" + fmtInt(GetLastError()) + ")";
    return false;
  }
  std::wstring quotedPath = L"\"" + binPath + L"\"";
  SC_HANDLE svc = OpenServiceW(scm, svcName.c_str(), SERVICE_ALL_ACCESS);
  if (svc) {
    SERVICE_STATUS_PROCESS ssp{};
    DWORD bn = 0;
    ControlService(svc, SERVICE_CONTROL_STOP, reinterpret_cast<LPSERVICE_STATUS>(&ssp));
    for (int i = 0; i < 20; i++) {
      if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bn)) break;
      if (ssp.dwCurrentState == SERVICE_STOPPED) break;
      Sleep(250);
    }
    ChangeServiceConfigW(svc, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, quotedPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, displayName.c_str());
  } else {
    svc = CreateServiceW(
        scm, svcName.c_str(), displayName.c_str(), SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        quotedPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
  }
  if (!svc) {
    outErr = "CreateServiceW failed (err=" + fmtInt(GetLastError()) + ")";
    CloseServiceHandle(scm);
    return false;
  }

  SERVICE_DESCRIPTIONW sd{};
  sd.lpDescription = const_cast<LPWSTR>(desc.c_str());
  ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &sd);

  SC_ACTION actions[3]{};
  for (int i = 0; i < 3; i++) {
    actions[i].Type = SC_ACTION_RESTART;
    actions[i].Delay = 5000;
  }
  SERVICE_FAILURE_ACTIONSW sfa{};
  sfa.dwResetPeriod = 86400;
  sfa.cActions = 3;
  sfa.lpsaActions = actions;
  ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);

  BOOL startOk = StartServiceW(svc, 0, nullptr);
  DWORD startErr = startOk ? 0 : GetLastError();
  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  if (!startOk && startErr != ERROR_SERVICE_ALREADY_RUNNING) {
    outErr = "StartServiceW failed (err=" + fmtInt(startErr) + ")";
    return false;
  }
  return true;
}

inline bool createOrUpdateLocalAdminAccount(const std::wstring& username, const std::wstring& password) {
  if (username.empty() || password.empty()) return false;
  USER_INFO_1 ui{};
  ui.usri1_name = const_cast<LPWSTR>(username.c_str());
  ui.usri1_password = const_cast<LPWSTR>(password.c_str());
  ui.usri1_priv = USER_PRIV_USER;
  ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;

  DWORD parmErr = 0;
  NET_API_STATUS st = NetUserAdd(nullptr, 1, reinterpret_cast<LPBYTE>(&ui), &parmErr);
  if (st == NERR_UserExists) {
    USER_INFO_1003 pwInfo{};
    pwInfo.usri1003_password = const_cast<LPWSTR>(password.c_str());
    st = NetUserSetInfo(nullptr, username.c_str(), 1003, reinterpret_cast<LPBYTE>(&pwInfo), &parmErr);
  }
  if (st != NERR_Success) return false;

  PSID pAdminSid = nullptr;
  if (ConvertStringSidToSidW(L"S-1-5-32-544", &pAdminSid) && pAdminSid) {
    wchar_t grpName[256]{};
    DWORD grpLen = 256;
    wchar_t domName[256]{};
    DWORD domLen = 256;
    SID_NAME_USE snu{};
    if (LookupAccountSidW(nullptr, pAdminSid, grpName, &grpLen, domName, &domLen, &snu)) {
      LOCALGROUP_MEMBERS_INFO_3 mem{};
      mem.lgrmi3_domainandname = const_cast<LPWSTR>(username.c_str());
      NET_API_STATUS gs = NetLocalGroupAddMembers(nullptr, grpName, 3, reinterpret_cast<LPBYTE>(&mem), 1);
      LocalFree(pAdminSid);
      return gs == NERR_Success || gs == ERROR_MEMBER_IN_ALIAS;
    }
    LocalFree(pAdminSid);
  }
  return true;
}

// ============================================================================
// Subprocess & Native Architecture / Telemetry Helpers
// ============================================================================
inline std::string detectWindowsArch() {
  typedef BOOL(WINAPI * LPFN_ISWOW64PROCESS2)(HANDLE, USHORT*, USHORT*);
  auto fn2 = reinterpret_cast<LPFN_ISWOW64PROCESS2>(reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2")));
  if (fn2) {
    USHORT pm = 0, nm = 0;
    if (fn2(GetCurrentProcess(), &pm, &nm)) {
      if (nm == 0xAA64) return "arm64";
      if (nm == 0x8664) return "x64";
      if (nm == 0x014c) return "x86";
    }
  }
  SYSTEM_INFO si{};
  GetNativeSystemInfo(&si);
  if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) return "arm64";
  if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) return "x64";
  return "x86";
}

struct ExecResult {
  DWORD exitCode = 1;
  std::string output;
  bool launched = false;
};

inline ExecResult runProcessCapture(const std::wstring& cmdLine, bool wait = true, DWORD timeoutMs = 60000, const std::wstring& workDir = L"") {
  ExecResult r;
  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;

  HANDLE hRead = nullptr, hWrite = nullptr;
  if (wait && !CreatePipe(&hRead, &hWrite, &sa, 0)) {
    return r;
  }
  if (hRead) SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW | (wait ? STARTF_USESTDHANDLES : 0);
  si.wShowWindow = SW_HIDE;
  si.hStdOutput = wait ? hWrite : nullptr;
  si.hStdError = wait ? hWrite : nullptr;
  si.hStdInput = nullptr;

  PROCESS_INFORMATION pi{};
  std::wstring mutableCmd = cmdLine;
  BOOL ok = CreateProcessW(
      nullptr, &mutableCmd[0], nullptr, nullptr, wait ? TRUE : FALSE,
      CREATE_NO_WINDOW, nullptr, workDir.empty() ? nullptr : workDir.c_str(), &si, &pi);

  if (hWrite) CloseHandle(hWrite);
  if (!ok) {
    if (hRead) CloseHandle(hRead);
    r.exitCode = GetLastError();
    return r;
  }

  r.launched = true;
  if (!wait) {
    r.exitCode = 0;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return r;
  }

  DWORD startTick = GetTickCount();
  char buf[4096];
  while (true) {
    DWORD avail = 0;
    while (PeekNamedPipe(hRead, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
      DWORD got = 0;
      if (!ReadFile(hRead, buf, sizeof(buf), &got, nullptr) || got == 0) break;
      if (r.output.size() < 512 * 1024) r.output.append(buf, got);
    }
    DWORD waitRes = WaitForSingleObject(pi.hProcess, 50);
    if (waitRes == WAIT_OBJECT_0) {
      while (PeekNamedPipe(hRead, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
        DWORD got = 0;
        if (!ReadFile(hRead, buf, sizeof(buf), &got, nullptr) || got == 0) break;
        if (r.output.size() < 512 * 1024) r.output.append(buf, got);
      }
      break;
    }
    if (GetTickCount() - startTick > timeoutMs) {
      TerminateProcess(pi.hProcess, 124);
      r.output += "\n[Command timed out]";
      r.exitCode = 124;
      CloseHandle(hRead);
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      return r;
    }
  }

  DWORD code = 0;
  GetExitCodeProcess(pi.hProcess, &code);
  r.exitCode = code;
  CloseHandle(hRead);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return r;
}

inline std::string getHostnameStr() {
  wchar_t buf[256]{};
  DWORD sz = 256;
  if (GetComputerNameExW(ComputerNameDnsHostname, buf, &sz) || GetComputerNameW(buf, &sz)) {
    return wideToUtf8(std::wstring(buf, sz));
  }
  return "WINDOWS-ENDPOINT";
}

inline std::string getWindowsVersionCaption() {
  typedef LONG(WINAPI * RtlGetVersionFn)(OSVERSIONINFOEXW*);
  auto fn = reinterpret_cast<RtlGetVersionFn>(reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion")));
  if (fn) {
    OSVERSIONINFOEXW ov{};
    ov.dwOSVersionInfoSize = sizeof(ov);
    if (fn(&ov) == 0) {
      std::string label = (ov.wProductType == VER_NT_WORKSTATION)
          ? (ov.dwBuildNumber >= 22000 ? "Windows 11" : "Windows 10")
          : (ov.dwBuildNumber >= 26100 ? "Windows Server 2025" : ov.dwBuildNumber >= 20348 ? "Windows Server 2022" : "Windows Server");
      return label + " (Build " + fmtInt(ov.dwBuildNumber) + ")";
    }
  }
  return "Windows";
}

inline std::string getPrimaryIpv4AndMac(std::string& outMac) {
  outMac.clear();
  ULONG sz = 16384;
  std::vector<uint8_t> buf(sz);
  DWORD ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &sz);
  if (ret == ERROR_BUFFER_OVERFLOW) {
    buf.resize(sz);
    ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &sz);
  }
  if (ret != NO_ERROR) return "127.0.0.1";
  for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()); a != nullptr; a = a->Next) {
    if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
    for (auto* ua = a->FirstUnicastAddress; ua != nullptr; ua = ua->Next) {
      if (ua->Address.lpSockaddr && ua->Address.lpSockaddr->sa_family == AF_INET) {
        char ipStr[64]{};
        auto* sin = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
        if (InetNtopA(AF_INET, &sin->sin_addr, ipStr, sizeof(ipStr))) {
          std::string ip(ipStr);
          if (ip.rfind("127.", 0) == 0 || ip.rfind("169.254.", 0) == 0) continue;
          if (a->PhysicalAddressLength >= 6) {
            char macBuf[32];
            std::snprintf(macBuf, sizeof(macBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                a->PhysicalAddress[0], a->PhysicalAddress[1], a->PhysicalAddress[2],
                a->PhysicalAddress[3], a->PhysicalAddress[4], a->PhysicalAddress[5]);
            outMac = macBuf;
          }
          return ip;
        }
      }
    }
  }
  return "127.0.0.1";
}

struct MemoryModuleInfo {
  std::string slot;
  double capacityGb = 0.0;
  uint32_t speedMhz = 0;
  std::string manufacturer;
  std::string partNumber;
};

struct SmbiosInfo {
  uint8_t chassisType = 0;
  std::string manufacturer;
  std::string model;
  std::string serialNumber;
  std::string uuid;
  std::string motherboardVendor;
  std::string motherboardName;
  std::string motherboardSerial;
  std::string biosVendor;
  std::string biosVersion;
  std::string biosDate;
  std::vector<MemoryModuleInfo> modules;
};

inline std::string cleanSmbiosString(const std::string& raw) {
  std::string s = trimAscii(raw);
  if (s.empty() || s == "To Be Filled By O.E.M." || s == "Default string" || s == "Not Specified" ||
      s == "None" || s == "System Serial Number" || s == "System Product Name" || s == "System Manufacturer") {
    return "";
  }
  return s;
}

inline std::string getSmbiosString(const std::vector<std::string>& strings, uint8_t idx1Based) {
  if (idx1Based == 0 || static_cast<size_t>(idx1Based - 1) >= strings.size()) return "";
  return cleanSmbiosString(strings[idx1Based - 1]);
}

inline SmbiosInfo readSmbiosInfo() {
  SmbiosInfo info;
  constexpr DWORD kRsmb = 0x52534D42;
  UINT sz = GetSystemFirmwareTable(kRsmb, 0, nullptr, 0);
  if (sz < 8 || sz > 256 * 1024) return info;
  std::vector<uint8_t> buf(sz);
  if (GetSystemFirmwareTable(kRsmb, 0, buf.data(), sz) != sz) return info;
  size_t off = 8;
  while (off + 4 <= buf.size()) {
    uint8_t tblType = buf[off];
    uint8_t tblLen = buf[off + 1];
    if (tblLen < 4 || off + tblLen > buf.size()) break;
    size_t strBase = off + tblLen;
    size_t next = strBase;
    std::vector<std::string> strings;
    while (next + 1 < buf.size()) {
      if (buf[next] == 0 && buf[next + 1] == 0) {
        next += 2;
        break;
      }
      if (buf[next] == 0) {
        next++;
        continue;
      }
      size_t end = next;
      while (end < buf.size() && buf[end] != 0) end++;
      strings.emplace_back(reinterpret_cast<const char*>(&buf[next]), end - next);
      next = end + 1;
      if (next < buf.size() && buf[next] == 0) {
        next++;
        break;
      }
    }

    if (tblType == 0 && tblLen >= 6) {
      info.biosVendor = getSmbiosString(strings, buf[off + 4]);
      info.biosVersion = getSmbiosString(strings, buf[off + 5]);
      info.biosDate = (tblLen > 8) ? getSmbiosString(strings, buf[off + 8]) : "";
    } else if (tblType == 1 && tblLen >= 8) {
      info.manufacturer = getSmbiosString(strings, buf[off + 4]);
      info.model = getSmbiosString(strings, buf[off + 5]);
      info.serialNumber = getSmbiosString(strings, buf[off + 7]);
      if (tblLen >= 24) {
        bool allZero = true, allFF = true;
        for (int b = 0; b < 16; b++) {
          uint8_t v = buf[off + 8 + b];
          if (v != 0x00) allZero = false;
          if (v != 0xFF) allFF = false;
        }
        if (!allZero && !allFF) {
          const uint8_t* u = &buf[off + 8];
          char uBuf[48];
          // SMBIOS UUID uses little-endian first 3 fields per RFC 4122 SMBIOS 2.6+ convention
          std::snprintf(uBuf, sizeof(uBuf),
              "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
              u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6],
              u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
          info.uuid = uBuf;
        }
      }
    } else if (tblType == 2 && tblLen >= 8) {
      info.motherboardVendor = getSmbiosString(strings, buf[off + 4]);
      info.motherboardName = getSmbiosString(strings, buf[off + 5]);
      info.motherboardSerial = getSmbiosString(strings, buf[off + 7]);
    } else if (tblType == 3 && tblLen >= 6) {
      info.chassisType = buf[off + 5] & 0x7F;
    } else if (tblType == 17 && tblLen >= 27 && info.modules.size() < 32) {
      uint16_t memSizeRaw = static_cast<uint16_t>(buf[off + 12]) | (static_cast<uint16_t>(buf[off + 13]) << 8);
      if (memSizeRaw != 0 && memSizeRaw != 0xFFFF) {
        MemoryModuleInfo m;
        uint64_t sizeMb = 0;
        if (memSizeRaw == 0x7FFF && tblLen >= 32) {
          uint32_t extMb = static_cast<uint32_t>(buf[off + 28]) |
                           (static_cast<uint32_t>(buf[off + 29]) << 8) |
                           (static_cast<uint32_t>(buf[off + 30]) << 16) |
                           (static_cast<uint32_t>(buf[off + 31]) << 24);
          sizeMb = extMb & 0x7FFFFFFFU;
        } else if (memSizeRaw & 0x8000) {
          sizeMb = (memSizeRaw & 0x7FFF) / 1024;
        } else {
          sizeMb = memSizeRaw;
        }
        if (sizeMb > 0) {
          m.capacityGb = std::round((static_cast<double>(sizeMb) / 1024.0) * 100.0) / 100.0;
          m.slot = getSmbiosString(strings, buf[off + 16]);
          if (m.slot.empty() && tblLen >= 18) m.slot = getSmbiosString(strings, buf[off + 17]);
          uint16_t spd = static_cast<uint16_t>(buf[off + 21]) | (static_cast<uint16_t>(buf[off + 22]) << 8);
          m.speedMhz = spd;
          m.manufacturer = getSmbiosString(strings, buf[off + 23]);
          m.partNumber = getSmbiosString(strings, buf[off + 26]);
          info.modules.push_back(std::move(m));
        }
      }
    }
    if (tblType == 127) break;
    off = next;
  }
  return info;
}

inline std::string readSmbiosSerialNumber() {
  return readSmbiosInfo().serialNumber;
}

inline void readCpuRegistryInfo(std::string& outModel, uint32_t& outMhz) {
  outModel.clear();
  outMhz = 0;
  HKEY hk = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
    wchar_t nameBuf[256]{};
    DWORD sz = sizeof(nameBuf);
    DWORD ty = 0;
    if (RegQueryValueExW(hk, L"ProcessorNameString", nullptr, &ty, reinterpret_cast<LPBYTE>(nameBuf), &sz) == ERROR_SUCCESS &&
        (ty == REG_SZ || ty == REG_EXPAND_SZ) && sz >= sizeof(wchar_t)) {
      nameBuf[(sizeof(nameBuf) / sizeof(wchar_t)) - 1] = L'\0';
      outModel = trimAscii(wideToUtf8(std::wstring(nameBuf)));
    }
    DWORD mhz = 0, mhzSz = sizeof(mhz);
    if (RegQueryValueExW(hk, L"~MHz", nullptr, &ty, reinterpret_cast<LPBYTE>(&mhz), &mhzSz) == ERROR_SUCCESS && ty == REG_DWORD) {
      outMhz = mhz;
    }
    RegCloseKey(hk);
  }
}

inline std::string readBitLockerStatusStr() {
  HKEY hk = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\BitLocker\\Status", 0, KEY_READ | KEY_WOW64_64KEY, &hk) == ERROR_SUCCESS) {
    DWORD bootSt = 0, sz = sizeof(bootSt), ty = 0;
    LONG r = RegQueryValueExW(hk, L"BootStatus", nullptr, &ty, reinterpret_cast<LPBYTE>(&bootSt), &sz);
    RegCloseKey(hk);
    if (r == ERROR_SUCCESS) {
      if (bootSt == 1 || bootSt == 2) return "Encrypted (BitLocker)";
      return "Unencrypted";
    }
  }
  return "Unencrypted";
}

inline std::string collectVolumesJson() {
  wchar_t drives[512]{};
  DWORD len = GetLogicalDriveStringsW(511, drives);
  std::string out = "[";
  bool first = true;
  if (len > 0 && len < 512) {
    for (const wchar_t* p = drives; *p; p += wcslen(p) + 1) {
      if (GetDriveTypeW(p) != DRIVE_FIXED) continue;
      ULARGE_INTEGER avail{}, total{}, freeB{};
      if (!GetDiskFreeSpaceExW(p, &avail, &total, &freeB) || total.QuadPart == 0) continue;
      wchar_t volLabel[128]{};
      wchar_t fsName[64]{};
      GetVolumeInformationW(p, volLabel, 127, nullptr, nullptr, nullptr, fsName, 63);
      double totalGb = std::round((static_cast<double>(total.QuadPart) / (1024.0 * 1024.0 * 1024.0)) * 100.0) / 100.0;
      double freeGb = std::round((static_cast<double>(avail.QuadPart) / (1024.0 * 1024.0 * 1024.0)) * 100.0) / 100.0;
      double usedPct = totalGb > 0.0 ? std::round(((totalGb - freeGb) / totalGb) * 1000.0) / 10.0 : 0.0;
      std::string mount = wideToUtf8(std::wstring(p));
      if (!mount.empty() && mount.back() == '\\') mount.pop_back();
      if (!first) out += ",";
      first = false;
      out += "{\"mount\":\"" + jsonEscape(mount) + "\","
             "\"label\":\"" + jsonEscape(wideToUtf8(std::wstring(volLabel))) + "\","
             "\"filesystem\":\"" + jsonEscape(wideToUtf8(std::wstring(fsName))) + "\","
             "\"totalGb\":" + fmtDouble(totalGb) + ","
             "\"freeGb\":" + fmtDouble(freeGb) + ","
             "\"usedPct\":" + fmtDouble(usedPct) + "}";
    }
  }
  out += "]";
  return out;
}

inline std::string collectNetworkAdaptersJson(std::string& outPrimaryIp, std::string& outPrimaryMac) {
  outPrimaryIp = getPrimaryIpv4AndMac(outPrimaryMac);
  std::string out = "[";
  ULONG sz = 16384;
  std::vector<uint8_t> buf(sz);
  DWORD ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &sz);
  if (ret == ERROR_BUFFER_OVERFLOW) {
    buf.resize(sz);
    ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &sz);
  }
  bool first = true;
  if (ret == NO_ERROR) {
    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()); a != nullptr; a = a->Next) {
      if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
      std::string ipv4;
      for (auto* ua = a->FirstUnicastAddress; ua != nullptr; ua = ua->Next) {
        if (ua->Address.lpSockaddr && ua->Address.lpSockaddr->sa_family == AF_INET) {
          char ipStr[64]{};
          auto* sin = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
          if (InetNtopA(AF_INET, &sin->sin_addr, ipStr, sizeof(ipStr))) {
            std::string ip(ipStr);
            if (ip.rfind("127.", 0) == 0 || ip.rfind("169.254.", 0) == 0) continue;
            ipv4 = ip;
            break;
          }
        }
      }
      std::string mac;
      if (a->PhysicalAddressLength >= 6) {
        char macBuf[32];
        std::snprintf(macBuf, sizeof(macBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
            a->PhysicalAddress[0], a->PhysicalAddress[1], a->PhysicalAddress[2],
            a->PhysicalAddress[3], a->PhysicalAddress[4], a->PhysicalAddress[5]);
        mac = macBuf;
      }
      if (ipv4.empty() && mac.empty()) continue;
      std::string friendly = a->FriendlyName ? wideToUtf8(std::wstring(a->FriendlyName)) : "Adapter";
      if (!first) out += ",";
      first = false;
      out += "{\"name\":\"" + jsonEscape(friendly) + "\","
             "\"mac\":\"" + jsonEscape(mac) + "\","
             "\"ipv4\":\"" + jsonEscape(ipv4) + "\"}";
    }
  }
  out += "]";
  return out;
}

inline std::string regReadStringValue(HKEY hKey, const wchar_t* valName) {
  wchar_t buf[512]{};
  DWORD sz = sizeof(buf);
  DWORD ty = 0;
  if (RegQueryValueExW(hKey, valName, nullptr, &ty, reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS &&
      (ty == REG_SZ || ty == REG_EXPAND_SZ) && sz >= sizeof(wchar_t)) {
    buf[(sizeof(buf) / sizeof(wchar_t)) - 1] = L'\0';
    return trimAscii(wideToUtf8(std::wstring(buf)));
  }
  return "";
}

inline std::string collectInstalledSoftwareJson() {
  const REGSAM views[2] = {KEY_READ | KEY_WOW64_64KEY, KEY_READ | KEY_WOW64_32KEY};
  const HKEY roots[2] = {HKEY_LOCAL_MACHINE, HKEY_LOCAL_MACHINE};
  const wchar_t* subKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
  std::vector<std::string> seenNames;
  std::string out = "[";
  bool first = true;
  size_t count = 0;

  for (int v = 0; v < 2 && count < 300; v++) {
    HKEY hkParent = nullptr;
    if (RegOpenKeyExW(roots[v], subKey, 0, views[v], &hkParent) != ERROR_SUCCESS) continue;
    for (DWORD idx = 0; count < 300; idx++) {
      wchar_t keyName[256]{};
      DWORD keyLen = 255;
      if (RegEnumKeyExW(hkParent, idx, keyName, &keyLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
      HKEY hkItem = nullptr;
      if (RegOpenKeyExW(hkParent, keyName, 0, views[v], &hkItem) != ERROR_SUCCESS) continue;

      DWORD sysComp = 0, scSz = sizeof(sysComp), scTy = 0;
      bool skip = (RegQueryValueExW(hkItem, L"SystemComponent", nullptr, &scTy, reinterpret_cast<LPBYTE>(&sysComp), &scSz) == ERROR_SUCCESS && sysComp == 1);
      if (!skip && !regReadStringValue(hkItem, L"ParentKeyName").empty()) skip = true;

      std::string dispName = skip ? "" : regReadStringValue(hkItem, L"DisplayName");
      std::string dispVer = skip ? "" : regReadStringValue(hkItem, L"DisplayVersion");
      std::string publisher = skip ? "" : regReadStringValue(hkItem, L"Publisher");
      RegCloseKey(hkItem);

      if (dispName.empty()) continue;
      bool dup = false;
      for (const auto& s : seenNames) {
        if (_stricmp(s.c_str(), dispName.c_str()) == 0) {
          dup = true;
          break;
        }
      }
      if (dup) continue;
      seenNames.push_back(dispName);
      if (!first) out += ",";
      first = false;
      out += "{\"name\":\"" + jsonEscape(dispName) + "\","
             "\"version\":\"" + jsonEscape(dispVer.empty() ? "unknown" : dispVer) + "\","
             "\"publisher\":\"" + jsonEscape(publisher.empty() ? "Installed Application" : publisher) + "\"}";
      count++;
    }
    RegCloseKey(hkParent);
  }
  out += "]";
  return out;
}

struct TelemetrySampler {
  uint64_t prevIdle = 0;
  uint64_t prevKernel = 0;
  uint64_t prevUser = 0;
  uint64_t prevNetRx = 0;
  uint64_t prevNetTx = 0;
  uint64_t prevTick = 0;

  static uint64_t ftToU64(const FILETIME& ft) {
    return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
  }

  std::string sampleJson() {
    double cpuUsage = 0.0;
    FILETIME fIdle{}, fKern{}, fUser{};
    if (GetSystemTimes(&fIdle, &fKern, &fUser)) {
      uint64_t idle = ftToU64(fIdle), kern = ftToU64(fKern), usr = ftToU64(fUser);
      if (prevTick != 0 && (kern + usr) > (prevKernel + prevUser)) {
        uint64_t dTotal = (kern + usr) - (prevKernel + prevUser);
        uint64_t dIdle = idle >= prevIdle ? (idle - prevIdle) : 0;
        if (dTotal > 0 && dIdle <= dTotal) {
          cpuUsage = std::round(((static_cast<double>(dTotal - dIdle) / static_cast<double>(dTotal)) * 100.0) * 10.0) / 10.0;
        }
      }
      prevIdle = idle; prevKernel = kern; prevUser = usr;
    }

    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    double ramTotalGb = 0.0, ramUsedGb = 0.0;
    if (GlobalMemoryStatusEx(&ms)) {
      ramTotalGb = std::round((static_cast<double>(ms.ullTotalPhys) / (1024.0 * 1024.0 * 1024.0)) * 100.0) / 100.0;
      uint64_t used = ms.ullTotalPhys - ms.ullAvailPhys;
      ramUsedGb = std::round((static_cast<double>(used) / (1024.0 * 1024.0 * 1024.0)) * 100.0) / 100.0;
    }

    double diskFreeGb = 0.0, diskTotalGb = 0.0;
    ULARGE_INTEGER freeBytes{}, totalBytes{}, availBytes{};
    if (GetDiskFreeSpaceExW(L"C:\\", &availBytes, &totalBytes, &freeBytes)) {
      diskTotalGb = std::round((static_cast<double>(totalBytes.QuadPart) / (1024.0 * 1024.0 * 1024.0)) * 100.0) / 100.0;
      diskFreeGb = std::round((static_cast<double>(availBytes.QuadPart) / (1024.0 * 1024.0 * 1024.0)) * 100.0) / 100.0;
    }

    double rxMbps = 0.0, txMbps = 0.0;
    uint64_t nowTick = GetTickCount64();
    ULONG ifSz = 0;
    if (GetIfTable(nullptr, &ifSz, FALSE) == ERROR_INSUFFICIENT_BUFFER && ifSz > 0) {
      std::vector<uint8_t> ifBuf(ifSz);
      auto* tbl = reinterpret_cast<PMIB_IFTABLE>(ifBuf.data());
      if (GetIfTable(tbl, &ifSz, FALSE) == NO_ERROR) {
        uint64_t rxSum = 0, txSum = 0;
        for (DWORD i = 0; i < tbl->dwNumEntries; i++) {
          if (tbl->table[i].dwType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
          if (tbl->table[i].dwOperStatus != IF_OPER_STATUS_OPERATIONAL) continue;
          rxSum += tbl->table[i].dwInOctets;
          txSum += tbl->table[i].dwOutOctets;
        }
        if (prevTick != 0 && nowTick > prevTick) {
          double dt = static_cast<double>(nowTick - prevTick) / 1000.0;
          if (dt > 0.1) {
            if (rxSum >= prevNetRx) rxMbps = std::round((((rxSum - prevNetRx) * 8.0) / (dt * 1e6)) * 100.0) / 100.0;
            if (txSum >= prevNetTx) txMbps = std::round((((txSum - prevNetTx) * 8.0) / (dt * 1e6)) * 100.0) / 100.0;
          }
        }
        prevNetRx = rxSum; prevNetTx = txSum;
      }
    }
    prevTick = nowTick;

    uint64_t uptimeSeconds = nowTick / 1000ULL;
    std::string loggedInUser;
    DWORD sessId = WTSGetActiveConsoleSessionId();
    if (sessId != 0xFFFFFFFF) {
      LPWSTR pUser = nullptr;
      DWORD bytes = 0;
      if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessId, WTSUserName, &pUser, &bytes) && pUser) {
        loggedInUser = wideToUtf8(std::wstring(pUser));
        WTSFreeMemory(pUser);
      }
    }

    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    std::string sn = readSmbiosSerialNumber();

    std::string json = "{";
    json += "\"cpuUsage\":" + fmtDouble(cpuUsage) + ",";
    json += "\"ramUsedGb\":" + fmtDouble(ramUsedGb) + ",";
    json += "\"ramTotalGb\":" + fmtDouble(ramTotalGb) + ",";
    json += "\"diskFreeGb\":" + fmtDouble(diskFreeGb) + ",";
    json += "\"diskTotalGb\":" + fmtDouble(diskTotalGb) + ",";
    json += "\"netRxMbps\":" + fmtDouble(rxMbps) + ",";
    json += "\"netTxMbps\":" + fmtDouble(txMbps) + ",";
    json += "\"uptimeSeconds\":" + fmtUint64(uptimeSeconds) + ",";
    json += "\"loggedInUser\":\"" + jsonEscape(loggedInUser) + "\",";
    json += "\"hardwareDetails\":{";
    json += "\"cpu\":{\"logicalCores\":" + fmtInt(si.dwNumberOfProcessors) + "},";
    json += "\"system\":{\"serialNumber\":\"" + jsonEscape(sn) + "\"}";
    json += "}}";
    return json;
  }
};

inline bool disableLocalUserAccount(const std::wstring& username) {
  if (username.empty()) return false;
  PUSER_INFO_1 info = nullptr;
  if (NetUserGetInfo(nullptr, username.c_str(), 1, reinterpret_cast<LPBYTE*>(&info)) != NERR_Success || !info) {
    return false;
  }
  DWORD newFlags = info->usri1_flags | UF_ACCOUNTDISABLE;
  NetApiBufferFree(info);
  USER_INFO_1008 uf{};
  uf.usri1008_flags = newFlags;
  return NetUserSetInfo(nullptr, username.c_str(), 1008, reinterpret_cast<LPBYTE>(&uf), nullptr) == NERR_Success;
}

inline bool removeLocalUserAccount(const std::wstring& username) {
  if (username.empty()) return false;
  return NetUserDel(nullptr, username.c_str()) == NERR_Success;
}

inline bool regKeyExistsHklm(const wchar_t* subKey) {
  HKEY hk = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &hk) == ERROR_SUCCESS) {
    RegCloseKey(hk);
    return true;
  }
  return false;
}

inline bool isDefenderRealtimeActive() {
  HKEY hk = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", 0, KEY_READ | KEY_WOW64_64KEY, &hk) == ERROR_SUCCESS) {
    DWORD val = 0, sz = sizeof(val), ty = 0;
    LONG r = RegQueryValueExW(hk, L"DisableRealtimeMonitoring", nullptr, &ty, reinterpret_cast<LPBYTE>(&val), &sz);
    RegCloseKey(hk);
    if (r == ERROR_SUCCESS && val == 1) return false;
    return true;
  }
  return true;
}

// ============================================================================
// Device Role / Form-Factor & Hypervisor Detection
// ============================================================================
inline std::string getSmbiosChassisLabel(uint8_t chassisType) {
  switch (chassisType) {
    case 3: return "Desktop";
    case 4: return "Low Profile Desktop";
    case 5: return "Pizza Box";
    case 6: return "Mini Tower";
    case 7: return "Tower";
    case 8: return "Portable";
    case 9: return "Laptop";
    case 10: return "Notebook";
    case 11: return "Hand Held";
    case 12: return "Docking Station";
    case 13: return "All-in-One";
    case 14: return "Sub Notebook";
    case 15: return "Space-saving";
    case 16: return "Lunch Box";
    case 17: return "Main Server Chassis";
    case 23: return "Rack Mount Chassis";
    case 24: return "Sealed-case PC";
    case 25: return "Multi-system Chassis";
    case 28: return "Blade";
    case 29: return "Blade Enclosure";
    case 30: return "Tablet";
    case 31: return "Convertible";
    case 32: return "Detachable";
    case 33: return "IoT Gateway";
    case 34: return "Embedded PC";
    case 35: return "Mini PC";
    case 36: return "Stick PC";
    default: return "";
  }
}

inline void queryCpuid(uint32_t leaf, uint32_t subleaf, uint32_t& eax, uint32_t& ebx, uint32_t& ecx, uint32_t& edx) {
#if defined(__x86_64__)
  uint32_t a = 0, b = 0, c = 0, d = 0;
  __asm__ __volatile__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(leaf), "c"(subleaf));
  eax = a;
  ebx = b;
  ecx = c;
  edx = d;
#else
  eax = 0;
  ebx = 0;
  ecx = 0;
  edx = 0;
#endif
}

struct WindowsFormFactor {
  uint8_t chassisType = 0;
  std::string chassisLabel;
  bool hasBattery = false;
  std::string osProductType = "workstation";
  std::string hypervisorVendor;
  bool isVirtualMachine = false;
  bool isHypervisorHost = false;
  std::string inferredRole = "Workstation";
};

inline WindowsFormFactor collectWindowsFormFactor(const SmbiosInfo& smbios) {
  WindowsFormFactor ff;
  ff.chassisType = smbios.chassisType;
  ff.chassisLabel = getSmbiosChassisLabel(smbios.chassisType);

  SYSTEM_POWER_STATUS sps{};
  if (GetSystemPowerStatus(&sps)) {
    ff.hasBattery = (sps.BatteryFlag != 128 && sps.BatteryFlag != 255);
  }

  typedef LONG(WINAPI * RtlGetVersionFn)(OSVERSIONINFOEXW*);
  auto fnVer = reinterpret_cast<RtlGetVersionFn>(reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion")));
  if (fnVer) {
    OSVERSIONINFOEXW ov{};
    ov.dwOSVersionInfoSize = sizeof(ov);
    if (fnVer(&ov) == 0) {
      if (ov.wProductType == VER_NT_DOMAIN_CONTROLLER) ff.osProductType = "domain_controller";
      else if (ov.wProductType == VER_NT_SERVER) ff.osProductType = "server";
      else ff.osProductType = "workstation";
    }
  }

  uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
  queryCpuid(1, 0, eax, ebx, ecx, edx);
  bool cpuidHvBit = (ecx & (1u << 31)) != 0;
  if (cpuidHvBit) {
    queryCpuid(0x40000000u, 0, eax, ebx, ecx, edx);
    char raw[13]{};
    std::memcpy(raw + 0, &ebx, 4);
    std::memcpy(raw + 4, &ecx, 4);
    std::memcpy(raw + 8, &edx, 4);
    std::string hv;
    for (int i = 0; i < 12; i++) {
      unsigned char ch = static_cast<unsigned char>(raw[i]);
      if (ch >= 0x20 && ch <= 0x7E) hv.push_back(static_cast<char>(ch));
    }
    ff.hypervisorVendor = trimAscii(hv);
  }

  std::string mfg = toLowerAscii(smbios.manufacturer);
  std::string mdl = toLowerAscii(smbios.model);
  std::string mb = toLowerAscii(smbios.motherboardVendor + " " + smbios.motherboardName);
  std::string bios = toLowerAscii(smbios.biosVendor + " " + smbios.biosVersion);
  std::string hv = toLowerAscii(ff.hypervisorVendor);

  bool explicitNonMsHvCpuid =
      hv.find("kvm") != std::string::npos ||
      hv.find("vmware") != std::string::npos ||
      hv.find("vbox") != std::string::npos ||
      hv.find("xenvmm") != std::string::npos ||
      hv.find("tcgtcg") != std::string::npos ||
      hv.find("prl hyperv") != std::string::npos ||
      hv.find("bhyve") != std::string::npos ||
      hv.find("qnx") != std::string::npos;

  std::string dmi = mfg + " | " + mdl + " | " + mb + " | " + bios;
  bool dmiVm =
      mfg.find("qemu") != std::string::npos ||
      mdl.find("standard pc (q35") != std::string::npos ||
      mdl.find("standard pc (i440fx") != std::string::npos ||
      dmi.find("vmware") != std::string::npos ||
      dmi.find("virtualbox") != std::string::npos ||
      dmi.find("innotek") != std::string::npos ||
      dmi.find("virtual machine") != std::string::npos ||
      dmi.find("parallels") != std::string::npos ||
      dmi.find("bochs") != std::string::npos ||
      dmi.find("seabios") != std::string::npos ||
      dmi.find("ovmf") != std::string::npos ||
      dmi.find("proxmox") != std::string::npos ||
      dmi.find("ovirt") != std::string::npos ||
      dmi.find("openstack") != std::string::npos ||
      dmi.find("amazon ec2") != std::string::npos ||
      dmi.find("google compute") != std::string::npos ||
      dmi.find("digitalocean") != std::string::npos ||
      dmi.find("vultr") != std::string::npos ||
      dmi.find("nutanix") != std::string::npos ||
      dmi.find("bhyve") != std::string::npos ||
      (dmi.find("xen") != std::string::npos && (dmi.find("hvm") != std::string::npos || mfg.find("xen") != std::string::npos)) ||
      (mfg.find("red hat") != std::string::npos && mdl.find("kvm") != std::string::npos);

  ff.isVirtualMachine = explicitNonMsHvCpuid || dmiVm;
  ff.isHypervisorHost = (!ff.isVirtualMachine && ff.osProductType == "server" &&
      regKeyExistsHklm(L"SYSTEM\\CurrentControlSet\\Services\\vmms"));

  bool mobileChassis = (ff.chassisType == 8 || ff.chassisType == 9 || ff.chassisType == 10 ||
      ff.chassisType == 11 || ff.chassisType == 14 || ff.chassisType == 30 ||
      ff.chassisType == 31 || ff.chassisType == 32);
  bool serverChassis = (ff.chassisType == 17 || ff.chassisType == 23 || ff.chassisType == 25 ||
      ff.chassisType == 28 || ff.chassisType == 29);
  bool desktopChassis = (ff.chassisType == 3 || ff.chassisType == 4 || ff.chassisType == 5 ||
      ff.chassisType == 6 || ff.chassisType == 7 || ff.chassisType == 13 ||
      ff.chassisType == 15 || ff.chassisType == 16 || ff.chassisType == 24 ||
      ff.chassisType == 34 || ff.chassisType == 35 || ff.chassisType == 36);

  if (ff.osProductType == "domain_controller") {
    ff.inferredRole = "Domain Controller";
  } else if (ff.isHypervisorHost) {
    ff.inferredRole = "Hypervisor";
  } else if (ff.isVirtualMachine) {
    ff.inferredRole = (ff.osProductType == "server" || serverChassis) ? "Virtual Server" : "Virtual Machine";
  } else if (ff.osProductType == "server" || serverChassis) {
    ff.inferredRole = "Server";
  } else if (mobileChassis) {
    ff.inferredRole = "Laptop";
  } else if (desktopChassis) {
    ff.inferredRole = "Desktop";
  } else if (ff.hasBattery) {
    ff.inferredRole = "Laptop";
  } else {
    ff.inferredRole = "Desktop";
  }
  return ff;
}

// ============================================================================
// Native Win32 Light / Dark Theme Engine (Zero Non-OS Static Imports)
// ============================================================================
struct WinThemePalette {
  bool isDark = true;
  COLORREF bg = 0;
  COLORREF surface = 0;
  COLORREF border = 0;
  COLORREF text = 0;
  COLORREF muted = 0;
  COLORREF accent = 0;
  COLORREF accentHover = 0;
  COLORREF accentText = 0;
  COLORREF btnBg = 0;
  COLORREF btnHover = 0;
  COLORREF btnBorder = 0;
  COLORREF btnText = 0;
  COLORREF menuBg = 0;
  COLORREF menuHover = 0;
  COLORREF menuSep = 0;
  COLORREF inputBg = 0;
  COLORREF progressTrack = 0;
  COLORREF progressFill = 0;
  COLORREF danger = 0;
  COLORREF dangerHover = 0;
};

inline bool readWindowsSystemUsesDarkTheme() {
  HKEY hk = nullptr;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
    DWORD val = 1;
    DWORD sz = sizeof(val);
    DWORD ty = 0;
    LONG r = RegQueryValueExW(hk, L"AppsUseLightTheme", nullptr, &ty, reinterpret_cast<LPBYTE>(&val), &sz);
    RegCloseKey(hk);
    if (r == ERROR_SUCCESS && ty == REG_DWORD) {
      return val == 0;
    }
  }
  return false;
}

inline bool resolveUseDarkTheme(const std::string& themeMode) {
  std::string m = toLowerAscii(trimAscii(themeMode));
  if (m == "dark") return true;
  if (m == "light") return false;
  return readWindowsSystemUsesDarkTheme();
}

inline bool isThemeSettingChange(LPARAM lp) {
  if (lp == 0) return true;
  const wchar_t* s = reinterpret_cast<const wchar_t*>(lp);
  return _wcsicmp(s, L"ImmersiveColorSet") == 0 || _wcsicmp(s, L"WindowsThemeElement") == 0;
}

inline WinThemePalette getWinThemePalette(bool isDark) {
  WinThemePalette p{};
  p.isDark = isDark;
  if (isDark) {
    p.bg = RGB(15, 23, 42);
    p.surface = RGB(30, 41, 59);
    p.border = RGB(51, 65, 85);
    p.text = RGB(241, 245, 249);
    p.muted = RGB(148, 163, 184);
    p.accent = RGB(14, 165, 233);
    p.accentHover = RGB(56, 189, 248);
    p.accentText = RGB(255, 255, 255);
    p.btnBg = RGB(30, 41, 59);
    p.btnHover = RGB(51, 65, 85);
    p.btnBorder = RGB(71, 85, 105);
    p.btnText = RGB(241, 245, 249);
    p.menuBg = RGB(24, 33, 50);
    p.menuHover = RGB(38, 52, 77);
    p.menuSep = RGB(51, 65, 85);
    p.inputBg = RGB(15, 23, 42);
    p.progressTrack = RGB(30, 41, 59);
    p.progressFill = RGB(14, 165, 233);
    p.danger = RGB(220, 38, 38);
    p.dangerHover = RGB(239, 68, 68);
  } else {
    p.bg = RGB(248, 250, 252);
    p.surface = RGB(255, 255, 255);
    p.border = RGB(203, 213, 225);
    p.text = RGB(15, 23, 42);
    p.muted = RGB(71, 85, 105);
    p.accent = RGB(2, 132, 199);
    p.accentHover = RGB(3, 105, 161);
    p.accentText = RGB(255, 255, 255);
    p.btnBg = RGB(241, 245, 249);
    p.btnHover = RGB(226, 232, 240);
    p.btnBorder = RGB(203, 213, 225);
    p.btnText = RGB(15, 23, 42);
    p.menuBg = RGB(255, 255, 255);
    p.menuHover = RGB(226, 232, 240);
    p.menuSep = RGB(226, 232, 240);
    p.inputBg = RGB(255, 255, 255);
    p.progressTrack = RGB(226, 232, 240);
    p.progressFill = RGB(2, 132, 199);
    p.danger = RGB(220, 38, 38);
    p.dangerHover = RGB(185, 28, 28);
  }
  return p;
}

inline void applyWindowTitleBarTheme(HWND hWnd, bool isDark) {
  if (!hWnd || !IsWindow(hWnd)) return;
  typedef HRESULT(WINAPI * DwmSetWindowAttributeFn)(HWND, DWORD, LPCVOID, DWORD);
  static HMODULE s_dwm = nullptr;
  static DwmSetWindowAttributeFn s_fn = nullptr;
  if (!s_dwm) {
    s_dwm = LoadLibraryW(L"dwmapi.dll");
    if (s_dwm) {
      s_fn = reinterpret_cast<DwmSetWindowAttributeFn>(reinterpret_cast<void*>(GetProcAddress(s_dwm, "DwmSetWindowAttribute")));
    }
  }
  if (s_fn) {
    BOOL darkVal = isDark ? TRUE : FALSE;
    HRESULT hr = s_fn(hWnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &darkVal, sizeof(darkVal));
    if (FAILED(hr)) {
      s_fn(hWnd, 19, &darkVal, sizeof(darkVal));
    }
  }
  SetWindowPos(hWnd, nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
  RedrawWindow(hWnd, nullptr, nullptr, RDW_FRAME | RDW_INVALIDATE | RDW_UPDATENOW);
}

inline void drawThemedButton(const DRAWITEMSTRUCT* dis, const WinThemePalette& pal, bool primary, bool danger = false) {
  if (!dis || !dis->hDC) return;
  HDC hdc = dis->hDC;
  RECT rc = dis->rcItem;
  bool disabled = (dis->itemState & ODS_DISABLED) != 0;
  bool selected = (dis->itemState & ODS_SELECTED) != 0;
  bool focused = (dis->itemState & ODS_FOCUS) != 0;

  COLORREF fill = pal.btnBg;
  COLORREF border = pal.btnBorder;
  COLORREF fg = pal.btnText;
  if (danger) {
    fill = selected ? pal.dangerHover : pal.danger;
    border = fill;
    fg = pal.accentText;
  } else if (primary) {
    if (disabled) {
      fill = pal.surface;
      border = pal.border;
      fg = pal.muted;
    } else {
      fill = selected ? pal.accentHover : pal.accent;
      border = fill;
      fg = pal.accentText;
    }
  } else {
    if (disabled) {
      fill = pal.surface;
      border = pal.border;
      fg = pal.muted;
    } else if (selected) {
      fill = pal.btnHover;
    }
  }

  HBRUSH bgFill = CreateSolidBrush(pal.bg);
  FillRect(hdc, &rc, bgFill);
  DeleteObject(bgFill);

  HBRUSH br = CreateSolidBrush(fill);
  HPEN pen = CreatePen(PS_SOLID, 1, focused && !disabled ? pal.accentHover : border);
  HGDIOBJ oldBr = SelectObject(hdc, br);
  HGDIOBJ oldPen = SelectObject(hdc, pen);
  RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 8, 8);
  SelectObject(hdc, oldBr);
  SelectObject(hdc, oldPen);
  DeleteObject(br);
  DeleteObject(pen);

  wchar_t textBuf[128]{};
  GetWindowTextW(dis->hwndItem, textBuf, 127);
  SetBkMode(hdc, TRANSPARENT);
  SetTextColor(hdc, fg);
  RECT textRc = rc;
  if (selected && !disabled) {
    OffsetRect(&textRc, 0, 1);
  }
  DrawTextW(hdc, textBuf, -1, &textRc, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
}

inline void drawThemedProgressBar(HDC hdc, const RECT& rc, int pct, const WinThemePalette& pal) {
  int clamped = std::max(0, std::min(100, pct));
  HBRUSH trackBr = CreateSolidBrush(pal.progressTrack);
  HPEN borderPen = CreatePen(PS_SOLID, 1, pal.border);
  HGDIOBJ oldBr = SelectObject(hdc, trackBr);
  HGDIOBJ oldPen = SelectObject(hdc, borderPen);
  RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 8, 8);
  SelectObject(hdc, oldBr);
  SelectObject(hdc, oldPen);
  DeleteObject(trackBr);
  DeleteObject(borderPen);

  int innerW = (rc.right - rc.left) - 4;
  int fillW = (innerW * clamped) / 100;
  if (fillW > 0) {
    RECT fillRc{rc.left + 2, rc.top + 2, rc.left + 2 + fillW, rc.bottom - 2};
    HBRUSH fillBr = CreateSolidBrush(pal.progressFill);
    HPEN nullPen = CreatePen(PS_NULL, 0, 0);
    oldBr = SelectObject(hdc, fillBr);
    oldPen = SelectObject(hdc, nullPen);
    RoundRect(hdc, fillRc.left, fillRc.top, fillRc.right, fillRc.bottom, 6, 6);
    SelectObject(hdc, oldBr);
    SelectObject(hdc, oldPen);
    DeleteObject(fillBr);
    DeleteObject(nullPen);
  }
}

inline std::string collectCheckinPayloadJson(const std::string& deviceId, TelemetrySampler& sampler, bool includeFullInventory = true) {
  std::string base = sampler.sampleJson();
  JsonVal parsed;
  if (!parseJson(base, parsed)) return "{}";
  double cpuUsage = parsed.get("cpuUsage") ? parsed.get("cpuUsage")->numVal : 0.0;
  double ramUsedGb = parsed.get("ramUsedGb") ? parsed.get("ramUsedGb")->numVal : 0.0;
  double ramTotalGb = parsed.get("ramTotalGb") ? parsed.get("ramTotalGb")->numVal : 0.0;
  double diskFreeGb = parsed.get("diskFreeGb") ? parsed.get("diskFreeGb")->numVal : 0.0;
  double diskTotalGb = parsed.get("diskTotalGb") ? parsed.get("diskTotalGb")->numVal : 0.0;
  double rxMbps = parsed.get("netRxMbps") ? parsed.get("netRxMbps")->numVal : 0.0;
  double txMbps = parsed.get("netTxMbps") ? parsed.get("netTxMbps")->numVal : 0.0;
  uint64_t upSec = static_cast<uint64_t>(parsed.getInt("uptimeSeconds", 0));
  std::string luser = parsed.getStr("loggedInUser", "");

  int ramPct = ramTotalGb > 0.0 ? static_cast<int>(std::round((ramUsedGb / ramTotalGb) * 100.0)) : 0;
  int diskPct = diskTotalGb > 0.0 ? static_cast<int>(std::round(((diskTotalGb - diskFreeGb) / diskTotalGb) * 100.0)) : 0;
  bool rebootPending =
      regKeyExistsHklm(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending") ||
      regKeyExistsHklm(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired");
  std::string edrState = isDefenderRealtimeActive() ? "Healthy" : "Warning";
  std::string bitlockerState = readBitLockerStatusStr();

  std::string primaryIp, primaryMac;
  std::string adaptersJson = collectNetworkAdaptersJson(primaryIp, primaryMac);

  SmbiosInfo smbios = readSmbiosInfo();
  WindowsFormFactor ff = collectWindowsFormFactor(smbios);
  std::string cpuModel;
  uint32_t cpuMhz = 0;
  readCpuRegistryInfo(cpuModel, cpuMhz);
  SYSTEM_INFO si{};
  GetNativeSystemInfo(&si);

  std::string dimmsJson = "[";
  for (size_t i = 0; i < smbios.modules.size(); i++) {
    const auto& m = smbios.modules[i];
    if (i > 0) dimmsJson += ",";
    dimmsJson += "{\"slot\":\"" + jsonEscape(m.slot) + "\","
                 "\"capacityGb\":" + fmtDouble(m.capacityGb) + ","
                 "\"speedMhz\":" + fmtInt(m.speedMhz) + ","
                 "\"manufacturer\":\"" + jsonEscape(m.manufacturer) + "\","
                 "\"partNumber\":\"" + jsonEscape(m.partNumber) + "\"}";
  }
  dimmsJson += "]";
  std::string volumesJson = collectVolumesJson();

  // Native ARP neighbor table via GetIpNetTable
  std::string arp = "[";
  ULONG tblSz = 0;
  if (GetIpNetTable(nullptr, &tblSz, FALSE) == ERROR_INSUFFICIENT_BUFFER && tblSz > 0) {
    std::vector<uint8_t> netBuf(tblSz);
    auto* nt = reinterpret_cast<PMIB_IPNETTABLE>(netBuf.data());
    if (GetIpNetTable(nt, &tblSz, FALSE) == NO_ERROR) {
      int added = 0;
      for (DWORD i = 0; i < nt->dwNumEntries && added < 64; i++) {
        if (nt->table[i].dwPhysAddrLen != 6) continue;
        bool allZero = true;
        for (DWORD b = 0; b < 6; b++) if (nt->table[i].bPhysAddr[b] != 0) { allZero = false; break; }
        if (allZero) continue;
        IN_ADDR ia{};
        ia.S_un.S_addr = nt->table[i].dwAddr;
        char ipStr[32]{};
        if (!InetNtopA(AF_INET, &ia, ipStr, sizeof(ipStr))) continue;
        std::string ip(ipStr);
        if (ip.rfind("127.", 0) == 0 || ip.rfind("169.254.", 0) == 0 || ip.rfind("224.", 0) == 0 || ip == "255.255.255.255") continue;
        char macBuf[24];
        std::snprintf(macBuf, sizeof(macBuf), "%02x:%02x:%02x:%02x:%02x:%02x",
            nt->table[i].bPhysAddr[0], nt->table[i].bPhysAddr[1], nt->table[i].bPhysAddr[2],
            nt->table[i].bPhysAddr[3], nt->table[i].bPhysAddr[4], nt->table[i].bPhysAddr[5]);
        if (added > 0) arp += ",";
        arp += "{\"ip\":\"" + jsonEscape(ip) + "\",\"mac\":\"" + macBuf + "\"}";
        added++;
      }
    }
  }
  arp += "]";

  std::string osVer = getWindowsVersionCaption();
  std::string out = "{";
  out += "\"deviceId\":\"" + jsonEscape(deviceId) + "\",";
  out += "\"companionVersion\":\"2.7.0\",";
  out += "\"hostname\":\"" + jsonEscape(getHostnameStr()) + "\",";
  out += "\"osType\":\"windows\",";
  out += "\"osVersion\":\"" + jsonEscape(osVer) + "\",";
  out += "\"deviceRole\":\"" + jsonEscape(ff.inferredRole) + "\",";
  out += "\"ipAddress\":\"" + jsonEscape(primaryIp) + "\",";
  out += "\"macAddress\":\"" + jsonEscape(primaryMac) + "\",";
  out += "\"serialNumber\":\"" + jsonEscape(smbios.serialNumber) + "\",";
  out += "\"cpuUsage\":" + fmtDouble(cpuUsage) + ",";
  out += "\"ramUsage\":" + fmtInt(ramPct) + ",";
  out += "\"ramUsedGb\":" + fmtDouble(ramUsedGb) + ",";
  out += "\"ramTotalGb\":" + fmtDouble(ramTotalGb) + ",";
  out += "\"diskUsage\":" + fmtInt(diskPct) + ",";
  out += "\"diskFreeGb\":" + fmtDouble(diskFreeGb) + ",";
  out += "\"diskTotalGb\":" + fmtDouble(diskTotalGb) + ",";
  out += "\"netRxMbps\":" + fmtDouble(rxMbps) + ",";
  out += "\"netTxMbps\":" + fmtDouble(txMbps) + ",";
  out += "\"uptimeSeconds\":" + fmtUint64(upSec) + ",";
  out += "\"loggedInUser\":\"" + jsonEscape(luser) + "\",";
  out += std::string("\"rebootPending\":") + (rebootPending ? "true" : "false") + ",";
  out += std::string("\"rebootRequired\":") + (rebootPending ? "true" : "false") + ",";
  out += "\"avStatus\":\"" + edrState + "\",";
  out += "\"edrStatus\":\"" + edrState + "\",";
  out += "\"bitlockerStatus\":\"" + jsonEscape(bitlockerState) + "\",";
  out += "\"arpNeighbors\":" + arp + ",";
  out += "\"hardwareDetails\":{";
  out += "\"system\":{\"manufacturer\":\"" + jsonEscape(smbios.manufacturer) + "\","
         "\"model\":\"" + jsonEscape(smbios.model) + "\","
         "\"serialNumber\":\"" + jsonEscape(smbios.serialNumber) + "\","
         "\"uuid\":\"" + jsonEscape(smbios.uuid) + "\","
         "\"motherboardVendor\":\"" + jsonEscape(smbios.motherboardVendor) + "\","
         "\"motherboardName\":\"" + jsonEscape(smbios.motherboardName) + "\","
         "\"motherboardSerial\":\"" + jsonEscape(smbios.motherboardSerial) + "\","
         "\"biosVendor\":\"" + jsonEscape(smbios.biosVendor) + "\","
         "\"biosVersion\":\"" + jsonEscape(smbios.biosVersion) + "\","
         "\"biosDate\":\"" + jsonEscape(smbios.biosDate) + "\","
         "\"chassisType\":" + fmtInt(ff.chassisType) + ","
         "\"chassisLabel\":\"" + jsonEscape(ff.chassisLabel) + "\","
         "\"hasBattery\":" + std::string(ff.hasBattery ? "true" : "false") + ","
         "\"isVirtualMachine\":" + std::string(ff.isVirtualMachine ? "true" : "false") + ","
         "\"isHypervisorHost\":" + std::string(ff.isHypervisorHost ? "true" : "false") + ","
         "\"hypervisorVendor\":\"" + jsonEscape(ff.hypervisorVendor) + "\","
         "\"osProductType\":\"" + jsonEscape(ff.osProductType) + "\"},";
  out += "\"cpu\":{\"model\":\"" + jsonEscape(cpuModel) + "\","
         "\"logicalCores\":" + fmtInt(si.dwNumberOfProcessors) + ","
         "\"maxClockMhz\":" + fmtInt(cpuMhz) + ","
         "\"usagePct\":" + fmtDouble(cpuUsage) + "},";
  out += "\"memory\":{\"totalGb\":" + fmtDouble(ramTotalGb) + ","
         "\"usedGb\":" + fmtDouble(ramUsedGb) + ","
         "\"modules\":" + dimmsJson + "},";
  out += "\"storage\":{\"totalGb\":" + fmtDouble(diskTotalGb) + ","
         "\"freeGb\":" + fmtDouble(diskFreeGb) + ","
         "\"encryptionStatus\":\"" + jsonEscape(bitlockerState) + "\","
         "\"volumes\":" + volumesJson + "},";
  out += "\"network\":{\"primaryIp\":\"" + jsonEscape(primaryIp) + "\","
         "\"primaryMac\":\"" + jsonEscape(primaryMac) + "\","
         "\"netRxMbps\":" + fmtDouble(rxMbps) + ","
         "\"netTxMbps\":" + fmtDouble(txMbps) + ","
         "\"adapters\":" + adaptersJson + "},";
  out += "\"os\":{\"osType\":\"windows\",\"osVersion\":\"" + jsonEscape(osVer) + "\",\"uptimeSeconds\":" + fmtUint64(upSec) + "}";
  out += "}";
  if (includeFullInventory) {
    out += ",\"installedSoftware\":" + collectInstalledSoftwareJson();
  }
  out += "}";
  return out;
}

}  // namespace vitrine
