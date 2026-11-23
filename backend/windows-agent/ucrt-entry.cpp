#include <windows.h>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <new>

extern "C" int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmdLine, int nCmdShow);

typedef void (__cdecl* InitFn)(void);
extern "C" {
__attribute__((section(".ctors"), used)) InitFn __vitrine_ctors_begin[1] = { reinterpret_cast<InitFn>(static_cast<uintptr_t>(-1)) };
extern InitFn __vitrine_ctors_end[];
__attribute__((section(".CRT$XCA"), used)) InitFn __vitrine_crt_xca[1] = { nullptr };
__attribute__((section(".CRT$XCZ"), used)) InitFn __vitrine_crt_xcz[1] = { nullptr };
}

static void runGlobalConstructors() {
  for (InitFn* p = __vitrine_crt_xca + 1; p < __vitrine_crt_xcz; ++p) {
    if (*p) (*p)();
  }
  for (InitFn* p = __vitrine_ctors_end; p > __vitrine_ctors_begin + 1; ) {
    --p;
    if (*p && reinterpret_cast<uintptr_t>(*p) != ~static_cast<uintptr_t>(0)) {
      (*p)();
    }
  }
}

namespace std {
void __throw_bad_alloc() { ExitProcess(1); }
void __throw_bad_array_new_length() { ExitProcess(1); }
void __throw_length_error(const char*) { ExitProcess(1); }
void __throw_logic_error(const char*) { ExitProcess(1); }
void __throw_out_of_range(const char*) { ExitProcess(1); }
void __throw_out_of_range_fmt(const char*, ...) { ExitProcess(1); }
void __throw_runtime_error(const char*) { ExitProcess(1); }
void __throw_invalid_argument(const char*) { ExitProcess(1); }
}

void* operator new(std::size_t n) {
  if (n == 0) n = 1;
  void* p = HeapAlloc(GetProcessHeap(), 0, n);
  if (!p) ExitProcess(1);
  return p;
}
void* operator new[](std::size_t n) { return ::operator new(n); }
void* operator new(std::size_t n, const std::nothrow_t&) noexcept {
  if (n == 0) n = 1;
  return HeapAlloc(GetProcessHeap(), 0, n);
}
void* operator new[](std::size_t n, const std::nothrow_t&) noexcept {
  if (n == 0) n = 1;
  return HeapAlloc(GetProcessHeap(), 0, n);
}
void operator delete(void* p) noexcept { if (p) HeapFree(GetProcessHeap(), 0, p); }
void operator delete[](void* p) noexcept { if (p) HeapFree(GetProcessHeap(), 0, p); }
void operator delete(void* p, std::size_t) noexcept { if (p) HeapFree(GetProcessHeap(), 0, p); }
void operator delete[](void* p, std::size_t) noexcept { if (p) HeapFree(GetProcessHeap(), 0, p); }

extern "C" {
// Unreachable exception landing-pad stubs for -fno-exceptions builds against prebuilt libstdc++.a;
// operator new and std::__throw_* call ExitProcess(1) so no C++ exception is ever thrown.
void _Unwind_Resume(void*) { ExitProcess(1); }
int __gxx_personality_seh0(void*, void*, void*, void*) { return 1; }
void* __cxa_begin_catch(void*) { ExitProcess(1); }
void __cxa_end_catch() { ExitProcess(1); }
void __cxa_rethrow() { ExitProcess(1); }
void __cxa_throw(void*, void*, void (*)(void*)) { ExitProcess(1); }

// Bind directly to UCRT imports rather than MinGW inline wrappers to avoid infinite recursion.
extern int (__cdecl* __imp___stdio_common_vsprintf)(unsigned long long, char*, std::size_t, const char*, void*, va_list);
extern double (__cdecl* __imp_strtod)(const char*, char**);

int __cdecl __mingw_vsnprintf(char* s, std::size_t n, const char* fmt, va_list ap) {
  constexpr unsigned long long kStdSnprintf = 2ULL;  // _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR
  if (!s || n == 0) {
    return __imp___stdio_common_vsprintf(kStdSnprintf, nullptr, 0, fmt, nullptr, ap);
  }
  int r = __imp___stdio_common_vsprintf(kStdSnprintf, s, n, fmt, nullptr, ap);
  if (r < 0) s[0] = '\0';
  else if (static_cast<std::size_t>(r) >= n) s[n - 1] = '\0';
  return r;
}

int __cdecl __mingw_snprintf(char* s, std::size_t n, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int r = __mingw_vsnprintf(s, n, fmt, ap);
  va_end(ap);
  return r;
}

double __cdecl __mingw_strtod(const char* nptr, char** endptr) {
  return __imp_strtod(nptr, endptr);
}

int __cxa_guard_acquire(long long* g) {
  volatile LONG* flag = reinterpret_cast<volatile LONG*>(g);
  for (;;) {
    LONG val = InterlockedCompareExchange(flag, 2, 0);
    if (val == 0) return 1;
    if (val == 1) return 0;
    SwitchToThread();
  }
}
void __cxa_guard_release(long long* g) { InterlockedExchange(reinterpret_cast<volatile LONG*>(g), 1); }
void __cxa_guard_abort(long long* g) { InterlockedExchange(reinterpret_cast<volatile LONG*>(g), 0); }
void __cxa_pure_virtual() { ExitProcess(1); }
int atexit(void (__cdecl*)(void)) { return 0; }

void WINAPI wWinMainCRTStartup() {
  runGlobalConstructors();
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  GetStartupInfoW(&si);
  int showCmd = (si.dwFlags & STARTF_USESHOWWINDOW) ? si.wShowWindow : SW_SHOWDEFAULT;
  LPWSTR cmdLine = GetCommandLineW();
  if (cmdLine) {
    bool inQuote = false;
    while (*cmdLine) {
      if (*cmdLine == L'"') inQuote = !inQuote;
      else if (!inQuote && (*cmdLine == L' ' || *cmdLine == L'\t')) break;
      cmdLine++;
    }
    while (*cmdLine == L' ' || *cmdLine == L'\t') cmdLine++;
  }
  int rc = wWinMain(GetModuleHandleW(nullptr), nullptr, cmdLine ? cmdLine : const_cast<LPWSTR>(L""), showCmd);
  ExitProcess(static_cast<UINT>(rc));
}
}

