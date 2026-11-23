typedef void (__cdecl* InitFn)(void);
extern "C" {
__attribute__((section(".ctors"), used)) InitFn __vitrine_ctors_end[1] = { nullptr };
}

