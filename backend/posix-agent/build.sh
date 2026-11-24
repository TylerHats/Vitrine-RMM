#!/usr/bin/env bash
# ==============================================================================
# Vitrine RMM Combined POSIX Native Agent Builder (Linux Desktop, Headless, macOS)
# Compiles dependency-free C++17 binaries into backend/dist/posix-agents/
# using runtime dlopen() for OpenSSL/WSS with zero -lssl build requirement.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$BACKEND_DIR/dist/posix-agents"
SRC="$SCRIPT_DIR/vitrine-posix-agent.cpp"

mkdir -p "$OUT_DIR"

HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"

pick_cxx() {
  for cand in clang++ g++ c++; do
    if command -v "$cand" >/dev/null 2>&1; then
      echo "$cand"
      return 0
    fi
  done
  return 1
}

CXX_BIN="$(pick_cxx || true)"
if [ -z "$CXX_BIN" ]; then
  echo "[!] WARNING: No C++17 compiler (g++/clang++) found; skipping POSIX native agent build." >&2
  exit 0
fi

if [ "$HOST_OS" = "Linux" ]; then
  COMMON_FLAGS=(-std=c++17 -O2 -Wall -Wextra -Wno-unused-result -I"$SCRIPT_DIR" -pthread -ldl)
  ARCH_TAG="x86_64"
  if [ "$HOST_ARCH" = "aarch64" ] || [ "$HOST_ARCH" = "arm64" ]; then
    ARCH_TAG="arm64"
  fi

  echo "[*] Building Linux Desktop native agent ($CXX_BIN) -> vitrine-agent-linux-$ARCH_TAG"
  "$CXX_BIN" "${COMMON_FLAGS[@]}" "$SRC" -o "$OUT_DIR/vitrine-agent-linux-$ARCH_TAG"

  echo "[*] Building Linux Headless Server native agent ($CXX_BIN) -> vitrine-agent-linux-headless-$ARCH_TAG"
  "$CXX_BIN" "${COMMON_FLAGS[@]}" -DVITRINE_HEADLESS_ONLY "$SRC" -o "$OUT_DIR/vitrine-agent-linux-headless-$ARCH_TAG"

  if [ "$ARCH_TAG" = "x86_64" ] && command -v aarch64-linux-gnu-g++ >/dev/null 2>&1; then
    echo "[*] Cross-compiling Linux ARM64 native agents..."
    aarch64-linux-gnu-g++ "${COMMON_FLAGS[@]}" "$SRC" -o "$OUT_DIR/vitrine-agent-linux-arm64"
    aarch64-linux-gnu-g++ "${COMMON_FLAGS[@]}" -DVITRINE_HEADLESS_ONLY "$SRC" -o "$OUT_DIR/vitrine-agent-linux-headless-arm64"
  elif [ "$ARCH_TAG" = "arm64" ] && command -v x86_64-linux-gnu-g++ >/dev/null 2>&1; then
    echo "[*] Cross-compiling Linux x86_64 native agents..."
    x86_64-linux-gnu-g++ "${COMMON_FLAGS[@]}" "$SRC" -o "$OUT_DIR/vitrine-agent-linux-x86_64"
    x86_64-linux-gnu-g++ "${COMMON_FLAGS[@]}" -DVITRINE_HEADLESS_ONLY "$SRC" -o "$OUT_DIR/vitrine-agent-linux-headless-x86_64"
  fi

  MAC_UNIVERSAL_OUT="$OUT_DIR/vitrine-agent-macos-universal"
  PREBUILT_MAC="$SCRIPT_DIR/prebuilt/vitrine-agent-macos-universal"
  OSX_LIPO="$(command -v lipo || command -v llvm-lipo || true)"
  if command -v oa64-clang++ >/dev/null 2>&1 && command -v o64-clang++ >/dev/null 2>&1 && [ -n "$OSX_LIPO" ]; then
    echo "[*] Cross-compiling macOS Universal native agent via osxcross..."
    MAC_FLAGS=(-std=c++17 -O2 -Wall -Wextra -Wno-unused-result -I"$SCRIPT_DIR" -pthread -ldl)
    oa64-clang++ "${MAC_FLAGS[@]}" "$SRC" -o "$OUT_DIR/.mac-arm64.tmp"
    o64-clang++ "${MAC_FLAGS[@]}" "$SRC" -o "$OUT_DIR/.mac-x86_64.tmp"
    "$OSX_LIPO" -create "$OUT_DIR/.mac-arm64.tmp" "$OUT_DIR/.mac-x86_64.tmp" -output "$MAC_UNIVERSAL_OUT"
    rm -f "$OUT_DIR/.mac-arm64.tmp" "$OUT_DIR/.mac-x86_64.tmp"
    chmod 755 "$MAC_UNIVERSAL_OUT"
  elif [ -f "$PREBUILT_MAC" ]; then
    echo "[*] Copying prebuilt macOS Universal native agent -> $MAC_UNIVERSAL_OUT"
    cp "$PREBUILT_MAC" "$MAC_UNIVERSAL_OUT"
    chmod 755 "$MAC_UNIVERSAL_OUT"
  else
    echo "[*] Skipping macOS Universal native build on Linux (requires Xcode SDK via osxcross or prebuilt $PREBUILT_MAC)."
  fi
elif [ "$HOST_OS" = "Darwin" ]; then
  COMMON_FLAGS=(-std=c++17 -O2 -Wall -Wextra -I"$SCRIPT_DIR" -pthread -ldl)
  echo "[*] Building macOS Universal native agent -> vitrine-agent-macos-universal"
  if "$CXX_BIN" "${COMMON_FLAGS[@]}" -arch arm64 -arch x86_64 "$SRC" -o "$OUT_DIR/vitrine-agent-macos-universal" 2>/dev/null; then
    true
  else
    "$CXX_BIN" "${COMMON_FLAGS[@]}" "$SRC" -o "$OUT_DIR/vitrine-agent-macos-universal"
  fi
else
  echo "[*] POSIX agent builder skipped on unsupported host OS: $HOST_OS"
fi

ls -lh "$OUT_DIR" || true

