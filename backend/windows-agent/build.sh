#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$BACKEND_DIR/.." && pwd)"
OUT_DIR="$BACKEND_DIR/dist/windows-agents"

mkdir -p "$OUT_DIR"

CXX=""
WINDRES=""
for c in x86_64-w64-mingw32-g++-win32 x86_64-w64-mingw32-g++; do
  if command -v "$c" >/dev/null 2>&1; then
    CXX="$c"
    break
  fi
done
if command -v x86_64-w64-mingw32-windres >/dev/null 2>&1; then
  WINDRES="x86_64-w64-mingw32-windres"
fi

if [ -z "$CXX" ] || [ -z "$WINDRES" ]; then
  echo "[!] WARNING: x86_64-w64-mingw32 toolchain not found; skipping native Windows PE template build." >&2
  exit 1
fi

# Generate compact (~15 KB) multi-size 16/32/48 uncompressed RGBA default brand .ico
LOGO_SRC="$ROOT_DIR/branding/logo.png"
if [ ! -f "$LOGO_SRC" ]; then
  LOGO_SRC="$ROOT_DIR/frontend/public/logo.png"
fi
ICO_OUT="$SCRIPT_DIR/vitrine-default.ico"
trap 'rm -f "$ICO_OUT"' EXIT
ICON_PROC_JS="$BACKEND_DIR/dist/services/agent/iconProcessor.js"
if [ -f "$LOGO_SRC" ] && [ -f "$ICON_PROC_JS" ]; then
  node --input-type=module -e '
    import fs from "node:fs";
    import { pathToFileURL } from "node:url";
    const { imageBufferToMultiSizeIco } = await import(pathToFileURL(process.argv[3]).href);
    const png = fs.readFileSync(process.argv[1]);
    const ico = imageBufferToMultiSizeIco(png);
    if (!ico) throw new Error("Failed to convert branding PNG to multi-size ICO");
    fs.writeFileSync(process.argv[2], ico);
  ' "$LOGO_SRC" "$ICO_OUT" "$ICON_PROC_JS"
else
  # Minimal valid 16x16 32-bit RGBA fallback ICO if no PNG or compiled processor exists
  node --input-type=module -e '
    import fs from "node:fs";
    const w = 16, h = 16;
    const dib = Buffer.alloc(40 + w * h * 4 + w * h / 8, 0);
    dib.writeUInt32LE(40, 0);
    dib.writeInt32LE(w, 4);
    dib.writeInt32LE(h * 2, 8);
    dib.writeUInt16LE(1, 12);
    dib.writeUInt16LE(32, 14);
    const hdr = Buffer.alloc(22);
    hdr.writeUInt16LE(1, 2);
    hdr.writeUInt16LE(1, 4);
    hdr.writeUInt8(w, 6);
    hdr.writeUInt8(h, 7);
    hdr.writeUInt16LE(1, 10);
    hdr.writeUInt16LE(32, 12);
    hdr.writeUInt32LE(dib.length, 14);
    hdr.writeUInt32LE(22, 18);
    fs.writeFileSync(process.argv[1], Buffer.concat([hdr, dib]));
  ' "$ICO_OUT"
fi

COMMON_FLAGS=()
USE_LLVM_UCRT=0
LIBSTDCXX=""
LIBGCC=""
LIBUCRTBASE=""

if command -v clang++ >/dev/null 2>&1 && command -v ld.lld >/dev/null 2>&1; then
  LIBSTDCXX="$("$CXX" -print-file-name=libstdc++.a 2>/dev/null || true)"
  LIBGCC="$("$CXX" -print-file-name=libgcc.a 2>/dev/null || true)"
  LIBUCRTBASE="$("$CXX" -print-file-name=libucrtbase.a 2>/dev/null || true)"
  if [ -n "$LIBSTDCXX" ] && [ -f "$LIBSTDCXX" ] && \
     [ -n "$LIBGCC" ] && [ -f "$LIBGCC" ] && \
     [ -n "$LIBUCRTBASE" ] && [ -f "$LIBUCRTBASE" ]; then
    USE_LLVM_UCRT=1
  fi
fi

if [ "$USE_LLVM_UCRT" -eq 1 ]; then
  echo "[INFO] Using Clang + LLD + UCRT 6-section PE pipeline"
  MINGW_SYSROOT_FLAGS=()
  LIB_DIR="$(cd "$(dirname "$LIBUCRTBASE")" && pwd)"
  MINGW_SYSROOT_FLAGS+=(-L"$LIB_DIR")
  while IFS= read -r inc_dir; do
    inc_dir="$(printf '%s' "$inc_dir" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    if [ -n "$inc_dir" ] && [ -d "$inc_dir" ]; then
      case "$inc_dir" in
        *include/c++*)
          MINGW_SYSROOT_FLAGS+=(-isystem "$inc_dir")
          ;;
        *x86_64-w64-mingw32/include)
          MINGW_SYSROOT_FLAGS+=(-idirafter "$inc_dir")
          ;;
      esac
    fi
  done < <("$CXX" -E -Wp,-v -x c++ /dev/null 2>&1 | sed -n '/#include <\.\.\.> search starts here:/,/End of search list\./p' | grep '^ ' || true)

  COMMON_FLAGS=(
    --target=x86_64-w64-mingw32
    -fuse-ld=lld
    -O2
    -s
    -std=c++17
    -fno-exceptions
    -fno-rtti
    -ffunction-sections
    -fdata-sections
    -DUNICODE
    -D_UNICODE
    -D_UCRT
    -D_UCRT_VERSION=0x0E00
    -D__USE_MINGW_ANSI_STDIO=0
    -Wall
    -Wextra
    -Wno-unused-parameter
    -nostdlib
    -Wl,--subsystem,windows
    -Wl,-e,wWinMainCRTStartup
    -Wl,--gc-sections
    -Wl,--nxcompat
    -Wl,--dynamicbase
    -Wl,--high-entropy-va
    -Wl,--tsaware
    "${MINGW_SYSROOT_FLAGS[@]}"
  )
else
  echo "[!] WARNING: clang++ / ld.lld or static MinGW UCRT archives not found; falling back to g++ (11-section msvcrt build). Install 'clang lld' for 6-section UCRT builds." >&2
  COMMON_FLAGS=(
    -O2
    -s
    -std=c++17
    -fno-exceptions
    -fno-rtti
    -ffunction-sections
    -fdata-sections
    -DUNICODE
    -D_UNICODE
    -municode
    -Wall
    -Wextra
    -Wno-unused-parameter
    -mwindows
    -static-libgcc
    -static-libstdc++
    -Wl,--gc-sections
    -Wl,--nxcompat
    -Wl,--dynamicbase
    -Wl,--high-entropy-va
    -Wl,--tsaware
  )
fi

build_target() {
  local name="$1"
  local cpp="$2"
  local rc="$3"
  shift 3
  local defs=()
  local libs=()
  for arg in "$@"; do
    case "$arg" in
      -D*) defs+=("$arg") ;;
      *) libs+=("$arg") ;;
    esac
  done
  local res_obj="$OUT_DIR/${name}.res.o"
  echo "--> Building Windows PE template: ${name}"
  (cd "$SCRIPT_DIR" && "$WINDRES" "$rc" -O coff -o "$res_obj")
  if [ "$USE_LLVM_UCRT" -eq 1 ]; then
    clang++ "${COMMON_FLAGS[@]}" "${defs[@]}" \
      -I"$SCRIPT_DIR" \
      "$SCRIPT_DIR/ucrt-entry.cpp" \
      "$SCRIPT_DIR/$cpp" \
      "$SCRIPT_DIR/ucrt-end.cpp" \
      "$res_obj" \
      -o "$OUT_DIR/$name" \
      "${libs[@]}" \
      "$LIBSTDCXX" \
      "$LIBGCC" \
      -lucrtbase \
      -lkernel32 \
      -luser32
  else
    "$CXX" "${COMMON_FLAGS[@]}" "${defs[@]}" \
      -I"$SCRIPT_DIR" "$SCRIPT_DIR/$cpp" "$res_obj" \
      -o "$OUT_DIR/$name" \
      "${libs[@]}"
  fi
  rm -f "$res_obj"
}

build_target "vitrine-companion-template.exe" "vitrine-companion.cpp" "vitrine-companion.rc" \
  -lwinhttp -lnetapi32 -ladvapi32 -liphlpapi -lws2_32 -lwtsapi32 -lshell32 -luser32

build_target "vitrine-tray-template.exe" "vitrine-tray.cpp" "vitrine-tray.rc" \
  -lwinhttp -ladvapi32 -liphlpapi -lws2_32 -lshell32 -luser32 -lgdi32 -lole32 -lgdiplus

build_target "vitrine-installer-template.exe" "vitrine-installer.cpp" "vitrine-installer.rc" \
  -lwinhttp -lwintrust -lcrypt32 -lnetapi32 -ladvapi32 -liphlpapi -lws2_32 -lcomctl32 -lshell32 -luser32 -lgdi32 -lbcrypt

build_target "vitrine-companion-setup-template.exe" "vitrine-installer.cpp" "vitrine-companion-setup.rc" \
  -DVITRINE_COMPANION_ONLY_DEFAULT -lwinhttp -lwintrust -lcrypt32 -lnetapi32 -ladvapi32 -liphlpapi -lws2_32 -lcomctl32 -lshell32 -luser32 -lgdi32 -lbcrypt

build_target "vitrine-quicksupport-template.exe" "vitrine-quicksupport.cpp" "vitrine-quicksupport.rc" \
  -lwinhttp -lwintrust -lcrypt32 -ladvapi32 -liphlpapi -lws2_32 -lcomctl32 -lshell32 -luser32 -lgdi32

echo "[OK] Built all 5 native Windows PE templates in $OUT_DIR"
