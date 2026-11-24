import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import zlib from 'zlib';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface LinuxPackageFile {
  /** Absolute POSIX path starting with '/' (e.g. '/opt/vitrineagent/vitrine-agent') */
  path: string;
  content: Buffer;
  mode: number;
}

export interface LinuxPackageSpec {
  format: 'deb' | 'rpm';
  arch: 'amd64' | 'arm64';
  packageName: string;
  version: string;
  release?: string;
  summary: string;
  description: string;
  maintainer?: string;
  url?: string;
  files: LinuxPackageFile[];
  directories: Array<{ path: string; mode: number }>;
  postinst: string;
  prerm: string;
  postrm: string;
}

/**
 * Generates a clean 128x128 RGBA fallback PNG icon when no custom logo is available.
 */
export function buildDefaultBrandPng(size = 128): Buffer {
  const buf = Buffer.alloc(size * size * 4, 0);
  const cx = (size - 1) / 2;
  const cy = (size - 1) / 2;
  const radius = size * 0.44;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const dx = x - cx;
      const dy = y - cy;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist > radius) continue;
      const nx = x / (size - 1);
      const ny = y / (size - 1);
      const leftV = Math.abs((nx - 0.24) - (ny - 0.24) * 0.5) < 0.095;
      const rightV = Math.abs((0.76 - nx) - (ny - 0.24) * 0.5) < 0.095;
      const inV = ny >= 0.26 && ny <= 0.78 && (leftV || rightV);
      const idx = (y * size + x) * 4;
      if (inV) {
        buf[idx] = 0;
        buf[idx + 1] = 242;
        buf[idx + 2] = 254;
        buf[idx + 3] = 255;
      } else {
        buf[idx] = 15;
        buf[idx + 1] = 23;
        buf[idx + 2] = 42;
        buf[idx + 3] = 245;
      }
    }
  }
  const stride = size * 4;
  const raw = Buffer.alloc(size * (stride + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (stride + 1)] = 0;
    buf.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const chunk = (tag: string, data: Buffer) => {
    const t = Buffer.from(tag, 'ascii');
    const len = Buffer.allocUnsafe(4);
    len.writeUInt32BE(data.length, 0);
    const body = Buffer.concat([t, data]);
    const crcBuf = Buffer.allocUnsafe(4);
    crcBuf.writeUInt32BE(crc32(body), 0);
    return Buffer.concat([len, body, crcBuf]);
  };
  const ihdr = Buffer.allocUnsafe(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0))
  ]);
}

const CRC_TABLE = (() => {
  const tbl = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    tbl[n] = c >>> 0;
  }
  return tbl;
})();

function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

export function resolveCompiledPosixBinary(
  target: 'linux-desktop' | 'linux-headless' | 'macos',
  arch: 'amd64' | 'arm64' | 'universal' = 'amd64'
): Buffer | null {
  const archSuffix = target === 'macos' ? 'universal' : arch === 'arm64' ? 'arm64' : 'x86_64';
  const filename =
    target === 'macos'
      ? 'vitrine-agent-macos-universal'
      : target === 'linux-headless'
        ? `vitrine-agent-linux-headless-${archSuffix}`
        : `vitrine-agent-linux-${archSuffix}`;

  const candidates = [
    path.resolve(__dirname, '../../posix-agents', filename),
    path.resolve(__dirname, '../../../dist/posix-agents', filename),
    path.resolve(process.cwd(), 'dist/posix-agents', filename),
    path.resolve(process.cwd(), 'backend/dist/posix-agents', filename)
  ];
  const found = candidates.find((p) => fs.existsSync(p) && fs.statSync(p).isFile());
  if (!found) return null;
  try {
    return fs.readFileSync(found);
  } catch {
    return null;
  }
}

export function buildLinuxInstallConfirmPy(): string {
  return [
    '#!/usr/bin/env python3',
    'import json, os, shutil, subprocess, sys',
    '',
    'BASE_DIR = os.path.dirname(os.path.abspath(__file__))',
    'CONFIRM_PATH = os.path.join(BASE_DIR, "install-confirm.json")',
    'ICON_PATH = os.path.join(BASE_DIR, "brand-icon.png")',
    '',
    'def load_info():',
    '    try:',
    '        with open(CONFIRM_PATH, "r", encoding="utf-8") as f:',
    '            return json.load(f)',
    '    except Exception:',
    '        return {}',
    '',
    'def main():',
    '    if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):',
    '        return 0',
    '    info = load_info()',
    '    brand = str(info.get("brandName") or "Vitrine RMM")',
    '    tenant = str(info.get("tenantName") or "")',
    '    host = str(info.get("hostname") or "")',
    '    enrolled = bool(info.get("enrolled", True))',
    '    theme = str(info.get("themeMode") or "system").lower()',
    '    msg = str(info.get("message") or ("The endpoint agent has been installed and enrolled successfully." if enrolled else "The endpoint agent package was installed."))',
    '    details = []',
    '    if host:',
    '        details.append(f"Device: {host}")',
    '    if tenant:',
    '        details.append(f"Organization: {tenant}")',
    '    details.append("Service: Active & Connected")',
    '    detail_txt = "\\n".join(details)',
    '    try:',
    '        import gi',
    '        gi.require_version("Gtk", "3.0")',
    '        from gi.repository import Gtk, Gdk, GdkPixbuf, GLib',
    '        dark = theme == "dark"',
    '        if theme == "system" and shutil.which("gsettings"):',
    '            try:',
    '                cs = subprocess.check_output(["gsettings", "get", "org.gnome.desktop.interface", "color-scheme"], text=True, timeout=1.5).lower()',
    '                if "prefer-dark" in cs:',
    '                    dark = True',
    '            except Exception:',
    '                pass',
    '        css = Gtk.CssProvider()',
    '        bg = "#0F172A" if dark else "#F8FAFC"',
    '        surf = "#1E293B" if dark else "#FFFFFF"',
    '        fg = "#F1F5F9" if dark else "#0F172A"',
    '        muted = "#94A3B8" if dark else "#475569"',
    '        border = "#334155" if dark else "#CBD5E1"',
    '        accent = "#0EA5E9" if dark else "#0284C7"',
    '        css.load_from_data(f"""',
    '        .vc-win {{ background-color: {bg}; color: {fg}; }}',
    '        .vc-card {{ background-color: {surf}; border: 1px solid {border}; border-radius: 10px; padding: 14px; }}',
    '        .vc-title {{ font-size: 16px; font-weight: 700; color: {fg}; }}',
    '        .vc-muted {{ font-size: 12px; color: {muted}; }}',
    '        .vc-btn {{ background-image: none; background-color: {accent}; color: #FFFFFF; border-radius: 7px; padding: 7px 18px; font-weight: 700; border: none; }}',
    '        """.encode("utf-8"))',
    '        Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)',
    '        win = Gtk.Window(title=f"{brand} — Installation Complete")',
    '        win.set_default_size(440, 235)',
    '        win.set_position(Gtk.WindowPosition.CENTER)',
    '        win.set_keep_above(True)',
    '        win.get_style_context().add_class("vc-win")',
    '        if os.path.exists(ICON_PATH):',
    '            try:',
    '                win.set_icon_from_file(ICON_PATH)',
    '            except Exception:',
    '                pass',
    '        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)',
    '        box.set_border_width(20)',
    '        hdr = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)',
    '        if os.path.exists(ICON_PATH):',
    '            try:',
    '                pb = GdkPixbuf.Pixbuf.new_from_file_at_scale(ICON_PATH, 42, 42, True)',
    '                hdr.pack_start(Gtk.Image.new_from_pixbuf(pb), False, False, 0)',
    '            except Exception:',
    '                pass',
    '        tbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)',
    '        l1 = Gtk.Label(label=f"{brand} Installed", xalign=0)',
    '        l1.get_style_context().add_class("vc-title")',
    '        l2 = Gtk.Label(label=msg, xalign=0)',
    '        l2.set_line_wrap(True)',
    '        l2.get_style_context().add_class("vc-muted")',
    '        tbox.pack_start(l1, False, False, 0)',
    '        tbox.pack_start(l2, False, False, 0)',
    '        hdr.pack_start(tbox, True, True, 0)',
    '        box.pack_start(hdr, False, False, 0)',
    '        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)',
    '        card.get_style_context().add_class("vc-card")',
    '        ld = Gtk.Label(label=detail_txt, xalign=0)',
    '        ld.set_selectable(True)',
    '        card.pack_start(ld, False, False, 0)',
    '        box.pack_start(card, True, True, 0)',
    '        brow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)',
    '        brow.set_halign(Gtk.Align.END)',
    '        btn = Gtk.Button(label="Done")',
    '        btn.get_style_context().add_class("vc-btn")',
    '        btn.connect("clicked", lambda _w: Gtk.main_quit())',
    '        brow.pack_start(btn, False, False, 0)',
    '        box.pack_start(brow, False, False, 0)',
    '        win.add(box)',
    '        win.connect("delete-event", lambda _w, _e: (Gtk.main_quit(), True)[1])',
    '        GLib.timeout_add_seconds(90, lambda: (Gtk.main_quit(), False)[1])',
    '        win.show_all()',
    '        btn.grab_focus()',
    '        Gtk.main()',
    '        return 0',
    '    except Exception:',
    '        pass',
    '    full_msg = f"{brand} Agent Installed\\n\\n{msg}\\n\\n{detail_txt}"',
    '    if shutil.which("zenity"):',
    '        subprocess.Popen(["zenity", "--info", "--title", f"{brand} — Installation Complete", "--text", full_msg, "--width=380"])',
    '    elif shutil.which("kdialog"):',
    '        subprocess.Popen(["kdialog", "--title", f"{brand} — Installation Complete", "--msgbox", full_msg])',
    '    return 0',
    '',
    'if __name__ == "__main__":',
    '    sys.exit(main())'
  ].join('\n');
}

// ============================================================================
// Pure-Node USTAR Tarball + AR (.deb) Builder
// ============================================================================
function writeTarOctal(buf: Buffer, offset: number, width: number, val: number): void {
  const str = val.toString(8).padStart(width - 1, '0') + '\0';
  buf.write(str.slice(0, width), offset, 'ascii');
}

function buildTarHeader(name: string, mode: number, size: number, typeflag: '0' | '5', mtime: number): Buffer {
  const hdr = Buffer.alloc(512, 0);
  const nameBuf = Buffer.from(name, 'utf8');
  if (nameBuf.length <= 100) {
    nameBuf.copy(hdr, 0);
  } else {
    // Split into prefix (155) and name (100) at '/'
    const clean = name;
    const splitIdx = clean.lastIndexOf('/', 154);
    if (splitIdx > 0 && clean.length - splitIdx - 1 <= 100) {
      hdr.write(clean.slice(0, splitIdx), 345, 155, 'utf8');
      hdr.write(clean.slice(splitIdx + 1), 0, 100, 'utf8');
    } else {
      nameBuf.copy(hdr, 0, 0, 100);
    }
  }
  writeTarOctal(hdr, 100, 8, mode & 0o7777);
  writeTarOctal(hdr, 108, 8, 0);
  writeTarOctal(hdr, 116, 8, 0);
  writeTarOctal(hdr, 124, 12, size);
  writeTarOctal(hdr, 136, 12, mtime);
  hdr.fill(0x20, 148, 156); // spaces for checksum computation
  hdr.write(typeflag, 156, 'ascii');
  hdr.write('ustar\0', 257, 'ascii');
  hdr.write('00', 263, 'ascii');
  hdr.write('root', 265, 'ascii');
  hdr.write('root', 297, 'ascii');

  let sum = 0;
  for (let i = 0; i < 512; i++) sum += hdr[i];
  const chkStr = sum.toString(8).padStart(6, '0') + '\0 ';
  hdr.write(chkStr, 148, 8, 'ascii');
  return hdr;
}

function buildUstarTarGz(
  entries: Array<{ name: string; mode: number; content?: Buffer; isDir?: boolean }>,
  mtime: number
): Buffer {
  const blocks: Buffer[] = [];
  for (const e of entries) {
    const cleanName = e.name.startsWith('./') ? e.name : `./${e.name.replace(/^\/+/, '')}`;
    if (e.isDir) {
      const dirName = cleanName.endsWith('/') ? cleanName : `${cleanName}/`;
      blocks.push(buildTarHeader(dirName, e.mode, 0, '5', mtime));
    } else {
      const content = e.content || Buffer.alloc(0);
      blocks.push(buildTarHeader(cleanName, e.mode, content.length, '0', mtime));
      if (content.length > 0) {
        blocks.push(content);
        const rem = content.length % 512;
        if (rem !== 0) blocks.push(Buffer.alloc(512 - rem, 0));
      }
    }
  }
  blocks.push(Buffer.alloc(1024, 0)); // EOF marker
  return zlib.gzipSync(Buffer.concat(blocks), { level: 9 });
}

function buildArMember(name: string, data: Buffer, mtime: number): Buffer {
  const hdr = Buffer.alloc(60, 0x20);
  const arName = name.endsWith('/') ? name : `${name}/`;
  hdr.write(arName.slice(0, 16), 0, 'ascii');
  hdr.write(String(mtime).slice(0, 12), 16, 'ascii');
  hdr.write('0', 28, 'ascii');
  hdr.write('0', 34, 'ascii');
  hdr.write('100644', 40, 'ascii');
  hdr.write(String(data.length).slice(0, 10), 48, 'ascii');
  hdr[58] = 0x60;
  hdr[59] = 0x0a;
  const pad = data.length % 2 === 1 ? Buffer.from([0x0a]) : Buffer.alloc(0);
  return Buffer.concat([hdr, data, pad]);
}

export function buildDebianPackage(spec: LinuxPackageSpec): Buffer {
  const mtime = Math.floor(Date.now() / 1000);
  const debArch = spec.arch === 'arm64' ? 'arm64' : 'amd64';
  const installedBytes = spec.files.reduce((acc, f) => acc + f.content.length, 0);
  const installedKb = Math.max(64, Math.ceil(installedBytes / 1024));

  const controlText = [
    `Package: ${spec.packageName}`,
    `Version: ${spec.version}`,
    `Section: admin`,
    `Priority: optional`,
    `Architecture: ${debArch}`,
    `Installed-Size: ${installedKb}`,
    `Depends: python3, systemd | bash`,
    `Maintainer: ${spec.maintainer || 'Vitrine RMM <support@vitrine.local>'}`,
    ...(spec.url ? [`Homepage: ${spec.url}`] : []),
    `Description: ${spec.summary}`,
    ` ${spec.description.replace(/\r?\n/g, '\n ')}`
  ].join('\n') + '\n';

  const controlTarGz = buildUstarTarGz(
    [
      { name: 'control', mode: 0o644, content: Buffer.from(controlText, 'utf8') },
      { name: 'postinst', mode: 0o755, content: Buffer.from(spec.postinst, 'utf8') },
      { name: 'prerm', mode: 0o755, content: Buffer.from(spec.prerm, 'utf8') },
      { name: 'postrm', mode: 0o755, content: Buffer.from(spec.postrm, 'utf8') }
    ],
    mtime
  );

  const dataEntries: Array<{ name: string; mode: number; content?: Buffer; isDir?: boolean }> = [];
  for (const dir of spec.directories) {
    dataEntries.push({ name: dir.path.replace(/^\/+/, ''), mode: dir.mode, isDir: true });
  }
  for (const file of spec.files) {
    dataEntries.push({ name: file.path.replace(/^\/+/, ''), mode: file.mode, content: file.content });
  }
  const dataTarGz = buildUstarTarGz(dataEntries, mtime);

  return Buffer.concat([
    Buffer.from('!<arch>\n', 'ascii'),
    buildArMember('debian-binary', Buffer.from('2.0\n', 'ascii'), mtime),
    buildArMember('control.tar.gz', controlTarGz, mtime),
    buildArMember('data.tar.gz', dataTarGz, mtime)
  ]);
}

// ============================================================================
// Pure-Node RPM v3.0 (.rpm) Builder (Lead + Signature Header + Main Header + Gzipped newc CPIO)
// ============================================================================
interface RpmHeaderTag {
  tag: number;
  type: 2 | 3 | 4 | 6 | 7 | 8 | 9; // CHAR=2, INT16=3, INT32=4, STRING=6, BIN=7, STRING_ARRAY=8, I18NSTRING=9
  value: number | number[] | string | string[] | Buffer;
}

function encodeRpmHeader(tags: RpmHeaderTag[], padTo8Bytes = false): Buffer {
  const sorted = [...tags].sort((a, b) => a.tag - b.tag);
  const indexBufs: Buffer[] = [];
  const dataChunks: Buffer[] = [];
  let dataLen = 0;

  const pushAligned = (align: number) => {
    if (align <= 1) return;
    const rem = dataLen % align;
    if (rem !== 0) {
      const pad = align - rem;
      dataChunks.push(Buffer.alloc(pad, 0));
      dataLen += pad;
    }
  };

  for (const item of sorted) {
    let count = 1;
    let payload: Buffer;

    if (item.type === 3) {
      pushAligned(2);
      const arr = Array.isArray(item.value) ? (item.value as number[]) : [Number(item.value)];
      count = arr.length;
      payload = Buffer.allocUnsafe(count * 2);
      for (let i = 0; i < count; i++) payload.writeUInt16BE(arr[i] & 0xffff, i * 2);
    } else if (item.type === 4) {
      pushAligned(4);
      const arr = Array.isArray(item.value) ? (item.value as number[]) : [Number(item.value)];
      count = arr.length;
      payload = Buffer.allocUnsafe(count * 4);
      for (let i = 0; i < count; i++) payload.writeUInt32BE(arr[i] >>> 0, i * 4);
    } else if (item.type === 7) {
      payload = Buffer.isBuffer(item.value) ? item.value : Buffer.from(String(item.value), 'utf8');
      count = payload.length;
    } else if (item.type === 8) {
      const arr = Array.isArray(item.value) ? (item.value as string[]) : [String(item.value)];
      count = arr.length;
      payload = Buffer.concat(arr.map((s) => Buffer.from(`${s}\0`, 'utf8')));
    } else if (item.type === 2) {
      const arr = Array.isArray(item.value) ? (item.value as number[]) : [Number(item.value)];
      count = arr.length;
      payload = Buffer.from(arr);
    } else {
      // STRING (6) or I18NSTRING (9)
      count = 1;
      payload = Buffer.from(`${String(item.value)}\0`, 'utf8');
    }

    const idx = Buffer.allocUnsafe(16);
    idx.writeUInt32BE(item.tag, 0);
    idx.writeUInt32BE(item.type, 4);
    idx.writeUInt32BE(dataLen, 8);
    idx.writeUInt32BE(count, 12);
    indexBufs.push(idx);

    dataChunks.push(payload);
    dataLen += payload.length;
  }

  const intro = Buffer.allocUnsafe(16);
  intro.set([0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00], 0);
  intro.writeUInt32BE(sorted.length, 8);
  intro.writeUInt32BE(dataLen, 12);

  const raw = Buffer.concat([intro, ...indexBufs, ...dataChunks]);
  if (!padTo8Bytes) return raw;
  const rem = raw.length % 8;
  return rem === 0 ? raw : Buffer.concat([raw, Buffer.alloc(8 - rem, 0)]);
}

function buildCpioNewcEntry(relPath: string, mode: number, mtime: number, inode: number, content: Buffer, isDir: boolean): Buffer {
  const cleanName = relPath.startsWith('./') ? relPath : `./${relPath.replace(/^\/+/, '')}`;
  const nameBuf = Buffer.from(`${cleanName}\0`, 'utf8');
  const fileMode = isDir ? 0o040000 | (mode & 0o7777) : 0o100000 | (mode & 0o7777);
  const nlink = isDir ? 2 : 1;
  const fsize = isDir ? 0 : content.length;

  const h8 = (n: number) => (n >>> 0).toString(16).padStart(8, '0');
  const hdrStr =
    '070701' +
    h8(inode) +
    h8(fileMode) +
    h8(0) +
    h8(0) +
    h8(nlink) +
    h8(mtime) +
    h8(fsize) +
    h8(0) +
    h8(0) +
    h8(0) +
    h8(0) +
    h8(nameBuf.length) +
    h8(0);

  const hdrPlusName = Buffer.concat([Buffer.from(hdrStr, 'ascii'), nameBuf]);
  const nameRem = hdrPlusName.length % 4;
  const namePad = nameRem === 0 ? Buffer.alloc(0) : Buffer.alloc(4 - nameRem, 0);

  if (fsize === 0) {
    return Buffer.concat([hdrPlusName, namePad]);
  }
  const fileRem = fsize % 4;
  const filePad = fileRem === 0 ? Buffer.alloc(0) : Buffer.alloc(4 - fileRem, 0);
  return Buffer.concat([hdrPlusName, namePad, content, filePad]);
}

export function buildRpmPackage(spec: LinuxPackageSpec): Buffer {
  const mtime = Math.floor(Date.now() / 1000);
  const rpmArch = spec.arch === 'arm64' ? 'aarch64' : 'x86_64';
  const rpmArchNum = spec.arch === 'arm64' ? 19 : 1;
  const release = spec.release || '1';
  const nevra = `${spec.packageName}-${spec.version}-${release}.${rpmArch}`;

  // Build CPIO payload (directories + files + TRAILER!!!)
  const cpioParts: Buffer[] = [];
  let inode = 1;

  const dirnamesMap = new Map<string, number>();
  const dirnames: string[] = [];
  const getDirIdx = (dirWithSlash: string) => {
    const existing = dirnamesMap.get(dirWithSlash);
    if (existing !== undefined) return existing;
    const idx = dirnames.length;
    dirnames.push(dirWithSlash);
    dirnamesMap.set(dirWithSlash, idx);
    return idx;
  };

  const basenames: string[] = [];
  const dirindexes: number[] = [];
  const filesizes: number[] = [];
  const filemodes: number[] = [];
  const filerdevs: number[] = [];
  const filemtimes: number[] = [];
  const filedigests: string[] = [];
  const filelinktos: string[] = [];
  const fileflags: number[] = [];
  const fileusernames: string[] = [];
  const filegroupnames: string[] = [];

  for (const d of spec.directories) {
    const absPath = d.path.startsWith('/') ? d.path : `/${d.path}`;
    cpioParts.push(buildCpioNewcEntry(absPath, d.mode, mtime, inode++, Buffer.alloc(0), true));
  }

  let totalFileBytes = 0;
  const sortedFiles = [...spec.files].sort((a, b) => a.path.localeCompare(b.path));
  for (const f of sortedFiles) {
    const absPath = f.path.startsWith('/') ? f.path : `/${f.path}`;
    const lastSlash = absPath.lastIndexOf('/');
    const dirPart = lastSlash <= 0 ? '/' : `${absPath.slice(0, lastSlash)}/`;
    const basePart = absPath.slice(lastSlash + 1);
    const sha256 = crypto.createHash('sha256').update(f.content).digest('hex');

    cpioParts.push(buildCpioNewcEntry(absPath, f.mode, mtime, inode++, f.content, false));

    totalFileBytes += f.content.length;
    basenames.push(basePart);
    dirindexes.push(getDirIdx(dirPart));
    filesizes.push(f.content.length);
    filemodes.push(0o100000 | (f.mode & 0o7777));
    filerdevs.push(0);
    filemtimes.push(mtime);
    filedigests.push(sha256);
    filelinktos.push('');
    fileflags.push(0);
    fileusernames.push('root');
    filegroupnames.push('root');
  }

  // CPIO Trailer
  const trailerName = Buffer.from('TRAILER!!!\0', 'ascii');
  const trailerHdr = Buffer.from(
    '070701' +
      '00000000'.repeat(4) +
      '00000001' +
      '00000000'.repeat(6) +
      trailerName.length.toString(16).padStart(8, '0') +
      '00000000',
    'ascii'
  );
  const trailerEntry = Buffer.concat([trailerHdr, trailerName]);
  const tRem = trailerEntry.length % 4;
  cpioParts.push(tRem === 0 ? trailerEntry : Buffer.concat([trailerEntry, Buffer.alloc(4 - tRem, 0)]));

  const cpioRaw = Buffer.concat(cpioParts);
  const payloadGz = zlib.gzipSync(cpioRaw, { level: 9 });

  const mainHeaderTags: RpmHeaderTag[] = [
    { tag: 100, type: 8, value: ['C'] }, // HEADERI18NTABLE
    { tag: 1000, type: 6, value: spec.packageName },
    { tag: 1001, type: 6, value: spec.version },
    { tag: 1002, type: 6, value: release },
    { tag: 1004, type: 9, value: spec.summary },
    { tag: 1005, type: 9, value: spec.description },
    { tag: 1006, type: 4, value: mtime },
    { tag: 1007, type: 6, value: 'vitrine-builder' },
    { tag: 1009, type: 4, value: totalFileBytes },
    { tag: 1014, type: 6, value: 'Commercial / Proprietary' },
    { tag: 1016, type: 9, value: 'System Environment/Daemons' },
    { tag: 1021, type: 6, value: 'linux' },
    { tag: 1022, type: 6, value: rpmArch },
    { tag: 1024, type: 6, value: spec.postinst },
    { tag: 1025, type: 6, value: spec.prerm },
    { tag: 1026, type: 6, value: spec.postrm },
    { tag: 1028, type: 4, value: filesizes },
    { tag: 1030, type: 3, value: filemodes },
    { tag: 1033, type: 3, value: filerdevs },
    { tag: 1034, type: 4, value: filemtimes },
    { tag: 1035, type: 8, value: filedigests },
    { tag: 1036, type: 8, value: filelinktos },
    { tag: 1037, type: 4, value: fileflags },
    { tag: 1039, type: 8, value: fileusernames },
    { tag: 1040, type: 8, value: filegroupnames },
    { tag: 1086, type: 6, value: '/bin/sh' },
    { tag: 1087, type: 6, value: '/bin/sh' },
    { tag: 1088, type: 6, value: '/bin/sh' },
    { tag: 1116, type: 4, value: dirindexes },
    { tag: 1117, type: 8, value: basenames },
    { tag: 1118, type: 8, value: dirnames },
    { tag: 1124, type: 6, value: 'cpio' },
    { tag: 1125, type: 6, value: 'gzip' },
    { tag: 1126, type: 6, value: '9' },
    { tag: 5011, type: 4, value: 8 } // RPMTAG_FILEDIGESTALGO = SHA256 (8)
  ];
  if (spec.url) {
    mainHeaderTags.push({ tag: 1020, type: 6, value: spec.url });
  }

  const mainHeaderBuf = encodeRpmHeader(mainHeaderTags, false);
  const headerAndPayload = Buffer.concat([mainHeaderBuf, payloadGz]);

  const headerSha1 = crypto.createHash('sha1').update(mainHeaderBuf).digest('hex');
  const fullMd5 = crypto.createHash('md5').update(headerAndPayload).digest();

  const sigHeaderBuf = encodeRpmHeader(
    [
      { tag: 269, type: 6, value: headerSha1 }, // RPMSIGTAG_SHA1
      { tag: 1000, type: 4, value: headerAndPayload.length }, // RPMSIGTAG_SIZE
      { tag: 1004, type: 7, value: fullMd5 }, // RPMSIGTAG_MD5
      { tag: 1007, type: 4, value: cpioRaw.length } // RPMSIGTAG_PAYLOADSIZE
    ],
    true
  );

  // 96-byte RPM v3 Lead
  const lead = Buffer.alloc(96, 0);
  lead[0] = 0xed;
  lead[1] = 0xab;
  lead[2] = 0xee;
  lead[3] = 0xdb;
  lead[4] = 3;
  lead[5] = 0;
  lead.writeUInt16BE(0, 6); // binary package
  lead.writeUInt16BE(rpmArchNum, 8);
  lead.write(nevra.slice(0, 65), 10, 'ascii');
  lead.writeUInt16BE(1, 76); // Linux OS
  lead.writeUInt16BE(5, 78); // RPMSIGTYPE_HEADERSIG

  return Buffer.concat([lead, sigHeaderBuf, headerAndPayload]);
}

