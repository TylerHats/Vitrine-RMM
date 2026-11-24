import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import * as ResEdit from 'resedit';
import { BRANDING_DIR_PATH, db } from '../../db/index.js';
import { imageBufferToMultiSizeIco, sanitizeAndSquareBrandingPng } from './iconProcessor.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export type WindowsTemplateName =
  | 'vitrine-companion-template.exe'
  | 'vitrine-tray-template.exe'
  | 'vitrine-installer-template.exe'
  | 'vitrine-companion-setup-template.exe'
  | 'vitrine-quicksupport-template.exe';

export interface WindowsPeStampOptions {
  productName: string;
  companyName: string;
  fileDescription: string;
  originalFilename: string;
  internalName?: string;
  fileVersion?: string;
  legalCopyright?: string;
  configJson?: Record<string, unknown>;
  customIconBuffer?: Buffer | null;
}

export function resolveWindowsTemplatePath(templateName: WindowsTemplateName): string {
  const candidates = [
    path.resolve(__dirname, '../../windows-agents', templateName),
    path.resolve(__dirname, '../../../dist/windows-agents', templateName),
    path.resolve(process.cwd(), 'dist/windows-agents', templateName),
    path.resolve(process.cwd(), 'backend/dist/windows-agents', templateName)
  ];
  const found = candidates.find((p) => fs.existsSync(p));
  if (!found) {
    throw new Error(
      `Missing native Windows PE template '${templateName}'. Run backend build with x86_64-w64-mingw32 toolchain installed.`
    );
  }
  return found;
}

export function resolveBrandingIconBuffer(iconUrl?: string): Buffer | null {
  try {
    const settings = (db.prepare('SELECT brand_logo_url FROM settings WHERE id = 1').get() || {}) as {
      brand_logo_url?: string;
    };
    const candidateUrl = String(iconUrl || settings.brand_logo_url || '').trim();
    const candidates: string[] = [];

    if (candidateUrl.startsWith('/branding/')) {
      const rel = candidateUrl.slice('/branding/'.length).replace(/[^a-zA-Z0-9._-]/g, '');
      if (rel) candidates.push(path.join(BRANDING_DIR_PATH, rel));
    }
    candidates.push(
      path.join(BRANDING_DIR_PATH, 'logo.ico'),
      path.join(BRANDING_DIR_PATH, 'logo.png')
    );

    for (const p of candidates) {
      if (!fs.existsSync(p) || !fs.statSync(p).isFile()) continue;
      const raw = fs.readFileSync(p);
      // Convert both PNG and ICO assets into a compact (~15 KB) multi-size 16/32/48 uncompressed RGBA ICO
      // so PE .rsrc size and entropy stay low across every stamped Windows binary.
      const multiIco = imageBufferToMultiSizeIco(raw);
      if (multiIco) return multiIco;
      if (raw.length >= 6 && raw.readUInt16LE(0) === 0 && raw.readUInt16LE(2) === 1) {
        return raw;
      }
    }
  } catch {
    // Fall back to default embedded template icon
  }
  return null;
}

export function resolveBrandingPngBuffer(iconUrl?: string, targetSize = 128): Buffer | null {
  try {
    const settings = (db.prepare('SELECT brand_logo_url FROM settings WHERE id = 1').get() || {}) as {
      brand_logo_url?: string;
    };
    const candidateUrl = String(iconUrl || settings.brand_logo_url || '').trim();
    const candidates: string[] = [];

    if (candidateUrl.startsWith('/branding/')) {
      const rel = candidateUrl.slice('/branding/'.length).replace(/[^a-zA-Z0-9._-]/g, '');
      if (rel) candidates.push(path.join(BRANDING_DIR_PATH, rel));
    }
    candidates.push(
      path.join(BRANDING_DIR_PATH, 'logo.png'),
      path.join(BRANDING_DIR_PATH, 'logo.ico')
    );

    for (const p of candidates) {
      if (!fs.existsSync(p) || !fs.statSync(p).isFile()) continue;
      const raw = fs.readFileSync(p);
      const png = sanitizeAndSquareBrandingPng(raw, targetSize);
      if (png) return png;
    }
  } catch {
    // Fall back to null
  }
  return null;
}

export function buildStampedWindowsPe(
  templateName: WindowsTemplateName,
  options: WindowsPeStampOptions
): Buffer {
  const tplPath = resolveWindowsTemplatePath(templateName);
  const rawTpl = fs.readFileSync(tplPath);

  const exe = ResEdit.NtExecutable.from(rawTpl);
  const res = ResEdit.NtExecutableResource.from(exe);

  // Inject RT_RCDATA resource ID 101 (UTF-8 JSON runtime config)
  if (options.configJson) {
    res.removeResourceEntry(10, 101);
    res.replaceResourceEntryFromString(10, 101, 1033, JSON.stringify(options.configJson));
  }

  // Stamp branded VS_VERSION_INFO properties
  const versionStr = options.fileVersion || '2.8.0.0';
  const verParts = versionStr.split('.').map((n) => Math.max(0, Math.min(65535, Number.parseInt(n, 10) || 0)));
  const vMajor = verParts[0] ?? 2;
  const vMinor = verParts[1] ?? 8;
  const vMicro = verParts[2] ?? 0;
  const vRev = verParts[3] ?? 0;

  const vis = ResEdit.Resource.VersionInfo.fromEntries(res.entries);
  const vi = vis.length > 0 ? vis[0] : ResEdit.Resource.VersionInfo.createEmpty();
  vi.setFileVersion(vMajor, vMinor, vMicro, vRev, 1033);
  vi.setProductVersion(vMajor, vMinor, vMicro, vRev, 1033);
  vi.setStringValues(
    { lang: 1033, codepage: 1200 },
    {
      CompanyName: options.companyName,
      ProductName: options.productName,
      FileDescription: options.fileDescription,
      OriginalFilename: options.originalFilename,
      InternalName: options.internalName || options.originalFilename,
      FileVersion: `${vMajor}.${vMinor}.${vMicro}.${vRev}`,
      ProductVersion: `${vMajor}.${vMinor}.${vMicro}.${vRev}`,
      LegalCopyright: options.legalCopyright || `Copyright (C) ${new Date().getFullYear()} ${options.companyName}`
    }
  );
  vi.outputToResourceEntries(res.entries);

  // Replace RT_GROUP_ICON ID 1 if valid branding ICO/PNG buffer is provided
  if (options.customIconBuffer) {
    try {
      const ico = ResEdit.Data.IconFile.from(options.customIconBuffer);
      const icons = ico.icons.map((item) => item.data);
      if (icons.length > 0) {
        const existingGroups = ResEdit.Resource.IconGroupEntry.fromEntries(res.entries);
        const groupId = existingGroups[0]?.id ?? 1;
        const groupLang = existingGroups[0]?.lang ?? 1033;
        ResEdit.Resource.IconGroupEntry.replaceIconsForResource(res.entries, groupId, groupLang, icons);
      }
    } catch {
      // Preserve template's valid compiled default icon if custom branding file isn't ICO-compatible
    }
  }

  res.outputResource(exe);
  return Buffer.from(exe.generate());
}

