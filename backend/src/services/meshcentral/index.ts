import WebSocket from 'ws';
import crypto from 'crypto';
import fs from 'fs';
import net from 'net';
import os from 'os';
import path from 'path';
import { execFile } from 'child_process';
import { fileURLToPath } from 'url';
import { db } from '../../db/index.js';
import {
  decryptVaultSecret,
  isBlockedOutboundIp,
  safeOutboundFetch,
  validateOutboundHostSafety
} from '../vault/index.js';
import { quotePowerShellLiteral, quoteBashLiteral, installerGenerator } from '../agent/installerGenerator.js';
import { agentSocketHub } from '../agent/socketHub.js';
import { mergeHardwareDetailsJson, recordDeviceTelemetrySample } from '../telemetry/index.js';
import {
  extractSignalsFromHardwareDetails,
  inferDeviceRole,
  shouldAutoUpdateDeviceRole
} from '../../utils/deviceRole.js';

export interface ProcessItem {
  pid: number;
  name: string;
  user: string;
  cpu: number;
  memoryMb: number;
  threads: number;
}

export interface ServiceItem {
  name: string;
  displayName: string;
  status: 'Running' | 'Stopped' | 'Paused';
  startType: 'Automatic' | 'Manual' | 'Disabled';
}

export interface RegistryEntry {
  path: string;
  name: string;
  type: 'REG_SZ' | 'REG_DWORD' | 'REG_BINARY' | 'REG_MULTI_SZ';
  value: string;
}

export interface ScheduledTaskItem {
  name: string;
  path: string;
  state: 'Ready' | 'Running' | 'Disabled';
  lastRunTime: string;
  nextRunTime: string;
  lastResult: string;
}

export interface FileItem {
  name: string;
  path: string;
  size: number;
  isDirectory: boolean;
  modified: string;
  permissions: string;
}

export interface MeshGroup {
  meshid: string;
  name: string;
  desc?: string;
  deviceCount?: number;
}

export interface DiscoveredMeshAgent {
  nodeId: string;
  hostname: string;
  meshId: string;
  meshName: string;
  osDesc: string;
  osType: 'windows' | 'linux' | 'macos';
  ipAddress: string;
  online: boolean;
  serialNumber?: string;
  manufacturer?: string;
  model?: string;
  cpuModel?: string;
  cpuCores?: number;
  ramTotalGb?: number;
  ramUsedGb?: number;
  diskTotalGb?: number;
  diskFreeGb?: number;
  macAddress?: string;
  biosVersion?: string;
  tpmVersion?: string;
  osBuild?: string;
  hardwareDetails?: Record<string, any>;
  amtSupported?: boolean;
  intelAmtEnabled?: boolean;
  amtProvisioned?: boolean;
  amtVersion?: string;
  edrName?: string;
  edrStatus?: string;
  pendingReboot?: boolean;
  loggedInUser?: string;
  agentPrivilegeMode?: 'standard_user' | 'elevated_admin' | 'system_service';
}

export interface MeshDiscoveryReport {
  reachable: boolean;
  authenticated: boolean;
  source: 'live_ws_control' | 'http_rest_api' | 'local_nedb_readonly' | 'unreachable';
  serverUrl: string;
  latencyMs: number;
  error?: string;
  groups: MeshGroup[];
  agents: DiscoveredMeshAgent[];
}

export interface SyncResult {
  success: boolean;
  imported: number;
  updated: number;
  importedDevices?: number;
  updatedDevices?: number;
  importedGroups: number;
  updatedGroups: number;
  unmappedMeshGroups: number;
  conflicts: Array<{ meshGroupId: string; meshGroupName: string; tenantId: string; deviceCount: number }>;
  conflictsNotified: number;
  message: string;
  timestamp: string;
}

export interface EventLogItem {
  id: number;
  timeGenerated: string;
  source: string;
  eventId: number;
  level: 'Critical' | 'Error' | 'Warning' | 'Information';
  channel: string;
  message: string;
}

const SERVICE_NAME_REGEX = /^[a-zA-Z0-9._@-]{1,128}$/;
const SAFE_ACCOUNT_NAME_REGEX = /^[a-zA-Z0-9._-]{1,20}$/;

const PROTECTED_UNIX_PATHS = new Set([
  '/',
  '/bin',
  '/boot',
  '/dev',
  '/etc',
  '/home',
  '/lib',
  '/lib64',
  '/opt',
  '/proc',
  '/root',
  '/run',
  '/sbin',
  '/sys',
  '/usr',
  '/var',
  '/System',
  '/Library',
  '/Applications',
  '/Users'
]);

const PROTECTED_WINDOWS_PATHS = new Set([
  'c:',
  'c:\\',
  'c:\\windows',
  'c:\\windows\\system32',
  'c:\\program files',
  'c:\\program files (x86)',
  'c:\\programdata',
  'c:\\users'
]);

function isLoopbackExactHostname(rawUrl: string): boolean {
  try {
    const h = new URL(rawUrl).hostname.toLowerCase().replace(/^\[|\]$/g, '');
    return h === 'localhost' || h === '127.0.0.1' || h === '::1';
  } catch {
    return false;
  }
}

function validateMeshServerUrl(rawUrl: string): {
  ok: boolean;
  normalized?: string;
  loginKey?: string;
  error?: string;
} {
  try {
    const parsed = new URL(rawUrl.trim());
    if (!['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol)) {
      return { ok: false, error: 'MeshCentral URL must start with http://, https://, ws://, or wss://.' };
    }
    const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    if (
      host === '169.254.169.254' ||
      host.startsWith('169.254.') ||
      host === 'metadata.google.internal' ||
      host === '100.100.100.200' ||
      host.startsWith('fe80:') ||
      (net.isIP(host) !== 0 && isBlockedOutboundIp(host, { allowLoopback: true, allowPrivateLan: true }))
    ) {
      return { ok: false, error: 'Link-local and cloud metadata addresses are blocked.' };
    }
    const loginKey = parsed.searchParams.get('key') || undefined;
    return { ok: true, normalized: parsed.origin, loginKey };
  } catch {
    return { ok: false, error: 'Invalid MeshCentral URL format.' };
  }
}

export function buildMeshWsAuthParams(
  normalizedOrigin: string,
  apiToken: string,
  loginKey?: string
): { wsUrl: string; headers: Record<string, string> } {
  const baseWs = normalizedOrigin.replace(/^http/i, 'ws');
  const headers: Record<string, string> = {};
  const queryParts: string[] = [];
  if (loginKey) {
    queryParts.push(`key=${encodeURIComponent(loginKey)}`);
  }

  const trimmed = String(apiToken || '').trim();
  if (trimmed.startsWith('~t:')) {
    // MeshCentral Login Token (~t:TokenUser:TokenPass or ~t:TokenUser TokenPass)
    const rest = trimmed.slice(3);
    const sepIdx = rest.search(/[:,\s]/);
    if (sepIdx > 0) {
      const userPart = trimmed.slice(0, 3 + sepIdx);
      const passPart = rest.slice(sepIdx + 1).trim();
      headers['x-meshauth'] =
        `${Buffer.from(userPart, 'utf8').toString('base64')},${Buffer.from(passPart, 'utf8').toString('base64')}`;
    } else {
      headers['x-meshauth'] = trimmed;
    }
  } else if (trimmed.includes(':') && !trimmed.startsWith('c=')) {
    // Support standard username:password (split on first ':' so passwords may contain ':')
    const idx = trimmed.indexOf(':');
    const userPart = trimmed.slice(0, idx);
    const passPart = trimmed.slice(idx + 1);
    headers['x-meshauth'] =
      `${Buffer.from(userPart, 'utf8').toString('base64')},${Buffer.from(passPart, 'utf8').toString('base64')}`;
  } else if (/^[A-Za-z0-9+/=]+,[A-Za-z0-9+/=]+(,[A-Za-z0-9+/=]+)?$/.test(trimmed)) {
    headers['x-meshauth'] = trimmed;
  } else if (trimmed) {
    // Encrypted MeshCentral cookie token (`auth=` query param, e.g. from `--logintoken`)
    queryParts.push(`auth=${encodeURIComponent(trimmed)}`);
  }

  const qs = queryParts.length > 0 ? `?${queryParts.join('&')}` : '';
  return { wsUrl: `${baseWs}/control.ashx${qs}`, headers };
}

function normalizeWindowsRegistryLiteralPath(regPath: string): string {
  const trimmed = String(regPath || '').trim().replace(/\0/g, '');
  if (/^HKLM(\\|$)/i.test(trimmed)) {
    return trimmed.replace(/^HKLM/i, 'Registry::HKEY_LOCAL_MACHINE');
  }
  if (/^HKEY_LOCAL_MACHINE(\\|$)/i.test(trimmed)) {
    return `Registry::${trimmed}`;
  }
  if (/^HKCU(\\|$)/i.test(trimmed)) {
    return trimmed.replace(/^HKCU/i, 'Registry::HKEY_CURRENT_USER');
  }
  if (/^HKEY_CURRENT_USER(\\|$)/i.test(trimmed)) {
    return `Registry::${trimmed}`;
  }
  if (/^HKU(\\|$)/i.test(trimmed)) {
    return trimmed.replace(/^HKU/i, 'Registry::HKEY_USERS');
  }
  if (/^HKCR(\\|$)/i.test(trimmed)) {
    return trimmed.replace(/^HKCR/i, 'Registry::HKEY_CLASSES_ROOT');
  }
  if (/^HKCC(\\|$)/i.test(trimmed)) {
    return trimmed.replace(/^HKCC/i, 'Registry::HKEY_CURRENT_CONFIG');
  }
  throw new Error('Registry path must begin with HKLM\\, HKCU\\, HKU\\, HKCR\\, or HKCC\\.');
}

function canonicalizeRemotePath(rawDir: string, osType: 'windows' | 'linux' | 'macos'): string {
  const trimmed = String(rawDir || '').trim().replace(/\0/g, '');
  if (osType === 'windows') {
    const winInput = !trimmed || trimmed === '/' ? 'C:\\' : trimmed.replace(/\//g, '\\');
    const normalized = path.win32.normalize(winInput);
    if (!/^[a-zA-Z]:\\/.test(normalized)) {
      throw new Error('Windows directory path must be an absolute drive path (e.g. C:\\Users).');
    }
    return normalized;
  }
  const posixInput = !trimmed || trimmed === 'C:\\' ? '/' : trimmed.replace(/\\/g, '/');
  const normalized = path.posix.normalize(posixInput);
  if (!normalized.startsWith('/')) {
    throw new Error('POSIX directory path must begin with /.');
  }
  return normalized;
}

class BoundedTtlCache<V> {
  private map = new Map<string, { value: V; expiresAt: number }>();
  constructor(
    private readonly maxEntries = 200,
    private readonly ttlMs = 15000
  ) {}

  get(key: string): V | undefined {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.map.delete(key);
      return undefined;
    }
    return entry.value;
  }

  set(key: string, value: V, customTtlMs?: number): void {
    if (this.map.size >= this.maxEntries && !this.map.has(key)) {
      const oldestKey = this.map.keys().next().value;
      if (oldestKey !== undefined) this.map.delete(oldestKey);
    }
    this.map.set(key, { value, expiresAt: Date.now() + (customTtlMs ?? this.ttlMs) });
  }

  delete(key: string): void {
    this.map.delete(key);
  }
}

interface FederatedSocketEntry {
  serverId: string;
  serverUrl: string;
  ws: WebSocket | null;
  connected: boolean;
  reconnectAttempts: number;
  reconnectTimer: ReturnType<typeof setTimeout> | null;
}

const WINDOWS_AGENT_IDS = new Set([1, 2, 3, 4, 21, 22, 34, 42, 43]);
const MACOS_AGENT_IDS = new Set([11, 16, 29]);
const LINUX_AGENT_IDS = new Set([5, 6, 7, 9, 10, 15, 18, 19, 20, 24, 25, 26, 27, 28, 32, 33, 36, 37, 40, 41, 44, 45]);

export function detectOsTypeFromMeshNode(node: any): 'windows' | 'linux' | 'macos' {
  const agentId = Number(node?.agent?.id || 0);
  if (WINDOWS_AGENT_IDS.has(agentId)) return 'windows';
  if (MACOS_AGENT_IDS.has(agentId)) return 'macos';
  if (LINUX_AGENT_IDS.has(agentId)) return 'linux';

  const desc = String(node?.osdesc || node?.ostype || '').toLowerCase();
  if (/darwin|mac\s?os|os\s?x/.test(desc)) return 'macos';
  if (/linux|ubuntu|debian|fedora|centos|rocky|alma|arch|alpine|suse|proxmox|red\s?hat|rhel|mint|kali|manjaro|freebsd|unix/.test(desc)) {
    return 'linux';
  }
  return 'windows';
}

const GENERIC_SERIAL_RE =
  /^(to be filled.*|default string|system serial number|none|n\/a|0+|unknown|o\.e\.m\.|not specified|chassis serial number|empty|invalid)$/i;

function pickCleanSerial(...candidates: Array<unknown>): string {
  let firstNonEmpty = '';
  for (const raw of candidates) {
    const val = String(raw ?? '').trim();
    if (!val) continue;
    if (!firstNonEmpty) firstNonEmpty = val;
    if (!GENERIC_SERIAL_RE.test(val)) return val.slice(0, 96);
  }
  return firstNonEmpty.slice(0, 96);
}

function extractBaseNodeFields(n: any): Partial<DiscoveredMeshAgent> {
  const intelAmtObj = n?.intelamt && typeof n.intelamt === 'object' ? n.intelamt : null;
  const amtSupported = Boolean(intelAmtObj);
  const intelAmtEnabled = Boolean(intelAmtObj && (Number(intelAmtObj.state) === 2 || intelAmtObj.state === 1));
  const amtVersion = intelAmtObj?.ver ? String(intelAmtObj.ver) : '';

  let edrName = '';
  let edrStatus = '';
  if (Array.isArray(n?.av) && n.av.length > 0) {
    const firstAv = n.av[0];
    if (firstAv?.product) {
      edrName = String(firstAv.product).slice(0, 96);
      edrStatus = firstAv.enabled === false ? 'Warning' : 'Healthy';
    }
  } else if (n?.defender && typeof n.defender === 'object') {
    edrName = 'Windows Defender';
    edrStatus = n.defender.RealTimeProtectionEnabled === false ? 'Warning' : 'Healthy';
  }

  const pendingReboot = Array.isArray(n?.pr) && n.pr.length > 0;
  let loggedInUser = '';
  if (Array.isArray(n?.users) && n.users.length > 0) {
    loggedInUser = String(n.users[0] || '');
  } else if (Array.isArray(n?.lusers) && n.lusers.length > 0) {
    loggedInUser = String(n.lusers[0] || '');
  } else if (Array.isArray(n?.upnusers) && n.upnusers.length > 0) {
    loggedInUser = String(n.upnusers[0] || '');
  }

  return {
    amtSupported,
    intelAmtEnabled,
    amtProvisioned: Boolean(intelAmtObj && Number(intelAmtObj.state) === 2),
    amtVersion,
    edrName,
    edrStatus,
    pendingReboot,
    loggedInUser: loggedInUser.slice(0, 96),
    agentPrivilegeMode: 'system_service'
  };
}

export function extractSysInfoAndNetInfo(sysinfo: any, netinfo: any): Partial<DiscoveredMeshAgent> {
  const out: Partial<DiscoveredMeshAgent> = {};
  const details: Record<string, any> = {
    system: {},
    cpu: {},
    memory: { modules: [] as any[] },
    storage: { physicalDisks: [] as any[], volumes: [] as any[] },
    gpus: [] as any[],
    networkAdapters: [] as any[],
    os: {}
  };

  const hardware = sysinfo?.hardware || sysinfo?.nodeinfo?.hardware || sysinfo?.sysinfo?.hardware;
  const ident = hardware?.identifiers;
  if (ident && typeof ident === 'object') {
    const serial = pickCleanSerial(ident.bios_serial, ident.chassis_serial, ident.board_serial, ident.product_uuid);
    if (serial) {
      out.serialNumber = serial;
      details.system.serialNumber = serial;
    }
    if (ident.product_uuid) details.system.uuid = String(ident.product_uuid).trim().slice(0, 96);
    const mfg = String(ident.chassis_manufacturer || ident.board_vendor || ident.bios_vendor || '').trim();
    if (mfg) {
      out.manufacturer = mfg.slice(0, 96);
      details.system.manufacturer = out.manufacturer;
    }
    const mdl = String(ident.product_name || ident.board_name || '').trim();
    if (mdl) {
      out.model = mdl.slice(0, 96);
      details.system.model = out.model;
    }
    if (ident.board_vendor) details.system.motherboardVendor = String(ident.board_vendor).trim().slice(0, 96);
    if (ident.board_name) details.system.motherboardName = String(ident.board_name).trim().slice(0, 96);
    if (ident.board_serial) details.system.motherboardSerial = String(ident.board_serial).trim().slice(0, 96);
    if (ident.bios_vendor) details.system.biosVendor = String(ident.bios_vendor).trim().slice(0, 96);
    if (ident.bios_date) details.system.biosDate = String(ident.bios_date).trim().slice(0, 48);

    const cpu = String(ident.cpu_name || '').trim();
    if (cpu) {
      out.cpuModel = cpu.slice(0, 128);
      details.cpu.model = out.cpuModel;
    }
    if (typeof ident.cpu_cores === 'number' && ident.cpu_cores > 0) {
      out.cpuCores = ident.cpu_cores;
      details.cpu.logicalCores = ident.cpu_cores;
    }
    const rawGpuNames = Array.isArray(ident.gpu_name)
      ? ident.gpu_name
      : ident.gpu_name
        ? [ident.gpu_name]
        : [];
    for (const gName of rawGpuNames) {
      const cleanGpu = String(gName || '').trim().slice(0, 96);
      if (cleanGpu && !details.gpus.some((g: any) => g.name === cleanGpu)) {
        details.gpus.push({ name: cleanGpu });
      }
    }
    const bios = String(ident.bios_version || '').trim();
    if (bios) {
      out.biosVersion = bios.slice(0, 96);
      details.system.biosVersion = out.biosVersion;
    }

    if (Array.isArray(ident.storage_devices) && ident.storage_devices.length > 0) {
      let totalBytes = 0;
      for (const sd of ident.storage_devices) {
        const sz = Number(sd?.Size || sd?.size || 0);
        if (sz > 0) totalBytes += sz;
        details.storage.physicalDisks.push({
          name: String(sd?.DeviceID || sd?.name || sd?.Model || 'Disk').slice(0, 80),
          model: String(sd?.Model || sd?.Caption || sd?.model || 'Storage Drive').slice(0, 96),
          sizeGb: sz > 0 ? Number((sz / (1024 * 1024 * 1024)).toFixed(1)) : 0,
          interfaceType: String(sd?.InterfaceType || sd?.BusType || '').slice(0, 32),
          mediaType: String(sd?.MediaType || '').slice(0, 48),
          status: String(sd?.Status || 'OK').slice(0, 32)
        });
      }
      if (totalBytes > 0) {
        out.diskTotalGb = Math.max(1, Math.round(totalBytes / (1024 * 1024 * 1024)));
      }
    }
  }

  if (hardware?.tpm?.SpecVersion) {
    out.tpmVersion = String(hardware.tpm.SpecVersion).slice(0, 32);
    details.system.tpmVersion = out.tpmVersion;
  }

  if (hardware?.windows) {
    if (hardware.windows.osinfo?.BuildNumber) {
      out.osBuild = String(hardware.windows.osinfo.BuildNumber).slice(0, 64);
      details.os.build = out.osBuild;
    }
    if (Array.isArray(hardware.windows.memory) && hardware.windows.memory.length > 0) {
      let ramBytes = 0;
      for (const dimm of hardware.windows.memory) {
        const cap = Number(dimm?.Capacity || 0);
        if (cap > 0) ramBytes += cap;
        details.memory.modules.push({
          slot: String(dimm?.DeviceLocator || dimm?.BankLabel || 'DIMM').slice(0, 48),
          capacityGb: cap > 0 ? Number((cap / (1024 * 1024 * 1024)).toFixed(1)) : 0,
          speedMhz: Number(dimm?.ConfiguredClockSpeed || dimm?.Speed || 0) || undefined,
          manufacturer: String(dimm?.Manufacturer || '').trim().slice(0, 64) || undefined,
          partNumber: String(dimm?.PartNumber || '').trim().slice(0, 64) || undefined
        });
      }
      if (ramBytes > 0) {
        out.ramTotalGb = Number((ramBytes / (1024 * 1024 * 1024)).toFixed(1));
        details.memory.totalGb = out.ramTotalGb;
      }
    }
    if (hardware.windows.volumes && typeof hardware.windows.volumes === 'object') {
      let capBytes = 0;
      let freeBytes = 0;
      for (const [volKey, vol] of Object.entries(hardware.windows.volumes) as Array<[string, any]>) {
        if (!vol) continue;
        const c = Number(vol.capacity || vol.Size || 0);
        const f = Number(vol.free || vol.FreeSpace || 0);
        if (c > 0) capBytes += c;
        if (f > 0) freeBytes += f;
        if (c > 0) {
          const totalGb = Number((c / (1024 * 1024 * 1024)).toFixed(1));
          const freeGb = Number((f / (1024 * 1024 * 1024)).toFixed(1));
          details.storage.volumes.push({
            mount: String(vol.name || vol.mount || volKey).slice(0, 64),
            label: String(vol.label || vol.VolumeName || '').slice(0, 64),
            filesystem: String(vol.filesystem || vol.FileSystem || '').slice(0, 24),
            totalGb,
            freeGb,
            usedPct: Number((((c - f) / c) * 100).toFixed(1))
          });
        }
      }
      if (!out.diskTotalGb && capBytes > 0) out.diskTotalGb = Math.max(1, Math.round(capBytes / (1024 * 1024 * 1024)));
      if (freeBytes > 0) out.diskFreeGb = Math.max(0, Math.round(freeBytes / (1024 * 1024 * 1024)));
    }
    if (Array.isArray(hardware.windows.gpu)) {
      for (const g of hardware.windows.gpu) {
        if (g?.Name || g?.Caption) {
          details.gpus.push({
            name: String(g.Name || g.Caption).slice(0, 96),
            driverVersion: g.DriverVersion ? String(g.DriverVersion).slice(0, 48) : undefined
          });
        }
      }
    }
  }

  if (hardware?.linux) {
    if (!out.osBuild && hardware.linux.kernel_release) {
      out.osBuild = String(hardware.linux.kernel_release).slice(0, 64);
      details.os.build = out.osBuild;
    }
    if (!out.cpuModel && hardware.linux.cpu_model) {
      out.cpuModel = String(hardware.linux.cpu_model).slice(0, 128);
      details.cpu.model = out.cpuModel;
    }
    if (!out.ramTotalGb && hardware.linux.memory?.total) {
      const kb = Number(hardware.linux.memory.total);
      if (kb > 0) {
        out.ramTotalGb = Number((kb / (1024 * 1024)).toFixed(1));
        details.memory.totalGb = out.ramTotalGb;
      }
    }
    const totalKb = Number(hardware.linux.memory?.total || 0);
    const availKb = Number(hardware.linux.memory?.available ?? hardware.linux.memory?.free ?? -1);
    if (totalKb > 0 && availKb >= 0 && availKb <= totalKb) {
      out.ramUsedGb = Number(((totalKb - availKb) / (1024 * 1024)).toFixed(2));
    }
    if (Array.isArray(hardware.linux.memory?.Memory_Device) && details.memory.modules.length === 0) {
      for (const dimm of hardware.linux.memory.Memory_Device) {
        if (!dimm) continue;
        const sizeStr = String(dimm.Size || '').trim();
        let capGb = 0;
        const gbMatch = sizeStr.match(/^([\d.]+)\s*GB/i);
        const mbMatch = sizeStr.match(/^([\d.]+)\s*MB/i);
        if (gbMatch) capGb = Number(gbMatch[1]);
        else if (mbMatch) capGb = Number((Number(mbMatch[1]) / 1024).toFixed(2));
        if (capGb > 0) {
          details.memory.modules.push({
            slot: String(dimm.Locator || dimm.Bank_Locator || 'DIMM').slice(0, 48),
            capacityGb: capGb,
            speedMhz: Number(String(dimm.Speed || '').replace(/[^\d]/g, '')) || undefined,
            manufacturer: String(dimm.Manufacturer || '').trim().slice(0, 64) || undefined,
            partNumber: String(dimm.Part_Number || dimm.Type || '').trim().slice(0, 64) || undefined
          });
        }
      }
    }
    if (Array.isArray(hardware.linux.volumes) && details.storage.volumes.length === 0) {
      let rootTotalGb = 0;
      let rootFreeGb = 0;
      let sumTotalGb = 0;
      let sumFreeGb = 0;
      for (const v of hardware.linux.volumes) {
        if (!v) continue;
        const mount = String(v.mount_point || '').trim();
        const sizeKb = Number(v.size || 0);
        const availBlocksKb = Number(v.available ?? 0);
        const usedKb = Number(v.used ?? 0);
        if (sizeKb <= 0 || !mount) continue;
        const totalGb = Number(((sizeKb * 1024) / (1024 * 1024 * 1024)).toFixed(2));
        const freeGb = Number(((availBlocksKb * 1024) / (1024 * 1024 * 1024)).toFixed(2));
        const usedPct = sizeKb > 0 ? Number((((usedKb || Math.max(0, sizeKb - availBlocksKb)) / sizeKb) * 100).toFixed(1)) : 0;
        details.storage.volumes.push({
          mount: mount.slice(0, 64),
          label: '',
          filesystem: String(v.type || '').slice(0, 24),
          totalGb,
          freeGb,
          usedPct
        });
        if (mount === '/') {
          rootTotalGb = totalGb;
          rootFreeGb = freeGb;
        }
        if (!mount.startsWith('/boot') && !mount.startsWith('/snap')) {
          sumTotalGb += totalGb;
          sumFreeGb += freeGb;
        }
      }
      if (!out.diskTotalGb && (rootTotalGb > 0 || sumTotalGb > 0)) {
        out.diskTotalGb = Number((rootTotalGb || sumTotalGb).toFixed(2));
      }
      if (out.diskFreeGb == null && (rootTotalGb > 0 || sumTotalGb > 0)) {
        out.diskFreeGb = Number((rootTotalGb > 0 ? rootFreeGb : sumFreeGb).toFixed(2));
      }
    }
  }

  // Extract primary MAC & IPv4 from network info (`netif2` preferred, fallback `netif`)
  if (netinfo && typeof netinfo === 'object') {
    if (netinfo.netif2 && typeof netinfo.netif2 === 'object') {
      for (const [ifName, ifArr] of Object.entries(netinfo.netif2) as Array<[string, any]>) {
        if (!Array.isArray(ifArr)) continue;
        let nicMac = '';
        let nicIp4 = '';
        let nicIp6 = '';
        for (const item of ifArr) {
          if (!item) continue;
          const mac = String(item.mac || '').trim();
          if (mac && !mac.startsWith('00:00:00:00')) {
            if (!nicMac) nicMac = mac.toUpperCase();
            if (!out.macAddress) out.macAddress = mac.toUpperCase();
          }
          const addr = String(item.address || '').trim();
          if (item.family === 'IPv4' && addr && !addr.startsWith('127.') && !addr.startsWith('169.254.')) {
            if (!nicIp4) nicIp4 = addr;
            if (!out.ipAddress) out.ipAddress = addr;
          } else if (item.family === 'IPv6' && addr && !addr.startsWith('::1') && !nicIp6) {
            nicIp6 = addr;
          }
        }
        if (nicIp4 || nicMac) {
          details.networkAdapters.push({
            name: String(ifName).slice(0, 64),
            mac: nicMac || undefined,
            ipv4: nicIp4 || undefined,
            ipv6: nicIp6 || undefined
          });
        }
      }
    }
    if ((!out.macAddress || !out.ipAddress) && netinfo.netif && typeof netinfo.netif === 'object') {
      for (const [ifName, m] of Object.entries(netinfo.netif) as Array<[string, any]>) {
        if (!m) continue;
        const mac = String(m.mac || '').trim();
        if (mac && !mac.startsWith('00:00:00:00') && !out.macAddress) {
          out.macAddress = mac.toUpperCase();
        }
        const addr = String(m.v4addr || '').trim();
        if (addr && addr !== '0.0.0.0' && !addr.startsWith('127.') && !addr.startsWith('169.254.') && !out.ipAddress) {
          out.ipAddress = addr;
        }
        if (details.networkAdapters.length === 0 && (mac || addr)) {
          details.networkAdapters.push({
            name: String(m.name || ifName).slice(0, 64),
            mac: mac ? mac.toUpperCase() : undefined,
            ipv4: addr && addr !== '0.0.0.0' ? addr : undefined
          });
        }
      }
    }
  }

  const hasDetailContent =
    Object.keys(details.system).length > 0 ||
    Object.keys(details.cpu).length > 0 ||
    details.memory.modules.length > 0 ||
    details.storage.physicalDisks.length > 0 ||
    details.storage.volumes.length > 0 ||
    details.gpus.length > 0 ||
    details.networkAdapters.length > 0;
  if (hasDetailContent) {
    out.hardwareDetails = details;
  }

  return out;
}

function extractDelimitedJson(raw: string): string {
  const clean = String(raw || '').trim();
  const eIdx = clean.lastIndexOf('__VJ_END__');
  const sIdx = eIdx > 0 ? clean.lastIndexOf('__VJ_START__', eIdx) : clean.indexOf('__VJ_START__');
  if (sIdx >= 0 && eIdx > sIdx) {
    return clean.slice(sIdx + 12, eIdx).trim();
  }
  const firstArr = clean.indexOf('[');
  const firstObj = clean.indexOf('{');
  let start = -1;
  let closeChar = '';
  if (firstArr >= 0 && (firstObj < 0 || firstArr < firstObj)) {
    start = firstArr;
    closeChar = ']';
  } else if (firstObj >= 0) {
    start = firstObj;
    closeChar = '}';
  }
  if (start >= 0) {
    const end = clean.lastIndexOf(closeChar);
    if (end > start) return clean.slice(start, end + 1);
  }
  return clean;
}

const CMD_SENTINEL_REGEX = /(?:\r?\n)?__VITRINE_RC:(-?\d+):([A-Za-z0-9_-]+)(?:\r?\n)?/;

function extractCommandSentinel(rawOutput: string): {
  cleanOutput: string;
  exitCode: number | null;
  cmdId: string | null;
} {
  const match = CMD_SENTINEL_REGEX.exec(rawOutput);
  if (!match) {
    return { cleanOutput: rawOutput, exitCode: null, cmdId: null };
  }
  const parsedRc = Number.parseInt(match[1], 10);
  const exitCode = Number.isNaN(parsedRc) ? 0 : parsedRc;
  const cmdId = match[2] || null;
  const before = rawOutput.slice(0, match.index);
  const after = rawOutput.slice(match.index + match[0].length);
  const joined = before && after ? `${before}\n${after}` : `${before}${after}`;
  return {
    cleanOutput: joined.replace(/\r?\n$/, ''),
    exitCode,
    cmdId
  };
}

export class MeshCentralBridge {
  private meshWs: WebSocket | null = null;
  private isConnected = false;
  private isConfigured = false;
  private connectedServerUrl: string | null = null;
  private lastConnectionError: string | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectAttempts = 0;
  private configEpoch = 0;

  private federatedPool = new Map<string, FederatedSocketEntry>();
  private nodeServerMap = new Map<string, string>();

  private pendingCmdWaiters = new Map<
    string,
    {
      resolve: (res: { output: string; exitCode: number } | null) => void;
      timer: ReturnType<typeof setTimeout>;
      nodeId?: string;
      consoleBuffer: string;
    }
  >();
  private pendingControlWaiters = new Map<
    string,
    { resolve: (msg: any) => void; timer: ReturnType<typeof setTimeout> }
  >();
  private pendingAuthCookieWaiters = new Map<
    string,
    Array<{ resolve: (cookie: { cookie: string; rcookie: string } | null) => void; timer: ReturnType<typeof setTimeout> }>
  >();
  private pendingSysInfoWaiters = new Map<string, Array<{ resolve: (doc: any) => void; timer: ReturnType<typeof setTimeout> }>>();
  private pendingNetInfoWaiters = new Map<string, Array<{ resolve: (doc: any) => void; timer: ReturnType<typeof setTimeout> }>>();
  private connectWaiters: Array<{ resolve: (ok: boolean) => void; timer: ReturnType<typeof setTimeout> }> = [];
  private nodeExecQueues = new Map<string, Promise<void>>();
  private enrichingNodes = new Set<string>();
  private liveTelemetryInFlight = new Map<string, Promise<{ sampled: boolean; sample?: any; reason?: string }>>();
  public lastToolError: string | null = null;

  // Bounded TTL caches storing ONLY real endpoint query responses
  private processCache = new BoundedTtlCache<ProcessItem[]>(150, 10000);
  private serviceCache = new BoundedTtlCache<ServiceItem[]>(150, 15000);
  private registryCache = new BoundedTtlCache<{ subkeys: string[]; values: RegistryEntry[] }>(200, 20000);
  private taskCache = new BoundedTtlCache<ScheduledTaskItem[]>(150, 20000);
  private fileCache = new BoundedTtlCache<FileItem[]>(250, 12000);
  private fileContentCache = new BoundedTtlCache<Buffer>(50, 120000);

  constructor() {
    this.checkConfig();
  }

  private closeExistingSocket() {
    this.configEpoch++;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.meshWs) {
      const oldWs = this.meshWs;
      this.meshWs = null;
      try {
        oldWs.removeAllListeners();
        oldWs.on('error', () => {});
        if (oldWs.readyState === WebSocket.OPEN) {
          oldWs.close();
        } else if (oldWs.readyState === WebSocket.CONNECTING) {
          oldWs.terminate();
        }
      } catch {}
    }
    this.isConnected = false;

    for (const [, entry] of this.federatedPool) {
      if (entry.reconnectTimer) clearTimeout(entry.reconnectTimer);
      if (entry.ws) {
        const oldFedWs = entry.ws;
        entry.ws = null;
        try {
          oldFedWs.removeAllListeners();
          oldFedWs.on('error', () => {});
          if (oldFedWs.readyState === WebSocket.OPEN) {
            oldFedWs.close();
          } else if (oldFedWs.readyState === WebSocket.CONNECTING) {
            oldFedWs.terminate();
          }
        } catch {}
      }
    }
    this.federatedPool.clear();
  }

  private resolveConnectWaiters(ok: boolean) {
    const waiters = this.connectWaiters.splice(0, this.connectWaiters.length);
    for (const w of waiters) {
      clearTimeout(w.timer);
      w.resolve(ok);
    }
  }

  public async reconnectAndWait(timeoutMs = 3500): Promise<boolean> {
    this.checkConfig();
    if (!this.isConfigured) return false;
    if (this.isConnected || Array.from(this.federatedPool.values()).some((f) => f.connected)) {
      return true;
    }
    return new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => {
        const idx = this.connectWaiters.findIndex((w) => w.resolve === resolve);
        if (idx >= 0) this.connectWaiters.splice(idx, 1);
        resolve(this.isConnected || Array.from(this.federatedPool.values()).some((f) => f.connected));
      }, timeoutMs);
      this.connectWaiters.push({ resolve, timer });
    });
  }

  public checkConfig() {
    this.closeExistingSocket();
    this.reconnectAttempts = 0;
    try {
      const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
      let serverUrl = (settings.meshcentral_url || '').trim();
      let apiToken = decryptVaultSecret(settings.meshcentral_api_token);
      let primaryAllowSelfSigned = Boolean(settings.meshcentral_allow_self_signed);

      const allServers = db
        .prepare('SELECT id, url, api_token, is_primary, allow_self_signed FROM mesh_servers ORDER BY is_primary DESC, created_at ASC')
        .all() as Array<{ id: string; url: string; api_token: string; is_primary: number; allow_self_signed?: number }>;

      if ((!serverUrl || !apiToken) && allServers.length > 0) {
        const primary = allServers[0];
        if (primary?.url && primary?.api_token) {
          serverUrl = String(primary.url).trim();
          apiToken = decryptVaultSecret(primary.api_token);
          primaryAllowSelfSigned = primaryAllowSelfSigned || Boolean(primary.allow_self_signed);
        }
      }

      const isPlaceholderUrl =
        !serverUrl ||
        serverUrl === 'https://mesh.vitrine.local' ||
        serverUrl === 'https://mesh.yourdomain.com';

      if (!isPlaceholderUrl && apiToken) {
        this.isConfigured = true;
        this.initLiveConnection(serverUrl, apiToken, primaryAllowSelfSigned);
      } else {
        this.isConfigured = false;
        this.isConnected = false;
        this.connectedServerUrl = serverUrl || null;
        this.lastConnectionError = null;
        this.resolveConnectWaiters(false);
      }

      // Connect additional federated MeshCentral servers into the multi-server pool
      for (const srv of allServers) {
        const srvUrl = String(srv.url || '').trim();
        const srvToken = decryptVaultSecret(srv.api_token);
        if (!srvUrl || !srvToken || srvUrl === serverUrl) continue;
        this.initFederatedSocket(
          srv.id,
          srvUrl,
          srvToken,
          Boolean(srv.allow_self_signed || settings.meshcentral_allow_self_signed)
        );
      }
    } catch (e: any) {
      this.isConfigured = false;
      this.isConnected = false;
      this.lastConnectionError = e?.message || 'Database not initialized';
      this.resolveConnectWaiters(false);
    }
  }

  private handleIncomingMeshFrame(raw: WebSocket.RawData, serverId = 'primary') {
    try {
      const msg = JSON.parse(raw.toString());
      if (!msg || typeof msg !== 'object') return;

      if (
        msg.action === 'close' &&
        (msg.cause === 'noauth' || msg.cause === 'notools' || msg.cause === 'emailvalidation')
      ) {
        const errMsg =
          msg.msg === 'tokenrequired'
            ? 'MeshCentral requires 2FA/TOTP for this account. Create a MeshCentral Login Token (~t:TokenUser:TokenPass) via My Account -> Login Tokens or meshctrl.js LoginTokens --add "Vitrine RMM" --token <6-digit-TOTP>.'
            : `MeshCentral rejected WebSocket authentication (${msg.msg || msg.cause}).`;
        if (serverId === 'primary') {
          this.isConnected = false;
          this.lastConnectionError = errMsg;
          this.resolveConnectWaiters(false);
        }
        return;
      }

      // First valid control message confirms authenticated connection
      if (
        serverId === 'primary' &&
        (msg.action === 'nodes' || msg.action === 'meshes' || msg.action === 'userinfo' || msg.action === 'serverinfo')
      ) {
        this.resolveConnectWaiters(true);
      }

      // Track node -> server mapping and online status + base telemetry transitions live!
      if (msg.action === 'nodes' && msg.nodes && typeof msg.nodes === 'object') {
        const nodesToEnrich: string[] = [];
        for (const arr of Object.values(msg.nodes)) {
          if (!Array.isArray(arr)) continue;
          for (const n of arr as any[]) {
            if (!n?._id) continue;
            const nid = String(n._id);
            this.nodeServerMap.set(nid, serverId);
            const online = Boolean(n.conn && (Number(n.conn) & 1) !== 0);
            const osType = detectOsTypeFromMeshNode(n);
            const base = extractBaseNodeFields(n);
            try {
              const existing = db
                .prepare('SELECT id, serial_number, cpu_model, mac_address FROM devices WHERE mesh_node_id = ?')
                .get(nid) as any;
              if (existing) {
                db.prepare(`
                  UPDATE devices
                  SET os_type = COALESCE(?, os_type),
                      os_version = CASE WHEN ? != '' THEN ? ELSE os_version END,
                      ip_address = CASE WHEN ? != '' THEN ? ELSE ip_address END,
                      status = CASE WHEN quarantined = 1 THEN 'isolated' ELSE ? END,
                      amt_supported = CASE WHEN ? = 1 THEN 1 ELSE amt_supported END,
                      intel_amt_enabled = CASE WHEN ? = 1 THEN 1 ELSE intel_amt_enabled END,
                      amt_provisioned = CASE WHEN ? = 1 THEN 1 ELSE amt_provisioned END,
                      amt_version = CASE WHEN ? != '' THEN ? ELSE amt_version END,
                      edr_name = CASE WHEN ? != '' THEN ? ELSE edr_name END,
                      edr_status = CASE WHEN ? != '' THEN ? ELSE edr_status END,
                      pending_reboot = ?,
                      logged_in_user = CASE WHEN ? != '' THEN ? ELSE logged_in_user END,
                      last_seen = CASE WHEN ? = 'online' THEN ? ELSE last_seen END
                  WHERE id = ?
                `).run(
                  osType,
                  String(n.osdesc || ''),
                  String(n.osdesc || ''),
                  String(n.ip || ''),
                  String(n.ip || ''),
                  online ? 'online' : 'offline',
                  base.amtSupported ? 1 : 0,
                  base.intelAmtEnabled ? 1 : 0,
                  base.amtProvisioned ? 1 : 0,
                  base.amtVersion || '',
                  base.amtVersion || '',
                  base.edrName || '',
                  base.edrName || '',
                  base.edrStatus || '',
                  base.edrStatus || '',
                  base.pendingReboot ? 1 : 0,
                  base.loggedInUser || '',
                  base.loggedInUser || '',
                  online ? 'online' : 'offline',
                  new Date().toISOString(),
                  existing.id
                );
                if (
                  !existing.serial_number ||
                  existing.cpu_model === 'Discovered Node' ||
                  existing.mac_address === '00:00:00:00:00:00'
                ) {
                  nodesToEnrich.push(existing.id);
                }
              }
            } catch {}
          }
        }
        if (nodesToEnrich.length > 0) {
          for (const devId of nodesToEnrich.slice(0, 15)) {
            void this.enrichDeviceFromMesh(devId).catch(() => {});
          }
        }
      } else if (msg.action === 'event' && msg.event?.nodeid) {
        const nid = String(msg.event.nodeid);
        this.nodeServerMap.set(nid, serverId);
        if (msg.event.etype === 'node' && typeof msg.event.conn === 'number') {
          const isOnline = (msg.event.conn & 1) !== 0;
          try {
            db.prepare(
              "UPDATE devices SET status = CASE WHEN quarantined = 1 THEN 'isolated' ELSE ? END, last_seen = ? WHERE mesh_node_id = ?"
            ).run(isOnline ? 'online' : 'offline', new Date().toISOString(), nid);

            if (isOnline) {
              const devRow = db
                .prepare('SELECT id, companion_deploy_pending, serial_number, cpu_model FROM devices WHERE mesh_node_id = ? LIMIT 1')
                .get(nid) as any;
              if (devRow) {
                if (devRow.companion_deploy_pending === 1) {
                  void this.deployCompanionOverMesh(devRow.id).catch(() => {});
                }
                if (!devRow.serial_number || devRow.cpu_model === 'Discovered Node') {
                  void this.enrichDeviceFromMesh(devRow.id).catch(() => {});
                }
                const pendingLaps = db
                  .prepare('SELECT device_id FROM laps_vault WHERE device_id = ? AND rotation_pending_online = 1')
                  .get(devRow.id);
                if (pendingLaps) {
                  void import('../laps/index.js')
                    .then(({ rotateLapsPasswordVerifiedAsync }) =>
                      rotateLapsPasswordVerifiedAsync(devRow.id, { reveal: false, actorUsername: 'system-reconnect' })
                    )
                    .catch(() => {});
                }
              }
            }
          } catch {}
        }
      }

      // Resolve authcookie waiters (MeshCentral sends { action: 'authcookie', cookie, rcookie } without responseid)
      if (msg.action === 'authcookie' && msg.cookie && msg.rcookie) {
        const queue = this.pendingAuthCookieWaiters.get(serverId);
        if (queue && queue.length > 0) {
          const w = queue.shift()!;
          clearTimeout(w.timer);
          w.resolve({ cookie: String(msg.cookie), rcookie: String(msg.rcookie) });
        }
        return;
      }

      // Resolve getsysinfo waiters (keyed by nodeid)
      if (msg.action === 'getsysinfo' && msg.nodeid) {
        const list = this.pendingSysInfoWaiters.get(String(msg.nodeid));
        if (list && list.length > 0) {
          const w = list.shift()!;
          clearTimeout(w.timer);
          if (list.length === 0) this.pendingSysInfoWaiters.delete(String(msg.nodeid));
          w.resolve(msg.noinfo ? null : msg);
        }
        return;
      }

      // Resolve getnetworkinfo waiters (keyed by nodeid)
      if (msg.action === 'getnetworkinfo' && msg.nodeid) {
        const list = this.pendingNetInfoWaiters.get(String(msg.nodeid));
        if (list && list.length > 0) {
          const w = list.shift()!;
          clearTimeout(w.timer);
          if (list.length === 0) this.pendingNetInfoWaiters.delete(String(msg.nodeid));
          w.resolve(msg.noinfo ? null : msg);
        }
        return;
      }

      // Resolve control RPC waiters (e.g., createDeviceShareLink)
      const respId = msg.responseid || msg.tag;
      if (respId && this.pendingControlWaiters.has(String(respId))) {
        const ctl = this.pendingControlWaiters.get(String(respId))!;
        clearTimeout(ctl.timer);
        this.pendingControlWaiters.delete(String(respId));
        ctl.resolve(msg);
      }

      // Resolve live command execution output (`reply: true` sends `action: 'msg', type: 'runcommands'` on exit)
      if (respId && this.pendingCmdWaiters.has(String(respId))) {
        // MeshCentral sends `{ action: 'runcommands', result: 'OK', responseid }` first as dispatch ack,
        // OR returns an immediate error like 'Agent not connected' / 'Invalid command type' / 'Access denied'.
        if (msg.action === 'runcommands' && msg.value === undefined && msg.output === undefined) {
          if (msg.result === 'OK') {
            return;
          }
          const waiter = this.pendingCmdWaiters.get(String(respId))!;
          clearTimeout(waiter.timer);
          this.pendingCmdWaiters.delete(String(respId));
          const errStr = String(msg.result || 'Command rejected');
          // Only fall through on Invalid nodeid; return immediate failure for Agent not connected / Invalid command type
          if (errStr === 'Invalid nodeid' || errStr === 'Invalid nodeids') {
            waiter.resolve(null);
          } else {
            waiter.resolve({ output: errStr, exitCode: 1 });
          }
          return;
        }
        const waiter = this.pendingCmdWaiters.get(String(respId))!;
        const rawOut = String(msg.result ?? msg.value ?? msg.output ?? '');
        const cleanRaw = /^(?:OK|Complete|Run commands? complete\.?)$/i.test(rawOut.trim()) ? '' : rawOut;
        let combinedOut: string;
        if (!waiter.consoleBuffer) {
          combinedOut = cleanRaw;
        } else if (!cleanRaw) {
          combinedOut = waiter.consoleBuffer;
        } else if (
          cleanRaw.includes(waiter.consoleBuffer) ||
          extractCommandSentinel(cleanRaw).cmdId === String(respId)
        ) {
          combinedOut = cleanRaw;
        } else if (waiter.consoleBuffer.includes(cleanRaw)) {
          combinedOut = waiter.consoleBuffer;
        } else {
          combinedOut = `${waiter.consoleBuffer}${cleanRaw}`;
        }
        const parsed = extractCommandSentinel(combinedOut);
        // MeshCentral often delivers the summary `Run commands complete.` ack slightly before the final streaming
        // `type: 'console'` chunk carrying large stdout + `__VITRINE_RC`. Wait up to 750ms instead of resolving empty!
        if (!cleanRaw && parsed.exitCode === null) {
          clearTimeout(waiter.timer);
          waiter.timer = setTimeout(() => {
            const w = this.pendingCmdWaiters.get(String(respId));
            if (!w) return;
            this.pendingCmdWaiters.delete(String(respId));
            const finalParsed = extractCommandSentinel(w.consoleBuffer);
            const finalExit =
              finalParsed.exitCode !== null
                ? finalParsed.exitCode
                : /CategoryInfo|FullyQualifiedErrorId|Exception/i.test(w.consoleBuffer)
                  ? 1
                  : 0;
            w.resolve({ output: finalParsed.cleanOutput, exitCode: finalExit });
          }, 750);
          return;
        }
        const inferredExit =
          parsed.exitCode !== null
            ? parsed.exitCode
            : /CategoryInfo|FullyQualifiedErrorId|Exception/i.test(combinedOut)
              ? 1
              : 0;
        clearTimeout(waiter.timer);
        this.pendingCmdWaiters.delete(String(respId));
        waiter.resolve({ output: parsed.cleanOutput, exitCode: inferredExit });
        return;
      }

      // Streaming `type: 'console'` frames do NOT carry `responseid` in MeshCentral 2!
      // NEVER resolve on the first chunk — accumulate into `waiter.consoleBuffer` and ONLY
      // resolve once the deterministic `__VITRINE_RC:<code>:<cmdId>` sentinel is complete.
      if (
        (msg.action === 'msg' || msg.type === 'runcommands' || msg.type === 'console') &&
        (msg.result !== undefined || msg.value !== undefined || msg.output !== undefined)
      ) {
        const rawOut = String(msg.result ?? msg.value ?? msg.output ?? '');
        const parsedDirect = extractCommandSentinel(rawOut);
        if (parsedDirect.cmdId && this.pendingCmdWaiters.has(parsedDirect.cmdId)) {
          const waiter = this.pendingCmdWaiters.get(parsedDirect.cmdId)!;
          const combined = waiter.consoleBuffer
            ? rawOut.includes(waiter.consoleBuffer)
              ? rawOut
              : waiter.consoleBuffer.includes(rawOut)
                ? waiter.consoleBuffer
                : `${waiter.consoleBuffer}${rawOut}`
            : rawOut;
          const parsedCombined = extractCommandSentinel(combined);
          clearTimeout(waiter.timer);
          this.pendingCmdWaiters.delete(parsedDirect.cmdId);
          waiter.resolve({ output: parsedCombined.cleanOutput, exitCode: parsedCombined.exitCode ?? 0 });
          return;
        }
        if (msg.nodeid) {
          for (const [k, waiter] of this.pendingCmdWaiters.entries()) {
            if (waiter.nodeId === String(msg.nodeid)) {
              const nextBuf = waiter.consoleBuffer + rawOut;
              waiter.consoleBuffer = nextBuf.length > 512 * 1024 ? nextBuf.slice(-512 * 1024) : nextBuf;
              if (waiter.consoleBuffer.includes("Run commands can't execute, already busy")) {
                clearTimeout(waiter.timer);
                this.pendingCmdWaiters.delete(k);
                waiter.resolve({ output: waiter.consoleBuffer.trim(), exitCode: 1 });
                break;
              }
              const parsedBuf = extractCommandSentinel(waiter.consoleBuffer);
              if (parsedBuf.cmdId === k) {
                clearTimeout(waiter.timer);
                this.pendingCmdWaiters.delete(k);
                waiter.resolve({ output: parsedBuf.cleanOutput, exitCode: parsedBuf.exitCode ?? 0 });
              }
              break;
            }
          }
        }
      }
    } catch {
      // Ignore binary/non-JSON frames
    }
  }

  private schedulePrimaryReconnect(serverUrl: string, apiToken: string, allowSelfSigned: boolean) {
    if (!this.isConfigured || this.reconnectTimer) return;
    const delayMs = Math.min(30000, 2000 * Math.pow(2, Math.min(4, this.reconnectAttempts++)));
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (this.isConfigured) {
        this.initLiveConnection(serverUrl, apiToken, allowSelfSigned);
      }
    }, delayMs);
  }

  private initLiveConnection(serverUrl: string, apiToken: string, allowSelfSigned = false) {
    const check = validateMeshServerUrl(serverUrl);
    if (!check.ok || !check.normalized) {
      this.isConnected = false;
      this.lastConnectionError = check.error || 'Invalid MeshCentral URL';
      return;
    }

    const normalizedUrl = check.normalized;
    const epoch = this.configEpoch;
    this.connectedServerUrl = normalizedUrl;

    void (async () => {
      const dnsSafety = await validateOutboundHostSafety(normalizedUrl, {
        allowLoopback: true,
        allowPrivateLan: true
      });
      if (epoch !== this.configEpoch || !this.isConfigured) return;
      if (!dnsSafety.safe) {
        this.isConnected = false;
        this.lastConnectionError = dnsSafety.reason || 'MeshCentral URL blocked by outbound safety policy';
        this.resolveConnectWaiters(false);
        return;
      }

      try {
        const { wsUrl, headers } = buildMeshWsAuthParams(normalizedUrl, apiToken, check.loginKey);

        const allowInsecure =
          allowSelfSigned ||
          process.env.MESHCENTRAL_ALLOW_SELF_SIGNED === 'true' ||
          isLoopbackExactHostname(normalizedUrl);

        const ws = new WebSocket(wsUrl, {
          headers,
          rejectUnauthorized: !allowInsecure,
          handshakeTimeout: 5000
        });
        this.meshWs = ws;

        ws.on('open', () => {
          if (this.meshWs !== ws) return;
          this.isConnected = true;
          this.reconnectAttempts = 0;
          this.lastConnectionError = null;
          try {
            ws.send(JSON.stringify({ action: 'nodes' }));
          } catch {}
          setTimeout(() => {
            if (this.meshWs === ws && this.isConnected) {
              this.resolveConnectWaiters(true);
            }
          }, 150);
          console.log(`[MeshCentralBridge] Connected to live MeshCentral server (${normalizedUrl})`);
        });

        ws.on('message', (raw) => this.handleIncomingMeshFrame(raw, 'primary'));

        ws.on('error', (err) => {
          if (this.meshWs !== ws) return;
          this.isConnected = false;
          this.lastConnectionError = err.message;
          this.resolveConnectWaiters(false);
        });

        ws.on('close', () => {
          if (this.meshWs !== ws) return;
          this.isConnected = false;
          this.resolveConnectWaiters(false);
          this.schedulePrimaryReconnect(serverUrl, apiToken, allowSelfSigned);
        });
      } catch (e: any) {
        this.isConnected = false;
        this.lastConnectionError = e?.message || 'Failed to initialize WebSocket';
        this.resolveConnectWaiters(false);
        this.schedulePrimaryReconnect(serverUrl, apiToken, allowSelfSigned);
      }
    })();
  }

  private initFederatedSocket(serverId: string, serverUrl: string, apiToken: string, allowSelfSigned: boolean) {
    const check = validateMeshServerUrl(serverUrl);
    if (!check.ok || !check.normalized) return;

    const normalizedUrl = check.normalized;
    const epoch = this.configEpoch;
    const entry: FederatedSocketEntry = this.federatedPool.get(serverId) || {
      serverId,
      serverUrl: normalizedUrl,
      ws: null,
      connected: false,
      reconnectAttempts: 0,
      reconnectTimer: null
    };
    entry.serverUrl = normalizedUrl;
    this.federatedPool.set(serverId, entry);

    void (async () => {
      const dnsSafety = await validateOutboundHostSafety(normalizedUrl, {
        allowLoopback: true,
        allowPrivateLan: true
      });
      if (epoch !== this.configEpoch || !this.federatedPool.has(serverId)) return;
      if (!dnsSafety.safe) {
        entry.connected = false;
        return;
      }

      const { wsUrl, headers } = buildMeshWsAuthParams(normalizedUrl, apiToken, check.loginKey);
      const allowInsecure =
        allowSelfSigned ||
        process.env.MESHCENTRAL_ALLOW_SELF_SIGNED === 'true' ||
        isLoopbackExactHostname(normalizedUrl);

      try {
        const ws = new WebSocket(wsUrl, {
          headers,
          rejectUnauthorized: !allowInsecure,
          handshakeTimeout: 5000
        });
        entry.ws = ws;

        ws.on('open', () => {
          entry.connected = true;
          entry.reconnectAttempts = 0;
          try {
            ws.send(JSON.stringify({ action: 'nodes' }));
            db.prepare("UPDATE mesh_servers SET status = 'online', last_synced = ? WHERE id = ?").run(
              new Date().toISOString(),
              serverId
            );
          } catch {}
        });

        ws.on('message', (raw) => this.handleIncomingMeshFrame(raw, serverId));

        ws.on('error', () => {
          entry.connected = false;
        });

        ws.on('close', () => {
          entry.connected = false;
          if (!this.federatedPool.has(serverId)) return;
          const delay = Math.min(30000, 3000 * Math.pow(2, Math.min(4, entry.reconnectAttempts++)));
          entry.reconnectTimer = setTimeout(() => {
            this.initFederatedSocket(serverId, serverUrl, apiToken, allowSelfSigned);
          }, delay);
        });
      } catch {}
    })();
  }

  private getOpenSocketAndServerForNode(meshNodeId?: string): {
    sock: WebSocket | null;
    serverUrl: string | null;
    serverId: string;
    allowSelfSigned: boolean;
  } {
    let settingsAllow = false;
    try {
      const s = db.prepare('SELECT meshcentral_allow_self_signed FROM settings WHERE id = 1').get() as any;
      settingsAllow = Boolean(s?.meshcentral_allow_self_signed);
    } catch {}

    if (meshNodeId) {
      const ownerId = this.nodeServerMap.get(meshNodeId);
      if (ownerId && ownerId !== 'primary') {
        const fed = this.federatedPool.get(ownerId);
        if (fed?.ws && fed.ws.readyState === WebSocket.OPEN) {
          let srvAllow = settingsAllow;
          try {
            const row = db.prepare('SELECT allow_self_signed FROM mesh_servers WHERE id = ?').get(ownerId) as any;
            srvAllow = Boolean(row?.allow_self_signed || settingsAllow);
          } catch {}
          return { sock: fed.ws, serverUrl: fed.serverUrl, serverId: ownerId, allowSelfSigned: srvAllow };
        }
      }
    }
    if (this.meshWs && this.meshWs.readyState === WebSocket.OPEN) {
      return { sock: this.meshWs, serverUrl: this.connectedServerUrl, serverId: 'primary', allowSelfSigned: settingsAllow };
    }
    for (const [fedId, fed] of this.federatedPool) {
      if (fed.ws && fed.ws.readyState === WebSocket.OPEN) {
        return { sock: fed.ws, serverUrl: fed.serverUrl, serverId: fedId, allowSelfSigned: settingsAllow };
      }
    }
    return { sock: null, serverUrl: this.connectedServerUrl, serverId: 'primary', allowSelfSigned: settingsAllow };
  }

  private getOpenSocketForNode(meshNodeId?: string): WebSocket | null {
    return this.getOpenSocketAndServerForNode(meshNodeId).sock;
  }

  public resolveMeshNodeId(deviceId: string): string {
    try {
      const row = db
        .prepare('SELECT mesh_node_id FROM devices WHERE id = ?')
        .get(deviceId) as { mesh_node_id?: string | null } | undefined;
      if (row?.mesh_node_id && row.mesh_node_id.trim()) {
        return row.mesh_node_id.trim();
      }
    } catch {}
    return deviceId;
  }

  public dispatchRpc(payload: Record<string, unknown>): boolean {
    const nodeIds = Array.isArray(payload.nodeids) ? (payload.nodeids as string[]) : undefined;
    const targetNode = (payload.nodeid as string | undefined) || nodeIds?.[0];
    const sock = this.getOpenSocketForNode(targetNode);
    if (sock && sock.readyState === WebSocket.OPEN) {
      try {
        sock.send(JSON.stringify(payload));
        return true;
      } catch {
        return false;
      }
    }
    return false;
  }

  public async createLiveDeviceSessionUrl(params: {
    deviceId: string;
    mode?: 'desktop' | 'terminal' | 'files';
    viewOnly?: boolean;
    durationMinutes?: number;
    guestName?: string;
    requireConsent?: boolean;
  }): Promise<{ live: boolean; url: string | null; serverUrl: string | null; error?: string }> {
    const meshNodeId = this.resolveMeshNodeId(params.deviceId);
    const { sock, serverUrl: matchedServerUrl } = this.getOpenSocketAndServerForNode(meshNodeId);
    if (!sock || sock.readyState !== WebSocket.OPEN) {
      return {
        live: false,
        url: null,
        serverUrl: matchedServerUrl,
        error: this.lastConnectionError || 'MeshCentral live control tunnel is not connected.'
      };
    }

    const responseId = `share-${crypto.randomUUID()}`;
    const pFlag = params.mode === 'terminal' ? 1 : params.mode === 'files' ? 4 : 2;
    const consentFlags = params.requireConsent
      ? pFlag === 2
        ? 0x0008 | 0x0040
        : pFlag === 1
          ? 0x0010
          : 0x0020
      : pFlag === 2
        ? 0x0040
        : 0;
    const expireMinutes = Math.max(5, Math.min(480, Number(params.durationMinutes || 60)));

    const msgPromise = new Promise<any>((resolve) => {
      const timer = setTimeout(() => {
        this.pendingControlWaiters.delete(responseId);
        resolve(null);
      }, 4500);
      this.pendingControlWaiters.set(responseId, { resolve, timer });
    });

    try {
      // Exact MeshCentral 2 meshuser.js schema: lowercase `guestname`, `expire` in minutes!
      sock.send(
        JSON.stringify({
          action: 'createDeviceShareLink',
          nodeid: meshNodeId,
          guestname: String(params.guestName || 'Vitrine Technician').slice(0, 48),
          p: pFlag,
          viewOnly: Boolean(params.viewOnly),
          expire: expireMinutes,
          consent: consentFlags,
          responseid: responseId
        })
      );
    } catch (err: any) {
      this.pendingControlWaiters.delete(responseId);
      return { live: false, url: null, serverUrl: matchedServerUrl, error: err?.message };
    }

    const reply = await msgPromise;
    if (reply && reply.url) {
      let resolvedUrl = String(reply.url);
      if (matchedServerUrl) {
        try {
          if (resolvedUrl.startsWith('/')) {
            resolvedUrl = new URL(resolvedUrl, matchedServerUrl).toString();
          } else {
            const parsedShare = new URL(resolvedUrl);
            const parsedServer = new URL(matchedServerUrl);
            const shareHost = parsedShare.hostname.toLowerCase();
            const serverHost = parsedServer.hostname.toLowerCase();
            if (
              (shareHost === 'localhost' || shareHost === '127.0.0.1') &&
              serverHost !== 'localhost' &&
              serverHost !== '127.0.0.1'
            ) {
              parsedShare.protocol = parsedServer.protocol;
              parsedShare.hostname = parsedServer.hostname;
              parsedShare.port = parsedServer.port;
              resolvedUrl = parsedShare.toString();
            }
          }
        } catch {}
      }
      return {
        live: true,
        url: resolvedUrl,
        serverUrl: matchedServerUrl
      };
    }

    return {
      live: false,
      url: null,
      serverUrl: matchedServerUrl,
      error: reply?.result || 'MeshCentral did not return a device share URL (verify node exists on server and guest sharing is enabled).'
    };
  }

  public getStatus() {
    let activeTunnels = 0;
    let federatedServers = 0;
    try {
      const onlineRow = db
        .prepare("SELECT COUNT(*) as c FROM devices WHERE status = 'online' AND COALESCE(lifecycle_state, 'active') = 'active'")
        .get() as { c: number } | undefined;
      activeTunnels = onlineRow?.c || 0;

      const srvRow = db.prepare('SELECT COUNT(*) as c FROM mesh_servers').get() as { c: number } | undefined;
      federatedServers = srvRow?.c || 0;
    } catch {
      activeTunnels = 0;
    }

    const anyFedConnected = Array.from(this.federatedPool.values()).some((f) => f.connected);

    return {
      connected: this.isConnected || anyFedConnected,
      configured: this.isConfigured || this.federatedPool.size > 0,
      serverUrl: this.connectedServerUrl,
      lastError: this.lastConnectionError,
      engine: 'MeshCentral 2 Micro-Agent Relay + Vitrine Companion',
      version: '2.8.0',
      activeTunnels,
      federatedServers
    };
  }

  public getDeviceOs(deviceId: string): 'windows' | 'linux' | 'macos' {
    try {
      const row = db.prepare('SELECT os_type FROM devices WHERE id = ?').get(deviceId) as { os_type?: string } | undefined;
      if (row?.os_type === 'linux' || row?.os_type === 'macos' || row?.os_type === 'windows') {
        return row.os_type;
      }
    } catch {}
    if (deviceId.includes('mac')) return 'macos';
    if (deviceId.includes('lin')) return 'linux';
    return 'windows';
  }

  private isLocalEnrolledHost(dev: any): boolean {
    if (process.env.VITRINE_ALLOW_LOCAL_SELF_EXEC !== 'true') return false;
    if (!dev || !dev.id || !dev.agent_auth_token) return false;
    const identityPath = '/opt/vitrineagent/agent-identity.json';
    try {
      if (!fs.existsSync(identityPath)) return false;
      const st = fs.lstatSync(identityPath);
      if (st.isSymbolicLink() || !st.isFile()) return false;
      const ident = JSON.parse(fs.readFileSync(identityPath, 'utf8')) as {
        deviceId?: unknown;
        agentAuthToken?: unknown;
        agentToken?: unknown;
      };
      if (!ident || typeof ident.deviceId !== 'string' || ident.deviceId !== String(dev.id)) {
        return false;
      }
      const diskToken =
        typeof ident.agentAuthToken === 'string' && ident.agentAuthToken.length > 0
          ? ident.agentAuthToken
          : typeof ident.agentToken === 'string' && ident.agentToken.length > 0
            ? ident.agentToken
            : '';
      const dbToken = decryptVaultSecret(String(dev.agent_auth_token));
      if (!diskToken || !dbToken) return false;
      const diskBuf = Buffer.from(diskToken, 'utf8');
      const dbBuf = Buffer.from(dbToken, 'utf8');
      if (diskBuf.length !== dbBuf.length) return false;
      return crypto.timingSafeEqual(diskBuf, dbBuf);
    } catch {
      return false;
    }
  }

  private execLocalBash(command: string, envVars?: Record<string, string>, timeoutMs = 8000): Promise<{ exitCode: number; output: string }> {
    return new Promise((resolve) => {
      execFile(
        '/bin/bash',
        ['-c', command],
        {
          timeout: timeoutMs,
          maxBuffer: 2 * 1024 * 1024,
          env: { ...process.env, ...(envVars || {}) }
        },
        (err, stdout, stderr) => {
          const combined = `${stdout || ''}${stderr ? (stdout ? '\n' : '') + stderr : ''}`.trimEnd();
          if (err) {
            const code = typeof (err as any).code === 'number' ? (err as any).code : 1;
            resolve({ exitCode: code, output: combined || err.message });
          } else {
            resolve({ exitCode: 0, output: combined });
          }
        }
      );
    });
  }

  private enqueueNodeCommand<T>(queueKey: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.nodeExecQueues.get(queueKey) || Promise.resolve();
    const run = prev.catch(() => {}).then(fn);
    const tail = run.then(
      () => undefined,
      () => undefined
    );
    this.nodeExecQueues.set(queueKey, tail);
    tail.finally(() => {
      if (this.nodeExecQueues.get(queueKey) === tail) {
        this.nodeExecQueues.delete(queueKey);
      }
    });
    return run;
  }

  // ============================================================================
  // Live Command Execution (MeshCentral 2 WS -> Companion Agent -> Honest Error)
  // ============================================================================
  public async executeCommandOnNode(
    deviceId: string,
    command: string,
    options?: {
      runAs?: 'system' | 'user';
      shell?: string;
      timeoutMs?: number;
      env?: Record<string, string>;
      executionId?: string;
      noQueue?: boolean;
    }
  ): Promise<{ live: boolean; exitCode: number; output: string; queued?: boolean; taskId?: string }> {
    const dev = db
      .prepare(
        'SELECT id, tenant_id, mesh_node_id, hostname, os_type, os_version, ip_address, status, lifecycle_state, agent_auth_token, last_seen FROM devices WHERE id = ?'
      )
      .get(deviceId) as any;

    if (!dev) {
      return {
        live: false,
        exitCode: 1,
        output: `Error: Target device '${deviceId}' does not exist in inventory.`
      };
    }

    if (dev.lifecycle_state === 'archived') {
      return {
        live: false,
        exitCode: 1,
        output: `Error: Endpoint '${dev.hostname}' is archived — live execution is disabled.`
      };
    }

    if (dev.status !== 'online' && dev.status !== 'isolated') {
      return {
        live: false,
        exitCode: 1,
        output: `Endpoint '${dev.hostname}' is currently ${dev.status || 'offline'} — command cannot be delivered until the agent tunnel reconnects.`
      };
    }

    const osType: 'windows' | 'linux' | 'macos' =
      dev.os_type === 'linux' || dev.os_type === 'macos' ? dev.os_type : 'windows';
    const runAs = options?.runAs === 'user' ? 'user' : 'system';
    const shell = options?.shell || (osType === 'macos' ? 'zsh' : osType === 'linux' ? 'bash' : 'powershell');
    const meshNodeId = dev.mesh_node_id || dev.id;
    const timeoutMs = options?.timeoutMs || 12000;

    // Handle Python scripts cleanly across Windows (PowerShell host) and Linux/macOS (bash/zsh host)
    let execCommand = command;
    if (shell === 'python') {
      if (osType === 'windows') {
        const pyB64 = Buffer.from(command, 'utf8').toString('base64');
        execCommand = [
          `$__vPyTmp = Join-Path $env:TEMP ('vitrine-py-' + [guid]::NewGuid().ToString('N') + '.py')`,
          `[IO.File]::WriteAllBytes($__vPyTmp, [Convert]::FromBase64String('${pyB64}'))`,
          `try { if (Get-Command python -ErrorAction SilentlyContinue) { & python $__vPyTmp } elseif (Get-Command python3 -ErrorAction SilentlyContinue) { & python3 $__vPyTmp } elseif (Get-Command py -ErrorAction SilentlyContinue) { & py -3 $__vPyTmp } else { throw 'Python interpreter not found on endpoint' } } finally { Remove-Item -LiteralPath $__vPyTmp -Force -ErrorAction SilentlyContinue }`
        ].join('; ');
      } else {
        const pyDelim = `VITRINE_PY_${crypto.randomBytes(4).toString('hex')}`;
        execCommand = `__VPY=$(command -v python3 || command -v python || true)\n[ -n "$__VPY" ] || { echo "Python interpreter not found on endpoint" >&2; exit 127; }\n"$__VPY" - <<'${pyDelim}'\n${command}\n${pyDelim}`;
      }
    }

    // Build shell-appropriate environment variable assignments (zero code interpolation!)
    let envPrefix = '';
    if (options?.env && Object.keys(options.env).length > 0) {
      const validEnvEntries = Object.entries(options.env).filter(([k]) =>
        /^VITRINE_PARAM_[A-Z0-9_]{1,64}$/.test(k)
      );
      if (validEnvEntries.length > 0) {
        if (osType === 'windows' && shell === 'cmd') {
          const cmdEnv = validEnvEntries
            .map(([k, v]) => `set "${k}=${String(v).replace(/[\r\n\0"]/g, '')}"`)
            .join(' & ');
          envPrefix = `${cmdEnv} & `;
        } else if (osType === 'windows') {
          const psEnv = validEnvEntries
            .map(([k, v]) => `$env:${k} = ${quotePowerShellLiteral(String(v))}`)
            .join('; ');
          envPrefix = `${psEnv}; `;
        } else {
          const shEnv = validEnvEntries
            .map(([k, v]) => `export ${k}=${quoteBashLiteral(String(v))}`)
            .join('; ');
          envPrefix = `${shEnv}\n`;
        }
      }
    }

    // 1. Live MeshCentral 2 `/control.ashx` (`runcommands` serialized per-node via `enqueueNodeCommand` so MeshAgent never rejects concurrent commands)
    const isGenuineMeshNode = !meshNodeId.startsWith('node//dev-') || this.nodeServerMap.has(meshNodeId);
    const sock = isGenuineMeshNode ? this.getOpenSocketForNode(meshNodeId) : null;
    if (sock && sock.readyState === WebSocket.OPEN && dev.mesh_node_id && isGenuineMeshNode) {
      const runLiveOnce = async () =>
        this.enqueueNodeCommand(meshNodeId, async () => {
          const activeSock = this.getOpenSocketForNode(meshNodeId);
          if (!activeSock || activeSock.readyState !== WebSocket.OPEN) return null;

          const responseId = `cmd-${crypto.randomUUID()}`;
          const cmdType = osType === 'windows' ? (shell === 'cmd' ? 1 : 2) : 3;
          let sentinelCommand = '';

          if (osType === 'windows' && cmdType === 1) {
            const cleanCmd = execCommand.includes('\n') ? execCommand.replace(/\r?\n/g, ' & ') : execCommand;
            sentinelCommand = `@echo off & ${envPrefix}${cleanCmd} & call echo __VITRINE_RC:%%ERRORLEVEL%%:${responseId}`;
          } else if (osType === 'windows') {
            // MeshCentral Windows PowerShell runcommands spawns `powershell.exe -command -` on stdin
            // without closing stdin until `exit`; multi-line blocks hang stdin, and `"$__vRc:${id}"` parses
            // `$__vRc:` as a scope drive. Keep every dispatched `cmds` payload strictly single-line.
            const needsTempPsFile =
              /[\r\n]/.test(execCommand) ||
              /#/.test(execCommand) ||
              /(?:^|[\s;{}|&])exit(?:\s|$|;)/i.test(execCommand);

            if (!needsTempPsFile) {
              sentinelCommand = `${envPrefix}$global:LASTEXITCODE = 0; $__vErr = $false; try { & { ${execCommand} } } catch { $__vErr = $true; [Console]::Error.WriteLine($_.Exception.Message) }; $__vRc = if ($__vErr) { if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { [int]$LASTEXITCODE } else { 1 } } elseif ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { [int]$LASTEXITCODE } elseif (-not $?) { 1 } else { 0 }; Write-Output ('__VITRINE_RC:' + $__vRc + ':${responseId}')`;
            } else {
              const utf8BomBytes = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(execCommand, 'utf8')]);
              const psB64 = utf8BomBytes.toString('base64');
              sentinelCommand = `${envPrefix}$__vTmp = Join-Path $env:TEMP ('vitrine-run-' + [guid]::NewGuid().ToString('N') + '.ps1'); $__vRc = 0; try { [IO.File]::WriteAllBytes($__vTmp, [Convert]::FromBase64String('${psB64}')); & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $__vTmp; $__vRc = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { if (-not $?) { 1 } else { 0 } } } catch { $__vRc = 1; [Console]::Error.WriteLine($_.Exception.Message) } finally { if (Test-Path -LiteralPath $__vTmp) { Remove-Item -LiteralPath $__vTmp -Force -ErrorAction SilentlyContinue } }; Write-Output ('__VITRINE_RC:' + $__vRc + ':${responseId}')`;
            }
          } else {
            // Wrap in a subshell `( ... )` so `set -e` / `exit N` inside the script never skips `__VITRINE_RC`
            sentinelCommand = `(\n${envPrefix}${execCommand}\n); __vitrine_rc=$?; echo "__VITRINE_RC:$__vitrine_rc:${responseId}"`;
          }

          const replyPromise = new Promise<{ output: string; exitCode: number } | null>((resolve) => {
            const timer = setTimeout(() => {
              this.pendingCmdWaiters.delete(responseId);
              resolve(null);
            }, timeoutMs);
            this.pendingCmdWaiters.set(responseId, {
              resolve: (res) => resolve(res),
              timer,
              nodeId: meshNodeId,
              consoleBuffer: ''
            });
          });

          try {
            activeSock.send(
              JSON.stringify({
                action: 'runcommands',
                nodeids: [meshNodeId],
                type: cmdType,
                runAsUser: runAs === 'user' ? 1 : 0,
                cmds: sentinelCommand,
                reply: true,
                responseid: responseId
              })
            );
            return await replyPromise;
          } catch {
            this.pendingCmdWaiters.delete(responseId);
            return null;
          }
        });

      let liveRes = await runLiveOnce();
      for (let attempt = 0; attempt < 3 && liveRes !== null; attempt++) {
        const isBusy = /already busy/i.test(liveRes.output || '');
        const missingJsonDelim =
          execCommand.includes('__VJ_START__') &&
          liveRes.exitCode === 0 &&
          !liveRes.output.includes('__VJ_START__');
        if (!isBusy && !missingJsonDelim) break;
        await new Promise((r) => setTimeout(r, 350 * (attempt + 1)));
        liveRes = await runLiveOnce();
      }

      if (liveRes !== null) {
        return { live: true, exitCode: liveRes.exitCode, output: liveRes.output };
      }
    }

    // 1b. Persistent Vitrine Agent WebSocket Hub (WSS direct RPC without MeshCentral dependency)
    if (agentSocketHub.isConnected(dev.id)) {
      const wsRes = await agentSocketHub.executeRpcCommand(dev.id, {
        command: `${envPrefix}${execCommand}`,
        shell,
        timeoutMs
      });
      if (wsRes !== null) {
        return wsRes;
      }
    }

    // 2. Enrolled Local Host Companion Fast-Path (executes directly on local Linux host when strictly enabled & verified)
    if (os.platform() === 'linux' && osType === 'linux' && this.isLocalEnrolledHost(dev)) {
      const localRes = await this.execLocalBash(execCommand, options?.env, timeoutMs);
      return {
        live: true,
        exitCode: localRes.exitCode,
        output: localRes.output
      };
    }

    // 3. Enrolled Remote Vitrine Companion Agent Queue (`agent_tasks`)
    if (dev.agent_auth_token && !options?.noQueue) {
      const taskId = `task-cmd-${crypto.randomUUID()}`;
      const taskPayloadJson = JSON.stringify({
        executionId: options?.executionId || undefined,
        language: shell,
        shell,
        code: command,
        env: options?.env || {},
        runAs,
        timeoutSec: Math.ceil(timeoutMs / 1000)
      });
      db.prepare(`
        INSERT INTO agent_tasks (id, device_id, tenant_id, task_type, payload_json, status)
        VALUES (?, ?, ?, 'script', ?, 'queued')
      `).run(
        taskId,
        dev.id,
        dev.tenant_id || null,
        taskPayloadJson
      );
      agentSocketHub.dispatchTaskIfConnected(dev.id, {
        id: taskId,
        task_type: 'script',
        payload_json: taskPayloadJson
      });

      // Poll briefly in case Companion checks in during interactive window
      const deadline = Date.now() + Math.min(timeoutMs, 500);
      while (Date.now() < deadline) {
        const row = db
          .prepare('SELECT status, exit_code, stdout, stderr, result_json FROM agent_tasks WHERE id = ?')
          .get(taskId) as any;
        if (row && (row.status === 'completed' || row.status === 'failed')) {
          let stdoutText = String(row.stdout || '');
          let stderrText = String(row.stderr || '');
          let fallbackExit: number | undefined;
          if (!stdoutText && !stderrText && row.result_json) {
            try {
              const parsed = JSON.parse(String(row.result_json));
              stdoutText = String(parsed?.stdout ?? parsed?.output ?? '');
              stderrText = String(parsed?.stderr ?? '');
              if (typeof parsed?.exitCode === 'number') {
                fallbackExit = parsed.exitCode;
              }
            } catch {}
          }
          const combined = `${stdoutText}${stderrText ? (stdoutText ? '\n' : '') + stderrText : ''}`.trim();
          return {
            live: true,
            taskId,
            exitCode: Number(row.exit_code ?? fallbackExit ?? (row.status === 'completed' ? 0 : 1)),
            output: combined
          };
        }
        await new Promise((r) => setTimeout(r, 125));
      }

      return {
        live: false,
        queued: true,
        taskId,
        exitCode: -1,
        output: 'Command queued for Companion Agent check-in.'
      };
    }

    return {
      live: false,
      exitCode: 1,
      output: `[Tunnel Unavailable] Neither a live MeshCentral 2 session nor an enrolled Vitrine Companion Agent is connected for '${dev.hostname}'. Connect MeshCentral in Settings or enroll the endpoint agent to run live commands.`
    };
  }

  public async openInteractiveTerminalRelay(
    deviceId: string,
    opts: {
      runAs: 'system' | 'user';
      shell: string;
      cols?: number;
      rows?: number;
      onData: (chunk: string) => void;
      onReady?: (info: { protocol: number; recorded: boolean }) => void;
      onClose?: (reason?: string) => void;
      onError?: (err: string) => void;
    }
  ): Promise<{ write: (data: string) => void; resize: (cols: number, rows: number) => void; close: () => void } | null> {
    const dev = db
      .prepare('SELECT id, mesh_node_id, os_type, status, lifecycle_state FROM devices WHERE id = ?')
      .get(deviceId) as any;
    if (!dev || dev.lifecycle_state === 'archived' || (dev.status !== 'online' && dev.status !== 'isolated')) {
      return null;
    }

    const meshNodeId = dev.mesh_node_id || dev.id;
    const isGenuineMeshNode = !meshNodeId.startsWith('node//dev-') || this.nodeServerMap.has(meshNodeId);
    if (!isGenuineMeshNode || !dev.mesh_node_id) {
      return null;
    }

    const { sock, serverUrl, serverId, allowSelfSigned } = this.getOpenSocketAndServerForNode(meshNodeId);
    if (!sock || sock.readyState !== WebSocket.OPEN || !serverUrl) {
      return null;
    }

    const cookiePair = await new Promise<{ cookie: string; rcookie: string } | null>((resolve) => {
      const timer = setTimeout(() => {
        const list = this.pendingAuthCookieWaiters.get(serverId) || [];
        const idx = list.findIndex((x) => x.resolve === resolve);
        if (idx >= 0) list.splice(idx, 1);
        resolve(null);
      }, 4500);
      const list = this.pendingAuthCookieWaiters.get(serverId) || [];
      list.push({ resolve, timer });
      this.pendingAuthCookieWaiters.set(serverId, list);
      try {
        sock.send(JSON.stringify({ action: 'authcookie' }));
      } catch {
        clearTimeout(timer);
        list.pop();
        resolve(null);
      }
    });

    if (!cookiePair) {
      opts.onError?.('MeshCentral did not issue an authcookie for terminal relay.');
      return null;
    }

    const osType = dev.os_type === 'linux' || dev.os_type === 'macos' ? dev.os_type : 'windows';
    const protocol =
      osType === 'windows'
        ? opts.runAs === 'user'
          ? opts.shell === 'cmd'
            ? 8
            : 9
          : opts.shell === 'cmd'
            ? 1
            : 6
        : 1;
    const tunnelId = crypto.randomBytes(6).toString('hex');
    const allowInsecure =
      allowSelfSigned ||
      process.env.MESHCENTRAL_ALLOW_SELF_SIGNED === 'true' ||
      isLoopbackExactHostname(serverUrl);
    const wsOrigin = serverUrl.replace(/^http/i, 'ws').replace(/\/$/, '');
    const relayUrl = `${wsOrigin}/meshrelay.ashx?browser=1&p=${protocol}&nodeid=${encodeURIComponent(meshNodeId)}&id=${tunnelId}&auth=${encodeURIComponent(cookiePair.cookie)}`;

    // Instruct MeshCentral agent to join the rendezvous tunnel on `meshrelay.ashx`
    try {
      sock.send(
        JSON.stringify({
          action: 'msg',
          nodeid: meshNodeId,
          type: 'tunnel',
          usage: 1,
          value: `*/meshrelay.ashx?p=${protocol}&nodeid=${meshNodeId}&id=${tunnelId}&rauth=${cookiePair.rcookie}`
        })
      );
    } catch (err: any) {
      opts.onError?.(err?.message || 'Failed to signal agent tunnel');
      return null;
    }

    return await new Promise((resolve) => {
      let state = 0;
      let resolvedHandle = false;
      let closed = false;
      const relayWs = new WebSocket(relayUrl, {
        rejectUnauthorized: !allowInsecure,
        handshakeTimeout: 8000
      });

      const handle = {
        write: (data: string) => {
          if (closed || state !== 1 || relayWs.readyState !== WebSocket.OPEN) return;
          try {
            relayWs.send(Buffer.from(data, 'utf8'));
          } catch {}
        },
        resize: (cols: number, rows: number) => {
          if (closed || state !== 1 || relayWs.readyState !== WebSocket.OPEN) return;
          try {
            relayWs.send(
              JSON.stringify({
                ctrlChannel: '102938',
                type: 'termsize',
                cols: Math.max(20, Math.min(400, Number(cols) || 80)),
                rows: Math.max(8, Math.min(200, Number(rows) || 24))
              })
            );
          } catch {}
        },
        close: () => {
          if (closed) return;
          closed = true;
          try {
            relayWs.close();
          } catch {}
        }
      };

      const connectTimeout = setTimeout(() => {
        if (!resolvedHandle) {
          resolvedHandle = true;
          handle.close();
          resolve(null);
        }
      }, 8000);

      relayWs.on('message', (raw) => {
        const text = raw.toString('utf8');
        if (state === 0) {
          if (text !== 'c' && text !== 'cr') return;
          state = 1;
          clearTimeout(connectTimeout);
          try {
            relayWs.send(
              JSON.stringify({
                ctrlChannel: '102938',
                type: 'options',
                cols: Math.max(20, Math.min(400, Number(opts.cols) || 100)),
                rows: Math.max(8, Math.min(200, Number(opts.rows) || 30))
              })
            );
            relayWs.send(String(protocol));
          } catch {}
          opts.onReady?.({ protocol, recorded: text === 'cr' });
          if (!resolvedHandle) {
            resolvedHandle = true;
            resolve(handle);
          }
          return;
        }

        if (text.startsWith('{"ctrlChannel":"102938"')) {
          try {
            const ctrl = JSON.parse(text);
            if (ctrl?.ctrlChannel === '102938' && ctrl?.type) return;
          } catch {}
        }
        opts.onData(text);
      });

      relayWs.on('error', (err) => {
        clearTimeout(connectTimeout);
        opts.onError?.(err.message);
        if (!resolvedHandle) {
          resolvedHandle = true;
          resolve(null);
        }
      });

      relayWs.on('close', () => {
        clearTimeout(connectTimeout);
        closed = true;
        if (!resolvedHandle) {
          resolvedHandle = true;
          resolve(null);
        } else {
          opts.onClose?.('Relay tunnel closed');
        }
      });
    });
  }

  public async enrichDeviceFromMesh(deviceId: string): Promise<{ updated: boolean; fields: Record<string, unknown> }> {
    if (this.enrichingNodes.has(deviceId)) return { updated: false, fields: {} };
    this.enrichingNodes.add(deviceId);
    try {
      const dev = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId) as any;
      if (!dev?.mesh_node_id) return { updated: false, fields: {} };
      const meshNodeId = String(dev.mesh_node_id);
      const sock = this.getOpenSocketForNode(meshNodeId);
      if (!sock || sock.readyState !== WebSocket.OPEN) return { updated: false, fields: {} };

      const waitSys = new Promise<any>((resolve) => {
        const timer = setTimeout(() => {
          const list = this.pendingSysInfoWaiters.get(meshNodeId) || [];
          const idx = list.findIndex((x) => x.resolve === resolve);
          if (idx >= 0) list.splice(idx, 1);
          resolve(null);
        }, 3500);
        const list = this.pendingSysInfoWaiters.get(meshNodeId) || [];
        list.push({ resolve, timer });
        this.pendingSysInfoWaiters.set(meshNodeId, list);
      });

      const waitNet = new Promise<any>((resolve) => {
        const timer = setTimeout(() => {
          const list = this.pendingNetInfoWaiters.get(meshNodeId) || [];
          const idx = list.findIndex((x) => x.resolve === resolve);
          if (idx >= 0) list.splice(idx, 1);
          resolve(null);
        }, 3500);
        const list = this.pendingNetInfoWaiters.get(meshNodeId) || [];
        list.push({ resolve, timer });
        this.pendingNetInfoWaiters.set(meshNodeId, list);
      });

      try {
        sock.send(JSON.stringify({ action: 'getsysinfo', nodeid: meshNodeId, nodeinfo: true }));
        sock.send(JSON.stringify({ action: 'getnetworkinfo', nodeid: meshNodeId }));
      } catch {
        return { updated: false, fields: {} };
      }

      const [sysDoc, netDoc] = await Promise.all([waitSys, waitNet]);
      const extracted = extractSysInfoAndNetInfo(sysDoc, netDoc);
      const base = sysDoc?.node ? extractBaseNodeFields(sysDoc.node) : {};
      const merged: any = { ...base, ...extracted };

      if (dev.os_type === 'linux' && !merged.cpuCores && !dev.cpu_cores) {
        try {
          const coreRes = await this.executeCommandOnNode(
            deviceId,
            'nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null',
            { runAs: 'system', timeoutMs: 5000, noQueue: true }
          );
          const nCores = Number(String(coreRes.output || '').trim().split(/\s+/)[0] || 0);
          if (Number.isInteger(nCores) && nCores > 0 && nCores <= 1024) {
            merged.cpuCores = nCores;
            if (!merged.hardwareDetails) merged.hardwareDetails = {};
            if (!merged.hardwareDetails.cpu) merged.hardwareDetails.cpu = {};
            merged.hardwareDetails.cpu.logicalCores = nCores;
          }
        } catch {}
      }

      if (merged.hardwareDetails) {
        merged.hardwareDetails.lastHardwareScanAt = new Date().toISOString();
      }

      const hasUseful = Boolean(
        merged.serialNumber ||
          merged.manufacturer ||
          merged.model ||
          merged.cpuModel ||
          merged.cpuCores ||
          merged.macAddress ||
          merged.biosVersion ||
          merged.ramTotalGb ||
          merged.diskTotalGb ||
          merged.intelAmtEnabled ||
          merged.amtSupported
      );
      if (!hasUseful) return { updated: false, fields: merged };

      const existingHwRow = db.prepare('SELECT hardware_details_json FROM devices WHERE id = ?').get(deviceId) as
        | { hardware_details_json?: string }
        | undefined;
      const nextHardwareDetailsJson = merged.hardwareDetails
        ? mergeHardwareDetailsJson(existingHwRow?.hardware_details_json, merged.hardwareDetails)
        : existingHwRow?.hardware_details_json || '{}';

      db.prepare(`
        UPDATE devices
        SET serial_number = CASE WHEN ? != '' THEN ? ELSE serial_number END,
            manufacturer = CASE WHEN ? != '' THEN ? ELSE manufacturer END,
            model = CASE WHEN ? != '' THEN ? ELSE model END,
            cpu_model = CASE WHEN ? != '' THEN ? ELSE cpu_model END,
            cpu_cores = CASE WHEN ? > 0 THEN ? ELSE cpu_cores END,
            ram_total_gb = CASE WHEN ? > 0 THEN ? ELSE ram_total_gb END,
            ram_used_gb = CASE WHEN ? > 0 THEN ? ELSE ram_used_gb END,
            disk_total_gb = CASE WHEN ? > 0 THEN ? ELSE disk_total_gb END,
            disk_free_gb = CASE WHEN ? >= 0 THEN ? ELSE disk_free_gb END,
            mac_address = CASE WHEN ? != '' THEN ? ELSE mac_address END,
            ip_address = CASE WHEN ? != '' THEN ? ELSE ip_address END,
            bios_version = CASE WHEN ? != '' THEN ? ELSE bios_version END,
            tpm_version = CASE WHEN ? != '' THEN ? ELSE tpm_version END,
            os_build = CASE WHEN ? != '' THEN ? ELSE os_build END,
            amt_supported = CASE WHEN ? = 1 THEN 1 ELSE amt_supported END,
            intel_amt_enabled = CASE WHEN ? = 1 THEN 1 ELSE intel_amt_enabled END,
            amt_provisioned = CASE WHEN ? = 1 THEN 1 ELSE amt_provisioned END,
            amt_version = CASE WHEN ? != '' THEN ? ELSE amt_version END,
            hardware_details_json = ?
        WHERE id = ?
      `).run(
        merged.serialNumber || '',
        merged.serialNumber || '',
        merged.manufacturer || '',
        merged.manufacturer || '',
        merged.model || '',
        merged.model || '',
        merged.cpuModel || '',
        merged.cpuModel || '',
        merged.cpuCores || 0,
        merged.cpuCores || 0,
        merged.ramTotalGb || 0,
        merged.ramTotalGb || 0,
        merged.ramUsedGb || 0,
        merged.ramUsedGb || 0,
        merged.diskTotalGb || 0,
        merged.diskTotalGb || 0,
        merged.diskFreeGb != null ? merged.diskFreeGb : -1,
        merged.diskFreeGb != null ? merged.diskFreeGb : -1,
        merged.macAddress || '',
        merged.macAddress || '',
        merged.ipAddress || '',
        merged.ipAddress || '',
        merged.biosVersion || '',
        merged.biosVersion || '',
        merged.tpmVersion || '',
        merged.tpmVersion || '',
        merged.osBuild || '',
        merged.osBuild || '',
        merged.amtSupported ? 1 : 0,
        merged.intelAmtEnabled ? 1 : 0,
        merged.amtProvisioned ? 1 : 0,
        merged.amtVersion || '',
        merged.amtVersion || '',
        nextHardwareDetailsJson,
        deviceId
      );

      return { updated: true, fields: merged };
    } finally {
      this.enrichingNodes.delete(deviceId);
    }
  }

  public async sampleLiveTelemetry(
    deviceId: string,
    options?: { includeDetailedHardware?: boolean; forceHistoryInsert?: boolean }
  ): Promise<{ sampled: boolean; sample?: any; reason?: string }> {
    const dedupeKey = `${deviceId}:${options?.includeDetailedHardware ? 'full' : 'quick'}`;
    const existingFlight = this.liveTelemetryInFlight.get(dedupeKey);
    if (existingFlight) {
      return await existingFlight;
    }

    const work = (async (): Promise<{ sampled: boolean; sample?: any; reason?: string }> => {
      const dev = db
        .prepare('SELECT id, mesh_node_id, os_type, status, lifecycle_state FROM devices WHERE id = ?')
        .get(deviceId) as any;
      if (!dev) return { sampled: false, reason: 'Device not found' };
      if ((dev.lifecycle_state || 'active') !== 'active') return { sampled: false, reason: 'Device archived' };
      if (dev.status !== 'online' && dev.status !== 'isolated') {
        return { sampled: false, reason: `Device is ${dev.status || 'offline'}` };
      }
      if (!dev.mesh_node_id) {
        return { sampled: false, reason: 'No remote engine node ID assigned' };
      }

      const sock = this.getOpenSocketForNode(String(dev.mesh_node_id));
      if (!sock || sock.readyState !== WebSocket.OPEN) {
        return { sampled: false, reason: 'Remote engine bridge is disconnected' };
      }

      const osType = dev.os_type === 'macos' ? 'macos' : dev.os_type === 'linux' ? 'linux' : 'windows';
      const detailed = Boolean(options?.includeDetailedHardware);
      let script = '';

      if (osType === 'windows') {
        const psDetailed = detailed
          ? `
$mods = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue | ForEach-Object { @{ slot = [string]$_.DeviceLocator; capacityGb = [Math]::Round(($_.Capacity / 1GB), 2); speedMhz = [int]$_.ConfiguredClockSpeed; manufacturer = ([string]$_.Manufacturer).Trim(); partNumber = ([string]$_.PartNumber).Trim() } })
$disks = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | ForEach-Object { @{ name = [string]$_.DeviceID; model = [string]$_.Model; sizeGb = [Math]::Round(($_.Size / 1GB), 1); interfaceType = [string]$_.InterfaceType; status = [string]$_.Status } })
$gpus = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | ForEach-Object { @{ name = [string]$_.Name; vramMb = if ($_.AdapterRAM) { [Math]::Round($_.AdapterRAM / 1MB, 0) } else { $null }; driverVersion = [string]$_.DriverVersion } })
$bb = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue | Select-Object -First 1
$bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -First 1
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object -First 1
$enc = Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue | Select-Object -First 1
$chassis = if ($enc -and $enc.ChassisTypes) { [int]$enc.ChassisTypes[0] } else { 0 }
$hasBat = (@(Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue).Count -gt 0)
$osProd = switch ([int]$os.ProductType) { 2 { 'domain_controller' } 3 { 'server' } default { 'workstation' } }
$isHvHost = ($osProd -eq 'server' -and (Get-Service -Name vmms -ErrorAction SilentlyContinue) -ne $null)
$cpuObj = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
$nics = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue | ForEach-Object { @{ name = [string]$_.Description; mac = [string]$_.MACAddress; ipv4 = if ($_.IPAddress) { [string]$_.IPAddress[0] } else { $null } } })
$hw = @{
  system = @{
    manufacturer = [string]$cs.Manufacturer; model = [string]$cs.Model; serialNumber = [string]$bios.SerialNumber;
    motherboardVendor = [string]$bb.Manufacturer; motherboardName = [string]$bb.Product; motherboardSerial = [string]$bb.SerialNumber;
    biosVendor = [string]$bios.Manufacturer; biosVersion = [string]$bios.SMBIOSBIOSVersion; biosDate = if ($bios.ReleaseDate) { ([string]$bios.ReleaseDate).Substring(0, [Math]::Min(10, ([string]$bios.ReleaseDate).Length)) } else { '' };
    chassisType = $chassis; hasBattery = $hasBat; osProductType = $osProd; isHypervisorHost = $isHvHost
  };
  cpu = @{ model = [string]$cpuObj.Name; physicalCores = [int]$cpuObj.NumberOfCores; logicalCores = [int]$cpuObj.NumberOfLogicalProcessors; maxClockMhz = [int]$cpuObj.MaxClockSpeed };
  memory = @{ totalGb = $ramTotalGb; modules = $mods };
  storage = @{ physicalDisks = $disks; volumes = $vols };
  gpus = $gpus;
  networkAdapters = $nics
}
`
          : `$hw = @{ storage = @{ volumes = $vols } }`;
        script = `
$ErrorActionPreference = 'SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
$cpuLoad = [double]((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average)
$ramTotalGb = if ($os -and $os.TotalVisibleMemorySize -gt 0) { [Math]::Round($os.TotalVisibleMemorySize / 1048576, 2) } else { 0 }
$ramUsedGb = if ($os -and $os.TotalVisibleMemorySize -gt 0) { [Math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1048576, 2) } else { 0 }
$vols = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Where-Object { $_.Size -gt 0 } | ForEach-Object { @{ mount = [string]$_.DeviceID; label = [string]$_.VolumeName; filesystem = [string]$_.FileSystem; totalGb = [Math]::Round($_.Size / 1GB, 2); freeGb = [Math]::Round($_.FreeSpace / 1GB, 2); usedPct = [Math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100, 1) } })
$diskTotalGb = [Math]::Round((($vols | Measure-Object -Property totalGb -Sum).Sum), 2)
$diskFreeGb = [Math]::Round((($vols | Measure-Object -Property freeGb -Sum).Sum), 2)
$uptimeSec = if ($os -and $os.LastBootUpTime) { [int][Math]::Max(0, ((Get-Date) - $os.LastBootUpTime).TotalSeconds) } else { 0 }
$loggedUser = [string](Get-CimInstance Win32_ComputerSystem).UserName
$rxMbps = 0.0; $txMbps = 0.0
try {
  $n1 = Get-CimInstance Win32_PerfRawData_Tcpip_NetworkInterface -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 1000
  $n2 = Get-CimInstance Win32_PerfRawData_Tcpip_NetworkInterface -ErrorAction SilentlyContinue
  $rx1 = ($n1 | Measure-Object -Property BytesReceivedPersec -Sum).Sum; $tx1 = ($n1 | Measure-Object -Property BytesSentPersec -Sum).Sum
  $rx2 = ($n2 | Measure-Object -Property BytesReceivedPersec -Sum).Sum; $tx2 = ($n2 | Measure-Object -Property BytesSentPersec -Sum).Sum
  $rxMbps = [Math]::Round(([Math]::Max(0, $rx2 - $rx1) * 8) / 1000000.0, 3)
  $txMbps = [Math]::Round(([Math]::Max(0, $tx2 - $tx1) * 8) / 1000000.0, 3)
} catch {}
${psDetailed}
$out = @{ cpuUsage = $cpuLoad; ramUsedGb = $ramUsedGb; ramTotalGb = $ramTotalGb; diskFreeGb = $diskFreeGb; diskTotalGb = $diskTotalGb; netRxMbps = $rxMbps; netTxMbps = $txMbps; uptimeSeconds = $uptimeSec; loggedInUser = $loggedUser; hardwareDetails = $hw } | ConvertTo-Json -Depth 6 -Compress
Write-Output "__VJ_START__$out__VJ_END__"
`.trim();
      } else if (osType === 'linux') {
        const pyScript = `
import json, os, subprocess, time
def read_cpu():
    try:
        with open('/proc/stat') as f:
            cols = [int(x) for x in f.readline().split()[1:]]
        idle = cols[3] + (cols[4] if len(cols) > 4 else 0)
        return idle, sum(cols)
    except Exception:
        return None
def read_net():
    rx = tx = 0
    try:
        with open('/proc/net/dev') as f:
            for ln in f.readlines()[2:]:
                if ':' not in ln: continue
                iface, rest = ln.split(':', 1)
                if iface.strip() == 'lo': continue
                c = rest.split()
                if len(c) >= 9:
                    rx += int(c[0]); tx += int(c[8])
    except Exception:
        pass
    return rx, tx
c1 = read_cpu(); n1 = read_net()
time.sleep(1.0)
c2 = read_cpu(); n2 = read_net()
cpu = 0.0
if c1 and c2 and c2[1] > c1[1]:
    cpu = round((1.0 - (c2[0] - c1[0]) / float(c2[1] - c1[1])) * 100.0, 1)
else:
    try:
        cpu = round(min(100.0, (os.getloadavg()[0] / max(1, os.cpu_count() or 1)) * 100.0), 1)
    except Exception:
        pass
rx_mbps = round(max(0, n2[0] - n1[0]) * 8 / 1000000.0, 3)
tx_mbps = round(max(0, n2[1] - n1[1]) * 8 / 1000000.0, 3)
mem = {}
try:
    with open('/proc/meminfo') as f:
        for ln in f:
            if ':' in ln:
                k, v = ln.split(':', 1)
                mem[k.strip()] = int(v.strip().split()[0])
except Exception:
    pass
mt = mem.get('MemTotal', 0)
ma = mem.get('MemAvailable', mem.get('MemFree', 0) + mem.get('Buffers', 0) + mem.get('Cached', 0))
ram_total = round(mt / 1048576.0, 2) if mt > 0 else 0
ram_used = round(max(0, mt - ma) / 1048576.0, 2) if mt > 0 else 0
vols = []; d_tot = 0.0; d_free = 0.0
try:
    df = subprocess.check_output(['df', '-B1', '-PT', '-x', 'tmpfs', '-x', 'devtmpfs', '-x', 'squashfs', '-x', 'overlay'], text=True, timeout=4)
    seen_dev = set()
    for ln in df.splitlines()[1:]:
        p = ln.split()
        if len(p) >= 7:
            devn, fst, tot, used, avail, pct, mnt = p[0], p[1], int(p[2]), int(p[3]), int(p[4]), p[5], p[6]
            if devn in seen_dev or tot <= 0: continue
            seen_dev.add(devn)
            t_gb = round(tot / (1024.0**3), 2); f_gb = round(avail / (1024.0**3), 2)
            d_tot += t_gb; d_free += f_gb
            vols.append({'mount': mnt, 'label': devn, 'filesystem': fst, 'totalGb': t_gb, 'freeGb': f_gb, 'usedPct': round(((tot - avail) / float(tot)) * 100.0, 1)})
except Exception:
    pass
if not vols:
    try:
        st = os.statvfs('/')
        if st.f_blocks > 0:
            d_tot = round((st.f_blocks * st.f_frsize) / (1024.0**3), 2)
            d_free = round((st.f_bavail * st.f_frsize) / (1024.0**3), 2)
            vols.append({'mount': '/', 'totalGb': d_tot, 'freeGb': d_free, 'usedPct': round(((d_tot - d_free)/max(0.01, d_tot))*100.0, 1)})
    except Exception:
        pass
up = 0
try:
    with open('/proc/uptime') as f: up = int(float(f.read().split()[0]))
except Exception:
    pass
luser = ''
try:
    w = subprocess.check_output(['who'], text=True, timeout=3).splitlines()
    if w: luser = w[0].split()[0]
except Exception:
    pass
hw = {'storage': {'volumes': vols}}
if ${detailed ? 'True' : 'False'}:
    def rf(p):
        try:
            with open(p) as f: return f.read().strip()
        except Exception: return ''
    cpu_mdl = ''; cores = os.cpu_count() or 0
    try:
        with open('/proc/cpuinfo') as f:
            for ln in f:
                if ln.lower().startswith('model name') and ':' in ln and not cpu_mdl:
                    cpu_mdl = ln.split(':', 1)[1].strip()
    except Exception:
        pass
    disks = []
    try:
        lb = json.loads(subprocess.check_output(['lsblk', '-b', '-d', '-o', 'NAME,MODEL,SIZE,TRAN', '-J'], text=True, timeout=4))
        for b in lb.get('blockdevices', []):
            sz = int(b.get('size') or 0)
            if sz > 0:
                disks.append({'name': '/dev/' + str(b.get('name','')), 'model': str(b.get('model') or b.get('name') or '').strip(), 'sizeGb': round(sz / (1024.0**3), 1), 'interfaceType': str(b.get('tran') or '')})
    except Exception:
        pass
    gpus = []
    try:
        lp = subprocess.check_output(['lspci'], text=True, timeout=4)
        for ln in lp.splitlines():
            if 'VGA compatible controller' in ln or '3D controller' in ln:
                gpus.append({'name': ln.split(':', 2)[-1].strip()})
    except Exception:
        pass
    nics = []
    try:
        ipj = json.loads(subprocess.check_output(['ip', '-j', 'addr'], text=True, timeout=4))
        for iface in ipj:
            if iface.get('ifname') == 'lo': continue
            ip4 = ''
            for ai in iface.get('addr_info', []):
                if ai.get('family') == 'inet' and not ip4: ip4 = ai.get('local','')
            nics.append({'name': iface.get('ifname',''), 'mac': (iface.get('address') or '').upper(), 'ipv4': ip4})
    except Exception:
        pass
    hw['system'] = {
      'manufacturer': rf('/sys/class/dmi/id/sys_vendor'),
      'model': rf('/sys/class/dmi/id/product_name'),
      'serialNumber': rf('/sys/class/dmi/id/product_serial'),
      'motherboardVendor': rf('/sys/class/dmi/id/board_vendor'),
      'motherboardName': rf('/sys/class/dmi/id/board_name'),
      'biosVendor': rf('/sys/class/dmi/id/bios_vendor'),
      'biosVersion': rf('/sys/class/dmi/id/bios_version'),
      'biosDate': rf('/sys/class/dmi/id/bios_date')
    }
    try:
        ct_raw = rf('/sys/class/dmi/id/chassis_type')
        if ct_raw: hw['system']['chassisType'] = int(ct_raw)
    except Exception: pass
    has_bat = False
    try:
        if os.path.isdir('/sys/class/power_supply'):
            has_bat = any(n.startswith('BAT') for n in os.listdir('/sys/class/power_supply'))
    except Exception: pass
    hw['system']['hasBattery'] = has_bat
    is_vm = False; hv_vendor = ''
    try:
        dv = subprocess.check_output(['systemd-detect-virt', '--vm'], text=True, timeout=2).strip()
        if dv and dv != 'none':
            is_vm = True; hv_vendor = dv
    except Exception:
        if 'hypervisor' in rf('/proc/cpuinfo'): is_vm = True
    hw['system']['isVirtualMachine'] = is_vm
    hw['system']['hypervisorVendor'] = hv_vendor
    hw['system']['isHypervisorHost'] = (not is_vm) and (os.path.exists('/usr/bin/pveversion') or os.path.exists('/usr/sbin/libvirtd'))
    has_gui = any(os.path.exists(p) for p in ('/usr/bin/gnome-shell', '/usr/bin/plasmashell', '/usr/bin/xfce4-session', '/usr/bin/Xorg', '/usr/sbin/gdm3', '/usr/sbin/sddm', '/usr/sbin/lightdm'))
    if not has_gui:
        try:
            has_gui = subprocess.check_output(['systemctl', 'get-default'], text=True, timeout=2).strip() == 'graphical.target'
        except Exception: pass
    c_type = hw['system'].get('chassisType', 0)
    hw['system']['osProductType'] = 'workstation' if (has_gui or has_bat or c_type in (8, 9, 10, 11, 14, 30, 31, 32)) else 'server'
    hw['cpu'] = {'model': cpu_mdl, 'logicalCores': cores}
    hw['memory'] = {'totalGb': ram_total, 'modules': []}
    hw['storage']['physicalDisks'] = disks
    hw['gpus'] = gpus
    hw['networkAdapters'] = nics
    hw['os'] = {'build': os.uname().release}
print('__VJ_START__' + json.dumps({'cpuUsage': cpu, 'ramUsedGb': ram_used, 'ramTotalGb': ram_total, 'diskFreeGb': round(d_free, 2), 'diskTotalGb': round(d_tot, 2), 'netRxMbps': rx_mbps, 'netTxMbps': tx_mbps, 'uptimeSeconds': up, 'loggedInUser': luser, 'hardwareDetails': hw}) + '__VJ_END__')
`.trim();
        script = `if command -v python3 >/dev/null 2>&1; then
python3 - <<'VITRINE_PY'
${pyScript}
VITRINE_PY
else
read -r _ u1 n1 s1 i1 w1 q1 sq1 st1 _ < /proc/stat
sleep 1
read -r _ u2 n2 s2 i2 w2 q2 sq2 st2 _ < /proc/stat
t1=$((u1+n1+s1+i1+w1+q1+sq1+st1)); t2=$((u2+n2+s2+i2+w2+q2+sq2+st2))
dt=$((t2-t1)); di=$(( (i2+w2) - (i1+w1) ))
CPU=$(awk -v dt="$dt" -v di="$di" 'BEGIN { if (dt>0) printf "%.1f", ((dt-di)/dt)*100; else print "0" }')
RTOT=$(awk '/^MemTotal:/ {printf "%.2f", $2/1048576}' /proc/meminfo)
RAVL=$(awk '/^MemAvailable:/ {printf "%.2f", $2/1048576}' /proc/meminfo)
if [ -z "$RAVL" ]; then RAVL=$(awk '/^MemFree:/ {printf "%.2f", $2/1048576}' /proc/meminfo); fi
RUSD=$(awk -v t="$RTOT" -v a="$RAVL" 'BEGIN { u=t-a; if (u<0) u=0; printf "%.2f", u }')
DTOT=$(df -k / | awk 'NR==2 {printf "%.2f", $2/1048576}')
DFREE=$(df -k / | awk 'NR==2 {printf "%.2f", $4/1048576}')
UP=$(awk '{printf "%d", $1}' /proc/uptime 2>/dev/null || echo 0)
printf '__VJ_START__{"cpuUsage":%s,"ramUsedGb":%s,"ramTotalGb":%s,"diskFreeGb":%s,"diskTotalGb":%s,"uptimeSeconds":%s}__VJ_END__\\n' "$CPU" "$RUSD" "$RTOT" "$DFREE" "$DTOT" "$UP"
fi`;
      } else {
        // macOS
        const macPy = `
import json, os, re, subprocess, time
def read_mac_net():
    rx = tx = 0; seen = set()
    try:
        out = subprocess.check_output(['netstat', '-ib'], text=True, timeout=4)
        for ln in out.splitlines()[1:]:
            c = ln.split()
            if len(c) >= 10 and not c[0].startswith('lo') and c[2].startswith('<Link#'):
                if c[0] in seen: continue
                seen.add(c[0])
                try: rx += int(c[6]); tx += int(c[9])
                except Exception: pass
    except Exception: pass
    return rx, tx
n1 = read_mac_net()
time.sleep(1.0)
n2 = read_mac_net()
rx_mbps = round(max(0, n2[0] - n1[0]) * 8 / 1000000.0, 3)
tx_mbps = round(max(0, n2[1] - n1[1]) * 8 / 1000000.0, 3)
cpu = 0.0
try:
    cpu = round(min(100.0, (os.getloadavg()[0] / max(1, os.cpu_count() or 1)) * 100.0), 1)
except Exception: pass
ram_tot = ram_used = 0.0
try:
    tot_b = int(subprocess.check_output(['sysctl', '-n', 'hw.memsize'], text=True, timeout=3).strip())
    vm = subprocess.check_output(['vm_stat'], text=True, timeout=3)
    ps = 4096
    m = re.search(r'page size of (\\d+) bytes', vm)
    if m: ps = int(m.group(1))
    free_p = 0
    for k in ('Pages free', 'Pages speculative'):
        mp = re.search(rf'{k}:\\s+(\\d+)\\.', vm)
        if mp: free_p += int(mp.group(1))
    ram_tot = round(tot_b / (1024.0**3), 2)
    ram_used = round(max(0, tot_b - free_p * ps) / (1024.0**3), 2)
except Exception: pass
d_tot = d_free = 0.0
try:
    st = os.statvfs('/')
    if st.f_blocks > 0:
        d_tot = round((st.f_blocks * st.f_frsize) / (1024.0**3), 2)
        d_free = round((st.f_bavail * st.f_frsize) / (1024.0**3), 2)
except Exception: pass
up = 0
try:
    bt = subprocess.check_output(['sysctl', '-n', 'kern.boottime'], text=True, timeout=3)
    mb = re.search(r'sec\\s*=\\s*(\\d+)', bt)
    if mb: up = max(0, int(time.time() - int(mb.group(1))))
except Exception: pass
luser = ''
try:
    luser = subprocess.check_output(['stat', '-f%Su', '/dev/console'], text=True, timeout=3).strip()
except Exception: pass
hw = {'storage': {'volumes': [{'mount': '/', 'totalGb': d_tot, 'freeGb': d_free, 'usedPct': round(((d_tot - d_free)/max(0.01, d_tot))*100.0, 1)}] if d_tot > 0 else []}}
if ${detailed ? 'True' : 'False'}:
    try:
        sp = json.loads(subprocess.check_output(['system_profiler', 'SPHardwareDataType', 'SPDisplaysDataType', '-json'], text=True, timeout=8))
        hw_list = sp.get('SPHardwareDataType', [])
        if hw_list:
            h0 = hw_list[0]
            mdl = h0.get('machine_model', '')
            has_bat = False
            try:
                has_bat = 'InternalBattery' in subprocess.check_output(['pmset', '-g', 'batt'], text=True, timeout=2)
            except Exception: pass
            is_vm = False
            try:
                is_vm = subprocess.check_output(['sysctl', '-n', 'kern.hv_vmm_present'], text=True, timeout=2).strip() == '1'
            except Exception: pass
            if any(x in mdl.lower() for x in ('virtualmac', 'vmware', 'parallels')): is_vm = True
            hw['system'] = {'manufacturer': 'Apple Inc.', 'model': mdl, 'serialNumber': h0.get('serial_number', ''), 'biosVersion': h0.get('boot_rom_version', ''), 'hasBattery': has_bat, 'isVirtualMachine': is_vm, 'osProductType': 'server' if mdl.lower().startswith('xserve') else 'workstation'}
            hw['cpu'] = {'model': h0.get('chip_type') or h0.get('cpu_type') or '', 'logicalCores': os.cpu_count() or 0}
        gpus = [{'name': g.get('sppci_model', '')} for g in sp.get('SPDisplaysDataType', []) if g.get('sppci_model')]
        if gpus: hw['gpus'] = gpus
    except Exception: pass
print('__VJ_START__' + json.dumps({'cpuUsage': cpu, 'ramUsedGb': ram_used, 'ramTotalGb': ram_tot, 'diskFreeGb': d_free, 'diskTotalGb': d_tot, 'netRxMbps': rx_mbps, 'netTxMbps': tx_mbps, 'uptimeSeconds': up, 'loggedInUser': luser, 'hardwareDetails': hw}) + '__VJ_END__')
`.trim();
        script = `python3 - <<'VITRINE_PY'
${macPy}
VITRINE_PY`;
      }

      const execRes = await this.executeCommandOnNode(deviceId, script, {
        runAs: 'system',
        shell: osType === 'windows' ? 'powershell' : osType === 'linux' ? 'bash' : 'zsh',
        timeoutMs: detailed ? 16000 : 11000
      });

      if (!execRes.live) {
        return { sampled: false, reason: execRes.output || 'Endpoint did not respond to live telemetry probe' };
      }

      const jsonStr = extractDelimitedJson(execRes.output);
      let parsed: any = null;
      try {
        parsed = JSON.parse(jsonStr);
      } catch {
        return { sampled: false, reason: 'Telemetry probe returned unparseable payload' };
      }

      if (!parsed || typeof parsed !== 'object') {
        return { sampled: false, reason: 'Telemetry probe returned empty payload' };
      }

      const recorded = recordDeviceTelemetrySample(deviceId, {
        cpuUsage: parsed.cpuUsage,
        ramUsedGb: parsed.ramUsedGb,
        ramTotalGb: parsed.ramTotalGb,
        diskFreeGb: parsed.diskFreeGb,
        diskTotalGb: parsed.diskTotalGb,
        netRxMbps: parsed.netRxMbps,
        netTxMbps: parsed.netTxMbps,
        uptimeSeconds: parsed.uptimeSeconds,
        loggedInUser: parsed.loggedInUser,
        hardwareDetails: parsed.hardwareDetails || null,
        forceHistoryInsert: Boolean(options?.forceHistoryInsert)
      });

      return { sampled: recorded.recorded, sample: recorded.point };
    })();

    this.liveTelemetryInFlight.set(dedupeKey, work);
    try {
      return await work;
    } finally {
      this.liveTelemetryInFlight.delete(dedupeKey);
    }
  }

  public async deployCompanionOverMesh(
    deviceId: string,
    vitrineServerUrl?: string
  ): Promise<{ dispatched: boolean; queuedOffline?: boolean; output: string }> {
    const dev = db
      .prepare('SELECT id, tenant_id, site_id, hostname, ip_address, os_type, status, lifecycle_state, device_role, mesh_node_id FROM devices WHERE id = ?')
      .get(deviceId) as any;
    if (!dev || dev.lifecycle_state === 'archived') {
      return { dispatched: false, output: 'Device not found or archived.' };
    }

    if (dev.status !== 'online' && dev.status !== 'isolated') {
      db.prepare('UPDATE devices SET companion_deploy_pending = 1 WHERE id = ?').run(deviceId);
      return {
        dispatched: false,
        queuedOffline: true,
        output: `Endpoint '${dev.hostname}' is offline; companion deployment queued for next online check-in.`
      };
    }

    const settings = (db.prepare('SELECT custom_domain, meshcentral_allow_self_signed FROM settings WHERE id = 1').get() || {}) as any;
    let resolvedServerUrl = String(vitrineServerUrl || '').trim();
    if (!resolvedServerUrl) {
      if (settings.custom_domain) {
        const dom = String(settings.custom_domain).trim();
        resolvedServerUrl = dom.startsWith('http') ? dom : `https://${dom}`;
      } else if (process.env.VITRINE_PUBLIC_URL || process.env.PUBLIC_URL) {
        resolvedServerUrl = String(process.env.VITRINE_PUBLIC_URL || process.env.PUBLIC_URL).trim();
      } else {
        const devIp = String(dev.ip_address || '').trim().toLowerCase();
        const isLoopbackTarget = devIp === '127.0.0.1' || devIp === '::1' || devIp === 'localhost';
        if (!isLoopbackTarget) {
          const warnMsg = `Cannot deploy Vitrine Companion to '${dev.hostname}' (${dev.ip_address || 'remote'}): configure Settings -> Public Domain (custom_domain) or VITRINE_PUBLIC_URL so the remote endpoint does not fall back to 127.0.0.1.`;
          console.warn(`[MeshCentralBridge] ${warnMsg}`);
          return { dispatched: false, output: warnMsg };
        }
        resolvedServerUrl = `http://127.0.0.1:${process.env.PORT || 8080}`;
      }
    }

    const tokenId = `tok-comp-${crypto.randomUUID().slice(0, 12)}`;
    const expiresAt = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const osType: 'windows' | 'linux' | 'macos' =
      dev.os_type === 'linux' || dev.os_type === 'macos' ? dev.os_type : 'windows';

    db.prepare(`
      INSERT INTO installer_audit_log (
        id, token_id, tenant_id, site_id, device_role, technician, ticket_number, platform, expires_at, max_uses, use_count
      ) VALUES (?, ?, ?, ?, ?, 'ms2-companion-push', 'MS2-AUTO-DEPLOY', ?, ?, 1, 0)
    `).run(
      `ia-${crypto.randomUUID().slice(0, 8)}`,
      tokenId,
      dev.tenant_id || 't-default',
      dev.site_id || null,
      dev.device_role || 'Workstation',
      osType,
      expiresAt
    );

    const bootstrapScript = await installerGenerator.generateCompanionOnlyBootstrap({
      os: osType,
      deviceId: dev.id,
      tenantId: dev.tenant_id || 't-default',
      enrollmentToken: tokenId,
      vitrineServerUrl: resolvedServerUrl,
      allowSelfSignedTls: Boolean(settings.meshcentral_allow_self_signed) || resolvedServerUrl.startsWith('https://127.0.0.1')
    });

    const execRes = await this.executeCommandOnNode(dev.id, bootstrapScript, {
      runAs: 'system',
      shell: osType === 'windows' ? 'powershell' : 'bash',
      timeoutMs: 25000
    });

    if (execRes.live && execRes.exitCode === 0) {
      db.prepare('UPDATE devices SET companion_deploy_pending = 0 WHERE id = ?').run(dev.id);
      return { dispatched: true, output: execRes.output || 'Vitrine Companion bootstrap dispatched.' };
    }

    db.prepare('UPDATE devices SET companion_deploy_pending = 1 WHERE id = ?').run(dev.id);
    return { dispatched: false, output: execRes.output || 'Failed to dispatch Vitrine Companion over MS2.' };
  }

  public async removeVitrineCompanionOnlyOverMesh(
    deviceId: string,
    opts?: { removeLapsAccount?: boolean; lapsAccountName?: string }
  ): Promise<{ dispatched: boolean; live: boolean; output: string }> {
    const dev = db
      .prepare('SELECT id, hostname, os_type, status, lifecycle_state FROM devices WHERE id = ?')
      .get(deviceId) as any;
    if (!dev || dev.lifecycle_state === 'archived') {
      return { dispatched: false, live: false, output: 'Device unavailable.' };
    }

    let safeServiceName = 'VitrineAgent';
    try {
      const settingsRow = db
        .prepare('SELECT installer_service_name, brand_name FROM settings WHERE id = 1')
        .get() as { installer_service_name?: string; brand_name?: string } | undefined;
      const rawSvc =
        settingsRow?.installer_service_name ||
        (settingsRow?.brand_name ? String(settingsRow.brand_name).replace(/[^a-zA-Z0-9]/g, '') + 'Agent' : '');
      const cleaned = String(rawSvc || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 40);
      if (cleaned) safeServiceName = cleaned;
    } catch {}
    const safeServiceLower = safeServiceName.toLowerCase();
    const safeAcc = SAFE_ACCOUNT_NAME_REGEX.test(opts?.lapsAccountName || '') ? opts!.lapsAccountName! : 'LocalAdmin';
    const osType = dev.os_type === 'linux' || dev.os_type === 'macos' ? dev.os_type : 'windows';

    let cleanupCmd = '';
    if (osType === 'windows') {
      const svcDirLit = quotePowerShellLiteral(`C:\\Program Files\\${safeServiceName}`);
      const trayDataLit = quotePowerShellLiteral(`C:\\ProgramData\\${safeServiceName}\\tray`);
      const trayKeyLit = quotePowerShellLiteral(`${safeServiceName}-Tray`);
      const taskLit = quotePowerShellLiteral(`${safeServiceName}-Companion`);
      const svcNameLit = quotePowerShellLiteral(`${safeServiceName}-Companion`);
      const uninstKeyLit = quotePowerShellLiteral(`HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${safeServiceName}`);
      const accLit = quotePowerShellLiteral(safeAcc);
      cleanupCmd = [
        `$ErrorActionPreference = 'SilentlyContinue'`,
        `Stop-Service -Name ${svcNameLit} -Force -ErrorAction SilentlyContinue`,
        `Stop-Service -Name 'VitrineAgent-Companion' -Force -ErrorAction SilentlyContinue`,
        `sc.exe delete ${svcNameLit} | Out-Null`,
        `sc.exe delete 'VitrineAgent-Companion' | Out-Null`,
        `Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name ${trayKeyLit} -ErrorAction SilentlyContinue`,
        `Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'VitrineAgent-Tray' -ErrorAction SilentlyContinue`,
        `Remove-Item -Path ${uninstKeyLit} -Force -ErrorAction SilentlyContinue`,
        `Remove-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VitrineAgent' -Force -ErrorAction SilentlyContinue`,
        `Unregister-ScheduledTask -TaskName ${taskLit} -Confirm:$false -ErrorAction SilentlyContinue`,
        `Unregister-ScheduledTask -TaskName '*Vitrine*-Companion' -Confirm:$false -ErrorAction SilentlyContinue`,
        ...(opts?.removeLapsAccount
          ? [
              `if (-not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) { $s500 = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }; if ($s500) { Enable-LocalUser -Name $s500.Name -ErrorAction SilentlyContinue } }`,
              `Remove-LocalUser -Name ${accLit} -ErrorAction SilentlyContinue`
            ]
          : []),
        `Stop-Process -Name 'vitrine-companion','vitrine-tray' -Force -ErrorAction SilentlyContinue`,
        `Get-CimInstance Win32_Process -Filter "Name LIKE 'powershell%'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*vitrine-companion*' -or $_.CommandLine -like '*vitrine-tray*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }`,
        `foreach ($d in @(${svcDirLit}, 'C:\\Program Files\\VitrineAgent')) { if (Test-Path -LiteralPath $d) { foreach ($f in @('vitrine-companion.exe','vitrine-tray.exe','vitrine-companion.ps1','vitrine-tray.ps1','agent-identity.json','companion-config.json','tray-inbox.json','tray-outbox.json','tray-icon.img')) { Remove-Item -LiteralPath (Join-Path $d $f) -Force -ErrorAction SilentlyContinue }; if (-not (Get-ChildItem -LiteralPath $d -Filter '*.exe' -ErrorAction SilentlyContinue) -and ((Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0)) { Remove-Item -LiteralPath $d -Force -ErrorAction SilentlyContinue } } }`,
        `Remove-Item -LiteralPath ${trayDataLit} -Recurse -Force -ErrorAction SilentlyContinue`,
        `Remove-Item -LiteralPath 'C:\\ProgramData\\VitrineAgent\\tray' -Recurse -Force -ErrorAction SilentlyContinue`,
        `Write-Output 'VITRINE_COMPANION_REMOVED'`
      ].join('; ');
    } else {
      const svcUnit = quoteBashLiteral(`${safeServiceLower}-companion.service`);
      const plistLabel = quoteBashLiteral(`/Library/LaunchDaemons/com.${safeServiceLower}.companion.plist`);
      const optDir = quoteBashLiteral(`/opt/${safeServiceLower}`);
      const macDir = quoteBashLiteral(`/Library/Application Support/${safeServiceLower}`);
      const accBash = quoteBashLiteral(safeAcc);
      cleanupCmd = [
        ...(opts?.removeLapsAccount ? [`userdel -r ${accBash} 2>/dev/null || sysadminctl -deleteUser ${accBash} 2>/dev/null || true`] : []),
        `systemctl disable --now ${svcUnit} vitrineagent-companion.service 2>/dev/null || true`,
        `rm -f /etc/systemd/system/${svcUnit} /etc/systemd/system/vitrineagent-companion.service`,
        `launchctl bootout system ${plistLabel} 2>/dev/null || launchctl unload -w ${plistLabel} 2>/dev/null || true`,
        `launchctl bootout system /Library/LaunchDaemons/com.vitrineagent.companion.plist 2>/dev/null || true`,
        `rm -f ${plistLabel} /Library/LaunchDaemons/com.vitrineagent.companion.plist`,
        `for d in ${optDir} /opt/vitrineagent ${macDir} '/Library/Application Support/vitrineagent'; do if [ -d "$d" ]; then rm -f "$d"/vitrine-companion.* "$d"/vitrine-tray.* "$d/agent-identity.json" "$d/companion-config.json" "$d/tray-inbox.json" "$d/tray-icon.img"; if [ ! -e "$d/meshagent" ] && [ ! -d "$d/meshcore" ]; then rmdir "$d" 2>/dev/null || true; fi; fi; done`,
        `echo 'VITRINE_COMPANION_REMOVED'`
      ].join('; ');
    }

    if (dev.status === 'online' || dev.status === 'isolated') {
      const res = await this.executeCommandOnNode(dev.id, cleanupCmd, { runAs: 'system', timeoutMs: 12000 });
      if (res.live) {
        db.prepare('UPDATE devices SET companion_installed = 0, companion_deploy_pending = 0, agent_auth_token = NULL WHERE id = ?').run(
          dev.id
        );
      }
      return { dispatched: true, live: res.live, output: res.output };
    }

    // Offline companion-enrolled fallback: queue self_uninstall with preserveMeshAgent = true
    const rmTaskId = `task-rmcomp-${crypto.randomUUID()}`;
    const rmPayloadJson = JSON.stringify({
      preserveMeshAgent: true,
      serviceName: safeServiceName,
      lapsAction: opts?.removeLapsAccount ? 'remove_account' : 'keep_account_as_is',
      lapsAccountName: safeAcc
    });
    db.prepare(`
      INSERT INTO agent_tasks (id, device_id, task_type, payload_json, status)
      VALUES (?, ?, 'self_uninstall', ?, 'queued')
    `).run(rmTaskId, dev.id, rmPayloadJson);
    agentSocketHub.dispatchTaskIfConnected(dev.id, {
      id: rmTaskId,
      task_type: 'self_uninstall',
      payload_json: rmPayloadJson
    });
    db.prepare('UPDATE devices SET companion_deploy_pending = 0 WHERE id = ?').run(dev.id);
    return { dispatched: true, live: false, output: 'Queued Vitrine-only uninstall task for next Companion check-in.' };
  }

  public async lockEndpointScreen(
    deviceId: string,
    actorUsername = 'admin'
  ): Promise<{ dispatched: boolean; success: boolean; live: boolean; output: string }> {
    const osType = this.getDeviceOs(deviceId);
    const lockCmd =
      osType === 'windows'
        ? `rundll32.exe user32.dll,LockWorkStation`
        : osType === 'macos'
          ? `"/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession" -suspend 2>/dev/null || pmset displaysleepnow`
          : `loginctl lock-sessions 2>/dev/null || xdg-screensaver lock 2>/dev/null || gnome-screensaver-command -l 2>/dev/null || true`;

    const res = await this.executeCommandOnNode(deviceId, lockCmd, {
      runAs: osType === 'windows' ? 'user' : 'system',
      timeoutMs: 8000
    });
    const ok = (res.live && res.exitCode === 0) || Boolean(res.queued);

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Remote Session Screen Locked', ?)
    `).run(
      `aud-lock-${crypto.randomUUID()}`,
      actorUsername,
      deviceId,
      `Screen lock dispatched on ${osType} endpoint (${res.live ? 'live verified' : res.queued ? 'queued' : 'failed'})`
    );

    return {
      dispatched: ok,
      success: ok,
      live: res.live,
      output: res.output
    };
  }

  public async verifyAndPushLapsCredentialToNode(
    deviceId: string,
    opts: {
      accountName: string;
      password: string;
      autoCreateAccount: boolean;
      disableSid500: boolean;
      previousAccountName?: string | null;
      cleanupOldAccountAction?: 'disable' | 'delete' | 'keep';
    }
  ): Promise<{ delivered: boolean; verifiedLive: boolean; output: string }> {
    if (!SAFE_ACCOUNT_NAME_REGEX.test(opts.accountName)) {
      throw new Error(`Invalid local admin account name (1-20 safe chars required): ${opts.accountName}`);
    }
    const osType = this.getDeviceOs(deviceId);

    let script = '';
    if (osType === 'windows') {
      const accLit = quotePowerShellLiteral(opts.accountName);
      const passLit = quotePowerShellLiteral(opts.password);
      const lines: string[] = [
        `$ErrorActionPreference = 'Stop'`,
        `$Acc = ${accLit}`,
        `$Sec = ConvertTo-SecureString ${passLit} -AsPlainText -Force`,
        `$Existing = Get-LocalUser -Name $Acc -ErrorAction SilentlyContinue`,
        opts.autoCreateAccount
          ? `if ($Existing) { Set-LocalUser -Name $Acc -Password $Sec; Enable-LocalUser -Name $Acc } else { New-LocalUser -Name $Acc -Password $Sec -PasswordNeverExpires:$false -Description 'Managed by Vitrine RMM LAPS' | Out-Null; Add-LocalGroupMember -Group 'Administrators' -Member $Acc -ErrorAction SilentlyContinue }`
          : `if ($Existing) { Set-LocalUser -Name $Acc -Password $Sec; Enable-LocalUser -Name $Acc } else { throw "Managed LAPS account $Acc does not exist on endpoint." }`,
        ...(opts.disableSid500
          ? [
              `$Sid500 = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' -and $_.Name -ne $Acc }`,
              `if ($Sid500) { Disable-LocalUser -Name $Sid500.Name -ErrorAction SilentlyContinue }`
            ]
          : []),
        `Write-Output "LAPS_ROTATE_OK:$Acc"`
      ];

      if (
        opts.previousAccountName &&
        opts.previousAccountName !== opts.accountName &&
        SAFE_ACCOUNT_NAME_REGEX.test(opts.previousAccountName)
      ) {
        const prevLit = quotePowerShellLiteral(opts.previousAccountName);
        if (opts.cleanupOldAccountAction === 'delete') {
          lines.push(`Remove-LocalUser -Name ${prevLit} -ErrorAction SilentlyContinue`);
        } else if (opts.cleanupOldAccountAction === 'disable') {
          lines.push(`Disable-LocalUser -Name ${prevLit} -ErrorAction SilentlyContinue`);
        }
      }
      script = lines.join('; ');
    } else if (osType === 'macos') {
      const passB64 = Buffer.from(opts.password, 'utf8').toString('base64');
      const prevAcc =
        opts.previousAccountName &&
        opts.previousAccountName !== opts.accountName &&
        SAFE_ACCOUNT_NAME_REGEX.test(opts.previousAccountName)
          ? opts.previousAccountName
          : '';
      const cleanupAction = opts.cleanupOldAccountAction || 'keep';
      // Pass password securely via PTY / stdin inside python3 so it NEVER appears in process argv (M-8)
      script = `python3 - ${quoteBashLiteral(opts.accountName)} ${opts.autoCreateAccount ? '1' : '0'} ${quoteBashLiteral(prevAcc)} ${quoteBashLiteral(cleanupAction)} <<'PYMACLAPS'
import base64, os, pty, select, subprocess, sys, time
acc, auto_create, prev_acc, cleanup_act = sys.argv[1], sys.argv[2] == "1", sys.argv[3], sys.argv[4]
pw = base64.b64decode("${passB64}").decode("utf-8")
exists = subprocess.run(["id", "-u", acc], capture_output=True).returncode == 0
if not exists:
    if not auto_create:
        raise SystemExit(2)
    subprocess.run(["sysadminctl", "-addUser", acc, "-fullName", acc, "-admin"], capture_output=True)
    if subprocess.run(["id", "-u", acc], capture_output=True).returncode != 0:
        raise SystemExit(3)
master, slave = pty.openpty()
proc = subprocess.Popen(["dscl", ".", "-passwd", f"/Users/{acc}"], stdin=slave, stdout=slave, stderr=slave, close_fds=True)
os.close(slave)
sent = False
deadline = time.time() + 10.0
while proc.poll() is None and time.time() < deadline:
    r, _, _ = select.select([master], [], [], 0.25)
    if r:
        try:
            chunk = os.read(master, 4096)
        except OSError:
            break
        if not sent and (b"assword" in chunk or b":" in chunk):
            os.write(master, (pw + "\\n").encode("utf-8"))
            sent = True
if not sent and proc.poll() is None:
    os.write(master, (pw + "\\n").encode("utf-8"))
try:
    os.close(master)
except OSError:
    pass
rc = proc.wait(timeout=5)
if rc != 0:
    raise SystemExit(rc)
if prev_acc and prev_acc != acc:
    if cleanup_act == "delete":
        subprocess.run(["sysadminctl", "-deleteUser", prev_acc], capture_output=True)
        subprocess.run(["dscl", ".", "-delete", f"/Users/{prev_acc}"], capture_output=True)
    elif cleanup_act == "disable":
        subprocess.run(["pwpolicy", "-u", prev_acc, "-disableuser"], capture_output=True)
        subprocess.run(["dscl", ".", "-create", f"/Users/{prev_acc}", "UserShell", "/usr/bin/false"], capture_output=True)
print("LAPS_ROTATE_OK")
PYMACLAPS`;
    } else {
      const accBash = quoteBashLiteral(opts.accountName);
      const passB64 = Buffer.from(`${opts.accountName}:${opts.password}\n`, 'utf8').toString('base64');
      let cleanupCmd = '';
      if (
        opts.previousAccountName &&
        opts.previousAccountName !== opts.accountName &&
        SAFE_ACCOUNT_NAME_REGEX.test(opts.previousAccountName)
      ) {
        const prevBash = quoteBashLiteral(opts.previousAccountName);
        if (opts.cleanupOldAccountAction === 'delete') {
          cleanupCmd = ` && (userdel -r ${prevBash} 2>/dev/null || userdel ${prevBash} 2>/dev/null || true)`;
        } else if (opts.cleanupOldAccountAction === 'disable') {
          cleanupCmd = ` && (usermod -L -s /usr/sbin/nologin ${prevBash} 2>/dev/null || usermod -L ${prevBash} 2>/dev/null || true)`;
        }
      }
      script = `(id -u ${accBash} >/dev/null 2>&1 || (${opts.autoCreateAccount ? `useradd -m -s /bin/bash ${accBash} && (usermod -aG sudo ${accBash} 2>/dev/null || usermod -aG wheel ${accBash} 2>/dev/null || true)` : 'exit 2'})) && printf '%s' '${passB64}' | base64 -d | chpasswd${cleanupCmd} && echo "LAPS_ROTATE_OK"`;
    }

    const res = await this.executeCommandOnNode(deviceId, script, {
      runAs: 'system',
      timeoutMs: 15000,
      noQueue: true
    });
    const verifiedLive = res.live && res.exitCode === 0 && res.output.includes('LAPS_ROTATE_OK');
    if (!verifiedLive && res.taskId) {
      try {
        db.prepare("DELETE FROM agent_tasks WHERE id = ? AND status = 'queued'").run(res.taskId);
      } catch {}
    }
    return {
      delivered: verifiedLive,
      verifiedLive,
      output: res.output
    };
  }

  public pushLapsCredentialToNode(
    deviceId: string,
    opts: {
      accountName: string;
      password: string;
      autoCreateAccount: boolean;
      disableSid500: boolean;
      previousAccountName?: string | null;
      cleanupOldAccountAction?: 'disable' | 'delete' | 'keep';
    }
  ): boolean {
    if (!SAFE_ACCOUNT_NAME_REGEX.test(opts.accountName)) {
      throw new Error(`Invalid local admin account name: ${opts.accountName}`);
    }
    void this.verifyAndPushLapsCredentialToNode(deviceId, opts);
    return this.getStatus().connected;
  }

  public dispatchAgentOffboard(
    deviceId: string,
    opts: { lapsAccountName: string; lapsAction: string }
  ): boolean {
    const osType = this.getDeviceOs(deviceId);
    const meshNodeId = this.resolveMeshNodeId(deviceId);
    return this.dispatchRawNodeOffboard(meshNodeId, opts.lapsAccountName, opts.lapsAction, osType, deviceId);
  }

  public dispatchRawNodeOffboard(
    meshNodeId: string,
    lapsAccountName: string,
    lapsAction: string,
    osType: 'windows' | 'linux' | 'macos' = 'windows',
    deviceId?: string
  ): boolean {
    const safeAcc = SAFE_ACCOUNT_NAME_REGEX.test(lapsAccountName) ? lapsAccountName : 'LocalAdmin';
    let safeServiceName = 'VitrineAgent';
    try {
      const settingsRow = db
        .prepare('SELECT installer_service_name, brand_name FROM settings WHERE id = 1')
        .get() as { installer_service_name?: string; brand_name?: string } | undefined;
      const rawSvc =
        settingsRow?.installer_service_name ||
        (settingsRow?.brand_name ? String(settingsRow.brand_name).replace(/[^a-zA-Z0-9]/g, '') + 'Agent' : '');
      const cleaned = String(rawSvc || '')
        .replace(/[^a-zA-Z0-9_-]/g, '')
        .slice(0, 40);
      if (cleaned) safeServiceName = cleaned;
    } catch {}
    const safeServiceLower = safeServiceName.toLowerCase();

    let targetCmd = '';
    if (osType === 'windows') {
      const accLit = quotePowerShellLiteral(safeAcc);
      const trayKeyLit = quotePowerShellLiteral(`${safeServiceName}-Tray`);
      const taskLit = quotePowerShellLiteral(`${safeServiceName}-Companion`);
      const svcPatternLit = quotePowerShellLiteral(`${safeServiceName}*`);
      const svcDirLit = quotePowerShellLiteral(`C:\\Program Files\\${safeServiceName}`);
      const svcAgentExeLit = quotePowerShellLiteral(`C:\\Program Files\\${safeServiceName}\\${safeServiceName}.exe`);
      // Safety net: on non-domain workgroup hosts, re-enable built-in SID-500 Administrator BEFORE removing LAPS account so endpoint is never locked out!
      const sid500Guard =
        lapsAction === 'remove_account' || lapsAction === 'disable_account'
          ? `if (-not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) { $s500 = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }; if ($s500) { Enable-LocalUser -Name $s500.Name -ErrorAction SilentlyContinue } }`
          : '';
      const lapsCmd =
        lapsAction === 'remove_account'
          ? `${sid500Guard}; Remove-LocalUser -Name ${accLit} -ErrorAction SilentlyContinue`
          : lapsAction === 'disable_account'
            ? `${sid500Guard}; Disable-LocalUser -Name ${accLit} -ErrorAction SilentlyContinue`
            : `# Preserving ${safeAcc}`;
      targetCmd = [
        `$ErrorActionPreference = 'SilentlyContinue'`,
        `Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name ${trayKeyLit} -ErrorAction SilentlyContinue`,
        `Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'VitrineAgent-Tray' -ErrorAction SilentlyContinue`,
        `Unregister-ScheduledTask -TaskName ${taskLit} -Confirm:$false -ErrorAction SilentlyContinue`,
        `Unregister-ScheduledTask -TaskName '*Vitrine*' -Confirm:$false -ErrorAction SilentlyContinue`,
        lapsCmd,
        `Stop-Service -Name ${svcPatternLit} -Force -ErrorAction SilentlyContinue`,
        `Stop-Service -Name 'VitrineAgent*' -Force -ErrorAction SilentlyContinue`,
        `if (Test-Path -LiteralPath ${svcAgentExeLit}) { Start-Process -FilePath ${svcAgentExeLit} -ArgumentList '-fulluninstall' -WindowStyle Hidden }`,
        `if (Test-Path 'C:\\Program Files\\Mesh Agent\\MeshAgent.exe') { Start-Process -FilePath 'C:\\Program Files\\Mesh Agent\\MeshAgent.exe' -ArgumentList '-fulluninstall' -WindowStyle Hidden }`,
        `Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-WindowStyle', 'Hidden', '-Command', "Start-Sleep -Seconds 3; Remove-Item -LiteralPath ${svcDirLit} -Recurse -Force -ErrorAction SilentlyContinue") -WindowStyle Hidden`
      ].join('; ');
    } else {
      const accBash = quoteBashLiteral(safeAcc);
      const svcUnit = quoteBashLiteral(`${safeServiceLower}-companion.service`);
      const plistLabel = quoteBashLiteral(`/Library/LaunchDaemons/com.${safeServiceLower}.companion.plist`);
      const optDir = quoteBashLiteral(`/opt/${safeServiceLower}`);
      const macDir = quoteBashLiteral(`/Library/Application Support/${safeServiceLower}`);
      const lapsSh =
        lapsAction === 'remove_account'
          ? `userdel -r ${accBash} 2>/dev/null || sysadminctl -deleteUser ${accBash} 2>/dev/null || true`
          : lapsAction === 'disable_account'
            ? `usermod -L ${accBash} 2>/dev/null || pwpolicy -u ${accBash} -disableuser 2>/dev/null || true`
            : `:`;
      targetCmd = [
        lapsSh,
        `systemctl disable --now ${svcUnit} vitrineagent-companion.service 2>/dev/null || true`,
        `rm -f /etc/systemd/system/${svcUnit} /etc/systemd/system/vitrineagent-companion.service`,
        `launchctl bootout system ${plistLabel} 2>/dev/null || launchctl unload -w ${plistLabel} 2>/dev/null || true`,
        `launchctl bootout system /Library/LaunchDaemons/com.vitrineagent.companion.plist 2>/dev/null || true`,
        `rm -f ${plistLabel} /Library/LaunchDaemons/com.vitrineagent.companion.plist`,
        `rm -rf ${optDir} /opt/vitrineagent ${macDir} '/Library/Application Support/vitrineagent'`
      ].join('; ');
    }

    if (deviceId) {
      try {
        const devRow = db
          .prepare('SELECT id, tenant_id, status, lifecycle_state, agent_auth_token FROM devices WHERE id = ?')
          .get(deviceId) as any;
        if (devRow && devRow.lifecycle_state !== 'archived') {
          if (devRow.status === 'online' || devRow.status === 'isolated') {
            // Single unified dispatch (uses MeshCentral WS if connected for node, else queues Companion task — no duplicate execution)
            void this.executeCommandOnNode(deviceId, targetCmd, { runAs: 'system', timeoutMs: 5000 });
            return true;
          }
          if (devRow.agent_auth_token) {
            db.prepare(`
              INSERT INTO agent_tasks (id, device_id, tenant_id, task_type, payload_json, status)
              VALUES (?, ?, ?, 'self_uninstall', ?, 'queued')
            `).run(
              `task-offboard-${crypto.randomUUID()}`,
              devRow.id,
              devRow.tenant_id || null,
              JSON.stringify({
                lapsAccountName: safeAcc,
                lapsAction,
                serviceName: safeServiceName,
                code: targetCmd
              })
            );
            return true;
          }
        }
      } catch {}
    }

    return this.dispatchRpc({
      action: 'runcommands',
      nodeids: [meshNodeId],
      type: osType === 'windows' ? 2 : 3,
      cmds: targetCmd
    });
  }

  // ============================================================================
  // Live Silent Background Process Manager (Zero Hardcoded Fake Processes)
  // ============================================================================
  public async getProcesses(deviceId: string): Promise<ProcessItem[]> {
    const cached = this.processCache.get(deviceId);
    if (cached) return cached;
    this.lastToolError = null;

    const osType = this.getDeviceOs(deviceId);
    if (osType === 'windows') {
      const ps = `Write-Output "__VJ_START__"; Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 60 Id, ProcessName, @{N='CpuSec';E={[math]::Round($_.CPU,1)}}, @{N='MemMb';E={[math]::Round($_.WorkingSet64/1MB,1)}}, @{N='Threads';E={$_.Threads.Count}} | ConvertTo-Json -Compress; Write-Output "__VJ_END__"`;
      const res = await this.executeCommandOnNode(deviceId, ps, { runAs: 'system', timeoutMs: 15000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const parsed = JSON.parse(extractDelimitedJson(res.output));
          const arr = Array.isArray(parsed) ? parsed : [parsed];
          const items: ProcessItem[] = arr
            .filter((p) => p && typeof p.Id === 'number')
            .map((p) => ({
              pid: Number(p.Id),
              name: String(p.ProcessName || 'process'),
              user: 'SYSTEM/User',
              cpu: Number(p.CpuSec || 0),
              memoryMb: Number(p.MemMb || 0),
              threads: Number(p.Threads || 1)
            }));
          this.processCache.set(deviceId, items);
          return items;
        } catch (err: any) {
          this.lastToolError = `Failed to parse live process output: ${err?.message || 'invalid JSON'}`;
        }
      } else if (!res.live || res.exitCode !== 0) {
        this.lastToolError = res.output || 'Endpoint did not respond to live process query.';
      }
    } else {
      const cmd = `echo "__VJ_START__"; if command -v python3 >/dev/null 2>&1; then python3 -c 'import subprocess,json; out=subprocess.check_output(["ps","-eo","pid,user,pcpu,rss,comm"],text=True); rows=[]; [rows.append({"pid":int(p[0]),"user":p[1],"cpu":float(p[2]),"memoryMb":round(int(p[3])/1024.0,1),"threads":1,"name":p[4]}) for line in out.splitlines()[1:] for p in [line.split(None,4)] if len(p)==5 and p[0].isdigit()]; rows.sort(key=lambda x:x["memoryMb"],reverse=True); print(json.dumps(rows[:60]))'; else ps -eo pid,user,pcpu,rss,comm | tail -n +2 | head -n 60 | awk '{printf "%s{\\"pid\\":%s,\\"user\\":\\"%s\\",\\"cpu\\":%s,\\"memoryMb\\":%.1f,\\"threads\\":1,\\"name\\":\\"%s\\"}", (NR>1?",":""), $1, $2, $3, $4/1024.0, $5}' | awk 'BEGIN{printf "["} {print} END{print "]"}'; fi; echo "__VJ_END__"`;
      const res = await this.executeCommandOnNode(deviceId, cmd, { runAs: 'system', timeoutMs: 15000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const items = JSON.parse(extractDelimitedJson(res.output)) as ProcessItem[];
          if (Array.isArray(items)) {
            this.processCache.set(deviceId, items);
            return items;
          }
        } catch (err: any) {
          this.lastToolError = `Failed to parse live process output: ${err?.message || 'invalid JSON'}`;
        }
      } else if (!res.live || res.exitCode !== 0) {
        this.lastToolError = res.output || 'Endpoint did not respond to live process query.';
      }
    }

    return [];
  }

  public async killProcess(deviceId: string, pid: number, actorUsername = 'admin'): Promise<boolean> {
    const cleanPid = Number(pid);
    if (!Number.isInteger(cleanPid) || cleanPid <= 1) {
      throw new Error('Invalid PID: must be an integer greater than 1.');
    }
    const osType = this.getDeviceOs(deviceId);
    const killCmd = osType === 'windows' ? `Stop-Process -Id ${cleanPid} -Force` : `kill -9 ${cleanPid}`;
    const res = await this.executeCommandOnNode(deviceId, killCmd, { runAs: 'system', timeoutMs: 6000 });
    this.processCache.delete(deviceId);

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Process Terminated', ?)
    `).run(
      `aud-kill-${crypto.randomUUID()}`,
      actorUsername,
      deviceId,
      `Terminated PID ${cleanPid} (${res.live ? 'live verified' : 'queued'})`
    );
    return res.exitCode === 0;
  }

  // ============================================================================
  // Live Silent Background Services / Daemons Manager
  // ============================================================================
  public async getServices(deviceId: string): Promise<ServiceItem[]> {
    const cached = this.serviceCache.get(deviceId);
    if (cached) return cached;
    this.lastToolError = null;

    const osType = this.getDeviceOs(deviceId);
    if (osType === 'windows') {
      const ps = `Write-Output "__VJ_START__"; Get-Service | Select-Object -First 80 Name, DisplayName, @{N='StatusStr';E={$_.Status.ToString()}}, @{N='StartStr';E={$_.StartType.ToString()}} | ConvertTo-Json -Compress; Write-Output "__VJ_END__"`;
      const res = await this.executeCommandOnNode(deviceId, ps, { runAs: 'system', timeoutMs: 15000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const parsed = JSON.parse(extractDelimitedJson(res.output));
          const arr = Array.isArray(parsed) ? parsed : [parsed];
          const items: ServiceItem[] = arr.map((s: any) => ({
            name: String(s.Name || ''),
            displayName: String(s.DisplayName || s.Name || ''),
            status: s.StatusStr === 'Running' ? 'Running' : s.StatusStr === 'Paused' ? 'Paused' : 'Stopped',
            startType: s.StartStr === 'Automatic' ? 'Automatic' : s.StartStr === 'Disabled' ? 'Disabled' : 'Manual'
          }));
          this.serviceCache.set(deviceId, items);
          return items;
        } catch (err: any) {
          this.lastToolError = `Failed to parse live service output: ${err?.message || 'invalid JSON'}`;
        }
      } else if (!res.live || res.exitCode !== 0) {
        this.lastToolError = res.output || 'Endpoint did not respond to live service query.';
      }
    } else if (osType === 'linux') {
      const cmd = `echo "__VJ_START__"; if command -v python3 >/dev/null 2>&1; then python3 -c 'import subprocess,json; out=subprocess.check_output(["systemctl","list-units","--type=service","--all","--no-pager","--no-legend"],text=True); items=[]; [items.append({"name":p[0],"displayName":p[4] if len(p)>4 else p[0],"status":"Running" if p[2]=="active" and p[3]=="running" else "Stopped","startType":"Automatic"}) for l in out.splitlines() for p in [l.lstrip("● ").split(None,4)] if len(p)>=4 and p[0].endswith(".service")]; print(json.dumps(items[:80]))'; else systemctl list-units --type=service --all --no-pager --no-legend | head -n 80 | awk '{st=($3=="active"&&$4=="running")?"Running":"Stopped"; gsub(/"/,"",$0); printf "%s{\\"name\\":\\"%s\\",\\"displayName\\":\\"%s\\",\\"status\\":\\"%s\\",\\"startType\\":\\"Automatic\\"}", (NR>1?",":""), $1, $1, st}' | awk 'BEGIN{printf "["} {print} END{print "]"}'; fi; echo "__VJ_END__"`;
      const res = await this.executeCommandOnNode(deviceId, cmd, { runAs: 'system', timeoutMs: 15000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const items = JSON.parse(extractDelimitedJson(res.output)) as ServiceItem[];
          if (Array.isArray(items)) {
            this.serviceCache.set(deviceId, items);
            return items;
          }
        } catch (err: any) {
          this.lastToolError = `Failed to parse live Linux service output: ${err?.message || 'invalid JSON'}`;
        }
      } else if (!res.live || res.exitCode !== 0) {
        this.lastToolError = res.output || 'Endpoint did not respond to live service query.';
      }
    } else {
      const py = `echo "__VJ_START__"; python3 -c 'import subprocess,json; out=subprocess.check_output(["launchctl","list"],text=True); items=[]; [items.append({"name":p[2],"displayName":p[2],"status":"Running" if p[0]!="-" else "Stopped","startType":"Automatic"}) for l in out.splitlines()[1:81] for p in [l.split(None,2)] if len(p)==3]; print(json.dumps(items))'; echo "__VJ_END__"`;
      const res = await this.executeCommandOnNode(deviceId, py, { runAs: 'system', timeoutMs: 15000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const items = JSON.parse(extractDelimitedJson(res.output)) as ServiceItem[];
          if (Array.isArray(items)) {
            this.serviceCache.set(deviceId, items);
            return items;
          }
        } catch (err: any) {
          this.lastToolError = `Failed to parse live macOS service output: ${err?.message || 'invalid JSON'}`;
        }
      } else if (!res.live || res.exitCode !== 0) {
        this.lastToolError = res.output || 'Endpoint did not respond to live service query.';
      }
    }

    return [];
  }

  public async manageService(
    deviceId: string,
    serviceName: string,
    action: 'start' | 'stop' | 'restart',
    actorUsername = 'admin'
  ): Promise<boolean> {
    if (!SERVICE_NAME_REGEX.test(serviceName)) {
      throw new Error('Invalid service name: only alphanumeric characters, dots, underscores, @, and hyphens are allowed.');
    }
    if (!['start', 'stop', 'restart'].includes(action)) {
      throw new Error('Invalid service action: must be start, stop, or restart.');
    }

    const osType = this.getDeviceOs(deviceId);
    const psVerb = action === 'start' ? 'Start-Service' : action === 'stop' ? 'Stop-Service' : 'Restart-Service';
    const nativeCmd =
      osType === 'windows'
        ? `${psVerb} -Name ${quotePowerShellLiteral(serviceName)} -Force`
        : osType === 'macos'
          ? `launchctl ${action === 'restart' ? 'kickstart -k' : action} ${quoteBashLiteral(`system/${serviceName}`)}`
          : `systemctl ${action} ${quoteBashLiteral(serviceName)}`;

    const res = await this.executeCommandOnNode(deviceId, nativeCmd, { runAs: 'system', timeoutMs: 8000 });
    this.serviceCache.delete(deviceId);

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Service State Changed', ?)
    `).run(`aud-svc-${crypto.randomUUID()}`, actorUsername, deviceId, `Action '${action}' executed on ${serviceName}`);
    return res.exitCode === 0;
  }

  // ============================================================================
  // Live Remote Registry / sysctl / plist Browser
  // ============================================================================
  public async getRegistryKeys(regPath: string, deviceId = 'default'): Promise<{ subkeys: string[]; values: RegistryEntry[] }> {
    this.lastToolError = null;
    const osType = this.getDeviceOs(deviceId);
    const normalizedPath =
      regPath ||
      (osType === 'windows'
        ? 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
        : osType === 'macos'
          ? 'NSGlobalDomain'
          : 'kernel');
    const cacheKey = `${deviceId}::${normalizedPath}`;
    const cached = this.registryCache.get(cacheKey);
    if (cached) return cached;

    if (osType === 'windows') {
      const litPath = normalizeWindowsRegistryLiteralPath(normalizedPath);
      const ps = `Write-Output "__VJ_START__"; $p = ${quotePowerShellLiteral(litPath)}; $subs = @(Get-ChildItem -LiteralPath $p -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName); $vals = @(); $item = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue; if ($item) { foreach ($vn in $item.GetValueNames()) { $vals += @{ path = ${quotePowerShellLiteral(normalizedPath)}; name = if ($vn) { $vn } else { '(Default)' }; type = 'REG_' + $item.GetValueKind($vn).ToString().ToUpper(); value = [string]$item.GetValue($vn) } } }; @{ subkeys = $subs; values = $vals } | ConvertTo-Json -Depth 4 -Compress; Write-Output "__VJ_END__"`;
      const res = await this.executeCommandOnNode(deviceId, ps, { runAs: 'system', timeoutMs: 15000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const parsed = JSON.parse(extractDelimitedJson(res.output));
          const result = {
            subkeys: Array.isArray(parsed.subkeys) ? parsed.subkeys.map(String) : [],
            values: Array.isArray(parsed.values) ? parsed.values : []
          };
          this.registryCache.set(cacheKey, result);
          return result;
        } catch (err: any) {
          this.lastToolError = `Failed to parse live registry output: ${err?.message || 'invalid JSON'}`;
        }
      } else if (!res.live || res.exitCode !== 0) {
        this.lastToolError = res.output || 'Endpoint did not respond to live registry query.';
      }
    } else if (osType === 'linux') {
      const sysctlPrefix = normalizedPath
        .replace(/^\/proc\/sys\//, '')
        .replace(/\//g, '.')
        .replace(/[^a-zA-Z0-9_.-]/g, '') || 'kernel';
      const py = `echo "__VJ_START__"; python3 - ${quoteBashLiteral(sysctlPrefix)} <<'PY'\nimport subprocess,json,sys\npref = sys.argv[1]\nout = subprocess.check_output(["sysctl","-a"],text=True,stderr=subprocess.DEVNULL)\nvals = []\nfor l in out.splitlines():\n  if "=" not in l: continue\n  k,v = l.split("=",1)\n  k = k.strip()\n  if pref in ("all","*") or k.startswith(pref + ".") or k == pref:\n    vals.append({"path": pref, "name": k, "type": "REG_SZ", "value": v.strip()})\n  if len(vals) >= 100: break\nprint(json.dumps({"subkeys":["kernel","net.ipv4","vm","fs"],"values":vals}))\nPY\necho "__VJ_END__"`;
      const res = await this.executeCommandOnNode(deviceId, py, { runAs: 'system', timeoutMs: 15000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const parsed = JSON.parse(extractDelimitedJson(res.output));
          this.registryCache.set(cacheKey, parsed);
          return parsed;
        } catch (err: any) {
          this.lastToolError = `Failed to parse live sysctl output: ${err?.message || 'invalid JSON'}`;
        }
      } else if (!res.live || res.exitCode !== 0) {
        this.lastToolError = res.output || 'Endpoint did not respond to live sysctl query.';
      }
    } else if (osType === 'macos') {
      const domainArg = normalizedPath.replace(/[^a-zA-Z0-9._/-]/g, '') || 'NSGlobalDomain';
      const py = `echo "__VJ_START__"; python3 - ${quoteBashLiteral(domainArg)} <<'PY'\nimport subprocess,json,plistlib,sys\ndom = sys.argv[1]\nout = subprocess.check_output(["defaults","export",dom,"-"],stderr=subprocess.DEVNULL)\ndata = plistlib.loads(out)\nvals = [{"path":dom,"name":str(k),"type":"REG_SZ","value":str(v)[:200]} for k,v in list(data.items())[:80]]\nprint(json.dumps({"subkeys":["NSGlobalDomain","/Library/Preferences/.GlobalPreferences.plist"],"values":vals}))\nPY\necho "__VJ_END__"`;
      const res = await this.executeCommandOnNode(deviceId, py, { runAs: 'system', timeoutMs: 15000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const parsed = JSON.parse(extractDelimitedJson(res.output));
          this.registryCache.set(cacheKey, parsed);
          return parsed;
        } catch (err: any) {
          this.lastToolError = `Failed to parse macOS plist defaults: ${err?.message || 'invalid JSON'}`;
        }
      } else if (!res.live || res.exitCode !== 0) {
        this.lastToolError = res.output || 'Endpoint did not respond to macOS defaults query.';
      }
    }

    return { subkeys: [], values: [] };
  }

  public async setRegistryValue(
    deviceId: string,
    regPath: string,
    entry: RegistryEntry,
    actorUsername = 'admin'
  ): Promise<{ subkeys: string[]; values: RegistryEntry[] }> {
    const osType = this.getDeviceOs(deviceId);
    if (osType === 'macos') {
      throw new Error('Registry / sysctl write is not supported on macOS endpoints.');
    }

    if (osType === 'windows') {
      const litPath = normalizeWindowsRegistryLiteralPath(regPath);
      let psType = 'String';
      let psValueExpr = quotePowerShellLiteral(String(entry.value));

      if (entry.type === 'REG_DWORD') {
        psType = 'DWord';
        const raw = String(entry.value).trim();
        const parsedInt = /^0x/i.test(raw) ? Number.parseInt(raw, 16) : Number.parseInt(raw, 10);
        if (!Number.isInteger(parsedInt) || parsedInt < 0 || parsedInt > 0xffffffff) {
          throw new Error('Invalid REG_DWORD integer value.');
        }
        psValueExpr = String(parsedInt);
      } else if (entry.type === 'REG_BINARY') {
        psType = 'Binary';
        const hexClean = String(entry.value || '').replace(/[^0-9a-fA-F]/g, '');
        if (!hexClean || hexClean.length % 2 !== 0) {
          throw new Error('REG_BINARY value must be an even-length hexadecimal string.');
        }
        const byteItems: string[] = [];
        for (let i = 0; i < hexClean.length; i += 2) {
          byteItems.push(`0x${hexClean.slice(i, i + 2)}`);
        }
        psValueExpr = `([byte[]]@(${byteItems.join(',')}))`;
      } else if (entry.type === 'REG_MULTI_SZ') {
        psType = 'MultiString';
        const parts = Array.isArray(entry.value)
          ? (entry.value as unknown[]).map((x) => quotePowerShellLiteral(String(x)))
          : String(entry.value ?? '')
              .split(/\r?\n/)
              .map((line) => quotePowerShellLiteral(line));
        psValueExpr = `([string[]]@(${parts.join(',')}))`;
      }

      const cmd = `if (-not (Test-Path -LiteralPath ${quotePowerShellLiteral(litPath)})) { New-Item -Path ${quotePowerShellLiteral(litPath)} -Force -ErrorAction Stop | Out-Null }; Set-ItemProperty -LiteralPath ${quotePowerShellLiteral(litPath)} -Name ${quotePowerShellLiteral(entry.name)} -Value ${psValueExpr} -Type ${psType} -ErrorAction Stop`;
      const res = await this.executeCommandOnNode(deviceId, cmd, { runAs: 'system', timeoutMs: 7000 });
      if (!res.live || res.exitCode !== 0) {
        throw new Error(res.output || `Failed to set Windows registry value ${regPath}\\${entry.name}.`);
      }
    } else if (osType === 'linux') {
      if (!/^[a-z0-9_.-]{2,96}$/i.test(entry.name)) {
        throw new Error(`Invalid Linux sysctl key '${entry.name}'.`);
      }
      const res = await this.executeCommandOnNode(
        deviceId,
        `sysctl -w ${quoteBashLiteral(`${entry.name}=${String(entry.value)}`)}`,
        { runAs: 'system', timeoutMs: 6000 }
      );
      if (!res.live || res.exitCode !== 0) {
        throw new Error(res.output || `Failed to set sysctl key '${entry.name}'.`);
      }
    }

    this.registryCache.delete(`${deviceId}::${regPath}`);
    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'System Config / Registry Modified', ?)
    `).run(`aud-reg-${crypto.randomUUID()}`, actorUsername, deviceId, `Set ${regPath}\\${entry.name} (${entry.type}) = ${entry.value}`);
    return this.getRegistryKeys(regPath, deviceId);
  }

  public async deleteRegistryValue(
    deviceId: string,
    regPath: string,
    name: string,
    actorUsername = 'admin'
  ): Promise<{ subkeys: string[]; values: RegistryEntry[] }> {
    const osType = this.getDeviceOs(deviceId);
    if (osType !== 'windows') {
      throw new Error(`Registry value deletion is not supported on ${osType} endpoints.`);
    }

    const litPath = normalizeWindowsRegistryLiteralPath(regPath);
    const cmd = `Remove-ItemProperty -LiteralPath ${quotePowerShellLiteral(litPath)} -Name ${quotePowerShellLiteral(name)} -ErrorAction Stop`;
    const res = await this.executeCommandOnNode(deviceId, cmd, { runAs: 'system', timeoutMs: 7000 });
    if (!res.live || res.exitCode !== 0) {
      throw new Error(res.output || `Failed to delete registry value ${regPath}\\${name}.`);
    }

    this.registryCache.delete(`${deviceId}::${regPath}`);
    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'System Config / Registry Deleted', ?)
    `).run(`aud-reg-${crypto.randomUUID()}`, actorUsername, deviceId, `Deleted config/registry value ${regPath}\\${name}`);
    return this.getRegistryKeys(regPath, deviceId);
  }

  // ============================================================================
  // Live Task Scheduler / Cron & systemd Timers / launchd Jobs
  // ============================================================================
  public async getScheduledTasks(deviceId: string): Promise<ScheduledTaskItem[]> {
    const cached = this.taskCache.get(deviceId);
    if (cached) return cached;
    this.lastToolError = null;

    const osType = this.getDeviceOs(deviceId);
    if (osType === 'windows') {
      const ps = `Write-Output "__VJ_START__"; Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\Windows\\*' } | Select-Object -First 60 TaskName, TaskPath, @{N='StateStr';E={$_.State.ToString()}} | ConvertTo-Json -Compress; Write-Output "__VJ_END__"`;
      const res = await this.executeCommandOnNode(deviceId, ps, { runAs: 'system', timeoutMs: 15000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const parsed = JSON.parse(extractDelimitedJson(res.output));
          const arr = Array.isArray(parsed) ? parsed : [parsed];
          const items: ScheduledTaskItem[] = arr.map((t: any) => ({
            name: String(t.TaskName || ''),
            path: String(t.TaskPath || '\\'),
            state: t.StateStr === 'Running' ? 'Running' : t.StateStr === 'Disabled' ? 'Disabled' : 'Ready',
            lastRunTime: 'Live',
            nextRunTime: 'Scheduled',
            lastResult: '0x0'
          }));
          this.taskCache.set(deviceId, items);
          return items;
        } catch (err: any) {
          this.lastToolError = `Failed to parse live scheduled tasks: ${err?.message || 'invalid JSON'}`;
        }
      } else if (!res.live || res.exitCode !== 0) {
        this.lastToolError = res.output || 'Endpoint did not respond to live scheduled tasks query.';
      }
    } else if (osType === 'linux') {
      const py = `echo "__VJ_START__"; python3 -c 'import subprocess,json; out=subprocess.check_output(["systemctl","list-timers","--all","--no-pager","--no-legend"],text=True); items=[]; [items.append({"name":p[-2],"path":"/lib/systemd/system/"+p[-2],"state":"Ready","lastRunTime":"Active","nextRunTime":p[0]+" "+p[1],"lastResult":"0"}) for l in out.splitlines() for p in [l.split()] if len(p)>=4 and ".timer" in l]; print(json.dumps(items[:60]))'; echo "__VJ_END__"`;
      const res = await this.executeCommandOnNode(deviceId, py, { runAs: 'system', timeoutMs: 15000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const items = JSON.parse(extractDelimitedJson(res.output)) as ScheduledTaskItem[];
          if (Array.isArray(items)) {
            this.taskCache.set(deviceId, items);
            return items;
          }
        } catch (err: any) {
          this.lastToolError = `Failed to parse Linux systemd timers: ${err?.message || 'invalid JSON'}`;
        }
      } else if (!res.live || res.exitCode !== 0) {
        this.lastToolError = res.output || 'Endpoint did not respond to live timer query.';
      }
    } else if (osType === 'macos') {
      const py = `echo "__VJ_START__"; python3 -c 'import subprocess,json; out=subprocess.check_output(["launchctl","list"],text=True); items=[]; [items.append({"name":p[2],"path":"/Library/LaunchDaemons/"+p[2]+".plist","state":"Running" if p[0]!="-" else "Ready","lastRunTime":"launchd","nextRunTime":"OnDemand","lastResult":p[1]}) for l in out.splitlines()[1:61] for p in [l.split(None,2)] if len(p)==3]; print(json.dumps(items))'; echo "__VJ_END__"`;
      const res = await this.executeCommandOnNode(deviceId, py, { runAs: 'system', timeoutMs: 15000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const items = JSON.parse(extractDelimitedJson(res.output)) as ScheduledTaskItem[];
          if (Array.isArray(items)) {
            this.taskCache.set(deviceId, items);
            return items;
          }
        } catch (err: any) {
          this.lastToolError = `Failed to parse macOS launchctl jobs: ${err?.message || 'invalid JSON'}`;
        }
      } else if (!res.live || res.exitCode !== 0) {
        this.lastToolError = res.output || 'Endpoint did not respond to live launchd query.';
      }
    }

    return [];
  }

  public async manageScheduledTask(
    deviceId: string,
    taskName: string,
    action: 'run' | 'enable' | 'disable',
    actorUsername = 'admin'
  ): Promise<ScheduledTaskItem[]> {
    if (!['run', 'enable', 'disable'].includes(action)) {
      throw new Error('Invalid scheduled task action.');
    }
    const osType = this.getDeviceOs(deviceId);
    if (osType === 'windows') {
      const verb =
        action === 'run' ? 'Start-ScheduledTask' : action === 'enable' ? 'Enable-ScheduledTask' : 'Disable-ScheduledTask';
      await this.executeCommandOnNode(
        deviceId,
        `${verb} -TaskName ${quotePowerShellLiteral(taskName)} -ErrorAction SilentlyContinue`,
        { runAs: 'system', timeoutMs: 7000 }
      );
    } else if (osType === 'linux' && SERVICE_NAME_REGEX.test(taskName)) {
      const cmd =
        action === 'run'
          ? `systemctl start ${quoteBashLiteral(taskName.replace(/\.timer$/, '.service'))}`
          : `systemctl ${action} ${quoteBashLiteral(taskName)}`;
      await this.executeCommandOnNode(deviceId, cmd, { runAs: 'system', timeoutMs: 7000 });
    } else if (osType === 'macos' && SERVICE_NAME_REGEX.test(taskName)) {
      const targetDomain = quoteBashLiteral(`system/${taskName}`);
      const cmd =
        action === 'run' ? `launchctl kickstart -k ${targetDomain}` : `launchctl ${action} ${targetDomain}`;
      await this.executeCommandOnNode(deviceId, cmd, { runAs: 'system', timeoutMs: 7000 });
    }

    this.taskCache.delete(deviceId);
    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Scheduled Task Action', ?)
    `).run(`aud-tsk-${crypto.randomUUID()}`, actorUsername, deviceId, `Executed '${action}' on scheduled task "${taskName}"`);
    return this.getScheduledTasks(deviceId);
  }

  // ============================================================================
  // Live Remote File Manager (Upload, Download, Mkdir, Safe Delete)
  // ============================================================================
  public async getDirectoryListing(deviceId: string, dirPath: string): Promise<FileItem[]> {
    this.lastToolError = null;
    const osType = this.getDeviceOs(deviceId);
    const normalizedDir = canonicalizeRemotePath(dirPath, osType);
    const cacheKey = `${deviceId}::${normalizedDir}`;
    const cached = this.fileCache.get(cacheKey);
    if (cached) return cached;

    if (osType === 'windows') {
      const ps = `Write-Output "__VJ_START__"; Get-ChildItem -LiteralPath ${quotePowerShellLiteral(normalizedDir)} -Force -ErrorAction Stop | Select-Object -First 150 Name, FullName, @{N='Size';E={if ($_.PSIsContainer) {0} else {[long]$_.Length}}}, PSIsContainer, @{N='Mod';E={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')}}, Mode | ConvertTo-Json -Compress; Write-Output "__VJ_END__"`;
      const res = await this.executeCommandOnNode(deviceId, ps, { runAs: 'system', timeoutMs: 15000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const rawJson = extractDelimitedJson(res.output);
          if (!rawJson || rawJson === '__VJ_START__\n__VJ_END__') {
            this.fileCache.set(cacheKey, []);
            return [];
          }
          const parsed = JSON.parse(rawJson);
          const arr = Array.isArray(parsed) ? parsed : [parsed];
          const items: FileItem[] = arr
            .filter((f) => f && f.Name)
            .map((f) => ({
              name: String(f.Name),
              path: String(f.FullName),
              size: Number(f.Size || 0),
              isDirectory: Boolean(f.PSIsContainer),
              modified: String(f.Mod || ''),
              permissions: String(f.Mode || '-rw-r--r--')
            }));
          this.fileCache.set(cacheKey, items);
          return items;
        } catch (err: any) {
          this.lastToolError = `Failed to parse Windows directory listing: ${err?.message || 'invalid JSON'}`;
        }
      } else if (!res.live || res.exitCode !== 0) {
        this.lastToolError = res.output || `Unable to list directory '${normalizedDir}' on endpoint.`;
      }
    } else {
      const py = `echo "__VJ_START__"; if command -v python3 >/dev/null 2>&1; then python3 - ${quoteBashLiteral(normalizedDir)} <<'PY'\nimport os, stat, time, json, sys\np = sys.argv[1]\nout = []\nfor entry in sorted(os.scandir(p), key=lambda e: (not e.is_dir(follow_symlinks=False), e.name.lower()))[:150]:\n    st = entry.stat(follow_symlinks=False)\n    out.append({\n        "name": entry.name,\n        "path": os.path.join(p, entry.name),\n        "size": 0 if stat.S_ISDIR(st.st_mode) else st.st_size,\n        "isDirectory": stat.S_ISDIR(st.st_mode),\n        "modified": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),\n        "permissions": stat.filemode(st.st_mode)\n    })\nprint(json.dumps(out))\nPY\nelse ls -la ${quoteBashLiteral(normalizedDir)} | tail -n +2 | head -n 150 | awk -v dir=${quoteBashLiteral(normalizedDir)} '{name=$NF; isd=(substr($1,1,1)=="d")?"true":"false"; printf "%s{\\"name\\":\\"%s\\",\\"path\\":\\"%s/%s\\",\\"size\\":%s,\\"isDirectory\\":%s,\\"modified\\":\\"%s %s\\",\\"permissions\\":\\"%s\\"}", (NR>1?",":""), name, dir, name, $5, isd, $6, $7, $1}' | awk 'BEGIN{printf "["} {print} END{print "]"}'; fi; echo "__VJ_END__"`;
      const res = await this.executeCommandOnNode(deviceId, py, { runAs: 'system', timeoutMs: 15000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const items = JSON.parse(extractDelimitedJson(res.output)) as FileItem[];
          if (Array.isArray(items)) {
            this.fileCache.set(cacheKey, items);
            return items;
          }
        } catch (err: any) {
          this.lastToolError = `Failed to parse directory listing: ${err?.message || 'invalid JSON'}`;
        }
      } else if (!res.live || res.exitCode !== 0) {
        this.lastToolError = res.output || `Unable to list directory '${normalizedDir}' on endpoint.`;
      }
    }

    return [];
  }

  public async manageFile(
    deviceId: string,
    dirPath: string,
    action: 'mkdir' | 'delete' | 'upload',
    name: string,
    _size = 2048,
    contentBase64?: string,
    actorUsername = 'admin'
  ): Promise<FileItem[]> {
    const cleanName = String(name || '').trim().replace(/\0/g, '');
    if (!cleanName || cleanName === '.' || cleanName === '..' || cleanName.includes('/') || cleanName.includes('\\')) {
      throw new Error('Invalid file or directory name.');
    }

    const osType = this.getDeviceOs(deviceId);
    const normalizedDir = canonicalizeRemotePath(dirPath, osType);
    const fullPath =
      osType === 'windows' ? path.win32.join(normalizedDir, cleanName) : path.posix.join(normalizedDir, cleanName);

    if (action === 'delete') {
      if (osType === 'windows') {
        if (PROTECTED_WINDOWS_PATHS.has(fullPath.toLowerCase().replace(/\\+$/, ''))) {
          throw new Error(`Refusing to delete protected operating system root path: ${fullPath}`);
        }
      } else {
        if (PROTECTED_UNIX_PATHS.has(fullPath.replace(/\/+$/, '') || '/')) {
          throw new Error(`Refusing to delete protected operating system root path: ${fullPath}`);
        }
      }
      this.fileContentCache.delete(`${deviceId}::${fullPath}`);
      const delCmd =
        osType === 'windows'
          ? `Remove-Item -LiteralPath ${quotePowerShellLiteral(fullPath)} -Recurse -Force -ErrorAction Stop`
          : `rm -rf -- ${quoteBashLiteral(fullPath)}`;
      const res = await this.executeCommandOnNode(deviceId, delCmd, { runAs: 'system', timeoutMs: 8000 });
      if (!res.live || res.exitCode !== 0) {
        throw new Error(res.output || `Failed to delete '${fullPath}' on endpoint.`);
      }
    } else if (action === 'mkdir') {
      const mkdirCmd =
        osType === 'windows'
          ? `New-Item -ItemType Directory -Path ${quotePowerShellLiteral(fullPath)} -Force -ErrorAction Stop | Out-Null`
          : `mkdir -p -- ${quoteBashLiteral(fullPath)}`;
      const res = await this.executeCommandOnNode(deviceId, mkdirCmd, { runAs: 'system', timeoutMs: 7000 });
      if (!res.live || res.exitCode !== 0) {
        throw new Error(res.output || `Failed to create directory '${fullPath}' on endpoint.`);
      }
    } else if (action === 'upload') {
      if (!contentBase64) {
        throw new Error('Missing base64 file content for upload.');
      }
      const cleanB64 = contentBase64.includes(',') ? contentBase64.split(',').pop()! : contentBase64;
      const buf = Buffer.from(cleanB64, 'base64');
      if (buf.length > 10 * 1024 * 1024) {
        throw new Error('Remote file upload exceeds 10 MB inline transfer limit.');
      }
      const b64Safe = buf.toString('base64');
      const chunkLimit = osType === 'windows' ? 16384 : 49152;
      if (b64Safe.length <= chunkLimit) {
        const uploadCmd =
          osType === 'windows'
            ? `[IO.File]::WriteAllBytes(${quotePowerShellLiteral(fullPath)}, [Convert]::FromBase64String('${b64Safe}'))`
            : `base64 -d <<'VITRINE_B64' > ${quoteBashLiteral(fullPath)}\n${b64Safe}\nVITRINE_B64`;
        const res = await this.executeCommandOnNode(deviceId, uploadCmd, { runAs: 'system', timeoutMs: 12000 });
        if (!res.live || res.exitCode !== 0) {
          throw new Error(res.output || `Failed to upload '${fullPath}' to endpoint.`);
        }
      } else {
        const stageToken = crypto.randomBytes(6).toString('hex');
        if (osType === 'windows') {
          const tmpB64Path = `${fullPath}.vitrine-${stageToken}.b64`;
          const tmpLit = quotePowerShellLiteral(tmpB64Path);
          const targetLit = quotePowerShellLiteral(fullPath);
          try {
            for (let i = 0; i < b64Safe.length; i += chunkLimit) {
              const part = b64Safe.slice(i, i + chunkLimit);
              const cmd =
                i === 0
                  ? `[IO.File]::WriteAllText(${tmpLit}, '${part}')`
                  : `[IO.File]::AppendAllText(${tmpLit}, '${part}')`;
              const chunkRes = await this.executeCommandOnNode(deviceId, cmd, { runAs: 'system', timeoutMs: 12000 });
              if (!chunkRes.live || chunkRes.exitCode !== 0) {
                throw new Error(chunkRes.output || `Chunked upload failed at offset ${i}.`);
              }
            }
            const finCmd = `[IO.File]::WriteAllBytes(${targetLit}, [Convert]::FromBase64String([IO.File]::ReadAllText(${tmpLit})))`;
            const finRes = await this.executeCommandOnNode(deviceId, finCmd, { runAs: 'system', timeoutMs: 15000 });
            if (!finRes.live || finRes.exitCode !== 0) {
              throw new Error(finRes.output || `Failed to finalize uploaded file '${fullPath}'.`);
            }
          } finally {
            await this.executeCommandOnNode(
              deviceId,
              `Remove-Item -LiteralPath ${tmpLit} -Force -ErrorAction SilentlyContinue`,
              { runAs: 'system', timeoutMs: 5000 }
            ).catch(() => {});
          }
        } else {
          const tmpB64Path = `/tmp/.vitrine-up-${stageToken}.b64`;
          const tmpQ = quoteBashLiteral(tmpB64Path);
          const targetQ = quoteBashLiteral(fullPath);
          try {
            for (let i = 0; i < b64Safe.length; i += chunkLimit) {
              const part = b64Safe.slice(i, i + chunkLimit);
              const redir = i === 0 ? '>' : '>>';
              const cmd = `cat <<'VITRINE_B64' ${redir} ${tmpQ}\n${part}\nVITRINE_B64`;
              const chunkRes = await this.executeCommandOnNode(deviceId, cmd, { runAs: 'system', timeoutMs: 12000 });
              if (!chunkRes.live || chunkRes.exitCode !== 0) {
                throw new Error(chunkRes.output || `Chunked upload failed at offset ${i}.`);
              }
            }
            const finRes = await this.executeCommandOnNode(
              deviceId,
              `base64 -d ${tmpQ} > ${targetQ}`,
              { runAs: 'system', timeoutMs: 15000 }
            );
            if (!finRes.live || finRes.exitCode !== 0) {
              throw new Error(finRes.output || `Failed to decode uploaded file '${fullPath}'.`);
            }
          } finally {
            await this.executeCommandOnNode(deviceId, `rm -f -- ${tmpQ}`, { runAs: 'system', timeoutMs: 5000 }).catch(
              () => {}
            );
          }
        }
      }
      this.fileContentCache.set(`${deviceId}::${fullPath}`, buf);
    }

    this.fileCache.delete(`${deviceId}::${normalizedDir}`);
    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Remote File Operation', ?)
    `).run(`aud-file-${crypto.randomUUID()}`, actorUsername, deviceId, `Executed '${action}' on ${fullPath}`);

    return this.getDirectoryListing(deviceId, normalizedDir);
  }

  public async downloadFile(deviceId: string, filePath: string, actorUsername = 'admin'): Promise<{
    filename: string;
    contentBase64: string;
    size: number;
  }> {
    const osType = this.getDeviceOs(deviceId);
    const cleanPath = canonicalizeRemotePath(filePath, osType);
    const filename =
      (osType === 'windows' ? path.win32.basename(cleanPath) : path.posix.basename(cleanPath)) || 'download.bin';
    const cacheKey = `${deviceId}::${cleanPath}`;

    let buf = this.fileContentCache.get(cacheKey);
    if (!buf) {
      const q = quoteBashLiteral(cleanPath);
      const readCmd =
        osType === 'windows'
          ? `$item = Get-Item -LiteralPath ${quotePowerShellLiteral(cleanPath)} -Force -ErrorAction Stop; if ($item.PSIsContainer) { throw 'Path is a directory' }; if ($item.Length -gt 10485760) { throw 'File exceeds 10MB download limit' }; [Convert]::ToBase64String([IO.File]::ReadAllBytes($item.FullName))`
          : `test -f ${q} && [ "$(wc -c < ${q})" -le 10485760 ] && { base64 -w 0 ${q} 2>/dev/null || base64 ${q}; }`;
      const res = await this.executeCommandOnNode(deviceId, readCmd, { runAs: 'system', timeoutMs: 12000 });
      const cleaned = String(res.output || '').replace(/\s+/g, '');
      if (!res.live || res.exitCode !== 0 || !cleaned || !/^[A-Za-z0-9+/=]+$/.test(cleaned)) {
        throw new Error(
          res.output ||
            `Unable to stream remote file '${cleanPath}' — endpoint offline, file missing/unreadable, empty, or exceeds 10 MB limit.`
        );
      }
      buf = Buffer.from(cleaned, 'base64');
      this.fileContentCache.set(cacheKey, buf);
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Remote File Downloaded', ?)
    `).run(`aud-fget-${crypto.randomUUID()}`, actorUsername, deviceId, `Downloaded ${cleanPath} (${buf.length} bytes)`);

    return {
      filename,
      contentBase64: buf.toString('base64'),
      size: buf.length
    };
  }

  // ============================================================================
  // Endpoint Network Quarantine (Genuine Host Firewall Isolation)
  // ============================================================================
  public toggleQuarantine(deviceId: string, quarantine: boolean, actorUsername = 'admin'): boolean {
    const dev = db.prepare('SELECT id, status, os_type FROM devices WHERE id = ?').get(deviceId) as any;
    if (!dev) return false;

    const nextStatus = quarantine ? 'isolated' : dev.status === 'isolated' ? 'online' : dev.status || 'offline';
    db.prepare('UPDATE devices SET quarantined = ?, status = ? WHERE id = ?').run(
      quarantine ? 1 : 0,
      nextStatus,
      deviceId
    );

    const osType = this.getDeviceOs(deviceId);
    const settings = (db.prepare('SELECT custom_domain, meshcentral_url FROM settings WHERE id = 1').get() || {}) as any;

    const rawCandidateUrls: Array<string | null | undefined> = [
      this.connectedServerUrl,
      settings.meshcentral_url,
      settings.custom_domain,
      process.env.VITRINE_PUBLIC_URL,
      process.env.PUBLIC_URL,
      process.env.PORT ? `http://127.0.0.1:${process.env.PORT}` : null
    ];
    try {
      const fedServers = db.prepare('SELECT url FROM mesh_servers').all() as Array<{ url?: string }>;
      for (const s of fedServers) {
        if (s?.url) rawCandidateUrls.push(s.url);
      }
    } catch {}

    const mgmtEndpoints = new Map<string, { hostname: string; port: number; ipFamily: number }>();
    for (const raw of rawCandidateUrls) {
      if (!raw || !String(raw).trim()) continue;
      try {
        const trimmed = String(raw).trim();
        const u = trimmed.includes('://') ? new URL(trimmed) : new URL(`https://${trimmed}`);
        const cleanHost = u.hostname.replace(/^\[|\]$/g, '');
        const ipFamily = net.isIP(cleanHost);
        if (ipFamily === 0 && !/^[a-zA-Z0-9.-]+$/.test(cleanHost)) continue;
        const port = u.port
          ? Number.parseInt(u.port, 10)
          : u.protocol === 'http:' || u.protocol === 'ws:'
            ? 80
            : 443;
        if (!Number.isInteger(port) || port < 1 || port > 65535) continue;
        mgmtEndpoints.set(`${cleanHost.toLowerCase()}:${port}`, { hostname: cleanHost, port, ipFamily });
      } catch {}
    }

    const endpointList = Array.from(mgmtEndpoints.values());

    if (osType === 'windows') {
      // On Windows Firewall, Explicit Block rules override Allow rules!
      // Proper isolation sets Profile DefaultOutboundAction=Block + DefaultInboundAction=Block
      // and adds explicit Allow rules ONLY for DNS, DHCP, MeshAgent/VitrineAgent binaries, AND
      // outbound TCP to management endpoints:ports (so powershell.exe Companion & custom ports stay reachable)!
      const mgmtPsRules = endpointList.map((ep, idx) => {
        if (ep.ipFamily !== 0) {
          return `New-NetFirewallRule -DisplayName 'VitrineQuar-Mgmt-${idx}' -Group 'VitrineQuarantine' -Direction Outbound -Protocol TCP -RemoteAddress ${quotePowerShellLiteral(ep.hostname)} -RemotePort ${ep.port} -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null`;
        }
        const hostLit = quotePowerShellLiteral(ep.hostname);
        return `try { $mIps = @([System.Net.Dns]::GetHostAddresses(${hostLit}) | ForEach-Object { $_.IPAddressToString } | Select-Object -Unique); if ($mIps.Count -gt 0) { New-NetFirewallRule -DisplayName 'VitrineQuar-Mgmt-${idx}' -Group 'VitrineQuarantine' -Direction Outbound -Protocol TCP -RemoteAddress $mIps -RemotePort ${ep.port} -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null } } catch {}`;
      });

      const cmd = quarantine
        ? [
            `Remove-NetFirewallRule -Group 'VitrineQuarantine' -ErrorAction SilentlyContinue`,
            `New-NetFirewallRule -DisplayName 'VitrineQuar-DNS-UDP' -Group 'VitrineQuarantine' -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow -Profile Any | Out-Null`,
            `New-NetFirewallRule -DisplayName 'VitrineQuar-DNS-TCP' -Group 'VitrineQuarantine' -Direction Outbound -Protocol TCP -RemotePort 53 -Action Allow -Profile Any | Out-Null`,
            `New-NetFirewallRule -DisplayName 'VitrineQuar-DHCP' -Group 'VitrineQuarantine' -Direction Outbound -Protocol UDP -LocalPort 68 -RemotePort 67 -Action Allow -Profile Any | Out-Null`,
            `Get-Process -Name 'MeshAgent*','VitrineAgent*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path -Unique | Where-Object { $_ } | ForEach-Object { New-NetFirewallRule -DisplayName "VitrineAllow-$((Split-Path $_ -Leaf))" -Group 'VitrineQuarantine' -Direction Outbound -Program $_ -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null }`,
            ...mgmtPsRules,
            `Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block`
          ].join('; ')
        : `Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow; Remove-NetFirewallRule -Group 'VitrineQuarantine' -ErrorAction SilentlyContinue`;
      void this.executeCommandOnNode(deviceId, cmd, { runAs: 'system', timeoutMs: 8000 });
    } else if (osType === 'linux') {
      const v4EndpointStmts: string[] = [];
      const v6EndpointStmts: string[] = [];
      for (const ep of endpointList) {
        const qHost = quoteBashLiteral(ep.hostname);
        if (ep.ipFamily === 4) {
          v4EndpointStmts.push(
            `iptables -A VITRINE_QUAR -p tcp -d ${qHost} --dport ${ep.port} -j ACCEPT`,
            `iptables -A VITRINE_QUAR -p tcp -s ${qHost} --sport ${ep.port} -j ACCEPT`
          );
        } else if (ep.ipFamily === 6) {
          v6EndpointStmts.push(
            `ip6tables -A VITRINE_QUAR -p tcp -d ${qHost} --dport ${ep.port} -j ACCEPT`,
            `ip6tables -A VITRINE_QUAR -p tcp -s ${qHost} --sport ${ep.port} -j ACCEPT`
          );
        } else {
          v4EndpointStmts.push(
            `for ip in $(getent ahostsv4 ${qHost} 2>/dev/null | awk '{print $1}' | sort -u); do iptables -A VITRINE_QUAR -p tcp -d "$ip" --dport ${ep.port} -j ACCEPT; iptables -A VITRINE_QUAR -p tcp -s "$ip" --sport ${ep.port} -j ACCEPT; done`
          );
          v6EndpointStmts.push(
            `for ip6 in $(getent ahostsv6 ${qHost} 2>/dev/null | awk '{print $1}' | sort -u); do ip6tables -A VITRINE_QUAR -p tcp -d "$ip6" --dport ${ep.port} -j ACCEPT; ip6tables -A VITRINE_QUAR -p tcp -s "$ip6" --sport ${ep.port} -j ACCEPT; done`
          );
        }
      }

      const ip6ApplyBlock = [
        `if command -v ip6tables >/dev/null 2>&1; then`,
        `ip6tables -N VITRINE_QUAR 2>/dev/null || ip6tables -F VITRINE_QUAR;`,
        `ip6tables -A VITRINE_QUAR -i lo -j ACCEPT;`,
        `ip6tables -A VITRINE_QUAR -o lo -j ACCEPT;`,
        `ip6tables -A VITRINE_QUAR -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT;`,
        `ip6tables -A VITRINE_QUAR -p udp --dport 53 -j ACCEPT;`,
        `ip6tables -A VITRINE_QUAR -p tcp --dport 53 -j ACCEPT;`,
        `ip6tables -A VITRINE_QUAR -p ipv6-icmp -j ACCEPT;`,
        ...(v6EndpointStmts.length > 0 ? [`${v6EndpointStmts.join('; ')};`] : []),
        `ip6tables -A VITRINE_QUAR -j DROP;`,
        `ip6tables -C OUTPUT -j VITRINE_QUAR 2>/dev/null || ip6tables -I OUTPUT 1 -j VITRINE_QUAR;`,
        `ip6tables -C INPUT -j VITRINE_QUAR 2>/dev/null || ip6tables -I INPUT 1 -j VITRINE_QUAR;`,
        `fi`
      ].join(' ');

      const cmd = quarantine
        ? [
            `iptables -N VITRINE_QUAR 2>/dev/null || iptables -F VITRINE_QUAR`,
            `iptables -A VITRINE_QUAR -i lo -j ACCEPT`,
            `iptables -A VITRINE_QUAR -o lo -j ACCEPT`,
            `iptables -A VITRINE_QUAR -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`,
            `iptables -A VITRINE_QUAR -p udp --dport 53 -j ACCEPT`,
            `iptables -A VITRINE_QUAR -p tcp --dport 53 -j ACCEPT`,
            `iptables -A VITRINE_QUAR -p udp --sport 68 --dport 67 -j ACCEPT`,
            ...v4EndpointStmts,
            `iptables -A VITRINE_QUAR -j DROP`,
            `iptables -C OUTPUT -j VITRINE_QUAR 2>/dev/null || iptables -I OUTPUT 1 -j VITRINE_QUAR`,
            `iptables -C INPUT -j VITRINE_QUAR 2>/dev/null || iptables -I INPUT 1 -j VITRINE_QUAR`,
            ip6ApplyBlock
          ].join('; ')
        : [
            `while iptables -D OUTPUT -j VITRINE_QUAR 2>/dev/null; do :; done`,
            `while iptables -D INPUT -j VITRINE_QUAR 2>/dev/null; do :; done`,
            `iptables -F VITRINE_QUAR 2>/dev/null || true`,
            `iptables -X VITRINE_QUAR 2>/dev/null || true`,
            `if command -v ip6tables >/dev/null 2>&1; then while ip6tables -D OUTPUT -j VITRINE_QUAR 2>/dev/null; do :; done; while ip6tables -D INPUT -j VITRINE_QUAR 2>/dev/null; do :; done; ip6tables -F VITRINE_QUAR 2>/dev/null || true; ip6tables -X VITRINE_QUAR 2>/dev/null || true; fi`
          ].join('; ');
      void this.executeCommandOnNode(deviceId, cmd, { runAs: 'system', timeoutMs: 8000 });
    } else {
      const endpointsJsonB64 = Buffer.from(
        JSON.stringify(endpointList.map((e) => ({ h: e.hostname, p: e.port }))),
        'utf8'
      ).toString('base64');
      const cmd = quarantine
        ? `python3 -c 'import base64,json,socket,subprocess; eps=json.loads(base64.b64decode("${endpointsJsonB64}").decode()); rules=["pass quick on lo0 all","pass out quick proto { tcp, udp } to any port 53","pass out quick proto udp from port 68 to any port 67"]; seen=set()\nfor e in eps:\n  try:\n    for info in socket.getaddrinfo(e["h"], e["p"], 0, socket.SOCK_STREAM):\n      ip=info[4][0].split("%")[0]; key=(ip,int(e["p"]))\n      if key not in seen:\n        seen.add(key); rules.append(f"pass out quick proto tcp to {ip} port {int(e[\\"p\\"])}")\n  except Exception: pass\nrules.append("block drop all"); subprocess.run(["pfctl","-a","com.vitrine.quarantine","-f","-"],input="\\n".join(rules)+"\\n",text=True,stderr=subprocess.DEVNULL); subprocess.run(["pfctl","-e"],stderr=subprocess.DEVNULL)' 2>/dev/null || true`
        : `pfctl -a com.vitrine.quarantine -F all 2>/dev/null || true`;
      void this.executeCommandOnNode(deviceId, cmd, { runAs: 'system', timeoutMs: 8000 });
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      `aud-quar-${crypto.randomUUID()}`,
      actorUsername,
      deviceId,
      quarantine ? 'Cyber Isolation Engaged' : 'Cyber Isolation Revoked',
      quarantine
        ? 'Applied host firewall quarantine blocking non-RMM lateral/internet traffic while preserving MeshCentral & Vitrine management tunnel.'
        : 'Removed VitrineQuarantine host firewall rules and restored normal network routing.'
    );

    return true;
  }

  // ============================================================================
  // Live Remote Event Viewer / journald / Unified Logs
  // ============================================================================
  public async getEventLogs(deviceId: string, channel = 'All', level = 'all', limit = 50): Promise<EventLogItem[]> {
    this.lastToolError = null;
    const safeLimit = Math.max(1, Math.min(200, Number(limit || 50)));
    const osType = this.getDeviceOs(deviceId);

    if (osType === 'windows') {
      const logName = channel && channel !== 'All' && channel !== 'all' ? channel : 'System';
      const ps = `Write-Output "__VJ_START__"; Get-WinEvent -LogName ${quotePowerShellLiteral(logName)} -MaxEvents ${safeLimit} -ErrorAction SilentlyContinue | Select-Object RecordId, @{N='TimeIso';E={$_.TimeCreated.ToUniversalTime().ToString('o')}}, ProviderName, Id, LevelDisplayName, LogName, Message | ConvertTo-Json -Compress; Write-Output "__VJ_END__"`;
      const res = await this.executeCommandOnNode(deviceId, ps, { runAs: 'system', timeoutMs: 15000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const parsed = JSON.parse(extractDelimitedJson(res.output));
          const arr = Array.isArray(parsed) ? parsed : [parsed];
          const items: EventLogItem[] = arr.map((e: any, idx: number) => ({
            id: Number(e.RecordId || idx + 1),
            timeGenerated: String(e.TimeIso || new Date().toISOString()),
            source: String(e.ProviderName || 'Windows'),
            eventId: Number(e.Id || 0),
            level:
              e.LevelDisplayName === 'Critical'
                ? 'Critical'
                : e.LevelDisplayName === 'Error'
                  ? 'Error'
                  : e.LevelDisplayName === 'Warning'
                    ? 'Warning'
                    : 'Information',
            channel: String(e.LogName || logName),
            message: String(e.Message || '').slice(0, 500)
          }));
          return level && level !== 'all'
            ? items.filter((i) => i.level.toLowerCase() === level.toLowerCase())
            : items;
        } catch (err: any) {
          this.lastToolError = `Failed to parse live Windows event logs: ${err?.message || 'invalid JSON'}`;
        }
      } else if (!res.live || res.exitCode !== 0) {
        this.lastToolError = res.output || 'Endpoint did not respond to live Windows event log query.';
      }
    } else if (osType === 'linux') {
      const py = `echo "__VJ_START__"; python3 -c 'import subprocess,json,datetime; out=subprocess.check_output(["journalctl","-n","${safeLimit}","-o","json","--no-pager"],text=True); items=[]; \nfor idx,l in enumerate(out.splitlines()):\n  try:\n    j=json.loads(l); p=int(j.get("PRIORITY",6)); lvl="Critical" if p<=2 else "Error" if p==3 else "Warning" if p==4 else "Information"; ts=int(j.get("__REALTIME_TIMESTAMP",0))/1e6; iso=datetime.datetime.fromtimestamp(ts,datetime.timezone.utc).isoformat() if ts else ""; items.append({"id":idx+1,"timeGenerated":iso,"source":j.get("SYSLOG_IDENTIFIER") or j.get("_COMM") or "kernel","eventId":int(j.get("_PID",0) or 0),"level":lvl,"channel":"journald","message":str(j.get("MESSAGE",""))[:500]})\n  except Exception: pass\nprint(json.dumps(items))'; echo "__VJ_END__"`;
      const res = await this.executeCommandOnNode(deviceId, py, { runAs: 'system', timeoutMs: 15000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const items = JSON.parse(extractDelimitedJson(res.output)) as EventLogItem[];
          if (Array.isArray(items)) {
            return level && level !== 'all'
              ? items.filter((i) => i.level.toLowerCase() === level.toLowerCase())
              : items;
          }
        } catch (err: any) {
          this.lastToolError = `Failed to parse Linux journald output: ${err?.message || 'invalid JSON'}`;
        }
      } else if (!res.live || res.exitCode !== 0) {
        this.lastToolError = res.output || 'Endpoint did not respond to live journalctl query.';
      }
    } else if (osType === 'macos') {
      const py = `echo "__VJ_START__"; python3 -c 'import subprocess,json; out=subprocess.check_output(["log","show","--style","compact","--last","30m"],text=True,stderr=subprocess.DEVNULL); lines=[l for l in out.splitlines() if l and not l.startswith("Timestamp")][-${safeLimit}:]; items=[]\nfor idx,l in enumerate(lines):\n  parts=l.split(None,4)\n  if len(parts)<5: continue\n  ts=parts[0]+"T"+parts[1]; ty=parts[2]; proc=parts[3]; msg=parts[4]\n  lvl="Critical" if ty=="F" else "Error" if ty=="E" else "Warning" if ty in ("W","A") else "Information"\n  items.append({"id":idx+1,"timeGenerated":ts,"source":proc.split("[")[0],"eventId":0,"level":lvl,"channel":"unified-log","message":msg[:500]})\nprint(json.dumps(items))'; echo "__VJ_END__"`;
      const res = await this.executeCommandOnNode(deviceId, py, { runAs: 'system', timeoutMs: 15000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const items = JSON.parse(extractDelimitedJson(res.output)) as EventLogItem[];
          if (Array.isArray(items)) {
            return level && level !== 'all'
              ? items.filter((i) => i.level.toLowerCase() === level.toLowerCase())
              : items;
          }
        } catch (err: any) {
          this.lastToolError = `Failed to parse macOS unified logs: ${err?.message || 'invalid JSON'}`;
        }
      } else if (!res.live || res.exitCode !== 0) {
        this.lastToolError = res.output || 'Endpoint did not respond to live unified log query.';
      }
    }

    return [];
  }

  // ============================================================================
  // Live MeshCentral 2 Server Discovery & Federation Sync (Groups + Devices!)
  // ============================================================================
  public async discoverServerResources(params: {
    url: string;
    apiToken?: string;
    localConfigPath?: string;
    allowSelfSigned?: boolean;
  }): Promise<MeshDiscoveryReport> {
    const startMs = Date.now();
    const urlCheck = validateMeshServerUrl(params.url || '');
    if (!urlCheck.ok || !urlCheck.normalized) {
      return {
        reachable: false,
        authenticated: false,
        source: 'unreachable',
        serverUrl: params.url || '',
        latencyMs: Date.now() - startMs,
        error: urlCheck.error || 'Invalid MeshCentral server URL.',
        groups: [],
        agents: []
      };
    }

    const normalizedUrl = urlCheck.normalized;
    const dnsSafety = await validateOutboundHostSafety(normalizedUrl, { allowLoopback: true, allowPrivateLan: true });
    if (!dnsSafety.safe) {
      return {
        reachable: false,
        authenticated: false,
        source: 'unreachable',
        serverUrl: normalizedUrl,
        latencyMs: Date.now() - startMs,
        error: dnsSafety.reason || 'MeshCentral URL blocked by SSRF policy.',
        groups: [],
        agents: []
      };
    }

    const cleanToken = params.apiToken ? decryptVaultSecret(params.apiToken) || params.apiToken : '';
    let wsAuthError = '';

    // 1. Live WebSocket control.ashx probe
    if (cleanToken) {
      try {
        const wsReport = await new Promise<{
          ok: boolean;
          meshes: MeshGroup[];
          nodes: DiscoveredMeshAgent[];
          error?: string;
        }>((resolve) => {
          const { wsUrl, headers } = buildMeshWsAuthParams(normalizedUrl, cleanToken, urlCheck.loginKey);
          const allowInsecure =
            Boolean(params.allowSelfSigned) ||
            process.env.MESHCENTRAL_ALLOW_SELF_SIGNED === 'true' ||
            isLoopbackExactHostname(normalizedUrl);

          let settled = false;
          const meshes: MeshGroup[] = [];
          const nodes: DiscoveredMeshAgent[] = [];
          const meshNameById = new Map<string, string>();
          const sysInfoByNode = new Map<string, any>();
          const netInfoByNode = new Map<string, any>();
          let gotMeshes = false;
          let gotNodes = false;
          let enrichmentStarted = false;
          let expectedSysReplies = 0;
          let gotSysReplies = 0;
          let expectedNetReplies = 0;
          let gotNetReplies = 0;
          let timer: ReturnType<typeof setTimeout> | null = null;
          let openTimer: ReturnType<typeof setTimeout> | null = null;
          let enrichTimer: ReturnType<typeof setTimeout> | null = null;

          const ws = new WebSocket(wsUrl, {
            headers,
            rejectUnauthorized: !allowInsecure,
            handshakeTimeout: 4000
          });

          const mergeAndFinish = (ok: boolean, error?: string) => {
            if (settled) return;
            settled = true;
            if (timer) clearTimeout(timer);
            if (openTimer) clearTimeout(openTimer);
            if (enrichTimer) clearTimeout(enrichTimer);
            for (const ag of nodes) {
              const extra = extractSysInfoAndNetInfo(sysInfoByNode.get(ag.nodeId), netInfoByNode.get(ag.nodeId));
              Object.assign(ag, extra);
            }
            try {
              ws.removeAllListeners();
              ws.close();
            } catch {}
            resolve({ ok, meshes, nodes, error });
          };

          timer = setTimeout(() => {
            mergeAndFinish(ws.readyState === WebSocket.OPEN);
          }, 6000);

          ws.on('open', () => {
            try {
              ws.send(JSON.stringify({ action: 'meshes' }));
              ws.send(JSON.stringify({ action: 'nodes' }));
            } catch {}
            openTimer = setTimeout(() => {
              mergeAndFinish(true);
            }, 3000);
          });

          ws.on('message', (raw) => {
            try {
              const msg = JSON.parse(raw.toString());
              if (msg.action === 'close') {
                const authErr =
                  msg.msg === 'tokenrequired'
                    ? 'MeshCentral requires 2FA/TOTP for this account. Create a persistent MeshCentral Login Token (~t:TokenUser:TokenPass) via My Account → Login Tokens or meshctrl.js LoginTokens --add "Vitrine RMM" --token <6-digit-TOTP>.'
                    : msg.cause === 'notools'
                      ? 'This MeshCentral account has "notools" enabled and cannot access the control WebSocket API.'
                      : `MeshCentral rejected authentication (${msg.msg || msg.cause || 'noauth'}).`;
                mergeAndFinish(false, authErr);
                return;
              }
              if (msg.action === 'meshes' && msg.meshes) {
                gotMeshes = true;
                const list = Array.isArray(msg.meshes) ? msg.meshes : Object.values(msg.meshes);
                for (const m of list as any[]) {
                  const id = String(m._id || m.meshid || '');
                  const name = String(m.name || id);
                  if (id) {
                    meshNameById.set(id, name);
                    meshes.push({ meshid: id, name, desc: m.desc || '', deviceCount: 0 });
                  }
                }
              } else if (msg.action === 'nodes' && msg.nodes && typeof msg.nodes === 'object') {
                gotNodes = true;
                for (const [meshKey, arr] of Object.entries(msg.nodes)) {
                  if (!Array.isArray(arr)) continue;
                  for (const n of arr as any[]) {
                    const osDesc = String(n.osdesc || n.ostype || 'Windows');
                    const osType = detectOsTypeFromMeshNode(n);
                    const base = extractBaseNodeFields(n);
                    nodes.push({
                      nodeId: String(n._id || ''),
                      hostname: String(n.name || n.rname || 'endpoint'),
                      meshId: meshKey,
                      meshName: meshNameById.get(meshKey) || meshKey,
                      osDesc,
                      osType,
                      ipAddress: String(n.ip || ''),
                      online: Boolean(n.conn && (Number(n.conn) & 1) !== 0),
                      ...base
                    });
                  }
                }
                for (const g of meshes) {
                  g.deviceCount = nodes.filter((n) => n.meshId === g.meshid).length;
                }
              } else if (msg.action === 'getsysinfo' && msg.nodeid) {
                gotSysReplies++;
                if (!msg.noinfo) sysInfoByNode.set(String(msg.nodeid), msg);
                if (gotSysReplies >= expectedSysReplies && gotNetReplies >= expectedNetReplies) {
                  mergeAndFinish(true);
                }
                return;
              } else if (msg.action === 'getnetworkinfo' && msg.nodeid) {
                gotNetReplies++;
                if (!msg.noinfo) netInfoByNode.set(String(msg.nodeid), msg);
                if (gotSysReplies >= expectedSysReplies && gotNetReplies >= expectedNetReplies) {
                  mergeAndFinish(true);
                }
                return;
              }

              if (gotMeshes && gotNodes && !enrichmentStarted) {
                enrichmentStarted = true;
                const toQuery = nodes.filter((n) => n.nodeId).slice(0, 50);
                if (toQuery.length === 0) {
                  mergeAndFinish(true);
                  return;
                }
                expectedSysReplies = toQuery.length;
                expectedNetReplies = toQuery.length;
                try {
                  for (const ag of toQuery) {
                    ws.send(JSON.stringify({ action: 'getsysinfo', nodeid: ag.nodeId, nodeinfo: true }));
                    ws.send(JSON.stringify({ action: 'getnetworkinfo', nodeid: ag.nodeId }));
                  }
                } catch {}
                enrichTimer = setTimeout(() => {
                  mergeAndFinish(true);
                }, 2500);
              }
            } catch {}
          });

          ws.on('error', (err) => {
            mergeAndFinish(false, err.message);
          });

          ws.on('close', (code) => {
            if (!settled) {
              mergeAndFinish(
                false,
                code >= 4000
                  ? `MeshCentral rejected auth credentials (code ${code})`
                  : 'MeshCentral closed the WebSocket connection before authentication succeeded.'
              );
            }
          });
        });

        if (wsReport.ok) {
          return {
            reachable: true,
            authenticated: true,
            source: 'live_ws_control',
            serverUrl: normalizedUrl,
            latencyMs: Date.now() - startMs,
            groups: wsReport.meshes,
            agents: wsReport.nodes
          };
        }
        if (wsReport.error) {
          wsAuthError = wsReport.error;
        }
      } catch {}
    }

    // 2. HTTP/HTTPS reachability check via safeOutboundFetch
    let httpReachable = false;
    let httpError = '';
    try {
      const allowInsecure =
        Boolean(params.allowSelfSigned) ||
        process.env.MESHCENTRAL_ALLOW_SELF_SIGNED === 'true' ||
        isLoopbackExactHostname(normalizedUrl);
      const rootRes = await safeOutboundFetch(normalizedUrl, {
        timeoutMs: 3500,
        allowInsecureTls: allowInsecure,
        safety: { allowLoopback: true, allowPrivateLan: true }
      });
      httpReachable = rootRes.status > 0 && rootRes.status < 500;
    } catch (err: any) {
      httpError = err?.message || 'Connection refused or timed out';
    }

    // 3. Optional Read-Only Same-Host NeDB Inspection (restricted to verified MeshCentral directories)
    if (params.localConfigPath) {
      try {
        const resolvedCfg = fs.realpathSync(params.localConfigPath);
        const allowedRoots = [
          '/opt/meshcentral',
          '/var/lib/meshcentral',
          path.resolve(process.cwd(), 'dev-meshcentral'),
          path.resolve(process.cwd(), '../dev-meshcentral')
        ];
        const isAllowedDir = allowedRoots.some((r) => {
          try {
            const rr = fs.existsSync(r) ? fs.realpathSync(r) : path.resolve(r);
            return resolvedCfg.startsWith(rr + path.sep);
          } catch {
            return false;
          }
        });
        if (isAllowedDir) {
          const dataDir = resolvedCfg.endsWith('.json') ? path.dirname(resolvedCfg) : resolvedCfg;
          const nedbPath = path.join(dataDir, 'meshcentral.db');
          if (fs.existsSync(nedbPath)) {
            const stat = fs.statSync(nedbPath);
            if (stat.isFile() && stat.size <= 50 * 1024 * 1024) {
              const lines = fs.readFileSync(nedbPath, 'utf8').split(/\r?\n/);
              const groups: MeshGroup[] = [];
              const agents: DiscoveredMeshAgent[] = [];
              const meshMap = new Map<string, MeshGroup>();

              for (const line of lines) {
                if (!line.trim()) continue;
                try {
                  const rec = JSON.parse(line);
                  if (rec.type === 'mesh' && rec._id && !rec.$$deleted) {
                    const g: MeshGroup = {
                      meshid: String(rec._id),
                      name: String(rec.name || rec._id),
                      desc: String(rec.desc || ''),
                      deviceCount: 0
                    };
                    meshMap.set(g.meshid, g);
                    groups.push(g);
                  } else if (rec.type === 'node' && rec._id && !rec.$$deleted) {
                    const osDesc = String(rec.osdesc || 'Windows');
                    const lower = osDesc.toLowerCase();
                    const osType: 'windows' | 'linux' | 'macos' =
                      lower.includes('darwin') || lower.includes('mac')
                        ? 'macos'
                        : lower.includes('linux')
                          ? 'linux'
                          : 'windows';
                    agents.push({
                      nodeId: String(rec._id),
                      hostname: String(rec.name || rec.rname || 'endpoint'),
                      meshId: String(rec.meshid || ''),
                      meshName: meshMap.get(String(rec.meshid || ''))?.name || 'Mesh Group',
                      osDesc,
                      osType,
                      ipAddress: String(rec.ip || ''),
                      online: false
                    });
                  }
                } catch {}
              }

              for (const g of groups) {
                g.deviceCount = agents.filter((a) => a.meshId === g.meshid).length;
              }

              return {
                reachable: httpReachable || true,
                authenticated: Boolean(cleanToken),
                source: 'local_nedb_readonly',
                serverUrl: normalizedUrl,
                latencyMs: Date.now() - startMs,
                groups,
                agents
              };
            }
          }
        }
      } catch {}
    }

    return {
      reachable: httpReachable,
      authenticated: false,
      source: httpReachable ? 'http_rest_api' : 'unreachable',
      serverUrl: normalizedUrl,
      latencyMs: Date.now() - startMs,
      error: httpReachable
        ? cleanToken
          ? wsAuthError ||
            'MeshCentral HTTP server responded, but WebSocket API authentication failed. Provide a MeshCentral Login Token (~t:TokenUser:TokenPass) or username:password (for accounts without 2FA).'
          : 'MeshCentral HTTP server is reachable. Provide API credentials to enumerate groups and agents.'
        : `Could not reach MeshCentral server at ${normalizedUrl}: ${httpError || 'Connection failed'}`,
      groups: [],
      agents: []
    };
  }

  public async fetchMeshGroups(): Promise<MeshGroup[]> {
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    const token = decryptVaultSecret(settings.meshcentral_api_token);
    if (settings.meshcentral_url && token) {
      const report = await this.discoverServerResources({
        url: settings.meshcentral_url,
        apiToken: token,
        allowSelfSigned: Boolean(settings.meshcentral_allow_self_signed)
      });
      if (report.reachable && report.groups.length > 0) {
        return report.groups;
      }
    }

    const tenants = db
      .prepare("SELECT id, name, slug, device_count, mesh_group_id FROM tenants WHERE COALESCE(lifecycle_state, 'active') = 'active'")
      .all() as any[];
    return tenants.map((t) => ({
      meshid: t.mesh_group_id || `mesh-${t.slug}`,
      name: t.name,
      desc: `Synced Vitrine client group for ${t.name}`,
      deviceCount: t.device_count || 0
    }));
  }

  public async syncDeviceGroupsWithClients(): Promise<SyncResult> {
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    const serverConfigs: Array<{ url: string; token: string; localPath?: string; allowSelfSigned?: boolean }> = [];

    const primaryToken = decryptVaultSecret(settings.meshcentral_api_token);
    if (settings.meshcentral_url && primaryToken) {
      serverConfigs.push({
        url: settings.meshcentral_url,
        token: primaryToken,
        allowSelfSigned: Boolean(settings.meshcentral_allow_self_signed)
      });
    }

    const dbServers = db
      .prepare('SELECT url, api_token, local_config_path, allow_self_signed FROM mesh_servers')
      .all() as any[];
    for (const s of dbServers) {
      const tok = decryptVaultSecret(s.api_token);
      if (s.url && tok && !serverConfigs.some((c) => c.url === s.url)) {
        serverConfigs.push({
          url: s.url,
          token: tok,
          localPath: s.local_config_path || undefined,
          allowSelfSigned: s.allow_self_signed != null ? Boolean(s.allow_self_signed) : Boolean(settings.meshcentral_allow_self_signed)
        });
      }
    }

    const discoveredGroups: MeshGroup[] = [];
    const discoveredAgents: DiscoveredMeshAgent[] = [];
    let liveAuthenticatedReportReceived = false;

    for (const cfg of serverConfigs) {
      const rep = await this.discoverServerResources({
        url: cfg.url,
        apiToken: cfg.token,
        localConfigPath: cfg.localPath,
        allowSelfSigned: cfg.allowSelfSigned
      });
      if (rep.reachable && rep.authenticated) {
        liveAuthenticatedReportReceived = true;
      }
      for (const g of rep.groups) {
        if (!discoveredGroups.some((x) => x.meshid === g.meshid)) discoveredGroups.push(g);
      }
      for (const a of rep.agents) {
        if (!discoveredAgents.some((x) => x.nodeId === a.nodeId)) discoveredAgents.push(a);
      }
    }

    const meshGroups = discoveredGroups.length > 0 ? discoveredGroups : await this.fetchMeshGroups();

    let importedGroups = 0;
    let updatedGroups = 0;
    let importedDevices = 0;
    let updatedDevices = 0;
    const conflicts: Array<{ meshGroupId: string; meshGroupName: string; tenantId: string; deviceCount: number }> = [];

    const existingTenants = db.prepare('SELECT id, name, slug, mesh_group_id FROM tenants').all() as any[];
    const tenantByMeshId = new Map(existingTenants.filter((t) => t.mesh_group_id).map((t) => [t.mesh_group_id, t]));
    const tenantByName = new Map(existingTenants.map((t) => [t.name.toLowerCase(), t]));

    for (const mg of meshGroups) {
      // Skip tombstoned deleted tenants
      const tombTenant = db
        .prepare('SELECT tenant_id FROM deleted_tenants_tombstones WHERE mesh_group_id = ?')
        .get(mg.meshid);
      if (tombTenant) continue;

      const match = tenantByMeshId.get(mg.meshid) || tenantByName.get(mg.name.toLowerCase());
      if (!match) {
        const baseSlug =
          mg.name
            .toLowerCase()
            .replace(/[^a-z0-9]/g, '-')
            .replace(/-+/g, '-')
            .replace(/^-|-$/g, '') || 'client';
        const slug = `${baseSlug}-${crypto.randomBytes(2).toString('hex')}`;
        const id = `t-${slug}`;
        db.prepare(`
          INSERT INTO tenants (id, name, slug, contact_email, device_count, mesh_group_id)
          VALUES (?, ?, ?, ?, ?, ?)
        `).run(id, mg.name, slug, `admin@${baseSlug}.local`, mg.deviceCount || 0, mg.meshid);
        tenantByMeshId.set(mg.meshid, { id, name: mg.name, slug, mesh_group_id: mg.meshid });
        importedGroups++;
      } else if (!match.mesh_group_id) {
        db.prepare('UPDATE tenants SET mesh_group_id = ? WHERE id = ?').run(mg.meshid, match.id);
        match.mesh_group_id = mg.meshid;
        tenantByMeshId.set(mg.meshid, match);
        updatedGroups++;
      }
    }

    // Sync discovered MeshCentral nodes directly into `devices` inventory!
    const nowIso = new Date().toISOString();
    for (const ag of discoveredAgents) {
      if (!ag.nodeId) continue;
      const tombDev = db
        .prepare('SELECT device_id FROM deleted_tenant_device_tombstones WHERE mesh_node_id = ?')
        .get(ag.nodeId);
      if (tombDev) continue;

      const ownerTenant = tenantByMeshId.get(ag.meshId);
      const targetTenantId = ownerTenant?.id || existingTenants[0]?.id || 't-default';

      const existingDev = db
        .prepare(
          'SELECT id, quarantined, device_role, device_role_manual, os_version, manufacturer, model, bios_version, hardware_details_json FROM devices WHERE mesh_node_id = ? OR (tenant_id = ? AND LOWER(hostname) = LOWER(?))'
        )
        .get(ag.nodeId, targetTenantId, ag.hostname) as any;

      const nextStatus = ag.online ? 'online' : 'offline';
      const nextHardwareDetailsJson = ag.hardwareDetails
        ? mergeHardwareDetailsJson(existingDev?.hardware_details_json, ag.hardwareDetails)
        : existingDev?.hardware_details_json || '{}';
      const syncRoleSignals = extractSignalsFromHardwareDetails(nextHardwareDetailsJson, {
        os_type: ag.osType,
        os_version: ag.osDesc || existingDev?.os_version || null,
        manufacturer: ag.manufacturer || existingDev?.manufacturer || null,
        model: ag.model || existingDev?.model || null,
        bios_version: ag.biosVersion || existingDev?.bios_version || null
      });
      const inferredSyncRole = inferDeviceRole(syncRoleSignals);

      if (!existingDev) {
        const devId = `dev-${crypto.randomUUID().slice(0, 8)}`;
        const initialSyncRole = inferredSyncRole || 'Workstation';
        db.prepare(`
          INSERT INTO devices (
            id, tenant_id, mesh_node_id, hostname, os_type, os_version, os_build,
            ip_address, mac_address, status, device_role, manufacturer, model, cpu_model, cpu_cores,
            ram_total_gb, ram_used_gb, disk_total_gb, disk_free_gb, serial_number, bios_version, tpm_version,
            amt_supported, intel_amt_enabled, amt_provisioned, amt_version,
            edr_name, edr_status, pending_reboot, logged_in_user,
            hardware_details_json,
            agent_privilege_mode, companion_installed, last_seen, enrolled_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
        `).run(
          devId,
          targetTenantId,
          ag.nodeId,
          ag.hostname,
          ag.osType,
          ag.osDesc,
          ag.osBuild || '',
          ag.ipAddress || '0.0.0.0',
          ag.macAddress || '00:00:00:00:00:00',
          nextStatus,
          initialSyncRole,
          ag.manufacturer || '',
          ag.model || '',
          ag.cpuModel || 'Unknown CPU',
          ag.cpuCores || 0,
          ag.ramTotalGb || 0,
          ag.ramUsedGb || 0,
          ag.diskTotalGb || 0,
          ag.diskFreeGb || 0,
          ag.serialNumber || '',
          ag.biosVersion || '',
          ag.tpmVersion || '',
          ag.amtSupported ? 1 : 0,
          ag.intelAmtEnabled ? 1 : 0,
          ag.amtProvisioned ? 1 : 0,
          ag.amtVersion || '',
          ag.edrName || 'Unmonitored',
          ag.edrStatus || 'Unknown',
          ag.pendingReboot ? 1 : 0,
          ag.loggedInUser || '',
          nextHardwareDetailsJson,
          ag.agentPrivilegeMode || 'system_service',
          nowIso,
          nowIso
        );
        importedDevices++;
      } else {
        const nextSyncRole = shouldAutoUpdateDeviceRole(existingDev.device_role, existingDev.device_role_manual, inferredSyncRole)
          ? (inferredSyncRole as string)
          : existingDev.device_role;
        db.prepare(`
          UPDATE devices
          SET mesh_node_id = ?,
              os_type = COALESCE(?, os_type),
              os_version = CASE WHEN ? != '' THEN ? ELSE os_version END,
              os_build = CASE WHEN ? != '' THEN ? ELSE os_build END,
              ip_address = CASE WHEN ? != '' THEN ? ELSE ip_address END,
              mac_address = CASE WHEN ? != '' THEN ? ELSE mac_address END,
              serial_number = CASE WHEN ? != '' THEN ? ELSE serial_number END,
              manufacturer = CASE WHEN ? != '' THEN ? ELSE manufacturer END,
              model = CASE WHEN ? != '' THEN ? ELSE model END,
              cpu_model = CASE WHEN ? != '' THEN ? ELSE cpu_model END,
              bios_version = CASE WHEN ? != '' THEN ? ELSE bios_version END,
              device_role = ?,
              ram_total_gb = CASE WHEN ? > 0 THEN ? ELSE ram_total_gb END,
              ram_used_gb = CASE WHEN ? > 0 THEN ? ELSE ram_used_gb END,
              disk_total_gb = CASE WHEN ? > 0 THEN ? ELSE disk_total_gb END,
              hardware_details_json = ?,
              amt_supported = CASE WHEN ? = 1 THEN 1 ELSE amt_supported END,
              intel_amt_enabled = CASE WHEN ? = 1 THEN 1 ELSE intel_amt_enabled END,
              amt_provisioned = CASE WHEN ? = 1 THEN 1 ELSE amt_provisioned END,
              amt_version = CASE WHEN ? != '' THEN ? ELSE amt_version END,
              status = CASE WHEN quarantined = 1 THEN 'isolated' ELSE ? END,
              last_seen = CASE WHEN ? = 'online' THEN ? ELSE last_seen END
          WHERE id = ?
        `).run(
          ag.nodeId,
          ag.osType,
          ag.osDesc || '',
          ag.osDesc || '',
          ag.osBuild || '',
          ag.osBuild || '',
          ag.ipAddress || '',
          ag.ipAddress || '',
          ag.macAddress || '',
          ag.macAddress || '',
          ag.serialNumber || '',
          ag.serialNumber || '',
          ag.manufacturer || '',
          ag.manufacturer || '',
          ag.model || '',
          ag.model || '',
          ag.cpuModel || '',
          ag.cpuModel || '',
          ag.biosVersion || '',
          ag.biosVersion || '',
          nextSyncRole,
          ag.ramTotalGb || 0,
          ag.ramTotalGb || 0,
          ag.ramUsedGb || 0,
          ag.ramUsedGb || 0,
          ag.diskTotalGb || 0,
          ag.diskTotalGb || 0,
          nextHardwareDetailsJson,
          ag.amtSupported ? 1 : 0,
          ag.intelAmtEnabled ? 1 : 0,
          ag.amtProvisioned ? 1 : 0,
          ag.amtVersion || '',
          ag.amtVersion || '',
          nextStatus,
          nextStatus,
          nowIso,
          existingDev.id
        );
        updatedDevices++;
      }
    }

    // Recalculate accurate tenant device_count
    db.exec(`
      UPDATE tenants
      SET device_count = (
        SELECT COUNT(*) FROM devices d
        WHERE d.tenant_id = tenants.id AND COALESCE(d.lifecycle_state, 'active') = 'active'
      )
    `);

    if (liveAuthenticatedReportReceived && discoveredGroups.length > 0) {
      const activeMeshIds = new Set(discoveredGroups.map((m) => m.meshid));
      for (const t of existingTenants) {
        if (t.mesh_group_id && !activeMeshIds.has(t.mesh_group_id)) {
          const deviceCount =
            (db.prepare('SELECT COUNT(*) as c FROM devices WHERE tenant_id = ?').get(t.id) as any)?.c || 0;
          if (deviceCount > 0) {
            conflicts.push({
              meshGroupId: t.mesh_group_id,
              meshGroupName: t.name,
              tenantId: t.id,
              deviceCount
            });
            const existingNotif = db
              .prepare("SELECT id FROM notifications WHERE type = 'mesh_conflict_prompt' AND title LIKE ?")
              .get(`%${t.name}%`);
            if (!existingNotif) {
              db.prepare(`
                INSERT INTO notifications (id, type, title, message, severity, actions_json, is_read)
                VALUES (?, 'mesh_conflict_prompt', ?, ?, 'warning', ?, 0)
              `).run(
                `notif-mesh-del-${crypto.randomUUID()}`,
                `MeshCentral Group Deletion Notice: "${t.name}"`,
                `The corresponding MeshCentral device group for Client "${t.name}" was deleted. ${deviceCount} endpoint(s) require handling.`,
                JSON.stringify([
                  { label: 'Move to Unassigned Group', action: 'move_to_unassigned', tenantId: t.id },
                  { label: 'De-provision & Uninstall Agents', action: 'uninstall', tenantId: t.id }
                ])
              );
            }
          }
        }
      }
    }

    return {
      success: true,
      imported: importedGroups + importedDevices,
      updated: updatedGroups + updatedDevices,
      importedDevices,
      updatedDevices,
      importedGroups,
      updatedGroups,
      unmappedMeshGroups: 0,
      conflicts,
      conflictsNotified: conflicts.length,
      message: `MeshCentral sync complete: ${importedGroups} group(s) & ${importedDevices} endpoint(s) imported, ${updatedGroups} group(s) & ${updatedDevices} endpoint(s) updated.`,
      timestamp: nowIso
    };
  }

  public async handleClientDeletion(
    tenantId: string,
    action: 'uninstall' | 'move_to_unassigned',
    actorUsername = 'admin'
  ): Promise<{ affectedDevices: number; action: string }> {
    const tenant = db.prepare('SELECT id, name, slug, mesh_group_id FROM tenants WHERE id = ?').get(tenantId) as any;
    const devices = db
      .prepare('SELECT id, mesh_node_id, hostname, os_type, agent_auth_token FROM devices WHERE tenant_id = ?')
      .all(tenantId) as any[];
    const affectedDevices = devices.length;

    if (action === 'uninstall') {
      if (tenant) {
        db.prepare(`
          INSERT OR REPLACE INTO deleted_tenants_tombstones (tenant_id, tenant_name, slug, mesh_group_id, laps_offboard_action)
          VALUES (?, ?, ?, ?, 'remove_account')
        `).run(tenant.id, tenant.name, tenant.slug || tenant.id, tenant.mesh_group_id || null);
      }

      for (const d of devices) {
        const vaultRow = db
          .prepare('SELECT account_name FROM laps_vault WHERE device_id = ?')
          .get(d.id) as { account_name?: string } | undefined;
        const lapsAccount = vaultRow?.account_name || 'LocalAdmin';
        const rawTok = d.agent_auth_token ? decryptVaultSecret(String(d.agent_auth_token)) : '';
        const tokenHash = rawTok ? crypto.createHash('sha256').update(rawTok).digest('hex') : null;

        try {
          db.prepare(`
            INSERT OR REPLACE INTO deleted_tenant_device_tombstones (
              device_id, mesh_node_id, hostname, tenant_id, tenant_name, laps_action, laps_account_name, os_type, agent_token_hash
            ) VALUES (?, ?, ?, ?, ?, 'remove_account', ?, ?, ?)
          `).run(
            d.id,
            d.mesh_node_id || null,
            d.hostname,
            tenantId,
            tenant?.name || 'Removed Client',
            lapsAccount,
            d.os_type || 'windows',
            tokenHash
          );
        } catch {
          db.prepare(`
            INSERT OR REPLACE INTO deleted_tenant_device_tombstones (
              device_id, mesh_node_id, hostname, tenant_id, tenant_name, laps_action, laps_account_name, os_type
            ) VALUES (?, ?, ?, ?, ?, 'remove_account', ?, ?)
          `).run(
            d.id,
            d.mesh_node_id || null,
            d.hostname,
            tenantId,
            tenant?.name || 'Removed Client',
            lapsAccount,
            d.os_type || 'windows'
          );
        }

        this.dispatchAgentOffboard(d.id, {
          lapsAccountName: lapsAccount,
          lapsAction: 'remove_account'
        });

        db.prepare(`
          INSERT INTO audit_logs (id, username, device_id, action, details)
          VALUES (?, ?, ?, 'Agent De-provisioned', 'Client removal triggered silent uninstallation of Vitrine and MeshCentral agent')
        `).run(`aud-uninst-${crypto.randomUUID()}`, actorUsername, d.id);
      }
      db.prepare('DELETE FROM devices WHERE tenant_id = ?').run(tenantId);
    } else {
      const unassignedTenant = db.prepare("SELECT id FROM tenants WHERE id = 't-unassigned'").get();
      if (!unassignedTenant) {
        db.prepare(`
          INSERT INTO tenants (id, name, slug, contact_email, device_count)
          VALUES ('t-unassigned', 'Unassigned Endpoints', 'unassigned-endpoints', 'admin@internal', 0)
        `).run();
      }
      db.prepare("UPDATE devices SET tenant_id = 't-unassigned', site_id = NULL WHERE tenant_id = ?").run(tenantId);
      const countRow = db
        .prepare("SELECT COUNT(*) as c FROM devices WHERE tenant_id = 't-unassigned'")
        .get() as { c: number };
      db.prepare("UPDATE tenants SET device_count = ? WHERE id = 't-unassigned'").run(countRow.c);
    }

    db.prepare('DELETE FROM sites WHERE tenant_id = ?').run(tenantId);
    db.prepare('DELETE FROM tenants WHERE id = ?').run(tenantId);

    return { affectedDevices, action };
  }
}

export interface LocalMeshCentralDetection {
  detected: boolean;
  deploymentMode: 'docker' | 'bare_metal_standalone' | 'bare_metal_coexistent';
  installDir: string | null;
  meshctrlPath: string | null;
  configPath: string | null;
  serviceName: string | null;
  detectedPort: number | null;
  detectedUrl: string | null;
  configWritable: boolean;
  configJsonValid: boolean;
  allowFraming: boolean | null;
  disableAgentUpdate: boolean | null;
}

const MESHCENTRAL_SERVICE_FILENAME = path.dirname(fileURLToPath(import.meta.url));
const VITRINE_REPO_ROOT = (() => {
  const rel = path.resolve(MESHCENTRAL_SERVICE_FILENAME, '../../../..');
  try {
    return fs.realpathSync(rel);
  } catch {
    return rel;
  }
})();

function isPathInsideVitrineRepo(candidatePath: string): boolean {
  try {
    const resolved = fs.existsSync(candidatePath) ? fs.realpathSync(candidatePath) : path.resolve(candidatePath);
    return resolved === VITRINE_REPO_ROOT || resolved.startsWith(VITRINE_REPO_ROOT + path.sep);
  } catch {
    return false;
  }
}

export function detectLocalMeshCentralInstallation(extraCandidateDirs?: string[]): LocalMeshCentralDetection {
  const emptyBase = (
    deploymentMode: 'docker' | 'bare_metal_standalone' | 'bare_metal_coexistent'
  ): LocalMeshCentralDetection => ({
    detected: false,
    deploymentMode,
    installDir: null,
    meshctrlPath: null,
    configPath: null,
    serviceName: null,
    detectedPort: null,
    detectedUrl: null,
    configWritable: false,
    configJsonValid: false,
    allowFraming: null,
    disableAgentUpdate: null
  });

  const hasExplicitOverrides = Boolean(extraCandidateDirs && extraCandidateDirs.length > 0);
  if (process.env.VITRINE_DOCKER === 'true' && !hasExplicitOverrides) {
    return emptyBase('docker');
  }

  const candidates: Array<{ dir: string; serviceName?: string; explicit: boolean }> = [];
  let detectedServiceName: string | null = null;

  if (extraCandidateDirs) {
    for (const d of extraCandidateDirs) {
      if (d && typeof d === 'string') {
        candidates.push({ dir: d, explicit: true });
      }
    }
  }

  // 1. Inspect local systemd service units referencing MeshCentral
  if (!hasExplicitOverrides) {
    for (const unitDir of ['/etc/systemd/system', '/lib/systemd/system', '/usr/lib/systemd/system']) {
      try {
        if (!fs.existsSync(unitDir)) continue;
        for (const entry of fs.readdirSync(unitDir)) {
          if (!/meshcentral.*\.service$/i.test(entry) || entry === 'vitrine-rmm.service') continue;
          if (!detectedServiceName) detectedServiceName = entry;
          const unitContent = fs.readFileSync(path.join(unitDir, entry), 'utf8');
          const wdMatch = unitContent.match(/^\s*WorkingDirectory=(.+)$/m);
          if (wdMatch?.[1]) {
            const rawWd = wdMatch[1].trim().replace(/^"(.*)"$/, '$1');
            if (rawWd) candidates.push({ dir: rawWd, serviceName: entry, explicit: false });
          }
          const execMatch = unitContent.match(/^\s*ExecStart=(.+)$/m);
          if (execMatch?.[1]) {
            const nmMatch = execMatch[1].match(/(\/[^\s"']+?)\/node_modules\/meshcentral\b/);
            if (nmMatch?.[1]) {
              candidates.push({ dir: nmMatch[1], serviceName: entry, explicit: false });
            }
          }
        }
      } catch {
        // Ignore inaccessible unit directories
      }
    }

    // 2. Inspect running MeshCentral processes via /proc on Linux
    try {
      if (fs.existsSync('/proc')) {
        for (const entry of fs.readdirSync('/proc')) {
          if (!/^\d+$/.test(entry)) continue;
          try {
            const cmdRaw = fs.readFileSync(`/proc/${entry}/cmdline`, 'utf8').replace(/\0/g, ' ').trim();
            if (!cmdRaw || !/meshcentral/i.test(cmdRaw) || /vitrine/i.test(cmdRaw)) continue;
            const nmMatch = cmdRaw.match(/(\/[^\s"']+?)\/node_modules\/meshcentral\b/);
            if (nmMatch?.[1]) {
              candidates.push({ dir: nmMatch[1], explicit: false });
            }
            const cwd = fs.readlinkSync(`/proc/${entry}/cwd`);
            if (cwd) {
              candidates.push({ dir: cwd, explicit: false });
            }
          } catch {
            // Process may belong to another user or exited
          }
        }
      }
    } catch {
      // Ignore /proc scan failures on non-Linux hosts
    }

    // 3. Scan standard filesystem locations & /home/* directories
    const fsPaths = [
      '/opt/meshcentral',
      '/var/lib/meshcentral',
      '/srv/meshcentral',
      '/usr/local/meshcentral',
      '/root/meshcentral',
      '/root'
    ];
    try {
      if (fs.existsSync('/home')) {
        for (const userEntry of fs.readdirSync('/home')) {
          const homeDir = path.join('/home', userEntry);
          fsPaths.push(homeDir, path.join(homeDir, 'meshcentral'));
        }
      }
    } catch {
      // Ignore inaccessible /home
    }
    for (const p of fsPaths) {
      candidates.push({ dir: p, explicit: false });
    }
  }

  const seenDirs = new Set<string>();
  for (const cand of candidates) {
    try {
      if (!fs.existsSync(cand.dir)) continue;
      let resolvedDir = fs.realpathSync(cand.dir);
      if (
        path.basename(resolvedDir) === 'meshcentral-data' &&
        fs.existsSync(path.join(resolvedDir, 'config.json'))
      ) {
        resolvedDir = path.dirname(resolvedDir);
      }
      if (seenDirs.has(resolvedDir)) continue;
      seenDirs.add(resolvedDir);

      if (!cand.explicit && isPathInsideVitrineRepo(resolvedDir)) {
        continue;
      }

      const meshctrlCandidate = path.join(resolvedDir, 'node_modules', 'meshcentral', 'meshctrl.js');
      const configCandidate = path.join(resolvedDir, 'meshcentral-data', 'config.json');
      const hasMeshctrl = fs.existsSync(meshctrlCandidate);
      const hasConfig = fs.existsSync(configCandidate);
      if (!hasMeshctrl && !hasConfig) continue;

      let configPath: string | null = null;
      let configWritable = false;
      let configJsonValid = false;
      let detectedPort: number | null = null;
      let detectedUrl: string | null = null;
      let allowFraming: boolean | null = null;
      let disableAgentUpdate: boolean | null = null;

      if (hasConfig) {
        try {
          const st = fs.lstatSync(configCandidate);
          if (!st.isSymbolicLink() && st.isFile() && st.size <= 2 * 1024 * 1024) {
            configPath = configCandidate;
            try {
              fs.accessSync(configCandidate, fs.constants.R_OK | fs.constants.W_OK);
              configWritable = true;
            } catch {
              configWritable = false;
            }
            try {
              const cfg = JSON.parse(fs.readFileSync(configCandidate, 'utf8'));
              configJsonValid = Boolean(cfg && typeof cfg === 'object');
              const portVal = Number(cfg?.settings?.port || cfg?.settings?.Port || 443);
              detectedPort = Number.isFinite(portVal) && portVal > 0 ? portVal : 443;
              if (cfg?.settings?.allowFraming !== undefined) {
                allowFraming = Boolean(cfg.settings.allowFraming);
              }
              if (cfg?.settings?.disableAgentUpdate !== undefined) {
                disableAgentUpdate = Boolean(cfg.settings.disableAgentUpdate);
              }
              const domainObj =
                cfg?.domains?.[''] ||
                (cfg?.domains && typeof cfg.domains === 'object' ? Object.values(cfg.domains)[0] : null);
              const loginKey = (domainObj as any)?.loginKey || (domainObj as any)?.loginkey || '';
              detectedUrl = `https://127.0.0.1:${detectedPort}${loginKey ? `?key=${encodeURIComponent(String(loginKey))}` : ''}`;
            } catch {
              configJsonValid = false;
            }
          }
        } catch {
          // Ignore unreadable config.json
        }
      }

      return {
        detected: true,
        deploymentMode: 'bare_metal_coexistent',
        installDir: resolvedDir,
        meshctrlPath: hasMeshctrl ? meshctrlCandidate : null,
        configPath,
        serviceName: cand.serviceName || detectedServiceName,
        detectedPort,
        detectedUrl,
        configWritable,
        configJsonValid,
        allowFraming,
        disableAgentUpdate
      };
    } catch {
      // Ignore candidate error
    }
  }

  return emptyBase('bare_metal_standalone');
}

export async function generateMeshLoginToken(params: {
  url: string;
  username: string;
  password: string;
  totp?: string;
  tokenName?: string;
  allowSelfSigned?: boolean;
}): Promise<{
  success: boolean;
  tokenName?: string;
  tokenUser?: string;
  tokenPass?: string;
  combinedToken?: string;
  totpRequired?: boolean;
  error?: string;
}> {
  const urlCheck = validateMeshServerUrl(params.url);
  if (!urlCheck.ok || !urlCheck.normalized) {
    return { success: false, error: urlCheck.error || 'Invalid MeshCentral server URL.' };
  }

  const normalizedUrl = urlCheck.normalized;
  const dnsSafety = await validateOutboundHostSafety(normalizedUrl, {
    allowLoopback: true,
    allowPrivateLan: true
  });
  if (!dnsSafety.safe) {
    return { success: false, error: dnsSafety.reason || 'MeshCentral URL blocked by outbound safety policy.' };
  }

  const username = String(params.username || '').trim();
  const password = String(params.password || '');
  if (!username || !password) {
    return { success: false, error: 'MeshCentral username and password are required.' };
  }

  const authParts = [
    Buffer.from(username, 'utf8').toString('base64'),
    Buffer.from(password, 'utf8').toString('base64')
  ];
  const totp = String(params.totp || '').trim();
  if (totp) {
    authParts.push(Buffer.from(totp, 'utf8').toString('base64'));
  }

  const baseWs = normalizedUrl.replace(/^http/i, 'ws');
  const wsUrl = `${baseWs}/control.ashx${urlCheck.loginKey ? `?key=${encodeURIComponent(urlCheck.loginKey)}` : ''}`;
  const allowInsecure =
    Boolean(params.allowSelfSigned) ||
    process.env.MESHCENTRAL_ALLOW_SELF_SIGNED === 'true' ||
    isLoopbackExactHostname(normalizedUrl);
  const desiredTokenName = String(params.tokenName || 'Vitrine RMM').trim().slice(0, 64) || 'Vitrine RMM';

  return await new Promise((resolve) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const ws = new WebSocket(wsUrl, {
      headers: { 'x-meshauth': authParts.join(',') },
      rejectUnauthorized: !allowInsecure,
      handshakeTimeout: 5000
    });

    const finish = (res: {
      success: boolean;
      tokenName?: string;
      tokenUser?: string;
      tokenPass?: string;
      combinedToken?: string;
      totpRequired?: boolean;
      error?: string;
    }) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try {
        ws.removeAllListeners();
        ws.close();
      } catch {}
      resolve(res);
    };

    timer = setTimeout(() => {
      finish({ success: false, error: 'Timed out waiting for MeshCentral Login Token response.' });
    }, 8000);

    ws.on('open', () => {
      try {
        ws.send(
          JSON.stringify({
            action: 'createLoginToken',
            name: desiredTokenName,
            expire: 0,
            responseid: 'vitrine-tok'
          })
        );
      } catch (err: any) {
        finish({ success: false, error: err?.message || 'Failed to send createLoginToken command.' });
      }
    });

    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw.toString());
        if (!msg || typeof msg !== 'object') return;

        if (msg.action === 'close') {
          if (msg.msg === 'tokenrequired') {
            finish({
              success: false,
              totpRequired: true,
              error: '2FA / TOTP verification required. Enter your current 6-digit authenticator code and try again.'
            });
            return;
          }
          if (msg.cause === 'notools') {
            finish({
              success: false,
              error: 'This MeshCentral account has "notools" restricted and cannot generate Login Tokens.'
            });
            return;
          }
          finish({
            success: false,
            error: `MeshCentral rejected login (${msg.msg || msg.cause || 'invalid credentials'}).`
          });
          return;
        }

        if (msg.action === 'createLoginToken') {
          if (msg.result) {
            finish({
              success: false,
              error: `MeshCentral declined Login Token creation: ${String(msg.result)}`
            });
            return;
          }
          if (msg.tokenUser && msg.tokenPass) {
            const tokenUser = String(msg.tokenUser);
            const tokenPass = String(msg.tokenPass);
            finish({
              success: true,
              tokenName: String(msg.name || desiredTokenName),
              tokenUser,
              tokenPass,
              combinedToken: `${tokenUser}:${tokenPass}`
            });
          }
        }
      } catch {
        // Ignore non-JSON frames
      }
    });

    ws.on('error', (err) => {
      finish({ success: false, error: err?.message || 'Failed to connect to MeshCentral server.' });
    });

    ws.on('close', (code) => {
      if (!settled) {
        finish({
          success: false,
          error:
            code >= 4000
              ? `MeshCentral closed connection with auth error code ${code}.`
              : 'MeshCentral closed the WebSocket connection before generating a Login Token.'
        });
      }
    });
  });
}

export function applyLocalMeshCentralConfig(options: {
  allowFraming?: boolean;
  disableAgentUpdate?: boolean;
  overrideConfigPathForTest?: string;
  overrideServiceNameForTest?: string;
}): {
  success: boolean;
  configPath?: string;
  backupPath?: string;
  applied?: { allowFraming: boolean; disableAgentUpdate: boolean };
  restartHint?: string;
  error?: string;
} {
  let configPath = options.overrideConfigPathForTest || '';
  let serviceName = options.overrideServiceNameForTest || null;

  if (!configPath) {
    const detected = detectLocalMeshCentralInstallation();
    if (!detected.detected || !detected.configPath) {
      return {
        success: false,
        error: 'No local MeshCentral config.json installation was detected on this host.'
      };
    }
    configPath = detected.configPath;
    serviceName = detected.serviceName;
  }

  try {
    if (!fs.existsSync(configPath)) {
      return { success: false, error: `MeshCentral config file not found at ${configPath}.` };
    }
    const stat = fs.lstatSync(configPath);
    if (stat.isSymbolicLink() || !stat.isFile()) {
      return { success: false, error: 'Refusing to modify config.json because it is a symbolic link or non-regular file.' };
    }

    const rawText = fs.readFileSync(configPath, 'utf8');
    let cfg: any;
    try {
      cfg = JSON.parse(rawText);
    } catch {
      return {
        success: false,
        error:
          'config.json contains comments or non-standard JSON syntax. Please add "allowFraming": true and/or "disableAgentUpdate": true under "settings" manually.'
      };
    }
    if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) {
      return { success: false, error: 'Unexpected config.json structure.' };
    }

    const mode = stat.mode & 0o777;
    const backupPath = `${configPath}.vitrine-bak-${Date.now()}`;
    fs.writeFileSync(backupPath, rawText, { encoding: 'utf8', mode });
    try {
      fs.chmodSync(backupPath, mode);
    } catch {}

    if (!cfg.settings || typeof cfg.settings !== 'object' || Array.isArray(cfg.settings)) {
      cfg.settings = {};
    }
    if (options.allowFraming === true) {
      cfg.settings.allowFraming = true;
    }
    if (options.disableAgentUpdate === true) {
      cfg.settings.disableAgentUpdate = true;
    }

    fs.writeFileSync(configPath, JSON.stringify(cfg, null, 2) + '\n', { encoding: 'utf8', mode });
    try {
      fs.chmodSync(configPath, mode);
    } catch {}

    return {
      success: true,
      configPath,
      backupPath,
      applied: {
        allowFraming: Boolean(cfg.settings.allowFraming),
        disableAgentUpdate: Boolean(cfg.settings.disableAgentUpdate)
      },
      restartHint: serviceName
        ? `sudo systemctl restart ${serviceName}`
        : 'Restart your MeshCentral 2 process for changes to take effect.'
    };
  } catch (err: any) {
    return {
      success: false,
      error: err?.message || 'Unable to update local MeshCentral config.json.'
    };
  }
}

export const meshBridge = new MeshCentralBridge();
