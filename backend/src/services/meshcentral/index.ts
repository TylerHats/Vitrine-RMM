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
import { quotePowerShellLiteral, quoteBashLiteral } from '../agent/installerGenerator.js';

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
    }
  >();
  private pendingControlWaiters = new Map<
    string,
    { resolve: (msg: any) => void; timer: ReturnType<typeof setTimeout> }
  >();

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

  public checkConfig() {
    this.closeExistingSocket();
    this.reconnectAttempts = 0;
    try {
      const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
      let serverUrl = (settings.meshcentral_url || '').trim();
      let apiToken = decryptVaultSecret(settings.meshcentral_api_token);

      const allServers = db
        .prepare('SELECT id, url, api_token, is_primary FROM mesh_servers ORDER BY is_primary DESC, created_at ASC')
        .all() as Array<{ id: string; url: string; api_token: string; is_primary: number }>;

      if ((!serverUrl || !apiToken) && allServers.length > 0) {
        const primary = allServers[0];
        if (primary?.url && primary?.api_token) {
          serverUrl = String(primary.url).trim();
          apiToken = decryptVaultSecret(primary.api_token);
        }
      }

      const isPlaceholderUrl =
        !serverUrl ||
        serverUrl === 'https://mesh.vitrine.local' ||
        serverUrl === 'https://mesh.yourdomain.com';

      if (!isPlaceholderUrl && apiToken) {
        this.isConfigured = true;
        this.initLiveConnection(serverUrl, apiToken, Boolean(settings.meshcentral_allow_self_signed));
      } else {
        this.isConfigured = false;
        this.isConnected = false;
        this.connectedServerUrl = serverUrl || null;
        this.lastConnectionError = null;
      }

      // Connect additional federated MeshCentral servers into the multi-server pool
      for (const srv of allServers) {
        const srvUrl = String(srv.url || '').trim();
        const srvToken = decryptVaultSecret(srv.api_token);
        if (!srvUrl || !srvToken || srvUrl === serverUrl) continue;
        this.initFederatedSocket(srv.id, srvUrl, srvToken, Boolean(settings.meshcentral_allow_self_signed));
      }
    } catch (e: any) {
      this.isConfigured = false;
      this.isConnected = false;
      this.lastConnectionError = e?.message || 'Database not initialized';
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
        }
        return;
      }

      // Track node -> server mapping and online status transitions live!
      if (msg.action === 'nodes' && msg.nodes && typeof msg.nodes === 'object') {
        for (const arr of Object.values(msg.nodes)) {
          if (!Array.isArray(arr)) continue;
          for (const n of arr as any[]) {
            if (n?._id) {
              this.nodeServerMap.set(String(n._id), serverId);
            }
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
          } catch {}
        }
      }

      // Resolve control RPC waiters (e.g., createDeviceShareLink, authcookie)
      const respId = msg.responseid || msg.tag;
      if (respId && this.pendingControlWaiters.has(String(respId))) {
        // Ignore the initial runcommands 'OK' ack if a command output waiter owns it
        const ctl = this.pendingControlWaiters.get(String(respId))!;
        clearTimeout(ctl.timer);
        this.pendingControlWaiters.delete(String(respId));
        ctl.resolve(msg);
      }

      // Resolve live command execution output (`reply: true` sends `action: 'msg', type: 'runcommands'` or `result`)
      if (respId && this.pendingCmdWaiters.has(String(respId))) {
        // MeshCentral sends `{ action: 'runcommands', result: 'OK', responseid }` first as dispatch ack,
        // followed by `{ action: 'msg', type: 'console'|'runcommands', value/result, responseid }` when output arrives.
        // If MeshCentral rejects the nodeid (e.g. `{ action: 'runcommands', result: 'Invalid nodeids' }` on a standalone Companion node),
        // resolve `null` so `executeCommandOnNode` falls through to Local Host / Companion Queue!
        if (msg.action === 'runcommands' && msg.value === undefined && msg.output === undefined) {
          if (msg.result === 'OK') {
            return;
          }
          const waiter = this.pendingCmdWaiters.get(String(respId))!;
          clearTimeout(waiter.timer);
          this.pendingCmdWaiters.delete(String(respId));
          waiter.resolve(null);
          return;
        }
        const rawOut = String(msg.result ?? msg.value ?? msg.output ?? '');
        const parsed = extractCommandSentinel(rawOut);
        const inferredExit =
          parsed.exitCode !== null
            ? parsed.exitCode
            : /CategoryInfo|FullyQualifiedErrorId|Exception/i.test(rawOut)
              ? 1
              : 0;
        const waiter = this.pendingCmdWaiters.get(String(respId))!;
        clearTimeout(waiter.timer);
        this.pendingCmdWaiters.delete(String(respId));
        waiter.resolve({ output: parsed.cleanOutput, exitCode: inferredExit });
        return;
      }

      // Match pending waiters by deterministic `<cmdId>` sentinel in output when `responseid` is absent,
      // falling back to `nodeid` only if no sentinel ID matched.
      if (
        (msg.action === 'msg' || msg.type === 'runcommands' || msg.type === 'console') &&
        (msg.result !== undefined || msg.value !== undefined || msg.output !== undefined)
      ) {
        const rawOut = String(msg.result ?? msg.value ?? msg.output ?? '');
        const parsed = extractCommandSentinel(rawOut);
        if (parsed.cmdId && this.pendingCmdWaiters.has(parsed.cmdId)) {
          const waiter = this.pendingCmdWaiters.get(parsed.cmdId)!;
          clearTimeout(waiter.timer);
          this.pendingCmdWaiters.delete(parsed.cmdId);
          waiter.resolve({ output: parsed.cleanOutput, exitCode: parsed.exitCode ?? 0 });
          return;
        }
        if (msg.nodeid) {
          for (const [k, waiter] of this.pendingCmdWaiters.entries()) {
            if (waiter.nodeId === String(msg.nodeid)) {
              clearTimeout(waiter.timer);
              this.pendingCmdWaiters.delete(k);
              const inferredExit =
                parsed.exitCode !== null
                  ? parsed.exitCode
                  : /CategoryInfo|FullyQualifiedErrorId|Exception/i.test(rawOut)
                    ? 1
                    : 0;
              waiter.resolve({ output: parsed.cleanOutput, exitCode: inferredExit });
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
          console.log(`[MeshCentralBridge] Connected to live MeshCentral server (${normalizedUrl})`);
        });

        ws.on('message', (raw) => this.handleIncomingMeshFrame(raw, 'primary'));

        ws.on('error', (err) => {
          if (this.meshWs !== ws) return;
          this.isConnected = false;
          this.lastConnectionError = err.message;
        });

        ws.on('close', () => {
          if (this.meshWs !== ws) return;
          this.isConnected = false;
          this.schedulePrimaryReconnect(serverUrl, apiToken, allowSelfSigned);
        });
      } catch (e: any) {
        this.isConnected = false;
        this.lastConnectionError = e?.message || 'Failed to initialize WebSocket';
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

  private getOpenSocketAndServerForNode(meshNodeId?: string): { sock: WebSocket | null; serverUrl: string | null } {
    if (meshNodeId) {
      const ownerId = this.nodeServerMap.get(meshNodeId);
      if (ownerId && ownerId !== 'primary') {
        const fed = this.federatedPool.get(ownerId);
        if (fed?.ws && fed.ws.readyState === WebSocket.OPEN) {
          return { sock: fed.ws, serverUrl: fed.serverUrl };
        }
      }
    }
    if (this.meshWs && this.meshWs.readyState === WebSocket.OPEN) {
      return { sock: this.meshWs, serverUrl: this.connectedServerUrl };
    }
    for (const [, fed] of this.federatedPool) {
      if (fed.ws && fed.ws.readyState === WebSocket.OPEN) {
        return { sock: fed.ws, serverUrl: fed.serverUrl };
      }
    }
    return { sock: null, serverUrl: this.connectedServerUrl };
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
        error: 'MeshCentral live control tunnel is not connected.'
      };
    }

    const responseId = `share-${crypto.randomUUID()}`;
    const pFlag = params.mode === 'terminal' ? 1 : params.mode === 'files' ? 4 : 2;
    const consentFlags = params.requireConsent ? 0x0008 | 0x0040 : 0x0040; // Desktop prompt + connection toolbar

    const msgPromise = new Promise<any>((resolve) => {
      const timer = setTimeout(() => {
        this.pendingControlWaiters.delete(responseId);
        resolve(null);
      }, 4500);
      this.pendingControlWaiters.set(responseId, { resolve, timer });
    });

    try {
      sock.send(
        JSON.stringify({
          action: 'createDeviceShareLink',
          nodeid: meshNodeId,
          p: pFlag,
          viewOnly: Boolean(params.viewOnly),
          guestName: String(params.guestName || 'Vitrine Technician').slice(0, 48),
          duration: Math.max(5, Math.min(480, Number(params.durationMinutes || 60))),
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
      return {
        live: true,
        url: String(reply.url),
        serverUrl: matchedServerUrl
      };
    }

    return {
      live: false,
      url: null,
      serverUrl: matchedServerUrl,
      error: reply?.result || 'MeshCentral did not return a device share URL (verify node exists on server).'
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
      version: '2.6.1',
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
    const timeoutMs = options?.timeoutMs || 8000;

    // Prepend safe environment variable assignments when provided (zero code interpolation!)
    let wrappedCommand = command;
    if (options?.env && Object.keys(options.env).length > 0) {
      if (osType === 'windows') {
        const envLines = Object.entries(options.env)
          .filter(([k]) => /^VITRINE_PARAM_[A-Z0-9_]{1,64}$/.test(k))
          .map(([k, v]) => `$env:${k} = ${quotePowerShellLiteral(String(v))}`);
        if (envLines.length > 0) {
          wrappedCommand = `${envLines.join('; ')}; ${command}`;
        }
      } else {
        const envLines = Object.entries(options.env)
          .filter(([k]) => /^VITRINE_PARAM_[A-Z0-9_]{1,64}$/.test(k))
          .map(([k, v]) => `export ${k}=${quoteBashLiteral(String(v))}`);
        if (envLines.length > 0) {
          wrappedCommand = `${envLines.join('; ')}; ${command}`;
        }
      }
    }

    // 1. Live MeshCentral 2 `/control.ashx` (`runcommands` with `reply: true` & `responseid`)
    // Standalone Vitrine Companion nodes (`node//dev-...`) are not registered on MeshCentral unless mapped in `nodeServerMap`.
    const isGenuineMeshNode = !meshNodeId.startsWith('node//dev-') || this.nodeServerMap.has(meshNodeId);
    const sock = isGenuineMeshNode ? this.getOpenSocketForNode(meshNodeId) : null;
    if (sock && sock.readyState === WebSocket.OPEN && dev.mesh_node_id && isGenuineMeshNode) {
      const responseId = `cmd-${crypto.randomUUID()}`;
      const cmdType = osType === 'windows' ? (shell === 'cmd' ? 0 : 2) : 0;
      const sep = wrappedCommand.includes('#') || wrappedCommand.includes('\n') ? '\n' : '; ';
      const sentinelCommand =
        osType === 'windows'
          ? cmdType === 0
            ? `${wrappedCommand} & call echo __VITRINE_RC:%ERRORLEVEL%:${responseId}`
            : `${wrappedCommand}${sep}Write-Output "__VITRINE_RC:$(if($?){0}else{1}):${responseId}"`
          : `${wrappedCommand}${sep}echo "__VITRINE_RC:$?:${responseId}"`;

      const replyPromise = new Promise<{ output: string; exitCode: number } | null>((resolve) => {
        const timer = setTimeout(() => {
          this.pendingCmdWaiters.delete(responseId);
          resolve(null);
        }, timeoutMs);
        this.pendingCmdWaiters.set(responseId, {
          resolve: (res) => resolve(res),
          timer,
          nodeId: meshNodeId
        });
      });

      try {
        sock.send(
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
        const liveRes = await replyPromise;
        if (liveRes !== null) {
          return { live: true, exitCode: liveRes.exitCode, output: liveRes.output };
        }
      } catch {
        this.pendingCmdWaiters.delete(responseId);
      }
    }

    // 2. Enrolled Local Host Companion Fast-Path (executes directly on local Linux host when strictly enabled & verified)
    if (os.platform() === 'linux' && osType === 'linux' && this.isLocalEnrolledHost(dev)) {
      const localRes = await this.execLocalBash(command, options?.env, timeoutMs);
      return {
        live: true,
        exitCode: localRes.exitCode,
        output: localRes.output
      };
    }

    // 3. Enrolled Remote Vitrine Companion Agent Queue (`agent_tasks`)
    if (dev.agent_auth_token) {
      const taskId = `task-cmd-${crypto.randomUUID()}`;
      db.prepare(`
        INSERT INTO agent_tasks (id, device_id, tenant_id, task_type, payload_json, status)
        VALUES (?, ?, ?, 'script', ?, 'queued')
      `).run(
        taskId,
        dev.id,
        dev.tenant_id || null,
        JSON.stringify({
          executionId: options?.executionId || undefined,
          language: shell,
          shell,
          code: command,
          env: options?.env || {},
          runAs,
          timeoutSec: Math.ceil(timeoutMs / 1000)
        })
      );

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
        `if ($Existing) { Set-LocalUser -Name $Acc -Password $Sec; Enable-LocalUser -Name $Acc }`,
        ...(opts.autoCreateAccount
          ? [
              `else { New-LocalUser -Name $Acc -Password $Sec -PasswordNeverExpires:$false -Description 'Managed by Vitrine RMM LAPS' | Out-Null; Add-LocalGroupMember -Group 'Administrators' -Member $Acc -ErrorAction SilentlyContinue }`
            ]
          : [`else { throw "Managed LAPS account $Acc does not exist on endpoint." }`]),
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
      const accBash = quoteBashLiteral(opts.accountName);
      const passBash = quoteBashLiteral(opts.password);
      const ensureAcc = opts.autoCreateAccount
        ? `(id -u ${accBash} >/dev/null 2>&1 || sysadminctl -addUser ${accBash} -fullName ${accBash} -password ${passBash} -admin)`
        : `id -u ${accBash} >/dev/null 2>&1`;
      let cleanupCmd = '';
      if (
        opts.previousAccountName &&
        opts.previousAccountName !== opts.accountName &&
        SAFE_ACCOUNT_NAME_REGEX.test(opts.previousAccountName)
      ) {
        const prevBash = quoteBashLiteral(opts.previousAccountName);
        if (opts.cleanupOldAccountAction === 'delete') {
          cleanupCmd = `; sysadminctl -deleteUser ${prevBash} 2>/dev/null || dscl . -delete /Users/${prevBash} 2>/dev/null || true`;
        } else if (opts.cleanupOldAccountAction === 'disable') {
          cleanupCmd = `; pwpolicy -u ${prevBash} -disableuser 2>/dev/null || dscl . -create /Users/${prevBash} UserShell /usr/bin/false 2>/dev/null || true`;
        }
      }
      script = `${ensureAcc} && dscl . -passwd /Users/${accBash} ${passBash}${cleanupCmd} && echo "LAPS_ROTATE_OK"`;
    } else {
      const accBash = quoteBashLiteral(opts.accountName);
      const passB64 = Buffer.from(`${opts.accountName}:${opts.password}\n`, 'utf8').toString('base64');
      script = `(id -u ${accBash} >/dev/null 2>&1 || (${opts.autoCreateAccount ? `useradd -m -s /bin/bash ${accBash} && (usermod -aG sudo ${accBash} 2>/dev/null || usermod -aG wheel ${accBash} 2>/dev/null || true)` : 'exit 2'})) && printf '%s' '${passB64}' | base64 -d | chpasswd && echo "LAPS_ROTATE_OK"`;
    }

    const res = await this.executeCommandOnNode(deviceId, script, { runAs: 'system', timeoutMs: 8000 });
    const verifiedLive = res.live && res.exitCode === 0 && res.output.includes('LAPS_ROTATE_OK');
    return {
      delivered: res.live && res.exitCode === 0,
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
      type: osType === 'windows' ? 2 : 0,
      cmds: targetCmd
    });
  }

  // ============================================================================
  // Live Silent Background Process Manager (Zero Hardcoded Fake Processes)
  // ============================================================================
  public async getProcesses(deviceId: string): Promise<ProcessItem[]> {
    const cached = this.processCache.get(deviceId);
    if (cached) return cached;

    const osType = this.getDeviceOs(deviceId);
    if (osType === 'windows') {
      const ps = `Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 40 Id, ProcessName, @{N='CpuSec';E={[math]::Round($_.CPU,1)}}, @{N='MemMb';E={[math]::Round($_.WorkingSet64/1MB,1)}}, @{N='Threads';E={$_.Threads.Count}} | ConvertTo-Json -Compress`;
      const res = await this.executeCommandOnNode(deviceId, ps, { runAs: 'system', timeoutMs: 7000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const parsed = JSON.parse(res.output);
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
        } catch {}
      }
    } else {
      const py = `python3 -c 'import subprocess,json; out=subprocess.check_output(["ps","-eo","pid,user,pcpu,rss,nlwp,comm","--no-headers"],text=True); rows=[]; [rows.append({"pid":int(p[0]),"user":p[1],"cpu":float(p[2]),"memoryMb":round(int(p[3])/1024.0,1),"threads":int(p[4]),"name":p[5]}) for line in out.splitlines() for p in [line.split(None,5)] if len(p)==6]; rows.sort(key=lambda x:x["memoryMb"],reverse=True); print(json.dumps(rows[:50]))'`;
      const res = await this.executeCommandOnNode(deviceId, py, { runAs: 'system', timeoutMs: 7000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const items = JSON.parse(res.output) as ProcessItem[];
          if (Array.isArray(items)) {
            this.processCache.set(deviceId, items);
            return items;
          }
        } catch {}
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

    const osType = this.getDeviceOs(deviceId);
    if (osType === 'windows') {
      const ps = `Get-Service | Select-Object -First 60 Name, DisplayName, @{N='StatusStr';E={$_.Status.ToString()}}, @{N='StartStr';E={$_.StartType.ToString()}} | ConvertTo-Json -Compress`;
      const res = await this.executeCommandOnNode(deviceId, ps, { runAs: 'system', timeoutMs: 7000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const parsed = JSON.parse(res.output);
          const arr = Array.isArray(parsed) ? parsed : [parsed];
          const items: ServiceItem[] = arr.map((s: any) => ({
            name: String(s.Name || ''),
            displayName: String(s.DisplayName || s.Name || ''),
            status: s.StatusStr === 'Running' ? 'Running' : s.StatusStr === 'Paused' ? 'Paused' : 'Stopped',
            startType: s.StartStr === 'Automatic' ? 'Automatic' : s.StartStr === 'Disabled' ? 'Disabled' : 'Manual'
          }));
          this.serviceCache.set(deviceId, items);
          return items;
        } catch {}
      }
    } else if (osType === 'linux') {
      const py = `python3 -c 'import subprocess,json; out=subprocess.check_output(["systemctl","list-units","--type=service","--all","--no-pager","--no-legend"],text=True); items=[]; [items.append({"name":p[0],"displayName":p[4] if len(p)>4 else p[0],"status":"Running" if p[2]=="active" and p[3]=="running" else "Stopped","startType":"Automatic"}) for l in out.splitlines() for p in [l.lstrip("● ").split(None,4)] if len(p)>=4 and p[0].endswith(".service")]; print(json.dumps(items[:60]))'`;
      const res = await this.executeCommandOnNode(deviceId, py, { runAs: 'system', timeoutMs: 7000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const items = JSON.parse(res.output) as ServiceItem[];
          if (Array.isArray(items)) {
            this.serviceCache.set(deviceId, items);
            return items;
          }
        } catch {}
      }
    } else {
      const py = `python3 -c 'import subprocess,json; out=subprocess.check_output(["launchctl","list"],text=True); items=[]; [items.append({"name":p[2],"displayName":p[2],"status":"Running" if p[0]!="-" else "Stopped","startType":"Automatic"}) for l in out.splitlines()[1:61] for p in [l.split(None,2)] if len(p)==3]; print(json.dumps(items))'`;
      const res = await this.executeCommandOnNode(deviceId, py, { runAs: 'system', timeoutMs: 7000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const items = JSON.parse(res.output) as ServiceItem[];
          if (Array.isArray(items)) {
            this.serviceCache.set(deviceId, items);
            return items;
          }
        } catch {}
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
    const osType = this.getDeviceOs(deviceId);
    const normalizedPath =
      regPath ||
      (osType === 'windows'
        ? 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
        : osType === 'macos'
          ? '/Library/Preferences/.GlobalPreferences.plist'
          : '/proc/sys/kernel');
    const cacheKey = `${deviceId}::${normalizedPath}`;
    const cached = this.registryCache.get(cacheKey);
    if (cached) return cached;

    if (osType === 'windows') {
      const litPath = normalizeWindowsRegistryLiteralPath(normalizedPath);
      const ps = `$p = ${quotePowerShellLiteral(litPath)}; $subs = @(Get-ChildItem -LiteralPath $p -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName); $vals = @(); $item = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue; if ($item) { foreach ($vn in $item.GetValueNames()) { $vals += @{ path = ${quotePowerShellLiteral(normalizedPath)}; name = if ($vn) { $vn } else { '(Default)' }; type = 'REG_' + $item.GetValueKind($vn).ToString().ToUpper(); value = [string]$item.GetValue($vn) } } }; @{ subkeys = $subs; values = $vals } | ConvertTo-Json -Depth 4 -Compress`;
      const res = await this.executeCommandOnNode(deviceId, ps, { runAs: 'system', timeoutMs: 7000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const parsed = JSON.parse(res.output);
          const result = {
            subkeys: Array.isArray(parsed.subkeys) ? parsed.subkeys.map(String) : [],
            values: Array.isArray(parsed.values) ? parsed.values : []
          };
          this.registryCache.set(cacheKey, result);
          return result;
        } catch {}
      }
    } else if (osType === 'linux') {
      const py = `python3 -c 'import subprocess,json; out=subprocess.check_output(["sysctl","-a"],text=True,stderr=subprocess.DEVNULL); vals=[]; [vals.append({"path":"sysctl","name":k.strip(),"type":"REG_SZ","value":v.strip()}) for l in out.splitlines()[:60] if "=" in l for k,v in [l.split("=",1)]]; print(json.dumps({"subkeys":["kernel","net.ipv4","vm","fs"],"values":vals}))'`;
      const res = await this.executeCommandOnNode(deviceId, py, { runAs: 'system', timeoutMs: 7000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const parsed = JSON.parse(res.output);
          this.registryCache.set(cacheKey, parsed);
          return parsed;
        } catch {}
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
    if (osType === 'windows') {
      const litPath = normalizeWindowsRegistryLiteralPath(regPath);
      const psType =
        entry.type === 'REG_DWORD'
          ? 'DWord'
          : entry.type === 'REG_BINARY'
            ? 'Binary'
            : entry.type === 'REG_MULTI_SZ'
              ? 'MultiString'
              : 'String';
      const cmd = `if (-not (Test-Path -LiteralPath ${quotePowerShellLiteral(litPath)})) { New-Item -Path ${quotePowerShellLiteral(litPath)} -Force | Out-Null }; Set-ItemProperty -LiteralPath ${quotePowerShellLiteral(litPath)} -Name ${quotePowerShellLiteral(entry.name)} -Value ${quotePowerShellLiteral(String(entry.value))} -Type ${psType}`;
      await this.executeCommandOnNode(deviceId, cmd, { runAs: 'system', timeoutMs: 7000 });
    } else if (osType === 'linux' && /^[a-z0-9_.-]{2,96}$/i.test(entry.name)) {
      await this.executeCommandOnNode(
        deviceId,
        `sysctl -w ${quoteBashLiteral(`${entry.name}=${String(entry.value)}`)}`,
        { runAs: 'system', timeoutMs: 6000 }
      );
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
    if (osType === 'windows') {
      const litPath = normalizeWindowsRegistryLiteralPath(regPath);
      const cmd = `Remove-ItemProperty -LiteralPath ${quotePowerShellLiteral(litPath)} -Name ${quotePowerShellLiteral(name)} -ErrorAction SilentlyContinue`;
      await this.executeCommandOnNode(deviceId, cmd, { runAs: 'system', timeoutMs: 7000 });
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

    const osType = this.getDeviceOs(deviceId);
    if (osType === 'windows') {
      const ps = `Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\Windows\\*' } | Select-Object -First 40 TaskName, TaskPath, @{N='StateStr';E={$_.State.ToString()}} | ConvertTo-Json -Compress`;
      const res = await this.executeCommandOnNode(deviceId, ps, { runAs: 'system', timeoutMs: 7000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const parsed = JSON.parse(res.output);
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
        } catch {}
      }
    } else if (osType === 'linux') {
      const py = `python3 -c 'import subprocess,json; out=subprocess.check_output(["systemctl","list-timers","--all","--no-pager","--no-legend"],text=True); items=[]; [items.append({"name":p[-2],"path":"/lib/systemd/system/"+p[-2],"state":"Ready","lastRunTime":"Active","nextRunTime":p[0]+" "+p[1],"lastResult":"0"}) for l in out.splitlines() for p in [l.split()] if len(p)>=4 and ".timer" in l]; print(json.dumps(items[:40]))'`;
      const res = await this.executeCommandOnNode(deviceId, py, { runAs: 'system', timeoutMs: 7000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const items = JSON.parse(res.output) as ScheduledTaskItem[];
          if (Array.isArray(items)) {
            this.taskCache.set(deviceId, items);
            return items;
          }
        } catch {}
      }
    } else if (osType === 'macos') {
      const py = `python3 -c 'import subprocess,json; out=subprocess.check_output(["launchctl","list"],text=True); items=[]; [items.append({"name":p[2],"path":"/Library/LaunchDaemons/"+p[2]+".plist","state":"Running" if p[0]!="-" else "Ready","lastRunTime":"launchd","nextRunTime":"OnDemand","lastResult":p[1]}) for l in out.splitlines()[1:41] for p in [l.split(None,2)] if len(p)==3]; print(json.dumps(items))'`;
      const res = await this.executeCommandOnNode(deviceId, py, { runAs: 'system', timeoutMs: 7000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const items = JSON.parse(res.output) as ScheduledTaskItem[];
          if (Array.isArray(items)) {
            this.taskCache.set(deviceId, items);
            return items;
          }
        } catch {}
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
    const osType = this.getDeviceOs(deviceId);
    const normalizedDir = canonicalizeRemotePath(dirPath, osType);
    const cacheKey = `${deviceId}::${normalizedDir}`;
    const cached = this.fileCache.get(cacheKey);
    if (cached) return cached;

    if (osType === 'windows') {
      const ps = `Get-ChildItem -LiteralPath ${quotePowerShellLiteral(normalizedDir)} -Force -ErrorAction Stop | Select-Object -First 150 Name, FullName, @{N='Size';E={if ($_.PSIsContainer) {0} else {[long]$_.Length}}}, PSIsContainer, @{N='Mod';E={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')}}, Mode | ConvertTo-Json -Compress`;
      const res = await this.executeCommandOnNode(deviceId, ps, { runAs: 'system', timeoutMs: 7000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const parsed = JSON.parse(res.output);
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
        } catch {}
      }
    } else {
      const py = `python3 - ${quoteBashLiteral(normalizedDir)} <<'PY'\nimport os, stat, time, json, sys\np = sys.argv[1]\nout = []\nfor entry in sorted(os.scandir(p), key=lambda e: (not e.is_dir(follow_symlinks=False), e.name.lower()))[:150]:\n    st = entry.stat(follow_symlinks=False)\n    out.append({\n        "name": entry.name,\n        "path": os.path.join(p, entry.name),\n        "size": 0 if stat.S_ISDIR(st.st_mode) else st.st_size,\n        "isDirectory": stat.S_ISDIR(st.st_mode),\n        "modified": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),\n        "permissions": stat.filemode(st.st_mode)\n    })\nprint(json.dumps(out))\nPY`;
      const res = await this.executeCommandOnNode(deviceId, py, { runAs: 'system', timeoutMs: 7000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const items = JSON.parse(res.output) as FileItem[];
          if (Array.isArray(items)) {
            this.fileCache.set(cacheKey, items);
            return items;
          }
        } catch {}
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
          ? `Remove-Item -LiteralPath ${quotePowerShellLiteral(fullPath)} -Recurse -Force`
          : `rm -rf -- ${quoteBashLiteral(fullPath)}`;
      await this.executeCommandOnNode(deviceId, delCmd, { runAs: 'system', timeoutMs: 8000 });
    } else if (action === 'mkdir') {
      const mkdirCmd =
        osType === 'windows'
          ? `New-Item -ItemType Directory -Path ${quotePowerShellLiteral(fullPath)} -Force | Out-Null`
          : `mkdir -p -- ${quoteBashLiteral(fullPath)}`;
      await this.executeCommandOnNode(deviceId, mkdirCmd, { runAs: 'system', timeoutMs: 7000 });
    } else if (action === 'upload') {
      if (!contentBase64) {
        throw new Error('Missing base64 file content for upload.');
      }
      const cleanB64 = contentBase64.includes(',') ? contentBase64.split(',').pop()! : contentBase64;
      const buf = Buffer.from(cleanB64, 'base64');
      if (buf.length > 10 * 1024 * 1024) {
        throw new Error('Remote file upload exceeds 10 MB inline transfer limit.');
      }
      this.fileContentCache.set(`${deviceId}::${fullPath}`, buf);
      const b64Safe = buf.toString('base64');
      const uploadCmd =
        osType === 'windows'
          ? `[IO.File]::WriteAllBytes(${quotePowerShellLiteral(fullPath)}, [Convert]::FromBase64String('${b64Safe}'))`
          : `printf '%s' '${b64Safe}' | base64 -d > ${quoteBashLiteral(fullPath)}`;
      await this.executeCommandOnNode(deviceId, uploadCmd, { runAs: 'system', timeoutMs: 12000 });
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
          ? `$bytes = [IO.File]::ReadAllBytes(${quotePowerShellLiteral(cleanPath)}); if ($bytes.Length -gt 10485760) { throw 'File exceeds 10MB download limit' }; [Convert]::ToBase64String($bytes)`
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
    const safeLimit = Math.max(1, Math.min(200, Number(limit || 50)));
    const osType = this.getDeviceOs(deviceId);

    if (osType === 'windows') {
      const logName = channel && channel !== 'All' && channel !== 'all' ? channel : 'System';
      const ps = `Get-WinEvent -LogName ${quotePowerShellLiteral(logName)} -MaxEvents ${safeLimit} -ErrorAction SilentlyContinue | Select-Object RecordId, @{N='TimeIso';E={$_.TimeCreated.ToUniversalTime().ToString('o')}}, ProviderName, Id, LevelDisplayName, LogName, Message | ConvertTo-Json -Compress`;
      const res = await this.executeCommandOnNode(deviceId, ps, { runAs: 'system', timeoutMs: 8000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const parsed = JSON.parse(res.output);
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
        } catch {}
      }
    } else if (osType === 'linux') {
      const py = `python3 -c 'import subprocess,json,datetime; out=subprocess.check_output(["journalctl","-n","${safeLimit}","-o","json","--no-pager"],text=True); items=[]; \nfor idx,l in enumerate(out.splitlines()):\n  try:\n    j=json.loads(l); p=int(j.get("PRIORITY",6)); lvl="Critical" if p<=2 else "Error" if p==3 else "Warning" if p==4 else "Information"; ts=int(j.get("__REALTIME_TIMESTAMP",0))/1e6; iso=datetime.datetime.fromtimestamp(ts,datetime.timezone.utc).isoformat() if ts else ""; items.append({"id":idx+1,"timeGenerated":iso,"source":j.get("SYSLOG_IDENTIFIER") or j.get("_COMM") or "kernel","eventId":int(j.get("_PID",0) or 0),"level":lvl,"channel":"journald","message":str(j.get("MESSAGE",""))[:500]})\n  except Exception: pass\nprint(json.dumps(items))'`;
      const res = await this.executeCommandOnNode(deviceId, py, { runAs: 'system', timeoutMs: 8000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const items = JSON.parse(res.output) as EventLogItem[];
          if (Array.isArray(items)) {
            return level && level !== 'all'
              ? items.filter((i) => i.level.toLowerCase() === level.toLowerCase())
              : items;
          }
        } catch {}
      }
    } else if (osType === 'macos') {
      const py = `python3 -c 'import subprocess,json; out=subprocess.check_output(["log","show","--style","compact","--last","30m"],text=True,stderr=subprocess.DEVNULL); lines=[l for l in out.splitlines() if l and not l.startswith("Timestamp")][-${safeLimit}:]; items=[]\nfor idx,l in enumerate(lines):\n  parts=l.split(None,4)\n  if len(parts)<5: continue\n  ts=parts[0]+"T"+parts[1]; ty=parts[2]; proc=parts[3]; msg=parts[4]\n  lvl="Critical" if ty=="F" else "Error" if ty=="E" else "Warning" if ty in ("W","A") else "Information"\n  items.append({"id":idx+1,"timeGenerated":ts,"source":proc.split("[")[0],"eventId":0,"level":lvl,"channel":"unified-log","message":msg[:500]})\nprint(json.dumps(items))'`;
      const res = await this.executeCommandOnNode(deviceId, py, { runAs: 'system', timeoutMs: 10000 });
      if (res.live && res.exitCode === 0 && res.output) {
        try {
          const items = JSON.parse(res.output) as EventLogItem[];
          if (Array.isArray(items)) {
            return level && level !== 'all'
              ? items.filter((i) => i.level.toLowerCase() === level.toLowerCase())
              : items;
          }
        } catch {}
      }
    }

    // Fallback to Vitrine's real recorded audit_logs for this device when endpoint tunnel is offline
    const rows = db
      .prepare('SELECT id, timestamp, username, action, details FROM audit_logs WHERE device_id = ? ORDER BY timestamp DESC LIMIT ?')
      .all(deviceId, safeLimit) as any[];
    return rows.map((r, idx) => ({
      id: idx + 1,
      timeGenerated: r.timestamp || new Date().toISOString(),
      source: `vitrine-audit (${r.username || 'system'})`,
      eventId: 1000 + idx,
      level: 'Information',
      channel: 'Audit',
      message: `${r.action}: ${r.details || ''}`
    }));
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
          let gotMeshes = false;
          let gotNodes = false;
          let timer: ReturnType<typeof setTimeout> | null = null;
          let openTimer: ReturnType<typeof setTimeout> | null = null;

          const ws = new WebSocket(wsUrl, {
            headers,
            rejectUnauthorized: !allowInsecure,
            handshakeTimeout: 4000
          });

          const finish = (res: { ok: boolean; meshes: MeshGroup[]; nodes: DiscoveredMeshAgent[]; error?: string }) => {
            if (settled) return;
            settled = true;
            if (timer) clearTimeout(timer);
            if (openTimer) clearTimeout(openTimer);
            try {
              ws.removeAllListeners();
              ws.close();
            } catch {}
            resolve(res);
          };

          timer = setTimeout(() => {
            finish({ ok: ws.readyState === WebSocket.OPEN, meshes, nodes });
          }, 3500);

          ws.on('open', () => {
            try {
              ws.send(JSON.stringify({ action: 'meshes' }));
              ws.send(JSON.stringify({ action: 'nodes' }));
            } catch {}
            openTimer = setTimeout(() => {
              finish({ ok: true, meshes, nodes });
            }, 1000);
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
                finish({ ok: false, meshes: [], nodes: [], error: authErr });
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
                    const lowerOs = osDesc.toLowerCase();
                    const osType: 'windows' | 'linux' | 'macos' =
                      lowerOs.includes('darwin') || lowerOs.includes('mac')
                        ? 'macos'
                        : lowerOs.includes('linux') || lowerOs.includes('ubuntu') || lowerOs.includes('debian')
                          ? 'linux'
                          : 'windows';
                    nodes.push({
                      nodeId: String(n._id || ''),
                      hostname: String(n.name || n.rname || 'endpoint'),
                      meshId: meshKey,
                      meshName: meshNameById.get(meshKey) || meshKey,
                      osDesc,
                      osType,
                      ipAddress: String(n.ip || ''),
                      online: Boolean(n.conn && (Number(n.conn) & 1) !== 0)
                    });
                  }
                }
                for (const g of meshes) {
                  g.deviceCount = nodes.filter((n) => n.meshId === g.meshid).length;
                }
              }
              if (gotMeshes && gotNodes) {
                finish({ ok: true, meshes, nodes });
              }
            } catch {}
          });

          ws.on('error', (err) => {
            finish({ ok: false, meshes: [], nodes: [], error: err.message });
          });

          ws.on('close', (code) => {
            if (!settled) {
              finish({
                ok: false,
                meshes: [],
                nodes: [],
                error:
                  code >= 4000
                    ? `MeshCentral rejected auth credentials (code ${code})`
                    : 'MeshCentral closed the WebSocket connection before authentication succeeded.'
              });
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
    const serverConfigs: Array<{ url: string; token: string; localPath?: string }> = [];

    const primaryToken = decryptVaultSecret(settings.meshcentral_api_token);
    if (settings.meshcentral_url && primaryToken) {
      serverConfigs.push({ url: settings.meshcentral_url, token: primaryToken });
    }

    const dbServers = db.prepare('SELECT url, api_token, local_config_path FROM mesh_servers').all() as any[];
    for (const s of dbServers) {
      const tok = decryptVaultSecret(s.api_token);
      if (s.url && tok && !serverConfigs.some((c) => c.url === s.url)) {
        serverConfigs.push({ url: s.url, token: tok, localPath: s.local_config_path || undefined });
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
        allowSelfSigned: Boolean(settings.meshcentral_allow_self_signed)
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
        .prepare('SELECT id, quarantined FROM devices WHERE mesh_node_id = ? OR (tenant_id = ? AND LOWER(hostname) = LOWER(?))')
        .get(ag.nodeId, targetTenantId, ag.hostname) as any;

      const nextStatus = ag.online ? 'online' : 'offline';
      if (!existingDev) {
        const devId = `dev-${crypto.randomUUID().slice(0, 8)}`;
        db.prepare(`
          INSERT INTO devices (
            id, tenant_id, mesh_node_id, hostname, os_type, os_version, ip_address, status, last_seen, enrolled_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          devId,
          targetTenantId,
          ag.nodeId,
          ag.hostname,
          ag.osType,
          ag.osDesc,
          ag.ipAddress || '0.0.0.0',
          nextStatus,
          nowIso,
          nowIso
        );
        importedDevices++;
      } else {
        db.prepare(`
          UPDATE devices
          SET mesh_node_id = ?,
              os_type = COALESCE(?, os_type),
              os_version = COALESCE(?, os_version),
              ip_address = CASE WHEN ? != '' THEN ? ELSE ip_address END,
              status = CASE WHEN quarantined = 1 THEN 'isolated' ELSE ? END,
              last_seen = CASE WHEN ? = 'online' THEN ? ELSE last_seen END
          WHERE id = ?
        `).run(
          ag.nodeId,
          ag.osType,
          ag.osDesc,
          ag.ipAddress,
          ag.ipAddress,
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
