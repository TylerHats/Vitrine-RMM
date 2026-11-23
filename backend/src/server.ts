import Fastify from 'fastify';
import type { FastifyReply, FastifyRequest } from 'fastify';
import cors from '@fastify/cors';
import fastifyWebsocket from '@fastify/websocket';
import path from 'path';
import fs from 'fs';
import os from 'os';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { initDatabase, closeDatabase, db, BRANDING_DIR_PATH, APP_VERSION } from './db/index.js';
import { registerApiRoutes } from './routes/api.js';
import {
  extractAuthContext,
  isSessionTokenActive,
  isTechnicianOrAbove,
  canUserAccessTenant,
  hasUserPermission,
  consumeEphemeralWsTicket
} from './services/auth/index.js';
import { hmacVerifyToken } from './services/vault/index.js';
import { meshBridge } from './services/meshcentral/index.js';
import { startScheduler, stopScheduler } from './services/scheduler/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const MIME_MAP: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.txt': 'text/plain; charset=utf-8',
  '.map': 'application/json; charset=utf-8'
};

function sendVerifiedStaticFile(
  rootDir: string,
  relativePath: string,
  req: FastifyRequest,
  reply: FastifyReply
): boolean {
  try {
    if (!fs.existsSync(rootDir)) return false;
    const realRoot = fs.realpathSync(rootDir);
    const cleanedRel = decodeURIComponent(relativePath).replace(/^[/\\]+/, '');
    if (cleanedRel.includes('\0')) return false;

    const candidate = path.resolve(realRoot, cleanedRel);
    if (candidate !== realRoot && !candidate.startsWith(realRoot + path.sep)) {
      return false;
    }
    if (!fs.existsSync(candidate)) return false;

    const realTarget = fs.realpathSync(candidate);
    if (realTarget !== realRoot && !realTarget.startsWith(realRoot + path.sep)) {
      return false;
    }

    const stat = fs.statSync(realTarget);
    if (!stat.isFile()) return false;

    const ext = path.extname(realTarget).toLowerCase();
    const contentType = MIME_MAP[ext] || 'application/octet-stream';
    const baseName = path.basename(realTarget);

    if (
      baseName === 'index.html' ||
      baseName === 'sw.js' ||
      baseName === 'manifest.json' ||
      baseName === 'manifest.webmanifest'
    ) {
      reply.header('Cache-Control', 'no-cache, no-store, must-revalidate');
    } else if (cleanedRel.startsWith('assets/')) {
      reply.header('Cache-Control', 'public, max-age=31536000, immutable');
    } else {
      reply.header('Cache-Control', 'public, max-age=300');
    }

    reply.header('Content-Type', contentType);
    reply.header('Content-Length', stat.size);

    if (req.method === 'HEAD') {
      reply.status(200).send();
      return true;
    }

    reply.status(200).send(fs.createReadStream(realTarget));
    return true;
  } catch {
    return false;
  }
}

const SAFE_BRANDING_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.webp', '.ico']);

export function isAllowedCorsOrigin(origin: string | undefined, requestHost?: string): boolean {
  if (!origin) return true;
  try {
    const parsed = new URL(origin);
    const host = parsed.hostname.toLowerCase();
    const originHostWithPort = parsed.host.toLowerCase();

    // Same-origin requests (matching the HTTP Host header, e.g. LAN OOBE or reverse proxy) are always valid
    if (requestHost && originHostWithPort === requestHost.trim().toLowerCase()) {
      return true;
    }

    // Allow local loopback cross-port origins only in non-production dev mode (e.g. Vite 5173 -> Fastify 8080)
    if (
      process.env.NODE_ENV !== 'production' &&
      (host === 'localhost' || host === '127.0.0.1' || host === '::1')
    ) {
      return true;
    }

    const settings = (db.prepare('SELECT custom_domain, quicksupport_custom_domain FROM settings WHERE id = 1').get() ||
      {}) as { custom_domain?: string; quicksupport_custom_domain?: string };

    const configuredHosts = [settings.custom_domain, settings.quicksupport_custom_domain]
      .filter(Boolean)
      .map((val) => {
        const s = String(val).trim();
        try {
          return s.includes('://') ? new URL(s).hostname.toLowerCase() : s.split('/')[0].split(':')[0].toLowerCase();
        } catch {
          return s.toLowerCase();
        }
      });

    if (configuredHosts.includes(host)) {
      return true;
    }

    if (process.env.VITRINE_ALLOWED_ORIGINS) {
      const extras = process.env.VITRINE_ALLOWED_ORIGINS.split(',').map((o) => o.trim().toLowerCase());
      if (extras.includes(origin.toLowerCase()) || extras.includes(host)) {
        return true;
      }
    }

    return false;
  } catch {
    return false;
  }
}

function buildContentSecurityPolicy(): string {
  const frameOrigins = new Set<string>(["'self'"]);
  try {
    const s = db.prepare('SELECT meshcentral_url FROM settings WHERE id = 1').get() as { meshcentral_url?: string } | undefined;
    const msRows = db.prepare('SELECT url FROM mesh_servers').all() as Array<{ url?: string }>;
    for (const raw of [s?.meshcentral_url, ...msRows.map((r) => r.url)]) {
      if (!raw) continue;
      try {
        const parsed = new URL(String(raw).trim());
        if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
          frameOrigins.add(parsed.origin);
        }
      } catch {
        // Ignore malformed URL
      }
    }
  } catch {
    // DB initializing
  }

  return [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data: blob: https:",
    "media-src 'self' data: blob:",
    "connect-src 'self' ws: wss: https: http://localhost:* http://127.0.0.1:*",
    `frame-src ${Array.from(frameOrigins).join(' ')}`,
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'self'"
  ].join('; ');
}

async function startServer() {
  initDatabase();
  meshBridge.checkConfig();

  const server = Fastify({
    trustProxy: process.env.VITRINE_TRUST_PROXY === 'true',
    bodyLimit: 25 * 1024 * 1024, // 25 MiB body limit (supports encrypted backup & WebM recording uploads)
    logger: {
      level: process.env.NODE_ENV === 'production' ? 'warn' : 'info'
    }
  });

  // Defensive HTTP security headers & strict Content-Security-Policy on every response
  server.addHook('onSend', (req, reply, payload, done) => {
    try {
      reply.header('X-Content-Type-Options', 'nosniff');
      reply.header('X-Frame-Options', 'SAMEORIGIN');
      reply.header('Referrer-Policy', 'strict-origin-when-cross-origin');
      reply.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
      if ((req.raw.url || '').startsWith('/branding/')) {
        reply.header('Content-Security-Policy', "default-src 'none'; sandbox");
      } else {
        reply.header('Content-Security-Policy', buildContentSecurityPolicy());
      }
    } catch {
      // Never block response delivery if header serialization throws
    }
    done(null, payload);
  });

  await server.register(cors, {
    delegator: (req, cb) => {
      cb(null, {
        origin: (origin, originCb) => {
          if (isAllowedCorsOrigin(origin, req.headers.host)) {
            originCb(null, true);
          } else {
            originCb(null, false);
          }
        },
        credentials: true,
        methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: [
          'Content-Type',
          'Authorization',
          'X-API-Key',
          'X-Vitrine-CSRF',
          'X-Vitrine-Guest-Token',
          'X-Guest-Token',
          'X-Vitrine-Signature'
        ]
      });
    }
  });

  await server.register(fastifyWebsocket);

  // ============================================================================
  // Branding Assets Static Endpoint (/branding/*) — Raster Images Only
  // ============================================================================
  server.get('/branding/*', (req, reply) => {
    const params = req.params as { '*'?: string };
    const rel = params['*'] || '';
    const ext = path.extname(rel).toLowerCase();
    if (!SAFE_BRANDING_EXTENSIONS.has(ext)) {
      return reply.status(403).send({ error: 'Unsupported branding asset format' });
    }
    if (sendVerifiedStaticFile(BRANDING_DIR_PATH, rel, req, reply)) {
      return;
    }
    return reply.status(404).send({ error: 'Branding asset not found' });
  });

  // ============================================================================
  // Authenticated WebSocket: Interactive Background Shell (/ws/terminal)
  // ============================================================================
  server.get('/ws/terminal', { websocket: true }, (rawSocket, req) => {
    const socket = (rawSocket as any).socket || rawSocket;
    if (!isAllowedCorsOrigin(req.headers.origin as string | undefined, req.headers.host)) {
      try {
        socket.close(1008, 'Cross-origin WebSocket rejected');
      } catch {}
      return;
    }

    const auth = extractAuthContext(req);

    if (!auth || !isTechnicianOrAbove(auth.user.role) || !hasUserPermission(auth.user, 'remote:connect')) {
      try {
        socket.send(
          JSON.stringify({
            type: 'output',
            data: '\r\n\x1b[31m[Access Denied] Valid Technician or Super Admin session required for remote PTY shell.\x1b[0m\r\n'
          })
        );
        socket.close(1008, 'Authentication required');
      } catch {
        // Ignore
      }
      return;
    }

    const query = (req.query || {}) as Record<string, string>;
    let currentDeviceId = query.deviceId || '';
    let currentRunAs: 'system' | 'user' = query.runAs === 'user' ? 'user' : 'system';
    let currentShell = query.shell || '';
    let currentCols = Math.max(40, Math.min(300, parseInt(query.cols || '120', 10) || 120));
    let currentRows = Math.max(10, Math.min(120, parseInt(query.rows || '34', 10) || 34));
    let activeRelay: { write: (data: string) => void; resize: (cols: number, rows: number) => void; close: () => void } | null = null;
    let terminalMode: 'pty' | 'line_fallback' | 'unconnected' = 'unconnected';
    let fallbackLineBuffer = '';
    let openGeneration = 0;

    const closeActiveRelay = () => {
      if (activeRelay) {
        try {
          activeRelay.close();
        } catch {}
        activeRelay = null;
      }
    };

    const getDeviceRow = (devId: string) => {
      if (!devId) return null;
      return db
        .prepare(
          'SELECT id, tenant_id, hostname, os_type, os_version, ip_address, cpu_model, ram_total_gb, status, lifecycle_state FROM devices WHERE id = ?'
        )
        .get(devId) as any;
    };

    const resolveShell = (osType: string, requestedShell: string) => {
      if (requestedShell) return requestedShell;
      if (osType === 'macos') return 'zsh';
      if (osType === 'linux') return 'bash';
      return 'powershell';
    };

    const getPrompt = (dev: any, runAs: 'system' | 'user', shell: string) => {
      const osType = dev?.os_type || 'windows';
      const host = (dev?.hostname || 'endpoint').toLowerCase();
      if (osType === 'windows') {
        const cwd = runAs === 'system' ? 'C:\\Windows\\System32' : 'C:\\Users\\Public';
        return shell === 'cmd' ? `${cwd}> ` : `PS ${cwd}> `;
      }
      if (osType === 'macos') {
        const user = runAs === 'system' ? 'root' : 'consoleuser';
        const sym = runAs === 'system' ? '#' : '%';
        const dir = runAs === 'system' ? '/var/root' : '~';
        return `${user}@${host} ${dir} ${sym} `;
      }
      const user = runAs === 'system' ? 'root' : 'localuser';
      const sym = runAs === 'system' ? '#' : '$';
      const dir = runAs === 'system' ? '/root' : '~';
      return `${user}@${host}:${dir}${sym} `;
    };

    const buildBanner = () => {
      if (!currentDeviceId) {
        return `\r\n\x1b[33m[Vitrine PTY] Select an online endpoint to open a terminal session.\x1b[0m\r\n> `;
      }
      const dev = getDeviceRow(currentDeviceId);
      if (!dev || !canUserAccessTenant(auth.user, dev.tenant_id)) {
        return `\r\n\x1b[31m[Access Denied] Endpoint unavailable or not authorized for your account.\x1b[0m\r\n> `;
      }
      const osType = dev.os_type || 'windows';
      const shell = resolveShell(osType, currentShell);
      currentShell = shell;
      const prompt = getPrompt(dev, currentRunAs, shell);
      const bridgeState = meshBridge.getStatus().connected ? 'LIVE MESHCENTRAL TUNNEL' : 'STANDALONE RELAY';
      const statusBadge = dev.status === 'online' ? 'ONLINE' : String(dev.status || 'OFFLINE').toUpperCase();

      return [
        '',
        '\x1b[36m======================================================================\x1b[0m',
        `\x1b[1;36m  Vitrine RMM Remote Shell — ${dev.hostname} (${dev.ip_address || 'N/A'}) [${statusBadge}]\x1b[0m`,
        `\x1b[33m  Operator : ${auth.user.username} | Context : ${currentRunAs.toUpperCase()} | Relay : ${bridgeState}\x1b[0m`,
        `\x1b[32m  Shell    : ${shell.toUpperCase()} (${dev.os_version || osType})\x1b[0m`,
        '\x1b[36m======================================================================\x1b[0m',
        '',
        prompt
      ].join('\r\n');
    };

    const openTerminalSession = async () => {
      const gen = ++openGeneration;
      closeActiveRelay();
      fallbackLineBuffer = '';

      if (!currentDeviceId) {
        terminalMode = 'unconnected';
        socket.send(JSON.stringify({ type: 'status', mode: 'unconnected' }));
        socket.send(JSON.stringify({ type: 'output', data: buildBanner() }));
        return;
      }

      const dev = getDeviceRow(currentDeviceId);
      if (!dev || !canUserAccessTenant(auth.user, dev.tenant_id)) {
        terminalMode = 'unconnected';
        socket.send(JSON.stringify({ type: 'status', mode: 'unconnected', error: 'Endpoint unavailable or access denied' }));
        socket.send(
          JSON.stringify({
            type: 'output',
            data: `\r\n\x1b[31m[Access Denied] Endpoint unavailable or not authorized for your account.\x1b[0m\r\n> `
          })
        );
        return;
      }

      const osType = dev.os_type || 'windows';
      currentShell = resolveShell(osType, currentShell);
      socket.send(
        JSON.stringify({
          type: 'status',
          mode: 'connecting',
          deviceId: dev.id,
          shell: currentShell,
          runAs: currentRunAs
        })
      );

      let relay: { write: (data: string) => void; resize: (cols: number, rows: number) => void; close: () => void } | null = null;
      if (dev.status === 'online' || dev.status === 'isolated') {
        relay = await meshBridge.openInteractiveTerminalRelay(dev.id, {
          runAs: currentRunAs,
          shell: currentShell,
          cols: currentCols,
          rows: currentRows,
          onData: (chunk) => {
            if (gen !== openGeneration || socket.readyState !== 1) return;
            try {
              socket.send(JSON.stringify({ type: 'output', data: chunk }));
            } catch {}
          },
          onReady: ({ protocol, recorded }) => {
            if (gen !== openGeneration || socket.readyState !== 1) return;
            try {
              socket.send(
                JSON.stringify({
                  type: 'status',
                  mode: 'pty',
                  deviceId: dev.id,
                  shell: currentShell,
                  runAs: currentRunAs,
                  protocol,
                  recorded
                })
              );
            } catch {}
          },
          onClose: (reason) => {
            if (gen !== openGeneration) return;
            activeRelay = null;
            if (terminalMode === 'pty') {
              terminalMode = 'line_fallback';
            }
            if (socket.readyState === 1) {
              try {
                socket.send(
                  JSON.stringify({
                    type: 'output',
                    data: `\r\n\x1b[33m[PTY Closed] ${reason || 'Remote tunnel disconnected.'}\x1b[0m\r\n`
                  })
                );
                socket.send(
                  JSON.stringify({
                    type: 'status',
                    mode: 'line_fallback',
                    deviceId: dev.id,
                    shell: currentShell,
                    runAs: currentRunAs
                  })
                );
              } catch {}
            }
          },
          onError: (err) => {
            if (gen !== openGeneration || socket.readyState !== 1) return;
            try {
              socket.send(
                JSON.stringify({
                  type: 'output',
                  data: `\r\n\x1b[31m[PTY Error] ${err}\x1b[0m\r\n`
                })
              );
            } catch {}
          }
        });
      }

      if (gen !== openGeneration || socket.readyState !== 1) {
        relay?.close();
        return;
      }

      if (relay) {
        activeRelay = relay;
        terminalMode = 'pty';
        db.prepare(`
          INSERT INTO audit_logs (id, username, device_id, action, details)
          VALUES (?, ?, ?, 'Interactive PTY Shell Opened', ?)
        `).run(
          `aud-pty-${crypto.randomUUID()}`,
          auth.user.username,
          dev.id,
          `Opened live MS2 PTY tunnel (${currentRunAs.toUpperCase()}/${currentShell}) on ${dev.hostname}`
        );
        socket.send(
          JSON.stringify({
            type: 'output',
            data: `\x1b[36m[Vitrine Live PTY — ${dev.hostname} (${currentShell.toUpperCase()} / ${currentRunAs.toUpperCase()})]\x1b[0m\r\n`
          })
        );
        socket.send(
          JSON.stringify({
            type: 'status',
            mode: 'pty',
            deviceId: dev.id,
            shell: currentShell,
            runAs: currentRunAs
          })
        );
        return;
      }

      terminalMode = 'line_fallback';
      const reason =
        dev.status !== 'online' && dev.status !== 'isolated'
          ? 'device_offline'
          : meshBridge.getStatus().connected
            ? 'meshrelay_unavailable'
            : 'mesh_bridge_disconnected';
      socket.send(
        JSON.stringify({
          type: 'status',
          mode: 'line_fallback',
          deviceId: dev.id,
          shell: currentShell,
          runAs: currentRunAs,
          reason
        })
      );
      socket.send(
        JSON.stringify({
          type: 'output',
          data:
            `\r\n\x1b[33m[Command Relay Fallback] Interactive PTY tunnel unavailable (${reason}). Commands execute per-line when you press Enter.\x1b[0m` +
            buildBanner()
        })
      );
    };

    const runLineCommand = async (rawCmd: string) => {
      const cmd = rawCmd.trim();
      const dev = getDeviceRow(currentDeviceId);
      if (!dev) {
        socket.send(JSON.stringify({ type: 'output', data: '\r\nDevice not found.\r\n> ' }));
        return;
      }
      if (!canUserAccessTenant(auth.user, dev.tenant_id)) {
        socket.send(JSON.stringify({ type: 'output', data: '\r\nAccess denied for target device.\r\n' }));
        return;
      }

      const shell = resolveShell(dev.os_type || 'windows', currentShell);
      const prompt = getPrompt(dev, currentRunAs, shell);

      if (!cmd) {
        socket.send(JSON.stringify({ type: 'output', data: `\r\n${prompt}` }));
        return;
      }

      if (cmd === 'clear' || cmd === 'cls') {
        socket.send(JSON.stringify({ type: 'output', data: `\x1b[2J\x1b[H${prompt}` }));
        return;
      }

      db.prepare(`
        INSERT INTO audit_logs (id, username, device_id, action, details)
        VALUES (?, ?, ?, 'Remote Shell Command', ?)
      `).run(
        `aud-pty-${crypto.randomUUID()}`,
        auth.user.username,
        dev.id,
        `[${currentRunAs.toUpperCase()}/${shell}] ${cmd.slice(0, 240)}`
      );

      const execRes = await meshBridge.executeCommandOnNode(dev.id, cmd, {
        runAs: currentRunAs,
        shell
      });

      socket.send(
        JSON.stringify({
          type: 'output',
          data: `\r\n${execRes.output}\r\n\r\n${prompt}`
        })
      );
    };

    void openTerminalSession();

    socket.on('close', () => {
      openGeneration++;
      closeActiveRelay();
    });

    socket.on('error', () => {
      openGeneration++;
      closeActiveRelay();
    });

    socket.on('message', async (message: Buffer) => {
      try {
        const liveUser = isSessionTokenActive(auth.tokenHash);
        const currentDev = currentDeviceId ? getDeviceRow(currentDeviceId) : null;
        const tenantRevoked = Boolean(
          currentDeviceId && (!currentDev || !canUserAccessTenant(liveUser, currentDev.tenant_id))
        );
        if (
          !liveUser ||
          !isTechnicianOrAbove(liveUser.role) ||
          !hasUserPermission(liveUser, 'remote:connect') ||
          tenantRevoked
        ) {
          socket.send(
            JSON.stringify({
              type: 'output',
              data: '\r\n\x1b[31m[Session Terminated] Your session expired or privileges were revoked.\x1b[0m\r\n'
            })
          );
          openGeneration++;
          closeActiveRelay();
          socket.close(1008, 'Session expired or revoked');
          return;
        }
        auth.user = liveUser;

        const parsed = JSON.parse(message.toString());

        if (parsed.type === 'switch_context') {
          if (parsed.deviceId) {
            const candidateDev = getDeviceRow(String(parsed.deviceId));
            if (!candidateDev || !canUserAccessTenant(auth.user, candidateDev.tenant_id)) {
              socket.send(
                JSON.stringify({
                  type: 'output',
                  data: `\r\n\x1b[31m[Access Denied] Endpoint unavailable or not authorized for your account.\x1b[0m\r\n> `
                })
              );
              return;
            }
            currentDeviceId = candidateDev.id;
          }
          if (parsed.runAs === 'system' || parsed.runAs === 'user') currentRunAs = parsed.runAs;
          if (parsed.shell) currentShell = String(parsed.shell);
          if (typeof parsed.cols === 'number') currentCols = Math.max(40, Math.min(300, parsed.cols));
          if (typeof parsed.rows === 'number') currentRows = Math.max(10, Math.min(120, parsed.rows));
          await openTerminalSession();
          return;
        }

        if (parsed.type === 'resize') {
          const nextCols = Math.max(40, Math.min(300, Number(parsed.cols) || currentCols));
          const nextRows = Math.max(10, Math.min(120, Number(parsed.rows) || currentRows));
          currentCols = nextCols;
          currentRows = nextRows;
          if (activeRelay) {
            activeRelay.resize(nextCols, nextRows);
          }
          return;
        }

        if (parsed.type === 'data') {
          const data = String(parsed.data ?? '');
          if (terminalMode === 'pty' && activeRelay) {
            activeRelay.write(data);
            return;
          }
          if (terminalMode === 'line_fallback') {
            for (const ch of data) {
              if (ch === '\r' || ch === '\n') {
                const toRun = fallbackLineBuffer;
                fallbackLineBuffer = '';
                await runLineCommand(toRun);
              } else if (ch === '\x7f' || ch === '\b') {
                if (fallbackLineBuffer.length > 0) {
                  fallbackLineBuffer = fallbackLineBuffer.slice(0, -1);
                  socket.send(JSON.stringify({ type: 'output', data: '\b \b' }));
                }
              } else if (ch === '\x03') {
                fallbackLineBuffer = '';
                const dev = getDeviceRow(currentDeviceId);
                const shell = resolveShell(dev?.os_type || 'windows', currentShell);
                socket.send(JSON.stringify({ type: 'output', data: `^C\r\n${getPrompt(dev, currentRunAs, shell)}` }));
              } else if (ch >= ' ') {
                fallbackLineBuffer += ch;
                socket.send(JSON.stringify({ type: 'output', data: ch }));
              }
            }
          }
          return;
        }

        if (parsed.type === 'input') {
          const rawInput = String(parsed.data || '');
          if (terminalMode === 'pty' && activeRelay) {
            activeRelay.write(rawInput.endsWith('\r') || rawInput.endsWith('\n') ? rawInput : `${rawInput}\r`);
            return;
          }
          await runLineCommand(rawInput);
        }
      } catch {
        // Ignore malformed WS frames
      }
    });
  });

  // ============================================================================
  // Authenticated WebSocket: Real-Time Telemetry Pulse (/ws/telemetry)
  // ============================================================================
  server.get('/ws/telemetry', { websocket: true }, (rawSocket, req) => {
    const socket = (rawSocket as any).socket || rawSocket;
    if (!isAllowedCorsOrigin(req.headers.origin as string | undefined, req.headers.host)) {
      try {
        socket.close(1008, 'Cross-origin WebSocket rejected');
      } catch {}
      return;
    }

    const query = (req.query || {}) as Record<string, string>;
    const auth = extractAuthContext(req);

    // Allow scoped Guest Portal telemetry via single-use ticket (preferred) or legacy guestToken
    let authorizedGuestDeviceId: string | null = null;
    let authorizedGuestGrantId: string | null = null;
    if (!auth) {
      let resolvedGrantId = '';
      if (query.ticket) {
        const consumed = consumeEphemeralWsTicket(query.ticket);
        if (consumed?.grantId) resolvedGrantId = consumed.grantId;
      } else if (query.guestToken && query.guestGrantId) {
        const verified = hmacVerifyToken<{ scope?: string; grantId?: string }>(query.guestToken);
        if (verified && verified.scope === 'guest_portal' && verified.grantId === query.guestGrantId) {
          resolvedGrantId = query.guestGrantId;
        }
      }
      if (resolvedGrantId) {
        const grant = db
          .prepare('SELECT id, status, expires_at, can_view_telemetry, device_ids_json FROM guest_access_grants WHERE id = ?')
          .get(resolvedGrantId) as any;
        if (
          grant &&
          grant.status === 'active' &&
          grant.can_view_telemetry &&
          grant.expires_at &&
          new Date(grant.expires_at).getTime() > Date.now()
        ) {
          try {
            const allowedIds: string[] = JSON.parse(grant.device_ids_json || '[]');
            if (query.deviceId && allowedIds.includes(query.deviceId)) {
              authorizedGuestDeviceId = query.deviceId;
              authorizedGuestGrantId = resolvedGrantId;
            }
          } catch {
            authorizedGuestDeviceId = null;
          }
        }
      }
    }

    if (!auth && !authorizedGuestDeviceId) {
      try {
        socket.close(1008, 'Authentication required');
      } catch {
        // Ignore
      }
      return;
    }

    const targetDeviceId = authorizedGuestDeviceId || query.deviceId || '';
    let lastLiveProbeAt = 0;
    let lastHostNetSample: { bytes: number; ts: number } | null = null;

    const sampleHostNetMbps = (): number => {
      try {
        const raw = fs.readFileSync('/proc/net/dev', 'utf8');
        let totalBytes = 0;
        for (const line of raw.split('\n')) {
          const trimmed = line.trim();
          const colonIdx = trimmed.indexOf(':');
          if (colonIdx <= 0) continue;
          const iface = trimmed.slice(0, colonIdx).trim();
          if (iface === 'lo') continue;
          const cols = trimmed.slice(colonIdx + 1).trim().split(/\s+/);
          if (cols.length >= 9) {
            const rx = Number(cols[0]) || 0;
            const tx = Number(cols[8]) || 0;
            totalBytes += rx + tx;
          }
        }
        const nowTs = Date.now();
        if (lastHostNetSample && nowTs > lastHostNetSample.ts) {
          const deltaBytes = Math.max(0, totalBytes - lastHostNetSample.bytes);
          const deltaSec = (nowTs - lastHostNetSample.ts) / 1000;
          lastHostNetSample = { bytes: totalBytes, ts: nowTs };
          return Number(((deltaBytes * 8) / (deltaSec * 1_000_000)).toFixed(2));
        }
        lastHostNetSample = { bytes: totalBytes, ts: nowTs };
      } catch {
        // /proc/net/dev unavailable on non-Linux hosts
      }
      return 0;
    };

    const triggerLiveTelemetryProbeIfStale = (dev: any) => {
      if (!dev || !dev.mesh_node_id || dev.status !== 'online' || (dev.lifecycle_state || 'active') !== 'active') return;
      if (!meshBridge.getStatus().connected) return;
      const nowMs = Date.now();
      if (nowMs - lastLiveProbeAt < 15_000) return;

      let stale = Number(dev.ram_used_gb || 0) <= 0;
      if (!stale) {
        try {
          const latest = db
            .prepare('SELECT recorded_at FROM device_telemetry_history WHERE device_id = ? ORDER BY recorded_at DESC, id DESC LIMIT 1')
            .get(dev.id) as { recorded_at?: string } | undefined;
          if (!latest?.recorded_at) {
            stale = true;
          } else {
            const latestMs = new Date(String(latest.recorded_at).replace(' ', 'T')).getTime();
            stale = Number.isNaN(latestMs) || nowMs - latestMs >= 30_000;
          }
        } catch {
          stale = true;
        }
      }
      if (stale) {
        lastLiveProbeAt = nowMs;
        void meshBridge.sampleLiveTelemetry(dev.id).catch(() => {});
      }
    };

    const emitSample = () => {
      if (socket.readyState !== 1) return; // 1 = WebSocket.OPEN

      if (auth) {
        const liveUser = isSessionTokenActive(auth.tokenHash);
        if (!liveUser) {
          socket.close(1008, 'Session expired or revoked');
          return;
        }
        auth.user = liveUser;
      } else if (authorizedGuestDeviceId && authorizedGuestGrantId) {
        const grantCheck = db
          .prepare('SELECT status, expires_at FROM guest_access_grants WHERE id = ?')
          .get(authorizedGuestGrantId) as { status?: string; expires_at?: string } | undefined;
        if (
          !grantCheck ||
          grantCheck.status !== 'active' ||
          !grantCheck.expires_at ||
          new Date(grantCheck.expires_at).getTime() <= Date.now()
        ) {
          socket.close(1008, 'Guest grant expired or revoked');
          return;
        }
      }

      if (targetDeviceId) {
        const dev = db
          .prepare(`
            SELECT id, tenant_id, status, lifecycle_state, mesh_node_id,
                   cpu_usage, ram_used_gb, ram_total_gb,
                   disk_free_gb, disk_total_gb,
                   net_rx_mbps, net_tx_mbps, uptime_seconds, last_seen
            FROM devices
            WHERE id = ?
          `)
          .get(targetDeviceId) as any;

        if (
          !dev ||
          (auth && (!hasUserPermission(auth.user, 'devices:read') || !canUserAccessTenant(auth.user, dev.tenant_id)))
        ) {
          socket.close(1008, 'Unauthorized device');
          return;
        }

        const isOnline = dev.status === 'online' && (dev.lifecycle_state || 'active') === 'active';
        if (!isOnline) {
          socket.send(
            JSON.stringify({
              timestamp: new Date().toISOString(),
              deviceId: dev.id,
              online: false,
              cpuUsage: 0,
              ramUsageGb: 0,
              ramTotalGb: Number(dev.ram_total_gb || 0),
              diskFreeGb: Number(dev.disk_free_gb || 0),
              diskTotalGb: Number(dev.disk_total_gb || 0),
              netRxMbps: 0,
              netTxMbps: 0,
              networkMbps: 0
            })
          );
          return;
        }

        triggerLiveTelemetryProbeIfStale(dev);

        const cpuVal = Number(Number(dev.cpu_usage || 0).toFixed(1));
        const ramVal = Number(Number(dev.ram_used_gb || 0).toFixed(2));
        const ramTotal = Number(Number(dev.ram_total_gb || 0).toFixed(2));
        const diskFree = Number(Number(dev.disk_free_gb || 0).toFixed(2));
        const diskTotal = Number(Number(dev.disk_total_gb || 0).toFixed(2));
        const netRx = Number(Number(dev.net_rx_mbps || 0).toFixed(3));
        const netTx = Number(Number(dev.net_tx_mbps || 0).toFixed(3));
        const netTotal = Number((netRx + netTx).toFixed(2));
        socket.send(
          JSON.stringify({
            type: 'telemetry_tick',
            timestamp: new Date().toISOString(),
            deviceId: dev.id,
            online: true,
            cpu: cpuVal,
            ramGb: ramVal,
            ramTotalGb: ramTotal,
            diskFreeGb: diskFree,
            diskTotalGb: diskTotal,
            netRxMbps: netRx,
            netTxMbps: netTx,
            netMbps: netTotal.toFixed(2),
            cpuUsage: cpuVal,
            ramUsageGb: ramVal,
            networkMbps: netTotal,
            uptimeSeconds: Number(dev.uptime_seconds || 0)
          })
        );
        return;
      }

      // Control plane host telemetry fallback when no deviceId is passed (restricted to MSP Technicians/Admins)
      if (!auth || !isTechnicianOrAbove(auth.user.role)) {
        socket.close(1008, 'Device ID required for scoped telemetry');
        return;
      }

      const cpus = os.cpus().length || 1;
      const loadPct = Number(Math.min(100, Math.max(0.5, (os.loadavg()[0] / cpus) * 100)).toFixed(1));
      const usedRamGb = Number(((os.totalmem() - os.freemem()) / (1024 * 1024 * 1024)).toFixed(1));
      const hostNetMbps = sampleHostNetMbps();

      socket.send(
        JSON.stringify({
          type: 'telemetry_tick',
          timestamp: new Date().toISOString(),
          online: true,
          cpu: loadPct,
          ramGb: usedRamGb,
          netMbps: hostNetMbps.toFixed(2),
          cpuUsage: loadPct,
          ramUsageGb: usedRamGb,
          networkMbps: hostNetMbps
        })
      );
    };

    emitSample();
    const interval = setInterval(() => {
      if (socket.readyState === 1) {
        emitSample();
      } else if (socket.readyState >= 2) {
        clearInterval(interval);
      }
    }, 2500);

    const cleanup = () => clearInterval(interval);
    socket.on('close', cleanup);
    socket.on('error', cleanup);
  });

  // ============================================================================
  // Register REST API Routes
  // ============================================================================
  await registerApiRoutes(server);

  // ============================================================================
  // Serve Frontend Bundle & HTML5 SPA Fallback (Docker & Bare-Metal)
  // ============================================================================
  const FRONTEND_CANDIDATES = [
    path.resolve(__dirname, '../../frontend/dist'),
    path.resolve(__dirname, '../frontend/dist'),
    path.resolve(process.cwd(), 'frontend/dist')
  ];
  const FRONTEND_DIST = FRONTEND_CANDIDATES.find((p) => fs.existsSync(p)) || FRONTEND_CANDIDATES[0];

  server.setNotFoundHandler((req, reply) => {
    const pathname = (req.raw.url || '/').split('?')[0];

    // Never serve HTML for unknown /api, /ws, or /branding paths
    if (
      pathname === '/api' ||
      pathname.startsWith('/api/') ||
      pathname === '/ws' ||
      pathname.startsWith('/ws/') ||
      pathname.startsWith('/branding/')
    ) {
      return reply.status(404).send({ error: 'Endpoint Not Found' });
    }

    if ((req.method === 'GET' || req.method === 'HEAD') && fs.existsSync(FRONTEND_DIST)) {
      const requestedFile = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
      if (sendVerifiedStaticFile(FRONTEND_DIST, requestedFile, req, reply)) {
        return;
      }

      // SPA route fallback (e.g., /remote, /guest/:id, /temporarysession) when pathname has no file extension
      if (!path.extname(pathname)) {
        if (sendVerifiedStaticFile(FRONTEND_DIST, 'index.html', req, reply)) {
          return;
        }
      }
    }

    return reply.status(404).send({ error: 'Endpoint Not Found' });
  });

  // Start periodic background tasks
  startScheduler();

  const PORT = parseInt(process.env.PORT || '8080', 10);
  const HOST = process.env.HOST || '0.0.0.0';

  const gracefulShutdown = async (signal: string) => {
    console.log(`\n[Vitrine RMM] Received ${signal} — shutting down cleanly...`);
    stopScheduler();
    try {
      await server.close();
    } catch {
      // Ignore
    }
    closeDatabase();
    process.exit(0);
  };

  process.once('SIGINT', () => void gracefulShutdown('SIGINT'));
  process.once('SIGTERM', () => void gracefulShutdown('SIGTERM'));

  try {
    await server.listen({ port: PORT, host: HOST });
    console.log(`\n🔮 Vitrine RMM v${APP_VERSION} control plane listening on http://${HOST}:${PORT}`);
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
}

startServer();
