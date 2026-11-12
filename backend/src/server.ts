import Fastify from 'fastify';
import type { FastifyReply, FastifyRequest } from 'fastify';
import cors from '@fastify/cors';
import fastifyWebsocket from '@fastify/websocket';
import path from 'path';
import fs from 'fs';
import os from 'os';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { initDatabase, closeDatabase, db, BRANDING_DIR_PATH } from './db/index.js';
import { registerApiRoutes } from './routes/api.js';
import {
  extractAuthContext,
  isTechnicianOrAbove,
  canUserAccessTenant
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

    if (baseName === 'index.html' || baseName === 'sw.js' || baseName === 'manifest.json') {
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

function isAllowedCorsOrigin(origin: string | undefined): boolean {
  if (!origin) return true;
  try {
    const parsed = new URL(origin);
    const host = parsed.hostname.toLowerCase();

    // Always allow local loopback origins for bare-metal local setup & Vite dev server
    if (host === 'localhost' || host === '127.0.0.1' || host === '::1') {
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

    // If not yet onboarded, allow LAN admin browser access to complete OOBE
    const oobeRow = db.prepare('SELECT is_onboarded FROM settings WHERE id = 1').get() as
      | { is_onboarded?: number }
      | undefined;
    if (!oobeRow?.is_onboarded) {
      return true;
    }

    return false;
  } catch {
    return false;
  }
}

async function startServer() {
  initDatabase();
  meshBridge.checkConfig();

  const server = Fastify({
    trustProxy: true,
    bodyLimit: 10 * 1024 * 1024, // 10 MiB default JSON body limit
    logger: {
      level: process.env.NODE_ENV === 'production' ? 'warn' : 'info'
    }
  });

  // Defensive HTTP security headers on every response
  server.addHook('onSend', async (_req, reply) => {
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('X-Frame-Options', 'SAMEORIGIN');
    reply.header('Referrer-Policy', 'strict-origin-when-cross-origin');
    reply.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  });

  await server.register(cors, {
    origin: (origin, cb) => {
      if (isAllowedCorsOrigin(origin)) {
        cb(null, true);
      } else {
        cb(null, false);
      }
    },
    credentials: true
  });

  await server.register(fastifyWebsocket);

  // ============================================================================
  // Branding Assets Static Endpoint (/branding/*)
  // ============================================================================
  server.get('/branding/*', (req, reply) => {
    const params = req.params as { '*'?: string };
    const rel = params['*'] || '';
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
    const auth = extractAuthContext(req);

    if (!auth || !isTechnicianOrAbove(auth.user.role)) {
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
      const dev = getDeviceRow(currentDeviceId);
      if (!dev) {
        return `\r\n\x1b[33m[Vitrine PTY] Select an online endpoint to open a terminal session.\x1b[0m\r\n> `;
      }
      if (!canUserAccessTenant(auth.user, dev.tenant_id)) {
        return `\r\n\x1b[31m[Access Denied] You are not authorized for this tenant's endpoints.\x1b[0m\r\n`;
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

    socket.send(JSON.stringify({ type: 'output', data: buildBanner() }));

    socket.on('message', async (message: Buffer) => {
      try {
        const parsed = JSON.parse(message.toString());

        if (parsed.type === 'switch_context') {
          if (parsed.deviceId) currentDeviceId = String(parsed.deviceId);
          if (parsed.runAs === 'system' || parsed.runAs === 'user') currentRunAs = parsed.runAs;
          if (parsed.shell) currentShell = String(parsed.shell);
          socket.send(
            JSON.stringify({
              type: 'output',
              data:
                `\r\n\x1b[35m[Vitrine PTY] Context -> runAs=${currentRunAs.toUpperCase()}, shell=${currentShell}...\x1b[0m\r\n` +
                buildBanner()
            })
          );
          return;
        }

        if (parsed.type === 'input') {
          const cmd = String(parsed.data || '').trim();
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
    const query = (req.query || {}) as Record<string, string>;
    const auth = extractAuthContext(req);

    // Also allow scoped Guest Portal telemetry tokens if can_view_telemetry = 1
    let authorizedGuestDeviceId: string | null = null;
    if (!auth && query.guestToken && query.guestGrantId) {
      const verified = hmacVerifyToken<{ scope?: string; grantId?: string }>(query.guestToken);
      if (verified && verified.scope === 'guest_portal' && verified.grantId === query.guestGrantId) {
        const grant = db
          .prepare('SELECT id, expires_at, can_view_telemetry, device_ids_json FROM guest_access_grants WHERE id = ?')
          .get(query.guestGrantId) as any;
        if (
          grant &&
          grant.can_view_telemetry &&
          grant.expires_at &&
          new Date(grant.expires_at).getTime() > Date.now()
        ) {
          try {
            const allowedIds: string[] = JSON.parse(grant.device_ids_json || '[]');
            if (query.deviceId && allowedIds.includes(query.deviceId)) {
              authorizedGuestDeviceId = query.deviceId;
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

    const emitSample = () => {
      if (socket.readyState !== 1) return; // 1 = WebSocket.OPEN

      if (targetDeviceId) {
        const dev = db
          .prepare(
            'SELECT id, tenant_id, status, lifecycle_state, cpu_usage, ram_used_gb, ram_total_gb FROM devices WHERE id = ?'
          )
          .get(targetDeviceId) as any;

        if (!dev || (auth && !canUserAccessTenant(auth.user, dev.tenant_id))) {
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
              networkMbps: 0
            })
          );
          return;
        }

        const cpuVal = Number(Number(dev.cpu_usage || 0).toFixed(1));
        const ramVal = Number(Number(dev.ram_used_gb || 0).toFixed(1));
        socket.send(
          JSON.stringify({
            type: 'telemetry_tick',
            timestamp: new Date().toISOString(),
            deviceId: dev.id,
            online: true,
            cpu: cpuVal,
            ramGb: ramVal,
            netMbps: '0.4',
            cpuUsage: cpuVal,
            ramUsageGb: ramVal,
            networkMbps: 0.4
          })
        );
        return;
      }

      // Control plane host telemetry fallback when no deviceId is passed
      const cpus = os.cpus().length || 1;
      const loadPct = Number(Math.min(100, Math.max(0.5, (os.loadavg()[0] / cpus) * 100)).toFixed(1));
      const usedRamGb = Number(((os.totalmem() - os.freemem()) / (1024 * 1024 * 1024)).toFixed(1));

      socket.send(
        JSON.stringify({
          type: 'telemetry_tick',
          timestamp: new Date().toISOString(),
          online: true,
          cpu: loadPct,
          ramGb: usedRamGb,
          netMbps: '0.2',
          cpuUsage: loadPct,
          ramUsageGb: usedRamGb,
          networkMbps: 0.2
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
    console.log(`\n🔮 Vitrine RMM v2.5.0 control plane listening on http://${HOST}:${PORT}`);
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
}

startServer();
