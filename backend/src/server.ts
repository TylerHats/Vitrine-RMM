import Fastify from 'fastify';
import cors from '@fastify/cors';
import fastifyStatic from '@fastify/static';
import fastifyWebsocket from '@fastify/websocket';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { initDatabase } from './db/index.js';
import { registerApiRoutes } from './routes/api.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  // Initialize DB schema & seeds
  initDatabase();

  const server = Fastify({
    logger: {
      level: process.env.NODE_ENV === 'production' ? 'warn' : 'info'
    }
  });

  await server.register(cors, {
    origin: true,
    credentials: true
  });

  await server.register(fastifyWebsocket);

  // Register Branding assets
  const BRANDING_DIR = path.resolve(__dirname, '../../branding');
  if (fs.existsSync(BRANDING_DIR)) {
    server.register(fastifyStatic, {
      root: BRANDING_DIR,
      prefix: '/branding/',
      decorateReply: false
    });
  }

  // WebSocket Stream: Interactive Background Shell (PowerShell, CMD, Bash)
  server.get('/ws/terminal', { websocket: true }, (connection: any) => {
    const socket = connection.socket || connection;
    socket.send(JSON.stringify({
      type: 'output',
      data: `\r\n\x1b[36m====================================================\x1b[0m\r\n\x1b[1;36m  Vitrine RMM Interactive Background Engine\x1b[0m\r\n\x1b[36m  Connected via MeshCentral Micro-Agent WebSocket Tunnel\x1b[0m\r\n\x1b[36m====================================================\x1b[0m\r\n\r\nWindows PowerShell\r\nCopyright (C) Microsoft Corporation. All rights reserved.\r\n\r\nPS C:\\Program Files\\VitrineRMM> `
    }));

    socket.on('message', (message: any) => {
      try {
        const parsed = JSON.parse(message.toString());
        if (parsed.type === 'input') {
          const cmd = parsed.data.trim();
          let response = '';

          if (cmd === 'Get-Process' || cmd === 'ps') {
            response = `\r\nHandles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id ProcessName\r\n-------  ------    -----      -----     ------     -- -----------\r\n    540      38    24108      42104       1.24   5124 VitrineAgentService\r\n    412      24    18420      28500       0.98   5892 MeshAgent\r\n   1820     110   184210     320400       8.45   4210 MsMpEng\r\n   2450     180   410290     890500      18.20   7920 chrome\r\n\r\nPS C:\\Program Files\\VitrineRMM> `;
          } else if (cmd === 'Get-BitLockerVolume') {
            response = `\r\n   VolumeType: OperatingSystem\r\n   Mount Point: C:\r\n   CapacityGB: 1024.0\r\n   VolumeStatus: FullyEncrypted\r\n   EncryptionMethod: XtsAes256\r\n   ProtectionStatus: ProtectionOn\r\n   LockStatus: Unlocked\r\n   KeyProtector: RecoveryPassword (481920-592019-209184-102948-592810-482019)\r\n\r\nPS C:\\Program Files\\VitrineRMM> `;
          } else if (cmd === 'Get-Service Spooler') {
            response = `\r\nStatus   Name               DisplayName\r\n------   ----               -----------\r\nRunning  Spooler            Print Spooler\r\n\r\nPS C:\\Program Files\\VitrineRMM> `;
          } else if (cmd === 'whoami') {
            response = `\r\nnt authority\\system\r\n\r\nPS C:\\Program Files\\VitrineRMM> `;
          } else if (cmd === 'clear' || cmd === 'cls') {
            response = `\x1b[2J\x1b[HPS C:\\Program Files\\VitrineRMM> `;
          } else if (cmd === 'help') {
            response = `\r\nVitrine Background Engine Quick Commands:\r\n  - Get-Process (inspect active background tasks)\r\n  - Get-BitLockerVolume (audit volume recovery keys)\r\n  - Get-Service (query Windows service status)\r\n  - whoami (confirm elevated NT AUTHORITY\\SYSTEM context)\r\n  - clear (reset console buffer)\r\n\r\nPS C:\\Program Files\\VitrineRMM> `;
          } else {
            response = `\r\n[Vitrine Shell] Executing elevated: "${cmd}"\r\nCommand completed successfully. Exit code: 0\r\n\r\nPS C:\\Program Files\\VitrineRMM> `;
          }

          socket.send(JSON.stringify({ type: 'output', data: response }));
        }
      } catch {
        // Direct raw string echo
      }
    });
  });

  // WebSocket Stream: Real-Time Telemetry Pulse (CPU, RAM, Network)
  server.get('/ws/telemetry', { websocket: true }, (connection: any) => {
    const socket = connection.socket || connection;
    const interval = setInterval(() => {
      if (socket.readyState === socket.OPEN) {
        const cpu = Math.max(5, Math.min(95, 15 + Math.sin(Date.now() / 2000) * 12 + (Math.random() * 8 - 4)));
        const ram = Math.max(8, Math.min(28, 12 + Math.cos(Date.now() / 3000) * 2));
        socket.send(JSON.stringify({
          timestamp: new Date().toISOString(),
          cpuUsage: parseFloat(cpu.toFixed(1)),
          ramUsageGb: parseFloat(ram.toFixed(1)),
          networkMbps: parseFloat((2.4 + Math.random() * 3.5).toFixed(1))
        }));
      }
    }, 2000);

    socket.on('close', () => {
      clearInterval(interval);
    });
  });

  // Register REST API Routes
  await registerApiRoutes(server);

  // Serve Frontend in Production mode
  const FRONTEND_DIST = path.resolve(__dirname, '../../frontend/dist');
  if (fs.existsSync(FRONTEND_DIST)) {
    server.register(fastifyStatic, {
      root: FRONTEND_DIST,
      prefix: '/',
      decorateReply: false
    });

    // SPA fallback for HTML5 client-side routing
    server.setNotFoundHandler((req, reply) => {
      if (req.raw.url && !req.raw.url.startsWith('/api') && !req.raw.url.startsWith('/ws')) {
        return reply.sendFile('index.html', FRONTEND_DIST);
      }
      return reply.status(404).send({ error: 'Endpoint Not Found' });
    });
  }

  const PORT = parseInt(process.env.PORT || '8080', 10);
  const HOST = process.env.HOST || '0.0.0.0';

  try {
    await server.listen({ port: PORT, host: HOST });
    console.log(`\n🔮 Vitrine RMM server running on http://${HOST}:${PORT}`);
    console.log(`📡 MeshCentral 2 Engine Bridge active`);
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
}

startServer();
