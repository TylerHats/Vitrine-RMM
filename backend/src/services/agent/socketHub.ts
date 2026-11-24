import crypto from 'crypto';
import type { FastifyRequest } from 'fastify';
import { db } from '../../db/index.js';
import { decryptVaultSecret } from '../vault/index.js';
import { processAgentCheckin, processAgentTaskResult } from './checkinProcessor.js';

interface ConnectedAgentSession {
  socket: any;
  deviceId: string;
  tenantId: string;
  variant: string;
  connectedAt: number;
  lastPongAt: number;
  pingTimer: ReturnType<typeof setInterval>;
}

interface PendingRpcWaiter {
  deviceId: string;
  resolve: (res: { live: boolean; exitCode: number; output: string } | null) => void;
  timer: ReturnType<typeof setTimeout>;
}

function constantTimeEquals(a: string, b: string): boolean {
  if (!a || !b) return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

class AgentSocketHub {
  private sessions = new Map<string, ConnectedAgentSession>();
  private pendingRpc = new Map<string, PendingRpcWaiter>();

  public getConnectedCount(): number {
    return this.sessions.size;
  }

  public isConnected(deviceId: string): boolean {
    const sess = this.sessions.get(deviceId);
    return Boolean(sess && sess.socket && sess.socket.readyState === 1);
  }

  private resolveClientIp(req: FastifyRequest): string {
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string' && xff.trim()) {
      return xff.split(',')[0].trim();
    }
    return req.ip || '127.0.0.1';
  }

  private authenticateToken(
    token: string,
    deviceIdHint?: string
  ):
    | { kind: 'device'; device: any }
    | { kind: 'tombstone'; lapsAccountName?: string; lapsAction?: string }
    | null {
    if (!token) return null;

    if (deviceIdHint) {
      const candidate = db
        .prepare("SELECT * FROM devices WHERE id = ? AND COALESCE(lifecycle_state, 'active') != 'archived'")
        .get(deviceIdHint) as any;
      if (candidate?.agent_auth_token) {
        const plain = decryptVaultSecret(candidate.agent_auth_token);
        if (plain && constantTimeEquals(plain, token)) {
          return { kind: 'device', device: candidate };
        }
      }
    }

    const candidates = db
      .prepare("SELECT * FROM devices WHERE agent_auth_token IS NOT NULL AND COALESCE(lifecycle_state, 'active') != 'archived'")
      .all() as any[];
    for (const dev of candidates) {
      const plain = decryptVaultSecret(dev.agent_auth_token);
      if (plain && constantTimeEquals(plain, token)) {
        return { kind: 'device', device: dev };
      }
    }

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    try {
      const tomb = db
        .prepare('SELECT laps_account_name, laps_action FROM deleted_tenant_device_tombstones WHERE agent_token_hash = ? LIMIT 1')
        .get(tokenHash) as { laps_account_name?: string; laps_action?: string } | undefined;
      if (tomb) {
        return {
          kind: 'tombstone',
          lapsAccountName: tomb.laps_account_name,
          lapsAction: tomb.laps_action
        };
      }
    } catch {}

    return null;
  }

  private sendJson(socket: any, payload: any): boolean {
    if (!socket || socket.readyState !== 1) return false;
    try {
      socket.send(JSON.stringify(payload));
      return true;
    } catch {
      return false;
    }
  }

  private flushPendingForDevice(deviceId: string): void {
    const sess = this.sessions.get(deviceId);
    if (!sess || sess.socket.readyState !== 1) return;

    try {
      const pendingTasks = db
        .prepare("SELECT * FROM agent_tasks WHERE device_id = ? AND status = 'queued' ORDER BY created_at ASC LIMIT 20")
        .all(deviceId) as any[];
      for (const task of pendingTasks) {
        this.dispatchTaskIfConnected(deviceId, task);
      }

      const unreadChats = db
        .prepare(
          "SELECT id, sender, message, created_at FROM chat_messages WHERE device_id = ? AND sender_role = 'technician' AND read_status = 0 ORDER BY created_at ASC LIMIT 10"
        )
        .all(deviceId) as any[];
      if (unreadChats.length > 0) {
        for (const ch of unreadChats) {
          this.sendJson(sess.socket, {
            type: 'chat',
            id: ch.id,
            sender: ch.sender || 'IT Support',
            message: ch.message || ''
          });
        }
        db.prepare(
          "UPDATE chat_messages SET read_status = 1 WHERE device_id = ? AND sender_role = 'technician' AND read_status = 0"
        ).run(deviceId);
      }
    } catch {}
  }

  public handleConnection(socket: any, req: FastifyRequest): void {
    const query = (req.query || {}) as Record<string, string>;
    const headerTok = String(req.headers['x-vitrine-agent-token'] || '').trim();
    const token = headerTok || String(query.token || '').trim();
    const deviceIdHint = String(req.headers['x-vitrine-device-id'] || query.deviceId || '').trim();

    const auth = this.authenticateToken(token, deviceIdHint || undefined);
    if (!auth) {
      this.sendJson(socket, { type: 'error', code: 'UNAUTHORIZED', message: 'Invalid or revoked agent token' });
      try {
        socket.close(1008, 'Unauthorized');
      } catch {}
      return;
    }

    if (auth.kind === 'tombstone') {
      this.sendJson(socket, {
        type: 'task',
        task: {
          id: `tomb-${crypto.randomUUID().slice(0, 8)}`,
          type: 'self_uninstall',
          task_type: 'self_uninstall',
          payload: {
            reason: 'Tenant or endpoint archived in Vitrine RMM',
            lapsAccountName: auth.lapsAccountName || '',
            lapsAction: auth.lapsAction || 'keep_account'
          }
        }
      });
      setTimeout(() => {
        try {
          socket.close(4010, 'Decommissioned');
        } catch {}
      }, 1500);
      return;
    }

    const dev = auth.device;
    const prev = this.sessions.get(dev.id);
    if (prev) {
      clearInterval(prev.pingTimer);
      try {
        prev.socket.close(4001, 'Replaced by newer agent session');
      } catch {}
    }

    const clientIp = this.resolveClientIp(req);
    const variant = String(query.variant || dev.agent_binary_variant || '').trim();

    const session: ConnectedAgentSession = {
      socket,
      deviceId: dev.id,
      tenantId: dev.tenant_id,
      variant,
      connectedAt: Date.now(),
      lastPongAt: Date.now(),
      pingTimer: setInterval(() => {
        const cur = this.sessions.get(dev.id);
        if (!cur || cur !== session) {
          clearInterval(session.pingTimer);
          return;
        }
        if (Date.now() - session.lastPongAt > 70_000 || socket.readyState !== 1) {
          try {
            socket.terminate ? socket.terminate() : socket.close(4000, 'Heartbeat timeout');
          } catch {}
          return;
        }
        try {
          if (typeof socket.ping === 'function') socket.ping();
        } catch {}
        this.sendJson(socket, { type: 'ping', ts: Date.now() });
      }, 25_000)
    };
    if (typeof session.pingTimer.unref === 'function') session.pingTimer.unref();

    this.sessions.set(dev.id, session);

    try {
      db.prepare(
        `UPDATE devices
         SET ws_connected = 1,
             agent_transport = 'wss',
             agent_binary_variant = COALESCE(NULLIF(?, ''), agent_binary_variant),
             status = CASE WHEN quarantined = 1 THEN 'isolated' ELSE 'online' END,
             last_seen = CURRENT_TIMESTAMP
         WHERE id = ?`
      ).run(variant, dev.id);
    } catch {}

    if (typeof socket.on === 'function') {
      socket.on('pong', () => {
        session.lastPongAt = Date.now();
      });

      socket.on('message', (raw: Buffer | string) => {
        session.lastPongAt = Date.now();
        let msg: any;
        try {
          msg = JSON.parse(typeof raw === 'string' ? raw : raw.toString('utf8'));
        } catch {
          return;
        }
        if (!msg || typeof msg !== 'object') return;
        const msgType = String(msg.type || '');

        if (msgType === 'pong') {
          session.lastPongAt = Date.now();
          return;
        }

        if (msgType === 'ping') {
          this.sendJson(socket, { type: 'pong', ts: msg.ts || Date.now() });
          return;
        }

        if (msgType === 'hello') {
          const nextVariant = String(msg.variant || msg.agentVariant || '').trim();
          if (nextVariant) {
            session.variant = nextVariant;
            try {
              db.prepare('UPDATE devices SET agent_binary_variant = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?').run(
                nextVariant,
                dev.id
              );
            } catch {}
          }
          return;
        }

        if (msgType === 'telemetry' || msgType === 'checkin') {
          const freshDev = db.prepare('SELECT * FROM devices WHERE id = ?').get(dev.id) as any;
          if (!freshDev) return;
          const payload = (msg.payload && typeof msg.payload === 'object' ? msg.payload : msg) as any;
          if (session.variant && !payload.agentVariant) {
            payload.agentVariant = session.variant;
          }
          const result = processAgentCheckin(freshDev, payload, clientIp, 'wss');
          this.sendJson(socket, {
            type: 'checkin_ack',
            ...result
          });
          return;
        }

        if (msgType === 'task_result') {
          const taskId = String(msg.taskId || '').trim();
          if (taskId) {
            const taskRow = db
              .prepare('SELECT * FROM agent_tasks WHERE id = ? AND device_id = ?')
              .get(taskId, dev.id) as any;
            if (taskRow) {
              processAgentTaskResult(taskRow, {
                exitCode: Number(msg.exitCode ?? 0),
                stdout: typeof msg.stdout === 'string' ? msg.stdout : '',
                stderr: typeof msg.stderr === 'string' ? msg.stderr : '',
                durationMs: typeof msg.durationMs === 'number' ? msg.durationMs : undefined
              });
            }
          }
          return;
        }

        if (msgType === 'rpc_response') {
          const reqId = String(msg.reqId || '').trim();
          const waiter = this.pendingRpc.get(reqId);
          if (waiter && waiter.deviceId === dev.id) {
            clearTimeout(waiter.timer);
            this.pendingRpc.delete(reqId);
            const stdout = typeof msg.stdout === 'string' ? msg.stdout : '';
            const stderr = typeof msg.stderr === 'string' ? msg.stderr : '';
            const combined = [stdout, stderr].filter(Boolean).join('\n').trim();
            waiter.resolve({
              live: true,
              exitCode: Number(msg.exitCode ?? 0),
              output: combined || String(msg.output || '')
            });
          }
          return;
        }

        if (msgType === 'chat') {
          const text = String(msg.message || '').trim().slice(0, 2000);
          const sender = String(msg.sender || 'Desktop User').trim().slice(0, 64) || 'Desktop User';
          if (text) {
            try {
              db.prepare(
                `INSERT INTO chat_messages (id, device_id, sender, sender_role, message, read_status)
                 VALUES (?, ?, ?, 'end_user', ?, 1)`
              ).run(`chat-${crypto.randomUUID().slice(0, 8)}`, dev.id, sender, text);
            } catch {}
          }
          return;
        }
      });

      const cleanup = () => {
        clearInterval(session.pingTimer);
        if (this.sessions.get(dev.id) === session) {
          this.sessions.delete(dev.id);
          try {
            db.prepare('UPDATE devices SET ws_connected = 0 WHERE id = ?').run(dev.id);
          } catch {}
        }
        for (const [reqId, w] of this.pendingRpc.entries()) {
          if (w.deviceId === dev.id) {
            clearTimeout(w.timer);
            this.pendingRpc.delete(reqId);
            w.resolve(null);
          }
        }
      };

      socket.on('close', cleanup);
      socket.on('error', cleanup);
    }

    this.sendJson(socket, {
      type: 'welcome',
      deviceId: dev.id,
      serverTime: new Date().toISOString(),
      heartbeatSec: 25
    });
    this.flushPendingForDevice(dev.id);
  }

  public dispatchTaskIfConnected(
    deviceId: string,
    task: { id: string; task_type: string; payload_json?: string; payload?: any }
  ): boolean {
    const sess = this.sessions.get(deviceId);
    if (!sess || sess.socket.readyState !== 1) return false;

    let payload = task.payload;
    if (!payload && task.payload_json) {
      try {
        payload = JSON.parse(task.payload_json);
      } catch {
        payload = {};
      }
    }

    const sent = this.sendJson(sess.socket, {
      type: 'task',
      task: {
        id: task.id,
        type: task.task_type,
        task_type: task.task_type,
        payload: payload || {}
      }
    });
    if (sent) {
      try {
        db.prepare("UPDATE agent_tasks SET status = 'dispatched', dispatched_at = CURRENT_TIMESTAMP WHERE id = ? AND status IN ('queued', 'pending')").run(
          task.id
        );
      } catch {}
    }
    return sent;
  }

  public pushChatIfConnected(
    deviceId: string,
    chat: { id?: string; sender: string; message: string }
  ): boolean {
    const sess = this.sessions.get(deviceId);
    if (!sess || sess.socket.readyState !== 1) return false;
    return this.sendJson(sess.socket, {
      type: 'chat',
      id: chat.id || `chat-${crypto.randomUUID().slice(0, 8)}`,
      sender: chat.sender || 'IT Support',
      message: chat.message
    });
  }

  public executeRpcCommand(
    deviceId: string,
    opts: { command: string; shell?: string; timeoutMs?: number }
  ): Promise<{ live: boolean; exitCode: number; output: string } | null> {
    const sess = this.sessions.get(deviceId);
    if (!sess || sess.socket.readyState !== 1) {
      return Promise.resolve(null);
    }

    const reqId = `rpc-${crypto.randomUUID()}`;
    const timeoutMs = Math.max(2000, Math.min(180_000, opts.timeoutMs || 15_000));

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pendingRpc.delete(reqId);
        resolve(null);
      }, timeoutMs);

      this.pendingRpc.set(reqId, { deviceId, resolve, timer });
      const sent = this.sendJson(sess.socket, {
        type: 'rpc_exec',
        reqId,
        command: opts.command,
        shell: opts.shell || 'bash',
        timeoutSec: Math.ceil(timeoutMs / 1000)
      });
      if (!sent) {
        clearTimeout(timer);
        this.pendingRpc.delete(reqId);
        resolve(null);
      }
    });
  }

  public shutdown(): void {
    for (const [devId, sess] of this.sessions.entries()) {
      clearInterval(sess.pingTimer);
      try {
        sess.socket.close(1001, 'Server shutting down');
      } catch {}
      try {
        db.prepare('UPDATE devices SET ws_connected = 0 WHERE id = ?').run(devId);
      } catch {}
    }
    this.sessions.clear();
    for (const [reqId, w] of this.pendingRpc.entries()) {
      clearTimeout(w.timer);
      this.pendingRpc.delete(reqId);
      w.resolve(null);
    }
  }
}

export const agentSocketHub = new AgentSocketHub();
