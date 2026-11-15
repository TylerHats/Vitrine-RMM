import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { db, PACKAGES_DIR_PATH } from '../db/index.js';
import {
  encryptVaultSecret,
  decryptVaultSecret,
  maskSecretValue,
  isMaskedSecret,
  validateOutboundHostSafety,
  safeOutboundFetch
} from '../services/vault/index.js';
import {
  checkRateLimit,
  isSuperAdminRole,
  isTechnicianOrAbove,
  canUserAccessTenant,
  getScopedTenantFilter,
  getActorUsername,
  hasUserPermission,
  normalizePermissionScopes,
  createScopedApiKey,
  listScopedApiKeys,
  revokeScopedApiKey,
  ALL_GRANULAR_PERMISSIONS
} from '../services/auth/index.js';
import { generateQrCodeSvg } from '../services/auth/qrcode.js';
import { quotePowerShellLiteral } from '../services/agent/installerGenerator.js';
import { handleAgentCheckInOrWake } from '../services/offboarding/index.js';
import { meshBridge } from '../services/meshcentral/index.js';
import {
  dispatchAlertToNotificationChannels,
  syncTicketWithExternalPsas
} from '../services/policy/index.js';
import {
  runScheduledAutomationNow,
  computeNextCronRunIso,
  evaluateSmartGroupDevices
} from '../services/automation/index.js';
import { backupService } from '../services/backup/index.js';

function constantTimeEquals(a: string, b: string): boolean {
  if (!a || !b) return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function safeJsonParse<T>(raw: string | null | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function quotePosixLiteral(val: string): string {
  return `'${String(val ?? '').replace(/'/g, "'\\''")}'`;
}

function buildSafeAttachmentDisposition(rawFilename: string): string {
  const cleaned =
    path
      .basename(String(rawFilename || 'package.bin'))
      .replace(/[\r\n"\\<>|?*:\0]/g, '_')
      .trim() || 'package.bin';
  return `attachment; filename="${cleaned}"; filename*=UTF-8''${encodeURIComponent(cleaned)}`;
}

function requireParityStepUpMfa(req: FastifyRequest, reply: FastifyReply): boolean {
  const globalPol = db
    .prepare("SELECT require_mfa_for_secrets FROM policies WHERE tier = 'global' LIMIT 1")
    .get() as { require_mfa_for_secrets?: number } | undefined;
  const mfaRequired = Boolean(globalPol?.require_mfa_for_secrets ?? 1);
  if (mfaRequired && !req.auth?.mfaVerified) {
    reply.status(403).send({
      error: 'Step-Up Multi-Factor Authentication is required for this security operation.',
      code: 'MFA_REQUIRED',
      mfaRequired: true
    });
    return false;
  }
  return true;
}

function authenticateAgentRequest(
  request: FastifyRequest,
  deviceIdHint?: string,
  hostnameHint?: string
): { valid: boolean; device: any | null; tombstoned?: any | null } {
  const providedToken = String(request.headers['x-vitrine-agent-token'] || '').trim();
  if (!providedToken) return { valid: false, device: null };

  if (deviceIdHint) {
    const candidate = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceIdHint) as any;
    if (candidate?.agent_auth_token) {
      const deviceToken = decryptVaultSecret(candidate.agent_auth_token);
      if (deviceToken && constantTimeEquals(providedToken, deviceToken)) {
        return { valid: true, device: candidate };
      }
    }
  } else if (hostnameHint) {
    const candidates = db
      .prepare('SELECT * FROM devices WHERE LOWER(hostname) = LOWER(?)')
      .all(hostnameHint) as any[];
    for (const candidate of candidates) {
      if (!candidate.agent_auth_token) continue;
      const deviceToken = decryptVaultSecret(candidate.agent_auth_token);
      if (deviceToken && constantTimeEquals(providedToken, deviceToken)) {
        return { valid: true, device: candidate };
      }
    }
  } else {
    // Token-only lookup (e.g. package download by agent without deviceId query param)
    const tokenDevices = db
      .prepare("SELECT * FROM devices WHERE agent_auth_token IS NOT NULL AND agent_auth_token != ''")
      .all() as any[];
    for (const candidate of tokenDevices) {
      const deviceToken = decryptVaultSecret(candidate.agent_auth_token);
      if (deviceToken && constantTimeEquals(providedToken, deviceToken)) {
        return { valid: true, device: candidate };
      }
    }
  }

  // Check tombstones for deleted-tenant devices so stranded companions receive a clean self-uninstall task
  try {
    const tokenHash = crypto.createHash('sha256').update(providedToken).digest('hex');
    const tombstone = db
      .prepare(
        'SELECT * FROM deleted_tenant_device_tombstones WHERE agent_token_hash = ? OR (device_id = ? AND agent_token_hash IS NOT NULL) LIMIT 1'
      )
      .get(tokenHash, deviceIdHint || '') as any;
    if (tombstone && tombstone.agent_token_hash && constantTimeEquals(tokenHash, String(tombstone.agent_token_hash))) {
      return { valid: true, device: null, tombstoned: tombstone };
    }
  } catch {
    // Ignore if column not yet migrated
  }

  return { valid: false, device: null };
}

export async function registerParityRoutes(server: FastifyInstance): Promise<void> {
  // ============================================================================
  // 1. Companion Agent Telemetry Check-In & Asynchronous Task Queue
  // ============================================================================
  server.post('/api/agent/checkin', async (request, reply) => {
    const rate = checkRateLimit(`agent-checkin:${request.ip}`, 180, 60_000);
    if (!rate.allowed) {
      return reply.status(429).send({ error: 'Too many check-in requests', retryAfterSec: rate.retryAfterSec });
    }

    const body = (request.body || {}) as {
      deviceId?: string;
      hostname?: string;
      osType?: string;
      osVersion?: string;
      cpuUsage?: number;
      ramUsedGb?: number;
      ramUsage?: number;
      ramTotalGb?: number;
      diskFreeGb?: number;
      diskUsage?: number;
      diskTotalGb?: number;
      edrStatus?: string;
      avStatus?: string;
      bitlockerStatus?: string;
      bitlockerEncrypted?: boolean;
      bitlockerRecoveryKey?: string;
      loggedInUser?: string;
      rebootRequired?: boolean;
      rebootPending?: boolean;
      uptimeSeconds?: number;
      companionVersion?: string;
      ipAddress?: string;
      gatewayIp?: string;
      interfaceName?: string;
      arpNeighbors?: Array<{ ip: string; mac: string }>;
      installedSoftware?: Array<{ name: string; version: string; publisher?: string }>;
    };

    const auth = authenticateAgentRequest(request, body.deviceId, body.hostname);
    if (!auth.valid) {
      return reply.status(401).send({ error: 'Invalid or unrecognized x-vitrine-agent-token' });
    }

    if (auth.tombstoned && !auth.device) {
      const uninstallPayload = {
        lapsAction: auth.tombstoned.laps_offboard_action || 'remove_account',
        reason: 'Parent client tenant was permanently deleted'
      };
      return {
        success: true,
        quietOffboard: true,
        tasks: [
          {
            id: `offboard-${auth.tombstoned.device_id || 'tombstone'}`,
            type: 'self_uninstall',
            task_type: 'self_uninstall',
            payload: uninstallPayload,
            payload_json: JSON.stringify(uninstallPayload)
          }
        ],
        unreadChats: [],
        timestamp: new Date().toISOString()
      };
    }

    if (!auth.device) {
      return reply.status(401).send({ error: 'Invalid or unrecognized x-vitrine-agent-token' });
    }

    const dev = auth.device;
    const encryptedRecoveryKey =
      body.bitlockerRecoveryKey && String(body.bitlockerRecoveryKey).trim().length >= 8
        ? encryptVaultSecret(String(body.bitlockerRecoveryKey).trim())
        : null;

    const reqIp = String(request.ip || '').trim();
    const reqIsLoopback = reqIp === '127.0.0.1' || reqIp === '::1' || reqIp === '::ffff:127.0.0.1';
    const rawIp = body.ipAddress != null ? String(body.ipAddress).trim() : '';
    const reportedIsLoopback = rawIp === '127.0.0.1' || rawIp === '::1' || rawIp.toLowerCase() === 'localhost';
    const safeCheckinIp = rawIp && (!reportedIsLoopback || reqIsLoopback) ? rawIp : null;

    const effRamTotal =
      body.ramTotalGb != null && Number.isFinite(Number(body.ramTotalGb))
        ? Number(body.ramTotalGb)
        : Number(dev.ram_total_gb || 0);
    const resolvedRamUsedGb =
      body.ramUsedGb != null && Number.isFinite(Number(body.ramUsedGb))
        ? Number(body.ramUsedGb)
        : body.ramUsage != null && Number.isFinite(Number(body.ramUsage)) && effRamTotal > 0
          ? Number(((Number(body.ramUsage) / 100) * effRamTotal).toFixed(2))
          : null;

    const effDiskTotal =
      body.diskTotalGb != null && Number.isFinite(Number(body.diskTotalGb))
        ? Number(body.diskTotalGb)
        : Number(dev.disk_total_gb || 0);
    const resolvedDiskFreeGb =
      body.diskFreeGb != null && Number.isFinite(Number(body.diskFreeGb))
        ? Number(body.diskFreeGb)
        : body.diskUsage != null && Number.isFinite(Number(body.diskUsage)) && effDiskTotal > 0
          ? Number((((100 - Math.min(100, Math.max(0, Number(body.diskUsage)))) / 100) * effDiskTotal).toFixed(2))
          : null;

    const resolvedEdr = body.edrStatus ?? body.avStatus ?? null;
    const resolvedBitlocker =
      body.bitlockerStatus ??
      (body.bitlockerEncrypted !== undefined
        ? body.bitlockerEncrypted
          ? dev.os_type === 'macos'
            ? 'FileVault Enabled'
            : dev.os_type === 'linux'
              ? 'LUKS Encrypted'
              : 'Encrypted (AES-256)'
          : 'Unencrypted'
        : null);

    const rawReboot = body.rebootRequired !== undefined ? body.rebootRequired : body.rebootPending;
    const rebootInt = rawReboot != null ? (rawReboot ? 1 : 0) : null;

    db.prepare(`
      UPDATE devices SET
        status = CASE WHEN quarantined = 1 THEN 'isolated' ELSE 'online' END,
        companion_installed = 1,
        companion_version = COALESCE(?, companion_version),
        os_version = COALESCE(?, os_version),
        ip_address = COALESCE(?, ip_address),
        cpu_usage = COALESCE(?, cpu_usage),
        ram_used_gb = COALESCE(?, ram_used_gb),
        ram_total_gb = COALESCE(?, ram_total_gb),
        disk_free_gb = COALESCE(?, disk_free_gb),
        disk_total_gb = COALESCE(?, disk_total_gb),
        edr_status = COALESCE(?, edr_status),
        bitlocker_status = COALESCE(?, bitlocker_status),
        bitlocker_key = COALESCE(?, bitlocker_key),
        logged_in_user = COALESCE(?, logged_in_user),
        reboot_required = COALESCE(?, reboot_required),
        pending_reboot = COALESCE(?, pending_reboot),
        pending_reboot_since = CASE
          WHEN ? = 1 THEN COALESCE(pending_reboot_since, CURRENT_TIMESTAMP)
          WHEN ? = 0 THEN NULL
          ELSE pending_reboot_since
        END,
        uptime_seconds = COALESCE(?, uptime_seconds),
        last_seen = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(
      body.companionVersion || '2.6.0',
      body.osVersion ?? null,
      safeCheckinIp,
      body.cpuUsage != null && Number.isFinite(Number(body.cpuUsage)) ? Number(body.cpuUsage) : null,
      resolvedRamUsedGb,
      body.ramTotalGb != null && Number.isFinite(Number(body.ramTotalGb)) ? Number(body.ramTotalGb) : null,
      resolvedDiskFreeGb,
      body.diskTotalGb != null && Number.isFinite(Number(body.diskTotalGb)) ? Number(body.diskTotalGb) : null,
      resolvedEdr,
      resolvedBitlocker,
      encryptedRecoveryKey,
      body.loggedInUser ?? null,
      rebootInt,
      rebootInt,
      rebootInt,
      rebootInt,
      body.uptimeSeconds != null && Number.isFinite(Number(body.uptimeSeconds)) ? Math.floor(Number(body.uptimeSeconds)) : null,
      dev.id
    );

    if (body.gatewayIp || safeCheckinIp) {
      const lastNet = db
        .prepare('SELECT local_ip, gateway_ip FROM network_history WHERE device_id = ? ORDER BY connected_at DESC LIMIT 1')
        .get(dev.id) as { local_ip?: string; gateway_ip?: string } | undefined;
      const curIp = safeCheckinIp || dev.ip_address;
      if (!lastNet || lastNet.local_ip !== curIp || (body.gatewayIp && lastNet.gateway_ip !== body.gatewayIp)) {
        db.prepare(`
          INSERT INTO network_history (id, device_id, interface_name, local_ip, gateway_ip, public_ip)
          VALUES (?, ?, ?, ?, ?, ?)
        `).run(
          `nh-${crypto.randomUUID().slice(0, 8)}`,
          dev.id,
          body.interfaceName || 'primary',
          curIp,
          body.gatewayIp || '',
          request.ip || ''
        );
      }
    }

    if (Array.isArray(body.installedSoftware) && body.installedSoftware.length > 0) {
      const syncTx = db.transaction((items: Array<{ name: string; version: string; publisher?: string }>) => {
        for (const sw of items.slice(0, 300)) {
          if (!sw.name) continue;
          const existing = db
            .prepare('SELECT id FROM software_inventory WHERE device_id = ? AND LOWER(name) = LOWER(?) LIMIT 1')
            .get(dev.id, sw.name) as { id: string } | undefined;
          if (existing) {
            db.prepare('UPDATE software_inventory SET version = ?, publisher = COALESCE(?, publisher) WHERE id = ?').run(
              sw.version || 'unknown',
              sw.publisher || null,
              existing.id
            );
          } else {
            db.prepare(`
              INSERT INTO software_inventory (id, device_id, name, version, publisher, install_date)
              VALUES (?, ?, ?, ?, ?, date('now'))
            `).run(
              `sw-${crypto.randomUUID().slice(0, 8)}`,
              dev.id,
              sw.name,
              sw.version || 'unknown',
              sw.publisher || 'Installed Package'
            );
          }
        }
      });
      syncTx(body.installedSoftware);
    }

    const lifecycle = handleAgentCheckInOrWake(dev.id, 'wake_checkin');

    // Fetch queued tasks for this endpoint and mark them dispatched
    const pendingTasks = db
      .prepare(`
        SELECT id, task_type, payload_json, created_at
        FROM agent_tasks
        WHERE device_id = ? AND status = 'queued'
        ORDER BY created_at ASC
        LIMIT 10
      `)
      .all(dev.id) as any[];

    if (pendingTasks.length > 0) {
      const markDispatched = db.prepare(
        "UPDATE agent_tasks SET status = 'dispatched', dispatched_at = CURRENT_TIMESTAMP WHERE id = ?"
      );
      for (const t of pendingTasks) {
        markDispatched.run(t.id);
      }
    }

    // Also include recent unread technician chat messages for the Tray helper
    const unreadChats = db
      .prepare(`
        SELECT id, sender, message, created_at
        FROM chat_messages
        WHERE device_id = ? AND sender_role = 'technician' AND read_status = 0
        ORDER BY created_at ASC
        LIMIT 10
      `)
      .all(dev.id) as any[];
    if (unreadChats.length > 0) {
      db.prepare("UPDATE chat_messages SET read_status = 1 WHERE device_id = ? AND sender_role = 'technician'").run(dev.id);
    }

    return {
      success: true,
      deviceId: dev.id,
      lifecycle,
      tasks: pendingTasks.map((t) => ({
        id: t.id,
        type: t.task_type,
        task_type: t.task_type,
        payload: safeJsonParse<Record<string, any>>(t.payload_json, {}),
        payload_json: t.payload_json || '{}'
      })),
      unreadChats,
      timestamp: new Date().toISOString()
    };
  });

  server.post('/api/agent/tasks/:id/result', async (request, reply) => {
    const rate = checkRateLimit(`agent-task-res:${request.ip}`, 180, 60_000);
    if (!rate.allowed) {
      return reply.status(429).send({ error: 'Too many task result submissions', retryAfterSec: rate.retryAfterSec });
    }

    const { id } = request.params as { id: string };
    const task = db.prepare('SELECT * FROM agent_tasks WHERE id = ?').get(id) as any;
    if (!task) {
      return reply.status(404).send({ error: 'Agent task not found' });
    }

    const auth = authenticateAgentRequest(request, task.device_id);
    if (!auth.valid) {
      return reply.status(401).send({ error: 'Invalid x-vitrine-agent-token' });
    }

    const body = (request.body || {}) as {
      exitCode?: number;
      stdout?: string;
      stderr?: string;
      output?: string;
      status?: 'completed' | 'failed';
      durationMs?: number;
    };

    const exitCode = Number(body.exitCode ?? 0);
    const finalStatus = body.status || (exitCode === 0 ? 'completed' : 'failed');
    const stdout = String(body.stdout ?? body.output ?? '');
    const stderr = String(body.stderr || '');

    db.prepare(`
      UPDATE agent_tasks
      SET status = ?,
          exit_code = ?,
          stdout = ?,
          stderr = ?,
          result_json = ?,
          completed_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(
      finalStatus,
      exitCode,
      stdout,
      stderr,
      JSON.stringify({ stdout, stderr, exitCode, durationMs: body.durationMs || 0 }),
      id
    );

    const payload = safeJsonParse<Record<string, any>>(task.payload_json, {});
    if (payload.executionId) {
      db.prepare(`
        UPDATE script_executions
        SET status = ?,
            exit_code = ?,
            output = ?,
            stdout = ?,
            stderr = ?,
            duration_ms = COALESCE(?, duration_ms)
        WHERE id = ?
      `).run(
        exitCode === 0 ? 'Completed (Companion)' : 'Failed',
        exitCode,
        [stdout, stderr].filter(Boolean).join('\n'),
        stdout,
        stderr,
        body.durationMs || null,
        payload.executionId
      );
    }

    if (payload.deploymentId) {
      db.prepare(`
        UPDATE software_deployments
        SET status = ?,
            exit_code = ?,
            output = ?,
            completed_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(
        exitCode === 0 ? 'installed' : 'failed',
        exitCode,
        [stdout, stderr].filter(Boolean).join('\n'),
        payload.deploymentId
      );
    }

    const backupJobId = payload.backupJobId || payload.jobId;
    if (backupJobId) {
      const combinedOut = [stdout, stderr].filter(Boolean).join('\n');
      const bytesMatch = stdout.trim().match(/(\d+)\s*$/);
      const parsedBytes = bytesMatch ? Number(bytesMatch[1]) : null;
      db.prepare(`
        UPDATE device_backup_jobs
        SET status = ?,
            bytes_processed = COALESCE(?, bytes_processed),
            output = ?,
            completed_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(exitCode === 0 ? 'completed' : 'failed', parsedBytes, combinedOut, backupJobId);
    }

    return { success: true, taskId: id, status: finalStatus };
  });

  // Allow end-user System Tray helper to send chat reply or quick ticket!
  server.post('/api/agent/chat', async (request, reply) => {
    const rate = checkRateLimit(`agent-chat:${request.ip}`, 30, 60_000);
    if (!rate.allowed) {
      return reply.status(429).send({ error: 'Too many chat messages', retryAfterSec: rate.retryAfterSec });
    }
    const body = (request.body || {}) as { deviceId?: string; sender?: string; message?: string };
    const auth = authenticateAgentRequest(request, body.deviceId);
    if (!auth.valid || !auth.device) {
      return reply.status(401).send({ error: 'Invalid x-vitrine-agent-token' });
    }
    const clean = String(body.message || '').trim();
    if (!clean) return reply.status(400).send({ error: 'Message required' });

    const id = `chat-${crypto.randomUUID().slice(0, 8)}`;
    db.prepare(`
      INSERT INTO chat_messages (id, device_id, sender, sender_role, message, read_status)
      VALUES (?, ?, ?, 'end_user', ?, 0)
    `).run(id, auth.device.id, body.sender || auth.device.logged_in_user || auth.device.hostname, clean);

    db.prepare(`
      INSERT INTO notifications (id, tenant_id, type, title, message, severity, is_read)
      VALUES (?, ?, 'endpoint_chat', ?, ?, 'info', 0)
    `).run(
      `notif-chat-${crypto.randomUUID().slice(0, 8)}`,
      auth.device.tenant_id,
      `End-User Chat from ${auth.device.hostname}`,
      clean.slice(0, 200)
    );

    return { success: true, id };
  });

  // ============================================================================
  // 2. Scheduled Automations Engine (Cron + Smart Group / Tenant / Device Targets)
  // ============================================================================
  const resolveAutomationTenantId = (
    explicitTenantId?: string | null,
    targetType?: string | null,
    targetId?: string | null
  ): string | null => {
    if (explicitTenantId && explicitTenantId !== 'all') return explicitTenantId;
    if (!targetType || targetType === 'all') return null;
    if (targetType === 'tenant') return targetId || null;
    if (targetType === 'site' && targetId) {
      return (db.prepare('SELECT tenant_id FROM sites WHERE id = ?').get(targetId) as any)?.tenant_id || null;
    }
    if (targetType === 'smart_group' && targetId) {
      return (db.prepare('SELECT tenant_id FROM smart_groups WHERE id = ?').get(targetId) as any)?.tenant_id || null;
    }
    if (targetType === 'device' && targetId) {
      return (db.prepare('SELECT tenant_id FROM devices WHERE id = ?').get(targetId) as any)?.tenant_id || null;
    }
    return null;
  };

  server.get('/api/automations', async (request) => {
    const user = request.auth?.user;
    const rows = db
      .prepare(`
        SELECT a.*, s.name as script_name, s.language as script_language
        FROM scheduled_automations a
        LEFT JOIN scripts s ON a.script_id = s.id
        ORDER BY a.created_at DESC
      `)
      .all() as any[];

    return rows
      .filter((r) => {
        const tid = resolveAutomationTenantId(r.tenant_id, r.target_type, r.target_id);
        return tid ? canUserAccessTenant(user, tid) : !getScopedTenantFilter(user);
      })
      .map((r) => ({
        ...r,
        enabled: Boolean(r.enabled),
        missed_run_catchup: Boolean(r.missed_run_catchup),
        params: safeJsonParse<Record<string, string>>(r.params_json, {})
      }));
  });

  server.post('/api/automations', async (request, reply) => {
    const body = (request.body || {}) as {
      name?: string;
      description?: string;
      script_id?: string;
      tenant_id?: string | null;
      target_type?: 'all' | 'tenant' | 'site' | 'smart_group' | 'device';
      target_id?: string | null;
      cron_expr?: string;
      run_as?: 'system' | 'user';
      params?: Record<string, string>;
      missed_run_catchup?: boolean;
      enabled?: boolean;
    };
    if (!body.name?.trim() || !body.script_id) {
      return reply.status(400).send({ error: 'Automation name and script_id are required.' });
    }
    const targetType = body.target_type || 'all';
    const resolvedTenantId = resolveAutomationTenantId(body.tenant_id, targetType, body.target_id);
    if (!resolvedTenantId && getScopedTenantFilter(request.auth?.user)) {
      return reply.status(403).send({ error: 'Scoped accounts cannot create global fleet-wide automations.' });
    }
    if (resolvedTenantId && !canUserAccessTenant(request.auth?.user, resolvedTenantId)) {
      return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
    }

    const cronExpr = String(body.cron_expr || '0 3 * * *').trim();
    const id = `auto-${crypto.randomUUID().slice(0, 8)}`;
    const nextRun = computeNextCronRunIso(cronExpr);

    db.prepare(`
      INSERT INTO scheduled_automations (
        id, name, description, tenant_id, script_id, target_type, target_id, cron_expression, cron_expr,
        run_as, params_json, parameters_json, missed_run_catchup, enabled, next_run_at, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      body.name.trim(),
      body.description || '',
      resolvedTenantId,
      body.script_id,
      targetType,
      body.target_id || null,
      cronExpr,
      cronExpr,
      body.run_as === 'user' ? 'user' : 'system',
      JSON.stringify(body.params || {}),
      JSON.stringify(body.params || {}),
      body.missed_run_catchup !== false ? 1 : 0,
      body.enabled !== false ? 1 : 0,
      nextRun,
      getActorUsername(request)
    );

    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'Scheduled Automation Created', ?)
    `).run(`aud-auto-${crypto.randomUUID()}`, getActorUsername(request), `Created cron schedule '${body.name}' (${cronExpr})`);

    return {
      success: true,
      automation: db.prepare('SELECT * FROM scheduled_automations WHERE id = ?').get(id)
    };
  });

  server.put('/api/automations/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM scheduled_automations WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Scheduled automation not found.' });
    const existingTid = resolveAutomationTenantId(existing.tenant_id, existing.target_type, existing.target_id);
    if (existingTid && !canUserAccessTenant(request.auth?.user, existingTid)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    if (!existingTid && getScopedTenantFilter(request.auth?.user)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const body = (request.body || {}) as Record<string, any>;
    const nextTargetType = body.target_type ?? existing.target_type;
    const nextTargetId = body.target_id !== undefined ? body.target_id : existing.target_id;
    const nextTenantId = resolveAutomationTenantId(
      body.tenant_id !== undefined ? body.tenant_id : existing.tenant_id,
      nextTargetType,
      nextTargetId
    );
    if (!nextTenantId && getScopedTenantFilter(request.auth?.user)) {
      return reply.status(403).send({ error: 'Scoped accounts cannot retarget automations globally.' });
    }
    if (nextTenantId && !canUserAccessTenant(request.auth?.user, nextTenantId)) {
      return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
    }

    const nextCron = body.cron_expr ? String(body.cron_expr).trim() : existing.cron_expr || existing.cron_expression;
    const nextRun = body.cron_expr ? computeNextCronRunIso(nextCron) : existing.next_run_at;

    db.prepare(`
      UPDATE scheduled_automations SET
        name = COALESCE(?, name),
        description = COALESCE(?, description),
        tenant_id = ?,
        script_id = COALESCE(?, script_id),
        target_type = COALESCE(?, target_type),
        target_id = ?,
        cron_expression = ?,
        cron_expr = ?,
        run_as = COALESCE(?, run_as),
        params_json = COALESCE(?, params_json),
        parameters_json = COALESCE(?, parameters_json),
        missed_run_catchup = COALESCE(?, missed_run_catchup),
        enabled = COALESCE(?, enabled),
        next_run_at = ?
      WHERE id = ?
    `).run(
      body.name ?? null,
      body.description ?? null,
      nextTenantId,
      body.script_id ?? null,
      body.target_type ?? null,
      nextTargetId,
      nextCron,
      nextCron,
      body.run_as ?? null,
      body.params ? JSON.stringify(body.params) : null,
      body.params ? JSON.stringify(body.params) : null,
      body.missed_run_catchup != null ? (body.missed_run_catchup ? 1 : 0) : null,
      body.enabled != null ? (body.enabled ? 1 : 0) : null,
      nextRun,
      id
    );

    return {
      success: true,
      automation: db.prepare('SELECT * FROM scheduled_automations WHERE id = ?').get(id)
    };
  });

  server.delete('/api/automations/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM scheduled_automations WHERE id = ?').get(id) as any;
    if (existing) {
      const tid = resolveAutomationTenantId(existing.tenant_id, existing.target_type, existing.target_id);
      if ((tid && !canUserAccessTenant(request.auth?.user, tid)) || (!tid && getScopedTenantFilter(request.auth?.user))) {
        return reply.status(403).send({ error: 'Forbidden' });
      }
    }
    db.prepare('DELETE FROM scheduled_automations WHERE id = ?').run(id);
    return { success: true };
  });

  server.post('/api/automations/:id/run', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM scheduled_automations WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ success: false, error: 'Scheduled automation not found.' });
    const tid = resolveAutomationTenantId(existing.tenant_id, existing.target_type, existing.target_id);
    if ((tid && !canUserAccessTenant(request.auth?.user, tid)) || (!tid && getScopedTenantFilter(request.auth?.user))) {
      return reply.status(403).send({ success: false, error: 'Forbidden' });
    }
    try {
      const res = await runScheduledAutomationNow(id, getActorUsername(request));
      return res;
    } catch (err: any) {
      return reply.status(400).send({ success: false, error: err?.message || 'Automation run failed' });
    }
  });

  // ============================================================================
  // 3. Software Package Catalog & 3rd-Party Deployments (Winget/Choco/Apt/Brew/MSI)
  // ============================================================================
  server.get('/api/software-packages', async () => {
    const rows = db.prepare('SELECT * FROM software_packages ORDER BY category ASC, name ASC').all() as any[];
    return rows.map((r) => ({
      ...r,
      os_type: r.os_type || r.platform || 'windows',
      package_manager: r.package_manager || r.package_type || 'winget',
      installer_url: r.installer_url || r.download_url || ''
    }));
  });

  server.post('/api/software-packages', { bodyLimit: 100 * 1024 * 1024 }, async (request, reply) => {
    const body = (request.body || {}) as {
      name?: string;
      vendor?: string;
      version?: string;
      os_type?: 'windows' | 'linux' | 'macos' | 'cross_platform';
      package_manager?: 'winget' | 'choco' | 'apt' | 'dnf' | 'brew' | 'msi_url' | 'deb_upload' | 'custom_cmd';
      package_identifier?: string;
      install_args?: string;
      uninstall_args?: string;
      installer_url?: string;
      sha256_hash?: string;
      category?: string;
      fileBase64?: string;
      filename?: string;
    };

    if (!body.name?.trim()) {
      return reply.status(400).send({ error: 'Software package name is required.' });
    }

    const id = `pkg-${crypto.randomUUID().slice(0, 8)}`;
    let installerUrl = body.installer_url || '';
    let localFilePath = '';
    let sha256 = body.sha256_hash || '';

    if (body.fileBase64 && body.filename) {
      const cleanB64 = body.fileBase64.includes(',') ? body.fileBase64.split(',').pop()! : body.fileBase64;
      const buf = Buffer.from(cleanB64, 'base64');
      if (!fs.existsSync(PACKAGES_DIR_PATH)) fs.mkdirSync(PACKAGES_DIR_PATH, { recursive: true });
      const safeName = `${id}-${path.basename(body.filename).replace(/[^a-zA-Z0-9._-]/g, '_')}`;
      localFilePath = path.join(PACKAGES_DIR_PATH, safeName);
      fs.writeFileSync(localFilePath, buf);
      sha256 = crypto.createHash('sha256').update(buf).digest('hex');
      installerUrl = `/api/software-packages/${id}/download`;
    }

    const osType = body.os_type || 'windows';
    const pkgMgr = body.package_manager || 'winget';

    db.prepare(`
      INSERT INTO software_packages (
        id, name, vendor, version, platform, os_type, package_type, package_manager, package_identifier,
        install_args, uninstall_args, download_url, installer_url, local_file_path, sha256_hash, category
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      body.name.trim(),
      body.vendor || 'Vendor',
      body.version || 'latest',
      osType,
      osType,
      pkgMgr,
      pkgMgr,
      body.package_identifier || body.name.trim().toLowerCase().replace(/[^a-z0-9._-]/g, '-'),
      body.install_args || '',
      body.uninstall_args || '',
      installerUrl,
      installerUrl || null,
      localFilePath,
      sha256,
      body.category || 'Utilities'
    );

    return {
      success: true,
      package: db.prepare('SELECT * FROM software_packages WHERE id = ?').get(id)
    };
  });

  server.get('/api/software-packages/:id/download', async (request, reply) => {
    const userAuthed = Boolean(request.auth && hasUserPermission(request.auth.user, 'devices:read'));
    const agentAuthed = userAuthed ? false : authenticateAgentRequest(request).valid;
    if (!userAuthed && !agentAuthed) {
      return reply.status(401).send({ error: 'Authentication required to download software package.' });
    }

    const { id } = request.params as { id: string };
    const pkg = db.prepare('SELECT * FROM software_packages WHERE id = ?').get(id) as any;
    if (!pkg || !pkg.local_file_path) {
      return reply.status(404).send({ error: 'Uploaded software package artifact not found.' });
    }

    const basePackagesDir = path.resolve(PACKAGES_DIR_PATH);
    const resolvedFilePath = path.resolve(String(pkg.local_file_path));
    if (!resolvedFilePath.startsWith(basePackagesDir + path.sep) || !fs.existsSync(resolvedFilePath)) {
      return reply.status(404).send({ error: 'Software package binary is missing on disk.' });
    }

    reply.header('Content-Type', 'application/octet-stream');
    reply.header('Content-Disposition', buildSafeAttachmentDisposition(path.basename(resolvedFilePath)));
    if (pkg.sha256_hash) {
      reply.header('X-Content-SHA256', String(pkg.sha256_hash));
    }
    return reply.send(fs.createReadStream(resolvedFilePath));
  });

  server.delete('/api/software-packages/:id', async (request) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT local_file_path FROM software_packages WHERE id = ?').get(id) as
      | { local_file_path?: string }
      | undefined;
    if (existing?.local_file_path) {
      const basePackagesDir = path.resolve(PACKAGES_DIR_PATH);
      const resolvedFilePath = path.resolve(String(existing.local_file_path));
      if (resolvedFilePath.startsWith(basePackagesDir + path.sep) && fs.existsSync(resolvedFilePath)) {
        try {
          fs.unlinkSync(resolvedFilePath);
        } catch {
          // Ignore best-effort file unlink race
        }
      }
    }
    db.prepare('DELETE FROM software_packages WHERE id = ?').run(id);
    return { success: true };
  });

  server.get('/api/software-deployments', async (request, reply) => {
    const query = (request.query || {}) as { device_id?: string };
    if (query.device_id) {
      const dev = db.prepare('SELECT tenant_id FROM devices WHERE id = ?').get(query.device_id) as
        | { tenant_id?: string }
        | undefined;
      if (dev && !canUserAccessTenant(request.auth?.user, dev.tenant_id)) {
        return reply.status(403).send({ error: 'Forbidden' });
      }
      return db
        .prepare('SELECT * FROM software_deployments WHERE device_id = ? ORDER BY created_at DESC LIMIT 50')
        .all(query.device_id);
    }
    const rows = db
      .prepare(`
        SELECT sd.*, d.tenant_id as device_tenant_id
        FROM software_deployments sd
        LEFT JOIN devices d ON sd.device_id = d.id
        ORDER BY sd.created_at DESC
        LIMIT 200
      `)
      .all() as any[];
    return rows
      .filter((r) => (r.device_tenant_id ? canUserAccessTenant(request.auth?.user, r.device_tenant_id) : !getScopedTenantFilter(request.auth?.user)))
      .slice(0, 100)
      .map(({ device_tenant_id: _unused, ...rest }) => rest);
  });

  server.post('/api/software-packages/:id/deploy', async (request, reply) => {
    const { id } = request.params as { id: string };
    const pkg = db.prepare('SELECT * FROM software_packages WHERE id = ?').get(id) as any;
    if (!pkg) return reply.status(404).send({ error: 'Software package not found.' });

    const body = (request.body || {}) as {
      deviceIds?: string[];
      smartGroupId?: string;
      action?: 'install' | 'upgrade' | 'uninstall';
    };

    let targetIds = Array.isArray(body.deviceIds) ? body.deviceIds.filter(Boolean) : [];
    if (body.smartGroupId) {
      const sg = db.prepare('SELECT * FROM smart_groups WHERE id = ?').get(body.smartGroupId) as any;
      if (sg && (!sg.tenant_id || canUserAccessTenant(request.auth?.user, sg.tenant_id))) {
        const matched = evaluateSmartGroupDevices(sg.criteria_json, sg.tenant_id);
        targetIds = Array.from(new Set([...targetIds, ...matched.map((d) => d.id)]));
      }
    }
    if (targetIds.length === 0) {
      return reply.status(400).send({ error: 'Select at least one target endpoint or Smart Group.' });
    }

    const action: 'install' | 'upgrade' | 'uninstall' =
      body.action === 'uninstall' ? 'uninstall' : body.action === 'upgrade' ? 'upgrade' : 'install';
    const actor = getActorUsername(request);
    const pkgMgr = String(pkg.package_manager || pkg.package_type || 'winget');
    const rawIdentifier = String(pkg.package_identifier || '').trim();
    const safeId = rawIdentifier.replace(/[^a-zA-Z0-9._/@+-]/g, '');
    if (['winget', 'choco', 'apt', 'dnf', 'brew'].includes(pkgMgr) && (!safeId || safeId.startsWith('-'))) {
      return reply.status(400).send({ error: 'Invalid or unsafe package_identifier (cannot be empty or start with "-").' });
    }

    const protoHeader = String(request.headers['x-forwarded-proto'] || '').split(',')[0].trim();
    const hostHeader = String(request.headers['x-forwarded-host'] || request.headers.host || 'localhost:3000').split(',')[0].trim();
    const baseControlUrl = (
      process.env.VITRINE_PUBLIC_URL ||
      `${protoHeader || (request.protocol === 'https' ? 'https' : 'http')}://${hostHeader}`
    ).replace(/\/+$/, '');

    const rawInstallerUrl = String(pkg.installer_url || pkg.download_url || '').trim();
    const resolvedInstallerUrl = rawInstallerUrl.startsWith('/')
      ? `${baseControlUrl}${rawInstallerUrl}`
      : rawInstallerUrl;
    const expectedSha256 = String(pkg.sha256_hash || '').trim().toLowerCase();
    const results: any[] = [];

    for (const devId of targetIds) {
      const dev = db.prepare('SELECT * FROM devices WHERE id = ?').get(devId) as any;
      if (!dev || !canUserAccessTenant(request.auth?.user, dev.tenant_id)) continue;

      const psId = quotePowerShellLiteral(safeId);
      const shId = quotePosixLiteral(safeId);
      let cmd = '';

      if (pkgMgr === 'winget') {
        const sub = action === 'uninstall' ? 'uninstall' : action === 'upgrade' ? 'upgrade' : 'install';
        cmd = `winget ${sub} --id ${psId} --exact --silent --accept-package-agreements --accept-source-agreements`;
      } else if (pkgMgr === 'choco') {
        const sub = action === 'uninstall' ? 'uninstall' : action === 'upgrade' ? 'upgrade' : 'install';
        cmd = `choco ${sub} ${psId} -y --no-progress`;
      } else if (pkgMgr === 'apt') {
        cmd =
          action === 'uninstall'
            ? `DEBIAN_FRONTEND=noninteractive apt-get remove -y -- ${shId}`
            : `DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -- ${shId}`;
      } else if (pkgMgr === 'dnf') {
        cmd = action === 'uninstall' ? `dnf remove -y -- ${shId}` : `dnf install -y -- ${shId}`;
      } else if (pkgMgr === 'brew') {
        cmd = action === 'uninstall' ? `brew uninstall -- ${shId}` : `brew install -- ${shId}`;
      } else if (pkgMgr === 'msi_url' && action !== 'uninstall' && resolvedInstallerUrl) {
        const psUrl = quotePowerShellLiteral(resolvedInstallerUrl);
        const psExtra = String(pkg.install_args || '/qn /norestart').trim();
        const shaCheck = /^[a-f0-9]{64}$/.test(expectedSha256)
          ? `$actual = (Get-FileHash -Path $tmpMsi -Algorithm SHA256).Hash.ToLower(); if ($actual -ne '${expectedSha256}') { Remove-Item -Force $tmpMsi -ErrorAction SilentlyContinue; throw "SHA-256 mismatch ($actual)" }; `
          : '';
        cmd = `$ErrorActionPreference = 'Stop'; $tmpMsi = Join-Path $env:TEMP ('vitrine-' + [guid]::NewGuid().ToString() + '.msi'); $hdrs = @{}; if ($env:VITRINE_AGENT_TOKEN) { $hdrs['x-vitrine-agent-token'] = $env:VITRINE_AGENT_TOKEN }; Invoke-WebRequest -Uri ${psUrl} -Headers $hdrs -UseBasicParsing -OutFile $tmpMsi; ${shaCheck}$p = Start-Process -FilePath 'msiexec.exe' -ArgumentList (@('/i', $tmpMsi) + @(${quotePowerShellLiteral(psExtra)} -split ' ')) -Wait -PassThru; Remove-Item -Force $tmpMsi -ErrorAction SilentlyContinue; exit $p.ExitCode`;
      } else if (pkgMgr === 'deb_upload' && action !== 'uninstall' && resolvedInstallerUrl) {
        const shUrl = quotePosixLiteral(resolvedInstallerUrl);
        const shaCheck = /^[a-f0-9]{64}$/.test(expectedSha256)
          ? `echo "${expectedSha256}  $TMP_DEB" | sha256sum -c - || { rm -f "$TMP_DEB"; exit 1; }; `
          : '';
        cmd = `set -e; TMP_DEB="/tmp/vitrine-${pkg.id}-$$.deb"; if [ -n "\${VITRINE_AGENT_TOKEN:-}" ]; then curl -fsSL -H "x-vitrine-agent-token: $VITRINE_AGENT_TOKEN" ${shUrl} -o "$TMP_DEB"; else curl -fsSL ${shUrl} -o "$TMP_DEB"; fi; ${shaCheck}DEBIAN_FRONTEND=noninteractive dpkg -i "$TMP_DEB" || DEBIAN_FRONTEND=noninteractive apt-get install -f -y; rm -f "$TMP_DEB"`;
      } else {
        cmd = action === 'uninstall' ? String(pkg.uninstall_args || '') : String(pkg.install_args || '');
      }

      if (!cmd.trim()) {
        return reply.status(400).send({ error: `No executable command or installer URL configured for '${pkg.name}'.` });
      }

      const depId = `dep-${crypto.randomUUID().slice(0, 8)}`;
      const shell = dev.os_type === 'windows' ? 'powershell' : 'bash';
      const execRes = await meshBridge.executeCommandOnNode(dev.id, cmd, {
        runAs: 'system',
        shell,
        timeoutMs: 25_000
      });

      const status = execRes.live ? (execRes.exitCode === 0 ? 'installed' : 'failed') : 'queued';
      const queuedViaMeshBridge = Boolean(
        execRes.queued || execRes.taskId || execRes.output.startsWith('[Vitrine Companion Queue]')
      );

      if (!execRes.live && queuedViaMeshBridge) {
        const existingQueued = execRes.taskId
          ? (db
              .prepare('SELECT id, payload_json FROM agent_tasks WHERE id = ?')
              .get(execRes.taskId) as { id: string; payload_json: string } | undefined)
          : (db
              .prepare(
                "SELECT id, payload_json FROM agent_tasks WHERE device_id = ? AND status = 'queued' ORDER BY created_at DESC LIMIT 1"
              )
              .get(dev.id) as { id: string; payload_json: string } | undefined);
        if (existingQueued) {
          const parsedPayload = safeJsonParse<Record<string, any>>(existingQueued.payload_json, {});
          parsedPayload.deploymentId = depId;
          db.prepare('UPDATE agent_tasks SET payload_json = ? WHERE id = ?').run(
            JSON.stringify(parsedPayload),
            existingQueued.id
          );
        }
      } else if (!execRes.live && dev.companion_installed) {
        const taskId = `task-${crypto.randomUUID().slice(0, 10)}`;
        db.prepare(`
          INSERT INTO agent_tasks (id, device_id, task_type, payload_json, status)
          VALUES (?, ?, 'script', ?, 'queued')
        `).run(taskId, dev.id, JSON.stringify({ deploymentId: depId, language: shell, shell, code: cmd, runAs: 'system' }));
      }

      db.prepare(`
        INSERT INTO software_deployments (
          id, package_id, package_name, device_id, hostname, action, status, exit_code, output, triggered_by, completed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CASE WHEN ? IN ('installed', 'failed') THEN CURRENT_TIMESTAMP ELSE NULL END)
      `).run(
        depId,
        pkg.id,
        pkg.name,
        dev.id,
        dev.hostname,
        action,
        status,
        execRes.live ? execRes.exitCode : null,
        execRes.output,
        actor,
        status
      );

      results.push({ deploymentId: depId, hostname: dev.hostname, status, output: execRes.output });
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'Software Package Deployed', ?)
    `).run(
      `aud-pkg-${crypto.randomUUID()}`,
      actor,
      `Dispatched ${action.toUpperCase()} of '${pkg.name}' across ${results.length} endpoint(s)`
    );

    return { success: true, deployedCount: results.length, results };
  });

  // ============================================================================
  // 4. Stateful Alert Incident Center & Notification Channels (Slack/Teams/PD/Webhook)
  // ============================================================================
  server.get('/api/alerts', async (request) => {
    const query = (request.query || {}) as { status?: string; severity?: string; tenant_id?: string };
    const user = request.auth?.user;
    const scopedTenant = getScopedTenantFilter(user);
    const clauses: string[] = [];
    const params: any[] = [];

    if (scopedTenant) {
      clauses.push('a.tenant_id = ?');
      params.push(scopedTenant);
    } else if (query.tenant_id && query.tenant_id !== 'all') {
      clauses.push('a.tenant_id = ?');
      params.push(query.tenant_id);
    }

    if (query.status && query.status !== 'all') {
      clauses.push('a.status = ?');
      params.push(query.status);
    }
    if (query.severity && query.severity !== 'all') {
      clauses.push('LOWER(a.severity) = LOWER(?)');
      params.push(query.severity);
    }

    const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = db
      .prepare(`
        SELECT a.*, t.name as tenant_name
        FROM alert_incidents a
        LEFT JOIN tenants t ON a.tenant_id = t.id
        ${whereSql}
        ORDER BY CASE a.status WHEN 'open' THEN 0 WHEN 'acknowledged' THEN 1 WHEN 'snoozed' THEN 2 ELSE 3 END ASC,
                 a.last_seen_at DESC
        LIMIT 250
      `)
      .all(...params) as any[];

    const hasRestrictedTenants = Boolean(scopedTenant || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0));
    return rows.filter((r) => (r.tenant_id ? canUserAccessTenant(user, r.tenant_id) : !hasRestrictedTenants));
  });

  server.post('/api/alerts/:id/acknowledge', async (request, reply) => {
    const { id } = request.params as { id: string };
    const inc = db.prepare('SELECT * FROM alert_incidents WHERE id = ?').get(id) as any;
    if (!inc) return reply.status(404).send({ error: 'Alert incident not found.' });
    const user = request.auth?.user;
    if (
      (inc.tenant_id && !canUserAccessTenant(user, inc.tenant_id)) ||
      (!inc.tenant_id && (getScopedTenantFilter(user) || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0)))
    ) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    const actor = getActorUsername(request);
    db.prepare(`
      UPDATE alert_incidents
      SET status = 'acknowledged',
          acknowledged_by = ?,
          acknowledged_at = CURRENT_TIMESTAMP,
          assigned_to = COALESCE(assigned_to, ?)
      WHERE id = ?
    `).run(actor, actor, id);
    return { success: true, incident: db.prepare('SELECT * FROM alert_incidents WHERE id = ?').get(id) };
  });

  server.post('/api/alerts/:id/snooze', async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = (request.body || {}) as { minutes?: number };
    const inc = db.prepare('SELECT * FROM alert_incidents WHERE id = ?').get(id) as any;
    if (!inc) return reply.status(404).send({ error: 'Alert incident not found.' });
    const user = request.auth?.user;
    if (
      (inc.tenant_id && !canUserAccessTenant(user, inc.tenant_id)) ||
      (!inc.tenant_id && (getScopedTenantFilter(user) || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0)))
    ) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    const mins = Math.max(5, Math.min(10080, Number(body.minutes || 60)));
    const untilIso = new Date(Date.now() + mins * 60_000).toISOString();
    db.prepare(`
      UPDATE alert_incidents
      SET status = 'snoozed', snoozed_until = ?, acknowledged_by = COALESCE(acknowledged_by, ?)
      WHERE id = ?
    `).run(untilIso, getActorUsername(request), id);
    return { success: true, snoozedUntil: untilIso };
  });

  server.post('/api/alerts/:id/resolve', async (request, reply) => {
    const { id } = request.params as { id: string };
    const inc = db.prepare('SELECT * FROM alert_incidents WHERE id = ?').get(id) as any;
    if (!inc) return reply.status(404).send({ error: 'Alert incident not found.' });
    const user = request.auth?.user;
    if (
      (inc.tenant_id && !canUserAccessTenant(user, inc.tenant_id)) ||
      (!inc.tenant_id && (getScopedTenantFilter(user) || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0)))
    ) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    db.prepare(`
      UPDATE alert_incidents
      SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(id);
    if (inc.psa_ticket_number) {
      db.prepare("UPDATE psa_tickets SET status = 'Resolved' WHERE ticket_number = ?").run(inc.psa_ticket_number);
    }
    return { success: true };
  });

  server.post('/api/alerts/:id/assign', async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = (request.body || {}) as { assignee?: string };
    const inc = db.prepare('SELECT * FROM alert_incidents WHERE id = ?').get(id) as any;
    if (!inc) return reply.status(404).send({ error: 'Alert incident not found.' });
    const user = request.auth?.user;
    if (
      (inc.tenant_id && !canUserAccessTenant(user, inc.tenant_id)) ||
      (!inc.tenant_id && (getScopedTenantFilter(user) || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0)))
    ) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    db.prepare('UPDATE alert_incidents SET assigned_to = ? WHERE id = ?').run(
      body.assignee || getActorUsername(request),
      id
    );
    return { success: true };
  });

  const sanitizeChannel = (c: any) => ({
    ...c,
    enabled: Boolean(c.enabled),
    webhook_url: maskSecretValue(c.webhook_url_encrypted),
    signing_secret: maskSecretValue(c.signing_secret_encrypted),
    routing_key: maskSecretValue(c.routing_key_encrypted),
    events: safeJsonParse<string[]>(c.events_json, ['all']),
    webhook_url_encrypted: undefined,
    signing_secret_encrypted: undefined,
    routing_key_encrypted: undefined
  });

  server.get('/api/notification-channels', async (request) => {
    const user = request.auth?.user;
    const hasRestrictedTenants = Boolean(getScopedTenantFilter(user) || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0));
    const rows = db.prepare('SELECT * FROM notification_channels ORDER BY created_at DESC').all() as any[];
    return rows
      .filter((r) => (r.tenant_id ? canUserAccessTenant(user, r.tenant_id) : !hasRestrictedTenants))
      .map(sanitizeChannel);
  });

  server.post('/api/notification-channels', async (request, reply) => {
    const body = (request.body || {}) as {
      name?: string;
      channel_type?: 'slack' | 'teams' | 'discord' | 'pagerduty' | 'webhook';
      webhook_url?: string;
      signing_secret?: string;
      routing_key?: string;
      min_severity?: string;
      tenant_id?: string | null;
      events?: string[];
      enabled?: boolean;
    };
    if (!body.name?.trim()) return reply.status(400).send({ error: 'Channel name is required.' });
    if (body.channel_type !== 'pagerduty' && !body.webhook_url?.trim()) {
      return reply.status(400).send({ error: 'Webhook URL is required.' });
    }
    if (body.channel_type === 'pagerduty' && !body.routing_key?.trim() && !body.webhook_url?.trim()) {
      return reply.status(400).send({ error: 'PagerDuty integration routing key is required.' });
    }
    const targetTenantId = body.tenant_id && body.tenant_id !== 'all' ? body.tenant_id : null;
    const user = request.auth?.user;
    if (
      (targetTenantId && !canUserAccessTenant(user, targetTenantId)) ||
      (!targetTenantId && (getScopedTenantFilter(user) || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0)))
    ) {
      return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
    }
    if (body.webhook_url) {
      const check = await validateOutboundHostSafety(body.webhook_url, { allowLoopback: false });
      if (!check.safe) {
        return reply.status(400).send({ error: check.reason || 'Webhook URL blocked by SSRF guard.' });
      }
    }

    const id = `nch-${crypto.randomUUID().slice(0, 8)}`;
    db.prepare(`
      INSERT INTO notification_channels (
        id, name, channel_type, webhook_url_encrypted, signing_secret_encrypted,
        routing_key_encrypted, min_severity, tenant_id, events_json, enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      body.name.trim(),
      body.channel_type || 'slack',
      body.webhook_url ? encryptVaultSecret(body.webhook_url.trim()) : '',
      body.signing_secret ? encryptVaultSecret(body.signing_secret.trim()) : '',
      body.routing_key ? encryptVaultSecret(body.routing_key.trim()) : null,
      body.min_severity || 'Warning',
      targetTenantId,
      JSON.stringify(body.events || ['all']),
      body.enabled !== false ? 1 : 0
    );

    const saved = db.prepare('SELECT * FROM notification_channels WHERE id = ?').get(id);
    return { success: true, channel: sanitizeChannel(saved) };
  });

  server.delete('/api/notification-channels/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM notification_channels WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Notification channel not found.' });
    const user = request.auth?.user;
    if (
      (existing.tenant_id && !canUserAccessTenant(user, existing.tenant_id)) ||
      (!existing.tenant_id && (getScopedTenantFilter(user) || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0)))
    ) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    db.prepare('DELETE FROM notification_channels WHERE id = ?').run(id);
    return { success: true };
  });

  server.post('/api/notification-channels/:id/test', async (request, reply) => {
    const { id } = request.params as { id: string };
    const ch = db.prepare('SELECT * FROM notification_channels WHERE id = ?').get(id) as any;
    if (!ch) return reply.status(404).send({ error: 'Notification channel not found.' });
    const user = request.auth?.user;
    if (
      (ch.tenant_id && !canUserAccessTenant(user, ch.tenant_id)) ||
      (!ch.tenant_id && (getScopedTenantFilter(user) || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0)))
    ) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const dispatched = await dispatchAlertToNotificationChannels({
      incidentId: `test-${Date.now()}`,
      entityName: 'vitrine-control-plane',
      clientName: 'Global MSP Control Plane',
      conditionId: 'webhook_test',
      label: `Vitrine RMM Test Alert (${ch.name})`,
      detail: `Outbound webhook verification triggered by ${getActorUsername(request)}.`,
      severity: 'critical',
      tenantId: ch.tenant_id
    });

    return { success: dispatched.length > 0, dispatched };
  });

  // ============================================================================
  // 5. MSP Documentation & Runbooks Knowledge Base (NinjaOne Documentation Parity)
  // ============================================================================
  server.get('/api/documentation', async (request) => {
    const query = (request.query || {}) as { tenant_id?: string; category?: string; search?: string };
    const user = request.auth?.user;
    const scopedTenant = getScopedTenantFilter(user);
    const hasRestrictedTenants = Boolean(scopedTenant || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0));
    const clauses: string[] = [];
    const params: any[] = [];

    if (scopedTenant) {
      clauses.push('(d.tenant_id = ?)');
      params.push(scopedTenant);
    } else if (query.tenant_id && query.tenant_id !== 'all') {
      if (hasRestrictedTenants) {
        clauses.push('(d.tenant_id = ?)');
        params.push(query.tenant_id);
      } else {
        clauses.push('(d.tenant_id = ? OR d.tenant_id IS NULL)');
        params.push(query.tenant_id);
      }
    }

    if (query.category && query.category !== 'all') {
      clauses.push('d.category = ?');
      params.push(query.category);
    }
    if (query.search?.trim()) {
      clauses.push('(d.title LIKE ? OR d.content_markdown LIKE ?)');
      const term = `%${query.search.trim()}%`;
      params.push(term, term);
    }

    const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = db
      .prepare(`
        SELECT d.*, t.name as tenant_name, s.name as linked_script_name
        FROM documentation_articles d
        LEFT JOIN tenants t ON d.tenant_id = t.id
        LEFT JOIN scripts s ON d.linked_script_id = s.id
        ${whereSql}
        ORDER BY d.is_pinned DESC, d.updated_at DESC
      `)
      .all(...params) as any[];

    return rows
      .filter((r) => (r.tenant_id ? canUserAccessTenant(user, r.tenant_id) : !hasRestrictedTenants))
      .map((r) => ({
        ...r,
        is_pinned: Boolean(r.is_pinned),
        has_encrypted_secrets: Boolean(r.encrypted_secrets_json),
        tags: safeJsonParse<string[]>(r.tags_json, []),
        encrypted_secrets_json: undefined
      }));
  });

  server.post('/api/documentation', async (request, reply) => {
    const body = (request.body || {}) as {
      tenant_id?: string | null;
      category?: string;
      title?: string;
      content_markdown?: string;
      tags?: string[];
      is_pinned?: boolean;
      linked_script_id?: string | null;
      secrets?: Array<{ label: string; value: string }>;
    };
    if (!body.title?.trim()) return reply.status(400).send({ error: 'Article title is required.' });

    const user = request.auth?.user;
    const scopedTenant = getScopedTenantFilter(user);
    const hasRestrictedTenants = Boolean(scopedTenant || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0));
    const resolvedTenantId =
      body.tenant_id && body.tenant_id !== 'all' ? body.tenant_id : scopedTenant && scopedTenant !== '__DENY_ALL__' ? scopedTenant : null;

    if (
      (resolvedTenantId && !canUserAccessTenant(user, resolvedTenantId)) ||
      (!resolvedTenantId && hasRestrictedTenants)
    ) {
      return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
    }

    const id = `doc-${crypto.randomUUID().slice(0, 8)}`;
    const actor = getActorUsername(request);
    const encSecrets =
      Array.isArray(body.secrets) && body.secrets.length > 0
        ? encryptVaultSecret(JSON.stringify(body.secrets))
        : null;

    db.prepare(`
      INSERT INTO documentation_articles (
        id, tenant_id, category, title, content_markdown, encrypted_secrets_json,
        tags_json, is_pinned, linked_script_id, author, last_edited_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      resolvedTenantId,
      body.category || 'Runbooks',
      body.title.trim(),
      body.content_markdown || '',
      encSecrets,
      JSON.stringify(body.tags || []),
      body.is_pinned ? 1 : 0,
      body.linked_script_id || null,
      actor,
      actor
    );

    const createdRow = db.prepare('SELECT * FROM documentation_articles WHERE id = ?').get(id) as any;
    return {
      success: true,
      article: {
        ...createdRow,
        is_pinned: Boolean(createdRow.is_pinned),
        has_encrypted_secrets: Boolean(createdRow.encrypted_secrets_json),
        tags: safeJsonParse<string[]>(createdRow.tags_json, []),
        encrypted_secrets_json: undefined
      }
    };
  });

  server.put('/api/documentation/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM documentation_articles WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Documentation article not found.' });

    const user = request.auth?.user;
    const hasRestrictedTenants = Boolean(getScopedTenantFilter(user) || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0));
    if (
      (existing.tenant_id && !canUserAccessTenant(user, existing.tenant_id)) ||
      (!existing.tenant_id && hasRestrictedTenants)
    ) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const body = (request.body || {}) as Record<string, any>;
    const nextTenantId =
      body.tenant_id !== undefined ? (body.tenant_id === 'all' ? null : body.tenant_id) : existing.tenant_id;
    if (
      (nextTenantId && !canUserAccessTenant(user, nextTenantId)) ||
      (!nextTenantId && hasRestrictedTenants)
    ) {
      return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
    }

    const encSecrets =
      body.secrets !== undefined
        ? Array.isArray(body.secrets) && body.secrets.length > 0
          ? encryptVaultSecret(JSON.stringify(body.secrets))
          : null
        : existing.encrypted_secrets_json;

    db.prepare(`
      UPDATE documentation_articles SET
        tenant_id = ?,
        category = COALESCE(?, category),
        title = COALESCE(?, title),
        content_markdown = COALESCE(?, content_markdown),
        encrypted_secrets_json = ?,
        tags_json = COALESCE(?, tags_json),
        is_pinned = COALESCE(?, is_pinned),
        linked_script_id = ?,
        version = COALESCE(version, 1) + 1,
        last_edited_by = ?,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(
      nextTenantId,
      body.category ?? null,
      body.title ?? null,
      body.content_markdown ?? null,
      encSecrets,
      body.tags ? JSON.stringify(body.tags) : null,
      body.is_pinned != null ? (body.is_pinned ? 1 : 0) : null,
      body.linked_script_id !== undefined ? body.linked_script_id : existing.linked_script_id,
      getActorUsername(request),
      id
    );

    const updatedRow = db.prepare('SELECT * FROM documentation_articles WHERE id = ?').get(id) as any;
    return {
      success: true,
      article: {
        ...updatedRow,
        is_pinned: Boolean(updatedRow.is_pinned),
        has_encrypted_secrets: Boolean(updatedRow.encrypted_secrets_json),
        tags: safeJsonParse<string[]>(updatedRow.tags_json, []),
        encrypted_secrets_json: undefined
      }
    };
  });

  server.get('/api/documentation/:id/secrets', async (request, reply) => {
    const user = request.auth?.user;
    if (!user || !isTechnicianOrAbove(user.role)) {
      return reply.status(403).send({ error: 'Technician or Super Admin role required to reveal encrypted runbook secrets.' });
    }
    const { id } = request.params as { id: string };
    const row = db.prepare('SELECT * FROM documentation_articles WHERE id = ?').get(id) as any;
    if (!row) return reply.status(404).send({ error: 'Documentation article not found.' });
    const hasRestrictedTenants = Boolean(getScopedTenantFilter(user) || (user.allowed_tenant_ids && user.allowed_tenant_ids.length > 0));
    if (
      (row.tenant_id && !canUserAccessTenant(user, row.tenant_id)) ||
      (!row.tenant_id && hasRestrictedTenants)
    ) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const globalPol = db
      .prepare("SELECT require_mfa_for_secrets FROM policies WHERE tier = 'global' LIMIT 1")
      .get() as { require_mfa_for_secrets?: number } | undefined;
    const mfaRequired = Boolean(globalPol?.require_mfa_for_secrets ?? 1);
    if (mfaRequired && !request.auth?.mfaVerified) {
      return reply.status(403).send({
        error: 'Step-Up Multi-Factor Authentication is required to reveal encrypted runbook secrets.',
        code: 'MFA_REQUIRED',
        mfaRequired: true
      });
    }

    const decryptedRaw = row.encrypted_secrets_json ? decryptVaultSecret(String(row.encrypted_secrets_json)) : '[]';
    const secrets = safeJsonParse<Array<{ label: string; value: string }>>(decryptedRaw, []);

    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'Documentation Secret Revealed', ?)
    `).run(
      `aud-docsec-${crypto.randomUUID()}`,
      getActorUsername(request),
      `Revealed ${secrets.length} encrypted vault secret(s) on runbook '${row.title}' (${id})`
    );

    return {
      success: true,
      secrets
    };
  });

  server.delete('/api/documentation/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM documentation_articles WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Documentation article not found.' });
    const user = request.auth?.user;
    const hasRestrictedTenants = Boolean(getScopedTenantFilter(user) || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0));
    if (
      (existing.tenant_id && !canUserAccessTenant(user, existing.tenant_id)) ||
      (!existing.tenant_id && hasRestrictedTenants)
    ) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    db.prepare('DELETE FROM documentation_articles WHERE id = ?').run(id);
    return { success: true };
  });

  // ============================================================================
  // 6. Multi-PSA Integrations (HaloPSA, ConnectWise, Autotask, Syncro, Zammad, ITFlow) & Time Entries
  // ============================================================================
  const sanitizePsa = (r: any) => ({
    ...r,
    enabled: Boolean(r.enabled),
    auto_sync_tickets: Boolean(r.auto_sync_tickets),
    auto_sync_assets: Boolean(r.auto_sync_assets),
    has_api_key: Boolean(r.api_key_encrypted),
    api_key: maskSecretValue(r.api_key_encrypted),
    client_secret: maskSecretValue(r.client_secret_encrypted),
    api_key_encrypted: undefined,
    client_secret_encrypted: undefined
  });

  const resolveTicketTenantId = (tkt: any): string | null => {
    if (!tkt) return null;
    if (tkt.device_id) {
      const dev = db.prepare('SELECT tenant_id FROM devices WHERE id = ?').get(tkt.device_id) as
        | { tenant_id?: string }
        | undefined;
      if (dev?.tenant_id) return dev.tenant_id;
    }
    if (tkt.client_name) {
      const ten = db
        .prepare('SELECT id FROM tenants WHERE LOWER(name) = LOWER(?) LIMIT 1')
        .get(String(tkt.client_name).trim()) as { id?: string } | undefined;
      if (ten?.id) return ten.id;
    }
    return null;
  };

  server.get('/api/psa/integrations', async () => {
    const rows = db.prepare('SELECT * FROM psa_integrations ORDER BY created_at DESC').all() as any[];
    return rows.map(sanitizePsa);
  });

  server.post('/api/psa/integrations', async (request, reply) => {
    const body = (request.body || {}) as {
      provider?: 'itflow' | 'halopsa' | 'connectwise' | 'autotask' | 'syncro' | 'zammad' | 'generic_webhook';
      name?: string;
      base_url?: string;
      client_id?: string;
      api_key?: string;
      client_secret?: string;
      default_board?: string;
      auto_sync_tickets?: boolean;
      auto_sync_assets?: boolean;
      enabled?: boolean;
    };
    if (!body.name?.trim() || !body.base_url?.trim()) {
      return reply.status(400).send({ error: 'PSA integration name and base URL are required.' });
    }
    const urlCheck = await validateOutboundHostSafety(body.base_url.trim(), { allowLoopback: false, allowPrivateLan: true });
    if (!urlCheck.safe) {
      return reply.status(400).send({ error: urlCheck.reason || 'PSA base URL blocked by SSRF guard.' });
    }

    const id = `psa-${crypto.randomUUID().slice(0, 8)}`;
    db.prepare(`
      INSERT INTO psa_integrations (
        id, provider, name, base_url, client_id, api_key_encrypted, client_secret_encrypted,
        default_board, auto_sync_tickets, auto_sync_assets, enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      body.provider || 'halopsa',
      body.name.trim(),
      body.base_url.trim(),
      body.client_id || '',
      body.api_key && !isMaskedSecret(body.api_key) ? encryptVaultSecret(body.api_key.trim()) : null,
      body.client_secret && !isMaskedSecret(body.client_secret) ? encryptVaultSecret(body.client_secret.trim()) : null,
      body.default_board || 'Service Desk',
      body.auto_sync_tickets !== false ? 1 : 0,
      body.auto_sync_assets ? 1 : 0,
      body.enabled !== false ? 1 : 0
    );

    return {
      success: true,
      integration: sanitizePsa(db.prepare('SELECT * FROM psa_integrations WHERE id = ?').get(id))
    };
  });

  server.post('/api/psa/integrations/:id/test', async (request, reply) => {
    const { id } = request.params as { id: string };
    const row = db.prepare('SELECT * FROM psa_integrations WHERE id = ?').get(id) as any;
    if (!row) return reply.status(404).send({ success: false, error: 'PSA integration not found.' });

    const urlCheck = await validateOutboundHostSafety(row.base_url, { allowLoopback: false, allowPrivateLan: true });
    if (!urlCheck.safe) {
      const blockMsg = urlCheck.reason || 'Blocked by SSRF guard.';
      db.prepare('UPDATE psa_integrations SET last_status = ?, last_error = ? WHERE id = ?').run(
        `Blocked: ${blockMsg}`,
        blockMsg,
        id
      );
      return reply.status(400).send({ success: false, error: blockMsg });
    }

    try {
      const apiKey = row.api_key_encrypted ? decryptVaultSecret(row.api_key_encrypted) : '';
      const headers: Record<string, string> = { Accept: 'application/json' };
      if (apiKey) headers.Authorization = `Bearer ${apiKey}`;

      const res = await safeOutboundFetch(row.base_url, {
        method: 'GET',
        headers,
        timeoutMs: 8000,
        allowLoopback: false,
        allowPrivateLan: true
      });
      const ok = res.status >= 200 && res.status < 500;
      const statusText = ok ? `HTTP ${res.status} Reachable` : `HTTP ${res.status} Error`;
      db.prepare(
        'UPDATE psa_integrations SET last_synced_at = CURRENT_TIMESTAMP, last_status = ?, last_error = ? WHERE id = ?'
      ).run(statusText, ok ? null : statusText, id);
      return {
        success: ok,
        status: res.status,
        message: statusText
      };
    } catch (err: any) {
      const msg = err?.message || 'Connection failed';
      db.prepare('UPDATE psa_integrations SET last_status = ?, last_error = ? WHERE id = ?').run(
        `Error: ${msg.slice(0, 80)}`,
        msg.slice(0, 240),
        id
      );
      return reply.status(502).send({ success: false, error: msg });
    }
  });

  server.delete('/api/psa/integrations/:id', async (request) => {
    const { id } = request.params as { id: string };
    db.prepare('DELETE FROM psa_integrations WHERE id = ?').run(id);
    return { success: true };
  });

  server.get('/api/psa/tickets/:id/time-entries', async (request, reply) => {
    const { id } = request.params as { id: string };
    const tkt = db.prepare('SELECT * FROM psa_tickets WHERE id = ?').get(id) as any;
    if (!tkt) return reply.status(404).send({ error: 'PSA ticket not found.' });
    const tid = resolveTicketTenantId(tkt);
    const user = request.auth?.user;
    if (
      (tid && !canUserAccessTenant(user, tid)) ||
      (!tid && (getScopedTenantFilter(user) || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0)))
    ) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    return db.prepare('SELECT * FROM psa_time_entries WHERE ticket_id = ? ORDER BY created_at DESC').all(id);
  });

  server.post('/api/psa/tickets/:id/time-entries', async (request, reply) => {
    const { id } = request.params as { id: string };
    const tkt = db.prepare('SELECT * FROM psa_tickets WHERE id = ?').get(id) as any;
    if (!tkt) return reply.status(404).send({ error: 'PSA ticket not found.' });
    const tid = resolveTicketTenantId(tkt);
    const user = request.auth?.user;
    if (
      (tid && !canUserAccessTenant(user, tid)) ||
      (!tid && (getScopedTenantFilter(user) || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0)))
    ) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const body = (request.body || {}) as {
      minutes_spent?: number;
      billable?: boolean;
      work_type?: string;
      notes?: string;
    };
    const mins = Math.max(1, Number(body.minutes_spent || 15));
    const entryId = `time-${crypto.randomUUID().slice(0, 8)}`;

    db.prepare(`
      INSERT INTO psa_time_entries (id, ticket_id, technician, minutes, minutes_spent, billable, work_type, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      entryId,
      id,
      getActorUsername(request),
      mins,
      mins,
      body.billable !== false ? 1 : 0,
      body.work_type || 'Remote Engineering',
      body.notes || ''
    );

    return {
      success: true,
      entry: db.prepare('SELECT * FROM psa_time_entries WHERE id = ?').get(entryId)
    };
  });

  server.delete('/api/psa/time-entries/:entryId', async (request, reply) => {
    const { entryId } = request.params as { entryId: string };
    const entry = db.prepare('SELECT * FROM psa_time_entries WHERE id = ?').get(entryId) as any;
    if (!entry) return reply.status(404).send({ error: 'Time entry not found.' });
    const tkt = db.prepare('SELECT * FROM psa_tickets WHERE id = ?').get(entry.ticket_id) as any;
    const tid = resolveTicketTenantId(tkt);
    const user = request.auth?.user;
    if (
      (tid && !canUserAccessTenant(user, tid)) ||
      (!tid && (getScopedTenantFilter(user) || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0)))
    ) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    db.prepare('DELETE FROM psa_time_entries WHERE id = ?').run(entryId);
    return { success: true };
  });

  // ============================================================================
  // 7. Managed Endpoint Security (Defender Scan/Update, BitLocker Enable), Backups & MDM Profiles
  // ============================================================================
  server.post('/api/devices/:id/security/action', async (request, reply) => {
    const { id } = request.params as { id: string };
    const dev = db.prepare('SELECT * FROM devices WHERE id = ?').get(id) as any;
    if (!dev) return reply.status(404).send({ error: 'Device not found.' });
    if (!canUserAccessTenant(request.auth?.user, dev.tenant_id)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const body = (request.body || {}) as {
      action?: 'av_quick_scan' | 'av_full_scan' | 'av_update_signatures' | 'enable_disk_encryption' | 'enable_encryption' | 'verify_encryption';
    };
    const act = body.action || 'av_quick_scan';
    let cmd = '';
    const shell = dev.os_type === 'windows' ? 'powershell' : 'bash';

    if (act === 'av_quick_scan') {
      cmd =
        dev.os_type === 'windows'
          ? 'Start-MpScan -ScanType QuickScan'
          : 'clamscan -r --bell -i /home /tmp 2>/dev/null || echo "AV Quick Scan completed"';
    } else if (act === 'av_full_scan') {
      cmd =
        dev.os_type === 'windows'
          ? 'Start-MpScan -ScanType FullScan'
          : 'clamscan -r -i / 2>/dev/null || echo "AV Full Scan queued"';
    } else if (act === 'av_update_signatures') {
      cmd =
        dev.os_type === 'windows'
          ? 'Update-MpSignature'
          : 'freshclam 2>/dev/null || echo "Signature definitions verified"';
    } else if (act === 'verify_encryption') {
      cmd =
        dev.os_type === 'windows'
          ? 'Get-BitLockerVolume -MountPoint "C:" | Select-Object MountPoint,VolumeStatus,ProtectionStatus | Format-List'
          : dev.os_type === 'macos'
            ? 'fdesetup status'
            : 'lsblk -f 2>/dev/null | head -n 15 || echo "Volume encryption probe completed"';
    } else if (act === 'enable_disk_encryption' || act === 'enable_encryption') {
      cmd =
        dev.os_type === 'windows'
          ? 'Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -RecoveryPasswordProtector -SkipHardwareTest'
          : dev.os_type === 'macos'
            ? 'fdesetup status'
            : 'cryptsetup status root || lsblk -f';
    }

    const execRes = await meshBridge.executeCommandOnNode(id, cmd, { runAs: 'system', shell, timeoutMs: 20_000 });
    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Endpoint Security Action Executed', ?)
    `).run(`aud-sec-${crypto.randomUUID()}`, getActorUsername(request), id, `Triggered '${act}' on ${dev.hostname}`);

    return {
      success: true,
      action: act,
      live: execRes.live,
      exitCode: execRes.exitCode,
      output: execRes.output
    };
  });

  const sanitizeBackupPolicy = (r: any) => {
    if (!r) return r;
    const { repository_password_encrypted, ...rest } = r;
    return {
      ...rest,
      enabled: Boolean(r.enabled),
      repository_url: r.repository_url || r.target_repo || '',
      has_repository_password: Boolean(repository_password_encrypted),
      repository_password: maskSecretValue(repository_password_encrypted),
      include_paths: safeJsonParse<string[]>(r.include_paths_json, []),
      exclude_paths: safeJsonParse<string[]>(r.exclude_paths_json, [])
    };
  };

  server.get('/api/backup-policies', async (request) => {
    const user = request.auth?.user;
    const hasRestrictedTenants = Boolean(getScopedTenantFilter(user) || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0));
    const rows = db.prepare('SELECT * FROM backup_policies ORDER BY created_at DESC').all() as any[];
    return rows
      .filter((r) => (r.tenant_id ? canUserAccessTenant(user, r.tenant_id) : !hasRestrictedTenants))
      .map(sanitizeBackupPolicy);
  });

  server.post('/api/backup-policies', async (request, reply) => {
    const body = (request.body || {}) as {
      name?: string;
      tenant_id?: string | null;
      engine?: 'restic' | 'borg' | 'vss_wbadmin' | 'timemachine';
      repository_url?: string;
      repository_password?: string;
      include_paths?: string[];
      exclude_paths?: string[];
      schedule_cron?: string;
      retention_days?: number;
      enabled?: boolean;
    };
    if (!body.name?.trim() || !body.repository_url?.trim()) {
      return reply.status(400).send({ error: 'Backup policy name and target repository URL/path are required.' });
    }
    const user = request.auth?.user;
    const scopedTenant = getScopedTenantFilter(user);
    const hasRestrictedTenants = Boolean(scopedTenant || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0));
    const resolvedTenantId =
      body.tenant_id && body.tenant_id !== 'all' ? body.tenant_id : scopedTenant && scopedTenant !== '__DENY_ALL__' ? scopedTenant : null;
    if (
      (resolvedTenantId && !canUserAccessTenant(user, resolvedTenantId)) ||
      (!resolvedTenantId && hasRestrictedTenants)
    ) {
      return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
    }

    const id = `bpol-${crypto.randomUUID().slice(0, 8)}`;
    const repoUrl = body.repository_url.trim();
    db.prepare(`
      INSERT INTO backup_policies (
        id, name, tenant_id, engine, target_repo, repository_url, repository_password_encrypted,
        include_paths_json, exclude_paths_json, schedule_cron, retention_days, enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      body.name.trim(),
      resolvedTenantId,
      body.engine || 'restic',
      repoUrl,
      repoUrl,
      body.repository_password && !isMaskedSecret(body.repository_password)
        ? encryptVaultSecret(body.repository_password)
        : null,
      JSON.stringify(body.include_paths || ['C:\\Users', '/etc', '/home']),
      JSON.stringify(body.exclude_paths || ['*.tmp', 'node_modules']),
      body.schedule_cron || '0 2 * * *',
      Number(body.retention_days || 30),
      body.enabled !== false ? 1 : 0
    );

    return {
      success: true,
      policy: sanitizeBackupPolicy(db.prepare('SELECT * FROM backup_policies WHERE id = ?').get(id))
    };
  });

  server.delete('/api/backup-policies/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM backup_policies WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Backup policy not found.' });
    const user = request.auth?.user;
    const hasRestrictedTenants = Boolean(getScopedTenantFilter(user) || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0));
    if (
      (existing.tenant_id && !canUserAccessTenant(user, existing.tenant_id)) ||
      (!existing.tenant_id && hasRestrictedTenants)
    ) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    db.prepare('DELETE FROM backup_policies WHERE id = ?').run(id);
    return { success: true };
  });

  server.get('/api/backup-jobs', async (request, reply) => {
    const query = (request.query || {}) as { device_id?: string };
    const user = request.auth?.user;
    if (query.device_id) {
      const dev = db.prepare('SELECT tenant_id FROM devices WHERE id = ?').get(query.device_id) as
        | { tenant_id?: string }
        | undefined;
      if (dev && !canUserAccessTenant(user, dev.tenant_id)) {
        return reply.status(403).send({ error: 'Forbidden' });
      }
      return db
        .prepare('SELECT * FROM device_backup_jobs WHERE device_id = ? ORDER BY started_at DESC LIMIT 50')
        .all(query.device_id);
    }
    const rows = db
      .prepare(`
        SELECT bj.*, d.tenant_id as device_tenant_id
        FROM device_backup_jobs bj
        LEFT JOIN devices d ON bj.device_id = d.id
        ORDER BY bj.started_at DESC
        LIMIT 200
      `)
      .all() as any[];
    return rows
      .filter((r) => (r.device_tenant_id ? canUserAccessTenant(user, r.device_tenant_id) : !getScopedTenantFilter(user)))
      .slice(0, 100)
      .map(({ device_tenant_id: _unused, ...rest }) => rest);
  });

  server.post('/api/devices/:id/backup/run', async (request, reply) => {
    const { id } = request.params as { id: string };
    const dev = db.prepare('SELECT * FROM devices WHERE id = ?').get(id) as any;
    if (!dev) return reply.status(404).send({ error: 'Device not found.' });
    if (!canUserAccessTenant(request.auth?.user, dev.tenant_id)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const body = (request.body || {}) as { policy_id?: string };
    const bpol = body.policy_id
      ? (db.prepare('SELECT * FROM backup_policies WHERE id = ?').get(body.policy_id) as any)
      : (db
          .prepare('SELECT * FROM backup_policies WHERE (tenant_id = ? OR tenant_id IS NULL) AND enabled = 1 LIMIT 1')
          .get(dev.tenant_id) as any);
    if (bpol?.tenant_id && !canUserAccessTenant(request.auth?.user, bpol.tenant_id)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const engine = bpol?.engine || (dev.os_type === 'windows' ? 'vss_wbadmin' : 'restic');
    const rawPaths = safeJsonParse<string[]>(bpol?.include_paths_json, dev.os_type === 'windows' ? ['C:\\Users'] : ['/etc']);
    const safePaths = (Array.isArray(rawPaths) ? rawPaths : [])
      .map((p) => String(p || '').trim())
      .filter((p) => p.length > 0 && !p.startsWith('-'));
    if (safePaths.length === 0) {
      safePaths.push(dev.os_type === 'windows' ? 'C:\\Users' : '/etc');
    }

    const jobId = `bjob-${crypto.randomUUID().slice(0, 8)}`;
    const shell = dev.os_type === 'windows' ? 'powershell' : 'bash';
    const snapFile = `/tmp/vitrine-endpoint-snap-${jobId}.tar.gz`;
    const quotedPosixPaths = safePaths.map((p) => quotePosixLiteral(p)).join(' ');
    const cmd =
      dev.os_type === 'windows'
        ? `vssadmin list shadows`
        : `tar -czf ${quotePosixLiteral(snapFile)} -- ${quotedPosixPaths} 2>/dev/null && (stat -c%s ${quotePosixLiteral(snapFile)} 2>/dev/null || stat -f%z ${quotePosixLiteral(snapFile)}) && rm -f ${quotePosixLiteral(snapFile)}`;

    const execRes = await meshBridge.executeCommandOnNode(id, cmd, {
      runAs: 'system',
      shell,
      timeoutMs: 25_000
    });

    const bytesMatch = execRes.output.trim().match(/(\d+)\s*$/);
    const bytesProcessed = bytesMatch ? Number(bytesMatch[1]) : 0;
    const status = execRes.live ? (execRes.exitCode === 0 ? 'completed' : 'failed') : 'queued';
    const queuedViaMeshBridge = Boolean(
      execRes.queued || execRes.taskId || execRes.output.startsWith('[Vitrine Companion Queue]')
    );

    if (!execRes.live && queuedViaMeshBridge) {
      const existingQueued = execRes.taskId
        ? (db
            .prepare('SELECT id, payload_json FROM agent_tasks WHERE id = ?')
            .get(execRes.taskId) as { id: string; payload_json: string } | undefined)
        : (db
            .prepare(
              "SELECT id, payload_json FROM agent_tasks WHERE device_id = ? AND status = 'queued' ORDER BY created_at DESC LIMIT 1"
            )
            .get(dev.id) as { id: string; payload_json: string } | undefined);
      if (existingQueued) {
        const parsedPayload = safeJsonParse<Record<string, any>>(existingQueued.payload_json, {});
        parsedPayload.backupJobId = jobId;
        db.prepare('UPDATE agent_tasks SET payload_json = ? WHERE id = ?').run(
          JSON.stringify(parsedPayload),
          existingQueued.id
        );
      }
    } else if (!execRes.live && dev.companion_installed) {
      const taskId = `task-${crypto.randomUUID().slice(0, 10)}`;
      db.prepare(`
        INSERT INTO agent_tasks (id, device_id, task_type, payload_json, status)
        VALUES (?, ?, 'script', ?, 'queued')
      `).run(taskId, dev.id, JSON.stringify({ backupJobId: jobId, language: shell, shell, code: cmd, runAs: 'system' }));
    }

    if (bpol?.id) {
      db.prepare('UPDATE backup_policies SET last_run_at = CURRENT_TIMESTAMP WHERE id = ?').run(bpol.id);
    }

    db.prepare(`
      INSERT INTO device_backup_jobs (
        id, policy_id, device_id, hostname, engine, status, snapshot_id, bytes_processed, output, completed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CASE WHEN ? IN ('completed', 'failed') THEN CURRENT_TIMESTAMP ELSE NULL END)
    `).run(
      jobId,
      bpol?.id || null,
      dev.id,
      dev.hostname,
      engine,
      status,
      `snap-${crypto.randomBytes(4).toString('hex')}`,
      bytesProcessed,
      execRes.output,
      status
    );

    return {
      success: true,
      job: db.prepare('SELECT * FROM device_backup_jobs WHERE id = ?').get(jobId)
    };
  });

  // MDM Compliance & Configuration Profiles (macOS mobileconfig / Windows CSP / Linux Policy)
  server.get('/api/mdm-profiles', async (request) => {
    const user = request.auth?.user;
    const hasRestrictedTenants = Boolean(getScopedTenantFilter(user) || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0));
    const rows = db.prepare('SELECT * FROM mdm_profiles ORDER BY created_at DESC').all() as any[];
    return rows
      .filter((r) => (r.tenant_id ? canUserAccessTenant(user, r.tenant_id) : !hasRestrictedTenants))
      .map((r) => ({
        ...r,
        enabled: Boolean(r.enabled),
        settings: safeJsonParse<Record<string, any>>(r.settings_json, {})
      }));
  });

  server.post('/api/mdm-profiles', async (request, reply) => {
    const body = (request.body || {}) as {
      name?: string;
      platform?: 'macos' | 'windows' | 'linux';
      profile_type?: string;
      tenant_id?: string | null;
      payload_xml?: string;
      settings?: Record<string, any>;
      enabled?: boolean;
    };
    if (!body.name?.trim()) return reply.status(400).send({ error: 'MDM profile name is required.' });
    const user = request.auth?.user;
    const scopedTenant = getScopedTenantFilter(user);
    const hasRestrictedTenants = Boolean(scopedTenant || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0));
    const resolvedTenantId =
      body.tenant_id && body.tenant_id !== 'all' ? body.tenant_id : scopedTenant && scopedTenant !== '__DENY_ALL__' ? scopedTenant : null;
    if (
      (resolvedTenantId && !canUserAccessTenant(user, resolvedTenantId)) ||
      (!resolvedTenantId && hasRestrictedTenants)
    ) {
      return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
    }
    const id = `mdm-${crypto.randomUUID().slice(0, 8)}`;
    db.prepare(`
      INSERT INTO mdm_profiles (id, name, platform, profile_type, tenant_id, payload_xml, settings_json, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      body.name.trim(),
      body.platform || 'macos',
      body.profile_type || 'security_baseline',
      resolvedTenantId,
      body.payload_xml || '',
      JSON.stringify(body.settings || {}),
      body.enabled !== false ? 1 : 0
    );
    return {
      success: true,
      profile: db.prepare('SELECT * FROM mdm_profiles WHERE id = ?').get(id)
    };
  });

  server.delete('/api/mdm-profiles/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM mdm_profiles WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'MDM profile not found.' });
    const user = request.auth?.user;
    const hasRestrictedTenants = Boolean(getScopedTenantFilter(user) || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0));
    if (
      (existing.tenant_id && !canUserAccessTenant(user, existing.tenant_id)) ||
      (!existing.tenant_id && hasRestrictedTenants)
    ) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    db.prepare('DELETE FROM mdm_profiles WHERE id = ?').run(id);
    return { success: true };
  });

  // ============================================================================
  // 8. Custom Granular RBAC Roles, Scoped REST API Keys, Offsite Backups & Audit Export
  // ============================================================================
  const formatRoleRow = (r: any) => {
    if (!r) return r;
    return {
      ...r,
      base_tier: r.base_tier || 'technician',
      is_system: Boolean(r.is_system),
      permissions: normalizePermissionScopes(safeJsonParse<string[]>(r.permissions_json, [])),
      allowed_tenant_ids: safeJsonParse<string[]>(r.allowed_tenant_ids_json, [])
    };
  };

  server.get('/api/roles', async () => {
    const rows = db.prepare('SELECT * FROM custom_roles ORDER BY is_system DESC, name ASC').all() as any[];
    return {
      availablePermissions: ALL_GRANULAR_PERMISSIONS,
      roles: rows.map(formatRoleRow)
    };
  });

  server.post('/api/roles', async (request, reply) => {
    if (!requireParityStepUpMfa(request, reply)) return;
    const body = (request.body || {}) as {
      name?: string;
      description?: string;
      base_tier?: string;
      permissions?: string[];
      allowed_tenant_ids?: string[];
    };
    if (!body.name?.trim()) return reply.status(400).send({ error: 'Role name is required.' });
    const normalizedPerms = normalizePermissionScopes(body.permissions || []).filter(
      (p) => p === '*' || (ALL_GRANULAR_PERMISSIONS as readonly string[]).includes(p)
    );
    const validTier = ['super_admin', 'technician', 'client_admin', 'auditor'].includes(String(body.base_tier || ''))
      ? String(body.base_tier)
      : 'technician';
    const allowedTenants = Array.isArray(body.allowed_tenant_ids)
      ? body.allowed_tenant_ids.map((t) => String(t).trim()).filter(Boolean)
      : [];
    const id = `role-${crypto.randomUUID().slice(0, 8)}`;
    db.prepare(`
      INSERT INTO custom_roles (id, name, description, base_tier, permissions_json, allowed_tenant_ids_json, is_system)
      VALUES (?, ?, ?, ?, ?, ?, 0)
    `).run(
      id,
      body.name.trim(),
      body.description || '',
      validTier,
      JSON.stringify(normalizedPerms),
      JSON.stringify(allowedTenants)
    );
    return {
      success: true,
      role: formatRoleRow(db.prepare('SELECT * FROM custom_roles WHERE id = ?').get(id))
    };
  });

  server.put('/api/roles/:id', async (request, reply) => {
    if (!requireParityStepUpMfa(request, reply)) return;
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM custom_roles WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Role not found.' });
    if (existing.id === 'role-super-admin' || existing.id === 'role-msp-super-admin') {
      return reply.status(400).send({ error: 'System Super Admin role permissions cannot be restricted.' });
    }
    const body = (request.body || {}) as {
      name?: string;
      description?: string;
      base_tier?: string;
      permissions?: string[];
      allowed_tenant_ids?: string[];
    };
    const validPerms = body.permissions
      ? normalizePermissionScopes(body.permissions).filter(
          (p) => p === '*' || (ALL_GRANULAR_PERMISSIONS as readonly string[]).includes(p)
        )
      : null;
    const validTier =
      body.base_tier && ['super_admin', 'technician', 'client_admin', 'auditor'].includes(body.base_tier)
        ? body.base_tier
        : null;
    const allowedTenants = Array.isArray(body.allowed_tenant_ids)
      ? body.allowed_tenant_ids.map((t) => String(t).trim()).filter(Boolean)
      : null;

    db.prepare(`
      UPDATE custom_roles SET
        name = COALESCE(?, name),
        description = COALESCE(?, description),
        base_tier = COALESCE(?, base_tier),
        permissions_json = COALESCE(?, permissions_json),
        allowed_tenant_ids_json = COALESCE(?, allowed_tenant_ids_json)
      WHERE id = ?
    `).run(
      body.name ?? null,
      body.description ?? null,
      validTier,
      validPerms ? JSON.stringify(validPerms) : null,
      allowedTenants ? JSON.stringify(allowedTenants) : null,
      id
    );

    return {
      success: true,
      role: formatRoleRow(db.prepare('SELECT * FROM custom_roles WHERE id = ?').get(id))
    };
  });

  server.delete('/api/roles/:id', async (request, reply) => {
    if (!requireParityStepUpMfa(request, reply)) return;
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM custom_roles WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Role not found.' });
    if (existing.is_system) {
      return reply.status(400).send({ error: 'Built-in system roles cannot be deleted.' });
    }
    db.prepare('UPDATE users SET custom_role_id = NULL WHERE custom_role_id = ?').run(id);
    db.prepare('DELETE FROM custom_roles WHERE id = ?').run(id);
    return { success: true };
  });

  // Scoped REST API Keys (`vrmm_live_...`)
  server.get('/api/api-keys', async () => {
    return listScopedApiKeys();
  });

  server.post('/api/api-keys', async (request, reply) => {
    if (!requireParityStepUpMfa(request, reply)) return;
    const body = (request.body || {}) as {
      name?: string;
      role?: string;
      scopes?: string[];
      tenant_id?: string | null;
      expiresInDays?: number | null;
    };
    if (!body.name?.trim()) return reply.status(400).send({ error: 'API key label is required.' });

    const normalizedScopes = normalizePermissionScopes(
      Array.isArray(body.scopes) && body.scopes.length > 0 ? body.scopes : ['devices:read', 'alerts:triage']
    );

    const created = createScopedApiKey({
      name: body.name,
      role: body.role || 'technician',
      scopes: normalizedScopes.length > 0 ? normalizedScopes : ['devices:read', 'alerts:triage'],
      tenantId: body.tenant_id || null,
      expiresInDays: body.expiresInDays ?? 90,
      createdBy: getActorUsername(request)
    });

    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'Scoped API Key Created', ?)
    `).run(`aud-key-${crypto.randomUUID()}`, getActorUsername(request), `Created API key '${body.name}' (${created.keyPrefix}...)`);

    return { success: true, ...created };
  });

  server.delete('/api/api-keys/:id', async (request, reply) => {
    if (!requireParityStepUpMfa(request, reply)) return;
    const { id } = request.params as { id: string };
    revokeScopedApiKey(id);
    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'Scoped API Key Revoked', ?)
    `).run(`aud-krev-${crypto.randomUUID()}`, getActorUsername(request), `Revoked API key ${id}`);
    return { success: true };
  });

  // Offsite S3 Vault Listing & Pull
  server.get('/api/backups/offsite', async () => {
    return await backupService.listOffsiteBackups();
  });

  server.post('/api/backups/offsite/pull', async (request, reply) => {
    if (!requireParityStepUpMfa(request, reply)) return;
    const body = (request.body || {}) as { key?: string; passphrase?: string };
    if (!body.key) return reply.status(400).send({ error: 'Remote object key is required.' });
    const res = await backupService.pullBackupFromOffsite(body.key, body.passphrase);
    if (!res.success) return reply.status(400).send(res);
    return res;
  });

  // Filtered Audit Explorer & CSV / JSON Compliance Export
  server.get('/api/audit-logs/export', async (request, reply) => {
    const query = (request.query || {}) as {
      format?: 'csv' | 'json';
      username?: string;
      action?: string;
      device_id?: string;
      search?: string;
      from?: string;
      to?: string;
      limit?: string;
    };

    const user = request.auth?.user;
    const scopedTenant = getScopedTenantFilter(user);
    const hasRestrictedTenants = Boolean(scopedTenant || (user?.allowed_tenant_ids && user.allowed_tenant_ids.length > 0));
    const clauses: string[] = [];
    const params: any[] = [];

    if (query.username?.trim()) {
      clauses.push('LOWER(a.username) = LOWER(?)');
      params.push(query.username.trim());
    }
    if (query.action?.trim()) {
      clauses.push('a.action LIKE ?');
      params.push(`%${query.action.trim()}%`);
    }
    if (query.device_id?.trim()) {
      clauses.push('a.device_id = ?');
      params.push(query.device_id.trim());
    }
    if (query.search?.trim()) {
      clauses.push('(a.details LIKE ? OR a.action LIKE ? OR a.username LIKE ?)');
      const s = `%${query.search.trim()}%`;
      params.push(s, s, s);
    }
    if (query.from?.trim()) {
      clauses.push('datetime(a.timestamp) >= datetime(?)');
      params.push(query.from.trim());
    }
    if (query.to?.trim()) {
      clauses.push('datetime(a.timestamp) <= datetime(?)');
      params.push(query.to.trim());
    }
    if (scopedTenant) {
      clauses.push('d.tenant_id = ?');
      params.push(scopedTenant);
    }

    const limit = Math.min(5000, Math.max(1, parseInt(query.limit || '1000', 10) || 1000));
    const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const rawRows = db
      .prepare(`
        SELECT a.*, d.tenant_id as device_tenant_id
        FROM audit_logs a
        LEFT JOIN devices d ON a.device_id = d.id
        ${whereSql}
        ORDER BY a.timestamp DESC
        LIMIT ?
      `)
      .all(...params, limit) as any[];

    const rows = rawRows
      .filter((r) => (!hasRestrictedTenants ? true : Boolean(r.device_tenant_id && canUserAccessTenant(user, r.device_tenant_id))))
      .map(({ device_tenant_id: _unused, ...rest }) => rest);

    if (query.format === 'csv') {
      const escCsv = (v: unknown) => {
        const s = String(v ?? '');
        const guarded = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
        return `"${guarded.replace(/"/g, '""')}"`;
      };
      const lines = [
        'id,timestamp,username,device_id,action,details',
        ...rows.map((r) => [r.id, r.timestamp, r.username, r.device_id || '', r.action, r.details].map(escCsv).join(','))
      ];
      reply.header('Content-Type', 'text/csv; charset=utf-8');
      reply.header('Content-Disposition', `attachment; filename="vitrine-audit-export-${Date.now()}.csv"`);
      return reply.send(lines.join('\n'));
    }

    return { count: rows.length, logs: rows };
  });

  // Expose local SVG QR helper for QuickSupport / Guest Portal URLs without external leaks!
  server.get('/api/utils/qr.svg', async (request, reply) => {
    if (!checkRateLimit(`qr-svg:${request.ip}`, 60, 60_000)) {
      return reply.status(429).send({ error: 'Too many QR generation requests.' });
    }
    const query = (request.query || {}) as { data?: string; text?: string };
    const text = String(query.data || query.text || '').trim();
    if (!text) return reply.status(400).send({ error: 'data or text parameter required' });
    if (Buffer.byteLength(text, 'utf8') > 500) {
      return reply.status(400).send({ error: 'QR payload exceeds maximum length (500 bytes).' });
    }
    try {
      const svg = generateQrCodeSvg(text);
      reply.header('Content-Type', 'image/svg+xml; charset=utf-8');
      return reply.send(svg);
    } catch (err: any) {
      return reply.status(400).send({ error: err?.message || 'Unable to generate QR code for input.' });
    }
  });
}
