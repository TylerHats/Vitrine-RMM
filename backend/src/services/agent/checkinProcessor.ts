import crypto from 'crypto';
import net from 'net';
import { db } from '../../db/index.js';
import { encryptVaultSecret } from '../vault/index.js';
import { handleAgentCheckInOrWake } from '../offboarding/index.js';
import { resolveEffectiveDevicePolicy } from '../policy/index.js';
import { recordDeviceTelemetrySample } from '../telemetry/index.js';

export interface AgentCheckinPayload {
  deviceId?: string;
  hostname?: string;
  osType?: string;
  osVersion?: string;
  osBuild?: string;
  macAddress?: string;
  serialNumber?: string;
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
  netRxMbps?: number;
  netTxMbps?: number;
  networkMbps?: number;
  hardwareDetails?: Record<string, any>;
  companionVersion?: string;
  agentVariant?: string;
  ipAddress?: string;
  publicIp?: string;
  gatewayIp?: string;
  interfaceName?: string;
  arpNeighbors?: Array<{ ip: string; mac: string }>;
  installedSoftware?: Array<{ name: string; version: string; publisher?: string }>;
}

export interface AgentTaskResultPayload {
  exitCode?: number;
  stdout?: string;
  stderr?: string;
  output?: string;
  status?: 'completed' | 'failed';
  durationMs?: number;
}

function safeJsonParse<T>(raw: string | null | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export function normalizeIpAddress(rawIp?: string | null): string {
  const cleaned = String(rawIp || '').trim();
  if (!cleaned) return '';
  if (cleaned.startsWith('::ffff:')) {
    return cleaned.slice(7).trim();
  }
  return cleaned;
}

export function isLoopbackIp(rawIp?: string | null): boolean {
  const ip = normalizeIpAddress(rawIp).toLowerCase();
  return ip === '127.0.0.1' || ip === '::1' || ip === 'localhost' || ip.startsWith('127.');
}

export function isPrivateOrLoopbackIp(rawIp?: string | null): boolean {
  const ip = normalizeIpAddress(rawIp).toLowerCase();
  if (!ip) return true;
  if (isLoopbackIp(ip)) return true;
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
    return false;
  }
  if (net.isIPv6(ip)) {
    return ip === '::1' || ip.startsWith('fe80:') || ip.startsWith('fc') || ip.startsWith('fd');
  }
  return true;
}

export function resolvePublicIpForDevice(
  reportedPublicIp?: string | null,
  remoteIp?: string | null,
  existingPublicIp?: string | null
): string {
  const normReported = normalizeIpAddress(reportedPublicIp);
  if (normReported && net.isIP(normReported) !== 0 && !isPrivateOrLoopbackIp(normReported)) {
    return normReported;
  }
  const normRemote = normalizeIpAddress(remoteIp);
  if (normRemote && net.isIP(normRemote) !== 0 && !isLoopbackIp(normRemote)) {
    if (!isPrivateOrLoopbackIp(normRemote) || !existingPublicIp) {
      return normRemote;
    }
  }
  if (normReported && net.isIP(normReported) !== 0 && !isLoopbackIp(normReported) && !existingPublicIp) {
    return normReported;
  }
  return '';
}

export function buildPendingTasksPayload(
  pendingTasks: any[],
  isSigningEnabled: boolean
): Array<{ id: string; type: string; task_type: string; payload: Record<string, any>; payload_json: string }> {
  return pendingTasks.map((t) => {
    const payload = safeJsonParse<Record<string, any>>(t.payload_json, {});
    if (
      !isSigningEnabled &&
      !payload.executionPolicy &&
      ['script', 'run_script', 'patch_scan', 'patch_install', 'software_deploy', 'backup_job'].includes(
        String(t.task_type || '')
      )
    ) {
      payload.executionPolicy = 'Bypass';
    }
    return {
      id: t.id,
      type: t.task_type,
      task_type: t.task_type,
      payload,
      payload_json: JSON.stringify(payload)
    };
  });
}

export function processAgentCheckin(
  dev: any,
  body: AgentCheckinPayload,
  remoteIp: string,
  transport: 'http' | 'wss' = 'http'
) {
  const encryptedRecoveryKey =
    body.bitlockerRecoveryKey && String(body.bitlockerRecoveryKey).trim().length >= 8
      ? encryptVaultSecret(String(body.bitlockerRecoveryKey).trim())
      : null;

  const reqIp = normalizeIpAddress(remoteIp);
  const reqIsLoopback = isLoopbackIp(reqIp);
  const rawIp = body.ipAddress != null ? normalizeIpAddress(body.ipAddress) : '';
  const reportedIsLoopback = isLoopbackIp(rawIp);
  const safeCheckinIp = rawIp && (!reportedIsLoopback || reqIsLoopback) ? rawIp : null;
  const resolvedPublicIp = resolvePublicIpForDevice(body.publicIp, remoteIp, dev.public_ip);

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

  const hwSys = body.hardwareDetails?.system;
  const hwCpu = body.hardwareDetails?.cpu;
  const hwNet = body.hardwareDetails?.network;
  const resolvedSerial = String(hwSys?.serialNumber || body.serialNumber || '').trim();
  const resolvedManufacturer = String(hwSys?.manufacturer || '').trim();
  const resolvedModel = String(hwSys?.model || '').trim();
  const resolvedBiosVer = String(hwSys?.biosVersion || '').trim();
  const resolvedCpuModel = String(hwCpu?.model || '').trim();
  const resolvedCpuCores =
    hwCpu?.logicalCores != null && Number.isFinite(Number(hwCpu.logicalCores)) && Number(hwCpu.logicalCores) > 0
      ? Math.floor(Number(hwCpu.logicalCores))
      : null;
  const resolvedMac = String(body.macAddress || hwNet?.primaryMac || '').trim();
  const resolvedVariant = body.agentVariant ? String(body.agentVariant).trim().slice(0, 48) : null;

  db.prepare(`
    UPDATE devices SET
      status = CASE WHEN quarantined = 1 THEN 'isolated' ELSE 'online' END,
      companion_installed = 1,
      companion_version = COALESCE(?, companion_version),
      os_version = COALESCE(?, os_version),
      os_build = COALESCE(NULLIF(?, ''), os_build),
      ip_address = COALESCE(?, ip_address),
      public_ip = COALESCE(NULLIF(?, ''), public_ip),
      mac_address = COALESCE(NULLIF(?, ''), mac_address),
      serial_number = COALESCE(NULLIF(?, ''), serial_number),
      manufacturer = COALESCE(NULLIF(?, ''), manufacturer),
      model = COALESCE(NULLIF(?, ''), model),
      bios_version = COALESCE(NULLIF(?, ''), bios_version),
      cpu_model = COALESCE(NULLIF(?, ''), cpu_model),
      cpu_cores = COALESCE(?, cpu_cores),
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
      agent_transport = ?,
      ws_connected = ?,
      agent_binary_variant = COALESCE(NULLIF(?, ''), agent_binary_variant),
      last_seen = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(
    body.companionVersion || '2.8.0',
    body.osVersion ?? null,
    body.osBuild ?? '',
    safeCheckinIp,
    resolvedPublicIp,
    resolvedMac,
    resolvedSerial,
    resolvedManufacturer,
    resolvedModel,
    resolvedBiosVer,
    resolvedCpuModel,
    resolvedCpuCores,
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
    transport,
    transport === 'wss' ? 1 : 0,
    resolvedVariant || '',
    dev.id
  );

  const parsedNetRx =
    body.netRxMbps != null && Number.isFinite(Number(body.netRxMbps))
      ? Number(body.netRxMbps)
      : body.networkMbps != null && Number.isFinite(Number(body.networkMbps))
        ? Number(body.networkMbps)
        : null;
  const parsedNetTx =
    body.netTxMbps != null && Number.isFinite(Number(body.netTxMbps)) ? Number(body.netTxMbps) : null;

  recordDeviceTelemetrySample(dev.id, {
    cpuUsage: body.cpuUsage != null && Number.isFinite(Number(body.cpuUsage)) ? Number(body.cpuUsage) : null,
    ramUsedGb: resolvedRamUsedGb,
    ramTotalGb: body.ramTotalGb != null && Number.isFinite(Number(body.ramTotalGb)) ? Number(body.ramTotalGb) : null,
    diskFreeGb: resolvedDiskFreeGb,
    diskTotalGb: body.diskTotalGb != null && Number.isFinite(Number(body.diskTotalGb)) ? Number(body.diskTotalGb) : null,
    netRxMbps: parsedNetRx,
    netTxMbps: parsedNetTx,
    uptimeSeconds:
      body.uptimeSeconds != null && Number.isFinite(Number(body.uptimeSeconds))
        ? Math.floor(Number(body.uptimeSeconds))
        : null,
    loggedInUser: body.loggedInUser ?? null,
    hardwareDetails: body.hardwareDetails ?? null
  });

  if (body.gatewayIp || safeCheckinIp || resolvedPublicIp) {
    const lastNet = db
      .prepare('SELECT local_ip, gateway_ip, public_ip FROM network_history WHERE device_id = ? ORDER BY connected_at DESC LIMIT 1')
      .get(dev.id) as { local_ip?: string; gateway_ip?: string; public_ip?: string } | undefined;
    const curIp = safeCheckinIp || dev.ip_address;
    const curPub = resolvedPublicIp || reqIp || '';
    if (
      !lastNet ||
      lastNet.local_ip !== curIp ||
      (body.gatewayIp && lastNet.gateway_ip !== body.gatewayIp) ||
      (curPub && lastNet.public_ip !== curPub)
    ) {
      db.prepare(`
        INSERT INTO network_history (id, device_id, interface_name, local_ip, gateway_ip, public_ip)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(
        `nh-${crypto.randomUUID().slice(0, 8)}`,
        dev.id,
        body.interfaceName || 'primary',
        curIp,
        body.gatewayIp || '',
        curPub
      );
    }
  }

  if (Array.isArray(body.installedSoftware) && body.installedSoftware.length > 0) {
    const syncTx = db.transaction((items: Array<{ name: string; version: string; publisher?: string }>) => {
      for (const sw of items.slice(0, 300)) {
        if (!sw.name) continue;
        const cleanName = String(sw.name).trim().slice(0, 180);
        if (!cleanName) continue;
        const existing = db
          .prepare('SELECT id FROM software_inventory WHERE device_id = ? AND LOWER(name) = LOWER(?) LIMIT 1')
          .get(dev.id, cleanName) as { id: string } | undefined;
        if (existing) {
          db.prepare('UPDATE software_inventory SET version = ?, publisher = COALESCE(?, publisher) WHERE id = ?').run(
            String(sw.version || 'unknown').slice(0, 80),
            sw.publisher ? String(sw.publisher).slice(0, 120) : null,
            existing.id
          );
        } else {
          db.prepare(`
            INSERT INTO software_inventory (id, device_id, name, version, publisher, install_date)
            VALUES (?, ?, ?, ?, ?, date('now'))
          `).run(
            `sw-${crypto.randomUUID().slice(0, 8)}`,
            dev.id,
            cleanName,
            String(sw.version || 'unknown').slice(0, 80),
            String(sw.publisher || 'Installed Package').slice(0, 120)
          );
        }
      }
    });
    syncTx(body.installedSoftware);
  }

  const lifecycle = handleAgentCheckInOrWake(dev.id, 'wake_checkin');

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

  let trayConfig: Record<string, unknown> | null = null;
  try {
    const effPolicy = resolveEffectiveDevicePolicy(dev.id);
    trayConfig = {
      brandName: effPolicy.trayBrandName,
      iconUrl: effPolicy.trayIconUrl,
      themeMode: effPolicy.trayThemeMode,
      enabled: effPolicy.trayEnabled,
      tooltip: effPolicy.trayTooltip,
      supportUrl: effPolicy.traySupportUrl,
      supportPhone: effPolicy.traySupportPhone,
      supportEmail: effPolicy.traySupportEmail,
      menuItems: effPolicy.trayMenuItems
    };
  } catch {
    trayConfig = null;
  }

  const signingRow =
    pendingTasks.length > 0
      ? ((db.prepare('SELECT code_signing_enabled FROM settings WHERE id = 1').get() || {}) as {
          code_signing_enabled?: number;
        })
      : null;
  const isSigningEnabled = Boolean(signingRow?.code_signing_enabled);

  return {
    success: true,
    deviceId: dev.id,
    lifecycle,
    trayConfig,
    tasks: buildPendingTasksPayload(pendingTasks, isSigningEnabled),
    unreadChats,
    timestamp: new Date().toISOString()
  };
}

export function processAgentTaskResult(task: any, body: AgentTaskResultPayload) {
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
    task.id
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

  return { success: true, taskId: task.id, status: finalStatus };
}

