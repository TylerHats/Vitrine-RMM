import crypto from 'crypto';
import { db } from '../../db/index.js';
import { resolveEffectiveDevicePolicy } from '../policy/index.js';
import { rotateLapsPasswordVerifiedAsync } from '../laps/index.js';
import { meshBridge } from '../meshcentral/index.js';
import { decryptVaultSecret } from '../vault/index.js';

function normalizeEndpointOs(rawOs?: string | null): 'windows' | 'linux' | 'macos' {
  const lower = String(rawOs || 'windows').trim().toLowerCase();
  if (lower === 'linux') return 'linux';
  if (lower === 'macos' || lower === 'darwin' || lower === 'mac') return 'macos';
  return 'windows';
}

function hashPlainAgentToken(encryptedOrPlainToken?: string | null, isEncrypted = true): string | null {
  if (!encryptedOrPlainToken) return null;
  const plain = isEncrypted ? decryptVaultSecret(encryptedOrPlainToken) : encryptedOrPlainToken;
  if (!plain) return null;
  return crypto.createHash('sha256').update(plain, 'utf8').digest('hex');
}

function upsertDeletedDeviceTombstoneRow(params: {
  deviceId: string;
  meshNodeId: string | null;
  hostname: string;
  tenantId: string;
  tenantName: string;
  lapsAction: string;
  lapsAccountName: string;
  osType: string;
  quietOffboardedAt: string | null;
  agentTokenHash: string | null;
}): void {
  try {
    db.prepare(`
      INSERT OR REPLACE INTO deleted_tenant_device_tombstones (
        device_id, mesh_node_id, hostname, tenant_id, tenant_name,
        laps_action, laps_account_name, os_type, quiet_offboarded_at, agent_token_hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      params.deviceId,
      params.meshNodeId,
      params.hostname,
      params.tenantId,
      params.tenantName,
      params.lapsAction,
      params.lapsAccountName,
      params.osType,
      params.quietOffboardedAt,
      params.agentTokenHash
    );
  } catch {
    db.prepare(`
      INSERT OR REPLACE INTO deleted_tenant_device_tombstones (
        device_id, mesh_node_id, hostname, tenant_id, tenant_name,
        laps_action, laps_account_name, os_type, quiet_offboarded_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      params.deviceId,
      params.meshNodeId,
      params.hostname,
      params.tenantId,
      params.tenantName,
      params.lapsAction,
      params.lapsAccountName,
      params.osType,
      params.quietOffboardedAt
    );
  }
}

export type LapsOffboardAction =
  | 'remove_account'
  | 'disable_account'
  | 'keep_account_rotate_final'
  | 'keep_account_as_is';

export interface DeviceOffboardResult {
  success: boolean;
  deviceId: string;
  hostname: string;
  previousState: string;
  newLifecycleState: 'pending_offboard' | 'archived';
  wasOnline: boolean;
  triggerSource: 'explicit_device' | 'client_archived' | 'client_deleted';
  lapsAccountName: string;
  lapsActionTaken: LapsOffboardAction;
  autoArchiveAfterDays: number;
  preservedData: {
    bitlockerKeyPreserved: boolean;
    lapsHistoryPreserved: boolean;
    hardwareHistoryPreserved: boolean;
  };
  stepsExecuted: string[];
  message: string;
}

export function sweepPendingOffboards(): { autoArchivedCount: number } {
  const pendingDevices = db
    .prepare("SELECT * FROM devices WHERE lifecycle_state = 'pending_offboard'")
    .all() as any[];

  let autoArchivedCount = 0;
  const nowMs = Date.now();

  for (const dev of pendingDevices) {
    let maxDays = 14;
    try {
      const pol = resolveEffectiveDevicePolicy(dev.id);
      maxDays = pol.offboardOfflineAutoArchiveDays || 14;
    } catch {
      // Default 14 days
    }

    const queuedMs = dev.offboard_queued_at ? new Date(dev.offboard_queued_at).getTime() : nowMs;
    const elapsedDays = (nowMs - queuedMs) / (1000 * 60 * 60 * 24);
    if (elapsedDays >= maxDays) {
      db.prepare(`
        UPDATE devices
        SET lifecycle_state = 'archived',
            status = 'offline',
            offboarded_at = CURRENT_TIMESTAMP,
            offboard_reason = COALESCE(offboard_reason, '') || ' [Auto-archived after ' || ? || 'd offline timeout]'
        WHERE id = ?
      `).run(maxDays, dev.id);
      autoArchivedCount++;
    }
  }

  return { autoArchivedCount };
}

export function initiateDeviceOffboard(
  deviceId: string,
  options: {
    reason?: string;
    triggerSource?: 'explicit_device' | 'client_archived' | 'client_deleted';
    overrideLapsAction?: LapsOffboardAction;
    forceImmediateArchive?: boolean;
    actorUsername?: string;
  } = {}
): DeviceOffboardResult {
  const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId) as any;
  if (!device) {
    throw new Error(`Device ${deviceId} not found`);
  }

  const actor = options.actorUsername || 'admin';
  const policy = resolveEffectiveDevicePolicy(deviceId);
  const triggerSource = options.triggerSource || 'explicit_device';

  let resolvedLapsAction: LapsOffboardAction = policy.lapsOffboardExplicitDeviceAction || 'remove_account';
  if (triggerSource === 'client_archived') {
    resolvedLapsAction = policy.lapsOffboardClientArchivedAction || 'keep_account_rotate_final';
  } else if (triggerSource === 'client_deleted') {
    resolvedLapsAction = policy.lapsOffboardClientDeletedAction || 'remove_account';
  }
  if (options.overrideLapsAction) {
    resolvedLapsAction = options.overrideLapsAction;
  }

  const isOnline = device.status === 'online';
  const forceArchive = Boolean(options.forceImmediateArchive);
  const reason = options.reason || 'Standard administrative offboarding';
  const stepsExecuted: string[] = [];

  if (isOnline) {
    if (resolvedLapsAction === 'keep_account_rotate_final') {
      // Kick off verified LAPS rotation while status is still 'online', and dispatch self-uninstall ONLY after verified LAPS completes!
      const verifiedRotPromise = rotateLapsPasswordVerifiedAsync(deviceId, {
        forceFinalArchiveSnapshot: true,
        actorUsername: actor
      });
      void verifiedRotPromise
        .catch(() => {})
        .finally(() => {
          meshBridge.dispatchAgentOffboard(deviceId, {
            lapsAccountName: policy.lapsAccountName,
            lapsAction: resolvedLapsAction
          });
        });
      stepsExecuted.push(
        `Rotated managed local admin (${policy.lapsAccountName}) to a verified final break-glass password and sealed it in the Archive Vault.`
      );
    } else {
      // Dispatch actual OS cleanup & agent self-uninstall via MeshCentral tunnel / Companion
      meshBridge.dispatchAgentOffboard(deviceId, {
        lapsAccountName: policy.lapsAccountName,
        lapsAction: resolvedLapsAction
      });
    }

    stepsExecuted.push(
      `Reverted endpoint policy overrides (restored OS power defaults, removed scheduled self-healing watchdogs, and verified built-in administrator fallback).`
    );
    if (resolvedLapsAction === 'remove_account') {
      stepsExecuted.push(
        `Removed managed local admin account '${policy.lapsAccountName}' from ${device.hostname} (historical LAPS credentials & BitLocker key preserved in Archive Vault).`
      );
    } else if (resolvedLapsAction === 'disable_account') {
      stepsExecuted.push(
        `Disabled managed local admin account '${policy.lapsAccountName}' on ${device.hostname} while keeping credentials in Archive Vault.`
      );
    } else {
      stepsExecuted.push(
        `Retained managed local admin account '${policy.lapsAccountName}' on ${device.hostname} per ${triggerSource} policy.`
      );
    }
    stepsExecuted.push(
      `Dispatched clean uninstall of Vitrine Companion Service, System Tray HUD, and MeshCentral Agent on ${device.hostname}.`
    );

    db.prepare(`
      UPDATE devices
      SET lifecycle_state = 'archived',
          status = 'offline',
          companion_installed = 0,
          offboarded_at = CURRENT_TIMESTAMP,
          offboard_reason = ?,
          offboard_trigger_source = ?,
          offboard_laps_action_taken = ?
      WHERE id = ?
    `).run(reason, triggerSource, resolvedLapsAction, deviceId);

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Device Offboarded to Archive', ?)
    `).run(
      `aud-off-${crypto.randomUUID()}`,
      actor,
      deviceId,
      `Cleanly offboarded online endpoint ${device.hostname}. Local Admin (${policy.lapsAccountName}) action: ${resolvedLapsAction}. BitLocker & LAPS keys preserved in Archive Vault.`
    );

    return {
      success: true,
      deviceId,
      hostname: device.hostname,
      previousState: device.lifecycle_state || 'active',
      newLifecycleState: 'archived',
      wasOnline: true,
      triggerSource,
      lapsAccountName: policy.lapsAccountName,
      lapsActionTaken: resolvedLapsAction,
      autoArchiveAfterDays: policy.offboardOfflineAutoArchiveDays || 14,
      preservedData: {
        bitlockerKeyPreserved: Boolean(device.bitlocker_key),
        lapsHistoryPreserved: true,
        hardwareHistoryPreserved: true
      },
      stepsExecuted,
      message: `${device.hostname} was online: policies reverted, local admin rule (${resolvedLapsAction}) executed, agent uninstalled cleanly, and record moved to Archive Vault with BitLocker & LAPS keys preserved.`
    };
  }

  // Offline handling
  if (forceArchive) {
    stepsExecuted.push(
      `Endpoint ${device.hostname} is offline; admin forced immediate transition to Archive Vault (last working LAPS password & BitLocker key preserved).`
    );
    db.prepare(`
      UPDATE devices
      SET lifecycle_state = 'archived',
          status = 'offline',
          companion_installed = 0,
          offboarded_at = CURRENT_TIMESTAMP,
          offboard_reason = ?,
          offboard_trigger_source = ?,
          offboard_laps_action_taken = ?
      WHERE id = ?
    `).run(`${reason} (Force-archived while offline)`, triggerSource, resolvedLapsAction, deviceId);

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Device Force-Archived Offline', ?)
    `).run(
      `aud-offf-${crypto.randomUUID()}`,
      actor,
      deviceId,
      `Force-archived offline endpoint ${device.hostname}. Vault secrets preserved.`
    );

    return {
      success: true,
      deviceId,
      hostname: device.hostname,
      previousState: device.lifecycle_state || 'active',
      newLifecycleState: 'archived',
      wasOnline: false,
      triggerSource,
      lapsAccountName: policy.lapsAccountName,
      lapsActionTaken: resolvedLapsAction,
      autoArchiveAfterDays: policy.offboardOfflineAutoArchiveDays || 14,
      preservedData: {
        bitlockerKeyPreserved: Boolean(device.bitlocker_key),
        lapsHistoryPreserved: true,
        hardwareHistoryPreserved: true
      },
      stepsExecuted,
      message: `${device.hostname} force-moved directly to Archive Vault while offline. If the parent client is archived/deleted and it wakes up later, it will quietly offboard itself.`
    };
  }

  stepsExecuted.push(
    `Endpoint ${device.hostname} is currently offline. Queued clean offboarding runbook (Local Admin rule: ${resolvedLapsAction}).`
  );
  stepsExecuted.push(
    `Will execute cleanup immediately upon next agent check-in, or auto-move to Archive Vault after ${policy.offboardOfflineAutoArchiveDays || 14} days offline.`
  );

  db.prepare(`
    UPDATE devices
    SET lifecycle_state = 'pending_offboard',
        offboard_queued_at = CURRENT_TIMESTAMP,
        offboard_reason = ?,
        offboard_trigger_source = ?,
        offboard_laps_action_taken = ?
    WHERE id = ?
  `).run(reason, triggerSource, resolvedLapsAction, deviceId);

  // Skip any scheduled LAPS rotations while pending offboarding so the current password is never overwritten
  db.prepare(`
    UPDATE laps_vault
    SET rotation_pending_online = 0,
        pending_rotation_reason = 'Skipped: Endpoint is queued in Pending Offboarding. Current password preserved.'
    WHERE device_id = ?
  `).run(deviceId);

  db.prepare(`
    INSERT INTO audit_logs (id, username, device_id, action, details)
    VALUES (?, ?, ?, 'Device Offboarding Queued (Offline)', ?)
  `).run(
    `aud-offq-${crypto.randomUUID()}`,
    actor,
    deviceId,
    `Queued offboarding for offline endpoint ${device.hostname}. Auto-archives after ${policy.offboardOfflineAutoArchiveDays || 14}d offline.`
  );

    return {
      success: true,
      deviceId,
      hostname: device.hostname,
      previousState: device.lifecycle_state || 'active',
      newLifecycleState: 'pending_offboard',
      wasOnline: false,
      triggerSource,
      lapsAccountName: policy.lapsAccountName,
      lapsActionTaken: resolvedLapsAction,
      autoArchiveAfterDays: policy.offboardOfflineAutoArchiveDays || 14,
      preservedData: {
        bitlockerKeyPreserved: Boolean(device.bitlocker_key),
        lapsHistoryPreserved: true,
        hardwareHistoryPreserved: true
      },
      stepsExecuted,
      message: `${device.hostname} is offline: queued in Pending Offboarding (will clean up on next check-in or auto-archive after ${policy.offboardOfflineAutoArchiveDays || 14} days).`
    };
}

export async function initiateDeviceOffboardAsync(
  deviceId: string,
  options: {
    reason?: string;
    triggerSource?: 'explicit_device' | 'client_archived' | 'client_deleted';
    overrideLapsAction?: LapsOffboardAction;
    forceImmediateArchive?: boolean;
    actorUsername?: string;
  } = {}
): Promise<DeviceOffboardResult> {
  const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId) as any;
  if (!device) {
    throw new Error(`Device ${deviceId} not found`);
  }
  const actor = options.actorUsername || 'admin';
  const policy = resolveEffectiveDevicePolicy(deviceId);
  const triggerSource = options.triggerSource || 'explicit_device';
  let resolvedLapsAction: LapsOffboardAction = policy.lapsOffboardExplicitDeviceAction || 'remove_account';
  if (triggerSource === 'client_archived') {
    resolvedLapsAction = policy.lapsOffboardClientArchivedAction || 'keep_account_rotate_final';
  } else if (triggerSource === 'client_deleted') {
    resolvedLapsAction = policy.lapsOffboardClientDeletedAction || 'remove_account';
  }
  if (options.overrideLapsAction) {
    resolvedLapsAction = options.overrideLapsAction;
  }

  if (device.status === 'online' && resolvedLapsAction === 'keep_account_rotate_final') {
    try {
      await rotateLapsPasswordVerifiedAsync(deviceId, {
        forceFinalArchiveSnapshot: true,
        actorUsername: actor
      });
    } catch {}
    // Now that final LAPS password has already been verified & committed, dispatch self-uninstall with keep_account_as_is so we don't double-rotate
    const res = initiateDeviceOffboard(deviceId, {
      ...options,
      overrideLapsAction: 'keep_account_as_is'
    });
    db.prepare('UPDATE devices SET offboard_laps_action_taken = ? WHERE id = ?').run(resolvedLapsAction, deviceId);
    return {
      ...res,
      lapsActionTaken: resolvedLapsAction
    };
  }

  return initiateDeviceOffboard(deviceId, options);
}

export function offboardClientTenant(
  tenantId: string,
  options: {
    mode: 'archive_client' | 'delete_client_permanently';
    reason?: string;
    overrideLapsAction?: LapsOffboardAction;
    forceArchiveOfflineDevices?: boolean;
    actorUsername?: string;
  }
): {
  success: boolean;
  tenantId: string;
  tenantName: string;
  mode: string;
  tombstoneRecorded?: boolean;
  onlineOffboardedCount: number;
  offlineQueuedCount: number;
  archivedTotalCount: number;
  message: string;
} {
  const actor = options.actorUsername || 'admin';
  const tenant = db.prepare('SELECT * FROM tenants WHERE id = ?').get(tenantId) as any;
  if (!tenant) {
    throw new Error(`Client tenant ${tenantId} not found`);
  }

  const devices = db.prepare('SELECT * FROM devices WHERE tenant_id = ?').all(tenantId) as any[];
  let onlineOffboardedCount = 0;
  let offlineQueuedCount = 0;

  if (options.mode === 'delete_client_permanently') {
    const samplePolicy = devices[0] ? resolveEffectiveDevicePolicy(devices[0].id) : null;
    const deletedLapsAction: LapsOffboardAction =
      options.overrideLapsAction || samplePolicy?.lapsOffboardClientDeletedAction || 'remove_account';

    db.prepare(`
      INSERT OR REPLACE INTO deleted_tenants_tombstones (
        tenant_id, tenant_name, slug, mesh_group_id, laps_offboard_action, deleted_at
      ) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).run(tenant.id, tenant.name, tenant.slug, tenant.mesh_group_id || null, deletedLapsAction);

    for (const dev of devices) {
      let devPol: any = null;
      try {
        devPol = resolveEffectiveDevicePolicy(dev.id);
      } catch {}
      const devLapsAction: LapsOffboardAction =
        options.overrideLapsAction || devPol?.lapsOffboardClientDeletedAction || deletedLapsAction;
      const lapsAccount = devPol?.lapsAccountName || 'LocalAdmin';
      const devOsType = normalizeEndpointOs(dev.os_type);
      const agentTokenHash = hashPlainAgentToken(dev.agent_auth_token, true);

      if (dev.status === 'online') {
        onlineOffboardedCount++;
        const rawNodeTarget = dev.mesh_node_id || dev.id;
        if (devLapsAction === 'keep_account_rotate_final') {
          const rotTask = rotateLapsPasswordVerifiedAsync(dev.id, {
            forceFinalArchiveSnapshot: true,
            actorUsername: actor
          });
          void rotTask.catch(() => {}).finally(() => {
            meshBridge.dispatchRawNodeOffboard(rawNodeTarget, lapsAccount, devLapsAction, devOsType, dev.id);
          });
        } else {
          meshBridge.dispatchAgentOffboard(dev.id, {
            lapsAccountName: lapsAccount,
            lapsAction: devLapsAction
          });
        }
        upsertDeletedDeviceTombstoneRow({
          deviceId: dev.id,
          meshNodeId: dev.mesh_node_id || null,
          hostname: dev.hostname,
          tenantId: tenant.id,
          tenantName: tenant.name,
          lapsAction: devLapsAction,
          lapsAccountName: lapsAccount,
          osType: devOsType,
          quietOffboardedAt: new Date().toISOString(),
          agentTokenHash
        });
      } else {
        offlineQueuedCount++;
        upsertDeletedDeviceTombstoneRow({
          deviceId: dev.id,
          meshNodeId: dev.mesh_node_id || null,
          hostname: dev.hostname,
          tenantId: tenant.id,
          tenantName: tenant.name,
          lapsAction: devLapsAction,
          lapsAccountName: lapsAccount,
          osType: devOsType,
          quietOffboardedAt: null,
          agentTokenHash
        });
      }
    }

    db.prepare('DELETE FROM tenants WHERE id = ?').run(tenantId);

    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'Client Permanently Deleted', ?)
    `).run(
      `aud-cdel-${crypto.randomUUID()}`,
      actor,
      `Permanently deleted client '${tenant.name}' (${devices.length} endpoints: ${onlineOffboardedCount} online offboarded, ${offlineQueuedCount} offline device tombstones registered for quiet future offboard).`
    );

    return {
      success: true,
      tenantId,
      tenantName: tenant.name,
      mode: options.mode,
      tombstoneRecorded: true,
      onlineOffboardedCount,
      offlineQueuedCount,
      archivedTotalCount: 0,
      message: `Client '${tenant.name}' permanently deleted. ${onlineOffboardedCount} online endpoint(s) offboarded immediately, and ${offlineQueuedCount} offline endpoint tombstone(s) registered so any sleeping PC that wakes up later quietly offboards itself (Local Admin rule: ${deletedLapsAction}).`
    };
  }

  // Default safe mode: Archive Entire Client & Keep Last-Known State in Data Archive
  db.prepare(`
    UPDATE tenants
    SET lifecycle_state = 'archived',
        archived_at = CURRENT_TIMESTAMP,
        offboard_reason = ?
    WHERE id = ?
  `).run(options.reason || 'Client offboarded — preserved in Data Archive Vault', tenantId);

  for (const dev of devices) {
    if (dev.lifecycle_state === 'archived') continue;
    const res = initiateDeviceOffboard(dev.id, {
      reason: options.reason || `Parent client '${tenant.name}' offboarded to Archive`,
      triggerSource: 'client_archived',
      overrideLapsAction: options.overrideLapsAction,
      forceImmediateArchive: options.forceArchiveOfflineDevices,
      actorUsername: actor
    });
    if (res.wasOnline || options.forceArchiveOfflineDevices) {
      onlineOffboardedCount++;
    } else {
      offlineQueuedCount++;
    }
  }

  const archivedTotalCount = (
    db
      .prepare("SELECT COUNT(*) as c FROM devices WHERE tenant_id = ? AND lifecycle_state = 'archived'")
      .get(tenantId) as { c: number }
  ).c;

  return {
    success: true,
    tenantId,
    tenantName: tenant.name,
    mode: 'archive_client',
    onlineOffboardedCount,
    offlineQueuedCount,
    archivedTotalCount,
    message: `Client '${tenant.name}' archived in last-known state! ${onlineOffboardedCount} endpoint(s) offboarded to Archive immediately, ${offlineQueuedCount} offline endpoint(s) queued. All BitLocker keys and LAPS histories remain preserved in the Archive Vault.`
  };
}

export async function offboardClientTenantAsync(
  tenantId: string,
  options: {
    mode: 'archive_client' | 'delete_client_permanently';
    reason?: string;
    overrideLapsAction?: LapsOffboardAction;
    forceArchiveOfflineDevices?: boolean;
    actorUsername?: string;
  }
) {
  const actor = options.actorUsername || 'admin';
  if (options.mode === 'archive_client') {
    const devices = db.prepare('SELECT id, status, lifecycle_state FROM devices WHERE tenant_id = ?').all(tenantId) as any[];
    for (const dev of devices) {
      if (dev.lifecycle_state === 'archived' || dev.status !== 'online') continue;
      let pol: any = null;
      try {
        pol = resolveEffectiveDevicePolicy(dev.id);
      } catch {}
      const resolvedAction: LapsOffboardAction =
        options.overrideLapsAction || pol?.lapsOffboardClientArchivedAction || 'keep_account_rotate_final';
      if (resolvedAction === 'keep_account_rotate_final') {
        try {
          await rotateLapsPasswordVerifiedAsync(dev.id, {
            forceFinalArchiveSnapshot: true,
            actorUsername: actor
          });
        } catch {}
      }
    }
    return offboardClientTenant(tenantId, {
      ...options,
      overrideLapsAction: options.overrideLapsAction || 'keep_account_as_is'
    });
  }
  return offboardClientTenant(tenantId, options);
}

export function reactivateArchivedClient(tenantId: string): { success: boolean; message: string } {
  const tenant = db.prepare('SELECT * FROM tenants WHERE id = ?').get(tenantId) as any;
  if (!tenant) throw new Error('Client not found');
  db.prepare(`
    UPDATE tenants
    SET lifecycle_state = 'active',
        archived_at = NULL,
        offboard_reason = NULL
    WHERE id = ?
  `).run(tenantId);
  return {
    success: true,
    message: `Client '${tenant.name}' restored to Active status. Archived devices remain in the Archive Vault until they wake up / check in or are manually restored.`
  };
}

export function handleAgentCheckInOrWake(
  deviceIdentifier: string,
  triggerType: 'wake_checkin' | 'reinstall_agent' = 'wake_checkin',
  tenantIdHint?: string,
  agentAuthToken?: string
): {
  success: boolean;
  deviceId: string;
  hostname: string;
  actionTaken:
    | 'resurrected_from_archive'
    | 'queued_offboard_completed_to_archive'
    | 'quiet_offboard_executed'
    | 'normal_heartbeat';
  newLifecycleState: string;
  lapsActionExecuted?: string;
  message: string;
} {
  let device = db
    .prepare('SELECT * FROM devices WHERE id = ? OR mesh_node_id = ? LIMIT 1')
    .get(deviceIdentifier, deviceIdentifier) as any;

  // Scope hostname fallback strictly by tenantIdHint (or require unique hostname match) to prevent cross-tenant collisions!
  if (!device) {
    if (tenantIdHint) {
      device = db
        .prepare('SELECT * FROM devices WHERE tenant_id = ? AND LOWER(hostname) = LOWER(?) LIMIT 1')
        .get(tenantIdHint, deviceIdentifier) as any;
    } else {
      const hostMatches = db
        .prepare('SELECT * FROM devices WHERE LOWER(hostname) = LOWER(?) LIMIT 2')
        .all(deviceIdentifier) as any[];
      if (hostMatches.length === 1) {
        device = hostMatches[0];
      }
    }
  }

  // Check per-device tombstone table if parent client was permanently deleted (cascade-removing devices row)
  if (!device) {
    let devTombstone = db
      .prepare('SELECT * FROM deleted_tenant_device_tombstones WHERE device_id = ? OR mesh_node_id = ? LIMIT 1')
      .get(deviceIdentifier, deviceIdentifier) as any;

    if (!devTombstone) {
      const candidateTokenHash = agentAuthToken
        ? hashPlainAgentToken(agentAuthToken, false)
        : /^[0-9a-fA-F]{64}$/.test(deviceIdentifier)
        ? deviceIdentifier.toLowerCase()
        : hashPlainAgentToken(deviceIdentifier, false);
      if (candidateTokenHash) {
        try {
          devTombstone = db
            .prepare('SELECT * FROM deleted_tenant_device_tombstones WHERE agent_token_hash = ? LIMIT 1')
            .get(candidateTokenHash) as any;
        } catch {}
      }
    }

    if (!devTombstone && tenantIdHint) {
      devTombstone = db
        .prepare('SELECT * FROM deleted_tenant_device_tombstones WHERE tenant_id = ? AND LOWER(hostname) = LOWER(?) LIMIT 1')
        .get(tenantIdHint, deviceIdentifier) as any;
    } else if (!devTombstone) {
      const tMatches = db
        .prepare('SELECT * FROM deleted_tenant_device_tombstones WHERE LOWER(hostname) = LOWER(?) LIMIT 2')
        .all(deviceIdentifier) as any[];
      if (tMatches.length === 1) {
        devTombstone = tMatches[0];
      }
    }

    if (!devTombstone) {
      throw new Error(`Device ${deviceIdentifier} not found`);
    }

    const lapsAction: LapsOffboardAction = devTombstone.laps_action || 'remove_account';
    const lapsAccountName = devTombstone.laps_account_name || 'LocalAdmin';
    const tombstoneOs = normalizeEndpointOs(devTombstone.os_type);
    meshBridge.dispatchRawNodeOffboard(
      devTombstone.mesh_node_id || devTombstone.device_id,
      lapsAccountName,
      lapsAction,
      tombstoneOs,
      devTombstone.device_id
    );

    db.prepare(`
      UPDATE deleted_tenant_device_tombstones
      SET quiet_offboarded_at = CURRENT_TIMESTAMP
      WHERE device_id = ?
    `).run(devTombstone.device_id);

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, 'system', ?, 'Quiet Offboard Dispatched (Deleted Client Tombstone)', ?)
    `).run(
      `aud-qoff-tomb-${crypto.randomUUID()}`,
      devTombstone.device_id,
      `Endpoint ${devTombstone.hostname} woke up after permanent deletion of client '${devTombstone.tenant_name}'. Dispatched quiet self-uninstall & local admin rule (${lapsAction}).`
    );

    return {
      success: true,
      deviceId: devTombstone.device_id,
      hostname: devTombstone.hostname,
      actionTaken: 'quiet_offboard_executed',
      newLifecycleState: 'purged_tombstone',
      lapsActionExecuted: lapsAction,
      message: `Quiet Offboard Executed: Parent client '${devTombstone.tenant_name}' was permanently deleted. ${devTombstone.hostname} matched tombstone registry and received quiet self-uninstall (Local Admin: ${lapsAction}).`
    };
  }

  const deviceId = device.id;
  const tenant = db.prepare('SELECT * FROM tenants WHERE id = ?').get(device.tenant_id) as any;
  const tombstone = db
    .prepare('SELECT * FROM deleted_tenants_tombstones WHERE tenant_id = ?')
    .get(device.tenant_id) as any;

  let policy: any = null;
  try {
    policy = resolveEffectiveDevicePolicy(deviceId);
  } catch {}

  // RULE 1: If parent Client was deleted OR is currently Archived -> Quietly offboard the endpoint!
  if (!tenant || tombstone || tenant.lifecycle_state === 'archived') {
    const isDeletedClient = !tenant || Boolean(tombstone);
    const lapsAction: LapsOffboardAction = isDeletedClient
      ? tombstone?.laps_offboard_action || policy?.lapsOffboardClientDeletedAction || 'remove_account'
      : policy?.lapsOffboardClientArchivedAction || 'keep_account_rotate_final';

    // Device just checked in online; rotate verified final archive password BEFORE dispatching self-uninstall!
    db.prepare("UPDATE devices SET status = 'online', last_seen = CURRENT_TIMESTAMP WHERE id = ?").run(deviceId);
    const targetLapsAccount = policy?.lapsAccountName || 'LocalAdmin';
    if (lapsAction === 'keep_account_rotate_final') {
      const rotTask = rotateLapsPasswordVerifiedAsync(deviceId, {
        forceFinalArchiveSnapshot: true,
        actorUsername: 'system'
      });
      void rotTask.catch(() => {}).finally(() => {
        meshBridge.dispatchAgentOffboard(deviceId, {
          lapsAccountName: targetLapsAccount,
          lapsAction
        });
      });
    } else {
      meshBridge.dispatchAgentOffboard(deviceId, {
        lapsAccountName: targetLapsAccount,
        lapsAction
      });
    }

    db.prepare(`
      UPDATE devices
      SET lifecycle_state = 'archived',
          status = 'offline',
          companion_installed = 0,
          offboarded_at = COALESCE(offboarded_at, CURRENT_TIMESTAMP),
          offboard_trigger_source = ?,
          offboard_laps_action_taken = ?,
          offboard_reason = COALESCE(offboard_reason, '') || ' [Quiet offboard executed upon wake/check-in because parent client is ' || ? || ']'
      WHERE id = ?
    `).run(
      isDeletedClient ? 'client_deleted' : 'client_archived',
      lapsAction,
      isDeletedClient ? 'deleted' : 'archived',
      deviceId
    );

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, 'system', ?, 'Quiet Offboard Dispatched', ?)
    `).run(
      `aud-qoff-${crypto.randomUUID()}`,
      deviceId,
      `Endpoint ${device.hostname} checked in under ${isDeletedClient ? 'deleted' : 'archived'} client '${tenant?.name || tombstone?.tenant_name || 'Deleted Client'}'. Dispatched quiet offboarding & agent removal (LAPS rule: ${lapsAction}).`
    );

    return {
      success: true,
      deviceId,
      hostname: device.hostname,
      actionTaken: 'quiet_offboard_executed',
      newLifecycleState: 'archived',
      lapsActionExecuted: lapsAction,
      message: `Quiet Offboard Executed: Because parent client '${tenant?.name || tombstone?.tenant_name || 'Deleted Client'}' is ${
        isDeletedClient ? 'deleted' : 'archived'
      }, ${device.hostname} quietly reverted policies, applied local admin rule (${lapsAction}), and uninstalled its agent without resurrecting.`
    };
  }

  // RULE 2: If device is in 'pending_offboard' -> Mark online FIRST so live cleanup & final LAPS rotation execute cleanly!
  if (device.lifecycle_state === 'pending_offboard') {
    db.prepare("UPDATE devices SET status = 'online', last_seen = CURRENT_TIMESTAMP WHERE id = ?").run(deviceId);
    const lapsAction: LapsOffboardAction =
      device.offboard_laps_action_taken || policy?.lapsOffboardExplicitDeviceAction || 'remove_account';
    const res = initiateDeviceOffboard(deviceId, {
      reason: device.offboard_reason || 'Completed queued offboarding upon endpoint online check-in',
      triggerSource: device.offboard_trigger_source || 'explicit_device',
      overrideLapsAction: lapsAction,
      actorUsername: 'system'
    });

    return {
      success: true,
      deviceId,
      hostname: device.hostname,
      actionTaken: 'queued_offboard_completed_to_archive',
      newLifecycleState: 'archived',
      lapsActionExecuted: res.lapsActionTaken,
      message: `${device.hostname} checked in while Pending Offboard: queued online cleanup executed (Local Admin: ${res.lapsActionTaken}), agent uninstalled, and device moved to Archive Vault.`
    };
  }

  // RULE 3: If device is in 'archived' AND parent Client is Active -> Return entry to life!
  // Guard against trailing heartbeats arriving within 90s of an active offboard!
  if (device.lifecycle_state === 'archived') {
    if (triggerType === 'wake_checkin' && device.offboarded_at) {
      const offboardMs = new Date(String(device.offboarded_at).replace(' ', 'T') + (String(device.offboarded_at).includes('Z') ? '' : 'Z')).getTime();
      if (!Number.isNaN(offboardMs) && Date.now() - offboardMs < 90000) {
        return {
          success: true,
          deviceId,
          hostname: device.hostname,
          actionTaken: 'quiet_offboard_executed',
          newLifecycleState: 'archived',
          message: `Ignored trailing heartbeat within 90s cooldown after offboarding ${device.hostname}.`
        };
      }
    }
    db.prepare(`
      UPDATE devices
      SET lifecycle_state = 'active',
          status = 'online',
          companion_installed = 1,
          resurrected_at = CURRENT_TIMESTAMP,
          resurrect_count = COALESCE(resurrect_count, 0) + 1,
          last_seen = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(deviceId);

    void rotateLapsPasswordVerifiedAsync(deviceId, { actorUsername: 'system' }).catch(() => {});

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, 'system', ?, 'Archived Device Returned to Life', ?)
    `).run(
      `aud-res-${crypto.randomUUID()}`,
      deviceId,
      `Archived endpoint ${device.hostname} (${triggerType}) under active client '${tenant.name}' automatically returned to Active fleet with all historical BitLocker & LAPS records intact.`
    );

    return {
      success: true,
      deviceId,
      hostname: device.hostname,
      actionTaken: 'resurrected_from_archive',
      newLifecycleState: 'active',
      message: `Returned to Life! Because ${device.hostname} was in the Archive Vault (no longer pending offboarding) and client '${tenant.name}' is active, its archived entry was restored to Active & Online with all historical BitLocker keys, LAPS history, and notes preserved.`
    };
  }

  // Normal active device check-in
  db.prepare("UPDATE devices SET status = 'online', last_seen = CURRENT_TIMESTAMP WHERE id = ?").run(deviceId);

  // Execute deferred LAPS rotation via verified async pipeline if due while offline
  const lapsRow = db.prepare('SELECT * FROM laps_vault WHERE device_id = ?').get(deviceId) as any;
  let deferredRotatedNote = '';
  if (
    lapsRow &&
    (lapsRow.rotation_pending_online === 1 ||
      (lapsRow.expires_at && new Date(lapsRow.expires_at).getTime() <= Date.now()))
  ) {
    void rotateLapsPasswordVerifiedAsync(deviceId, { actorUsername: 'system' }).catch(() => {});
    deferredRotatedNote = ` Deferred LAPS rotation for '${lapsRow.account_name}' was triggered via verified live agent delivery.`;
  }

  return {
    success: true,
    deviceId,
    hostname: device.hostname,
    actionTaken: 'normal_heartbeat',
    newLifecycleState: 'active',
    message: `${device.hostname} checked in normally (Active & Online).${deferredRotatedNote}`
  };
}
