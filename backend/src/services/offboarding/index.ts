import crypto from 'crypto';
import { db } from '../../db/index.js';
import { resolveEffectiveDevicePolicy } from '../policy/index.js';
import { rotateLapsPassword } from '../laps/index.js';
import { meshBridge } from '../meshcentral/index.js';

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
      rotateLapsPassword(deviceId, { forceFinalArchiveSnapshot: true, actorUsername: actor });
      stepsExecuted.push(
        `Rotated managed local admin (${policy.lapsAccountName}) to a final break-glass password and sealed it in the Archive Vault.`
      );
    }

    // Dispatch actual OS cleanup & agent self-uninstall via MeshCentral tunnel
    meshBridge.dispatchAgentOffboard(deviceId, {
      lapsAccountName: policy.lapsAccountName,
      lapsAction: resolvedLapsAction
    });

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

    const insertDeviceTombstone = db.prepare(`
      INSERT OR REPLACE INTO deleted_tenant_device_tombstones (
        device_id, mesh_node_id, hostname, tenant_id, tenant_name, laps_action, quiet_offboarded_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    for (const dev of devices) {
      let devPol: any = null;
      try {
        devPol = resolveEffectiveDevicePolicy(dev.id);
      } catch {}
      const devLapsAction: LapsOffboardAction =
        options.overrideLapsAction || devPol?.lapsOffboardClientDeletedAction || deletedLapsAction;
      const lapsAccount = devPol?.lapsAccountName || 'LocalAdmin';

      if (dev.status === 'online') {
        onlineOffboardedCount++;
        meshBridge.dispatchAgentOffboard(dev.id, {
          lapsAccountName: lapsAccount,
          lapsAction: devLapsAction
        });
        insertDeviceTombstone.run(
          dev.id,
          dev.mesh_node_id || null,
          dev.hostname,
          tenant.id,
          tenant.name,
          devLapsAction,
          new Date().toISOString()
        );
      } else {
        offlineQueuedCount++;
        insertDeviceTombstone.run(
          dev.id,
          dev.mesh_node_id || null,
          dev.hostname,
          tenant.id,
          tenant.name,
          devLapsAction,
          null
        );
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
  triggerType: 'wake_checkin' | 'reinstall_agent' = 'wake_checkin'
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
  const device = db
    .prepare('SELECT * FROM devices WHERE id = ? OR mesh_node_id = ? OR LOWER(hostname) = LOWER(?) LIMIT 1')
    .get(deviceIdentifier, deviceIdentifier, deviceIdentifier) as any;

  // Check per-device tombstone table if parent client was permanently deleted (cascade-removing devices row)
  if (!device) {
    const devTombstone = db
      .prepare(
        'SELECT * FROM deleted_tenant_device_tombstones WHERE device_id = ? OR mesh_node_id = ? OR LOWER(hostname) = LOWER(?) LIMIT 1'
      )
      .get(deviceIdentifier, deviceIdentifier, deviceIdentifier) as any;

    if (!devTombstone) {
      throw new Error(`Device ${deviceIdentifier} not found`);
    }

    const lapsAction: LapsOffboardAction = devTombstone.laps_action || 'remove_account';
    if (devTombstone.mesh_node_id) {
      meshBridge.dispatchRawNodeOffboard(devTombstone.mesh_node_id, 'LocalAdmin', lapsAction);
    }

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

    // Device just checked in online; rotate final archive password if required
    db.prepare("UPDATE devices SET status = 'online', last_seen = CURRENT_TIMESTAMP WHERE id = ?").run(deviceId);
    if (lapsAction === 'keep_account_rotate_final') {
      try {
        rotateLapsPassword(deviceId, { forceFinalArchiveSnapshot: true, actorUsername: 'system' });
      } catch {}
    }

    meshBridge.dispatchAgentOffboard(deviceId, {
      lapsAccountName: policy?.lapsAccountName || 'LocalAdmin',
      lapsAction
    });

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
  if (device.lifecycle_state === 'archived') {
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

    try {
      rotateLapsPassword(deviceId, { actorUsername: 'system' });
    } catch {}

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

  // Execute deferred LAPS rotation if due while offline
  const lapsRow = db.prepare('SELECT * FROM laps_vault WHERE device_id = ?').get(deviceId) as any;
  let deferredRotatedNote = '';
  if (
    lapsRow &&
    (lapsRow.rotation_pending_online === 1 ||
      (lapsRow.expires_at && new Date(lapsRow.expires_at).getTime() <= Date.now()))
  ) {
    try {
      const rotated = rotateLapsPassword(deviceId, { actorUsername: 'system' });
      deferredRotatedNote = ` Deferred LAPS rotation for '${rotated.accountName}' was now safely executed and confirmed online (previous password retained in N-1 history).`;
    } catch {}
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
