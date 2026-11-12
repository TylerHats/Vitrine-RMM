import crypto from 'crypto';
import { db } from '../../db/index.js';
import { resolveEffectiveDevicePolicy } from '../policy/index.js';
import { encryptVaultSecret, decryptVaultSecret } from '../vault/index.js';
import { meshBridge } from '../meshcentral/index.js';

const PASSPHRASE_WORDLIST = [
  'Cobalt', 'Falcon', 'Nebula', 'Quartz', 'Vortex', 'Cipher', 'Beacon', 'Vector',
  'Zenith', 'Prism', 'Harbor', 'Glacier', 'Titan', 'Summit', 'Aurora', 'Photon',
  'Anchor', 'Balsa', 'Canopy', 'Dynamo', 'Ember', 'Fjord', 'Granite', 'Helix',
  'Krypton', 'Lunar', 'Magnet', 'Nexus', 'Orbit', 'Pulsar', 'Quasar', 'Radius',
  'Sierra', 'Tundra', 'Vertex', 'Zephyr', 'Citadel', 'Bastion', 'Aegis', 'Keystone'
];

export interface LapsCredential {
  deviceId: string;
  accountName: string;
  previousAccountName?: string | null;
  password?: string;
  previousPassword?: string | null;
  passwordMode?: 'random' | 'passphrase' | 'static';
  autoCreateAccount?: boolean;
  sid500BuiltinDisabled?: boolean;
  cleanupOldAccountAction?: 'disable' | 'delete' | 'keep';
  expiresAt: string;
  lastRotated: string;
  autoRotateScheduled?: boolean;
  rotationPendingOnline?: boolean;
  pendingRotationReason?: string | null;
  pendingAccountName?: string | null;
  rotationStatus?: 'active' | 'rotated_live' | 'deferred_until_online' | 'skipped_pending_offboard';
}

const MASK = '••••••••••••••••';

export function getLapsCredential(
  deviceId: string,
  reveal = false,
  options?: { actorUsername?: string; skipAccessExpiryMutation?: boolean }
): LapsCredential | null {
  const deviceExists = db.prepare('SELECT id, status, lifecycle_state FROM devices WHERE id = ?').get(deviceId) as
    | { id: string; status?: string; lifecycle_state?: string }
    | undefined;
  if (!deviceExists) {
    return null;
  }

  const row = db.prepare('SELECT * FROM laps_vault WHERE device_id = ?').get(deviceId) as any;
  if (!row) {
    // Initialize vault record while strictly respecting `reveal`
    return rotateLapsPassword(deviceId, {
      reveal,
      actorUsername: options?.actorUsername || 'system',
      forceInitialProvision: true
    });
  }

  let policy: any = null;
  try {
    policy = resolveEffectiveDevicePolicy(deviceId);
  } catch {
    // Ignore if policy lookup fails
  }

  let decryptedPassword = '';
  let decryptedPreviousPassword = '';
  let autoRotateScheduled = false;

  if (reveal) {
    decryptedPassword = decryptVaultSecret(row.encrypted_password);
    decryptedPreviousPassword = decryptVaultSecret(row.previous_encrypted_password);

    if (
      !options?.skipAccessExpiryMutation &&
      policy &&
      policy.lapsRotateOnAccess &&
      policy.lapsPasswordMode !== 'static' &&
      deviceExists.lifecycle_state === 'active'
    ) {
      const graceHours = policy.lapsPostAccessGraceHours || 2;
      const newExpiry = new Date(Date.now() + graceHours * 3600 * 1000).toISOString();
      db.prepare('UPDATE laps_vault SET expires_at = ? WHERE device_id = ?').run(newExpiry, deviceId);
      row.expires_at = newExpiry;
      autoRotateScheduled = true;
      db.prepare(`
        INSERT INTO audit_logs (id, username, device_id, action, details)
        VALUES (?, ?, ?, 'LAPS Ephemeral Access', ?)
      `).run(
        `aud-laps-${crypto.randomUUID()}`,
        options?.actorUsername || 'technician',
        deviceId,
        `Revealed LAPS secret for '${row.account_name}'. Auto-rotation grace window armed for ${graceHours} hour(s).`
      );
    }
  }

  const isExpiredWhileOffline =
    deviceExists.status !== 'online' &&
    deviceExists.lifecycle_state === 'active' &&
    row.expires_at &&
    new Date(row.expires_at).getTime() <= Date.now();

  const rotationPendingOnline = Boolean(row.rotation_pending_online || isExpiredWhileOffline);
  const pendingReason =
    row.pending_rotation_reason ||
    (isExpiredWhileOffline
      ? 'Scheduled rotation due while endpoint is offline — current password preserved until agent is back online'
      : null);

  return {
    deviceId: row.device_id,
    accountName: row.account_name,
    previousAccountName: row.previous_account_name || null,
    password: reveal ? decryptedPassword : MASK,
    previousPassword: reveal
      ? decryptedPreviousPassword || null
      : row.previous_encrypted_password
      ? MASK
      : null,
    passwordMode: policy?.lapsPasswordMode || 'random',
    autoCreateAccount: policy?.lapsAutoCreateAccount ?? true,
    sid500BuiltinDisabled: Boolean(policy?.lapsDisableBuiltinSid500Admin ?? row.sid500_builtin_disabled ?? 1),
    cleanupOldAccountAction: policy?.lapsCleanupOldAccountOnRename || 'disable',
    expiresAt: row.expires_at,
    lastRotated: row.last_rotated,
    autoRotateScheduled,
    rotationPendingOnline,
    pendingRotationReason: pendingReason,
    pendingAccountName: row.pending_account_name || null,
    rotationStatus:
      deviceExists.lifecycle_state === 'pending_offboard'
        ? 'skipped_pending_offboard'
        : rotationPendingOnline
        ? 'deferred_until_online'
        : 'active'
  };
}

export function rotateLapsPassword(
  deviceId: string,
  options?: {
    forceFinalArchiveSnapshot?: boolean;
    forceInitialProvision?: boolean;
    reveal?: boolean;
    actorUsername?: string;
  }
): LapsCredential {
  const shouldReveal = Boolean(options?.reveal);
  const actor = options?.actorUsername || 'system';

  let policy: any = null;
  try {
    policy = resolveEffectiveDevicePolicy(deviceId);
  } catch {
    // Fallback defaults
  }

  const device = db
    .prepare('SELECT hostname, status, lifecycle_state, os_type, mesh_node_id FROM devices WHERE id = ?')
    .get(deviceId) as
    | { hostname: string; status: string; lifecycle_state?: string; os_type?: string; mesh_node_id?: string }
    | undefined;

  if (!device) {
    throw new Error(`Device ${deviceId} not found`);
  }

  const existingRow = db.prepare('SELECT * FROM laps_vault WHERE device_id = ?').get(deviceId) as any;

  const accountName = policy?.lapsAccountName || 'LocalAdmin';
  const passwordMode: 'random' | 'passphrase' | 'static' = policy?.lapsPasswordMode || 'random';
  const passLength = Math.max(12, Math.min(64, policy?.lapsPasswordLength || 20));
  const complexity = policy?.lapsComplexity || 'alphanumeric_symbols';
  const rotationDays = policy?.lapsRotationDays ?? 30;
  const autoCreateAccount = policy?.lapsAutoCreateAccount ?? true;
  const sid500Disabled = policy?.lapsDisableBuiltinSid500Admin !== false ? 1 : 0;
  const cleanupAction: 'disable' | 'delete' | 'keep' = policy?.lapsCleanupOldAccountOnRename || 'disable';

  // SAFETY GUARDRAIL #1: Never rotate or overwrite credentials if device has a pending offboarding (or is archived)
  if (
    existingRow &&
    (device.lifecycle_state === 'pending_offboard' || device.lifecycle_state === 'archived') &&
    !options?.forceFinalArchiveSnapshot
  ) {
    const skipReason =
      device.lifecycle_state === 'pending_offboard'
        ? 'Skipped scheduled/manual rotation: Endpoint has a pending offboarding queued. Current password preserved to prevent lockout.'
        : 'Skipped rotation: Endpoint is in the Data Archive Vault. Historical password preserved.';
    db.prepare(`
      UPDATE laps_vault
      SET rotation_pending_online = 0, pending_rotation_reason = ?
      WHERE device_id = ?
    `).run(skipReason, deviceId);

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'LAPS Rotation Skipped (Offboard Guard)', ?)
    `).run(`aud-laps-skip-${crypto.randomUUID()}`, actor, deviceId, skipReason);

    return {
      deviceId,
      accountName: existingRow.account_name,
      previousAccountName: existingRow.previous_account_name || null,
      password: shouldReveal ? decryptVaultSecret(existingRow.encrypted_password) : MASK,
      previousPassword: shouldReveal
        ? decryptVaultSecret(existingRow.previous_encrypted_password) || null
        : existingRow.previous_encrypted_password
        ? MASK
        : null,
      passwordMode,
      autoCreateAccount,
      sid500BuiltinDisabled: Boolean(sid500Disabled),
      cleanupOldAccountAction: cleanupAction,
      expiresAt: existingRow.expires_at,
      lastRotated: existingRow.last_rotated,
      autoRotateScheduled: false,
      rotationPendingOnline: false,
      pendingRotationReason: skipReason,
      pendingAccountName: null,
      rotationStatus: 'skipped_pending_offboard'
    };
  }

  // SAFETY GUARDRAIL #2: If device is OFFLINE, NEVER overwrite an existing vaulted password in Vitrine!
  if (existingRow && device.status !== 'online' && !options?.forceFinalArchiveSnapshot) {
    const deferReason = `Deferred until ${device.hostname} returns online: Current vaulted password ('${existingRow.account_name}') is preserved in Vitrine so technicians are never locked out while the machine is offline.`;
    db.prepare(`
      UPDATE laps_vault
      SET rotation_pending_online = 1,
          pending_rotation_reason = ?,
          pending_account_name = ?
      WHERE device_id = ?
    `).run(deferReason, accountName, deviceId);

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'LAPS Rotation Deferred (Offline Lockout Guard)', ?)
    `).run(`aud-laps-defer-${crypto.randomUUID()}`, actor, deviceId, deferReason);

    return {
      deviceId,
      accountName: existingRow.account_name,
      previousAccountName: existingRow.previous_account_name || null,
      password: shouldReveal ? decryptVaultSecret(existingRow.encrypted_password) : MASK,
      previousPassword: shouldReveal
        ? decryptVaultSecret(existingRow.previous_encrypted_password) || null
        : existingRow.previous_encrypted_password
        ? MASK
        : null,
      passwordMode,
      autoCreateAccount,
      sid500BuiltinDisabled: Boolean(sid500Disabled),
      cleanupOldAccountAction: cleanupAction,
      expiresAt: existingRow.expires_at,
      lastRotated: existingRow.last_rotated,
      autoRotateScheduled: false,
      rotationPendingOnline: true,
      pendingRotationReason: deferReason,
      pendingAccountName: accountName !== existingRow.account_name ? accountName : null,
      rotationStatus: 'deferred_until_online'
    };
  }

  let newPass = '';
  const staticConfigured = policy?.lapsStaticPasswordRaw
    ? decryptVaultSecret(policy.lapsStaticPasswordRaw)
    : '';

  if (passwordMode === 'static' && staticConfigured) {
    newPass = staticConfigured;
  } else if (passwordMode === 'passphrase') {
    const wordCount = Math.max(3, Math.min(8, policy?.lapsPassphraseWords || 5));
    const sep = policy?.lapsPassphraseSeparator || '-';
    const picked: string[] = [];
    for (let i = 0; i < wordCount; i++) {
      picked.push(PASSPHRASE_WORDLIST[crypto.randomInt(0, PASSPHRASE_WORDLIST.length)]);
    }
    const suffixNum = crypto.randomInt(10, 99);
    const symbols = '!@#$%^&*';
    const suffixSym = symbols[crypto.randomInt(0, symbols.length)];
    newPass = `${picked.join(sep)}${sep}${suffixNum}${suffixSym}`;
  } else {
    let charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*';
    if (complexity === 'alphanumeric') {
      charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    } else if (complexity === 'ascii_printable') {
      charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    }
    for (let i = 0; i < passLength; i++) {
      newPass += charset[crypto.randomInt(0, charset.length)];
    }
  }

  const encryptedPayload = encryptVaultSecret(newPass);
  const ivMarker = encryptedPayload.split(':')[2] || '';

  const expiresAt =
    passwordMode === 'static' || rotationDays === 0
      ? new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000).toISOString()
      : new Date(Date.now() + rotationDays * 24 * 60 * 60 * 1000).toISOString();
  const now = new Date().toISOString();

  const previousAccount = existingRow?.account_name || null;
  const previousEncrypted = existingRow?.encrypted_password || null;
  const previousIv = existingRow?.iv || null;

  db.prepare(`
    INSERT INTO laps_vault (
      device_id, account_name, encrypted_password, iv, expires_at, last_rotated,
      previous_account_name, previous_encrypted_password, previous_iv, sid500_builtin_disabled,
      rotation_pending_online, pending_rotation_reason, pending_account_name
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL)
    ON CONFLICT(device_id) DO UPDATE SET
      previous_account_name = laps_vault.account_name,
      previous_encrypted_password = laps_vault.encrypted_password,
      previous_iv = laps_vault.iv,
      account_name = excluded.account_name,
      encrypted_password = excluded.encrypted_password,
      iv = excluded.iv,
      expires_at = excluded.expires_at,
      last_rotated = excluded.last_rotated,
      sid500_builtin_disabled = excluded.sid500_builtin_disabled,
      rotation_pending_online = 0,
      pending_rotation_reason = NULL,
      pending_account_name = NULL
  `).run(
    deviceId,
    accountName,
    encryptedPayload,
    ivMarker,
    expiresAt,
    now,
    previousAccount,
    previousEncrypted,
    previousIv,
    sid500Disabled
  );

  // Push local administrator account rotation over live MeshCentral agent tunnel if connected
  if (device.status === 'online' && !options?.forceInitialProvision) {
    try {
      meshBridge.pushLapsCredentialToNode(deviceId, {
        accountName,
        password: newPass,
        autoCreateAccount,
        disableSid500: Boolean(sid500Disabled),
        previousAccountName: previousAccount && previousAccount !== accountName ? previousAccount : null,
        cleanupOldAccountAction: cleanupAction
      });
    } catch {
      // Non-fatal if tunnel not active
    }
  }

  const renameNote =
    previousAccount && previousAccount !== accountName
      ? ` | Renamed from '${previousAccount}' -> '${accountName}' (Old Account Cleanup: ${cleanupAction.toUpperCase()})`
      : '';

  db.prepare(`
    INSERT INTO audit_logs (id, username, device_id, action, details)
    VALUES (?, ?, ?, 'LAPS Password Rotated', ?)
  `).run(
    `aud-laps-${crypto.randomUUID()}`,
    actor,
    deviceId,
    `Provisioned/Rotated account '${accountName}' on ${device.hostname} (Mode: ${passwordMode}, Auto-Create: ${autoCreateAccount ? 'Enabled' : 'Disabled'}, SID-500 Disabled: ${sid500Disabled ? 'Yes' : 'No'})${renameNote}`
  );

  return {
    deviceId,
    accountName,
    previousAccountName: previousAccount,
    password: shouldReveal ? newPass : MASK,
    previousPassword: shouldReveal
      ? decryptVaultSecret(previousEncrypted) || null
      : previousEncrypted
      ? MASK
      : null,
    passwordMode,
    autoCreateAccount,
    sid500BuiltinDisabled: Boolean(sid500Disabled),
    cleanupOldAccountAction: cleanupAction,
    expiresAt,
    lastRotated: now,
    autoRotateScheduled: false,
    rotationPendingOnline: false,
    pendingRotationReason: null,
    pendingAccountName: null,
    rotationStatus: 'rotated_live'
  };
}

export interface BreakGlassRecoveryEntry {
  deviceId: string;
  hostname: string;
  tenantName: string;
  siteName: string;
  lifecycleState: string;
  serialNumber: string;
  osVersion: string;
  lapsAccountName: string;
  currentLapsPassword: string;
  previousLapsAccountName: string | null;
  previousLapsPassword: string | null;
  bitlockerRecoveryKey: string;
  bitlockerStatus: string;
  sid500BuiltinDisabled: boolean;
  lastRotated: string;
  offboardedAt: string | null;
}

export function exportLapsBreakGlassSheet(
  tenantId?: string,
  includeArchived = true,
  actorUsername = 'admin'
): {
  generatedAt: string;
  totalEndpoints: number;
  archivedIncludedCount: number;
  entries: BreakGlassRecoveryEntry[];
} {
  let sql = `
    SELECT d.*, t.name as tenant_name, s.name as site_name
    FROM devices d
    LEFT JOIN tenants t ON d.tenant_id = t.id
    LEFT JOIN sites s ON d.site_id = s.id
    WHERE 1=1
  `;
  const params: any[] = [];
  if (tenantId && tenantId !== 'all') {
    sql += ' AND d.tenant_id = ?';
    params.push(tenantId);
  }
  if (!includeArchived) {
    sql += " AND COALESCE(d.lifecycle_state, 'active') = 'active'";
  }
  sql += ' ORDER BY d.lifecycle_state ASC, t.name ASC, d.hostname ASC';

  const devices = db.prepare(sql).all(...params) as any[];
  const entries: BreakGlassRecoveryEntry[] = devices.map((d) => {
    // Read without mutating post-access expiry timers across the fleet
    const cred = getLapsCredential(d.id, true, {
      actorUsername,
      skipAccessExpiryMutation: true
    });
    const decryptedBitlocker = decryptVaultSecret(d.bitlocker_key);
    return {
      deviceId: d.id,
      hostname: d.hostname,
      tenantName: d.tenant_name || 'Unassigned',
      siteName: d.site_name || 'Default Site',
      lifecycleState: d.lifecycle_state || 'active',
      serialNumber: d.serial_number || 'N/A',
      osVersion: d.os_version,
      lapsAccountName: cred?.accountName || 'LocalAdmin',
      currentLapsPassword: cred?.password || 'N/A',
      previousLapsAccountName: cred?.previousAccountName || null,
      previousLapsPassword: cred?.previousPassword || null,
      bitlockerRecoveryKey: decryptedBitlocker || 'Not Escrowed',
      bitlockerStatus: d.bitlocker_status || 'Unknown',
      sid500BuiltinDisabled: Boolean(cred?.sid500BuiltinDisabled ?? true),
      lastRotated: cred?.lastRotated || d.last_seen,
      offboardedAt: d.offboarded_at || null
    };
  });

  db.prepare(`
    INSERT INTO audit_logs (id, username, action, details)
    VALUES (?, ?, 'Emergency Break-Glass Vault Export', ?)
  `).run(
    `aud-bg-${crypto.randomUUID()}`,
    actorUsername,
    `Exported emergency offline Break-Glass LAPS + BitLocker recovery sheet for ${entries.length} endpoint(s) (Archived included: ${includeArchived ? 'Yes' : 'No'}).`
  );

  return {
    generatedAt: new Date().toISOString(),
    totalEndpoints: entries.length,
    archivedIncludedCount: entries.filter((e) => e.lifecycleState === 'archived').length,
    entries
  };
}
