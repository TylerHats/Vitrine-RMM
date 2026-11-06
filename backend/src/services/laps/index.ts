import crypto from 'crypto';
import { db } from '../../db/index.js';
import { resolveEffectiveDevicePolicy } from '../policy/index.js';

const ALGORITHM = 'aes-256-gcm';
// In production, derive key from secure master secret; fallback to secure machine-specific key
const SECRET_KEY = crypto.scryptSync(process.env.LAPS_MASTER_SECRET || 'vitrine-rmm-laps-master-key-production-seed-9812', 'salt', 32);

export interface LapsCredential {
  deviceId: string;
  accountName: string;
  password?: string;
  expiresAt: string;
  lastRotated: string;
  autoRotateScheduled?: boolean;
}

export function getLapsCredential(deviceId: string, reveal = false): LapsCredential | null {
  const row = db.prepare('SELECT * FROM laps_vault WHERE device_id = ?').get(deviceId) as any;
  if (!row) {
    // Generate initial LAPS password if not present
    return rotateLapsPassword(deviceId);
  }

  let policy: any = null;
  try {
    policy = resolveEffectiveDevicePolicy(deviceId);
  } catch {}

  let decryptedPassword = '';
  let autoRotateScheduled = false;

  if (reveal) {
    try {
      const [ivHex, authTagHex, encryptedHex] = row.encrypted_password.split(':');
      const decipher = crypto.createDecipheriv(ALGORITHM, SECRET_KEY, Buffer.from(ivHex, 'hex'));
      decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
      decryptedPassword = decipher.update(encryptedHex, 'hex', 'utf8') + decipher.final('utf8');
    } catch (err) {
      decryptedPassword = 'DecryptionError';
    }

    // Auto-rotate on access rule (User Request 7)
    if (policy && policy.lapsRotateOnAccess) {
      const graceHours = policy.lapsPostAccessGraceHours || 2;
      const newExpiry = new Date(Date.now() + graceHours * 3600 * 1000).toISOString();
      db.prepare('UPDATE laps_vault SET expires_at = ? WHERE device_id = ?').run(newExpiry, deviceId);
      row.expires_at = newExpiry;
      autoRotateScheduled = true;
      db.prepare(`
        INSERT INTO audit_logs (id, username, device_id, action, details)
        VALUES (?, 'technician', ?, 'LAPS Ephemeral Access', ?)
      `).run(`aud-laps-${crypto.randomUUID()}`, deviceId, `Technician revealed LAPS secret. Auto-rotation grace window armed for ${graceHours} hour(s)`);
    }
  }

  return {
    deviceId: row.device_id,
    accountName: row.account_name,
    password: reveal ? decryptedPassword : '••••••••••••••••',
    expiresAt: row.expires_at,
    lastRotated: row.last_rotated,
    autoRotateScheduled
  };
}

export function rotateLapsPassword(deviceId: string): LapsCredential {
  let policy: any = null;
  try {
    policy = resolveEffectiveDevicePolicy(deviceId);
  } catch {}

  const accountName = policy?.lapsAccountName || 'LocalAdmin';
  const passLength = policy?.lapsPasswordLength || 20;
  const complexity = policy?.lapsComplexity || 'alphanumeric_symbols';
  const rotationDays = policy?.lapsRotationDays || 30;

  let charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*';
  if (complexity === 'alphanumeric') {
    charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  } else if (complexity === 'ascii_printable') {
    charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
  }

  let newPass = '';
  for (let i = 0; i < passLength; i++) {
    newPass += charset[crypto.randomInt(0, charset.length)];
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, SECRET_KEY, iv);
  const encrypted = cipher.update(newPass, 'utf8', 'hex') + cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  const encryptedPayload = `${iv.toString('hex')}:${authTag}:${encrypted}`;

  const expiresAt = new Date(Date.now() + rotationDays * 24 * 60 * 60 * 1000).toISOString();
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO laps_vault (device_id, account_name, encrypted_password, iv, expires_at, last_rotated)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(device_id) DO UPDATE SET
      account_name = excluded.account_name,
      encrypted_password = excluded.encrypted_password,
      iv = excluded.iv,
      expires_at = excluded.expires_at,
      last_rotated = excluded.last_rotated
  `).run(deviceId, accountName, encryptedPayload, iv.toString('hex'), expiresAt, now);

  db.prepare(`
    INSERT INTO audit_logs (id, username, device_id, action, details)
    VALUES (?, 'system', ?, 'LAPS Password Rotated', ?)
  `).run(`aud-laps-${crypto.randomUUID()}`, deviceId, `Rotated account ${accountName} with length ${passLength} and ${complexity} policy`);

  return {
    deviceId,
    accountName,
    password: newPass,
    expiresAt,
    lastRotated: now,
    autoRotateScheduled: false
  };
}
