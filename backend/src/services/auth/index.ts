import crypto from 'crypto';
import type { FastifyRequest, FastifyReply } from 'fastify';
import { db } from '../../db/index.js';
import {
  encryptVaultSecret,
  decryptVaultSecret,
  hashPasswordScrypt,
  verifyPasswordScrypt,
  generateRandomBase32,
  verifyTotp,
  buildOtpAuthUri,
  hmacSignToken,
  hmacVerifyToken
} from '../vault/index.js';

export const SESSION_COOKIE_NAME = 'vitrine_session';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours
const MFA_STEPUP_TTL_MS = 10 * 60 * 1000; // 10 minutes

export interface AuthenticatedUser {
  id: string;
  username: string;
  email: string;
  role: 'msp_super_admin' | 'technician' | 'client_admin' | string;
  tenant_id: string | null;
  totp_enabled: boolean;
}

export interface AuthContext {
  user: AuthenticatedUser;
  tokenHash: string;
  rawToken: string;
  mfaVerified: boolean;
  mfaVerifiedUntil: string | null;
}

declare module 'fastify' {
  interface FastifyRequest {
    auth?: AuthContext | null;
    guestGrantId?: string | null;
  }
}

// ============================================================================
// Sliding-Window Rate Limiter (In-Memory)
// ============================================================================
const rateBuckets = new Map<string, number[]>();

export function checkRateLimit(bucketKey: string, maxRequests: number, windowMs: number): {
  allowed: boolean;
  retryAfterSec: number;
} {
  const now = Date.now();
  const cutoff = now - windowMs;
  const existing = (rateBuckets.get(bucketKey) || []).filter((ts) => ts > cutoff);

  if (existing.length >= maxRequests) {
    const retryAfterSec = Math.max(1, Math.ceil((existing[0] + windowMs - now) / 1000));
    rateBuckets.set(bucketKey, existing);
    return { allowed: false, retryAfterSec };
  }

  existing.push(now);
  rateBuckets.set(bucketKey, existing);

  // Periodic cleanup to prevent unbounded growth
  if (rateBuckets.size > 5000) {
    for (const [k, arr] of rateBuckets.entries()) {
      const pruned = arr.filter((ts) => ts > cutoff);
      if (pruned.length === 0) rateBuckets.delete(k);
      else rateBuckets.set(k, pruned);
    }
  }

  return { allowed: true, retryAfterSec: 0 };
}

// ============================================================================
// Role & Tenant Authorization Helpers
// ============================================================================
export function isSuperAdminRole(role?: string | null): boolean {
  return role === 'msp_super_admin' || role === 'super_admin' || role === 'admin';
}

export function isTechnicianOrAbove(role?: string | null): boolean {
  return isSuperAdminRole(role) || role === 'technician' || role === 'msp_tech';
}

export function canUserAccessTenant(user: AuthenticatedUser | null | undefined, tenantId?: string | null): boolean {
  if (!user) return false;
  if (isTechnicianOrAbove(user.role)) return true;
  if (!tenantId) return false;
  return Boolean(user.tenant_id && user.tenant_id === tenantId);
}

export function canUserRunScriptRole(userRole: string, requiredRole?: string | null): boolean {
  const req = (requiredRole || 'technician').toLowerCase();
  if (isSuperAdminRole(userRole)) return true;
  if (req === 'admin' || req === 'msp_super_admin' || req === 'super_admin') {
    return false;
  }
  if (req === 'technician') {
    return isTechnicianOrAbove(userRole);
  }
  return true;
}

export function getActorUsername(req?: FastifyRequest | null, fallback = 'system'): string {
  if (req?.auth?.user?.username) {
    return req.auth.user.username;
  }
  return fallback;
}

// ============================================================================
// Initial Admin Bootstrap & User Management
// ============================================================================
export function hasConfiguredAdminUser(): boolean {
  const row = db
    .prepare("SELECT COUNT(*) as c FROM users WHERE password_hash IS NOT NULL AND password_hash != ''")
    .get() as { c: number };
  return row.c > 0;
}

export function generateOneTimeRecoveryCodes(count = 8): {
  plaintextCodes: string[];
  hashedCodes: string[];
} {
  const plaintextCodes: string[] = [];
  const hashedCodes: string[] = [];
  for (let i = 0; i < count; i++) {
    const partA = crypto.randomBytes(2).toString('hex').toUpperCase();
    const partB = crypto.randomBytes(2).toString('hex').toUpperCase();
    const code = `${partA}-${partB}`;
    plaintextCodes.push(code);
    hashedCodes.push(crypto.createHash('sha256').update(code).digest('hex'));
  }
  return { plaintextCodes, hashedCodes };
}

export function setupInitialSuperAdmin(params: {
  username: string;
  email: string;
  password: string;
}): {
  user: AuthenticatedUser;
  totpSecret: string;
  otpAuthUri: string;
  recoveryCodes: string[];
} {
  if (hasConfiguredAdminUser()) {
    throw new Error('Initial administrator has already been configured.');
  }
  const username = (params.username || '').trim();
  const email = (params.email || '').trim().toLowerCase();
  const password = params.password || '';

  if (!username || username.length < 2 || !/^[a-zA-Z0-9._-]+$/.test(username)) {
    throw new Error('Username must be at least 2 characters (letters, numbers, dots, underscores, or hyphens).');
  }
  if (!email || !email.includes('@')) {
    throw new Error('A valid administrator email address is required.');
  }
  if (password.length < 10) {
    throw new Error('Administrator password must be at least 10 characters.');
  }

  const settings = (db.prepare('SELECT brand_name FROM settings WHERE id = 1').get() || {}) as { brand_name?: string };
  const issuer = settings.brand_name || 'Vitrine RMM';
  const totpSecret = generateRandomBase32(20);
  const { plaintextCodes, hashedCodes } = generateOneTimeRecoveryCodes(8);
  const passwordHash = hashPasswordScrypt(password);

  // Sync global fallback totp_secret with initial admin so single-admin setups work seamlessly
  db.prepare('UPDATE settings SET totp_secret = ? WHERE id = 1').run(encryptVaultSecret(totpSecret));

  const existing = db
    .prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?) LIMIT 1')
    .get(username, email) as { id: string } | undefined;

  const userId = existing?.id || 'usr-admin';

  if (existing) {
    db.prepare(`
      UPDATE users
      SET username = ?,
          email = ?,
          role = 'msp_super_admin',
          tenant_id = NULL,
          password_hash = ?,
          totp_secret = ?,
          totp_enabled = 1,
          recovery_codes_json = ?
      WHERE id = ?
    `).run(username, email, passwordHash, encryptVaultSecret(totpSecret), JSON.stringify(hashedCodes), userId);
  } else {
    db.prepare(`
      INSERT INTO users (id, username, email, role, tenant_id, password_hash, totp_secret, totp_enabled, recovery_codes_json)
      VALUES (?, ?, ?, 'msp_super_admin', NULL, ?, ?, 1, ?)
    `).run(userId, username, email, passwordHash, encryptVaultSecret(totpSecret), JSON.stringify(hashedCodes));
  }

  db.prepare(`
    INSERT INTO audit_logs (id, username, action, details)
    VALUES (?, ?, 'Initial Super Admin Provisioned', ?)
  `).run(
    `aud-init-admin-${crypto.randomUUID()}`,
    username,
    `Provisioned primary MSP Super Admin '${username}' (${email}) with Scrypt password hash and TOTP Step-Up MFA.`
  );

  return {
    user: {
      id: userId,
      username,
      email,
      role: 'msp_super_admin',
      tenant_id: null,
      totp_enabled: true
    },
    totpSecret,
    otpAuthUri: buildOtpAuthUri(username, issuer, totpSecret),
    recoveryCodes: plaintextCodes
  };
}

// ============================================================================
// Session Creation, Cookie Management & Extraction
// ============================================================================
function sha256Hex(val: string): string {
  return crypto.createHash('sha256').update(val).digest('hex');
}

export function createUserSession(
  userId: string,
  ipAddress?: string,
  userAgent?: string
): { rawToken: string; expiresAt: string } {
  // Prune expired sessions opportunistically
  try {
    db.prepare('DELETE FROM auth_sessions WHERE expires_at <= ?').run(new Date().toISOString());
  } catch {
    // Ignore
  }

  const rawToken = crypto.randomBytes(32).toString('base64url');
  const tokenHash = sha256Hex(rawToken);
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();

  db.prepare(`
    INSERT INTO auth_sessions (token_hash, user_id, expires_at, mfa_verified_until, ip_address, user_agent)
    VALUES (?, ?, ?, NULL, ?, ?)
  `).run(tokenHash, userId, expiresAt, ipAddress || null, (userAgent || '').slice(0, 255));

  db.prepare('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?').run(userId);

  return { rawToken, expiresAt };
}

export function setSessionCookie(reply: FastifyReply, req: FastifyRequest, rawToken: string): void {
  const isSecure =
    req.protocol === 'https' ||
    req.headers['x-forwarded-proto'] === 'https' ||
    process.env.FORCE_SECURE_COOKIE === 'true';
  const maxAgeSec = Math.floor(SESSION_TTL_MS / 1000);
  const parts = [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(rawToken)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSec}`
  ];
  if (isSecure) parts.push('Secure');
  reply.header('Set-Cookie', parts.join('; '));
}

export function clearSessionCookie(reply: FastifyReply): void {
  reply.header('Set-Cookie', `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}

function parseCookies(cookieHeader?: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;
  for (const pair of cookieHeader.split(';')) {
    const idx = pair.indexOf('=');
    if (idx === -1) continue;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    try {
      out[k] = decodeURIComponent(v);
    } catch {
      out[k] = v;
    }
  }
  return out;
}

export function extractAuthContext(req: FastifyRequest): AuthContext | null {
  let rawToken = '';
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
    rawToken = authHeader.slice(7).trim();
  }
  if (!rawToken && req.headers.cookie) {
    const cookies = parseCookies(req.headers.cookie);
    if (cookies[SESSION_COOKIE_NAME]) {
      rawToken = cookies[SESSION_COOKIE_NAME];
    }
  }
  if (!rawToken && req.url?.startsWith('/ws/')) {
    const q = (req.query || {}) as Record<string, string>;
    if (q.token) rawToken = q.token;
  }

  if (!rawToken || rawToken.length < 20) return null;

  const tokenHash = sha256Hex(rawToken);
  const row = db
    .prepare(`
      SELECT s.token_hash, s.expires_at, s.mfa_verified_until,
             u.id, u.username, u.email, u.role, u.tenant_id, u.totp_enabled
      FROM auth_sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.token_hash = ?
    `)
    .get(tokenHash) as any;

  if (!row) return null;
  if (!row.expires_at || new Date(row.expires_at).getTime() <= Date.now()) {
    db.prepare('DELETE FROM auth_sessions WHERE token_hash = ?').run(tokenHash);
    return null;
  }

  const mfaVerified = Boolean(
    row.mfa_verified_until && new Date(row.mfa_verified_until).getTime() > Date.now()
  );

  return {
    user: {
      id: row.id,
      username: row.username,
      email: row.email,
      role: row.role,
      tenant_id: row.tenant_id || null,
      totp_enabled: Boolean(row.totp_enabled)
    },
    tokenHash,
    rawToken,
    mfaVerified,
    mfaVerifiedUntil: row.mfa_verified_until || null
  };
}

export function authenticateUserPassword(
  identifier: string,
  password: string
): AuthenticatedUser | null {
  const cleanId = (identifier || '').trim();
  if (!cleanId || !password) return null;

  const row = db
    .prepare(
      'SELECT id, username, email, role, tenant_id, password_hash, totp_enabled FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?) LIMIT 1'
    )
    .get(cleanId, cleanId) as any;

  if (!row || !row.password_hash) {
    // Perform dummy hash work to mitigate username enumeration timing side-channels
    hashPasswordScrypt('dummy-timing-equalizer');
    return null;
  }

  if (!verifyPasswordScrypt(password, row.password_hash)) {
    return null;
  }

  return {
    id: row.id,
    username: row.username,
    email: row.email,
    role: row.role,
    tenant_id: row.tenant_id || null,
    totp_enabled: Boolean(row.totp_enabled)
  };
}

// ============================================================================
// Step-Up MFA Verification & Enrollment Helpers
// ============================================================================
export function verifySessionStepUpMfa(
  auth: AuthContext,
  codeInput: string
): { success: boolean; verifiedUntil?: string; usedRecoveryCode?: boolean; error?: string } {
  const cleaned = (codeInput || '').trim().toUpperCase();
  if (!cleaned) {
    return { success: false, error: 'Verification code is required.' };
  }

  const userRow = db
    .prepare('SELECT id, username, totp_secret, last_totp_step, recovery_codes_json FROM users WHERE id = ?')
    .get(auth.user.id) as any;

  if (!userRow) {
    return { success: false, error: 'User account not found.' };
  }

  const settingsRow = db.prepare('SELECT totp_secret FROM settings WHERE id = 1').get() as any;
  const userSecret = decryptVaultSecret(userRow.totp_secret) || decryptVaultSecret(settingsRow?.totp_secret);

  // 1. Check 6-digit RFC 6238 TOTP with replay guard
  const numericOnly = cleaned.replace(/\s|-/g, '');
  if (/^\d{6}$/.test(numericOnly) && userSecret) {
    const check = verifyTotp(userSecret, numericOnly, userRow.last_totp_step, 1);
    if (check.replayDetected) {
      return {
        success: false,
        error: 'This 6-digit TOTP code was already used. Wait for the next 30-second code.'
      };
    }
    if (check.valid && check.matchedStep != null) {
      const verifiedUntil = new Date(Date.now() + MFA_STEPUP_TTL_MS).toISOString();
      db.prepare('UPDATE users SET last_totp_step = ?, totp_enabled = 1 WHERE id = ?').run(
        check.matchedStep,
        auth.user.id
      );
      db.prepare('UPDATE auth_sessions SET mfa_verified_until = ? WHERE token_hash = ?').run(
        verifiedUntil,
        auth.tokenHash
      );
      return { success: true, verifiedUntil };
    }
  }

  // 2. Check one-time XXXX-XXXX recovery codes (single-use consumption)
  if (userRow.recovery_codes_json) {
    try {
      const storedHashes: string[] = JSON.parse(userRow.recovery_codes_json);
      const normalizedRecovery = cleaned.includes('-')
        ? cleaned
        : cleaned.length === 8
        ? `${cleaned.slice(0, 4)}-${cleaned.slice(4)}`
        : cleaned;
      const candidateHash = sha256Hex(normalizedRecovery);
      const matchIdx = storedHashes.findIndex((h) => {
        const a = Buffer.from(h, 'utf8');
        const b = Buffer.from(candidateHash, 'utf8');
        return a.length === b.length && crypto.timingSafeEqual(a, b);
      });

      if (matchIdx !== -1) {
        storedHashes.splice(matchIdx, 1);
        const verifiedUntil = new Date(Date.now() + MFA_STEPUP_TTL_MS).toISOString();
        db.prepare('UPDATE users SET recovery_codes_json = ? WHERE id = ?').run(
          JSON.stringify(storedHashes),
          auth.user.id
        );
        db.prepare('UPDATE auth_sessions SET mfa_verified_until = ? WHERE token_hash = ?').run(
          verifiedUntil,
          auth.tokenHash
        );
        return { success: true, verifiedUntil, usedRecoveryCode: true };
      }
    } catch {
      // Ignore corrupt recovery JSON
    }
  }

  return {
    success: false,
    error: 'Invalid TOTP verification code or one-time recovery code.'
  };
}

export function getOrEnrollUserMfaDetails(userId: string): {
  totpSecret: string;
  otpAuthUri: string;
  remainingRecoveryCodes: number;
} {
  const userRow = db
    .prepare('SELECT id, username, totp_secret, recovery_codes_json FROM users WHERE id = ?')
    .get(userId) as any;
  if (!userRow) throw new Error('User not found');

  const settings = (db.prepare('SELECT brand_name, totp_secret FROM settings WHERE id = 1').get() || {}) as any;
  let secret = decryptVaultSecret(userRow.totp_secret);
  if (!secret) {
    secret = decryptVaultSecret(settings.totp_secret) || generateRandomBase32(20);
    db.prepare('UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?').run(
      encryptVaultSecret(secret),
      userId
    );
  }

  let remaining = 0;
  if (userRow.recovery_codes_json) {
    try {
      const parsed = JSON.parse(userRow.recovery_codes_json);
      if (Array.isArray(parsed)) remaining = parsed.length;
    } catch {
      remaining = 0;
    }
  }

  return {
    totpSecret: secret,
    otpAuthUri: buildOtpAuthUri(userRow.username, settings.brand_name || 'Vitrine RMM', secret),
    remainingRecoveryCodes: remaining
  };
}

// ============================================================================
// Scoped Guest Portal Session Tokens
// ============================================================================
export function issueGuestPortalToken(grantId: string, expiresAtIso: string): string {
  const grantExp = new Date(expiresAtIso).getTime();
  const exp = Math.min(grantExp, Date.now() + 4 * 60 * 60 * 1000);
  return hmacSignToken({
    scope: 'guest_portal',
    grantId,
    exp
  });
}

export function verifyGuestPortalRequest(req: FastifyRequest, expectedGrantId: string): boolean {
  const header = req.headers['x-guest-token'] || req.headers.authorization;
  let raw = '';
  if (typeof header === 'string') {
    raw = header.toLowerCase().startsWith('bearer ') ? header.slice(7).trim() : header.trim();
  }
  if (!raw) return false;
  const payload = hmacVerifyToken<{ scope?: string; grantId?: string }>(raw);
  return Boolean(payload && payload.scope === 'guest_portal' && payload.grantId === expectedGrantId);
}

