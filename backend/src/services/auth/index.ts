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
import { generateQrCodeSvg } from './qrcode.js';

export const SESSION_COOKIE_NAME = 'vitrine_session';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours
const MFA_STEPUP_TTL_MS = 10 * 60 * 1000; // 10 minutes

export const ALLOWED_USER_ROLES = new Set([
  'msp_super_admin',
  'super_admin',
  'admin',
  'technician',
  'client_admin',
  'auditor'
]);

export interface AuthenticatedUser {
  id: string;
  username: string;
  email: string;
  role: 'msp_super_admin' | 'super_admin' | 'technician' | 'client_admin' | 'auditor' | string;
  tenant_id: string | null;
  totp_enabled: boolean;
  totp_confirmed?: boolean;
  custom_role_id?: string | null;
  custom_role_name?: string | null;
  permissions?: string[];
  allowed_tenant_ids?: string[];
  is_api_key?: boolean;
}

export interface AuthContext {
  user: AuthenticatedUser;
  tokenHash: string;
  rawToken: string;
  authSource: 'cookie' | 'bearer' | 'api_key' | 'ws_ticket';
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
// Sliding-Window Rate Limiter (Per-Bucket Window Tracking)
// ============================================================================
interface RateBucket {
  timestamps: number[];
  windowMs: number;
}

const rateBuckets = new Map<string, RateBucket>();
const usedWsNonces = new Map<string, number>();

export function checkRateLimit(
  bucketKey: string,
  maxRequests: number,
  windowMs: number
): {
  allowed: boolean;
  retryAfterSec: number;
} {
  const now = Date.now();
  const cutoff = now - windowMs;
  const bucket = rateBuckets.get(bucketKey);
  const existing = (bucket?.timestamps || []).filter((ts) => ts > cutoff);

  if (existing.length >= maxRequests) {
    const retryAfterSec = Math.max(1, Math.ceil((existing[0] + windowMs - now) / 1000));
    rateBuckets.set(bucketKey, { timestamps: existing, windowMs });
    return { allowed: false, retryAfterSec };
  }

  existing.push(now);
  rateBuckets.set(bucketKey, { timestamps: existing, windowMs });

  // Periodic cleanup honoring each bucket's own windowMs so short-window routes
  // never prematurely prune 5m/10m login or MFA lockout buckets.
  if (rateBuckets.size > 4000) {
    for (const [k, b] of rateBuckets.entries()) {
      const bCutoff = now - b.windowMs;
      const pruned = b.timestamps.filter((ts) => ts > bCutoff);
      if (pruned.length === 0) rateBuckets.delete(k);
      else rateBuckets.set(k, { timestamps: pruned, windowMs: b.windowMs });
    }
  }

  return { allowed: true, retryAfterSec: 0 };
}

// ============================================================================
// Role, Custom Permission Matrix & Tenant Authorization Helpers
// ============================================================================
export function isSuperAdminRole(role?: string | null): boolean {
  return role === 'msp_super_admin' || role === 'super_admin' || role === 'admin';
}

export function isTechnicianOrAbove(role?: string | null): boolean {
  return isSuperAdminRole(role) || role === 'technician' || role === 'msp_tech';
}

export function isReadOnlyRole(role?: string | null): boolean {
  return role === 'client_admin' || role === 'auditor';
}

export function normalizeAndValidateRole(role?: string | null): string {
  const clean = String(role || '').trim().toLowerCase();
  if (!ALLOWED_USER_ROLES.has(clean)) {
    throw new Error(
      `Invalid role '${role}'. Allowed roles: msp_super_admin, super_admin, technician, client_admin, auditor.`
    );
  }
  return clean;
}

const DEFAULT_ROLE_PERMISSIONS: Record<string, string[]> = {
  technician: [
    'devices:read',
    'devices:manage',
    'remote:connect',
    'remote:unattended',
    'remote:elevate',
    'scripts:run',
    'scripts:write',
    'automations:manage',
    'patches:approve',
    'software:deploy',
    'laps:reveal',
    'laps:rotate',
    'alerts:triage',
    'docs:write',
    'psa:manage',
    'audit:export'
  ],
  client_admin: ['devices:read'],
  auditor: ['devices:read', 'audit:export']
};

export const ALL_GRANULAR_PERMISSIONS = [
  'devices:read',
  'devices:manage',
  'remote:connect',
  'remote:unattended',
  'remote:elevate',
  'scripts:run',
  'scripts:write',
  'automations:manage',
  'patches:approve',
  'software:deploy',
  'laps:reveal',
  'laps:rotate',
  'policies:write',
  'alerts:triage',
  'docs:write',
  'psa:manage',
  'users:manage',
  'backups:manage',
  'settings:write',
  'audit:export'
] as const;

const PERMISSION_SCOPE_ALIASES: Record<string, string> = {
  'read:devices': 'devices:read',
  'devices.read': 'devices:read',
  'devices.view': 'devices:read',
  'write:devices': 'devices:manage',
  'devices.write': 'devices:manage',
  'devices.manage': 'devices:manage',
  'remote.connect': 'remote:connect',
  'connect:remote': 'remote:connect',
  'remote.unattended': 'remote:unattended',
  'remote.elevate': 'remote:elevate',
  'run:scripts': 'scripts:run',
  'scripts.run': 'scripts:run',
  'write:scripts': 'scripts:write',
  'scripts.write': 'scripts:write',
  'scripts.manage': 'scripts:write',
  'automations.manage': 'automations:manage',
  'automations.write': 'automations:manage',
  'patches.approve': 'patches:approve',
  'patches.manage': 'patches:approve',
  'software.deploy': 'software:deploy',
  'software.manage': 'software:deploy',
  'laps.reveal': 'laps:reveal',
  'secrets.reveal': 'laps:reveal',
  'laps.rotate': 'laps:rotate',
  'policies.write': 'policies:write',
  'policies.manage': 'policies:write',
  'read:alerts': 'alerts:triage',
  'write:alerts': 'alerts:triage',
  'alerts.read': 'alerts:triage',
  'alerts.view': 'alerts:triage',
  'alerts.manage': 'alerts:triage',
  'alerts.triage': 'alerts:triage',
  'docs.view': 'docs:write',
  'docs.read': 'docs:write',
  'docs.write': 'docs:write',
  'docs.manage': 'docs:write',
  'psa.manage': 'psa:manage',
  'psa.write': 'psa:manage',
  'users.manage': 'users:manage',
  'users.write': 'users:manage',
  'backups.manage': 'backups:manage',
  'backups.write': 'backups:manage',
  'settings.write': 'settings:write',
  'settings.manage': 'settings:write',
  'audit.export': 'audit:export',
  'audit.read': 'audit:export',
  'audit.view': 'audit:export'
};

export function normalizePermissionScope(scope: string): string {
  const clean = String(scope || '').trim().toLowerCase();
  return PERMISSION_SCOPE_ALIASES[clean] || clean;
}

export function normalizePermissionScopes(scopes: string[] | null | undefined): string[] {
  if (!Array.isArray(scopes)) return [];
  const dedup = new Set<string>();
  for (const s of scopes) {
    const norm = normalizePermissionScope(s);
    if (norm) dedup.add(norm);
  }
  return Array.from(dedup);
}

export function resolveEffectivePermissions(
  role: string,
  customPermissions?: string[] | null
): string[] {
  if (isSuperAdminRole(role)) {
    return [...ALL_GRANULAR_PERMISSIONS];
  }
  if (customPermissions && customPermissions.length > 0) {
    return normalizePermissionScopes(customPermissions);
  }
  return DEFAULT_ROLE_PERMISSIONS[role] || ['devices:read'];
}

export function hasUserPermission(
  user: AuthenticatedUser | null | undefined,
  permission: string
): boolean {
  if (!user) return false;
  if (isSuperAdminRole(user.role) && !user.is_api_key) return true;
  const normalizedTarget = normalizePermissionScope(permission);
  const perms = normalizePermissionScopes(
    user.permissions || resolveEffectivePermissions(user.role)
  );
  return perms.includes(normalizedTarget) || perms.includes('*');
}

export function canUserAccessTenant(
  user: AuthenticatedUser | null | undefined,
  tenantId?: string | null
): boolean {
  if (!user) return false;
  if (isSuperAdminRole(user.role) && !user.is_api_key) return true;

  // Tenant-pinned accounts or API keys are strictly confined to their assigned tenant
  if (user.tenant_id) {
    return Boolean(tenantId && user.tenant_id === tenantId);
  }

  // Multi-tenant custom role or explicit tenant allowlist
  if (user.allowed_tenant_ids && user.allowed_tenant_ids.length > 0) {
    return Boolean(tenantId && user.allowed_tenant_ids.includes(tenantId));
  }

  // Global (unpinned) technicians, super-admin API keys, and MSP-wide compliance auditors
  if (isTechnicianOrAbove(user.role) || user.role === 'auditor') {
    return true;
  }

  // Fail-closed for client_admin or unrecognized roles without an assigned tenant
  return false;
}

/**
 * Returns the forced single-tenant filter for SQL queries, or '__DENY_ALL__' if a tenant-only
 * role (e.g. client_admin) has no assigned tenant (preventing null tenant_id fail-open leaks).
 * Note: When a user has multiple `allowed_tenant_ids` (>1), callers should also filter rows via `canUserAccessTenant`.
 */
export function getScopedTenantFilter(user: AuthenticatedUser | null | undefined): string | null {
  if (!user) return '__DENY_ALL__';
  if (isSuperAdminRole(user.role) && !user.is_api_key) return null;

  if (user.tenant_id) {
    return user.tenant_id;
  }

  if (user.allowed_tenant_ids && user.allowed_tenant_ids.length > 0) {
    return user.allowed_tenant_ids.length === 1 ? user.allowed_tenant_ids[0] : null;
  }

  if (isTechnicianOrAbove(user.role) || user.role === 'auditor') {
    return null;
  }

  return '__DENY_ALL__';
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
  return false;
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
  qrCodeSvg: string;
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
  const otpAuthUri = buildOtpAuthUri(username, issuer, totpSecret);
  const qrCodeSvg = generateQrCodeSvg(otpAuthUri);
  const { plaintextCodes, hashedCodes } = generateOneTimeRecoveryCodes(8);
  const passwordHash = hashPasswordScrypt(password);

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
          totp_confirmed_at = NULL,
          recovery_codes_json = ?
      WHERE id = ?
    `).run(username, email, passwordHash, encryptVaultSecret(totpSecret), JSON.stringify(hashedCodes), userId);
  } else {
    db.prepare(`
      INSERT INTO users (id, username, email, role, tenant_id, password_hash, totp_secret, totp_enabled, totp_confirmed_at, recovery_codes_json)
      VALUES (?, ?, ?, 'msp_super_admin', NULL, ?, ?, 1, NULL, ?)
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
      totp_enabled: true,
      totp_confirmed: false,
      permissions: resolveEffectivePermissions('msp_super_admin')
    },
    totpSecret,
    otpAuthUri,
    qrCodeSvg,
    recoveryCodes: plaintextCodes
  };
}

// ============================================================================
// Session Creation, Cookie Management, Revocation & Extraction
// ============================================================================
function sha256Hex(val: string): string {
  return crypto.createHash('sha256').update(val).digest('hex');
}

export function createUserSession(
  userId: string,
  ipAddress?: string,
  userAgent?: string
): { rawToken: string; expiresAt: string } {
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

export function revokeUserSessions(userId: string, keepTokenHash?: string): number {
  if (keepTokenHash) {
    return db
      .prepare('DELETE FROM auth_sessions WHERE user_id = ? AND token_hash != ?')
      .run(userId, keepTokenHash).changes;
  }
  return db.prepare('DELETE FROM auth_sessions WHERE user_id = ?').run(userId).changes;
}

export function listActiveSessions(filterUserId?: string): Array<{
  sessionPrefix: string;
  userId: string;
  username: string;
  role: string;
  ipAddress: string | null;
  userAgent: string | null;
  mfaVerified: boolean;
  createdAt: string;
  expiresAt: string;
}> {
  const nowIso = new Date().toISOString();
  const rows = (filterUserId
    ? db
        .prepare(`
          SELECT s.token_hash, s.user_id, s.ip_address, s.user_agent, s.mfa_verified_until, s.created_at, s.expires_at,
                 u.username, u.role
          FROM auth_sessions s
          JOIN users u ON s.user_id = u.id
          WHERE s.expires_at > ? AND s.user_id = ?
          ORDER BY s.created_at DESC
        `)
        .all(nowIso, filterUserId)
    : db
        .prepare(`
          SELECT s.token_hash, s.user_id, s.ip_address, s.user_agent, s.mfa_verified_until, s.created_at, s.expires_at,
                 u.username, u.role
          FROM auth_sessions s
          JOIN users u ON s.user_id = u.id
          WHERE s.expires_at > ?
          ORDER BY s.created_at DESC
        `)
        .all(nowIso)) as any[];

  return rows.map((r) => ({
    sessionPrefix: String(r.token_hash).slice(0, 12),
    userId: r.user_id,
    username: r.username,
    role: r.role,
    ipAddress: r.ip_address || null,
    userAgent: r.user_agent || null,
    mfaVerified: Boolean(r.mfa_verified_until && new Date(r.mfa_verified_until).getTime() > Date.now()),
    createdAt: r.created_at,
    expiresAt: r.expires_at
  }));
}

export function revokeSessionByPrefix(
  sessionPrefix: string,
  requesterUserId: string,
  requesterIsSuperAdmin: boolean
): boolean {
  const clean = (sessionPrefix || '').replace(/[^0-9a-f]/gi, '').toLowerCase();
  if (clean.length < 8) return false;
  const res = requesterIsSuperAdmin
    ? db.prepare('DELETE FROM auth_sessions WHERE token_hash LIKE ?').run(`${clean}%`)
    : db
        .prepare('DELETE FROM auth_sessions WHERE user_id = ? AND token_hash LIKE ?')
        .run(requesterUserId, `${clean}%`);
  return res.changes > 0;
}

export function setSessionCookie(reply: FastifyReply, req: FastifyRequest, rawToken: string): void {
  const isSecure =
    req.protocol === 'https' ||
    (process.env.VITRINE_TRUST_PROXY === 'true' && req.headers['x-forwarded-proto'] === 'https') ||
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

function hydrateUserRow(row: any): AuthenticatedUser {
  let customPerms: string[] | null = null;
  let allowedTenants: string[] = [];
  let customRoleName: string | null = null;

  if (row.custom_role_id) {
    try {
      const cr = db
        .prepare('SELECT name, base_tier, permissions_json, allowed_tenant_ids_json FROM custom_roles WHERE id = ?')
        .get(row.custom_role_id) as any;
      if (cr) {
        customRoleName = cr.name;
        if (cr.permissions_json) customPerms = JSON.parse(cr.permissions_json);
        if (cr.allowed_tenant_ids_json) allowedTenants = JSON.parse(cr.allowed_tenant_ids_json);
      }
    } catch {
      // Ignore missing custom_roles table during bootstrap
    }
  }

  return {
    id: row.id,
    username: row.username,
    email: row.email,
    role: row.role,
    tenant_id: row.tenant_id || null,
    totp_enabled: Boolean(row.totp_enabled),
    totp_confirmed: Boolean(row.totp_confirmed_at),
    custom_role_id: row.custom_role_id || null,
    custom_role_name: customRoleName,
    permissions: resolveEffectivePermissions(row.role, customPerms),
    allowed_tenant_ids: allowedTenants
  };
}

export function issueEphemeralWsTicket(params: {
  userId?: string;
  grantId?: string;
}): string {
  const nonce = crypto.randomBytes(12).toString('hex');
  return hmacSignToken({
    scope: 'ws_ticket',
    userId: params.userId || null,
    grantId: params.grantId || null,
    nonce,
    exp: Date.now() + 45_000
  });
}

export function consumeEphemeralWsTicket(ticket?: string | null): {
  userId?: string | null;
  grantId?: string | null;
} | null {
  const payload = hmacVerifyToken<{
    scope?: string;
    userId?: string | null;
    grantId?: string | null;
    nonce?: string;
    exp?: number;
  }>(ticket);
  if (!payload || payload.scope !== 'ws_ticket' || !payload.nonce) return null;

  const now = Date.now();
  for (const [n, exp] of usedWsNonces.entries()) {
    if (exp <= now) usedWsNonces.delete(n);
  }
  if (usedWsNonces.has(payload.nonce)) return null;
  usedWsNonces.set(payload.nonce, payload.exp || now + 45_000);

  return { userId: payload.userId, grantId: payload.grantId };
}

export function issuePublicApiKey(params: {
  name: string;
  role?: string;
  scopes: string[];
  tenantId?: string | null;
  createdBy: string;
  expiresInDays?: number | null;
}): { id: string; rawKey: string; keyPrefix: string; expiresAt: string | null } {
  const id = `ak-${crypto.randomUUID().slice(0, 12)}`;
  const secretBody = crypto.randomBytes(28).toString('base64url');
  const rawKey = `vrmm_live_${secretBody}`;
  const keyPrefix = rawKey.slice(0, 16);
  const keyHash = sha256Hex(rawKey);
  const expiresAt =
    params.expiresInDays && params.expiresInDays > 0
      ? new Date(Date.now() + params.expiresInDays * 86_400_000).toISOString()
      : null;

  const normalizedScopes = normalizePermissionScopes(params.scopes);
  const cleanRole = ALLOWED_USER_ROLES.has(String(params.role || '').trim().toLowerCase())
    ? String(params.role).trim().toLowerCase()
    : params.tenantId
    ? 'client_admin'
    : 'technician';
  const boundedRole = params.tenantId && isSuperAdminRole(cleanRole) ? 'technician' : cleanRole;

  db.prepare(`
    INSERT INTO api_keys (id, name, role, key_prefix, key_hash, scopes_json, tenant_id, created_by, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    params.name.trim(),
    boundedRole,
    keyPrefix,
    keyHash,
    JSON.stringify(normalizedScopes.length > 0 ? normalizedScopes : ['devices:read']),
    params.tenantId || null,
    params.createdBy,
    expiresAt
  );

  return { id, rawKey, keyPrefix, expiresAt };
}

export const createScopedApiKey = issuePublicApiKey;

export function listScopedApiKeys() {
  const rows = db
    .prepare(
      'SELECT id, name, role, key_prefix, scopes_json, tenant_id, created_by, expires_at, last_used_at, revoked_at, created_at FROM api_keys ORDER BY created_at DESC'
    )
    .all() as any[];
  return rows.map((r) => ({
    ...r,
    scopes: (() => {
      try {
        return JSON.parse(r.scopes_json || '[]');
      } catch {
        return [];
      }
    })(),
    revoked: Boolean(r.revoked_at)
  }));
}

export function revokeScopedApiKey(id: string): boolean {
  const res = db
    .prepare('UPDATE api_keys SET revoked_at = CURRENT_TIMESTAMP WHERE id = ?')
    .run(id);
  return res.changes > 0;
}

export function extractAuthContext(req: FastifyRequest): AuthContext | null {
  // 1. Check Scoped Public REST API Key (X-API-Key or Bearer vrmm_live_...)
  const apiKeyHeader = typeof req.headers['x-api-key'] === 'string' ? req.headers['x-api-key'].trim() : '';
  const authHeader = typeof req.headers.authorization === 'string' ? req.headers.authorization.trim() : '';
  const bearerVal = authHeader.toLowerCase().startsWith('bearer ') ? authHeader.slice(7).trim() : '';
  const candidateApiKey =
    apiKeyHeader.startsWith('vrmm_live_')
      ? apiKeyHeader
      : bearerVal.startsWith('vrmm_live_')
      ? bearerVal
      : '';

  if (candidateApiKey) {
    const keyHash = sha256Hex(candidateApiKey);
    try {
      const keyRow = db
        .prepare('SELECT * FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL')
        .get(keyHash) as any;
      if (!keyRow) return null;
      if (keyRow.expires_at && new Date(keyRow.expires_at).getTime() <= Date.now()) {
        return null;
      }
      db.prepare('UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?').run(keyRow.id);
      let scopes: string[] = ['devices:read'];
      try {
        scopes = JSON.parse(keyRow.scopes_json || '[]');
      } catch {
        scopes = ['devices:read'];
      }
      const mappedPerms = normalizePermissionScopes(scopes);
      const rawKeyRole = String(keyRow.role || '').trim().toLowerCase();
      const validRole = ALLOWED_USER_ROLES.has(rawKeyRole)
        ? rawKeyRole
        : keyRow.tenant_id
        ? 'client_admin'
        : 'technician';
      // Tenant-scoped API keys can never escalate to global super_admin tier
      const effectiveRole = keyRow.tenant_id && isSuperAdminRole(validRole) ? 'technician' : validRole;

      return {
        user: {
          id: keyRow.id,
          username: `apikey:${keyRow.name}`,
          email: '',
          role: effectiveRole,
          tenant_id: keyRow.tenant_id || null,
          totp_enabled: false,
          permissions: mappedPerms.length > 0 ? mappedPerms : ['devices:read'],
          allowed_tenant_ids: keyRow.tenant_id ? [keyRow.tenant_id] : [],
          is_api_key: true
        },
        tokenHash: keyHash,
        rawToken: candidateApiKey,
        authSource: 'api_key',
        mfaVerified: false,
        mfaVerifiedUntil: null
      };
    } catch {
      return null;
    }
  }

  // If X-API-Key was explicitly provided with a non-vrmm_live_ value, do NOT silently fall back to cookies
  if (apiKeyHeader) {
    return null;
  }

  // 2. Check standard Bearer header, HttpOnly session cookie, or ephemeral WS ticket
  let rawToken = '';
  let authSource: AuthContext['authSource'] = 'cookie';

  if (authHeader) {
    if (!bearerVal || bearerVal.startsWith('vrmm_live_')) {
      return null;
    }
    rawToken = bearerVal;
    authSource = 'bearer';
  } else if (req.headers.cookie) {
    const cookies = parseCookies(req.headers.cookie);
    if (cookies[SESSION_COOKIE_NAME]) {
      rawToken = cookies[SESSION_COOKIE_NAME];
      authSource = 'cookie';
    }
  }
  if (!rawToken && req.url?.startsWith('/ws/')) {
    const q = (req.query || {}) as Record<string, string>;
    if (q.ticket) {
      const consumed = consumeEphemeralWsTicket(q.ticket);
      if (consumed?.userId) {
        const uRow = db.prepare('SELECT * FROM users WHERE id = ?').get(consumed.userId) as any;
        if (uRow) {
          return {
            user: hydrateUserRow(uRow),
            tokenHash: `ws-ticket-${consumed.userId}`,
            rawToken: '',
            authSource: 'ws_ticket',
            mfaVerified: false,
            mfaVerifiedUntil: null
          };
        }
      }
    }
    if (q.token) {
      rawToken = q.token;
      authSource = 'bearer';
    }
  }

  if (!rawToken || rawToken.length < 20) return null;

  const tokenHash = sha256Hex(rawToken);
  const row = db
    .prepare(`
      SELECT s.token_hash, s.expires_at, s.mfa_verified_until,
             u.id, u.username, u.email, u.role, u.tenant_id, u.totp_enabled, u.totp_confirmed_at, u.custom_role_id
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
    user: hydrateUserRow(row),
    tokenHash,
    rawToken,
    authSource,
    mfaVerified,
    mfaVerifiedUntil: row.mfa_verified_until || null
  };
}

export function isSessionTokenActive(tokenHash?: string | null): AuthenticatedUser | null {
  if (!tokenHash) return null;
  if (tokenHash.startsWith('ws-ticket-')) {
    const uid = tokenHash.slice('ws-ticket-'.length);
    const activeSession = db
      .prepare('SELECT expires_at FROM auth_sessions WHERE user_id = ? ORDER BY expires_at DESC LIMIT 1')
      .get(uid) as { expires_at?: string } | undefined;
    if (!activeSession?.expires_at || new Date(activeSession.expires_at).getTime() <= Date.now()) {
      return null;
    }
    const uRow = db.prepare('SELECT * FROM users WHERE id = ?').get(uid) as any;
    return uRow ? hydrateUserRow(uRow) : null;
  }
  const row = db
    .prepare(`
      SELECT s.expires_at, u.id, u.username, u.email, u.role, u.tenant_id, u.totp_enabled, u.totp_confirmed_at, u.custom_role_id
      FROM auth_sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.token_hash = ?
    `)
    .get(tokenHash) as any;

  if (!row) {
    // Also support live revocation/expiry checks for scoped API keys over WebSockets
    const keyRow = db
      .prepare('SELECT * FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL')
      .get(tokenHash) as any;
    if (!keyRow) return null;
    if (keyRow.expires_at && new Date(keyRow.expires_at).getTime() <= Date.now()) return null;
    let scopes: string[] = ['devices:read'];
    try {
      scopes = JSON.parse(keyRow.scopes_json || '[]');
    } catch {
      scopes = ['devices:read'];
    }
    const mappedPerms = normalizePermissionScopes(scopes);
    const rawKeyRole = String(keyRow.role || '').trim().toLowerCase();
    const validRole = ALLOWED_USER_ROLES.has(rawKeyRole)
      ? rawKeyRole
      : keyRow.tenant_id
      ? 'client_admin'
      : 'technician';
    const effectiveRole = keyRow.tenant_id && isSuperAdminRole(validRole) ? 'technician' : validRole;
    return {
      id: keyRow.id,
      username: `apikey:${keyRow.name}`,
      email: '',
      role: effectiveRole,
      tenant_id: keyRow.tenant_id || null,
      totp_enabled: false,
      permissions: mappedPerms.length > 0 ? mappedPerms : ['devices:read'],
      allowed_tenant_ids: keyRow.tenant_id ? [keyRow.tenant_id] : [],
      is_api_key: true
    };
  }
  if (!row.expires_at || new Date(row.expires_at).getTime() <= Date.now()) {
    db.prepare('DELETE FROM auth_sessions WHERE token_hash = ?').run(tokenHash);
    return null;
  }
  return hydrateUserRow(row);
}

export function authenticateUserPassword(
  identifier: string,
  password: string
): AuthenticatedUser | null {
  const cleanId = (identifier || '').trim();
  if (!cleanId || !password) return null;

  const row = db
    .prepare(
      'SELECT id, username, email, role, tenant_id, password_hash, totp_enabled, totp_confirmed_at, custom_role_id FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?) LIMIT 1'
    )
    .get(cleanId, cleanId) as any;

  if (!row || !row.password_hash) {
    hashPasswordScrypt('dummy-timing-equalizer');
    return null;
  }

  if (!verifyPasswordScrypt(password, row.password_hash)) {
    return null;
  }

  return hydrateUserRow(row);
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

  // Per-user rate limit (in addition to IP rate limit) so rotating IPs cannot brute-force 6-digit TOTP
  const userRate = checkRateLimit(`mfa-user:${auth.user.id}`, 8, 5 * 60_000);
  if (!userRate.allowed) {
    return {
      success: false,
      error: `Too many MFA verification attempts for this account. Try again in ${userRate.retryAfterSec}s.`
    };
  }

  const txVerify = db.transaction((): {
    success: boolean;
    verifiedUntil?: string;
    usedRecoveryCode?: boolean;
    error?: string;
  } => {
    const userRow = db
      .prepare(
        'SELECT id, username, totp_secret, last_totp_step, totp_confirmed_at, recovery_codes_json FROM users WHERE id = ?'
      )
      .get(auth.user.id) as any;

    if (!userRow) {
      return { success: false, error: 'User account not found.' };
    }

    const userSecret = decryptVaultSecret(userRow.totp_secret);

    // 1. Check 6-digit RFC 6238 TOTP with atomic replay guard
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
        db.prepare(
          'UPDATE users SET last_totp_step = ?, totp_enabled = 1, totp_confirmed_at = COALESCE(totp_confirmed_at, CURRENT_TIMESTAMP) WHERE id = ?'
        ).run(check.matchedStep, auth.user.id);
        db.prepare('UPDATE auth_sessions SET mfa_verified_until = ? WHERE token_hash = ?').run(
          verifiedUntil,
          auth.tokenHash
        );
        return { success: true, verifiedUntil };
      }
    }

    // 2. Check one-time XXXX-XXXX recovery codes (atomic single-use consumption)
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
          db.prepare(
            'UPDATE users SET recovery_codes_json = ?, totp_confirmed_at = COALESCE(totp_confirmed_at, CURRENT_TIMESTAMP) WHERE id = ?'
          ).run(JSON.stringify(storedHashes), auth.user.id);
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
  });

  return txVerify.immediate();
}

/**
 * Returns TOTP secret & scannable SVG QR code ONLY during initial unconfirmed enrollment
 * OR when the caller has already completed Step-Up MFA verification (closing CRIT-01).
 */
export function getOrEnrollUserMfaDetails(
  userId: string,
  options?: { callerMfaVerified?: boolean; resetEnrollment?: boolean }
): {
  enrolled: boolean;
  confirmed: boolean;
  secretRedacted: boolean;
  totpSecret: string | null;
  otpAuthUri: string | null;
  qrCodeSvg: string | null;
  remainingRecoveryCodes: number;
  newRecoveryCodes?: string[];
} {
  const userRow = db
    .prepare('SELECT id, username, totp_secret, totp_confirmed_at, recovery_codes_json FROM users WHERE id = ?')
    .get(userId) as any;
  if (!userRow) throw new Error('User not found');

  const settings = (db.prepare('SELECT brand_name FROM settings WHERE id = 1').get() || {}) as any;
  let secret = decryptVaultSecret(userRow.totp_secret);
  let newPlainRecoveryCodes: string[] | undefined;

  if (!secret || options?.resetEnrollment) {
    secret = generateRandomBase32(20);
    const { plaintextCodes, hashedCodes } = generateOneTimeRecoveryCodes(8);
    newPlainRecoveryCodes = plaintextCodes;
    db.prepare(
      'UPDATE users SET totp_secret = ?, totp_enabled = 1, totp_confirmed_at = NULL, last_totp_step = NULL, recovery_codes_json = ? WHERE id = ?'
    ).run(encryptVaultSecret(secret), JSON.stringify(hashedCodes), userId);
    userRow.totp_confirmed_at = null;
    userRow.recovery_codes_json = JSON.stringify(hashedCodes);
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

  const isConfirmed = Boolean(userRow.totp_confirmed_at);
  const canExposeSecret = !isConfirmed || Boolean(options?.callerMfaVerified) || Boolean(options?.resetEnrollment);

  if (!canExposeSecret) {
    return {
      enrolled: true,
      confirmed: true,
      secretRedacted: true,
      totpSecret: null,
      otpAuthUri: null,
      qrCodeSvg: null,
      remainingRecoveryCodes: remaining
    };
  }

  const otpAuthUri = buildOtpAuthUri(userRow.username, settings.brand_name || 'Vitrine RMM', secret);
  return {
    enrolled: true,
    confirmed: isConfirmed,
    secretRedacted: false,
    totpSecret: secret,
    otpAuthUri,
    qrCodeSvg: generateQrCodeSvg(otpAuthUri),
    remainingRecoveryCodes: remaining,
    ...(newPlainRecoveryCodes ? { newRecoveryCodes: newPlainRecoveryCodes } : {})
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
  const header =
    req.headers['x-vitrine-guest-token'] ||
    req.headers['x-guest-token'] ||
    req.headers.authorization;
  let raw = '';
  if (typeof header === 'string') {
    raw = header.toLowerCase().startsWith('bearer ') ? header.slice(7).trim() : header.trim();
  }
  if (!raw) return false;
  const payload = hmacVerifyToken<{ scope?: string; grantId?: string }>(raw);
  return Boolean(payload && payload.scope === 'guest_portal' && payload.grantId === expectedGrantId);
}
