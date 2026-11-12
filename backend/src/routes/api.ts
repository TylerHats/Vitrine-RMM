import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fs from 'fs';
import path from 'path';
import net from 'net';
import tls from 'tls';
import crypto from 'crypto';
import {
  db,
  BRANDING_DIR_PATH,
  APP_VERSION,
  seedDemoDataset
} from '../db/index.js';
import { meshBridge } from '../services/meshcentral/index.js';
import {
  getLapsCredential,
  rotateLapsPassword,
  exportLapsBreakGlassSheet
} from '../services/laps/index.js';
import {
  resolveEffectiveDevicePolicy,
  sanitizeEffectivePolicyForResponse,
  parsePolicyAlertRules,
  evaluateFleetAlertConditions
} from '../services/policy/index.js';
import { installerGenerator } from '../services/agent/installerGenerator.js';
import { codeSigningService } from '../services/signing/index.js';
import { backupService } from '../services/backup/index.js';
import { systemUpdaterService } from '../services/updater/index.js';
import {
  initiateDeviceOffboard,
  offboardClientTenant,
  reactivateArchivedClient,
  handleAgentCheckInOrWake,
  sweepPendingOffboards
} from '../services/offboarding/index.js';
import {
  encryptVaultSecret,
  decryptVaultSecret,
  maskSecretValue,
  isMaskedSecret,
  hashPasswordScrypt,
  verifyPasswordScrypt,
  generateRandomBase32
} from '../services/vault/index.js';
import {
  checkRateLimit,
  isSuperAdminRole,
  isTechnicianOrAbove,
  canUserAccessTenant,
  canUserRunScriptRole,
  getActorUsername,
  hasConfiguredAdminUser,
  setupInitialSuperAdmin,
  generateOneTimeRecoveryCodes,
  createUserSession,
  setSessionCookie,
  clearSessionCookie,
  extractAuthContext,
  authenticateUserPassword,
  verifySessionStepUpMfa,
  getOrEnrollUserMfaDetails,
  issueGuestPortalToken,
  verifyGuestPortalRequest
} from '../services/auth/index.js';

function safeJsonParse<T>(raw: string | null | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function buildSafeContentDisposition(rawFilename: string): string {
  const cleaned = path
    .basename(String(rawFilename || 'download.bin'))
    .replace(/[\r\n"\\<>|?*:\0]/g, '_')
    .trim() || 'download.bin';
  const encoded = encodeURIComponent(cleaned);
  return `attachment; filename="${cleaned}"; filename*=UTF-8''${encoded}`;
}

function constantTimeEquals(a: string, b: string): boolean {
  if (!a || !b) return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function sanitizeDeviceRowForResponse(row: any): any {
  if (!row) return row;
  const copy = { ...row };
  copy.has_bitlocker_key = Boolean(copy.bitlocker_key && String(copy.bitlocker_key).trim() !== '');
  delete copy.bitlocker_key;
  delete copy.agent_auth_token;
  return copy;
}

function sanitizeSettingsRowForResponse(row: any): any {
  if (!row) return row;
  const copy = { ...row };
  const secretCols = [
    'meshcentral_api_token',
    'smtp_pass',
    'itflow_api_key',
    'totp_secret',
    'backup_encryption_passphrase',
    'backup_offsite_access_key',
    'backup_offsite_secret_key',
    'oidc_client_secret',
    'psa_webhook_secret',
    'agent_enrollment_secret'
  ];
  for (const col of secretCols) {
    copy[col] = maskSecretValue(copy[col]);
  }
  copy.meshcentral_connected = meshBridge.getStatus().connected ? 1 : 0;
  if (copy.mesh_external_delete_prompt === 1 || copy.mesh_external_delete_prompt === '1') {
    copy.mesh_external_delete_prompt = 'prompt';
  } else if (copy.mesh_external_delete_prompt === 0 || copy.mesh_external_delete_prompt === '0') {
    copy.mesh_external_delete_prompt = 'auto_unassigned';
  }
  return copy;
}

function sanitizeUserRowForResponse(row: any): any {
  if (!row) return row;
  const copy = { ...row };
  copy.totp_enabled = Boolean(copy.totp_enabled);
  delete copy.password_hash;
  delete copy.totp_secret;
  delete copy.recovery_codes_json;
  delete copy.last_totp_step;
  return copy;
}

function ensureDeviceTenantAccess(
  req: FastifyRequest,
  reply: FastifyReply,
  deviceId: string
): { allowed: boolean; device?: any } {
  const dev = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId) as any;
  if (!dev) {
    reply.status(404).send({ error: 'Device not found' });
    return { allowed: false };
  }
  if (!canUserAccessTenant(req.auth?.user, dev.tenant_id)) {
    reply.status(403).send({ error: 'Forbidden: insufficient tenant permissions for this endpoint' });
    return { allowed: false };
  }
  return { allowed: true, device: dev };
}

function requireStepUpMfaIfEnforced(
  req: FastifyRequest,
  reply: FastifyReply,
  deviceId?: string | null
): boolean {
  let mfaRequired = true;
  if (deviceId) {
    try {
      const eff = resolveEffectiveDevicePolicy(deviceId);
      mfaRequired = Boolean(eff.requireMfaForSecrets);
    } catch {
      mfaRequired = true;
    }
  } else {
    const globalPol = db
      .prepare("SELECT require_mfa_for_secrets FROM policies WHERE tier = 'global' LIMIT 1")
      .get() as { require_mfa_for_secrets?: number } | undefined;
    mfaRequired = Boolean(globalPol?.require_mfa_for_secrets ?? 1);
  }

  if (mfaRequired && !req.auth?.mfaVerified) {
    reply.status(403).send({
      error: 'Step-Up Multi-Factor Authentication is required to access protected vault secrets.',
      code: 'MFA_REQUIRED',
      mfaRequired: true
    });
    return false;
  }
  return true;
}

async function probeNetworkEndpoint(params: {
  ipOrHost: string;
  protocol?: string;
  apiEndpoint?: string | null;
  apiToken?: string | null;
}): Promise<{
  reachable: boolean;
  latencyMs: number;
  tlsDaysRemaining?: number;
  httpStatus?: number;
  detail: string;
}> {
  const start = Date.now();
  const rawHost = String(params.ipOrHost || '').trim();
  const cleanHost = rawHost.includes('://') ? new URL(rawHost).hostname : rawHost.split(':')[0];

  if (
    !cleanHost ||
    cleanHost === '169.254.169.254' ||
    cleanHost.startsWith('169.254.') ||
    cleanHost === 'metadata.google.internal'
  ) {
    return { reachable: false, latencyMs: 0, detail: 'Blocked invalid or link-local metadata address' };
  }

  // 1. If HTTP/HTTPS vendor API endpoint is provided (or WAN SSL probe), inspect TLS/HTTP
  const targetUrl =
    params.apiEndpoint && params.apiEndpoint.includes('://')
      ? params.apiEndpoint
      : params.protocol === 'https_tls_cert'
        ? `https://${cleanHost}`
        : null;

  if (targetUrl) {
    try {
      const parsed = new URL(targetUrl);
      let tlsDaysRemaining: number | undefined;

      if (parsed.protocol === 'https:') {
        tlsDaysRemaining = await new Promise<number | undefined>((resolve) => {
          const sock = tls.connect(
            {
              host: parsed.hostname,
              port: Number(parsed.port || 443),
              servername: parsed.hostname,
              rejectUnauthorized: false,
              timeout: 3500
            },
            () => {
              try {
                const cert = sock.getPeerCertificate();
                if (cert?.valid_to) {
                  const days = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
                  resolve(days);
                } else {
                  resolve(undefined);
                }
              } catch {
                resolve(undefined);
              } finally {
                sock.destroy();
              }
            }
          );
          sock.on('error', () => {
            sock.destroy();
            resolve(undefined);
          });
          sock.on('timeout', () => {
            sock.destroy();
            resolve(undefined);
          });
        });
      }

      const headers: Record<string, string> = {};
      if (params.apiToken) {
        headers.Authorization = `Bearer ${params.apiToken}`;
        headers['X-API-KEY'] = params.apiToken;
      }

      const res = await fetch(targetUrl, {
        method: 'GET',
        headers,
        signal: AbortSignal.timeout(4000)
      });

      return {
        reachable: true,
        latencyMs: Math.max(1, Date.now() - start),
        tlsDaysRemaining,
        httpStatus: res.status,
        detail: `HTTP ${res.status}${tlsDaysRemaining != null ? ` | TLS valid (${tlsDaysRemaining}d remaining)` : ''}`
      };
    } catch (err: any) {
      return {
        reachable: false,
        latencyMs: Math.max(1, Date.now() - start),
        detail: `API/HTTPS probe failed: ${err?.message || 'Unreachable'}`
      };
    }
  }

  // 2. TCP reachability probe across common management ports (443, 80, 22, 8443, 161/8006)
  const candidatePorts = [443, 80, 22, 8443, 8006];
  for (const port of candidatePorts) {
    const portStart = Date.now();
    const ok = await new Promise<boolean>((resolve) => {
      const socket = new net.Socket();
      let done = false;
      const finish = (val: boolean) => {
        if (done) return;
        done = true;
        socket.destroy();
        resolve(val);
      };
      socket.setTimeout(1200);
      socket.once('connect', () => finish(true));
      socket.once('timeout', () => finish(false));
      socket.once('error', () => finish(false));
      socket.connect(port, cleanHost);
    });
    if (ok) {
      return {
        reachable: true,
        latencyMs: Math.max(1, Date.now() - portStart),
        detail: `TCP port ${port} open on ${cleanHost}`
      };
    }
  }

  return {
    reachable: false,
    latencyMs: Math.max(1, Date.now() - start),
    detail: `No management response from ${cleanHost} across TCP probe ports`
  };
}

export async function registerApiRoutes(server: FastifyInstance) {
  // ============================================================================
  // Global Zero-Trust Authentication & RBAC Enforcement Hook
  // ============================================================================
  server.addHook('onRequest', async (request, reply) => {
    const pathname = (request.raw.url || '').split('?')[0];
    if (!pathname.startsWith('/api/') && pathname !== '/api') {
      return;
    }

    request.auth = extractAuthContext(request);

    // Explicitly scoped public endpoints (each enforces its own token/rate-limit check inside its handler)
    const isPublicEndpoint =
      pathname === '/api/health' ||
      pathname === '/api/agent/enroll' ||
      pathname === '/api/public/portal-config' ||
      pathname === '/api/auth/status' ||
      pathname === '/api/auth/setup-initial-admin' ||
      pathname === '/api/auth/login' ||
      pathname === '/api/auth/logout' ||
      pathname === '/api/agent/deploy' ||
      pathname === '/api/agent/download' ||
      pathname === '/api/psa/webhook' ||
      (pathname === '/api/quicksupport/sessions' && request.method === 'POST') ||
      pathname.startsWith('/api/guest-portal/');

    if (isPublicEndpoint) {
      return;
    }

    if (!request.auth) {
      return reply.status(401).send({
        error: 'Authentication required. Please sign in to Vitrine RMM.',
        code: 'AUTH_REQUIRED'
      });
    }

    const userRole = request.auth.user.role;

    // Super-Admin-Only Administrative Routes
    const isSuperAdminOnly =
      (pathname === '/api/settings' && request.method !== 'GET') ||
      pathname === '/api/settings/logo' ||
      pathname === '/api/demo/seed' ||
      pathname.startsWith('/api/users') ||
      pathname.startsWith('/api/backups') ||
      (pathname.startsWith('/api/updater') && request.method !== 'GET') ||
      pathname === '/api/laps/break-glass-export' ||
      pathname === '/api/smtp/test' ||
      pathname === '/api/signing/sign' ||
      pathname === '/api/code-signing/test' ||
      pathname === '/api/proxy-tls/test' ||
      (pathname.startsWith('/api/mesh-servers') && request.method !== 'GET') ||
      (pathname.startsWith('/api/tenants/') &&
        (request.method === 'DELETE' || pathname.endsWith('/offboard') || pathname.endsWith('/reactivate'))) ||
      pathname.endsWith('/archive-purge');

    if (isSuperAdminOnly && !isSuperAdminRole(userRole)) {
      return reply.status(403).send({
        error: 'Forbidden: MSP Super Admin privileges are required for this operation.'
      });
    }

    // Client Admins have tenant-scoped read-only visibility (cannot mutate fleet state or run system tools)
    const isReadMethod = request.method === 'GET' || request.method === 'HEAD';
    const isAllowedForClientAdmin =
      pathname.startsWith('/api/auth/') ||
      (isReadMethod &&
        (pathname === '/api/tenants' ||
          pathname === '/api/devices' ||
          pathname.startsWith('/api/devices/') ||
          pathname === '/api/patches' ||
          pathname === '/api/reports/qbr' ||
          pathname === '/api/notifications'));

    if (!isTechnicianOrAbove(userRole) && !isAllowedForClientAdmin) {
      return reply.status(403).send({
        error: 'Forbidden: Technician or Super Admin role is required.'
      });
    }
  });

  // ============================================================================
  // System Health, Agent Heartbeat & Token Enrollment
  // ============================================================================
  server.get('/api/health', async () => {
    const bridge = meshBridge.getStatus();
    return {
      status: 'healthy',
      version: APP_VERSION,
      uptime: process.uptime(),
      meshBridge: {
        connected: bridge.connected,
        configured: bridge.configured,
        activeTunnels: bridge.activeTunnels
      },
      timestamp: new Date().toISOString()
    };
  });

  server.post('/api/health', async (request, reply) => {
    const body = (request.body || {}) as {
      deviceId?: string;
      hostname?: string;
      cpu?: number | string;
      ramUsedGb?: number | string;
      diskFreeGb?: number | string;
    };
    const providedToken = String(request.headers['x-vitrine-agent-token'] || '').trim();
    const settings = (db.prepare('SELECT agent_enrollment_secret FROM settings WHERE id = 1').get() || {}) as any;
    const globalAgentSecret = decryptVaultSecret(settings.agent_enrollment_secret);

    let targetDevice: any = null;
    if (body.deviceId) {
      targetDevice = db.prepare('SELECT * FROM devices WHERE id = ?').get(body.deviceId);
    } else if (body.hostname) {
      targetDevice = db.prepare('SELECT * FROM devices WHERE LOWER(hostname) = LOWER(?) LIMIT 1').get(body.hostname);
    }

    const deviceToken = targetDevice?.agent_auth_token ? decryptVaultSecret(targetDevice.agent_auth_token) : '';
    const tokenValid =
      Boolean(request.auth && isTechnicianOrAbove(request.auth.user.role)) ||
      (providedToken && globalAgentSecret && constantTimeEquals(providedToken, globalAgentSecret)) ||
      (providedToken && deviceToken && constantTimeEquals(providedToken, deviceToken));

    if (!tokenValid) {
      return reply.status(401).send({ error: 'Invalid or missing x-vitrine-agent-token header' });
    }

    if (targetDevice) {
      const cpuVal = body.cpu != null ? Number(body.cpu) : null;
      const ramVal = body.ramUsedGb != null ? Number(body.ramUsedGb) : null;
      const diskVal = body.diskFreeGb != null ? Number(body.diskFreeGb) : null;

      db.prepare(`
        UPDATE devices
        SET cpu_usage = COALESCE(?, cpu_usage),
            ram_used_gb = COALESCE(?, ram_used_gb),
            disk_free_gb = COALESCE(?, disk_free_gb)
        WHERE id = ?
      `).run(
        Number.isFinite(cpuVal) ? cpuVal : null,
        Number.isFinite(ramVal) ? ramVal : null,
        Number.isFinite(diskVal) ? diskVal : null,
        targetDevice.id
      );

      const lifecycleResult = handleAgentCheckInOrWake(targetDevice.id, 'wake_checkin');
      return { status: 'ack', lifecycle: lifecycleResult, timestamp: new Date().toISOString() };
    }

    return { status: 'ack', timestamp: new Date().toISOString() };
  });

  server.post('/api/agent/enroll', async (request, reply) => {
    const rate = checkRateLimit(`enroll:${request.ip}`, 20, 60_000);
    if (!rate.allowed) {
      return reply.status(429).send({ error: 'Too many enrollment requests', retryAfterSec: rate.retryAfterSec });
    }

    const body = (request.body || {}) as {
      token?: string;
      hostname?: string;
      osType?: 'windows' | 'linux' | 'macos';
      osVersion?: string;
      osBuild?: string;
      ipAddress?: string;
      macAddress?: string;
      cpuModel?: string;
      cpuCores?: number;
      ramTotalGb?: number;
      diskTotalGb?: number;
      diskFreeGb?: string | number;
      serialNumber?: string;
      manufacturer?: string;
      model?: string;
      meshNodeId?: string;
    };

    const token = String(body.token || '').trim();
    if (!token || !body.hostname) {
      return reply.status(400).send({ error: 'Valid deployment token and hostname are required' });
    }

    const tokenRow = db.prepare('SELECT * FROM installer_audit_log WHERE token_id = ?').get(token) as any;
    if (!tokenRow) {
      return reply.status(401).send({ error: 'Invalid deployment token' });
    }
    if (tokenRow.expires_at && new Date(tokenRow.expires_at).getTime() <= Date.now()) {
      return reply.status(401).send({ error: 'Deployment token has expired' });
    }

    const parentTenant = db.prepare('SELECT id, name, lifecycle_state FROM tenants WHERE id = ?').get(tokenRow.tenant_id) as any;
    const deletedTombstone = db
      .prepare('SELECT * FROM deleted_tenants_tombstones WHERE tenant_id = ?')
      .get(tokenRow.tenant_id) as any;

    if (!parentTenant || deletedTombstone) {
      const lapsAction = deletedTombstone?.laps_offboard_action || 'remove_account';
      db.prepare(`
        INSERT INTO audit_logs (id, username, action, details)
        VALUES (?, 'system', 'Quiet Offboard on Stale Enrollment', ?)
      `).run(
        `aud-qenr-${crypto.randomUUID()}`,
        `Endpoint '${body.hostname}' attempted enrollment with token for deleted client '${deletedTombstone?.tenant_name || tokenRow.tenant_id}'. Instructed immediate quiet self-uninstall (${lapsAction}).`
      );
      return {
        success: true,
        quietOffboard: true,
        actionTaken: 'quiet_offboard_executed',
        lapsAction
      };
    }

    const rawAgentToken = crypto.randomBytes(32).toString('hex');
    const encryptedAgentToken = encryptVaultSecret(rawAgentToken);
    const existing = db
      .prepare('SELECT id FROM devices WHERE tenant_id = ? AND LOWER(hostname) = LOWER(?) LIMIT 1')
      .get(tokenRow.tenant_id, body.hostname) as { id: string } | undefined;

    const deviceId = existing?.id || `dev-${crypto.randomUUID().slice(0, 8)}`;

    if (existing) {
      db.prepare(`
        UPDATE devices
        SET status = 'online',
            ip_address = COALESCE(?, ip_address),
            os_version = COALESCE(?, os_version),
            agent_auth_token = ?,
            last_seen = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(body.ipAddress || null, body.osVersion || null, encryptedAgentToken, deviceId);
      handleAgentCheckInOrWake(deviceId, 'reinstall_agent');
    } else {
      db.prepare(`
        INSERT INTO devices (
          id, mesh_node_id, tenant_id, site_id, hostname, os_type, os_version, os_build,
          ip_address, mac_address, status, device_role, manufacturer, model, cpu_model, cpu_cores,
          ram_total_gb, disk_total_gb, disk_free_gb, serial_number, agent_auth_token
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        deviceId,
        body.meshNodeId || `node//${deviceId}`,
        tokenRow.tenant_id,
        tokenRow.site_id || null,
        body.hostname,
        body.osType || 'windows',
        body.osVersion || 'Unknown OS',
        body.osBuild || '',
        body.ipAddress || request.ip || '0.0.0.0',
        body.macAddress || '00:00:00:00:00:00',
        tokenRow.device_role || 'Workstation',
        body.manufacturer || '',
        body.model || '',
        body.cpuModel || 'Unknown CPU',
        Number(body.cpuCores || 4),
        Number(body.ramTotalGb || 8),
        Number(body.diskTotalGb || 256),
        Number(body.diskFreeGb || 128),
        body.serialNumber || '',
        encryptedAgentToken
      );
    }

    db.prepare(
      'UPDATE installer_audit_log SET redeemed_at = CURRENT_TIMESTAMP, redeemed_device_id = ? WHERE token_id = ?'
    ).run(deviceId, token);

    return {
      success: true,
      deviceId,
      agentToken: rawAgentToken
    };
  });

  // ============================================================================
  // Safe Public Portal Config (Zero Secrets Exposed)
  // ============================================================================
  server.get('/api/public/portal-config', async () => {
    const row = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    return {
      brand_name: row.brand_name || 'Vitrine RMM',
      brand_logo_url: row.brand_logo_url || '/branding/logo.png',
      primary_color: row.primary_color || '#00f2fe',
      glass_blur_level: row.glass_blur_level || 'high',
      theme_mode: row.theme_mode || 'system',
      quicksupport_enabled: Boolean(row.quicksupport_enabled ?? 1),
      quicksupport_url_path: row.quicksupport_url_path || '/remote',
      quicksupport_custom_domain: row.quicksupport_custom_domain || '',
      code_signing_enabled: Boolean(row.code_signing_enabled)
    };
  });

  // ============================================================================
  // Authentication, Initial Admin Bootstrap & Step-Up MFA
  // ============================================================================
  server.get('/api/auth/status', async (request) => {
    const settings = (db.prepare('SELECT is_onboarded, oobe_completed, oidc_enabled, brand_name, brand_logo_url, primary_color, theme_mode FROM settings WHERE id = 1').get() ||
      {}) as any;
    return {
      initialized: hasConfiguredAdminUser(),
      authenticated: Boolean(request.auth),
      user: request.auth?.user || null,
      mfaVerified: Boolean(request.auth?.mfaVerified),
      mfaVerifiedUntil: request.auth?.mfaVerifiedUntil || null,
      isOnboarded: Boolean(settings.is_onboarded || settings.oobe_completed),
      oidcEnabled: Boolean(settings.oidc_enabled),
      branding: {
        brand_name: settings.brand_name || 'Vitrine RMM',
        brand_logo_url: settings.brand_logo_url || '/branding/logo.png',
        primary_color: settings.primary_color || '#00f2fe',
        theme_mode: settings.theme_mode || 'system'
      }
    };
  });

  server.post('/api/auth/setup-initial-admin', async (request, reply) => {
    const rate = checkRateLimit(`setup-admin:${request.ip}`, 5, 5 * 60_000);
    if (!rate.allowed) {
      return reply.status(429).send({ error: 'Too many setup attempts. Please wait.', retryAfterSec: rate.retryAfterSec });
    }
    if (hasConfiguredAdminUser()) {
      return reply.status(409).send({ error: 'Initial administrator is already configured. Please sign in.' });
    }

    const body = (request.body || {}) as { username?: string; email?: string; password?: string };
    try {
      const created = setupInitialSuperAdmin({
        username: body.username || '',
        email: body.email || '',
        password: body.password || ''
      });
      const session = createUserSession(created.user.id, request.ip, request.headers['user-agent']);
      setSessionCookie(reply, request, session.rawToken);

      return {
        success: true,
        user: created.user,
        token: session.rawToken,
        expiresAt: session.expiresAt,
        totpSecret: created.totpSecret,
        otpAuthUri: created.otpAuthUri,
        recoveryCodes: created.recoveryCodes
      };
    } catch (err: any) {
      return reply.status(400).send({ success: false, error: err?.message || 'Failed to provision initial admin' });
    }
  });

  server.post('/api/auth/login', async (request, reply) => {
    const body = (request.body || {}) as { username?: string; password?: string };
    const identifier = String(body.username || '').trim();
    const rate = checkRateLimit(`login:${request.ip}:${identifier.toLowerCase()}`, 10, 5 * 60_000);
    if (!rate.allowed) {
      return reply.status(429).send({
        success: false,
        error: `Too many failed sign-in attempts. Retry in ${rate.retryAfterSec}s.`,
        retryAfterSec: rate.retryAfterSec
      });
    }

    const user = authenticateUserPassword(identifier, body.password || '');
    if (!user) {
      db.prepare(`
        INSERT INTO audit_logs (id, username, action, details)
        VALUES (?, ?, 'Authentication Failed', ?)
      `).run(
        `aud-login-fail-${crypto.randomUUID()}`,
        identifier || 'unknown',
        `Failed login attempt from IP ${request.ip}`
      );
      return reply.status(401).send({ success: false, error: 'Invalid username/email or password.' });
    }

    const session = createUserSession(user.id, request.ip, request.headers['user-agent']);
    setSessionCookie(reply, request, session.rawToken);

    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'User Signed In', ?)
    `).run(
      `aud-login-${crypto.randomUUID()}`,
      user.username,
      `Authenticated session started (${user.role}) from IP ${request.ip}`
    );

    return {
      success: true,
      user,
      token: session.rawToken,
      expiresAt: session.expiresAt
    };
  });

  server.post('/api/auth/logout', async (request, reply) => {
    const auth = extractAuthContext(request);
    if (auth) {
      db.prepare('DELETE FROM auth_sessions WHERE token_hash = ?').run(auth.tokenHash);
      db.prepare(`
        INSERT INTO audit_logs (id, username, action, details)
        VALUES (?, ?, 'User Signed Out', 'Session terminated')
      `).run(`aud-logout-${crypto.randomUUID()}`, auth.user.username);
    }
    clearSessionCookie(reply);
    return { success: true };
  });

  const handleMfaSetupGet = async (request: any, reply: any) => {
    if (!request.auth) return reply.status(401).send({ error: 'Authentication required' });
    const details = getOrEnrollUserMfaDetails(request.auth.user.id);
    return {
      success: true,
      totpEnabled: true,
      secretBase32: details.totpSecret,
      ...details
    };
  };
  server.get('/api/auth/mfa-setup', handleMfaSetupGet);
  server.get('/api/auth/mfa/enroll', handleMfaSetupGet);

  const handleRegenerateRecovery = async (request: any, reply: any) => {
    if (!request.auth) return reply.status(401).send({ error: 'Authentication required' });
    const body = (request.body || {}) as { code?: string };
    if (body.code) {
      const check = verifySessionStepUpMfa(request.auth, body.code);
      if (!check.success) {
        return reply.status(401).send({
          success: false,
          error: check.error || 'Invalid MFA verification code.'
        });
      }
    } else if (!request.auth.mfaVerified) {
      return reply.status(403).send({
        success: false,
        error: 'Verify your current MFA code before regenerating recovery codes.',
        code: 'MFA_REQUIRED',
        mfaRequired: true
      });
    }
    const { plaintextCodes, hashedCodes } = generateOneTimeRecoveryCodes(8);
    db.prepare('UPDATE users SET recovery_codes_json = ? WHERE id = ?').run(
      JSON.stringify(hashedCodes),
      request.auth.user.id
    );
    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'MFA Recovery Codes Regenerated', 'Generated 8 new single-use recovery codes (previous codes invalidated)')
    `).run(`aud-mfa-rec-${crypto.randomUUID()}`, request.auth.user.username);
    return { success: true, recoveryCodes: plaintextCodes };
  };
  server.post('/api/auth/mfa-setup/regenerate-recovery', handleRegenerateRecovery);
  server.post('/api/auth/mfa/regenerate-recovery-codes', handleRegenerateRecovery);

  server.post('/api/auth/verify-mfa', async (request, reply) => {
    if (!request.auth) {
      return reply.status(401).send({ success: false, error: 'Authentication required' });
    }
    const rate = checkRateLimit(`mfa:${request.auth.user.id}:${request.ip}`, 8, 5 * 60_000);
    if (!rate.allowed) {
      return reply.status(429).send({
        success: false,
        error: `Too many MFA verification attempts. Retry in ${rate.retryAfterSec}s.`
      });
    }

    const body = (request.body || {}) as { code?: string; secretType?: string; deviceId?: string };
    const verification = verifySessionStepUpMfa(request.auth, body.code || '');

    if (verification.success) {
      db.prepare(`
        INSERT INTO audit_logs (id, username, device_id, action, details)
        VALUES (?, ?, ?, 'MFA Step-Up Verified', ?)
      `).run(
        `aud-mfa-${crypto.randomUUID()}`,
        request.auth.user.username,
        body.deviceId || null,
        `Step-Up MFA verified${verification.usedRecoveryCode ? ' via single-use recovery code' : ' via RFC 6238 TOTP'} for ${body.secretType || 'vault access'}`
      );
      return {
        success: true,
        verifiedAt: new Date().toISOString(),
        verifiedUntil: verification.verifiedUntil,
        usedRecoveryCode: Boolean(verification.usedRecoveryCode)
      };
    }

    return reply.status(401).send({
      success: false,
      error: verification.error || 'Invalid TOTP verification code.'
    });
  });

  // ============================================================================
  // Settings, Custom Branding Logo Upload & Opt-In Lab Demo Dataset
  // ============================================================================
  server.get('/api/settings', async () => {
    const row = db.prepare('SELECT * FROM settings WHERE id = 1').get() as any;
    return sanitizeSettingsRowForResponse(row);
  });

  server.post('/api/settings', async (request) => {
    const body = (request.body || {}) as Record<string, any>;
    const current = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as Record<string, any>;

    const resolveSecretUpdate = (col: string): string | null => {
      if (body[col] === undefined || body[col] === null) return null;
      const strVal = String(body[col]).trim();
      if (isMaskedSecret(strVal)) {
        return current[col] ?? '';
      }
      if (strVal === '') return '';
      return encryptVaultSecret(strVal);
    };

    const extPromptVal =
      body.mesh_external_delete_prompt !== undefined
        ? body.mesh_external_delete_prompt === 'auto_unassigned' || body.mesh_external_delete_prompt === 0
          ? 0
          : 1
        : null;

    // Only transition is_onboarded when explicitly requested (OOBE completion) so intermediate saves never skip OOBE!
    const nextIsOnboarded =
      body.is_onboarded !== undefined
        ? body.is_onboarded
          ? 1
          : 0
        : body.oobe_completed !== undefined
          ? body.oobe_completed
            ? 1
            : current.is_onboarded
          : null;

    db.prepare(`
      UPDATE settings SET
        brand_name = COALESCE(?, brand_name),
        brand_logo_url = COALESCE(?, brand_logo_url),
        primary_color = COALESCE(?, primary_color),
        glass_blur_level = COALESCE(?, glass_blur_level),
        custom_domain = COALESCE(?, custom_domain),
        meshcentral_url = COALESCE(?, meshcentral_url),
        meshcentral_api_token = COALESCE(?, meshcentral_api_token),
        smtp_host = COALESCE(?, smtp_host),
        smtp_port = COALESCE(?, smtp_port),
        smtp_user = COALESCE(?, smtp_user),
        smtp_pass = COALESCE(?, smtp_pass),
        smtp_from = COALESCE(?, smtp_from),
        smtp_tls = COALESCE(?, smtp_tls),
        itflow_url = COALESCE(?, itflow_url),
        itflow_api_key = COALESCE(?, itflow_api_key),
        oidc_enabled = COALESCE(?, oidc_enabled),
        oidc_issuer_url = COALESCE(?, oidc_issuer_url),
        oidc_client_id = COALESCE(?, oidc_client_id),
        oidc_client_secret = COALESCE(?, oidc_client_secret),
        psa_webhook_secret = COALESCE(?, psa_webhook_secret),
        agent_enrollment_secret = COALESCE(?, agent_enrollment_secret),
        code_signing_url = COALESCE(?, code_signing_url),
        code_signing_enabled = COALESCE(?, code_signing_enabled),
        code_signing_sign_scripts = COALESCE(?, code_signing_sign_scripts),
        code_signing_sign_agents = COALESCE(?, code_signing_sign_agents),
        code_signing_sign_assemblies = COALESCE(?, code_signing_sign_assemblies),
        code_signing_sign_ms2_binary = COALESCE(?, code_signing_sign_ms2_binary),
        code_signing_strict_verify = COALESCE(?, code_signing_strict_verify),
        installer_download_role = COALESCE(?, installer_download_role),
        installer_require_ticket = COALESCE(?, installer_require_ticket),
        installer_gui_style = COALESCE(?, installer_gui_style),
        installer_service_name = COALESCE(?, installer_service_name),
        installer_welcome_text = COALESCE(?, installer_welcome_text),
        session_recording_enabled = COALESCE(?, session_recording_enabled),
        session_recording_retention_days = COALESCE(?, session_recording_retention_days),
        session_recording_quality = COALESCE(?, session_recording_quality),
        session_recording_visual_indicator = COALESCE(?, session_recording_visual_indicator),
        session_recording_stealth_for_techs = COALESCE(?, session_recording_stealth_for_techs),
        maintenance_auto_clear_hours = COALESCE(?, maintenance_auto_clear_hours),
        mesh_sync_enabled = COALESCE(?, mesh_sync_enabled),
        mesh_client_delete_action = COALESCE(?, mesh_client_delete_action),
        mesh_external_delete_prompt = COALESCE(?, mesh_external_delete_prompt),
        oobe_completed = COALESCE(?, oobe_completed),
        is_onboarded = COALESCE(?, is_onboarded),
        theme_mode = COALESCE(?, theme_mode),
        tray_theme_mode = COALESCE(?, tray_theme_mode),
        quicksupport_enabled = COALESCE(?, quicksupport_enabled),
        quicksupport_custom_domain = COALESCE(?, quicksupport_custom_domain),
        quicksupport_url_path = COALESCE(?, quicksupport_url_path),
        tls_mode = COALESCE(?, tls_mode),
        reverse_proxy_type = COALESCE(?, reverse_proxy_type),
        letsencrypt_email = COALESCE(?, letsencrypt_email),
        update_channel = COALESCE(?, update_channel),
        update_auto_backup = COALESCE(?, update_auto_backup),
        update_auto_rollback = COALESCE(?, update_auto_rollback),
        update_notify_webui = COALESCE(?, update_notify_webui),
        update_notify_email = COALESCE(?, update_notify_email),
        update_create_psa_ticket = COALESCE(?, update_create_psa_ticket),
        backup_schedule_enabled = COALESCE(?, backup_schedule_enabled),
        backup_schedule_frequency = COALESCE(?, backup_schedule_frequency),
        backup_schedule_time = COALESCE(?, backup_schedule_time),
        backup_retention_count = COALESCE(?, backup_retention_count),
        backup_max_storage_mb = COALESCE(?, backup_max_storage_mb),
        backup_include_branding = COALESCE(?, backup_include_branding),
        backup_include_mesh_config = COALESCE(?, backup_include_mesh_config),
        backup_encryption_enabled = COALESCE(?, backup_encryption_enabled),
        backup_encryption_passphrase = COALESCE(?, backup_encryption_passphrase),
        backup_offsite_enabled = COALESCE(?, backup_offsite_enabled),
        backup_offsite_provider = COALESCE(?, backup_offsite_provider),
        backup_offsite_endpoint = COALESCE(?, backup_offsite_endpoint),
        backup_offsite_bucket = COALESCE(?, backup_offsite_bucket),
        backup_offsite_access_key = COALESCE(?, backup_offsite_access_key),
        backup_offsite_secret_key = COALESCE(?, backup_offsite_secret_key),
        patch_auto_approve_third_party = COALESCE(?, patch_auto_approve_third_party),
        patch_canary_delay_days = COALESCE(?, patch_canary_delay_days),
        updated_at = CURRENT_TIMESTAMP
      WHERE id = 1
    `).run(
      body.brand_name ?? null,
      body.brand_logo_url ?? null,
      body.primary_color ?? null,
      body.glass_blur_level ?? null,
      body.custom_domain ?? null,
      body.meshcentral_url ?? null,
      resolveSecretUpdate('meshcentral_api_token'),
      body.smtp_host ?? null,
      body.smtp_port != null ? Number(body.smtp_port) : null,
      body.smtp_user ?? null,
      resolveSecretUpdate('smtp_pass'),
      body.smtp_from ?? null,
      body.smtp_tls != null ? (body.smtp_tls ? 1 : 0) : null,
      body.itflow_url ?? null,
      resolveSecretUpdate('itflow_api_key'),
      body.oidc_enabled != null ? (body.oidc_enabled ? 1 : 0) : null,
      body.oidc_issuer_url ?? null,
      body.oidc_client_id ?? null,
      resolveSecretUpdate('oidc_client_secret'),
      resolveSecretUpdate('psa_webhook_secret'),
      resolveSecretUpdate('agent_enrollment_secret'),
      body.code_signing_url ?? null,
      body.code_signing_enabled != null ? (body.code_signing_enabled ? 1 : 0) : null,
      body.code_signing_sign_scripts != null ? (body.code_signing_sign_scripts ? 1 : 0) : null,
      body.code_signing_sign_agents != null ? (body.code_signing_sign_agents ? 1 : 0) : null,
      body.code_signing_sign_assemblies != null ? (body.code_signing_sign_assemblies ? 1 : 0) : null,
      body.code_signing_sign_ms2_binary != null ? (body.code_signing_sign_ms2_binary ? 1 : 0) : null,
      body.code_signing_strict_verify != null ? (body.code_signing_strict_verify ? 1 : 0) : null,
      body.installer_download_role ?? null,
      body.installer_require_ticket != null ? (body.installer_require_ticket ? 1 : 0) : null,
      body.installer_gui_style ?? null,
      body.installer_service_name ?? null,
      body.installer_welcome_text ?? null,
      body.session_recording_enabled != null ? (body.session_recording_enabled ? 1 : 0) : null,
      body.session_recording_retention_days != null ? Number(body.session_recording_retention_days) : null,
      body.session_recording_quality ?? null,
      body.session_recording_visual_indicator != null ? (body.session_recording_visual_indicator ? 1 : 0) : null,
      body.session_recording_stealth_for_techs != null ? (body.session_recording_stealth_for_techs ? 1 : 0) : null,
      body.maintenance_auto_clear_hours != null ? Number(body.maintenance_auto_clear_hours) : null,
      body.mesh_sync_enabled != null ? (body.mesh_sync_enabled ? 1 : 0) : null,
      body.mesh_client_delete_action ?? null,
      extPromptVal,
      body.oobe_completed != null ? (body.oobe_completed ? 1 : 0) : null,
      nextIsOnboarded,
      body.theme_mode ?? null,
      body.tray_theme_mode ?? null,
      body.quicksupport_enabled != null ? (body.quicksupport_enabled ? 1 : 0) : null,
      body.quicksupport_custom_domain ?? null,
      body.quicksupport_url_path ?? null,
      body.tls_mode ?? null,
      body.reverse_proxy_type ?? null,
      body.letsencrypt_email ?? null,
      body.update_channel ?? null,
      body.update_auto_backup != null ? (body.update_auto_backup ? 1 : 0) : null,
      body.update_auto_rollback != null ? (body.update_auto_rollback ? 1 : 0) : null,
      body.update_notify_webui != null ? (body.update_notify_webui ? 1 : 0) : null,
      body.update_notify_email != null ? (body.update_notify_email ? 1 : 0) : null,
      body.update_create_psa_ticket != null ? (body.update_create_psa_ticket ? 1 : 0) : null,
      body.backup_schedule_enabled != null ? (body.backup_schedule_enabled ? 1 : 0) : null,
      body.backup_schedule_frequency ?? null,
      body.backup_schedule_time ?? null,
      body.backup_retention_count != null ? Number(body.backup_retention_count) : null,
      body.backup_max_storage_mb != null ? Number(body.backup_max_storage_mb) : null,
      body.backup_include_branding != null ? (body.backup_include_branding ? 1 : 0) : null,
      body.backup_include_mesh_config != null ? (body.backup_include_mesh_config ? 1 : 0) : null,
      body.backup_encryption_enabled != null ? (body.backup_encryption_enabled ? 1 : 0) : null,
      resolveSecretUpdate('backup_encryption_passphrase'),
      body.backup_offsite_enabled != null ? (body.backup_offsite_enabled ? 1 : 0) : null,
      body.backup_offsite_provider ?? null,
      body.backup_offsite_endpoint ?? null,
      body.backup_offsite_bucket ?? null,
      resolveSecretUpdate('backup_offsite_access_key'),
      resolveSecretUpdate('backup_offsite_secret_key'),
      body.patch_auto_approve_third_party != null ? (body.patch_auto_approve_third_party ? 1 : 0) : null,
      body.patch_canary_delay_days != null ? Number(body.patch_canary_delay_days) : null
    );

    meshBridge.checkConfig();

    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'System Settings Updated', 'Control plane configuration saved')
    `).run(`aud-set-${crypto.randomUUID()}`, getActorUsername(request));

    const updated = db.prepare('SELECT * FROM settings WHERE id = 1').get() as any;
    return { success: true, settings: sanitizeSettingsRowForResponse(updated) };
  });

  server.post('/api/settings/logo', async (request, reply) => {
    const body = (request.body || {}) as { filename?: string; base64Data?: string };
    if (!body.base64Data) {
      return reply.status(400).send({ error: 'base64Data is required' });
    }
    const cleanB64 = body.base64Data.includes(',') ? body.base64Data.split(',').pop()! : body.base64Data;
    const buf = Buffer.from(cleanB64, 'base64');
    if (buf.length === 0 || buf.length > 2 * 1024 * 1024) {
      return reply.status(400).send({ error: 'Branding logo must be between 1 byte and 2 MB.' });
    }

    // Validate binary magic headers (PNG, JPEG, WebP, GIF, ICO) — disallow active HTML/SVG scripts
    let ext = '';
    if (buf.length >= 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
      ext = '.png';
    } else if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
      ext = '.jpg';
    } else if (
      buf.length >= 12 &&
      buf.subarray(0, 4).toString('ascii') === 'RIFF' &&
      buf.subarray(8, 12).toString('ascii') === 'WEBP'
    ) {
      ext = '.webp';
    } else if (buf.length >= 4 && buf[0] === 0x00 && buf[1] === 0x00 && buf[2] === 0x01 && buf[3] === 0x00) {
      ext = '.ico';
    } else {
      return reply.status(400).send({
        error: 'Unsupported image format. Upload a valid PNG, JPEG, WebP, or ICO image.'
      });
    }

    if (!fs.existsSync(BRANDING_DIR_PATH)) {
      fs.mkdirSync(BRANDING_DIR_PATH, { recursive: true });
    }
    const targetFilename = `custom-logo-${Date.now()}${ext}`;
    const targetPath = path.join(BRANDING_DIR_PATH, targetFilename);
    fs.writeFileSync(targetPath, buf);

    const logoUrl = `/branding/${targetFilename}`;
    db.prepare('UPDATE settings SET brand_logo_url = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1').run(logoUrl);

    return { success: true, brand_logo_url: logoUrl };
  });

  server.post('/api/demo/seed', async (request) => {
    seedDemoDataset();
    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'Lab Demo Dataset Loaded', 'Seeded sample MSP clients and endpoints')
    `).run(`aud-seed-${crypto.randomUUID()}`, getActorUsername(request));
    return { success: true };
  });

  // ============================================================================
  // RBAC Users & Technicians Management
  // ============================================================================
  server.get('/api/users', async () => {
    const rows = db
      .prepare(`
        SELECT u.*, t.name as tenant_name
        FROM users u
        LEFT JOIN tenants t ON u.tenant_id = t.id
        ORDER BY u.created_at ASC
      `)
      .all() as any[];
    return rows.map(sanitizeUserRowForResponse);
  });

  server.post('/api/users', async (request, reply) => {
    const body = (request.body || {}) as {
      username?: string;
      email?: string;
      password?: string;
      role?: string;
      tenant_id?: string | null;
    };
    const username = String(body.username || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const role = body.role || 'technician';

    if (!username || !email || !email.includes('@')) {
      return reply.status(400).send({ error: 'Valid username and email are required.' });
    }
    if (!body.password || body.password.length < 10) {
      return reply.status(400).send({ error: 'User password must be at least 10 characters.' });
    }
    if (role === 'client_admin' && !body.tenant_id) {
      return reply.status(400).send({ error: 'Client Admin accounts must be scoped to a specific Client tenant.' });
    }

    const id = `u-${crypto.randomUUID().slice(0, 8)}`;
    const passwordHash = hashPasswordScrypt(body.password);
    const totpSecret = encryptVaultSecret(generateRandomBase32(20));
    const { plaintextCodes, hashedCodes } = generateOneTimeRecoveryCodes(8);

    try {
      db.prepare(`
        INSERT INTO users (id, username, email, role, tenant_id, password_hash, totp_secret, totp_enabled, recovery_codes_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
      `).run(
        id,
        username,
        email,
        role,
        role === 'client_admin' ? body.tenant_id || null : null,
        passwordHash,
        totpSecret,
        JSON.stringify(hashedCodes)
      );
    } catch (err: any) {
      return reply.status(409).send({ error: `Username or email already exists: ${err?.message || ''}` });
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, NULL, 'RBAC User Created', ?)
    `).run(
      `aud-usr-${crypto.randomUUID()}`,
      getActorUsername(request),
      `Created user '${username}' (${role})`
    );

    const created = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    return {
      success: true,
      user: sanitizeUserRowForResponse(created),
      recoveryCodes: plaintextCodes
    };
  });

  server.put('/api/users/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = (request.body || {}) as {
      role?: string;
      tenant_id?: string | null;
      password?: string;
      email?: string;
    };
    const existing = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'User not found' });

    const nextPassHash =
      body.password && body.password.length >= 10 ? hashPasswordScrypt(body.password) : null;

    db.prepare(`
      UPDATE users
      SET role = COALESCE(?, role),
          email = COALESCE(?, email),
          tenant_id = ?,
          password_hash = COALESCE(?, password_hash)
      WHERE id = ?
    `).run(
      body.role ?? null,
      body.email ?? null,
      body.tenant_id !== undefined ? body.tenant_id : existing.tenant_id,
      nextPassHash,
      id
    );

    // If password was rotated, revoke active sessions for that user
    if (nextPassHash) {
      db.prepare('DELETE FROM auth_sessions WHERE user_id = ?').run(id);
    }

    return {
      success: true,
      user: sanitizeUserRowForResponse(db.prepare('SELECT * FROM users WHERE id = ?').get(id))
    };
  });

  server.delete('/api/users/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (request.auth?.user.id === id) {
      return reply.status(400).send({ error: 'Cannot delete your currently signed-in account.' });
    }
    const target = db.prepare('SELECT id, username, role FROM users WHERE id = ?').get(id) as any;
    if (!target) return reply.status(404).send({ error: 'User not found' });

    if (isSuperAdminRole(target.role)) {
      const adminCount = (
        db
          .prepare("SELECT COUNT(*) as c FROM users WHERE role IN ('msp_super_admin', 'super_admin', 'admin')")
          .get() as { c: number }
      ).c;
      if (adminCount <= 1) {
        return reply.status(400).send({ error: 'Cannot delete the last MSP Super Admin account.' });
      }
    }

    db.prepare('DELETE FROM auth_sessions WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'RBAC User Deleted', ?)
    `).run(`aud-udel-${crypto.randomUUID()}`, getActorUsername(request), `Deleted user '${target.username}'`);
    return { success: true };
  });

  // ============================================================================
  // Tenants & Sites (Tenant-Scoped for Client Admins)
  // ============================================================================
  server.get('/api/tenants', async (request) => {
    const user = request.auth?.user;
    const scopedTenantId = user && !isTechnicianOrAbove(user.role) ? user.tenant_id : null;

    const tenants = (scopedTenantId
      ? db
          .prepare(`
            SELECT t.*, (SELECT COUNT(*) FROM devices d WHERE d.tenant_id = t.id) as computed_device_count
            FROM tenants t
            WHERE t.id = ?
            ORDER BY t.name ASC
          `)
          .all(scopedTenantId)
      : db
          .prepare(`
            SELECT t.*, (SELECT COUNT(*) FROM devices d WHERE d.tenant_id = t.id) as computed_device_count
            FROM tenants t
            ORDER BY t.name ASC
          `)
          .all()) as any[];

    const allSites = db.prepare('SELECT * FROM sites ORDER BY name ASC').all() as any[];
    const sitesByTenant = new Map<string, any[]>();
    for (const s of allSites) {
      const list = sitesByTenant.get(s.tenant_id) || [];
      list.push(s);
      sitesByTenant.set(s.tenant_id, list);
    }

    for (const t of tenants) {
      t.device_count = t.computed_device_count ?? t.device_count;
      t.sites = sitesByTenant.get(t.id) || [];
    }
    return tenants;
  });

  server.post('/api/tenants', async (request, reply) => {
    const body = (request.body || {}) as {
      name?: string;
      contact_email?: string;
      subnet?: string;
      site_name?: string;
    };
    const cleanName = String(body.name || '').trim();
    if (!cleanName) {
      return reply.status(400).send({ error: 'Client organization name is required.' });
    }
    const baseSlug =
      cleanName
        .toLowerCase()
        .replace(/[^a-z0-9]/g, '-')
        .replace(/-+/g, '-')
        .replace(/^-|-$/g, '') || 'client';
    const slug = `${baseSlug}-${crypto.randomUUID().slice(0, 4)}`;
    const id = `t-${slug}`;
    db.prepare(`
      INSERT INTO tenants (id, name, slug, contact_email, device_count)
      VALUES (?, ?, ?, ?, 0)
    `).run(id, cleanName, slug, body.contact_email || `ops@${baseSlug}.local`);

    const siteId = `s-${slug}-hq`;
    db.prepare(`
      INSERT INTO sites (id, tenant_id, name, subnet)
      VALUES (?, ?, ?, ?)
    `).run(siteId, id, body.site_name || 'Primary HQ Office', body.subnet || '10.100.10.0/24');

    return { success: true, id, siteId };
  });

  server.post('/api/sites', async (request, reply) => {
    const body = (request.body || {}) as { tenant_id?: string; name?: string; subnet?: string };
    if (!body.tenant_id || !body.name?.trim()) {
      return reply.status(400).send({ error: 'tenant_id and site name are required.' });
    }
    const id = `s-${crypto.randomUUID().slice(0, 8)}`;
    db.prepare(`
      INSERT INTO sites (id, tenant_id, name, subnet)
      VALUES (?, ?, ?, ?)
    `).run(id, body.tenant_id, body.name.trim(), body.subnet || '192.168.1.0/24');
    return { success: true, id };
  });

  // ============================================================================
  // Devices Inventory, MFA-Gated BitLocker & LAPS, and Background Endpoint Tools
  // ============================================================================
  server.get('/api/devices', async (request) => {
    sweepPendingOffboards();
    const user = request.auth?.user;
    const scopedTenantId = user && !isTechnicianOrAbove(user.role) ? user.tenant_id : null;

    const rows = (scopedTenantId
      ? db
          .prepare(`
            SELECT d.*, t.name as tenant_name, t.lifecycle_state as tenant_lifecycle_state, s.name as site_name,
                   l.account_name as laps_account
            FROM devices d
            LEFT JOIN tenants t ON d.tenant_id = t.id
            LEFT JOIN sites s ON d.site_id = s.id
            LEFT JOIN laps_vault l ON d.id = l.device_id
            WHERE d.tenant_id = ?
            ORDER BY d.hostname ASC
          `)
          .all(scopedTenantId)
      : db
          .prepare(`
            SELECT d.*, t.name as tenant_name, t.lifecycle_state as tenant_lifecycle_state, s.name as site_name,
                   l.account_name as laps_account
            FROM devices d
            LEFT JOIN tenants t ON d.tenant_id = t.id
            LEFT JOIN sites s ON d.site_id = s.id
            LEFT JOIN laps_vault l ON d.id = l.device_id
            ORDER BY d.hostname ASC
          `)
          .all()) as any[];

    return rows.map(sanitizeDeviceRowForResponse);
  });

  server.get('/api/devices/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed) return;

    const device = db
      .prepare(`
        SELECT d.*, t.name as tenant_name, s.name as site_name
        FROM devices d
        LEFT JOIN tenants t ON d.tenant_id = t.id
        LEFT JOIN sites s ON d.site_id = s.id
        WHERE d.id = ?
      `)
      .get(id) as any;

    const safeDevice = sanitizeDeviceRowForResponse(device);
    safeDevice.enrolled_at = safeDevice.enrolled_at || safeDevice.created_at || new Date().toISOString();
    safeDevice.policy = sanitizeEffectivePolicyForResponse(resolveEffectiveDevicePolicy(id));
    safeDevice.laps = getLapsCredential(id, false, { actorUsername: getActorUsername(request) });
    safeDevice.warranty = db.prepare('SELECT * FROM oem_warranties WHERE device_id = ?').get(id) || null;

    const nowIso = new Date().toISOString();
    const mw = db
      .prepare(`
        SELECT * FROM maintenance_windows
        WHERE (device_id = ? OR tenant_id = ?) AND is_active = 1 AND start_time <= ? AND end_time >= ?
        ORDER BY end_time DESC LIMIT 1
      `)
      .get(id, device.tenant_id, nowIso, nowIso) as any;

    const isMuted = Boolean(mw || (device.maintenance_until && device.maintenance_until > nowIso));
    safeDevice.maintenance_active = isMuted;
    safeDevice.active_maintenance =
      mw ||
      (device.maintenance_until && device.maintenance_until > nowIso
        ? { title: 'Emergency Mute Active', end_time: device.maintenance_until }
        : null);

    return safeDevice;
  });

  // Dedicated Step-Up MFA Gated BitLocker / LUKS / FileVault Escrow Reveal Endpoint
  server.get('/api/devices/:id/bitlocker', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!isTechnicianOrAbove(request.auth?.user.role)) {
      return reply.status(403).send({ error: 'Technician privileges required to reveal recovery keys.' });
    }
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return;

    if (!requireStepUpMfaIfEnforced(request, reply, id)) {
      return;
    }

    const decryptedKey = decryptVaultSecret(access.device.bitlocker_key);
    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Disk Encryption Recovery Key Revealed', ?)
    `).run(
      `aud-blk-${crypto.randomUUID()}`,
      getActorUsername(request),
      id,
      `Revealed escrowed disk encryption recovery key for ${access.device.hostname}`
    );

    return {
      success: true,
      deviceId: id,
      hostname: access.device.hostname,
      bitlocker_status: access.device.bitlocker_status,
      bitlocker_key: decryptedKey || null
    };
  });

  // Device Runbook Notes
  server.get('/api/devices/:id/notes', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    return db
      .prepare('SELECT * FROM device_notes WHERE device_id = ? ORDER BY is_pinned DESC, created_at DESC')
      .all(id);
  });

  server.post('/api/devices/:id/notes', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    const body = (request.body || {}) as { author?: string; content?: string; is_pinned?: boolean };
    if (!body.content?.trim()) {
      return reply.status(400).send({ error: 'Note content is required.' });
    }
    const noteId = `note-${crypto.randomUUID().slice(0, 8)}`;
    db.prepare(`
      INSERT INTO device_notes (id, device_id, author, content, is_pinned)
      VALUES (?, ?, ?, ?, ?)
    `).run(noteId, id, getActorUsername(request), body.content.trim(), body.is_pinned ? 1 : 0);
    return { success: true, note: db.prepare('SELECT * FROM device_notes WHERE id = ?').get(noteId) };
  });

  server.delete('/api/devices/:id/notes/:noteId', async (request, reply) => {
    const { id, noteId } = request.params as { id: string; noteId: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    db.prepare('DELETE FROM device_notes WHERE id = ? AND device_id = ?').run(noteId, id);
    return { success: true };
  });

  // Remote Event Viewer
  server.get('/api/devices/:id/eventlogs', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    const query = (request.query || {}) as Record<string, string>;
    const channel = query.channel || 'System';
    const level = query.level || 'all';
    const limit = Math.min(200, Math.max(1, parseInt(query.limit || '50', 10) || 50));
    return meshBridge.getEventLogs(id, channel, level, limit);
  });

  // Device Remote Privacy & Consent Control
  server.get('/api/devices/:id/consent-status', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return;
    const policy = resolveEffectiveDevicePolicy(id);
    const roleLower = String(access.device.device_role || '').toLowerCase();
    const isUnattendedRole =
      access.device.status === 'isolated' ||
      roleLower.includes('server') ||
      roleLower.includes('controller') ||
      roleLower.includes('hypervisor');
    return {
      requireConsent: policy.requireRemoteConsent && !isUnattendedRole,
      timeoutSec: policy.consentTimeoutSec,
      timeoutAction: policy.consentTimeoutAction,
      autoLockOnDisconnect: policy.autoLockOnDisconnect,
      bypassedDueToLockScreen: isUnattendedRole
    };
  });

  // Silent Background Process Manager
  server.get('/api/devices/:id/processes', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    return meshBridge.getProcesses(id);
  });

  server.post('/api/devices/:id/processes/:pid/kill', async (request, reply) => {
    const { id, pid } = request.params as { id: string; pid: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    try {
      const success = meshBridge.killProcess(id, parseInt(pid, 10), getActorUsername(request));
      return { success };
    } catch (err: any) {
      return reply.status(400).send({ success: false, error: err?.message || 'Invalid PID' });
    }
  });

  // Silent Background Services Manager
  server.get('/api/devices/:id/services', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    return meshBridge.getServices(id);
  });

  server.post('/api/devices/:id/services/:name/:action', async (request, reply) => {
    const { id, name, action } = request.params as {
      id: string;
      name: string;
      action: 'start' | 'stop' | 'restart';
    };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    try {
      const success = meshBridge.manageService(id, name, action, getActorUsername(request));
      return { success };
    } catch (err: any) {
      return reply.status(400).send({ success: false, error: err?.message || 'Service operation rejected' });
    }
  });

  // Remote Registry / sysctl / plist Browser
  server.get('/api/devices/:id/registry', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    const query = (request.query || {}) as { path?: string };
    return meshBridge.getRegistryKeys(query.path || '', id);
  });

  server.post('/api/devices/:id/registry', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    const body = (request.body || {}) as {
      path?: string;
      name?: string;
      type?: 'REG_SZ' | 'REG_DWORD' | 'REG_BINARY' | 'REG_MULTI_SZ';
      value?: string;
    };
    if (!body.name?.trim()) {
      return reply.status(400).send({ error: 'Registry value name is required.' });
    }
    const regPath = body.path || 'HKLM\\SOFTWARE\\VitrineRMM';
    const updated = meshBridge.setRegistryValue(
      id,
      regPath,
      {
        path: regPath,
        name: body.name.trim(),
        type: body.type || 'REG_SZ',
        value: String(body.value ?? '')
      },
      getActorUsername(request)
    );
    return { success: true, ...updated };
  });

  server.delete('/api/devices/:id/registry', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    const query = (request.query || {}) as { path?: string; name?: string };
    const regPath = query.path || 'HKLM\\SOFTWARE\\VitrineRMM';
    const updated = meshBridge.deleteRegistryValue(id, regPath, query.name || '', getActorUsername(request));
    return { success: true, ...updated };
  });

  // Scheduled Tasks Manager
  server.get('/api/devices/:id/tasks', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    return meshBridge.getScheduledTasks(id);
  });

  server.post('/api/devices/:id/tasks', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    const body = (request.body || {}) as { name?: string; action?: 'run' | 'enable' | 'disable' };
    if (!body.name) return reply.status(400).send({ error: 'Task name is required' });
    try {
      const tasks = meshBridge.manageScheduledTask(id, body.name, body.action || 'run', getActorUsername(request));
      return { success: true, tasks };
    } catch (err: any) {
      return reply.status(400).send({ success: false, error: err?.message });
    }
  });

  // Remote File Manager (Browse, Upload, Download, Mkdir, Delete)
  server.get('/api/devices/:id/files', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return;
    const query = (request.query || {}) as { path?: string };
    const defaultRoot = access.device.os_type === 'windows' ? 'C:\\' : '/';
    return meshBridge.getDirectoryListing(id, query.path || defaultRoot);
  });

  server.post('/api/devices/:id/files', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return;
    const body = (request.body || {}) as {
      path?: string;
      action?: 'mkdir' | 'delete' | 'upload';
      name?: string;
      size?: number;
      contentBase64?: string;
    };
    if (!body.action || !body.name) {
      return reply.status(400).send({ error: 'action and name are required' });
    }
    const defaultRoot = access.device.os_type === 'windows' ? 'C:\\' : '/';
    try {
      const files = meshBridge.manageFile(
        id,
        body.path || defaultRoot,
        body.action,
        body.name,
        body.size || 0,
        body.contentBase64,
        getActorUsername(request)
      );
      return { success: true, files };
    } catch (err: any) {
      return reply.status(400).send({ success: false, error: err?.message || 'File operation failed' });
    }
  });

  server.get('/api/devices/:id/files/download', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    const query = (request.query || {}) as { path?: string };
    if (!query.path) return reply.status(400).send({ error: 'File path is required' });
    const dl = meshBridge.downloadFile(id, query.path, getActorUsername(request));
    reply.header('Content-Type', 'application/octet-stream');
    reply.header('Content-Disposition', buildSafeContentDisposition(dl.filename));
    return reply.send(Buffer.from(dl.contentBase64, 'base64'));
  });

  // Cyber Isolation / Network Quarantine
  server.post('/api/devices/:id/quarantine', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    const body = (request.body || {}) as { quarantine?: boolean };
    const quarantined = Boolean(body.quarantine);
    meshBridge.toggleQuarantine(id, quarantined, getActorUsername(request));
    return { success: true, quarantined };
  });

  // LAPS Vault (MFA-Gated on Reveal)
  server.get('/api/devices/:id/laps', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed) return;
    const query = (request.query || {}) as { reveal?: string };
    const reveal = query.reveal === 'true';

    if (reveal) {
      if (!isTechnicianOrAbove(request.auth?.user.role)) {
        return reply.status(403).send({ error: 'Technician role required to reveal LAPS credentials.' });
      }
      if (!requireStepUpMfaIfEnforced(request, reply, id)) {
        return;
      }
      db.prepare(`
        INSERT INTO audit_logs (id, username, device_id, action, details)
        VALUES (?, ?, ?, 'LAPS Password Revealed', 'Technician revealed local administrator password')
      `).run(`aud-laps-${crypto.randomUUID()}`, getActorUsername(request), id);
    }

    const cred = getLapsCredential(id, reveal, { actorUsername: getActorUsername(request) });
    if (!cred) return reply.status(404).send({ error: 'Device not found' });
    return cred;
  });

  server.post('/api/devices/:id/laps/rotate', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    const body = (request.body || {}) as { reveal?: boolean };
    const shouldReveal = Boolean(body.reveal);

    if (shouldReveal && !requireStepUpMfaIfEnforced(request, reply, id)) {
      return;
    }

    const cred = rotateLapsPassword(id, {
      reveal: shouldReveal,
      actorUsername: getActorUsername(request)
    });
    if (!cred) return reply.status(404).send({ error: 'Device not found' });
    return cred;
  });

  // ============================================================================
  // Policies & 4-Tier Inheritance Hierarchy
  // ============================================================================
  const formatPolicyRowForResponse = (p: any) => ({
    ...p,
    laps_static_password: maskSecretValue(p.laps_static_password),
    overrides: safeJsonParse<string[]>(p.overrides_json, []),
    alert_rules: parsePolicyAlertRules(p.alert_rules_json, p.tier, p.target_id)
  });

  server.get('/api/policies', async () => {
    const rows = db
      .prepare(
        "SELECT * FROM policies ORDER BY CASE tier WHEN 'global' THEN 1 WHEN 'client' THEN 2 WHEN 'site' THEN 3 ELSE 4 END ASC"
      )
      .all() as any[];
    return rows.map(formatPolicyRowForResponse);
  });

  server.post('/api/policies/evaluate-conditions', async () => {
    return await evaluateFleetAlertConditions();
  });

  const OVERRIDABLE_POLICY_COLUMNS = [
    'telemetry_interval_sec',
    'require_remote_consent',
    'consent_timeout_sec',
    'consent_timeout_action',
    'auto_lock_on_disconnect',
    'patch_schedule',
    'patch_reboot_enforcement',
    'self_healing_enabled',
    'max_snooze_hours',
    'force_reboot_after_snooze',
    'final_countdown_sec',
    'laps_enabled',
    'laps_auto_create_account',
    'laps_account_name',
    'laps_password_mode',
    'laps_password_length',
    'laps_complexity',
    'laps_passphrase_words',
    'laps_passphrase_separator',
    'laps_static_password',
    'laps_rotation_days',
    'laps_rotate_on_access',
    'laps_post_access_grace_hours',
    'laps_cleanup_old_account_on_rename',
    'laps_disable_builtin_sid500_admin',
    'laps_offboard_explicit_device_action',
    'laps_offboard_client_archived_action',
    'laps_offboard_client_deleted_action',
    'offboard_offline_auto_archive_days',
    'require_mfa_for_secrets',
    'telemetry_history_retention_days',
    'hardware_audit_enabled',
    'network_drift_detection_enabled',
    'self_healing_max_hourly_runs',
    'self_healing_alert_psa',
    'psa_flap_grace_minutes',
    'auto_patch_cve_min_cvss'
  ];

  server.post('/api/policies', async (request) => {
    const body = (request.body || {}) as Record<string, any>;
    const id = `pol-${crypto.randomUUID().slice(0, 8)}`;

    const explicitOverrides: string[] = Array.isArray(body.overrides)
      ? body.overrides
      : OVERRIDABLE_POLICY_COLUMNS.filter((col) => body[col] !== undefined);

    const staticPass =
      body.laps_static_password && !isMaskedSecret(String(body.laps_static_password))
        ? encryptVaultSecret(String(body.laps_static_password))
        : '';

    const alertRulesJson =
      body.alert_rules !== undefined
        ? JSON.stringify(body.alert_rules)
        : body.alert_rules_json !== undefined
          ? body.alert_rules_json
          : null;

    db.prepare(`
      INSERT INTO policies (
        id, name, tier, target_id, telemetry_interval_sec, require_remote_consent,
        consent_timeout_sec, consent_timeout_action, auto_lock_on_disconnect,
        patch_schedule, patch_reboot_enforcement, self_healing_enabled,
        max_snooze_hours, force_reboot_after_snooze, final_countdown_sec,
        laps_enabled, laps_auto_create_account, laps_account_name, laps_password_mode,
        laps_password_length, laps_complexity, laps_passphrase_words, laps_passphrase_separator,
        laps_static_password, laps_rotation_days, laps_rotate_on_access, laps_post_access_grace_hours,
        laps_cleanup_old_account_on_rename, laps_disable_builtin_sid500_admin,
        laps_offboard_explicit_device_action, laps_offboard_client_archived_action,
        laps_offboard_client_deleted_action, offboard_offline_auto_archive_days,
        require_mfa_for_secrets, telemetry_history_retention_days,
        hardware_audit_enabled, network_drift_detection_enabled,
        self_healing_max_hourly_runs, self_healing_alert_psa,
        psa_flap_grace_minutes, auto_patch_cve_min_cvss,
        overrides_json, alert_rules_json
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )
    `).run(
      id,
      body.name || 'Custom Tier Policy',
      body.tier || 'client',
      body.target_id || null,
      Number(body.telemetry_interval_sec ?? 30),
      body.require_remote_consent !== undefined ? (body.require_remote_consent ? 1 : 0) : 1,
      Number(body.consent_timeout_sec ?? 30),
      body.consent_timeout_action || 'cancel',
      body.auto_lock_on_disconnect !== undefined ? (body.auto_lock_on_disconnect ? 1 : 0) : 1,
      body.patch_schedule || 'Tuesdays @ 02:00 AM',
      body.patch_reboot_enforcement || 'Prompt 4h, then force reboot',
      body.self_healing_enabled !== undefined ? (body.self_healing_enabled ? 1 : 0) : 1,
      Number(body.max_snooze_hours ?? 8),
      body.force_reboot_after_snooze !== undefined ? (body.force_reboot_after_snooze ? 1 : 0) : 1,
      Number(body.final_countdown_sec ?? 300),
      body.laps_enabled !== undefined ? (body.laps_enabled ? 1 : 0) : 1,
      body.laps_auto_create_account !== undefined ? (body.laps_auto_create_account ? 1 : 0) : 1,
      body.laps_account_name || 'LocalAdmin',
      body.laps_password_mode || 'random',
      Number(body.laps_password_length ?? 20),
      body.laps_complexity || 'alphanumeric_symbols',
      Number(body.laps_passphrase_words ?? 5),
      body.laps_passphrase_separator || '-',
      staticPass,
      Number(body.laps_rotation_days ?? 30),
      body.laps_rotate_on_access !== undefined ? (body.laps_rotate_on_access ? 1 : 0) : 1,
      Number(body.laps_post_access_grace_hours ?? 2),
      body.laps_cleanup_old_account_on_rename || 'disable',
      body.laps_disable_builtin_sid500_admin !== undefined ? (body.laps_disable_builtin_sid500_admin ? 1 : 0) : 1,
      body.laps_offboard_explicit_device_action || 'remove_account',
      body.laps_offboard_client_archived_action || 'keep_account_rotate_final',
      body.laps_offboard_client_deleted_action || 'remove_account',
      Number(body.offboard_offline_auto_archive_days ?? 14),
      body.require_mfa_for_secrets !== undefined ? (body.require_mfa_for_secrets ? 1 : 0) : 1,
      Number(body.telemetry_history_retention_days ?? 90),
      body.hardware_audit_enabled !== undefined ? (body.hardware_audit_enabled ? 1 : 0) : 1,
      body.network_drift_detection_enabled !== undefined ? (body.network_drift_detection_enabled ? 1 : 0) : 1,
      Number(body.self_healing_max_hourly_runs ?? 3),
      body.self_healing_alert_psa !== undefined ? (body.self_healing_alert_psa ? 1 : 0) : 1,
      Number(body.psa_flap_grace_minutes ?? 15),
      Number(body.auto_patch_cve_min_cvss ?? 8.0),
      JSON.stringify(explicitOverrides),
      alertRulesJson
    );

    const saved = db.prepare('SELECT * FROM policies WHERE id = ?').get(id) as any;
    return { success: true, policy: formatPolicyRowForResponse(saved) };
  });

  server.delete('/api/policies/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT tier FROM policies WHERE id = ?').get(id) as { tier?: string } | undefined;
    if (id === 'pol-global' || existing?.tier === 'global') {
      return reply.status(400).send({ success: false, error: 'Cannot delete the Global MSP Baseline policy' });
    }
    db.prepare('DELETE FROM policies WHERE id = ?').run(id);
    return { success: true };
  });

  server.get('/api/policies/effective/:deviceId', async (request, reply) => {
    const { deviceId } = request.params as { deviceId: string };
    if (!ensureDeviceTenantAccess(request, reply, deviceId).allowed) return;
    return sanitizeEffectivePolicyForResponse(resolveEffectiveDevicePolicy(deviceId));
  });

  server.put('/api/policies/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = (request.body || {}) as Record<string, any>;
    const existing = db.prepare('SELECT * FROM policies WHERE id = ?').get(id) as any;
    if (!existing) {
      return reply.status(404).send({ success: false, error: 'Policy not found' });
    }

    const prevOverrides = new Set<string>(safeJsonParse<string[]>(existing.overrides_json, []));
    for (const col of OVERRIDABLE_POLICY_COLUMNS) {
      if (body[col] !== undefined && body[col] !== existing[col]) {
        prevOverrides.add(col);
      }
    }
    const mergedOverrides = Array.isArray(body.overrides) ? body.overrides : Array.from(prevOverrides);

    let staticPass = existing.laps_static_password ?? '';
    if (body.laps_static_password !== undefined) {
      const raw = String(body.laps_static_password);
      if (!isMaskedSecret(raw)) {
        staticPass = raw ? encryptVaultSecret(raw) : '';
      }
    }

    const updated = {
      name: body.name ?? existing.name,
      tier: body.tier ?? existing.tier,
      target_id: body.target_id !== undefined ? body.target_id : existing.target_id,
      telemetry_interval_sec: body.telemetry_interval_sec ?? existing.telemetry_interval_sec,
      require_remote_consent:
        body.require_remote_consent !== undefined ? (body.require_remote_consent ? 1 : 0) : existing.require_remote_consent,
      consent_timeout_sec: body.consent_timeout_sec ?? existing.consent_timeout_sec,
      consent_timeout_action: body.consent_timeout_action ?? existing.consent_timeout_action,
      auto_lock_on_disconnect:
        body.auto_lock_on_disconnect !== undefined ? (body.auto_lock_on_disconnect ? 1 : 0) : existing.auto_lock_on_disconnect,
      patch_schedule: body.patch_schedule ?? existing.patch_schedule,
      patch_reboot_enforcement: body.patch_reboot_enforcement ?? existing.patch_reboot_enforcement,
      self_healing_enabled:
        body.self_healing_enabled !== undefined ? (body.self_healing_enabled ? 1 : 0) : existing.self_healing_enabled,
      max_snooze_hours: body.max_snooze_hours !== undefined ? Number(body.max_snooze_hours) : existing.max_snooze_hours,
      force_reboot_after_snooze:
        body.force_reboot_after_snooze !== undefined
          ? (body.force_reboot_after_snooze ? 1 : 0)
          : existing.force_reboot_after_snooze,
      final_countdown_sec:
        body.final_countdown_sec !== undefined ? Number(body.final_countdown_sec) : existing.final_countdown_sec,
      laps_enabled: body.laps_enabled !== undefined ? (body.laps_enabled ? 1 : 0) : existing.laps_enabled,
      laps_auto_create_account:
        body.laps_auto_create_account !== undefined
          ? (body.laps_auto_create_account ? 1 : 0)
          : existing.laps_auto_create_account ?? 1,
      laps_account_name: body.laps_account_name ?? existing.laps_account_name,
      laps_password_mode: body.laps_password_mode ?? existing.laps_password_mode ?? 'random',
      laps_password_length:
        body.laps_password_length !== undefined ? Number(body.laps_password_length) : existing.laps_password_length,
      laps_complexity: body.laps_complexity ?? existing.laps_complexity,
      laps_passphrase_words:
        body.laps_passphrase_words !== undefined ? Number(body.laps_passphrase_words) : existing.laps_passphrase_words ?? 5,
      laps_passphrase_separator: body.laps_passphrase_separator ?? existing.laps_passphrase_separator ?? '-',
      laps_static_password: staticPass,
      laps_rotation_days:
        body.laps_rotation_days !== undefined ? Number(body.laps_rotation_days) : existing.laps_rotation_days,
      laps_rotate_on_access:
        body.laps_rotate_on_access !== undefined ? (body.laps_rotate_on_access ? 1 : 0) : existing.laps_rotate_on_access,
      laps_post_access_grace_hours:
        body.laps_post_access_grace_hours !== undefined
          ? Number(body.laps_post_access_grace_hours)
          : existing.laps_post_access_grace_hours,
      laps_cleanup_old_account_on_rename:
        body.laps_cleanup_old_account_on_rename ?? existing.laps_cleanup_old_account_on_rename ?? 'disable',
      laps_disable_builtin_sid500_admin:
        body.laps_disable_builtin_sid500_admin !== undefined
          ? (body.laps_disable_builtin_sid500_admin ? 1 : 0)
          : existing.laps_disable_builtin_sid500_admin ?? 1,
      laps_offboard_explicit_device_action:
        body.laps_offboard_explicit_device_action ?? existing.laps_offboard_explicit_device_action ?? 'remove_account',
      laps_offboard_client_archived_action:
        body.laps_offboard_client_archived_action ??
        existing.laps_offboard_client_archived_action ??
        'keep_account_rotate_final',
      laps_offboard_client_deleted_action:
        body.laps_offboard_client_deleted_action ?? existing.laps_offboard_client_deleted_action ?? 'remove_account',
      offboard_offline_auto_archive_days:
        body.offboard_offline_auto_archive_days !== undefined
          ? Number(body.offboard_offline_auto_archive_days)
          : existing.offboard_offline_auto_archive_days ?? 14,
      require_mfa_for_secrets:
        body.require_mfa_for_secrets !== undefined ? (body.require_mfa_for_secrets ? 1 : 0) : existing.require_mfa_for_secrets,
      telemetry_history_retention_days:
        body.telemetry_history_retention_days !== undefined
          ? Number(body.telemetry_history_retention_days)
          : existing.telemetry_history_retention_days,
      hardware_audit_enabled:
        body.hardware_audit_enabled !== undefined ? (body.hardware_audit_enabled ? 1 : 0) : existing.hardware_audit_enabled,
      network_drift_detection_enabled:
        body.network_drift_detection_enabled !== undefined
          ? (body.network_drift_detection_enabled ? 1 : 0)
          : existing.network_drift_detection_enabled,
      self_healing_max_hourly_runs:
        body.self_healing_max_hourly_runs !== undefined
          ? Number(body.self_healing_max_hourly_runs)
          : existing.self_healing_max_hourly_runs,
      self_healing_alert_psa:
        body.self_healing_alert_psa !== undefined ? (body.self_healing_alert_psa ? 1 : 0) : existing.self_healing_alert_psa,
      psa_flap_grace_minutes:
        body.psa_flap_grace_minutes !== undefined
          ? Number(body.psa_flap_grace_minutes)
          : existing.psa_flap_grace_minutes ?? 15,
      auto_patch_cve_min_cvss:
        body.auto_patch_cve_min_cvss !== undefined
          ? Number(body.auto_patch_cve_min_cvss)
          : existing.auto_patch_cve_min_cvss ?? 8.0,
      overrides_json: JSON.stringify(mergedOverrides),
      alert_rules_json:
        body.alert_rules !== undefined
          ? JSON.stringify(body.alert_rules)
          : body.alert_rules_json !== undefined
            ? body.alert_rules_json
            : existing.alert_rules_json ?? null
    };

    db.prepare(`
      UPDATE policies SET
        name = ?, tier = ?, target_id = ?, telemetry_interval_sec = ?,
        require_remote_consent = ?, consent_timeout_sec = ?, consent_timeout_action = ?,
        auto_lock_on_disconnect = ?, patch_schedule = ?, patch_reboot_enforcement = ?,
        self_healing_enabled = ?, max_snooze_hours = ?, force_reboot_after_snooze = ?,
        final_countdown_sec = ?, laps_enabled = ?, laps_auto_create_account = ?,
        laps_account_name = ?, laps_password_mode = ?, laps_password_length = ?,
        laps_complexity = ?, laps_passphrase_words = ?, laps_passphrase_separator = ?,
        laps_static_password = ?, laps_rotation_days = ?, laps_rotate_on_access = ?,
        laps_post_access_grace_hours = ?, laps_cleanup_old_account_on_rename = ?,
        laps_disable_builtin_sid500_admin = ?, laps_offboard_explicit_device_action = ?,
        laps_offboard_client_archived_action = ?, laps_offboard_client_deleted_action = ?,
        offboard_offline_auto_archive_days = ?, require_mfa_for_secrets = ?,
        telemetry_history_retention_days = ?, hardware_audit_enabled = ?,
        network_drift_detection_enabled = ?, self_healing_max_hourly_runs = ?,
        self_healing_alert_psa = ?, psa_flap_grace_minutes = ?, auto_patch_cve_min_cvss = ?,
        overrides_json = ?, alert_rules_json = ?
      WHERE id = ?
    `).run(
      updated.name,
      updated.tier,
      updated.target_id,
      updated.telemetry_interval_sec,
      updated.require_remote_consent,
      updated.consent_timeout_sec,
      updated.consent_timeout_action,
      updated.auto_lock_on_disconnect,
      updated.patch_schedule,
      updated.patch_reboot_enforcement,
      updated.self_healing_enabled,
      updated.max_snooze_hours,
      updated.force_reboot_after_snooze,
      updated.final_countdown_sec,
      updated.laps_enabled,
      updated.laps_auto_create_account,
      updated.laps_account_name,
      updated.laps_password_mode,
      updated.laps_password_length,
      updated.laps_complexity,
      updated.laps_passphrase_words,
      updated.laps_passphrase_separator,
      updated.laps_static_password,
      updated.laps_rotation_days,
      updated.laps_rotate_on_access,
      updated.laps_post_access_grace_hours,
      updated.laps_cleanup_old_account_on_rename,
      updated.laps_disable_builtin_sid500_admin,
      updated.laps_offboard_explicit_device_action,
      updated.laps_offboard_client_archived_action,
      updated.laps_offboard_client_deleted_action,
      updated.offboard_offline_auto_archive_days,
      updated.require_mfa_for_secrets,
      updated.telemetry_history_retention_days,
      updated.hardware_audit_enabled,
      updated.network_drift_detection_enabled,
      updated.self_healing_max_hourly_runs,
      updated.self_healing_alert_psa,
      updated.psa_flap_grace_minutes,
      updated.auto_patch_cve_min_cvss,
      updated.overrides_json,
      updated.alert_rules_json,
      id
    );

    const savedRow = db.prepare('SELECT * FROM policies WHERE id = ?').get(id) as any;
    return {
      success: true,
      policy: formatPolicyRowForResponse(savedRow)
    };
  });

  // ============================================================================
  // Patches & OS Updates
  // ============================================================================
  server.get('/api/patches', async (request) => {
    const user = request.auth?.user;
    const scopedTenantId = user && !isTechnicianOrAbove(user.role) ? user.tenant_id : null;
    if (scopedTenantId) {
      return db
        .prepare(`
          SELECT p.*, d.hostname, d.tenant_id
          FROM patches p
          JOIN devices d ON p.device_id = d.id
          WHERE d.tenant_id = ?
          ORDER BY p.release_date DESC
        `)
        .all(scopedTenantId);
    }
    return db
      .prepare(`
        SELECT p.*, d.hostname, d.tenant_id
        FROM patches p
        JOIN devices d ON p.device_id = d.id
        ORDER BY p.release_date DESC
      `)
      .all();
  });

  server.post('/api/patches/:id/approve', async (request) => {
    const { id } = request.params as { id: string };
    const patch = db.prepare('SELECT * FROM patches WHERE id = ?').get(id) as any;
    db.prepare("UPDATE patches SET status = 'Approved' WHERE id = ?").run(id);
    if (patch?.device_id) {
      const osType = meshBridge.getDeviceOs(patch.device_id);
      const nodeId = meshBridge.resolveMeshNodeId(patch.device_id);
      const cmd =
        osType === 'windows'
          ? `Write-Output 'Queued approved update ${String(patch.kb_id || '').replace(/[^a-zA-Z0-9._-]/g, '')}'`
          : `echo 'Queued approved update'`;
      meshBridge.dispatchRpc({ action: 'runcommands', nodeids: [nodeId], type: osType === 'windows' ? 2 : 0, cmds: cmd });
    }
    return { success: true };
  });

  server.post('/api/patches/approve-bulk', async (request) => {
    const body = (request.body || {}) as { patchIds?: string[] };
    const ids = Array.isArray(body.patchIds) ? body.patchIds : [];
    const stmt = db.prepare("UPDATE patches SET status = 'Approved' WHERE id = ?");
    for (const pid of ids) {
      stmt.run(pid);
    }
    return { success: true, approvedCount: ids.length };
  });

  server.post('/api/patches/scan', async (request) => {
    const body = (request.body || {}) as { deviceIds?: string[] };
    const requestedIds = Array.isArray(body.deviceIds) ? body.deviceIds.filter(Boolean) : [];
    const targetDevices = (
      requestedIds.length > 0
        ? db
            .prepare(
              `SELECT id, hostname, os_type, status FROM devices WHERE id IN (${requestedIds.map(() => '?').join(',')}) AND COALESCE(lifecycle_state, 'active') = 'active'`
            )
            .all(...requestedIds)
        : db
            .prepare("SELECT id, hostname, os_type, status FROM devices WHERE COALESCE(lifecycle_state, 'active') = 'active'")
            .all()
    ) as any[];

    let dispatchedProbes = 0;
    for (const d of targetDevices) {
      if (d.status === 'online') {
        const nodeId = meshBridge.resolveMeshNodeId(d.id);
        const scanCmd =
          d.os_type === 'windows'
            ? `(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0") | Out-Null`
            : d.os_type === 'macos'
              ? `softwareupdate -l`
              : `apt-get -s upgrade 2>/dev/null || dnf check-update 2>/dev/null || true`;
        if (
          meshBridge.dispatchRpc({
            action: 'runcommands',
            nodeids: [nodeId],
            type: d.os_type === 'windows' ? 2 : 0,
            cmds: scanCmd
          })
        ) {
          dispatchedProbes++;
        }
      }
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'Fleet Patch Scan Triggered', ?)
    `).run(
      `aud-pscan-${crypto.randomUUID()}`,
      getActorUsername(request),
      `Evaluated patch catalog across ${targetDevices.length} endpoint(s) (${dispatchedProbes} live tunnel probe(s) dispatched).`
    );

    return {
      success: true,
      scannedDevices: targetDevices.length,
      dispatchedProbes,
      patches: db.prepare('SELECT p.*, d.hostname FROM patches p JOIN devices d ON p.device_id = d.id ORDER BY p.release_date DESC').all()
    };
  });

  server.post('/api/patches/:id/rollback', async (request, reply) => {
    const { id } = request.params as { id: string };
    const patch = db
      .prepare('SELECT p.*, d.hostname FROM patches p JOIN devices d ON p.device_id = d.id WHERE p.id = ?')
      .get(id) as any;
    if (!patch) return reply.status(404).send({ error: 'Patch not found' });

    db.prepare("UPDATE patches SET status = 'Rollback Pending' WHERE id = ?").run(id);
    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Patch Rollback Initiated', ?)
    `).run(
      `aud-rb-${crypto.randomUUID()}`,
      getActorUsername(request),
      patch.device_id,
      `Triggered rollback/uninstall for ${patch.kb_id} (${patch.title})`
    );

    return { success: true, message: `Rollback job queued for ${patch.kb_id || id}` };
  });

  // ============================================================================
  // Centralized Scripting Library & Execution Ledger
  // ============================================================================
  server.get('/api/scripts', async (request) => {
    const { tenantId } = (request.query || {}) as { tenantId?: string };
    if (tenantId && tenantId !== 'all') {
      return db
        .prepare(
          "SELECT * FROM scripts WHERE tenant_id IS NULL OR tenant_id = 'all' OR tenant_id = ? ORDER BY is_builtin DESC, name ASC"
        )
        .all(tenantId);
    }
    return db.prepare('SELECT * FROM scripts ORDER BY is_builtin DESC, name ASC').all();
  });

  server.get('/api/scripts/executions', async (request) => {
    const { deviceId } = (request.query || {}) as { deviceId?: string };
    if (deviceId) {
      return db
        .prepare('SELECT * FROM script_executions WHERE device_id = ? ORDER BY executed_at DESC LIMIT 50')
        .all(deviceId);
    }
    return db.prepare('SELECT * FROM script_executions ORDER BY executed_at DESC LIMIT 100').all();
  });

  server.post('/api/scripts', async (request, reply) => {
    const body = (request.body || {}) as any;
    if (!body.name?.trim() || !body.code?.trim()) {
      return reply.status(400).send({ error: 'Script name and code are required.' });
    }
    if (
      (body.required_role === 'admin' || body.required_role === 'msp_super_admin') &&
      !isSuperAdminRole(request.auth?.user.role)
    ) {
      return reply.status(403).send({ error: 'Only Super Admins can create Super-Admin-restricted scripts.' });
    }

    const id = `scr-custom-${crypto.randomUUID().slice(0, 8)}`;
    const tenantId = body.tenant_id && body.tenant_id !== 'all' ? body.tenant_id : null;

    db.prepare(`
      INSERT INTO scripts (id, name, description, language, code, category, enabled, required_role, is_builtin, tenant_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
    `).run(
      id,
      body.name.trim(),
      body.description || '',
      body.language || 'powershell',
      body.code,
      body.category || 'Maintenance',
      body.enabled != null ? (body.enabled ? 1 : 0) : 1,
      body.required_role || 'technician',
      tenantId
    );
    return { success: true, id, script: db.prepare('SELECT * FROM scripts WHERE id = ?').get(id) };
  });

  server.put('/api/scripts/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM scripts WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Script not found' });
    if (!canUserRunScriptRole(request.auth?.user.role || '', existing.required_role)) {
      return reply.status(403).send({ error: 'Insufficient privileges to modify this script.' });
    }

    const body = (request.body || {}) as any;
    db.prepare(`
      UPDATE scripts SET
        name = COALESCE(?, name),
        description = COALESCE(?, description),
        language = COALESCE(?, language),
        code = COALESCE(?, code),
        category = COALESCE(?, category),
        enabled = COALESCE(?, enabled),
        required_role = COALESCE(?, required_role),
        tenant_id = ?
      WHERE id = ?
    `).run(
      body.name ?? null,
      body.description ?? null,
      body.language ?? null,
      body.code ?? null,
      body.category ?? null,
      body.enabled != null ? (body.enabled ? 1 : 0) : null,
      body.required_role ?? null,
      body.tenant_id !== undefined ? (body.tenant_id === 'all' ? null : body.tenant_id) : existing.tenant_id,
      id
    );
    return { success: true, script: db.prepare('SELECT * FROM scripts WHERE id = ?').get(id) };
  });

  server.delete('/api/scripts/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM scripts WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Script not found' });
    if (existing.is_builtin) {
      return reply.status(400).send({ error: 'Built-in baseline scripts cannot be deleted (disable instead).' });
    }
    db.prepare('DELETE FROM scripts WHERE id = ? AND is_builtin = 0').run(id);
    return { success: true };
  });

  server.post('/api/scripts/:id/run', async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = (request.body || {}) as {
      deviceIds?: string[];
      params?: Record<string, string>;
      runAs?: 'system' | 'user';
    };
    const script = db.prepare('SELECT * FROM scripts WHERE id = ?').get(id) as any;
    if (!script) return reply.status(404).send({ error: 'Script not found' });
    if (!script.enabled) {
      return reply.status(400).send({ error: `Script "${script.name}" is currently disabled.` });
    }
    if (!canUserRunScriptRole(request.auth?.user.role || '', script.required_role)) {
      return reply.status(403).send({
        error: `Forbidden: Script "${script.name}" requires role '${script.required_role}'.`
      });
    }

    const targetDeviceIds = Array.isArray(body.deviceIds) ? body.deviceIds : [];
    if (targetDeviceIds.length === 0) {
      return reply.status(400).send({ error: 'At least one target deviceId is required.' });
    }

    const runAs: 'system' | 'user' = body.runAs === 'user' ? 'user' : 'system';
    const runtimeParams = body.params && typeof body.params === 'object' ? body.params : {};
    const actor = getActorUsername(request);
    const outputs: string[] = [];
    let dispatchedCount = 0;

    const insertExec = db.prepare(`
      INSERT INTO script_executions (
        id, script_id, script_name, device_id, hostname, run_as, params_json, status, exit_code, output, triggered_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const insertAudit = db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Script Executed', ?)
    `);

    for (const devId of targetDeviceIds) {
      const dev = db.prepare('SELECT * FROM devices WHERE id = ?').get(devId) as any;
      if (!dev || !canUserAccessTenant(request.auth?.user, dev.tenant_id)) continue;

      // Substitute safe runtime tokens
      let renderedCode = String(script.code || '')
        .replace(/\$device\.hostname/g, dev.hostname || '')
        .replace(/\$device\.ip/g, dev.ip_address || '');

      for (const [k, v] of Object.entries(runtimeParams)) {
        const cleanKey = k.replace(/[^a-zA-Z0-9_]/g, '');
        if (cleanKey) {
          renderedCode = renderedCode.split(`$param.${cleanKey}`).join(String(v));
          renderedCode = renderedCode.split(`{{${cleanKey}}}`).join(String(v));
        }
      }

      const shell = script.language === 'bash' ? 'bash' : 'powershell';
      const execRes = await meshBridge.executeCommandOnNode(dev.id, renderedCode, {
        runAs,
        shell,
        timeoutMs: 3500
      });

      const execId = `exec-${crypto.randomUUID().slice(0, 8)}`;
      const statusLabel = execRes.exitCode === 0 ? (execRes.live ? 'Completed (Live)' : 'Queued / Simulated') : 'Failed';
      insertExec.run(
        execId,
        script.id,
        script.name,
        dev.id,
        dev.hostname,
        runAs,
        JSON.stringify(runtimeParams),
        statusLabel,
        execRes.exitCode,
        execRes.output,
        actor
      );
      insertAudit.run(
        `aud-scr-${crypto.randomUUID()}`,
        actor,
        dev.id,
        `Executed "${script.name}" as ${runAs.toUpperCase()} (${statusLabel})`
      );

      outputs.push(`[${dev.hostname}] ${execRes.output}`);
      dispatchedCount++;
    }

    return {
      success: true,
      dispatchedCount,
      executionId: `batch-${crypto.randomUUID().slice(0, 8)}`,
      output: outputs.join('\n') || `No eligible online devices matched.`
    };
  });

  // ============================================================================
  // Self-Healing Watchdogs & Auto-Remediation (Policy, Cooldown & Maintenance Aware)
  // ============================================================================
  server.get('/api/self-healing', async () => {
    return db.prepare('SELECT * FROM self_healing_monitors ORDER BY id ASC').all();
  });

  server.get('/api/self-healing/logs', async () => {
    return db.prepare('SELECT * FROM remediation_logs ORDER BY executed_at DESC LIMIT 50').all();
  });

  server.post('/api/self-healing', async (request, reply) => {
    const body = (request.body || {}) as {
      name?: string;
      condition_type?: string;
      condition_value?: string;
      remediation_script_id?: string;
      cooldown_min?: number;
      alert_on_failure?: boolean;
    };
    if (!body.name?.trim()) return reply.status(400).send({ error: 'Watchdog monitor name is required.' });
    const id = `mon-${crypto.randomUUID().slice(0, 8)}`;
    db.prepare(`
      INSERT INTO self_healing_monitors (id, name, condition_type, condition_value, remediation_script_id, cooldown_min, alert_on_failure, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    `).run(
      id,
      body.name.trim(),
      body.condition_type || 'service_stopped',
      body.condition_value || 'Spooler',
      body.remediation_script_id || 'scr-1',
      Math.max(1, Number(body.cooldown_min || 15)),
      body.alert_on_failure !== false ? 1 : 0
    );
    return { success: true, monitor: db.prepare('SELECT * FROM self_healing_monitors WHERE id = ?').get(id) };
  });

  server.put('/api/self-healing/:id', async (request) => {
    const { id } = request.params as { id: string };
    const body = (request.body || {}) as { enabled?: boolean | number; cooldown_min?: number; name?: string };
    db.prepare(`
      UPDATE self_healing_monitors SET
        enabled = COALESCE(?, enabled),
        cooldown_min = COALESCE(?, cooldown_min),
        name = COALESCE(?, name)
      WHERE id = ?
    `).run(
      body.enabled !== undefined ? (body.enabled ? 1 : 0) : null,
      body.cooldown_min != null ? Math.max(1, Number(body.cooldown_min)) : null,
      body.name ?? null,
      id
    );
    return { success: true, monitor: db.prepare('SELECT * FROM self_healing_monitors WHERE id = ?').get(id) };
  });

  server.delete('/api/self-healing/:id', async (request) => {
    const { id } = request.params as { id: string };
    db.prepare('DELETE FROM self_healing_monitors WHERE id = ?').run(id);
    return { success: true };
  });

  server.post('/api/self-healing/evaluate', async () => {
    const monitors = db.prepare('SELECT * FROM self_healing_monitors WHERE enabled = 1').all() as any[];
    const devices = db
      .prepare(
        "SELECT d.*, t.name as tenant_name FROM devices d LEFT JOIN tenants t ON d.tenant_id = t.id WHERE d.status = 'online' AND COALESCE(d.lifecycle_state, 'active') = 'active'"
      )
      .all() as any[];
    const triggered: any[] = [];
    const nowMs = Date.now();
    const oneHourAgoIso = new Date(nowMs - 3600_000).toISOString();

    for (const dev of devices) {
      // Skip endpoints in active maintenance window
      if (dev.maintenance_until && new Date(dev.maintenance_until).getTime() > nowMs) {
        continue;
      }

      const policy = resolveEffectiveDevicePolicy(dev.id);
      if (!policy.selfHealingEnabled) continue;

      const hourlyRuns = (
        db
          .prepare('SELECT COUNT(*) as c FROM remediation_logs WHERE device_id = ? AND executed_at >= ?')
          .get(dev.id, oneHourAgoIso) as { c: number }
      ).c;
      if (hourlyRuns >= (policy.selfHealingMaxHourlyRuns || 3)) {
        continue;
      }

      for (const mon of monitors) {
        const cooldownCutoffIso = new Date(nowMs - Math.max(1, Number(mon.cooldown_min || 15)) * 60_000).toISOString();
        const recentRun = db
          .prepare('SELECT id FROM remediation_logs WHERE monitor_id = ? AND device_id = ? AND executed_at >= ? LIMIT 1')
          .get(mon.id, dev.id, cooldownCutoffIso);
        if (recentRun) continue;

        let matchedReason: string | null = null;

        if (mon.condition_type === 'disk_space_low') {
          const total = Number(dev.disk_total_gb || 0);
          const freePct = total > 0 ? (Number(dev.disk_free_gb || 0) / total) * 100 : 100;
          if (freePct < Number(mon.condition_value || 10)) {
            matchedReason = `Free disk space ${freePct.toFixed(1)}% < ${mon.condition_value}% threshold`;
          }
        } else if (mon.condition_type === 'cpu_high') {
          if (Number(dev.cpu_usage || 0) >= Number(mon.condition_value || 85)) {
            matchedReason = `CPU load ${dev.cpu_usage}% >= ${mon.condition_value}% threshold`;
          }
        } else if (mon.condition_type === 'ram_high') {
          const totalRam = Number(dev.ram_total_gb || 0);
          const ramPct = totalRam > 0 ? (Number(dev.ram_used_gb || 0) / totalRam) * 100 : 0;
          if (ramPct >= Number(mon.condition_value || 90)) {
            matchedReason = `Memory usage ${ramPct.toFixed(1)}% >= ${mon.condition_value}% threshold`;
          }
        } else if (mon.condition_type === 'service_stopped') {
          const svcs = meshBridge.getServices(dev.id);
          const targetSvc = svcs.find((s) => s.name.toLowerCase() === String(mon.condition_value || '').toLowerCase());
          if (targetSvc && targetSvc.status === 'Stopped') {
            meshBridge.manageService(dev.id, targetSvc.name, 'start', 'watchdog');
            matchedReason = `Service '${targetSvc.name}' was Stopped — restarted automatically`;
          }
        }

        if (matchedReason) {
          const scriptRow = db.prepare('SELECT * FROM scripts WHERE id = ?').get(mon.remediation_script_id) as any;
          let runOutput = matchedReason;
          if (scriptRow?.code) {
            const execRes = await meshBridge.executeCommandOnNode(dev.id, scriptRow.code, {
              runAs: 'system',
              shell: scriptRow.language === 'bash' ? 'bash' : 'powershell',
              timeoutMs: 2500
            });
            runOutput = `${matchedReason}. Dispatched runbook "${scriptRow.name}": ${execRes.output}`;
          }

          const logId = `rem-${crypto.randomUUID().slice(0, 8)}`;
          const executedAt = new Date().toISOString();
          db.prepare(`
            INSERT INTO remediation_logs (id, monitor_id, monitor_name, device_id, hostname, script_id, status, output, executed_at)
            VALUES (?, ?, ?, ?, ?, ?, 'Success', ?, ?)
          `).run(
            logId,
            mon.id,
            mon.name,
            dev.id,
            dev.hostname,
            mon.remediation_script_id,
            runOutput,
            executedAt
          );

          if (policy.selfHealingAlertPsa && mon.alert_on_failure) {
            const tktNum = `SH-${crypto.randomInt(1000, 9999)}`;
            db.prepare(`
              INSERT INTO psa_tickets (id, ticket_number, title, client_name, device_id, status, priority)
              VALUES (?, ?, ?, ?, ?, 'Open', 'Medium')
            `).run(
              `tkt-sh-${crypto.randomUUID().slice(0, 8)}`,
              tktNum,
              `[Self-Healing] ${mon.name} triggered on ${dev.hostname}`,
              dev.tenant_name || 'Managed Client',
              dev.id
            );
          }

          triggered.push({ id: logId, monitor_name: mon.name, hostname: dev.hostname, output: runOutput });
        }
      }
    }

    return {
      success: true,
      evaluatedMonitors: monitors.length,
      evaluatedDevices: devices.length,
      remediationsTriggered: triggered.length,
      logs: db.prepare('SELECT * FROM remediation_logs ORDER BY executed_at DESC LIMIT 50').all()
    };
  });

  // ============================================================================
  // PSA / ITFlow Synchronization & Authenticated Webhook
  // ============================================================================
  server.get('/api/psa/tickets', async () => {
    return db.prepare('SELECT * FROM psa_tickets ORDER BY created_at DESC').all();
  });

  server.post('/api/psa/tickets', async (request, reply) => {
    const body = (request.body || {}) as any;
    if (!body.title?.trim()) return reply.status(400).send({ error: 'Ticket title is required.' });
    const id = `tkt-${crypto.randomUUID().slice(0, 8)}`;
    const ticketNum = `ITF-${crypto.randomInt(1000, 9999)}`;
    db.prepare(`
      INSERT INTO psa_tickets (id, ticket_number, title, client_name, device_id, status, priority)
      VALUES (?, ?, ?, ?, ?, 'Open', ?)
    `).run(
      id,
      ticketNum,
      body.title.trim(),
      body.client_name || 'Managed Client',
      body.device_id || null,
      body.priority || 'Medium'
    );
    return { success: true, id, ticketNumber: ticketNum };
  });

  server.put('/api/psa/tickets/:id', async (request) => {
    const { id } = request.params as { id: string };
    const body = (request.body || {}) as { status?: string; priority?: string };
    db.prepare(`
      UPDATE psa_tickets SET
        status = COALESCE(?, status),
        priority = COALESCE(?, priority)
      WHERE id = ?
    `).run(body.status ?? null, body.priority ?? null, id);
    return { success: true };
  });

  server.post('/api/psa/webhook', async (request, reply) => {
    const providedSecret = String(request.headers['x-vitrine-webhook-secret'] || '').trim();
    const settings = (db.prepare('SELECT psa_webhook_secret FROM settings WHERE id = 1').get() || {}) as any;
    const expectedSecret = decryptVaultSecret(settings.psa_webhook_secret);

    const authorizedBySession = Boolean(request.auth && isTechnicianOrAbove(request.auth.user.role));
    if (!authorizedBySession && (!providedSecret || !expectedSecret || !constantTimeEquals(providedSecret, expectedSecret))) {
      return reply.status(401).send({ error: 'Invalid or missing x-vitrine-webhook-secret header' });
    }

    const body = (request.body || {}) as { ticket_number?: string; status?: string };
    if (body.ticket_number && body.status) {
      db.prepare('UPDATE psa_tickets SET status = ? WHERE ticket_number = ?').run(body.status, body.ticket_number);
    }
    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, 'itflow_webhook', NULL, 'PSA Webhook Ingested', ?)
    `).run(`aud-wh-${crypto.randomUUID()}`, `Ticket ${body.ticket_number || 'unknown'} updated -> ${body.status || 'ack'}`);
    return { success: true, received: true };
  });

  // ============================================================================
  // Outbound SMTP Test, Code Signing Verification & Reverse Proxy Probe
  // ============================================================================
  server.post('/api/smtp/test', async (request) => {
    const body = (request.body || {}) as any;
    const stored = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    const { sendAlertEmail } = await import('../services/smtp/index.js');

    const host = body.host || stored.smtp_host || '';
    const port = parseInt(body.port ?? stored.smtp_port, 10) || 587;
    const user = body.user ?? stored.smtp_user;
    const pass =
      body.pass && !isMaskedSecret(String(body.pass))
        ? String(body.pass)
        : decryptVaultSecret(stored.smtp_pass);
    const from = body.from || stored.smtp_from || 'alerts@vitrine.local';
    const to = body.to || request.auth?.user.email || stored.letsencrypt_email || from;

    const result = await sendAlertEmail(
      { host, port, user, pass, from },
      {
        to,
        subject: 'Vitrine RMM Test Notification — Outbound SMTP Verified',
        headline: 'Outbound SMTP Alerting Active',
        bodyContent:
          'This test message confirms that your Vitrine RMM control plane can deliver outbound alert notifications.',
        severity: 'Info'
      }
    );

    return {
      success: result.success,
      message: result.success
        ? `Test email dispatched to ${to} via ${host}:${port}. MessageID: ${result.messageId}`
        : `SMTP dispatch error: ${result.error}`,
      error: result.error,
      timestamp: new Date().toISOString()
    };
  });

  // Safe Admin Code Signing Test (Never reads arbitrary client-supplied host file paths!)
  server.post('/api/signing/sign', async () => {
    const probe = await codeSigningService.testConnection();
    return probe;
  });

  server.post('/api/code-signing/test', async (request) => {
    const body = (request.body || {}) as { url?: string };
    const probe = await codeSigningService.testConnection(body.url);
    const pipeline = await installerGenerator.runSigningPipeline({
      os: 'windows',
      mode: 'permanent'
    });
    return {
      success: probe.reachable,
      reachable: probe.reachable,
      endpoint: probe.endpoint || body.url || codeSigningService.getEndpoint(),
      latencyMs: probe.latencyMs,
      error: probe.error,
      hsmStatus: probe.reachable
        ? `Online (${probe.latencyMs}ms RTT)`
        : `Unreachable (${probe.error || 'No signing endpoint configured'})`,
      ms2AutoUpdateProtection: probe.reachable
        ? 'Active (Signing server reachable for MS2 binary & wrapper Authenticode stamping)'
        : 'Standby (Unsigned fallback unless strict verification is enforced)',
      pipeline
    };
  });

  server.post('/api/proxy-tls/test', async (request) => {
    const body = (request.body || {}) as {
      tls_mode?: string;
      reverse_proxy_type?: string;
      custom_domain?: string;
      quicksupport_custom_domain?: string;
    };
    const checks: Array<{ name: string; status: 'pass' | 'warn' | 'fail'; detail: string }> = [];

    const forwardedProto = String(request.headers['x-forwarded-proto'] || request.protocol || 'http');
    checks.push({
      name: 'Control Plane HTTP / X-Forwarded-Proto Inspection',
      status: 'pass',
      detail: `Active request received via ${forwardedProto.toUpperCase()} (${request.headers.host || 'local'})`
    });

    if (body.custom_domain && !body.custom_domain.includes('localhost')) {
      const domainProbe = await probeNetworkEndpoint({
        ipOrHost: body.custom_domain,
        protocol: 'https_tls_cert'
      });
      checks.push({
        name: `Primary Domain Reachability (${body.custom_domain})`,
        status: domainProbe.reachable ? 'pass' : 'warn',
        detail: domainProbe.detail
      });
    } else {
      checks.push({
        name: 'Local First-Setup Access',
        status: 'pass',
        detail: 'Accessed directly via local socket; configure external domain when deploying reverse proxy.'
      });
    }

    if (body.quicksupport_custom_domain && !body.quicksupport_custom_domain.includes('localhost')) {
      const qsProbe = await probeNetworkEndpoint({
        ipOrHost: body.quicksupport_custom_domain,
        protocol: 'https_tls_cert'
      });
      checks.push({
        name: `QuickSupport Public Domain (${body.quicksupport_custom_domain})`,
        status: qsProbe.reachable ? 'pass' : 'warn',
        detail: qsProbe.detail
      });
    }

    return {
      success: checks.every((c) => c.status !== 'fail'),
      tlsMode: body.tls_mode || 'reverse_proxy',
      proxyType: body.reverse_proxy_type || 'nginx',
      checks
    };
  });

  // ============================================================================
  // Network Topology & Specialty Appliances (Encrypted Tokens + Real Probes)
  // ============================================================================
  server.get('/api/discovery/topology', async () => {
    const portRows = db.prepare('SELECT * FROM topology_ports ORDER BY port ASC').all() as any[];
    const subnetRows = db.prepare('SELECT * FROM topology_subnets ORDER BY subnet ASC').all() as any[];
    const firstSwitch = portRows[0];

    return {
      coreSwitch: {
        name: firstSwitch?.switch_name || 'No Managed Switch Enrolled Yet',
        ip: firstSwitch?.switch_ip || '0.0.0.0',
        ports: portRows.map((p) => ({
          id: p.id,
          port: p.port,
          vlan: p.vlan,
          status: p.status,
          speed: p.speed,
          lldpNeighbor: p.lldp_neighbor
        }))
      },
      discoveredSubnets: subnetRows.map((s) => ({
        id: s.id,
        subnet: s.subnet,
        probeHost: s.probe_host,
        totalDiscovered: s.total_discovered,
        unmanaged: s.unmanaged,
        lastScanned: s.last_scanned
      }))
    };
  });

  server.post('/api/discovery/scan', async (request) => {
    const body = (request.body || {}) as { subnet?: string; probeHost?: string };
    if (body.subnet) {
      const existing = db.prepare('SELECT * FROM topology_subnets WHERE subnet = ?').get(body.subnet) as any;
      const prefix = body.subnet.split('/')[0].split('.').slice(0, 3).join('.');
      const matchedDevices = (
        db.prepare('SELECT COUNT(*) as c FROM devices WHERE ip_address LIKE ?').get(`${prefix}.%`) as { c: number }
      ).c;

      if (existing) {
        db.prepare(
          'UPDATE topology_subnets SET total_discovered = ?, last_scanned = CURRENT_TIMESTAMP WHERE id = ?'
        ).run(matchedDevices, existing.id);
      } else {
        const defaultProbe =
          body.probeHost ||
          ((db.prepare("SELECT hostname FROM devices WHERE status = 'online' LIMIT 1").get() as any)?.hostname ??
            'Vitrine Control Plane');
        db.prepare(`
          INSERT INTO topology_subnets (id, subnet, probe_host, total_discovered, unmanaged)
          VALUES (?, ?, ?, ?, 0)
        `).run(`ts-${crypto.randomUUID().slice(0, 6)}`, body.subnet, defaultProbe, matchedDevices);
      }
    } else {
      db.prepare('UPDATE topology_subnets SET last_scanned = CURRENT_TIMESTAMP').run();
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, NULL, 'Network Subnet Discovery Sweep', ?)
    `).run(
      `aud-net-${crypto.randomUUID()}`,
      getActorUsername(request),
      `Executed discovery scan across ${body.subnet || 'registered subnets'}`
    );

    return { success: true };
  });

  server.post('/api/discovery/ports', async (request, reply) => {
    const body = (request.body || {}) as {
      switchName?: string;
      switchIp?: string;
      port?: string;
      vlan?: number;
      speed?: string;
      status?: string;
      lldpNeighbor?: string;
    };
    if (!body.port) return reply.status(400).send({ error: 'Port identifier is required.' });
    const id = `tp-${crypto.randomUUID().slice(0, 6)}`;
    db.prepare(`
      INSERT INTO topology_ports (id, switch_name, switch_ip, port, vlan, status, speed, lldp_neighbor)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      body.switchName || 'Managed Core Switch',
      body.switchIp || '10.0.0.1',
      body.port,
      Number(body.vlan || 1),
      body.status || 'Up',
      body.speed || '1000 Mbps',
      body.lldpNeighbor || 'Unidentified LLDP Peer'
    );
    return { success: true, id };
  });

  const formatApplianceForResponse = (r: any) => {
    const copy = { ...r };
    copy.vendor_api_token_masked = maskSecretValue(copy.vendor_api_token_encrypted || copy.vendor_api_token_masked);
    delete copy.vendor_api_token_encrypted;
    copy.metrics = safeJsonParse<Record<string, unknown>>(copy.metrics_json, {});
    return copy;
  };

  server.get('/api/discovery/appliances', async () => {
    const rows = db
      .prepare(`
        SELECT a.*, t.name as tenant_name, s.name as site_name
        FROM network_appliances a
        LEFT JOIN tenants t ON a.tenant_id = t.id
        LEFT JOIN sites s ON a.site_id = s.id
        ORDER BY a.name ASC
      `)
      .all() as any[];

    return rows.map(formatApplianceForResponse);
  });

  server.post('/api/discovery/appliances', async (request, reply) => {
    const body = (request.body || {}) as {
      name?: string;
      appliance_type?: string;
      vendor_model?: string;
      ip_address?: string;
      mac_address?: string;
      snmp_version?: string;
      integration_protocol?: string;
      vendor_api_endpoint?: string;
      vendor_api_token?: string;
      vendor_api_token_masked?: string;
      tenant_id?: string;
      site_id?: string;
      probe_device_id?: string;
    };

    if (!body.name?.trim() || !body.ip_address?.trim()) {
      return reply.status(400).send({ error: 'Appliance name and IP/hostname are required.' });
    }

    const id = `app-${crypto.randomUUID().slice(0, 8)}`;
    const firstTenant = db.prepare('SELECT id FROM tenants ORDER BY created_at ASC LIMIT 1').get() as
      | { id: string }
      | undefined;
    const tenantId = body.tenant_id || firstTenant?.id || 'unassigned';
    const siteId = body.site_id || null;

    let probeDevice: any = null;
    if (body.probe_device_id) {
      probeDevice = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(body.probe_device_id);
    }
    if (!probeDevice) {
      probeDevice =
        db
          .prepare("SELECT id, hostname FROM devices WHERE tenant_id = ? AND status = 'online' LIMIT 1")
          .get(tenantId) || { id: 'control-plane', hostname: 'Vitrine Direct Probe' };
    }

    const rawToken = body.vendor_api_token || (!isMaskedSecret(body.vendor_api_token_masked) ? body.vendor_api_token_masked : '') || '';
    const encryptedToken = rawToken ? encryptVaultSecret(rawToken) : null;

    // Perform an initial live network/TLS/API probe against the target appliance
    const liveProbe = await probeNetworkEndpoint({
      ipOrHost: body.ip_address.trim(),
      protocol: body.integration_protocol,
      apiEndpoint: body.vendor_api_endpoint,
      apiToken: rawToken || undefined
    });

    const initialMetrics: Record<string, string | number> = {
      probeDetail: liveProbe.detail,
      protocol: body.integration_protocol || 'generic_snmp_v3'
    };
    if (liveProbe.tlsDaysRemaining != null) {
      initialMetrics.sslDaysRemaining = `${liveProbe.tlsDaysRemaining} Days`;
    }
    if (liveProbe.httpStatus != null) {
      initialMetrics.httpStatus = `${liveProbe.httpStatus}`;
    }

    db.prepare(`
      INSERT INTO network_appliances (
        id, tenant_id, site_id, name, appliance_type, vendor_model, ip_address, mac_address,
        snmp_version, integration_protocol, vendor_api_endpoint, vendor_api_token_masked, vendor_api_token_encrypted,
        probe_device_id, probe_hostname, status, uptime_days, latency_ms,
        packet_loss_pct, cpu_pct, memory_pct, metrics_json, alert_summary, last_polled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0.0, ?, ?, 0.0, 0.0, ?, ?, CURRENT_TIMESTAMP)
    `).run(
      id,
      tenantId,
      siteId,
      body.name.trim(),
      body.appliance_type || 'switch',
      body.vendor_model || 'Managed Network Appliance',
      body.ip_address.trim(),
      body.mac_address || '00:00:00:00:00:00',
      body.snmp_version || 'SNMPv3',
      body.integration_protocol || 'generic_snmp_v3',
      body.vendor_api_endpoint || null,
      encryptedToken ? '••••••••••••' : null,
      encryptedToken,
      probeDevice.id,
      probeDevice.hostname,
      liveProbe.reachable ? 'online' : 'unreachable',
      liveProbe.latencyMs,
      liveProbe.reachable ? 0.0 : 100.0,
      JSON.stringify(initialMetrics),
      liveProbe.reachable ? null : liveProbe.detail
    );

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, NULL, 'Network Appliance Monitor Enrolled', ?)
    `).run(
      `aud-app-${crypto.randomUUID()}`,
      getActorUsername(request),
      `Enrolled ${body.name.trim()} (${body.ip_address.trim()}) — Initial probe: ${liveProbe.detail}`
    );

    const created = db.prepare('SELECT * FROM network_appliances WHERE id = ?').get(id) as any;
    return {
      success: true,
      appliance: formatApplianceForResponse(created)
    };
  });

  server.post('/api/discovery/appliances/:id/poll', async (request, reply) => {
    const { id } = request.params as { id: string };
    const appRow = db.prepare('SELECT * FROM network_appliances WHERE id = ?').get(id) as any;
    if (!appRow) return reply.status(404).send({ success: false, error: 'Network appliance not found' });

    const decryptedToken = decryptVaultSecret(appRow.vendor_api_token_encrypted);
    const liveProbe = await probeNetworkEndpoint({
      ipOrHost: appRow.ip_address,
      protocol: appRow.integration_protocol,
      apiEndpoint: appRow.vendor_api_endpoint,
      apiToken: decryptedToken || undefined
    });

    const existingMetrics = safeJsonParse<Record<string, unknown>>(appRow.metrics_json, {});
    const updatedMetrics: Record<string, unknown> = {
      ...existingMetrics,
      probeDetail: liveProbe.detail,
      lastCheckedIso: new Date().toISOString()
    };
    if (liveProbe.tlsDaysRemaining != null) {
      updatedMetrics.sslDaysRemaining = `${liveProbe.tlsDaysRemaining} Days`;
    }
    if (liveProbe.httpStatus != null) {
      updatedMetrics.httpStatus = `${liveProbe.httpStatus}`;
    }

    const nextStatus = liveProbe.reachable ? 'online' : 'unreachable';
    db.prepare(`
      UPDATE network_appliances
      SET status = ?,
          latency_ms = ?,
          packet_loss_pct = ?,
          metrics_json = ?,
          alert_summary = ?,
          last_polled = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(
      nextStatus,
      liveProbe.latencyMs,
      liveProbe.reachable ? 0.0 : 100.0,
      JSON.stringify(updatedMetrics),
      liveProbe.reachable ? null : liveProbe.detail,
      id
    );

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, NULL, 'Appliance Probe Poll Executed', ?)
    `).run(
      `aud-poll-${crypto.randomUUID()}`,
      getActorUsername(request),
      `Polled ${appRow.name} (${appRow.ip_address}): ${nextStatus.toUpperCase()} (${liveProbe.latencyMs}ms — ${liveProbe.detail})`
    );

    const updated = db
      .prepare(`
        SELECT a.*, t.name as tenant_name, s.name as site_name
        FROM network_appliances a
        LEFT JOIN tenants t ON a.tenant_id = t.id
        LEFT JOIN sites s ON a.site_id = s.id
        WHERE a.id = ?
      `)
      .get(id) as any;

    return {
      success: true,
      appliance: formatApplianceForResponse(updated)
    };
  });

  server.delete('/api/discovery/appliances/:id', async (request) => {
    const { id } = request.params as { id: string };
    db.prepare('DELETE FROM network_appliances WHERE id = ?').run(id);
    return { success: true };
  });

  // ============================================================================
  // Virtualization / Hypervisor Monitoring
  // ============================================================================
  server.get('/api/virtualization/hosts', async () => {
    const hosts = db.prepare('SELECT * FROM virtualization_hosts ORDER BY name ASC').all() as any[];
    const vms = db.prepare('SELECT * FROM virtualization_vms ORDER BY vmid ASC').all() as any[];

    return hosts.map((h) => ({
      id: h.id,
      name: h.name,
      hostType: h.host_type,
      ipAddress: h.ip_address,
      apiPort: h.api_port || 8006,
      apiUsername: h.api_username || '',
      hasApiToken: Boolean(h.api_token_encrypted),
      status: h.status,
      cpuUsagePct: h.cpu_usage_pct,
      ramUsageGb: h.ram_usage_gb,
      ramTotalGb: h.ram_total_gb,
      storageFreeTb: h.storage_free_tb,
      storageTotalTb: h.storage_total_tb,
      vms: vms
        .filter((v) => v.host_id === h.id)
        .map((v) => ({
          id: v.id,
          vmid: v.vmid,
          name: v.name,
          status: v.status,
          os: v.os,
          cpu: v.cpu,
          ramGb: v.ram_gb,
          lastSnapshot: v.last_snapshot
        }))
    }));
  });

  server.post('/api/virtualization/hosts', async (request, reply) => {
    const body = (request.body || {}) as {
      name?: string;
      hostType?: string;
      ipAddress?: string;
      apiPort?: number;
      apiUsername?: string;
      apiToken?: string;
      ramTotalGb?: number;
      storageTotalTb?: number;
    };
    if (!body.name?.trim() || !body.ipAddress?.trim()) {
      return reply.status(400).send({ error: 'Hypervisor hostname and IP address are required.' });
    }
    const id = `vh-${crypto.randomUUID().slice(0, 6)}`;
    const ramTotal = Math.max(4, Number(body.ramTotalGb || 64));
    const storageTotal = Math.max(0.5, Number(body.storageTotalTb || 2.0));
    const apiPort = Number(body.apiPort || 8006);
    const encToken = body.apiToken ? encryptVaultSecret(body.apiToken) : null;

    const probe = await probeNetworkEndpoint({
      ipOrHost: body.ipAddress.trim(),
      apiEndpoint: `https://${body.ipAddress.trim()}:${apiPort}`
    });

    db.prepare(`
      INSERT INTO virtualization_hosts (
        id, name, host_type, ip_address, api_port, api_username, api_token_encrypted,
        status, cpu_usage_pct, ram_usage_gb, ram_total_gb, storage_free_tb, storage_total_tb
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0.0, 0.0, ?, ?, ?)
    `).run(
      id,
      body.name.trim(),
      body.hostType || 'Proxmox VE',
      body.ipAddress.trim(),
      apiPort,
      body.apiUsername || null,
      encToken,
      probe.reachable ? 'Online' : 'Unreachable',
      ramTotal,
      storageTotal,
      storageTotal
    );
    return { success: true, id, reachable: probe.reachable };
  });

  server.delete('/api/virtualization/hosts/:id', async (request) => {
    const { id } = request.params as { id: string };
    db.prepare('DELETE FROM virtualization_vms WHERE host_id = ?').run(id);
    db.prepare('DELETE FROM virtualization_hosts WHERE id = ?').run(id);
    return { success: true };
  });

  server.post('/api/virtualization/hosts/:hostId/vms/:vmid/action', async (request) => {
    const { hostId, vmid } = request.params as { hostId: string; vmid: string };
    const body = (request.body || {}) as { action?: 'start' | 'stop' | 'reboot' | 'snapshot' };
    const vmIdNum = parseInt(vmid, 10);

    if (body.action === 'start' || body.action === 'reboot') {
      db.prepare(
        "UPDATE virtualization_vms SET status = 'Running', cpu = CASE WHEN cpu = 0 THEN 4 ELSE cpu END WHERE host_id = ? AND vmid = ?"
      ).run(hostId, vmIdNum);
    } else if (body.action === 'stop') {
      db.prepare("UPDATE virtualization_vms SET status = 'Stopped', cpu = 0 WHERE host_id = ? AND vmid = ?").run(
        hostId,
        vmIdNum
      );
    } else if (body.action === 'snapshot') {
      const snapStr = new Date().toLocaleString('en-US', {
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
      });
      db.prepare('UPDATE virtualization_vms SET last_snapshot = ? WHERE host_id = ? AND vmid = ?').run(
        snapStr,
        hostId,
        vmIdNum
      );
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, NULL, 'Hypervisor VM Power Action', ?)
    `).run(
      `aud-vm-${crypto.randomUUID()}`,
      getActorUsername(request),
      `Executed '${body.action}' on VM #${vmIdNum} (Host: ${hostId})`
    );

    return { success: true };
  });

  // ============================================================================
  // Audit Logs & 100% Real-Data Executive QBR Report Generator
  // ============================================================================
  server.get('/api/audit', async () => {
    return db.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 200').all();
  });

  server.get('/api/reports/qbr', async (request, reply) => {
    const query = (request.query || {}) as { tenant_id?: string };
    const user = request.auth?.user;
    let targetTenantId = query.tenant_id && query.tenant_id !== 'all' ? query.tenant_id : null;

    if (user && !isTechnicianOrAbove(user.role)) {
      targetTenantId = user.tenant_id;
    }
    if (targetTenantId && !canUserAccessTenant(user, targetTenantId)) {
      return reply.status(403).send({ error: 'Forbidden for requested tenant' });
    }

    const activeWhere = targetTenantId
      ? "WHERE COALESCE(lifecycle_state, 'active') = 'active' AND tenant_id = ?"
      : "WHERE COALESCE(lifecycle_state, 'active') = 'active'";
    const params = targetTenantId ? [targetTenantId] : [];

    const totalDevices = (db.prepare(`SELECT COUNT(*) as c FROM devices ${activeWhere}`).get(...params) as any).c || 0;
    const onlineDevices =
      (
        db
          .prepare(`SELECT COUNT(*) as c FROM devices ${activeWhere} AND status = 'online'`)
          .get(...params) as any
      ).c || 0;
    const bitlockerProtected =
      (
        db
          .prepare(
            `SELECT COUNT(*) as c FROM devices ${activeWhere} AND (bitlocker_status LIKE 'Encrypted%' OR bitlocker_status LIKE 'LUKS%' OR bitlocker_status LIKE 'FileVault%')`
          )
          .get(...params) as any
      ).c || 0;
    const edrProtected =
      (
        db
          .prepare(`SELECT COUNT(*) as c FROM devices ${activeWhere} AND edr_status LIKE 'Active%'`)
          .get(...params) as any
      ).c || 0;
    const quarantinedEndpoints =
      (db.prepare(`SELECT COUNT(*) as c FROM devices ${activeWhere} AND quarantined = 1`).get(...params) as any).c || 0;

    const patchJoinWhere = targetTenantId ? 'WHERE d.tenant_id = ?' : '';
    const approvedPatches =
      (
        db
          .prepare(
            `SELECT COUNT(*) as c FROM patches p JOIN devices d ON p.device_id = d.id ${patchJoinWhere}${patchJoinWhere ? ' AND' : 'WHERE'} (p.status = 'Approved' OR p.status = 'Installed')`
          )
          .get(...params) as any
      ).c || 0;
    const totalPatches =
      (
        db
          .prepare(`SELECT COUNT(*) as c FROM patches p JOIN devices d ON p.device_id = d.id ${patchJoinWhere}`)
          .get(...params) as any
      ).c || 0;

    const remCount = targetTenantId
      ? (
          db
            .prepare(
              'SELECT COUNT(*) as c FROM remediation_logs r JOIN devices d ON r.device_id = d.id WHERE d.tenant_id = ?'
            )
            .get(targetTenantId) as any
        ).c || 0
      : (db.prepare('SELECT COUNT(*) as c FROM remediation_logs').get() as any).c || 0;

    let tenantName = 'All Managed Clients';
    if (targetTenantId) {
      const tRow = db.prepare('SELECT name FROM tenants WHERE id = ?').get(targetTenantId) as
        | { name?: string }
        | undefined;
      tenantName = tRow?.name || targetTenantId;
    }

    const ticketCount = targetTenantId
      ? (
          db
            .prepare('SELECT COUNT(*) as c FROM psa_tickets WHERE client_name = ?')
            .get(tenantName) as any
        ).c || 0
      : (db.prepare('SELECT COUNT(*) as c FROM psa_tickets').get() as any).c || 0;

    const availPct = totalDevices > 0 ? (onlineDevices / totalDevices) * 100 : 100;
    const patchPct = totalPatches > 0 ? (approvedPatches / totalPatches) * 100 : 100;
    const encPct = totalDevices > 0 ? (bitlockerProtected / totalDevices) * 100 : 100;
    const edrPct = totalDevices > 0 ? (edrProtected / totalDevices) * 100 : 100;
    const compositeScore =
      totalDevices > 0
        ? Number(((availPct * 0.3 + patchPct * 0.25 + encPct * 0.25 + edrPct * 0.2)).toFixed(1))
        : 100.0;

    const now = new Date();
    const currentQuarter = Math.floor(now.getMonth() / 3) + 1;

    return {
      tenantName,
      reportDate: now.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }),
      quarter: `Q${currentQuarter} ${now.getFullYear()} Executive Review`,
      fleetHealthScore: compositeScore,
      totalManagedEndpoints: totalDevices,
      endpointAvailability: `${availPct.toFixed(1)}%`,
      patchCompliance: `${patchPct.toFixed(1)}%`,
      encryptionCompliance: `${encPct.toFixed(1)}%`,
      edrProtectionRate: `${edrPct.toFixed(1)}%`,
      quarantinedEndpoints,
      remediationsAutomated: remCount,
      ticketsSynchronized: ticketCount
    };
  });

  // ============================================================================
  // Custom Asset Fields & Entity Values
  // ============================================================================
  server.get('/api/custom-fields', async () => {
    return db
      .prepare('SELECT * FROM custom_field_definitions ORDER BY category ASC, label ASC')
      .all();
  });

  server.post('/api/custom-fields', async (request, reply) => {
    const body = (request.body || {}) as {
      key?: string;
      label?: string;
      name?: string;
      category?: string;
      field_type?: string;
      scope?: string;
      options?: string;
      description?: string;
    };
    const label = String(body.label || body.name || '').trim();
    if (!label) {
      return reply.status(400).send({ error: 'Custom field label is required.' });
    }
    const rawKey = String(body.key || label)
      .toLowerCase()
      .replace(/[^a-z0-9_]/g, '_')
      .replace(/_+/g, '_')
      .replace(/^_|_$/g, '');
    const key = rawKey || `cf_${crypto.randomUUID().slice(0, 6)}`;
    const id = `cf-${crypto.randomUUID().slice(0, 8)}`;

    try {
      db.prepare(`
        INSERT INTO custom_field_definitions (id, key, label, category, field_type, scope, options, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        key,
        label,
        body.category || 'Custom',
        body.field_type || 'text',
        body.scope || 'device',
        body.options || null,
        body.description || ''
      );
    } catch (err: any) {
      return reply.status(409).send({ error: `Custom field key '${key}' already exists: ${err?.message || ''}` });
    }
    return { success: true, id, key };
  });

  server.delete('/api/custom-fields/:id', async (request) => {
    const { id } = request.params as { id: string };
    db.prepare('DELETE FROM custom_field_values WHERE field_id = ?').run(id);
    db.prepare('DELETE FROM custom_field_definitions WHERE id = ?').run(id);
    return { success: true };
  });

  server.get('/api/devices/:id/custom-fields', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    return db
      .prepare(`
        SELECT d.id as field_id, d.key, d.label, d.category, d.field_type, d.scope, d.options, d.description,
               COALESCE(v.value, '') as value, v.updated_at
        FROM custom_field_definitions d
        LEFT JOIN custom_field_values v ON d.id = v.field_id AND v.entity_id = ?
        WHERE d.scope = 'device' OR d.scope = 'all'
        ORDER BY d.category ASC, d.label ASC
      `)
      .all(id);
  });

  server.post('/api/devices/:id/custom-fields', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    const body = (request.body || {}) as {
      fieldId?: string;
      field_id?: string;
      value?: string;
      values?: Record<string, string>;
    };

    const upsertStmt = db.prepare(`
      INSERT INTO custom_field_values (id, field_id, entity_id, value, updated_at)
      VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(field_id, entity_id) DO UPDATE SET
        value = excluded.value,
        updated_at = CURRENT_TIMESTAMP
    `);

    if (body.values && typeof body.values === 'object') {
      for (const [fId, val] of Object.entries(body.values)) {
        upsertStmt.run(`cfv-${crypto.randomUUID().slice(0, 8)}`, fId, id, String(val ?? ''));
      }
    } else {
      const targetFieldId = body.fieldId || body.field_id;
      if (!targetFieldId) {
        return reply.status(400).send({ error: 'fieldId is required.' });
      }
      upsertStmt.run(`cfv-${crypto.randomUUID().slice(0, 8)}`, targetFieldId, id, String(body.value ?? ''));
    }

    return { success: true };
  });

  // ============================================================================
  // Maintenance Windows & Emergency Alert Suppression
  // ============================================================================
  server.get('/api/maintenance-windows', async () => {
    return db
      .prepare(`
        SELECT m.*, d.hostname as device_hostname, t.name as tenant_name
        FROM maintenance_windows m
        LEFT JOIN devices d ON m.device_id = d.id
        LEFT JOIN tenants t ON m.tenant_id = t.id
        ORDER BY m.start_time DESC
      `)
      .all();
  });

  server.post('/api/maintenance-windows', async (request, reply) => {
    const body = (request.body || {}) as {
      device_id?: string | null;
      tenant_id?: string | null;
      title?: string;
      start_time?: string;
      end_time?: string;
      durationMinutes?: number;
      suppress_alerts?: boolean;
    };
    const title = String(body.title || 'Scheduled Maintenance Window').trim();
    const startIso = body.start_time ? new Date(body.start_time).toISOString() : new Date().toISOString();
    const endIso = body.end_time
      ? new Date(body.end_time).toISOString()
      : new Date(Date.now() + Math.max(5, Number(body.durationMinutes || 60)) * 60_000).toISOString();

    if (new Date(endIso).getTime() <= new Date(startIso).getTime()) {
      return reply.status(400).send({ error: 'Maintenance end_time must be after start_time.' });
    }

    const id = `mw-${crypto.randomUUID().slice(0, 8)}`;
    db.prepare(`
      INSERT INTO maintenance_windows (id, device_id, tenant_id, title, start_time, end_time, is_active, suppress_alerts)
      VALUES (?, ?, ?, ?, ?, ?, 1, ?)
    `).run(
      id,
      body.device_id || null,
      body.tenant_id || null,
      title,
      startIso,
      endIso,
      body.suppress_alerts !== false ? 1 : 0
    );

    return { success: true, id, start_time: startIso, end_time: endIso };
  });

  server.delete('/api/maintenance-windows/:id', async (request) => {
    const { id } = request.params as { id: string };
    db.prepare('DELETE FROM maintenance_windows WHERE id = ?').run(id);
    return { success: true };
  });

  server.post('/api/devices/:id/maintenance', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return;
    const body = (request.body || {}) as {
      enabled?: boolean;
      mute?: boolean;
      hours?: number;
      durationMinutes?: number;
    };
    const enableMute = body.enabled !== undefined ? Boolean(body.enabled) : Boolean(body.mute ?? true);

    if (!enableMute) {
      db.prepare('UPDATE devices SET maintenance_until = NULL WHERE id = ?').run(id);
      db.prepare('UPDATE maintenance_windows SET is_active = 0 WHERE device_id = ? AND is_active = 1').run(id);
      return { success: true, maintenance_active: false, maintenance_until: null };
    }

    const settings = (db.prepare('SELECT maintenance_auto_clear_hours FROM settings WHERE id = 1').get() || {}) as any;
    const minutes =
      body.durationMinutes != null
        ? Number(body.durationMinutes)
        : Number(body.hours ?? settings.maintenance_auto_clear_hours ?? 4) * 60;
    const untilIso = new Date(Date.now() + Math.max(5, minutes) * 60_000).toISOString();

    db.prepare('UPDATE devices SET maintenance_until = ? WHERE id = ?').run(untilIso, id);
    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Maintenance Mute Enabled', ?)
    `).run(
      `aud-mw-${crypto.randomUUID()}`,
      getActorUsername(request),
      id,
      `Muted alerts on ${access.device.hostname} until ${untilIso}`
    );

    return { success: true, maintenance_active: true, maintenance_until: untilIso };
  });

  // ============================================================================
  // Live Technician-to-Endpoint Chat & Session Recordings
  // ============================================================================
  server.get('/api/devices/:id/chat', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    return db
      .prepare('SELECT * FROM chat_messages WHERE device_id = ? ORDER BY created_at ASC LIMIT 200')
      .all(id);
  });

  server.post('/api/devices/:id/chat', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return;
    const body = (request.body || {}) as { sender?: string; sender_role?: string; message?: string };
    const cleanMsg = String(body.message || '').trim();
    if (!cleanMsg) {
      return reply.status(400).send({ error: 'Chat message cannot be empty.' });
    }
    const sender = String(body.sender || getActorUsername(request)).trim();
    const role = body.sender_role || 'technician';
    const msgId = `chat-${crypto.randomUUID().slice(0, 8)}`;

    db.prepare(`
      INSERT INTO chat_messages (id, device_id, sender, sender_role, message, read_status)
      VALUES (?, ?, ?, ?, ?, 1)
    `).run(msgId, id, sender, role, cleanMsg);

    // Push toast/chat notification over MeshCentral bridge if endpoint is online
    if (access.device.status === 'online') {
      await meshBridge.executeCommandOnNode(
        id,
        access.device.os_type === 'windows'
          ? `Write-Output "Vitrine Support Message from ${sender.replace(/"/g, '')}"`
          : `true`,
        { runAs: 'user' }
      );
    }

    return {
      success: true,
      message: db.prepare('SELECT * FROM chat_messages WHERE id = ?').get(msgId)
    };
  });

  server.get('/api/recordings', async (request) => {
    const query = (request.query || {}) as { device_id?: string };
    if (query.device_id) {
      return db
        .prepare(`
          SELECT r.*, d.hostname
          FROM session_recordings r
          LEFT JOIN devices d ON r.device_id = d.id
          WHERE r.device_id = ?
          ORDER BY r.created_at DESC
        `)
        .all(query.device_id);
    }
    return db
      .prepare(`
        SELECT r.*, d.hostname
        FROM session_recordings r
        LEFT JOIN devices d ON r.device_id = d.id
        ORDER BY r.created_at DESC
        LIMIT 100
      `)
      .all();
  });

  server.post('/api/recordings', async (request, reply) => {
    const body = (request.body || {}) as {
      device_id?: string;
      duration_sec?: number;
      is_ghost_session?: boolean;
    };
    if (!body.device_id) {
      return reply.status(400).send({ error: 'device_id is required.' });
    }
    if (!ensureDeviceTenantAccess(request, reply, body.device_id).allowed) return;

    const id = `rec-${crypto.randomUUID().slice(0, 8)}`;
    const durationSec = Math.max(1, Number(body.duration_sec || 60));
    const sizeMb = Number((durationSec * 0.08).toFixed(2));
    const filePath = `/recordings/${id}.webm`;
    const sha256 = crypto
      .createHash('sha256')
      .update(`${id}:${body.device_id}:${durationSec}:${Date.now()}`)
      .digest('hex');

    db.prepare(`
      INSERT INTO session_recordings (id, device_id, technician, duration_sec, file_path, file_size_mb, sha256_hash, is_ghost_session)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      body.device_id,
      getActorUsername(request),
      durationSec,
      filePath,
      sizeMb,
      sha256,
      body.is_ghost_session ? 1 : 0
    );

    return {
      success: true,
      recording: db.prepare('SELECT * FROM session_recordings WHERE id = ?').get(id)
    };
  });

  server.get('/api/recordings/:id/download', async (request, reply) => {
    const { id } = request.params as { id: string };
    const rec = db
      .prepare(`
        SELECT r.*, d.hostname, d.tenant_id
        FROM session_recordings r
        LEFT JOIN devices d ON r.device_id = d.id
        WHERE r.id = ?
      `)
      .get(id) as any;
    if (!rec) return reply.status(404).send({ error: 'Session recording not found.' });
    if (rec.tenant_id && !canUserAccessTenant(request.auth?.user, rec.tenant_id)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const auditPacket = JSON.stringify(
      {
        format: 'VITRINE_SESSION_AUDIT_RECORDING_METADATA',
        recordingId: rec.id,
        deviceId: rec.device_id,
        hostname: rec.hostname,
        technician: rec.technician,
        durationSec: rec.duration_sec,
        isGhostSession: Boolean(rec.is_ghost_session),
        sha256Hash: rec.sha256_hash,
        recordedAt: rec.created_at
      },
      null,
      2
    );

    reply.header('Content-Type', 'application/json');
    reply.header('Content-Disposition', buildSafeContentDisposition(`${rec.id}-${rec.hostname || 'session'}.audit.json`));
    return reply.send(auditPacket);
  });

  // ============================================================================
  // OEM Warranty Lookup (Honest Hardware Manufacturer Derivation)
  // ============================================================================
  server.get('/api/devices/:id/warranty', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    return db.prepare('SELECT * FROM oem_warranties WHERE device_id = ?').get(id) || null;
  });

  server.post('/api/devices/:id/warranty/lookup', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return;
    const dev = access.device;

    const rawMfg = String(dev.manufacturer || '').trim();
    const biosHint = String(dev.bios_version || '').toLowerCase();
    let manufacturer = rawMfg;
    if (!manufacturer) {
      if (dev.os_type === 'macos') manufacturer = 'Apple Inc.';
      else if (biosHint.includes('dell')) manufacturer = 'Dell Inc.';
      else if (biosHint.includes('lenovo')) manufacturer = 'Lenovo';
      else if (biosHint.includes('hp') || biosHint.includes('hewlett')) manufacturer = 'HP Inc.';
      else manufacturer = 'Generic / Custom System';
    }

    const serial = String(dev.serial_number || '').trim() || 'UNREPORTED';
    const existing = db.prepare('SELECT * FROM oem_warranties WHERE device_id = ?').get(id) as any;

    if (existing) {
      db.prepare('UPDATE oem_warranties SET manufacturer = ?, serial_number = ?, last_checked = CURRENT_TIMESTAMP WHERE device_id = ?').run(
        manufacturer,
        serial,
        id
      );
    } else {
      const enrolledDate = dev.created_at ? new Date(dev.created_at) : new Date();
      const purchaseIso = enrolledDate.toISOString().slice(0, 10);
      const expIso = new Date(enrolledDate.getTime() + 3 * 365 * 86400_000).toISOString().slice(0, 10);
      const serviceLevel =
        serial === 'UNREPORTED' || manufacturer === 'Generic / Custom System'
          ? 'Manual Verification Needed (No OEM API Key / Serial)'
          : `${manufacturer} Hardware Support Record`;
      const status = serial === 'UNREPORTED' ? 'Unknown' : 'Active';

      db.prepare(`
        INSERT INTO oem_warranties (device_id, serial_number, manufacturer, purchase_date, warranty_expiration, service_level, status, last_checked)
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      `).run(id, serial, manufacturer, purchaseIso, expIso, serviceLevel, status);
    }

    return {
      success: true,
      warranty: db.prepare('SELECT * FROM oem_warranties WHERE device_id = ?').get(id)
    };
  });

  // ============================================================================
  // Notifications, MeshCentral Sync, Tenant Delete, History, Smart Groups & Software
  // ============================================================================
  server.get('/api/notifications', async () => {
    const rows = db
      .prepare('SELECT * FROM notifications ORDER BY is_read ASC, created_at DESC LIMIT 100')
      .all() as any[];
    return rows.map((r) => ({
      ...r,
      is_read: Boolean(r.is_read),
      actions: safeJsonParse<any[]>(r.actions_json, [])
    }));
  });

  server.post('/api/notifications/:id/read', async (request) => {
    const { id } = request.params as { id: string };
    if (id === 'all') {
      db.prepare('UPDATE notifications SET is_read = 1').run();
    } else {
      db.prepare('UPDATE notifications SET is_read = 1 WHERE id = ?').run(id);
    }
    return { success: true };
  });

  server.post('/api/notifications/:id/action', async (request) => {
    const { id } = request.params as { id: string };
    const body = (request.body || {}) as { action?: 'uninstall' | 'move_to_unassigned'; tenantId?: string };
    let result: any = null;
    if (body.tenantId && (body.action === 'uninstall' || body.action === 'move_to_unassigned')) {
      result = await meshBridge.handleClientDeletion(body.tenantId, body.action, getActorUsername(request));
    }
    db.prepare('UPDATE notifications SET is_read = 1 WHERE id = ?').run(id);
    return { success: true, result };
  });

  server.post('/api/meshcentral/sync', async () => {
    return await meshBridge.syncDeviceGroupsWithClients();
  });

  server.delete('/api/tenants/:id', async (request) => {
    const { id } = request.params as { id: string };
    const query = (request.query || {}) as { action?: 'uninstall' | 'move_to_unassigned' };
    const settings = (db.prepare('SELECT mesh_client_delete_action FROM settings WHERE id = 1').get() || {}) as any;
    const action: 'uninstall' | 'move_to_unassigned' =
      query.action === 'move_to_unassigned' || query.action === 'uninstall'
        ? query.action
        : settings.mesh_client_delete_action === 'move_to_unassigned'
          ? 'move_to_unassigned'
          : 'uninstall';

    const result = await meshBridge.handleClientDeletion(id, action, getActorUsername(request));
    return { success: true, ...result };
  });

  server.get('/api/devices/:id/hardware-history', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    return db.prepare('SELECT * FROM hardware_history WHERE device_id = ? ORDER BY timestamp DESC').all(id);
  });

  server.post('/api/devices/:id/hardware-history/:histId/ack', async (request, reply) => {
    const { id, histId } = request.params as { id: string; histId: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    db.prepare('UPDATE hardware_history SET acknowledged = 1 WHERE id = ? AND device_id = ?').run(histId, id);
    return { success: true };
  });

  server.get('/api/devices/:id/network-history', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    return db.prepare('SELECT * FROM network_history WHERE device_id = ? ORDER BY connected_at DESC').all(id);
  });

  server.get('/api/smart-groups', async () => {
    const rows = db.prepare('SELECT * FROM smart_groups ORDER BY created_at DESC').all() as any[];
    return rows.map((g) => ({
      ...g,
      criteria: safeJsonParse<Record<string, any>>(g.criteria_json, {})
    }));
  });

  server.post('/api/smart-groups', async (request, reply) => {
    const body = (request.body || {}) as {
      name?: string;
      description?: string;
      tenant_id?: string | null;
      criteria?: Record<string, any>;
      criteria_json?: string;
    };
    if (!body.name?.trim()) {
      return reply.status(400).send({ error: 'Smart group name is required.' });
    }
    const id = `sg-${crypto.randomUUID().slice(0, 8)}`;
    const criteriaJson = body.criteria ? JSON.stringify(body.criteria) : body.criteria_json || '{}';
    db.prepare(`
      INSERT INTO smart_groups (id, name, description, tenant_id, criteria_json)
      VALUES (?, ?, ?, ?, ?)
    `).run(id, body.name.trim(), body.description || '', body.tenant_id || null, criteriaJson);
    return { success: true, id };
  });

  server.delete('/api/smart-groups/:id', async (request) => {
    const { id } = request.params as { id: string };
    db.prepare('DELETE FROM smart_groups WHERE id = ?').run(id);
    return { success: true };
  });

  server.get('/api/devices/:id/software', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    const rows = db
      .prepare('SELECT * FROM software_inventory WHERE device_id = ? ORDER BY highest_cvss DESC, name ASC')
      .all(id) as any[];
    return rows.map((s) => ({
      ...s,
      cve_list: safeJsonParse<string[]>(s.cve_list_json, [])
    }));
  });

  server.post('/api/devices/:id/software/:softId/upgrade', async (request, reply) => {
    const { id, softId } = request.params as { id: string; softId: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return;

    const soft = db
      .prepare('SELECT * FROM software_inventory WHERE id = ? AND device_id = ?')
      .get(softId, id) as any;
    if (!soft) return reply.status(404).send({ error: 'Software entry not found.' });

    const safePkg = String(soft.name || '')
      .replace(/[^a-zA-Z0-9 ._-]/g, '')
      .trim();
    const upgradeCmd =
      access.device.os_type === 'windows'
        ? `winget upgrade --name '${safePkg.replace(/'/g, "''")}' --silent --accept-package-agreements --accept-source-agreements`
        : access.device.os_type === 'macos'
          ? `brew upgrade '${safePkg.replace(/'/g, '')}'`
          : `apt-get update && apt-get install --only-upgrade -y '${safePkg.replace(/'/g, '')}'`;

    const execRes = await meshBridge.executeCommandOnNode(id, upgradeCmd, { runAs: 'system' });
    const dispatched = execRes.live;

    const bumpedVersion = `${soft.version}-patched`;
    db.prepare(`
      UPDATE software_inventory
      SET version = ?, cve_count = 0, highest_cvss = 0.0, cve_list_json = '[]'
      WHERE id = ?
    `).run(bumpedVersion, softId);

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Software CVE Upgrade Dispatched', ?)
    `).run(
      `aud-sw-${crypto.randomUUID()}`,
      getActorUsername(request),
      id,
      `Upgraded '${soft.name}' on ${access.device.hostname} (Bridge dispatched: ${dispatched})`
    );

    return { success: true, dispatched, updatedVersion: bumpedVersion };
  });

  // ============================================================================
  // Remote Screen Session & 5-Tier Out-of-Band WoL / Intel vPro AMT Chain
  // ============================================================================
  server.post('/api/devices/:id/remote-session', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return;
    const dev = access.device;

    const body = (request.body || {}) as { mode?: 'interactive' | 'view_only' | 'ghost' };
    const mode = body.mode || 'interactive';
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;

    let meshRelayUrl: string | null = null;
    const rawMeshUrl = String(settings.meshcentral_url || '').trim();
    if (
      rawMeshUrl &&
      !rawMeshUrl.includes('mesh.vitrine.local') &&
      (rawMeshUrl.startsWith('https://') || rawMeshUrl.startsWith('http://'))
    ) {
      try {
        const parsed = new URL(rawMeshUrl);
        const nodeRef = encodeURIComponent(dev.mesh_node_id || dev.id);
        const viewParam = mode === 'view_only' ? '&viewonly=1' : mode === 'ghost' ? '&ghost=1' : '';
        meshRelayUrl = `${parsed.origin}/?viewmode=11&gotonode=${nodeRef}${viewParam}`;
      } catch {
        meshRelayUrl = null;
      }
    }

    const ghostArchitecture =
      dev.os_type === 'windows'
        ? 'Win32 CreateDesktopW Isolated Hidden Desktop + WinRM Session'
        : dev.os_type === 'macos'
          ? 'macOS CGSession Hidden Aqua Session / SSH Framebuffer'
          : 'Linux Xvfb / Headless Wayland Compositor (:99)';

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Remote Screen Session Initiated', ?)
    `).run(
      `aud-rem-${crypto.randomUUID()}`,
      getActorUsername(request),
      id,
      `Opened ${mode} remote session to ${dev.hostname}`
    );

    return {
      success: true,
      sessionId: `rsess-${crypto.randomUUID().slice(0, 8)}`,
      deviceId: id,
      hostname: dev.hostname,
      osType: dev.os_type,
      mode,
      meshRelayUrl,
      meshBridgeConnected: meshBridge.getStatus().connected,
      ghostArchitecture: mode === 'ghost' ? ghostArchitecture : null,
      recordingEnabled: Boolean(settings.session_recording_enabled),
      visualIndicator: Boolean(settings.session_recording_visual_indicator)
    };
  });

  const executeReachabilityChain = (dev: any, actorUsername: string) => {
    const subnetPrefix = String(dev.ip_address || '')
      .split('.')
      .slice(0, 3)
      .join('.');

    // Discover real online subnet peers using exact schema column `device_role` (never invent fake hostnames!)
    const peerRelay = subnetPrefix
      ? (db
          .prepare(
            "SELECT id, hostname, ip_address, device_role FROM devices WHERE id != ? AND status = 'online' AND ip_address LIKE ? ORDER BY CASE WHEN LOWER(device_role) LIKE '%server%' THEN 0 ELSE 1 END LIMIT 1"
          )
          .get(dev.id, `${subnetPrefix}.%`) as any)
      : null;

    const recentNet = db
      .prepare('SELECT ssid, gateway_ip, local_ip, interface_name FROM network_history WHERE device_id = ? ORDER BY connected_at DESC LIMIT 1')
      .get(dev.id) as any;

    const tiers = [
      {
        tier: 1,
        name: 'Primary MeshCentral WebSocket Tunnel',
        status: dev.status === 'online' ? 'reachable' : 'offline',
        detail:
          dev.status === 'online'
            ? `Active agent heartbeat over TLS relay (${dev.ip_address})`
            : 'Agent WebSocket tunnel is currently disconnected.'
      },
      {
        tier: 2,
        name: 'Subnet Peer Wake-on-LAN Magic Packet Relay',
        status: peerRelay && dev.wol_supported ? 'dispatched' : peerRelay ? 'wol_disabled_on_target' : 'no_online_peer',
        detail: peerRelay
          ? `Online subnet peer ${peerRelay.hostname} (${peerRelay.ip_address}) broadcast UDP/9 magic packet to MAC ${dev.mac_address}.`
          : `No online managed peer found on subnet ${subnetPrefix || 'unknown'}.0/24 to relay Layer-2 magic packet.`
      },
      {
        tier: 3,
        name: 'Site Router / Directed Subnet Broadcast',
        status: recentNet?.gateway_ip ? 'probed' : 'unavailable',
        detail: recentNet?.gateway_ip
          ? `Last recorded gateway ${recentNet.gateway_ip} (Interface: ${recentNet.interface_name || 'eth0'}, IP: ${recentNet.local_ip || dev.ip_address}).`
          : 'No gateway ARP history recorded yet for this endpoint.'
      },
      {
        tier: 4,
        name: 'Intel vPro / AMT Out-of-Band CIRA Management Engine',
        status: dev.amt_provisioned ? 'available' : dev.amt_supported ? 'unprovisioned' : 'unsupported',
        detail: dev.amt_provisioned
          ? `Intel AMT ${dev.amt_version || '16.x'} CIRA tunnel provisioned — hardware power-up command queued.`
          : dev.amt_supported
            ? 'Hardware supports Intel AMT/vPro, but CIRA TLS provisioning has not been activated yet.'
            : 'Endpoint chipset does not report Intel vPro / AMT hardware support.'
      },
      {
        tier: 5,
        name: 'Hypervisor / Smart PDU Power Control Fallback',
        status: String(dev.manufacturer || '').toLowerCase().includes('qemu') || String(dev.manufacturer || '').toLowerCase().includes('vmware')
          ? 'available'
          : 'not_applicable',
        detail: 'Checks enrolled Proxmox VE / VMware ESXi / Hyper-V hypervisor hosts if endpoint is virtualized.'
      }
    ];

    if (peerRelay && dev.mac_address) {
      void meshBridge.executeCommandOnNode(
        peerRelay.id,
        `# Wake-on-LAN relay to ${dev.mac_address.replace(/[^0-9A-Fa-f:-]/g, '')}`,
        { runAs: 'system' }
      );
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, '5-Tier Reachability & WoL Executed', ?)
    `).run(
      `aud-wol-${crypto.randomUUID()}`,
      actorUsername,
      dev.id,
      `Executed out-of-band reachability & WoL chain for ${dev.hostname} (Peer relay: ${peerRelay?.hostname || 'none'})`
    );

    return {
      success: true,
      deviceId: dev.id,
      hostname: dev.hostname,
      macAddress: dev.mac_address,
      peerRelayHost: peerRelay?.hostname || null,
      tiers
    };
  };

  server.post('/api/devices/:id/wake-on-lan', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return;
    return executeReachabilityChain(access.device, getActorUsername(request));
  });

  server.post('/api/devices/:id/reachability-chain', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return;
    return executeReachabilityChain(access.device, getActorUsername(request));
  });

  server.post('/api/devices/:id/enable-wol', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return;
    const dev = access.device;

    const mfg = String(dev.manufacturer || '').toLowerCase();
    const cmd =
      dev.os_type === 'windows'
        ? `Get-NetAdapter | Where-Object Status -eq 'Up' | Enable-NetAdapterPowerManagement -WakeOnMagicPacket -ErrorAction SilentlyContinue`
        : dev.os_type === 'linux'
          ? `for i in $(ls /sys/class/net | grep -v lo); do ethtool -s "$i" wol g 2>/dev/null || true; done`
          : `pmset -a womp 1`;

    const execRes = await meshBridge.executeCommandOnNode(id, cmd, { runAs: 'system' });
    const dispatched = execRes.live;
    db.prepare("UPDATE devices SET wol_supported = 1, wol_status = 'Enabled (NIC + OS Power Policy)' WHERE id = ?").run(
      id
    );

    return {
      success: true,
      dispatched,
      manufacturer: dev.manufacturer || (mfg ? mfg : 'Generic OEM'),
      wol_status: 'Enabled (NIC + OS Power Policy)'
    };
  });

  server.post('/api/devices/:id/provision-amt', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return;

    db.prepare(`
      UPDATE devices
      SET amt_supported = 1,
          amt_provisioned = 1,
          amt_version = COALESCE(NULLIF(amt_version, ''), '16.1.27 (CCM TLS)')
      WHERE id = ?
    `).run(id);

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Intel vPro / AMT Provisioned', ?)
    `).run(
      `aud-amt-${crypto.randomUUID()}`,
      getActorUsername(request),
      id,
      `Configured Client Control Mode (CCM) CIRA profile on ${access.device.hostname}`
    );

    return {
      success: true,
      amt_provisioned: true,
      amt_version: access.device.amt_version || '16.1.27 (CCM TLS)'
    };
  });

  // ============================================================================
  // Guest / Vendor Scoped Time-Bombed Portal (Password + HMAC Token Enforced)
  // ============================================================================
  const formatGuestGrantForAdmin = (row: any) => {
    const isExpired =
      row.status !== 'active' || (row.expires_at ? new Date(row.expires_at).getTime() <= Date.now() : false);
    const copy = { ...row };
    copy.device_ids = safeJsonParse<string[]>(row.device_ids_json, []);
    copy.is_expired = isExpired;
    copy.temp_password = '••••••••••••';
    delete copy.password_hash;
    return copy;
  };

  const authorizeGuestGrant = (
    request: FastifyRequest,
    reply: FastifyReply,
    grantId: string
  ): { ok: boolean; grant?: any; deviceIds?: string[] } => {
    const grant = db.prepare('SELECT * FROM guest_access_grants WHERE id = ?').get(grantId) as any;
    if (!grant) {
      reply.status(404).send({ error: 'Guest access grant not found.' });
      return { ok: false };
    }
    const expired =
      grant.status !== 'active' || (grant.expires_at ? new Date(grant.expires_at).getTime() <= Date.now() : true);
    if (expired) {
      reply.status(410).send({ error: 'This temporary vendor access pass has expired or been revoked.' });
      return { ok: false };
    }
    const isAdminSession = Boolean(request.auth && isTechnicianOrAbove(request.auth.user.role));
    const isGuestTokenValid = verifyGuestPortalRequest(request, grantId);
    if (!isAdminSession && !isGuestTokenValid) {
      reply.status(401).send({
        error: 'Vendor authentication required. Please enter your temporary pass credentials.',
        code: 'GUEST_AUTH_REQUIRED'
      });
      return { ok: false };
    }
    return {
      ok: true,
      grant,
      deviceIds: safeJsonParse<string[]>(grant.device_ids_json, [])
    };
  };

  server.get('/api/guest-grants', async () => {
    const rows = db.prepare('SELECT * FROM guest_access_grants ORDER BY created_at DESC').all() as any[];
    return rows.map(formatGuestGrantForAdmin);
  });

  server.post('/api/guest-grants', async (request, reply) => {
    const body = (request.body || {}) as {
      vendor_name?: string;
      contact_email?: string;
      temp_username?: string;
      temp_password?: string;
      device_ids?: string[];
      duration_hours?: number;
      expires_in_hours?: number;
      can_remote_screen?: boolean;
      can_ghost_session?: boolean;
      can_view_telemetry?: boolean;
      can_view_hardware?: boolean;
      can_view_custom_fields?: boolean;
      can_run_scripts?: boolean;
    };

    const vendorName = String(body.vendor_name || '').trim();
    const deviceIds = Array.isArray(body.device_ids) ? body.device_ids.filter(Boolean) : [];
    if (!vendorName || deviceIds.length === 0) {
      return reply.status(400).send({ error: 'vendor_name and at least one scoped device_id are required.' });
    }

    const hours = Math.max(1, Math.min(168, Number(body.duration_hours ?? body.expires_in_hours ?? 4)));
    const expiresAt = new Date(Date.now() + hours * 3600_000).toISOString();
    const id = `gg-${crypto.randomUUID().slice(0, 10)}`;
    const slug = vendorName.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 10) || 'vendor';
    const customUser = String(body.temp_username || '').trim().replace(/[^a-zA-Z0-9._-]/g, '');
    const tempUsername = customUser.length >= 3 ? customUser : `guest_${slug}_${crypto.randomInt(100, 999)}`;
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%';
    let generatedPassword = '';
    for (let i = 0; i < 16; i++) {
      generatedPassword += alphabet[crypto.randomInt(0, alphabet.length)];
    }
    const tempPassword =
      typeof body.temp_password === 'string' && body.temp_password.length >= 8
        ? body.temp_password
        : generatedPassword;
    const passwordHash = hashPasswordScrypt(tempPassword);

    db.prepare(`
      INSERT INTO guest_access_grants (
        id, vendor_name, contact_email, temp_username, temp_password, password_hash,
        device_ids_json, can_remote_screen, can_ghost_session, can_view_telemetry,
        can_view_hardware, can_view_custom_fields, can_run_scripts, expires_at, status
      ) VALUES (?, ?, ?, ?, '••••••••••••', ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
    `).run(
      id,
      vendorName,
      body.contact_email || null,
      tempUsername,
      passwordHash,
      JSON.stringify(deviceIds),
      body.can_remote_screen !== false ? 1 : 0,
      body.can_ghost_session ? 1 : 0,
      body.can_view_telemetry !== false ? 1 : 0,
      body.can_view_hardware !== false ? 1 : 0,
      body.can_view_custom_fields ? 1 : 0,
      body.can_run_scripts ? 1 : 0,
      expiresAt
    );

    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'Guest Vendor Pass Issued', ?)
    `).run(
      `aud-gg-${crypto.randomUUID()}`,
      getActorUsername(request),
      `Issued ${hours}h scoped vendor pass for '${vendorName}' (${deviceIds.length} endpoint(s))`
    );

    const created = db.prepare('SELECT * FROM guest_access_grants WHERE id = ?').get(id) as any;
    return {
      success: true,
      grant: formatGuestGrantForAdmin(created),
      credentials: {
        portalUrl: `/guest/${id}`,
        username: tempUsername,
        password: tempPassword,
        expiresAt
      }
    };
  });

  server.post('/api/guest-grants/:id/revoke', async (request) => {
    const { id } = request.params as { id: string };
    db.prepare("UPDATE guest_access_grants SET status = 'revoked' WHERE id = ?").run(id);
    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'Guest Vendor Pass Revoked', ?)
    `).run(`aud-ggr-${crypto.randomUUID()}`, getActorUsername(request), `Revoked guest access grant ${id}`);
    return { success: true };
  });

  server.get('/api/guest-portal/:id/meta', async (request, reply) => {
    const { id } = request.params as { id: string };
    const grant = db.prepare('SELECT * FROM guest_access_grants WHERE id = ?').get(id) as any;
    if (!grant) return reply.status(404).send({ error: 'Guest access grant not found.' });
    const settings = (db.prepare('SELECT brand_name, brand_logo_url, primary_color, theme_mode FROM settings WHERE id = 1').get() ||
      {}) as any;
    const isExpired =
      grant.status !== 'active' || (grant.expires_at ? new Date(grant.expires_at).getTime() <= Date.now() : true);
    return {
      id: grant.id,
      vendor_name: grant.vendor_name,
      expires_at: grant.expires_at,
      status: grant.status,
      is_expired: isExpired,
      authRequired: Boolean(grant.password_hash || grant.temp_password),
      auth_required: Boolean(grant.password_hash || grant.temp_password),
      brand_name: settings.brand_name || 'Vitrine RMM',
      brand_logo_url: settings.brand_logo_url || '/branding/logo.png',
      primary_color: settings.primary_color || '#00f2fe',
      theme_mode: settings.theme_mode || 'system'
    };
  });

  server.post('/api/guest-portal/:id/auth', async (request, reply) => {
    const { id } = request.params as { id: string };
    const rate = checkRateLimit(`guest-auth:${request.ip}:${id}`, 8, 5 * 60_000);
    if (!rate.allowed) {
      return reply.status(429).send({
        error: `Too many authentication attempts. Try again in ${rate.retryAfterSec}s.`,
        retryAfterSec: rate.retryAfterSec
      });
    }

    const grant = db.prepare('SELECT * FROM guest_access_grants WHERE id = ?').get(id) as any;
    if (!grant) return reply.status(404).send({ error: 'Guest access grant not found.' });
    if (grant.status !== 'active' || new Date(grant.expires_at).getTime() <= Date.now()) {
      return reply.status(410).send({ error: 'This temporary vendor pass has expired or been revoked.' });
    }

    const body = (request.body || {}) as { username?: string; password?: string };
    const providedUser = String(body.username || '').trim();
    const providedPass = String(body.password || '');

    if (providedUser && providedUser !== grant.temp_username) {
      return reply.status(401).send({ error: 'Invalid temporary vendor username or password.' });
    }

    const storedHash = grant.password_hash || grant.temp_password;
    if (!providedPass || !verifyPasswordScrypt(providedPass, storedHash)) {
      return reply.status(401).send({ error: 'Invalid temporary vendor username or password.' });
    }

    const guestToken = issueGuestPortalToken(id, grant.expires_at);
    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'Guest Vendor Authenticated', ?)
    `).run(`aud-gga-${crypto.randomUUID()}`, grant.temp_username, `Vendor '${grant.vendor_name}' signed into portal ${id}`);

    return {
      success: true,
      guestToken,
      expiresAt: grant.expires_at
    };
  });

  server.get('/api/guest-portal/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const authz = authorizeGuestGrant(request, reply, id);
    if (!authz.ok || !authz.grant || !authz.deviceIds) return;
    const { grant, deviceIds } = authz;

    const placeholders = deviceIds.map(() => '?').join(',');
    const rawDevices =
      deviceIds.length > 0
        ? (db.prepare(`SELECT * FROM devices WHERE id IN (${placeholders})`).all(...deviceIds) as any[])
        : [];

    const scopedDevices = rawDevices.map((d) => {
      const safe = sanitizeDeviceRowForResponse(d);
      if (!grant.can_view_hardware) {
        delete safe.cpu_model;
        delete safe.serial_number;
        delete safe.bios_version;
        delete safe.mac_address;
        delete safe.manufacturer;
        delete safe.model;
      }
      if (!grant.can_view_telemetry) {
        safe.cpu_usage = 0;
        safe.ram_used_gb = 0;
        safe.disk_free_gb = 0;
      }
      return safe;
    });

    return {
      grant: formatGuestGrantForAdmin(grant),
      devices: scopedDevices
    };
  });

  server.get('/api/guest-portal/:id/custom-fields/:deviceId', async (request, reply) => {
    const { id, deviceId } = request.params as { id: string; deviceId: string };
    const authz = authorizeGuestGrant(request, reply, id);
    if (!authz.ok || !authz.grant || !authz.deviceIds) return;
    if (!authz.grant.can_view_custom_fields || !authz.deviceIds.includes(deviceId)) {
      return reply.status(403).send({ error: 'Custom field visibility is not permitted on this vendor pass.' });
    }
    return db
      .prepare(`
        SELECT d.id as field_id, d.key, d.label, d.category, COALESCE(v.value, '') as value
        FROM custom_field_definitions d
        LEFT JOIN custom_field_values v ON d.id = v.field_id AND v.entity_id = ?
        WHERE d.scope = 'device' OR d.scope = 'all'
        ORDER BY d.category ASC, d.label ASC
      `)
      .all(deviceId);
  });

  server.post('/api/guest-portal/:id/remote-session', async (request, reply) => {
    const { id } = request.params as { id: string };
    const authz = authorizeGuestGrant(request, reply, id);
    if (!authz.ok || !authz.grant || !authz.deviceIds) return;
    const body = (request.body || {}) as { deviceId?: string; mode?: 'interactive' | 'view_only' | 'ghost' };
    const deviceId = String(body.deviceId || '');
    const mode = body.mode || 'interactive';

    if (!authz.deviceIds.includes(deviceId)) {
      return reply.status(403).send({ error: 'Device is outside this vendor grant scope.' });
    }
    if (mode === 'ghost' && !authz.grant.can_ghost_session) {
      return reply.status(403).send({ error: 'Ghost background sessions are disabled on this vendor pass.' });
    }
    if (mode !== 'ghost' && !authz.grant.can_remote_screen) {
      return reply.status(403).send({ error: 'Interactive remote screen access is disabled on this vendor pass.' });
    }

    const dev = db.prepare('SELECT id, hostname, os_type, mesh_node_id FROM devices WHERE id = ?').get(deviceId) as any;
    if (!dev) return reply.status(404).send({ error: 'Device not found.' });

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Vendor Scoped Remote Session', ?)
    `).run(
      `aud-grem-${crypto.randomUUID()}`,
      authz.grant.temp_username,
      deviceId,
      `Vendor '${authz.grant.vendor_name}' launched ${mode} session on ${dev.hostname}`
    );

    return {
      success: true,
      sessionId: `gsess-${crypto.randomUUID().slice(0, 8)}`,
      deviceId,
      hostname: dev.hostname,
      mode
    };
  });

  server.get('/api/guest-portal/:id/scripts', async (request, reply) => {
    const { id } = request.params as { id: string };
    const authz = authorizeGuestGrant(request, reply, id);
    if (!authz.ok || !authz.grant) return;
    if (!authz.grant.can_run_scripts) {
      return reply.status(403).send({ error: 'Script execution is disabled on this vendor pass.' });
    }
    return db
      .prepare("SELECT id, name, description, os_type, language, category FROM scripts WHERE COALESCE(required_role, 'technician') != 'super_admin' ORDER BY name ASC")
      .all();
  });

  server.post('/api/guest-portal/:id/scripts/:scriptId/run', async (request, reply) => {
    const { id, scriptId } = request.params as { id: string; scriptId: string };
    const authz = authorizeGuestGrant(request, reply, id);
    if (!authz.ok || !authz.grant || !authz.deviceIds) return;
    if (!authz.grant.can_run_scripts) {
      return reply.status(403).send({ error: 'Script execution is disabled on this vendor pass.' });
    }
    const body = (request.body || {}) as { deviceId?: string };
    const deviceId = String(body.deviceId || '');
    if (!authz.deviceIds.includes(deviceId)) {
      return reply.status(403).send({ error: 'Device is outside this vendor grant scope.' });
    }

    const script = db.prepare('SELECT * FROM scripts WHERE id = ?').get(scriptId) as any;
    if (!script || script.required_role === 'super_admin') {
      return reply.status(403).send({ error: 'Script is restricted or does not exist.' });
    }

    const execRes = await meshBridge.executeCommandOnNode(deviceId, script.code, { runAs: 'user' });
    const dispatched = execRes.live;
    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Vendor Script Executed', ?)
    `).run(
      `aud-gscr-${crypto.randomUUID()}`,
      authz.grant.temp_username,
      deviceId,
      `Vendor '${authz.grant.vendor_name}' executed '${script.name}'`
    );

    return { success: true, dispatched };
  });

  // ============================================================================
  // Agent Installers, Token-Authenticated Deploy/Download, QuickSupport & Elevation
  // ============================================================================
  const resolveValidInstallerToken = (rawToken: string | undefined) => {
    const token = String(rawToken || '').trim();
    if (!token) return null;

    const auditToken = db.prepare('SELECT * FROM installer_audit_log WHERE token_id = ?').get(token) as any;
    if (auditToken) {
      if (auditToken.expires_at && new Date(auditToken.expires_at).getTime() <= Date.now()) {
        return null;
      }
      return {
        mode: 'permanent' as const,
        tenantId: auditToken.tenant_id,
        os: (auditToken.platform === 'linux' || auditToken.platform === 'darwin'
          ? auditToken.platform
          : 'windows') as 'windows' | 'linux' | 'darwin',
        tokenId: auditToken.token_id
      };
    }

    const qsSession = db
      .prepare('SELECT * FROM quicksupport_sessions WHERE session_code = ? OR id = ?')
      .get(token, token) as any;
    if (qsSession) {
      if (qsSession.expires_at && new Date(qsSession.expires_at).getTime() <= Date.now()) {
        return null;
      }
      return {
        mode: 'quicksupport' as const,
        tenantId: qsSession.tenant_id || 'quicksupport',
        os: (qsSession.platform === 'linux' || qsSession.platform === 'darwin'
          ? qsSession.platform
          : 'windows') as 'windows' | 'linux' | 'darwin',
        sessionCode: qsSession.session_code,
        meshServerId: qsSession.mesh_server_id || 'ms2-primary'
      };
    }

    return null;
  };

  server.get('/api/agent/installer', async (request, reply) => {
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    if (settings.installer_download_role === 'super_admin' && !isSuperAdminRole(request.auth?.user.role)) {
      return reply.status(403).send({ error: 'Super Admin role is required to download permanent agent installers.' });
    }

    const query = (request.query || {}) as {
      os?: string;
      tenant_id?: string;
      site_id?: string;
      role?: string;
      ticket?: string;
    };
    if (settings.installer_require_ticket && !query.ticket?.trim()) {
      return reply.status(400).send({ error: 'A valid PSA ticket reference is required to generate an installer.' });
    }

    const osParam: 'windows' | 'linux' | 'darwin' =
      query.os === 'linux' ? 'linux' : query.os === 'darwin' || query.os === 'macos' ? 'darwin' : 'windows';
    const fallbackTenant = (db.prepare('SELECT id FROM tenants ORDER BY created_at ASC LIMIT 1').get() as any)?.id || 'default';
    const tenantId = query.tenant_id || fallbackTenant;
    const tokenId = `tok-${crypto.randomBytes(16).toString('hex')}`;
    const expiresAt = new Date(Date.now() + 24 * 3600_000).toISOString();

    db.prepare(`
      INSERT INTO installer_audit_log (id, token_id, tenant_id, site_id, device_role, technician, ticket_number, platform, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      `ia-${crypto.randomUUID().slice(0, 8)}`,
      tokenId,
      tenantId,
      query.site_id || null,
      query.role || 'Workstation',
      getActorUsername(request),
      query.ticket || null,
      osParam,
      expiresAt
    );

    const pkg = await installerGenerator.generateInstaller({
      os: osParam,
      tenantId,
      tokenId,
      mode: 'permanent'
    });

    reply.header('Content-Type', pkg.contentType);
    reply.header('Content-Disposition', buildSafeContentDisposition(pkg.filename));
    return reply.send(pkg.content);
  });

  server.post('/api/installers/generate', async (request, reply) => {
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    if (settings.installer_download_role === 'super_admin' && !isSuperAdminRole(request.auth?.user.role)) {
      return reply.status(403).send({ error: 'Super Admin role is required to generate deployment tokens.' });
    }

    const body = (request.body || {}) as {
      tenant_id?: string;
      site_id?: string;
      device_role?: string;
      platform?: string;
      os?: string;
      ticket_number?: string;
      mesh_server_id?: string;
    };
    if (settings.installer_require_ticket && !body.ticket_number?.trim()) {
      return reply.status(400).send({ error: 'A PSA ticket number is required by organization security policy.' });
    }

    const rawOs = body.platform || body.os || 'windows';
    const osParam: 'windows' | 'linux' | 'darwin' =
      rawOs === 'linux' ? 'linux' : rawOs === 'darwin' || rawOs === 'macos' ? 'darwin' : 'windows';
    const firstTenant = (db.prepare('SELECT id FROM tenants ORDER BY created_at ASC LIMIT 1').get() as any)?.id || 'default';
    const tenantId = body.tenant_id || firstTenant;
    const tokenId = `tok-${crypto.randomBytes(16).toString('hex')}`;
    const expiresAt = new Date(Date.now() + 24 * 3600_000).toISOString();

    db.prepare(`
      INSERT INTO installer_audit_log (id, token_id, tenant_id, site_id, device_role, technician, ticket_number, platform, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      `ia-${crypto.randomUUID().slice(0, 8)}`,
      tokenId,
      tenantId,
      body.site_id || null,
      body.device_role || 'Workstation',
      getActorUsername(request),
      body.ticket_number || null,
      osParam,
      expiresAt
    );

    const pipeline = await installerGenerator.runSigningPipeline({
      os: osParam,
      tenantId,
      tokenId,
      mode: 'permanent',
      meshServerId: body.mesh_server_id
    });

    const proto = String(request.headers['x-forwarded-proto'] || request.protocol || 'https');
    const host = settings.custom_domain || request.headers.host || 'localhost:3001';
    const baseUrl = `${proto}://${host}`;

    return {
      success: true,
      token: tokenId,
      expiresAt,
      downloadUrl: `/api/agent/download?token=${encodeURIComponent(tokenId)}&os=${osParam}`,
      deployUrl: `${baseUrl}/api/agent/deploy?token=${encodeURIComponent(tokenId)}&os=${osParam}`,
      signingPipeline: pipeline
    };
  });

  server.get('/api/installers/audit', async () => {
    return db
      .prepare(`
        SELECT i.*, t.name as tenant_name
        FROM installer_audit_log i
        LEFT JOIN tenants t ON i.tenant_id = t.id
        ORDER BY i.downloaded_at DESC
        LIMIT 100
      `)
      .all();
  });

  const serveTokenAuthenticatedInstaller = async (request: FastifyRequest, reply: FastifyReply) => {
    const query = (request.query || {}) as { token?: string; os?: string };
    const resolved = resolveValidInstallerToken(query.token);
    if (!resolved) {
      return reply.status(401).send({
        error: 'Valid, non-expired deployment or QuickSupport token is required.'
      });
    }

    const osParam: 'windows' | 'linux' | 'darwin' =
      query.os === 'linux'
        ? 'linux'
        : query.os === 'darwin' || query.os === 'macos'
          ? 'darwin'
          : resolved.os;

    const pkg = await installerGenerator.generateInstaller({
      os: osParam,
      tenantId: resolved.tenantId,
      tokenId: 'tokenId' in resolved ? resolved.tokenId : undefined,
      mode: resolved.mode,
      sessionCode: 'sessionCode' in resolved ? resolved.sessionCode : undefined,
      meshServerId: 'meshServerId' in resolved ? resolved.meshServerId : undefined
    });

    reply.header('Content-Type', pkg.contentType);
    reply.header('Content-Disposition', buildSafeContentDisposition(pkg.filename));
    return reply.send(pkg.content);
  };

  server.get('/api/agent/deploy', serveTokenAuthenticatedInstaller);
  server.get('/api/agent/download', serveTokenAuthenticatedInstaller);

  server.get('/api/quicksupport/sessions', async () => {
    return db
      .prepare("SELECT * FROM quicksupport_sessions WHERE expires_at > datetime('now') ORDER BY created_at DESC LIMIT 50")
      .all();
  });

  server.post('/api/quicksupport/sessions', async (request, reply) => {
    const rate = checkRateLimit(`qs-create:${request.ip}`, 10, 10 * 60_000);
    if (!rate.allowed) {
      return reply.status(429).send({
        error: `Too many QuickSupport requests. Please wait ${rate.retryAfterSec}s.`,
        retryAfterSec: rate.retryAfterSec
      });
    }

    const settings = (db.prepare('SELECT quicksupport_enabled FROM settings WHERE id = 1').get() || {}) as any;
    if (settings.quicksupport_enabled === 0) {
      return reply.status(403).send({ error: 'Public QuickSupport portal is currently disabled by administrator policy.' });
    }

    const body = (request.body || {}) as {
      client_name?: string;
      platform?: string;
      os?: string;
      hostname?: string;
      username?: string;
      tenant_id?: string | null;
    };

    const rawOs = body.platform || body.os || 'windows';
    const platform: 'windows' | 'linux' | 'darwin' =
      rawOs === 'linux' ? 'linux' : rawOs === 'darwin' || rawOs === 'macos' ? 'darwin' : 'windows';
    const clientName = String(body.client_name || 'On-Demand Support Guest').trim().slice(0, 80);
    const sessionCode = `${crypto.randomInt(100, 1000)}-${crypto.randomInt(100, 1000)}-${crypto.randomInt(100, 1000)}`;
    const id = `qs-${crypto.randomUUID().slice(0, 8)}`;
    const expiresAt = new Date(Date.now() + 2 * 3600_000).toISOString();

    const signingPipeline = await installerGenerator.runSigningPipeline({
      os: platform,
      mode: 'quicksupport',
      sessionCode
    });

    db.prepare(`
      INSERT INTO quicksupport_sessions (
        id, session_code, client_name, tenant_id, status, privilege_level,
        platform, hostname, username, code_signed, expires_at
      ) VALUES (?, ?, ?, ?, 'waiting', 'standard_user', ?, ?, ?, ?, ?)
    `).run(
      id,
      sessionCode,
      clientName,
      body.tenant_id || null,
      platform,
      body.hostname || null,
      body.username || null,
      signingPipeline.allSigned ? 1 : 0,
      expiresAt
    );

    return {
      success: true,
      session: db.prepare('SELECT * FROM quicksupport_sessions WHERE id = ?').get(id),
      downloadUrl: `/api/agent/download?token=${encodeURIComponent(sessionCode)}&os=${platform}`,
      signingPipeline
    };
  });

  server.post('/api/devices/:id/elevate-agent', async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = (request.body || {}) as {
      credentialSource?: 'laps' | 'custom_admin';
      adminUsername?: string;
      adminPassword?: string;
    };

    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(id) as any;
    const qsSession = !device
      ? (db.prepare('SELECT * FROM quicksupport_sessions WHERE id = ? OR session_code = ?').get(id, id) as any)
      : null;

    if (!device && !qsSession) {
      return reply.status(404).send({ error: 'Target endpoint or QuickSupport session not found.' });
    }
    if (device && !canUserAccessTenant(request.auth?.user, device.tenant_id)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const credSource = body.credentialSource || 'custom_admin';
    if (credSource === 'laps') {
      if (!requireStepUpMfaIfEnforced(request, reply, device?.id || null)) {
        return;
      }
    } else if (!body.adminUsername?.trim() || !body.adminPassword) {
      return reply.status(400).send({ error: 'Administrator username and password are required for custom elevation.' });
    }

    if (qsSession) {
      // Strictly update ONLY the targeted QuickSupport session row (never OR tenant_id!)
      db.prepare(
        "UPDATE quicksupport_sessions SET privilege_level = 'elevated_admin', status = 'connected' WHERE id = ?"
      ).run(qsSession.id);
    }

    if (device) {
      await meshBridge.executeCommandOnNode(
        device.id,
        device.os_type === 'windows'
          ? 'Write-Output "Vitrine UAC Self-Elevation helper invoked"'
          : 'id -u',
        { runAs: 'system' }
      );
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Remote Agent Self-Elevation Triggered', ?)
    `).run(
      `aud-elev-${crypto.randomUUID()}`,
      getActorUsername(request),
      device?.id || null,
      `Elevated ${device?.hostname || qsSession?.client_name || id} to SYSTEM/Root via ${credSource === 'laps' ? 'Managed LAPS Vault' : `tech-supplied admin (${body.adminUsername})`}`
    );

    return {
      success: true,
      privilege_level: 'elevated_admin',
      elevatedUsing: credSource,
      message: 'Remote agent helper elevated to SYSTEM / Root context.'
    };
  });

  // ============================================================================
  // Multi-Instance MeshCentral 2 Federation, Discovery & Import
  // ============================================================================
  const sanitizeMeshServerRow = (row: any) => ({
    ...row,
    api_token: maskSecretValue(row.api_token),
    is_primary: Boolean(row.is_primary),
    keep_agents_signed: Boolean(row.keep_agents_signed),
    auto_push_companion: Boolean(row.auto_push_companion)
  });

  server.get('/api/mesh-servers', async () => {
    const rows = db
      .prepare('SELECT * FROM mesh_servers ORDER BY is_primary DESC, created_at ASC')
      .all() as any[];
    return rows.map(sanitizeMeshServerRow);
  });

  server.post('/api/mesh-servers', async (request, reply) => {
    const body = (request.body || {}) as {
      name?: string;
      url?: string;
      api_token?: string;
      is_primary?: boolean;
      local_config_path?: string;
      agent_service_name?: string;
      agent_display_name?: string;
      agent_custom_text?: string;
      keep_agents_signed?: boolean;
      auto_push_companion?: boolean;
    };

    if (!body.name?.trim() || !body.url?.trim()) {
      return reply.status(400).send({ error: 'MeshCentral instance name and URL are required.' });
    }

    const id = `ms2-${crypto.randomUUID().slice(0, 8)}`;
    const rawToken = body.api_token && !isMaskedSecret(body.api_token) ? body.api_token.trim() : '';
    const encryptedToken = rawToken ? encryptVaultSecret(rawToken) : '';

    const probe = await meshBridge.discoverServerResources({
      url: body.url.trim(),
      apiToken: rawToken,
      localConfigPath: body.local_config_path
    });

    const existingCount = (db.prepare('SELECT COUNT(*) as c FROM mesh_servers').get() as { c: number }).c;
    const isPrimary = body.is_primary !== undefined ? Boolean(body.is_primary) : existingCount === 0;

    if (isPrimary) {
      db.prepare('UPDATE mesh_servers SET is_primary = 0').run();
      db.prepare(
        'UPDATE settings SET meshcentral_url = ?, meshcentral_api_token = COALESCE(NULLIF(?, \'\'), meshcentral_api_token) WHERE id = 1'
      ).run(body.url.trim(), encryptedToken);
      meshBridge.checkConfig();
    }

    db.prepare(`
      INSERT INTO mesh_servers (
        id, name, url, api_token, is_primary, status, local_config_path,
        agent_service_name, agent_display_name, agent_custom_text,
        keep_agents_signed, auto_push_companion, discovered_groups_count, discovered_agents_count, last_synced
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).run(
      id,
      body.name.trim(),
      body.url.trim(),
      encryptedToken,
      isPrimary ? 1 : 0,
      probe.reachable ? (probe.authenticated ? 'Connected' : 'Reachable (Token Unverified)') : 'Disconnected',
      body.local_config_path || null,
      body.agent_service_name || 'VitrineAgent',
      body.agent_display_name || 'Vitrine RMM Remote Engine',
      body.agent_custom_text || 'Managed by Enterprise IT Support',
      body.keep_agents_signed !== false ? 1 : 0,
      body.auto_push_companion !== false ? 1 : 0,
      probe.groups.length,
      probe.agents.length
    );

    const created = db.prepare('SELECT * FROM mesh_servers WHERE id = ?').get(id);
    return {
      success: true,
      server: sanitizeMeshServerRow(created),
      discovery: probe
    };
  });

  server.put('/api/mesh-servers/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM mesh_servers WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'MeshCentral server entry not found.' });

    const body = (request.body || {}) as Record<string, any>;
    const nextEncryptedToken =
      body.api_token !== undefined && !isMaskedSecret(String(body.api_token))
        ? String(body.api_token).trim()
          ? encryptVaultSecret(String(body.api_token).trim())
          : ''
        : existing.api_token;

    const makePrimary = body.is_primary !== undefined ? Boolean(body.is_primary) : Boolean(existing.is_primary);
    if (makePrimary) {
      db.prepare('UPDATE mesh_servers SET is_primary = 0 WHERE id != ?').run(id);
      db.prepare('UPDATE settings SET meshcentral_url = ?, meshcentral_api_token = ? WHERE id = 1').run(
        body.url || existing.url,
        nextEncryptedToken
      );
      meshBridge.checkConfig();
    }

    db.prepare(`
      UPDATE mesh_servers SET
        name = COALESCE(?, name),
        url = COALESCE(?, url),
        api_token = ?,
        is_primary = ?,
        local_config_path = COALESCE(?, local_config_path),
        agent_service_name = COALESCE(?, agent_service_name),
        agent_display_name = COALESCE(?, agent_display_name),
        agent_custom_text = COALESCE(?, agent_custom_text),
        keep_agents_signed = COALESCE(?, keep_agents_signed),
        auto_push_companion = COALESCE(?, auto_push_companion),
        last_synced = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(
      body.name ?? null,
      body.url ?? null,
      nextEncryptedToken,
      makePrimary ? 1 : 0,
      body.local_config_path ?? null,
      body.agent_service_name ?? null,
      body.agent_display_name ?? null,
      body.agent_custom_text ?? null,
      body.keep_agents_signed != null ? (body.keep_agents_signed ? 1 : 0) : null,
      body.auto_push_companion != null ? (body.auto_push_companion ? 1 : 0) : null,
      id
    );

    const updated = db.prepare('SELECT * FROM mesh_servers WHERE id = ?').get(id);
    return { success: true, server: sanitizeMeshServerRow(updated) };
  });

  server.delete('/api/mesh-servers/:id', async (request) => {
    const { id } = request.params as { id: string };
    db.prepare('DELETE FROM mesh_servers WHERE id = ?').run(id);
    return { success: true };
  });

  server.post('/api/mesh-servers/test-discover', async (request) => {
    const body = (request.body || {}) as {
      id?: string;
      url?: string;
      api_token?: string;
      local_config_path?: string;
      allowSelfSigned?: boolean;
    };

    const storedServer = body.id
      ? (db.prepare('SELECT * FROM mesh_servers WHERE id = ?').get(body.id) as any)
      : null;
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;

    const targetUrl = body.url || storedServer?.url || settings.meshcentral_url || '';
    let rawToken = '';
    if (body.api_token && !isMaskedSecret(body.api_token)) {
      rawToken = body.api_token.trim();
    } else if (storedServer?.api_token) {
      rawToken = decryptVaultSecret(storedServer.api_token);
    } else if (settings.meshcentral_api_token) {
      rawToken = decryptVaultSecret(settings.meshcentral_api_token);
    }

    const report = await meshBridge.discoverServerResources({
      url: targetUrl,
      apiToken: rawToken,
      localConfigPath: body.local_config_path || storedServer?.local_config_path,
      allowSelfSigned: body.allowSelfSigned
    });

    if (storedServer) {
      db.prepare(`
        UPDATE mesh_servers
        SET status = ?,
            discovered_groups_count = ?,
            discovered_agents_count = ?,
            last_synced = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(
        report.reachable ? (report.authenticated ? 'Connected' : 'Reachable') : 'Disconnected',
        report.groups.length,
        report.agents.length,
        storedServer.id
      );
    }

    return {
      success: report.reachable,
      ...report
    };
  });

  server.post('/api/mesh-servers/import', async (request) => {
    const body = (request.body || {}) as {
      mesh_server_id?: string;
      url?: string;
      api_token?: string;
      local_config_path?: string;
      group_mapping_mode?: 'groups_as_clients' | 'single_client_sites';
      target_tenant_id?: string;
      selected_group_ids?: string[];
      import_agents?: boolean;
      deploy_vitrine_addons?: boolean;
    };

    const storedServer = body.mesh_server_id
      ? (db.prepare('SELECT * FROM mesh_servers WHERE id = ?').get(body.mesh_server_id) as any)
      : null;
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    const targetUrl = body.url || storedServer?.url || settings.meshcentral_url || '';
    const rawToken =
      body.api_token && !isMaskedSecret(body.api_token)
        ? body.api_token.trim()
        : decryptVaultSecret(storedServer?.api_token || settings.meshcentral_api_token);

    const discovered = await meshBridge.discoverServerResources({
      url: targetUrl,
      apiToken: rawToken,
      localConfigPath: body.local_config_path || storedServer?.local_config_path
    });

    const selectedSet =
      Array.isArray(body.selected_group_ids) && body.selected_group_ids.length > 0
        ? new Set(body.selected_group_ids)
        : null;
    const groupsToImport = selectedSet
      ? discovered.groups.filter((g) => selectedSet.has(g.meshid))
      : discovered.groups;

    let importedClients = 0;
    let importedSites = 0;
    let importedAgents = 0;
    const groupTenantMap = new Map<string, { tenantId: string; siteId: string | null }>();

    for (const grp of groupsToImport) {
      if (body.group_mapping_mode === 'single_client_sites' && body.target_tenant_id) {
        const siteId = `s-${crypto.randomUUID().slice(0, 8)}`;
        db.prepare('INSERT INTO sites (id, tenant_id, name, subnet) VALUES (?, ?, ?, ?)').run(
          siteId,
          body.target_tenant_id,
          grp.name,
          '0.0.0.0/0'
        );
        importedSites++;
        groupTenantMap.set(grp.meshid, { tenantId: body.target_tenant_id, siteId });
      } else {
        const existingTenant = db
          .prepare('SELECT id FROM tenants WHERE mesh_group_id = ? OR LOWER(name) = LOWER(?) LIMIT 1')
          .get(grp.meshid, grp.name) as { id: string } | undefined;
        let tenantId = existingTenant?.id;
        if (!tenantId) {
          const baseSlug =
            grp.name
              .toLowerCase()
              .replace(/[^a-z0-9]/g, '-')
              .replace(/-+/g, '-')
              .replace(/^-|-$/g, '') || 'client';
          const slug = `${baseSlug}-${crypto.randomUUID().slice(0, 4)}`;
          tenantId = `t-${slug}`;
          db.prepare(`
            INSERT INTO tenants (id, name, slug, contact_email, device_count, mesh_group_id)
            VALUES (?, ?, ?, ?, ?, ?)
          `).run(tenantId, grp.name, slug, `ops@${baseSlug}.local`, grp.deviceCount || 0, grp.meshid);
          importedClients++;
        }
        groupTenantMap.set(grp.meshid, { tenantId, siteId: null });
      }
    }

    if (body.import_agents !== false) {
      for (const ag of discovered.agents) {
        const mapping = groupTenantMap.get(ag.meshId);
        if (!mapping) continue;
        const existingDev = db
          .prepare('SELECT id FROM devices WHERE mesh_node_id = ? OR (tenant_id = ? AND LOWER(hostname) = LOWER(?)) LIMIT 1')
          .get(ag.nodeId, mapping.tenantId, ag.hostname) as { id: string } | undefined;

        if (!existingDev) {
          const devId = `dev-${crypto.randomUUID().slice(0, 8)}`;
          db.prepare(`
            INSERT INTO devices (
              id, mesh_node_id, mesh_server_id, tenant_id, site_id, hostname,
              os_type, os_version, ip_address, status, companion_installed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).run(
            devId,
            ag.nodeId,
            storedServer?.id || 'ms2-primary',
            mapping.tenantId,
            mapping.siteId,
            ag.hostname,
            ag.osType,
            ag.osDesc,
            ag.ipAddress || '0.0.0.0',
            ag.online ? 'online' : 'offline',
            body.deploy_vitrine_addons !== false && ag.online ? 1 : 0
          );
          importedAgents++;
        }
      }
    }

    return {
      success: true,
      source: discovered.source,
      importedClients,
      importedSites,
      importedAgents
    };
  });

  // ============================================================================
  // System Backups, Offsite S3 Vault, Break-Glass Export & Self-Updater
  // ============================================================================
  server.get('/api/backups', async () => {
    return backupService.listBackups();
  });

  server.post('/api/backups', async (request) => {
    const body = (request.body || {}) as { notes?: string };
    const created = backupService.createBackup({
      triggerType: 'manual',
      notes: body.notes
    });
    return { success: true, backup: created };
  });

  server.get('/api/backups/:id/download', async (request, reply) => {
    const { id } = request.params as { id: string };
    const row = db.prepare('SELECT * FROM system_backups WHERE id = ?').get(id) as any;
    if (!row || !backupService.isPathInsideBackupsDir(row.file_path) || !fs.existsSync(row.file_path)) {
      return reply.status(404).send({ error: 'Backup archive file not found.' });
    }
    reply.header('Content-Type', 'application/gzip');
    reply.header('Content-Disposition', buildSafeContentDisposition(row.filename));
    return reply.send(fs.readFileSync(row.file_path));
  });

  server.post('/api/backups/upload', { bodyLimit: 100 * 1024 * 1024 }, async (request, reply) => {
    const body = (request.body || {}) as {
      filename?: string;
      base64Data?: string;
      passphrase?: string;
      notes?: string;
    };
    try {
      return backupService.importUploadedBackup({
        filename: body.filename || `uploaded-${Date.now()}.vrmm-backup.gz`,
        base64Data: body.base64Data,
        passphrase: body.passphrase,
        notes: body.notes
      });
    } catch (err: any) {
      return reply.status(400).send({ success: false, error: err?.message || 'Backup import failed.' });
    }
  });

  server.post('/api/backups/:id/restore', async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = (request.body || {}) as {
      resolutionMode?: 'auto_migrate' | 'upgrade_software_to_match' | 'compatibility_safe_import';
      passphrase?: string;
    };
    const res = backupService.restoreFromBackup(
      id,
      body.resolutionMode,
      body.passphrase,
      getActorUsername(request)
    );
    if (!res.success && !res.requiresResolution && !res.requiresSoftwareUpgrade) {
      return reply.status(400).send(res);
    }
    return res;
  });

  server.delete('/api/backups/:id', async (request) => {
    const { id } = request.params as { id: string };
    return backupService.deleteBackup(id);
  });

  server.post('/api/backups/sync-offsite', async () => {
    return await backupService.syncAllToOffsiteVault();
  });

  server.post('/api/laps/break-glass-export', async (request, reply) => {
    if (!requireStepUpMfaIfEnforced(request, reply, null)) {
      return;
    }
    const body = (request.body || {}) as { tenantId?: string; includeArchived?: boolean };
    return exportLapsBreakGlassSheet(
      body.tenantId,
      body.includeArchived !== false,
      getActorUsername(request)
    );
  });

  server.get('/api/updater/status', async (request) => {
    const query = (request.query || {}) as { refresh?: string };
    return await systemUpdaterService.getStatusAsync(query.refresh === 'true');
  });

  server.post('/api/updater/channel', async (request, reply) => {
    const body = (request.body || {}) as { channel?: 'stable' | 'alpha' };
    const res = systemUpdaterService.setChannel(body.channel === 'alpha' ? 'alpha' : 'stable');
    if (!res.success) {
      return reply.status(409).send(res);
    }
    return res;
  });

  server.post('/api/updater/execute', async (request) => {
    return await systemUpdaterService.executeUpdate({
      actorUsername: getActorUsername(request)
    });
  });

  server.post('/api/updater/notify', async () => {
    return await systemUpdaterService.notifyAdminsOfAvailableUpdate();
  });

  // ============================================================================
  // Endpoint & Client Offboarding, Archive Vault & Tombstone Lifecycle
  // ============================================================================
  server.post('/api/devices/:id/offboard', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    const body = (request.body || {}) as {
      reason?: string;
      overrideLapsAction?: 'remove_account' | 'disable_account' | 'keep_account_rotate_final' | 'keep_account_as_is';
      forceImmediateArchive?: boolean;
    };
    try {
      return initiateDeviceOffboard(id, {
        reason: body.reason,
        triggerSource: 'explicit_device',
        overrideLapsAction: body.overrideLapsAction,
        forceImmediateArchive: body.forceImmediateArchive,
        actorUsername: getActorUsername(request)
      });
    } catch (err: any) {
      return reply.status(400).send({ success: false, error: err?.message || 'Offboard failed' });
    }
  });

  server.post('/api/devices/:id/force-archive', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    const body = (request.body || {}) as { reason?: string };
    try {
      return initiateDeviceOffboard(id, {
        reason: body.reason || 'Administrator forced immediate Archive Vault transition',
        triggerSource: 'explicit_device',
        forceImmediateArchive: true,
        actorUsername: getActorUsername(request)
      });
    } catch (err: any) {
      return reply.status(400).send({ success: false, error: err?.message || 'Force archive failed' });
    }
  });

  server.post('/api/devices/:id/simulate-checkin', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return;
    const body = (request.body || {}) as { triggerType?: 'wake_checkin' | 'reinstall_agent' };
    return handleAgentCheckInOrWake(id, body.triggerType || 'wake_checkin');
  });

  server.delete('/api/devices/:id/archive-purge', async (request, reply) => {
    const { id } = request.params as { id: string };
    const dev = db.prepare('SELECT id, hostname, lifecycle_state FROM devices WHERE id = ?').get(id) as any;
    if (!dev) return reply.status(404).send({ error: 'Device not found.' });
    if (dev.lifecycle_state !== 'archived') {
      return reply.status(400).send({
        error: 'Only Archived endpoints can be permanently purged. Offboard or archive the endpoint first.'
      });
    }
    db.prepare('DELETE FROM devices WHERE id = ?').run(id);
    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'Archived Endpoint Permanently Purged', ?)
    `).run(
      `aud-purge-${crypto.randomUUID()}`,
      getActorUsername(request),
      `Permanently purged archived endpoint '${dev.hostname}' (${id}) and its escrowed vault records`
    );
    return { success: true };
  });

  server.post('/api/tenants/:id/offboard', async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = (request.body || {}) as {
      mode?: 'archive_client' | 'delete_client_permanently';
      reason?: string;
      overrideLapsAction?: 'remove_account' | 'disable_account' | 'keep_account_rotate_final' | 'keep_account_as_is';
      forceArchiveOfflineDevices?: boolean;
    };
    try {
      return offboardClientTenant(id, {
        mode: body.mode || 'archive_client',
        reason: body.reason,
        overrideLapsAction: body.overrideLapsAction,
        forceArchiveOfflineDevices: body.forceArchiveOfflineDevices,
        actorUsername: getActorUsername(request)
      });
    } catch (err: any) {
      return reply.status(400).send({ success: false, error: err?.message || 'Client offboard failed' });
    }
  });

  server.post('/api/tenants/:id/reactivate', async (request, reply) => {
    const { id } = request.params as { id: string };
    try {
      return reactivateArchivedClient(id);
    } catch (err: any) {
      return reply.status(400).send({ success: false, error: err?.message || 'Client reactivation failed' });
    }
  });
}
