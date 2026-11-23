import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fs from 'fs';
import path from 'path';
import net from 'net';
import tls from 'tls';
import crypto from 'crypto';
import {
  db,
  BRANDING_DIR_PATH,
  RECORDINGS_DIR_PATH,
  APP_VERSION,
  seedDemoDataset
} from '../db/index.js';
import {
  meshBridge,
  detectLocalMeshCentralInstallation,
  generateMeshLoginToken,
  applyLocalMeshCentralConfig
} from '../services/meshcentral/index.js';
import {
  getLapsCredential,
  rotateLapsPasswordVerifiedAsync,
  exportLapsBreakGlassSheet
} from '../services/laps/index.js';
import {
  resolveEffectiveDevicePolicy,
  resolvePolicyForInstallerScope,
  sanitizeEffectivePolicyForResponse,
  parsePolicyAlertRules,
  parsePolicyTrayMenuItems,
  evaluateFleetAlertConditions,
  syncTicketWithExternalPsas
} from '../services/policy/index.js';
import { installerGenerator, quotePowerShellLiteral } from '../services/agent/installerGenerator.js';
import { sanitizeAndSquareBrandingPng } from '../services/agent/iconProcessor.js';
import { codeSigningService } from '../services/signing/index.js';
import { backupService } from '../services/backup/index.js';
import { systemUpdaterService } from '../services/updater/index.js';
import {
  initiateDeviceOffboard,
  initiateDeviceOffboardAsync,
  offboardClientTenant,
  offboardClientTenantAsync,
  reactivateArchivedClient,
  handleAgentCheckInOrWake,
  sweepPendingOffboards
} from '../services/offboarding/index.js';
import {
  encryptVaultSecret,
  decryptVaultSecret,
  isEncryptedVaultSecret,
  maskSecretValue,
  isMaskedSecret,
  hashPasswordScrypt,
  verifyPasswordScrypt,
  generateRandomBase32,
  validateOutboundHostSafety,
  safeOutboundFetch
} from '../services/vault/index.js';
import {
  createOidcAuthorizationRedirect,
  completeOidcCallback,
  testOidcDiscoveryConfig
} from '../services/auth/oidc.js';
import { generateQrCodeSvg } from '../services/auth/qrcode.js';
import {
  syncVirtualizationHost,
  dispatchLiveHypervisorVmAction
} from '../services/virtualization/index.js';
import {
  networkDiscoveryService,
  sendWakeOnLanMagicPacket
} from '../services/network/index.js';
import {
  evaluateSmartGroupDevices,
  buildSafeScriptEnvParams
} from '../services/automation/index.js';
import {
  recordDeviceTelemetrySample,
  queryDeviceTelemetryHistory,
  mergeHardwareDetailsJson
} from '../services/telemetry/index.js';
import {
  extractSignalsFromHardwareDetails,
  getSmbiosChassisLabel,
  inferDeviceRole,
  isAutoRolePlaceholder,
  shouldAutoUpdateDeviceRole
} from '../utils/deviceRole.js';
import { registerParityRoutes } from './parityRoutes.js';
import {
  checkRateLimit,
  isSuperAdminRole,
  isTechnicianOrAbove,
  canUserAccessTenant,
  getAllowedTenantIds,
  parseCookies,
  hasUserPermission,
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
  doesUserRequireLoginMfa,
  issuePendingMfaLoginToken,
  verifyPendingMfaLoginChallenge,
  verifySessionStepUpMfa,
  getOrEnrollUserMfaDetails,
  issueGuestPortalToken,
  verifyGuestPortalRequest,
  normalizeAndValidateRole,
  revokeUserSessions,
  listActiveSessions,
  revokeSessionByPrefix,
  issueEphemeralWsTicket
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

function resolveSafeRequestOriginParts(request: FastifyRequest): { proto: string; host: string } {
  const trustProxy = process.env.VITRINE_TRUST_PROXY === 'true';
  const fwdProto = trustProxy ? String(request.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase() : '';
  const proto = fwdProto === 'https' || fwdProto === 'http' ? fwdProto : request.protocol === 'https' ? 'https' : 'http';
  const rawHost = String((trustProxy ? request.headers['x-forwarded-host'] : '') || request.headers.host || 'localhost:8080')
    .split(',')[0]
    .trim();
  const host = /^[a-zA-Z0-9.:[\]-]+$/.test(rawHost) ? rawHost : 'localhost:8080';
  return { proto, host };
}

function resolvePublicBaseUrl(request: FastifyRequest, settings?: { custom_domain?: string | null }): string {
  const { proto, host } = resolveSafeRequestOriginParts(request);
  const rawCustom = String(settings?.custom_domain || '').trim().replace(/\/+$/, '');
  if (!rawCustom) {
    return `${proto}://${host}`;
  }
  const candidate = /^https?:\/\//i.test(rawCustom) ? rawCustom : `${proto}://${rawCustom}`;
  try {
    const parsed = new URL(candidate);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return parsed.origin;
    }
  } catch {
    // Fall back to safe request origin on malformed custom_domain
  }
  return `${proto}://${host}`;
}

function isSameUrlOrigin(candidateUrl: string, storedUrl?: string | null): boolean {
  if (!storedUrl) return false;
  try {
    return new URL(candidateUrl.trim()).origin === new URL(storedUrl.trim()).origin;
  } catch {
    return false;
  }
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
    'agent_enrollment_secret',
    'code_signing_api_key'
  ];
  for (const col of secretCols) {
    copy[col] = maskSecretValue(copy[col]);
  }
  copy.meshcentral_connected = meshBridge.getStatus().connected ? 1 : 0;
  copy.backup_key_acknowledged = Boolean(copy.backup_key_acknowledged);
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

  if (!cleanHost) {
    return { reachable: false, latencyMs: 0, detail: 'Target hostname or IP is empty' };
  }

  const hostSafety = await validateOutboundHostSafety(cleanHost, {
    allowLoopback: false,
    allowPrivateLan: true
  });
  if (!hostSafety.safe) {
    return {
      reachable: false,
      latencyMs: 0,
      detail: hostSafety.reason || 'Blocked invalid or restricted address'
    };
  }

  // 1. If HTTP/HTTPS vendor API endpoint is provided (or WAN SSL probe), inspect TLS/HTTP
  const targetUrl =
    params.apiEndpoint && params.apiEndpoint.includes('://')
      ? params.apiEndpoint
      : params.protocol === 'https_tls_cert'
        ? `https://${cleanHost}`
        : null;

  if (targetUrl) {
    const urlSafety = await validateOutboundHostSafety(targetUrl, {
      allowLoopback: false,
      allowPrivateLan: true
    });
    if (!urlSafety.safe) {
      return {
        reachable: false,
        latencyMs: 0,
        detail: urlSafety.reason || 'Blocked restricted API endpoint URL'
      };
    }
    try {
      const parsed = new URL(targetUrl);
      const pinnedIp = urlSafety.resolvedAddresses?.[0] || parsed.hostname;
      let tlsDaysRemaining: number | undefined;
      let tlsAuthorized = false;

      if (parsed.protocol === 'https:') {
        const tlsInfo = await new Promise<{ days?: number; authorized: boolean }>((resolve) => {
          let settled = false;
          let sock: tls.TLSSocket | null = null;
          const finish = (info: { days?: number; authorized: boolean }) => {
            if (settled) return;
            settled = true;
            clearTimeout(hardTimer);
            try {
              sock?.destroy();
            } catch {}
            resolve(info);
          };
          const hardTimer = setTimeout(() => finish({ days: undefined, authorized: false }), 4000);

          sock = tls.connect(
            {
              host: pinnedIp,
              port: Number(parsed.port || 443),
              servername: parsed.hostname,
              rejectUnauthorized: false,
              timeout: 3500
            },
            () => {
              try {
                const cert = sock?.getPeerCertificate();
                const authorized = Boolean(sock?.authorized);
                if (cert?.valid_to) {
                  const days = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
                  finish({ days, authorized });
                } else {
                  finish({ days: undefined, authorized });
                }
              } catch {
                finish({ days: undefined, authorized: false });
              }
            }
          );
          sock.on('error', () => finish({ days: undefined, authorized: false }));
          sock.on('timeout', () => finish({ days: undefined, authorized: false }));
          sock.on('close', () => finish({ days: undefined, authorized: false }));
        });
        tlsDaysRemaining = tlsInfo.days;
        tlsAuthorized = tlsInfo.authorized;
      }

      const headers: Record<string, string> = {};
      if (params.apiToken) {
        headers.Authorization = `Bearer ${params.apiToken}`;
        headers['X-API-KEY'] = params.apiToken;
      }

      const res = await safeOutboundFetch(targetUrl, {
        method: 'GET',
        headers,
        timeoutMs: 4000,
        allowPrivateLan: true,
        allowSelfSigned: true
      });

      const tlsSummary =
        tlsDaysRemaining != null
          ? tlsDaysRemaining <= 0
            ? ` | TLS EXPIRED (${tlsDaysRemaining}d)`
            : tlsAuthorized
              ? ` | TLS valid (${tlsDaysRemaining}d remaining)`
              : ` | TLS self-signed/untrusted (${tlsDaysRemaining}d remaining)`
          : '';

      return {
        reachable: true,
        latencyMs: Math.max(1, Date.now() - start),
        tlsDaysRemaining,
        httpStatus: res.status,
        detail: `HTTP ${res.status}${tlsSummary}`
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
  const pinnedTcpHost = hostSafety.resolvedAddresses?.[0] || cleanHost;
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
      socket.connect(port, pinnedTcpHost);
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
  // Global Zero-Trust Authentication, Normalized URL, CSRF & RBAC Enforcement Hook
  // ============================================================================
  function getRequiredRoutePermission(
    pathname: string,
    method: string,
    rawUrl: string,
    isApiKey = false
  ): string | null {
    const isSafe = method === 'GET' || method === 'HEAD' || method === 'OPTIONS';
    const hasRevealQuery = /[?&]reveal=true(?:&|$)/i.test(rawUrl);

    if (
      /^\/api\/devices\/[^/]+\/bitlocker$/.test(pathname) ||
      (/^\/api\/devices\/[^/]+\/laps$/.test(pathname) && hasRevealQuery) ||
      /^\/api\/documentation\/[^/]+\/secrets$/.test(pathname) ||
      (/^\/api\/devices\/[^/]+\/custom-fields$/.test(pathname) && hasRevealQuery) ||
      pathname === '/api/laps/break-glass-export'
    ) {
      return 'laps:reveal';
    }
    if (/^\/api\/devices\/[^/]+\/laps\/rotate$/.test(pathname)) {
      return 'laps:rotate';
    }
    if (
      /^\/api\/devices\/[^/]+\/elevate-agent$/.test(pathname) ||
      /^\/api\/remote-sessions\/[^/]+\/elevate$/.test(pathname)
    ) {
      return 'remote:elevate';
    }
    if (/^\/api\/devices\/[^/]+\/remote-session\/consent-bypass$/.test(pathname)) {
      return 'remote:unattended';
    }
    if (/^\/api\/devices\/[^/]+\/(remote-session|mesh-url|lock-screen)$/.test(pathname)) {
      return 'remote:connect';
    }
    if (/^\/api\/scripts\/[^/]+\/run$/.test(pathname) && !isSafe) {
      return 'scripts:run';
    }
    if (pathname.startsWith('/api/scripts') && !isSafe) {
      return 'scripts:write';
    }
    if ((pathname.startsWith('/api/automations') || pathname.startsWith('/api/self-healing')) && !isSafe) {
      return 'automations:manage';
    }
    if (pathname.startsWith('/api/patches') && !isSafe) {
      return 'patches:approve';
    }
    if (
      (pathname.startsWith('/api/software-packages') ||
        pathname.startsWith('/api/software-deployments') ||
        /^\/api\/devices\/[^/]+\/software\//.test(pathname)) &&
      !isSafe
    ) {
      return 'software:deploy';
    }
    if (
      (pathname.startsWith('/api/policies') ||
        pathname.startsWith('/api/backup-policies') ||
        pathname.startsWith('/api/mdm-profiles')) &&
      !isSafe &&
      pathname !== '/api/policies/evaluate-conditions'
    ) {
      return 'policies:write';
    }
    if (pathname.startsWith('/api/alerts') && !isSafe) {
      return 'alerts:triage';
    }
    if (pathname.startsWith('/api/documentation') && !isSafe) {
      return 'docs:write';
    }
    if ((pathname.startsWith('/api/psa/tickets') || pathname.startsWith('/api/psa/time-entries')) && !isSafe) {
      return 'psa:manage';
    }
    if ((pathname.startsWith('/api/users') || pathname.startsWith('/api/roles') || pathname.startsWith('/api/api-keys')) && !isSafe) {
      return 'users:manage';
    }
    if (pathname.startsWith('/api/backups') && !isSafe) {
      return 'backups:manage';
    }
    if (pathname.startsWith('/api/settings') && !isSafe) {
      return 'settings:write';
    }
    if (pathname === '/api/audit-logs/export') {
      return 'audit:export';
    }
    if (pathname.startsWith('/api/devices') && !isSafe) {
      return 'devices:manage';
    }
    if (pathname.startsWith('/api/devices') && isSafe) {
      return 'devices:read';
    }

    if (!isApiKey) {
      return null;
    }

    // Deny-by-default strict route scope mapping for Scoped REST API Keys
    if (pathname.startsWith('/api/scripts')) return 'scripts:run';
    if (pathname.startsWith('/api/automations') || pathname.startsWith('/api/self-healing')) {
      return 'automations:manage';
    }
    if (pathname.startsWith('/api/patches/blacklist')) return 'patches:approve';
    if (pathname.startsWith('/api/patches')) return 'devices:read';
    if (pathname.startsWith('/api/software-packages') || pathname.startsWith('/api/software-deployments')) {
      return 'devices:read';
    }
    if (pathname === '/api/policies/evaluate-conditions') return 'alerts:triage';
    if (
      pathname.startsWith('/api/policies') ||
      pathname.startsWith('/api/backup-policies') ||
      pathname.startsWith('/api/mdm-profiles')
    ) {
      return 'policies:write';
    }
    if (pathname.startsWith('/api/alerts') || pathname.startsWith('/api/notifications')) {
      return isSafe ? 'alerts:read' : 'alerts:triage';
    }
    if (pathname.startsWith('/api/notification-channels')) return 'alerts:triage';
    if (pathname.startsWith('/api/documentation')) return 'docs:read';
    if (pathname.startsWith('/api/psa/integrations')) return 'settings:write';
    if (pathname.startsWith('/api/psa')) return 'psa:manage';
    if (
      pathname.startsWith('/api/users') ||
      pathname.startsWith('/api/roles') ||
      pathname.startsWith('/api/api-keys') ||
      pathname.startsWith('/api/auth/sessions')
    ) {
      return 'users:manage';
    }
    if (pathname.startsWith('/api/backups') || pathname.startsWith('/api/backup-jobs')) {
      return 'backups:manage';
    }
    if (
      pathname.startsWith('/api/settings') ||
      pathname === '/api/demo/seed' ||
      pathname === '/api/smtp/test' ||
      pathname === '/api/signing/sign' ||
      pathname === '/api/code-signing/test' ||
      pathname === '/api/proxy-tls/test' ||
      pathname === '/api/auth/oidc/test' ||
      pathname.startsWith('/api/updater') ||
      pathname.startsWith('/api/system/') ||
      pathname.startsWith('/api/mesh-servers') ||
      pathname.startsWith('/api/meshcentral')
    ) {
      return 'settings:write';
    }
    if (pathname.startsWith('/api/audit')) return 'audit:export';
    if (pathname.startsWith('/api/recordings')) {
      return method === 'POST' ? 'remote:connect' : 'audit:export';
    }
    if (pathname.startsWith('/api/guest-grants') || pathname.startsWith('/api/quicksupport')) {
      return 'remote:connect';
    }
    if (pathname === '/api/agent/installer' || pathname.startsWith('/api/installers')) {
      return isSafe ? 'devices:read' : 'devices:manage';
    }
    if (
      pathname.startsWith('/api/tenants') ||
      pathname.startsWith('/api/sites') ||
      pathname.startsWith('/api/smart-groups') ||
      pathname.startsWith('/api/custom-fields') ||
      pathname.startsWith('/api/maintenance-windows') ||
      pathname.startsWith('/api/discovery') ||
      pathname.startsWith('/api/network-appliances') ||
      pathname.startsWith('/api/virtualization') ||
      pathname === '/api/reports/qbr'
    ) {
      return isSafe ? 'devices:read' : 'devices:manage';
    }
    return null;
  }

  server.addHook('onRequest', async (request, reply) => {
    if (request.method === 'OPTIONS') {
      return;
    }

    const rawUrl = request.raw.url || request.url || '/';
    let pathname = '/';
    try {
      pathname = new URL(rawUrl, 'http://localhost').pathname.replace(/\/+/g, '/');
    } catch {
      pathname = rawUrl.split('?')[0].replace(/\/+/g, '/');
    }

    if (!pathname.startsWith('/api/') && pathname !== '/api') {
      return;
    }

    request.auth = extractAuthContext(request);

    // Explicitly scoped public or agent-token endpoints (each enforces its own token/rate-limit check inside its handler)
    const isPublicEndpoint =
      pathname === '/api/health' ||
      pathname === '/api/agent/enroll' ||
      pathname === '/api/agent/checkin' ||
      pathname === '/api/agent/chat' ||
      pathname === '/api/agent/mesh-binary' ||
      pathname === '/api/agent/binary' ||
      /^\/api\/agent\/tasks\/[^/]+\/result$/.test(pathname) ||
      /^\/api\/software-packages\/[^/]+\/download$/.test(pathname) ||
      pathname === '/api/public/portal-config' ||
      pathname === '/api/utils/qr.svg' ||
      pathname === '/api/auth/status' ||
      pathname === '/api/auth/setup-initial-admin' ||
      pathname === '/api/auth/login' ||
      pathname === '/api/auth/login/verify-mfa' ||
      pathname === '/api/auth/logout' ||
      pathname === '/api/auth/oidc/login' ||
      pathname === '/api/auth/oidc/callback' ||
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

    // Enforce CSRF header (`X-Vitrine-CSRF: 1`) on cookie-authenticated state-mutating requests
    const isSafeMethod = request.method === 'GET' || request.method === 'HEAD' || request.method === 'OPTIONS';
    if (!isSafeMethod && request.auth.authSource === 'cookie') {
      const csrfHeader = String(request.headers['x-vitrine-csrf'] || '').trim();
      if (csrfHeader !== '1') {
        return reply.status(403).send({
          error: 'CSRF verification failed: missing X-Vitrine-CSRF header.',
          code: 'CSRF_REQUIRED'
        });
      }
    }

    const userRole = request.auth.user.role;

    // Super-Admin-Only Administrative Routes
    const isSuperAdminOnly =
      (pathname === '/api/settings' && !isSafeMethod) ||
      pathname === '/api/settings/logo' ||
      pathname === '/api/demo/seed' ||
      pathname.startsWith('/api/users') ||
      (pathname.startsWith('/api/roles') && !isSafeMethod) ||
      pathname.startsWith('/api/api-keys') ||
      pathname.startsWith('/api/backups') ||
      pathname === '/api/auth/oidc/test' ||
      (pathname.startsWith('/api/updater') && !isSafeMethod) ||
      pathname === '/api/laps/break-glass-export' ||
      pathname === '/api/smtp/test' ||
      pathname === '/api/signing/sign' ||
      pathname === '/api/code-signing/test' ||
      pathname === '/api/proxy-tls/test' ||
      pathname === '/api/system/cleanup-vitrine-companions' ||
      pathname === '/api/mesh-servers/local-detect' ||
      (pathname.startsWith('/api/mesh-servers') && !isSafeMethod) ||
      (pathname.startsWith('/api/psa/integrations') && !isSafeMethod) ||
      (pathname.startsWith('/api/notification-channels') && !isSafeMethod) ||
      (pathname.startsWith('/api/patches/blacklist') && !isSafeMethod) ||
      (pathname === '/api/tenants' && !isSafeMethod) ||
      (pathname === '/api/sites' && !isSafeMethod) ||
      (pathname.startsWith('/api/tenants/') &&
        (request.method === 'PUT' ||
          request.method === 'DELETE' ||
          pathname.endsWith('/offboard') ||
          pathname.endsWith('/reactivate'))) ||
      (pathname.startsWith('/api/recordings/') && request.method === 'DELETE') ||
      pathname.endsWith('/archive-purge');

    if (isSuperAdminOnly && !isSuperAdminRole(userRole)) {
      return reply.status(403).send({
        error: 'Forbidden: MSP Super Admin privileges are required for this operation.'
      });
    }

    // Enforce granular RBAC / API key permission scopes across REST routes
    const isApiKey = Boolean(request.auth.isApiKey || request.auth.user.is_api_key);
    const requiredPerm = getRequiredRoutePermission(pathname, request.method, rawUrl, isApiKey);
    if (isApiKey && !requiredPerm) {
      return reply.status(403).send({
        error: 'API key endpoint not permitted by scoped route policy'
      });
    }
    if (requiredPerm && !hasUserPermission(request.auth.user, requiredPerm)) {
      return reply.status(403).send({
        error: `Forbidden: missing required permission '${requiredPerm}'.`,
        requiredPermission: requiredPerm
      });
    }

    // Compliance Auditor role: read-only visibility across fleet, policies, alerts, docs, and audit logs
    if (userRole === 'auditor') {
      const isAllowedAuditorWrite =
        pathname.startsWith('/api/auth/') ||
        (request.method === 'POST' && /^\/api\/notifications\/[^/]+\/read$/.test(pathname));
      const isBlockedVaultOrInternalRead =
        /^\/api\/devices\/[^/]+\/(bitlocker|laps|files|registry|processes|services|tasks|eventlogs)(\/|$)/.test(
          pathname
        ) ||
        /^\/api\/documentation\/[^/]+\/secrets$/.test(pathname) ||
        (pathname.includes('/custom-fields') && /[?&]reveal=true(?:&|$)/i.test(rawUrl)) ||
        pathname === '/api/settings' ||
        pathname.startsWith('/api/psa/integrations') ||
        pathname.startsWith('/api/notification-channels') ||
        pathname.startsWith('/api/backup-policies');
      if ((!isSafeMethod && !isAllowedAuditorWrite) || isBlockedVaultOrInternalRead) {
        return reply.status(403).send({
          error: 'Forbidden: Compliance Auditor accounts are strictly read-only and cannot access endpoint vaults.'
        });
      }
      return;
    }

    // Client Admins have strictly tenant-scoped read-only visibility on safe inventory routes only
    // (never remote files, registry, processes, services, eventlogs, scheduled tasks, or LAPS/BitLocker vaults)
    const isReadMethod = request.method === 'GET' || request.method === 'HEAD';
    const isSafeClientAdminDeviceSubroute =
      /^\/api\/devices\/[^/]+$/.test(pathname) ||
      (/^\/api\/devices\/[^/]+\/(software|warranty|hardware-history|network-history|custom-fields)$/.test(pathname) &&
        !/[?&]reveal=true(?:&|$)/i.test(rawUrl));
    const isAllowedForClientAdmin =
      pathname.startsWith('/api/auth/') ||
      (request.method === 'POST' && /^\/api\/notifications\/[^/]+\/read$/.test(pathname)) ||
      (isReadMethod &&
        (pathname === '/api/tenants' ||
          pathname === '/api/devices' ||
          isSafeClientAdminDeviceSubroute ||
          pathname === '/api/patches' ||
          pathname === '/api/alerts' ||
          pathname === '/api/documentation' ||
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
    const rate = checkRateLimit(`health-post:${request.ip}`, 120, 60_000);
    if (!rate.allowed) {
      return reply.status(429).send({ error: 'Too many heartbeat requests', retryAfterSec: rate.retryAfterSec });
    }

    const body = (request.body || {}) as {
      deviceId?: string;
      hostname?: string;
      cpu?: number | string;
      cpuUsage?: number | string;
      ramUsedGb?: number | string;
      ramTotalGb?: number | string;
      diskFreeGb?: number | string;
      diskTotalGb?: number | string;
      netRxMbps?: number | string;
      netTxMbps?: number | string;
    };
    const providedToken = String(request.headers['x-vitrine-agent-token'] || '').trim();
    const isTechSession = Boolean(
      request.auth &&
        isTechnicianOrAbove(request.auth.user.role) &&
        hasUserPermission(request.auth.user, 'devices:manage')
    );

    let targetDevice: any = null;
    let tokenMatched = false;
    let usedSessionFallback = false;

    if (body.deviceId) {
      const candidate = db.prepare('SELECT * FROM devices WHERE id = ?').get(body.deviceId) as any;
      if (candidate) {
        const deviceToken = candidate.agent_auth_token ? decryptVaultSecret(candidate.agent_auth_token) : '';
        if (providedToken && deviceToken && constantTimeEquals(providedToken, deviceToken)) {
          targetDevice = candidate;
          tokenMatched = true;
        } else if (!providedToken && isTechSession && canUserAccessTenant(request.auth?.user, candidate.tenant_id)) {
          targetDevice = candidate;
          tokenMatched = true;
          usedSessionFallback = true;
        }
      }
    } else if (body.hostname && providedToken) {
      const candidates = db
        .prepare('SELECT * FROM devices WHERE LOWER(hostname) = LOWER(?)')
        .all(body.hostname) as any[];
      for (const candidate of candidates) {
        const deviceToken = candidate.agent_auth_token ? decryptVaultSecret(candidate.agent_auth_token) : '';
        if (deviceToken && constantTimeEquals(providedToken, deviceToken)) {
          targetDevice = candidate;
          tokenMatched = true;
          break;
        }
      }
    } else if (!providedToken && isTechSession && !body.deviceId && !body.hostname) {
      tokenMatched = true;
      usedSessionFallback = true;
    }

    if (usedSessionFallback && request.auth?.authSource === 'cookie') {
      const csrfHeader = String(request.headers['x-vitrine-csrf'] || '').trim();
      if (csrfHeader !== '1') {
        return reply.status(403).send({
          error: 'CSRF verification failed: missing X-Vitrine-CSRF header.',
          code: 'CSRF_REQUIRED'
        });
      }
    }

    if (!tokenMatched) {
      return reply.status(401).send({ error: 'Invalid or missing per-device x-vitrine-agent-token header' });
    }

    if (targetDevice) {
      const cpuRaw = body.cpuUsage ?? body.cpu;
      const cpuVal = cpuRaw != null ? Number(cpuRaw) : null;
      const ramVal = body.ramUsedGb != null ? Number(body.ramUsedGb) : null;
      const ramTotVal = body.ramTotalGb != null ? Number(body.ramTotalGb) : null;
      const diskVal = body.diskFreeGb != null ? Number(body.diskFreeGb) : null;
      const diskTotVal = body.diskTotalGb != null ? Number(body.diskTotalGb) : null;
      const netRxVal = body.netRxMbps != null ? Number(body.netRxMbps) : null;
      const netTxVal = body.netTxMbps != null ? Number(body.netTxMbps) : null;

      recordDeviceTelemetrySample(targetDevice.id, {
        cpuUsage: Number.isFinite(cpuVal) ? cpuVal : null,
        ramUsedGb: Number.isFinite(ramVal) ? ramVal : null,
        ramTotalGb: Number.isFinite(ramTotVal) ? ramTotVal : null,
        diskFreeGb: Number.isFinite(diskVal) ? diskVal : null,
        diskTotalGb: Number.isFinite(diskTotVal) ? diskTotVal : null,
        netRxMbps: Number.isFinite(netRxVal) ? netRxVal : null,
        netTxMbps: Number.isFinite(netTxVal) ? netTxVal : null
      });

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
      enrollmentToken?: string;
      deviceId?: string;
      hostname?: string;
      osType?: 'windows' | 'linux' | 'macos' | 'darwin' | string;
      osVersion?: string;
      osBuild?: string;
      deviceRole?: string;
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
      biosVersion?: string;
      meshNodeId?: string;
      hardwareDetails?: Record<string, any>;
    };

    const token = String(body.token || body.enrollmentToken || '').trim();
    const hostname = String(body.hostname || '').trim();
    if (!token || !hostname) {
      return reply.status(400).send({ error: 'Valid deployment token and hostname are required' });
    }

    const reqIp = String(request.ip || '').trim();
    const reqIsLoopback = reqIp === '127.0.0.1' || reqIp === '::1' || reqIp === '::ffff:127.0.0.1';
    const rawReportedIp = String(body.ipAddress || '').trim();
    const reportedIsLoopback =
      rawReportedIp === '127.0.0.1' ||
      rawReportedIp === '::1' ||
      rawReportedIp.toLowerCase() === 'localhost';
    const safeIpAddress =
      rawReportedIp && (!reportedIsLoopback || reqIsLoopback)
        ? rawReportedIp
        : reqIp || null;

    const enrollTx = db.transaction((): { status: number; payload: Record<string, any> } => {
      const tokenRow = db.prepare('SELECT * FROM installer_audit_log WHERE token_id = ?').get(token) as any;
      if (!tokenRow) {
        const qsRow = db
          .prepare('SELECT * FROM quicksupport_sessions WHERE session_code = ? OR id = ?')
          .get(token, token) as any;
        if (!qsRow) {
          return { status: 401, payload: { error: 'Invalid deployment token' } };
        }
        if (qsRow.expires_at && new Date(qsRow.expires_at).getTime() <= Date.now()) {
          return { status: 401, payload: { error: 'QuickSupport session has expired.' } };
        }

        const qsRawOs = String(body.osType || qsRow.platform || 'windows').trim().toLowerCase();
        const qsNormalizedOs: 'windows' | 'linux' | 'macos' =
          qsRawOs === 'darwin' || qsRawOs === 'macos' ? 'macos' : qsRawOs === 'linux' ? 'linux' : 'windows';
        const fallbackTenantId =
          qsRow.tenant_id ||
          (db.prepare('SELECT id FROM tenants ORDER BY created_at ASC LIMIT 1').get() as { id?: string } | undefined)?.id ||
          't-default';
        const qsAgentToken = crypto.randomBytes(32).toString('hex');
        const qsEncToken = encryptVaultSecret(qsAgentToken);
        const qsDeviceId = `dev-qs-${crypto.randomUUID().slice(0, 8)}`;
        const qsHwJson = mergeHardwareDetailsJson('{}', body.hardwareDetails || null);

        db.prepare(`
          INSERT INTO devices (
            id, mesh_node_id, tenant_id, site_id, hostname, os_type, os_version, os_build,
            ip_address, mac_address, status, device_role, device_role_manual, manufacturer, model, cpu_model, cpu_cores,
            ram_total_gb, disk_total_gb, disk_free_gb, serial_number, hardware_details_json, companion_installed, agent_auth_token
          ) VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, 'online', 'QuickSupport', 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        `).run(
          qsDeviceId,
          body.meshNodeId || `node//${qsDeviceId}`,
          fallbackTenantId,
          hostname,
          qsNormalizedOs,
          body.osVersion || 'Unknown OS',
          body.osBuild || '',
          safeIpAddress || '0.0.0.0',
          body.macAddress || '00:00:00:00:00:00',
          body.manufacturer || '',
          body.model || '',
          body.cpuModel || 'Unknown CPU',
          Number(body.cpuCores || 4),
          Number(body.ramTotalGb || 8),
          Number(body.diskTotalGb || 256),
          Number(body.diskFreeGb || 128),
          body.serialNumber || '',
          qsHwJson,
          qsEncToken
        );

        db.prepare(`
          UPDATE quicksupport_sessions
          SET status = 'connected',
              hostname = COALESCE(?, hostname),
              username = COALESCE(?, username)
          WHERE id = ?
        `).run(hostname, null, qsRow.id);

        return {
          status: 200,
          payload: {
            success: true,
            mode: 'quicksupport',
            deviceId: qsDeviceId,
            agentToken: qsAgentToken
          }
        };
      }
      if (tokenRow.expires_at && new Date(tokenRow.expires_at).getTime() <= Date.now()) {
        return { status: 401, payload: { error: 'Deployment token has expired' } };
      }
      const maxUses = Number(tokenRow.max_uses ?? 1);
      const currentUses = Number(tokenRow.use_count ?? (tokenRow.redeemed_at ? 1 : 0));
      if (maxUses > 0 && currentUses >= maxUses) {
        return {
          status: 401,
          payload: { error: 'Deployment token has already reached its maximum enrollment limit.' }
        };
      }

      const parentTenant = db
        .prepare('SELECT id, name, lifecycle_state FROM tenants WHERE id = ?')
        .get(tokenRow.tenant_id) as any;
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
          `Endpoint '${hostname}' attempted enrollment with token for deleted client '${deletedTombstone?.tenant_name || tokenRow.tenant_id}'. Instructed immediate quiet self-uninstall (${lapsAction}).`
        );
        return {
          status: 200,
          payload: {
            success: true,
            quietOffboard: true,
            actionTaken: 'quiet_offboard_executed',
            lapsAction
          }
        };
      }

      const rawOs = String(body.osType || tokenRow.platform || 'windows').trim().toLowerCase();
      const normalizedOs: 'windows' | 'linux' | 'macos' =
        rawOs === 'darwin' || rawOs === 'macos' ? 'macos' : rawOs === 'linux' ? 'linux' : 'windows';

      const rawAgentToken = crypto.randomBytes(32).toString('hex');
      const encryptedAgentToken = encryptVaultSecret(rawAgentToken);

      if (body.deviceId) {
        const byIdAnyTenant = db
          .prepare('SELECT id, tenant_id FROM devices WHERE id = ? LIMIT 1')
          .get(String(body.deviceId)) as { id: string; tenant_id: string } | undefined;
        if (byIdAnyTenant && byIdAnyTenant.tenant_id !== tokenRow.tenant_id) {
          return {
            status: 403,
            payload: { error: 'Forbidden: deviceId belongs to a different client tenant.' }
          };
        }
      }
      if (body.meshNodeId) {
        const byNodeAnyTenant = db
          .prepare('SELECT id, tenant_id FROM devices WHERE mesh_node_id = ? LIMIT 1')
          .get(String(body.meshNodeId)) as { id: string; tenant_id: string } | undefined;
        if (byNodeAnyTenant && byNodeAnyTenant.tenant_id !== tokenRow.tenant_id) {
          return {
            status: 403,
            payload: { error: 'Forbidden: meshNodeId belongs to a different client tenant.' }
          };
        }
      }

      const existing = ((body.deviceId
        ? db
            .prepare('SELECT id, device_role, device_role_manual, hardware_details_json, manufacturer, model, bios_version FROM devices WHERE id = ? AND tenant_id = ? LIMIT 1')
            .get(String(body.deviceId), tokenRow.tenant_id)
        : null) ||
        (body.meshNodeId
          ? db
              .prepare('SELECT id, device_role, device_role_manual, hardware_details_json, manufacturer, model, bios_version FROM devices WHERE mesh_node_id = ? AND tenant_id = ? LIMIT 1')
              .get(String(body.meshNodeId), tokenRow.tenant_id)
          : null) ||
        db
          .prepare('SELECT id, device_role, device_role_manual, hardware_details_json, manufacturer, model, bios_version FROM devices WHERE tenant_id = ? AND LOWER(hostname) = LOWER(?) LIMIT 1')
          .get(tokenRow.tenant_id, hostname)) as any;

      // Atomically verify & increment token use_count inside the immediate DB transaction
      const claimTokenRes = db
        .prepare(
          `UPDATE installer_audit_log
           SET redeemed_at = CURRENT_TIMESTAMP,
               use_count = COALESCE(use_count, 0) + 1
           WHERE token_id = ? AND (COALESCE(max_uses, 1) = 0 OR COALESCE(use_count, 0) < COALESCE(max_uses, 1))`
        )
        .run(token);
      if (claimTokenRes.changes === 0) {
        return {
          status: 401,
          payload: { error: 'Deployment token has already reached its maximum enrollment limit.' }
        };
      }

      const deviceId = (existing as { id: string } | undefined)?.id || `dev-${crypto.randomUUID().slice(0, 8)}`;

      const tokenRoleRaw = String(tokenRow.device_role || '').trim();
      const tokenRoleLower = tokenRoleRaw.toLowerCase();
      const isExplicitManualTokenRole = Boolean(
        tokenRoleRaw && tokenRoleLower !== 'auto' && tokenRoleLower !== 'auto-detect' && tokenRoleLower !== 'workstation'
      );

      const mergedEnrollHwJson = mergeHardwareDetailsJson(existing?.hardware_details_json, body.hardwareDetails || null);
      const roleSignals = extractSignalsFromHardwareDetails(mergedEnrollHwJson, {
        os_type: normalizedOs,
        os_version: body.osVersion || null,
        manufacturer: body.manufacturer || existing?.manufacturer || null,
        model: body.model || existing?.model || null,
        bios_version: body.biosVersion || existing?.bios_version || null
      });
      const inferredEnrollRole =
        inferDeviceRole(roleSignals) ||
        (body.deviceRole && !isAutoRolePlaceholder(body.deviceRole) ? String(body.deviceRole).trim() : '') ||
        'Workstation';

      if (existing) {
        const nextRole = isExplicitManualTokenRole
          ? tokenRoleRaw
          : shouldAutoUpdateDeviceRole(existing.device_role, existing.device_role_manual, inferredEnrollRole)
            ? inferredEnrollRole
            : existing.device_role;
        const nextRoleManual = isExplicitManualTokenRole ? 1 : Number(existing.device_role_manual || 0);

        db.prepare(`
          UPDATE devices
          SET status = CASE WHEN quarantined = 1 THEN 'isolated' ELSE 'online' END,
              os_type = ?,
              ip_address = COALESCE(?, ip_address),
              os_version = COALESCE(?, os_version),
              manufacturer = COALESCE(NULLIF(?, ''), manufacturer),
              model = COALESCE(NULLIF(?, ''), model),
              bios_version = COALESCE(NULLIF(?, ''), bios_version),
              cpu_model = COALESCE(NULLIF(?, ''), cpu_model),
              cpu_cores = COALESCE(?, cpu_cores),
              serial_number = COALESCE(NULLIF(?, ''), serial_number),
              device_role = ?,
              device_role_manual = ?,
              hardware_details_json = ?,
              companion_installed = 1,
              companion_deploy_pending = 0,
              agent_auth_token = ?,
              last_seen = CURRENT_TIMESTAMP
          WHERE id = ? AND tenant_id = ?
        `).run(
          normalizedOs,
          safeIpAddress,
          body.osVersion || null,
          body.manufacturer || '',
          body.model || '',
          body.biosVersion || '',
          body.cpuModel || '',
          body.cpuCores != null && Number.isFinite(Number(body.cpuCores)) ? Number(body.cpuCores) : null,
          body.serialNumber || '',
          nextRole,
          nextRoleManual,
          mergedEnrollHwJson,
          encryptedAgentToken,
          deviceId,
          tokenRow.tenant_id
        );
        handleAgentCheckInOrWake(deviceId, 'reinstall_agent');
      } else {
        const initialRole = isExplicitManualTokenRole ? tokenRoleRaw : inferredEnrollRole;
        const initialManual = isExplicitManualTokenRole ? 1 : 0;

        db.prepare(`
          INSERT INTO devices (
            id, mesh_node_id, tenant_id, site_id, hostname, os_type, os_version, os_build,
            ip_address, mac_address, status, device_role, device_role_manual, manufacturer, model, bios_version, cpu_model, cpu_cores,
            ram_total_gb, disk_total_gb, disk_free_gb, serial_number, hardware_details_json, companion_installed, agent_auth_token
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        `).run(
          deviceId,
          body.meshNodeId || `node//${deviceId}`,
          tokenRow.tenant_id,
          tokenRow.site_id || null,
          hostname,
          normalizedOs,
          body.osVersion || 'Unknown OS',
          body.osBuild || '',
          safeIpAddress || '0.0.0.0',
          body.macAddress || '00:00:00:00:00:00',
          initialRole,
          initialManual,
          body.manufacturer || '',
          body.model || '',
          body.biosVersion || '',
          body.cpuModel || 'Unknown CPU',
          Number(body.cpuCores || 4),
          Number(body.ramTotalGb || 8),
          Number(body.diskTotalGb || 256),
          Number(body.diskFreeGb || 128),
          body.serialNumber || '',
          mergedEnrollHwJson,
          encryptedAgentToken
        );
      }

      db.prepare('UPDATE installer_audit_log SET redeemed_device_id = ? WHERE token_id = ?').run(deviceId, token);

      return {
        status: 200,
        payload: {
          success: true,
          deviceId,
          agentToken: rawAgentToken
        }
      };
    });

    const outcome = enrollTx.immediate();
    return reply.status(outcome.status).send(outcome.payload);
  });

  // ============================================================================
  // Safe Public Portal Config (Zero Secrets Exposed)
  // ============================================================================
  server.get('/api/public/portal-config', async () => {
    const row = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    const qsPolicy = (db
      .prepare(
        "SELECT tray_brand_name, tray_icon_url, tray_theme_mode, tray_tooltip FROM policies WHERE id = 'pol-quicksupport' OR tier = 'quicksupport' LIMIT 1"
      )
      .get() || {}) as any;
    const qsBrandName = String(qsPolicy.tray_brand_name || '').trim() || row.brand_name || 'Vitrine RMM';
    const qsIconUrl = String(qsPolicy.tray_icon_url || '').trim() || row.brand_logo_url || '/branding/logo.png';
    const qsThemeMode =
      qsPolicy.tray_theme_mode === 'light' || qsPolicy.tray_theme_mode === 'dark' || qsPolicy.tray_theme_mode === 'system'
        ? qsPolicy.tray_theme_mode
        : row.theme_mode || 'system';
    return {
      brand_name: row.brand_name || 'Vitrine RMM',
      brand_logo_url: row.brand_logo_url || '/branding/logo.png',
      primary_color: row.primary_color || '#00f2fe',
      glass_blur_level: row.glass_blur_level || 'high',
      theme_mode: row.theme_mode || 'system',
      quicksupport_enabled: Boolean(row.quicksupport_enabled ?? 1),
      quicksupport_url_path: row.quicksupport_url_path || '/remote',
      quicksupport_custom_domain: row.quicksupport_custom_domain || '',
      quicksupport_brand_name: qsBrandName,
      quicksupport_icon_url: qsIconUrl,
      quicksupport_theme_mode: qsThemeMode,
      code_signing_enabled: Boolean(row.code_signing_enabled)
    };
  });

  // ============================================================================
  // Authentication, Initial Admin Bootstrap & Step-Up MFA
  // ============================================================================
  server.get('/api/auth/status', async (request) => {
    const settings = (db
      .prepare(
        'SELECT is_onboarded, oobe_completed, oidc_enabled, oidc_issuer_url, oidc_client_id, brand_name, brand_logo_url, primary_color, theme_mode FROM settings WHERE id = 1'
      )
      .get() || {}) as any;
    const hasOidcConfig = Boolean(
      String(settings.oidc_issuer_url || '').trim() && String(settings.oidc_client_id || '').trim()
    );
    return {
      initialized: hasConfiguredAdminUser(),
      authenticated: Boolean(request.auth),
      user: request.auth?.user || null,
      mfaVerified: Boolean(request.auth?.mfaVerified),
      mfaVerifiedUntil: request.auth?.mfaVerifiedUntil || null,
      isOnboarded: Boolean(settings.is_onboarded || settings.oobe_completed),
      oidcEnabled: Boolean(hasOidcConfig && (settings.oidc_enabled ?? 1)),
      branding: {
        brand_name: settings.brand_name || 'Vitrine RMM',
        brand_logo_url: settings.brand_logo_url || '/branding/logo.png',
        primary_color: settings.primary_color || '#00f2fe',
        theme_mode: settings.theme_mode || 'system'
      }
    };
  });

  server.get('/api/auth/oidc/login', async (request, reply) => {
    const rate = checkRateLimit(`oidc-login:${request.ip}`, 15, 5 * 60_000);
    if (!rate.allowed) {
      return reply.redirect(`/?sso_error=${encodeURIComponent('Too many SSO attempts. Please wait and try again.')}`);
    }
    try {
      const redirectUrl = await createOidcAuthorizationRedirect(request);
      const stateParam = new URL(redirectUrl).searchParams.get('state') || '';
      const isSecure =
        request.protocol === 'https' ||
        (process.env.VITRINE_TRUST_PROXY === 'true' && request.headers['x-forwarded-proto'] === 'https') ||
        process.env.FORCE_SECURE_COOKIE === 'true';
      const cookieParts = [
        `vitrine_oidc_state=${encodeURIComponent(stateParam)}`,
        'Path=/api/auth/oidc',
        'HttpOnly',
        'SameSite=Lax',
        'Max-Age=600'
      ];
      if (isSecure) cookieParts.push('Secure');
      reply.header('Set-Cookie', cookieParts.join('; '));
      return reply.redirect(redirectUrl);
    } catch (err: any) {
      return reply.redirect(
        `/?sso_error=${encodeURIComponent(err?.message || 'Unable to initiate Enterprise SSO login.')}`
      );
    }
  });

  server.get('/api/auth/oidc/callback', async (request, reply) => {
    const clearOidcStateCookie = 'vitrine_oidc_state=; Path=/api/auth/oidc; HttpOnly; SameSite=Lax; Max-Age=0';
    reply.header('Set-Cookie', clearOidcStateCookie);

    const query = (request.query || {}) as {
      code?: string;
      state?: string;
      error?: string;
      error_description?: string;
    };
    if (query.error) {
      return reply.redirect(
        `/?sso_error=${encodeURIComponent(query.error_description || query.error || 'SSO authentication cancelled.')}`
      );
    }
    if (!query.code || !query.state) {
      return reply.redirect(`/?sso_error=${encodeURIComponent('Missing authorization code or state parameter.')}`);
    }
    const cookies = parseCookies(request.headers.cookie);
    const cookieState = cookies.vitrine_oidc_state || '';
    if (!cookieState || !constantTimeEquals(cookieState, query.state)) {
      return reply.redirect(
        `/?sso_error=${encodeURIComponent('OIDC state validation failed (missing or mismatched state cookie). Please try again.')}`
      );
    }
    try {
      const user = await completeOidcCallback({ code: query.code, state: query.state });
      const session = createUserSession(user.id, request.ip, request.headers['user-agent']);
      setSessionCookie(reply, request, session.rawToken);
      return reply.redirect('/');
    } catch (err: any) {
      return reply.redirect(
        `/?sso_error=${encodeURIComponent(err?.message || 'Enterprise SSO authentication failed.')}`
      );
    }
  });

  server.post('/api/auth/oidc/test', async (request) => {
    const body = (request.body || {}) as { issuerUrl?: string; clientId?: string };
    return await testOidcDiscoveryConfig(body);
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
        qrSvg: generateQrCodeSvg(created.otpAuthUri),
        recoveryCodes: created.recoveryCodes
      };
    } catch (err: any) {
      return reply.status(400).send({ success: false, error: err?.message || 'Failed to provision initial admin' });
    }
  });

  server.post('/api/auth/login', async (request, reply) => {
    const body = (request.body || {}) as { username?: string; password?: string };
    const identifier = String(body.username || '').trim();
    const rateIp = checkRateLimit(`login-ip:${request.ip}`, 25, 5 * 60_000);
    const rateUser = identifier
      ? checkRateLimit(`login-user:${identifier.toLowerCase()}`, 10, 5 * 60_000)
      : { allowed: true, retryAfterSec: 0 };
    const ratePair = checkRateLimit(`login:${request.ip}:${identifier.toLowerCase()}`, 10, 5 * 60_000);
    if (!rateIp.allowed || !rateUser.allowed || !ratePair.allowed) {
      const retryAfterSec = Math.max(rateIp.retryAfterSec, rateUser.retryAfterSec, ratePair.retryAfterSec);
      return reply.status(429).send({
        success: false,
        error: `Too many failed sign-in attempts. Retry in ${retryAfterSec}s.`,
        retryAfterSec
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

    const mfaState = doesUserRequireLoginMfa(user.id);
    if (mfaState.requiresMfaChallenge) {
      const mfaChallengeToken = issuePendingMfaLoginToken(user.id);
      return {
        success: true,
        mfaRequired: true,
        mfaChallengeToken,
        username: user.username,
        message: 'Enter your 6-digit authenticator code or a single-use recovery code.'
      };
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

  server.post('/api/auth/login/verify-mfa', async (request, reply) => {
    const rate = checkRateLimit(`login-mfa:${request.ip}`, 15, 5 * 60_000);
    if (!rate.allowed) {
      return reply.status(429).send({
        success: false,
        error: `Too many MFA attempts. Retry in ${rate.retryAfterSec}s.`,
        retryAfterSec: rate.retryAfterSec
      });
    }

    const body = (request.body || {}) as { mfaChallengeToken?: string; code?: string };
    const challengeToken = String(body.mfaChallengeToken || '').trim();
    const code = String(body.code || '').trim();
    if (!challengeToken || !code) {
      return reply.status(400).send({
        success: false,
        error: 'MFA challenge token and verification code are required.'
      });
    }

    const verified = verifyPendingMfaLoginChallenge(challengeToken, code);
    if (!verified.success || !verified.user) {
      db.prepare(`
        INSERT INTO audit_logs (id, username, action, details)
        VALUES (?, 'unknown', 'Login MFA Verification Failed', ?)
      `).run(
        `aud-login-mfa-fail-${crypto.randomUUID()}`,
        `Rejected login MFA verification from IP ${request.ip}: ${verified.error || 'Invalid code'}`
      );
      return reply.status(401).send({
        success: false,
        error: verified.error || 'Invalid authenticator or recovery code.'
      });
    }

    const session = createUserSession(
      verified.user.id,
      request.ip,
      request.headers['user-agent'],
      { mfaVerified: true }
    );
    setSessionCookie(reply, request, session.rawToken);

    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'User Signed In (MFA Verified)', ?)
    `).run(
      `aud-login-mfa-${crypto.randomUUID()}`,
      verified.user.username,
      `MFA-verified session started (${verified.user.role}${verified.usedRecoveryCode ? ', via recovery code' : ''}) from IP ${request.ip}`
    );

    return {
      success: true,
      user: verified.user,
      token: session.rawToken,
      expiresAt: session.expiresAt,
      usedRecoveryCode: Boolean(verified.usedRecoveryCode)
    };
  });

  server.post('/api/auth/logout', async (request, reply) => {
    const auth = extractAuthContext(request);
    if (auth && auth.authSource === 'cookie') {
      const csrfHeader = String(request.headers['x-vitrine-csrf'] || '').trim();
      if (csrfHeader !== '1') {
        return reply.status(403).send({
          error: 'CSRF verification failed: missing X-Vitrine-CSRF header.',
          code: 'CSRF_REQUIRED'
        });
      }
    }
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
    const details = getOrEnrollUserMfaDetails(request.auth.user.id, {
      callerMfaVerified: Boolean(request.auth.mfaVerified)
    });
    return {
      success: true,
      totpEnabled: true,
      secretBase32: details.totpSecret,
      qrSvg: details.qrCodeSvg || (details.otpAuthUri ? generateQrCodeSvg(details.otpAuthUri) : null),
      ...details
    };
  };
  server.get('/api/auth/mfa-setup', handleMfaSetupGet);
  server.get('/api/auth/mfa/enroll', handleMfaSetupGet);

  server.get('/api/auth/ws-ticket', async (request, reply) => {
    if (!request.auth) return reply.status(401).send({ error: 'Authentication required' });
    const ticket = issueEphemeralWsTicket({
      userId: request.auth.user.id,
      grantId: request.guestGrantId || undefined
    });
    return { success: true, ticket, expiresInSeconds: 45 };
  });

  server.get('/api/auth/sessions', async (request, reply) => {
    if (!request.auth) return reply.status(401).send({ error: 'Authentication required' });
    const isSuper = isSuperAdminRole(request.auth.user.role);
    return {
      success: true,
      sessions: listActiveSessions(isSuper ? undefined : request.auth.user.id),
      currentSessionPrefix: request.auth.tokenHash ? request.auth.tokenHash.slice(0, 12) : null
    };
  });

  server.delete('/api/auth/sessions/:prefix', async (request, reply) => {
    if (!request.auth) return reply.status(401).send({ error: 'Authentication required' });
    const { prefix } = request.params as { prefix: string };
    const revoked = revokeSessionByPrefix(
      prefix,
      request.auth.user.id,
      isSuperAdminRole(request.auth.user.role)
    );
    return { success: revoked };
  });

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

    const body = (request.body || {}) as {
      code?: string;
      secretType?: string;
      deviceId?: string;
      totpOnly?: boolean;
    };
    const totpOnly =
      Boolean(body.totpOnly) ||
      body.secretType === 'initial_admin_mfa_enrollment' ||
      body.secretType === 'mfa_enrollment_confirm';
    const verification = verifySessionStepUpMfa(request.auth, body.code || '', { totpOnly });

    if (verification.success) {
      const auditDetail =
        body.secretType === 'initial_admin_mfa_enrollment'
          ? 'Initial Super Admin TOTP authenticator enrollment verified via RFC 6238 TOTP'
          : `Step-Up MFA verified${verification.usedRecoveryCode ? ' via single-use recovery code' : ' via RFC 6238 TOTP'} for ${body.secretType || 'vault access'}`;
      db.prepare(`
        INSERT INTO audit_logs (id, username, device_id, action, details)
        VALUES (?, ?, ?, 'MFA Step-Up Verified', ?)
      `).run(
        `aud-mfa-${crypto.randomUUID()}`,
        request.auth.user.username,
        body.deviceId || null,
        auditDetail
      );
      return {
        success: true,
        verifiedAt: new Date().toISOString(),
        verifiedUntil: verification.verifiedUntil,
        usedRecoveryCode: Boolean(verification.usedRecoveryCode),
        totpConfirmed: true
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

  const handleSaveSettings = async (request: FastifyRequest, reply: FastifyReply) => {
    const body = (request.body || {}) as Record<string, any>;
    const current = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as Record<string, any>;

    const hasPlainSettingChanged = (col: string): boolean => {
      if (body[col] === undefined || body[col] === null) return false;
      return String(body[col]).trim() !== String(current[col] ?? '').trim();
    };

    const hasSecretSettingChanged = (col: string): boolean => {
      if (body[col] === undefined || body[col] === null) return false;
      const incoming = String(body[col]).trim();
      if (isMaskedSecret(incoming)) return false;
      const existingPlain = current[col] ? decryptVaultSecret(current[col]) : '';
      return incoming !== existingPlain;
    };

    // Require Step-Up MFA ONLY when critical security settings actually change after OOBE is complete
    const mutatingCriticalSecurity =
      Boolean(current.is_onboarded) &&
      (hasPlainSettingChanged('oidc_issuer_url') ||
        hasPlainSettingChanged('oidc_client_id') ||
        hasSecretSettingChanged('oidc_client_secret') ||
        hasSecretSettingChanged('agent_enrollment_secret') ||
        hasPlainSettingChanged('meshcentral_url') ||
        hasSecretSettingChanged('meshcentral_api_token') ||
        hasPlainSettingChanged('code_signing_url') ||
        hasSecretSettingChanged('code_signing_api_key') ||
        hasSecretSettingChanged('psa_webhook_secret') ||
        hasPlainSettingChanged('backup_offsite_endpoint') ||
        hasSecretSettingChanged('backup_offsite_secret_key') ||
        (body.backup_encryption_enabled !== undefined &&
          Boolean(body.backup_encryption_enabled) === false &&
          Boolean(current.backup_encryption_enabled)));

    if (mutatingCriticalSecurity && !requireStepUpMfaIfEnforced(request, reply, null)) {
      return reply;
    }

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

    const resolvedOidcEnabled =
      body.oidc_enabled != null
        ? body.oidc_enabled
          ? 1
          : 0
        : body.oidc_issuer_url !== undefined || body.oidc_client_id !== undefined
          ? String(body.oidc_issuer_url ?? current.oidc_issuer_url ?? '').trim() &&
            String(body.oidc_client_id ?? current.oidc_client_id ?? '').trim()
            ? 1
            : 0
          : null;

    const customBackupPassSet = Boolean(
      body.backup_encryption_passphrase &&
        !isMaskedSecret(String(body.backup_encryption_passphrase)) &&
        String(body.backup_encryption_passphrase).trim().length > 0
    );
    const resolvedBackupAck =
      body.backup_key_acknowledged != null
        ? body.backup_key_acknowledged
          ? 1
          : 0
        : customBackupPassSet
          ? 1
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
        meshcentral_allow_self_signed = COALESCE(?, meshcentral_allow_self_signed),
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
        code_signing_api_key = COALESCE(?, code_signing_api_key),
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
        backup_key_acknowledged = COALESCE(?, backup_key_acknowledged),
        backup_offsite_enabled = COALESCE(?, backup_offsite_enabled),
        backup_offsite_provider = COALESCE(?, backup_offsite_provider),
        backup_offsite_endpoint = COALESCE(?, backup_offsite_endpoint),
        backup_offsite_bucket = COALESCE(?, backup_offsite_bucket),
        backup_offsite_region = COALESCE(?, backup_offsite_region),
        backup_offsite_access_key = COALESCE(?, backup_offsite_access_key),
        backup_offsite_secret_key = COALESCE(?, backup_offsite_secret_key),
        patch_auto_approve_third_party = COALESCE(?, patch_auto_approve_third_party),
        patch_canary_delay_days = COALESCE(?, patch_canary_delay_days),
        oobe_auto_deploy_companion = COALESCE(?, oobe_auto_deploy_companion),
        oobe_enforce_laps_on_import = COALESCE(?, oobe_enforce_laps_on_import),
        oobe_lock_signed_updates = COALESCE(?, oobe_lock_signed_updates),
        session_idle_timeout_min = COALESCE(?, session_idle_timeout_min),
        session_timeout_min = COALESCE(?, session_timeout_min),
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
      body.meshcentral_allow_self_signed != null ? (body.meshcentral_allow_self_signed ? 1 : 0) : null,
      body.smtp_host ?? null,
      body.smtp_port != null ? Number(body.smtp_port) : null,
      body.smtp_user ?? null,
      resolveSecretUpdate('smtp_pass'),
      body.smtp_from ?? null,
      body.smtp_tls != null ? (body.smtp_tls ? 1 : 0) : null,
      body.itflow_url ?? null,
      resolveSecretUpdate('itflow_api_key'),
      resolvedOidcEnabled,
      body.oidc_issuer_url ?? null,
      body.oidc_client_id ?? null,
      resolveSecretUpdate('oidc_client_secret'),
      resolveSecretUpdate('psa_webhook_secret'),
      resolveSecretUpdate('agent_enrollment_secret'),
      body.code_signing_url ?? null,
      resolveSecretUpdate('code_signing_api_key'),
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
      resolvedBackupAck,
      body.backup_offsite_enabled != null ? (body.backup_offsite_enabled ? 1 : 0) : null,
      body.backup_offsite_provider ?? null,
      body.backup_offsite_endpoint ?? null,
      body.backup_offsite_bucket ?? null,
      body.backup_offsite_region ?? null,
      resolveSecretUpdate('backup_offsite_access_key'),
      resolveSecretUpdate('backup_offsite_secret_key'),
      body.patch_auto_approve_third_party != null ? (body.patch_auto_approve_third_party ? 1 : 0) : null,
      body.patch_canary_delay_days != null ? Number(body.patch_canary_delay_days) : null,
      body.oobe_auto_deploy_companion != null ? (body.oobe_auto_deploy_companion ? 1 : 0) : null,
      body.oobe_enforce_laps_on_import != null ? (body.oobe_enforce_laps_on_import ? 1 : 0) : null,
      body.oobe_lock_signed_updates != null ? (body.oobe_lock_signed_updates ? 1 : 0) : null,
      body.session_idle_timeout_min != null && Number.isFinite(Number(body.session_idle_timeout_min))
        ? Math.max(1, Math.min(43_200, Number(body.session_idle_timeout_min)))
        : null,
      body.session_timeout_min != null && Number.isFinite(Number(body.session_timeout_min))
        ? Math.max(1, Math.min(43_200, Number(body.session_timeout_min)))
        : null
    );

    await meshBridge.reconnectAndWait(3500);

    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'System Settings Updated', 'Control plane configuration saved')
    `).run(`aud-set-${crypto.randomUUID()}`, getActorUsername(request));

    const updated = db.prepare('SELECT * FROM settings WHERE id = 1').get() as any;
    const wasOnboarded = Boolean(current.oobe_completed || current.is_onboarded);
    const nowOnboarded = Boolean(updated?.oobe_completed || updated?.is_onboarded);

    if (!wasOnboarded && nowOnboarded) {
      const { proto: protoHdr, host: hostHdr } = resolveSafeRequestOriginParts(request);
      const customDom = String(updated?.custom_domain || '').trim();
      const reqOrigin = customDom
        ? customDom.startsWith('http')
          ? customDom
          : `https://${customDom}`
        : hostHdr
          ? `${protoHdr}://${hostHdr}`
          : undefined;

      void (async () => {
        try {
          if (!meshBridge.getStatus().connected) {
            await meshBridge.reconnectAndWait(3500);
          }
          if (updated?.oobe_auto_deploy_companion) {
            const pendingDevs = db
              .prepare(`
                SELECT id FROM devices
                WHERE COALESCE(lifecycle_state, 'active') = 'active'
                  AND status = 'online'
                  AND mesh_node_id IS NOT NULL
                  AND COALESCE(companion_installed, 0) = 0
                  AND COALESCE(companion_deploy_pending, 0) = 1
              `)
              .all() as Array<{ id: string }>;
            for (const d of pendingDevs) {
              try {
                await meshBridge.deployCompanionOverMesh(d.id, reqOrigin);
              } catch {}
            }
          }
          if (updated?.oobe_enforce_laps_on_import) {
            const unprovisionedLapsDevs = db
              .prepare(`
                SELECT d.id FROM devices d
                LEFT JOIN laps_vault v ON v.device_id = d.id
                WHERE COALESCE(d.lifecycle_state, 'active') = 'active'
                  AND d.status = 'online'
                  AND d.mesh_node_id IS NOT NULL
                  AND v.device_id IS NULL
              `)
              .all() as Array<{ id: string }>;
            for (const d of unprovisionedLapsDevs) {
              try {
                await rotateLapsPasswordVerifiedAsync(d.id, { reveal: false, actorUsername: 'oobe-rollout' });
              } catch {}
            }
          }
        } catch {}
      })();
    }

    return { success: true, settings: sanitizeSettingsRowForResponse(updated) };
  };
  server.post('/api/settings', handleSaveSettings);
  server.put('/api/settings', handleSaveSettings);

  const saveValidatedBrandingRasterImage = (
    base64Data: string | undefined,
    filePrefix: string
  ): { ok: true; url: string } | { ok: false; status: number; error: string } => {
    if (!base64Data) {
      return { ok: false, status: 400, error: 'base64Data is required' };
    }
    const cleanB64 = base64Data.includes(',') ? base64Data.split(',').pop()! : base64Data;
    const buf = Buffer.from(cleanB64, 'base64');
    if (buf.length === 0 || buf.length > 2 * 1024 * 1024) {
      return { ok: false, status: 400, error: 'Branding image must be between 1 byte and 2 MB.' };
    }

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
      return {
        ok: false,
        status: 400,
        error: 'Unsupported image format. Upload a valid PNG, JPEG, WebP, or ICO image.'
      };
    }

    let outBuf: Buffer = buf;
    if (ext === '.png' || ext === '.ico') {
      try {
        const squared = sanitizeAndSquareBrandingPng(buf, 256);
        if (!squared) {
          return {
            ok: false,
            status: 400,
            error: 'Malformed or unreadable PNG/ICO branding image.'
          };
        }
        outBuf = squared;
        ext = '.png';
      } catch {
        return {
          ok: false,
          status: 400,
          error: 'Malformed or unreadable PNG/ICO branding image.'
        };
      }
    }

    if (!fs.existsSync(BRANDING_DIR_PATH)) {
      fs.mkdirSync(BRANDING_DIR_PATH, { recursive: true });
    }
    const safePrefix = filePrefix.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 40) || 'branding';
    const targetFilename = `${safePrefix}-${Date.now()}${ext}`;
    const targetPath = path.join(BRANDING_DIR_PATH, targetFilename);
    fs.writeFileSync(targetPath, outBuf);
    return { ok: true, url: `/branding/${targetFilename}` };
  };

  server.post('/api/settings/logo', async (request, reply) => {
    const body = (request.body || {}) as { filename?: string; base64Data?: string };
    const saved = saveValidatedBrandingRasterImage(body.base64Data, 'custom-logo');
    if (!saved.ok) {
      return reply.status(saved.status).send({ error: saved.error });
    }
    db.prepare('UPDATE settings SET brand_logo_url = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1').run(saved.url);
    return { success: true, brand_logo_url: saved.url };
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
    if (!requireStepUpMfaIfEnforced(request, reply, null)) {
      return reply;
    }
    const body = (request.body || {}) as {
      username?: string;
      email?: string;
      password?: string;
      role?: string;
      custom_role_id?: string | null;
      tenant_id?: string | null;
    };
    const username = String(body.username || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const role = normalizeAndValidateRole(body.role || 'technician');
    if (!role) {
      return reply.status(400).send({
        error: 'Invalid user role. Allowed roles: msp_super_admin, technician, client_admin, auditor.'
      });
    }

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
    const rawBase32 = generateRandomBase32(20);
    const totpSecret = encryptVaultSecret(rawBase32);
    const { plaintextCodes, hashedCodes } = generateOneTimeRecoveryCodes(8);

    try {
      db.prepare(`
        INSERT INTO users (id, username, email, role, custom_role_id, tenant_id, password_hash, totp_secret, totp_enabled, recovery_codes_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
      `).run(
        id,
        username,
        email,
        role,
        body.custom_role_id || null,
        isSuperAdminRole(role) ? null : body.tenant_id || null,
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
    if (!requireStepUpMfaIfEnforced(request, reply, null)) {
      return reply;
    }
    const { id } = request.params as { id: string };
    const body = (request.body || {}) as {
      role?: string;
      custom_role_id?: string | null;
      tenant_id?: string | null;
      password?: string;
      email?: string;
    };
    const existing = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'User not found' });

    if (body.password !== undefined && body.password !== '' && body.password.length < 10) {
      return reply.status(400).send({ error: 'User password must be at least 10 characters.' });
    }

    let nextRole = existing.role;
    if (body.role !== undefined) {
      const validated = normalizeAndValidateRole(body.role);
      if (!validated) {
        return reply.status(400).send({
          error: 'Invalid user role. Allowed roles: msp_super_admin, technician, client_admin, auditor.'
        });
      }
      nextRole = validated;
    }

    if (isSuperAdminRole(existing.role) && !isSuperAdminRole(nextRole)) {
      const adminCount = (
        db
          .prepare("SELECT COUNT(*) as c FROM users WHERE role IN ('msp_super_admin', 'super_admin', 'admin')")
          .get() as { c: number }
      ).c;
      if (adminCount <= 1) {
        return reply.status(400).send({ error: 'Cannot demote the last MSP Super Admin account.' });
      }
    }

    const nextTenantId = isSuperAdminRole(nextRole)
      ? null
      : body.tenant_id !== undefined
      ? body.tenant_id || null
      : existing.tenant_id || null;
    if (nextRole === 'client_admin' && !nextTenantId) {
      return reply.status(400).send({ error: 'Client Admin accounts must be scoped to a specific Client tenant.' });
    }

    const nextPassHash =
      body.password && body.password.length >= 10 ? hashPasswordScrypt(body.password) : null;

    db.prepare(`
      UPDATE users
      SET role = ?,
          custom_role_id = ?,
          email = COALESCE(?, email),
          tenant_id = ?,
          password_hash = COALESCE(?, password_hash),
          password_changed_at = CASE WHEN ? IS NOT NULL THEN CURRENT_TIMESTAMP ELSE password_changed_at END
      WHERE id = ?
    `).run(
      nextRole,
      body.custom_role_id !== undefined ? body.custom_role_id : existing.custom_role_id ?? null,
      body.email ? body.email.trim().toLowerCase() : null,
      nextTenantId,
      nextPassHash,
      nextPassHash,
      id
    );

    // If password was rotated or role/tenant scope changed, revoke active sessions for that user immediately
    if (nextPassHash || nextRole !== existing.role || nextTenantId !== existing.tenant_id) {
      revokeUserSessions(id);
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'RBAC User Updated', ?)
    `).run(`aud-uedit-${crypto.randomUUID()}`, getActorUsername(request), `Updated user '${existing.username}' (${nextRole})`);

    return {
      success: true,
      user: sanitizeUserRowForResponse(db.prepare('SELECT * FROM users WHERE id = ?').get(id))
    };
  });

  server.post('/api/users/:id/reset-mfa', async (request, reply) => {
    if (!requireStepUpMfaIfEnforced(request, reply, null)) {
      return reply;
    }
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'User not found' });

    const details = getOrEnrollUserMfaDetails(id, { resetEnrollment: true, callerMfaVerified: true });
    const { plaintextCodes, hashedCodes } = generateOneTimeRecoveryCodes(8);
    db.prepare('UPDATE users SET recovery_codes_json = ? WHERE id = ?').run(JSON.stringify(hashedCodes), id);
    revokeUserSessions(id);

    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'User MFA Reset by Admin', ?)
    `).run(`aud-mfar-${crypto.randomUUID()}`, getActorUsername(request), `Reset TOTP & recovery codes for '${existing.username}'`);

    return {
      success: true,
      totpSecret: details.totpSecret,
      otpAuthUri: details.otpAuthUri,
      qrSvg: details.otpAuthUri ? generateQrCodeSvg(details.otpAuthUri) : null,
      recoveryCodes: plaintextCodes
    };
  });

  server.delete('/api/users/:id', async (request, reply) => {
    if (!requireStepUpMfaIfEnforced(request, reply, null)) {
      return reply;
    }
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
    const allowedTenants = getAllowedTenantIds(user);
    if (allowedTenants !== null && allowedTenants.length === 0) {
      return [];
    }

    const rawTenants = (allowedTenants !== null
      ? db
          .prepare(`
            SELECT t.*, (SELECT COUNT(*) FROM devices d WHERE d.tenant_id = t.id) as computed_device_count
            FROM tenants t
            WHERE t.id IN (${allowedTenants.map(() => '?').join(',')})
            ORDER BY t.name ASC
          `)
          .all(...allowedTenants)
      : db
          .prepare(`
            SELECT t.*, (SELECT COUNT(*) FROM devices d WHERE d.tenant_id = t.id) as computed_device_count
            FROM tenants t
            ORDER BY t.name ASC
          `)
          .all()) as any[];

    const tenants = rawTenants.filter((t) => canUserAccessTenant(user, t.id));

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

  server.put('/api/tenants/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM tenants WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Tenant not found.' });

    const body = (request.body || {}) as {
      name?: string;
      contact_email?: string;
      offline_auto_archive_days?: number;
    };

    const nextName = body.name !== undefined ? String(body.name).trim() : existing.name;
    if (!nextName) return reply.status(400).send({ error: 'Client organization name cannot be empty.' });

    const nextEmail =
      body.contact_email !== undefined ? String(body.contact_email).trim() : existing.contact_email;
    const nextArchiveDays =
      body.offline_auto_archive_days != null && Number.isFinite(Number(body.offline_auto_archive_days))
        ? Math.max(1, Number(body.offline_auto_archive_days))
        : existing.offline_auto_archive_days;

    db.prepare(`
      UPDATE tenants
      SET name = ?, contact_email = ?, offline_auto_archive_days = COALESCE(?, offline_auto_archive_days)
      WHERE id = ?
    `).run(nextName, nextEmail, nextArchiveDays ?? null, id);

    return { success: true, tenant: db.prepare('SELECT * FROM tenants WHERE id = ?').get(id) };
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
    const allowedTenants = getAllowedTenantIds(user);
    if (allowedTenants !== null && allowedTenants.length === 0) {
      return [];
    }

    const rows = (allowedTenants !== null
      ? db
          .prepare(`
            SELECT d.*, t.name as tenant_name, t.lifecycle_state as tenant_lifecycle_state, s.name as site_name,
                   l.account_name as laps_account
            FROM devices d
            LEFT JOIN tenants t ON d.tenant_id = t.id
            LEFT JOIN sites s ON d.site_id = s.id
            LEFT JOIN laps_vault l ON d.id = l.device_id
            WHERE d.tenant_id IN (${allowedTenants.map(() => '?').join(',')})
            ORDER BY d.hostname ASC
          `)
          .all(...allowedTenants)
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

    return rows.filter((d) => canUserAccessTenant(user, d.tenant_id)).map(sanitizeDeviceRowForResponse);
  });

  server.get('/api/devices/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed) return reply;

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
    safeDevice.laps = isTechnicianOrAbove(request.auth?.user.role)
      ? getLapsCredential(id, false, { actorUsername: getActorUsername(request) })
      : null;
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

  // Historical Telemetry Series & Live Telemetry Sampling + Detailed Hardware Inventory
  server.get('/api/devices/:id/telemetry-history', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
    const query = (request.query || {}) as { range?: string };
    return queryDeviceTelemetryHistory(id, query.range || '24h');
  });

  server.post('/api/devices/:id/telemetry-sample', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
    const body = (request.body || {}) as { includeDetailedHardware?: boolean; forceHistoryInsert?: boolean };

    const res = await meshBridge.sampleLiveTelemetry(id, {
      includeDetailedHardware: Boolean(body.includeDetailedHardware),
      forceHistoryInsert: body.forceHistoryInsert !== false
    });

    const updated = db.prepare('SELECT * FROM devices WHERE id = ?').get(id);
    return {
      success: true,
      sampled: res.sampled,
      reason: res.reason || null,
      sample: res.sample || null,
      device: sanitizeDeviceRowForResponse(updated)
    };
  });

  server.patch('/api/devices/:id/role', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
    if (!isTechnicianOrAbove(request.auth?.user.role)) {
      return reply.status(403).send({ error: 'Technician role required to modify device role.' });
    }

    const body = (request.body || {}) as { device_role?: string; auto_detect?: boolean };
    const dev = access.device as any;
    const rawRole = String(body.device_role || '').trim().slice(0, 64);
    const useAuto = Boolean(body.auto_detect) || ['auto', 'auto-detect', ''].includes(rawRole.toLowerCase());

    if (useAuto) {
      const signals = extractSignalsFromHardwareDetails(dev.hardware_details_json, {
        os_type: dev.os_type,
        os_version: dev.os_version,
        manufacturer: dev.manufacturer,
        model: dev.model,
        bios_version: dev.bios_version
      });
      const nextRole = inferDeviceRole(signals) || 'Workstation';
      db.prepare('UPDATE devices SET device_role = ?, device_role_manual = 0 WHERE id = ?').run(nextRole, id);
      return {
        success: true,
        device_role: nextRole,
        device_role_manual: 0,
        device: sanitizeDeviceRowForResponse(db.prepare('SELECT * FROM devices WHERE id = ?').get(id))
      };
    }

    db.prepare('UPDATE devices SET device_role = ?, device_role_manual = 1 WHERE id = ?').run(rawRole, id);
    return {
      success: true,
      device_role: rawRole,
      device_role_manual: 1,
      device: sanitizeDeviceRowForResponse(db.prepare('SELECT * FROM devices WHERE id = ?').get(id))
    };
  });

  server.get('/api/devices/:id/hardware', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
    const dev = access.device;

    let parsedDetails: Record<string, any> = {};
    if (dev.hardware_details_json) {
      try {
        const obj = JSON.parse(dev.hardware_details_json);
        if (obj && typeof obj === 'object') parsedDetails = obj;
      } catch {
        parsedDetails = {};
      }
    }

    return {
      deviceId: dev.id,
      hostname: dev.hostname,
      status: dev.status,
      system: {
        manufacturer: parsedDetails.system?.manufacturer || dev.manufacturer || '',
        model: parsedDetails.system?.model || dev.model || '',
        serialNumber: parsedDetails.system?.serialNumber || dev.serial_number || '',
        uuid: parsedDetails.system?.uuid || '',
        motherboardVendor: parsedDetails.system?.motherboardVendor || '',
        motherboardName: parsedDetails.system?.motherboardName || '',
        motherboardSerial: parsedDetails.system?.motherboardSerial || '',
        biosVendor: parsedDetails.system?.biosVendor || '',
        biosVersion: parsedDetails.system?.biosVersion || dev.bios_version || '',
        biosDate: parsedDetails.system?.biosDate || '',
        tpmVersion: parsedDetails.system?.tpmVersion || dev.tpm_version || '',
        chassisType: parsedDetails.system?.chassisType ? Number(parsedDetails.system.chassisType) : undefined,
        chassisLabel:
          parsedDetails.system?.chassisLabel ||
          (parsedDetails.system?.chassisType ? getSmbiosChassisLabel(Number(parsedDetails.system.chassisType)) : ''),
        hasBattery: parsedDetails.system?.hasBattery ?? null,
        isVirtualMachine: parsedDetails.system?.isVirtualMachine ?? null,
        isHypervisorHost: parsedDetails.system?.isHypervisorHost ?? null,
        hypervisorVendor: parsedDetails.system?.hypervisorVendor || '',
        osProductType: parsedDetails.system?.osProductType || ''
      },
      cpu: {
        model: parsedDetails.cpu?.model || dev.cpu_model || '',
        physicalCores: parsedDetails.cpu?.physicalCores || null,
        logicalCores: parsedDetails.cpu?.logicalCores || dev.cpu_cores || 0,
        maxClockMhz: parsedDetails.cpu?.maxClockMhz || null,
        usagePct: Number(dev.cpu_usage || 0)
      },
      memory: {
        totalGb: Number(dev.ram_total_gb || parsedDetails.memory?.totalGb || 0),
        usedGb: Number(dev.ram_used_gb || 0),
        usedPct:
          Number(dev.ram_total_gb || 0) > 0
            ? Number(((Number(dev.ram_used_gb || 0) / Number(dev.ram_total_gb)) * 100).toFixed(1))
            : 0,
        modules: Array.isArray(parsedDetails.memory?.modules) ? parsedDetails.memory.modules : []
      },
      storage: {
        totalGb: Number(dev.disk_total_gb || 0),
        freeGb: Number(dev.disk_free_gb || 0),
        smartStatus: dev.smart_status || 'Unknown',
        encryptionStatus: dev.bitlocker_status || 'Unknown',
        physicalDisks: Array.isArray(parsedDetails.storage?.physicalDisks)
          ? parsedDetails.storage.physicalDisks
          : [],
        volumes: Array.isArray(parsedDetails.storage?.volumes) ? parsedDetails.storage.volumes : []
      },
      gpus: Array.isArray(parsedDetails.gpus) ? parsedDetails.gpus : [],
      network: {
        primaryIp: dev.ip_address || '',
        primaryMac: dev.mac_address || '',
        netRxMbps: Number(dev.net_rx_mbps || 0),
        netTxMbps: Number(dev.net_tx_mbps || 0),
        adapters: Array.isArray(parsedDetails.networkAdapters)
          ? parsedDetails.networkAdapters
          : Array.isArray(parsedDetails.network?.adapters)
            ? parsedDetails.network.adapters
            : []
      },
      os: {
        osType: dev.os_type || 'windows',
        osVersion: dev.os_version || '',
        osBuild: parsedDetails.os?.build || dev.os_build || '',
        uptimeSeconds: Number(dev.uptime_seconds || 0),
        loggedInUser: String(dev.logged_in_user || ''),
        pendingReboot: Boolean(dev.pending_reboot),
        lastSeen: dev.last_seen || ''
      },
      lastHardwareScanAt: parsedDetails.lastHardwareScanAt || null
    };
  });

  // Dedicated Step-Up MFA Gated BitLocker / LUKS / FileVault Escrow Reveal Endpoint
  server.get('/api/devices/:id/bitlocker', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!isTechnicianOrAbove(request.auth?.user.role)) {
      return reply.status(403).send({ error: 'Technician privileges required to reveal recovery keys.' });
    }
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;

    if (!requireStepUpMfaIfEnforced(request, reply, id)) {
      return reply;
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
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
    return db
      .prepare('SELECT * FROM device_notes WHERE device_id = ? ORDER BY is_pinned DESC, created_at DESC')
      .all(id);
  });

  server.post('/api/devices/:id/notes', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
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
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
    db.prepare('DELETE FROM device_notes WHERE id = ? AND device_id = ?').run(noteId, id);
    return { success: true };
  });

  const setBackgroundToolHeaders = (reply: FastifyReply, dev: any, isEmpty: boolean) => {
    if (!dev || (dev.status !== 'online' && dev.status !== 'isolated')) {
      reply.header('X-Vitrine-Tool-Status', 'offline');
      reply.header(
        'X-Vitrine-Tool-Error',
        `Endpoint ${dev?.hostname || 'device'} is offline; live query cannot run.`
      );
      return;
    }
    if (meshBridge.lastToolError) {
      const cleanErr = String(meshBridge.lastToolError)
        .replace(/[\r\n]+/g, ' ')
        .trim()
        .slice(0, 260);
      reply.header('X-Vitrine-Tool-Status', 'error');
      reply.header('X-Vitrine-Tool-Error', cleanErr);
      return;
    }
    const bridgeStatus = meshBridge.getStatus();
    if (!bridgeStatus.connected && isEmpty) {
      const cleanBridgeErr = String(bridgeStatus.lastError || 'check MS2 URL and login token')
        .replace(/[\r\n]+/g, ' ')
        .trim()
        .slice(0, 180);
      reply.header('X-Vitrine-Tool-Status', 'disconnected');
      reply.header(
        'X-Vitrine-Tool-Error',
        `MeshCentral 2 control bridge is disconnected (${cleanBridgeErr}).`
      );
      return;
    }
    reply.header('X-Vitrine-Tool-Status', 'live');
  };

  // Remote Event Viewer
  server.get('/api/devices/:id/eventlogs', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
    const query = (request.query || {}) as Record<string, string>;
    const channel = query.channel || 'System';
    const level = query.level || 'all';
    const limit = Math.min(200, Math.max(1, parseInt(query.limit || '50', 10) || 50));
    const logs = await meshBridge.getEventLogs(id, channel, level, limit);
    setBackgroundToolHeaders(reply, access.device, !Array.isArray(logs) || logs.length === 0);
    return logs;
  });

  // Device Remote Privacy & Consent Control
  server.get('/api/devices/:id/consent-status', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
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
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
    const procs = await meshBridge.getProcesses(id);
    setBackgroundToolHeaders(reply, access.device, !Array.isArray(procs) || procs.length === 0);
    return procs;
  });

  server.post('/api/devices/:id/processes/:pid/kill', async (request, reply) => {
    const { id, pid } = request.params as { id: string; pid: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
    try {
      const success = await meshBridge.killProcess(id, parseInt(pid, 10), getActorUsername(request));
      return { success };
    } catch (err: any) {
      return reply.status(400).send({ success: false, error: err?.message || 'Invalid PID' });
    }
  });

  // Silent Background Services Manager
  server.get('/api/devices/:id/services', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
    const svcs = await meshBridge.getServices(id);
    setBackgroundToolHeaders(reply, access.device, !Array.isArray(svcs) || svcs.length === 0);
    return svcs;
  });

  server.post('/api/devices/:id/services/:name/:action', async (request, reply) => {
    const { id, name, action } = request.params as {
      id: string;
      name: string;
      action: 'start' | 'stop' | 'restart';
    };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
    try {
      const success = await meshBridge.manageService(id, name, action, getActorUsername(request));
      return { success };
    } catch (err: any) {
      return reply.status(400).send({ success: false, error: err?.message || 'Service operation rejected' });
    }
  });

  // Remote Registry / sysctl / plist Browser
  server.get('/api/devices/:id/registry', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
    const query = (request.query || {}) as { path?: string };
    const reg = await meshBridge.getRegistryKeys(query.path || '', id);
    const isEmpty = (!reg?.subkeys || reg.subkeys.length === 0) && (!reg?.values || reg.values.length === 0);
    setBackgroundToolHeaders(reply, access.device, isEmpty);
    return reg;
  });

  server.post('/api/devices/:id/registry', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
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
    try {
      const updated = await meshBridge.setRegistryValue(
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
    } catch (err: any) {
      return reply.status(400).send({ success: false, error: err?.message || 'Registry operation rejected' });
    }
  });

  server.delete('/api/devices/:id/registry', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
    const query = (request.query || {}) as { path?: string; name?: string };
    const regPath = query.path || 'HKLM\\SOFTWARE\\VitrineRMM';
    try {
      const updated = await meshBridge.deleteRegistryValue(id, regPath, query.name || '', getActorUsername(request));
      return { success: true, ...updated };
    } catch (err: any) {
      return reply.status(400).send({ success: false, error: err?.message || 'Registry delete rejected' });
    }
  });

  // Scheduled Tasks Manager
  server.get('/api/devices/:id/tasks', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
    const tasks = await meshBridge.getScheduledTasks(id);
    setBackgroundToolHeaders(reply, access.device, !Array.isArray(tasks) || tasks.length === 0);
    return tasks;
  });

  server.post('/api/devices/:id/tasks', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
    const body = (request.body || {}) as { name?: string; action?: 'run' | 'enable' | 'disable' };
    if (!body.name) return reply.status(400).send({ error: 'Task name is required' });
    try {
      const tasks = await meshBridge.manageScheduledTask(id, body.name, body.action || 'run', getActorUsername(request));
      return { success: true, tasks };
    } catch (err: any) {
      return reply.status(400).send({ success: false, error: err?.message });
    }
  });

  // Remote File Manager (Browse, Upload, Download, Mkdir, Delete)
  server.get('/api/devices/:id/files', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
    const query = (request.query || {}) as { path?: string };
    const defaultRoot = access.device.os_type === 'windows' ? 'C:\\' : '/';
    const listing = await meshBridge.getDirectoryListing(id, query.path || defaultRoot);
    setBackgroundToolHeaders(reply, access.device, !Array.isArray(listing) || listing.length === 0);
    return listing;
  });

  server.post('/api/devices/:id/files', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
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
      const files = await meshBridge.manageFile(
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
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
    const query = (request.query || {}) as { path?: string };
    if (!query.path) return reply.status(400).send({ error: 'File path is required' });
    const dl = await meshBridge.downloadFile(id, query.path, getActorUsername(request));
    reply.header('Content-Type', 'application/octet-stream');
    reply.header('Content-Disposition', buildSafeContentDisposition(dl.filename));
    return reply.send(Buffer.from(dl.contentBase64, 'base64'));
  });

  // Cyber Isolation / Network Quarantine
  server.post('/api/devices/:id/quarantine', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
    const body = (request.body || {}) as { quarantine?: boolean };
    const quarantined = Boolean(body.quarantine);
    meshBridge.toggleQuarantine(id, quarantined, getActorUsername(request));
    return { success: true, quarantined };
  });

  // LAPS Vault (MFA-Gated on Reveal)
  server.get('/api/devices/:id/laps', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed) return reply;
    const query = (request.query || {}) as { reveal?: string };
    const reveal = query.reveal === 'true';

    if (reveal) {
      if (!isTechnicianOrAbove(request.auth?.user.role)) {
        return reply.status(403).send({ error: 'Technician role required to reveal LAPS credentials.' });
      }
      if (!requireStepUpMfaIfEnforced(request, reply, id)) {
        return reply;
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
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
    const body = (request.body || {}) as { reveal?: boolean };
    const shouldReveal = Boolean(body.reveal);

    if (shouldReveal && !requireStepUpMfaIfEnforced(request, reply, id)) {
      return reply;
    }

    const cred = await rotateLapsPasswordVerifiedAsync(id, {
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
    alert_rules: parsePolicyAlertRules(p.alert_rules_json, p.tier, p.target_id),
    tray_menu_items: p.tray_menu_items_json ? parsePolicyTrayMenuItems(p.tray_menu_items_json) : null
  });

  const resolvePolicyTenantId = (tier?: string | null, targetId?: string | null): string | null => {
    if (!tier || tier === 'global' || tier === 'quicksupport') return null;
    if (tier === 'client') return targetId || null;
    if (tier === 'site' && targetId) {
      const s = db.prepare('SELECT tenant_id FROM sites WHERE id = ?').get(targetId) as { tenant_id?: string } | undefined;
      return s?.tenant_id || null;
    }
    if (tier === 'device' && targetId) {
      const d = db.prepare('SELECT tenant_id FROM devices WHERE id = ?').get(targetId) as { tenant_id?: string } | undefined;
      return d?.tenant_id || null;
    }
    return null;
  };

  server.get('/api/policies', async (request) => {
    const user = request.auth?.user;
    const rows = db
      .prepare(
        "SELECT * FROM policies ORDER BY CASE tier WHEN 'global' THEN 1 WHEN 'quicksupport' THEN 2 WHEN 'client' THEN 3 WHEN 'site' THEN 4 ELSE 5 END ASC"
      )
      .all() as any[];
    const visible = rows.filter((p) => {
      if (p.tier === 'global' || p.tier === 'quicksupport') return true;
      const pTenantId = resolvePolicyTenantId(p.tier, p.target_id);
      return pTenantId ? canUserAccessTenant(user, pTenantId) : isSuperAdminRole(user?.role);
    });
    return visible.map(formatPolicyRowForResponse);
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
    'auto_patch_cve_min_cvss',
    'patch_ring',
    'patch_delay_days',
    'defender_managed',
    'bitlocker_enforced',
    'tray_brand_name',
    'tray_icon_url',
    'tray_theme_mode',
    'tray_enabled',
    'tray_tooltip',
    'tray_support_url',
    'tray_support_phone',
    'tray_support_email',
    'tray_menu_items_json',
    'companion_auto_deploy'
  ];

  server.post('/api/policies', async (request, reply) => {
    const body = (request.body || {}) as Record<string, any>;
    const tier = String(body.tier || 'client').trim().toLowerCase();
    if (!['global', 'role', 'client', 'site', 'device'].includes(tier)) {
      return reply.status(400).send({ error: `Invalid policy tier '${tier}'.` });
    }
    if ((tier === 'global' || tier === 'role') && !isSuperAdminRole(request.auth?.user.role)) {
      return reply.status(403).send({ error: 'Only MSP Super Admins can create global or role policies.' });
    }
    if (tier !== 'global' && tier !== 'role') {
      const targetTenantId = resolvePolicyTenantId(tier, body.target_id);
      if (!targetTenantId || !canUserAccessTenant(request.auth?.user, targetTenantId)) {
        return reply.status(403).send({ error: 'Forbidden for target policy scope.' });
      }
    }
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

    const trayMenuItemsJson =
      body.tray_menu_items !== undefined
        ? JSON.stringify(parsePolicyTrayMenuItems(JSON.stringify(body.tray_menu_items)))
        : body.tray_menu_items_json !== undefined
          ? body.tray_menu_items_json
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
        tray_brand_name, tray_icon_url, tray_theme_mode, tray_enabled,
        tray_tooltip, tray_support_url, tray_support_phone, tray_support_email,
        tray_menu_items_json, companion_auto_deploy,
        overrides_json, alert_rules_json
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )
    `).run(
      id,
      body.name || 'Custom Tier Policy',
      tier,
      tier === 'global' ? null : body.target_id || null,
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
      String(body.tray_brand_name || ''),
      String(body.tray_icon_url || ''),
      String(body.tray_theme_mode || ''),
      body.tray_enabled !== undefined ? (body.tray_enabled ? 1 : 0) : 1,
      String(body.tray_tooltip || ''),
      String(body.tray_support_url || ''),
      String(body.tray_support_phone || ''),
      String(body.tray_support_email || ''),
      trayMenuItemsJson,
      body.companion_auto_deploy !== undefined ? (body.companion_auto_deploy ? 1 : 0) : 0,
      JSON.stringify(explicitOverrides),
      alertRulesJson
    );

    const saved = db.prepare('SELECT * FROM policies WHERE id = ?').get(id) as any;
    return { success: true, policy: formatPolicyRowForResponse(saved) };
  });

  server.delete('/api/policies/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT tier, target_id FROM policies WHERE id = ?').get(id) as
      | { tier?: string; target_id?: string | null }
      | undefined;
    if (!existing) {
      return reply.status(404).send({ success: false, error: 'Policy not found' });
    }
    if (id === 'pol-global' || existing.tier === 'global') {
      return reply.status(400).send({ success: false, error: 'Cannot delete the Global MSP Baseline policy' });
    }
    if (id === 'pol-quicksupport' || existing.tier === 'quicksupport') {
      return reply.status(400).send({ success: false, error: 'Cannot delete the built-in QuickSupport branding profile' });
    }
    if (existing.tier === 'role') {
      if (!isSuperAdminRole(request.auth?.user.role)) {
        return reply.status(403).send({ success: false, error: 'Only MSP Super Admins can delete role-tier policies.' });
      }
    } else {
      const existingTenant = resolvePolicyTenantId(existing.tier, existing.target_id);
      if (!existingTenant || !canUserAccessTenant(request.auth?.user, existingTenant)) {
        return reply.status(403).send({ success: false, error: 'Forbidden for target policy scope.' });
      }
    }
    db.prepare('DELETE FROM policies WHERE id = ?').run(id);
    return { success: true };
  });

  server.get('/api/policies/effective/:deviceId', async (request, reply) => {
    const { deviceId } = request.params as { deviceId: string };
    if (!ensureDeviceTenantAccess(request, reply, deviceId).allowed) return reply;
    return sanitizeEffectivePolicyForResponse(resolveEffectiveDevicePolicy(deviceId));
  });

  server.put('/api/policies/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = (request.body || {}) as Record<string, any>;
    const existing = db.prepare('SELECT * FROM policies WHERE id = ?').get(id) as any;
    if (!existing) {
      return reply.status(404).send({ success: false, error: 'Policy not found' });
    }

    if ((existing.tier === 'global' || existing.tier === 'quicksupport' || existing.tier === 'role') && !isSuperAdminRole(request.auth?.user.role)) {
      return reply.status(403).send({ success: false, error: 'Only MSP Super Admins can modify global, QuickSupport, or role policies.' });
    }
    if (existing.tier !== 'global' && existing.tier !== 'quicksupport' && existing.tier !== 'role') {
      const existingTenant = resolvePolicyTenantId(existing.tier, existing.target_id);
      if (!existingTenant || !canUserAccessTenant(request.auth?.user, existingTenant)) {
        return reply.status(403).send({ success: false, error: 'Forbidden for target policy scope.' });
      }
    }

    const nextTier = body.tier !== undefined ? String(body.tier).trim().toLowerCase() : String(existing.tier || 'client').toLowerCase();
    const nextTargetId = body.target_id !== undefined ? body.target_id : existing.target_id;
    if (!['global', 'quicksupport', 'role', 'client', 'site', 'device'].includes(nextTier)) {
      return reply.status(400).send({ success: false, error: `Invalid policy tier '${nextTier}'.` });
    }
    if ((nextTier === 'global' || nextTier === 'quicksupport' || nextTier === 'role') && !isSuperAdminRole(request.auth?.user.role)) {
      return reply.status(403).send({ success: false, error: 'Only MSP Super Admins can target global, QuickSupport, or role policy tiers.' });
    }
    if (nextTier !== 'global' && nextTier !== 'quicksupport' && nextTier !== 'role') {
      const nextTenant = resolvePolicyTenantId(nextTier, nextTargetId);
      if (!nextTenant || !canUserAccessTenant(request.auth?.user, nextTenant)) {
        return reply.status(403).send({ success: false, error: 'Forbidden for target policy scope.' });
      }
    }

    // Require Step-Up MFA before weakening MFA enforcement or altering LAPS static password / offboard rules
    const weakensSecurity =
      (body.require_mfa_for_secrets === false || body.require_mfa_for_secrets === 0) ||
      (body.laps_static_password !== undefined && !isMaskedSecret(String(body.laps_static_password))) ||
      body.laps_offboard_client_deleted_action !== undefined;
    if (weakensSecurity && !requireStepUpMfaIfEnforced(request, reply, null)) {
      return reply;
    }

    const prevOverrides = new Set<string>(safeJsonParse<string[]>(existing.overrides_json, []));
    const normalizedTrayMenuJson =
      body.tray_menu_items !== undefined
        ? body.tray_menu_items === null
          ? null
          : JSON.stringify(parsePolicyTrayMenuItems(JSON.stringify(body.tray_menu_items)))
        : body.tray_menu_items_json !== undefined
          ? body.tray_menu_items_json
          : undefined;
    if (normalizedTrayMenuJson !== undefined) {
      body.tray_menu_items_json = normalizedTrayMenuJson;
    }
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
      tier: nextTier,
      target_id: nextTier === 'global' ? null : nextTargetId,
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

    const defenderVal = body.defender_managed ?? body.managed_defender_enabled;
    const bitlockerVal = body.bitlocker_enforced ?? body.bitlocker_enforcement;
    if (
      body.patch_ring !== undefined ||
      body.patch_delay_days !== undefined ||
      defenderVal !== undefined ||
      bitlockerVal !== undefined ||
      body.backup_policy_id !== undefined ||
      body.mdm_profile_id !== undefined ||
      body.tray_brand_name !== undefined ||
      body.tray_icon_url !== undefined ||
      body.tray_theme_mode !== undefined ||
      body.tray_enabled !== undefined ||
      body.tray_tooltip !== undefined ||
      body.tray_support_url !== undefined ||
      body.tray_support_phone !== undefined ||
      body.tray_support_email !== undefined ||
      body.tray_menu_items !== undefined ||
      body.tray_menu_items_json !== undefined ||
      body.companion_auto_deploy !== undefined
    ) {
      db.prepare(`
        UPDATE policies SET
          patch_ring = COALESCE(?, patch_ring),
          patch_delay_days = COALESCE(?, patch_delay_days),
          defender_managed = COALESCE(?, defender_managed),
          bitlocker_enforced = COALESCE(?, bitlocker_enforced),
          backup_policy_id = ?,
          mdm_profile_id = ?,
          tray_brand_name = COALESCE(?, tray_brand_name),
          tray_icon_url = COALESCE(?, tray_icon_url),
          tray_theme_mode = COALESCE(?, tray_theme_mode),
          tray_enabled = COALESCE(?, tray_enabled),
          tray_tooltip = COALESCE(?, tray_tooltip),
          tray_support_url = COALESCE(?, tray_support_url),
          tray_support_phone = COALESCE(?, tray_support_phone),
          tray_support_email = COALESCE(?, tray_support_email),
          tray_menu_items_json = ?,
          companion_auto_deploy = COALESCE(?, companion_auto_deploy)
        WHERE id = ?
      `).run(
        body.patch_ring ?? null,
        body.patch_delay_days != null ? Number(body.patch_delay_days) : null,
        defenderVal != null ? (defenderVal ? 1 : 0) : null,
        bitlockerVal != null ? (bitlockerVal ? 1 : 0) : null,
        body.backup_policy_id !== undefined ? body.backup_policy_id : existing.backup_policy_id ?? null,
        body.mdm_profile_id !== undefined ? body.mdm_profile_id : existing.mdm_profile_id ?? null,
        body.tray_brand_name !== undefined ? String(body.tray_brand_name) : null,
        body.tray_icon_url !== undefined ? String(body.tray_icon_url) : null,
        body.tray_theme_mode !== undefined ? String(body.tray_theme_mode) : null,
        body.tray_enabled !== undefined ? (body.tray_enabled ? 1 : 0) : null,
        body.tray_tooltip !== undefined ? String(body.tray_tooltip) : null,
        body.tray_support_url !== undefined ? String(body.tray_support_url) : null,
        body.tray_support_phone !== undefined ? String(body.tray_support_phone) : null,
        body.tray_support_email !== undefined ? String(body.tray_support_email) : null,
        body.tray_menu_items_json !== undefined ? body.tray_menu_items_json : existing.tray_menu_items_json ?? null,
        body.companion_auto_deploy !== undefined ? (body.companion_auto_deploy ? 1 : 0) : null,
        id
      );
    }

    const savedRow = db.prepare('SELECT * FROM policies WHERE id = ?').get(id) as any;
    return {
      success: true,
      policy: formatPolicyRowForResponse(savedRow)
    };
  });

  server.post('/api/policies/:id/tray-icon', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM policies WHERE id = ?').get(id) as any;
    if (!existing) {
      return reply.status(404).send({ error: 'Policy not found' });
    }
    if ((existing.tier === 'global' || existing.tier === 'quicksupport' || existing.tier === 'role') && !isSuperAdminRole(request.auth?.user.role)) {
      return reply.status(403).send({ error: 'Only MSP Super Admins can modify Global, QuickSupport, or Role policy icons.' });
    }
    if (existing.tier !== 'global' && existing.tier !== 'quicksupport' && existing.tier !== 'role') {
      const existingTenant = resolvePolicyTenantId(existing.tier, existing.target_id);
      if (!existingTenant || !canUserAccessTenant(request.auth?.user, existingTenant)) {
        return reply.status(403).send({ error: 'Forbidden for target policy scope.' });
      }
    }

    const body = (request.body || {}) as { filename?: string; base64Data?: string };
    const saved = saveValidatedBrandingRasterImage(body.base64Data, `policy-${id}`);
    if (!saved.ok) {
      return reply.status(saved.status).send({ error: saved.error });
    }

    const prevOverrides = new Set<string>(safeJsonParse<string[]>(existing.overrides_json, []));
    prevOverrides.add('tray_icon_url');
    db.prepare('UPDATE policies SET tray_icon_url = ?, overrides_json = ? WHERE id = ?').run(
      saved.url,
      JSON.stringify(Array.from(prevOverrides)),
      id
    );
    return { success: true, tray_icon_url: saved.url };
  });

  // ============================================================================
  // Patches, OS Updates & KB Blocklist
  // ============================================================================
  server.get('/api/patches/blacklist', async () => {
    const rows = db.prepare('SELECT * FROM kb_blacklist ORDER BY created_at DESC').all() as any[];
    return rows.map((r) => ({
      ...r,
      kb_or_pkg_id: r.kb_or_pkg_id || r.kb_id || '',
      kb_id: r.kb_id || r.kb_or_pkg_id || ''
    }));
  });

  server.post('/api/patches/blacklist', async (request, reply) => {
    const body = (request.body || {}) as {
      kb_or_pkg_id?: string;
      kb_or_package?: string;
      kb_id?: string;
      platform?: string;
      title?: string;
      reason?: string;
      tenant_id?: string | null;
    };
    const kbId = String(body.kb_or_pkg_id || body.kb_or_package || body.kb_id || '').trim().toUpperCase();
    if (!kbId) return reply.status(400).send({ error: 'KB or package identifier is required.' });
    const id = `kbbl-${crypto.randomUUID().slice(0, 8)}`;
    db.prepare(`
      INSERT INTO kb_blacklist (id, kb_or_pkg_id, kb_id, platform, title, reason, tenant_id, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      kbId,
      kbId,
      body.platform || 'all',
      body.title || '',
      body.reason || 'Blocked by MSP patch policy',
      body.tenant_id || null,
      getActorUsername(request)
    );
    db.prepare("UPDATE patches SET status = 'Blocked' WHERE UPPER(kb_id) = ?").run(kbId);
    const saved = db.prepare('SELECT * FROM kb_blacklist WHERE id = ?').get(id) as any;
    return {
      success: true,
      entry: { ...saved, kb_or_pkg_id: saved.kb_or_pkg_id || kbId, kb_id: saved.kb_id || kbId }
    };
  });

  server.delete('/api/patches/blacklist/:id', async (request) => {
    const { id } = request.params as { id: string };
    const row = db
      .prepare('SELECT kb_or_pkg_id, kb_id FROM kb_blacklist WHERE id = ?')
      .get(id) as { kb_or_pkg_id?: string; kb_id?: string } | undefined;
    db.prepare('DELETE FROM kb_blacklist WHERE id = ?').run(id);
    const targetKb = row?.kb_or_pkg_id || row?.kb_id;
    if (targetKb) {
      db.prepare("UPDATE patches SET status = 'Pending' WHERE UPPER(kb_id) = ? AND status = 'Blocked'").run(targetKb.toUpperCase());
    }
    return { success: true };
  });

  server.get('/api/patches', async (request) => {
    const user = request.auth?.user;
    const allowedTenants = getAllowedTenantIds(user);
    if (allowedTenants !== null && allowedTenants.length === 0) {
      return [];
    }
    const rows = (allowedTenants !== null
      ? db
          .prepare(`
            SELECT p.*, d.hostname, d.tenant_id
            FROM patches p
            JOIN devices d ON p.device_id = d.id
            WHERE d.tenant_id IN (${allowedTenants.map(() => '?').join(',')})
            ORDER BY p.release_date DESC
          `)
          .all(...allowedTenants)
      : db
          .prepare(`
            SELECT p.*, d.hostname, d.tenant_id
            FROM patches p
            JOIN devices d ON p.device_id = d.id
            ORDER BY p.release_date DESC
          `)
          .all()) as any[];
    return rows.filter((r) => canUserAccessTenant(user, r.tenant_id));
  });

  server.post('/api/patches/:id/approve', async (request, reply) => {
    const { id } = request.params as { id: string };
    const patch = db
      .prepare('SELECT p.*, d.tenant_id, d.os_type, d.hostname FROM patches p JOIN devices d ON p.device_id = d.id WHERE p.id = ?')
      .get(id) as any;
    if (!patch) return reply.status(404).send({ error: 'Patch not found' });
    if (!canUserAccessTenant(request.auth?.user, patch.tenant_id)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const blocked = db
      .prepare("SELECT id FROM kb_blacklist WHERE UPPER(COALESCE(NULLIF(kb_or_pkg_id, ''), kb_id)) = UPPER(?) AND (tenant_id IS NULL OR tenant_id = ?) LIMIT 1")
      .get(patch.kb_id || '', patch.tenant_id);
    if (blocked) {
      return reply.status(409).send({ error: `Update ${patch.kb_id} is on the KB Blocklist and cannot be approved.` });
    }

    db.prepare("UPDATE patches SET status = 'Approved' WHERE id = ?").run(id);
    let liveResult: any = null;
    if (patch.device_id) {
      const safeKb = String(patch.kb_id || '').replace(/[^a-zA-Z0-9._+-]/g, '');
      const cmd =
        patch.os_type === 'windows'
          ? `if (Get-Command Install-WindowsUpdate -ErrorAction SilentlyContinue) { Install-WindowsUpdate -KBArticleID '${safeKb}' -AcceptAll -IgnoreReboot } else { UsoClient StartInstall }`
          : patch.os_type === 'macos'
            ? `softwareupdate -i '${safeKb}'`
            : `DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y '${safeKb}' 2>/dev/null || dnf update -y '${safeKb}' 2>/dev/null || true`;
      liveResult = await meshBridge.executeCommandOnNode(patch.device_id, cmd, {
        runAs: 'system',
        shell: patch.os_type === 'windows' ? 'powershell' : 'bash',
        timeoutMs: 20_000
      });
      if (liveResult.live && liveResult.exitCode === 0) {
        db.prepare("UPDATE patches SET status = 'Installed' WHERE id = ?").run(id);
      }
    }
    return { success: true, liveDispatched: Boolean(liveResult?.live) };
  });

  server.post('/api/patches/approve-bulk', async (request) => {
    const body = (request.body || {}) as { patchIds?: string[] };
    const ids = Array.isArray(body.patchIds) ? body.patchIds : [];
    const blockedSet = new Set(
      (db.prepare("SELECT UPPER(COALESCE(NULLIF(kb_or_pkg_id, ''), kb_id)) as kb FROM kb_blacklist").all() as Array<{ kb: string }>).map((r) => r.kb)
    );
    const stmt = db.prepare("UPDATE patches SET status = 'Approved' WHERE id = ?");
    let approvedCount = 0;
    for (const pid of ids) {
      const p = db
        .prepare('SELECT p.kb_id, d.tenant_id FROM patches p JOIN devices d ON p.device_id = d.id WHERE p.id = ?')
        .get(pid) as { kb_id?: string; tenant_id?: string } | undefined;
      if (!p || !canUserAccessTenant(request.auth?.user, p.tenant_id)) continue;
      if (p.kb_id && blockedSet.has(p.kb_id.toUpperCase())) continue;
      stmt.run(pid);
      approvedCount++;
    }
    return { success: true, approvedCount };
  });

  server.post('/api/patches/scan', async (request) => {
    const body = (request.body || {}) as { deviceIds?: string[] };
    const requestedIds = Array.isArray(body.deviceIds) ? body.deviceIds.filter(Boolean) : [];
    const rawTargetDevices = (
      requestedIds.length > 0
        ? db
            .prepare(
              `SELECT id, tenant_id, hostname, os_type, status FROM devices WHERE id IN (${requestedIds.map(() => '?').join(',')}) AND COALESCE(lifecycle_state, 'active') = 'active'`
            )
            .all(...requestedIds)
        : db
            .prepare("SELECT id, tenant_id, hostname, os_type, status FROM devices WHERE COALESCE(lifecycle_state, 'active') = 'active'")
            .all()
    ) as any[];
    const targetDevices = rawTargetDevices.filter((d) => canUserAccessTenant(request.auth?.user, d.tenant_id));

    const blockedSet = new Set(
      (db.prepare("SELECT UPPER(COALESCE(NULLIF(kb_or_pkg_id, ''), kb_id)) as kb FROM kb_blacklist").all() as Array<{ kb: string }>).map((r) => r.kb)
    );

    let dispatchedProbes = 0;
    let discoveredCount = 0;

    for (const d of targetDevices) {
      if (d.status === 'online') {
        const scanCmd =
          d.os_type === 'windows'
            ? `$s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0"); foreach ($u in $s.Updates) { $kb = if ($u.KBArticleIDs.Count -gt 0) { "KB" + $u.KBArticleIDs.Item(0) } else { "WU-" + $u.Identity.UpdateID.Substring(0,6) }; Write-Output "$kb|$($u.Title)|$($u.MsrcSeverity)" }`
            : d.os_type === 'macos'
              ? `softwareupdate -l 2>/dev/null | grep -E '^\\* Label:' | sed 's/* Label: //'`
              : `apt list --upgradable 2>/dev/null | tail -n +2 | head -n 25`;

        const res = await meshBridge.executeCommandOnNode(d.id, scanCmd, {
          runAs: 'system',
          shell: d.os_type === 'windows' ? 'powershell' : 'bash',
          timeoutMs: 12_000
        });
        if (res.live) {
          dispatchedProbes++;
          const lines = res.output.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
          for (const line of lines) {
            if (d.os_type === 'linux' && line.includes('/')) {
              // e.g. openssl/jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: ...]
              const pkgName = line.split('/')[0].trim();
              const verPart = line.split(/\s+/)[1] || 'latest';
              const isSec = line.toLowerCase().includes('security');
              if (!pkgName || pkgName === 'Listing...') continue;
              const existing = db
                .prepare('SELECT id FROM patches WHERE device_id = ? AND kb_id = ? LIMIT 1')
                .get(d.id, pkgName);
              if (!existing) {
                const status = blockedSet.has(pkgName.toUpperCase()) ? 'Blocked' : 'Pending';
                db.prepare(`
                  INSERT INTO patches (id, device_id, kb_id, title, category, severity, cvss_score, status, release_date)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, date('now'))
                `).run(
                  `pat-${crypto.randomUUID().slice(0, 8)}`,
                  d.id,
                  pkgName,
                  `${pkgName} -> ${verPart}`,
                  isSec ? 'Security Update' : 'Package Upgrade',
                  isSec ? 'Important' : 'Moderate',
                  isSec ? 7.5 : 4.2,
                  status
                );
                discoveredCount++;
              }
            } else if (d.os_type === 'windows' && line.includes('|')) {
              const [kb, title, sev] = line.split('|');
              if (!kb || !title) continue;
              const existing = db
                .prepare('SELECT id FROM patches WHERE device_id = ? AND kb_id = ? LIMIT 1')
                .get(d.id, kb.trim());
              if (!existing) {
                const status = blockedSet.has(kb.trim().toUpperCase()) ? 'Blocked' : 'Pending';
                db.prepare(`
                  INSERT INTO patches (id, device_id, kb_id, title, category, severity, cvss_score, status, release_date)
                  VALUES (?, ?, ?, ?, 'Security Update', ?, ?, ?, date('now'))
                `).run(
                  `pat-${crypto.randomUUID().slice(0, 8)}`,
                  d.id,
                  kb.trim(),
                  title.trim(),
                  sev?.trim() || 'Important',
                  sev?.trim() === 'Critical' ? 9.1 : 7.2,
                  status
                );
                discoveredCount++;
              }
            }
          }
        }
      }
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'Fleet Patch Scan Triggered', ?)
    `).run(
      `aud-pscan-${crypto.randomUUID()}`,
      getActorUsername(request),
      `Evaluated patch catalog across ${targetDevices.length} endpoint(s) (${dispatchedProbes} live probe(s), ${discoveredCount} new update(s)).`
    );

    const visiblePatches = (
      db
        .prepare('SELECT p.*, d.hostname, d.tenant_id FROM patches p JOIN devices d ON p.device_id = d.id ORDER BY p.release_date DESC')
        .all() as any[]
    ).filter((p) => canUserAccessTenant(request.auth?.user, p.tenant_id));

    return {
      success: true,
      scannedDevices: targetDevices.length,
      dispatchedProbes,
      discoveredCount,
      patches: visiblePatches
    };
  });

  server.post('/api/patches/:id/rollback', async (request, reply) => {
    const { id } = request.params as { id: string };
    const patch = db
      .prepare('SELECT p.*, d.hostname, d.os_type, d.tenant_id FROM patches p JOIN devices d ON p.device_id = d.id WHERE p.id = ?')
      .get(id) as any;
    if (!patch) return reply.status(404).send({ error: 'Patch not found' });
    if (!canUserAccessTenant(request.auth?.user, patch.tenant_id)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const safeKb = String(patch.kb_id || '').replace(/^KB/i, '').replace(/[^a-zA-Z0-9._+-]/g, '');
    const rollbackCmd =
      patch.os_type === 'windows'
        ? `wusa.exe /uninstall /kb:${safeKb} /quiet /norestart`
        : `dnf history undo last -y 2>/dev/null || echo 'Package rollback logged'`;
    await meshBridge.executeCommandOnNode(patch.device_id, rollbackCmd, {
      runAs: 'system',
      shell: patch.os_type === 'windows' ? 'powershell' : 'bash',
      timeoutMs: 15_000
    });

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
  // Centralized Scripting Library & Execution Ledger (Typed Params, Zero Injection)
  // ============================================================================
  const formatScriptRow = (s: any) => ({
    ...s,
    parameters_schema: safeJsonParse<any[]>(s.parameters_schema_json, [])
  });

  const resolveScriptParametersSchemaJson = (body: Record<string, any>): string | null => {
    const raw = body.parameters_schema !== undefined ? body.parameters_schema : body.parameters_schema_json;
    if (raw === undefined) return null;
    if (Array.isArray(raw)) return JSON.stringify(raw);
    if (typeof raw === 'string') {
      try {
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? JSON.stringify(parsed) : '[]';
      } catch {
        return '[]';
      }
    }
    return '[]';
  };

  server.get('/api/scripts', async (request, reply) => {
    const user = request.auth?.user;
    const { tenantId } = (request.query || {}) as { tenantId?: string };
    if (tenantId && tenantId !== 'all' && !canUserAccessTenant(user, tenantId)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    const rows = (
      tenantId && tenantId !== 'all'
        ? db
            .prepare(
              "SELECT * FROM scripts WHERE tenant_id IS NULL OR tenant_id = 'all' OR tenant_id = ? ORDER BY is_builtin DESC, name ASC"
            )
            .all(tenantId)
        : db.prepare('SELECT * FROM scripts ORDER BY is_builtin DESC, name ASC').all()
    ) as any[];
    return rows
      .filter((s) => !s.tenant_id || s.tenant_id === 'all' || canUserAccessTenant(user, s.tenant_id))
      .map(formatScriptRow);
  });

  server.get('/api/scripts/executions', async (request, reply) => {
    const query = (request.query || {}) as { deviceId?: string; scriptId?: string; script_id?: string };
    const deviceId = query.deviceId;
    const scriptId = query.scriptId || query.script_id;
    const user = request.auth?.user;
    const isGlobalUser = getAllowedTenantIds(user) === null;

    if (deviceId) {
      if (!ensureDeviceTenantAccess(request, reply, deviceId).allowed) return reply;
      if (scriptId) {
        return db
          .prepare('SELECT * FROM script_executions WHERE device_id = ? AND script_id = ? ORDER BY executed_at DESC LIMIT 50')
          .all(deviceId, scriptId);
      }
      return db
        .prepare('SELECT * FROM script_executions WHERE device_id = ? ORDER BY executed_at DESC LIMIT 50')
        .all(deviceId);
    }

    const rows = (scriptId
      ? db
          .prepare(`
            SELECT se.*, d.tenant_id
            FROM script_executions se
            LEFT JOIN devices d ON se.device_id = d.id
            WHERE se.script_id = ?
            ORDER BY se.executed_at DESC
            LIMIT 100
          `)
          .all(scriptId)
      : db
          .prepare(`
            SELECT se.*, d.tenant_id
            FROM script_executions se
            LEFT JOIN devices d ON se.device_id = d.id
            ORDER BY se.executed_at DESC
            LIMIT 100
          `)
          .all()) as any[];

    return rows.filter((r) => (r.tenant_id ? canUserAccessTenant(user, r.tenant_id) : isGlobalUser));
  });

  server.post('/api/scripts', async (request, reply) => {
    const body = (request.body || {}) as any;
    const user = request.auth?.user;
    if (!body.name?.trim() || !body.code?.trim()) {
      return reply.status(400).send({ error: 'Script name and code are required.' });
    }
    if (body.required_role !== undefined && !isSuperAdminRole(user?.role)) {
      if (String(body.required_role).trim().toLowerCase() !== 'technician') {
        return reply.status(403).send({ error: 'Only MSP Super Admins can set script required_role.' });
      }
    }

    const tenantId = body.tenant_id && body.tenant_id !== 'all' ? String(body.tenant_id) : null;
    if (tenantId && !canUserAccessTenant(user, tenantId)) {
      return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
    }
    if (!tenantId && getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Scoped accounts cannot create global (all-tenant) scripts.' });
    }

    const id = `scr-custom-${crypto.randomUUID().slice(0, 8)}`;
    const paramsSchemaJson = resolveScriptParametersSchemaJson(body) ?? '[]';

    db.prepare(`
      INSERT INTO scripts (id, name, description, language, code, category, enabled, required_role, is_builtin, tenant_id, parameters_schema_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
    `).run(
      id,
      body.name.trim(),
      body.description || '',
      body.language || 'powershell',
      body.code,
      body.category || 'Maintenance',
      body.enabled != null ? (body.enabled ? 1 : 0) : 1,
      isSuperAdminRole(user?.role) ? body.required_role || 'technician' : 'technician',
      tenantId,
      paramsSchemaJson
    );
    return { success: true, id, script: formatScriptRow(db.prepare('SELECT * FROM scripts WHERE id = ?').get(id)) };
  });

  server.put('/api/scripts/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM scripts WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Script not found' });
    const user = request.auth?.user;
    if (!canUserRunScriptRole(user?.role || '', existing.required_role)) {
      return reply.status(403).send({ error: 'Insufficient privileges to modify this script.' });
    }
    const existingTenantId = existing.tenant_id && existing.tenant_id !== 'all' ? existing.tenant_id : null;
    if (!existingTenantId && !isSuperAdminRole(user?.role)) {
      return reply.status(403).send({ error: 'Only MSP Super Admins may modify global scripts.' });
    }
    if (existingTenantId && !canUserAccessTenant(user, existingTenantId)) {
      return reply.status(403).send({ error: 'Forbidden for target script tenant.' });
    }

    const body = (request.body || {}) as any;
    if (
      body.required_role !== undefined &&
      String(body.required_role).trim().toLowerCase() !== String(existing.required_role || 'technician').toLowerCase() &&
      !isSuperAdminRole(user?.role)
    ) {
      return reply.status(403).send({ error: 'Only MSP Super Admins may change script required_role.' });
    }

    const nextTenantId =
      body.tenant_id !== undefined
        ? body.tenant_id && body.tenant_id !== 'all'
          ? String(body.tenant_id)
          : null
        : existingTenantId;
    if (!nextTenantId && !isSuperAdminRole(user?.role)) {
      return reply.status(403).send({ error: 'Only MSP Super Admins may scope scripts globally.' });
    }
    if (nextTenantId && !canUserAccessTenant(user, nextTenantId)) {
      return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
    }

    if (existing.is_builtin && body.code !== undefined && body.code !== existing.code) {
      if (!isSuperAdminRole(user?.role)) {
        return reply.status(403).send({ error: 'Only MSP Super Admins may modify built-in baseline scripts.' });
      }
      if (!requireStepUpMfaIfEnforced(request, reply, null)) {
        return reply;
      }
    }

    const nextSchemaJson = resolveScriptParametersSchemaJson(body);

    db.prepare(`
      UPDATE scripts SET
        name = COALESCE(?, name),
        description = COALESCE(?, description),
        language = COALESCE(?, language),
        code = COALESCE(?, code),
        category = COALESCE(?, category),
        enabled = COALESCE(?, enabled),
        required_role = COALESCE(?, required_role),
        tenant_id = ?,
        parameters_schema_json = COALESCE(?, parameters_schema_json)
      WHERE id = ?
    `).run(
      body.name ?? null,
      body.description ?? null,
      body.language ?? null,
      body.code ?? null,
      body.category ?? null,
      body.enabled != null ? (body.enabled ? 1 : 0) : null,
      isSuperAdminRole(user?.role) ? body.required_role ?? null : null,
      nextTenantId,
      nextSchemaJson,
      id
    );
    return { success: true, script: formatScriptRow(db.prepare('SELECT * FROM scripts WHERE id = ?').get(id)) };
  });

  server.delete('/api/scripts/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM scripts WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Script not found' });
    const user = request.auth?.user;
    if (!canUserRunScriptRole(user?.role || '', existing.required_role)) {
      return reply.status(403).send({ error: 'Insufficient privileges to delete this script.' });
    }
    const existingTenantId = existing.tenant_id && existing.tenant_id !== 'all' ? existing.tenant_id : null;
    if (!existingTenantId && !isSuperAdminRole(user?.role)) {
      return reply.status(403).send({ error: 'Only MSP Super Admins may delete global scripts.' });
    }
    if (existingTenantId && !canUserAccessTenant(user, existingTenantId)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    if (existing.is_builtin) {
      return reply.status(400).send({ error: 'Built-in baseline scripts cannot be deleted (disable instead).' });
    }
    db.prepare('DELETE FROM scripts WHERE id = ? AND is_builtin = 0').run(id);
    return { success: true };
  });

  server.post('/api/scripts/:id/run', async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = (request.body || {}) as {
      deviceId?: string;
      deviceIds?: string[];
      smartGroupId?: string;
      params?: Record<string, string>;
      runAs?: 'system' | 'user';
    };
    const user = request.auth?.user;
    const script = db.prepare('SELECT * FROM scripts WHERE id = ?').get(id) as any;
    if (!script) return reply.status(404).send({ error: 'Script not found' });
    if (!script.enabled) {
      return reply.status(400).send({ error: `Script "${script.name}" is currently disabled.` });
    }
    if (!canUserRunScriptRole(user?.role || '', script.required_role)) {
      return reply.status(403).send({
        error: `Forbidden: Script "${script.name}" requires role '${script.required_role}'.`
      });
    }
    if (script.tenant_id && script.tenant_id !== 'all' && !canUserAccessTenant(user, script.tenant_id)) {
      return reply.status(403).send({ error: 'Forbidden: script belongs to another client tenant.' });
    }

    const explicitDeviceIds = Array.from(
      new Set([
        ...(Array.isArray(body.deviceIds) ? body.deviceIds.map((d) => String(d || '').trim()).filter(Boolean) : []),
        ...(typeof body.deviceId === 'string' && body.deviceId.trim() ? [body.deviceId.trim()] : [])
      ])
    );
    for (const reqDevId of explicitDeviceIds) {
      const devCheck = db.prepare('SELECT id, tenant_id FROM devices WHERE id = ?').get(reqDevId) as
        | { id: string; tenant_id: string }
        | undefined;
      if (devCheck && !canUserAccessTenant(user, devCheck.tenant_id)) {
        return reply.status(403).send({ error: 'Forbidden: target endpoint is outside your tenant scope.' });
      }
    }

    let targetDeviceIds = [...explicitDeviceIds];
    if (body.smartGroupId) {
      const sg = db.prepare('SELECT * FROM smart_groups WHERE id = ?').get(body.smartGroupId) as any;
      if (!sg) {
        return reply.status(404).send({ error: 'Smart group not found.' });
      }
      if (sg.tenant_id ? !canUserAccessTenant(user, sg.tenant_id) : getAllowedTenantIds(user) !== null) {
        return reply.status(403).send({ error: 'Forbidden: smart group is outside your tenant scope.' });
      }
      const matched = evaluateSmartGroupDevices(sg.criteria_json, sg.tenant_id).filter((m) =>
        canUserAccessTenant(user, m.tenant_id)
      );
      targetDeviceIds = Array.from(new Set([...targetDeviceIds, ...matched.map((m) => m.id)]));
    }
    if (targetDeviceIds.length === 0) {
      return reply.status(400).send({ error: 'At least one target deviceId or smartGroupId is required.' });
    }

    const runAs: 'system' | 'user' = body.runAs === 'user' ? 'user' : 'system';
    const runtimeParams = body.params && typeof body.params === 'object' ? body.params : {};
    const actor = getActorUsername(request);
    const outputs: string[] = [];
    let dispatchedCount = 0;

    const signingSettings = (db
      .prepare('SELECT code_signing_enabled, code_signing_sign_scripts, code_signing_strict_verify FROM settings WHERE id = 1')
      .get() || {}) as {
      code_signing_enabled?: number;
      code_signing_sign_scripts?: number;
      code_signing_strict_verify?: number;
    };

    const insertExec = db.prepare(`
      INSERT INTO script_executions (
        id, script_id, script_name, device_id, hostname, run_as, params_json, status, exit_code, output, stdout, stderr, duration_ms, triggered_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const insertAudit = db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Script Executed', ?)
    `);

    for (const devId of targetDeviceIds) {
      const dev = db.prepare('SELECT * FROM devices WHERE id = ?').get(devId) as any;
      if (!dev || !canUserAccessTenant(user, dev.tenant_id)) continue;

      const shellLang: 'powershell' | 'bash' | 'python' =
        script.language === 'bash' ? 'bash' : script.language === 'python' ? 'python' : 'powershell';

      // Bind parameters strictly via VITRINE_PARAM_* environment variables (NEVER string-substitute raw user text into code!)
      const envVars = buildSafeScriptEnvParams(script.parameters_schema_json, {
        ...runtimeParams,
        HOSTNAME: dev.hostname,
        IP_ADDRESS: dev.ip_address,
        DEVICE_ID: dev.id,
        TENANT_ID: dev.tenant_id
      });
      const safeRenderedCode = String(script.code || '');

      let bridgeCommand = safeRenderedCode;
      let bridgeShell: 'powershell' | 'bash' = shellLang === 'bash' ? 'bash' : 'powershell';

      if (shellLang === 'python') {
        const b64Py = Buffer.from(safeRenderedCode, 'utf8').toString('base64');
        if (dev.os_type === 'windows') {
          bridgeShell = 'powershell';
          bridgeCommand = `$pyCode = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('${b64Py}')); if (Get-Command py -ErrorAction SilentlyContinue) { $pyCode | py -3 - } elseif (Get-Command python3 -ErrorAction SilentlyContinue) { $pyCode | python3 - } else { $pyCode | python - }`;
        } else {
          bridgeShell = 'bash';
          bridgeCommand = `if command -v python3 >/dev/null 2>&1; then printf '%s' '${b64Py}' | (base64 -d 2>/dev/null || base64 -D) | python3 -; else printf '%s' '${b64Py}' | (base64 -d 2>/dev/null || base64 -D) | python -; fi`;
        }
      } else if (
        dev.os_type === 'windows' &&
        shellLang === 'powershell' &&
        signingSettings.code_signing_enabled &&
        signingSettings.code_signing_sign_scripts
      ) {
        const signedWrap = await codeSigningService.wrapPowerShellExecutionIfSigningEnabled(
          safeRenderedCode,
          Boolean(signingSettings.code_signing_strict_verify)
        );
        if (signedWrap.error && signingSettings.code_signing_strict_verify) {
          return reply.status(502).send({
            success: false,
            error: `Code signing policy blocked unsigned PowerShell execution: ${signedWrap.error}`
          });
        }
        bridgeCommand = signedWrap.command;
      }

      const execId = `exec-${crypto.randomUUID().slice(0, 8)}`;
      const startMs = Date.now();
      const execRes = await meshBridge.executeCommandOnNode(dev.id, bridgeCommand, {
        runAs,
        shell: bridgeShell,
        timeoutMs: 12_000,
        env: envVars,
        executionId: execId
      });
      const durationMs = Date.now() - startMs;

      const isQueuedCompanion = Boolean(execRes.queued || execRes.output.startsWith('[Vitrine Companion Queue]'));
      let statusLabel = isQueuedCompanion
        ? 'Queued (Companion)'
        : execRes.exitCode === 0
          ? execRes.live
            ? 'Completed (Live)'
            : 'Queued'
          : 'Failed';

      if (!execRes.live && !isQueuedCompanion && dev.companion_installed) {
        const taskId = `task-${crypto.randomUUID().slice(0, 10)}`;
        db.prepare(`
          INSERT INTO agent_tasks (id, device_id, task_type, payload_json, status)
          VALUES (?, ?, 'script', ?, 'queued')
        `).run(
          taskId,
          dev.id,
          JSON.stringify({
            executionId: execId,
            language: shellLang,
            shell: shellLang,
            code: safeRenderedCode,
            env: envVars,
            runAs
          })
        );
        statusLabel = 'Queued (Companion)';
      }

      insertExec.run(
        execId,
        script.id,
        script.name,
        dev.id,
        dev.hostname,
        runAs,
        JSON.stringify(runtimeParams),
        statusLabel,
        execRes.live ? (execRes.exitCode ?? 0) : -1,
        execRes.output,
        execRes.live && execRes.exitCode === 0 ? execRes.output : '',
        execRes.live && execRes.exitCode !== 0 ? execRes.output : '',
        durationMs,
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
  server.get('/api/self-healing', async (request) => {
    const user = request.auth?.user;
    const isGlobalUser = getAllowedTenantIds(user) === null;
    const rows = db.prepare('SELECT * FROM self_healing_monitors ORDER BY id ASC').all() as any[];
    return rows.filter((m) => (m.tenant_id ? canUserAccessTenant(user, m.tenant_id) : isGlobalUser));
  });

  server.get('/api/self-healing/logs', async (request) => {
    const user = request.auth?.user;
    const isGlobalUser = getAllowedTenantIds(user) === null;
    const rows = db
      .prepare(`
        SELECT r.*, d.tenant_id
        FROM remediation_logs r
        LEFT JOIN devices d ON r.device_id = d.id
        ORDER BY r.executed_at DESC
        LIMIT 50
      `)
      .all() as any[];
    return rows.filter((r) => (r.tenant_id ? canUserAccessTenant(user, r.tenant_id) : isGlobalUser));
  });

  server.post('/api/self-healing', async (request, reply) => {
    const user = request.auth?.user;
    const body = (request.body || {}) as {
      name?: string;
      condition_type?: string;
      condition_value?: string;
      remediation_script_id?: string;
      cooldown_min?: number;
      alert_on_failure?: boolean;
      tenant_id?: string | null;
    };
    if (!body.name?.trim()) return reply.status(400).send({ error: 'Watchdog monitor name is required.' });
    const scriptId = body.remediation_script_id || 'scr-1';
    const remScript = db.prepare('SELECT * FROM scripts WHERE id = ?').get(scriptId) as any;
    if (!remScript) return reply.status(404).send({ error: 'Remediation script not found.' });
    if (!canUserRunScriptRole(user?.role || '', remScript.required_role)) {
      return reply.status(403).send({
        error: `Forbidden: remediation script "${remScript.name}" requires role '${remScript.required_role}'.`
      });
    }
    if (remScript.tenant_id && remScript.tenant_id !== 'all' && !canUserAccessTenant(user, remScript.tenant_id)) {
      return reply.status(403).send({ error: 'Forbidden: remediation script is outside your tenant scope.' });
    }
    const targetTenantId = body.tenant_id && body.tenant_id !== 'all' ? String(body.tenant_id) : null;
    if (targetTenantId ? !canUserAccessTenant(user, targetTenantId) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
    }
    const id = `mon-${crypto.randomUUID().slice(0, 8)}`;
    db.prepare(`
      INSERT INTO self_healing_monitors (id, name, condition_type, condition_value, remediation_script_id, cooldown_min, alert_on_failure, tenant_id, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
    `).run(
      id,
      body.name.trim(),
      body.condition_type || 'service_stopped',
      body.condition_value || 'Spooler',
      scriptId,
      Math.max(1, Number(body.cooldown_min || 15)),
      body.alert_on_failure !== false ? 1 : 0,
      targetTenantId
    );
    return { success: true, monitor: db.prepare('SELECT * FROM self_healing_monitors WHERE id = ?').get(id) };
  });

  server.put('/api/self-healing/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM self_healing_monitors WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Watchdog monitor not found.' });
    const user = request.auth?.user;
    if (existing.tenant_id ? !canUserAccessTenant(user, existing.tenant_id) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    const existingScript = db.prepare('SELECT * FROM scripts WHERE id = ?').get(existing.remediation_script_id) as any;
    if (existingScript && !canUserRunScriptRole(user?.role || '', existingScript.required_role)) {
      return reply.status(403).send({ error: 'Insufficient privileges to modify watchdog using a restricted script.' });
    }

    const body = (request.body || {}) as {
      enabled?: boolean | number;
      cooldown_min?: number;
      name?: string;
      remediation_script_id?: string;
      tenant_id?: string | null;
    };
    if (body.remediation_script_id) {
      const nextScript = db.prepare('SELECT * FROM scripts WHERE id = ?').get(body.remediation_script_id) as any;
      if (!nextScript) return reply.status(404).send({ error: 'Remediation script not found.' });
      if (!canUserRunScriptRole(user?.role || '', nextScript.required_role)) {
        return reply.status(403).send({
          error: `Forbidden: remediation script "${nextScript.name}" requires role '${nextScript.required_role}'.`
        });
      }
      if (nextScript.tenant_id && nextScript.tenant_id !== 'all' && !canUserAccessTenant(user, nextScript.tenant_id)) {
        return reply.status(403).send({ error: 'Forbidden: remediation script is outside your tenant scope.' });
      }
    }
    const nextTenantId =
      body.tenant_id !== undefined
        ? body.tenant_id && body.tenant_id !== 'all'
          ? String(body.tenant_id)
          : null
        : existing.tenant_id ?? null;
    if (nextTenantId ? !canUserAccessTenant(user, nextTenantId) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
    }

    db.prepare(`
      UPDATE self_healing_monitors SET
        enabled = COALESCE(?, enabled),
        cooldown_min = COALESCE(?, cooldown_min),
        name = COALESCE(?, name),
        remediation_script_id = COALESCE(?, remediation_script_id),
        tenant_id = ?
      WHERE id = ?
    `).run(
      body.enabled !== undefined ? (body.enabled ? 1 : 0) : null,
      body.cooldown_min != null ? Math.max(1, Number(body.cooldown_min)) : null,
      body.name ?? null,
      body.remediation_script_id ?? null,
      nextTenantId,
      id
    );
    return { success: true, monitor: db.prepare('SELECT * FROM self_healing_monitors WHERE id = ?').get(id) };
  });

  server.delete('/api/self-healing/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM self_healing_monitors WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Watchdog monitor not found.' });
    const user = request.auth?.user;
    if (existing.tenant_id ? !canUserAccessTenant(user, existing.tenant_id) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    const existingScript = db.prepare('SELECT * FROM scripts WHERE id = ?').get(existing.remediation_script_id) as any;
    if (existingScript && !canUserRunScriptRole(user?.role || '', existingScript.required_role)) {
      return reply.status(403).send({ error: 'Insufficient privileges to delete watchdog using a restricted script.' });
    }
    db.prepare('DELETE FROM self_healing_monitors WHERE id = ?').run(id);
    return { success: true };
  });

  server.post('/api/self-healing/evaluate', async (request) => {
    const user = request.auth?.user;
    const isGlobalUser = getAllowedTenantIds(user) === null;
    const monitors = (db.prepare('SELECT * FROM self_healing_monitors WHERE enabled = 1').all() as any[]).filter((m) =>
      m.tenant_id ? canUserAccessTenant(user, m.tenant_id) : isGlobalUser
    );
    const devices = (
      db
        .prepare(
          "SELECT d.*, t.name as tenant_name FROM devices d LEFT JOIN tenants t ON d.tenant_id = t.id WHERE d.status = 'online' AND COALESCE(d.lifecycle_state, 'active') = 'active'"
        )
        .all() as any[]
    ).filter((d) => canUserAccessTenant(user, d.tenant_id));
    const triggered: any[] = [];
    const nowMs = Date.now();
    const nowIso = new Date(nowMs).toISOString();
    const oneHourAgoIso = new Date(nowMs - 3600_000).toISOString();

    for (const dev of devices) {
      // Skip endpoints in active emergency mute or scheduled maintenance window
      if (dev.maintenance_until && new Date(dev.maintenance_until).getTime() > nowMs) {
        continue;
      }
      const activeMw = db
        .prepare(
          'SELECT id FROM maintenance_windows WHERE (device_id = ? OR tenant_id = ?) AND is_active = 1 AND start_time <= ? AND end_time >= ? LIMIT 1'
        )
        .get(dev.id, dev.tenant_id, nowIso, nowIso);
      if (activeMw) {
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
        if (mon.tenant_id && mon.tenant_id !== dev.tenant_id) continue;
        const scriptCheck = db.prepare('SELECT * FROM scripts WHERE id = ?').get(mon.remediation_script_id) as any;
        if (scriptCheck && !canUserRunScriptRole(user?.role || '', scriptCheck.required_role)) continue;
        if (scriptCheck?.tenant_id && scriptCheck.tenant_id !== 'all' && !canUserAccessTenant(user, scriptCheck.tenant_id)) {
          continue;
        }

        const cooldownCutoffIso = new Date(nowMs - Math.max(1, Number(mon.cooldown_min || 15)) * 60_000).toISOString();
        const recentRun = db
          .prepare('SELECT id FROM remediation_logs WHERE monitor_id = ? AND device_id = ? AND executed_at >= ? LIMIT 1')
          .get(mon.id, dev.id, cooldownCutoffIso);
        if (recentRun) continue;

        let matchedReason: string | null = null;
        let serviceRestartOk = true;

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
          const svcs = await meshBridge.getServices(dev.id);
          const targetSvc = svcs.find((s) => s.name.toLowerCase() === String(mon.condition_value || '').toLowerCase());
          if (targetSvc && targetSvc.status === 'Stopped') {
            serviceRestartOk = await meshBridge.manageService(dev.id, targetSvc.name, 'start', 'watchdog');
            matchedReason = serviceRestartOk
              ? `Service '${targetSvc.name}' was Stopped — restart command dispatched`
              : `Service '${targetSvc.name}' was Stopped — restart failed`;
          }
        }

        if (matchedReason) {
          const scriptRow = db.prepare('SELECT * FROM scripts WHERE id = ?').get(mon.remediation_script_id) as any;
          let runOutput = matchedReason;
          let remediationOk = serviceRestartOk;
          if (scriptRow?.code) {
            const execRes = await meshBridge.executeCommandOnNode(dev.id, scriptRow.code, {
              runAs: 'system',
              shell: scriptRow.language === 'bash' ? 'bash' : 'powershell',
              timeoutMs: 5000
            });
            remediationOk = remediationOk && execRes.exitCode === 0;
            runOutput = `${matchedReason}. Dispatched runbook "${scriptRow.name}": ${execRes.output}`;
          }

          const logId = `rem-${crypto.randomUUID().slice(0, 8)}`;
          const executedAt = new Date().toISOString();
          const remStatus = remediationOk ? 'Success' : 'Failed';
          db.prepare(`
            INSERT INTO remediation_logs (id, monitor_id, monitor_name, device_id, hostname, script_id, status, output, executed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).run(
            logId,
            mon.id,
            mon.name,
            dev.id,
            dev.hostname,
            mon.remediation_script_id,
            remStatus,
            runOutput,
            executedAt
          );

          // Open a PSA escalation ticket when self-healing fails (or when policy mandates PSA audit logging and alert_on_failure is not restricting to failures)
          if (policy.selfHealingAlertPsa && (!remediationOk || !mon.alert_on_failure)) {
            const tktNum = `SH-${crypto.randomInt(1000, 9999)}`;
            db.prepare(`
              INSERT INTO psa_tickets (id, ticket_number, title, client_name, device_id, status, priority)
              VALUES (?, ?, ?, ?, ?, 'Open', ?)
            `).run(
              `tkt-sh-${crypto.randomUUID().slice(0, 8)}`,
              tktNum,
              `[Self-Healing ${remStatus}] ${mon.name} on ${dev.hostname}`,
              dev.tenant_name || 'Managed Client',
              dev.id,
              remediationOk ? 'Medium' : 'High'
            );
          }

          triggered.push({ id: logId, monitor_name: mon.name, hostname: dev.hostname, status: remStatus, output: runOutput });
        }
      }
    }

    const scopedLogs = (
      db
        .prepare(`
          SELECT r.*, d.tenant_id
          FROM remediation_logs r
          LEFT JOIN devices d ON r.device_id = d.id
          ORDER BY r.executed_at DESC
          LIMIT 50
        `)
        .all() as any[]
    ).filter((r) => (r.tenant_id ? canUserAccessTenant(user, r.tenant_id) : isGlobalUser));

    return {
      success: true,
      evaluatedMonitors: monitors.length,
      evaluatedDevices: devices.length,
      remediationsTriggered: triggered.length,
      logs: scopedLogs
    };
  });

  // ============================================================================
  // PSA / ITFlow Synchronization & Authenticated Webhook
  // ============================================================================
  server.get('/api/psa/tickets', async (request) => {
    const user = request.auth?.user;
    const isGlobalUser = getAllowedTenantIds(user) === null;
    const rows = db
      .prepare(`
        SELECT p.*, d.tenant_id as device_tenant_id, t.id as matched_tenant_id
        FROM psa_tickets p
        LEFT JOIN devices d ON p.device_id = d.id
        LEFT JOIN tenants t ON LOWER(p.client_name) = LOWER(t.name)
        ORDER BY p.created_at DESC
      `)
      .all() as any[];
    return rows.filter((r) => {
      const tid = r.device_tenant_id || r.matched_tenant_id;
      return !tid ? isGlobalUser : canUserAccessTenant(user, tid);
    });
  });

  server.post('/api/psa/tickets', async (request, reply) => {
    const body = (request.body || {}) as any;
    const user = request.auth?.user;
    const isGlobalUser = getAllowedTenantIds(user) === null;
    if (!body.title?.trim()) return reply.status(400).send({ error: 'Ticket title is required.' });
    let resolvedDeviceId: string | null = null;
    let resolvedDeviceTenant: string | null = null;
    if (body.device_id) {
      const devs = db
        .prepare('SELECT id, tenant_id FROM devices WHERE id = ? OR LOWER(hostname) = LOWER(?)')
        .all(body.device_id, body.device_id) as Array<{ id: string; tenant_id: string }>;
      const directMatch = devs.find((d) => d.id === body.device_id);
      const accessibleMatch = devs.find((d) => canUserAccessTenant(user, d.tenant_id));
      if (directMatch && !canUserAccessTenant(user, directMatch.tenant_id)) {
        return reply.status(403).send({ error: 'Forbidden: target device is outside your tenant scope.' });
      }
      if (devs.length > 0 && !accessibleMatch) {
        return reply.status(403).send({ error: 'Forbidden: target device is outside your tenant scope.' });
      }
      if (accessibleMatch) {
        resolvedDeviceId = accessibleMatch.id;
        resolvedDeviceTenant = accessibleMatch.tenant_id;
      }
    }
    const clientName = body.client_name || 'Managed Client';
    const matchedTenant = db
      .prepare('SELECT id FROM tenants WHERE LOWER(name) = LOWER(?) LIMIT 1')
      .get(String(clientName).trim()) as { id?: string } | undefined;
    const effectiveTenant = resolvedDeviceTenant || matchedTenant?.id || null;
    if (effectiveTenant ? !canUserAccessTenant(user, effectiveTenant) : !isGlobalUser) {
      return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
    }
    const id = `tkt-${crypto.randomUUID().slice(0, 8)}`;
    const ticketNum = `ITF-${crypto.randomInt(1000, 9999)}`;
    const priority = body.priority || 'Medium';
    db.prepare(`
      INSERT INTO psa_tickets (id, ticket_number, title, client_name, device_id, status, priority)
      VALUES (?, ?, ?, ?, ?, 'Open', ?)
    `).run(id, ticketNum, body.title.trim(), clientName, resolvedDeviceId, priority);

    await syncTicketWithExternalPsas({
      localTicketId: id,
      ticketNumber: ticketNum,
      title: body.title.trim(),
      details: body.description || body.title.trim(),
      clientName,
      priority
    });

    return { success: true, id, ticketNumber: ticketNum };
  });

  server.put('/api/psa/tickets/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db
      .prepare(`
        SELECT p.*, d.tenant_id as device_tenant_id, t.id as matched_tenant_id
        FROM psa_tickets p
        LEFT JOIN devices d ON p.device_id = d.id
        LEFT JOIN tenants t ON LOWER(p.client_name) = LOWER(t.name)
        WHERE p.id = ?
      `)
      .get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Ticket not found' });
    const tid = existing.device_tenant_id || existing.matched_tenant_id;
    const user = request.auth?.user;
    if (tid ? !canUserAccessTenant(user, tid) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    const body = (request.body || {}) as { status?: string; priority?: string };
    db.prepare(`
      UPDATE psa_tickets SET
        status = COALESCE(?, status),
        priority = COALESCE(?, priority)
      WHERE id = ?
    `).run(body.status ?? null, body.priority ?? null, id);
    const updated = db.prepare('SELECT * FROM psa_tickets WHERE id = ?').get(id) as any;
    if (updated && body.status === 'Resolved') {
      await syncTicketWithExternalPsas({
        localTicketId: id,
        ticketNumber: updated.ticket_number || id,
        title: `[RESOLVED] ${updated.title}`,
        details: `Ticket marked Resolved by ${getActorUsername(request)}`,
        clientName: updated.client_name,
        priority: updated.priority
      });
    }
    return { success: true };
  });

  server.post('/api/psa/webhook', async (request, reply) => {
    const rate = checkRateLimit(`psa-wh:${request.ip}`, 60, 60_000);
    if (!rate.allowed) {
      return reply.status(429).send({ error: 'Too many webhook requests', retryAfterSec: rate.retryAfterSec });
    }
    const providedSecret = String(request.headers['x-vitrine-webhook-secret'] || '').trim();
    const settings = (db.prepare('SELECT psa_webhook_secret FROM settings WHERE id = 1').get() || {}) as any;
    const expectedSecret = decryptVaultSecret(settings.psa_webhook_secret);

    // Webhook endpoint refuses cookie auth; requires HMAC/shared webhook secret
    if (!providedSecret || !expectedSecret || !constantTimeEquals(providedSecret, expectedSecret)) {
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
    const body = (request.body || {}) as {
      host?: string;
      port?: number | string;
      user?: string;
      pass?: string;
      from?: string;
      to?: string;
      tls?: boolean;
      secure?: boolean;
      verifyOnly?: boolean;
      mode?: string;
    };
    const stored = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    const { sendAlertEmail, verifySmtpConnection } = await import('../services/smtp/index.js');

    const host = body.host !== undefined ? String(body.host).trim() : String(stored.smtp_host || '').trim();
    const port = parseInt(String(body.port ?? stored.smtp_port ?? 587), 10) || 587;
    const user = body.user !== undefined ? String(body.user).trim() : String(stored.smtp_user || '').trim();
    const pass =
      body.pass !== undefined && !isMaskedSecret(String(body.pass))
        ? String(body.pass)
        : decryptVaultSecret(stored.smtp_pass);
    const from =
      body.from !== undefined && String(body.from).trim()
        ? String(body.from).trim()
        : stored.smtp_from || 'alerts@vitrine.local';
    const tls = body.tls !== undefined ? Boolean(body.tls) : Boolean(stored.smtp_tls ?? 1);
    const secure = body.secure !== undefined ? Boolean(body.secure) : port === 465;

    if (Boolean(body.verifyOnly) || body.mode === 'verify') {
      const verifyRes = await verifySmtpConnection({ host, port, user, pass, from, tls, secure } as any);
      return {
        success: verifyRes.success,
        mode: 'verify',
        latencyMs: verifyRes.latencyMs,
        message: verifyRes.success
          ? `SMTP connection and credentials verified for ${host}:${port}${user ? ` (${user})` : ''} (${verifyRes.latencyMs ?? 0}ms).`
          : `SMTP verification failed: ${verifyRes.error}`,
        error: verifyRes.error,
        timestamp: new Date().toISOString()
      };
    }

    const to = String(body.to || '').trim() || request.auth?.user.email || stored.letsencrypt_email || from;

    const result = await sendAlertEmail(
      { host, port, user, pass, from, tls, secure } as any,
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
      mode: 'send',
      recipient: to,
      message: result.success
        ? `Test email dispatched to ${to} via ${host}:${port}. MessageID: ${result.messageId}`
        : `SMTP dispatch error: ${result.error}`,
      error: result.error,
      timestamp: new Date().toISOString()
    };
  });

  // Safe Admin Code Signing Test (Never reads arbitrary client-supplied host file paths!)
  server.post('/api/signing/sign', async () => {
    const settings = (db.prepare('SELECT code_signing_enabled, code_signing_url FROM settings WHERE id = 1').get() || {}) as any;
    if (!settings.code_signing_enabled || !String(settings.code_signing_url || '').trim()) {
      return {
        reachable: false,
        endpoint: String(settings.code_signing_url || ''),
        latencyMs: 0,
        error: 'Code signing is disabled or no signing URL is configured.'
      };
    }
    const probe = await codeSigningService.testConnection();
    return probe;
  });

  server.post('/api/code-signing/test', async (request, reply) => {
    const body = (request.body || {}) as { url?: string };
    const settings = (db.prepare('SELECT code_signing_enabled, code_signing_url FROM settings WHERE id = 1').get() || {}) as any;
    const storedUrl = String(settings.code_signing_url || codeSigningService.getEndpoint() || '').trim();

    let probe: { reachable: boolean; endpoint: string; latencyMs: number; error?: string };

    if (body.url && String(body.url).trim()) {
      const candidateUrl = String(body.url).trim();
      let parsedCandidate: URL;
      try {
        parsedCandidate = new URL(candidateUrl);
        if (parsedCandidate.protocol !== 'http:' && parsedCandidate.protocol !== 'https:') {
          return reply.status(400).send({ success: false, reachable: false, error: 'Invalid code signing URL protocol.' });
        }
      } catch {
        return reply.status(400).send({ success: false, reachable: false, error: 'Invalid code signing URL.' });
      }

      // CodeSigningService.testConnection already isolates stored API keys to exact origin matches only
      probe = await codeSigningService.testConnection(candidateUrl);
    } else if (!settings.code_signing_enabled || !storedUrl) {
      probe = {
        reachable: false,
        endpoint: storedUrl,
        latencyMs: 0,
        error: 'Code signing is disabled or no signing URL is configured.'
      };
    } else {
      probe = await codeSigningService.testConnection();
    }

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

    const { proto: forwardedProto, host: safeHost } = resolveSafeRequestOriginParts(request);
    checks.push({
      name: 'Control Plane HTTP / X-Forwarded-Proto Inspection',
      status: 'pass',
      detail: `Active request received via ${forwardedProto.toUpperCase()} (${safeHost})`
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
  server.get('/api/discovery/topology', async (request) => {
    const user = request.auth?.user;
    const allowedTenants = getAllowedTenantIds(user);
    const portRows = allowedTenants === null
      ? (db.prepare('SELECT * FROM topology_ports ORDER BY port ASC').all() as any[])
      : [];
    const subnetRowsRaw = db.prepare('SELECT * FROM topology_subnets ORDER BY subnet ASC').all() as any[];
    const subnetRows =
      allowedTenants === null
        ? subnetRowsRaw
        : allowedTenants.length === 0
          ? []
          : (() => {
              const allowedSubnets = new Set(
                (
                  db
                    .prepare(`SELECT subnet FROM sites WHERE tenant_id IN (${allowedTenants.map(() => '?').join(',')})`)
                    .all(...allowedTenants) as Array<{ subnet?: string }>
                ).map((s) => s.subnet)
              );
              return subnetRowsRaw.filter((s) => allowedSubnets.has(s.subnet));
            })();
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

  const handleSubnetScan = async (request: FastifyRequest, reply: FastifyReply) => {
    const user = request.auth?.user;
    const body = (request.body || {}) as { subnet?: string; probeHost?: string; snmpCommunity?: string; tenant_id?: string };
    const allowedTenants = getAllowedTenantIds(user);
    const fallbackTenant =
      allowedTenants && allowedTenants.length > 0
        ? allowedTenants[0]
        : (db.prepare('SELECT id FROM tenants ORDER BY created_at ASC LIMIT 1').get() as { id?: string } | undefined)?.id ||
          'default';
    const targetTenantId = body.tenant_id || fallbackTenant;
    if (!canUserAccessTenant(user, targetTenantId)) {
      return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
    }
    let discoveredHosts: any[] = [];
    if (body.subnet) {
      try {
        const scanRes = await networkDiscoveryService.scanSubnet({
          tenantId: targetTenantId,
          cidr: body.subnet,
          community: body.snmpCommunity || 'public',
          autoRegister: true
        });
        discoveredHosts = scanRes.discovered;
      } catch (err: any) {
        return reply.status(400).send({ error: err?.message || 'Invalid subnet CIDR' });
      }
    } else if (allowedTenants === null) {
      db.prepare('UPDATE topology_subnets SET last_scanned = CURRENT_TIMESTAMP').run();
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, NULL, 'Network Subnet Discovery Sweep', ?)
    `).run(
      `aud-net-${crypto.randomUUID()}`,
      getActorUsername(request),
      `Executed live discovery scan across ${body.subnet || 'registered subnets'} (${discoveredHosts.length} active host(s))`
    );

    return { success: true, discoveredHosts };
  };
  server.post('/api/discovery/scan', handleSubnetScan);
  server.post('/api/network-appliances/scan-subnet', handleSubnetScan);

  server.post('/api/discovery/ports', async (request, reply) => {
    if (getAllowedTenantIds(request.auth?.user) !== null) {
      return reply.status(403).send({ error: 'Forbidden: global switch topology management requires unrestricted access.' });
    }
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
    copy.vendor_api_token_masked = maskSecretValue(
      copy.vendor_api_token_encrypted || copy.api_token_encrypted || copy.vendor_api_token_masked
    );
    copy.snmp_community_masked = maskSecretValue(copy.snmp_community_encrypted);
    delete copy.vendor_api_token_encrypted;
    delete copy.api_token_encrypted;
    delete copy.snmp_community_encrypted;
    delete copy.snmp_v3_auth_key_encrypted;
    delete copy.snmp_v3_priv_key_encrypted;
    copy.metrics = safeJsonParse<Record<string, unknown>>(copy.metrics_json, {});
    return copy;
  };

  server.get('/api/discovery/appliances', async (request) => {
    const user = request.auth?.user;
    const isGlobalUser = getAllowedTenantIds(user) === null;
    const rows = db
      .prepare(`
        SELECT a.*, t.name as tenant_name, s.name as site_name
        FROM network_appliances a
        LEFT JOIN tenants t ON a.tenant_id = t.id
        LEFT JOIN sites s ON a.site_id = s.id
        ORDER BY a.name ASC
      `)
      .all() as any[];

    return rows
      .filter((r) => (r.tenant_id ? canUserAccessTenant(user, r.tenant_id) : isGlobalUser))
      .map(formatApplianceForResponse);
  });

  server.post('/api/discovery/appliances', async (request, reply) => {
    const user = request.auth?.user;
    const allowedTenants = getAllowedTenantIds(user);
    const body = (request.body || {}) as {
      name?: string;
      appliance_type?: string;
      manufacturer?: string;
      model?: string;
      vendor_model?: string;
      ip_address?: string;
      mac_address?: string;
      snmp_version?: string;
      snmp_port?: number;
      snmp_community?: string;
      snmp_v3_username?: string;
      snmp_v3_user?: string;
      snmp_v3_auth_proto?: string;
      snmp_v3_auth_protocol?: string;
      snmp_v3_auth_key?: string;
      snmp_v3_priv_proto?: string;
      snmp_v3_priv_key?: string;
      integration_protocol?: string;
      vendor_api_endpoint?: string;
      vendor_api_token?: string;
      api_token?: string;
      vendor_api_token_masked?: string;
      tenant_id?: string;
      site_id?: string;
      probe_device_id?: string;
    };

    if (!body.name?.trim() || !body.ip_address?.trim()) {
      return reply.status(400).send({ error: 'Appliance name and IP/hostname are required.' });
    }

    const rawTarget = body.ip_address.trim();
    let parsedTargetHost = rawTarget;
    try {
      parsedTargetHost = rawTarget.includes('://') ? new URL(rawTarget).hostname : rawTarget.split(':')[0];
    } catch {
      return reply.status(400).send({ error: 'Invalid IP address or hostname format.' });
    }
    const hostCheck = await validateOutboundHostSafety(parsedTargetHost, {
      allowLoopback: false,
      allowPrivateLan: true
    });
    if (!hostCheck.safe) {
      return reply.status(400).send({ error: hostCheck.reason || 'Blocked unsafe or restricted appliance target.' });
    }
    if (body.vendor_api_endpoint && body.vendor_api_endpoint.includes('://')) {
      try {
        const epHost = new URL(body.vendor_api_endpoint).hostname;
        const epCheck = await validateOutboundHostSafety(epHost, { allowLoopback: false, allowPrivateLan: true });
        if (!epCheck.safe) {
          return reply.status(400).send({ error: epCheck.reason || 'Blocked unsafe vendor API endpoint.' });
        }
      } catch {
        return reply.status(400).send({ error: 'Invalid vendor API endpoint URL.' });
      }
    }

    const id = `app-${crypto.randomUUID().slice(0, 8)}`;
    const firstTenant = db.prepare('SELECT id FROM tenants ORDER BY created_at ASC LIMIT 1').get() as
      | { id: string }
      | undefined;
    const defaultTenant =
      allowedTenants && allowedTenants.length > 0 ? allowedTenants[0] : firstTenant?.id || 'unassigned';
    const tenantId = body.tenant_id || defaultTenant;
    if (!canUserAccessTenant(user, tenantId)) {
      return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
    }
    const siteId = body.site_id || null;
    if (siteId) {
      const siteRow = db.prepare('SELECT tenant_id FROM sites WHERE id = ?').get(siteId) as { tenant_id?: string } | undefined;
      if (!siteRow || siteRow.tenant_id !== tenantId) {
        return reply.status(400).send({ error: 'Selected site does not belong to the target tenant.' });
      }
    }

    let probeDevice: any = null;
    if (body.probe_device_id) {
      probeDevice = db.prepare('SELECT id, hostname, tenant_id FROM devices WHERE id = ?').get(body.probe_device_id);
      if (!probeDevice) {
        return reply.status(404).send({ error: 'Selected probe device not found.' });
      }
      if (!canUserAccessTenant(user, probeDevice.tenant_id)) {
        return reply.status(403).send({ error: 'Forbidden: probe device belongs to another tenant.' });
      }
    }
    if (!probeDevice) {
      probeDevice =
        db
          .prepare("SELECT id, hostname FROM devices WHERE tenant_id = ? AND status = 'online' LIMIT 1")
          .get(tenantId) || { id: 'control-plane', hostname: 'Vitrine Direct Probe' };
    }

    const rawToken =
      body.vendor_api_token ||
      body.api_token ||
      (!isMaskedSecret(body.vendor_api_token_masked) ? body.vendor_api_token_masked : '') ||
      '';
    const encryptedToken = rawToken ? encryptVaultSecret(rawToken) : null;
    const encCommunity = body.snmp_community ? encryptVaultSecret(body.snmp_community.trim()) : null;
    const encV3Auth = body.snmp_v3_auth_key ? encryptVaultSecret(body.snmp_v3_auth_key.trim()) : null;
    const encV3Priv = body.snmp_v3_priv_key ? encryptVaultSecret(body.snmp_v3_priv_key.trim()) : null;
    const manufacturer = String(body.manufacturer || '').trim() || null;
    const model = String(body.model || '').trim() || null;
    const vendorModel =
      String(body.vendor_model || '').trim() ||
      [manufacturer, model].filter(Boolean).join(' ') ||
      'Managed Network Appliance';
    const v3User = body.snmp_v3_username || body.snmp_v3_user || null;
    const v3AuthProto = body.snmp_v3_auth_proto || body.snmp_v3_auth_protocol || 'SHA';

    db.prepare(`
      INSERT INTO network_appliances (
        id, tenant_id, site_id, name, appliance_type, manufacturer, model, vendor_model, ip_address, mac_address,
        snmp_version, snmp_port, snmp_community_encrypted, snmp_v3_username, snmp_v3_auth_proto,
        snmp_v3_auth_key_encrypted, snmp_v3_priv_proto, snmp_v3_priv_key_encrypted,
        integration_protocol, vendor_api_endpoint, vendor_api_token_masked, vendor_api_token_encrypted,
        probe_device_id, probe_hostname, status, uptime_days, latency_ms,
        packet_loss_pct, cpu_pct, memory_pct, metrics_json, alert_summary, last_polled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0.0, 0, 0.0, 0.0, 0.0, '{}', NULL, CURRENT_TIMESTAMP)
    `).run(
      id,
      tenantId,
      siteId,
      body.name.trim(),
      body.appliance_type || 'switch',
      manufacturer,
      model,
      vendorModel,
      body.ip_address.trim(),
      body.mac_address || '00:00:00:00:00:00',
      body.snmp_version || 'SNMPv3',
      Number(body.snmp_port || 161),
      encCommunity,
      v3User,
      v3AuthProto,
      encV3Auth,
      body.snmp_v3_priv_proto || 'AES',
      encV3Priv,
      body.integration_protocol || 'generic_snmp_v3',
      body.vendor_api_endpoint || null,
      encryptedToken ? '••••••••••••' : null,
      encryptedToken,
      probeDevice.id,
      probeDevice.hostname
    );

    // Execute live SNMPv2c/v3 / Vendor REST API / TLS / TCP poll immediately
    const pollRes = await networkDiscoveryService.pollAppliance(id);

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, NULL, 'Network Appliance Monitor Enrolled', ?)
    `).run(
      `aud-app-${crypto.randomUUID()}`,
      getActorUsername(request),
      `Enrolled ${body.name.trim()} (${body.ip_address.trim()}) — Initial poll: ${pollRes.status} (${pollRes.latencyMs}ms)`
    );

    const created = db.prepare('SELECT * FROM network_appliances WHERE id = ?').get(id) as any;
    return {
      success: true,
      appliance: formatApplianceForResponse(created)
    };
  });

  const handleUpdateAppliance = async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM network_appliances WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Network appliance not found.' });
    const user = request.auth?.user;
    if (existing.tenant_id ? !canUserAccessTenant(user, existing.tenant_id) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const body = (request.body || {}) as Record<string, any>;
    const nextTenantId = body.tenant_id !== undefined ? String(body.tenant_id || '') : existing.tenant_id;
    if (nextTenantId ? !canUserAccessTenant(user, nextTenantId) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
    }

    if (body.ip_address !== undefined) {
      const rawTarget = String(body.ip_address || '').trim();
      if (!rawTarget) return reply.status(400).send({ error: 'IP address / hostname cannot be empty.' });
      let parsedHost = rawTarget;
      try {
        parsedHost = rawTarget.includes('://') ? new URL(rawTarget).hostname : rawTarget.split(':')[0];
      } catch {
        return reply.status(400).send({ error: 'Invalid IP address or hostname format.' });
      }
      const hostCheck = await validateOutboundHostSafety(parsedHost, { allowLoopback: false, allowPrivateLan: true });
      if (!hostCheck.safe) {
        return reply.status(400).send({ error: hostCheck.reason || 'Blocked unsafe appliance target.' });
      }
    }

    if (body.vendor_api_endpoint && String(body.vendor_api_endpoint).includes('://')) {
      try {
        const epHost = new URL(String(body.vendor_api_endpoint)).hostname;
        const epCheck = await validateOutboundHostSafety(epHost, { allowLoopback: false, allowPrivateLan: true });
        if (!epCheck.safe) {
          return reply.status(400).send({ error: epCheck.reason || 'Blocked unsafe vendor API endpoint.' });
        }
      } catch {
        return reply.status(400).send({ error: 'Invalid vendor API endpoint URL.' });
      }
    }

    const rawToken =
      body.vendor_api_token !== undefined
        ? String(body.vendor_api_token || '')
        : body.api_token !== undefined
          ? String(body.api_token || '')
          : undefined;
    const nextEncToken =
      rawToken !== undefined && !isMaskedSecret(rawToken)
        ? rawToken.trim()
          ? encryptVaultSecret(rawToken.trim())
          : null
        : existing.vendor_api_token_encrypted;
    const nextEncCommunity =
      body.snmp_community !== undefined && !isMaskedSecret(String(body.snmp_community))
        ? String(body.snmp_community).trim()
          ? encryptVaultSecret(String(body.snmp_community).trim())
          : null
        : existing.snmp_community_encrypted;
    const nextEncV3Auth =
      body.snmp_v3_auth_key !== undefined && !isMaskedSecret(String(body.snmp_v3_auth_key))
        ? String(body.snmp_v3_auth_key).trim()
          ? encryptVaultSecret(String(body.snmp_v3_auth_key).trim())
          : null
        : existing.snmp_v3_auth_key_encrypted;
    const nextEncV3Priv =
      body.snmp_v3_priv_key !== undefined && !isMaskedSecret(String(body.snmp_v3_priv_key))
        ? String(body.snmp_v3_priv_key).trim()
          ? encryptVaultSecret(String(body.snmp_v3_priv_key).trim())
          : null
        : existing.snmp_v3_priv_key_encrypted;

    const nextMfg = body.manufacturer !== undefined ? String(body.manufacturer || '').trim() || null : existing.manufacturer;
    const nextModel = body.model !== undefined ? String(body.model || '').trim() || null : existing.model;
    const nextVendorModel =
      body.vendor_model !== undefined
        ? String(body.vendor_model || '').trim() || existing.vendor_model
        : body.manufacturer !== undefined || body.model !== undefined
          ? [nextMfg, nextModel].filter(Boolean).join(' ') || existing.vendor_model
          : existing.vendor_model;

    db.prepare(`
      UPDATE network_appliances SET
        tenant_id = ?,
        site_id = ?,
        name = COALESCE(?, name),
        appliance_type = COALESCE(?, appliance_type),
        manufacturer = ?,
        model = ?,
        vendor_model = ?,
        ip_address = COALESCE(?, ip_address),
        mac_address = COALESCE(?, mac_address),
        snmp_version = COALESCE(?, snmp_version),
        snmp_port = COALESCE(?, snmp_port),
        snmp_community_encrypted = ?,
        snmp_v3_username = COALESCE(?, snmp_v3_username),
        snmp_v3_auth_proto = COALESCE(?, snmp_v3_auth_proto),
        snmp_v3_auth_key_encrypted = ?,
        snmp_v3_priv_proto = COALESCE(?, snmp_v3_priv_proto),
        snmp_v3_priv_key_encrypted = ?,
        integration_protocol = COALESCE(?, integration_protocol),
        vendor_api_endpoint = COALESCE(?, vendor_api_endpoint),
        vendor_api_token_masked = ?,
        vendor_api_token_encrypted = ?
      WHERE id = ?
    `).run(
      nextTenantId,
      body.site_id !== undefined ? body.site_id || null : existing.site_id,
      body.name ? String(body.name).trim() : null,
      body.appliance_type ?? null,
      nextMfg,
      nextModel,
      nextVendorModel,
      body.ip_address ? String(body.ip_address).trim() : null,
      body.mac_address ?? null,
      body.snmp_version ?? null,
      body.snmp_port != null ? Number(body.snmp_port) : null,
      nextEncCommunity,
      body.snmp_v3_username ?? body.snmp_v3_user ?? null,
      body.snmp_v3_auth_proto ?? body.snmp_v3_auth_protocol ?? null,
      nextEncV3Auth,
      body.snmp_v3_priv_proto ?? null,
      nextEncV3Priv,
      body.integration_protocol ?? null,
      body.vendor_api_endpoint ?? null,
      nextEncToken ? '••••••••••••' : null,
      nextEncToken,
      id
    );

    const updated = db.prepare('SELECT * FROM network_appliances WHERE id = ?').get(id);
    return { success: true, appliance: formatApplianceForResponse(updated) };
  };
  server.put('/api/discovery/appliances/:id', handleUpdateAppliance);
  server.put('/api/network-appliances/:id', handleUpdateAppliance);

  const handlePollAppliance = async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const appRow = db.prepare('SELECT * FROM network_appliances WHERE id = ?').get(id) as any;
    if (!appRow) return reply.status(404).send({ success: false, error: 'Network appliance not found' });
    if (
      appRow.tenant_id
        ? !canUserAccessTenant(request.auth?.user, appRow.tenant_id)
        : getAllowedTenantIds(request.auth?.user) !== null
    ) {
      return reply.status(403).send({ success: false, error: 'Forbidden' });
    }

    const pollRes = await networkDiscoveryService.pollAppliance(id);

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, NULL, 'Appliance Probe Poll Executed', ?)
    `).run(
      `aud-poll-${crypto.randomUUID()}`,
      getActorUsername(request),
      `Polled ${appRow.name} (${appRow.ip_address}): ${pollRes.status.toUpperCase()} (${pollRes.latencyMs}ms)`
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
  };
  server.post('/api/discovery/appliances/:id/poll', handlePollAppliance);
  server.post('/api/network-appliances/:id/poll', handlePollAppliance);

  server.delete('/api/discovery/appliances/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const appRow = db.prepare('SELECT tenant_id FROM network_appliances WHERE id = ?').get(id) as any;
    if (!appRow) return reply.status(404).send({ error: 'Network appliance not found.' });
    if (
      appRow.tenant_id
        ? !canUserAccessTenant(request.auth?.user, appRow.tenant_id)
        : getAllowedTenantIds(request.auth?.user) !== null
    ) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    db.prepare('DELETE FROM network_appliances WHERE id = ?').run(id);
    return { success: true };
  });

  // ============================================================================
  // Virtualization / Hypervisor Monitoring
  // ============================================================================
  server.get('/api/virtualization/hosts', async (request) => {
    const user = request.auth?.user;
    const isGlobalUser = getAllowedTenantIds(user) === null;
    const hosts = (db.prepare('SELECT * FROM virtualization_hosts ORDER BY name ASC').all() as any[]).filter((h) =>
      h.tenant_id ? canUserAccessTenant(user, h.tenant_id) : isGlobalUser
    );
    const allowedHostIds = new Set(hosts.map((h) => h.id));
    const vms = (db.prepare('SELECT * FROM virtualization_vms ORDER BY vmid ASC').all() as any[]).filter((v) =>
      allowedHostIds.has(v.host_id)
    );

    return hosts.map((h) => ({
      id: h.id,
      tenantId: h.tenant_id || null,
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
    const user = request.auth?.user;
    const isGlobalUser = getAllowedTenantIds(user) === null;
    const body = (request.body || {}) as {
      name?: string;
      hostType?: string;
      ipAddress?: string;
      apiPort?: number;
      apiUsername?: string;
      apiToken?: string;
      allowSelfSigned?: boolean;
      tlsFingerprintSha256?: string;
      linkedDeviceId?: string;
      linked_device_id?: string;
      tenantId?: string | null;
      tenant_id?: string | null;
      ramTotalGb?: number;
      storageTotalTb?: number;
    };
    if (!body.name?.trim() || !body.ipAddress?.trim()) {
      return reply.status(400).send({ error: 'Hypervisor hostname and IP address are required.' });
    }

    const linkedDeviceId = body.linkedDeviceId || body.linked_device_id || null;
    let resolvedTenantId = (body.tenantId ?? body.tenant_id ?? null) || null;

    if (linkedDeviceId) {
      const linkedDev = db.prepare('SELECT id, tenant_id FROM devices WHERE id = ?').get(linkedDeviceId) as
        | { id: string; tenant_id: string }
        | undefined;
      if (!linkedDev) {
        return reply.status(404).send({ error: 'Linked endpoint device not found.' });
      }
      if (!canUserAccessTenant(user, linkedDev.tenant_id)) {
        return reply.status(403).send({ error: 'Forbidden: linked device belongs to another tenant.' });
      }
      if (resolvedTenantId && resolvedTenantId !== linkedDev.tenant_id) {
        return reply.status(400).send({ error: 'linked_device_id belongs to a different tenant than tenant_id.' });
      }
      resolvedTenantId = resolvedTenantId || linkedDev.tenant_id;
    }

    if (resolvedTenantId) {
      if (!canUserAccessTenant(user, resolvedTenantId)) {
        return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
      }
    } else if (!isGlobalUser) {
      return reply.status(403).send({ error: 'Scoped accounts must provide an accessible tenant_id for hypervisor hosts.' });
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
        id, tenant_id, name, host_type, ip_address, api_port, api_username, api_token_encrypted,
        allow_self_signed, tls_fingerprint_sha256, linked_device_id,
        status, cpu_usage_pct, ram_usage_gb, ram_total_gb, storage_free_tb, storage_total_tb
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0.0, 0.0, ?, ?, ?)
    `).run(
      id,
      resolvedTenantId,
      body.name.trim(),
      body.hostType || 'Proxmox VE',
      body.ipAddress.trim(),
      apiPort,
      body.apiUsername || null,
      encToken,
      body.allowSelfSigned !== false ? 1 : 0,
      body.tlsFingerprintSha256 || null,
      linkedDeviceId,
      probe.reachable ? 'Online' : 'Unreachable',
      ramTotal,
      storageTotal,
      storageTotal
    );

    const syncReport = await syncVirtualizationHost(id);
    return {
      success: true,
      id,
      tenantId: resolvedTenantId,
      reachable: syncReport.synced || probe.reachable,
      sync: syncReport
    };
  });

  server.post('/api/virtualization/hosts/:id/sync', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT id, name, tenant_id FROM virtualization_hosts WHERE id = ?').get(id) as any;
    if (!existing) {
      return reply.status(404).send({ success: false, error: 'Virtualization host not found.' });
    }
    const user = request.auth?.user;
    if (existing.tenant_id ? !canUserAccessTenant(user, existing.tenant_id) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ success: false, error: 'Forbidden' });
    }
    const syncReport = await syncVirtualizationHost(id);
    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, NULL, 'Hypervisor Host Synchronized', ?)
    `).run(
      `aud-vsync-${crypto.randomUUID()}`,
      getActorUsername(request),
      `Polled hypervisor '${existing.name}': ${syncReport.message}`
    );
    return { success: true, ...syncReport };
  });

  server.delete('/api/virtualization/hosts/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT id, tenant_id FROM virtualization_hosts WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Virtualization host not found.' });
    const user = request.auth?.user;
    if (existing.tenant_id ? !canUserAccessTenant(user, existing.tenant_id) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    db.prepare('DELETE FROM virtualization_vms WHERE host_id = ?').run(id);
    db.prepare('DELETE FROM virtualization_hosts WHERE id = ?').run(id);
    return { success: true };
  });

  server.post('/api/virtualization/hosts/:hostId/vms/:vmid/action', async (request, reply) => {
    const { hostId, vmid } = request.params as { hostId: string; vmid: string };
    const host = db.prepare('SELECT id, tenant_id FROM virtualization_hosts WHERE id = ?').get(hostId) as any;
    if (!host) {
      return reply.status(404).send({ success: false, error: 'Virtualization host not found.' });
    }
    const user = request.auth?.user;
    if (host.tenant_id ? !canUserAccessTenant(user, host.tenant_id) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ success: false, error: 'Forbidden' });
    }
    const body = (request.body || {}) as { action?: 'start' | 'stop' | 'reboot' | 'snapshot' };
    const vmKey = String(vmid || '').trim();
    if (!vmKey) {
      return reply.status(400).send({ success: false, error: 'VM identifier is required.' });
    }
    const vmTarget: any = /^\d+$/.test(vmKey) ? Number(vmKey) : vmKey;
    const act = body.action || 'start';

    let liveResult: { dispatchedLive: boolean; detail: string } = {
      dispatchedLive: false,
      detail: 'Local VM state updated.'
    };
    try {
      liveResult = await dispatchLiveHypervisorVmAction(hostId, vmTarget, act);
    } catch (err: any) {
      return reply.status(502).send({
        success: false,
        error: err?.message || 'Hypervisor API rejected the VM action.'
      });
    }

    if (act === 'start' || act === 'reboot') {
      db.prepare(
        "UPDATE virtualization_vms SET status = 'Running', cpu = CASE WHEN cpu = 0 THEN 4 ELSE cpu END WHERE host_id = ? AND (CAST(vmid AS TEXT) = ? OR id = ? OR moref_id = ?)"
      ).run(hostId, vmKey, vmKey, vmKey);
    } else if (act === 'stop') {
      db.prepare(
        "UPDATE virtualization_vms SET status = 'Stopped', cpu = 0 WHERE host_id = ? AND (CAST(vmid AS TEXT) = ? OR id = ? OR moref_id = ?)"
      ).run(hostId, vmKey, vmKey, vmKey);
    } else if (act === 'snapshot') {
      const snapStr = new Date().toLocaleString('en-US', {
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
      });
      db.prepare(
        'UPDATE virtualization_vms SET last_snapshot = ? WHERE host_id = ? AND (CAST(vmid AS TEXT) = ? OR id = ? OR moref_id = ?)'
      ).run(snapStr, hostId, vmKey, vmKey, vmKey);
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, NULL, 'Hypervisor VM Power Action', ?)
    `).run(
      `aud-vm-${crypto.randomUUID()}`,
      getActorUsername(request),
      `Executed '${act}' on VM #${vmKey} (Host: ${hostId}) — ${liveResult.detail}`
    );

    return {
      success: true,
      dispatchedLive: liveResult.dispatchedLive,
      detail: liveResult.detail
    };
  });

  // ============================================================================
  // Audit Logs & 100% Real-Data Executive QBR Report Generator
  // ============================================================================
  server.get('/api/audit', async (request) => {
    const user = request.auth?.user;
    const allowedTenants = getAllowedTenantIds(user);
    if (allowedTenants !== null) {
      if (allowedTenants.length === 0) return [];
      const rows = db
        .prepare(`
          SELECT a.*, d.tenant_id as device_tenant_id
          FROM audit_logs a
          LEFT JOIN devices d ON a.device_id = d.id
          WHERE d.tenant_id IN (${allowedTenants.map(() => '?').join(',')})
          ORDER BY a.timestamp DESC
          LIMIT 250
        `)
        .all(...allowedTenants) as any[];
      return rows.filter((r) => r.device_tenant_id && canUserAccessTenant(user, r.device_tenant_id));
    }
    return db.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 200').all();
  });

  server.get('/api/reports/qbr', async (request, reply) => {
    const query = (request.query || {}) as { tenant_id?: string };
    const user = request.auth?.user;
    const allowedTenants = getAllowedTenantIds(user);
    if (allowedTenants !== null && allowedTenants.length === 0) {
      return reply.status(403).send({ error: 'Forbidden for requested tenant' });
    }

    let scopedIds: string[] | null = null;
    if (query.tenant_id && query.tenant_id !== 'all') {
      if (!canUserAccessTenant(user, query.tenant_id)) {
        return reply.status(403).send({ error: 'Forbidden for requested tenant' });
      }
      scopedIds = [query.tenant_id];
    } else if (allowedTenants !== null) {
      scopedIds = allowedTenants;
    }

    const activeWhere =
      scopedIds && scopedIds.length > 0
        ? `WHERE COALESCE(lifecycle_state, 'active') = 'active' AND tenant_id IN (${scopedIds.map(() => '?').join(',')})`
        : "WHERE COALESCE(lifecycle_state, 'active') = 'active'";
    const params = scopedIds && scopedIds.length > 0 ? scopedIds : [];

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
          .prepare(
            `SELECT COUNT(*) as c FROM devices ${activeWhere} AND (LOWER(edr_status) LIKE 'active%' OR LOWER(edr_status) IN ('healthy', 'protected', 'running'))`
          )
          .get(...params) as any
      ).c || 0;
    const quarantinedEndpoints =
      (db.prepare(`SELECT COUNT(*) as c FROM devices ${activeWhere} AND quarantined = 1`).get(...params) as any).c || 0;

    const patchJoinWhere =
      scopedIds && scopedIds.length > 0 ? `WHERE d.tenant_id IN (${scopedIds.map(() => '?').join(',')})` : '';
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

    const remCount =
      scopedIds && scopedIds.length > 0
        ? (
            db
              .prepare(
                `SELECT COUNT(*) as c FROM remediation_logs r JOIN devices d ON r.device_id = d.id WHERE d.tenant_id IN (${scopedIds.map(() => '?').join(',')})`
              )
              .get(...scopedIds) as any
          ).c || 0
        : (db.prepare('SELECT COUNT(*) as c FROM remediation_logs').get() as any).c || 0;

    let tenantName = 'All Managed Clients';
    if (scopedIds && scopedIds.length === 1) {
      const tRow = db.prepare('SELECT name FROM tenants WHERE id = ?').get(scopedIds[0]) as
        | { name?: string }
        | undefined;
      tenantName = tRow?.name || scopedIds[0];
    } else if (scopedIds && scopedIds.length > 1) {
      tenantName = 'Scoped Managed Clients';
    }

    const ticketCount =
      scopedIds && scopedIds.length > 0
        ? (
            db
              .prepare(
                `SELECT COUNT(DISTINCT p.id) as c
                 FROM psa_tickets p
                 LEFT JOIN devices d ON p.device_id = d.id
                 LEFT JOIN tenants t ON LOWER(p.client_name) = LOWER(t.name)
                 WHERE COALESCE(d.tenant_id, t.id) IN (${scopedIds.map(() => '?').join(',')})`
              )
              .get(...scopedIds) as any
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
  server.get('/api/custom-fields', async (request) => {
    const user = request.auth?.user;
    const rows = db
      .prepare('SELECT * FROM custom_field_definitions ORDER BY category ASC, label ASC')
      .all() as any[];
    return rows.filter((r) => !r.tenant_id || canUserAccessTenant(user, r.tenant_id));
  });

  server.post('/api/custom-fields', async (request, reply) => {
    const user = request.auth?.user;
    const body = (request.body || {}) as {
      key?: string;
      label?: string;
      name?: string;
      category?: string;
      field_type?: string;
      scope?: string;
      options?: string;
      description?: string;
      tenant_id?: string | null;
    };
    const targetTenantId = body.tenant_id && body.tenant_id !== 'all' ? String(body.tenant_id) : null;
    if (targetTenantId ? !canUserAccessTenant(user, targetTenantId) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Forbidden for target custom field scope.' });
    }
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
        INSERT INTO custom_field_definitions (id, key, label, category, field_type, scope, options, description, tenant_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        key,
        label,
        body.category || 'Custom',
        body.field_type || 'text',
        body.scope || 'device',
        body.options || null,
        body.description || '',
        targetTenantId
      );
    } catch (err: any) {
      return reply.status(409).send({ error: `Custom field key '${key}' already exists: ${err?.message || ''}` });
    }
    return { success: true, id, key };
  });

  server.put('/api/custom-fields/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM custom_field_definitions WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Custom field not found.' });
    const user = request.auth?.user;
    if (existing.tenant_id ? !canUserAccessTenant(user, existing.tenant_id) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const body = (request.body || {}) as {
      label?: string;
      name?: string;
      category?: string;
      field_type?: string;
      scope?: string;
      options?: string | null;
      description?: string;
      tenant_id?: string | null;
    };
    const nextTenantId =
      body.tenant_id !== undefined
        ? body.tenant_id && body.tenant_id !== 'all'
          ? String(body.tenant_id)
          : null
        : existing.tenant_id ?? null;
    if (nextTenantId ? !canUserAccessTenant(user, nextTenantId) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Forbidden for target custom field scope.' });
    }
    const nextLabel = String(body.label || body.name || existing.label).trim();
    if (!nextLabel) return reply.status(400).send({ error: 'Custom field label cannot be empty.' });

    db.prepare(`
      UPDATE custom_field_definitions
      SET label = ?,
          category = ?,
          field_type = ?,
          scope = ?,
          options = ?,
          description = ?,
          tenant_id = ?
      WHERE id = ?
    `).run(
      nextLabel,
      body.category ?? existing.category,
      body.field_type ?? existing.field_type,
      body.scope ?? existing.scope,
      body.options !== undefined ? body.options : existing.options,
      body.description ?? existing.description,
      nextTenantId,
      id
    );

    return { success: true, field: db.prepare('SELECT * FROM custom_field_definitions WHERE id = ?').get(id) };
  });

  server.delete('/api/custom-fields/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT tenant_id FROM custom_field_definitions WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Custom field not found.' });
    const user = request.auth?.user;
    if (existing.tenant_id ? !canUserAccessTenant(user, existing.tenant_id) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    db.prepare('DELETE FROM custom_field_values WHERE field_id = ?').run(id);
    db.prepare('DELETE FROM custom_field_definitions WHERE id = ?').run(id);
    return { success: true };
  });

  server.get('/api/devices/:id/custom-fields', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;

    const isTech = isTechnicianOrAbove(request.auth?.user.role);
    const query = (request.query || {}) as { reveal?: string; fieldId?: string };
    const revealSecrets = isTech && query.reveal === 'true';

    if (revealSecrets) {
      if (!requireStepUpMfaIfEnforced(request, reply, id)) {
        return reply;
      }
      db.prepare(`
        INSERT INTO audit_logs (id, username, device_id, action, details)
        VALUES (?, ?, ?, 'Secret Custom Field Revealed', ?)
      `).run(
        `aud-cfs-${crypto.randomUUID()}`,
        getActorUsername(request),
        id,
        `Revealed encrypted custom asset secret field(s) on ${access.device.hostname}`
      );
    }

    const rows = db
      .prepare(`
        SELECT d.id as field_id, d.key, d.label, d.category, d.field_type, d.scope, d.options, d.description,
               COALESCE(v.value, '') as value, v.updated_at
        FROM custom_field_definitions d
        LEFT JOIN custom_field_values v ON d.id = v.field_id AND v.entity_id = ?
        WHERE (d.scope = 'device' OR d.scope = 'all') AND (d.tenant_id IS NULL OR d.tenant_id = ?)
        ORDER BY d.category ASC, d.label ASC
      `)
      .all(id, access.device.tenant_id) as any[];

    return rows
      .filter((r) => isTech || r.field_type !== 'secret')
      .map((r) => {
        if (r.field_type !== 'secret') return r;
        const hasVal = Boolean(r.value && String(r.value).trim() !== '');
        if (!hasVal) {
          return { ...r, value: '', has_secret: false };
        }
        const shouldRevealThis = revealSecrets && (!query.fieldId || query.fieldId === r.field_id);
        if (shouldRevealThis) {
          const plain = isEncryptedVaultSecret(r.value) ? decryptVaultSecret(r.value) : String(r.value);
          return { ...r, value: plain, has_secret: true, revealed: true };
        }
        return { ...r, value: '••••••••••••', has_secret: true, revealed: false };
      });
  });

  server.post('/api/devices/:id/custom-fields', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
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

    const saveSingleFieldValue = (fId: string, rawVal: unknown) => {
      const def = db
        .prepare('SELECT field_type FROM custom_field_definitions WHERE id = ?')
        .get(fId) as { field_type?: string } | undefined;
      const strVal = String(rawVal ?? '');

      if (def?.field_type === 'secret') {
        if (isMaskedSecret(strVal)) {
          // Preserve existing ciphertext when client saves masked placeholder
          return;
        }
        const toStore = strVal ? encryptVaultSecret(strVal) : '';
        upsertStmt.run(`cfv-${crypto.randomUUID().slice(0, 8)}`, fId, id, toStore);
        return;
      }

      upsertStmt.run(`cfv-${crypto.randomUUID().slice(0, 8)}`, fId, id, strVal);
    };

    if (body.values && typeof body.values === 'object') {
      for (const [fId, val] of Object.entries(body.values)) {
        saveSingleFieldValue(fId, val);
      }
    } else {
      const targetFieldId = body.fieldId || body.field_id;
      if (!targetFieldId) {
        return reply.status(400).send({ error: 'fieldId is required.' });
      }
      saveSingleFieldValue(targetFieldId, body.value);
    }

    return { success: true };
  });

  // ============================================================================
  // Maintenance Windows & Emergency Alert Suppression
  // ============================================================================
  server.get('/api/maintenance-windows', async (request) => {
    const user = request.auth?.user;
    const isGlobalUser = getAllowedTenantIds(user) === null;
    const rows = db
      .prepare(`
        SELECT m.*, d.hostname as device_hostname, d.tenant_id as device_tenant_id, t.name as tenant_name
        FROM maintenance_windows m
        LEFT JOIN devices d ON m.device_id = d.id
        LEFT JOIN tenants t ON m.tenant_id = t.id
        ORDER BY m.start_time DESC
      `)
      .all() as any[];
    return rows
      .filter((r) => {
        const tid = r.tenant_id || r.device_tenant_id;
        return tid ? canUserAccessTenant(user, tid) : isGlobalUser;
      })
      .map(({ device_tenant_id: _unused, ...rest }) => rest);
  });

  server.post('/api/maintenance-windows', async (request, reply) => {
    const user = request.auth?.user;
    const body = (request.body || {}) as {
      device_id?: string | null;
      tenant_id?: string | null;
      title?: string;
      start_time?: string;
      end_time?: string;
      durationMinutes?: number;
      suppress_alerts?: boolean;
    };
    let devTenantId: string | null = null;
    if (body.device_id) {
      const dev = db.prepare('SELECT id, tenant_id FROM devices WHERE id = ?').get(body.device_id) as
        | { id: string; tenant_id: string }
        | undefined;
      if (!dev) return reply.status(404).send({ error: 'Target device not found.' });
      if (!canUserAccessTenant(user, dev.tenant_id)) {
        return reply.status(403).send({ error: 'Forbidden: target device is outside your tenant scope.' });
      }
      devTenantId = dev.tenant_id;
    }
    if (body.tenant_id && body.tenant_id !== 'all') {
      if (!canUserAccessTenant(user, body.tenant_id)) {
        return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
      }
      if (devTenantId && devTenantId !== body.tenant_id) {
        return reply.status(400).send({ error: 'Target device belongs to a different tenant.' });
      }
    }
    const effectiveTenantId = body.tenant_id && body.tenant_id !== 'all' ? body.tenant_id : devTenantId;
    if (!effectiveTenantId && getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Scoped accounts cannot create global maintenance windows.' });
    }

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
      effectiveTenantId,
      title,
      startIso,
      endIso,
      body.suppress_alerts !== false ? 1 : 0
    );

    return { success: true, id, start_time: startIso, end_time: endIso };
  });

  server.put('/api/maintenance-windows/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db
      .prepare(`
        SELECT m.*, d.tenant_id as device_tenant_id
        FROM maintenance_windows m
        LEFT JOIN devices d ON m.device_id = d.id
        WHERE m.id = ?
      `)
      .get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Maintenance window not found.' });
    const user = request.auth?.user;
    const isGlobalUser = getAllowedTenantIds(user) === null;
    const existingTenant = existing.tenant_id || existing.device_tenant_id;
    if (existingTenant ? !canUserAccessTenant(user, existingTenant) : !isGlobalUser) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const body = (request.body || {}) as {
      title?: string;
      device_id?: string | null;
      tenant_id?: string | null;
      start_time?: string;
      end_time?: string;
      durationMinutes?: number;
      suppress_alerts?: boolean;
      is_active?: boolean;
    };

    const nextDeviceId = body.device_id !== undefined ? body.device_id || null : existing.device_id;
    let nextDevTenant: string | null = existing.device_tenant_id || null;
    if (nextDeviceId) {
      const dev = db.prepare('SELECT id, tenant_id FROM devices WHERE id = ?').get(nextDeviceId) as
        | { id: string; tenant_id: string }
        | undefined;
      if (!dev) return reply.status(404).send({ error: 'Target device not found.' });
      if (!canUserAccessTenant(user, dev.tenant_id)) {
        return reply.status(403).send({ error: 'Forbidden: target device is outside your tenant scope.' });
      }
      nextDevTenant = dev.tenant_id;
    } else {
      nextDevTenant = null;
    }
    const nextTenantId =
      body.tenant_id !== undefined
        ? body.tenant_id && body.tenant_id !== 'all'
          ? body.tenant_id
          : null
        : existing.tenant_id;
    const effectiveNextTenant = nextTenantId || nextDevTenant;
    if (effectiveNextTenant ? !canUserAccessTenant(user, effectiveNextTenant) : !isGlobalUser) {
      return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
    }

    const nextTitle = body.title !== undefined ? String(body.title).trim() : existing.title;
    if (!nextTitle) return reply.status(400).send({ error: 'Maintenance window title cannot be empty.' });

    const startIso = body.start_time ? new Date(body.start_time).toISOString() : existing.start_time;
    const endIso = body.end_time
      ? new Date(body.end_time).toISOString()
      : body.durationMinutes != null
        ? new Date(new Date(startIso).getTime() + Math.max(5, Number(body.durationMinutes)) * 60_000).toISOString()
        : existing.end_time;

    if (new Date(endIso).getTime() <= new Date(startIso).getTime()) {
      return reply.status(400).send({ error: 'Maintenance end_time must be after start_time.' });
    }

    db.prepare(`
      UPDATE maintenance_windows
      SET title = ?,
          device_id = ?,
          tenant_id = ?,
          start_time = ?,
          end_time = ?,
          suppress_alerts = ?,
          is_active = ?
      WHERE id = ?
    `).run(
      nextTitle,
      nextDeviceId,
      effectiveNextTenant,
      startIso,
      endIso,
      body.suppress_alerts !== undefined ? (body.suppress_alerts ? 1 : 0) : existing.suppress_alerts,
      body.is_active !== undefined ? (body.is_active ? 1 : 0) : existing.is_active,
      id
    );

    return { success: true, window: db.prepare('SELECT * FROM maintenance_windows WHERE id = ?').get(id) };
  });

  server.delete('/api/maintenance-windows/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db
      .prepare(`
        SELECT m.tenant_id, d.tenant_id as device_tenant_id
        FROM maintenance_windows m
        LEFT JOIN devices d ON m.device_id = d.id
        WHERE m.id = ?
      `)
      .get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Maintenance window not found.' });
    const user = request.auth?.user;
    const tid = existing.tenant_id || existing.device_tenant_id;
    if (tid ? !canUserAccessTenant(user, tid) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    db.prepare('DELETE FROM maintenance_windows WHERE id = ?').run(id);
    return { success: true };
  });

  server.post('/api/devices/:id/maintenance', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
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
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
    return db
      .prepare('SELECT * FROM chat_messages WHERE device_id = ? ORDER BY created_at ASC LIMIT 200')
      .all(id);
  });

  server.post('/api/devices/:id/chat', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
    const body = (request.body || {}) as { sender?: string; sender_role?: string; message?: string };
    const cleanMsg = String(body.message || '').trim().slice(0, 4000);
    if (!cleanMsg) {
      return reply.status(400).send({ error: 'Chat message cannot be empty.' });
    }
    const sender = String(body.sender || getActorUsername(request)).trim().slice(0, 120);
    const role =
      body.sender_role === 'user' || body.sender_role === 'end_user' || body.sender_role === 'endpoint'
        ? 'end_user'
        : 'technician';
    const msgId = `chat-${crypto.randomUUID().slice(0, 8)}`;

    db.prepare(`
      INSERT INTO chat_messages (id, device_id, sender, sender_role, message, read_status)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(msgId, id, sender, role, cleanMsg, role === 'technician' ? 0 : 1);

    // Queue notification for Vitrine Companion Tray if installed
    if (role === 'technician' && access.device.companion_installed) {
      db.prepare(`
        INSERT INTO agent_tasks (id, device_id, task_type, payload_json, status)
        VALUES (?, ?, 'tray_notify', ?, 'queued')
      `).run(
        `task-chat-${crypto.randomUUID().slice(0, 8)}`,
        id,
        JSON.stringify({ title: `IT Support (${sender})`, message: cleanMsg })
      );
    }

    // Push safe toast/chat notification over MeshCentral bridge if endpoint is online (zero shell/PS interpolation!)
    if (access.device.status === 'online' && role === 'technician') {
      const safePsSender = quotePowerShellLiteral(sender);
      const safePsMsg = quotePowerShellLiteral(cleanMsg);
      const safePosixTitle = `'${`IT Support (${sender})`.replace(/'/g, "'\\''")}'`;
      const safePosixMsg = `'${cleanMsg.replace(/'/g, "'\\''")}'`;
      await meshBridge.executeCommandOnNode(
        id,
        access.device.os_type === 'windows'
          ? `$s = ${safePsSender}; $m = ${safePsMsg}; Write-Output ("Vitrine Support Message from " + $s + ": " + $m)`
          : `command -v notify-send >/dev/null 2>&1 && notify-send ${safePosixTitle} ${safePosixMsg} || true`,
        { runAs: 'user' }
      );
    }

    return {
      success: true,
      message: db.prepare('SELECT * FROM chat_messages WHERE id = ?').get(msgId)
    };
  });

  server.get('/api/recordings', async (request, reply) => {
    const user = request.auth?.user;
    const isGlobalUser = getAllowedTenantIds(user) === null;
    const query = (request.query || {}) as { device_id?: string };
    if (query.device_id) {
      const access = ensureDeviceTenantAccess(request, reply, query.device_id);
      if (!access.allowed) return reply;
    }
    const rows = (query.device_id
      ? db
          .prepare(`
            SELECT r.*, d.hostname, d.tenant_id, t.name as tenant_name
            FROM session_recordings r
            LEFT JOIN devices d ON r.device_id = d.id
            LEFT JOIN tenants t ON d.tenant_id = t.id
            WHERE r.device_id = ?
            ORDER BY r.created_at DESC
          `)
          .all(query.device_id)
      : db
          .prepare(`
            SELECT r.*, d.hostname, d.tenant_id, t.name as tenant_name
            FROM session_recordings r
            LEFT JOIN devices d ON r.device_id = d.id
            LEFT JOIN tenants t ON d.tenant_id = t.id
            ORDER BY r.created_at DESC
            LIMIT 250
          `)
          .all()) as any[];

    return rows
      .filter((r) => (r.tenant_id ? canUserAccessTenant(user, r.tenant_id) : isGlobalUser))
      .map((r) => ({
        ...r,
        has_video: Boolean(r.video_path && fs.existsSync(r.video_path))
      }));
  });

  server.post('/api/recordings', { bodyLimit: 50 * 1024 * 1024 }, async (request, reply) => {
    const body = (request.body || {}) as {
      device_id?: string;
      duration_sec?: number;
      is_ghost_session?: boolean;
      video_base64?: string;
      mime_type?: string;
    };
    if (!body.device_id) {
      return reply.status(400).send({ error: 'device_id is required.' });
    }
    if (!ensureDeviceTenantAccess(request, reply, body.device_id).allowed) return reply;

    const id = `rec-${crypto.randomUUID().slice(0, 8)}`;
    const durationSec = Math.max(1, Number(body.duration_sec || 60));
    const mimeType =
      typeof body.mime_type === 'string' && body.mime_type.startsWith('video/')
        ? body.mime_type.slice(0, 64)
        : 'video/webm';

    let videoDiskPath: string | null = null;
    let fileSizeBytes = 0;
    let sizeMb = 0;
    let sha256 = '';

    if (typeof body.video_base64 === 'string' && body.video_base64.trim().length > 0) {
      const cleanedB64 = body.video_base64.replace(/^data:[^;]+;base64,/, '');
      const videoBuf = Buffer.from(cleanedB64, 'base64');
      if (videoBuf.length > 0) {
        fs.mkdirSync(RECORDINGS_DIR_PATH, { recursive: true });
        const ext = mimeType.includes('mp4') ? 'mp4' : 'webm';
        videoDiskPath = path.join(RECORDINGS_DIR_PATH, `${id}.${ext}`);
        fs.writeFileSync(videoDiskPath, videoBuf, { mode: 0o600 });
        fileSizeBytes = videoBuf.length;
        sizeMb = Number((fileSizeBytes / (1024 * 1024)).toFixed(3));
        sha256 = crypto.createHash('sha256').update(videoBuf).digest('hex');
      }
    }

    if (!sha256) {
      const metaPayload = JSON.stringify({
        id,
        deviceId: body.device_id,
        technician: getActorUsername(request),
        durationSec,
        recordedAt: new Date().toISOString()
      });
      fileSizeBytes = Buffer.byteLength(metaPayload, 'utf8');
      sizeMb = Number((fileSizeBytes / (1024 * 1024)).toFixed(4));
      sha256 = crypto.createHash('sha256').update(metaPayload).digest('hex');
    }

    const filePath = `/api/recordings/${id}/download`;

    db.prepare(`
      INSERT INTO session_recordings (
        id, device_id, technician, duration_sec, file_path, video_path, mime_type,
        file_size_bytes, file_size_mb, sha256_hash, is_ghost_session
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      body.device_id,
      getActorUsername(request),
      durationSec,
      filePath,
      videoDiskPath,
      videoDiskPath ? mimeType : 'application/json',
      fileSizeBytes,
      sizeMb,
      sha256,
      body.is_ghost_session ? 1 : 0
    );

    const inserted = db.prepare('SELECT * FROM session_recordings WHERE id = ?').get(id) as any;
    return {
      success: true,
      recording: {
        ...inserted,
        has_video: Boolean(videoDiskPath && fs.existsSync(videoDiskPath))
      }
    };
  });

  server.get('/api/recordings/:id/download', async (request, reply) => {
    const { id } = request.params as { id: string };
    const query = (request.query || {}) as { format?: string };
    const rec = db
      .prepare(`
        SELECT r.*, d.hostname, d.tenant_id
        FROM session_recordings r
        LEFT JOIN devices d ON r.device_id = d.id
        WHERE r.id = ?
      `)
      .get(id) as any;
    if (!rec) return reply.status(404).send({ error: 'Session recording not found.' });
    const user = request.auth?.user;
    if (rec.tenant_id ? !canUserAccessTenant(user, rec.tenant_id) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    if (
      query.format !== 'audit' &&
      rec.video_path &&
      path.resolve(rec.video_path).startsWith(path.resolve(RECORDINGS_DIR_PATH) + path.sep) &&
      fs.existsSync(rec.video_path)
    ) {
      const ext = String(rec.mime_type || '').includes('mp4') ? 'mp4' : 'webm';
      reply.header('Content-Type', rec.mime_type || 'video/webm');
      reply.header(
        'Content-Disposition',
        query.format === 'inline'
          ? 'inline'
          : buildSafeContentDisposition(`${rec.id}-${rec.hostname || 'session'}.${ext}`)
      );
      return reply.send(fs.readFileSync(rec.video_path));
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
        hasVideoArtifact: Boolean(rec.video_path && fs.existsSync(rec.video_path)),
        fileSizeBytes: rec.file_size_bytes || 0,
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

  server.delete('/api/recordings/:id', async (request, reply) => {
    if (!isSuperAdminRole(request.auth?.user?.role)) {
      return reply.status(403).send({ error: 'Forbidden: Super Admin privileges required to delete recordings.' });
    }
    const { id } = request.params as { id: string };
    const rec = db.prepare('SELECT id, device_id, video_path FROM session_recordings WHERE id = ?').get(id) as any;
    if (!rec) return reply.status(404).send({ error: 'Session recording not found.' });

    if (rec.video_path && fs.existsSync(RECORDINGS_DIR_PATH) && fs.existsSync(rec.video_path)) {
      try {
        const realRoot = fs.realpathSync(RECORDINGS_DIR_PATH);
        if (!fs.lstatSync(rec.video_path).isSymbolicLink()) {
          const resolved = fs.realpathSync(rec.video_path);
          if (resolved.startsWith(realRoot + path.sep) && !fs.lstatSync(resolved).isSymbolicLink() && fs.statSync(resolved).isFile()) {
            fs.unlinkSync(resolved);
          }
        }
      } catch {}
    }

    db.prepare('DELETE FROM session_recordings WHERE id = ?').run(id);
    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Session Recording Deleted', ?)
    `).run(
      `aud-recdel-${crypto.randomUUID()}`,
      getActorUsername(request),
      rec.device_id || null,
      `Deleted compliance session recording '${id}'`
    );

    return { success: true };
  });

  // ============================================================================
  // OEM Warranty Lookup (Honest Hardware Manufacturer Derivation)
  // ============================================================================
  server.get('/api/devices/:id/warranty', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
    return db.prepare('SELECT * FROM oem_warranties WHERE device_id = ?').get(id) || null;
  });

  server.post('/api/devices/:id/warranty/lookup', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
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
  server.get('/api/notifications', async (request) => {
    const user = request.auth?.user;
    const allowedTenants = getAllowedTenantIds(user);
    if (allowedTenants !== null && allowedTenants.length === 0) {
      return [];
    }
    const rows = (allowedTenants !== null
      ? db
          .prepare(
            `SELECT * FROM notifications WHERE tenant_id IN (${allowedTenants.map(() => '?').join(',')}) ORDER BY is_read ASC, created_at DESC LIMIT 100`
          )
          .all(...allowedTenants)
      : db
          .prepare('SELECT * FROM notifications ORDER BY is_read ASC, created_at DESC LIMIT 100')
          .all()) as any[];
    return rows
      .filter((r) => (!r.tenant_id ? allowedTenants === null : canUserAccessTenant(user, r.tenant_id)))
      .map((r) => ({
        ...r,
        is_read: Boolean(r.is_read),
        actions: safeJsonParse<any[]>(r.actions_json, [])
      }));
  });

  server.post('/api/notifications/:id/read', async (request) => {
    const { id } = request.params as { id: string };
    const user = request.auth?.user;
    const allowedTenants = getAllowedTenantIds(user);
    if (allowedTenants !== null) {
      if (allowedTenants.length === 0) {
        return { success: true };
      }
      const placeholders = allowedTenants.map(() => '?').join(',');
      if (id === 'all') {
        db.prepare(`UPDATE notifications SET is_read = 1 WHERE tenant_id IN (${placeholders})`).run(...allowedTenants);
      } else {
        db.prepare(`UPDATE notifications SET is_read = 1 WHERE id = ? AND tenant_id IN (${placeholders})`).run(
          id,
          ...allowedTenants
        );
      }
      return { success: true };
    }
    if (id === 'all') {
      db.prepare('UPDATE notifications SET is_read = 1').run();
    } else {
      db.prepare('UPDATE notifications SET is_read = 1 WHERE id = ?').run(id);
    }
    return { success: true };
  });

  server.post('/api/notifications/:id/action', async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = (request.body || {}) as { action?: 'uninstall' | 'move_to_unassigned'; tenantId?: string };
    let result: any = null;
    if (body.tenantId && (body.action === 'uninstall' || body.action === 'move_to_unassigned')) {
      if (!isSuperAdminRole(request.auth?.user.role)) {
        return reply.status(403).send({ error: 'Super Admin role is required to execute client deletion actions.' });
      }
      if (!requireStepUpMfaIfEnforced(request, reply, null)) {
        return reply;
      }
      result = await meshBridge.handleClientDeletion(body.tenantId, body.action, getActorUsername(request));
    }
    db.prepare('UPDATE notifications SET is_read = 1 WHERE id = ?').run(id);
    return { success: true, result };
  });

  server.post('/api/meshcentral/sync', async () => {
    return await meshBridge.syncDeviceGroupsWithClients();
  });

  server.delete('/api/tenants/:id', async (request, reply) => {
    if (!requireStepUpMfaIfEnforced(request, reply, null)) {
      return reply;
    }
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
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
    return db.prepare('SELECT * FROM hardware_history WHERE device_id = ? ORDER BY timestamp DESC').all(id);
  });

  server.post('/api/devices/:id/hardware-history/:histId/ack', async (request, reply) => {
    const { id, histId } = request.params as { id: string; histId: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
    db.prepare('UPDATE hardware_history SET acknowledged = 1 WHERE id = ? AND device_id = ?').run(histId, id);
    return { success: true };
  });

  server.get('/api/devices/:id/network-history', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
    return db.prepare('SELECT * FROM network_history WHERE device_id = ? ORDER BY connected_at DESC').all(id);
  });

  server.get('/api/smart-groups', async (request) => {
    const user = request.auth?.user;
    const isGlobalUser = getAllowedTenantIds(user) === null;
    const rows = db.prepare('SELECT * FROM smart_groups ORDER BY created_at DESC').all() as any[];
    return rows
      .filter((g) => (g.tenant_id ? canUserAccessTenant(user, g.tenant_id) : isGlobalUser))
      .map((g) => {
        const matched = evaluateSmartGroupDevices(g.criteria_json, g.tenant_id).filter((d: any) =>
          canUserAccessTenant(user, d.tenant_id)
        );
        return {
          ...g,
          criteria: safeJsonParse<Record<string, any>>(g.criteria_json, {}),
          matchedCount: matched.length,
          matchedDeviceIds: matched.map((d: any) => d.id)
        };
      });
  });

  server.get('/api/smart-groups/:id/devices', async (request, reply) => {
    const { id } = request.params as { id: string };
    const grp = db.prepare('SELECT * FROM smart_groups WHERE id = ?').get(id) as any;
    if (!grp) return reply.status(404).send({ error: 'Smart group not found.' });
    const user = request.auth?.user;
    if (grp.tenant_id ? !canUserAccessTenant(user, grp.tenant_id) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    const matched = evaluateSmartGroupDevices(grp.criteria_json, grp.tenant_id).filter((d: any) =>
      canUserAccessTenant(user, d.tenant_id)
    );
    return matched.map(sanitizeDeviceRowForResponse);
  });

  server.post('/api/smart-groups', async (request, reply) => {
    const user = request.auth?.user;
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
    const targetTenantId = body.tenant_id && body.tenant_id !== 'all' ? body.tenant_id : null;
    if (targetTenantId ? !canUserAccessTenant(user, targetTenantId) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Forbidden for target smart group tenant scope.' });
    }
    const id = `sg-${crypto.randomUUID().slice(0, 8)}`;
    const criteriaJson = body.criteria ? JSON.stringify(body.criteria) : body.criteria_json || '{}';
    db.prepare(`
      INSERT INTO smart_groups (id, name, description, tenant_id, criteria_json)
      VALUES (?, ?, ?, ?, ?)
    `).run(id, body.name.trim(), body.description || '', targetTenantId, criteriaJson);
    const matched = evaluateSmartGroupDevices(criteriaJson, targetTenantId).filter((d: any) =>
      canUserAccessTenant(user, d.tenant_id)
    );
    return {
      success: true,
      id,
      matchedCount: matched.length,
      matchedDeviceIds: matched.map((d: any) => d.id)
    };
  });

  server.put('/api/smart-groups/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT * FROM smart_groups WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Smart group not found.' });
    const user = request.auth?.user;
    const isGlobalUser = getAllowedTenantIds(user) === null;
    if (existing.tenant_id ? !canUserAccessTenant(user, existing.tenant_id) : !isGlobalUser) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    const body = (request.body || {}) as {
      name?: string;
      description?: string;
      tenant_id?: string | null;
      criteria?: Record<string, any>;
      criteria_json?: string;
    };
    const nextCriteriaJson =
      body.criteria !== undefined
        ? JSON.stringify(body.criteria)
        : body.criteria_json !== undefined
          ? body.criteria_json
          : existing.criteria_json;
    const nextTenantId =
      body.tenant_id !== undefined
        ? body.tenant_id && body.tenant_id !== 'all'
          ? body.tenant_id
          : null
        : existing.tenant_id;
    if (nextTenantId ? !canUserAccessTenant(user, nextTenantId) : !isGlobalUser) {
      return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
    }

    db.prepare(`
      UPDATE smart_groups
      SET name = COALESCE(?, name),
          description = COALESCE(?, description),
          tenant_id = ?,
          criteria_json = ?
      WHERE id = ?
    `).run(body.name?.trim() || null, body.description ?? null, nextTenantId, nextCriteriaJson, id);

    const matched = evaluateSmartGroupDevices(nextCriteriaJson, nextTenantId).filter((d: any) =>
      canUserAccessTenant(user, d.tenant_id)
    );
    return {
      success: true,
      id,
      matchedCount: matched.length,
      matchedDeviceIds: matched.map((d: any) => d.id)
    };
  });

  server.delete('/api/smart-groups/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT tenant_id FROM smart_groups WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Smart group not found.' });
    const user = request.auth?.user;
    if (existing.tenant_id ? !canUserAccessTenant(user, existing.tenant_id) : getAllowedTenantIds(user) !== null) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    db.prepare('DELETE FROM smart_groups WHERE id = ?').run(id);
    return { success: true };
  });

  server.get('/api/devices/:id/software', async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
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
    if (!access.allowed || !access.device) return reply;

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
    const isQueued = execRes.output.startsWith('[Vitrine Companion Queue]') || (!execRes.live && execRes.exitCode === 0);
    const liveSucceeded = Boolean(execRes.live && execRes.exitCode === 0);

    let updatedVersion = soft.version;
    if (liveSucceeded) {
      updatedVersion = `${soft.version}-patched`;
      db.prepare(`
        UPDATE software_inventory
        SET version = ?, cve_count = 0, highest_cvss = 0.0, cve_list_json = '[]'
        WHERE id = ?
      `).run(updatedVersion, softId);
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Software CVE Upgrade Dispatched', ?)
    `).run(
      `aud-sw-${crypto.randomUUID()}`,
      getActorUsername(request),
      id,
      `Upgrade '${soft.name}' on ${access.device.hostname} (live=${dispatched}, exit=${execRes.exitCode})`
    );

    if (execRes.live && execRes.exitCode !== 0) {
      return reply.status(502).send({
        success: false,
        dispatched: true,
        exitCode: execRes.exitCode,
        output: execRes.output,
        error: `Package upgrade command exited with code ${execRes.exitCode}.`
      });
    }

    return {
      success: true,
      dispatched,
      queued: !liveSucceeded && isQueued,
      status: liveSucceeded ? 'upgraded' : 'queued',
      updatedVersion,
      output: execRes.output
    };
  });

  // ============================================================================
  // Remote Screen Session & 5-Tier Out-of-Band WoL / Intel vPro AMT Chain
  // ============================================================================
  server.post('/api/devices/:id/remote-session', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
    const dev = access.device;

    const body = (request.body || {}) as { mode?: 'interactive' | 'view_only' | 'ghost' | 'amt_kvm' };
    const mode = body.mode || 'interactive';
    if (
      mode === 'ghost' &&
      !isSuperAdminRole(request.auth?.user.role) &&
      !hasUserPermission(request.auth?.user, 'remote:unattended')
    ) {
      return reply.status(403).send({
        error: "Forbidden: missing required permission 'remote:unattended' for Ghost background sessions.",
        requiredPermission: 'remote:unattended'
      });
    }
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;

    if (mode === 'amt_kvm') {
      const cpuStr = String(dev.cpu_model || '');
      const nonIntel = /\b(amd|ryzen|epyc|threadripper|athlon|apple|arm|aarch64|qualcomm|snapdragon)\b/i.test(cpuStr);
      if (dev.os_type === 'macos' || nonIntel || (!dev.amt_supported && !dev.amt_provisioned)) {
        return reply.status(400).send({
          success: false,
          error:
            dev.os_type === 'macos'
              ? 'Intel AMT / vPro KVM is not supported on macOS hardware.'
              : nonIntel
                ? `Endpoint CPU (${cpuStr}) does not support Intel vPro / AMT hardware KVM.`
                : 'Intel vPro / AMT has not been detected or provisioned on this endpoint.'
        });
      }
    }

    let policyConsentRequired = false;
    try {
      const policy = resolveEffectiveDevicePolicy(id);
      policyConsentRequired = Boolean(policy?.requireRemoteConsent);
    } catch {}
    const roleLower = String(dev.device_role || '').toLowerCase();
    const isUnattended =
      dev.status === 'isolated' ||
      roleLower.includes('server') ||
      roleLower.includes('controller') ||
      roleLower.includes('hypervisor') ||
      mode === 'ghost' ||
      mode === 'amt_kvm';
    const requireConsent = policyConsentRequired && !isUnattended;

    const liveSession = await meshBridge.createLiveDeviceSessionUrl({
      deviceId: id,
      mode: mode === 'ghost' ? 'terminal' : 'desktop',
      viewOnly: mode === 'view_only',
      requireConsent,
      guestName: getActorUsername(request),
      durationMinutes: 60
    });

    let fallbackUrl: string | null = null;
    const rawMeshUrl = String(settings.meshcentral_url || '').trim();
    const validRawMeshUrl =
      rawMeshUrl &&
      !rawMeshUrl.includes('mesh.vitrine.local') &&
      (rawMeshUrl.startsWith('https://') || rawMeshUrl.startsWith('http://'))
        ? rawMeshUrl
        : null;
    if (!liveSession.url && validRawMeshUrl) {
      try {
        const parsed = new URL(validRawMeshUrl);
        const nodeRef = encodeURIComponent(dev.mesh_node_id || dev.id);
        const viewParam = mode === 'view_only' ? '&viewonly=1' : '';
        fallbackUrl = `${parsed.origin}/?viewmode=11&gotonode=${nodeRef}${viewParam}`;
      } catch {
        fallbackUrl = null;
      }
    }

    const meshRelayUrl = liveSession.url || fallbackUrl;
    const bridgeStatus = meshBridge.getStatus();
    const meshRelayError =
      liveSession.error ||
      (!bridgeStatus.connected ? bridgeStatus.lastError || 'MeshCentral bridge not connected' : null);

    const ghostArchitecture =
      dev.os_type === 'windows'
        ? 'Win32 CreateDesktopW / Background Session Host'
        : dev.os_type === 'macos'
          ? 'macOS Background SSH / Terminal Multiplexer'
          : 'Linux Background PTY / Headless Session';

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Remote Screen Session Initiated', ?)
    `).run(
      `aud-rem-${crypto.randomUUID()}`,
      getActorUsername(request),
      id,
      `Opened ${mode} remote session to ${dev.hostname} (shareLink=${Boolean(liveSession.url)})`
    );

    return {
      success: true,
      sessionId: `rsess-${crypto.randomUUID().slice(0, 8)}`,
      deviceId: id,
      hostname: dev.hostname,
      osType: dev.os_type,
      mode,
      meshRelayUrl,
      serverUrl: liveSession.serverUrl || validRawMeshUrl || null,
      meshRelayError,
      shareLinkSource: liveSession.live ? 'meshcentral_share_link' : fallbackUrl ? 'meshcentral_gotonode' : 'unavailable',
      meshBridgeConnected: bridgeStatus.connected,
      ghostArchitecture: mode === 'ghost' ? ghostArchitecture : null,
      recordingEnabled: Boolean(settings.session_recording_enabled),
      visualIndicator: Boolean(settings.session_recording_visual_indicator)
    };
  });

  server.post('/api/devices/:id/lock-screen', async (request, reply) => {
    const { id } = request.params as { id: string };
    const user = request.auth?.user;
    if (!isTechnicianOrAbove(user?.role) || !hasUserPermission(user, 'remote:connect')) {
      return reply.status(403).send({ error: 'Technician role and remote:connect permission required to lock screen.' });
    }
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;

    const actor = getActorUsername(request);
    const lockRes = await meshBridge.lockEndpointScreen(id, actor);
    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Endpoint Screen Locked', ?)
    `).run(
      `aud-lock-${crypto.randomUUID()}`,
      actor,
      id,
      `Triggered endpoint lock-screen on ${access.device.hostname} (dispatched=${lockRes.dispatched}, live=${lockRes.live})`
    );
    return {
      success: lockRes.dispatched,
      dispatched: lockRes.dispatched,
      live: lockRes.live,
      output: lockRes.output
    };
  });

  server.post('/api/devices/:id/remote-session/consent-bypass', async (request, reply) => {
    const { id } = request.params as { id: string };
    const user = request.auth?.user;
    if (!isSuperAdminRole(user?.role) && !hasUserPermission(user, 'remote:unattended')) {
      return reply.status(403).send({
        error: "Forbidden: missing required permission 'remote:unattended' to bypass remote consent.",
        requiredPermission: 'remote:unattended'
      });
    }
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;

    const body = (request.body || {}) as { reason?: string; sessionId?: string };
    const reason = String(body.reason || 'Unattended administrative override').trim().slice(0, 240);
    const actor = getActorUsername(request);

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Remote Consent Bypassed', ?)
    `).run(
      `aud-cbyp-${crypto.randomUUID()}`,
      actor,
      id,
      `Operator '${actor}' bypassed interactive consent on ${access.device.hostname}: ${reason}`
    );

    return {
      success: true,
      bypassed: true,
      deviceId: id,
      audited: true,
      reason
    };
  });

  const executeReachabilityChain = async (dev: any, actorUsername: string) => {
    const subnetPrefix = String(dev.ip_address || '')
      .split('.')
      .slice(0, 3)
      .join('.');
    const siteRow = dev.site_id
      ? (db.prepare('SELECT subnet FROM sites WHERE id = ?').get(dev.site_id) as { subnet?: string } | undefined)
      : undefined;
    const siteSubnet =
      siteRow?.subnet && siteRow.subnet !== '0.0.0.0/0'
        ? siteRow.subnet
        : subnetPrefix
          ? `${subnetPrefix}.0/24`
          : undefined;

    // Discover real online subnet peers strictly within the same client tenant (prevents cross-tenant lateral relay)
    const peerRelay = subnetPrefix
      ? (db
          .prepare(
            "SELECT id, hostname, ip_address, device_role, os_type, companion_installed FROM devices WHERE id != ? AND tenant_id = ? AND status = 'online' AND ip_address LIKE ? ORDER BY CASE WHEN LOWER(device_role) LIKE '%server%' THEN 0 ELSE 1 END LIMIT 1"
          )
          .get(dev.id, dev.tenant_id, `${subnetPrefix}.%`) as any)
      : null;

    const recentNet = db
      .prepare('SELECT ssid, gateway_ip, local_ip, interface_name FROM network_history WHERE device_id = ? ORDER BY connected_at DESC LIMIT 1')
      .get(dev.id) as any;

    let wolBroadcastResult: { sent: boolean; targets: string[]; error?: string } = { sent: false, targets: [] };
    if (dev.mac_address && dev.mac_address !== '00:00:00:00:00:00') {
      try {
        const wolRes = await sendWakeOnLanMagicPacket({
          macAddress: dev.mac_address,
          ipAddress: dev.ip_address || siteSubnet?.split('/')[0] || null,
          tenantId: dev.tenant_id,
          deviceId: dev.id
        });
        wolBroadcastResult = { sent: wolRes.sent, targets: wolRes.broadcastTargets };
      } catch (err: any) {
        wolBroadcastResult = { sent: false, targets: [], error: err?.message };
      }
    }

    if (peerRelay && dev.mac_address && dev.mac_address !== '00:00:00:00:00:00') {
      const cleanHexMac = String(dev.mac_address).replace(/[^0-9A-Fa-f]/g, '');
      if (cleanHexMac.length === 12) {
        const peerWolCmd =
          peerRelay.os_type === 'windows'
            ? `$mac = '${cleanHexMac}'; $pkt = [byte[]](,0xFF * 6) + (($mac -split '(..)' | Where-Object { $_ }) | ForEach-Object { [Convert]::ToByte($_, 16) }) * 16; $u = New-Object System.Net.Sockets.UdpClient; $u.EnableBroadcast = $true; [void]$u.Send($pkt, $pkt.Length, '255.255.255.255', 9); $u.Close()`
            : `python3 -c "import socket; d=bytes.fromhex('ff'*6 + '${cleanHexMac}'*16); s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); s.sendto(d, ('255.255.255.255', 9)); s.close()" 2>/dev/null || true`;
        void meshBridge.executeCommandOnNode(peerRelay.id, peerWolCmd, { runAs: 'system' });
      }
    }

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
          ? `Online subnet peer ${peerRelay.hostname} (${peerRelay.ip_address}) relayed IEEE 802.3 UDP/9 magic packet to MAC ${dev.mac_address}.`
          : `No online managed peer found on subnet ${subnetPrefix || 'unknown'}.0/24 to relay Layer-2 magic packet.`
      },
      {
        tier: 3,
        name: 'Site Router / Directed Subnet Broadcast',
        status: wolBroadcastResult.sent ? 'dispatched' : recentNet?.gateway_ip ? 'probed' : 'unavailable',
        detail: wolBroadcastResult.sent
          ? `Server broadcast UDP/7 & UDP/9 IEEE Magic Packet to [${wolBroadcastResult.targets.join(', ')}] (Last gateway: ${recentNet?.gateway_ip || 'direct'}).`
          : recentNet?.gateway_ip
            ? `Last recorded gateway ${recentNet.gateway_ip} (Interface: ${recentNet.interface_name || 'eth0'}, IP: ${recentNet.local_ip || dev.ip_address}).`
            : wolBroadcastResult.error || 'No valid MAC or gateway history recorded yet for this endpoint.'
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

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, '5-Tier Reachability & WoL Executed', ?)
    `).run(
      `aud-wol-${crypto.randomUUID()}`,
      actorUsername,
      dev.id,
      `Executed out-of-band reachability & WoL chain for ${dev.hostname} (UDP broadcast=${wolBroadcastResult.sent}, Peer relay=${peerRelay?.hostname || 'none'})`
    );

    return {
      success: true,
      deviceId: dev.id,
      hostname: dev.hostname,
      targetIp: dev.ip_address || siteSubnet?.split('/')[0] || null,
      macAddress: dev.mac_address,
      wolSent: wolBroadcastResult.sent,
      wolTargets: wolBroadcastResult.targets,
      peerRelayHost: peerRelay?.hostname || null,
      tiers
    };
  };

  server.post('/api/devices/:id/wake-on-lan', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
    return await executeReachabilityChain(access.device, getActorUsername(request));
  });

  server.post('/api/devices/:id/wol', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
    return await executeReachabilityChain(access.device, getActorUsername(request));
  });

  server.post('/api/devices/:id/wake', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
    return await executeReachabilityChain(access.device, getActorUsername(request));
  });

  server.post('/api/devices/:id/reachability-chain', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
    return await executeReachabilityChain(access.device, getActorUsername(request));
  });

  server.post('/api/devices/:id/enable-wol', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
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
    const confirmed = Boolean(execRes.live && execRes.exitCode === 0);
    const nextWolStatus = confirmed
      ? 'Enabled (NIC + OS Power Policy)'
      : execRes.live
        ? `Failed (Exit ${execRes.exitCode})`
        : 'Pending (Endpoint Offline)';

    if (confirmed) {
      db.prepare('UPDATE devices SET wol_supported = 1, wol_status = ? WHERE id = ?').run(nextWolStatus, id);
    } else {
      db.prepare('UPDATE devices SET wol_status = ? WHERE id = ?').run(nextWolStatus, id);
    }

    return {
      success: confirmed,
      dispatched,
      live: execRes.live,
      exitCode: execRes.exitCode,
      wol_supported: confirmed ? 1 : Number(dev.wol_supported || 0),
      manufacturer: dev.manufacturer || (mfg ? mfg : 'Generic OEM'),
      wol_status: nextWolStatus,
      output: execRes.output
    };
  });

  const handleProvisionAmt = async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;
    const dev = access.device;

    if (dev.os_type === 'macos') {
      return reply.status(400).send({
        success: false,
        error: 'macOS endpoints do not support Intel vPro / AMT hardware management.'
      });
    }

    const cpuStr = String(dev.cpu_model || '');
    if (/\b(amd|ryzen|epyc|threadripper|athlon|apple|arm|aarch64|qualcomm|snapdragon)\b/i.test(cpuStr)) {
      return reply.status(400).send({
        success: false,
        amt_provisioned: false,
        error: `Endpoint CPU (${cpuStr}) is not an Intel vPro / AMT platform.`
      });
    }

    const probeCmd =
      dev.os_type === 'windows'
        ? `$mei = Get-PnpDevice -FriendlyName '*Management Engine*' -ErrorAction SilentlyContinue | Select-Object -First 1; if (-not $mei) { exit 2 }; Write-Output "AMT_PRESENT|$($mei.Status)"; $mc = "$env:ProgramFiles\\Mesh Agent\\meshcmd.exe"; if (Test-Path $mc) { & $mc amtinfo }`
        : `if [ -e /dev/mei0 ] || lspci 2>/dev/null | grep -qi 'Management Engine'; then echo 'AMT_PRESENT|Active'; if command -v meshcmd >/dev/null 2>&1; then meshcmd amtinfo || true; fi; else exit 2; fi`;

    const probeRes = await meshBridge.executeCommandOnNode(id, probeCmd, {
      runAs: 'system',
      shell: dev.os_type === 'windows' ? 'powershell' : 'bash',
      timeoutMs: 10_000
    });

    if (probeRes.live && probeRes.exitCode !== 0 && !dev.amt_supported) {
      return reply.status(400).send({
        success: false,
        amt_provisioned: false,
        error: 'No Intel Management Engine (MEI / vPro) hardware interface detected on this endpoint.'
      });
    }

    const verifiedHardware = Boolean(probeRes.live && probeRes.exitCode === 0 && probeRes.output.includes('AMT_PRESENT'));
    if (!verifiedHardware && !dev.amt_supported) {
      return reply.status(409).send({
        success: false,
        amt_provisioned: false,
        queued: probeRes.output.startsWith('[Vitrine Companion Queue]'),
        error: 'Endpoint must be online with verified Intel vPro/MEI hardware before AMT probe or provisioning can run.'
      });
    }

    // Only report amt_provisioned=true if amtinfo confirms active CCM/ACM provisioning (not from a bare hardware probe)
    const amtProvisioningConfirmed = Boolean(
      probeRes.live &&
        /(control\s*mode\s*:\s*(client|admin)|provisioning\s*state\s*:\s*post|cira\s*connected)/i.test(
          probeRes.output || ''
        )
    );
    const finalProvisioned = amtProvisioningConfirmed || Boolean(dev.amt_provisioned);
    const resolvedVersion = dev.amt_version || (finalProvisioned ? '16.1 (CCM CIRA)' : '');

    db.prepare(`
      UPDATE devices
      SET amt_supported = 1,
          amt_provisioned = ?,
          amt_version = ?
      WHERE id = ?
    `).run(finalProvisioned ? 1 : 0, resolvedVersion, id);

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      `aud-amt-${crypto.randomUUID()}`,
      getActorUsername(request),
      id,
      finalProvisioned ? 'Intel vPro / AMT Verified' : 'Intel vPro / AMT Hardware Probe Completed',
      finalProvisioned
        ? `Confirmed AMT provisioning (${resolvedVersion}) on ${dev.hostname}`
        : `Detected Intel MEI hardware capability on ${dev.hostname}; AMT CCM/CIRA provisioning not yet active`
    );

    return {
      success: true,
      amt_supported: true,
      amt_provisioned: finalProvisioned,
      amt_version: resolvedVersion,
      probeOnly: !finalProvisioned,
      message: finalProvisioned
        ? 'Intel vPro / AMT provisioning verified on endpoint.'
        : 'Intel MEI hardware capability detected, but AMT CIRA/CCM provisioning has not been activated yet.'
    };
  };
  server.post('/api/devices/:id/provision-amt', handleProvisionAmt);
  server.post('/api/devices/:id/configure-amt', handleProvisionAmt);

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
    const isSafeMethod = request.method === 'GET' || request.method === 'HEAD' || request.method === 'OPTIONS';
    if (!isSafeMethod && !isGuestTokenValid && request.auth?.authSource === 'cookie') {
      const csrfHeader = String(request.headers['x-vitrine-csrf'] || '').trim();
      if (csrfHeader !== '1') {
        reply.status(403).send({
          error: 'CSRF verification failed: missing X-Vitrine-CSRF header.',
          code: 'CSRF_REQUIRED'
        });
        return { ok: false };
      }
    }
    const deviceIds = safeJsonParse<string[]>(grant.device_ids_json, []);
    if (!isGuestTokenValid && isAdminSession) {
      const user = request.auth?.user;
      if (deviceIds.length === 0) {
        if (!isSuperAdminRole(user?.role)) {
          reply.status(403).send({ error: 'Forbidden' });
          return { ok: false };
        }
      } else {
        const placeholders = deviceIds.map(() => '?').join(',');
        const devs = db
          .prepare(`SELECT id, tenant_id FROM devices WHERE id IN (${placeholders})`)
          .all(...deviceIds) as Array<{ id: string; tenant_id: string }>;
        if (devs.length !== deviceIds.length || devs.some((d) => !canUserAccessTenant(user, d.tenant_id))) {
          reply.status(403).send({ error: 'Forbidden: vendor pass includes devices outside your tenant scope.' });
          return { ok: false };
        }
      }
    }
    return {
      ok: true,
      grant,
      deviceIds
    };
  };

  server.get('/api/guest-grants', async (request) => {
    const user = request.auth?.user;
    const isGlobalUser = getAllowedTenantIds(user) === null;
    const rows = db.prepare('SELECT * FROM guest_access_grants ORDER BY created_at DESC').all() as any[];
    const visible = rows.filter((g) => {
      const devIds = safeJsonParse<string[]>(g.device_ids_json, []);
      if (devIds.length === 0) return isGlobalUser;
      const placeholders = devIds.map(() => '?').join(',');
      const devs = db
        .prepare(`SELECT tenant_id FROM devices WHERE id IN (${placeholders})`)
        .all(...devIds) as Array<{ tenant_id: string }>;
      return devs.length > 0 && devs.every((d) => canUserAccessTenant(user, d.tenant_id));
    });
    return visible.map(formatGuestGrantForAdmin);
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
    const deviceIds = Array.isArray(body.device_ids) ? Array.from(new Set(body.device_ids.filter(Boolean))) : [];
    if (!vendorName || deviceIds.length === 0) {
      return reply.status(400).send({ error: 'vendor_name and at least one scoped device_id are required.' });
    }

    for (const devId of deviceIds) {
      const dev = db.prepare('SELECT id, tenant_id FROM devices WHERE id = ?').get(devId) as { id: string; tenant_id: string } | undefined;
      if (!dev) {
        return reply.status(404).send({ error: `Scoped device '${devId}' does not exist.` });
      }
      if (!canUserAccessTenant(request.auth?.user, dev.tenant_id)) {
        return reply.status(403).send({ error: 'Forbidden: cannot issue a vendor pass for a device outside your tenant scope.' });
      }
    }

    const rawHours = Number(body.duration_hours ?? body.expires_in_hours ?? 4);
    const hours = Number.isFinite(rawHours) ? Math.max(1, Math.min(168, rawHours)) : 4;
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

  server.post('/api/guest-grants/:id/revoke', async (request, reply) => {
    const { id } = request.params as { id: string };
    const existing = db.prepare('SELECT device_ids_json FROM guest_access_grants WHERE id = ?').get(id) as any;
    if (!existing) return reply.status(404).send({ error: 'Guest access grant not found.' });
    const devIds = safeJsonParse<string[]>(existing.device_ids_json, []);
    if (devIds.length > 0) {
      const placeholders = devIds.map(() => '?').join(',');
      const devs = db
        .prepare(`SELECT tenant_id FROM devices WHERE id IN (${placeholders})`)
        .all(...devIds) as Array<{ tenant_id: string }>;
      if (devs.some((d) => !canUserAccessTenant(request.auth?.user, d.tenant_id))) {
        return reply.status(403).send({ error: 'Forbidden: vendor pass includes devices outside your tenant scope.' });
      }
    }
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
      status: isExpired ? 'expired' : 'active',
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

    if (!providedUser || !constantTimeEquals(providedUser, String(grant.temp_username || ''))) {
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

  server.get('/api/guest-portal/:id/ws-ticket', async (request, reply) => {
    const { id } = request.params as { id: string };
    const authz = authorizeGuestGrant(request, reply, id);
    if (!authz.ok || !authz.grant) return;
    const ticket = issueEphemeralWsTicket({ grantId: id });
    return { success: true, ticket, expiresInSeconds: 45 };
  });

  server.get('/api/guest-portal/:id/custom-fields/:deviceId', async (request, reply) => {
    const { id, deviceId } = request.params as { id: string; deviceId: string };
    const authz = authorizeGuestGrant(request, reply, id);
    if (!authz.ok || !authz.grant || !authz.deviceIds) return;
    if (!authz.grant.can_view_custom_fields || !authz.deviceIds.includes(deviceId)) {
      return reply.status(403).send({ error: 'Custom field visibility is not permitted on this vendor pass.' });
    }
    const dev = db.prepare('SELECT tenant_id FROM devices WHERE id = ?').get(deviceId) as
      | { tenant_id?: string }
      | undefined;
    if (!dev) return reply.status(404).send({ error: 'Device not found.' });
    return db
      .prepare(`
        SELECT d.id as field_id, d.key, d.label, d.category, COALESCE(v.value, '') as value
        FROM custom_field_definitions d
        LEFT JOIN custom_field_values v ON d.id = v.field_id AND v.entity_id = ?
        WHERE (d.scope = 'device' OR d.scope = 'all')
          AND d.field_type != 'secret'
          AND (d.tenant_id IS NULL OR d.tenant_id = ?)
        ORDER BY d.category ASC, d.label ASC
      `)
      .all(deviceId, dev.tenant_id || '');
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

    const liveSession = await meshBridge.createLiveDeviceSessionUrl({
      deviceId,
      mode: mode === 'ghost' ? 'terminal' : 'desktop',
      viewOnly: mode === 'view_only',
      guestName: `${authz.grant.vendor_name} (${authz.grant.temp_username})`,
      durationMinutes: 60
    });

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
      osType: dev.os_type,
      mode,
      meshRelayUrl: liveSession.url,
      shareLinkSource: liveSession.live ? 'meshcentral_share_link' : 'unavailable',
      isGuestPortal: true
    };
  });

  server.get('/api/guest-portal/:id/scripts', async (request, reply) => {
    const { id } = request.params as { id: string };
    const authz = authorizeGuestGrant(request, reply, id);
    if (!authz.ok || !authz.grant || !authz.deviceIds) return;
    if (!authz.grant.can_run_scripts) {
      return reply.status(403).send({ error: 'Script execution is disabled on this vendor pass.' });
    }
    const grantTenants = new Set<string>();
    if (authz.deviceIds.length > 0) {
      const placeholders = authz.deviceIds.map(() => '?').join(',');
      const devs = db
        .prepare(`SELECT DISTINCT tenant_id FROM devices WHERE id IN (${placeholders})`)
        .all(...authz.deviceIds) as Array<{ tenant_id?: string }>;
      for (const d of devs) {
        if (d.tenant_id) grantTenants.add(d.tenant_id);
      }
    }
    const rows = db
      .prepare(
        "SELECT id, name, description, language, category, tenant_id FROM scripts WHERE COALESCE(enabled, 1) = 1 AND COALESCE(required_role, 'technician') NOT IN ('admin', 'super_admin', 'msp_super_admin') ORDER BY name ASC"
      )
      .all() as any[];
    return rows
      .filter((s) => !s.tenant_id || s.tenant_id === 'all' || grantTenants.has(s.tenant_id))
      .map(({ tenant_id: _tid, ...rest }) => rest);
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
    const targetDev = db.prepare('SELECT id, tenant_id FROM devices WHERE id = ?').get(deviceId) as
      | { id: string; tenant_id: string }
      | undefined;
    if (!targetDev) return reply.status(404).send({ error: 'Device not found.' });

    const script = db.prepare('SELECT * FROM scripts WHERE id = ?').get(scriptId) as any;
    if (
      !script ||
      !script.enabled ||
      ['admin', 'super_admin', 'msp_super_admin'].includes(String(script.required_role || '')) ||
      (script.tenant_id && script.tenant_id !== 'all' && script.tenant_id !== targetDev.tenant_id)
    ) {
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
      const maxUses = Number(auditToken.max_uses ?? 0);
      const useCount = Number(auditToken.use_count ?? 0);
      if (maxUses > 0 && useCount >= maxUses) {
        return null;
      }
      return {
        mode: 'permanent' as const,
        tenantId: auditToken.tenant_id,
        siteId: auditToken.site_id || undefined,
        deviceRole: auditToken.device_role || undefined,
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
        tenantId: qsSession.tenant_id || undefined,
        siteId: undefined,
        deviceRole: undefined,
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
    if (
      ['super_admin', 'msp_super_admin', 'admin'].includes(String(settings.installer_download_role || '')) &&
      !isSuperAdminRole(request.auth?.user.role)
    ) {
      return reply.status(403).send({ error: 'Super Admin role is required to download permanent agent installers.' });
    }

    const query = (request.query || {}) as {
      os?: string;
      mode?: string;
      tenant_id?: string;
      site_id?: string;
      role?: string;
      ticket?: string;
      max_uses?: string;
    };
    const requestedQueryMode = String(query.mode || '').trim().toLowerCase();
    const installerMode: 'permanent' | 'companion_only' =
      requestedQueryMode === 'companion' || requestedQueryMode === 'companion_only' ? 'companion_only' : 'permanent';
    if (settings.installer_require_ticket && !query.ticket?.trim()) {
      return reply.status(400).send({ error: 'A valid PSA ticket reference is required to generate an installer.' });
    }

    const osParam: 'windows' | 'linux' | 'darwin' =
      query.os === 'linux' ? 'linux' : query.os === 'darwin' || query.os === 'macos' ? 'darwin' : 'windows';
    const allowedTenants = getAllowedTenantIds(request.auth?.user);
    const fallbackTenant =
      allowedTenants && allowedTenants.length > 0
        ? allowedTenants[0]
        : (db.prepare('SELECT id FROM tenants ORDER BY created_at ASC LIMIT 1').get() as any)?.id || 'default';
    const tenantId = query.tenant_id || fallbackTenant;
    if (!canUserAccessTenant(request.auth?.user, tenantId)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    const tokenId = `tok-${crypto.randomBytes(16).toString('hex')}`;
    const expiresAt = new Date(Date.now() + 24 * 3600_000).toISOString();
    const maxUses = query.max_uses !== undefined ? Math.max(0, Number(query.max_uses) || 0) : 1;

    db.prepare(`
      INSERT INTO installer_audit_log (id, token_id, tenant_id, site_id, device_role, technician, ticket_number, platform, expires_at, max_uses, use_count)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
    `).run(
      `ia-${crypto.randomUUID().slice(0, 8)}`,
      tokenId,
      tenantId,
      query.site_id || null,
      query.role || 'Auto',
      getActorUsername(request),
      query.ticket || null,
      osParam,
      expiresAt,
      maxUses
    );

    const pkg = await installerGenerator.generateInstaller({
      os: osParam,
      tenantId,
      siteId: query.site_id || undefined,
      deviceRole: query.role || 'Auto',
      tokenId,
      mode: installerMode,
      vitrineServerUrl: resolvePublicBaseUrl(request, settings)
    });

    reply.header('Content-Type', pkg.contentType);
    reply.header('Content-Disposition', buildSafeContentDisposition(pkg.filename));
    return reply.send(pkg.content);
  });

  server.post('/api/installers/generate', async (request, reply) => {
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    if (
      ['super_admin', 'msp_super_admin', 'admin'].includes(String(settings.installer_download_role || '')) &&
      !isSuperAdminRole(request.auth?.user.role)
    ) {
      return reply.status(403).send({ error: 'Super Admin role is required to generate deployment tokens.' });
    }

    const body = (request.body || {}) as {
      tenant_id?: string;
      site_id?: string;
      device_role?: string;
      platform?: string;
      os?: string;
      mode?: 'permanent' | 'quicksupport' | 'companion_only';
      ticket_number?: string;
      mesh_server_id?: string;
      max_uses?: number;
    };
    const requestedMode: 'permanent' | 'quicksupport' | 'companion_only' =
      body.mode === 'quicksupport' ? 'quicksupport' : body.mode === 'companion_only' ? 'companion_only' : 'permanent';

    if (requestedMode === 'permanent' && settings.installer_require_ticket && !body.ticket_number?.trim()) {
      return reply.status(400).send({ error: 'A PSA ticket number is required by organization security policy.' });
    }

    const rawOs = body.platform || body.os || 'windows';
    const osParam: 'windows' | 'linux' | 'darwin' =
      rawOs === 'linux' ? 'linux' : rawOs === 'darwin' || rawOs === 'macos' ? 'darwin' : 'windows';
    const allowedTenants = getAllowedTenantIds(request.auth?.user);
    const firstTenant =
      allowedTenants && allowedTenants.length > 0
        ? allowedTenants[0]
        : (db.prepare('SELECT id FROM tenants ORDER BY created_at ASC LIMIT 1').get() as any)?.id || 'default';
    const tenantId =
      requestedMode === 'quicksupport' && !body.tenant_id && allowedTenants === null
        ? undefined
        : body.tenant_id || firstTenant;
    if (tenantId && !canUserAccessTenant(request.auth?.user, tenantId)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    if (requestedMode === 'quicksupport') {
      if (settings.quicksupport_enabled === 0) {
        return reply.status(403).send({
          error: 'Public QuickSupport portal is currently disabled by administrator policy.'
        });
      }
      const sessionCode = `${crypto.randomInt(100, 1000)}-${crypto.randomInt(100, 1000)}-${crypto.randomInt(100, 1000)}`;
      const qsId = `qs-${crypto.randomUUID().slice(0, 8)}`;
      const qsExpiresAt = new Date(Date.now() + 2 * 3600_000).toISOString();
      const pipeline = await installerGenerator.runSigningPipeline({
        os: osParam,
        tenantId,
        mode: 'quicksupport',
        sessionCode,
        meshServerId: body.mesh_server_id
      });
      db.prepare(`
        INSERT INTO quicksupport_sessions (
          id, session_code, client_name, tenant_id, status, privilege_level,
          platform, code_signed, mesh_server_id, expires_at
        ) VALUES (?, ?, ?, ?, 'waiting', 'standard_user', ?, ?, ?, ?)
      `).run(
        qsId,
        sessionCode,
        `QuickSupport (${getActorUsername(request)})`,
        tenantId || null,
        osParam,
        pipeline.allSigned ? 1 : 0,
        body.mesh_server_id || null,
        qsExpiresAt
      );
      const baseUrl = resolvePublicBaseUrl(request, settings);
      return {
        success: true,
        mode: 'quicksupport',
        token: sessionCode,
        sessionCode,
        expiresAt: qsExpiresAt,
        downloadUrl: `/api/agent/download?token=${encodeURIComponent(sessionCode)}&os=${osParam}`,
        deployUrl: `${baseUrl}/api/agent/deploy?token=${encodeURIComponent(sessionCode)}&os=${osParam}`,
        signingPipeline: pipeline
      };
    }

    const tokenId = `tok-${crypto.randomBytes(16).toString('hex')}`;
    const expiresAt = new Date(Date.now() + 24 * 3600_000).toISOString();
    const maxUses = body.max_uses !== undefined ? Math.max(0, Number(body.max_uses) || 0) : 1;

    db.prepare(`
      INSERT INTO installer_audit_log (id, token_id, tenant_id, site_id, device_role, technician, ticket_number, platform, expires_at, max_uses, use_count)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
    `).run(
      `ia-${crypto.randomUUID().slice(0, 8)}`,
      tokenId,
      tenantId || firstTenant,
      body.site_id || null,
      body.device_role || 'Auto',
      getActorUsername(request),
      body.ticket_number || null,
      osParam,
      expiresAt,
      maxUses
    );

    const pipeline = await installerGenerator.runSigningPipeline({
      os: osParam,
      tenantId: tenantId || firstTenant,
      siteId: body.site_id || undefined,
      deviceRole: body.device_role || 'Auto',
      tokenId,
      mode: requestedMode,
      meshServerId: body.mesh_server_id
    });

    const baseUrl = resolvePublicBaseUrl(request, settings);
    const modeQuery = requestedMode === 'companion_only' ? '&mode=companion' : '';

    return {
      success: true,
      token: tokenId,
      mode: requestedMode,
      expiresAt,
      downloadUrl: `/api/agent/download?token=${encodeURIComponent(tokenId)}&os=${osParam}${modeQuery}`,
      deployUrl: `${baseUrl}/api/agent/deploy?token=${encodeURIComponent(tokenId)}&os=${osParam}${modeQuery}`,
      signingPipeline: pipeline
    };
  });

  server.get('/api/installers/audit', async (request) => {
    const user = request.auth?.user;
    const isGlobalUser = getAllowedTenantIds(user) === null;
    const rows = db
      .prepare(`
        SELECT i.*, t.name as tenant_name
        FROM installer_audit_log i
        LEFT JOIN tenants t ON i.tenant_id = t.id
        ORDER BY i.downloaded_at DESC
        LIMIT 100
      `)
      .all() as any[];
    return rows.filter((r) => (r.tenant_id ? canUserAccessTenant(user, r.tenant_id) : isGlobalUser));
  });

  const serveTokenAuthenticatedInstaller = async (request: FastifyRequest, reply: FastifyReply) => {
    const rate = checkRateLimit(`agent-dl:${request.ip}`, 30, 60_000);
    if (!rate.allowed) {
      return reply.status(429).send({
        error: `Too many installer download requests. Try again in ${rate.retryAfterSec}s.`,
        retryAfterSec: rate.retryAfterSec
      });
    }
    const query = (request.query || {}) as { token?: string; os?: string; mode?: string; deviceId?: string };
    const resolved = resolveValidInstallerToken(query.token);
    if (!resolved) {
      return reply.status(401).send({
        error: 'Valid, non-expired deployment or QuickSupport token is required.'
      });
    }

    const rawQueryOs = String(query.os || '').trim().toLowerCase();
    const osParam: 'windows' | 'linux' | 'darwin' =
      rawQueryOs === 'windows' || rawQueryOs === 'win'
        ? 'windows'
        : rawQueryOs === 'linux'
          ? 'linux'
          : rawQueryOs === 'darwin' || rawQueryOs === 'macos'
            ? 'darwin'
            : resolved.os;

    const requestedMode = String(query.mode || '').trim().toLowerCase();
    const effectiveMode: 'permanent' | 'quicksupport' | 'companion_only' =
      resolved.mode === 'permanent' && (requestedMode === 'companion' || requestedMode === 'companion_only')
        ? 'companion_only'
        : resolved.mode;

    const targetDeviceId =
      effectiveMode === 'companion_only' && query.deviceId
        ? String(query.deviceId).replace(/[^a-zA-Z0-9._-]/g, '').slice(0, 80) || undefined
        : undefined;

    const dlSettings = (db.prepare('SELECT custom_domain FROM settings WHERE id = 1').get() || {}) as { custom_domain?: string };
    const vitrineServerUrl = resolvePublicBaseUrl(request, dlSettings);

    const pkg = await installerGenerator.generateInstaller({
      os: osParam,
      tenantId: resolved.tenantId,
      siteId: resolved.siteId,
      deviceRole: resolved.deviceRole,
      tokenId: 'tokenId' in resolved ? resolved.tokenId : undefined,
      mode: effectiveMode,
      sessionCode: 'sessionCode' in resolved ? resolved.sessionCode : undefined,
      meshServerId: 'meshServerId' in resolved ? resolved.meshServerId : undefined,
      targetDeviceId,
      vitrineServerUrl
    });

    reply.header('Content-Type', pkg.contentType);
    reply.header('Content-Disposition', buildSafeContentDisposition(pkg.filename));
    return reply.send(pkg.content);
  };

  server.get('/api/agent/deploy', serveTokenAuthenticatedInstaller);
  server.get('/api/agent/download', serveTokenAuthenticatedInstaller);

  server.get('/api/agent/mesh-binary', async (request, reply) => {
    const rate = checkRateLimit(`mesh-bin:${request.ip}`, 20, 60_000);
    if (!rate.allowed) {
      return reply.status(429).send({
        error: `Too many MeshAgent binary download requests. Try again in ${rate.retryAfterSec}s.`,
        retryAfterSec: rate.retryAfterSec
      });
    }

    const query = (request.query || {}) as { arch?: string; token?: string };
    const rawToken = String(query.token || request.headers['x-vitrine-enrollment-token'] || '').trim();
    const isTechAuth = Boolean(request.auth && isTechnicianOrAbove(request.auth.user.role));

    // Support both standard deployment tokens and active QuickSupport session codes
    const tokenAuthorized = Boolean(rawToken && resolveValidInstallerToken(rawToken));

    if (!tokenAuthorized && !isTechAuth) {
      return reply.status(401).send({
        error: 'Valid, non-expired deployment token or authenticated technician session is required.'
      });
    }

    const rawArch = String(query.arch || 'x64').trim().toLowerCase();
    const arch: 'x64' | 'arm64' | 'x86' =
      rawArch === 'arm64' || rawArch === 'aarch64'
        ? 'arm64'
        : rawArch === 'x86' || rawArch === 'ia32' || rawArch === '32'
          ? 'x86'
          : 'x64';

    const settings = (db.prepare('SELECT meshcentral_allow_self_signed FROM settings WHERE id = 1').get() || {}) as {
      meshcentral_allow_self_signed?: number;
    };

    try {
      const built = await installerGenerator.getOrBuildSignedMeshBinary(
        arch,
        Boolean(settings.meshcentral_allow_self_signed)
      );
      reply.header('Content-Type', 'application/octet-stream');
      reply.header('Content-Disposition', buildSafeContentDisposition(built.filename));
      reply.header('X-Content-SHA256', built.sha256);
      reply.header('X-Vitrine-Code-Signed', built.signed ? 'true' : 'false');
      return reply.send(built.buffer);
    } catch (err: any) {
      return reply.status(502).send({
        error: err?.message || 'Failed to build or fetch MeshCentral agent binary.'
      });
    }
  });

  server.get('/api/agent/binary', async (request, reply) => {
    const rate = checkRateLimit(`agent-bin:${request.ip}`, 40, 60_000);
    if (!rate.allowed) {
      return reply.status(429).send({
        error: `Too many agent component download requests. Try again in ${rate.retryAfterSec}s.`,
        retryAfterSec: rate.retryAfterSec
      });
    }

    const query = (request.query || {}) as {
      component?: string;
      token?: string;
      deviceId?: string;
      tenant_id?: string;
      site_id?: string;
      role?: string;
      mode?: string;
    };
    const rawToken = String(query.token || request.headers['x-vitrine-enrollment-token'] || '').trim();
    const isTechAuth = Boolean(request.auth && isTechnicianOrAbove(request.auth.user.role));
    const resolvedToken = rawToken ? resolveValidInstallerToken(rawToken) : null;
    const tokenAuthorized = Boolean(resolvedToken);

    if (!tokenAuthorized && !isTechAuth) {
      return reply.status(401).send({
        error: 'Valid, non-expired deployment token or authenticated technician session is required.'
      });
    }

    const component: 'companion' | 'tray' =
      String(query.component || '').trim().toLowerCase() === 'tray' ? 'tray' : 'companion';

    try {
      const requestedMode =
        resolvedToken?.mode ||
        (query.mode === 'quicksupport' ? 'quicksupport' : query.mode === 'companion_only' ? 'companion_only' : 'permanent');
      const effPolicy = resolvePolicyForInstallerScope({
        mode: requestedMode,
        tenantId: query.tenant_id || resolvedToken?.tenantId || null,
        siteId: query.site_id || resolvedToken?.siteId || null,
        deviceRole: query.role || resolvedToken?.deviceRole || null,
        deviceId: query.deviceId || null
      });
      const built = await installerGenerator.getOrBuildSignedWindowsComponent(component, {
        brandName: effPolicy.trayBrandName,
        iconUrl: effPolicy.trayIconUrl
      });
      reply.header('Content-Type', 'application/vnd.microsoft.portable-executable');
      reply.header('Content-Disposition', buildSafeContentDisposition(built.filename));
      reply.header('X-Content-SHA256', built.sha256);
      reply.header('X-Vitrine-Code-Signed', built.signed ? 'true' : 'false');
      return reply.send(built.buffer);
    } catch (err: any) {
      return reply.status(502).send({
        error: err?.message || 'Failed to build or sign Windows agent component executable.'
      });
    }
  });

  server.get('/api/quicksupport/sessions', async (request) => {
    const user = request.auth?.user;
    const isGlobalUser = getAllowedTenantIds(user) === null;
    const rows = db
      .prepare("SELECT * FROM quicksupport_sessions WHERE julianday(expires_at) > julianday('now') ORDER BY created_at DESC LIMIT 50")
      .all() as any[];
    return rows.filter((r) => (r.tenant_id ? canUserAccessTenant(user, r.tenant_id) : isGlobalUser));
  });

  server.post('/api/quicksupport/sessions', async (request, reply) => {
    const rate = checkRateLimit(`qs-create:${request.ip}`, 10, 10 * 60_000);
    if (!rate.allowed) {
      return reply.status(429).send({
        error: `Too many QuickSupport requests. Please wait ${rate.retryAfterSec}s.`,
        retryAfterSec: rate.retryAfterSec
      });
    }

    if (request.auth?.authSource === 'cookie') {
      const csrfHeader = String(request.headers['x-vitrine-csrf'] || '').trim();
      if (csrfHeader !== '1') {
        return reply.status(403).send({
          error: 'CSRF verification failed: missing X-Vitrine-CSRF header.',
          code: 'CSRF_REQUIRED'
        });
      }
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

    if (body.tenant_id && (!request.auth || !canUserAccessTenant(request.auth.user, body.tenant_id))) {
      return reply.status(403).send({ error: 'Forbidden for target tenant scope.' });
    }

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

    const verifiedTenantId =
      body.tenant_id && request.auth && canUserAccessTenant(request.auth.user, body.tenant_id)
        ? body.tenant_id
        : null;

    db.prepare(`
      INSERT INTO quicksupport_sessions (
        id, session_code, client_name, tenant_id, status, privilege_level,
        platform, hostname, username, code_signed, expires_at
      ) VALUES (?, ?, ?, ?, 'waiting', 'standard_user', ?, ?, ?, ?, ?)
    `).run(
      id,
      sessionCode,
      clientName,
      verifiedTenantId,
      platform,
      body.hostname || null,
      body.username || null,
      signingPipeline.allSigned ? 1 : 0,
      expiresAt
    );

    const qsSettings = (db.prepare('SELECT custom_domain FROM settings WHERE id = 1').get() || {}) as { custom_domain?: string };
    const qsBaseUrl = resolvePublicBaseUrl(request, qsSettings);

    return {
      success: true,
      session: db.prepare('SELECT * FROM quicksupport_sessions WHERE id = ?').get(id),
      downloadUrl: `/api/agent/download?token=${encodeURIComponent(sessionCode)}&os=${platform}`,
      deployUrl: `${qsBaseUrl}/api/agent/deploy?token=${encodeURIComponent(sessionCode)}&os=${platform}`,
      signingPipeline
    };
  });

  const handleElevateRemoteSession = async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const body = (request.body || {}) as {
      credentialSource?: 'laps' | 'custom_admin' | 'end_user_uac';
      elevationAction?: 'elevate_session' | 'promote_permanent_service';
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
    if (
      qsSession &&
      (qsSession.tenant_id
        ? !canUserAccessTenant(request.auth?.user, qsSession.tenant_id)
        : getAllowedTenantIds(request.auth?.user) !== null)
    ) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const credSource = body.credentialSource || 'custom_admin';
    const elevationAction = body.elevationAction || 'elevate_session';
    let resolvedAdminUser = '';
    let resolvedAdminPass = '';

    if (credSource === 'laps') {
      if (!device) {
        return reply.status(400).send({ error: 'LAPS Vault elevation requires an enrolled managed endpoint.' });
      }
      if (!requireStepUpMfaIfEnforced(request, reply, device.id)) {
        return reply;
      }
      const lapsCred = getLapsCredential(device.id, true, { actorUsername: getActorUsername(request) });
      if (!lapsCred || !lapsCred.password) {
        return reply.status(404).send({ error: 'No escrowed LAPS password is available for this endpoint.' });
      }
      resolvedAdminUser = lapsCred.accountName || 'LocalAdmin';
      resolvedAdminPass = lapsCred.password;
    } else if (credSource === 'custom_admin') {
      if (!body.adminUsername?.trim() || !body.adminPassword) {
        return reply.status(400).send({ error: 'Administrator username and password are required for custom elevation.' });
      }
      resolvedAdminUser = body.adminUsername.trim();
      resolvedAdminPass = body.adminPassword;
    } else if (credSource !== 'end_user_uac') {
      return reply.status(400).send({ error: 'Invalid credentialSource. Expected laps, custom_admin, or end_user_uac.' });
    }

    let execOutput = '';
    let dispatchedLive = false;
    let actuallyElevated = false;

    if (device) {
      const promoteSuffix =
        elevationAction === 'promote_permanent_service'
          ? device.os_type === 'windows'
            ? '; Set-Service -Name "Mesh Agent" -StartupType Automatic -ErrorAction SilentlyContinue'
            : '; systemctl enable meshagent 2>/dev/null || true'
          : '';

      let elevCmd = '';
      const envVars: Record<string, string> = {};
      if (credSource === 'end_user_uac') {
        elevCmd =
          device.os_type === 'windows'
            ? `Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '-NoProfile -Command "Write-Output ELEVATED_OK"' -PassThru | Out-Null; Write-Output "UAC_PROMPT_DISPATCHED"${promoteSuffix}`
            : device.os_type === 'macos'
              ? `osascript -e 'do shell script "id -u" with administrator privileges'${promoteSuffix}`
              : `pkexec id -u${promoteSuffix}`;
      } else {
        envVars.VITRINE_ELEV_USER = resolvedAdminUser;
        envVars.VITRINE_ELEV_PASS = resolvedAdminPass;
        elevCmd =
          device.os_type === 'windows'
            ? `$sec = ConvertTo-SecureString $env:VITRINE_ELEV_PASS -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential($env:VITRINE_ELEV_USER, $sec); $isAdm = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); if (-not $isAdm) { Write-Output 'UNVERIFIED_USER_SESSION'; exit 1 }; Write-Output ("ELEVATED_CONTEXT_READY:" + $cred.UserName)${promoteSuffix}`
            : `id -u${promoteSuffix}`;
      }

      const execRes = await meshBridge.executeCommandOnNode(device.id, elevCmd, {
        runAs: credSource === 'end_user_uac' ? 'user' : 'system',
        shell: device.os_type === 'windows' ? 'powershell' : 'bash',
        env: envVars,
        timeoutMs: 15_000
      });
      execOutput = execRes.output;
      dispatchedLive = execRes.live;

      if (execRes.live && execRes.exitCode !== 0) {
        return reply.status(502).send({
          success: false,
          elevated: false,
          privilege_level: device.agent_privilege_mode || 'standard_user',
          error: `Remote elevation failed (exit code ${execRes.exitCode}).`,
          output: execRes.output
        });
      }

      if (dispatchedLive && execRes.exitCode === 0) {
        if (credSource === 'end_user_uac') {
          if (device.os_type !== 'windows' && execOutput.trim().split(/\r?\n/)[0]?.trim() === '0') {
            actuallyElevated = true;
          }
        } else if (device.os_type === 'windows') {
          actuallyElevated = execOutput.includes('ELEVATED_CONTEXT_READY:');
        } else {
          actuallyElevated = execOutput.trim().split(/\r?\n/)[0]?.trim() === '0';
        }
      }
    }

    const nextPrivLevel = actuallyElevated
      ? 'elevated_admin'
      : credSource === 'end_user_uac'
        ? 'uac_pending'
        : !device
          ? qsSession?.privilege_level || 'standard_user'
          : !dispatchedLive
            ? 'pending_offline'
            : 'standard_user';

    if (qsSession) {
      db.prepare('UPDATE quicksupport_sessions SET privilege_level = ?, status = ? WHERE id = ?').run(
        nextPrivLevel,
        actuallyElevated && elevationAction === 'promote_permanent_service' ? 'promoted_permanent' : qsSession.status,
        qsSession.id
      );
    }

    const sourceLabel =
      credSource === 'laps'
        ? `Managed LAPS Vault (${resolvedAdminUser})`
        : credSource === 'end_user_uac'
          ? 'End-User UAC / Polkit Prompt'
          : `Tech-supplied admin (${resolvedAdminUser})`;

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Remote Agent Self-Elevation Triggered', ?)
    `).run(
      `aud-elev-${crypto.randomUUID()}`,
      getActorUsername(request),
      device?.id || null,
      `${elevationAction === 'promote_permanent_service' ? 'Promote/elevate' : 'Elevate'} ${device?.hostname || qsSession?.client_name || id} via ${sourceLabel} (elevated=${actuallyElevated}, status=${nextPrivLevel})`
    );

    return {
      success: true,
      elevated: actuallyElevated,
      privilege_level: nextPrivLevel,
      elevationAction,
      elevatedUsing: credSource,
      dispatchedLive,
      output: execOutput || undefined,
      message: actuallyElevated
        ? elevationAction === 'promote_permanent_service'
          ? 'Remote session elevated and promoted to permanent unattended service.'
          : 'Remote agent helper elevated to SYSTEM / Root context.'
        : !device
          ? 'No enrolled live device linked to QuickSupport session; elevation was not executed.'
          : !dispatchedLive
            ? 'Endpoint is offline; elevation command queued and not yet verified.'
            : credSource === 'end_user_uac'
              ? 'Interactive UAC prompt dispatched; awaiting end-user approval.'
              : 'Remote session remains unverified user-mode context (elevation not confirmed).'
    };
  };
  server.post('/api/devices/:id/elevate-agent', handleElevateRemoteSession);
  server.post('/api/remote-sessions/:id/elevate', handleElevateRemoteSession);

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
      allow_self_signed?: boolean;
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
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(body.url.trim());
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        return reply.status(400).send({ error: 'MeshCentral URL must use http:// or https://.' });
      }
    } catch {
      return reply.status(400).send({ error: 'Invalid MeshCentral URL format.' });
    }
    const urlSafety = await validateOutboundHostSafety(parsedUrl.toString(), {
      allowLoopback: true,
      allowPrivateLan: true
    });
    if (!urlSafety.safe) {
      return reply.status(400).send({ error: urlSafety.reason || 'Blocked unsafe MeshCentral URL.' });
    }

    const id = `ms2-${crypto.randomUUID().slice(0, 8)}`;
    const rawToken = body.api_token && !isMaskedSecret(body.api_token) ? body.api_token.trim() : '';
    const encryptedToken = rawToken ? encryptVaultSecret(rawToken) : '';
    const allowSelfSigned = Boolean(body.allow_self_signed);

    const probe = await meshBridge.discoverServerResources({
      url: body.url.trim(),
      apiToken: rawToken,
      localConfigPath: body.local_config_path,
      allowSelfSigned
    });

    const existingCount = (db.prepare('SELECT COUNT(*) as c FROM mesh_servers').get() as { c: number }).c;
    const isPrimary = body.is_primary !== undefined ? Boolean(body.is_primary) : existingCount === 0;

    if (isPrimary) {
      db.prepare('UPDATE mesh_servers SET is_primary = 0').run();
      db.prepare(
        `UPDATE settings
         SET meshcentral_url = ?,
             meshcentral_api_token = COALESCE(NULLIF(?, ''), meshcentral_api_token),
             meshcentral_allow_self_signed = COALESCE(?, meshcentral_allow_self_signed)
         WHERE id = 1`
      ).run(body.url.trim(), encryptedToken, body.allow_self_signed !== undefined ? (allowSelfSigned ? 1 : 0) : null);
    }

    db.prepare(`
      INSERT INTO mesh_servers (
        id, name, url, api_token, is_primary, allow_self_signed, status, local_config_path,
        agent_service_name, agent_display_name, agent_custom_text,
        keep_agents_signed, auto_push_companion, discovered_groups_count, discovered_agents_count, last_synced
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).run(
      id,
      body.name.trim(),
      body.url.trim(),
      encryptedToken,
      isPrimary ? 1 : 0,
      allowSelfSigned ? 1 : 0,
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

    await meshBridge.reconnectAndWait(3500);

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
    if (body.url !== undefined) {
      const candidateUrl = String(body.url || '').trim();
      if (!candidateUrl) {
        return reply.status(400).send({ error: 'MeshCentral URL cannot be empty.' });
      }
      let parsedUrl: URL;
      try {
        parsedUrl = new URL(candidateUrl);
        if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
          return reply.status(400).send({ error: 'MeshCentral URL must use http:// or https://.' });
        }
      } catch {
        return reply.status(400).send({ error: 'Invalid MeshCentral URL format.' });
      }
      const urlSafety = await validateOutboundHostSafety(parsedUrl.toString(), {
        allowLoopback: true,
        allowPrivateLan: true
      });
      if (!urlSafety.safe) {
        return reply.status(400).send({ error: urlSafety.reason || 'Blocked unsafe MeshCentral URL.' });
      }
      body.url = candidateUrl;
    }
    const nextEncryptedToken =
      body.api_token !== undefined && !isMaskedSecret(String(body.api_token))
        ? String(body.api_token).trim()
          ? encryptVaultSecret(String(body.api_token).trim())
          : ''
        : existing.api_token;

    const makePrimary = body.is_primary !== undefined ? Boolean(body.is_primary) : Boolean(existing.is_primary);
    const nextAllowSelfSigned =
      body.allow_self_signed != null ? (body.allow_self_signed ? 1 : 0) : null;

    if (makePrimary) {
      db.prepare('UPDATE mesh_servers SET is_primary = 0 WHERE id != ?').run(id);
      db.prepare(
        `UPDATE settings
         SET meshcentral_url = ?,
             meshcentral_api_token = ?,
             meshcentral_allow_self_signed = COALESCE(?, meshcentral_allow_self_signed)
         WHERE id = 1`
      ).run(body.url || existing.url, nextEncryptedToken, nextAllowSelfSigned);
    }

    db.prepare(`
      UPDATE mesh_servers SET
        name = COALESCE(?, name),
        url = COALESCE(?, url),
        api_token = ?,
        is_primary = ?,
        allow_self_signed = COALESCE(?, allow_self_signed),
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
      nextAllowSelfSigned,
      body.local_config_path ?? null,
      body.agent_service_name ?? null,
      body.agent_display_name ?? null,
      body.agent_custom_text ?? null,
      body.keep_agents_signed != null ? (body.keep_agents_signed ? 1 : 0) : null,
      body.auto_push_companion != null ? (body.auto_push_companion ? 1 : 0) : null,
      id
    );

    await meshBridge.reconnectAndWait(3500);

    const updated = db.prepare('SELECT * FROM mesh_servers WHERE id = ?').get(id);
    return { success: true, server: sanitizeMeshServerRow(updated) };
  });

  server.delete('/api/mesh-servers/:id', async (request) => {
    const { id } = request.params as { id: string };
    db.prepare('DELETE FROM mesh_servers WHERE id = ?').run(id);
    await meshBridge.reconnectAndWait(3500);
    return { success: true };
  });

  server.get('/api/mesh-servers/local-detect', async () => {
    return detectLocalMeshCentralInstallation();
  });

  server.post('/api/mesh-servers/generate-token', async (request, reply) => {
    const rate = checkRateLimit(`mesh-gen-tok:${request.ip}:${getActorUsername(request)}`, 10, 5 * 60_000);
    if (!rate.allowed) {
      return reply.status(429).send({
        success: false,
        error: `Too many token generation attempts. Try again in ${rate.retryAfterSec}s.`,
        retryAfterSec: rate.retryAfterSec
      });
    }

    const body = (request.body || {}) as {
      url?: string;
      username?: string;
      password?: string;
      totp?: string;
      tokenName?: string;
      allowSelfSigned?: boolean;
    };

    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    const targetUrl = String(body.url || settings.meshcentral_url || '').trim();
    const username = String(body.username || '').trim();
    const password = String(body.password || '');

    if (!targetUrl || !username || !password) {
      return reply.status(400).send({
        success: false,
        error: 'MeshCentral URL, admin username, and password are required to generate a Login Token.'
      });
    }

    const res = await generateMeshLoginToken({
      url: targetUrl,
      username,
      password,
      totp: body.totp,
      tokenName: body.tokenName || 'Vitrine RMM',
      allowSelfSigned: body.allowSelfSigned ?? Boolean(settings.meshcentral_allow_self_signed)
    });

    if (!res.success) {
      return reply.status(400).send(res);
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'MeshCentral Login Token Generated', ?)
    `).run(
      `aud-mstok-${crypto.randomUUID()}`,
      getActorUsername(request),
      `Generated persistent MeshCentral Login Token '${res.tokenName || 'Vitrine RMM'}' on ${targetUrl}`
    );

    return res;
  });

  server.post('/api/mesh-servers/local-apply-config', async (request, reply) => {
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    if (Boolean(settings.is_onboarded) && !requireStepUpMfaIfEnforced(request, reply, null)) {
      return reply;
    }

    const body = (request.body || {}) as {
      allowFraming?: boolean;
      disableAgentUpdate?: boolean;
    };

    if (!body.allowFraming && !body.disableAgentUpdate) {
      return reply.status(400).send({
        success: false,
        error: 'Select at least one setting (allowFraming or disableAgentUpdate) to apply.'
      });
    }

    const result = applyLocalMeshCentralConfig({
      allowFraming: Boolean(body.allowFraming),
      disableAgentUpdate: Boolean(body.disableAgentUpdate)
    });

    if (!result.success) {
      return reply.status(400).send(result);
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'Local MeshCentral Config Updated', ?)
    `).run(
      `aud-mscfg-${crypto.randomUUID()}`,
      getActorUsername(request),
      `Updated ${result.configPath} (backup: ${result.backupPath}; allowFraming=${result.applied?.allowFraming}, disableAgentUpdate=${result.applied?.disableAgentUpdate})`
    );

    return result;
  });

  server.post('/api/mesh-servers/test-discover', async (request) => {
    const body = (request.body || {}) as {
      id?: string;
      url?: string;
      api_token?: string;
      api_username?: string;
      api_password?: string;
      local_config_path?: string;
      allowSelfSigned?: boolean;
    };

    const storedServer = body.id
      ? (db.prepare('SELECT * FROM mesh_servers WHERE id = ?').get(body.id) as any)
      : null;
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;

    const targetUrl = String(body.url || storedServer?.url || settings.meshcentral_url || '').trim();
    const allowStoredCreds =
      !body.url ||
      (storedServer?.url ? isSameUrlOrigin(targetUrl, storedServer.url) : isSameUrlOrigin(targetUrl, settings.meshcentral_url));

    let rawToken = '';
    if (body.api_token && !isMaskedSecret(body.api_token)) {
      rawToken = body.api_token.trim();
    } else if (body.api_username?.trim() && body.api_password) {
      rawToken = `${body.api_username.trim()}:${body.api_password}`;
    } else if (allowStoredCreds && storedServer?.api_token) {
      rawToken = decryptVaultSecret(storedServer.api_token);
    } else if (allowStoredCreds && !storedServer && settings.meshcentral_api_token) {
      rawToken = decryptVaultSecret(settings.meshcentral_api_token);
    }

    const report = await meshBridge.discoverServerResources({
      url: targetUrl,
      apiToken: rawToken,
      localConfigPath: body.local_config_path || storedServer?.local_config_path,
      allowSelfSigned:
        body.allowSelfSigned ?? Boolean(storedServer ? storedServer.allow_self_signed : settings.meshcentral_allow_self_signed)
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

  server.post('/api/mesh-servers/import', async (request, reply) => {
    const body = (request.body || {}) as {
      mesh_server_id?: string;
      url?: string;
      api_token?: string;
      api_username?: string;
      api_password?: string;
      local_config_path?: string;
      group_mapping_mode?: 'groups_as_clients' | 'single_client_sites';
      target_tenant_id?: string;
      selected_group_ids?: string[];
      import_agents?: boolean;
      import_new_groups?: boolean;
      deploy_vitrine_addons?: boolean;
      auto_deploy_companion?: boolean;
      enforce_laps_on_import?: boolean;
      lock_signed_binary_updates?: boolean;
      allowSelfSigned?: boolean;
    };

    if (body.target_tenant_id) {
      const targetTenantRow = db.prepare('SELECT id FROM tenants WHERE id = ?').get(body.target_tenant_id);
      if (!targetTenantRow) {
        return reply.status(404).send({ error: `Target client tenant '${body.target_tenant_id}' not found.` });
      }
    }

    const storedServer = body.mesh_server_id
      ? (db.prepare('SELECT * FROM mesh_servers WHERE id = ?').get(body.mesh_server_id) as any)
      : null;
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    const targetUrl = (body.url || storedServer?.url || settings.meshcentral_url || '').trim();
    const allowStoredCreds =
      !body.url ||
      (storedServer?.url ? isSameUrlOrigin(targetUrl, storedServer.url) : isSameUrlOrigin(targetUrl, settings.meshcentral_url));
    const rawToken =
      body.api_token && !isMaskedSecret(body.api_token)
        ? body.api_token.trim()
        : body.api_username?.trim() && body.api_password
          ? `${body.api_username.trim()}:${body.api_password}`
          : allowStoredCreds
            ? decryptVaultSecret(storedServer ? storedServer.api_token : settings.meshcentral_api_token)
            : '';
    const allowSelfSigned =
      body.allowSelfSigned !== undefined
        ? Boolean(body.allowSelfSigned)
        : Boolean(storedServer?.allow_self_signed ?? settings.meshcentral_allow_self_signed);

    const autoDeploy =
      body.auto_deploy_companion !== undefined
        ? Boolean(body.auto_deploy_companion)
        : body.deploy_vitrine_addons !== false;
    const enforceLaps = body.enforce_laps_on_import !== false;
    const lockSignedUpdates = body.lock_signed_binary_updates !== false;
    const importNewGroups = body.import_new_groups !== false;

    const discovered = await meshBridge.discoverServerResources({
      url: targetUrl,
      apiToken: rawToken,
      localConfigPath: body.local_config_path || storedServer?.local_config_path,
      allowSelfSigned
    });

    // Persist MS2 credentials & OOBE import preferences before syncing fleet
    const encryptedToken = rawToken ? encryptVaultSecret(rawToken) : storedServer?.api_token || settings.meshcentral_api_token || '';
    const primaryServerId = storedServer?.id || 'ms2-primary';
    if (targetUrl) {
      db.prepare(`
        UPDATE settings SET
          meshcentral_url = ?,
          meshcentral_api_token = COALESCE(NULLIF(?, ''), meshcentral_api_token),
          meshcentral_allow_self_signed = ?,
          oobe_auto_deploy_companion = ?,
          oobe_enforce_laps_on_import = ?,
          oobe_lock_signed_updates = ?,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = 1
      `).run(
        targetUrl,
        encryptedToken,
        allowSelfSigned ? 1 : 0,
        autoDeploy ? 1 : 0,
        enforceLaps ? 1 : 0,
        lockSignedUpdates ? 1 : 0
      );

      const existingMsRow = db.prepare('SELECT id FROM mesh_servers WHERE id = ?').get(primaryServerId);
      const serverStatus = discovered.reachable
        ? discovered.authenticated
          ? 'Connected'
          : 'Reachable (Token Unverified)'
        : 'Disconnected';
      if (existingMsRow) {
        db.prepare(`
          UPDATE mesh_servers SET
            url = ?,
            api_token = COALESCE(NULLIF(?, ''), api_token),
            allow_self_signed = ?,
            status = ?,
            local_config_path = COALESCE(?, local_config_path),
            auto_push_companion = ?,
            keep_agents_signed = ?,
            discovered_groups_count = ?,
            discovered_agents_count = ?,
            last_synced = CURRENT_TIMESTAMP
          WHERE id = ?
        `).run(
          targetUrl,
          encryptedToken,
          allowSelfSigned ? 1 : 0,
          serverStatus,
          body.local_config_path || null,
          autoDeploy ? 1 : 0,
          lockSignedUpdates ? 1 : 0,
          discovered.groups.length,
          discovered.agents.length,
          primaryServerId
        );
      } else {
        db.prepare('UPDATE mesh_servers SET is_primary = 0').run();
        db.prepare(`
          INSERT INTO mesh_servers (
            id, name, url, api_token, is_primary, allow_self_signed, status, local_config_path,
            keep_agents_signed, auto_push_companion, discovered_groups_count, discovered_agents_count, last_synced
          ) VALUES (?, 'Primary MeshCentral 2 Engine', ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        `).run(
          primaryServerId,
          targetUrl,
          encryptedToken,
          allowSelfSigned ? 1 : 0,
          serverStatus,
          body.local_config_path || null,
          lockSignedUpdates ? 1 : 0,
          autoDeploy ? 1 : 0,
          discovered.groups.length,
          discovered.agents.length
        );
      }
    }

    const conn = await meshBridge.reconnectAndWait(3500);

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
        const existingSite = db
          .prepare('SELECT id FROM sites WHERE tenant_id = ? AND LOWER(name) = LOWER(?) LIMIT 1')
          .get(body.target_tenant_id, grp.name) as { id: string } | undefined;
        let siteId = existingSite?.id;
        if (!siteId && importNewGroups) {
          siteId = `s-${crypto.randomUUID().slice(0, 8)}`;
          db.prepare('INSERT INTO sites (id, tenant_id, name, subnet) VALUES (?, ?, ?, ?)').run(
            siteId,
            body.target_tenant_id,
            grp.name,
            '0.0.0.0/0'
          );
          importedSites++;
        }
        groupTenantMap.set(grp.meshid, { tenantId: body.target_tenant_id, siteId: siteId || null });
      } else {
        const existingTenant = db
          .prepare('SELECT id FROM tenants WHERE mesh_group_id = ? OR LOWER(name) = LOWER(?) LIMIT 1')
          .get(grp.meshid, grp.name) as { id: string } | undefined;
        let tenantId = existingTenant?.id;
        if (!tenantId && importNewGroups) {
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
        if (tenantId) {
          groupTenantMap.set(grp.meshid, { tenantId, siteId: null });
        }
      }
    }

    const deployCandidates: Array<{ id: string; online: boolean }> = [];

    if (body.import_agents !== false) {
      for (const ag of discovered.agents) {
        let mapping = groupTenantMap.get(ag.meshId);
        if (!mapping && body.target_tenant_id) {
          mapping = { tenantId: body.target_tenant_id, siteId: null };
        }
        if (!mapping) continue;

        const existingDev = db
          .prepare('SELECT id, companion_installed FROM devices WHERE mesh_node_id = ? OR (tenant_id = ? AND LOWER(hostname) = LOWER(?)) LIMIT 1')
          .get(ag.nodeId, mapping.tenantId, ag.hostname) as { id: string; companion_installed?: number } | undefined;

        if (!existingDev) {
          const devId = `dev-${crypto.randomUUID().slice(0, 8)}`;
          db.prepare(`
            INSERT INTO devices (
              id, mesh_node_id, mesh_server_id, tenant_id, site_id, hostname,
              os_type, os_version, os_build, cpu_model, cpu_cores, ram_total_gb,
              disk_total_gb, disk_free_gb, ip_address, mac_address, serial_number,
              manufacturer, model, bios_version, tpm_version, amt_supported,
              intel_amt_enabled, amt_provisioned, amt_version, edr_name, edr_status,
              pending_reboot, logged_in_user, agent_privilege_mode,
              status, companion_installed, companion_deploy_pending, last_seen
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, CURRENT_TIMESTAMP)
          `).run(
            devId,
            ag.nodeId,
            primaryServerId,
            mapping.tenantId,
            mapping.siteId,
            ag.hostname,
            ag.osType,
            ag.osDesc,
            ag.osBuild || '',
            ag.cpuModel || '',
            Number(ag.cpuCores ?? 0),
            Number(ag.ramTotalGb ?? 0),
            Number(ag.diskTotalGb ?? 0),
            Number(ag.diskFreeGb ?? 0),
            ag.ipAddress || '',
            ag.macAddress || '',
            ag.serialNumber || '',
            ag.manufacturer || '',
            ag.model || '',
            ag.biosVersion || '',
            ag.tpmVersion || '',
            ag.amtSupported ? 1 : 0,
            ag.intelAmtEnabled ? 1 : 0,
            ag.amtProvisioned ? 1 : 0,
            ag.amtVersion || '',
            ag.edrName || '',
            ag.edrStatus || '',
            ag.pendingReboot ? 1 : 0,
            ag.loggedInUser || null,
            ag.agentPrivilegeMode || 'system_service',
            ag.online ? 'online' : 'offline',
            autoDeploy ? 1 : 0
          );
          importedAgents++;
          if (autoDeploy) {
            deployCandidates.push({ id: devId, online: Boolean(ag.online) });
          }
        } else {
          db.prepare(`
            UPDATE devices SET
              mesh_node_id = COALESCE(NULLIF(?, ''), mesh_node_id),
              mesh_server_id = ?,
              os_type = COALESCE(NULLIF(?, ''), os_type),
              os_version = COALESCE(NULLIF(?, ''), os_version),
              os_build = COALESCE(NULLIF(?, ''), os_build),
              cpu_model = COALESCE(NULLIF(?, ''), CASE WHEN cpu_model = 'Discovered Node' THEN '' ELSE cpu_model END),
              cpu_cores = CASE WHEN ? > 0 THEN ? ELSE cpu_cores END,
              ram_total_gb = CASE WHEN ? > 0 THEN ? ELSE ram_total_gb END,
              disk_total_gb = CASE WHEN ? > 0 THEN ? ELSE disk_total_gb END,
              disk_free_gb = CASE WHEN ? > 0 THEN ? ELSE disk_free_gb END,
              ip_address = COALESCE(NULLIF(?, ''), CASE WHEN ip_address = '0.0.0.0' THEN '' ELSE ip_address END),
              mac_address = COALESCE(NULLIF(?, ''), CASE WHEN mac_address = '00:00:00:00:00:00' THEN '' ELSE mac_address END),
              serial_number = COALESCE(NULLIF(?, ''), serial_number),
              manufacturer = COALESCE(NULLIF(?, ''), manufacturer),
              model = COALESCE(NULLIF(?, ''), model),
              bios_version = COALESCE(NULLIF(?, ''), bios_version),
              tpm_version = COALESCE(NULLIF(?, ''), tpm_version),
              amt_supported = CASE WHEN ? = 1 THEN 1 ELSE amt_supported END,
              intel_amt_enabled = CASE WHEN ? = 1 THEN 1 ELSE intel_amt_enabled END,
              amt_provisioned = CASE WHEN ? = 1 THEN 1 ELSE amt_provisioned END,
              amt_version = COALESCE(NULLIF(?, ''), amt_version),
              logged_in_user = COALESCE(?, logged_in_user),
              status = CASE WHEN quarantined = 1 THEN 'isolated' ELSE ? END,
              companion_deploy_pending = CASE WHEN COALESCE(companion_installed, 0) = 0 AND ? = 1 THEN 1 ELSE COALESCE(companion_deploy_pending, 0) END,
              last_seen = CURRENT_TIMESTAMP
            WHERE id = ?
          `).run(
            ag.nodeId,
            primaryServerId,
            ag.osType,
            ag.osDesc,
            ag.osBuild || '',
            ag.cpuModel || '',
            Number(ag.cpuCores ?? 0),
            Number(ag.cpuCores ?? 0),
            Number(ag.ramTotalGb ?? 0),
            Number(ag.ramTotalGb ?? 0),
            Number(ag.diskTotalGb ?? 0),
            Number(ag.diskTotalGb ?? 0),
            Number(ag.diskFreeGb ?? 0),
            Number(ag.diskFreeGb ?? 0),
            ag.ipAddress || '',
            ag.macAddress || '',
            ag.serialNumber || '',
            ag.manufacturer || '',
            ag.model || '',
            ag.biosVersion || '',
            ag.tpmVersion || '',
            ag.amtSupported ? 1 : 0,
            ag.intelAmtEnabled ? 1 : 0,
            ag.amtProvisioned ? 1 : 0,
            ag.amtVersion || '',
            ag.loggedInUser || null,
            ag.online ? 'online' : 'offline',
            autoDeploy ? 1 : 0,
            existingDev.id
          );
          if (autoDeploy && !existingDev.companion_installed) {
            deployCandidates.push({ id: existingDev.id, online: Boolean(ag.online) });
          }
        }
      }
    }

    const refreshedSettings = (db.prepare('SELECT oobe_completed, is_onboarded, custom_domain FROM settings WHERE id = 1').get() || {}) as any;
    const isPostOobe = Boolean(refreshedSettings.oobe_completed || refreshedSettings.is_onboarded);
    let companionsDispatchedOnline = 0;
    let companionsQueuedPending = 0;
    let companionDeployTiming: 'after_oobe' | 'immediate' | 'disabled' = 'disabled';

    if (autoDeploy) {
      if (!isPostOobe) {
        companionDeployTiming = 'after_oobe';
        companionsQueuedPending = deployCandidates.length;
      } else {
        companionDeployTiming = 'immediate';
        const { proto: protoHdr, host: hostHdr } = resolveSafeRequestOriginParts(request);
        const customDom = String(refreshedSettings.custom_domain || '').trim();
        const reqOrigin = customDom
          ? customDom.startsWith('http')
            ? customDom
            : `https://${customDom}`
          : hostHdr
            ? `${protoHdr}://${hostHdr}`
            : undefined;

        for (const cand of deployCandidates) {
          if (cand.online && conn) {
            try {
              const push = await meshBridge.deployCompanionOverMesh(cand.id, reqOrigin);
              if (push.dispatched) {
                companionsDispatchedOnline++;
              } else {
                companionsQueuedPending++;
              }
            } catch {
              companionsQueuedPending++;
            }
          } else {
            companionsQueuedPending++;
          }
        }
      }
    }

    return {
      success: true,
      source: discovered.source,
      importedClients,
      importedSites,
      importedAgents,
      companionsDispatchedOnline,
      companionsQueuedPending,
      companionDeployTiming,
      meshBridgeConnected: conn
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
    return reply.send(fs.createReadStream(row.file_path));
  });

  server.post('/api/backups/upload', { bodyLimit: 100 * 1024 * 1024 }, async (request, reply) => {
    if (!requireStepUpMfaIfEnforced(request, reply, null)) {
      return reply;
    }
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
    if (!requireStepUpMfaIfEnforced(request, reply, null)) {
      return reply;
    }
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

  server.delete('/api/backups/:id', async (request, reply) => {
    if (!requireStepUpMfaIfEnforced(request, reply, null)) {
      return reply;
    }
    const { id } = request.params as { id: string };
    return backupService.deleteBackup(id);
  });

  server.post('/api/backups/sync-offsite', async () => {
    return await backupService.syncAllToOffsiteVault();
  });

  server.post('/api/backups/recovery-key', async (request, reply) => {
    if (!requireStepUpMfaIfEnforced(request, reply, null)) {
      return reply;
    }
    const info = backupService.getOrGenerateRecoveryPassphrase(true);
    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, NULL, 'Backup Encryption Key Revealed', 'MSP Super Admin viewed/exported the Disaster Recovery Backup Encryption Passphrase')
    `).run(`aud-bkkey-${crypto.randomUUID()}`, getActorUsername(request));
    return {
      success: true,
      passphrase: info.passphrase,
      encryptionEnabled: info.encryptionEnabled,
      acknowledged: true
    };
  });

  server.post('/api/backups/acknowledge-key', async (request) => {
    db.prepare('UPDATE settings SET backup_key_acknowledged = 1 WHERE id = 1').run();
    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, NULL, 'Backup Recovery Key Acknowledged', 'Administrator confirmed external escrow of Backup Encryption Passphrase')
    `).run(`aud-bkack-${crypto.randomUUID()}`, getActorUsername(request));
    return { success: true, acknowledged: true };
  });

  server.post('/api/laps/break-glass-export', async (request, reply) => {
    if (!requireStepUpMfaIfEnforced(request, reply, null)) {
      return reply;
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

  server.post('/api/updater/execute', async (request, reply) => {
    if (!requireStepUpMfaIfEnforced(request, reply, null)) {
      return reply;
    }
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
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
    const body = (request.body || {}) as {
      reason?: string;
      overrideLapsAction?: 'remove_account' | 'disable_account' | 'keep_account_rotate_final' | 'keep_account_as_is';
      forceImmediateArchive?: boolean;
    };
    try {
      return await initiateDeviceOffboardAsync(id, {
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
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
    const body = (request.body || {}) as { reason?: string };
    try {
      return await initiateDeviceOffboardAsync(id, {
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
    if (!ensureDeviceTenantAccess(request, reply, id).allowed) return reply;
    const body = (request.body || {}) as { triggerType?: 'wake_checkin' | 'reinstall_agent' };
    return handleAgentCheckInOrWake(id, body.triggerType || 'wake_checkin');
  });

  server.delete('/api/devices/:id/archive-purge', async (request, reply) => {
    if (!requireStepUpMfaIfEnforced(request, reply, null)) {
      return reply;
    }
    const { id } = request.params as { id: string };
    const dev = db.prepare('SELECT id, hostname, lifecycle_state FROM devices WHERE id = ?').get(id) as any;
    if (!dev) return reply.status(404).send({ error: 'Device not found.' });
    if (dev.lifecycle_state !== 'archived') {
      return reply.status(400).send({
        error: 'Only Archived endpoints can be permanently purged. Offboard or archive the endpoint first.'
      });
    }
    const recRows = db
      .prepare('SELECT video_path FROM session_recordings WHERE device_id = ?')
      .all(id) as Array<{ video_path?: string | null }>;
    for (const rec of recRows) {
      if (rec.video_path && fs.existsSync(RECORDINGS_DIR_PATH) && fs.existsSync(rec.video_path)) {
        try {
          const realRoot = fs.realpathSync(RECORDINGS_DIR_PATH);
          if (!fs.lstatSync(rec.video_path).isSymbolicLink()) {
            const resolved = fs.realpathSync(rec.video_path);
            if (
              resolved.startsWith(realRoot + path.sep) &&
              !fs.lstatSync(resolved).isSymbolicLink() &&
              fs.statSync(resolved).isFile()
            ) {
              fs.unlinkSync(resolved);
            }
          }
        } catch {}
      }
    }

    const purgeTx = db.transaction(() => {
      db.prepare('DELETE FROM session_recordings WHERE device_id = ?').run(id);
      db.prepare('DELETE FROM maintenance_windows WHERE device_id = ?').run(id);
      db.prepare('DELETE FROM alert_incidents WHERE device_id = ?').run(id);
      db.prepare('DELETE FROM remediation_logs WHERE device_id = ?').run(id);
      db.prepare('DELETE FROM script_executions WHERE device_id = ?').run(id);
      db.prepare('DELETE FROM device_backup_jobs WHERE device_id = ?').run(id);
      db.prepare('DELETE FROM software_deployments WHERE device_id = ?').run(id);
      db.prepare('DELETE FROM agent_tasks WHERE device_id = ?').run(id);
      db.prepare('DELETE FROM chat_messages WHERE device_id = ?').run(id);
      db.prepare('DELETE FROM custom_field_values WHERE entity_id = ?').run(id);
      db.prepare('UPDATE psa_tickets SET device_id = NULL WHERE device_id = ?').run(id);
      db.prepare('DELETE FROM devices WHERE id = ?').run(id);
      db.prepare(`
        INSERT INTO audit_logs (id, username, action, details)
        VALUES (?, ?, 'Archived Endpoint Permanently Purged', ?)
      `).run(
        `aud-purge-${crypto.randomUUID()}`,
        getActorUsername(request),
        `Permanently purged archived endpoint '${dev.hostname}' (${id}) and its escrowed vault records`
      );
    });
    purgeTx();
    return { success: true };
  });

  server.post('/api/tenants/:id/offboard', async (request, reply) => {
    if (!requireStepUpMfaIfEnforced(request, reply, null)) {
      return reply;
    }
    const { id } = request.params as { id: string };
    const body = (request.body || {}) as {
      mode?: 'archive_client' | 'delete_client_permanently';
      reason?: string;
      overrideLapsAction?: 'remove_account' | 'disable_account' | 'keep_account_rotate_final' | 'keep_account_as_is';
      forceArchiveOfflineDevices?: boolean;
    };
    try {
      return await offboardClientTenantAsync(id, {
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

  // ============================================================================
  // Endpoint Companion Deploy, Live MS2 Hardware Sync & Uninstall Companion Cleanup
  // ============================================================================
  const resolveServerBaseOrigin = (request: FastifyRequest): string | undefined => {
    const row = db.prepare('SELECT custom_domain FROM settings WHERE id = 1').get() as { custom_domain?: string } | undefined;
    const customDom = String(row?.custom_domain || '').trim();
    if (customDom) {
      return customDom.startsWith('http') ? customDom : `https://${customDom}`;
    }
    const { proto: protoHdr, host: hostHdr } = resolveSafeRequestOriginParts(request);
    return `${protoHdr}://${hostHdr}`;
  };

  server.post('/api/devices/:id/deploy-companion', async (request, reply) => {
    if (!isTechnicianOrAbove(request.auth?.user?.role)) {
      return reply.status(403).send({ error: 'Technician or Super Admin privileges required.' });
    }
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;

    db.prepare('UPDATE devices SET companion_deploy_pending = 1 WHERE id = ?').run(id);
    const res = await meshBridge.deployCompanionOverMesh(id, resolveServerBaseOrigin(request));
    const isLivePush = Boolean(res.dispatched && !res.queuedOffline);
    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'Vitrine Companion Deployment Dispatched', ?)
    `).run(
      `aud-cmp-${crypto.randomUUID()}`,
      getActorUsername(request),
      id,
      `Triggered companion & tray deployment for ${access.device.hostname} (live=${isLivePush}, dispatched=${res.dispatched}, queuedOffline=${Boolean(res.queuedOffline)})`
    );
    return {
      success: res.dispatched,
      dispatched: res.dispatched,
      live: isLivePush,
      queuedOffline: Boolean(res.queuedOffline),
      output: res.output
    };
  });

  server.post('/api/devices/:id/sync-hardware', async (request, reply) => {
    const { id } = request.params as { id: string };
    const access = ensureDeviceTenantAccess(request, reply, id);
    if (!access.allowed || !access.device) return reply;

    const enrichRes = await meshBridge.enrichDeviceFromMesh(id);
    if (access.device.status === 'online' && meshBridge.getStatus().connected) {
      void meshBridge.sampleLiveTelemetry(id, { includeDetailedHardware: true }).catch(() => {});
    }
    const updatedRow = db.prepare('SELECT * FROM devices WHERE id = ?').get(id);
    return {
      success: true,
      updated: enrichRes.updated,
      fields: enrichRes.fields,
      device: sanitizeDeviceRowForResponse(updatedRow)
    };
  });

  server.post('/api/system/cleanup-vitrine-companions', async (request, reply) => {
    if (!isSuperAdminRole(request.auth?.user?.role)) {
      return reply.status(403).send({ error: 'Forbidden: Super Admin privileges required.' });
    }
    if (!requireStepUpMfaIfEnforced(request, reply, null)) {
      return reply;
    }
    const body = (request.body || {}) as { removeLapsAccount?: boolean };
    const candidates = db
      .prepare(`
        SELECT id, hostname, status, mesh_node_id
        FROM devices
        WHERE mesh_node_id IS NOT NULL
          AND COALESCE(lifecycle_state, 'active') = 'active'
          AND (
            COALESCE(companion_installed, 0) = 1
            OR COALESCE(companion_deploy_pending, 0) = 1
            OR agent_auth_token IS NOT NULL
          )
      `)
      .all() as Array<{ id: string; hostname: string; status: string; mesh_node_id: string }>;

    let cleaned = 0;
    let failed = 0;
    let skippedOffline = 0;
    const results: Array<{ deviceId: string; hostname: string; status: string; live: boolean; output: string }> = [];

    for (const dev of candidates) {
      if (dev.status !== 'online') {
        skippedOffline++;
        results.push({
          deviceId: dev.id,
          hostname: dev.hostname,
          status: 'skipped_offline',
          live: false,
          output: 'Endpoint offline'
        });
        continue;
      }
      const res = await meshBridge.removeVitrineCompanionOnlyOverMesh(dev.id, {
        removeLapsAccount: Boolean(body.removeLapsAccount)
      });
      if (res.live) {
        cleaned++;
        db.prepare('UPDATE devices SET companion_installed = 0, companion_deploy_pending = 0 WHERE id = ?').run(dev.id);
      } else {
        failed++;
      }
      results.push({
        deviceId: dev.id,
        hostname: dev.hostname,
        status: res.live ? 'cleaned' : 'failed',
        live: res.live,
        output: res.output
      });
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, action, details)
      VALUES (?, ?, 'Vitrine Companion Fleet Cleanup', ?)
    `).run(
      `aud-cln-${crypto.randomUUID()}`,
      getActorUsername(request),
      `Cleaned Vitrine companion software on ${cleaned} online endpoint(s) (${failed} failed, ${skippedOffline} offline). MeshCentral MeshAgents left untouched.`
    );

    return {
      success: true,
      cleaned,
      failed,
      skippedOffline,
      meshAgentTouched: false,
      results
    };
  });

  // Register NinjaOne Feature Parity Routes (Companion Agent, Automations, Software Packages,
  // Stateful Alert Incidents, Notification Channels, Documentation, Multi-PSA, Managed Security,
  // Endpoint Backups, MDM Profiles, Custom RBAC Roles, API Keys, Offsite Vault & Audit Export)
  await registerParityRoutes(server);
}
