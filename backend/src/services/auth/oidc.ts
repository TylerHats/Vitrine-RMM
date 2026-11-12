import crypto from 'crypto';
import type { FastifyRequest } from 'fastify';
import { db } from '../../db/index.js';
import { decryptVaultSecret, validateOutboundHostSafety } from '../vault/index.js';
import { AuthenticatedUser } from './index.js';

interface OidcDiscoveryMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri?: string;
}

interface PendingPkceState {
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
  createdAtMs: number;
}

const PKCE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const pendingStates = new Map<string, PendingPkceState>();

function prunePendingStates(): void {
  const cutoff = Date.now() - PKCE_TTL_MS;
  for (const [k, v] of pendingStates.entries()) {
    if (v.createdAtMs < cutoff) {
      pendingStates.delete(k);
    }
  }
}

export function getStoredOidcSettings(): {
  enabled: boolean;
  issuerUrl: string;
  clientId: string;
  clientSecret: string;
} {
  const row = (db
    .prepare('SELECT oidc_enabled, oidc_issuer_url, oidc_client_id, oidc_client_secret FROM settings WHERE id = 1')
    .get() || {}) as any;

  const issuerUrl = String(row.oidc_issuer_url || '').trim().replace(/\/+$/, '');
  const clientId = String(row.oidc_client_id || '').trim();
  const clientSecret = decryptVaultSecret(row.oidc_client_secret) || '';

  return {
    enabled: Boolean(row.oidc_enabled && issuerUrl && clientId),
    issuerUrl,
    clientId,
    clientSecret
  };
}

export function resolveRequestOrigin(req: FastifyRequest): string {
  const protoHeader = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const proto = protoHeader === 'https' || req.protocol === 'https' ? 'https' : 'http';
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || 'localhost:3001')
    .split(',')[0]
    .trim();
  return `${proto}://${host}`;
}

export async function fetchOidcDiscovery(issuerUrlRaw: string): Promise<OidcDiscoveryMetadata> {
  const cleanIssuer = (issuerUrlRaw || '').trim().replace(/\/+$/, '');
  if (!cleanIssuer) {
    throw new Error('OIDC Issuer URL is not configured.');
  }

  const discoveryUrl = cleanIssuer.endsWith('/.well-known/openid-configuration')
    ? cleanIssuer
    : `${cleanIssuer}/.well-known/openid-configuration`;

  const safety = await validateOutboundHostSafety(discoveryUrl, { allowLoopback: true });
  if (!safety.safe) {
    throw new Error(safety.reason || 'OIDC Issuer URL blocked by SSRF security policy.');
  }

  const res = await fetch(discoveryUrl, {
    method: 'GET',
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(8000)
  });

  if (!res.ok) {
    throw new Error(`OIDC discovery failed with HTTP ${res.status} from ${discoveryUrl}`);
  }

  const doc = (await res.json()) as Partial<OidcDiscoveryMetadata>;
  if (!doc.authorization_endpoint || !doc.token_endpoint) {
    throw new Error('OIDC discovery metadata is missing authorization_endpoint or token_endpoint.');
  }

  // Validate discovered endpoints against SSRF DNS rebinding as well
  for (const ep of [doc.authorization_endpoint, doc.token_endpoint, doc.userinfo_endpoint].filter(Boolean) as string[]) {
    const epSafety = await validateOutboundHostSafety(ep, { allowLoopback: true });
    if (!epSafety.safe) {
      throw new Error(`OIDC endpoint '${ep}' blocked: ${epSafety.reason}`);
    }
  }

  return doc as OidcDiscoveryMetadata;
}

export async function testOidcDiscoveryConfig(override?: {
  issuerUrl?: string;
  clientId?: string;
}): Promise<{
  success: boolean;
  reachable: boolean;
  issuer?: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  userinfoEndpoint?: string;
  error?: string;
}> {
  try {
    const stored = getStoredOidcSettings();
    const issuerUrl = (override?.issuerUrl ?? stored.issuerUrl).trim();
    if (!issuerUrl) {
      return { success: false, reachable: false, error: 'OIDC Issuer URL is empty.' };
    }
    const meta = await fetchOidcDiscovery(issuerUrl);
    return {
      success: true,
      reachable: true,
      issuer: meta.issuer,
      authorizationEndpoint: meta.authorization_endpoint,
      tokenEndpoint: meta.token_endpoint,
      userinfoEndpoint: meta.userinfo_endpoint
    };
  } catch (err: any) {
    return {
      success: false,
      reachable: false,
      error: err?.message || 'Failed to reach OIDC discovery endpoint.'
    };
  }
}

export async function createOidcAuthorizationRedirect(req: FastifyRequest): Promise<string> {
  prunePendingStates();
  const cfg = getStoredOidcSettings();
  if (!cfg.enabled) {
    throw new Error('Enterprise SSO (OIDC) is not configured.');
  }

  const meta = await fetchOidcDiscovery(cfg.issuerUrl);
  const state = crypto.randomBytes(24).toString('base64url');
  const nonce = crypto.randomBytes(24).toString('base64url');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  const redirectUri = `${resolveRequestOrigin(req)}/api/auth/oidc/callback`;

  pendingStates.set(state, {
    state,
    nonce,
    codeVerifier,
    redirectUri,
    createdAtMs: Date.now()
  });

  const authUrl = new URL(meta.authorization_endpoint);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', cfg.clientId);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('scope', 'openid profile email');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('nonce', nonce);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  return authUrl.toString();
}

function decodeJwtPayloadUnsafe(jwt: string): Record<string, any> | null {
  const parts = (jwt || '').split('.');
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

export async function completeOidcCallback(params: {
  code: string;
  state: string;
}): Promise<AuthenticatedUser> {
  prunePendingStates();
  const pending = pendingStates.get(params.state);
  if (!pending) {
    throw new Error('OIDC login state expired or invalid. Please initiate SSO sign-in again.');
  }
  pendingStates.delete(params.state);

  const cfg = getStoredOidcSettings();
  if (!cfg.enabled) {
    throw new Error('OIDC SSO is not enabled.');
  }

  const meta = await fetchOidcDiscovery(cfg.issuerUrl);
  const tokenSafety = await validateOutboundHostSafety(meta.token_endpoint, { allowLoopback: true });
  if (!tokenSafety.safe) {
    throw new Error(tokenSafety.reason || 'Token endpoint blocked by SSRF guard.');
  }

  const form = new URLSearchParams();
  form.set('grant_type', 'authorization_code');
  form.set('code', params.code);
  form.set('redirect_uri', pending.redirectUri);
  form.set('client_id', cfg.clientId);
  form.set('code_verifier', pending.codeVerifier);
  if (cfg.clientSecret) {
    form.set('client_secret', cfg.clientSecret);
  }

  const tokenRes = await fetch(meta.token_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json'
    },
    body: form.toString(),
    signal: AbortSignal.timeout(10000)
  });

  if (!tokenRes.ok) {
    const errTxt = (await tokenRes.text()).slice(0, 200);
    throw new Error(`OIDC token exchange failed (HTTP ${tokenRes.status}): ${errTxt}`);
  }

  const tokenData = (await tokenRes.json()) as {
    access_token?: string;
    id_token?: string;
  };

  let claims: Record<string, any> = {};
  if (tokenData.id_token) {
    const idClaims = decodeJwtPayloadUnsafe(tokenData.id_token);
    if (!idClaims) {
      throw new Error('Malformed OIDC id_token returned by identity provider.');
    }
    if (idClaims.nonce && idClaims.nonce !== pending.nonce) {
      throw new Error('OIDC nonce mismatch detected.');
    }
    if (idClaims.exp && Number(idClaims.exp) * 1000 < Date.now() - 30_000) {
      throw new Error('OIDC id_token is expired.');
    }
    claims = { ...idClaims };
  }

  if (tokenData.access_token && meta.userinfo_endpoint) {
    const uiSafety = await validateOutboundHostSafety(meta.userinfo_endpoint, { allowLoopback: true });
    if (uiSafety.safe) {
      const uiRes = await fetch(meta.userinfo_endpoint, {
        headers: { Authorization: `Bearer ${tokenData.access_token}`, Accept: 'application/json' },
        signal: AbortSignal.timeout(8000)
      });
      if (uiRes.ok) {
        const uiJson = (await uiRes.json()) as Record<string, any>;
        claims = { ...claims, ...uiJson };
      }
    }
  }

  const email = String(claims.email || '').trim().toLowerCase();
  const preferredUsername = String(claims.preferred_username || claims.name || email.split('@')[0] || '')
    .trim()
    .replace(/[^a-zA-Z0-9._-]/g, '');

  if (!email && !preferredUsername) {
    throw new Error('OIDC identity provider did not return an email or username claim.');
  }

  const existing = db
    .prepare(
      "SELECT id, username, email, role, tenant_id, totp_enabled FROM users WHERE (email != '' AND LOWER(email) = LOWER(?)) OR LOWER(username) = LOWER(?) LIMIT 1"
    )
    .get(email || '__none__', preferredUsername || '__none__') as any;

  if (!existing) {
    throw new Error(
      `No Vitrine RMM user account matches SSO identity '${email || preferredUsername}'. Ask an MSP Super Admin to pre-register this email under Settings -> Team & RBAC.`
    );
  }

  db.prepare(`
    INSERT INTO audit_logs (id, username, action, details)
    VALUES (?, ?, 'OIDC SSO Login', ?)
  `).run(
    `aud-oidc-${crypto.randomUUID()}`,
    existing.username,
    `Authenticated via OpenID Connect SSO (${meta.issuer || cfg.issuerUrl}) as ${email || preferredUsername}.`
  );

  return {
    id: existing.id,
    username: existing.username,
    email: existing.email,
    role: existing.role,
    tenant_id: existing.tenant_id || null,
    totp_enabled: Boolean(existing.totp_enabled)
  };
}
