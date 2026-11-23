import crypto from 'crypto';
import type { FastifyRequest } from 'fastify';
import { db } from '../../db/index.js';
import { decryptVaultSecret, safeOutboundFetch, validateOutboundHostSafety } from '../vault/index.js';
import { AuthenticatedUser, hydrateUserRow } from './index.js';

interface OidcDiscoveryMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri: string;
}

interface PendingPkceState {
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
  createdAtMs: number;
}

const PKCE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const JWKS_CACHE_TTL_MS = 15 * 60 * 1000;
const MAX_PENDING_OIDC_STATES = 1000;
const MAX_JWKS_CACHE_ENTRIES = 50;
const pendingStates = new Map<string, PendingPkceState>();
const jwksCache = new Map<string, { keys: any[]; fetchedAtMs: number }>();

function prunePendingStates(): void {
  const cutoff = Date.now() - PKCE_TTL_MS;
  for (const [k, v] of pendingStates.entries()) {
    if (v.createdAtMs < cutoff) {
      pendingStates.delete(k);
    }
  }
  while (pendingStates.size >= MAX_PENDING_OIDC_STATES) {
    const oldest = pendingStates.keys().next().value;
    if (oldest === undefined) break;
    pendingStates.delete(oldest);
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
  const settings = (db.prepare('SELECT custom_domain FROM settings WHERE id = 1').get() || {}) as {
    custom_domain?: string;
  };
  const configuredDomain = String(settings.custom_domain || '').trim();
  if (configuredDomain) {
    if (/^https?:\/\//i.test(configuredDomain)) {
      const parsed = new URL(configuredDomain);
      return `${parsed.protocol}//${parsed.host}`;
    }
    const cleanHost = configuredDomain.split('/')[0].trim();
    if (/^[a-zA-Z0-9.:[\]-]+$/.test(cleanHost)) {
      return `https://${cleanHost}`;
    }
  }

  const trustProxy = process.env.VITRINE_TRUST_PROXY === 'true';
  const protoHeader = trustProxy ? String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() : '';
  const proto = protoHeader === 'https' || req.protocol === 'https' ? 'https' : 'http';
  const rawHost = String(
    (trustProxy ? req.headers['x-forwarded-host'] : '') || req.headers.host || 'localhost:8080'
  )
    .split(',')[0]
    .trim();
  const safeHost = /^[a-zA-Z0-9.:[\]-]+$/.test(rawHost) ? rawHost : 'localhost:8080';
  return `${proto}://${safeHost}`;
}

const allowLocalOidc = () => ({
  allowLoopback: process.env.ALLOW_LOCAL_OIDC === 'true' || process.env.NODE_ENV !== 'production',
  allowPrivateLan:
    process.env.VITRINE_ALLOW_PRIVATE_OIDC === 'true' ||
    process.env.ALLOW_LOCAL_OIDC === 'true' ||
    process.env.NODE_ENV !== 'production'
});

function ensureOidcTransportSecurity(targetUrl: string, allowLoopback: boolean): void {
  const parsed = new URL(targetUrl);
  if (process.env.NODE_ENV === 'production' && parsed.protocol !== 'https:') {
    const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    const isLocal = allowLoopback && (host === 'localhost' || host === '127.0.0.1' || host === '::1');
    if (!isLocal) {
      throw new Error(`OIDC endpoint '${parsed.origin}' must use HTTPS in production.`);
    }
  }
}

export async function fetchOidcDiscovery(issuerUrlRaw: string): Promise<OidcDiscoveryMetadata> {
  const cleanIssuer = (issuerUrlRaw || '').trim().replace(/\/+$/, '');
  if (!cleanIssuer) {
    throw new Error('OIDC Issuer URL is not configured.');
  }

  const discoveryUrl = cleanIssuer.endsWith('/.well-known/openid-configuration')
    ? cleanIssuer
    : `${cleanIssuer}/.well-known/openid-configuration`;

  const safetyOpts = allowLocalOidc();
  ensureOidcTransportSecurity(discoveryUrl, safetyOpts.allowLoopback);
  const res = await safeOutboundFetch(discoveryUrl, {
    method: 'GET',
    headers: { Accept: 'application/json' },
    timeoutMs: 8000,
    ...safetyOpts
  });

  if (!res.ok) {
    throw new Error(`OIDC discovery failed with HTTP ${res.status}`);
  }

  const doc = res.json<Partial<OidcDiscoveryMetadata>>();
  if (!doc.issuer || !doc.authorization_endpoint || !doc.token_endpoint || !doc.jwks_uri) {
    throw new Error(
      'OIDC discovery metadata is missing required fields (issuer, authorization_endpoint, token_endpoint, or jwks_uri).'
    );
  }

  for (const ep of [
    doc.authorization_endpoint,
    doc.token_endpoint,
    doc.jwks_uri,
    doc.userinfo_endpoint
  ].filter(Boolean) as string[]) {
    ensureOidcTransportSecurity(ep, safetyOpts.allowLoopback);
    const epSafety = await validateOutboundHostSafety(ep, safetyOpts);
    if (!epSafety.safe) {
      throw new Error(`OIDC endpoint '${ep}' blocked: ${epSafety.reason}`);
    }
  }

  return doc as OidcDiscoveryMetadata;
}

async function fetchJwksKeys(jwksUri: string, forceRefresh = false): Promise<any[]> {
  const cached = jwksCache.get(jwksUri);
  if (!forceRefresh && cached && Date.now() - cached.fetchedAtMs < JWKS_CACHE_TTL_MS) {
    return cached.keys;
  }

  const res = await safeOutboundFetch(jwksUri, {
    method: 'GET',
    headers: { Accept: 'application/json' },
    timeoutMs: 8000,
    ...allowLocalOidc()
  });

  if (!res.ok) {
    throw new Error(`Failed to fetch OIDC JWKS keys (HTTP ${res.status})`);
  }

  const parsed = res.json<{ keys?: any[] }>();
  if (!Array.isArray(parsed?.keys) || parsed.keys.length === 0) {
    throw new Error('OIDC JWKS endpoint returned no signing keys.');
  }

  if (jwksCache.size >= MAX_JWKS_CACHE_ENTRIES && !jwksCache.has(jwksUri)) {
    const oldest = jwksCache.keys().next().value;
    if (oldest !== undefined) jwksCache.delete(oldest);
  }
  jwksCache.set(jwksUri, { keys: parsed.keys, fetchedAtMs: Date.now() });
  return parsed.keys;
}

function verifyJwsSignatureWithJwk(
  alg: string,
  signingInput: Buffer,
  signature: Buffer,
  jwk: Record<string, any>
): boolean {
  const pubKey = crypto.createPublicKey({ key: jwk as any, format: 'jwk' });

  switch (alg) {
    case 'RS256':
      return crypto.verify('RSA-SHA256', signingInput, pubKey, signature);
    case 'RS384':
      return crypto.verify('RSA-SHA384', signingInput, pubKey, signature);
    case 'RS512':
      return crypto.verify('RSA-SHA512', signingInput, pubKey, signature);
    case 'PS256':
      return crypto.verify(
        'sha256',
        signingInput,
        { key: pubKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
        signature
      );
    case 'PS384':
      return crypto.verify(
        'sha384',
        signingInput,
        { key: pubKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 },
        signature
      );
    case 'PS512':
      return crypto.verify(
        'sha512',
        signingInput,
        { key: pubKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 64 },
        signature
      );
    case 'ES256':
      return crypto.verify('sha256', signingInput, { key: pubKey, dsaEncoding: 'ieee-p1363' }, signature);
    case 'ES384':
      return crypto.verify('sha384', signingInput, { key: pubKey, dsaEncoding: 'ieee-p1363' }, signature);
    case 'ES512':
      return crypto.verify('sha512', signingInput, { key: pubKey, dsaEncoding: 'ieee-p1363' }, signature);
    case 'EdDSA':
      return crypto.verify(null, signingInput, pubKey, signature);
    default:
      throw new Error(`Unsupported OIDC JWT signing algorithm '${alg}'.`);
  }
}

export async function verifyOidcIdToken(params: {
  idToken: string;
  jwksUri: string;
  expectedIssuer: string;
  expectedAudience: string;
  expectedNonce: string;
}): Promise<Record<string, any>> {
  const parts = (params.idToken || '').split('.');
  if (parts.length !== 3) {
    throw new Error('Malformed OIDC id_token structure.');
  }

  let header: Record<string, any>;
  let payload: Record<string, any>;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    throw new Error('Malformed OIDC id_token JSON encoding.');
  }

  const alg = String(header.alg || '');
  if (!alg || alg.toLowerCase() === 'none' || alg.startsWith('HS')) {
    throw new Error(`Rejected insecure or non-asymmetric OIDC JWT algorithm '${alg || 'none'}'.`);
  }

  const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii');
  const signature = Buffer.from(parts[2], 'base64url');

  const tryMatchKeys = (keys: any[]): boolean => {
    const candidates = keys.filter((k) => {
      if (k.use && k.use !== 'sig') return false;
      if (header.kid && k.kid && k.kid !== header.kid) return false;
      if (k.alg && k.alg !== alg) return false;
      return true;
    });
    for (const jwk of candidates) {
      try {
        if (verifyJwsSignatureWithJwk(alg, signingInput, signature, jwk)) {
          return true;
        }
      } catch {
        // Try next candidate JWK
      }
    }
    return false;
  };

  let keys = await fetchJwksKeys(params.jwksUri, false);
  let verified = tryMatchKeys(keys);
  if (!verified) {
    // Refresh JWKS cache once in case IdP rotated signing keys
    keys = await fetchJwksKeys(params.jwksUri, true);
    verified = tryMatchKeys(keys);
  }

  if (!verified) {
    throw new Error('OIDC id_token cryptographic signature verification failed against IdP JWKS.');
  }

  // Validate Issuer
  const cleanExpectedIss = params.expectedIssuer.replace(/\/+$/, '');
  const cleanActualIss = String(payload.iss || '').replace(/\/+$/, '');
  if (!cleanActualIss || cleanActualIss !== cleanExpectedIss) {
    throw new Error(`OIDC issuer mismatch: expected '${cleanExpectedIss}', received '${cleanActualIss}'.`);
  }

  // Validate Audience & Authorized Party
  const aud = payload.aud;
  const audMatches = Array.isArray(aud)
    ? aud.includes(params.expectedAudience)
    : aud === params.expectedAudience;
  if (!audMatches) {
    throw new Error('OIDC audience (aud) claim does not match configured Client ID.');
  }
  if (Array.isArray(aud) && aud.length > 1 && (!payload.azp || payload.azp !== params.expectedAudience)) {
    throw new Error('OIDC authorized party (azp) claim missing or mismatched for multi-audience token.');
  }

  // Validate Time Claims (exp, nbf, iat) with 30s clock skew tolerance
  const nowSec = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < nowSec - 30) {
    throw new Error('OIDC id_token is expired or missing exp claim.');
  }
  if (typeof payload.iat !== 'number' || payload.iat > nowSec + 300) {
    throw new Error('OIDC id_token has invalid or future iat claim.');
  }
  if (typeof payload.nbf === 'number' && payload.nbf > nowSec + 30) {
    throw new Error('OIDC id_token is not yet valid (nbf claim).');
  }

  // Mandatory Nonce Verification (prevents replay/CSRF token substitution)
  if (!payload.nonce || payload.nonce !== params.expectedNonce) {
    throw new Error('OIDC nonce missing or mismatched.');
  }

  if (!payload.sub || typeof payload.sub !== 'string') {
    throw new Error('OIDC id_token is missing mandatory subject (sub) claim.');
  }

  return payload;
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
  jwksUri?: string;
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
      userinfoEndpoint: meta.userinfo_endpoint,
      jwksUri: meta.jwks_uri
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
  const expectedCfgIssuer = cfg.issuerUrl
    .replace(/\/\.well-known\/openid-configuration\/?$/i, '')
    .replace(/\/+$/, '');
  const discoveredMetaIssuer = String(meta.issuer || '').trim().replace(/\/+$/, '');
  if (!discoveredMetaIssuer || discoveredMetaIssuer !== expectedCfgIssuer) {
    throw new Error(
      `OIDC discovery issuer mismatch: expected '${expectedCfgIssuer}', received '${discoveredMetaIssuer}'.`
    );
  }
  const safetyOpts = allowLocalOidc();

  const form = new URLSearchParams();
  form.set('grant_type', 'authorization_code');
  form.set('code', params.code);
  form.set('redirect_uri', pending.redirectUri);
  form.set('client_id', cfg.clientId);
  form.set('code_verifier', pending.codeVerifier);
  if (cfg.clientSecret) {
    form.set('client_secret', cfg.clientSecret);
  }

  const tokenRes = await safeOutboundFetch(meta.token_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json'
    },
    body: form.toString(),
    timeoutMs: 10000,
    ...safetyOpts
  });

  if (!tokenRes.ok) {
    throw new Error(`OIDC token exchange failed (HTTP ${tokenRes.status}). Verify OIDC Client ID, Secret, and Redirect URI.`);
  }

  const tokenData = tokenRes.json<{
    access_token?: string;
    id_token?: string;
  }>();

  if (!tokenData.id_token) {
    throw new Error('Identity provider did not return a signed OIDC id_token.');
  }

  // Cryptographically verify id_token signature & mandatory OIDC claims
  let claims = await verifyOidcIdToken({
    idToken: tokenData.id_token,
    jwksUri: meta.jwks_uri,
    expectedIssuer: meta.issuer,
    expectedAudience: cfg.clientId,
    expectedNonce: pending.nonce
  });

  if (tokenData.access_token && meta.userinfo_endpoint) {
    try {
      const uiRes = await safeOutboundFetch(meta.userinfo_endpoint, {
        headers: { Authorization: `Bearer ${tokenData.access_token}`, Accept: 'application/json' },
        timeoutMs: 8000,
        ...safetyOpts
      });
      if (uiRes.ok) {
        const uiJson = uiRes.json<Record<string, any>>();
        if (uiJson.sub && uiJson.sub !== claims.sub) {
          throw new Error('OIDC userinfo subject mismatch.');
        }
        claims = { ...uiJson, ...claims };
      }
    } catch (uiErr: any) {
      if (uiErr?.message?.includes('mismatch')) throw uiErr;
    }
  }

  const issuer = String(meta.issuer).replace(/\/+$/, '');
  const subject = String(claims.sub);
  const email = String(claims.email || '').trim().toLowerCase();
  const emailVerified = claims.email_verified === true || claims.email_verified === 'true';

  // 1. Primary lookup: immutable (oidc_issuer, oidc_sub) binding
  let existing = db
    .prepare(
      'SELECT id, username, email, role, tenant_id, totp_enabled, totp_confirmed_at, custom_role_id, oidc_issuer, oidc_sub FROM users WHERE oidc_issuer = ? AND oidc_sub = ? LIMIT 1'
    )
    .get(issuer, subject) as any;

  // 2. First-time linking: strictly verified full email match ONLY (never username or local-part!)
  if (!existing && email) {
    if (!emailVerified) {
      throw new Error('OIDC email address is not marked as verified (email_verified=true required).');
    }
    const byEmail = db
      .prepare(
        "SELECT id, username, email, role, tenant_id, totp_enabled, totp_confirmed_at, custom_role_id, oidc_issuer, oidc_sub FROM users WHERE email != '' AND LOWER(email) = LOWER(?) LIMIT 1"
      )
      .get(email) as any;

    if (byEmail) {
      if (byEmail.oidc_sub && (byEmail.oidc_sub !== subject || byEmail.oidc_issuer !== issuer)) {
        throw new Error('This Vitrine RMM user is already bound to a different OIDC subject identity.');
      }
      db.prepare('UPDATE users SET oidc_issuer = ?, oidc_sub = ? WHERE id = ?').run(issuer, subject, byEmail.id);
      existing = byEmail;
    }
  }

  if (!existing) {
    throw new Error(
      `No Vitrine RMM user account matches verified SSO email '${email || subject}'. Ask an MSP Super Admin to pre-register this exact email under Settings -> Team & RBAC.`
    );
  }

  db.prepare(`
    INSERT INTO audit_logs (id, username, action, details)
    VALUES (?, ?, 'OIDC SSO Login', ?)
  `).run(
    `aud-oidc-${crypto.randomUUID()}`,
    existing.username,
    `Authenticated via verified OpenID Connect SSO (${issuer}, sub=${subject}) as ${email || existing.email}.`
  );

  return hydrateUserRow(existing);
}
