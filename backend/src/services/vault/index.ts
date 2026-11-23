import crypto from 'crypto';
import dns from 'dns';
import fs from 'fs';
import http from 'http';
import https from 'https';
import net from 'net';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const MASKED_SECRET = '••••••••••••';

function resolveDataDirForVault(): string {
  if (process.env.DATA_DIR && process.env.DATA_DIR.trim()) {
    const dir = path.resolve(process.env.DATA_DIR.trim());
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    return dir;
  }
  const candidates = [
    path.resolve(process.cwd(), 'data'),
    path.resolve(process.cwd(), '../data'),
    path.resolve(__dirname, '../../../../data'),
    path.resolve(__dirname, '../../../data')
  ];
  const found = candidates.find((p) => fs.existsSync(p)) || candidates[0];
  if (!fs.existsSync(found)) {
    fs.mkdirSync(found, { recursive: true, mode: 0o700 });
  }
  return found;
}

interface PersistedVaultKeyMaterial {
  masterSecretHex: string;
  kdfSaltHex: string;
  createdAt: string;
}

let cachedMasterKey: Buffer | null = null;
let cachedEnvDeterministicKey: Buffer | null = null;
const DETERMINISTIC_ENV_SALT = crypto
  .createHash('sha256')
  .update('vitrine-rmm-env-master-key-salt-v2')
  .digest()
  .subarray(0, 16);
const LEGACY_SEED_KEY = crypto.scryptSync(
  'vitrine-rmm-laps-master-key-production-seed-9812',
  'salt',
  32
);

export function getVaultMasterKey(): Buffer {
  if (cachedMasterKey) return cachedMasterKey;

  const dataDir = resolveDataDirForVault();
  const keyFilePath = path.join(dataDir, '.vault-key.json');
  let material: PersistedVaultKeyMaterial | null = null;

  const envMaster =
    (process.env.VITRINE_MASTER_KEY && process.env.VITRINE_MASTER_KEY.trim()) ||
    (process.env.LAPS_MASTER_SECRET && process.env.LAPS_MASTER_SECRET.trim()) ||
    '';

  if (fs.existsSync(keyFilePath)) {
    try {
      material = JSON.parse(fs.readFileSync(keyFilePath, 'utf8')) as PersistedVaultKeyMaterial;
    } catch {
      material = null;
    }
  }

  if (!material || !material.kdfSaltHex || !material.masterSecretHex) {
    // Use deterministic salt when VITRINE_MASTER_KEY is configured so disaster recovery
    // with VITRINE_MASTER_KEY alone succeeds even if .vault-key.json is lost.
    const saltHex =
      envMaster.length >= 16
        ? DETERMINISTIC_ENV_SALT.toString('hex')
        : crypto.randomBytes(16).toString('hex');
    material = {
      masterSecretHex: crypto.randomBytes(32).toString('hex'),
      kdfSaltHex: saltHex,
      createdAt: new Date().toISOString()
    };
    fs.writeFileSync(keyFilePath, JSON.stringify(material, null, 2), { encoding: 'utf8', mode: 0o600 });
    try {
      fs.chmodSync(keyFilePath, 0o600);
    } catch {
      // Ignore chmod error on non-POSIX FS
    }
  }

  if (envMaster.length >= 16) {
    cachedEnvDeterministicKey = crypto.scryptSync(envMaster, DETERMINISTIC_ENV_SALT, 32);
  }

  const rawSecret = envMaster.length >= 16 ? envMaster : material.masterSecretHex;
  const saltBuf = Buffer.from(material.kdfSaltHex, 'hex');
  cachedMasterKey = crypto.scryptSync(rawSecret, saltBuf, 32);
  return cachedMasterKey;
}

export function reloadVaultMasterKey(): Buffer {
  cachedMasterKey = null;
  cachedEnvDeterministicKey = null;
  return getVaultMasterKey();
}

function parseIpv6ToWords(ip: string): number[] | null {
  let addr = ip.trim().toLowerCase();
  const zoneIdx = addr.indexOf('%');
  if (zoneIdx !== -1) addr = addr.slice(0, zoneIdx);
  if (net.isIP(addr) !== 6) return null;

  // Handle dotted-quad tail (e.g. ::ffff:127.0.0.1)
  const lastColon = addr.lastIndexOf(':');
  if (lastColon !== -1 && addr.slice(lastColon + 1).includes('.')) {
    const v4Part = addr.slice(lastColon + 1);
    const octets = v4Part.split('.').map((p) => parseInt(p, 10));
    if (octets.length !== 4 || octets.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
    const hi = ((octets[0] << 8) | octets[1]).toString(16);
    const lo = ((octets[2] << 8) | octets[3]).toString(16);
    addr = `${addr.slice(0, lastColon)}:${hi}:${lo}`;
  }

  const halves = addr.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - (left.length + right.length);
  if (halves.length === 1 && missing !== 0) return null;
  if (halves.length === 2 && missing < 1) return null;

  const full = [...left, ...Array(Math.max(0, missing)).fill('0'), ...right];
  if (full.length !== 8) return null;
  const words = full.map((h) => parseInt(h || '0', 16));
  if (words.some((w) => Number.isNaN(w) || w < 0 || w > 0xffff)) return null;
  return words;
}

export interface OutboundSafetyOptions {
  allowLoopback?: boolean;
  allowPrivateLan?: boolean;
}

export function isBlockedOutboundIp(
  ipRaw: string,
  allowLoopbackOrOptions: boolean | OutboundSafetyOptions = false
): boolean {
  const opts: OutboundSafetyOptions =
    typeof allowLoopbackOrOptions === 'boolean'
      ? { allowLoopback: allowLoopbackOrOptions, allowPrivateLan: false }
      : allowLoopbackOrOptions;
  const allowLoopback = Boolean(opts.allowLoopback);
  const allowPrivateLan = Boolean(opts.allowPrivateLan);

  const ip = (ipRaw || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!ip) return true;

  const checkIpv4Octets = (parts: number[]): boolean => {
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
    const [a, b, c] = parts;
    // Unspecified 0.0.0.0/8
    if (a === 0) return true;
    // Loopback 127.0.0.0/8
    if (a === 127) return !allowLoopback;
    // Link-local / AWS & Azure & GCP cloud metadata 169.254.0.0/16
    if (a === 169 && b === 254) return true;
    // Carrier-Grade NAT 100.64.0.0/10 (includes Alibaba Cloud IMDS 100.100.100.200)
    if (a === 100 && b >= 64 && b <= 127) return true;
    // RFC1918 Private LAN ranges (10/8, 172.16/12, 192.168/16)
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) {
      return !allowPrivateLan;
    }
    // Special-purpose IETF / TEST-NET / Benchmarking ranges
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a === 198 && b === 51 && c === 100) return true;
    if (a === 203 && b === 0 && c === 113) return true;
    // Multicast / broadcast 224.0.0.0+
    if (a >= 224) return true;
    return false;
  };

  const version = net.isIP(ip);
  if (version === 4) {
    return checkIpv4Octets(ip.split('.').map((p) => parseInt(p, 10)));
  }

  if (version === 6) {
    const words = parseIpv6ToWords(ip);
    if (!words) return true;

    const allZeroPrefix5 = words[0] === 0 && words[1] === 0 && words[2] === 0 && words[3] === 0 && words[4] === 0;
    // Unspecified ::
    if (allZeroPrefix5 && words[5] === 0 && words[6] === 0 && words[7] === 0) return true;
    // Loopback ::1
    if (allZeroPrefix5 && words[5] === 0 && words[6] === 0 && words[7] === 1) return !allowLoopback;

    // IPv4-mapped (::ffff:0:0/96) or IPv4-compatible (::/96)
    if (allZeroPrefix5 && (words[5] === 0xffff || words[5] === 0)) {
      const octets = [(words[6] >> 8) & 0xff, words[6] & 0xff, (words[7] >> 8) & 0xff, words[7] & 0xff];
      return checkIpv4Octets(octets);
    }

    // NAT64 well-known prefix 64:ff9b::/96 and local-use 64:ff9b:1::/48
    if (words[0] === 0x0064 && words[1] === 0xff9b) {
      const octets = [(words[6] >> 8) & 0xff, words[6] & 0xff, (words[7] >> 8) & 0xff, words[7] & 0xff];
      return checkIpv4Octets(octets);
    }

    // 6to4 2002::/16 embeds IPv4 in words[1..2]
    if (words[0] === 0x2002) {
      const octets = [(words[1] >> 8) & 0xff, words[1] & 0xff, (words[2] >> 8) & 0xff, words[2] & 0xff];
      return checkIpv4Octets(octets);
    }

    // Link-local fe80::/10 or multicast ff00::/8
    if ((words[0] & 0xffc0) === 0xfe80 || (words[0] & 0xff00) === 0xff00) return true;

    // AWS EC2 IPv6 IMDS fd00:ec2::254
    if (words[0] === 0xfd00 && words[1] === 0x0ec2) return true;

    // IPv6 Unique Local Addresses fc00::/7
    if ((words[0] & 0xfe00) === 0xfc00) {
      return !allowPrivateLan;
    }

    return false;
  }

  return true;
}

export async function validateOutboundHostSafety(
  rawUrlOrHost: string,
  options?: OutboundSafetyOptions
): Promise<{ safe: boolean; reason?: string; resolvedAddresses?: string[]; hostname?: string }> {
  const allowLoopback = Boolean(options?.allowLoopback);
  const allowPrivateLan = Boolean(options?.allowPrivateLan);
  const safetyOpts: OutboundSafetyOptions = { allowLoopback, allowPrivateLan };

  const trimmed = (rawUrlOrHost || '').trim();
  if (!trimmed) {
    return { safe: false, reason: 'Target host or URL is empty.' };
  }

  let hostname = trimmed;
  if (trimmed.includes('://')) {
    try {
      const parsed = new URL(trimmed);
      if (
        parsed.protocol !== 'http:' &&
        parsed.protocol !== 'https:' &&
        parsed.protocol !== 'ws:' &&
        parsed.protocol !== 'wss:'
      ) {
        return { safe: false, reason: `Unsupported outbound protocol '${parsed.protocol}'.` };
      }
      hostname = parsed.hostname;
    } catch {
      return { safe: false, reason: 'Invalid URL format.' };
    }
  } else {
    hostname = trimmed.replace(/^\[|\]$/g, '').split('/')[0];
    if (hostname.includes(':') && net.isIP(hostname) === 0) {
      hostname = hostname.split(':')[0];
    }
  }

  hostname = hostname.replace(/^\[|\]$/g, '').trim().toLowerCase();
  if (!hostname) {
    return { safe: false, reason: 'Target hostname is empty.' };
  }

  if (
    hostname === 'metadata.google.internal' ||
    hostname === 'metadata' ||
    hostname.endsWith('.metadata.google.internal') ||
    hostname === 'instance-data' ||
    hostname.endsWith('.internal.cloudapp.net')
  ) {
    return { safe: false, reason: 'Cloud metadata hostnames are blocked for SSRF protection.' };
  }

  if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
    return allowLoopback
      ? { safe: true, resolvedAddresses: ['127.0.0.1'], hostname }
      : { safe: false, reason: 'Loopback targets are disallowed for this endpoint.' };
  }

  if (net.isIP(hostname) !== 0) {
    if (isBlockedOutboundIp(hostname, safetyOpts)) {
      return {
        safe: false,
        reason: `Target IP '${hostname}' is blocked by outbound SSRF security policy.`
      };
    }
    return { safe: true, resolvedAddresses: [hostname], hostname };
  }

  try {
    const records = await dns.promises.lookup(hostname, { all: true, verbatim: true });
    if (!records || records.length === 0) {
      return { safe: false, reason: `Hostname '${hostname}' did not resolve to any IP address.` };
    }
    const addrs = records.map((r) => r.address);
    for (const addr of addrs) {
      if (isBlockedOutboundIp(addr, safetyOpts)) {
        return {
          safe: false,
          reason: `Hostname '${hostname}' resolved to restricted IP '${addr}' (DNS-rebinding / SSRF guard).`
        };
      }
    }
    return { safe: true, resolvedAddresses: addrs, hostname };
  } catch (err: any) {
    return {
      safe: false,
      reason: `DNS lookup failed for '${hostname}': ${err?.code || err?.message || 'ENOTFOUND'}`
    };
  }
}

export interface SafeOutboundResponse {
  ok: boolean;
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  bodyBuffer: Buffer;
  text: () => string;
  json: <T = any>() => T;
}

/**
 * DNS-pinned, non-redirecting HTTP/HTTPS client that eliminates DNS-rebinding TOCTOU
 * and prevents 301/302/307/308 credential forwarding to internal metadata services.
 */
export async function safeOutboundFetch(
  urlStr: string,
  options?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string | Buffer;
    timeoutMs?: number;
    maxBytes?: number;
    rejectUnauthorized?: boolean;
    allowSelfSigned?: boolean;
    allowInsecureTls?: boolean;
    expectedCertSha256?: string;
    allowLoopback?: boolean;
    allowPrivateLan?: boolean;
    safety?: OutboundSafetyOptions;
  }
): Promise<SafeOutboundResponse> {
  const parsed = new URL(urlStr);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Unsupported HTTP protocol: ${parsed.protocol}`);
  }

  const safety = await validateOutboundHostSafety(urlStr, {
    allowLoopback: options?.allowLoopback ?? options?.safety?.allowLoopback,
    allowPrivateLan: options?.allowPrivateLan ?? options?.safety?.allowPrivateLan
  });
  if (!safety.safe || !safety.resolvedAddresses?.length) {
    throw new Error(safety.reason || 'Blocked by outbound SSRF policy');
  }

  const pinnedIp = safety.resolvedAddresses[0];
  const pinnedFamily = net.isIP(pinnedIp) === 6 ? 6 : 4;
  const timeoutMs = options?.timeoutMs ?? 8000;
  const maxBytes = options?.maxBytes ?? 10 * 1024 * 1024;
  const isHttps = parsed.protocol === 'https:';
  const transport = isHttps ? https : http;

  const pinnedLookup = (
    _host: string,
    lookupOpts: dns.LookupOptions,
    cb: (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family?: number) => void
  ) => {
    if (lookupOpts && lookupOpts.all) {
      cb(null, [{ address: pinnedIp, family: pinnedFamily }]);
    } else {
      cb(null, pinnedIp, pinnedFamily);
    }
  };

  return new Promise<SafeOutboundResponse>((resolve, reject) => {
    let settled = false;
    let activeRes: http.IncomingMessage | null = null;
    const finishResolve = (val: SafeOutboundResponse) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardTimer);
      resolve(val);
    };
    const finishReject = (err: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardTimer);
      try {
        activeRes?.destroy();
      } catch {}
      try {
        req.destroy();
      } catch {}
      reject(err instanceof Error ? err : new Error(String(err)));
    };

    const hardTimer = setTimeout(() => {
      finishReject(new Error(`Outbound HTTP request timed out after ${timeoutMs}ms`));
    }, timeoutMs + 2000);

    const req = transport.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname.replace(/^\[|\]$/g, ''),
        port: parsed.port || (isHttps ? 443 : 80),
        path: `${parsed.pathname}${parsed.search}`,
        method: options?.method || 'GET',
        headers: options?.headers || {},
        lookup: pinnedLookup as any,
        timeout: timeoutMs,
        ...(isHttps
          ? {
              servername: net.isIP(parsed.hostname.replace(/^\[|\]$/g, '')) === 0 ? parsed.hostname : undefined,
              rejectUnauthorized:
                options?.rejectUnauthorized ??
                (options?.allowSelfSigned || options?.allowInsecureTls ? false : true)
            }
          : {})
      },
      (res) => {
        activeRes = res;
        if (isHttps && options?.expectedCertSha256) {
          const tlsSock = res.socket as any;
          const cert = tlsSock?.getPeerCertificate?.();
          const actualFp = String(cert?.fingerprint256 || '')
            .replace(/:/g, '')
            .toLowerCase();
          const expectedFp = options.expectedCertSha256.replace(/:/g, '').toLowerCase();
          if (!actualFp || actualFp !== expectedFp) {
            res.destroy();
            finishReject(new Error('TLS certificate SHA-256 fingerprint mismatch'));
            return;
          }
        }

        const status = res.statusCode || 0;
        if (status >= 300 && status < 400) {
          res.resume();
          finishReject(new Error(`Outbound HTTP redirect (${status}) blocked by SSRF policy`));
          return;
        }

        const chunks: Buffer[] = [];
        let received = 0;
        res.on('data', (chunk: Buffer) => {
          received += chunk.length;
          if (received > maxBytes) {
            finishReject(new Error(`Outbound response exceeded ${maxBytes} bytes limit`));
            return;
          }
          chunks.push(Buffer.from(chunk));
        });
        res.on('error', finishReject);
        res.on('close', () => {
          if (!settled && !res.complete) {
            finishReject(new Error('Outbound HTTP response closed prematurely'));
          }
        });
        res.on('end', () => {
          const bodyBuffer = Buffer.concat(chunks);
          finishResolve({
            ok: status >= 200 && status < 300,
            status,
            headers: res.headers,
            body: bodyBuffer,
            bodyBuffer,
            text: () => bodyBuffer.toString('utf8'),
            json: <T = any>() => JSON.parse(bodyBuffer.toString('utf8')) as T
          });
        });
      }
    );

    req.on('timeout', () => {
      finishReject(new Error(`Outbound HTTP request timed out after ${timeoutMs}ms`));
    });
    req.on('error', finishReject);

    if (options?.body !== undefined) {
      req.write(options.body);
    }
    req.end();
  });
}

export function isEncryptedVaultSecret(val?: string | null): boolean {
  return Boolean(val && val.startsWith('enc:v1:'));
}

export function isMaskedSecret(val?: string | null): boolean {
  if (!val) return false;
  return val === MASKED_SECRET || /^•+$/.test(val.trim()) || /^\*{6,}$/.test(val.trim());
}

export function encryptVaultSecret(plaintext: string): string {
  if (!plaintext) return '';
  if (isEncryptedVaultSecret(plaintext)) return plaintext;
  const key = getVaultMasterKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `enc:v1:${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

export function decryptVaultSecret(stored?: string | null): string {
  if (!stored) return '';

  // Modern format: enc:v1:<ivHex>:<tagHex>:<cipherHex>
  if (stored.startsWith('enc:v1:')) {
    const parts = stored.split(':');
    if (parts.length !== 5) return '';
    const [, , ivHex, tagHex, cipherHex] = parts;
    const primaryKey = getVaultMasterKey();
    const candidateKeys = cachedEnvDeterministicKey ? [primaryKey, cachedEnvDeterministicKey] : [primaryKey];
    for (const key of candidateKeys) {
      try {
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
        decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
        return Buffer.concat([decipher.update(Buffer.from(cipherHex, 'hex')), decipher.final()]).toString('utf8');
      } catch {
        // Try deterministic recovery key if primary differed
      }
    }
    return '';
  }

  // Legacy LAPS format: <24hexIv>:<32hexTag>:<hexCipher>
  const colonParts = stored.split(':');
  if (
    colonParts.length === 3 &&
    /^[0-9a-fA-F]{24}$/.test(colonParts[0]) &&
    /^[0-9a-fA-F]{32}$/.test(colonParts[1]) &&
    /^[0-9a-fA-F]+$/.test(colonParts[2])
  ) {
    const [ivHex, tagHex, cipherHex] = colonParts;
    for (const candidateKey of [getVaultMasterKey(), LEGACY_SEED_KEY]) {
      try {
        const decipher = crypto.createDecipheriv('aes-256-gcm', candidateKey, Buffer.from(ivHex, 'hex'));
        decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
        return Buffer.concat([decipher.update(Buffer.from(cipherHex, 'hex')), decipher.final()]).toString('utf8');
      } catch {
        // Try next key
      }
    }
    return '';
  }

  // Legacy unencrypted value prior to vault migration
  return stored;
}

export function maskSecretValue(stored?: string | null): string {
  if (!stored) return '';
  const plain = decryptVaultSecret(stored);
  return plain ? MASKED_SECRET : '';
}

// ============================================================================
// Binary Archive Encryption (AES-256-GCM with Scrypt KDF)
// Header format: "VRMMENC1" (8B) | salt (16B) | iv (12B) | authTag (16B) | ciphertext
// ============================================================================
const ARCHIVE_MAGIC = Buffer.from('VRMMENC1', 'ascii');

export function isEncryptedArchiveBuffer(buf: Buffer): boolean {
  return buf.length > 52 && buf.subarray(0, 8).equals(ARCHIVE_MAGIC);
}

export function encryptBufferAesGcm(plainBuf: Buffer, passphrase: string): Buffer {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(passphrase, salt, 32);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([ARCHIVE_MAGIC, salt, iv, tag, ciphertext]);
}

export function decryptBufferAesGcm(encBuf: Buffer, passphrase: string): Buffer {
  if (!isEncryptedArchiveBuffer(encBuf)) {
    return encBuf;
  }
  const salt = encBuf.subarray(8, 24);
  const iv = encBuf.subarray(24, 36);
  const tag = encBuf.subarray(36, 52);
  const ciphertext = encBuf.subarray(52);
  const key = crypto.scryptSync(passphrase, salt, 32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// ============================================================================
// Password Hashing (Scrypt + Constant-Time Verification)
// ============================================================================
export function hashPasswordScrypt(password: string): string {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, 64);
  return `scrypt:v1:${salt.toString('hex')}:${derived.toString('hex')}`;
}

export function verifyPasswordScrypt(password: string, storedHash?: string | null): boolean {
  if (!password || !storedHash) return false;
  if (storedHash.startsWith('scrypt:v1:')) {
    const parts = storedHash.split(':');
    if (parts.length !== 4) return false;
    const salt = Buffer.from(parts[2], 'hex');
    const expected = Buffer.from(parts[3], 'hex');
    const actual = crypto.scryptSync(password, salt, expected.length);
    if (actual.length !== expected.length) return false;
    return crypto.timingSafeEqual(actual, expected);
  }
  // Constant-time fallback only if comparing legacy unhashed temp token
  const a = Buffer.from(password, 'utf8');
  const b = Buffer.from(storedHash, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ============================================================================
// RFC 6238 TOTP Generator & Constant-Time Verifier
// ============================================================================
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateRandomBase32(byteLength = 20): string {
  const bytes = crypto.randomBytes(byteLength);
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

export function decodeBase32(secret: string): Buffer {
  const cleaned = secret.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const ch of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

export function generateTotpForStep(secretBase32: string, stepCounter: number): string {
  const key = decodeBase32(secretBase32);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(stepCounter));
  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, '0');
}

export function verifyTotp(
  secretBase32: string,
  codeInput: string,
  lastUsedStep?: number | null,
  windowSteps = 1
): { valid: boolean; matchedStep?: number; replayDetected?: boolean } {
  const normalized = (codeInput || '').replace(/\s|-/g, '');
  if (!/^\d{6}$/.test(normalized) || !secretBase32) {
    return { valid: false };
  }
  const currentStep = Math.floor(Date.now() / 30000);
  const inputBuf = Buffer.from(normalized, 'utf8');

  for (let delta = -windowSteps; delta <= windowSteps; delta++) {
    const step = currentStep + delta;
    const candidate = Buffer.from(generateTotpForStep(secretBase32, step), 'utf8');
    if (candidate.length === inputBuf.length && crypto.timingSafeEqual(candidate, inputBuf)) {
      if (lastUsedStep != null && step <= lastUsedStep) {
        return { valid: false, replayDetected: true };
      }
      return { valid: true, matchedStep: step };
    }
  }
  return { valid: false };
}

export function buildOtpAuthUri(accountName: string, issuer: string, secretBase32: string): string {
  const safeIssuer = encodeURIComponent(issuer || 'Vitrine RMM');
  const safeAccount = encodeURIComponent(accountName || 'admin');
  return `otpauth://totp/${safeIssuer}:${safeAccount}?secret=${encodeURIComponent(secretBase32)}&issuer=${safeIssuer}&algorithm=SHA1&digits=6&period=30`;
}

// ============================================================================
// Signed Scoped Tokens (Guest Portal / Agent Callback / Short-Lived Grants)
// ============================================================================
export function hmacSignToken(payloadObj: Record<string, unknown>): string {
  const payloadB64 = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', getVaultMasterKey()).update(payloadB64).digest('base64url');
  return `${payloadB64}.${sig}`;
}

export function hmacVerifyToken<T = Record<string, any>>(token?: string | null): T | null {
  if (!token || !token.includes('.')) return null;
  const [payloadB64, sigB64] = token.split('.');
  if (!payloadB64 || !sigB64) return null;
  const expectedSig = crypto.createHmac('sha256', getVaultMasterKey()).update(payloadB64).digest('base64url');
  const a = Buffer.from(sigB64, 'utf8');
  const b = Buffer.from(expectedSig, 'utf8');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return null;
  }
  try {
    const parsed = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    if (parsed.exp && typeof parsed.exp === 'number' && Date.now() > parsed.exp) {
      return null;
    }
    return parsed as T;
  } catch {
    return null;
  }
}

