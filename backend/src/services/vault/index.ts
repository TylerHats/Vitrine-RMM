import crypto from 'crypto';
import fs from 'fs';
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

  if (fs.existsSync(keyFilePath)) {
    try {
      material = JSON.parse(fs.readFileSync(keyFilePath, 'utf8')) as PersistedVaultKeyMaterial;
    } catch {
      material = null;
    }
  }

  if (!material || !material.kdfSaltHex || !material.masterSecretHex) {
    material = {
      masterSecretHex: crypto.randomBytes(32).toString('hex'),
      kdfSaltHex: crypto.randomBytes(16).toString('hex'),
      createdAt: new Date().toISOString()
    };
    fs.writeFileSync(keyFilePath, JSON.stringify(material, null, 2), { encoding: 'utf8', mode: 0o600 });
    try {
      fs.chmodSync(keyFilePath, 0o600);
    } catch {
      // Ignore chmod error on non-POSIX FS
    }
  }

  const rawSecret =
    process.env.LAPS_MASTER_SECRET && process.env.LAPS_MASTER_SECRET.trim().length >= 16
      ? process.env.LAPS_MASTER_SECRET.trim()
      : material.masterSecretHex;

  const saltBuf = Buffer.from(material.kdfSaltHex, 'hex');
  cachedMasterKey = crypto.scryptSync(rawSecret, saltBuf, 32);
  return cachedMasterKey;
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
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', getVaultMasterKey(), Buffer.from(ivHex, 'hex'));
      decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
      return Buffer.concat([decipher.update(Buffer.from(cipherHex, 'hex')), decipher.final()]).toString('utf8');
    } catch {
      return '';
    }
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

