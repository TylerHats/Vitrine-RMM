import fs from 'fs';
import net from 'net';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { db, DATA_DIR_PATH } from '../../db/index.js';
import { decryptVaultSecret, isBlockedOutboundIp, safeOutboundFetch } from '../vault/index.js';

export interface SigningResult {
  success: boolean;
  signedFilePath?: string;
  error?: string;
  filename?: string;
  durationMs?: number;
}

function isLoopbackSigningHost(rawHost: string): boolean {
  const clean = rawHost.trim().toLowerCase().replace(/^\[|\]$/g, '');
  return (
    clean === 'localhost' ||
    clean === '::1' ||
    clean === '127.0.0.1' ||
    clean.startsWith('127.')
  );
}

function normalizePs1ScriptContent(raw: string): string {
  return raw
    .replace(/^\uFEFF/, '')
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .replace(/\n+$/, '');
}

export function validateSigningEndpointUrl(rawUrl: string): { valid: boolean; normalizedUrl?: string; error?: string } {
  const trimmed = (rawUrl || '').trim();
  if (!trimmed) {
    return { valid: false, error: 'Code signing URL is not configured.' };
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, error: 'Invalid code signing URL format.' };
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return { valid: false, error: 'Code signing URL must use http:// or https://.' };
  }
  const host = parsed.hostname.toLowerCase();
  const cleanHost = host.replace(/^\[|\]$/g, '');
  if (
    cleanHost === '169.254.169.254' ||
    cleanHost.startsWith('169.254.') ||
    cleanHost === 'metadata.google.internal' ||
    cleanHost === '100.100.100.200' ||
    (net.isIP(cleanHost) !== 0 &&
      isBlockedOutboundIp(cleanHost, { allowLoopback: true, allowPrivateLan: true }))
  ) {
    return { valid: false, error: 'Cloud metadata / link-local endpoints are blocked.' };
  }
  if (process.env.NODE_ENV === 'production' && parsed.protocol !== 'https:' && !isLoopbackSigningHost(cleanHost)) {
    return {
      valid: false,
      error: 'Code signing URL must use https:// in production for non-loopback endpoints.'
    };
  }
  return { valid: true, normalizedUrl: parsed.toString().replace(/\/$/, '') };
}

function isAllowedSigningFilePath(candidatePath: string): boolean {
  try {
    const resolvedFile = fs.realpathSync(candidatePath);
    const allowedRoots = [
      os.tmpdir(),
      path.join(DATA_DIR_PATH, 'signing-staging'),
      path.join(DATA_DIR_PATH, 'signed-agents')
    ].map((root) => {
      if (!fs.existsSync(root)) {
        fs.mkdirSync(root, { recursive: true, mode: 0o700 });
      }
      return fs.realpathSync(root);
    });

    return allowedRoots.some(
      (root) => resolvedFile.startsWith(root + path.sep) && fs.statSync(resolvedFile).isFile()
    );
  } catch {
    return false;
  }
}

export class CodeSigningService {
  private endpointUrl: string;

  constructor(endpointUrl = process.env.CODE_SIGNING_URL || '') {
    this.endpointUrl = endpointUrl;
  }

  public getEndpoint(): string {
    try {
      const settings = db.prepare('SELECT code_signing_url FROM settings WHERE id = 1').get() as any;
      if (settings?.code_signing_url) return settings.code_signing_url;
    } catch {}
    return this.endpointUrl;
  }

  public getApiKey(): string {
    try {
      const settings = db.prepare('SELECT code_signing_api_key FROM settings WHERE id = 1').get() as any;
      const decrypted = decryptVaultSecret(settings?.code_signing_api_key);
      if (decrypted) {
        return decrypted.replace(/[\r\n]+/g, '').trim();
      }
    } catch {}
    return (process.env.CODE_SIGNING_API_KEY || '').replace(/[\r\n]+/g, '').trim();
  }

  public async testConnection(urlOverride?: string): Promise<{
    reachable: boolean;
    endpoint: string;
    httpStatus?: number;
    latencyMs: number;
    error?: string;
  }> {
    const rawTarget = urlOverride ?? this.getEndpoint();
    const start = Date.now();
    const check = validateSigningEndpointUrl(rawTarget);
    if (!check.valid || !check.normalizedUrl) {
      return {
        reachable: false,
        endpoint: rawTarget || '(unconfigured)',
        latencyMs: Date.now() - start,
        error: check.error || 'Code signing endpoint URL is not configured.'
      };
    }

    const apiKey = this.getApiKey();
    const authHeaders: Record<string, string> = apiKey ? { Authorization: `Bearer ${apiKey}` } : {};

    try {
      const res = await safeOutboundFetch(`${check.normalizedUrl}/health`, {
        method: 'GET',
        headers: authHeaders,
        timeoutMs: 5000,
        safety: { allowLoopback: true, allowPrivateLan: true }
      }).catch(async () => {
        return safeOutboundFetch(check.normalizedUrl!, {
          method: 'HEAD',
          headers: authHeaders,
          timeoutMs: 5000,
          safety: { allowLoopback: true, allowPrivateLan: true }
        });
      });

      return {
        reachable: res.status < 500,
        endpoint: check.normalizedUrl,
        httpStatus: res.status,
        latencyMs: Date.now() - start,
        error: res.status >= 500 ? `Endpoint returned HTTP ${res.status}` : undefined
      };
    } catch (err: any) {
      return {
        reachable: false,
        endpoint: check.normalizedUrl,
        latencyMs: Date.now() - start,
        error: err?.message || 'Unable to reach code signing server'
      };
    }
  }

  public async signFile(filePath: string): Promise<SigningResult> {
    const start = Date.now();
    try {
      if (!isAllowedSigningFilePath(filePath)) {
        return {
          success: false,
          error: 'Target file must reside inside an authorized Vitrine signing staging directory.',
          durationMs: Date.now() - start
        };
      }

      const activeEndpoint = this.getEndpoint();
      const urlCheck = validateSigningEndpointUrl(activeEndpoint);
      if (!urlCheck.valid || !urlCheck.normalizedUrl) {
        return {
          success: false,
          error: urlCheck.error || 'Code signing endpoint URL is invalid.',
          durationMs: Date.now() - start
        };
      }

      const safeFilename = path.basename(filePath).replace(/[^a-zA-Z0-9._-]/g, '_');
      const fileData = fs.readFileSync(filePath);
      const boundary = '----VitrineSignBoundary' + crypto.randomBytes(16).toString('hex');

      const pre = Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${safeFilename}"\r\nContent-Type: application/octet-stream\r\n\r\n`
      );
      const post = Buffer.from(`\r\n--${boundary}--\r\n`);
      const body = Buffer.concat([pre, fileData, post]);

      const apiKey = this.getApiKey();
      const reqHeaders: Record<string, string> = {
        'Content-Type': `multipart/form-data; boundary=${boundary}`
      };
      if (apiKey) {
        reqHeaders.Authorization = `Bearer ${apiKey}`;
      }

      const res = await safeOutboundFetch(`${urlCheck.normalizedUrl}/sign`, {
        method: 'POST',
        headers: reqHeaders,
        body,
        timeoutMs: 10000,
        maxBytes: 64 * 1024 * 1024,
        safety: { allowLoopback: true, allowPrivateLan: true }
      });

      if (res.status < 200 || res.status >= 300) {
        const errorText = res.body.toString('utf8').slice(0, 300);
        return {
          success: false,
          error: `Signer returned HTTP ${res.status}: ${errorText}`,
          filename: safeFilename,
          durationMs: Date.now() - start
        };
      }

      const signedBuffer = res.body;
      const textPreview = signedBuffer.subarray(0, 100).toString('utf8');
      if (textPreview.startsWith('{"status":"Failed"')) {
        try {
          const parsed = JSON.parse(signedBuffer.toString('utf8'));
          return {
            success: false,
            error: parsed.error || 'Signing server reported failure.',
            filename: safeFilename,
            durationMs: Date.now() - start
          };
        } catch {
          return {
            success: false,
            error: 'Signing server returned failure payload.',
            filename: safeFilename,
            durationMs: Date.now() - start
          };
        }
      }

      const parsedPath = path.parse(filePath);
      if (parsedPath.ext.toLowerCase() === '.ps1') {
        const signedText = signedBuffer.toString('utf8');
        const sigBeginMarker = '# SIG # Begin signature block';
        const sigEndMarker = '# SIG # End signature block';
        const sigIdx = signedText.indexOf(sigBeginMarker);
        const sigEndIdx = signedText.indexOf(sigEndMarker);
        if (sigIdx < 0 || sigEndIdx <= sigIdx) {
          return {
            success: false,
            error: 'Signed PowerShell script is missing a valid # SIG # Authenticode signature block.',
            filename: safeFilename,
            durationMs: Date.now() - start
          };
        }
        const trailingAfterSig = signedText.slice(sigEndIdx + sigEndMarker.length).trim();
        const originalNormalized = normalizePs1ScriptContent(fileData.toString('utf8'));
        const signedBodyNormalized = normalizePs1ScriptContent(signedText.slice(0, sigIdx));
        if (trailingAfterSig.length > 0 || signedBodyNormalized !== originalNormalized) {
          return {
            success: false,
            error: 'Signed PowerShell script content failed integrity verification against unsigned original.',
            filename: safeFilename,
            durationMs: Date.now() - start
          };
        }
      }

      const signedFilePath = path.join(parsedPath.dir, `${parsedPath.name}.signed${parsedPath.ext}`);
      fs.writeFileSync(signedFilePath, signedBuffer, { mode: 0o600 });

      return {
        success: true,
        signedFilePath,
        filename: safeFilename,
        durationMs: Date.now() - start
      };
    } catch (err: any) {
      return {
        success: false,
        error: err?.message || 'Code signing request failed',
        durationMs: Date.now() - start
      };
    }
  }
}

export const codeSigningService = new CodeSigningService();
