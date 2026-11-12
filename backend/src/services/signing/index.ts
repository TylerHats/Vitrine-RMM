import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { db, DATA_DIR_PATH } from '../../db/index.js';
import { validateOutboundHostSafety } from '../vault/index.js';

export interface SigningResult {
  success: boolean;
  signedFilePath?: string;
  error?: string;
  filename?: string;
  durationMs?: number;
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
  if (
    host === '169.254.169.254' ||
    host.startsWith('169.254.') ||
    host === 'metadata.google.internal' ||
    host === '100.100.100.200'
  ) {
    return { valid: false, error: 'Cloud metadata / link-local endpoints are blocked.' };
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
    } catch {
      // DB not ready
    }
    return this.endpointUrl;
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

    const dnsSafety = await validateOutboundHostSafety(check.normalizedUrl, { allowLoopback: true });
    if (!dnsSafety.safe) {
      return {
        reachable: false,
        endpoint: check.normalizedUrl,
        latencyMs: Date.now() - start,
        error: dnsSafety.reason || 'Code signing URL blocked by SSRF policy.'
      };
    }

    try {
      const res = await fetch(`${check.normalizedUrl}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000)
      }).catch(async () => {
        return fetch(check.normalizedUrl!, {
          method: 'HEAD',
          signal: AbortSignal.timeout(5000)
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

      const dnsSafety = await validateOutboundHostSafety(urlCheck.normalizedUrl, { allowLoopback: true });
      if (!dnsSafety.safe) {
        return {
          success: false,
          error: dnsSafety.reason || 'Code signing endpoint blocked by SSRF policy.',
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

      const res = await fetch(`${urlCheck.normalizedUrl}/sign`, {
        method: 'POST',
        headers: {
          'Content-Type': `multipart/form-data; boundary=${boundary}`
        },
        body,
        signal: AbortSignal.timeout(8000)
      });

      if (!res.ok) {
        const errorText = (await res.text()).slice(0, 300);
        return {
          success: false,
          error: `Signer returned HTTP ${res.status}: ${errorText}`,
          filename: safeFilename,
          durationMs: Date.now() - start
        };
      }

      const arrayBuffer = await res.arrayBuffer();
      const signedBuffer = Buffer.from(arrayBuffer);

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
