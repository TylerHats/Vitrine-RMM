import nodemailer from 'nodemailer';
import dns from 'dns';
import net from 'net';
import { db, APP_VERSION } from '../../db/index.js';
import { decryptVaultSecret, validateOutboundHostSafety } from '../vault/index.js';

export interface SmtpConfig {
  host: string;
  port: number;
  user?: string;
  pass?: string;
  from: string;
  secure?: boolean;
  tls?: boolean;
  allowSelfSignedTls?: boolean;
}

export interface EmailPayload {
  to: string;
  subject: string;
  headline?: string;
  bodyContent: string;
  severity?: 'Info' | 'Warning' | 'Critical';
  targetDevice?: string;
}

export function escapeHtml(input?: string | null): string {
  if (!input) return '';
  return String(input)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function sanitizeHeaderValue(input?: string | null): string {
  if (!input) return '';
  return String(input).replace(/[\r\n]+/g, ' ').trim();
}

export function validateSmtpTargetHost(host: string): { valid: boolean; reason?: string } {
  const trimmed = (host || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!trimmed) return { valid: false, reason: 'SMTP host is empty.' };
  // Block cloud metadata and link-local SSRF targets
  if (
    trimmed === '169.254.169.254' ||
    trimmed.startsWith('169.254.') ||
    trimmed === 'metadata.google.internal' ||
    trimmed === '100.100.100.200' ||
    trimmed.startsWith('fe80:')
  ) {
    return { valid: false, reason: 'Link-local / cloud metadata addresses are not permitted for SMTP.' };
  }
  // Support public FQDNs, IPv4/IPv6 literals, localhost, AND single-label Docker service hostnames (e.g. mailpit, postfix)
  if (net.isIP(trimmed) === 0 && !/^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/i.test(trimmed)) {
    return { valid: false, reason: 'Invalid SMTP hostname format.' };
  }
  return { valid: true };
}

export function createGlassmorphicEmailHtml(brandName: string, payload: EmailPayload): string {
  const accentColor =
    payload.severity === 'Critical' ? '#ef4444' : payload.severity === 'Warning' ? '#f59e0b' : '#00f2fe';
  const safeBrand = escapeHtml(brandName || 'Vitrine RMM');
  const safeSubject = escapeHtml(payload.subject);
  const safeHeadline = escapeHtml(payload.headline || payload.subject);
  const safeBody = escapeHtml(payload.bodyContent).replace(/\n/g, '<br/>');
  const safeSeverity = escapeHtml(payload.severity || 'System Alert');
  const safeDevice = payload.targetDevice ? escapeHtml(payload.targetDevice) : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${safeSubject}</title>
  <style>
    body { margin: 0; padding: 0; background-color: #0b1120; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f8fafc; }
    .email-container { max-width: 600px; margin: 30px auto; background: #0f172a; border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 16px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
    .header { padding: 25px 30px; background: linear-gradient(135deg, rgba(0, 242, 254, 0.15) 0%, rgba(127, 0, 255, 0.15) 100%); border-bottom: 1px solid rgba(255, 255, 255, 0.08); display: flex; align-items: center; justify-content: space-between; }
    .brand-title { font-size: 20px; font-weight: 700; color: #ffffff; letter-spacing: -0.02em; }
    .severity-badge { display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; background: ${accentColor}22; color: ${accentColor}; border: 1px solid ${accentColor}55; }
    .content { padding: 30px; line-height: 1.6; font-size: 15px; color: #cbd5e1; }
    .headline { font-size: 18px; font-weight: 600; color: #ffffff; margin-bottom: 15px; }
    .meta-box { background: rgba(0, 0, 0, 0.3); border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.06); padding: 15px; margin: 20px 0; font-family: 'JetBrains Mono', Courier, monospace; font-size: 13px; color: #38bdf8; }
    .footer { padding: 20px 30px; background: rgba(0, 0, 0, 0.2); border-top: 1px solid rgba(255, 255, 255, 0.06); font-size: 12px; color: #64748b; text-align: center; }
  </style>
</head>
<body>
  <div class="email-container">
    <div class="header">
      <div class="brand-title">${safeBrand}</div>
      <div class="severity-badge">${safeSeverity}</div>
    </div>
    <div class="content">
      <div class="headline">${safeHeadline}</div>
      <p>${safeBody}</p>
      ${safeDevice ? `<div class="meta-box">Target Endpoint: ${safeDevice}<br/>Status: Monitored via Vitrine RMM Control Plane</div>` : ''}
    </div>
    <div class="footer">
      Sent automatically by ${safeBrand} Event Watcher (v${APP_VERSION})<br/>
      To manage alert subscriptions, visit your Vitrine Policy Hierarchy dashboard.
    </div>
  </div>
</body>
</html>`;
}

const SMTP_EMAIL_REGEX =
  /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

function validateRecipientEmail(rawTo?: string | null): { valid: boolean; cleaned?: string; error?: string } {
  const rawStr = String(rawTo ?? '');
  if (!rawStr.trim() || /[\r\n\0]/.test(rawStr)) {
    return { valid: false, error: 'Recipient email address is invalid or contains control characters.' };
  }
  const trimmed = rawStr.trim();
  if (/[,;]/.test(trimmed)) {
    return { valid: false, error: 'Multiple recipient addresses or delimiters are not permitted.' };
  }
  const ltCount = (trimmed.match(/</g) || []).length;
  const gtCount = (trimmed.match(/>/g) || []).length;
  if (ltCount !== gtCount || ltCount > 1) {
    return { valid: false, error: 'Invalid recipient email bracket syntax.' };
  }

  if (ltCount === 1) {
    const angleMatch = trimmed.match(/^([^<>"]*?)<\s*([^<>\s"]+)\s*>$/);
    if (!angleMatch) {
      return { valid: false, error: 'Invalid recipient email address format.' };
    }
    const rawDisplay = angleMatch[1].trim();
    const addr = angleMatch[2].trim();
    if (/[@,;\\<>"]/.test(rawDisplay) || !SMTP_EMAIL_REGEX.test(addr)) {
      return { valid: false, error: 'Invalid recipient email address format.' };
    }
    return { valid: true, cleaned: rawDisplay ? `"${rawDisplay}" <${addr}>` : addr };
  }

  if (!SMTP_EMAIL_REGEX.test(trimmed)) {
    return { valid: false, error: 'Invalid recipient email address format.' };
  }
  return { valid: true, cleaned: trimmed };
}

function formatSafeSenderHeader(rawFrom: string | undefined, fallbackBrand: string): { valid: boolean; formatted?: string; error?: string } {
  const sanitized = sanitizeHeaderValue(rawFrom || 'alerts@vitrine.local');

  const angleMatch = sanitized.match(/^(.*?)<\s*([^<>"]+)\s*>$/);
  if (angleMatch) {
    const rawDisplay = angleMatch[1].trim().replace(/^"+|"+$/g, '').replace(/[<>"]/g, '').trim();
    const addr = angleMatch[2].trim();
    if (!SMTP_EMAIL_REGEX.test(addr)) {
      return { valid: false, error: 'Invalid sender email address in From header.' };
    }
    const display = rawDisplay || `${fallbackBrand} Alerts`;
    return { valid: true, formatted: `"${display}" <${addr}>` };
  }

  const bareAddr = sanitized.replace(/^"+|"+$/g, '').trim();
  if (!SMTP_EMAIL_REGEX.test(bareAddr)) {
    return { valid: false, error: 'Invalid sender email address format.' };
  }
  return { valid: true, formatted: `"${fallbackBrand} Alerts" <${bareAddr}>` };
}

type SmtpTransporter = ReturnType<typeof nodemailer.createTransport>;

async function createValidatedSmtpTransport(
  config: SmtpConfig
): Promise<{ ok: true; transporter: SmtpTransporter } | { ok: false; error: string }> {
  const hostCheck = validateSmtpTargetHost(config.host);
  if (!hostCheck.valid) {
    return { ok: false, error: hostCheck.reason || 'Invalid SMTP host.' };
  }
  const port = Number(config.port || 587);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, error: 'Invalid SMTP port.' };
  }

  const cleanHost = config.host.trim().replace(/^\[|\]$/g, '');
  const urlHost = net.isIPv6(cleanHost) ? `[${cleanHost}]` : cleanHost;
  const dnsSafety = await validateOutboundHostSafety(`http://${urlHost}:${port}`, {
    allowLoopback: true,
    allowPrivateLan: true
  });
  if (!dnsSafety.safe) {
    return { ok: false, error: dnsSafety.reason || 'SMTP host blocked by outbound safety policy.' };
  }

  const pinnedIp = dnsSafety.resolvedAddresses?.[0];
  const pinnedFamily: 4 | 6 = pinnedIp && net.isIP(pinnedIp) === 6 ? 6 : 4;
  const pinnedLookup: net.LookupFunction | undefined = pinnedIp
    ? (_hostname, opts: any, cb: any) => {
        const callback = typeof opts === 'function' ? opts : cb;
        if (opts && typeof opts === 'object' && opts.all) {
          callback(null, [{ address: pinnedIp, family: pinnedFamily }]);
        } else {
          callback(null, pinnedIp, pinnedFamily);
        }
      }
    : undefined;

  const isImplicitTls = config.secure ?? port === 465;
  const requireStartTls = Boolean(config.tls && port !== 465);
  const trimmedUser = (config.user || '').trim();

  const transportOpts: any = {
    host: pinnedIp || cleanHost,
    port,
    secure: isImplicitTls,
    requireTLS: requireStartTls,
    lookup: pinnedLookup,
    connectionTimeout: 7000,
    greetingTimeout: 7000,
    socketTimeout: 10000,
    auth: trimmedUser ? { user: trimmedUser, pass: config.pass || '' } : undefined,
    tls: {
      servername: net.isIP(cleanHost) === 0 ? cleanHost : undefined,
      lookup: pinnedLookup,
      rejectUnauthorized: config.allowSelfSignedTls
        ? false
        : process.env.SMTP_ALLOW_SELF_SIGNED === 'true'
        ? false
        : true
    }
  };

  return { ok: true, transporter: nodemailer.createTransport(transportOpts) };
}

export async function verifySmtpConnection(
  config: SmtpConfig
): Promise<{ success: boolean; latencyMs?: number; error?: string }> {
  const startedAt = Date.now();
  let transporter: SmtpTransporter | null = null;
  try {
    const built = await createValidatedSmtpTransport(config);
    if (!built.ok) {
      return { success: false, error: built.error };
    }
    transporter = built.transporter;
    await transporter.verify();
    return { success: true, latencyMs: Math.max(1, Date.now() - startedAt) };
  } catch (err: any) {
    return { success: false, error: err?.message || 'SMTP connection or authentication failed' };
  } finally {
    try {
      transporter?.close();
    } catch {
      // Ignore cleanup errors
    }
  }
}

export async function sendAlertEmail(
  config: SmtpConfig,
  payload: EmailPayload
): Promise<{ success: boolean; messageId?: string; error?: string }> {
  let transporter: SmtpTransporter | null = null;
  try {
    const recipientCheck = validateRecipientEmail(payload.to);
    if (!recipientCheck.valid || !recipientCheck.cleaned) {
      return { success: false, error: recipientCheck.error || 'Invalid recipient email address format.' };
    }

    const built = await createValidatedSmtpTransport(config);
    if (!built.ok) {
      return { success: false, error: built.error };
    }
    transporter = built.transporter;

    const settings = db.prepare('SELECT brand_name FROM settings WHERE id = 1').get() as any;
    const brandName = sanitizeHeaderValue(settings?.brand_name || 'Vitrine RMM').replace(/"/g, '');
    const fromParsed = formatSafeSenderHeader(config.from, brandName);
    if (!fromParsed.valid || !fromParsed.formatted) {
      return { success: false, error: fromParsed.error || 'Invalid SMTP From address.' };
    }

    const cleanTo = recipientCheck.cleaned;
    const cleanSubject = sanitizeHeaderValue(payload.subject);

    const html = createGlassmorphicEmailHtml(brandName, payload);
    const plainText = `${cleanSubject}\n\n${payload.bodyContent}\n\n${
      payload.targetDevice ? `Target Endpoint: ${payload.targetDevice}\n` : ''
    }-- Sent by ${brandName}`;

    const info = await transporter.sendMail({
      from: fromParsed.formatted,
      to: cleanTo,
      subject: cleanSubject,
      text: plainText,
      html,
      headers: {
        'X-Mailer': `Vitrine-RMM-Engine/${APP_VERSION}`,
        'X-Auto-Response-Suppress': 'OOF, AutoReply',
        'Auto-Submitted': 'auto-generated'
      }
    });

    return { success: true, messageId: info.messageId };
  } catch (err: any) {
    return { success: false, error: err?.message || 'SMTP dispatch failed' };
  } finally {
    try {
      transporter?.close();
    } catch {
      // Ignore cleanup errors
    }
  }
}

export async function sendAlertEmailUsingStoredSettings(payload: {
  subject: string;
  headline?: string;
  bodyContent: string;
  severity?: 'Info' | 'Warning' | 'Critical';
  targetDevice?: string;
  toOverride?: string;
}): Promise<{ dispatched: boolean; error?: string }> {
  try {
    const settings = db.prepare('SELECT * FROM settings WHERE id = 1').get() as any;
    const decryptedPass = decryptVaultSecret(settings?.smtp_pass);
    // Only skip if smtp_host is empty OR still sitting at initial unauthenticated seed default (`smtp.mailgun.org` with blank user & pass)
    const isUnconfiguredSeed =
      settings?.smtp_host === 'smtp.mailgun.org' && !settings?.smtp_user && !decryptedPass;
    if (!settings || !settings.smtp_host || isUnconfiguredSeed) {
      return { dispatched: false, error: 'SMTP server not configured' };
    }
    const adminRow = db
      .prepare("SELECT email FROM users WHERE role IN ('msp_super_admin', 'super_admin', 'admin') ORDER BY created_at ASC LIMIT 1")
      .get() as { email?: string } | undefined;
    const recipient = payload.toOverride || adminRow?.email || settings.letsencrypt_email || settings.smtp_user;
    if (!recipient || !recipient.includes('@')) {
      return { dispatched: false, error: 'No recipient email configured' };
    }

    const smtpPort = Number(settings.smtp_port || 587);
    const res = await sendAlertEmail(
      {
        host: settings.smtp_host,
        port: smtpPort,
        user: settings.smtp_user || undefined,
        pass: decryptedPass || undefined,
        from: settings.smtp_from || 'alerts@vitrine.local',
        secure: smtpPort === 465,
        tls: Boolean(settings.smtp_tls ?? 1)
      },
      {
        to: recipient,
        subject: payload.subject,
        headline: payload.headline,
        bodyContent: payload.bodyContent,
        severity: payload.severity,
        targetDevice: payload.targetDevice
      }
    );
    return { dispatched: res.success, error: res.error };
  } catch (e: any) {
    return { dispatched: false, error: e?.message };
  }
}
