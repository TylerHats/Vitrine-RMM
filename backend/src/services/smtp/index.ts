import nodemailer from 'nodemailer';
import { db } from '../../db/index.js';

export interface SmtpConfig {
  host: string;
  port: number;
  user?: string;
  pass?: string;
  from: string;
  secure?: boolean;
}

export interface EmailPayload {
  to: string;
  subject: string;
  headline?: string;
  bodyContent: string;
  severity?: 'Info' | 'Warning' | 'Critical';
  targetDevice?: string;
}

export function createGlassmorphicEmailHtml(brandName: string, payload: EmailPayload): string {
  const accentColor = payload.severity === 'Critical' ? '#ef4444' : payload.severity === 'Warning' ? '#f59e0b' : '#00f2fe';
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${payload.subject}</title>
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
      <div class="brand-title">🔮 ${brandName || 'Vitrine RMM'}</div>
      <div class="severity-badge">${payload.severity || 'System Alert'}</div>
    </div>
    <div class="content">
      <div class="headline">${payload.headline || payload.subject}</div>
      <p>${payload.bodyContent}</p>
      ${payload.targetDevice ? `<div class="meta-box">Target Endpoint: ${payload.targetDevice}<br/>Status: Preserved via RMM Tunnel</div>` : ''}
    </div>
    <div class="footer">
      Sent automatically by ${brandName || 'Vitrine RMM'} Event Watcher • MeshCentral 2 Engine Bridge<br/>
      To manage alert subscriptions, visit your Vitrine Policy Hierarchy dashboard.
    </div>
  </div>
</body>
</html>`;
}

export async function sendAlertEmail(config: SmtpConfig, payload: EmailPayload): Promise<{ success: boolean; messageId?: string; error?: string }> {
  try {
    const transporter = nodemailer.createTransport({
      host: config.host,
      port: config.port,
      secure: config.port === 465,
      auth: config.user && config.pass ? { user: config.user, pass: config.pass } : undefined,
      tls: {
        rejectUnauthorized: false
      }
    });

    const settings = db.prepare('SELECT brand_name FROM settings WHERE id = 1').get() as any;
    const brandName = settings?.brand_name || 'Vitrine RMM';
    const html = createGlassmorphicEmailHtml(brandName, payload);
    const plainText = `${payload.subject}\n\n${payload.bodyContent}\n\n${payload.targetDevice ? `Target Endpoint: ${payload.targetDevice}\n` : ''}-- Sent by ${brandName}`;

    const info = await transporter.sendMail({
      from: `"${brandName} Alerts" <${config.from}>`,
      to: payload.to,
      subject: payload.subject,
      text: plainText,
      html: html,
      headers: {
        'X-Mailer': 'Vitrine-RMM-Engine/2.1.0',
        'X-Auto-Response-Suppress': 'OOF, AutoReply',
        'Auto-Submitted': 'auto-generated'
      }
    });

    return { success: true, messageId: info.messageId };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}
