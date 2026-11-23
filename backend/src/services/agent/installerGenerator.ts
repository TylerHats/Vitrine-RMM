import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { db, DATA_DIR_PATH } from '../../db/index.js';
import { CodeSigningService } from '../signing/index.js';
import { safeOutboundFetch } from '../vault/index.js';
import {
  buildStampedWindowsPe,
  resolveBrandingIconBuffer,
  resolveWindowsTemplatePath,
  type WindowsTemplateName
} from './windowsPeBuilder.js';
import {
  getDefaultTrayMenuItems,
  resolveEffectiveDevicePolicy,
  resolvePolicyForInstallerScope,
  type TrayMenuItem
} from '../policy/index.js';
import { buildLinuxCompanionPy, buildLinuxTrayPy } from './linuxAgentTemplates.js';

export interface InstallerOptions {
  os: 'windows' | 'linux' | 'darwin' | 'macos';
  tenantId?: string;
  siteId?: string;
  deviceRole?: string;
  serverUrl?: string;
  vitrineServerUrl?: string;
  meshGroupId?: string;
  tokenId?: string;
  mode?: 'permanent' | 'quicksupport' | 'companion_only';
  sessionCode?: string;
  meshServerId?: string;
  allowSelfSignedTls?: boolean;
  targetDeviceId?: string;
}

export interface SigningStageReport {
  stepNumber: number;
  component: string;
  description: string;
  status: 'signed' | 'verified' | 'bypassed' | 'unreachable';
  sha256: string;
  timestampAuthority: string;
  durationMs: number;
}

/**
 * Safely quotes an arbitrary string as a PowerShell single-quoted literal ('...').
 * In PowerShell 5.1 & 7+, Unicode curly single-quote characters (\u2018..\u201B) are treated
 * identically to ASCII ' as string delimiters, so ALL single-quote variants MUST be doubled!
 */
export function quotePowerShellLiteral(value: string | null | undefined): string {
  const clean = String(value ?? '').replace(/\0/g, '');
  return `'${clean.replace(/['\u2018\u2019\u201A\u201B]/g, "''")}'`;
}

/**
 * Safely quotes an arbitrary string as a POSIX/Bash single-quoted literal ('...').
 * Single-quoted strings in POSIX shell disable $, `, \, and ! expansion completely.
 */
export function quoteBashLiteral(value: string | null | undefined): string {
  const clean = String(value ?? '').replace(/\0/g, '');
  return `'${clean.replace(/'/g, `'\\''`)}'`;
}

function sanitizeIdentifier(raw: string | undefined, fallback: string, maxLen = 48): string {
  const cleaned = String(raw || '')
    .replace(/[^a-zA-Z0-9._-]/g, '')
    .slice(0, maxLen);
  return cleaned || fallback;
}

function sanitizeSingleLine(raw: unknown, fallback = '', maxLen = 160): string {
  const cleaned = String(raw ?? '')
    .replace(/[\r\n\0]+/g, ' ')
    .trim()
    .slice(0, maxLen);
  return cleaned || fallback;
}

function sanitizeHexColor(raw: string | undefined): string {
  const val = String(raw || '').trim();
  return /^#[0-9a-fA-F]{6}$/.test(val) ? val : '#00f2fe';
}

function sanitizeServerUrl(raw: string | undefined, fallback = 'https://127.0.0.1:443'): string {
  const val = String(raw || '').trim();
  try {
    const u = new URL(val);
    if (u.protocol === 'https:' || u.protocol === 'http:') {
      return u.toString().replace(/\/$/, '');
    }
  } catch {
    // Fallback
  }
  return fallback;
}

export class InstallerGeneratorService {
  private signer: CodeSigningService;

  constructor() {
    this.signer = new CodeSigningService();
  }

  public async getOrBuildSignedMeshBinary(
    arch: 'x64' | 'arm64' | 'x86' = 'x64',
    allowSelfSignedTls = false
  ): Promise<{ buffer: Buffer; filename: string; sha256: string; signed: boolean }> {
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    const primaryRow = db
      .prepare('SELECT url, allow_self_signed FROM mesh_servers ORDER BY is_primary DESC, created_at ASC LIMIT 1')
      .get() as { url?: string; allow_self_signed?: number } | undefined;

    const rawServerUrl = String(primaryRow?.url || settings.meshcentral_url || '').trim();
    if (
      !rawServerUrl ||
      rawServerUrl === 'https://mesh.vitrine.local' ||
      rawServerUrl === 'https://mesh.yourdomain.com'
    ) {
      throw new Error('Primary MeshCentral server URL is not configured.');
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(rawServerUrl);
    } catch {
      throw new Error('Configured MeshCentral server URL is invalid.');
    }
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      throw new Error('MeshCentral server URL must use http:// or https://.');
    }

    const cleanHost = parsedUrl.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    const isLoopback = cleanHost === 'localhost' || cleanHost === '127.0.0.1' || cleanHost === '::1';
    const allowInsecure = Boolean(
      allowSelfSignedTls ||
        primaryRow?.allow_self_signed ||
        settings.meshcentral_allow_self_signed ||
        process.env.MESHCENTRAL_ALLOW_SELF_SIGNED === 'true' ||
        isLoopback
    );

    const agentMeta =
      arch === 'arm64'
        ? { agentId: 43, filename: 'MeshServiceARM64.exe' }
        : arch === 'x86'
          ? { agentId: 3, filename: 'MeshService32.exe' }
          : { agentId: 4, filename: 'MeshService64.exe' };

    const downloadUrl = `${parsedUrl.origin}/meshagents?id=${agentMeta.agentId}`;
    const res = await safeOutboundFetch(downloadUrl, {
      method: 'GET',
      timeoutMs: 30000,
      maxBytes: 32 * 1024 * 1024,
      allowInsecureTls: allowInsecure,
      safety: { allowLoopback: true, allowPrivateLan: true }
    });

    if (res.status < 200 || res.status >= 300 || !res.body || res.body.length < 1024) {
      throw new Error(`Failed to fetch MeshCentral agent binary (${agentMeta.filename}, HTTP ${res.status}).`);
    }
    if (res.body[0] !== 0x4d || res.body[1] !== 0x5a) {
      throw new Error(`Downloaded ${agentMeta.filename} is not a valid Windows PE executable.`);
    }

    const rawSha256 = crypto.createHash('sha256').update(res.body).digest('hex');
    const sha16 = rawSha256.slice(0, 16);
    const signingEnabled = Boolean(settings.code_signing_enabled && settings.code_signing_url);
    const signMs2 = Boolean(settings.code_signing_sign_ms2_binary ?? 1);
    const strictVerify = Boolean(settings.code_signing_enabled && (settings.code_signing_strict_verify ?? 1));

    if (!signingEnabled || !signMs2) {
      return { buffer: res.body, filename: agentMeta.filename, sha256: rawSha256, signed: false };
    }

    const signedCacheDir = path.join(DATA_DIR_PATH, 'signed-agents');
    if (!fs.existsSync(signedCacheDir)) {
      fs.mkdirSync(signedCacheDir, { recursive: true, mode: 0o700 });
    }

    const cachedSignedPath = path.join(signedCacheDir, `meshagent-${arch}-${sha16}.signed.exe`);
    const cachedMetaPath = path.join(signedCacheDir, `meshagent-${arch}-${sha16}.signed.meta.json`);
    const latestArchMetaPath = path.join(signedCacheDir, `meshagent-${arch}.signed.meta.json`);

    if (fs.existsSync(cachedSignedPath) && fs.existsSync(cachedMetaPath)) {
      try {
        const meta = JSON.parse(fs.readFileSync(cachedMetaPath, 'utf8'));
        if (
          meta?.rawSha256 === rawSha256 &&
          meta?.signed === true &&
          meta?.signingEndpoint === settings.code_signing_url &&
          fs.statSync(cachedSignedPath).size > 1024
        ) {
          const cachedBuf = fs.readFileSync(cachedSignedPath);
          const cachedSha = crypto.createHash('sha256').update(cachedBuf).digest('hex');
          return { buffer: cachedBuf, filename: agentMeta.filename, sha256: cachedSha, signed: true };
        }
      } catch {}
    }

    const rawStagePath = path.join(signedCacheDir, `meshagent-${arch}-${sha16}.exe`);
    try {
      fs.writeFileSync(rawStagePath, res.body, { mode: 0o600 });
      const signRes = await this.signer.signFile(rawStagePath);
      if (signRes.success && signRes.signedFilePath && fs.existsSync(signRes.signedFilePath)) {
        const signedBuf = fs.readFileSync(signRes.signedFilePath);
        const signedSha = crypto.createHash('sha256').update(signedBuf).digest('hex');
        const metaPayload = JSON.stringify(
          {
            arch,
            filename: agentMeta.filename,
            cachedFile: path.basename(cachedSignedPath),
            rawSha256,
            sha256: signedSha,
            signed: true,
            endpointVerified: true,
            signingEndpoint: settings.code_signing_url,
            recordedAt: new Date().toISOString(),
            disableUnsignedAutoUpdate: Boolean(strictVerify)
          },
          null,
          2
        );
        fs.writeFileSync(cachedMetaPath, metaPayload, { mode: 0o600 });
        fs.writeFileSync(latestArchMetaPath, metaPayload, { mode: 0o600 });
        return { buffer: signedBuf, filename: agentMeta.filename, sha256: signedSha, signed: true };
      }

      if (strictVerify) {
        throw new Error(
          `Strict Authenticode signing failed for ${agentMeta.filename}: ${signRes.error || 'Unknown signing error'}`
        );
      }
      return { buffer: res.body, filename: agentMeta.filename, sha256: rawSha256, signed: false };
    } finally {
      try {
        if (fs.existsSync(rawStagePath)) fs.unlinkSync(rawStagePath);
      } catch {}
    }
  }

  private resolveInstallerContext(options: InstallerOptions) {
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;

    const tenantId = sanitizeIdentifier(options.tenantId, options.mode === 'quicksupport' ? 'quicksupport' : 'default', 64);
    const siteId = options.siteId ? sanitizeIdentifier(options.siteId, '', 64) : undefined;
    const rawDeviceRole = options.deviceRole ? sanitizeSingleLine(options.deviceRole, '', 64) : undefined;
    const deviceRole =
      rawDeviceRole && !['auto', 'auto-detect'].includes(rawDeviceRole.toLowerCase()) ? rawDeviceRole : undefined;
    const tenantRow =
      tenantId && tenantId !== 'quicksupport'
        ? ((db.prepare('SELECT * FROM tenants WHERE id = ?').get(tenantId) || {}) as any)
        : {};
    const meshServerRow = options.meshServerId
      ? ((db.prepare('SELECT * FROM mesh_servers WHERE id = ?').get(options.meshServerId) || {}) as any)
      : ((db.prepare('SELECT * FROM mesh_servers ORDER BY is_primary DESC LIMIT 1').get() || {}) as any);

    const isCompanionOnly = options.mode === 'companion_only';
    const isQuickSupport = !isCompanionOnly && options.mode === 'quicksupport';

    const effectivePolicy = resolvePolicyForInstallerScope({
      mode: options.mode || 'permanent',
      tenantId: tenantId === 'quicksupport' ? null : tenantId,
      siteId: siteId || null,
      deviceRole: deviceRole || null,
      deviceId: options.targetDeviceId || null
    });

    const brandName = sanitizeSingleLine(settings.brand_name, 'Vitrine RMM', 64);
    const primaryColor = sanitizeHexColor(settings.primary_color);

    const meshServerUrl = sanitizeServerUrl(
      meshServerRow?.url || settings.meshcentral_url || options.serverUrl,
      'https://127.0.0.1:4430'
    );
    const customDomainUrl = settings.custom_domain
      ? settings.custom_domain.startsWith('http')
        ? settings.custom_domain
        : `https://${settings.custom_domain}`
      : undefined;
    const vitrineServerUrl = sanitizeServerUrl(
      options.vitrineServerUrl || options.serverUrl || customDomainUrl,
      'http://127.0.0.1:8080'
    );
    const meshGroupId = String(options.meshGroupId || tenantRow?.mesh_group_id || '').replace(/[\r\n\0]/g, '').slice(0, 160);
    const enrollmentToken = sanitizeIdentifier(options.tokenId, '', 96);

    const resolvedTrayBrand = sanitizeSingleLine(effectivePolicy.trayBrandName || brandName, 'Vitrine RMM', 64);
    const resolvedTrayIconUrl = sanitizeSingleLine(effectivePolicy.trayIconUrl || settings.brand_logo_url || '', '', 512);
    const resolvedTrayTheme = effectivePolicy.trayThemeMode || 'system';
    const resolvedTrayEnabled = effectivePolicy.trayEnabled !== false;
    const resolvedTrayTooltip = sanitizeSingleLine(effectivePolicy.trayTooltip || '', '', 63);
    const resolvedTraySupportUrl = sanitizeSingleLine(effectivePolicy.traySupportUrl || '', '', 256);
    const resolvedTraySupportPhone = sanitizeSingleLine(effectivePolicy.traySupportPhone || '', '', 64);
    const resolvedTraySupportEmail = sanitizeSingleLine(effectivePolicy.traySupportEmail || '', '', 128);
    const resolvedMenuItems: TrayMenuItem[] = effectivePolicy.trayMenuItems || getDefaultTrayMenuItems();

    const customSvc = settings.installer_service_name || resolvedTrayBrand.replace(/[^a-zA-Z0-9]/g, '') + 'Agent';
    const serviceName = sanitizeIdentifier(customSvc, 'VitrineAgent', 40).replace(/\./g, '');
    const welcomeText = sanitizeSingleLine(
      settings.installer_welcome_text,
      'Installing Enterprise IT Support & Endpoint Protection',
      160
    );
    const guiStyle: 'modern_glass' | 'silent_headless' | 'native_ms2' =
      settings.installer_gui_style === 'silent_headless' || settings.installer_gui_style === 'native_ms2'
        ? settings.installer_gui_style
        : 'modern_glass';
    const sessionCode = sanitizeIdentifier(options.sessionCode, '', 24);

    const maxSnoozeHours = Math.max(0, Math.min(168, Number(effectivePolicy.maxSnoozeHours ?? 8)));
    const forceRebootEnabled = effectivePolicy.forceRebootAfterSnooze ? 1 : 0;
    const finalCountdownSec = Math.max(30, Math.min(3600, Number(effectivePolicy.finalCountdownSec ?? 300)));
    const telemetryIntervalSec = Math.max(10, Math.min(3600, Number(effectivePolicy.telemetryIntervalSec ?? 30)));
    const lapsAutoCreate = effectivePolicy.lapsAutoCreateAccount !== false ? 1 : 0;
    const lapsAccountName = sanitizeIdentifier(effectivePolicy.lapsAccountName, 'LocalAdmin', 20);
    const strictVerify = Boolean(settings.code_signing_enabled && (settings.code_signing_strict_verify ?? 1));
    const allowSelfSignedTls = Boolean(
      options.allowSelfSignedTls ??
        (meshServerRow?.allow_self_signed != null
          ? Boolean(meshServerRow.allow_self_signed)
          : settings.meshcentral_allow_self_signed != null
            ? Boolean(settings.meshcentral_allow_self_signed)
            : meshServerUrl.includes('127.0.0.1'))
    );

    return {
      settings,
      tenantId,
      siteId,
      deviceRole,
      brandName,
      primaryColor,
      meshServerUrl,
      vitrineServerUrl,
      meshGroupId,
      enrollmentToken,
      serviceName,
      welcomeText,
      trayThemeMode: resolvedTrayTheme,
      guiStyle,
      isQuickSupport,
      isCompanionOnly,
      targetDeviceId: options.targetDeviceId,
      sessionCode,
      maxSnoozeHours,
      forceRebootEnabled,
      finalCountdownSec,
      telemetryIntervalSec,
      lapsAutoCreate,
      lapsAccountName,
      strictVerify,
      allowSelfSignedTls,
      resolvedTrayBrand,
      resolvedTrayIconUrl,
      resolvedTrayTheme,
      resolvedTrayEnabled,
      resolvedTrayTooltip,
      resolvedTraySupportUrl,
      resolvedTraySupportPhone,
      resolvedTraySupportEmail,
      resolvedMenuItems
    };
  }

  private buildWindowsRuntimeSpec(ctx: ReturnType<InstallerGeneratorService['resolveInstallerContext']>): {
    templateName: WindowsTemplateName;
    outputFilename: string;
    fileDescription: string;
    configJson: Record<string, unknown>;
    customIcon: Buffer | null;
  } {
    const safeBrand = sanitizeSingleLine(ctx.resolvedTrayBrand || ctx.brandName, 'Vitrine RMM', 64);
    const safeWelcome = sanitizeSingleLine(
      ctx.welcomeText,
      'Installing Enterprise IT Support & Endpoint Protection',
      160
    );
    const sleepSec = Math.max(10, Math.min(3600, Math.round(Number(ctx.telemetryIntervalSec || 30))));

    const companionConfig = {
      BrandName: safeBrand,
      ServiceName: ctx.serviceName,
      VitrineServerUrl: ctx.vitrineServerUrl,
      MaxSnoozeHours: ctx.maxSnoozeHours,
      ForceRebootEnabled: ctx.forceRebootEnabled === 1,
      FinalCountdownSec: ctx.finalCountdownSec,
      TelemetryIntervalSec: sleepSec,
      AllowSelfSignedTls: Boolean(ctx.allowSelfSignedTls),
      IconUrl: ctx.resolvedTrayIconUrl || '',
      EmbeddedIconUrl: ctx.resolvedTrayIconUrl || '',
      ThemeMode: ctx.resolvedTrayTheme || 'system',
      TrayEnabled: ctx.resolvedTrayEnabled !== false,
      Tooltip: ctx.resolvedTrayTooltip || '',
      SupportUrl: ctx.resolvedTraySupportUrl || '',
      SupportPhone: ctx.resolvedTraySupportPhone || '',
      SupportEmail: ctx.resolvedTraySupportEmail || '',
      MenuItems: ctx.resolvedMenuItems || getDefaultTrayMenuItems()
    };

    const templateName: WindowsTemplateName = ctx.isQuickSupport
      ? 'vitrine-quicksupport-template.exe'
      : ctx.isCompanionOnly
        ? 'vitrine-companion-setup-template.exe'
        : 'vitrine-installer-template.exe';

    const prefix = ctx.isQuickSupport
      ? `QuickSupport-${ctx.serviceName}`
      : ctx.isCompanionOnly
        ? `CompanionSetup-${ctx.serviceName}`
        : `Install-${ctx.serviceName}`;

    const fileDescription = ctx.isQuickSupport
      ? `${safeBrand} QuickSupport On-Demand Launcher`
      : ctx.isCompanionOnly
        ? `${safeBrand} Companion Service Setup`
        : `${safeBrand} Endpoint Agent Installer`;

    return {
      templateName,
      outputFilename: `${prefix}.exe`,
      fileDescription,
      customIcon: resolveBrandingIconBuffer(ctx.resolvedTrayIconUrl),
      configJson: {
        brandName: safeBrand,
        serviceName: ctx.serviceName,
        welcomeText: safeWelcome,
        meshServerUrl: ctx.meshServerUrl,
        vitrineServerUrl: ctx.vitrineServerUrl,
        meshGroupId: ctx.meshGroupId,
        enrollmentToken: ctx.enrollmentToken,
        sessionCode: ctx.sessionCode || '',
        tenantId: ctx.tenantId,
        targetDeviceId: ctx.targetDeviceId || '',
        guiStyle: ctx.guiStyle,
        trayThemeMode: ctx.resolvedTrayTheme,
        isQuickSupport: ctx.isQuickSupport,
        companionOnly: ctx.isCompanionOnly,
        strictAuthenticodeVerify: ctx.strictVerify,
        allowSelfSignedTls: ctx.allowSelfSignedTls,
        lapsAutoCreate: ctx.lapsAutoCreate === 1,
        lapsAccountName: ctx.lapsAccountName,
        trayEnabled: ctx.resolvedTrayEnabled !== false,
        companionConfig
      }
    };
  }

  public async getOrBuildSignedWindowsComponent(
    component: 'companion' | 'tray',
    opts?: { brandName?: string; iconUrl?: string }
  ): Promise<{ buffer: Buffer; filename: string; sha256: string; signed: boolean }> {
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    const policy = (db.prepare("SELECT tray_brand_name, tray_icon_url FROM policies WHERE tier = 'global' LIMIT 1").get() || {}) as any;
    const brandName = sanitizeSingleLine(opts?.brandName || policy.tray_brand_name || settings.brand_name, 'Vitrine RMM', 64);
    const iconUrl = String(opts?.iconUrl || policy.tray_icon_url || settings.brand_logo_url || '').trim();
    const customIcon = resolveBrandingIconBuffer(iconUrl);

    const templateName: WindowsTemplateName =
      component === 'tray' ? 'vitrine-tray-template.exe' : 'vitrine-companion-template.exe';
    const targetFilename = component === 'tray' ? 'vitrine-tray.exe' : 'vitrine-companion.exe';
    const fileDescription =
      component === 'tray' ? `${brandName} Desktop Support Tray` : `${brandName} Background Companion Service`;

    const stampedBuf = buildStampedWindowsPe(templateName, {
      companyName: brandName,
      productName: brandName,
      fileDescription,
      originalFilename: targetFilename,
      internalName: targetFilename,
      customIconBuffer: customIcon
    });

    const rawSha256 = crypto.createHash('sha256').update(stampedBuf).digest('hex');
    const sha16 = rawSha256.slice(0, 16);
    const signingEnabled = Boolean(settings.code_signing_enabled && settings.code_signing_url);
    const signAgents = Boolean(settings.code_signing_sign_agents ?? 1);
    const strictVerify = Boolean(settings.code_signing_enabled && (settings.code_signing_strict_verify ?? 1));

    if (!signingEnabled || !signAgents) {
      return { buffer: stampedBuf, filename: targetFilename, sha256: rawSha256, signed: false };
    }

    const signedCacheDir = path.join(DATA_DIR_PATH, 'signed-agents');
    if (!fs.existsSync(signedCacheDir)) {
      fs.mkdirSync(signedCacheDir, { recursive: true, mode: 0o700 });
    }

    const cachedSignedPath = path.join(signedCacheDir, `vitrine-${component}-${sha16}.signed.exe`);
    const cachedMetaPath = path.join(signedCacheDir, `vitrine-${component}-${sha16}.signed.meta.json`);
    if (fs.existsSync(cachedSignedPath) && fs.existsSync(cachedMetaPath)) {
      try {
        const meta = JSON.parse(fs.readFileSync(cachedMetaPath, 'utf8'));
        if (
          meta?.rawSha256 === rawSha256 &&
          meta?.signed === true &&
          meta?.signingEndpoint === settings.code_signing_url &&
          fs.statSync(cachedSignedPath).size > 1024
        ) {
          const cachedBuf = fs.readFileSync(cachedSignedPath);
          const cachedSha = crypto.createHash('sha256').update(cachedBuf).digest('hex');
          return { buffer: cachedBuf, filename: targetFilename, sha256: cachedSha, signed: true };
        }
      } catch {}
    }

    const rawStagePath = path.join(signedCacheDir, `vitrine-${component}-${sha16}.exe`);
    try {
      fs.writeFileSync(rawStagePath, stampedBuf, { mode: 0o600 });
      const signRes = await this.signer.signFile(rawStagePath);
      if (signRes.success && signRes.signedFilePath && fs.existsSync(signRes.signedFilePath)) {
        const signedBuf = fs.readFileSync(signRes.signedFilePath);
        const signedSha = crypto.createHash('sha256').update(signedBuf).digest('hex');
        const metaPayload = JSON.stringify(
          {
            component,
            filename: targetFilename,
            cachedFile: path.basename(cachedSignedPath),
            rawSha256,
            sha256: signedSha,
            signed: true,
            signingEndpoint: settings.code_signing_url,
            recordedAt: new Date().toISOString()
          },
          null,
          2
        );
        fs.writeFileSync(cachedMetaPath, metaPayload, { mode: 0o600 });
        return { buffer: signedBuf, filename: targetFilename, sha256: signedSha, signed: true };
      }
      if (strictVerify) {
        throw new Error(`Strict Authenticode signing failed for ${targetFilename}: ${signRes.error || 'Unknown signing error'}`);
      }
      return { buffer: stampedBuf, filename: targetFilename, sha256: rawSha256, signed: false };
    } finally {
      try {
        if (fs.existsSync(rawStagePath)) fs.unlinkSync(rawStagePath);
      } catch {}
    }
  }

  public async runSigningPipeline(options: InstallerOptions): Promise<{
    allSigned: boolean;
    signed?: boolean;
    endpointVerified?: boolean;
    strictVerified: boolean;
    stages: SigningStageReport[];
  }> {
    const ctx = this.resolveInstallerContext(options);
    const settings = ctx.settings;
    const signingEnabled = Boolean(settings.code_signing_enabled && settings.code_signing_url);
    const signMs2 = Boolean(settings.code_signing_sign_ms2_binary ?? 1);
    const signAgents = Boolean(settings.code_signing_sign_agents ?? 1);
    const strictVerify = Boolean(settings.code_signing_strict_verify ?? 1);

    const signedCacheDir = path.join(DATA_DIR_PATH, 'signed-agents');
    if (!fs.existsSync(signedCacheDir)) {
      fs.mkdirSync(signedCacheDir, { recursive: true, mode: 0o700 });
    }

    let endpointReady = false;
    let probeLatency = 0;
    let probeError = '';
    if (signingEnabled) {
      const probe = await this.signer.testConnection(settings.code_signing_url);
      endpointReady = Boolean(probe.reachable && probe.authenticated !== false);
      probeLatency = probe.latencyMs;
      probeError = probe.error || '';
    }

    const stages: SigningStageReport[] = [];
    const safeOs =
      options.os === 'linux' ? 'linux' : options.os === 'darwin' || options.os === 'macos' ? 'macos' : 'windows';

    const resolveStatus = (stageFlag: boolean): SigningStageReport['status'] => {
      if (!signingEnabled || !stageFlag) return 'bypassed';
      return endpointReady ? 'verified' : 'unreachable';
    };

    const resolveAuthority = (stageFlag: boolean): string => {
      if (!signingEnabled || !stageFlag) return 'Unsigned (Signing Disabled in Settings)';
      if (endpointReady) return `Signing Endpoint Verified (${settings.code_signing_url})`;
      return probeError
        ? `Signing API Unreachable (${probeError})`
        : `Signing API Unreachable (${settings.code_signing_url})`;
    };

    // Stage 1: Native MeshCentral 2 Core Agent Binary
    const stage1Start = Date.now();
    let stage1Status: SigningStageReport['status'] = resolveStatus(signMs2);
    let stage1Authority = resolveAuthority(signMs2);
    let stage1Sha256 = '';
    if (safeOs === 'windows') {
      const cachedMetaPath = path.join(signedCacheDir, 'meshagent-x64.signed.meta.json');
      if (fs.existsSync(cachedMetaPath)) {
        try {
          const cachedMeta = JSON.parse(fs.readFileSync(cachedMetaPath, 'utf8'));
          const cachedExe = cachedMeta?.cachedFile ? path.join(signedCacheDir, path.basename(cachedMeta.cachedFile)) : '';
          if (
            cachedMeta?.signed === true &&
            cachedExe &&
            fs.existsSync(cachedExe) &&
            (!signingEnabled || cachedMeta?.signingEndpoint === settings.code_signing_url)
          ) {
            stage1Sha256 = crypto.createHash('sha256').update(fs.readFileSync(cachedExe)).digest('hex');
            if (signingEnabled && signMs2) {
              stage1Status = 'signed';
              stage1Authority = `Authenticode + RFC 3161 (${settings.code_signing_url})`;
            }
          }
        } catch {}
      }
    }

    stages.push({
      stepNumber: 1,
      component: `MeshCentral 2 Core Agent (${safeOs === 'windows' ? 'MeshService64.exe' : 'meshagent'})`,
      description: 'Authenticode PE header verification & signed-agents/ update cache lock',
      status: stage1Status,
      sha256: stage1Sha256,
      timestampAuthority: stage1Authority,
      durationMs: Math.max(1, probeLatency || Date.now() - stage1Start)
    });

    // Stage 2 & Stage 3: Component & Outer Package Verification / Digest
    const stage2Start = Date.now();
    let companionHash = '';
    let companionStatus: SigningStageReport['status'] = resolveStatus(signAgents);
    let companionAuthority = resolveAuthority(signAgents);
    let installerHash = '';

    if (safeOs === 'windows') {
      if (signingEnabled && signAgents && endpointReady) {
        try {
          const comp = await this.getOrBuildSignedWindowsComponent('companion', {
            brandName: ctx.resolvedTrayBrand,
            iconUrl: ctx.resolvedTrayIconUrl
          });
          await this.getOrBuildSignedWindowsComponent('tray', {
            brandName: ctx.resolvedTrayBrand,
            iconUrl: ctx.resolvedTrayIconUrl
          });
          companionHash = comp.sha256;
          if (comp.signed) {
            companionStatus = 'signed';
            companionAuthority = `Authenticode + RFC 3161 (${settings.code_signing_url})`;
          }
        } catch {
          companionHash = crypto
            .createHash('sha256')
            .update(fs.readFileSync(resolveWindowsTemplatePath('vitrine-companion-template.exe')))
            .digest('hex');
        }
      } else {
        try {
          companionHash = crypto
            .createHash('sha256')
            .update(fs.readFileSync(resolveWindowsTemplatePath('vitrine-companion-template.exe')))
            .digest('hex');
        } catch {}
      }

      const spec = this.buildWindowsRuntimeSpec(ctx);
      const previewPe = buildStampedWindowsPe(spec.templateName, {
        companyName: ctx.resolvedTrayBrand || ctx.brandName,
        productName: ctx.resolvedTrayBrand || ctx.brandName,
        fileDescription: spec.fileDescription,
        originalFilename: spec.outputFilename,
        internalName: spec.outputFilename,
        configJson: spec.configJson,
        customIconBuffer: spec.customIcon
      });
      installerHash = crypto.createHash('sha256').update(previewPe).digest('hex');
    } else if (safeOs === 'linux') {
      const linuxSrc = this.generateLinuxInstaller({
        brandName: ctx.resolvedTrayBrand || ctx.brandName,
        primaryColor: ctx.primaryColor,
        meshServerUrl: ctx.meshServerUrl,
        vitrineServerUrl: ctx.vitrineServerUrl,
        meshGroupId: ctx.meshGroupId,
        enrollmentToken: ctx.enrollmentToken,
        tenantId: ctx.tenantId,
        serviceName: ctx.serviceName.toLowerCase(),
        trayThemeMode: ctx.resolvedTrayTheme,
        trayEnabled: ctx.resolvedTrayEnabled,
        trayTooltip: ctx.resolvedTrayTooltip,
        trayIconUrl: ctx.resolvedTrayIconUrl,
        traySupportUrl: ctx.resolvedTraySupportUrl,
        traySupportPhone: ctx.resolvedTraySupportPhone,
        traySupportEmail: ctx.resolvedTraySupportEmail,
        trayMenuItems: ctx.resolvedMenuItems,
        isQuickSupport: ctx.isQuickSupport,
        sessionCode: ctx.sessionCode,
        lapsAutoCreate: ctx.lapsAutoCreate,
        lapsAccountName: ctx.lapsAccountName,
        allowSelfSignedTls: ctx.allowSelfSignedTls,
        telemetryIntervalSec: ctx.telemetryIntervalSec
      });
      companionHash = crypto.createHash('sha256').update(linuxSrc, 'utf8').digest('hex');
      installerHash = companionHash;
    } else {
      const macSrc = this.generateMacInstaller({
        brandName: ctx.brandName,
        primaryColor: ctx.primaryColor,
        meshServerUrl: ctx.meshServerUrl,
        vitrineServerUrl: ctx.vitrineServerUrl,
        meshGroupId: ctx.meshGroupId,
        enrollmentToken: ctx.enrollmentToken,
        tenantId: ctx.tenantId,
        serviceName: ctx.serviceName,
        trayThemeMode: ctx.trayThemeMode,
        isQuickSupport: ctx.isQuickSupport,
        lapsAutoCreate: ctx.lapsAutoCreate,
        lapsAccountName: ctx.lapsAccountName,
        allowSelfSignedTls: ctx.allowSelfSignedTls,
        telemetryIntervalSec: ctx.telemetryIntervalSec
      });
      companionHash = crypto.createHash('sha256').update(macSrc, 'utf8').digest('hex');
      installerHash = companionHash;
    }

    stages.push({
      stepNumber: 2,
      component:
        safeOs === 'windows'
          ? 'Vitrine Desktop Companion & Tray Executables (vitrine-companion.exe / vitrine-tray.exe)'
          : 'Vitrine Desktop Companion & Telemetry Agent',
      description: 'Native Windows Service, Tray HUD, Check-in Task Runner & LAPS module',
      status: companionStatus,
      sha256: companionHash,
      timestampAuthority: companionAuthority,
      durationMs: Math.max(1, Date.now() - stage2Start)
    });

    const stage3Start = Date.now();
    stages.push({
      stepNumber: 3,
      component:
        options.mode === 'quicksupport'
          ? 'Vitrine QuickSupport On-Demand Launcher (.exe, asInvoker)'
          : options.mode === 'companion_only'
            ? 'Vitrine Companion Setup Executable (.exe, requireAdministrator)'
            : 'Vitrine Modern GUI Installer (.exe, requireAdministrator)',
      description: 'Native Win32 PE32+ executable with VS_VERSION_INFO, Manifest, Brand Icon & digital signature',
      status: resolveStatus(signAgents),
      sha256: installerHash,
      timestampAuthority: resolveAuthority(signAgents),
      durationMs: Math.max(1, Date.now() - stage3Start)
    });

    const hasSignedOrVerified = stages.some((s) => s.status === 'signed' || s.status === 'verified');
    return {
      allSigned:
        hasSignedOrVerified &&
        stages.every((s) => s.status === 'signed' || s.status === 'verified' || s.status === 'bypassed'),
      signed: hasSignedOrVerified,
      endpointVerified: Boolean(signingEnabled && endpointReady),
      strictVerified: strictVerify,
      stages
    };
  }

  public async generateInstaller(options: InstallerOptions): Promise<{
    filename: string;
    contentType: string;
    content: string | Buffer;
    signingPipeline?: {
      allSigned: boolean;
      signed?: boolean;
      endpointVerified?: boolean;
      strictVerified: boolean;
      stages: SigningStageReport[];
    };
  }> {
    const ctx = this.resolveInstallerContext(options);
    const settings = ctx.settings;
    const signingPipeline = await this.runSigningPipeline(options);

    if (options.os === 'windows') {
      const spec = this.buildWindowsRuntimeSpec(ctx);
      let finalPe: Buffer = buildStampedWindowsPe(spec.templateName, {
        companyName: ctx.resolvedTrayBrand || ctx.brandName,
        productName: ctx.resolvedTrayBrand || ctx.brandName,
        fileDescription: spec.fileDescription,
        originalFilename: spec.outputFilename,
        internalName: spec.outputFilename,
        configJson: spec.configJson,
        customIconBuffer: spec.customIcon
      });

      if (settings.code_signing_enabled && settings.code_signing_sign_agents && settings.code_signing_url) {
        const stagingDir = path.join(DATA_DIR_PATH, 'signing-staging');
        if (!fs.existsSync(stagingDir)) {
          fs.mkdirSync(stagingDir, { recursive: true, mode: 0o700 });
        }
        const tmpExe = path.join(stagingDir, `vitrine-inst-${crypto.randomUUID()}.exe`);
        let signedPathToClean: string | undefined;
        try {
          fs.writeFileSync(tmpExe, finalPe, { mode: 0o600 });
          const signRes = await this.signer.signFile(tmpExe);
          signedPathToClean = signRes.signedFilePath;
          if (signRes.success && signRes.signedFilePath && fs.existsSync(signRes.signedFilePath)) {
            finalPe = fs.readFileSync(signRes.signedFilePath);
            const signedSha = crypto.createHash('sha256').update(finalPe).digest('hex');
            signingPipeline.signed = true;
            const stg3 = signingPipeline.stages.find((s) => s.stepNumber === 3);
            if (stg3 && stg3.status !== 'bypassed') {
              stg3.status = 'signed';
              stg3.sha256 = signedSha;
              stg3.timestampAuthority = `Authenticode + RFC 3161 (${settings.code_signing_url})`;
              if (signRes.durationMs) stg3.durationMs = signRes.durationMs;
            }
            signingPipeline.allSigned =
              signingPipeline.stages.some((s) => s.status === 'signed' || s.status === 'verified') &&
              signingPipeline.stages.every(
                (s) => s.status === 'signed' || s.status === 'verified' || s.status === 'bypassed'
              );
          } else if (ctx.strictVerify) {
            throw new Error(
              `Strict code signing is enforced, and signing server failed: ${signRes.error || 'Unknown error'}`
            );
          }
        } finally {
          try {
            if (fs.existsSync(tmpExe)) fs.unlinkSync(tmpExe);
          } catch {}
          try {
            if (signedPathToClean && fs.existsSync(signedPathToClean)) fs.unlinkSync(signedPathToClean);
          } catch {}
        }
      }

      return {
        filename: spec.outputFilename,
        contentType: 'application/vnd.microsoft.portable-executable',
        content: finalPe,
        signingPipeline
      };
    } else if (options.os === 'linux') {
      const script = this.generateLinuxInstaller({
        brandName: ctx.resolvedTrayBrand || ctx.brandName,
        primaryColor: ctx.primaryColor,
        meshServerUrl: ctx.meshServerUrl,
        vitrineServerUrl: ctx.vitrineServerUrl,
        meshGroupId: ctx.meshGroupId,
        enrollmentToken: ctx.enrollmentToken,
        tenantId: ctx.tenantId,
        serviceName: ctx.serviceName.toLowerCase(),
        trayThemeMode: ctx.resolvedTrayTheme,
        trayEnabled: ctx.resolvedTrayEnabled,
        trayTooltip: ctx.resolvedTrayTooltip,
        trayIconUrl: ctx.resolvedTrayIconUrl,
        traySupportUrl: ctx.resolvedTraySupportUrl,
        traySupportPhone: ctx.resolvedTraySupportPhone,
        traySupportEmail: ctx.resolvedTraySupportEmail,
        trayMenuItems: ctx.resolvedMenuItems,
        isQuickSupport: ctx.isQuickSupport,
        sessionCode: ctx.sessionCode,
        lapsAutoCreate: ctx.lapsAutoCreate,
        lapsAccountName: ctx.lapsAccountName,
        allowSelfSignedTls: ctx.allowSelfSignedTls,
        telemetryIntervalSec: ctx.telemetryIntervalSec
      });

      return {
        filename: ctx.isQuickSupport
          ? `quicksupport-${ctx.serviceName.toLowerCase()}.sh`
          : `install-${ctx.serviceName.toLowerCase()}.sh`,
        contentType: 'text/x-shellscript; charset=utf-8',
        content: script,
        signingPipeline
      };
    } else {
      const script = this.generateMacInstaller({
        brandName: ctx.brandName,
        primaryColor: ctx.primaryColor,
        meshServerUrl: ctx.meshServerUrl,
        vitrineServerUrl: ctx.vitrineServerUrl,
        meshGroupId: ctx.meshGroupId,
        enrollmentToken: ctx.enrollmentToken,
        tenantId: ctx.tenantId,
        serviceName: ctx.serviceName,
        trayThemeMode: ctx.trayThemeMode,
        isQuickSupport: ctx.isQuickSupport,
        lapsAutoCreate: ctx.lapsAutoCreate,
        lapsAccountName: ctx.lapsAccountName,
        allowSelfSignedTls: ctx.allowSelfSignedTls,
        telemetryIntervalSec: ctx.telemetryIntervalSec
      });

      return {
        filename: ctx.isQuickSupport
          ? `quicksupport-${ctx.serviceName.toLowerCase()}-mac.sh`
          : `install-${ctx.serviceName.toLowerCase()}-mac.sh`,
        contentType: 'text/x-shellscript; charset=utf-8',
        content: script,
        signingPipeline
      };
    }
  }

  public async generateCompanionOnlyBootstrap(options: {
    os: 'windows' | 'linux' | 'macos';
    deviceId: string;
    tenantId: string;
    enrollmentToken: string;
    vitrineServerUrl: string;
    allowSelfSignedTls?: boolean;
  }): Promise<string> {
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    let eff: ReturnType<typeof resolveEffectiveDevicePolicy> | null = null;
    try {
      eff = resolveEffectiveDevicePolicy(options.deviceId);
    } catch {
      eff = null;
    }

    const brandName = sanitizeSingleLine(eff?.trayBrandName || settings.brand_name, 'Vitrine RMM', 64);
    const customSvc = settings.installer_service_name || brandName.replace(/[^a-zA-Z0-9]/g, '') + 'Agent';
    const serviceName = sanitizeIdentifier(customSvc, 'VitrineAgent', 40).replace(/\./g, '');
    const vitrineServerUrl = sanitizeServerUrl(options.vitrineServerUrl, 'http://127.0.0.1:8080');
    const enrollmentToken = sanitizeIdentifier(options.enrollmentToken, '', 96);
    const tenantId = sanitizeIdentifier(options.tenantId, 'default', 64);
    const allowSelfSignedTls = Boolean(options.allowSelfSignedTls);

    if (options.os === 'windows') {
      const setupUrl = `${vitrineServerUrl}/api/agent/download?token=${encodeURIComponent(enrollmentToken)}&os=windows&mode=companion&deviceId=${encodeURIComponent(options.deviceId)}`;
      const strictVerify = Boolean(settings.code_signing_enabled && (settings.code_signing_strict_verify ?? 1));
      return [
        '$ErrorActionPreference = "Stop"',
        '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13',
        ...(allowSelfSignedTls ? ['[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }'] : []),
        `$exeUrl = ${quotePowerShellLiteral(setupUrl)}`,
        `$tmpExe = Join-Path $env:TEMP ('CompanionSetup-' + [guid]::NewGuid().ToString('N') + '.exe')`,
        'try {',
        '    Invoke-WebRequest -Uri $exeUrl -OutFile $tmpExe -UseBasicParsing -TimeoutSec 45',
        ...(strictVerify
          ? [
              '$sig = Get-AuthenticodeSignature -FilePath $tmpExe -ErrorAction SilentlyContinue',
              'if ($null -eq $sig -or $sig.Status -ne "Valid") { throw "Strict Authenticode check failed for CompanionSetup executable ($($sig.Status))" }'
            ]
          : []),
        '    $proc = Start-Process -FilePath $tmpExe -ArgumentList @("/S") -Wait -PassThru -WindowStyle Hidden',
        '    if ($proc.ExitCode -ne 0) { throw "CompanionSetup exited with code $($proc.ExitCode)" }',
        '    Write-Output "COMPANION_DEPLOY_OK"',
        '} finally {',
        '    if (Test-Path -LiteralPath $tmpExe) { Remove-Item -LiteralPath $tmpExe -Force -ErrorAction SilentlyContinue }',
        '}'
      ].join('\r\n');
    }

    const telemetryIntervalSec = Math.max(10, Math.min(3600, Number(eff?.telemetryIntervalSec ?? 30)));
    const full =
      options.os === 'linux'
        ? this.generateLinuxInstaller({
            brandName,
            primaryColor: sanitizeHexColor(settings.primary_color),
            meshServerUrl: vitrineServerUrl,
            vitrineServerUrl,
            meshGroupId: '',
            enrollmentToken,
            tenantId,
            serviceName: serviceName.toLowerCase(),
            trayThemeMode: eff?.trayThemeMode || 'system',
            trayEnabled: eff?.trayEnabled !== false,
            trayTooltip: eff?.trayTooltip || '',
            trayIconUrl: eff?.trayIconUrl || settings.brand_logo_url || '',
            traySupportUrl: eff?.traySupportUrl || '',
            traySupportPhone: eff?.traySupportPhone || '',
            traySupportEmail: eff?.traySupportEmail || '',
            trayMenuItems: eff?.trayMenuItems || getDefaultTrayMenuItems(),
            isQuickSupport: false,
            lapsAutoCreate: 0,
            lapsAccountName: 'LocalAdmin',
            allowSelfSignedTls,
            skipMeshAgentDownload: true,
            targetDeviceId: options.deviceId,
            telemetryIntervalSec
          })
        : this.generateMacInstaller({
            brandName,
            primaryColor: sanitizeHexColor(settings.primary_color),
            meshServerUrl: vitrineServerUrl,
            vitrineServerUrl,
            meshGroupId: '',
            enrollmentToken,
            tenantId,
            serviceName,
            trayThemeMode: eff?.trayThemeMode || 'system',
            isQuickSupport: false,
            lapsAutoCreate: 0,
            lapsAccountName: 'LocalAdmin',
            allowSelfSignedTls,
            skipMeshAgentDownload: true,
            targetDeviceId: options.deviceId,
            telemetryIntervalSec
          });
    return `${full}\necho "COMPANION_DEPLOY_OK"`;
  }

  private generateLinuxInstaller(vars: {
    brandName: string;
    primaryColor: string;
    meshServerUrl: string;
    vitrineServerUrl: string;
    meshGroupId: string;
    enrollmentToken: string;
    tenantId: string;
    serviceName: string;
    trayThemeMode: 'system' | 'dark' | 'light';
    trayEnabled?: boolean;
    trayTooltip?: string;
    trayIconUrl?: string;
    traySupportUrl?: string;
    traySupportPhone?: string;
    traySupportEmail?: string;
    trayMenuItems?: TrayMenuItem[];
    isQuickSupport: boolean;
    sessionCode?: string;
    lapsAutoCreate: number;
    lapsAccountName: string;
    allowSelfSignedTls?: boolean;
    skipMeshAgentDownload?: boolean;
    targetDeviceId?: string;
    telemetryIntervalSec?: number;
  }): string {
    const cleanBrand = sanitizeSingleLine(vars.brandName, 'Vitrine RMM', 64);
    const safeServiceName = sanitizeIdentifier(vars.serviceName, 'vitrineagent', 40).toLowerCase();
    const safeCommentBrand = cleanBrand.replace(/#/g, '');
    const safeUnitBrand = cleanBrand.replace(/["\\]/g, '').trim() || 'Vitrine RMM';
    const curlTlsFlag = vars.allowSelfSignedTls ? '--insecure ' : '';
    const sleepSec = Math.max(10, Math.min(3600, Math.round(Number(vars.telemetryIntervalSec || 25))));
    const companionConfigJson = JSON.stringify({
      BrandName: cleanBrand,
      ServiceName: safeServiceName,
      serviceSlug: safeServiceName,
      VitrineServerUrl: vars.vitrineServerUrl,
      TelemetryIntervalSec: sleepSec,
      AllowSelfSignedTls: Boolean(vars.allowSelfSignedTls),
      IconUrl: vars.trayIconUrl || '',
      ThemeMode: vars.trayThemeMode || 'system',
      TrayEnabled: vars.trayEnabled !== false,
      Tooltip: vars.trayTooltip || `${cleanBrand} Support`,
      SupportUrl: vars.traySupportUrl || '',
      SupportPhone: vars.traySupportPhone || '',
      SupportEmail: vars.traySupportEmail || '',
      MenuItems: vars.trayMenuItems || getDefaultTrayMenuItems(),
      isQuickSupport: Boolean(vars.isQuickSupport),
      SessionCode: vars.sessionCode || ''
    });
    const companionPy = buildLinuxCompanionPy(sleepSec);
    const trayPy = buildLinuxTrayPy();

    const lines = [
      '#!/usr/bin/env bash',
      '# ==============================================================================',
      `# ${safeCommentBrand} - Linux Cross-Distro Agent, Companion & Desktop Tray`,
      `# Distros: Debian / Ubuntu / RHEL / Fedora / Rocky / Alma / Arch`,
      `# Mode: ${vars.isQuickSupport ? 'QuickSupport On-Demand (User Space)' : 'Permanent Systemd Service + Desktop Tray'}`,
      '# ==============================================================================',
      'set -euo pipefail',
      '',
      ...(vars.isQuickSupport
        ? ['# QuickSupport runs in standard user session; supports pkexec/sudo remote elevation']
        : [
            'if [ "${EUID:-$(id -u)}" -ne 0 ]; then',
            '  echo "[-] Please run as root (sudo ./install.sh)" >&2',
            '  exit 1',
            'fi'
          ]),
      '',
      `BRAND_NAME=${quoteBashLiteral(cleanBrand)}`,
      `SAFE_UNIT_BRAND=${quoteBashLiteral(safeUnitBrand)}`,
      `SERVICE_NAME=${quoteBashLiteral(safeServiceName)}`,
      `MESH_SERVER_URL=${quoteBashLiteral(vars.meshServerUrl)}`,
      `VITRINE_SERVER_URL=${quoteBashLiteral(vars.vitrineServerUrl)}`,
      `MESH_GROUP_ID=${quoteBashLiteral(vars.meshGroupId.replace(/^mesh\/\//, ''))}`,
      `ENROLLMENT_TOKEN=${quoteBashLiteral(vars.enrollmentToken)}`,
      `TENANT_ID=${quoteBashLiteral(vars.tenantId)}`,
      `TRAY_THEME=${quoteBashLiteral(vars.trayThemeMode)}`,
      `TRAY_ICON_URL=${quoteBashLiteral(vars.trayIconUrl || '')}`,
      `SESSION_CODE=${quoteBashLiteral(vars.sessionCode || '')}`,
      `LAPS_AUTO_CREATE=${quoteBashLiteral(String(vars.lapsAutoCreate))}`,
      `LAPS_USER=${quoteBashLiteral(sanitizeIdentifier(vars.lapsAccountName, 'LocalAdmin', 20))}`,
      `CURL_TLS_FLAG=${quoteBashLiteral(vars.allowSelfSignedTls ? '--insecure' : '')}`,
      vars.isQuickSupport
        ? 'INSTALL_DIR="$HOME/.local/share/${SERVICE_NAME}-quicksupport"'
        : 'INSTALL_DIR="/opt/${SERVICE_NAME}"',
      vars.isQuickSupport
        ? 'TRAY_DIR="$INSTALL_DIR/tray"'
        : 'TRAY_DIR="/var/lib/${SERVICE_NAME}/tray"',
      '',
      'http_get_file() {',
      '  if command -v curl >/dev/null 2>&1; then',
      '    if [ -n "$CURL_TLS_FLAG" ]; then curl --insecure -fsSL "$1" -o "$2"; else curl -fsSL "$1" -o "$2"; fi',
      '  else',
      '    python3 -c \'import ssl,sys,urllib.request; ctx=ssl._create_unverified_context() if sys.argv[3]=="--insecure" else ssl.create_default_context(); r=urllib.request.urlopen(urllib.request.Request(sys.argv[1],method="GET"),timeout=30,context=ctx); open(sys.argv[2],"wb").write(r.read())\' "$1" "$2" "$CURL_TLS_FLAG"',
      '  fi',
      '}',
      'http_post_json() {',
      '  if command -v curl >/dev/null 2>&1; then',
      '    if [ -n "$CURL_TLS_FLAG" ]; then curl --insecure -fsSL -X POST "$1" -H "Content-Type: application/json" -d "$2"; else curl -fsSL -X POST "$1" -H "Content-Type: application/json" -d "$2"; fi',
      '  else',
      '    python3 -c \'import ssl,sys,urllib.request; ctx=ssl._create_unverified_context() if sys.argv[3]=="--insecure" else ssl.create_default_context(); req=urllib.request.Request(sys.argv[1],data=sys.argv[2].encode("utf-8"),method="POST",headers={"Content-Type":"application/json"}); sys.stdout.write(urllib.request.urlopen(req,timeout=30,context=ctx).read().decode("utf-8"))\' "$1" "$2" "$CURL_TLS_FLAG"',
      '  fi',
      '}',
      '',
      vars.isQuickSupport ? 'umask 077' : 'umask 022',
      'mkdir -p "$INSTALL_DIR" "$TRAY_DIR/inbox" "$TRAY_DIR/outbox"',
      ...(vars.isQuickSupport
        ? ['chmod 700 "$INSTALL_DIR" "$TRAY_DIR" "$TRAY_DIR/inbox" "$TRAY_DIR/outbox"']
        : [
            'chmod 755 "$INSTALL_DIR" "/var/lib/${SERVICE_NAME}" "$TRAY_DIR" "$TRAY_DIR/inbox"',
            'chmod 1777 "$TRAY_DIR/outbox"'
          ]),
      '',
      'ARCH="$(uname -m)"',
      'MESH_TYPE=6',
      'if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then MESH_TYPE=25; fi',
      '',
      'if [ -n "$MESH_GROUP_ID" ]; then',
      '  http_get_file "$MESH_SERVER_URL/meshsettings?id=$MESH_GROUP_ID" "$INSTALL_DIR/meshagent.msh" || true',
      'fi',
      '',
      ...(vars.skipMeshAgentDownload
        ? ['# Companion-only deployment over live MeshCentral tunnel (leaving existing MeshAgent untouched)']
        : [
            'if http_get_file "$MESH_SERVER_URL/meshagents?id=$MESH_TYPE" "$INSTALL_DIR/meshagent" 2>/dev/null; then',
            '  if [ -s "$INSTALL_DIR/meshagent" ]; then',
            '    chmod 755 "$INSTALL_DIR/meshagent"',
            ...(vars.isQuickSupport
              ? ['    "$INSTALL_DIR/meshagent" -connect >/dev/null 2>&1 &']
              : [
                  '    mkdir -p "$INSTALL_DIR/meshcore"',
                  '    if [ -s "$INSTALL_DIR/meshagent.msh" ]; then cp "$INSTALL_DIR/meshagent.msh" "$INSTALL_DIR/meshcore/meshagent.msh" && chmod 600 "$INSTALL_DIR/meshcore/meshagent.msh"; fi',
                  '    (cd "$INSTALL_DIR" && "$INSTALL_DIR/meshagent" -install --installPath="$INSTALL_DIR/meshcore") || true',
                  '    if [ -s "$INSTALL_DIR/meshagent.msh" ]; then cp "$INSTALL_DIR/meshagent.msh" "$INSTALL_DIR/meshcore/meshagent.msh" && chmod 600 "$INSTALL_DIR/meshcore/meshagent.msh" && (systemctl restart meshagent 2>/dev/null || true); fi'
                ]),
            '  fi',
            'else',
            '  echo "[!] MeshCentral binary download skipped or unreachable; proceeding with Vitrine Companion Agent." >&2',
            'fi'
          ]),
      '',
      '# Provision Managed Local Admin Account (Debian sudo vs RHEL/Arch wheel)',
      'if [ "${EUID:-$(id -u)}" -eq 0 ] && [ "$LAPS_AUTO_CREATE" = "1" ]; then',
      '  if ! id "$LAPS_USER" >/dev/null 2>&1; then',
      '    useradd -m -s /bin/bash "$LAPS_USER"',
      '    INIT_PASS="$(head -c 24 /dev/urandom | base64 | tr -dc "A-Za-z0-9" | head -c 24)!9vR"',
      '    printf "%s:%s\\n" "$LAPS_USER" "$INIT_PASS" | chpasswd',
      '    if getent group sudo >/dev/null 2>&1; then',
      '      usermod -aG sudo "$LAPS_USER" 2>/dev/null || true',
      '    elif getent group wheel >/dev/null 2>&1; then',
      '      usermod -aG wheel "$LAPS_USER" 2>/dev/null || true',
      '    fi',
      '    if [ -d /etc/sudoers.d ]; then',
      '      printf "%s ALL=(ALL:ALL) ALL\\n" "$LAPS_USER" > "/etc/sudoers.d/90-vitrine-laps"',
      '      chmod 0440 "/etc/sudoers.d/90-vitrine-laps"',
      '      if command -v visudo >/dev/null 2>&1 && ! visudo -cf "/etc/sudoers.d/90-vitrine-laps" >/dev/null 2>&1; then',
      '        rm -f "/etc/sudoers.d/90-vitrine-laps"',
      '      fi',
      '    fi',
      '  fi',
      'fi',
      '',
      '# Write Tray/Companion Policy Configuration',
      "cat > \"$INSTALL_DIR/companion-config.json\" <<'VITRINE_CFG_EOF'",
      companionConfigJson,
      'VITRINE_CFG_EOF',
      vars.isQuickSupport
        ? 'chmod 600 "$INSTALL_DIR/companion-config.json"'
        : 'chmod 644 "$INSTALL_DIR/companion-config.json"',
      '',
      'if [ -n "$TRAY_ICON_URL" ]; then',
      '  ICON_DL="$TRAY_ICON_URL"',
      '  case "$ICON_DL" in',
      '    http://*|https://*) ;;',
      '    /*) ICON_DL="${VITRINE_SERVER_URL%/}$ICON_DL" ;;',
      '    *) ICON_DL="${VITRINE_SERVER_URL%/}/$ICON_DL" ;;',
      '  esac',
      '  if http_get_file "$ICON_DL" "$TRAY_DIR/tray-icon.png" 2>/dev/null; then',
      '    chmod 644 "$TRAY_DIR/tray-icon.png" 2>/dev/null || true',
      '    printf "%s" "$TRAY_ICON_URL" > "$TRAY_DIR/tray-icon.url" && chmod 644 "$TRAY_DIR/tray-icon.url" 2>/dev/null || true',
      '  else',
      '    rm -f "$TRAY_DIR/tray-icon.png"',
      '  fi',
      'fi',
      '',
      '# Write Cross-Distro Companion Worker & Theme-Aware Desktop Tray',
      "cat > \"$INSTALL_DIR/vitrine-companion.py\" <<'PYAGENT'",
      companionPy,
      'PYAGENT',
      'chmod 700 "$INSTALL_DIR/vitrine-companion.py"',
      '',
      "cat > \"$INSTALL_DIR/vitrine-tray.py\" <<'PYTRAY'",
      trayPy,
      'PYTRAY',
      vars.isQuickSupport
        ? 'chmod 700 "$INSTALL_DIR/vitrine-tray.py"'
        : 'chmod 755 "$INSTALL_DIR/vitrine-tray.py"',
      '',
      '# Enroll with VitrineRMM Control Plane (including full hardware/role telemetry)',
      'HOSTNAME_VAL="$(hostname)"',
      'IP_ADDR="$(hostname -I 2>/dev/null | awk \'{print $1}\')"',
      'MAC_ADDR="$(ip link show 2>/dev/null | awk \'/link\\/ether/ {print $2; exit}\')"',
      'HW_ENROLL_JSON="$(python3 "$INSTALL_DIR/vitrine-companion.py" --print-enroll-hw 2>/dev/null || echo \'{}\')"',
      '',
      'ENROLL_JSON="$(python3 -c \'import json,sys; hw=json.loads(sys.argv[8]) if sys.argv[8].strip().startswith("{") else {}; d={"token":sys.argv[1],"enrollmentToken":sys.argv[1],"tenantId":sys.argv[2],"hostname":sys.argv[3],"osType":"linux","ipAddress":sys.argv[4] or "127.0.0.1","macAddress":sys.argv[5] or "","deviceId":sys.argv[6] or None,"trayThemeMode":sys.argv[7] or "system"}; d.update(hw); print(json.dumps(d))\' "$ENROLLMENT_TOKEN" "$TENANT_ID" "$HOSTNAME_VAL" "$IP_ADDR" "$MAC_ADDR" ' + quoteBashLiteral(vars.targetDeviceId || '') + ' "$TRAY_THEME" "$HW_ENROLL_JSON")"',
      'if ENROLL_RESP="$(http_post_json "$VITRINE_SERVER_URL/api/agent/enroll" "$ENROLL_JSON" 2>/dev/null)"; then',
      '  python3 - "$ENROLL_RESP" "$VITRINE_SERVER_URL" "$TENANT_ID" "$INSTALL_DIR/agent-identity.json" "$CURL_TLS_FLAG" "$SERVICE_NAME" <<\'PYEOF\'',
      'import json, os, sys',
      'resp = json.loads(sys.argv[1])',
      'tok = resp.get("agentToken") or resp.get("agentAuthToken")',
      'if tok:',
      '    out = {',
      '        "deviceId": resp.get("deviceId"),',
      '        "agentToken": tok,',
      '        "agentAuthToken": tok,',
      '        "vitrineServerUrl": sys.argv[2],',
      '        "tenantId": sys.argv[3],',
      '        "insecureTls": sys.argv[5] == "--insecure",',
      '        "serviceSlug": sys.argv[6]',
      '    }',
      '    fd = os.open(sys.argv[4], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)',
      '    with os.fdopen(fd, "w") as f:',
      '        json.dump(out, f)',
      'PYEOF',
      'fi',
      '',
      ...(vars.isQuickSupport
        ? [
            'nohup python3 "$INSTALL_DIR/vitrine-companion.py" >/dev/null 2>&1 &',
            'if [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; then',
            '  nohup python3 "$INSTALL_DIR/vitrine-tray.py" --quicksupport --code "${SESSION_CODE:-$ENROLLMENT_TOKEN}" >/dev/null 2>&1 &',
            'fi'
          ]
        : [
            'if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then',
            '  UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}-companion.service"',
            '  cat > "$UNIT_PATH" <<\'EOF\'',
            '[Unit]',
            'Description=__VITRINE_DESC__',
            'After=network-online.target',
            '',
            '[Service]',
            'Type=simple',
            'ExecStart=/usr/bin/env python3 __VITRINE_EXEC__',
            'Restart=always',
            'RestartSec=10',
            '',
            '[Install]',
            'WantedBy=multi-user.target',
            'EOF',
            '  python3 - "$UNIT_PATH" "$SAFE_UNIT_BRAND Endpoint Telemetry & Task Companion" "${INSTALL_DIR}/vitrine-companion.py" <<\'PYUNIT\'',
            'import sys',
            'p, desc, exec_p = sys.argv[1], sys.argv[2].replace("\\n", " ").replace("\\r", " "), sys.argv[3].replace("\\n", "").replace("\\r", "")',
            'with open(p, "r") as f: data = f.read()',
            'data = data.replace("__VITRINE_DESC__", desc).replace("__VITRINE_EXEC__", exec_p)',
            'with open(p, "w") as f: f.write(data)',
            'PYUNIT',
            '  chmod 644 "$UNIT_PATH"',
            '  systemctl daemon-reload || true',
            '  (systemctl enable "${SERVICE_NAME}-companion.service" && systemctl restart "${SERVICE_NAME}-companion.service") || nohup python3 "$INSTALL_DIR/vitrine-companion.py" >/dev/null 2>&1 &',
            'else',
            '  nohup python3 "$INSTALL_DIR/vitrine-companion.py" >/dev/null 2>&1 &',
            'fi',
            '',
            '# Install XDG Autostart entry & launch theme-aware Desktop Tray if a graphical session is active',
            'if [ -d /etc/xdg/autostart ] || mkdir -p /etc/xdg/autostart 2>/dev/null; then',
            '  cat > "/etc/xdg/autostart/${SERVICE_NAME}-tray.desktop" <<DESKEOF',
            '[Desktop Entry]',
            'Type=Application',
            'Name=${SAFE_UNIT_BRAND} Support Tray',
            'Exec=/usr/bin/env python3 ${INSTALL_DIR}/vitrine-tray.py',
            'Terminal=false',
            'X-GNOME-Autostart-enabled=true',
            'DESKEOF',
            '  chmod 644 "/etc/xdg/autostart/${SERVICE_NAME}-tray.desktop"',
            'fi',
            'pkill -f "${INSTALL_DIR}/vitrine-tray.py" >/dev/null 2>&1 || true',
            'GUI_USER="${SUDO_USER:-}"',
            'if [ -z "$GUI_USER" ] || [ "$GUI_USER" = "root" ]; then',
            '  GUI_USER="$(who | awk \'{print $1; exit}\' || true)"',
            'fi',
            'if [ -n "$GUI_USER" ] && [ "$GUI_USER" != "root" ] && id "$GUI_USER" >/dev/null 2>&1; then',
            '  GUI_UID="$(id -u "$GUI_USER")"',
            '  GUI_RT="/run/user/$GUI_UID"',
            '  if [ -d "$GUI_RT" ]; then',
            '    GUI_DISP=""',
            '    GUI_WL=""',
            '    for s in "$GUI_RT"/wayland-[0-9]*; do [ -S "$s" ] && GUI_WL="$(basename "$s")" && break; done',
            '    if [ -n "${DISPLAY:-}" ]; then GUI_DISP="$DISPLAY"; elif [ -S /tmp/.X11-unix/X0 ]; then GUI_DISP=":0"; elif [ -S /tmp/.X11-unix/X1 ]; then GUI_DISP=":1"; fi',
            '    if [ -n "$GUI_DISP" ] || [ -n "$GUI_WL" ]; then',
            '      GUI_CMD=(env "XDG_RUNTIME_DIR=$GUI_RT")',
            '      [ -n "$GUI_DISP" ] && GUI_CMD+=("DISPLAY=$GUI_DISP")',
            '      [ -n "$GUI_WL" ] && GUI_CMD+=("WAYLAND_DISPLAY=$GUI_WL")',
            '      [ -S "$GUI_RT/bus" ] && GUI_CMD+=("DBUS_SESSION_BUS_ADDRESS=unix:path=$GUI_RT/bus")',
            '      nohup su -s /bin/sh "$GUI_USER" -c "${GUI_CMD[*]} python3 ${INSTALL_DIR}/vitrine-tray.py >/dev/null 2>&1 &" >/dev/null 2>&1 || true',
            '    fi',
            '  fi',
            'fi'
          ]),
      '',
      'printf "[OK] %s Linux deployment completed.\\n" "$BRAND_NAME"'
    ];

    return lines.join('\n');
  }

  private generateMacInstaller(vars: {
    brandName: string;
    primaryColor: string;
    meshServerUrl: string;
    vitrineServerUrl: string;
    meshGroupId: string;
    enrollmentToken: string;
    tenantId: string;
    serviceName: string;
    trayThemeMode: 'system' | 'dark' | 'light';
    isQuickSupport: boolean;
    lapsAutoCreate?: number;
    lapsAccountName?: string;
    allowSelfSignedTls?: boolean;
    skipMeshAgentDownload?: boolean;
    targetDeviceId?: string;
    telemetryIntervalSec?: number;
  }): string {
    const cleanBrand = sanitizeSingleLine(vars.brandName, 'Vitrine RMM', 64);
    const safeCommentBrand = cleanBrand.replace(/#/g, '');
    const curlTlsFlag = vars.allowSelfSignedTls ? '--insecure ' : '';
    const safeService = vars.serviceName.toLowerCase().replace(/[^a-z0-9_-]/g, '') || 'vitrineagent';
    const plistLabel = `com.${safeService}.companion`;
    const sleepSec = Math.max(10, Math.min(3600, Math.round(Number(vars.telemetryIntervalSec || 25))));

    const lines = [
      '#!/usr/bin/env bash',
      '# ==============================================================================',
      `# ${safeCommentBrand} - macOS Universal Agent & Telemetry Companion`,
      `# Mode: ${vars.isQuickSupport ? 'QuickSupport On-Demand (User Space)' : 'Permanent LaunchDaemon'}`,
      '# ==============================================================================',
      'set -euo pipefail',
      '',
      ...(vars.isQuickSupport
        ? ['# QuickSupport runs in standard user space']
        : [
            'if [ "${EUID:-$(id -u)}" -ne 0 ]; then',
            '  echo "[-] Please run as root (sudo ./install-mac.sh)" >&2',
            '  exit 1',
            'fi'
          ]),
      '',
      `BRAND_NAME=${quoteBashLiteral(cleanBrand)}`,
      `MESH_SERVER_URL=${quoteBashLiteral(vars.meshServerUrl)}`,
      `VITRINE_SERVER_URL=${quoteBashLiteral(vars.vitrineServerUrl)}`,
      `MESH_GROUP_ID=${quoteBashLiteral(vars.meshGroupId.replace(/^mesh\/\//, ''))}`,
      `ENROLLMENT_TOKEN=${quoteBashLiteral(vars.enrollmentToken)}`,
      `TENANT_ID=${quoteBashLiteral(vars.tenantId)}`,
      `TRAY_THEME=${quoteBashLiteral(vars.trayThemeMode)}`,
      `SERVICE_SLUG=${quoteBashLiteral(safeService)}`,
      `PLIST_LABEL=${quoteBashLiteral(plistLabel)}`,
      `LAPS_AUTO_CREATE=${quoteBashLiteral(String(vars.lapsAutoCreate ?? 1))}`,
      `LAPS_USER=${quoteBashLiteral(sanitizeIdentifier(vars.lapsAccountName, 'LocalAdmin', 20))}`,
      `CURL_TLS_FLAG=${quoteBashLiteral(vars.allowSelfSignedTls ? '--insecure' : '')}`,
      vars.isQuickSupport
        ? 'INSTALL_DIR="$HOME/Library/Application Support/${SERVICE_SLUG}-quicksupport"'
        : 'INSTALL_DIR="/Library/Application Support/${SERVICE_SLUG}"',
      '',
      'umask 077',
      'mkdir -p "$INSTALL_DIR"',
      'chmod 700 "$INSTALL_DIR"',
      'ARCH="$(uname -m)"',
      'MESH_TYPE=16',
      'if [ "$ARCH" = "arm64" ]; then MESH_TYPE=29; fi',
      '',
      'if [ -n "$MESH_GROUP_ID" ]; then',
      `  curl ${curlTlsFlag}-fsSL "$MESH_SERVER_URL/meshsettings?id=$MESH_GROUP_ID" -o "$INSTALL_DIR/meshagent.msh" || true`,
      'fi',
      '',
      ...(vars.skipMeshAgentDownload
        ? ['# Companion-only deployment over live MeshCentral tunnel (leaving existing MeshAgent untouched)']
        : [
            `if curl ${curlTlsFlag}-fsSL "$MESH_SERVER_URL/meshagents?id=$MESH_TYPE" -o "$INSTALL_DIR/meshagent"; then`,
            '  if [ -s "$INSTALL_DIR/meshagent" ]; then',
            '    chmod 755 "$INSTALL_DIR/meshagent"',
            ...(vars.isQuickSupport
              ? ['    "$INSTALL_DIR/meshagent" -connect >/dev/null 2>&1 &']
              : [
                  '    mkdir -p "$INSTALL_DIR/meshcore"',
                  '    if [ -s "$INSTALL_DIR/meshagent.msh" ]; then cp "$INSTALL_DIR/meshagent.msh" "$INSTALL_DIR/meshcore/meshagent.msh" && chmod 600 "$INSTALL_DIR/meshcore/meshagent.msh"; fi',
                  '    (cd "$INSTALL_DIR" && "$INSTALL_DIR/meshagent" -install --installPath="$INSTALL_DIR/meshcore") || true',
                  '    if [ -s "$INSTALL_DIR/meshagent.msh" ]; then cp "$INSTALL_DIR/meshagent.msh" "$INSTALL_DIR/meshcore/meshagent.msh" && chmod 600 "$INSTALL_DIR/meshcore/meshagent.msh"; fi'
                ]),
            '  fi',
            'else',
            '  echo "[!] MeshCentral binary download skipped or unreachable; proceeding with Vitrine Companion Agent." >&2',
            'fi'
          ]),
      '',
      'if [ "${EUID:-$(id -u)}" -eq 0 ] && [ "$LAPS_AUTO_CREATE" = "1" ]; then',
      '  if ! id "$LAPS_USER" >/dev/null 2>&1; then',
      '    INIT_PASS="$(head -c 24 /dev/urandom | base64 | tr -dc "A-Za-z0-9" | head -c 24)!9vR"',
      '    sysadminctl -addUser "$LAPS_USER" -fullName "$BRAND_NAME Managed Admin" -password "$INIT_PASS" -admin 2>/dev/null || true',
      '  fi',
      'fi',
      '',
      'HOSTNAME_VAL="$(scutil --get LocalHostName 2>/dev/null || hostname)"',
      'OS_VER="macOS $(sw_vers -productVersion 2>/dev/null || uname -r)"',
      'DEF_IFACE="$(route -n get default 2>/dev/null | awk \'/interface:/ {print $2; exit}\')"',
      'IP_ADDR="$(ipconfig getifaddr "${DEF_IFACE:-en0}" 2>/dev/null || echo "")"',
      'MAC_ADDR="$(ifconfig "${DEF_IFACE:-en0}" 2>/dev/null | awk \'/ether / {print $2; exit}\')"',
      'ENROLL_JSON="$(python3 -c \'import json,sys; print(json.dumps({"token":sys.argv[1],"enrollmentToken":sys.argv[1],"tenantId":sys.argv[2],"hostname":sys.argv[3],"osType":"macos","osVersion":sys.argv[4],"ipAddress":sys.argv[5] or "127.0.0.1","macAddress":sys.argv[6] or "","deviceId":sys.argv[7] or None}))\' "$ENROLLMENT_TOKEN" "$TENANT_ID" "$HOSTNAME_VAL" "$OS_VER" "$IP_ADDR" "$MAC_ADDR" ' + quoteBashLiteral(vars.targetDeviceId || '') + ')"',
      `if ENROLL_RESP="$(curl ${curlTlsFlag}-fsSL -X POST "$VITRINE_SERVER_URL/api/agent/enroll" -H "Content-Type: application/json" -d "$ENROLL_JSON" 2>/dev/null)"; then`,
      '  python3 - "$ENROLL_RESP" "$VITRINE_SERVER_URL" "$TENANT_ID" "$INSTALL_DIR/agent-identity.json" "$CURL_TLS_FLAG" "$SERVICE_SLUG" <<\'PYEOF\'',
      'import json, os, sys',
      'r = json.loads(sys.argv[1])',
      'tok = r.get("agentToken") or r.get("agentAuthToken")',
      'if tok:',
      '    fd = os.open(sys.argv[4], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)',
      '    with os.fdopen(fd, "w") as f:',
      '        json.dump({',
      '            "deviceId": r.get("deviceId"),',
      '            "agentToken": tok,',
      '            "agentAuthToken": tok,',
      '            "vitrineServerUrl": sys.argv[2],',
      '            "tenantId": sys.argv[3],',
      '            "insecureTls": sys.argv[5] == "--insecure",',
      '            "serviceSlug": sys.argv[6]',
      '        }, f)',
      'PYEOF',
      'fi',
      '',
      '# Write Python3 macOS Companion Worker (Telemetry, Unified Task Runner, WoL Relay & Self-Uninstall)',
      'cat > "$INSTALL_DIR/vitrine-companion.py" <<\'PYMAC\'',
      '#!/usr/bin/env python3',
      'import getpass, json, os, platform, re, shutil, socket, ssl, subprocess, sys, time, urllib.parse, urllib.request',
      '',
      'BASE_DIR = os.path.dirname(os.path.abspath(__file__))',
      'ID_PATH = os.path.join(BASE_DIR, "agent-identity.json")',
      'PARAM_KEY_RE = re.compile(r"^VITRINE_PARAM_[A-Z0-9_]+$")',
      'SAFE_ACC_RE = re.compile(r"^[a-zA-Z0-9._-]{1,20}$")',
      '',
      'def post_json(url, payload, token, insecure=False):',
      '    data = json.dumps(payload).encode("utf-8")',
      '    req = urllib.request.Request(url, data=data, method="POST")',
      '    req.add_header("Content-Type", "application/json")',
      '    req.add_header("x-vitrine-agent-token", token)',
      '    ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()',
      '    with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:',
      '        return json.loads(resp.read().decode("utf-8"))',
      '',
      'def send_chat(ident, message):',
      '    token = ident.get("agentToken") or ident.get("agentAuthToken")',
      '    srv = (ident.get("vitrineServerUrl") or "").rstrip("/")',
      '    if not token or not srv:',
      '        return',
      '    post_json(f"{srv}/api/agent/chat", {',
      '        "deviceId": ident.get("deviceId"),',
      '        "sender": getpass.getuser(),',
      '        "message": str(message)',
      '    }, token, bool(ident.get("insecureTls")))',
      '',
      'def collect_metrics(device_id=None):',
      '    cpu_pct = 10',
      '    try:',
      '        load1 = os.getloadavg()[0]',
      '        cores = max(1, os.cpu_count() or 1)',
      '        cpu_pct = min(100, max(1, int(round((load1 / cores) * 100))))',
      '    except Exception:',
      '        pass',
      '    ram_pct = 30',
      '    ram_total_gb = 16.0',
      '    ram_used_gb = 4.8',
      '    try:',
      '        total_bytes = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True, timeout=3).strip())',
      '        vm_out = subprocess.check_output(["vm_stat"], text=True, timeout=3)',
      '        page_size = 4096',
      '        m_ps = re.search(r"page size of (\\d+) bytes", vm_out)',
      '        if m_ps:',
      '            page_size = int(m_ps.group(1))',
      '        free_pages = 0',
      '        for key in ("Pages free", "Pages speculative"):',
      '            m_pg = re.search(rf"{key}:\\s+(\\d+)\\.", vm_out)',
      '            if m_pg:',
      '                free_pages += int(m_pg.group(1))',
      '        used_bytes = max(0, total_bytes - (free_pages * page_size))',
      '        if total_bytes > 0:',
      '            ram_total_gb = round(total_bytes / (1024.0 ** 3), 2)',
      '            ram_used_gb = round(used_bytes / (1024.0 ** 3), 2)',
      '            ram_pct = min(100, max(1, int(round((used_bytes / total_bytes) * 100))))',
      '    except Exception:',
      '        pass',
      '    disk_pct = 25',
      '    disk_total_gb = 256.0',
      '    disk_free_gb = 180.0',
      '    try:',
      '        st = os.statvfs("/")',
      '        if st.f_blocks > 0:',
      '            disk_pct = min(100, max(1, int(round(((st.f_blocks - st.f_bavail) / st.f_blocks) * 100))))',
      '            disk_total_gb = round((st.f_blocks * st.f_frsize) / (1024.0 ** 3), 2)',
      '            disk_free_gb = round((st.f_bavail * st.f_frsize) / (1024.0 ** 3), 2)',
      '    except Exception:',
      '        pass',
      '    os_ver = f"macOS {platform.mac_ver()[0] or platform.release()}"',
      '    mac_model = ""; has_battery = False; is_vm = False',
      '    try:',
      '        mac_model = subprocess.check_output(["sysctl", "-n", "hw.model"], text=True, timeout=2).strip()',
      '    except Exception: pass',
      '    try:',
      '        batt_out = subprocess.check_output(["pmset", "-g", "batt"], text=True, timeout=2)',
      '        has_battery = "InternalBattery" in batt_out',
      '    except Exception: pass',
      '    try:',
      '        vmm = subprocess.check_output(["sysctl", "-n", "kern.hv_vmm_present"], text=True, timeout=2).strip()',
      '        if vmm == "1": is_vm = True',
      '    except Exception: pass',
      '    if "virtualmac" in mac_model.lower() or "vmware" in mac_model.lower() or "parallels" in mac_model.lower(): is_vm = True',
      '    hw_sys = {"manufacturer": "Apple Inc.", "model": mac_model, "hasBattery": has_battery, "isVirtualMachine": is_vm, "osProductType": "server" if mac_model.lower().startswith("xserve") else "workstation"}',
      '    fv_active = False',
      '    try:',
      '        fv = subprocess.run(["fdesetup", "isactive"], capture_output=True, text=True, timeout=4)',
      '        fv_active = fv.returncode == 0 or "true" in (fv.stdout or "").lower()',
      '    except Exception:',
      '        pass',
      '    edr_status = "Healthy" if os.path.exists("/Library/Apple/System/Library/CoreServices/XProtect.bundle") else "Unmonitored"',
      '    reboot_req = bool(os.path.exists("/Library/Updates/ProductMetadata.plist") or os.path.exists("/var/db/.AppleUpgrade"))',
      '    uptime_sec = 0',
      '    try:',
      '        bt = subprocess.check_output(["sysctl", "-n", "kern.boottime"], text=True, timeout=3)',
      '        m_bt = re.search(r"sec\\s*=\\s*(\\d+)", bt)',
      '        if m_bt:',
      '            uptime_sec = max(0, int(time.time() - int(m_bt.group(1))))',
      '    except Exception:',
      '        pass',
      '    net_rx_mbps = 0.0',
      '    net_tx_mbps = 0.0',
      '    try:',
      '        def _read_mac_net():',
      '            rx = tx = 0',
      '            out_ns = subprocess.check_output(["netstat", "-ib"], text=True, timeout=4)',
      '            seen = set()',
      '            for ln in out_ns.splitlines()[1:]:',
      '                cols = ln.split()',
      '                if len(cols) >= 10 and not cols[0].startswith("lo") and cols[2].startswith("<Link#"):',
      '                    if cols[0] in seen: continue',
      '                    seen.add(cols[0])',
      '                    try:',
      '                        rx += int(cols[6]); tx += int(cols[9])',
      '                    except Exception:',
      '                        pass',
      '            return rx, tx',
      '        r1, t1 = _read_mac_net()',
      '        time.sleep(1.0)',
      '        r2, t2 = _read_mac_net()',
      '        net_rx_mbps = round(max(0, r2 - r1) * 8 / 1000000.0, 3)',
      '        net_tx_mbps = round(max(0, t2 - t1) * 8 / 1000000.0, 3)',
      '    except Exception:',
      '        pass',
      '    arp_neighbors = []',
      '    try:',
      '        arp_out = subprocess.check_output(["arp", "-an"], text=True, timeout=4)',
      '        for ln in arp_out.splitlines():',
      '            m = re.search(r"\\((\\d+\\.\\d+\\.\\d+\\.\\d+)\\)\\s+at\\s+([0-9a-fA-F:]{11,17})", ln)',
      '            if m and m.group(2).lower() != "ff:ff:ff:ff:ff:ff":',
      '                arp_neighbors.append({"ip": m.group(1), "mac": m.group(2).lower()})',
      '    except Exception:',
      '        pass',
      '    return {',
      '        "deviceId": device_id,',
      '        "hostname": socket.gethostname(),',
      '        "osType": "macos",',
      '        "osVersion": os_ver,',
      '        "cpuUsage": cpu_pct,',
      '        "ramUsage": ram_pct,',
      '        "ramUsedGb": ram_used_gb,',
      '        "ramTotalGb": ram_total_gb,',
      '        "diskUsage": disk_pct,',
      '        "diskFreeGb": disk_free_gb,',
      '        "diskTotalGb": disk_total_gb,',
      '        "netRxMbps": net_rx_mbps,',
      '        "netTxMbps": net_tx_mbps,',
      '        "uptimeSeconds": uptime_sec,',
      '        "edrStatus": edr_status,',
      '        "avStatus": edr_status,',
      '        "bitlockerEncrypted": fv_active,',
      '        "bitlockerStatus": "Encrypted" if fv_active else "Unencrypted",',
      '        "rebootPending": reboot_req,',
      '        "rebootRequired": reboot_req,',
      '        "hardwareDetails": {"system": hw_sys},',
      '        "arpNeighbors": arp_neighbors[:64]',
      '    }',
      '',
      'def execute_task(t, server_url, token, insecure, ident):',
      '    tid = str(t.get("id") or "")',
      '    uri_tid = urllib.parse.quote(tid, safe="")',
      '    ttype = t.get("type") or t.get("task_type") or ""',
      '    try:',
      '        payload = t.get("payload") if isinstance(t.get("payload"), dict) else json.loads(t.get("payload_json") or "{}")',
      '    except Exception:',
      '        payload = {}',
      '    if not isinstance(payload, dict):',
      '        payload = {}',
      '    exit_code = 0',
      '    stdout_str = ""',
      '    stderr_str = ""',
      '    if ttype == "self_uninstall":',
      '        try:',
      '            post_json(f"{server_url}/api/agent/tasks/{uri_tid}/result", {',
      '                "deviceId": ident.get("deviceId"),',
      '                "exitCode": 0,',
      '                "stdout": "Self-uninstall initiated",',
      '                "stderr": ""',
      '            }, token, insecure)',
      '        except Exception:',
      '            pass',
      '        acc = str(payload.get("lapsAccountName") or "")',
      '        act = str(payload.get("lapsAction") or "")',
      '        if SAFE_ACC_RE.match(acc):',
      '            if act == "remove_account":',
      '                subprocess.run(["sysadminctl", "-deleteUser", acc], capture_output=True)',
      '            elif act == "disable_account":',
      '                subprocess.run(["pwpolicy", "-u", acc, "-disableuser"], capture_output=True)',
      '        slug = re.sub(r"[^a-z0-9_-]", "", str(payload.get("serviceName") or ident.get("serviceSlug") or "vitrineagent").lower()) or "vitrineagent"',
      '        plist_path = f"/Library/LaunchDaemons/com.{slug}.companion.plist"',
      '        if not payload.get("preserveMeshAgent"):',
      '            mesh_bin = os.path.join(BASE_DIR, "meshagent")',
      '            if os.path.exists(mesh_bin):',
      '                subprocess.run([mesh_bin, "-uninstall"], capture_output=True)',
      '        subprocess.run(["launchctl", "bootout", "system", plist_path], capture_output=True)',
      '        try:',
      '            if os.path.exists(plist_path):',
      '                os.remove(plist_path)',
      '            shutil.rmtree(BASE_DIR, ignore_errors=True)',
      '        except Exception:',
      '            pass',
      '        sys.exit(0)',
      '    try:',
      '        if ttype in ("script", "run_script", "patch_scan", "patch_install", "software_deploy", "backup_job"):',
      '            code = payload.get("code") or payload.get("command") or "echo ok"',
      '            env = os.environ.copy()',
      '            for k, v in (payload.get("env") or {}).items():',
      '                if isinstance(k, str) and PARAM_KEY_RE.match(k):',
      '                    env[k] = str(v)',
      '            timeout_s = max(5, min(3600, int(payload.get("timeoutSec") or 120)))',
      '            if payload.get("shell") == "python" or payload.get("language") == "python":',
      '                proc = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=timeout_s)',
      '            else:',
      '                shell_bin = "/bin/zsh" if os.path.exists("/bin/zsh") else "/bin/bash"',
      '                proc = subprocess.run([shell_bin, "-c", code], env=env, capture_output=True, text=True, timeout=timeout_s)',
      '            exit_code = proc.returncode',
      '            stdout_str = (proc.stdout or "")[-32000:]',
      '            stderr_str = (proc.stderr or "")[-16000:]',
      '        elif ttype == "wol_relay":',
      '            mac_hex = (payload.get("mac") or "").replace(":", "").replace("-", "").strip()',
      '            if len(mac_hex) == 12:',
      '                pkt = bytes.fromhex("FF" * 6 + mac_hex * 16)',
      '                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)',
      '                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)',
      '                s.sendto(pkt, (payload.get("broadcastIp") or "255.255.255.255", int(payload.get("port") or 9)))',
      '                s.close()',
      '                stdout_str = f"Magic packet relayed to {mac_hex}"',
      '            else:',
      '                exit_code = 1',
      '                stderr_str = "Invalid MAC address"',
      '        elif ttype in ("tray_notify", "reboot_prompt"):',
      '            title = str(payload.get("title") or "IT Support")',
      '            msg = str(payload.get("message") or "")',
      '            subprocess.run(["osascript", "-e", "on run argv", "-e", "display notification (item 1 of argv) with title (item 2 of argv)", "-e", "end run", msg, title], capture_output=True, timeout=5)',
      '            stdout_str = "Notification delivered"',
      '    except Exception as exc:',
      '        exit_code = 1',
      '        stderr_str = str(exc)',
      '    try:',
      '        post_json(f"{server_url}/api/agent/tasks/{uri_tid}/result", {',
      '            "deviceId": ident.get("deviceId"),',
      '            "exitCode": exit_code,',
      '            "stdout": stdout_str,',
      '            "stderr": stderr_str,',
      '            "backupJobId": payload.get("backupJobId")',
      '        }, token, insecure)',
      '    except Exception:',
      '        pass',
      '',
      'def main():',
      '    if len(sys.argv) >= 3 and sys.argv[1] == "--chat":',
      '        if os.path.exists(ID_PATH):',
      '            with open(ID_PATH, "r") as f:',
      '                send_chat(json.load(f), sys.argv[2])',
      '        return',
      '    once = "--once" in sys.argv',
      '    while True:',
      '        try:',
      '            if os.path.exists(ID_PATH):',
      '                with open(ID_PATH, "r") as f:',
      '                    ident = json.load(f)',
      '                token = ident.get("agentToken") or ident.get("agentAuthToken")',
      '                srv = (ident.get("vitrineServerUrl") or "").rstrip("/")',
      '                insec = bool(ident.get("insecureTls"))',
      '                if token and srv:',
      '                    resp = post_json(f"{srv}/api/agent/checkin", collect_metrics(ident.get("deviceId")), token, insec)',
      '                    for task in (resp.get("tasks") or []):',
      '                        execute_task(task, srv, token, insec, ident)',
      '        except Exception:',
      '            pass',
      '        if once:',
      '            break',
      `        time.sleep(${sleepSec})`,
      '',
      'if __name__ == "__main__":',
      '    main()',
      'PYMAC',
      'chmod 700 "$INSTALL_DIR/vitrine-companion.py"',
      '',
      ...(vars.isQuickSupport
        ? ['nohup python3 "$INSTALL_DIR/vitrine-companion.py" >/dev/null 2>&1 &']
        : [
            `PLIST_PATH="/Library/LaunchDaemons/com.${safeService}.companion.plist"`,
            'cat > "$PLIST_PATH" <<EOF',
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
            '<plist version="1.0">',
            '<dict>',
            '  <key>Label</key>',
            `  <string>com.${safeService}.companion</string>`,
            '  <key>ProgramArguments</key>',
            '  <array>',
            '    <string>/usr/bin/python3</string>',
            '    <string>${INSTALL_DIR}/vitrine-companion.py</string>',
            '  </array>',
            '  <key>RunAtLoad</key>',
            '  <true/>',
            '  <key>KeepAlive</key>',
            '  <true/>',
            '  <key>StandardOutPath</key>',
            `  <string>/var/log/${safeService}-companion.log</string>`,
            '  <key>StandardErrorPath</key>',
            `  <string>/var/log/${safeService}-companion.err.log</string>`,
            '</dict>',
            '</plist>',
            'EOF',
            'chmod 644 "$PLIST_PATH"',
            'chown root:wheel "$PLIST_PATH" 2>/dev/null || true',
            'launchctl bootout system "$PLIST_PATH" 2>/dev/null || true',
            'launchctl bootstrap system "$PLIST_PATH" 2>/dev/null || launchctl load -w "$PLIST_PATH" 2>/dev/null || nohup python3 "$INSTALL_DIR/vitrine-companion.py" >/dev/null 2>&1 &'
          ]),
      '',
      'printf "[OK] %s macOS deployment completed.\\n" "$BRAND_NAME"'
    ];

    return lines.join('\n');
  }
}

export const installerGenerator = new InstallerGeneratorService();

export async function getOrBuildSignedMeshBinary(
  arch: 'x64' | 'arm64' | 'x86' = 'x64',
  allowSelfSignedTls = false
) {
  return installerGenerator.getOrBuildSignedMeshBinary(arch, allowSelfSignedTls);
}
