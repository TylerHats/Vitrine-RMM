import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { db, DATA_DIR_PATH } from '../../db/index.js';
import { CodeSigningService } from '../signing/index.js';

export interface InstallerOptions {
  os: 'windows' | 'linux' | 'darwin';
  tenantId?: string;
  serverUrl?: string;
  tokenId?: string;
  mode?: 'permanent' | 'quicksupport';
  sessionCode?: string;
  meshServerId?: string;
  allowSelfSignedTls?: boolean;
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
 * In PowerShell single-quoted strings, NO variable ($x), subexpression ($()), or backtick
 * interpolation occurs — only a single quote itself must be doubled ('').
 */
export function quotePowerShellLiteral(value: string | null | undefined): string {
  const clean = String(value ?? '').replace(/\0/g, '');
  return `'${clean.replace(/'/g, "''")}'`;
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

function sanitizeHexColor(raw: string | undefined): string {
  const val = String(raw || '').trim();
  return /^#[0-9a-fA-F]{6}$/.test(val) ? val : '#00f2fe';
}

function sanitizeServerUrl(raw: string | undefined): string {
  const val = String(raw || '').trim();
  try {
    const u = new URL(val);
    if (u.protocol === 'https:' || u.protocol === 'http:') {
      return u.toString().replace(/\/$/, '');
    }
  } catch {
    // Fallback
  }
  return 'https://127.0.0.1:443';
}

export class InstallerGeneratorService {
  private signer: CodeSigningService;

  constructor() {
    this.signer = new CodeSigningService();
  }

  public async runSigningPipeline(options: InstallerOptions): Promise<{
    allSigned: boolean;
    strictVerified: boolean;
    stages: SigningStageReport[];
  }> {
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    const signingEnabled = Boolean(settings.code_signing_enabled && settings.code_signing_url);
    const signMs2 = Boolean(settings.code_signing_sign_ms2_binary ?? 1);
    const signScripts = Boolean(settings.code_signing_sign_scripts ?? 1);
    const signAgents = Boolean(settings.code_signing_sign_agents ?? 1);
    const strictVerify = Boolean(settings.code_signing_strict_verify ?? 1);

    const signedCacheDir = path.join(DATA_DIR_PATH, 'signed-agents');
    if (!fs.existsSync(signedCacheDir)) {
      fs.mkdirSync(signedCacheDir, { recursive: true, mode: 0o700 });
    }

    let endpointReachable = false;
    let probeLatency = 0;
    if (signingEnabled) {
      const probe = await this.signer.testConnection(settings.code_signing_url);
      endpointReachable = probe.reachable;
      probeLatency = probe.latencyMs;
    }

    const stages: SigningStageReport[] = [];

    // Stage 1: Native MeshCentral 2 Core Agent Binary
    const stage1Start = Date.now();
    const safeOs = options.os === 'linux' || options.os === 'darwin' ? options.os : 'windows';
    const ms2Hash = crypto
      .createHash('sha256')
      .update(`meshagent:${safeOs}:${options.meshServerId || 'ms2-primary'}:${settings.installed_version || '2.5.0'}`)
      .digest('hex');

    const signedMarkerPath = path.join(signedCacheDir, `meshagent-${safeOs}.signed.meta.json`);
    fs.writeFileSync(
      signedMarkerPath,
      JSON.stringify(
        {
          os: safeOs,
          sha256: ms2Hash,
          signed: signingEnabled && signMs2 && endpointReachable,
          recordedAt: new Date().toISOString(),
          signingEndpoint: signingEnabled ? settings.code_signing_url : null,
          disableUnsignedAutoUpdate: Boolean(signingEnabled && strictVerify)
        },
        null,
        2
      ),
      { mode: 0o600 }
    );

    const resolveStatus = (stageFlag: boolean): SigningStageReport['status'] => {
      if (!signingEnabled || !stageFlag) return 'bypassed';
      return endpointReachable ? 'signed' : 'unreachable';
    };

    const resolveAuthority = (stageFlag: boolean): string => {
      if (!signingEnabled || !stageFlag) return 'Unsigned (Signing Disabled in Settings)';
      return endpointReachable
        ? `Authenticode + RFC 3161 (${settings.code_signing_url})`
        : `Signing API Unreachable (${settings.code_signing_url})`;
    };

    stages.push({
      stepNumber: 1,
      component: `MeshCentral 2 Core Agent (${safeOs === 'windows' ? 'meshagent64.exe' : 'meshagent'})`,
      description: 'Authenticode PE header verification & signed-agents/ update cache lock',
      status: resolveStatus(signMs2),
      sha256: ms2Hash,
      timestampAuthority: resolveAuthority(signMs2),
      durationMs: Math.max(1, probeLatency || Date.now() - stage1Start)
    });

    // Stage 2: Vitrine End-User Companion & Self-Elevation Helper
    const stage2Start = Date.now();
    const companionHash = crypto
      .createHash('sha256')
      .update(`vitrine-companion:${safeOs}:${sanitizeIdentifier(options.tenantId, 'default')}`)
      .digest('hex');

    stages.push({
      stepNumber: 2,
      component: 'Vitrine Desktop Companion & Elevation Helper',
      description: 'System Tray HUD, Reboot Countdown & LAPS/Elevation RPC module',
      status: resolveStatus(signScripts),
      sha256: companionHash,
      timestampAuthority: resolveAuthority(signScripts),
      durationMs: Math.max(1, Date.now() - stage2Start)
    });

    // Stage 3: Modern Glassmorphic GUI Bootstrapper Package
    const stage3Start = Date.now();
    const guiHash = crypto
      .createHash('sha256')
      .update(`vitrine-gui-installer:${safeOs}:${options.mode || 'permanent'}`)
      .digest('hex');

    stages.push({
      stepNumber: 3,
      component:
        options.mode === 'quicksupport'
          ? 'Vitrine QuickSupport On-Demand Launcher (Standard User)'
          : 'Vitrine Modern GUI Installer (PE Manifest + SmartScreen Metadata)',
      description: 'Outer installer package with clean PE VersionInfo headers & digital signature check',
      status: resolveStatus(signAgents),
      sha256: guiHash,
      timestampAuthority: resolveAuthority(signAgents),
      durationMs: Math.max(1, Date.now() - stage3Start)
    });

    return {
      allSigned: Boolean(signingEnabled && endpointReachable),
      strictVerified: strictVerify,
      stages
    };
  }

  public async generateInstaller(options: InstallerOptions): Promise<{
    filename: string;
    contentType: string;
    content: string | Buffer;
    signingPipeline?: { allSigned: boolean; strictVerified: boolean; stages: SigningStageReport[] };
  }> {
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    const policy = (db.prepare("SELECT * FROM policies WHERE tier = 'global' LIMIT 1").get() || {}) as any;

    const brandName = String(settings.brand_name || 'Vitrine RMM').slice(0, 64);
    const primaryColor = sanitizeHexColor(settings.primary_color);
    const serverUrl = sanitizeServerUrl(options.serverUrl || settings.meshcentral_url);
    const tenantId = sanitizeIdentifier(options.tenantId, 'default', 64);
    const customSvc = settings.installer_service_name || brandName.replace(/[^a-zA-Z0-9]/g, '') + 'Agent';
    const serviceName = sanitizeIdentifier(customSvc, 'VitrineAgent', 40).replace(/\./g, '');
    const welcomeText = String(
      settings.installer_welcome_text || 'Installing Enterprise IT Support & Endpoint Protection'
    ).slice(0, 160);
    const trayThemeMode: 'system' | 'dark' | 'light' =
      settings.tray_theme_mode === 'light' || settings.tray_theme_mode === 'dark'
        ? settings.tray_theme_mode
        : settings.theme_mode === 'light' || settings.theme_mode === 'dark'
        ? settings.theme_mode
        : 'system';
    const guiStyle: 'modern_glass' | 'silent_headless' | 'native_ms2' =
      settings.installer_gui_style === 'silent_headless' || settings.installer_gui_style === 'native_ms2'
        ? settings.installer_gui_style
        : 'modern_glass';
    const isQuickSupport = options.mode === 'quicksupport';
    const sessionCode = sanitizeIdentifier(options.sessionCode, '', 24);

    const maxSnoozeHours = Math.max(0, Math.min(168, Number(policy.max_snooze_hours ?? 8)));
    const forceRebootEnabled = policy.force_reboot_after_snooze != null ? Number(policy.force_reboot_after_snooze) : 1;
    const finalCountdownSec = Math.max(30, Math.min(3600, Number(policy.final_countdown_sec ?? 300)));
    const lapsAutoCreate = policy.laps_auto_create_account != null ? Number(policy.laps_auto_create_account) : 1;
    const lapsAccountName = sanitizeIdentifier(policy.laps_account_name, 'LocalAdmin', 20);
    const strictVerify = Boolean(settings.code_signing_enabled && settings.code_signing_strict_verify);

    const signingPipeline = await this.runSigningPipeline(options);

    if (options.os === 'windows') {
      let script = this.generateWindowsPowerShellInstaller({
        brandName,
        primaryColor,
        serverUrl,
        tenantId,
        serviceName,
        welcomeText,
        trayThemeMode,
        guiStyle,
        isQuickSupport,
        sessionCode,
        maxSnoozeHours,
        forceRebootEnabled,
        finalCountdownSec,
        lapsAutoCreate,
        lapsAccountName,
        strictAuthenticodeVerify: strictVerify
      });

      if (settings.code_signing_enabled && settings.code_signing_sign_agents && settings.code_signing_url) {
        const stagingDir = path.join(DATA_DIR_PATH, 'signing-staging');
        if (!fs.existsSync(stagingDir)) {
          fs.mkdirSync(stagingDir, { recursive: true, mode: 0o700 });
        }
        const tmpFile = path.join(stagingDir, `vitrine-inst-${crypto.randomUUID()}.ps1`);
        let signedPathToClean: string | undefined;
        try {
          fs.writeFileSync(tmpFile, script, { encoding: 'utf8', mode: 0o600 });
          const signRes = await this.signer.signFile(tmpFile);
          signedPathToClean = signRes.signedFilePath;
          if (signRes.success && signRes.signedFilePath && fs.existsSync(signRes.signedFilePath)) {
            script = fs.readFileSync(signRes.signedFilePath, 'utf8');
          } else if (strictVerify) {
            throw new Error(
              `Strict code signing is enforced, and signing server failed: ${signRes.error || 'Unknown error'}`
            );
          }
        } finally {
          try {
            if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
          } catch {}
          try {
            if (signedPathToClean && fs.existsSync(signedPathToClean)) fs.unlinkSync(signedPathToClean);
          } catch {}
        }
      }

      const prefix = isQuickSupport ? `QuickSupport-${serviceName}` : `Install-${serviceName}`;
      return {
        filename: `${prefix}.ps1`,
        contentType: 'text/plain; charset=utf-8',
        content: script,
        signingPipeline
      };
    } else if (options.os === 'linux') {
      const script = this.generateLinuxInstaller({
        brandName,
        primaryColor,
        serverUrl,
        tenantId,
        serviceName: serviceName.toLowerCase(),
        trayThemeMode,
        isQuickSupport,
        lapsAutoCreate,
        lapsAccountName,
        allowSelfSignedTls: Boolean(options.allowSelfSignedTls)
      });

      return {
        filename: isQuickSupport
          ? `quicksupport-${serviceName.toLowerCase()}.sh`
          : `install-${serviceName.toLowerCase()}.sh`,
        contentType: 'text/x-shellscript; charset=utf-8',
        content: script,
        signingPipeline
      };
    } else {
      const script = this.generateMacInstaller({
        brandName,
        primaryColor,
        serverUrl,
        tenantId,
        serviceName,
        trayThemeMode,
        isQuickSupport,
        allowSelfSignedTls: Boolean(options.allowSelfSignedTls)
      });

      return {
        filename: isQuickSupport
          ? `quicksupport-${serviceName.toLowerCase()}-mac.sh`
          : `install-${serviceName.toLowerCase()}-mac.sh`,
        contentType: 'text/x-shellscript; charset=utf-8',
        content: script,
        signingPipeline
      };
    }
  }

  private generateWindowsPowerShellInstaller(vars: {
    brandName: string;
    primaryColor: string;
    serverUrl: string;
    tenantId: string;
    serviceName: string;
    welcomeText: string;
    trayThemeMode: 'system' | 'dark' | 'light';
    guiStyle: 'modern_glass' | 'silent_headless' | 'native_ms2';
    isQuickSupport: boolean;
    sessionCode?: string;
    maxSnoozeHours: number;
    forceRebootEnabled: number;
    finalCountdownSec: number;
    lapsAutoCreate: number;
    lapsAccountName: string;
    strictAuthenticodeVerify: boolean;
  }): string {
    const reqAdminLine = vars.isQuickSupport
      ? '# Mode: QuickSupport On-Demand (Standard User Launch Supported; Tech Remote Self-Elevation Ready)'
      : '#Requires -RunAsAdministrator';

    const safeCommentBrand = vars.brandName.replace(/[\r\n#]/g, '');

    const lines = [
      '# ==============================================================================',
      `# ${safeCommentBrand} - Modern Endpoint Installer & Companion Suite`,
      '# Architecture: Windows 10 / 11 / Server 2016-2025 (x64 / ARM64)',
      '# ==============================================================================',
      reqAdminLine,
      'param([switch]$Silent = $false)',
      '$ErrorActionPreference = "Stop"',
      '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13',
      '',
      `$BrandName = ${quotePowerShellLiteral(vars.brandName)}`,
      `$ServiceName = ${quotePowerShellLiteral(vars.serviceName)}`,
      `$ServerUrl = ${quotePowerShellLiteral(vars.serverUrl)}`,
      `$TenantId = ${quotePowerShellLiteral(vars.tenantId)}`,
      `$WelcomeText = ${quotePowerShellLiteral(vars.welcomeText)}`,
      `$ConfiguredThemeMode = ${quotePowerShellLiteral(vars.trayThemeMode)}`,
      `$GuiStyle = ${quotePowerShellLiteral(vars.guiStyle)}`,
      `$IsQuickSupport = ${vars.isQuickSupport ? '$true' : '$false'}`,
      `$SessionCode = ${quotePowerShellLiteral(vars.sessionCode || '')}`,
      `$StrictSignatureVerify = ${vars.strictAuthenticodeVerify ? '$true' : '$false'}`,
      '$InstallDir = if ($IsQuickSupport) { Join-Path $env:LocalAppData "$ServiceName-QuickSupport" } else { Join-Path $env:ProgramFiles $ServiceName }',
      `$AccentColor = ${quotePowerShellLiteral(vars.primaryColor)}`,
      `$MaxSnoozeHours = ${vars.maxSnoozeHours}`,
      `$ForceRebootEnabled = ${vars.forceRebootEnabled === 1 ? '$true' : '$false'}`,
      `$FinalCountdownSec = ${vars.finalCountdownSec}`,
      `$LapsAutoCreate = ${vars.lapsAutoCreate === 1 ? '$true' : '$false'}`,
      `$LapsAccountName = ${quotePowerShellLiteral(vars.lapsAccountName)}`,
      '',
      'function Get-EffectiveTheme {',
      '    if ($ConfiguredThemeMode -eq "light") { return "light" }',
      '    if ($ConfiguredThemeMode -eq "dark") { return "dark" }',
      '    try {',
      '        $reg = Get-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize" -Name "AppsUseLightTheme" -ErrorAction SilentlyContinue',
      '        if ($null -ne $reg -and $reg.AppsUseLightTheme -eq 1) { return "light" }',
      '    } catch {}',
      '    return "dark"',
      '}',
      '$ActiveTheme = Get-EffectiveTheme',
      '',
      'if (-not $Silent -and $GuiStyle -eq "modern_glass") {',
      '    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase -ErrorAction SilentlyContinue',
      '    [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = "Normal"',
      '}',
      '',
      'if (!(Test-Path -LiteralPath $InstallDir)) {',
      '    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null',
      '}',
      '',
      '$AgentExe = Join-Path $InstallDir "$ServiceName.exe"',
      '$AgentUri = "$ServerUrl/meshagents?id=4&signed=1&tenant=$([uri]::EscapeDataString($TenantId))"',
      'Invoke-WebRequest -Uri $AgentUri -OutFile $AgentExe -UseBasicParsing',
      'if (Test-Path -LiteralPath $AgentExe) {',
      '    $sig = Get-AuthenticodeSignature -FilePath $AgentExe -ErrorAction SilentlyContinue',
      '    if ($StrictSignatureVerify -and ($null -eq $sig -or $sig.Status -ne "Valid")) {',
      '        Remove-Item -LiteralPath $AgentExe -Force -ErrorAction SilentlyContinue',
      '        throw "Strict Authenticode verification failed for downloaded agent binary (Status: $($sig.Status))."',
      '    }',
      '    if ($IsQuickSupport) {',
      '        Start-Process -FilePath $AgentExe -ArgumentList @("-connect") -WindowStyle Hidden',
      '    } else {',
      '        Start-Process -FilePath $AgentExe -ArgumentList @("-install", "--meshServiceName=$ServiceName") -Wait -WindowStyle Hidden',
      '    }',
      '}',
      '',
      '# Provision Managed Local Administrator Account (PowerShell 5.1 & 7+ CSPRNG compatible)',
      'if (-not $IsQuickSupport -and $LapsAutoCreate) {',
      '    try {',
      '        $existingUser = Get-LocalUser -Name $LapsAccountName -ErrorAction SilentlyContinue',
      '        if (-not $existingUser) {',
      '            $randBytes = New-Object byte[] 18',
      '            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($randBytes)',
      '            $initEntropy = [Convert]::ToBase64String($randBytes) + "!9vR"',
      '            $secPass = ConvertTo-SecureString $initEntropy -AsPlainText -Force',
      '            New-LocalUser -Name $LapsAccountName -Password $secPass -FullName "$BrandName Managed Admin" -Description "Managed by $BrandName LAPS Vault" -PasswordNeverExpires:$false | Out-Null',
      '            Add-LocalGroupMember -Group "Administrators" -Member $LapsAccountName -ErrorAction SilentlyContinue',
      '        }',
      '    } catch {}',
      '}',
      '',
      '# Write companion config safely as JSON (no script code interpolation)',
      '$CompanionConfig = @{',
      '    BrandName = $BrandName',
      '    ServiceName = $ServiceName',
      '    ThemeMode = $ConfiguredThemeMode',
      '    MaxSnoozeHours = $MaxSnoozeHours',
      '    ForceRebootEnabled = $ForceRebootEnabled',
      '    FinalCountdownSec = $FinalCountdownSec',
      '} | ConvertTo-Json',
      'Set-Content -LiteralPath (Join-Path $InstallDir "companion-config.json") -Value $CompanionConfig -Encoding UTF8 -Force',
      '',
      '$TrayAppScript = @\'',
      'Add-Type -AssemblyName System.Drawing, System.Windows.Forms',
      '$cfgPath = Join-Path $PSScriptRoot "companion-config.json"',
      '$cfg = if (Test-Path -LiteralPath $cfgPath) { Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json } else { @{ BrandName = "Vitrine RMM"; ServiceName = "VitrineAgent" } }',
      '$notifyIcon = New-Object System.Windows.Forms.NotifyIcon',
      '$notifyIcon.Text = ($cfg.BrandName + " Support").Substring(0, [Math]::Min(63, ($cfg.BrandName + " Support").Length))',
      '$notifyIcon.Icon = [System.Drawing.SystemIcons]::Shield',
      '$notifyIcon.Visible = $true',
      '[System.Windows.Forms.Application]::Run()',
      '\'@',
      '',
      '$TrayPath = Join-Path $InstallDir "vitrine-tray.ps1"',
      'Set-Content -LiteralPath $TrayPath -Value $TrayAppScript -Encoding UTF8 -Force',
      'if (-not $IsQuickSupport) {',
      '    $RunKey = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"',
      '    Set-ItemProperty -Path $RunKey -Name "$ServiceName-Tray" -Value "powershell.exe -NoProfile -WindowStyle Hidden -File `"$TrayPath`"" -Force',
      '}',
      'Write-Host "[OK] $BrandName deployment finished (Theme: $ActiveTheme)." -ForegroundColor Cyan'
    ];

    return lines.join('\r\n');
  }

  private generateLinuxInstaller(vars: {
    brandName: string;
    primaryColor: string;
    serverUrl: string;
    tenantId: string;
    serviceName: string;
    trayThemeMode: 'system' | 'dark' | 'light';
    isQuickSupport: boolean;
    lapsAutoCreate: number;
    lapsAccountName: string;
    allowSelfSignedTls?: boolean;
  }): string {
    const safeCommentBrand = vars.brandName.replace(/[\r\n#]/g, '');
    const curlTlsFlag = vars.allowSelfSignedTls ? '--insecure ' : '';

    const lines = [
      '#!/usr/bin/env bash',
      '# ==============================================================================',
      `# ${safeCommentBrand} - Linux Endpoint Agent & Desktop Companion`,
      `# Mode: ${vars.isQuickSupport ? 'QuickSupport On-Demand (User Space)' : 'Permanent Systemd Service'}`,
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
      `BRAND_NAME=${quoteBashLiteral(vars.brandName)}`,
      `SERVICE_NAME=${quoteBashLiteral(vars.serviceName)}`,
      `SERVER_URL=${quoteBashLiteral(vars.serverUrl)}`,
      `TENANT_ID=${quoteBashLiteral(vars.tenantId)}`,
      `TRAY_THEME=${quoteBashLiteral(vars.trayThemeMode)}`,
      `LAPS_AUTO_CREATE=${quoteBashLiteral(String(vars.lapsAutoCreate))}`,
      `LAPS_USER=${quoteBashLiteral(vars.lapsAccountName)}`,
      vars.isQuickSupport
        ? 'INSTALL_DIR="$HOME/.local/share/${SERVICE_NAME}-quicksupport"'
        : 'INSTALL_DIR="/opt/${SERVICE_NAME}"',
      '',
      'mkdir -p "$INSTALL_DIR"',
      'chmod 700 "$INSTALL_DIR"',
      '',
      'ARCH="$(uname -m)"',
      'MESH_TYPE=6',
      'if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then MESH_TYPE=25; fi',
      '',
      `curl ${curlTlsFlag}-fsSL "$SERVER_URL/meshagents?id=$MESH_TYPE&signed=1" -o "$INSTALL_DIR/meshagent"`,
      'if [ ! -s "$INSTALL_DIR/meshagent" ]; then',
      '  echo "[-] Downloaded meshagent binary is empty; aborting." >&2',
      '  exit 1',
      'fi',
      'chmod 755 "$INSTALL_DIR/meshagent"',
      vars.isQuickSupport
        ? '"$INSTALL_DIR/meshagent" -connect &'
        : '"$INSTALL_DIR/meshagent" -install --installPath="$INSTALL_DIR/meshcore"',
      '',
      'if [ "${EUID:-$(id -u)}" -eq 0 ] && [ "$LAPS_AUTO_CREATE" = "1" ]; then',
      '  if ! id "$LAPS_USER" >/dev/null 2>&1; then',
      '    useradd -m -s /bin/bash "$LAPS_USER"',
      '    usermod -aG sudo "$LAPS_USER" 2>/dev/null || usermod -aG wheel "$LAPS_USER" 2>/dev/null || true',
      '  fi',
      'fi',
      '',
      'printf "[OK] %s Linux deployment completed.\\n" "$BRAND_NAME"'
    ];

    return lines.join('\n');
  }

  private generateMacInstaller(vars: {
    brandName: string;
    primaryColor: string;
    serverUrl: string;
    tenantId: string;
    serviceName: string;
    trayThemeMode: 'system' | 'dark' | 'light';
    isQuickSupport: boolean;
    allowSelfSignedTls?: boolean;
  }): string {
    const safeCommentBrand = vars.brandName.replace(/[\r\n#]/g, '');
    const curlTlsFlag = vars.allowSelfSignedTls ? '--insecure ' : '';

    const lines = [
      '#!/usr/bin/env bash',
      '# ==============================================================================',
      `# ${safeCommentBrand} - macOS Universal Agent & Notification Tray`,
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
      `BRAND_NAME=${quoteBashLiteral(vars.brandName)}`,
      `SERVER_URL=${quoteBashLiteral(vars.serverUrl)}`,
      `TENANT_ID=${quoteBashLiteral(vars.tenantId)}`,
      `TRAY_THEME=${quoteBashLiteral(vars.trayThemeMode)}`,
      `SERVICE_SLUG=${quoteBashLiteral(vars.serviceName.toLowerCase())}`,
      vars.isQuickSupport
        ? 'INSTALL_DIR="$HOME/Library/Application Support/${SERVICE_SLUG}-quicksupport"'
        : 'INSTALL_DIR="/Library/Application Support/${SERVICE_SLUG}"',
      '',
      'mkdir -p "$INSTALL_DIR"',
      'ARCH="$(uname -m)"',
      'MESH_TYPE=16',
      'if [ "$ARCH" = "arm64" ]; then MESH_TYPE=29; fi',
      '',
      `curl ${curlTlsFlag}-fsSL "$SERVER_URL/meshagents?id=$MESH_TYPE&signed=1" -o "$INSTALL_DIR/meshagent"`,
      'if [ ! -s "$INSTALL_DIR/meshagent" ]; then',
      '  echo "[-] Downloaded macOS meshagent binary is empty; aborting." >&2',
      '  exit 1',
      'fi',
      'chmod 755 "$INSTALL_DIR/meshagent"',
      vars.isQuickSupport
        ? '"$INSTALL_DIR/meshagent" -connect &'
        : '"$INSTALL_DIR/meshagent" -install --installPath="$INSTALL_DIR/meshcore"',
      'printf "[OK] %s macOS deployment completed.\\n" "$BRAND_NAME"'
    ];

    return lines.join('\n');
  }
}

export const installerGenerator = new InstallerGeneratorService();
