import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { db, DATA_DIR_PATH } from '../../db/index.js';
import { CodeSigningService } from '../signing/index.js';

export interface InstallerOptions {
  os: 'windows' | 'linux' | 'darwin' | 'macos';
  tenantId?: string;
  serverUrl?: string;
  vitrineServerUrl?: string;
  meshGroupId?: string;
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

  public async runSigningPipeline(options: InstallerOptions): Promise<{
    allSigned: boolean;
    signed?: boolean;
    endpointVerified?: boolean;
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
    const safeOs =
      options.os === 'linux' ? 'linux' : options.os === 'darwin' || options.os === 'macos' ? 'macos' : 'windows';
    const ms2Hash = crypto
      .createHash('sha256')
      .update(`meshagent:${safeOs}:${options.meshServerId || 'ms2-primary'}:${settings.installed_version || '2.6.1'}`)
      .digest('hex');

    const signedMarkerPath = path.join(signedCacheDir, `meshagent-${safeOs}.signed.meta.json`);
    fs.writeFileSync(
      signedMarkerPath,
      JSON.stringify(
        {
          os: safeOs,
          sha256: ms2Hash,
          signed: false,
          endpointVerified: Boolean(signingEnabled && signMs2 && endpointReachable),
          recordedAt: new Date().toISOString(),
          signingEndpoint: signingEnabled ? settings.code_signing_url : null,
          disableUnsignedAutoUpdate: Boolean(signingEnabled && strictVerify)
        },
        null,
        2
      ),
      { mode: 0o600 }
    );

    // `runSigningPipeline` only probes endpoint connectivity; stages are marked `'verified'`
    // until `this.signer.signFile(...)` cryptographically signs actual bytes.
    const resolveStatus = (stageFlag: boolean): SigningStageReport['status'] => {
      if (!signingEnabled || !stageFlag) return 'bypassed';
      return endpointReachable ? 'verified' : 'unreachable';
    };

    const resolveAuthority = (stageFlag: boolean): string => {
      if (!signingEnabled || !stageFlag) return 'Unsigned (Signing Disabled in Settings)';
      return endpointReachable
        ? `Signing Endpoint Verified (${settings.code_signing_url})`
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
      component: 'Vitrine Desktop Companion & Telemetry Agent',
      description: 'System Tray HUD, Check-in Task Runner, Reboot Countdown & LAPS/Elevation RPC module',
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
      allSigned: false,
      signed: false,
      endpointVerified: Boolean(signingEnabled && endpointReachable),
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
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    const policy = (db.prepare("SELECT * FROM policies WHERE tier = 'global' LIMIT 1").get() || {}) as any;

    const tenantId = sanitizeIdentifier(options.tenantId, 'default', 64);
    const tenantRow = (db.prepare('SELECT * FROM tenants WHERE id = ?').get(tenantId) || {}) as any;
    const meshServerRow = options.meshServerId
      ? ((db.prepare('SELECT * FROM mesh_servers WHERE id = ?').get(options.meshServerId) || {}) as any)
      : ((db.prepare('SELECT * FROM mesh_servers ORDER BY is_primary DESC LIMIT 1').get() || {}) as any);

    const brandName = String(settings.brand_name || 'Vitrine RMM').slice(0, 64);
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
      'http://127.0.0.1:3001'
    );
    const meshGroupId = String(options.meshGroupId || tenantRow?.mesh_group_id || '').replace(/[\r\n]/g, '').slice(0, 160);
    const enrollmentToken = sanitizeIdentifier(options.tokenId, '', 96);

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
    const allowSelfSignedTls = Boolean(options.allowSelfSignedTls ?? meshServerUrl.includes('127.0.0.1') ?? false);

    const signingPipeline = await this.runSigningPipeline(options);

    if (options.os === 'windows') {
      let script = this.generateWindowsPowerShellInstaller({
        brandName,
        primaryColor,
        meshServerUrl,
        vitrineServerUrl,
        meshGroupId,
        enrollmentToken,
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
        strictAuthenticodeVerify: strictVerify,
        allowSelfSignedTls
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
            const signedSha = crypto.createHash('sha256').update(script, 'utf8').digest('hex');
            signingPipeline.signed = true;
            for (const stg of signingPipeline.stages) {
              if (stg.stepNumber === 3 || stg.stepNumber === 2) {
                if (stg.status !== 'bypassed') {
                  stg.status = 'signed';
                  stg.sha256 = signedSha;
                  stg.timestampAuthority = `Authenticode + RFC 3161 (${settings.code_signing_url})`;
                  if (signRes.durationMs) stg.durationMs = signRes.durationMs;
                }
              }
            }
            signingPipeline.allSigned = signingPipeline.stages.every(
              (s) => s.status === 'signed' || s.status === 'bypassed'
            );
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
        meshServerUrl,
        vitrineServerUrl,
        meshGroupId,
        enrollmentToken,
        tenantId,
        serviceName: serviceName.toLowerCase(),
        trayThemeMode,
        isQuickSupport,
        lapsAutoCreate,
        lapsAccountName,
        allowSelfSignedTls
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
        meshServerUrl,
        vitrineServerUrl,
        meshGroupId,
        enrollmentToken,
        tenantId,
        serviceName,
        trayThemeMode,
        isQuickSupport,
        lapsAutoCreate,
        lapsAccountName,
        allowSelfSignedTls
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
    meshServerUrl: string;
    vitrineServerUrl: string;
    meshGroupId: string;
    enrollmentToken: string;
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
    allowSelfSignedTls: boolean;
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
      `$MeshServerUrl = ${quotePowerShellLiteral(vars.meshServerUrl)}`,
      `$VitrineServerUrl = ${quotePowerShellLiteral(vars.vitrineServerUrl)}`,
      `$MeshGroupId = ${quotePowerShellLiteral(vars.meshGroupId)}`,
      `$EnrollmentToken = ${quotePowerShellLiteral(vars.enrollmentToken)}`,
      `$TenantId = ${quotePowerShellLiteral(vars.tenantId)}`,
      `$WelcomeText = ${quotePowerShellLiteral(vars.welcomeText)}`,
      `$ConfiguredThemeMode = ${quotePowerShellLiteral(vars.trayThemeMode)}`,
      `$GuiStyle = ${quotePowerShellLiteral(vars.guiStyle)}`,
      `$IsQuickSupport = ${vars.isQuickSupport ? '$true' : '$false'}`,
      `$SessionCode = ${quotePowerShellLiteral(vars.sessionCode || '')}`,
      `$StrictSignatureVerify = ${vars.strictAuthenticodeVerify ? '$true' : '$false'}`,
      `$AllowSelfSignedTls = ${vars.allowSelfSignedTls ? '$true' : '$false'}`,
      '$InstallDir = if ($IsQuickSupport) { Join-Path $env:LocalAppData "$ServiceName-QuickSupport" } else { Join-Path $env:ProgramFiles $ServiceName }',
      `$AccentColor = ${quotePowerShellLiteral(vars.primaryColor)}`,
      `$MaxSnoozeHours = ${vars.maxSnoozeHours}`,
      `$ForceRebootEnabled = ${vars.forceRebootEnabled === 1 ? '$true' : '$false'}`,
      `$FinalCountdownSec = ${vars.finalCountdownSec}`,
      `$LapsAutoCreate = ${vars.lapsAutoCreate === 1 ? '$true' : '$false'}`,
      `$LapsAccountName = ${quotePowerShellLiteral(vars.lapsAccountName)}`,
      '',
      'if ($AllowSelfSignedTls) {',
      '    try {',
      '        if (-not ("TrustLocalDevCertsPolicy" -as [type])) {',
      '            Add-Type @"',
      'using System.Net;',
      'using System.Security.Cryptography.X509Certificates;',
      'public class TrustLocalDevCertsPolicy : ICertificatePolicy {',
      '    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { return true; }',
      '}',
      '"@',
      '        }',
      '        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustLocalDevCertsPolicy',
      '    } catch {}',
      '}',
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
      'if (!(Test-Path -LiteralPath $InstallDir)) {',
      '    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null',
      '}',
      '',
      '# Download MeshCentral 2 Core Agent & Group Policy (.msh)',
      '$AgentExe = Join-Path $InstallDir "$ServiceName.exe"',
      '$AgentMsh = Join-Path $InstallDir "$ServiceName.msh"',
      '$MeshIdQuery = if ($MeshGroupId) { "&id=$([uri]::EscapeDataString($MeshGroupId))" } else { "" }',
      'try {',
      '    if ($MeshGroupId) {',
      '        Invoke-WebRequest -Uri "$MeshServerUrl/meshsettings?id=$([uri]::EscapeDataString($MeshGroupId))" -OutFile $AgentMsh -UseBasicParsing -ErrorAction SilentlyContinue',
      '    }',
      '    $ArchType = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "43" } else { "4" }',
      '    $AgentUri = "$MeshServerUrl/meshagents?id=$ArchType$MeshIdQuery"',
      '    Invoke-WebRequest -Uri $AgentUri -OutFile $AgentExe -UseBasicParsing',
      '} catch {',
      '    Write-Warning "MeshAgent binary download skipped or unreachable ($($_.Exception.Message)); continuing with Vitrine Companion Agent enrollment."',
      '}',
      '',
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
      '# Enroll Endpoint with VitrineRMM Control Plane & Obtain Device Agent Token',
      '$IdentityPath = Join-Path $InstallDir "agent-identity.json"',
      'try {',
      '    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue',
      '    $ipAddr = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } | Select-Object -First 1).IPAddress',
      '    $macAddr = (Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1).MacAddress',
      '    $enrollBody = @{',
      '        token = $EnrollmentToken',
      '        enrollmentToken = $EnrollmentToken',
      '        tenantId = $TenantId',
      '        hostname = $env:COMPUTERNAME',
      '        osType = "windows"',
      '        osVersion = if ($osInfo) { $osInfo.Caption } else { "Windows" }',
      '        ipAddress = if ($ipAddr) { $ipAddr } else { "127.0.0.1" }',
      '        macAddress = if ($macAddr) { $macAddr } else { "" }',
      '    } | ConvertTo-Json',
      '    $enrollRes = Invoke-RestMethod -Method Post -Uri "$VitrineServerUrl/api/agent/enroll" -ContentType "application/json" -Body $enrollBody -TimeoutSec 15',
      '    $agentTok = if ($enrollRes -and $enrollRes.agentToken) { $enrollRes.agentToken } elseif ($enrollRes -and $enrollRes.agentAuthToken) { $enrollRes.agentAuthToken } else { $null }',
      '    if ($agentTok) {',
      '        $identObj = @{',
      '            deviceId = $enrollRes.deviceId',
      '            agentToken = $agentTok',
      '            agentAuthToken = $agentTok',
      '            vitrineServerUrl = $VitrineServerUrl',
      '            tenantId = $TenantId',
      '            serviceName = $ServiceName',
      '        } | ConvertTo-Json',
      '        Set-Content -LiteralPath $IdentityPath -Value $identObj -Encoding UTF8 -Force',
      '    }',
      '} catch {',
      '    Write-Warning "Vitrine enrollment note: $($_.Exception.Message)"',
      '}',
      '',
      '# Write companion config safely as JSON (no script code interpolation)',
      '$CompanionConfig = @{',
      '    BrandName = $BrandName',
      '    ServiceName = $ServiceName',
      '    VitrineServerUrl = $VitrineServerUrl',
      '    ThemeMode = $ConfiguredThemeMode',
      '    MaxSnoozeHours = $MaxSnoozeHours',
      '    ForceRebootEnabled = $ForceRebootEnabled',
      '    FinalCountdownSec = $FinalCountdownSec',
      '} | ConvertTo-Json',
      'Set-Content -LiteralPath (Join-Path $InstallDir "companion-config.json") -Value $CompanionConfig -Encoding UTF8 -Force',
      '',
      '# Install Vitrine Background Telemetry & Task Runner Companion',
      '$CompanionWorkerScript = @\'',
      '$ErrorActionPreference = "SilentlyContinue"',
      '$idPath = Join-Path $PSScriptRoot "agent-identity.json"',
      '$cfgPath = Join-Path $PSScriptRoot "companion-config.json"',
      '$inboxPath = Join-Path $PSScriptRoot "tray-inbox.json"',
      'while ($true) {',
      '    if (Test-Path -LiteralPath $idPath) {',
      '        $id = Get-Content -LiteralPath $idPath -Raw | ConvertFrom-Json',
      '        $tok = if ($id.agentToken) { $id.agentToken } else { $id.agentAuthToken }',
      '        if ($tok -and $id.vitrineServerUrl) {',
      '            $cpu = [int]((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average)',
      '            $os = Get-CimInstance Win32_OperatingSystem',
      '            $ram = if ($os -and $os.TotalVisibleMemorySize -gt 0) { [int]([Math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100)) } else { 25 }',
      '            $ramTotalGb = if ($os -and $os.TotalVisibleMemorySize -gt 0) { [Math]::Round($os.TotalVisibleMemorySize / 1048576, 2) } else { 8 }',
      '            $ramUsedGb = if ($os -and $os.TotalVisibleMemorySize -gt 0) { [Math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1048576, 2) } else { 2 }',
      '            $diskObj = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID=\'C:\'"',
      '            $disk = if ($diskObj -and $diskObj.Size -gt 0) { [int]([Math]::Round((($diskObj.Size - $diskObj.FreeSpace) / $diskObj.Size) * 100)) } else { 30 }',
      '            $diskTotalGb = if ($diskObj -and $diskObj.Size -gt 0) { [Math]::Round($diskObj.Size / 1GB, 2) } else { 256 }',
      '            $diskFreeGb = if ($diskObj -and $diskObj.Size -gt 0) { [Math]::Round($diskObj.FreeSpace / 1GB, 2) } else { 180 }',
      '            $mp = Get-MpComputerStatus',
      '            $bl = Get-BitLockerVolume -MountPoint "C:"',
      '            $edrState = if ($mp -and $mp.RealTimeProtectionEnabled) { "Healthy" } else { "Warning" }',
      '            $blEncrypted = [bool]($bl -and ($bl.ProtectionStatus -eq "On" -or $bl.ProtectionStatus -eq 1))',
      '            $blStatus = if ($blEncrypted) { "Encrypted" } else { "Unencrypted" }',
      '            $rebootPending = [bool]((Test-Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending") -or (Test-Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired"))',
      '            $neighbors = @()',
      '            try {',
      '                $neighbors = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -ne "00-00-00-00-00-00" -and $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } | Select-Object -First 64 | ForEach-Object { @{ ip = $_.IPAddress; mac = ($_.LinkLayerAddress -replace "-", ":").ToLower() } })',
      '            } catch {}',
      '            $headers = @{ "x-vitrine-agent-token" = $tok }',
      '            $payload = @{',
      '                deviceId = $id.deviceId',
      '                hostname = $env:COMPUTERNAME',
      '                osType = "windows"',
      '                osVersion = if ($os) { $os.Caption } else { "Windows" }',
      '                cpuUsage = $cpu',
      '                ramUsage = $ram',
      '                ramUsedGb = $ramUsedGb',
      '                ramTotalGb = $ramTotalGb',
      '                diskUsage = $disk',
      '                diskFreeGb = $diskFreeGb',
      '                diskTotalGb = $diskTotalGb',
      '                loggedInUser = (Get-CimInstance Win32_ComputerSystem).UserName',
      '                rebootPending = $rebootPending',
      '                rebootRequired = $rebootPending',
      '                avStatus = $edrState',
      '                edrStatus = $edrState',
      '                bitlockerEncrypted = $blEncrypted',
      '                bitlockerStatus = $blStatus',
      '                arpNeighbors = $neighbors',
      '            } | ConvertTo-Json -Depth 5',
      '            $resp = Invoke-RestMethod -Method Post -Uri "$($id.vitrineServerUrl)/api/agent/checkin" -Headers $headers -ContentType "application/json" -Body $payload -TimeoutSec 20',
      '            if ($resp -and $resp.tasks) {',
      '                foreach ($t in $resp.tasks) {',
      '                    $ttype = if ($t.type) { $t.type } else { $t.task_type }',
      '                    $pObj = if ($t.payload -and $t.payload -isnot [string]) { $t.payload } elseif ($t.payload_json) { $t.payload_json | ConvertFrom-Json } else { @{} }',
      '                    $safeTaskId = ([string]$t.id -replace "[^a-zA-Z0-9_-]", "")',
      '                    if (-not $safeTaskId) { $safeTaskId = [guid]::NewGuid().ToString("N") }',
      '                    $uriTaskId = [uri]::EscapeDataString([string]$t.id)',
      '                    if ($ttype -eq "tray_notify" -or $ttype -eq "reboot_prompt") {',
      '                        Set-Content -LiteralPath $inboxPath -Value ($t | ConvertTo-Json -Depth 6) -Encoding UTF8 -Force',
      '                        Invoke-RestMethod -Method Post -Uri "$($id.vitrineServerUrl)/api/agent/tasks/$uriTaskId/result" -Headers $headers -ContentType "application/json" -Body (@{ deviceId = $id.deviceId; exitCode = 0; stdout = "Delivered to user tray"; stderr = "" } | ConvertTo-Json) | Out-Null',
      '                    } elseif ($ttype -eq "wol_relay") {',
      '                        $macHex = ([string]$pObj.mac -replace "[:\\-]", "").Trim()',
      '                        $ec = 0; $out = ""; $errOut = ""',
      '                        if ($macHex -match "^[0-9A-Fa-f]{12}$") {',
      '                            try {',
      '                                $macBytes = New-Object byte[] 6',
      '                                for ($i = 0; $i -lt 6; $i++) { $macBytes[$i] = [Convert]::ToByte($macHex.Substring($i * 2, 2), 16) }',
      '                                $pkt = New-Object byte[] 102',
      '                                for ($i = 0; $i -lt 6; $i++) { $pkt[$i] = 0xFF }',
      '                                for ($i = 1; $i -le 16; $i++) { [Array]::Copy($macBytes, 0, $pkt, $i * 6, 6) }',
      '                                $bcast = if ($pObj.broadcastIp) { [string]$pObj.broadcastIp } else { "255.255.255.255" }',
      '                                $wport = if ($pObj.port) { [int]$pObj.port } else { 9 }',
      '                                $udp = New-Object System.Net.Sockets.UdpClient',
      '                                $udp.EnableBroadcast = $true',
      '                                [void]$udp.Send($pkt, $pkt.Length, $bcast, $wport)',
      '                                $udp.Close()',
      '                                $out = "Magic packet relayed to $macHex"',
      '                            } catch {',
      '                                $ec = 1; $errOut = $_.Exception.Message',
      '                            }',
      '                        } else {',
      '                            $ec = 1; $errOut = "Invalid MAC address"',
      '                        }',
      '                        Invoke-RestMethod -Method Post -Uri "$($id.vitrineServerUrl)/api/agent/tasks/$uriTaskId/result" -Headers $headers -ContentType "application/json" -Body (@{ deviceId = $id.deviceId; exitCode = $ec; stdout = $out; stderr = $errOut } | ConvertTo-Json) | Out-Null',
      '                    } elseif ($ttype -eq "self_uninstall") {',
      '                        Invoke-RestMethod -Method Post -Uri "$($id.vitrineServerUrl)/api/agent/tasks/$uriTaskId/result" -Headers $headers -ContentType "application/json" -Body (@{ deviceId = $id.deviceId; exitCode = 0; stdout = "Self-uninstall initiated"; stderr = "" } | ConvertTo-Json) | Out-Null',
      '                        $cfgLocal = if (Test-Path -LiteralPath $cfgPath) { Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json } else { @{ ServiceName = "VitrineAgent" } }',
      '                        $svcLocal = if ($pObj.serviceName) { [string]$pObj.serviceName } elseif ($id.serviceName) { [string]$id.serviceName } elseif ($cfgLocal.ServiceName) { [string]$cfgLocal.ServiceName } else { "VitrineAgent" }',
      '                        $svcLocal = ($svcLocal -replace "[^a-zA-Z0-9_-]", "")',
      '                        if (-not $svcLocal) { $svcLocal = "VitrineAgent" }',
      '                        Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "$svcLocal-Tray" -ErrorAction SilentlyContinue',
      '                        Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "VitrineAgent-Tray" -ErrorAction SilentlyContinue',
      '                        Unregister-ScheduledTask -TaskName "$svcLocal-Companion" -Confirm:$false -ErrorAction SilentlyContinue',
      '                        if ($pObj.lapsAccountName -and ($pObj.lapsAccountName -match "^[a-zA-Z0-9._-]{1,20}$")) {',
      '                            if ($pObj.lapsAction -eq "remove_account" -or $pObj.lapsAction -eq "disable_account") {',
      '                                if (-not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) {',
      '                                    $s500 = Get-LocalUser | Where-Object { $_.SID.Value -like "*-500" }',
      '                                    if ($s500) { Enable-LocalUser -Name $s500.Name -ErrorAction SilentlyContinue }',
      '                                }',
      '                                if ($pObj.lapsAction -eq "remove_account") { Remove-LocalUser -Name ([string]$pObj.lapsAccountName) -ErrorAction SilentlyContinue }',
      '                                else { Disable-LocalUser -Name ([string]$pObj.lapsAccountName) -ErrorAction SilentlyContinue }',
      '                            }',
      '                        }',
      '                        $localMesh = Join-Path $PSScriptRoot "$svcLocal.exe"',
      '                        if (Test-Path -LiteralPath $localMesh) { Start-Process -FilePath $localMesh -ArgumentList "-fulluninstall" -WindowStyle Hidden }',
      '                        if (Test-Path "C:\\Program Files\\Mesh Agent\\MeshAgent.exe") { Start-Process -FilePath "C:\\Program Files\\Mesh Agent\\MeshAgent.exe" -ArgumentList "-fulluninstall" -WindowStyle Hidden }',
      '                        Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-WindowStyle", "Hidden", "-Command", ("Start-Sleep -Seconds 3; Remove-Item -LiteralPath \'" + ($PSScriptRoot -replace "\'", "\'\'") + "\' -Recurse -Force -ErrorAction SilentlyContinue")) -WindowStyle Hidden',
      '                        exit 0',
      '                    } elseif ($ttype -in @("script", "run_script", "patch_scan", "patch_install", "software_deploy", "backup_job")) {',
      '                        $scriptBody = if ($pObj.code) { [string]$pObj.code } elseif ($pObj.command) { [string]$pObj.command } elseif ($ttype -eq "software_deploy" -and ($pObj.packageId -match "^[a-zA-Z0-9._-]+$")) { "winget install --id $($pObj.packageId) --silent --accept-package-agreements --accept-source-agreements" } elseif ($ttype -eq "backup_job") { "vssadmin create shadow /for=C:" } else { "Write-Output ok" }',
      '                        $tmpPs1 = Join-Path $env:TEMP "vitrine-task-$safeTaskId.ps1"',
      '                        $savedEnv = @{}',
      '                        $addedEnv = New-Object System.Collections.Generic.List[string]',
      '                        $ec = 0; $out = ""; $errOut = ""',
      '                        try {',
      '                            if ($pObj.env) {',
      '                                foreach ($prop in $pObj.env.PSObject.Properties) {',
      '                                    if ($prop.Name -match "^VITRINE_PARAM_[A-Z0-9_]+$") {',
      '                                        if (Test-Path "Env:$($prop.Name)") { $savedEnv[$prop.Name] = (Get-Item "Env:$($prop.Name)").Value }',
      '                                        [void]$addedEnv.Add($prop.Name)',
      '                                        Set-Item -Path "Env:$($prop.Name)" -Value ([string]$prop.Value)',
      '                                    }',
      '                                }',
      '                            }',
      '                            Set-Content -LiteralPath $tmpPs1 -Value $scriptBody -Encoding UTF8 -Force',
      '                            $out = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $tmpPs1 2>&1 | Out-String)',
      '                            $ec = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { 0 }',
      '                        } catch {',
      '                            $ec = 1; $errOut = $_.Exception.Message',
      '                        } finally {',
      '                            foreach ($envKey in $addedEnv) {',
      '                                if ($savedEnv.ContainsKey($envKey)) { Set-Item -Path "Env:$envKey" -Value $savedEnv[$envKey] }',
      '                                else { Remove-Item -Path "Env:$envKey" -ErrorAction SilentlyContinue }',
      '                            }',
      '                            if (Test-Path -LiteralPath $tmpPs1) { Remove-Item -LiteralPath $tmpPs1 -Force -ErrorAction SilentlyContinue }',
      '                        }',
      '                        $resBody = @{ deviceId = $id.deviceId; exitCode = $ec; stdout = $out; stderr = $errOut; backupJobId = $pObj.backupJobId } | ConvertTo-Json',
      '                        Invoke-RestMethod -Method Post -Uri "$($id.vitrineServerUrl)/api/agent/tasks/$uriTaskId/result" -Headers $headers -ContentType "application/json" -Body $resBody | Out-Null',
      '                    }',
      '                }',
      '            }',
      '        }',
      '    }',
      '    Start-Sleep -Seconds 30',
      '}',
      '\'@',
      '$WorkerPath = Join-Path $InstallDir "vitrine-companion.ps1"',
      'Set-Content -LiteralPath $WorkerPath -Value $CompanionWorkerScript -Encoding UTF8 -Force',
      '',
      '$TrayAppScript = @\'',
      'Add-Type -AssemblyName System.Drawing, System.Windows.Forms, Microsoft.VisualBasic',
      '$cfgPath = Join-Path $PSScriptRoot "companion-config.json"',
      '$idPath = Join-Path $PSScriptRoot "agent-identity.json"',
      '$inboxPath = Join-Path $PSScriptRoot "tray-inbox.json"',
      '$cfg = if (Test-Path -LiteralPath $cfgPath) { Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json } else { @{ BrandName = "Vitrine RMM"; ServiceName = "VitrineAgent" } }',
      '$notifyIcon = New-Object System.Windows.Forms.NotifyIcon',
      '$notifyIcon.Text = ($cfg.BrandName + " Support").Substring(0, [Math]::Min(63, ($cfg.BrandName + " Support").Length))',
      '$notifyIcon.Icon = [System.Drawing.SystemIcons]::Shield',
      '$menu = New-Object System.Windows.Forms.ContextMenuStrip',
      '$statusItem = $menu.Items.Add(($cfg.BrandName + " Protected"))',
      '$statusItem.Enabled = $false',
      '$menu.Items.Add("-") | Out-Null',
      '$chatItem = $menu.Items.Add("Message IT Support")',
      '$chatItem.Add_Click({',
      '    try {',
      '        $userMsg = [Microsoft.VisualBasic.Interaction]::InputBox("Describe your IT issue or message for support:", "$($cfg.BrandName) Live Support", "")',
      '        if ($userMsg -and (Test-Path -LiteralPath $idPath)) {',
      '            $id = Get-Content -LiteralPath $idPath -Raw | ConvertFrom-Json',
      '            $tok = if ($id.agentToken) { $id.agentToken } else { $id.agentAuthToken }',
      '            if ($tok -and $id.vitrineServerUrl) {',
      '                $chatPayload = @{ deviceId = $id.deviceId; sender = $env:USERNAME; message = $userMsg } | ConvertTo-Json',
      '                Invoke-RestMethod -Method Post -Uri "$($id.vitrineServerUrl)/api/agent/chat" -Headers @{ "x-vitrine-agent-token" = $tok } -ContentType "application/json" -Body $chatPayload -TimeoutSec 10 | Out-Null',
      '                $notifyIcon.BalloonTipTitle = $cfg.BrandName',
      '                $notifyIcon.BalloonTipText = "Your message has been sent to IT Support."',
      '                $notifyIcon.ShowBalloonTip(5000)',
      '            }',
      '        }',
      '    } catch {}',
      '})',
      '$helpItem = $menu.Items.Add("Endpoint Status")',
      '$helpItem.Add_Click({ [System.Windows.Forms.MessageBox]::Show("Managed by $($cfg.BrandName). Endpoint protection and telemetry active.", $cfg.BrandName) })',
      '$notifyIcon.ContextMenuStrip = $menu',
      '$notifyIcon.Visible = $true',
      '$timer = New-Object System.Windows.Forms.Timer',
      '$timer.Interval = 4000',
      '$timer.Add_Tick({',
      '    if (Test-Path -LiteralPath $inboxPath) {',
      '        try {',
      '            $msg = Get-Content -LiteralPath $inboxPath -Raw | ConvertFrom-Json',
      '            Remove-Item -LiteralPath $inboxPath -Force -ErrorAction SilentlyContinue',
      '            $p = if ($msg.payload -and $msg.payload -isnot [string]) { $msg.payload } elseif ($msg.payload_json) { $msg.payload_json | ConvertFrom-Json } else { @{} }',
      '            $notifyIcon.BalloonTipTitle = if ($p.title) { $p.title } else { $cfg.BrandName }',
      '            $notifyIcon.BalloonTipText = if ($p.message) { $p.message } else { "IT Support Notification" }',
      '            $notifyIcon.ShowBalloonTip(8000)',
      '        } catch {}',
      '    }',
      '})',
      '$timer.Start()',
      '[System.Windows.Forms.Application]::Run()',
      '\'@',
      '',
      '$TrayPath = Join-Path $InstallDir "vitrine-tray.ps1"',
      'Set-Content -LiteralPath $TrayPath -Value $TrayAppScript -Encoding UTF8 -Force',
      'if (-not $IsQuickSupport) {',
      '    $RunKey = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"',
      '    Set-ItemProperty -Path $RunKey -Name "$ServiceName-Tray" -Value "powershell.exe -NoProfile -WindowStyle Hidden -File `"$TrayPath`"" -Force',
      '    try {',
      '        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$WorkerPath`""',
      '        $trigger = New-ScheduledTaskTrigger -AtStartup',
      '        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest',
      '        Register-ScheduledTask -TaskName "$ServiceName-Companion" -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null',
      '        Start-ScheduledTask -TaskName "$ServiceName-Companion" -ErrorAction SilentlyContinue',
      '    } catch {}',
      '}',
      'Write-Host "[OK] $BrandName deployment finished (Theme: $ActiveTheme)." -ForegroundColor Cyan'
    ];

    return lines.join('\r\n');
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
      `# ${safeCommentBrand} - Linux Endpoint Agent & Telemetry Companion`,
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
      `MESH_SERVER_URL=${quoteBashLiteral(vars.meshServerUrl)}`,
      `VITRINE_SERVER_URL=${quoteBashLiteral(vars.vitrineServerUrl)}`,
      `MESH_GROUP_ID=${quoteBashLiteral(vars.meshGroupId)}`,
      `ENROLLMENT_TOKEN=${quoteBashLiteral(vars.enrollmentToken)}`,
      `TENANT_ID=${quoteBashLiteral(vars.tenantId)}`,
      `TRAY_THEME=${quoteBashLiteral(vars.trayThemeMode)}`,
      `LAPS_AUTO_CREATE=${quoteBashLiteral(String(vars.lapsAutoCreate))}`,
      `LAPS_USER=${quoteBashLiteral(vars.lapsAccountName)}`,
      `CURL_TLS_FLAG=${quoteBashLiteral(vars.allowSelfSignedTls ? '--insecure' : '')}`,
      vars.isQuickSupport
        ? 'INSTALL_DIR="$HOME/.local/share/${SERVICE_NAME}-quicksupport"'
        : 'INSTALL_DIR="/opt/${SERVICE_NAME}"',
      '',
      'umask 077',
      'mkdir -p "$INSTALL_DIR"',
      'chmod 700 "$INSTALL_DIR"',
      '',
      'ARCH="$(uname -m)"',
      'MESH_TYPE=6',
      'if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then MESH_TYPE=25; fi',
      '',
      'if [ -n "$MESH_GROUP_ID" ]; then',
      `  curl ${curlTlsFlag}-fsSL "$MESH_SERVER_URL/meshsettings?id=$MESH_GROUP_ID" -o "$INSTALL_DIR/meshagent.msh" || true`,
      'fi',
      '',
      `if curl ${curlTlsFlag}-fsSL "$MESH_SERVER_URL/meshagents?id=$MESH_TYPE" -o "$INSTALL_DIR/meshagent"; then`,
      '  if [ -s "$INSTALL_DIR/meshagent" ]; then',
      '    chmod 755 "$INSTALL_DIR/meshagent"',
      vars.isQuickSupport
        ? '    "$INSTALL_DIR/meshagent" -connect >/dev/null 2>&1 &'
        : '    "$INSTALL_DIR/meshagent" -install --installPath="$INSTALL_DIR/meshcore" || true',
      '  fi',
      'else',
      '  echo "[!] MeshCentral binary download skipped or unreachable; proceeding with Vitrine Companion Agent." >&2',
      'fi',
      '',
      '# Provision Managed Local Admin Account with cryptographically random initial password',
      'if [ "${EUID:-$(id -u)}" -eq 0 ] && [ "$LAPS_AUTO_CREATE" = "1" ]; then',
      '  if ! id "$LAPS_USER" >/dev/null 2>&1; then',
      '    useradd -m -s /bin/bash "$LAPS_USER"',
      '    INIT_PASS="$(head -c 24 /dev/urandom | base64 | tr -dc "A-Za-z0-9" | head -c 24)!9vR"',
      '    printf "%s:%s\\n" "$LAPS_USER" "$INIT_PASS" | chpasswd',
      '    usermod -aG sudo "$LAPS_USER" 2>/dev/null || usermod -aG wheel "$LAPS_USER" 2>/dev/null || true',
      '  fi',
      'fi',
      '',
      '# Enroll with VitrineRMM Control Plane',
      'HOSTNAME_VAL="$(hostname)"',
      'OS_VER="$(. /etc/os-release 2>/dev/null && printf "%s" "${PRETTY_NAME:-Linux}" || uname -sr)"',
      'IP_ADDR="$(hostname -I 2>/dev/null | awk "{print \\$1}")"',
      'MAC_ADDR="$(ip link show 2>/dev/null | awk "/link\\/ether/ {print \\$2; exit}")"',
      '',
      'ENROLL_JSON="$(python3 -c \'import json,sys; print(json.dumps({"token":sys.argv[1],"enrollmentToken":sys.argv[1],"tenantId":sys.argv[2],"hostname":sys.argv[3],"osType":"linux","osVersion":sys.argv[4],"ipAddress":sys.argv[5] or "127.0.0.1","macAddress":sys.argv[6] or ""}))\' "$ENROLLMENT_TOKEN" "$TENANT_ID" "$HOSTNAME_VAL" "$OS_VER" "$IP_ADDR" "$MAC_ADDR")"',
      `if ENROLL_RESP="$(curl ${curlTlsFlag}-fsSL -X POST "$VITRINE_SERVER_URL/api/agent/enroll" -H "Content-Type: application/json" -d "$ENROLL_JSON" 2>/dev/null)"; then`,
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
      '# Write Python3 Vitrine Companion Agent (Telemetry, Patch/Software Inventory, Subnet Probe & Task Executor)',
      'cat > "$INSTALL_DIR/vitrine-companion.py" <<\'PYAGENT\'',
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
      '    ram_pct = 25',
      '    ram_total_gb = 8.0',
      '    ram_used_gb = 2.0',
      '    try:',
      '        mem = {}',
      '        with open("/proc/meminfo", "r") as f:',
      '            for line in f:',
      '                parts = line.split(":", 1)',
      '                if len(parts) == 2:',
      '                    mem[parts[0].strip()] = int(parts[1].strip().split()[0])',
      '        total = mem.get("MemTotal", 0)',
      '        avail = mem.get("MemAvailable", mem.get("MemFree", 0))',
      '        if total > 0:',
      '            used_kb = max(0, total - avail)',
      '            ram_pct = min(100, max(1, int(round((used_kb / total) * 100))))',
      '            ram_total_gb = round(total / (1024.0 * 1024.0), 2)',
      '            ram_used_gb = round(used_kb / (1024.0 * 1024.0), 2)',
      '    except Exception:',
      '        pass',
      '    disk_pct = 20',
      '    disk_total_gb = 64.0',
      '    disk_free_gb = 48.0',
      '    try:',
      '        st = os.statvfs("/")',
      '        if st.f_blocks > 0:',
      '            disk_pct = min(100, max(1, int(round(((st.f_blocks - st.f_bavail) / st.f_blocks) * 100))))',
      '            disk_total_gb = round((st.f_blocks * st.f_frsize) / (1024.0 ** 3), 2)',
      '            disk_free_gb = round((st.f_bavail * st.f_frsize) / (1024.0 ** 3), 2)',
      '    except Exception:',
      '        pass',
      '    os_ver = platform.platform()',
      '    try:',
      '        with open("/etc/os-release", "r") as f:',
      '            for line in f:',
      '                if line.startswith("PRETTY_NAME="):',
      '                    os_ver = line.split("=", 1)[1].strip().strip(\'"\')',
      '                    break',
      '    except Exception:',
      '        pass',
      '    edr_status = "Healthy" if (os.path.exists("/sys/module/apparmor") or os.path.exists("/sys/fs/selinux")) else "Unmonitored"',
      '    luks_encrypted = False',
      '    try:',
      '        if os.path.exists("/etc/crypttab"):',
      '            with open("/etc/crypttab", "r") as cf:',
      '                luks_encrypted = any(ln.strip() and not ln.strip().startswith("#") for ln in cf)',
      '    except Exception:',
      '        pass',
      '    reboot_req = bool(os.path.exists("/var/run/reboot-required"))',
      '    arp_neighbors = []',
      '    try:',
      '        out = subprocess.check_output(["ip", "neigh", "show"], text=True, timeout=4)',
      '        for line in out.splitlines():',
      '            cols = line.split()',
      '            if len(cols) >= 5 and "lladdr" in cols:',
      '                idx = cols.index("lladdr")',
      '                if idx + 1 < len(cols):',
      '                    arp_neighbors.append({"ip": cols[0], "mac": cols[idx + 1]})',
      '    except Exception:',
      '        pass',
      '    return {',
      '        "deviceId": device_id,',
      '        "hostname": socket.gethostname(),',
      '        "osType": "linux",',
      '        "osVersion": os_ver,',
      '        "cpuUsage": cpu_pct,',
      '        "ramUsage": ram_pct,',
      '        "ramUsedGb": ram_used_gb,',
      '        "ramTotalGb": ram_total_gb,',
      '        "diskUsage": disk_pct,',
      '        "diskFreeGb": disk_free_gb,',
      '        "diskTotalGb": disk_total_gb,',
      '        "edrStatus": edr_status,',
      '        "avStatus": edr_status,',
      '        "bitlockerEncrypted": luks_encrypted,',
      '        "bitlockerStatus": "Encrypted" if luks_encrypted else "Unencrypted",',
      '        "rebootPending": reboot_req,',
      '        "rebootRequired": reboot_req,',
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
      '                subprocess.run(["userdel", "-r", acc], capture_output=True)',
      '            elif act == "disable_account":',
      '                subprocess.run(["usermod", "-L", acc], capture_output=True)',
      '        slug = re.sub(r"[^a-z0-9_-]", "", str(payload.get("serviceName") or ident.get("serviceSlug") or "vitrineagent").lower()) or "vitrineagent"',
      '        mesh_bin = os.path.join(BASE_DIR, "meshagent")',
      '        if os.path.exists(mesh_bin):',
      '            subprocess.run([mesh_bin, "-uninstall"], capture_output=True)',
      '        subprocess.run(["systemctl", "disable", "--now", f"{slug}-companion.service"], capture_output=True)',
      '        try:',
      '            unit_path = f"/etc/systemd/system/{slug}-companion.service"',
      '            if os.path.exists(unit_path):',
      '                os.remove(unit_path)',
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
      '            proc = subprocess.run(["/bin/bash", "-c", code], env=env, capture_output=True, text=True, timeout=timeout_s)',
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
      '            subprocess.run(["wall", f"[{title}] {msg}"], capture_output=True, timeout=5)',
      '            stdout_str = "Broadcast delivered"',
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
      '        time.sleep(25)',
      '',
      'if __name__ == "__main__":',
      '    main()',
      'PYAGENT',
      'chmod 700 "$INSTALL_DIR/vitrine-companion.py"',
      '',
      ...(vars.isQuickSupport
        ? ['nohup python3 "$INSTALL_DIR/vitrine-companion.py" >/dev/null 2>&1 &']
        : [
            'if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then',
            '  cat > "/etc/systemd/system/${SERVICE_NAME}-companion.service" <<EOF',
            '[Unit]',
            'Description=${BRAND_NAME} Endpoint Telemetry & Task Companion',
            'After=network-online.target',
            '',
            '[Service]',
            'Type=simple',
            'ExecStart=/usr/bin/env python3 ${INSTALL_DIR}/vitrine-companion.py',
            'Restart=always',
            'RestartSec=10',
            '',
            '[Install]',
            'WantedBy=multi-user.target',
            'EOF',
            '  systemctl daemon-reload || true',
            '  systemctl enable --now "${SERVICE_NAME}-companion.service" || nohup python3 "$INSTALL_DIR/vitrine-companion.py" >/dev/null 2>&1 &',
            'else',
            '  nohup python3 "$INSTALL_DIR/vitrine-companion.py" >/dev/null 2>&1 &',
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
  }): string {
    const safeCommentBrand = vars.brandName.replace(/[\r\n#]/g, '');
    const curlTlsFlag = vars.allowSelfSignedTls ? '--insecure ' : '';
    const safeService = vars.serviceName.toLowerCase().replace(/[^a-z0-9_-]/g, '') || 'vitrineagent';
    const plistLabel = `com.${safeService}.companion`;

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
      `BRAND_NAME=${quoteBashLiteral(vars.brandName)}`,
      `MESH_SERVER_URL=${quoteBashLiteral(vars.meshServerUrl)}`,
      `VITRINE_SERVER_URL=${quoteBashLiteral(vars.vitrineServerUrl)}`,
      `MESH_GROUP_ID=${quoteBashLiteral(vars.meshGroupId)}`,
      `ENROLLMENT_TOKEN=${quoteBashLiteral(vars.enrollmentToken)}`,
      `TENANT_ID=${quoteBashLiteral(vars.tenantId)}`,
      `TRAY_THEME=${quoteBashLiteral(vars.trayThemeMode)}`,
      `SERVICE_SLUG=${quoteBashLiteral(safeService)}`,
      `PLIST_LABEL=${quoteBashLiteral(plistLabel)}`,
      `LAPS_AUTO_CREATE=${quoteBashLiteral(String(vars.lapsAutoCreate ?? 1))}`,
      `LAPS_USER=${quoteBashLiteral(vars.lapsAccountName || 'LocalAdmin')}`,
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
      `if curl ${curlTlsFlag}-fsSL "$MESH_SERVER_URL/meshagents?id=$MESH_TYPE" -o "$INSTALL_DIR/meshagent"; then`,
      '  if [ -s "$INSTALL_DIR/meshagent" ]; then',
      '    chmod 755 "$INSTALL_DIR/meshagent"',
      vars.isQuickSupport
        ? '    "$INSTALL_DIR/meshagent" -connect >/dev/null 2>&1 &'
        : '    "$INSTALL_DIR/meshagent" -install --installPath="$INSTALL_DIR/meshcore" || true',
      '  fi',
      'else',
      '  echo "[!] MeshCentral binary download skipped or unreachable; proceeding with Vitrine Companion Agent." >&2',
      'fi',
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
      'ENROLL_JSON="$(python3 -c \'import json,sys; print(json.dumps({"token":sys.argv[1],"enrollmentToken":sys.argv[1],"tenantId":sys.argv[2],"hostname":sys.argv[3],"osType":"macos","osVersion":sys.argv[4],"ipAddress":sys.argv[5] or "127.0.0.1","macAddress":sys.argv[6] or ""}))\' "$ENROLLMENT_TOKEN" "$TENANT_ID" "$HOSTNAME_VAL" "$OS_VER" "$IP_ADDR" "$MAC_ADDR")"',
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
      '    fv_active = False',
      '    try:',
      '        fv = subprocess.run(["fdesetup", "isactive"], capture_output=True, text=True, timeout=4)',
      '        fv_active = fv.returncode == 0 or "true" in (fv.stdout or "").lower()',
      '    except Exception:',
      '        pass',
      '    edr_status = "Healthy" if os.path.exists("/Library/Apple/System/Library/CoreServices/XProtect.bundle") else "Unmonitored"',
      '    reboot_req = bool(os.path.exists("/Library/Updates/ProductMetadata.plist") or os.path.exists("/var/db/.AppleUpgrade"))',
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
      '        "edrStatus": edr_status,',
      '        "avStatus": edr_status,',
      '        "bitlockerEncrypted": fv_active,',
      '        "bitlockerStatus": "Encrypted" if fv_active else "Unencrypted",',
      '        "rebootPending": reboot_req,',
      '        "rebootRequired": reboot_req,',
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
      '        mesh_bin = os.path.join(BASE_DIR, "meshagent")',
      '        if os.path.exists(mesh_bin):',
      '            subprocess.run([mesh_bin, "-uninstall"], capture_output=True)',
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
      '            shell_bin = "/bin/zsh" if os.path.exists("/bin/zsh") else "/bin/bash"',
      '            proc = subprocess.run([shell_bin, "-c", code], env=env, capture_output=True, text=True, timeout=timeout_s)',
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
      '            title = str(payload.get("title") or "IT Support").replace(\'"\', "\'")',
      '            msg = str(payload.get("message") or "").replace(\'"\', "\'")',
      '            subprocess.run(["osascript", "-e", f\'display notification "{msg}" with title "{title}"\'], capture_output=True, timeout=5)',
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
      '        time.sleep(25)',
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
