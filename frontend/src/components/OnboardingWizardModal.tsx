import React, { useEffect, useRef, useState } from 'react';
import {
  Sparkles,
  Globe,
  Palette,
  Shield,
  Mail,
  CheckCircle2,
  X,
  KeyRound,
  Server,
  HelpCircle,
  RefreshCw,
  HardDrive,
  Lock,
  Copy,
  Check,
  Download,
  Upload,
  AlertTriangle,
  AlertCircle,
  Send
} from 'lucide-react';
import { Settings, MeshDiscoveryResult, LocalMeshCentralDetection } from '../types/index.js';
import {
  updateSettings,
  uploadBrandLogo,
  fetchLocalMeshCentralStatus,
  generateMeshCentralLoginToken,
  applyLocalMeshCentralConfig,
  testDiscoverMeshServer,
  importFromMeshServer,
  testCodeSigningPipeline,
  testProxyTlsSetup,
  testSmtp,
  createSystemBackup,
  revealBackupRecoveryKey,
  acknowledgeBackupRecoveryKey,
  testOidcDiscovery
} from '../services/api.js';
import { copyToClipboard } from '../utils/clipboard.js';
import { MfaChallengeModal } from './MfaChallengeModal.js';
import { IconCropModal } from './IconCropModal.js';

function parseMeshTokenPair(raw?: string | null): {
  user: string;
  pass: string;
  isMasked: boolean;
  isCombinedOnly: boolean;
} {
  const trimmed = String(raw || '').trim();
  if (!trimmed) return { user: '', pass: '', isMasked: false, isCombinedOnly: false };
  if (/^[•*]{4,}$/.test(trimmed)) return { user: '', pass: '', isMasked: true, isCombinedOnly: false };
  if (trimmed.startsWith('~t:')) {
    const rest = trimmed.slice(3);
    const sepIdx = rest.search(/[:,\s]/);
    if (sepIdx > 0) {
      return {
        user: trimmed.slice(0, 3 + sepIdx),
        pass: rest.slice(sepIdx + 1).trim(),
        isMasked: false,
        isCombinedOnly: false
      };
    }
    return { user: trimmed, pass: '', isMasked: false, isCombinedOnly: false };
  }
  if (trimmed.includes(':') && !trimmed.startsWith('c=')) {
    const idx = trimmed.indexOf(':');
    return {
      user: trimmed.slice(0, idx),
      pass: trimmed.slice(idx + 1),
      isMasked: false,
      isCombinedOnly: false
    };
  }
  return { user: '', pass: '', isMasked: false, isCombinedOnly: true };
}

interface OnboardingWizardModalProps {
  settings: Settings;
  adminEmail?: string;
  onClose: () => void;
  onSaved: (updated: Settings) => void;
}

const STEP_GUIDES: Record<
  number,
  { title: string; subtitle: string; bullets: string[]; codeSnippet: string }
> = {
  1: {
    title: 'Walkthrough: Branding, Adaptive Themes & Public QuickSupport Routing',
    subtitle: 'How Vitrine adapts to OS Light/Dark mode and serves your public client support portal',
    bullets: [
      'System Auto Theme: Setting Web UI and Endpoint Tray Theme to "System Auto" listens to browser prefers-color-scheme and Windows HKCU\\...\\Personalize\\AppsUseLightTheme (plus GNOME/macOS equivalents) automatically.',
      'Guided Installer: Replaces basic command-line prompts with a branded wizard using your custom Windows Service Name.',
      'Dedicated QuickSupport Endpoint: Point a CNAME (e.g., remote.yourdomain.com) or path (/remote, /temporarysession) to Vitrine so clients can launch non-admin temporary sessions.'
    ],
    codeSnippet: `# DNS CNAME Setup for Dedicated Client QuickSupport Portal:
remote.yourdomain.com.  300  IN  CNAME  rmm.yourdomain.com.
# Accessible at: https://remote.yourdomain.com/remote or https://rmm.yourdomain.com/temporarysession`
  },
  2: {
    title: 'Walkthrough: Connecting MeshCentral & Login Token Setup',
    subtitle: 'Connecting to a remote MeshCentral server or an isolated co-resident instance on the same host',
    bullets: [
      'Remote or Co-Resident Deployment: Vitrine connects over MeshCentral WebSockets whether MeshCentral runs in another container/VM or locally on the same host. If MeshCentral is detected locally on this host, Vitrine keeps itself isolated and offers an optional config helper.',
      'Option A (Web UI — Easiest with 2FA/TOTP): Sign into MeshCentral -> My Account -> Account Security -> Login Tokens -> Create ("Vitrine RMM"), then paste the generated Token Username (~t:...) and Token Password into the two fields.',
      'Option B (Auto-Generate in Vitrine): Use the "Auto-Generate in Vitrine" tab with your MeshCentral admin username/password (+ 6-digit TOTP if 2FA is active) to mint a persistent Login Token over TLS without saving your admin password.',
      'Option C (CLI via meshctrl.js): Run meshctrl.js LoginTokens --add "Vitrine RMM" from your MeshCentral installation folder (include --token <6-digit-TOTP> if 2FA is enabled). Login Tokens bypass 2FA permanently so your admin account can keep MFA enabled.'
    ],
    codeSnippet: `# Option A (MeshCentral Web UI — Recommended):
# My Account -> Account Security -> Login Tokens -> Create -> Name: "Vitrine RMM"
# Paste the returned Username (~t:...) and Password into Vitrine's two Token fields.

# Option C (CLI on your MeshCentral host — replace path if not in /opt/meshcentral):
cd /path/to/meshcentral   # e.g. /opt/meshcentral or /home/<user>/meshcentral
node node_modules/meshcentral/meshctrl.js --url wss://127.0.0.1:4430 \\
  --loginuser admin --loginpass 'YourPass' --token 123456 \\
  LoginTokens --add "Vitrine RMM"

# Optional settings inside meshcentral-data/config.json under "settings":
"allowFraming": true,
"disableAgentUpdate": true  # Lets Vitrine keep MeshCentral agent binaries Authenticode-signed!`
  },
  3: {
    title: 'Walkthrough: Setting Up the 3-Stage Authenticode & Code Signing API',
    subtitle: 'Ensuring the Modern GUI Installer, Companion Scripts, and Native MeshCentral Binary stay signed',
    bullets: [
      'Why 3-Stage Signing Matters: Antivirus/SmartScreen flags unsigned wrappers OR unsigned inner binaries. Vitrine signs (1) the native MeshCentral meshagent binary, (2) the Vitrine Tray/Elevation scripts, and (3) the outer Modern GUI Installer.',
      'Keeping Agent Updates Signed: When MeshCentral updates, stock MeshCentral normally pushes unsigned agent updates. Vitrine intercepts new MeshCentral agent binaries, signs them via your Signing API, and caches them in signedagents/ before allowing endpoints to update.',
      'Supported Signers: SignPath.io REST API, Azure KeyVault / DigiCert KeyLocker webhook, or a local osslsigncode / signtool microservice.'
    ],
    codeSnippet: `# Example SignTool / osslsigncode Signing Webhook Endpoint:
POST https://signer.msp-domain.example/sign
Content-Type: multipart/form-data; name="file"
# Returns SHA-256 Authenticode + RFC 3161 Timestamped PE/PS1 binary`
  },
  4: {
    title: 'Walkthrough: Reverse Proxy WebSockets vs. External ACME / Certbot TLS',
    subtitle: 'Preventing WebSocket disconnects while accessing Vitrine locally during initial setup',
    bullets: [
      'Local First-Boot Access: During initial guided setup, access Vitrine directly via http://localhost:8080 or your LAN IP.',
      'Option A (Reverse Proxy Handles TLS — Recommended): If using Nginx, Nginx Proxy Manager, Caddy, Traefik, or Cloudflare Tunnel in front of Vitrine & MeshCentral, pass WebSocket Upgrade headers and increase proxy_read_timeout so live PTY shells and KVM streams do not drop every 60 seconds.',
      'Option B (External Let\'s Encrypt / ACME Certificates): Terminate TLS with Caddy/Traefik/Certbot and supply the issued certificate paths in your container or reverse proxy.'
    ],
    codeSnippet: `# Critical Reverse Proxy Headers for Vitrine + MeshCentral WebSockets:
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_read_timeout 3600s;
proxy_send_timeout 3600s;`
  },
  5: {
    title: 'Walkthrough: Outbound SMTP & Admin Update Notification Routing',
    subtitle: 'Configuring email alerts, login banners, and automated PSA maintenance tickets',
    bullets: [
      'SMTP Relay: Use Mailgun, Amazon SES, Microsoft 365 (smtp.office365.com:587), or an internal postfix relay.',
      'Update Notifications: Choose whether new Vitrine Stable releases or Alpha commits trigger a Web UI banner at login, an email to admins, and/or an automated maintenance ticket in your PSA.'
    ],
    codeSnippet: `# Standard STARTTLS SMTP Configuration:
Host: smtp.office365.com (or smtp.mailgun.org)
Port: 587 (STARTTLS)
From: alerts@yourdomain.com`
  },
  6: {
    title: 'Walkthrough: OIDC Single Sign-On & Automated Self-Backup Retention',
    subtitle: 'Securing technician logins and scheduling automated self-restoring backups',
    bullets: [
      'OpenID Connect (Authentik / Entra ID / Okta): Create an OAuth2/OIDC Provider with Redirect URI https://rmm.yourdomain.com/api/auth/oidc/callback.',
      'Unified Self-Backup System: Every scheduled or pre-update backup bundles vitrine.db, the AES-256 LAPS vault, branding logos, and a schema version manifest into data/backups/.'
    ],
    codeSnippet: `# OIDC Redirect URI to register in Authentik / Keycloak / Entra ID:
https://rmm.yourdomain.com/api/auth/oidc/callback`
  }
};

export const OnboardingWizardModal: React.FC<OnboardingWizardModalProps> = ({
  settings,
  adminEmail,
  onClose,
  onSaved
}) => {
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState<Partial<Settings>>({
    ...settings,
    theme_mode: settings.theme_mode || 'system',
    tray_theme_mode: settings.tray_theme_mode || 'system',
    installer_gui_style: settings.installer_gui_style || 'modern_glass',
    installer_service_name: settings.installer_service_name || 'VitrineAgent',
    quicksupport_custom_domain: settings.quicksupport_custom_domain ?? '',
    quicksupport_url_path: settings.quicksupport_url_path || '/remote',
    tls_mode: settings.tls_mode || 'reverse_proxy',
    reverse_proxy_type: settings.reverse_proxy_type || 'nginx',
    code_signing_sign_ms2_binary: settings.code_signing_sign_ms2_binary ?? 1,
    code_signing_strict_verify: settings.code_signing_strict_verify ?? 1,
    backup_schedule_enabled: settings.backup_schedule_enabled ?? 1,
    backup_schedule_frequency: settings.backup_schedule_frequency || 'daily',
    backup_retention_count: settings.backup_retention_count || 14
  });

  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [showSaveMfa, setShowSaveMfa] = useState(false);
  const [pendingMfaAction, setPendingMfaAction] = useState<'save' | 'local_cfg'>('save');
  const [codeSigningManuallyToggled, setCodeSigningManuallyToggled] = useState(false);
  const [oidcManuallyToggled, setOidcManuallyToggled] = useState(false);
  const [guideOpenForStep, setGuideOpenForStep] = useState<number | null>(null);
  const [copiedProxyConfig, setCopiedProxyConfig] = useState(false);

  // Step 1: Brand / Default Companion Tray Icon Upload State
  const logoInputRef = useRef<HTMLInputElement | null>(null);
  const [cropLogoFile, setCropLogoFile] = useState<File | null>(null);
  const [uploadingLogo, setUploadingLogo] = useState(false);
  const [logoUploadMsg, setLogoUploadMsg] = useState<string | null>(null);
  const [logoUploadError, setLogoUploadError] = useState(false);

  const handleWizardLogoSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (logoInputRef.current) logoInputRef.current.value = '';
    if (!file) return;
    setLogoUploadMsg(null);
    setLogoUploadError(false);
    setCropLogoFile(file);
  };

  const handleWizardLogoCropped = async (cropped: { filename: string; base64Data: string }) => {
    setCropLogoFile(null);
    setUploadingLogo(true);
    setLogoUploadMsg(null);
    setLogoUploadError(false);
    try {
      const res = await uploadBrandLogo(cropped.filename, cropped.base64Data);
      if (res.success && res.brand_logo_url) {
        setFormData((prev) => ({ ...prev, brand_logo_url: res.brand_logo_url }));
        setLogoUploadMsg('Square custom icon saved for Web UI, installers & agent tray defaults.');
      } else {
        setLogoUploadError(true);
        setLogoUploadMsg(res.error || 'Failed to upload custom icon.');
      }
    } catch (err: any) {
      setLogoUploadError(true);
      setLogoUploadMsg(err?.message || 'Failed to upload custom icon.');
    } finally {
      setUploadingLogo(false);
    }
  };

  // Step 2: Local Detection, Two-Field Token, Auto-Generate, & Live MS2 Discovery State
  const initialTokenPair = parseMeshTokenPair(settings.meshcentral_api_token);
  const [localMesh, setLocalMesh] = useState<LocalMeshCentralDetection | null>(null);
  const [meshTokenUser, setMeshTokenUser] = useState(initialTokenPair.user);
  const [meshTokenPass, setMeshTokenPass] = useState(initialTokenPair.pass);
  const [meshTokenInitiallyMasked] = useState(initialTokenPair.isMasked);
  const [useCombinedTokenMode, setUseCombinedTokenMode] = useState(initialTokenPair.isCombinedOnly);
  const [tokenGuideTab, setTokenGuideTab] = useState<'webui' | 'auto' | 'cli'>('webui');
  const [copiedCliCmd, setCopiedCliCmd] = useState(false);

  const [autoMs2User, setAutoMs2User] = useState('admin');
  const [autoMs2Pass, setAutoMs2Pass] = useState('');
  const [autoMs2Totp, setAutoMs2Totp] = useState('');
  const [autoMs2TotpRequired, setAutoMs2TotpRequired] = useState(false);
  const [generatingToken, setGeneratingToken] = useState(false);
  const [autoTokenMsg, setAutoTokenMsg] = useState<string | null>(null);
  const [autoTokenIsError, setAutoTokenIsError] = useState(false);

  const [optAllowFraming, setOptAllowFraming] = useState(true);
  const [optDisableAgentUpdate, setOptDisableAgentUpdate] = useState(false);
  const [applyingLocalCfg, setApplyingLocalCfg] = useState(false);
  const [localCfgMsg, setLocalCfgMsg] = useState<string | null>(null);
  const [localCfgIsError, setLocalCfgIsError] = useState(false);

  const [discoveringMesh, setDiscoveringMesh] = useState(false);
  const [discoveryResult, setDiscoveryResult] = useState<MeshDiscoveryResult | null>(null);
  const [importNewGroups, setImportNewGroups] = useState(true);
  const [autoDeployCompanion, setAutoDeployCompanion] = useState(true);
  const [enforceLapsOnImport, setEnforceLapsOnImport] = useState(true);
  const [lockSignedUpdates, setLockSignedUpdates] = useState(true);
  const [importingMesh, setImportingMesh] = useState(false);
  const [importSummary, setImportSummary] = useState<string | null>(null);
  const [importIsError, setImportIsError] = useState(false);

  useEffect(() => {
    let active = true;
    fetchLocalMeshCentralStatus()
      .then((info) => {
        if (!active) return;
        setLocalMesh(info);
        if (info.detected) {
          if (info.allowFraming === true) setOptAllowFraming(false);
          if (info.disableAgentUpdate === true) setOptDisableAgentUpdate(false);
          if (info.detectedUrl) {
            setFormData((prev) => {
              const cur = String(prev.meshcentral_url || '').trim();
              if (!cur || cur === 'https://mesh.vitrine.local' || cur === 'https://mesh.yourdomain.com') {
                return { ...prev, meshcentral_url: info.detectedUrl || cur };
              }
              return prev;
            });
          }
        }
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, []);

  const syncTwoFieldToken = (nextUser: string, nextPass: string) => {
    const trimmedUser = nextUser.trim();
    if (trimmedUser && nextPass) {
      setFormData((prev) => ({ ...prev, meshcentral_api_token: `${trimmedUser}:${nextPass}` }));
    } else if (!trimmedUser && !nextPass && meshTokenInitiallyMasked) {
      setFormData((prev) => ({ ...prev, meshcentral_api_token: settings.meshcentral_api_token }));
    } else {
      setFormData((prev) => ({ ...prev, meshcentral_api_token: '' }));
    }
  };

  const handleMeshTokenUserChange = (rawVal: string) => {
    // Auto-split if the user pasted a combined ~t:TokenUser:TokenPass string
    if (rawVal.trim().startsWith('~t:')) {
      const parsed = parseMeshTokenPair(rawVal);
      if (parsed.pass) {
        setMeshTokenUser(parsed.user);
        setMeshTokenPass(parsed.pass);
        syncTwoFieldToken(parsed.user, parsed.pass);
        return;
      }
    }
    setMeshTokenUser(rawVal);
    syncTwoFieldToken(rawVal, meshTokenPass);
  };

  const handleMeshTokenPassChange = (rawPass: string) => {
    setMeshTokenPass(rawPass);
    syncTwoFieldToken(meshTokenUser, rawPass);
  };

  const handleAutoGenerateToken = async () => {
    const targetUrl = String(formData.meshcentral_url || localMesh?.detectedUrl || '').trim();
    if (!targetUrl) {
      setAutoTokenIsError(true);
      setAutoTokenMsg('Enter your MeshCentral 2 Server Endpoint URL above first.');
      return;
    }
    if (!autoMs2User.trim() || !autoMs2Pass) {
      setAutoTokenIsError(true);
      setAutoTokenMsg('Enter your MeshCentral admin username and password.');
      return;
    }
    setGeneratingToken(true);
    setAutoTokenMsg(null);
    setAutoTokenIsError(false);
    try {
      const res = await generateMeshCentralLoginToken({
        url: targetUrl,
        username: autoMs2User.trim(),
        password: autoMs2Pass,
        totp: autoMs2Totp.trim() || undefined,
        tokenName: 'Vitrine RMM',
        allowSelfSigned: Boolean(formData.meshcentral_allow_self_signed)
      });
      if (!res.success || !res.tokenUser || !res.tokenPass) {
        setAutoTokenIsError(true);
        setAutoTokenMsg(res.error || 'Unable to generate MeshCentral Login Token.');
        if (res.totpRequired) setAutoMs2TotpRequired(true);
        return;
      }
      setUseCombinedTokenMode(false);
      setMeshTokenUser(res.tokenUser);
      setMeshTokenPass(res.tokenPass);
      const combined = res.combinedToken || `${res.tokenUser}:${res.tokenPass}`;
      setFormData((prev) => ({
        ...prev,
        meshcentral_url: prev.meshcentral_url || targetUrl,
        meshcentral_api_token: combined
      }));
      // Immediately clear ephemeral admin password and TOTP from component memory
      setAutoMs2Pass('');
      setAutoMs2Totp('');
      setAutoMs2TotpRequired(false);
      setAutoTokenIsError(false);
      setAutoTokenMsg(
        `✓ Created Login Token "${res.tokenName || 'Vitrine RMM'}" and populated the Token Username & Password fields above.`
      );
    } catch (err: any) {
      setAutoTokenIsError(true);
      setAutoTokenMsg(err?.message || 'Failed to contact MeshCentral server.');
    } finally {
      setGeneratingToken(false);
    }
  };

  const handleApplyLocalConfig = async () => {
    setApplyingLocalCfg(true);
    setLocalCfgMsg(null);
    setLocalCfgIsError(false);
    try {
      const res = await applyLocalMeshCentralConfig({
        allowFraming: optAllowFraming,
        disableAgentUpdate: optDisableAgentUpdate
      });
      if (res.mfaRequired) {
        setPendingMfaAction('local_cfg');
        setShowSaveMfa(true);
        return;
      }
      if (!res.success) {
        setLocalCfgIsError(true);
        setLocalCfgMsg(res.error || 'Failed to update local config.json.');
        return;
      }
      setLocalCfgIsError(false);
      setLocalCfgMsg(
        `✓ Updated ${res.configPath} (backup: ${res.backupPath}). ${res.restartHint || ''}`
      );
      fetchLocalMeshCentralStatus().then(setLocalMesh).catch(() => {});
    } catch (err: any) {
      setLocalCfgIsError(true);
      setLocalCfgMsg(err?.message || 'Failed to update local config.json.');
    } finally {
      setApplyingLocalCfg(false);
    }
  };

  // Step 3: Code Signing Test State
  const [testingSigner, setTestingSigner] = useState(false);
  const [signerResult, setSignerResult] = useState<string | null>(null);
  const [signerIsError, setSignerIsError] = useState(false);

  // Step 4: Reverse Proxy / TLS Test State
  const [testingProxy, setTestingProxy] = useState(false);
  const [proxyTestChecks, setProxyTestChecks] = useState<Array<{ name: string; status: string; detail: string }> | null>(null);

  // Step 5: Outbound SMTP Credential Verification & Test Email State
  const [smtpTestRecipient, setSmtpTestRecipient] = useState(adminEmail || '');
  const [smtpTestingMode, setSmtpTestingMode] = useState<'verify' | 'send' | null>(null);
  const [smtpTestResult, setSmtpTestResult] = useState<string | null>(null);
  const [smtpTestIsError, setSmtpTestIsError] = useState(false);

  // Step 6: Initial Baseline Backup Option + OIDC Test + Backup Encryption Key Escrow
  const [createInitialBackup, setCreateInitialBackup] = useState(true);
  const [testingOidc, setTestingOidc] = useState(false);
  const [oidcTestMsg, setOidcTestMsg] = useState<string | null>(null);
  const [oidcIsError, setOidcIsError] = useState(false);
  const [revealedWizardBackupKey, setRevealedWizardBackupKey] = useState<string | null>(null);
  const [revealingBackupKey, setRevealingBackupKey] = useState(false);
  const [backupKeyError, setBackupKeyError] = useState<string | null>(null);
  const [acknowledgingBackupKey, setAcknowledgingBackupKey] = useState(false);
  const [backupKeyAckNotice, setBackupKeyAckNotice] = useState<string | null>(null);
  const [showWizardBackupKeyMfa, setShowWizardBackupKeyMfa] = useState(false);
  const [copiedWizardBackupKey, setCopiedWizardBackupKey] = useState(false);

  const handleRevealWizardBackupKey = async () => {
    if (revealingBackupKey) return;
    setRevealingBackupKey(true);
    setBackupKeyError(null);
    try {
      const res = await revealBackupRecoveryKey();
      if (res.mfaRequired) {
        setShowWizardBackupKeyMfa(true);
        return;
      }
      if (res.success && res.passphrase) {
        setRevealedWizardBackupKey(res.passphrase);
        setFormData((prev) => ({ ...prev, backup_key_acknowledged: 1 }));
        setBackupKeyAckNotice(null);
      } else {
        setBackupKeyError(
          res.error || 'Unable to reveal the backup recovery passphrase. Please try again.'
        );
      }
    } catch (err: any) {
      setBackupKeyError(
        err?.message || 'Unable to reach Vitrine server to reveal the backup recovery passphrase.'
      );
    } finally {
      setRevealingBackupKey(false);
    }
  };

  const handleDownloadWizardBackupKit = (passphrase: string) => {
    const content = [
      `${formData.brand_name || 'Vitrine RMM'} — Disaster Recovery Backup Encryption Key`,
      `Generated: ${new Date().toISOString()}`,
      '',
      'IMPORTANT: Store this passphrase in an external password manager (1Password, Bitwarden, Keeper).',
      'You will need this passphrase to decrypt .vrmm-backup.gz archives during bare-metal or cross-host disaster recovery.',
      '',
      `AES-256-GCM Backup Passphrase:`,
      passphrase
    ].join('\n');
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'vitrine-rmm-backup-encryption-key.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleTestDiscoverMesh = async () => {
    setDiscoveringMesh(true);
    setImportSummary(null);
    try {
      const res = await testDiscoverMeshServer({
        url: formData.meshcentral_url,
        api_token: formData.meshcentral_api_token,
        allowSelfSigned: Boolean(formData.meshcentral_allow_self_signed)
      });
      setDiscoveryResult(res);
    } catch (err: any) {
      setDiscoveryResult({
        success: false,
        reachable: false,
        authenticated: false,
        meshVersion: '',
        coexistenceSafe: false,
        tlsVerified: false,
        summary: err?.message || 'MeshCentral discovery request failed.',
        error: err?.message || 'Unable to connect to MeshCentral server.',
        discoveredGroups: [],
        discoveredAgents: [],
        serverUrl: formData.meshcentral_url || ''
      });
    } finally {
      setDiscoveringMesh(false);
    }
  };

  const handleImportDiscoveredMesh = async () => {
    setImportingMesh(true);
    try {
      const res = await importFromMeshServer({
        mesh_server_id: 'ms2-primary',
        url: formData.meshcentral_url,
        api_token: formData.meshcentral_api_token,
        allowSelfSigned: Boolean(formData.meshcentral_allow_self_signed),
        import_new_groups: importNewGroups,
        auto_deploy_companion: autoDeployCompanion,
        enforce_laps_on_import: enforceLapsOnImport,
        lock_signed_binary_updates: lockSignedUpdates
      });
      if (res.success) {
        setImportIsError(false);
        setImportSummary(res.message);
      } else {
        setImportIsError(true);
        setImportSummary('Unable to import: check MeshCentral URL & API token.');
      }
    } catch (err: any) {
      setImportIsError(true);
      setImportSummary(err?.message || 'Unable to import from MeshCentral.');
    } finally {
      setImportingMesh(false);
    }
  };

  const handleTestCodeSigning = async () => {
    setTestingSigner(true);
    try {
      const res = await testCodeSigningPipeline(formData.code_signing_url);
      if (res.success) {
        if (!codeSigningManuallyToggled) {
          setFormData((prev) => ({ ...prev, code_signing_enabled: 1 }));
        }
        setSignerIsError(false);
        setSignerResult(
          `Verified Code Signing Pipeline (${res.hsmStatus}) • ${res.ms2AutoUpdateProtection}`
        );
      } else {
        setSignerIsError(true);
        setSignerResult(`Signing endpoint check failed: ${res.error || res.hsmStatus || 'Unreachable'}`);
      }
    } catch (err: any) {
      setSignerIsError(true);
      setSignerResult(`Signing endpoint check failed: ${err?.message || 'Unreachable'}`);
    } finally {
      setTestingSigner(false);
    }
  };

  const handleTestProxy = async () => {
    setTestingProxy(true);
    try {
      const res = await testProxyTlsSetup({
        tls_mode: formData.tls_mode,
        reverse_proxy_type: formData.reverse_proxy_type,
        custom_domain: formData.custom_domain,
        quicksupport_custom_domain: formData.quicksupport_custom_domain
      });
      setProxyTestChecks(res.checks);
    } catch (err: any) {
      setProxyTestChecks([
        {
          name: 'Proxy & TLS Verification',
          status: 'fail',
          detail: err?.message || 'Failed to verify reverse proxy / TLS setup.'
        }
      ]);
    } finally {
      setTestingProxy(false);
    }
  };

  const runSmtpTest = async (verifyOnly: boolean) => {
    const host = String(formData.smtp_host || '').trim();
    if (!host) {
      setSmtpTestIsError(true);
      setSmtpTestResult('Enter an SMTP Relay Host first.');
      return;
    }
    const recipient = smtpTestRecipient.trim();
    if (!verifyOnly && (!recipient || !recipient.includes('@'))) {
      setSmtpTestIsError(true);
      setSmtpTestResult('Enter a valid recipient email address to send a test email.');
      return;
    }

    setSmtpTestingMode(verifyOnly ? 'verify' : 'send');
    setSmtpTestResult(null);
    setSmtpTestIsError(false);
    try {
      const res = await testSmtp({
        host,
        port: Number(formData.smtp_port) || 587,
        user: formData.smtp_user || '',
        pass: formData.smtp_pass || '',
        from: formData.smtp_from || 'alerts@vitrine.local',
        ...(verifyOnly ? { verifyOnly: true } : { to: recipient, verifyOnly: false })
      });
      setSmtpTestIsError(!res.success);
      setSmtpTestResult(
        res.message ||
          (res.success
            ? verifyOnly
              ? 'SMTP connection and credentials verified.'
              : `Test email dispatched to ${recipient}.`
            : res.error || 'SMTP test failed.')
      );
    } catch (err: any) {
      setSmtpTestIsError(true);
      setSmtpTestResult(`SMTP test failed: ${err?.message || 'Connection error'}`);
    } finally {
      setSmtpTestingMode(null);
    }
  };

  const getGeneratedProxyConfig = () => {
    const rmmDomain = formData.custom_domain || 'rmm.yourdomain.com';
    const qsDomain = formData.quicksupport_custom_domain || 'remote.yourdomain.com';
    const proxyType = formData.reverse_proxy_type || 'nginx';

    if (proxyType === 'caddy') {
      return `${rmmDomain}, ${qsDomain} {
    # Co-existence safe reverse proxy with automatic WebSocket upgrade
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Forwarded-Proto {scheme}
        header_up X-Forwarded-For {remote_host}
    }
}`;
    }

    if (proxyType === 'traefik') {
      return `# Traefik v3 Dynamic File Provider (http/routes.yml)
http:
  routers:
    vitrine-rmm:
      rule: "Host(\`${rmmDomain}\`) || Host(\`${qsDomain}\`)"
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt
      service: vitrine-rmm
  services:
    vitrine-rmm:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"`;
    }

    if (proxyType === 'cloudflare') {
      return `# Cloudflare Tunnel (cloudflared config.yml)
tunnel: <YOUR-TUNNEL-UUID>
credentials-file: /etc/cloudflared/<YOUR-TUNNEL-UUID>.json

ingress:
  - hostname: ${rmmDomain}
    service: http://127.0.0.1:8080
  - hostname: ${qsDomain}
    service: http://127.0.0.1:8080
  - service: http_status:404`;
    }

    return `server {
    listen 443 ssl http2;
    server_name ${rmmDomain} ${qsDomain};

    # Redirect root on QuickSupport domain directly to /remote portal
    if ($host = "${qsDomain}") {
        rewrite ^/$ ${formData.quicksupport_url_path || '/remote'} redirect;
    }

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}`;
  };

  const handleSave = async () => {
    setSaving(true);
    setSaveError(null);
    try {
      const res = await updateSettings({
        ...formData,
        oobe_completed: 1,
        is_onboarded: 1
      });
      if (res.mfaRequired) {
        setShowSaveMfa(true);
        return;
      }
      if (!res.success) {
        setSaveError(res.error || 'Failed to save initial setup configuration.');
        return;
      }
      if (createInitialBackup) {
        await createSystemBackup({
          triggerType: 'manual',
          notes: 'Initial Post-Setup Baseline Backup Snapshot'
        }).catch(() => {});
      }
      onSaved(res.settings);
      onClose();
    } catch (err: any) {
      setSaveError(err?.message || 'Failed to save initial setup configuration.');
    } finally {
      setSaving(false);
    }
  };

  const steps = [
    { num: 1, title: '1. Brand & GUI', icon: Palette },
    { num: 2, title: '2. Mesh & Import', icon: Server },
    { num: 3, title: '3. Code Signing', icon: KeyRound },
    { num: 4, title: '4. Proxy & TLS', icon: Lock },
    { num: 5, title: '5. SMTP & Alerts', icon: Mail },
    { num: 6, title: '6. SSO & Backups', icon: HardDrive }
  ];

  return (
    <div className="modal-backdrop" id="onboarding-wizard-modal" style={{ zIndex: 1100 }}>
      <div className="glass-modal glass-modal-lg" style={{ maxWidth: '940px' }}>
        {/* Header */}
        <div className="modal-header">
          <div className="modal-title" style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Sparkles size={20} style={{ color: '#00f2fe' }} />
            <span>Initial Setup Wizard</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button
              type="button"
              className="btn-glass"
              onClick={() => setGuideOpenForStep(step)}
              style={{
                fontSize: '0.76rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.35rem',
                borderColor: 'rgba(0, 242, 254, 0.45)',
                color: '#00f2fe'
              }}
            >
              <HelpCircle size={14} />
              <span>Step {step} Setup Guide</span>
            </button>
            <button className="btn-glass btn-icon" onClick={onClose} id="close-wizard-btn">
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Wizard Step Progress */}
        <div style={{ display: 'flex', borderBottom: '1px solid var(--glass-border)', background: 'rgba(0, 0, 0, 0.18)', overflowX: 'auto' }}>
          {steps.map((s) => {
            const Icon = s.icon;
            const isCurrent = step === s.num;
            const isCompleted = step > s.num;
            return (
              <button
                key={s.num}
                type="button"
                onClick={() => setStep(s.num)}
                style={{
                  flex: 1,
                  minWidth: '130px',
                  padding: '0.75rem 0.65rem',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '0.45rem',
                  background: isCurrent ? 'rgba(0, 242, 254, 0.12)' : 'transparent',
                  border: 'none',
                  borderBottom: isCurrent ? '2px solid var(--primary)' : '2px solid transparent',
                  color: isCurrent ? 'var(--text-main)' : 'var(--text-muted)',
                  cursor: 'pointer',
                  fontSize: '0.76rem',
                  fontWeight: isCurrent ? 700 : 500
                }}
              >
                <div
                  style={{
                    width: '20px',
                    height: '20px',
                    borderRadius: '50%',
                    background: isCompleted ? '#10b981' : isCurrent ? 'var(--primary)' : 'rgba(255, 255, 255, 0.15)',
                    color: '#000',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '0.7rem',
                    fontWeight: 800
                  }}
                >
                  {isCompleted ? '✓' : s.num}
                </div>
                <Icon size={13} />
                <span>{s.title}</span>
              </button>
            );
          })}
        </div>

        {/* Body */}
        <div className="modal-body" style={{ minHeight: '420px', maxHeight: '72vh', overflowY: 'auto' }}>
          {/* STEP 1: BRANDING, ADAPTIVE THEME & MODERN INSTALLER GUI */}
          {step === 1 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.15rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem' }}>
                <div className="form-group">
                  <label className="form-label">Brand / Application Name</label>
                  <input
                    type="text"
                    className="glass-input"
                    value={formData.brand_name || ''}
                    onChange={(e) => setFormData({ ...formData, brand_name: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Primary RMM Domain</label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="rmm.yourdomain.com"
                    value={formData.custom_domain || ''}
                    onChange={(e) => setFormData({ ...formData, custom_domain: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Public QuickSupport Domain / Path</label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="remote.yourdomain.com"
                    value={formData.quicksupport_custom_domain || ''}
                    onChange={(e) => setFormData({ ...formData, quicksupport_custom_domain: e.target.value })}
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem' }}>
                <div className="form-group">
                  <label className="form-label">Web UI &amp; Portal Theme Mode</label>
                  <select
                    className="glass-select"
                    value={formData.theme_mode || 'system'}
                    onChange={(e) => setFormData({ ...formData, theme_mode: e.target.value as 'system' | 'dark' | 'light' })}
                  >
                    <option value="system">System / Browser Auto (Respects OS Light/Dark)</option>
                    <option value="dark">Force Dark Glassmorphic</option>
                    <option value="light">Force Daylight Crisp Light</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Endpoint Tray &amp; Installer Theme</label>
                  <select
                    className="glass-select"
                    value={formData.tray_theme_mode || 'system'}
                    onChange={(e) => setFormData({ ...formData, tray_theme_mode: e.target.value as 'system' | 'dark' | 'light' })}
                  >
                    <option value="system">OS Registry Auto (AppsUseLightTheme / Dark)</option>
                    <option value="dark">Always Dark Tray &amp; HUD</option>
                    <option value="light">Always Light Tray &amp; HUD</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Primary Accent Color</label>
                  <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                    <input
                      type="color"
                      value={formData.primary_color || '#00f2fe'}
                      onChange={(e) => setFormData({ ...formData, primary_color: e.target.value })}
                      style={{ width: '42px', height: '36px', borderRadius: '6px', border: 'none', cursor: 'pointer', background: 'transparent' }}
                    />
                    <input
                      type="text"
                      className="glass-input"
                      value={formData.primary_color || '#00f2fe'}
                      onChange={(e) => setFormData({ ...formData, primary_color: e.target.value })}
                    />
                  </div>
                </div>
              </div>

              <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--glass-border)', padding: '1rem', borderRadius: '8px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div className="form-group">
                  <label className="form-label">Modern Vitrine Installer Architecture</label>
                  <select
                    className="glass-select"
                    value={formData.installer_gui_style || 'modern_glass'}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        installer_gui_style: e.target.value as 'modern_glass' | 'silent_headless' | 'native_ms2'
                      })
                    }
                  >
                    <option value="modern_glass">Branded Guided Installer (Recommended)</option>
                    <option value="silent_headless">Zero-Touch Silent Service Installer (GPO / Intune)</option>
                    <option value="native_ms2">Stock MeshCentral 2 Native Dialog</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Custom Endpoint Service Name</label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="VitrineAgent"
                    value={formData.installer_service_name || 'VitrineAgent'}
                    onChange={(e) => setFormData({ ...formData, installer_service_name: e.target.value })}
                  />
                </div>
              </div>

              <div
                style={{
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid var(--glass-border)',
                  padding: '0.9rem 1rem',
                  borderRadius: '8px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '1rem',
                  flexWrap: 'wrap'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                  {formData.brand_logo_url ? (
                    <img
                      src={formData.brand_logo_url}
                      alt="Brand Logo"
                      style={{ height: '38px', width: '38px', borderRadius: '8px', objectFit: 'contain', background: 'rgba(0,0,0,0.35)', padding: '3px' }}
                    />
                  ) : (
                    <div
                      style={{
                        height: '38px',
                        width: '38px',
                        borderRadius: '8px',
                        background: 'rgba(0, 242, 254, 0.1)',
                        border: '1px dashed rgba(0, 242, 254, 0.35)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: 'var(--primary)'
                      }}
                    >
                      <Palette size={18} />
                    </div>
                  )}
                  <div>
                    <div style={{ fontSize: '0.84rem', fontWeight: 600 }}>Brand Logo &amp; Default Companion Tray Icon</div>
                    <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                      Used across the Web UI, agent installer GUI, and endpoint system tray (can be overridden per Client, Site, or Role in Policies).
                    </div>
                    {logoUploadMsg && (
                      <div style={{ fontSize: '0.73rem', marginTop: '0.25rem', color: logoUploadError ? '#f87171' : '#34d399' }}>
                        {logoUploadMsg}
                      </div>
                    )}
                  </div>
                </div>
                <div>
                  <input
                    ref={logoInputRef}
                    type="file"
                    accept="image/png,image/jpeg,image/webp,image/x-icon,.ico"
                    style={{ display: 'none' }}
                    onChange={handleWizardLogoSelect}
                  />
                  <button
                    type="button"
                    className="btn-glass"
                    style={{ fontSize: '0.78rem' }}
                    disabled={uploadingLogo}
                    onClick={() => logoInputRef.current?.click()}
                  >
                    <Upload size={14} /> {uploadingLogo ? 'Uploading...' : formData.brand_logo_url ? 'Change Icon / Logo' : 'Upload Icon / Logo'}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* STEP 2: MESHCENTRAL 2 CONNECTION, LOGIN TOKEN & LIVE DISCOVERY IMPORT */}
          {step === 2 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.95rem' }}>
              {localMesh?.detected ? (
                <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', padding: '0.75rem 1rem', borderRadius: '8px', fontSize: '0.78rem' }}>
                  <strong style={{ color: '#34d399' }}>✓ Local MeshCentral 2 Instance Detected ({localMesh.installDir || localMesh.serviceName}):</strong>{' '}
                  Vitrine is running in isolated co-existence mode alongside it and will never overwrite or stop your existing MeshCentral service.
                </div>
              ) : (
                <div style={{ background: 'rgba(56, 189, 248, 0.1)', border: '1px solid rgba(56, 189, 248, 0.3)', padding: '0.75rem 1rem', borderRadius: '8px', fontSize: '0.78rem', color: '#bae6fd' }}>
                  <strong style={{ color: '#38bdf8' }}>
                    {localMesh?.deploymentMode === 'docker' ? '🐳 Docker Container Mode' : '🖥️ Standalone Host Detected'}:
                  </strong>{' '}
                  No local MeshCentral 2 installation was found on this machine. Enter your remote MeshCentral 2 server URL and Login Token below (or auto-generate one over TLS).
                </div>
              )}

              <div style={{ display: 'grid', gridTemplateColumns: '1.5fr auto', gap: '0.85rem', alignItems: 'end' }}>
                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label className="form-label">Primary MeshCentral 2 Server Endpoint URL</label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder={localMesh?.detectedUrl || 'https://mesh.yourdomain.com (or https://10.0.0.50:4430)'}
                    value={formData.meshcentral_url || ''}
                    onChange={(e) => setFormData({ ...formData, meshcentral_url: e.target.value })}
                  />
                </div>

                <button
                  type="button"
                  className="btn-glass btn-primary"
                  onClick={handleTestDiscoverMesh}
                  disabled={discoveringMesh}
                  style={{ height: '40px', whiteSpace: 'nowrap' }}
                >
                  <RefreshCw size={14} className={discoveringMesh ? 'spin' : ''} />
                  <span>{discoveringMesh ? 'Scanning MeshCentral...' : 'Test & Discover Fleet'}</span>
                </button>
              </div>

              {!useCombinedTokenMode ? (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                  <div className="form-group">
                    <label className="form-label">Login Token Username (from MeshCentral)</label>
                    <input
                      type="text"
                      className="glass-input"
                      placeholder={meshTokenInitiallyMasked ? 'Saved in vault (leave blank to keep)' : '~t:AbCdEf123456 (or admin)'}
                      value={meshTokenUser}
                      onChange={(e) => handleMeshTokenUserChange(e.target.value)}
                    />
                  </div>

                  <div className="form-group">
                    <label className="form-label">Login Token Password (from MeshCentral)</label>
                    <input
                      type="password"
                      className="glass-input"
                      placeholder={meshTokenInitiallyMasked ? '•••••••••••• (leave blank to keep)' : 'Generated Token Password'}
                      value={meshTokenPass}
                      onChange={(e) => handleMeshTokenPassChange(e.target.value)}
                    />
                  </div>
                </div>
              ) : (
                <div className="form-group">
                  <label className="form-label">Combined Login Token / Base64 x-meshauth / Cookie Token</label>
                  <input
                    type="password"
                    className="glass-input"
                    placeholder="~t:TokenUser:TokenPass or base64(user),base64(pass)"
                    value={formData.meshcentral_api_token || ''}
                    onChange={(e) => setFormData({ ...formData, meshcentral_api_token: e.target.value })}
                  />
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem', fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                <button
                  type="button"
                  onClick={() => setUseCombinedTokenMode((v) => !v)}
                  style={{
                    background: 'none',
                    border: 'none',
                    padding: 0,
                    color: '#38bdf8',
                    cursor: 'pointer',
                    textDecoration: 'underline',
                    fontSize: '0.74rem'
                  }}
                >
                  {useCombinedTokenMode
                    ? 'Switch to separate Token Username + Password fields'
                    : 'Paste a raw base64 x-meshauth string or cookie token instead'}
                </button>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', cursor: 'pointer', color: 'var(--text-main)' }}>
                  <input
                    type="checkbox"
                    checked={Boolean(formData.meshcentral_allow_self_signed)}
                    onChange={(e) => setFormData({ ...formData, meshcentral_allow_self_signed: e.target.checked ? 1 : 0 })}
                  />
                  <span>Allow self-signed TLS certificate</span>
                </label>
              </div>

              {/* 3-Option MeshCentral Login Token Helper */}
              <div
                style={{
                  background: 'rgba(15, 23, 42, 0.45)',
                  border: '1px solid var(--glass-border)',
                  borderRadius: '10px',
                  padding: '0.85rem 1rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.75rem'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#e2e8f0', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <KeyRound size={14} color="var(--primary)" />
                    <span>How to Get a 2FA-Safe MeshCentral Login Token</span>
                  </div>
                  <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                    {(
                      [
                        { id: 'webui', label: 'Web UI (Easiest)' },
                        { id: 'auto', label: 'Auto-Generate in Vitrine' },
                        { id: 'cli', label: 'CLI (meshctrl.js)' }
                      ] as const
                    ).map((t) => (
                      <button
                        key={t.id}
                        type="button"
                        className={`btn-glass ${tokenGuideTab === t.id ? 'btn-primary' : ''}`}
                        style={{ fontSize: '0.72rem', padding: '0.28rem 0.65rem' }}
                        onClick={() => setTokenGuideTab(t.id)}
                      >
                        {t.label}
                      </button>
                    ))}
                  </div>
                </div>

                {tokenGuideTab === 'webui' && (
                  <ol style={{ margin: 0, paddingLeft: '1.25rem', fontSize: '0.76rem', color: '#cbd5e1', lineHeight: 1.55 }}>
                    <li>Log into your MeshCentral 2 Web UI and click <strong>My Account</strong> in the left sidebar.</li>
                    <li>Under <strong>Account Security</strong>, click <strong>Manage...</strong> next to <strong>Login Tokens</strong>, then click <strong>Create</strong>.</li>
                    <li>Enter a name like <code>Vitrine RMM</code> (set expiration to <em>Never expires</em>) and click <strong>OK</strong>.</li>
                    <li>Copy both the generated <strong>Username</strong> (<code>~t:...</code>) and <strong>Password</strong> into the two fields above. Login Tokens bypass 2FA/TOTP automatically while keeping MFA enabled on your admin account.</li>
                  </ol>
                )}

                {tokenGuideTab === 'auto' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                    <div style={{ fontSize: '0.74rem', color: '#94a3b8' }}>
                      Enter your MeshCentral admin credentials once to mint a persistent <code>Vitrine RMM</code> Login Token directly over WebSockets (works for both remote and local servers; credentials are cleared immediately after generation and never saved).
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 0.8fr auto', gap: '0.6rem', alignItems: 'end' }}>
                      <div className="form-group">
                        <label className="form-label" style={{ fontSize: '0.72rem' }}>MeshCentral Admin Username</label>
                        <input
                          type="text"
                          className="glass-input"
                          placeholder="admin"
                          value={autoMs2User}
                          onChange={(e) => setAutoMs2User(e.target.value)}
                        />
                      </div>
                      <div className="form-group">
                        <label className="form-label" style={{ fontSize: '0.72rem' }}>MeshCentral Admin Password</label>
                        <input
                          type="password"
                          className="glass-input"
                          placeholder="Admin Password (not saved)"
                          value={autoMs2Pass}
                          onChange={(e) => setAutoMs2Pass(e.target.value)}
                        />
                      </div>
                      <div className="form-group">
                        <label
                          className="form-label"
                          style={{ fontSize: '0.72rem', color: autoMs2TotpRequired ? '#fbbf24' : undefined }}
                        >
                          {autoMs2TotpRequired ? '2FA TOTP Required' : '2FA Code (if enabled)'}
                        </label>
                        <input
                          type="text"
                          className="glass-input"
                          placeholder="123456"
                          value={autoMs2Totp}
                          onChange={(e) => setAutoMs2Totp(e.target.value)}
                          style={autoMs2TotpRequired ? { borderColor: '#f59e0b' } : undefined}
                        />
                      </div>
                      <button
                        type="button"
                        className="btn-glass btn-primary"
                        onClick={handleAutoGenerateToken}
                        disabled={generatingToken}
                        style={{ height: '38px', fontSize: '0.76rem', whiteSpace: 'nowrap' }}
                      >
                        <KeyRound size={14} />
                        <span>{generatingToken ? 'Generating...' : 'Generate Token'}</span>
                      </button>
                    </div>
                    {autoTokenMsg && (
                      <div style={{ fontSize: '0.76rem', color: autoTokenIsError ? '#f87171' : '#34d399', fontWeight: 600 }}>
                        {autoTokenMsg}
                      </div>
                    )}
                  </div>
                )}

                {tokenGuideTab === 'cli' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <div style={{ fontSize: '0.74rem', color: '#94a3b8' }}>
                      Run on your MeshCentral 2 server (omit <code>--token 123456</code> if 2FA is disabled on that account):
                    </div>
                    {(() => {
                      const cliDir = localMesh?.detected && localMesh.installDir
                        ? localMesh.installDir
                        : '/path/to/meshcentral  # e.g. /opt/meshcentral or /home/<user>/meshcentral';
                      const wsTarget = (formData.meshcentral_url || localMesh?.detectedUrl || 'https://127.0.0.1:4430').replace(/^http/i, 'ws');
                      const cliCmd = `cd ${cliDir}\nnode node_modules/meshcentral/meshctrl.js --url ${wsTarget} --loginuser admin --loginpass 'YourPass' --token 123456 LoginTokens --add "Vitrine RMM"`;
                      return (
                        <div style={{ position: 'relative' }}>
                          <pre
                            style={{
                              margin: 0,
                              padding: '0.65rem 0.75rem',
                              borderRadius: '8px',
                              background: 'rgba(2, 6, 23, 0.72)',
                              border: '1px solid rgba(148, 163, 184, 0.2)',
                              color: '#e2e8f0',
                              fontSize: '0.72rem',
                              overflowX: 'auto',
                              whiteSpace: 'pre-wrap'
                            }}
                          >
                            {cliCmd}
                          </pre>
                          <button
                            type="button"
                            className="btn-glass"
                            style={{ position: 'absolute', top: '0.45rem', right: '0.45rem', fontSize: '0.68rem', padding: '0.2rem 0.45rem' }}
                            onClick={async () => {
                              await copyToClipboard(cliCmd);
                              setCopiedCliCmd(true);
                              setTimeout(() => setCopiedCliCmd(false), 2000);
                            }}
                          >
                            {copiedCliCmd ? <Check size={12} /> : <Copy size={12} />}
                          </button>
                        </div>
                      );
                    })()}
                  </div>
                )}
              </div>

              {/* Opt-In Local MS2 config.json Helper (strictly shown only when local MS2 is detected) */}
              {localMesh?.detected && localMesh.configPath && (
                <div
                  style={{
                    background: 'rgba(255, 255, 255, 0.03)',
                    border: '1px solid rgba(148, 163, 184, 0.22)',
                    borderRadius: '10px',
                    padding: '0.85rem 1rem',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.6rem'
                  }}
                >
                  <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#e2e8f0' }}>
                    Optional Local MeshCentral Config Settings (<code>{localMesh.configPath}</code>)
                  </div>
                  <div style={{ fontSize: '0.73rem', color: '#94a3b8' }}>
                    Status: <code>allowFraming</code> = <strong>{localMesh.allowFraming === true ? 'true' : localMesh.allowFraming === false ? 'false' : 'unset'}</strong>{' '}
                    • <code>disableAgentUpdate</code> = <strong>{localMesh.disableAgentUpdate === true ? 'true' : localMesh.disableAgentUpdate === false ? 'false' : 'unset'}</strong>
                  </div>
                  {localMesh.configJsonValid && localMesh.configWritable ? (
                    <>
                      <div style={{ display: 'flex', gap: '1.25rem', flexWrap: 'wrap', fontSize: '0.76rem' }}>
                        <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer' }}>
                          <input
                            type="checkbox"
                            checked={optAllowFraming}
                            onChange={(e) => setOptAllowFraming(e.target.checked)}
                          />
                          <span>Set <code>&quot;allowFraming&quot;: true</code> (embedded KVM viewer)</span>
                        </label>
                        <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer' }}>
                          <input
                            type="checkbox"
                            checked={optDisableAgentUpdate}
                            onChange={(e) => setOptDisableAgentUpdate(e.target.checked)}
                          />
                          <span>Set <code>&quot;disableAgentUpdate&quot;: true</code> (preserves code-signed agents)</span>
                        </label>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                        <button
                          type="button"
                          className="btn-glass"
                          disabled={applyingLocalCfg || (!optAllowFraming && !optDisableAgentUpdate)}
                          onClick={handleApplyLocalConfig}
                          style={{ fontSize: '0.74rem', padding: '0.35rem 0.75rem' }}
                        >
                          <Shield size={13} />
                          <span>{applyingLocalCfg ? 'Backing up & Saving...' : 'Backup & Apply to Local config.json'}</span>
                        </button>
                        {localCfgMsg && (
                          <span style={{ fontSize: '0.74rem', color: localCfgIsError ? '#f87171' : '#34d399', fontWeight: 600 }}>
                            {localCfgMsg}
                          </span>
                        )}
                      </div>
                    </>
                  ) : (
                    <div style={{ fontSize: '0.73rem', color: '#fbbf24' }}>
                      {!localMesh.configWritable
                        ? 'Local config.json is not writable by the Vitrine service user; add "allowFraming": true under "settings" manually if needed.'
                        : 'Local config.json contains comments/JSONC syntax; edit manually under "settings" to preserve comments.'}
                    </div>
                  )}
                </div>
              )}

              {discoveryResult && (!discoveryResult.reachable || discoveryResult.authenticated === false) && (
                <div
                  style={{
                    background: 'rgba(239, 68, 68, 0.14)',
                    border: '1px solid rgba(239, 68, 68, 0.35)',
                    borderRadius: '10px',
                    padding: '0.85rem 1rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.6rem',
                    fontSize: '0.82rem',
                    color: '#f87171'
                  }}
                >
                  <AlertCircle size={16} style={{ flexShrink: 0 }} />
                  <span>{discoveryResult.error || discoveryResult.summary || 'MeshCentral server unreachable'}</span>
                </div>
              )}

              {discoveryResult && discoveryResult.reachable && discoveryResult.authenticated !== false && (
                <div
                  style={{
                    background: 'rgba(0, 0, 0, 0.28)',
                    border: '1px solid rgba(0, 242, 254, 0.3)',
                    borderRadius: '10px',
                    padding: '1rem',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.85rem'
                  }}
                >
                  <div style={{ fontSize: '0.82rem', color: '#7dd3fc', fontWeight: 600 }}>
                    ✓ {discoveryResult.summary}
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                    <div style={{ background: 'rgba(255,255,255,0.03)', padding: '0.75rem', borderRadius: '8px' }}>
                      <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--primary)', marginBottom: '0.4rem' }}>
                        DISCOVERED MESHCENTRAL DEVICE GROUPS ({discoveryResult.discoveredGroups.length})
                      </div>
                      {discoveryResult.discoveredGroups.map((g) => (
                        <div key={g.meshGroupId} style={{ fontSize: '0.75rem', padding: '0.3rem 0', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'space-between' }}>
                          <span>
                            <strong>{g.name}</strong> ({g.agentCount} agents)
                          </span>
                          <span style={{ color: g.matchedTenantId ? '#10b981' : '#f59e0b' }}>
                            {g.matchedTenantId ? 'Matches Existing Client' : 'New Client Group'}
                          </span>
                        </div>
                      ))}
                    </div>

                    <div style={{ background: 'rgba(255,255,255,0.03)', padding: '0.75rem', borderRadius: '8px' }}>
                      <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--primary)', marginBottom: '0.4rem' }}>
                        UNIMPORTED MESHCENTRAL AGENTS ({discoveryResult.discoveredAgents.length})
                      </div>
                      {discoveryResult.discoveredAgents.map((a) => (
                        <div key={a.meshNodeId} style={{ fontSize: '0.75rem', padding: '0.3rem 0', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'space-between' }}>
                          <span>
                            <strong>{a.hostname}</strong> ({a.os})
                          </span>
                          <span style={{ color: a.online ? '#10b981' : '#94a3b8' }}>
                            {a.online ? 'Online — Ready for Auto-Companion Push' : 'Offline — Queued'}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Import Options */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.78rem' }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', cursor: 'pointer' }}>
                      <input type="checkbox" checked={importNewGroups} onChange={(e) => setImportNewGroups(e.target.checked)} />
                      <span>Import unmatched MeshCentral Device Groups as Vitrine Clients &amp; Sites</span>
                    </label>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', cursor: 'pointer' }}>
                      <input type="checkbox" checked={autoDeployCompanion} onChange={(e) => setAutoDeployCompanion(e.target.checked)} />
                      <span>Queue signed Vitrine Tray Companion for auto-deploy when setup completes (and on reconnect)</span>
                    </label>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', cursor: 'pointer' }}>
                      <input type="checkbox" checked={enforceLapsOnImport} onChange={(e) => setEnforceLapsOnImport(e.target.checked)} />
                      <span>Provision LAPS Managed Local Admin account on online endpoints when setup completes</span>
                    </label>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', cursor: 'pointer' }}>
                      <input type="checkbox" checked={lockSignedUpdates} onChange={(e) => setLockSignedUpdates(e.target.checked)} />
                      <span>Lock MeshCentral agent updates to Vitrine Code-Signed binaries only</span>
                    </label>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                    <button
                      type="button"
                      className="btn-glass btn-primary"
                      onClick={handleImportDiscoveredMesh}
                      disabled={importingMesh}
                      style={{ fontSize: '0.78rem' }}
                    >
                      <CheckCircle2 size={14} />
                      <span>{importingMesh ? 'Importing Endpoints...' : 'Execute MeshCentral Import & Save Queue Preferences'}</span>
                    </button>
                    {importSummary && (
                      <span style={{ fontSize: '0.76rem', color: importIsError ? '#f87171' : '#34d399', fontWeight: 600 }}>
                        {importSummary}
                      </span>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* STEP 3: CODE SIGNING & AGENT BINARY PROTECTION */}
          {step === 3 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.15rem' }}>
              <div className="form-group">
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontWeight: 700 }}>
                  <input
                    type="checkbox"
                    checked={Boolean(formData.code_signing_enabled)}
                    onChange={(e) => {
                      setCodeSigningManuallyToggled(true);
                      setFormData({ ...formData, code_signing_enabled: e.target.checked ? 1 : 0 });
                    }}
                  />
                  <span>Enable Automated Authenticode &amp; RFC 3161 Code Signing Pipeline</span>
                </label>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr auto', gap: '0.85rem', alignItems: 'end' }}>
                <div className="form-group">
                  <label className="form-label">Code Signing HSM / SignPath / Webhook Endpoint URL</label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="https://signer.msp-domain.example/sign"
                    value={formData.code_signing_url || ''}
                    onChange={(e) => {
                      const nextUrl = e.target.value;
                      setFormData((prev) => ({
                        ...prev,
                        code_signing_url: nextUrl,
                        ...(!codeSigningManuallyToggled && nextUrl.trim().length > 0 ? { code_signing_enabled: 1 } : {})
                      }));
                    }}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Signing API Key / Bearer Token (Vaulted)</label>
                  <input
                    type="password"
                    className="glass-input"
                    placeholder="Optional signing webhook key"
                    value={formData.code_signing_api_key || ''}
                    onChange={(e) => setFormData({ ...formData, code_signing_api_key: e.target.value })}
                  />
                </div>
                <button
                  type="button"
                  className="btn-glass btn-primary"
                  onClick={handleTestCodeSigning}
                  disabled={testingSigner}
                  style={{ height: '38px' }}
                >
                  <Shield size={14} />
                  <span>{testingSigner ? 'Verifying...' : 'Verify Signing API'}</span>
                </button>
              </div>

              <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid var(--glass-border)', borderRadius: '8px', padding: '1rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '0.8rem' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={Boolean(formData.code_signing_sign_ms2_binary ?? 1)}
                    onChange={(e) => setFormData({ ...formData, code_signing_sign_ms2_binary: e.target.checked ? 1 : 0 })}
                  />
                  <span><strong>Stage 1:</strong> Sign Native MeshCentral Agent Binary &amp; Lock Auto-Updates to Signed Cache</span>
                </label>

                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={Boolean(formData.code_signing_sign_scripts ?? 1)}
                    onChange={(e) => setFormData({ ...formData, code_signing_sign_scripts: e.target.checked ? 1 : 0 })}
                  />
                  <span><strong>Stage 2:</strong> Sign Vitrine Tray Companion, Elevation Helper &amp; PowerShell Runbooks</span>
                </label>

                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={Boolean(formData.code_signing_sign_agents ?? 1)}
                    onChange={(e) => setFormData({ ...formData, code_signing_sign_agents: e.target.checked ? 1 : 0 })}
                  />
                  <span><strong>Stage 3:</strong> Sign Modern Vitrine GUI Installer &amp; QuickSupport Packages</span>
                </label>

                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={Boolean(formData.code_signing_strict_verify ?? 1)}
                    onChange={(e) => setFormData({ ...formData, code_signing_strict_verify: e.target.checked ? 1 : 0 })}
                  />
                  <span><strong>Strict Pre-Flight Gate:</strong> Verify all 3 signatures before releasing any installer download</span>
                </label>
              </div>

              {signerResult && (
                <div
                  style={{
                    background: signerIsError ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
                    border: `1px solid ${signerIsError ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                    padding: '0.75rem 1rem',
                    borderRadius: '8px',
                    fontSize: '0.8rem',
                    color: signerIsError ? '#f87171' : '#34d399'
                  }}
                >
                  {signerIsError ? '⚠ ' : '✓ '}
                  {signerResult}
                </div>
              )}
            </div>
          )}

          {/* STEP 4: REVERSE PROXY & LET'S ENCRYPT TLS SETUP */}
          {step === 4 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ background: 'rgba(0, 242, 254, 0.08)', border: '1px solid rgba(0, 242, 254, 0.25)', padding: '0.75rem 1rem', borderRadius: '8px', fontSize: '0.78rem' }}>
                <strong>Local Setup Expected:</strong> You are currently configuring Vitrine locally. Choose whether an upstream Reverse Proxy or external Let&apos;s Encrypt / ACME tooling handles public TLS termination and WebSocket upgrades (<code>wss://</code>).
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: '1rem', alignItems: 'end' }}>
                <div className="form-group">
                  <label className="form-label">TLS Termination Architecture</label>
                  <select
                    className="glass-select"
                    value={formData.tls_mode || 'reverse_proxy'}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        tls_mode: e.target.value as 'reverse_proxy' | 'letsencrypt' | 'self_signed'
                      })
                    }
                  >
                    <option value="reverse_proxy">External Reverse Proxy Handles TLS (Nginx / Caddy / Traefik / Cloudflare)</option>
                    <option value="letsencrypt">External Let&apos;s Encrypt / Certbot Certificates (Reverse Proxy Recommended)</option>
                    <option value="self_signed">Internal LAN Self-Signed TLS Certificate</option>
                  </select>
                </div>

                {formData.tls_mode === 'letsencrypt' ? (
                  <div className="form-group">
                    <label className="form-label">Let&apos;s Encrypt ACME Registration Email</label>
                    <input
                      type="email"
                      className="glass-input"
                      value={formData.letsencrypt_email || ''}
                      onChange={(e) => setFormData({ ...formData, letsencrypt_email: e.target.value })}
                    />
                  </div>
                ) : (
                  <div className="form-group">
                    <label className="form-label">Reverse Proxy Platform</label>
                    <select
                      className="glass-select"
                      value={formData.reverse_proxy_type || 'nginx'}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          reverse_proxy_type: e.target.value as 'nginx' | 'npm' | 'caddy' | 'traefik' | 'cloudflare'
                        })
                      }
                    >
                      <option value="nginx">Nginx / Nginx Proxy Manager (NPM)</option>
                      <option value="caddy">Caddy v2 Server</option>
                      <option value="traefik">Traefik v3</option>
                      <option value="cloudflare">Cloudflare Zero Trust Tunnel</option>
                    </select>
                  </div>
                )}

                <button
                  type="button"
                  className="btn-glass btn-primary"
                  onClick={handleTestProxy}
                  disabled={testingProxy}
                  style={{ height: '38px' }}
                >
                  <Globe size={14} />
                  <span>{testingProxy ? 'Testing...' : 'Test WebSockets & Routing'}</span>
                </button>
              </div>

              <div style={{ position: 'relative' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                  <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-dim)' }}>
                    GENERATED CO-EXISTENCE &amp; WEBSOCKET REVERSE PROXY CONFIG (INCLUDES /remote PORTAL)
                  </span>
                  <button
                    type="button"
                    className="btn-glass"
                    style={{ fontSize: '0.72rem', padding: '0.25rem 0.6rem' }}
                    onClick={async () => {
                      const ok = await copyToClipboard(getGeneratedProxyConfig());
                      if (ok) {
                        setCopiedProxyConfig(true);
                        setTimeout(() => setCopiedProxyConfig(false), 2000);
                      }
                    }}
                  >
                    {copiedProxyConfig ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                    <span>{copiedProxyConfig ? 'Copied!' : 'Copy Config'}</span>
                  </button>
                </div>
                <pre
                  style={{
                    background: 'rgba(0,0,0,0.45)',
                    border: '1px solid var(--glass-border)',
                    borderRadius: '8px',
                    padding: '0.75rem',
                    fontSize: '0.73rem',
                    fontFamily: 'var(--font-mono)',
                    overflowX: 'auto',
                    maxHeight: '165px',
                    margin: 0
                  }}
                >
                  {getGeneratedProxyConfig()}
                </pre>
              </div>

              {proxyTestChecks && (
                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.35rem',
                    background: proxyTestChecks.some((c) => ['fail', 'error'].includes(String(c.status).toLowerCase()))
                      ? 'rgba(239, 68, 68, 0.1)'
                      : proxyTestChecks.some((c) => ['warn', 'warning'].includes(String(c.status).toLowerCase()))
                        ? 'rgba(245, 158, 11, 0.1)'
                        : 'rgba(16, 185, 129, 0.1)',
                    border: `1px solid ${
                      proxyTestChecks.some((c) => ['fail', 'error'].includes(String(c.status).toLowerCase()))
                        ? 'rgba(239, 68, 68, 0.35)'
                        : proxyTestChecks.some((c) => ['warn', 'warning'].includes(String(c.status).toLowerCase()))
                          ? 'rgba(245, 158, 11, 0.35)'
                          : 'rgba(16, 185, 129, 0.3)'
                    }`,
                    padding: '0.7rem 0.9rem',
                    borderRadius: '8px',
                    fontSize: '0.76rem'
                  }}
                >
                  {proxyTestChecks.map((c, idx) => {
                    const st = String(c.status || '').toLowerCase();
                    const isFail = st === 'fail' || st === 'error';
                    const isWarn = st === 'warn' || st === 'warning';
                    const color = isFail ? '#f87171' : isWarn ? '#fbbf24' : '#34d399';
                    const mark = isFail ? '✕' : isWarn ? '!' : '✓';
                    return (
                      <div key={idx}>
                        <strong style={{ color }}>{mark} {c.name}:</strong> {c.detail}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* STEP 5: OUTBOUND SMTP & ADMIN UPDATE NOTIFICATIONS */}
          {step === 5 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.15rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1rem' }}>
                <div className="form-group">
                  <label className="form-label">SMTP Relay Host</label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="smtp.office365.com"
                    value={formData.smtp_host || ''}
                    onChange={(e) => setFormData({ ...formData, smtp_host: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Port</label>
                  <input
                    type="number"
                    className="glass-input"
                    value={formData.smtp_port ?? ''}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        smtp_port: e.target.value === '' ? undefined : parseInt(e.target.value, 10)
                      })
                    }
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem' }}>
                <div className="form-group">
                  <label className="form-label">SMTP Username</label>
                  <input
                    type="text"
                    className="glass-input"
                    value={formData.smtp_user || ''}
                    onChange={(e) => setFormData({ ...formData, smtp_user: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">SMTP Password</label>
                  <input
                    type="password"
                    className="glass-input"
                    value={formData.smtp_pass || ''}
                    onChange={(e) => setFormData({ ...formData, smtp_pass: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">From Address</label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="alerts@yourdomain.com"
                    value={formData.smtp_from || ''}
                    onChange={(e) => setFormData({ ...formData, smtp_from: e.target.value })}
                  />
                </div>
              </div>

              <div
                style={{
                  background: 'rgba(0, 242, 254, 0.05)',
                  border: '1px solid rgba(0, 242, 254, 0.2)',
                  borderRadius: '8px',
                  padding: '1rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.75rem'
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    gap: '0.5rem'
                  }}
                >
                  <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--primary)' }}>
                    VERIFY SMTP CREDENTIALS &amp; TEST DELIVERY
                  </div>
                  <button
                    type="button"
                    id="oobe-smtp-verify-btn"
                    className="btn-glass"
                    style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }}
                    disabled={smtpTestingMode !== null || !String(formData.smtp_host || '').trim()}
                    onClick={() => runSmtpTest(true)}
                  >
                    <Shield size={14} />{' '}
                    {smtpTestingMode === 'verify' ? 'Verifying Credentials...' : 'Test Connection & Credentials'}
                  </button>
                </div>

                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '1fr auto',
                    gap: '0.75rem',
                    alignItems: 'end'
                  }}
                >
                  <div className="form-group" style={{ marginBottom: 0 }}>
                    <label className="form-label" htmlFor="oobe-smtp-test-recipient">
                      Send Test Email To (Recipient)
                    </label>
                    <input
                      id="oobe-smtp-test-recipient"
                      type="email"
                      className="glass-input"
                      placeholder="admin@yourdomain.com"
                      value={smtpTestRecipient}
                      onChange={(e) => setSmtpTestRecipient(e.target.value)}
                    />
                  </div>
                  <button
                    type="button"
                    id="oobe-smtp-send-test-btn"
                    className="btn-glass btn-primary"
                    disabled={
                      smtpTestingMode !== null ||
                      !String(formData.smtp_host || '').trim() ||
                      !smtpTestRecipient.trim()
                    }
                    onClick={() => runSmtpTest(false)}
                  >
                    <Send size={14} />{' '}
                    {smtpTestingMode === 'send' ? 'Sending Test Email...' : 'Send Test Email'}
                  </button>
                </div>

                {smtpTestResult && (
                  <div
                    id="oobe-smtp-test-result"
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem',
                      padding: '0.65rem 0.85rem',
                      borderRadius: '6px',
                      fontSize: '0.78rem',
                      background: smtpTestIsError
                        ? 'rgba(239, 68, 68, 0.14)'
                        : 'rgba(16, 185, 129, 0.12)',
                      border: `1px solid ${
                        smtpTestIsError ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'
                      }`,
                      color: smtpTestIsError ? '#f87171' : '#34d399'
                    }}
                  >
                    {smtpTestIsError ? (
                      <AlertCircle size={15} style={{ flexShrink: 0 }} />
                    ) : (
                      <CheckCircle2 size={15} style={{ flexShrink: 0 }} />
                    )}
                    <span>{smtpTestResult}</span>
                  </div>
                )}
              </div>

              <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid var(--glass-border)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--primary)' }}>
                  SELF-UPDATER NOTIFICATION CHANNELS
                </div>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={Boolean(formData.update_notify_webui ?? 1)}
                    onChange={(e) => setFormData({ ...formData, update_notify_webui: e.target.checked ? 1 : 0 })}
                  />
                  <span>Show Admin Notification Banner in Web UI &amp; at Login when a new Stable/Alpha update is available</span>
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={Boolean(formData.update_notify_email ?? 1)}
                    onChange={(e) => setFormData({ ...formData, update_notify_email: e.target.checked ? 1 : 0 })}
                  />
                  <span>Dispatch Email Notification to MSP Super Admins when new updates are published</span>
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={Boolean(formData.update_create_psa_ticket ?? 1)}
                    onChange={(e) => setFormData({ ...formData, update_create_psa_ticket: e.target.checked ? 1 : 0 })}
                  />
                  <span>Automatically open a Service Desk Maintenance Ticket when an update is ready</span>
                </label>
              </div>
            </div>
          )}

          {/* STEP 6: OIDC SSO & UNIFIED SELF-BACKUP SCHEDULE */}
          {step === 6 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.15rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.84rem', fontWeight: 600, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={Boolean(formData.oidc_enabled)}
                    onChange={(e) => {
                      setOidcManuallyToggled(true);
                      setFormData({ ...formData, oidc_enabled: e.target.checked ? 1 : 0 });
                    }}
                  />
                  <span>Enable OpenID Connect (OIDC + PKCE) Single Sign-On</span>
                </label>
                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.76rem', padding: '0.3rem 0.7rem' }}
                  disabled={testingOidc || !formData.oidc_issuer_url}
                  onClick={async () => {
                    setTestingOidc(true);
                    setOidcTestMsg(null);
                    setOidcIsError(false);
                    try {
                      const res = await testOidcDiscovery({
                        issuerUrl: formData.oidc_issuer_url,
                        clientId: formData.oidc_client_id
                      });
                      if (res.success && !oidcManuallyToggled) {
                        setFormData((prev) => ({ ...prev, oidc_enabled: 1 }));
                      }
                      setOidcIsError(!res.success);
                      setOidcTestMsg(
                        res.success
                          ? `✓ OIDC Discovery verified (${res.issuer}) — Auth endpoint ready.`
                          : `OIDC check failed: ${res.error || 'Unable to fetch .well-known/openid-configuration'}`
                      );
                    } catch (err: any) {
                      setOidcIsError(true);
                      setOidcTestMsg(`OIDC check failed: ${err?.message || 'Unable to reach OIDC issuer'}`);
                    } finally {
                      setTestingOidc(false);
                    }
                  }}
                >
                  <Globe size={13} /> {testingOidc ? 'Testing OIDC...' : 'Test OIDC Discovery'}
                </button>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: '1rem' }}>
                <div className="form-group">
                  <label className="form-label">OpenID Connect / Authentik Issuer URL</label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="https://auth.internal/application/o/vitrine/"
                    value={formData.oidc_issuer_url || ''}
                    onChange={(e) => {
                      const nextIssuer = e.target.value;
                      setFormData((prev) => ({
                        ...prev,
                        oidc_issuer_url: nextIssuer,
                        ...(!oidcManuallyToggled && nextIssuer.trim() && String(prev.oidc_client_id || '').trim()
                          ? { oidc_enabled: 1 }
                          : {})
                      }));
                    }}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">OIDC Client ID</label>
                  <input
                    type="text"
                    className="glass-input"
                    value={formData.oidc_client_id || ''}
                    onChange={(e) => {
                      const nextClientId = e.target.value;
                      setFormData((prev) => ({
                        ...prev,
                        oidc_client_id: nextClientId,
                        ...(!oidcManuallyToggled && nextClientId.trim() && String(prev.oidc_issuer_url || '').trim()
                          ? { oidc_enabled: 1 }
                          : {})
                      }));
                    }}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">OIDC Client Secret (Vaulted)</label>
                  <input
                    type="password"
                    className="glass-input"
                    placeholder="Optional for public PKCE"
                    value={formData.oidc_client_secret || ''}
                    onChange={(e) => setFormData({ ...formData, oidc_client_secret: e.target.value })}
                  />
                </div>
              </div>

              {oidcTestMsg && (
                <div
                  style={{
                    padding: '0.6rem 0.9rem',
                    borderRadius: '8px',
                    background: oidcIsError ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
                    border: `1px solid ${oidcIsError ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                    color: oidcIsError ? '#f87171' : '#34d399',
                    fontSize: '0.78rem'
                  }}
                >
                  {oidcTestMsg}
                </div>
              )}

              {/* Disaster Recovery Backup Encryption Key Reminder & Escrow */}
              <div
                style={{
                  background: 'rgba(245, 158, 11, 0.1)',
                  border: '1px solid rgba(245, 158, 11, 0.42)',
                  borderRadius: '8px',
                  padding: '0.95rem 1.05rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.65rem'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.82rem', fontWeight: 700, color: '#fbbf24' }}>
                    <AlertTriangle size={16} />
                    <span>IMPORTANT: Escrow Your Backup Encryption Passphrase Offline</span>
                  </div>
                  <div style={{ display: 'flex', gap: '0.45rem' }}>
                    <button
                      type="button"
                      id="oobe-reveal-backup-key-btn"
                      className="btn-glass"
                      style={{ fontSize: '0.74rem', padding: '0.28rem 0.65rem', borderColor: 'rgba(245, 158, 11, 0.45)', color: '#fbbf24' }}
                      disabled={revealingBackupKey}
                      onClick={handleRevealWizardBackupKey}
                    >
                      <KeyRound size={13} />{' '}
                      {revealingBackupKey ? 'Revealing Key...' : 'Reveal Auto-Generated Recovery Key (MFA)'}
                    </button>
                  </div>
                </div>
                <div style={{ fontSize: '0.77rem', color: 'var(--text-muted)', lineHeight: 1.45 }}>
                  All <code>.vrmm-backup.gz</code> archives are encrypted with AES-256-GCM. Save your recovery passphrase in 1Password/Bitwarden now—or set a custom passphrase below—so you can restore backups on a replacement server if this host is ever lost.
                </div>

                {backupKeyError && (
                  <div
                    id="oobe-backup-key-error"
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem',
                      padding: '0.55rem 0.75rem',
                      borderRadius: '6px',
                      background: 'rgba(239, 68, 68, 0.14)',
                      border: '1px solid rgba(239, 68, 68, 0.35)',
                      color: '#f87171',
                      fontSize: '0.76rem'
                    }}
                  >
                    <AlertCircle size={14} style={{ flexShrink: 0 }} />
                    <span>{backupKeyError}</span>
                  </div>
                )}

                {backupKeyAckNotice && (
                  <div
                    id="oobe-backup-key-ack-notice"
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem',
                      padding: '0.55rem 0.75rem',
                      borderRadius: '6px',
                      background: 'rgba(16, 185, 129, 0.12)',
                      border: '1px solid rgba(16, 185, 129, 0.35)',
                      color: '#34d399',
                      fontSize: '0.76rem'
                    }}
                  >
                    <CheckCircle2 size={14} style={{ flexShrink: 0 }} />
                    <span>{backupKeyAckNotice}</span>
                  </div>
                )}

                {revealedWizardBackupKey && (
                  <div style={{ display: 'flex', gap: '0.45rem', alignItems: 'center', flexWrap: 'wrap' }}>
                    <input
                      type="text"
                      readOnly
                      className="glass-input"
                      style={{ flex: 1, fontFamily: 'var(--font-mono)', fontSize: '0.78rem', fontWeight: 700, color: 'var(--primary)' }}
                      value={revealedWizardBackupKey}
                    />
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ fontSize: '0.74rem', padding: '0.35rem 0.65rem' }}
                      onClick={async () => {
                        const ok = await copyToClipboard(revealedWizardBackupKey);
                        if (ok) {
                          setCopiedWizardBackupKey(true);
                          setTimeout(() => setCopiedWizardBackupKey(false), 2000);
                        }
                      }}
                    >
                      {copiedWizardBackupKey ? <Check size={13} color="#10b981" /> : <Copy size={13} />}
                      <span>{copiedWizardBackupKey ? 'Copied' : 'Copy'}</span>
                    </button>
                    <button
                      type="button"
                      className="btn-glass btn-primary"
                      style={{ fontSize: '0.74rem', padding: '0.35rem 0.7rem' }}
                      onClick={() => handleDownloadWizardBackupKit(revealedWizardBackupKey)}
                    >
                      <Download size={13} /> Download .txt Kit
                    </button>
                  </div>
                )}

                <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: '0.65rem', alignItems: 'end' }}>
                  <div className="form-group" style={{ margin: 0 }}>
                    <label className="form-label" style={{ fontSize: '0.72rem' }}>
                      Or Customize Backup Archive Passphrase (Optional)
                    </label>
                    <input
                      type="password"
                      className="glass-input"
                      style={{ fontSize: '0.78rem' }}
                      placeholder="Leave unchanged to keep auto-generated high-entropy passphrase"
                      value={formData.backup_encryption_passphrase || ''}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          backup_encryption_passphrase: e.target.value,
                          backup_key_acknowledged: 1
                        })
                      }
                    />
                  </div>
                  <button
                    type="button"
                    className="btn-glass"
                    style={{ fontSize: '0.74rem', padding: '0.45rem 0.75rem' }}
                    disabled={acknowledgingBackupKey}
                    onClick={async () => {
                      if (acknowledgingBackupKey) return;
                      setAcknowledgingBackupKey(true);
                      setBackupKeyError(null);
                      try {
                        const res = await acknowledgeBackupRecoveryKey();
                        if (res.success) {
                          setFormData((prev) => ({ ...prev, backup_key_acknowledged: 1 }));
                          setBackupKeyAckNotice('✓ Backup recovery key marked as escrowed offline.');
                        } else {
                          setBackupKeyError(res.error || 'Failed to mark backup recovery key as escrowed.');
                        }
                      } catch (err: any) {
                        setBackupKeyError(
                          err?.message || 'Unable to reach Vitrine server while acknowledging backup key.'
                        );
                      } finally {
                        setAcknowledgingBackupKey(false);
                      }
                    }}
                  >
                    <CheckCircle2 size={13} />{' '}
                    {acknowledgingBackupKey ? 'Saving...' : 'Mark Key Escrowed'}
                  </button>
                </div>
              </div>

              <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid var(--glass-border)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--primary)' }}>
                  UNIFIED SELF-BACKUP &amp; PRE-UPDATE SNAPSHOT SCHEDULE
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem' }}>
                  <div className="form-group">
                    <label className="form-label">Automated Backup Frequency</label>
                    <select
                      className="glass-select"
                      value={formData.backup_schedule_frequency || 'daily'}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          backup_schedule_frequency: e.target.value as 'hourly' | 'daily' | 'weekly'
                        })
                      }
                    >
                      <option value="hourly">Hourly</option>
                      <option value="daily">Daily (03:00 AM Recommended)</option>
                      <option value="weekly">Weekly</option>
                    </select>
                  </div>

                  <div className="form-group">
                    <label className="form-label">Keep Last N Backups</label>
                    <input
                      type="number"
                      className="glass-input"
                      value={formData.backup_retention_count || 14}
                      onChange={(e) => setFormData({ ...formData, backup_retention_count: parseInt(e.target.value, 10) })}
                    />
                  </div>

                  <div className="form-group">
                    <label className="form-label">Max Local Backup Storage (MB)</label>
                    <input
                      type="number"
                      className="glass-input"
                      value={formData.backup_max_storage_mb || 2048}
                      onChange={(e) => setFormData({ ...formData, backup_max_storage_mb: parseInt(e.target.value, 10) })}
                    />
                  </div>
                </div>

                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.82rem', cursor: 'pointer', color: '#34d399', fontWeight: 600 }}>
                  <input
                    type="checkbox"
                    checked={createInitialBackup}
                    onChange={(e) => setCreateInitialBackup(e.target.checked)}
                  />
                  <span>Create an initial self-restoring baseline backup archive (DB + LAPS Vault + Branding) upon completing guided setup</span>
                </label>
              </div>
            </div>
          )}

          {saveError && (
            <div
              style={{
                marginTop: '1rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.55rem',
                padding: '0.75rem 1rem',
                borderRadius: '8px',
                background: 'rgba(239, 68, 68, 0.14)',
                border: '1px solid rgba(239, 68, 68, 0.35)',
                color: '#f87171',
                fontSize: '0.82rem'
              }}
            >
              <AlertCircle size={16} style={{ flexShrink: 0 }} />
              <span>{saveError}</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="modal-footer" style={{ display: 'flex', justifyContent: 'space-between' }}>
          <div>
            {step > 1 && (
              <button type="button" className="btn-glass" onClick={() => setStep(step - 1)}>
                Previous Step
              </button>
            )}
          </div>

          <div style={{ display: 'flex', gap: '0.65rem' }}>
            <button type="button" className="btn-glass" onClick={() => setGuideOpenForStep(step)}>
              <HelpCircle size={15} /> Need Help with Step {step}?
            </button>

            {step < 6 ? (
              <button type="button" className="btn-glass btn-primary" onClick={() => setStep(step + 1)}>
                Continue to Step {step + 1}
              </button>
            ) : (
              <button
                type="button"
                className="btn-glass btn-primary"
                onClick={handleSave}
                disabled={saving}
                id="save-wizard-btn"
              >
                <CheckCircle2 size={16} /> Complete Guided Setup &amp; Save Configuration
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Hand-Held Step-by-Step Guide Popup Modal */}
      {guideOpenForStep !== null && STEP_GUIDES[guideOpenForStep] && (
        <div
          className="modal-backdrop"
          style={{ zIndex: 1200, background: 'rgba(0, 0, 0, 0.78)' }}
          onClick={() => setGuideOpenForStep(null)}
        >
          <div
            className="glass-modal glass-modal-md"
            style={{ maxWidth: '680px' }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-header">
              <div className="modal-title">
                <HelpCircle size={20} color="#00f2fe" />
                <span>{STEP_GUIDES[guideOpenForStep].title}</span>
              </div>
              <button className="btn-glass btn-icon" onClick={() => setGuideOpenForStep(null)}>
                <X size={18} />
              </button>
            </div>
            <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ fontSize: '0.84rem', color: 'var(--primary)', fontWeight: 600 }}>
                {STEP_GUIDES[guideOpenForStep].subtitle}
              </div>
              <ul style={{ margin: 0, paddingLeft: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.55rem', fontSize: '0.82rem', lineHeight: 1.5 }}>
                {STEP_GUIDES[guideOpenForStep].bullets.map((b, i) => (
                  <li key={i}>{b}</li>
                ))}
              </ul>
              <div>
                <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '0.35rem' }}>
                  REFERENCE COMMANDS &amp; CONFIGURATION
                </div>
                <pre
                  style={{
                    background: 'rgba(0,0,0,0.55)',
                    border: '1px solid var(--glass-border)',
                    borderRadius: '8px',
                    padding: '0.85rem',
                    fontSize: '0.75rem',
                    fontFamily: 'var(--font-mono)',
                    overflowX: 'auto',
                    margin: 0
                  }}
                >
                  {STEP_GUIDES[guideOpenForStep].codeSnippet}
                </pre>
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn-glass btn-primary" onClick={() => setGuideOpenForStep(null)}>
                Got It — Back to Wizard
              </button>
            </div>
          </div>
        </div>
      )}

      <MfaChallengeModal
        isOpen={showWizardBackupKeyMfa}
        onClose={() => setShowWizardBackupKeyMfa(false)}
        onSuccess={() => {
          setShowWizardBackupKeyMfa(false);
          handleRevealWizardBackupKey();
        }}
        title="Step-Up MFA: Reveal Backup Recovery Key"
        description="Enter your 6-digit TOTP authenticator code or recovery code to view and download the AES-256-GCM Backup Encryption Passphrase."
        secretType="backup_recovery_key"
      />

      <MfaChallengeModal
        isOpen={showSaveMfa}
        onClose={() => {
          setShowSaveMfa(false);
          setPendingMfaAction('save');
        }}
        onSuccess={() => {
          const action = pendingMfaAction;
          setShowSaveMfa(false);
          setPendingMfaAction('save');
          if (action === 'local_cfg') {
            handleApplyLocalConfig();
          } else {
            handleSave();
          }
        }}
        title={pendingMfaAction === 'local_cfg' ? 'Step-Up MFA: Update Local MeshCentral config.json' : 'Step-Up MFA: Complete Guided Setup'}
        description="Enter your 6-digit TOTP authenticator code or recovery code to authorize this configuration update."
        secretType="system_settings"
      />

      <IconCropModal
        isOpen={Boolean(cropLogoFile)}
        file={cropLogoFile}
        title="Crop Brand & Agent Tray Icon"
        onCancel={() => setCropLogoFile(null)}
        onConfirm={handleWizardLogoCropped}
      />
    </div>
  );
};
