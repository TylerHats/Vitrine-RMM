import React, { useState } from 'react';
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
  AlertTriangle
} from 'lucide-react';
import { Settings, MeshDiscoveryResult } from '../types/index.js';
import {
  updateSettings,
  testDiscoverMeshServer,
  importFromMeshServer,
  testCodeSigningPipeline,
  testProxyTlsSetup,
  createSystemBackup,
  revealBackupRecoveryKey,
  acknowledgeBackupRecoveryKey,
  testOidcDiscovery
} from '../services/api.js';
import { MfaChallengeModal } from './MfaChallengeModal.js';

interface OnboardingWizardModalProps {
  settings: Settings;
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
      'Modern GUI Installer: Replaces MeshCentral\'s dated gray Win32 prompt with a signed glassmorphic WPF/PE installer using your custom Windows Service Name.',
      'Dedicated QuickSupport Endpoint: Point a CNAME (e.g., remote.yourdomain.com) or path (/remote, /temporarysession) to Vitrine so clients can launch non-admin temporary sessions.'
    ],
    codeSnippet: `# DNS CNAME Setup for Dedicated Client QuickSupport Portal:
remote.yourdomain.com.  300  IN  CNAME  rmm.yourdomain.com.
# Accessible at: https://remote.yourdomain.com/remote or https://rmm.yourdomain.com/temporarysession`
  },
  2: {
    title: 'Walkthrough: Generating Your MeshCentral 2 API Token & Safe Co-Existence',
    subtitle: 'Connecting to a local bare-metal or remote MeshCentral 2 instance without disrupting existing agents',
    bullets: [
      'Bare-Metal Co-Existence: Vitrine runs on an isolated port (8080) and systemd unit (vitrine-rmm.service). It never overwrites or stops your neighboring meshcentral.service.',
      'Step 1: On your MeshCentral 2 server, generate a Login Token Key or API Token using meshctrl.js (shown below).',
      'Step 2: Paste the URL and Token into Step 2 and click "Test Connection & Discover Fleet".',
      'Step 3: Select how existing MS2 Device Groups and Agents should be imported. Vitrine will automatically push the Vitrine Tray Companion & LAPS policies over the existing MS2 channel as soon as each imported agent is online—no manual re-install needed!'
    ],
    codeSnippet: `# 1. Generate a persistent API Login Token on your MeshCentral 2 server:
cd /opt/meshcentral
node node_modules/meshcentral/meshctrl.js --url wss://127.0.0.1:4430 --loginuser admin --loginpass 'YourPass' Token

# 2. (Optional) In meshcentral-data/config.json under "settings":
"allowFraming": true,
"disableAgentUpdate": true  # Lets Vitrine keep MS2 agent binaries Authenticode-signed!`
  },
  3: {
    title: 'Walkthrough: Setting Up the 3-Stage Authenticode & Code Signing API',
    subtitle: 'Ensuring the Modern GUI Installer, Companion Scripts, and Native MS2 Binary stay signed',
    bullets: [
      'Why 3-Stage Signing Matters: Antivirus/SmartScreen flags unsigned wrappers OR unsigned inner binaries. Vitrine signs (1) the native MS2 meshagent binary, (2) the Vitrine Tray/Elevation scripts, and (3) the outer Modern GUI Installer.',
      'Keeping MS2 Updates Signed: When MeshCentral updates, stock MS2 normally pushes unsigned agent updates. Vitrine intercepts new MS2 agent binaries, signs them via your Signing API, and caches them in signedagents/ before allowing endpoints to update.',
      'Supported Signers: SignPath.io REST API, Azure KeyVault / DigiCert KeyLocker webhook, or a local osslsigncode / signtool microservice.'
    ],
    codeSnippet: `# Example SignTool / osslsigncode Signing Webhook Endpoint:
POST http://10.10.10.20:5000/sign
Content-Type: multipart/form-data; name="file"
# Returns SHA-256 Authenticode + RFC 3161 Timestamped PE/PS1 binary`
  },
  4: {
    title: 'Walkthrough: Reverse Proxy WebSockets vs. Built-In Let\'s Encrypt TLS',
    subtitle: 'Preventing WebSocket disconnects while accessing Vitrine locally during initial setup',
    bullets: [
      'Local First-Boot Access: During initial OOBE setup, access Vitrine directly via http://localhost:8080 or your LAN IP.',
      'Option A (Reverse Proxy Handles TLS): If using Nginx, Nginx Proxy Manager, Caddy, or Traefik in front of Vitrine & MS2, you MUST pass WebSocket Upgrade headers and increase proxy_read_timeout so live PTY shells and KVM streams do not drop every 60 seconds.',
      'Option B (Vitrine Handles TLS via Let\'s Encrypt): Vitrine can manage ACME HTTP-01/DNS-01 certificates directly and terminate TLS 1.3 natively.'
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
      'OpenID Connect (Authentik / Entra ID / Okta): Create an OAuth2/OIDC Provider with Redirect URI https://rmm.yourdomain.com/api/auth/callback.',
      'Unified Self-Backup System: Every scheduled or pre-update backup bundles vitrine.db, the AES-256 LAPS vault, branding logos, and a schema version manifest into data/backups/.'
    ],
    codeSnippet: `# OIDC Redirect URI to register in Authentik / Keycloak / Entra ID:
https://rmm.yourdomain.com/api/auth/oidc/callback`
  }
};

export const OnboardingWizardModal: React.FC<OnboardingWizardModalProps> = ({
  settings,
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
    quicksupport_custom_domain: settings.quicksupport_custom_domain || 'remote.vitrine.local',
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
  const [guideOpenForStep, setGuideOpenForStep] = useState<number | null>(null);
  const [copiedProxyConfig, setCopiedProxyConfig] = useState(false);

  // Step 2: Live MS2 Discovery & Import State
  const [discoveringMesh, setDiscoveringMesh] = useState(false);
  const [discoveryResult, setDiscoveryResult] = useState<MeshDiscoveryResult | null>(null);
  const [importNewGroups, setImportNewGroups] = useState(true);
  const [autoDeployCompanion, setAutoDeployCompanion] = useState(true);
  const [enforceLapsOnImport, setEnforceLapsOnImport] = useState(true);
  const [lockSignedUpdates, setLockSignedUpdates] = useState(true);
  const [importingMesh, setImportingMesh] = useState(false);
  const [importSummary, setImportSummary] = useState<string | null>(null);

  // Step 3: Code Signing Test State
  const [testingSigner, setTestingSigner] = useState(false);
  const [signerResult, setSignerResult] = useState<string | null>(null);

  // Step 4: Reverse Proxy / TLS Test State
  const [testingProxy, setTestingProxy] = useState(false);
  const [proxyTestChecks, setProxyTestChecks] = useState<Array<{ name: string; status: string; detail: string }> | null>(null);

  // Step 6: Initial Baseline Backup Option + OIDC Test + Backup Encryption Key Escrow
  const [createInitialBackup, setCreateInitialBackup] = useState(true);
  const [testingOidc, setTestingOidc] = useState(false);
  const [oidcTestMsg, setOidcTestMsg] = useState<string | null>(null);
  const [revealedWizardBackupKey, setRevealedWizardBackupKey] = useState<string | null>(null);
  const [showWizardBackupKeyMfa, setShowWizardBackupKeyMfa] = useState(false);
  const [copiedWizardBackupKey, setCopiedWizardBackupKey] = useState(false);

  const handleRevealWizardBackupKey = async () => {
    const res = await revealBackupRecoveryKey();
    if (res.mfaRequired) {
      setShowWizardBackupKeyMfa(true);
      return;
    }
    if (res.success && res.passphrase) {
      setRevealedWizardBackupKey(res.passphrase);
      setFormData((prev) => ({ ...prev, backup_key_acknowledged: 1 }));
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
        api_token: formData.meshcentral_api_token
      });
      setDiscoveryResult(res);
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
        import_new_groups: importNewGroups,
        auto_deploy_companion: autoDeployCompanion,
        enforce_laps_on_import: enforceLapsOnImport,
        lock_signed_binary_updates: lockSignedUpdates
      });
      if (res.success) {
        setImportSummary(res.message);
      } else {
        setImportSummary('Unable to import: check MeshCentral URL & API token.');
      }
    } finally {
      setImportingMesh(false);
    }
  };

  const handleTestCodeSigning = async () => {
    setTestingSigner(true);
    try {
      const res = await testCodeSigningPipeline(formData.code_signing_url);
      if (res.success) {
        setSignerResult(
          `Verified 3-Stage Signing Pipeline (${res.hsmStatus}) • ${res.ms2AutoUpdateProtection}`
        );
      } else {
        setSignerResult(`Signing endpoint check: ${res.error || res.hsmStatus || 'Unreachable'}`);
      }
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
    } finally {
      setTestingProxy(false);
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
    try {
      const res = await updateSettings({
        ...formData,
        oobe_completed: 1,
        is_onboarded: 1
      });
      if (createInitialBackup) {
        await createSystemBackup({
          triggerType: 'manual',
          notes: 'Initial Post-OOBE Baseline Backup Snapshot'
        }).catch(() => {});
      }
      if (res.success) {
        onSaved(res.settings);
        onClose();
      }
    } finally {
      setSaving(false);
    }
  };

  const steps = [
    { num: 1, title: '1. Brand & GUI', icon: Palette },
    { num: 2, title: '2. MS2 & Import', icon: Server },
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
            <span>Vitrine RMM Comprehensive OOBE Setup &amp; Co-Existence Wizard</span>
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
              <span>Step {step} Hand-Held Setup Guide</span>
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
                    <option value="modern_glass">Modern Vitrine GUI Wrapper (Clean PE Headers + Low AV False-Positive)</option>
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
            </div>
          )}

          {/* STEP 2: MESHCENTRAL 2 FEDERATION, CO-EXISTENCE & LIVE DISCOVERY IMPORT */}
          {step === 2 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', padding: '0.75rem 1rem', borderRadius: '8px', fontSize: '0.78rem' }}>
                <strong style={{ color: '#34d399' }}>✓ Bare-Metal Co-Existence Isolation Verified:</strong> Vitrine operates in its own isolated directory and service unit. Connecting or later uninstalling Vitrine will never alter or disrupt a neighboring MeshCentral 2 installation.
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr auto', gap: '0.85rem', alignItems: 'end' }}>
                <div className="form-group">
                  <label className="form-label">Primary MeshCentral 2 Server Endpoint URL</label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="https://127.0.0.1:4430"
                    value={formData.meshcentral_url || ''}
                    onChange={(e) => setFormData({ ...formData, meshcentral_url: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">MeshCentral API Login Key / Token</label>
                  <input
                    type="password"
                    className="glass-input"
                    placeholder="••••••••••••••••"
                    value={formData.meshcentral_api_token || ''}
                    onChange={(e) => setFormData({ ...formData, meshcentral_api_token: e.target.value })}
                  />
                </div>

                <button
                  type="button"
                  className="btn-glass btn-primary"
                  onClick={handleTestDiscoverMesh}
                  disabled={discoveringMesh}
                  style={{ height: '38px' }}
                >
                  <RefreshCw size={14} className={discoveringMesh ? 'spin' : ''} />
                  <span>{discoveringMesh ? 'Scanning MS2...' : 'Test & Discover Fleet'}</span>
                </button>
              </div>

              {discoveryResult && (
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
                        DISCOVERED MS2 DEVICE GROUPS ({discoveryResult.discoveredGroups.length})
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
                        UNIMPORTED MS2 AGENTS ({discoveryResult.discoveredAgents.length})
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
                      <span>Import unmatched MS2 Device Groups as Vitrine Clients &amp; Sites</span>
                    </label>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', cursor: 'pointer' }}>
                      <input type="checkbox" checked={autoDeployCompanion} onChange={(e) => setAutoDeployCompanion(e.target.checked)} />
                      <span>Auto-push signed Vitrine Tray Companion over MS2 channel when online</span>
                    </label>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', cursor: 'pointer' }}>
                      <input type="checkbox" checked={enforceLapsOnImport} onChange={(e) => setEnforceLapsOnImport(e.target.checked)} />
                      <span>Provision LAPS Managed Local Admin account on imported endpoints</span>
                    </label>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', cursor: 'pointer' }}>
                      <input type="checkbox" checked={lockSignedUpdates} onChange={(e) => setLockSignedUpdates(e.target.checked)} />
                      <span>Lock MS2 agent updates to Vitrine Code-Signed binaries only</span>
                    </label>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <button
                      type="button"
                      className="btn-glass btn-primary"
                      onClick={handleImportDiscoveredMesh}
                      disabled={importingMesh}
                      style={{ fontSize: '0.78rem' }}
                    >
                      <CheckCircle2 size={14} />
                      <span>{importingMesh ? 'Importing & Pushing Add-ons...' : 'Execute MS2 Import & Queue Companion Add-Ons'}</span>
                    </button>
                    {importSummary && (
                      <span style={{ fontSize: '0.76rem', color: '#34d399', fontWeight: 600 }}>{importSummary}</span>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* STEP 3: 3-STAGE CODE SIGNING & MS2 AGENT BINARY PROTECTION */}
          {step === 3 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.15rem' }}>
              <div className="form-group">
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontWeight: 700 }}>
                  <input
                    type="checkbox"
                    checked={Boolean(formData.code_signing_enabled ?? 1)}
                    onChange={(e) => setFormData({ ...formData, code_signing_enabled: e.target.checked ? 1 : 0 })}
                  />
                  <span>Enable 3-Stage Authenticode &amp; RFC 3161 Code Signing Pipeline</span>
                </label>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: '0.85rem', alignItems: 'end' }}>
                <div className="form-group">
                  <label className="form-label">Code Signing HSM / SignPath / Webhook Endpoint URL</label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="http://10.10.10.20:5000/sign"
                    value={formData.code_signing_url || ''}
                    onChange={(e) => setFormData({ ...formData, code_signing_url: e.target.value })}
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
                  <span>{testingSigner ? 'Verifying HSM...' : 'Verify 3-Stage Signing'}</span>
                </button>
              </div>

              <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid var(--glass-border)', borderRadius: '8px', padding: '1rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '0.8rem' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={Boolean(formData.code_signing_sign_ms2_binary ?? 1)}
                    onChange={(e) => setFormData({ ...formData, code_signing_sign_ms2_binary: e.target.checked ? 1 : 0 })}
                  />
                  <span><strong>Stage 1:</strong> Sign Native MS2 Agent Binary &amp; Lock MS2 Auto-Updates to Signed Cache</span>
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
                <div style={{ background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.35)', padding: '0.75rem 1rem', borderRadius: '8px', fontSize: '0.8rem', color: '#34d399' }}>
                  ✓ {signerResult}
                </div>
              )}
            </div>
          )}

          {/* STEP 4: REVERSE PROXY & LET'S ENCRYPT TLS SETUP */}
          {step === 4 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ background: 'rgba(0, 242, 254, 0.08)', border: '1px solid rgba(0, 242, 254, 0.25)', padding: '0.75rem 1rem', borderRadius: '8px', fontSize: '0.78rem' }}>
                <strong>Local Setup Expected:</strong> You are currently configuring Vitrine locally. Choose whether an upstream Reverse Proxy or Vitrine&apos;s built-in Let&apos;s Encrypt client will handle public TLS termination and WebSocket upgrades (`wss://`).
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
                    <option value="reverse_proxy">External Reverse Proxy Handles TLS (Nginx / Caddy / Traefik)</option>
                    <option value="letsencrypt">Vitrine Built-In Let&apos;s Encrypt ACME Auto-TLS</option>
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
                    onClick={() => {
                      navigator.clipboard.writeText(getGeneratedProxyConfig());
                      setCopiedProxyConfig(true);
                      setTimeout(() => setCopiedProxyConfig(false), 2000);
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
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', padding: '0.7rem 0.9rem', borderRadius: '8px', fontSize: '0.76rem' }}>
                  {proxyTestChecks.map((c, idx) => (
                    <div key={idx}>
                      <strong style={{ color: '#34d399' }}>✓ {c.name}:</strong> {c.detail}
                    </div>
                  ))}
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
                    value={formData.smtp_host || ''}
                    onChange={(e) => setFormData({ ...formData, smtp_host: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Port</label>
                  <input
                    type="number"
                    className="glass-input"
                    value={formData.smtp_port || 587}
                    onChange={(e) => setFormData({ ...formData, smtp_port: parseInt(e.target.value, 10) })}
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
                    value={formData.smtp_from || ''}
                    onChange={(e) => setFormData({ ...formData, smtp_from: e.target.value })}
                  />
                </div>
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
                  <span>Automatically open a PSA / ITFlow Maintenance Ticket when an update is ready</span>
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
                    onChange={(e) => setFormData({ ...formData, oidc_enabled: e.target.checked ? 1 : 0 })}
                  />
                  <span>Enable Enterprise OpenID Connect (OIDC + PKCE) Single Sign-On</span>
                </label>
                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.76rem', padding: '0.3rem 0.7rem' }}
                  disabled={testingOidc || !formData.oidc_issuer_url}
                  onClick={async () => {
                    setTestingOidc(true);
                    setOidcTestMsg(null);
                    try {
                      const res = await testOidcDiscovery({
                        issuerUrl: formData.oidc_issuer_url,
                        clientId: formData.oidc_client_id
                      });
                      setOidcTestMsg(
                        res.success
                          ? `✓ OIDC Discovery verified (${res.issuer}) — Auth endpoint ready.`
                          : `OIDC check failed: ${res.error || 'Unable to fetch .well-known/openid-configuration'}`
                      );
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
                    onChange={(e) => setFormData({ ...formData, oidc_issuer_url: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">OIDC Client ID</label>
                  <input
                    type="text"
                    className="glass-input"
                    value={formData.oidc_client_id || ''}
                    onChange={(e) => setFormData({ ...formData, oidc_client_id: e.target.value })}
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
                <div style={{ padding: '0.6rem 0.9rem', borderRadius: '8px', background: 'rgba(0, 242, 254, 0.1)', border: '1px solid rgba(0, 242, 254, 0.35)', fontSize: '0.78rem' }}>
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
                      className="btn-glass"
                      style={{ fontSize: '0.74rem', padding: '0.28rem 0.65rem', borderColor: 'rgba(245, 158, 11, 0.45)', color: '#fbbf24' }}
                      onClick={handleRevealWizardBackupKey}
                    >
                      <KeyRound size={13} /> Reveal Auto-Generated Recovery Key (MFA)
                    </button>
                  </div>
                </div>
                <div style={{ fontSize: '0.77rem', color: 'var(--text-muted)', lineHeight: 1.45 }}>
                  All <code>.vrmm-backup.gz</code> archives are encrypted with AES-256-GCM. Save your recovery passphrase in 1Password/Bitwarden now—or set a custom passphrase below—so you can restore backups on a replacement server if this host is ever lost.
                </div>

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
                      onClick={() => {
                        navigator.clipboard.writeText(revealedWizardBackupKey);
                        setCopiedWizardBackupKey(true);
                        setTimeout(() => setCopiedWizardBackupKey(false), 2000);
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
                    onClick={async () => {
                      await acknowledgeBackupRecoveryKey();
                      setFormData((prev) => ({ ...prev, backup_key_acknowledged: 1 }));
                    }}
                  >
                    <CheckCircle2 size={13} /> Mark Key Escrowed
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
                  <span>Create an initial self-restoring baseline backup archive (DB + LAPS Vault + Branding) upon completing OOBE</span>
                </label>
              </div>
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
                <CheckCircle2 size={16} /> Complete OOBE Setup &amp; Save Configuration
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
    </div>
  );
};
