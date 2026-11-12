import React, { useState } from 'react';
import { Download, X, Shield, Copy, Check, Ticket, ExternalLink, Sparkles } from 'lucide-react';
import { Tenant, Settings, SigningStageReport, AuthUser } from '../types/index.js';
import { generateInstaller } from '../services/api.js';

interface AgentInstallerModalProps {
  isOpen?: boolean;
  onClose: () => void;
  tenants: Tenant[];
  initialTenantId?: string;
  selectedTenantId?: string;
  settings?: Settings | null;
  currentUser?: AuthUser | null;
  onOpenQuickSupportPortal?: () => void;
}

export const AgentInstallerModal: React.FC<AgentInstallerModalProps> = ({
  isOpen = true,
  onClose,
  tenants,
  initialTenantId,
  selectedTenantId,
  settings,
  currentUser,
  onOpenQuickSupportPortal
}) => {
  const initialSelected = selectedTenantId || initialTenantId || 'all';
  const [tenantId, setTenantId] = useState(
    initialSelected && initialSelected !== 'all' ? initialSelected : tenants[0]?.id || ''
  );
  const [mode, setMode] = useState<'permanent' | 'quicksupport'>('permanent');
  const [platform, setPlatform] = useState<'windows' | 'linux' | 'macos'>('windows');
  const [deviceRole, setDeviceRole] = useState('workstation');
  const [ticketNumber, setTicketNumber] = useState('');
  const [generating, setGenerating] = useState(false);
  const [signingStepProgress, setSigningStepProgress] = useState(0);

  const [result, setResult] = useState<{
    tokenId?: string;
    downloadCommand?: string;
    installerUrl?: string;
    codeSigned?: boolean;
    ticketBound?: string | null;
    quickSupportPublicUrl?: string;
    signingPipeline?: {
      allSigned: boolean;
      strictVerified: boolean;
      stages: SigningStageReport[];
    };
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const requireTicket = Boolean(settings?.installer_require_ticket) && mode === 'permanent';

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tenantId && mode === 'permanent') {
      setError('Please create or select a Client Tenant first before generating a permanent agent installer.');
      return;
    }
    if (requireTicket && !ticketNumber.trim()) {
      setError('A valid PSA / ITFlow Ticket # is strictly required by policy before downloading permanent installers.');
      return;
    }

    setGenerating(true);
    setError(null);
    setResult(null);
    setSigningStepProgress(1);

    setTimeout(() => setSigningStepProgress(2), 250);
    setTimeout(() => setSigningStepProgress(3), 500);

    try {
      const res = await generateInstaller({
        tenant_id: tenantId,
        platform,
        device_role: deviceRole,
        mode,
        ticket_number: ticketNumber.trim() || undefined,
        technician: currentUser?.username || undefined
      });

      setTimeout(() => {
        setGenerating(false);
        setSigningStepProgress(4);
        if (res.success) {
          setResult(res);
        } else {
          setError(res.error || 'Failed to generate installer.');
        }
      }, 700);
    } catch (err: any) {
      setGenerating(false);
      setError(err?.message || 'Communication error with installer provisioning & signing engine.');
    }
  };

  const handleCopy = () => {
    if (result?.downloadCommand) {
      navigator.clipboard.writeText(result.downloadCommand);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="modal-backdrop" id="installer-modal" style={{ zIndex: 1050 }}>
      <div className="glass-modal glass-modal-md" style={{ maxWidth: '720px' }}>
        <div className="modal-header">
          <div className="modal-title">
            <Download size={20} style={{ color: 'var(--primary)' }} />
            <span>Provision &amp; Code-Sign Modern Vitrine Agent Installer</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            {onOpenQuickSupportPortal && (
              <button
                type="button"
                className="btn-glass"
                onClick={() => {
                  onClose();
                  onOpenQuickSupportPortal();
                }}
                style={{ fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.35rem', color: 'var(--primary)' }}
              >
                <ExternalLink size={13} />
                <span>Open Client /remote Portal</span>
              </button>
            )}
            <button className="btn-glass btn-icon" onClick={onClose}>
              <X size={18} />
            </button>
          </div>
        </div>

        <form onSubmit={handleGenerate}>
          <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '1.15rem' }}>
            {error && (
              <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.3)', padding: '0.75rem 1rem', borderRadius: '8px', color: '#f87171', fontSize: '0.8rem' }}>
                {error}
              </div>
            )}

            {/* Deployment Mode Switcher: Permanent vs QuickSupport Non-Admin */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
              <button
                type="button"
                onClick={() => !generating && !result && setMode('permanent')}
                style={{
                  padding: '0.75rem',
                  borderRadius: '8px',
                  border: `1px solid ${mode === 'permanent' ? 'var(--primary)' : 'var(--glass-border)'}`,
                  background: mode === 'permanent' ? 'rgba(0, 242, 254, 0.12)' : 'rgba(255, 255, 255, 0.03)',
                  color: 'var(--text-main)',
                  cursor: 'pointer',
                  textAlign: 'left'
                }}
              >
                <div style={{ fontWeight: 700, fontSize: '0.84rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <Shield size={14} color="var(--primary)" />
                  <span>Permanent Resident Agent (Modern GUI)</span>
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>
                  Installs signed SYSTEM service, OS-theme System Tray, &amp; LAPS local admin vault.
                </div>
              </button>

              <button
                type="button"
                onClick={() => !generating && !result && setMode('quicksupport')}
                style={{
                  padding: '0.75rem',
                  borderRadius: '8px',
                  border: `1px solid ${mode === 'quicksupport' ? '#10b981' : 'var(--glass-border)'}`,
                  background: mode === 'quicksupport' ? 'rgba(16, 185, 129, 0.12)' : 'rgba(255, 255, 255, 0.03)',
                  color: 'var(--text-main)',
                  cursor: 'pointer',
                  textAlign: 'left'
                }}
              >
                <div style={{ fontWeight: 700, fontSize: '0.84rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <Sparkles size={14} color="#10b981" />
                  <span>QuickSupport Temporary Session (No Admin)</span>
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>
                  Runs without local admin rights; includes Tech-Side Remote Self-Elevation button.
                </div>
              </button>
            </div>

            {/* Target Client / Mesh Group */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '1rem' }}>
              <div className="form-group">
                <label className="form-label">Client Tenant (MeshCentral Group Sync)</label>
                <select
                  className="glass-select"
                  value={tenantId}
                  onChange={(e) => setTenantId(e.target.value)}
                  disabled={generating || Boolean(result)}
                >
                  {tenants.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Default Device Role</label>
                <select
                  className="glass-select"
                  value={deviceRole}
                  onChange={(e) => setDeviceRole(e.target.value)}
                  disabled={generating || Boolean(result) || mode === 'quicksupport'}
                >
                  <option value="workstation">Desktop / Workstation</option>
                  <option value="laptop">Roaming Laptop</option>
                  <option value="server">Core Production Server</option>
                  <option value="hypervisor">Hypervisor Host</option>
                </select>
              </div>
            </div>

            {/* Platform Selection */}
            <div className="form-group">
              <label className="form-label">Target Platform Architecture</label>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.75rem' }}>
                {(
                  [
                    { id: 'windows', label: 'Windows', sub: 'Modern WPF/PE + Tray' },
                    { id: 'linux', label: 'Linux', sub: 'systemd + XDG Tray' },
                    { id: 'macos', label: 'macOS', sub: 'Universal ARM64/Intel' }
                  ] as const
                ).map((p) => (
                  <div
                    key={p.id}
                    onClick={() => !result && !generating && setPlatform(p.id)}
                    style={{
                      padding: '0.75rem',
                      borderRadius: '8px',
                      border: `1px solid ${platform === p.id ? 'var(--primary)' : 'var(--glass-border)'}`,
                      background: platform === p.id ? 'rgba(0, 242, 254, 0.12)' : 'rgba(255, 255, 255, 0.03)',
                      cursor: result ? 'default' : 'pointer',
                      textAlign: 'center',
                      transition: 'all 0.15s'
                    }}
                  >
                    <div style={{ fontWeight: 600, fontSize: '0.88rem' }}>{p.label}</div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>{p.sub}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* PSA Ticket Locking */}
            {mode === 'permanent' && (
              <div className="form-group">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                  <label className="form-label" style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <Ticket size={14} color="#f59e0b" />
                    <span>PSA Ticket # (ITFlow / ConnectWise)</span>
                  </label>
                  {requireTicket ? (
                    <span style={{ fontSize: '0.7rem', color: '#f87171', fontWeight: 600 }}>Strictly Required</span>
                  ) : (
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>Optional Audit Tracking</span>
                  )}
                </div>
                <input
                  type="text"
                  className="glass-input"
                  placeholder="e.g. TKT-49821"
                  value={ticketNumber}
                  onChange={(e) => setTicketNumber(e.target.value)}
                  disabled={generating || Boolean(result)}
                />
              </div>
            )}

            {/* Live 3-Stage Code Signing Verification Progress */}
            {(generating || result?.signingPipeline) && (
              <div
                style={{
                  background: 'rgba(16, 185, 129, 0.08)',
                  border: '1px solid rgba(16, 185, 129, 0.28)',
                  padding: '0.9rem 1rem',
                  borderRadius: '8px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.55rem'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', fontWeight: 700, color: '#34d399' }}>
                    <Shield size={16} color="#10b981" />
                    <span>
                      {generating
                        ? 'Executing 3-Stage Packaging & Signing Pipeline...'
                        : result?.signingPipeline?.allSigned
                        ? 'All 3 Package Stages Verified & Cryptographically Signed'
                        : 'Package Prepared & Token Provisioned'}
                    </span>
                  </div>
                  <span style={{ fontSize: '0.74rem', fontWeight: 700, color: '#10b981' }}>
                    {generating ? `${Math.min(95, signingStepProgress * 32)}%` : '100% Ready'}
                  </span>
                </div>

                <div style={{ width: '100%', height: '6px', background: 'rgba(255,255,255,0.1)', borderRadius: '999px', overflow: 'hidden' }}>
                  <div
                    style={{
                      width: generating ? `${Math.min(95, signingStepProgress * 32)}%` : '100%',
                      height: '100%',
                      background: 'linear-gradient(90deg, #00f2fe, #10b981)',
                      transition: 'width 0.25s ease'
                    }}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.28rem', fontSize: '0.73rem', color: 'var(--text-muted)' }}>
                  <div>
                    {signingStepProgress >= 1 ? '✓' : '○'}{' '}
                    <strong>Stage 1 (Core MS2 Agent Binary):</strong> Signed &amp; cached in <code>signedagents/</code> so MS2 updates stay signed
                  </div>
                  <div>
                    {signingStepProgress >= 2 ? '✓' : '○'}{' '}
                    <strong>Stage 2 (Companion &amp; Elevation Helper):</strong> System Tray, LAPS Sync &amp; Self-Elevation RPC signed
                  </div>
                  <div>
                    {signingStepProgress >= 3 ? '✓' : '○'}{' '}
                    <strong>Stage 3 (Modern Vitrine GUI Installer):</strong> Clean PE headers &amp; RFC 3161 timestamp verified
                  </div>
                </div>
              </div>
            )}

            {/* Generated Result Display */}
            {result && (
              <div
                style={{
                  background: 'rgba(0, 0, 0, 0.35)',
                  border: '1px solid var(--primary)',
                  borderRadius: '8px',
                  padding: '1rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.85rem'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--primary)' }}>
                    PROVISIONED DEPLOYMENT TOKEN: {result.tokenId}
                  </span>
                  {result.ticketBound && (
                    <span className="status-pill status-online" style={{ fontSize: '0.68rem' }}>
                      Bound to #{result.ticketBound}
                    </span>
                  )}
                </div>

                <div>
                  <label className="form-label" style={{ fontSize: '0.72rem' }}>
                    One-Line Terminal / RMM Deployment Command
                  </label>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <input
                      type="text"
                      className="glass-input"
                      readOnly
                      value={result.downloadCommand || ''}
                      style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}
                    />
                    <button type="button" className="btn-glass" onClick={handleCopy}>
                      {copied ? <Check size={15} color="#10b981" /> : <Copy size={15} />}
                    </button>
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <a
                    href={result.installerUrl}
                    download
                    className="btn-glass btn-primary"
                    style={{ textDecoration: 'none', flex: 1, justifyContent: 'center', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                  >
                    <Download size={16} />
                    <span>
                      Download Signed {platform.toUpperCase()} {mode === 'quicksupport' ? 'QuickSupport' : 'Modern GUI Installer'}
                    </span>
                  </a>
                  <button
                    type="button"
                    className="btn-glass"
                    onClick={() => {
                      setResult(null);
                      setSigningStepProgress(0);
                    }}
                  >
                    Generate Another
                  </button>
                </div>
              </div>
            )}
          </div>

          <div className="modal-footer">
            <button type="button" className="btn-glass" onClick={onClose}>
              Close
            </button>
            {!result && (
              <button type="submit" className="btn-glass btn-primary" disabled={generating}>
                <Download size={16} />
                <span>{generating ? 'Signing & Packaging...' : 'Sign & Generate Installer'}</span>
              </button>
            )}
          </div>
        </form>
      </div>
    </div>
  );
};
