import React, { useState, useRef, useEffect } from 'react';
import { Download, X, Shield, Copy, Check, Ticket, ExternalLink, Sparkles } from 'lucide-react';
import { Tenant, Settings, SigningStageReport, AuthUser } from '../types/index.js';
import { generateInstaller } from '../services/api.js';
import { copyToClipboard } from '../utils/clipboard.js';
import { sanitizeSafeUrl } from '../utils/urlSafety.js';

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
  const [siteId, setSiteId] = useState('');
  const [mode, setMode] = useState<'permanent' | 'quicksupport'>('permanent');
  const [platform, setPlatform] = useState<'windows' | 'linux' | 'macos'>('windows');
  const [deviceRole, setDeviceRole] = useState('auto');
  const [ticketNumber, setTicketNumber] = useState('');
  const [generating, setGenerating] = useState(false);

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
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
    };
  }, []);

  if (!isOpen) return null;

  const requireTicket = Boolean(settings?.installer_require_ticket) && mode === 'permanent';

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tenantId && mode === 'permanent') {
      setError('Please create or select a Client Tenant first before generating a permanent agent installer.');
      return;
    }
    if (requireTicket && !ticketNumber.trim()) {
      setError('A valid Support Ticket # is strictly required by policy before downloading permanent installers.');
      return;
    }

    setGenerating(true);
    setError(null);
    setResult(null);

    try {
      const res = await generateInstaller({
        tenant_id: tenantId || undefined,
        site_id: siteId || undefined,
        platform,
        device_role: deviceRole,
        mode,
        ticket_number: ticketNumber.trim() || undefined,
        technician: currentUser?.username || undefined
      });

      if (!res.success) {
        setError(res.error || 'Failed to generate installer.');
        return;
      }

      setResult(res);
    } catch (err: any) {
      setError(err?.message || 'Communication error with installer provisioning & signing engine.');
    } finally {
      setGenerating(false);
    }
  };

  const handleCopy = async () => {
    if (result?.downloadCommand) {
      await copyToClipboard(result.downloadCommand);
      setCopied(true);
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
      copyTimerRef.current = setTimeout(() => setCopied(false), 2000);
    }
  };

  const safeInstallerUrl = sanitizeSafeUrl(result?.installerUrl);

  const selectedTenantObj = tenants.find((t) => t.id === tenantId);
  const availableSites = selectedTenantObj?.sites || [];

  return (
    <div className="modal-backdrop" id="installer-modal" style={{ zIndex: 1050 }}>
      <div className="glass-modal glass-modal-md" style={{ maxWidth: '720px' }}>
        <div className="modal-header">
          <div className="modal-title">
            <Download size={20} style={{ color: 'var(--primary)' }} />
            <span>Download Agent Installer</span>
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
                <span>Open Client QuickSupport Portal</span>
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
                onClick={() => {
                  if (generating || result) return;
                  setMode('permanent');
                  if (!tenantId && tenants[0]?.id) setTenantId(tenants[0].id);
                }}
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
                  <span>Managed Device Agent (Permanent)</span>
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>
                  Installs background service, system tray, &amp; local admin credential management.
                </div>
              </button>

              <button
                type="button"
                onClick={() => {
                  if (generating || result) return;
                  setMode('quicksupport');
                  setTenantId('');
                  setSiteId('');
                }}
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
                  <span>On-Demand QuickSupport (No Admin)</span>
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>
                  Runs without local admin rights; supports remote privilege elevation when needed.
                </div>
              </button>
            </div>

            {/* Target Client / Site Location / Role (embeds policy-resolved icon & branding into EXE) */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.85rem' }}>
              <div className="form-group">
                <label className="form-label">
                  {mode === 'quicksupport' ? 'Branding Profile / Client' : 'Client Tenant'}
                </label>
                <select
                  className="glass-select"
                  value={tenantId}
                  onChange={(e) => {
                    setTenantId(e.target.value);
                    setSiteId('');
                  }}
                  disabled={generating || Boolean(result)}
                >
                  {mode === 'quicksupport' && (
                    <option value="">Dedicated QuickSupport Profile (Default)</option>
                  )}
                  {tenants.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Site Location</label>
                <select
                  className="glass-select"
                  value={siteId}
                  onChange={(e) => setSiteId(e.target.value)}
                  disabled={generating || Boolean(result) || mode === 'quicksupport' || availableSites.length === 0}
                >
                  <option value="">
                    {availableSites.length === 0 ? 'Client Default (No Sites)' : 'Client Default (All Sites)'}
                  </option>
                  {availableSites.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
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
                  <option value="auto">Auto-Detect Hardware &amp; OS (Recommended)</option>
                  <option value="Desktop">Desktop</option>
                  <option value="Laptop">Laptop</option>
                  <option value="Server">Server</option>
                  <option value="Domain Controller">Domain Controller</option>
                  <option value="Hypervisor">Hypervisor</option>
                  <option value="Virtual Machine">Virtual Machine</option>
                  <option value="Virtual Server">Virtual Server</option>
                  <option value="Workstation">Workstation</option>
                </select>
              </div>
            </div>

            {/* Platform Selection */}
            <div className="form-group">
              <label className="form-label">Target Platform Architecture</label>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.75rem' }}>
                {(
                  [
                    { id: 'windows', label: 'Windows', sub: 'Windows Service + System Tray' },
                    { id: 'linux', label: 'Linux', sub: 'systemd Service + Tray' },
                    { id: 'macos', label: 'macOS', sub: 'Universal ARM64 / Intel' }
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
                    <span>Support Ticket #</span>
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

            {/* Honest Server Code-Signing Pipeline Status */}
            {(generating || result?.signingPipeline) && (
              <div
                style={{
                  background: generating
                    ? 'rgba(56, 189, 248, 0.08)'
                    : result?.signingPipeline?.allSigned
                      ? 'rgba(16, 185, 129, 0.08)'
                      : 'rgba(245, 158, 11, 0.09)',
                  border: `1px solid ${
                    generating
                      ? 'rgba(56, 189, 248, 0.28)'
                      : result?.signingPipeline?.allSigned
                        ? 'rgba(16, 185, 129, 0.28)'
                        : 'rgba(245, 158, 11, 0.32)'
                  }`,
                  padding: '0.9rem 1rem',
                  borderRadius: '8px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.55rem'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem',
                      fontSize: '0.8rem',
                      fontWeight: 700,
                      color: generating
                        ? 'var(--primary)'
                        : result?.signingPipeline?.allSigned
                          ? '#34d399'
                          : '#fbbf24'
                    }}
                  >
                    <Shield size={16} />
                    <span>
                      {generating
                        ? 'Provisioning Enrollment Token & Running Server Signing Pipeline...'
                        : result?.signingPipeline?.allSigned
                          ? 'All Package Components Verified & Digitally Signed'
                          : 'Enrollment Token Provisioned (Unsigned / Partial Signing Pipeline)'}
                    </span>
                  </div>
                </div>

                {result?.signingPipeline?.stages && result.signingPipeline.stages.length > 0 && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem', fontSize: '0.73rem', color: 'var(--text-muted)' }}>
                    {result.signingPipeline.stages.map((st, idx) => {
                      const isOk = st.status === 'signed' || st.status === 'verified';
                      const isWarn = st.status === 'bypassed';
                      const marker = isOk ? '✓' : isWarn ? '○' : '✕';
                      const markerColor = isOk ? '#34d399' : isWarn ? '#fbbf24' : '#f87171';
                      return (
                        <div key={st.stepNumber || idx} style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem' }}>
                          <span>
                            <span style={{ color: markerColor, fontWeight: 700, marginRight: '0.35rem' }}>{marker}</span>
                            <strong>Step {st.stepNumber || idx + 1} ({st.component}):</strong> {st.description}
                          </span>
                          <span style={{ color: markerColor, textTransform: 'uppercase', fontSize: '0.68rem', fontWeight: 700, whiteSpace: 'nowrap' }}>
                            {st.status}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                )}
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
                  {safeInstallerUrl && (
                    <a
                      href={safeInstallerUrl}
                      download
                      className="btn-glass btn-primary"
                      style={{ textDecoration: 'none', flex: 1, justifyContent: 'center', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                    >
                      <Download size={16} />
                      <span>
                        Download {result.codeSigned ? 'Signed ' : ''}
                        {platform.toUpperCase()}{' '}
                        {platform === 'windows'
                          ? mode === 'quicksupport'
                            ? 'QuickSupport App (.exe)'
                            : 'Windows Installer (.exe)'
                          : mode === 'quicksupport'
                            ? 'QuickSupport Script (.sh)'
                            : 'Deploy Script (.sh)'}
                      </span>
                    </a>
                  )}
                  <button
                    type="button"
                    className="btn-glass"
                    onClick={() => {
                      setResult(null);
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
