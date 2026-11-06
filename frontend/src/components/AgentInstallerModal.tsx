import React, { useState } from 'react';
import { Download, X, Shield, Copy, Check, Ticket } from 'lucide-react';
import { Tenant, Settings } from '../types/index.js';
import { generateInstaller } from '../services/api.js';

interface AgentInstallerModalProps {
  isOpen?: boolean;
  onClose: () => void;
  tenants: Tenant[];
  initialTenantId?: string;
  selectedTenantId?: string;
  settings?: Settings | null;
}

export const AgentInstallerModal: React.FC<AgentInstallerModalProps> = ({
  isOpen = true,
  onClose,
  tenants,
  initialTenantId,
  selectedTenantId,
  settings
}) => {
  const initialSelected = selectedTenantId || initialTenantId || 'all';
  const [tenantId, setTenantId] = useState(
    initialSelected && initialSelected !== 'all' ? initialSelected : tenants[0]?.id || ''
  );
  const [platform, setPlatform] = useState<'windows' | 'linux' | 'macos'>('windows');
  const [deviceRole, setDeviceRole] = useState('workstation');
  const [ticketNumber, setTicketNumber] = useState('');
  const [generating, setGenerating] = useState(false);
  const [result, setResult] = useState<{
    tokenId?: string;
    downloadCommand?: string;
    installerUrl?: string;
    codeSigned?: boolean;
    ticketBound?: string | null;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const requireTicket = Boolean(settings?.installer_require_ticket);
  const isCodeSigned = Boolean(settings?.code_signing_enabled && settings?.code_signing_sign_agents);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (requireTicket && !ticketNumber.trim()) {
      setError('A valid PSA / ITFlow Ticket # is strictly required by policy before downloading installers.');
      return;
    }

    setGenerating(true);
    setError(null);
    try {
      const res = await generateInstaller({
        tenant_id: tenantId,
        platform,
        device_role: deviceRole,
        ticket_number: ticketNumber.trim() || undefined,
        technician: 'Tyler Hats (Tech)'
      });

      if (res.success) {
        setResult(res);
      } else {
        setError(res.error || 'Failed to generate installer.');
      }
    } catch {
      setError('Communication error with installer provisioning engine.');
    } finally {
      setGenerating(false);
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
      <div className="glass-modal glass-modal-md" style={{ maxWidth: '680px' }}>
        <div className="modal-header">
          <div className="modal-title">
            <Download size={20} style={{ color: 'var(--primary)' }} />
            <span>Provision &amp; Download Vitrine Agent Installer</span>
          </div>
          <button className="btn-glass btn-icon" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleGenerate}>
          <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {error && (
              <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.3)', padding: '0.75rem 1rem', borderRadius: '8px', color: '#f87171', fontSize: '0.8rem' }}>
                {error}
              </div>
            )}

            {/* Target Client / Mesh Group */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '1rem' }}>
              <div className="form-group">
                <label className="form-label">Client Tenant (Mesh Group Mapping)</label>
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
                  disabled={generating || Boolean(result)}
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
                    { id: 'windows', label: 'Windows', sub: 'x64 / x86 + Tray' },
                    { id: 'linux', label: 'Linux', sub: 'systemd Daemon' },
                    { id: 'macos', label: 'macOS', sub: 'Universal ARM64/Intel' }
                  ] as const
                ).map((p) => (
                  <div
                    key={p.id}
                    onClick={() => !result && setPlatform(p.id)}
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

            {/* PSA / ITFlow Ticket Locking (User Request 2) */}
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
                placeholder="e.g. TKT-2026-8492"
                required={requireTicket}
                value={ticketNumber}
                onChange={(e) => setTicketNumber(e.target.value)}
                disabled={generating || Boolean(result)}
              />
              <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.25rem', display: 'block' }}>
                Vitrine adds an audit note upon installer generation and posts a follow-up note when the machine enrolls.
              </span>
            </div>

            {/* Code Signing Status Indicator */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.25)', padding: '0.65rem 0.85rem', borderRadius: '6px', fontSize: '0.75rem' }}>
              <Shield size={16} color="#10b981" />
              <span>
                <strong>Authenticode Code Signing:</strong> {isCodeSigned ? 'Enabled (Signed via HSM with RFC 3161 Timestamp)' : 'Direct Raw Deployment'}
              </span>
            </div>

            {/* Result Display */}
            {result && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', background: 'rgba(0, 0, 0, 0.35)', border: '1px solid var(--glass-border)', padding: '1rem', borderRadius: '8px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--primary)' }}>
                    One-Liner Terminal Bootstrap Command:
                  </span>
                  <button type="button" className="btn-glass" style={{ padding: '0.2rem 0.55rem', fontSize: '0.72rem' }} onClick={handleCopy}>
                    {copied ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                    <span>{copied ? 'Copied!' : 'Copy'}</span>
                  </button>
                </div>
                <input
                  type="text"
                  readOnly
                  className="glass-input"
                  style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#00f2fe' }}
                  value={result.downloadCommand || ''}
                />

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.5rem' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                    Token: <code>{result.tokenId}</code> • Bound to Ticket #{result.ticketBound || 'N/A'}
                  </span>
                  <a
                    href={result.installerUrl}
                    download
                    className="btn-glass btn-primary"
                    style={{ textDecoration: 'none', padding: '0.35rem 0.75rem', fontSize: '0.8rem' }}
                  >
                    <Download size={14} /> Download Standalone Package
                  </a>
                </div>
              </div>
            )}
          </div>

          <div className="modal-footer" style={{ marginTop: '1rem' }}>
            {result ? (
              <button type="button" className="btn-glass btn-primary" onClick={onClose}>
                Done
              </button>
            ) : (
              <>
                <button type="button" className="btn-glass" onClick={onClose} disabled={generating}>
                  Cancel
                </button>
                <button type="submit" className="btn-glass btn-primary" disabled={generating}>
                  {generating ? 'Generating & Signing...' : 'Generate Installer Package'}
                </button>
              </>
            )}
          </div>
        </form>
      </div>
    </div>
  );
};
