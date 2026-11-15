import React, { useState } from 'react';
import { ShieldAlert, ShieldCheck, X, AlertTriangle, AlertCircle } from 'lucide-react';
import { Device } from '../types/index.js';
import { toggleQuarantine } from '../services/api.js';
import { MfaChallengeModal } from './MfaChallengeModal.js';

interface CyberIsolationModalProps {
  device: Device;
  onClose: () => void;
  onUpdated: (quarantined: boolean) => void;
}

export const CyberIsolationModal: React.FC<CyberIsolationModalProps> = ({
  device,
  onClose,
  onUpdated
}) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mfaOpen, setMfaOpen] = useState(false);
  const isIsolated = Boolean(device.quarantined);

  const handleToggle = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await toggleQuarantine(device.id, !isIsolated);
      if (res.mfaRequired) {
        setMfaOpen(true);
        return;
      }
      if (!res.success) {
        setError(res.error || 'Failed to update endpoint quarantine state.');
        return;
      }
      onUpdated(res.quarantined);
      onClose();
    } catch (err: any) {
      setError(err?.message || 'Failed to update endpoint quarantine state.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-backdrop" id="quarantine-modal">
      <div className="glass-modal glass-modal-sm">
        <div className="modal-header">
          <div className="modal-title">
            <ShieldAlert size={20} style={{ color: isIsolated ? '#10b981' : '#ef4444' }} />
            <span>Endpoint Cyber Isolation (Quarantine)</span>
          </div>
          <button className="btn-glass btn-icon" onClick={onClose} id="close-quarantine-btn">
            <X size={18} />
          </button>
        </div>

        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div
            style={{
              padding: '1rem',
              borderRadius: '8px',
              background: isIsolated ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.12)',
              border: `1px solid ${isIsolated ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
              display: 'flex',
              gap: '0.85rem'
            }}
          >
            <AlertTriangle size={24} color={isIsolated ? '#10b981' : '#ef4444'} style={{ flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 600, color: isIsolated ? '#10b981' : '#f87171', marginBottom: '0.25rem' }}>
                {isIsolated ? 'Target Endpoint is Currently Isolated' : 'Emergency Cyber Containment'}
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-main)', lineHeight: 1.45 }}>
                {isIsolated ? (
                  'All general inbound and outbound network connectivity is blocked. Only the Vitrine & MeshCentral RMM management tunnel remains connected for forensic inspection.'
                ) : (
                  'Engaging Cyber Isolation injects strict host firewall rules dropping all local and internet traffic immediately. The persistent WebSocket control tunnel back to Vitrine is preserved.'
                )}
              </div>
            </div>
          </div>

          <div style={{ background: 'rgba(0, 0, 0, 0.25)', padding: '1rem', borderRadius: '8px' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', marginBottom: '0.5rem' }}>ISOLATION FIREWALL RULES</div>
            <ul style={{ fontSize: '0.78rem', color: 'var(--text-muted)', paddingLeft: '1.2rem', lineHeight: 1.6 }}>
              <li><code>BLOCK INBOUND *</code> from entire LAN and WAN</li>
              <li><code>BLOCK OUTBOUND *</code> preventing malware lateral movement</li>
              <li><code>ALLOW OUTBOUND TCP 443 / 8080</code> to Vitrine RMM server only</li>
            </ul>
          </div>

          <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
            Target: <strong>{device.hostname}</strong> ({device.ip_address})<br />
            Tenant: <strong>{device.tenant_name || 'Unassigned Client'}</strong>
          </div>

          {error && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.55rem',
                padding: '0.7rem 0.9rem',
                borderRadius: '8px',
                background: 'rgba(239, 68, 68, 0.14)',
                border: '1px solid rgba(239, 68, 68, 0.35)',
                color: '#f87171',
                fontSize: '0.8rem'
              }}
            >
              <AlertCircle size={16} style={{ flexShrink: 0 }} />
              <span>{error}</span>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button className="btn-glass" onClick={onClose} disabled={loading}>
            Cancel
          </button>
          <button
            className={`btn-glass ${isIsolated ? 'btn-primary' : 'btn-danger'}`}
            onClick={handleToggle}
            disabled={loading}
            id="confirm-quarantine-btn"
          >
            {isIsolated ? (
              <>
                <ShieldCheck size={16} /> Restore Network Traffic
              </>
            ) : (
              <>
                <ShieldAlert size={16} /> Engage Cyber Isolation
              </>
            )}
          </button>
        </div>
      </div>

      <MfaChallengeModal
        isOpen={mfaOpen}
        onClose={() => setMfaOpen(false)}
        onSuccess={() => {
          setMfaOpen(false);
          handleToggle();
        }}
        title="Step-Up MFA: Endpoint Cyber Isolation"
        description="Enter your 6-digit TOTP authenticator code or recovery code to modify endpoint quarantine firewall containment."
        secretType="device_quarantine"
        deviceId={device.id}
      />
    </div>
  );
};
