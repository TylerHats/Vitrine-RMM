import React, { useState, useEffect, useCallback } from 'react';
import { KeyRound, ShieldAlert, Copy, RotateCcw, X, CheckCircle, Eye, Clock } from 'lucide-react';
import { Device, LapsCredential } from '../types/index.js';
import { fetchLapsPassword, rotateLapsPassword } from '../services/api.js';
import { MfaChallengeModal } from './MfaChallengeModal.js';

interface LapsModalProps {
  device: Device;
  onClose: () => void;
}

export const LapsModal: React.FC<LapsModalProps> = ({ device, onClose }) => {
  const [lapsData, setLapsData] = useState<LapsCredential | null>(null);
  const [isRevealed, setIsRevealed] = useState(false);
  const [copied, setCopied] = useState(false);
  const [countdown, setCountdown] = useState(900); // 15 minutes timed reveal
  const [loading, setLoading] = useState(false);
  const [showMfa, setShowMfa] = useState(false);

  const loadLaps = useCallback(async (reveal: boolean) => {
    setLoading(true);
    try {
      const data = await fetchLapsPassword(device.id, reveal);
      setLapsData(data);
      if (reveal) setIsRevealed(true);
    } finally {
      setLoading(false);
    }
  }, [device.id]);

  useEffect(() => {
    loadLaps(false);
  }, [loadLaps]);

  useEffect(() => {
    if (!isRevealed) return;
    const interval = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          setIsRevealed(false);
          loadLaps(false);
          return 900;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [isRevealed, loadLaps]);

  const handleRevealClick = () => {
    const pol = device.policy as Record<string, unknown> | undefined;
    const requiresMfa =
      pol?.requireMfaForSecrets !== false &&
      pol?.require_mfa_for_secrets !== false &&
      pol?.require_mfa_for_secrets !== 0;
    if (requiresMfa) {
      setShowMfa(true);
    } else {
      loadLaps(true);
    }
  };

  const handleRotate = async () => {
    if (confirm(`Immediately rotate the local administrator (${lapsData?.accountName || 'LocalAdmin'}) password on ${device.hostname}?`)) {
      setLoading(true);
      try {
        const data = await rotateLapsPassword(device.id);
        setLapsData(data);
        setIsRevealed(true);
        setCountdown(900);
      } finally {
        setLoading(false);
      }
    }
  };

  const handleCopy = () => {
    if (lapsData?.password && isRevealed) {
      navigator.clipboard.writeText(lapsData.password);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const formatTime = (secs: number) => {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}:${s < 10 ? '0' : ''}${s}`;
  };

  return (
    <>
      <div className="modal-backdrop" id="laps-modal">
        <div className="glass-modal glass-modal-sm">
          <div className="modal-header">
            <div className="modal-title">
              <KeyRound size={20} style={{ color: '#00f2fe' }} />
              <span>Automated LAPS Vault</span>
            </div>
            <button className="btn-glass btn-icon" onClick={onClose} id="close-laps-btn">
              <X size={18} />
            </button>
          </div>

          <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div style={{ background: 'rgba(0, 242, 254, 0.08)', border: '1px solid rgba(0, 242, 254, 0.2)', padding: '0.85rem 1rem', borderRadius: '8px' }}>
              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--primary)', marginBottom: '0.2rem' }}>
                Endpoint: {device.hostname}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Managed by Vitrine AES-256-GCM Vault. Access is logged in the immutable audit log.
              </div>
            </div>

            {lapsData?.autoRotateScheduled && (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.6rem',
                background: 'rgba(245, 158, 11, 0.12)',
                border: '1px solid rgba(245, 158, 11, 0.3)',
                padding: '0.65rem 0.85rem',
                borderRadius: '6px',
                fontSize: '0.75rem',
                color: '#f59e0b'
              }}>
                <Clock size={16} />
                <span><strong>Rotate-On-Access Active:</strong> Password will auto-rotate upon technician grace window expiry.</span>
              </div>
            )}

            <div className="form-group">
              <label className="form-label">Local Admin Username</label>
              <input type="text" className="glass-input" readOnly value={lapsData?.accountName || 'LocalAdmin'} />
            </div>

            <div className="form-group">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                <label className="form-label" style={{ margin: 0 }}>Password</label>
                {isRevealed && (
                  <span style={{ fontSize: '0.75rem', color: '#f59e0b', fontWeight: 600 }}>
                    Auto-Masking in {formatTime(countdown)}
                  </span>
                )}
              </div>

              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <input
                  type="text"
                  className="glass-input"
                  style={{ fontFamily: 'var(--font-mono)', letterSpacing: isRevealed ? '0.05em' : '0.2em' }}
                  readOnly
                  value={isRevealed ? lapsData?.password : '••••••••••••••••••••'}
                />
                {isRevealed ? (
                  <button className="btn-glass" onClick={handleCopy} title="Copy to clipboard">
                    {copied ? <CheckCircle size={16} color="#10b981" /> : <Copy size={16} />}
                  </button>
                ) : (
                  <button className="btn-glass btn-primary" onClick={handleRevealClick}>
                    <Eye size={16} /> Reveal (MFA)
                  </button>
                )}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
              <span>Last Rotated: {lapsData?.lastRotated ? new Date(lapsData.lastRotated).toLocaleDateString() : 'Recent'}</span>
              <span>Expires: {lapsData?.expiresAt ? new Date(lapsData.expiresAt).toLocaleDateString() : 'Policy Controlled'}</span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.25)', padding: '0.65rem 0.85rem', borderRadius: '6px' }}>
              <ShieldAlert size={16} color="#ef4444" />
              <span style={{ fontSize: '0.72rem', color: '#f87171' }}>
                Revealing passwords creates a tamper-evident audit entry associated with your technician session.
              </span>
            </div>
          </div>

          <div className="modal-footer" style={{ display: 'flex', justifyContent: 'space-between' }}>
            <button className="btn-glass" onClick={handleRotate} disabled={loading} style={{ color: '#00f2fe' }}>
              <RotateCcw size={14} /> Rotate Password On-Demand
            </button>
            <button className="btn-glass btn-primary" onClick={onClose}>
              Done
            </button>
          </div>
        </div>
      </div>

      <MfaChallengeModal
        isOpen={showMfa}
        onClose={() => setShowMfa(false)}
        onSuccess={() => loadLaps(true)}
        title="Step-Up MFA: Reveal LAPS Password"
        description={`Enter your 6-digit authenticator code to decrypt the local admin password for ${device.hostname}.`}
        secretType="laps_credential"
        deviceId={device.id}
      />
    </>
  );
};
