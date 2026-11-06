import React, { useState } from 'react';
import { ShieldCheck, Lock, AlertCircle, X, Check } from 'lucide-react';
import { verifyMfa } from '../services/api.js';

interface MfaChallengeModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  title?: string;
  description?: string;
  secretType?: string;
  deviceId?: string;
}

export const MfaChallengeModal: React.FC<MfaChallengeModalProps> = ({
  isOpen,
  onClose,
  onSuccess,
  title = 'Step-Up MFA Verification Required',
  description = 'To view this sensitive secret (LAPS / BitLocker / Secure Attribute), enter your 6-digit authenticator token.',
  secretType = 'laps_credential',
  deviceId
}) => {
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!code || code.trim().length < 6) {
      setError('Please enter a valid 6-digit verification code.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await verifyMfa(code.trim(), secretType, deviceId);
      if (res.success) {
        onSuccess();
        onClose();
      } else {
        setError(res.error || 'Invalid authentication code. Please try again.');
      }
    } catch {
      setError('Failed to communicate with authentication service.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-backdrop" id="mfa-challenge-modal" style={{ zIndex: 9999 }}>
      <div className="glass-modal glass-modal-sm" style={{ border: '1px solid rgba(0, 242, 254, 0.3)' }}>
        <div className="modal-header">
          <div className="modal-title">
            <Lock size={20} style={{ color: '#00f2fe' }} />
            <span>{title}</span>
          </div>
          <button className="btn-glass btn-icon" onClick={onClose} id="close-mfa-btn">
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div style={{
              background: 'rgba(0, 242, 254, 0.08)',
              border: '1px solid rgba(0, 242, 254, 0.2)',
              padding: '0.85rem 1rem',
              borderRadius: '8px',
              fontSize: '0.8rem',
              color: 'var(--text-dim)',
              lineHeight: 1.4
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600, color: '#00f2fe', marginBottom: '0.3rem' }}>
                <ShieldCheck size={16} />
                Zero-Trust Secret Protection
              </div>
              {description}
            </div>

            {error && (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                background: 'rgba(239, 68, 68, 0.15)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                padding: '0.65rem 0.85rem',
                borderRadius: '6px',
                fontSize: '0.78rem',
                color: '#f87171'
              }}>
                <AlertCircle size={16} />
                <span>{error}</span>
              </div>
            )}

            <div className="form-group">
              <label className="form-label" style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>6-Digit Authenticator Code (TOTP)</span>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>e.g. 123456</span>
              </label>
              <input
                type="text"
                className="glass-input"
                maxLength={6}
                autoFocus
                placeholder="000000"
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                style={{
                  fontSize: '1.4rem',
                  letterSpacing: '0.35em',
                  textAlign: 'center',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  color: '#00f2fe'
                }}
              />
            </div>
          </div>

          <div className="modal-footer" style={{ marginTop: '1rem' }}>
            <button type="button" className="btn-glass" onClick={onClose} disabled={loading}>
              Cancel
            </button>
            <button
              type="submit"
              className="btn-glass btn-primary"
              disabled={loading || code.length < 6}
              id="confirm-mfa-btn"
            >
              {loading ? 'Verifying...' : (
                <>
                  <Check size={16} /> Verify & Unlock
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
