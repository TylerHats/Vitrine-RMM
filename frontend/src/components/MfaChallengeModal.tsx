import React, { useState, useEffect } from 'react';
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
  description = 'To decrypt this protected secret (LAPS / BitLocker / Break-Glass Vault), enter your 6-digit TOTP code or a single-use recovery code.',
  secretType = 'laps_credential',
  deviceId
}) => {
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isOpen) {
      setCode('');
      setError(null);
      setLoading(false);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleaned = code.trim();
    if (cleaned.length < 6) {
      setError('Enter a valid 6-digit authenticator code or 8-character recovery code.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await verifyMfa(cleaned, secretType, deviceId);
      if (res.success) {
        setCode('');
        onSuccess();
        onClose();
      } else {
        setError(res.error || 'Invalid authentication or recovery code. Please try again.');
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
            <Lock size={20} style={{ color: 'var(--primary)' }} />
            <span>{title}</span>
          </div>
          <button type="button" className="btn-glass btn-icon" onClick={onClose} id="close-mfa-btn">
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div
              style={{
                background: 'rgba(0, 242, 254, 0.08)',
                border: '1px solid rgba(0, 242, 254, 0.2)',
                padding: '0.85rem 1rem',
                borderRadius: '8px',
                fontSize: '0.8rem',
                color: 'var(--text-muted)',
                lineHeight: 1.45
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  fontWeight: 600,
                  color: 'var(--primary)',
                  marginBottom: '0.3rem'
                }}
              >
                <ShieldCheck size={16} />
                Zero-Trust Step-Up Secret Protection
              </div>
              {description}
            </div>

            {error && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  background: 'rgba(239, 68, 68, 0.15)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  padding: '0.65rem 0.85rem',
                  borderRadius: '6px',
                  fontSize: '0.78rem',
                  color: '#f87171'
                }}
              >
                <AlertCircle size={16} />
                <span>{error}</span>
              </div>
            )}

            <div className="form-group">
              <label className="form-label" style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>6-Digit TOTP or Recovery Code</span>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'none' }}>
                  RFC 6238 / XXXX-XXXX
                </span>
              </label>
              <input
                type="text"
                className="glass-input"
                maxLength={12}
                autoFocus
                placeholder="000000"
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/[^0-9a-zA-Z-]/g, '').toUpperCase())}
                style={{
                  fontSize: '1.35rem',
                  letterSpacing: '0.25em',
                  textAlign: 'center',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  color: 'var(--primary)'
                }}
              />
            </div>
          </div>

          <div className="modal-footer" style={{ marginTop: '0.5rem' }}>
            <button type="button" className="btn-glass" onClick={onClose} disabled={loading}>
              Cancel
            </button>
            <button
              type="submit"
              className="btn-glass btn-primary"
              disabled={loading || code.trim().length < 6}
              id="confirm-mfa-btn"
            >
              {loading ? (
                'Verifying...'
              ) : (
                <>
                  <Check size={16} /> Verify &amp; Unlock
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
