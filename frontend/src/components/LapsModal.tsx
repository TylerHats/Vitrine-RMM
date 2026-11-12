import React, { useState, useEffect, useCallback } from 'react';
import { KeyRound, ShieldAlert, Copy, RotateCcw, X, CheckCircle, Eye, Clock, AlertCircle } from 'lucide-react';
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
  const [countdown, setCountdown] = useState(900);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showMfa, setShowMfa] = useState(false);
  const [pendingActionAfterMfa, setPendingActionAfterMfa] = useState<'reveal' | 'rotate'>('reveal');

  const isPasswordCleartext = (val?: string | null) => Boolean(val && !val.includes('••'));

  const loadLaps = useCallback(
    async (reveal: boolean) => {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchLapsPassword(device.id, reveal);
        if (data.mfaRequired) {
          setPendingActionAfterMfa('reveal');
          setShowMfa(true);
          return;
        }
        if (data.error) {
          setError(data.error);
          return;
        }
        setLapsData(data);
        if (reveal && isPasswordCleartext(data.password)) {
          setIsRevealed(true);
          setCountdown(900);
        } else if (!reveal) {
          setIsRevealed(false);
        }
      } catch (err: any) {
        setError(err?.message || 'Failed to load LAPS vault record.');
      } finally {
        setLoading(false);
      }
    },
    [device.id]
  );

  useEffect(() => {
    setIsRevealed(false);
    setLapsData(null);
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

  const executeRotation = async (revealAfterRotate: boolean) => {
    setLoading(true);
    setError(null);
    try {
      const data = await rotateLapsPassword(device.id, revealAfterRotate);
      if (data.mfaRequired) {
        setPendingActionAfterMfa('rotate');
        setShowMfa(true);
        return;
      }
      if (data.error) {
        setError(data.error);
        return;
      }
      setLapsData(data);
      if (revealAfterRotate && isPasswordCleartext(data.password)) {
        setIsRevealed(true);
        setCountdown(900);
      } else {
        setIsRevealed(false);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to rotate LAPS password.');
    } finally {
      setLoading(false);
    }
  };

  const handleRevealClick = () => {
    loadLaps(true);
  };

  const handleRotate = async () => {
    const promptMsg =
      device.lifecycle_state === 'pending_offboard'
        ? `${device.hostname} is queued in Pending Offboarding. Scheduled/manual rotations are skipped so the current local admin password is never lost before offboarding completes.`
        : device.status !== 'online'
          ? `${device.hostname} is currently OFFLINE. Queue a deferred rotation that will ONLY execute once the endpoint returns online (keeping the current working password intact in Vitrine so you are never locked out)?`
          : `Immediately rotate the local administrator (${lapsData?.accountName || 'LocalAdmin'}) password on ${device.hostname}?`;
    if (confirm(promptMsg)) {
      await executeRotation(device.status === 'online' && device.lifecycle_state !== 'pending_offboard');
    }
  };

  const handleCopy = () => {
    if (lapsData?.password && isRevealed && isPasswordCleartext(lapsData.password)) {
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
              <KeyRound size={20} style={{ color: 'var(--primary)' }} />
              <span>Automated LAPS Vault</span>
            </div>
            <button type="button" className="btn-glass btn-icon" onClick={onClose} id="close-laps-btn">
              <X size={18} />
            </button>
          </div>

          <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '1.15rem' }}>
            <div
              style={{
                background: 'rgba(0, 242, 254, 0.08)',
                border: '1px solid rgba(0, 242, 254, 0.2)',
                padding: '0.85rem 1rem',
                borderRadius: '8px'
              }}
            >
              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--primary)', marginBottom: '0.2rem' }}>
                Endpoint: {device.hostname}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Encrypted at rest with AES-256-GCM. Every reveal or rotation is recorded in the audit log.
              </div>
            </div>

            {error && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  background: 'rgba(239, 68, 68, 0.14)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  padding: '0.65rem 0.85rem',
                  borderRadius: '6px',
                  fontSize: '0.78rem',
                  color: '#f87171'
                }}
              >
                <AlertCircle size={15} />
                <span>{error}</span>
              </div>
            )}

            {lapsData?.autoRotateScheduled && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.6rem',
                  background: 'rgba(245, 158, 11, 0.12)',
                  border: '1px solid rgba(245, 158, 11, 0.3)',
                  padding: '0.65rem 0.85rem',
                  borderRadius: '6px',
                  fontSize: '0.75rem',
                  color: '#f59e0b'
                }}
              >
                <Clock size={16} />
                <span>
                  <strong>Rotate-On-Access Active:</strong> Password will auto-rotate upon grace window expiry.
                </span>
              </div>
            )}

            {(device.status !== 'online' ||
              lapsData?.rotationPendingOnline ||
              device.lifecycle_state === 'pending_offboard') && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '0.6rem',
                  background: 'rgba(56, 189, 248, 0.12)',
                  border: '1px solid rgba(56, 189, 248, 0.35)',
                  padding: '0.7rem 0.9rem',
                  borderRadius: '8px',
                  fontSize: '0.75rem',
                  color: 'var(--text-main)',
                  lineHeight: 1.45
                }}
              >
                <Clock size={16} style={{ flexShrink: 0, marginTop: '0.1rem', color: 'var(--primary)' }} />
                <div>
                  <strong>
                    {device.lifecycle_state === 'pending_offboard'
                      ? 'Pending Offboarding Guard Active (Scheduled Rotations Skipped):'
                      : 'Offline Lockout Protection Active (Rotation Deferred Until Online):'}
                  </strong>{' '}
                  {lapsData?.pendingRotationReason ||
                    (device.lifecycle_state === 'pending_offboard'
                      ? 'Because this endpoint is pending offboarding, scheduled LAPS rotations are skipped so the current local admin password remains intact.'
                      : 'Because this endpoint is currently offline, Vitrine preserves the last confirmed working password in the vault and defers any scheduled rotation until the agent reconnects.')}
                </div>
              </div>
            )}

            <div className="form-group" style={{ marginBottom: 0 }}>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '0.3rem'
                }}
              >
                <label className="form-label" style={{ margin: 0 }}>
                  Local Admin Username
                </label>
                {lapsData?.sid500BuiltinDisabled !== false && (
                  <span className="status-pill status-online" style={{ fontSize: '0.68rem' }}>
                    SID -500 Built-in Admin Disabled
                  </span>
                )}
              </div>
              <input type="text" className="glass-input" readOnly value={lapsData?.accountName || 'LocalAdmin'} />
              {lapsData?.previousAccountName && lapsData.previousAccountName !== lapsData.accountName && (
                <div style={{ fontSize: '0.72rem', color: 'var(--primary)', marginTop: '0.3rem' }}>
                  Previous Username: <code>{lapsData.previousAccountName}</code>
                </div>
              )}
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '0.35rem'
                }}
              >
                <label className="form-label" style={{ margin: 0 }}>
                  Current Password
                </label>
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
                  value={
                    isRevealed && isPasswordCleartext(lapsData?.password)
                      ? lapsData?.password
                      : '••••••••••••••••••••'
                  }
                />
                {isRevealed && isPasswordCleartext(lapsData?.password) ? (
                  <button type="button" className="btn-glass" onClick={handleCopy} title="Copy to clipboard">
                    {copied ? <CheckCircle size={16} color="#10b981" /> : <Copy size={16} />}
                  </button>
                ) : (
                  <button
                    type="button"
                    className="btn-glass btn-primary"
                    onClick={handleRevealClick}
                    disabled={loading}
                    id="reveal-laps-btn"
                  >
                    <Eye size={16} /> Reveal
                  </button>
                )}
              </div>
            </div>

            {isRevealed && isPasswordCleartext(lapsData?.previousPassword) && (
              <div
                className="form-group"
                style={{
                  marginBottom: 0,
                  background: 'var(--input-bg)',
                  padding: '0.65rem 0.85rem',
                  borderRadius: '8px',
                  border: '1px solid var(--glass-border)'
                }}
              >
                <label
                  className="form-label"
                  style={{ fontSize: '0.74rem', color: 'var(--text-dim)', marginBottom: '0.25rem' }}
                >
                  N-1 Historical Password ({lapsData?.previousAccountName || lapsData?.accountName})
                </label>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', userSelect: 'all' }}>
                  {lapsData?.previousPassword}
                </div>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
              <span>
                Last Rotated: {lapsData?.lastRotated ? new Date(lapsData.lastRotated).toLocaleDateString() : 'Recent'}
              </span>
              <span>
                Expires: {lapsData?.expiresAt ? new Date(lapsData.expiresAt).toLocaleDateString() : 'Policy Controlled'}
              </span>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.25)',
                padding: '0.65rem 0.85rem',
                borderRadius: '6px'
              }}
            >
              <ShieldAlert size={16} color="#ef4444" />
              <span style={{ fontSize: '0.72rem', color: '#f87171' }}>
                Revealing passwords records an immutable audit entry bound to your authenticated user session.
              </span>
            </div>
          </div>

          <div className="modal-footer" style={{ display: 'flex', justifyContent: 'space-between' }}>
            <button
              type="button"
              className="btn-glass"
              onClick={handleRotate}
              disabled={loading || device.lifecycle_state === 'archived'}
              style={{ color: 'var(--primary)' }}
            >
              <RotateCcw size={14} />{' '}
              {device.lifecycle_state === 'pending_offboard'
                ? 'Rotation Skipped (Pending Offboard)'
                : device.status !== 'online'
                  ? 'Queue Rotation for Next Check-In'
                  : 'Rotate Password Now'}
            </button>
            <button type="button" className="btn-glass btn-primary" onClick={onClose}>
              Done
            </button>
          </div>
        </div>
      </div>

      <MfaChallengeModal
        isOpen={showMfa}
        onClose={() => setShowMfa(false)}
        onSuccess={() => {
          if (pendingActionAfterMfa === 'rotate') {
            executeRotation(true);
          } else {
            loadLaps(true);
          }
        }}
        title="Step-Up MFA: Unlock LAPS Vault"
        description={`Verify your identity to decrypt the local administrator credentials for ${device.hostname}.`}
        secretType="laps_credential"
        deviceId={device.id}
      />
    </>
  );
};
