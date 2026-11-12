import React, { useState } from 'react';
import {
  ShieldCheck,
  Lock,
  User,
  Mail,
  KeyRound,
  Copy,
  Download,
  CheckCircle,
  AlertCircle,
  ArrowRight,
  LifeBuoy
} from 'lucide-react';
import { setupInitialSuperAdmin, loginWithPassword } from '../services/api.js';
import { AuthStatusResponse, AuthUser } from '../types/index.js';

interface LoginViewProps {
  authStatus: AuthStatusResponse;
  onAuthenticated: (user: AuthUser, triggerOobe?: boolean) => void;
  onOpenQuickSupport?: () => void;
}

export const LoginView: React.FC<LoginViewProps> = ({
  authStatus,
  onAuthenticated,
  onOpenQuickSupport
}) => {
  const isFirstSetup = !authStatus.initialized;
  const brandName = authStatus.branding?.brand_name || 'Vitrine RMM';
  const brandLogoUrl = authStatus.branding?.brand_logo_url || '/logo.png';

  const [username, setUsername] = useState(isFirstSetup ? 'admin' : '');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Post-bootstrap MFA Enrollment & Recovery Codes screen
  const [provisionedMfa, setProvisionedMfa] = useState<{
    user: AuthUser;
    totpSecret: string;
    otpAuthUri: string;
    recoveryCodes: string[];
  } | null>(null);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);
  const [confirmedSaved, setConfirmedSaved] = useState(false);

  const handleBootstrapSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!username.trim() || !email.trim()) {
      setError('Administrator username and email address are required.');
      return;
    }
    if (password.length < 10) {
      setError('Master password must be at least 10 characters long.');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      const res = await setupInitialSuperAdmin({
        username: username.trim(),
        email: email.trim(),
        password
      });
      if (!res.success || !res.user) {
        setError(res.error || 'Failed to initialize Super Admin account.');
        return;
      }
      setProvisionedMfa({
        user: res.user,
        totpSecret: res.totpSecret || '',
        otpAuthUri: res.otpAuthUri || '',
        recoveryCodes: res.recoveryCodes || []
      });
    } catch (err: any) {
      setError(err?.message || 'Unable to reach Vitrine authentication service.');
    } finally {
      setLoading(false);
    }
  };

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!username.trim() || !password) {
      setError('Please enter your username and password.');
      return;
    }

    setLoading(true);
    try {
      const res = await loginWithPassword({
        username: username.trim(),
        password
      });
      if (!res.success || !res.user) {
        setError(res.error || 'Invalid username or password.');
        return;
      }
      onAuthenticated(res.user, !authStatus.isOnboarded);
    } catch (err: any) {
      setError(err?.message || 'Authentication request failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadRecoveryKit = () => {
    if (!provisionedMfa) return;
    const content = [
      `${brandName} — Initial Super Admin MFA & Recovery Kit`,
      `Generated: ${new Date().toISOString()}`,
      `Username: ${provisionedMfa.user.username}`,
      `Email: ${provisionedMfa.user.email}`,
      '',
      `TOTP Base32 Secret (RFC 6238 / SHA-1 / 6 Digits / 30s):`,
      provisionedMfa.totpSecret,
      '',
      `Authenticator URI:`,
      provisionedMfa.otpAuthUri,
      '',
      `Single-Use Emergency Recovery Codes (Store Offline):`,
      ...provisionedMfa.recoveryCodes.map((c, idx) => `  ${idx + 1}. ${c}`)
    ].join('\n');

    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vitrine-rmm-recovery-codes-${provisionedMfa.user.username}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (provisionedMfa) {
    return (
      <div
        style={{
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '1.5rem'
        }}
      >
        <div className="glass-card" style={{ maxWidth: '620px', width: '100%', padding: '2rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', marginBottom: '1.25rem' }}>
            <ShieldCheck size={28} color="var(--accent-success)" />
            <div>
              <h2 style={{ fontSize: '1.35rem', fontWeight: 700 }}>
                Enroll Step-Up MFA &amp; Save Recovery Codes
              </h2>
              <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                Required to decrypt LAPS local admin passwords, BitLocker keys, and Break-Glass exports.
              </p>
            </div>
          </div>

          <div
            style={{
              background: 'rgba(0, 242, 254, 0.08)',
              border: '1px solid rgba(0, 242, 254, 0.25)',
              borderRadius: '10px',
              padding: '1rem',
              marginBottom: '1.1rem'
            }}
          >
            <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--primary)', marginBottom: '0.35rem' }}>
              1. Add Base32 Secret to Authenticator App (1Password, Bitwarden, Authy, Google/Microsoft Authenticator)
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <input
                type="text"
                readOnly
                className="glass-input"
                value={provisionedMfa.totpSecret}
                style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, letterSpacing: '0.1em' }}
              />
              <button
                type="button"
                className="btn-glass"
                onClick={() => {
                  navigator.clipboard.writeText(provisionedMfa.totpSecret);
                  setCopiedSecret(true);
                  setTimeout(() => setCopiedSecret(false), 2000);
                }}
              >
                {copiedSecret ? <CheckCircle size={15} color="#10b981" /> : <Copy size={15} />}
                <span>{copiedSecret ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </div>

          <div
            style={{
              background: 'rgba(245, 158, 11, 0.08)',
              border: '1px solid rgba(245, 158, 11, 0.28)',
              borderRadius: '10px',
              padding: '1rem',
              marginBottom: '1.1rem'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.76rem', fontWeight: 600, color: 'var(--accent-warning)' }}>
                2. One-Time Emergency Recovery Codes (8 Single-Use Backup Codes)
              </span>
              <div style={{ display: 'flex', gap: '0.4rem' }}>
                <button
                  type="button"
                  className="btn-glass"
                  style={{ padding: '0.3rem 0.65rem', fontSize: '0.75rem' }}
                  onClick={() => {
                    navigator.clipboard.writeText(provisionedMfa.recoveryCodes.join('\n'));
                    setCopiedCodes(true);
                    setTimeout(() => setCopiedCodes(false), 2000);
                  }}
                >
                  {copiedCodes ? <CheckCircle size={13} color="#10b981" /> : <Copy size={13} />}
                  <span>{copiedCodes ? 'Copied' : 'Copy All'}</span>
                </button>
                <button
                  type="button"
                  className="btn-glass"
                  style={{ padding: '0.3rem 0.65rem', fontSize: '0.75rem' }}
                  onClick={handleDownloadRecoveryKit}
                >
                  <Download size={13} />
                  <span>Download .txt</span>
                </button>
              </div>
            </div>
            <div className="grid-2" style={{ gap: '0.45rem' }}>
              {provisionedMfa.recoveryCodes.map((code) => (
                <div
                  key={code}
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.84rem',
                    padding: '0.4rem 0.65rem',
                    borderRadius: '6px',
                    background: 'var(--input-bg)',
                    border: '1px solid var(--glass-border)',
                    textAlign: 'center',
                    fontWeight: 600
                  }}
                >
                  {code}
                </div>
              ))}
            </div>
          </div>

          <label
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.6rem',
              fontSize: '0.82rem',
              cursor: 'pointer',
              marginBottom: '1.25rem'
            }}
          >
            <input
              type="checkbox"
              checked={confirmedSaved}
              onChange={(e) => setConfirmedSaved(e.target.checked)}
            />
            <span>I have enrolled my TOTP authenticator or saved my emergency recovery codes offline.</span>
          </label>

          <button
            type="button"
            className="btn-glass btn-primary"
            style={{ width: '100%', padding: '0.75rem' }}
            disabled={!confirmedSaved}
            onClick={() => onAuthenticated(provisionedMfa.user, true)}
            id="complete-admin-bootstrap-btn"
          >
            <span>Continue to Guided OOBE Setup</span>
            <ArrowRight size={16} />
          </button>
        </div>
      </div>
    );
  }

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1.5rem'
      }}
    >
      <div className="glass-card" style={{ maxWidth: '460px', width: '100%', padding: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', marginBottom: '1.5rem' }}>
          <img src={brandLogoUrl} alt={brandName} className="brand-logo-img" style={{ width: 42, height: 42 }} />
          <div>
            <div className="brand-title" style={{ fontSize: '1.35rem' }}>
              {brandName}
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              {isFirstSetup
                ? 'First-Visit Setup — Create MSP Super Admin Account'
                : 'Zero-Trust Control Plane Sign In'}
            </div>
          </div>
        </div>

        {error && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.55rem',
              background: 'rgba(239, 68, 68, 0.14)',
              border: '1px solid rgba(239, 68, 68, 0.35)',
              color: '#f87171',
              padding: '0.7rem 0.9rem',
              borderRadius: '8px',
              fontSize: '0.8rem',
              marginBottom: '1.1rem'
            }}
          >
            <AlertCircle size={16} style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={isFirstSetup ? handleBootstrapSubmit : handleLoginSubmit}>
          <div className="form-group">
            <label className="form-label">
              <User size={13} style={{ display: 'inline', marginRight: 5 }} />
              {isFirstSetup ? 'Super Admin Username' : 'Username or Email'}
            </label>
            <input
              type="text"
              className="glass-input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="admin"
              autoFocus
              required
              id="login-username-input"
            />
          </div>

          {isFirstSetup && (
            <div className="form-group">
              <label className="form-label">
                <Mail size={13} style={{ display: 'inline', marginRight: 5 }} />
                Administrator Email
              </label>
              <input
                type="email"
                className="glass-input"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="ops@yourmsp.com"
                required
                id="login-email-input"
              />
            </div>
          )}

          <div className="form-group">
            <label className="form-label">
              <Lock size={13} style={{ display: 'inline', marginRight: 5 }} />
              Password {isFirstSetup && '(Minimum 10 characters)'}
            </label>
            <input
              type="password"
              className="glass-input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              required
              id="login-password-input"
            />
          </div>

          {isFirstSetup && (
            <div className="form-group">
              <label className="form-label">
                <KeyRound size={13} style={{ display: 'inline', marginRight: 5 }} />
                Confirm Master Password
              </label>
              <input
                type="password"
                className="glass-input"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="••••••••••••"
                required
                id="login-confirm-password-input"
              />
            </div>
          )}

          <button
            type="submit"
            className="btn-glass btn-primary"
            style={{ width: '100%', padding: '0.75rem', marginTop: '0.35rem' }}
            disabled={loading}
            id="login-submit-btn"
          >
            {loading
              ? isFirstSetup
                ? 'Provisioning Encrypted Vault & Admin...'
                : 'Signing In...'
              : isFirstSetup
                ? 'Initialize Super Admin & Vault'
                : 'Sign In to Control Plane'}
          </button>
        </form>

        {onOpenQuickSupport && (
          <div
            style={{
              marginTop: '1.25rem',
              paddingTop: '1rem',
              borderTop: '1px solid var(--glass-border)',
              display: 'flex',
              justifyContent: 'center'
            }}
          >
            <button
              type="button"
              className="btn-glass"
              style={{ fontSize: '0.78rem', padding: '0.4rem 0.85rem' }}
              onClick={onOpenQuickSupport}
            >
              <LifeBuoy size={14} />
              <span>Need On-Demand Client Support? Open QuickSupport Portal</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

