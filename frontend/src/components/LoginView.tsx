import React, { useState, useEffect } from 'react';
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
  LifeBuoy,
  Globe
} from 'lucide-react';
import {
  setupInitialSuperAdmin,
  loginWithPassword,
  verifyLoginMfa,
  getLocalQrSvgUrl,
  verifyMfa,
  fetchMfaEnrollment
} from '../services/api.js';
import { AuthStatusResponse, AuthUser } from '../types/index.js';
import { copyToClipboard } from '../utils/clipboard.js';
import { isSuperAdmin as checkIsSuperAdmin } from '../utils/permissions.js';
import { sanitizeSafeUrl } from '../utils/urlSafety.js';

const SSO_ERROR_MESSAGES: Record<string, string> = {
  access_denied: 'Single Sign-On authorization was cancelled or denied by the identity provider.',
  invalid_request: 'Invalid Single Sign-On request parameters.',
  unauthorized_client: 'OIDC client is not authorized for this grant type.',
  invalid_state: 'Single Sign-On session state mismatch or expired. Please try signing in again.',
  missing_code: 'Identity provider callback did not include an authorization code.',
  oidc_disabled: 'OpenID Connect SSO is currently disabled by your administrator.',
  oidc_not_configured: 'OpenID Connect SSO is not yet configured on this server.',
  token_exchange_failed: 'Failed to exchange authorization code with the OIDC identity provider.',
  invalid_id_token: 'Identity provider returned an invalid or untrusted ID token.',
  email_unverified: 'Your SSO provider did not assert a verified email address.',
  user_not_provisioned: 'No matching Vitrine user account is provisioned for your SSO identity.',
  user_disabled: 'Your user account has been disabled. Contact your administrator.',
  server_error: 'The OIDC identity provider encountered an internal error.',
  temporarily_unavailable: 'The OIDC identity provider is temporarily unavailable.',
  sso_failed: 'Single Sign-On authentication failed. Please try again or use local credentials.'
};

interface LoginViewProps {
  authStatus: AuthStatusResponse;
  onAuthenticated: (user: AuthUser, triggerOobe?: boolean) => void;
  onOpenQuickSupport?: () => void;
  pendingMfaUser?: AuthUser | null;
  onSignOutPendingMfa?: () => Promise<void> | void;
}

export const LoginView: React.FC<LoginViewProps> = ({
  authStatus,
  onAuthenticated,
  onOpenQuickSupport,
  pendingMfaUser,
  onSignOutPendingMfa
}) => {
  const isFirstSetup = !authStatus.initialized;
  const brandName = authStatus.branding?.brand_name || 'Vitrine RMM';
  const brandLogoUrl = sanitizeSafeUrl(authStatus.branding?.brand_logo_url) || '/branding/logo.png';

  const [username, setUsername] = useState(isFirstSetup ? 'admin' : '');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const ssoErr = params.get('sso_error');
    if (ssoErr) {
      const normalized = ssoErr.trim().toLowerCase();
      setError(SSO_ERROR_MESSAGES[normalized] || SSO_ERROR_MESSAGES.sso_failed);
      params.delete('sso_error');
      const cleanQuery = params.toString();
      const nextUrl = `${window.location.pathname}${cleanQuery ? `?${cleanQuery}` : ''}${window.location.hash}`;
      window.history.replaceState({}, '', nextUrl);
    }
  }, []);

  // Post-bootstrap MFA Enrollment & Recovery Codes screen
  const [provisionedMfa, setProvisionedMfa] = useState<{
    user: AuthUser;
    totpSecret: string;
    otpAuthUri: string;
    qrSvg?: string;
    recoveryCodes: string[];
    remainingRecoveryCodes?: number;
    resumed?: boolean;
  } | null>(null);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);
  const [totpCode, setTotpCode] = useState('');
  const [mfaVerifying, setMfaVerifying] = useState(false);
  const [mfaVerifyError, setMfaVerifyError] = useState<string | null>(null);
  const [loadingPendingMfa, setLoadingPendingMfa] = useState(false);
  const [pendingMfaLoadError, setPendingMfaLoadError] = useState<string | null>(null);

  // Returning user sign-in TOTP MFA challenge state
  const [loginMfaChallenge, setLoginMfaChallenge] = useState<{
    token: string;
    username: string;
  } | null>(null);
  const [loginMfaCode, setLoginMfaCode] = useState('');
  const [loginMfaError, setLoginMfaError] = useState<string | null>(null);
  const [loginMfaSubmitting, setLoginMfaSubmitting] = useState(false);

  const loadPendingMfaEnrollment = async (user: AuthUser) => {
    setLoadingPendingMfa(true);
    setPendingMfaLoadError(null);
    try {
      const details = await fetchMfaEnrollment();
      setProvisionedMfa({
        user,
        totpSecret: details.secretBase32 || '',
        otpAuthUri: details.otpAuthUri || '',
        qrSvg: details.qrSvg || details.qrCodeSvg || undefined,
        recoveryCodes: [],
        remainingRecoveryCodes: details.remainingRecoveryCodes,
        resumed: true
      });
    } catch (err: any) {
      setPendingMfaLoadError(err?.message || 'Unable to load pending MFA enrollment details.');
    } finally {
      setLoadingPendingMfa(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    if (!pendingMfaUser) return;
    if (provisionedMfa && provisionedMfa.user.id === pendingMfaUser.id) return;

    const resumeEnrollment = async () => {
      setLoadingPendingMfa(true);
      setPendingMfaLoadError(null);
      try {
        const details = await fetchMfaEnrollment();
        if (cancelled) return;
        setProvisionedMfa({
          user: pendingMfaUser,
          totpSecret: details.secretBase32 || '',
          otpAuthUri: details.otpAuthUri || '',
          qrSvg: details.qrSvg || details.qrCodeSvg || undefined,
          recoveryCodes: [],
          remainingRecoveryCodes: details.remainingRecoveryCodes,
          resumed: true
        });
      } catch (err: any) {
        if (cancelled) return;
        setPendingMfaLoadError(err?.message || 'Unable to load pending MFA enrollment details.');
      } finally {
        if (!cancelled) {
          setLoadingPendingMfa(false);
        }
      }
    };

    resumeEnrollment();
    return () => {
      cancelled = true;
    };
  }, [pendingMfaUser, provisionedMfa]);

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
      setTotpCode('');
      setMfaVerifyError(null);
      setProvisionedMfa({
        user: res.user,
        totpSecret: res.totpSecret || '',
        otpAuthUri: res.otpAuthUri || '',
        qrSvg: res.qrSvg || undefined,
        recoveryCodes: res.recoveryCodes || []
      });
    } catch (err: any) {
      setError(err?.message || 'Unable to reach Vitrine authentication service.');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyInitialTotp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!provisionedMfa) return;

    const cleaned = totpCode.replace(/\D/g, '').trim();
    if (cleaned.length !== 6) {
      setMfaVerifyError('Enter the current 6-digit code from your authenticator app.');
      return;
    }

    setMfaVerifying(true);
    setMfaVerifyError(null);
    try {
      const res = await verifyMfa(cleaned, 'initial_admin_mfa_enrollment', undefined, {
        totpOnly: true
      });
      if (res.success) {
        onAuthenticated({ ...provisionedMfa.user, totp_confirmed: true }, !authStatus.isOnboarded);
      } else {
        setMfaVerifyError(
          res.error || 'Invalid 6-digit authenticator code. Please check your authenticator app and try again.'
        );
      }
    } catch (err: any) {
      setMfaVerifyError(err?.message || 'Failed to verify authenticator code. Please try again.');
    } finally {
      setMfaVerifying(false);
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
      if (!res.success) {
        setError(res.error || 'Invalid username or password.');
        return;
      }
      if (res.mfaRequired && res.mfaChallengeToken) {
        setLoginMfaCode('');
        setLoginMfaError(null);
        setLoginMfaChallenge({
          token: res.mfaChallengeToken,
          username: res.username || username.trim()
        });
        return;
      }
      if (!res.user) {
        setError(res.error || 'Invalid username or password.');
        return;
      }
      onAuthenticated(res.user, !authStatus.isOnboarded && checkIsSuperAdmin(res.user) && res.user.totp_confirmed !== false);
    } catch (err: any) {
      setError(err?.message || 'Authentication request failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleLoginMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!loginMfaChallenge) return;
    const cleaned = loginMfaCode.trim();
    if (!cleaned) {
      setLoginMfaError('Enter your 6-digit authenticator code or an emergency recovery code.');
      return;
    }

    setLoginMfaSubmitting(true);
    setLoginMfaError(null);
    try {
      const res = await verifyLoginMfa(loginMfaChallenge.token, cleaned);
      if (!res.success || !res.user) {
        setLoginMfaError(res.error || 'Invalid authenticator or recovery code.');
        return;
      }
      setLoginMfaChallenge(null);
      setLoginMfaCode('');
      onAuthenticated(res.user, !authStatus.isOnboarded && checkIsSuperAdmin(res.user) && res.user.totp_confirmed !== false);
    } catch (err: any) {
      setLoginMfaError(err?.message || 'Unable to verify MFA code.');
    } finally {
      setLoginMfaSubmitting(false);
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

  if (pendingMfaUser && !provisionedMfa) {
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
        <div className="glass-card" style={{ maxWidth: '500px', width: '100%', padding: '2rem', textAlign: 'center' }}>
          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '1rem' }}>
            <ShieldCheck size={32} color="var(--primary)" />
          </div>
          <h2 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: '0.5rem' }}>
            Complete Authenticator Enrollment
          </h2>
          {loadingPendingMfa ? (
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              Loading TOTP MFA setup for {pendingMfaUser.username}...
            </p>
          ) : (
            <>
              <p style={{ fontSize: '0.84rem', color: '#f87171', marginBottom: '1rem' }}>
                {pendingMfaLoadError || 'Failed to load pending MFA enrollment details.'}
              </p>
              <div style={{ display: 'flex', gap: '0.6rem', justifyContent: 'center' }}>
                <button
                  type="button"
                  className="btn-glass btn-primary"
                  onClick={() => loadPendingMfaEnrollment(pendingMfaUser)}
                >
                  Retry Loading Setup
                </button>
                {onSignOutPendingMfa && (
                  <button
                    type="button"
                    className="btn-glass"
                    onClick={() => onSignOutPendingMfa()}
                  >
                    Sign Out
                  </button>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    );
  }

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
            <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--primary)', marginBottom: '0.5rem' }}>
              1. Scan QR Code or Add Base32 Secret to Authenticator App (1Password, Bitwarden, Authy, Google/Microsoft Authenticator)
            </div>
            {provisionedMfa.otpAuthUri && (
              <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '0.75rem' }}>
                <div
                  style={{
                    background: '#ffffff',
                    padding: '0.6rem',
                    borderRadius: '10px',
                    display: 'inline-flex',
                    boxShadow: '0 6px 20px rgba(0, 0, 0, 0.35)'
                  }}
                >
                  <img
                    src={
                      provisionedMfa.qrSvg
                        ? `data:image/svg+xml;utf8,${encodeURIComponent(provisionedMfa.qrSvg)}`
                        : getLocalQrSvgUrl(provisionedMfa.otpAuthUri)
                    }
                    alt="TOTP MFA Enrollment QR Code"
                    style={{ width: 168, height: 168, display: 'block' }}
                  />
                </div>
              </div>
            )}
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
                onClick={async () => {
                  const ok = await copyToClipboard(provisionedMfa.totpSecret);
                  if (ok) {
                    setCopiedSecret(true);
                    setTimeout(() => setCopiedSecret(false), 2000);
                  }
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
            {provisionedMfa.recoveryCodes.length > 0 ? (
              <>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <span style={{ fontSize: '0.76rem', fontWeight: 600, color: 'var(--accent-warning)' }}>
                    2. One-Time Emergency Recovery Codes (8 Single-Use Backup Codes)
                  </span>
                  <div style={{ display: 'flex', gap: '0.4rem' }}>
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ padding: '0.3rem 0.65rem', fontSize: '0.75rem' }}
                      onClick={async () => {
                        const ok = await copyToClipboard(provisionedMfa.recoveryCodes.join('\n'));
                        if (ok) {
                          setCopiedCodes(true);
                          setTimeout(() => setCopiedCodes(false), 2000);
                        }
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
                <p style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '0.55rem', marginBottom: 0 }}>
                  Save these offline now — they are only displayed once during initial setup.
                </p>
              </>
            ) : (
              <div>
                <div style={{ fontSize: '0.76rem', fontWeight: 600, color: 'var(--accent-warning)', marginBottom: '0.3rem' }}>
                  2. Single-Use Emergency Recovery Codes
                </div>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: 0 }}>
                  {provisionedMfa.remainingRecoveryCodes ?? 8} single-use emergency recovery codes are active for{' '}
                  <strong>{provisionedMfa.user.username}</strong>. Once setup completes, you can regenerate recovery codes
                  anytime in <strong>Settings → Security &amp; MFA</strong>.
                </p>
              </div>
            )}
          </div>

          <form onSubmit={handleVerifyInitialTotp}>
            <div
              style={{
                background: 'rgba(16, 185, 129, 0.08)',
                border: '1px solid rgba(16, 185, 129, 0.28)',
                borderRadius: '10px',
                padding: '1rem',
                marginBottom: '1rem'
              }}
            >
              <label
                htmlFor="initial-totp-code-input"
                style={{
                  display: 'block',
                  fontSize: '0.76rem',
                  fontWeight: 600,
                  color: 'var(--accent-success)',
                  marginBottom: '0.45rem'
                }}
              >
                3. Enter Current 6-Digit Authenticator Code to Continue
              </label>
              <input
                id="initial-totp-code-input"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                autoFocus
                className="glass-input"
                placeholder="000000"
                value={totpCode}
                onChange={(e) => {
                  setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6));
                  if (mfaVerifyError) setMfaVerifyError(null);
                }}
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '1.25rem',
                  fontWeight: 700,
                  letterSpacing: '0.35em',
                  textAlign: 'center'
                }}
              />
              <p style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '0.45rem', marginBottom: 0 }}>
                Confirm your authenticator app is synced by entering the current 6-digit TOTP code.
              </p>
            </div>

            {mfaVerifyError && (
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
                  marginBottom: '0.9rem'
                }}
              >
                <AlertCircle size={16} style={{ flexShrink: 0 }} />
                <span>{mfaVerifyError}</span>
              </div>
            )}

            <button
              type="submit"
              className="btn-glass btn-primary"
              style={{ width: '100%', padding: '0.75rem' }}
              disabled={mfaVerifying || totpCode.length !== 6}
              id="complete-admin-bootstrap-btn"
            >
              <span>
                {mfaVerifying
                  ? 'Verifying Authenticator Code...'
                  : authStatus.isOnboarded
                    ? 'Verify Code & Continue'
                    : 'Verify Code & Continue to Guided Setup'}
              </span>
              <ArrowRight size={16} />
            </button>

            {pendingMfaUser && onSignOutPendingMfa && (
              <button
                type="button"
                className="btn-glass"
                style={{ width: '100%', padding: '0.55rem', marginTop: '0.6rem', justifyContent: 'center', fontSize: '0.8rem' }}
                onClick={() => onSignOutPendingMfa()}
              >
                Sign Out
              </button>
            )}
          </form>
        </div>
      </div>
    );
  }

  if (loginMfaChallenge) {
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', marginBottom: '1.35rem' }}>
            <img src={brandLogoUrl} alt={brandName} className="brand-logo-img" style={{ width: 42, height: 42 }} />
            <div>
              <div className="brand-title" style={{ fontSize: '1.3rem' }}>
                {brandName}
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Two-Factor Authentication Required — {loginMfaChallenge.username}
              </div>
            </div>
          </div>

          <p style={{ fontSize: '0.83rem', color: 'var(--text-muted)', marginTop: 0, marginBottom: '1.15rem', lineHeight: 1.5 }}>
            Enter the current 6-digit verification code from your authenticator app, or enter one of your saved{' '}
            <code>XXXX-XXXX</code> emergency recovery codes.
          </p>

          <form onSubmit={handleLoginMfaSubmit}>
            <div className="form-group">
              <label htmlFor="login-mfa-code-input" className="form-label">
                <ShieldCheck size={13} style={{ display: 'inline', marginRight: 5 }} />
                Authenticator or Recovery Code
              </label>
              <input
                id="login-mfa-code-input"
                type="text"
                autoComplete="one-time-code"
                autoFocus
                className="glass-input"
                placeholder="000000 or XXXX-XXXX"
                value={loginMfaCode}
                onChange={(e) => {
                  setLoginMfaCode(e.target.value);
                  if (loginMfaError) setLoginMfaError(null);
                }}
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '1.2rem',
                  fontWeight: 700,
                  letterSpacing: '0.2em',
                  textAlign: 'center'
                }}
              />
            </div>

            {loginMfaError && (
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
                  marginBottom: '1rem'
                }}
              >
                <AlertCircle size={16} style={{ flexShrink: 0 }} />
                <span>{loginMfaError}</span>
              </div>
            )}

            <button
              type="submit"
              className="btn-glass btn-primary"
              style={{ width: '100%', padding: '0.75rem' }}
              disabled={loginMfaSubmitting || !loginMfaCode.trim()}
              id="login-mfa-submit-btn"
            >
              <span>{loginMfaSubmitting ? 'Verifying Code...' : 'Verify & Sign In'}</span>
              <ArrowRight size={16} />
            </button>

            <button
              type="button"
              className="btn-glass"
              style={{ width: '100%', padding: '0.55rem', marginTop: '0.65rem', justifyContent: 'center', fontSize: '0.8rem' }}
              onClick={() => {
                setLoginMfaChallenge(null);
                setLoginMfaCode('');
                setLoginMfaError(null);
              }}
            >
              Use a different account
            </button>
          </form>
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
                ? 'First-Visit Setup — Create Super Admin Account'
                : 'Sign in to your account'}
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
                ? 'Creating Administrator Account...'
                : 'Signing In...'
              : isFirstSetup
                ? 'Initialize Super Admin & Vault'
                : 'Sign In'}
          </button>

          {!isFirstSetup && authStatus.oidcEnabled && (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', margin: '0.85rem 0 0.65rem', color: 'var(--text-dim)', fontSize: '0.74rem' }}>
                <span style={{ flex: 1, height: '1px', background: 'var(--glass-border)' }} />
                <span>OR</span>
                <span style={{ flex: 1, height: '1px', background: 'var(--glass-border)' }} />
              </div>
              <button
                type="button"
                className="btn-glass"
                style={{
                  width: '100%',
                  padding: '0.72rem',
                  justifyContent: 'center',
                  borderColor: 'rgba(0, 242, 254, 0.45)',
                  background: 'rgba(0, 242, 254, 0.08)',
                  color: 'var(--primary)',
                  fontWeight: 600
                }}
                onClick={() => {
                  window.location.href = '/api/auth/oidc/login';
                }}
                id="oidc-sso-login-btn"
              >
                <Globe size={15} />
                <span>Sign in with SSO</span>
              </button>
            </>
          )}
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

