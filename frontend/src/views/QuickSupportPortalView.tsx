import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  Download,
  Lock,
  Sparkles,
  Sun,
  Moon,
  Terminal,
  KeyRound
} from 'lucide-react';
import { createQuickSupportSession, fetchPublicPortalConfig } from '../services/api.js';
import { PublicPortalConfig, SigningStageReport } from '../types/index.js';
import { sanitizeSafeUrl } from '../utils/urlSafety.js';

export const QuickSupportPortalView: React.FC = () => {
  const [portalConfig, setPortalConfig] = useState<PublicPortalConfig | null>(null);
  const [themePref, setThemePref] = useState<'system' | 'dark' | 'light'>('system');
  const [effectiveTheme, setEffectiveTheme] = useState<'dark' | 'light'>('dark');

  const [clientName, setClientName] = useState('');
  const [sessionCodeInput, setSessionCodeInput] = useState('');
  const [platform, setPlatform] = useState<'windows' | 'macos' | 'linux'>(() => {
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes('mac')) return 'macos';
    if (ua.includes('linux') && !ua.includes('android')) return 'linux';
    return 'windows';
  });

  const [preparing, setPreparing] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [sessionResult, setSessionResult] = useState<{
    sessionCode: string;
    downloadUrl: string;
    allSigned: boolean;
    stages: SigningStageReport[];
  } | null>(null);

  useEffect(() => {
    fetchPublicPortalConfig()
      .then((cfg) => {
        setPortalConfig(cfg);
        const preferredTheme = cfg?.quicksupport_theme_mode || cfg?.theme_mode;
        if (preferredTheme) setThemePref(preferredTheme);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: light)');
    const updateEffective = () => {
      if (themePref === 'system') {
        setEffectiveTheme(media.matches ? 'light' : 'dark');
      } else {
        setEffectiveTheme(themePref);
      }
    };
    updateEffective();
    media.addEventListener('change', updateEffective);
    return () => media.removeEventListener('change', updateEffective);
  }, [themePref]);

  const handleStartQuickSupport = async (e: React.FormEvent) => {
    e.preventDefault();
    setPreparing(true);
    setErrorMsg(null);
    setSessionResult(null);

    try {
      const res = await createQuickSupportSession({
        client_name: clientName.trim() || 'On-Demand Remote Support Guest',
        platform,
        session_code: sessionCodeInput.trim() || undefined
      });

      if (!res.success || !res.session) {
        setErrorMsg(res.error || 'Unable to generate QuickSupport launcher at this time.');
        return;
      }

      setSessionResult({
        sessionCode: res.session.session_code,
        downloadUrl: res.downloadUrl,
        allSigned: Boolean(res.signingPipeline?.allSigned),
        stages: res.signingPipeline?.stages || []
      });
    } catch (err: any) {
      setErrorMsg(err?.message || 'Network error generating QuickSupport launcher.');
    } finally {
      setPreparing(false);
    }
  };

  const isLight = effectiveTheme === 'light';
  const brandName = portalConfig?.quicksupport_brand_name || portalConfig?.brand_name || 'Vitrine RMM';
  const brandLogo =
    sanitizeSafeUrl(portalConfig?.quicksupport_icon_url) ||
    sanitizeSafeUrl(portalConfig?.brand_logo_url) ||
    '/branding/logo.png';
  const accent = isLight ? '#0284c7' : portalConfig?.primary_color || '#00f2fe';
  const isPortalDisabled = portalConfig !== null && portalConfig.quicksupport_enabled === false;
  const safeDownloadUrl = sanitizeSafeUrl(sessionResult?.downloadUrl);

  return (
    <div
      data-theme={effectiveTheme}
      style={{
        minHeight: '100vh',
        background: isLight
          ? 'radial-gradient(circle at 20% 20%, #e0f2fe 0%, #f8fafc 55%, #f1f5f9 100%)'
          : 'radial-gradient(circle at 20% 20%, rgba(0, 242, 254, 0.12) 0%, #020617 55%, #090d16 100%)',
        color: isLight ? '#0f172a' : '#f8fafc',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '2rem 1.25rem',
        fontFamily: 'var(--font-sans, Inter, system-ui, sans-serif)'
      }}
    >
      {/* Top Bar */}
      <div
        style={{
          width: '100%',
          maxWidth: '720px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '1.5rem'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <img
            src={brandLogo}
            alt={brandName}
            style={{ width: '40px', height: '40px', borderRadius: '10px', objectFit: 'contain' }}
          />
          <div>
            <div style={{ fontWeight: 700, fontSize: '1.1rem' }}>{brandName} — QuickSupport Portal</div>
            <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>
              On-Demand Temporary Remote Assistance (No Administrator Rights Required)
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <button
            type="button"
            className="btn-glass"
            onClick={() =>
              setThemePref((prev) => (prev === 'system' ? 'light' : prev === 'light' ? 'dark' : 'system'))
            }
            style={{ fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
            title="Cycle System / Light / Dark Mode"
          >
            {effectiveTheme === 'light' ? <Sun size={14} /> : <Moon size={14} />}
            <span>Theme: {themePref.toUpperCase()}</span>
          </button>
        </div>
      </div>

      {/* Main Card */}
      <div
        className="glass-card"
        style={{
          width: '100%',
          maxWidth: '720px',
          padding: '2rem',
          borderRadius: '16px',
          background: isLight ? 'rgba(255, 255, 255, 0.88)' : 'rgba(15, 23, 42, 0.82)',
          border: isLight ? '1px solid rgba(15, 23, 42, 0.12)' : '1px solid rgba(255, 255, 255, 0.12)',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.35)'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.5rem' }}>
          <Sparkles size={20} color={accent} />
          <h1 style={{ fontSize: '1.4rem', fontWeight: 700, margin: 0 }}>
            {isPortalDisabled ? 'QuickSupport Portal Currently Disabled' : 'Start a Temporary Support Session'}
          </h1>
        </div>
        {isPortalDisabled ? (
          <div
            style={{
              marginTop: '1rem',
              padding: '1.25rem',
              borderRadius: '12px',
              background: 'rgba(245, 158, 11, 0.12)',
              border: '1px solid rgba(245, 158, 11, 0.35)',
              fontSize: '0.88rem',
              lineHeight: 1.55
            }}
          >
            Public on-demand QuickSupport launcher downloads have been disabled by your organization&apos;s administrator. Please contact your support technician directly for an authorized session invite link.
          </div>
        ) : (
        <>
        <p style={{ fontSize: '0.85rem', opacity: 0.78, marginBottom: '1.5rem', lineHeight: 1.5 }}>
          Connect with an authorized support technician in seconds. This launcher runs in temporary user mode
          without requiring local administrator permissions.
        </p>

        <form onSubmit={handleStartQuickSupport} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '1rem' }}>
            <div>
              <label className="form-label">Your Name or Organization</label>
              <input
                type="text"
                className="glass-input"
                placeholder="e.g. Jane Doe — Finance Dept"
                value={clientName}
                onChange={(e) => setClientName(e.target.value)}
              />
            </div>

            <div>
              <label className="form-label">6-Digit Technician Code (Optional)</label>
              <input
                type="text"
                className="glass-input"
                placeholder="Optional (e.g. 849-204)"
                value={sessionCodeInput}
                onChange={(e) => setSessionCodeInput(e.target.value)}
              />
            </div>
          </div>

          <div>
            <label className="form-label">Operating System (Auto-Detected)</label>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.75rem' }}>
              {(
                [
                  { id: 'windows', label: 'Windows 10 / 11', sub: 'Signed Windows App (.exe)' },
                  { id: 'macos', label: 'macOS', sub: 'macOS Quick Support (.sh)' },
                  { id: 'linux', label: 'Linux', sub: 'Linux Support Client (.sh)' }
                ] as const
              ).map((p) => (
                <div
                  key={p.id}
                  onClick={() => setPlatform(p.id)}
                  style={{
                    padding: '0.85rem',
                    borderRadius: '10px',
                    cursor: 'pointer',
                    textAlign: 'center',
                    border: `2px solid ${platform === p.id ? accent : 'rgba(148, 163, 184, 0.25)'}`,
                    background: platform === p.id ? 'rgba(0, 242, 254, 0.1)' : 'transparent'
                  }}
                >
                  <div style={{ fontWeight: 600, fontSize: '0.88rem' }}>{p.label}</div>
                  <div style={{ fontSize: '0.72rem', opacity: 0.7, marginTop: '0.2rem' }}>{p.sub}</div>
                </div>
              ))}
            </div>
          </div>

          {errorMsg && (
            <div
              style={{
                padding: '0.85rem 1rem',
                borderRadius: '10px',
                background: 'rgba(239, 68, 68, 0.14)',
                border: '1px solid rgba(239, 68, 68, 0.35)',
                color: isLight ? '#b91c1c' : '#fca5a5',
                fontSize: '0.82rem'
              }}
            >
              {errorMsg}
            </div>
          )}

          {/* Honest Server Package & Signing Status */}
          {(preparing || sessionResult) && (
            <div
              style={{
                padding: '1rem 1.25rem',
                borderRadius: '10px',
                background: isLight ? 'rgba(15, 23, 42, 0.04)' : 'rgba(0, 0, 0, 0.35)',
                border: `1px solid ${
                  preparing
                    ? 'rgba(56, 189, 248, 0.28)'
                    : sessionResult?.allSigned
                      ? 'rgba(16, 185, 129, 0.32)'
                      : 'rgba(245, 158, 11, 0.32)'
                }`,
                display: 'flex',
                flexDirection: 'column',
                gap: '0.65rem'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span
                  style={{
                    fontSize: '0.8rem',
                    fontWeight: 700,
                    color: preparing ? accent : sessionResult?.allSigned ? '#10b981' : '#f59e0b',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem'
                  }}
                >
                  <ShieldCheck size={16} />
                  {preparing
                    ? 'Preparing your QuickSupport launcher...'
                    : sessionResult?.allSigned
                      ? 'Verified & Signed Support Package Ready'
                      : 'Support Download Ready (Unsigned / Partial Verification)'}
                </span>
              </div>

              {sessionResult && sessionResult.stages.length > 0 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.75rem' }}>
                  {sessionResult.stages.map((st, idx) => {
                    const isOk = st.status === 'signed' || st.status === 'verified';
                    const isWarn = st.status === 'bypassed';
                    const marker = isOk ? '✓' : isWarn ? '○' : '✕';
                    const markerColor = isOk ? '#10b981' : isWarn ? '#f59e0b' : '#ef4444';
                    return (
                      <div key={st.stepNumber || idx} style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem' }}>
                        <span>
                          <span style={{ color: markerColor, fontWeight: 700, marginRight: '0.35rem' }}>{marker}</span>
                          <strong>Step {st.stepNumber || idx + 1}:</strong> {st.description}
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

          {!sessionResult ? (
            <button
              type="submit"
              className="btn-glass btn-primary"
              disabled={preparing}
              style={{ padding: '0.9rem 1.5rem', fontSize: '0.95rem', fontWeight: 700, justifyContent: 'center' }}
            >
              <Download size={18} />
              <span>
                {preparing ? 'Preparing Support Download...' : `Download Quick Support (${platform === 'windows' ? 'Windows .exe' : platform === 'macos' ? 'macOS .sh' : 'Linux .sh'})`}
              </span>
            </button>
          ) : (
            <div
              style={{
                padding: '1.25rem',
                borderRadius: '12px',
                background: 'rgba(16, 185, 129, 0.12)',
                border: '1px solid rgba(16, 185, 129, 0.35)',
                display: 'flex',
                flexDirection: 'column',
                gap: '1rem'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
                <div>
                  <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.06em', color: '#10b981', fontWeight: 700 }}>
                    Active Support Session Code
                  </div>
                  <div style={{ fontSize: '2rem', fontWeight: 800, fontFamily: 'var(--font-mono)', letterSpacing: '0.08em' }}>
                    {sessionResult.sessionCode}
                  </div>
                  <div style={{ fontSize: '0.78rem', opacity: 0.8 }}>
                    Provide this code to your technician. If administrative tasks are needed later, your technician can remotely elevate this session.
                  </div>
                </div>

                {safeDownloadUrl && (
                  <a
                    href={safeDownloadUrl}
                    download
                    className="btn-glass btn-primary"
                    style={{ textDecoration: 'none', padding: '0.85rem 1.4rem', fontWeight: 700 }}
                  >
                    <Download size={16} /> Download Quick Support ({platform === 'windows' ? '.exe' : '.sh'})
                  </a>
                )}
              </div>
            </div>
          )}
        </form>
        </>
        )}

        {/* Security Footnote */}
        <div
          style={{
            marginTop: '1.5rem',
            paddingTop: '1rem',
            borderTop: '1px solid rgba(148, 163, 184, 0.2)',
            display: 'grid',
            gridTemplateColumns: 'repeat(3, 1fr)',
            gap: '0.75rem',
            fontSize: '0.74rem',
            opacity: 0.8
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <Lock size={14} color="#10b981" />
            <span>No Admin Password Needed</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <KeyRound size={14} color={accent} />
            <span>Encrypted Remote Connection</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <Terminal size={14} color="#f59e0b" />
            <span>One-Time Enrollment Token</span>
          </div>
        </div>
      </div>
    </div>
  );
};

