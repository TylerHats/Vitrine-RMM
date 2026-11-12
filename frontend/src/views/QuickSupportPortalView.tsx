import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  Download,
  Lock,
  Sparkles,
  CheckCircle2,
  Monitor,
  Sun,
  Moon,
  ArrowLeft,
  Terminal,
  KeyRound
} from 'lucide-react';
import { createQuickSupportSession, fetchPublicPortalConfig } from '../services/api.js';
import { PublicPortalConfig, SigningStageReport } from '../types/index.js';

interface QuickSupportPortalViewProps {
  onBackToAdmin?: () => void;
}

export const QuickSupportPortalView: React.FC<QuickSupportPortalViewProps> = ({ onBackToAdmin }) => {
  const [portalConfig, setPortalConfig] = useState<PublicPortalConfig | null>(null);
  const [themePref, setThemePref] = useState<'system' | 'dark' | 'light'>('system');
  const [effectiveTheme, setEffectiveTheme] = useState<'dark' | 'light'>('dark');

  const [clientName, setClientName] = useState('');
  const [sessionCodeInput, setSessionCodeInput] = useState('');
  const [platform, setPlatform] = useState<'windows' | 'macos' | 'linux'>(() => {
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes('mac')) return 'macos';
    if (ua.includes('linux')) return 'linux';
    return 'windows';
  });

  const [preparing, setPreparing] = useState(false);
  const [activeStageIdx, setActiveStageIdx] = useState(0);
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
        if (cfg?.theme_mode) setThemePref(cfg.theme_mode);
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
    setActiveStageIdx(1);

    setTimeout(() => setActiveStageIdx(2), 300);
    setTimeout(() => setActiveStageIdx(3), 600);

    try {
      const res = await createQuickSupportSession({
        client_name: clientName.trim() || 'On-Demand Remote Support Guest',
        platform,
        session_code: sessionCodeInput.trim() || undefined
      });

      setTimeout(() => {
        setPreparing(false);
        setActiveStageIdx(4);
        if (res.success && res.session) {
          setSessionResult({
            sessionCode: res.session.session_code,
            downloadUrl: res.downloadUrl,
            allSigned: Boolean(res.signingPipeline?.allSigned),
            stages: res.signingPipeline?.stages || []
          });
        } else {
          setErrorMsg(res.error || 'Unable to generate QuickSupport launcher at this time.');
        }
      }, 800);
    } catch (err: any) {
      setPreparing(false);
      setErrorMsg(err?.message || 'Network error generating QuickSupport launcher.');
    }
  };

  const isLight = effectiveTheme === 'light';
  const brandName = portalConfig?.brand_name || 'Vitrine RMM';
  const brandLogo = portalConfig?.brand_logo_url || '/logo.png';
  const accent = portalConfig?.primary_color || '#00f2fe';

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

          {onBackToAdmin && (
            <button
              type="button"
              className="btn-glass"
              onClick={onBackToAdmin}
              style={{ fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
            >
              <ArrowLeft size={14} />
              <span>Admin Console</span>
            </button>
          )}
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
            Start a Temporary Support Session
          </h1>
        </div>
        <p style={{ fontSize: '0.85rem', opacity: 0.78, marginBottom: '1.5rem', lineHeight: 1.5 }}>
          Connect with an authorized support technician in seconds. This launcher runs in temporary user mode
          without requiring local administrator permissions, and every component is cryptographically code-signed
          before download.
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
                placeholder="Auto-generated if blank (e.g. 849-204)"
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
                  { id: 'windows', label: 'Windows 10 / 11', sub: 'Modern WPF QuickConnect' },
                  { id: 'macos', label: 'macOS (Apple / Intel)', sub: 'Universal QuickConnect' },
                  { id: 'linux', label: 'Linux Desktop', sub: 'User-Space QuickConnect' }
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

          {/* Live 3-Stage Code Signing Progress Indicator */}
          {(preparing || sessionResult) && (
            <div
              style={{
                padding: '1rem 1.25rem',
                borderRadius: '10px',
                background: isLight ? 'rgba(15, 23, 42, 0.04)' : 'rgba(0, 0, 0, 0.35)',
                border: '1px solid rgba(0, 242, 254, 0.25)',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.65rem'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.8rem', fontWeight: 700, color: accent, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <ShieldCheck size={16} />
                  {preparing
                    ? 'Preparing QuickSupport Package (3-Stage Pipeline)...'
                    : sessionResult?.allSigned
                      ? 'All 3 Package Components Cryptographically Signed & Verified'
                      : 'QuickSupport Package Ready for Download'}
                </span>
                <span style={{ fontSize: '0.75rem', fontWeight: 600 }}>
                  {preparing ? `${Math.min(95, activeStageIdx * 32)}%` : '100% Ready'}
                </span>
              </div>

              <div style={{ width: '100%', height: '6px', background: 'rgba(148, 163, 184, 0.2)', borderRadius: '999px', overflow: 'hidden' }}>
                <div
                  style={{
                    width: preparing ? `${Math.min(95, activeStageIdx * 32)}%` : '100%',
                    height: '100%',
                    background: 'linear-gradient(90deg, #00f2fe, #10b981)',
                    transition: 'width 0.3s ease'
                  }}
                />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.75rem' }}>
                {sessionResult && sessionResult.stages.length > 0 ? (
                  sessionResult.stages.map((st, idx) => (
                    <div key={st.stepNumber || idx}>
                      {st.status === 'signed' || st.status === 'verified' ? '✓' : '•'}{' '}
                      <strong>Stage {st.stepNumber || idx + 1} ({st.component}):</strong> {st.description}
                    </div>
                  ))
                ) : (
                  <>
                    <div>
                      {activeStageIdx >= 1 ? '✓' : '○'}{' '}
                      <strong>Stage 1:</strong> MeshCentral 2 Core Binary (<code>-connect</code> mode) check
                    </div>
                    <div>
                      {activeStageIdx >= 2 ? '✓' : '○'}{' '}
                      <strong>Stage 2:</strong> Vitrine Companion &amp; Tech Remote Self-Elevation Helper check
                    </div>
                    <div>
                      {activeStageIdx >= 3 ? '✓' : '○'}{' '}
                      <strong>Stage 3:</strong> Modern QuickSupport Launcher packaging
                    </div>
                  </>
                )}
              </div>
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
                {preparing ? 'Signing & Preparing Launcher...' : `Generate & Download Signed ${platform.toUpperCase()} QuickSupport`}
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

                <a
                  href={sessionResult.downloadUrl}
                  download
                  className="btn-glass btn-primary"
                  style={{ textDecoration: 'none', padding: '0.85rem 1.4rem', fontWeight: 700 }}
                >
                  <Download size={16} /> Download Signed Launcher
                </a>
              </div>
            </div>
          )}
        </form>

        {/* Security & Elevation Footnote */}
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
            <span>Zero Admin Rights Needed to Start</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <KeyRound size={14} color={accent} />
            <span>Tech-Side Credential / LAPS Self-Elevation Ready</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <Terminal size={14} color="#f59e0b" />
            <span>3-Stage Authenticode &amp; RFC 3161 Signed</span>
          </div>
        </div>
      </div>
    </div>
  );
};

