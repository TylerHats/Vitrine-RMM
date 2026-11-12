import { useState, useEffect, useCallback } from 'react';
import { Sparkles, X, ShieldCheck, RefreshCw } from 'lucide-react';
import { Sidebar } from './components/Sidebar.js';
import { TopNavbar } from './components/TopNavbar.js';
import { LoginView } from './components/LoginView.js';
import { FleetDashboard } from './views/FleetDashboard.js';
import { DeviceDetailView } from './views/DeviceDetailView.js';
import { PoliciesView } from './views/PoliciesView.js';
import { PatchManagementView } from './views/PatchManagementView.js';
import { ScriptLibraryView } from './views/ScriptLibraryView.js';
import { SelfHealingView } from './views/SelfHealingView.js';
import { NetworkTopologyView } from './views/NetworkTopologyView.js';
import { VirtualizationView } from './views/VirtualizationView.js';
import { PsaSyncView } from './views/PsaSyncView.js';
import { SettingsView } from './views/SettingsView.js';

import { RemoteScreenModal } from './components/RemoteScreenModal.js';
import { BackgroundToolsModal } from './components/BackgroundToolsModal.js';
import { LapsModal } from './components/LapsModal.js';
import { CyberIsolationModal } from './components/CyberIsolationModal.js';
import { OnboardingWizardModal } from './components/OnboardingWizardModal.js';
import { QbrReportModal } from './components/QbrReportModal.js';
import { AgentInstallerModal } from './components/AgentInstallerModal.js';
import { GuestAccessModal } from './components/GuestAccessModal.js';
import { MfaChallengeModal } from './components/MfaChallengeModal.js';
import { GuestPortalView } from './views/GuestPortalView.js';
import { QuickSupportPortalView } from './views/QuickSupportPortalView.js';

import {
  fetchAuthStatus,
  fetchPublicPortalConfig,
  logoutSession,
  fetchDevices,
  fetchTenants,
  fetchSettings,
  fetchUpdaterStatus,
  fetchQuickSupportSessions,
  elevateRemoteAgent
} from './services/api.js';
import {
  Device,
  Tenant,
  Settings,
  UpdaterStatus,
  AuthUser,
  PublicPortalConfig,
  QuickSupportSession
} from './types/index.js';

import './styles/theme.css';
import './styles/components.css';

function applyVisualSettings(
  sets: { primary_color?: string; glass_blur_level?: string } | null
) {
  if (!sets) return;
  if (sets.primary_color) {
    document.documentElement.style.setProperty('--primary', sets.primary_color);
  }
  if (sets.glass_blur_level) {
    const blurMap: Record<string, string> = {
      high: 'blur(20px) saturate(190%)',
      medium: 'blur(12px) saturate(160%)',
      low: 'blur(4px) saturate(120%)'
    };
    document.documentElement.style.setProperty(
      '--glass-blur',
      blurMap[sets.glass_blur_level] || blurMap.high
    );
  }
}

export function App() {
  const [authChecked, setAuthChecked] = useState(false);
  const [authInitialized, setAuthInitialized] = useState(true);
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [publicConfig, setPublicConfig] = useState<PublicPortalConfig | null>(null);

  const [currentView, setCurrentView] = useState('dashboard');
  const [themeOverride, setThemeOverride] = useState<'dark' | 'light' | null>(() => {
    try {
      const saved = localStorage.getItem('vitrine_theme_override');
      return saved === 'dark' || saved === 'light' ? saved : null;
    } catch {
      return null;
    }
  });
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');

  const [devices, setDevices] = useState<Device[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [settings, setSettings] = useState<Settings | null>(null);

  const [selectedTenantId, setSelectedTenantId] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = useState(false);

  const [remoteModal, setRemoteModal] = useState<{ open: boolean; device: Device | null; isGhost: boolean }>({
    open: false,
    device: null,
    isGhost: false
  });
  const [bgToolsModal, setBgToolsModal] = useState<{ open: boolean; device: Device | null; initialTab: string }>({
    open: false,
    device: null,
    initialTab: 'terminal'
  });
  const [lapsModal, setLapsModal] = useState<{ open: boolean; device: Device | null }>({
    open: false,
    device: null
  });
  const [quarantineModal, setQuarantineModal] = useState<{ open: boolean; device: Device | null }>({
    open: false,
    device: null
  });
  const [onboardingOpen, setOnboardingOpen] = useState(false);
  const [hasAutoCheckedOobe, setHasAutoCheckedOobe] = useState(false);
  const [qbrOpen, setQbrOpen] = useState(false);
  const [installerModalOpen, setInstallerModalOpen] = useState(false);
  const [guestAccessModalOpen, setGuestAccessModalOpen] = useState(false);
  const [quickSupportQueueOpen, setQuickSupportQueueOpen] = useState(false);
  const [qsSessions, setQsSessions] = useState<QuickSupportSession[]>([]);
  const [qsElevatingDeviceId, setQsElevatingDeviceId] = useState<string | null>(null);
  const [qsElevationMfaOpen, setQsElevationMfaOpen] = useState(false);
  const [qsMessage, setQsMessage] = useState<string | null>(null);

  const [updaterStatus, setUpdaterStatus] = useState<UpdaterStatus | null>(null);
  const [dismissedUpdateBanner, setDismissedUpdateBanner] = useState(false);
  const [locationTick, setLocationTick] = useState(0);

  useEffect(() => {
    const onPopState = () => setLocationTick((t) => t + 1);
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  const navigatePath = (nextPath: string) => {
    window.history.pushState({}, '', nextPath);
    setLocationTick((t) => t + 1);
  };

  const urlParams = new URLSearchParams(window.location.search);
  const pathMatchGuest = window.location.pathname.match(/^\/guest\/([^/]+)/i);
  const guestGrantId = pathMatchGuest?.[1] || urlParams.get('grant') || urlParams.get('guest');
  const pathname = window.location.pathname.toLowerCase();
  const configuredQsPath = (publicConfig?.quicksupport_url_path || settings?.quicksupport_url_path || '/remote').toLowerCase();
  const isQuickSupportRoute =
    (locationTick >= 0 &&
      (pathname === '/remote' ||
        pathname === '/temporarysession' ||
        pathname === '/quicksupport' ||
        pathname === configuredQsPath ||
        urlParams.get('mode') === 'remote')) ||
    Boolean(
      publicConfig?.quicksupport_custom_domain &&
        window.location.hostname.toLowerCase() === publicConfig.quicksupport_custom_domain.toLowerCase()
    );

  // Check public config & auth status on startup
  const refreshAuthAndPublic = useCallback(async () => {
    try {
      const [pub, auth] = await Promise.all([
        fetchPublicPortalConfig().catch(() => null),
        fetchAuthStatus().catch(() => ({ initialized: true, authenticated: false, user: null }))
      ]);
      if (pub) {
        setPublicConfig(pub);
        applyVisualSettings(pub);
      }
      setAuthInitialized(auth.initialized);
      setCurrentUser(auth.authenticated && auth.user ? auth.user : null);
    } finally {
      setAuthChecked(true);
    }
  }, []);

  useEffect(() => {
    refreshAuthAndPublic();
    const onAuthExpired = () => {
      setCurrentUser(null);
    };
    window.addEventListener('vitrine:auth-expired', onAuthExpired);
    return () => window.removeEventListener('vitrine:auth-expired', onAuthExpired);
  }, [refreshAuthAndPublic]);

  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: light)');
    const applyResolvedTheme = () => {
      const mode = themeOverride || settings?.theme_mode || publicConfig?.theme_mode || 'system';
      const resolved: 'dark' | 'light' =
        mode === 'light' ? 'light' : mode === 'dark' ? 'dark' : mediaQuery.matches ? 'light' : 'dark';
      setTheme(resolved);
      document.documentElement.setAttribute('data-theme', resolved);
    };
    applyResolvedTheme();
    mediaQuery.addEventListener('change', applyResolvedTheme);
    return () => mediaQuery.removeEventListener('change', applyResolvedTheme);
  }, [themeOverride, settings?.theme_mode, publicConfig?.theme_mode]);

  const loadData = useCallback(async () => {
    if (guestGrantId || isQuickSupportRoute || !currentUser) return;
    try {
      const [devs, tens, sets, upd] = await Promise.all([
        fetchDevices(),
        fetchTenants(),
        fetchSettings().catch(() => null),
        currentUser.role !== 'client_admin' ? fetchUpdaterStatus().catch(() => null) : Promise.resolve(null)
      ]);
      setDevices(devs);
      setTenants(tens);
      if (sets) {
        setSettings(sets);
        applyVisualSettings(sets);
        if (
          !hasAutoCheckedOobe &&
          currentUser.role === 'super_admin' &&
          sets.oobe_completed === 0 &&
          sets.is_onboarded === 0
        ) {
          setOnboardingOpen(true);
          setHasAutoCheckedOobe(true);
        }
      }
      if (upd) setUpdaterStatus(upd);
    } catch (err) {
      console.error('Error loading fleet data:', err);
    }
  }, [guestGrantId, isQuickSupportRoute, currentUser, hasAutoCheckedOobe]);

  useEffect(() => {
    loadData();
    if (!currentUser || guestGrantId || isQuickSupportRoute) return;
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, [loadData, currentUser, guestGrantId, isQuickSupportRoute]);
  const loadQuickSupportQueue = async () => {
    try {
      const list = await fetchQuickSupportSessions();
      setQsSessions(list);
    } catch {
      setQsSessions([]);
    }
  };

  const handleOpenQuickSupportQueue = () => {
    setQsMessage(null);
    setQuickSupportQueueOpen(true);
    loadQuickSupportQueue();
  };

  const handleElevateQuickSupport = async (
    deviceId: string,
    action: 'elevate_temp_session' | 'promote_permanent_service'
  ) => {
    setQsElevatingDeviceId(deviceId);
    setQsMessage(null);
    try {
      const res = await elevateRemoteAgent(deviceId, {
        credentialSource: 'laps',
        elevationAction: action
      });
      if (res.mfaRequired) {
        setQsElevationMfaOpen(true);
        return;
      }
      if (res.success) {
        setQsMessage(res.message || 'Remote elevation command dispatched.');
        loadQuickSupportQueue();
        loadData();
      } else {
        setQsMessage(res.error || 'Elevation failed.');
      }
    } finally {
      setQsElevatingDeviceId(null);
    }
  };

  if (guestGrantId) {
    return <GuestPortalView grantId={guestGrantId} />;
  }

  if (isQuickSupportRoute) {
    return <QuickSupportPortalView onBackToAdmin={() => navigatePath('/')} />;
  }

  if (!authChecked) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#090d16', color: '#f8fafc' }}>
        <div style={{ textAlign: 'center' }}>
          <div className="pulse-dot" style={{ margin: '0 auto 1rem', width: '14px', height: '14px' }} />
          <div style={{ fontSize: '0.9rem', opacity: 0.85 }}>Initializing Vitrine Control Plane...</div>
        </div>
      </div>
    );
  }

  if (!currentUser) {
    return (
      <LoginView
        authStatus={{
          initialized: authInitialized,
          authenticated: false,
          user: null,
          mfaVerified: false,
          mfaVerifiedUntil: null,
          isOnboarded: Boolean(settings?.is_onboarded),
          oidcEnabled: false,
          branding: {
            brand_name: publicConfig?.brand_name || 'Vitrine RMM',
            brand_logo_url: publicConfig?.brand_logo_url || '/logo.png',
            primary_color: publicConfig?.primary_color || '#00f2fe',
            theme_mode: publicConfig?.theme_mode || 'system'
          }
        }}
        onAuthenticated={(user, triggerOobe) => {
          setAuthInitialized(true);
          setCurrentUser(user);
          if (triggerOobe) setOnboardingOpen(true);
        }}
        onOpenQuickSupport={() => navigatePath(configuredQsPath || '/remote')}
      />
    );
  }

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setThemeOverride(nextTheme);
    setTheme(nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
    try {
      localStorage.setItem('vitrine_theme_override', nextTheme);
    } catch {
      // Ignore storage error
    }
  };

  const handleLogout = async () => {
    await logoutSession();
    setCurrentUser(null);
    setSelectedDeviceId(null);
    setCurrentView('dashboard');
  };

  const activeDeviceForDetail = selectedDeviceId ? devices.find((d) => d.id === selectedDeviceId) || null : null;

  const handleDeviceSelect = (dev: Device) => {
    setSelectedDeviceId(dev.id);
    setCurrentView('device-detail');
  };

  const handleDeviceQuarantineUpdated = (quarantined: boolean) => {
    if (quarantineModal.device) {
      setDevices(
        devices.map((d) =>
          d.id === quarantineModal.device!.id
            ? { ...d, quarantined: quarantined ? 1 : 0, status: quarantined ? 'isolated' : 'online' }
            : d
        )
      );
    }
  };

  const handleSettingsUpdated = (s: Settings) => {
    setSettings(s);
    applyVisualSettings(s);
    loadData();
  };

  return (
    <div className="app-shell" data-theme={theme}>
      <Sidebar
        currentView={currentView}
        onSelectView={(v) => {
          setCurrentView(v);
          setSelectedDeviceId(null);
          setIsMobileSidebarOpen(false);
        }}
        theme={theme}
        onToggleTheme={toggleTheme}
        brandName={settings?.brand_name || publicConfig?.brand_name || 'Vitrine RMM'}
        brandLogoUrl={settings?.brand_logo_url || publicConfig?.brand_logo_url}
        onOpenOnboarding={() => setOnboardingOpen(true)}
        onOpenQbr={() => setQbrOpen(true)}
        isMobileOpen={isMobileSidebarOpen}
        onCloseMobile={() => setIsMobileSidebarOpen(false)}
        currentUser={currentUser}
        meshConnected={Boolean(settings?.meshcentral_connected)}
        appVersion={updaterStatus?.installedVersion || '2.5.0'}
      />

      <div className="main-wrapper">
        <TopNavbar
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          tenants={tenants}
          selectedTenantId={selectedTenantId}
          onTenantChange={setSelectedTenantId}
          onDownloadInstaller={() => setInstallerModalOpen(true)}
          onOpenGuestAccess={() => setGuestAccessModalOpen(true)}
          onOpenQuickSupportQueue={handleOpenQuickSupportQueue}
          onToggleMobileSidebar={() => setIsMobileSidebarOpen(!isMobileSidebarOpen)}
          devices={devices}
          onSelectDevice={handleDeviceSelect}
          onSelectView={(v) => {
            setCurrentView(v);
            setSelectedDeviceId(null);
          }}
          currentUser={currentUser}
          meshConnected={Boolean(settings?.meshcentral_connected)}
          onLogout={handleLogout}
        />

        <main className="content-container">
          {updaterStatus?.updateAvailable &&
            currentUser.role !== 'client_admin' &&
            !dismissedUpdateBanner &&
            (settings?.update_notify_webui ?? 1) !== 0 && (
              <div
                style={{
                  marginBottom: '1.25rem',
                  padding: '0.75rem 1.25rem',
                  borderRadius: '10px',
                  background: 'rgba(0, 242, 254, 0.12)',
                  border: '1px solid rgba(0, 242, 254, 0.38)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '0.75rem',
                  fontSize: '0.83rem'
                }}
              >
                <div>
                  <strong style={{ color: 'var(--primary)' }}>
                    Vitrine-RMM System Update Available ({updaterStatus.channel.toUpperCase()} Channel):
                  </strong>{' '}
                  <span>
                    Target{' '}
                    <strong>
                      {updaterStatus.channel === 'stable'
                        ? updaterStatus.latestStable.version
                        : `Alpha (${updaterStatus.latestAlpha.sha})`}
                    </strong>{' '}
                    is ready with automatic pre-update backup &amp; rollback protection.
                  </span>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  {currentUser.role === 'super_admin' && (
                    <button
                      type="button"
                      className="btn-glass btn-primary"
                      style={{ padding: '0.3rem 0.75rem', fontSize: '0.76rem' }}
                      onClick={() => {
                        setCurrentView('settings');
                        setSelectedDeviceId(null);
                      }}
                    >
                      Review Release Notes &amp; Update
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn-glass"
                    style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
                    onClick={() => setDismissedUpdateBanner(true)}
                  >
                    Dismiss
                  </button>
                </div>
              </div>
            )}

          {currentView === 'dashboard' && (
            <FleetDashboard
              devices={devices}
              searchQuery={searchQuery}
              selectedTenantId={selectedTenantId}
              onOpenRemote={(device, isGhost) => setRemoteModal({ open: true, device, isGhost })}
              onOpenBgTools={(device, initialTab) =>
                setBgToolsModal({ open: true, device, initialTab: initialTab || 'terminal' })
              }
              onOpenLaps={(device) => setLapsModal({ open: true, device })}
              onOpenQuarantine={(device) => setQuarantineModal({ open: true, device })}
              onSelectDevice={handleDeviceSelect}
              onOpenInstaller={() => setInstallerModalOpen(true)}
              onOpenOnboarding={() => setOnboardingOpen(true)}
              onRefreshFleet={loadData}
              currentUser={currentUser}
            />
          )}

          {currentView === 'device-detail' && activeDeviceForDetail && (
            <DeviceDetailView
              device={activeDeviceForDetail}
              onBack={() => setCurrentView('dashboard')}
              onOpenRemote={(device, isGhost) => setRemoteModal({ open: true, device, isGhost })}
              onOpenBgTools={(device, initialTab) =>
                setBgToolsModal({ open: true, device, initialTab: initialTab || 'terminal' })
              }
              onOpenLaps={(device) => setLapsModal({ open: true, device })}
              onOpenQuarantine={(device) => setQuarantineModal({ open: true, device })}
              currentUser={currentUser}
              onRefreshFleet={loadData}
            />
          )}

          {currentView === 'policies' && currentUser.role !== 'client_admin' && (
            <PoliciesView devices={devices} tenants={tenants} />
          )}
          {currentView === 'patching' && <PatchManagementView settings={settings} onSettingsUpdated={handleSettingsUpdated} />}
          {currentView === 'scripts' && currentUser.role !== 'client_admin' && <ScriptLibraryView devices={devices} />}
          {currentView === 'self-healing' && currentUser.role !== 'client_admin' && <SelfHealingView />}
          {currentView === 'topology' && currentUser.role !== 'client_admin' && <NetworkTopologyView />}
          {currentView === 'virtualization' && currentUser.role !== 'client_admin' && <VirtualizationView />}
          {currentView === 'psa' && currentUser.role !== 'client_admin' && (
            <PsaSyncView tenants={tenants} devices={devices} />
          )}
          {currentView === 'settings' && currentUser.role === 'super_admin' && (
            <SettingsView
              settings={settings || ({} as Settings)}
              onUpdated={handleSettingsUpdated}
              onOpenWizard={() => setOnboardingOpen(true)}
              tenants={tenants}
            />
          )}
        </main>
      </div>

      {remoteModal.open && remoteModal.device && (
        <RemoteScreenModal
          device={remoteModal.device}
          isGhostSession={remoteModal.isGhost}
          onClose={() => setRemoteModal({ open: false, device: null, isGhost: false })}
        />
      )}

      {bgToolsModal.open && bgToolsModal.device && (
        <BackgroundToolsModal
          device={bgToolsModal.device}
          initialTab={bgToolsModal.initialTab}
          onClose={() => setBgToolsModal({ open: false, device: null, initialTab: 'terminal' })}
        />
      )}

      {lapsModal.open && lapsModal.device && (
        <LapsModal
          device={lapsModal.device}
          onClose={() => setLapsModal({ open: false, device: null })}
        />
      )}

      {quarantineModal.open && quarantineModal.device && (
        <CyberIsolationModal
          device={quarantineModal.device}
          onClose={() => setQuarantineModal({ open: false, device: null })}
          onUpdated={handleDeviceQuarantineUpdated}
        />
      )}

      {onboardingOpen && (
        <OnboardingWizardModal
          settings={settings || ({} as Settings)}
          onClose={() => setOnboardingOpen(false)}
          onSaved={handleSettingsUpdated}
        />
      )}

      {qbrOpen && (
        <QbrReportModal
          brandLogoUrl={settings?.brand_logo_url}
          tenants={tenants}
          initialTenantId={selectedTenantId}
          onClose={() => setQbrOpen(false)}
        />
      )}

      {installerModalOpen && (
        <AgentInstallerModal
          tenants={tenants}
          selectedTenantId={selectedTenantId}
          settings={settings}
          currentUser={currentUser}
          onOpenQuickSupportPortal={() => navigatePath(configuredQsPath || '/remote')}
          onClose={() => setInstallerModalOpen(false)}
        />
      )}

      {guestAccessModalOpen && (
        <GuestAccessModal
          devices={devices}
          onClose={() => setGuestAccessModalOpen(false)}
        />
      )}

      {quickSupportQueueOpen && (
        <div className="modal-backdrop" style={{ zIndex: 1050 }}>
          <div className="glass-modal glass-modal-md" style={{ maxWidth: '720px' }}>
            <div className="modal-header">
              <div className="modal-title">
                <Sparkles size={18} style={{ color: 'var(--primary)' }} />
                <span>QuickSupport Temporary Session Queue</span>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button className="btn-glass" onClick={loadQuickSupportQueue} style={{ fontSize: '0.75rem' }}>
                  <RefreshCw size={13} /> Refresh
                </button>
                <button className="btn-glass" onClick={() => navigatePath(configuredQsPath || '/remote')} style={{ fontSize: '0.75rem' }}>
                  Open Public Portal
                </button>
                <button className="btn-glass btn-icon" onClick={() => setQuickSupportQueueOpen(false)}>
                  <X size={18} />
                </button>
              </div>
            </div>
            <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
              {qsMessage && (
                <div style={{ padding: '0.7rem 0.9rem', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.14)', border: '1px solid rgba(16, 185, 129, 0.35)', fontSize: '0.8rem' }}>
                  {qsMessage}
                </div>
              )}
              {qsSessions.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                  No active QuickSupport sessions waiting in queue. Direct clients to{' '}
                  <code>{window.location.origin}{configuredQsPath}</code> to start an on-demand support session.
                </div>
              ) : (
                qsSessions.map((qs) => (
                  <div key={qs.id} className="glass-card" style={{ padding: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
                    <div>
                      <div style={{ fontWeight: 700, fontSize: '0.95rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--primary)' }}>{qs.session_code}</span>
                        <span>• {qs.client_name}</span>
                        <span className="status-pill status-online" style={{ fontSize: '0.68rem' }}>{qs.status}</span>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                        OS: {qs.platform.toUpperCase()} • Privilege: <strong>{qs.privilege_level}</strong> • Expires {new Date(qs.expires_at).toLocaleTimeString()}
                      </div>
                    </div>
                    {(() => {
                      const targetId = qs.device_id || qs.id;
                      return (
                        <div style={{ display: 'flex', gap: '0.45rem' }}>
                          <button
                            className="btn-glass"
                            style={{ fontSize: '0.75rem' }}
                            disabled={qsElevatingDeviceId === targetId}
                            onClick={() => handleElevateQuickSupport(targetId, 'elevate_temp_session')}
                          >
                            <ShieldCheck size={13} /> Self-Elevate (LAPS)
                          </button>
                          <button
                            className="btn-glass btn-primary"
                            style={{ fontSize: '0.75rem' }}
                            disabled={qsElevatingDeviceId === targetId}
                            onClick={() => handleElevateQuickSupport(targetId, 'promote_permanent_service')}
                          >
                            Promote to Service
                          </button>
                        </div>
                      );
                    })()}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      <MfaChallengeModal
        isOpen={qsElevationMfaOpen}
        onClose={() => setQsElevationMfaOpen(false)}
        onSuccess={() => {
          setQsElevationMfaOpen(false);
          setQsMessage('Step-Up MFA verified. Click Self-Elevate again to dispatch elevated token.');
        }}
        secretType="LAPS Remote Self-Elevation"
      />
    </div>
  );
}
export default App;
