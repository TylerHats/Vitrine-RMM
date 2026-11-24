import { useState, useEffect, useCallback, lazy, Suspense } from 'react';
import { Sparkles, X, ShieldCheck, RefreshCw } from 'lucide-react';
import { Sidebar } from './components/Sidebar.js';
import { TopNavbar } from './components/TopNavbar.js';
import { LoginView } from './components/LoginView.js';
import { FleetDashboard } from './views/FleetDashboard.js';
import { MfaChallengeModal } from './components/MfaChallengeModal.js';
import { isSuperAdmin as checkIsSuperAdmin, canMutateFleet } from './utils/permissions.js';
import { sanitizeSafeUrl } from './utils/urlSafety.js';

const DevicesView = lazy(() =>
  import('./views/DevicesView.js').then((m) => ({ default: m.DevicesView }))
);
const DeviceDetailView = lazy(() =>
  import('./views/DeviceDetailView.js').then((m) => ({ default: m.DeviceDetailView }))
);
const AlertsCenterView = lazy(() =>
  import('./views/AlertsCenterView.js').then((m) => ({ default: m.AlertsCenterView }))
);
const DocumentationView = lazy(() =>
  import('./views/DocumentationView.js').then((m) => ({ default: m.DocumentationView }))
);
const AuditExplorerView = lazy(() =>
  import('./views/AuditExplorerView.js').then((m) => ({ default: m.AuditExplorerView }))
);
const PoliciesView = lazy(() =>
  import('./views/PoliciesView.js').then((m) => ({ default: m.PoliciesView }))
);
const PatchManagementView = lazy(() =>
  import('./views/PatchManagementView.js').then((m) => ({ default: m.PatchManagementView }))
);
const ScriptLibraryView = lazy(() =>
  import('./views/ScriptLibraryView.js').then((m) => ({ default: m.ScriptLibraryView }))
);
const SelfHealingView = lazy(() =>
  import('./views/SelfHealingView.js').then((m) => ({ default: m.SelfHealingView }))
);
const NetworkTopologyView = lazy(() =>
  import('./views/NetworkTopologyView.js').then((m) => ({ default: m.NetworkTopologyView }))
);
const VirtualizationView = lazy(() =>
  import('./views/VirtualizationView.js').then((m) => ({ default: m.VirtualizationView }))
);
const PsaSyncView = lazy(() =>
  import('./views/PsaSyncView.js').then((m) => ({ default: m.PsaSyncView }))
);
const SessionRecordingsView = lazy(() =>
  import('./views/SessionRecordingsView.js').then((m) => ({ default: m.SessionRecordingsView }))
);
const SettingsView = lazy(() =>
  import('./views/SettingsView.js').then((m) => ({ default: m.SettingsView }))
);
const GuestPortalView = lazy(() =>
  import('./views/GuestPortalView.js').then((m) => ({ default: m.GuestPortalView }))
);
const QuickSupportPortalView = lazy(() =>
  import('./views/QuickSupportPortalView.js').then((m) => ({ default: m.QuickSupportPortalView }))
);

const RemoteScreenModal = lazy(() =>
  import('./components/RemoteScreenModal.js').then((m) => ({ default: m.RemoteScreenModal }))
);
const BackgroundToolsModal = lazy(() =>
  import('./components/BackgroundToolsModal.js').then((m) => ({ default: m.BackgroundToolsModal }))
);
const LapsModal = lazy(() =>
  import('./components/LapsModal.js').then((m) => ({ default: m.LapsModal }))
);
const CyberIsolationModal = lazy(() =>
  import('./components/CyberIsolationModal.js').then((m) => ({ default: m.CyberIsolationModal }))
);
const OnboardingWizardModal = lazy(() =>
  import('./components/OnboardingWizardModal.js').then((m) => ({ default: m.OnboardingWizardModal }))
);
const QbrReportModal = lazy(() =>
  import('./components/QbrReportModal.js').then((m) => ({ default: m.QbrReportModal }))
);
const AgentInstallerModal = lazy(() =>
  import('./components/AgentInstallerModal.js').then((m) => ({ default: m.AgentInstallerModal }))
);
const GuestAccessModal = lazy(() =>
  import('./components/GuestAccessModal.js').then((m) => ({ default: m.GuestAccessModal }))
);

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
  QuickSupportSession,
  DevicesPresetFilter
} from './types/index.js';

import './styles/theme.css';
import './styles/components.css';

function parseHexRgb(hex: string): [number, number, number] | null {
  const clean = hex.trim().replace(/^#/, '');
  if (/^[0-9a-fA-F]{3}$/.test(clean)) {
    return [
      parseInt(clean[0] + clean[0], 16),
      parseInt(clean[1] + clean[1], 16),
      parseInt(clean[2] + clean[2], 16)
    ];
  }
  if (/^[0-9a-fA-F]{6}$/.test(clean)) {
    return [
      parseInt(clean.slice(0, 2), 16),
      parseInt(clean.slice(2, 4), 16),
      parseInt(clean.slice(4, 6), 16)
    ];
  }
  return null;
}

function relativeLuminance([r, g, b]: [number, number, number]): number {
  const chan = [r, g, b].map((c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * chan[0] + 0.7152 * chan[1] + 0.0722 * chan[2];
}

function clampPrimaryForTheme(rawColor: string, effectiveTheme: 'dark' | 'light'): string | null {
  const trimmed = rawColor.trim();
  if (!trimmed) return null;
  if (effectiveTheme === 'dark') return trimmed;
  if (trimmed.toLowerCase() === '#00f2fe') return '#0284c7';
  const rgb = parseHexRgb(trimmed);
  if (!rgb) return '#0284c7';
  if (relativeLuminance(rgb) <= 0.185) return trimmed;
  let [r, g, b] = rgb;
  if (Math.max(r, g, b) - Math.min(r, g, b) < 18) return '#0284c7';
  for (let i = 0; i < 12 && relativeLuminance([r, g, b]) > 0.185; i++) {
    r = Math.max(0, Math.round(r * 0.82));
    g = Math.max(0, Math.round(g * 0.82));
    b = Math.max(0, Math.round(b * 0.82));
  }
  const toHex = (n: number) => n.toString(16).padStart(2, '0');
  return `#${toHex(r)}${toHex(g)}${toHex(b)}`;
}

function resolveEffectiveTheme(
  themeOverride: 'dark' | 'light' | null,
  settingsMode?: string | null,
  publicMode?: string | null
): 'dark' | 'light' {
  const mode = themeOverride || settingsMode || publicMode || 'system';
  if (mode === 'light') return 'light';
  if (mode === 'dark') return 'dark';
  return typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: light)').matches
    ? 'light'
    : 'dark';
}

function applyVisualSettings(
  sets: { primary_color?: string; glass_blur_level?: string } | null,
  effectiveTheme: 'dark' | 'light' = 'dark'
) {
  if (!sets) {
    if (effectiveTheme === 'light') {
      document.documentElement.style.removeProperty('--primary');
    }
    return;
  }
  if (sets.primary_color) {
    if (effectiveTheme === 'light' && sets.primary_color.trim().toLowerCase() === '#00f2fe') {
      document.documentElement.style.removeProperty('--primary');
    } else {
      const resolvedPrimary = clampPrimaryForTheme(sets.primary_color, effectiveTheme);
      if (resolvedPrimary) {
        document.documentElement.style.setProperty('--primary', resolvedPrimary);
      }
    }
  } else if (effectiveTheme === 'light') {
    document.documentElement.style.removeProperty('--primary');
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
  const [authMeta, setAuthMeta] = useState<{
    initialized: boolean;
    oidcEnabled: boolean;
    isOnboarded: boolean;
  }>({
    initialized: true,
    oidcEnabled: false,
    isOnboarded: true
  });
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [publicConfig, setPublicConfig] = useState<PublicPortalConfig | null>(null);
  const [globalMfaModal, setGlobalMfaModal] = useState<{ open: boolean; secretType: string }>({
    open: false,
    secretType: 'step_up_action'
  });

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
  const [deviceDetailReturnView, setDeviceDetailReturnView] = useState<'dashboard' | 'devices'>('devices');
  const [devicesPresetFilter, setDevicesPresetFilter] = useState<DevicesPresetFilter | null>(null);
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
  const [qsSelectedSession, setQsSelectedSession] = useState<QuickSupportSession | null>(null);
  const [qsElevationAction, setQsElevationAction] = useState<'elevate_temp_session' | 'promote_permanent_service'>('elevate_temp_session');
  const [qsCredentialSource, setQsCredentialSource] = useState<'laps' | 'custom_admin' | 'end_user_uac'>('end_user_uac');
  const [qsAdminUsername, setQsAdminUsername] = useState('');
  const [qsAdminPassword, setQsAdminPassword] = useState('');
  const [qsElevatingDeviceId, setQsElevatingDeviceId] = useState<string | null>(null);
  const [qsElevationMfaOpen, setQsElevationMfaOpen] = useState(false);
  const [qsMessage, setQsMessage] = useState<string | null>(null);
  const [qsMessageIsError, setQsMessageIsError] = useState(false);

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

  const purgeSensitiveSessionState = useCallback(() => {
    setCurrentUser(null);
    setDevices([]);
    setTenants([]);
    setSettings(null);
    setUpdaterStatus(null);
    setSelectedDeviceId(null);
    setSelectedTenantId('all');
    setSearchQuery('');
    setCurrentView('dashboard');
    setIsMobileSidebarOpen(false);
    setHasAutoCheckedOobe(false);
    setDismissedUpdateBanner(false);
    setQsSessions([]);
    setQsSelectedSession(null);
    setQsAdminUsername('');
    setQsAdminPassword('');
    setQsElevatingDeviceId(null);
    setQsMessage(null);
    setQsMessageIsError(false);
    setRemoteModal({ open: false, device: null, isGhost: false });
    setBgToolsModal({ open: false, device: null, initialTab: 'terminal' });
    setLapsModal({ open: false, device: null });
    setQuarantineModal({ open: false, device: null });
    setOnboardingOpen(false);
    setQbrOpen(false);
    setInstallerModalOpen(false);
    setGuestAccessModalOpen(false);
    setQuickSupportQueueOpen(false);
    setQsElevationMfaOpen(false);
    setGlobalMfaModal({ open: false, secretType: 'step_up_action' });
  }, []);

  // Check public config & auth status on startup
  const refreshAuthAndPublic = useCallback(async () => {
    try {
      const [pub, auth] = await Promise.all([
        fetchPublicPortalConfig().catch(() => null),
        fetchAuthStatus().catch(() => ({
          initialized: true,
          authenticated: false,
          user: null,
          oidcEnabled: false,
          isOnboarded: true
        }))
      ]);
      if (pub) {
        setPublicConfig(pub);
        const effTheme = resolveEffectiveTheme(themeOverride, null, pub.theme_mode);
        applyVisualSettings(pub, effTheme);
      }
      const authTyped = auth as { oidcEnabled?: boolean; isOnboarded?: boolean };
      setAuthMeta({
        initialized: auth.initialized,
        oidcEnabled: Boolean(authTyped.oidcEnabled),
        isOnboarded: authTyped.isOnboarded !== undefined ? Boolean(authTyped.isOnboarded) : true
      });
      setCurrentUser(auth.authenticated && auth.user ? auth.user : null);
    } finally {
      setAuthChecked(true);
    }
  }, [themeOverride]);

  useEffect(() => {
    refreshAuthAndPublic();
    const onAuthExpired = () => {
      purgeSensitiveSessionState();
    };
    const onMfaRequired = (e: Event) => {
      const detail = (e as CustomEvent)?.detail;
      setTimeout(() => {
        if (!document.getElementById('mfa-challenge-modal')) {
          setGlobalMfaModal({
            open: true,
            secretType: detail?.action || detail?.secretType || 'step_up_action'
          });
        }
      }, 45);
    };
    window.addEventListener('vitrine:auth-expired', onAuthExpired);
    window.addEventListener('vitrine:mfa-required', onMfaRequired);
    return () => {
      window.removeEventListener('vitrine:auth-expired', onAuthExpired);
      window.removeEventListener('vitrine:mfa-required', onMfaRequired);
    };
  }, [refreshAuthAndPublic, purgeSensitiveSessionState]);

  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: light)');
    const applyResolvedTheme = () => {
      const resolved = resolveEffectiveTheme(themeOverride, settings?.theme_mode, publicConfig?.theme_mode);
      setTheme(resolved);
      document.documentElement.setAttribute('data-theme', resolved);
      applyVisualSettings(settings || publicConfig, resolved);
    };
    applyResolvedTheme();
    mediaQuery.addEventListener('change', applyResolvedTheme);
    return () => mediaQuery.removeEventListener('change', applyResolvedTheme);
  }, [themeOverride, settings, publicConfig]);

  useEffect(() => {
    const brand = settings?.brand_name || publicConfig?.brand_name || 'Vitrine RMM';
    document.title = brand;
    const rawLogoUrl = settings?.brand_logo_url || publicConfig?.brand_logo_url;
    const safeLogoUrl = sanitizeSafeUrl(rawLogoUrl);
    if (safeLogoUrl) {
      const link = document.querySelector<HTMLLinkElement>("link[rel~='icon']");
      if (link) link.href = safeLogoUrl;
    }
  }, [settings?.brand_name, settings?.brand_logo_url, publicConfig?.brand_name, publicConfig?.brand_logo_url]);

  const needsInitialMfaConfirm = Boolean(
    currentUser && currentUser.totp_enabled && currentUser.totp_confirmed === false
  );

  const loadData = useCallback(async () => {
    if (guestGrantId || isQuickSupportRoute || !currentUser || needsInitialMfaConfirm) return;
    try {
      const [devs, tens, sets, upd] = await Promise.all([
        fetchDevices(),
        fetchTenants(),
        fetchSettings().catch(() => null),
        checkIsSuperAdmin(currentUser) ? fetchUpdaterStatus().catch(() => null) : Promise.resolve(null)
      ]);
      setDevices(devs);
      setTenants(tens);
      if (sets) {
        setSettings(sets);
        const effTheme = resolveEffectiveTheme(themeOverride, sets.theme_mode, publicConfig?.theme_mode);
        applyVisualSettings(sets, effTheme);
        if (
          !hasAutoCheckedOobe &&
          checkIsSuperAdmin(currentUser) &&
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
  }, [guestGrantId, isQuickSupportRoute, currentUser, needsInitialMfaConfirm, hasAutoCheckedOobe, themeOverride, publicConfig?.theme_mode]);

  useEffect(() => {
    loadData();
    if (!currentUser || needsInitialMfaConfirm || guestGrantId || isQuickSupportRoute) return;
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, [loadData, currentUser, needsInitialMfaConfirm, guestGrantId, isQuickSupportRoute]);

  const activeDeviceForDetail = selectedDeviceId ? devices.find((d) => d.id === selectedDeviceId) || null : null;

  useEffect(() => {
    if (!authChecked || !currentUser || needsInitialMfaConfirm || guestGrantId || isQuickSupportRoute) return;
    if (currentView === 'device-detail' && !activeDeviceForDetail) {
      setSelectedDeviceId(null);
      setCurrentView('dashboard');
    }
  }, [
    authChecked,
    currentUser,
    needsInitialMfaConfirm,
    guestGrantId,
    isQuickSupportRoute,
    currentView,
    activeDeviceForDetail
  ]);
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
    setQsMessageIsError(false);
    setQsSelectedSession(null);
    setQuickSupportQueueOpen(true);
    loadQuickSupportQueue();
  };

  const openQuickSupportElevation = (
    session: QuickSupportSession,
    action: 'elevate_temp_session' | 'promote_permanent_service'
  ) => {
    setQsSelectedSession(session);
    setQsElevationAction(action);
    setQsCredentialSource(session.device_id ? 'laps' : 'end_user_uac');
    setQsAdminUsername('');
    setQsAdminPassword('');
    setQsMessage(null);
    setQsMessageIsError(false);
  };

  const handleElevateQuickSupport = async (
    overrideSession?: QuickSupportSession,
    overrideAction?: 'elevate_temp_session' | 'promote_permanent_service'
  ) => {
    const activeQs = overrideSession || qsSelectedSession;
    if (!activeQs) return;
    const targetId = activeQs.device_id || activeQs.id;
    const action = overrideAction || qsElevationAction;
    const effectiveCredentialSource =
      !activeQs.device_id && qsCredentialSource === 'laps' ? 'end_user_uac' : qsCredentialSource;

    setQsElevatingDeviceId(targetId);
    setQsMessage(null);
    setQsMessageIsError(false);
    try {
      const res = await elevateRemoteAgent(targetId, {
        credentialSource: effectiveCredentialSource,
        elevationAction: action,
        adminUsername: effectiveCredentialSource === 'custom_admin' ? qsAdminUsername.trim() : undefined,
        adminPassword: effectiveCredentialSource === 'custom_admin' ? qsAdminPassword : undefined
      });
      if (res.mfaRequired) {
        setQsElevationMfaOpen(true);
        return;
      }
      if (res.success) {
        setQsMessageIsError(false);
        setQsMessage(res.message || 'Remote elevation command dispatched.');
        setQsSelectedSession(null);
        loadQuickSupportQueue();
        loadData();
      } else {
        setQsMessageIsError(true);
        setQsMessage(res.error || 'Elevation failed.');
      }
    } catch (err: unknown) {
      setQsMessageIsError(true);
      setQsMessage(err instanceof Error ? err.message : 'Elevation failed.');
    } finally {
      setQsElevatingDeviceId(null);
    }
  };

  if (guestGrantId) {
    return (
      <Suspense
        fallback={
          <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--surface-base)', color: 'var(--text-main)' }}>
            Loading Guest Portal...
          </div>
        }
      >
        <GuestPortalView grantId={guestGrantId} />
      </Suspense>
    );
  }

  if (isQuickSupportRoute) {
    return (
      <Suspense
        fallback={
          <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--surface-base)', color: 'var(--text-main)' }}>
            Loading QuickSupport Portal...
          </div>
        }
      >
        <QuickSupportPortalView />
      </Suspense>
    );
  }

  if (!authChecked) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--surface-base)', color: 'var(--text-main)' }}>
        <div style={{ textAlign: 'center' }}>
          <div className="pulse-dot" style={{ margin: '0 auto 1rem', width: '14px', height: '14px' }} />
          <div style={{ fontSize: '0.9rem', opacity: 0.85 }}>
            Loading {publicConfig?.brand_name || 'Vitrine RMM'}...
          </div>
        </div>
      </div>
    );
  }

  const handleLogout = async () => {
    try {
      await logoutSession();
    } catch {
      // Ignore network errors during logout cleanup
    } finally {
      purgeSensitiveSessionState();
      await refreshAuthAndPublic();
    }
  };

  if (!currentUser || needsInitialMfaConfirm) {
    return (
      <LoginView
        authStatus={{
          initialized: authMeta.initialized,
          authenticated: Boolean(currentUser),
          user: currentUser,
          mfaVerified: false,
          mfaVerifiedUntil: null,
          isOnboarded: authMeta.isOnboarded || Boolean(settings?.is_onboarded),
          oidcEnabled: authMeta.oidcEnabled,
          branding: {
            brand_name: settings?.brand_name || publicConfig?.brand_name || 'Vitrine RMM',
            brand_logo_url: settings?.brand_logo_url || publicConfig?.brand_logo_url || '/branding/logo.png',
            primary_color: settings?.primary_color || publicConfig?.primary_color || '#00f2fe',
            theme_mode: settings?.theme_mode || publicConfig?.theme_mode || 'system'
          }
        }}
        pendingMfaUser={needsInitialMfaConfirm ? currentUser : null}
        onSignOutPendingMfa={handleLogout}
        onAuthenticated={(user, triggerOobe) => {
          setAuthMeta((prev) => ({ ...prev, initialized: true }));
          setCurrentUser(user);
          if (triggerOobe && checkIsSuperAdmin(user) && user.totp_confirmed !== false) {
            setOnboardingOpen(true);
          }
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
    applyVisualSettings(settings || publicConfig, nextTheme);
    try {
      localStorage.setItem('vitrine_theme_override', nextTheme);
    } catch {
      // Ignore storage error
    }
  };

  const handleDeviceSelect = (dev: Device) => {
    setDeviceDetailReturnView(currentView === 'dashboard' ? 'dashboard' : 'devices');
    setSelectedDeviceId(dev.id);
    setCurrentView('device-detail');
  };

  const handleNavigateToDevices = (preset?: DevicesPresetFilter) => {
    if (preset) {
      setDevicesPresetFilter(preset);
    }
    setSelectedDeviceId(null);
    setCurrentView('devices');
  };

  const handleDeviceQuarantineUpdated = (quarantined: boolean) => {
    if (quarantineModal.device) {
      setDevices((prev) =>
        prev.map((d) =>
          d.id === quarantineModal.device!.id
            ? {
                ...d,
                quarantined: quarantined ? 1 : 0,
                status: quarantined ? 'isolated' : d.status === 'isolated' ? 'online' : d.status
              }
            : d
        )
      );
    }
    loadData();
  };

  const handleSettingsUpdated = (s: Settings) => {
    setSettings(s);
    const effTheme = resolveEffectiveTheme(themeOverride, s.theme_mode, publicConfig?.theme_mode);
    applyVisualSettings(s, effTheme);
    setPublicConfig((prev) => ({
      brand_name: s.brand_name || prev?.brand_name || 'Vitrine RMM',
      brand_logo_url: s.brand_logo_url || prev?.brand_logo_url || '/branding/logo.png',
      primary_color: s.primary_color || prev?.primary_color || '#00f2fe',
      glass_blur_level: s.glass_blur_level || prev?.glass_blur_level || 'high',
      theme_mode: (s.theme_mode || prev?.theme_mode || 'system') as 'system' | 'dark' | 'light',
      quicksupport_enabled:
        s.quicksupport_enabled !== undefined
          ? Boolean(s.quicksupport_enabled)
          : (prev?.quicksupport_enabled ?? true),
      quicksupport_url_path: s.quicksupport_url_path || prev?.quicksupport_url_path || '/remote',
      quicksupport_custom_domain: s.quicksupport_custom_domain ?? prev?.quicksupport_custom_domain ?? '',
      code_signing_enabled: Boolean(s.code_signing_enabled)
    }));
    const hasOidcConfig = Boolean(String(s.oidc_issuer_url || '').trim() && String(s.oidc_client_id || '').trim());
    setAuthMeta((prev) => ({
      ...prev,
      isOnboarded: Boolean(s.is_onboarded || s.oobe_completed || prev.isOnboarded),
      oidcEnabled: Boolean(hasOidcConfig && Boolean(s.oidc_enabled))
    }));
    void refreshAuthAndPublic();
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
        appVersion={updaterStatus?.installedVersion || '2.8.0'}
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
            checkIsSuperAdmin(currentUser) &&
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
              tenants={tenants}
              selectedTenantId={selectedTenantId}
              onSelectDevice={handleDeviceSelect}
              onNavigateDevices={handleNavigateToDevices}
              onOpenInstaller={() => setInstallerModalOpen(true)}
              onOpenOnboarding={() => setOnboardingOpen(true)}
              onRefreshFleet={loadData}
              currentUser={currentUser}
            />
          )}

          <Suspense
            fallback={
              <div className="glass-card" style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.88rem' }}>
                Loading module...
              </div>
            }
          >
            {currentView === 'devices' && (
              <DevicesView
                devices={devices}
                tenants={tenants}
                searchQuery={searchQuery}
                selectedTenantId={selectedTenantId}
                onTenantChange={setSelectedTenantId}
                presetFilter={devicesPresetFilter}
                onConsumePreset={() => setDevicesPresetFilter(null)}
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
                onBack={() => setCurrentView(deviceDetailReturnView)}
                onOpenRemote={(device, isGhost) => setRemoteModal({ open: true, device, isGhost })}
                onOpenBgTools={(device, initialTab) =>
                  setBgToolsModal({ open: true, device, initialTab: initialTab || 'terminal' })
                }
                onOpenLaps={(device) => setLapsModal({ open: true, device })}
                onOpenQuarantine={(device) => setQuarantineModal({ open: true, device })}
                currentUser={currentUser}
                settings={settings}
                onRefreshFleet={loadData}
              />
            )}

            {currentView === 'alerts' && (
              <AlertsCenterView
                tenants={tenants}
                selectedTenantId={selectedTenantId}
                currentUser={currentUser}
              />
            )}
            {currentView === 'documentation' && (
              <DocumentationView
                tenants={tenants}
                devices={devices}
                selectedTenantId={selectedTenantId}
                currentUser={currentUser}
              />
            )}
            {currentView === 'audit' && currentUser.role !== 'client_admin' && <AuditExplorerView />}
            {currentView === 'policies' && currentUser.role !== 'client_admin' && (
              <PoliciesView devices={devices} tenants={tenants} currentUser={currentUser} />
            )}
            {currentView === 'patching' && (
              <PatchManagementView
                settings={settings}
                onSettingsUpdated={handleSettingsUpdated}
                currentUser={currentUser}
              />
            )}
            {currentView === 'scripts' && currentUser.role !== 'client_admin' && (
              <ScriptLibraryView devices={devices} currentUser={currentUser} />
            )}
            {currentView === 'self-healing' && currentUser.role !== 'client_admin' && (
              <SelfHealingView currentUser={currentUser} />
            )}
            {currentView === 'topology' && currentUser.role !== 'client_admin' && (
              <NetworkTopologyView currentUser={currentUser} />
            )}
            {currentView === 'virtualization' && currentUser.role !== 'client_admin' && (
              <VirtualizationView currentUser={currentUser} />
            )}
            {currentView === 'recordings' && currentUser.role !== 'client_admin' && (
              <SessionRecordingsView
                tenants={tenants}
                devices={devices}
                selectedTenantId={selectedTenantId}
                currentUser={currentUser}
                onSelectDevice={handleDeviceSelect}
              />
            )}
            {currentView === 'psa' && currentUser.role !== 'client_admin' && (
              <PsaSyncView tenants={tenants} devices={devices} currentUser={currentUser} />
            )}
            {currentView === 'settings' && checkIsSuperAdmin(currentUser) && (
              <SettingsView
                settings={settings || ({} as Settings)}
                onUpdated={handleSettingsUpdated}
                onOpenWizard={() => setOnboardingOpen(true)}
                tenants={tenants}
              />
            )}
          </Suspense>
        </main>
      </div>

      <Suspense fallback={null}>
        {remoteModal.open && remoteModal.device && (
          <RemoteScreenModal
            device={devices.find((d) => d.id === remoteModal.device!.id) || remoteModal.device}
            isGhostSession={remoteModal.isGhost}
            onClose={() => setRemoteModal({ open: false, device: null, isGhost: false })}
          />
        )}

        {bgToolsModal.open && bgToolsModal.device && (
          <BackgroundToolsModal
            device={devices.find((d) => d.id === bgToolsModal.device!.id) || bgToolsModal.device}
            initialTab={bgToolsModal.initialTab}
            onClose={() => setBgToolsModal({ open: false, device: null, initialTab: 'terminal' })}
          />
        )}

        {lapsModal.open && lapsModal.device && (
          <LapsModal
            device={devices.find((d) => d.id === lapsModal.device!.id) || lapsModal.device}
            currentUser={currentUser}
            onClose={() => setLapsModal({ open: false, device: null })}
          />
        )}

        {quarantineModal.open && quarantineModal.device && (
          <CyberIsolationModal
            device={devices.find((d) => d.id === quarantineModal.device!.id) || quarantineModal.device}
            onClose={() => setQuarantineModal({ open: false, device: null })}
            onUpdated={handleDeviceQuarantineUpdated}
          />
        )}

        {onboardingOpen && checkIsSuperAdmin(currentUser) && (
          <OnboardingWizardModal
            settings={settings || ({} as Settings)}
            adminEmail={currentUser?.email || ''}
            onClose={() => setOnboardingOpen(false)}
            onSaved={(updated) => {
              setAuthMeta((prev) => ({ ...prev, isOnboarded: true }));
              handleSettingsUpdated(updated);
            }}
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
      </Suspense>

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
                <div
                  style={{
                    padding: '0.7rem 0.9rem',
                    borderRadius: '8px',
                    background: qsMessageIsError ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.14)',
                    border: `1px solid ${qsMessageIsError ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                    color: qsMessageIsError ? '#f87171' : '#34d399',
                    fontSize: '0.8rem'
                  }}
                >
                  {qsMessage}
                </div>
              )}

              {qsSelectedSession && canMutateFleet(currentUser) && (
                <div
                  className="glass-card"
                  style={{
                    padding: '1rem',
                    border: '1px solid rgba(0, 242, 254, 0.35)',
                    background: 'rgba(0, 242, 254, 0.06)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.75rem'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ fontWeight: 700, fontSize: '0.88rem', color: 'var(--primary)' }}>
                      {qsElevationAction === 'promote_permanent_service'
                        ? `Promote QuickSupport Session ${qsSelectedSession.session_code} to Permanent Service`
                        : `Self-Elevate QuickSupport Session ${qsSelectedSession.session_code}`}
                    </div>
                    <button
                      type="button"
                      className="btn-glass btn-icon"
                      onClick={() => setQsSelectedSession(null)}
                    >
                      <X size={15} />
                    </button>
                  </div>

                  <div className="form-group" style={{ margin: 0 }}>
                    <label className="form-label" style={{ fontSize: '0.75rem' }}>
                      Elevation Credential Source
                    </label>
                    <select
                      className="glass-select"
                      value={!qsSelectedSession.device_id && qsCredentialSource === 'laps' ? 'end_user_uac' : qsCredentialSource}
                      onChange={(e) =>
                        setQsCredentialSource(e.target.value as 'laps' | 'custom_admin' | 'end_user_uac')
                      }
                    >
                      {Boolean(qsSelectedSession.device_id) && (
                        <option value="laps">Use Escrowed Vitrine LAPS Vault Credential</option>
                      )}
                      <option value="end_user_uac">Trigger Interactive End-User UAC / Polkit Consent Prompt</option>
                      <option value="custom_admin">Supply One-Time Local / Domain Admin Credentials</option>
                    </select>
                  </div>

                  {qsCredentialSource === 'custom_admin' && (
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.65rem' }}>
                      <input
                        type="text"
                        className="glass-input"
                        placeholder="Administrator or DOMAIN\Admin"
                        value={qsAdminUsername}
                        onChange={(e) => setQsAdminUsername(e.target.value)}
                      />
                      <input
                        type="password"
                        className="glass-input"
                        placeholder="Admin Password"
                        value={qsAdminPassword}
                        onChange={(e) => setQsAdminPassword(e.target.value)}
                      />
                    </div>
                  )}

                  <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                    <button type="button" className="btn-glass" onClick={() => setQsSelectedSession(null)}>
                      Cancel
                    </button>
                    <button
                      type="button"
                      className="btn-glass btn-primary"
                      disabled={
                        qsElevatingDeviceId === (qsSelectedSession.device_id || qsSelectedSession.id) ||
                        (qsCredentialSource === 'custom_admin' && (!qsAdminUsername.trim() || !qsAdminPassword))
                      }
                      onClick={() => handleElevateQuickSupport()}
                    >
                      <ShieldCheck size={14} />{' '}
                      {qsElevationAction === 'promote_permanent_service'
                        ? 'Dispatch Service Promotion'
                        : 'Dispatch Self-Elevation'}
                    </button>
                  </div>
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
                    {canMutateFleet(currentUser) && (() => {
                      const targetId = qs.device_id || qs.id;
                      return (
                        <div style={{ display: 'flex', gap: '0.45rem' }}>
                          <button
                            className="btn-glass"
                            style={{ fontSize: '0.75rem' }}
                            disabled={qsElevatingDeviceId === targetId}
                            onClick={() => openQuickSupportElevation(qs, 'elevate_temp_session')}
                          >
                            <ShieldCheck size={13} /> Self-Elevate
                          </button>
                          <button
                            className="btn-glass btn-primary"
                            style={{ fontSize: '0.75rem' }}
                            disabled={qsElevatingDeviceId === targetId}
                            onClick={() => openQuickSupportElevation(qs, 'promote_permanent_service')}
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
          handleElevateQuickSupport();
        }}
        secretType="LAPS Remote Self-Elevation"
      />

      <MfaChallengeModal
        isOpen={globalMfaModal.open}
        onClose={() => setGlobalMfaModal({ open: false, secretType: 'step_up_action' })}
        onSuccess={() => setGlobalMfaModal({ open: false, secretType: 'step_up_action' })}
        title="Step-Up MFA Verification Required"
        description="This administrative or vault action requires a fresh 6-digit TOTP authenticator code or recovery code. Once verified, you can retry your action immediately."
        secretType={globalMfaModal.secretType}
      />
    </div>
  );
}
export default App;
