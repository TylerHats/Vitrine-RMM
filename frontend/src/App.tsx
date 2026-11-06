import { useState, useEffect, useCallback } from 'react';
import { Sidebar } from './components/Sidebar.js';
import { TopNavbar } from './components/TopNavbar.js';
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
import { GuestPortalView } from './views/GuestPortalView.js';

import { fetchDevices, fetchTenants, fetchSettings } from './services/api.js';
import { Device, Tenant, Settings } from './types/index.js';

import './styles/theme.css';
import './styles/components.css';

function applyVisualSettings(sets: Settings | null) {
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
    document.documentElement.style.setProperty('--glass-blur', blurMap[sets.glass_blur_level] || blurMap.high);
  }
}

export function App() {
  const [currentView, setCurrentView] = useState('dashboard');
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [devices, setDevices] = useState<Device[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [settings, setSettings] = useState<Settings | null>(null);

  const [selectedTenantId, setSelectedTenantId] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedDeviceForDetail, setSelectedDeviceForDetail] = useState<Device | null>(null);
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = useState(false);

  // Modals
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
  const [qbrOpen, setQbrOpen] = useState(false);
  const [installerModalOpen, setInstallerModalOpen] = useState(false);
  const [guestAccessModalOpen, setGuestAccessModalOpen] = useState(false);

  const urlParams = new URLSearchParams(window.location.search);
  const guestGrantId = urlParams.get('grant') || urlParams.get('guest');

  // Load initial data
  const loadData = useCallback(async () => {
    if (guestGrantId) return;
    try {
      const [devs, tens, sets] = await Promise.all([fetchDevices(), fetchTenants(), fetchSettings()]);
      setDevices(devs);
      setTenants(tens);
      setSettings(sets);
      applyVisualSettings(sets);
    } catch (err) {
      console.error('Error loading fleet data:', err);
    }
  }, [guestGrantId]);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, [loadData]);

  // Check if current URL is a guest vendor session (after all hooks are declared)
  if (guestGrantId) {
    return <GuestPortalView grantId={guestGrantId} />;
  }

  // Theme management
  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
  };

  const handleDeviceSelect = (dev: Device) => {
    setSelectedDeviceForDetail(dev);
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

  const handleDownloadInstaller = () => {
    setInstallerModalOpen(true);
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
          setSelectedDeviceForDetail(null);
          setIsMobileSidebarOpen(false);
        }}
        theme={theme}
        onToggleTheme={toggleTheme}
        brandName={settings?.brand_name || 'Vitrine RMM'}
        brandLogoUrl={settings?.brand_logo_url}
        onOpenOnboarding={() => setOnboardingOpen(true)}
        onOpenQbr={() => setQbrOpen(true)}
        isMobileOpen={isMobileSidebarOpen}
        onCloseMobile={() => setIsMobileSidebarOpen(false)}
      />

      <div className="main-wrapper">
        <TopNavbar
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          tenants={tenants}
          selectedTenantId={selectedTenantId}
          onTenantChange={setSelectedTenantId}
          onDownloadInstaller={handleDownloadInstaller}
          onOpenGuestAccess={() => setGuestAccessModalOpen(true)}
          onToggleMobileSidebar={() => setIsMobileSidebarOpen(!isMobileSidebarOpen)}
          devices={devices}
          onSelectDevice={handleDeviceSelect}
          onSelectView={(v) => {
            setCurrentView(v);
            setSelectedDeviceForDetail(null);
          }}
        />

        <main className="content-container">
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
            />
          )}

          {currentView === 'device-detail' && selectedDeviceForDetail && (
            <DeviceDetailView
              device={selectedDeviceForDetail}
              onBack={() => setCurrentView('dashboard')}
              onOpenRemote={(device, isGhost) => setRemoteModal({ open: true, device, isGhost })}
              onOpenBgTools={(device, initialTab) =>
                setBgToolsModal({ open: true, device, initialTab: initialTab || 'terminal' })
              }
              onOpenLaps={(device) => setLapsModal({ open: true, device })}
              onOpenQuarantine={(device) => setQuarantineModal({ open: true, device })}
            />
          )}

          {currentView === 'policies' && <PoliciesView devices={devices} tenants={tenants} />}
          {currentView === 'patching' && <PatchManagementView />}
          {currentView === 'scripts' && <ScriptLibraryView devices={devices} />}
          {currentView === 'self-healing' && <SelfHealingView />}
          {currentView === 'topology' && <NetworkTopologyView />}
          {currentView === 'virtualization' && <VirtualizationView />}
          {currentView === 'psa' && <PsaSyncView />}
          {currentView === 'settings' && (
            <SettingsView
              settings={settings || ({} as Settings)}
              onUpdated={handleSettingsUpdated}
              onOpenWizard={() => setOnboardingOpen(true)}
            />
          )}
        </main>
      </div>

      {/* MODALS */}
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
          onClose={() => setQbrOpen(false)}
        />
      )}

      {installerModalOpen && (
        <AgentInstallerModal
          tenants={tenants}
          selectedTenantId={selectedTenantId}
          settings={settings}
          onClose={() => setInstallerModalOpen(false)}
        />
      )}

      {guestAccessModalOpen && (
        <GuestAccessModal
          devices={devices}
          onClose={() => setGuestAccessModalOpen(false)}
        />
      )}
    </div>
  );
}
export default App;
