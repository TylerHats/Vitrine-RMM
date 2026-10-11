import React, { useState, useEffect } from 'react';
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

import { fetchDevices, fetchTenants, fetchSettings } from './services/api.js';
import { Device, Tenant, Settings } from './types/index.js';

import './styles/theme.css';
import './styles/components.css';

export function App() {
  const [currentView, setCurrentView] = useState('dashboard');
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [devices, setDevices] = useState<Device[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [settings, setSettings] = useState<Settings | null>(null);

  const [selectedTenantId, setSelectedTenantId] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedDeviceForDetail, setSelectedDeviceForDetail] = useState<Device | null>(null);

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

  // Load initial data
  const loadData = async () => {
    try {
      const [devs, tens, sets] = await Promise.all([fetchDevices(), fetchTenants(), fetchSettings()]);
      setDevices(devs);
      setTenants(tens);
      setSettings(sets);

      if (sets?.primary_color) {
        document.documentElement.style.setProperty('--primary', sets.primary_color);
      }
    } catch (err) {
      console.error('Error loading fleet data:', err);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, []);

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
    alert(
      `Generating on-demand tokenized agent installer for ${
        selectedTenantId === 'all' ? 'Global Fleet' : selectedTenantId
      }...\n\nBranded with logo: /branding/logo.png\nRelay Endpoint: ${
        settings?.meshcentral_url || 'https://127.0.0.1:443'
      }\nToken Lifetime: 24 Hours`
    );
  };

  return (
    <div className="app-shell" data-theme={theme}>
      <Sidebar
        currentView={currentView}
        onSelectView={(v) => {
          setCurrentView(v);
          setSelectedDeviceForDetail(null);
        }}
        theme={theme}
        onToggleTheme={toggleTheme}
        brandName={settings?.brand_name || 'Vitrine RMM'}
        onOpenOnboarding={() => setOnboardingOpen(true)}
        onOpenQbr={() => setQbrOpen(true)}
      />

      <div className="main-wrapper">
        <TopNavbar
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          tenants={tenants}
          selectedTenantId={selectedTenantId}
          onTenantChange={setSelectedTenantId}
          onDownloadInstaller={handleDownloadInstaller}
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

          {currentView === 'policies' && <PoliciesView devices={devices} />}
          {currentView === 'patching' && <PatchManagementView />}
          {currentView === 'scripts' && <ScriptLibraryView devices={devices} />}
          {currentView === 'self-healing' && <SelfHealingView />}
          {currentView === 'topology' && <NetworkTopologyView />}
          {currentView === 'virtualization' && <VirtualizationView />}
          {currentView === 'psa' && <PsaSyncView />}
          {currentView === 'settings' && (
            <SettingsView
              settings={settings || ({} as Settings)}
              onUpdated={(s) => setSettings(s)}
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
          onSaved={(s) => setSettings(s)}
        />
      )}

      {qbrOpen && <QbrReportModal onClose={() => setQbrOpen(false)} />}
    </div>
  );
}
export default App;
