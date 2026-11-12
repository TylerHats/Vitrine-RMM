import React from 'react';
import {
  LayoutDashboard,
  ShieldCheck,
  RefreshCw,
  Code2,
  HeartPulse,
  Network,
  Server,
  Ticket,
  Settings,
  Sun,
  Moon,
  Sparkles,
  FileText
} from 'lucide-react';
import { AuthUser } from '../types/index.js';

interface SidebarProps {
  currentView: string;
  onSelectView: (view: string) => void;
  theme: string;
  onToggleTheme: () => void;
  brandName: string;
  brandLogoUrl?: string;
  onOpenOnboarding: () => void;
  onOpenQbr: () => void;
  isMobileOpen?: boolean;
  onCloseMobile?: () => void;
  currentUser?: AuthUser | null;
  meshConnected?: boolean;
  appVersion?: string;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  onSelectView,
  theme,
  onToggleTheme,
  brandName,
  brandLogoUrl,
  onOpenOnboarding,
  onOpenQbr,
  isMobileOpen = false,
  onCloseMobile,
  currentUser,
  meshConnected = false,
  appVersion = '2.5.0'
}) => {
  const isClientAdmin = currentUser?.role === 'client_admin';
  const isSuperAdmin =
    !currentUser ||
    currentUser.role === 'msp_super_admin' ||
    currentUser.role === 'super_admin' ||
    currentUser.role === 'admin';

  const coreNavItems = [
    { id: 'dashboard', label: 'Fleet Dashboard', icon: LayoutDashboard, allowClient: true },
    { id: 'policies', label: 'Policy Hierarchy', icon: ShieldCheck, allowClient: false },
    { id: 'patching', label: 'Patch Management', icon: RefreshCw, allowClient: true },
    { id: 'scripts', label: 'Script Library', icon: Code2, allowClient: false },
    { id: 'self-healing', label: 'Self-Healing', icon: HeartPulse, allowClient: false }
  ].filter((item) => !isClientAdmin || item.allowClient);

  const infraNavItems = [
    { id: 'topology', label: 'Network & Topology', icon: Network, allowClient: false },
    { id: 'virtualization', label: 'Hypervisors & VMs', icon: Server, allowClient: false },
    { id: 'psa', label: 'PSA / ITFlow Sync', icon: Ticket, allowClient: false },
    ...(isSuperAdmin ? [{ id: 'settings', label: 'White-Label & Setup', icon: Settings, allowClient: false }] : [])
  ].filter((item) => !isClientAdmin || item.allowClient);

  const handleNavClick = (id: string) => {
    onSelectView(id);
    if (onCloseMobile) onCloseMobile();
  };

  return (
    <>
      <div
        className={`sidebar-overlay ${isMobileOpen ? 'mobile-open' : ''}`}
        onClick={onCloseMobile}
        id="sidebar-mobile-overlay"
      />
      <aside className={`sidebar ${isMobileOpen ? 'mobile-open' : ''}`} id="app-sidebar">
        <div className="sidebar-header">
          <img src={brandLogoUrl || '/branding/logo.png'} alt="Vitrine Logo" className="brand-logo-img" />
          <span className="brand-title">{brandName || 'Vitrine RMM'}</span>
          <span className="brand-badge">v{appVersion}</span>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section-title">Core Fleet</div>
          {coreNavItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentView === item.id;
            return (
              <button
                key={item.id}
                type="button"
                className={`nav-item ${isActive ? 'active' : ''}`}
                onClick={() => handleNavClick(item.id)}
                id={`nav-${item.id}`}
              >
                <Icon size={18} />
                <span>{item.label}</span>
              </button>
            );
          })}

          {infraNavItems.length > 0 && (
            <>
              <div className="nav-section-title">Infrastructure &amp; Integrations</div>
              {infraNavItems.map((item) => {
                const Icon = item.icon;
                const isActive = currentView === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    className={`nav-item ${isActive ? 'active' : ''}`}
                    onClick={() => handleNavClick(item.id)}
                    id={`nav-${item.id}`}
                  >
                    <Icon size={18} />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </>
          )}

          <div className="nav-section-title">Reports &amp; Tools</div>
          <button
            type="button"
            className="nav-item"
            onClick={() => {
              onOpenQbr();
              if (onCloseMobile) onCloseMobile();
            }}
            id="nav-qbr-report"
          >
            <FileText size={18} />
            <span>Executive QBR Report</span>
          </button>

          {isSuperAdmin && (
            <button
              type="button"
              className="nav-item"
              onClick={() => {
                onOpenOnboarding();
                if (onCloseMobile) onCloseMobile();
              }}
              id="nav-setup-wizard"
            >
              <Sparkles size={18} style={{ color: 'var(--primary)' }} />
              <span>Setup Wizard</span>
            </button>
          )}
        </nav>

        <div className="sidebar-footer">
          <button
            type="button"
            className="btn-glass btn-icon"
            onClick={onToggleTheme}
            title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
            id="theme-toggle-btn"
          >
            {theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}
          </button>
          <div style={{ fontSize: '0.73rem', color: 'var(--text-dim)', textAlign: 'right' }}>
            MeshCentral 2 Bridge
            <br />
            {meshConnected ? (
              <span style={{ color: 'var(--accent-success)', fontWeight: 600 }}>● Connected Relay</span>
            ) : (
              <span style={{ color: 'var(--accent-warning)', fontWeight: 600 }}>○ Standalone Mode</span>
            )}
          </div>
        </div>
      </aside>
    </>
  );
};
