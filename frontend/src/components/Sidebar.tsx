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

interface SidebarProps {
  currentView: string;
  onSelectView: (view: string) => void;
  theme: string;
  onToggleTheme: () => void;
  brandName: string;
  onOpenOnboarding: () => void;
  onOpenQbr: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  onSelectView,
  theme,
  onToggleTheme,
  brandName,
  onOpenOnboarding,
  onOpenQbr
}) => {
  const navItems = [
    { id: 'dashboard', label: 'Fleet Dashboard', icon: LayoutDashboard },
    { id: 'policies', label: 'Policy Hierarchy', icon: ShieldCheck },
    { id: 'patching', label: 'Patch Management', icon: RefreshCw },
    { id: 'scripts', label: 'Script Library', icon: Code2 },
    { id: 'self-healing', label: 'Self-Healing', icon: HeartPulse },
    { id: 'topology', label: 'Network & Topology', icon: Network },
    { id: 'virtualization', label: 'Hypervisors & VMs', icon: Server },
    { id: 'psa', label: 'PSA / ITFlow Sync', icon: Ticket },
    { id: 'settings', label: 'White-Label & Setup', icon: Settings }
  ];

  return (
    <aside className="sidebar" id="app-sidebar">
      <div className="sidebar-header">
        <img src="/logo.png" alt="Vitrine Logo" className="brand-logo-img" />
        <span className="brand-title">{brandName || 'Vitrine RMM'}</span>
        <span className="brand-badge">PRO</span>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-title">Core Fleet</div>
        {navItems.slice(0, 5).map((item) => {
          const Icon = item.icon;
          const isActive = currentView === item.id;
          return (
            <button
              key={item.id}
              className={`nav-item ${isActive ? 'active' : ''}`}
              onClick={() => onSelectView(item.id)}
              id={`nav-${item.id}`}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </button>
          );
        })}

        <div className="nav-section-title">Infrastructure & Integrations</div>
        {navItems.slice(5).map((item) => {
          const Icon = item.icon;
          const isActive = currentView === item.id;
          return (
            <button
              key={item.id}
              className={`nav-item ${isActive ? 'active' : ''}`}
              onClick={() => onSelectView(item.id)}
              id={`nav-${item.id}`}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </button>
          );
        })}

        <div className="nav-section-title">Reports & Tools</div>
        <button className="nav-item" onClick={onOpenQbr} id="nav-qbr-report">
          <FileText size={18} />
          <span>Executive QBR Report</span>
        </button>
        <button className="nav-item" onClick={onOpenOnboarding} id="nav-setup-wizard">
          <Sparkles size={18} style={{ color: '#00f2fe' }} />
          <span>Setup Wizard</span>
        </button>
      </nav>

      <div className="sidebar-footer">
        <button
          className="btn-glass btn-icon"
          onClick={onToggleTheme}
          title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
          id="theme-toggle-btn"
        >
          {theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}
        </button>
        <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textAlign: 'right' }}>
          MeshCentral 2 Engine<br />
          <span style={{ color: 'var(--accent-success)' }}>● v2.1.0 Relay</span>
        </div>
      </div>
    </aside>
  );
};
