import React from 'react';
import { Search, Shield, Download, Bell, User } from 'lucide-react';
import { Tenant } from '../types/index.js';

interface TopNavbarProps {
  searchQuery: string;
  onSearchChange: (q: string) => void;
  tenants: Tenant[];
  selectedTenantId: string;
  onTenantChange: (id: string) => void;
  onDownloadInstaller: () => void;
}

export const TopNavbar: React.FC<TopNavbarProps> = ({
  searchQuery,
  onSearchChange,
  tenants,
  selectedTenantId,
  onTenantChange,
  onDownloadInstaller
}) => {
  return (
    <header className="topbar" id="app-topbar">
      <div className="topbar-left">
        <div className="topbar-search">
          <Search size={16} />
          <input
            type="text"
            placeholder="Search endpoints, IP, BitLocker, MAC, role..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            id="global-search-input"
          />
        </div>

        <select
          className="glass-select"
          style={{ width: '220px', padding: '0.45rem 0.85rem' }}
          value={selectedTenantId}
          onChange={(e) => onTenantChange(e.target.value)}
          id="tenant-filter-select"
        >
          <option value="all">🏢 All Clients (MSP View)</option>
          {tenants.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name} ({t.device_count} devices)
            </option>
          ))}
        </select>
      </div>

      <div className="topbar-right">
        <div className="mesh-status-indicator" title="Connected to MeshCentral 2 Core via WebSocket Relay">
          <div className="pulse-dot" />
          <span>MeshCentral Engine Live</span>
        </div>

        <button
          className="btn-glass"
          onClick={onDownloadInstaller}
          title="Generate on-demand tokenized agent installer"
          id="btn-gen-installer"
        >
          <Download size={15} />
          <span>Agent Installer</span>
        </button>

        <button className="btn-glass btn-icon" title="Audit Alerts" id="btn-alerts">
          <Bell size={16} />
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginLeft: '0.5rem' }}>
          <div
            style={{
              width: '34px',
              height: '34px',
              borderRadius: '50%',
              background: 'linear-gradient(135deg, #00f2fe 0%, #7f00ff 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#fff'
            }}
          >
            <User size={18} />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>TylerHats</span>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>MSP Super Admin</span>
          </div>
        </div>
      </div>
    </header>
  );
};
