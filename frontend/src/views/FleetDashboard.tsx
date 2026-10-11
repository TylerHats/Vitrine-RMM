import React, { useState } from 'react';
import {
  Monitor,
  EyeOff,
  Terminal,
  KeyRound,
  ShieldAlert,
  ShieldCheck,
  RotateCcw,
  Cpu,
  HardDrive,
  CheckCircle,
  AlertTriangle,
  Clock,
  Layers,
  Sparkles
} from 'lucide-react';
import { Device } from '../types/index.js';

interface FleetDashboardProps {
  devices: Device[];
  searchQuery: string;
  selectedTenantId: string;
  onOpenRemote: (device: Device, isGhost: boolean) => void;
  onOpenBgTools: (device: Device, initialTab?: string) => void;
  onOpenLaps: (device: Device) => void;
  onOpenQuarantine: (device: Device) => void;
  onSelectDevice: (device: Device) => void;
}

export const FleetDashboard: React.FC<FleetDashboardProps> = ({
  devices,
  searchQuery,
  selectedTenantId,
  onOpenRemote,
  onOpenBgTools,
  onOpenLaps,
  onOpenQuarantine,
  onSelectDevice
}) => {
  const [smartGroup, setSmartGroup] = useState('all');

  // Filter devices based on tenant, search, and dynamic smart groups
  const filteredDevices = devices.filter((d) => {
    // Tenant filter
    if (selectedTenantId !== 'all' && d.tenant_id !== selectedTenantId) {
      return false;
    }

    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match =
        d.hostname.toLowerCase().includes(q) ||
        d.ip_address.toLowerCase().includes(q) ||
        d.os_version.toLowerCase().includes(q) ||
        d.device_role.toLowerCase().includes(q) ||
        d.serial_number.toLowerCase().includes(q) ||
        (d.tenant_name && d.tenant_name.toLowerCase().includes(q));
      if (!match) return false;
    }

    // Dynamic Smart Groups (Feature 27)
    if (smartGroup === 'pending_reboot') return d.pending_reboot === 1;
    if (smartGroup === 'isolated') return d.quarantined === 1;
    if (smartGroup === 'unencrypted') return !d.bitlocker_status.includes('Encrypted');
    if (smartGroup === 'multi_os') return d.os_type === 'linux' || d.os_type === 'macos';
    if (smartGroup === 'servers') return d.device_role.toLowerCase().includes('server') || d.device_role.toLowerCase().includes('controller') || d.device_role.toLowerCase().includes('hypervisor');

    return true;
  });

  // Aggregate metrics
  const totalCount = devices.length;
  const onlineCount = devices.filter((d) => d.status === 'online').length;
  const rebootCount = devices.filter((d) => d.pending_reboot === 1).length;
  const isolatedCount = devices.filter((d) => d.quarantined === 1).length;
  const bitlockerCount = devices.filter((d) => d.bitlocker_status.includes('Encrypted')).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="fleet-dashboard-view">
      {/* Metrics Row */}
      <div className="metrics-grid">
        <div className="glass-card">
          <div className="metric-header">
            <span className="metric-title">TOTAL ENDPOINTS</span>
            <div className="metric-icon-wrap"><Cpu size={18} /></div>
          </div>
          <div className="metric-value">{totalCount}</div>
          <div className="metric-subtext">{onlineCount} actively connected to MeshCentral</div>
        </div>

        <div className="glass-card">
          <div className="metric-header">
            <span className="metric-title">ONLINE AVAILABILITY</span>
            <div className="metric-icon-wrap" style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#10b981', borderColor: 'rgba(16, 185, 129, 0.25)' }}>
              <CheckCircle size={18} />
            </div>
          </div>
          <div className="metric-value" style={{ color: '#34d399' }}>
            {((onlineCount / (totalCount || 1)) * 100).toFixed(0)}%
          </div>
          <div className="metric-subtext">Telemetry rate: 10s - 30s interval</div>
        </div>

        <div className="glass-card">
          <div className="metric-header">
            <span className="metric-title">PENDING REBOOTS</span>
            <div className="metric-icon-wrap" style={{ background: 'rgba(245, 158, 11, 0.1)', color: '#f59e0b', borderColor: 'rgba(245, 158, 11, 0.25)' }}>
              <RotateCcw size={18} />
            </div>
          </div>
          <div className="metric-value" style={{ color: '#fbbf24' }}>{rebootCount}</div>
          <div className="metric-subtext">CBS &amp; Windows Update flags detected</div>
        </div>

        <div className="glass-card">
          <div className="metric-header">
            <span className="metric-title">CYBER ISOLATED</span>
            <div className="metric-icon-wrap" style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', borderColor: 'rgba(239, 68, 68, 0.25)' }}>
              <ShieldAlert size={18} />
            </div>
          </div>
          <div className="metric-value" style={{ color: isolatedCount > 0 ? '#f87171' : 'var(--text-main)' }}>
            {isolatedCount}
          </div>
          <div className="metric-subtext">Quarantined endpoints with RMM tunnel</div>
        </div>

        <div className="glass-card">
          <div className="metric-header">
            <span className="metric-title">DISK ENCRYPTION</span>
            <div className="metric-icon-wrap" style={{ background: 'rgba(0, 242, 254, 0.1)', color: 'var(--primary)', borderColor: 'rgba(0, 242, 254, 0.2)' }}>
              <HardDrive size={18} />
            </div>
          </div>
          <div className="metric-value">{bitlockerCount} / {totalCount}</div>
          <div className="metric-subtext">BitLocker / LUKS / FileVault Escrowed</div>
        </div>
      </div>

      {/* Dynamic Smart Device Groups (Feature 27) */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
        <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)', marginRight: '0.35rem' }}>
          SMART GROUPS:
        </span>
        {[
          { id: 'all', label: 'All Fleet Devices' },
          { id: 'servers', label: 'Servers & Hypervisors' },
          { id: 'pending_reboot', label: '⚠️ Pending Reboot' },
          { id: 'isolated', label: '🛡️ Cyber Isolated' },
          { id: 'unencrypted', label: '🔓 Missing BitLocker' },
          { id: 'multi_os', label: '🐧 Linux & macOS Parity' }
        ].map((g) => (
          <button
            key={g.id}
            className={`btn-glass ${smartGroup === g.id ? 'btn-primary' : ''}`}
            style={{ padding: '0.35rem 0.85rem', fontSize: '0.8rem' }}
            onClick={() => setSmartGroup(g.id)}
            id={`smart-group-${g.id}`}
          >
            {g.label}
          </button>
        ))}
      </div>

      {/* Fleet Table */}
      <div className="glass-card" style={{ padding: 0 }}>
        <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--glass-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h3 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.15rem', fontWeight: 600 }}>
              Managed Fleet Inventory
            </h3>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Showing {filteredDevices.length} endpoints matching current policy scope
            </span>
          </div>
        </div>

        <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
          <table className="glass-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Endpoint / Role</th>
                <th>Client / Site</th>
                <th>Operating System</th>
                <th>CPU &amp; RAM Load</th>
                <th>Security &amp; Health</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredDevices.map((d) => (
                <tr key={d.id} id={`device-row-${d.id}`}>
                  <td>
                    <span
                      className={`status-pill ${
                        d.quarantined
                          ? 'status-isolated'
                          : d.pending_reboot
                          ? 'status-reboot'
                          : d.status === 'online'
                          ? 'status-online'
                          : 'status-offline'
                      }`}
                    >
                      <div className="pulse-dot" />
                      {d.quarantined ? 'Isolated' : d.pending_reboot ? 'Reboot Req' : d.status}
                    </span>
                  </td>

                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                      <span
                        style={{ fontWeight: 600, color: 'var(--text-main)', cursor: 'pointer' }}
                        onClick={() => onSelectDevice(d)}
                        className="hover-underline"
                      >
                        {d.hostname}
                      </span>
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                        {d.device_role} • {d.ip_address}
                      </span>
                    </div>
                  </td>

                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                      <span style={{ fontSize: '0.82rem', fontWeight: 500 }}>{d.tenant_name || 'Apex Financial'}</span>
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>{d.site_name || 'Main Office'}</span>
                    </div>
                  </td>

                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                      <span style={{ fontSize: '0.82rem' }}>{d.os_version}</span>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>{d.os_build}</span>
                    </div>
                  </td>

                  <td style={{ minWidth: '150px' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem' }}>
                        <span>CPU: {d.cpu_usage.toFixed(1)}%</span>
                        <span>RAM: {d.ram_used_gb.toFixed(1)}/{d.ram_total_gb}GB</span>
                      </div>
                      <div style={{ width: '100%', height: '5px', background: 'rgba(255, 255, 255, 0.1)', borderRadius: '3px', overflow: 'hidden' }}>
                        <div
                          style={{
                            width: `${Math.min(100, d.cpu_usage)}%`,
                            height: '100%',
                            background: d.cpu_usage > 80 ? '#ef4444' : 'var(--primary)'
                          }}
                        />
                      </div>
                    </div>
                  </td>

                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                      <span style={{ fontSize: '0.75rem', color: '#10b981', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                        <ShieldCheck size={12} /> {d.edr_name ? 'EDR Active' : 'Defender Active'}
                      </span>
                      <span style={{ fontSize: '0.7rem', color: d.bitlocker_status.includes('Encrypted') ? '#38bdf8' : '#f59e0b' }}>
                        🔒 {d.bitlocker_status.includes('Encrypted') ? 'BitLocker Escrowed' : 'Unencrypted'}
                      </span>
                    </div>
                  </td>

                  <td style={{ textAlign: 'right' }}>
                    <div className="action-group" style={{ justifyContent: 'flex-end' }}>
                      {/* Feature 7: Interactive Screen Control */}
                      <button
                        className="btn-glass btn-icon"
                        title="Low-Latency Screen Control (KVM)"
                        onClick={() => onOpenRemote(d, false)}
                        id={`btn-remote-${d.id}`}
                      >
                        <Monitor size={15} color="#00f2fe" />
                      </button>

                      {/* Feature 8: Ghost Session (Headless / Background Remote Desktop) */}
                      <button
                        className="btn-glass btn-icon"
                        title="Ghost Session (Headless Remote Desktop)"
                        onClick={() => onOpenRemote(d, true)}
                        id={`btn-ghost-${d.id}`}
                      >
                        <EyeOff size={15} color="#c084fc" />
                      </button>

                      {/* Feature 11-15: Background Management Suite */}
                      <button
                        className="btn-glass btn-icon"
                        title="Silent Background Suite (Shell, Task Manager, Services, Registry, Files)"
                        onClick={() => onOpenBgTools(d, 'terminal')}
                        id={`btn-bg-tools-${d.id}`}
                      >
                        <Terminal size={15} />
                      </button>

                      {/* Feature 32: LAPS Vault */}
                      <button
                        className="btn-glass btn-icon"
                        title="Automated LAPS Vault (Local Admin Password)"
                        onClick={() => onOpenLaps(d)}
                        id={`btn-laps-${d.id}`}
                      >
                        <KeyRound size={15} color="#fbbf24" />
                      </button>

                      {/* Feature 31: Cyber Isolation */}
                      <button
                        className={`btn-glass btn-icon ${d.quarantined ? 'btn-danger' : ''}`}
                        title={d.quarantined ? 'Isolated: Click to restore network' : 'One-Click Cyber Isolation'}
                        onClick={() => onOpenQuarantine(d)}
                        id={`btn-quarantine-${d.id}`}
                      >
                        <ShieldAlert size={15} color={d.quarantined ? '#ef4444' : '#94a3b8'} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
