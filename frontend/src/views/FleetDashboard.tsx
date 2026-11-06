import React, { useState, useEffect } from 'react';
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
  Plus,
  Download,
  RefreshCw,
  Trash2,
  X
} from 'lucide-react';
import { Device, SmartGroup } from '../types/index.js';
import { fetchSmartGroups, createSmartGroup, deleteSmartGroup, scanPatches } from '../services/api.js';

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
  const [customGroups, setCustomGroups] = useState<SmartGroup[]>([]);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [showNewGroupModal, setShowNewGroupModal] = useState(false);
  const [newGroupName, setNewGroupName] = useState('');
  const [newGroupRule, setNewGroupRule] = useState('cpu_usage > 70');
  const [newGroupDesc, setNewGroupDesc] = useState('');
  const [bulkStatusMsg, setBulkStatusMsg] = useState<string | null>(null);

  useEffect(() => {
    fetchSmartGroups()
      .then(setCustomGroups)
      .catch(() => {});
  }, []);

  const evaluateCustomRule = (d: Device, rule: string): boolean => {
    const r = rule.toLowerCase();
    if (r.includes('pending_reboot = 1')) return d.pending_reboot === 1;
    if (r.includes('edr_status != active')) return d.edr_status !== 'Active';
    if (r.includes('bitlocker_status not like')) return !d.bitlocker_status.includes('Encrypted');
    if (r.includes('os_type in')) return d.os_type === 'linux' || d.os_type === 'macos';
    const cpuMatch = r.match(/cpu_usage\s*>\s*(\d+)/);
    if (cpuMatch) return d.cpu_usage > Number(cpuMatch[1]);
    return (
      d.hostname.toLowerCase().includes(r) ||
      d.device_role.toLowerCase().includes(r) ||
      d.os_version.toLowerCase().includes(r)
    );
  };

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
    if (smartGroup === 'servers') {
      return (
        d.device_role.toLowerCase().includes('server') ||
        d.device_role.toLowerCase().includes('controller') ||
        d.device_role.toLowerCase().includes('hypervisor')
      );
    }

    const customGrp = customGroups.find((cg) => cg.id === smartGroup);
    if (customGrp) {
      return evaluateCustomRule(d, customGrp.criteria_json || '');
    }

    return true;
  });

  // Aggregate metrics
  const totalCount = devices.length;
  const onlineCount = devices.filter((d) => d.status === 'online').length;
  const rebootCount = devices.filter((d) => d.pending_reboot === 1).length;
  const isolatedCount = devices.filter((d) => d.quarantined === 1).length;
  const bitlockerCount = devices.filter((d) => d.bitlocker_status.includes('Encrypted')).length;

  const toggleSelectAll = () => {
    if (selectedIds.length === filteredDevices.length && filteredDevices.length > 0) {
      setSelectedIds([]);
    } else {
      setSelectedIds(filteredDevices.map((d) => d.id));
    }
  };

  const toggleSelectRow = (id: string) => {
    setSelectedIds((prev) => (prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]));
  };

  const handleExportCsv = () => {
    const targetList =
      selectedIds.length > 0 ? filteredDevices.filter((d) => selectedIds.includes(d.id)) : filteredDevices;
    const headers = ['Hostname', 'Role', 'Tenant', 'Site', 'IP Address', 'OS', 'Status', 'CPU %', 'RAM Used GB', 'BitLocker'];
    const rows = targetList.map((d) => [
      d.hostname,
      d.device_role,
      d.tenant_name || 'Apex Financial',
      d.site_name || 'Main Office',
      d.ip_address,
      d.os_version,
      d.status,
      d.cpu_usage.toFixed(1),
      d.ram_used_gb.toFixed(1),
      d.bitlocker_status
    ]);
    const csvContent = [headers, ...rows].map((row) => row.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `vitrine-fleet-export-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleBulkPatchScan = async () => {
    const res = await scanPatches();
    setBulkStatusMsg(`Patch scan completed across ${selectedIds.length || filteredDevices.length} endpoints (${res.patches?.length || 0} updates indexed).`);
    setTimeout(() => setBulkStatusMsg(null), 4000);
  };

  const handleCreateSmartGroup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newGroupName.trim()) return;
    const res = await createSmartGroup({
      name: newGroupName.trim(),
      criteria_json: newGroupRule.trim(),
      description: newGroupDesc.trim() || `Dynamic query: ${newGroupRule.trim()}`
    });
    if (res.success && res.id) {
      const updated = await fetchSmartGroups();
      setCustomGroups(updated);
      setSmartGroup(res.id);
      setShowNewGroupModal(false);
      setNewGroupName('');
      setNewGroupDesc('');
    }
  };

  const handleDeleteCustomGroup = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    await deleteSmartGroup(id);
    setCustomGroups((prev) => prev.filter((g) => g.id !== id));
    if (smartGroup === id) setSmartGroup('all');
  };

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

        {customGroups.map((cg) => (
          <button
            key={cg.id}
            className={`btn-glass ${smartGroup === cg.id ? 'btn-primary' : ''}`}
            style={{ padding: '0.35rem 0.75rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
            onClick={() => setSmartGroup(cg.id)}
            title={`${cg.description || ''} (${cg.criteria_json})`}
          >
            <span>⚡ {cg.name}</span>
            <Trash2
              size={12}
              style={{ opacity: 0.7 }}
              onClick={(e) => handleDeleteCustomGroup(cg.id, e)}
            />
          </button>
        ))}

        <button
          className="btn-glass"
          style={{ padding: '0.35rem 0.75rem', fontSize: '0.78rem', borderStyle: 'dashed' }}
          onClick={() => setShowNewGroupModal(true)}
        >
          <Plus size={13} /> New Smart Group
        </button>
      </div>

      {bulkStatusMsg && (
        <div
          className="glass-card"
          style={{
            padding: '0.75rem 1.25rem',
            background: 'rgba(16, 185, 129, 0.12)',
            borderColor: 'rgba(16, 185, 129, 0.35)',
            color: '#34d399',
            fontSize: '0.85rem',
            fontWeight: 500
          }}
        >
          ✓ {bulkStatusMsg}
        </div>
      )}

      {/* Fleet Table */}
      <div className="glass-card" style={{ padding: 0 }}>
        <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--glass-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div>
            <h3 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.15rem', fontWeight: 600 }}>
              Managed Fleet Inventory
            </h3>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Showing {filteredDevices.length} endpoints matching current policy scope
              {selectedIds.length > 0 && ` • ${selectedIds.length} selected`}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            {selectedIds.length > 0 && (
              <button
                className="btn-glass btn-primary"
                style={{ fontSize: '0.78rem', padding: '0.4rem 0.85rem' }}
                onClick={handleBulkPatchScan}
              >
                <RefreshCw size={14} /> Scan Selected ({selectedIds.length})
              </button>
            )}
            <button
              className="btn-glass"
              style={{ fontSize: '0.78rem', padding: '0.4rem 0.85rem' }}
              onClick={handleExportCsv}
            >
              <Download size={14} /> Export CSV
            </button>
          </div>
        </div>

        <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
          <table className="glass-table">
            <thead>
              <tr>
                <th style={{ width: '36px' }}>
                  <input
                    type="checkbox"
                    checked={filteredDevices.length > 0 && selectedIds.length === filteredDevices.length}
                    onChange={toggleSelectAll}
                  />
                </th>
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
                    <input
                      type="checkbox"
                      checked={selectedIds.includes(d.id)}
                      onChange={() => toggleSelectRow(d.id)}
                    />
                  </td>
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

      {/* Create Smart Group Modal */}
      {showNewGroupModal && (
        <div className="modal-overlay" onClick={() => setShowNewGroupModal(false)}>
          <div className="glass-modal" style={{ maxWidth: '480px', padding: '1.5rem' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>Create Dynamic Smart Group</h3>
              <button className="btn-glass btn-icon" onClick={() => setShowNewGroupModal(false)}>
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleCreateSmartGroup} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Smart Group Name
                </label>
                <input
                  type="text"
                  required
                  className="glass-input"
                  placeholder="e.g. High CPU Workstations"
                  value={newGroupName}
                  onChange={(e) => setNewGroupName(e.target.value)}
                />
              </div>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Filter Rule Expression
                </label>
                <select
                  className="glass-select"
                  value={newGroupRule}
                  onChange={(e) => setNewGroupRule(e.target.value)}
                >
                  <option value="cpu_usage > 70">cpu_usage &gt; 70 (High CPU Load)</option>
                  <option value="cpu_usage > 40">cpu_usage &gt; 40 (Elevated CPU Load)</option>
                  <option value="pending_reboot = 1">pending_reboot = 1 (Requires Reboot)</option>
                  <option value="edr_status != Active">edr_status != Active (Missing EDR)</option>
                  <option value="bitlocker_status NOT LIKE %Encrypted%">bitlocker_status NOT LIKE %Encrypted%</option>
                  <option value="os_type IN (linux, macos)">os_type IN (linux, macos)</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Description
                </label>
                <input
                  type="text"
                  className="glass-input"
                  placeholder="Optional description..."
                  value={newGroupDesc}
                  onChange={(e) => setNewGroupDesc(e.target.value)}
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button type="button" className="btn-glass" onClick={() => setShowNewGroupModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-glass btn-primary">
                  Save Smart Group
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
