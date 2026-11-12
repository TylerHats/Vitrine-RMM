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
  X,
  Archive,
  Zap,
  FileSpreadsheet
} from 'lucide-react';
import { Device, SmartGroup, BreakGlassRecoveryEntry, AuthUser } from '../types/index.js';
import {
  fetchSmartGroups,
  createSmartGroup,
  deleteSmartGroup,
  scanPatches,
  forceArchiveDevice,
  simulateDeviceCheckin,
  purgeArchivedDevice,
  exportBreakGlassSheet,
  seedDemoLabData
} from '../services/api.js';
import { MfaChallengeModal } from '../components/MfaChallengeModal.js';

function sanitizeCsvCell(val: unknown): string {
  const raw = String(val ?? '');
  const safe = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
  return `"${safe.replace(/"/g, '""')}"`;
}

interface FleetDashboardProps {
  devices: Device[];
  searchQuery: string;
  selectedTenantId: string;
  onOpenRemote: (device: Device, isGhost: boolean) => void;
  onOpenBgTools: (device: Device, initialTab?: string) => void;
  onOpenLaps: (device: Device) => void;
  onOpenQuarantine: (device: Device) => void;
  onSelectDevice: (device: Device) => void;
  onOpenInstaller?: () => void;
  onOpenOnboarding?: () => void;
  onRefreshFleet?: () => void;
  currentUser?: AuthUser | null;
}

export const FleetDashboard: React.FC<FleetDashboardProps> = ({
  devices,
  searchQuery,
  selectedTenantId,
  onOpenRemote,
  onOpenBgTools,
  onOpenLaps,
  onOpenQuarantine,
  onSelectDevice,
  onOpenInstaller,
  onOpenOnboarding,
  onRefreshFleet,
  currentUser
}) => {
  const [smartGroup, setSmartGroup] = useState('all');
  const [lifecycleView, setLifecycleView] = useState<'active' | 'pending_offboard' | 'archived'>('active');
  const [customGroups, setCustomGroups] = useState<SmartGroup[]>([]);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [showNewGroupModal, setShowNewGroupModal] = useState(false);
  const [newGroupName, setNewGroupName] = useState('');
  const [newGroupRule, setNewGroupRule] = useState('cpu_usage > 70');
  const [newGroupDesc, setNewGroupDesc] = useState('');
  const [bulkStatusMsg, setBulkStatusMsg] = useState<string | null>(null);
  const [localDevices, setLocalDevices] = useState<Device[]>(devices);
  const [showBreakGlassMfa, setShowBreakGlassMfa] = useState(false);
  const [breakGlassRows, setBreakGlassRows] = useState<BreakGlassRecoveryEntry[] | null>(null);

  useEffect(() => {
    setLocalDevices(devices);
  }, [devices]);

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

  const activeLifecycleCount = localDevices.filter((d) => (d.lifecycle_state || 'active') === 'active').length;
  const pendingOffboardCount = localDevices.filter((d) => d.lifecycle_state === 'pending_offboard').length;
  const archivedVaultCount = localDevices.filter((d) => d.lifecycle_state === 'archived').length;

  // Filter devices based on lifecycle, tenant, search, and dynamic smart groups
  const filteredDevices = localDevices.filter((d) => {
    const state = d.lifecycle_state || 'active';
    if (state !== lifecycleView) return false;

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

  // Aggregate metrics (Active Fleet + Archive awareness)
  const activeDevices = localDevices.filter((d) => (d.lifecycle_state || 'active') === 'active');
  const totalCount = activeDevices.length;
  const onlineCount = activeDevices.filter((d) => d.status === 'online').length;
  const rebootCount = activeDevices.filter((d) => d.pending_reboot === 1).length;
  const isolatedCount = activeDevices.filter((d) => d.quarantined === 1).length;
  const bitlockerCount = localDevices.filter((d) => d.bitlocker_status.includes('Encrypted')).length;

  const handleForceArchive = async (d: Device) => {
    const res = await forceArchiveDevice(d.id);
    if (res.success) {
      setLocalDevices((prev) =>
        prev.map((item) => (item.id === d.id ? { ...item, lifecycle_state: 'archived', status: 'offline' } : item))
      );
      setBulkStatusMsg(res.message);
      setTimeout(() => setBulkStatusMsg(null), 5000);
    }
  };

  const handleSimulateWakeCheckIn = async (d: Device) => {
    const res = await simulateDeviceCheckin(d.id);
    if (res.success) {
      if (res.actionTaken === 'resurrected_from_archive') {
        setLocalDevices((prev) =>
          prev.map((item) => (item.id === d.id ? { ...item, lifecycle_state: 'active', status: 'online' } : item))
        );
      } else if (res.actionTaken === 'queued_offboard_completed_to_archive' || res.actionTaken === 'quiet_offboard_executed') {
        setLocalDevices((prev) =>
          prev.map((item) => (item.id === d.id ? { ...item, lifecycle_state: 'archived', status: 'offline' } : item))
        );
      }
      setBulkStatusMsg(`${d.hostname}: ${res.message}`);
      setTimeout(() => setBulkStatusMsg(null), 6500);
    }
  };

  const handlePurgeArchived = async (d: Device) => {
    if (!confirm(`Permanently purge ${d.hostname} from the Data Archive Vault? Its BitLocker recovery key and LAPS password history will be irreversibly deleted.`)) {
      return;
    }
    const res = await purgeArchivedDevice(d.id);
    if (res.success) {
      setLocalDevices((prev) => prev.filter((item) => item.id !== d.id));
      setBulkStatusMsg(`Permanently purged ${d.hostname} from the Data Archive Vault.`);
      setTimeout(() => setBulkStatusMsg(null), 5000);
    }
  };

  const handleBreakGlassExportSuccess = async () => {
    const res = await exportBreakGlassSheet({
      tenantId: selectedTenantId === 'all' ? undefined : selectedTenantId,
      includeArchived: true
    });
    if (res.entries) {
      setBreakGlassRows(res.entries);
    }
  };

  const downloadBreakGlassCsv = () => {
    if (!breakGlassRows) return;
    const headers = [
      'Hostname',
      'Client',
      'Site',
      'Lifecycle State',
      'Serial Number',
      'LAPS Admin Account',
      'Current LAPS Password',
      'Previous LAPS Account',
      'Previous (N-1) LAPS Password',
      'SID -500 Built-in Admin Disabled',
      'BitLocker Status',
      'BitLocker Recovery Key'
    ];
    const rows = breakGlassRows.map((r) => [
      r.hostname,
      r.tenantName,
      r.siteName,
      r.lifecycleState,
      r.serialNumber,
      r.lapsAccountName,
      r.currentLapsPassword,
      r.previousLapsAccountName || '',
      r.previousLapsPassword || '',
      r.sid500BuiltinDisabled ? 'Yes' : 'No',
      r.bitlockerStatus,
      r.bitlockerRecoveryKey
    ]);
    const csvContent = [headers, ...rows]
      .map((row) => row.map((v) => sanitizeCsvCell(v)).join(','))
      .join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `vitrine-break-glass-laps-bitlocker-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

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
      d.tenant_name || 'Unassigned',
      d.site_name || 'Default Site',
      d.ip_address,
      d.os_version,
      d.status,
      d.cpu_usage.toFixed(1),
      d.ram_used_gb.toFixed(1),
      d.bitlocker_status
    ]);
    const csvContent = [headers, ...rows].map((row) => row.map((v) => sanitizeCsvCell(v)).join(',')).join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `vitrine-fleet-export-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleBulkPatchScan = async () => {
    const res = await scanPatches(selectedIds.length > 0 ? selectedIds : undefined);
    setBulkStatusMsg(`Patch scan completed across ${selectedIds.length || filteredDevices.length} endpoints (${res.patches?.length || 0} updates indexed).`);
    setTimeout(() => setBulkStatusMsg(null), 4000);
  };

  const handleSeedDemoLab = async () => {
    const res = await seedDemoLabData();
    if (res.success) {
      setBulkStatusMsg('Evaluation lab dataset seeded. Refreshing fleet inventory...');
      onRefreshFleet?.();
      setTimeout(() => setBulkStatusMsg(null), 4000);
    }
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
          <div className="metric-value">{bitlockerCount} / {localDevices.length}</div>
          <div className="metric-subtext">BitLocker / LUKS / FileVault Escrowed (Incl. Archive)</div>
        </div>
      </div>

      {/* Lifecycle Category Switcher (Active Fleet vs. Pending Offboard Queue vs. Data Archive Vault) */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem', padding: '0.85rem 1.1rem', borderRadius: '10px', background: 'var(--glass-bg)', border: '1px solid var(--glass-border)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-dim)', marginRight: '0.25rem' }}>
            LIFECYCLE VIEW:
          </span>
          <button
            className={`btn-glass ${lifecycleView === 'active' ? 'btn-primary' : ''}`}
            style={{ fontSize: '0.8rem', padding: '0.35rem 0.85rem' }}
            onClick={() => setLifecycleView('active')}
          >
            Active Fleet ({activeLifecycleCount})
          </button>
          <button
            className={`btn-glass ${lifecycleView === 'pending_offboard' ? 'btn-primary' : ''}`}
            style={{
              fontSize: '0.8rem',
              padding: '0.35rem 0.85rem',
              borderColor: pendingOffboardCount > 0 ? 'rgba(245, 158, 11, 0.45)' : undefined,
              color: lifecycleView === 'pending_offboard' ? '#fff' : pendingOffboardCount > 0 ? '#fbbf24' : undefined
            }}
            onClick={() => setLifecycleView('pending_offboard')}
          >
            ⏳ Pending Offboard Queue ({pendingOffboardCount})
          </button>
          <button
            className={`btn-glass ${lifecycleView === 'archived' ? 'btn-primary' : ''}`}
            style={{ fontSize: '0.8rem', padding: '0.35rem 0.85rem' }}
            onClick={() => setLifecycleView('archived')}
          >
            <Archive size={13} /> Data Archive Vault ({archivedVaultCount} — BitLocker &amp; LAPS Preserved)
          </button>
        </div>

        <button
          className="btn-glass"
          style={{ fontSize: '0.78rem', padding: '0.4rem 0.85rem', borderColor: 'rgba(245, 158, 11, 0.45)', color: '#fbbf24' }}
          onClick={() => setShowBreakGlassMfa(true)}
          title="Step-Up MFA-gated emergency offline Break-Glass export containing current + N-1 LAPS passwords and BitLocker recovery keys across Active & Archived endpoints"
        >
          <FileSpreadsheet size={14} /> Export Break-Glass Sheet (LAPS + BitLocker)
        </button>
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
                        d.lifecycle_state === 'archived'
                          ? 'status-offline'
                          : d.lifecycle_state === 'pending_offboard'
                          ? 'status-reboot'
                          : d.quarantined
                          ? 'status-isolated'
                          : d.pending_reboot
                          ? 'status-reboot'
                          : d.status === 'online'
                          ? 'status-online'
                          : 'status-offline'
                      }`}
                    >
                      <div className="pulse-dot" />
                      {d.lifecycle_state === 'archived'
                        ? 'Archived Vault'
                        : d.lifecycle_state === 'pending_offboard'
                        ? 'Pending Offboard'
                        : d.quarantined
                        ? 'Isolated'
                        : d.pending_reboot
                        ? 'Reboot Req'
                        : d.status}
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
                        {d.offboard_reason ? ` • ${d.offboard_reason}` : ''}
                      </span>
                    </div>
                  </td>

                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                      <span style={{ fontSize: '0.82rem', fontWeight: 500 }}>{d.tenant_name || 'Unassigned'}</span>
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>{d.site_name || 'Default Site'}</span>
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
                      <div style={{ width: '100%', height: '5px', background: 'rgba(148, 163, 184, 0.22)', borderRadius: '3px', overflow: 'hidden' }}>
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
                      <span
                        style={{
                          fontSize: '0.75rem',
                          color: d.edr_status === 'Active' ? '#10b981' : '#f59e0b',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.35rem'
                        }}
                      >
                        <ShieldCheck size={12} /> {d.edr_status === 'Active' ? d.edr_name || 'EDR Active' : d.edr_status || 'Unmonitored'}
                      </span>
                      <span style={{ fontSize: '0.7rem', color: d.has_bitlocker_key || d.bitlocker_status.includes('Encrypted') ? '#38bdf8' : '#f59e0b' }}>
                        🔒 {d.has_bitlocker_key || d.bitlocker_status.includes('Encrypted') ? 'BitLocker Escrowed' : 'Unencrypted'}
                      </span>
                    </div>
                  </td>

                  <td style={{ textAlign: 'right' }}>
                    <div className="action-group" style={{ justifyContent: 'flex-end' }}>
                      {d.lifecycle_state === 'pending_offboard' && (
                        <button
                          className="btn-glass"
                          style={{ padding: '0.25rem 0.55rem', fontSize: '0.72rem', borderColor: 'rgba(245, 158, 11, 0.45)', color: '#fbbf24' }}
                          title="Force move this offline pending-offboard endpoint directly into the Data Archive Vault now"
                          onClick={() => handleForceArchive(d)}
                        >
                          <Archive size={13} /> Force Archive
                        </button>
                      )}

                      {(d.lifecycle_state === 'pending_offboard' || d.lifecycle_state === 'archived') && (
                        <button
                          className="btn-glass"
                          style={{ padding: '0.25rem 0.55rem', fontSize: '0.72rem', borderColor: 'rgba(56, 189, 248, 0.45)', color: '#38bdf8' }}
                          title="Simulate this endpoint waking up or re-installing: resurrects to Active if Archived & parent client is Active; executes queued/quiet offboard if Pending Offboard or parent client is Archived/Deleted"
                          onClick={() => handleSimulateWakeCheckIn(d)}
                        >
                          <Zap size={13} /> Simulate Wake / Check-In
                        </button>
                      )}

                      {d.lifecycle_state === 'archived' && (
                        <button
                          className="btn-glass btn-icon"
                          title="Explicitly & permanently purge this archived endpoint (deletes preserved BitLocker & LAPS keys)"
                          onClick={() => handlePurgeArchived(d)}
                        >
                          <Trash2 size={14} color="#ef4444" />
                        </button>
                      )}

                      {/* Feature 7: Interactive Screen Control */}
                      {(!d.lifecycle_state || d.lifecycle_state === 'active') && (
                        <>
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
                        </>
                      )}

                      {/* Feature 32: LAPS Vault (Available on Active AND Archived endpoints!) */}
                      <button
                        className="btn-glass btn-icon"
                        title="Automated LAPS Vault (Local Admin Password & Historical Archive)"
                        onClick={() => onOpenLaps(d)}
                        id={`btn-laps-${d.id}`}
                      >
                        <KeyRound size={15} color="#fbbf24" />
                      </button>

                      {/* Feature 31: Cyber Isolation */}
                      {(!d.lifecycle_state || d.lifecycle_state === 'active') && (
                        <button
                          className={`btn-glass btn-icon ${d.quarantined ? 'btn-danger' : ''}`}
                          title={d.quarantined ? 'Isolated: Click to restore network' : 'One-Click Cyber Isolation'}
                          onClick={() => onOpenQuarantine(d)}
                          id={`btn-quarantine-${d.id}`}
                        >
                          <ShieldAlert size={15} color={d.quarantined ? '#ef4444' : '#94a3b8'} />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {filteredDevices.length === 0 && (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: '3rem 1.5rem' }}>
                    {localDevices.length === 0 ? (
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.85rem' }}>
                        <div style={{ fontWeight: 700, fontSize: '1rem' }}>No Endpoints Enrolled Yet</div>
                        <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', maxWidth: '520px' }}>
                          Your Vitrine control plane starts clean with zero fake demo clients. Provision a signed agent installer, import existing device groups from MeshCentral 2, or load the optional evaluation lab dataset.
                        </div>
                        <div style={{ display: 'flex', gap: '0.65rem', flexWrap: 'wrap', justifyContent: 'center', marginTop: '0.35rem' }}>
                          {onOpenInstaller && (
                            <button className="btn-glass btn-primary" onClick={onOpenInstaller}>
                              <Download size={14} /> Provision Signed Agent
                            </button>
                          )}
                          {onOpenOnboarding && currentUser?.role === 'super_admin' && (
                            <button className="btn-glass" onClick={onOpenOnboarding}>
                              Import from MeshCentral 2
                            </button>
                          )}
                          {currentUser?.role === 'super_admin' && (
                            <button className="btn-glass" onClick={handleSeedDemoLab}>
                              Load Lab Demo Dataset
                            </button>
                          )}
                        </div>
                      </div>
                    ) : (
                      <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                        No endpoints match the selected lifecycle state or filter criteria.
                      </span>
                    )}
                  </td>
                </tr>
              )}
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

      {/* Step-Up MFA Challenge for Emergency Break-Glass Sheet Export */}
      <MfaChallengeModal
        isOpen={showBreakGlassMfa}
        onClose={() => setShowBreakGlassMfa(false)}
        onSuccess={handleBreakGlassExportSuccess}
        title="Step-Up MFA: Emergency Break-Glass LAPS & BitLocker Export"
        description="Enter your 6-digit authenticator code to export all current + N-1 historical LAPS passwords and BitLocker recovery keys (including Archived endpoints)."
        secretType="laps_credential"
        deviceId="fleet-break-glass"
      />

      {/* Emergency Break-Glass Sheet Modal */}
      {breakGlassRows && (
        <div className="modal-backdrop" onClick={() => setBreakGlassRows(null)}>
          <div className="glass-modal" style={{ maxWidth: '940px' }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title" style={{ color: '#fbbf24' }}>
                <FileSpreadsheet size={20} color="#fbbf24" />
                <span>Emergency Break-Glass Recovery Sheet (LAPS + BitLocker Escrowed Keys)</span>
              </div>
              <button className="btn-glass btn-icon" onClick={() => setBreakGlassRows(null)}>
                <X size={18} />
              </button>
            </div>
            <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Includes both <strong>Active</strong> and <strong>Archived Vault</strong> endpoints so you never lose a BitLocker recovery key or LAPS password months after offboarding a machine.
              </div>
              <div className="table-wrapper" style={{ maxHeight: '360px', overflowY: 'auto' }}>
                <table className="glass-table">
                  <thead>
                    <tr>
                      <th>Hostname / State</th>
                      <th>Client / Site</th>
                      <th>LAPS Admin Account</th>
                      <th>Current Password</th>
                      <th>N-1 Previous Password</th>
                      <th>BitLocker Recovery Key</th>
                    </tr>
                  </thead>
                  <tbody>
                    {breakGlassRows.map((r) => (
                      <tr key={r.deviceId}>
                        <td>
                          <div style={{ fontWeight: 600, fontSize: '0.8rem' }}>{r.hostname}</div>
                          <span className={`status-pill ${r.lifecycleState === 'archived' ? 'status-offline' : 'status-online'}`} style={{ fontSize: '0.65rem' }}>
                            {r.lifecycleState}
                          </span>
                        </td>
                        <td style={{ fontSize: '0.76rem' }}>
                          <div>{r.tenantName}</div>
                          <div style={{ color: 'var(--text-dim)', fontSize: '0.68rem' }}>{r.siteName}</div>
                        </td>
                        <td style={{ fontSize: '0.78rem' }}>
                          <code>{r.lapsAccountName}</code>
                          {r.previousLapsAccountName && r.previousLapsAccountName !== r.lapsAccountName && (
                            <div style={{ fontSize: '0.68rem', color: '#38bdf8' }}>Prev: {r.previousLapsAccountName}</div>
                          )}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.76rem', color: '#34d399' }}>{r.currentLapsPassword}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.74rem', color: 'var(--text-muted)' }}>{r.previousLapsPassword || '—'}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.74rem', color: '#38bdf8' }}>{r.bitlockerRecoveryKey}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            <div className="modal-footer" style={{ display: 'flex', justifyContent: 'space-between' }}>
              <button className="btn-glass" onClick={downloadBreakGlassCsv}>
                <Download size={14} /> Download Encrypted-Ready CSV Sheet
              </button>
              <button className="btn-glass btn-primary" onClick={() => setBreakGlassRows(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
