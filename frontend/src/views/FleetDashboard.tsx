import React, { useMemo, useState } from 'react';
import {
  Cpu,
  CheckCircle,
  RotateCcw,
  ShieldAlert,
  HardDrive,
  Monitor,
  Server,
  Laptop,
  ArrowRight,
  Download,
  AlertTriangle,
  Wifi,
  Building2
} from 'lucide-react';
import { Device, Tenant, AuthUser, DevicesPresetFilter } from '../types/index.js';
import { seedDemoLabData } from '../services/api.js';
import { isSuperAdmin, canMutateFleet } from '../utils/permissions.js';

interface FleetDashboardProps {
  devices: Device[];
  tenants: Tenant[];
  selectedTenantId: string;
  onSelectDevice: (device: Device) => void;
  onNavigateDevices: (preset?: DevicesPresetFilter) => void;
  onOpenInstaller?: () => void;
  onOpenOnboarding?: () => void;
  onRefreshFleet?: () => void;
  currentUser?: AuthUser | null;
}

export const FleetDashboard: React.FC<FleetDashboardProps> = ({
  devices,
  tenants,
  selectedTenantId,
  onSelectDevice,
  onNavigateDevices,
  onOpenInstaller,
  onOpenOnboarding,
  onRefreshFleet,
  currentUser
}) => {
  const enableLabDemo = import.meta.env.VITE_ENABLE_LAB_DEMO === 'true';
  const canMutate = canMutateFleet(currentUser);
  const [statusBanner, setStatusBanner] = useState<string | null>(null);

  const tenantScopedDevices = useMemo(
    () => (selectedTenantId === 'all' ? devices : devices.filter((d) => d.tenant_id === selectedTenantId)),
    [devices, selectedTenantId]
  );

  const activeDevices = useMemo(
    () => tenantScopedDevices.filter((d) => (d.lifecycle_state || 'active') === 'active'),
    [tenantScopedDevices]
  );

  const totalCount = activeDevices.length;
  const onlineCount = activeDevices.filter((d) => d.status === 'online').length;
  const rebootCount = activeDevices.filter((d) => d.pending_reboot === 1).length;
  const isolatedCount = activeDevices.filter((d) => d.quarantined === 1).length;
  const bitlockerCount = tenantScopedDevices.filter((d) => d.bitlocker_status?.includes('Encrypted')).length;
  const wssCount = activeDevices.filter((d) => Boolean(d.ws_connected) || d.agent_transport === 'wss').length;

  const osBreakdown = useMemo(() => {
    const counts = { windows: 0, linux: 0, macos: 0 };
    for (const d of activeDevices) {
      if (d.os_type === 'linux') counts.linux++;
      else if (d.os_type === 'macos') counts.macos++;
      else counts.windows++;
    }
    return counts;
  }, [activeDevices]);

  const roleBreakdown = useMemo(() => {
    const map = new Map<string, number>();
    for (const d of activeDevices) {
      const role = d.device_role || 'Workstation';
      map.set(role, (map.get(role) || 0) + 1);
    }
    return Array.from(map.entries()).sort((a, b) => b[1] - a[1]);
  }, [activeDevices]);

  const attentionDevices = useMemo(() => {
    return activeDevices
      .map((d) => {
        const reasons: string[] = [];
        let weight = 0;
        if (d.quarantined === 1) {
          reasons.push('Cyber Isolated');
          weight += 100;
        }
        if (d.smart_status === 'Failing' || d.smart_status === 'Warning') {
          reasons.push(`SMART ${d.smart_status}`);
          weight += 80;
        }
        const isServer = /server|controller|hypervisor/i.test(d.device_role || '');
        if (d.status === 'offline' && isServer) {
          reasons.push('Offline Server');
          weight += 70;
        } else if (d.status === 'offline') {
          reasons.push('Offline');
          weight += 20;
        }
        if (d.pending_reboot === 1) {
          reasons.push('Reboot Pending');
          weight += 30;
        }
        if (!d.bitlocker_status?.includes('Encrypted') && !d.has_bitlocker_key) {
          reasons.push('Unencrypted');
          weight += 15;
        }
        return { device: d, reasons, weight };
      })
      .filter((item) => item.reasons.length > 0)
      .sort((a, b) => b.weight - a.weight)
      .slice(0, 8);
  }, [activeDevices]);

  const clientSummaries = useMemo(() => {
    const targetTenants = selectedTenantId === 'all' ? tenants : tenants.filter((t) => t.id === selectedTenantId);
    return targetTenants.map((t) => {
      const devs = devices.filter((d) => d.tenant_id === t.id && (d.lifecycle_state || 'active') === 'active');
      const online = devs.filter((d) => d.status === 'online').length;
      const alerts = devs.filter((d) => d.quarantined === 1 || d.pending_reboot === 1 || d.smart_status !== 'Healthy').length;
      return { tenant: t, total: devs.length, online, alerts };
    });
  }, [tenants, devices, selectedTenantId]);

  const handleSeedDemoLab = async () => {
    const res = await seedDemoLabData();
    if (res.success) {
      setStatusBanner('Evaluation lab dataset seeded. Refreshing fleet inventory...');
      onRefreshFleet?.();
      setTimeout(() => setStatusBanner(null), 4000);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }} id="fleet-dashboard-view">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>
            Fleet Overview Dashboard
          </h2>
          <span style={{ fontSize: '0.84rem', color: 'var(--text-muted)' }}>
            Real-time health metrics, OS &amp; role posture, and client availability summary
          </span>
        </div>
        <button className="btn-glass btn-primary" onClick={() => onNavigateDevices({})} id="dashboard-open-devices-btn">
          <Monitor size={15} /> Open All Devices ({totalCount}) <ArrowRight size={14} />
        </button>
      </div>

      {statusBanner && (
        <div className="glass-card" style={{ padding: '0.75rem 1.25rem', color: '#34d399', borderColor: 'rgba(16, 185, 129, 0.35)' }}>
          ✓ {statusBanner}
        </div>
      )}

      {/* Executive KPI Cards (Clickable to jump to Devices view with preset filter) */}
      <div className="metrics-grid">
        <div
          className="glass-card glass-card-interactive"
          style={{ cursor: 'pointer' }}
          onClick={() => onNavigateDevices({ status: 'all' })}
        >
          <div className="metric-header">
            <span className="metric-title">TOTAL ENDPOINTS</span>
            <div className="metric-icon-wrap"><Cpu size={18} /></div>
          </div>
          <div className="metric-value">{totalCount}</div>
          <div className="metric-subtext">{onlineCount} online • {wssCount} live WSS</div>
        </div>

        <div
          className="glass-card glass-card-interactive"
          style={{ cursor: 'pointer' }}
          onClick={() => onNavigateDevices({ status: 'online' })}
        >
          <div className="metric-header">
            <span className="metric-title">ONLINE AVAILABILITY</span>
            <div className="metric-icon-wrap" style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#10b981', borderColor: 'rgba(16, 185, 129, 0.25)' }}>
              <CheckCircle size={18} />
            </div>
          </div>
          <div className="metric-value" style={{ color: '#34d399' }}>
            {((onlineCount / (totalCount || 1)) * 100).toFixed(0)}%
          </div>
          <div className="metric-subtext">Click to view online endpoints</div>
        </div>

        <div
          className="glass-card glass-card-interactive"
          style={{ cursor: 'pointer' }}
          onClick={() => onNavigateDevices({ status: 'reboot_pending' })}
        >
          <div className="metric-header">
            <span className="metric-title">PENDING REBOOTS</span>
            <div className="metric-icon-wrap" style={{ background: 'rgba(245, 158, 11, 0.1)', color: '#f59e0b', borderColor: 'rgba(245, 158, 11, 0.25)' }}>
              <RotateCcw size={18} />
            </div>
          </div>
          <div className="metric-value" style={{ color: '#fbbf24' }}>{rebootCount}</div>
          <div className="metric-subtext">Endpoints awaiting restart</div>
        </div>

        <div
          className="glass-card glass-card-interactive"
          style={{ cursor: 'pointer' }}
          onClick={() => onNavigateDevices({ status: 'isolated' })}
        >
          <div className="metric-header">
            <span className="metric-title">CYBER ISOLATED</span>
            <div className="metric-icon-wrap" style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', borderColor: 'rgba(239, 68, 68, 0.25)' }}>
              <ShieldAlert size={18} />
            </div>
          </div>
          <div className="metric-value" style={{ color: isolatedCount > 0 ? '#f87171' : 'var(--text-main)' }}>
            {isolatedCount}
          </div>
          <div className="metric-subtext">Quarantined endpoints</div>
        </div>

        <div
          className="glass-card glass-card-interactive"
          style={{ cursor: 'pointer' }}
          onClick={() => onNavigateDevices({ smartGroup: 'unencrypted' })}
        >
          <div className="metric-header">
            <span className="metric-title">DISK ENCRYPTION</span>
            <div className="metric-icon-wrap" style={{ background: 'rgba(0, 242, 254, 0.1)', color: 'var(--primary)', borderColor: 'rgba(0, 242, 254, 0.2)' }}>
              <HardDrive size={18} />
            </div>
          </div>
          <div className="metric-value">{bitlockerCount} / {tenantScopedDevices.length}</div>
          <div className="metric-subtext">BitLocker / LUKS / FileVault</div>
        </div>
      </div>

      {devices.length === 0 ? (
        <div className="glass-card" style={{ textAlign: 'center', padding: '3rem 1.5rem' }}>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.85rem' }}>
            <div style={{ fontWeight: 700, fontSize: '1.08rem' }}>No Endpoints Enrolled Yet</div>
            <div style={{ fontSize: '0.84rem', color: 'var(--text-muted)', maxWidth: '540px' }}>
              Your Vitrine control plane starts clean with zero fake demo clients. Provision a signed agent installer, import existing device groups from MeshCentral 2, or load the optional evaluation lab dataset.
            </div>
            <div style={{ display: 'flex', gap: '0.65rem', flexWrap: 'wrap', justifyContent: 'center', marginTop: '0.35rem' }}>
              {onOpenInstaller && canMutate && (
                <button className="btn-glass btn-primary" onClick={onOpenInstaller}>
                  <Download size={14} /> Provision Signed Agent
                </button>
              )}
              {onOpenOnboarding && isSuperAdmin(currentUser) && (
                <button className="btn-glass" onClick={onOpenOnboarding}>
                  Import from MeshCentral
                </button>
              )}
              {enableLabDemo && isSuperAdmin(currentUser) && (
                <button className="btn-glass" onClick={handleSeedDemoLab}>
                  Load Lab Demo Dataset
                </button>
              )}
            </div>
          </div>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1.25rem' }}>
          {/* Fleet Breakdown Card */}
          <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ margin: 0, fontSize: '1.02rem', fontWeight: 600 }}>Fleet Breakdown &amp; Transport</h3>
              <span style={{ fontSize: '0.74rem', color: 'var(--text-dim)', display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                <Wifi size={13} color="#38bdf8" /> {wssCount} WSS / {Math.max(0, totalCount - wssCount)} HTTP
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
              {[
                { key: 'windows', label: 'Windows', count: osBreakdown.windows, color: '#38bdf8' },
                { key: 'linux', label: 'Linux', count: osBreakdown.linux, color: '#34d399' },
                { key: 'macos', label: 'macOS', count: osBreakdown.macos, color: '#c084fc' }
              ].map((os) => {
                const pct = totalCount > 0 ? Math.round((os.count / totalCount) * 100) : 0;
                return (
                  <div
                    key={os.key}
                    style={{ cursor: 'pointer' }}
                    onClick={() =>
                      onNavigateDevices({
                        extraFilter: { field: 'os_type', operator: 'is', value: os.key }
                      })
                    }
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '0.25rem' }}>
                      <span>{os.label}</span>
                      <span style={{ color: 'var(--text-muted)' }}>
                        {os.count} ({pct}%)
                      </span>
                    </div>
                    <div style={{ height: '7px', borderRadius: '4px', background: 'rgba(148, 163, 184, 0.16)', overflow: 'hidden' }}>
                      <div style={{ width: `${pct}%`, height: '100%', background: os.color }} />
                    </div>
                  </div>
                );
              })}
            </div>

            <div style={{ borderTop: '1px solid var(--glass-border)', paddingTop: '0.85rem' }}>
              <div style={{ fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-dim)', marginBottom: '0.5rem' }}>
                DEVICE ROLES
              </div>
              <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap' }}>
                {roleBreakdown.map(([role, count]) => (
                  <button
                    key={role}
                    type="button"
                    className="btn-glass"
                    style={{ fontSize: '0.74rem', padding: '0.28rem 0.65rem' }}
                    onClick={() => onNavigateDevices({ deviceRole: role })}
                  >
                    {role.toLowerCase().includes('laptop') ? (
                      <Laptop size={12} color="#38bdf8" />
                    ) : role.toLowerCase().includes('server') || role.toLowerCase().includes('hypervisor') ? (
                      <Server size={12} color="#a78bfa" />
                    ) : (
                      <Monitor size={12} />
                    )}
                    <span>
                      {role}: <strong>{count}</strong>
                    </span>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Attention Required Card */}
          <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ margin: 0, fontSize: '1.02rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                <AlertTriangle size={16} color="#fbbf24" /> Attention Required
              </h3>
              <button
                type="button"
                className="btn-glass"
                style={{ fontSize: '0.73rem', padding: '0.25rem 0.6rem' }}
                onClick={() => onNavigateDevices({})}
              >
                View All in Devices
              </button>
            </div>

            {attentionDevices.length === 0 ? (
              <div style={{ padding: '2rem 1rem', textAlign: 'center', color: '#34d399', fontSize: '0.85rem' }}>
                All active endpoints are online, healthy, and encrypted.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
                {attentionDevices.map(({ device, reasons }) => (
                  <div
                    key={device.id}
                    onClick={() => onSelectDevice(device)}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: '0.65rem',
                      padding: '0.55rem 0.75rem',
                      borderRadius: '8px',
                      background: 'rgba(255, 255, 255, 0.03)',
                      border: '1px solid var(--glass-border)',
                      cursor: 'pointer'
                    }}
                  >
                    <div style={{ minWidth: 0 }}>
                      <div style={{ fontWeight: 600, fontSize: '0.82rem' }}>{device.hostname}</div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                        {device.tenant_name || 'Unassigned'} • {device.device_role}
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                      {reasons.slice(0, 2).map((r) => (
                        <span
                          key={r}
                          className={`status-pill ${
                            r === 'Cyber Isolated' || r.includes('Failing') || r === 'Offline Server'
                              ? 'status-isolated'
                              : r === 'Offline' || r === 'Unencrypted'
                              ? 'status-offline'
                              : 'status-reboot'
                          }`}
                          style={{ fontSize: '0.66rem', padding: '0.15rem 0.5rem' }}
                        >
                          {r}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Client Organizations Summary */}
          <div className="glass-card" style={{ gridColumn: '1 / -1', display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ margin: 0, fontSize: '1.02rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                <Building2 size={16} color="var(--primary)" /> Client Organizations
              </h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                Click a client to inspect its endpoints in Devices
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: '0.75rem' }}>
              {clientSummaries.map(({ tenant, total, online, alerts }) => {
                const pct = total > 0 ? Math.round((online / total) * 100) : 0;
                return (
                  <div
                    key={tenant.id}
                    onClick={() => onNavigateDevices({ tenantId: tenant.id })}
                    className="glass-card-interactive"
                    style={{
                      padding: '0.85rem 1rem',
                      borderRadius: '10px',
                      background: 'rgba(255, 255, 255, 0.03)',
                      border: '1px solid var(--glass-border)',
                      cursor: 'pointer',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.45rem'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.4rem' }}>
                      <strong style={{ fontSize: '0.86rem' }}>{tenant.name}</strong>
                      <span style={{ fontSize: '0.72rem', color: '#34d399', fontWeight: 600 }}>
                        {online}/{total} online
                      </span>
                    </div>
                    <div style={{ height: '5px', borderRadius: '3px', background: 'rgba(148, 163, 184, 0.16)', overflow: 'hidden' }}>
                      <div style={{ width: `${pct}%`, height: '100%', background: pct >= 80 ? '#10b981' : '#f59e0b' }} />
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                      <span>{tenant.sites?.length || 0} location(s)</span>
                      <span style={{ color: alerts > 0 ? '#fbbf24' : 'var(--text-dim)' }}>
                        {alerts > 0 ? `${alerts} flagged` : 'All clear'}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
