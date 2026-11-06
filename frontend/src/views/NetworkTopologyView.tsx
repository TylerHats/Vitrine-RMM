import React, { useState, useEffect, useCallback } from 'react';
import { Router, RefreshCw, Plus, X, Shield, BatteryCharging, HardDrive, Printer, Activity, Trash2 } from 'lucide-react';
import { NetworkAppliance } from '../types/index.js';
import {
  fetchTopology,
  triggerTopologyScan,
  addTopologyPort,
  fetchNetworkAppliances,
  createNetworkAppliance,
  pollNetworkAppliance,
  deleteNetworkAppliance
} from '../services/api.js';

interface SwitchPort {
  port: string;
  vlan: number | string;
  speed: string;
  status: string;
  lldpNeighbor: string;
}

interface CoreSwitch {
  name: string;
  ip: string;
  ports: SwitchPort[];
}

interface DiscoveredSubnet {
  subnet: string;
  probeHost: string;
  totalDiscovered: number;
  unmanaged: number;
}

interface TopologyData {
  coreSwitch: CoreSwitch;
  discoveredSubnets: DiscoveredSubnet[];
}

export const NetworkTopologyView: React.FC = () => {
  const [data, setData] = useState<TopologyData | null>(null);
  const [appliances, setAppliances] = useState<NetworkAppliance[]>([]);
  const [pollingId, setPollingId] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanMsg, setScanMsg] = useState<string | null>(null);

  // Add Switch Port Modal
  const [showAddPort, setShowAddPort] = useState(false);
  const [newPort, setNewPort] = useState('Gi1/0/5');
  const [newVlan, setNewVlan] = useState(10);
  const [newSpeed, setNewSpeed] = useState('1 Gbps');
  const [newNeighbor, setNewNeighbor] = useState('');

  // Add Network Appliance Modal
  const [showAddAppliance, setShowAddAppliance] = useState(false);
  const [appName, setAppName] = useState('');
  const [appType, setAppType] = useState<'firewall' | 'switch' | 'ups' | 'nas' | 'printer'>('firewall');
  const [appVendor, setAppVendor] = useState('');
  const [appIp, setAppIp] = useState('10.200.10.250');
  const [appSnmp, setAppSnmp] = useState('SNMPv3 (AES-256 / SHA-2)');

  const loadTopology = useCallback(() => {
    fetchTopology().then((res) => setData(res as unknown as TopologyData));
    fetchNetworkAppliances().then(setAppliances).catch(console.error);
  }, []);

  useEffect(() => {
    loadTopology();
  }, [loadTopology]);

  const handleTriggerSweep = async () => {
    setScanning(true);
    try {
      await triggerTopologyScan();
      setScanMsg('ARP, LLDP & SNMPv3 local agent probe sweep complete.');
      loadTopology();
      setTimeout(() => setScanMsg(null), 4000);
    } finally {
      setScanning(false);
    }
  };

  const handlePollAppliance = async (id: string) => {
    setPollingId(id);
    try {
      const res = await pollNetworkAppliance(id);
      if (res.success && res.appliance) {
        setAppliances((prev) => prev.map((a) => (a.id === id ? res.appliance : a)));
        setScanMsg(`SNMP Probe ${res.appliance.probe_hostname} polled ${res.appliance.name} (${res.appliance.ip_address}): RTT ${res.appliance.latency_ms} ms`);
        setTimeout(() => setScanMsg(null), 4000);
      }
    } finally {
      setPollingId(null);
    }
  };

  const handleCreateAppliance = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!appName.trim() || !appIp.trim()) return;
    const res = await createNetworkAppliance({
      name: appName.trim(),
      appliance_type: appType,
      vendor_model: appVendor.trim() || 'Enterprise SNMP Appliance',
      ip_address: appIp.trim(),
      snmp_version: appSnmp
    });
    if (res.success) {
      loadTopology();
      setShowAddAppliance(false);
      setAppName('');
      setAppVendor('');
    }
  };

  const handleDeleteAppliance = async (id: string, name: string) => {
    if (!confirm(`Remove network appliance monitor "${name}"?`)) return;
    await deleteNetworkAppliance(id);
    setAppliances((prev) => prev.filter((a) => a.id !== id));
  };

  const handleAddPort = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPort.trim() || !newNeighbor.trim()) return;
    await addTopologyPort({
      port: newPort.trim(),
      vlan: newVlan,
      speed: newSpeed,
      status: 'Up',
      lldpNeighbor: newNeighbor.trim()
    });
    loadTopology();
    setShowAddPort(false);
    setNewNeighbor('');
  };

  if (!data) return <div>Loading topology &amp; SNMP mappings...</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="network-topology-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
            Network Appliances, SNMP Probes &amp; Layer-2 Topology
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Agent-relayed SNMP v2c/v3 appliance monitors (Firewalls, Switches, Smart UPS, SAN/NAS, Printers) &amp; LLDP port mapping
          </span>
        </div>
        <div style={{ display: 'flex', gap: '0.65rem', flexWrap: 'wrap' }}>
          <button className="btn-glass" onClick={() => setShowAddAppliance(true)}>
            <Plus size={15} /> Add Network Appliance
          </button>
          <button className="btn-glass" onClick={() => setShowAddPort(true)}>
            <Plus size={15} /> Map Switch Port
          </button>
          <button className="btn-glass btn-primary" onClick={handleTriggerSweep} disabled={scanning}>
            <RefreshCw size={15} /> {scanning ? 'Sweeping Subnets...' : 'Trigger Subnet Sweep'}
          </button>
        </div>
      </div>

      {scanMsg && (
        <div
          className="glass-card"
          style={{
            padding: '0.75rem 1.25rem',
            background: 'rgba(0, 242, 254, 0.12)',
            borderColor: 'rgba(0, 242, 254, 0.35)',
            color: '#38bdf8',
            fontSize: '0.85rem'
          }}
        >
          ✓ {scanMsg}
        </div>
      )}

      {/* Agent-Relayed Network Appliances & SNMP Infrastructure Monitors */}
      <div className="glass-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0 }}>
              Network Appliances &amp; SNMP Infrastructure Monitors ({appliances.length})
            </h3>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>
              Polled over LAN by designated online Managed Agent Probes in the same company &amp; subnet
            </span>
          </div>
          <span className="status-pill status-online">SNMPv3 + ICMP Probe Relay Active</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1rem' }}>
          {appliances.map((app) => {
            const IconComp =
              app.appliance_type === 'firewall'
                ? Shield
                : app.appliance_type === 'ups'
                  ? BatteryCharging
                  : app.appliance_type === 'nas'
                    ? HardDrive
                    : app.appliance_type === 'printer'
                      ? Printer
                      : Router;
            return (
              <div
                key={app.id}
                className="glass-card"
                style={{
                  padding: '1rem 1.15rem',
                  background: 'rgba(15, 23, 42, 0.72)',
                  border: `1px solid ${app.status === 'warning' ? 'rgba(245, 158, 11, 0.4)' : 'var(--glass-border)'}`,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.7rem'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                    <IconComp size={20} color={app.status === 'warning' ? '#fbbf24' : '#38bdf8'} />
                    <div>
                      <div style={{ fontWeight: 700, fontSize: '0.95rem', color: '#f8fafc' }}>{app.name}</div>
                      <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                        {app.vendor_model} • <code>{app.ip_address}</code>
                      </div>
                    </div>
                  </div>
                  <span
                    className={`status-pill ${
                      app.status === 'online' ? 'status-online' : app.status === 'warning' ? 'status-reboot' : 'status-isolated'
                    }`}
                    style={{ fontSize: '0.7rem' }}
                  >
                    {app.status.toUpperCase()}
                  </span>
                </div>

                {app.alert_summary && (
                  <div
                    style={{
                      padding: '0.45rem 0.65rem',
                      borderRadius: '6px',
                      background: 'rgba(245, 158, 11, 0.14)',
                      border: '1px solid rgba(245, 158, 11, 0.35)',
                      color: '#fbbf24',
                      fontSize: '0.74rem'
                    }}
                  >
                    ⚠️ {app.alert_summary}
                  </div>
                )}

                <div style={{ display: 'flex', gap: '0.9rem', flexWrap: 'wrap', fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                  <span>RTT: <strong style={{ color: '#10b981' }}>{app.latency_ms} ms</strong></span>
                  <span>CPU: <strong>{app.cpu_pct}%</strong></span>
                  <span>RAM: <strong>{app.memory_pct}%</strong></span>
                  <span>Uptime: <strong>{app.uptime_days}d</strong></span>
                </div>

                {/* Appliance-Specific SNMP OID Metrics */}
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                  {Object.entries(app.metrics || {}).map(([k, v]) => (
                    <span
                      key={k}
                      style={{
                        padding: '0.2rem 0.5rem',
                        borderRadius: '5px',
                        background: 'rgba(255, 255, 255, 0.05)',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        fontSize: '0.71rem',
                        color: '#cbd5e1'
                      }}
                    >
                      <span style={{ color: 'var(--text-dim)' }}>{k}:</span> <strong>{String(v)}</strong>
                    </span>
                  ))}
                </div>

                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    paddingTop: '0.45rem',
                    borderTop: '1px solid rgba(255, 255, 255, 0.06)',
                    fontSize: '0.72rem',
                    color: 'var(--text-dim)'
                  }}
                >
                  <span>
                    Probe Relay: <strong style={{ color: '#38bdf8' }}>{app.probe_hostname}</strong> ({app.snmp_version.split(' ')[0]})
                  </span>
                  <div style={{ display: 'flex', gap: '0.4rem' }}>
                    <button
                      className="btn-glass"
                      style={{ padding: '0.2rem 0.55rem', fontSize: '0.7rem' }}
                      onClick={() => handlePollAppliance(app.id)}
                      disabled={pollingId === app.id}
                    >
                      <Activity size={11} /> {pollingId === app.id ? 'Polling...' : 'Poll Probe'}
                    </button>
                    <button
                      className="btn-glass btn-danger"
                      style={{ padding: '0.2rem 0.45rem', fontSize: '0.7rem' }}
                      onClick={() => handleDeleteAppliance(app.id, app.name)}
                    >
                      <Trash2 size={11} />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Core Switch Card */}
      <div className="glass-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
            <Router size={24} color="var(--primary)" />
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>{data.coreSwitch.name}</h3>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>IP: {data.coreSwitch.ip} • Polled via Managed Probe</span>
            </div>
          </div>
          <span className="status-pill status-online">SNMP v3 Active</span>
        </div>

        <div className="table-wrapper">
          <table className="glass-table">
            <thead>
              <tr>
                <th>Port Interface</th>
                <th>VLAN</th>
                <th>Link Speed</th>
                <th>Link Status</th>
                <th>LLDP / CDP Discovered Neighbor</th>
              </tr>
            </thead>
            <tbody>
              {data.coreSwitch.ports.map((p: SwitchPort) => (
                <tr key={p.port}>
                  <td><strong>{p.port}</strong></td>
                  <td><span className="status-pill status-reboot" style={{ fontSize: '0.72rem' }}>VLAN {p.vlan}</span></td>
                  <td>{p.speed}</td>
                  <td><span className="status-pill status-online">{p.status}</span></td>
                  <td>
                    <span style={{ fontWeight: 600, color: 'var(--primary)' }}>
                      🖥️ {p.lldpNeighbor}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Subnet Sweep Probes */}
      <div className="glass-card">
        <h3 style={{ fontSize: '1.05rem', fontWeight: 600, marginBottom: '0.75rem' }}>
          Designated Subnet ARP &amp; IP Sweeps
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
          {data.discoveredSubnets.map((s: DiscoveredSubnet, idx: number) => (
            <div key={idx} className="glass-card" style={{ padding: '1rem', background: 'rgba(0, 0, 0, 0.25)' }}>
              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--primary)' }}>{s.subnet}</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>Probe Host: {s.probeHost}</div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.85rem', fontSize: '0.8rem' }}>
                <span>Discovered: <strong>{s.totalDiscovered} hosts</strong></span>
                <span style={{ color: '#fbbf24' }}>Unmanaged: <strong>{s.unmanaged} devices</strong></span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {showAddPort && (
        <div className="modal-overlay" onClick={() => setShowAddPort(false)}>
          <div className="glass-modal" style={{ maxWidth: '460px', padding: '1.5rem' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>Map Switch Port Neighbor</h3>
              <button className="btn-glass btn-icon" onClick={() => setShowAddPort(false)}>
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleAddPort} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Switch Port Interface
                  </label>
                  <input
                    type="text"
                    required
                    className="glass-input"
                    value={newPort}
                    onChange={(e) => setNewPort(e.target.value)}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    VLAN ID
                  </label>
                  <input
                    type="number"
                    className="glass-input"
                    value={newVlan}
                    onChange={(e) => setNewVlan(Number(e.target.value))}
                  />
                </div>
              </div>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Link Speed
                </label>
                <select className="glass-select" value={newSpeed} onChange={(e) => setNewSpeed(e.target.value)}>
                  <option value="1 Gbps">1 Gbps</option>
                  <option value="2.5 Gbps">2.5 Gbps</option>
                  <option value="10 Gbps">10 Gbps</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  LLDP / CDP Discovered Neighbor
                </label>
                <input
                  type="text"
                  required
                  className="glass-input"
                  placeholder="e.g. NAS-SYNOLOGY-BACKUP (10.20.4.80)"
                  value={newNeighbor}
                  onChange={(e) => setNewNeighbor(e.target.value)}
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button type="button" className="btn-glass" onClick={() => setShowAddPort(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-glass btn-primary">
                  Save Port Mapping
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
      {showAddAppliance && (
        <div className="modal-overlay" onClick={() => setShowAddAppliance(false)}>
          <div className="glass-modal" style={{ maxWidth: '480px', padding: '1.5rem' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>Enroll SNMP Network Appliance Monitor</h3>
              <button className="btn-glass btn-icon" onClick={() => setShowAddAppliance(false)}>
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleCreateAppliance} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Appliance Hostname / Identifier
                </label>
                <input
                  type="text"
                  required
                  className="glass-input"
                  placeholder="e.g. FW-BRANCH-MERAKI-01"
                  value={appName}
                  onChange={(e) => setAppName(e.target.value)}
                />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Appliance Class
                  </label>
                  <select
                    className="glass-select"
                    value={appType}
                    onChange={(e) => setAppType(e.target.value as 'firewall' | 'switch' | 'ups' | 'nas' | 'printer')}
                  >
                    <option value="firewall">Firewall / UTM Gateway</option>
                    <option value="switch">Managed Layer-2/3 Switch</option>
                    <option value="ups">Smart UPS / PDU Battery</option>
                    <option value="nas">SAN / NAS Storage Array</option>
                    <option value="printer">Network Printer / MFP</option>
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    LAN IPv4 Address
                  </label>
                  <input
                    type="text"
                    required
                    className="glass-input"
                    value={appIp}
                    onChange={(e) => setAppIp(e.target.value)}
                  />
                </div>
              </div>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Vendor &amp; Hardware Model
                </label>
                <input
                  type="text"
                  required
                  className="glass-input"
                  placeholder="e.g. FortiGate 100F / APC Smart-UPS 3000VA"
                  value={appVendor}
                  onChange={(e) => setAppVendor(e.target.value)}
                />
              </div>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  SNMP Protocol &amp; Auth Profile (Relayed via Same-Site Online Agent Probe)
                </label>
                <select className="glass-select" value={appSnmp} onChange={(e) => setAppSnmp(e.target.value)}>
                  <option value="SNMPv3 (AES-256 / SHA-2)">SNMPv3 (authPriv AES-256 / SHA-2)</option>
                  <option value="SNMPv2c (Read-Only Community)">SNMPv2c (Read-Only LAN Community)</option>
                </select>
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button type="button" className="btn-glass" onClick={() => setShowAddAppliance(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-glass btn-primary">
                  Enroll Appliance Monitor
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
