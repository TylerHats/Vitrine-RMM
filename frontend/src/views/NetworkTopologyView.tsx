import React, { useState, useEffect, useCallback } from 'react';
import { Router, RefreshCw, Plus, X } from 'lucide-react';
import { fetchTopology, triggerTopologyScan, addTopologyPort } from '../services/api.js';

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
  const [scanning, setScanning] = useState(false);
  const [scanMsg, setScanMsg] = useState<string | null>(null);

  // Add Switch Port Modal
  const [showAddPort, setShowAddPort] = useState(false);
  const [newPort, setNewPort] = useState('Gi1/0/5');
  const [newVlan, setNewVlan] = useState(10);
  const [newSpeed, setNewSpeed] = useState('1 Gbps');
  const [newNeighbor, setNewNeighbor] = useState('');

  const loadTopology = useCallback(() => {
    fetchTopology().then((res) => setData(res as unknown as TopologyData));
  }, []);

  useEffect(() => {
    loadTopology();
  }, [loadTopology]);

  const handleTriggerSweep = async () => {
    setScanning(true);
    try {
      await triggerTopologyScan();
      setScanMsg('ARP & LLDP subnet discovery sweep complete.');
      loadTopology();
      setTimeout(() => setScanMsg(null), 4000);
    } finally {
      setScanning(false);
    }
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
            Network Discovery, SNMP Probes &amp; Layer-2 Topology
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Local agent subnet sweeps, LLDP/CDP switch port visualization, and unmanaged hardware detection
          </span>
        </div>
        <div style={{ display: 'flex', gap: '0.65rem' }}>
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
    </div>
  );
};
