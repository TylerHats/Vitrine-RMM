import React, { useState, useEffect } from 'react';
import { Network, Server, Router, Search, ShieldCheck, Activity } from 'lucide-react';
import { fetchTopology } from '../services/api.js';

export const NetworkTopologyView: React.FC = () => {
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    fetchTopology().then(setData);
  }, []);

  if (!data) return <div>Loading topology &amp; SNMP mappings...</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="network-topology-view">
      <div>
        <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
          Network Discovery, SNMP Probes &amp; Layer-2 Topology
        </h2>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          Local agent subnet sweeps, LLDP/CDP switch port visualization, and unmanaged hardware detection
        </span>
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
              {data.coreSwitch.ports.map((p: any) => (
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
          {data.discoveredSubnets.map((s: any, idx: number) => (
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
    </div>
  );
};
