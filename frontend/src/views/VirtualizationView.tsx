import React, { useState, useEffect } from 'react';
import { Server, Play, Square, HardDrive, Cpu, Activity } from 'lucide-react';
import { fetchVirtualization } from '../services/api.js';

export const VirtualizationView: React.FC = () => {
  const [hosts, setHosts] = useState<any[]>([]);

  useEffect(() => {
    fetchVirtualization().then(setHosts);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="virtualization-view">
      <div>
        <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
          Hypervisor &amp; Virtualization Host Monitoring
        </h2>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          Agentless API integration for Proxmox VE, Hyper-V, and VMware ESXi clusters
        </span>
      </div>

      {hosts.map((h) => (
        <div key={h.id} className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
              <Server size={24} color="#00f2fe" />
              <div>
                <h3 style={{ fontSize: '1.15rem', fontWeight: 600 }}>{h.name}</h3>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>{h.hostType}</span>
              </div>
            </div>
            <span className="status-pill status-online">API Connected</span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
            <div className="glass-card" style={{ padding: '0.85rem', background: 'rgba(0,0,0,0.2)' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>CPU UTILIZATION</div>
              <div style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--primary)' }}>{h.cpuUsagePct}%</div>
            </div>
            <div className="glass-card" style={{ padding: '0.85rem', background: 'rgba(0,0,0,0.2)' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>MEMORY ALLOCATED</div>
              <div style={{ fontSize: '1.3rem', fontWeight: 700 }}>{h.ramUsageGb} / {h.ramTotalGb} GB</div>
            </div>
            <div className="glass-card" style={{ padding: '0.85rem', background: 'rgba(0,0,0,0.2)' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>STORAGE POOL FREE</div>
              <div style={{ fontSize: '1.3rem', fontWeight: 700, color: '#34d399' }}>{h.storageFreeTb} TB / {h.storageTotalTb} TB</div>
            </div>
          </div>

          <div>
            <h4 style={{ fontSize: '0.9rem', fontWeight: 600, marginBottom: '0.65rem' }}>GUEST VIRTUAL MACHINES</h4>
            <div className="table-wrapper">
              <table className="glass-table">
                <thead>
                  <tr>
                    <th>VMID</th>
                    <th>Virtual Machine Name</th>
                    <th>Guest OS</th>
                    <th>Allocated vCPUs</th>
                    <th>RAM</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {h.vms.map((vm: any) => (
                    <tr key={vm.vmid}>
                      <td><strong>{vm.vmid}</strong></td>
                      <td>{vm.name}</td>
                      <td>{vm.os}</td>
                      <td>{vm.cpu} cores</td>
                      <td>{vm.ramGb} GB</td>
                      <td>
                        <span className={`status-pill ${vm.status === 'Running' ? 'status-online' : 'status-offline'}`}>
                          {vm.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};
