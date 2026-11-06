import React, { useState, useEffect, useCallback } from 'react';
import { Server, Play, Square, RotateCcw, Camera, Plus, X } from 'lucide-react';
import { fetchVirtualization, manageVmPower, addVirtualizationHost } from '../services/api.js';

interface GuestVm {
  vmid: number | string;
  name: string;
  os: string;
  cpu: number | string;
  ramGb: number | string;
  status: string;
}

interface HypervisorHost {
  id: string;
  name: string;
  hostType: string;
  cpuUsagePct: number;
  ramUsageGb: number;
  ramTotalGb: number;
  storageFreeTb: number;
  storageTotalTb: number;
  vms: GuestVm[];
}

export const VirtualizationView: React.FC = () => {
  const [hosts, setHosts] = useState<HypervisorHost[]>([]);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  // Add Hypervisor Host Modal
  const [showAddHost, setShowAddHost] = useState(false);
  const [newHostName, setNewHostName] = useState('');
  const [newHostType, setNewHostType] = useState('Proxmox VE 8.2');

  const loadHosts = useCallback(() => {
    fetchVirtualization().then((res) => setHosts(res as unknown as HypervisorHost[]));
  }, []);

  useEffect(() => {
    loadHosts();
  }, [loadHosts]);

  const handleVmPower = async (hostId: string, vmid: number | string, action: 'start' | 'stop' | 'reboot' | 'snapshot') => {
    const res = await manageVmPower(hostId, Number(vmid), action);
    if (res.success) {
      setActionMsg(`Dispatched ${action.toUpperCase()} command to VM #${vmid} on ${hostId}.`);
      loadHosts();
      setTimeout(() => setActionMsg(null), 4000);
    }
  };

  const handleAddHost = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newHostName.trim()) return;
    await addVirtualizationHost({
      name: newHostName.trim(),
      hostType: newHostType
    });
    loadHosts();
    setShowAddHost(false);
    setNewHostName('');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="virtualization-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
            Hypervisor &amp; Virtualization Host Monitoring
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Agentless API integration for Proxmox VE, Hyper-V, and VMware ESXi clusters with direct VM lifecycle controls
          </span>
        </div>
        <button className="btn-glass btn-primary" onClick={() => setShowAddHost(true)}>
          <Plus size={15} /> Add Hypervisor Host
        </button>
      </div>

      {actionMsg && (
        <div
          className="glass-card"
          style={{
            padding: '0.75rem 1.25rem',
            background: 'rgba(16, 185, 129, 0.12)',
            borderColor: 'rgba(16, 185, 129, 0.35)',
            color: '#34d399',
            fontSize: '0.85rem'
          }}
        >
          ✓ {actionMsg}
        </div>
      )}

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
                    <th style={{ textAlign: 'right' }}>Power &amp; Snapshots</th>
                  </tr>
                </thead>
                <tbody>
                  {h.vms.map((vm: GuestVm) => (
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
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.35rem' }}>
                          {vm.status !== 'Running' ? (
                            <button
                              className="btn-glass btn-icon"
                              title="Start VM"
                              onClick={() => handleVmPower(h.id, vm.vmid, 'start')}
                            >
                              <Play size={13} color="#10b981" />
                            </button>
                          ) : (
                            <button
                              className="btn-glass btn-icon"
                              title="Stop VM"
                              onClick={() => handleVmPower(h.id, vm.vmid, 'stop')}
                            >
                              <Square size={13} color="#ef4444" />
                            </button>
                          )}
                          <button
                            className="btn-glass btn-icon"
                            title="Reboot VM"
                            onClick={() => handleVmPower(h.id, vm.vmid, 'reboot')}
                          >
                            <RotateCcw size={13} color="#fbbf24" />
                          </button>
                          <button
                            className="btn-glass btn-icon"
                            title="Take Snapshot"
                            onClick={() => handleVmPower(h.id, vm.vmid, 'snapshot')}
                          >
                            <Camera size={13} color="#38bdf8" />
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
      ))}

      {showAddHost && (
        <div className="modal-overlay" onClick={() => setShowAddHost(false)}>
          <div className="glass-modal" style={{ maxWidth: '440px', padding: '1.5rem' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>Connect Hypervisor Host</h3>
              <button className="btn-glass btn-icon" onClick={() => setShowAddHost(false)}>
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleAddHost} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Hypervisor Hostname
                </label>
                <input
                  type="text"
                  required
                  className="glass-input"
                  placeholder="e.g. PVE-CLUSTER-NODE-02"
                  value={newHostName}
                  onChange={(e) => setNewHostName(e.target.value)}
                />
              </div>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Hypervisor Platform
                </label>
                <select className="glass-select" value={newHostType} onChange={(e) => setNewHostType(e.target.value)}>
                  <option value="Proxmox VE 8.2">Proxmox VE 8.2</option>
                  <option value="VMware ESXi 8.0">VMware ESXi 8.0</option>
                  <option value="Microsoft Hyper-V 2022">Microsoft Hyper-V 2022</option>
                </select>
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button type="button" className="btn-glass" onClick={() => setShowAddHost(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-glass btn-primary">
                  Connect Host
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
