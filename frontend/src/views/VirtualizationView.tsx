import React, { useState, useEffect, useCallback } from 'react';
import { Server, Play, Square, RotateCcw, Camera, Plus, Trash2, X } from 'lucide-react';
import { fetchVirtualization, manageVmPower, addVirtualizationHost, deleteVirtualizationHost } from '../services/api.js';

interface GuestVm {
  vmid: number | string;
  name: string;
  os: string;
  cpu: number | string;
  ramGb: number | string;
  status: string;
  lastSnapshot?: string;
}

interface HypervisorHost {
  id: string;
  name: string;
  hostType: string;
  ipAddress?: string;
  apiPort?: number;
  apiUsername?: string;
  hasApiToken?: boolean;
  status?: string;
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

  const [showAddHost, setShowAddHost] = useState(false);
  const [newHostName, setNewHostName] = useState('');
  const [newHostType, setNewHostType] = useState('Proxmox VE 8.2');
  const [newIpAddress, setNewIpAddress] = useState('');
  const [newApiPort, setNewApiPort] = useState(8006);
  const [newApiUsername, setNewApiUsername] = useState('root@pam');
  const [newApiToken, setNewApiToken] = useState('');

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
      hostType: newHostType,
      ipAddress: newIpAddress.trim() || undefined,
      apiPort: newApiPort,
      apiUsername: newApiUsername.trim() || undefined,
      apiToken: newApiToken.trim() || undefined
    });
    loadHosts();
    setShowAddHost(false);
    setNewHostName('');
    setNewIpAddress('');
    setNewApiToken('');
  };

  const handleDeleteHost = async (id: string, name: string) => {
    if (!confirm(`Remove hypervisor host "${name}" from Vitrine monitoring?`)) return;
    await deleteVirtualizationHost(id);
    loadHosts();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="virtualization-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
            Hypervisor &amp; Virtualization Host Monitoring
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Agentless API integration for Proxmox VE, Hyper-V, and VMware ESXi clusters with AES-256-GCM credential vaulting
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

      {hosts.length === 0 && (
        <div className="glass-card" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
          No hypervisor hosts registered yet. Click <strong>Add Hypervisor Host</strong> to connect Proxmox VE, ESXi, or Hyper-V.
        </div>
      )}

      {hosts.map((h) => {
        const isOnline = !h.status || h.status.toLowerCase() === 'online' || h.status.toLowerCase() === 'connected';
        return (
          <div key={h.id} className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                <Server size={24} color="var(--primary)" />
                <div>
                  <h3 style={{ fontSize: '1.15rem', fontWeight: 600 }}>{h.name}</h3>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>
                    {h.hostType}
                    {h.ipAddress ? ` • ${h.ipAddress}:${h.apiPort || 8006}` : ''}
                    {h.hasApiToken ? ' • Vault API Token Stored' : ''}
                  </span>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span className={`status-pill ${isOnline ? 'status-online' : 'status-offline'}`}>
                  {h.status || 'Connected'}
                </span>
                <button
                  className="btn-glass btn-icon"
                  title="Remove Hypervisor Host"
                  onClick={() => handleDeleteHost(h.id, h.name)}
                >
                  <Trash2 size={14} color="#ef4444" />
                </button>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
              <div className="glass-card" style={{ padding: '0.85rem' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>CPU UTILIZATION</div>
                <div style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--primary)' }}>{h.cpuUsagePct}%</div>
              </div>
              <div className="glass-card" style={{ padding: '0.85rem' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>MEMORY ALLOCATED</div>
                <div style={{ fontSize: '1.3rem', fontWeight: 700 }}>{h.ramUsageGb} / {h.ramTotalGb} GB</div>
              </div>
              <div className="glass-card" style={{ padding: '0.85rem' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>STORAGE POOL FREE</div>
                <div style={{ fontSize: '1.3rem', fontWeight: 700, color: '#34d399' }}>{h.storageFreeTb} TB / {h.storageTotalTb} TB</div>
              </div>
            </div>

            <div>
              <h4 style={{ fontSize: '0.9rem', fontWeight: 600, marginBottom: '0.65rem' }}>GUEST VIRTUAL MACHINES ({h.vms.length})</h4>
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
                              <button className="btn-glass btn-icon" title="Start VM" onClick={() => handleVmPower(h.id, vm.vmid, 'start')}>
                                <Play size={13} color="#10b981" />
                              </button>
                            ) : (
                              <button className="btn-glass btn-icon" title="Stop VM" onClick={() => handleVmPower(h.id, vm.vmid, 'stop')}>
                                <Square size={13} color="#ef4444" />
                              </button>
                            )}
                            <button className="btn-glass btn-icon" title="Reboot VM" onClick={() => handleVmPower(h.id, vm.vmid, 'reboot')}>
                              <RotateCcw size={13} color="#fbbf24" />
                            </button>
                            <button className="btn-glass btn-icon" title="Take Snapshot" onClick={() => handleVmPower(h.id, vm.vmid, 'snapshot')}>
                              <Camera size={13} color="#38bdf8" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                    {h.vms.length === 0 && (
                      <tr>
                        <td colSpan={7} style={{ textAlign: 'center', padding: '1.25rem', color: 'var(--text-muted)' }}>
                          No virtual machines indexed on this host yet.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        );
      })}

      {showAddHost && (
        <div className="modal-overlay" onClick={() => setShowAddHost(false)}>
          <div className="glass-modal" style={{ maxWidth: '480px', padding: '1.5rem' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>Connect Hypervisor Host</h3>
              <button className="btn-glass btn-icon" onClick={() => setShowAddHost(false)}>
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleAddHost} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label className="form-label">Hypervisor Hostname *</label>
                <input
                  type="text"
                  required
                  className="glass-input"
                  placeholder="e.g. PVE-CLUSTER-NODE-01"
                  value={newHostName}
                  onChange={(e) => setNewHostName(e.target.value)}
                />
              </div>
              <div>
                <label className="form-label">Hypervisor Platform</label>
                <select
                  className="glass-select"
                  value={newHostType}
                  onChange={(e) => {
                    setNewHostType(e.target.value);
                    if (e.target.value.includes('ESXi')) setNewApiPort(443);
                    else if (e.target.value.includes('Hyper-V')) setNewApiPort(5986);
                    else setNewApiPort(8006);
                  }}
                >
                  <option value="Proxmox VE 8.2">Proxmox VE 8.x</option>
                  <option value="VMware ESXi 8.0">VMware ESXi 8.0</option>
                  <option value="Microsoft Hyper-V 2022">Microsoft Hyper-V 2022</option>
                </select>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '0.75rem' }}>
                <div>
                  <label className="form-label">Management IP / FQDN</label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="10.0.10.50"
                    value={newIpAddress}
                    onChange={(e) => setNewIpAddress(e.target.value)}
                  />
                </div>
                <div>
                  <label className="form-label">API Port</label>
                  <input
                    type="number"
                    className="glass-input"
                    value={newApiPort}
                    onChange={(e) => setNewApiPort(Number(e.target.value))}
                  />
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div>
                  <label className="form-label">API Username / Realm</label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="root@pam!vitrine"
                    value={newApiUsername}
                    onChange={(e) => setNewApiUsername(e.target.value)}
                  />
                </div>
                <div>
                  <label className="form-label">API Secret / Token (Vaulted)</label>
                  <input
                    type="password"
                    className="glass-input"
                    placeholder="Encrypted at rest"
                    value={newApiToken}
                    onChange={(e) => setNewApiToken(e.target.value)}
                  />
                </div>
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
