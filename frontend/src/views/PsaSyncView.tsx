import React, { useState, useEffect, useCallback } from 'react';
import { Plus, CheckCircle2, X } from 'lucide-react';
import { fetchPsaTickets, createPsaTicket, updatePsaTicket, fetchTenants, fetchDevices } from '../services/api.js';
import { Tenant, Device } from '../types/index.js';

interface PsaTicket {
  id: string;
  ticket_number: string;
  title: string;
  client_name: string;
  device_id?: string;
  priority: string;
  status: string;
}

interface PsaSyncViewProps {
  tenants?: Tenant[];
  devices?: Device[];
}

export const PsaSyncView: React.FC<PsaSyncViewProps> = ({ tenants: propTenants, devices: propDevices }) => {
  const [tickets, setTickets] = useState<PsaTicket[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>(propTenants || []);
  const [devices, setDevices] = useState<Device[]>(propDevices || []);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newClient, setNewClient] = useState('');
  const [newDevice, setNewDevice] = useState('');
  const [newPriority, setNewPriority] = useState('High');

  const loadTickets = useCallback(() => {
    fetchPsaTickets().then((res) => setTickets(res as unknown as PsaTicket[]));
  }, []);

  useEffect(() => {
    loadTickets();
    if (!propTenants) {
      fetchTenants().then((t) => {
        setTenants(t);
        if (t[0] && !newClient) setNewClient(t[0].name);
      });
    } else {
      setTenants(propTenants);
      if (propTenants[0] && !newClient) setNewClient(propTenants[0].name);
    }
    if (!propDevices) {
      fetchDevices().then(setDevices);
    } else {
      setDevices(propDevices);
    }
  }, [loadTickets, propTenants, propDevices, newClient]);

  const handleCreateTicket = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    await createPsaTicket({
      title: newTitle.trim(),
      client_name: newClient.trim() || 'General MSP Service Desk',
      device_id: newDevice.trim() || undefined,
      priority: newPriority
    });
    loadTickets();
    setShowCreateModal(false);
    setNewTitle('');
  };

  const handleToggleStatus = async (t: PsaTicket) => {
    const nextStatus = t.status === 'Resolved' ? 'Open' : 'Resolved';
    await updatePsaTicket(t.id, { status: nextStatus });
    loadTickets();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="psa-sync-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
            Two-Way PSA &amp; ITFlow Synchronization
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Bidirectional ticket lifecycle, telemetry auto-appending, and auto-closing upon self-healing remediation
          </span>
        </div>
        <button className="btn-glass btn-primary" onClick={() => setShowCreateModal(true)}>
          <Plus size={15} /> Create PSA Ticket
        </button>
      </div>

      <div className="metrics-grid">
        <div className="glass-card">
          <div className="metric-title">SYNCHRONIZED TICKETS</div>
          <div className="metric-value" style={{ color: 'var(--primary)' }}>{tickets.length}</div>
          <div className="metric-subtext">Active &amp; historical service desk queue</div>
        </div>

        <div className="glass-card">
          <div className="metric-title">RESOLVED INCIDENTS</div>
          <div className="metric-value" style={{ color: '#34d399' }}>
            {tickets.filter((t) => t.status === 'Resolved').length}
          </div>
          <div className="metric-subtext">Closed manually or via condition auto-resolution</div>
        </div>

        <div className="glass-card">
          <div className="metric-title">API WEBHOOK BUS</div>
          <div className="metric-value" style={{ color: '#38bdf8' }}>Active</div>
          <div className="metric-subtext">Listening on /api/psa/webhook (HMAC Verified)</div>
        </div>
      </div>

      <div className="glass-card" style={{ padding: 0 }}>
        <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
          <table className="glass-table">
            <thead>
              <tr>
                <th>Ticket #</th>
                <th>Subject / Alert Trigger</th>
                <th>Client Tenant</th>
                <th>Target Endpoint</th>
                <th>Priority</th>
                <th>Sync Status</th>
                <th style={{ textAlign: 'right' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {tickets.map((t) => (
                <tr key={t.id}>
                  <td><strong>{t.ticket_number}</strong></td>
                  <td>{t.title}</td>
                  <td>{t.client_name}</td>
                  <td><code>{t.device_id || 'System Fleet'}</code></td>
                  <td>
                    <span
                      className={`status-pill ${
                        t.priority === 'Urgent'
                          ? 'status-isolated'
                          : t.priority === 'High'
                          ? 'status-reboot'
                          : 'status-online'
                      }`}
                    >
                      {t.priority}
                    </span>
                  </td>
                  <td>
                    <span className={`status-pill ${t.status === 'Resolved' ? 'status-online' : 'status-reboot'}`}>
                      {t.status}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      className="btn-glass"
                      style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem' }}
                      onClick={() => handleToggleStatus(t)}
                    >
                      <CheckCircle2 size={12} /> {t.status === 'Resolved' ? 'Reopen' : 'Resolve'}
                    </button>
                  </td>
                </tr>
              ))}
              {tickets.length === 0 && (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                    No PSA tickets recorded yet. Condition alerts and manual tickets will appear here.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {showCreateModal && (
        <div className="modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="glass-modal" style={{ maxWidth: '460px', padding: '1.5rem' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>Create PSA Service Ticket</h3>
              <button className="btn-glass btn-icon" onClick={() => setShowCreateModal(false)}>
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleCreateTicket} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Subject / Incident Description
                </label>
                <input
                  type="text"
                  required
                  className="glass-input"
                  placeholder="e.g. Disk space critical on SQL volume"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                />
              </div>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Client Tenant
                </label>
                {tenants.length > 0 ? (
                  <select className="glass-select" value={newClient} onChange={(e) => setNewClient(e.target.value)}>
                    {tenants.map((ten) => (
                      <option key={ten.id} value={ten.name}>
                        {ten.name}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="Client Organization Name"
                    value={newClient}
                    onChange={(e) => setNewClient(e.target.value)}
                  />
                )}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Target Endpoint (Optional)
                  </label>
                  {devices.length > 0 ? (
                    <select className="glass-select" value={newDevice} onChange={(e) => setNewDevice(e.target.value)}>
                      <option value="">System / General</option>
                      {devices.map((dev) => (
                        <option key={dev.id} value={dev.hostname}>
                          {dev.hostname}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <input
                      type="text"
                      className="glass-input"
                      placeholder="Hostname or ID"
                      value={newDevice}
                      onChange={(e) => setNewDevice(e.target.value)}
                    />
                  )}
                </div>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Priority
                  </label>
                  <select className="glass-select" value={newPriority} onChange={(e) => setNewPriority(e.target.value)}>
                    <option value="Low">Low</option>
                    <option value="Medium">Medium</option>
                    <option value="High">High</option>
                    <option value="Urgent">Urgent</option>
                  </select>
                </div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button type="button" className="btn-glass" onClick={() => setShowCreateModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-glass btn-primary">
                  Dispatch Ticket
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
