import React, { useState, useEffect, useCallback } from 'react';
import { Plus, CheckCircle2, X } from 'lucide-react';
import { fetchPsaTickets, createPsaTicket, updatePsaTicket } from '../services/api.js';

interface PsaTicket {
  id: string;
  ticket_number: string;
  title: string;
  client_name: string;
  device_id?: string;
  priority: string;
  status: string;
}

export const PsaSyncView: React.FC = () => {
  const [tickets, setTickets] = useState<PsaTicket[]>([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newClient, setNewClient] = useState('Apex Financial Partners');
  const [newDevice, setNewDevice] = useState('WIN11-PRO-EXEC');
  const [newPriority, setNewPriority] = useState('High');

  const loadTickets = useCallback(() => {
    fetchPsaTickets().then((res) => setTickets(res as unknown as PsaTicket[]));
  }, []);

  useEffect(() => {
    loadTickets();
  }, [loadTickets]);

  const handleCreateTicket = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    await createPsaTicket({
      title: newTitle.trim(),
      client_name: newClient,
      device_id: newDevice,
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
          <div className="metric-subtext">Connected to ITFlow instance</div>
        </div>

        <div className="glass-card">
          <div className="metric-title">AUTO-RESOLVED VIA RUNBOOKS</div>
          <div className="metric-value" style={{ color: '#34d399' }}>
            {23 + tickets.filter((t) => t.status === 'Resolved').length}
          </div>
          <div className="metric-subtext">Auto-closed upon self-healing condition resolution</div>
        </div>

        <div className="glass-card">
          <div className="metric-title">API WEBHOOK BUS</div>
          <div className="metric-value" style={{ color: '#38bdf8' }}>Active</div>
          <div className="metric-subtext">Listening on /api/psa/webhook</div>
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
                    <span
                      className={`status-pill ${
                        t.status === 'Resolved' ? 'status-online' : 'status-reboot'
                      }`}
                    >
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
                <select className="glass-select" value={newClient} onChange={(e) => setNewClient(e.target.value)}>
                  <option value="Apex Financial Partners">Apex Financial Partners</option>
                  <option value="NovaBio Diagnostics">NovaBio Diagnostics</option>
                  <option value="Vanguard Logistics">Vanguard Logistics</option>
                </select>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Endpoint Hostname / ID
                  </label>
                  <input
                    type="text"
                    className="glass-input"
                    value={newDevice}
                    onChange={(e) => setNewDevice(e.target.value)}
                  />
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
