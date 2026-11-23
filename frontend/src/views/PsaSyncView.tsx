import React, { useState, useEffect, useCallback } from 'react';
import { Plus, CheckCircle2, X, Clock, Plug, Trash2, RefreshCw } from 'lucide-react';
import {
  fetchPsaTickets,
  createPsaTicket,
  updatePsaTicket,
  fetchTenants,
  fetchDevices,
  fetchPsaIntegrations,
  createPsaIntegration,
  testPsaIntegration,
  deletePsaIntegration,
  fetchTicketTimeEntries,
  addTicketTimeEntry,
  deleteTicketTimeEntry
} from '../services/api.js';
import { Tenant, Device, PsaIntegration, PsaTimeEntry, AuthUser } from '../types/index.js';
import { canMutateFleet, isSuperAdmin as checkIsSuperAdmin } from '../utils/permissions.js';

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
  currentUser?: AuthUser | null;
}

export const PsaSyncView: React.FC<PsaSyncViewProps> = ({ tenants: propTenants, devices: propDevices, currentUser }) => {
  const canMutate = canMutateFleet(currentUser);
  const isSuperAdmin = Boolean(currentUser && checkIsSuperAdmin(currentUser));
  const [activeTab, setActiveTab] = useState<'tickets' | 'connectors'>('tickets');
  const [tickets, setTickets] = useState<PsaTicket[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>(propTenants || []);
  const [devices, setDevices] = useState<Device[]>(propDevices || []);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newClient, setNewClient] = useState('');
  const [newDeviceId, setNewDeviceId] = useState('');
  const [newPriority, setNewPriority] = useState('High');

  // Multi-PSA Connectors state
  const [integrations, setIntegrations] = useState<PsaIntegration[]>([]);
  const [showAddConnector, setShowAddConnector] = useState(false);
  const [connName, setConnName] = useState('');
  const [connProvider, setConnProvider] = useState<PsaIntegration['provider']>('halopsa');
  const [connBaseUrl, setConnBaseUrl] = useState('');
  const [connApiKey, setConnApiKey] = useState('');
  const [connClientId, setConnClientId] = useState('');
  const [connectorNotice, setConnectorNotice] = useState<string | null>(null);

  // Technician Time Entries Drawer state
  const [selectedTicketForTime, setSelectedTicketForTime] = useState<PsaTicket | null>(null);
  const [timeEntries, setTimeEntries] = useState<PsaTimeEntry[]>([]);
  const [minutesSpent, setMinutesSpent] = useState(30);
  const [billable, setBillable] = useState(true);
  const [workNotes, setWorkNotes] = useState('');

  const loadTickets = useCallback(() => {
    fetchPsaTickets()
      .then((res) => setTickets(res as unknown as PsaTicket[]))
      .catch(() => {});
  }, []);

  const loadIntegrations = useCallback(() => {
    fetchPsaIntegrations()
      .then(setIntegrations)
      .catch(() => {});
  }, []);

  useEffect(() => {
    loadTickets();
    if (isSuperAdmin) loadIntegrations();
    if (!propTenants) {
      fetchTenants()
        .then((t) => {
          setTenants(t);
          if (t[0]) setNewClient((prev) => prev || t[0].name);
        })
        .catch(() => {});
    } else {
      setTenants(propTenants);
      if (propTenants[0]) setNewClient((prev) => prev || propTenants[0].name);
    }
    if (!propDevices) {
      fetchDevices()
        .then(setDevices)
        .catch(() => {});
    } else {
      setDevices(propDevices);
    }
  }, [loadTickets, loadIntegrations, isSuperAdmin, propTenants, propDevices]);

  const resolveDeviceLabel = (deviceId?: string) => {
    if (!deviceId) return 'System Fleet';
    const match = devices.find((d) => d.id === deviceId || d.hostname === deviceId);
    return match ? `${match.hostname} (${match.ip_address})` : deviceId;
  };

  const handleCreateTicket = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    await createPsaTicket({
      title: newTitle.trim(),
      client_name: newClient.trim() || 'General MSP Service Desk',
      device_id: newDeviceId.trim() || undefined,
      priority: newPriority
    });
    loadTickets();
    setShowCreateModal(false);
    setNewTitle('');
    setNewDeviceId('');
  };

  const handleToggleStatus = async (t: PsaTicket) => {
    const nextStatus = t.status === 'Resolved' ? 'Open' : 'Resolved';
    await updatePsaTicket(t.id, { status: nextStatus });
    loadTickets();
  };

  const handleOpenTimeModal = async (t: PsaTicket) => {
    setSelectedTicketForTime(t);
    const entries = await fetchTicketTimeEntries(t.id).catch(() => []);
    setTimeEntries(entries);
  };

  const handleAddTimeEntry = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedTicketForTime || minutesSpent <= 0) return;
    const res = await addTicketTimeEntry(selectedTicketForTime.id, {
      minutes_spent: minutesSpent,
      billable,
      notes: workNotes.trim() || 'Remote diagnostics and remediation'
    });
    if (res.success) {
      const updated = await fetchTicketTimeEntries(selectedTicketForTime.id).catch(() => []);
      setTimeEntries(updated);
      setWorkNotes('');
    }
  };

  const handleDeleteTimeEntry = async (entryId: string) => {
    if (!selectedTicketForTime) return;
    if (!confirm('Delete this logged time entry?')) return;
    try {
      const res: any = await deleteTicketTimeEntry(entryId);
      if (res?.success === false) {
        setConnectorNotice(`⚠ Failed to delete time entry: ${res.error || 'Request rejected'}`);
        return;
      }
      setTimeEntries((prev) => prev.filter((item) => item.id !== entryId));
    } catch (err: any) {
      setConnectorNotice(`⚠ Failed to delete time entry: ${err?.message || 'Network error'}`);
    }
  };

  const handleCreateConnector = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!connName.trim() || !connBaseUrl.trim()) return;
    const res = await createPsaIntegration({
      name: connName.trim(),
      provider: connProvider,
      base_url: connBaseUrl.trim(),
      api_key: connApiKey.trim() || undefined,
      client_id: connClientId.trim() || undefined,
      enabled: true,
      auto_sync_tickets: true
    });
    if (res.success) {
      loadIntegrations();
      setShowAddConnector(false);
      setConnName('');
      setConnBaseUrl('');
      setConnApiKey('');
      setConnClientId('');
      setConnectorNotice(`PSA connector "${connName.trim()}" saved with AES-256-GCM credential encryption.`);
    }
  };

  const handleTestConnector = async (id: string) => {
    const res = await testPsaIntegration(id);
    setConnectorNotice(
      res.success
        ? `✓ Connector verified (${res.status || 200}): ${res.message || 'Endpoint reachable'}`
        : `⚠ Connector test failed: ${res.error || res.message || 'Unreachable'}`
    );
    loadIntegrations();
  };

  const handleDeleteConnector = async (id: string) => {
    if (!confirm('Delete this PSA connector integration?')) return;
    try {
      const res: any = await deletePsaIntegration(id);
      if (res?.success === false) {
        setConnectorNotice(`⚠ Failed to delete PSA connector: ${res.error || 'Request rejected'}`);
        return;
      }
      setConnectorNotice('PSA connector deleted.');
      loadIntegrations();
    } catch (err: any) {
      setConnectorNotice(`⚠ Failed to delete PSA connector: ${err?.message || 'Network error'}`);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="psa-sync-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
            Service Desk Tickets &amp; Time Tracking
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            {isSuperAdmin && activeTab === 'connectors'
              ? 'Manage outbound PSA webhooks and API bridges (HaloPSA, ConnectWise, Autotask, Syncro, Zammad, ITFlow)'
              : 'Create and manage support tickets, incident escalations, and technician billable time entries'}
          </span>
        </div>
        <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
          <button
            className={`btn-glass ${activeTab === 'tickets' ? 'btn-primary' : ''}`}
            onClick={() => setActiveTab('tickets')}
          >
            Service Tickets ({tickets.length})
          </button>
          {isSuperAdmin && (
            <button
              className={`btn-glass ${activeTab === 'connectors' ? 'btn-primary' : ''}`}
              onClick={() => setActiveTab('connectors')}
            >
              <Plug size={14} /> PSA Connectors ({integrations.length})
            </button>
          )}
          {canMutate &&
            (activeTab === 'tickets' || !isSuperAdmin ? (
              <button className="btn-glass btn-primary" onClick={() => setShowCreateModal(true)}>
                <Plus size={15} /> Create Support Ticket
              </button>
            ) : (
              <button className="btn-glass btn-primary" onClick={() => setShowAddConnector(true)}>
                <Plus size={15} /> Add PSA Connector
              </button>
            ))}
        </div>
      </div>

      <div className="metrics-grid">
        <div className="glass-card">
          <div className="metric-title">SERVICE TICKETS</div>
          <div className="metric-value" style={{ color: 'var(--primary)' }}>{tickets.length}</div>
          <div className="metric-subtext">Active &amp; historical service desk queue</div>
        </div>

        <div className="glass-card">
          <div className="metric-title">RESOLVED TICKETS</div>
          <div className="metric-value" style={{ color: '#34d399' }}>
            {tickets.filter((t) => t.status === 'Resolved').length}
          </div>
          <div className="metric-subtext">Closed manually or via condition auto-resolution</div>
        </div>

        <div className="glass-card">
          <div className="metric-title">OPEN TICKETS</div>
          <div className="metric-value" style={{ color: '#38bdf8' }}>
            {tickets.filter((t) => t.status !== 'Resolved').length}
          </div>
          <div className="metric-subtext">Awaiting technician triage or completion</div>
        </div>
      </div>

      {connectorNotice && (() => {
        const isConnErr = connectorNotice.startsWith('⚠') || /error|fail|unreach/i.test(connectorNotice);
        return (
          <div
            className="glass-card"
            style={{
              padding: '0.75rem 1.15rem',
              fontSize: '0.82rem',
              background: isConnErr ? 'rgba(239, 68, 68, 0.12)' : undefined,
              color: isConnErr ? '#fca5a5' : '#7dd3fc',
              borderColor: isConnErr ? 'rgba(239, 68, 68, 0.35)' : 'rgba(56, 189, 248, 0.35)'
            }}
          >
            {connectorNotice}
          </div>
        );
      })()}

      {activeTab === 'tickets' && (
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
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {tickets.map((t) => (
                  <tr key={t.id}>
                    <td><strong>{t.ticket_number}</strong></td>
                    <td>{t.title}</td>
                    <td>{t.client_name}</td>
                    <td><code>{resolveDeviceLabel(t.device_id)}</code></td>
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
                      {canMutate ? (
                        <div style={{ display: 'inline-flex', gap: '0.4rem' }}>
                          <button
                            className="btn-glass"
                            style={{ padding: '0.25rem 0.6rem', fontSize: '0.74rem' }}
                            onClick={() => handleOpenTimeModal(t)}
                            title="Log technician billable/non-billable time entry"
                          >
                            <Clock size={12} /> Log Time
                          </button>
                          <button
                            className="btn-glass"
                            style={{ padding: '0.25rem 0.65rem', fontSize: '0.74rem' }}
                            onClick={() => handleToggleStatus(t)}
                          >
                            <CheckCircle2 size={12} /> {t.status === 'Resolved' ? 'Reopen' : 'Resolve'}
                          </button>
                        </div>
                      ) : (
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Read-Only</span>
                      )}
                    </td>
                  </tr>
                ))}
                {tickets.length === 0 && (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                      No service tickets recorded yet. Automated alert tickets and manual tickets will appear here.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {isSuperAdmin && activeTab === 'connectors' && (
        <div className="glass-card" style={{ padding: 0 }}>
          <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
            <table className="glass-table">
              <thead>
                <tr>
                  <th>Connector Name</th>
                  <th>PSA Platform</th>
                  <th>API Endpoint</th>
                  <th>Vaulted Secret</th>
                  <th>Last Sync</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {integrations.map((c) => (
                  <tr key={c.id}>
                    <td><strong>{c.name}</strong></td>
                    <td>
                      <span className="status-pill status-online" style={{ fontSize: '0.72rem' }}>
                        {c.provider.toUpperCase()}
                      </span>
                    </td>
                    <td><code>{c.base_url}</code></td>
                    <td>
                      <span style={{ color: c.has_api_key || Boolean(c.api_key) ? '#34d399' : '#94a3b8', fontSize: '0.78rem' }}>
                        {c.has_api_key || Boolean(c.api_key) ? 'AES-256-GCM Encrypted' : 'Unauthenticated / Headerless'}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.76rem', color: 'var(--text-dim)' }}>
                      {c.last_status || 'Ready'}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      {canMutate ? (
                        <div style={{ display: 'inline-flex', gap: '0.4rem' }}>
                          <button
                            className="btn-glass"
                            style={{ padding: '0.22rem 0.55rem', fontSize: '0.74rem' }}
                            onClick={() => handleTestConnector(c.id)}
                          >
                            <RefreshCw size={12} /> Test API
                          </button>
                          <button
                            className="btn-glass btn-icon"
                            onClick={() => handleDeleteConnector(c.id)}
                            title="Delete PSA Connector"
                          >
                            <Trash2 size={13} color="#ef4444" />
                          </button>
                        </div>
                      ) : (
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Read-Only</span>
                      )}
                    </td>
                  </tr>
                ))}
                {integrations.length === 0 && (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                      No outbound PSA connectors configured yet. Click &quot;Add PSA Connector&quot; to connect HaloPSA, ConnectWise, Autotask, Syncro, Zammad, or ITFlow.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Create Ticket Modal */}
      {showCreateModal && (
        <div className="modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="glass-modal" style={{ maxWidth: '460px', padding: '1.5rem' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>Create Support Ticket</h3>
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
                    <select className="glass-select" value={newDeviceId} onChange={(e) => setNewDeviceId(e.target.value)}>
                      <option value="">System / General</option>
                      {devices.map((dev) => (
                        <option key={dev.id} value={dev.id}>
                          {dev.hostname} ({dev.ip_address})
                        </option>
                      ))}
                    </select>
                  ) : (
                    <input
                      type="text"
                      className="glass-input"
                      placeholder="Device ID"
                      value={newDeviceId}
                      onChange={(e) => setNewDeviceId(e.target.value)}
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

      {/* Add Multi-PSA Connector Modal */}
      {showAddConnector && (
        <div className="modal-overlay" onClick={() => setShowAddConnector(false)}>
          <div className="glass-modal" style={{ maxWidth: '500px', padding: '1.5rem' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>Configure Multi-PSA API Bridge</h3>
              <button className="btn-glass btn-icon" onClick={() => setShowAddConnector(false)}>
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleCreateConnector} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Connector Label
                  </label>
                  <input
                    type="text"
                    required
                    className="glass-input"
                    placeholder="e.g. Primary HaloPSA"
                    value={connName}
                    onChange={(e) => setConnName(e.target.value)}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    PSA Platform
                  </label>
                  <select className="glass-select" value={connProvider} onChange={(e) => setConnProvider(e.target.value as any)}>
                    <option value="halopsa">HaloPSA</option>
                    <option value="connectwise">ConnectWise Manage</option>
                    <option value="autotask">Datto Autotask PSA</option>
                    <option value="syncro">SyncroMSP</option>
                    <option value="zammad">Zammad Helpdesk</option>
                    <option value="itflow">ITFlow</option>
                    <option value="generic_webhook">Generic JSON Webhook</option>
                  </select>
                </div>
              </div>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  PSA Base URL / Webhook Endpoint
                </label>
                <input
                  type="url"
                  required
                  className="glass-input"
                  placeholder="https://psa.yourmsp.com/api"
                  value={connBaseUrl}
                  onChange={(e) => setConnBaseUrl(e.target.value)}
                />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Client ID / Company ID (Optional)
                  </label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="OAuth Client / Company ID"
                    value={connClientId}
                    onChange={(e) => setConnClientId(e.target.value)}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    API Key / Secret (Encrypted)
                  </label>
                  <input
                    type="password"
                    className="glass-input"
                    placeholder="••••••••••••••••"
                    value={connApiKey}
                    onChange={(e) => setConnApiKey(e.target.value)}
                  />
                </div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button type="button" className="btn-glass" onClick={() => setShowAddConnector(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-glass btn-primary">
                  Save Connector
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Technician Time Entries Modal */}
      {selectedTicketForTime && (
        <div className="modal-overlay" onClick={() => setSelectedTicketForTime(null)}>
          <div className="glass-modal" style={{ maxWidth: '560px', padding: '1.5rem' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '1.08rem', fontWeight: 700 }}>
                  Technician Time Entries — {selectedTicketForTime.ticket_number}
                </h3>
                <span style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                  {selectedTicketForTime.title}
                </span>
              </div>
              <button className="btn-glass btn-icon" onClick={() => setSelectedTicketForTime(null)}>
                <X size={16} />
              </button>
            </div>

            {canMutate && (
              <form onSubmit={handleAddTimeEntry} style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginBottom: '1.1rem', paddingBottom: '1rem', borderBottom: '1px solid var(--glass-border)' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '130px 1fr', gap: '0.75rem', alignItems: 'end' }}>
                  <div>
                    <label style={{ fontSize: '0.75rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                      Minutes Spent
                    </label>
                    <input
                      type="number"
                      min={1}
                      max={1440}
                      className="glass-input"
                      value={minutesSpent}
                      onChange={(e) => setMinutesSpent(Number(e.target.value))}
                    />
                  </div>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', cursor: 'pointer', fontSize: '0.82rem', paddingBottom: '0.45rem' }}>
                    <input type="checkbox" checked={billable} onChange={(e) => setBillable(e.target.checked)} />
                    <span>Billable Service Time</span>
                  </label>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="Work performed / resolution summary..."
                    value={workNotes}
                    onChange={(e) => setWorkNotes(e.target.value)}
                  />
                  <button type="submit" className="btn-glass btn-primary" style={{ whiteSpace: 'nowrap' }}>
                    <Plus size={14} /> Log Time
                  </button>
                </div>
              </form>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '240px', overflowY: 'auto' }}>
              {timeEntries.length === 0 ? (
                <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)', textAlign: 'center', padding: '1rem' }}>
                  No time entries logged on this ticket yet.
                </div>
              ) : (
                timeEntries.map((te) => (
                  <div
                    key={te.id}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      padding: '0.6rem 0.85rem',
                      borderRadius: '8px',
                      background: 'rgba(255, 255, 255, 0.03)',
                      border: '1px solid var(--glass-border)',
                      fontSize: '0.78rem'
                    }}
                  >
                    <div>
                      <div>
                        <strong>{te.technician}</strong> • <span style={{ color: '#38bdf8' }}>{te.minutes_spent ?? te.minutes}m</span>{' '}
                        <span style={{ color: te.billable ? '#34d399' : '#94a3b8' }}>
                          ({te.billable ? 'Billable' : 'Non-Billable'})
                        </span>
                      </div>
                      <div style={{ color: 'var(--text-muted)', marginTop: '0.15rem' }}>{te.notes}</div>
                    </div>
                    {canMutate && (
                      <button className="btn-glass btn-icon" onClick={() => handleDeleteTimeEntry(te.id)}>
                        <Trash2 size={12} color="#ef4444" />
                      </button>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
