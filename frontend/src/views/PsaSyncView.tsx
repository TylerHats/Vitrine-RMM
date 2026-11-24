import React, { useState, useEffect, useCallback } from 'react';
import {
  Plus,
  CheckCircle2,
  X,
  Clock,
  Plug,
  Trash2,
  RefreshCw,
  Edit3,
  MessageSquare,
  Sparkles,
  Server,
  AlertTriangle
} from 'lucide-react';
import {
  fetchPsaTickets,
  createPsaTicket,
  updatePsaTicket,
  fetchPsaTicketNotes,
  addPsaTicketNote,
  fetchTenants,
  fetchDevices,
  fetchPsaIntegrations,
  createPsaIntegration,
  testPsaIntegration,
  deletePsaIntegration,
  fetchTicketTimeEntries,
  addTicketTimeEntry,
  deleteTicketTimeEntry,
  fetchItflowStatus,
  discoverItflowClients,
  applyItflowMappings,
  triggerItflowAssetSync,
  triggerItflowTicketPull
} from '../services/api.js';
import {
  Tenant,
  Device,
  PsaIntegration,
  PsaTimeEntry,
  PsaTicketNote,
  ItflowClientRecord,
  AuthUser
} from '../types/index.js';
import { canMutateFleet, isSuperAdmin as checkIsSuperAdmin } from '../utils/permissions.js';
import { ItflowSetupWizardModal } from '../components/ItflowSetupWizardModal.js';

interface PsaTicket {
  id: string;
  ticket_number: string;
  title: string;
  description?: string;
  client_name: string;
  device_id?: string;
  priority: string;
  status: string;
  external_provider?: string | null;
  external_ticket_id?: string | null;
  external_client_id?: number | null;
  external_asset_id?: number | null;
}

interface PsaSyncViewProps {
  tenants?: Tenant[];
  devices?: Device[];
  currentUser?: AuthUser | null;
}

export const PsaSyncView: React.FC<PsaSyncViewProps> = ({ tenants: propTenants, devices: propDevices, currentUser }) => {
  const canMutate = canMutateFleet(currentUser);
  const isSuperAdmin = Boolean(currentUser && checkIsSuperAdmin(currentUser));
  const [activeTab, setActiveTab] = useState<'tickets' | 'itflow' | 'connectors'>('tickets');
  const [tickets, setTickets] = useState<PsaTicket[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>(propTenants || []);
  const [devices, setDevices] = useState<Device[]>(propDevices || []);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newClient, setNewClient] = useState('');
  const [newDeviceId, setNewDeviceId] = useState('');
  const [newPriority, setNewPriority] = useState('High');

  // Edit Ticket & Notes modal state
  const [editingTicket, setEditingTicket] = useState<PsaTicket | null>(null);
  const [editTitle, setEditTitle] = useState('');
  const [editDescription, setEditDescription] = useState('');
  const [editStatus, setEditStatus] = useState('Open');
  const [editPriority, setEditPriority] = useState('Medium');
  const [ticketNotes, setTicketNotes] = useState<PsaTicketNote[]>([]);
  const [noteBody, setNoteBody] = useState('');
  const [noteType, setNoteType] = useState<'Internal' | 'Public'>('Internal');
  const [noteMinutes, setNoteMinutes] = useState(0);
  const [savingTicket, setSavingTicket] = useState(false);

  // ITFlow guided setup & live client mapping state
  const [showItflowWizard, setShowItflowWizard] = useState(false);
  const [itflowStatus, setItflowStatus] = useState<any>(null);
  const [itflowClients, setItflowClients] = useState<ItflowClientRecord[]>([]);
  const [syncingAssets, setSyncingAssets] = useState(false);
  const [pullingTickets, setPullingTickets] = useState(false);
  const [remapModal, setRemapModal] = useState<{
    tenantId: string;
    tenantName: string;
    currentClientId: number | null;
    currentClientName: string | null;
    syncedAssetCount: number;
    action: 'link' | 'create_new' | 'disable';
    itflowClientId: number | null;
    itflowClientName: string | null;
    onExistingAssets: 'move' | 'duplicate';
    newClientName: string;
    newContactName: string;
    newContactEmail: string;
    newLocationName: string;
    newAddress: string;
  } | null>(null);

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

  const loadItflowState = useCallback(() => {
    fetchItflowStatus()
      .then((st) => {
        setItflowStatus(st);
        if (st.url && st.hasApiKey) {
          discoverItflowClients()
            .then((d) => {
              if (d.success && Array.isArray(d.clients)) setItflowClients(d.clients);
            })
            .catch(() => {});
        }
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    loadTickets();
    if (isSuperAdmin) {
      loadIntegrations();
      loadItflowState();
    }
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
      description: newDescription.trim() || undefined,
      client_name: newClient.trim() || 'General MSP Service Desk',
      device_id: newDeviceId.trim() || undefined,
      priority: newPriority
    });
    loadTickets();
    setShowCreateModal(false);
    setNewTitle('');
    setNewDescription('');
    setNewDeviceId('');
  };

  const handleOpenEditTicket = async (t: PsaTicket) => {
    setEditingTicket(t);
    setEditTitle(t.title);
    setEditDescription(t.description || '');
    setEditStatus(t.status);
    setEditPriority(t.priority);
    setNoteBody('');
    setNoteMinutes(0);
    const notes = await fetchPsaTicketNotes(t.id).catch(() => []);
    setTicketNotes(notes);
  };

  const handleSaveTicketEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingTicket) return;
    setSavingTicket(true);
    try {
      await updatePsaTicket(editingTicket.id, {
        title: editTitle.trim(),
        description: editDescription,
        status: editStatus,
        priority: editPriority
      });
      loadTickets();
      setConnectorNotice(`✓ Ticket ${editingTicket.ticket_number} updated.`);
      setEditingTicket((prev) =>
        prev
          ? { ...prev, title: editTitle.trim(), description: editDescription, status: editStatus, priority: editPriority }
          : null
      );
    } finally {
      setSavingTicket(false);
    }
  };

  const handleSubmitTicketNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingTicket || !noteBody.trim()) return;
    setSavingTicket(true);
    try {
      const res = await addPsaTicketNote(editingTicket.id, {
        body: noteBody.trim(),
        note_type: noteType,
        time_worked_sec: Math.max(0, noteMinutes) * 60
      });
      if (res.success) {
        const refreshed = await fetchPsaTicketNotes(editingTicket.id).catch(() => []);
        setTicketNotes(refreshed);
        setNoteBody('');
        setNoteMinutes(0);
        if (res.syncedExternal) {
          setConnectorNotice(`✓ Note added & synced to ITFlow Ticket #${editingTicket.external_ticket_id}.`);
        }
      }
    } finally {
      setSavingTicket(false);
    }
  };

  const handleSyncAssetsNow = async () => {
    setSyncingAssets(true);
    try {
      const res = await triggerItflowAssetSync({ force: false });
      setConnectorNotice(
        res.success
          ? `✓ ITFlow Asset Sync complete: ${res.created} created, ${res.updated} updated, ${res.skipped} unchanged, ${res.failed} failed.`
          : `⚠ Asset sync failed: ${res.error || 'Error'}`
      );
      loadItflowState();
    } finally {
      setSyncingAssets(false);
    }
  };

  const handlePullItflowTickets = async () => {
    setPullingTickets(true);
    try {
      const res = await triggerItflowTicketPull();
      if (res.success) {
        setConnectorNotice(
          `✓ ITFlow Ticket Pull complete (${res.checked} checked): ${res.updatedTickets} ticket(s) updated, ${res.importedNotes} new note(s) imported.`
        );
        loadTickets();
        if (editingTicket) {
          const refreshedNotes = await fetchPsaTicketNotes(editingTicket.id).catch(() => null);
          if (refreshedNotes) setTicketNotes(refreshedNotes);
        }
      } else {
        setConnectorNotice(`⚠ Ticket pull failed: ${res.error || res.errors?.[0] || 'Error'}`);
      }
    } finally {
      setPullingTickets(false);
    }
  };

  const handleSelectTenantMappingChange = async (
    m: any,
    nextAction: 'link' | 'create_new' | 'disable',
    nextClientId: number | null
  ) => {
    const targetClient = itflowClients.find((c) => c.client_id === nextClientId);
    const hasSynced = Number(m.synced_asset_count || 0) > 0;
    const changedClient =
      nextAction === 'create_new' ||
      (nextAction === 'disable' && m.itflow_client_id !== null) ||
      (nextAction === 'link' && m.itflow_client_id !== null && nextClientId !== m.itflow_client_id);

    if (nextAction === 'create_new' || (hasSynced && changedClient)) {
      setRemapModal({
        tenantId: m.tenant_id,
        tenantName: m.tenant_name,
        currentClientId: m.itflow_client_id,
        currentClientName: m.itflow_client_name,
        syncedAssetCount: Number(m.synced_asset_count || 0),
        action: nextAction,
        itflowClientId: nextClientId,
        itflowClientName: targetClient?.client_name || null,
        onExistingAssets: 'duplicate',
        newClientName: m.tenant_name,
        newContactName: '',
        newContactEmail: m.tenant_contact_email || '',
        newLocationName: 'Primary Office',
        newAddress: ''
      });
      return;
    }

    const res = await applyItflowMappings({
      assignments: [
        {
          tenantId: m.tenant_id,
          action: nextAction,
          itflowClientId: nextClientId,
          itflowClientName: targetClient?.client_name || null
        }
      ],
      triggerInitialSync: nextAction !== 'disable'
    });
    if (res.success) {
      setConnectorNotice(`✓ Updated ITFlow sync mapping for ${m.tenant_name}.`);
      loadItflowState();
    } else {
      setConnectorNotice(`⚠ ${res.error || 'Failed to update client mapping'}`);
    }
  };

  const handleConfirmRemapModal = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!remapModal) return;
    const res = await applyItflowMappings({
      assignments: [
        {
          tenantId: remapModal.tenantId,
          action: remapModal.action,
          itflowClientId: remapModal.action === 'link' ? remapModal.itflowClientId : null,
          itflowClientName: remapModal.action === 'link' ? remapModal.itflowClientName : null,
          onExistingAssets: remapModal.syncedAssetCount > 0 ? remapModal.onExistingAssets : undefined,
          newClient:
            remapModal.action === 'create_new'
              ? {
                  name: remapModal.newClientName.trim(),
                  contactName: remapModal.newContactName.trim(),
                  email: remapModal.newContactEmail.trim(),
                  locationName: remapModal.newLocationName.trim() || 'Primary Office',
                  address: remapModal.newAddress.trim()
                }
              : undefined
        }
      ],
      triggerInitialSync: remapModal.action !== 'disable'
    });
    if (res.success) {
      const moved = res.mappingResult?.assetsMovedDeletedOld || 0;
      setConnectorNotice(
        `✓ Updated mapping for ${remapModal.tenantName}${moved > 0 ? ` (${moved} prior asset(s) deleted & moved)` : ''}.`
      );
      setRemapModal(null);
      loadItflowState();
    } else {
      setConnectorNotice(`⚠ ${res.error || 'Failed applying remapping'}`);
    }
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
              className={`btn-glass ${activeTab === 'itflow' ? 'btn-primary' : ''}`}
              onClick={() => setActiveTab('itflow')}
            >
              <Sparkles size={14} /> ITFlow Sync ({itflowStatus?.mappings?.filter((m: any) => m.sync_enabled).length || 0})
            </button>
          )}
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
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                {itflowStatus?.enabled && (
                  <button
                    type="button"
                    className="btn-glass"
                    disabled={pullingTickets}
                    onClick={handlePullItflowTickets}
                    title="Pull latest ticket status updates & replies from ITFlow"
                  >
                    <RefreshCw size={14} className={pullingTickets ? 'animate-spin' : ''} />
                    <span>{pullingTickets ? 'Pulling ITFlow...' : 'Pull ITFlow Ticket Updates'}</span>
                  </button>
                )}
                <button className="btn-glass btn-primary" onClick={() => setShowCreateModal(true)}>
                  <Plus size={15} /> Create Support Ticket
                </button>
              </div>
            ) : activeTab === 'itflow' ? (
              <button className="btn-glass btn-primary" onClick={() => setShowItflowWizard(true)}>
                <Sparkles size={15} /> Guided Setup Wizard
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
              background: isConnErr ? 'rgba(239, 68, 68, 0.12)' : 'rgba(14, 165, 233, 0.1)',
              color: isConnErr ? '#ef4444' : '#0284c7',
              borderColor: isConnErr ? 'rgba(239, 68, 68, 0.35)' : 'rgba(14, 165, 233, 0.35)'
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
                    <td>
                      <strong>{t.ticket_number}</strong>
                      {t.external_provider === 'itflow' && t.external_ticket_id && (
                        <div style={{ fontSize: '0.67rem', color: '#38bdf8', marginTop: '0.15rem' }}>
                          ITFlow #{t.external_ticket_id}
                        </div>
                      )}
                    </td>
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
                            onClick={() => handleOpenEditTicket(t)}
                            title="Edit ticket properties & view/add ITFlow notes"
                          >
                            <Edit3 size={12} /> Edit &amp; Notes
                          </button>
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

      {isSuperAdmin && activeTab === 'itflow' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div className="glass-card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <Server size={18} color="var(--primary)" />
                <strong style={{ fontSize: '1rem' }}>ITFlow Bi-Directional Ticket &amp; Asset Sync</strong>
                <span className={`status-pill ${itflowStatus?.enabled && itflowStatus?.setupCompleted ? 'status-online' : 'status-reboot'}`}>
                  {itflowStatus?.enabled && itflowStatus?.setupCompleted ? 'Configured & Active' : 'Setup Incomplete'}
                </span>
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>
                Endpoint: <code>{itflowStatus?.apiBase || 'Not set'}</code> • Sync Interval: Every {itflowStatus?.syncIntervalMin || 60}m
                {itflowStatus?.lastAssetSyncSummary ? ` • Last Sync: ${itflowStatus.lastAssetSyncSummary}` : ''}
              </div>
            </div>
            <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
              <button
                type="button"
                className="btn-glass"
                disabled={pullingTickets || !itflowStatus?.enabled}
                onClick={handlePullItflowTickets}
              >
                <RefreshCw size={14} className={pullingTickets ? 'animate-spin' : ''} />
                <span>{pullingTickets ? 'Pulling Tickets...' : 'Pull ITFlow Ticket Updates'}</span>
              </button>
              <button
                type="button"
                className="btn-glass"
                disabled={syncingAssets || !itflowStatus?.enabled}
                onClick={handleSyncAssetsNow}
              >
                <RefreshCw size={14} className={syncingAssets ? 'animate-spin' : ''} />
                <span>{syncingAssets ? 'Syncing Assets...' : 'Sync All Assets Now'}</span>
              </button>
              <button type="button" className="btn-glass btn-primary" onClick={() => setShowItflowWizard(true)}>
                <Sparkles size={14} /> Launch Guided Setup Wizard
              </button>
            </div>
          </div>

          <div className="glass-card" style={{ padding: 0 }}>
            <div style={{ padding: '0.85rem 1.15rem', borderBottom: '1px solid var(--glass-border)', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
              Client Sync Mapping Overrides — Change any Vitrine client between existing ITFlow clients, Create New ITFlow Client, or Disable Sync anytime. Moving away from a synced client prompts Move vs Duplicate assets.
            </div>
            <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
              <table className="glass-table">
                <thead>
                  <tr>
                    <th>Vitrine Organization</th>
                    <th>Devices / Linked Assets</th>
                    <th>Sync Mode</th>
                    <th>Target ITFlow Client</th>
                  </tr>
                </thead>
                <tbody>
                  {(itflowStatus?.mappings || []).map((m: any) => (
                    <tr key={m.tenant_id}>
                      <td><strong>{m.tenant_name}</strong></td>
                      <td style={{ fontSize: '0.8rem' }}>
                        {m.device_count} devices / <span style={{ color: '#34d399' }}>{m.synced_asset_count} synced</span>
                      </td>
                      <td>
                        <select
                          className="glass-select"
                          style={{ fontSize: '0.76rem', padding: '0.25rem 0.45rem' }}
                          value={!m.sync_enabled ? 'disable' : 'link'}
                          disabled={itflowClients.length === 0}
                          onChange={(e) => {
                            const act = e.target.value as 'link' | 'create_new' | 'disable';
                            const nextId = act === 'link' ? m.itflow_client_id || itflowClients[0]?.client_id || null : null;
                            handleSelectTenantMappingChange(m, act, nextId);
                          }}
                        >
                          <option value="link">Sync to ITFlow Client</option>
                          <option value="create_new">+ Create New Client</option>
                          <option value="disable">Disable Sync</option>
                        </select>
                      </td>
                      <td>
                        {m.sync_enabled ? (
                          <select
                            className="glass-select"
                            style={{ fontSize: '0.76rem', padding: '0.25rem 0.45rem' }}
                            value={m.itflow_client_id || ''}
                            onChange={(e) =>
                              handleSelectTenantMappingChange(
                                m,
                                'link',
                                e.target.value ? Number(e.target.value) : null
                              )
                            }
                          >
                            <option value="">-- Select ITFlow Client --</option>
                            {m.itflow_client_id &&
                              !itflowClients.some((c) => c.client_id === m.itflow_client_id) && (
                                <option value={m.itflow_client_id}>
                                  {m.itflow_client_name || `Client #${m.itflow_client_id}`}
                                </option>
                              )}
                            {itflowClients.map((c) => (
                              <option key={c.client_id} value={c.client_id}>
                                {c.client_name} (#{c.client_id})
                              </option>
                            ))}
                          </select>
                        ) : (
                          <span style={{ fontSize: '0.76rem', color: 'var(--text-dim)' }}>Sync disabled for this client</span>
                        )}
                      </td>
                    </tr>
                  ))}
                  {(!itflowStatus?.mappings || itflowStatus.mappings.length === 0) && (
                    <tr>
                      <td colSpan={4} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                        Launch the Guided Setup Wizard to connect ITFlow and review client mappings.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
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
                  Detailed Incident Notes (Optional)
                </label>
                <textarea
                  className="glass-input"
                  rows={3}
                  placeholder="Initial diagnostic details or condition notes..."
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
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

      {/* Edit Ticket & ITFlow Notes Modal */}
      {editingTicket && (
        <div className="modal-overlay" onClick={() => setEditingTicket(null)}>
          <div className="glass-modal" style={{ maxWidth: '640px', width: '95vw', maxHeight: '88vh', overflowY: 'auto', padding: '1.5rem' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>
                  {editingTicket.ticket_number} — Edit Ticket &amp; Notes
                </h3>
                {editingTicket.external_provider === 'itflow' && editingTicket.external_ticket_id && (
                  <span style={{ fontSize: '0.74rem', color: '#38bdf8' }}>
                    Linked to ITFlow Ticket #{editingTicket.external_ticket_id}
                  </span>
                )}
              </div>
              <button className="btn-glass btn-icon" onClick={() => setEditingTicket(null)}>
                <X size={16} />
              </button>
            </div>

            <form onSubmit={handleSaveTicketEdit} style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', paddingBottom: '1rem', borderBottom: '1px solid var(--glass-border)', marginBottom: '1rem' }}>
              <div>
                <label className="form-label" style={{ fontSize: '0.74rem' }}>Subject</label>
                <input
                  type="text"
                  required
                  className="glass-input"
                  value={editTitle}
                  onChange={(e) => setEditTitle(e.target.value)}
                />
              </div>
              <div>
                <label className="form-label" style={{ fontSize: '0.74rem' }}>Description / Details</label>
                <textarea
                  className="glass-input"
                  rows={2}
                  value={editDescription}
                  onChange={(e) => setEditDescription(e.target.value)}
                />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: '0.65rem', alignItems: 'end' }}>
                <div>
                  <label className="form-label" style={{ fontSize: '0.74rem' }}>Status</label>
                  <select className="glass-select" value={editStatus} onChange={(e) => setEditStatus(e.target.value)}>
                    <option value="Open">Open</option>
                    <option value="In Progress">In Progress</option>
                    <option value="Resolved">Resolved</option>
                    <option value="Closed">Closed</option>
                  </select>
                </div>
                <div>
                  <label className="form-label" style={{ fontSize: '0.74rem' }}>Priority</label>
                  <select className="glass-select" value={editPriority} onChange={(e) => setEditPriority(e.target.value)}>
                    <option value="Low">Low</option>
                    <option value="Medium">Medium</option>
                    <option value="High">High</option>
                    <option value="Urgent">Urgent</option>
                    <option value="Critical">Critical</option>
                  </select>
                </div>
                <button type="submit" className="btn-glass btn-primary" disabled={savingTicket}>
                  Save Ticket Updates
                </button>
              </div>
            </form>

            <div>
              <h4 style={{ margin: '0 0 0.6rem 0', fontSize: '0.88rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <MessageSquare size={15} color="var(--primary)" />
                <span>Ticket Notes &amp; Worklog ({ticketNotes.length})</span>
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', maxHeight: '200px', overflowY: 'auto', marginBottom: '0.85rem' }}>
                {ticketNotes.length === 0 ? (
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', padding: '0.75rem', textAlign: 'center' }}>
                    No notes recorded yet.
                  </div>
                ) : (
                  ticketNotes.map((n) => (
                    <div
                      key={n.id}
                      style={{
                        padding: '0.6rem 0.8rem',
                        borderRadius: '8px',
                        background: 'rgba(255,255,255,0.03)',
                        border: '1px solid var(--glass-border)',
                        fontSize: '0.78rem'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.2rem' }}>
                        <span>
                          <strong>{n.author}</strong> •{' '}
                          <span className="status-pill status-online" style={{ fontSize: '0.64rem' }}>{n.note_type}</span>
                          {n.time_worked_sec > 0 && (
                            <span style={{ color: '#38bdf8', marginLeft: '0.4rem' }}>{Math.round(n.time_worked_sec / 60)}m</span>
                          )}
                        </span>
                        <span style={{ fontSize: '0.68rem', color: n.synced_external ? '#34d399' : 'var(--text-dim)' }}>
                          {n.synced_external ? 'Synced to ITFlow' : 'Local Only'}
                        </span>
                      </div>
                      <div style={{ whiteSpace: 'pre-wrap', color: 'var(--text-muted)' }}>{n.body}</div>
                    </div>
                  ))
                )}
              </div>

              {canMutate && (
                <form onSubmit={handleSubmitTicketNote} style={{ display: 'flex', flexDirection: 'column', gap: '0.55rem' }}>
                  <textarea
                    required
                    className="glass-input"
                    rows={2}
                    placeholder="Add technician progress note or resolution summary..."
                    value={noteBody}
                    onChange={(e) => setNoteBody(e.target.value)}
                  />
                  <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap' }}>
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                      <select
                        className="glass-select"
                        style={{ width: 'auto', fontSize: '0.76rem' }}
                        value={noteType}
                        onChange={(e) => setNoteType(e.target.value as 'Internal' | 'Public')}
                      >
                        <option value="Internal">Internal Note</option>
                        <option value="Public">Public Customer Reply</option>
                      </select>
                      <input
                        type="number"
                        min={0}
                        max={480}
                        className="glass-input"
                        style={{ width: '110px', fontSize: '0.76rem' }}
                        placeholder="Mins (opt)"
                        value={noteMinutes || ''}
                        onChange={(e) => setNoteMinutes(Number(e.target.value) || 0)}
                      />
                    </div>
                    <button type="submit" className="btn-glass btn-primary" disabled={savingTicket || !noteBody.trim()}>
                      <Plus size={14} /> Add Note
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Client Remapping Move vs Duplicate Prompt */}
      {remapModal && (
        <div className="modal-overlay" onClick={() => setRemapModal(null)}>
          <div className="glass-modal" style={{ maxWidth: '540px', padding: '1.5rem' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <AlertTriangle size={17} color="#fbbf24" />
                <span>Confirm ITFlow Client Change — {remapModal.tenantName}</span>
              </h3>
              <button className="btn-glass btn-icon" onClick={() => setRemapModal(null)}>
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleConfirmRemapModal} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              {remapModal.action === 'create_new' && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.55rem' }}>
                  <div>
                    <label className="form-label" style={{ fontSize: '0.72rem' }}>New ITFlow Client Name *</label>
                    <input
                      type="text"
                      required
                      className="glass-input"
                      value={remapModal.newClientName}
                      onChange={(e) => setRemapModal({ ...remapModal, newClientName: e.target.value })}
                    />
                  </div>
                  <div>
                    <label className="form-label" style={{ fontSize: '0.72rem' }}>Primary Contact Name</label>
                    <input
                      type="text"
                      className="glass-input"
                      value={remapModal.newContactName}
                      onChange={(e) => setRemapModal({ ...remapModal, newContactName: e.target.value })}
                    />
                  </div>
                  <div>
                    <label className="form-label" style={{ fontSize: '0.72rem' }}>Contact Email</label>
                    <input
                      type="email"
                      className="glass-input"
                      value={remapModal.newContactEmail}
                      onChange={(e) => setRemapModal({ ...remapModal, newContactEmail: e.target.value })}
                    />
                  </div>
                  <div>
                    <label className="form-label" style={{ fontSize: '0.72rem' }}>Primary Location Name</label>
                    <input
                      type="text"
                      className="glass-input"
                      value={remapModal.newLocationName}
                      onChange={(e) => setRemapModal({ ...remapModal, newLocationName: e.target.value })}
                    />
                  </div>
                </div>
              )}

              {remapModal.syncedAssetCount > 0 && (
                <div
                  style={{
                    padding: '0.85rem',
                    borderRadius: '8px',
                    background: 'rgba(245, 158, 11, 0.1)',
                    border: '1px solid rgba(245, 158, 11, 0.35)',
                    fontSize: '0.8rem',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.5rem'
                  }}
                >
                  <div>
                    <strong>{remapModal.syncedAssetCount} asset(s)</strong> were previously synced to{' '}
                    <strong>{remapModal.currentClientName}</strong>. Choose how Vitrine should handle them:
                  </div>
                  <label style={{ display: 'flex', alignItems: 'flex-start', gap: '0.45rem', cursor: 'pointer' }}>
                    <input
                      type="radio"
                      checked={remapModal.onExistingAssets === 'move'}
                      onChange={() => setRemapModal({ ...remapModal, onExistingAssets: 'move' })}
                    />
                    <span>
                      <strong>Move Assets</strong> — Delete the existing assets from <em>{remapModal.currentClientName}</em>{' '}
                      and create them under {remapModal.action === 'disable' ? 'no client (unlinked)' : 'the new client'}.
                    </span>
                  </label>
                  <label style={{ display: 'flex', alignItems: 'flex-start', gap: '0.45rem', cursor: 'pointer' }}>
                    <input
                      type="radio"
                      checked={remapModal.onExistingAssets === 'duplicate'}
                      onChange={() => setRemapModal({ ...remapModal, onExistingAssets: 'duplicate' })}
                    />
                    <span>
                      <strong>Duplicate / Keep Prior Assets</strong> — Leave existing assets untouched in{' '}
                      <em>{remapModal.currentClientName}</em> and create fresh records under the new destination.
                    </span>
                  </label>
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                <button type="button" className="btn-glass" onClick={() => setRemapModal(null)}>
                  Cancel
                </button>
                <button type="submit" className="btn-glass btn-primary">
                  Apply Mapping Change
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <ItflowSetupWizardModal
        isOpen={showItflowWizard}
        onClose={() => setShowItflowWizard(false)}
        onCompleted={() => {
          loadItflowState();
          loadTickets();
        }}
      />
    </div>
  );
};
