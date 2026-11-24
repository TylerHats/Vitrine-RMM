import React, { useState, useEffect } from 'react';
import {
  X,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  ArrowRight,
  ArrowLeft,
  Link2,
  PlusCircle,
  Ban,
  Sparkles,
  Server,
  KeyRound,
  Clock,
  ShieldCheck
} from 'lucide-react';
import {
  ItflowClientRecord,
  ItflowLocationRecord,
  ItflowTenantMappingSuggestion
} from '../types/index.js';
import {
  fetchItflowStatus,
  testItflowConnection,
  discoverItflowClients,
  saveItflowConfig,
  applyItflowMappings
} from '../services/api.js';

interface ItflowSetupWizardModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCompleted?: () => void;
}

interface DraftTenantAssignment {
  action: 'link' | 'create_new' | 'disable';
  itflowClientId: number | null;
  defaultLocationId: number | null;
  onExistingAssets: 'move' | 'duplicate';
  siteMappings: Record<string, { itflowLocationId: number | null; createLocationName: string }>;
  newClient: {
    name: string;
    type: string;
    website: string;
    phone: string;
    email: string;
    contactName: string;
    locationName: string;
    address: string;
    city: string;
    state: string;
    zip: string;
    notes: string;
  };
}

export const ItflowSetupWizardModal: React.FC<ItflowSetupWizardModalProps> = ({
  isOpen,
  onClose,
  onCompleted
}) => {
  const [step, setStep] = useState<1 | 2 | 3 | 4>(1);
  const [loadingInit, setLoadingInit] = useState(false);

  // Step 1: Credentials
  const [url, setUrl] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [hasSavedKey, setHasSavedKey] = useState(false);
  const [allowSelfSigned, setAllowSelfSigned] = useState(false);
  const [testingConn, setTestingConn] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string; apiBase?: string } | null>(null);

  // Step 2: Client discovery + fuzzy match
  const [discovering, setDiscovering] = useState(false);
  const [discoverError, setDiscoverError] = useState<string | null>(null);
  const [itflowClients, setItflowClients] = useState<ItflowClientRecord[]>([]);
  const [itflowLocations, setItflowLocations] = useState<ItflowLocationRecord[]>([]);
  const [suggestions, setSuggestions] = useState<ItflowTenantMappingSuggestion[]>([]);
  const [drafts, setDrafts] = useState<Record<string, DraftTenantAssignment>>({});
  const [tenantFilter, setTenantFilter] = useState('');
  const [reviewedConfirmed, setReviewedConfirmed] = useState(false);

  // Step 3: Automation & note options
  const [options, setOptions] = useState({
    syncTicketsOnConditions: true,
    autoResolveClosedTickets: true,
    createNotesOnConditions: true,
    defaultNoteType: 'Internal' as 'Internal' | 'Public',
    syncTimeEntries: true,
    preserveManualAssetNotes: true,
    autoSyncNewDevices: true,
    includeHardwareInNotes: true
  });

  // Step 4: Schedule & execution
  const [syncIntervalMin, setSyncIntervalMin] = useState(60);
  const [applying, setApplying] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);
  const [finalSummary, setFinalSummary] = useState<any>(null);

  useEffect(() => {
    if (!isOpen) return;
    setStep(1);
    setFinalSummary(null);
    setApplyError(null);
    setDiscoverError(null);
    setTestResult(null);
    setReviewedConfirmed(false);
    setLoadingInit(true);
    fetchItflowStatus()
      .then((st) => {
        setUrl(st.url || '');
        setHasSavedKey(Boolean(st.hasApiKey));
        setAllowSelfSigned(Boolean(st.allowSelfSigned));
        setSyncIntervalMin(Number(st.syncIntervalMin || 60));
        if (st.options) setOptions((prev) => ({ ...prev, ...st.options }));
      })
      .catch(() => {})
      .finally(() => setLoadingInit(false));
  }, [isOpen]);

  if (!isOpen) return null;

  const handleTestConnection = async () => {
    setTestingConn(true);
    setTestResult(null);
    try {
      const res = await testItflowConnection({
        url: url.trim(),
        apiKey: apiKey.trim() || undefined,
        allowSelfSigned
      });
      setTestResult({ ok: Boolean(res.ok), message: res.message, apiBase: res.apiBase });
    } catch (err: any) {
      setTestResult({ ok: false, message: err?.message || 'Connection test failed.' });
    } finally {
      setTestingConn(false);
    }
  };

  const handleProceedToDiscovery = async () => {
    setDiscovering(true);
    setDiscoverError(null);
    setReviewedConfirmed(false);
    try {
      const res = await discoverItflowClients({
        url: url.trim(),
        apiKey: apiKey.trim() || undefined,
        allowSelfSigned
      });
      if (!res.success) {
        setDiscoverError(res.error || 'Failed to scan ITFlow clients.');
        return;
      }
      const cls = res.clients || [];
      const locs = res.locations || [];
      const sugs = res.suggestions || [];
      setItflowClients(cls);
      setItflowLocations(locs);
      setSuggestions(sugs);

      const nextDrafts: Record<string, DraftTenantAssignment> = {};
      for (const s of sugs) {
        const saved = s.existing_mapping;
        let action: 'link' | 'create_new' | 'disable' = 'create_new';
        let clientId: number | null = null;

        if (saved && !saved.sync_enabled && saved.itflow_client_id === null) {
          action = 'disable';
        } else if (saved && saved.sync_enabled && saved.itflow_client_id) {
          action = 'link';
          clientId = saved.itflow_client_id;
        } else if (s.suggested_client_id) {
          action = 'link';
          clientId = s.suggested_client_id;
        } else {
          action = 'create_new';
        }

        const siteMap: Record<string, { itflowLocationId: number | null; createLocationName: string }> = {};
        const clientLocs = locs.filter((l) => l.location_client_id === clientId);
        for (const st of s.sites || []) {
          const locMatch = clientLocs.find((l) => l.location_name.toLowerCase() === st.name.toLowerCase());
          siteMap[st.id] = { itflowLocationId: locMatch ? locMatch.location_id : null, createLocationName: '' };
        }

        nextDrafts[s.tenant_id] = {
          action,
          itflowClientId: clientId,
          defaultLocationId: saved?.itflow_default_location_id || clientLocs.find((l) => l.location_primary)?.location_id || null,
          onExistingAssets: 'duplicate',
          siteMappings: siteMap,
          newClient: {
            name: s.tenant_name,
            type: 'Business',
            website: '',
            phone: '',
            email: s.tenant_contact_email || '',
            contactName: '',
            locationName: s.sites?.[0]?.name || 'Primary Office',
            address: '',
            city: '',
            state: '',
            zip: '',
            notes: `Onboarded from Vitrine RMM (${s.device_count} managed endpoint(s))`
          }
        };
      }
      setDrafts(nextDrafts);
      setStep(2);
    } catch (err: any) {
      setDiscoverError(err?.message || 'Unable to scan ITFlow clients.');
    } finally {
      setDiscovering(false);
    }
  };

  const updateDraft = (tenantId: string, patch: Partial<DraftTenantAssignment>) => {
    setDrafts((prev) => ({
      ...prev,
      [tenantId]: { ...prev[tenantId], ...patch }
    }));
  };

  const hasAssetChangeRequiringDecision = (s: ItflowTenantMappingSuggestion, d: DraftTenantAssignment): boolean => {
    if (!s.existing_mapping || s.existing_mapping.synced_asset_count <= 0) return false;
    const prevId = s.existing_mapping.itflow_client_id;
    if (d.action === 'disable') return prevId !== null;
    if (d.action === 'create_new') return prevId !== null;
    return prevId !== null && d.itflowClientId !== prevId;
  };

  const canLeaveStep2 = (() => {
    if (!reviewedConfirmed) return false;
    for (const s of suggestions) {
      const d = drafts[s.tenant_id];
      if (!d) continue;
      if (d.action === 'link' && !d.itflowClientId) return false;
      if (d.action === 'create_new' && !d.newClient.name.trim()) return false;
    }
    return true;
  })();

  const handleSaveAndSync = async () => {
    setApplying(true);
    setApplyError(null);
    try {
      await saveItflowConfig({
        url: url.trim(),
        apiKey: apiKey.trim() || undefined,
        enabled: true,
        setupCompleted: true,
        syncIntervalMin,
        options
      });

      const assignments = suggestions.map((s) => {
        const d = drafts[s.tenant_id];
        const chosenClient = itflowClients.find((c) => c.client_id === d.itflowClientId);
        return {
          tenantId: s.tenant_id,
          action: d.action,
          itflowClientId: d.action === 'link' ? d.itflowClientId : null,
          itflowClientName: d.action === 'link' ? chosenClient?.client_name || null : null,
          defaultLocationId: d.action === 'link' ? d.defaultLocationId : null,
          newClient: d.action === 'create_new' ? d.newClient : undefined,
          onExistingAssets: hasAssetChangeRequiringDecision(s, d) ? d.onExistingAssets : undefined,
          siteMappings:
            d.action === 'link'
              ? (s.sites || []).map((st) => ({
                  siteId: st.id,
                  itflowLocationId: d.siteMappings[st.id]?.itflowLocationId || null,
                  createLocationName: d.siteMappings[st.id]?.createLocationName || undefined
                }))
              : []
        };
      });

      const res = await applyItflowMappings({
        assignments,
        url: url.trim(),
        apiKey: apiKey.trim() || undefined,
        allowSelfSigned,
        markSetupCompleted: true,
        triggerInitialSync: true
      });
      if (!res.success) {
        setApplyError(res.error || 'Failed applying ITFlow setup.');
        return;
      }
      setFinalSummary(res);
      if (onCompleted) onCompleted();
    } catch (err: any) {
      setApplyError(err?.message || 'Error applying ITFlow integration setup.');
    } finally {
      setApplying(false);
    }
  };

  const filteredSuggestions = suggestions.filter((s) =>
    !tenantFilter.trim() || s.tenant_name.toLowerCase().includes(tenantFilter.trim().toLowerCase())
  );

  const linkCount = Object.values(drafts).filter((d) => d.action === 'link').length;
  const createCount = Object.values(drafts).filter((d) => d.action === 'create_new').length;
  const disableCount = Object.values(drafts).filter((d) => d.action === 'disable').length;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="glass-modal"
        style={{ maxWidth: '920px', width: '95vw', maxHeight: '90vh', overflowY: 'auto', padding: '1.5rem' }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header & Stepper */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div>
            <h2 style={{ margin: 0, fontSize: '1.22rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Sparkles size={19} color="var(--primary)" />
              <span>ITFlow Guided Integration Setup</span>
            </h2>
            <p style={{ margin: '0.2rem 0 0 0', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Step-by-step handshake, fuzzy client mapping review, ticket rules, and automated asset synchronization
            </p>
          </div>
          <button type="button" className="btn-glass btn-icon" onClick={onClose}>
            <X size={17} />
          </button>
        </div>

        {/* Progress Bar */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.5rem', marginBottom: '1.25rem' }}>
          {[
            { num: 1, title: '1. Connect & Verify' },
            { num: 2, title: '2. Client Mapping Review' },
            { num: 3, title: '3. Tickets & Notes' },
            { num: 4, title: '4. Sync Schedule' }
          ].map((s) => (
            <div
              key={s.num}
              style={{
                padding: '0.5rem 0.7rem',
                borderRadius: '8px',
                fontSize: '0.75rem',
                fontWeight: step === s.num ? 700 : 500,
                background:
                  step === s.num
                    ? 'rgba(0, 242, 254, 0.14)'
                    : step > s.num
                      ? 'rgba(16, 185, 129, 0.12)'
                      : 'rgba(255,255,255,0.03)',
                border: `1px solid ${
                  step === s.num
                    ? 'var(--primary)'
                    : step > s.num
                      ? 'rgba(16, 185, 129, 0.35)'
                      : 'var(--glass-border)'
                }`,
                color: step > s.num ? '#34d399' : step === s.num ? 'var(--primary)' : 'var(--text-muted)'
              }}
            >
              {s.title}
            </div>
          ))}
        </div>

        {loadingInit ? (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>Loading saved ITFlow configuration...</div>
        ) : (
          <>
            {/* STEP 1: CONNECTION */}
            {step === 1 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <div
                  style={{
                    background: 'rgba(56, 189, 248, 0.08)',
                    border: '1px solid rgba(56, 189, 248, 0.28)',
                    borderRadius: '8px',
                    padding: '0.85rem 1rem',
                    fontSize: '0.8rem',
                    lineHeight: 1.5
                  }}
                >
                  <strong>How to generate your ITFlow API Key:</strong> Log into ITFlow as an Administrator &rarr;{' '}
                  <strong>Administration &rarr; Settings &rarr; API Keys &rarr; New Key</strong>. Paste the base URL (e.g.{' '}
                  <code>https://itflow.yourmsp.com</code> or <code>https://itflow.yourmsp.com/api/v1</code>) and key below. Vitrine never alters ITFlow until you explicitly review client mappings in Step 2.
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr', gap: '0.9rem' }}>
                  <div className="form-group" style={{ margin: 0 }}>
                    <label className="form-label">ITFlow Instance URL</label>
                    <input
                      type="text"
                      className="glass-input"
                      placeholder="https://psa.yourmsp.com/api/v1"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                    />
                  </div>
                  <div className="form-group" style={{ margin: 0 }}>
                    <label className="form-label" style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                      <KeyRound size={13} />
                      <span>ITFlow API Key {hasSavedKey && <span style={{ color: '#34d399', fontSize: '0.7rem' }}>(Vaulted Key Stored)</span>}</span>
                    </label>
                    <input
                      type="password"
                      className="glass-input"
                      placeholder={hasSavedKey ? 'Leave blank to use stored vaulted API key' : 'Paste ITFlow X-API-Key'}
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                    />
                  </div>
                </div>

                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.8rem' }}>
                  <input
                    type="checkbox"
                    checked={allowSelfSigned}
                    onChange={(e) => setAllowSelfSigned(e.target.checked)}
                  />
                  <span>Allow self-signed / internal lab TLS certificates when contacting ITFlow</span>
                </label>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    className="btn-glass"
                    disabled={testingConn || !url.trim() || (!apiKey.trim() && !hasSavedKey)}
                    onClick={handleTestConnection}
                  >
                    <RefreshCw size={14} className={testingConn ? 'animate-spin' : ''} />
                    <span>{testingConn ? 'Testing ITFlow API...' : 'Test Connection'}</span>
                  </button>
                  {testResult && (
                    <span style={{ fontSize: '0.8rem', color: testResult.ok ? '#34d399' : '#f87171', fontWeight: 600 }}>
                      {testResult.ok ? '✓ ' : '✕ '}
                      {testResult.message}
                    </span>
                  )}
                </div>

                {discoverError && (
                  <div style={{ padding: '0.75rem', borderRadius: '8px', background: 'rgba(239,68,68,0.12)', color: '#fca5a5', fontSize: '0.8rem' }}>
                    {discoverError}
                  </div>
                )}

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.6rem', marginTop: '0.5rem' }}>
                  <button type="button" className="btn-glass" onClick={onClose}>
                    Cancel
                  </button>
                  <button
                    type="button"
                    className="btn-glass btn-primary"
                    disabled={discovering || !url.trim() || (!apiKey.trim() && !hasSavedKey)}
                    onClick={handleProceedToDiscovery}
                  >
                    <span>{discovering ? 'Scanning ITFlow Clients...' : 'Scan ITFlow & Match Clients'}</span>
                    <ArrowRight size={15} />
                  </button>
                </div>
              </div>
            )}

            {/* STEP 2: MANDATORY FUZZY MATCH REVIEW */}
            {step === 2 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
                <div
                  style={{
                    background: 'rgba(245, 158, 11, 0.1)',
                    border: '1px solid rgba(245, 158, 11, 0.35)',
                    borderRadius: '8px',
                    padding: '0.75rem 0.95rem',
                    fontSize: '0.78rem',
                    lineHeight: 1.45
                  }}
                >
                  <strong>Mandatory Review Before Sync:</strong> Vitrine scanned <strong>{itflowClients.length}</strong> client(s) in ITFlow and fuzzily matched them to your <strong>{suggestions.length}</strong> Vitrine organization(s). You can link each client to any ITFlow client (including sharing one ITFlow client across multiple Vitrine tenants), create a populated ITFlow client, or disable sync.
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="Filter Vitrine clients..."
                    value={tenantFilter}
                    onChange={(e) => setTenantFilter(e.target.value)}
                    style={{ maxWidth: '280px' }}
                  />
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', gap: '0.8rem' }}>
                    <span style={{ color: '#34d399' }}>Link: {linkCount}</span>
                    <span style={{ color: '#38bdf8' }}>Create New: {createCount}</span>
                    <span style={{ color: '#94a3b8' }}>Disabled: {disableCount}</span>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.7rem', maxHeight: '42vh', overflowY: 'auto', paddingRight: '0.25rem' }}>
                  {filteredSuggestions.map((s) => {
                    const d = drafts[s.tenant_id];
                    if (!d) return null;
                    const needsRemapDecision = hasAssetChangeRequiringDecision(s, d);
                    const clientLocations = itflowLocations.filter((l) => l.location_client_id === d.itflowClientId);

                    return (
                      <div
                        key={s.tenant_id}
                        style={{
                          background: 'rgba(15, 23, 42, 0.5)',
                          border: `1px solid ${needsRemapDecision ? 'rgba(245, 158, 11, 0.5)' : 'var(--glass-border)'}`,
                          borderRadius: '10px',
                          padding: '0.85rem 1rem',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '0.65rem'
                        }}
                      >
                        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 180px 1.3fr', gap: '0.75rem', alignItems: 'center' }}>
                          <div>
                            <div style={{ fontWeight: 700, fontSize: '0.9rem' }}>{s.tenant_name}</div>
                            <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.15rem' }}>
                              {s.device_count} active device(s)
                              {s.existing_mapping?.synced_asset_count
                                ? ` • ${s.existing_mapping.synced_asset_count} linked asset(s) under ${s.existing_mapping.itflow_client_name}`
                                : ''}
                            </div>
                            <div style={{ marginTop: '0.25rem' }}>
                              <span
                                className={`status-pill ${
                                  s.confidence >= 85 ? 'status-online' : s.confidence >= 50 ? 'status-reboot' : ''
                                }`}
                                style={{ fontSize: '0.66rem' }}
                              >
                                {s.confidence >= 50
                                  ? `Fuzzy Match ${s.confidence}%: ${s.suggested_client_name}`
                                  : `No Match (${s.match_reason})`}
                              </span>
                            </div>
                          </div>

                          <div>
                            <select
                              className="glass-select"
                              value={d.action}
                              onChange={(e) => {
                                const nextAct = e.target.value as 'link' | 'create_new' | 'disable';
                                updateDraft(s.tenant_id, {
                                  action: nextAct,
                                  itflowClientId:
                                    nextAct === 'link'
                                      ? d.itflowClientId || s.suggested_client_id || itflowClients[0]?.client_id || null
                                      : d.itflowClientId
                                });
                              }}
                            >
                              <option value="link" disabled={itflowClients.length === 0}>
                                Link to Existing Client
                              </option>
                              <option value="create_new">Create New ITFlow Client</option>
                              <option value="disable">Disable Sync (Skip)</option>
                            </select>
                          </div>

                          <div>
                            {d.action === 'link' && (
                              <select
                                className="glass-select"
                                value={d.itflowClientId || ''}
                                onChange={(e) =>
                                  updateDraft(s.tenant_id, {
                                    itflowClientId: e.target.value ? Number(e.target.value) : null,
                                    defaultLocationId: null
                                  })
                                }
                              >
                                <option value="">-- Select Any ITFlow Client --</option>
                                {itflowClients.map((c) => (
                                  <option key={c.client_id} value={c.client_id}>
                                    {c.client_name} (#{c.client_id})
                                  </option>
                                ))}
                              </select>
                            )}
                            {d.action === 'create_new' && (
                              <div style={{ fontSize: '0.74rem', color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                                <PlusCircle size={14} />
                                <span>Will create populated ITFlow client below</span>
                              </div>
                            )}
                            {d.action === 'disable' && (
                              <div style={{ fontSize: '0.74rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                                <Ban size={14} />
                                <span>Assets &amp; tickets for this client will not auto-sync</span>
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Site to ITFlow Location mapping when linked */}
                        {d.action === 'link' && d.itflowClientId && (clientLocations.length > 0 || (s.sites && s.sites.length > 0)) && (
                          <div style={{ paddingTop: '0.5rem', borderTop: '1px solid rgba(255,255,255,0.06)', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                            {clientLocations.length > 0 && (
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.74rem' }}>
                                <span style={{ color: 'var(--text-dim)', minWidth: '150px' }}>Default Client Location:</span>
                                <select
                                  className="glass-select"
                                  style={{ maxWidth: '280px', fontSize: '0.74rem', padding: '0.25rem 0.5rem' }}
                                  value={d.defaultLocationId || ''}
                                  onChange={(e) =>
                                    updateDraft(s.tenant_id, {
                                      defaultLocationId: e.target.value ? Number(e.target.value) : null
                                    })
                                  }
                                >
                                  <option value="">ITFlow Default (None)</option>
                                  {clientLocations.map((l) => (
                                    <option key={l.location_id} value={l.location_id}>
                                      {l.location_name} {l.location_city ? `(${l.location_city})` : ''}
                                    </option>
                                  ))}
                                </select>
                              </div>
                            )}
                            {(s.sites || []).map((st) => (
                              <div key={st.id} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.74rem' }}>
                                <span style={{ color: 'var(--text-muted)', minWidth: '150px' }}>Site &ldquo;{st.name}&rdquo; &rarr;</span>
                                <select
                                  className="glass-select"
                                  style={{ maxWidth: '240px', fontSize: '0.73rem', padding: '0.22rem 0.5rem' }}
                                  value={d.siteMappings[st.id]?.itflowLocationId || ''}
                                  onChange={(e) => {
                                    const val = e.target.value ? Number(e.target.value) : null;
                                    updateDraft(s.tenant_id, {
                                      siteMappings: {
                                        ...d.siteMappings,
                                        [st.id]: { itflowLocationId: val, createLocationName: val ? '' : d.siteMappings[st.id]?.createLocationName || '' }
                                      }
                                    });
                                  }}
                                >
                                  <option value="">Use Default Client Location</option>
                                  {clientLocations.map((l) => (
                                    <option key={l.location_id} value={l.location_id}>
                                      {l.location_name}
                                    </option>
                                  ))}
                                </select>
                                {!d.siteMappings[st.id]?.itflowLocationId && (
                                  <input
                                    type="text"
                                    className="glass-input"
                                    style={{ maxWidth: '210px', fontSize: '0.72rem', padding: '0.22rem 0.5rem' }}
                                    placeholder={`Or create "${st.name}"...`}
                                    value={d.siteMappings[st.id]?.createLocationName || ''}
                                    onChange={(e) =>
                                      updateDraft(s.tenant_id, {
                                        siteMappings: {
                                          ...d.siteMappings,
                                          [st.id]: { itflowLocationId: null, createLocationName: e.target.value }
                                        }
                                      })
                                    }
                                  />
                                )}
                              </div>
                            ))}
                          </div>
                        )}

                        {/* Inline Create New Client Details Form */}
                        {d.action === 'create_new' && (
                          <div
                            style={{
                              padding: '0.75rem',
                              borderRadius: '8px',
                              background: 'rgba(56, 189, 248, 0.06)',
                              border: '1px solid rgba(56, 189, 248, 0.2)',
                              display: 'grid',
                              gridTemplateColumns: 'repeat(3, 1fr)',
                              gap: '0.55rem'
                            }}
                          >
                            <div>
                              <label className="form-label" style={{ fontSize: '0.68rem' }}>Client Name *</label>
                              <input
                                type="text"
                                className="glass-input"
                                style={{ fontSize: '0.76rem' }}
                                value={d.newClient.name}
                                onChange={(e) =>
                                  updateDraft(s.tenant_id, { newClient: { ...d.newClient, name: e.target.value } })
                                }
                              />
                            </div>
                            <div>
                              <label className="form-label" style={{ fontSize: '0.68rem' }}>Primary Contact Name</label>
                              <input
                                type="text"
                                className="glass-input"
                                style={{ fontSize: '0.76rem' }}
                                placeholder="e.g. Jane Doe"
                                value={d.newClient.contactName}
                                onChange={(e) =>
                                  updateDraft(s.tenant_id, { newClient: { ...d.newClient, contactName: e.target.value } })
                                }
                              />
                            </div>
                            <div>
                              <label className="form-label" style={{ fontSize: '0.68rem' }}>Contact Email</label>
                              <input
                                type="email"
                                className="glass-input"
                                style={{ fontSize: '0.76rem' }}
                                value={d.newClient.email}
                                onChange={(e) =>
                                  updateDraft(s.tenant_id, { newClient: { ...d.newClient, email: e.target.value } })
                                }
                              />
                            </div>
                            <div>
                              <label className="form-label" style={{ fontSize: '0.68rem' }}>Phone / Website</label>
                              <input
                                type="text"
                                className="glass-input"
                                style={{ fontSize: '0.76rem' }}
                                placeholder="(555) 123-4567"
                                value={d.newClient.phone}
                                onChange={(e) =>
                                  updateDraft(s.tenant_id, { newClient: { ...d.newClient, phone: e.target.value } })
                                }
                              />
                            </div>
                            <div>
                              <label className="form-label" style={{ fontSize: '0.68rem' }}>Primary Location Name</label>
                              <input
                                type="text"
                                className="glass-input"
                                style={{ fontSize: '0.76rem' }}
                                value={d.newClient.locationName}
                                onChange={(e) =>
                                  updateDraft(s.tenant_id, { newClient: { ...d.newClient, locationName: e.target.value } })
                                }
                              />
                            </div>
                            <div>
                              <label className="form-label" style={{ fontSize: '0.68rem' }}>Street Address / City / State</label>
                              <input
                                type="text"
                                className="glass-input"
                                style={{ fontSize: '0.76rem' }}
                                placeholder="123 Main St, Suite 200"
                                value={d.newClient.address}
                                onChange={(e) =>
                                  updateDraft(s.tenant_id, { newClient: { ...d.newClient, address: e.target.value } })
                                }
                              />
                            </div>
                          </div>
                        )}

                        {/* Asset Move vs Duplicate Guard */}
                        {needsRemapDecision && (
                          <div
                            style={{
                              padding: '0.65rem 0.8rem',
                              borderRadius: '8px',
                              background: 'rgba(245, 158, 11, 0.12)',
                              border: '1px solid rgba(245, 158, 11, 0.4)',
                              fontSize: '0.76rem',
                              display: 'flex',
                              flexDirection: 'column',
                              gap: '0.4rem'
                            }}
                          >
                            <div style={{ fontWeight: 700, color: '#fbbf24', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                              <AlertTriangle size={14} />
                              <span>
                                Destination Changed ({s.existing_mapping?.synced_asset_count} Existing Synced Asset(s) in{' '}
                                {s.existing_mapping?.itflow_client_name})
                              </span>
                            </div>
                            <div style={{ display: 'flex', gap: '1.25rem', flexWrap: 'wrap' }}>
                              <label style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', cursor: 'pointer' }}>
                                <input
                                  type="radio"
                                  name={`remap-${s.tenant_id}`}
                                  checked={d.onExistingAssets === 'move'}
                                  onChange={() => updateDraft(s.tenant_id, { onExistingAssets: 'move' })}
                                />
                                <span>
                                  <strong>Move Assets</strong> (delete from prior ITFlow client &amp; recreate in new)
                                </span>
                              </label>
                              <label style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', cursor: 'pointer' }}>
                                <input
                                  type="radio"
                                  name={`remap-${s.tenant_id}`}
                                  checked={d.onExistingAssets === 'duplicate'}
                                  onChange={() => updateDraft(s.tenant_id, { onExistingAssets: 'duplicate' })}
                                />
                                <span>
                                  <strong>Duplicate / Keep Prior</strong> (leave prior ITFlow assets intact)
                                </span>
                              </label>
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>

                <label
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.55rem',
                    padding: '0.7rem 0.9rem',
                    borderRadius: '8px',
                    background: reviewedConfirmed ? 'rgba(16, 185, 129, 0.1)' : 'rgba(255,255,255,0.03)',
                    border: `1px solid ${reviewedConfirmed ? 'rgba(16, 185, 129, 0.35)' : 'var(--glass-border)'}`,
                    cursor: 'pointer',
                    fontSize: '0.82rem',
                    fontWeight: 600
                  }}
                >
                  <input
                    type="checkbox"
                    checked={reviewedConfirmed}
                    onChange={(e) => setReviewedConfirmed(e.target.checked)}
                  />
                  <span>I have reviewed these client matches, new client details, and sync selections.</span>
                </label>

                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.25rem' }}>
                  <button type="button" className="btn-glass" onClick={() => setStep(1)}>
                    <ArrowLeft size={15} /> Back
                  </button>
                  <button type="button" className="btn-glass btn-primary" disabled={!canLeaveStep2} onClick={() => setStep(3)}>
                    <span>Next: Ticket &amp; Note Rules</span>
                    <ArrowRight size={15} />
                  </button>
                </div>
              </div>
            )}

            {/* STEP 3: TICKETS & NOTES */}
            {step === 3 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                  {(
                    [
                      { key: 'syncTicketsOnConditions', label: 'Create ITFlow tickets from Condition Engine alerts & escalations' },
                      { key: 'autoResolveClosedTickets', label: 'Auto-resolve ITFlow tickets & post recovery note when cleared' },
                      { key: 'createNotesOnConditions', label: 'Add progress notes to open ITFlow tickets while condition stays active' },
                      { key: 'syncTimeEntries', label: 'Push Vitrine technician time entries to ITFlow ticket replies' },
                      { key: 'autoSyncNewDevices', label: 'Auto-sync newly enrolled devices as ITFlow assets immediately' },
                      { key: 'includeHardwareInNotes', label: 'Populate ITFlow asset notes with CPU/RAM/Disk/IP/User telemetry' },
                      { key: 'preserveManualAssetNotes', label: 'Preserve manual asset notes edited directly in ITFlow' }
                    ] as const
                  ).map((opt) => (
                    <label
                      key={opt.key}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.55rem',
                        padding: '0.7rem 0.85rem',
                        borderRadius: '8px',
                        background: 'rgba(255,255,255,0.03)',
                        border: '1px solid var(--glass-border)',
                        cursor: 'pointer',
                        fontSize: '0.79rem'
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={Boolean(options[opt.key])}
                        onChange={(e) => setOptions({ ...options, [opt.key]: e.target.checked })}
                      />
                      <span>{opt.label}</span>
                    </label>
                  ))}
                  <div
                    style={{
                      padding: '0.7rem 0.85rem',
                      borderRadius: '8px',
                      background: 'rgba(255,255,255,0.03)',
                      border: '1px solid var(--glass-border)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center'
                    }}
                  >
                    <span style={{ fontSize: '0.79rem' }}>Default Automated Ticket Note Visibility:</span>
                    <select
                      className="glass-select"
                      style={{ width: 'auto', fontSize: '0.78rem' }}
                      value={options.defaultNoteType}
                      onChange={(e) => setOptions({ ...options, defaultNoteType: e.target.value as 'Internal' | 'Public' })}
                    >
                      <option value="Internal">Internal Technician Note</option>
                      <option value="Public">Public Customer Reply</option>
                    </select>
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.35rem' }}>
                  <button type="button" className="btn-glass" onClick={() => setStep(2)}>
                    <ArrowLeft size={15} /> Back to Mapping Review
                  </button>
                  <button type="button" className="btn-glass btn-primary" onClick={() => setStep(4)}>
                    <span>Next: Schedule &amp; Initial Sync</span>
                    <ArrowRight size={15} />
                  </button>
                </div>
              </div>
            )}

            {/* STEP 4: SCHEDULE & INITIAL SYNC */}
            {step === 4 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <div className="form-group" style={{ margin: 0 }}>
                  <label className="form-label" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <Clock size={14} color="var(--primary)" />
                    <span>Periodic Asset Details Refresh Interval</span>
                  </label>
                  <select
                    className="glass-select"
                    value={syncIntervalMin}
                    onChange={(e) => setSyncIntervalMin(Number(e.target.value))}
                    disabled={applying || Boolean(finalSummary)}
                    style={{ maxWidth: '340px' }}
                  >
                    <option value={15}>Every 15 Minutes (High Frequency)</option>
                    <option value={30}>Every 30 Minutes</option>
                    <option value={60}>Every 60 Minutes (Recommended)</option>
                    <option value={180}>Every 3 Hours</option>
                    <option value={360}>Every 6 Hours</option>
                    <option value={1440}>Once Daily (24 Hours)</option>
                  </select>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.75rem' }}>
                  <div className="glass-card" style={{ padding: '0.85rem' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>LINKED CLIENTS</div>
                    <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#34d399' }}>{linkCount}</div>
                  </div>
                  <div className="glass-card" style={{ padding: '0.85rem' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>NEW CLIENTS TO CREATE</div>
                    <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#38bdf8' }}>{createCount}</div>
                  </div>
                  <div className="glass-card" style={{ padding: '0.85rem' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>SYNC DISABLED</div>
                    <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#94a3b8' }}>{disableCount}</div>
                  </div>
                </div>

                {applyError && (
                  <div style={{ padding: '0.8rem', borderRadius: '8px', background: 'rgba(239,68,68,0.12)', color: '#fca5a5', fontSize: '0.82rem' }}>
                    {applyError}
                  </div>
                )}

                {finalSummary && (
                  <div
                    style={{
                      padding: '1rem',
                      borderRadius: '10px',
                      background: 'rgba(16, 185, 129, 0.1)',
                      border: '1px solid rgba(16, 185, 129, 0.35)',
                      fontSize: '0.82rem',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.35rem'
                    }}
                  >
                    <div style={{ fontWeight: 700, color: '#34d399', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      <CheckCircle2 size={16} />
                      <span>ITFlow Setup Completed &amp; Initial Sync Executed</span>
                    </div>
                    <div>
                      Clients linked: <strong>{finalSummary.mappingResult?.linkedTenants || 0}</strong> | New clients created:{' '}
                      <strong>{finalSummary.mappingResult?.createdClients || 0}</strong> | Assets moved (old deleted):{' '}
                      <strong>{finalSummary.mappingResult?.assetsMovedDeletedOld || 0}</strong>
                    </div>
                    {finalSummary.syncResult && (
                      <div>
                        Asset sync: <strong>{finalSummary.syncResult.created}</strong> created,{' '}
                        <strong>{finalSummary.syncResult.updated}</strong> updated,{' '}
                        <strong>{finalSummary.syncResult.skipped}</strong> unchanged,{' '}
                        <strong>{finalSummary.syncResult.failed}</strong> failed.
                      </div>
                    )}
                  </div>
                )}

                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.25rem' }}>
                  <button type="button" className="btn-glass" disabled={applying} onClick={() => setStep(3)}>
                    <ArrowLeft size={15} /> Back
                  </button>
                  {finalSummary ? (
                    <button type="button" className="btn-glass btn-primary" onClick={onClose}>
                      <ShieldCheck size={15} /> Done
                    </button>
                  ) : (
                    <button type="button" className="btn-glass btn-primary" disabled={applying} onClick={handleSaveAndSync}>
                      <Server size={15} />
                      <span>{applying ? 'Applying Mappings & Syncing Assets...' : 'Save Configuration & Sync Assets Now'}</span>
                    </button>
                  )}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

