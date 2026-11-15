import React, { useState, useEffect, useCallback } from 'react';
import {
  BellRing,
  CheckCircle2,
  Clock,
  AlertTriangle,
  ShieldAlert,
  Send,
  Plus,
  Trash2,
  RefreshCw,
  UserCheck,
  Webhook
} from 'lucide-react';
import { AlertIncident, NotificationChannel, Tenant, AuthUser } from '../types/index.js';
import {
  fetchAlertIncidents,
  acknowledgeAlertIncident,
  snoozeAlertIncident,
  resolveAlertIncident,
  assignAlertIncident,
  evaluatePolicyConditions,
  fetchNotificationChannels,
  createNotificationChannel,
  deleteNotificationChannel,
  testNotificationChannel
} from '../services/api.js';
import { canMutateFleet } from '../utils/permissions.js';

interface AlertsCenterViewProps {
  tenants: Tenant[];
  selectedTenantId: string;
  currentUser?: AuthUser | null;
}

export const AlertsCenterView: React.FC<AlertsCenterViewProps> = ({
  tenants,
  selectedTenantId,
  currentUser
}) => {
  const [activeTab, setActiveTab] = useState<'incidents' | 'channels'>('incidents');
  const [statusFilter, setStatusFilter] = useState<string>('open');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [incidents, setIncidents] = useState<AlertIncident[]>([]);
  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const [loading, setLoading] = useState(false);
  const [evaluating, setEvaluating] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [assignInputs, setAssignInputs] = useState<Record<string, string>>({});

  // New Notification Channel state
  const [chanName, setChanName] = useState('');
  const [chanType, setChanType] = useState<'slack' | 'teams' | 'discord' | 'pagerduty' | 'webhook'>('slack');
  const [chanUrl, setChanUrl] = useState('');
  const [chanRoutingKey, setChanRoutingKey] = useState('');
  const [chanSecret, setChanSecret] = useState('');
  const [chanMinSeverity, setChanMinSeverity] = useState('warning');
  const [chanTenantId, setChanTenantId] = useState('');
  const [testingId, setTestingId] = useState<string | null>(null);

  const allowMutate = canMutateFleet(currentUser);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [incList, chanList] = await Promise.all([
        fetchAlertIncidents({
          status: statusFilter === 'all' ? undefined : statusFilter,
          severity: severityFilter === 'all' ? undefined : severityFilter,
          tenant_id: selectedTenantId !== 'all' ? selectedTenantId : undefined
        }),
        currentUser?.role !== 'client_admin'
          ? fetchNotificationChannels().catch(() => [])
          : Promise.resolve([])
      ]);
      setIncidents(incList);
      setChannels(chanList);
    } finally {
      setLoading(false);
    }
  }, [statusFilter, severityFilter, selectedTenantId, currentUser?.role]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleEvaluateConditions = async () => {
    setEvaluating(true);
    setNotice(null);
    try {
      const res = await evaluatePolicyConditions();
      setNotice(
        `✓ Evaluated ${res.evaluatedDevices} endpoint(s) & ${res.evaluatedAppliances} appliance(s): ${res.triggeredConditions.length} active condition(s) matched.`
      );
      loadData();
    } catch (err: any) {
      setNotice(`Condition evaluation error: ${err.message}`);
    } finally {
      setEvaluating(false);
    }
  };

  const handleCreateChannel = async (e: React.FormEvent) => {
    e.preventDefault();
    setNotice(null);
    if (!chanName.trim()) {
      setNotice('Channel name is required.');
      return;
    }
    const res = await createNotificationChannel({
      name: chanName.trim(),
      channel_type: chanType,
      webhook_url: chanUrl.trim() || undefined,
      routing_key: chanRoutingKey.trim() || undefined,
      signing_secret: chanSecret.trim() || undefined,
      min_severity: chanMinSeverity,
      tenant_id: chanTenantId || null,
      enabled: true
    });
    if (res.success) {
      setChanName('');
      setChanUrl('');
      setChanRoutingKey('');
      setChanSecret('');
      setNotice(`✓ Notification channel "${res.channel?.name || chanName}" saved.`);
      loadData();
    } else {
      setNotice(`Failed to create channel: ${res.error || 'Verify webhook URL safety'}`);
    }
  };

  const handleTestChannel = async (id: string, name: string) => {
    setTestingId(id);
    setNotice(null);
    try {
      const res = await testNotificationChannel(id);
      setNotice(
        res.success
          ? `✓ Test alert dispatched to "${name}".`
          : `Channel test failed for "${name}": ${res.error || 'Check endpoint reachability'}`
      );
      loadData();
    } finally {
      setTestingId(null);
    }
  };

  const criticalCount = incidents.filter((i) => i.severity === 'critical' && i.status !== 'resolved').length;
  const openCount = incidents.filter((i) => i.status === 'open').length;
  const ackCount = incidents.filter((i) => i.status === 'acknowledged').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }} id="alerts-center-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>
            Stateful Alerts &amp; Incident Center
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Deduplicated condition incidents with Acknowledge, Snooze, Assignment &amp; Multi-Channel Dispatch
          </span>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <button
            type="button"
            className={`btn-glass ${activeTab === 'incidents' ? 'btn-primary' : ''}`}
            onClick={() => setActiveTab('incidents')}
            id="tab-alert-incidents"
          >
            <BellRing size={15} /> Incident Queue ({incidents.length})
          </button>
          {currentUser?.role !== 'client_admin' && (
            <button
              type="button"
              className={`btn-glass ${activeTab === 'channels' ? 'btn-primary' : ''}`}
              onClick={() => setActiveTab('channels')}
              id="tab-notification-channels"
            >
              <Webhook size={15} /> Notification Channels ({channels.length})
            </button>
          )}
          {allowMutate && (
            <button
              type="button"
              className="btn-glass"
              onClick={handleEvaluateConditions}
              disabled={evaluating}
              id="btn-evaluate-conditions-now"
            >
              <RefreshCw size={14} className={evaluating ? 'spin' : ''} />
              {evaluating ? 'Evaluating...' : 'Evaluate Conditions Now'}
            </button>
          )}
        </div>
      </div>

      {/* KPI Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
        <div className="glass-card" style={{ padding: '1rem 1.25rem' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Open Unacknowledged</div>
          <div style={{ fontSize: '1.65rem', fontWeight: 700, color: openCount > 0 ? '#f59e0b' : '#10b981' }}>
            {openCount}
          </div>
        </div>
        <div className="glass-card" style={{ padding: '1rem 1.25rem' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Critical Severity Active</div>
          <div style={{ fontSize: '1.65rem', fontWeight: 700, color: criticalCount > 0 ? '#ef4444' : '#10b981' }}>
            {criticalCount}
          </div>
        </div>
        <div className="glass-card" style={{ padding: '1rem 1.25rem' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Acknowledged / In Progress</div>
          <div style={{ fontSize: '1.65rem', fontWeight: 700, color: '#38bdf8' }}>{ackCount}</div>
        </div>
        <div className="glass-card" style={{ padding: '1rem 1.25rem' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Outbound Channels Active</div>
          <div style={{ fontSize: '1.65rem', fontWeight: 700, color: 'var(--primary)' }}>
            {channels.filter((c) => c.enabled).length}
          </div>
        </div>
      </div>

      {notice && (() => {
        const isAlertErr = !notice.startsWith('✓') && /fail|error|required/i.test(notice);
        return (
          <div
            className="glass-card"
            style={{
              padding: '0.75rem 1.15rem',
              background: isAlertErr ? 'rgba(239, 68, 68, 0.12)' : 'rgba(56, 189, 248, 0.12)',
              borderColor: isAlertErr ? 'rgba(239, 68, 68, 0.35)' : 'rgba(56, 189, 248, 0.35)',
              color: isAlertErr ? '#fca5a5' : 'var(--text-main)',
              fontSize: '0.82rem'
            }}
          >
            {isAlertErr ? '⚠ ' : ''}{notice}
          </div>
        );
      })()}

      {activeTab === 'incidents' ? (
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
            <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap' }}>
              {(['open', 'acknowledged', 'snoozed', 'resolved', 'all'] as const).map((st) => (
                <button
                  key={st}
                  type="button"
                  className={`btn-glass ${statusFilter === st ? 'btn-primary' : ''}`}
                  style={{ fontSize: '0.76rem', padding: '0.32rem 0.75rem', textTransform: 'capitalize' }}
                  onClick={() => setStatusFilter(st)}
                >
                  {st}
                </button>
              ))}
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <select
                className="glass-select"
                style={{ width: 'auto', fontSize: '0.78rem' }}
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical Only</option>
                <option value="warning">Warning</option>
                <option value="info">Informational</option>
              </select>
              <button type="button" className="btn-glass btn-icon" onClick={loadData} title="Refresh Queue">
                <RefreshCw size={14} className={loading ? 'spin' : ''} />
              </button>
            </div>
          </div>

          <div className="table-wrapper">
            <table className="glass-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Endpoint / Entity</th>
                  <th>Condition &amp; Telemetry Detail</th>
                  <th>Status / Assignee</th>
                  <th>Triggered</th>
                  {allowMutate && <th style={{ textAlign: 'right' }}>Incident Actions</th>}
                </tr>
              </thead>
              <tbody>
                {incidents.length === 0 ? (
                  <tr>
                    <td colSpan={allowMutate ? 6 : 5} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-dim)' }}>
                      No alert incidents match the current filter. Click &quot;Evaluate Conditions Now&quot; to run policy health checks across all online endpoints.
                    </td>
                  </tr>
                ) : (
                  incidents.map((inc) => (
                    <tr key={inc.id}>
                      <td>
                        <span
                          className={`status-pill ${
                            inc.severity === 'critical'
                              ? 'status-offline'
                              : inc.severity === 'warning'
                              ? 'status-reboot'
                              : 'status-online'
                          }`}
                          style={{ fontSize: '0.7rem', display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}
                        >
                          {inc.severity === 'critical' ? <ShieldAlert size={12} /> : <AlertTriangle size={12} />}
                          {inc.severity.toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <div style={{ fontWeight: 700, fontSize: '0.84rem' }}>{inc.entity_name}</div>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                          {inc.tenant_name || 'Global Fleet'}
                          {inc.occurrence_count && inc.occurrence_count > 1 ? ` • ${inc.occurrence_count}x` : ''}
                        </div>
                      </td>
                      <td>
                        <div style={{ fontWeight: 600, fontSize: '0.82rem' }}>{inc.title}</div>
                        <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>{inc.detail}</div>
                        {inc.psa_ticket_number && (
                          <span style={{ fontSize: '0.7rem', color: 'var(--primary)' }}>
                            PSA Ticket #{inc.psa_ticket_number}
                          </span>
                        )}
                      </td>
                      <td>
                        <span
                          className={`status-pill ${
                            inc.status === 'resolved'
                              ? 'status-online'
                              : inc.status === 'open'
                              ? 'status-reboot'
                              : ''
                          }`}
                          style={{ fontSize: '0.68rem', textTransform: 'uppercase' }}
                        >
                          {inc.status}
                        </span>
                        {inc.assigned_to && (
                          <div style={{ fontSize: '0.72rem', color: '#38bdf8', marginTop: '0.2rem' }}>
                            Owner: {inc.assigned_to}
                          </div>
                        )}
                        {inc.snoozed_until && inc.status === 'snoozed' && (
                          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.15rem' }}>
                            Until {new Date(inc.snoozed_until).toLocaleTimeString()}
                          </div>
                        )}
                      </td>
                      <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {new Date(inc.triggered_at).toLocaleString()}
                      </td>
                      {allowMutate && (
                        <td style={{ textAlign: 'right' }}>
                          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.35rem', flexWrap: 'wrap' }}>
                            {inc.status === 'open' && (
                              <button
                                type="button"
                                className="btn-glass"
                                style={{ padding: '0.22rem 0.55rem', fontSize: '0.72rem' }}
                                onClick={async () => {
                                  await acknowledgeAlertIncident(inc.id);
                                  loadData();
                                }}
                              >
                                Ack
                              </button>
                            )}
                            {inc.status !== 'resolved' && (
                              <>
                                <button
                                  type="button"
                                  className="btn-glass"
                                  style={{ padding: '0.22rem 0.55rem', fontSize: '0.72rem' }}
                                  title="Snooze 1 Hour"
                                  onClick={async () => {
                                    await snoozeAlertIncident(inc.id, 60);
                                    loadData();
                                  }}
                                >
                                  <Clock size={12} /> 1h
                                </button>
                                <input
                                  type="text"
                                  className="glass-input"
                                  style={{ width: '95px', padding: '0.2rem 0.45rem', fontSize: '0.72rem' }}
                                  placeholder="Assignee"
                                  value={assignInputs[inc.id] ?? ''}
                                  onChange={(e) =>
                                    setAssignInputs((prev) => ({ ...prev, [inc.id]: e.target.value }))
                                  }
                                />
                                {assignInputs[inc.id]?.trim() && (
                                  <button
                                    type="button"
                                    className="btn-glass"
                                    style={{ padding: '0.22rem 0.5rem', fontSize: '0.72rem' }}
                                    onClick={async () => {
                                      await assignAlertIncident(inc.id, assignInputs[inc.id].trim());
                                      setAssignInputs((prev) => ({ ...prev, [inc.id]: '' }));
                                      loadData();
                                    }}
                                  >
                                    <UserCheck size={12} />
                                  </button>
                                )}
                                <button
                                  type="button"
                                  className="btn-glass btn-primary"
                                  style={{ padding: '0.22rem 0.6rem', fontSize: '0.72rem' }}
                                  onClick={async () => {
                                    await resolveAlertIncident(inc.id);
                                    loadData();
                                  }}
                                >
                                  <CheckCircle2 size={12} /> Resolve
                                </button>
                              </>
                            )}
                          </div>
                        </td>
                      )}
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {allowMutate && (
            <form onSubmit={handleCreateChannel} className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 600, margin: 0 }}>
                Add Outbound Alert Notification Channel
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: '0.75rem' }}>
                <div>
                  <label className="form-label">Channel Name</label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="NOC Critical Slack"
                    value={chanName}
                    onChange={(e) => setChanName(e.target.value)}
                  />
                </div>
                <div>
                  <label className="form-label">Provider Type</label>
                  <select
                    className="glass-select"
                    value={chanType}
                    onChange={(e) => setChanType(e.target.value as any)}
                  >
                    <option value="slack">Slack Incoming Webhook</option>
                    <option value="teams">Microsoft Teams Adaptive Card</option>
                    <option value="discord">Discord Webhook</option>
                    <option value="pagerduty">PagerDuty Events API v2</option>
                    <option value="webhook">Generic JSON HMAC-SHA256 Webhook</option>
                  </select>
                </div>
                <div>
                  <label className="form-label">Minimum Severity</label>
                  <select
                    className="glass-select"
                    value={chanMinSeverity}
                    onChange={(e) => setChanMinSeverity(e.target.value)}
                  >
                    <option value="info">All (Info+)</option>
                    <option value="warning">Warning &amp; Critical</option>
                    <option value="critical">Critical Only</option>
                  </select>
                </div>
                <div>
                  <label className="form-label">Client Scope</label>
                  <select
                    className="glass-select"
                    value={chanTenantId}
                    onChange={(e) => setChanTenantId(e.target.value)}
                  >
                    <option value="">Global (All Clients)</option>
                    {tenants.map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.name}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr auto', gap: '0.75rem', alignItems: 'end' }}>
                <div>
                  <label className="form-label">Webhook Endpoint URL (SSRF-Validated HTTPS)</label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="https://hooks.slack.com/services/..."
                    value={chanUrl}
                    onChange={(e) => setChanUrl(e.target.value)}
                  />
                </div>
                <div>
                  <label className="form-label">PagerDuty Routing Key (Optional)</label>
                  <input
                    type="password"
                    className="glass-input"
                    placeholder="Integration key"
                    value={chanRoutingKey}
                    onChange={(e) => setChanRoutingKey(e.target.value)}
                  />
                </div>
                <div>
                  <label className="form-label">HMAC Signing Secret (Vaulted)</label>
                  <input
                    type="password"
                    className="glass-input"
                    placeholder="Optional secret"
                    value={chanSecret}
                    onChange={(e) => setChanSecret(e.target.value)}
                  />
                </div>
                <button type="submit" className="btn-glass btn-primary">
                  <Plus size={15} /> Save Channel
                </button>
              </div>
            </form>
          )}

          <div className="glass-card">
            <div className="table-wrapper">
              <table className="glass-table">
                <thead>
                  <tr>
                    <th>Channel</th>
                    <th>Provider</th>
                    <th>Min Severity</th>
                    <th>Last Dispatch</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {channels.length === 0 ? (
                    <tr>
                      <td colSpan={5} style={{ textAlign: 'center', padding: '1.75rem', color: 'var(--text-dim)' }}>
                        No outbound notification channels configured yet.
                      </td>
                    </tr>
                  ) : (
                    channels.map((ch) => (
                      <tr key={ch.id}>
                        <td style={{ fontWeight: 600 }}>{ch.name}</td>
                        <td>
                          <span className="status-pill status-online" style={{ fontSize: '0.68rem', textTransform: 'uppercase' }}>
                            {ch.channel_type}
                          </span>
                        </td>
                        <td style={{ textTransform: 'capitalize', fontSize: '0.8rem' }}>{ch.min_severity}</td>
                        <td style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                          {ch.last_triggered_at
                            ? `${new Date(ch.last_triggered_at).toLocaleString()} (${ch.last_status || 'ok'})`
                            : 'Never tested'}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.4rem' }}>
                            {allowMutate && (
                              <>
                                <button
                                  type="button"
                                  className="btn-glass"
                                  style={{ padding: '0.25rem 0.65rem', fontSize: '0.74rem' }}
                                  disabled={testingId === ch.id}
                                  onClick={() => handleTestChannel(ch.id, ch.name)}
                                >
                                  <Send size={12} /> {testingId === ch.id ? 'Sending...' : 'Test'}
                                </button>
                                <button
                                  type="button"
                                  className="btn-glass btn-icon"
                                  onClick={async () => {
                                    await deleteNotificationChannel(ch.id);
                                    loadData();
                                  }}
                                >
                                  <Trash2 size={13} color="#ef4444" />
                                </button>
                              </>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

