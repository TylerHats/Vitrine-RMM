import React, { useState, useEffect, useCallback } from 'react';
import { ArrowRight, Sliders, Edit3, X, Clock, KeyRound, ShieldCheck, Database, Zap, Plus, Trash2, Bell } from 'lucide-react';
import { Policy, Device, Tenant, ConditionAlertRule } from '../types/index.js';
import { fetchPolicies, updatePolicy, createPolicy, deletePolicy, evaluatePolicyConditions } from '../services/api.js';

interface PoliciesViewProps {
  devices: Device[];
  tenants?: Tenant[];
}

interface InheritanceNode {
  tier: string;
  name: string;
}

interface EffectivePolicy {
  inheritanceChain: InheritanceNode[];
  telemetryIntervalSec: number;
  requireRemoteConsent: boolean;
  consentTimeoutSec: number;
  autoLockOnDisconnect: boolean;
  bitlockerEnforcement?: boolean;
  patchSchedule: string;
  patchRebootEnforcement?: string;
  maxSnoozeHours?: number;
  forceRebootAfterSnooze?: boolean;
  finalCountdownSec?: number;
  lapsAccountName?: string;
  lapsAutoCreateAccount?: boolean;
  lapsPasswordMode?: 'random' | 'passphrase' | 'static';
  lapsRotationDays?: number;
  lapsCleanupOldAccountOnRename?: 'disable' | 'delete' | 'keep';
  lapsDisableBuiltinSid500Admin?: boolean;
  lapsOffboardExplicitDeviceAction?: string;
  lapsOffboardClientArchivedAction?: string;
  lapsOffboardClientDeletedAction?: string;
  offboardOfflineAutoArchiveDays?: number;
  alertRules?: ConditionAlertRule[];
}

export const PoliciesView: React.FC<PoliciesViewProps> = ({ devices, tenants = [] }) => {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState<string>(devices[0]?.id || '');
  const [effectivePolicy, setEffectivePolicy] = useState<EffectivePolicy | null>(null);
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [evaluatingConditions, setEvaluatingConditions] = useState(false);
  const [evalSummaryMsg, setEvalSummaryMsg] = useState<string | null>(null);

  const handleEvaluateConditionsNow = async () => {
    setEvaluatingConditions(true);
    setEvalSummaryMsg(null);
    try {
      const res = await evaluatePolicyConditions();
      if (res.success) {
        setEvalSummaryMsg(
          `✓ Evaluated ${res.evaluatedDevices} active endpoints & ${res.evaluatedAppliances} specialty appliances across 4-tier policies: ${res.triggeredConditions.length} condition(s) matched → ${res.webUiNotificationsCreated} Web UI alert(s), ${res.emailsDispatched} Email dispatch(es), and ${res.psaTicketsCreated} Direct PSA Ticket(s) created.`
        );
      }
    } finally {
      setEvaluatingConditions(false);
    }
  };

  const handleUpdateAlertRule = (index: number, patch: Partial<ConditionAlertRule>) => {
    if (!editingPolicy) return;
    const currentRules = [...(editingPolicy.alert_rules || [])];
    if (!currentRules[index]) return;
    currentRules[index] = { ...currentRules[index], ...patch };
    setEditingPolicy({ ...editingPolicy, alert_rules: currentRules });
  };

  // Create Policy Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newPolicyName, setNewPolicyName] = useState('');
  const [newPolicyTier, setNewPolicyTier] = useState<'client' | 'site' | 'role'>('client');
  const [newPolicyTargetId, setNewPolicyTargetId] = useState(tenants[0]?.id || 'ten-1');
  const [newPolicyTelemetry, setNewPolicyTelemetry] = useState(15);
  const [newPolicyPatchSchedule, setNewPolicyPatchSchedule] = useState('Sat 03:00 AM');

  const loadPolicies = useCallback(() => {
    fetchPolicies().then(setPolicies);
  }, []);

  useEffect(() => {
    loadPolicies();
  }, [loadPolicies]);

  const loadEffective = useCallback(() => {
    if (!selectedDeviceId) return;
    fetch(`/api/policies/effective/${selectedDeviceId}`)
      .then((res) => res.json())
      .then(setEffectivePolicy);
  }, [selectedDeviceId]);

  useEffect(() => {
    loadEffective();
  }, [loadEffective]);

  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPolicyName.trim()) return;
    const res = await createPolicy({
      name: newPolicyName.trim(),
      tier: newPolicyTier,
      target_id: newPolicyTargetId,
      telemetry_interval_sec: newPolicyTelemetry,
      patch_schedule: newPolicyPatchSchedule
    });
    if (res.success) {
      loadPolicies();
      loadEffective();
      setShowCreateModal(false);
      setNewPolicyName('');
    }
  };

  const handleDeletePolicy = async (id: string) => {
    await deletePolicy(id);
    loadPolicies();
    loadEffective();
  };

  const handleSavePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingPolicy) return;
    setSavingPolicy(true);
    try {
      await updatePolicy(editingPolicy.id, {
        name: editingPolicy.name,
        telemetry_interval_sec: editingPolicy.telemetry_interval_sec,
        require_remote_consent: editingPolicy.require_remote_consent,
        consent_timeout_sec: editingPolicy.consent_timeout_sec,
        consent_timeout_action: editingPolicy.consent_timeout_action,
        auto_lock_on_disconnect: editingPolicy.auto_lock_on_disconnect,
        patch_schedule: editingPolicy.patch_schedule,
        patch_reboot_enforcement: editingPolicy.patch_reboot_enforcement,
        max_snooze_hours: editingPolicy.max_snooze_hours,
        force_reboot_after_snooze: editingPolicy.force_reboot_after_snooze,
        final_countdown_sec: editingPolicy.final_countdown_sec,
        laps_enabled: editingPolicy.laps_enabled,
        laps_account_name: editingPolicy.laps_account_name,
        laps_auto_create_account: editingPolicy.laps_auto_create_account,
        laps_password_mode: editingPolicy.laps_password_mode,
        laps_passphrase_words: editingPolicy.laps_passphrase_words,
        laps_passphrase_separator: editingPolicy.laps_passphrase_separator,
        laps_static_password: editingPolicy.laps_static_password,
        laps_password_length: editingPolicy.laps_password_length,
        laps_complexity: editingPolicy.laps_complexity,
        laps_rotation_days: editingPolicy.laps_rotation_days,
        laps_rotate_on_access: editingPolicy.laps_rotate_on_access,
        laps_post_access_grace_hours: editingPolicy.laps_post_access_grace_hours,
        laps_cleanup_old_account_on_rename: editingPolicy.laps_cleanup_old_account_on_rename,
        laps_disable_builtin_sid500_admin: editingPolicy.laps_disable_builtin_sid500_admin,
        laps_offboard_explicit_device_action: editingPolicy.laps_offboard_explicit_device_action,
        laps_offboard_client_archived_action: editingPolicy.laps_offboard_client_archived_action,
        laps_offboard_client_deleted_action: editingPolicy.laps_offboard_client_deleted_action,
        offboard_offline_auto_archive_days: editingPolicy.offboard_offline_auto_archive_days,
        require_mfa_for_secrets: editingPolicy.require_mfa_for_secrets,
        telemetry_history_retention_days: editingPolicy.telemetry_history_retention_days,
        hardware_audit_enabled: editingPolicy.hardware_audit_enabled,
        network_drift_detection_enabled: editingPolicy.network_drift_detection_enabled,
        self_healing_max_hourly_runs: editingPolicy.self_healing_max_hourly_runs,
        self_healing_alert_psa: editingPolicy.self_healing_alert_psa,
        alert_rules: editingPolicy.alert_rules
      });
      loadPolicies();
      loadEffective();
      setEditingPolicy(null);
    } catch (err) {
      console.error('Failed to update policy:', err);
    } finally {
      setSavingPolicy(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="policies-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
            Hierarchical Policy Inheritance &amp; Reboot Governance
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Multi-tiered governance cascading from Global &rarr; Client Tenant &rarr; Site Location &rarr; Device Role with configurable tray snooze and transparent forced reboot HUD timers
          </span>
        </div>
        <div style={{ display: 'flex', gap: '0.65rem', flexWrap: 'wrap' }}>
          <button
            className="btn-glass"
            style={{ borderColor: 'rgba(56, 189, 248, 0.45)', color: '#38bdf8' }}
            disabled={evaluatingConditions}
            onClick={handleEvaluateConditionsNow}
          >
            <Bell size={15} />{' '}
            {evaluatingConditions ? 'Evaluating 4-Tier Conditions...' : 'Evaluate Fleet Conditions & Dispatch Alerts'}
          </button>
          <button className="btn-glass btn-primary" onClick={() => setShowCreateModal(true)}>
            <Plus size={16} /> Create Tier Policy
          </button>
        </div>
      </div>

      {evalSummaryMsg && (
        <div
          className="glass-card"
          style={{
            padding: '0.8rem 1.25rem',
            background: 'rgba(56, 189, 248, 0.12)',
            borderColor: 'rgba(56, 189, 248, 0.35)',
            color: '#7dd3fc',
            fontSize: '0.84rem'
          }}
        >
          {evalSummaryMsg}
        </div>
      )}

      {/* Inheritance Architecture Diagram */}
      <div className="glass-card" style={{ background: 'var(--glass-bg)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-around', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ textAlign: 'center' }}>
            <div className="status-pill status-online" style={{ fontSize: '0.78rem', marginBottom: '0.5rem' }}>Tier 1: Global</div>
            <div style={{ fontWeight: 600 }}>MSP Default Baseline</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Applies to all tenants</div>
          </div>
          <ArrowRight size={20} color="var(--primary)" />
          <div style={{ textAlign: 'center' }}>
            <div className="status-pill status-reboot" style={{ fontSize: '0.78rem', marginBottom: '0.5rem' }}>Tier 2: Client</div>
            <div style={{ fontWeight: 600 }}>Tenant Specific Rules</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Overrides Global settings</div>
          </div>
          <ArrowRight size={20} color="var(--primary)" />
          <div style={{ textAlign: 'center' }}>
            <div className="status-pill status-isolated" style={{ fontSize: '0.78rem', marginBottom: '0.5rem', background: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa' }}>Tier 3: Site</div>
            <div style={{ fontWeight: 600 }}>Branch / Subnet Rules</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Overrides Client tier</div>
          </div>
          <ArrowRight size={20} color="var(--primary)" />
          <div style={{ textAlign: 'center' }}>
            <div className="status-pill status-isolated" style={{ fontSize: '0.78rem', marginBottom: '0.5rem', background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc' }}>Tier 4: Role</div>
            <div style={{ fontWeight: 600 }}>Device Role (DC/Server/POS)</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Highest precedence</div>
          </div>
        </div>
      </div>

      {/* Interactive Simulator */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '1.5rem' }}>
        {/* Policy Definitions List */}
        <div className="glass-card" style={{ padding: 0 }}>
          <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--glass-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: '1.05rem', fontWeight: 600, margin: 0 }}>Defined Tier Policies ({policies.length})</h3>
          </div>
          <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
            <table className="glass-table">
              <thead>
                <tr>
                  <th>Tier</th>
                  <th>Policy Name</th>
                  <th>Telemetry</th>
                  <th>Max Snooze</th>
                  <th>Forced HUD</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {policies.map((p) => (
                  <tr key={p.id}>
                    <td>
                      <span className="status-pill status-online" style={{ fontSize: '0.7rem' }}>
                        {p.tier.toUpperCase()}
                      </span>
                    </td>
                    <td><strong>{p.name}</strong></td>
                    <td>{p.telemetry_interval_sec}s</td>
                    <td>
                      <span style={{ fontWeight: 600, color: 'var(--accent-primary, #00f2fe)' }}>
                        {p.max_snooze_hours ?? 8}h Max
                      </span>
                    </td>
                    <td>
                      {p.force_reboot_after_snooze ? (
                        <span style={{ fontSize: '0.72rem', padding: '0.15rem 0.45rem', borderRadius: '4px', background: 'rgba(239, 68, 68, 0.2)', color: '#f87171' }}>
                          {p.final_countdown_sec ?? 300}s Timer
                        </span>
                      ) : (
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Disabled</span>
                      )}
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                        <button
                          className="btn-glass"
                          onClick={() => setEditingPolicy(p)}
                          style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                        >
                          <Edit3 size={12} />
                          <span>Edit</span>
                        </button>
                        {p.tier !== 'global' && (
                          <button
                            className="btn-glass btn-icon"
                            title="Delete Tier Policy"
                            style={{ padding: '0.2rem 0.4rem' }}
                            onClick={() => handleDeletePolicy(p.id)}
                          >
                            <Trash2 size={12} color="#ef4444" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Live Resolved Policy Inspector */}
        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
            <h3 style={{ fontSize: '1.05rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0 }}>
              <Sliders size={18} color="var(--primary)" />
              <span>Effective Device Policy Inspector</span>
            </h3>
            <select
              className="glass-select"
              style={{ width: '200px' }}
              value={selectedDeviceId}
              onChange={(e) => setSelectedDeviceId(e.target.value)}
            >
              {devices.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.hostname} ({d.device_role})
                </option>
              ))}
            </select>
          </div>

          {effectivePolicy ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ background: 'rgba(0, 242, 254, 0.08)', padding: '0.85rem 1rem', borderRadius: '8px', border: '1px solid rgba(0, 242, 254, 0.2)' }}>
                <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--primary)', marginBottom: '0.35rem' }}>
                  ACTIVE INHERITANCE CHAIN
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', fontSize: '0.78rem' }}>
                  {effectivePolicy.inheritanceChain.map((node: InheritanceNode, idx: number) => (
                    <React.Fragment key={idx}>
                      <span style={{ background: 'rgba(255, 255, 255, 0.1)', padding: '0.2rem 0.5rem', borderRadius: '4px' }}>
                        [{node.tier.toUpperCase()}] {node.name}
                      </span>
                      {idx < effectivePolicy.inheritanceChain.length - 1 && <ArrowRight size={12} color="var(--text-dim)" />}
                    </React.Fragment>
                  ))}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem', fontSize: '0.85rem' }}>
                <div className="glass-card" style={{ padding: '0.85rem' }}>
                  <div style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>Telemetry Rate</div>
                  <div style={{ fontWeight: 600, fontSize: '1.05rem', color: 'var(--primary)' }}>
                    Every {effectivePolicy.telemetryIntervalSec} seconds
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '0.85rem' }}>
                  <div style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>Remote Consent Rule</div>
                  <div style={{ fontWeight: 600, fontSize: '1.05rem', color: effectivePolicy.requireRemoteConsent ? '#fbbf24' : '#10b981' }}>
                    {effectivePolicy.requireRemoteConsent ? `Prompt (${effectivePolicy.consentTimeoutSec}s)` : 'Instant Connect'}
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '0.85rem' }}>
                  <div style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>Max Tray Snooze Timeout</div>
                  <div style={{ fontWeight: 600, fontSize: '1.05rem', color: 'var(--accent-primary, #00f2fe)' }}>
                    {effectivePolicy.maxSnoozeHours ?? 8} Hours Limit
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '0.85rem' }}>
                  <div style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>Transparent Forced Reboot HUD</div>
                  <div style={{ fontWeight: 600, fontSize: '1.05rem', color: effectivePolicy.forceRebootAfterSnooze ? '#f87171' : '#64748b' }}>
                    {effectivePolicy.forceRebootAfterSnooze ? `Active (${effectivePolicy.finalCountdownSec ?? 300}s timer)` : 'Disabled'}
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '0.85rem', gridColumn: 'span 2' }}>
                  <div style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>Patch Reboot Enforcement Rule</div>
                  <div style={{ fontWeight: 600, fontSize: '0.95rem', marginTop: '0.15rem' }}>
                    {effectivePolicy.patchRebootEnforcement}
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '0.85rem', gridColumn: 'span 2', borderColor: 'rgba(245, 158, 11, 0.3)' }}>
                  <div style={{ color: '#fbbf24', fontSize: '0.75rem', fontWeight: 600 }}>Resolved LAPS Local Admin &amp; Offboarding Governance</div>
                  <div style={{ fontWeight: 600, fontSize: '0.86rem', marginTop: '0.2rem' }}>
                    Account: <code>{effectivePolicy.lapsAccountName || 'VitrineAdmin'}</code> • Mode:{' '}
                    <span style={{ color: '#38bdf8' }}>{(effectivePolicy.lapsPasswordMode || 'random').toUpperCase()}</span> •{' '}
                    SID-500 Hardening: <span style={{ color: effectivePolicy.lapsDisableBuiltinSid500Admin !== false ? '#10b981' : '#94a3b8' }}>
                      {effectivePolicy.lapsDisableBuiltinSid500Admin !== false ? 'Disabled' : 'Untouched'}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginTop: '0.3rem' }}>
                    Offboard Rules — Device: <code>{effectivePolicy.lapsOffboardExplicitDeviceAction || 'remove_account'}</code> • Client Archive:{' '}
                    <code>{effectivePolicy.lapsOffboardClientArchivedAction || 'keep_account_rotate_final'}</code> • Client Delete:{' '}
                    <code>{effectivePolicy.lapsOffboardClientDeletedAction || 'remove_account'}</code> • Offline Auto-Archive:{' '}
                    <strong>{effectivePolicy.offboardOfflineAutoArchiveDays ?? 14}d</strong>
                  </div>
                </div>

                {effectivePolicy.alertRules && effectivePolicy.alertRules.length > 0 && (
                  <div className="glass-card" style={{ padding: '0.85rem', gridColumn: 'span 2', borderColor: 'rgba(56, 189, 248, 0.3)' }}>
                    <div style={{ color: '#38bdf8', fontSize: '0.75rem', fontWeight: 600, marginBottom: '0.45rem' }}>
                      Resolved 4-Tier Condition &amp; State Notification Routing ({effectivePolicy.alertRules.filter((r) => r.enabled).length} Active Watchdogs)
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', maxHeight: '175px', overflowY: 'auto' }}>
                      {effectivePolicy.alertRules
                        .filter((r) => r.enabled)
                        .map((r) => (
                          <div
                            key={r.conditionId}
                            style={{
                              display: 'flex',
                              justifyContent: 'space-between',
                              alignItems: 'center',
                              fontSize: '0.74rem',
                              padding: '0.3rem 0.5rem',
                              borderRadius: '6px',
                              background: 'rgba(255, 255, 255, 0.03)'
                            }}
                          >
                            <span>
                              <strong>{r.label}</strong>{' '}
                              {r.thresholdUnit !== 'state' && (
                                <code style={{ color: '#fbbf24' }}>
                                  ({r.thresholdValue} {r.thresholdUnit})
                                </code>
                              )}
                            </span>
                            <div style={{ display: 'flex', gap: '0.3rem' }}>
                              {r.notifyWebUi && <span className="status-pill status-online" style={{ fontSize: '0.62rem' }}>Web UI</span>}
                              {r.notifyEmail && <span className="status-pill status-reboot" style={{ fontSize: '0.62rem' }}>Email</span>}
                              {r.createPsaTicket && (
                                <span className="status-pill status-isolated" style={{ fontSize: '0.62rem' }}>PSA Ticket</span>
                              )}
                            </div>
                          </div>
                        ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div>Loading effective policy cascade...</div>
          )}
        </div>
      </div>

      {/* Create Tier Policy Modal */}
      {showCreateModal && (
        <div className="modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="glass-modal" style={{ maxWidth: '480px', padding: '1.5rem' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>Create Hierarchical Tier Policy</h3>
              <button className="btn-glass btn-icon" onClick={() => setShowCreateModal(false)}>
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleCreatePolicy} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Policy Name
                </label>
                <input
                  type="text"
                  required
                  className="glass-input"
                  placeholder="e.g. Executive Laptops High-Security Policy"
                  value={newPolicyName}
                  onChange={(e) => setNewPolicyName(e.target.value)}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Hierarchy Tier
                  </label>
                  <select
                    className="glass-select"
                    value={newPolicyTier}
                    onChange={(e) => {
                      const tier = e.target.value as 'client' | 'site' | 'role';
                      setNewPolicyTier(tier);
                      if (tier === 'client') setNewPolicyTargetId(tenants[0]?.id || 'ten-1');
                      else if (tier === 'site') setNewPolicyTargetId('site-1');
                      else setNewPolicyTargetId('Workstation');
                    }}
                  >
                    <option value="client">Tier 2: Client Tenant</option>
                    <option value="site">Tier 3: Site Location</option>
                    <option value="role">Tier 4: Device Role</option>
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Target Scope ({newPolicyTier})
                  </label>
                  {newPolicyTier === 'client' ? (
                    <select
                      className="glass-select"
                      value={newPolicyTargetId}
                      onChange={(e) => setNewPolicyTargetId(e.target.value)}
                    >
                      {tenants.map((t) => (
                        <option key={t.id} value={t.id}>{t.name}</option>
                      ))}
                    </select>
                  ) : newPolicyTier === 'site' ? (
                    <select
                      className="glass-select"
                      value={newPolicyTargetId}
                      onChange={(e) => setNewPolicyTargetId(e.target.value)}
                    >
                      {tenants.flatMap((t) => t.sites || []).map((s) => (
                        <option key={s.id} value={s.id}>{s.name} ({s.subnet})</option>
                      ))}
                    </select>
                  ) : (
                    <input
                      type="text"
                      className="glass-input"
                      placeholder="e.g. Workstation or Domain Controller"
                      value={newPolicyTargetId}
                      onChange={(e) => setNewPolicyTargetId(e.target.value)}
                    />
                  )}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Telemetry Interval (Sec)
                  </label>
                  <input
                    type="number"
                    min={5}
                    max={3600}
                    className="glass-input"
                    value={newPolicyTelemetry}
                    onChange={(e) => setNewPolicyTelemetry(Number(e.target.value))}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Patch Window
                  </label>
                  <input
                    type="text"
                    className="glass-input"
                    value={newPolicyPatchSchedule}
                    onChange={(e) => setNewPolicyPatchSchedule(e.target.value)}
                  />
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button type="button" className="btn-glass" onClick={() => setShowCreateModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-glass btn-primary">
                  Create Policy
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Policy Modal */}
      {editingPolicy && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(8px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '1.5rem'
          }}
          onClick={() => setEditingPolicy(null)}
        >
          <div
            className="glass-card"
            style={{
              width: '100%',
              maxWidth: '620px',
              maxHeight: '90vh',
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: '1.25rem',
              padding: '1.75rem',
              border: '1px solid rgba(255, 255, 255, 0.15)',
              boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7)'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Edit3 size={18} color="var(--accent-primary, #00f2fe)" />
                <h3 style={{ fontSize: '1.25rem', fontWeight: 700, margin: 0 }}>
                  Configure Policy: {editingPolicy.name}
                </h3>
              </div>
              <button
                onClick={() => setEditingPolicy(null)}
                style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer' }}
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleSavePolicy} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                  Policy Name
                </label>
                <input
                  type="text"
                  required
                  className="glass-input"
                  value={editingPolicy.name}
                  onChange={(e) => setEditingPolicy({ ...editingPolicy, name: e.target.value })}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div>
                  <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                    Telemetry Interval (Seconds)
                  </label>
                  <input
                    type="number"
                    min={5}
                    max={3600}
                    className="glass-input"
                    value={editingPolicy.telemetry_interval_sec}
                    onChange={(e) => setEditingPolicy({ ...editingPolicy, telemetry_interval_sec: Number(e.target.value) })}
                  />
                </div>

                <div>
                  <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                    Patch Schedule Window
                  </label>
                  <input
                    type="text"
                    className="glass-input"
                    value={editingPolicy.patch_schedule}
                    onChange={(e) => setEditingPolicy({ ...editingPolicy, patch_schedule: e.target.value })}
                  />
                </div>
              </div>

              {/* Update Reminder & Reboot Controls (User Request 1) */}
              <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <Clock size={16} color="var(--accent-primary, #00f2fe)" />
                  <span style={{ fontWeight: 600, fontSize: '0.9rem', color: '#fff' }}>
                    Tray Update Reminder &amp; Reboot Snooze Policy
                  </span>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                  <div>
                    <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                      Maximum Snooze Duration (Hours)
                    </label>
                    <select
                      className="glass-select"
                      value={editingPolicy.max_snooze_hours ?? 8}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, max_snooze_hours: Number(e.target.value) })}
                    >
                      <option value={1}>1 Hour (Strict)</option>
                      <option value={2}>2 Hours</option>
                      <option value={4}>4 Hours</option>
                      <option value={8}>8 Hours (Standard Business Day)</option>
                      <option value={12}>12 Hours</option>
                      <option value={24}>24 Hours (1 Day)</option>
                    </select>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.2rem', display: 'block' }}>
                      Cumulative snooze allowed before forced reboot sequence engages.
                    </span>
                  </div>

                  <div>
                    <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                      Final Transparent Countdown (Seconds)
                    </label>
                    <select
                      className="glass-select"
                      value={editingPolicy.final_countdown_sec ?? 300}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, final_countdown_sec: Number(e.target.value) })}
                    >
                      <option value={60}>60 Seconds (1 Minute)</option>
                      <option value={180}>180 Seconds (3 Minutes)</option>
                      <option value={300}>300 Seconds (5 Minutes - Default)</option>
                      <option value={600}>600 Seconds (10 Minutes)</option>
                    </select>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.2rem', display: 'block' }}>
                      Timer displayed on bottom-left transparent HUD before shutdown.
                    </span>
                  </div>
                </div>

                <div style={{ marginTop: '0.25rem' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem' }}>
                    <input
                      type="checkbox"
                      checked={Boolean(editingPolicy.force_reboot_after_snooze)}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, force_reboot_after_snooze: e.target.checked ? 1 : 0 })}
                    />
                    <span>Force Reboot when Maximum Snooze Timeout is reached</span>
                  </label>
                </div>
              </div>

              <div>
                <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                  Patch Reboot Enforcement Description
                </label>
                <input
                  type="text"
                  className="glass-input"
                  value={editingPolicy.patch_reboot_enforcement}
                  onChange={(e) => setEditingPolicy({ ...editingPolicy, patch_reboot_enforcement: e.target.value })}
                />
              </div>

              {/* LAPS & Local Administrator Governance */}
              <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <KeyRound size={16} color="#fbbf24" />
                  <span style={{ fontWeight: 600, fontSize: '0.9rem', color: '#fff' }}>
                    Automated Local Administrator (LAPS) Vault &amp; Endpoint Account Governance
                  </span>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                  <div>
                    <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                      Local Admin Account Name (Supports Template Tokens)
                    </label>
                    <input
                      type="text"
                      className="glass-input"
                      placeholder="e.g. VitrineAdmin or {ClientSlug}Admin"
                      value={editingPolicy.laps_account_name || 'VitrineAdmin'}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, laps_account_name: e.target.value })}
                    />
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-dim)', marginTop: '0.2rem', display: 'block' }}>
                      Tokens: <code>{'{ClientSlug}'}</code>, <code>{'{SiteSlug}'}</code>, <code>{'{Role}'}</code> (e.g. <code>{'{ClientSlug}Admin'}</code>)
                    </span>
                  </div>

                  <div>
                    <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                      Password Generation Mode
                    </label>
                    <select
                      className="glass-select"
                      value={editingPolicy.laps_password_mode || 'random'}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, laps_password_mode: e.target.value as 'random' | 'passphrase' | 'static' })}
                    >
                      <option value="random">Random High-Entropy Characters</option>
                      <option value="passphrase">Human-Readable Diceware Passphrase</option>
                      <option value="static">Static Emergency Admin Password</option>
                    </select>
                  </div>
                </div>

                {(editingPolicy.laps_password_mode || 'random') === 'random' && (
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                    <div>
                      <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                        Random Password Length
                      </label>
                      <select
                        className="glass-select"
                        value={editingPolicy.laps_password_length ?? 24}
                        onChange={(e) => setEditingPolicy({ ...editingPolicy, laps_password_length: Number(e.target.value) })}
                      >
                        <option value={16}>16 Characters</option>
                        <option value={20}>20 Characters</option>
                        <option value={24}>24 Characters (Standard)</option>
                        <option value={32}>32 Characters (High Security)</option>
                      </select>
                    </div>
                    <div>
                      <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                        Character Complexity
                      </label>
                      <select
                        className="glass-select"
                        value={editingPolicy.laps_complexity || 'alphanumeric_symbols'}
                        onChange={(e) => setEditingPolicy({ ...editingPolicy, laps_complexity: e.target.value })}
                      >
                        <option value="alphanumeric_symbols">Upper + Lower + Numbers + Symbols</option>
                        <option value="alphanumeric">Alphanumeric Only (No Symbols)</option>
                      </select>
                    </div>
                  </div>
                )}

                {editingPolicy.laps_password_mode === 'passphrase' && (
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                    <div>
                      <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                        Passphrase Word Count
                      </label>
                      <select
                        className="glass-select"
                        value={editingPolicy.laps_passphrase_words ?? 4}
                        onChange={(e) => setEditingPolicy({ ...editingPolicy, laps_passphrase_words: Number(e.target.value) })}
                      >
                        <option value={3}>3 Words + Number</option>
                        <option value={4}>4 Words + Number (Recommended)</option>
                        <option value={5}>5 Words + Number</option>
                        <option value={6}>6 Words + Number (Max Entropy)</option>
                      </select>
                    </div>
                    <div>
                      <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                        Word Separator
                      </label>
                      <select
                        className="glass-select"
                        value={editingPolicy.laps_passphrase_separator || '-'}
                        onChange={(e) => setEditingPolicy({ ...editingPolicy, laps_passphrase_separator: e.target.value })}
                      >
                        <option value="-">Hyphen (-) e.g. Cobalt-Falcon-84!</option>
                        <option value=".">Period (.) e.g. Cobalt.Falcon.84!</option>
                        <option value="_">Underscore (_) e.g. Cobalt_Falcon_84!</option>
                      </select>
                    </div>
                  </div>
                )}

                {editingPolicy.laps_password_mode === 'static' && (
                  <div>
                    <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                      Static Local Admin Password (Per Client / Site / Role Tier)
                    </label>
                    <input
                      type="password"
                      className="glass-input"
                      placeholder="Enter static fallback local admin password..."
                      value={editingPolicy.laps_static_password || ''}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, laps_static_password: e.target.value })}
                    />
                  </div>
                )}

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                  <div>
                    <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                      Rotation Frequency (Days)
                    </label>
                    <select
                      className="glass-select"
                      value={editingPolicy.laps_rotation_days ?? 30}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, laps_rotation_days: Number(e.target.value) })}
                    >
                      <option value={1}>1 Day (Daily)</option>
                      <option value={7}>7 Days (Weekly)</option>
                      <option value={14}>14 Days (Bi-weekly)</option>
                      <option value={30}>30 Days (Monthly - Recommended)</option>
                      <option value={60}>60 Days</option>
                      <option value={90}>90 Days (Quarterly)</option>
                    </select>
                  </div>

                  <div>
                    <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                      Post-Access Rotation Grace Window (Hours)
                    </label>
                    <select
                      className="glass-select"
                      value={editingPolicy.laps_post_access_grace_hours ?? 2}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, laps_post_access_grace_hours: Number(e.target.value) })}
                    >
                      <option value={1}>1 Hour</option>
                      <option value={2}>2 Hours (Recommended)</option>
                      <option value={4}>4 Hours</option>
                      <option value={8}>8 Hours</option>
                    </select>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.25rem' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem' }}>
                    <input
                      type="checkbox"
                      checked={Boolean(editingPolicy.laps_enabled ?? 1)}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, laps_enabled: e.target.checked ? 1 : 0 })}
                    />
                    <span>Enable Automated LAPS for endpoints bound to this policy</span>
                  </label>

                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem' }}>
                    <input
                      type="checkbox"
                      checked={Boolean(editingPolicy.laps_auto_create_account ?? 1)}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, laps_auto_create_account: e.target.checked ? 1 : 0 })}
                    />
                    <span>Ensure &amp; Auto-Create Managed Local Admin Account on Endpoint PCs (Add to Administrators / sudoers &amp; keep enabled)</span>
                  </label>

                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem' }}>
                    <input
                      type="checkbox"
                      checked={Boolean(editingPolicy.laps_rotate_on_access ?? 1)}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, laps_rotate_on_access: e.target.checked ? 1 : 0 })}
                    />
                    <span>Automatically rotate password after technician reveals/accesses it</span>
                  </label>

                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem' }}>
                    <input
                      type="checkbox"
                      checked={Boolean(editingPolicy.laps_disable_builtin_sid500_admin ?? 1)}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, laps_disable_builtin_sid500_admin: e.target.checked ? 1 : 0 })}
                    />
                    <span>Harden Endpoint: Automatically disable built-in OS SID <code>-500</code> Administrator account once managed LAPS admin is active</span>
                  </label>
                </div>

                {/* Old Account Cleanup on Username Rename + 4-Tier Offboarding Local Admin Governance */}
                <div style={{ marginTop: '0.5rem', paddingTop: '0.75rem', borderTop: '1px solid rgba(255, 255, 255, 0.08)', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  <div style={{ fontSize: '0.82rem', fontWeight: 700, color: '#fbbf24' }}>
                    Account Rename Cleanup &amp; 4-Tier Offboarding Local Admin Rules
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                    <div>
                      <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.3rem' }}>
                        Previous Managed Account on Rename
                      </label>
                      <select
                        className="glass-select"
                        value={editingPolicy.laps_cleanup_old_account_on_rename || 'disable'}
                        onChange={(e) => setEditingPolicy({ ...editingPolicy, laps_cleanup_old_account_on_rename: e.target.value as any })}
                      >
                        <option value="disable">Disable Old Managed Account (Safe Default)</option>
                        <option value="delete">Delete Old Managed Account Completely</option>
                        <option value="keep">Leave Old Managed Account Untouched</option>
                      </select>
                    </div>

                    <div>
                      <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.3rem' }}>
                        Offline Pending-Offboard Auto-Archive (Days)
                      </label>
                      <select
                        className="glass-select"
                        value={editingPolicy.offboard_offline_auto_archive_days ?? 14}
                        onChange={(e) => setEditingPolicy({ ...editingPolicy, offboard_offline_auto_archive_days: Number(e.target.value) })}
                      >
                        <option value={3}>3 Days Offline &rarr; Move to Archive</option>
                        <option value={7}>7 Days Offline &rarr; Move to Archive</option>
                        <option value={14}>14 Days Offline &rarr; Move to Archive (Default)</option>
                        <option value={30}>30 Days Offline &rarr; Move to Archive</option>
                        <option value={60}>60 Days Offline &rarr; Move to Archive</option>
                      </select>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.75rem' }}>
                    <div>
                      <label style={{ fontSize: '0.73rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.3rem' }}>
                        1. Explicit Agent Offboard
                      </label>
                      <select
                        className="glass-select"
                        style={{ fontSize: '0.76rem' }}
                        value={editingPolicy.laps_offboard_explicit_device_action || 'remove_account'}
                        onChange={(e) => setEditingPolicy({ ...editingPolicy, laps_offboard_explicit_device_action: e.target.value as any })}
                      >
                        <option value="remove_account">Remove Local Admin Account</option>
                        <option value="disable_account">Disable Local Admin Account</option>
                        <option value="keep_account_rotate_final">Keep Account &amp; Rotate Final Password</option>
                        <option value="keep_account_as_is">Keep Local Admin Account As-Is</option>
                      </select>
                    </div>

                    <div>
                      <label style={{ fontSize: '0.73rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.3rem' }}>
                        2. Client Archived / Offboarded
                      </label>
                      <select
                        className="glass-select"
                        style={{ fontSize: '0.76rem' }}
                        value={editingPolicy.laps_offboard_client_archived_action || 'keep_account_rotate_final'}
                        onChange={(e) => setEditingPolicy({ ...editingPolicy, laps_offboard_client_archived_action: e.target.value as any })}
                      >
                        <option value="keep_account_rotate_final">Keep Account &amp; Rotate Final Password</option>
                        <option value="remove_account">Remove Local Admin Account</option>
                        <option value="disable_account">Disable Local Admin Account</option>
                        <option value="keep_account_as_is">Keep Local Admin Account As-Is</option>
                      </select>
                    </div>

                    <div>
                      <label style={{ fontSize: '0.73rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.3rem' }}>
                        3. Client Permanently Deleted
                      </label>
                      <select
                        className="glass-select"
                        style={{ fontSize: '0.76rem' }}
                        value={editingPolicy.laps_offboard_client_deleted_action || 'remove_account'}
                        onChange={(e) => setEditingPolicy({ ...editingPolicy, laps_offboard_client_deleted_action: e.target.value as any })}
                      >
                        <option value="remove_account">Remove Local Admin Account</option>
                        <option value="disable_account">Disable Local Admin Account</option>
                        <option value="keep_account_rotate_final">Keep Account &amp; Rotate Final Password</option>
                        <option value="keep_account_as_is">Keep Local Admin Account As-Is</option>
                      </select>
                    </div>
                  </div>
                </div>
              </div>

              {/* Zero-Trust & MFA Settings */}
              <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <ShieldCheck size={16} color="#34d399" />
                  <span style={{ fontWeight: 600, fontSize: '0.9rem', color: '#fff' }}>
                    Zero-Trust Secret Protection &amp; Step-Up MFA
                  </span>
                </div>

                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem' }}>
                  <input
                    type="checkbox"
                    checked={Boolean(editingPolicy.require_mfa_for_secrets ?? 1)}
                    onChange={(e) => setEditingPolicy({ ...editingPolicy, require_mfa_for_secrets: e.target.checked ? 1 : 0 })}
                  />
                  <span>Require Step-Up MFA Authenticator (TOTP) to decrypt LAPS passwords, BitLocker keys, and secure attributes</span>
                </label>
              </div>

              {/* Telemetry & Audit Retention */}
              <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <Database size={16} color="#38bdf8" />
                  <span style={{ fontWeight: 600, fontSize: '0.9rem', color: '#fff' }}>
                    Telemetry History Retention &amp; Hardware/Network Watchdogs
                  </span>
                </div>

                <div>
                  <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                    Performance History Storage Retention (Days)
                  </label>
                  <select
                    className="glass-select"
                    value={editingPolicy.telemetry_history_retention_days ?? 90}
                    onChange={(e) => setEditingPolicy({ ...editingPolicy, telemetry_history_retention_days: Number(e.target.value) })}
                  >
                    <option value={30}>30 Days</option>
                    <option value={60}>60 Days</option>
                    <option value={90}>90 Days (Quarterly Standard)</option>
                    <option value={180}>180 Days (Half Year)</option>
                    <option value={365}>365 Days (1 Full Year)</option>
                  </select>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem' }}>
                    <input
                      type="checkbox"
                      checked={Boolean(editingPolicy.hardware_audit_enabled ?? 1)}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, hardware_audit_enabled: e.target.checked ? 1 : 0 })}
                    />
                    <span>Track and audit hardware alterations (RAM upgrades, disk swaps, GPU changes) with PCI vendor decoding</span>
                  </label>

                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem' }}>
                    <input
                      type="checkbox"
                      checked={Boolean(editingPolicy.network_drift_detection_enabled ?? 1)}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, network_drift_detection_enabled: e.target.checked ? 1 : 0 })}
                    />
                    <span>Log network transitions and alert on unauthorized/rogue corporate subnet drift</span>
                  </label>
                </div>
              </div>

              {/* Self-Healing Circuit Breaker */}
              <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <Zap size={16} color="#a855f7" />
                  <span style={{ fontWeight: 600, fontSize: '0.9rem', color: '#fff' }}>
                    Automated Self-Healing Circuit Breakers &amp; Ticketing
                  </span>
                </div>

                <div>
                  <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                    Max Remediation Runs Per Hour (Flap Breaker)
                  </label>
                  <select
                    className="glass-select"
                    value={editingPolicy.self_healing_max_hourly_runs ?? 3}
                    onChange={(e) => setEditingPolicy({ ...editingPolicy, self_healing_max_hourly_runs: Number(e.target.value) })}
                  >
                    <option value={1}>1 Run / Hour (Conservative)</option>
                    <option value={3}>3 Runs / Hour (Recommended Default)</option>
                    <option value={5}>5 Runs / Hour</option>
                    <option value={10}>10 Runs / Hour</option>
                  </select>
                </div>

                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem' }}>
                  <input
                    type="checkbox"
                    checked={Boolean(editingPolicy.self_healing_alert_psa ?? 1)}
                    onChange={(e) => setEditingPolicy({ ...editingPolicy, self_healing_alert_psa: e.target.checked ? 1 : 0 })}
                  />
                  <span>Automatically open High-Priority PSA Incident Ticket when self-healing circuit breaker trips</span>
                </label>
              </div>

              {/* 4-Tier Condition & State Notification Routing Matrix (Web UI, Email, Direct PSA Ticket) */}
              {editingPolicy.alert_rules && editingPolicy.alert_rules.length > 0 && (
                <div style={{ background: 'rgba(56, 189, 248, 0.04)', border: '1px solid rgba(56, 189, 248, 0.25)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                      <Bell size={16} color="#38bdf8" />
                      <span style={{ fontWeight: 700, fontSize: '0.9rem', color: '#fff' }}>
                        Per-Tier Condition &amp; State Notification Matrix ({editingPolicy.tier.toUpperCase()} Level)
                      </span>
                    </div>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                      Configure thresholds &amp; independent Web UI, Email, and Direct PSA Ticket routing per state
                    </span>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '320px', overflowY: 'auto', paddingRight: '0.25rem' }}>
                    {editingPolicy.alert_rules.map((rule, idx) => (
                      <div
                        key={rule.conditionId}
                        style={{
                          padding: '0.6rem 0.75rem',
                          borderRadius: '6px',
                          background: rule.enabled ? 'var(--glass-bg)' : 'rgba(148, 163, 184, 0.06)',
                          border: '1px solid var(--border-color)',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '0.45rem'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                          <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '0.78rem', fontWeight: 600, cursor: 'pointer', color: rule.enabled ? 'var(--text-main)' : 'var(--text-dim)' }}>
                            <input
                              type="checkbox"
                              checked={rule.enabled}
                              onChange={(e) => handleUpdateAlertRule(idx, { enabled: e.target.checked })}
                            />
                            <span>{rule.label}</span>
                          </label>

                          {rule.thresholdUnit !== 'state' && (
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                              <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>Threshold:</span>
                              <input
                                type="number"
                                step={rule.thresholdUnit === 'cvss' ? 0.1 : 1}
                                min={1}
                                className="glass-input"
                                style={{ width: '68px', padding: '0.2rem 0.4rem', fontSize: '0.75rem' }}
                                value={rule.thresholdValue}
                                onChange={(e) => handleUpdateAlertRule(idx, { thresholdValue: Number(e.target.value) })}
                              />
                              {rule.conditionId === 'endpoint_offline' ? (
                                <select
                                  className="glass-select"
                                  style={{ width: 'auto', padding: '0.2rem 0.45rem', fontSize: '0.73rem' }}
                                  value={rule.thresholdUnit}
                                  onChange={(e) => handleUpdateAlertRule(idx, { thresholdUnit: e.target.value as any })}
                                >
                                  <option value="days">Days Offline</option>
                                  <option value="hours">Hours Offline</option>
                                </select>
                              ) : (
                                <span style={{ fontSize: '0.72rem', color: '#38bdf8' }}>{rule.thresholdUnit}</span>
                              )}
                            </div>
                          )}
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.6rem', fontSize: '0.73rem', color: '#cbd5e1' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', flexWrap: 'wrap' }}>
                            <label style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', cursor: 'pointer' }}>
                              <input
                                type="checkbox"
                                checked={rule.notifyWebUi}
                                onChange={(e) => handleUpdateAlertRule(idx, { notifyWebUi: e.target.checked })}
                              />
                              <span>Web UI Alert</span>
                            </label>
                            <label style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', cursor: 'pointer' }}>
                              <input
                                type="checkbox"
                                checked={rule.notifyEmail}
                                onChange={(e) => handleUpdateAlertRule(idx, { notifyEmail: e.target.checked })}
                              />
                              <span>Email Notification</span>
                            </label>
                            <label style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', cursor: 'pointer' }}>
                              <input
                                type="checkbox"
                                checked={rule.createPsaTicket}
                                onChange={(e) => handleUpdateAlertRule(idx, { createPsaTicket: e.target.checked })}
                              />
                              <span style={{ color: rule.createPsaTicket ? '#fbbf24' : undefined }}>Direct PSA Ticket</span>
                            </label>
                            <label style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', cursor: 'pointer' }}>
                              <input
                                type="checkbox"
                                checked={rule.autoResolveTicket}
                                onChange={(e) => handleUpdateAlertRule(idx, { autoResolveTicket: e.target.checked })}
                              />
                              <span>Auto-Close Ticket on Recovery</span>
                            </label>
                          </div>

                          <select
                            className="glass-select"
                            style={{ width: 'auto', padding: '0.15rem 0.45rem', fontSize: '0.7rem' }}
                            value={rule.severity}
                            onChange={(e) => handleUpdateAlertRule(idx, { severity: e.target.value as any })}
                          >
                            <option value="info">Severity: Info</option>
                            <option value="warning">Severity: Warning</option>
                            <option value="critical">Severity: Critical</option>
                          </select>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.75rem' }}>
                <button
                  type="button"
                  className="btn-glass"
                  onClick={() => setEditingPolicy(null)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={savingPolicy}
                  className="btn-glass btn-primary"
                >
                  {savingPolicy ? 'Saving Changes...' : 'Save Policy'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
