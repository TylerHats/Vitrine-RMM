import React, { useState, useEffect, useCallback, useRef } from 'react';
import { ArrowRight, Sliders, Edit3, X, Clock, KeyRound, ShieldCheck, Database, Zap, Plus, Trash2, Bell, AlertCircle, Upload, Monitor } from 'lucide-react';
import { Policy, Device, Tenant, ConditionAlertRule, BackupPolicy, MdmProfile, AuthUser, TrayMenuItem } from '../types/index.js';
import {
  fetchPolicies,
  updatePolicy,
  createPolicy,
  deletePolicy,
  evaluatePolicyConditions,
  fetchEffectiveDevicePolicy,
  fetchBackupPolicies,
  fetchMdmProfiles,
  uploadPolicyTrayIcon
} from '../services/api.js';
import { canMutateFleet } from '../utils/permissions.js';
import { MfaChallengeModal } from '../components/MfaChallengeModal.js';
import { IconCropModal } from '../components/IconCropModal.js';

interface PoliciesViewProps {
  devices: Device[];
  tenants?: Tenant[];
  currentUser?: AuthUser | null;
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
  patchRing?: 'canary' | 'pilot' | 'production';
  patchDelayDays?: number;
  managedDefenderEnabled?: boolean;
  backupPolicyId?: string | null;
  mdmProfileId?: string | null;
  alertRules?: ConditionAlertRule[];
  trayBrandName?: string;
  trayIconUrl?: string;
  trayThemeMode?: 'system' | 'dark' | 'light';
  trayEnabled?: boolean;
  trayTooltip?: string;
  traySupportUrl?: string;
  traySupportPhone?: string;
  traySupportEmail?: string;
  trayMenuItems?: TrayMenuItem[];
  companionAutoDeploy?: boolean;
}

const DEFAULT_TRAY_MENU_ITEMS: TrayMenuItem[] = [
  { id: 'tray-support', label: 'Open Support Portal', action: 'open_url', target: '', enabled: true },
  { id: 'tray-info', label: 'Show Device Info', action: 'show_device_info', target: '', enabled: true },
  { id: 'tray-help', label: 'Request Remote Help', action: 'request_remote_help', target: '', enabled: true },
  { id: 'tray-copy', label: 'Copy Hostname & IP', action: 'copy_hostname', target: '', enabled: true }
];

function parseTrayMenuItemsFromPolicy(p: Policy | null): TrayMenuItem[] | null {
  if (!p) return null;
  if (Array.isArray(p.tray_menu_items)) {
    return p.tray_menu_items.map((item) => ({ ...item }));
  }
  if (typeof p.tray_menu_items_json === 'string' && p.tray_menu_items_json.trim() !== '') {
    try {
      const parsed = JSON.parse(p.tray_menu_items_json);
      if (Array.isArray(parsed)) return parsed;
    } catch {
      // Fall back when tray menu JSON is invalid
    }
  }
  return null;
}

export const PoliciesView: React.FC<PoliciesViewProps> = ({ devices, tenants = [], currentUser }) => {
  const canMutate = canMutateFleet(currentUser);
  const trayIconInputRef = useRef<HTMLInputElement | null>(null);
  const [cropPolicyIconFile, setCropPolicyIconFile] = useState<File | null>(null);
  const [uploadingTrayIcon, setUploadingTrayIcon] = useState(false);
  const [trayIconStatus, setTrayIconStatus] = useState<string | null>(null);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [backupPolicies, setBackupPolicies] = useState<BackupPolicy[]>([]);
  const [mdmProfiles, setMdmProfiles] = useState<MdmProfile[]>([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState<string>(devices[0]?.id || '');
  const [effectivePolicy, setEffectivePolicy] = useState<EffectivePolicy | null>(null);
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [listNotice, setListNotice] = useState<{ text: string; isError?: boolean } | null>(null);
  const [createPolicyError, setCreatePolicyError] = useState<string | null>(null);
  const [mfaRetryAction, setMfaRetryAction] = useState<'save' | 'create' | null>(null);
  const [evaluatingConditions, setEvaluatingConditions] = useState(false);
  const [evalSummaryMsg, setEvalSummaryMsg] = useState<string | null>(null);

  const handleEvaluateConditionsNow = async () => {
    setEvaluatingConditions(true);
    setEvalSummaryMsg(null);
    try {
      const res = await evaluatePolicyConditions();
      if (res.success) {
        setEvalSummaryMsg(
          `✓ Evaluated ${res.evaluatedDevices} active endpoints & ${res.evaluatedAppliances} specialty appliances across 4-tier policies: ${res.triggeredConditions.length} condition(s) matched → ${res.webUiNotificationsCreated} Web UI alert(s), ${res.emailsDispatched} Email dispatch(es), and ${res.psaTicketsCreated} Support Ticket(s) created.`
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

  const getEditingTrayItems = (pol: Policy): TrayMenuItem[] => {
    const parsed = parseTrayMenuItemsFromPolicy(pol);
    if (parsed !== null) return parsed;
    return pol.tier === 'global' ? DEFAULT_TRAY_MENU_ITEMS.map((item) => ({ ...item })) : [];
  };

  const handleUpdateTrayMenuItem = (index: number, patch: Partial<TrayMenuItem>) => {
    if (!editingPolicy) return;
    const items = getEditingTrayItems(editingPolicy);
    if (!items[index]) return;
    items[index] = { ...items[index], ...patch };
    setEditingPolicy({ ...editingPolicy, tray_menu_items: items });
  };

  const handleAddTrayMenuItem = () => {
    if (!editingPolicy) return;
    const items = getEditingTrayItems(editingPolicy);
    items.push({
      id: `tray-${Date.now()}`,
      label: 'Custom Support Link',
      action: 'open_url',
      target: editingPolicy.tray_support_url || '',
      enabled: true
    });
    setEditingPolicy({ ...editingPolicy, tray_menu_items: items });
  };

  const handleRemoveTrayMenuItem = (index: number) => {
    if (!editingPolicy) return;
    const items = getEditingTrayItems(editingPolicy).filter((_, i) => i !== index);
    setEditingPolicy({ ...editingPolicy, tray_menu_items: items });
  };

  const handleTrayIconFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (trayIconInputRef.current) trayIconInputRef.current.value = '';
    if (!file || !editingPolicy) return;
    setTrayIconStatus(null);
    setCropPolicyIconFile(file);
  };

  const handleTrayIconCropped = async (cropped: { filename: string; base64Data: string }) => {
    setCropPolicyIconFile(null);
    if (!editingPolicy) return;
    setUploadingTrayIcon(true);
    setTrayIconStatus(null);
    try {
      const res = await uploadPolicyTrayIcon(editingPolicy.id, cropped.filename, cropped.base64Data);
      if (res.success && res.tray_icon_url) {
        setEditingPolicy((prev) => (prev ? { ...prev, tray_icon_url: res.tray_icon_url } : prev));
        setTrayIconStatus('Square icon saved for EXE installers & endpoint tray.');
      } else {
        setTrayIconStatus(res.error || 'Failed to upload custom icon.');
      }
    } catch (err: any) {
      setTrayIconStatus(err?.message || 'Failed to upload custom icon.');
    } finally {
      setUploadingTrayIcon(false);
    }
  };

  // Create Policy Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newPolicyName, setNewPolicyName] = useState('');
  const [newPolicyTier, setNewPolicyTier] = useState<'client' | 'site' | 'role'>('client');
  const [newPolicyTargetId, setNewPolicyTargetId] = useState(tenants[0]?.id || 'ten-1');
  const [newPolicyTelemetry, setNewPolicyTelemetry] = useState(15);
  const [newPolicyPatchSchedule, setNewPolicyPatchSchedule] = useState('Sat 03:00 AM');
  const [newPolicyTrayEnabled, setNewPolicyTrayEnabled] = useState(true);
  const [newPolicyAutoDeployCompanion, setNewPolicyAutoDeployCompanion] = useState(true);
  const [newPolicyTrayBrandName, setNewPolicyTrayBrandName] = useState('');

  const loadPolicies = useCallback(() => {
    fetchPolicies().then(setPolicies).catch(() => {});
    fetchBackupPolicies().then(setBackupPolicies).catch(() => {});
    fetchMdmProfiles().then(setMdmProfiles).catch(() => {});
  }, []);

  useEffect(() => {
    loadPolicies();
  }, [loadPolicies]);

  useEffect(() => {
    if (!selectedDeviceId && devices[0]?.id) {
      setSelectedDeviceId(devices[0].id);
    }
  }, [devices, selectedDeviceId]);

  const loadEffective = useCallback(() => {
    if (!selectedDeviceId) return;
    fetchEffectiveDevicePolicy(selectedDeviceId)
      .then((res) => setEffectivePolicy(res as EffectivePolicy))
      .catch(() => {});
  }, [selectedDeviceId]);

  useEffect(() => {
    loadEffective();
  }, [loadEffective]);

  const performCreatePolicy = async () => {
    if (!newPolicyName.trim()) return;
    setCreatePolicyError(null);
    try {
      const res = await createPolicy({
        name: newPolicyName.trim(),
        tier: newPolicyTier,
        target_id: newPolicyTargetId,
        telemetry_interval_sec: newPolicyTelemetry,
        patch_schedule: newPolicyPatchSchedule,
        tray_enabled: newPolicyTrayEnabled ? 1 : 0,
        companion_auto_deploy: newPolicyAutoDeployCompanion ? 1 : 0,
        tray_brand_name: newPolicyTrayBrandName.trim() || undefined
      });
      if (res.mfaRequired) {
        setMfaRetryAction('create');
        return;
      }
      if (res.success) {
        loadPolicies();
        loadEffective();
        setShowCreateModal(false);
        setNewPolicyName('');
        setNewPolicyTrayBrandName('');
      } else {
        setCreatePolicyError(res.error || 'Failed to create policy.');
      }
    } catch (err: any) {
      setCreatePolicyError(err?.message || 'Failed to create policy.');
    }
  };

  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    await performCreatePolicy();
  };

  const handleDeletePolicy = async (id: string) => {
    if (!confirm('Delete this tier policy? Endpoints inheriting it will revert to parent policy tiers.')) return;
    setListNotice(null);
    try {
      const res = await deletePolicy(id);
      if (!res.success) {
        setListNotice({ text: res.error || 'Failed to delete policy.', isError: true });
        return;
      }
      setListNotice({ text: 'Tier policy deleted.' });
      loadPolicies();
      loadEffective();
    } catch (err: any) {
      setListNotice({ text: err?.message || 'Failed to delete policy.', isError: true });
    }
  };

  const performSavePolicy = async () => {
    if (!editingPolicy) return;
    setSavingPolicy(true);
    setPolicyError(null);
    const isGlobal = editingPolicy.tier === 'global';
    const parsedTrayItems = parseTrayMenuItemsFromPolicy(editingPolicy);
    const trayItemsToSave =
      Array.isArray(editingPolicy.tray_menu_items)
        ? editingPolicy.tray_menu_items
        : isGlobal
          ? parsedTrayItems ?? DEFAULT_TRAY_MENU_ITEMS.map((item) => ({ ...item }))
          : parsedTrayItems ?? undefined;

    try {
      const res = await updatePolicy(editingPolicy.id, {
        name: editingPolicy.name,
        telemetry_interval_sec: editingPolicy.telemetry_interval_sec,
        require_remote_consent: editingPolicy.require_remote_consent,
        consent_timeout_sec: editingPolicy.consent_timeout_sec,
        consent_timeout_action: editingPolicy.consent_timeout_action,
        auto_lock_on_disconnect: editingPolicy.auto_lock_on_disconnect,
        bitlocker_enforced: isGlobal
          ? (editingPolicy.bitlocker_enforced ?? editingPolicy.bitlocker_enforcement ?? 1)
          : (editingPolicy.bitlocker_enforced ?? editingPolicy.bitlocker_enforcement ?? undefined),
        patch_schedule: isGlobal ? (editingPolicy.patch_schedule || '') : (editingPolicy.patch_schedule ?? undefined),
        patch_ring: isGlobal ? (editingPolicy.patch_ring || 'production') : (editingPolicy.patch_ring ?? undefined),
        patch_delay_days: isGlobal ? (editingPolicy.patch_delay_days ?? 0) : (editingPolicy.patch_delay_days ?? undefined),
        defender_managed: isGlobal
          ? (editingPolicy.defender_managed ?? editingPolicy.managed_defender_enabled ?? 1)
          : (editingPolicy.defender_managed ?? editingPolicy.managed_defender_enabled ?? undefined),
        backup_policy_id: isGlobal ? (editingPolicy.backup_policy_id || null) : editingPolicy.backup_policy_id,
        mdm_profile_id: isGlobal ? (editingPolicy.mdm_profile_id || null) : editingPolicy.mdm_profile_id,
        patch_reboot_enforcement: isGlobal
          ? (editingPolicy.patch_reboot_enforcement || '')
          : (editingPolicy.patch_reboot_enforcement ?? undefined),
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
        alert_rules: editingPolicy.alert_rules,
        tray_brand_name: editingPolicy.tray_brand_name ?? undefined,
        tray_icon_url: editingPolicy.tray_icon_url ?? undefined,
        tray_theme_mode: editingPolicy.tray_theme_mode ?? undefined,
        tray_enabled:
          editingPolicy.tray_enabled === undefined || editingPolicy.tray_enabled === null
            ? undefined
            : editingPolicy.tray_enabled
              ? 1
              : 0,
        tray_tooltip: editingPolicy.tray_tooltip ?? undefined,
        tray_support_url: editingPolicy.tray_support_url ?? undefined,
        tray_support_phone: editingPolicy.tray_support_phone ?? undefined,
        tray_support_email: editingPolicy.tray_support_email ?? undefined,
        tray_menu_items: trayItemsToSave,
        companion_auto_deploy:
          editingPolicy.companion_auto_deploy === undefined || editingPolicy.companion_auto_deploy === null
            ? undefined
            : editingPolicy.companion_auto_deploy
              ? 1
              : 0
      });
      if (res.mfaRequired) {
        setMfaRetryAction('save');
        return;
      }
      if (!res.success) {
        setPolicyError(res.error || 'Failed to update policy.');
        return;
      }
      loadPolicies();
      loadEffective();
      setEditingPolicy(null);
    } catch (err: any) {
      setPolicyError(err?.message || 'Failed to update policy.');
    } finally {
      setSavingPolicy(false);
    }
  };

  const handleSavePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    await performSavePolicy();
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
        {canMutate && (
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
            <button
              className="btn-glass btn-primary"
              onClick={() => {
                setCreatePolicyError(null);
                setShowCreateModal(true);
              }}
            >
              <Plus size={16} /> Create Tier Policy
            </button>
          </div>
        )}
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
                      <span
                        className="status-pill status-online"
                        style={{
                          fontSize: '0.7rem',
                          background: p.tier === 'quicksupport' ? 'rgba(16, 185, 129, 0.16)' : undefined,
                          color: p.tier === 'quicksupport' ? '#34d399' : undefined
                        }}
                      >
                        {p.tier === 'quicksupport' ? 'QUICKSUPPORT' : p.tier.toUpperCase()}
                      </span>
                    </td>
                    <td><strong>{p.name}</strong></td>
                    <td>{p.telemetry_interval_sec}s</td>
                    <td>
                      <span style={{ fontWeight: 600, color: 'var(--primary)' }}>
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
                      {canMutate ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                          <button
                            className="btn-glass"
                            onClick={() => {
                              setPolicyError(null);
                              setEditingPolicy(p);
                            }}
                            style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                          >
                            <Edit3 size={12} />
                            <span>Edit</span>
                          </button>
                          {p.tier !== 'global' && p.tier !== 'quicksupport' && (
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
                      ) : (
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Read-only</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {listNotice && (
            <div
              style={{
                marginTop: '0.75rem',
                padding: '0.65rem 0.9rem',
                borderRadius: '8px',
                fontSize: '0.8rem',
                background: listNotice.isError ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
                border: `1px solid ${listNotice.isError ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                color: listNotice.isError ? '#f87171' : '#34d399'
              }}
            >
              {listNotice.text}
            </div>
          )}
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
              disabled={devices.length === 0}
            >
              {devices.length === 0 ? (
                <option value="">No endpoints enrolled</option>
              ) : (
                devices.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.hostname} ({d.device_role})
                  </option>
                ))
              )}
            </select>
          </div>

          {devices.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', padding: '1rem 0' }}>
              No endpoints enrolled yet. Enroll a managed endpoint to inspect its live effective inherited policy cascade.
            </div>
          ) : effectivePolicy ? (
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
                  <div style={{ fontWeight: 600, fontSize: '1.05rem', color: 'var(--primary)' }}>
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
                  <div style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>Patch Ring &amp; Reboot Enforcement Rule</div>
                  <div style={{ fontWeight: 600, fontSize: '0.92rem', marginTop: '0.15rem' }}>
                    Ring: <span style={{ color: '#38bdf8' }}>{(effectivePolicy.patchRing || 'production').toUpperCase()}</span>{' '}
                    ({effectivePolicy.patchDelayDays ?? 0}d delay) • {effectivePolicy.patchRebootEnforcement || 'Standard Window'}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                    Managed AV/Defender: <strong>{effectivePolicy.managedDefenderEnabled !== false ? 'Enforced' : 'Monitor Only'}</strong> •{' '}
                    Disk Encryption: <strong>{effectivePolicy.bitlockerEnforcement ? 'Enforced (TPM Escrow)' : 'Audit Only'}</strong>
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

                <div className="glass-card" style={{ padding: '0.85rem', gridColumn: 'span 2', borderColor: 'rgba(0, 242, 254, 0.3)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                    <div>
                      <div style={{ color: '#00f2fe', fontSize: '0.75rem', fontWeight: 600 }}>Resolved Endpoint Companion &amp; Tray Branding</div>
                      <div style={{ fontWeight: 600, fontSize: '0.86rem', marginTop: '0.2rem' }}>
                        Tray UI: <span style={{ color: effectivePolicy.trayEnabled !== false ? '#10b981' : '#94a3b8' }}>
                          {effectivePolicy.trayEnabled !== false ? 'Visible' : 'Hidden (Service Only)'}
                        </span> • Brand Label: <code>{effectivePolicy.trayBrandName || 'Vitrine RMM'}</code> • Auto-Deploy:{' '}
                        <strong>{effectivePolicy.companionAutoDeploy !== false ? 'Enabled' : 'Manual'}</strong>
                      </div>
                      <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                        Theme: <code>{effectivePolicy.trayThemeMode || 'system'}</code> • Menu Items:{' '}
                        <strong>{Array.isArray(effectivePolicy.trayMenuItems) ? effectivePolicy.trayMenuItems.filter((m) => m.enabled !== false).length : 0}</strong>{' '}
                        {effectivePolicy.traySupportUrl ? `• Portal: ${effectivePolicy.traySupportUrl}` : ''}
                      </div>
                    </div>
                    {effectivePolicy.trayIconUrl && (
                      <img
                        src={effectivePolicy.trayIconUrl}
                        alt="Effective Tray Icon"
                        style={{ height: '32px', width: '32px', borderRadius: '6px', objectFit: 'contain', background: 'rgba(0,0,0,0.35)', padding: '2px' }}
                      />
                    )}
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
                                <span className="status-pill status-isolated" style={{ fontSize: '0.62rem' }}>Ticket</span>
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
                      else if (tier === 'site') {
                        const firstSite = tenants.flatMap((t) => t.sites || [])[0];
                        setNewPolicyTargetId(firstSite?.id || 'site-1');
                      } else setNewPolicyTargetId('Workstation');
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

              <div style={{ background: 'rgba(0, 242, 254, 0.04)', border: '1px solid rgba(0, 242, 254, 0.22)', borderRadius: '8px', padding: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.55rem' }}>
                <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#00f2fe' }}>
                  Companion Agent &amp; System Tray Defaults
                </div>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '0.78rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={newPolicyTrayEnabled}
                    onChange={(e) => setNewPolicyTrayEnabled(e.target.checked)}
                  />
                  <span>Show Endpoint System Tray Icon &amp; Support Menu</span>
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '0.78rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={newPolicyAutoDeployCompanion}
                    onChange={(e) => setNewPolicyAutoDeployCompanion(e.target.checked)}
                  />
                  <span>Auto-deploy Vitrine Companion on online MS2 devices in this scope</span>
                </label>
                <div>
                  <label style={{ fontSize: '0.74rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.2rem' }}>
                    Tray Brand Label Override (optional)
                  </label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="Inherit Global Brand Name"
                    value={newPolicyTrayBrandName}
                    onChange={(e) => setNewPolicyTrayBrandName(e.target.value)}
                  />
                </div>
              </div>

              {createPolicyError && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    padding: '0.65rem 0.85rem',
                    borderRadius: '8px',
                    background: 'rgba(239, 68, 68, 0.14)',
                    border: '1px solid rgba(239, 68, 68, 0.35)',
                    color: '#f87171',
                    fontSize: '0.78rem'
                  }}
                >
                  <AlertCircle size={15} style={{ flexShrink: 0 }} />
                  <span>{createPolicyError}</span>
                </div>
              )}

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
                <Edit3 size={18} color="var(--primary)" />
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
                    value={editingPolicy.patch_schedule || ''}
                    onChange={(e) => setEditingPolicy({ ...editingPolicy, patch_schedule: e.target.value })}
                  />
                </div>
              </div>

              {/* NinjaOne Parity: Patch Deployment Rings, Managed Endpoint Security, Backup & MDM Bindings */}
              <div style={{ background: 'rgba(56, 189, 248, 0.05)', border: '1px solid rgba(56, 189, 248, 0.22)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div style={{ fontWeight: 600, fontSize: '0.9rem', color: '#38bdf8' }}>
                  Patch Ring Rollout, Endpoint Security, Backup &amp; MDM Bindings
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                  <div>
                    <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                      Patch Deployment Ring
                    </label>
                    <select
                      className="glass-select"
                      value={editingPolicy.patch_ring || 'production'}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, patch_ring: e.target.value as any })}
                    >
                      <option value="canary">Ring 0 — Canary / Internal IT (0d delay)</option>
                      <option value="pilot">Ring 1 — Pilot Champions</option>
                      <option value="production">Ring 2 — Broad Production Fleet</option>
                    </select>
                  </div>
                  <div>
                    <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                      Ring Deferral Delay (Days post-release)
                    </label>
                    <input
                      type="number"
                      min={0}
                      max={60}
                      className="glass-input"
                      value={editingPolicy.patch_delay_days ?? 0}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, patch_delay_days: Number(e.target.value) })}
                    />
                  </div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                  <div>
                    <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                      Endpoint Backup Policy
                    </label>
                    <select
                      className="glass-select"
                      value={editingPolicy.backup_policy_id || ''}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, backup_policy_id: e.target.value || null })}
                    >
                      <option value="">-- Inherit / Unbound --</option>
                      {backupPolicies.map((bp) => (
                        <option key={bp.id} value={bp.id}>
                          {bp.name} ({bp.engine})
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                      MDM / OS Configuration Profile
                    </label>
                    <select
                      className="glass-select"
                      value={editingPolicy.mdm_profile_id || ''}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, mdm_profile_id: e.target.value || null })}
                    >
                      <option value="">-- Inherit / Unbound --</option>
                      {mdmProfiles.map((mp) => (
                        <option key={mp.id} value={mp.id}>
                          {mp.name} ({mp.platform})
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '1.25rem', flexWrap: 'wrap', fontSize: '0.8rem' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={Boolean(editingPolicy.defender_managed ?? editingPolicy.managed_defender_enabled ?? 1)}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, defender_managed: e.target.checked ? 1 : 0, managed_defender_enabled: e.target.checked ? 1 : 0 })}
                    />
                    <span>Enforce Managed Defender / ClamAV Real-Time Protection</span>
                  </label>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={Boolean(editingPolicy.bitlocker_enforced ?? editingPolicy.bitlocker_enforcement ?? 1)}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, bitlocker_enforced: e.target.checked ? 1 : 0, bitlocker_enforcement: e.target.checked ? 1 : 0 })}
                    />
                    <span>Enforce BitLocker / FileVault / LUKS Volume Encryption &amp; Escrow</span>
                  </label>
                </div>
              </div>

              {/* Remote Session Privacy Consent & Auto-Lock Controls */}
              <div style={{ background: 'var(--surface-panel)', border: '1px solid var(--glass-border)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-main)' }}>
                  Remote Control Privacy Consent &amp; Session Security
                </div>
                <div className="grid-2" style={{ gap: '0.85rem' }}>
                  <div>
                    <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                      End-User Consent Prompt
                    </label>
                    <select
                      className="glass-select"
                      value={
                        editingPolicy.require_remote_consent === undefined || editingPolicy.require_remote_consent === null
                          ? ''
                          : editingPolicy.require_remote_consent
                            ? '1'
                            : '0'
                      }
                      onChange={(e) =>
                        setEditingPolicy({
                          ...editingPolicy,
                          require_remote_consent:
                            e.target.value === '' ? undefined : Number(e.target.value)
                        })
                      }
                    >
                      {editingPolicy.tier !== 'global' && <option value="">Inherit from Parent Tier</option>}
                      <option value="1">Require User Approval Prompt</option>
                      <option value="0">Instant Connect (No Prompt)</option>
                    </select>
                  </div>

                  <div>
                    <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                      Consent Prompt Timeout (Seconds)
                    </label>
                    <input
                      type="number"
                      min={5}
                      max={300}
                      className="glass-input"
                      placeholder={editingPolicy.tier === 'global' ? '15' : 'Inherit'}
                      value={editingPolicy.consent_timeout_sec ?? ''}
                      onChange={(e) =>
                        setEditingPolicy({
                          ...editingPolicy,
                          consent_timeout_sec: e.target.value === '' ? undefined : Number(e.target.value)
                        })
                      }
                    />
                  </div>

                  <div>
                    <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                      Action If Consent Times Out
                    </label>
                    <select
                      className="glass-select"
                      value={editingPolicy.consent_timeout_action ?? ''}
                      onChange={(e) =>
                        setEditingPolicy({
                          ...editingPolicy,
                          consent_timeout_action: (e.target.value || undefined) as 'allow' | 'deny' | undefined
                        })
                      }
                    >
                      {editingPolicy.tier !== 'global' && <option value="">Inherit from Parent Tier</option>}
                      <option value="deny">Deny Remote Session</option>
                      <option value="allow">Auto-Allow After Countdown</option>
                    </select>
                  </div>

                  <div>
                    <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                      Auto-Lock Workstation on Disconnect
                    </label>
                    <select
                      className="glass-select"
                      value={
                        editingPolicy.auto_lock_on_disconnect === undefined || editingPolicy.auto_lock_on_disconnect === null
                          ? ''
                          : editingPolicy.auto_lock_on_disconnect
                            ? '1'
                            : '0'
                      }
                      onChange={(e) =>
                        setEditingPolicy({
                          ...editingPolicy,
                          auto_lock_on_disconnect:
                            e.target.value === '' ? undefined : Number(e.target.value)
                        })
                      }
                    >
                      {editingPolicy.tier !== 'global' && <option value="">Inherit from Parent Tier</option>}
                      <option value="1">Auto-Lock Screen on Disconnect</option>
                      <option value="0">Leave Session Unlocked</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Update Reminder & Reboot Controls */}
              <div style={{ background: 'var(--surface-panel)', border: '1px solid var(--glass-border)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <Clock size={16} color="var(--primary)" />
                  <span style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-main)' }}>
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
                  value={editingPolicy.patch_reboot_enforcement || ''}
                  onChange={(e) => setEditingPolicy({ ...editingPolicy, patch_reboot_enforcement: e.target.value })}
                />
              </div>

              {/* LAPS & Local Administrator Governance */}
              <div style={{ background: 'var(--surface-panel)', border: '1px solid var(--glass-border)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <KeyRound size={16} color="#fbbf24" />
                  <span style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-main)' }}>
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
                      value={editingPolicy.laps_account_name ?? ''}
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
              <div style={{ background: 'var(--surface-panel)', border: '1px solid var(--glass-border)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <ShieldCheck size={16} color="#34d399" />
                  <span style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-main)' }}>
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
              <div style={{ background: 'var(--surface-panel)', border: '1px solid var(--glass-border)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <Database size={16} color="#38bdf8" />
                  <span style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-main)' }}>
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
              <div style={{ background: 'var(--surface-panel)', border: '1px solid var(--glass-border)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <Zap size={16} color="#a855f7" />
                  <span style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-main)' }}>
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
                  <span>Automatically open High-Priority Support Ticket when self-healing triggers</span>
                </label>
              </div>

              {/* Companion Agent Tray Branding, Icon Override & Popup Menu Customizer */}
              <div style={{ background: 'rgba(0, 242, 254, 0.04)', border: '1px solid rgba(0, 242, 254, 0.25)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                    <Monitor size={16} color="var(--primary)" />
                    <span style={{ fontWeight: 700, fontSize: '0.9rem', color: 'var(--text-main)' }}>
                      Companion Agent Tray Branding &amp; Interactive Menu
                    </span>
                  </div>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                    Delivered automatically on companion install &amp; next agent check-in
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem' }}>
                    <input
                      type="checkbox"
                      checked={editingPolicy.tray_enabled !== 0 && editingPolicy.tray_enabled !== false}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, tray_enabled: e.target.checked ? 1 : 0 })}
                    />
                    <span>Enable Endpoint System Tray Icon &amp; Support Menu (uncheck on headless servers to run service-only)</span>
                  </label>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem' }}>
                    <input
                      type="checkbox"
                      checked={editingPolicy.companion_auto_deploy !== 0 && editingPolicy.companion_auto_deploy !== false}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, companion_auto_deploy: e.target.checked ? 1 : 0 })}
                    />
                    <span>Auto-deploy Vitrine Companion &amp; Tray onto online MS2-managed devices in this tier</span>
                  </label>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                  <div>
                    <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                      Tray Brand / Company Label Override
                    </label>
                    <input
                      type="text"
                      className="glass-input"
                      placeholder="Inherit Global Brand Name"
                      value={editingPolicy.tray_brand_name || ''}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, tray_brand_name: e.target.value })}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                      Tray &amp; HUD Color Theme
                    </label>
                    <select
                      className="glass-select"
                      value={editingPolicy.tray_theme_mode || 'inherit'}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, tray_theme_mode: e.target.value as any })}
                    >
                      <option value="inherit">Inherit Parent / Global Theme</option>
                      <option value="system">OS Registry Auto (AppsUseLightTheme)</option>
                      <option value="dark">Force Obsidian Dark</option>
                      <option value="light">Force Crisp Daylight</option>
                    </select>
                  </div>
                </div>

                {/* Custom Tray Icon Upload */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.85rem', padding: '0.65rem 0.85rem', background: 'rgba(255,255,255,0.03)', borderRadius: '6px', border: '1px solid var(--glass-border)', flexWrap: 'wrap' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                    {editingPolicy.tray_icon_url ? (
                      <img
                        src={editingPolicy.tray_icon_url}
                        alt="Tray Icon"
                        style={{ height: '32px', width: '32px', borderRadius: '6px', objectFit: 'contain', background: 'rgba(0,0,0,0.4)', padding: '2px' }}
                      />
                    ) : (
                      <div style={{ height: '32px', width: '32px', borderRadius: '6px', background: 'rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.65rem', color: 'var(--text-dim)' }}>
                        Auto
                      </div>
                    )}
                    <div>
                      <div style={{ fontSize: '0.78rem', fontWeight: 600 }}>Custom Tier EXE &amp; Tray Icon (PNG / JPEG / WebP / ICO)</div>
                      <div style={{ fontSize: '0.71rem', color: trayIconStatus ? '#34d399' : 'var(--text-dim)' }}>
                        {trayIconStatus || (editingPolicy.tray_icon_url ? `Embedded in EXEs & Tray: ${editingPolicy.tray_icon_url}` : 'Inheriting global or parent tier logo')}
                      </div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '0.45rem', alignItems: 'center' }}>
                    <input
                      ref={trayIconInputRef}
                      type="file"
                      accept="image/png,image/jpeg,image/webp,image/x-icon,.ico"
                      style={{ display: 'none' }}
                      onChange={handleTrayIconFileSelect}
                    />
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ fontSize: '0.74rem', padding: '0.28rem 0.65rem' }}
                      disabled={uploadingTrayIcon}
                      onClick={() => trayIconInputRef.current?.click()}
                    >
                      <Upload size={12} /> {uploadingTrayIcon ? 'Uploading...' : 'Crop & Upload Icon'}
                    </button>
                    {editingPolicy.tray_icon_url && (
                      <button
                        type="button"
                        className="btn-glass btn-danger"
                        style={{ fontSize: '0.72rem', padding: '0.28rem 0.55rem' }}
                        onClick={() => setEditingPolicy({ ...editingPolicy, tray_icon_url: '' })}
                      >
                        Clear
                      </button>
                    )}
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                  <div>
                    <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                      Hover Tooltip Text
                    </label>
                    <input
                      type="text"
                      className="glass-input"
                      placeholder="Protected by Enterprise IT Support"
                      value={editingPolicy.tray_tooltip || ''}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, tray_tooltip: e.target.value })}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                      Support Portal URL
                    </label>
                    <input
                      type="url"
                      className="glass-input"
                      placeholder="https://support.yourdomain.com"
                      value={editingPolicy.tray_support_url || ''}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, tray_support_url: e.target.value })}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                      Helpdesk Phone Number
                    </label>
                    <input
                      type="text"
                      className="glass-input"
                      placeholder="+1 (800) 555-0199"
                      value={editingPolicy.tray_support_phone || ''}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, tray_support_phone: e.target.value })}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                      Helpdesk Support Email
                    </label>
                    <input
                      type="email"
                      className="glass-input"
                      placeholder="helpdesk@yourdomain.com"
                      value={editingPolicy.tray_support_email || ''}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, tray_support_email: e.target.value })}
                    />
                  </div>
                </div>

                {/* Interactive Popup Menu Builder */}
                <div style={{ borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-main)' }}>
                      Popup Context Menu Actions ({getEditingTrayItems(editingPolicy).length})
                    </span>
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ fontSize: '0.72rem', padding: '0.22rem 0.55rem' }}
                      onClick={handleAddTrayMenuItem}
                    >
                      <Plus size={12} /> Add Menu Item
                    </button>
                  </div>

                  {getEditingTrayItems(editingPolicy).map((item, idx) => (
                    <div
                      key={item.id || idx}
                      style={{
                        display: 'grid',
                        gridTemplateColumns: 'auto 1.1fr 1fr 1.1fr auto',
                        gap: '0.45rem',
                        alignItems: 'center',
                        padding: '0.45rem',
                        borderRadius: '6px',
                        background: 'rgba(255,255,255,0.03)',
                        border: '1px solid var(--border-color)'
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={item.enabled !== false}
                        onChange={(e) => handleUpdateTrayMenuItem(idx, { enabled: e.target.checked })}
                        title="Enable menu item"
                      />
                      <input
                        type="text"
                        className="glass-input"
                        style={{ padding: '0.28rem 0.45rem', fontSize: '0.74rem' }}
                        placeholder="Menu Label"
                        value={item.label}
                        onChange={(e) => handleUpdateTrayMenuItem(idx, { label: e.target.value })}
                      />
                      <select
                        className="glass-select"
                        style={{ padding: '0.28rem 0.45rem', fontSize: '0.73rem' }}
                        value={item.action}
                        onChange={(e) => handleUpdateTrayMenuItem(idx, { action: e.target.value as TrayMenuItem['action'] })}
                      >
                        <option value="open_url">Open Support URL</option>
                        <option value="open_support_ticket">Open Ticket Form</option>
                        <option value="show_device_info">Show Device Info HUD</option>
                        <option value="request_remote_help">Request Remote Help</option>
                        <option value="copy_hostname">Copy Hostname &amp; IP</option>
                        <option value="custom_message">Show Notice Message</option>
                      </select>
                      <input
                        type="text"
                        className="glass-input"
                        style={{ padding: '0.28rem 0.45rem', fontSize: '0.73rem' }}
                        placeholder={
                          item.action === 'open_url'
                            ? 'https://... (or Support URL)'
                            : item.action === 'custom_message'
                              ? 'Popup notice text...'
                              : 'Optional target / email'
                        }
                        value={item.target || ''}
                        onChange={(e) => handleUpdateTrayMenuItem(idx, { target: e.target.value })}
                      />
                      <button
                        type="button"
                        className="btn-glass btn-danger btn-icon"
                        style={{ padding: '0.25rem' }}
                        onClick={() => handleRemoveTrayMenuItem(idx)}
                        title="Remove menu item"
                      >
                        <Trash2 size={12} />
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              {/* 4-Tier Condition & State Notification Routing Matrix (Web UI, Email, Direct PSA Ticket) */}
              {editingPolicy.alert_rules && editingPolicy.alert_rules.length > 0 && (
                <div style={{ background: 'rgba(56, 189, 248, 0.04)', border: '1px solid rgba(56, 189, 248, 0.25)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                      <Bell size={16} color="#38bdf8" />
                      <span style={{ fontWeight: 700, fontSize: '0.9rem', color: 'var(--text-main)' }}>
                        Per-Tier Condition &amp; State Notification Matrix ({editingPolicy.tier.toUpperCase()} Level)
                      </span>
                    </div>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                      Configure thresholds &amp; independent Web UI, Email, and Support Ticket routing per state
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

                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.6rem', fontSize: '0.73rem', color: 'var(--text-muted)' }}>
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
                              <span style={{ color: rule.createPsaTicket ? '#fbbf24' : undefined }}>Create Support Ticket</span>
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

              {policyError && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.55rem',
                    padding: '0.75rem 1rem',
                    borderRadius: '8px',
                    background: 'rgba(239, 68, 68, 0.14)',
                    border: '1px solid rgba(239, 68, 68, 0.35)',
                    color: '#f87171',
                    fontSize: '0.82rem'
                  }}
                >
                  <AlertCircle size={16} style={{ flexShrink: 0 }} />
                  <span>{policyError}</span>
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

      <MfaChallengeModal
        isOpen={Boolean(mfaRetryAction)}
        onClose={() => setMfaRetryAction(null)}
        onSuccess={() => {
          const action = mfaRetryAction;
          setMfaRetryAction(null);
          if (action === 'save') {
            performSavePolicy();
          } else if (action === 'create') {
            performCreatePolicy();
          }
        }}
        title="Step-Up MFA: Policy Governance"
        description="Enter your 6-digit TOTP authenticator code or recovery code to authorize modifying hierarchical fleet security & LAPS policies."
        secretType="policy_governance"
      />

      <IconCropModal
        isOpen={Boolean(cropPolicyIconFile)}
        file={cropPolicyIconFile}
        title="Crop Custom Tier EXE & Tray Icon"
        onCancel={() => setCropPolicyIconFile(null)}
        onConfirm={handleTrayIconCropped}
      />
    </div>
  );
};
