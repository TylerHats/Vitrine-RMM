import React, { useState, useEffect, useCallback } from 'react';
import {
  Play,
  CheckCircle2,
  Copy,
  Check,
  Sparkles,
  User,
  Shield,
  Plus,
  X,
  Sliders,
  ToggleLeft,
  ToggleRight,
  Building,
  Trash2,
  Edit3,
  Clock,
  Terminal,
  RefreshCw,
  AlertCircle
} from 'lucide-react';
import {
  ScriptItem,
  ScriptParameterDef,
  ScheduledAutomation,
  SmartGroup,
  Device,
  Tenant,
  AuthUser
} from '../types/index.js';
import {
  fetchScripts,
  runScript,
  createScript,
  updateScript,
  deleteScript,
  fetchScriptExecutions,
  fetchTenants,
  fetchSmartGroups,
  fetchAutomations,
  createAutomation,
  runAutomationNow,
  deleteAutomation
} from '../services/api.js';
import { canMutateFleet } from '../utils/permissions.js';
import { copyToClipboard } from '../utils/clipboard.js';
import { MfaChallengeModal } from '../components/MfaChallengeModal.js';

interface ScriptLibraryViewProps {
  devices: Device[];
  currentUser?: AuthUser | null;
}

interface ScriptExecutionResponse {
  success: boolean;
  executionId: string;
  dispatchedCount: number;
  message?: string;
}

export const ScriptLibraryView: React.FC<ScriptLibraryViewProps> = ({ devices, currentUser }) => {
  const canMutate = canMutateFleet(currentUser);
  const [activeTab, setActiveTab] = useState<'library' | 'schedules'>('library');
  const [scripts, setScripts] = useState<ScriptItem[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [smartGroups, setSmartGroups] = useState<SmartGroup[]>([]);
  const [selectedScript, setSelectedScript] = useState<ScriptItem | null>(null);
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<string[]>([]);
  const [runSmartGroupId, setRunSmartGroupId] = useState<string>('');
  const [copied, setCopied] = useState(false);
  const [running, setRunning] = useState(false);
  const [runResult, setRunResult] = useState<ScriptExecutionResponse | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [noticeIsError, setNoticeIsError] = useState(false);
  const [showSaveCodeMfa, setShowSaveCodeMfa] = useState(false);
  const [scriptParams, setScriptParams] = useState('');
  const [typedParamValues, setTypedParamValues] = useState<Record<string, string>>({});
  const [runAsContext, setRunAsContext] = useState<'system' | 'user'>('system');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [roleFilter, setRoleFilter] = useState('all');
  const [tenantFilter, setTenantFilter] = useState('all');
  const [showAddModal, setShowAddModal] = useState(false);

  // Script Execution History Drawer
  const [executions, setExecutions] = useState<Array<Record<string, any>>>([]);
  const [loadingExecutions, setLoadingExecutions] = useState(false);

  // New script form state (+ Typed Parameters Schema Builder)
  const [newScriptName, setNewScriptName] = useState('');
  const [newScriptDesc, setNewScriptDesc] = useState('');
  const [newScriptCategory, setNewScriptCategory] = useState('Administration');
  const [newScriptLang, setNewScriptLang] = useState<'powershell' | 'batch' | 'bash' | 'python'>('powershell');
  const [newScriptRole, setNewScriptRole] = useState<'admin' | 'technician' | 'readonly'>('technician');
  const [newScriptTenantId, setNewScriptTenantId] = useState('');
  const [newScriptCode, setNewScriptCode] = useState('');
  const [newScriptEnabled, setNewScriptEnabled] = useState(true);
  const [newParamDefs, setNewParamDefs] = useState<ScriptParameterDef[]>([]);
  const [savingNewScript, setSavingNewScript] = useState(false);
  const [editingCode, setEditingCode] = useState(false);
  const [editedCodeBuffer, setEditedCodeBuffer] = useState('');

  // Scheduled Automations (Cron) state
  const [automations, setAutomations] = useState<ScheduledAutomation[]>([]);
  const [showCreateScheduleModal, setShowCreateScheduleModal] = useState(false);
  const [schedName, setSchedName] = useState('');
  const [schedScriptId, setSchedScriptId] = useState('');
  const [schedTargetType, setSchedTargetType] = useState<ScheduledAutomation['target_type']>('all');
  const [schedTargetId, setSchedTargetId] = useState('');
  const [schedCron, setSchedCron] = useState('0 3 * * *');
  const [schedRunAs, setSchedRunAs] = useState<'system' | 'user'>('system');
  const [schedNotice, setSchedNotice] = useState<string | null>(null);
  const [schedNoticeIsError, setSchedNoticeIsError] = useState(false);

  const parseParamSchema = (s?: ScriptItem | null): ScriptParameterDef[] => {
    if (!s) return [];
    if (Array.isArray(s.parameters_schema)) return s.parameters_schema;
    if (s.parameters_schema_json) {
      try {
        const parsed = JSON.parse(s.parameters_schema_json);
        if (Array.isArray(parsed)) return parsed;
      } catch {
        // Ignore malformed parameter schema JSON
      }
    }
    return [];
  };

  const loadExecutions = useCallback(async (scriptId?: string) => {
    setLoadingExecutions(true);
    try {
      const list = await fetchScriptExecutions(scriptId);
      setExecutions(list);
    } catch {
      setExecutions([]);
    } finally {
      setLoadingExecutions(false);
    }
  }, []);

  const loadAutomations = useCallback(() => {
    fetchAutomations().then(setAutomations).catch(() => {});
  }, []);

  const loadScripts = useCallback(async (tenantIdArg?: string) => {
    const tid = tenantIdArg !== undefined ? tenantIdArg : tenantFilter;
    const arg = (tid === 'all' || tid === 'global') ? undefined : tid;
    const data = await fetchScripts(arg);
    setScripts(data);
    if (data[0]) {
      setSchedScriptId((prev) => prev || data[0].id);
    }
    setSelectedScript((prev) => {
      if (!prev && data.length > 0) return data[0];
      if (prev) return data.find((s) => s.id === prev.id) || prev;
      return null;
    });
  }, [tenantFilter]);

  useEffect(() => {
    fetchTenants().then(setTenants).catch(console.error);
    fetchSmartGroups().then(setSmartGroups).catch(() => {});
    loadScripts();
    loadAutomations();
  }, [loadScripts, loadAutomations]);

  useEffect(() => {
    setEditingCode(false);
    setEditedCodeBuffer(selectedScript?.code || '');
    if (!selectedScript) {
      setTypedParamValues({});
      return;
    }
    const defs = parseParamSchema(selectedScript);
    const defaults: Record<string, string> = {};
    defs.forEach((d) => {
      const defaultVal = d.default ?? d.defaultValue;
      if (defaultVal !== undefined) defaults[d.name] = String(defaultVal);
    });
    setTypedParamValues(defaults);
    loadExecutions(selectedScript.id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedScript?.id]);

  const handleSaveEditedCode = async () => {
    if (!selectedScript || !editedCodeBuffer.trim()) return;
    setNotice(null);
    setNoticeIsError(false);
    try {
      const res = await updateScript(selectedScript.id, { code: editedCodeBuffer });
      if (res.mfaRequired) {
        setShowSaveCodeMfa(true);
        return;
      }
      if (!res.success) {
        setNoticeIsError(true);
        setNotice(res.error || 'Failed to save script code.');
        return;
      }
      setEditingCode(false);
      setNoticeIsError(false);
      setNotice(`✓ Saved updated code for "${selectedScript.name}".`);
      await loadScripts();
    } catch (err: any) {
      setNoticeIsError(true);
      setNotice(err?.message || 'Failed to save script code.');
    }
  };

  const handleDeleteSelectedScript = async () => {
    if (!selectedScript || selectedScript.is_builtin) return;
    if (!confirm(`Delete custom script "${selectedScript.name}"?`)) return;
    const res = await deleteScript(selectedScript.id);
    if (res.success) {
      setSelectedScript(null);
      await loadScripts();
    } else {
      setNoticeIsError(true);
      setNotice(res.error || 'Failed to delete script.');
    }
  };

  const handleCopyCode = async () => {
    if (selectedScript) {
      const ok = await copyToClipboard(selectedScript.code);
      if (ok) {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }
    }
  };

  const insertToken = (token: string) => {
    setScriptParams((prev) => (prev ? `${prev} ${token}` : token));
  };

  const handleToggleEnabled = async (script: ScriptItem, e: React.MouseEvent) => {
    e.stopPropagation();
    const newStatus = (script.enabled ?? 1) !== 0 ? 0 : 1;
    setNotice(null);
    setNoticeIsError(false);
    try {
      const res = await updateScript(script.id, { enabled: newStatus });
      if (!res.success) {
        setNoticeIsError(true);
        setNotice(res.error || 'Failed to update script enabled status.');
        return;
      }
      setScripts((prev) => prev.map((s) => (s.id === script.id ? { ...s, enabled: newStatus } : s)));
      if (selectedScript?.id === script.id) {
        setSelectedScript((prev) => (prev ? { ...prev, enabled: newStatus } : null));
      }
    } catch (err: any) {
      setNoticeIsError(true);
      setNotice(err?.message || 'Failed to update script enabled status.');
    }
  };

  const handleCreateScript = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newScriptName.trim() || !newScriptCode.trim()) return;
    setSavingNewScript(true);
    setNotice(null);
    setNoticeIsError(false);
    try {
      const cleanParams = newParamDefs.filter((p) => p.name.trim());
      const res = await createScript({
        name: newScriptName.trim(),
        description: newScriptDesc.trim(),
        category: newScriptCategory,
        language: newScriptLang,
        required_role: newScriptRole,
        code: newScriptCode,
        enabled: newScriptEnabled ? 1 : 0,
        is_builtin: 0,
        tenant_id: newScriptTenantId || null,
        parameters_schema: cleanParams.length > 0 ? cleanParams : undefined
      });
      if (res.success) {
        setShowAddModal(false);
        setNewScriptName('');
        setNewScriptDesc('');
        setNewScriptCode('');
        setNewScriptTenantId('');
        setNewParamDefs([]);
        setNoticeIsError(false);
        setNotice(`Script "${newScriptName.trim()}" added to library.`);
        await loadScripts();
      } else {
        setNoticeIsError(true);
        setNotice(res.error || 'Failed to create script.');
      }
    } catch (err: any) {
      setNoticeIsError(true);
      setNotice(err?.message || 'Failed to create script.');
    } finally {
      setSavingNewScript(false);
    }
  };

  const handleRunMass = async () => {
    if (!selectedScript) return;
    if (!selectedScript.enabled) {
      setNoticeIsError(true);
      setNotice('This script is currently disabled by an administrator. Please enable it before running.');
      return;
    }
    if (selectedDeviceIds.length === 0 && !runSmartGroupId) {
      setNoticeIsError(true);
      setNotice('Please select at least one target device or a Smart Group for orchestration.');
      return;
    }

    setRunning(true);
    setNotice(null);
    setNoticeIsError(false);
    try {
      const mergedParams: Record<string, string> = { ...typedParamValues };
      if (scriptParams.trim()) mergedParams.args = scriptParams.trim();
      const res = await runScript(selectedScript.id, selectedDeviceIds, {
        params: Object.keys(mergedParams).length > 0 ? mergedParams : undefined,
        runAs: runAsContext,
        smartGroupId: runSmartGroupId || undefined
      });
      if (!res.success) {
        setNoticeIsError(true);
        setNotice(res.error || 'Script execution dispatch failed.');
      } else {
        setRunResult(res as ScriptExecutionResponse);
      }
      await loadExecutions(selectedScript.id);
    } catch (err: any) {
      setNoticeIsError(true);
      setNotice(err?.message || 'Script execution dispatch failed.');
    } finally {
      setRunning(false);
    }
  };

  const handleCreateAutomation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!schedName.trim() || !schedScriptId || !schedCron.trim()) return;
    try {
      const res: any = await createAutomation({
        name: schedName.trim(),
        script_id: schedScriptId,
        target_type: schedTargetType,
        target_id: schedTargetType === 'all' ? null : schedTargetId || null,
        cron_expr: schedCron.trim(),
        run_as: schedRunAs,
        enabled: true
      });
      if (res.success) {
        setShowCreateScheduleModal(false);
        setSchedName('');
        loadAutomations();
        setSchedNoticeIsError(false);
        setSchedNotice(`Scheduled automation "${schedName.trim()}" active (${schedCron.trim()}).`);
      } else {
        setSchedNoticeIsError(true);
        setSchedNotice(res.error || 'Failed to create scheduled automation.');
      }
    } catch (err: any) {
      setSchedNoticeIsError(true);
      setSchedNotice(err?.message || 'Failed to create scheduled automation.');
    }
  };

  const handleRunAutomationNow = async (id: string) => {
    try {
      const res = await runAutomationNow(id);
      setSchedNoticeIsError(!res.success);
      setSchedNotice(
        res.success
          ? `✓ Dispatched scheduled automation across ${res.targetedDevices ?? 0} endpoint(s).`
          : `⚠ Automation error: ${res.error || 'Failed'}`
      );
      loadAutomations();
    } catch (err: any) {
      setSchedNoticeIsError(true);
      setSchedNotice(err?.message || 'Failed to execute scheduled automation.');
    }
  };

  const handleDeleteAutomation = async (id: string) => {
    if (!confirm('Delete this scheduled automation?')) return;
    try {
      const res: any = await deleteAutomation(id);
      if (res?.success === false) {
        setSchedNoticeIsError(true);
        setSchedNotice(res.error || 'Failed to delete scheduled automation.');
        return;
      }
      setSchedNoticeIsError(false);
      setSchedNotice('Scheduled automation removed.');
      loadAutomations();
    } catch (err: any) {
      setSchedNoticeIsError(true);
      setSchedNotice(err?.message || 'Failed to delete scheduled automation.');
    }
  };

  const toggleDeviceSelection = (id: string) => {
    if (selectedDeviceIds.includes(id)) {
      setSelectedDeviceIds(selectedDeviceIds.filter((d) => d !== id));
    } else {
      setSelectedDeviceIds([...selectedDeviceIds, id]);
    }
  };

  const tenantMap = tenants.reduce<Record<string, string>>((acc, t) => {
    acc[t.id] = t.name;
    return acc;
  }, {});

  const filteredScripts = scripts.filter((s) => {
    if (categoryFilter !== 'all' && s.category !== categoryFilter) return false;
    if (roleFilter !== 'all' && s.required_role !== roleFilter) return false;
    if (tenantFilter === 'global' && s.tenant_id) return false;
    if (tenantFilter !== 'all' && tenantFilter !== 'global' && s.tenant_id !== tenantFilter && s.tenant_id !== null && s.tenant_id !== undefined) return false;
    return true;
  });

  const categories = Array.from(new Set(scripts.map((s) => s.category || 'General')));
  const activeParamDefs = parseParamSchema(selectedScript);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="script-library-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
            Centralized Automation, Typed Runbooks &amp; Cron Schedules
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Production-grade automation repository with typed runtime parameters (<code>$env:VITRINE_PARAM_*</code>), live execution logs, and recurring Cron orchestration
          </span>
        </div>

        <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
          <button
            className={`btn-glass ${activeTab === 'library' ? 'btn-primary' : ''}`}
            onClick={() => setActiveTab('library')}
          >
            <Terminal size={15} /> Script Library ({scripts.length})
          </button>
          <button
            className={`btn-glass ${activeTab === 'schedules' ? 'btn-primary' : ''}`}
            onClick={() => setActiveTab('schedules')}
          >
            <Clock size={15} /> Scheduled Automations ({automations.length})
          </button>
          {canMutate && (activeTab === 'library' ? (
            <button
              className="btn-glass btn-primary"
              onClick={() => setShowAddModal(true)}
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}
            >
              <Plus size={16} />
              <span>New Automation Script</span>
            </button>
          ) : (
            <button
              className="btn-glass btn-primary"
              onClick={() => setShowCreateScheduleModal(true)}
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}
            >
              <Plus size={16} />
              <span>New Cron Schedule</span>
            </button>
          ))}
        </div>
      </div>

      {notice && (
        <div
          className="glass-card"
          style={{
            padding: '0.75rem 1.15rem',
            fontSize: '0.82rem',
            background: noticeIsError ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
            borderColor: noticeIsError ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)',
            color: noticeIsError ? '#f87171' : '#34d399',
            display: 'flex',
            alignItems: 'center',
            gap: '0.55rem'
          }}
        >
          {noticeIsError && <AlertCircle size={15} style={{ flexShrink: 0 }} />}
          <span>{notice}</span>
        </div>
      )}

      {activeTab === 'schedules' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {schedNotice && (
            <div
              className="glass-card"
              style={{
                padding: '0.75rem 1.15rem',
                fontSize: '0.82rem',
                background: schedNoticeIsError ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
                borderColor: schedNoticeIsError ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)',
                color: schedNoticeIsError ? '#f87171' : '#34d399',
                display: 'flex',
                alignItems: 'center',
                gap: '0.55rem'
              }}
            >
              {schedNoticeIsError && <AlertCircle size={15} style={{ flexShrink: 0 }} />}
              <span>{schedNotice}</span>
            </div>
          )}
          <div className="glass-card" style={{ padding: 0 }}>
            <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
              <table className="glass-table">
                <thead>
                  <tr>
                    <th>Schedule Name</th>
                    <th>Linked Script</th>
                    <th>Cron Expression</th>
                    <th>Target Scope</th>
                    <th>Context</th>
                    <th>Next Run / Runs</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {automations.map((auto) => (
                    <tr key={auto.id}>
                      <td><strong>{auto.name}</strong></td>
                      <td>{auto.script_name || scripts.find((s) => s.id === auto.script_id)?.name || auto.script_id}</td>
                      <td><code>{auto.cron_expr}</code></td>
                      <td>
                        <span className="status-pill status-online" style={{ fontSize: '0.7rem' }}>
                          {auto.target_type.toUpperCase()} {auto.target_id ? `(${auto.target_id})` : ''}
                        </span>
                      </td>
                      <td><code>{(auto.run_as || 'system').toUpperCase()}</code></td>
                      <td style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                        {auto.next_run_at ? new Date(auto.next_run_at).toLocaleString() : 'Pending'} ({auto.run_count || 0} runs)
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        {canMutate ? (
                          <div style={{ display: 'inline-flex', gap: '0.4rem' }}>
                            <button
                              className="btn-glass btn-primary"
                              style={{ padding: '0.22rem 0.6rem', fontSize: '0.74rem' }}
                              onClick={() => handleRunAutomationNow(auto.id)}
                            >
                              <Play size={12} /> Run Now
                            </button>
                            <button
                              className="btn-glass btn-icon"
                              onClick={() => handleDeleteAutomation(auto.id)}
                              title="Delete Schedule"
                            >
                              <Trash2 size={13} color="#ef4444" />
                            </button>
                          </div>
                        ) : (
                          <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Read-only</span>
                        )}
                      </td>
                    </tr>
                  ))}
                  {automations.length === 0 && (
                    <tr>
                      <td colSpan={7} style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                        No recurring Cron automations configured yet. Click &quot;New Cron Schedule&quot; to automate recurring scripts across Smart Groups, Clients, or the entire fleet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'library' && (
        <>
          {/* Filter Toolbar */}
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Sliders size={14} color="var(--primary)" />
              <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)' }}>Category:</span>
              <select
                className="glass-select"
                style={{ padding: '0.35rem 0.65rem', fontSize: '0.8rem' }}
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
              >
                <option value="all">All Categories</option>
                {categories.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Shield size={14} color="var(--secondary)" />
              <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)' }}>RBAC Tier:</span>
              <select
                className="glass-select"
                style={{ padding: '0.35rem 0.65rem', fontSize: '0.8rem' }}
                value={roleFilter}
                onChange={(e) => setRoleFilter(e.target.value)}
              >
                <option value="all">All Roles</option>
                <option value="admin">Admin Only</option>
                <option value="technician">Technician+</option>
                <option value="readonly">Read Only / All</option>
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Building size={14} color="#f59e0b" />
              <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)' }}>Client Scope:</span>
              <select
                className="glass-select"
                style={{ padding: '0.35rem 0.65rem', fontSize: '0.8rem' }}
                value={tenantFilter}
                onChange={(e) => {
                  setTenantFilter(e.target.value);
                  loadScripts(e.target.value);
                }}
              >
                <option value="all">All Scopes (Global + Clients)</option>
                <option value="global">Global Only</option>
                {tenants.map((t) => (
                  <option key={t.id} value={t.id}>Client: {t.name}</option>
                ))}
              </select>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '340px 1fr', gap: '1.5rem', minHeight: '520px' }}>
            {/* Scripts Selector List */}
            <div className="glass-card" style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '780px', overflowY: 'auto' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)' }}>
                  SCRIPTS ({filteredScripts.length} of {scripts.length})
                </span>
              </div>

              {filteredScripts.map((s) => {
                const isSelected = selectedScript?.id === s.id;
                const isEnabled = (s.enabled ?? 1) !== 0;

                const roleBadgeColor =
                  s.required_role === 'admin' ? '#ef4444' :
                  s.required_role === 'readonly' ? '#10b981' : '#38bdf8';

                return (
                  <div
                    key={s.id}
                    onClick={() => { setSelectedScript(s); setRunResult(null); }}
                    style={{
                      padding: '0.75rem 1rem',
                      borderRadius: '8px',
                      background: isSelected ? 'rgba(0, 242, 254, 0.12)' : 'rgba(255, 255, 255, 0.03)',
                      border: `1px solid ${isSelected ? 'rgba(0, 242, 254, 0.35)' : 'rgba(255, 255, 255, 0.06)'}`,
                      cursor: 'pointer',
                      opacity: isEnabled ? 1 : 0.6,
                      transition: 'all 0.15s'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '0.5rem' }}>
                      <div style={{ display: 'flex', flexDirection: 'column' }}>
                        <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>{s.name}</span>
                        <span style={{ fontSize: '0.68rem', color: 'var(--text-dim)', marginTop: '0.15rem' }}>
                          {s.category || 'Administration'} {s.is_builtin ? '• Built-in' : '• Custom'}
                        </span>
                      </div>

                      {canMutate && (
                        <button
                          onClick={(e) => handleToggleEnabled(s, e)}
                          title={isEnabled ? 'Click to disable script' : 'Click to enable script'}
                          style={{
                            background: 'none',
                            border: 'none',
                            cursor: 'pointer',
                            color: isEnabled ? '#10b981' : '#64748b',
                            padding: 0
                          }}
                        >
                          {isEnabled ? <ToggleRight size={22} /> : <ToggleLeft size={22} />}
                        </button>
                      )}
                    </div>

                    <div style={{ display: 'flex', gap: '0.4rem', marginTop: '0.45rem', alignItems: 'center', flexWrap: 'wrap' }}>
                      <span className="status-pill status-reboot" style={{ fontSize: '0.62rem', padding: '0.1rem 0.4rem' }}>
                        {s.language}
                      </span>
                      <span
                        style={{
                          fontSize: '0.62rem',
                          padding: '0.1rem 0.4rem',
                          borderRadius: '4px',
                          background: s.tenant_id ? 'rgba(245, 158, 11, 0.15)' : 'rgba(56, 189, 248, 0.15)',
                          color: s.tenant_id ? '#fbbf24' : '#38bdf8',
                          border: `1px solid ${s.tenant_id ? 'rgba(245, 158, 11, 0.3)' : 'rgba(56, 189, 248, 0.3)'}`,
                          fontWeight: 600
                        }}
                      >
                        {s.tenant_id ? (tenantMap[s.tenant_id] || 'Client-Specific') : 'Global'}
                      </span>
                      <span
                        style={{
                          fontSize: '0.62rem',
                          padding: '0.1rem 0.4rem',
                          borderRadius: '4px',
                          background: `${roleBadgeColor}20`,
                          color: roleBadgeColor,
                          border: `1px solid ${roleBadgeColor}40`,
                          fontWeight: 600
                        }}
                      >
                        {s.required_role ? s.required_role.toUpperCase() : 'TECH'}
                      </span>
                      {!isEnabled && (
                        <span style={{ fontSize: '0.62rem', color: '#f87171', marginLeft: 'auto', fontWeight: 600 }}>
                          DISABLED
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Script Editor & Mass Orchestration Target Selector */}
            {selectedScript && (
              <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                      <h3 style={{ fontSize: '1.2rem', fontWeight: 600, margin: 0 }}>{selectedScript.name}</h3>
                      {(selectedScript.enabled ?? 1) === 0 ? (
                        <span style={{ fontSize: '0.7rem', padding: '0.2rem 0.6rem', borderRadius: '4px', background: 'rgba(239, 68, 68, 0.2)', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.4)' }}>
                          Disabled
                        </span>
                      ) : (
                        <span style={{ fontSize: '0.7rem', padding: '0.2rem 0.6rem', borderRadius: '4px', background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', border: '1px solid rgba(16, 185, 129, 0.4)' }}>
                          Active
                        </span>
                      )}
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                        Access Tier: <strong>{selectedScript.required_role?.toUpperCase() || 'TECHNICIAN'}</strong>
                      </span>
                    </div>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: '0.35rem 0 0 0' }}>{selectedScript.description}</p>
                  </div>

                  <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                    {canMutate && (
                      <>
                        <button
                          className="btn-glass"
                          onClick={(e) => handleToggleEnabled(selectedScript, e)}
                          title={(selectedScript.enabled ?? 1) !== 0 ? 'Disable Script' : 'Enable Script'}
                        >
                          {(selectedScript.enabled ?? 1) !== 0 ? <ToggleRight size={16} color="#10b981" /> : <ToggleLeft size={16} color="#64748b" />}
                          <span>{(selectedScript.enabled ?? 1) !== 0 ? 'Enabled' : 'Disabled'}</span>
                        </button>
                        <button
                          className="btn-glass"
                          onClick={() => {
                            if (editingCode) {
                              setEditingCode(false);
                            } else {
                              setEditedCodeBuffer(selectedScript.code);
                              setEditingCode(true);
                            }
                          }}
                        >
                          <Edit3 size={14} />
                          <span>{editingCode ? 'Cancel Edit' : 'Edit'}</span>
                        </button>
                        {editingCode && (
                          <button className="btn-glass btn-primary" onClick={handleSaveEditedCode}>
                            <Check size={14} /> Save Code
                          </button>
                        )}
                        {!selectedScript.is_builtin && (
                          <button className="btn-glass btn-icon" title="Delete Custom Script" onClick={handleDeleteSelectedScript}>
                            <Trash2 size={14} color="#ef4444" />
                          </button>
                        )}
                      </>
                    )}
                    <button className="btn-glass" onClick={handleCopyCode}>
                      {copied ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
                      <span>{copied ? 'Copied' : 'Copy'}</span>
                    </button>
                    {canMutate && (
                      <button
                        className="btn-glass btn-primary"
                        onClick={handleRunMass}
                        disabled={running || (selectedScript.enabled ?? 1) === 0}
                        title={(selectedScript.enabled ?? 1) === 0 ? 'Script is disabled' : 'Execute script across targets'}
                      >
                        <Play size={14} />
                        <span>{running ? 'Dispatching...' : 'Mass Execute'}</span>
                      </button>
                    )}
                  </div>
                </div>

                {/* Code Viewer / Editor */}
                {editingCode ? (
                  <textarea
                    rows={9}
                    className="glass-input"
                    style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', resize: 'vertical' }}
                    value={editedCodeBuffer}
                    onChange={(e) => setEditedCodeBuffer(e.target.value)}
                  />
                ) : (
                  <div className="terminal-window" style={{ height: '210px', color: '#7dd3fc', overflowY: 'auto' }}>
                    {selectedScript.code}
                  </div>
                )}

                {/* Typed Runtime Parameters Form (if defined on script) */}
                {activeParamDefs.length > 0 && (
                  <div style={{ background: 'rgba(56, 189, 248, 0.05)', border: '1px solid rgba(56, 189, 248, 0.25)', borderRadius: '8px', padding: '0.85rem' }}>
                    <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#38bdf8', marginBottom: '0.55rem' }}>
                      Typed Script Variables (Injected safely as <code>VITRINE_PARAM_*</code> environment variables)
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem' }}>
                      {activeParamDefs.map((pd) => (
                        <div key={pd.name}>
                          <label style={{ fontSize: '0.74rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.2rem' }}>
                            {pd.label || pd.name} {pd.required ? '*' : ''}
                          </label>
                          {(pd.type === 'select' || pd.type === 'choice') && (pd.options || pd.choices) ? (
                            <select
                              className="glass-select"
                              style={{ fontSize: '0.78rem' }}
                              value={typedParamValues[pd.name] ?? ''}
                              onChange={(e) => setTypedParamValues({ ...typedParamValues, [pd.name]: e.target.value })}
                            >
                              {(pd.options || pd.choices || []).map((opt) => (
                                <option key={opt} value={opt}>{opt}</option>
                              ))}
                            </select>
                          ) : pd.type === 'boolean' ? (
                            <select
                              className="glass-select"
                              style={{ fontSize: '0.78rem' }}
                              value={typedParamValues[pd.name] ?? 'true'}
                              onChange={(e) => setTypedParamValues({ ...typedParamValues, [pd.name]: e.target.value })}
                            >
                              <option value="true">True</option>
                              <option value="false">False</option>
                            </select>
                          ) : (
                            <input
                              type={pd.type === 'secret' ? 'password' : pd.type === 'number' ? 'number' : 'text'}
                              className="glass-input"
                              style={{ fontSize: '0.78rem' }}
                              value={typedParamValues[pd.name] ?? ''}
                              onChange={(e) => setTypedParamValues({ ...typedParamValues, [pd.name]: e.target.value })}
                            />
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Execution Context & Parameters Bar */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 220px', gap: '1rem', background: 'rgba(255, 255, 255, 0.02)', padding: '0.85rem', borderRadius: '8px', border: '1px solid var(--glass-border)' }}>
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                      <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)' }}>
                        Runtime Parameters &amp; Flags:
                      </label>
                      <div style={{ display: 'flex', gap: '0.35rem' }}>
                        <button
                          type="button"
                          className="btn-glass"
                          style={{ padding: '0.15rem 0.4rem', fontSize: '0.65rem' }}
                          onClick={() => insertToken('$vitrine.device.hostname')}
                        >
                          <Sparkles size={10} /> $device.hostname
                        </button>
                        <button
                          type="button"
                          className="btn-glass"
                          style={{ padding: '0.15rem 0.4rem', fontSize: '0.65rem' }}
                          onClick={() => insertToken('$vitrine.device.client_id')}
                        >
                          $device.client_id
                        </button>
                        <button
                          type="button"
                          className="btn-glass"
                          style={{ padding: '0.15rem 0.4rem', fontSize: '0.65rem' }}
                          onClick={() => insertToken('$vitrine.custom.asset_tag')}
                        >
                          $custom.asset_tag
                        </button>
                      </div>
                    </div>
                    <input
                      type="text"
                      className="glass-input"
                      style={{ fontSize: '0.8rem', padding: '0.4rem 0.65rem' }}
                      placeholder="e.g. -Force -TargetPort 8443 $vitrine.device.hostname"
                      value={scriptParams}
                      onChange={(e) => setScriptParams(e.target.value)}
                    />
                  </div>

                  <div>
                    <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                      Execution Context:
                    </label>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button
                        type="button"
                        className={`btn-glass ${runAsContext === 'system' ? 'btn-primary' : ''}`}
                        style={{ flex: 1, padding: '0.4rem 0.5rem', fontSize: '0.75rem' }}
                        onClick={() => setRunAsContext('system')}
                      >
                        <Shield size={12} /> SYSTEM
                      </button>
                      <button
                        type="button"
                        className={`btn-glass ${runAsContext === 'user' ? 'btn-primary' : ''}`}
                        style={{ flex: 1, padding: '0.4rem 0.5rem', fontSize: '0.75rem' }}
                        onClick={() => setRunAsContext('user')}
                      >
                        <User size={12} /> User (GUI)
                      </button>
                    </div>
                  </div>
                </div>

                {/* Target Devices Selector */}
                <div style={{ borderTop: '1px solid var(--glass-border)', paddingTop: '1rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                    <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)' }}>
                      TARGET DISPATCH SCOPE ({selectedDeviceIds.length} of {devices.length} selected{runSmartGroupId ? ' + Dynamic Smart Group' : ''})
                    </span>
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                      <select
                        className="glass-select"
                        style={{ padding: '0.22rem 0.55rem', fontSize: '0.74rem', width: 'auto' }}
                        value={runSmartGroupId}
                        onChange={(e) => setRunSmartGroupId(e.target.value)}
                      >
                        <option value="">-- Optional Smart Group Target --</option>
                        {smartGroups.map((sg) => (
                          <option key={sg.id} value={sg.id}>
                            Smart Group: {sg.name}
                          </option>
                        ))}
                      </select>
                      <button
                        className="btn-glass"
                        style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
                        onClick={() => setSelectedDeviceIds(devices.map((d) => d.id))}
                      >
                        Select All
                      </button>
                      <button
                        className="btn-glass"
                        style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
                        onClick={() => {
                          setSelectedDeviceIds([]);
                          setRunSmartGroupId('');
                        }}
                      >
                        Clear
                      </button>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: '0.65rem' }}>
                    {devices.map((d) => {
                      const isChecked = selectedDeviceIds.includes(d.id);
                      return (
                        <label
                          key={d.id}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.5rem',
                            padding: '0.5rem 0.75rem',
                            background: isChecked ? 'rgba(0, 242, 254, 0.1)' : 'rgba(0, 0, 0, 0.2)',
                            border: `1px solid ${isChecked ? 'rgba(0, 242, 254, 0.3)' : 'var(--glass-border)'}`,
                            borderRadius: '6px',
                            cursor: 'pointer',
                            fontSize: '0.8rem'
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={isChecked}
                            onChange={() => toggleDeviceSelection(d.id)}
                          />
                          <span>{d.hostname}</span>
                          <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginLeft: 'auto' }}>{d.device_role}</span>
                        </label>
                      );
                    })}
                  </div>
                </div>

                {/* Mass Run Output Banner */}
                {runResult && (
                  <div style={{ background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.3)', padding: '0.85rem 1.25rem', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <CheckCircle2 size={18} color="#10b981" />
                    <div style={{ fontSize: '0.82rem', color: '#34d399' }}>
                      Execution Dispatched: Script executed across <strong>{runResult.dispatchedCount} endpoints</strong> under <strong>{runAsContext.toUpperCase()}</strong> authority. Execution ID: <code>{runResult.executionId}</code>.
                    </div>
                  </div>
                )}

                {/* Live Script Execution History & Stdout/Stderr Output Log */}
                <div style={{ borderTop: '1px solid var(--glass-border)', paddingTop: '1rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.65rem' }}>
                    <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-dim)' }}>
                      RECENT EXECUTION OUTPUTS ({executions.length})
                    </span>
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ padding: '0.2rem 0.55rem', fontSize: '0.72rem' }}
                      onClick={() => loadExecutions(selectedScript.id)}
                    >
                      <RefreshCw size={12} className={loadingExecutions ? 'spin' : ''} /> Refresh Logs
                    </button>
                  </div>
                  {executions.length === 0 ? (
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>
                      No execution history recorded for this script yet.
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '220px', overflowY: 'auto' }}>
                      {executions.slice(0, 12).map((ex) => (
                        <div
                          key={ex.id}
                          style={{
                            padding: '0.6rem 0.85rem',
                            borderRadius: '8px',
                            background: 'rgba(0, 0, 0, 0.28)',
                            border: '1px solid var(--glass-border)',
                            fontSize: '0.76rem'
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                            <span>
                              <strong>{ex.hostname || ex.device_id}</strong> • <code>{(ex.run_as || 'system').toUpperCase()}</code> • by {ex.triggered_by || 'Admin'}
                            </span>
                            <span style={{ color: ex.status === 'completed' || ex.exit_code === 0 ? '#34d399' : '#fbbf24' }}>
                              {ex.status || 'completed'} (exit {ex.exit_code ?? 0}) • {ex.executed_at ? new Date(ex.executed_at).toLocaleTimeString() : ''}
                            </span>
                          </div>
                          {ex.output_log && (
                            <pre style={{ margin: 0, fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: '#cbd5e1', whiteSpace: 'pre-wrap' }}>
                              {ex.output_log}
                            </pre>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {/* New Automation Script Modal */}
      {showAddModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.7)',
            backdropFilter: 'blur(8px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '1.5rem'
          }}
          onClick={() => setShowAddModal(false)}
        >
          <div
            className="glass-card"
            style={{
              width: '100%',
              maxWidth: '680px',
              maxHeight: '90vh',
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: '1.1rem',
              padding: '1.75rem',
              border: '1px solid rgba(255, 255, 255, 0.15)',
              boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7)'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Plus size={18} color="var(--primary)" />
                <h3 style={{ fontSize: '1.25rem', fontWeight: 700, margin: 0 }}>Add Automation Script</h3>
              </div>
              <button
                onClick={() => setShowAddModal(false)}
                style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer' }}
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleCreateScript} style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
              <div>
                <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                  Script Name *
                </label>
                <input
                  type="text"
                  required
                  className="glass-input"
                  placeholder="e.g. Purge Printer Spooler & Reset Service"
                  value={newScriptName}
                  onChange={(e) => setNewScriptName(e.target.value)}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div>
                  <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                    Client Scope
                  </label>
                  <select
                    className="glass-select"
                    value={newScriptTenantId}
                    onChange={(e) => setNewScriptTenantId(e.target.value)}
                  >
                    <option value="">Global (All Clients / Tenants)</option>
                    {tenants.map((t) => (
                      <option key={t.id} value={t.id}>Client: {t.name}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                    Category
                  </label>
                  <select
                    className="glass-select"
                    value={newScriptCategory}
                    onChange={(e) => setNewScriptCategory(e.target.value)}
                  >
                    <option value="Administration">Administration</option>
                    <option value="Maintenance">Maintenance</option>
                    <option value="Remediation">Remediation</option>
                    <option value="Security">Security</option>
                    <option value="Diagnostics">Diagnostics</option>
                    <option value="Custom">Custom</option>
                  </select>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div>
                  <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                    Language
                  </label>
                  <select
                    className="glass-select"
                    value={newScriptLang}
                    onChange={(e) => setNewScriptLang(e.target.value as 'powershell' | 'batch' | 'bash' | 'python')}
                  >
                    <option value="powershell">PowerShell</option>
                    <option value="batch">Batch / CMD</option>
                    <option value="bash">Bash / Shell</option>
                    <option value="python">Python</option>
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                    Required RBAC Role
                  </label>
                  <select
                    className="glass-select"
                    value={newScriptRole}
                    onChange={(e) => setNewScriptRole(e.target.value as 'admin' | 'technician' | 'readonly')}
                  >
                    <option value="technician">Technician+</option>
                    <option value="admin">MSP Super Admin Only</option>
                    <option value="readonly">Read-Only (Audit / Inspect)</option>
                  </select>
                </div>
              </div>

              {/* Typed Parameter Schema Builder */}
              <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid var(--glass-border)', borderRadius: '8px', padding: '0.8rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.45rem' }}>
                  <span style={{ fontSize: '0.78rem', fontWeight: 600, color: '#38bdf8' }}>
                    Typed Runtime Variables (Optional)
                  </span>
                  <button
                    type="button"
                    className="btn-glass"
                    style={{ fontSize: '0.72rem', padding: '0.2rem 0.5rem' }}
                    onClick={() =>
                      setNewParamDefs([
                        ...newParamDefs,
                        { name: 'TARGET_PORT', label: 'Target Port', type: 'string', default: '443' }
                      ])
                    }
                  >
                    <Plus size={12} /> Add Variable
                  </button>
                </div>
                {newParamDefs.map((pd, idx) => (
                  <div key={idx} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 0.8fr 0.8fr auto', gap: '0.4rem', marginBottom: '0.35rem' }}>
                    <input
                      className="glass-input"
                      style={{ fontSize: '0.74rem' }}
                      placeholder="ENV_KEY"
                      value={pd.name}
                      onChange={(e) => {
                        const copy = [...newParamDefs];
                        copy[idx] = { ...copy[idx], name: e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, '_') };
                        setNewParamDefs(copy);
                      }}
                    />
                    <input
                      className="glass-input"
                      style={{ fontSize: '0.74rem' }}
                      placeholder="Display Label"
                      value={pd.label}
                      onChange={(e) => {
                        const copy = [...newParamDefs];
                        copy[idx] = { ...copy[idx], label: e.target.value };
                        setNewParamDefs(copy);
                      }}
                    />
                    <select
                      className="glass-select"
                      style={{ fontSize: '0.74rem' }}
                      value={pd.type}
                      onChange={(e) => {
                        const copy = [...newParamDefs];
                        copy[idx] = { ...copy[idx], type: e.target.value as any };
                        setNewParamDefs(copy);
                      }}
                    >
                      <option value="string">String</option>
                      <option value="number">Number</option>
                      <option value="boolean">Boolean</option>
                      <option value="secret">Secret</option>
                    </select>
                    <input
                      className="glass-input"
                      style={{ fontSize: '0.74rem' }}
                      placeholder="Default"
                      value={String(pd.default ?? '')}
                      onChange={(e) => {
                        const copy = [...newParamDefs];
                        copy[idx] = { ...copy[idx], default: e.target.value };
                        setNewParamDefs(copy);
                      }}
                    />
                    <button
                      type="button"
                      className="btn-glass btn-icon"
                      onClick={() => setNewParamDefs(newParamDefs.filter((_, i) => i !== idx))}
                    >
                      <Trash2 size={12} color="#ef4444" />
                    </button>
                  </div>
                ))}
              </div>

              <div>
                <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                  Description
                </label>
                <input
                  type="text"
                  className="glass-input"
                  placeholder="e.g. Stops spooler, deletes corrupt queue files in Spool\PRINTERS, and restarts service"
                  value={newScriptDesc}
                  onChange={(e) => setNewScriptDesc(e.target.value)}
                />
              </div>

              <div>
                <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                  Script Content / Code *
                </label>
                <textarea
                  required
                  rows={7}
                  className="glass-input"
                  style={{ fontFamily: 'monospace', fontSize: '0.82rem', resize: 'vertical' }}
                  placeholder="# Access typed variables via $env:VITRINE_PARAM_KEY or $VITRINE_PARAM_KEY"
                  value={newScriptCode}
                  onChange={(e) => setNewScriptCode(e.target.value)}
                />
              </div>

              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.85rem' }}>
                <input
                  type="checkbox"
                  checked={newScriptEnabled}
                  onChange={(e) => setNewScriptEnabled(e.target.checked)}
                />
                <span>Enabled by Default</span>
              </label>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
                <button type="button" className="btn-glass" onClick={() => setShowAddModal(false)}>
                  Cancel
                </button>
                <button type="submit" disabled={savingNewScript} className="btn-glass btn-primary">
                  {savingNewScript ? 'Saving Script...' : 'Save & Publish to Library'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Create Recurring Cron Automation Modal */}
      {showCreateScheduleModal && (
        <div className="modal-overlay" onClick={() => setShowCreateScheduleModal(false)}>
          <div className="glass-modal" style={{ maxWidth: '500px', padding: '1.5rem' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>Create Recurring Cron Automation</h3>
              <button className="btn-glass btn-icon" onClick={() => setShowCreateScheduleModal(false)}>
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleCreateAutomation} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Schedule Name
                </label>
                <input
                  type="text"
                  required
                  className="glass-input"
                  placeholder="e.g. Nightly Temp Cleanup & DNS Flush"
                  value={schedName}
                  onChange={(e) => setSchedName(e.target.value)}
                />
              </div>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Automation Script
                </label>
                <select className="glass-select" value={schedScriptId} onChange={(e) => setSchedScriptId(e.target.value)}>
                  {scripts.map((s) => (
                    <option key={s.id} value={s.id}>{s.name} ({s.language})</option>
                  ))}
                </select>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Cron Expression (UTC/Local)
                  </label>
                  <input
                    type="text"
                    required
                    className="glass-input"
                    placeholder="0 3 * * *"
                    value={schedCron}
                    onChange={(e) => setSchedCron(e.target.value)}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Run As Context
                  </label>
                  <select className="glass-select" value={schedRunAs} onChange={(e) => setSchedRunAs(e.target.value as any)}>
                    <option value="system">SYSTEM / root</option>
                    <option value="user">Interactive User</option>
                  </select>
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Target Scope Type
                  </label>
                  <select
                    className="glass-select"
                    value={schedTargetType}
                    onChange={(e) => {
                      const tt = e.target.value as any;
                      setSchedTargetType(tt);
                      if (tt === 'tenant') setSchedTargetId(tenants[0]?.id || '');
                      else if (tt === 'smart_group') setSchedTargetId(smartGroups[0]?.id || '');
                      else if (tt === 'device') setSchedTargetId(devices[0]?.id || '');
                      else setSchedTargetId('');
                    }}
                  >
                    <option value="all">Entire Active Fleet</option>
                    <option value="tenant">Client Tenant</option>
                    <option value="smart_group">Dynamic Smart Group</option>
                    <option value="device">Single Endpoint</option>
                  </select>
                </div>
                {schedTargetType !== 'all' && (
                  <div>
                    <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                      Target Entity
                    </label>
                    <select className="glass-select" value={schedTargetId} onChange={(e) => setSchedTargetId(e.target.value)}>
                      {schedTargetType === 'tenant' && tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                      {schedTargetType === 'smart_group' && smartGroups.map((sg) => <option key={sg.id} value={sg.id}>{sg.name}</option>)}
                      {schedTargetType === 'device' && devices.map((d) => <option key={d.id} value={d.id}>{d.hostname}</option>)}
                    </select>
                  </div>
                )}
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button type="button" className="btn-glass" onClick={() => setShowCreateScheduleModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-glass btn-primary">
                  Save Schedule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <MfaChallengeModal
        isOpen={showSaveCodeMfa}
        onClose={() => setShowSaveCodeMfa(false)}
        onSuccess={() => {
          setShowSaveCodeMfa(false);
          handleSaveEditedCode();
        }}
        title="Step-Up MFA: Edit Built-In / Protected Script"
        description="Enter your 6-digit TOTP authenticator code or recovery code to authorize modifying protected automation script code."
        secretType="script_library_write"
      />
    </div>
  );
};
