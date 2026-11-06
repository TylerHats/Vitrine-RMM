import React, { useState, useEffect, useCallback } from 'react';
import { Play, CheckCircle2, Copy, Check, Sparkles, User, Shield, Plus, X, Sliders, ToggleLeft, ToggleRight, Building } from 'lucide-react';
import { ScriptItem, Device, Tenant } from '../types/index.js';
import { fetchScripts, runScript, createScript, updateScript, fetchTenants } from '../services/api.js';

interface ScriptLibraryViewProps {
  devices: Device[];
}

interface ScriptExecutionResponse {
  success: boolean;
  executionId: string;
  dispatchedCount: number;
  message?: string;
}

export const ScriptLibraryView: React.FC<ScriptLibraryViewProps> = ({ devices }) => {
  const [scripts, setScripts] = useState<ScriptItem[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [selectedScript, setSelectedScript] = useState<ScriptItem | null>(null);
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<string[]>([]);
  const [copied, setCopied] = useState(false);
  const [running, setRunning] = useState(false);
  const [runResult, setRunResult] = useState<ScriptExecutionResponse | null>(null);
  const [scriptParams, setScriptParams] = useState('');
  const [runAsContext, setRunAsContext] = useState<'system' | 'user'>('system');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [roleFilter, setRoleFilter] = useState('all');
  const [tenantFilter, setTenantFilter] = useState('all');
  const [showAddModal, setShowAddModal] = useState(false);

  // New script form state
  const [newScriptName, setNewScriptName] = useState('');
  const [newScriptDesc, setNewScriptDesc] = useState('');
  const [newScriptCategory, setNewScriptCategory] = useState('Administration');
  const [newScriptLang, setNewScriptLang] = useState<'powershell' | 'batch' | 'bash' | 'python'>('powershell');
  const [newScriptRole, setNewScriptRole] = useState<'admin' | 'technician' | 'readonly'>('technician');
  const [newScriptTenantId, setNewScriptTenantId] = useState('');
  const [newScriptCode, setNewScriptCode] = useState('');
  const [newScriptEnabled, setNewScriptEnabled] = useState(true);
  const [savingNewScript, setSavingNewScript] = useState(false);

  const loadScripts = useCallback(async (tenantIdArg?: string) => {
    const tid = tenantIdArg !== undefined ? tenantIdArg : tenantFilter;
    const arg = (tid === 'all' || tid === 'global') ? undefined : tid;
    const data = await fetchScripts(arg);
    setScripts(data);
    setSelectedScript((prev) => {
      if (!prev && data.length > 0) return data[0];
      if (prev) return data.find((s) => s.id === prev.id) || prev;
      return null;
    });
  }, [tenantFilter]);

  useEffect(() => {
    fetchTenants().then(setTenants).catch(console.error);
    loadScripts();
  }, [loadScripts]);

  const handleCopyCode = () => {
    if (selectedScript) {
      navigator.clipboard.writeText(selectedScript.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const insertToken = (token: string) => {
    setScriptParams((prev) => (prev ? `${prev} ${token}` : token));
  };

  const handleToggleEnabled = async (script: ScriptItem, e: React.MouseEvent) => {
    e.stopPropagation();
    const newStatus = (script.enabled ?? 1) !== 0 ? 0 : 1;
    try {
      await updateScript(script.id, { enabled: newStatus });
      setScripts(prev => prev.map(s => s.id === script.id ? { ...s, enabled: newStatus } : s));
      if (selectedScript?.id === script.id) {
        setSelectedScript(prev => prev ? { ...prev, enabled: newStatus } : null);
      }
    } catch (err) {
      console.error('Failed to update script enabled status:', err);
    }
  };

  const handleCreateScript = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newScriptName.trim() || !newScriptCode.trim()) return;
    setSavingNewScript(true);
    try {
      const res = await createScript({
        name: newScriptName.trim(),
        description: newScriptDesc.trim(),
        category: newScriptCategory,
        language: newScriptLang,
        required_role: newScriptRole,
        code: newScriptCode,
        enabled: newScriptEnabled ? 1 : 0,
        is_builtin: 0,
        tenant_id: newScriptTenantId || null
      });
      if (res.success) {
        setShowAddModal(false);
        setNewScriptName('');
        setNewScriptDesc('');
        setNewScriptCode('');
        setNewScriptTenantId('');
        await loadScripts();
      }
    } catch (err) {
      console.error('Failed to create script:', err);
    } finally {
      setSavingNewScript(false);
    }
  };

  const handleRunMass = async () => {
    if (!selectedScript) return;
    if (!selectedScript.enabled) {
      alert('This script is currently disabled by an administrator. Please enable it before running.');
      return;
    }
    if (selectedDeviceIds.length === 0) {
      alert('Please select at least one target device for mass orchestration.');
      return;
    }

    setRunning(true);
    try {
      const res = await runScript(selectedScript.id, selectedDeviceIds);
      setRunResult(res as ScriptExecutionResponse);
    } finally {
      setRunning(false);
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

  const filteredScripts = scripts.filter(s => {
    if (categoryFilter !== 'all' && s.category !== categoryFilter) return false;
    if (roleFilter !== 'all' && s.required_role !== roleFilter) return false;
    if (tenantFilter === 'global' && s.tenant_id) return false;
    if (tenantFilter !== 'all' && tenantFilter !== 'global' && s.tenant_id !== tenantFilter && s.tenant_id !== null && s.tenant_id !== undefined) return false;
    return true;
  });

  const categories = Array.from(new Set(scripts.map(s => s.category || 'General')));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="script-library-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
            Centralized Automation &amp; Script Library
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Production-grade admin automation repository with RBAC access control tiers, per-script enable/disable enforcement, and dynamic parameter injection
          </span>
        </div>

        <button
          className="btn-glass btn-primary"
          onClick={() => setShowAddModal(true)}
          style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}
        >
          <Plus size={16} />
          <span>New Automation Script</span>
        </button>
      </div>

      {/* Filter Toolbar */}
      <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Sliders size={14} color="var(--accent-primary, #00f2fe)" />
          <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)' }}>Category:</span>
          <select
            className="glass-select"
            style={{ padding: '0.35rem 0.65rem', fontSize: '0.8rem' }}
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
          >
            <option value="all">All Categories</option>
            {categories.map(c => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Shield size={14} color="var(--accent-secondary, #7f00ff)" />
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
            {tenants.map(t => (
              <option key={t.id} value={t.id}>Client: {t.name}</option>
            ))}
          </select>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '340px 1fr', gap: '1.5rem', minHeight: '520px' }}>
        {/* Scripts Selector List */}
        <div className="glass-card" style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '720px', overflowY: 'auto' }}>
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

                  {/* Enable / Disable Switch button */}
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

              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <button
                  className="btn-glass"
                  onClick={(e) => handleToggleEnabled(selectedScript, e)}
                  title={(selectedScript.enabled ?? 1) !== 0 ? 'Disable Script' : 'Enable Script'}
                >
                  {(selectedScript.enabled ?? 1) !== 0 ? <ToggleRight size={16} color="#10b981" /> : <ToggleLeft size={16} color="#64748b" />}
                  <span>{(selectedScript.enabled ?? 1) !== 0 ? 'Enabled' : 'Disabled'}</span>
                </button>
                <button className="btn-glass" onClick={handleCopyCode}>
                  {copied ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
                <button
                  className="btn-glass btn-primary"
                  onClick={handleRunMass}
                  disabled={running || (selectedScript.enabled ?? 1) === 0}
                  title={(selectedScript.enabled ?? 1) === 0 ? 'Script is disabled' : 'Execute script across targets'}
                >
                  <Play size={14} />
                  <span>{running ? 'Dispatching...' : 'Mass Execute'}</span>
                </button>
              </div>
            </div>

            {/* Code Viewer */}
            <div className="terminal-window" style={{ height: '220px', color: '#7dd3fc', overflowY: 'auto' }}>
              {selectedScript.code}
            </div>

            {/* Execution Context & Parameters Bar (Ninja Feature) */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 220px', gap: '1rem', background: 'rgba(255, 255, 255, 0.02)', padding: '0.85rem', borderRadius: '8px', border: '1px solid var(--glass-border)' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                  <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)' }}>
                    Runtime Parameters &amp; Flags:
                  </label>
                  {/* Dynamic Token Quick-Injectors */}
                  <div style={{ display: 'flex', gap: '0.35rem' }}>
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ padding: '0.15rem 0.4rem', fontSize: '0.65rem' }}
                      onClick={() => insertToken('$vitrine.device.hostname')}
                      title="Inject Hostname token"
                    >
                      <Sparkles size={10} /> $device.hostname
                    </button>
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ padding: '0.15rem 0.4rem', fontSize: '0.65rem' }}
                      onClick={() => insertToken('$vitrine.device.client_id')}
                      title="Inject Tenant ID token"
                    >
                      $device.client_id
                    </button>
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ padding: '0.15rem 0.4rem', fontSize: '0.65rem' }}
                      onClick={() => insertToken('$vitrine.custom.asset_tag')}
                      title="Inject Custom Field token"
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
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)' }}>
                  TARGET DISPATCH SCOPE ({selectedDeviceIds.length} of {devices.length} selected)
                </span>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
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
                    onClick={() => setSelectedDeviceIds([])}
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
                  Execution Dispatched: Script successfully queued across <strong>{runResult.dispatchedCount} endpoints</strong> under <strong>{runAsContext.toUpperCase()}</strong> authority. Execution ID: <code>{runResult.executionId}</code>.
                </div>
              </div>
            )}
          </div>
        )}
      </div>

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
              maxWidth: '650px',
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
                <Plus size={18} color="var(--accent-primary, #00f2fe)" />
                <h3 style={{ fontSize: '1.25rem', fontWeight: 700, margin: 0 }}>Add Automation Script</h3>
              </div>
              <button
                onClick={() => setShowAddModal(false)}
                style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer' }}
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleCreateScript} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
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
                    {tenants.map(t => (
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

              <div>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.85rem', marginTop: '0.25rem' }}>
                  <input
                    type="checkbox"
                    checked={newScriptEnabled}
                    onChange={(e) => setNewScriptEnabled(e.target.checked)}
                  />
                  <span>Enabled by Default</span>
                </label>
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
                  rows={8}
                  className="glass-input"
                  style={{ fontFamily: 'monospace', fontSize: '0.82rem', resize: 'vertical' }}
                  placeholder="# PowerShell code here..."
                  value={newScriptCode}
                  onChange={(e) => setNewScriptCode(e.target.value)}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
                <button
                  type="button"
                  className="btn-glass"
                  onClick={() => setShowAddModal(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={savingNewScript}
                  className="btn-glass btn-primary"
                >
                  {savingNewScript ? 'Saving Script...' : 'Save & Publish to Library'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
