import React, { useState, useEffect, useCallback } from 'react';
import { Play, Zap, Clock, Ticket, Plus, Trash2, RefreshCw, X } from 'lucide-react';
import { SelfHealingMonitor, RemediationLog, ScriptItem } from '../types/index.js';
import {
  fetchSelfHealing,
  fetchRemediationLogs,
  createSelfHealingMonitor,
  updateSelfHealingMonitor,
  deleteSelfHealingMonitor,
  evaluateSelfHealingMonitors,
  fetchScripts
} from '../services/api.js';

export const SelfHealingView: React.FC = () => {
  const [monitors, setMonitors] = useState<SelfHealingMonitor[]>([]);
  const [logs, setLogs] = useState<RemediationLog[]>([]);
  const [scripts, setScripts] = useState<ScriptItem[]>([]);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [evaluating, setEvaluating] = useState(false);

  // Create Monitor Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newName, setNewName] = useState('');
  const [newConditionType, setNewConditionType] = useState('Service Stopped');
  const [newConditionValue, setNewConditionValue] = useState('Spooler (Print Spooler)');
  const [newScriptId, setNewScriptId] = useState('scr-1');
  const [newCooldown, setNewCooldown] = useState(15);

  const loadAll = useCallback(() => {
    fetchSelfHealing().then(setMonitors);
    fetchRemediationLogs().then(setLogs);
    fetchScripts().then(setScripts);
  }, []);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  const handleEvaluateNow = async () => {
    setEvaluating(true);
    try {
      const res = await evaluateSelfHealingMonitors();
      setStatusMessage(
        `Evaluated ${res.evaluatedMonitors} monitors across ${res.evaluatedDevices} devices: ${res.remediationsTriggered} remediations executed.`
      );
      loadAll();
      setTimeout(() => setStatusMessage(null), 5000);
    } finally {
      setEvaluating(false);
    }
  };

  const handleCreateMonitor = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim()) return;
    await createSelfHealingMonitor({
      name: newName.trim(),
      condition_type: newConditionType,
      condition_value: newConditionValue.trim(),
      remediation_script_id: newScriptId,
      cooldown_min: newCooldown
    });
    loadAll();
    setShowCreateModal(false);
    setNewName('');
  };

  const handleToggleMonitor = async (m: SelfHealingMonitor) => {
    await updateSelfHealingMonitor(m.id, { enabled: m.enabled ? 0 : 1 });
    loadAll();
  };

  const handleDeleteMonitor = async (id: string) => {
    await deleteSelfHealingMonitor(id);
    loadAll();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="self-healing-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
            Condition Monitoring &amp; Auto-Remediation (Self-Healing)
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Event-driven watchdog engine evaluating stopped services, low storage, or high load with automatic script triggers and circuit-breaker flap protection
          </span>
        </div>
        <div style={{ display: 'flex', gap: '0.65rem' }}>
          <button className="btn-glass" onClick={handleEvaluateNow} disabled={evaluating}>
            <RefreshCw size={15} /> {evaluating ? 'Evaluating Fleet...' : 'Evaluate Fleet Now'}
          </button>
          <button className="btn-glass btn-primary" onClick={() => setShowCreateModal(true)}>
            <Plus size={15} /> New Watchdog Monitor
          </button>
        </div>
      </div>

      {statusMessage && (
        <div
          className="glass-card"
          style={{
            padding: '0.75rem 1.25rem',
            background: 'rgba(16, 185, 129, 0.12)',
            borderColor: 'rgba(16, 185, 129, 0.35)',
            color: '#34d399',
            fontSize: '0.85rem'
          }}
        >
          ✓ {statusMessage}
        </div>
      )}

      <div className="metrics-grid">
        <div className="glass-card">
          <div className="metric-title">ACTIVE WATCHDOG MONITORS</div>
          <div className="metric-value" style={{ color: 'var(--primary)' }}>
            {monitors.filter((m) => m.enabled).length} / {monitors.length}
          </div>
          <div className="metric-subtext">Evaluating telemetry stream in real-time</div>
        </div>

        <div className="glass-card">
          <div className="metric-title">RECORDED REMEDIATIONS</div>
          <div className="metric-value" style={{ color: '#34d399' }}>{logs.length}</div>
          <div className="metric-subtext">Issues resolved with zero technician tickets</div>
        </div>

        <div className="glass-card">
          <div className="metric-title">WATCHDOG COOLDOWN SAFETY</div>
          <div className="metric-value">15m</div>
          <div className="metric-subtext">Prevents script flapping loops</div>
        </div>

        <div className="glass-card">
          <div className="metric-title">CIRCUIT BREAKER TRIP RATE</div>
          <div className="metric-value" style={{ color: '#a855f7' }}>3/hr</div>
          <div className="metric-subtext">Max hourly runs before PSA ticket trigger</div>
        </div>
      </div>

      {/* Circuit Breaker & Safeguard Banner */}
      <div
        className="glass-card"
        style={{
          background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.08) 0%, rgba(56, 189, 248, 0.05) 100%)',
          border: '1px solid rgba(168, 85, 247, 0.25)',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.75rem'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <Zap size={20} color="#a855f7" />
          <h3 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0 }}>
            Policy-Governed Self-Healing Safeguards &amp; Flap Protection
          </h3>
        </div>
        <p style={{ fontSize: '0.82rem', color: 'var(--text-dim)', margin: 0, lineHeight: 1.5 }}>
          To prevent infinite retry storms or resource exhaustion on failing endpoints, Vitrine enforces circuit-breaker trip thresholds configured per Policy tier. If an automated runbook fails or triggers more than the allowable hourly limit, the monitor automatically dispatches an urgent incident to the connected PSA and suppresses further execution.
        </p>
        <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap', fontSize: '0.78rem', color: 'var(--text-main)', paddingTop: '0.35rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <Clock size={15} color="var(--primary)" />
            <span><strong>Maintenance Mode Suppression:</strong> Auto-remediations silently muted during scheduled maintenance.</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <Ticket size={15} color="#34d399" />
            <span><strong>Automated PSA Ticketing:</strong> Immediate dispatch with execution transcript upon circuit breaker trip.</span>
          </div>
        </div>
      </div>

      <div className="glass-card" style={{ padding: 0 }}>
        <div style={{ padding: '1rem 1.5rem', borderBottom: '1px solid var(--glass-border)' }}>
          <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 600 }}>Configured Watchdog Monitors</h3>
        </div>
        <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
          <table className="glass-table">
            <thead>
              <tr>
                <th>Monitor Name</th>
                <th>Trigger Condition</th>
                <th>Threshold Value</th>
                <th>Remediation Runbook</th>
                <th>Cooldown</th>
                <th>Status</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {monitors.map((m) => (
                <tr key={m.id}>
                  <td><strong>{m.name}</strong></td>
                  <td>
                    <span className="status-pill status-reboot" style={{ fontSize: '0.72rem' }}>
                      {m.condition_type}
                    </span>
                  </td>
                  <td><code>{m.condition_value}</code></td>
                  <td>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', color: 'var(--primary)', fontSize: '0.82rem' }}>
                      <Play size={12} /> {scripts.find((s) => s.id === m.remediation_script_id)?.name || m.remediation_script_id}
                    </span>
                  </td>
                  <td>{m.cooldown_min} minutes</td>
                  <td>
                    <span
                      className={`status-pill ${m.enabled ? 'status-online' : 'status-offline'}`}
                      style={{ cursor: 'pointer' }}
                      onClick={() => handleToggleMonitor(m)}
                      title="Click to toggle monitor state"
                    >
                      <div className="pulse-dot" /> {m.enabled ? 'Guarding' : 'Paused'}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      className="btn-glass btn-icon"
                      title="Delete Watchdog Monitor"
                      onClick={() => handleDeleteMonitor(m.id)}
                    >
                      <Trash2 size={14} color="#ef4444" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Live Remediation Execution Logs */}
      <div className="glass-card" style={{ padding: 0 }}>
        <div style={{ padding: '1rem 1.5rem', borderBottom: '1px solid var(--glass-border)' }}>
          <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 600 }}>
            Live Self-Healing Remediation &amp; Circuit Breaker Log ({logs.length})
          </h3>
        </div>
        <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
          <table className="glass-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Watchdog Monitor</th>
                <th>Endpoint</th>
                <th>Outcome</th>
                <th>Execution Transcript / PSA Escalation</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id}>
                  <td style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>{log.executed_at}</td>
                  <td><strong>{log.monitor_name}</strong></td>
                  <td><code>{log.hostname}</code></td>
                  <td>
                    <span
                      className={`status-pill ${
                        log.status === 'Remediated' || log.status === 'Success' ? 'status-online' : 'status-isolated'
                      }`}
                    >
                      {log.status}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    {log.output}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {showCreateModal && (
        <div className="modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="glass-modal" style={{ maxWidth: '480px', padding: '1.5rem' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>Create Self-Healing Watchdog</h3>
              <button className="btn-glass btn-icon" onClick={() => setShowCreateModal(false)}>
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleCreateMonitor} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Monitor Name
                </label>
                <input
                  type="text"
                  required
                  className="glass-input"
                  placeholder="e.g. DNS Client Service Auto-Restart"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Condition Type
                  </label>
                  <select
                    className="glass-select"
                    value={newConditionType}
                    onChange={(e) => setNewConditionType(e.target.value)}
                  >
                    <option value="Service Stopped">Service Stopped</option>
                    <option value="Disk Free Space">Disk Free Space</option>
                    <option value="CPU Load Sustained">CPU Load Sustained</option>
                    <option value="Memory Pressure">Memory Pressure</option>
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Threshold / Service Name
                  </label>
                  <input
                    type="text"
                    required
                    className="glass-input"
                    value={newConditionValue}
                    onChange={(e) => setNewConditionValue(e.target.value)}
                  />
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Remediation Runbook Script
                  </label>
                  <select
                    className="glass-select"
                    value={newScriptId}
                    onChange={(e) => setNewScriptId(e.target.value)}
                  >
                    {scripts.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.name} ({s.language})
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Cooldown (Min)
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={240}
                    className="glass-input"
                    value={newCooldown}
                    onChange={(e) => setNewCooldown(Number(e.target.value))}
                  />
                </div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button type="button" className="btn-glass" onClick={() => setShowCreateModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-glass btn-primary">
                  Create Watchdog
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
