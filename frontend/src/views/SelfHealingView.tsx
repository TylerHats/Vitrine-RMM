import React, { useState, useEffect } from 'react';
import { HeartPulse, CheckCircle2, AlertTriangle, Play, Shield, RefreshCw } from 'lucide-react';
import { SelfHealingMonitor } from '../types/index.js';
import { fetchSelfHealing } from '../services/api.js';

export const SelfHealingView: React.FC = () => {
  const [monitors, setMonitors] = useState<SelfHealingMonitor[]>([]);

  useEffect(() => {
    fetchSelfHealing().then(setMonitors);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="self-healing-view">
      <div>
        <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
          Condition Monitoring &amp; Auto-Remediation (Self-Healing)
        </h2>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          Event-driven watchdog engine evaluating stopped services, low storage, or high load with automatic script triggers
        </span>
      </div>

      <div className="metrics-grid">
        <div className="glass-card">
          <div className="metric-title">ACTIVE WATCHDOG MONITORS</div>
          <div className="metric-value" style={{ color: 'var(--primary)' }}>{monitors.length}</div>
          <div className="metric-subtext">Evaluating telemetry stream in real-time</div>
        </div>

        <div className="glass-card">
          <div className="metric-title">AUTO-REMEDIATIONS THIS MONTH</div>
          <div className="metric-value" style={{ color: '#34d399' }}>142</div>
          <div className="metric-subtext">Issues resolved with zero technician tickets</div>
        </div>

        <div className="glass-card">
          <div className="metric-title">WATCHDOG COOLDOWN SAFETY</div>
          <div className="metric-value">15m</div>
          <div className="metric-subtext">Prevents script flapping loops</div>
        </div>
      </div>

      <div className="glass-card" style={{ padding: 0 }}>
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
                      <Play size={12} /> Runbook ID {m.remediation_script_id}
                    </span>
                  </td>
                  <td>{m.cooldown_min} minutes</td>
                  <td>
                    <span className="status-pill status-online">
                      <div className="pulse-dot" /> Guarding
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
