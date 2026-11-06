import React, { useState, useEffect, useCallback } from 'react';
import { CheckCircle2, Play, Clock, Undo2, ShieldAlert, Sparkles } from 'lucide-react';
import { Patch } from '../types/index.js';
import { fetchPatches, approvePatch, approvePatchesBulk, scanPatches, rollbackPatch } from '../services/api.js';

export const PatchManagementView: React.FC = () => {
  const [patches, setPatches] = useState<Patch[]>([]);
  const [filterCategory, setFilterCategory] = useState('all');
  const [autoApproveThirdParty, setAutoApproveThirdParty] = useState(true);
  const [canaryDelayDays, setCanaryDelayDays] = useState(3);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const loadPatches = useCallback(() => {
    fetchPatches().then(setPatches);
  }, []);

  useEffect(() => {
    loadPatches();
  }, [loadPatches]);

  const showNotification = (msg: string) => {
    setActionMessage(msg);
    setTimeout(() => setActionMessage(null), 4000);
  };

  const handleApprove = async (id: string) => {
    await approvePatch(id);
    setPatches(patches.map((p) => (p.id === id ? { ...p, status: 'Approved' } : p)));
    showNotification(`Patch ${id} approved for the next scheduled maintenance window.`);
  };

  const handleBulkApprovePending = async () => {
    const pendingIds = filteredPatches.filter((p) => p.status === 'Pending').map((p) => p.id);
    if (pendingIds.length === 0) return;
    const res = await approvePatchesBulk(pendingIds);
    loadPatches();
    showNotification(`Approved ${res.approvedCount} pending updates for staged deployment.`);
  };

  const handleFleetScan = async () => {
    const res = await scanPatches();
    loadPatches();
    showNotification(`Triggered fleet patch scan across all active endpoints (${res.patches?.length || 0} updates indexed).`);
  };

  const handleRollback = async (id: string, kbId: string) => {
    if (!confirm(`Are you sure you want to trigger DISM/WUSA rollback and uninstall ${kbId}?`)) return;
    const res = await rollbackPatch(id);
    if (res.success) {
      setPatches(patches.map((p) => (p.id === id ? { ...p, status: 'Rolled Back' } : p)));
      showNotification(`Rollback initiated for ${kbId}: ${res.message}`);
    }
  };

  const filteredPatches = patches.filter((p) => {
    if (filterCategory === 'all') return true;
    if (filterCategory === 'os') return p.category.includes('Security') || p.category.includes('Critical');
    if (filterCategory === 'third_party') return p.category.includes('Winget') || p.category.includes('Third-Party');
    return true;
  });

  const pendingCount = filteredPatches.filter((p) => p.status === 'Pending').length;

  const getCvssBadgeColor = (score?: number) => {
    if (!score) return '#94a3b8';
    if (score >= 9.0) return '#ef4444';
    if (score >= 7.0) return '#f97316';
    if (score >= 4.0) return '#eab308';
    return '#10b981';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="patch-management-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
            OS &amp; Third-Party Patch Management
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Automated Windows Update orchestration, CVE vulnerability scoring, OEM driver staging, and Winget/Chocolatey silent deployments
          </span>
        </div>
        <div style={{ display: 'flex', gap: '0.65rem' }}>
          {pendingCount > 0 && (
            <button className="btn-glass" onClick={handleBulkApprovePending}>
              <CheckCircle2 size={15} color="#10b981" /> Approve All Pending ({pendingCount})
            </button>
          )}
          <button className="btn-glass btn-primary" onClick={handleFleetScan}>
            <Play size={15} /> Trigger Fleet Scan
          </button>
        </div>
      </div>

      {actionMessage && (
        <div style={{ background: 'rgba(0, 242, 254, 0.12)', border: '1px solid rgba(0, 242, 254, 0.35)', padding: '0.75rem 1.25rem', borderRadius: '8px', color: '#38bdf8', fontSize: '0.85rem' }}>
          {actionMessage}
        </div>
      )}

      {/* Auto-Approval & Canary Automation Panel */}
      <div className="glass-card" style={{ padding: '1.25rem 1.5rem', background: 'rgba(255, 255, 255, 0.02)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <Sparkles size={20} color="var(--primary)" />
            <div>
              <div style={{ fontWeight: 600, fontSize: '0.95rem' }}>Automated Patch Approval Rules (Ninja-Grade)</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Stage deployments gradually to canary devices before fleet-wide rollout.
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '1.5rem', alignItems: 'center' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={autoApproveThirdParty}
                onChange={(e) => setAutoApproveThirdParty(e.target.checked)}
              />
              <span>Auto-approve 3rd-party apps (Winget/Choco)</span>
            </label>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem' }}>
              <span style={{ color: 'var(--text-muted)' }}>OS Canary Deferral:</span>
              <select
                className="glass-select"
                style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem', width: 'auto' }}
                value={canaryDelayDays}
                onChange={(e) => setCanaryDelayDays(Number(e.target.value))}
              >
                <option value={0}>Immediate (0 Days)</option>
                <option value={3}>3 Days (Canary Stage)</option>
                <option value={7}>7 Days (Pilot Batch)</option>
                <option value={14}>14 Days (Conservative)</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Filter Tabs */}
      <div style={{ display: 'flex', gap: '0.65rem' }}>
        <button
          className={`btn-glass ${filterCategory === 'all' ? 'btn-primary' : ''}`}
          onClick={() => setFilterCategory('all')}
        >
          All Updates ({patches.length})
        </button>
        <button
          className={`btn-glass ${filterCategory === 'os' ? 'btn-primary' : ''}`}
          onClick={() => setFilterCategory('os')}
        >
          Windows OS &amp; Security KBs
        </button>
        <button
          className={`btn-glass ${filterCategory === 'third_party' ? 'btn-primary' : ''}`}
          onClick={() => setFilterCategory('third_party')}
        >
          📦 Third-Party Repos (Winget / Choco)
        </button>
      </div>

      {/* Patches Table */}
      <div className="glass-card" style={{ padding: 0 }}>
        <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
          <table className="glass-table">
            <thead>
              <tr>
                <th>Target Host</th>
                <th>Update Title / Package</th>
                <th>KB / Version</th>
                <th>CVE / CVSS Score</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Approval Status</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredPatches.map((p) => (
                <tr key={p.id}>
                  <td><strong>{p.hostname || 'WIN11-PRO-EXEC'}</strong></td>
                  <td>{p.title}</td>
                  <td><code>{p.kb_id}</code></td>
                  <td>
                    {p.cve_id ? (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <span style={{ fontSize: '0.72rem', fontFamily: 'monospace', color: '#93c5fd' }}>
                          {p.cve_id}
                        </span>
                        {p.cvss_score && (
                          <span
                            style={{
                              fontSize: '0.65rem',
                              fontWeight: 700,
                              padding: '1px 5px',
                              borderRadius: '4px',
                              background: 'rgba(0, 0, 0, 0.4)',
                              color: getCvssBadgeColor(p.cvss_score),
                              border: `1px solid ${getCvssBadgeColor(p.cvss_score)}44`
                            }}
                            title={`CVSS v3.1 Severity Score: ${p.cvss_score}`}
                          >
                            {p.cvss_score.toFixed(1)}
                          </span>
                        )}
                      </div>
                    ) : (
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>—</span>
                    )}
                  </td>
                  <td>{p.category}</td>
                  <td>
                    <span
                      className={`status-pill ${
                        p.severity === 'Critical' ? 'status-isolated' : 'status-reboot'
                      }`}
                    >
                      {p.severity === 'Critical' && <ShieldAlert size={11} style={{ marginRight: 3 }} />}
                      {p.severity}
                    </span>
                  </td>
                  <td>
                    <span
                      className={`status-pill ${
                        p.status === 'Installed'
                          ? 'status-online'
                          : p.status === 'Approved'
                          ? 'status-reboot'
                          : p.status === 'Rolled Back'
                          ? 'status-isolated'
                          : 'status-offline'
                      }`}
                    >
                      {p.status}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end', alignItems: 'center' }}>
                      {p.status === 'Pending' && (
                        <button
                          className="btn-glass btn-primary"
                          style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem' }}
                          onClick={() => handleApprove(p.id)}
                        >
                          <CheckCircle2 size={13} /> Approve
                        </button>
                      )}
                      {p.status === 'Approved' && (
                        <span style={{ fontSize: '0.75rem', color: '#10b981', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                          <Clock size={13} /> Staged for Window
                        </span>
                      )}
                      {p.status === 'Installed' && (
                        <>
                          <span style={{ fontSize: '0.75rem', color: '#38bdf8' }}>✓ Up to date</span>
                          <button
                            className="btn-glass"
                            style={{ padding: '0.25rem 0.5rem', fontSize: '0.72rem', color: '#f43f5e' }}
                            title="Rollback / Uninstall KB via DISM/WUSA"
                            onClick={() => handleRollback(p.id, p.kb_id)}
                          >
                            <Undo2 size={12} /> Rollback
                          </button>
                        </>
                      )}
                      {p.status === 'Rolled Back' && (
                        <span style={{ fontSize: '0.72rem', color: '#f87171' }}>Rolled Back</span>
                      )}
                    </div>
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
