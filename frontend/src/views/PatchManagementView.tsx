import React, { useState, useEffect } from 'react';
import { RefreshCw, CheckCircle2, AlertCircle, Shield, Package, Play, Clock } from 'lucide-react';
import { Patch } from '../types/index.js';
import { fetchPatches, approvePatch } from '../services/api.js';

export const PatchManagementView: React.FC = () => {
  const [patches, setPatches] = useState<Patch[]>([]);
  const [filterCategory, setFilterCategory] = useState('all');

  useEffect(() => {
    fetchPatches().then(setPatches);
  }, []);

  const handleApprove = async (id: string) => {
    await approvePatch(id);
    setPatches(patches.map((p) => (p.id === id ? { ...p, status: 'Approved' } : p)));
  };

  const filteredPatches = patches.filter((p) => {
    if (filterCategory === 'all') return true;
    if (filterCategory === 'os') return p.category.includes('Security') || p.category.includes('Critical');
    if (filterCategory === 'third_party') return p.category.includes('Winget') || p.category.includes('Third-Party');
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="patch-management-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
            OS &amp; Third-Party Patch Management
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Automated Windows Update orchestration, OEM driver staging, and Winget/Chocolatey silent deployments
          </span>
        </div>
        <button className="btn-glass btn-primary" onClick={() => alert('Triggered fleet patch scan across all active agents.')}>
          <Play size={15} /> Trigger Fleet Scan
        </button>
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
                  <td>{p.category}</td>
                  <td>
                    <span
                      className={`status-pill ${
                        p.severity === 'Critical' ? 'status-isolated' : 'status-reboot'
                      }`}
                    >
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
                          : 'status-offline'
                      }`}
                    >
                      {p.status}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
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
                      <span style={{ fontSize: '0.75rem', color: '#10b981', display: 'flex', alignItems: 'center', gap: '0.3rem', justifyContent: 'flex-end' }}>
                        <Clock size={13} /> Staged for Window
                      </span>
                    )}
                    {p.status === 'Installed' && (
                      <span style={{ fontSize: '0.75rem', color: '#38bdf8' }}>✓ Up to date</span>
                    )}
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
