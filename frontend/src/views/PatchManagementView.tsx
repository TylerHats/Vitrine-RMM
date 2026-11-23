import React, { useState, useEffect, useCallback } from 'react';
import {
  CheckCircle2,
  Play,
  Clock,
  Undo2,
  ShieldAlert,
  Sparkles,
  Package,
  Ban,
  Plus,
  Trash2,
  X
} from 'lucide-react';
import {
  Patch,
  Settings,
  SoftwarePackage,
  SoftwareDeployment,
  KbBlacklistEntry,
  Device,
  Tenant,
  AuthUser
} from '../types/index.js';
import {
  fetchPatches,
  approvePatch,
  approvePatchesBulk,
  scanPatches,
  rollbackPatch,
  updateSettings,
  fetchSoftwarePackages,
  createSoftwarePackage,
  deleteSoftwarePackage,
  deploySoftwarePackage,
  fetchSoftwareDeployments,
  fetchPatchBlacklist,
  addPatchBlacklist,
  removePatchBlacklist,
  fetchDevices,
  fetchTenants
} from '../services/api.js';
import { canMutateFleet, isSuperAdmin } from '../utils/permissions.js';

interface PatchManagementViewProps {
  settings?: Settings | null;
  onSettingsUpdated?: (s: Settings) => void;
  currentUser?: AuthUser | null;
}

export const PatchManagementView: React.FC<PatchManagementViewProps> = ({
  settings,
  onSettingsUpdated,
  currentUser
}) => {
  const canMutate = canMutateFleet(currentUser);
  const isSuper = isSuperAdmin(currentUser);
  const [activeTab, setActiveTab] = useState<'patches' | 'catalog' | 'blacklist'>('patches');
  const [patches, setPatches] = useState<Patch[]>([]);
  const [filterCategory, setFilterCategory] = useState('all');
  const [autoApproveThirdParty, setAutoApproveThirdParty] = useState(
    settings?.patch_auto_approve_third_party !== undefined ? Boolean(settings.patch_auto_approve_third_party) : true
  );
  const [canaryDelayDays, setCanaryDelayDays] = useState(
    settings?.patch_canary_delay_days !== undefined ? Number(settings.patch_canary_delay_days) : 3
  );
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Software Package Catalog & Deployments
  const [packages, setPackages] = useState<SoftwarePackage[]>([]);
  const [deployments, setDeployments] = useState<SoftwareDeployment[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [selectedDeployDevices, setSelectedDeployDevices] = useState<string[]>([]);
  const [showAddPkgModal, setShowAddPkgModal] = useState(false);
  const [pkgName, setPkgName] = useState('');
  const [pkgVendor, setPkgVendor] = useState('');
  const [pkgVersion, setPkgVersion] = useState('latest');
  const [pkgOs, setPkgOs] = useState<SoftwarePackage['os_type']>('windows');
  const [pkgManager, setPkgManager] = useState<SoftwarePackage['package_manager']>('winget');
  const [pkgIdentifier, setPkgIdentifier] = useState('');
  const [pkgInstallArgs, setPkgInstallArgs] = useState('--silent --accept-package-agreements');
  const [pkgSha256, setPkgSha256] = useState('');

  // KB / Package Blocklist
  const [blacklist, setBlacklist] = useState<KbBlacklistEntry[]>([]);
  const [blockKbId, setBlockKbId] = useState('');
  const [blockReason, setBlockReason] = useState('');
  const [blockTenantId, setBlockTenantId] = useState('');

  useEffect(() => {
    if (settings?.patch_auto_approve_third_party !== undefined) {
      setAutoApproveThirdParty(Boolean(settings.patch_auto_approve_third_party));
    }
    if (settings?.patch_canary_delay_days !== undefined) {
      setCanaryDelayDays(Number(settings.patch_canary_delay_days));
    }
  }, [settings?.patch_auto_approve_third_party, settings?.patch_canary_delay_days]);

  const loadAll = useCallback(() => {
    fetchPatches().then(setPatches).catch(() => {});
    fetchSoftwarePackages().then(setPackages).catch(() => {});
    fetchSoftwareDeployments().then(setDeployments).catch(() => {});
    fetchPatchBlacklist().then(setBlacklist).catch(() => {});
    fetchDevices().then((d) => {
      setDevices(d);
      setSelectedDeployDevices((prev) => (prev.length > 0 ? prev : d.slice(0, 1).map((x) => x.id)));
    }).catch(() => {});
    fetchTenants().then(setTenants).catch(() => {});
  }, []);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  const showNotification = (msg: string) => {
    setActionMessage(msg);
    setTimeout(() => setActionMessage(null), 4500);
  };

  const handleApprove = async (id: string) => {
    const res = await approvePatch(id);
    if (!res.success) {
      showNotification(`Error approving patch ${id}: ${res.error || 'Request rejected'}`);
      return;
    }
    setPatches(patches.map((p) => (p.id === id ? { ...p, status: 'Approved' } : p)));
    showNotification(`Patch ${id} approved for the next scheduled maintenance window.`);
  };

  const handleBulkApprovePending = async () => {
    const pendingIds = filteredPatches.filter((p) => p.status === 'Pending').map((p) => p.id);
    if (pendingIds.length === 0) return;
    const res = await approvePatchesBulk(pendingIds);
    if (!res.success) {
      showNotification(`Error approving patches: ${res.error || 'Request rejected'}`);
      return;
    }
    loadAll();
    showNotification(`Approved ${res.approvedCount} pending updates for staged deployment.`);
  };

  const handleFleetScan = async () => {
    const res = await scanPatches();
    if (!res.success) {
      showNotification(`Error running patch scan: ${res.error || 'Request rejected'}`);
      return;
    }
    loadAll();
    showNotification(`Triggered fleet patch scan across all active endpoints (${res.patches?.length || 0} updates indexed).`);
  };

  const handleRollback = async (id: string, kbId: string) => {
    if (!confirm(`Are you sure you want to trigger DISM/WUSA rollback and uninstall ${kbId}?`)) return;
    const res = await rollbackPatch(id);
    if (res.success) {
      setPatches(patches.map((p) => (p.id === id ? { ...p, status: 'Rolled Back' } : p)));
      showNotification(`Rollback initiated for ${kbId}: ${res.message}`);
    } else {
      showNotification(`Error rolling back ${kbId}: ${res.error || 'Request rejected'}`);
    }
  };

  const handleCreatePackage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pkgName.trim() || !pkgIdentifier.trim()) return;
    const res = await createSoftwarePackage({
      name: pkgName.trim(),
      vendor: pkgVendor.trim() || 'Enterprise Catalog',
      version: pkgVersion.trim() || 'latest',
      os_type: pkgOs,
      package_manager: pkgManager,
      package_identifier: pkgIdentifier.trim(),
      install_args: pkgInstallArgs.trim(),
      sha256_hash: pkgSha256.trim() || undefined
    });
    if (res.success) {
      setShowAddPkgModal(false);
      setPkgName('');
      setPkgIdentifier('');
      setPkgSha256('');
      loadAll();
      showNotification(`Added "${pkgName.trim()}" to Software Deployment Catalog.`);
    }
  };

  const handleDeployPackage = async (pkg: SoftwarePackage, action: 'install' | 'upgrade' | 'uninstall') => {
    if (selectedDeployDevices.length === 0) {
      showNotification('⚠ Select at least one target endpoint above to deploy software.');
      return;
    }
    const res = await deploySoftwarePackage(pkg.id, { deviceIds: selectedDeployDevices, action });
    if (res.success) {
      loadAll();
      showNotification(`Dispatched ${action.toUpperCase()} of "${pkg.name}" across ${res.deployedCount ?? selectedDeployDevices.length} endpoint(s).`);
    } else {
      showNotification(`Error dispatching ${action} of "${pkg.name}": ${(res as any).error || 'Request rejected'}`);
    }
  };

  const handleAddBlacklist = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!blockKbId.trim()) return;
    const res = await addPatchBlacklist({
      kb_or_pkg_id: blockKbId.trim(),
      reason: blockReason.trim() || 'Blocked by MSP patch governance',
      tenant_id: blockTenantId || null
    });
    if (res.success) {
      setBlockKbId('');
      setBlockReason('');
      loadAll();
      showNotification(`Blocked update "${blockKbId.trim()}" from automated approval & deployment.`);
    }
  };

  const filteredPatches = patches.filter((p) => {
    if (filterCategory === 'all') return true;
    if (filterCategory === 'os') {
      return (
        p.category.includes('Security') ||
        p.category.includes('Critical') ||
        p.category.includes('Rollup') ||
        p.category.includes('Driver') ||
        p.category.includes('OS')
      );
    }
    if (filterCategory === 'third_party') {
      return p.category.includes('Winget') || p.category.includes('Third-Party') || p.category.includes('Choco');
    }
    return true;
  });

  const handleToggleAutoApprove = async (checked: boolean) => {
    if (!isSuper) return;
    setAutoApproveThirdParty(checked);
    try {
      const res = await updateSettings({ patch_auto_approve_third_party: checked ? 1 : 0 });
      if (res.success && res.settings) {
        onSettingsUpdated?.(res.settings);
      } else if (!res.success) {
        setActionMessage(`⚠️ Failed to save auto-approve setting: ${res.error || 'Unknown error'}`);
      }
    } catch (err: unknown) {
      setActionMessage(`⚠️ Failed to save auto-approve setting: ${err instanceof Error ? err.message : 'Request failed'}`);
    }
  };

  const handleCanaryChange = async (days: number) => {
    if (!isSuper) return;
    setCanaryDelayDays(days);
    try {
      const res = await updateSettings({ patch_canary_delay_days: days });
      if (res.success && res.settings) {
        onSettingsUpdated?.(res.settings);
      } else if (!res.success) {
        setActionMessage(`⚠️ Failed to save canary delay setting: ${res.error || 'Unknown error'}`);
      }
    } catch (err: unknown) {
      setActionMessage(`⚠️ Failed to save canary delay setting: ${err instanceof Error ? err.message : 'Request failed'}`);
    }
  };

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
            OS Patching, Software Deployment Catalog &amp; KB Blocklist
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Staged ring patch orchestration, silent MSI/EXE/PKG/Winget/APT software catalog deployment, and problematic KB blocklisting
          </span>
        </div>
        <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
          <button
            className={`btn-glass ${activeTab === 'patches' ? 'btn-primary' : ''}`}
            onClick={() => setActiveTab('patches')}
          >
            OS &amp; 3rd-Party Updates ({patches.length})
          </button>
          <button
            className={`btn-glass ${activeTab === 'catalog' ? 'btn-primary' : ''}`}
            onClick={() => setActiveTab('catalog')}
          >
            <Package size={14} /> Software Catalog ({packages.length})
          </button>
          <button
            className={`btn-glass ${activeTab === 'blacklist' ? 'btn-primary' : ''}`}
            onClick={() => setActiveTab('blacklist')}
          >
            <Ban size={14} /> KB Blocklist ({blacklist.length})
          </button>
          {canMutate && activeTab === 'patches' && (
            <>
              {pendingCount > 0 && (
                <button className="btn-glass" onClick={handleBulkApprovePending}>
                  <CheckCircle2 size={15} color="#10b981" /> Approve Pending ({pendingCount})
                </button>
              )}
              <button className="btn-glass btn-primary" onClick={handleFleetScan}>
                <Play size={15} /> Trigger Fleet Scan
              </button>
            </>
          )}
          {canMutate && activeTab === 'catalog' && (
            <button className="btn-glass btn-primary" onClick={() => setShowAddPkgModal(true)}>
              <Plus size={15} /> Add Software Package
            </button>
          )}
        </div>
      </div>

      {actionMessage && (() => {
        const isPatchErr = actionMessage.startsWith('⚠') || /^error/i.test(actionMessage);
        return (
          <div
            style={{
              background: isPatchErr ? 'rgba(239, 68, 68, 0.14)' : 'rgba(0, 242, 254, 0.12)',
              border: `1px solid ${isPatchErr ? 'rgba(239, 68, 68, 0.35)' : 'rgba(0, 242, 254, 0.35)'}`,
              padding: '0.75rem 1.25rem',
              borderRadius: '8px',
              color: isPatchErr ? '#f87171' : 'var(--primary)',
              fontSize: '0.85rem'
            }}
          >
            {actionMessage}
          </div>
        );
      })()}

      {activeTab === 'patches' && (
        <>
          <div className="glass-card" style={{ padding: '1.25rem 1.5rem', background: 'rgba(255, 255, 255, 0.02)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <Sparkles size={20} color="var(--primary)" />
                <div>
                  <div style={{ fontWeight: 600, fontSize: '0.95rem' }}>Automated Patch Approval Rules (Ring-Staged)</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Stage deployments gradually across Canary &rarr; Pilot &rarr; Production rings while respecting the KB Blocklist.
                  </div>
                </div>
              </div>

              {isSuper && (
                <div style={{ display: 'flex', gap: '1.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={autoApproveThirdParty}
                      onChange={(e) => handleToggleAutoApprove(e.target.checked)}
                    />
                    <span>Auto-approve 3rd-party apps (Winget/Choco/APT/Brew)</span>
                  </label>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem' }}>
                    <span style={{ color: 'var(--text-muted)' }}>OS Canary Deferral:</span>
                    <select
                      className="glass-select"
                      style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem', width: 'auto' }}
                      value={canaryDelayDays}
                      onChange={(e) => handleCanaryChange(Number(e.target.value))}
                    >
                      <option value={0}>Immediate (0 Days)</option>
                      <option value={3}>3 Days (Canary Stage)</option>
                      <option value={7}>7 Days (Pilot Batch)</option>
                      <option value={14}>14 Days (Conservative)</option>
                    </select>
                  </div>
                </div>
              )}
            </div>
          </div>

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
              OS &amp; Security KBs
            </button>
            <button
              className={`btn-glass ${filterCategory === 'third_party' ? 'btn-primary' : ''}`}
              onClick={() => setFilterCategory('third_party')}
            >
              📦 Third-Party Repos (Winget / Choco / APT / Brew)
            </button>
          </div>

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
                      <td><strong>{p.hostname || p.device_id || 'Managed Endpoint'}</strong></td>
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
                        <span className={`status-pill ${p.severity === 'Critical' ? 'status-isolated' : 'status-reboot'}`}>
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
                          {p.status === 'Pending' && canMutate && (
                            <button
                              className="btn-glass btn-primary"
                              style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem' }}
                              onClick={() => handleApprove(p.id)}
                            >
                              <CheckCircle2 size={13} /> Approve
                            </button>
                          )}
                          {p.status === 'Pending' && !canMutate && (
                            <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Awaiting Approval</span>
                          )}
                          {p.status === 'Approved' && (
                            <span style={{ fontSize: '0.75rem', color: '#10b981', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                              <Clock size={13} /> Staged for Window
                            </span>
                          )}
                          {p.status === 'Installed' && (
                            <>
                              <span style={{ fontSize: '0.75rem', color: '#38bdf8' }}>✓ Up to date</span>
                              {canMutate && (
                                <button
                                  className="btn-glass"
                                  style={{ padding: '0.25rem 0.5rem', fontSize: '0.72rem', color: '#f43f5e' }}
                                  onClick={() => handleRollback(p.id, p.kb_id)}
                                >
                                  <Undo2 size={12} /> Rollback
                                </button>
                              )}
                            </>
                          )}
                          {p.status === 'Rolled Back' && (
                            <span style={{ fontSize: '0.72rem', color: '#f87171' }}>Rolled Back</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                  {filteredPatches.length === 0 && (
                    <tr>
                      <td colSpan={8} style={{ textAlign: 'center', padding: '2.25rem', color: 'var(--text-muted)' }}>
                        No pending or historical OS updates recorded yet. Click &quot;Trigger Fleet Scan&quot; to index updates across online endpoints.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {activeTab === 'catalog' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Target Endpoints Selector for 1-Click Deployment */}
          <div className="glass-card" style={{ padding: '1rem 1.25rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.6rem' }}>
              <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-dim)' }}>
                DEPLOYMENT TARGET ENDPOINTS ({selectedDeployDevices.length} selected)
              </span>
              <div style={{ display: 'flex', gap: '0.4rem' }}>
                <button className="btn-glass" style={{ fontSize: '0.72rem', padding: '0.2rem 0.5rem' }} onClick={() => setSelectedDeployDevices(devices.map((d) => d.id))}>
                  Select All
                </button>
                <button className="btn-glass" style={{ fontSize: '0.72rem', padding: '0.2rem 0.5rem' }} onClick={() => setSelectedDeployDevices([])}>
                  Clear
                </button>
              </div>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              {devices.map((d) => {
                const checked = selectedDeployDevices.includes(d.id);
                return (
                  <label
                    key={d.id}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.4rem',
                      padding: '0.35rem 0.65rem',
                      borderRadius: '6px',
                      background: checked ? 'rgba(0, 242, 254, 0.12)' : 'rgba(255,255,255,0.03)',
                      border: `1px solid ${checked ? 'rgba(0, 242, 254, 0.35)' : 'var(--glass-border)'}`,
                      fontSize: '0.78rem',
                      cursor: 'pointer'
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() =>
                        setSelectedDeployDevices((prev) =>
                          prev.includes(d.id) ? prev.filter((x) => x !== d.id) : [...prev, d.id]
                        )
                      }
                    />
                    <span>{d.hostname} ({d.os_type})</span>
                  </label>
                );
              })}
            </div>
          </div>

          <div className="glass-card" style={{ padding: 0 }}>
            <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
              <table className="glass-table">
                <thead>
                  <tr>
                    <th>Application</th>
                    <th>OS / Manager</th>
                    <th>Package ID / URL</th>
                    <th>Version</th>
                    <th>Silent Flags</th>
                    <th style={{ textAlign: 'right' }}>Deploy</th>
                  </tr>
                </thead>
                <tbody>
                  {packages.map((pkg) => (
                    <tr key={pkg.id}>
                      <td>
                        <strong>{pkg.name}</strong>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>{pkg.vendor}</div>
                      </td>
                      <td>
                        <span className="status-pill status-online" style={{ fontSize: '0.7rem' }}>
                          {(pkg.os_type || pkg.platform || 'any').toUpperCase()} • {pkg.package_manager || pkg.package_type}
                        </span>
                      </td>
                      <td><code>{pkg.package_identifier}</code></td>
                      <td><code>{pkg.version || 'latest'}</code></td>
                      <td style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                        <code>{pkg.install_args || '—'}</code>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        {canMutate ? (
                          <div style={{ display: 'inline-flex', gap: '0.35rem' }}>
                            <button
                              className="btn-glass btn-primary"
                              style={{ padding: '0.22rem 0.6rem', fontSize: '0.74rem' }}
                              onClick={() => handleDeployPackage(pkg, 'install')}
                            >
                              <Play size={12} /> Install
                            </button>
                            <button
                              className="btn-glass"
                              style={{ padding: '0.22rem 0.55rem', fontSize: '0.74rem' }}
                              onClick={() => handleDeployPackage(pkg, 'upgrade')}
                            >
                              Upgrade
                            </button>
                            <button
                              className="btn-glass btn-icon"
                              onClick={async () => {
                                await deleteSoftwarePackage(pkg.id);
                                loadAll();
                              }}
                              title="Remove from Catalog"
                            >
                              <Trash2 size={13} color="#ef4444" />
                            </button>
                          </div>
                        ) : (
                          <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Read-Only</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {deployments.length > 0 && (
            <div className="glass-card">
              <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '0.6rem' }}>
                RECENT SOFTWARE DEPLOYMENT JOBS ({deployments.length})
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', maxHeight: '190px', overflowY: 'auto' }}>
                {deployments.slice(0, 12).map((dep) => (
                  <div
                    key={dep.id}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      padding: '0.5rem 0.75rem',
                      borderRadius: '6px',
                      background: 'rgba(255,255,255,0.03)',
                      fontSize: '0.76rem'
                    }}
                  >
                    <span>
                      <strong>{dep.package_name || dep.package_id}</strong> ({dep.action.toUpperCase()}) &rarr;{' '}
                      <code>{dep.hostname || dep.device_id}</code>
                    </span>
                    <span style={{ color: dep.status === 'completed' ? '#34d399' : '#fbbf24' }}>
                      {dep.status} • {dep.created_at ? new Date(dep.created_at).toLocaleTimeString() : ''}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'blacklist' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {canMutate && (
            <form onSubmit={handleAddBlacklist} className="glass-card" style={{ display: 'grid', gridTemplateColumns: '1fr 1.5fr 1fr auto', gap: '0.75rem', alignItems: 'end' }}>
              <div>
                <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  KB ID or Package Identifier *
                </label>
                <input
                  type="text"
                  required
                  className="glass-input"
                  placeholder="e.g. KB5034441"
                  value={blockKbId}
                  onChange={(e) => setBlockKbId(e.target.value)}
                />
              </div>
              <div>
                <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Block Reason / Advisory Reference
                </label>
                <input
                  type="text"
                  className="glass-input"
                  placeholder="e.g. Known WinRE partition resize failure"
                  value={blockReason}
                  onChange={(e) => setBlockReason(e.target.value)}
                />
              </div>
              <div>
                <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Client Scope
                </label>
                <select className="glass-select" value={blockTenantId} onChange={(e) => setBlockTenantId(e.target.value)}>
                  <option value="">Global (All Clients)</option>
                  {tenants.map((t) => (
                    <option key={t.id} value={t.id}>{t.name}</option>
                  ))}
                </select>
              </div>
              <button type="submit" className="btn-glass btn-primary">
                <Ban size={14} /> Block Update
              </button>
            </form>
          )}

          <div className="glass-card" style={{ padding: 0 }}>
            <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
              <table className="glass-table">
                <thead>
                  <tr>
                    <th>Blocked KB / Package</th>
                    <th>Scope</th>
                    <th>Reason</th>
                    <th>Created By</th>
                    <th style={{ textAlign: 'right' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {blacklist.map((b) => (
                    <tr key={b.id}>
                      <td><code>{b.kb_or_pkg_id || b.kb_id}</code></td>
                      <td>{b.tenant_id ? tenants.find((t) => t.id === b.tenant_id)?.name || b.tenant_id : 'Global Fleet'}</td>
                      <td>{b.reason}</td>
                      <td style={{ fontSize: '0.76rem', color: 'var(--text-dim)' }}>{b.created_by}</td>
                      <td style={{ textAlign: 'right' }}>
                        {canMutate ? (
                          <button
                            className="btn-glass btn-icon"
                            onClick={async () => {
                              await removePatchBlacklist(b.id);
                              loadAll();
                            }}
                            title="Unblock Update"
                          >
                            <Trash2 size={13} color="#ef4444" />
                          </button>
                        ) : (
                          <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                  {blacklist.length === 0 && (
                    <tr>
                      <td colSpan={5} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                        No KBs or packages are currently blocklisted.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Add Software Package Modal */}
      {showAddPkgModal && (
        <div className="modal-overlay" onClick={() => setShowAddPkgModal(false)}>
          <div className="glass-modal" style={{ maxWidth: '520px', padding: '1.5rem' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>Add Package to Deployment Catalog</h3>
              <button className="btn-glass btn-icon" onClick={() => setShowAddPkgModal(false)}>
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleCreatePackage} style={{ display: 'flex', flexDirection: 'column', gap: '0.8rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr', gap: '0.8rem' }}>
                <div>
                  <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Package Name *
                  </label>
                  <input type="text" required className="glass-input" placeholder="e.g. Tailscale VPN Client" value={pkgName} onChange={(e) => setPkgName(e.target.value)} />
                </div>
                <div>
                  <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Vendor
                  </label>
                  <input type="text" className="glass-input" placeholder="e.g. Tailscale Inc." value={pkgVendor} onChange={(e) => setPkgVendor(e.target.value)} />
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.8rem' }}>
                <div>
                  <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Target OS
                  </label>
                  <select className="glass-select" value={pkgOs} onChange={(e) => setPkgOs(e.target.value as any)}>
                    <option value="windows">Windows</option>
                    <option value="linux">Linux</option>
                    <option value="macos">macOS</option>
                    <option value="any">Cross-Platform</option>
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Installer Engine
                  </label>
                  <select className="glass-select" value={pkgManager} onChange={(e) => setPkgManager(e.target.value as any)}>
                    <option value="winget">Winget</option>
                    <option value="choco">Chocolatey</option>
                    <option value="msi">Custom MSI URL</option>
                    <option value="exe">Custom EXE URL</option>
                    <option value="apt">APT (Debian/Ubuntu)</option>
                    <option value="dnf">DNF (RHEL/Rocky)</option>
                    <option value="brew">Homebrew (macOS)</option>
                    <option value="pkg">Custom PKG URL</option>
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Version
                  </label>
                  <input type="text" className="glass-input" value={pkgVersion} onChange={(e) => setPkgVersion(e.target.value)} />
                </div>
              </div>
              <div>
                <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Package ID or HTTPS Download URL *
                </label>
                <input
                  type="text"
                  required
                  className="glass-input"
                  placeholder="e.g. Tailscale.Tailscale or https://pkgs.vendor.com/agent.msi"
                  value={pkgIdentifier}
                  onChange={(e) => setPkgIdentifier(e.target.value)}
                />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.8rem' }}>
                <div>
                  <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Silent Install Flags
                  </label>
                  <input type="text" className="glass-input" value={pkgInstallArgs} onChange={(e) => setPkgInstallArgs(e.target.value)} />
                </div>
                <div>
                  <label style={{ fontSize: '0.76rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Expected SHA-256 (Optional)
                  </label>
                  <input type="text" className="glass-input" placeholder="64-hex SHA-256" value={pkgSha256} onChange={(e) => setPkgSha256(e.target.value)} />
                </div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button type="button" className="btn-glass" onClick={() => setShowAddPkgModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-glass btn-primary">
                  Save Package
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
