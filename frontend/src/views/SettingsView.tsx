import React, { useState, useEffect, useCallback } from 'react';
import {
  Mail,
  Shield,
  Palette,
  CheckCircle2,
  Send,
  Video,
  KeyRound,
  RefreshCw,
  Clock,
  Users,
  Building,
  Plus,
  Trash2
} from 'lucide-react';
import { Settings, RbacUser, Tenant } from '../types/index.js';
import {
  updateSettings,
  testSmtp,
  syncMeshCentral,
  fetchUsers,
  createUser,
  deleteUser,
  fetchTenants,
  createTenant,
  createSite
} from '../services/api.js';

interface SettingsViewProps {
  settings: Settings;
  onUpdated: (s: Settings) => void;
  onOpenWizard: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ settings, onUpdated, onOpenWizard }) => {
  const [formData, setFormData] = useState<Settings>({ ...settings });
  const [saving, setSaving] = useState(false);
  const [saveBanner, setSaveBanner] = useState<string | null>(null);
  const [smtpTestResult, setSmtpTestResult] = useState<string | null>(null);
  const [testingSmtp, setTestingSmtp] = useState(false);
  const [syncingMesh, setSyncingMesh] = useState(false);
  const [meshSyncResult, setMeshSyncResult] = useState<string | null>(null);

  // RBAC Users & Tenants management state
  const [users, setUsers] = useState<RbacUser[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [newUserEmail, setNewUserEmail] = useState('');
  const [newUserName, setNewUserName] = useState('');
  const [newUserRole, setNewUserRole] = useState<'msp_super_admin' | 'client_admin' | 'senior_tech' | 'support_tech' | 'auditor'>('senior_tech');

  const [newTenantName, setNewTenantName] = useState('');
  const [newTenantContact, setNewTenantContact] = useState('');
  const [newSiteTenantId, setNewSiteTenantId] = useState('ten-1');
  const [newSiteName, setNewSiteName] = useState('');
  const [newSiteSubnet, setNewSiteSubnet] = useState('');

  useEffect(() => {
    setFormData({ ...settings });
  }, [settings]);

  const loadUsersAndTenants = useCallback(() => {
    fetchUsers().then(setUsers).catch(() => {});
    fetchTenants().then(setTenants).catch(() => {});
  }, []);

  useEffect(() => {
    loadUsersAndTenants();
  }, [loadUsersAndTenants]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const res = await updateSettings(formData);
      if (res.success) {
        onUpdated(res.settings);
        setSaveBanner('Settings, White-Labeling, Code Signing & Recording updated successfully!');
        setTimeout(() => setSaveBanner(null), 4000);
      }
    } finally {
      setSaving(false);
    }
  };

  const handleSyncMesh = async () => {
    setSyncingMesh(true);
    setMeshSyncResult(null);
    try {
      const res = await syncMeshCentral();
      if (res.success) {
        const importedCount = res.imported ?? 0;
        const updatedCount = res.updated ?? 0;
        const conflictsCount = (res.conflicts || []).length;
        setMeshSyncResult(
          `Sync Completed: ${importedCount} group(s) imported as Clients, ${updatedCount} client(s) updated. ${
            conflictsCount > 0
              ? `${conflictsCount} conflict alert(s) posted to Notifications.`
              : 'All group memberships matched perfectly.'
          }`
        );
        loadUsersAndTenants();
      } else {
        setMeshSyncResult('Sync encountered an issue: ' + (res.message || 'Check connection settings'));
      }
    } catch {
      setMeshSyncResult('Sync failed. Please verify MeshCentral URL and API token.');
    } finally {
      setSyncingMesh(false);
    }
  };

  const handleTestSmtp = async () => {
    setTestingSmtp(true);
    try {
      const res = await testSmtp({
        host: formData.smtp_host,
        port: formData.smtp_port,
        user: formData.smtp_user,
        pass: formData.smtp_pass,
        from: formData.smtp_from
      });
      setSmtpTestResult(res.message);
    } finally {
      setTestingSmtp(false);
    }
  };

  const handleAddUser = async () => {
    if (!newUserEmail.trim() || !newUserName.trim()) return;
    await createUser({
      username: newUserName.trim(),
      email: newUserEmail.trim(),
      role: newUserRole
    });
    setNewUserEmail('');
    setNewUserName('');
    loadUsersAndTenants();
  };

  const handleDeleteUser = async (id: string) => {
    await deleteUser(id);
    loadUsersAndTenants();
  };

  const handleAddTenant = async () => {
    if (!newTenantName.trim()) return;
    await createTenant({
      name: newTenantName.trim(),
      contact_email: newTenantContact.trim() || `it@${newTenantName.trim().toLowerCase().replace(/[^a-z0-9]/g, '')}.com`
    });
    setNewTenantName('');
    setNewTenantContact('');
    loadUsersAndTenants();
  };

  const handleAddSite = async () => {
    if (!newSiteName.trim()) return;
    await createSite({
      tenant_id: newSiteTenantId,
      name: newSiteName.trim(),
      subnet: newSiteSubnet.trim() || '10.50.0.0/24'
    });
    setNewSiteName('');
    setNewSiteSubnet('');
    loadUsersAndTenants();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="settings-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
            System Settings, RBAC &amp; White-Labeling
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Configure global branding, RBAC technicians, Client tenants, Code Signing HSM API, Session Recording, and MeshCentral 2 link
          </span>
        </div>
        <button className="btn-glass btn-primary" onClick={onOpenWizard}>
          Launch Onboarding Wizard
        </button>
      </div>

      {saveBanner && (
        <div
          className="glass-card"
          style={{
            padding: '0.85rem 1.25rem',
            background: 'rgba(16, 185, 129, 0.12)',
            borderColor: 'rgba(16, 185, 129, 0.35)',
            color: '#34d399',
            fontSize: '0.85rem',
            fontWeight: 500
          }}
        >
          ✓ {saveBanner}
        </div>
      )}

      {/* RBAC Technician Management & Client Tenants */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        {/* RBAC Technicians */}
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <Users size={20} color="var(--primary)" />
            <div>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 600, margin: 0 }}>Role-Based Access Control (RBAC)</h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Manage technician tiers and MFA status</span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <input
              type="text"
              className="glass-input"
              style={{ flex: 1, minWidth: '120px', fontSize: '0.78rem' }}
              placeholder="Full Name"
              value={newUserName}
              onChange={(e) => setNewUserName(e.target.value)}
            />
            <input
              type="email"
              className="glass-input"
              style={{ flex: 1, minWidth: '140px', fontSize: '0.78rem' }}
              placeholder="Email Address"
              value={newUserEmail}
              onChange={(e) => setNewUserEmail(e.target.value)}
            />
            <select
              className="glass-select"
              style={{ width: 'auto', fontSize: '0.78rem' }}
              value={newUserRole}
              onChange={(e) => setNewUserRole(e.target.value as 'msp_super_admin' | 'client_admin' | 'senior_tech' | 'support_tech' | 'auditor')}
            >
              <option value="senior_tech">Senior Tech</option>
              <option value="support_tech">Support Tech</option>
              <option value="msp_super_admin">MSP Super Admin</option>
              <option value="client_admin">Client Admin</option>
              <option value="auditor">Auditor</option>
            </select>
            <button type="button" className="btn-glass btn-primary" style={{ fontSize: '0.78rem' }} onClick={handleAddUser}>
              <Plus size={14} /> Add
            </button>
          </div>

          <div className="table-wrapper">
            <table className="glass-table">
              <thead>
                <tr>
                  <th>Name / Email</th>
                  <th>Role</th>
                  <th>Scope</th>
                  <th style={{ textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>
                      <div style={{ fontWeight: 600, fontSize: '0.8rem' }}>{u.username}</div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>{u.email}</div>
                    </td>
                    <td>
                      <span className="status-pill status-reboot" style={{ fontSize: '0.68rem' }}>
                        {u.role}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: '0.72rem', color: '#10b981' }}>
                        {u.tenant_name || 'Global MSP'}
                      </span>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      {u.id !== 'usr-1' && (
                        <button
                          type="button"
                          className="btn-glass btn-icon"
                          onClick={() => handleDeleteUser(u.id)}
                          title="Remove Technician"
                        >
                          <Trash2 size={13} color="#ef4444" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Client Tenants & Sites Management */}
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <Building size={20} color="#f59e0b" />
            <div>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 600, margin: 0 }}>Client Tenants &amp; Branch Sites</h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Create multi-tenant organizations and branch subnets</span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <input
              type="text"
              className="glass-input"
              style={{ flex: 1, fontSize: '0.78rem' }}
              placeholder="New Client Organization Name"
              value={newTenantName}
              onChange={(e) => setNewTenantName(e.target.value)}
            />
            <input
              type="email"
              className="glass-input"
              style={{ flex: 1, fontSize: '0.78rem' }}
              placeholder="Primary Contact Email"
              value={newTenantContact}
              onChange={(e) => setNewTenantContact(e.target.value)}
            />
            <button type="button" className="btn-glass btn-primary" style={{ fontSize: '0.78rem' }} onClick={handleAddTenant}>
              <Plus size={14} /> Client
            </button>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <select
              className="glass-select"
              style={{ flex: 1, fontSize: '0.78rem' }}
              value={newSiteTenantId}
              onChange={(e) => setNewSiteTenantId(e.target.value)}
            >
              {tenants.map((t) => (
                <option key={t.id} value={t.id}>{t.name}</option>
              ))}
            </select>
            <input
              type="text"
              className="glass-input"
              style={{ flex: 1, fontSize: '0.78rem' }}
              placeholder="New Site Name"
              value={newSiteName}
              onChange={(e) => setNewSiteName(e.target.value)}
            />
            <input
              type="text"
              className="glass-input"
              style={{ width: '130px', fontSize: '0.78rem' }}
              placeholder="Subnet CIDR"
              value={newSiteSubnet}
              onChange={(e) => setNewSiteSubnet(e.target.value)}
            />
            <button type="button" className="btn-glass" style={{ fontSize: '0.78rem' }} onClick={handleAddSite}>
              <Plus size={14} /> Site
            </button>
          </div>

          <div style={{ maxHeight: '190px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
            {tenants.map((t) => (
              <div
                key={t.id}
                style={{
                  padding: '0.55rem 0.85rem',
                  borderRadius: '6px',
                  background: 'rgba(255,255,255,0.03)',
                  border: '1px solid var(--glass-border)',
                  fontSize: '0.78rem'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 600 }}>
                  <span>{t.name}</span>
                  <span style={{ color: 'var(--primary)' }}>{t.device_count} devices</span>
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>
                  Sites: {(t.sites || []).map((s) => `${s.name} (${s.subnet})`).join(' • ') || 'None'}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {/* White-Labeling Card */}
        <div className="glass-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1.25rem' }}>
            <Palette size={20} color="var(--primary)" />
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Global White-Labeling &amp; Branding</h3>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
            <div className="form-group">
              <label className="form-label">Brand Name</label>
              <input
                type="text"
                className="glass-input"
                value={formData.brand_name || ''}
                onChange={(e) => setFormData({ ...formData, brand_name: e.target.value })}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Custom Domain Routing</label>
              <input
                type="text"
                className="glass-input"
                value={formData.custom_domain || ''}
                onChange={(e) => setFormData({ ...formData, custom_domain: e.target.value })}
              />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
            <div className="form-group">
              <label className="form-label">Primary Theme Accent (Hex)</label>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <input
                  type="color"
                  value={formData.primary_color || '#00f2fe'}
                  onChange={(e) => setFormData({ ...formData, primary_color: e.target.value })}
                  style={{ width: '40px', height: '36px', borderRadius: '6px', border: 'none', background: 'transparent', cursor: 'pointer' }}
                />
                <input
                  type="text"
                  className="glass-input"
                  value={formData.primary_color || '#00f2fe'}
                  onChange={(e) => setFormData({ ...formData, primary_color: e.target.value })}
                />
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">Glassmorphic Blur Preset</label>
              <select
                className="glass-select"
                value={formData.glass_blur_level || 'high'}
                onChange={(e) => setFormData({ ...formData, glass_blur_level: e.target.value })}
              >
                <option value="high">High Specular (16px Blur)</option>
                <option value="medium">Medium Frosted (10px Blur)</option>
                <option value="low">Subtle Minimalist (4px Blur)</option>
              </select>
            </div>
          </div>
        </div>

        {/* Code Signing API Card */}
        <div className="glass-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1.25rem' }}>
            <KeyRound size={20} color="var(--primary)" />
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Windows Authenticode &amp; Code Signing API</h3>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Automates EV/OV code signing of generated agent EXEs, PowerShell companion runbooks, and .NET assemblies via Cloud HSM or SignPath.
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div className="form-group">
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.88rem', fontWeight: 600, color: '#fff' }}>
                <input
                  type="checkbox"
                  checked={(formData.code_signing_enabled ?? 1) !== 0}
                  onChange={(e) => setFormData({ ...formData, code_signing_enabled: e.target.checked ? 1 : 0 })}
                />
                <span>Enable Automated Code Signing Pipeline</span>
              </label>
            </div>

            <div className="form-group">
              <label className="form-label">Code Signing Webhook / API URL</label>
              <input
                type="text"
                className="glass-input"
                placeholder="http://10.10.10.20:5000/sign or https://app.signpath.io/api/v1/..."
                value={formData.code_signing_url || ''}
                onChange={(e) => setFormData({ ...formData, code_signing_url: e.target.value })}
              />
              <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.35rem', display: 'block' }}>
                Submits payloads with Authenticode SHA256 signatures and RFC 3161 timestamps to prevent SmartScreen/AV blocks.
              </span>
            </div>

            <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--glass-border)', padding: '0.85rem 1rem', borderRadius: '8px', display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
              <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)' }}>SIGNING TARGET SCOPE</span>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.75rem' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem' }}>
                  <input
                    type="checkbox"
                    checked={(formData.code_signing_sign_agents ?? 1) !== 0}
                    onChange={(e) => setFormData({ ...formData, code_signing_sign_agents: e.target.checked ? 1 : 0 })}
                  />
                  <span>MeshAgent Binaries &amp; EXEs</span>
                </label>

                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem' }}>
                  <input
                    type="checkbox"
                    checked={(formData.code_signing_sign_scripts ?? 1) !== 0}
                    onChange={(e) => setFormData({ ...formData, code_signing_sign_scripts: e.target.checked ? 1 : 0 })}
                  />
                  <span>PowerShell (.ps1) Runbooks</span>
                </label>

                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem' }}>
                  <input
                    type="checkbox"
                    checked={(formData.code_signing_sign_assemblies ?? 1) !== 0}
                    onChange={(e) => setFormData({ ...formData, code_signing_sign_assemblies: e.target.checked ? 1 : 0 })}
                  />
                  <span>.NET GUI Tray Assemblies</span>
                </label>
              </div>
            </div>
          </div>
        </div>

        {/* Session Recording & Audit Vault Card */}
        <div className="glass-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1.25rem' }}>
            <Video size={20} color="var(--primary)" />
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Server-Side Session Recording &amp; Audit Vault</h3>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Automatically records interactive remote desktop control and background terminal sessions for compliance and technician auditability.
              </p>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem', marginBottom: '1rem' }}>
            <div className="form-group">
              <label className="form-label">Automatic Session Recording</label>
              <select
                className="glass-select"
                value={formData.session_recording_enabled ? 'enabled' : 'disabled'}
                onChange={(e) => setFormData({ ...formData, session_recording_enabled: e.target.value === 'enabled' ? 1 : 0 })}
              >
                <option value="enabled">Enabled (Record all remote sessions)</option>
                <option value="disabled">Disabled (Manual trigger only)</option>
              </select>
            </div>

            <div className="form-group">
              <label className="form-label">Retention Policy (Days)</label>
              <select
                className="glass-select"
                value={formData.session_recording_retention_days || 90}
                onChange={(e) => setFormData({ ...formData, session_recording_retention_days: parseInt(e.target.value, 10) })}
              >
                <option value={30}>30 Days (Standard)</option>
                <option value={90}>90 Days (HIPAA / SOC2 Recommended)</option>
                <option value={180}>180 Days (Extended)</option>
                <option value={365}>365 Days (1 Year Compliance Archive)</option>
              </select>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem', marginBottom: '1rem' }}>
            <div className="form-group">
              <label className="form-label">Encoding Quality &amp; Compression</label>
              <select
                className="glass-select"
                value={formData.session_recording_quality || '720p_balanced'}
                onChange={(e) => setFormData({ ...formData, session_recording_quality: e.target.value })}
              >
                <option value="1080p_high">1080p 60fps (High Fidelity, ~8 MB/min)</option>
                <option value="720p_balanced">720p 30fps VP8 (Balanced, ~3 MB/min - Recommended)</option>
                <option value="480p_compact">480p Low Bitrate Compact (~1 MB/min)</option>
              </select>
            </div>

            <div className="form-group">
              <label className="form-label">Endpoint Recording Visual Sign</label>
              <select
                className="glass-select"
                value={(formData.session_recording_visual_indicator ?? 1) !== 0 ? 'visible' : 'stealth'}
                onChange={(e) => setFormData({ ...formData, session_recording_visual_indicator: e.target.value === 'visible' ? 1 : 0 })}
              >
                <option value="stealth">Stealth / Silent (No visual sign of recording on endpoint)</option>
                <option value="visible">Visible Badge (Display non-intrusive recording HUD)</option>
              </select>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.25rem', display: 'block' }}>
                When set to Stealth, sessions are captured silently without banners, yellow screen borders, or tray notifications.
              </span>
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Technician WebUI Recording Visibility</label>
            <select
              className="glass-select"
              value={formData.session_recording_stealth_for_techs ? 'hidden' : 'visible'}
              onChange={(e) => setFormData({ ...formData, session_recording_stealth_for_techs: e.target.value === 'hidden' ? 1 : 0 })}
            >
              <option value="visible">Visible Marker (Techs see recording indicator in WebUI viewer)</option>
              <option value="hidden">Stealth to Technicians (Recording marker hidden from tech WebUI; admins only)</option>
            </select>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.25rem', display: 'block' }}>
              When set to Stealth, technicians will not see any indicator that automated server-side compliance recording is active.
            </span>
          </div>
        </div>

        {/* Agent Installer RBAC & PSA Ticket Locking */}
        <div className="glass-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1.25rem' }}>
            <Shield size={20} color="var(--primary)" />
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Agent Installer Downloads &amp; PSA Ticket Enforcement</h3>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Lock down installer generation to authorized technician tiers and require ticket numbers for audit traceability.
              </p>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
            <div className="form-group">
              <label className="form-label">Minimum Role to Download Installers</label>
              <select
                className="glass-select"
                value={formData.installer_download_role || 'technician'}
                onChange={(e) => setFormData({ ...formData, installer_download_role: e.target.value })}
              >
                <option value="technician">Technician+ (All Staff)</option>
                <option value="admin">MSP Super Admin Only</option>
              </select>
            </div>

            <div className="form-group">
              <label className="form-label">Require PSA / ITFlow Ticket # for Download</label>
              <select
                className="glass-select"
                value={formData.installer_require_ticket ? 'required' : 'optional'}
                onChange={(e) => setFormData({ ...formData, installer_require_ticket: e.target.value === 'required' ? 1 : 0 })}
              >
                <option value="optional">Optional (Direct Download Allowed)</option>
                <option value="required">Strictly Enforced (Must provide valid PSA ticket #)</option>
              </select>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.25rem', display: 'block' }}>
                Vitrine adds an audit note to the ticket upon download, and posts a follow-up with device name &amp; URL upon check-in.
              </span>
            </div>
          </div>
        </div>

        {/* Fleet Maintenance Mode Safety */}
        <div className="glass-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1.25rem' }}>
            <Clock size={20} color="#f59e0b" />
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Fleet Maintenance Mode Auto-Clear Safety</h3>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Prevents servers or workstations from being left indefinitely in unmonitored maintenance mode if a technician forgets to clear it.
              </p>
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Maximum Online Duration Before Auto-Clearing Maintenance</label>
            <select
              className="glass-select"
              value={formData.maintenance_auto_clear_hours || 24}
              onChange={(e) => setFormData({ ...formData, maintenance_auto_clear_hours: parseInt(e.target.value, 10) })}
            >
              <option value={12}>12 Hours Online</option>
              <option value={24}>24 Hours Online (Recommended Default)</option>
              <option value={48}>48 Hours Online (2 Days)</option>
              <option value={72}>72 Hours Online (3 Days)</option>
            </select>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.25rem', display: 'block' }}>
              If a device has been online for this duration without an active preset timeout, Vitrine automatically reverts maintenance mode and re-engages watchdogs.
            </span>
          </div>
        </div>

        {/* MeshCentral Bi-Directional Sync Card */}
        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <Shield size={20} color="var(--primary)" />
              <div>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0 }}>
                  MeshCentral 2 Bi-Directional Sync &amp; Agent Matching
                </h3>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: '0.2rem 0 0 0' }}>
                  Bi-directional mirroring of MeshCentral Device Groups &harr; Vitrine Clients with automated endpoint membership alignment
                </p>
              </div>
            </div>

            <button
              type="button"
              className="btn-glass"
              onClick={handleSyncMesh}
              disabled={syncingMesh}
              style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '0.8rem' }}
            >
              <RefreshCw size={14} className={syncingMesh ? 'spin' : ''} />
              <span>{syncingMesh ? 'Syncing with MeshCentral...' : 'Synchronize MeshCentral Now'}</span>
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.25rem', marginBottom: '1.25rem' }}>
            <div className="form-group">
              <label className="form-label">MeshCentral Server URL</label>
              <input
                type="text"
                className="glass-input"
                value={formData.meshcentral_url || ''}
                onChange={(e) => setFormData({ ...formData, meshcentral_url: e.target.value })}
              />
            </div>

            <div className="form-group">
              <label className="form-label">API Key / Token</label>
              <input
                type="password"
                className="glass-input"
                placeholder="••••••••••••••••"
                value={formData.meshcentral_api_token || ''}
                onChange={(e) => setFormData({ ...formData, meshcentral_api_token: e.target.value })}
              />
            </div>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--glass-border)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.85rem' }}>
              <input
                type="checkbox"
                checked={Boolean(formData.mesh_sync_enabled)}
                onChange={(e) => setFormData({ ...formData, mesh_sync_enabled: e.target.checked ? 1 : 0 })}
              />
              <span style={{ fontWeight: 600 }}>Enable Continuous Bi-Directional Group &amp; Client Sync</span>
            </label>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
              <div className="form-group">
                <label className="form-label">Client Deletion Policy (Vitrine Side)</label>
                <select
                  className="glass-select"
                  value={formData.mesh_client_delete_action || 'move_to_unassigned'}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      mesh_client_delete_action: e.target.value as 'uninstall' | 'move_to_unassigned'
                    })
                  }
                >
                  <option value="move_to_unassigned">Move endpoints to Unassigned holding group (Safe - Recommended)</option>
                  <option value="uninstall">Mass uninstall Vitrine &amp; MeshCentral agents from endpoints (Destructive)</option>
                </select>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.25rem', display: 'block' }}>
                  Decides whether deleting a Client in Vitrine mass uninstalls agents or saves endpoints in holding.
                </span>
              </div>

              <div className="form-group">
                <label className="form-label">External MeshCentral Group Deletion Action</label>
                <select
                  className="glass-select"
                  value={formData.mesh_external_delete_prompt || 'prompt'}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      mesh_external_delete_prompt: e.target.value as 'prompt' | 'auto_unassigned'
                    })
                  }
                >
                  <option value="prompt">Prompt Admins via Notification System &amp; Email Alert (Default)</option>
                  <option value="auto_unassigned">Automatically migrate endpoints to Unassigned group without prompt</option>
                </select>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.25rem', display: 'block' }}>
                  When a group is removed directly inside MeshCentral, Vitrine alerts admins to decide endpoint handling.
                </span>
              </div>
            </div>
          </div>

          {meshSyncResult && (
            <div style={{ background: 'rgba(0, 242, 254, 0.1)', border: '1px solid rgba(0, 242, 254, 0.3)', padding: '0.75rem 1rem', borderRadius: '6px', fontSize: '0.8rem', color: '#7dd3fc', marginTop: '1rem' }}>
              {meshSyncResult}
            </div>
          )}
        </div>

        {/* Outbound SMTP Notifications Card */}
        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <Mail size={20} color="var(--primary)" />
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Outbound SMTP &amp; Alert Routing</h3>
            </div>
            <button type="button" className="btn-glass" onClick={handleTestSmtp} disabled={testingSmtp}>
              <Send size={14} /> Send Test Dispatch
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.25rem' }}>
            <div className="form-group">
              <label className="form-label">SMTP Host</label>
              <input
                type="text"
                className="glass-input"
                value={formData.smtp_host || ''}
                onChange={(e) => setFormData({ ...formData, smtp_host: e.target.value })}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Port</label>
              <input
                type="number"
                className="glass-input"
                value={formData.smtp_port || 587}
                onChange={(e) => setFormData({ ...formData, smtp_port: parseInt(e.target.value, 10) })}
              />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
            <div className="form-group">
              <label className="form-label">Username</label>
              <input
                type="text"
                className="glass-input"
                value={formData.smtp_user || ''}
                onChange={(e) => setFormData({ ...formData, smtp_user: e.target.value })}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Password</label>
              <input
                type="password"
                className="glass-input"
                value={formData.smtp_pass || ''}
                onChange={(e) => setFormData({ ...formData, smtp_pass: e.target.value })}
              />
            </div>
          </div>

          {smtpTestResult && (
            <div style={{ background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.3)', padding: '0.75rem 1rem', borderRadius: '6px', fontSize: '0.8rem', color: '#34d399' }}>
              {smtpTestResult}
            </div>
          )}
        </div>

        {/* Save Button */}
        <div>
          <button type="submit" className="btn-glass btn-primary" style={{ padding: '0.75rem 1.75rem' }} disabled={saving}>
            <CheckCircle2 size={16} /> Save All Changes
          </button>
        </div>
      </form>
    </div>
  );
};
