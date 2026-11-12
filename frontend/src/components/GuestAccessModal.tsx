import React, { useState, useEffect } from 'react';
import {
  X,
  Shield,
  Key,
  Clock,
  UserCheck,
  Laptop,
  CheckCircle2,
  Copy,
  ExternalLink,
  Ban
} from 'lucide-react';
import { Device, GuestAccessGrant } from '../types/index.js';
import { fetchGuestGrants, createGuestGrant, revokeGuestGrant } from '../services/api.js';

interface GuestAccessModalProps {
  devices: Device[];
  onClose: () => void;
}

export const GuestAccessModal: React.FC<GuestAccessModalProps> = ({ devices, onClose }) => {
  const [activeTab, setActiveTab] = useState<'list' | 'create'>('list');
  const [grants, setGrants] = useState<GuestAccessGrant[]>([]);
  const [loading, setLoading] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Form state
  const [vendorName, setVendorName] = useState('');
  const [contactEmail, setContactEmail] = useState('');
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<string[]>([]);
  const [durationHours, setDurationHours] = useState<number>(4);

  // Permissions state
  const [canRemoteScreen, setCanRemoteScreen] = useState(true);
  const [canGhostSession, setCanGhostSession] = useState(false);
  const [canViewTelemetry, setCanViewTelemetry] = useState(true);
  const [canViewHardware, setCanViewHardware] = useState(true);
  const [canViewCustomFields, setCanViewCustomFields] = useState(false);
  const [canRunScripts, setCanRunScripts] = useState(false);

  // Result state after creation
  const [createdResult, setCreatedResult] = useState<{
    id: string;
    tempUsername: string;
    tempPassword: string;
    expiresAt: string;
    portalUrl: string;
  } | null>(null);

  const loadGrants = async () => {
    setLoading(true);
    try {
      const data = await fetchGuestGrants();
      if (Array.isArray(data)) {
        setGrants(data);
      }
    } catch (err) {
      console.error('Failed to load guest grants:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadGrants();
  }, []);

  const handleDeviceToggle = (devId: string) => {
    setSelectedDeviceIds(prev =>
      prev.includes(devId) ? prev.filter(id => id !== devId) : [...prev, devId]
    );
  };

  const handleSelectAllDevices = () => {
    if (selectedDeviceIds.length === devices.length) {
      setSelectedDeviceIds([]);
    } else {
      setSelectedDeviceIds(devices.map(d => d.id));
    }
  };

  const handleCreateGrant = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!vendorName.trim()) {
      alert('Please specify the vendor or guest name.');
      return;
    }
    if (selectedDeviceIds.length === 0) {
      alert('Please select at least one endpoint for this vendor session.');
      return;
    }

    setLoading(true);
    try {
      const res = await createGuestGrant({
        vendor_name: vendorName.trim(),
        contact_email: contactEmail.trim(),
        device_ids: selectedDeviceIds,
        duration_hours: durationHours,
        can_remote_screen: canRemoteScreen,
        can_ghost_session: canGhostSession,
        can_view_telemetry: canViewTelemetry,
        can_view_hardware: canViewHardware,
        can_view_custom_fields: canViewCustomFields,
        can_run_scripts: canRunScripts
      });

      if (res.success && res.id && res.tempUsername && res.tempPassword && res.expiresAt && res.portalUrl) {
        const resolvedUrl = res.portalUrl.startsWith('http')
          ? res.portalUrl
          : `${window.location.origin}${res.portalUrl}`;
        setCreatedResult({
          id: res.id,
          tempUsername: res.tempUsername,
          tempPassword: res.tempPassword,
          expiresAt: res.expiresAt,
          portalUrl: resolvedUrl
        });
        loadGrants();
      } else {
        alert(`Failed to issue guest pass: ${res.error || 'Unknown error'}`);
      }
    } catch (err: unknown) {
      alert(`Error creating grant: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  };

  const handleRevoke = async (id: string) => {
    if (!confirm('Are you sure you want to immediately terminate and revoke this vendor access pass?')) return;
    try {
      await revokeGuestGrant(id);
      loadGrants();
    } catch (err: unknown) {
      alert(`Failed to revoke grant: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2500);
  };

  return (
    <div className="modal-backdrop">
      <div className="glass-modal" style={{ maxWidth: '850px', width: '95%' }}>
        {/* Header */}
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div
              style={{
                width: '38px',
                height: '38px',
                borderRadius: '8px',
                background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.2), rgba(168, 85, 247, 0.2))',
                border: '1px solid rgba(168, 85, 247, 0.4)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#c084fc'
              }}
            >
              <UserCheck size={20} />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 600 }}>Vendor & Guest Session Access</h3>
              <p style={{ margin: 0, fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Issue time-bound, permission-scoped credentials and isolated portals for third-party technicians
              </p>
            </div>
          </div>
          <button className="btn-glass btn-icon" onClick={onClose} id="btn-close-guest-modal">
            <X size={18} />
          </button>
        </div>

        {/* Tab Switcher */}
        <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid var(--glass-border)', padding: '0.5rem 1.5rem 0' }}>
          <button
            className={`btn-glass ${activeTab === 'list' ? 'btn-primary' : ''}`}
            onClick={() => { setActiveTab('list'); setCreatedResult(null); }}
            style={{
              padding: '0.6rem 1rem',
              borderBottom: activeTab === 'list' ? '2px solid var(--primary)' : '2px solid transparent',
              borderRadius: '6px 6px 0 0',
              fontWeight: 600
            }}
          >
            Active Vendor Passes ({grants.filter(g => g.status === 'active' && new Date(g.expires_at).getTime() > Date.now()).length})
          </button>
          <button
            className={`btn-glass ${activeTab === 'create' ? 'btn-primary' : ''}`}
            onClick={() => { setActiveTab('create'); setCreatedResult(null); }}
            style={{
              padding: '0.6rem 1rem',
              borderBottom: activeTab === 'create' ? '2px solid var(--primary)' : '2px solid transparent',
              borderRadius: '6px 6px 0 0',
              fontWeight: 600
            }}
          >
            + Issue New Temporary Pass
          </button>
        </div>

        {/* Modal Body */}
        <div className="modal-body" style={{ maxHeight: '70vh', overflowY: 'auto', padding: '1.5rem' }}>
          {activeTab === 'list' && (
            <div>
              {loading && grants.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
                  Loading vendor sessions...
                </div>
              ) : grants.length === 0 ? (
                <div
                  style={{
                    textAlign: 'center',
                    padding: '3rem 1rem',
                    background: 'rgba(255, 255, 255, 0.02)',
                    borderRadius: '12px',
                    border: '1px dashed var(--glass-border)'
                  }}
                >
                  <Key size={36} style={{ color: 'var(--text-muted)', marginBottom: '0.75rem', opacity: 0.5 }} />
                  <h4 style={{ margin: 0, fontSize: '1rem', color: 'var(--text-main)' }}>No Active Vendor Passes</h4>
                  <p style={{ margin: '0.5rem 0 1.25rem', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                    Grant temporary, audited remote desktop or telemetry access to external software vendors without sharing technician logins.
                  </p>
                  <button className="btn-glass btn-primary" onClick={() => setActiveTab('create')}>
                    Issue First Vendor Pass
                  </button>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  {grants.map((grant) => {
                    const isExpired = new Date(grant.expires_at).getTime() < Date.now();
                    const isRevoked = grant.status === 'revoked';
                    const isActive = !isExpired && !isRevoked;
                    const grantWithJson = grant as GuestAccessGrant & { device_ids_json?: string };
                    const deviceIds: string[] = Array.isArray(grant.device_ids)
                      ? grant.device_ids
                      : JSON.parse(grantWithJson.device_ids_json || '[]');

                    return (
                      <div
                        key={grant.id}
                        style={{
                          background: 'rgba(255, 255, 255, 0.03)',
                          border: `1px solid ${isActive ? 'rgba(99, 102, 241, 0.3)' : 'var(--glass-border)'}`,
                          borderRadius: '10px',
                          padding: '1.25rem',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '0.85rem'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.5rem' }}>
                          <div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                              <h4 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 600 }}>{grant.vendor_name}</h4>
                              {isActive ? (
                                <span className="status-pill status-online">
                                  Active Session
                                </span>
                              ) : isRevoked ? (
                                <span className="status-pill status-isolated">
                                  Revoked
                                </span>
                              ) : (
                                <span className="status-pill status-offline">
                                  Expired
                                </span>
                              )}
                            </div>
                            {grant.contact_email && (
                              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                                Contact: {grant.contact_email}
                              </div>
                            )}
                          </div>

                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            {isActive && (
                              <button
                                className="btn-glass"
                                style={{ color: '#ef4444', borderColor: 'rgba(239, 68, 68, 0.3)', fontSize: '0.8rem', padding: '0.35rem 0.65rem' }}
                                onClick={() => handleRevoke(grant.id)}
                                title="Instantly kill active sessions and invalidate credentials"
                              >
                                <Ban size={14} /> Revoke
                              </button>
                            )}
                            <button
                              className="btn-glass"
                              style={{ fontSize: '0.8rem', padding: '0.35rem 0.65rem' }}
                              onClick={() => copyToClipboard(`${window.location.origin}/guest/${grant.id}`, `link-${grant.id}`)}
                            >
                              {copiedId === `link-${grant.id}` ? <CheckCircle2 size={14} color="#34d399" /> : <Copy size={14} />}
                              <span>{copiedId === `link-${grant.id}` ? 'Copied' : 'Copy Link'}</span>
                            </button>
                            <a
                              href={`/guest/${grant.id}`}
                              target="_blank"
                              rel="noreferrer"
                              className="btn-glass"
                              style={{ fontSize: '0.8rem', padding: '0.35rem 0.65rem' }}
                              title="Open Vendor Portal"
                            >
                              <ExternalLink size={14} />
                            </a>
                          </div>
                        </div>

                        {/* Grant Details Bar */}
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem', fontSize: '0.8rem', background: 'rgba(0, 0, 0, 0.2)', padding: '0.75rem', borderRadius: '6px' }}>
                          <div>
                            <div style={{ color: 'var(--text-muted)' }}>Temporary Username</div>
                            <div style={{ fontWeight: 600, fontFamily: 'monospace', color: '#818cf8' }}>{grant.temp_username}</div>
                          </div>
                          <div>
                            <div style={{ color: 'var(--text-muted)' }}>Assigned Endpoints</div>
                            <div style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                              <Laptop size={14} /> {deviceIds.length} Device{deviceIds.length === 1 ? '' : 's'}
                            </div>
                          </div>
                          <div>
                            <div style={{ color: 'var(--text-muted)' }}>Expires At</div>
                            <div style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.35rem', color: isActive ? '#f59e0b' : 'var(--text-muted)' }}>
                              <Clock size={14} /> {new Date(grant.expires_at).toLocaleString()}
                            </div>
                          </div>
                        </div>

                        {/* Scoped Permissions Pills */}
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', fontSize: '0.75rem' }}>
                          <span style={{ color: 'var(--text-muted)', marginRight: '0.25rem', display: 'flex', alignItems: 'center' }}>
                            Allowed Tools:
                          </span>
                          {grant.can_remote_screen ? (
                            <span style={{ background: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa', padding: '0.15rem 0.5rem', borderRadius: '4px' }}>
                              Interactive Screen
                            </span>
                          ) : null}
                          {grant.can_ghost_session ? (
                            <span style={{ background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc', padding: '0.15rem 0.5rem', borderRadius: '4px' }}>
                              Ghost Desktop
                            </span>
                          ) : null}
                          {grant.can_view_telemetry ? (
                            <span style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#34d399', padding: '0.15rem 0.5rem', borderRadius: '4px' }}>
                              Live Telemetry
                            </span>
                          ) : null}
                          {grant.can_view_hardware ? (
                            <span style={{ background: 'rgba(234, 179, 8, 0.15)', color: '#facc15', padding: '0.15rem 0.5rem', borderRadius: '4px' }}>
                              Hardware Specs
                            </span>
                          ) : null}
                          {grant.can_view_custom_fields ? (
                            <span style={{ background: 'rgba(99, 102, 241, 0.15)', color: '#818cf8', padding: '0.15rem 0.5rem', borderRadius: '4px' }}>
                              Custom Attributes
                            </span>
                          ) : null}
                          {grant.can_run_scripts ? (
                            <span style={{ background: 'rgba(239, 68, 68, 0.15)', color: '#f87171', padding: '0.15rem 0.5rem', borderRadius: '4px' }}>
                              Script Execution
                            </span>
                          ) : null}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {activeTab === 'create' && !createdResult && (
            <form onSubmit={handleCreateGrant} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.4rem' }}>
                    Vendor / Guest Name *
                  </label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="e.g. Sage 300 ERP Support Team"
                    value={vendorName}
                    onChange={(e) => setVendorName(e.target.value)}
                    required
                    style={{ width: '100%' }}
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.4rem' }}>
                    Contact Email (Optional)
                  </label>
                  <input
                    type="email"
                    className="glass-input"
                    placeholder="support@vendor.com"
                    value={contactEmail}
                    onChange={(e) => setContactEmail(e.target.value)}
                    style={{ width: '100%' }}
                  />
                </div>
              </div>

              {/* Expiration Presets */}
              <div>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.4rem' }}>
                  Session Validity Window *
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '0.5rem' }}>
                  {[1, 2, 4, 8, 24].map((hours) => (
                    <button
                      type="button"
                      key={hours}
                      className={`btn-glass ${durationHours === hours ? 'active' : ''}`}
                      onClick={() => setDurationHours(hours)}
                      style={{
                        padding: '0.5rem',
                        fontSize: '0.85rem',
                        textAlign: 'center',
                        borderColor: durationHours === hours ? 'var(--primary)' : 'var(--border-color)',
                        background: durationHours === hours ? 'rgba(99, 102, 241, 0.2)' : 'rgba(255, 255, 255, 0.02)'
                      }}
                    >
                      <Clock size={14} style={{ display: 'inline', marginRight: '4px', verticalAlign: '-2px' }} />
                      {hours} {hours === 1 ? 'Hour' : 'Hours'}
                    </button>
                  ))}
                </div>
              </div>

              {/* Permissions Matrix */}
              <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                  <Shield size={16} color="var(--primary)" />
                  <span style={{ fontSize: '0.9rem', fontWeight: 600 }}>Feature Scoping & Permissions</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={canRemoteScreen}
                      onChange={(e) => setCanRemoteScreen(e.target.checked)}
                    />
                    <span>Remote Screen Control (Interactive)</span>
                  </label>

                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={canGhostSession}
                      onChange={(e) => setCanGhostSession(e.target.checked)}
                    />
                    <span>Ghost Desktop Session (Headless)</span>
                  </label>

                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={canViewTelemetry}
                      onChange={(e) => setCanViewTelemetry(e.target.checked)}
                    />
                    <span>Live Telemetry (CPU / RAM / Disk)</span>
                  </label>

                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={canViewHardware}
                      onChange={(e) => setCanViewHardware(e.target.checked)}
                    />
                    <span>Hardware Specs & Storage Layout</span>
                  </label>

                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={canViewCustomFields}
                      onChange={(e) => setCanViewCustomFields(e.target.checked)}
                    />
                    <span>Custom Attribute Data (Client Metadata)</span>
                  </label>

                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={canRunScripts}
                      onChange={(e) => setCanRunScripts(e.target.checked)}
                    />
                    <span style={{ color: canRunScripts ? '#f87171' : 'inherit' }}>
                      Diagnostic Script Execution (High Privilege)
                    </span>
                  </label>
                </div>
              </div>

              {/* Endpoint Assignment */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <label style={{ fontSize: '0.85rem', fontWeight: 600 }}>
                    Assign Authorized Endpoints ({selectedDeviceIds.length} of {devices.length} selected) *
                  </label>
                  <button
                    type="button"
                    className="btn-glass"
                    onClick={handleSelectAllDevices}
                    style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem' }}
                  >
                    {selectedDeviceIds.length === devices.length ? 'Deselect All' : 'Select All'}
                  </button>
                </div>

                <div
                  style={{
                    maxHeight: '180px',
                    overflowY: 'auto',
                    border: '1px solid var(--glass-border)',
                    borderRadius: '8px',
                    padding: '0.5rem',
                    background: 'rgba(0, 0, 0, 0.2)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.35rem'
                  }}
                >
                  {devices.map((dev) => (
                    <label
                      key={dev.id}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.6rem',
                        padding: '0.4rem 0.6rem',
                        borderRadius: '4px',
                        background: selectedDeviceIds.includes(dev.id) ? 'rgba(99, 102, 241, 0.15)' : 'transparent',
                        cursor: 'pointer',
                        fontSize: '0.85rem'
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={selectedDeviceIds.includes(dev.id)}
                        onChange={() => handleDeviceToggle(dev.id)}
                      />
                      <Laptop size={14} color="var(--primary)" />
                      <span style={{ fontWeight: 600 }}>{dev.hostname}</span>
                      <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>({dev.ip_address} • {dev.os_type} {dev.os_version})</span>
                    </label>
                  ))}
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
                <button type="button" className="btn-glass" onClick={() => setActiveTab('list')}>
                  Cancel
                </button>
                <button type="submit" className="btn-glass btn-primary" disabled={loading}>
                  {loading ? 'Generating Pass...' : 'Issue Vendor Pass & Generate Credentials'}
                </button>
              </div>
            </form>
          )}

          {/* Created Confirmation View */}
          {createdResult && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div
                style={{
                  background: 'rgba(16, 185, 129, 0.1)',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  padding: '1.25rem',
                  borderRadius: '10px',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '0.75rem'
                }}
              >
                <CheckCircle2 size={24} color="#34d399" style={{ flexShrink: 0, marginTop: '2px' }} />
                <div>
                  <h4 style={{ margin: 0, fontSize: '1.05rem', color: '#34d399', fontWeight: 600 }}>
                    Vendor Pass Successfully Generated!
                  </h4>
                  <p style={{ margin: '0.25rem 0 0', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                    Share the magic link or temporary credentials below with the vendor technician. This grant will auto-expire in {durationHours} hours.
                  </p>
                </div>
              </div>

              {/* Direct Portal Magic Link */}
              <div>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.4rem' }}>
                  Direct Vendor Portal Magic Link
                </label>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <input
                    type="text"
                    readOnly
                    className="glass-input"
                    value={createdResult.portalUrl}
                    style={{ width: '100%', fontFamily: 'monospace', fontSize: '0.85rem' }}
                  />
                  <button
                    className="btn-glass"
                    onClick={() => copyToClipboard(createdResult.portalUrl, 'magic-link')}
                  >
                    {copiedId === 'magic-link' ? <CheckCircle2 size={16} color="#34d399" /> : <Copy size={16} />}
                    <span>{copiedId === 'magic-link' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
              </div>

              {/* Temporary Credentials */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div style={{ background: 'rgba(0, 0, 0, 0.25)', padding: '0.75rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Temporary Username</div>
                  <div style={{ fontSize: '1rem', fontFamily: 'monospace', fontWeight: 600, color: '#818cf8', marginTop: '0.25rem' }}>
                    {createdResult.tempUsername}
                  </div>
                </div>

                <div style={{ background: 'rgba(0, 0, 0, 0.25)', padding: '0.75rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Temporary Password</div>
                  <div style={{ fontSize: '1rem', fontFamily: 'monospace', fontWeight: 600, color: '#facc15', marginTop: '0.25rem' }}>
                    {createdResult.tempPassword}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '1rem' }}>
                <button
                  className="btn-glass"
                  onClick={() => {
                    const text = `Vitrine RMM Vendor Session Portal:\nURL: ${createdResult.portalUrl}\nUsername: ${createdResult.tempUsername}\nPassword: ${createdResult.tempPassword}\nExpires: ${new Date(createdResult.expiresAt).toLocaleString()}`;
                    copyToClipboard(text, 'full-creds');
                  }}
                >
                  {copiedId === 'full-creds' ? <CheckCircle2 size={16} color="#34d399" /> : <Copy size={16} />}
                  <span>{copiedId === 'full-creds' ? 'Copied Full Summary' : 'Copy All Details'}</span>
                </button>
                <button
                  className="btn-glass btn-primary"
                  onClick={() => {
                    setCreatedResult(null);
                    setActiveTab('list');
                  }}
                >
                  Done
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
