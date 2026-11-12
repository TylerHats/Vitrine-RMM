import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  Clock,
  Laptop,
  Monitor,
  Activity,
  Lock,
  Terminal,
  KeyRound,
  LogOut
} from 'lucide-react';
import {
  fetchGuestPortalMeta,
  fetchGuestPortal,
  authenticateGuestPortal,
  fetchGuestPortalScripts,
  runGuestPortalScript,
  fetchGuestPortalCustomFields,
  setStoredGuestToken
} from '../services/api.js';
import { Device, ScriptItem } from '../types/index.js';
import { RemoteScreenModal } from '../components/RemoteScreenModal.js';

interface GuestPortalGrant {
  id: string;
  vendor_name: string;
  expires_at: string;
  permissions: Record<string, boolean>;
}

interface GuestPortalViewProps {
  grantId: string;
}

export const GuestPortalView: React.FC<GuestPortalViewProps> = ({ grantId }) => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [meta, setMeta] = useState<{
    vendor_name: string;
    expires_at: string;
    brand_name: string;
    brand_logo_url: string;
    primary_color: string;
    is_expired: boolean;
    status: string;
  } | null>(null);

  const [authRequired, setAuthRequired] = useState(false);
  const [tempUsername, setTempUsername] = useState('');
  const [tempPassword, setTempPassword] = useState('');
  const [authSubmitting, setAuthSubmitting] = useState(false);
  const [credError, setCredError] = useState<string | null>(null);

  const [grant, setGrant] = useState<GuestPortalGrant | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [availableScripts, setAvailableScripts] = useState<ScriptItem[]>([]);
  const [selectedScriptId, setSelectedScriptId] = useState<string>('');
  const [deviceCustomFields, setDeviceCustomFields] = useState<
    Record<string, Array<{ field_id: string; key: string; label: string; category: string; value: string }>>
  >({});

  const [timeRemaining, setTimeRemaining] = useState<string>('');
  const [isExpired, setIsExpired] = useState(false);
  const [scriptOutput, setScriptOutput] = useState<{ deviceId: string; output: string } | null>(null);

  const [activeRemote, setActiveRemote] = useState<{
    open: boolean;
    device: Device | null;
    isGhost: boolean;
  }>({
    open: false,
    device: null,
    isGhost: false
  });

  const loadScopedPortalPayload = useCallback(async () => {
    const res = await fetchGuestPortal(grantId);
    if (res.authRequired) {
      setAuthRequired(true);
      return;
    }
    if (!res.success || !res.grant) {
      setError(res.error || 'Failed to load scoped vendor portal.');
      return;
    }

    setAuthRequired(false);
    setGrant(res.grant as GuestPortalGrant);
    const loadedDevices = res.devices || [];
    setDevices(loadedDevices);

    if (res.grant.permissions?.can_run_scripts) {
      try {
        const scrs = await fetchGuestPortalScripts(grantId);
        setAvailableScripts(scrs);
        if (scrs.length > 0) setSelectedScriptId(scrs[0].id);
      } catch {
        // Ignore script fetch failure if none
      }
    }

    if (res.grant.permissions?.can_view_custom_fields) {
      const cfMap: Record<string, any[]> = {};
      for (const dev of loadedDevices) {
        try {
          cfMap[dev.id] = await fetchGuestPortalCustomFields(grantId, dev.id);
        } catch {
          cfMap[dev.id] = [];
        }
      }
      setDeviceCustomFields(cfMap);
    }
  }, [grantId]);

  useEffect(() => {
    const initialize = async () => {
      setLoading(true);
      setError(null);
      try {
        const metaRes = await fetchGuestPortalMeta(grantId);
        if (metaRes.error) {
          setError(metaRes.error);
          setLoading(false);
          return;
        }
        setMeta(metaRes);
        if (metaRes.is_expired || metaRes.status !== 'active') {
          setIsExpired(true);
          setError('This temporary vendor access grant has expired or been revoked.');
          setLoading(false);
          return;
        }
        await loadScopedPortalPayload();
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : 'Network error connecting to Vitrine Portal');
      } finally {
        setLoading(false);
      }
    };

    initialize();
  }, [grantId, loadScopedPortalPayload]);

  useEffect(() => {
    const expIso = grant?.expires_at || meta?.expires_at;
    if (!expIso) return;

    const updateTimer = () => {
      const diff = new Date(expIso).getTime() - Date.now();
      if (diff <= 0) {
        setTimeRemaining('00:00:00 (Expired)');
        setIsExpired(true);
      } else {
        const hours = Math.floor(diff / 3600000);
        const minutes = Math.floor((diff % 3600000) / 60000);
        const seconds = Math.floor((diff % 60000) / 1000);
        setTimeRemaining(
          `${hours.toString().padStart(2, '0')}h ${minutes.toString().padStart(2, '0')}m ${seconds
            .toString()
            .padStart(2, '0')}s`
        );
      }
    };

    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    return () => clearInterval(interval);
  }, [grant, meta]);

  const handleVerifyVendorCreds = async (e: React.FormEvent) => {
    e.preventDefault();
    setCredError(null);
    setAuthSubmitting(true);
    try {
      const res = await authenticateGuestPortal(grantId, tempUsername.trim(), tempPassword);
      if (res.success) {
        setTempPassword('');
        await loadScopedPortalPayload();
      } else {
        setCredError(res.error || 'Invalid temporary vendor credentials.');
      }
    } catch (err: any) {
      setCredError(err?.message || 'Authentication failed.');
    } finally {
      setAuthSubmitting(false);
    }
  };

  const handleRunVendorDiag = async (device: Device) => {
    if (!selectedScriptId) {
      setScriptOutput({ deviceId: device.id, output: 'No authorized diagnostic script available.' });
      return;
    }
    const res = await runGuestPortalScript(grantId, selectedScriptId, device.id);
    if (res.success) {
      setScriptOutput({
        deviceId: device.id,
        output: res.dispatched
          ? `Authorized script dispatched live to ${device.hostname}.`
          : `Authorized script queued for ${device.hostname}.`
      });
    } else {
      setScriptOutput({
        deviceId: device.id,
        output: `Execution denied: ${res.error || 'Unauthorized'}`
      });
    }
  };
  if (loading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#0a0d14', color: '#f3f4f6' }}>
        <div style={{ textAlign: 'center' }}>
          <div className="pulse-dot" style={{ margin: '0 auto 1rem', width: '16px', height: '16px' }} />
          <h3>Connecting to Scoped Vendor Session...</h3>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Verifying access grant window and cryptographic scope</p>
        </div>
      </div>
    );
  }

  if (error || isExpired) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#0a0d14', padding: '1.5rem' }}>
        <div
          style={{
            maxWidth: '520px',
            width: '100%',
            background: 'rgba(23, 27, 38, 0.85)',
            backdropFilter: 'blur(16px)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: '16px',
            padding: '2.5rem',
            textAlign: 'center',
            boxShadow: '0 20px 40px rgba(0, 0, 0, 0.6)'
          }}
        >
          <div
            style={{
              width: '60px',
              height: '60px',
              borderRadius: '50%',
              background: 'rgba(239, 68, 68, 0.15)',
              border: '1px solid rgba(239, 68, 68, 0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 1.5rem',
              color: '#ef4444'
            }}
          >
            <Lock size={28} />
          </div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 700, margin: '0 0 0.5rem', color: '#f87171' }}>
            Session Expired or Revoked
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', lineHeight: 1.5, margin: '0 0 1.5rem' }}>
            {error || 'This temporary vendor access session has passed its expiration window or has been revoked by the system administrator.'}
          </p>
          <a
            href="/"
            style={{
              display: 'inline-block',
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid var(--glass-border)',
              color: '#f8fafc',
              padding: '0.6rem 1.5rem',
              borderRadius: '8px',
              textDecoration: 'none',
              fontSize: '0.85rem',
              fontWeight: 600
            }}
          >
            Return to Vitrine Portal
          </a>
        </div>
      </div>
    );
  }

  if (authRequired) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'radial-gradient(ellipse at top, #131726, #0a0d14)', color: '#f3f4f6', padding: '1.5rem' }}>
        <div
          style={{
            maxWidth: '460px',
            width: '100%',
            background: 'rgba(23, 27, 38, 0.9)',
            border: '1px solid rgba(99, 102, 241, 0.35)',
            borderRadius: '16px',
            padding: '2.25rem',
            boxShadow: '0 24px 48px rgba(0, 0, 0, 0.55)'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', marginBottom: '1.25rem' }}>
            <div style={{ width: '44px', height: '44px', borderRadius: '10px', background: 'linear-gradient(135deg, #6366f1, #a855f7)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <KeyRound size={22} color="#fff" />
            </div>
            <div>
              <h2 style={{ margin: 0, fontSize: '1.2rem', fontWeight: 700 }}>
                {meta?.brand_name || 'Vitrine'} Vendor Portal
              </h2>
              <div style={{ fontSize: '0.78rem', color: '#9ca3af' }}>
                Authorized Vendor: <strong>{meta?.vendor_name || 'Scoped Guest'}</strong>
              </div>
            </div>
          </div>

          <p style={{ fontSize: '0.84rem', color: '#cbd5e1', lineHeight: 1.5, marginBottom: '1.25rem' }}>
            Enter the temporary vendor username and password issued for this session. Time remaining:{' '}
            <strong style={{ color: '#fbbf24', fontFamily: 'monospace' }}>{timeRemaining}</strong>
          </p>

          {credError && (
            <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.35)', color: '#fca5a5', padding: '0.7rem 0.9rem', borderRadius: '8px', fontSize: '0.8rem', marginBottom: '1rem' }}>
              {credError}
            </div>
          )}

          <form onSubmit={handleVerifyVendorCreds} style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', color: '#cbd5e1', marginBottom: '0.35rem' }}>
                Temporary Username
              </label>
              <input
                type="text"
                required
                className="glass-input"
                placeholder="e.g. vendor-8a2f"
                value={tempUsername}
                onChange={(e) => setTempUsername(e.target.value)}
                autoComplete="username"
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', color: '#cbd5e1', marginBottom: '0.35rem' }}>
                Temporary Password
              </label>
              <input
                type="password"
                required
                className="glass-input"
                placeholder="Enter issued one-time password"
                value={tempPassword}
                onChange={(e) => setTempPassword(e.target.value)}
                autoComplete="current-password"
              />
            </div>
            <button type="submit" className="btn-glass btn-primary" disabled={authSubmitting} style={{ justifyContent: 'center', padding: '0.75rem', fontWeight: 700 }}>
              {authSubmitting ? 'Verifying Credentials...' : 'Unlock Scoped Vendor Portal'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  const perms = grant?.permissions || {
    can_remote_screen: false,
    can_ghost_session: false,
    can_view_telemetry: true,
    can_view_hardware: true,
    can_run_scripts: false,
    can_view_custom_fields: false
  };

  return (
    <div style={{ minHeight: '100vh', background: 'radial-gradient(ellipse at top, #131726, #0a0d14)', color: '#f3f4f6', padding: '2rem 1.5rem' }}>
      <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
        <header
          style={{
            background: 'rgba(23, 27, 38, 0.7)',
            backdropFilter: 'blur(16px)',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: '16px',
            padding: '1.5rem 2rem',
            marginBottom: '2rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '1.25rem'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div style={{ width: '44px', height: '44px', borderRadius: '10px', background: 'linear-gradient(135deg, #6366f1, #a855f7)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff' }}>
              <Shield size={24} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <h1 style={{ margin: 0, fontSize: '1.35rem', fontWeight: 700 }}>Vendor Access Portal</h1>
                <span style={{ background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', border: '1px solid rgba(16, 185, 129, 0.4)', fontSize: '0.72rem', padding: '0.15rem 0.6rem', borderRadius: '12px', fontWeight: 600 }}>
                  Authenticated
                </span>
              </div>
              <p style={{ margin: '0.2rem 0 0', fontSize: '0.85rem', color: '#9ca3af' }}>
                Authorized Vendor: <strong style={{ color: '#e0e7ff' }}>{grant?.vendor_name}</strong>
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.3)', padding: '0.65rem 1.25rem', borderRadius: '12px' }}>
              <Clock size={20} color="#f59e0b" />
              <div>
                <div style={{ fontSize: '0.7rem', color: '#f59e0b', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 700 }}>
                  Time Remaining
                </div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, fontFamily: 'monospace', color: '#fbbf24' }}>
                  {timeRemaining}
                </div>
              </div>
            </div>
            <button
              type="button"
              className="btn-glass"
              onClick={() => {
                setStoredGuestToken(grantId, null);
                setGrant(null);
                setDevices([]);
                setAuthRequired(true);
              }}
              title="Lock Vendor Session"
            >
              <LogOut size={15} />
            </button>
          </div>
        </header>

        <div style={{ background: 'rgba(15, 23, 42, 0.6)', border: '1px solid rgba(255, 255, 255, 0.05)', borderRadius: '12px', padding: '1rem 1.5rem', marginBottom: '2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', color: '#9ca3af', flexWrap: 'wrap' }}>
            <Lock size={15} color="#818cf8" />
            <span>Active Permissions:</span>
            {perms.can_remote_screen && <span style={{ background: 'rgba(59, 130, 246, 0.2)', color: '#93c5fd', padding: '0.15rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem' }}>Remote Screen</span>}
            {perms.can_ghost_session && <span style={{ background: 'rgba(168, 85, 247, 0.2)', color: '#d8b4fe', padding: '0.15rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem' }}>Ghost Desktop</span>}
            {perms.can_view_telemetry && <span style={{ background: 'rgba(16, 185, 129, 0.2)', color: '#6ee7b7', padding: '0.15rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem' }}>Live Telemetry</span>}
            {perms.can_view_hardware && <span style={{ background: 'rgba(234, 179, 8, 0.2)', color: '#fde047', padding: '0.15rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem' }}>Hardware Specs</span>}
            {perms.can_view_custom_fields && <span style={{ background: 'rgba(14, 165, 233, 0.2)', color: '#7dd3fc', padding: '0.15rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem' }}>Custom Fields</span>}
            {perms.can_run_scripts && <span style={{ background: 'rgba(239, 68, 68, 0.2)', color: '#fca5a5', padding: '0.15rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem' }}>Script Execution</span>}
          </div>
          {perms.can_run_scripts && availableScripts.length > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.78rem' }}>
              <span>Diagnostic Script:</span>
              <select className="glass-select" value={selectedScriptId} onChange={(e) => setSelectedScriptId(e.target.value)} style={{ padding: '0.3rem 0.6rem', fontSize: '0.78rem' }}>
                {availableScripts.map((s) => (
                  <option key={s.id} value={s.id}>{s.name}</option>
                ))}
              </select>
            </div>
          )}
        </div>

        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <Laptop size={20} color="#00f2fe" />
            <h2 style={{ margin: 0, fontSize: '1.15rem', fontWeight: 600 }}>
              Authorized Target Endpoints ({devices.length})
            </h2>
          </div>

          {devices.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '3rem', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '12px', border: '1px dashed rgba(255,255,255,0.12)' }}>
              <p style={{ margin: 0, color: '#9ca3af' }}>No devices are currently assigned to this vendor session.</p>
            </div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: '1.25rem' }}>
              {devices.map((device) => {
                const isOnline = device.status === 'online';
                const cFields = deviceCustomFields[device.id] || [];
                return (
                  <div key={device.id} style={{ background: 'rgba(23, 27, 38, 0.75)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '12px', padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <div>
                        <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 600, color: '#f9fafb' }}>{device.hostname}</h3>
                        <div style={{ fontSize: '0.8rem', color: '#9ca3af', marginTop: '0.2rem' }}>
                          {device.os_type} {device.os_version} • {device.ip_address}
                        </div>
                      </div>
                      <span style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem', borderRadius: '4px', background: isOnline ? 'rgba(16, 185, 129, 0.15)' : 'rgba(107, 114, 128, 0.15)', color: isOnline ? '#34d399' : '#9ca3af' }}>
                        {isOnline ? 'Online' : 'Offline'}
                      </span>
                    </div>

                    {perms.can_view_telemetry && (
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.5rem', background: 'rgba(0, 0, 0, 0.25)', padding: '0.75rem', borderRadius: '8px', fontSize: '0.75rem' }}>
                        <div>
                          <div style={{ color: '#9ca3af' }}>CPU Load</div>
                          <div style={{ fontWeight: 700, fontSize: '0.95rem', color: '#60a5fa', marginTop: '0.2rem' }}>{device.cpu_usage || 0}%</div>
                        </div>
                        <div>
                          <div style={{ color: '#9ca3af' }}>Memory</div>
                          <div style={{ fontWeight: 700, fontSize: '0.95rem', color: '#c084fc', marginTop: '0.2rem' }}>{device.ram_total_gb ? Math.round((device.ram_used_gb / device.ram_total_gb) * 100) : 0}%</div>
                        </div>
                        <div>
                          <div style={{ color: '#9ca3af' }}>Disk Used</div>
                          <div style={{ fontWeight: 700, fontSize: '0.95rem', color: '#34d399', marginTop: '0.2rem' }}>{device.disk_total_gb ? Math.round(((device.disk_total_gb - device.disk_free_gb) / device.disk_total_gb) * 100) : 0}%</div>
                        </div>
                      </div>
                    )}

                    {perms.can_view_hardware && (
                      <div style={{ fontSize: '0.75rem', color: '#9ca3af', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                        <div><strong>CPU / Role:</strong> {device.cpu_model || 'Standard Endpoint'} • {device.device_role}</div>
                        <div><strong>Serial / BIOS:</strong> {device.serial_number || 'N/A'} • {device.bios_version || 'UEFI'}</div>
                      </div>
                    )}

                    {perms.can_view_custom_fields && cFields.length > 0 && (
                      <div style={{ fontSize: '0.74rem', color: '#cbd5e1', background: 'rgba(255,255,255,0.03)', padding: '0.55rem 0.75rem', borderRadius: '6px' }}>
                        {cFields.map((cf) => (
                          <div key={cf.field_id}><strong>{cf.label}:</strong> {cf.value || '—'}</div>
                        ))}
                      </div>
                    )}

                    {scriptOutput && scriptOutput.deviceId === device.id && (
                      <pre style={{ background: 'rgba(0,0,0,0.45)', padding: '0.6rem', borderRadius: '6px', fontSize: '0.72rem', color: '#34d399', margin: 0, whiteSpace: 'pre-wrap' }}>
                        {scriptOutput.output}
                      </pre>
                    )}

                    <div style={{ display: 'flex', gap: '0.5rem', marginTop: 'auto', paddingTop: '0.5rem', flexWrap: 'wrap' }}>
                      {perms.can_remote_screen && (
                        <button className="btn-glass btn-primary" style={{ flex: 1, padding: '0.6rem', fontSize: '0.82rem', justifyContent: 'center' }} disabled={!isOnline} onClick={() => setActiveRemote({ open: true, device, isGhost: false })}>
                          <Monitor size={15} />
                          <span>Remote Control</span>
                        </button>
                      )}
                      {perms.can_ghost_session && (
                        <button className="btn-glass" style={{ flex: 1, padding: '0.6rem', fontSize: '0.82rem', justifyContent: 'center', borderColor: 'rgba(168, 85, 247, 0.4)', color: '#d8b4fe' }} disabled={!isOnline} onClick={() => setActiveRemote({ open: true, device, isGhost: true })}>
                          <Activity size={15} />
                          <span>Ghost Session</span>
                        </button>
                      )}
                      {perms.can_run_scripts && (
                        <button className="btn-glass" style={{ padding: '0.6rem', fontSize: '0.8rem' }} disabled={!isOnline || !selectedScriptId} onClick={() => handleRunVendorDiag(device)}>
                          <Terminal size={14} />
                          <span>Run Script</span>
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {activeRemote.open && activeRemote.device && (
        <RemoteScreenModal
          device={activeRemote.device}
          isGhostSession={activeRemote.isGhost}
          onClose={() => setActiveRemote({ open: false, device: null, isGhost: false })}
        />
      )}
    </div>
  );
};
