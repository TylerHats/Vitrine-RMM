import React, { useState, useEffect } from 'react';
import {
  Shield,
  Clock,
  Laptop,
  Monitor,
  Activity,
  Lock,
  Terminal,
  KeyRound
} from 'lucide-react';
import { fetchGuestPortal, authenticateGuestPortal, runScript } from '../services/api.js';
import { Device } from '../types/index.js';
import { RemoteScreenModal } from '../components/RemoteScreenModal.js';

interface GuestPortalGrant {
  id: string;
  vendor_name: string;
  temp_username?: string;
  expires_at: string;
  permissions: Record<string, boolean>;
}

interface GuestPortalViewProps {
  grantId: string;
}

export const GuestPortalView: React.FC<GuestPortalViewProps> = ({ grantId }) => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [grant, setGrant] = useState<GuestPortalGrant | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [timeRemaining, setTimeRemaining] = useState<string>('');
  const [isExpired, setIsExpired] = useState(false);

  // Optional Vendor Credential Verification state
  const [showCredVerify, setShowCredVerify] = useState(false);
  const [tempUsername, setTempUsername] = useState('');
  const [tempPassword, setTempPassword] = useState('');
  const [credVerified, setCredVerified] = useState(false);
  const [credError, setCredError] = useState<string | null>(null);

  // Quick Script Output
  const [scriptOutput, setScriptOutput] = useState<{ deviceId: string; output: string } | null>(null);

  // Remote session modal
  const [activeRemote, setActiveRemote] = useState<{
    open: boolean;
    device: Device | null;
    isGhost: boolean;
  }>({
    open: false,
    device: null,
    isGhost: false
  });

  useEffect(() => {
    const loadPortalData = async () => {
      try {
        const res = await fetchGuestPortal(grantId);
        if (res.success && res.grant) {
          const g = res.grant as GuestPortalGrant;
          setGrant(g);
          setDevices(res.devices || []);
          setTempUsername(g.temp_username || '');
        } else {
          setError(res.error || 'Failed to authenticate vendor access token');
        }
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : 'Network error connecting to Vitrine Portal');
      } finally {
        setLoading(false);
      }
    };

    loadPortalData();
  }, [grantId]);

  // Live Countdown timer
  useEffect(() => {
    if (!grant?.expires_at) return;

    const updateTimer = () => {
      const now = Date.now();
      const exp = new Date(grant.expires_at).getTime();
      const diff = exp - now;

      if (diff <= 0) {
        setTimeRemaining('00:00:00 (Expired)');
        setIsExpired(true);
      } else {
        const hours = Math.floor(diff / 3600000);
        const minutes = Math.floor((diff % 3600000) / 60000);
        const seconds = Math.floor((diff % 60000) / 1000);
        setTimeRemaining(
          `${hours.toString().padStart(2, '0')}h ${minutes.toString().padStart(2, '0')}m ${seconds.toString().padStart(2, '0')}s`
        );
      }
    };

    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    return () => clearInterval(interval);
  }, [grant]);

  const handleVerifyVendorCreds = async (e: React.FormEvent) => {
    e.preventDefault();
    setCredError(null);
    const res = await authenticateGuestPortal(grantId, tempUsername, tempPassword);
    if (res.success) {
      setCredVerified(true);
      setShowCredVerify(false);
    } else {
      setCredError(res.error || 'Invalid temporary vendor credentials');
    }
  };

  const handleRunVendorDiag = async (device: Device) => {
    const res = await runScript('scr-1', [device.id]);
    const firstOut = `Diagnostic script queued on ${device.hostname} (Execution ID: ${res.executionId}).`;
    setScriptOutput({ deviceId: device.id, output: firstOut });
  };

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#0a0d14', color: '#f3f4f6' }}>
        <div style={{ textAlign: 'center' }}>
          <div className="pulse-dot" style={{ margin: '0 auto 1rem', width: '16px', height: '16px' }} />
          <h3>Authenticating Vendor Session...</h3>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Verifying cryptographic access token and policy scope</p>
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
          <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: '0.85rem', borderRadius: '8px', fontSize: '0.8rem', color: '#9ca3af', marginBottom: '1.5rem' }}>
            To request renewed access, please reach out to your IT Support Contact or primary MSP service desk.
          </div>
          <a
            href="/"
            style={{
              display: 'inline-block',
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid var(--glass-border)',
              color: 'var(--text-main)',
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
        {/* Top Header */}
        <header
          style={{
            background: 'rgba(23, 27, 38, 0.7)',
            backdropFilter: 'blur(16px)',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: '16px',
            padding: '1.5rem 2rem',
            marginBottom: '2rem',
            boxShadow: '0 10px 30px rgba(0, 0, 0, 0.4)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '1.25rem'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div
              style={{
                width: '44px',
                height: '44px',
                borderRadius: '10px',
                background: 'linear-gradient(135deg, #6366f1, #a855f7)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#fff',
                boxShadow: '0 0 16px rgba(99, 102, 241, 0.4)'
              }}
            >
              <Shield size={24} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <h1 style={{ margin: 0, fontSize: '1.35rem', fontWeight: 700 }}>Vendor Access Portal</h1>
                <span style={{ background: 'rgba(99, 102, 241, 0.2)', color: '#a5b4fc', border: '1px solid rgba(99, 102, 241, 0.4)', fontSize: '0.75rem', padding: '0.15rem 0.6rem', borderRadius: '12px', fontWeight: 600 }}>
                  Scoped Session
                </span>
                {credVerified && (
                  <span style={{ background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', border: '1px solid rgba(16, 185, 129, 0.4)', fontSize: '0.72rem', padding: '0.15rem 0.6rem', borderRadius: '12px', fontWeight: 600 }}>
                    Credentials Verified
                  </span>
                )}
              </div>
              <p style={{ margin: '0.2rem 0 0', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                Authenticated Guest: <strong style={{ color: '#e0e7ff' }}>{grant?.vendor_name}</strong> ({grant?.temp_username})
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            {!credVerified && (
              <button
                className="btn-glass"
                style={{ fontSize: '0.78rem' }}
                onClick={() => setShowCredVerify((prev) => !prev)}
              >
                <KeyRound size={14} /> Verify Temp Credentials
              </button>
            )}

            {/* Time Remaining Pill */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                background: 'rgba(245, 158, 11, 0.1)',
                border: '1px solid rgba(245, 158, 11, 0.3)',
                padding: '0.65rem 1.25rem',
                borderRadius: '12px'
              }}
            >
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
          </div>
        </header>

        {showCredVerify && (
          <form
            onSubmit={handleVerifyVendorCreds}
            className="glass-card"
            style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}
          >
            <span style={{ fontSize: '0.82rem', fontWeight: 600 }}>Temporary Credentials Check:</span>
            <input
              type="text"
              className="glass-input"
              style={{ maxWidth: '200px' }}
              placeholder="Temp Username"
              value={tempUsername}
              onChange={(e) => setTempUsername(e.target.value)}
            />
            <input
              type="password"
              className="glass-input"
              style={{ maxWidth: '200px' }}
              placeholder="Temp Password"
              value={tempPassword}
              onChange={(e) => setTempPassword(e.target.value)}
            />
            <button type="submit" className="btn-glass btn-primary" style={{ fontSize: '0.8rem' }}>
              Authenticate
            </button>
            {credError && <span style={{ color: '#f87171', fontSize: '0.78rem' }}>{credError}</span>}
          </form>
        )}

        {/* Permissions & Security Banner */}
        <div
          style={{
            background: 'rgba(15, 23, 42, 0.6)',
            border: '1px solid rgba(255, 255, 255, 0.05)',
            borderRadius: '12px',
            padding: '1rem 1.5rem',
            marginBottom: '2rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '1rem'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            <Lock size={15} color="#818cf8" />
            <span>Active Permissions:</span>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
              {perms.can_remote_screen && (
                <span style={{ background: 'rgba(59, 130, 246, 0.2)', color: '#93c5fd', padding: '0.15rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem' }}>
                  Remote Screen
                </span>
              )}
              {perms.can_ghost_session && (
                <span style={{ background: 'rgba(168, 85, 247, 0.2)', color: '#d8b4fe', padding: '0.15rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem' }}>
                  Ghost Desktop
                </span>
              )}
              {perms.can_view_telemetry && (
                <span style={{ background: 'rgba(16, 185, 129, 0.2)', color: '#6ee7b7', padding: '0.15rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem' }}>
                  Live Telemetry
                </span>
              )}
              {perms.can_view_hardware && (
                <span style={{ background: 'rgba(234, 179, 8, 0.2)', color: '#fde047', padding: '0.15rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem' }}>
                  Hardware Specs
                </span>
              )}
              {perms.can_run_scripts && (
                <span style={{ background: 'rgba(239, 68, 68, 0.2)', color: '#fca5a5', padding: '0.15rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem' }}>
                  Script Execution
                </span>
              )}
            </div>
          </div>

          <div style={{ fontSize: '0.75rem', color: '#9ca3af' }}>
            🔒 All vendor actions are audited and recorded for compliance
          </div>
        </div>

        {/* Assigned Devices Grid */}
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <Laptop size={20} color="var(--primary)" />
            <h2 style={{ margin: 0, fontSize: '1.15rem', fontWeight: 600 }}>
              Authorized Target Endpoints ({devices.length})
            </h2>
          </div>

          {devices.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '3rem', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '12px', border: '1px dashed var(--glass-border)' }}>
              <p style={{ margin: 0, color: 'var(--text-muted)' }}>No devices are currently assigned to this vendor session.</p>
            </div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: '1.25rem' }}>
              {devices.map((device) => {
                const isOnline = device.status === 'online';
                return (
                  <div
                    key={device.id}
                    style={{
                      background: 'rgba(23, 27, 38, 0.75)',
                      backdropFilter: 'blur(12px)',
                      border: '1px solid rgba(255, 255, 255, 0.08)',
                      borderRadius: '12px',
                      padding: '1.5rem',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '1rem',
                      boxShadow: '0 8px 24px rgba(0, 0, 0, 0.3)'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 600, color: '#f9fafb' }}>
                            {device.hostname}
                          </h3>
                          <span
                            style={{
                              width: '8px',
                              height: '8px',
                              borderRadius: '50%',
                              background: isOnline ? '#10b981' : '#6b7280',
                              boxShadow: isOnline ? '0 0 8px #10b981' : 'none'
                            }}
                          />
                        </div>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                          {device.os_type} {device.os_version} • {device.ip_address}
                        </div>
                      </div>

                      <span
                        style={{
                          fontSize: '0.75rem',
                          padding: '0.2rem 0.5rem',
                          borderRadius: '4px',
                          background: isOnline ? 'rgba(16, 185, 129, 0.15)' : 'rgba(107, 114, 128, 0.15)',
                          color: isOnline ? '#34d399' : '#9ca3af',
                          border: `1px solid ${isOnline ? 'rgba(16, 185, 129, 0.3)' : 'rgba(107, 114, 128, 0.3)'}`
                        }}
                      >
                        {isOnline ? 'Online' : 'Offline'}
                      </span>
                    </div>

                    {/* Live Telemetry Gauges if allowed */}
                    {perms.can_view_telemetry && (
                      <div
                        style={{
                          display: 'grid',
                          gridTemplateColumns: 'repeat(3, 1fr)',
                          gap: '0.5rem',
                          background: 'rgba(0, 0, 0, 0.25)',
                          padding: '0.75rem',
                          borderRadius: '8px',
                          fontSize: '0.75rem'
                        }}
                      >
                        <div>
                          <div style={{ color: 'var(--text-muted)' }}>CPU Load</div>
                          <div style={{ fontWeight: 700, fontSize: '0.95rem', color: '#60a5fa', marginTop: '0.2rem' }}>
                            {device.cpu_usage || 0}%
                          </div>
                        </div>
                        <div>
                          <div style={{ color: 'var(--text-muted)' }}>Memory</div>
                          <div style={{ fontWeight: 700, fontSize: '0.95rem', color: '#c084fc', marginTop: '0.2rem' }}>
                            {device.ram_total_gb ? Math.round((device.ram_used_gb / device.ram_total_gb) * 100) : 0}%
                          </div>
                        </div>
                        <div>
                          <div style={{ color: 'var(--text-muted)' }}>Disk Used</div>
                          <div style={{ fontWeight: 700, fontSize: '0.95rem', color: '#34d399', marginTop: '0.2rem' }}>
                            {device.disk_total_gb ? Math.round(((device.disk_total_gb - device.disk_free_gb) / device.disk_total_gb) * 100) : 0}%
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Hardware details if allowed */}
                    {perms.can_view_hardware && (
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                        <div><strong>CPU / Role:</strong> {device.cpu_model || 'Standard Endpoint'} • {device.device_role}</div>
                        <div><strong>Serial / BIOS:</strong> {device.serial_number || 'N/A'} • {device.bios_version || 'UEFI'}</div>
                      </div>
                    )}

                    {scriptOutput && scriptOutput.deviceId === device.id && (
                      <pre
                        style={{
                          background: 'rgba(0,0,0,0.45)',
                          padding: '0.6rem',
                          borderRadius: '6px',
                          fontSize: '0.72rem',
                          color: '#34d399',
                          margin: 0,
                          whiteSpace: 'pre-wrap'
                        }}
                      >
                        {scriptOutput.output}
                      </pre>
                    )}

                    {/* Action Buttons */}
                    <div style={{ display: 'flex', gap: '0.5rem', marginTop: 'auto', paddingTop: '0.5rem', flexWrap: 'wrap' }}>
                      {perms.can_remote_screen && (
                        <button
                          className="btn-glass btn-primary"
                          style={{ flex: 1, padding: '0.6rem', fontSize: '0.82rem', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '0.4rem' }}
                          disabled={!isOnline}
                          onClick={() => setActiveRemote({ open: true, device, isGhost: false })}
                        >
                          <Monitor size={15} />
                          <span>Remote Control</span>
                        </button>
                      )}

                      {perms.can_ghost_session && (
                        <button
                          className="btn-glass"
                          style={{
                            flex: 1,
                            padding: '0.6rem',
                            fontSize: '0.82rem',
                            display: 'flex',
                            justifyContent: 'center',
                            alignItems: 'center',
                            gap: '0.4rem',
                            borderColor: 'rgba(168, 85, 247, 0.4)',
                            color: '#d8b4fe'
                          }}
                          disabled={!isOnline}
                          onClick={() => setActiveRemote({ open: true, device, isGhost: true })}
                        >
                          <Activity size={15} />
                          <span>Ghost Session</span>
                        </button>
                      )}

                      {perms.can_run_scripts && (
                        <button
                          className="btn-glass"
                          style={{ padding: '0.6rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                          disabled={!isOnline}
                          onClick={() => handleRunVendorDiag(device)}
                        >
                          <Terminal size={14} />
                          <span>Run Diag</span>
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

      {/* Remote Screen Modal if triggered */}
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
