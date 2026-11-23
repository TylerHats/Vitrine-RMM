import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { Video, Download, Trash2, Search, RefreshCw, Play, X, Clock, HardDrive, Monitor } from 'lucide-react';
import { AuthUser, Device, SessionRecording, Tenant } from '../types/index.js';
import { fetchRecordings, getRecordingDownloadUrl, deleteRecording } from '../services/api.js';
import { isSuperAdmin as checkIsSuperAdmin } from '../utils/permissions.js';

interface SessionRecordingsViewProps {
  tenants: Tenant[];
  devices: Device[];
  selectedTenantId: string;
  currentUser?: AuthUser | null;
  onSelectDevice?: (device: Device) => void;
}

function formatDuration(totalSec: number): string {
  const secs = Math.max(0, Math.floor(totalSec || 0));
  const hrs = Math.floor(secs / 3600);
  const mins = Math.floor((secs % 3600) / 60);
  const rem = secs % 60;
  if (hrs > 0) return `${hrs}h ${mins}m ${rem}s`;
  if (mins > 0) return `${mins}m ${rem}s`;
  return `${rem}s`;
}

export const SessionRecordingsView: React.FC<SessionRecordingsViewProps> = ({
  tenants,
  devices,
  selectedTenantId,
  currentUser,
  onSelectDevice
}) => {
  const isSuperAdmin = Boolean(currentUser && checkIsSuperAdmin(currentUser));
  const [recordings, setRecordings] = useState<SessionRecording[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [tenantFilter, setTenantFilter] = useState(selectedTenantId || 'all');
  const [modeFilter, setModeFilter] = useState<'all' | 'kvm' | 'ghost'>('all');
  const [mediaFilter, setMediaFilter] = useState<'all' | 'video' | 'audit'>('all');
  const [activePlayback, setActivePlayback] = useState<SessionRecording | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [noticeIsError, setNoticeIsError] = useState(false);

  useEffect(() => {
    setTenantFilter(selectedTenantId || 'all');
  }, [selectedTenantId]);

  const loadRecordings = useCallback(async () => {
    setLoading(true);
    try {
      const list = await fetchRecordings();
      setRecordings(Array.isArray(list) ? list : []);
    } catch {
      setRecordings([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRecordings();
  }, [loadRecordings]);

  const deviceById = useMemo(() => new Map(devices.map((d) => [d.id, d])), [devices]);

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return recordings.filter((rec) => {
      const matchedDev = deviceById.get(rec.device_id);
      const effectiveTenantId = rec.tenant_id || matchedDev?.tenant_id || '';
      if (tenantFilter !== 'all' && effectiveTenantId !== tenantFilter) return false;
      if (modeFilter === 'ghost' && !rec.is_ghost_session) return false;
      if (modeFilter === 'kvm' && rec.is_ghost_session) return false;
      const isVid = Boolean(rec.has_video || rec.mime_type?.startsWith('video/'));
      if (mediaFilter === 'video' && !isVid) return false;
      if (mediaFilter === 'audit' && isVid) return false;
      if (!q) return true;
      const hostname = (rec.hostname || matchedDev?.hostname || rec.device_id || '').toLowerCase();
      const tech = (rec.technician || '').toLowerCase();
      const tenantName = (rec.tenant_name || matchedDev?.tenant_name || '').toLowerCase();
      return (
        hostname.includes(q) ||
        tech.includes(q) ||
        tenantName.includes(q) ||
        rec.id.toLowerCase().includes(q)
      );
    });
  }, [recordings, deviceById, tenantFilter, modeFilter, mediaFilter, searchQuery]);

  const totalStorageMb = useMemo(
    () => recordings.reduce((acc, r) => acc + Number(r.file_size_mb || 0), 0),
    [recordings]
  );
  const totalDurationSec = useMemo(
    () => recordings.reduce((acc, r) => acc + Number(r.duration_sec || 0), 0),
    [recordings]
  );
  const videoCount = useMemo(
    () => recordings.filter((r) => Boolean(r.has_video || r.mime_type?.startsWith('video/'))).length,
    [recordings]
  );

  const handleDelete = async (rec: SessionRecording) => {
    if (!confirm(`Permanently delete recorded session for ${rec.hostname || rec.device_id}?`)) return;
    try {
      const res = await deleteRecording(rec.id);
      if (res.success) {
        if (activePlayback?.id === rec.id) setActivePlayback(null);
        setNoticeIsError(false);
        setNotice(`Removed recording ${rec.id}.`);
        loadRecordings();
      } else {
        setNoticeIsError(true);
        setNotice(res.error || 'Failed to delete session recording.');
      }
    } catch (err: any) {
      setNoticeIsError(true);
      setNotice(err?.message || 'Failed to delete session recording.');
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }} id="session-recordings-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>
            Recorded Remote Control Sessions
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Browse, play back WebM video captures, and export compliance session logs across all managed endpoints
          </span>
        </div>
        <button type="button" className="btn-glass" onClick={loadRecordings} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          <span>Refresh Archive</span>
        </button>
      </div>

      {/* Summary KPIs */}
      <div className="metrics-grid">
        <div className="glass-card">
          <div className="metric-header">
            <span className="metric-title">TOTAL SESSIONS RECORDED</span>
            <div className="metric-icon-wrap"><Video size={18} /></div>
          </div>
          <div className="metric-value">{recordings.length}</div>
          <div className="metric-subtext">Compliance remote access archive</div>
        </div>

        <div className="glass-card">
          <div className="metric-header">
            <span className="metric-title">VIDEO CAPTURES (WEBM)</span>
            <div className="metric-icon-wrap" style={{ color: '#c084fc' }}><Play size={18} /></div>
          </div>
          <div className="metric-value">{videoCount}</div>
          <div className="metric-subtext">Playable directly in browser</div>
        </div>

        <div className="glass-card">
          <div className="metric-header">
            <span className="metric-title">RECORDED DURATION</span>
            <div className="metric-icon-wrap"><Clock size={18} /></div>
          </div>
          <div className="metric-value" style={{ fontSize: '1.55rem' }}>{formatDuration(totalDurationSec)}</div>
          <div className="metric-subtext">Cumulative remote technician time</div>
        </div>

        <div className="glass-card">
          <div className="metric-header">
            <span className="metric-title">ARCHIVE FOOTPRINT</span>
            <div className="metric-icon-wrap"><HardDrive size={18} /></div>
          </div>
          <div className="metric-value">{totalStorageMb.toFixed(2)} MB</div>
          <div className="metric-subtext">Retained per global recording policy</div>
        </div>
      </div>

      {notice && (
        <div
          className="glass-card"
          style={{
            padding: '0.75rem 1.1rem',
            fontSize: '0.82rem',
            background: noticeIsError ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
            borderColor: noticeIsError ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)',
            color: noticeIsError ? '#f87171' : '#34d399'
          }}
        >
          {notice}
        </div>
      )}

      {/* Inline Video Player Panel */}
      {activePlayback && (
        <div className="glass-card" style={{ borderColor: 'rgba(192, 132, 252, 0.45)', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <Video size={18} color="#c084fc" />
              <strong>
                Playback: {activePlayback.hostname || activePlayback.device_id} — {activePlayback.technician}
              </strong>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                {new Date(activePlayback.created_at).toLocaleString()} • {formatDuration(activePlayback.duration_sec)}
              </span>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <a
                href={getRecordingDownloadUrl(activePlayback.id)}
                download
                className="btn-glass"
                style={{ fontSize: '0.76rem', textDecoration: 'none' }}
              >
                <Download size={13} /> Download File
              </a>
              <button type="button" className="btn-glass btn-icon" onClick={() => setActivePlayback(null)}>
                <X size={16} />
              </button>
            </div>
          </div>
          <div style={{ borderRadius: '10px', overflow: 'hidden', background: '#000', border: '1px solid var(--glass-border)' }}>
            <video
              key={activePlayback.id}
              controls
              autoPlay
              src={getRecordingDownloadUrl(activePlayback.id, 'inline')}
              style={{ width: '100%', maxHeight: '480px', display: 'block' }}
            />
          </div>
        </div>
      )}

      {/* Filter Bar */}
      <div className="glass-card" style={{ padding: '0.9rem 1.15rem', display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <div style={{ position: 'relative', flex: '1 1 240px' }}>
          <Search size={15} style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-dim)' }} />
          <input
            type="text"
            className="glass-input"
            style={{ paddingLeft: '2.2rem', fontSize: '0.82rem' }}
            placeholder="Filter by hostname, technician, client, or recording ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <select
          className="glass-select"
          style={{ width: 'auto', minWidth: '175px', fontSize: '0.8rem' }}
          value={tenantFilter}
          onChange={(e) => setTenantFilter(e.target.value)}
        >
          <option value="all">All Client Tenants</option>
          {tenants.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name}
            </option>
          ))}
        </select>

        <select
          className="glass-select"
          style={{ width: 'auto', fontSize: '0.8rem' }}
          value={modeFilter}
          onChange={(e) => setModeFilter(e.target.value as any)}
        >
          <option value="all">All Session Modes</option>
          <option value="kvm">Interactive Screen</option>
          <option value="ghost">Background / Ghost</option>
        </select>

        <select
          className="glass-select"
          style={{ width: 'auto', fontSize: '0.8rem' }}
          value={mediaFilter}
          onChange={(e) => setMediaFilter(e.target.value as any)}
        >
          <option value="all">All Formats</option>
          <option value="video">Video Captures Only</option>
          <option value="audit">Session Logs Only</option>
        </select>
      </div>

      {/* Recordings Table */}
      <div className="glass-card" style={{ padding: 0 }}>
        <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
          <table className="glass-table">
            <thead>
              <tr>
                <th>Recorded At</th>
                <th>Endpoint</th>
                <th>Client</th>
                <th>Technician</th>
                <th>Mode</th>
                <th>Duration</th>
                <th>Format &amp; Size</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((rec) => {
                const dev = deviceById.get(rec.device_id);
                const hasVideo = Boolean(rec.has_video || rec.mime_type?.startsWith('video/'));
                const displayClient = rec.tenant_name || dev?.tenant_name || '—';
                const displayHost = rec.hostname || dev?.hostname || rec.device_id;
                return (
                  <tr key={rec.id}>
                    <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                      {new Date(rec.created_at).toLocaleString()}
                    </td>
                    <td>
                      {dev && onSelectDevice ? (
                        <button
                          type="button"
                          onClick={() => onSelectDevice(dev)}
                          style={{
                            background: 'none',
                            border: 'none',
                            padding: 0,
                            color: 'var(--primary)',
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.35rem'
                          }}
                        >
                          <Monitor size={13} />
                          <span>{displayHost}</span>
                        </button>
                      ) : (
                        <strong>{displayHost}</strong>
                      )}
                    </td>
                    <td style={{ fontSize: '0.8rem' }}>{displayClient}</td>
                    <td style={{ fontSize: '0.8rem' }}>
                      <strong>{rec.technician}</strong>
                    </td>
                    <td>
                      <span
                        className={`status-pill ${rec.is_ghost_session ? 'status-isolated' : 'status-online'}`}
                        style={{ fontSize: '0.68rem' }}
                      >
                        {rec.is_ghost_session ? 'Backstage Ghost' : 'Interactive KVM'}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                      {formatDuration(rec.duration_sec)}
                    </td>
                    <td>
                      <span className="status-pill" style={{ fontSize: '0.68rem', background: hasVideo ? 'rgba(192, 132, 252, 0.16)' : 'rgba(148, 163, 184, 0.14)', color: hasVideo ? '#d8b4fe' : 'var(--text-muted)' }}>
                        {hasVideo ? 'WebM Video' : 'Audit Log'} • {Number(rec.file_size_mb || 0).toFixed(2)} MB
                      </span>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: '0.4rem', alignItems: 'center' }}>
                        {hasVideo && (
                          <button
                            type="button"
                            className="btn-glass"
                            style={{ padding: '0.25rem 0.6rem', fontSize: '0.73rem', color: '#d8b4fe' }}
                            onClick={() => setActivePlayback(activePlayback?.id === rec.id ? null : rec)}
                          >
                            <Play size={12} /> {activePlayback?.id === rec.id ? 'Hide' : 'Play'}
                          </button>
                        )}
                        <a
                          href={getRecordingDownloadUrl(rec.id)}
                          download
                          className="btn-glass"
                          style={{ padding: '0.25rem 0.6rem', fontSize: '0.73rem', textDecoration: 'none' }}
                          title="Download Session Archive"
                        >
                          <Download size={12} /> Download
                        </a>
                        {isSuperAdmin && (
                          <button
                            type="button"
                            className="btn-glass btn-icon"
                            onClick={() => handleDelete(rec)}
                            title="Delete Recording"
                          >
                            <Trash2 size={13} color="#ef4444" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}

              {!loading && filtered.length === 0 && (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: '2.75rem', color: 'var(--text-dim)', fontSize: '0.84rem' }}>
                    {recordings.length === 0
                      ? 'No control sessions recorded yet. When technicians open a remote desktop or backstage session (with recording enabled in Settings), sessions are archived here upon closing — use "Capture Video" inside the session toolbar to save a WebM video.'
                      : 'No session recordings match the current filter.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

