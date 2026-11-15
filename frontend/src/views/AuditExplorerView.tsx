import React, { useState, useEffect, useCallback } from 'react';
import { ScrollText, Search, Download, RefreshCw } from 'lucide-react';
import { AuditLogRecord } from '../types/index.js';
import { fetchAuditLogs, getAuditExportUrl } from '../services/api.js';

export const AuditExplorerView: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogRecord[]>([]);
  const [search, setSearch] = useState('');
  const [username, setUsername] = useState('');
  const [action, setAction] = useState('');
  const [limit, setLimit] = useState(200);
  const [loading, setLoading] = useState(false);

  const loadLogs = useCallback(async () => {
    setLoading(true);
    try {
      const rows = await fetchAuditLogs({
        search: search.trim() || undefined,
        username: username.trim() || undefined,
        action: action.trim() || undefined,
        limit
      });
      setLogs(rows);
    } finally {
      setLoading(false);
    }
  }, [search, username, action, limit]);

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  const currentFilters = {
    search: search.trim() || undefined,
    username: username.trim() || undefined,
    action: action.trim() || undefined
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }} id="audit-explorer-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>
            Compliance Audit Log Explorer
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Immutable technician, LAPS, BitLocker, RBAC &amp; automation event ledger with SOC2 / HIPAA CSV &amp; JSON export
          </span>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <a
            href={getAuditExportUrl('csv', currentFilters)}
            download="vitrine-audit-logs.csv"
            className="btn-glass btn-primary"
            style={{ textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem' }}
            id="btn-export-audit-csv"
          >
            <Download size={14} /> Export CSV
          </a>
          <a
            href={getAuditExportUrl('json', currentFilters)}
            download="vitrine-audit-logs.json"
            className="btn-glass"
            style={{ textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem' }}
            id="btn-export-audit-json"
          >
            <Download size={14} /> Export JSON
          </a>
        </div>
      </div>

      <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr 1fr auto auto', gap: '0.75rem', alignItems: 'center' }}>
          <div style={{ position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: '0.75rem', top: '0.68rem', color: 'var(--text-dim)' }} />
            <input
              type="text"
              className="glass-input"
              style={{ paddingLeft: '2.1rem', fontSize: '0.8rem' }}
              placeholder="Search details, hostnames, ticket numbers..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <input
            type="text"
            className="glass-input"
            style={{ fontSize: '0.8rem' }}
            placeholder="Filter Actor / Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <input
            type="text"
            className="glass-input"
            style={{ fontSize: '0.8rem' }}
            placeholder="Filter Action Type"
            value={action}
            onChange={(e) => setAction(e.target.value)}
          />
          <select
            className="glass-select"
            style={{ width: 'auto', fontSize: '0.8rem' }}
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
          >
            <option value={100}>100 rows</option>
            <option value={200}>200 rows</option>
            <option value={500}>500 rows</option>
          </select>
          <button type="button" className="btn-glass" onClick={loadLogs}>
            <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
          </button>
        </div>

        <div className="table-wrapper">
          <table className="glass-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Endpoint</th>
                <th>Audit Trail Details</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-dim)' }}>
                    <ScrollText size={24} style={{ opacity: 0.4, marginBottom: '0.4rem' }} />
                    <div>No audit records match the current filter.</div>
                  </td>
                </tr>
              ) : (
                logs.map((row) => (
                  <tr key={row.id}>
                    <td style={{ whiteSpace: 'nowrap', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {new Date(row.timestamp).toLocaleString()}
                    </td>
                    <td>
                      <span style={{ fontWeight: 600, fontSize: '0.8rem', color: 'var(--primary)' }}>
                        {row.username}
                      </span>
                    </td>
                    <td>
                      <span className="status-pill status-online" style={{ fontSize: '0.68rem' }}>
                        {row.action}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.78rem' }}>{row.hostname || row.device_id || 'Control Plane'}</td>
                    <td style={{ fontSize: '0.78rem', color: 'var(--text-main)', wordBreak: 'break-word' }}>
                      {row.details}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

