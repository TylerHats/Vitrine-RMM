import React, { useState, useEffect } from 'react';
import { Ticket, ArrowLeftRight, CheckCircle2, Clock, AlertTriangle, ExternalLink } from 'lucide-react';
import { fetchPsaTickets } from '../services/api.js';

export const PsaSyncView: React.FC = () => {
  const [tickets, setTickets] = useState<any[]>([]);

  useEffect(() => {
    fetchPsaTickets().then(setTickets);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="psa-sync-view">
      <div>
        <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
          Two-Way PSA &amp; ITFlow Synchronization
        </h2>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          Bidirectional ticket lifecycle, telemetry telemetry auto-appending, and auto-closing upon self-healing remediation
        </span>
      </div>

      <div className="metrics-grid">
        <div className="glass-card">
          <div className="metric-title">SYNCHRONIZED TICKETS</div>
          <div className="metric-value" style={{ color: 'var(--primary)' }}>{tickets.length}</div>
          <div className="metric-subtext">Connected to ITFlow instance</div>
        </div>

        <div className="glass-card">
          <div className="metric-title">AUTO-RESOLVED VIA RUNBOOKS</div>
          <div className="metric-value" style={{ color: '#34d399' }}>24</div>
          <div className="metric-subtext">Auto-closed upon self-healing condition resolution</div>
        </div>

        <div className="glass-card">
          <div className="metric-title">API WEBHOOK BUS</div>
          <div className="metric-value" style={{ color: '#38bdf8' }}>Active</div>
          <div className="metric-subtext">Listening on /api/psa/webhook</div>
        </div>
      </div>

      <div className="glass-card" style={{ padding: 0 }}>
        <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
          <table className="glass-table">
            <thead>
              <tr>
                <th>Ticket #</th>
                <th>Subject / Alert Trigger</th>
                <th>Client Tenant</th>
                <th>Target Endpoint</th>
                <th>Priority</th>
                <th>Sync Status</th>
              </tr>
            </thead>
            <tbody>
              {tickets.map((t) => (
                <tr key={t.id}>
                  <td><strong>{t.ticket_number}</strong></td>
                  <td>{t.title}</td>
                  <td>{t.client_name}</td>
                  <td><code>{t.device_id || 'System Fleet'}</code></td>
                  <td>
                    <span
                      className={`status-pill ${
                        t.priority === 'Urgent'
                          ? 'status-isolated'
                          : t.priority === 'High'
                          ? 'status-reboot'
                          : 'status-online'
                      }`}
                    >
                      {t.priority}
                    </span>
                  </td>
                  <td>
                    <span
                      className={`status-pill ${
                        t.status === 'Resolved' ? 'status-online' : 'status-reboot'
                      }`}
                    >
                      {t.status}
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
