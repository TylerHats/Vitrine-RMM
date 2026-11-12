import React, { useState, useEffect } from 'react';
import { FileText, Printer, CheckCircle2, Shield, AlertTriangle, X } from 'lucide-react';
import { fetchQbrReport } from '../services/api.js';
import { Tenant } from '../types/index.js';

interface QbrReportData {
  tenantName?: string;
  quarter: string;
  reportDate: string;
  fleetHealthScore: number;
  totalManagedEndpoints: number;
  endpointAvailability: string;
  patchCompliance: string;
  encryptionCompliance: string;
  edrProtectionRate: string;
  quarantinedEndpoints: number;
  remediationsAutomated: number;
  ticketsSynchronized: number;
}

interface QbrReportModalProps {
  brandLogoUrl?: string;
  tenants?: Tenant[];
  initialTenantId?: string;
  onClose: () => void;
}

export const QbrReportModal: React.FC<QbrReportModalProps> = ({
  brandLogoUrl,
  tenants = [],
  initialTenantId = 'all',
  onClose
}) => {
  const [selectedTenantId, setSelectedTenantId] = useState(initialTenantId);
  const [data, setData] = useState<QbrReportData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    fetchQbrReport(selectedTenantId)
      .then((res) => setData(res as unknown as QbrReportData))
      .finally(() => setLoading(false));
  }, [selectedTenantId]);

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="modal-backdrop" id="qbr-modal">
      <div className="glass-modal glass-modal-lg" style={{ maxHeight: '92vh' }}>
        <div className="modal-header">
          <div className="modal-title">
            <FileText size={20} style={{ color: 'var(--primary)' }} />
            <span>Executive Fleet Health &amp; QBR Report Generator</span>
          </div>
          <div style={{ display: 'flex', gap: '0.65rem', alignItems: 'center' }}>
            {tenants.length > 0 && (
              <select
                className="glass-select"
                value={selectedTenantId}
                onChange={(e) => setSelectedTenantId(e.target.value)}
                style={{ width: 'auto', minWidth: '180px', padding: '0.4rem 0.7rem', fontSize: '0.8rem' }}
              >
                <option value="all">All Managed Clients</option>
                {tenants.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            )}
            <button className="btn-glass btn-primary" onClick={handlePrint} id="print-qbr-btn">
              <Printer size={15} /> Print / Export PDF
            </button>
            <button className="btn-glass btn-icon" onClick={onClose} id="close-qbr-btn">
              <X size={18} />
            </button>
          </div>
        </div>

        <div className="modal-body" style={{ padding: '2rem' }}>
          {loading ? (
            <div style={{ textAlign: 'center', padding: '3rem' }}>Generating live QBR metrics...</div>
          ) : data ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--glass-border)', paddingBottom: '1.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                  <img src={brandLogoUrl || '/logo.png'} alt="Logo" style={{ width: '56px', height: '56px', objectFit: 'contain' }} />
                  <div>
                    <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem' }}>
                      Quarterly Executive Business Review
                    </h2>
                    <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                      Scope: <strong>{data.tenantName || 'All Managed Clients'}</strong> ({data.totalManagedEndpoints} Managed Endpoint{data.totalManagedEndpoints === 1 ? '' : 's'})
                    </span>
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: '0.9rem', fontWeight: 600 }}>{data.quarter}</div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>Generated: {data.reportDate}</div>
                </div>
              </div>

              <div
                style={{
                  background: 'linear-gradient(135deg, rgba(0, 242, 254, 0.15) 0%, rgba(127, 0, 255, 0.15) 100%)',
                  border: '1px solid rgba(0, 242, 254, 0.3)',
                  borderRadius: '16px',
                  padding: '1.75rem',
                  display: 'flex',
                  justifyContent: 'space-around',
                  alignItems: 'center',
                  textAlign: 'center',
                  flexWrap: 'wrap',
                  gap: '1rem'
                }}
              >
                <div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>FLEET HEALTH INDEX</div>
                  <div style={{ fontSize: '2.5rem', fontWeight: 800, color: 'var(--primary)', fontFamily: 'var(--font-heading)' }}>
                    {data.fleetHealthScore} / 100
                  </div>
                </div>
                <div style={{ width: '1px', height: '60px', background: 'var(--glass-border)' }} />
                <div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>ENDPOINT AVAILABILITY</div>
                  <div style={{ fontSize: '2rem', fontWeight: 700, color: '#34d399' }}>{data.endpointAvailability}</div>
                </div>
                <div style={{ width: '1px', height: '60px', background: 'var(--glass-border)' }} />
                <div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>PATCH COMPLIANCE</div>
                  <div style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--primary)' }}>{data.patchCompliance}</div>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1.25rem' }}>
                <div className="glass-card" style={{ padding: '1.25rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.65rem' }}>
                    <Shield size={18} color="#10b981" />
                    <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>Disk Encryption (BitLocker)</span>
                  </div>
                  <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#10b981' }}>{data.encryptionCompliance}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
                    Key escrow encrypted in Vitrine vault
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '1.25rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.65rem' }}>
                    <CheckCircle2 size={18} color="var(--primary)" />
                    <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>EDR Protection Rate</span>
                  </div>
                  <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--primary)' }}>{data.edrProtectionRate}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
                    {data.quarantinedEndpoints} isolated endpoint{data.quarantinedEndpoints === 1 ? '' : 's'}
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '1.25rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.65rem' }}>
                    <AlertTriangle size={18} color="#fbbf24" />
                    <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>Automated Remediations</span>
                  </div>
                  <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#fbbf24' }}>{data.remediationsAutomated}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
                    {data.ticketsSynchronized} PSA ticket{data.ticketsSynchronized === 1 ? '' : 's'} synchronized
                  </div>
                </div>
              </div>

              <div className="glass-card">
                <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.75rem' }}>Executive Summary &amp; Live Fleet Posture</h3>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                  {data.totalManagedEndpoints === 0 ? (
                    <>No active endpoints are currently enrolled under <strong>{data.tenantName || 'All Managed Clients'}</strong>. Deploy signed Vitrine agents or import existing MeshCentral 2 groups to populate live compliance metrics.</>
                  ) : (
                    <>
                      During <strong>{data.quarter}</strong>, <strong>{data.tenantName || 'the managed fleet'}</strong> ({data.totalManagedEndpoints} active endpoint{data.totalManagedEndpoints === 1 ? '' : 's'}) achieved a composite health index of <strong>{data.fleetHealthScore}/100</strong> with <strong>{data.endpointAvailability}</strong> live connectivity and <strong>{data.patchCompliance}</strong> OS/application patch compliance. Disk encryption coverage stands at <strong>{data.encryptionCompliance}</strong> with recovery keys escrowed in the AES-256-GCM vault, EDR protection is active across <strong>{data.edrProtectionRate}</strong> of endpoints, and self-healing monitors executed <strong>{data.remediationsAutomated}</strong> automated remediation runbook{data.remediationsAutomated === 1 ? '' : 's'}.
                    </>
                  )}
                </p>
              </div>
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '3rem' }}>Unable to generate QBR metrics.</div>
          )}
        </div>
      </div>
    </div>
  );
};
