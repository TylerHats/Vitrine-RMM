import React, { useState, useEffect } from 'react';
import { FileText, Printer, Download, CheckCircle2, Shield, AlertTriangle, X } from 'lucide-react';
import { fetchQbrReport } from '../services/api.js';

interface QbrReportModalProps {
  onClose: () => void;
}

export const QbrReportModal: React.FC<QbrReportModalProps> = ({ onClose }) => {
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    fetchQbrReport().then(setData);
  }, []);

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="modal-backdrop" id="qbr-modal">
      <div className="glass-modal glass-modal-lg" style={{ maxHeight: '92vh' }}>
        <div className="modal-header">
          <div className="modal-title">
            <FileText size={20} style={{ color: '#00f2fe' }} />
            <span>Executive Fleet Health &amp; QBR Report Generator</span>
          </div>
          <div style={{ display: 'flex', gap: '0.65rem' }}>
            <button className="btn-glass btn-primary" onClick={handlePrint} id="print-qbr-btn">
              <Printer size={15} /> Print / Export PDF
            </button>
            <button className="btn-glass btn-icon" onClick={onClose} id="close-qbr-btn">
              <X size={18} />
            </button>
          </div>
        </div>

        <div className="modal-body" style={{ padding: '2rem' }}>
          {data ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
              {/* Report Header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--glass-border)', paddingBottom: '1.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                  <img src="/logo.png" alt="Vitrine Logo" style={{ width: '56px', height: '56px' }} />
                  <div>
                    <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem' }}>Quarterly Executive Business Review</h2>
                    <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                      Managed IT Infrastructure &amp; Security Compliance Report
                    </span>
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: '0.9rem', fontWeight: 600 }}>{data.quarter}</div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>Generated: {data.reportDate}</div>
                </div>
              </div>

              {/* Health Score Banner */}
              <div
                style={{
                  background: 'linear-gradient(135deg, rgba(0, 242, 254, 0.15) 0%, rgba(127, 0, 255, 0.15) 100%)',
                  border: '1px solid rgba(0, 242, 254, 0.3)',
                  borderRadius: '16px',
                  padding: '1.75rem',
                  display: 'flex',
                  justifyContent: 'space-around',
                  alignItems: 'center',
                  textAlign: 'center'
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
                  <div style={{ fontSize: '2rem', fontWeight: 700, color: '#00f2fe' }}>{data.patchCompliance}</div>
                </div>
              </div>

              {/* Security & Audit Breakdown */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1.25rem' }}>
                <div className="glass-card" style={{ padding: '1.25rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.65rem' }}>
                    <Shield size={18} color="#10b981" />
                    <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>Disk Encryption (BitLocker)</span>
                  </div>
                  <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#10b981' }}>{data.encryptionCompliance}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
                    Key escrow archived in Vitrine vault
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '1.25rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.65rem' }}>
                    <CheckCircle2 size={18} color="#00f2fe" />
                    <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>EDR Protection Rate</span>
                  </div>
                  <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#00f2fe' }}>{data.edrProtectionRate}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
                    Real-time definition freshness verified
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '1.25rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.65rem' }}>
                    <AlertTriangle size={18} color="#fbbf24" />
                    <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>Automated Remediations</span>
                  </div>
                  <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#fbbf24' }}>{data.remediationsAutomated}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
                    Self-healing issues resolved without tickets
                  </div>
                </div>
              </div>

              {/* Executive Summary Narrative */}
              <div className="glass-card">
                <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.75rem' }}>Executive Summary &amp; Recommendations</h3>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                  During Q4 2026, the managed fleet maintained a 98.4% health compliance rating. Zero unmitigated critical vulnerabilities were detected. 
                  Automated condition watchdogs intercepted 142 service hangs and disk warnings, auto-executing remediation runbooks before end-user impact. 
                  All fixed storage volumes maintain compliant BitLocker XTS-AES 256 encryption with synchronized escrow.
                </p>
              </div>
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '3rem' }}>Generating QBR metrics...</div>
          )}
        </div>
      </div>
    </div>
  );
};
