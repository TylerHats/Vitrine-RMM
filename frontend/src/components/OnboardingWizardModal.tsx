import React, { useState } from 'react';
import { Sparkles, Globe, Palette, Shield, Mail, CheckCircle2, X } from 'lucide-react';
import { Settings } from '../types/index.js';
import { updateSettings } from '../services/api.js';

interface OnboardingWizardModalProps {
  settings: Settings;
  onClose: () => void;
  onSaved: (updated: Settings) => void;
}

export const OnboardingWizardModal: React.FC<OnboardingWizardModalProps> = ({
  settings,
  onClose,
  onSaved
}) => {
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState<Partial<Settings>>({ ...settings });
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    setSaving(true);
    try {
      const res = await updateSettings(formData);
      if (res.success) {
        onSaved(res.settings);
        onClose();
      }
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-backdrop" id="onboarding-wizard-modal">
      <div className="glass-modal glass-modal-lg">
        {/* Header */}
        <div className="modal-header">
          <div className="modal-title">
            <Sparkles size={20} style={{ color: '#00f2fe' }} />
            <span>Vitrine RMM Setup &amp; White-Labeling Wizard</span>
          </div>
          <button className="btn-glass btn-icon" onClick={onClose} id="close-wizard-btn">
            <X size={18} />
          </button>
        </div>

        {/* Wizard Step Progress */}
        <div style={{ display: 'flex', borderBottom: '1px solid var(--glass-border)', background: 'rgba(0, 0, 0, 0.15)' }}>
          {[
            { num: 1, title: 'Branding & Aesthetics', icon: Palette },
            { num: 2, title: 'MeshCentral 2 Engine', icon: Shield },
            { num: 3, title: 'SMTP & Notifications', icon: Mail },
            { num: 4, title: 'SSO & Multi-Tenancy', icon: Globe }
          ].map((s) => {
            const Icon = s.icon;
            const isCurrent = step === s.num;
            const isCompleted = step > s.num;
            return (
              <button
                key={s.num}
                onClick={() => setStep(s.num)}
                style={{
                  flex: 1,
                  padding: '0.85rem 1rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.65rem',
                  background: isCurrent ? 'rgba(0, 242, 254, 0.1)' : 'transparent',
                  border: 'none',
                  borderBottom: isCurrent ? '2px solid var(--primary)' : '2px solid transparent',
                  color: isCurrent ? '#fff' : 'var(--text-muted)',
                  cursor: 'pointer',
                  fontSize: '0.82rem',
                  fontWeight: isCurrent ? 600 : 500,
                  transition: 'all 0.2s'
                }}
              >
                <div
                  style={{
                    width: '22px',
                    height: '22px',
                    borderRadius: '50%',
                    background: isCompleted ? '#10b981' : isCurrent ? 'var(--primary)' : 'rgba(255, 255, 255, 0.15)',
                    color: '#000',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '0.75rem',
                    fontWeight: 700
                  }}
                >
                  {isCompleted ? '✓' : s.num}
                </div>
                <span>{s.title}</span>
              </button>
            );
          })}
        </div>

        {/* Body */}
        <div className="modal-body" style={{ minHeight: '380px' }}>
          {step === 1 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
                <div className="form-group">
                  <label className="form-label">Brand / Application Name</label>
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
                    placeholder="rmm.yourdomain.com"
                    value={formData.custom_domain || ''}
                    onChange={(e) => setFormData({ ...formData, custom_domain: e.target.value })}
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
                <div className="form-group">
                  <label className="form-label">Primary Accent Color</label>
                  <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                    <input
                      type="color"
                      value={formData.primary_color || '#00f2fe'}
                      onChange={(e) => setFormData({ ...formData, primary_color: e.target.value })}
                      style={{ width: '48px', height: '38px', borderRadius: '6px', border: 'none', cursor: 'pointer', background: 'transparent' }}
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
                  <label className="form-label">Glassmorphic Blur Intensity</label>
                  <select
                    className="glass-select"
                    value={formData.glass_blur_level || 'high'}
                    onChange={(e) => setFormData({ ...formData, glass_blur_level: e.target.value })}
                  >
                    <option value="high">High Specular (16px Blur + 180% Saturation)</option>
                    <option value="medium">Medium Frosted (10px Blur)</option>
                    <option value="low">Subtle Minimalist (4px Blur)</option>
                  </select>
                </div>
              </div>

              <div style={{ background: 'rgba(0, 0, 0, 0.25)', padding: '1rem', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '1rem' }}>
                <img src="/logo.png" alt="Branded Logo Preview" style={{ width: '56px', height: '56px', objectFit: 'contain' }} />
                <div>
                  <div style={{ fontWeight: 600 }}>Active Built-in Logo</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                    Loaded from <code>branding/logo.png</code>. Appears in navigation, system tray clients, and client QBR PDF reports.
                  </div>
                </div>
              </div>
            </div>
          )}

          {step === 2 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div className="form-group">
                <label className="form-label">MeshCentral 2 Server Endpoint URL</label>
                <input
                  type="text"
                  className="glass-input"
                  placeholder="https://mesh.internal:443"
                  value={formData.meshcentral_url || ''}
                  onChange={(e) => setFormData({ ...formData, meshcentral_url: e.target.value })}
                />
                <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                  Default points to local container or integrated micro-agent relay.
                </span>
              </div>

              <div className="form-group">
                <label className="form-label">MeshCentral API Login Key / Auth Token</label>
                <input
                  type="password"
                  className="glass-input"
                  placeholder="••••••••••••••••••••••••••••••••"
                  value={formData.meshcentral_api_token || ''}
                  onChange={(e) => setFormData({ ...formData, meshcentral_api_token: e.target.value })}
                />
              </div>

              <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.25)', padding: '0.85rem', borderRadius: '8px' }}>
                <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#34d399' }}>Auto-Failover Bridge Enabled</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Vitrine operates with zero downtime. If external MeshCentral is offline, Vitrine engages its internal agent proxy automatically.
                </div>
              </div>
            </div>
          )}

          {step === 3 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.25rem' }}>
                <div className="form-group">
                  <label className="form-label">SMTP Relay Host</label>
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
                  <label className="form-label">SMTP Username</label>
                  <input
                    type="text"
                    className="glass-input"
                    value={formData.smtp_user || ''}
                    onChange={(e) => setFormData({ ...formData, smtp_user: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">SMTP Password</label>
                  <input
                    type="password"
                    className="glass-input"
                    value={formData.smtp_pass || ''}
                    onChange={(e) => setFormData({ ...formData, smtp_pass: e.target.value })}
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Outbound From Address</label>
                <input
                  type="text"
                  className="glass-input"
                  value={formData.smtp_from || ''}
                  onChange={(e) => setFormData({ ...formData, smtp_from: e.target.value })}
                />
              </div>
            </div>
          )}

          {step === 4 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div className="form-group">
                <label className="form-label">OpenID Connect / Authentik Issuer URL</label>
                <input
                  type="text"
                  className="glass-input"
                  placeholder="https://auth.internal/application/o/vitrine/"
                  value={formData.oidc_issuer_url || ''}
                  onChange={(e) => setFormData({ ...formData, oidc_issuer_url: e.target.value })}
                />
              </div>

              <div className="form-group">
                <label className="form-label">OIDC Client ID</label>
                <input
                  type="text"
                  className="glass-input"
                  value={formData.oidc_client_id || ''}
                  onChange={(e) => setFormData({ ...formData, oidc_client_id: e.target.value })}
                />
              </div>

              <div style={{ background: 'rgba(0, 242, 254, 0.08)', border: '1px solid rgba(0, 242, 254, 0.2)', padding: '0.85rem', borderRadius: '8px' }}>
                <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--primary)' }}>Strict Multi-Tenancy &amp; RBAC</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Role claim mapping automatically isolates client technicians to their respective organizational containers.
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="modal-footer">
          {step > 1 && (
            <button className="btn-glass" onClick={() => setStep(step - 1)}>
              Previous
            </button>
          )}

          {step < 4 ? (
            <button className="btn-glass btn-primary" onClick={() => setStep(step + 1)}>
              Continue
            </button>
          ) : (
            <button className="btn-glass btn-primary" onClick={handleSave} disabled={saving} id="save-wizard-btn">
              <CheckCircle2 size={16} /> Save &amp; Apply Branding
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
