import React, { useState } from 'react';
import { Settings as SettingsIcon, Mail, Shield, Globe, Palette, CheckCircle2, Send } from 'lucide-react';
import { Settings } from '../types/index.js';
import { updateSettings, testSmtp } from '../services/api.js';

interface SettingsViewProps {
  settings: Settings;
  onUpdated: (s: Settings) => void;
  onOpenWizard: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ settings, onUpdated, onOpenWizard }) => {
  const [formData, setFormData] = useState<Settings>({ ...settings });
  const [saving, setSaving] = useState(false);
  const [smtpTestResult, setSmtpTestResult] = useState<string | null>(null);
  const [testingSmtp, setTestingSmtp] = useState(false);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const res = await updateSettings(formData);
      if (res.success) {
        onUpdated(res.settings);
        alert('Settings & white-labeling updated successfully!');
      }
    } finally {
      setSaving(false);
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="settings-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
            System Settings &amp; White-Labeling
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Configure global branding, MeshCentral 2 backend connection, SMTP notifications, and Authentik SSO
          </span>
        </div>
        <button className="btn-glass btn-primary" onClick={onOpenWizard}>
          Launch Onboarding Wizard
        </button>
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

        {/* MeshCentral Link Card */}
        <div className="glass-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1.25rem' }}>
            <Shield size={20} color="var(--primary)" />
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>MeshCentral 2 Remote Engine Link</h3>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.25rem' }}>
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
        </div>

        {/* Outbound SMTP Notifications Card (Feature 29) */}
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
