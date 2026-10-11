import React from 'react';
import {
  Cpu,
  HardDrive,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Monitor,
  EyeOff,
  KeyRound,
  RotateCcw,
  Zap,
  Activity,
  ArrowLeft,
  CheckCircle2,
  Lock,
  Layers,
  Power
} from 'lucide-react';
import { Device } from '../types/index.js';

interface DeviceDetailViewProps {
  device: Device;
  onBack: () => void;
  onOpenRemote: (device: Device, isGhost: boolean) => void;
  onOpenBgTools: (device: Device, initialTab?: string) => void;
  onOpenLaps: (device: Device) => void;
  onOpenQuarantine: (device: Device) => void;
}

export const DeviceDetailView: React.FC<DeviceDetailViewProps> = ({
  device,
  onBack,
  onOpenRemote,
  onOpenBgTools,
  onOpenLaps,
  onOpenQuarantine
}) => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="device-detail-view">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <button className="btn-glass btn-icon" onClick={onBack} title="Back to Fleet Dashboard">
            <ArrowLeft size={18} />
          </button>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.6rem', fontWeight: 700 }}>
                {device.hostname}
              </h2>
              <span className={`status-pill ${device.quarantined ? 'status-isolated' : 'status-online'}`}>
                {device.quarantined ? 'Quarantined' : device.status}
              </span>
            </div>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              {device.tenant_name || 'Apex Financial'} • {device.site_name || 'Main Office'} • IP: {device.ip_address}
            </span>
          </div>
        </div>

        {/* Quick Action Toolbar */}
        <div style={{ display: 'flex', gap: '0.65rem' }}>
          <button className="btn-glass btn-primary" onClick={() => onOpenRemote(device, false)}>
            <Monitor size={15} /> Remote Desktop
          </button>
          <button className="btn-glass" onClick={() => onOpenRemote(device, true)}>
            <EyeOff size={15} color="#c084fc" /> Ghost Session
          </button>
          <button className="btn-glass" onClick={() => onOpenBgTools(device, 'terminal')}>
            <Terminal size={15} /> Shell
          </button>
          <button className="btn-glass" onClick={() => onOpenLaps(device)}>
            <KeyRound size={15} color="#fbbf24" /> LAPS
          </button>
          <button className={`btn-glass ${device.quarantined ? 'btn-primary' : 'btn-danger'}`} onClick={() => onOpenQuarantine(device)}>
            <ShieldAlert size={15} /> {device.quarantined ? 'Restore Network' : 'Quarantine'}
          </button>
        </div>
      </div>

      {/* Hardware Lifecycle & Telemetry Cards */}
      <div className="metrics-grid">
        <div className="glass-card">
          <div className="metric-header">
            <span className="metric-title">PROCESSOR LOAD</span>
            <div className="metric-icon-wrap"><Cpu size={18} /></div>
          </div>
          <div className="metric-value">{device.cpu_usage.toFixed(1)}%</div>
          <div className="metric-subtext">{device.cpu_model} ({device.cpu_cores} Cores)</div>
        </div>

        <div className="glass-card">
          <div className="metric-header">
            <span className="metric-title">PHYSICAL RAM</span>
            <div className="metric-icon-wrap"><Activity size={18} /></div>
          </div>
          <div className="metric-value">{device.ram_used_gb.toFixed(1)} GB</div>
          <div className="metric-subtext">of {device.ram_total_gb.toFixed(1)} GB Total Installed</div>
        </div>

        <div className="glass-card">
          <div className="metric-header">
            <span className="metric-title">SYSTEM STORAGE</span>
            <div className="metric-icon-wrap"><HardDrive size={18} /></div>
          </div>
          <div className="metric-value">{device.disk_free_gb.toFixed(0)} GB</div>
          <div className="metric-subtext">Free of {device.disk_total_gb.toFixed(0)} GB ({device.smart_status} SMART)</div>
        </div>

        <div className="glass-card">
          <div className="metric-header">
            <span className="metric-title">OUT-OF-BAND (AMT)</span>
            <div className="metric-icon-wrap" style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#10b981' }}>
              <Power size={18} />
            </div>
          </div>
          <div className="metric-value" style={{ fontSize: '1.4rem', color: '#34d399' }}>
            {device.intel_amt_enabled ? 'Intel vPro Ready' : 'WoL Subnet Active'}
          </div>
          <div className="metric-subtext">Hardware-level remote power cycling</div>
        </div>
      </div>

      {/* Security & Audit Diagnostics */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        {/* BitLocker & Cryptographic Identity */}
        <div className="glass-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1.25rem' }}>
            <Lock size={20} color="var(--primary)" />
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Volume Encryption &amp; TPM</h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', fontSize: '0.85rem' }}>
            <div>
              <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>ENCRYPTION STATUS</span>
              <div style={{ fontWeight: 600, color: '#34d399' }}>{device.bitlocker_status}</div>
            </div>

            <div>
              <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>ESCROWED RECOVERY KEY</span>
              <div style={{ fontFamily: 'var(--font-mono)', background: 'rgba(0,0,0,0.3)', padding: '0.5rem 0.75rem', borderRadius: '6px', fontSize: '0.82rem', marginTop: '0.25rem' }}>
                {device.bitlocker_key}
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div>
                <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>TPM CHIP VERSION</span>
                <div style={{ fontWeight: 600 }}>{device.tpm_version} (Discrete Cryptoprocessor)</div>
              </div>
              <div>
                <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>BIOS FIRMWARE</span>
                <div style={{ fontWeight: 600 }}>{device.bios_version}</div>
              </div>
            </div>
          </div>
        </div>

        {/* EDR Sensor & Threat Protection */}
        <div className="glass-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1.25rem' }}>
            <ShieldCheck size={20} color="#10b981" />
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Endpoint Detection &amp; Response (EDR)</h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', fontSize: '0.85rem' }}>
            <div>
              <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>ACTIVE EDR ENGINE</span>
              <div style={{ fontWeight: 600 }}>{device.edr_name}</div>
            </div>

            <div>
              <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>SENSOR DEFINITIONS</span>
              <div style={{ fontWeight: 600, color: '#10b981' }}>{device.edr_status}</div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div>
                <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>HARDWARE SERIAL</span>
                <div style={{ fontFamily: 'var(--font-mono)' }}>{device.serial_number}</div>
              </div>
              <div>
                <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>MAC ADDRESS</span>
                <div style={{ fontFamily: 'var(--font-mono)' }}>{device.mac_address}</div>
              </div>
            </div>

            <div style={{ borderTop: '1px solid var(--glass-border)', paddingTop: '0.85rem', display: 'flex', gap: '0.5rem' }}>
              <button
                className="btn-glass"
                style={{ fontSize: '0.78rem' }}
                onClick={() => alert(`Triggered silent QuickScan on ${device.hostname}.`)}
              >
                Trigger Quick Scan
              </button>
              <button
                className="btn-glass"
                style={{ fontSize: '0.78rem' }}
                onClick={() => alert(`Signatures updated to latest definition ring.`)}
              >
                Update Definitions
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
