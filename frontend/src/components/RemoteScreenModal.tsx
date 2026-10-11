import React, { useState, useEffect, useRef } from 'react';
import {
  Monitor,
  X,
  Maximize2,
  Lock,
  Volume2,
  VolumeX,
  Clipboard,
  Shield,
  EyeOff,
  Zap,
  Activity,
  CheckCircle2
} from 'lucide-react';
import { Device } from '../types/index.js';

interface RemoteScreenModalProps {
  device: Device;
  isGhostSession?: boolean;
  onClose: () => void;
}

export const RemoteScreenModal: React.FC<RemoteScreenModalProps> = ({
  device,
  isGhostSession = false,
  onClose
}) => {
  const [selectedMonitor, setSelectedMonitor] = useState(1);
  const [audioEnabled, setAudioEnabled] = useState(false);
  const [consentGranted, setConsentGranted] = useState(false);
  const [consentCountdown, setConsentCountdown] = useState(15);
  const [autoLockOnDisconnect, setAutoLockOnDisconnect] = useState(true);
  const [clipboardSynced, setClipboardSynced] = useState(false);
  const [latencyMs, setLatencyMs] = useState(16);
  const [fps, setFps] = useState(60);

  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  // Determine if consent is required based on policy and device state
  const isServer = device.device_role.toLowerCase().includes('server') || device.device_role.toLowerCase().includes('controller') || isGhostSession;

  useEffect(() => {
    if (isServer) {
      setConsentGranted(true);
    } else {
      const timer = setInterval(() => {
        setConsentCountdown((prev) => {
          if (prev <= 1) {
            clearInterval(timer);
            setConsentGranted(true); // Default policy auto-connect or bypass
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
      return () => clearInterval(timer);
    }
  }, [isServer]);

  // Canvas rendering of interactive screen viewport
  useEffect(() => {
    if (!consentGranted) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let frameId: number;
    let t = 0;

    const render = () => {
      t += 0.03;
      const w = canvas.width;
      const h = canvas.height;

      // Draw desktop background
      const grad = ctx.createLinearGradient(0, 0, w, h);
      if (isGhostSession) {
        grad.addColorStop(0, '#0a192f');
        grad.addColorStop(1, '#020c1b');
      } else {
        grad.addColorStop(0, '#0284c7');
        grad.addColorStop(1, '#0f172a');
      }
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, w, h);

      // Draw Desktop Icons
      ctx.fillStyle = 'rgba(255, 255, 255, 0.85)';
      ctx.font = '11px Inter, sans-serif';

      // Icon 1
      ctx.fillStyle = 'rgba(255, 255, 255, 0.2)';
      ctx.fillRect(20, 20, 40, 40);
      ctx.fillStyle = '#ffffff';
      ctx.fillText('This PC', 20, 75);

      // Icon 2
      ctx.fillStyle = 'rgba(255, 255, 255, 0.2)';
      ctx.fillRect(20, 95, 40, 40);
      ctx.fillStyle = '#ffffff';
      ctx.fillText('Vitrine Tray', 14, 150);

      // Draw sample Admin Application Window
      const winX = 120 + Math.sin(t * 0.5) * 8;
      const winY = 60 + Math.cos(t * 0.5) * 6;
      const winW = 580;
      const winH = 340;

      // Window Drop Shadow
      ctx.shadowColor = 'rgba(0, 0, 0, 0.5)';
      ctx.shadowBlur = 20;
      ctx.fillStyle = 'rgba(15, 23, 42, 0.95)';
      ctx.fillRect(winX, winY, winW, winH);
      ctx.shadowBlur = 0;

      // Window Titlebar
      ctx.fillStyle = isGhostSession ? '#312e81' : '#0369a1';
      ctx.fillRect(winX, winY, winW, 28);
      ctx.fillStyle = '#ffffff';
      ctx.font = '600 11px Inter, sans-serif';
      ctx.fillText(
        isGhostSession
          ? `[GHOST SESSION] Headless Admin Console - ${device.hostname}`
          : `Active Session: CORP\\${device.hostname} - Administrator`,
        winX + 12,
        winY + 18
      );

      // Window Content (Simulated Diagnostic Graph)
      ctx.fillStyle = '#38bdf8';
      ctx.font = '11px JetBrains Mono, monospace';
      ctx.fillText(`OS: ${device.os_version} | RAM Used: ${device.ram_used_gb} GB / ${device.ram_total_gb} GB`, winX + 16, winY + 54);
      ctx.fillText(`BitLocker: ${device.bitlocker_status}`, winX + 16, winY + 76);
      ctx.fillText(`EDR Sensor: ${device.edr_status}`, winX + 16, winY + 98);

      // Live animated waveform
      ctx.beginPath();
      ctx.strokeStyle = '#00f2fe';
      ctx.lineWidth = 2;
      for (let x = 0; x < 300; x += 4) {
        const y = winY + 160 + Math.sin((x + t * 40) * 0.05) * 20;
        if (x === 0) ctx.moveTo(winX + 16 + x, y);
        else ctx.lineTo(winX + 16 + x, y);
      }
      ctx.stroke();

      // Draw Taskbar
      ctx.fillStyle = 'rgba(10, 15, 25, 0.92)';
      ctx.fillRect(0, h - 38, w, 38);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
      ctx.beginPath();
      ctx.moveTo(0, h - 38);
      ctx.lineTo(w, h - 38);
      ctx.stroke();

      // Windows Start Button
      ctx.fillStyle = '#00f2fe';
      ctx.fillRect(w / 2 - 20, h - 30, 8, 8);
      ctx.fillRect(w / 2 - 10, h - 30, 8, 8);
      ctx.fillRect(w / 2 - 20, h - 20, 8, 8);
      ctx.fillRect(w / 2 - 10, h - 20, 8, 8);

      // Live Cursor
      const curX = w / 2 + Math.cos(t) * 120;
      const curY = h / 2 + Math.sin(t * 1.5) * 80;
      ctx.fillStyle = '#ffffff';
      ctx.beginPath();
      ctx.moveTo(curX, curY);
      ctx.lineTo(curX + 10, curY + 14);
      ctx.lineTo(curX + 4, curY + 14);
      ctx.lineTo(curX, curY);
      ctx.fill();

      // Watermark indicator
      if (isGhostSession) {
        ctx.fillStyle = 'rgba(168, 85, 247, 0.85)';
        ctx.font = '700 13px Inter, sans-serif';
        ctx.fillText('🛡️ GHOST SESSION (PHYSICAL DISPLAY UNDISTURBED)', 16, 26);
      }

      frameId = requestAnimationFrame(render);
    };

    render();
    return () => cancelAnimationFrame(frameId);
  }, [consentGranted, isGhostSession, device]);

  const handleSendCtrlAltDel = () => {
    alert(`Ctrl+Alt+Del injected successfully to ${device.hostname} via MeshCentral SAS API.`);
  };

  const handleSyncClipboard = () => {
    setClipboardSynced(true);
    setTimeout(() => setClipboardSynced(false), 2000);
  };

  return (
    <div className="modal-backdrop" id="remote-screen-modal">
      <div className="glass-modal glass-modal-lg" style={{ height: '92vh', maxWidth: '1350px' }}>
        {/* Modal Header */}
        <div className="modal-header" style={{ padding: '0.85rem 1.5rem' }}>
          <div className="modal-title" style={{ fontSize: '1.05rem' }}>
            {isGhostSession ? (
              <>
                <EyeOff size={18} style={{ color: '#a855f7' }} />
                <span>Ghost Session (Headless RDP) — {device.hostname}</span>
                <span className="status-pill status-isolated" style={{ background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc', border: '1px solid rgba(168, 85, 247, 0.3)' }}>
                  Invisible Admin
                </span>
              </>
            ) : (
              <>
                <Monitor size={18} style={{ color: '#00f2fe' }} />
                <span>Interactive Screen Control — {device.hostname}</span>
                <span className="status-pill status-online">Low-Latency KVM</span>
              </>
            )}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            {/* Monitor Switcher */}
            <div style={{ display: 'flex', background: 'rgba(0, 0, 0, 0.3)', borderRadius: '6px', padding: '2px' }}>
              <button
                className={`btn-glass ${selectedMonitor === 1 ? 'btn-primary' : ''}`}
                style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem' }}
                onClick={() => setSelectedMonitor(1)}
              >
                Display 1 (4K)
              </button>
              <button
                className={`btn-glass ${selectedMonitor === 2 ? 'btn-primary' : ''}`}
                style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem' }}
                onClick={() => setSelectedMonitor(2)}
              >
                Display 2 (1080p)
              </button>
            </div>

            <button className="btn-glass" style={{ padding: '0.35rem 0.65rem', fontSize: '0.75rem' }} onClick={handleSendCtrlAltDel} title="Inject Ctrl+Alt+Del">
              <Lock size={13} />
              <span>Ctrl+Alt+Del</span>
            </button>

            <button className="btn-glass" style={{ padding: '0.35rem 0.65rem', fontSize: '0.75rem' }} onClick={handleSyncClipboard} title="Sync Clipboard">
              {clipboardSynced ? <CheckCircle2 size={13} color="#10b981" /> : <Clipboard size={13} />}
              <span>{clipboardSynced ? 'Synced!' : 'Clipboard'}</span>
            </button>

            <button
              className="btn-glass btn-icon"
              style={{ padding: '0.35rem' }}
              onClick={() => setAudioEnabled(!audioEnabled)}
              title={audioEnabled ? 'Remote Audio Enabled' : 'Remote Audio Muted'}
            >
              {audioEnabled ? <Volume2 size={15} color="#00f2fe" /> : <VolumeX size={15} />}
            </button>

            <button
              className="btn-glass btn-icon"
              style={{ padding: '0.35rem' }}
              onClick={() => setAutoLockOnDisconnect(!autoLockOnDisconnect)}
              title={autoLockOnDisconnect ? 'Auto-lock target endpoint upon disconnect (Active)' : 'Auto-lock disabled'}
            >
              <Lock size={15} color={autoLockOnDisconnect ? '#10b981' : '#94a3b8'} />
            </button>

            <button className="btn-glass btn-icon" onClick={onClose} id="close-remote-modal-btn">
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Consent Warning Banner (Feature 9) */}
        {!consentGranted && (
          <div
            style={{
              padding: '0.75rem 1.5rem',
              background: 'rgba(245, 158, 11, 0.15)',
              borderBottom: '1px solid rgba(245, 158, 11, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              color: '#fbbf24',
              fontSize: '0.85rem'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <Shield size={18} />
              <span>
                <strong>User Privacy Policy Enforced:</strong> Prompting end-user on target endpoint. Auto-connecting in <strong>{consentCountdown}s</strong> if unattended.
              </span>
            </div>
            <button
              className="btn-glass"
              style={{ padding: '0.25rem 0.75rem', fontSize: '0.75rem', background: '#f59e0b', color: '#000', fontWeight: 600 }}
              onClick={() => setConsentGranted(true)}
            >
              Bypass Consent (Admin Elevation)
            </button>
          </div>
        )}

        {/* Viewport Canvas */}
        <div style={{ flex: 1, position: 'relative', background: '#000', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
          <canvas
            ref={canvasRef}
            width={1280}
            height={720}
            style={{
              width: '100%',
              height: '100%',
              objectFit: 'contain',
              cursor: consentGranted ? 'default' : 'wait'
            }}
          />

          {/* Real-time Performance HUD */}
          <div
            style={{
              position: 'absolute',
              bottom: '12px',
              left: '16px',
              background: 'rgba(15, 23, 42, 0.85)',
              border: '1px solid var(--glass-border)',
              borderRadius: '6px',
              padding: '4px 10px',
              fontSize: '0.72rem',
              color: 'var(--text-muted)',
              display: 'flex',
              gap: '12px',
              alignItems: 'center'
            }}
          >
            <span>Engine: <strong>MeshCentral WebRTC</strong></span>
            <span>Latency: <strong style={{ color: '#10b981' }}>{latencyMs} ms</strong></span>
            <span>FPS: <strong>{fps}</strong></span>
            <span>Codec: <strong>VP8 / WebRTC</strong></span>
          </div>
        </div>
      </div>
    </div>
  );
};
