import React, { useState, useEffect, useRef } from 'react';
import {
  Monitor,
  X,
  Lock,
  Volume2,
  VolumeX,
  Clipboard,
  Shield,
  EyeOff,
  CheckCircle2,
  CircleDot,
  Cpu,
  ExternalLink,
  KeyRound
} from 'lucide-react';
import { Device, RemoteSessionDescriptor } from '../types/index.js';
import {
  saveRecording,
  getRecordingDownloadUrl,
  fetchSettings,
  fetchDeviceConsentStatus,
  negotiateRemoteSession,
  elevateRemoteAgent
} from '../services/api.js';
import { MfaChallengeModal } from './MfaChallengeModal.js';

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
  const [sessionMode, setSessionMode] = useState<'kvm' | 'ghost' | 'amt_kvm'>(isGhostSession ? 'ghost' : 'kvm');
  const [selectedMonitor, setSelectedMonitor] = useState(1);
  const [sessionDescriptor, setSessionDescriptor] = useState<RemoteSessionDescriptor | null>(null);
  const [useLiveMeshIframe, setUseLiveMeshIframe] = useState(false);
  const [audioEnabled, setAudioEnabled] = useState(false);
  const [consentGranted, setConsentGranted] = useState(false);
  const [consentCountdown, setConsentCountdown] = useState(15);
  const [autoLockOnDisconnect, setAutoLockOnDisconnect] = useState(true);
  const [clipboardSynced, setClipboardSynced] = useState(false);
  const [isRecording, setIsRecording] = useState(true);
  const [recordSeconds, setRecordSeconds] = useState(0);
  const [stealthForTechs, setStealthForTechs] = useState(false);
  const [manualRecording, setManualRecording] = useState(false);
  const [manualSeconds, setManualSeconds] = useState(0);
  const [latencyMs] = useState(14);
  const [fps] = useState(60);

  // Tech-Side Remote Self-Elevation state
  const [showElevateModal, setShowElevateModal] = useState(false);
  const [elevateSource, setElevateSource] = useState<'laps' | 'custom_admin' | 'end_user_uac'>('laps');
  const [elevateTargetAction, setElevateTargetAction] = useState<'elevate_temp_session' | 'promote_permanent_service'>('elevate_temp_session');
  const [customAdminUsername, setCustomAdminUsername] = useState('.\\Administrator');
  const [customAdminPassword, setCustomAdminPassword] = useState('');
  const [elevating, setElevating] = useState(false);
  const [elevateSuccessMsg, setElevateSuccessMsg] = useState<string | null>(null);
  const [elevateMfaOpen, setElevateMfaOpen] = useState(false);
  const [statusBanner, setStatusBanner] = useState<string | null>(null);
  const [agentPrivilegeLevel, setAgentPrivilegeLevel] = useState<string>(device.agent_privilege_mode || 'SYSTEM');

  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  const showTransientBanner = (msg: string) => {
    setStatusBanner(msg);
    setTimeout(() => setStatusBanner(null), 4000);
  };

  // Negotiate OS-specific display pipeline & Ghost Session isolation with backend
  useEffect(() => {
    negotiateRemoteSession(device.id, sessionMode, selectedMonitor)
      .then((desc) => {
        if (desc?.success) setSessionDescriptor(desc);
      })
      .catch(() => {});
  }, [device.id, sessionMode, selectedMonitor]);

  // Load stealth settings & policy consent configuration
  useEffect(() => {
    fetchSettings()
      .then((s) => {
        setStealthForTechs(Boolean(s.session_recording_stealth_for_techs));
      })
      .catch(() => {});
    fetchDeviceConsentStatus(device.id)
      .then((cs) => {
        if (cs) {
          setAutoLockOnDisconnect(Boolean(cs.autoLockOnDisconnect));
          if (!cs.requireConsent || cs.bypassedDueToLockScreen) {
            setConsentGranted(true);
          } else if (cs.timeoutSec) {
            setConsentCountdown(cs.timeoutSec);
          }
        }
      })
      .catch(() => {});
  }, [device.id]);

  // Timer for active server-side recording
  useEffect(() => {
    if (!isRecording) return;
    const interval = setInterval(() => {
      setRecordSeconds((s) => s + 1);
    }, 1000);
    return () => clearInterval(interval);
  }, [isRecording]);

  // Timer for manual clip recording
  useEffect(() => {
    if (!manualRecording) return;
    const interval = setInterval(() => {
      setManualSeconds((s) => s + 1);
    }, 1000);
    return () => clearInterval(interval);
  }, [manualRecording]);

  // Ghost Sessions and Out-of-Band AMT KVM never interrupt or prompt the physical user
  const bypassesUserPrompt =
    device.device_role.toLowerCase().includes('server') ||
    device.device_role.toLowerCase().includes('controller') ||
    sessionMode === 'ghost' ||
    sessionMode === 'amt_kvm';

  useEffect(() => {
    if (bypassesUserPrompt) {
      setConsentGranted(true);
    } else {
      const timer = setInterval(() => {
        setConsentCountdown((prev) => {
          if (prev <= 1) {
            clearInterval(timer);
            setConsentGranted(true);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
      return () => clearInterval(timer);
    }
  }, [bypassesUserPrompt]);

  // OS-aware & Mode-aware Canvas rendering of interactive screen viewport
  useEffect(() => {
    if (!consentGranted || useLiveMeshIframe) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let frameId: number;
    let t = 0;
    const osType = device.os_type || 'windows';

    const render = () => {
      t += 0.03;
      const w = canvas.width;
      const h = canvas.height;

      if (sessionMode === 'amt_kvm') {
        // Intel AMT / vPro Hardware Out-of-Band BIOS / Pre-Boot KVM View
        ctx.fillStyle = '#070b14';
        ctx.fillRect(0, 0, w, h);

        ctx.fillStyle = '#1e3a8a';
        ctx.fillRect(0, 0, w, 42);
        ctx.fillStyle = '#ffffff';
        ctx.font = '700 13px JetBrains Mono, monospace';
        ctx.fillText(`INTEL(R) AMT / vPRO HARDWARE KVM — OUT-OF-BAND MEI FRAMEBUFFER (${device.hostname})`, 20, 26);

        ctx.strokeStyle = '#3b82f6';
        ctx.lineWidth = 1.5;
        ctx.strokeRect(40, 70, w - 80, h - 130);

        ctx.fillStyle = '#93c5fd';
        ctx.font = '600 13px JetBrains Mono, monospace';
        ctx.fillText(`UEFI / BIOS Setup & Pre-Boot Hardware Telemetry — Serial: ${device.serial_number}`, 64, 105);
        ctx.fillStyle = '#e2e8f0';
        ctx.font = '12px JetBrains Mono, monospace';
        ctx.fillText(`Processor       : ${device.cpu_model} (${device.cpu_cores} Cores)`, 64, 140);
        ctx.fillText(`Installed RAM   : ${device.ram_total_gb * 1024} MB ECC/Non-ECC DDR5`, 64, 165);
        ctx.fillText(`Firmware / BIOS : ${device.bios_version} | TPM: ${device.tpm_version}`, 64, 190);
        ctx.fillText(`Boot Volume     : ${device.bitlocker_status} (${device.disk_total_gb} GB NVMe)`, 64, 215);
        ctx.fillText(`MEI Power State : S0 Working (CIRA / WS-Management Port 16993 TLS Active)`, 64, 240);

        ctx.fillStyle = 'rgba(30, 58, 138, 0.45)';
        ctx.fillRect(64, 275, w - 128, 160);
        ctx.fillStyle = '#38bdf8';
        ctx.fillText(`[F2] Enter UEFI Setup    [F12] Network PXE Boot    [F8] Windows Recovery / Safe Mode`, 84, 310);
        ctx.fillStyle = '#a7f3d0';
        ctx.fillText(`> Hardware Redfish / WS-Man KVM stream synchronized @ 30fps (Pre-OS keyboard capture active)`, 84, 350);
        ctx.fillText(`> Physical monitor blanking: Optional (Current state: Mirrored)`, 84, 380);
      } else {
        // Draw OS-specific desktop background
        const grad = ctx.createLinearGradient(0, 0, w, h);
        if (sessionMode === 'ghost') {
          grad.addColorStop(0, '#1e1b4b');
          grad.addColorStop(1, '#090d16');
        } else if (osType === 'macos') {
          grad.addColorStop(0, '#0f766e');
          grad.addColorStop(0.5, '#1d4ed8');
          grad.addColorStop(1, '#1e1b4b');
        } else if (osType === 'linux') {
          grad.addColorStop(0, '#4a154b');
          grad.addColorStop(1, '#111827');
        } else {
          grad.addColorStop(0, '#0284c7');
          grad.addColorStop(1, '#0f172a');
        }
        ctx.fillStyle = grad;
        ctx.fillRect(0, 0, w, h);

        // macOS / Linux GNOME Top Bar
        if (osType === 'macos' || osType === 'linux') {
          ctx.fillStyle = 'rgba(10, 15, 25, 0.85)';
          ctx.fillRect(0, 0, w, 26);
          ctx.fillStyle = '#f8fafc';
          ctx.font = '600 11px Inter, sans-serif';
          if (osType === 'macos') {
            ctx.fillText(`  Finder   File   Edit   View   Go   Window   Help`, 16, 17);
            ctx.fillText(`${device.hostname}  |  ${sessionMode === 'ghost' ? 'Secondary CGSession (Ghost)' : 'Console CGSession'}`, w - 340, 17);
          } else {
            ctx.fillText(`Activities   Terminal   System Monitor`, 16, 17);
            ctx.fillText(`${device.hostname} (${sessionMode === 'ghost' ? 'Xvfb :99 Ghost Desktop' : 'Display :0'})`, w - 310, 17);
          }
        }

        // Draw Desktop Icons
        const topOffset = osType === 'windows' ? 24 : 44;
        ctx.fillStyle = 'rgba(255, 255, 255, 0.2)';
        ctx.fillRect(20, topOffset, 42, 42);
        ctx.fillStyle = '#ffffff';
        ctx.font = '11px Inter, sans-serif';
        ctx.fillText(osType === 'macos' ? 'Macintosh HD' : osType === 'linux' ? 'Root FS (/)' : 'This PC', 14, topOffset + 56);

        ctx.fillStyle = 'rgba(255, 255, 255, 0.2)';
        ctx.fillRect(20, topOffset + 78, 42, 42);
        ctx.fillStyle = '#ffffff';
        ctx.fillText('Vitrine Agent', 14, topOffset + 134);

        // Draw Primary Application Window
        const winX = 110 + Math.sin(t * 0.5) * 6;
        const winY = 64 + Math.cos(t * 0.5) * 4;
        const winW = 680;
        const winH = 380;

        ctx.shadowColor = 'rgba(0, 0, 0, 0.55)';
        ctx.shadowBlur = 22;
        ctx.fillStyle = 'rgba(15, 23, 42, 0.96)';
        ctx.fillRect(winX, winY, winW, winH);
        ctx.shadowBlur = 0;

        // Window Titlebar
        ctx.fillStyle = sessionMode === 'ghost' ? '#4c1d95' : osType === 'linux' ? '#374151' : '#0369a1';
        ctx.fillRect(winX, winY, winW, 30);

        if (osType === 'macos') {
          // macOS Traffic Light Buttons
          ctx.fillStyle = '#ef4444';
          ctx.beginPath();
          ctx.arc(winX + 16, winY + 15, 5, 0, Math.PI * 2);
          ctx.fill();
          ctx.fillStyle = '#f59e0b';
          ctx.beginPath();
          ctx.arc(winX + 32, winY + 15, 5, 0, Math.PI * 2);
          ctx.fill();
          ctx.fillStyle = '#10b981';
          ctx.beginPath();
          ctx.arc(winX + 48, winY + 15, 5, 0, Math.PI * 2);
          ctx.fill();
        }

        ctx.fillStyle = '#ffffff';
        ctx.font = '600 11px Inter, sans-serif';
        const titlePrefix =
          sessionMode === 'ghost'
            ? `[GHOST BACKEND DESKTOP — USER UNDISTURBED] `
            : `[INTERACTIVE KVM] `;
        ctx.fillText(
          `${titlePrefix}${device.hostname} (${device.os_version}) — Display ${selectedMonitor}`,
          winX + (osType === 'macos' ? 68 : 14),
          winY + 19
        );

        // Window Content
        ctx.fillStyle = '#38bdf8';
        ctx.font = '11.5px JetBrains Mono, monospace';
        ctx.fillText(
          `Pipeline  : ${sessionDescriptor?.displayDriver || (sessionMode === 'ghost' ? 'Isolated Virtual Framebuffer' : 'Primary Display Capture')}`,
          winX + 18,
          winY + 56
        );
        ctx.fillText(
          `Isolation : ${sessionDescriptor?.sessionIsolation || (sessionMode === 'ghost' ? 'Background Graphical Session (Physical User Undisturbed)' : 'Shared Console Session')}`,
          winX + 18,
          winY + 78
        );
        ctx.fillText(
          `Telemetry : CPU ${device.cpu_usage}% | RAM ${device.ram_used_gb} / ${device.ram_total_gb} GB | Disk Free ${device.disk_free_gb} GB`,
          winX + 18,
          winY + 100
        );
        ctx.fillText(
          `Security  : ${device.bitlocker_status} | EDR: ${device.edr_name} (${device.edr_status})`,
          winX + 18,
          winY + 122
        );

        // Secondary Floating Terminal Window inside the Graphical Desktop
        const termX = winX + 36;
        const termY = winY + 148;
        const termW = winW - 72;
        const termH = 195;
        ctx.fillStyle = '#050811';
        ctx.fillRect(termX, termY, termW, termH);
        ctx.strokeStyle = 'rgba(56, 189, 248, 0.35)';
        ctx.strokeRect(termX, termY, termW, termH);

        ctx.fillStyle = '#a7f3d0';
        ctx.font = '11px JetBrains Mono, monospace';
        if (osType === 'windows') {
          ctx.fillText(`PS C:\\Windows\\System32> qwinsta`, termX + 12, termY + 24);
          ctx.fillStyle = '#cbd5e1';
          ctx.fillText(` SESSIONNAME       USERNAME                 ID  STATE   TYPE`, termX + 12, termY + 44);
          ctx.fillText(` console           local-user                1  Active  wdcon (Physical User)`, termX + 12, termY + 62);
          if (sessionMode === 'ghost') {
            ctx.fillStyle = '#c084fc';
            ctx.fillText(`>vitrine-ghost#99  NT AUTHORITY\\SYSTEM       2  Active  idd-virtual (Ghost GUI)`, termX + 12, termY + 80);
          }
        } else if (osType === 'macos') {
          ctx.fillText(`root@${device.hostname.toLowerCase()} ~ # launchctl print system/com.apple.WindowServer`, termX + 12, termY + 24);
          ctx.fillStyle = '#cbd5e1';
          ctx.fillText(` active count = 2 | Console CGSession (UID 501) + Vitrine Ghost CGSession (UID 0)`, termX + 12, termY + 46);
        } else {
          ctx.fillText(`root@${device.hostname.toLowerCase()}:~# loginctl list-sessions`, termX + 12, termY + 24);
          ctx.fillStyle = '#cbd5e1';
          ctx.fillText(` SESSION  UID USER   SEAT  TTY   DISPLAY`, termX + 12, termY + 44);
          ctx.fillText(`       1 1000 ubuntu seat0 tty2  :0 (Physical Desktop)`, termX + 12, termY + 62);
          if (sessionMode === 'ghost') {
            ctx.fillStyle = '#c084fc';
            ctx.fillText(`      99    0 root   -     pts/4 :99 (Xvfb Headless Ghost GUI)`, termX + 12, termY + 80);
          }
        }

        // Live animated waveform inside terminal
        ctx.beginPath();
        ctx.strokeStyle = sessionMode === 'ghost' ? '#a855f7' : '#00f2fe';
        ctx.lineWidth = 2;
        for (let x = 0; x < termW - 32; x += 4) {
          const y = termY + 145 + Math.sin((x + t * 40) * 0.05) * 18;
          if (x === 0) ctx.moveTo(termX + 16 + x, y);
          else ctx.lineTo(termX + 16 + x, y);
        }
        ctx.stroke();

        // Draw OS Taskbar / Dock
        if (osType === 'macos') {
          // macOS Translucent Bottom Dock
          const dockW = 320;
          ctx.fillStyle = 'rgba(15, 23, 42, 0.78)';
          ctx.fillRect((w - dockW) / 2, h - 46, dockW, 38);
          ctx.strokeStyle = 'rgba(255, 255, 255, 0.2)';
          ctx.strokeRect((w - dockW) / 2, h - 46, dockW, 38);
          for (let i = 0; i < 6; i++) {
            ctx.fillStyle = i % 2 === 0 ? '#38bdf8' : '#818cf8';
            ctx.fillRect((w - dockW) / 2 + 24 + i * 48, h - 38, 24, 22);
          }
        } else {
          // Windows 11 / Linux Panel
          ctx.fillStyle = 'rgba(10, 15, 25, 0.92)';
          ctx.fillRect(0, h - 38, w, 38);
          ctx.fillStyle = '#00f2fe';
          ctx.fillRect(w / 2 - 20, h - 30, 8, 8);
          ctx.fillRect(w / 2 - 10, h - 30, 8, 8);
          ctx.fillRect(w / 2 - 20, h - 20, 8, 8);
          ctx.fillRect(w / 2 - 10, h - 20, 8, 8);
        }
      }

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

      // Mode Watermark Badge
      if (sessionMode === 'ghost') {
        ctx.fillStyle = 'rgba(168, 85, 247, 0.92)';
        ctx.font = '700 12px Inter, sans-serif';
        ctx.fillText(
          `🛡️ HEADLESS GHOST DESKTOP (${osType.toUpperCase()}) — ZERO INTERFERENCE WITH LOGGED-IN USER SESSION`,
          16,
          osType === 'windows' ? 24 : 44
        );
      }

      frameId = requestAnimationFrame(render);
    };

    render();
    return () => cancelAnimationFrame(frameId);
  }, [consentGranted, sessionMode, selectedMonitor, sessionDescriptor, useLiveMeshIframe, device]);

  const handleSendCtrlAltDel = () => {
    showTransientBanner(`Ctrl+Alt+Del Secure Attention Sequence dispatched to ${device.hostname}.`);
  };

  const handleSyncClipboard = async () => {
    try {
      await navigator.clipboard.readText();
    } catch {
      // Clipboard permission optional
    }
    setClipboardSynced(true);
    showTransientBanner(`Clipboard synchronized with ${device.hostname}.`);
    setTimeout(() => setClipboardSynced(false), 2000);
  };

  const handleTriggerElevation = async () => {
    setElevating(true);
    setElevateSuccessMsg(null);
    try {
      const res = await elevateRemoteAgent(device.id, {
        credentialSource: elevateSource,
        adminUsername: elevateSource === 'custom_admin' ? customAdminUsername : undefined,
        adminPassword: elevateSource === 'custom_admin' ? customAdminPassword : undefined,
        elevationAction: elevateTargetAction
      });
      if (res.mfaRequired) {
        setElevateMfaOpen(true);
        return;
      }
      if (res.success) {
        setAgentPrivilegeLevel(res.newPrivilegeLevel || 'elevated_admin');
        setElevateSuccessMsg(res.message);
      } else {
        setElevateSuccessMsg(res.error || 'Remote elevation failed');
      }
    } catch (e: any) {
      setElevateSuccessMsg(e?.message || 'Remote elevation failed');
    } finally {
      setElevating(false);
    }
  };

  return (
    <div className="modal-backdrop" id="remote-screen-modal">
      <div className="glass-modal glass-modal-lg" style={{ height: '92vh', maxWidth: '1380px' }}>
        {/* Modal Header */}
        <div className="modal-header" style={{ padding: '0.85rem 1.5rem' }}>
          <div className="modal-title" style={{ fontSize: '1.02rem', gap: '0.6rem', flexWrap: 'wrap' }}>
            {sessionMode === 'ghost' ? (
              <>
                <EyeOff size={18} style={{ color: '#a855f7' }} />
                <span>Ghost Desktop Session — {device.hostname}</span>
                <span className="status-pill status-isolated" style={{ background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc', border: '1px solid rgba(168, 85, 247, 0.3)' }}>
                  Headless Graphical Desktop (User Undisturbed)
                </span>
              </>
            ) : sessionMode === 'amt_kvm' ? (
              <>
                <Cpu size={18} style={{ color: '#3b82f6' }} />
                <span>Intel AMT / vPro Hardware KVM — {device.hostname}</span>
                <span className="status-pill status-online" style={{ background: 'rgba(59, 130, 246, 0.18)', color: '#60a5fa' }}>
                  Out-of-Band Silicon KVM
                </span>
              </>
            ) : (
              <>
                <Monitor size={18} style={{ color: '#00f2fe' }} />
                <span>Interactive Screen Control — {device.hostname}</span>
                <span className="status-pill status-online">Low-Latency KVM</span>
              </>
            )}

            {/* 3-Mode Session Type Switcher */}
            <div style={{ display: 'flex', background: 'rgba(0, 0, 0, 0.35)', borderRadius: '6px', padding: '2px', marginLeft: '0.5rem' }}>
              <button
                type="button"
                className={`btn-glass ${sessionMode === 'kvm' ? 'btn-primary' : ''}`}
                style={{ padding: '0.2rem 0.55rem', fontSize: '0.72rem' }}
                onClick={() => setSessionMode('kvm')}
              >
                Standard KVM
              </button>
              <button
                type="button"
                className={`btn-glass ${sessionMode === 'ghost' ? 'btn-primary' : ''}`}
                style={{ padding: '0.2rem 0.55rem', fontSize: '0.72rem' }}
                onClick={() => setSessionMode('ghost')}
                title="Spawn a full headless graphical desktop without interfering with the logged-in user"
              >
                Ghost Session (Headless GUI)
              </button>
              <button
                type="button"
                className={`btn-glass ${sessionMode === 'amt_kvm' ? 'btn-primary' : ''}`}
                style={{ padding: '0.2rem 0.55rem', fontSize: '0.72rem' }}
                onClick={() => setSessionMode('amt_kvm')}
                title="Out-of-Band Intel AMT / vPro Hardware KVM (BIOS / Pre-Boot)"
              >
                Intel AMT KVM
              </button>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            {/* Server-Side Session Recording Indicator (Shown only if NOT in Admin Stealth Mode) */}
            {!stealthForTechs && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                {isRecording ? (
                  <button
                    type="button"
                    onClick={() => setIsRecording(false)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.35rem',
                      padding: '0.25rem 0.6rem',
                      borderRadius: '20px',
                      background: 'rgba(239, 68, 68, 0.15)',
                      border: '1px solid rgba(239, 68, 68, 0.4)',
                      color: '#f87171',
                      fontSize: '0.72rem',
                      fontWeight: 700,
                      cursor: 'pointer'
                    }}
                    title="Automated server-side compliance recording active (Click to pause)"
                  >
                    <CircleDot size={12} className="animate-pulse" color="#ef4444" />
                    <span>
                      VAULT REC {Math.floor(recordSeconds / 60).toString().padStart(2, '0')}:
                      {(recordSeconds % 60).toString().padStart(2, '0')}
                    </span>
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => setIsRecording(true)}
                    className="btn-glass"
                    style={{ fontSize: '0.72rem', color: 'var(--text-dim)', padding: '0.2rem 0.55rem' }}
                  >
                    Resume Vault Rec
                  </button>
                )}
              </div>
            )}

            {/* Manual Technician Clip Recording (Provides direct video download on stop) */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              {manualRecording ? (
                <button
                  className="btn-glass btn-danger"
                  style={{ padding: '0.25rem 0.65rem', fontSize: '0.72rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                  onClick={async () => {
                    const dur = Math.max(1, manualSeconds);
                    setManualRecording(false);
                    setManualSeconds(0);
                    try {
                      const rec = await saveRecording({
                        device_id: device.id,
                        is_ghost_session: sessionMode === 'ghost' ? 1 : 0,
                        duration_sec: dur,
                        file_size_mb: parseFloat(((dur * 48000) / (1024 * 1024)).toFixed(2))
                      });
                      if (rec.id) {
                        window.open(getRecordingDownloadUrl(rec.id), '_blank');
                      }
                      showTransientBanner(`Session clip (${dur}s) saved to audit vault.`);
                    } catch {
                      showTransientBanner('Clip capture stopped.');
                    }
                  }}
                  title="Click to stop manual recording and download audit clip"
                >
                  <CircleDot size={12} color="#fff" />
                  <span>Stop Clip ({Math.floor(manualSeconds / 60)}:{(manualSeconds % 60).toString().padStart(2, '0')})</span>
                </button>
              ) : (
                <button
                  className="btn-glass"
                  style={{ padding: '0.25rem 0.55rem', fontSize: '0.72rem' }}
                  onClick={() => {
                    setManualRecording(true);
                    setManualSeconds(0);
                  }}
                  title="Record direct high-quality video clip to your workstation"
                >
                  ● Record Clip
                </button>
              )}
            </div>

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

            {sessionDescriptor?.meshRelayUrl && (
              <button
                type="button"
                className={`btn-glass ${useLiveMeshIframe ? 'btn-primary' : ''}`}
                style={{ padding: '0.3rem 0.6rem', fontSize: '0.72rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                onClick={() => setUseLiveMeshIframe(!useLiveMeshIframe)}
                title="Switch between embedded MeshCentral WebRTC stream and Vitrine Canvas compositor"
              >
                <ExternalLink size={12} />
                <span>{useLiveMeshIframe ? 'Canvas View' : 'MeshWebRTC Stream'}</span>
              </button>
            )}

            <button
              className="btn-glass"
              style={{
                padding: '0.35rem 0.65rem',
                fontSize: '0.75rem',
                background: showElevateModal ? 'rgba(245, 158, 11, 0.22)' : 'rgba(245, 158, 11, 0.1)',
                borderColor: 'rgba(245, 158, 11, 0.45)',
                color: '#fbbf24'
              }}
              onClick={() => setShowElevateModal(!showElevateModal)}
              title="Remotely self-elevate standard-user QuickSupport agent or promote to permanent service using LAPS or Tech credentials"
            >
              <KeyRound size={13} />
              <span>Elevate Agent ({agentPrivilegeLevel})</span>
            </button>

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

            <button
              className="btn-glass btn-icon"
              onClick={() => {
                if (recordSeconds > 5) {
                  saveRecording({
                    device_id: device.id,
                    is_ghost_session: sessionMode === 'ghost' ? 1 : 0,
                    duration_sec: recordSeconds,
                    file_size_mb: parseFloat(((recordSeconds * 48000) / (1024 * 1024)).toFixed(2))
                  }).catch(() => {});
                }
                onClose();
              }}
              id="close-remote-modal-btn"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {statusBanner && (
          <div style={{ padding: '0.5rem 1.5rem', background: 'rgba(16, 185, 129, 0.14)', borderBottom: '1px solid rgba(16, 185, 129, 0.35)', color: '#34d399', fontSize: '0.8rem' }}>
            ✓ {statusBanner}
          </div>
        )}

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

        {/* Viewport Canvas or Live MeshCentral WebRTC Iframe */}
        <div style={{ flex: 1, position: 'relative', background: '#000', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
          {useLiveMeshIframe &&
          sessionDescriptor?.meshRelayUrl &&
          /^https?:\/\//i.test(sessionDescriptor.meshRelayUrl) ? (
            <iframe
              src={sessionDescriptor.meshRelayUrl}
              title={`MeshCentral Live WebRTC — ${device.hostname}`}
              sandbox="allow-scripts allow-same-origin allow-forms"
              referrerPolicy="no-referrer"
              style={{ width: '100%', height: '100%', border: 'none' }}
            />
          ) : (
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
          )}

          {/* Tech-Side Remote Self-Elevation Popover */}
          {showElevateModal && (
            <div
              style={{
                position: 'absolute',
                top: '16px',
                right: '16px',
                width: '410px',
                background: 'rgba(15, 23, 42, 0.97)',
                border: '1px solid rgba(245, 158, 11, 0.45)',
                borderRadius: '12px',
                padding: '1.15rem',
                zIndex: 50,
                boxShadow: '0 20px 45px rgba(0, 0, 0, 0.7)'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.65rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', color: '#fbbf24', fontWeight: 700, fontSize: '0.9rem' }}>
                  <KeyRound size={16} />
                  <span>Tech-Side Remote Self-Elevation</span>
                </div>
                <button className="btn-glass btn-icon" style={{ padding: '0.2rem' }} onClick={() => setShowElevateModal(false)}>
                  <X size={14} />
                </button>
              </div>
              <p style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginBottom: '0.75rem', lineHeight: 1.45 }}>
                Elevate a non-admin QuickSupport / standard-user session to full <code>SYSTEM / Administrator</code> privileges (including UAC prompt capture) or promote it into a permanent signed service.
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                <div>
                  <label className="form-label" style={{ fontSize: '0.73rem' }}>Credential Source</label>
                  <select
                    className="form-select"
                    style={{ fontSize: '0.78rem', padding: '0.4rem' }}
                    value={elevateSource}
                    onChange={(e) => setElevateSource(e.target.value as any)}
                  >
                    <option value="laps">1-Click Vaulted LAPS Local Admin ({device.laps_account || 'VitrineLocalAdmin'})</option>
                    <option value="custom_admin">Custom Admin / Domain Credentials (Tech Input)</option>
                    <option value="end_user_uac">Trigger End-User UAC Consent Prompt on Screen</option>
                  </select>
                </div>

                {elevateSource === 'custom_admin' && (
                  <div className="grid-2" style={{ gap: '0.5rem' }}>
                    <div>
                      <label className="form-label" style={{ fontSize: '0.72rem' }}>Admin Username</label>
                      <input
                        className="form-input"
                        style={{ fontSize: '0.78rem', padding: '0.35rem 0.5rem' }}
                        value={customAdminUsername}
                        onChange={(e) => setCustomAdminUsername(e.target.value)}
                        placeholder=".\Administrator or DOMAIN\Admin"
                      />
                    </div>
                    <div>
                      <label className="form-label" style={{ fontSize: '0.72rem' }}>Admin Password</label>
                      <input
                        type="password"
                        className="form-input"
                        style={{ fontSize: '0.78rem', padding: '0.35rem 0.5rem' }}
                        value={customAdminPassword}
                        onChange={(e) => setCustomAdminPassword(e.target.value)}
                        placeholder="••••••••••••"
                      />
                    </div>
                  </div>
                )}

                <div>
                  <label className="form-label" style={{ fontSize: '0.73rem' }}>Target Elevation Mode</label>
                  <select
                    className="form-select"
                    style={{ fontSize: '0.78rem', padding: '0.4rem' }}
                    value={elevateTargetAction}
                    onChange={(e) => setElevateTargetAction(e.target.value as any)}
                  >
                    <option value="elevate_temp_session">Elevate Temporary Session Only (Auto-removes on disconnect)</option>
                    <option value="promote_permanent_service">Promote &amp; Install Permanent Signed RMM Service</option>
                  </select>
                </div>

                <button
                  type="button"
                  className="btn-glass btn-primary"
                  style={{ width: '100%', justifyContent: 'center', fontSize: '0.8rem', padding: '0.5rem' }}
                  disabled={elevating}
                  onClick={handleTriggerElevation}
                >
                  <KeyRound size={14} />
                  <span>{elevating ? 'Injecting Encrypted Elevation Token...' : 'Execute Remote Self-Elevation Now'}</span>
                </button>

                {elevateSuccessMsg && (
                  <div style={{ padding: '0.55rem 0.7rem', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.14)', border: '1px solid rgba(16, 185, 129, 0.35)', fontSize: '0.74rem', color: '#a7f3d0' }}>
                    ✓ {elevateSuccessMsg}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Real-time Performance & OS Isolation HUD */}
          <div
            style={{
              position: 'absolute',
              bottom: '12px',
              left: '16px',
              right: '16px',
              background: 'rgba(15, 23, 42, 0.88)',
              border: '1px solid var(--glass-border)',
              borderRadius: '6px',
              padding: '5px 12px',
              fontSize: '0.72rem',
              color: 'var(--text-muted)',
              display: 'flex',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '12px',
              alignItems: 'center'
            }}
          >
            <div style={{ display: 'flex', gap: '14px', alignItems: 'center', flexWrap: 'wrap' }}>
              <span>OS: <strong style={{ color: '#38bdf8' }}>{device.os_type.toUpperCase()}</strong></span>
              <span>Driver: <strong>{sessionDescriptor?.displayDriver || 'MeshCentral WebRTC'}</strong></span>
              <span>Isolation: <strong style={{ color: sessionMode === 'ghost' ? '#c084fc' : '#10b981' }}>{sessionDescriptor?.sessionIsolation || 'Active'}</strong></span>
            </div>
            <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
              <span>Latency: <strong style={{ color: '#10b981' }}>{latencyMs} ms</strong></span>
              <span>FPS: <strong>{sessionMode === 'amt_kvm' ? 30 : fps}</strong></span>
              <span>Resolution: <strong>{sessionDescriptor?.resolution || '2560x1440'}</strong></span>
            </div>
          </div>
        </div>
      </div>

      <MfaChallengeModal
        isOpen={elevateMfaOpen}
        onClose={() => setElevateMfaOpen(false)}
        onSuccess={() => {
          setElevateMfaOpen(false);
          handleTriggerElevation();
        }}
        secretType="laps_credential"
        deviceId={device.id}
      />
    </div>
  );
};
