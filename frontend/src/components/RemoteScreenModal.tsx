import React, { useState, useEffect, useRef } from 'react';
import {
  Monitor,
  X,
  Lock,
  Shield,
  EyeOff,
  CircleDot,
  Cpu,
  ExternalLink,
  KeyRound,
  RefreshCw,
  AlertTriangle,
  Video
} from 'lucide-react';
import { Device, RemoteSessionDescriptor } from '../types/index.js';
import {
  fetchSettings,
  fetchDeviceConsentStatus,
  negotiateRemoteSession,
  elevateRemoteAgent,
  startGuestPortalRemoteSession,
  saveRecording,
  lockDeviceScreen,
  bypassRemoteConsent
} from '../services/api.js';
import { MfaChallengeModal } from './MfaChallengeModal.js';
import { isIntelAmtEligible, isTemporaryOrNonServiceAgent } from '../utils/deviceHelpers.js';
import { sanitizeSafeUrl } from '../utils/urlSafety.js';

interface RemoteScreenModalProps {
  device: Device;
  isGhostSession?: boolean;
  guestGrantId?: string;
  guestPermissions?: {
    canRemoteScreen?: boolean;
    canGhostSession?: boolean;
  };
  onClose: () => void;
}

export const RemoteScreenModal: React.FC<RemoteScreenModalProps> = ({
  device,
  isGhostSession = false,
  guestGrantId,
  guestPermissions,
  onClose
}) => {
  const isGuestPortal = Boolean(guestGrantId);
  const amtEligible = isIntelAmtEligible(device);
  const showElevateButton = isTemporaryOrNonServiceAgent(device);
  const canUseKvm = !isGuestPortal || !guestPermissions || guestPermissions.canRemoteScreen !== false;
  const canUseGhost = !isGuestPortal || !guestPermissions || Boolean(guestPermissions.canGhostSession);
  const [sessionMode, setSessionMode] = useState<'kvm' | 'ghost' | 'amt_kvm'>(
    isGhostSession && canUseGhost ? 'ghost' : canUseKvm ? 'kvm' : 'ghost'
  );
  const [sessionDescriptor, setSessionDescriptor] = useState<RemoteSessionDescriptor | null>(null);
  const [sessionLoading, setSessionLoading] = useState(true);
  const [sessionRetrySeq, setSessionRetrySeq] = useState(0);
  const [consentGranted, setConsentGranted] = useState(false);
  const [consentCountdown, setConsentCountdown] = useState(15);
  const [consentTimeoutAction, setConsentTimeoutAction] = useState<string>('deny');
  const [consentTimedOut, setConsentTimedOut] = useState(false);
  const [consentConfigLoaded, setConsentConfigLoaded] = useState(false);
  const [consentRetrySeq, setConsentRetrySeq] = useState(0);
  const [bypassingConsent, setBypassingConsent] = useState(false);
  const [consentError, setConsentError] = useState<string | null>(null);
  const [autoLockOnDisconnect, setAutoLockOnDisconnect] = useState(true);
  const [isRecording, setIsRecording] = useState(true);
  const [recordSeconds, setRecordSeconds] = useState(0);
  const [stealthForTechs, setStealthForTechs] = useState(false);
  const [videoCapturing, setVideoCapturing] = useState(false);
  const [closingAndSaving, setClosingAndSaving] = useState(false);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const mediaStreamRef = useRef<MediaStream | null>(null);
  const recordedChunksRef = useRef<Blob[]>([]);
  const savedRecordingRef = useRef(false);

  // Tech-Side Remote Self-Elevation state
  const [showElevateModal, setShowElevateModal] = useState(false);
  const [elevateSource, setElevateSource] = useState<'laps' | 'custom_admin' | 'end_user_uac'>('laps');
  const [elevateTargetAction, setElevateTargetAction] = useState<'elevate_temp_session' | 'promote_permanent_service'>('elevate_temp_session');
  const [customAdminUsername, setCustomAdminUsername] = useState('.\\Administrator');
  const [customAdminPassword, setCustomAdminPassword] = useState('');
  const [elevating, setElevating] = useState(false);
  const [elevateSuccessMsg, setElevateSuccessMsg] = useState<string | null>(null);
  const [elevateIsError, setElevateIsError] = useState(false);
  const [elevateMfaOpen, setElevateMfaOpen] = useState(false);
  const [statusBanner, setStatusBanner] = useState<string | null>(null);
  const [agentPrivilegeLevel, setAgentPrivilegeLevel] = useState<string>(device.agent_privilege_mode || 'system_service');

  const showTransientBanner = (msg: string) => {
    setStatusBanner(msg);
    setTimeout(() => setStatusBanner(null), 4000);
  };

  useEffect(() => {
    if (sessionMode === 'amt_kvm' && !amtEligible) {
      setSessionMode(canUseKvm ? 'kvm' : 'ghost');
    }
  }, [amtEligible, canUseKvm, sessionMode]);

  // Negotiate live MeshCentral relay session URL with backend
  useEffect(() => {
    let active = true;
    setSessionLoading(true);
    if (guestGrantId) {
      startGuestPortalRemoteSession(
        guestGrantId,
        device.id,
        sessionMode === 'ghost' ? 'ghost' : 'interactive'
      )
        .then((res) => {
          if (!active) return;
          if (res?.success) {
            const relayUrl = (res as any).session?.meshRelayUrl || res.meshRelayUrl || null;
            setSessionDescriptor({
              success: true,
              sessionId: res.sessionId || `guest-${Date.now()}`,
              deviceId: device.id,
              hostname: device.hostname,
              osType: device.os_type,
              mode: sessionMode,
              monitor: 1,
              displayDriver: relayUrl ? 'MeshCentral Live Relay' : 'Scoped Vendor KVM Relay',
              sessionIsolation:
                sessionMode === 'ghost'
                  ? 'Scoped Vendor Ghost Session'
                  : 'Scoped Vendor Interactive Session',
              audioPipeline: 'WebAudio Opus',
              resolution: '1920x1080',
              meshRelayUrl: relayUrl,
              meshBridgeConnected: Boolean(relayUrl),
              userInterference: sessionMode === 'ghost' ? 'None (Background Isolated)' : 'Shared Console'
            });
            setConsentGranted(true);
          }
        })
        .catch(() => {})
        .finally(() => {
          if (active) setSessionLoading(false);
        });
      return () => {
        active = false;
      };
    }

    negotiateRemoteSession(device.id, sessionMode, 1)
      .then((desc) => {
        if (!active) return;
        setSessionDescriptor(desc);
      })
      .catch(() => {})
      .finally(() => {
        if (active) setSessionLoading(false);
      });

    return () => {
      active = false;
    };
  }, [device.id, device.hostname, device.os_type, guestGrantId, sessionMode, sessionRetrySeq]);

  // Load stealth settings & policy consent configuration
  useEffect(() => {
    if (guestGrantId) {
      setConsentGranted(true);
      setConsentConfigLoaded(true);
      return;
    }
    fetchSettings()
      .then((s) => {
        setStealthForTechs(Boolean(s.session_recording_stealth_for_techs));
      })
      .catch(() => {});
    fetchDeviceConsentStatus(device.id)
      .then((cs) => {
        if (cs) {
          setAutoLockOnDisconnect(Boolean(cs.autoLockOnDisconnect));
          const resolvedAction = String((cs as any).consent_timeout_action || cs.timeoutAction || 'deny').toLowerCase();
          setConsentTimeoutAction(resolvedAction);
          if (!cs.requireConsent || cs.bypassedDueToLockScreen) {
            setConsentGranted(true);
          } else if (cs.timeoutSec) {
            setConsentCountdown(cs.timeoutSec);
          }
        }
      })
      .catch(() => {})
      .finally(() => setConsentConfigLoaded(true));
  }, [device.id, guestGrantId]);

  // Timer for active server-side recording
  useEffect(() => {
    if (!isRecording) return;
    const interval = setInterval(() => {
      setRecordSeconds((s) => s + 1);
    }, 1000);
    return () => clearInterval(interval);
  }, [isRecording]);

  useEffect(() => {
    return () => {
      try {
        if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
          mediaRecorderRef.current.stop();
        }
      } catch {
        // Ignore recorder cleanup failure
      }
      try {
        mediaStreamRef.current?.getTracks().forEach((t) => t.stop());
      } catch {
        // Ignore stream track cleanup failure
      }
    };
  }, []);

  const handleToggleVideoCapture = async () => {
    if (videoCapturing) {
      try {
        if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
          mediaRecorderRef.current.stop();
        }
      } catch {
        // Ignore recorder stop error
      }
      try {
        mediaStreamRef.current?.getTracks().forEach((t) => t.stop());
      } catch {
        // Ignore stream track stop error
      }
      setVideoCapturing(false);
      showTransientBanner('Video capture stopped. Recording will save when session closes.');
      return;
    }
    if (!navigator.mediaDevices?.getDisplayMedia || typeof MediaRecorder === 'undefined') {
      showTransientBanner('Browser screen capture API is unavailable in this environment.');
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false });
      recordedChunksRef.current = [];
      const mimeType = MediaRecorder.isTypeSupported('video/webm;codecs=vp9')
        ? 'video/webm;codecs=vp9'
        : 'video/webm';
      const recorder = new MediaRecorder(stream, { mimeType });
      recorder.ondataavailable = (ev) => {
        if (ev.data && ev.data.size > 0) recordedChunksRef.current.push(ev.data);
      };
      stream.getVideoTracks().forEach((track) => {
        track.onended = () => setVideoCapturing(false);
      });
      recorder.start(1000);
      mediaStreamRef.current = stream;
      mediaRecorderRef.current = recorder;
      setVideoCapturing(true);
      showTransientBanner('Capturing WebM session video — it will save to Session Recordings on close.');
    } catch {
      showTransientBanner('Screen capture permission cancelled.');
    }
  };

  const handleClose = async () => {
    if (closingAndSaving) return;
    setClosingAndSaving(true);
    try {
      let videoBase64: string | undefined;
      let mimeType: string | undefined;

      if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
        const rec = mediaRecorderRef.current;
        await new Promise<void>((resolve) => {
          const fallbackTimer = setTimeout(resolve, 800);
          rec.onstop = () => {
            clearTimeout(fallbackTimer);
            resolve();
          };
          try {
            rec.stop();
          } catch {
            clearTimeout(fallbackTimer);
            resolve();
          }
        });
      }
      try {
        mediaStreamRef.current?.getTracks().forEach((t) => t.stop());
      } catch {
        // Ignore stream track stop error
      }

      if (recordedChunksRef.current.length > 0) {
        const blob = new Blob(recordedChunksRef.current, { type: 'video/webm' });
        if (blob.size > 0 && blob.size <= 35 * 1024 * 1024) {
          mimeType = 'video/webm';
          videoBase64 = await new Promise<string>((resolve) => {
            const reader = new FileReader();
            reader.onloadend = () => resolve(String(reader.result || ''));
            reader.readAsDataURL(blob);
          });
        }
      }

      if (
        !savedRecordingRef.current &&
        !isGuestPortal &&
        consentGranted &&
        (sessionDescriptor?.recordingEnabled || Boolean(videoBase64)) &&
        (recordSeconds >= 1 || Boolean(videoBase64))
      ) {
        savedRecordingRef.current = true;
        await saveRecording({
          device_id: device.id,
          duration_sec: Math.max(1, recordSeconds),
          is_ghost_session: sessionMode === 'ghost',
          ...(videoBase64 ? { video_base64: videoBase64, mime_type: mimeType } : {})
        }).catch(() => {});
      }

      if (autoLockOnDisconnect && !isGuestPortal && consentGranted) {
        await lockDeviceScreen(device.id).catch(() => {});
      }
    } finally {
      setClosingAndSaving(false);
      onClose();
    }
  };

  // Ghost Sessions and Out-of-Band AMT KVM never interrupt or prompt the physical user
  const bypassesUserPrompt =
    device.device_role.toLowerCase().includes('server') ||
    device.device_role.toLowerCase().includes('controller') ||
    sessionMode === 'ghost' ||
    sessionMode === 'amt_kvm';

  useEffect(() => {
    if (bypassesUserPrompt) {
      setConsentTimedOut(false);
      setConsentGranted(true);
      return;
    }
    if (!consentConfigLoaded || consentGranted || consentTimedOut) return;
    const timer = setInterval(() => {
      setConsentCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          if (consentTimeoutAction === 'allow') {
            setConsentGranted(true);
          } else {
            setConsentTimedOut(true);
          }
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [bypassesUserPrompt, consentConfigLoaded, consentGranted, consentTimedOut, consentTimeoutAction, consentRetrySeq]);

  const handleToggleRecording = () => {
    const next = !isRecording;
    setIsRecording(next);
    const rec = mediaRecorderRef.current;
    if (rec) {
      try {
        if (!next && rec.state === 'recording') {
          rec.pause();
        } else if (next && rec.state === 'paused') {
          rec.resume();
        }
      } catch {
        // MediaRecorder pause/resume unsupported in current browser
      }
    }
  };

  const handleBypassConsent = async () => {
    setBypassingConsent(true);
    setConsentError(null);
    try {
      const res = await bypassRemoteConsent(device.id);
      if (res.success) {
        setConsentGranted(true);
        showTransientBanner(`Consent bypass authorized and audited for ${device.hostname}.`);
      } else {
        setConsentError(res.error || 'Failed to bypass remote user consent.');
      }
    } catch (e: any) {
      setConsentError(e?.message || 'Failed to bypass remote user consent.');
    } finally {
      setBypassingConsent(false);
    }
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
        setElevateIsError(false);
        setElevateSuccessMsg(res.message);
      } else {
        setElevateIsError(true);
        setElevateSuccessMsg(res.error || 'Remote elevation failed');
      }
    } catch (e: any) {
      setElevateIsError(true);
      setElevateSuccessMsg(e?.message || 'Remote elevation failed');
    } finally {
      setElevating(false);
    }
  };

  const safeMeshRelayUrl = sanitizeSafeUrl(sessionDescriptor?.meshRelayUrl, false);
  const safeServerUrl = sanitizeSafeUrl(sessionDescriptor?.serverUrl, false);
  const liveStreamActive = Boolean(safeMeshRelayUrl);

  return (
    <div className="modal-backdrop" id="remote-screen-modal">
      <div className="glass-modal glass-modal-lg" style={{ height: '92vh', maxWidth: '1380px' }}>
        {/* Modal Header */}
        <div className="modal-header" style={{ padding: '0.85rem 1.5rem' }}>
          <div className="modal-title" style={{ fontSize: '1.02rem', gap: '0.6rem', flexWrap: 'wrap' }}>
            {sessionMode === 'ghost' ? (
              <>
                <EyeOff size={18} style={{ color: '#a855f7' }} />
                <span>Ghost Backstage Session — {device.hostname}</span>
                <span className="status-pill status-isolated" style={{ background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc', border: '1px solid rgba(168, 85, 247, 0.3)' }}>
                  Background Terminal / Session Relay (User Undisturbed)
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

            {/* Mode Switcher */}
            <div style={{ display: 'flex', background: 'rgba(0, 0, 0, 0.35)', borderRadius: '6px', padding: '2px', marginLeft: '0.5rem' }}>
              {canUseKvm && (
                <button
                  type="button"
                  className={`btn-glass ${sessionMode === 'kvm' ? 'btn-primary' : ''}`}
                  style={{ padding: '0.2rem 0.55rem', fontSize: '0.72rem' }}
                  onClick={() => setSessionMode('kvm')}
                >
                  Standard KVM
                </button>
              )}
              {canUseGhost && (
                <button
                  type="button"
                  className={`btn-glass ${sessionMode === 'ghost' ? 'btn-primary' : ''}`}
                  style={{ padding: '0.2rem 0.55rem', fontSize: '0.72rem' }}
                  onClick={() => setSessionMode('ghost')}
                  title="Open an isolated background MeshCentral session without interfering with the logged-in user console"
                >
                  Ghost Session (Backstage)
                </button>
              )}
              {!isGuestPortal && amtEligible && (
                <button
                  type="button"
                  className={`btn-glass ${sessionMode === 'amt_kvm' ? 'btn-primary' : ''}`}
                  style={{ padding: '0.2rem 0.55rem', fontSize: '0.72rem' }}
                  onClick={() => setSessionMode('amt_kvm')}
                  title="Out-of-Band Intel AMT / vPro Hardware KVM (BIOS / Pre-Boot)"
                >
                  Intel AMT KVM
                </button>
              )}
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            {/* Server-Side Session Recording Indicator (Shown only if NOT in Admin Stealth Mode or Guest Portal) */}
            {!stealthForTechs && !isGuestPortal && sessionDescriptor?.recordingEnabled && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                {isRecording ? (
                  <button
                    type="button"
                    onClick={handleToggleRecording}
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
                    title="Compliance session recording active (Click to pause timer & capture)"
                  >
                    <CircleDot size={12} className="animate-pulse" color="#ef4444" />
                    <span>
                      REC {Math.floor(recordSeconds / 60).toString().padStart(2, '0')}:
                      {(recordSeconds % 60).toString().padStart(2, '0')}
                    </span>
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={handleToggleRecording}
                    className="btn-glass"
                    style={{ fontSize: '0.72rem', color: 'var(--text-dim)', padding: '0.2rem 0.55rem' }}
                    title="Resume recording timer & capture"
                  >
                    Resume REC
                  </button>
                )}
                <button
                  type="button"
                  onClick={handleToggleVideoCapture}
                  className="btn-glass"
                  style={{
                    fontSize: '0.72rem',
                    padding: '0.22rem 0.55rem',
                    borderColor: videoCapturing ? 'rgba(192, 132, 252, 0.55)' : undefined,
                    color: videoCapturing ? '#d8b4fe' : undefined
                  }}
                  title="Capture browser tab as playable WebM video saved to Session Recordings"
                >
                  <Video size={12} />
                  <span>{videoCapturing ? 'Stop Video' : 'Capture Video'}</span>
                </button>
              </div>
            )}

            {liveStreamActive && safeMeshRelayUrl && (
              <button
                type="button"
                className="btn-glass btn-primary"
                style={{ padding: '0.3rem 0.65rem', fontSize: '0.74rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                onClick={() => window.open(safeMeshRelayUrl, '_blank', 'noopener,noreferrer')}
                title="Open live MeshCentral session stream in a full browser tab"
              >
                <ExternalLink size={13} />
                <span>Open Live Stream in New Tab</span>
              </button>
            )}

            {!isGuestPortal && showElevateButton && agentPrivilegeLevel !== 'system_service' && (
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
            )}

            {!isGuestPortal && (
              <button
                type="button"
                className="btn-glass"
                style={{
                  padding: '0.3rem 0.6rem',
                  fontSize: '0.73rem',
                  borderColor: autoLockOnDisconnect ? 'rgba(16, 185, 129, 0.45)' : undefined,
                  color: autoLockOnDisconnect ? '#10b981' : 'var(--text-muted)'
                }}
                onClick={() => setAutoLockOnDisconnect(!autoLockOnDisconnect)}
                title={
                  autoLockOnDisconnect
                    ? 'Endpoint screen will lock automatically when this session disconnects'
                    : 'Auto-Lock on Disconnect is disabled'
                }
              >
                <Lock size={13} color={autoLockOnDisconnect ? '#10b981' : '#94a3b8'} />
                <span>Auto-Lock on Disconnect</span>
              </button>
            )}

            <button
              type="button"
              className="btn-glass btn-icon"
              onClick={handleClose}
              disabled={closingAndSaving}
              id="close-remote-modal-btn"
              aria-label="Close remote session"
              title="Close"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {statusBanner && (
          <div style={{ padding: '0.5rem 1.5rem', background: 'rgba(16, 185, 119, 0.14)', borderBottom: '1px solid rgba(16, 185, 129, 0.35)', color: '#34d399', fontSize: '0.8rem' }}>
            ✓ {statusBanner}
          </div>
        )}

        {/* Consent Warning Banner (Feature 9) */}
        {!consentGranted && (
          <div
            style={{
              padding: '0.75rem 1.5rem',
              background: consentTimedOut ? 'rgba(239, 68, 68, 0.16)' : 'rgba(245, 158, 11, 0.15)',
              borderBottom: `1px solid ${consentTimedOut ? 'rgba(239, 68, 68, 0.4)' : 'rgba(245, 158, 11, 0.3)'}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '0.75rem',
              color: consentTimedOut ? '#f87171' : '#fbbf24',
              fontSize: '0.85rem'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <Shield size={18} />
              {consentTimedOut ? (
                <span>
                  <strong>End-user consent timed out (Denied by policy):</strong> The remote user did not approve interactive screen sharing within the policy window.
                </span>
              ) : (
                <span>
                  <strong>User Privacy Policy Enforced:</strong> Prompting end-user on target endpoint ({consentCountdown}s remaining — timeout action:{' '}
                  <strong>{consentTimeoutAction === 'allow' ? 'Auto-Allow' : 'Deny Session'}</strong>).
                </span>
              )}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              {consentTimedOut && (
                <>
                  <button
                    type="button"
                    className="btn-glass"
                    style={{ padding: '0.25rem 0.75rem', fontSize: '0.75rem' }}
                    onClick={() => {
                      setConsentTimedOut(false);
                      setConsentCountdown(15);
                      setConsentRetrySeq((s) => s + 1);
                    }}
                  >
                    Retry Prompt
                  </button>
                  <button
                    type="button"
                    className="btn-glass btn-danger"
                    style={{ padding: '0.25rem 0.75rem', fontSize: '0.75rem' }}
                    onClick={onClose}
                  >
                    Close
                  </button>
                </>
              )}
              {!isGuestPortal && !consentTimedOut && (
                <button
                  type="button"
                  className="btn-glass"
                  style={{ padding: '0.25rem 0.75rem', fontSize: '0.75rem', background: '#f59e0b', color: '#000', fontWeight: 600 }}
                  disabled={bypassingConsent}
                  onClick={handleBypassConsent}
                >
                  {bypassingConsent ? 'Authorizing Bypass...' : 'Bypass Consent (Admin Elevation)'}
                </button>
              )}
            </div>
          </div>
        )}

        {consentError && !consentGranted && (
          <div style={{ padding: '0.5rem 1.5rem', background: 'rgba(239, 68, 68, 0.14)', borderBottom: '1px solid rgba(239, 68, 68, 0.35)', color: '#f87171', fontSize: '0.8rem' }}>
            {consentError}
          </div>
        )}

        {/* Live MeshCentral WebRTC Iframe or Honest Connection Diagnostics */}
        <div style={{ flex: 1, position: 'relative', background: '#070b14', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {liveStreamActive && consentGranted && safeMeshRelayUrl ? (
            <>
              <div
                style={{
                  padding: '0.35rem 1rem',
                  background: 'rgba(15, 23, 42, 0.9)',
                  borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
                  fontSize: '0.73rem',
                  color: 'var(--text-dim)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  gap: '0.75rem',
                  flexWrap: 'wrap'
                }}
              >
                <span>
                  Connected via {sessionDescriptor?.shareLinkSource === 'meshcentral_share_link' ? 'authenticated MeshCentral Share Link' : 'MeshCentral Direct Node Relay'}. Use the native MeshCentral toolbar inside the stream for Ctrl+Alt+Del, clipboard, audio, and monitor selection.
                </span>
                <button
                  type="button"
                  className="btn-glass"
                  style={{ padding: '0.18rem 0.55rem', fontSize: '0.71rem' }}
                  onClick={() => setSessionRetrySeq((s) => s + 1)}
                >
                  <RefreshCw size={11} /> Re-Negotiate
                </button>
              </div>
              <iframe
                src={safeMeshRelayUrl}
                title={`MeshCentral Live WebRTC — ${device.hostname}`}
                sandbox="allow-scripts allow-same-origin allow-forms"
                referrerPolicy="no-referrer"
                style={{ flex: 1, width: '100%', height: '100%', border: 'none' }}
              />
            </>
          ) : liveStreamActive && !consentGranted ? (
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '2rem' }}>
              <div className="glass-card" style={{ maxWidth: '520px', textAlign: 'center', padding: '2rem' }}>
                <Shield size={32} color="#fbbf24" style={{ marginBottom: '0.75rem' }} />
                <h3 style={{ margin: '0 0 0.5rem' }}>Waiting for User Privacy Consent</h3>
                <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)', margin: 0 }}>
                  Live video relay for {device.hostname} is ready and will mount as soon as consent is approved or bypassed.
                </p>
              </div>
            </div>
          ) : (
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '2rem' }}>
              <div className="glass-card" style={{ maxWidth: '600px', width: '100%', padding: '1.75rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <AlertTriangle size={24} color="#fbbf24" />
                  <div>
                    <h3 style={{ margin: 0, fontSize: '1.08rem' }}>
                      {sessionLoading
                        ? `Negotiating Live MeshCentral Relay for ${device.hostname}...`
                        : 'Live Remote Display Relay Unavailable'}
                    </h3>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>
                      Device Status: <strong>{String(device.status || 'unknown').toUpperCase()}</strong> • MeshCentral Bridge:{' '}
                      <strong style={{ color: sessionDescriptor?.meshBridgeConnected ? '#34d399' : '#f87171' }}>
                        {sessionDescriptor?.meshBridgeConnected ? 'Connected' : 'Disconnected'}
                      </strong>
                    </div>
                  </div>
                </div>

                <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.25)', borderRadius: '8px', padding: '0.85rem 1rem', fontSize: '0.8rem', color: '#fca5a5', lineHeight: 1.5 }}>
                  {sessionDescriptor?.meshRelayError ||
                    (device.status !== 'online'
                      ? `${device.hostname} is currently ${device.status}. Bring the endpoint online (or use Wake-on-LAN / Power Control) before starting a live remote stream.`
                      : 'MeshCentral did not return a live sharing URL for this node. Verify Settings -> MeshCentral URL & Login Token and ensure the agent is online in MeshCentral.')}
                </div>

                {sessionMode === 'ghost' && (
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: 1.45 }}>
                    Note: Ghost / Backstage mode uses MeshCentral&apos;s background terminal relay (<code>{sessionDescriptor?.displayDriver || 'Background PTY'}</code>) rather than an interactive desktop screen capture so the logged-in user is never interrupted.
                  </div>
                )}

                <div style={{ display: 'flex', gap: '0.65rem', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    className="btn-glass btn-primary"
                    onClick={() => setSessionRetrySeq((s) => s + 1)}
                    disabled={sessionLoading}
                  >
                    <RefreshCw size={14} className={sessionLoading ? 'spin' : ''} />
                    <span>{sessionLoading ? 'Connecting...' : 'Retry Connection'}</span>
                  </button>
                  {safeServerUrl && (
                    <button
                      type="button"
                      className="btn-glass"
                      onClick={() => window.open(safeServerUrl, '_blank', 'noopener,noreferrer')}
                    >
                      <ExternalLink size={14} />
                      <span>Open MeshCentral Console</span>
                    </button>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Tech-Side Remote Self-Elevation Popover */}
          {showElevateModal && (
            <div
              style={{
                position: 'absolute',
                top: '16px',
                right: '16px',
                width: 'min(410px, 92vw)',
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
                  <div
                    style={{
                      padding: '0.55rem 0.7rem',
                      borderRadius: '8px',
                      background: elevateIsError ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.14)',
                      border: `1px solid ${elevateIsError ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                      fontSize: '0.74rem',
                      color: elevateIsError ? '#f87171' : '#a7f3d0'
                    }}
                  >
                    {elevateIsError ? '⚠ ' : '✓ '}
                    {elevateSuccessMsg}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Honest Session & Relay Status Bar */}
          <div
            style={{
              background: 'rgba(15, 23, 42, 0.94)',
              borderTop: '1px solid var(--glass-border)',
              padding: '6px 16px',
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
              <span>
                Relay Source:{' '}
                <strong style={{ color: liveStreamActive ? '#10b981' : '#fbbf24' }}>
                  {sessionDescriptor?.shareLinkSource === 'meshcentral_share_link'
                    ? 'MeshCentral Authenticated Share Link'
                    : sessionDescriptor?.shareLinkSource === 'meshcentral_gotonode'
                      ? 'MeshCentral Direct Node Relay'
                      : 'Not Connected'}
                </strong>
              </span>
              <span>
                MeshCentral Bridge:{' '}
                <strong style={{ color: sessionDescriptor?.meshBridgeConnected ? '#10b981' : '#f87171' }}>
                  {sessionDescriptor?.meshBridgeConnected ? 'Connected' : 'Disconnected'}
                </strong>
              </span>
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
