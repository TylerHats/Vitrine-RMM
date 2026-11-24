import React, { useState, useEffect, useRef } from 'react';
import {
  Cpu,
  HardDrive,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Monitor,
  EyeOff,
  KeyRound,
  Activity,
  ArrowLeft,
  Lock,
  Power,
  Clock,
  MessageSquare,
  Award,
  Send,
  Save,
  CheckCircle2,
  RotateCw,
  Copy,
  Eye,
  History,
  Network,
  AlertTriangle,
  Check,
  Laptop,
  Package,
  Zap,
  FileText,
  Video,
  Plus,
  Trash2,
  Archive,
  Download,
  BarChart3,
  Server,
  ChevronDown,
  ExternalLink
} from 'lucide-react';
import { AuthUser, Device, DeviceItflowStatus, CustomFieldDefinition, OemWarranty, ChatMessage, HardwareHistoryItem, NetworkHistoryItem, SoftwareItem, DeviceNote, SessionRecording, WakeOnLanResult, DeviceBackupJob, DocumentationArticle, TelemetryHistoryResponse, DeviceHardwareDetails, Settings } from '../types/index.js';
import {
  fetchDeviceCustomFields,
  revealDeviceSecretCustomFields,
  saveDeviceCustomFields,
  fetchWarranty,
  triggerWarrantyLookup,
  fetchChatMessages,
  sendChatMessage,
  toggleDeviceMaintenance,
  fetchHardwareHistory,
  fetchNetworkHistory,
  fetchDeviceSoftware,
  upgradeDeviceSoftware,
  wakeDeviceOnLan,
  enableDeviceWakeOnLan,
  provisionDeviceAmt,
  fetchDeviceNotes,
  createDeviceNote,
  deleteDeviceNote,
  fetchRecordings,
  getRecordingDownloadUrl,
  revealDeviceBitlockerKey,
  fetchWsTicket,
  elevateRemoteAgent,
  offboardDevice,
  forceArchiveDevice,
  simulateDeviceCheckin,
  purgeArchivedDevice,
  runEndpointSecurityAction,
  fetchDeviceBackupJobs,
  runDeviceBackupNow,
  fetchDocumentation,
  acknowledgeHardwareDrift,
  deployDeviceCompanion,
  syncDeviceHardwareFromMesh,
  fetchDeviceTelemetryHistory,
  sampleDeviceTelemetryNow,
  fetchDeviceHardwareDetails,
  updateDeviceRole,
  syncSingleDeviceToItflow,
  fetchDeviceDetail
} from '../services/api.js';
import { MfaChallengeModal } from '../components/MfaChallengeModal.js';
import { TelemetryChartCard } from '../components/TelemetryCharts.js';
import { copyToClipboard } from '../utils/clipboard.js';
import { canMutateFleet } from '../utils/permissions.js';
import { isIntelAmtEligible, isTemporaryOrNonServiceAgent } from '../utils/deviceHelpers.js';

interface DeviceDetailViewProps {
  device: Device;
  onBack: () => void;
  onOpenRemote: (device: Device, isGhost: boolean) => void;
  onOpenBgTools: (device: Device, initialTab?: string) => void;
  onOpenLaps: (device: Device) => void;
  onOpenQuarantine: (device: Device) => void;
  currentUser?: AuthUser | null;
  settings?: Settings | null;
  onRefreshFleet?: () => void;
}

function parseFieldOptions(raw?: string | null): string[] {
  if (!raw) return [];
  const trimmed = raw.trim();
  if (!trimmed) return [];
  if (trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed)) return parsed.map((v) => String(v));
    } catch {
      // Fallback to comma-separated parsing if JSON is malformed
    }
  }
  return trimmed
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

const PCI_VENDORS: Record<string, string> = {
  '0x802C': 'Micron / Crucial Technology',
  '0x144D': 'Samsung Electronics',
  '0x10DE': 'NVIDIA Corporation',
  '0x8086': 'Intel Corporation',
  '0x1002': 'AMD / Radeon Technologies',
  '0x15B7': 'Western Digital / SanDisk',
  '0x10EC': 'Realtek Semiconductor',
  '0x14E4': 'Broadcom'
};

function formatVendor(vendorId?: string): string {
  if (!vendorId) return 'Generic OEM';
  return PCI_VENDORS[vendorId] || `Vendor ID ${vendorId}`;
}

function formatUptime(seconds?: number | null): string {
  const s = Number(seconds || 0);
  if (!Number.isFinite(s) || s <= 0) return 'Not reported';
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const mins = Math.floor((s % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${mins}m`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

export const DeviceDetailView: React.FC<DeviceDetailViewProps> = ({
  device,
  onBack,
  onOpenRemote,
  onOpenBgTools,
  onOpenLaps,
  onOpenQuarantine,
  currentUser,
  settings,
  onRefreshFleet
}) => {
  const canMutate = canMutateFleet(currentUser);
  const enableLabDemo = import.meta.env.VITE_ENABLE_LAB_DEMO === 'true';
  const [activeTab, setActiveTab] = useState<'overview' | 'performance' | 'hardware' | 'history' | 'software' | 'attributes' | 'chat'>('overview');

  // Maintenance state
  const [isMaintenanceActive, setIsMaintenanceActive] = useState(Boolean(device.maintenance_active));
  const [maintenanceUntil, setMaintenanceUntil] = useState<string | null>(device.maintenance_until || null);
  const [maintenanceDuration, setMaintenanceDuration] = useState(60);

  // Software & CVE state + Wake Reachability state
  const [softwareItems, setSoftwareItems] = useState<SoftwareItem[]>([]);
  const [deviceStatus, setDeviceStatus] = useState<Device['status']>(device.status);
  const [wakingUp, setWakingUp] = useState(false);
  const [wolNotice, setWolNotice] = useState<string | null>(null);
  const [wolChainResult, setWolChainResult] = useState<WakeOnLanResult | null>(null);
  const [deployingCompanion, setDeployingCompanion] = useState(false);
  const [companionDeployNotice, setCompanionDeployNotice] = useState<string | null>(null);
  const [syncingHardware, setSyncingHardware] = useState(false);

  // Warranty state
  const [warranty, setWarranty] = useState<OemWarranty | null>(device.warranty || null);
  const [loadingWarranty, setLoadingWarranty] = useState(false);

  // Custom Fields state
  const [customFields, setCustomFields] = useState<CustomFieldDefinition[]>([]);
  const [fieldValues, setFieldValues] = useState<Record<string, string>>({});
  const [revealedSecretFields, setRevealedSecretFields] = useState<Record<string, boolean>>({});
  const [pendingSecretFieldId, setPendingSecretFieldId] = useState<string | null>(null);
  const [showSecretFieldMfa, setShowSecretFieldMfa] = useState(false);
  const [savingFields, setSavingFields] = useState(false);
  const [fieldsSavedNotice, setFieldsSavedNotice] = useState(false);

  // Chat state
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [sendingChat, setSendingChat] = useState(false);

  // Hardware & Network History state
  const [hardwareHistory, setHardwareHistory] = useState<HardwareHistoryItem[]>([]);
  const [networkHistory, setNetworkHistory] = useState<NetworkHistoryItem[]>([]);
  const [ackingHistId, setAckingHistId] = useState<string | null>(null);

  // BitLocker Key Security Reveal state
  const [isBitlockerRevealed, setIsBitlockerRevealed] = useState(false);
  const [revealedBitlockerKey, setRevealedBitlockerKey] = useState<string | null>(null);
  const [showBitlockerMfa, setShowBitlockerMfa] = useState(false);
  const [bitlockerError, setBitlockerError] = useState<string | null>(null);
  const [showElevateMfa, setShowElevateMfa] = useState(false);
  const [bitlockerCopied, setBitlockerCopied] = useState(false);

  // Live Telemetry WebSocket & History state
  const [liveCpu, setLiveCpu] = useState<number>(device.cpu_usage);
  const [liveRam, setLiveRam] = useState<number>(device.ram_used_gb);
  const [liveRamTotal, setLiveRamTotal] = useState<number>(device.ram_total_gb);
  const [liveDiskFree, setLiveDiskFree] = useState<number>(device.disk_free_gb);
  const [liveDiskTotal, setLiveDiskTotal] = useState<number>(device.disk_total_gb);
  const [liveNetRxMbps, setLiveNetRxMbps] = useState<number>(device.net_rx_mbps || 0);
  const [liveNetTxMbps, setLiveNetTxMbps] = useState<number>(device.net_tx_mbps || 0);
  const [liveNetMbps, setLiveNetMbps] = useState<string>(
    ((device.net_rx_mbps || 0) + (device.net_tx_mbps || 0)).toFixed(2)
  );
  const [telemetryRange, setTelemetryRange] = useState<'1h' | '6h' | '24h' | '7d' | '30d'>('24h');
  const [telemetryHistory, setTelemetryHistory] = useState<TelemetryHistoryResponse | null>(null);
  const [loadingTelemetry, setLoadingTelemetry] = useState(false);
  const [samplingTelemetry, setSamplingTelemetry] = useState(false);
  const [telemetryNotice, setTelemetryNotice] = useState<string | null>(null);
  const [hardwareDetails, setHardwareDetails] = useState<DeviceHardwareDetails | null>(null);
  const [loadingHardware, setLoadingHardware] = useState(false);
  const [deepScanningHardware, setDeepScanningHardware] = useState(false);
  const [currentRole, setCurrentRole] = useState<string>(device.device_role || 'Workstation');
  const [isManualRole, setIsManualRole] = useState<boolean>(Boolean(device.device_role_manual));
  const [savingRole, setSavingRole] = useState(false);
  const [showMoreActions, setShowMoreActions] = useState(false);
  const moreActionsRef = useRef<HTMLDivElement | null>(null);
  const autoSampledDeviceRef = useRef<string | null>(null);

  useEffect(() => {
    setShowMoreActions(false);
  }, [device.id]);

  useEffect(() => {
    if (!showMoreActions) return;
    const onDocClick = (e: MouseEvent) => {
      if (moreActionsRef.current && !moreActionsRef.current.contains(e.target as Node)) {
        setShowMoreActions(false);
      }
    };
    document.addEventListener('mousedown', onDocClick);
    return () => document.removeEventListener('mousedown', onDocClick);
  }, [showMoreActions]);
  const onRefreshFleetRef = useRef(onRefreshFleet);
  onRefreshFleetRef.current = onRefreshFleet;
  const liveTotalsRef = useRef({ liveRamTotal, liveDiskFree, liveDiskTotal });
  liveTotalsRef.current = { liveRamTotal, liveDiskFree, liveDiskTotal };

  // Technician Runbook Notes, Session Recordings, Backups & Endpoint Security state
  const [notes, setNotes] = useState<DeviceNote[]>([]);
  const [newNoteContent, setNewNoteContent] = useState('');
  const [recordings, setRecordings] = useState<SessionRecording[]>([]);
  const [playingRecId, setPlayingRecId] = useState<string | null>(null);
  const [upgradingSoftId, setUpgradingSoftId] = useState<string | null>(null);
  const [backupJobs, setBackupJobs] = useState<DeviceBackupJob[]>([]);
  const [runningBackup, setRunningBackup] = useState(false);
  const [securityActionOutput, setSecurityActionOutput] = useState<string | null>(null);
  const [runningSecAction, setRunningSecAction] = useState<string | null>(null);
  const [linkedDocs, setLinkedDocs] = useState<DocumentationArticle[]>([]);
  const [itflowInfo, setItflowInfo] = useState<DeviceItflowStatus | null>(device.itflow || null);
  const [syncingItflow, setSyncingItflow] = useState(false);
  const [itflowNotice, setItflowNotice] = useState<string | null>(null);

  useEffect(() => {
    setIsMaintenanceActive(Boolean(device.maintenance_active));
    setMaintenanceUntil(device.maintenance_until || null);
    setDeviceStatus(device.status);
    setLifecycleState(device.lifecycle_state || 'active');
    setOffboardReason(device.offboard_reason || 'Endpoint decommissioned / user offboarded');
    setWolNotice(null);
    setWolChainResult(null);
    setAmtNotice(null);
    setElevateNotice(null);
    setOffboardNotice(null);
    setIsBitlockerRevealed(false);
    setRevealedBitlockerKey(null);
    setBitlockerError(null);
    setRevealedSecretFields({});
    setCurrentRole(device.device_role || 'Workstation');
    setIsManualRole(Boolean(device.device_role_manual));
  }, [
    device.id,
    device.maintenance_active,
    device.maintenance_until,
    device.status,
    device.lifecycle_state,
    device.offboard_reason,
    device.device_role,
    device.device_role_manual
  ]);

  const handleRoleChange = async (val: string) => {
    if (savingRole) return;
    setSavingRole(true);
    try {
      const res = await updateDeviceRole(
        device.id,
        val === 'auto' ? { auto_detect: true } : { device_role: val }
      );
      if (res.success) {
        setCurrentRole(res.device_role);
        setIsManualRole(Boolean(res.device_role_manual));
        onRefreshFleetRef.current?.();
      }
    } finally {
      setSavingRole(false);
    }
  };

  useEffect(() => {
    setLiveCpu(device.cpu_usage);
    setLiveRam(device.ram_used_gb);
    setLiveRamTotal(device.ram_total_gb);
    setLiveDiskFree(device.disk_free_gb);
    setLiveDiskTotal(device.disk_total_gb);
    setLiveNetRxMbps(device.net_rx_mbps || 0);
    setLiveNetTxMbps(device.net_tx_mbps || 0);
    setLiveNetMbps(((device.net_rx_mbps || 0) + (device.net_tx_mbps || 0)).toFixed(2));
  }, [
    device.id,
    device.cpu_usage,
    device.ram_used_gb,
    device.ram_total_gb,
    device.disk_free_gb,
    device.disk_total_gb,
    device.net_rx_mbps,
    device.net_tx_mbps
  ]);

  useEffect(() => {
    setTelemetryNotice(null);
    setItflowNotice(null);
    setItflowInfo(device.itflow || null);
    fetchDeviceDetail(device.id)
      .then((full) => {
        if (full?.itflow) setItflowInfo(full.itflow);
      })
      .catch(() => {});
    fetchWarranty(device.id).then((w) => setWarranty(w)).catch(() => setWarranty(null));

    fetchDeviceCustomFields(device.id)
      .then((fields) => {
        setCustomFields(fields);
        const vals: Record<string, string> = {};
        fields.forEach((f) => {
          if (f.current_value != null) vals[f.id] = f.current_value;
        });
        setFieldValues(vals);
      })
      .catch(console.error);

    fetchChatMessages(device.id).then(setChatMessages).catch(console.error);
    fetchHardwareHistory(device.id).then(setHardwareHistory).catch(console.error);
    fetchNetworkHistory(device.id).then(setNetworkHistory).catch(console.error);
    fetchDeviceSoftware(device.id).then(setSoftwareItems).catch(console.error);
    fetchDeviceNotes(device.id).then(setNotes).catch(console.error);
    fetchRecordings(device.id).then(setRecordings).catch(console.error);
    fetchDeviceBackupJobs(device.id).then(setBackupJobs).catch(() => setBackupJobs([]));
    fetchDocumentation({ tenant_id: device.tenant_id }).then(setLinkedDocs).catch(() => setLinkedDocs([]));
    setLoadingHardware(true);
    fetchDeviceHardwareDetails(device.id)
      .then(setHardwareDetails)
      .catch(() => setHardwareDetails(null))
      .finally(() => setLoadingHardware(false));
  }, [device.id, device.tenant_id]);

  useEffect(() => {
    let active = true;
    setLoadingTelemetry(true);
    fetchDeviceTelemetryHistory(device.id, telemetryRange)
      .then((res) => {
        if (!active) return;
        setTelemetryHistory(res);
        if (res.current && res.current.ram_used_gb > 0) {
          setLiveRam(res.current.ram_used_gb);
        }
      })
      .catch(() => {
        if (active) setTelemetryHistory(null);
      })
      .finally(() => {
        if (active) setLoadingTelemetry(false);
      });
    return () => {
      active = false;
    };
  }, [device.id, telemetryRange]);

  useEffect(() => {
    if (deviceStatus !== 'online') return;
    if (autoSampledDeviceRef.current === device.id) return;
    const missingMetrics = device.ram_used_gb <= 0 || device.cpu_usage <= 0;
    const noHistoryYet = telemetryHistory !== null && telemetryHistory.sampleCount === 0;
    if (!missingMetrics && !noHistoryYet) return;
    autoSampledDeviceRef.current = device.id;
    let cancelled = false;
    setSamplingTelemetry(true);
    sampleDeviceTelemetryNow(device.id, false)
      .then(async (res) => {
        if (cancelled) return;
        if (res.sampled && res.device) {
          setLiveCpu(res.device.cpu_usage);
          setLiveRam(res.device.ram_used_gb);
          setLiveRamTotal(res.device.ram_total_gb);
          setLiveDiskFree(res.device.disk_free_gb);
          setLiveDiskTotal(res.device.disk_total_gb);
          const rx = res.device.net_rx_mbps || 0;
          const tx = res.device.net_tx_mbps || 0;
          setLiveNetRxMbps(rx);
          setLiveNetTxMbps(tx);
          setLiveNetMbps((rx + tx).toFixed(2));
          const hist = await fetchDeviceTelemetryHistory(device.id, telemetryRange).catch(() => null);
          if (!cancelled && hist) setTelemetryHistory(hist);
          onRefreshFleetRef.current?.();
        }
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setSamplingTelemetry(false);
      });
    return () => {
      cancelled = true;
    };
  }, [device.id, deviceStatus, device.ram_used_gb, device.cpu_usage, telemetryHistory, telemetryRange]);

  useEffect(() => {
    if (activeTab !== 'chat') return;
    fetchChatMessages(device.id).then(setChatMessages).catch(() => {});
    const chatPollTimer = setInterval(() => {
      fetchChatMessages(device.id).then(setChatMessages).catch(() => {});
    }, 5000);
    return () => clearInterval(chatPollTimer);
  }, [activeTab, device.id]);

  useEffect(() => {
    if (deviceStatus !== 'online') return;
    let cancelled = false;
    let ws: WebSocket | null = null;
    (async () => {
      let ticketQuery = '';
      try {
        const t = await fetchWsTicket();
        if (t?.ticket) ticketQuery = `&ticket=${encodeURIComponent(t.ticket)}`;
      } catch {
        // Same-origin cookie fallback
      }
      if (cancelled) return;
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(
        `${protocol}//${window.location.host}/ws/telemetry?deviceId=${encodeURIComponent(device.id)}${ticketQuery}`
      );
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          const nextCpu = msg.type === 'telemetry_tick' ? Number(msg.cpu) : typeof msg.cpuUsage === 'number' ? Number(msg.cpuUsage) : null;
          if (nextCpu === null) return;
          const nextRam = msg.type === 'telemetry_tick' ? Number(msg.ramGb || 0) : Number(msg.ramUsageGb || 0);
          const nextRamTotal = Number(msg.ramTotalGb ?? liveTotalsRef.current.liveRamTotal);
          const nextDiskFree = Number(msg.diskFreeGb ?? liveTotalsRef.current.liveDiskFree);
          const nextDiskTotal = Number(msg.diskTotalGb ?? liveTotalsRef.current.liveDiskTotal);
          const nextRx = Number(msg.netRxMbps ?? 0);
          const nextTx = Number(msg.netTxMbps ?? 0);
          const nextNetStr = String(
            msg.type === 'telemetry_tick'
              ? msg.netMbps ?? (nextRx + nextTx).toFixed(2)
              : msg.networkMbps ?? (nextRx + nextTx).toFixed(2)
          );
          setLiveCpu(nextCpu);
          setLiveRam(nextRam);
          if (Number.isFinite(nextRamTotal) && nextRamTotal > 0) setLiveRamTotal(nextRamTotal);
          if (Number.isFinite(nextDiskFree) && nextDiskFree >= 0) setLiveDiskFree(nextDiskFree);
          if (Number.isFinite(nextDiskTotal) && nextDiskTotal > 0) setLiveDiskTotal(nextDiskTotal);
          setLiveNetRxMbps(nextRx);
          setLiveNetTxMbps(nextTx);
          setLiveNetMbps(nextNetStr);
          if (telemetryRange === '1h' || telemetryRange === '6h') {
            setTelemetryHistory((prev) => {
              if (!prev) return prev;
              const ts = msg.timestamp || new Date().toISOString();
              const ramPct = nextRamTotal > 0 ? Number(((nextRam / nextRamTotal) * 100).toFixed(1)) : 0;
              const diskUsedPct =
                nextDiskTotal > 0 ? Number((((nextDiskTotal - nextDiskFree) / nextDiskTotal) * 100).toFixed(1)) : 0;
              const lastPt = prev.points[prev.points.length - 1];
              if (lastPt && Math.abs(new Date(ts).getTime() - new Date(lastPt.recorded_at).getTime()) < 9000) {
                return prev;
              }
              const nextPoint = {
                recorded_at: ts,
                cpu_usage: nextCpu,
                ram_used_gb: nextRam,
                ram_total_gb: nextRamTotal,
                ram_used_pct: ramPct,
                disk_used_pct: diskUsedPct,
                disk_free_gb: nextDiskFree,
                disk_total_gb: nextDiskTotal,
                net_rx_mbps: nextRx,
                net_tx_mbps: nextTx,
                net_total_mbps: Number((nextRx + nextTx).toFixed(2))
              };
              const nextPoints = [...prev.points, nextPoint].slice(-200);
              return { ...prev, sampleCount: prev.sampleCount + 1, points: nextPoints };
            });
          }
        } catch {
          // ignore parse errors
        }
      };
    })();
    return () => {
      cancelled = true;
      ws?.close();
    };
  }, [device.id, deviceStatus, telemetryRange]);

  const handleRunSecurityAction = async (
    action: 'av_quick_scan' | 'av_full_scan' | 'av_update_signatures' | 'verify_encryption' | 'enable_encryption'
  ) => {
    setRunningSecAction(action);
    setSecurityActionOutput(null);
    try {
      const res = await runEndpointSecurityAction(device.id, action);
      setSecurityActionOutput(res.output || (res.success ? 'Action completed.' : res.error || 'Failed'));
      onRefreshFleet?.();
    } catch (err: any) {
      setSecurityActionOutput(err?.message || 'Endpoint security command failed');
    } finally {
      setRunningSecAction(null);
    }
  };

  const handleRunBackupSnapshot = async () => {
    setRunningBackup(true);
    try {
      await runDeviceBackupNow(device.id);
      const updated = await fetchDeviceBackupJobs(device.id);
      setBackupJobs(updated);
    } finally {
      setRunningBackup(false);
    }
  };

  const handleRequestBitlockerReveal = async () => {
    setBitlockerError(null);
    try {
      const res = await revealDeviceBitlockerKey(device.id);
      if (res.mfaRequired) {
        setShowBitlockerMfa(true);
        return;
      }
      if (res.success) {
        setRevealedBitlockerKey(res.bitlocker_key || null);
        setIsBitlockerRevealed(true);
      } else {
        setBitlockerError((res as any).error || 'Unable to reveal BitLocker recovery key.');
      }
    } catch (err: any) {
      const msg = String(err?.message || '');
      if (msg.toLowerCase().includes('mfa')) {
        setShowBitlockerMfa(true);
      } else {
        setBitlockerError(msg || 'Failed to retrieve BitLocker recovery key.');
      }
    }
  };

  const handleBitlockerMfaSuccess = async () => {
    const res = await revealDeviceBitlockerKey(device.id);
    if (res.success) {
      setRevealedBitlockerKey(res.bitlocker_key || null);
      setIsBitlockerRevealed(true);
    }
  };

  const handleToggleRevealSecretField = async (fieldId: string) => {
    if (revealedSecretFields[fieldId]) {
      setRevealedSecretFields((prev) => ({ ...prev, [fieldId]: false }));
      setFieldValues((prev) => ({ ...prev, [fieldId]: '••••••••••••' }));
      return;
    }
    const res = await revealDeviceSecretCustomFields(device.id, fieldId);
    if (res.mfaRequired) {
      setPendingSecretFieldId(fieldId);
      setShowSecretFieldMfa(true);
      return;
    }
    if (res.success && res.fields) {
      const target = res.fields.find((item) => item.id === fieldId);
      if (target) {
        setFieldValues((prev) => ({ ...prev, [fieldId]: target.current_value || '' }));
        setRevealedSecretFields((prev) => ({ ...prev, [fieldId]: true }));
      }
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNoteContent.trim()) return;
    const res = await createDeviceNote(device.id, { content: newNoteContent.trim() });
    if (res.success && res.note) {
      setNotes((prev) => [res.note, ...prev]);
      setNewNoteContent('');
    }
  };

  const handleDeleteNote = async (noteId: string) => {
    await deleteDeviceNote(device.id, noteId);
    setNotes((prev) => prev.filter((n) => n.id !== noteId));
  };

  const handleUpgradeSoftware = async (soft: SoftwareItem) => {
    setUpgradingSoftId(soft.id);
    try {
      const res = await upgradeDeviceSoftware(device.id, soft.id);
      if (res.success) {
        const updated = await fetchDeviceSoftware(device.id);
        setSoftwareItems(updated);
      }
    } finally {
      setUpgradingSoftId(null);
    }
  };

  const handleAckHardwareDrift = async (histId: string) => {
    setAckingHistId(histId);
    try {
      const res = await acknowledgeHardwareDrift(device.id, histId);
      if (res.success) {
        setHardwareHistory((prev) =>
          prev.map((item) =>
            item.id === histId
              ? {
                  ...item,
                  acknowledged: 1,
                  acknowledged_by: currentUser?.username || 'Technician',
                  acknowledged_at: new Date().toISOString()
                }
              : item
          )
        );
      }
    } finally {
      setAckingHistId(null);
    }
  };

  const handleWakeOnLan = async (bootTarget: 'normal' | 'bios_uefi' | 'pxe' = 'normal') => {
    setWakingUp(true);
    setWolNotice('Sending Wake-on-LAN & out-of-band power reachability signal...');
    try {
      const res = await wakeDeviceOnLan(device.id, { wakeAndOnline: true, bootTarget });
      if (res.success) {
        setWolChainResult(res);
        const relayStr = res.dispatchedRelays?.length
          ? `Relayed via peer devices: ${res.dispatchedRelays.join(', ')}.`
          : 'Dispatched via local subnet broadcast.';
        if (res.verifiedOnline) {
          setDeviceStatus('online');
          setWolNotice(`⚡ Wake & Reachability Check Succeeded for ${res.targetHostname} (${res.targetMac}). ${relayStr} Endpoint verified ONLINE.`);
        } else {
          setWolNotice(`📡 Wake-on-LAN / peer relay packets dispatched for ${res.targetHostname} (${res.targetMac}). ${relayStr} Awaiting agent check-in before marking online.`);
        }
      } else {
        setWolNotice(`Failed to execute reachability check: ${res.error || 'Unknown error'}`);
      }
    } catch {
      setWolNotice('Error communicating with wake relay service.');
    } finally {
      setWakingUp(false);
    }
  };

  const [enablingWol, setEnablingWol] = useState(false);
  const [provisioningAmt, setProvisioningAmt] = useState(false);
  const [amtNotice, setAmtNotice] = useState<string | null>(null);
  const [showElevateCard, setShowElevateCard] = useState(false);
  const [elevateSource, setElevateSource] = useState<'laps' | 'custom_admin' | 'end_user_uac'>('laps');
  const [elevateAction, setElevateAction] = useState<'elevate_temp_session' | 'promote_permanent_service'>('elevate_temp_session');
  const [customUsername, setCustomUsername] = useState('.\\Administrator');
  const [customPassword, setCustomPassword] = useState('');
  const [elevatingAgent, setElevatingAgent] = useState(false);
  const [elevateNotice, setElevateNotice] = useState<string | null>(null);

  // Offboarding & Data Archive Vault state
  const [lifecycleState, setLifecycleState] = useState<'active' | 'pending_offboard' | 'archived'>(
    device.lifecycle_state || 'active'
  );
  const [showOffboardCard, setShowOffboardCard] = useState(false);
  const [offboardReason, setOffboardReason] = useState(device.offboard_reason || 'Endpoint decommissioned / user offboarded');
  const [offboardLapsOverride, setOffboardLapsOverride] = useState<string>('policy_default');
  const [forceImmediateArchive, setForceImmediateArchive] = useState(false);
  const [offboardingInProgress, setOffboardingInProgress] = useState(false);
  const [offboardNotice, setOffboardNotice] = useState<string | null>(null);

  const handleOffboardDevice = async () => {
    setOffboardingInProgress(true);
    setOffboardNotice(null);
    try {
      const res = await offboardDevice(device.id, {
        reason: offboardReason,
        forceImmediateArchive,
        overrideLapsAction: offboardLapsOverride === 'policy_default' ? undefined : (offboardLapsOverride as any)
      });
      if (res.success) {
        setLifecycleState(res.newLifecycleState);
        if (res.newLifecycleState === 'archived') setDeviceStatus('offline');
        setOffboardNotice(`✓ ${res.message} (LAPS Action: ${res.lapsActionTaken})`);
        onRefreshFleet?.();
      }
    } catch (e: any) {
      setOffboardNotice(`Offboard error: ${e.message}`);
    } finally {
      setOffboardingInProgress(false);
    }
  };

  const handleForceArchiveNow = async () => {
    const res = await forceArchiveDevice(device.id);
    if (res.success) {
      setLifecycleState('archived');
      setDeviceStatus('offline');
      setOffboardNotice(`✓ ${res.message}`);
      onRefreshFleet?.();
    }
  };

  const handleSimulateWakeOrCheckIn = async () => {
    const res = await simulateDeviceCheckin(device.id);
    if (res.success) {
      if (res.actionTaken === 'resurrected_from_archive') {
        setLifecycleState('active');
        setDeviceStatus('online');
      } else if (res.actionTaken === 'queued_offboard_completed_to_archive' || res.actionTaken === 'quiet_offboard_executed') {
        setLifecycleState('archived');
        setDeviceStatus('offline');
      }
      setOffboardNotice(`⚡ ${res.message}`);
      onRefreshFleet?.();
    }
  };

  const handlePurgeDeviceFromArchive = async () => {
    if (!confirm(`Permanently delete ${device.hostname} from the Data Archive Vault? Its BitLocker recovery key and LAPS password history will be permanently erased.`)) {
      return;
    }
    const res = await purgeArchivedDevice(device.id);
    if (res.success) {
      onRefreshFleet?.();
      onBack();
    }
  };

  const handleElevateAgent = async () => {
    setElevatingAgent(true);
    setElevateNotice(null);
    try {
      const res: any = await elevateRemoteAgent(device.id, {
        credentialSource: elevateSource,
        adminUsername: elevateSource === 'custom_admin' ? customUsername : undefined,
        adminPassword: elevateSource === 'custom_admin' ? customPassword : undefined,
        elevationAction: elevateAction
      });
      if (res?.mfaRequired) {
        setShowElevateMfa(true);
        return;
      }
      if (res.success) {
        setElevateNotice(`✓ ${res.message} (Privilege: ${res.newPrivilegeLevel})`);
        onRefreshFleet?.();
      } else {
        setElevateNotice(`Elevation failed: ${res.error || 'Unknown error'}`);
      }
    } catch (e: any) {
      if (String(e?.message || '').toLowerCase().includes('mfa')) {
        setShowElevateMfa(true);
      } else {
        setElevateNotice(`Elevation failed: ${e.message || 'Unknown error'}`);
      }
    } finally {
      setElevatingAgent(false);
    }
  };

  const handleEnableWol = async () => {
    setEnablingWol(true);
    setWolNotice('Configuring OS NIC properties, disabling Fast Startup, and triggering OEM WMI BIOS commands...');
    try {
      const res = await enableDeviceWakeOnLan(device.id);
      if (res.success) {
        setWolNotice(`✅ Wake-on-LAN Successfully Configured! OS Driver: *WakeOnMagicPacket & *WakeOnPattern set to Enabled. Power: Fast Startup power-cut disabled (HiberbootEnabled=0). Firmware: ${warranty?.manufacturer || 'OEM Enterprise'} WMI BIOS enabler executed.`);
      } else {
        setWolNotice(`WoL Configuration failed: ${res.error || 'Unknown error'}`);
      }
    } catch {
      setWolNotice('Error dispatching Wake-on-LAN enabler runbook.');
    } finally {
      setEnablingWol(false);
    }
  };

  const handleProvisionAmt = async () => {
    setProvisioningAmt(true);
    setAmtNotice('Querying Intel MEI driver and initiating host-based zero-touch AMT activation...');
    try {
      const res = await provisionDeviceAmt(device.id);
      if (res.success) {
        setAmtNotice(`⚡ Intel vPro / AMT Activated! Node Deduplication: Unified Node Preserved (No Duplicate Mesh Node Created). Out-of-band power, hardware KVM, and force BIOS boot are now unlocked.`);
      } else {
        setAmtNotice(`vPro / AMT Provisioning failed: ${res.error || 'Unknown error'}`);
      }
    } catch {
      setAmtNotice('Error communicating with Intel AMT provisioning engine.');
    } finally {
      setProvisioningAmt(false);
    }
  };

  const handleDeployCompanion = async () => {
    setDeployingCompanion(true);
    setCompanionDeployNotice(null);
    try {
      const res = await deployDeviceCompanion(device.id);
      if (res.success) {
        setCompanionDeployNotice(
          res.live
            ? `✓ Vitrine companion & tray deployed over live MS2 relay (${res.output?.slice(0, 120) || 'enrolled'}).`
            : `Vitrine companion rollout queued: ${res.output || 'will execute on next online check-in'}`
        );
        onRefreshFleet?.();
      } else {
        setCompanionDeployNotice(`Companion deploy failed: ${res.error || res.output || 'Unknown error'}`);
      }
    } catch (err: any) {
      setCompanionDeployNotice(`Companion deploy failed: ${err?.message || 'Request failed'}`);
    } finally {
      setDeployingCompanion(false);
    }
  };

  const handleSampleTelemetry = async (includeDetailedHardware = false) => {
    if (includeDetailedHardware) {
      setDeepScanningHardware(true);
    } else {
      setSamplingTelemetry(true);
    }
    setTelemetryNotice(null);
    try {
      const res = await sampleDeviceTelemetryNow(device.id, includeDetailedHardware);
      if (res.success && res.sampled) {
        if (res.device) {
          setLiveCpu(res.device.cpu_usage);
          setLiveRam(res.device.ram_used_gb);
          setLiveRamTotal(res.device.ram_total_gb);
          setLiveDiskFree(res.device.disk_free_gb);
          setLiveDiskTotal(res.device.disk_total_gb);
          const rx = res.device.net_rx_mbps || 0;
          const tx = res.device.net_tx_mbps || 0;
          setLiveNetRxMbps(rx);
          setLiveNetTxMbps(tx);
          setLiveNetMbps((rx + tx).toFixed(2));
        }
        const [hist, hw] = await Promise.all([
          fetchDeviceTelemetryHistory(device.id, telemetryRange).catch(() => null),
          fetchDeviceHardwareDetails(device.id).catch(() => null)
        ]);
        if (hist) setTelemetryHistory(hist);
        if (hw) setHardwareDetails(hw);
        setTelemetryNotice(
          includeDetailedHardware
            ? '✓ Deep hardware inventory scan & live telemetry sample completed.'
            : '✓ Live CPU, memory, disk, and network sample recorded.'
        );
        onRefreshFleet?.();
      } else {
        setTelemetryNotice(
          res.reason || res.error || 'Live telemetry probe could not reach the endpoint agent right now.'
        );
      }
    } catch (err: any) {
      setTelemetryNotice(`Telemetry sampling failed: ${err?.message || 'Request failed'}`);
    } finally {
      setSamplingTelemetry(false);
      setDeepScanningHardware(false);
    }
  };

  const handleSyncHardware = async () => {
    setSyncingHardware(true);
    setCompanionDeployNotice(null);
    try {
      const res = await syncDeviceHardwareFromMesh(device.id);
      const [hw, hist] = await Promise.all([
        fetchDeviceHardwareDetails(device.id).catch(() => null),
        fetchDeviceTelemetryHistory(device.id, telemetryRange).catch(() => null)
      ]);
      if (hw) setHardwareDetails(hw);
      if (hist) setTelemetryHistory(hist);
      if (res.success && res.updated) {
        setCompanionDeployNotice('✓ Hardware inventory, serial number, CPU, RAM, and network metadata synced.');
        onRefreshFleet?.();
      } else if (res.success) {
        setCompanionDeployNotice('Remote engine probe completed (no new hardware fields reported; check device online status).');
      } else {
        setCompanionDeployNotice(`Hardware sync failed: ${res.error || 'Unknown error'}`);
      }
    } catch (err: any) {
      setCompanionDeployNotice(`Hardware sync failed: ${err?.message || 'Request failed'}`);
    } finally {
      setSyncingHardware(false);
    }
  };

  const handleToggleMaintenance = async () => {
    const nextState = !isMaintenanceActive;
    const res = await toggleDeviceMaintenance(device.id, nextState, maintenanceDuration);
    if (res.success) {
      setIsMaintenanceActive(res.active);
      setMaintenanceUntil(res.maintenanceUntil);
      onRefreshFleet?.();
    }
  };

  const handleLookupWarranty = async () => {
    setLoadingWarranty(true);
    try {
      const res = await triggerWarrantyLookup(device.id);
      if (res.success) {
        setWarranty(res.warranty);
      }
    } finally {
      setLoadingWarranty(false);
    }
  };

  const handleSaveCustomFields = async () => {
    setSavingFields(true);
    try {
      const res = await saveDeviceCustomFields(device.id, fieldValues);
      if (res.success) {
        setFieldsSavedNotice(true);
        setTimeout(() => setFieldsSavedNotice(false), 3000);
      }
    } finally {
      setSavingFields(false);
    }
  };

  const handleSendChat = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim() || sendingChat) return;
    const senderLabel = currentUser?.username || currentUser?.email || 'Technician';
    setSendingChat(true);
    try {
      const res = await sendChatMessage(device.id, chatInput.trim(), senderLabel, 'technician');
      if (res.success) {
        setChatMessages((prev) => [
          ...prev,
          {
            id: res.id || `msg-${Date.now()}`,
            device_id: device.id,
            sender: senderLabel,
            sender_role: 'technician',
            message: chatInput.trim(),
            read_status: 1,
            created_at: res.timestamp || new Date().toISOString()
          }
        ]);
        setChatInput('');
      }
    } finally {
      setSendingChat(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="device-detail-view">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <button className="btn-glass btn-icon" onClick={onBack} title="Back to Fleet Dashboard">
            <ArrowLeft size={18} />
          </button>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
              <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.6rem', fontWeight: 700, margin: 0 }}>
                {device.hostname}
              </h2>
              <span className={`status-pill ${device.quarantined ? 'status-isolated' : isMaintenanceActive ? 'status-reboot' : deviceStatus === 'offline' ? 'status-offline' : 'status-online'}`}>
                {device.quarantined ? 'Quarantined' : isMaintenanceActive ? 'Maintenance Active' : deviceStatus}
              </span>
              {Boolean(device.intel_amt_enabled) && (
                <span
                  className="status-pill"
                  style={{
                    background: 'rgba(16, 185, 129, 0.15)',
                    color: '#34d399',
                    border: '1px solid rgba(16, 185, 129, 0.35)',
                    fontSize: '0.72rem'
                  }}
                  title="Intel Active Management Technology (vPro AMT) is provisioned on this platform"
                >
                  ⚡ vPro / AMT Ready
                </span>
              )}
              {deviceStatus === 'offline' && Boolean(device.intel_amt_reachable) && (
                <span
                  className="status-pill"
                  style={{
                    background: 'rgba(245, 158, 11, 0.2)',
                    color: '#fbbf24',
                    border: '1px solid rgba(245, 158, 11, 0.4)',
                    fontSize: '0.72rem',
                    animation: 'pulse 2s infinite'
                  }}
                  title="OS Agent offline, but Out-Of-Band Management Controller is reachable via same-subnet peer relays"
                >
                  ⚡ OOB / Peer Reachable
                </span>
              )}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              <span>{device.tenant_name || 'Unassigned Client'} • {device.site_name || 'Unassigned Site'} • IP: {device.ip_address} • Role:</span>
              {canMutate ? (
                <select
                  className="glass-select"
                  value={currentRole}
                  disabled={savingRole}
                  onChange={(e) => handleRoleChange(e.target.value)}
                  title={isManualRole ? 'Manually assigned role (select Re-detect Auto to revert)' : 'Auto-detected device role'}
                  style={{ fontSize: '0.76rem', padding: '0.18rem 0.45rem', minHeight: 'auto', width: 'auto' }}
                >
                  {![
                    'Desktop',
                    'Laptop',
                    'Server',
                    'Domain Controller',
                    'Hypervisor',
                    'Virtual Machine',
                    'Virtual Server',
                    'Workstation',
                    'QuickSupport'
                  ].includes(currentRole) && <option value={currentRole}>{currentRole}</option>}
                  <option value="Desktop">Desktop</option>
                  <option value="Laptop">Laptop</option>
                  <option value="Server">Server</option>
                  <option value="Domain Controller">Domain Controller</option>
                  <option value="Hypervisor">Hypervisor</option>
                  <option value="Virtual Machine">Virtual Machine</option>
                  <option value="Virtual Server">Virtual Server</option>
                  <option value="Workstation">Workstation</option>
                  <option value="QuickSupport">QuickSupport</option>
                  <option value="auto">Auto-Detect (Reset)</option>
                </select>
              ) : (
                <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>{currentRole}</span>
              )}
            </div>
          </div>
        </div>

        {/* Quick Action Toolbar */}
        {canMutate && (
          <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap', alignItems: 'center' }}>
            {deviceStatus === 'offline' && (
              <button
                className="btn-glass"
                style={{ background: 'rgba(56, 189, 248, 0.16)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.4)' }}
                onClick={() => handleWakeOnLan('normal')}
                disabled={wakingUp}
                title="Send Wake-on-LAN / peer-relayed wake signal and verify endpoint reachability"
              >
                <Zap size={15} /> {wakingUp ? 'Waking Device...' : 'Wake Device'}
              </button>
            )}

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
              <KeyRound size={15} color="#fbbf24" /> LAPS Vault
            </button>
            {isTemporaryOrNonServiceAgent(device) && (
              <button
                className="btn-glass"
                style={{
                  background: showElevateCard ? 'rgba(245, 158, 11, 0.22)' : 'rgba(245, 158, 11, 0.1)',
                  color: '#fbbf24',
                  border: '1px solid rgba(245, 158, 11, 0.4)'
                }}
                onClick={() => setShowElevateCard(!showElevateCard)}
                title="Remotely self-elevate a non-admin QuickSupport agent or promote it to a permanent signed service"
              >
                <ShieldCheck size={15} /> Elevate / Promote Agent
              </button>
            )}
            {Boolean(device.quarantined) && (
              <button className="btn-glass btn-primary" onClick={() => onOpenQuarantine(device)}>
                <ShieldAlert size={15} /> Restore Network
              </button>
            )}
            {deviceStatus === 'online' && !device.companion_installed && Boolean(device.mesh_node_id) && (
              <button
                className="btn-glass"
                style={{
                  background: 'rgba(16, 185, 129, 0.12)',
                  color: '#34d399',
                  border: '1px solid rgba(16, 185, 129, 0.35)'
                }}
                onClick={handleDeployCompanion}
                disabled={deployingCompanion}
                title="Deploy or repair the companion agent & branded tray on this endpoint"
              >
                <Download size={15} /> {deployingCompanion ? 'Deploying Companion...' : 'Deploy Companion Tray'}
              </button>
            )}

            <div ref={moreActionsRef} style={{ position: 'relative' }}>
              <button
                type="button"
                className="btn-glass"
                onClick={() => setShowMoreActions((prev) => !prev)}
                aria-expanded={showMoreActions}
              >
                <span>More Actions</span>
                <ChevronDown size={14} style={{ transform: showMoreActions ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }} />
              </button>
              {showMoreActions && (
                <div
                  className="glass-card"
                  style={{
                    position: 'absolute',
                    right: 0,
                    top: 'calc(100% + 0.45rem)',
                    minWidth: '235px',
                    padding: '0.45rem',
                    zIndex: 40,
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.25rem',
                    background: 'var(--surface-elevated)',
                    border: '1px solid var(--border-glass)',
                    boxShadow: '0 16px 36px rgba(0, 0, 0, 0.42)'
                  }}
                >
                  {deviceStatus === 'online' && (
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ justifyContent: 'flex-start', width: '100%', fontSize: '0.8rem', border: 'none' }}
                      onClick={() => {
                        setShowMoreActions(false);
                        handleWakeOnLan('normal');
                      }}
                      disabled={wakingUp}
                    >
                      <Zap size={14} color="#38bdf8" /> {wakingUp ? 'Waking Device...' : 'Test Wake Reachability'}
                    </button>
                  )}
                  {deviceStatus === 'online' && (
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ justifyContent: 'flex-start', width: '100%', fontSize: '0.8rem', border: 'none' }}
                      onClick={() => {
                        setShowMoreActions(false);
                        handleEnableWol();
                      }}
                      disabled={enablingWol}
                    >
                      <Zap size={14} color="#38bdf8" /> {enablingWol ? 'Configuring WoL...' : 'Enable WoL (OS & BIOS)'}
                    </button>
                  )}
                  {Boolean(device.intel_amt_enabled) && isIntelAmtEligible(device) && (
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ justifyContent: 'flex-start', width: '100%', fontSize: '0.8rem', border: 'none', color: '#fbbf24' }}
                      onClick={() => {
                        setShowMoreActions(false);
                        handleWakeOnLan('bios_uefi');
                      }}
                      disabled={wakingUp}
                    >
                      <Power size={14} /> Peer-Relayed AMT Boot
                    </button>
                  )}
                  {deviceStatus === 'online' && isIntelAmtEligible(device) && (
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ justifyContent: 'flex-start', width: '100%', fontSize: '0.8rem', border: 'none', color: device.intel_amt_enabled ? '#34d399' : '#c084fc' }}
                      onClick={() => {
                        setShowMoreActions(false);
                        handleProvisionAmt();
                      }}
                      disabled={provisioningAmt}
                    >
                      <Cpu size={14} /> {provisioningAmt ? 'Provisioning...' : device.intel_amt_enabled ? '⚡ vPro Provisioned' : 'Auto-Provision vPro'}
                    </button>
                  )}
                  {Boolean(device.mesh_node_id) && (
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ justifyContent: 'flex-start', width: '100%', fontSize: '0.8rem', border: 'none' }}
                      onClick={() => {
                        setShowMoreActions(false);
                        handleSyncHardware();
                      }}
                      disabled={syncingHardware}
                    >
                      <RotateCw size={14} className={syncingHardware ? 'spin' : ''} /> {syncingHardware ? 'Syncing Inventory...' : 'Sync Hardware Inventory'}
                    </button>
                  )}
                  <div style={{ height: '1px', background: 'var(--border-glass)', margin: '0.25rem 0.4rem' }} />
                  {!device.quarantined && (
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ justifyContent: 'flex-start', width: '100%', fontSize: '0.8rem', border: 'none', color: '#f87171' }}
                      onClick={() => {
                        setShowMoreActions(false);
                        onOpenQuarantine(device);
                      }}
                    >
                      <ShieldAlert size={14} /> Quarantine Endpoint
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn-glass"
                    style={{ justifyContent: 'flex-start', width: '100%', fontSize: '0.8rem', border: 'none', color: '#f87171' }}
                    onClick={() => {
                      setShowMoreActions(false);
                      setShowOffboardCard(!showOffboardCard);
                    }}
                  >
                    <Archive size={14} /> {lifecycleState === 'archived' ? 'Archived Vault Controls' : 'Offboard Endpoint'}
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Offboarding, Data Archive Vault, Auto-Resurrection & Quiet Offboard Engine Card */}
      {(showOffboardCard || lifecycleState !== 'active' || offboardNotice) && (
        <div
          className="glass-card"
          style={{
            border: `1px solid ${lifecycleState === 'archived' ? 'rgba(56, 189, 248, 0.45)' : 'rgba(239, 68, 68, 0.45)'}`,
            background: 'var(--glass-bg)'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
              <Archive size={18} color={lifecycleState === 'archived' ? '#38bdf8' : '#f87171'} />
              <strong style={{ fontSize: '0.95rem', color: 'var(--text-main)' }}>
                Endpoint Offboarding &amp; Data Archive Vault — {device.hostname}
              </strong>
              <span
                className={`status-pill ${
                  lifecycleState === 'archived'
                    ? 'status-offline'
                    : lifecycleState === 'pending_offboard'
                    ? 'status-reboot'
                    : 'status-online'
                }`}
                style={{ fontSize: '0.7rem' }}
              >
                Lifecycle: {lifecycleState.toUpperCase()}
              </span>
            </div>
            <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap' }}>
              {canMutate && lifecycleState === 'pending_offboard' && (
                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.74rem', borderColor: 'rgba(245, 158, 11, 0.45)', color: '#fbbf24' }}
                  onClick={handleForceArchiveNow}
                >
                  Force Move to Archive Now
                </button>
              )}
              {enableLabDemo && canMutate && lifecycleState !== 'active' && (
                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.74rem', borderColor: 'rgba(56, 189, 248, 0.45)', color: '#38bdf8' }}
                  onClick={handleSimulateWakeOrCheckIn}
                  title="Lab demo: simulate this endpoint waking up or re-installing"
                >
                  <Zap size={13} /> Simulate Wake / Re-Install Check-In
                </button>
              )}
              {canMutate && lifecycleState === 'archived' && (
                <button
                  type="button"
                  className="btn-glass btn-danger"
                  style={{ fontSize: '0.74rem' }}
                  onClick={handlePurgeDeviceFromArchive}
                >
                  <Trash2 size={13} /> Permanently Purge from Archive
                </button>
              )}
              {showOffboardCard && (
                <button className="btn-glass" style={{ padding: '0.2rem 0.55rem', fontSize: '0.72rem' }} onClick={() => setShowOffboardCard(false)}>
                  Close
                </button>
              )}
            </div>
          </div>

          <p style={{ fontSize: '0.79rem', color: 'var(--text-muted)', marginBottom: '0.85rem', lineHeight: 1.5 }}>
            Offboarded endpoints are retained in the <strong>Data Archive Vault</strong> so you never lose escrowed <strong>BitLocker recovery keys</strong> or <strong>LAPS password history</strong> months later. Online agents immediately revert policy changes, execute the configured LAPS local admin rule, and cleanly uninstall software. Offline agents queue in <code>pending_offboard</code> (or can be force-archived immediately). If an archived PC wakes up or re-installs while its parent client is active, it automatically returns to life!
          </p>

          {canMutate && lifecycleState === 'active' && (
            <div className="grid-3" style={{ gap: '0.85rem', alignItems: 'end' }}>
              <div>
                <label className="form-label">Offboard Reason / Audit Note</label>
                <input
                  className="form-input"
                  value={offboardReason}
                  onChange={(e) => setOffboardReason(e.target.value)}
                  placeholder="e.g. Laptop retired / employee offboarded"
                />
              </div>
              <div>
                <label className="form-label">Managed Local Admin Account Action</label>
                <select
                  className="form-select"
                  value={offboardLapsOverride}
                  onChange={(e) => setOffboardLapsOverride(e.target.value)}
                >
                  <option value="policy_default">Use 4-Tier Policy Default (Global/Client/Site/Role)</option>
                  <option value="keep_account_rotate_final">Keep Account &amp; Rotate Final Random Password into Archive</option>
                  <option value="disable_account">Disable Managed Local Admin Account on Endpoint</option>
                  <option value="remove_account">Remove / Delete Managed Local Admin Account from OS</option>
                  <option value="keep_account_as_is">Keep Managed Local Admin Account Untouched</option>
                </select>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '0.76rem', cursor: 'pointer', color: 'var(--text-main)' }}>
                  <input
                    type="checkbox"
                    checked={forceImmediateArchive}
                    onChange={(e) => setForceImmediateArchive(e.target.checked)}
                  />
                  <span>Force immediate move to Archive even if offline</span>
                </label>
                <button
                  type="button"
                  className="btn-glass btn-danger"
                  style={{ width: '100%', justifyContent: 'center' }}
                  disabled={offboardingInProgress}
                  onClick={handleOffboardDevice}
                >
                  <Archive size={15} />
                  <span>{offboardingInProgress ? 'Executing Offboard Runbook...' : 'Execute Clean Offboard'}</span>
                </button>
              </div>
            </div>
          )}

          {offboardNotice && (() => {
            const isOffboardErr = /error|fail/i.test(offboardNotice);
            return (
              <div
                style={{
                  marginTop: '0.85rem',
                  padding: '0.65rem 0.9rem',
                  borderRadius: '8px',
                  background: isOffboardErr ? 'rgba(239, 68, 68, 0.14)' : 'rgba(56, 189, 248, 0.14)',
                  border: `1px solid ${isOffboardErr ? 'rgba(239, 68, 68, 0.35)' : 'rgba(56, 189, 248, 0.35)'}`,
                  fontSize: '0.8rem',
                  color: isOffboardErr ? '#fca5a5' : 'var(--text-main)'
                }}
              >
                {offboardNotice}
              </div>
            );
          })()}
        </div>
      )}

      {/* Remote Elevation & Permanent Agent Promotion Card */}
      {showElevateCard && isTemporaryOrNonServiceAgent(device) && (
        <div className="glass-card" style={{ border: '1px solid rgba(245, 158, 11, 0.45)', background: 'var(--glass-bg)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <KeyRound size={18} color="#fbbf24" />
              <strong style={{ fontSize: '0.95rem', color: 'var(--text-main)' }}>
                Elevate Session &amp; Install Permanent Agent — {device.hostname}
              </strong>
              <span className="status-pill status-online" style={{ fontSize: '0.7rem' }}>
                Current Privilege: {device.agent_privilege_mode || 'SYSTEM / Administrator'}
              </span>
            </div>
            <button className="btn-glass" style={{ padding: '0.2rem 0.55rem', fontSize: '0.72rem' }} onClick={() => setShowElevateCard(false)}>
              Close
            </button>
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.85rem' }}>
            Remotely elevate a non-admin QuickSupport / standard-user session using vaulted LAPS credentials or technician-supplied credentials, or promote a temporary session into a permanently installed signed service.
          </p>
          <div className="grid-3" style={{ gap: '0.85rem', alignItems: 'end' }}>
            <div>
              <label className="form-label">Credential Source</label>
              <select className="form-select" value={elevateSource} onChange={(e) => setElevateSource(e.target.value as any)}>
                <option value="laps">1-Click Vaulted LAPS Admin ({device.laps_account || 'VitrineLocalAdmin'})</option>
                <option value="custom_admin">Custom Local / Domain Admin Credentials</option>
                <option value="end_user_uac">Trigger End-User UAC Consent Prompt</option>
              </select>
            </div>
            <div>
              <label className="form-label">Target Elevation Action</label>
              <select className="form-select" value={elevateAction} onChange={(e) => setElevateAction(e.target.value as any)}>
                <option value="elevate_temp_session">Elevate Temporary Session Only (Auto-clean on disconnect)</option>
                <option value="promote_permanent_service">Promote &amp; Install Permanent Signed Service</option>
              </select>
            </div>
            <div>
              <button
                type="button"
                className="btn-glass btn-primary"
                style={{ width: '100%', justifyContent: 'center' }}
                disabled={elevatingAgent}
                onClick={handleElevateAgent}
              >
                <KeyRound size={15} />
                <span>{elevatingAgent ? 'Injecting Encrypted Elevation Token...' : 'Execute Remote Self-Elevation'}</span>
              </button>
            </div>
          </div>
          {elevateSource === 'custom_admin' && (
            <div className="grid-2" style={{ gap: '0.85rem', marginTop: '0.75rem' }}>
              <div>
                <label className="form-label">Admin Username</label>
                <input className="form-input" value={customUsername} onChange={(e) => setCustomUsername(e.target.value)} placeholder=".\Administrator or DOMAIN\Admin" />
              </div>
              <div>
                <label className="form-label">Admin Password</label>
                <input type="password" className="form-input" value={customPassword} onChange={(e) => setCustomPassword(e.target.value)} placeholder="••••••••••••" />
              </div>
            </div>
          )}
          {elevateNotice && (() => {
            const isElevateErr = /fail|error/i.test(elevateNotice);
            return (
              <div
                style={{
                  marginTop: '0.85rem',
                  padding: '0.65rem 0.9rem',
                  borderRadius: '8px',
                  background: isElevateErr ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.14)',
                  border: `1px solid ${isElevateErr ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                  fontSize: '0.8rem',
                  color: isElevateErr ? '#fca5a5' : 'var(--text-main)'
                }}
              >
                {elevateNotice}
              </div>
            );
          })()}
        </div>
      )}

      {companionDeployNotice && (() => {
        const isCompErr = /fail|error/i.test(companionDeployNotice);
        return (
          <div
            style={{
              padding: '0.85rem 1.25rem',
              background: isCompErr ? 'rgba(239, 68, 68, 0.12)' : 'rgba(16, 185, 129, 0.12)',
              border: `1px solid ${isCompErr ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
              borderRadius: '10px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              color: isCompErr ? '#fca5a5' : '#34d399',
              fontSize: '0.82rem'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <CheckCircle2 size={18} />
              <span>{companionDeployNotice}</span>
            </div>
            <button
              className="btn-glass"
              style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
              onClick={() => setCompanionDeployNotice(null)}
            >
              Dismiss
            </button>
          </div>
        );
      })()}

      {/* Maintenance Mode Banner & WoL Status Notice */}
      {wolNotice && (() => {
        const isWolErr = /^(failed|error|wol configuration failed)/i.test(wolNotice.trim());
        return (
          <div
            style={{
              padding: '0.85rem 1.25rem',
              background: isWolErr ? 'rgba(239, 68, 68, 0.12)' : 'rgba(56, 189, 248, 0.12)',
              border: `1px solid ${isWolErr ? 'rgba(239, 68, 68, 0.35)' : 'rgba(56, 189, 248, 0.35)'}`,
              borderRadius: '10px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              color: isWolErr ? '#fca5a5' : '#38bdf8',
              fontSize: '0.82rem'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <Zap size={18} />
              <span>{wolNotice}</span>
            </div>
            <button
              className="btn-glass"
              style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
              onClick={() => setWolNotice(null)}
            >
              Dismiss
            </button>
          </div>
        );
      })()}

      {/* Wake-on-LAN & Out-of-Band Reachability Trace Card */}
      {wolChainResult?.stages && (
        <div className="glass-card" style={{ border: '1px solid rgba(56, 189, 248, 0.35)', background: 'var(--glass-bg)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <Network size={18} color="#38bdf8" />
              <strong style={{ fontSize: '0.95rem', color: 'var(--text-main)' }}>
                Wake-on-LAN &amp; Out-of-Band Reachability Trace — {wolChainResult.targetHostname} ({wolChainResult.targetIp || device.ip_address || 'endpoint'})
              </strong>
              <span
                className={`status-pill ${wolChainResult.verifiedOnline ? 'status-online' : 'status-reboot'}`}
                style={{ fontSize: '0.7rem' }}
              >
                {wolChainResult.verifiedOnline ? (wolChainResult.bootTarget || 'Verified Online') : 'Wake Dispatched (Awaiting Check-In)'}
              </span>
            </div>
            <button
              className="btn-glass"
              style={{ padding: '0.2rem 0.6rem', fontSize: '0.72rem' }}
              onClick={() => setWolChainResult(null)}
            >
              Hide Trace
            </button>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.55rem' }}>
            {wolChainResult.stages.map((st) => (
              <div
                key={st.tier}
                style={{
                  padding: '0.65rem 0.9rem',
                  borderRadius: '8px',
                  background: 'rgba(148, 163, 184, 0.08)',
                  borderLeft: `3px solid ${st.status === 'success' ? '#10b981' : st.status === 'escalated' ? '#f59e0b' : '#64748b'}`,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.25rem'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontWeight: 700, fontSize: '0.82rem', color: 'var(--text-main)' }}>{st.name}</span>
                    <span className="status-pill" style={{ fontSize: '0.68rem', background: 'rgba(56, 189, 248, 0.14)', color: '#38bdf8' }}>
                      {st.protocol}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', fontSize: '0.74rem' }}>
                    <span style={{ color: 'var(--text-dim)' }}>Relay: <strong style={{ color: 'var(--text-main)' }}>{st.relayHost}</strong></span>
                    <span style={{ color: '#10b981', fontWeight: 600 }}>{st.latencyMs} ms</span>
                    <span
                      className={`status-pill ${st.status === 'success' ? 'status-online' : 'status-reboot'}`}
                      style={{ fontSize: '0.68rem' }}
                    >
                      {st.status.toUpperCase()}
                    </span>
                  </div>
                </div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{st.detail}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {amtNotice && (() => {
        const isAmtErr = /fail|error/i.test(amtNotice);
        return (
          <div
            style={{
              padding: '0.85rem 1.25rem',
              background: isAmtErr ? 'rgba(239, 68, 68, 0.12)' : 'rgba(16, 185, 129, 0.12)',
              border: `1px solid ${isAmtErr ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
              borderRadius: '10px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              color: isAmtErr ? '#fca5a5' : '#34d399',
              fontSize: '0.82rem'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <Cpu size={18} />
              <span>{amtNotice}</span>
            </div>
            <button
              className="btn-glass"
              style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
              onClick={() => setAmtNotice(null)}
            >
              Dismiss
            </button>
          </div>
        );
      })()}

      {isMaintenanceActive && (
        <div
          style={{
            padding: '0.85rem 1.25rem',
            background: 'rgba(245, 158, 11, 0.15)',
            border: '1px solid rgba(245, 158, 11, 0.35)',
            borderRadius: '10px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            color: '#fbbf24',
            fontSize: '0.85rem'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <Clock size={18} />
            <span>
              <strong>Maintenance Mode Active:</strong> Condition watchdogs &amp; automated ticketing are suppressed until{' '}
              <strong>{maintenanceUntil ? new Date(maintenanceUntil).toLocaleTimeString() : 'manually cleared'}</strong> (Auto-clear limit: {settings?.maintenance_auto_clear_hours ?? 24}h online).
            </span>
          </div>
          {canMutate && (
            <button
              className="btn-glass"
              style={{ padding: '0.25rem 0.75rem', fontSize: '0.75rem', background: '#f59e0b', color: '#000', fontWeight: 600 }}
              onClick={handleToggleMaintenance}
            >
              End Maintenance
            </button>
          )}
        </div>
      )}

      {/* View Tabs */}
      <div className="tab-list">
        <button className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}>
          <Activity size={16} />
          <span>Overview</span>
        </button>
        <button className={`tab-btn ${activeTab === 'performance' ? 'active' : ''}`} onClick={() => setActiveTab('performance')}>
          <BarChart3 size={16} />
          <span>Performance &amp; Graphs{telemetryHistory?.sampleCount ? ` (${telemetryHistory.sampleCount})` : ''}</span>
        </button>
        <button className={`tab-btn ${activeTab === 'hardware' ? 'active' : ''}`} onClick={() => setActiveTab('hardware')}>
          <Server size={16} />
          <span>Hardware Specs</span>
        </button>
        <button className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`} onClick={() => setActiveTab('history')}>
          <History size={16} />
          <span>Audit &amp; Drift History ({hardwareHistory.length + networkHistory.length})</span>
        </button>
        <button className={`tab-btn ${activeTab === 'software' ? 'active' : ''}`} onClick={() => setActiveTab('software')}>
          <Package size={16} />
          <span>Software &amp; CVEs ({softwareItems.length})</span>
        </button>
        <button className={`tab-btn ${activeTab === 'attributes' ? 'active' : ''}`} onClick={() => setActiveTab('attributes')}>
          <Award size={16} />
          <span>Attributes &amp; Custom Fields ({customFields.length})</span>
        </button>
        <button className={`tab-btn ${activeTab === 'chat' ? 'active' : ''}`} onClick={() => setActiveTab('chat')}>
          <MessageSquare size={16} />
          <span>Live End-User Chat ({chatMessages.length})</span>
        </button>
      </div>

      {/* PERFORMANCE & TELEMETRY GRAPHS TAB */}
      {activeTab === 'performance' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="glass-card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.85rem' }}>
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0 }}>Tracked Resource Usage &amp; Telemetry History</h3>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                {telemetryHistory?.sampleCount
                  ? `${telemetryHistory.sampleCount} persisted samples in selected window • Last check-in ${new Date(telemetryHistory.current?.last_seen || device.last_seen).toLocaleString()}`
                  : 'Waiting for endpoint telemetry samples'}
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
              {(['1h', '6h', '24h', '7d', '30d'] as const).map((r) => (
                <button
                  key={r}
                  type="button"
                  className={`btn-glass ${telemetryRange === r ? 'btn-primary' : ''}`}
                  style={{ fontSize: '0.74rem', padding: '0.3rem 0.65rem' }}
                  onClick={() => setTelemetryRange(r)}
                >
                  {r.toUpperCase()}
                </button>
              ))}
              {canMutate && (
                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.76rem', borderColor: 'rgba(56, 189, 248, 0.35)', color: '#38bdf8' }}
                  onClick={() => handleSampleTelemetry(false)}
                  disabled={samplingTelemetry || deviceStatus !== 'online'}
                  title={deviceStatus !== 'online' ? 'Device must be online to run a live telemetry probe' : 'Query live CPU, memory, disk, and network counters now'}
                >
                  <RotateCw size={13} className={samplingTelemetry ? 'spin' : ''} />{' '}
                  {samplingTelemetry ? 'Sampling...' : 'Sample Now'}
                </button>
              )}
            </div>
          </div>

          {telemetryNotice && (
            <div
              style={{
                padding: '0.6rem 0.9rem',
                borderRadius: '8px',
                fontSize: '0.78rem',
                background: telemetryNotice.startsWith('✓') ? 'rgba(16, 185, 129, 0.12)' : 'rgba(245, 158, 11, 0.12)',
                border: `1px solid ${telemetryNotice.startsWith('✓') ? 'rgba(16, 185, 129, 0.35)' : 'rgba(245, 158, 11, 0.35)'}`,
                color: telemetryNotice.startsWith('✓') ? '#34d399' : '#fbbf24'
              }}
            >
              {telemetryNotice}
            </div>
          )}

          {loadingTelemetry && !telemetryHistory ? (
            <div className="glass-card" style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
              Loading telemetry history...
            </div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: '1.25rem' }}>
              <TelemetryChartCard
                title="CPU Utilization"
                subtitle={`${device.cpu_model || 'Processor'} (${device.cpu_cores || 0} logical cores)`}
                unit="%"
                range={telemetryRange}
                primaryLabel="CPU %"
                primaryColor="#38bdf8"
                maxY={100}
                points={(telemetryHistory?.points || []).map((p) => ({
                  timestamp: p.recorded_at,
                  primary: p.cpu_usage
                }))}
                currentText={`${(telemetryHistory?.summary?.cpu?.current ?? liveCpu).toFixed(1)}%`}
                avgText={`${(telemetryHistory?.summary?.cpu?.avg ?? 0).toFixed(1)}%`}
                peakText={`${(telemetryHistory?.summary?.cpu?.max ?? 0).toFixed(1)}%`}
                emptyMessage="No CPU samples recorded yet. Online endpoints sample periodically or via Sample Now."
              />

              <TelemetryChartCard
                title="Physical Memory Usage"
                subtitle={`Installed RAM: ${liveRamTotal > 0 ? `${liveRamTotal.toFixed(1)} GB` : 'Unknown'}`}
                unit=" GB"
                range={telemetryRange}
                primaryLabel="RAM Used"
                primaryColor="#a78bfa"
                maxY={Math.max(liveRamTotal || 1, 1)}
                points={(telemetryHistory?.points || []).map((p) => ({
                  timestamp: p.recorded_at,
                  primary: p.ram_used_gb
                }))}
                currentText={
                  liveRam > 0
                    ? `${liveRam.toFixed(1)} GB${liveRamTotal > 0 ? ` (${Math.round((liveRam / liveRamTotal) * 100)}%)` : ''}`
                    : 'Not sampled'
                }
                avgText={`${(telemetryHistory?.summary?.ramUsedGb?.avg ?? 0).toFixed(1)} GB`}
                peakText={`${(telemetryHistory?.summary?.ramUsedGb?.max ?? 0).toFixed(1)} GB`}
                formatValue={(v) => `${v.toFixed(1)} GB`}
                emptyMessage="No memory utilization samples recorded yet."
              />

              <TelemetryChartCard
                title="Storage Utilization"
                subtitle={`${liveDiskFree.toFixed(0)} GB free of ${liveDiskTotal.toFixed(0)} GB total`}
                unit="%"
                range={telemetryRange}
                primaryLabel="Disk Used %"
                primaryColor="#f59e0b"
                maxY={100}
                points={(telemetryHistory?.points || []).map((p) => ({
                  timestamp: p.recorded_at,
                  primary:
                    p.disk_used_pct > 0
                      ? p.disk_used_pct
                      : p.disk_total_gb > 0
                      ? Number((((p.disk_total_gb - p.disk_free_gb) / p.disk_total_gb) * 100).toFixed(1))
                      : 0
                }))}
                currentText={`${(telemetryHistory?.summary?.diskUsedPct?.current ?? (liveDiskTotal > 0 ? ((liveDiskTotal - liveDiskFree) / liveDiskTotal) * 100 : 0)).toFixed(1)}%`}
                avgText={`${(telemetryHistory?.summary?.diskUsedPct?.avg ?? 0).toFixed(1)}%`}
                peakText={`${(telemetryHistory?.summary?.diskUsedPct?.max ?? 0).toFixed(1)}%`}
                emptyMessage="No disk utilization history recorded yet."
              />

              <TelemetryChartCard
                title="Network Throughput"
                subtitle={`Primary NIC: ${device.ip_address || 'Unknown IP'} • MAC: ${device.mac_address || 'Unknown'}`}
                unit=" Mbps"
                range={telemetryRange}
                primaryLabel="Download (Rx)"
                primaryColor="#10b981"
                secondaryLabel="Upload (Tx)"
                secondaryColor="#60a5fa"
                points={(telemetryHistory?.points || []).map((p) => ({
                  timestamp: p.recorded_at,
                  primary: p.net_rx_mbps,
                  secondary: p.net_tx_mbps
                }))}
                currentText={`${(liveNetRxMbps + liveNetTxMbps).toFixed(2)} Mbps (${liveNetRxMbps.toFixed(2)}↓ / ${liveNetTxMbps.toFixed(2)}↑)`}
                avgText={`${(telemetryHistory?.summary?.netMbps?.avg ?? 0).toFixed(2)} Mbps`}
                peakText={`${(telemetryHistory?.summary?.netMbps?.max ?? 0).toFixed(2)} Mbps`}
                formatValue={(v) => `${v.toFixed(2)} Mbps`}
                emptyMessage="No network throughput samples recorded yet."
              />
            </div>
          )}
        </div>
      )}

      {/* HARDWARE SPECIFICATIONS TAB */}
      {activeTab === 'hardware' && (() => {
        const hwSys = hardwareDetails?.system;
        const hwCpu = hardwareDetails?.cpu;
        const hwMem = hardwareDetails?.memory;
        const hwStor = hardwareDetails?.storage;
        const hwGpus = hardwareDetails?.gpus || [];
        const hwNet = hardwareDetails?.network;
        const hwOs = hardwareDetails?.os;
        const ramUsedVal = hwMem?.usedGb && hwMem.usedGb > 0 ? hwMem.usedGb : liveRam;
        const ramTotalVal = hwMem?.totalGb && hwMem.totalGb > 0 ? hwMem.totalGb : liveRamTotal;
        const ramPctVal = ramTotalVal > 0 && ramUsedVal > 0 ? Math.min(100, Math.round((ramUsedVal / ramTotalVal) * 100)) : 0;

        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            <div className="glass-card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.85rem' }}>
              <div>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0 }}>Detailed Endpoint Hardware Inventory</h3>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                  {hardwareDetails?.lastHardwareScanAt
                    ? `Last deep hardware scan: ${new Date(hardwareDetails.lastHardwareScanAt).toLocaleString()}`
                    : 'Run a Deep Hardware Scan on an online endpoint to collect DIMMs, physical disks, motherboard, BIOS, and GPUs.'}
                </span>
              </div>
              {canMutate && (
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    className="btn-glass"
                    style={{ fontSize: '0.78rem' }}
                    onClick={handleSyncHardware}
                    disabled={syncingHardware}
                  >
                    <RotateCw size={13} className={syncingHardware ? 'spin' : ''} />{' '}
                    {syncingHardware ? 'Syncing...' : 'Sync Inventory'}
                  </button>
                  <button
                    type="button"
                    className="btn-glass btn-primary"
                    style={{ fontSize: '0.78rem' }}
                    onClick={() => handleSampleTelemetry(true)}
                    disabled={deepScanningHardware || deviceStatus !== 'online'}
                    title={deviceStatus !== 'online' ? 'Device must be online to run a deep OS hardware scan' : 'Collect full SMBIOS, DIMM, storage, GPU, and NIC specifications'}
                  >
                    <Server size={13} /> {deepScanningHardware ? 'Scanning Hardware...' : 'Deep Hardware Scan'}
                  </button>
                </div>
              )}
            </div>

            {telemetryNotice && (
              <div
                style={{
                  padding: '0.6rem 0.9rem',
                  borderRadius: '8px',
                  fontSize: '0.78rem',
                  background: telemetryNotice.startsWith('✓') ? 'rgba(16, 185, 129, 0.12)' : 'rgba(245, 158, 11, 0.12)',
                  border: `1px solid ${telemetryNotice.startsWith('✓') ? 'rgba(16, 185, 129, 0.35)' : 'rgba(245, 158, 11, 0.35)'}`,
                  color: telemetryNotice.startsWith('✓') ? '#34d399' : '#fbbf24'
                }}
              >
                {telemetryNotice}
              </div>
            )}

            {loadingHardware && !hardwareDetails ? (
              <div className="glass-card" style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                Loading hardware specifications...
              </div>
            ) : (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1.25rem' }}>
                  {/* System, Motherboard, BIOS & TPM */}
                  <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <Laptop size={18} color="var(--primary)" />
                      <h4 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>System, Motherboard, BIOS &amp; TPM</h4>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.65rem', fontSize: '0.8rem' }}>
                      <div><span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>MANUFACTURER</span><div style={{ fontWeight: 600 }}>{hwSys?.manufacturer || device.manufacturer || 'Unknown'}</div></div>
                      <div><span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>MODEL</span><div style={{ fontWeight: 600 }}>{hwSys?.model || device.model || 'Unknown'}</div></div>
                      <div><span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>SERIAL / SERVICE TAG</span><div style={{ fontFamily: 'var(--font-mono)' }}>{hwSys?.serialNumber || device.serial_number || 'Pending'}</div></div>
                      <div style={{ gridColumn: '1 / -1' }}><span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>SYSTEM UUID</span><div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.76rem' }}>{hwSys?.uuid || '—'}</div></div>
                      <div><span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>MOTHERBOARD</span><div>{hwSys?.motherboardVendor || hwSys?.motherboardName ? `${hwSys?.motherboardVendor || ''} ${hwSys?.motherboardName || ''}`.trim() : '—'}</div></div>
                      <div><span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>BOARD SERIAL</span><div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.74rem' }}>{hwSys?.motherboardSerial || '—'}</div></div>
                      <div><span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>BIOS / UEFI</span><div>{hwSys?.biosVersion ? `${hwSys?.biosVendor ? `${hwSys.biosVendor} • ` : ''}${hwSys.biosVersion}` : device.bios_version || '—'}</div></div>
                      <div><span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>BIOS DATE / TPM</span><div>{[hwSys?.biosDate, hwSys?.tpmVersion || device.tpm_version].filter(Boolean).join(' • ') || '—'}</div></div>
                      <div><span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>FORM FACTOR / CHASSIS</span><div>{[hwSys?.chassisLabel || (hwSys?.chassisType ? `Chassis #${hwSys.chassisType}` : ''), hwSys?.hasBattery === true ? 'Battery Present' : hwSys?.hasBattery === false ? 'AC / No Battery' : ''].filter(Boolean).join(' • ') || '—'}</div></div>
                      <div><span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>VIRTUALIZATION / ROLE</span><div>{hwSys?.isVirtualMachine ? `Virtual Machine${hwSys?.hypervisorVendor ? ` (${hwSys.hypervisorVendor})` : ''}` : hwSys?.isHypervisorHost ? 'Hypervisor Host' : currentRole}</div></div>
                    </div>
                  </div>

                  {/* Processor & OS */}
                  <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <Cpu size={18} color="#38bdf8" />
                      <h4 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>Processor &amp; Operating System</h4>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.65rem', fontSize: '0.8rem' }}>
                      <div style={{ gridColumn: '1 / -1' }}><span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>PROCESSOR MODEL</span><div style={{ fontWeight: 600 }}>{hwCpu?.model || device.cpu_model || 'Unknown'}</div></div>
                      <div><span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>CORES / THREADS</span><div>{hwCpu?.physicalCores != null ? `${hwCpu.physicalCores} Physical / ` : ''}{hwCpu?.logicalCores || device.cpu_cores || 0} Logical</div></div>
                      <div><span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>MAX CLOCK SPEED</span><div>{hwCpu?.maxClockMhz ? `${(hwCpu.maxClockMhz / 1000).toFixed(2)} GHz (${hwCpu.maxClockMhz} MHz)` : '—'}</div></div>
                      <div><span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>OPERATING SYSTEM</span><div>{hwOs?.osVersion || device.os_version}</div></div>
                      <div><span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>OS BUILD / PLATFORM</span><div>{hwOs?.osBuild || device.os_build || '—'} ({(hwOs?.osType || device.os_type).toUpperCase()})</div></div>
                      <div><span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>SYSTEM UPTIME</span><div>{formatUptime(hwOs?.uptimeSeconds ?? device.uptime_seconds)}</div></div>
                      <div><span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>LOGGED-IN USER</span><div>{hwOs?.loggedInUser || device.logged_in_user || 'None'}</div></div>
                    </div>
                  </div>
                </div>

                {/* Memory & DIMM Modules */}
                <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <Activity size={18} color="#a78bfa" />
                      <h4 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>Physical Memory &amp; DIMM Slots</h4>
                    </div>
                    <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>
                      {ramUsedVal > 0 ? `${ramUsedVal.toFixed(1)} GB used of ${ramTotalVal.toFixed(1)} GB (${ramPctVal}%)` : ramTotalVal > 0 ? `${ramTotalVal.toFixed(1)} GB Total Installed` : 'RAM size pending'}
                    </span>
                  </div>
                  {ramTotalVal > 0 && (
                    <div style={{ width: '100%', height: '8px', background: 'rgba(148, 163, 184, 0.16)', borderRadius: '999px', overflow: 'hidden' }}>
                      <div style={{ width: `${ramPctVal}%`, height: '100%', background: ramPctVal > 85 ? '#ef4444' : '#a78bfa' }} />
                    </div>
                  )}
                  {(hwMem?.modules || []).length > 0 ? (
                    <div style={{ overflowX: 'auto' }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.78rem' }}>
                        <thead>
                          <tr style={{ textAlign: 'left', color: 'var(--text-dim)', borderBottom: '1px solid var(--glass-border)' }}>
                            <th style={{ padding: '0.4rem 0.5rem' }}>Slot</th>
                            <th style={{ padding: '0.4rem 0.5rem' }}>Capacity</th>
                            <th style={{ padding: '0.4rem 0.5rem' }}>Speed</th>
                            <th style={{ padding: '0.4rem 0.5rem' }}>Manufacturer</th>
                            <th style={{ padding: '0.4rem 0.5rem' }}>Part Number</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(hwMem?.modules || []).map((m, idx) => (
                            <tr key={`${m.slot || 'dimm'}-${idx}`} style={{ borderBottom: '1px solid rgba(148, 163, 184, 0.08)' }}>
                              <td style={{ padding: '0.45rem 0.5rem', fontFamily: 'var(--font-mono)' }}>{m.slot || `DIMM ${idx + 1}`}</td>
                              <td style={{ padding: '0.45rem 0.5rem', fontWeight: 600 }}>{m.capacityGb != null ? `${m.capacityGb} GB` : '—'}</td>
                              <td style={{ padding: '0.45rem 0.5rem' }}>{m.speedMhz ? `${m.speedMhz} MT/s` : '—'}</td>
                              <td style={{ padding: '0.45rem 0.5rem' }}>{m.manufacturer || '—'}</td>
                              <td style={{ padding: '0.45rem 0.5rem', fontFamily: 'var(--font-mono)' }}>{m.partNumber || '—'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>
                      Per-slot DIMM metadata has not been collected yet. Click <strong>Deep Hardware Scan</strong> above while the endpoint is online.
                    </div>
                  )}
                </div>

                {/* Storage Drives & Volumes */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1.25rem' }}>
                  <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <HardDrive size={18} color="#f59e0b" />
                      <h4 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>Physical Disks &amp; Volumes</h4>
                    </div>
                    {(hwStor?.physicalDisks || []).length > 0 ? (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
                        {(hwStor?.physicalDisks || []).map((disk, idx) => (
                          <div key={`${disk.name || disk.model || 'disk'}-${idx}`} style={{ padding: '0.55rem 0.7rem', borderRadius: '6px', background: 'rgba(148, 163, 184, 0.06)', border: '1px solid var(--glass-border)', fontSize: '0.78rem' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 600 }}>
                              <span>{disk.model || disk.name || `Disk ${idx}`}</span>
                              <span>{disk.sizeGb != null ? `${disk.sizeGb} GB` : ''}</span>
                            </div>
                            <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.15rem' }}>
                              {[disk.interfaceType, disk.mediaType, disk.status ? `Health: ${disk.status}` : null].filter(Boolean).join(' • ') || `SMART: ${hwStor?.smartStatus || device.smart_status}`}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>
                        Primary capacity: {liveDiskFree.toFixed(0)} GB free of {liveDiskTotal.toFixed(0)} GB (SMART: {hwStor?.smartStatus || device.smart_status} • {hwStor?.encryptionStatus || device.bitlocker_status || 'Unknown'}).
                      </div>
                    )}

                    {(hwStor?.volumes || []).length > 0 && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.25rem' }}>
                        {(hwStor?.volumes || []).map((vol, idx) => {
                          const total = vol.totalGb || 0;
                          const free = vol.freeGb || 0;
                          const pct = vol.usedPct != null ? vol.usedPct : total > 0 ? Math.round(((total - free) / total) * 100) : 0;
                          return (
                            <div key={`${vol.mount || 'vol'}-${idx}`} style={{ fontSize: '0.76rem' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.2rem' }}>
                                <span>
                                  <strong>{vol.mount || '/'}</strong> {vol.label ? `(${vol.label})` : ''} {vol.filesystem ? `• ${vol.filesystem}` : ''}
                                </span>
                                <span>{free.toFixed(1)} GB free / {total.toFixed(1)} GB ({pct}% used)</span>
                              </div>
                              <div style={{ width: '100%', height: '6px', background: 'rgba(148, 163, 184, 0.16)', borderRadius: '999px', overflow: 'hidden' }}>
                                <div style={{ width: `${Math.min(100, Math.max(0, pct))}%`, height: '100%', background: pct > 88 ? '#ef4444' : '#f59e0b' }} />
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  {/* GPUs & Network Adapters */}
                  <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <Network size={18} color="#10b981" />
                      <h4 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>Graphics &amp; Network Interfaces</h4>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
                      {hwGpus.length > 0 ? (
                        hwGpus.map((g, idx) => (
                          <div key={`${g.name || 'gpu'}-${idx}`} style={{ padding: '0.45rem 0.65rem', borderRadius: '6px', background: 'rgba(148, 163, 184, 0.06)', border: '1px solid var(--glass-border)', fontSize: '0.78rem' }}>
                            <strong>GPU: {g.name || 'Display Adapter'}</strong>
                            {(g.vramMb || g.driverVersion) && (
                              <div style={{ fontSize: '0.71rem', color: 'var(--text-dim)' }}>
                                {[g.vramMb ? `${Math.round(g.vramMb / 1024 * 10) / 10} GB VRAM` : null, g.driverVersion ? `Driver ${g.driverVersion}` : null].filter(Boolean).join(' • ')}
                              </div>
                            )}
                          </div>
                        ))
                      ) : (
                        <div style={{ fontSize: '0.76rem', color: 'var(--text-dim)' }}>GPU details pending deep hardware scan.</div>
                      )}
                    </div>

                    {(hwNet?.adapters || []).length > 0 ? (
                      <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem' }}>
                          <thead>
                            <tr style={{ textAlign: 'left', color: 'var(--text-dim)', borderBottom: '1px solid var(--glass-border)' }}>
                              <th style={{ padding: '0.35rem 0.45rem' }}>Interface</th>
                              <th style={{ padding: '0.35rem 0.45rem' }}>IPv4</th>
                              <th style={{ padding: '0.35rem 0.45rem' }}>MAC</th>
                            </tr>
                          </thead>
                          <tbody>
                            {(hwNet?.adapters || []).map((nic, idx) => (
                              <tr key={`${nic.name || nic.mac || 'nic'}-${idx}`} style={{ borderBottom: '1px solid rgba(148, 163, 184, 0.08)' }}>
                                <td style={{ padding: '0.4rem 0.45rem', fontWeight: 500 }}>{nic.name || `eth${idx}`}</td>
                                <td style={{ padding: '0.4rem 0.45rem', fontFamily: 'var(--font-mono)' }}>{nic.ipv4 || nic.ipv6 || '—'}</td>
                                <td style={{ padding: '0.4rem 0.45rem', fontFamily: 'var(--font-mono)' }}>{nic.mac || '—'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>
                        Primary IP: <code>{hwNet?.primaryIp || device.ip_address || 'Unknown'}</code> • MAC: <code>{hwNet?.primaryMac || device.mac_address || 'Unknown'}</code>
                      </div>
                    )}
                  </div>
                </div>
              </>
            )}
          </div>
        );
      })()}

      {/* TAB 1: OVERVIEW */}
      {activeTab === 'overview' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
          {/* Hardware Lifecycle & Telemetry Cards */}
          <div className="metrics-grid">
            <div className="glass-card">
              <div className="metric-header">
                <span className="metric-title">PROCESSOR LOAD</span>
                <div className="metric-icon-wrap"><Cpu size={18} /></div>
              </div>
              <div className="metric-value">
                {deviceStatus === 'offline' && liveCpu <= 0 ? 'Offline' : `${liveCpu.toFixed(1)}%`}
              </div>
              <div className="metric-subtext">{device.cpu_model} ({device.cpu_cores} Cores • {liveNetMbps} Mbps)</div>
            </div>

            <div className="glass-card">
              <div className="metric-header">
                <span className="metric-title">PHYSICAL RAM</span>
                <div className="metric-icon-wrap"><Activity size={18} /></div>
              </div>
              <div className="metric-value" style={liveRam <= 0 ? { fontSize: '1.35rem', color: 'var(--text-muted)' } : undefined}>
                {liveRam > 0
                  ? `${liveRam.toFixed(1)} GB`
                  : deviceStatus === 'online'
                  ? samplingTelemetry
                    ? 'Sampling…'
                    : 'Pending'
                  : 'Offline'}
              </div>
              <div className="metric-subtext">
                {liveRamTotal > 0
                  ? liveRam > 0
                    ? `${Math.round((liveRam / liveRamTotal) * 100)}% of ${liveRamTotal.toFixed(1)} GB Total Installed`
                    : `of ${liveRamTotal.toFixed(1)} GB Total Installed`
                  : 'Awaiting hardware inventory'}
              </div>
            </div>

            <div className="glass-card">
              <div className="metric-header">
                <span className="metric-title">SYSTEM STORAGE</span>
                <div className="metric-icon-wrap"><HardDrive size={18} /></div>
              </div>
              <div className="metric-value">{liveDiskFree.toFixed(0)} GB</div>
              <div className="metric-subtext">Free of {liveDiskTotal.toFixed(0)} GB ({device.smart_status} SMART • {device.bitlocker_status || 'Unknown'})</div>
            </div>

            <div className="glass-card">
              <div className="metric-header">
                <span className="metric-title">POWER &amp; REACHABILITY</span>
                <div className="metric-icon-wrap" style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#10b981' }}>
                  <Power size={18} />
                </div>
              </div>
              <div className="metric-value" style={{ fontSize: '1.4rem', color: '#34d399' }}>
                {isIntelAmtEligible(device) && device.intel_amt_enabled
                  ? device.intel_amt_reachable
                    ? 'vPro Online (OOB)'
                    : 'Intel vPro Ready'
                  : 'WoL Subnet Active'}
              </div>
              <div className="metric-subtext">
                {isIntelAmtEligible(device) && device.intel_amt_enabled
                  ? 'Hardware-level remote power cycling & KVM'
                  : 'Wake-on-LAN & relay wake support'}
              </div>
            </div>
          </div>

          {/* Telemetry & Hardware Quick Preview */}
          <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.65rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <BarChart3 size={18} color="var(--primary)" />
                <div>
                  <h3 style={{ fontSize: '1rem', fontWeight: 600, margin: 0 }}>Recent Resource Utilization ({telemetryRange.toUpperCase()})</h3>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Network: {liveNetRxMbps.toFixed(2)} Mbps ↓ / {liveNetTxMbps.toFixed(2)} Mbps ↑ • Uptime: {formatUptime(hardwareDetails?.os?.uptimeSeconds ?? device.uptime_seconds)}
                  </span>
                </div>
              </div>
              <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', alignItems: 'center' }}>
                {(['1h', '6h', '24h', '7d', '30d'] as const).map((r) => (
                  <button
                    key={r}
                    type="button"
                    className={`btn-glass ${telemetryRange === r ? 'btn-primary' : ''}`}
                    style={{ fontSize: '0.7rem', padding: '0.22rem 0.5rem' }}
                    onClick={() => setTelemetryRange(r)}
                  >
                    {r.toUpperCase()}
                  </button>
                ))}
                {canMutate && deviceStatus === 'online' && (
                  <button
                    type="button"
                    className="btn-glass"
                    style={{ fontSize: '0.75rem' }}
                    onClick={() => handleSampleTelemetry(false)}
                    disabled={samplingTelemetry}
                  >
                    <RotateCw size={13} className={samplingTelemetry ? 'spin' : ''} />{' '}
                    {samplingTelemetry ? 'Sampling...' : 'Sample Now'}
                  </button>
                )}
                <button type="button" className="btn-glass" style={{ fontSize: '0.75rem' }} onClick={() => setActiveTab('performance')}>
                  <BarChart3 size={13} /> All Usage Graphs
                </button>
                <button type="button" className="btn-glass" style={{ fontSize: '0.75rem' }} onClick={() => setActiveTab('hardware')}>
                  <Server size={13} /> Full Hardware Specs
                </button>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '1rem' }}>
              <TelemetryChartCard
                title="CPU Load"
                unit="%"
                range={telemetryRange}
                primaryLabel="CPU %"
                primaryColor="#38bdf8"
                maxY={100}
                height={150}
                points={(telemetryHistory?.points || []).map((p) => ({
                  timestamp: p.recorded_at,
                  primary: p.cpu_usage
                }))}
                currentText={`${liveCpu.toFixed(1)}%`}
                peakText={`${(telemetryHistory?.summary?.cpu?.max ?? 0).toFixed(1)}%`}
                emptyMessage="No telemetry samples recorded yet."
              />
              <TelemetryChartCard
                title="Memory Usage"
                unit=" GB"
                range={telemetryRange}
                primaryLabel="RAM Used"
                primaryColor="#a78bfa"
                maxY={Math.max(liveRamTotal || 1, 1)}
                height={150}
                points={(telemetryHistory?.points || []).map((p) => ({
                  timestamp: p.recorded_at,
                  primary: p.ram_used_gb
                }))}
                currentText={liveRam > 0 ? `${liveRam.toFixed(1)} / ${liveRamTotal.toFixed(1)} GB` : 'Pending sample'}
                peakText={`${(telemetryHistory?.summary?.ramUsedGb?.max ?? 0).toFixed(1)} GB`}
                formatValue={(v) => `${v.toFixed(1)} GB`}
                emptyMessage="No memory samples recorded yet."
              />
            </div>
          </div>

          {/* OEM Warranty Lifecycle & Maintenance Toolbar */}
          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: '1.5rem' }}>
            {/* Warranty Lifecycle Card */}
            <div className="glass-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                  <Award size={20} color="var(--primary)" />
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>OEM Hardware Lifecycle &amp; Warranty</h3>
                </div>
                {canMutate && (
                  <button className="btn-glass" onClick={handleLookupWarranty} disabled={loadingWarranty} style={{ fontSize: '0.78rem' }}>
                    <RotateCw size={13} /> {loadingWarranty ? 'Querying OEM...' : 'Refresh OEM'}
                  </button>
                )}
              </div>

              {warranty ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', fontSize: '0.85rem' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                    <div>
                      <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>MANUFACTURER</span>
                      <div style={{ fontWeight: 600 }}>{warranty.manufacturer}</div>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>SERIAL / SERVICE TAG</span>
                      <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--primary)' }}>
                        {warranty.serial_number}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                    <div>
                      <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>ENTITLEMENT STATUS</span>
                      <div>
                        <span className={`status-pill ${warranty.status === 'Active' ? 'status-online' : 'status-reboot'}`}>
                          {warranty.status}
                        </span>
                      </div>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>EXPIRATION DATE</span>
                      <div style={{ fontWeight: 600 }}>{warranty.warranty_expiration || 'Ongoing'}</div>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                    <div>
                      <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>PURCHASE / SHIP DATE</span>
                      <div style={{ fontWeight: 600 }}>{warranty.purchase_date || 'N/A'}</div>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>ENROLLED INTO VITRINE</span>
                      <div style={{ fontWeight: 600, color: 'var(--primary)' }}>
                        {device.enrolled_at ? new Date(device.enrolled_at).toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Initial Discovery'}
                      </div>
                    </div>
                  </div>

                  <div>
                    <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>SERVICE LEVEL AGREEMENT</span>
                    <div style={{ background: 'rgba(148, 163, 184, 0.08)', padding: '0.5rem 0.75rem', borderRadius: '6px', fontSize: '0.8rem', marginTop: '0.2rem' }}>
                      {warranty.service_level || 'Standard OEM Support'}
                    </div>
                  </div>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', fontSize: '0.85rem' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                    <div>
                      <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>ENROLLED INTO VITRINE</span>
                      <div style={{ fontWeight: 600, color: 'var(--primary)' }}>
                        {device.enrolled_at ? new Date(device.enrolled_at).toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Initial Discovery'}
                      </div>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>LAST TELEMETRY CHECKIN</span>
                      <div style={{ fontWeight: 600 }}>{device.last_seen || 'Active'}</div>
                    </div>
                  </div>
                  <div style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>
                    No warranty records synchronized. Click &quot;Refresh OEM&quot; to query vendor lifecycle database.
                  </div>
                </div>
              )}
            </div>

            {/* Maintenance Mode Scheduler */}
            <div className="glass-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1.25rem' }}>
                <Clock size={20} color="#f59e0b" />
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Maintenance &amp; Mute Window</h3>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', fontSize: '0.85rem' }}>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                  Temporarily mute condition watchdogs and ticketing alerts while performing maintenance or manual driver installs.
                </p>

                <div className="form-group">
                  <label className="form-label">Duration Preset</label>
                  <select
                    className="glass-select"
                    value={maintenanceDuration}
                    onChange={(e) => setMaintenanceDuration(parseInt(e.target.value, 10))}
                    disabled={isMaintenanceActive || !canMutate}
                  >
                    <option value={30}>30 Minutes</option>
                    <option value={60}>1 Hour</option>
                    <option value={240}>4 Hours</option>
                    <option value={1440}>24 Hours (Full Day)</option>
                  </select>
                </div>

                {canMutate && (
                  <button
                    className={`btn-glass ${isMaintenanceActive ? 'btn-danger' : 'btn-primary'}`}
                    onClick={handleToggleMaintenance}
                    style={{ width: '100%', justifyContent: 'center' }}
                  >
                    <Clock size={15} />
                    <span>{isMaintenanceActive ? 'Cancel Active Maintenance Window' : `Engage Maintenance (${maintenanceDuration}m)`}</span>
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* ITFlow Asset Synchronization Card */}
          <div className="glass-card" id="device-itflow-sync-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.85rem', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
                <Server size={20} color="var(--primary)" />
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>ITFlow Asset Sync</h3>
                {itflowInfo ? (
                  !itflowInfo.enabled ? (
                    <span className="status-pill status-reboot">Integration Disabled</span>
                  ) : !itflowInfo.mappingEnabled ? (
                    <span className="status-pill status-reboot">Client Sync Disabled</span>
                  ) : itflowInfo.lastError ? (
                    <span className="status-pill status-offline">Sync Error</span>
                  ) : itflowInfo.itflowAssetId ? (
                    <span className="status-pill status-online">Synced (#{itflowInfo.itflowAssetId})</span>
                  ) : (
                    <span className="status-pill status-reboot">Pending Initial Sync</span>
                  )
                ) : (
                  <span className="status-pill status-reboot">Checking...</span>
                )}
              </div>
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                {itflowInfo?.assetUrl && (
                  <a
                    href={itflowInfo.assetUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="btn-glass"
                    style={{ fontSize: '0.78rem', textDecoration: 'none' }}
                  >
                    <ExternalLink size={13} /> Open in ITFlow
                  </a>
                )}
                {canMutate && (
                  <button
                    type="button"
                    className="btn-glass btn-primary"
                    disabled={syncingItflow || !itflowInfo?.enabled || !itflowInfo?.mappingEnabled}
                    onClick={async () => {
                      setSyncingItflow(true);
                      setItflowNotice(null);
                      try {
                        const res = await syncSingleDeviceToItflow(device.id);
                        if (res.itflow) setItflowInfo(res.itflow);
                        if (res.success) {
                          setItflowNotice(`✓ Asset ${res.action || 'synced'} in ITFlow${res.assetId ? ` (Asset #${res.assetId})` : ''}.`);
                        } else {
                          setItflowNotice(`⚠ ${res.error || 'Failed to sync asset to ITFlow.'}`);
                        }
                      } finally {
                        setSyncingItflow(false);
                      }
                    }}
                    style={{ fontSize: '0.78rem' }}
                  >
                    <RotateCw size={13} className={syncingItflow ? 'animate-spin' : ''} />
                    <span>{syncingItflow ? 'Syncing Asset...' : 'Sync Asset to ITFlow'}</span>
                  </button>
                )}
              </div>
            </div>

            {itflowNotice && (
              <div
                style={{
                  marginBottom: '0.85rem',
                  padding: '0.55rem 0.8rem',
                  borderRadius: '8px',
                  fontSize: '0.8rem',
                  background: itflowNotice.startsWith('⚠') ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
                  color: itflowNotice.startsWith('⚠') ? '#ef4444' : '#059669',
                  border: `1px solid ${itflowNotice.startsWith('⚠') ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`
                }}
              >
                {itflowNotice}
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', fontSize: '0.84rem' }}>
              <div>
                <span style={{ color: 'var(--text-dim)', fontSize: '0.74rem' }}>TARGET ITFLOW CLIENT</span>
                <div style={{ fontWeight: 600 }}>
                  {itflowInfo?.itflowClientName
                    ? `${itflowInfo.itflowClientName} (#${itflowInfo.itflowClientId})`
                    : itflowInfo?.itflowClientId
                    ? `Client #${itflowInfo.itflowClientId}`
                    : 'Unmapped'}
                </div>
              </div>
              <div>
                <span style={{ color: 'var(--text-dim)', fontSize: '0.74rem' }}>ITFLOW ASSET ID</span>
                <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--primary)' }}>
                  {itflowInfo?.itflowAssetId ? `#${itflowInfo.itflowAssetId}` : 'Not created yet'}
                </div>
              </div>
              <div>
                <span style={{ color: 'var(--text-dim)', fontSize: '0.74rem' }}>LAST SYNCED TO ITFLOW</span>
                <div style={{ fontWeight: 600 }}>
                  {itflowInfo?.lastSyncedAt ? new Date(itflowInfo.lastSyncedAt).toLocaleString() : 'Never'}
                </div>
              </div>
            </div>

            {itflowInfo?.lastError && (
              <div
                style={{
                  marginTop: '0.85rem',
                  padding: '0.55rem 0.8rem',
                  borderRadius: '8px',
                  fontSize: '0.78rem',
                  background: 'rgba(239, 68, 68, 0.12)',
                  color: '#fca5a5',
                  border: '1px solid rgba(239, 68, 68, 0.3)'
                }}
              >
                Last sync error: {itflowInfo.lastError}
              </div>
            )}
          </div>

          {/* Security & Cryptographic Identity */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
            <div className="glass-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1.25rem' }}>
                <Lock size={20} color="var(--primary)" />
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Volume Encryption &amp; BitLocker Key</h3>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', fontSize: '0.85rem' }}>
                <div>
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>ENCRYPTION STATUS</span>
                  <div style={{ fontWeight: 600, color: device.bitlocker_status?.includes('Encrypted') ? '#34d399' : '#f59e0b' }}>
                    {device.bitlocker_status || 'Not Reported'}
                  </div>
                </div>

                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                    <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>ESCROWED RECOVERY KEY</span>
                    {!isBitlockerRevealed ? (
                      canMutate ? (
                        <button
                          className="btn-glass"
                          style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem', display: 'flex', alignItems: 'center', gap: '0.35rem', color: 'var(--primary)' }}
                          onClick={handleRequestBitlockerReveal}
                        >
                          <Eye size={12} /> Reveal Key (MFA)
                        </button>
                      ) : null
                    ) : revealedBitlockerKey ? (
                      <button
                        className="btn-glass"
                        style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                        onClick={async () => {
                          await copyToClipboard(revealedBitlockerKey);
                          setBitlockerCopied(true);
                          setTimeout(() => setBitlockerCopied(false), 2000);
                        }}
                      >
                        {bitlockerCopied ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                        <span>{bitlockerCopied ? 'Copied Key!' : 'Copy Key'}</span>
                      </button>
                    ) : null}
                  </div>
                  <div style={{
                    fontFamily: 'var(--font-mono)',
                    background: 'rgba(148, 163, 184, 0.08)',
                    border: '1px solid var(--glass-border)',
                    padding: '0.55rem 0.75rem',
                    borderRadius: '6px',
                    fontSize: '0.82rem',
                    letterSpacing: isBitlockerRevealed ? '0.04em' : '0.2em',
                    color: isBitlockerRevealed ? 'var(--primary)' : 'var(--text-dim)',
                    wordBreak: 'break-all'
                  }}>
                    {isBitlockerRevealed
                      ? (revealedBitlockerKey || 'No BitLocker recovery key escrowed')
                      : (device.has_bitlocker_key ? '••••••••-••••-••••-••••-••••••••••••' : 'Not Escrowed')}
                  </div>
                  {bitlockerError && (
                    <div style={{ marginTop: '0.4rem', fontSize: '0.76rem', color: '#f87171' }}>
                      {bitlockerError}
                    </div>
                  )}
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                  <div>
                    <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>TPM HARDWARE CHIP</span>
                    <div style={{ fontWeight: 600 }}>{device.tpm_version || 'Not Reported'}</div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>BIOS FIRMWARE</span>
                    <div style={{ fontWeight: 600 }}>{device.bios_version}</div>
                  </div>
                </div>
              </div>
            </div>

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

                {/* Managed Antivirus / Defender & Encryption Live Remediation Controls */}
                {canMutate && (
                  <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap', paddingTop: '0.4rem', borderTop: '1px solid var(--glass-border)' }}>
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ fontSize: '0.72rem', padding: '0.25rem 0.55rem' }}
                      disabled={Boolean(runningSecAction)}
                      onClick={() => handleRunSecurityAction('av_quick_scan')}
                    >
                      {runningSecAction === 'av_quick_scan' ? 'Scanning...' : 'AV Quick Scan'}
                    </button>
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ fontSize: '0.72rem', padding: '0.25rem 0.55rem' }}
                      disabled={Boolean(runningSecAction)}
                      onClick={() => handleRunSecurityAction('av_update_signatures')}
                    >
                      {runningSecAction === 'av_update_signatures' ? 'Updating...' : 'Update Signatures'}
                    </button>
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ fontSize: '0.72rem', padding: '0.25rem 0.55rem' }}
                      disabled={Boolean(runningSecAction)}
                      onClick={() => handleRunSecurityAction('verify_encryption')}
                    >
                      {runningSecAction === 'verify_encryption' ? 'Checking...' : 'Verify Encryption'}
                    </button>
                  </div>
                )}
                {securityActionOutput && (
                  <pre style={{ margin: 0, padding: '0.5rem 0.7rem', borderRadius: '6px', background: 'rgba(0,0,0,0.35)', fontSize: '0.72rem', color: '#34d399', whiteSpace: 'pre-wrap', maxHeight: '110px', overflowY: 'auto' }}>
                    {securityActionOutput}
                  </pre>
                )}
              </div>
            </div>
          </div>

          {/* Endpoint Backup Snapshots & Linked Client Runbooks */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
            <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <HardDrive size={18} color="#38bdf8" />
                  <h3 style={{ fontSize: '1.05rem', fontWeight: 600, margin: 0 }}>
                    Endpoint Backup Snapshots ({backupJobs.length})
                  </h3>
                </div>
                {canMutate && (
                  <button
                    type="button"
                    className="btn-glass btn-primary"
                    style={{ fontSize: '0.75rem', padding: '0.28rem 0.65rem' }}
                    disabled={runningBackup}
                    onClick={handleRunBackupSnapshot}
                  >
                    <RotateCw size={12} /> {runningBackup ? 'Snapshotting...' : 'Run Backup Now'}
                  </button>
                )}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', maxHeight: '165px', overflowY: 'auto' }}>
                {backupJobs.length === 0 ? (
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                    No endpoint backup snapshots recorded yet. Trigger a VSS / restic / Time Machine snapshot above.
                  </div>
                ) : (
                  backupJobs.map((bj) => (
                    <div
                      key={bj.id}
                      style={{
                        padding: '0.55rem 0.75rem',
                        borderRadius: '8px',
                        background: 'rgba(255,255,255,0.03)',
                        border: '1px solid var(--glass-border)',
                        fontSize: '0.76rem',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center'
                      }}
                    >
                      <div>
                        <strong>{bj.snapshot_id || bj.id}</strong>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                          {bj.started_at ? new Date(bj.started_at).toLocaleString() : 'Completed'}
                        </div>
                      </div>
                      <span className={`status-pill ${bj.status === 'completed' ? 'status-online' : 'status-reboot'}`} style={{ fontSize: '0.68rem' }}>
                        {bj.status}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <FileText size={18} color="#f59e0b" />
                <h3 style={{ fontSize: '1.05rem', fontWeight: 600, margin: 0 }}>
                  Client Documentation &amp; SOP Runbooks ({linkedDocs.length})
                </h3>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', maxHeight: '165px', overflowY: 'auto' }}>
                {linkedDocs.length === 0 ? (
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                    No client or global SOP runbooks published yet. Author articles in MSP Documentation.
                  </div>
                ) : (
                  linkedDocs.slice(0, 6).map((doc) => (
                    <div
                      key={doc.id}
                      style={{
                        padding: '0.55rem 0.75rem',
                        borderRadius: '8px',
                        background: 'rgba(255,255,255,0.03)',
                        border: '1px solid var(--glass-border)',
                        fontSize: '0.76rem'
                      }}
                    >
                      <div style={{ fontWeight: 600 }}>
                        {doc.is_pinned ? '📌 ' : ''}
                        {doc.title} <span style={{ color: 'var(--text-dim)', fontWeight: 400 }}>({doc.category})</span>
                      </div>
                      <div style={{ fontSize: '0.71rem', color: 'var(--text-muted)', marginTop: '0.15rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {doc.content_markdown}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Technician Runbook Notes & Session Recordings */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
            {/* Technician Runbook Notes */}
            <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                <FileText size={20} color="var(--primary)" />
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0 }}>
                  Technician Runbook Notes ({notes.length})
                </h3>
              </div>

              {canMutate && (
                <form onSubmit={handleAddNote} style={{ display: 'flex', gap: '0.5rem' }}>
                  <input
                    type="text"
                    className="glass-input"
                    style={{ fontSize: '0.8rem' }}
                    placeholder="Add pinned runbook note or escalation instructions..."
                    value={newNoteContent}
                    onChange={(e) => setNewNoteContent(e.target.value)}
                  />
                  <button type="submit" className="btn-glass btn-primary" style={{ fontSize: '0.8rem' }}>
                    <Plus size={14} /> Add
                  </button>
                </form>
              )}

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '180px', overflowY: 'auto' }}>
                {notes.map((n) => (
                  <div
                    key={n.id}
                    style={{
                      padding: '0.65rem 0.85rem',
                      background: 'rgba(255,255,255,0.03)',
                      border: '1px solid var(--glass-border)',
                      borderRadius: '8px',
                      fontSize: '0.8rem',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'flex-start',
                      gap: '0.5rem'
                    }}
                  >
                    <div>
                      <div style={{ color: 'var(--text-main)', lineHeight: 1.4 }}>{n.content}</div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>
                        {n.author} • {new Date(n.created_at).toLocaleString()}
                      </div>
                    </div>
                    {canMutate && (
                      <button
                        type="button"
                        className="btn-glass btn-icon"
                        onClick={() => handleDeleteNote(n.id)}
                        title="Delete Note"
                      >
                        <Trash2 size={12} color="#ef4444" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Session Recordings Audit Vault */}
            <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                <Video size={20} color="#c084fc" />
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0 }}>
                  Recorded Compliance Sessions ({recordings.length})
                </h3>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '220px', overflowY: 'auto' }}>
                {recordings.length === 0 ? (
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                    No compliance session recordings archived for this endpoint yet.
                  </div>
                ) : (
                  recordings.map((rec) => (
                    <div
                      key={rec.id}
                      style={{
                        padding: '0.65rem 0.85rem',
                        background: 'rgba(148, 163, 184, 0.06)',
                        border: '1px solid var(--glass-border)',
                        borderRadius: '8px',
                        fontSize: '0.78rem',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        gap: '0.5rem'
                      }}
                    >
                      <div>
                        <div style={{ fontWeight: 600, color: 'var(--text-main)' }}>
                          {rec.is_ghost_session ? 'Ghost Desktop' : 'Remote KVM'} • {rec.technician}
                        </div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                          {new Date(rec.created_at).toLocaleString()} • {rec.duration_sec}s • {rec.file_size_mb} MB
                        </div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        {(rec.has_video || rec.mime_type?.startsWith('video/')) && (
                          <button
                            type="button"
                            className="btn-glass"
                            style={{ padding: '0.2rem 0.5rem', fontSize: '0.7rem' }}
                            onClick={() => setPlayingRecId(playingRecId === rec.id ? null : rec.id)}
                          >
                            {playingRecId === rec.id ? 'Hide Video' : '▶ Play WebM'}
                          </button>
                        )}
                        <span className="status-pill status-online" style={{ fontSize: '0.68rem' }}>
                          {rec.has_video ? 'WebM Video' : 'Archived'}
                        </span>
                        <a
                          href={getRecordingDownloadUrl(rec.id)}
                          download
                          className="btn-glass"
                          style={{ padding: '0.2rem 0.45rem', fontSize: '0.7rem', textDecoration: 'none' }}
                          title="Download Compliance Session Recording"
                        >
                          <Download size={12} />
                        </a>
                      </div>
                    </div>
                  ))
                )}
                {playingRecId && (
                  <div style={{ marginTop: '0.5rem', borderRadius: '8px', overflow: 'hidden', border: '1px solid var(--glass-border)', background: '#000' }}>
                    <video
                      key={playingRecId}
                      controls
                      autoPlay
                      src={getRecordingDownloadUrl(playingRecId, 'inline')}
                      style={{ width: '100%', maxHeight: '260px', display: 'block' }}
                    />
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: AUDIT & DRIFT HISTORY */}
      {activeTab === 'history' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
          {/* Hardware Change Audit Trail */}
          <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                <Cpu size={20} color="var(--primary)" />
                <div>
                  <h3 style={{ fontSize: '1.15rem', fontWeight: 600, margin: 0 }}>Hardware Change History</h3>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    Hardware component tracking &amp; delta events detected across agent inventory scans
                  </span>
                </div>
              </div>
              <span className="status-pill status-online" style={{ fontSize: '0.72rem' }}>
                Hardware Drift Watchdog Active
              </span>
            </div>

            {hardwareHistory.length === 0 ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
                No hardware alterations detected since device enrollment.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {hardwareHistory.map((item) => (
                  <div
                    key={item.id}
                    style={{
                      background: 'rgba(255, 255, 255, 0.03)',
                      border: '1px solid var(--glass-border)',
                      padding: '0.85rem 1rem',
                      borderRadius: '8px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: '0.75rem'
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.2rem' }}>
                        <span className="status-pill status-reboot" style={{ fontSize: '0.68rem', textTransform: 'uppercase' }}>
                          {item.change_type}
                        </span>
                        <span style={{ fontWeight: 600, fontSize: '0.88rem' }}>{item.description}</span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                        <span>
                          Vendor: <strong style={{ color: '#00f2fe' }}>{formatVendor(item.vendor_id)}</strong>
                          {item.vendor_id && ` (${item.vendor_id})`}
                        </span>
                        {item.device_id_pci && <span>PCI Device: <code>{item.device_id_pci}</code></span>}
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                        {new Date(item.timestamp).toLocaleString()}
                      </span>
                      {item.acknowledged ? (
                        <span className="status-pill status-online" style={{ fontSize: '0.68rem' }}>
                          ✓ Acknowledged{item.acknowledged_by ? ` (${item.acknowledged_by})` : ''}
                        </span>
                      ) : canMutate ? (
                        <button
                          type="button"
                          className="btn-glass"
                          style={{ padding: '0.2rem 0.55rem', fontSize: '0.72rem' }}
                          disabled={ackingHistId === item.id}
                          onClick={() => handleAckHardwareDrift(item.id)}
                        >
                          <Check size={12} /> {ackingHistId === item.id ? 'Acknowledging...' : 'Acknowledge'}
                        </button>
                      ) : null}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Network History & Rogue Drift Detection */}
          <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                <Network size={20} color="#38bdf8" />
                <div>
                  <h3 style={{ fontSize: '1.15rem', fontWeight: 600, margin: 0 }}>Network History &amp; Connection Drift Watchdog</h3>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    Continuous tracking of SSID associations, gateway BSSID MAC addresses, and rogue corporate subnet anomalies
                  </span>
                </div>
              </div>
              <span className="status-pill status-online" style={{ fontSize: '0.72rem' }}>
                Subnet Drift Active
              </span>
            </div>

            {networkHistory.length === 0 ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
                No network transition history recorded yet.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {networkHistory.map((net) => {
                  const isDrift = Boolean(net.is_flagged_drift);
                  return (
                    <div
                      key={net.id}
                      style={{
                        background: isDrift ? 'rgba(239, 68, 68, 0.08)' : 'rgba(255, 255, 255, 0.03)',
                        border: `1px solid ${isDrift ? 'rgba(239, 68, 68, 0.35)' : 'var(--glass-border)'}`,
                        padding: '0.85rem 1rem',
                        borderRadius: '8px',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        flexWrap: 'wrap',
                        gap: '0.75rem'
                      }}
                    >
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.2rem' }}>
                          <span style={{ fontWeight: 600, fontSize: '0.88rem' }}>
                            {net.ssid || 'Wired Corporate Ethernet'}
                          </span>
                          {isDrift ? (
                            <span className="status-pill status-isolated" style={{ fontSize: '0.68rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                              <AlertTriangle size={11} /> Rogue Network Drift Flagged
                            </span>
                          ) : (
                            <span className="status-pill status-online" style={{ fontSize: '0.68rem' }}>
                              Authorized Subnet
                            </span>
                          )}
                        </div>
                        <div style={{ display: 'flex', gap: '1rem', fontSize: '0.75rem', color: 'var(--text-dim)', flexWrap: 'wrap' }}>
                          <span>Gateway IP: <code>{net.gateway_ip || 'N/A'}</code></span>
                          <span>Gateway MAC: <code>{net.gateway_mac || 'N/A'}</code></span>
                          <span>Subnet: <code>{net.subnet || 'N/A'}</code></span>
                        </div>
                      </div>
                      <div style={{ textAlign: 'right', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                        <div>Connected: {new Date(net.connected_at).toLocaleString()}</div>
                        {net.disconnected_at && <div>Disconnected: {new Date(net.disconnected_at).toLocaleString()}</div>}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* OEM Vendor Catalog Updates */}
          <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                <Laptop size={20} color="#f59e0b" />
                <div>
                  <h3 style={{ fontSize: '1.15rem', fontWeight: 600, margin: 0 }}>OEM Vendor Catalog &amp; Driver Integrations</h3>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    Native orchestration for Dell Command | Update, Lenovo Commercial Vantage, and HP Image Assistant
                  </span>
                </div>
              </div>
              <span className={`status-pill ${warranty?.manufacturer ? 'status-online' : 'status-offline'}`} style={{ fontSize: '0.72rem' }}>
                {warranty?.manufacturer ? `${warranty.manufacturer} Detected` : 'On-Demand Catalog'}
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
              <div style={{ background: 'rgba(148, 163, 184, 0.06)', border: '1px solid var(--glass-border)', padding: '1rem', borderRadius: '8px' }}>
                <div style={{ fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.3rem', color: 'var(--primary)' }}>Dell Command | Update (DCU)</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', lineHeight: 1.4 }}>
                  {(warranty?.manufacturer || '').toLowerCase().includes('dell')
                    ? 'Dell OEM platform detected. DCU CLI catalog sync available for BIOS & chipset updates.'
                    : 'Standby — auto-activates on Dell OptiPlex, Latitude, Precision, and PowerEdge hardware.'}
                </div>
              </div>

              <div style={{ background: 'rgba(148, 163, 184, 0.06)', border: '1px solid var(--glass-border)', padding: '1rem', borderRadius: '8px' }}>
                <div style={{ fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.3rem', color: '#38bdf8' }}>Lenovo Commercial Vantage</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', lineHeight: 1.4 }}>
                  {(warranty?.manufacturer || '').toLowerCase().includes('lenovo')
                    ? 'Lenovo OEM platform detected. LSUClient / Commercial Vantage catalog aligned with policy.'
                    : 'Standby — auto-activates on Lenovo ThinkPad, ThinkCentre, and ThinkSystem hardware.'}
                </div>
              </div>

              <div style={{ background: 'rgba(148, 163, 184, 0.06)', border: '1px solid var(--glass-border)', padding: '1rem', borderRadius: '8px' }}>
                <div style={{ fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.3rem', color: '#34d399' }}>HP Image Assistant (HPIA)</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', lineHeight: 1.4 }}>
                  {(warranty?.manufacturer || '').toLowerCase().includes('hp') || (warranty?.manufacturer || '').toLowerCase().includes('hewlett')
                    ? 'HP OEM platform detected. SoftPaq HPIA reference catalog matched to endpoint.'
                    : 'Standby — auto-activates on HP EliteBook, ProDesk, ZBook, and ProLiant hardware.'}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: SOFTWARE & CVE VULNERABILITIES */}
      {activeTab === 'software' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="glass-card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h3 style={{ fontSize: '1.15rem', fontWeight: 600, margin: 0 }}>Installed Software &amp; Vulnerability (CVE) Tracking</h3>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Automated application inventory normalized against National Vulnerability Database (NVD) with automated PSA ticket generation
              </span>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <span className="status-pill status-isolated" style={{ fontSize: '0.72rem' }}>
                {softwareItems.filter((s) => s.highest_cvss >= 7.0).length} High/Critical CVEs
              </span>
            </div>
          </div>

          <div className="glass-card" style={{ padding: 0 }}>
            <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
              <table className="glass-table">
                <thead>
                  <tr>
                    <th>Application</th>
                    <th>Publisher</th>
                    <th>Installed Version</th>
                    <th>CVE Risk Assessment</th>
                    <th>Auto-Patchable</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {softwareItems.length === 0 ? (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-dim)' }}>
                        No software inventory collected yet.
                      </td>
                    </tr>
                  ) : (
                    softwareItems.map((soft) => {
                      const hasHighCve = soft.highest_cvss >= 7.0;
                      return (
                        <tr key={soft.id}>
                          <td>
                            <strong>{soft.name}</strong>
                          </td>
                          <td style={{ color: 'var(--text-dim)', fontSize: '0.82rem' }}>{soft.publisher || 'Third Party'}</td>
                          <td><code>{soft.version}</code></td>
                          <td>
                            {soft.cve_count > 0 ? (
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                <span
                                  className="status-pill"
                                  style={{
                                    background: hasHighCve ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                                    color: hasHighCve ? '#f87171' : '#fbbf24',
                                    border: `1px solid ${hasHighCve ? 'rgba(239, 68, 68, 0.4)' : 'rgba(245, 158, 11, 0.4)'}`,
                                    fontSize: '0.72rem'
                                  }}
                                >
                                  CVSS {soft.highest_cvss.toFixed(1)} ({soft.cve_count} CVEs)
                                </span>
                                {soft.cve_list?.[0] && (
                                  <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                                    {soft.cve_list[0].id}
                                  </span>
                                )}
                              </div>
                            ) : (
                              <span className="status-pill status-online" style={{ fontSize: '0.72rem' }}>
                                Clean (0 CVEs)
                              </span>
                            )}
                          </td>
                          <td>
                            {soft.auto_patchable ? (
                              <span style={{ color: '#34d399', fontSize: '0.78rem' }}>Supported (Winget/Apt)</span>
                            ) : (
                              <span style={{ color: 'var(--text-dim)', fontSize: '0.78rem' }}>Manual Vendor Pack</span>
                            )}
                          </td>
                          <td>
                            {soft.cve_count > 0 && canMutate && (
                              <button
                                className="btn-glass btn-primary"
                                style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
                                disabled={upgradingSoftId === soft.id}
                                onClick={() => handleUpgradeSoftware(soft)}
                              >
                                {upgradingSoftId === soft.id ? 'Patching...' : 'Auto-Remediate'}
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: ATTRIBUTES (CUSTOM FIELDS) */}
      {activeTab === 'attributes' && (
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h3 style={{ fontSize: '1.15rem', fontWeight: 600 }}>Custom Attributes &amp; Inventory Parameters</h3>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Custom endpoint attributes. Values are passed to scripts and automations via <code>VITRINE_PARAM_*</code> environment variables.
              </span>
            </div>
            {canMutate && (
              <button className="btn-glass btn-primary" onClick={handleSaveCustomFields} disabled={savingFields}>
                <Save size={15} /> {savingFields ? 'Saving...' : 'Save Attributes'}
              </button>
            )}
          </div>

          {fieldsSavedNotice && (
            <div style={{ background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.35)', padding: '0.65rem 1rem', borderRadius: '6px', color: '#34d399', fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <CheckCircle2 size={16} /> Attributes saved successfully and synchronized across policy inheritance hierarchy.
            </div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
            {customFields.map((f) => {
              const currentVal = fieldValues[f.id] ?? '';
              const options = parseFieldOptions(f.options);

              return (
                <div key={f.id} className="form-group">
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                    <label className="form-label" style={{ margin: 0 }}>
                      {f.label}
                    </label>
                    <div style={{ display: 'flex', gap: '0.35rem', alignItems: 'center' }}>
                      {f.field_type === 'secret' && (
                        <span className="status-pill status-online" style={{ fontSize: '0.62rem' }}>
                          Encrypted Vault
                        </span>
                      )}
                      <span className="status-pill status-reboot" style={{ fontSize: '0.65rem' }}>
                        {f.category}
                      </span>
                    </div>
                  </div>

                  {f.field_type === 'dropdown' ? (
                    <select
                      className="glass-select"
                      value={currentVal}
                      disabled={!canMutate}
                      onChange={(e) => setFieldValues({ ...fieldValues, [f.id]: e.target.value })}
                    >
                      <option value="">-- Unassigned --</option>
                      {options.map((opt: string) => (
                        <option key={opt} value={opt}>
                          {opt}
                        </option>
                      ))}
                    </select>
                  ) : f.field_type === 'checkbox' ? (
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: canMutate ? 'pointer' : 'default', fontSize: '0.85rem' }}>
                      <input
                        type="checkbox"
                        checked={currentVal === 'true'}
                        disabled={!canMutate}
                        onChange={(e) => setFieldValues({ ...fieldValues, [f.id]: e.target.checked ? 'true' : 'false' })}
                      />
                      <span>Enabled</span>
                    </label>
                  ) : f.field_type === 'secret' ? (
                    <div style={{ display: 'flex', gap: '0.45rem' }}>
                      <input
                        type={revealedSecretFields[f.id] ? 'text' : 'password'}
                        className="glass-input"
                        placeholder="Enter secret value (AES-256-GCM encrypted at rest)"
                        value={currentVal}
                        disabled={!canMutate}
                        onChange={(e) => setFieldValues({ ...fieldValues, [f.id]: e.target.value })}
                      />
                      {canMutate && (f.has_secret || Boolean(currentVal)) && (
                        <button
                          type="button"
                          className="btn-glass"
                          style={{ whiteSpace: 'nowrap', fontSize: '0.75rem', padding: '0 0.7rem' }}
                          onClick={() => handleToggleRevealSecretField(f.id)}
                        >
                          {revealedSecretFields[f.id] ? <EyeOff size={14} /> : <Eye size={14} />}
                          <span>{revealedSecretFields[f.id] ? 'Hide' : 'Reveal (MFA)'}</span>
                        </button>
                      )}
                    </div>
                  ) : (
                    <input
                      type="text"
                      className="glass-input"
                      value={currentVal}
                      disabled={!canMutate}
                      onChange={(e) => setFieldValues({ ...fieldValues, [f.id]: e.target.value })}
                    />
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 4: LIVE END-USER CHAT */}
      {activeTab === 'chat' && (
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem', minHeight: '400px' }}>
          <div>
            <h3 style={{ fontSize: '1.15rem', fontWeight: 600 }}>Real-Time End-User Chat</h3>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Messages delivered instantly to the Vitrine Tray companion agent on the user&apos;s active Windows/macOS/Linux session.
            </span>
          </div>

          {/* Chat Message Stream */}
          <div
            style={{
              flex: 1,
              maxHeight: '340px',
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.75rem',
              padding: '0.5rem',
              background: 'rgba(148, 163, 184, 0.08)',
              borderRadius: '8px'
            }}
          >
            {chatMessages.length === 0 ? (
              <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem', padding: '2rem 0' }}>
                No chat messages exchanged yet. Send a message to initiate contact with the user.
              </div>
            ) : (
              chatMessages.map((msg) => {
                const isTech = msg.sender_role === 'technician';
                return (
                  <div
                    key={msg.id}
                    style={{
                      alignSelf: isTech ? 'flex-end' : 'flex-start',
                      maxWidth: '75%',
                      background: isTech ? 'rgba(0, 242, 254, 0.14)' : 'var(--glass-bg)',
                      border: `1px solid ${isTech ? 'rgba(0, 242, 254, 0.35)' : 'var(--glass-border)'}`,
                      borderRadius: '12px',
                      padding: '0.75rem 1rem'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', fontSize: '0.72rem', color: isTech ? 'var(--primary)' : 'var(--text-muted)', marginBottom: '0.25rem' }}>
                      <strong>{msg.sender}</strong>
                      <span>{new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                    </div>
                    <div style={{ fontSize: '0.85rem', color: 'var(--text-main)', lineHeight: 1.45 }}>{msg.message}</div>
                  </div>
                );
              })
            )}
          </div>

          {/* Chat Form */}
          {canMutate && (
            <form onSubmit={handleSendChat} style={{ display: 'flex', gap: '0.65rem', borderTop: '1px solid var(--glass-border)', paddingTop: '0.85rem' }}>
              <input
                type="text"
                className="glass-input"
                placeholder="Type message to pop up on user's desktop..."
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                disabled={sendingChat}
              />
              <button type="submit" className="btn-glass btn-primary" disabled={sendingChat || !chatInput.trim()}>
                <Send size={15} /> Send Message
              </button>
            </form>
          )}
        </div>
      )}

      {/* MFA Challenge for BitLocker Recovery Key Unlock */}
      <MfaChallengeModal
        isOpen={showBitlockerMfa}
        onClose={() => setShowBitlockerMfa(false)}
        onSuccess={() => {
          setShowBitlockerMfa(false);
          handleBitlockerMfaSuccess();
        }}
        title="Step-Up MFA: Reveal BitLocker Recovery Key"
        description={`Enter your 6-digit authenticator code to decrypt and view the BitLocker Drive Encryption volume key for ${device.hostname}.`}
        secretType="bitlocker_key"
        deviceId={device.id}
      />

      {/* MFA Challenge for Remote Agent Elevation via LAPS */}
      <MfaChallengeModal
        isOpen={showElevateMfa}
        onClose={() => setShowElevateMfa(false)}
        onSuccess={() => {
          setShowElevateMfa(false);
          handleElevateAgent();
        }}
        title="Step-Up MFA: Remote LAPS Self-Elevation"
        description={`Verify your TOTP authenticator or recovery code to inject vaulted LAPS credentials into ${device.hostname}.`}
        secretType="laps_password"
        deviceId={device.id}
      />

      {/* MFA Challenge for Encrypted Secret Custom Field Reveal */}
      <MfaChallengeModal
        isOpen={showSecretFieldMfa}
        onClose={() => {
          setShowSecretFieldMfa(false);
          setPendingSecretFieldId(null);
        }}
        onSuccess={() => {
          const targetField = pendingSecretFieldId;
          setShowSecretFieldMfa(false);
          setPendingSecretFieldId(null);
          if (targetField) {
            handleToggleRevealSecretField(targetField);
          }
        }}
        title="Step-Up MFA: Reveal Encrypted Custom Attribute"
        description={`Verify your 6-digit authenticator or recovery code to decrypt this vaulted custom field on ${device.hostname}.`}
        secretType="custom_field_secret"
        deviceId={device.id}
      />
    </div>
  );
};
