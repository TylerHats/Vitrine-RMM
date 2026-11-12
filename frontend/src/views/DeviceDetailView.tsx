import React, { useState, useEffect } from 'react';
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
  Download
} from 'lucide-react';
import { AuthUser, Device, CustomFieldDefinition, OemWarranty, ChatMessage, HardwareHistoryItem, NetworkHistoryItem, SoftwareItem, DeviceNote, SessionRecording, WakeOnLanResult } from '../types/index.js';
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
  getStoredSessionToken,
  elevateRemoteAgent,
  offboardDevice,
  forceArchiveDevice,
  simulateDeviceCheckin,
  purgeArchivedDevice
} from '../services/api.js';
import { MfaChallengeModal } from '../components/MfaChallengeModal.js';

interface DeviceDetailViewProps {
  device: Device;
  onBack: () => void;
  onOpenRemote: (device: Device, isGhost: boolean) => void;
  onOpenBgTools: (device: Device, initialTab?: string) => void;
  onOpenLaps: (device: Device) => void;
  onOpenQuarantine: (device: Device) => void;
  currentUser?: AuthUser | null;
  onRefreshFleet?: () => void;
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

export const DeviceDetailView: React.FC<DeviceDetailViewProps> = ({
  device,
  onBack,
  onOpenRemote,
  onOpenBgTools,
  onOpenLaps,
  onOpenQuarantine,
  currentUser,
  onRefreshFleet
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'history' | 'software' | 'attributes' | 'chat'>('overview');

  // Maintenance state
  const [isMaintenanceActive, setIsMaintenanceActive] = useState(Boolean(device.maintenance_active));
  const [maintenanceUntil, setMaintenanceUntil] = useState<string | null>(device.maintenance_until || null);
  const [maintenanceDuration, setMaintenanceDuration] = useState(60);

  // Software & CVE state + 5-Tier Peer Reachability Chain state
  const [softwareItems, setSoftwareItems] = useState<SoftwareItem[]>([]);
  const [deviceStatus, setDeviceStatus] = useState<Device['status']>(device.status);
  const [wakingUp, setWakingUp] = useState(false);
  const [wolNotice, setWolNotice] = useState<string | null>(null);
  const [wolChainResult, setWolChainResult] = useState<WakeOnLanResult | null>(null);

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

  // BitLocker Key Security Reveal state
  const [isBitlockerRevealed, setIsBitlockerRevealed] = useState(false);
  const [revealedBitlockerKey, setRevealedBitlockerKey] = useState<string | null>(null);
  const [showBitlockerMfa, setShowBitlockerMfa] = useState(false);
  const [showElevateMfa, setShowElevateMfa] = useState(false);
  const [bitlockerCopied, setBitlockerCopied] = useState(false);

  // Live Telemetry WebSocket state
  const [liveCpu, setLiveCpu] = useState<number>(device.cpu_usage);
  const [liveRam, setLiveRam] = useState<number>(device.ram_used_gb);
  const [liveNetMbps, setLiveNetMbps] = useState<string>(device.status === 'online' ? '1.2' : '0.0');

  // Technician Runbook Notes & Session Recordings state
  const [notes, setNotes] = useState<DeviceNote[]>([]);
  const [newNoteContent, setNewNoteContent] = useState('');
  const [recordings, setRecordings] = useState<SessionRecording[]>([]);
  const [upgradingSoftId, setUpgradingSoftId] = useState<string | null>(null);

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
    setRevealedSecretFields({});
  }, [
    device.id,
    device.maintenance_active,
    device.maintenance_until,
    device.status,
    device.lifecycle_state,
    device.offboard_reason
  ]);

  useEffect(() => {
    setLiveCpu(device.cpu_usage);
    setLiveRam(device.ram_used_gb);
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
  }, [device.id, device.cpu_usage, device.ram_used_gb]);

  useEffect(() => {
    if (deviceStatus !== 'online') return;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const token = getStoredSessionToken();
    const tokenQuery = token ? `&token=${encodeURIComponent(token)}` : '';
    const ws = new WebSocket(
      `${protocol}//${window.location.host}/ws/telemetry?deviceId=${encodeURIComponent(device.id)}${tokenQuery}`
    );
    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'telemetry_tick') {
          setLiveCpu(Number(msg.cpu));
          setLiveRam(Number(msg.ramGb));
          setLiveNetMbps(String(msg.netMbps));
        }
      } catch {
        // ignore parse errors
      }
    };
    return () => ws.close();
  }, [device.id, deviceStatus]);

  const handleRequestBitlockerReveal = async () => {
    try {
      const res = await revealDeviceBitlockerKey(device.id);
      if (res.mfaRequired) {
        setShowBitlockerMfa(true);
        return;
      }
      if (res.success) {
        setRevealedBitlockerKey(res.bitlocker_key || null);
        setIsBitlockerRevealed(true);
      }
    } catch {
      setShowBitlockerMfa(true);
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

  const handleWakeOnLan = async (bootTarget: 'normal' | 'bios_uefi' | 'pxe' = 'normal') => {
    setWakingUp(true);
    setWolNotice('Executing 5-Tier Same-Company & Same-Network Peer Reachability Chain (Cloud CIRA -> Peer LAN AMT 16993 -> Multi-Peer WoL Magic Packets -> Historical Roaming Subnets -> ARP Verification)...');
    try {
      const res = await wakeDeviceOnLan(device.id, { wakeAndOnline: true, bootTarget });
      if (res.success) {
        setWolChainResult(res);
        setDeviceStatus('online');
        const relayStr = res.dispatchedRelays?.length
          ? `Relayed via same-company peers: ${res.dispatchedRelays.join(', ')}.`
          : 'Dispatched via local subnet broadcast.';
        setWolNotice(`⚡ 5-Tier Wake & AMT Reachability Chain Succeeded for ${res.targetHostname} (${res.targetMac}). ${relayStr} Endpoint verified ONLINE via Peer ARP & Agent TLS Handshake!`);
      } else {
        setWolNotice(`Failed to execute reachability chain: ${res.error || 'Unknown error'}`);
      }
    } catch {
      setWolNotice('Error communicating with 5-Tier WoL & AMT relay engine.');
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
            <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              {device.tenant_name || 'Unassigned Client'} • {device.site_name || 'Unassigned Site'} • IP: {device.ip_address}
            </span>
          </div>
        </div>

        {/* Quick Action Toolbar */}
        <div style={{ display: 'flex', gap: '0.65rem', flexWrap: 'wrap' }}>
          <button
            className="btn-glass"
            style={{ background: 'rgba(56, 189, 248, 0.16)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.4)' }}
            onClick={() => handleWakeOnLan('normal')}
            disabled={wakingUp}
            title="Execute 5-Tier Reachability Chain (Cloud CIRA -> Same-Subnet Peer AMT 16993 -> Same-Subnet Peer Magic Packets -> Historical Roaming Subnet Relay -> ARP Link-Up Verification)"
          >
            <Zap size={15} /> {wakingUp ? 'Relaying 5-Tier Wake...' : deviceStatus === 'offline' ? '5-Tier Wake (WoL + Peer AMT)' : 'Test 5-Tier Peer Reachability'}
          </button>
          {Boolean(device.intel_amt_enabled) && (
            <button
              className="btn-glass"
              style={{ background: 'rgba(245, 158, 11, 0.2)', color: '#fbbf24', border: '1px solid rgba(245, 158, 11, 0.4)' }}
              onClick={() => handleWakeOnLan('bios_uefi')}
              disabled={wakingUp}
              title="Relay Intel AMT / vPro WS-Management Power-On / Force UEFI Setup via Online Peer on the Same LAN Subnet"
            >
              <Power size={15} /> Peer-Relayed AMT Boot
            </button>
          )}

          {deviceStatus === 'online' && (
            <button
              className="btn-glass"
              style={{ background: 'rgba(56, 189, 248, 0.12)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.3)' }}
              onClick={handleEnableWol}
              disabled={enablingWol}
              title="Configure Windows Driver properties, disable Fast Startup, and execute OEM WMI BIOS commands without a manual reboot"
            >
              <Zap size={15} /> {enablingWol ? 'Configuring WoL...' : 'Enable WoL (OS & BIOS)'}
            </button>
          )}

          {deviceStatus === 'online' && (
            <button
              className="btn-glass"
              style={{
                background: device.intel_amt_enabled ? 'rgba(16, 185, 129, 0.12)' : 'rgba(168, 85, 247, 0.12)',
                color: device.intel_amt_enabled ? '#34d399' : '#c084fc',
                border: `1px solid ${device.intel_amt_enabled ? 'rgba(16, 185, 129, 0.35)' : 'rgba(168, 85, 247, 0.35)'}`
              }}
              onClick={handleProvisionAmt}
              disabled={provisioningAmt}
              title="Inspect Intel MEI driver and provision Intel vPro AMT CIRA tunnel without duplicate nodes"
            >
              <Cpu size={15} /> {provisioningAmt ? 'Provisioning...' : device.intel_amt_enabled ? '⚡ vPro Provisioned' : 'Auto-Provision vPro'}
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
          <button className={`btn-glass ${device.quarantined ? 'btn-primary' : 'btn-danger'}`} onClick={() => onOpenQuarantine(device)}>
            <ShieldAlert size={15} /> {device.quarantined ? 'Restore Network' : 'Quarantine'}
          </button>
          <button
            className="btn-glass"
            style={{
              background: showOffboardCard ? 'rgba(239, 68, 68, 0.22)' : 'rgba(239, 68, 68, 0.1)',
              color: '#f87171',
              border: '1px solid rgba(239, 68, 68, 0.4)'
            }}
            onClick={() => setShowOffboardCard(!showOffboardCard)}
            title="Cleanly offboard endpoint (revert policies, apply LAPS local admin rule, uninstall agents, and preserve BitLocker & LAPS in Archive)"
          >
            <Archive size={15} /> {lifecycleState === 'archived' ? 'Archived Vault Controls' : 'Offboard Endpoint'}
          </button>
        </div>
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
              {lifecycleState === 'pending_offboard' && (
                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.74rem', borderColor: 'rgba(245, 158, 11, 0.45)', color: '#fbbf24' }}
                  onClick={handleForceArchiveNow}
                >
                  Force Move to Archive Now
                </button>
              )}
              {lifecycleState !== 'active' && (
                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.74rem', borderColor: 'rgba(56, 189, 248, 0.45)', color: '#38bdf8' }}
                  onClick={handleSimulateWakeOrCheckIn}
                  title="Simulate this PC waking up or re-installing: resurrects to Active if Archived & client is Active; or runs queued/quiet offboard if Pending Offboard or client is Archived/Deleted"
                >
                  <Zap size={13} /> Simulate Wake / Re-Install Check-In
                </button>
              )}
              {lifecycleState === 'archived' && (
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

          {lifecycleState === 'active' && (
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

          {offboardNotice && (
            <div
              style={{
                marginTop: '0.85rem',
                padding: '0.65rem 0.9rem',
                borderRadius: '8px',
                background: 'rgba(56, 189, 248, 0.14)',
                border: '1px solid rgba(56, 189, 248, 0.35)',
                fontSize: '0.8rem',
                color: 'var(--text-main)'
              }}
            >
              {offboardNotice}
            </div>
          )}
        </div>
      )}

      {/* Tech-Side Remote Self-Elevation & QuickSupport Promotion Card */}
      {showElevateCard && (
        <div className="glass-card" style={{ border: '1px solid rgba(245, 158, 11, 0.45)', background: 'var(--glass-bg)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <KeyRound size={18} color="#fbbf24" />
              <strong style={{ fontSize: '0.95rem', color: 'var(--text-main)' }}>
                Tech-Side Remote Self-Elevation &amp; Permanent Service Promotion — {device.hostname}
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
          {elevateNotice && (
            <div style={{ marginTop: '0.85rem', padding: '0.65rem 0.9rem', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.14)', border: '1px solid rgba(16, 185, 129, 0.35)', fontSize: '0.8rem', color: 'var(--text-main)' }}>
              {elevateNotice}
            </div>
          )}
        </div>
      )}

      {/* Maintenance Mode Banner & WoL Status Notice */}
      {wolNotice && (
        <div
          style={{
            padding: '0.85rem 1.25rem',
            background: 'rgba(56, 189, 248, 0.12)',
            border: '1px solid rgba(56, 189, 248, 0.35)',
            borderRadius: '10px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            color: '#38bdf8',
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
      )}

      {/* 5-Tier Peer-Relayed Wake-on-LAN & Intel AMT Execution Trace Card */}
      {wolChainResult?.stages && (
        <div className="glass-card" style={{ border: '1px solid rgba(56, 189, 248, 0.35)', background: 'var(--glass-bg)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <Network size={18} color="#38bdf8" />
              <strong style={{ fontSize: '0.95rem', color: 'var(--text-main)' }}>
                5-Tier Same-Company &amp; Same-Network Peer Reachability Chain — {wolChainResult.targetHostname} ({wolChainResult.targetIp})
              </strong>
              <span className="status-pill status-online" style={{ fontSize: '0.7rem' }}>
                {wolChainResult.bootTarget || 'Verified Online'}
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

      {amtNotice && (
        <div
          style={{
            padding: '0.85rem 1.25rem',
            background: 'rgba(16, 185, 129, 0.12)',
            border: '1px solid rgba(16, 185, 129, 0.35)',
            borderRadius: '10px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            color: '#34d399',
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
      )}

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
              <strong>{maintenanceUntil ? new Date(maintenanceUntil).toLocaleTimeString() : 'manually cleared'}</strong> (Auto-clear limit: 24h online).
            </span>
          </div>
          <button
            className="btn-glass"
            style={{ padding: '0.25rem 0.75rem', fontSize: '0.75rem', background: '#f59e0b', color: '#000', fontWeight: 600 }}
            onClick={handleToggleMaintenance}
          >
            End Maintenance
          </button>
        </div>
      )}

      {/* View Tabs */}
      <div className="tab-list">
        <button className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}>
          <Activity size={16} />
          <span>System &amp; Hardware</span>
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
              <div className="metric-value">{liveCpu.toFixed(1)}%</div>
              <div className="metric-subtext">{device.cpu_model} ({device.cpu_cores} Cores • {liveNetMbps} Mbps)</div>
            </div>

            <div className="glass-card">
              <div className="metric-header">
                <span className="metric-title">PHYSICAL RAM</span>
                <div className="metric-icon-wrap"><Activity size={18} /></div>
              </div>
              <div className="metric-value">{liveRam.toFixed(1)} GB</div>
              <div className="metric-subtext">of {device.ram_total_gb.toFixed(1)} GB Total Installed</div>
            </div>

            <div className="glass-card">
              <div className="metric-header">
                <span className="metric-title">SYSTEM STORAGE</span>
                <div className="metric-icon-wrap"><HardDrive size={18} /></div>
              </div>
              <div className="metric-value">{device.disk_free_gb.toFixed(0)} GB</div>
              <div className="metric-subtext">Free of {device.disk_total_gb.toFixed(0)} GB ({device.smart_status} SMART • Encrypted)</div>
            </div>

            <div className="glass-card">
              <div className="metric-header">
                <span className="metric-title">OUT-OF-BAND (AMT)</span>
                <div className="metric-icon-wrap" style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#10b981' }}>
                  <Power size={18} />
                </div>
              </div>
              <div className="metric-value" style={{ fontSize: '1.4rem', color: '#34d399' }}>
                {device.intel_amt_enabled ? (device.intel_amt_reachable ? 'vPro Online (OOB)' : 'Intel vPro Ready') : 'WoL Subnet Active'}
              </div>
              <div className="metric-subtext">Hardware-level remote power cycling &amp; KVM</div>
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
                <button className="btn-glass" onClick={handleLookupWarranty} disabled={loadingWarranty} style={{ fontSize: '0.78rem' }}>
                  <RotateCw size={13} /> {loadingWarranty ? 'Querying OEM...' : 'Refresh OEM'}
                </button>
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
                      <div style={{ fontWeight: 600, color: 'var(--accent-primary, #00f2fe)' }}>
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
                      <div style={{ fontWeight: 600, color: 'var(--accent-primary, #00f2fe)' }}>
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
                    disabled={isMaintenanceActive}
                  >
                    <option value={30}>30 Minutes</option>
                    <option value={60}>1 Hour</option>
                    <option value={240}>4 Hours</option>
                    <option value={1440}>24 Hours (Full Day)</option>
                  </select>
                </div>

                <button
                  className={`btn-glass ${isMaintenanceActive ? 'btn-danger' : 'btn-primary'}`}
                  onClick={handleToggleMaintenance}
                  style={{ width: '100%', justifyContent: 'center' }}
                >
                  <Clock size={15} />
                  <span>{isMaintenanceActive ? 'Cancel Active Maintenance Window' : `Engage Maintenance (${maintenanceDuration}m)`}</span>
                </button>
              </div>
            </div>
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
                  <div style={{ fontWeight: 600, color: '#34d399' }}>{device.bitlocker_status || 'XTS-AES 128-bit Fully Encrypted'}</div>
                </div>

                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                    <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>ESCROWED RECOVERY KEY</span>
                    {!isBitlockerRevealed ? (
                      <button
                        className="btn-glass"
                        style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem', display: 'flex', alignItems: 'center', gap: '0.35rem', color: 'var(--primary)' }}
                        onClick={handleRequestBitlockerReveal}
                      >
                        <Eye size={12} /> Reveal Key (MFA)
                      </button>
                    ) : revealedBitlockerKey ? (
                      <button
                        className="btn-glass"
                        style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                        onClick={() => {
                          navigator.clipboard.writeText(revealedBitlockerKey);
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
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                  <div>
                    <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>TPM HARDWARE CHIP</span>
                    <div style={{ fontWeight: 600 }}>{device.tpm_version || 'TPM 2.0 (TCG Certified)'}</div>
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
                    <button
                      type="button"
                      className="btn-glass btn-icon"
                      onClick={() => handleDeleteNote(n.id)}
                      title="Delete Note"
                    >
                      <Trash2 size={12} color="#ef4444" />
                    </button>
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
                        <span className="status-pill status-online" style={{ fontSize: '0.68rem' }}>
                          Archived
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
                  <h3 style={{ fontSize: '1.15rem', fontWeight: 600, margin: 0 }}>Hardware Audit Trail &amp; Vendor Delta Tracking</h3>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    Accurate hardware component recognition decoded via PCI/SMBIOS Vendor IDs (Micron, Samsung, NVIDIA, Intel)
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
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                      {new Date(item.timestamp).toLocaleString()}
                    </span>
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
                          <span>Gateway IP: <code>{net.gateway_ip || '10.0.1.1'}</code></span>
                          <span>Gateway MAC: <code>{net.gateway_mac || '00:1A:2B:3C:4D:5E'}</code></span>
                          <span>Subnet: <code>{net.subnet || '10.0.1.0/24'}</code></span>
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
              <span className="status-pill status-reboot" style={{ fontSize: '0.72rem' }}>
                OEM Updates Synchronized
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
                            {soft.cve_count > 0 && (
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
                Ninja-style device custom fields. Values are injected into scripts and automation runbooks as <code>$vitrine.CustomField</code>.
              </span>
            </div>
            <button className="btn-glass btn-primary" onClick={handleSaveCustomFields} disabled={savingFields}>
              <Save size={15} /> {savingFields ? 'Saving...' : 'Save Attributes'}
            </button>
          </div>

          {fieldsSavedNotice && (
            <div style={{ background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.35)', padding: '0.65rem 1rem', borderRadius: '6px', color: '#34d399', fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <CheckCircle2 size={16} /> Attributes saved successfully and synchronized across policy inheritance hierarchy.
            </div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
            {customFields.map((f) => {
              const currentVal = fieldValues[f.id] ?? '';
              const options = f.options ? JSON.parse(f.options) : [];

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
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.85rem' }}>
                      <input
                        type="checkbox"
                        checked={currentVal === 'true'}
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
                        onChange={(e) => setFieldValues({ ...fieldValues, [f.id]: e.target.value })}
                      />
                      {currentUser?.role !== 'client_admin' && (f.has_secret || Boolean(currentVal)) && (
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
