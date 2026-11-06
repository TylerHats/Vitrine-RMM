import {
  Device,
  Tenant,
  Policy,
  Patch,
  ScriptItem,
  SelfHealingMonitor,
  Settings,
  ProcessItem,
  ServiceItem,
  CustomFieldDefinition,
  MaintenanceWindow,
  ChatMessage,
  SessionRecording,
  OemWarranty,
  EventLogItem,
  LapsCredential,
  AppNotification,
  HardwareHistoryItem,
  NetworkHistoryItem,
  SmartGroup,
  SoftwareItem,
  GuestAccessGrant,
  RbacUser,
  RemediationLog,
  DeviceNote
} from '../types/index.js';

const API_BASE = '/api';

export async function fetchSettings(): Promise<Settings> {
  const res = await fetch(`${API_BASE}/settings`);
  return res.json();
}

export async function updateSettings(settings: Partial<Settings>): Promise<{ success: boolean; settings: Settings }> {
  const res = await fetch(`${API_BASE}/settings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings)
  });
  return res.json();
}

export async function fetchTenants(): Promise<Tenant[]> {
  const res = await fetch(`${API_BASE}/tenants`);
  return res.json();
}

export async function fetchDevices(): Promise<Device[]> {
  const res = await fetch(`${API_BASE}/devices`);
  return res.json();
}

export async function fetchDevice(id: string): Promise<Device> {
  const res = await fetch(`${API_BASE}/devices/${id}`);
  return res.json();
}

export async function toggleQuarantine(id: string, quarantine: boolean): Promise<{ success: boolean; quarantined: boolean }> {
  const res = await fetch(`${API_BASE}/devices/${id}/quarantine`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ quarantine })
  });
  return res.json();
}

export async function fetchLapsPassword(id: string, reveal: boolean): Promise<LapsCredential> {
  const res = await fetch(`${API_BASE}/devices/${id}/laps?reveal=${reveal}`);
  return res.json();
}

export async function rotateLapsPassword(id: string): Promise<LapsCredential> {
  const res = await fetch(`${API_BASE}/devices/${id}/laps/rotate`, { method: 'POST' });
  return res.json();
}

export async function fetchProcesses(deviceId: string): Promise<ProcessItem[]> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/processes`);
  return res.json();
}

export async function killProcess(deviceId: string, pid: number): Promise<{ success: boolean }> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/processes/${pid}/kill`, { method: 'POST' });
  return res.json();
}

export async function fetchServices(deviceId: string): Promise<ServiceItem[]> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/services`);
  return res.json();
}

export async function manageService(deviceId: string, name: string, action: 'start' | 'stop' | 'restart'): Promise<{ success: boolean }> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/services/${name}/${action}`, { method: 'POST' });
  return res.json();
}

export async function fetchRegistry(deviceId: string, path?: string): Promise<{ subkeys: string[]; values: Array<{ path: string; name: string; type: string; value: string }> }> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/registry?path=${encodeURIComponent(path || '')}`);
  return res.json();
}

export async function fetchScheduledTasks(deviceId: string): Promise<Array<{ name: string; path: string; state: string; lastRunTime: string; nextRunTime: string; lastResult: string }>> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/tasks`);
  return res.json();
}

export async function fetchFiles(deviceId: string, path?: string): Promise<Array<{ name: string; path: string; size: number; isDirectory: boolean; modified: string; permissions: string }>> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/files?path=${encodeURIComponent(path || '')}`);
  return res.json();
}

export async function fetchEventLogs(deviceId: string, channel = 'System', level = 'all', limit = 50): Promise<EventLogItem[]> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/eventlogs?channel=${encodeURIComponent(channel)}&level=${encodeURIComponent(level)}&limit=${limit}`);
  return res.json();
}

export async function fetchPolicies(): Promise<Policy[]> {
  const res = await fetch(`${API_BASE}/policies`);
  return res.json();
}

export async function fetchPatches(): Promise<Patch[]> {
  const res = await fetch(`${API_BASE}/patches`);
  return res.json();
}

export async function approvePatch(patchId: string): Promise<{ success: boolean }> {
  const res = await fetch(`${API_BASE}/patches/${patchId}/approve`, { method: 'POST' });
  return res.json();
}

export async function rollbackPatch(patchId: string): Promise<{ success: boolean; message: string }> {
  const res = await fetch(`${API_BASE}/patches/${patchId}/rollback`, { method: 'POST' });
  return res.json();
}

export async function fetchScripts(tenantId?: string): Promise<ScriptItem[]> {
  const url = tenantId ? `${API_BASE}/scripts?tenantId=${encodeURIComponent(tenantId)}` : `${API_BASE}/scripts`;
  const res = await fetch(url);
  return res.json();
}

export async function fetchHardwareHistory(deviceId: string): Promise<HardwareHistoryItem[]> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/hardware-history`);
  return res.json();
}

export async function fetchNetworkHistory(deviceId: string): Promise<NetworkHistoryItem[]> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/network-history`);
  return res.json();
}

export async function verifyMfa(code: string, secretType?: string, deviceId?: string): Promise<{ success: boolean; error?: string }> {
  const res = await fetch(`${API_BASE}/auth/verify-mfa`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code, secretType, deviceId })
  });
  return res.json();
}

export async function runScript(scriptId: string, deviceIds: string[]): Promise<{ success: boolean; dispatchedCount: number; executionId: string }> {
  const res = await fetch(`${API_BASE}/scripts/${scriptId}/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceIds })
  });
  return res.json();
}

export async function fetchSelfHealing(): Promise<SelfHealingMonitor[]> {
  const res = await fetch(`${API_BASE}/self-healing`);
  return res.json();
}

export async function fetchTopology(): Promise<{ coreSwitch: { name: string; ip: string; ports: Array<{ port: string; vlan: number; speed: string; status: string; lldpNeighbor: string }> }; discoveredSubnets: Array<{ subnet: string; probeHost: string; totalDiscovered: number; unmanaged: number }> }> {
  const res = await fetch(`${API_BASE}/discovery/topology`);
  return res.json();
}

export async function fetchVirtualization(): Promise<Array<{ id: string; name: string; hostType: string; status: string; cpuUsagePct: number; ramUsageGb: number; ramTotalGb: number; storageFreeTb: number; storageTotalTb: number; vms: Array<{ vmid: number; name: string; status: string; os: string; cpu: number; ramGb: number }> }>> {
  const res = await fetch(`${API_BASE}/virtualization/hosts`);
  return res.json();
}

export async function fetchPsaTickets(): Promise<Array<{ id: string; ticket_number: string; title: string; client_name: string; device_id: string; status: string; priority: string; created_at: string }>> {
  const res = await fetch(`${API_BASE}/psa/tickets`);
  return res.json();
}

export async function testSmtp(data: { host: string; port: number; user?: string; pass?: string; from: string; to?: string }): Promise<{ success: boolean; message: string }> {
  const res = await fetch(`${API_BASE}/smtp/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json();
}

export async function fetchQbrReport(): Promise<{
  reportDate: string;
  quarter: string;
  fleetHealthScore: number;
  totalManagedEndpoints: number;
  endpointAvailability: string;
  patchCompliance: string;
  encryptionCompliance: string;
  edrProtectionRate: string;
  quarantinedEndpoints: number;
  remediationsAutomated: number;
  ticketsSynchronized: number;
}> {
  const res = await fetch(`${API_BASE}/reports/qbr`);
  return res.json();
}

// Custom Fields
export async function fetchCustomFields(): Promise<CustomFieldDefinition[]> {
  const res = await fetch(`${API_BASE}/custom-fields`);
  return res.json();
}

export async function saveCustomField(def: Partial<CustomFieldDefinition>): Promise<{ success: boolean; id: string }> {
  const res = await fetch(`${API_BASE}/custom-fields`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(def)
  });
  return res.json();
}

export async function fetchDeviceCustomFields(deviceId: string): Promise<CustomFieldDefinition[]> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/custom-fields`);
  return res.json();
}

export async function saveDeviceCustomFields(deviceId: string, fields: Record<string, string>): Promise<{ success: boolean }> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/custom-fields`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields })
  });
  return res.json();
}

// Maintenance Windows
export async function fetchMaintenanceWindows(): Promise<MaintenanceWindow[]> {
  const res = await fetch(`${API_BASE}/maintenance-windows`);
  return res.json();
}

export async function createMaintenanceWindow(win: Partial<MaintenanceWindow>): Promise<{ success: boolean; id: string }> {
  const res = await fetch(`${API_BASE}/maintenance-windows`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(win)
  });
  return res.json();
}

export async function toggleDeviceMaintenance(deviceId: string, active: boolean, minutes = 60): Promise<{ success: boolean; active: boolean; maintenanceUntil: string | null }> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/maintenance`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ active, minutes })
  });
  return res.json();
}

// Live Chat
export async function fetchChatMessages(deviceId: string): Promise<ChatMessage[]> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/chat`);
  return res.json();
}

export async function sendChatMessage(deviceId: string, message: string, sender = 'Tyler Hats (Tech)', senderRole: 'technician' | 'end_user' = 'technician'): Promise<{ success: boolean; id: string; timestamp: string }> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, sender, sender_role: senderRole })
  });
  return res.json();
}

// Session Recordings
export async function fetchRecordings(deviceId?: string): Promise<SessionRecording[]> {
  const url = deviceId ? `${API_BASE}/recordings?deviceId=${encodeURIComponent(deviceId)}` : `${API_BASE}/recordings`;
  const res = await fetch(url);
  return res.json();
}

export async function saveRecording(recording: Partial<SessionRecording>): Promise<{ success: boolean; id: string }> {
  const res = await fetch(`${API_BASE}/recordings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(recording)
  });
  return res.json();
}

// OEM Warranty
export async function fetchWarranty(deviceId: string): Promise<OemWarranty | null> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/warranty`);
  return res.json();
}

export async function triggerWarrantyLookup(deviceId: string): Promise<{ success: boolean; warranty: OemWarranty }> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/warranty/lookup`, { method: 'POST' });
  return res.json();
}

// Notifications & Prompts
export async function fetchNotifications(): Promise<AppNotification[]> {
  const res = await fetch(`${API_BASE}/notifications`);
  return res.json();
}

export async function markNotificationRead(id: string): Promise<{ success: boolean }> {
  const res = await fetch(`${API_BASE}/notifications/${id}/read`, { method: 'POST' });
  return res.json();
}

export async function executeNotificationAction(id: string, action: string, tenantId?: string): Promise<{ success: boolean; message?: string }> {
  const res = await fetch(`${API_BASE}/notifications/${id}/action`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, tenantId })
  });
  return res.json();
}

// Policy Management
export async function updatePolicy(id: string, updates: Partial<Policy>): Promise<{ success: boolean; policy: Policy }> {
  const res = await fetch(`${API_BASE}/policies/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates)
  });
  return res.json();
}

// Scripts Library
export async function createScript(script: Partial<ScriptItem>): Promise<{ success: boolean; id: string }> {
  const res = await fetch(`${API_BASE}/scripts`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(script)
  });
  return res.json();
}

export async function updateScript(id: string, updates: Partial<ScriptItem>): Promise<{ success: boolean }> {
  const res = await fetch(`${API_BASE}/scripts/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates)
  });
  return res.json();
}

// MeshCentral Sync & Tenants
export async function syncMeshCentral(): Promise<{
  success: boolean;
  imported: number;
  updated: number;
  unmappedMeshGroups: number;
  conflicts: Array<{ meshGroupId: string; meshGroupName: string; tenantId: string; deviceCount: number }>;
  message: string;
}> {
  const res = await fetch(`${API_BASE}/meshcentral/sync`, { method: 'POST' });
  return res.json();
}

export async function deleteTenant(id: string, action: 'uninstall' | 'move_to_unassigned' = 'move_to_unassigned'): Promise<{ success: boolean; action: string }> {
  const res = await fetch(`${API_BASE}/tenants/${id}?action=${action}`, { method: 'DELETE' });
  return res.json();
}

// Smart Groups
export async function fetchSmartGroups(): Promise<SmartGroup[]> {
  const res = await fetch(`${API_BASE}/smart-groups`);
  return res.json();
}

export async function createSmartGroup(group: Partial<SmartGroup>): Promise<{ success: boolean; id: string }> {
  const res = await fetch(`${API_BASE}/smart-groups`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(group)
  });
  return res.json();
}

export async function deleteSmartGroup(id: string): Promise<{ success: boolean }> {
  const res = await fetch(`${API_BASE}/smart-groups/${id}`, { method: 'DELETE' });
  return res.json();
}

// Software Inventory & CVEs
export async function fetchDeviceSoftware(deviceId: string): Promise<SoftwareItem[]> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/software`);
  return res.json();
}

// Tiered Wake-on-LAN Relay
export async function wakeDeviceOnLan(deviceId: string): Promise<{
  success: boolean;
  targetHostname?: string;
  targetMac?: string;
  tieredStrategy?: {
    tier1_current_subnet_relays: number;
    tier2_historical_subnets: number;
    tier3_amt_fallback: boolean;
  };
  dispatchedRelays?: string[];
  confirmationWindowSec?: number;
  verificationMode?: string;
  error?: string;
}> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/wake-on-lan`, { method: 'POST' });
  return res.json();
}

// Guest / Vendor Access System
export async function fetchGuestGrants(): Promise<GuestAccessGrant[]> {
  const res = await fetch(`${API_BASE}/guest-grants`);
  return res.json();
}

export async function createGuestGrant(data: {
  vendor_name: string;
  contact_email?: string;
  device_ids: string[];
  duration_hours?: number;
  can_remote_screen?: boolean;
  can_ghost_session?: boolean;
  can_view_telemetry?: boolean;
  can_view_hardware?: boolean;
  can_view_custom_fields?: boolean;
  can_run_scripts?: boolean;
}): Promise<{
  success: boolean;
  id?: string;
  tempUsername?: string;
  tempPassword?: string;
  expiresAt?: string;
  portalUrl?: string;
  error?: string;
}> {
  const res = await fetch(`${API_BASE}/guest-grants`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json();
}

export async function revokeGuestGrant(id: string): Promise<{ success: boolean }> {
  const res = await fetch(`${API_BASE}/guest-grants/${id}/revoke`, { method: 'POST' });
  return res.json();
}

export async function fetchGuestPortal(id: string): Promise<{
  success: boolean;
  grant?: {
    id: string;
    vendor_name: string;
    expires_at: string;
    permissions: Record<string, boolean>;
  };
  devices?: Device[];
  error?: string;
}> {
  const res = await fetch(`${API_BASE}/guest-portal/${id}`);
  return res.json();
}

// Installer Generator with PSA Ticket Enforcement
export async function generateInstaller(data: {
  tenant_id: string;
  site_id?: string;
  device_role?: string;
  ticket_number?: string;
  technician?: string;
  platform?: 'windows' | 'linux' | 'macos';
}): Promise<{
  success: boolean;
  tokenId?: string;
  platform?: string;
  tenantName?: string;
  ticketBound?: string | null;
  codeSigned?: boolean;
  downloadCommand?: string;
  installerUrl?: string;
  error?: string;
}> {
  const res = await fetch(`${API_BASE}/installers/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json();
}

export async function enableDeviceWakeOnLan(id: string): Promise<{
  success: boolean;
  actionsApplied?: string[];
  currentStatus?: string;
  error?: string;
}> {
  const res = await fetch(`${API_BASE}/devices/${id}/enable-wol`, {
    method: 'POST'
  });
  return res.json();
}

export async function provisionDeviceAmt(id: string): Promise<{
  success: boolean;
  amtSupported?: boolean;
  provisioningMode?: string;
  nodeDeduplication?: string;
  unlockedCapabilities?: string[];
  error?: string;
}> {
  const res = await fetch(`${API_BASE}/devices/${id}/provision-amt`, {
    method: 'POST'
  });
  return res.json();
}

// RBAC Users & Technicians
export async function fetchUsers(): Promise<RbacUser[]> {
  const res = await fetch(`${API_BASE}/users`);
  return res.json();
}

export async function createUser(data: { username: string; email: string; role: string; tenant_id?: string | null }): Promise<{ success: boolean; user: RbacUser }> {
  const res = await fetch(`${API_BASE}/users`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json();
}

export async function deleteUser(id: string): Promise<{ success: boolean }> {
  const res = await fetch(`${API_BASE}/users/${id}`, { method: 'DELETE' });
  return res.json();
}

// Tenant & Site Creation
export async function createTenant(data: { name: string; contact_email?: string; site_name?: string; subnet?: string }): Promise<{ success: boolean; id: string; siteId: string }> {
  const res = await fetch(`${API_BASE}/tenants`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json();
}

export async function createSite(data: { tenant_id: string; name: string; subnet: string }): Promise<{ success: boolean; id: string }> {
  const res = await fetch(`${API_BASE}/sites`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json();
}

// Policy Creation & Deletion
export async function createPolicy(policy: Partial<Policy>): Promise<{ success: boolean; policy: Policy }> {
  const res = await fetch(`${API_BASE}/policies`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(policy)
  });
  return res.json();
}

export async function deletePolicy(id: string): Promise<{ success: boolean; error?: string }> {
  const res = await fetch(`${API_BASE}/policies/${id}`, { method: 'DELETE' });
  return res.json();
}

// Self-Healing Watchdog CRUD & Evaluation
export async function fetchRemediationLogs(): Promise<RemediationLog[]> {
  const res = await fetch(`${API_BASE}/self-healing/logs`);
  return res.json();
}

export async function createSelfHealingMonitor(data: {
  name: string;
  condition_type: string;
  condition_value: string;
  remediation_script_id: string;
  cooldown_min?: number;
  alert_on_failure?: boolean;
}): Promise<{ success: boolean; monitor: SelfHealingMonitor }> {
  const res = await fetch(`${API_BASE}/self-healing`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json();
}

export async function updateSelfHealingMonitor(id: string, updates: Partial<SelfHealingMonitor>): Promise<{ success: boolean; monitor: SelfHealingMonitor }> {
  const res = await fetch(`${API_BASE}/self-healing/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates)
  });
  return res.json();
}

export async function deleteSelfHealingMonitor(id: string): Promise<{ success: boolean }> {
  const res = await fetch(`${API_BASE}/self-healing/${id}`, { method: 'DELETE' });
  return res.json();
}

export async function evaluateSelfHealingMonitors(): Promise<{
  success: boolean;
  evaluatedMonitors: number;
  evaluatedDevices: number;
  remediationsTriggered: number;
  logs: RemediationLog[];
}> {
  const res = await fetch(`${API_BASE}/self-healing/evaluate`, { method: 'POST' });
  return res.json();
}

// Interactive Background Tools Mutations (Registry, Tasks, Files)
export async function setRegistryValue(
  deviceId: string,
  data: { path: string; name: string; type: string; value: string }
): Promise<{ success: boolean; subkeys: string[]; values: Array<{ path: string; name: string; type: string; value: string }> }> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/registry`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json();
}

export async function deleteRegistryValue(
  deviceId: string,
  path: string,
  name: string
): Promise<{ success: boolean; subkeys: string[]; values: Array<{ path: string; name: string; type: string; value: string }> }> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/registry?path=${encodeURIComponent(path)}&name=${encodeURIComponent(name)}`, {
    method: 'DELETE'
  });
  return res.json();
}

export async function manageScheduledTask(
  deviceId: string,
  name: string,
  action: 'run' | 'enable' | 'disable'
): Promise<{ success: boolean; tasks: Array<{ name: string; path: string; state: string; lastRunTime: string; nextRunTime: string; lastResult: string }> }> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/tasks`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, action })
  });
  return res.json();
}

export async function manageRemoteFile(
  deviceId: string,
  data: { path: string; action: 'mkdir' | 'delete' | 'upload'; name: string; size?: number }
): Promise<{ success: boolean; files: Array<{ name: string; path: string; size: number; isDirectory: boolean; modified: string; permissions: string }> }> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/files`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json();
}

// Network Topology & Virtualization Actions
export async function triggerTopologyScan(subnet?: string, probeHost?: string): Promise<{ success: boolean }> {
  const res = await fetch(`${API_BASE}/discovery/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subnet, probeHost })
  });
  return res.json();
}

export async function addTopologyPort(data: { port: string; vlan: number; speed: string; status: string; lldpNeighbor: string }): Promise<{ success: boolean; id: string }> {
  const res = await fetch(`${API_BASE}/discovery/ports`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json();
}

export async function addVirtualizationHost(data: {
  name: string;
  hostType: string;
  ipAddress?: string;
  ramTotalGb?: number;
  storageTotalTb?: number;
}): Promise<{ success: boolean; id: string }> {
  const res = await fetch(`${API_BASE}/virtualization/hosts`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json();
}

export async function manageVmPower(
  hostId: string,
  vmid: number,
  action: 'start' | 'stop' | 'reboot' | 'snapshot'
): Promise<{ success: boolean }> {
  const res = await fetch(`${API_BASE}/virtualization/hosts/${hostId}/vms/${vmid}/action`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action })
  });
  return res.json();
}

// Patch Bulk Approval, Discovery Scan & Winget Upgrades
export async function scanPatches(): Promise<{ success: boolean; patches: Patch[] }> {
  const res = await fetch(`${API_BASE}/patches/scan`, { method: 'POST' });
  return res.json();
}

export async function approvePatchesBulk(patchIds: string[]): Promise<{ success: boolean; approvedCount: number }> {
  const res = await fetch(`${API_BASE}/patches/approve-bulk`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ patchIds })
  });
  return res.json();
}

export async function upgradeDeviceSoftware(deviceId: string, softId: string): Promise<{ success: boolean }> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/software/${softId}/upgrade`, { method: 'POST' });
  return res.json();
}

// Device Runbook Notes
export async function fetchDeviceNotes(deviceId: string): Promise<DeviceNote[]> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/notes`);
  return res.json();
}

export async function createDeviceNote(deviceId: string, data: { author?: string; content: string; is_pinned?: boolean }): Promise<{ success: boolean; note: DeviceNote }> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/notes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json();
}

export async function deleteDeviceNote(deviceId: string, noteId: string): Promise<{ success: boolean }> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/notes/${noteId}`, { method: 'DELETE' });
  return res.json();
}

// PSA Ticket Creation & Status Updates
export async function createPsaTicket(data: { title: string; client_name: string; device_id?: string; priority?: string }): Promise<{ success: boolean; id: string; ticketNumber: string }> {
  const res = await fetch(`${API_BASE}/psa/tickets`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json();
}

export async function updatePsaTicket(id: string, updates: { status?: string; priority?: string }): Promise<{ success: boolean }> {
  const res = await fetch(`${API_BASE}/psa/tickets/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates)
  });
  return res.json();
}

// Guest Portal Authentication
export async function authenticateGuestPortal(id: string, username: string, password: string): Promise<{ success: boolean; error?: string }> {
  const res = await fetch(`${API_BASE}/guest-portal/${id}/auth`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  return res.json();
}


