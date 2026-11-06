export interface Device {
  id: string;
  mesh_node_id: string;
  tenant_id: string;
  tenant_name?: string;
  site_id: string;
  site_name?: string;
  hostname: string;
  os_type: 'windows' | 'linux' | 'macos';
  os_version: string;
  os_build: string;
  ip_address: string;
  mac_address: string;
  status: 'online' | 'offline' | 'isolated' | 'reboot_pending';
  device_role: string;
  cpu_model: string;
  cpu_cores: number;
  cpu_usage: number;
  ram_total_gb: number;
  ram_used_gb: number;
  disk_total_gb: number;
  disk_free_gb: number;
  smart_status: 'Healthy' | 'Warning' | 'Failing';
  bitlocker_status: string;
  bitlocker_key: string;
  tpm_version: string;
  bios_version: string;
  serial_number: string;
  edr_name: string;
  edr_status: string;
  pending_reboot: number;
  quarantined: number;
  intel_amt_enabled: number;
  intel_amt_reachable?: number;
  last_seen: string;
  created_at: string;
  enrolled_at?: string;
  policy?: Record<string, unknown>;
  laps?: LapsCredential | null;
  maintenance_until?: string | null;
  maintenance_active?: boolean;
  active_maintenance?: { title?: string; end_time: string } | null;
  warranty?: OemWarranty | null;
}

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  contact_email: string;
  device_count: number;
  mesh_group_id?: string;
  sites?: Site[];
}

export interface Site {
  id: string;
  tenant_id: string;
  name: string;
  subnet: string;
}

export interface Policy {
  id: string;
  name: string;
  tier: 'global' | 'client' | 'site' | 'role';
  target_id: string | null;
  telemetry_interval_sec: number;
  require_remote_consent: number;
  consent_timeout_sec: number;
  consent_timeout_action: string;
  auto_lock_on_disconnect: number;
  patch_schedule: string;
  patch_reboot_enforcement: string;
  self_healing_enabled: number;
  max_snooze_hours?: number;
  force_reboot_after_snooze?: number;
  final_countdown_sec?: number;
  laps_enabled?: number | boolean;
  laps_account_name?: string;
  laps_password_length?: number;
  laps_complexity?: string;
  laps_rotation_days?: number;
  laps_rotate_on_access?: number | boolean;
  laps_post_access_grace_hours?: number;
  require_mfa_for_secrets?: number | boolean;
  telemetry_history_retention_days?: number;
  hardware_audit_enabled?: number | boolean;
  network_drift_detection_enabled?: number | boolean;
  self_healing_max_hourly_runs?: number;
  self_healing_alert_psa?: number | boolean;
}

export interface Patch {
  id: string;
  device_id: string;
  hostname?: string;
  title: string;
  kb_id: string;
  category: string;
  severity: string;
  status: string;
  release_date: string;
  cve_id?: string;
  cvss_score?: number;
}

export interface ScriptItem {
  id: string;
  name: string;
  description: string;
  language: 'powershell' | 'batch' | 'bash' | 'python';
  code: string;
  category: string;
  enabled?: number | boolean;
  required_role?: 'admin' | 'technician' | 'readonly';
  is_builtin?: number | boolean;
  tenant_id?: string | null;
}

export interface SelfHealingMonitor {
  id: string;
  name: string;
  condition_type: string;
  condition_value: string;
  remediation_script_id: string;
  cooldown_min: number;
  alert_on_failure: number;
  enabled: number;
}

export interface LapsCredential {
  deviceId: string;
  accountName: string;
  password?: string;
  expiresAt: string;
  lastRotated: string;
  autoRotateScheduled?: boolean;
}

export interface HardwareHistoryItem {
  id: string;
  device_id: string;
  change_type: string;
  description: string;
  vendor_id?: string;
  device_id_pci?: string;
  timestamp: string;
}

export interface NetworkHistoryItem {
  id: string;
  device_id: string;
  ssid?: string;
  bssid?: string;
  gateway_ip?: string;
  gateway_mac?: string;
  subnet?: string;
  interface_name?: string;
  connected_at: string;
  disconnected_at?: string | null;
  is_flagged_drift: number | boolean;
}

export interface ProcessItem {
  pid: number;
  name: string;
  user: string;
  cpu: number;
  memoryMb: number;
  threads: number;
}

export interface ServiceItem {
  name: string;
  displayName: string;
  status: 'Running' | 'Stopped' | 'Paused';
  startType: 'Automatic' | 'Manual' | 'Disabled';
}

export interface Settings {
  id: number;
  is_onboarded: number;
  brand_name: string;
  brand_logo_url: string;
  primary_color: string;
  glass_blur_level: string;
  custom_domain: string;
  meshcentral_url: string;
  meshcentral_api_token: string;
  meshcentral_connected: number;
  smtp_host: string;
  smtp_port: number;
  smtp_user: string;
  smtp_pass: string;
  smtp_from: string;
  itflow_url: string;
  itflow_api_key: string;
  oidc_enabled: number;
  oidc_issuer_url: string;
  oidc_client_id: string;
  code_signing_url?: string;
  code_signing_enabled?: number | boolean;
  code_signing_sign_scripts?: number | boolean;
  code_signing_sign_agents?: number | boolean;
  code_signing_sign_assemblies?: number | boolean;
  installer_download_role?: string;
  installer_require_ticket?: number | boolean;
  session_recording_enabled?: number | boolean;
  session_recording_retention_days?: number;
  session_recording_quality?: string;
  session_recording_visual_indicator?: number | boolean;
  session_recording_stealth_for_techs?: number | boolean;
  maintenance_auto_clear_hours?: number;
  mesh_sync_enabled?: number | boolean;
  mesh_client_delete_action?: string;
  mesh_external_delete_prompt?: string | number;
}

export interface AppNotification {
  id: string;
  type: string;
  title: string;
  message: string;
  severity: 'info' | 'warning' | 'error' | 'critical' | 'danger';
  actions_json?: string | null;
  is_read: number | boolean;
  created_at: string;
}

export interface CustomFieldDefinition {
  id: string;
  key: string;
  label: string;
  category: string;
  field_type: 'text' | 'number' | 'dropdown' | 'multiselect' | 'secret' | 'date' | 'ip' | 'checkbox' | 'url';
  scope: 'device' | 'tenant' | 'site';
  options?: string | null;
  description?: string | null;
  current_value?: string | null;
  value_updated_at?: string | null;
}

export interface MaintenanceWindow {
  id: string;
  device_id?: string | null;
  tenant_id?: string | null;
  title: string;
  start_time: string;
  end_time: string;
  is_active: number;
  suppress_alerts: number;
}

export interface ChatMessage {
  id: string;
  device_id: string;
  sender: string;
  sender_role: 'technician' | 'end_user' | 'system';
  message: string;
  read_status: number;
  created_at: string;
}

export interface SessionRecording {
  id: string;
  device_id: string;
  hostname?: string;
  technician: string;
  duration_sec: number;
  file_path: string;
  file_size_mb: number;
  sha256_hash?: string | null;
  is_ghost_session: number;
  created_at: string;
}

export interface OemWarranty {
  device_id: string;
  serial_number: string;
  manufacturer: string;
  purchase_date?: string;
  warranty_expiration?: string;
  service_level?: string;
  status: string;
  last_checked: string;
}

export interface EventLogItem {
  id: number;
  timeGenerated: string;
  source: string;
  eventId: number;
  level: 'Critical' | 'Error' | 'Warning' | 'Information';
  channel: string;
  message: string;
}

export interface SmartGroup {
  id: string;
  name: string;
  description?: string;
  tenant_id?: string | null;
  criteria_json: string;
  criteria?: Record<string, unknown>;
  created_at: string;
}

export interface SoftwareItem {
  id: string;
  device_id: string;
  name: string;
  version: string;
  publisher?: string;
  install_date?: string;
  cve_count: number;
  highest_cvss: number;
  cve_list?: Array<{ id: string; cvss: number; severity: string; summary: string }>;
  auto_patchable: number | boolean;
}

export interface GuestAccessGrant {
  id: string;
  vendor_name: string;
  contact_email?: string;
  temp_username: string;
  temp_password?: string;
  device_ids: string[];
  can_remote_screen: boolean | number;
  can_ghost_session: boolean | number;
  can_view_telemetry: boolean | number;
  can_view_hardware: boolean | number;
  can_view_custom_fields: boolean | number;
  can_run_scripts: boolean | number;
  expires_at: string;
  created_at: string;
  status: 'active' | 'expired' | 'revoked';
  is_expired?: boolean;
}

export interface RbacUser {
  id: string;
  username: string;
  email: string;
  role: 'msp_super_admin' | 'client_admin' | 'senior_tech' | 'support_tech' | 'auditor';
  tenant_id?: string | null;
  tenant_name?: string | null;
  created_at: string;
}

export interface RemediationLog {
  id: string;
  monitor_id: string;
  monitor_name: string;
  device_id: string;
  hostname: string;
  script_id: string;
  status: string;
  output: string;
  executed_at: string;
}

export interface DeviceNote {
  id: string;
  device_id: string;
  author: string;
  content: string;
  is_pinned: number | boolean;
  created_at: string;
}

export interface NetworkAppliance {
  id: string;
  tenant_id: string;
  tenant_name?: string;
  site_id: string;
  site_name?: string;
  name: string;
  appliance_type: 'firewall' | 'switch' | 'ups' | 'nas' | 'printer';
  vendor_model: string;
  ip_address: string;
  mac_address: string;
  snmp_version: string;
  probe_device_id: string;
  probe_hostname: string;
  status: 'online' | 'warning' | 'critical' | 'offline';
  uptime_days: number;
  latency_ms: number;
  packet_loss_pct: number;
  cpu_pct: number;
  memory_pct: number;
  metrics: Record<string, string | number>;
  alert_summary?: string | null;
  last_polled: string;
}

export interface WakeChainStage {
  tier: number;
  name: string;
  protocol: string;
  relayHost: string;
  targetEndpoint: string;
  status: 'success' | 'escalated' | 'skipped';
  latencyMs: number;
  detail: string;
}

export interface WakeOnLanResult {
  success: boolean;
  targetDeviceId?: string;
  targetHostname: string;
  targetIp?: string;
  targetMac: string;
  tenantName?: string;
  siteName?: string;
  newStatus?: string;
  bootTarget?: string;
  tieredStrategy: {
    tier1_current_subnet_relays: number;
    tier2_historical_subnets: number;
    tier3_amt_fallback: boolean;
  };
  dispatchedRelays: string[];
  stages?: WakeChainStage[];
  confirmationWindowSec: number;
  verificationMode: string;
}

export interface RemoteSessionDescriptor {
  success: boolean;
  sessionId: string;
  deviceId: string;
  hostname: string;
  osType: 'windows' | 'linux' | 'macos';
  mode: 'kvm' | 'ghost' | 'amt_kvm';
  monitor: number;
  displayDriver: string;
  sessionIsolation: string;
  audioPipeline: string;
  resolution: string;
  meshRelayUrl?: string | null;
  userInterference: string;
}


