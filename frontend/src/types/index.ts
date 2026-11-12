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
  bitlocker_key?: string;
  has_bitlocker_key?: boolean;
  manufacturer?: string;
  model?: string;
  wol_supported?: number | boolean;
  wol_status?: string;
  amt_supported?: number | boolean;
  amt_provisioned?: number | boolean;
  amt_version?: string;
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
  mesh_server_id?: string;
  agent_privilege_mode?: 'standard_user' | 'elevated_admin' | 'system_service';
  companion_installed?: number | boolean;
  agent_code_signed?: number | boolean;
  laps_account?: string;
  lifecycle_state?: 'active' | 'pending_offboard' | 'archived';
  tenant_lifecycle_state?: 'active' | 'pending_offboard' | 'archived';
  offboard_queued_at?: string | null;
  offboarded_at?: string | null;
  offboard_reason?: string | null;
  offboard_trigger_source?: 'explicit_device' | 'client_archived' | 'client_deleted' | null;
  offboard_laps_action_taken?: 'remove_account' | 'disable_account' | 'keep_account_rotate_final' | 'keep_account_as_is' | null;
  resurrected_at?: string | null;
  resurrect_count?: number;
}

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  contact_email: string;
  device_count: number;
  mesh_group_id?: string;
  mesh_server_id?: string;
  lifecycle_state?: 'active' | 'pending_offboard' | 'archived';
  archived_at?: string | null;
  offboard_reason?: string | null;
  offline_auto_archive_days?: number;
  sites?: Site[];
}

export interface Site {
  id: string;
  tenant_id: string;
  name: string;
  subnet: string;
}

export interface ConditionAlertRule {
  conditionId: string;
  label: string;
  category: 'availability' | 'security' | 'hardware_storage' | 'specialty_network';
  enabled: boolean;
  thresholdValue: number;
  thresholdUnit: 'hours' | 'days' | 'percent' | 'cvss' | 'state';
  severity: 'info' | 'warning' | 'critical';
  notifyWebUi: boolean;
  notifyEmail: boolean;
  createPsaTicket: boolean;
  autoResolveTicket: boolean;
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
  laps_auto_create_account?: number | boolean;
  laps_account_name?: string;
  laps_password_mode?: 'random' | 'passphrase' | 'static';
  laps_password_length?: number;
  laps_complexity?: string;
  laps_passphrase_words?: number;
  laps_passphrase_separator?: string;
  laps_static_password?: string;
  laps_rotation_days?: number;
  laps_rotate_on_access?: number | boolean;
  laps_post_access_grace_hours?: number;
  laps_cleanup_old_account_on_rename?: 'disable' | 'delete' | 'keep';
  laps_disable_builtin_sid500_admin?: number | boolean;
  laps_offboard_explicit_device_action?: 'remove_account' | 'disable_account' | 'keep_account_rotate_final' | 'keep_account_as_is';
  laps_offboard_client_archived_action?: 'remove_account' | 'disable_account' | 'keep_account_rotate_final' | 'keep_account_as_is';
  laps_offboard_client_deleted_action?: 'remove_account' | 'disable_account' | 'keep_account_rotate_final' | 'keep_account_as_is';
  offboard_offline_auto_archive_days?: number;
  require_mfa_for_secrets?: number | boolean;
  telemetry_history_retention_days?: number;
  hardware_audit_enabled?: number | boolean;
  network_drift_detection_enabled?: number | boolean;
  self_healing_max_hourly_runs?: number;
  self_healing_alert_psa?: number | boolean;
  alert_rules?: ConditionAlertRule[];
  alert_rules_json?: string | null;
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
  required_role?: 'admin' | 'super_admin' | 'technician' | 'readonly';
  os_type?: 'windows' | 'linux' | 'macos' | 'any';
  default_run_as?: 'system' | 'user';
  parameters_json?: string | null;
  parameters?: Array<{ name: string; label?: string; default?: string }>;
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
  previousAccountName?: string | null;
  password?: string;
  previousPassword?: string | null;
  passwordMode?: 'random' | 'passphrase' | 'static';
  autoCreateAccount?: boolean;
  sid500BuiltinDisabled?: boolean;
  cleanupOldAccountAction?: 'disable' | 'delete' | 'keep';
  expiresAt: string;
  lastRotated: string;
  autoRotateScheduled?: boolean;
  rotationPendingOnline?: boolean;
  pendingRotationReason?: string | null;
  pendingAccountName?: string | null;
  rotationStatus?: 'active' | 'rotated_live' | 'deferred_until_online' | 'skipped_pending_offboard';
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
  oobe_completed?: number | boolean;
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
  smtp_tls?: number | boolean;
  itflow_url: string;
  itflow_api_key: string;
  psa_webhook_secret?: string;
  agent_enrollment_secret?: string;
  oidc_enabled: number;
  oidc_issuer_url: string;
  oidc_client_id: string;
  oidc_client_secret?: string;
  patch_auto_approve_third_party?: number | boolean;
  patch_canary_delay_days?: number;
  code_signing_url?: string;
  code_signing_enabled?: number | boolean;
  code_signing_sign_scripts?: number | boolean;
  code_signing_sign_agents?: number | boolean;
  code_signing_sign_assemblies?: number | boolean;
  code_signing_sign_ms2_binary?: number | boolean;
  code_signing_strict_verify?: number | boolean;
  installer_download_role?: string;
  installer_require_ticket?: number | boolean;
  installer_gui_style?: 'modern_glass' | 'silent_headless' | 'native_ms2';
  installer_service_name?: string;
  installer_welcome_text?: string;
  session_recording_enabled?: number | boolean;
  session_recording_retention_days?: number;
  session_recording_quality?: string;
  session_recording_visual_indicator?: number | boolean;
  session_recording_stealth_for_techs?: number | boolean;
  maintenance_auto_clear_hours?: number;
  mesh_sync_enabled?: number | boolean;
  mesh_client_delete_action?: string;
  mesh_external_delete_prompt?: string | number;
  theme_mode?: 'system' | 'dark' | 'light';
  tray_theme_mode?: 'system' | 'dark' | 'light';
  quicksupport_enabled?: number | boolean;
  quicksupport_custom_domain?: string;
  quicksupport_url_path?: string;
  tls_mode?: 'reverse_proxy' | 'letsencrypt' | 'self_signed';
  reverse_proxy_type?: 'nginx' | 'npm' | 'caddy' | 'traefik' | 'cloudflare';
  letsencrypt_email?: string;
  update_channel?: 'stable' | 'alpha';
  installed_version?: string;
  installed_commit?: string;
  db_schema_version?: number;
  update_auto_backup?: number | boolean;
  update_auto_rollback?: number | boolean;
  update_notify_webui?: number | boolean;
  update_notify_email?: number | boolean;
  update_create_psa_ticket?: number | boolean;
  backup_schedule_enabled?: number | boolean;
  backup_schedule_frequency?: 'hourly' | 'daily' | 'weekly';
  backup_schedule_time?: string;
  backup_retention_count?: number;
  backup_max_storage_mb?: number;
  backup_include_branding?: number | boolean;
  backup_include_mesh_config?: number | boolean;
  backup_encryption_enabled?: number | boolean;
  backup_encryption_passphrase?: string;
  backup_offsite_enabled?: number | boolean;
  backup_offsite_provider?: 's3' | 'backblaze_b2' | 'b2' | 'minio' | 'sftp' | 'smb' | string;
  backup_offsite_endpoint?: string;
  backup_offsite_bucket?: string;
  backup_offsite_access_key?: string;
  backup_offsite_secret_key?: string;
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
  role: 'super_admin' | 'technician' | 'client_admin' | 'msp_super_admin' | 'senior_tech' | 'support_tech' | 'auditor' | string;
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

export type SpecialtyApplianceType =
  | 'firewall'
  | 'switch'
  | 'wap'
  | 'ups'
  | 'nas'
  | 'printer'
  | 'oob_bmc'
  | 'nvr_camera'
  | 'voip_pbx'
  | 'env_sensor'
  | 'pos_kiosk'
  | 'wan_ssl_probe'
  | string;

export interface NetworkAppliance {
  id: string;
  tenant_id: string;
  tenant_name?: string;
  site_id: string;
  site_name?: string;
  name: string;
  appliance_type: SpecialtyApplianceType;
  vendor_model: string;
  ip_address: string;
  mac_address: string;
  snmp_version: string;
  integration_protocol?: string;
  vendor_api_endpoint?: string | null;
  vendor_api_token_masked?: string | null;
  probe_device_id: string;
  probe_hostname: string;
  status: 'online' | 'warning' | 'critical' | 'offline' | 'Healthy' | 'Warning';
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

export interface MeshServer {
  id: string;
  name: string;
  url: string;
  api_token: string;
  is_primary: number | boolean;
  status: string;
  local_config_path?: string | null;
  agent_service_name: string;
  agent_display_name: string;
  agent_custom_text: string;
  keep_agents_signed: number | boolean;
  auto_push_companion: number | boolean;
  discovered_groups_count: number;
  discovered_agents_count: number;
  last_synced: string;
  created_at: string;
}

export interface MeshDiscoveryResult {
  success: boolean;
  reachable: boolean;
  serverUrl: string;
  meshVersion: string;
  coexistenceSafe: boolean;
  tlsVerified: boolean;
  summary: string;
  discoveredGroups: Array<{
    meshGroupId: string;
    name: string;
    siteGuess: string;
    agentCount: number;
    onlineCount: number;
    matchedTenantId: string | null;
    recommendedAction: 'merge_existing_client' | 'import_as_new_client';
  }>;
  discoveredAgents: Array<{
    meshNodeId: string;
    hostname: string;
    os: string;
    ip: string;
    groupName: string;
    online: boolean;
    companionInstalled: boolean;
    codeSignedBinary: boolean;
  }>;
}

export interface SigningStageReport {
  stepNumber: number;
  component: string;
  description: string;
  status: 'signed' | 'verified' | 'bypassed' | 'unreachable';
  sha256: string;
  timestampAuthority: string;
  durationMs: number;
}

export interface QuickSupportSession {
  id: string;
  device_id?: string | null;
  session_code: string;
  client_name: string;
  tenant_id?: string;
  mesh_server_id?: string;
  status: 'waiting' | 'connected' | 'elevated' | 'installed_permanent' | 'expired';
  privilege_level: 'standard_user' | 'elevated_admin' | 'system_service';
  platform: 'windows' | 'linux' | 'macos';
  hostname?: string;
  username?: string;
  code_signed: number | boolean;
  expires_at: string;
  created_at: string;
}

export interface BackupCompatibilityReport {
  status: 'exact_match' | 'older_db_auto_migratable' | 'newer_db_warning';
  backupSchemaVersion: number;
  targetSoftwareSchemaVersion: number;
  backupAppVersion: string;
  targetAppVersion: string;
  backupGitCommit: string;
  canRestoreCleanly: boolean;
  requiresAdminResolution: boolean;
  message: string;
  resolutionOptions: Array<{
    id: 'auto_migrate' | 'upgrade_software_to_match' | 'compatibility_safe_import' | 'cancel';
    label: string;
    description: string;
    recommended?: boolean;
  }>;
}

export interface SystemBackupItem {
  id: string;
  filename: string;
  file_path: string;
  size_bytes: number;
  trigger_type: 'manual' | 'scheduled' | 'pre-update' | 'pre-restore' | 'uploaded';
  app_version: string;
  git_commit: string;
  db_schema_version: number;
  sha256_hash: string;
  includes_branding: number | boolean;
  includes_mesh_config: number | boolean;
  encrypted?: number | boolean;
  offsite_synced?: number | boolean;
  offsite_location?: string;
  notes?: string;
  created_at: string;
  compatibility?: BackupCompatibilityReport;
}

export interface BreakGlassRecoveryEntry {
  deviceId: string;
  hostname: string;
  tenantName: string;
  siteName: string;
  lifecycleState: string;
  serialNumber: string;
  osVersion: string;
  lapsAccountName: string;
  currentLapsPassword: string;
  previousLapsAccountName: string | null;
  previousLapsPassword: string | null;
  bitlockerRecoveryKey: string;
  bitlockerStatus: string;
  sid500BuiltinDisabled: boolean;
  lastRotated: string;
  offboardedAt: string | null;
}

export interface UpdaterStatus {
  channel: 'stable' | 'alpha';
  deploymentMode?: 'docker' | 'bare_metal';
  upstreamSource?: string;
  dockerPullInstructions?: string | null;
  installedVersion: string;
  installedCommit: string;
  installedSchemaVersion: number;
  targetSoftwareSchemaVersion: number;
  dbNewerThanSoftware: boolean;
  updateAvailable: boolean;
  latestStable: {
    version: string;
    tag: string;
    commitSha: string;
    publishedAt: string;
    schemaVersion: number;
    title: string;
    releaseNotes: string;
  };
  latestAlpha: {
    sha: string;
    date: string;
    author: string;
    message: string;
    schemaVersion: number;
  };
  stableReleases: Array<{
    version: string;
    tag: string;
    commitSha: string;
    publishedAt: string;
    schemaVersion: number;
    title: string;
    releaseNotes: string;
  }>;
  pendingAlphaCommits: Array<{
    sha: string;
    date: string;
    author: string;
    message: string;
    schemaVersion: number;
  }>;
  allRecentCommits: Array<{
    sha: string;
    date: string;
    author: string;
    message: string;
    schemaVersion: number;
  }>;
  canSwitchAlphaToStable: boolean;
  alphaToStableBlockReason: string | null;
  preferences: {
    autoBackup: boolean;
    autoRollback: boolean;
    notifyWebUi: boolean;
    notifyEmail: boolean;
    createPsaTicket: boolean;
  };
  history: Array<{
    id: string;
    channel: string;
    from_version: string;
    to_version: string;
    from_commit: string;
    to_commit: string;
    status: 'completed' | 'rolled_back' | 'failed';
    backup_id?: string | null;
    error_log?: string | null;
    release_notes?: string | null;
    executed_at: string;
  }>;
}




export interface AuthUser {
  id: string;
  username: string;
  email: string;
  role: 'msp_super_admin' | 'super_admin' | 'admin' | 'technician' | 'senior_tech' | 'support_tech' | 'client_admin' | 'auditor' | string;
  tenant_id: string | null;
  totp_enabled: boolean;
}

export interface AuthStatusResponse {
  initialized: boolean;
  authenticated: boolean;
  user: AuthUser | null;
  mfaVerified: boolean;
  mfaVerifiedUntil: string | null;
  isOnboarded: boolean;
  oidcEnabled: boolean;
  branding: {
    brand_name: string;
    brand_logo_url: string;
    primary_color: string;
    theme_mode: 'system' | 'dark' | 'light';
  };
}

export interface PublicPortalConfig {
  brand_name: string;
  brand_logo_url: string;
  primary_color: string;
  glass_blur_level: string;
  theme_mode: 'system' | 'dark' | 'light';
  quicksupport_enabled: boolean;
  quicksupport_url_path: string;
  quicksupport_custom_domain: string;
  code_signing_enabled: boolean;
}
