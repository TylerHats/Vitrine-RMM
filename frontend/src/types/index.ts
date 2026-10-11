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
  last_seen: string;
  created_at: string;
  policy?: any;
  laps?: any;
}

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  contact_email: string;
  device_count: number;
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
}

export interface ScriptItem {
  id: string;
  name: string;
  description: string;
  language: 'powershell' | 'batch' | 'bash' | 'python';
  code: string;
  category: string;
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
}
