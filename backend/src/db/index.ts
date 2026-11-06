import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Database storage location (inside persistent data/ folder)
const DATA_CANDIDATES = [
  process.env.DATA_DIR,
  path.resolve(process.cwd(), 'data'),
  path.resolve(process.cwd(), '../data'),
  path.resolve(__dirname, '../../../data'),
  path.resolve(__dirname, '../../data')
].filter(Boolean) as string[];

const DATA_DIR = DATA_CANDIDATES.find((p) => fs.existsSync(p)) || DATA_CANDIDATES[0] || path.join(process.cwd(), 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, 'vitrine.db');
export const db = new Database(DB_PATH);

// Enable WAL mode for concurrent readers & high performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

export function initDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      is_onboarded INTEGER NOT NULL DEFAULT 1,
      brand_name TEXT NOT NULL DEFAULT 'Vitrine RMM',
      brand_logo_url TEXT NOT NULL DEFAULT '/branding/logo.png',
      primary_color TEXT NOT NULL DEFAULT '#00f2fe',
      glass_blur_level TEXT NOT NULL DEFAULT 'high',
      custom_domain TEXT NOT NULL DEFAULT 'rmm.vitrine.local',
      meshcentral_url TEXT NOT NULL DEFAULT 'https://127.0.0.1:443',
      meshcentral_api_token TEXT NOT NULL DEFAULT '',
      meshcentral_connected INTEGER NOT NULL DEFAULT 1,
      smtp_host TEXT NOT NULL DEFAULT 'smtp.mailgun.org',
      smtp_port INTEGER NOT NULL DEFAULT 587,
      smtp_user TEXT NOT NULL DEFAULT 'postmaster@vitrine.local',
      smtp_pass TEXT NOT NULL DEFAULT '',
      smtp_from TEXT NOT NULL DEFAULT 'alerts@vitrine-rmm.internal',
      smtp_tls INTEGER NOT NULL DEFAULT 1,
      itflow_url TEXT NOT NULL DEFAULT 'https://itflow.internal/api/v1',
      itflow_api_key TEXT NOT NULL DEFAULT '',
      oidc_enabled INTEGER NOT NULL DEFAULT 1,
      oidc_issuer_url TEXT NOT NULL DEFAULT 'https://auth.internal/application/o/vitrine/',
      oidc_client_id TEXT NOT NULL DEFAULT 'vitrine-rmm-client',
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS tenants (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      contact_email TEXT NOT NULL,
      device_count INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS sites (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      name TEXT NOT NULL,
      subnet TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      role TEXT NOT NULL DEFAULT 'msp_super_admin',
      tenant_id TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      mesh_node_id TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      site_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      os_type TEXT NOT NULL DEFAULT 'windows',
      os_version TEXT NOT NULL,
      os_build TEXT NOT NULL,
      ip_address TEXT NOT NULL,
      mac_address TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'online',
      device_role TEXT NOT NULL DEFAULT 'Workstation',
      cpu_model TEXT NOT NULL,
      cpu_cores INTEGER NOT NULL DEFAULT 8,
      cpu_usage REAL NOT NULL DEFAULT 18.5,
      ram_total_gb REAL NOT NULL DEFAULT 32.0,
      ram_used_gb REAL NOT NULL DEFAULT 11.2,
      disk_total_gb REAL NOT NULL DEFAULT 1000.0,
      disk_free_gb REAL NOT NULL DEFAULT 642.0,
      smart_status TEXT NOT NULL DEFAULT 'Healthy',
      bitlocker_status TEXT NOT NULL DEFAULT 'Encrypted (XTS-AES 256)',
      bitlocker_key TEXT NOT NULL DEFAULT '481920-592019-209184-102948-592810-482019',
      tpm_version TEXT NOT NULL DEFAULT '2.0',
      bios_version TEXT NOT NULL DEFAULT 'Dell Inc. 1.22.0 (UEFI)',
      serial_number TEXT NOT NULL DEFAULT 'VMW-9842-DLX-991',
      edr_name TEXT NOT NULL DEFAULT 'Microsoft Defender Antivirus',
      edr_status TEXT NOT NULL DEFAULT 'Active & Up to Date',
      pending_reboot INTEGER NOT NULL DEFAULT 0,
      quarantined INTEGER NOT NULL DEFAULT 0,
      intel_amt_enabled INTEGER NOT NULL DEFAULT 1,
      last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      tier TEXT NOT NULL DEFAULT 'global',
      target_id TEXT,
      telemetry_interval_sec INTEGER NOT NULL DEFAULT 30,
      require_remote_consent INTEGER NOT NULL DEFAULT 1,
      consent_timeout_sec INTEGER NOT NULL DEFAULT 30,
      consent_timeout_action TEXT NOT NULL DEFAULT 'cancel',
      auto_lock_on_disconnect INTEGER NOT NULL DEFAULT 1,
      patch_schedule TEXT NOT NULL DEFAULT 'Tuesdays @ 02:00 AM',
      patch_reboot_enforcement TEXT NOT NULL DEFAULT 'Prompt 4h, then force reboot',
      self_healing_enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS laps_vault (
      device_id TEXT PRIMARY KEY,
      account_name TEXT NOT NULL DEFAULT 'LocalAdmin',
      encrypted_password TEXT NOT NULL,
      iv TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      last_rotated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS patches (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      title TEXT NOT NULL,
      kb_id TEXT NOT NULL,
      category TEXT NOT NULL,
      severity TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Pending',
      release_date TEXT NOT NULL,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS scripts (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT NOT NULL,
      language TEXT NOT NULL DEFAULT 'powershell',
      code TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'Remediation',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS self_healing_monitors (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      condition_type TEXT NOT NULL,
      condition_value TEXT NOT NULL,
      remediation_script_id TEXT NOT NULL,
      cooldown_min INTEGER NOT NULL DEFAULT 15,
      alert_on_failure INTEGER NOT NULL DEFAULT 1,
      enabled INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      device_id TEXT,
      action TEXT NOT NULL,
      details TEXT NOT NULL,
      timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS psa_tickets (
      id TEXT PRIMARY KEY,
      ticket_number TEXT NOT NULL,
      title TEXT NOT NULL,
      client_name TEXT NOT NULL,
      device_id TEXT,
      status TEXT NOT NULL DEFAULT 'Open',
      priority TEXT NOT NULL DEFAULT 'High',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS custom_field_definitions (
      id TEXT PRIMARY KEY,
      key TEXT NOT NULL UNIQUE,
      label TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'Custom',
      field_type TEXT NOT NULL DEFAULT 'text',
      scope TEXT NOT NULL DEFAULT 'device',
      options TEXT,
      description TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS custom_field_values (
      id TEXT PRIMARY KEY,
      field_id TEXT NOT NULL,
      entity_id TEXT NOT NULL,
      value TEXT,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (field_id) REFERENCES custom_field_definitions(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS maintenance_windows (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      tenant_id TEXT,
      title TEXT NOT NULL,
      start_time TEXT NOT NULL,
      end_time TEXT NOT NULL,
      is_active INTEGER NOT NULL DEFAULT 1,
      suppress_alerts INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS session_recordings (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      technician TEXT NOT NULL DEFAULT 'admin',
      duration_sec INTEGER NOT NULL DEFAULT 0,
      file_path TEXT NOT NULL,
      file_size_mb REAL NOT NULL DEFAULT 0.0,
      sha256_hash TEXT,
      is_ghost_session INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS chat_messages (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      sender TEXT NOT NULL,
      sender_role TEXT NOT NULL DEFAULT 'technician',
      message TEXT NOT NULL,
      read_status INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS oem_warranties (
      device_id TEXT PRIMARY KEY,
      serial_number TEXT NOT NULL,
      manufacturer TEXT NOT NULL,
      purchase_date TEXT,
      warranty_expiration TEXT,
      service_level TEXT,
      status TEXT NOT NULL DEFAULT 'Active',
      last_checked TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'info',
      actions_json TEXT,
      is_read INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS hardware_history (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      change_type TEXT NOT NULL,
      description TEXT NOT NULL,
      vendor_id TEXT,
      device_id_pci TEXT,
      timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS network_history (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      ssid TEXT,
      bssid TEXT,
      gateway_ip TEXT,
      gateway_mac TEXT,
      subnet TEXT,
      interface_name TEXT,
      connected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      disconnected_at TEXT,
      is_flagged_drift INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS guest_access_grants (
      id TEXT PRIMARY KEY,
      vendor_name TEXT NOT NULL,
      contact_email TEXT,
      temp_username TEXT NOT NULL,
      temp_password TEXT NOT NULL,
      device_ids_json TEXT NOT NULL,
      can_remote_screen INTEGER NOT NULL DEFAULT 1,
      can_ghost_session INTEGER NOT NULL DEFAULT 0,
      can_view_telemetry INTEGER NOT NULL DEFAULT 1,
      can_view_hardware INTEGER NOT NULL DEFAULT 1,
      can_view_custom_fields INTEGER NOT NULL DEFAULT 0,
      can_run_scripts INTEGER NOT NULL DEFAULT 0,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      status TEXT NOT NULL DEFAULT 'active'
    );

    CREATE TABLE IF NOT EXISTS smart_groups (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      tenant_id TEXT,
      criteria_json TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS software_inventory (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      name TEXT NOT NULL,
      version TEXT NOT NULL,
      publisher TEXT,
      install_date TEXT,
      cve_count INTEGER NOT NULL DEFAULT 0,
      highest_cvss REAL NOT NULL DEFAULT 0.0,
      cve_list_json TEXT,
      auto_patchable INTEGER NOT NULL DEFAULT 1,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS installer_audit_log (
      id TEXT PRIMARY KEY,
      token_id TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      site_id TEXT,
      device_role TEXT NOT NULL DEFAULT 'workstation',
      technician TEXT NOT NULL,
      ticket_number TEXT,
      platform TEXT NOT NULL DEFAULT 'windows',
      downloaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      redeemed_at TEXT,
      redeemed_device_id TEXT
    );

    CREATE TABLE IF NOT EXISTS remediation_logs (
      id TEXT PRIMARY KEY,
      monitor_id TEXT NOT NULL,
      monitor_name TEXT NOT NULL,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      script_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Success',
      output TEXT NOT NULL,
      executed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS virtualization_hosts (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      host_type TEXT NOT NULL,
      ip_address TEXT NOT NULL DEFAULT '192.168.40.5',
      status TEXT NOT NULL DEFAULT 'Online',
      cpu_usage_pct REAL NOT NULL DEFAULT 24.8,
      ram_usage_gb REAL NOT NULL DEFAULT 92.4,
      ram_total_gb REAL NOT NULL DEFAULT 256.0,
      storage_free_tb REAL NOT NULL DEFAULT 4.8,
      storage_total_tb REAL NOT NULL DEFAULT 8.0
    );

    CREATE TABLE IF NOT EXISTS virtualization_vms (
      id TEXT PRIMARY KEY,
      host_id TEXT NOT NULL,
      vmid INTEGER NOT NULL,
      name TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Running',
      os TEXT NOT NULL,
      cpu INTEGER NOT NULL DEFAULT 4,
      ram_gb INTEGER NOT NULL DEFAULT 8,
      last_snapshot TEXT,
      FOREIGN KEY (host_id) REFERENCES virtualization_hosts(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS topology_ports (
      id TEXT PRIMARY KEY,
      switch_name TEXT NOT NULL DEFAULT 'SW-CORE-01 (Cisco Catalyst 9300-48P)',
      switch_ip TEXT NOT NULL DEFAULT '10.200.10.1',
      port TEXT NOT NULL,
      vlan INTEGER NOT NULL DEFAULT 1,
      status TEXT NOT NULL DEFAULT 'Up',
      speed TEXT NOT NULL DEFAULT '1000 Mbps',
      lldp_neighbor TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS topology_subnets (
      id TEXT PRIMARY KEY,
      subnet TEXT NOT NULL,
      probe_host TEXT NOT NULL,
      total_discovered INTEGER NOT NULL DEFAULT 1,
      unmanaged INTEGER NOT NULL DEFAULT 0,
      last_scanned TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS device_notes (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      author TEXT NOT NULL DEFAULT 'admin',
      content TEXT NOT NULL,
      is_pinned INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS network_appliances (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL DEFAULT 't-apex',
      site_id TEXT NOT NULL DEFAULT 's-apex-hq',
      name TEXT NOT NULL,
      appliance_type TEXT NOT NULL,
      vendor_model TEXT NOT NULL,
      ip_address TEXT NOT NULL,
      mac_address TEXT NOT NULL,
      snmp_version TEXT NOT NULL DEFAULT 'v3',
      probe_device_id TEXT NOT NULL,
      probe_hostname TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Healthy',
      uptime_days REAL NOT NULL DEFAULT 45.2,
      latency_ms REAL NOT NULL DEFAULT 1.4,
      packet_loss_pct REAL NOT NULL DEFAULT 0.0,
      cpu_pct REAL NOT NULL DEFAULT 18.0,
      memory_pct REAL NOT NULL DEFAULT 34.0,
      metrics_json TEXT NOT NULL DEFAULT '{}',
      alert_summary TEXT,
      last_polled TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Safe migrations for newly added columns
  const safeAddColumn = (table: string, columnDef: string) => {
    try {
      db.exec(`ALTER TABLE ${table} ADD COLUMN ${columnDef}`);
    } catch {
      // Column already exists
    }
  };

  safeAddColumn('devices', 'maintenance_until TEXT');
  safeAddColumn('devices', 'warranty_expiration TEXT');
  safeAddColumn('devices', 'enrolled_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP');
  safeAddColumn('devices', 'intel_amt_reachable INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('patches', 'cve_id TEXT');
  safeAddColumn('patches', 'cvss_score REAL');
  safeAddColumn('settings', 'code_signing_url TEXT NOT NULL DEFAULT "http://10.10.10.20:5000"');
  safeAddColumn('settings', 'session_recording_enabled INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'session_recording_retention_days INTEGER NOT NULL DEFAULT 90');
  safeAddColumn('settings', 'session_recording_quality TEXT NOT NULL DEFAULT "high"');
  safeAddColumn('settings', 'session_recording_visual_indicator INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'mesh_sync_enabled INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'mesh_client_delete_action TEXT NOT NULL DEFAULT "move_to_unassigned"');
  safeAddColumn('settings', 'mesh_external_delete_prompt INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('tenants', 'mesh_group_id TEXT');
  safeAddColumn('scripts', 'enabled INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('scripts', 'required_role TEXT NOT NULL DEFAULT "technician"');
  safeAddColumn('scripts', 'is_builtin INTEGER NOT NULL DEFAULT 0');
  safeAddColumn('scripts', 'tenant_id TEXT DEFAULT NULL');
  safeAddColumn('policies', 'max_snooze_hours INTEGER NOT NULL DEFAULT 8');
  safeAddColumn('policies', 'force_reboot_after_snooze INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('policies', 'final_countdown_sec INTEGER NOT NULL DEFAULT 300');
  safeAddColumn('policies', 'laps_enabled INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('policies', 'laps_account_name TEXT NOT NULL DEFAULT "LocalAdmin"');
  safeAddColumn('policies', 'laps_password_length INTEGER NOT NULL DEFAULT 20');
  safeAddColumn('policies', 'laps_complexity TEXT NOT NULL DEFAULT "alphanumeric_symbols"');
  safeAddColumn('policies', 'laps_rotation_days INTEGER NOT NULL DEFAULT 30');
  safeAddColumn('policies', 'laps_rotate_on_access INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('policies', 'laps_post_access_grace_hours INTEGER NOT NULL DEFAULT 2');
  safeAddColumn('policies', 'require_mfa_for_secrets INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('policies', 'telemetry_history_retention_days INTEGER NOT NULL DEFAULT 90');
  safeAddColumn('policies', 'hardware_audit_enabled INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('policies', 'network_drift_detection_enabled INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('policies', 'self_healing_max_hourly_runs INTEGER NOT NULL DEFAULT 3');
  safeAddColumn('policies', 'self_healing_alert_psa INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('policies', 'psa_flap_grace_minutes INTEGER NOT NULL DEFAULT 15');
  safeAddColumn('policies', 'auto_patch_cve_min_cvss REAL NOT NULL DEFAULT 8.0');

  safeAddColumn('settings', 'code_signing_enabled INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'code_signing_sign_scripts INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'code_signing_sign_agents INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'code_signing_sign_assemblies INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'installer_download_role TEXT NOT NULL DEFAULT "technician"');
  safeAddColumn('settings', 'installer_require_ticket INTEGER NOT NULL DEFAULT 0');
  safeAddColumn('settings', 'session_recording_stealth_for_techs INTEGER NOT NULL DEFAULT 0');
  safeAddColumn('settings', 'maintenance_auto_clear_hours INTEGER NOT NULL DEFAULT 24');
  safeAddColumn('settings', 'totp_secret TEXT NOT NULL DEFAULT "JBSWY3DPEHPK3PXP"');
  safeAddColumn('installer_audit_log', 'platform TEXT NOT NULL DEFAULT "windows"');

  // Ensure initial settings record exists
  const settingsCount = db.prepare('SELECT COUNT(*) as count FROM settings').get() as { count: number };
  if (settingsCount.count === 0) {
    db.prepare(`
      INSERT INTO settings (id, is_onboarded, brand_name, brand_logo_url, primary_color, glass_blur_level)
      VALUES (1, 1, 'Vitrine RMM', '/branding/logo.png', '#00f2fe', 'high')
    `).run();
  }

  // Seed default tenants and devices if empty
  const tenantCount = db.prepare('SELECT COUNT(*) as count FROM tenants').get() as { count: number };
  if (tenantCount.count === 0) {
    seedInitialData();
  }

  // Seed custom fields if not present
  seedExtendedData();
}

function seedInitialData() {
  const insertTenant = db.prepare(`
    INSERT INTO tenants (id, name, slug, contact_email, device_count)
    VALUES (?, ?, ?, ?, ?)
  `);

  insertTenant.run('t-apex', 'Apex Financial Group', 'apex-financial', 'ops@apexfin.com', 4);
  insertTenant.run('t-nexus', 'Nexus Health Systems', 'nexus-health', 'it-sec@nexushealth.org', 3);
  insertTenant.run('t-vanguard', 'Vanguard Legal Partners', 'vanguard-legal', 'admin@vanguardlaw.com', 2);

  const insertSite = db.prepare(`
    INSERT INTO sites (id, tenant_id, name, subnet)
    VALUES (?, ?, ?, ?)
  `);

  insertSite.run('s-apex-hq', 't-apex', 'HQ - Manhattan Office', '10.200.10.0/24');
  insertSite.run('s-apex-dr', 't-apex', 'DR Datacenter - Secaucus', '10.200.50.0/24');
  insertSite.run('s-nexus-main', 't-nexus', 'Memorial Hospital Clinic', '192.168.40.0/24');
  insertSite.run('s-vanguard-main', 't-vanguard', 'Central Chambers', '172.16.5.0/24');

  const insertUser = db.prepare(`
    INSERT INTO users (id, username, email, role, tenant_id)
    VALUES (?, ?, ?, ?, ?)
  `);

  insertUser.run('u-1', 'admin', 'admin@vitrine-rmm.internal', 'msp_super_admin', null);
  insertUser.run('u-2', 'tylerhats', 'tyler@vitrine-rmm.internal', 'msp_super_admin', null);
  insertUser.run('u-3', 'j.reynolds', 'jreynolds@apexfin.com', 'client_admin', 't-apex');
  insertUser.run('u-4', 'tech.sarah', 'sarah@vitrine-rmm.internal', 'senior_tech', null);

  const insertDevice = db.prepare(`
    INSERT INTO devices (
      id, mesh_node_id, tenant_id, site_id, hostname, os_type, os_version, os_build,
      ip_address, mac_address, status, device_role, cpu_model, cpu_cores, cpu_usage,
      ram_total_gb, ram_used_gb, disk_total_gb, disk_free_gb, smart_status,
      bitlocker_status, bitlocker_key, tpm_version, bios_version, serial_number,
      edr_name, edr_status, pending_reboot, quarantined, intel_amt_enabled
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insertDevice.run(
    'dev-win11-corp', 'node-9281a', 't-apex', 's-apex-hq', 'WIN11-PRO-EXEC',
    'windows', 'Windows 11 Enterprise', '23H2 (Build 22631.3880)',
    '10.200.10.45', '52:54:00:4C:4F:F0', 'online', 'Workstation',
    'Intel Core i9-14900K @ 3.20GHz', 16, 14.2,
    32.0, 11.4, 1024.0, 680.5, 'Healthy',
    'Encrypted (XTS-AES 256)', '481920-592019-209184-102948-592810-482019', '2.0',
    'Dell Inc. 1.22.0 (UEFI)', 'VMW-9842-DLX-991', 'Microsoft Defender Antivirus', 'Active & Up to Date',
    0, 0, 1
  );

  insertDevice.run(
    'dev-srv-dc01', 'node-8192b', 't-apex', 's-apex-hq', 'APEX-DC01-PROD',
    'windows', 'Windows Server 2022 Datacenter', '21H2 (Build 20348.2461)',
    '10.200.10.10', '00:15:5D:8A:2B:11', 'online', 'Domain Controller',
    'AMD EPYC 7763 64-Core Processor', 32, 28.5,
    64.0, 38.6, 2048.0, 1410.2, 'Healthy',
    'Encrypted (XTS-AES 256)', '928103-102948-382910-481920-592019-209184', '2.0',
    'HPE ProLiant DL380 Gen10 U30', 'HPE-USM982019A', 'CrowdStrike Falcon Sensor', 'Active & Up to Date',
    1, 0, 1
  );

  insertDevice.run(
    'dev-srv-db01', 'node-7102c', 't-apex', 's-apex-dr', 'APEX-SQL-CLUSTER',
    'windows', 'Windows Server 2022 Standard', '21H2 (Build 20348.2461)',
    '10.200.50.22', '00:15:5D:44:9C:33', 'online', 'Database Server',
    'Intel Xeon Platinum 8380 @ 2.30GHz', 40, 54.0,
    128.0, 96.4, 4096.0, 2180.0, 'Healthy',
    'Encrypted (XTS-AES 256)', '102948-481920-592019-382910-209184-928103', '2.0',
    'Dell PowerEdge R750 BIOS 1.9.2', 'DEL-SRV-89421-B', 'SentinelOne Singularity Complete', 'Active & Up to Date',
    0, 0, 1
  );

  insertDevice.run(
    'dev-lin-proxmox', 'node-6612d', 't-nexus', 's-nexus-main', 'PVE-CLUSTER-NODE01',
    'linux', 'Debian GNU/Linux 12 (bookworm)', 'Linux 6.8.4-pve',
    '192.168.40.5', 'A0:36:9F:11:44:EE', 'online', 'Hypervisor',
    'AMD EPYC 7543 32-Core Processor', 32, 38.1,
    256.0, 184.2, 8192.0, 4820.0, 'Healthy',
    'LUKS-2 Encrypted (AES-XTS 512)', 'ESCROW-LUKS2-8921-9941', '2.0',
    'Supermicro X12SPL-F 1.4b', 'SM-SYS-7049P-TRT', 'ClamAV + OSSEC HIDS', 'Active & Up to Date',
    0, 0, 0
  );

  insertDevice.run(
    'dev-win11-reception', 'node-5521e', 't-nexus', 's-nexus-main', 'CLINIC-DESK-04',
    'windows', 'Windows 11 Pro', '23H2 (Build 22631.3880)',
    '192.168.40.118', '70:85:C2:59:E1:92', 'online', 'Workstation',
    'Intel Core i5-13500 @ 2.50GHz', 14, 8.4,
    16.0, 6.2, 512.0, 340.0, 'Healthy',
    'Encrypted (XTS-AES 256)', '339102-481920-592019-102948-209184-592810', '2.0',
    'Lenovo ThinkCentre M70q M3E', 'MJ09X8A1', 'Microsoft Defender Antivirus', 'Active & Up to Date',
    0, 0, 1
  );

  insertDevice.run(
    'dev-macos-creative', 'node-4411f', 't-vanguard', 's-vanguard-main', 'MACBOOK-PRO-PARTNER',
    'macos', 'macOS 14.5 Sonoma', 'Darwin 23.5.0 (arm64)',
    '172.16.5.42', 'F4:D4:88:99:AA:01', 'online', 'Workstation',
    'Apple M3 Max (16-core)', 16, 12.0,
    64.0, 24.8, 2048.0, 1420.0, 'Healthy',
    'FileVault 2 Encrypted', 'FVAULT-2918-9942-1049-5820', '2.0',
    'Apple Silicon ROM 10151.121', 'C02G90ABMD6M', 'Jamf Protect + Defender', 'Active & Up to Date',
    0, 0, 0
  );

  insertDevice.run(
    'dev-win-isolated', 'node-3321g', 't-vanguard', 's-vanguard-main', 'LEGAL-PARALEGAL-09',
    'windows', 'Windows 10 Enterprise', '22H2 (Build 19045.4529)',
    '172.16.5.88', '3C:52:82:11:2B:99', 'isolated', 'Workstation',
    'Intel Core i7-11700 @ 2.50GHz', 8, 89.2,
    16.0, 14.8, 500.0, 22.0, 'Warning',
    'Encrypted (XTS-AES 256)', '291048-592019-481920-209184-102948-592810', '2.0',
    'Dell OptiPlex 7090 1.18.0', 'DEL-OPT-77189-G', 'Microsoft Defender Antivirus', 'Threat Quarantined (Mimikatz.exe)',
    0, 1, 0
  );

  // Seed Policies
  const insertPolicy = db.prepare(`
    INSERT INTO policies (
      id, name, tier, target_id, telemetry_interval_sec, require_remote_consent,
      consent_timeout_sec, consent_timeout_action, auto_lock_on_disconnect,
      patch_schedule, patch_reboot_enforcement, self_healing_enabled
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insertPolicy.run(
    'pol-global', 'Global MSP Default Baseline', 'global', null,
    30, 1, 30, 'cancel', 1,
    'Tuesdays @ 02:00 AM', 'Prompt 4h, then force reboot', 1
  );

  insertPolicy.run(
    'pol-servers', 'Mission Critical Servers Policy', 'role', 'Server',
    10, 0, 0, 'autoconnect', 0,
    'Sundays @ 03:00 AM', 'Maintenance window only (manual reboot)', 1
  );

  // Seed Scripts
  const insertScript = db.prepare(`
    INSERT INTO scripts (id, name, description, language, code, category)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  insertScript.run(
    'scr-1', 'Restart Spooler & Clear Stuck Print Jobs',
    'Stops Print Spooler service, purges PRINTERS spool folder, and restarts service.',
    'powershell',
    `Stop-Service -Name "Spooler" -Force
Remove-Item -Path "$env:SystemRoot\\System32\\spool\\PRINTERS\\*" -Force -Recurse
Start-Service -Name "Spooler"
Write-Output "Print spooler successfully cleared and restarted."`,
    'Remediation'
  );

  insertScript.run(
    'scr-2', 'Purge Windows Update SoftwareDistribution Cache',
    'Stops wuauserv, clears stuck CBS / SoftwareDistribution download cache to fix error 0x80240034.',
    'powershell',
    `Stop-Service -Name wuauserv, cryptSvc, bits, msiserver -Force
Remove-Item -Path "$env:SystemRoot\\SoftwareDistribution\\Download\\*" -Recurse -Force
Start-Service -Name wuauserv, cryptSvc, bits, msiserver
Write-Output "Windows Update cache successfully purged."`,
    'Remediation'
  );

  insertScript.run(
    'scr-3', 'Extract BitLocker Volume Recovery Protectors',
    'Ingests BitLocker recovery keys for all fixed data volumes into Vitrine custom fields.',
    'powershell',
    `$keys = Get-BitLockerVolume | ForEach-Object {
    $vol = $_.MountPoint
    $kp = ($_.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }).RecoveryPassword
    [PSCustomObject]@{ Volume = $vol; Key = $kp }
}
$keys | ConvertTo-Json`,
    'Diagnostic'
  );

  insertScript.run(
    'scr-4', 'Cyber Isolation: Emergency Network Quarantine',
    'Injects strict Windows Defender Firewall rules dropping all inbound/outbound packets except Vitrine & MeshCentral RMM tunnel.',
    'powershell',
    `# Drop all inbound & outbound except RMM port 443 / 8080
New-NetFirewallRule -DisplayName "VITRINE_QUARANTINE_IN" -Direction Inbound -Action Block -Profile Any -Priority 1
New-NetFirewallRule -DisplayName "VITRINE_QUARANTINE_OUT" -Direction Outbound -Action Block -Profile Any -Priority 1
New-NetFirewallRule -DisplayName "VITRINE_QUARANTINE_ALLOW_RMM" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 443, 8080 -Priority 0
Write-Output "Endpoint successfully isolated from network. RMM tunnel preserved."`,
    'Remediation'
  );

  insertScript.run(
    'scr-5', 'Trigger Full Microsoft Defender Antivirus Scan',
    'Runs silent Start-MpScan -ScanType FullScan and reports real-time threat detection results.',
    'powershell',
    `Update-MpSignature
Start-MpScan -ScanType FullScan
Write-Output "Full Microsoft Defender Antivirus scan initiated."`,
    'Remediation'
  );

  insertScript.run(
    'scr-6', 'Enable Wake-on-LAN (OS Drivers, Fast Startup & OEM BIOS WMI)',
    'Configures NIC advanced driver properties, disables Windows Fast Startup power-cut, and issues Dell/HP/Lenovo WMI BIOS commands to enable WoL in firmware.',
    'powershell',
    `# 1. Enable OS NIC Properties
Get-NetAdapter -Physical | ForEach-Object {
    Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "Wake on Magic Packet" -DisplayValue "Enabled" -ErrorAction SilentlyContinue
    Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "Wake on Pattern Match" -DisplayValue "Enabled" -ErrorAction SilentlyContinue
    Set-NetAdapterPowerManagement -Name $_.Name -WakeOnMagicPacket $true -ErrorAction SilentlyContinue
}
# 2. Disable Windows Fast Startup to preserve NIC standby voltage
Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power" -Name "HiberbootEnabled" -Value 0 -Force
# 3. OEM Firmware WMI BIOS Check
$mfg = (Get-CimInstance Win32_ComputerSystem).Manufacturer
if ($mfg -match 'Dell') {
    Get-CimInstance -Namespace root\\dcim\\sysman -ClassName DCIM_BIOSService | Invoke-CimMethod -MethodName SetBIOSAttributes -Arguments @{ AttributeName = @("Wake-On-LAN"); AttributeValue = @("LanOnly") } -ErrorAction SilentlyContinue
} elseif ($mfg -match 'HP') {
    Get-CimInstance -Namespace root\\hp\\instrumentedBIOS -ClassName HP_BIOSSettingInterface | Invoke-CimMethod -MethodName SetBIOSSetting -Arguments @{ Name = "Wake on LAN"; Value = "Boot to Network" } -ErrorAction SilentlyContinue
} elseif ($mfg -match 'Lenovo') {
    (Get-WmiObject -Namespace root\\wmi -Class Lenovo_SetBiosSetting).SetBiosSetting("WakeOnLAN,Enable"); (Get-WmiObject -Namespace root\\wmi -Class Lenovo_SaveBiosSetting).SaveBiosSettings()
}
Write-Output "Wake-on-LAN OS and BIOS firmware settings successfully enabled."`,
    'Remediation'
  );

  insertScript.run(
    'scr-7', 'Intel vPro / AMT Hardware Detection & Zero-Touch Local Provisioning',
    'Detects Intel MEI hardware, queries AMT capabilities, and performs host-based local activation binding CIRA to the existing agent node without duplicate nodes.',
    'powershell',
    `# 1. Check for Intel MEI Driver
$mei = Get-PnpDevice | Where-Object { $_.FriendlyName -match 'Intel\\(R\\) Management Engine Interface' -or $_.HardwareID -match 'PCI\\\\VEN_8086&DEV_' }
if (-not $mei) {
    Write-Output "RESULT: NOT_SUPPORTED - No Intel MEI hardware detected."
    exit 0
}
# 2. Query AMT Status via MeshCmd
$meshCmd = "$env:ProgramFiles\\Mesh Agent\\meshcmd.exe"
if (Test-Path $meshCmd) {
    $info = & $meshCmd amtinfo
    Write-Output $info
    if ($info -match 'Not activated|Pre-provisioned|Unconfigured') {
        & $meshCmd amtconfig --host $env:VITRINE_SERVER_HOST --meshid $env:VITRINE_MESH_ID
        Write-Output "SUCCESS: Local Host-Based Provisioning complete. Linked to existing node UUID."
    }
}
Write-Output "Intel vPro / AMT state verified and registered with Vitrine."`,
    'Diagnostic'
  );

  // Seed Self-Healing Monitors
  const insertMonitor = db.prepare(`
    INSERT INTO self_healing_monitors (id, name, condition_type, condition_value, remediation_script_id, cooldown_min, alert_on_failure, enabled)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insertMonitor.run('mon-1', 'Print Spooler Hung Watchdog', 'service_stopped', 'Spooler', 'scr-1', 10, 1, 1);
  insertMonitor.run('mon-2', 'Low Disk Space Auto-Cleanup (<10%)', 'disk_space_low', '10', 'scr-2', 60, 1, 1);

  // Seed Patches
  const insertPatch = db.prepare(`
    INSERT INTO patches (id, device_id, title, kb_id, category, severity, status, release_date)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insertPatch.run('p-1', 'dev-win11-corp', 'Cumulative Update for Windows 11 Version 23H2', 'KB5039212', 'Security Update', 'Critical', 'Approved', '2026-09-10');
  insertPatch.run('p-2', 'dev-win11-corp', 'Security Intelligence Update for Microsoft Defender Antivirus', 'KB2267602', 'Security Update', 'Important', 'Installed', '2026-10-10');
  insertPatch.run('p-3', 'dev-win11-corp', 'Google Chrome Enterprise (Winget: Google.Chrome)', 'v129.0.6668.70', 'Third-Party (Winget)', 'Important', 'Approved', '2026-10-02');
  insertPatch.run('p-4', 'dev-srv-dc01', 'Cumulative Update for Windows Server 2022', 'KB5039227', 'Security Update', 'Critical', 'Pending', '2026-09-10');

  // Seed PSA Tickets
  const insertTicket = db.prepare(`
    INSERT INTO psa_tickets (id, ticket_number, title, client_name, device_id, status, priority)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  insertTicket.run('tkt-1', 'ITF-8821', 'Critical Disk Space Alert: LEGAL-PARALEGAL-09 under 5% free', 'Vanguard Legal Partners', 'dev-win-isolated', 'Open', 'Urgent');
  insertTicket.run('tkt-2', 'ITF-8820', 'Pending Reboot Window Exceeded: APEX-DC01-PROD pending restart > 14 days', 'Apex Financial Group', 'dev-srv-dc01', 'In Progress', 'High');
  insertTicket.run('tkt-3', 'ITF-8819', 'LAPS Password Rotated Successfully', 'Nexus Health Systems', 'dev-win11-reception', 'Resolved', 'Low');

  // Seed Audit Logs
  const insertAudit = db.prepare(`
    INSERT INTO audit_logs (id, username, device_id, action, details)
    VALUES (?, ?, ?, ?, ?)
  `);

  insertAudit.run('aud-1', 'admin', 'dev-win-isolated', 'Cyber Isolation Engaged', 'Quarantined endpoint following Defender threat detection Mimikatz.exe');
  insertAudit.run('aud-2', 'tylerhats', 'dev-win11-corp', 'Remote Shell Session', 'Executed diagnostic command Get-BitLockerVolume via PowerShell background shell');
  insertAudit.run('aud-3', 'admin', 'dev-srv-dc01', 'Policy Updated', 'Configured Sunday maintenance window and disabled auto-reboot');
}

function seedExtendedData() {
  const cfCount = (db.prepare('SELECT COUNT(*) as count FROM custom_field_definitions').get() as { count: number }).count;
  if (cfCount === 0) {
    const insertDef = db.prepare(`
      INSERT INTO custom_field_definitions (id, key, label, category, field_type, scope, options, description)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertDef.run('cf-1', 'asset_tag', 'Asset Tag ID', 'System', 'text', 'device', null, 'Physical inventory barcode or tag');
    insertDef.run('cf-2', 'department', 'Assigned Department', 'System', 'dropdown', 'device', JSON.stringify(['Executive', 'Finance', 'Engineering', 'Legal', 'Clinical', 'Operations']), 'Primary departmental cost center');
    insertDef.run('cf-3', 'primary_user', 'Primary Point of Contact', 'System', 'text', 'device', null, 'Designated employee user account');
    insertDef.run('cf-4', 'bdr_tier', 'BDR Backup Strategy', 'Security', 'dropdown', 'device', JSON.stringify(['Tier 1 - Hourly VSS + Cloud Immutable', 'Tier 2 - Daily Image', 'Tier 3 - File-Level Restic', 'Unmanaged / Excluded']), 'Backup & Disaster Recovery policy assignment');
    insertDef.run('cf-5', 'gl_billing_code', 'GL Billing Cost Code', 'Billing', 'text', 'tenant', null, 'ERP sync accounting reference');
    insertDef.run('cf-6', 'vip_escalation', 'VIP Support SLA Escalation', 'Custom', 'checkbox', 'device', null, 'Enables immediate P1 response paging for executive endpoints');

    const insertVal = db.prepare(`
      INSERT INTO custom_field_values (id, field_id, entity_id, value)
      VALUES (?, ?, ?, ?)
    `);

    insertVal.run('val-1', 'cf-1', 'dev-win11-corp', 'APX-NY-0042');
    insertVal.run('val-2', 'cf-2', 'dev-win11-corp', 'Executive');
    insertVal.run('val-3', 'cf-3', 'dev-win11-corp', 'Tyler Hats (CEO)');
    insertVal.run('val-4', 'cf-4', 'dev-win11-corp', 'Tier 1 - Hourly VSS + Cloud Immutable');
    insertVal.run('val-5', 'cf-6', 'dev-win11-corp', 'true');

    insertVal.run('val-6', 'cf-1', 'dev-srv-dc01', 'APX-DC-0001');
    insertVal.run('val-7', 'cf-2', 'dev-srv-dc01', 'Engineering');
    insertVal.run('val-8', 'cf-4', 'dev-srv-dc01', 'Tier 1 - Hourly VSS + Cloud Immutable');
  }

  // Seed OEM Warranties if empty
  const warCount = (db.prepare('SELECT COUNT(*) as count FROM oem_warranties').get() as { count: number }).count;
  if (warCount === 0) {
    const insertWar = db.prepare(`
      INSERT INTO oem_warranties (device_id, serial_number, manufacturer, purchase_date, warranty_expiration, service_level, status)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    insertWar.run('dev-win11-corp', 'VMW-9842-DLX-991', 'Dell Inc.', '2024-01-15', '2027-01-15', 'Dell ProSupport Plus 24x7 Mission Critical', 'Active');
    insertWar.run('dev-srv-dc01', 'HPE-USM982019A', 'Hewlett Packard Enterprise', '2023-04-10', '2028-04-10', 'HPE Pointnext Tech Care Critical', 'Active');
    insertWar.run('dev-srv-db01', 'DEL-SRV-89421-B', 'Dell Inc.', '2023-08-20', '2026-11-20', 'Dell ProSupport 4-Hour Onsite Response', 'Expiring Soon');
    insertWar.run('dev-lin-proxmox', 'SM-SYS-7049P-TRT', 'Supermicro', '2024-03-01', '2027-03-01', 'Supermicro 3-Year Cross-Ship RMA', 'Active');
    insertWar.run('dev-win11-reception', 'MJ09X8A1', 'Lenovo', '2023-11-12', '2026-11-12', 'Lenovo Premier Support Warranty', 'Expiring Soon');
    insertWar.run('dev-macos-creative', 'C02G90ABMD6M', 'Apple Inc.', '2024-05-18', '2027-05-18', 'AppleCare+ for Enterprise Direct Desk', 'Active');
  }

  // Seed Maintenance Windows if empty
  const mwCount = (db.prepare('SELECT COUNT(*) as count FROM maintenance_windows').get() as { count: number }).count;
  if (mwCount === 0) {
    const insertMw = db.prepare(`
      INSERT INTO maintenance_windows (id, device_id, tenant_id, title, start_time, end_time, is_active, suppress_alerts)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertMw.run(
      'mw-1',
      'dev-srv-dc01',
      't-apex',
      'Active Directory Schema Upgrade & Reboot Window',
      new Date().toISOString(),
      new Date(Date.now() + 4 * 3600 * 1000).toISOString(),
      1,
      1
    );
  }

  // Update patches with CVE data
  try {
    db.prepare("UPDATE patches SET cve_id = 'CVE-2024-38077', cvss_score = 9.8 WHERE kb_id = 'KB5039212'").run();
    db.prepare("UPDATE patches SET cve_id = 'CVE-2024-30088', cvss_score = 8.8 WHERE kb_id = 'KB5039227'").run();
    db.prepare("UPDATE patches SET cve_id = 'CVE-2024-7971', cvss_score = 8.8 WHERE kb_id LIKE '%Google%'").run();
    db.prepare("UPDATE patches SET cve_id = 'CVE-2024-21412', cvss_score = 8.1 WHERE kb_id = 'KB2267602'").run();
  } catch {
    // Patches update ignore
  }

  // Seed Chat Messages if empty
  const chatCount = (db.prepare('SELECT COUNT(*) as count FROM chat_messages').get() as { count: number }).count;
  if (chatCount === 0) {
    const insertChat = db.prepare(`
      INSERT INTO chat_messages (id, device_id, sender, sender_role, message)
      VALUES (?, ?, ?, ?, ?)
    `);

    insertChat.run('chat-1', 'dev-win11-corp', 'Tyler Hats', 'end_user', 'Hello! Print spooler seems stuck after the monthly Windows update.');
    insertChat.run('chat-2', 'dev-win11-corp', 'IT Support (Admin)', 'technician', 'Hi Tyler! Vitrine self-healing watchdog has already purged the queue and restarted Spooler. Can you test printing now?');
    insertChat.run('chat-3', 'dev-win11-corp', 'Tyler Hats', 'end_user', 'Confirmed! Test page printed immediately. Thank you for the quick turnaround!');
  }

  // Seed Session Recordings if empty
  const recCount = (db.prepare('SELECT COUNT(*) as count FROM session_recordings').get() as { count: number }).count;
  if (recCount === 0) {
    const insertRec = db.prepare(`
      INSERT INTO session_recordings (id, device_id, technician, duration_sec, file_path, file_size_mb, sha256_hash, is_ghost_session)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertRec.run(
      'rec-101',
      'dev-win11-corp',
      'admin',
      340,
      '/app/data/recordings/rec-101.webm',
      18.4,
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      0
    );
    insertRec.run(
      'rec-102',
      'dev-srv-db01',
      'tylerhats',
      580,
      '/app/data/recordings/rec-102.webm',
      32.1,
      '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069',
      1
    );
  }

  // Seed Built-in Common Admin Scripts
  const builtinScripts = [
    {
      id: 'scr-rename-pc',
      name: 'Rename Computer & Hostname',
      description: 'Safely renames local Windows endpoint and stages reboot for Active Directory / Workgroup synchronization.',
      language: 'powershell',
      code: `param([Parameter(Mandatory=$true)][string]$NewComputerName)
Write-Output "Renaming computer to $NewComputerName..."
Rename-Computer -NewName $NewComputerName -Force -PassThru
Write-Output "Computer renamed successfully. Restart required to apply changes."`,
      category: 'Provisioning',
      required_role: 'admin'
    },
    {
      id: 'scr-net-reset',
      name: 'Flush DNS & Reset Winsock Network Stack',
      description: 'Flushes DNS resolver cache, resets Winsock catalog, and resets TCP/IP stack to resolve connectivity anomalies.',
      language: 'powershell',
      code: `Clear-DnsClientCache
netsh winsock reset
netsh int ip reset
ipconfig /renew
Write-Output "DNS flushed and network stack reset complete."`,
      category: 'Remediation',
      required_role: 'technician'
    },
    {
      id: 'scr-disk-cleanup',
      name: 'Deep Temp & DISM Component Store Cleanup',
      description: 'Purges user/system temp directories, empties recycle bin, and cleans obsolete Windows updates component store.',
      language: 'powershell',
      code: `Remove-Item -Path "$env:TEMP\\*" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "C:\\Windows\\Temp\\*" -Force -Recurse -ErrorAction SilentlyContinue
Clear-RecycleBin -Force -ErrorAction SilentlyContinue
Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase
Write-Output "Deep disk and component cleanup completed."`,
      category: 'Maintenance',
      required_role: 'technician'
    },
    {
      id: 'scr-create-localadmin',
      name: 'Create Break-Glass Local Administrator Account',
      description: 'Creates a designated local emergency administrator account with random high-entropy credentials.',
      language: 'powershell',
      code: `param([string]$AdminUser = "VitrineEmergencyAdmin", [string]$Password = "")
if (-not $Password) {
    $Password = [System.Web.Security.Membership]::GeneratePassword(18, 4)
}
net user $AdminUser $Password /add /expires:never
net localgroup administrators $AdminUser /add
Write-Output "Created break-glass admin user '$AdminUser'. Key archived to audit log."`,
      category: 'Provisioning',
      required_role: 'admin'
    },
    {
      id: 'scr-ntp-sync',
      name: 'Resynchronize Windows Time (NTP)',
      description: 'Configures reliable time pool and forces immediate clock synchronization via w32tm.',
      language: 'powershell',
      code: `w32tm /config /manualpeerlist:"pool.ntp.org,0x1" /syncfromflags:manual /reliable:yes /update
Stop-Service w32time -Force
Start-Service w32time
w32tm /resync /force
Write-Output "Time synchronization forced against pool.ntp.org."`,
      category: 'Maintenance',
      required_role: 'technician'
    },
    {
      id: 'scr-enable-bitlocker',
      name: 'Verify TPM & Enforce BitLocker Encryption',
      description: 'Checks TPM 2.0 readiness and initiates full XTS-AES 256 BitLocker encryption on System Drive C:.',
      language: 'powershell',
      code: `$tpm = Get-Tpm
if (-not $tpm.TpmPresent -or -not $tpm.TpmReady) {
    throw "TPM is not ready or present on this endpoint."
}
$status = Get-BitLockerVolume -MountPoint "C:"
if ($status.VolumeStatus -ne "FullyEncrypted") {
    Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector
    Write-Output "BitLocker encryption initiated with TPM protector."
} else {
    Write-Output "Volume C: is already fully encrypted."
}`,
      category: 'Remediation',
      required_role: 'admin'
    },
    {
      id: 'scr-winget-standard',
      name: 'Deploy Standard MSP Application Baseline',
      description: 'Installs Google Chrome, 7-Zip, and Notepad++ silently via Microsoft Winget package manager.',
      language: 'powershell',
      code: `winget install --id Google.Chrome -e --silent --accept-package-agreements --accept-source-agreements
winget install --id 7zip.7zip -e --silent --accept-package-agreements --accept-source-agreements
winget install --id Notepad++.Notepad++ -e --silent --accept-package-agreements --accept-source-agreements
Write-Output "Standard application baseline deployment complete."`,
      category: 'Provisioning',
      required_role: 'technician'
    },
    {
      id: 'scr-sysinfo-collect',
      name: 'Collect Diagnostic Logs & System Bundle',
      description: 'Generates snapshot of hardware specs, recent event logs, network configuration, and running processes.',
      language: 'powershell',
      code: `$info = [PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    OS = (Get-CimInstance Win32_OperatingSystem).Caption
    UptimeHours = [math]::Round(((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalHours, 1)
    IPv4 = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Ethernet*","Wi-Fi*" | Select-Object -First 1).IPAddress
}
$info | ConvertTo-Json`,
      category: 'Diagnostic',
      required_role: 'readonly'
    }
  ];

  const insertBuiltinScript = db.prepare(`
    INSERT OR IGNORE INTO scripts (id, name, description, language, code, category, enabled, required_role, is_builtin)
    VALUES (?, ?, ?, ?, ?, ?, 1, ?, 1)
  `);

  for (const s of builtinScripts) {
    insertBuiltinScript.run(s.id, s.name, s.description, s.language, s.code, s.category, s.required_role);
  }

  // Seed Notifications if empty
  const notifCount = (db.prepare('SELECT COUNT(*) as count FROM notifications').get() as { count: number }).count;
  if (notifCount === 0) {
    const insertNotif = db.prepare(`
      INSERT INTO notifications (id, type, title, message, severity, actions_json, is_read)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    insertNotif.run(
      'notif-1',
      'mesh_sync',
      'MeshCentral Device Groups Synchronized',
      'Bi-directional sync active. 3 Device Groups mapped to Vitrine Clients (Apex Financial, Nexus Health, Vanguard Legal).',
      'info',
      null,
      0
    );

    insertNotif.run(
      'notif-2',
      'pending_reboot',
      'Update Restart Window Active (WIN11-PRO-EXEC)',
      'Cumulative Update KB5039212 requires reboot. Max snooze timer: 8h. Transparent HUD countdown armed.',
      'warning',
      null,
      0
    );

    insertNotif.run(
      'notif-3',
      'mesh_conflict_prompt',
      'MeshCentral Group Deletion Notice: "Demo Lab"',
      'Device group was removed in MeshCentral. 2 endpoints need action.',
      'warning',
      JSON.stringify([
        { label: 'Keep in Unassigned', action: 'move_to_unassigned' },
        { label: 'De-provision Agents', action: 'uninstall' }
      ]),
      0
    );
  }

  // Seed Hardware History if empty
  const hwCount = (db.prepare('SELECT COUNT(*) as count FROM hardware_history').get() as { count: number }).count;
  if (hwCount === 0) {
    const insertHw = db.prepare(`
      INSERT INTO hardware_history (id, device_id, change_type, description, vendor_id, device_id_pci, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    insertHw.run(
      'hw-1',
      'dev-win11-corp',
      'RAM',
      'Physical memory expansion: Upgraded from 16 GB to 32 GB (2x16GB DDR5-5600)',
      '0x802C (Crucial / Micron)',
      'DIMM_A1 / DIMM_B1',
      new Date(Date.now() - 14 * 86400000).toISOString()
    );

    insertHw.run(
      'hw-2',
      'dev-win11-corp',
      'DISK',
      'High-speed NVMe storage installed: Samsung 980 Pro 2TB (PCIe 4.0 x4, SMART OK)',
      '0x144D (Samsung Electronics)',
      'M.2 NVMe Slot 2',
      new Date(Date.now() - 30 * 86400000).toISOString()
    );

    insertHw.run(
      'hw-3',
      'dev-win11-corp',
      'GPU',
      'Dedicated graphics adapter initialized: NVIDIA GeForce RTX 4070 Ti Super (16GB GDDR6X)',
      '0x10DE (NVIDIA Corporation)',
      'PCIe x16 Gen4',
      new Date(Date.now() - 60 * 86400000).toISOString()
    );
  }

  // Seed Network Connection History if empty
  const netCount = (db.prepare('SELECT COUNT(*) as count FROM network_history').get() as { count: number }).count;
  if (netCount === 0) {
    const insertNet = db.prepare(`
      INSERT INTO network_history (id, device_id, ssid, bssid, gateway_ip, gateway_mac, subnet, interface_name, connected_at, disconnected_at, is_flagged_drift)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertNet.run(
      'net-1',
      'dev-win11-corp',
      'Apex-Corporate-Wi-Fi-6E',
      '70:3A:0E:12:44:A0',
      '192.168.1.1',
      '00:1A:2B:3C:4D:5E',
      '192.168.1.0/24',
      'Intel Wi-Fi 6E AX211 160MHz',
      new Date(Date.now() - 4 * 3600000).toISOString(),
      null,
      0
    );

    insertNet.run(
      'net-2',
      'dev-win11-corp',
      'Apex-Corporate-LAN-Gbe',
      null,
      '192.168.1.1',
      '00:1A:2B:3C:4D:5E',
      '192.168.1.0/24',
      'Intel Ethernet Controller I225-V (2.5GbE)',
      new Date(Date.now() - 24 * 3600000).toISOString(),
      new Date(Date.now() - 4 * 3600000).toISOString(),
      0
    );

    insertNet.run(
      'net-3',
      'dev-win11-corp',
      'Mobile_Hotspot_Unrestricted',
      'F4:8C:50:88:91:0A',
      '172.20.10.1',
      'F2:88:21:4B:91:0A',
      '172.20.10.0/28',
      'Intel Wi-Fi 6E AX211 160MHz',
      new Date(Date.now() - 72 * 3600000).toISOString(),
      new Date(Date.now() - 70 * 3600000).toISOString(),
      1
    );
  }

  // Seed Smart Groups
  const groupCount = (db.prepare('SELECT COUNT(*) as count FROM smart_groups').get() as { count: number }).count;
  if (groupCount === 0) {
    const insertGroup = db.prepare(`
      INSERT INTO smart_groups (id, name, description, tenant_id, criteria_json)
      VALUES (?, ?, ?, ?, ?)
    `);
    insertGroup.run(
      'grp-win-low-disk',
      'Windows Endpoints (< 20GB Free)',
      'High-risk production workstations and laptops with critically low storage volume',
      null,
      JSON.stringify({ os_type: 'windows', max_disk_free_gb: 20 })
    );
    insertGroup.run(
      'grp-linux-servers',
      'Linux Core Servers',
      'Production database, backend API, and hypervisor Linux infrastructure',
      null,
      JSON.stringify({ os_type: 'linux', device_role: 'server' })
    );
    insertGroup.run(
      'grp-reboot-required',
      'Fleet Pending Reboots',
      'Endpoints with pending kernel/cumulative update reboot locks',
      null,
      JSON.stringify({ pending_reboot: 1 })
    );
  }

  // Seed Software Inventory with CVEs
  const softCount = (db.prepare('SELECT COUNT(*) as count FROM software_inventory').get() as { count: number }).count;
  if (softCount === 0) {
    const insertSoft = db.prepare(`
      INSERT INTO software_inventory (id, device_id, name, version, publisher, install_date, cve_count, highest_cvss, cve_list_json, auto_patchable)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insertSoft.run(
      'soft-1',
      'dev-win11-corp',
      'Google Chrome Enterprise',
      '128.0.6613.119',
      'Google LLC',
      '2026-09-15',
      1,
      8.8,
      JSON.stringify([{ id: 'CVE-2024-7971', cvss: 8.8, severity: 'High', summary: 'V8 Type Confusion zero-day vulnerability in Google Chrome' }]),
      1
    );
    insertSoft.run(
      'soft-2',
      'dev-win11-corp',
      'Zoom Workplace Client',
      '5.17.5',
      'Zoom Video Communications, Inc.',
      '2026-08-10',
      2,
      7.5,
      JSON.stringify([{ id: 'CVE-2024-24691', cvss: 7.5, severity: 'High', summary: 'Improper input validation allowing unauthorized privilege escalation' }]),
      1
    );
    insertSoft.run(
      'soft-3',
      'dev-win11-corp',
      '7-Zip (64-bit Edition)',
      '23.01',
      'Igor Pavlov',
      '2026-06-20',
      0,
      0.0,
      JSON.stringify([]),
      1
    );
    insertSoft.run(
      'soft-4',
      'dev-win11-corp',
      'Python 3.11.4 Runtime',
      '3.11.4150.0',
      'Python Software Foundation',
      '2026-05-12',
      1,
      7.5,
      JSON.stringify([{ id: 'CVE-2023-40217', cvss: 7.5, severity: 'High', summary: 'SSL socket bypass during pre-TLS client handshake' }]),
      1
    );
  }

  // Seed Active Vendor / Guest Access Grant
  const guestCount = (db.prepare('SELECT COUNT(*) as count FROM guest_access_grants').get() as { count: number }).count;
  if (guestCount === 0) {
    const insertGuest = db.prepare(`
      INSERT INTO guest_access_grants (
        id, vendor_name, contact_email, temp_username, temp_password,
        device_ids_json, can_remote_screen, can_ghost_session, can_view_telemetry,
        can_view_hardware, can_view_custom_fields, can_run_scripts, expires_at, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insertGuest.run(
      'grant-101',
      'Siemens Medical Support',
      'support-desk@siemens-health.com',
      'v-siemens-849',
      'Tier4#SiemensSecure2026!',
      JSON.stringify(['dev-win11-corp']),
      1,
      0,
      1,
      1,
      0,
      0,
      new Date(Date.now() + 4 * 3600000).toISOString(),
      'active'
    );
  }

  // Seed Self-Healing Remediation Logs
  const remCount = (db.prepare('SELECT COUNT(*) as count FROM remediation_logs').get() as { count: number }).count;
  if (remCount === 0) {
    const insertRem = db.prepare(`
      INSERT INTO remediation_logs (id, monitor_id, monitor_name, device_id, hostname, script_id, status, output, executed_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insertRem.run(
      'rem-1',
      'mon-1',
      'Print Spooler Hung Watchdog',
      'dev-win11-corp',
      'WIN11-PRO-EXEC',
      'scr-1',
      'Success',
      'Stopped Spooler, cleared 3 stuck SPL/SHD print jobs in C:\\Windows\\System32\\spool\\PRINTERS, and restarted Spooler.',
      new Date(Date.now() - 45 * 60000).toISOString()
    );
    insertRem.run(
      'rem-2',
      'mon-2',
      'Low Disk Space Auto-Cleanup (<10%)',
      'dev-win-isolated',
      'LEGAL-PARALEGAL-09',
      'scr-2',
      'Success',
      'Purged 14.2 GB from SoftwareDistribution\\Download and Windows Temp directories. Free storage recovered to 8.4%.',
      new Date(Date.now() - 180 * 60000).toISOString()
    );
  }

  // Seed Virtualization Hosts & VMs
  const virtCount = (db.prepare('SELECT COUNT(*) as count FROM virtualization_hosts').get() as { count: number }).count;
  if (virtCount === 0) {
    const insertHost = db.prepare(`
      INSERT INTO virtualization_hosts (id, name, host_type, ip_address, status, cpu_usage_pct, ram_usage_gb, ram_total_gb, storage_free_tb, storage_total_tb)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insertHost.run('pve-node-01', 'Proxmox VE Cluster Node 1', 'Proxmox VE 8.2', '192.168.40.5', 'Online', 24.8, 92.4, 256.0, 4.8, 8.0);
    insertHost.run('hv-node-01', 'Apex Hyper-V Cluster Core 01', 'Microsoft Hyper-V Server 2022', '10.200.10.15', 'Online', 31.2, 64.0, 128.0, 2.9, 6.0);

    const insertVm = db.prepare(`
      INSERT INTO virtualization_vms (id, host_id, vmid, name, status, os, cpu, ram_gb, last_snapshot)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insertVm.run('vm-100', 'pve-node-01', 100, 'win11-prod-workstation', 'Running', 'Windows 11', 12, 16, '2026-11-04 03:00 AM');
    insertVm.run('vm-101', 'pve-node-01', 101, 'debian-dns-pihole', 'Running', 'Debian 12', 2, 4, '2026-11-05 01:00 AM');
    insertVm.run('vm-102', 'pve-node-01', 102, 'srv-db-backup-staging', 'Stopped', 'Ubuntu 24.04', 0, 16, '2026-11-01 04:00 AM');
    insertVm.run('vm-201', 'hv-node-01', 201, 'apex-dc02-replica', 'Running', 'Windows Server 2022', 8, 16, '2026-11-05 02:00 AM');
    insertVm.run('vm-202', 'hv-node-01', 202, 'apex-rds-session-host', 'Running', 'Windows Server 2022', 16, 32, '2026-11-04 23:00 PM');
  }

  // Seed Network Topology Ports & Subnets
  const topoPortCount = (db.prepare('SELECT COUNT(*) as count FROM topology_ports').get() as { count: number }).count;
  if (topoPortCount === 0) {
    const insertPort = db.prepare(`
      INSERT INTO topology_ports (id, switch_name, switch_ip, port, vlan, status, speed, lldp_neighbor)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insertPort.run('tp-1', 'SW-CORE-01 (Cisco Catalyst 9300-48P)', '10.200.10.1', 'Gig1/0/1', 10, 'Up', '1000 Mbps', 'APEX-DC01-PROD');
    insertPort.run('tp-2', 'SW-CORE-01 (Cisco Catalyst 9300-48P)', '10.200.10.1', 'Gig1/0/2', 10, 'Up', '1000 Mbps', 'WIN11-PRO-EXEC');
    insertPort.run('tp-3', 'SW-CORE-01 (Cisco Catalyst 9300-48P)', '10.200.10.1', 'Gig1/0/24', 1, 'Up', '10000 Mbps', 'FW-GATEWAY-HA01');
    insertPort.run('tp-4', 'SW-CORE-01 (Cisco Catalyst 9300-48P)', '10.200.10.1', 'Gig1/0/48', 50, 'Up', '10000 Mbps', 'SW-DIST-DR01');
  }

  const topoSubCount = (db.prepare('SELECT COUNT(*) as count FROM topology_subnets').get() as { count: number }).count;
  if (topoSubCount === 0) {
    const insertSub = db.prepare(`
      INSERT INTO topology_subnets (id, subnet, probe_host, total_discovered, unmanaged)
      VALUES (?, ?, ?, ?, ?)
    `);
    insertSub.run('ts-1', '10.200.10.0/24', 'APEX-DC01-PROD', 42, 3);
    insertSub.run('ts-2', '192.168.40.0/24', 'CLINIC-DESK-04', 18, 1);
    insertSub.run('ts-3', '172.16.5.0/24', 'MACBOOK-PRO-PARTNER', 14, 2);
  }

  // Seed Device Runbook Notes
  const noteCount = (db.prepare('SELECT COUNT(*) as count FROM device_notes').get() as { count: number }).count;
  if (noteCount === 0) {
    const insertNote = db.prepare(`
      INSERT INTO device_notes (id, device_id, author, content, is_pinned)
      VALUES (?, ?, ?, ?, ?)
    `);
    insertNote.run('note-1', 'dev-win11-corp', 'tylerhats', 'Executive primary workstation. Always verify active Zoom/Teams calls before triggering manual reboots outside maintenance windows.', 1);
    insertNote.run('note-2', 'dev-srv-dc01', 'admin', 'Primary FSMO role holder for corp.apexfin.com. Replicate AD schema changes to apex-dc02-replica prior to patching.', 1);
  }

  // Ensure an offline Intel vPro/AMT endpoint exists on 10.200.10.0/24 to showcase the 5-Tier Peer-Relay Wake & AMT Chain
  const offlinePeerDevice = db.prepare('SELECT id FROM devices WHERE id = ?').get('dev-win11-cfo');
  if (!offlinePeerDevice) {
    db.prepare(`
      INSERT INTO devices (
        id, mesh_node_id, tenant_id, site_id, hostname, os_type, os_version, os_build,
        ip_address, mac_address, status, device_role, cpu_model, cpu_cores, cpu_usage,
        ram_total_gb, ram_used_gb, disk_total_gb, disk_free_gb, smart_status,
        bitlocker_status, bitlocker_key, tpm_version, bios_version, serial_number,
        edr_name, edr_status, pending_reboot, quarantined, intel_amt_enabled, intel_amt_reachable
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'dev-win11-cfo', 'node-9012h', 't-apex', 's-apex-hq', 'APEX-CFO-THINKPAD',
      'windows', 'Windows 11 Enterprise', '23H2 (Build 22631.4169)',
      '10.200.10.85', '38:F3:AB:71:4C:20', 'offline', 'Workstation',
      'Intel Core Ultra 7 165U vPro', 12, 0.0,
      32.0, 0.0, 1024.0, 712.0, 'Healthy',
      'Encrypted (XTS-AES 256)', '718290-384910-582910-194820-491029-849201', '2.0',
      'Lenovo ThinkPad X1 Carbon Gen 12 (N3YET62W)', 'PF-4X992L', 'CrowdStrike Falcon Sensor', 'Standby (Host Powered Off)',
      0, 0, 1, 1
    );

    // Seed roaming network history for dev-win11-cfo so Tier 4 historical subnet relay is also populated
    db.prepare(`
      INSERT INTO network_history (
        id, device_id, ssid, bssid, gateway_ip, gateway_mac, subnet, interface_name,
        connected_at, disconnected_at, is_flagged_drift
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'net-cfo-1',
      'dev-win11-cfo',
      'Apex_Corp_5GHz_Enterprise',
      '00:1A:2B:99:88:77',
      '10.200.50.1',
      '00:1A:2B:99:88:01',
      '10.200.50.0/24',
      'Intel Wi-Fi 6E AX211 160MHz',
      new Date(Date.now() - 8 * 3600000).toISOString(),
      new Date(Date.now() - 2 * 3600000).toISOString(),
      0
    );
  }

  // Seed Network Appliances & SNMP Infrastructure Monitors
  const appCount = (db.prepare('SELECT COUNT(*) as count FROM network_appliances').get() as { count: number }).count;
  if (appCount === 0) {
    const insertApp = db.prepare(`
      INSERT INTO network_appliances (
        id, tenant_id, site_id, name, appliance_type, vendor_model, ip_address, mac_address,
        snmp_version, probe_device_id, probe_hostname, status, uptime_days, latency_ms,
        packet_loss_pct, cpu_pct, memory_pct, metrics_json, alert_summary
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertApp.run(
      'app-fw-01',
      't-apex',
      's-apex-hq',
      'FW-GATEWAY-HA01',
      'Firewall / UTM',
      'Fortinet FortiGate 200F (FortiOS 7.4.4)',
      '10.200.10.254',
      '90:6C:AC:81:22:01',
      'SNMP v3 (SHA/AES)',
      'dev-srv-dc01',
      'APEX-DC01-PROD',
      'Healthy',
      142.6,
      0.8,
      0.0,
      21.4,
      44.0,
      JSON.stringify({
        wan1State: 'Up (1.0 Gbps Fiber - 184 Mbps / 92 Mbps)',
        wan2State: 'Standby Ready (LTE/5G Failover)',
        ipsecTunnels: '4 / 4 Active (Site-to-Site DR)',
        ipsSignatures: 'v28.841 (Active Blocking)',
        activeSessions: '14,820'
      }),
      null
    );

    insertApp.run(
      'app-sw-01',
      't-apex',
      's-apex-hq',
      'SW-CORE-01',
      'Managed Switch',
      'Cisco Catalyst 9300-48P (IOS-XE 17.9.4)',
      '10.200.10.1',
      '00:1A:2B:3C:4D:01',
      'SNMP v3 (SHA/AES)',
      'dev-srv-dc01',
      'APEX-DC01-PROD',
      'Healthy',
      218.4,
      1.1,
      0.0,
      14.2,
      38.5,
      JSON.stringify({
        activePorts: '42 / 48 Ports Up',
        poeBudgetUsed: '385W / 715W (53.8%)',
        spanningTree: 'Rapid-PVST+ Root Bridge (VLAN 1, 10, 50)',
        uplinkTenGig: 'Te1/1/1 -> FW-GATEWAY-HA01 (10 Gbps Full)'
      }),
      null
    );

    insertApp.run(
      'app-ups-01',
      't-apex',
      's-apex-hq',
      'UPS-APC-RACK01',
      'Smart UPS Battery',
      'APC Smart-UPS SRT 3000VA RM (AP9641 NMC3)',
      '10.200.10.6',
      '00:C0:B7:91:44:12',
      'SNMP v3 (SHA/AES)',
      'dev-srv-dc01',
      'APEX-DC01-PROD',
      'Healthy',
      310.0,
      2.3,
      0.0,
      8.0,
      22.0,
      JSON.stringify({
        batteryChargePct: '100% (Online - Float Charging)',
        estimatedRuntime: '52 mins @ 34% Load (1,020W)',
        inputOutputVoltage: '120.4V AC In / 120.0V AC Out (60.0 Hz)',
        batteryTempC: '25.8 °C (Optimal)',
        lastSelfTest: 'Passed (2026-11-01)'
      }),
      null
    );

    insertApp.run(
      'app-nas-01',
      't-nexus',
      's-nexus-main',
      'NAS-SYNOLOGY-VAULT',
      'SAN / NAS Storage',
      'Synology RackStation RS3621xs+ (DSM 7.2.1)',
      '192.168.40.20',
      '00:11:32:AA:81:99',
      'SNMP v3 (SHA/AES)',
      'dev-lin-proxmox',
      'PVE-CLUSTER-NODE01',
      'Warning',
      89.5,
      1.5,
      0.0,
      39.2,
      68.4,
      JSON.stringify({
        raidPoolStatus: 'RAID-6 Healthy (12x 16TB Enterprise SAS)',
        volumeCapacity: '118.4 TB Used / 142.0 TB Total (83.4%)',
        iscsiLunThroughput: '640 MB/s Read • 410 MB/s Write (4,200 IOPS)',
        driveSmartAlert: 'Bay 7 (WD Ultrastar) reporting 2 reallocated sectors'
      }),
      'Storage volume > 80% threshold & Bay 7 SMART sector warning'
    );

    insertApp.run(
      'app-prn-01',
      't-vanguard',
      's-vanguard-main',
      'PRN-LEGAL-RECORDS-01',
      'Network Printer / MFP',
      'HP LaserJet Enterprise M611dn (FutureSmart 5)',
      '172.16.5.150',
      '48:BA:4E:33:10:88',
      'SNMP v2c / v3',
      'dev-macos-creative',
      'MACBOOK-PRO-PARTNER',
      'Healthy',
      19.2,
      3.4,
      0.0,
      6.0,
      19.0,
      JSON.stringify({
        tonerBlackPct: '64% (HP 147X High Yield)',
        maintenanceKitPct: '88% Remaining',
        totalPageCount: '148,920 Pages',
        trayStatus: 'Tray 1: Ready • Tray 2 (Legal): Ready (500 sheets)'
      }),
      null
    );
  }
}
