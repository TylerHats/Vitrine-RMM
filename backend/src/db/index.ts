import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import {
  encryptVaultSecret,
  isEncryptedVaultSecret,
  generateRandomBase32,
  hashPasswordScrypt
} from '../services/vault/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================================================================
// Persistent Data & Branding Directory Resolution
// ============================================================================
function resolveDataDir(): string {
  if (process.env.DATA_DIR && process.env.DATA_DIR.trim()) {
    const explicit = path.resolve(process.env.DATA_DIR.trim());
    if (!fs.existsSync(explicit)) {
      fs.mkdirSync(explicit, { recursive: true, mode: 0o700 });
    }
    return explicit;
  }

  const candidates = [
    path.resolve(process.cwd(), 'data'),
    path.resolve(process.cwd(), '../data'),
    path.resolve(__dirname, '../../../data'),
    path.resolve(__dirname, '../../data')
  ];

  const found = candidates.find((p) => fs.existsSync(p)) || candidates[0];
  if (!fs.existsSync(found)) {
    fs.mkdirSync(found, { recursive: true, mode: 0o700 });
  }
  return found;
}

function resolveBrandingDir(): string {
  let found: string;
  if (process.env.BRANDING_DIR && process.env.BRANDING_DIR.trim()) {
    found = path.resolve(process.env.BRANDING_DIR.trim());
  } else {
    const candidates = [
      path.resolve(__dirname, '../../../branding'),
      path.resolve(__dirname, '../../branding'),
      path.resolve(process.cwd(), 'branding'),
      path.resolve(process.cwd(), '../branding')
    ];
    found = candidates.find((p) => fs.existsSync(p)) || candidates[0];
  }

  if (!fs.existsSync(found)) {
    fs.mkdirSync(found, { recursive: true });
  }

  // If branding directory is an empty bind-mount (e.g. Docker first boot), seed default logo
  const targetLogo = path.join(found, 'logo.png');
  if (!fs.existsSync(targetLogo)) {
    const fallbackLogos = [
      path.resolve('/app/branding-defaults/logo.png'),
      path.resolve(__dirname, '../../../branding-defaults/logo.png'),
      path.resolve(__dirname, '../../frontend/dist/logo.png'),
      path.resolve(__dirname, '../../../frontend/public/logo.png'),
      path.resolve(process.cwd(), '../frontend/public/logo.png')
    ];
    const sourceLogo = fallbackLogos.find((p) => fs.existsSync(p));
    if (sourceLogo) {
      try {
        fs.copyFileSync(sourceLogo, targetLogo);
      } catch {
        // Non-fatal if read-only mount
      }
    }
  }

  return found;
}

const DATA_DIR = resolveDataDir();
const BRANDING_DIR = resolveBrandingDir();
const DB_PATH = path.join(DATA_DIR, 'vitrine.db');

export const DATA_DIR_PATH = DATA_DIR;
export const BRANDING_DIR_PATH = BRANDING_DIR;
export const DB_FILE_PATH = DB_PATH;
export const APP_VERSION = '2.5.0';
export const APP_SCHEMA_VERSION = 15;

function detectInstalledCommit(): string {
  if (process.env.VITRINE_GIT_COMMIT && process.env.VITRINE_GIT_COMMIT.trim()) {
    return process.env.VITRINE_GIT_COMMIT.trim().slice(0, 12);
  }
  const metaCandidates = [
    path.join(DATA_DIR, 'install-meta.json'),
    path.resolve(__dirname, '../../install-meta.json'),
    path.resolve(__dirname, '../../../install-meta.json')
  ];
  for (const metaPath of metaCandidates) {
    if (fs.existsSync(metaPath)) {
      try {
        const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
        if (meta?.commit && meta.commit !== 'release-build') {
          return String(meta.commit).slice(0, 12);
        }
      } catch {
        // Ignore malformed metadata
      }
    }
  }
  try {
    const gitRoot = path.resolve(__dirname, '../../..');
    if (fs.existsSync(path.join(gitRoot, '.git'))) {
      const sha = execSync('git rev-parse --short HEAD', {
        cwd: gitRoot,
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 2000
      })
        .toString('utf8')
        .trim();
      if (sha) return sha;
    }
  } catch {
    // Git binary or repo unavailable
  }
  return 'v2.5.0';
}

export const APP_INSTALLED_COMMIT = detectInstalledCommit();

export function isRunningInDocker(): boolean {
  if (process.env.CONTAINER === 'true' || process.env.VITRINE_DOCKER === '1') return true;
  try {
    if (fs.existsSync('/.dockerenv') || fs.existsSync('/run/.containerenv')) return true;
  } catch {
    // Ignore
  }
  return false;
}

// ============================================================================
// Reconnectable SQLite Singleton Proxy (Enables Live Atomic DB Restore)
// ============================================================================
function openConfiguredDatabase(filePath: string): Database.Database {
  const handle = new Database(filePath);
  handle.pragma('journal_mode = WAL');
  handle.pragma('foreign_keys = ON');
  handle.pragma('busy_timeout = 5000');
  return handle;
}

let activeDb: Database.Database = openConfiguredDatabase(DB_PATH);

export const db: Database.Database = new Proxy({} as Database.Database, {
  get(_target, prop, _receiver) {
    const val = (activeDb as any)[prop];
    return typeof val === 'function' ? val.bind(activeDb) : val;
  },
  set(_target, prop, value) {
    (activeDb as any)[prop] = value;
    return true;
  }
});

export function getRawDatabaseHandle(): Database.Database {
  return activeDb;
}

export function closeDatabase(): void {
  try {
    if (activeDb && activeDb.open) {
      try {
        activeDb.pragma('wal_checkpoint(TRUNCATE)');
      } catch {
        // Ignore checkpoint error on closing
      }
      activeDb.close();
    }
  } catch {
    // Ignore already closed
  }
}

export function reopenDatabase(): Database.Database {
  closeDatabase();
  activeDb = openConfiguredDatabase(DB_PATH);
  return activeDb;
}

// ============================================================================
// Schema Initialization & Forward Migrations
// ============================================================================
export function initDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      is_onboarded INTEGER NOT NULL DEFAULT 0,
      brand_name TEXT NOT NULL DEFAULT 'Vitrine RMM',
      brand_logo_url TEXT NOT NULL DEFAULT '/branding/logo.png',
      primary_color TEXT NOT NULL DEFAULT '#00f2fe',
      glass_blur_level TEXT NOT NULL DEFAULT 'high',
      custom_domain TEXT NOT NULL DEFAULT '',
      meshcentral_url TEXT NOT NULL DEFAULT 'https://127.0.0.1:443',
      meshcentral_api_token TEXT NOT NULL DEFAULT '',
      meshcentral_connected INTEGER NOT NULL DEFAULT 0,
      smtp_host TEXT NOT NULL DEFAULT '',
      smtp_port INTEGER NOT NULL DEFAULT 587,
      smtp_user TEXT NOT NULL DEFAULT '',
      smtp_pass TEXT NOT NULL DEFAULT '',
      smtp_from TEXT NOT NULL DEFAULT 'alerts@vitrine.local',
      smtp_tls INTEGER NOT NULL DEFAULT 1,
      itflow_url TEXT NOT NULL DEFAULT '',
      itflow_api_key TEXT NOT NULL DEFAULT '',
      oidc_enabled INTEGER NOT NULL DEFAULT 0,
      oidc_issuer_url TEXT NOT NULL DEFAULT '',
      oidc_client_id TEXT NOT NULL DEFAULT '',
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
      password_hash TEXT,
      totp_secret TEXT,
      totp_enabled INTEGER NOT NULL DEFAULT 0,
      last_totp_step INTEGER,
      recovery_codes_json TEXT,
      last_login_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS auth_sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      mfa_verified_until TEXT,
      ip_address TEXT,
      user_agent TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      mesh_node_id TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      site_id TEXT,
      hostname TEXT NOT NULL,
      os_type TEXT NOT NULL DEFAULT 'windows',
      os_version TEXT NOT NULL,
      os_build TEXT NOT NULL,
      ip_address TEXT NOT NULL,
      mac_address TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'online',
      device_role TEXT NOT NULL DEFAULT 'Workstation',
      manufacturer TEXT NOT NULL DEFAULT '',
      model TEXT NOT NULL DEFAULT '',
      cpu_model TEXT NOT NULL,
      cpu_cores INTEGER NOT NULL DEFAULT 8,
      cpu_usage REAL NOT NULL DEFAULT 0.0,
      ram_total_gb REAL NOT NULL DEFAULT 16.0,
      ram_used_gb REAL NOT NULL DEFAULT 0.0,
      disk_total_gb REAL NOT NULL DEFAULT 512.0,
      disk_free_gb REAL NOT NULL DEFAULT 400.0,
      smart_status TEXT NOT NULL DEFAULT 'Healthy',
      bitlocker_status TEXT NOT NULL DEFAULT 'Unknown',
      bitlocker_key TEXT NOT NULL DEFAULT '',
      tpm_version TEXT NOT NULL DEFAULT '2.0',
      bios_version TEXT NOT NULL DEFAULT '',
      serial_number TEXT NOT NULL DEFAULT '',
      edr_name TEXT NOT NULL DEFAULT '',
      edr_status TEXT NOT NULL DEFAULT 'Unknown',
      pending_reboot INTEGER NOT NULL DEFAULT 0,
      pending_reboot_since TEXT,
      quarantined INTEGER NOT NULL DEFAULT 0,
      intel_amt_enabled INTEGER NOT NULL DEFAULT 0,
      agent_auth_token TEXT,
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
      overrides_json TEXT,
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

    CREATE TABLE IF NOT EXISTS script_executions (
      id TEXT PRIMARY KEY,
      script_id TEXT NOT NULL,
      script_name TEXT NOT NULL,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      run_as TEXT NOT NULL DEFAULT 'system',
      params_json TEXT,
      status TEXT NOT NULL DEFAULT 'Completed',
      exit_code INTEGER NOT NULL DEFAULT 0,
      output TEXT NOT NULL,
      triggered_by TEXT NOT NULL,
      executed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
      acknowledged INTEGER NOT NULL DEFAULT 0,
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
      local_ip TEXT,
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
      password_hash TEXT,
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
      expires_at TEXT,
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
      ip_address TEXT NOT NULL DEFAULT '',
      api_port INTEGER NOT NULL DEFAULT 8006,
      api_username TEXT,
      api_token_encrypted TEXT,
      status TEXT NOT NULL DEFAULT 'Online',
      cpu_usage_pct REAL NOT NULL DEFAULT 0.0,
      ram_usage_gb REAL NOT NULL DEFAULT 0.0,
      ram_total_gb REAL NOT NULL DEFAULT 64.0,
      storage_free_tb REAL NOT NULL DEFAULT 1.0,
      storage_total_tb REAL NOT NULL DEFAULT 2.0
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
      switch_name TEXT NOT NULL,
      switch_ip TEXT NOT NULL,
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
      total_discovered INTEGER NOT NULL DEFAULT 0,
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
      tenant_id TEXT NOT NULL,
      site_id TEXT,
      name TEXT NOT NULL,
      appliance_type TEXT NOT NULL,
      vendor_model TEXT NOT NULL,
      ip_address TEXT NOT NULL,
      mac_address TEXT NOT NULL,
      snmp_version TEXT NOT NULL DEFAULT 'v3',
      probe_device_id TEXT NOT NULL,
      probe_hostname TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Healthy',
      uptime_days REAL NOT NULL DEFAULT 0.0,
      latency_ms REAL NOT NULL DEFAULT 0.0,
      packet_loss_pct REAL NOT NULL DEFAULT 0.0,
      cpu_pct REAL NOT NULL DEFAULT 0.0,
      memory_pct REAL NOT NULL DEFAULT 0.0,
      metrics_json TEXT NOT NULL DEFAULT '{}',
      alert_summary TEXT,
      last_polled TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS mesh_servers (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      url TEXT NOT NULL,
      api_token TEXT NOT NULL DEFAULT '',
      is_primary INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'Disconnected',
      local_config_path TEXT,
      agent_service_name TEXT NOT NULL DEFAULT 'VitrineAgent',
      agent_display_name TEXT NOT NULL DEFAULT 'Vitrine RMM Remote Engine',
      agent_custom_text TEXT NOT NULL DEFAULT 'Managed by Enterprise IT Support',
      keep_agents_signed INTEGER NOT NULL DEFAULT 1,
      auto_push_companion INTEGER NOT NULL DEFAULT 1,
      discovered_groups_count INTEGER NOT NULL DEFAULT 0,
      discovered_agents_count INTEGER NOT NULL DEFAULT 0,
      last_synced TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS system_backups (
      id TEXT PRIMARY KEY,
      filename TEXT NOT NULL,
      file_path TEXT NOT NULL,
      size_bytes INTEGER NOT NULL DEFAULT 0,
      trigger_type TEXT NOT NULL DEFAULT 'manual',
      app_version TEXT NOT NULL DEFAULT '2.5.0',
      git_commit TEXT NOT NULL DEFAULT 'v2.5.0',
      db_schema_version INTEGER NOT NULL DEFAULT 15,
      sha256_hash TEXT NOT NULL,
      includes_branding INTEGER NOT NULL DEFAULT 1,
      includes_mesh_config INTEGER NOT NULL DEFAULT 1,
      notes TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS system_updates (
      id TEXT PRIMARY KEY,
      channel TEXT NOT NULL DEFAULT 'stable',
      from_version TEXT NOT NULL,
      to_version TEXT NOT NULL,
      from_commit TEXT NOT NULL,
      to_commit TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'completed',
      backup_id TEXT,
      error_log TEXT,
      release_notes TEXT,
      executed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS quicksupport_sessions (
      id TEXT PRIMARY KEY,
      session_code TEXT NOT NULL UNIQUE,
      client_name TEXT NOT NULL,
      tenant_id TEXT,
      mesh_server_id TEXT DEFAULT 'ms2-primary',
      status TEXT NOT NULL DEFAULT 'waiting',
      privilege_level TEXT NOT NULL DEFAULT 'standard_user',
      platform TEXT NOT NULL DEFAULT 'windows',
      hostname TEXT,
      username TEXT,
      code_signed INTEGER NOT NULL DEFAULT 0,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS deleted_tenants_tombstones (
      tenant_id TEXT PRIMARY KEY,
      tenant_name TEXT NOT NULL,
      slug TEXT NOT NULL,
      mesh_group_id TEXT,
      laps_offboard_action TEXT NOT NULL DEFAULT 'remove_account',
      deleted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS deleted_tenant_device_tombstones (
      device_id TEXT PRIMARY KEY,
      mesh_node_id TEXT,
      hostname TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      tenant_name TEXT NOT NULL,
      laps_action TEXT NOT NULL DEFAULT 'remove_account',
      quiet_offboarded_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  runDatabaseMigrations();

  // Ensure initial settings record exists with per-instance random secrets
  const settingsCount = (db.prepare('SELECT COUNT(*) as count FROM settings').get() as { count: number }).count;
  if (settingsCount === 0) {
    const generatedTotp = encryptVaultSecret(generateRandomBase32(20));
    const generatedWebhookSecret = encryptVaultSecret(crypto.randomBytes(24).toString('hex'));
    const generatedAgentSecret = encryptVaultSecret(crypto.randomBytes(24).toString('hex'));
    const generatedBackupPass = encryptVaultSecret(crypto.randomBytes(24).toString('base64url'));

    db.prepare(`
      INSERT INTO settings (
        id, is_onboarded, oobe_completed, brand_name, brand_logo_url, primary_color, glass_blur_level,
        meshcentral_connected, code_signing_enabled, code_signing_url, totp_secret,
        psa_webhook_secret, agent_enrollment_secret, backup_encryption_passphrase,
        backup_offsite_enabled, backup_offsite_access_key, backup_offsite_secret_key,
        installed_version, installed_commit, db_schema_version
      )
      VALUES (
        1, 0, 0, 'Vitrine RMM', '/branding/logo.png', '#00f2fe', 'high',
        0, 0, '', ?,
        ?, ?, ?,
        0, '', '',
        ?, ?, ?
      )
    `).run(
      generatedTotp,
      generatedWebhookSecret,
      generatedAgentSecret,
      generatedBackupPass,
      APP_VERSION,
      APP_INSTALLED_COMMIT,
      APP_SCHEMA_VERSION
    );
  }

  // Always seed essential baseline policies, standard custom field definitions, and built-in RMM scripts
  seedProductionBaseline();

  // Only load demo MSP dataset if explicitly requested via SEED_DEMO_DATA=true
  if (process.env.SEED_DEMO_DATA === 'true') {
    const tenantCount = (db.prepare('SELECT COUNT(*) as count FROM tenants').get() as { count: number }).count;
    if (tenantCount === 0) {
      seedDemoDataset();
    }
  }
}

export function runDatabaseMigrations() {
  const safeAddColumn = (table: string, columnDef: string) => {
    try {
      db.exec(`ALTER TABLE ${table} ADD COLUMN ${columnDef}`);
    } catch {
      // Column already exists
    }
  };

  // Core table creation for upgraded older DBs
  db.exec(`
    CREATE TABLE IF NOT EXISTS auth_sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      mfa_verified_until TEXT,
      ip_address TEXT,
      user_agent TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS script_executions (
      id TEXT PRIMARY KEY,
      script_id TEXT NOT NULL,
      script_name TEXT NOT NULL,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      run_as TEXT NOT NULL DEFAULT 'system',
      params_json TEXT,
      status TEXT NOT NULL DEFAULT 'Completed',
      exit_code INTEGER NOT NULL DEFAULT 0,
      output TEXT NOT NULL,
      triggered_by TEXT NOT NULL,
      executed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS deleted_tenant_device_tombstones (
      device_id TEXT PRIMARY KEY,
      mesh_node_id TEXT,
      hostname TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      tenant_name TEXT NOT NULL,
      laps_action TEXT NOT NULL DEFAULT 'remove_account',
      quiet_offboarded_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // User authentication & MFA columns
  safeAddColumn('users', 'password_hash TEXT');
  safeAddColumn('users', 'totp_secret TEXT');
  safeAddColumn('users', 'totp_enabled INTEGER NOT NULL DEFAULT 0');
  safeAddColumn('users', 'last_totp_step INTEGER');
  safeAddColumn('users', 'recovery_codes_json TEXT');
  safeAddColumn('users', 'last_login_at TEXT');

  // Device extended columns
  safeAddColumn('devices', 'maintenance_until TEXT');
  safeAddColumn('devices', 'warranty_expiration TEXT');
  safeAddColumn('devices', 'enrolled_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP');
  safeAddColumn('devices', 'intel_amt_reachable INTEGER NOT NULL DEFAULT 0');
  safeAddColumn('devices', 'mesh_server_id TEXT NOT NULL DEFAULT "ms2-primary"');
  safeAddColumn('devices', 'agent_privilege_mode TEXT NOT NULL DEFAULT "system_service"');
  safeAddColumn('devices', 'companion_installed INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('devices', 'agent_code_signed INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('devices', 'manufacturer TEXT NOT NULL DEFAULT ""');
  safeAddColumn('devices', 'model TEXT NOT NULL DEFAULT ""');
  safeAddColumn('devices', 'pending_reboot_since TEXT');
  safeAddColumn('devices', 'agent_auth_token TEXT');
  safeAddColumn('devices', 'lifecycle_state TEXT NOT NULL DEFAULT "active"');
  safeAddColumn('devices', 'offboard_queued_at TEXT');
  safeAddColumn('devices', 'offboarded_at TEXT');
  safeAddColumn('devices', 'offboard_reason TEXT');
  safeAddColumn('devices', 'offboard_trigger_source TEXT');
  safeAddColumn('devices', 'offboard_laps_action_taken TEXT');
  safeAddColumn('devices', 'resurrected_at TEXT');
  safeAddColumn('devices', 'resurrect_count INTEGER NOT NULL DEFAULT 0');

  // Patches, Hardware & Network History
  safeAddColumn('patches', 'cve_id TEXT');
  safeAddColumn('patches', 'cvss_score REAL');
  safeAddColumn('hardware_history', 'acknowledged INTEGER NOT NULL DEFAULT 0');
  safeAddColumn('network_history', 'local_ip TEXT');

  // Tenants & Scripts
  safeAddColumn('tenants', 'mesh_group_id TEXT');
  safeAddColumn('tenants', 'mesh_server_id TEXT NOT NULL DEFAULT "ms2-primary"');
  safeAddColumn('tenants', 'lifecycle_state TEXT NOT NULL DEFAULT "active"');
  safeAddColumn('tenants', 'archived_at TEXT');
  safeAddColumn('tenants', 'offboard_reason TEXT');
  safeAddColumn('tenants', 'offline_auto_archive_days INTEGER NOT NULL DEFAULT 14');

  safeAddColumn('scripts', 'enabled INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('scripts', 'required_role TEXT NOT NULL DEFAULT "technician"');
  safeAddColumn('scripts', 'is_builtin INTEGER NOT NULL DEFAULT 0');
  safeAddColumn('scripts', 'tenant_id TEXT DEFAULT NULL');

  // Policy & LAPS extended columns + explicit override tracking
  safeAddColumn('policies', 'overrides_json TEXT');
  safeAddColumn('policies', 'max_snooze_hours INTEGER NOT NULL DEFAULT 8');
  safeAddColumn('policies', 'force_reboot_after_snooze INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('policies', 'final_countdown_sec INTEGER NOT NULL DEFAULT 300');
  safeAddColumn('policies', 'laps_enabled INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('policies', 'laps_auto_create_account INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('policies', 'laps_account_name TEXT NOT NULL DEFAULT "LocalAdmin"');
  safeAddColumn('policies', 'laps_password_mode TEXT NOT NULL DEFAULT "random"');
  safeAddColumn('policies', 'laps_password_length INTEGER NOT NULL DEFAULT 20');
  safeAddColumn('policies', 'laps_complexity TEXT NOT NULL DEFAULT "alphanumeric_symbols"');
  safeAddColumn('policies', 'laps_passphrase_words INTEGER NOT NULL DEFAULT 5');
  safeAddColumn('policies', 'laps_passphrase_separator TEXT NOT NULL DEFAULT "-"');
  safeAddColumn('policies', 'laps_static_password TEXT NOT NULL DEFAULT ""');
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
  safeAddColumn('policies', 'laps_cleanup_old_account_on_rename TEXT NOT NULL DEFAULT "disable"');
  safeAddColumn('policies', 'laps_disable_builtin_sid500_admin INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('policies', 'laps_offboard_explicit_device_action TEXT NOT NULL DEFAULT "remove_account"');
  safeAddColumn('policies', 'laps_offboard_client_archived_action TEXT NOT NULL DEFAULT "keep_account_rotate_final"');
  safeAddColumn('policies', 'laps_offboard_client_deleted_action TEXT NOT NULL DEFAULT "remove_account"');
  safeAddColumn('policies', 'offboard_offline_auto_archive_days INTEGER NOT NULL DEFAULT 14');
  safeAddColumn('policies', 'alert_rules_json TEXT');

  // Settings extended columns
  safeAddColumn('settings', 'code_signing_url TEXT NOT NULL DEFAULT ""');
  safeAddColumn('settings', 'session_recording_enabled INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'session_recording_retention_days INTEGER NOT NULL DEFAULT 90');
  safeAddColumn('settings', 'session_recording_quality TEXT NOT NULL DEFAULT "high"');
  safeAddColumn('settings', 'session_recording_visual_indicator INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'mesh_sync_enabled INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'mesh_client_delete_action TEXT NOT NULL DEFAULT "move_to_unassigned"');
  safeAddColumn('settings', 'mesh_external_delete_prompt INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'code_signing_enabled INTEGER NOT NULL DEFAULT 0');
  safeAddColumn('settings', 'code_signing_sign_scripts INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'code_signing_sign_agents INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'code_signing_sign_assemblies INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'code_signing_sign_ms2_binary INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'code_signing_strict_verify INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'installer_download_role TEXT NOT NULL DEFAULT "technician"');
  safeAddColumn('settings', 'installer_require_ticket INTEGER NOT NULL DEFAULT 0');
  safeAddColumn('settings', 'installer_gui_style TEXT NOT NULL DEFAULT "modern_glass"');
  safeAddColumn('settings', 'installer_service_name TEXT NOT NULL DEFAULT "VitrineAgent"');
  safeAddColumn('settings', 'installer_welcome_text TEXT NOT NULL DEFAULT "Installing Enterprise IT Support & Endpoint Protection"');
  safeAddColumn('settings', 'session_recording_stealth_for_techs INTEGER NOT NULL DEFAULT 0');
  safeAddColumn('settings', 'maintenance_auto_clear_hours INTEGER NOT NULL DEFAULT 24');
  safeAddColumn('settings', 'totp_secret TEXT NOT NULL DEFAULT ""');
  safeAddColumn('settings', 'oobe_completed INTEGER NOT NULL DEFAULT 0');
  safeAddColumn('settings', 'theme_mode TEXT NOT NULL DEFAULT "system"');
  safeAddColumn('settings', 'tray_theme_mode TEXT NOT NULL DEFAULT "system"');
  safeAddColumn('settings', 'quicksupport_enabled INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'quicksupport_custom_domain TEXT NOT NULL DEFAULT ""');
  safeAddColumn('settings', 'quicksupport_url_path TEXT NOT NULL DEFAULT "/remote"');
  safeAddColumn('settings', 'tls_mode TEXT NOT NULL DEFAULT "reverse_proxy"');
  safeAddColumn('settings', 'reverse_proxy_type TEXT NOT NULL DEFAULT "nginx"');
  safeAddColumn('settings', 'letsencrypt_email TEXT NOT NULL DEFAULT ""');
  safeAddColumn('settings', 'update_channel TEXT NOT NULL DEFAULT "stable"');
  safeAddColumn('settings', 'installed_version TEXT NOT NULL DEFAULT "2.5.0"');
  safeAddColumn('settings', 'installed_commit TEXT NOT NULL DEFAULT "v2.5.0"');
  safeAddColumn('settings', 'db_schema_version INTEGER NOT NULL DEFAULT 15');
  safeAddColumn('settings', 'update_auto_backup INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'update_auto_rollback INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'update_notify_webui INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'update_notify_email INTEGER NOT NULL DEFAULT 0');
  safeAddColumn('settings', 'update_create_psa_ticket INTEGER NOT NULL DEFAULT 0');
  safeAddColumn('settings', 'backup_schedule_enabled INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'backup_schedule_frequency TEXT NOT NULL DEFAULT "daily"');
  safeAddColumn('settings', 'backup_schedule_time TEXT NOT NULL DEFAULT "03:00"');
  safeAddColumn('settings', 'backup_retention_count INTEGER NOT NULL DEFAULT 14');
  safeAddColumn('settings', 'backup_max_storage_mb INTEGER NOT NULL DEFAULT 2048');
  safeAddColumn('settings', 'backup_include_branding INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'backup_include_mesh_config INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'backup_encryption_enabled INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'backup_encryption_passphrase TEXT NOT NULL DEFAULT ""');
  safeAddColumn('settings', 'backup_offsite_enabled INTEGER NOT NULL DEFAULT 0');
  safeAddColumn('settings', 'backup_offsite_provider TEXT NOT NULL DEFAULT "s3"');
  safeAddColumn('settings', 'backup_offsite_endpoint TEXT NOT NULL DEFAULT ""');
  safeAddColumn('settings', 'backup_offsite_bucket TEXT NOT NULL DEFAULT ""');
  safeAddColumn('settings', 'backup_offsite_access_key TEXT NOT NULL DEFAULT ""');
  safeAddColumn('settings', 'backup_offsite_secret_key TEXT NOT NULL DEFAULT ""');
  safeAddColumn('settings', 'oidc_client_secret TEXT NOT NULL DEFAULT ""');
  safeAddColumn('settings', 'psa_webhook_secret TEXT NOT NULL DEFAULT ""');
  safeAddColumn('settings', 'agent_enrollment_secret TEXT NOT NULL DEFAULT ""');
  safeAddColumn('settings', 'patch_auto_approve_third_party INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('settings', 'patch_canary_delay_days INTEGER NOT NULL DEFAULT 3');

  // Installer, Guest, Backup, LAPS, Appliances & Virtualization extended columns
  safeAddColumn('installer_audit_log', 'platform TEXT NOT NULL DEFAULT "windows"');
  safeAddColumn('installer_audit_log', 'expires_at TEXT');
  safeAddColumn('guest_access_grants', 'password_hash TEXT');
  safeAddColumn('system_backups', 'encrypted INTEGER NOT NULL DEFAULT 0');
  safeAddColumn('system_backups', 'offsite_synced INTEGER NOT NULL DEFAULT 0');
  safeAddColumn('system_backups', 'offsite_location TEXT NOT NULL DEFAULT "local-only"');

  safeAddColumn('laps_vault', 'previous_account_name TEXT');
  safeAddColumn('laps_vault', 'previous_encrypted_password TEXT');
  safeAddColumn('laps_vault', 'previous_iv TEXT');
  safeAddColumn('laps_vault', 'sid500_builtin_disabled INTEGER NOT NULL DEFAULT 1');
  safeAddColumn('laps_vault', 'rotation_pending_online INTEGER NOT NULL DEFAULT 0');
  safeAddColumn('laps_vault', 'pending_rotation_reason TEXT');
  safeAddColumn('laps_vault', 'pending_account_name TEXT');

  safeAddColumn('network_appliances', 'integration_protocol TEXT NOT NULL DEFAULT "generic_snmp_v3"');
  safeAddColumn('network_appliances', 'vendor_api_endpoint TEXT');
  safeAddColumn('network_appliances', 'vendor_api_token_masked TEXT');
  safeAddColumn('network_appliances', 'vendor_api_token_encrypted TEXT');

  safeAddColumn('virtualization_hosts', 'api_port INTEGER NOT NULL DEFAULT 8006');
  safeAddColumn('virtualization_hosts', 'api_username TEXT');
  safeAddColumn('virtualization_hosts', 'api_token_encrypted TEXT');

  // Deduplicate custom_field_values before enforcing UNIQUE(field_id, entity_id)
  try {
    db.exec(`
      DELETE FROM custom_field_values
      WHERE rowid NOT IN (
        SELECT MAX(rowid) FROM custom_field_values GROUP BY field_id, entity_id
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_custom_field_values_unique
      ON custom_field_values(field_id, entity_id);
    `);
  } catch {
    // Ignore if table empty or index exists
  }

  // Synchronize runtime binary version/commit and migrate plaintext secrets to AES-256-GCM vault
  migrateSecretsAndRuntimeMetadata();
}

function migrateSecretsAndRuntimeMetadata() {
  try {
    const settings = db.prepare('SELECT * FROM settings WHERE id = 1').get() as any;
    if (settings) {
      // Keep running software version & schema version synchronized with the actual binary on disk
      db.prepare(`
        UPDATE settings
        SET installed_version = ?,
            installed_commit = ?,
            db_schema_version = ?
        WHERE id = 1
      `).run(APP_VERSION, APP_INSTALLED_COMMIT, APP_SCHEMA_VERSION);

      const secretColumns = [
        'meshcentral_api_token',
        'smtp_pass',
        'itflow_api_key',
        'totp_secret',
        'backup_encryption_passphrase',
        'backup_offsite_access_key',
        'backup_offsite_secret_key',
        'oidc_client_secret',
        'psa_webhook_secret',
        'agent_enrollment_secret'
      ];

      for (const col of secretColumns) {
        let rawVal = settings[col];
        if (col === 'totp_secret' && (!rawVal || rawVal === 'JBSWY3DPEHPK3PXP')) {
          rawVal = generateRandomBase32(20);
        }
        if (col === 'psa_webhook_secret' && !rawVal) {
          rawVal = crypto.randomBytes(24).toString('hex');
        }
        if (col === 'agent_enrollment_secret' && !rawVal) {
          rawVal = crypto.randomBytes(24).toString('hex');
        }
        if (col === 'backup_offsite_access_key' && rawVal === 'AKIAVITRINERMMVAULT') {
          rawVal = '';
        }
        if (rawVal && !isEncryptedVaultSecret(rawVal)) {
          db.prepare(`UPDATE settings SET ${col} = ? WHERE id = 1`).run(encryptVaultSecret(rawVal));
        } else if (rawVal === '' && (col === 'backup_offsite_access_key')) {
          db.prepare(`UPDATE settings SET ${col} = '' WHERE id = 1`).run();
        }
      }

      // If legacy unreachable code signing IP is still set without explicit user configuration, disable by default
      if (settings.code_signing_url === 'http://10.10.10.20:5000' && !settings.oobe_completed) {
        db.prepare("UPDATE settings SET code_signing_enabled = 0, code_signing_url = '' WHERE id = 1").run();
      }
    }

    // Encrypt plaintext BitLocker keys at rest
    const devices = db.prepare('SELECT id, bitlocker_key FROM devices WHERE bitlocker_key IS NOT NULL AND bitlocker_key != ""').all() as Array<{ id: string; bitlocker_key: string }>;
    for (const dev of devices) {
      if (!isEncryptedVaultSecret(dev.bitlocker_key)) {
        db.prepare('UPDATE devices SET bitlocker_key = ? WHERE id = ?').run(encryptVaultSecret(dev.bitlocker_key), dev.id);
      }
    }

    // Encrypt plaintext static LAPS passwords in policies
    const policies = db.prepare('SELECT id, laps_static_password FROM policies WHERE laps_static_password IS NOT NULL AND laps_static_password != ""').all() as Array<{ id: string; laps_static_password: string }>;
    for (const pol of policies) {
      if (!isEncryptedVaultSecret(pol.laps_static_password)) {
        db.prepare('UPDATE policies SET laps_static_password = ? WHERE id = ?').run(encryptVaultSecret(pol.laps_static_password), pol.id);
      }
    }

    // Encrypt plaintext MeshCentral server tokens
    const meshServers = db.prepare('SELECT id, api_token FROM mesh_servers WHERE api_token IS NOT NULL AND api_token != ""').all() as Array<{ id: string; api_token: string }>;
    for (const ms of meshServers) {
      if (!isEncryptedVaultSecret(ms.api_token)) {
        db.prepare('UPDATE mesh_servers SET api_token = ? WHERE id = ?').run(encryptVaultSecret(ms.api_token), ms.id);
      }
    }

    // Hash plaintext guest portal passwords and redact cleartext column
    const grants = db.prepare('SELECT id, temp_password, password_hash FROM guest_access_grants').all() as Array<{ id: string; temp_password: string; password_hash?: string }>;
    for (const g of grants) {
      if (!g.password_hash && g.temp_password && g.temp_password !== '[HASHED]') {
        db.prepare('UPDATE guest_access_grants SET password_hash = ?, temp_password = ? WHERE id = ?').run(
          hashPasswordScrypt(g.temp_password),
          '[HASHED]',
          g.id
        );
      }
    }
  } catch {
    // Safe fallback if migrating partial schema
  }
}

function seedProductionBaseline() {
  // 1. Default Global Policy Baseline
  const globalPolCount = (db.prepare("SELECT COUNT(*) as c FROM policies WHERE tier = 'global'").get() as { c: number }).c;
  if (globalPolCount === 0) {
    db.prepare(`
      INSERT INTO policies (
        id, name, tier, target_id, telemetry_interval_sec, require_remote_consent,
        consent_timeout_sec, consent_timeout_action, auto_lock_on_disconnect,
        patch_schedule, patch_reboot_enforcement, self_healing_enabled
      ) VALUES (
        'pol-global', 'Global MSP Baseline', 'global', NULL, 30, 1,
        30, 'cancel', 1,
        'Tuesdays @ 02:00 AM', 'Prompt 4h, then force reboot', 1
      )
    `).run();
  }

  // 2. Built-in Production RMM Script Library (Cross-Platform PowerShell & Bash)
  const builtinScripts = [
    {
      id: 'scr-1',
      name: 'Restart Spooler & Clear Stuck Print Jobs',
      description: 'Stops Print Spooler service, purges PRINTERS spool folder, and restarts service.',
      language: 'powershell',
      code: `Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:SystemRoot\\System32\\spool\\PRINTERS\\*" -Force -Recurse -ErrorAction SilentlyContinue
Start-Service -Name "Spooler"
Write-Output "Print spooler cleared and restarted on $env:COMPUTERNAME."`,
      category: 'Remediation',
      required_role: 'technician'
    },
    {
      id: 'scr-2',
      name: 'Purge Windows Update SoftwareDistribution Cache',
      description: 'Stops wuauserv, clears stuck CBS / SoftwareDistribution download cache, and restarts update services.',
      language: 'powershell',
      code: `Stop-Service -Name wuauserv, cryptSvc, bits, msiserver -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:SystemRoot\\SoftwareDistribution\\Download\\*" -Recurse -Force -ErrorAction SilentlyContinue
Start-Service -Name wuauserv, cryptSvc, bits, msiserver -ErrorAction SilentlyContinue
Write-Output "Windows Update cache successfully purged."`,
      category: 'Remediation',
      required_role: 'technician'
    },
    {
      id: 'scr-3',
      name: 'Extract BitLocker Volume Recovery Protectors',
      description: 'Reads BitLocker recovery keys for all fixed volumes for secure vault escrow.',
      language: 'powershell',
      code: `$keys = Get-BitLockerVolume | ForEach-Object {
    $vol = $_.MountPoint
    $kp = ($_.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }).RecoveryPassword
    [PSCustomObject]@{ Volume = $vol; Status = [string]$_.VolumeStatus; Key = $kp }
}
$keys | ConvertTo-Json -Compress`,
      category: 'Diagnostic',
      required_role: 'msp_super_admin'
    },
    {
      id: 'scr-4',
      name: 'Cyber Isolation: Emergency Network Quarantine',
      description: 'Applies strict Windows Defender Firewall rules dropping inbound/outbound traffic except the RMM control plane.',
      language: 'powershell',
      code: `New-NetFirewallRule -DisplayName "VITRINE_QUARANTINE_IN" -Direction Inbound -Action Block -Profile Any -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "VITRINE_QUARANTINE_OUT" -Direction Outbound -Action Block -Profile Any -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "VITRINE_QUARANTINE_ALLOW_RMM" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 443, 4430, 8080 -ErrorAction SilentlyContinue
Write-Output "Endpoint isolated from lateral network traffic; RMM control channel preserved."`,
      category: 'Security',
      required_role: 'msp_super_admin'
    },
    {
      id: 'scr-5',
      name: 'Trigger Full Microsoft Defender Antivirus Scan',
      description: 'Updates signatures and runs Start-MpScan -ScanType FullScan.',
      language: 'powershell',
      code: `Update-MpSignature
Start-MpScan -ScanType FullScan
Write-Output "Full Microsoft Defender Antivirus scan completed."`,
      category: 'Security',
      required_role: 'technician'
    },
    {
      id: 'scr-6',
      name: 'Enable Wake-on-LAN (OS NIC Drivers, Fast Startup & OEM BIOS WMI)',
      description: 'Configures NIC Wake on Magic Packet, disables Fast Startup power-cut, and applies Dell/HP/Lenovo WMI BIOS flags.',
      language: 'powershell',
      code: `Get-NetAdapter -Physical | ForEach-Object {
    Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "Wake on Magic Packet" -DisplayValue "Enabled" -ErrorAction SilentlyContinue
    Set-NetAdapterPowerManagement -Name $_.Name -WakeOnMagicPacket $true -ErrorAction SilentlyContinue
}
Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power" -Name "HiberbootEnabled" -Value 0 -Force
Write-Output "Wake-on-LAN OS NIC and power settings enabled."`,
      category: 'Provisioning',
      required_role: 'technician'
    },
    {
      id: 'scr-7',
      name: 'Intel vPro / AMT Hardware Detection & Local Provisioning',
      description: 'Detects Intel MEI hardware and queries AMT status via MeshCmd.',
      language: 'powershell',
      code: `$mei = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -match 'Management Engine Interface' }
if (-not $mei) { Write-Output "RESULT: NOT_SUPPORTED - No Intel MEI detected."; exit 0 }
$meshCmd = "$env:ProgramFiles\\Mesh Agent\\meshcmd.exe"
if (Test-Path $meshCmd) { & $meshCmd amtinfo }
Write-Output "Intel vPro / AMT hardware audit finished."`,
      category: 'Diagnostic',
      required_role: 'msp_super_admin'
    },
    {
      id: 'scr-net-reset',
      name: 'Flush DNS & Reset Winsock Network Stack',
      description: 'Flushes DNS cache, resets Winsock catalog, and renews DHCP lease.',
      language: 'powershell',
      code: `Clear-DnsClientCache
netsh winsock reset
netsh int ip reset
Write-Output "DNS flushed and network stack reset complete."`,
      category: 'Remediation',
      required_role: 'technician'
    },
    {
      id: 'scr-disk-cleanup',
      name: 'Deep Temp & DISM Component Store Cleanup',
      description: 'Purges system/user temp directories and runs DISM StartComponentCleanup.',
      language: 'powershell',
      code: `Remove-Item -Path "$env:TEMP\\*" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "C:\\Windows\\Temp\\*" -Force -Recurse -ErrorAction SilentlyContinue
Dism.exe /Online /Cleanup-Image /StartComponentCleanup
Write-Output "Deep disk and component cleanup completed."`,
      category: 'Maintenance',
      required_role: 'technician'
    },
    {
      id: 'scr-create-localadmin',
      name: 'Create Break-Glass Local Administrator Account',
      description: 'Creates a local emergency administrator account using CSPRNG entropy compatible with PowerShell 5.1 & 7+.',
      language: 'powershell',
      code: `param([string]$AdminUser = "VitrineEmergencyAdmin")
$bytes = New-Object byte[] 18
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$Password = [Convert]::ToBase64String($bytes) + "!9aA"
$sec = ConvertTo-SecureString $Password -AsPlainText -Force
New-LocalUser -Name $AdminUser -Password $sec -FullName "Emergency Admin" -ErrorAction Stop | Out-Null
Add-LocalGroupMember -Group "Administrators" -Member $AdminUser
Write-Output "Created break-glass admin user '$AdminUser'."`,
      category: 'Provisioning',
      required_role: 'msp_super_admin'
    },
    {
      id: 'scr-linux-maint',
      name: 'Linux Journal Vacuum & Package Cache Cleanup',
      description: 'Trims systemd journal logs to 7 days and cleans apt/dnf package caches.',
      language: 'bash',
      code: `#!/usr/bin/env bash
set -e
journalctl --vacuum-time=7d || true
if command -v apt-get >/dev/null 2>&1; then apt-get clean; fi
if command -v dnf >/dev/null 2>&1; then dnf clean all; fi
df -h /`,
      category: 'Maintenance',
      required_role: 'technician'
    },
    {
      id: 'scr-sysinfo-collect',
      name: 'Collect Cross-Platform Diagnostic Summary',
      description: 'Captures hostname, OS build, uptime, and primary IPv4 configuration.',
      language: 'powershell',
      code: `$os = Get-CimInstance Win32_OperatingSystem
[PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    OS = $os.Caption
    Build = $os.BuildNumber
    UptimeHours = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
} | ConvertTo-Json`,
      category: 'Diagnostic',
      required_role: 'technician'
    }
  ];

  const insertScript = db.prepare(`
    INSERT OR IGNORE INTO scripts (id, name, description, language, code, category, enabled, required_role, is_builtin)
    VALUES (?, ?, ?, ?, ?, ?, 1, ?, 1)
  `);
  for (const s of builtinScripts) {
    insertScript.run(s.id, s.name, s.description, s.language, s.code, s.category, s.required_role);
  }

  // 3. Default Self-Healing Watchdog Rules
  const monCount = (db.prepare('SELECT COUNT(*) as c FROM self_healing_monitors').get() as { c: number }).c;
  if (monCount === 0) {
    const insMon = db.prepare(`
      INSERT OR IGNORE INTO self_healing_monitors (id, name, condition_type, condition_value, remediation_script_id, cooldown_min, alert_on_failure, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insMon.run('mon-1', 'Print Spooler Hung Watchdog', 'service_stopped', 'Spooler', 'scr-1', 15, 1, 1);
    insMon.run('mon-2', 'Low Disk Space Auto-Cleanup (<10%)', 'disk_space_low', '10', 'scr-disk-cleanup', 60, 1, 1);
  }

  // 4. Standard Custom Field Schema Definitions (No fake values)
  const cfCount = (db.prepare('SELECT COUNT(*) as c FROM custom_field_definitions').get() as { c: number }).c;
  if (cfCount === 0) {
    const insCf = db.prepare(`
      INSERT OR IGNORE INTO custom_field_definitions (id, key, label, category, field_type, scope, options, description)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insCf.run('cf-1', 'asset_tag', 'Asset Tag ID', 'System', 'text', 'device', null, 'Physical inventory barcode or tag');
    insCf.run('cf-2', 'department', 'Assigned Department', 'System', 'dropdown', 'device', JSON.stringify(['Executive', 'Finance', 'Engineering', 'Legal', 'Clinical', 'Operations']), 'Primary departmental cost center');
    insCf.run('cf-3', 'primary_user', 'Primary Point of Contact', 'System', 'text', 'device', null, 'Designated employee user account');
    insCf.run('cf-4', 'bdr_tier', 'BDR Backup Strategy', 'Security', 'dropdown', 'device', JSON.stringify(['Tier 1 - Hourly VSS + Cloud Immutable', 'Tier 2 - Daily Image', 'Tier 3 - File-Level Restic', 'Unmanaged / Excluded']), 'Backup & Disaster Recovery policy assignment');
    insCf.run('cf-5', 'gl_billing_code', 'GL Billing Cost Code', 'Billing', 'text', 'tenant', null, 'ERP sync accounting reference');
    insCf.run('cf-6', 'vip_escalation', 'VIP Support SLA Escalation', 'Custom', 'checkbox', 'device', null, 'Enables immediate P1 response paging for executive endpoints');
  }
}

// Explicit opt-in evaluation dataset generator (never auto-run on clean production OOBE)
export function seedDemoDataset() {
  const insertTenant = db.prepare(`
    INSERT OR IGNORE INTO tenants (id, name, slug, contact_email, device_count)
    VALUES (?, ?, ?, ?, ?)
  `);
  insertTenant.run('t-apex', 'Apex Financial Group', 'apex-financial', 'ops@apexfin.example', 2);
  insertTenant.run('t-nexus', 'Nexus Health Systems', 'nexus-health', 'it-sec@nexushealth.example', 2);

  const insertSite = db.prepare(`
    INSERT OR IGNORE INTO sites (id, tenant_id, name, subnet)
    VALUES (?, ?, ?, ?)
  `);
  insertSite.run('s-apex-hq', 't-apex', 'HQ - Primary Office', '10.200.10.0/24');
  insertSite.run('s-nexus-clinic', 't-nexus', 'Main Clinic', '172.16.40.0/24');

  const insertDevice = db.prepare(`
    INSERT OR IGNORE INTO devices (
      id, mesh_node_id, tenant_id, site_id, hostname, os_type, os_version, os_build,
      ip_address, mac_address, status, device_role, manufacturer, model, cpu_model, cpu_cores,
      cpu_usage, ram_total_gb, ram_used_gb, disk_total_gb, disk_free_gb,
      smart_status, bitlocker_status, bitlocker_key, serial_number, edr_name, edr_status, pending_reboot, quarantined, intel_amt_enabled
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insertDevice.run(
    'dev-win11-corp',
    'node//demo-win11-corp',
    't-apex',
    's-apex-hq',
    'WIN11-EXEC-01',
    'windows',
    'Windows 11 Pro 23H2',
    '22631.4169',
    '10.200.10.42',
    '00:1A:2B:3C:4D:5E',
    'online',
    'Workstation',
    'Dell Inc.',
    'Latitude 7440',
    'Intel Core i7-1365U vPro',
    10,
    18.4,
    32,
    11.2,
    1000,
    642,
    'Healthy',
    'Encrypted (XTS-AES 256)',
    encryptVaultSecret('481920-592019-209184-102948-592810-482019'),
    'DL-7440-001',
    'Microsoft Defender Antivirus',
    'Active & Up to Date',
    0,
    0,
    1
  );

  insertDevice.run(
    'dev-srv-db01',
    'node//demo-srv-db01',
    't-apex',
    's-apex-hq',
    'APEX-PGSQL-01',
    'linux',
    'Ubuntu 24.04.1 LTS',
    '6.8.0-45-generic',
    '10.200.10.22',
    '00:16:3E:74:12:9A',
    'online',
    'Database Server',
    'Supermicro',
    'SYS-111C-NR',
    'AMD EPYC 9354P 32-Core',
    32,
    24.1,
    128,
    48.6,
    2000,
    1420,
    'Healthy',
    'Encrypted (LUKS2 AES-XTS)',
    encryptVaultSecret('LUKS2-994012-883920-112948-774829'),
    'SM-9354-022',
    'CrowdStrike Falcon Sensor',
    'Active & Up to Date',
    0,
    0,
    0
  );

  insertDevice.run(
    'dev-nexus-wks01',
    'node//demo-nexus-wks01',
    't-nexus',
    's-nexus-clinic',
    'NEXUS-CLINIC-01',
    'windows',
    'Windows 11 Enterprise 23H2',
    '22631.4317',
    '172.16.40.15',
    '00:1B:44:11:3A:B7',
    'online',
    'Workstation',
    'HP',
    'EliteBook 840 G10',
    'Intel Core i7-1355U',
    10,
    14.2,
    16,
    7.8,
    512,
    310,
    'Healthy',
    'Encrypted (XTS-AES 256)',
    encryptVaultSecret('719283-482910-663819-209384-118273-994012'),
    'HP-840G10-104',
    'Microsoft Defender for Endpoint',
    'Active & Up to Date',
    0,
    0,
    1
  );

  insertDevice.run(
    'dev-nexus-hl7-01',
    'node//demo-nexus-hl7-01',
    't-nexus',
    's-nexus-clinic',
    'NEXUS-HL7-GW01',
    'linux',
    'Rocky Linux 9.4',
    '5.14.0-427.el9',
    '172.16.40.10',
    '00:1B:44:11:3A:C0',
    'online',
    'Application Server',
    'Dell Inc.',
    'PowerEdge R350',
    'Intel Xeon E-2378G',
    8,
    19.7,
    64,
    21.4,
    1000,
    760,
    'Healthy',
    'Encrypted (LUKS2 AES-XTS)',
    encryptVaultSecret('LUKS2-615243-881920-334910-552819'),
    'DL-R350-882',
    'SentinelOne Singularity',
    'Active & Up to Date',
    0,
    0,
    0
  );
}
