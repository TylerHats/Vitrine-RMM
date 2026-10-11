import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';

// Database storage location (inside persistent data/ folder)
const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), '..', 'data');
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
  `);

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
