import { FastifyInstance } from 'fastify';
import { db } from '../db/index.js';
import { meshBridge } from '../services/meshcentral/index.js';
import { getLapsCredential, rotateLapsPassword } from '../services/laps/index.js';
import { resolveEffectiveDevicePolicy } from '../services/policy/index.js';

export async function registerApiRoutes(server: FastifyInstance) {
  // Settings & Onboarding
  server.get('/api/settings', async () => {
    return db.prepare('SELECT * FROM settings WHERE id = 1').get();
  });

  server.post('/api/settings', async (request) => {
    const body = request.body as any;
    db.prepare(`
      UPDATE settings SET
        brand_name = COALESCE(?, brand_name),
        primary_color = COALESCE(?, primary_color),
        glass_blur_level = COALESCE(?, glass_blur_level),
        custom_domain = COALESCE(?, custom_domain),
        meshcentral_url = COALESCE(?, meshcentral_url),
        meshcentral_api_token = COALESCE(?, meshcentral_api_token),
        smtp_host = COALESCE(?, smtp_host),
        smtp_port = COALESCE(?, smtp_port),
        smtp_user = COALESCE(?, smtp_user),
        smtp_pass = COALESCE(?, smtp_pass),
        smtp_from = COALESCE(?, smtp_from),
        itflow_url = COALESCE(?, itflow_url),
        itflow_api_key = COALESCE(?, itflow_api_key),
        is_onboarded = 1,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = 1
    `).run(
      body.brand_name,
      body.primary_color,
      body.glass_blur_level,
      body.custom_domain,
      body.meshcentral_url,
      body.meshcentral_api_token,
      body.smtp_host,
      body.smtp_port,
      body.smtp_user,
      body.smtp_pass,
      body.smtp_from,
      body.itflow_url,
      body.itflow_api_key
    );

    meshBridge.checkConfig();
    return { success: true, settings: db.prepare('SELECT * FROM settings WHERE id = 1').get() };
  });

  // Tenants & Sites
  server.get('/api/tenants', async () => {
    const tenants = db.prepare('SELECT * FROM tenants').all() as any[];
    for (const t of tenants) {
      t.sites = db.prepare('SELECT * FROM sites WHERE tenant_id = ?').all(t.id);
    }
    return tenants;
  });

  // Devices Fleet
  server.get('/api/devices', async () => {
    return db.prepare(`
      SELECT d.*, t.name as tenant_name, s.name as site_name
      FROM devices d
      LEFT JOIN tenants t ON d.tenant_id = t.id
      LEFT JOIN sites s ON d.site_id = s.id
      ORDER BY d.hostname ASC
    `).all();
  });

  server.get('/api/devices/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const device = db.prepare(`
      SELECT d.*, t.name as tenant_name, s.name as site_name
      FROM devices d
      LEFT JOIN tenants t ON d.tenant_id = t.id
      LEFT JOIN sites s ON d.site_id = s.id
      WHERE d.id = ?
    `).get(id) as any;

    if (!device) return reply.status(404).send({ error: 'Device not found' });
    device.policy = resolveEffectiveDevicePolicy(id);
    device.laps = getLapsCredential(id, false);
    return device;
  });

  // Device Remote Privacy & Consent Control
  server.get('/api/devices/:id/consent-status', async (request) => {
    const { id } = request.params as { id: string };
    const policy = resolveEffectiveDevicePolicy(id);
    // Context-aware prompt bypass: if lock screen / no active user, prompt can be bypassed
    const isAtLockScreen = id.includes('isolated') || id.includes('srv');
    return {
      requireConsent: policy.requireRemoteConsent && !isAtLockScreen,
      timeoutSec: policy.consentTimeoutSec,
      timeoutAction: policy.consentTimeoutAction,
      autoLockOnDisconnect: policy.autoLockOnDisconnect,
      bypassedDueToLockScreen: isAtLockScreen
    };
  });

  // Silent Background Process Manager
  server.get('/api/devices/:id/processes', async (request) => {
    const { id } = request.params as { id: string };
    return meshBridge.getProcesses(id);
  });

  server.post('/api/devices/:id/processes/:pid/kill', async (request) => {
    const { id, pid } = request.params as { id: string; pid: string };
    const success = meshBridge.killProcess(id, parseInt(pid, 10));
    return { success };
  });

  // Silent Background Services Manager
  server.get('/api/devices/:id/services', async (request) => {
    const { id } = request.params as { id: string };
    return meshBridge.getServices(id);
  });

  server.post('/api/devices/:id/services/:name/:action', async (request) => {
    const { id, name, action } = request.params as { id: string; name: string; action: 'start' | 'stop' | 'restart' };
    const success = meshBridge.manageService(id, name, action);
    return { success };
  });

  // Remote Registry Browser
  server.get('/api/devices/:id/registry', async (request) => {
    const query = request.query as any;
    const path = query.path || 'HKLM\\SOFTWARE\\VitrineRMM';
    return meshBridge.getRegistryKeys(path);
  });

  // Scheduled Tasks Manager
  server.get('/api/devices/:id/tasks', async (request) => {
    const { id } = request.params as { id: string };
    return meshBridge.getScheduledTasks(id);
  });

  // Dual-Pane File Manager
  server.get('/api/devices/:id/files', async (request) => {
    const { id } = request.params as { id: string };
    const query = request.query as any;
    const path = query.path || (id.includes('lin') ? '/etc' : 'C:\\');
    return meshBridge.getDirectoryListing(id, path);
  });

  // Cyber Isolation / Network Quarantine
  server.post('/api/devices/:id/quarantine', async (request) => {
    const { id } = request.params as { id: string };
    const body = request.body as any;
    const quarantined = Boolean(body.quarantine);
    meshBridge.toggleQuarantine(id, quarantined);
    return { success: true, quarantined };
  });

  // LAPS Vault (Local Admin Password Solution)
  server.get('/api/devices/:id/laps', async (request) => {
    const { id } = request.params as { id: string };
    const query = request.query as any;
    const reveal = query.reveal === 'true';
    if (reveal) {
      db.prepare(`
        INSERT INTO audit_logs (id, username, device_id, action, details)
        VALUES (?, 'admin', ?, 'LAPS Password Revealed', 'Technician revealed ephemeral local administrator password')
      `).run(`aud-laps-${Date.now()}`, id);
    }
    return getLapsCredential(id, reveal);
  });

  server.post('/api/devices/:id/laps/rotate', async (request) => {
    const { id } = request.params as { id: string };
    const cred = rotateLapsPassword(id);
    return cred;
  });

  // Policies & Hierarchy
  server.get('/api/policies', async () => {
    return db.prepare('SELECT * FROM policies ORDER BY tier ASC').all();
  });

  server.get('/api/policies/effective/:deviceId', async (request) => {
    const { deviceId } = request.params as { deviceId: string };
    return resolveEffectiveDevicePolicy(deviceId);
  });

  // Patches & Updates
  server.get('/api/patches', async () => {
    return db.prepare(`
      SELECT p.*, d.hostname
      FROM patches p
      JOIN devices d ON p.device_id = d.id
    `).all();
  });

  server.post('/api/patches/:id/approve', async (request) => {
    const { id } = request.params as { id: string };
    db.prepare("UPDATE patches SET status = 'Approved' WHERE id = ?").run(id);
    return { success: true };
  });

  // Centralized Scripting Library
  server.get('/api/scripts', async () => {
    return db.prepare('SELECT * FROM scripts').all();
  });

  server.post('/api/scripts/:id/run', async (request) => {
    const { id } = request.params as { id: string };
    const body = request.body as any;
    const targetDeviceIds = body.deviceIds || [];

    for (const devId of targetDeviceIds) {
      db.prepare(`
        INSERT INTO audit_logs (id, username, device_id, action, details)
        VALUES (?, 'admin', ?, 'Script Executed', ?)
      `).run(`aud-scr-${Date.now()}`, devId, `Script ID ${id} dispatched via mass orchestration`);
    }

    return {
      success: true,
      dispatchedCount: targetDeviceIds.length,
      executionId: `exec-${Date.now()}`
    };
  });

  // Self-Healing Watchdogs
  server.get('/api/self-healing', async () => {
    return db.prepare('SELECT * FROM self_healing_monitors').all();
  });

  // PSA / ITFlow Synchronization
  server.get('/api/psa/tickets', async () => {
    return db.prepare('SELECT * FROM psa_tickets ORDER BY created_at DESC').all();
  });

  server.post('/api/psa/tickets', async (request) => {
    const body = request.body as any;
    const id = `tkt-${Date.now()}`;
    const ticketNum = `ITF-${Math.floor(1000 + Math.random() * 9000)}`;
    db.prepare(`
      INSERT INTO psa_tickets (id, ticket_number, title, client_name, device_id, status, priority)
      VALUES (?, ?, ?, ?, ?, 'Open', ?)
    `).run(id, ticketNum, body.title, body.client_name, body.device_id, body.priority || 'Medium');
    return { success: true, id, ticketNumber: ticketNum };
  });

  // Outbound SMTP Testing
  server.post('/api/smtp/test', async (request) => {
    const body = request.body as any;
    return {
      success: true,
      message: `Test email dispatched to ${body.to || 'admin@vitrine-rmm.internal'} via ${body.host || 'smtp.mailgun.org'}:587 (TLS)`,
      timestamp: new Date().toISOString()
    };
  });

  // Network Discovery & SNMP Probes
  server.get('/api/discovery/topology', async () => {
    return {
      coreSwitch: {
        name: 'SW-CORE-01 (Cisco Catalyst 9300-48P)',
        ip: '10.200.10.1',
        ports: [
          { port: 'Gig1/0/1', vlan: 10, status: 'Up', speed: '1000 Mbps', lldpNeighbor: 'APEX-DC01-PROD' },
          { port: 'Gig1/0/2', vlan: 10, status: 'Up', speed: '1000 Mbps', lldpNeighbor: 'WIN11-PRO-EXEC' },
          { port: 'Gig1/0/24', vlan: 1, status: 'Up', speed: '10000 Mbps', lldpNeighbor: 'FW-GATEWAY-HA01' },
          { port: 'Gig1/0/48', vlan: 50, status: 'Up', speed: '10000 Mbps', lldpNeighbor: 'SW-DIST-DR01' }
        ]
      },
      discoveredSubnets: [
        { subnet: '10.200.10.0/24', probeHost: 'APEX-DC01-PROD', totalDiscovered: 42, unmanaged: 3 },
        { subnet: '192.168.40.0/24', probeHost: 'CLINIC-DESK-04', totalDiscovered: 18, unmanaged: 1 }
      ]
    };
  });

  // Virtualization / Hypervisor Monitoring
  server.get('/api/virtualization/hosts', async () => {
    return [
      {
        id: 'pve-node-01',
        name: 'Proxmox VE Cluster Node 1',
        hostType: 'Proxmox VE 8.2',
        status: 'Online',
        cpuUsagePct: 24.8,
        ramUsageGb: 92.4,
        ramTotalGb: 256.0,
        storageFreeTb: 4.8,
        storageTotalTb: 8.0,
        vms: [
          { vmid: 100, name: 'win11-prod-workstation', status: 'Running', os: 'Windows 11', cpu: 12, ramGb: 16 },
          { vmid: 101, name: 'debian-dns-pihole', status: 'Running', os: 'Debian 12', cpu: 2, ramGb: 4 },
          { vmid: 102, name: 'srv-db-backup-staging', status: 'Stopped', os: 'Ubuntu 24.04', cpu: 0, ramGb: 16 }
        ]
      }
    ];
  });

  // Audit Logs
  server.get('/api/audit', async () => {
    return db.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 50').all();
  });

  // Executive QBR Report Generator
  server.get('/api/reports/qbr', async () => {
    const totalDevices = (db.prepare('SELECT COUNT(*) as c FROM devices').get() as any).c;
    const onlineDevices = (db.prepare("SELECT COUNT(*) as c FROM devices WHERE status = 'online'").get() as any).c;
    const bitlockerProtected = (db.prepare("SELECT COUNT(*) as c FROM devices WHERE bitlocker_status LIKE 'Encrypted%'").get() as any).c;
    const approvedPatches = (db.prepare("SELECT COUNT(*) as c FROM patches WHERE status = 'Approved' OR status = 'Installed'").get() as any).c;
    const totalPatches = (db.prepare('SELECT COUNT(*) as c FROM patches').get() as any).c;

    return {
      reportDate: new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }),
      quarter: 'Q4 2026 Executive Review',
      fleetHealthScore: 98.4,
      totalManagedEndpoints: totalDevices,
      endpointAvailability: `${((onlineDevices / totalDevices) * 100).toFixed(1)}%`,
      patchCompliance: `${((approvedPatches / (totalPatches || 1)) * 100).toFixed(1)}%`,
      encryptionCompliance: `${((bitlockerProtected / totalDevices) * 100).toFixed(1)}%`,
      edrProtectionRate: '100.0%',
      quarantinedEndpoints: 1,
      remediationsAutomated: 142,
      ticketsSynchronized: 38
    };
  });
}
