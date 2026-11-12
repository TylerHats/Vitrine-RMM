import https from 'https';
import http from 'http';
import net from 'net';
import { db } from '../../db/index.js';
import { decryptVaultSecret, validateOutboundHostSafety } from '../vault/index.js';

interface RawJsonResponse {
  status: number;
  body: any;
}

// Performs an HTTPS/HTTP JSON request allowing self-signed lab certificates on Proxmox/vSphere
// AFTER DNS/IP SSRF safety has been strictly verified.
function requestHypervisorJson(
  urlStr: string,
  options: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    timeoutMs?: number;
  } = {}
): Promise<RawJsonResponse> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(urlStr);
    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    const req = lib.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: `${parsed.pathname}${parsed.search}`,
        method: options.method || 'GET',
        headers: {
          Accept: 'application/json',
          ...(options.headers || {})
        },
        rejectUnauthorized: false,
        timeout: options.timeoutMs || 6000
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json: any = null;
          try {
            json = text ? JSON.parse(text) : null;
          } catch {
            json = { raw: text.slice(0, 300) };
          }
          resolve({ status: res.statusCode || 0, body: json });
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error('Hypervisor API request timed out'));
    });
    req.on('error', (err) => reject(err));
    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

function probeTcpPort(host: string, port: number, timeoutMs = 3000): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let settled = false;
    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      sock.destroy();
      resolve(ok);
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    sock.connect(port, host);
  });
}

function formatProxmoxTokenHeader(apiUsername?: string | null, rawToken?: string): string {
  const token = (rawToken || '').trim();
  if (!token) return '';
  if (token.toLowerCase().startsWith('pveapitoken=')) {
    return token;
  }
  // If user pasted full 'root@pam!vitrine=xxxx-xxxx', prefix PVEAPIToken=
  if (token.includes('!') && token.includes('=')) {
    return `PVEAPIToken=${token}`;
  }
  const userPart = (apiUsername || 'root@pam!vitrine').trim();
  if (userPart.includes('!')) {
    return `PVEAPIToken=${userPart}=${token}`;
  }
  return `PVEAPIToken=${userPart}!vitrine=${token}`;
}

export async function syncVirtualizationHost(hostId: string): Promise<{
  synced: boolean;
  liveApiConnected: boolean;
  discoveredVms: number;
  status: string;
  message: string;
}> {
  const host = db.prepare('SELECT * FROM virtualization_hosts WHERE id = ?').get(hostId) as any;
  if (!host) {
    return { synced: false, liveApiConnected: false, discoveredVms: 0, status: 'Unknown', message: 'Host not found.' };
  }

  const ipOrHost = String(host.ip_address || '').trim();
  const port = Number(host.api_port || 8006);
  if (!ipOrHost) {
    return {
      synced: false,
      liveApiConnected: false,
      discoveredVms: 0,
      status: host.status || 'Online',
      message: 'No IP/hostname configured on virtualization host.'
    };
  }

  const safety = await validateOutboundHostSafety(ipOrHost, { allowLoopback: false });
  if (!safety.safe) {
    return {
      synced: false,
      liveApiConnected: false,
      discoveredVms: 0,
      status: 'Unreachable',
      message: safety.reason || 'Blocked by outbound SSRF guard.'
    };
  }

  const decryptedSecret = decryptVaultSecret(host.api_token_encrypted);
  const hostTypeLower = String(host.host_type || '').toLowerCase();

  // 1. Proxmox VE REST API (/api2/json/nodes)
  if (hostTypeLower.includes('proxmox') && decryptedSecret) {
    try {
      const baseUrl = `https://${ipOrHost}:${port}/api2/json`;
      const authHeader = formatProxmoxTokenHeader(host.api_username, decryptedSecret);
      const nodesRes = await requestHypervisorJson(`${baseUrl}/nodes`, {
        headers: { Authorization: authHeader }
      });

      if (nodesRes.status >= 200 && nodesRes.status < 300 && Array.isArray(nodesRes.body?.data)) {
        const nodes = nodesRes.body.data as any[];
        let totalCpuRatio = 0;
        let activeNodes = 0;
        let memUsedBytes = 0;
        let memTotalBytes = 0;
        let diskUsedBytes = 0;
        let diskTotalBytes = 0;
        let discoveredCount = 0;

        for (const node of nodes) {
          const nodeName = String(node.node || '');
          if (!nodeName) continue;
          if (node.status === 'online') activeNodes++;
          totalCpuRatio += Number(node.cpu || 0);
          memUsedBytes += Number(node.mem || 0);
          memTotalBytes += Number(node.maxmem || 0);
          diskUsedBytes += Number(node.disk || 0);
          diskTotalBytes += Number(node.maxdisk || 0);

          for (const kind of ['qemu', 'lxc'] as const) {
            const vmRes = await requestHypervisorJson(`${baseUrl}/nodes/${encodeURIComponent(nodeName)}/${kind}`, {
              headers: { Authorization: authHeader }
            }).catch(() => ({ status: 0, body: null }));

            if (vmRes.status >= 200 && vmRes.status < 300 && Array.isArray(vmRes.body?.data)) {
              for (const vm of vmRes.body.data) {
                const vmid = Number(vm.vmid);
                if (!Number.isFinite(vmid)) continue;
                discoveredCount++;
                const vmRowId = `vm-${host.id}-${vmid}`;
                const statusStr = String(vm.status || '').toLowerCase() === 'running' ? 'Running' : 'Stopped';
                const ramGb = Math.max(1, Math.round(Number(vm.maxmem || 0) / (1024 ** 3)));
                const cpus = Math.max(1, Number(vm.cpus || vm.maxcpu || 2));
                const vmName = String(vm.name || `${kind.toUpperCase()}-${vmid}`);
                const osLabel = kind === 'lxc' ? 'Linux LXC Container' : 'Proxmox QEMU Guest';

                db.prepare(`
                  INSERT INTO virtualization_vms (id, host_id, vmid, name, status, os, cpu, ram_gb, last_snapshot)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT last_snapshot FROM virtualization_vms WHERE id = ?), 'Managed via PVE'))
                  ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    status = excluded.status,
                    cpu = excluded.cpu,
                    ram_gb = excluded.ram_gb
                `).run(vmRowId, host.id, vmid, vmName, statusStr, osLabel, cpus, ramGb, vmRowId);
              }
            }
          }
        }

        const avgCpuPct = nodes.length > 0 ? Number(((totalCpuRatio / nodes.length) * 100).toFixed(1)) : 0;
        const ramUsedGb = Number((memUsedBytes / 1024 ** 3).toFixed(1));
        const ramTotalGb = Math.max(1, Number((memTotalBytes / 1024 ** 3).toFixed(1)));
        const storageTotalTb = Math.max(0.1, Number((diskTotalBytes / 1024 ** 4).toFixed(2)));
        const storageFreeTb = Math.max(0, Number(((diskTotalBytes - diskUsedBytes) / 1024 ** 4).toFixed(2)));
        const hostStatus = activeNodes > 0 ? 'Online' : 'Degraded';

        db.prepare(`
          UPDATE virtualization_hosts
          SET status = ?, cpu_usage_pct = ?, ram_usage_gb = ?, ram_total_gb = ?, storage_free_tb = ?, storage_total_tb = ?
          WHERE id = ?
        `).run(hostStatus, avgCpuPct, ramUsedGb, ramTotalGb, storageFreeTb, storageTotalTb, host.id);

        return {
          synced: true,
          liveApiConnected: true,
          discoveredVms: discoveredCount,
          status: hostStatus,
          message: `Polled Proxmox VE API (${nodes.length} node(s), ${discoveredCount} guests synchronized).`
        };
      }
    } catch (err: any) {
      db.prepare("UPDATE virtualization_hosts SET status = 'Unreachable' WHERE id = ?").run(host.id);
      return {
        synced: false,
        liveApiConnected: false,
        discoveredVms: 0,
        status: 'Unreachable',
        message: `Proxmox VE API connection failed: ${err?.message || 'Unreachable'}`
      };
    }
  }

  // 2. VMware vSphere REST API (/api/vcenter/vm)
  if ((hostTypeLower.includes('vmware') || hostTypeLower.includes('vsphere') || hostTypeLower.includes('esxi')) && decryptedSecret) {
    try {
      const baseUrl = `https://${ipOrHost}:${port || 443}`;
      let sessionToken = decryptedSecret;
      if (host.api_username) {
        const basic = Buffer.from(`${host.api_username}:${decryptedSecret}`, 'utf8').toString('base64');
        const sesRes = await requestHypervisorJson(`${baseUrl}/api/session`, {
          method: 'POST',
          headers: { Authorization: `Basic ${basic}` }
        });
        if (sesRes.status >= 200 && sesRes.status < 300 && typeof sesRes.body === 'string') {
          sessionToken = sesRes.body;
        }
      }
      const vmRes = await requestHypervisorJson(`${baseUrl}/api/vcenter/vm`, {
        headers: { 'vmware-api-session-id': sessionToken }
      });
      if (vmRes.status >= 200 && vmRes.status < 300 && Array.isArray(vmRes.body)) {
        let idx = 100;
        for (const vm of vmRes.body) {
          idx++;
          const vmid = parseInt(String(vm.vm || '').replace(/\D/g, ''), 10) || idx;
          const vmRowId = `vm-${host.id}-${vmid}`;
          const statusStr = String(vm.power_state || '').toUpperCase() === 'POWERED_ON' ? 'Running' : 'Stopped';
          const ramGb = Math.max(1, Math.round(Number(vm.memory_size_MiB || 4096) / 1024));
          const cpus = Math.max(1, Number(vm.cpu_count || 2));
          db.prepare(`
            INSERT INTO virtualization_vms (id, host_id, vmid, name, status, os, cpu, ram_gb, last_snapshot)
            VALUES (?, ?, ?, ?, ?, 'vSphere Guest', ?, ?, 'vCenter Managed')
            ON CONFLICT(id) DO UPDATE SET name = excluded.name, status = excluded.status, cpu = excluded.cpu, ram_gb = excluded.ram_gb
          `).run(vmRowId, host.id, vmid, String(vm.name || `VM-${vmid}`), statusStr, cpus, ramGb);
        }
        db.prepare("UPDATE virtualization_hosts SET status = 'Online' WHERE id = ?").run(host.id);
        return {
          synced: true,
          liveApiConnected: true,
          discoveredVms: vmRes.body.length,
          status: 'Online',
          message: `Polled vSphere REST API (${vmRes.body.length} VMs synchronized).`
        };
      }
    } catch {
      // Fall through to TCP reachability probe
    }
  }

  // 3. Generic TCP Reachability Fallback (Hyper-V WinRM 5985/5986 or unauthenticated Proxmox/ESXi port)
  const reachable = await probeTcpPort(ipOrHost, port);
  const nextStatus = reachable ? 'Online' : 'Unreachable';
  db.prepare('UPDATE virtualization_hosts SET status = ? WHERE id = ?').run(nextStatus, host.id);
  const existingCount = (
    db.prepare('SELECT COUNT(*) as c FROM virtualization_vms WHERE host_id = ?').get(host.id) as { c: number }
  ).c;

  return {
    synced: reachable,
    liveApiConnected: false,
    discoveredVms: existingCount,
    status: nextStatus,
    message: reachable
      ? `TCP port ${port} is reachable on ${ipOrHost} (${decryptedSecret ? 'API credentials did not match REST schema' : 'configure API token for live guest discovery'}).`
      : `Host ${ipOrHost}:${port} did not respond to TCP probe.`
  };
}

export async function dispatchLiveHypervisorVmAction(
  hostId: string,
  vmid: number,
  action: 'start' | 'stop' | 'reboot' | 'snapshot'
): Promise<{ dispatchedLive: boolean; detail: string }> {
  const host = db.prepare('SELECT * FROM virtualization_hosts WHERE id = ?').get(hostId) as any;
  if (!host || !host.ip_address || !host.api_token_encrypted) {
    return { dispatchedLive: false, detail: 'Local state updated (no hypervisor API token configured).' };
  }

  const decryptedSecret = decryptVaultSecret(host.api_token_encrypted);
  if (!decryptedSecret) {
    return { dispatchedLive: false, detail: 'Local state updated (unable to decrypt hypervisor API token).' };
  }

  const safety = await validateOutboundHostSafety(host.ip_address, { allowLoopback: false });
  if (!safety.safe) {
    throw new Error(safety.reason || 'Hypervisor target blocked by SSRF guard.');
  }

  const hostTypeLower = String(host.host_type || '').toLowerCase();
  if (hostTypeLower.includes('proxmox')) {
    const port = Number(host.api_port || 8006);
    const baseUrl = `https://${host.ip_address}:${port}/api2/json`;
    const authHeader = formatProxmoxTokenHeader(host.api_username, decryptedSecret);
    const nodesRes = await requestHypervisorJson(`${baseUrl}/nodes`, {
      headers: { Authorization: authHeader }
    });
    const firstNode = Array.isArray(nodesRes.body?.data) ? nodesRes.body.data[0]?.node : null;
    if (!firstNode) {
      throw new Error('Could not resolve target Proxmox node via /api2/json/nodes.');
    }

    const vmRow = db
      .prepare('SELECT os FROM virtualization_vms WHERE host_id = ? AND vmid = ?')
      .get(hostId, vmid) as { os?: string } | undefined;
    const kind = vmRow?.os?.toLowerCase().includes('lxc') ? 'lxc' : 'qemu';

    if (action === 'snapshot') {
      const snapName = `vitrine_${new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 12)}`;
      const form = new URLSearchParams({ snapname: snapName, description: 'Created by Vitrine RMM' }).toString();
      const snapRes = await requestHypervisorJson(
        `${baseUrl}/nodes/${encodeURIComponent(firstNode)}/${kind}/${vmid}/snapshot`,
        {
          method: 'POST',
          headers: { Authorization: authHeader, 'Content-Type': 'application/x-www-form-urlencoded' },
          body: form
        }
      );
      if (snapRes.status < 200 || snapRes.status >= 300) {
        throw new Error(`Proxmox snapshot API returned HTTP ${snapRes.status}`);
      }
      return { dispatchedLive: true, detail: `Proxmox VE snapshot '${snapName}' created on node '${firstNode}'.` };
    }

    const pveEndpoint = `${baseUrl}/nodes/${encodeURIComponent(firstNode)}/${kind}/${vmid}/status/${action}`;
    const actRes = await requestHypervisorJson(pveEndpoint, {
      method: 'POST',
      headers: { Authorization: authHeader }
    });
    if (actRes.status < 200 || actRes.status >= 300) {
      throw new Error(`Proxmox ${action} API returned HTTP ${actRes.status}`);
    }
    return { dispatchedLive: true, detail: `Dispatched Proxmox VE '${action}' task to ${kind}/${vmid} on '${firstNode}'.` };
  }

  return { dispatchedLive: false, detail: 'Updated VM state in Vitrine catalog.' };
}
