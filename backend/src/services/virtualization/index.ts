import net from 'net';
import { db } from '../../db/index.js';
import { decryptVaultSecret, safeOutboundFetch, validateOutboundHostSafety } from '../vault/index.js';
import { meshBridge } from '../meshcentral/index.js';
import { quotePowerShellLiteral } from '../agent/installerGenerator.js';

interface RawJsonResponse {
  status: number;
  body: any;
}

function formatHostForUrl(ipOrHost: string): string {
  const clean = ipOrHost.trim().replace(/^\[|\]$/g, '');
  return net.isIPv6(clean) ? `[${clean}]` : clean;
}

async function requestHypervisorJson(
  urlStr: string,
  options: {
    method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
    headers?: Record<string, string>;
    body?: string;
    timeoutMs?: number;
    allowSelfSigned?: boolean;
    pinnedFingerprintSha256?: string | null;
  } = {}
): Promise<RawJsonResponse> {
  const res = await safeOutboundFetch(urlStr, {
    method: options.method || 'GET',
    headers: {
      Accept: 'application/json',
      ...(options.headers || {})
    },
    body: options.body,
    timeoutMs: options.timeoutMs || 7000,
    allowInsecureTls: Boolean(options.allowSelfSigned),
    expectedCertSha256: options.pinnedFingerprintSha256 || undefined,
    safety: { allowLoopback: true, allowPrivateLan: true }
  });

  const text = res.body.toString('utf8');
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text.slice(0, 300) };
  }
  return { status: res.status, body: json };
}

function probeTcpPort(host: string, port: number, timeoutMs = 3000): Promise<boolean> {
  return new Promise((resolve) => {
    const cleanHost = host.trim().replace(/^\[|\]$/g, '');
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
    sock.connect(port, cleanHost);
  });
}

function formatProxmoxTokenHeader(apiUsername?: string | null, rawToken?: string): string {
  const token = (rawToken || '').trim();
  if (!token) return '';
  if (token.toLowerCase().startsWith('pveapitoken=')) {
    return token;
  }
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
  const hostTypeLower = String(host.host_type || '').toLowerCase();
  const allowSelfSigned = Boolean(host.allow_self_signed ?? 0);
  const pinnedFp = host.tls_fingerprint_sha256 || null;

  // 0. Microsoft Hyper-V via Linked Windows Agent (`linked_device_id` or online Windows Server in tenant)
  if (hostTypeLower.includes('hyper-v') || hostTypeLower.includes('hyperv')) {
    const linkedId =
      host.linked_device_id ||
      (
        db
          .prepare(
            "SELECT id FROM devices WHERE tenant_id = ? AND os_type = 'windows' AND status = 'online' ORDER BY last_seen DESC LIMIT 1"
          )
          .get(host.tenant_id || '') as { id?: string } | undefined
      )?.id;

    if (linkedId) {
      const ps = `Get-VM | Select-Object @{N='Id';E={$_.VMId.ToString()}}, Name, @{N='StateStr';E={$_.State.ToString()}}, ProcessorCount, @{N='RamGb';E={[math]::Max(1,[math]::Round($_.MemoryAssigned/1GB,0))}} | ConvertTo-Json -Compress`;
      const execRes = await meshBridge.executeCommandOnNode(linkedId, ps, { runAs: 'system', timeoutMs: 9000 });
      if (execRes.live && execRes.exitCode === 0 && execRes.output) {
        try {
          const parsed = JSON.parse(execRes.output);
          const arr = Array.isArray(parsed) ? parsed : [parsed];
          let idx = 200;
          for (const vm of arr) {
            if (!vm?.Name) continue;
            idx++;
            const vmRowId = `vm-${host.id}-${idx}`;
            const statusStr = String(vm.StateStr || '').toLowerCase() === 'running' ? 'Running' : 'Stopped';
            db.prepare(`
              INSERT INTO virtualization_vms (id, host_id, vmid, name, status, os, cpu, ram_gb, last_snapshot, moref_id)
              VALUES (?, ?, ?, ?, ?, 'Hyper-V Guest', ?, ?, 'Hyper-V Checkpoint Ready', ?)
              ON CONFLICT(id) DO UPDATE SET name = excluded.name, status = excluded.status, cpu = excluded.cpu, ram_gb = excluded.ram_gb, moref_id = excluded.moref_id
            `).run(
              vmRowId,
              host.id,
              idx,
              String(vm.Name),
              statusStr,
              Number(vm.ProcessorCount || 2),
              Number(vm.RamGb || 4),
              String(vm.Id || vm.Name)
            );
          }
          db.prepare("UPDATE virtualization_hosts SET status = 'Online', linked_device_id = ? WHERE id = ?").run(
            linkedId,
            host.id
          );
          return {
            synced: true,
            liveApiConnected: true,
            discoveredVms: arr.length,
            status: 'Online',
            message: `Synchronized ${arr.length} Hyper-V guest(s) via live PowerShell agent tunnel.`
          };
        } catch {}
      }
    }
  }

  if (!ipOrHost) {
    return {
      synced: false,
      liveApiConnected: false,
      discoveredVms: 0,
      status: host.status || 'Online',
      message: 'No IP/hostname configured on virtualization host.'
    };
  }

  const bracketedHost = formatHostForUrl(ipOrHost);
  const safety = await validateOutboundHostSafety(`https://${bracketedHost}:${port}`, {
    allowLoopback: true,
    allowPrivateLan: true
  });
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

  // 1. Proxmox VE REST API (/api2/json/nodes)
  if (hostTypeLower.includes('proxmox') && decryptedSecret) {
    try {
      const baseUrl = `https://${bracketedHost}:${port}/api2/json`;
      const authHeader = formatProxmoxTokenHeader(host.api_username, decryptedSecret);
      const nodesRes = await requestHypervisorJson(`${baseUrl}/nodes`, {
        headers: { Authorization: authHeader },
        allowSelfSigned,
        pinnedFingerprintSha256: pinnedFp
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
              headers: { Authorization: authHeader },
              allowSelfSigned,
              pinnedFingerprintSha256: pinnedFp
            }).catch(() => ({ status: 0, body: null }));

            if (vmRes.status >= 200 && vmRes.status < 300 && Array.isArray(vmRes.body?.data)) {
              for (const vm of vmRes.body.data) {
                const vmid = Number(vm.vmid);
                if (!Number.isFinite(vmid)) continue;
                discoveredCount++;
                const vmRowId = `vm-${host.id}-${vmid}`;
                const statusStr = String(vm.status || '').toLowerCase() === 'running' ? 'Running' : 'Stopped';
                const ramGb = Math.max(1, Math.round(Number(vm.maxmem || 0) / 1024 ** 3));
                const cpus = Math.max(1, Number(vm.cpus || vm.maxcpu || 2));
                const vmName = String(vm.name || `${kind.toUpperCase()}-${vmid}`);
                const osLabel = kind === 'lxc' ? 'Linux LXC Container' : 'Proxmox QEMU Guest';

                db.prepare(`
                  INSERT INTO virtualization_vms (id, host_id, vmid, name, status, os, cpu, ram_gb, last_snapshot, node_name)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT last_snapshot FROM virtualization_vms WHERE id = ?), 'Managed via PVE'), ?)
                  ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    status = excluded.status,
                    cpu = excluded.cpu,
                    ram_gb = excluded.ram_gb,
                    node_name = excluded.node_name
                `).run(vmRowId, host.id, vmid, vmName, statusStr, osLabel, cpus, ramGb, vmRowId, nodeName);
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

  // 2. VMware vSphere REST API (/api/vcenter/vm & /api/vcenter/host)
  if ((hostTypeLower.includes('vmware') || hostTypeLower.includes('vsphere') || hostTypeLower.includes('esxi')) && decryptedSecret) {
    try {
      const baseUrl = `https://${bracketedHost}:${port || 443}`;
      let sessionToken = decryptedSecret;
      if (host.api_username) {
        const basic = Buffer.from(`${host.api_username}:${decryptedSecret}`, 'utf8').toString('base64');
        const sesRes = await requestHypervisorJson(`${baseUrl}/api/session`, {
          method: 'POST',
          headers: { Authorization: `Basic ${basic}` },
          allowSelfSigned,
          pinnedFingerprintSha256: pinnedFp
        });
        if (sesRes.status >= 200 && sesRes.status < 300 && typeof sesRes.body === 'string') {
          sessionToken = sesRes.body;
        }
      }
      const vmRes = await requestHypervisorJson(`${baseUrl}/api/vcenter/vm`, {
        headers: { 'vmware-api-session-id': sessionToken },
        allowSelfSigned,
        pinnedFingerprintSha256: pinnedFp
      });
      if (vmRes.status >= 200 && vmRes.status < 300 && Array.isArray(vmRes.body)) {
        let idx = 100;
        for (const vm of vmRes.body) {
          idx++;
          const moref = String(vm.vm || `vm-${idx}`);
          const vmid = parseInt(moref.replace(/\D/g, ''), 10) || idx;
          const vmRowId = `vm-${host.id}-${vmid}`;
          const statusStr = String(vm.power_state || '').toUpperCase() === 'POWERED_ON' ? 'Running' : 'Stopped';
          const ramGb = Math.max(1, Math.round(Number(vm.memory_size_MiB || 4096) / 1024));
          const cpus = Math.max(1, Number(vm.cpu_count || 2));
          db.prepare(`
            INSERT INTO virtualization_vms (id, host_id, vmid, name, status, os, cpu, ram_gb, last_snapshot, moref_id)
            VALUES (?, ?, ?, ?, ?, 'vSphere Guest', ?, ?, 'vCenter Managed', ?)
            ON CONFLICT(id) DO UPDATE SET name = excluded.name, status = excluded.status, cpu = excluded.cpu, ram_gb = excluded.ram_gb, moref_id = excluded.moref_id
          `).run(vmRowId, host.id, vmid, String(vm.name || `VM-${vmid}`), statusStr, cpus, ramGb, moref);
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
    } catch {}
  }

  // 3. Generic TCP Reachability Fallback
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
  if (!host) {
    return { dispatchedLive: false, detail: 'Hypervisor host not found.' };
  }

  const hostTypeLower = String(host.host_type || '').toLowerCase();
  const vmRow = db
    .prepare('SELECT * FROM virtualization_vms WHERE host_id = ? AND vmid = ?')
    .get(hostId, vmid) as any;

  // 1. Hyper-V Live PowerShell Action via Linked Windows Agent
  if ((hostTypeLower.includes('hyper-v') || hostTypeLower.includes('hyperv')) && host.linked_device_id && vmRow?.name) {
    const vmLit = quotePowerShellLiteral(vmRow.name);
    const hvCmd =
      action === 'start'
        ? `Start-VM -Name ${vmLit}`
        : action === 'stop'
          ? `Stop-VM -Name ${vmLit} -Force`
          : action === 'reboot'
            ? `Restart-VM -Name ${vmLit} -Force`
            : `Checkpoint-VM -Name ${vmLit} -SnapshotName ('Vitrine-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))`;
    const res = await meshBridge.executeCommandOnNode(host.linked_device_id, hvCmd, {
      runAs: 'system',
      timeoutMs: 12000
    });
    if (res.live && res.exitCode === 0) {
      return { dispatchedLive: true, detail: `Executed Hyper-V '${action}' on '${vmRow.name}' via Windows agent.` };
    }
    throw new Error(`Hyper-V command failed: ${res.output}`);
  }

  if (!host.ip_address || !host.api_token_encrypted) {
    return { dispatchedLive: false, detail: 'Local state updated (no hypervisor API token configured).' };
  }

  const decryptedSecret = decryptVaultSecret(host.api_token_encrypted);
  if (!decryptedSecret) {
    return { dispatchedLive: false, detail: 'Local state updated (unable to decrypt hypervisor API token).' };
  }

  const bracketedHost = formatHostForUrl(host.ip_address);
  const port = Number(host.api_port || 8006);
  const allowSelfSigned = Boolean(host.allow_self_signed ?? 0);
  const pinnedFp = host.tls_fingerprint_sha256 || null;

  const safety = await validateOutboundHostSafety(`https://${bracketedHost}:${port}`, {
    allowLoopback: true,
    allowPrivateLan: true
  });
  if (!safety.safe) {
    throw new Error(safety.reason || 'Hypervisor target blocked by SSRF guard.');
  }

  // 2. Proxmox VE Multi-Node-Aware VM Action (uses stored vmRow.node_name!)
  if (hostTypeLower.includes('proxmox')) {
    const baseUrl = `https://${bracketedHost}:${port}/api2/json`;
    const authHeader = formatProxmoxTokenHeader(host.api_username, decryptedSecret);
    let targetNode: string | null = vmRow?.node_name || null;

    if (!targetNode) {
      const nodesRes = await requestHypervisorJson(`${baseUrl}/nodes`, {
        headers: { Authorization: authHeader },
        allowSelfSigned,
        pinnedFingerprintSha256: pinnedFp
      });
      targetNode = Array.isArray(nodesRes.body?.data) ? nodesRes.body.data[0]?.node : null;
    }

    if (!targetNode) {
      throw new Error('Could not resolve target Proxmox node via /api2/json/nodes.');
    }

    const kind = vmRow?.os?.toLowerCase().includes('lxc') ? 'lxc' : 'qemu';

    if (action === 'snapshot') {
      const snapName = `vitrine_${new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 12)}`;
      const form = new URLSearchParams({ snapname: snapName, description: 'Created by Vitrine RMM' }).toString();
      const snapRes = await requestHypervisorJson(
        `${baseUrl}/nodes/${encodeURIComponent(targetNode)}/${kind}/${vmid}/snapshot`,
        {
          method: 'POST',
          headers: { Authorization: authHeader, 'Content-Type': 'application/x-www-form-urlencoded' },
          body: form,
          allowSelfSigned,
          pinnedFingerprintSha256: pinnedFp
        }
      );
      if (snapRes.status < 200 || snapRes.status >= 300) {
        throw new Error(`Proxmox snapshot API returned HTTP ${snapRes.status}`);
      }
      return { dispatchedLive: true, detail: `Proxmox VE snapshot '${snapName}' created on node '${targetNode}'.` };
    }

    const pveEndpoint = `${baseUrl}/nodes/${encodeURIComponent(targetNode)}/${kind}/${vmid}/status/${action}`;
    const actRes = await requestHypervisorJson(pveEndpoint, {
      method: 'POST',
      headers: { Authorization: authHeader },
      allowSelfSigned,
      pinnedFingerprintSha256: pinnedFp
    });
    if (actRes.status < 200 || actRes.status >= 300) {
      throw new Error(`Proxmox ${action} API returned HTTP ${actRes.status}`);
    }
    return { dispatchedLive: true, detail: `Dispatched Proxmox VE '${action}' task to ${kind}/${vmid} on '${targetNode}'.` };
  }

  // 3. VMware vSphere Live Power Actions (/api/vcenter/vm/{moref}/power)
  if (hostTypeLower.includes('vmware') || hostTypeLower.includes('vsphere') || hostTypeLower.includes('esxi')) {
    const baseUrl = `https://${bracketedHost}:${Number(host.api_port || 443)}`;
    let sessionToken = decryptedSecret;
    if (host.api_username) {
      const basic = Buffer.from(`${host.api_username}:${decryptedSecret}`, 'utf8').toString('base64');
      const sesRes = await requestHypervisorJson(`${baseUrl}/api/session`, {
        method: 'POST',
        headers: { Authorization: `Basic ${basic}` },
        allowSelfSigned,
        pinnedFingerprintSha256: pinnedFp
      });
      if (sesRes.status >= 200 && sesRes.status < 300 && typeof sesRes.body === 'string') {
        sessionToken = sesRes.body;
      }
    }

    const moref = vmRow?.moref_id || `vm-${vmid}`;
    if (action === 'snapshot') {
      return { dispatchedLive: false, detail: 'Recorded snapshot marker (vSphere REST vCenter VM snapshot requires SOAP/PowerCLI).' };
    }
    const powerOp = action === 'reboot' ? 'reset' : action;
    const vsRes = await requestHypervisorJson(
      `${baseUrl}/api/vcenter/vm/${encodeURIComponent(moref)}/power?action=${powerOp}`,
      {
        method: 'POST',
        headers: { 'vmware-api-session-id': sessionToken },
        allowSelfSigned,
        pinnedFingerprintSha256: pinnedFp
      }
    );
    if (vsRes.status < 200 || vsRes.status >= 300) {
      throw new Error(`vSphere power API returned HTTP ${vsRes.status}`);
    }
    return { dispatchedLive: true, detail: `Dispatched vSphere '${powerOp}' on VM '${moref}'.` };
  }

  return { dispatchedLive: false, detail: 'Updated VM state in Vitrine catalog.' };
}
