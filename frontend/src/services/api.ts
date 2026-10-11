import { Device, Tenant, Policy, Patch, ScriptItem, SelfHealingMonitor, Settings, ProcessItem, ServiceItem } from '../types/index.js';

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

export async function fetchLapsPassword(id: string, reveal: boolean): Promise<any> {
  const res = await fetch(`${API_BASE}/devices/${id}/laps?reveal=${reveal}`);
  return res.json();
}

export async function rotateLapsPassword(id: string): Promise<any> {
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

export async function fetchRegistry(deviceId: string, path?: string): Promise<any> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/registry?path=${encodeURIComponent(path || '')}`);
  return res.json();
}

export async function fetchScheduledTasks(deviceId: string): Promise<any[]> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/tasks`);
  return res.json();
}

export async function fetchFiles(deviceId: string, path?: string): Promise<any[]> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/files?path=${encodeURIComponent(path || '')}`);
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

export async function fetchScripts(): Promise<ScriptItem[]> {
  const res = await fetch(`${API_BASE}/scripts`);
  return res.json();
}

export async function runScript(scriptId: string, deviceIds: string[]): Promise<any> {
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

export async function fetchTopology(): Promise<any> {
  const res = await fetch(`${API_BASE}/discovery/topology`);
  return res.json();
}

export async function fetchVirtualization(): Promise<any[]> {
  const res = await fetch(`${API_BASE}/virtualization/hosts`);
  return res.json();
}

export async function fetchPsaTickets(): Promise<any[]> {
  const res = await fetch(`${API_BASE}/psa/tickets`);
  return res.json();
}

export async function testSmtp(data: any): Promise<any> {
  const res = await fetch(`${API_BASE}/smtp/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json();
}

export async function fetchQbrReport(): Promise<any> {
  const res = await fetch(`${API_BASE}/reports/qbr`);
  return res.json();
}
