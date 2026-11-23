import { Device } from '../types/index.js';

const NON_INTEL_CPU_RE = /\b(amd|ryzen|epyc|threadripper|athlon|apple|arm|aarch64|qualcomm|snapdragon)\b/i;

export function matchesDeviceSearch(
  device: Device,
  rawQuery: string,
  extra?: { tenantName?: string | null; siteName?: string | null }
): boolean {
  const q = rawQuery.trim().toLowerCase();
  if (!q) return true;

  const fields: Array<string | null | undefined> = [
    device.hostname,
    device.ip_address,
    device.mac_address,
    device.serial_number,
    device.manufacturer,
    device.model,
    device.cpu_model,
    device.os_version,
    device.os_build,
    device.device_role,
    device.logged_in_user,
    device.bios_version,
    extra?.tenantName,
    extra?.siteName,
    ...(Array.isArray((device as any).tags)
      ? (device as any).tags
      : typeof (device as any).tags === 'string'
        ? [(device as any).tags]
        : [])
  ];

  return fields.some((val) => typeof val === 'string' && val.toLowerCase().includes(q));
}

export function isIntelAmtEligible(device: Partial<Device> | null | undefined): boolean {
  if (!device) return false;
  if (device.os_type === 'macos') return false;
  const cpu = String(device.cpu_model || '');
  if (cpu && NON_INTEL_CPU_RE.test(cpu)) return false;
  return Boolean(device.amt_supported || device.intel_amt_enabled || device.amt_provisioned);
}

export function isTemporaryOrNonServiceAgent(device: Partial<Device> | null | undefined): boolean {
  if (!device) return false;
  if ((device as any).quicksupport_session) return true;
  const mode = device.agent_privilege_mode || device.agent_privilege_level;
  return mode === 'standard_user' || mode === 'elevated_admin';
}
