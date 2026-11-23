export interface DeviceRoleSignals {
  osType?: string | null;
  osVersion?: string | null;
  manufacturer?: string | null;
  model?: string | null;
  motherboardVendor?: string | null;
  motherboardName?: string | null;
  biosVendor?: string | null;
  biosVersion?: string | null;
  chassisType?: number | null;
  hasBattery?: boolean | null;
  isVirtualMachine?: boolean | null;
  hypervisorVendor?: string | null;
  osProductType?: string | null;
  isDomainController?: boolean | null;
  isHypervisorHost?: boolean | null;
  isServerOs?: boolean | null;
}

const SMBIOS_CHASSIS_LABELS: Record<number, string> = {
  1: 'Other',
  2: 'Unknown',
  3: 'Desktop',
  4: 'Low Profile Desktop',
  5: 'Pizza Box',
  6: 'Mini Tower',
  7: 'Tower',
  8: 'Portable',
  9: 'Laptop',
  10: 'Notebook',
  11: 'Hand Held',
  12: 'Docking Station',
  13: 'All-in-One',
  14: 'Sub Notebook',
  15: 'Space-saving',
  16: 'Lunch Box',
  17: 'Main Server Chassis',
  18: 'Expansion Chassis',
  19: 'SubChassis',
  20: 'Bus Expansion Chassis',
  21: 'Peripheral Chassis',
  22: 'RAID Chassis',
  23: 'Rack Mount Chassis',
  24: 'Sealed-case PC',
  25: 'Multi-system Chassis',
  28: 'Blade',
  29: 'Blade Enclosure',
  30: 'Tablet',
  31: 'Convertible',
  32: 'Detachable',
  33: 'IoT Gateway',
  34: 'Embedded PC',
  35: 'Mini PC',
  36: 'Stick PC'
};

const MOBILE_CHASSIS_TYPES = new Set([8, 9, 10, 11, 14, 30, 31, 32]);
const SERVER_CHASSIS_TYPES = new Set([17, 23, 25, 28, 29]);
const DESKTOP_CHASSIS_TYPES = new Set([3, 4, 5, 6, 7, 13, 15, 16, 24, 34, 35, 36]);

const AUTO_DETECTABLE_ROLES = new Set([
  '',
  'auto',
  'auto-detect',
  'workstation',
  'desktop',
  'laptop',
  'server',
  'virtual machine',
  'virtual server',
  'hypervisor',
  'domain controller',
  'unassigned'
]);

export function getSmbiosChassisLabel(chassisType?: number | null): string {
  const code = Number(chassisType || 0);
  return SMBIOS_CHASSIS_LABELS[code] || '';
}

export function isAutoRolePlaceholder(role?: string | null): boolean {
  const norm = String(role || '').trim().toLowerCase();
  return AUTO_DETECTABLE_ROLES.has(norm);
}

export function extractSignalsFromHardwareDetails(
  hwRaw: unknown,
  device?: {
    os_type?: string | null;
    os_version?: string | null;
    manufacturer?: string | null;
    model?: string | null;
    bios_version?: string | null;
  } | null
): DeviceRoleSignals {
  let hw: Record<string, any> = {};
  if (typeof hwRaw === 'string' && hwRaw.trim()) {
    try {
      const parsed = JSON.parse(hwRaw);
      if (parsed && typeof parsed === 'object') hw = parsed;
    } catch {
      hw = {};
    }
  } else if (hwRaw && typeof hwRaw === 'object') {
    hw = hwRaw as Record<string, any>;
  }

  const sys = (hw.system && typeof hw.system === 'object' ? hw.system : {}) as Record<string, any>;
  const osObj = (hw.os && typeof hw.os === 'object' ? hw.os : {}) as Record<string, any>;

  const parseOptBool = (v: unknown): boolean | null => {
    if (typeof v === 'boolean') return v;
    if (v === 'true' || v === 1) return true;
    if (v === 'false' || v === 0) return false;
    return null;
  };

  const rawChassis = sys.chassisType != null ? Number(sys.chassisType) : NaN;

  return {
    osType: (osObj.osType as string) || device?.os_type || null,
    osVersion: (osObj.osVersion as string) || device?.os_version || null,
    manufacturer: (sys.manufacturer as string) || device?.manufacturer || null,
    model: (sys.model as string) || device?.model || null,
    motherboardVendor: (sys.motherboardVendor as string) || null,
    motherboardName: (sys.motherboardName as string) || null,
    biosVendor: (sys.biosVendor as string) || null,
    biosVersion: (sys.biosVersion as string) || device?.bios_version || null,
    chassisType: Number.isFinite(rawChassis) && rawChassis > 0 ? Math.floor(rawChassis) : null,
    hasBattery: parseOptBool(sys.hasBattery),
    isVirtualMachine: parseOptBool(sys.isVirtualMachine),
    hypervisorVendor: (sys.hypervisorVendor as string) || null,
    osProductType: (sys.osProductType as string) || null,
    isDomainController: parseOptBool(sys.isDomainController),
    isHypervisorHost: parseOptBool(sys.isHypervisorHost),
    isServerOs: parseOptBool(sys.isServerOs)
  };
}

export function detectVirtualMachine(signals: DeviceRoleSignals): boolean {
  const mfg = String(signals.manufacturer || '').trim().toLowerCase();
  const mdl = String(signals.model || '').trim().toLowerCase();
  const mb = `${signals.motherboardVendor || ''} ${signals.motherboardName || ''}`.trim().toLowerCase();
  const bios = `${signals.biosVendor || ''} ${signals.biosVersion || ''}`.trim().toLowerCase();
  const hv = String(signals.hypervisorVendor || '').trim().toLowerCase();

  // Explicit non-Hyper-V hypervisor CPUID vendors strongly indicate guest VM execution
  if (
    hv.includes('kvm') ||
    hv.includes('vmware') ||
    hv.includes('vbox') ||
    hv.includes('xenvmm') ||
    hv.includes('tcgtcg') ||
    hv.includes('prl hyperv') ||
    hv.includes('bhyve') ||
    hv.includes('qnx')
  ) {
    return true;
  }

  // DMI / SMBIOS guest VM signatures
  const combinedDmi = `${mfg} | ${mdl} | ${mb} | ${bios}`;
  const dmiVm =
    mfg.includes('qemu') ||
    mdl.includes('standard pc (q35') ||
    mdl.includes('standard pc (i440fx') ||
    combinedDmi.includes('vmware') ||
    combinedDmi.includes('virtualbox') ||
    combinedDmi.includes('innotek') ||
    (mfg.includes('oracle') && (mdl.includes('virtualbox') || bios.includes('virtualbox'))) ||
    combinedDmi.includes('virtual machine') ||
    combinedDmi.includes('virtualmac') ||
    combinedDmi.includes('parallels') ||
    combinedDmi.includes('bochs') ||
    combinedDmi.includes('seabios') ||
    combinedDmi.includes('ovmf') ||
    combinedDmi.includes('kubevirt') ||
    combinedDmi.includes('proxmox') ||
    combinedDmi.includes('ovirt') ||
    combinedDmi.includes('openstack') ||
    combinedDmi.includes('amazon ec2') ||
    combinedDmi.includes('google compute') ||
    combinedDmi.includes('digitalocean') ||
    combinedDmi.includes('vultr') ||
    combinedDmi.includes('bhyve') ||
    combinedDmi.includes('nutanix') ||
    (combinedDmi.includes('xen') && (combinedDmi.includes('hvm') || mfg.includes('xen'))) ||
    (mfg.includes('red hat') && mdl.includes('kvm'));

  if (dmiVm) return true;

  // Notice: Microsoft VBS / Core Isolation / WSL2 on bare-metal physical PCs also exposes CPUID "Microsoft Hv".
  // Only classify a "Microsoft Hv" host as a VM if native probing explicitly marked isVirtualMachine WITHOUT
  // contradictory bare-metal OEM hardware, or if DMI matched "Virtual Machine" above.
  if (hv.includes('microsoft hv')) {
    return signals.isVirtualMachine === true && mfg.includes('microsoft') && !mdl.includes('surface');
  }

  return signals.isVirtualMachine === true;
}

function hasDistinctHardwareEvidence(signals: DeviceRoleSignals): boolean {
  return Boolean(
    (signals.chassisType && signals.chassisType > 2) ||
      signals.hasBattery != null ||
      signals.isVirtualMachine != null ||
      signals.isDomainController === true ||
      signals.isHypervisorHost === true ||
      signals.isServerOs === true ||
      String(signals.osProductType || '').trim() !== '' ||
      String(signals.hypervisorVendor || '').trim() !== '' ||
      String(signals.manufacturer || '').trim() !== '' ||
      String(signals.model || '').trim() !== '' ||
      String(signals.osVersion || '').trim() !== ''
  );
}

export function inferDeviceRole(signals: DeviceRoleSignals): string | null {
  if (!hasDistinctHardwareEvidence(signals)) {
    return null;
  }

  const osType = String(signals.osType || '').trim().toLowerCase();
  const osVer = String(signals.osVersion || '').trim().toLowerCase();
  const prodType = String(signals.osProductType || '').trim().toLowerCase();
  const chassis = Number(signals.chassisType || 0);
  const mfg = String(signals.manufacturer || '').trim().toLowerCase();
  const mdl = String(signals.model || '').trim().toLowerCase();
  const combinedMdl = `${mfg} ${mdl}`.trim();

  const isVm = detectVirtualMachine(signals);
  const isDc = Boolean(signals.isDomainController || prodType === 'domain_controller');
  if (isDc) {
    return 'Domain Controller';
  }

  const isServer = Boolean(
    signals.isServerOs ||
      prodType === 'server' ||
      SERVER_CHASSIS_TYPES.has(chassis) ||
      osVer.includes('windows server') ||
      osVer.includes('ubuntu server') ||
      osVer.includes('red hat enterprise linux server') ||
      osVer.includes('esxi') ||
      osVer.includes('proxmox') ||
      osVer.includes('truenas') ||
      mdl.startsWith('xserve')
  );

  const isHypervisor =
    !isVm &&
    Boolean(
      signals.isHypervisorHost ||
        osVer.includes('proxmox') ||
        osVer.includes('esxi') ||
        osVer.includes('xcp-ng') ||
        osVer.includes('xenserver') ||
        osVer.includes('hyper-v server')
    );
  if (isHypervisor) {
    return 'Hypervisor';
  }

  if (isVm) {
    return isServer ? 'Virtual Server' : 'Virtual Machine';
  }

  if (isServer) {
    return 'Server';
  }

  // Physical macOS models
  if (osType === 'macos' || mfg.includes('apple')) {
    if (mdl.includes('macbook')) return 'Laptop';
    if (mdl.includes('xserve')) return 'Server';
    if (mdl.includes('imac') || mdl.includes('macmini') || mdl.includes('mac mini') || mdl.includes('macstudio') || mdl.includes('mac studio') || mdl.includes('macpro') || mdl.includes('mac pro')) {
      return 'Desktop';
    }
  }

  // Mobile SMBIOS enclosure (Notebook/Laptop/Tablet/Convertible/Detachable/Portable)
  if (MOBILE_CHASSIS_TYPES.has(chassis)) {
    return 'Laptop';
  }

  // Desktop/Tower/AIO/Mini-PC SMBIOS enclosure (ignores USB UPS battery false positives)
  if (DESKTOP_CHASSIS_TYPES.has(chassis)) {
    return 'Desktop';
  }

  // Explicit desktop model guard when chassis is unknown, then battery check
  const knownDesktopModel =
    /\b(optiplex|thinkcentre|thinkstation|prodesk|elitedesk|precision tower|workstation|mac mini|mac studio|mac pro|imac|nuc)\b/.test(
      combinedMdl
    );
  if (knownDesktopModel) {
    return 'Desktop';
  }

  if (signals.hasBattery === true) {
    return 'Laptop';
  }

  const knownLaptopModel =
    /\b(macbook|thinkpad|latitude|elitebook|probook|zbook|inspiron 1\d|vostro 1\d|ideapad|yoga|legion|spectre|envy|pavilion|surface laptop|surface book|surface pro|zenbook|vivobook|toughbook|lg gram|razer blade|chromebook)\b/.test(
      combinedMdl
    );
  if (knownLaptopModel) {
    return 'Laptop';
  }

  if (signals.hasBattery === false && (mfg || mdl || prodType === 'workstation')) {
    return 'Desktop';
  }

  if (mfg || mdl) {
    return 'Desktop';
  }

  return null;
}

export function shouldAutoUpdateDeviceRole(
  currentRole: string | null | undefined,
  deviceRoleManual: number | boolean | null | undefined,
  inferredRole: string | null | undefined
): boolean {
  if (!inferredRole) return false;
  if (Boolean(deviceRoleManual)) return false;
  const cur = String(currentRole || '').trim();
  if (cur.toLowerCase() === 'quicksupport') return false;
  if (!isAutoRolePlaceholder(cur)) return false;
  return cur !== inferredRole;
}

