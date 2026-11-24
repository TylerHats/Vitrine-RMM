import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  Monitor,
  Laptop,
  Server,
  EyeOff,
  Terminal,
  KeyRound,
  ShieldAlert,
  ShieldCheck,
  Cpu,
  Plus,
  Download,
  RefreshCw,
  Trash2,
  X,
  Archive,
  Zap,
  FileSpreadsheet,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  SlidersHorizontal,
  Search,
  BookmarkPlus,
  RotateCcw
} from 'lucide-react';
import {
  Device,
  Tenant,
  SmartGroup,
  SmartGroupRule,
  BreakGlassRecoveryEntry,
  AuthUser,
  DeviceFilterRule,
  DeviceFilterOperator,
  DeviceFilterOptions,
  DeviceSortKey,
  DevicesPresetFilter
} from '../types/index.js';
import {
  fetchSmartGroups,
  createSmartGroup,
  deleteSmartGroup,
  scanPatches,
  forceArchiveDevice,
  simulateDeviceCheckin,
  purgeArchivedDevice,
  exportBreakGlassSheet,
  seedDemoLabData,
  deleteTenant,
  offboardTenant,
  queryDevices,
  fetchDeviceFilterOptions
} from '../services/api.js';
import { MfaChallengeModal } from '../components/MfaChallengeModal.js';
import { isSuperAdmin, canMutateFleet } from '../utils/permissions.js';
import { matchesDeviceSearch } from '../utils/deviceHelpers.js';

function sanitizeCsvCell(val: unknown): string {
  const raw = String(val ?? '');
  const safe = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
  return `"${safe.replace(/"/g, '""')}"`;
}

type FieldKind = 'text' | 'number' | 'software' | 'enum' | 'boolean';

interface FilterFieldDef {
  field: string;
  label: string;
  category: 'User & Network' | 'Software & Patches' | 'Hardware & OS' | 'Security & Compliance' | 'Custom Fields';
  kind: FieldKind;
  placeholder?: string;
  enumOptions?: Array<{ value: string; label: string }>;
}

const BUILTIN_FILTER_FIELDS: FilterFieldDef[] = [
  // User & Network
  { field: 'logged_in_user', label: 'Last Logged-On User', category: 'User & Network', kind: 'text', placeholder: 'e.g. jdoe' },
  { field: 'ip_address', label: 'Private IP Address', category: 'User & Network', kind: 'text', placeholder: 'e.g. 192.168.1.' },
  { field: 'public_ip', label: 'Public IP Address', category: 'User & Network', kind: 'text', placeholder: 'e.g. 203.0.113.' },
  { field: 'mac_address', label: 'MAC Address', category: 'User & Network', kind: 'text', placeholder: 'e.g. 00:1A:2B' },
  {
    field: 'agent_transport',
    label: 'Agent Transport',
    category: 'User & Network',
    kind: 'enum',
    enumOptions: [
      { value: 'wss', label: 'WSS Real-Time' },
      { value: 'http', label: 'HTTP Polling' }
    ]
  },

  // Software & Patches
  { field: 'installed_software', label: 'Installed Programs', category: 'Software & Patches', kind: 'software', placeholder: 'e.g. Chrome, 7-Zip, Office' },
  { field: 'pending_patch_count', label: 'Pending Patches Count', category: 'Software & Patches', kind: 'number', placeholder: 'e.g. 3' },

  // Hardware & OS
  {
    field: 'os_type',
    label: 'OS Platform',
    category: 'Hardware & OS',
    kind: 'enum',
    enumOptions: [
      { value: 'windows', label: 'Windows' },
      { value: 'linux', label: 'Linux' },
      { value: 'macos', label: 'macOS' }
    ]
  },
  { field: 'os_version', label: 'OS Version', category: 'Hardware & OS', kind: 'text', placeholder: 'e.g. Windows 11, Ubuntu 24.04' },
  { field: 'os_build', label: 'OS Build / Kernel', category: 'Hardware & OS', kind: 'text', placeholder: 'e.g. 22631, 6.8.' },
  { field: 'manufacturer', label: 'Manufacturer', category: 'Hardware & OS', kind: 'text', placeholder: 'e.g. Dell, Lenovo, HP' },
  { field: 'model', label: 'Hardware Model', category: 'Hardware & OS', kind: 'text', placeholder: 'e.g. OptiPlex, ThinkPad' },
  { field: 'serial_number', label: 'Serial Number', category: 'Hardware & OS', kind: 'text', placeholder: 'Serial / Service Tag' },
  { field: 'cpu_model', label: 'CPU Model', category: 'Hardware & OS', kind: 'text', placeholder: 'e.g. Ryzen, Xeon, Core i7' },
  { field: 'cpu_usage', label: 'CPU Usage (%)', category: 'Hardware & OS', kind: 'number', placeholder: 'e.g. 80' },
  { field: 'ram_total_gb', label: 'Total RAM (GB)', category: 'Hardware & OS', kind: 'number', placeholder: 'e.g. 16' },
  { field: 'disk_free_gb', label: 'Free Disk (GB)', category: 'Hardware & OS', kind: 'number', placeholder: 'e.g. 25' },
  {
    field: 'smart_status',
    label: 'SMART Disk Health',
    category: 'Hardware & OS',
    kind: 'enum',
    enumOptions: [
      { value: 'Healthy', label: 'Healthy' },
      { value: 'Warning', label: 'Warning' },
      { value: 'Failing', label: 'Failing' }
    ]
  },

  // Security & Compliance
  { field: 'bitlocker_status', label: 'Disk Encryption Status', category: 'Security & Compliance', kind: 'text', placeholder: 'e.g. Encrypted, LUKS, Unencrypted' },
  { field: 'edr_status', label: 'EDR / AV Status', category: 'Security & Compliance', kind: 'text', placeholder: 'e.g. Active, Healthy, Unmonitored' },
  { field: 'edr_name', label: 'EDR / AV Product', category: 'Security & Compliance', kind: 'text', placeholder: 'e.g. Defender, SentinelOne' },
  {
    field: 'pending_reboot',
    label: 'Pending Reboot',
    category: 'Security & Compliance',
    kind: 'boolean',
    enumOptions: [
      { value: '1', label: 'Yes (Reboot Pending)' },
      { value: '0', label: 'No' }
    ]
  },
  {
    field: 'maintenance_active',
    label: 'Maintenance Window Active',
    category: 'Security & Compliance',
    kind: 'boolean',
    enumOptions: [
      { value: '1', label: 'In Maintenance' },
      { value: '0', label: 'Not in Maintenance' }
    ]
  },
  { field: 'tags', label: 'Device Tags', category: 'Security & Compliance', kind: 'text', placeholder: 'Tag keyword' }
];

const OPERATOR_LABELS: Record<DeviceFilterOperator, string> = {
  contains: 'contains',
  not_contains: 'does not contain',
  is: 'is',
  is_not: 'is not',
  starts_with: 'starts with',
  ends_with: 'ends with',
  gt: '>',
  gte: '>=',
  lt: '<',
  lte: '<=',
  is_empty: 'is empty',
  is_not_empty: 'is not empty'
};

function getOperatorsForKind(kind: FieldKind): DeviceFilterOperator[] {
  if (kind === 'number') return ['gt', 'gte', 'lt', 'lte', 'is', 'is_not'];
  if (kind === 'software') return ['contains', 'not_contains', 'is', 'is_not', 'starts_with', 'is_empty', 'is_not_empty'];
  if (kind === 'enum' || kind === 'boolean') return ['is', 'is_not'];
  return ['contains', 'not_contains', 'is', 'is_not', 'starts_with', 'ends_with', 'is_empty', 'is_not_empty'];
}

function defaultOperatorForKind(kind: FieldKind): DeviceFilterOperator {
  if (kind === 'number') return 'gt';
  if (kind === 'enum' || kind === 'boolean') return 'is';
  return 'contains';
}

function ipToSortableTuple(ip: string | null | undefined): string {
  const clean = String(ip || '').trim();
  const parts = clean.split('.');
  if (parts.length === 4 && parts.every((p) => /^\d+$/.test(p))) {
    return parts.map((p) => p.padStart(3, '0')).join('.');
  }
  return clean.toLowerCase();
}

function getDeviceStatusRank(d: Device): number {
  if (d.lifecycle_state === 'archived') return 5;
  if (d.lifecycle_state === 'pending_offboard') return 4;
  if (d.quarantined) return 3;
  if (d.pending_reboot) return 2;
  if (d.status === 'online') return 0;
  return 1;
}

function sortDeviceList(list: Device[], sortBy: DeviceSortKey, sortDir: 'asc' | 'desc'): Device[] {
  const mul = sortDir === 'desc' ? -1 : 1;
  return [...list].sort((a, b) => {
    let cmp = 0;
    switch (sortBy) {
      case 'status':
        cmp = getDeviceStatusRank(a) - getDeviceStatusRank(b);
        if (cmp === 0) cmp = String(a.status || '').localeCompare(String(b.status || ''));
        break;
      case 'hostname':
        cmp = String(a.hostname || '').localeCompare(String(b.hostname || ''), undefined, { numeric: true, sensitivity: 'base' });
        break;
      case 'device_role':
        cmp = String(a.device_role || '').localeCompare(String(b.device_role || ''), undefined, { sensitivity: 'base' });
        break;
      case 'tenant_name':
        cmp = String(a.tenant_name || 'Unassigned').localeCompare(String(b.tenant_name || 'Unassigned'), undefined, { sensitivity: 'base' });
        if (cmp === 0) {
          cmp = String(a.site_name || 'Default Site').localeCompare(String(b.site_name || 'Default Site'), undefined, { sensitivity: 'base' });
        }
        break;
      case 'site_name':
        cmp = String(a.site_name || 'Default Site').localeCompare(String(b.site_name || 'Default Site'), undefined, { sensitivity: 'base' });
        break;
      case 'logged_in_user':
        cmp = String(a.logged_in_user || '').localeCompare(String(b.logged_in_user || ''), undefined, { sensitivity: 'base' });
        break;
      case 'ip_address':
        cmp = ipToSortableTuple(a.ip_address).localeCompare(ipToSortableTuple(b.ip_address));
        break;
      case 'public_ip':
        cmp = ipToSortableTuple(a.public_ip).localeCompare(ipToSortableTuple(b.public_ip));
        break;
      case 'os_version':
        cmp = String(a.os_version || '').localeCompare(String(b.os_version || ''), undefined, { numeric: true, sensitivity: 'base' });
        break;
      case 'cpu_usage':
        cmp = Number(a.cpu_usage ?? 0) - Number(b.cpu_usage ?? 0);
        break;
      case 'ram_used_gb':
        cmp = Number(a.ram_used_gb ?? 0) - Number(b.ram_used_gb ?? 0);
        break;
      case 'edr_status':
        cmp = String(a.edr_status || '').localeCompare(String(b.edr_status || ''), undefined, { sensitivity: 'base' });
        break;
      case 'last_seen':
        cmp =
          (a.last_seen ? new Date(String(a.last_seen).replace(' ', 'T')).getTime() || 0 : 0) -
          (b.last_seen ? new Date(String(b.last_seen).replace(' ', 'T')).getTime() || 0 : 0);
        break;
    }
    if (cmp !== 0) return cmp * mul;
    return String(a.hostname || '').localeCompare(String(b.hostname || ''), undefined, { numeric: true, sensitivity: 'base' });
  });
}

function evalLocalScalarRule(actualRaw: unknown, op: DeviceFilterOperator, targetRaw: string): boolean {
  const actualStr = String(actualRaw ?? '').trim();
  const actualLower = actualStr.toLowerCase();
  const targetStr = String(targetRaw ?? '').trim();
  const targetLower = targetStr.toLowerCase();
  const numActual = Number(actualRaw);
  const numTarget = Number(targetRaw);

  switch (op) {
    case 'is_empty':
      return actualStr === '';
    case 'is_not_empty':
      return actualStr !== '';
    case 'is':
      return actualLower === targetLower;
    case 'is_not':
      return actualLower !== targetLower;
    case 'contains':
      return actualLower.includes(targetLower);
    case 'not_contains':
      return !actualLower.includes(targetLower);
    case 'starts_with':
      return actualLower.startsWith(targetLower);
    case 'ends_with':
      return actualLower.endsWith(targetLower);
    case 'gt':
      return actualStr !== '' && targetStr !== '' && !Number.isNaN(numActual) && !Number.isNaN(numTarget) && numActual > numTarget;
    case 'gte':
      return actualStr !== '' && targetStr !== '' && !Number.isNaN(numActual) && !Number.isNaN(numTarget) && numActual >= numTarget;
    case 'lt':
      return actualStr !== '' && targetStr !== '' && !Number.isNaN(numActual) && !Number.isNaN(numTarget) && numActual < numTarget;
    case 'lte':
      return actualStr !== '' && targetStr !== '' && !Number.isNaN(numActual) && !Number.isNaN(numTarget) && numActual <= numTarget;
    default:
      return true;
  }
}

function formatRelativeSeen(lastSeen?: string): string {
  if (!lastSeen) return 'Never';
  const ts = new Date(String(lastSeen).replace(' ', 'T')).getTime();
  if (Number.isNaN(ts)) return lastSeen;
  const diffSec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

interface DevicesViewProps {
  devices: Device[];
  tenants: Tenant[];
  searchQuery: string;
  selectedTenantId: string;
  onTenantChange: (tenantId: string) => void;
  presetFilter?: DevicesPresetFilter | null;
  onConsumePreset?: () => void;
  onOpenRemote: (device: Device, isGhost: boolean) => void;
  onOpenBgTools: (device: Device, initialTab?: string) => void;
  onOpenLaps: (device: Device) => void;
  onOpenQuarantine: (device: Device) => void;
  onSelectDevice: (device: Device) => void;
  onOpenInstaller?: () => void;
  onOpenOnboarding?: () => void;
  onRefreshFleet?: () => void;
  currentUser?: AuthUser | null;
}

export const DevicesView: React.FC<DevicesViewProps> = ({
  devices,
  tenants,
  searchQuery,
  selectedTenantId,
  onTenantChange,
  presetFilter,
  onConsumePreset,
  onOpenRemote,
  onOpenBgTools,
  onOpenLaps,
  onOpenQuarantine,
  onSelectDevice,
  onOpenInstaller,
  onOpenOnboarding,
  onRefreshFleet,
  currentUser
}) => {
  const enableLabDemo = import.meta.env.VITE_ENABLE_LAB_DEMO === 'true';
  const canMutate = canMutateFleet(currentUser);

  const [localDevices, setLocalDevices] = useState<Device[]>(devices);
  const [serverFilteredDevices, setServerFilteredDevices] = useState<Device[] | null>(null);
  const [queryLoading, setQueryLoading] = useState(false);

  // Primary NinjaRMM-style filters
  const [localSearch, setLocalSearch] = useState('');
  const [siteFilter, setSiteFilter] = useState('all');
  const [deviceTypeFilter, setDeviceTypeFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [smartGroup, setSmartGroup] = useState('all');
  const [lifecycleView, setLifecycleView] = useState<'active' | 'pending_offboard' | 'archived'>('active');

  // + More Filters searchable popover & dynamic chips
  const [moreFiltersOpen, setMoreFiltersOpen] = useState(false);
  const [filterSearch, setFilterSearch] = useState('');
  const [combinator, setCombinator] = useState<'AND' | 'OR'>('AND');
  const [advancedFilters, setAdvancedFilters] = useState<DeviceFilterRule[]>([]);
  const [filterOptions, setFilterOptions] = useState<DeviceFilterOptions>({
    roles: [],
    osVersions: [],
    users: [],
    softwareNames: [],
    customFields: []
  });
  const moreFiltersRef = useRef<HTMLDivElement | null>(null);

  // Column sorting
  const [sortBy, setSortBy] = useState<DeviceSortKey>('hostname');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');

  // Smart groups, selection & modals
  const [customGroups, setCustomGroups] = useState<SmartGroup[]>([]);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [showNewGroupModal, setShowNewGroupModal] = useState(false);
  const [newGroupName, setNewGroupName] = useState('');
  const [newGroupLogic, setNewGroupLogic] = useState<'AND' | 'OR'>('AND');
  const [newGroupRules, setNewGroupRules] = useState<SmartGroupRule[]>([
    { field: 'cpu_usage', op: '>', value: '70' }
  ]);
  const [newGroupDesc, setNewGroupDesc] = useState('');
  const [bulkStatusMsg, setBulkStatusMsg] = useState<string | null>(null);
  const [showBreakGlassMfa, setShowBreakGlassMfa] = useState(false);
  const [breakGlassRows, setBreakGlassRows] = useState<BreakGlassRecoveryEntry[] | null>(null);

  useEffect(() => {
    setLocalDevices(devices);
  }, [devices]);

  useEffect(() => {
    fetchSmartGroups().then(setCustomGroups).catch(() => {});
    fetchDeviceFilterOptions().then(setFilterOptions).catch(() => {});
  }, []);

  // Reset site filter when client changes and current site no longer belongs
  useEffect(() => {
    if (selectedTenantId === 'all' || siteFilter === 'all') return;
    const t = tenants.find((item) => item.id === selectedTenantId);
    if (!t?.sites?.some((s) => s.id === siteFilter)) {
      setSiteFilter('all');
    }
  }, [selectedTenantId, tenants, siteFilter]);

  // Apply incoming dashboard preset filters
  useEffect(() => {
    if (!presetFilter) return;
    if (presetFilter.tenantId !== undefined) onTenantChange(presetFilter.tenantId);
    setSiteFilter(presetFilter.siteId || 'all');
    setDeviceTypeFilter(presetFilter.deviceRole || 'all');
    setStatusFilter(presetFilter.status || 'all');
    setSmartGroup(presetFilter.smartGroup || 'all');
    setLifecycleView(presetFilter.lifecycleView || 'active');
    setAdvancedFilters(
      presetFilter.extraFilter
        ? [{ ...presetFilter.extraFilter, id: `flt-${Date.now()}` }]
        : []
    );
    onConsumePreset?.();
  }, [presetFilter, onTenantChange, onConsumePreset]);

  // Close + More Filters popover on outside click
  useEffect(() => {
    if (!moreFiltersOpen) return;
    const onDocClick = (e: MouseEvent) => {
      if (moreFiltersRef.current && !moreFiltersRef.current.contains(e.target as Node)) {
        setMoreFiltersOpen(false);
      }
    };
    document.addEventListener('mousedown', onDocClick);
    return () => document.removeEventListener('mousedown', onDocClick);
  }, [moreFiltersOpen]);

  const combinedSearch = [searchQuery.trim(), localSearch.trim()].filter(Boolean).join(' ').trim();

  const allFieldDefs: FilterFieldDef[] = useMemo(() => {
    const cfDefs: FilterFieldDef[] = (filterOptions.customFields || []).map((cf) => ({
      field: `custom_field:${cf.key}`,
      label: cf.label || cf.key,
      category: 'Custom Fields',
      kind: cf.field_type === 'number' ? 'number' : cf.field_type === 'checkbox' ? 'boolean' : 'text',
      placeholder: `Value for ${cf.label || cf.key}`,
      enumOptions:
        cf.field_type === 'checkbox'
          ? [
              { value: 'true', label: 'Checked / True' },
              { value: 'false', label: 'Unchecked / False' }
            ]
          : undefined
    }));
    return [...BUILTIN_FILTER_FIELDS, ...cfDefs];
  }, [filterOptions.customFields]);

  const getFieldDef = (field: string): FilterFieldDef =>
    allFieldDefs.find((f) => f.field === field) || {
      field,
      label: field,
      category: 'Custom Fields',
      kind: 'text'
    };

  const requiresServerQuery = useMemo(
    () =>
      advancedFilters.some(
        (f) => f.field === 'installed_software' || f.field.startsWith('custom_field:') || f.field === 'maintenance_active'
      ),
    [advancedFilters]
  );

  // Sync with server-side /api/devices/query whenever advanced server-evaluated filters are active
  useEffect(() => {
    if (!requiresServerQuery) {
      setServerFilteredDevices(null);
      return;
    }
    let cancelled = false;
    setQueryLoading(true);
    const timer = setTimeout(() => {
      queryDevices({
        tenantId: selectedTenantId,
        siteId: siteFilter,
        deviceRole: deviceTypeFilter,
        status: statusFilter,
        lifecycleState: lifecycleView,
        search: combinedSearch,
        smartGroupId: smartGroup,
        combinator,
        filters: advancedFilters.map((f) => ({
          field: f.field,
          operator: f.operator,
          value: f.value
        })),
        sortBy,
        sortDir
      })
        .then((res) => {
          if (!cancelled) setServerFilteredDevices(res.devices);
        })
        .catch(() => {
          if (!cancelled) setServerFilteredDevices(null);
        })
        .finally(() => {
          if (!cancelled) setQueryLoading(false);
        });
    }, 180);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [
    requiresServerQuery,
    selectedTenantId,
    siteFilter,
    deviceTypeFilter,
    statusFilter,
    lifecycleView,
    combinedSearch,
    smartGroup,
    combinator,
    advancedFilters,
    sortBy,
    sortDir,
    devices
  ]);

  const evaluateCustomGroupRule = (d: Device, rule: SmartGroupRule): boolean => {
    const op = String(rule.operator || rule.op || 'eq');
    const mappedOp: DeviceFilterOperator =
      op === '=' || op === 'eq'
        ? 'is'
        : op === '!=' || op === 'neq'
        ? 'is_not'
        : op === '>'
        ? 'gt'
        : op === '>='
        ? 'gte'
        : op === '<'
        ? 'lt'
        : op === '<='
        ? 'lte'
        : (op as DeviceFilterOperator);
    return evalLocalScalarRule((d as any)[rule.field], mappedOp, String(rule.value ?? ''));
  };

  const evaluateCustomGroup = (d: Device, grp: SmartGroup): boolean => {
    if (Array.isArray(grp.matchedDeviceIds)) {
      return grp.matchedDeviceIds.includes(d.id);
    }
    try {
      const parsed = JSON.parse(grp.criteria_json || '');
      if (parsed && Array.isArray(parsed.rules)) {
        const logic = parsed.logic === 'OR' || parsed.combinator === 'OR' ? 'OR' : 'AND';
        return logic === 'OR'
          ? parsed.rules.some((rl: SmartGroupRule) => evaluateCustomGroupRule(d, rl))
          : parsed.rules.every((rl: SmartGroupRule) => evaluateCustomGroupRule(d, rl));
      }
    } catch {}
    return true;
  };

  const filteredDevices = useMemo(() => {
    if (requiresServerQuery && serverFilteredDevices) {
      return sortDeviceList(serverFilteredDevices, sortBy, sortDir);
    }

    const baseFiltered = localDevices.filter((d) => {
      const state = d.lifecycle_state || 'active';
      if (state !== lifecycleView) return false;
      if (selectedTenantId !== 'all' && d.tenant_id !== selectedTenantId) return false;
      if (siteFilter !== 'all' && d.site_id !== siteFilter) return false;

      if (deviceTypeFilter !== 'all') {
        if (String(d.device_role || '').toLowerCase() !== deviceTypeFilter.toLowerCase()) return false;
      }

      if (statusFilter !== 'all') {
        if (statusFilter === 'online' && !(d.status === 'online' && !d.quarantined)) return false;
        if (statusFilter === 'offline' && d.status !== 'offline') return false;
        if (statusFilter === 'isolated' && !d.quarantined) return false;
        if (statusFilter === 'reboot_pending' && !d.pending_reboot) return false;
        if (statusFilter === 'maintenance' && !d.maintenance_active) return false;
      }

      if (combinedSearch) {
        const extraMatched =
          matchesDeviceSearch(d, combinedSearch, { tenantName: d.tenant_name, siteName: d.site_name }) ||
          Boolean(d.public_ip && d.public_ip.toLowerCase().includes(combinedSearch.toLowerCase()));
        if (!extraMatched) return false;
      }

      if (smartGroup !== 'all') {
        if (smartGroup === 'pending_reboot' && d.pending_reboot !== 1) return false;
        else if (smartGroup === 'isolated' && d.quarantined !== 1) return false;
        else if (smartGroup === 'unencrypted' && d.bitlocker_status?.includes('Encrypted')) return false;
        else if (smartGroup === 'multi_os' && d.os_type !== 'linux' && d.os_type !== 'macos') return false;
        else if (smartGroup === 'servers') {
          const r = (d.device_role || '').toLowerCase();
          if (!r.includes('server') && !r.includes('controller') && !r.includes('hypervisor')) return false;
        } else {
          const customGrp = customGroups.find((cg) => cg.id === smartGroup);
          if (customGrp && !evaluateCustomGroup(d, customGrp)) return false;
        }
      }

      if (advancedFilters.length > 0) {
        const checkFilter = (rule: DeviceFilterRule) => {
          if (rule.field === 'installed_software' || rule.field.startsWith('custom_field:')) {
            return true; // Evaluated server-side via /api/devices/query
          }
          if (rule.field === 'tags') {
            return evalLocalScalarRule(d.tags_json || '[]', rule.operator, rule.value);
          }
          return evalLocalScalarRule((d as any)[rule.field], rule.operator, rule.value);
        };
        const matchesAdv =
          combinator === 'OR' ? advancedFilters.some(checkFilter) : advancedFilters.every(checkFilter);
        if (!matchesAdv) return false;
      }

      return true;
    });

    return sortDeviceList(baseFiltered, sortBy, sortDir);
  }, [
    requiresServerQuery,
    serverFilteredDevices,
    localDevices,
    lifecycleView,
    selectedTenantId,
    siteFilter,
    deviceTypeFilter,
    statusFilter,
    combinedSearch,
    smartGroup,
    customGroups,
    advancedFilters,
    combinator,
    sortBy,
    sortDir
  ]);

  useEffect(() => {
    setSelectedIds([]);
  }, [selectedTenantId, siteFilter, deviceTypeFilter, statusFilter, lifecycleView, smartGroup, combinedSearch]);

  useEffect(() => {
    setSelectedIds((prev) => prev.filter((id) => devices.some((d) => d.id === id)));
  }, [devices]);

  const tenantScopedDevices =
    selectedTenantId === 'all' ? localDevices : localDevices.filter((d) => d.tenant_id === selectedTenantId);
  const activeLifecycleCount = tenantScopedDevices.filter((d) => (d.lifecycle_state || 'active') === 'active').length;
  const pendingOffboardCount = tenantScopedDevices.filter((d) => d.lifecycle_state === 'pending_offboard').length;
  const archivedVaultCount = tenantScopedDevices.filter((d) => d.lifecycle_state === 'archived').length;

  const availableLocations = useMemo(() => {
    if (selectedTenantId !== 'all') {
      const t = tenants.find((item) => item.id === selectedTenantId);
      return (t?.sites || []).map((s) => ({ id: s.id, label: s.name }));
    }
    const list: Array<{ id: string; label: string }> = [];
    for (const t of tenants) {
      for (const s of t.sites || []) {
        list.push({ id: s.id, label: `${t.name} — ${s.name}` });
      }
    }
    return list;
  }, [tenants, selectedTenantId]);

  const availableDeviceTypes = useMemo(() => {
    const defaults = [
      'Workstation',
      'Laptop',
      'Desktop',
      'Server',
      'Domain Controller',
      'Hypervisor',
      'Virtual Machine',
      'Virtual Server',
      'QuickSupport'
    ];
    const set = new Set<string>(defaults);
    for (const d of localDevices) {
      if (d.device_role) set.add(d.device_role);
    }
    for (const r of filterOptions.roles || []) {
      if (r) set.add(r);
    }
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [localDevices, filterOptions.roles]);

  const handleSortClick = (key: DeviceSortKey, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    if (sortBy === key) {
      setSortDir((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortBy(key);
      setSortDir(key === 'cpu_usage' || key === 'ram_used_gb' || key === 'last_seen' ? 'desc' : 'asc');
    }
  };

  const renderSortIcon = (key: DeviceSortKey) => {
    if (sortBy !== key) return <ArrowUpDown size={12} style={{ opacity: 0.45 }} />;
    return sortDir === 'asc' ? (
      <ArrowUp size={12} style={{ color: 'var(--primary)' }} />
    ) : (
      <ArrowDown size={12} style={{ color: 'var(--primary)' }} />
    );
  };

  const handleAddMoreFilter = (fieldDef: FilterFieldDef) => {
    const defaultVal = fieldDef.enumOptions?.[0]?.value || '';
    setAdvancedFilters((prev) => [
      ...prev,
      {
        id: `flt-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        field: fieldDef.field,
        operator: defaultOperatorForKind(fieldDef.kind),
        value: defaultVal
      }
    ]);
    setMoreFiltersOpen(false);
    setFilterSearch('');
  };

  const handleClearAllFilters = () => {
    onTenantChange('all');
    setSiteFilter('all');
    setDeviceTypeFilter('all');
    setStatusFilter('all');
    setSmartGroup('all');
    setLocalSearch('');
    setAdvancedFilters([]);
  };

  const handleSaveFiltersAsSmartGroup = () => {
    const mappedRules: SmartGroupRule[] = [];
    if (deviceTypeFilter !== 'all') {
      mappedRules.push({ field: 'device_role', op: '=', value: deviceTypeFilter });
    }
    if (statusFilter === 'online' || statusFilter === 'offline') {
      mappedRules.push({ field: 'status', op: '=', value: statusFilter });
    } else if (statusFilter === 'isolated') {
      mappedRules.push({ field: 'quarantined', op: '=', value: '1' });
    } else if (statusFilter === 'reboot_pending') {
      mappedRules.push({ field: 'pending_reboot', op: '=', value: '1' });
    }
    for (const f of advancedFilters) {
      const opMap: Record<string, string> = {
        is: 'eq',
        is_not: 'neq',
        contains: 'contains',
        not_contains: 'not_contains',
        starts_with: 'starts_with',
        ends_with: 'ends_with',
        gt: 'gt',
        gte: 'gte',
        lt: 'lt',
        lte: 'lte',
        is_empty: 'is_empty',
        is_not_empty: 'is_not_empty'
      };
      mappedRules.push({ field: f.field, op: opMap[f.operator] || f.operator, value: f.value });
    }
    setNewGroupLogic(combinator);
    setNewGroupRules(mappedRules.length > 0 ? mappedRules : [{ field: 'cpu_usage', op: '>', value: '70' }]);
    setNewGroupName('');
    setNewGroupDesc('');
    setShowNewGroupModal(true);
  };

  const hasAnyActiveFilter =
    selectedTenantId !== 'all' ||
    siteFilter !== 'all' ||
    deviceTypeFilter !== 'all' ||
    statusFilter !== 'all' ||
    smartGroup !== 'all' ||
    Boolean(localSearch.trim()) ||
    advancedFilters.length > 0;

  // Action handlers
  const handleForceArchive = async (d: Device) => {
    const res = await forceArchiveDevice(d.id);
    if (res.success) {
      setLocalDevices((prev) =>
        prev.map((item) => (item.id === d.id ? { ...item, lifecycle_state: 'archived', status: 'offline' } : item))
      );
      setBulkStatusMsg(res.message);
      setTimeout(() => setBulkStatusMsg(null), 5000);
    }
  };

  const handleSimulateWakeCheckIn = async (d: Device) => {
    const res = await simulateDeviceCheckin(d.id);
    if (res.success) {
      if (res.actionTaken === 'resurrected_from_archive') {
        setLocalDevices((prev) =>
          prev.map((item) => (item.id === d.id ? { ...item, lifecycle_state: 'active', status: 'online' } : item))
        );
      } else if (res.actionTaken === 'queued_offboard_completed_to_archive' || res.actionTaken === 'quiet_offboard_executed') {
        setLocalDevices((prev) =>
          prev.map((item) => (item.id === d.id ? { ...item, lifecycle_state: 'archived', status: 'offline' } : item))
        );
      }
      setBulkStatusMsg(`${d.hostname}: ${res.message}`);
      setTimeout(() => setBulkStatusMsg(null), 6500);
    }
  };

  const handlePurgeArchived = async (d: Device) => {
    if (!confirm(`Permanently purge ${d.hostname} from the Data Archive Vault? Its BitLocker recovery key and LAPS password history will be irreversibly deleted.`)) {
      return;
    }
    const res = await purgeArchivedDevice(d.id);
    if (res.success) {
      setLocalDevices((prev) => prev.filter((item) => item.id !== d.id));
      setBulkStatusMsg(`Permanently purged ${d.hostname} from the Data Archive Vault.`);
      setTimeout(() => setBulkStatusMsg(null), 5000);
    }
  };

  const handleBreakGlassExportSuccess = async () => {
    const res = await exportBreakGlassSheet({
      tenantId: selectedTenantId === 'all' ? undefined : selectedTenantId,
      includeArchived: true
    });
    if (res.entries) {
      setBreakGlassRows(res.entries);
    }
  };

  const downloadBreakGlassCsv = () => {
    if (!breakGlassRows) return;
    const headers = [
      'Hostname',
      'Client',
      'Site',
      'Lifecycle State',
      'Serial Number',
      'LAPS Admin Account',
      'Current LAPS Password',
      'Previous LAPS Account',
      'Previous (N-1) LAPS Password',
      'SID -500 Built-in Admin Disabled',
      'BitLocker Status',
      'BitLocker Recovery Key'
    ];
    const rows = breakGlassRows.map((r) => [
      r.hostname,
      r.tenantName,
      r.siteName,
      r.lifecycleState,
      r.serialNumber,
      r.lapsAccountName,
      r.currentLapsPassword,
      r.previousLapsAccountName || '',
      r.previousLapsPassword || '',
      r.sid500BuiltinDisabled ? 'Yes' : 'No',
      r.bitlockerStatus,
      r.bitlockerRecoveryKey
    ]);
    const csvContent = [headers, ...rows].map((row) => row.map((v) => sanitizeCsvCell(v)).join(',')).join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `vitrine-break-glass-laps-bitlocker-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const toggleSelectAll = () => {
    if (selectedIds.length === filteredDevices.length && filteredDevices.length > 0) {
      setSelectedIds([]);
    } else {
      setSelectedIds(filteredDevices.map((d) => d.id));
    }
  };

  const toggleSelectRow = (id: string) => {
    setSelectedIds((prev) => (prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]));
  };

  const handleExportCsv = () => {
    const targetList =
      selectedIds.length > 0 ? filteredDevices.filter((d) => selectedIds.includes(d.id)) : filteredDevices;
    const headers = [
      'Hostname',
      'Role',
      'Client',
      'Location',
      'Last Logged-On User',
      'Private IP',
      'Public IP',
      'OS',
      'Status',
      'CPU %',
      'RAM Used GB',
      'BitLocker',
      'Last Seen'
    ];
    const rows = targetList.map((d) => [
      d.hostname,
      d.device_role,
      d.tenant_name || 'Unassigned',
      d.site_name || 'Default Site',
      d.logged_in_user || '',
      d.ip_address,
      d.public_ip || '',
      d.os_version,
      d.status,
      d.cpu_usage.toFixed(1),
      d.ram_used_gb.toFixed(1),
      d.bitlocker_status,
      d.last_seen
    ]);
    const csvContent = [headers, ...rows].map((row) => row.map((v) => sanitizeCsvCell(v)).join(',')).join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `vitrine-devices-export-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleBulkPatchScan = async () => {
    const res = await scanPatches(selectedIds.length > 0 ? selectedIds : undefined);
    setBulkStatusMsg(
      `Patch scan completed across ${selectedIds.length || filteredDevices.length} endpoints (${res.patches?.length || 0} updates indexed).`
    );
    setTimeout(() => setBulkStatusMsg(null), 4000);
  };

  const handleSeedDemoLab = async () => {
    const res = await seedDemoLabData();
    if (res.success) {
      setBulkStatusMsg('Evaluation lab dataset seeded. Refreshing fleet inventory...');
      onRefreshFleet?.();
      setTimeout(() => setBulkStatusMsg(null), 4000);
    }
  };

  const handleCreateSmartGroup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newGroupName.trim() || newGroupRules.length === 0) return;
    const criteriaPayload = JSON.stringify({
      logic: newGroupLogic,
      combinator: newGroupLogic,
      rules: newGroupRules.map((r) => ({
        field: r.field,
        op: r.op,
        operator: r.op,
        value: r.value
      }))
    });
    const summaryStr = newGroupRules.map((r) => `${r.field} ${r.op} ${r.value}`).join(` ${newGroupLogic} `);
    const res = await createSmartGroup({
      name: newGroupName.trim(),
      criteria_json: criteriaPayload,
      description: newGroupDesc.trim() || `Dynamic query: ${summaryStr}`
    });
    if (res.success && res.id) {
      const updated = await fetchSmartGroups();
      setCustomGroups(updated);
      setSmartGroup(res.id);
      setShowNewGroupModal(false);
      setNewGroupName('');
      setNewGroupDesc('');
      setNewGroupRules([{ field: 'cpu_usage', op: '>', value: '70' }]);
    }
  };

  const handleOffboardCurrentClient = async () => {
    if (selectedTenantId === 'all') return;
    if (!confirm('Archive this client organization and queue clean offboarding across its endpoints?')) return;
    const res = await offboardTenant(selectedTenantId, { mode: 'archive_client', reason: 'Client archived by Super Admin' });
    if (res.success) {
      setBulkStatusMsg(res.message);
      onRefreshFleet?.();
    }
  };

  const handleDeleteEmptyClient = async () => {
    if (selectedTenantId === 'all') return;
    if (!confirm('Delete this client organization? (Active/archived devices must be offboarded or purged first.)')) return;
    const res = await deleteTenant(selectedTenantId);
    if (res.success) {
      setBulkStatusMsg('Client organization removed.');
      onTenantChange('all');
      onRefreshFleet?.();
    } else {
      setBulkStatusMsg(res.error || 'Cannot delete client while endpoints remain attached.');
    }
  };

  const handleDeleteCustomGroup = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    await deleteSmartGroup(id);
    setCustomGroups((prev) => prev.filter((g) => g.id !== id));
    if (smartGroup === id) setSmartGroup('all');
  };

  const filteredFieldDefsForPopover = useMemo(() => {
    const q = filterSearch.trim().toLowerCase();
    return allFieldDefs.filter(
      (f) => !q || f.label.toLowerCase().includes(q) || f.field.toLowerCase().includes(q) || f.category.toLowerCase().includes(q)
    );
  }, [allFieldDefs, filterSearch]);

  const groupedPopoverFields = useMemo(() => {
    const groups: Record<string, FilterFieldDef[]> = {};
    for (const def of filteredFieldDefsForPopover) {
      if (!groups[def.category]) groups[def.category] = [];
      groups[def.category].push(def);
    }
    return groups;
  }, [filteredFieldDefsForPopover]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }} id="devices-directory-view">
      {/* Page Header & Lifecycle Switcher */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>
            Devices Inventory
          </h2>
          <span style={{ fontSize: '0.84rem', color: 'var(--text-muted)' }}>
            Search, filter, sort, and manage all endpoints across clients, locations, software, and telemetry
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          {selectedTenantId !== 'all' && isSuperAdmin(currentUser) && (
            <>
              <button
                className="btn-glass"
                style={{ fontSize: '0.76rem', padding: '0.38rem 0.75rem' }}
                onClick={handleOffboardCurrentClient}
                title="Archive selected client organization and offboard its endpoints"
              >
                <Archive size={13} /> Archive Client
              </button>
              {localDevices.filter((d) => d.tenant_id === selectedTenantId).length === 0 && (
                <button
                  className="btn-glass btn-danger"
                  style={{ fontSize: '0.76rem', padding: '0.38rem 0.75rem' }}
                  onClick={handleDeleteEmptyClient}
                  title="Delete empty client tenant"
                >
                  <Trash2 size={13} /> Delete Empty Client
                </button>
              )}
            </>
          )}
          {isSuperAdmin(currentUser) && (
            <button
              className="btn-glass"
              style={{ fontSize: '0.78rem', padding: '0.4rem 0.85rem', borderColor: 'rgba(245, 158, 11, 0.45)', color: '#fbbf24' }}
              onClick={() => setShowBreakGlassMfa(true)}
              title="Step-Up MFA-gated emergency offline Break-Glass export containing current + N-1 LAPS passwords and BitLocker recovery keys"
            >
              <FileSpreadsheet size={14} /> Break-Glass Sheet
            </button>
          )}
          {onOpenInstaller && canMutate && (
            <button className="btn-glass btn-primary" style={{ fontSize: '0.78rem', padding: '0.42rem 0.85rem' }} onClick={onOpenInstaller}>
              <Download size={14} /> Deploy Agent
            </button>
          )}
        </div>
      </div>

      {/* Lifecycle Tabs */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', flexWrap: 'wrap' }}>
        <span style={{ fontSize: '0.76rem', fontWeight: 700, color: 'var(--text-dim)', marginRight: '0.2rem' }}>
          LIFECYCLE:
        </span>
        <button
          className={`btn-glass ${lifecycleView === 'active' ? 'btn-primary' : ''}`}
          style={{ fontSize: '0.78rem', padding: '0.32rem 0.8rem' }}
          onClick={() => setLifecycleView('active')}
        >
          Active Fleet ({activeLifecycleCount})
        </button>
        <button
          className={`btn-glass ${lifecycleView === 'pending_offboard' ? 'btn-primary' : ''}`}
          style={{
            fontSize: '0.78rem',
            padding: '0.32rem 0.8rem',
            borderColor: pendingOffboardCount > 0 ? 'rgba(245, 158, 11, 0.45)' : undefined,
            color: lifecycleView === 'pending_offboard' ? '#fff' : pendingOffboardCount > 0 ? '#fbbf24' : undefined
          }}
          onClick={() => setLifecycleView('pending_offboard')}
        >
          Pending Offboard ({pendingOffboardCount})
        </button>
        <button
          className={`btn-glass ${lifecycleView === 'archived' ? 'btn-primary' : ''}`}
          style={{ fontSize: '0.78rem', padding: '0.32rem 0.8rem' }}
          onClick={() => setLifecycleView('archived')}
        >
          <Archive size={13} /> Archive Vault ({archivedVaultCount})
        </button>
      </div>

      {/* NinjaRMM-Style Primary Filter Bar + "+ More Filters" Popover */}
      <div className="glass-card" style={{ padding: '1rem 1.15rem', display: 'flex', flexDirection: 'column', gap: '0.85rem', zIndex: 20 }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(190px, 1.4fr) repeat(4, minmax(135px, 1fr)) auto', gap: '0.65rem', alignItems: 'end' }}>
          <div>
            <label className="form-label" style={{ fontSize: '0.7rem', marginBottom: '0.25rem' }}>Search Devices</label>
            <div style={{ position: 'relative' }}>
              <Search size={14} style={{ position: 'absolute', left: '0.65rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-dim)', pointerEvents: 'none' }} />
              <input
                type="text"
                className="glass-input"
                style={{ paddingLeft: '2rem', fontSize: '0.8rem' }}
                placeholder="Hostname, IP, user, serial..."
                value={localSearch}
                onChange={(e) => setLocalSearch(e.target.value)}
                id="devices-search-input"
              />
            </div>
          </div>

          <div>
            <label className="form-label" style={{ fontSize: '0.7rem', marginBottom: '0.25rem' }}>Client</label>
            <select
              className="glass-select"
              style={{ fontSize: '0.8rem' }}
              value={selectedTenantId}
              onChange={(e) => onTenantChange(e.target.value)}
              id="devices-filter-client"
            >
              <option value="all">All Clients</option>
              {tenants.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="form-label" style={{ fontSize: '0.7rem', marginBottom: '0.25rem' }}>Location</label>
            <select
              className="glass-select"
              style={{ fontSize: '0.8rem' }}
              value={siteFilter}
              onChange={(e) => setSiteFilter(e.target.value)}
              disabled={availableLocations.length === 0}
              id="devices-filter-location"
            >
              <option value="all">{availableLocations.length === 0 ? 'All Locations (None)' : 'All Locations'}</option>
              {availableLocations.map((loc) => (
                <option key={loc.id} value={loc.id}>
                  {loc.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="form-label" style={{ fontSize: '0.7rem', marginBottom: '0.25rem' }}>Device Type</label>
            <select
              className="glass-select"
              style={{ fontSize: '0.8rem' }}
              value={deviceTypeFilter}
              onChange={(e) => setDeviceTypeFilter(e.target.value)}
              id="devices-filter-type"
            >
              <option value="all">All Device Types</option>
              {availableDeviceTypes.map((role) => (
                <option key={role} value={role}>
                  {role}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="form-label" style={{ fontSize: '0.7rem', marginBottom: '0.25rem' }}>Status</label>
            <select
              className="glass-select"
              style={{ fontSize: '0.8rem' }}
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              id="devices-filter-status"
            >
              <option value="all">All Statuses</option>
              <option value="online">Online</option>
              <option value="offline">Offline</option>
              <option value="reboot_pending">Pending Reboot</option>
              <option value="isolated">Cyber Isolated</option>
              <option value="maintenance">In Maintenance</option>
            </select>
          </div>

          <div ref={moreFiltersRef} style={{ position: 'relative' }}>
            <button
              type="button"
              className={`btn-glass ${moreFiltersOpen || advancedFilters.length > 0 ? 'btn-primary' : ''}`}
              style={{ fontSize: '0.8rem', padding: '0.52rem 0.85rem', whiteSpace: 'nowrap' }}
              onClick={() => setMoreFiltersOpen((o) => !o)}
              id="devices-more-filters-btn"
            >
              <SlidersHorizontal size={14} />
              <span>More Filters{advancedFilters.length > 0 ? ` (${advancedFilters.length})` : ''}</span>
            </button>

            {moreFiltersOpen && (
              <div
                className="glass-card"
                style={{
                  position: 'absolute',
                  right: 0,
                  top: 'calc(100% + 8px)',
                  width: '340px',
                  maxHeight: '440px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.6rem',
                  padding: '0.85rem',
                  zIndex: 80,
                  background: 'var(--surface-elevated, #0f172a)',
                  border: '1px solid var(--primary)',
                  boxShadow: '0 20px 45px rgba(0, 0, 0, 0.55)'
                }}
                id="devices-more-filters-popover"
              >
                <div style={{ position: 'relative' }}>
                  <Search size={13} style={{ position: 'absolute', left: '0.6rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-dim)' }} />
                  <input
                    type="text"
                    className="glass-input"
                    autoFocus
                    style={{ paddingLeft: '1.9rem', fontSize: '0.78rem' }}
                    placeholder="Search filter attributes (user, IP, programs...)"
                    value={filterSearch}
                    onChange={(e) => setFilterSearch(e.target.value)}
                    id="devices-more-filters-search"
                  />
                </div>
                <div style={{ overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.65rem', paddingRight: '0.2rem' }}>
                  {Object.entries(groupedPopoverFields).map(([category, defs]) => (
                    <div key={category} style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                      <div style={{ fontSize: '0.67rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--primary)', padding: '0.2rem 0.35rem' }}>
                        {category}
                      </div>
                      {defs.map((def) => (
                        <button
                          key={def.field}
                          type="button"
                          className="btn-glass"
                          style={{
                            justifyContent: 'space-between',
                            fontSize: '0.78rem',
                            padding: '0.38rem 0.6rem',
                            border: '1px solid transparent',
                            textAlign: 'left'
                          }}
                          onClick={() => handleAddMoreFilter(def)}
                        >
                          <span>{def.label}</span>
                          <Plus size={12} style={{ opacity: 0.7 }} />
                        </button>
                      ))}
                    </div>
                  ))}
                  {filteredFieldDefsForPopover.length === 0 && (
                    <div style={{ textAlign: 'center', fontSize: '0.78rem', color: 'var(--text-dim)', padding: '1rem' }}>
                      No filter attributes match &ldquo;{filterSearch}&rdquo;.
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Active Advanced Filter Chips */}
        {(advancedFilters.length > 0 || hasAnyActiveFilter) && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', paddingTop: '0.45rem', borderTop: '1px solid var(--glass-border)' }}>
            {advancedFilters.length > 1 && (
              <select
                className="glass-select"
                style={{ width: 'auto', fontSize: '0.73rem', padding: '0.25rem 0.5rem' }}
                value={combinator}
                onChange={(e) => setCombinator(e.target.value as 'AND' | 'OR')}
              >
                <option value="AND">Match ALL (AND)</option>
                <option value="OR">Match ANY (OR)</option>
              </select>
            )}

            {advancedFilters.map((flt, idx) => {
              const def = getFieldDef(flt.field);
              const operators = getOperatorsForKind(def.kind);
              const needsValue = flt.operator !== 'is_empty' && flt.operator !== 'is_not_empty';
              const listId = `dl-${flt.id || idx}`;

              return (
                <div
                  key={flt.id || idx}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.35rem',
                    padding: '0.25rem 0.45rem',
                    borderRadius: '8px',
                    background: 'rgba(0, 242, 254, 0.08)',
                    border: '1px solid rgba(0, 242, 254, 0.28)',
                    fontSize: '0.75rem'
                  }}
                >
                  <span style={{ fontWeight: 600, color: 'var(--primary)', whiteSpace: 'nowrap' }}>{def.label}</span>
                  <select
                    className="glass-select"
                    style={{ width: 'auto', fontSize: '0.73rem', padding: '0.18rem 0.35rem' }}
                    value={flt.operator}
                    onChange={(e) => {
                      const nextOp = e.target.value as DeviceFilterOperator;
                      setAdvancedFilters((prev) =>
                        prev.map((item, i) => (i === idx ? { ...item, operator: nextOp } : item))
                      );
                    }}
                  >
                    {operators.map((op) => (
                      <option key={op} value={op}>
                        {OPERATOR_LABELS[op]}
                      </option>
                    ))}
                  </select>

                  {needsValue &&
                    (def.enumOptions ? (
                      <select
                        className="glass-select"
                        style={{ width: 'auto', fontSize: '0.73rem', padding: '0.18rem 0.4rem' }}
                        value={flt.value}
                        onChange={(e) => {
                          const v = e.target.value;
                          setAdvancedFilters((prev) => prev.map((item, i) => (i === idx ? { ...item, value: v } : item)));
                        }}
                      >
                        {def.enumOptions.map((opt) => (
                          <option key={opt.value} value={opt.value}>
                            {opt.label}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <>
                        <input
                          type={def.kind === 'number' ? 'number' : 'text'}
                          list={listId}
                          className="glass-input"
                          style={{ width: '145px', fontSize: '0.74rem', padding: '0.2rem 0.45rem' }}
                          placeholder={def.placeholder || 'Value...'}
                          value={flt.value}
                          onChange={(e) => {
                            const v = e.target.value;
                            setAdvancedFilters((prev) => prev.map((item, i) => (i === idx ? { ...item, value: v } : item)));
                          }}
                        />
                        {(flt.field === 'installed_software' ||
                          flt.field === 'logged_in_user' ||
                          flt.field === 'os_version') && (
                          <datalist id={listId}>
                            {(flt.field === 'installed_software'
                              ? filterOptions.softwareNames
                              : flt.field === 'logged_in_user'
                              ? filterOptions.users
                              : filterOptions.osVersions
                            )
                              .slice(0, 120)
                              .map((opt) => (
                                <option key={opt} value={opt} />
                              ))}
                          </datalist>
                        )}
                      </>
                    ))}

                  <button
                    type="button"
                    className="btn-glass btn-icon"
                    style={{ padding: '0.15rem' }}
                    onClick={() => setAdvancedFilters((prev) => prev.filter((_, i) => i !== idx))}
                    title="Remove filter"
                  >
                    <X size={12} />
                  </button>
                </div>
              );
            })}

            <div style={{ marginLeft: 'auto', display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
              {canMutate && (advancedFilters.length > 0 || deviceTypeFilter !== 'all' || statusFilter !== 'all') && (
                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.73rem', padding: '0.24rem 0.6rem' }}
                  onClick={handleSaveFiltersAsSmartGroup}
                >
                  <BookmarkPlus size={12} /> Save as Smart Group
                </button>
              )}
              {hasAnyActiveFilter && (
                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.73rem', padding: '0.24rem 0.6rem', color: 'var(--text-muted)' }}
                  onClick={handleClearAllFilters}
                >
                  <RotateCcw size={12} /> Clear Filters
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Dynamic Smart Device Groups */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', flexWrap: 'wrap' }}>
        <span style={{ fontSize: '0.76rem', fontWeight: 600, color: 'var(--text-dim)', marginRight: '0.25rem' }}>
          SMART GROUPS:
        </span>
        {[
          { id: 'all', label: 'All Devices' },
          { id: 'servers', label: 'Servers & Hypervisors' },
          { id: 'pending_reboot', label: 'Pending Reboot' },
          { id: 'isolated', label: 'Cyber Isolated' },
          { id: 'unencrypted', label: 'Missing Encryption' },
          { id: 'multi_os', label: 'Linux & macOS' }
        ].map((g) => (
          <button
            key={g.id}
            className={`btn-glass ${smartGroup === g.id ? 'btn-primary' : ''}`}
            style={{ padding: '0.32rem 0.78rem', fontSize: '0.78rem' }}
            onClick={() => setSmartGroup(g.id)}
            id={`smart-group-${g.id}`}
          >
            {g.label}
          </button>
        ))}

        {customGroups.map((cg) => (
          <button
            key={cg.id}
            className={`btn-glass ${smartGroup === cg.id ? 'btn-primary' : ''}`}
            style={{ padding: '0.32rem 0.72rem', fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.38rem' }}
            onClick={() => setSmartGroup(cg.id)}
            title={`${cg.description || ''} (${cg.criteria_json})`}
          >
            <span>
              ⚡ {cg.name}
              {typeof cg.matchedCount === 'number' ? ` (${cg.matchedCount})` : ''}
            </span>
            {canMutate && (
              <Trash2 size={12} style={{ opacity: 0.7 }} onClick={(e) => handleDeleteCustomGroup(cg.id, e)} />
            )}
          </button>
        ))}

        {canMutate && (
          <button
            className="btn-glass"
            style={{ padding: '0.32rem 0.72rem', fontSize: '0.76rem', borderStyle: 'dashed' }}
            onClick={() => setShowNewGroupModal(true)}
          >
            <Plus size={13} /> New Smart Group
          </button>
        )}
      </div>

      {bulkStatusMsg &&
        (() => {
          const isBulkErr = /^(cannot|error|failed|⚠)/i.test(bulkStatusMsg.trim());
          return (
            <div
              className="glass-card"
              style={{
                padding: '0.75rem 1.25rem',
                background: isBulkErr ? 'rgba(239, 68, 68, 0.12)' : 'rgba(16, 185, 129, 0.12)',
                borderColor: isBulkErr ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)',
                color: isBulkErr ? '#fca5a5' : '#34d399',
                fontSize: '0.85rem',
                fontWeight: 500
              }}
            >
              {isBulkErr ? '⚠ ' : '✓ '}
              {bulkStatusMsg}
            </div>
          );
        })()}

      {/* Sortable Devices Table */}
      <div className="glass-card" style={{ padding: 0 }}>
        <div
          style={{
            padding: '1rem 1.35rem',
            borderBottom: '1px solid var(--glass-border)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '0.75rem'
          }}
        >
          <div>
            <h3 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.08rem', fontWeight: 600, margin: 0 }}>
              Managed Fleet Inventory
            </h3>
            <span style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
              Showing {filteredDevices.length} endpoint{filteredDevices.length === 1 ? '' : 's'}
              {queryLoading ? ' • Querying inventory...' : ''}
              {selectedIds.length > 0 && ` • ${selectedIds.length} selected`}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem' }}>
            {canMutate && selectedIds.length > 0 && (
              <button
                className="btn-glass btn-primary"
                style={{ fontSize: '0.78rem', padding: '0.38rem 0.8rem' }}
                onClick={handleBulkPatchScan}
              >
                <RefreshCw size={14} /> Scan Selected ({selectedIds.length})
              </button>
            )}
            <button className="btn-glass" style={{ fontSize: '0.78rem', padding: '0.38rem 0.8rem' }} onClick={handleExportCsv}>
              <Download size={14} /> Export CSV
            </button>
          </div>
        </div>

        <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
          <table className="glass-table glass-table-compact">
            <thead>
              <tr>
                <th style={{ width: '36px' }}>
                  <input
                    type="checkbox"
                    checked={filteredDevices.length > 0 && selectedIds.length === filteredDevices.length}
                    onChange={toggleSelectAll}
                  />
                </th>
                <th style={{ cursor: 'pointer', userSelect: 'none' }} onClick={() => handleSortClick('status')}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                    Status {renderSortIcon('status')}
                  </span>
                </th>
                <th style={{ cursor: 'pointer', userSelect: 'none' }} onClick={() => handleSortClick('hostname')}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                    Device Name {renderSortIcon('hostname')}
                    <span
                      onClick={(e) => handleSortClick('device_role', e)}
                      title="Sort by Device Role"
                      style={{ fontSize: '0.64rem', opacity: sortBy === 'device_role' ? 1 : 0.65, color: sortBy === 'device_role' ? 'var(--primary)' : undefined }}
                    >
                      / Role
                    </span>
                  </span>
                </th>
                <th style={{ cursor: 'pointer', userSelect: 'none' }} onClick={() => handleSortClick('tenant_name')}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                    Client {renderSortIcon('tenant_name')}
                    <span
                      onClick={(e) => handleSortClick('site_name', e)}
                      title="Sort by Location / Site"
                      style={{ fontSize: '0.64rem', opacity: sortBy === 'site_name' ? 1 : 0.65, color: sortBy === 'site_name' ? 'var(--primary)' : undefined }}
                    >
                      / Site
                    </span>
                  </span>
                </th>
                <th style={{ cursor: 'pointer', userSelect: 'none' }} onClick={() => handleSortClick('logged_in_user')}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                    Last User {renderSortIcon('logged_in_user')}
                  </span>
                </th>
                <th style={{ cursor: 'pointer', userSelect: 'none' }} onClick={() => handleSortClick('ip_address')}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                    Private IP {renderSortIcon('ip_address')}
                    <span
                      onClick={(e) => handleSortClick('public_ip', e)}
                      title="Sort by Public IP"
                      style={{ fontSize: '0.64rem', opacity: sortBy === 'public_ip' ? 1 : 0.65, color: sortBy === 'public_ip' ? 'var(--primary)' : undefined }}
                    >
                      / Public
                    </span>
                  </span>
                </th>
                <th style={{ cursor: 'pointer', userSelect: 'none' }} onClick={() => handleSortClick('os_version')}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                    OS {renderSortIcon('os_version')}
                  </span>
                </th>
                <th style={{ cursor: 'pointer', userSelect: 'none' }} onClick={() => handleSortClick('cpu_usage')}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                    CPU {renderSortIcon('cpu_usage')}
                    <span
                      onClick={(e) => handleSortClick('ram_used_gb', e)}
                      title="Sort by RAM Usage"
                      style={{ fontSize: '0.64rem', opacity: sortBy === 'ram_used_gb' ? 1 : 0.65, color: sortBy === 'ram_used_gb' ? 'var(--primary)' : undefined }}
                    >
                      / RAM
                    </span>
                  </span>
                </th>
                <th style={{ cursor: 'pointer', userSelect: 'none' }} onClick={() => handleSortClick('edr_status')}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                    Security {renderSortIcon('edr_status')}
                  </span>
                </th>
                <th style={{ cursor: 'pointer', userSelect: 'none' }} onClick={() => handleSortClick('last_seen')}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                    Last Seen {renderSortIcon('last_seen')}
                  </span>
                </th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredDevices.map((d) => (
                <tr key={d.id} id={`device-row-${d.id}`}>
                  <td>
                    <input type="checkbox" checked={selectedIds.includes(d.id)} onChange={() => toggleSelectRow(d.id)} />
                  </td>
                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem', alignItems: 'flex-start' }}>
                      <span
                        className={`status-pill ${
                          d.lifecycle_state === 'archived'
                            ? 'status-offline'
                            : d.lifecycle_state === 'pending_offboard'
                            ? 'status-reboot'
                            : d.quarantined
                            ? 'status-isolated'
                            : d.pending_reboot
                            ? 'status-reboot'
                            : d.status === 'online'
                            ? 'status-online'
                            : 'status-offline'
                        }`}
                      >
                        <div className="pulse-dot" />
                        {d.lifecycle_state === 'archived'
                          ? 'Archived'
                          : d.lifecycle_state === 'pending_offboard'
                          ? 'Pending Offboard'
                          : d.quarantined
                          ? 'Isolated'
                          : d.pending_reboot
                          ? 'Reboot Req'
                          : d.status}
                      </span>
                      {d.ws_connected ? (
                        <span style={{ fontSize: '0.64rem', color: '#38bdf8', fontWeight: 600 }}>● WSS Live</span>
                      ) : null}
                    </div>
                  </td>

                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                      <span
                        style={{ fontWeight: 600, color: 'var(--text-main)', cursor: 'pointer' }}
                        onClick={() => onSelectDevice(d)}
                        className="hover-underline"
                      >
                        {d.hostname}
                      </span>
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                        {(() => {
                          const r = (d.device_role || '').toLowerCase();
                          if (r.includes('laptop')) return <Laptop size={12} color="#38bdf8" />;
                          if (r.includes('server') || r.includes('hypervisor') || r.includes('controller'))
                            return <Server size={12} color="#a78bfa" />;
                          if (r.includes('virtual')) return <Cpu size={12} color="#34d399" />;
                          return <Monitor size={12} color="var(--text-dim)" />;
                        })()}
                        {d.device_role}
                        {d.offboard_reason ? ` • ${d.offboard_reason}` : ''}
                      </span>
                    </div>
                  </td>

                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                      <span style={{ fontSize: '0.82rem', fontWeight: 500 }}>{d.tenant_name || 'Unassigned'}</span>
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>{d.site_name || 'Default Site'}</span>
                    </div>
                  </td>

                  <td>
                    <span style={{ fontSize: '0.8rem', color: d.logged_in_user ? 'var(--text-main)' : 'var(--text-dim)' }}>
                      {d.logged_in_user || '—'}
                    </span>
                  </td>

                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                      <span>{d.ip_address || '—'}</span>
                      <span style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>
                        {d.public_ip ? `Pub: ${d.public_ip}` : 'Pub: —'}
                      </span>
                    </div>
                  </td>

                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                      <span style={{ fontSize: '0.8rem' }}>{d.os_version}</span>
                      <span style={{ fontSize: '0.69rem', color: 'var(--text-dim)' }}>{d.os_build || d.os_type}</span>
                    </div>
                  </td>

                  <td style={{ minWidth: '155px' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.45rem', fontSize: '0.71rem', whiteSpace: 'nowrap' }}>
                        <span>CPU: {d.status === 'offline' && d.cpu_usage <= 0 ? '—' : `${d.cpu_usage.toFixed(1)}%`}</span>
                        <span>
                          RAM:{' '}
                          {d.ram_used_gb > 0
                            ? `${d.ram_used_gb.toFixed(1)}/${d.ram_total_gb.toFixed(0)}G`
                            : d.ram_total_gb > 0
                            ? `—/${d.ram_total_gb.toFixed(0)}G`
                            : '—'}
                        </span>
                      </div>
                      <div style={{ width: '100%', height: '5px', background: 'rgba(148, 163, 184, 0.22)', borderRadius: '3px', overflow: 'hidden' }}>
                        <div
                          style={{
                            width: `${Math.min(100, d.cpu_usage)}%`,
                            height: '100%',
                            background: d.cpu_usage > 80 ? '#ef4444' : 'var(--primary)'
                          }}
                        />
                      </div>
                    </div>
                  </td>

                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.18rem' }}>
                      <span
                        style={{
                          fontSize: '0.74rem',
                          color: d.edr_status === 'Active' || d.edr_status === 'Healthy' ? '#10b981' : '#f59e0b',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.3rem'
                        }}
                      >
                        <ShieldCheck size={12} />{' '}
                        {d.edr_status === 'Active' || d.edr_status === 'Healthy'
                          ? d.edr_name || 'EDR Active'
                          : d.edr_status || 'Unmonitored'}
                      </span>
                      <span style={{ fontSize: '0.69rem', color: d.has_bitlocker_key || d.bitlocker_status?.includes('Encrypted') ? '#38bdf8' : '#f59e0b' }}>
                        🔒 {d.has_bitlocker_key || d.bitlocker_status?.includes('Encrypted') ? 'Encrypted' : 'Unencrypted'}
                      </span>
                    </div>
                  </td>

                  <td style={{ fontSize: '0.74rem', color: 'var(--text-dim)', whiteSpace: 'nowrap' }} title={d.last_seen}>
                    {formatRelativeSeen(d.last_seen)}
                  </td>

                  <td style={{ textAlign: 'right' }}>
                    {canMutate ? (
                      <div className="action-group" style={{ justifyContent: 'flex-end' }}>
                        {d.lifecycle_state === 'pending_offboard' && (
                          <button
                            className="btn-glass"
                            style={{ padding: '0.25rem 0.55rem', fontSize: '0.72rem', borderColor: 'rgba(245, 158, 11, 0.45)', color: '#fbbf24' }}
                            title="Force move this offline pending-offboard endpoint directly into the Data Archive Vault now"
                            onClick={() => handleForceArchive(d)}
                          >
                            <Archive size={13} /> Force Archive
                          </button>
                        )}

                        {enableLabDemo && (d.lifecycle_state === 'pending_offboard' || d.lifecycle_state === 'archived') && (
                          <button
                            className="btn-glass"
                            style={{ padding: '0.25rem 0.55rem', fontSize: '0.72rem', borderColor: 'rgba(56, 189, 248, 0.45)', color: '#38bdf8' }}
                            title="Lab demo: simulate this endpoint checking back in"
                            onClick={() => handleSimulateWakeCheckIn(d)}
                          >
                            <Zap size={13} /> Simulate Wake
                          </button>
                        )}

                        {d.lifecycle_state === 'archived' && (
                          <button
                            className="btn-glass btn-icon"
                            title="Explicitly & permanently purge this archived endpoint (deletes preserved BitLocker & LAPS keys)"
                            onClick={() => handlePurgeArchived(d)}
                          >
                            <Trash2 size={14} color="#ef4444" />
                          </button>
                        )}

                        {(!d.lifecycle_state || d.lifecycle_state === 'active') && (
                          <>
                            <button
                              className="btn-glass btn-icon"
                              title="Low-Latency Screen Control (KVM)"
                              onClick={() => onOpenRemote(d, false)}
                              id={`btn-remote-${d.id}`}
                            >
                              <Monitor size={15} color="#00f2fe" />
                            </button>

                            <button
                              className="btn-glass btn-icon"
                              title="Ghost Session (Headless Remote Desktop)"
                              onClick={() => onOpenRemote(d, true)}
                              id={`btn-ghost-${d.id}`}
                            >
                              <EyeOff size={15} color="#c084fc" />
                            </button>

                            <button
                              className="btn-glass btn-icon"
                              title="Silent Background Suite (Shell, Task Manager, Services, Registry, Files)"
                              onClick={() => onOpenBgTools(d, 'terminal')}
                              id={`btn-bg-tools-${d.id}`}
                            >
                              <Terminal size={15} />
                            </button>
                          </>
                        )}

                        <button
                          className="btn-glass btn-icon"
                          title="Automated LAPS Vault (Local Admin Password & Historical Archive)"
                          onClick={() => onOpenLaps(d)}
                          id={`btn-laps-${d.id}`}
                        >
                          <KeyRound size={15} color="#fbbf24" />
                        </button>

                        {(!d.lifecycle_state || d.lifecycle_state === 'active') && (
                          <button
                            className={`btn-glass btn-icon ${d.quarantined ? 'btn-danger' : ''}`}
                            title={d.quarantined ? 'Isolated: Click to restore network' : 'One-Click Cyber Isolation'}
                            onClick={() => onOpenQuarantine(d)}
                            id={`btn-quarantine-${d.id}`}
                          >
                            <ShieldAlert size={15} color={d.quarantined ? '#ef4444' : '#94a3b8'} />
                          </button>
                        )}
                      </div>
                    ) : (
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Read-Only</span>
                    )}
                  </td>
                </tr>
              ))}
              {filteredDevices.length === 0 && (
                <tr>
                  <td colSpan={11} style={{ textAlign: 'center', padding: '3rem 1.5rem' }}>
                    {localDevices.length === 0 ? (
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.85rem' }}>
                        <div style={{ fontWeight: 700, fontSize: '1rem' }}>No Endpoints Enrolled Yet</div>
                        <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', maxWidth: '520px' }}>
                          Provision a signed agent installer, import existing device groups from MeshCentral 2, or load the evaluation lab dataset.
                        </div>
                        <div style={{ display: 'flex', gap: '0.65rem', flexWrap: 'wrap', justifyContent: 'center', marginTop: '0.35rem' }}>
                          {onOpenInstaller && canMutate && (
                            <button className="btn-glass btn-primary" onClick={onOpenInstaller}>
                              <Download size={14} /> Provision Signed Agent
                            </button>
                          )}
                          {onOpenOnboarding && isSuperAdmin(currentUser) && (
                            <button className="btn-glass" onClick={onOpenOnboarding}>
                              Import from MeshCentral
                            </button>
                          )}
                          {enableLabDemo && isSuperAdmin(currentUser) && (
                            <button className="btn-glass" onClick={handleSeedDemoLab}>
                              Load Lab Demo Dataset
                            </button>
                          )}
                        </div>
                      </div>
                    ) : (
                      <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                        No endpoints match the selected lifecycle state or filter criteria.
                      </span>
                    )}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create Smart Group Modal */}
      {showNewGroupModal && (
        <div className="modal-overlay" onClick={() => setShowNewGroupModal(false)}>
          <div className="glass-modal" style={{ maxWidth: '540px', padding: '1.5rem' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>Create Dynamic Smart Group</h3>
              <button className="btn-glass btn-icon" onClick={() => setShowNewGroupModal(false)}>
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleCreateSmartGroup} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Smart Group Name
                </label>
                <input
                  type="text"
                  required
                  className="glass-input"
                  placeholder="e.g. Workstations with Chrome"
                  value={newGroupName}
                  onChange={(e) => setNewGroupName(e.target.value)}
                />
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.55rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>Compound Dynamic Conditions</label>
                  <select
                    className="glass-select"
                    style={{ width: 'auto', padding: '0.2rem 0.55rem', fontSize: '0.75rem' }}
                    value={newGroupLogic}
                    onChange={(e) => setNewGroupLogic(e.target.value as 'AND' | 'OR')}
                  >
                    <option value="AND">Match ALL Rules (AND)</option>
                    <option value="OR">Match ANY Rule (OR)</option>
                  </select>
                </div>

                {newGroupRules.map((rule, rIdx) => (
                  <div key={rIdx} style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.9fr 1fr auto', gap: '0.4rem', alignItems: 'center' }}>
                    <select
                      className="glass-select"
                      style={{ fontSize: '0.76rem', padding: '0.35rem 0.45rem' }}
                      value={rule.field}
                      onChange={(e) => {
                        const copy = [...newGroupRules];
                        copy[rIdx] = { ...copy[rIdx], field: e.target.value };
                        setNewGroupRules(copy);
                      }}
                    >
                      <option value="cpu_usage">CPU %</option>
                      <option value="ram_used_gb">RAM Used (GB)</option>
                      <option value="disk_free_gb">Disk Free (GB)</option>
                      <option value="os_type">OS Type (windows/linux/macos)</option>
                      <option value="os_version">OS Version</option>
                      <option value="device_role">Device Role</option>
                      <option value="status">Online Status</option>
                      <option value="logged_in_user">Last Logged-On User</option>
                      <option value="ip_address">Private IP</option>
                      <option value="public_ip">Public IP</option>
                      <option value="installed_software">Installed Program</option>
                      <option value="pending_reboot">Pending Reboot (0/1)</option>
                      <option value="edr_status">EDR Status</option>
                      <option value="bitlocker_status">Disk Encryption</option>
                      <option value="hostname">Hostname</option>
                    </select>
                    <select
                      className="glass-select"
                      style={{ fontSize: '0.76rem', padding: '0.35rem 0.45rem' }}
                      value={rule.op}
                      onChange={(e) => {
                        const copy = [...newGroupRules];
                        copy[rIdx] = { ...copy[rIdx], op: e.target.value as any };
                        setNewGroupRules(copy);
                      }}
                    >
                      <option value="=">=</option>
                      <option value="!=">!=</option>
                      <option value=">">&gt;</option>
                      <option value="<">&lt;</option>
                      <option value="contains">Contains</option>
                      <option value="not_contains">Not Contains</option>
                      <option value="starts_with">Starts With</option>
                    </select>
                    <input
                      type="text"
                      required
                      className="glass-input"
                      style={{ fontSize: '0.76rem', padding: '0.35rem 0.5rem' }}
                      value={String(rule.value)}
                      onChange={(e) => {
                        const copy = [...newGroupRules];
                        copy[rIdx] = { ...copy[rIdx], value: e.target.value };
                        setNewGroupRules(copy);
                      }}
                    />
                    {newGroupRules.length > 1 && (
                      <button
                        type="button"
                        className="btn-glass btn-icon"
                        onClick={() => setNewGroupRules(newGroupRules.filter((_, idx) => idx !== rIdx))}
                      >
                        <Trash2 size={12} color="#ef4444" />
                      </button>
                    )}
                  </div>
                ))}

                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.75rem', alignSelf: 'flex-start' }}
                  onClick={() => setNewGroupRules([...newGroupRules, { field: 'os_type', op: '=', value: 'windows' }])}
                >
                  <Plus size={12} /> Add Condition Row
                </button>
              </div>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Description
                </label>
                <input
                  type="text"
                  className="glass-input"
                  placeholder="Optional description..."
                  value={newGroupDesc}
                  onChange={(e) => setNewGroupDesc(e.target.value)}
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button type="button" className="btn-glass" onClick={() => setShowNewGroupModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-glass btn-primary">
                  Save Smart Group
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Step-Up MFA Challenge for Emergency Break-Glass Sheet Export */}
      <MfaChallengeModal
        isOpen={showBreakGlassMfa}
        onClose={() => setShowBreakGlassMfa(false)}
        onSuccess={handleBreakGlassExportSuccess}
        title="Step-Up MFA: Emergency Break-Glass LAPS & BitLocker Export"
        description="Enter your 6-digit authenticator code to export all current + N-1 historical LAPS passwords and BitLocker recovery keys (including Archived endpoints)."
        secretType="laps_credential"
        deviceId="fleet-break-glass"
      />

      {/* Emergency Break-Glass Sheet Modal */}
      {breakGlassRows && (
        <div className="modal-backdrop" onClick={() => setBreakGlassRows(null)}>
          <div className="glass-modal" style={{ maxWidth: '940px' }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title" style={{ color: '#fbbf24' }}>
                <FileSpreadsheet size={20} color="#fbbf24" />
                <span>Emergency Break-Glass Recovery Sheet (LAPS + BitLocker Escrowed Keys)</span>
              </div>
              <button className="btn-glass btn-icon" onClick={() => setBreakGlassRows(null)}>
                <X size={18} />
              </button>
            </div>
            <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Includes both <strong>Active</strong> and <strong>Archived Vault</strong> endpoints so you never lose a BitLocker recovery key or LAPS password months after offboarding a machine.
              </div>
              <div className="table-wrapper" style={{ maxHeight: '360px', overflowY: 'auto' }}>
                <table className="glass-table">
                  <thead>
                    <tr>
                      <th>Hostname / State</th>
                      <th>Client / Site</th>
                      <th>LAPS Admin Account</th>
                      <th>Current Password</th>
                      <th>N-1 Previous Password</th>
                      <th>BitLocker Recovery Key</th>
                    </tr>
                  </thead>
                  <tbody>
                    {breakGlassRows.map((r) => (
                      <tr key={r.deviceId}>
                        <td>
                          <div style={{ fontWeight: 600, fontSize: '0.8rem' }}>{r.hostname}</div>
                          <span className={`status-pill ${r.lifecycleState === 'archived' ? 'status-offline' : 'status-online'}`} style={{ fontSize: '0.65rem' }}>
                            {r.lifecycleState}
                          </span>
                        </td>
                        <td style={{ fontSize: '0.76rem' }}>
                          <div>{r.tenantName}</div>
                          <div style={{ color: 'var(--text-dim)', fontSize: '0.68rem' }}>{r.siteName}</div>
                        </td>
                        <td style={{ fontSize: '0.78rem' }}>
                          <code>{r.lapsAccountName}</code>
                          {r.previousLapsAccountName && r.previousLapsAccountName !== r.lapsAccountName && (
                            <div style={{ fontSize: '0.68rem', color: '#38bdf8' }}>Prev: {r.previousLapsAccountName}</div>
                          )}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.76rem', color: '#34d399' }}>{r.currentLapsPassword}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.74rem', color: 'var(--text-muted)' }}>{r.previousLapsPassword || '—'}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.74rem', color: '#38bdf8' }}>{r.bitlockerRecoveryKey}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            <div className="modal-footer" style={{ display: 'flex', justifyContent: 'space-between' }}>
              <button className="btn-glass" onClick={downloadBreakGlassCsv}>
                <Download size={14} /> Download Plaintext Break-Glass CSV
              </button>
              <button className="btn-glass btn-primary" onClick={() => setBreakGlassRows(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

