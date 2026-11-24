import crypto from 'crypto';
import { db } from '../../db/index.js';
import { maskSecretValue, decryptVaultSecret, safeOutboundFetch } from '../vault/index.js';
import { sendAlertEmailUsingStoredSettings } from '../smtp/index.js';
import {
  getItflowRuntimeConfig,
  createItflowTicket,
  updateItflowTicket,
  addItflowTicketNote
} from '../itflow/index.js';

export interface ConditionAlertRule {
  conditionId: string;
  label: string;
  category: 'availability' | 'security' | 'hardware_storage' | 'specialty_network';
  enabled: boolean;
  thresholdValue: number;
  thresholdUnit: 'hours' | 'days' | 'percent' | 'cvss' | 'state';
  severity: 'info' | 'warning' | 'critical';
  notifyWebUi: boolean;
  notifyEmail: boolean;
  createPsaTicket: boolean;
  autoResolveTicket: boolean;
  psaNoteOnUpdate?: boolean;
  psaNoteType?: 'Internal' | 'Public';
}

export function getDefaultConditionAlertRules(tier?: string, targetId?: string | null): ConditionAlertRule[] {
  const isServerRole =
    tier === 'role' &&
    targetId &&
    (targetId.toLowerCase().includes('server') ||
      targetId.toLowerCase().includes('controller') ||
      targetId.toLowerCase().includes('hypervisor'));

  return [
    {
      conditionId: 'endpoint_offline',
      label: 'Endpoint Offline > X Duration',
      category: 'availability',
      enabled: true,
      thresholdValue: isServerRole ? 1 : 7,
      thresholdUnit: isServerRole ? 'hours' : 'days',
      severity: isServerRole ? 'critical' : 'warning',
      notifyWebUi: true,
      notifyEmail: true,
      createPsaTicket: Boolean(isServerRole),
      autoResolveTicket: true
    },
    {
      conditionId: 'disk_free_low',
      label: 'System Storage Free Space < X%',
      category: 'hardware_storage',
      enabled: true,
      thresholdValue: 10,
      thresholdUnit: 'percent',
      severity: 'critical',
      notifyWebUi: true,
      notifyEmail: true,
      createPsaTicket: true,
      autoResolveTicket: true
    },
    {
      conditionId: 'smart_disk_health',
      label: 'SMART Disk Health Warning / Predictive Failure',
      category: 'hardware_storage',
      enabled: true,
      thresholdValue: 1,
      thresholdUnit: 'state',
      severity: 'critical',
      notifyWebUi: true,
      notifyEmail: true,
      createPsaTicket: true,
      autoResolveTicket: false
    },
    {
      conditionId: 'cpu_ram_sustained',
      label: 'Sustained High CPU / RAM Load > X%',
      category: 'hardware_storage',
      enabled: true,
      thresholdValue: 90,
      thresholdUnit: 'percent',
      severity: 'warning',
      notifyWebUi: true,
      notifyEmail: false,
      createPsaTicket: false,
      autoResolveTicket: true
    },
    {
      conditionId: 'edr_av_inactive',
      label: 'EDR / Antivirus Missing, Tampered, or Disabled',
      category: 'security',
      enabled: true,
      thresholdValue: 1,
      thresholdUnit: 'state',
      severity: 'critical',
      notifyWebUi: true,
      notifyEmail: true,
      createPsaTicket: true,
      autoResolveTicket: true
    },
    {
      conditionId: 'bitlocker_unencrypted',
      label: 'BitLocker / Disk Encryption Suspended or Decrypted',
      category: 'security',
      enabled: true,
      thresholdValue: 1,
      thresholdUnit: 'state',
      severity: 'warning',
      notifyWebUi: true,
      notifyEmail: true,
      createPsaTicket: false,
      autoResolveTicket: true
    },
    {
      conditionId: 'pending_reboot_overdue',
      label: 'Pending Reboot Overdue > X Days',
      category: 'availability',
      enabled: true,
      thresholdValue: 7,
      thresholdUnit: 'days',
      severity: 'warning',
      notifyWebUi: true,
      notifyEmail: false,
      createPsaTicket: false,
      autoResolveTicket: true
    },
    {
      conditionId: 'critical_cve_detected',
      label: 'Zero-Day / Critical Software Vulnerability (CVSS >= X)',
      category: 'security',
      enabled: true,
      thresholdValue: 9.0,
      thresholdUnit: 'cvss',
      severity: 'critical',
      notifyWebUi: true,
      notifyEmail: true,
      createPsaTicket: true,
      autoResolveTicket: true
    },
    {
      conditionId: 'hardware_tamper_drift',
      label: 'Hardware Component Drift / Physical Tamper (RAM/NVMe/GPU)',
      category: 'hardware_storage',
      enabled: true,
      thresholdValue: 1,
      thresholdUnit: 'state',
      severity: 'warning',
      notifyWebUi: true,
      notifyEmail: true,
      createPsaTicket: true,
      autoResolveTicket: false
    },
    {
      conditionId: 'network_rogue_drift',
      label: 'Network / Untrusted Gateway or Rogue Subnet Drift',
      category: 'security',
      enabled: true,
      thresholdValue: 1,
      thresholdUnit: 'state',
      severity: 'warning',
      notifyWebUi: true,
      notifyEmail: true,
      createPsaTicket: false,
      autoResolveTicket: true
    },
    {
      conditionId: 'warranty_expiring',
      label: 'OEM Hardware Warranty Expiring < X Days',
      category: 'hardware_storage',
      enabled: true,
      thresholdValue: 30,
      thresholdUnit: 'days',
      severity: 'info',
      notifyWebUi: true,
      notifyEmail: true,
      createPsaTicket: false,
      autoResolveTicket: true
    },
    {
      conditionId: 'laps_secret_access',
      label: 'LAPS Admin Password Revealed or Break-Glass Sheet Exported',
      category: 'security',
      enabled: true,
      thresholdValue: 1,
      thresholdUnit: 'state',
      severity: 'info',
      notifyWebUi: true,
      notifyEmail: true,
      createPsaTicket: false,
      autoResolveTicket: true
    },
    {
      conditionId: 'specialty_appliance_state',
      label: 'Specialty / Network Appliance Offline, UPS on Battery, NAS Degraded, or SSL/WAN Alert',
      category: 'specialty_network',
      enabled: true,
      thresholdValue: 1,
      thresholdUnit: 'state',
      severity: 'critical',
      notifyWebUi: true,
      notifyEmail: true,
      createPsaTicket: true,
      autoResolveTicket: true
    }
  ];
}

export function parsePolicyAlertRules(
  rawJson?: string | null,
  tier?: string,
  targetId?: string | null
): ConditionAlertRule[] {
  const defaults = getDefaultConditionAlertRules(tier, targetId).map((r) => ({
    ...r,
    psaNoteOnUpdate: r.psaNoteOnUpdate ?? true,
    psaNoteType: r.psaNoteType ?? ('Internal' as const)
  }));
  if (!rawJson) return defaults;
  try {
    const parsed = JSON.parse(rawJson);
    if (!Array.isArray(parsed)) return defaults;
    return defaults.map((def) => {
      const match = parsed.find((p: any) => p.conditionId === def.conditionId);
      return match ? { ...def, ...match } : def;
    });
  } catch {
    return defaults;
  }
}

function mergeAlertRules(baseRules: ConditionAlertRule[], overrideJson?: string | null): ConditionAlertRule[] {
  const normalizedBase = baseRules.map((r) => ({
    ...r,
    psaNoteOnUpdate: r.psaNoteOnUpdate ?? true,
    psaNoteType: r.psaNoteType ?? ('Internal' as const)
  }));
  if (!overrideJson) return normalizedBase;
  try {
    const parsed = JSON.parse(overrideJson);
    if (!Array.isArray(parsed)) return normalizedBase;
    return normalizedBase.map((rule) => {
      const override = parsed.find((o: any) => o.conditionId === rule.conditionId);
      return override ? { ...rule, ...override } : rule;
    });
  } catch {
    return normalizedBase;
  }
}

export interface TrayMenuItem {
  id: string;
  label: string;
  type: 'message_support' | 'open_url' | 'endpoint_status' | 'copy_hostname_ip' | 'custom_info' | 'separator';
  target?: string;
  enabled: boolean;
}

const VALID_TRAY_ITEM_TYPES = new Set<TrayMenuItem['type']>([
  'message_support',
  'open_url',
  'endpoint_status',
  'copy_hostname_ip',
  'custom_info',
  'separator'
]);

export function getDefaultTrayMenuItems(): TrayMenuItem[] {
  return [
    { id: 'msg-support', label: 'Message IT Support', type: 'message_support', enabled: true },
    { id: 'copy-info', label: 'Copy Device Name & IP', type: 'copy_hostname_ip', enabled: true },
    { id: 'sep-1', label: '---', type: 'separator', enabled: true },
    { id: 'status', label: 'Endpoint Status', type: 'endpoint_status', enabled: true }
  ];
}

export function parsePolicyTrayMenuItems(rawJson?: string | null): TrayMenuItem[] {
  const defaults = getDefaultTrayMenuItems();
  if (!rawJson) return defaults;
  try {
    const parsed = typeof rawJson === 'string' ? JSON.parse(rawJson) : rawJson;
    if (!Array.isArray(parsed)) return defaults;
    const cleaned: TrayMenuItem[] = [];
    for (let i = 0; i < parsed.length; i++) {
      const item = parsed[i];
      if (!item || typeof item !== 'object') continue;
      const itemType = VALID_TRAY_ITEM_TYPES.has(item.type) ? (item.type as TrayMenuItem['type']) : 'custom_info';
      const label =
        itemType === 'separator'
          ? '---'
          : String(item.label || '').trim().slice(0, 80);
      if (!label) continue;
      const cleanItem: TrayMenuItem = {
        id: String(item.id || `tray-item-${i + 1}`).replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 48) || `tray-item-${i + 1}`,
        label,
        type: itemType,
        enabled: item.enabled !== false
      };
      if (item.target != null && String(item.target).trim()) {
        cleanItem.target = String(item.target).trim().slice(0, 500);
      }
      cleaned.push(cleanItem);
    }
    return cleaned.length > 0 ? cleaned : defaults;
  } catch {
    return defaults;
  }
}

export interface PolicyRule {
  id: string;
  name: string;
  tier: 'global' | 'quicksupport' | 'client' | 'site' | 'role';
  targetId: string | null;
  telemetryIntervalSec: number;
  requireRemoteConsent: boolean;
  consentTimeoutSec: number;
  consentTimeoutAction: 'cancel' | 'autoconnect';
  autoLockOnDisconnect: boolean;
  patchSchedule: string;
  patchRebootEnforcement: string;
  selfHealingEnabled: boolean;
  maxSnoozeHours: number;
  forceRebootAfterSnooze: boolean;
  finalCountdownSec: number;
  lapsEnabled: boolean;
  lapsAutoCreateAccount: boolean;
  lapsAccountName: string;
  lapsPasswordMode: 'random' | 'passphrase' | 'static';
  lapsPasswordLength: number;
  lapsComplexity: string;
  lapsPassphraseWords: number;
  lapsPassphraseSeparator: string;
  lapsStaticPassword?: string;
  lapsStaticPasswordRaw?: string;
  lapsRotationDays: number;
  lapsRotateOnAccess: boolean;
  lapsPostAccessGraceHours: number;
  lapsCleanupOldAccountOnRename: 'disable' | 'delete' | 'keep';
  lapsDisableBuiltinSid500Admin: boolean;
  lapsOffboardExplicitDeviceAction:
    | 'remove_account'
    | 'disable_account'
    | 'keep_account_rotate_final'
    | 'keep_account_as_is';
  lapsOffboardClientArchivedAction:
    | 'remove_account'
    | 'disable_account'
    | 'keep_account_rotate_final'
    | 'keep_account_as_is';
  lapsOffboardClientDeletedAction:
    | 'remove_account'
    | 'disable_account'
    | 'keep_account_rotate_final'
    | 'keep_account_as_is';
  offboardOfflineAutoArchiveDays: number;
  requireMfaForSecrets: boolean;
  telemetryHistoryRetentionDays: number;
  hardwareAuditEnabled: boolean;
  networkDriftDetectionEnabled: boolean;
  selfHealingMaxHourlyRuns: number;
  selfHealingAlertPsa: boolean;
  psaFlapGraceMinutes: number;
  autoPatchCveMinCvss: number;
  osPatchApprovalJson?: string;
  thirdPartyPatchApprovalJson?: string;
  requiredSoftwareJson?: string;
  defenderPolicyJson?: string;
  backupPolicyId?: string | null;
  mdmProfileId?: string | null;
  trayBrandName: string;
  trayIconUrl: string;
  trayThemeMode: 'system' | 'dark' | 'light';
  trayEnabled: boolean;
  trayTooltip: string;
  traySupportUrl: string;
  traySupportPhone: string;
  traySupportEmail: string;
  trayMenuItems: TrayMenuItem[];
  companionAutoDeploy: boolean;
  alertRules: ConditionAlertRule[];
}

export interface EffectiveDevicePolicy extends PolicyRule {
  require_mfa_for_secrets?: boolean;
  inheritanceChain: Array<{ tier: string; name: string }>;
}

export function sanitizeEffectivePolicyForResponse(eff: EffectiveDevicePolicy): EffectiveDevicePolicy {
  const copy = { ...eff };
  delete copy.lapsStaticPasswordRaw;
  return copy;
}

function buildBaseEffectivePolicy(label: string, targetId: string | null): {
  effective: EffectiveDevicePolicy;
  globalRow: any;
} {
  const globalRow = db.prepare("SELECT * FROM policies WHERE tier = 'global' LIMIT 1").get() as any;
  const settingsRow = (db
    .prepare('SELECT brand_name, brand_logo_url, tray_theme_mode FROM settings WHERE id = 1')
    .get() || {}) as { brand_name?: string; brand_logo_url?: string; tray_theme_mode?: string };
  const baseTrayTheme =
    globalRow?.tray_theme_mode === 'light' || globalRow?.tray_theme_mode === 'dark' || globalRow?.tray_theme_mode === 'system'
      ? globalRow.tray_theme_mode
      : settingsRow.tray_theme_mode === 'light' || settingsRow.tray_theme_mode === 'dark'
        ? settingsRow.tray_theme_mode
        : 'system';

  const effective: EffectiveDevicePolicy = {
    id: 'effective-' + (targetId || 'scope'),
    name: label,
    tier: 'global',
    targetId,
    telemetryIntervalSec: globalRow?.telemetry_interval_sec ?? 30,
    requireRemoteConsent: Boolean(globalRow?.require_remote_consent ?? 1),
    consentTimeoutSec: globalRow?.consent_timeout_sec ?? 30,
    consentTimeoutAction: globalRow?.consent_timeout_action ?? 'cancel',
    autoLockOnDisconnect: Boolean(globalRow?.auto_lock_on_disconnect ?? 1),
    patchSchedule: globalRow?.patch_schedule ?? 'Tuesdays @ 02:00 AM',
    patchRebootEnforcement: globalRow?.patch_reboot_enforcement ?? 'Prompt 4h, then force reboot',
    selfHealingEnabled: Boolean(globalRow?.self_healing_enabled ?? 1),
    maxSnoozeHours: globalRow?.max_snooze_hours ?? 8,
    forceRebootAfterSnooze: Boolean(globalRow?.force_reboot_after_snooze ?? 1),
    finalCountdownSec: globalRow?.final_countdown_sec ?? 300,
    lapsEnabled: Boolean(globalRow?.laps_enabled ?? 1),
    lapsAutoCreateAccount: Boolean(globalRow?.laps_auto_create_account ?? 1),
    lapsAccountName: globalRow?.laps_account_name || 'LocalAdmin',
    lapsPasswordMode: (globalRow?.laps_password_mode as 'random' | 'passphrase' | 'static') || 'random',
    lapsPasswordLength: globalRow?.laps_password_length ?? 20,
    lapsComplexity: globalRow?.laps_complexity || 'alphanumeric_symbols',
    lapsPassphraseWords: globalRow?.laps_passphrase_words ?? 5,
    lapsPassphraseSeparator: globalRow?.laps_passphrase_separator || '-',
    lapsStaticPassword: maskSecretValue(globalRow?.laps_static_password),
    lapsStaticPasswordRaw: globalRow?.laps_static_password || '',
    lapsRotationDays: globalRow?.laps_rotation_days ?? 30,
    lapsRotateOnAccess: Boolean(globalRow?.laps_rotate_on_access ?? 1),
    lapsPostAccessGraceHours: globalRow?.laps_post_access_grace_hours ?? 2,
    lapsCleanupOldAccountOnRename: (globalRow?.laps_cleanup_old_account_on_rename as any) || 'disable',
    lapsDisableBuiltinSid500Admin: Boolean(globalRow?.laps_disable_builtin_sid500_admin ?? 1),
    lapsOffboardExplicitDeviceAction: (globalRow?.laps_offboard_explicit_device_action as any) || 'remove_account',
    lapsOffboardClientArchivedAction:
      (globalRow?.laps_offboard_client_archived_action as any) || 'keep_account_rotate_final',
    lapsOffboardClientDeletedAction: (globalRow?.laps_offboard_client_deleted_action as any) || 'remove_account',
    offboardOfflineAutoArchiveDays: globalRow?.offboard_offline_auto_archive_days ?? 14,
    requireMfaForSecrets: Boolean(globalRow?.require_mfa_for_secrets ?? 1),
    require_mfa_for_secrets: Boolean(globalRow?.require_mfa_for_secrets ?? 1),
    telemetryHistoryRetentionDays: globalRow?.telemetry_history_retention_days ?? 90,
    hardwareAuditEnabled: Boolean(globalRow?.hardware_audit_enabled ?? 1),
    networkDriftDetectionEnabled: Boolean(globalRow?.network_drift_detection_enabled ?? 1),
    selfHealingMaxHourlyRuns: globalRow?.self_healing_max_hourly_runs ?? 3,
    selfHealingAlertPsa: Boolean(globalRow?.self_healing_alert_psa ?? 1),
    psaFlapGraceMinutes: globalRow?.psa_flap_grace_minutes ?? 15,
    autoPatchCveMinCvss: Number(globalRow?.auto_patch_cve_min_cvss ?? 8.0),
    osPatchApprovalJson: globalRow?.os_patch_approval_json || '{}',
    thirdPartyPatchApprovalJson: globalRow?.third_party_patch_approval_json || '{}',
    requiredSoftwareJson: globalRow?.required_software_json || '[]',
    defenderPolicyJson: globalRow?.defender_policy_json || '{}',
    backupPolicyId: globalRow?.backup_policy_id || null,
    mdmProfileId: globalRow?.mdm_profile_id || null,
    trayBrandName: String(globalRow?.tray_brand_name || settingsRow.brand_name || 'Vitrine RMM').trim(),
    trayIconUrl: String(globalRow?.tray_icon_url || settingsRow.brand_logo_url || '').trim(),
    trayThemeMode: baseTrayTheme as 'system' | 'dark' | 'light',
    trayEnabled: Boolean(globalRow?.tray_enabled ?? 1),
    trayTooltip: String(globalRow?.tray_tooltip || '').trim(),
    traySupportUrl: String(globalRow?.tray_support_url || '').trim(),
    traySupportPhone: String(globalRow?.tray_support_phone || '').trim(),
    traySupportEmail: String(globalRow?.tray_support_email || '').trim(),
    trayMenuItems: parsePolicyTrayMenuItems(globalRow?.tray_menu_items_json),
    companionAutoDeploy: Boolean(globalRow?.companion_auto_deploy ?? 0),
    alertRules: parsePolicyAlertRules(globalRow?.alert_rules_json, 'global', null),
    inheritanceChain: [{ tier: 'global', name: globalRow?.name || 'Global MSP Baseline' }]
  };

  return { effective, globalRow };
}

function resolveLapsTemplateAccount(
  effective: EffectiveDevicePolicy,
  tenantId?: string | null,
  siteId?: string | null,
  deviceRole?: string | null
): void {
  const tenantRow = tenantId
    ? (db.prepare('SELECT name, slug FROM tenants WHERE id = ?').get(tenantId) as
        | { name?: string; slug?: string }
        | undefined)
    : undefined;
  const siteRow = siteId
    ? (db.prepare('SELECT name FROM sites WHERE id = ?').get(siteId) as { name?: string } | undefined)
    : undefined;
  const clientSlugClean = (tenantRow?.slug || tenantRow?.name || 'Client').replace(/[^a-zA-Z0-9]/g, '').slice(0, 10);
  const siteSlugClean = (siteRow?.name || 'Site').replace(/[^a-zA-Z0-9]/g, '').slice(0, 8);
  const roleClean = (deviceRole || 'Endpoint').replace(/[^a-zA-Z0-9]/g, '').slice(0, 8);

  effective.lapsAccountName =
    (effective.lapsAccountName || 'LocalAdmin')
      .replace(/\{ClientSlug\}/gi, clientSlugClean)
      .replace(/\{ClientName\}/gi, clientSlugClean)
      .replace(/\{SiteSlug\}/gi, siteSlugClean)
      .replace(/\{Role\}/gi, roleClean)
      .replace(/[^a-zA-Z0-9._-]/g, '')
      .slice(0, 20) || 'LocalAdmin';
}

export function resolveEffectiveDevicePolicy(deviceId: string): EffectiveDevicePolicy {
  const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId) as any;
  if (!device) {
    throw new Error(`Device ${deviceId} not found`);
  }

  const { effective, globalRow } = buildBaseEffectivePolicy('Effective Policy for ' + device.hostname, deviceId);

  // 1b. QuickSupport Session Baseline Override (when running as temporary QuickSupport session)
  if (String(device.device_role || '').toLowerCase() === 'quicksupport') {
    const qsPolicy = db
      .prepare("SELECT * FROM policies WHERE tier = 'quicksupport' OR id = 'pol-quicksupport' LIMIT 1")
      .get() as any;
    if (qsPolicy) {
      applyOverrides(effective, qsPolicy, globalRow);
      effective.inheritanceChain.push({ tier: 'quicksupport', name: qsPolicy.name });
    }
  }

  // 2. Client Tier Override
  if (device.tenant_id) {
    const clientPolicy = db
      .prepare("SELECT * FROM policies WHERE tier = 'client' AND target_id = ?")
      .get(device.tenant_id) as any;
    if (clientPolicy) {
      applyOverrides(effective, clientPolicy, globalRow);
      effective.inheritanceChain.push({ tier: 'client', name: clientPolicy.name });
    }
  }

  // 3. Site Tier Override
  if (device.site_id) {
    const sitePolicy = db
      .prepare("SELECT * FROM policies WHERE tier = 'site' AND target_id = ?")
      .get(device.site_id) as any;
    if (sitePolicy) {
      applyOverrides(effective, sitePolicy, globalRow);
      effective.inheritanceChain.push({ tier: 'site', name: sitePolicy.name });
    }
  }

  // 4. Role Tier Override
  if (device.device_role) {
    const rolePolicy = db
      .prepare(
        "SELECT * FROM policies WHERE tier = 'role' AND (LOWER(?) = LOWER(target_id) OR LOWER(?) LIKE '%' || LOWER(target_id) || '%') LIMIT 1"
      )
      .get(device.device_role, device.device_role) as any;
    if (rolePolicy) {
      applyOverrides(effective, rolePolicy, globalRow);
      effective.inheritanceChain.push({ tier: 'role', name: rolePolicy.name });
    }
  }

  resolveLapsTemplateAccount(effective, device.tenant_id, device.site_id, device.device_role);
  return effective;
}

export function resolvePolicyForInstallerScope(scope: {
  mode?: 'permanent' | 'quicksupport' | 'companion_only';
  tenantId?: string | null;
  siteId?: string | null;
  deviceRole?: string | null;
  deviceId?: string | null;
}): EffectiveDevicePolicy {
  if (scope.deviceId) {
    const existing = db.prepare('SELECT id FROM devices WHERE id = ?').get(scope.deviceId) as { id?: string } | undefined;
    if (existing?.id) {
      return resolveEffectiveDevicePolicy(existing.id);
    }
  }

  const { effective, globalRow } = buildBaseEffectivePolicy(
    scope.mode === 'quicksupport' ? 'Effective Policy for QuickSupport' : 'Effective Installer Scope Policy',
    scope.tenantId || null
  );

  if (scope.mode === 'quicksupport') {
    const qsPolicy = db
      .prepare("SELECT * FROM policies WHERE tier = 'quicksupport' OR id = 'pol-quicksupport' LIMIT 1")
      .get() as any;
    if (qsPolicy) {
      applyOverrides(effective, qsPolicy, globalRow);
      effective.inheritanceChain.push({ tier: 'quicksupport', name: qsPolicy.name });
    }
    if (scope.tenantId && scope.tenantId !== 'default' && scope.tenantId !== 'quicksupport') {
      const clientPolicy = db
        .prepare("SELECT * FROM policies WHERE tier = 'client' AND target_id = ?")
        .get(scope.tenantId) as any;
      if (clientPolicy) {
        applyOverrides(effective, clientPolicy, globalRow);
        effective.inheritanceChain.push({ tier: 'client', name: clientPolicy.name });
      }
    }
  } else {
    if (scope.tenantId && scope.tenantId !== 'quicksupport') {
      const clientPolicy = db
        .prepare("SELECT * FROM policies WHERE tier = 'client' AND target_id = ?")
        .get(scope.tenantId) as any;
      if (clientPolicy) {
        applyOverrides(effective, clientPolicy, globalRow);
        effective.inheritanceChain.push({ tier: 'client', name: clientPolicy.name });
      }
    }
    if (scope.siteId) {
      const sitePolicy = db
        .prepare("SELECT * FROM policies WHERE tier = 'site' AND target_id = ?")
        .get(scope.siteId) as any;
      if (sitePolicy) {
        applyOverrides(effective, sitePolicy, globalRow);
        effective.inheritanceChain.push({ tier: 'site', name: sitePolicy.name });
      }
    }
    if (scope.deviceRole) {
      const rolePolicy = db
        .prepare(
          "SELECT * FROM policies WHERE tier = 'role' AND (LOWER(?) = LOWER(target_id) OR LOWER(?) LIKE '%' || LOWER(target_id) || '%') LIMIT 1"
        )
        .get(scope.deviceRole, scope.deviceRole) as any;
      if (rolePolicy) {
        applyOverrides(effective, rolePolicy, globalRow);
        effective.inheritanceChain.push({ tier: 'role', name: rolePolicy.name });
      }
    }
  }

  resolveLapsTemplateAccount(effective, scope.tenantId, scope.siteId, scope.deviceRole);
  return effective;
}

const SQLITE_POLICY_DEFAULTS: Record<string, unknown> = {
  telemetry_interval_sec: 30,
  require_remote_consent: 1,
  consent_timeout_sec: 30,
  consent_timeout_action: 'cancel',
  auto_lock_on_disconnect: 1,
  patch_schedule: 'Tuesdays @ 02:00 AM',
  patch_reboot_enforcement: 'Prompt 4h, then force reboot',
  self_healing_enabled: 1,
  max_snooze_hours: 8,
  force_reboot_after_snooze: 1,
  final_countdown_sec: 300,
  laps_enabled: 1,
  laps_auto_create_account: 1,
  laps_account_name: 'LocalAdmin',
  laps_password_mode: 'random',
  laps_password_length: 20,
  laps_complexity: 'alphanumeric_symbols',
  laps_passphrase_words: 5,
  laps_passphrase_separator: '-',
  laps_static_password: '',
  laps_rotation_days: 30,
  laps_rotate_on_access: 1,
  laps_post_access_grace_hours: 2,
  laps_cleanup_old_account_on_rename: 'disable',
  laps_disable_builtin_sid500_admin: 1,
  laps_offboard_explicit_device_action: 'remove_account',
  laps_offboard_client_archived_action: 'keep_account_rotate_final',
  laps_offboard_client_deleted_action: 'remove_account',
  offboard_offline_auto_archive_days: 14,
  require_mfa_for_secrets: 1,
  telemetry_history_retention_days: 90,
  hardware_audit_enabled: 1,
  network_drift_detection_enabled: 1,
  self_healing_max_hourly_runs: 3,
  self_healing_alert_psa: 1,
  psa_flap_grace_minutes: 15,
  auto_patch_cve_min_cvss: 8.0,
  os_patch_approval_json: '{}',
  third_party_patch_approval_json: '{}',
  required_software_json: '[]',
  defender_policy_json: '{}',
  backup_policy_id: null,
  mdm_profile_id: null,
  tray_brand_name: '',
  tray_icon_url: '',
  tray_theme_mode: '',
  tray_enabled: 1,
  tray_tooltip: '',
  tray_support_url: '',
  tray_support_phone: '',
  tray_support_email: '',
  tray_menu_items_json: null,
  companion_auto_deploy: 0
};

function applyOverrides(target: EffectiveDevicePolicy, source: any, _globalRow?: any) {
  let explicitKeys: Set<string> | null = null;
  if (source.overrides_json) {
    try {
      const parsed = JSON.parse(source.overrides_json);
      if (Array.isArray(parsed)) {
        explicitKeys = new Set(parsed);
      } else if (parsed && typeof parsed === 'object') {
        explicitKeys = new Set(Object.keys(parsed).filter((k) => parsed[k]));
      }
    } catch {
      explicitKeys = null;
    }
  }

  const shouldApply = (col: string): boolean => {
    if (source[col] == null) return false;
    if (explicitKeys) return explicitKeys.has(col);
    return source[col] !== SQLITE_POLICY_DEFAULTS[col];
  };

  if (shouldApply('telemetry_interval_sec')) target.telemetryIntervalSec = Number(source.telemetry_interval_sec);
  if (shouldApply('require_remote_consent')) target.requireRemoteConsent = Boolean(source.require_remote_consent);
  if (shouldApply('consent_timeout_sec')) target.consentTimeoutSec = Number(source.consent_timeout_sec);
  if (shouldApply('consent_timeout_action')) target.consentTimeoutAction = source.consent_timeout_action;
  if (shouldApply('auto_lock_on_disconnect')) target.autoLockOnDisconnect = Boolean(source.auto_lock_on_disconnect);
  if (shouldApply('patch_schedule')) target.patchSchedule = source.patch_schedule;
  if (shouldApply('patch_reboot_enforcement')) target.patchRebootEnforcement = source.patch_reboot_enforcement;
  if (shouldApply('self_healing_enabled')) target.selfHealingEnabled = Boolean(source.self_healing_enabled);
  if (shouldApply('max_snooze_hours')) target.maxSnoozeHours = Number(source.max_snooze_hours);
  if (shouldApply('force_reboot_after_snooze'))
    target.forceRebootAfterSnooze = Boolean(source.force_reboot_after_snooze);
  if (shouldApply('final_countdown_sec')) target.finalCountdownSec = Number(source.final_countdown_sec);
  if (shouldApply('laps_enabled')) target.lapsEnabled = Boolean(source.laps_enabled);
  if (shouldApply('laps_auto_create_account')) target.lapsAutoCreateAccount = Boolean(source.laps_auto_create_account);
  if (shouldApply('laps_account_name')) target.lapsAccountName = source.laps_account_name;
  if (shouldApply('laps_password_mode')) target.lapsPasswordMode = source.laps_password_mode;
  if (shouldApply('laps_password_length')) target.lapsPasswordLength = Number(source.laps_password_length);
  if (shouldApply('laps_complexity')) target.lapsComplexity = source.laps_complexity;
  if (shouldApply('laps_passphrase_words')) target.lapsPassphraseWords = Number(source.laps_passphrase_words);
  if (shouldApply('laps_passphrase_separator')) target.lapsPassphraseSeparator = source.laps_passphrase_separator;
  if (shouldApply('laps_static_password') && source.laps_static_password !== '') {
    target.lapsStaticPasswordRaw = source.laps_static_password;
    target.lapsStaticPassword = maskSecretValue(source.laps_static_password);
  }
  if (shouldApply('laps_rotation_days')) target.lapsRotationDays = Number(source.laps_rotation_days);
  if (shouldApply('laps_rotate_on_access')) target.lapsRotateOnAccess = Boolean(source.laps_rotate_on_access);
  if (shouldApply('laps_post_access_grace_hours'))
    target.lapsPostAccessGraceHours = Number(source.laps_post_access_grace_hours);
  if (shouldApply('laps_cleanup_old_account_on_rename'))
    target.lapsCleanupOldAccountOnRename = source.laps_cleanup_old_account_on_rename;
  if (shouldApply('laps_disable_builtin_sid500_admin'))
    target.lapsDisableBuiltinSid500Admin = Boolean(source.laps_disable_builtin_sid500_admin);
  if (shouldApply('laps_offboard_explicit_device_action'))
    target.lapsOffboardExplicitDeviceAction = source.laps_offboard_explicit_device_action;
  if (shouldApply('laps_offboard_client_archived_action'))
    target.lapsOffboardClientArchivedAction = source.laps_offboard_client_archived_action;
  if (shouldApply('laps_offboard_client_deleted_action'))
    target.lapsOffboardClientDeletedAction = source.laps_offboard_client_deleted_action;
  if (shouldApply('offboard_offline_auto_archive_days'))
    target.offboardOfflineAutoArchiveDays = Number(source.offboard_offline_auto_archive_days);
  if (shouldApply('require_mfa_for_secrets')) {
    target.requireMfaForSecrets = Boolean(source.require_mfa_for_secrets);
    target.require_mfa_for_secrets = Boolean(source.require_mfa_for_secrets);
  }
  if (shouldApply('telemetry_history_retention_days'))
    target.telemetryHistoryRetentionDays = Number(source.telemetry_history_retention_days);
  if (shouldApply('hardware_audit_enabled')) target.hardwareAuditEnabled = Boolean(source.hardware_audit_enabled);
  if (shouldApply('network_drift_detection_enabled'))
    target.networkDriftDetectionEnabled = Boolean(source.network_drift_detection_enabled);
  if (shouldApply('self_healing_max_hourly_runs'))
    target.selfHealingMaxHourlyRuns = Number(source.self_healing_max_hourly_runs);
  if (shouldApply('self_healing_alert_psa')) target.selfHealingAlertPsa = Boolean(source.self_healing_alert_psa);
  if (shouldApply('psa_flap_grace_minutes')) target.psaFlapGraceMinutes = Number(source.psa_flap_grace_minutes);
  if (shouldApply('auto_patch_cve_min_cvss')) target.autoPatchCveMinCvss = Number(source.auto_patch_cve_min_cvss);
  if (shouldApply('os_patch_approval_json')) target.osPatchApprovalJson = source.os_patch_approval_json;
  if (shouldApply('third_party_patch_approval_json'))
    target.thirdPartyPatchApprovalJson = source.third_party_patch_approval_json;
  if (shouldApply('required_software_json')) target.requiredSoftwareJson = source.required_software_json;
  if (shouldApply('defender_policy_json')) target.defenderPolicyJson = source.defender_policy_json;
  if (shouldApply('backup_policy_id')) target.backupPolicyId = source.backup_policy_id;
  if (shouldApply('mdm_profile_id')) target.mdmProfileId = source.mdm_profile_id;

  const applyNonEmptyStringOverride = (col: string, setter: (v: string) => void) => {
    if (!shouldApply(col)) return;
    const val = String(source[col] ?? '').trim();
    if (val || (explicitKeys && explicitKeys.has(col) && source[col] !== '')) {
      setter(val);
    }
  };
  applyNonEmptyStringOverride('tray_brand_name', (v) => {
    if (v) target.trayBrandName = v;
  });
  applyNonEmptyStringOverride('tray_icon_url', (v) => {
    target.trayIconUrl = v;
  });
  if (shouldApply('tray_theme_mode')) {
    const t = String(source.tray_theme_mode || '').trim();
    if (t === 'system' || t === 'dark' || t === 'light') {
      target.trayThemeMode = t;
    }
  }
  if (shouldApply('tray_enabled')) target.trayEnabled = Boolean(source.tray_enabled);
  applyNonEmptyStringOverride('tray_tooltip', (v) => {
    target.trayTooltip = v;
  });
  applyNonEmptyStringOverride('tray_support_url', (v) => {
    target.traySupportUrl = v;
  });
  applyNonEmptyStringOverride('tray_support_phone', (v) => {
    target.traySupportPhone = v;
  });
  applyNonEmptyStringOverride('tray_support_email', (v) => {
    target.traySupportEmail = v;
  });
  if (source.tray_menu_items_json && (shouldApply('tray_menu_items_json') || source.tray_menu_items_json !== null)) {
    target.trayMenuItems = parsePolicyTrayMenuItems(source.tray_menu_items_json);
  }
  if (shouldApply('companion_auto_deploy')) target.companionAutoDeploy = Boolean(source.companion_auto_deploy);

  if (source.alert_rules_json) {
    target.alertRules = mergeAlertRules(target.alertRules, source.alert_rules_json);
  }
}

function parseSqlTimestampMs(raw?: string | null): number {
  if (!raw) return NaN;
  const str = String(raw).trim();
  const normalized = str.includes('T') ? str : str.replace(' ', 'T') + (str.endsWith('Z') ? '' : 'Z');
  return new Date(normalized).getTime();
}

function escapeSqlLikePrefix(input: string): string {
  return input.replace(/[\\%_]/g, (m) => `\\${m}`);
}

export function isEntityInMaintenanceSuppression(
  deviceId?: string | null,
  tenantId?: string | null,
  maintenanceUntil?: string | null
): boolean {
  const nowIso = new Date().toISOString();
  if (maintenanceUntil && parseSqlTimestampMs(maintenanceUntil) > Date.now()) {
    return true;
  }
  const activeWin = db
    .prepare(`
      SELECT id FROM maintenance_windows
      WHERE is_active = 1
        AND suppress_alerts = 1
        AND datetime(start_time) <= datetime(?)
        AND datetime(end_time) >= datetime(?)
        AND (
          (device_id IS NOT NULL AND device_id = ?)
          OR (device_id IS NULL AND tenant_id IS NOT NULL AND tenant_id = ?)
          OR (device_id IS NULL AND tenant_id IS NULL)
        )
      LIMIT 1
    `)
    .get(nowIso, nowIso, deviceId || '', tenantId || '') as { id?: string } | undefined;

  return Boolean(activeWin);
}

// ============================================================================
// Multi-Channel Webhook Dispatcher (Slack / MS Teams / Discord / PagerDuty / Generic HMAC)
// ============================================================================
export async function dispatchAlertToNotificationChannels(alert: {
  incidentId?: string;
  tenantId?: string | null;
  entityName: string;
  clientName: string;
  conditionId: string;
  label: string;
  detail: string;
  severity: 'info' | 'warning' | 'critical';
  eventAction?: 'trigger' | 'resolve';
}): Promise<string[]> {
  const rows = db
    .prepare(
      'SELECT * FROM notification_channels WHERE enabled = 1 AND (tenant_id IS NULL OR tenant_id = ?)'
    )
    .all(alert.tenantId || '') as any[];

  const dispatchedNames: string[] = [];
  const sevRank = { info: 1, warning: 2, critical: 3 };

  for (const ch of rows) {
    const minSevKey = String(ch.min_severity || 'warning').trim().toLowerCase() as 'info' | 'warning' | 'critical';
    const minRank = sevRank[minSevKey] || 2;
    const alertSevKey = String(alert.severity || 'warning').trim().toLowerCase() as 'info' | 'warning' | 'critical';
    const alertRank = sevRank[alertSevKey] || 2;
    if (alert.eventAction !== 'resolve' && alertRank < minRank) continue;

    if (ch.events_json) {
      try {
        const parsedEvents = JSON.parse(ch.events_json);
        if (Array.isArray(parsedEvents) && parsedEvents.length > 0) {
          const eventName = alert.eventAction === 'resolve' ? 'alert.resolved' : 'alert.triggered';
          const allowed = parsedEvents.map((ev: unknown) => String(ev).trim().toLowerCase());
          const matchesEvent =
            allowed.includes('*') ||
            allowed.includes('all') ||
            allowed.includes(eventName) ||
            allowed.includes(String(alert.conditionId || '').toLowerCase()) ||
            allowed.includes(alertSevKey);
          if (!matchesEvent) continue;
        }
      } catch {}
    }

    const type = String(ch.channel_type || 'webhook').toLowerCase();
    const targetUrl = decryptVaultSecret(ch.webhook_url_encrypted) || '';
    const secret =
      decryptVaultSecret(ch.secret_encrypted) || decryptVaultSecret(ch.signing_secret_encrypted) || '';
    const routingKey = decryptVaultSecret(ch.routing_key_encrypted) || '';
    if (!targetUrl && !(type === 'pagerduty' && (routingKey || secret))) continue;

    const colorHex = alert.severity === 'critical' ? '#ef4444' : alert.severity === 'warning' ? '#f59e0b' : '#06b6d4';
    const colorInt = alert.severity === 'critical' ? 0xef4444 : alert.severity === 'warning' ? 0xf59e0b : 0x06b6d4;
    const titleText =
      alert.eventAction === 'resolve'
        ? `[RESOLVED] ${alert.label}: ${alert.entityName}`
        : `[${alert.severity.toUpperCase()}] ${alert.label}: ${alert.entityName}`;

    let bodyObj: any;
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };

    if (type === 'slack') {
      bodyObj = {
        text: `${titleText} — ${alert.detail}`,
        blocks: [
          {
            type: 'header',
            text: { type: 'plain_text', text: titleText.slice(0, 140) }
          },
          {
            type: 'section',
            fields: [
              { type: 'mrkdwn', text: `*Endpoint:*\n${alert.entityName}` },
              { type: 'mrkdwn', text: `*Client:*\n${alert.clientName}` },
              { type: 'mrkdwn', text: `*Condition:*\n${alert.label}` },
              { type: 'mrkdwn', text: `*Severity:*\n${alert.severity.toUpperCase()}` }
            ]
          },
          {
            type: 'section',
            text: { type: 'mrkdwn', text: alert.detail }
          }
        ]
      };
    } else if (type === 'teams') {
      bodyObj = {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        themeColor: colorHex.replace('#', ''),
        summary: titleText,
        sections: [
          {
            activityTitle: titleText,
            activitySubtitle: `Client: ${alert.clientName}`,
            facts: [
              { name: 'Endpoint', value: alert.entityName },
              { name: 'Severity', value: alert.severity.toUpperCase() },
              { name: 'Details', value: alert.detail }
            ],
            markdown: true
          }
        ]
      };
    } else if (type === 'discord') {
      bodyObj = {
        embeds: [
          {
            title: titleText,
            description: alert.detail,
            color: colorInt,
            fields: [
              { name: 'Client', value: alert.clientName, inline: true },
              { name: 'Severity', value: alert.severity.toUpperCase(), inline: true }
            ],
            timestamp: new Date().toISOString()
          }
        ]
      };
    } else if (type === 'pagerduty') {
      bodyObj = {
        routing_key: routingKey || secret || targetUrl,
        event_action: alert.eventAction === 'resolve' ? 'resolve' : 'trigger',
        dedup_key: `vitrine-${alert.conditionId}-${alert.entityName}`,
        payload: {
          summary: `${titleText} — ${alert.detail}`.slice(0, 1000),
          source: alert.entityName,
          severity: alert.severity === 'critical' ? 'critical' : alert.severity === 'warning' ? 'warning' : 'info',
          custom_details: {
            client: alert.clientName,
            conditionId: alert.conditionId,
            incidentId: alert.incidentId
          }
        }
      };
    } else {
      bodyObj = {
        event: alert.eventAction === 'resolve' ? 'alert.resolved' : 'alert.triggered',
        incidentId: alert.incidentId || null,
        timestamp: new Date().toISOString(),
        severity: alert.severity,
        conditionId: alert.conditionId,
        label: alert.label,
        entityName: alert.entityName,
        clientName: alert.clientName,
        detail: alert.detail
      };
    }

    const rawBody = JSON.stringify(bodyObj);
    if (secret && type !== 'pagerduty') {
      const sig = crypto.createHmac('sha256', secret).update(rawBody, 'utf8').digest('hex');
      headers['X-Vitrine-Signature-256'] = `sha256=${sig}`;
    }

    try {
      const targetEndpoint =
        type === 'pagerduty' && !targetUrl.startsWith('http')
          ? 'https://events.pagerduty.com/v2/enqueue'
          : targetUrl;
      const res = await safeOutboundFetch(targetEndpoint, {
        method: 'POST',
        headers,
        body: rawBody,
        timeoutMs: 6000,
        safety: { allowLoopback: false, allowPrivateLan: false }
      });
      const nowIso = new Date().toISOString();
      if (res.status >= 200 && res.status < 300) {
        dispatchedNames.push(`${ch.name} (${type})`);
        try {
          db.prepare('UPDATE notification_channels SET last_triggered_at = ?, last_status = ? WHERE id = ?').run(
            nowIso,
            'OK',
            ch.id
          );
        } catch {}
      } else {
        try {
          db.prepare('UPDATE notification_channels SET last_triggered_at = ?, last_status = ? WHERE id = ?').run(
            nowIso,
            `HTTP ${res.status}`,
            ch.id
          );
        } catch {}
      }
    } catch (err: any) {
      try {
        db.prepare('UPDATE notification_channels SET last_triggered_at = ?, last_status = ? WHERE id = ?').run(
          new Date().toISOString(),
          String(err?.message || 'Webhook delivery failed').slice(0, 180),
          ch.id
        );
      } catch {}
    }
  }

  return dispatchedNames;
}

// ============================================================================
// Multi-PSA Connector Ticket Dispatcher (ITFlow, HaloPSA, ConnectWise, Autotask, Syncro, Zammad)
// ============================================================================
export async function syncTicketWithExternalPsas(ticket: {
  localTicketId?: string;
  ticketNumber: string;
  title: string;
  clientName: string;
  priority: string;
  details?: string;
  deviceId?: string | null;
  tenantId?: string | null;
}): Promise<void> {
  const detailsText =
    ticket.details ||
    `Created automatically by Vitrine RMM Condition Engine (${ticket.ticketNumber}) for client ${ticket.clientName}.`;

  // 1. Unified ITFlow Service Connector (client/asset-linked) or fallback legacy ITFlow settings connector
  const itflowCfg = getItflowRuntimeConfig();
  let handledByUnifiedItflow = false;
  if (itflowCfg.enabled && ticket.localTicketId) {
    try {
      const existingTkt = db
        .prepare('SELECT external_provider, external_ticket_id FROM psa_tickets WHERE id = ?')
        .get(ticket.localTicketId) as { external_provider?: string; external_ticket_id?: string } | undefined;
      if (existingTkt?.external_provider === 'itflow' && existingTkt?.external_ticket_id) {
        handledByUnifiedItflow = true;
      } else {
        const res = await createItflowTicket({
          localTicketId: ticket.localTicketId,
          tenantId: ticket.tenantId,
          deviceId: ticket.deviceId,
          clientName: ticket.clientName,
          subject: ticket.title,
          details: detailsText,
          priority: ticket.priority
        });
        if (res.ok) handledByUnifiedItflow = true;
      }
    } catch {}
  } else {
    try {
      const settings = db.prepare('SELECT itflow_url, itflow_api_key FROM settings WHERE id = 1').get() as any;
      const apiKey = decryptVaultSecret(settings?.itflow_api_key);
      if (settings?.itflow_url && apiKey && !settings.itflow_url.includes('itflow.internal')) {
        await safeOutboundFetch(`${settings.itflow_url.replace(/\/$/, '')}/tickets/create.php`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            api_key: apiKey,
            ticket_subject: ticket.title,
            ticket_priority: ticket.priority,
            ticket_details: detailsText
          }),
          timeoutMs: 5000,
          safety: { allowLoopback: true, allowPrivateLan: true }
        });
      }
    } catch {}
  }

  // 2. Multi-PSA Integrations Table (`psa_integrations`)
  let integrations: any[] = [];
  try {
    integrations = db.prepare('SELECT * FROM psa_integrations WHERE enabled = 1').all() as any[];
  } catch {
    return;
  }
  for (const psa of integrations) {
    const baseUrl = String(psa.base_url || '').trim().replace(/\/$/, '');
    const apiKey =
      decryptVaultSecret(psa.api_key_encrypted) || decryptVaultSecret(psa.api_secret_encrypted) || '';
    const clientSecret = decryptVaultSecret(psa.client_secret_encrypted) || '';
    if (!baseUrl || (!apiKey && !clientSecret)) continue;

    const provider = String(psa.provider || '').toLowerCase();
    if (provider === 'itflow' && handledByUnifiedItflow) {
      continue;
    }
    try {
      let endpoint = `${baseUrl}/api/tickets`;
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      let payload: any = { subject: ticket.title, body: detailsText, priority: ticket.priority };

      if (provider === 'halopsa') {
        endpoint = `${baseUrl}/api/Tickets`;
        headers.Authorization = `Bearer ${apiKey}`;
        payload = [{ summary: ticket.title, details: detailsText, priority_id: ticket.priority === 'Critical' ? 1 : 2 }];
      } else if (provider === 'connectwise') {
        endpoint = `${baseUrl}/v4_6_release/apis/3.0/service/tickets`;
        headers.Authorization = `Basic ${Buffer.from(`${psa.client_id || ''}:${apiKey}`).toString('base64')}`;
        if (clientSecret) headers.clientId = clientSecret;
        payload = { summary: ticket.title.slice(0, 100), initialDescription: detailsText };
      } else if (provider === 'autotask') {
        endpoint = `${baseUrl}/ATServicesRest/V1.0/Tickets`;
        headers.ApiIntegrationCode = psa.client_id || '';
        headers.UserName = psa.default_board || '';
        headers.Secret = apiKey;
        payload = { title: ticket.title, description: detailsText, status: 1, priority: 1 };
      } else if (provider === 'syncro') {
        endpoint = `${baseUrl}/api/v1/tickets`;
        headers.Authorization = `Bearer ${apiKey}`;
        payload = { subject: ticket.title, problem_type: 'RMM Alert', status: 'New', comment_body: detailsText };
      } else if (provider === 'zammad') {
        endpoint = `${baseUrl}/api/v1/tickets`;
        headers.Authorization = `Token token=${apiKey}`;
        payload = {
          title: ticket.title,
          group: psa.default_board || 'Users',
          article: { subject: ticket.title, body: detailsText, type: 'note', internal: false }
        };
      } else if (provider === 'itflow') {
        endpoint = `${baseUrl}/tickets/create.php`;
        payload = {
          api_key: apiKey,
          ticket_subject: ticket.title,
          ticket_priority: ticket.priority,
          ticket_details: detailsText
        };
      } else {
        headers.Authorization = `Bearer ${apiKey}`;
      }

      const res = await safeOutboundFetch(endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        timeoutMs: 6000,
        safety: { allowLoopback: true, allowPrivateLan: true }
      });
      const syncIso = new Date().toISOString();
      if (res.status >= 200 && res.status < 300) {
        try {
          db.prepare(
            "UPDATE psa_integrations SET last_synced_at = ?, last_status = 'OK', last_error = NULL WHERE id = ?"
          ).run(syncIso, psa.id);
        } catch {
          try {
            db.prepare("UPDATE psa_integrations SET last_synced_at = ?, last_status = 'OK' WHERE id = ?").run(
              syncIso,
              psa.id
            );
          } catch {}
        }
      } else {
        const errMsg = `HTTP ${res.status}`;
        try {
          db.prepare('UPDATE psa_integrations SET last_status = ?, last_error = ? WHERE id = ?').run(
            errMsg,
            errMsg,
            psa.id
          );
        } catch {
          try {
            db.prepare('UPDATE psa_integrations SET last_status = ? WHERE id = ?').run(errMsg, psa.id);
          } catch {}
        }
      }
    } catch (err: any) {
      const errMsg = String(err?.message || 'PSA sync error').slice(0, 180);
      try {
        db.prepare('UPDATE psa_integrations SET last_status = ?, last_error = ? WHERE id = ?').run(
          errMsg,
          errMsg,
          psa.id
        );
      } catch {
        try {
          db.prepare('UPDATE psa_integrations SET last_status = ? WHERE id = ?').run(errMsg, psa.id);
        } catch {}
      }
    }
  }
}

export async function evaluateFleetAlertConditions(): Promise<{
  success: boolean;
  evaluatedDevices: number;
  evaluatedAppliances: number;
  suppressedByMaintenance: number;
  autoResolvedTickets: number;
  triggeredConditions: Array<{
    entityName: string;
    conditionId: string;
    label: string;
    detail: string;
    severity: string;
    channelsDispatched: string[];
  }>;
  webUiNotificationsCreated: number;
  emailsDispatched: number;
  psaTicketsCreated: number;
}> {
  const activeDevices = db
    .prepare(
      "SELECT d.*, t.name as tenant_name FROM devices d LEFT JOIN tenants t ON d.tenant_id = t.id WHERE COALESCE(d.lifecycle_state, 'active') = 'active'"
    )
    .all() as any[];
  const appliances = db
    .prepare('SELECT a.*, t.name as tenant_name FROM network_appliances a LEFT JOIN tenants t ON a.tenant_id = t.id')
    .all() as any[];

  const triggeredConditions: Array<{
    entityName: string;
    conditionId: string;
    label: string;
    detail: string;
    severity: string;
    channelsDispatched: string[];
  }> = [];

  let webUiNotificationsCreated = 0;
  let emailsDispatched = 0;
  let psaTicketsCreated = 0;
  let suppressedByMaintenance = 0;
  let autoResolvedTickets = 0;

  const autoResolveConditionState = async (
    entityId: string,
    entityName: string,
    clientName: string,
    rule: ConditionAlertRule,
    isAppliance = false,
    tenantId?: string | null
  ) => {
    // 1. Resolve open alert_incidents row if present
    const openInc = db
      .prepare(
        "SELECT id FROM alert_incidents WHERE condition_id = ? AND ((? = 0 AND device_id = ?) OR (? = 1 AND appliance_id = ?)) AND status != 'resolved' LIMIT 1"
      )
      .get(rule.conditionId, isAppliance ? 1 : 0, entityId, isAppliance ? 1 : 0, entityId) as { id?: string } | undefined;

    if (openInc?.id) {
      db.prepare("UPDATE alert_incidents SET status = 'resolved', resolved_at = ? WHERE id = ?").run(
        new Date().toISOString(),
        openInc.id
      );
      await dispatchAlertToNotificationChannels({
        incidentId: openInc.id,
        tenantId,
        entityName,
        clientName,
        conditionId: rule.conditionId,
        label: rule.label,
        detail: 'Condition cleared automatically on endpoint telemetry recovery.',
        severity: rule.severity,
        eventAction: 'resolve'
      });
    }

    // 2. Scoped PSA ticket auto-resolution (strictly scoped by device_id or client_name + escaped LIKE!)
    if (!rule.autoResolveTicket) return;
    const escapedPrefix = escapeSqlLikePrefix(`[${rule.label}] ${entityName}:`);
    const openTicketsToResolve = (isAppliance
      ? db
          .prepare(
            "SELECT id, external_provider, external_ticket_id FROM psa_tickets WHERE status != 'Resolved' AND status != 'Closed' AND client_name = ? AND title LIKE ? ESCAPE '\\'"
          )
          .all(clientName || 'Global MSP', `${escapedPrefix}%`)
      : db
          .prepare(
            "SELECT id, external_provider, external_ticket_id FROM psa_tickets WHERE status != 'Resolved' AND status != 'Closed' AND device_id = ? AND title LIKE ? ESCAPE '\\'"
          )
          .all(entityId, `${escapedPrefix}%`)) as Array<{
      id: string;
      external_provider?: string | null;
      external_ticket_id?: string | null;
    }>;

    const res = isAppliance
      ? db
          .prepare(
            "UPDATE psa_tickets SET status = 'Resolved', updated_at = CURRENT_TIMESTAMP WHERE status != 'Resolved' AND status != 'Closed' AND client_name = ? AND title LIKE ? ESCAPE '\\'"
          )
          .run(clientName || 'Global MSP', `${escapedPrefix}%`)
      : db
          .prepare(
            "UPDATE psa_tickets SET status = 'Resolved', updated_at = CURRENT_TIMESTAMP WHERE status != 'Resolved' AND status != 'Closed' AND device_id = ? AND title LIKE ? ESCAPE '\\'"
          )
          .run(entityId, `${escapedPrefix}%`);
    if (res.changes > 0) {
      autoResolvedTickets += res.changes;
      for (const tkt of openTicketsToResolve) {
        if (tkt.external_provider === 'itflow' && tkt.external_ticket_id) {
          await addItflowTicketNote({
            localTicketId: tkt.id,
            author: 'Vitrine Condition Engine',
            body: `Condition cleared automatically on endpoint telemetry recovery (${rule.label} on ${entityName}).`,
            noteType: rule.psaNoteType === 'Public' ? 'Public' : 'Internal',
            status: 'Resolved'
          }).catch(() => {});
          await updateItflowTicket(tkt.id, { status: 'Resolved' }).catch(() => {});
        }
      }
    }
  };

  const dispatchConditionAlert = async (
    entityId: string,
    entityName: string,
    clientName: string,
    rule: ConditionAlertRule,
    detail: string,
    flapGraceMinutes = 15,
    tenantId?: string | null,
    isAppliance = false
  ) => {
    if (!rule.enabled) return;

    const resolvedTenantId =
      tenantId !== undefined
        ? tenantId
        : isAppliance
        ? ((db.prepare('SELECT tenant_id FROM network_appliances WHERE id = ?').get(entityId) as any)?.tenant_id ?? null)
        : ((db.prepare('SELECT tenant_id FROM devices WHERE id = ?').get(entityId) as any)?.tenant_id ?? null);

    const nowIso = new Date().toISOString();

    // Upsert stateful alert_incidents record (respecting snoozed & acknowledged states!)
    const existingInc = db
      .prepare(
        "SELECT * FROM alert_incidents WHERE condition_id = ? AND ((? = 0 AND device_id = ?) OR (? = 1 AND appliance_id = ?)) AND status != 'resolved' LIMIT 1"
      )
      .get(rule.conditionId, isAppliance ? 1 : 0, entityId, isAppliance ? 1 : 0, entityId) as any;

    let incidentId = existingInc?.id as string | undefined;
    let suppressedBySnoozeOrAck = false;

    if (existingInc) {
      if (existingInc.status === 'snoozed' && existingInc.snoozed_until && parseSqlTimestampMs(existingInc.snoozed_until) > Date.now()) {
        suppressedBySnoozeOrAck = true;
      } else if (existingInc.status === 'snoozed') {
        db.prepare("UPDATE alert_incidents SET status = 'open', snoozed_until = NULL WHERE id = ?").run(existingInc.id);
      }
      if (existingInc.status === 'acknowledged') {
        suppressedBySnoozeOrAck = true;
      }
      db.prepare(`
        UPDATE alert_incidents
        SET detail = ?, severity = ?, last_seen_at = ?, occurrence_count = COALESCE(occurrence_count, 1) + 1
        WHERE id = ?
      `).run(detail, rule.severity, nowIso, existingInc.id);
    } else {
      incidentId = `inc-${crypto.randomUUID()}`;
      db.prepare(`
        INSERT INTO alert_incidents (
          id, tenant_id, device_id, appliance_id, entity_name, condition_id, title, detail, severity, status, first_seen_at, last_seen_at, occurrence_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, 1)
      `).run(
        incidentId,
        resolvedTenantId,
        isAppliance ? null : entityId,
        isAppliance ? entityId : null,
        entityName,
        rule.conditionId,
        `${rule.label}: ${entityName}`,
        detail,
        rule.severity,
        nowIso,
        nowIso
      );
    }

    if (suppressedBySnoozeOrAck) {
      return;
    }

    // Deduplicate alerts via `alert_incidents` (not UI `notifications`!) within flapGraceMinutes
    const graceMs = Math.max(1, flapGraceMinutes) * 60 * 1000;
    const prevSeenMs = existingInc ? parseSqlTimestampMs(existingInc.last_seen_at) : NaN;
    const isDeduplicated = Boolean(existingInc && !Number.isNaN(prevSeenMs) && Date.now() - prevSeenMs < graceMs);
    const expectedTitlePrefix = `[${rule.severity.toUpperCase()}] ${rule.label}: ${entityName}`;

    const channels: string[] = [];

    if (rule.notifyWebUi && !isDeduplicated) {
      channels.push('Web UI Notification');
      webUiNotificationsCreated++;
      db.prepare(`
        INSERT INTO notifications (id, tenant_id, type, title, message, severity)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(
        `notif-cond-${crypto.randomUUID()}`,
        resolvedTenantId,
        rule.conditionId,
        expectedTitlePrefix,
        `${detail} (${clientName || 'Global MSP'})`,
        rule.severity
      );
    }

    if (rule.notifyEmail && !isDeduplicated) {
      const emailRes = await sendAlertEmailUsingStoredSettings({
        subject: `${expectedTitlePrefix}`,
        headline: `${rule.label} — ${entityName}`,
        bodyContent: `${detail}\nClient: ${clientName || 'Global MSP'}`,
        severity: rule.severity === 'critical' ? 'Critical' : rule.severity === 'warning' ? 'Warning' : 'Info',
        targetDevice: entityName
      });
      if (emailRes.dispatched) {
        channels.push('Email Dispatch');
        emailsDispatched++;
      }
    }

    if (!isDeduplicated) {
      const webhookSent = await dispatchAlertToNotificationChannels({
        incidentId,
        tenantId: resolvedTenantId,
        entityName,
        clientName: clientName || 'Global MSP',
        conditionId: rule.conditionId,
        label: rule.label,
        detail,
        severity: rule.severity,
        eventAction: 'trigger'
      });
      channels.push(...webhookSent);
    }

    if (rule.createPsaTicket) {
      const ticketPrefix = `[${rule.label}] ${entityName}:`;
      const escapedPrefix = escapeSqlLikePrefix(ticketPrefix);
      const existingOpenTicket = isAppliance
        ? (db
            .prepare(
              "SELECT id FROM psa_tickets WHERE status != 'Resolved' AND client_name = ? AND title LIKE ? ESCAPE '\\' LIMIT 1"
            )
            .get(clientName || 'Global MSP', `${escapedPrefix}%`) as { id?: string } | undefined)
        : (db
            .prepare(
              "SELECT id FROM psa_tickets WHERE status != 'Resolved' AND device_id = ? AND title LIKE ? ESCAPE '\\' LIMIT 1"
            )
            .get(entityId, `${escapedPrefix}%`) as { id?: string } | undefined);

      if (!existingOpenTicket) {
        channels.push('Direct PSA Ticket');
        psaTicketsCreated++;
        const ticketNum = `INC-${crypto.randomInt(10000, 99999)}`;
        const priority = rule.severity === 'critical' ? 'Critical' : rule.severity === 'warning' ? 'High' : 'Medium';
        const fullTitle = `${ticketPrefix} ${detail}`;
        const localTicketId = `tkt-cond-${crypto.randomUUID()}`;

        db.prepare(`
          INSERT INTO psa_tickets (id, ticket_number, title, description, client_name, device_id, status, priority)
          VALUES (?, ?, ?, ?, ?, ?, 'Open', ?)
        `).run(
          localTicketId,
          ticketNum,
          fullTitle,
          detail,
          clientName || 'Global MSP',
          isAppliance ? null : entityId,
          priority
        );

        if (incidentId) {
          db.prepare('UPDATE alert_incidents SET psa_ticket_id = ? WHERE id = ?').run(localTicketId, incidentId);
        }

        await syncTicketWithExternalPsas({
          localTicketId,
          ticketNumber: ticketNum,
          title: fullTitle,
          details: detail,
          clientName: clientName || 'Global MSP',
          priority,
          deviceId: isAppliance ? null : entityId,
          tenantId: resolvedTenantId
        });
      } else if (!isDeduplicated && rule.psaNoteOnUpdate !== false && existingOpenTicket?.id) {
        await addItflowTicketNote({
          localTicketId: existingOpenTicket.id,
          author: 'Vitrine Condition Engine',
          body: `[Condition Active Update — ${rule.label}] ${detail}`,
          noteType: rule.psaNoteType === 'Public' ? 'Public' : 'Internal'
        }).catch(() => {});
      }
    }

    triggeredConditions.push({
      entityName,
      conditionId: rule.conditionId,
      label: rule.label,
      detail,
      severity: rule.severity,
      channelsDispatched: channels.length > 0 ? channels : ['Active (Deduplicated within Grace Window)']
    });
  };

  for (const d of activeDevices) {
    if (isEntityInMaintenanceSuppression(d.id, d.tenant_id, d.maintenance_until)) {
      suppressedByMaintenance++;
      continue;
    }

    let eff: EffectiveDevicePolicy;
    try {
      eff = resolveEffectiveDevicePolicy(d.id);
    } catch {
      continue;
    }

    const clientLabel = d.tenant_name || 'Unassigned Client';
    const graceMin = eff.psaFlapGraceMinutes || 15;
    const findRule = (id: string) => eff.alertRules.find((r) => r.conditionId === id);

    // 1. Endpoint Offline > X Duration
    const offlineRule = findRule('endpoint_offline');
    if (offlineRule && offlineRule.enabled) {
      if (d.status !== 'online') {
        const lastSeenMs = parseSqlTimestampMs(d.last_seen);
        const offlineHours = Number.isNaN(lastSeenMs) ? 0 : Math.max(0, (Date.now() - lastSeenMs) / (1000 * 3600));
        const thresholdHours =
          offlineRule.thresholdUnit === 'days' ? offlineRule.thresholdValue * 24 : offlineRule.thresholdValue;
        if (offlineHours >= thresholdHours) {
          await dispatchConditionAlert(
            d.id,
            d.hostname,
            clientLabel,
            offlineRule,
            `Endpoint has been offline for ${offlineHours.toFixed(1)}h (threshold: > ${offlineRule.thresholdValue} ${offlineRule.thresholdUnit})`,
            graceMin,
            d.tenant_id
          );
        }
      } else {
        await autoResolveConditionState(d.id, d.hostname, clientLabel, offlineRule, false, d.tenant_id);
      }
    }

    // 2. Low Disk Free %
    const diskPct = d.disk_total_gb > 0 ? (d.disk_free_gb / d.disk_total_gb) * 100 : 100;
    const diskRule = findRule('disk_free_low');
    if (diskRule && diskRule.enabled) {
      if (diskPct < diskRule.thresholdValue) {
        await dispatchConditionAlert(
          d.id,
          d.hostname,
          clientLabel,
          diskRule,
          `System disk free space is ${diskPct.toFixed(1)}% (< ${diskRule.thresholdValue}% policy threshold)`,
          graceMin,
          d.tenant_id
        );
      } else {
        await autoResolveConditionState(d.id, d.hostname, clientLabel, diskRule, false, d.tenant_id);
      }
    }

    // 3. SMART Disk Health
    const smartRule = findRule('smart_disk_health');
    if (smartRule && smartRule.enabled) {
      if (d.smart_status && d.smart_status !== 'Healthy') {
        await dispatchConditionAlert(
          d.id,
          d.hostname,
          clientLabel,
          smartRule,
          `SMART disk telemetry reported status: ${d.smart_status}`,
          graceMin,
          d.tenant_id
        );
      } else {
        await autoResolveConditionState(d.id, d.hostname, clientLabel, smartRule, false, d.tenant_id);
      }
    }

    // 4. Sustained High CPU / RAM Load > X%
    const loadRule = findRule('cpu_ram_sustained');
    if (loadRule && loadRule.enabled && d.status === 'online') {
      const ramPct = d.ram_total_gb > 0 ? (d.ram_used_gb / d.ram_total_gb) * 100 : 0;
      if (d.cpu_usage >= loadRule.thresholdValue || ramPct >= loadRule.thresholdValue) {
        await dispatchConditionAlert(
          d.id,
          d.hostname,
          clientLabel,
          loadRule,
          `Resource utilization exceeded ${loadRule.thresholdValue}% (CPU: ${Number(d.cpu_usage).toFixed(1)}%, RAM: ${ramPct.toFixed(1)}%)`,
          graceMin,
          d.tenant_id
        );
      } else {
        await autoResolveConditionState(d.id, d.hostname, clientLabel, loadRule, false, d.tenant_id);
      }
    }

    // 5. EDR / Antivirus Missing, Tampered, or Disabled
    const edrRule = findRule('edr_av_inactive');
    if (edrRule && edrRule.enabled) {
      const edrBad =
        !d.edr_status || /disabled|inactive|tamper|missing|stopped|unprotected|outdated/i.test(d.edr_status);
      if (edrBad && d.edr_status !== 'Unknown') {
        await dispatchConditionAlert(
          d.id,
          d.hostname,
          clientLabel,
          edrRule,
          `EDR/AV sensor (${d.edr_name || 'Endpoint Protection'}) status: '${d.edr_status}'`,
          graceMin,
          d.tenant_id
        );
      } else if (!edrBad) {
        await autoResolveConditionState(d.id, d.hostname, clientLabel, edrRule, false, d.tenant_id);
      }
    }

    // 6. BitLocker / Disk Encryption Unencrypted
    const bitRule = findRule('bitlocker_unencrypted');
    if (bitRule && bitRule.enabled) {
      const unencrypted =
        d.bitlocker_status &&
        d.bitlocker_status !== 'Unknown' &&
        (!/encrypted|protectionon|active|on/i.test(d.bitlocker_status) ||
          /unencrypted|suspended|decrypted|off/i.test(d.bitlocker_status));
      if (unencrypted) {
        await dispatchConditionAlert(
          d.id,
          d.hostname,
          clientLabel,
          bitRule,
          `Disk encryption state is '${d.bitlocker_status}'`,
          graceMin,
          d.tenant_id
        );
      } else if (
        d.bitlocker_status &&
        /encrypted|on|active|protectionon/i.test(d.bitlocker_status) &&
        !/unencrypted|suspended|decrypted|off/i.test(d.bitlocker_status)
      ) {
        await autoResolveConditionState(d.id, d.hostname, clientLabel, bitRule, false, d.tenant_id);
      }
    }

    // 7. Pending Reboot Overdue > X Days
    const rebRule = findRule('pending_reboot_overdue');
    if (rebRule && rebRule.enabled) {
      if (Boolean(d.pending_reboot || d.reboot_required)) {
        const sinceIso = d.pending_reboot_since || d.enrolled_at || d.created_at;
        const sinceMs = parseSqlTimestampMs(sinceIso);
        const pendingDays = !Number.isNaN(sinceMs) ? (Date.now() - sinceMs) / (1000 * 86400) : rebRule.thresholdValue;
        if (pendingDays >= rebRule.thresholdValue) {
          await dispatchConditionAlert(
            d.id,
            d.hostname,
            clientLabel,
            rebRule,
            `Pending reboot overdue for ${pendingDays.toFixed(1)} days (threshold: > ${rebRule.thresholdValue} days)`,
            graceMin,
            d.tenant_id
          );
        }
      } else {
        await autoResolveConditionState(d.id, d.hostname, clientLabel, rebRule, false, d.tenant_id);
      }
    }

    // 8. Critical CVE Detected (CVSS >= X)
    const cveRule = findRule('critical_cve_detected');
    if (cveRule && cveRule.enabled) {
      const critPatch = db
        .prepare(
          "SELECT kb_id, cve_id, cvss_score FROM patches WHERE device_id = ? AND status != 'Installed' AND COALESCE(is_blacklisted, 0) = 0 AND COALESCE(cvss_score, 0) >= ? ORDER BY cvss_score DESC LIMIT 1"
        )
        .get(d.id, cveRule.thresholdValue) as { kb_id?: string; cve_id?: string; cvss_score?: number } | undefined;
      const critSoft = db
        .prepare(
          'SELECT name, highest_cvss FROM software_inventory WHERE device_id = ? AND cve_count > 0 AND highest_cvss >= ? ORDER BY highest_cvss DESC LIMIT 1'
        )
        .get(d.id, cveRule.thresholdValue) as { name?: string; highest_cvss?: number } | undefined;

      if (critPatch || critSoft) {
        const desc = critPatch
          ? `Unpatched ${critPatch.cve_id || critPatch.kb_id} (CVSS ${critPatch.cvss_score})`
          : `Vulnerable package ${critSoft?.name} (CVSS ${critSoft?.highest_cvss})`;
        await dispatchConditionAlert(d.id, d.hostname, clientLabel, cveRule, desc, graceMin, d.tenant_id);
      } else {
        await autoResolveConditionState(d.id, d.hostname, clientLabel, cveRule, false, d.tenant_id);
      }
    }

    // 9. Hardware Component Drift / Physical Tamper
    const hwRule = findRule('hardware_tamper_drift');
    if (hwRule && hwRule.enabled && eff.hardwareAuditEnabled) {
      const unackHw = db
        .prepare(
          'SELECT change_type, description FROM hardware_history WHERE device_id = ? AND COALESCE(acknowledged, 0) = 0 ORDER BY timestamp DESC LIMIT 1'
        )
        .get(d.id) as { change_type?: string; description?: string } | undefined;
      if (unackHw) {
        await dispatchConditionAlert(
          d.id,
          d.hostname,
          clientLabel,
          hwRule,
          `Hardware change detected (${unackHw.change_type}): ${unackHw.description}`,
          graceMin,
          d.tenant_id
        );
      } else {
        await autoResolveConditionState(d.id, d.hostname, clientLabel, hwRule, false, d.tenant_id);
      }
    }

    // 10. Network / Untrusted Gateway or Rogue Subnet Drift
    const netRule = findRule('network_rogue_drift');
    if (netRule && netRule.enabled && eff.networkDriftDetectionEnabled) {
      const driftNet = db
        .prepare(
          'SELECT ssid, subnet, gateway_ip FROM network_history WHERE device_id = ? AND is_flagged_drift = 1 AND disconnected_at IS NULL ORDER BY connected_at DESC LIMIT 1'
        )
        .get(d.id) as { ssid?: string; subnet?: string; gateway_ip?: string } | undefined;
      if (driftNet) {
        await dispatchConditionAlert(
          d.id,
          d.hostname,
          clientLabel,
          netRule,
          `Connected to untrusted network (${driftNet.ssid || driftNet.subnet || driftNet.gateway_ip})`,
          graceMin,
          d.tenant_id
        );
      } else {
        await autoResolveConditionState(d.id, d.hostname, clientLabel, netRule, false, d.tenant_id);
      }
    }

    // 11. OEM Hardware Warranty Expiring < X Days
    const warRule = findRule('warranty_expiring');
    if (warRule && warRule.enabled) {
      const war = db
        .prepare('SELECT warranty_expiration, manufacturer FROM oem_warranties WHERE device_id = ?')
        .get(d.id) as { warranty_expiration?: string; manufacturer?: string } | undefined;
      const expDateStr = war?.warranty_expiration || d.warranty_expiration;
      if (expDateStr) {
        const daysLeft = (new Date(expDateStr).getTime() - Date.now()) / (1000 * 86400);
        if (daysLeft <= warRule.thresholdValue) {
          await dispatchConditionAlert(
            d.id,
            d.hostname,
            clientLabel,
            warRule,
            daysLeft < 0
              ? `OEM warranty expired ${Math.abs(Math.round(daysLeft))} days ago (${expDateStr})`
              : `OEM warranty expires in ${Math.round(daysLeft)} days (${expDateStr})`,
            graceMin,
            d.tenant_id
          );
        } else {
          await autoResolveConditionState(d.id, d.hostname, clientLabel, warRule, false, d.tenant_id);
        }
      }
    }

    // 12. LAPS Admin Secret Access / Break-Glass Audit Event (within last 15m — SQLite datetime() normalized!)
    const lapsRule = findRule('laps_secret_access');
    if (lapsRule && lapsRule.enabled) {
      const recentCutoff = new Date(Date.now() - 15 * 60 * 1000).toISOString();
      const lapsAudit = db
        .prepare(
          "SELECT username, action FROM audit_logs WHERE device_id = ? AND action = 'LAPS Ephemeral Access' AND datetime(timestamp) >= datetime(?) ORDER BY timestamp DESC LIMIT 1"
        )
        .get(d.id, recentCutoff) as { username?: string; action?: string } | undefined;
      if (lapsAudit) {
        await dispatchConditionAlert(
          d.id,
          d.hostname,
          clientLabel,
          lapsRule,
          `LAPS administrator credential accessed by '${lapsAudit.username}'`,
          graceMin,
          d.tenant_id
        );
      } else {
        await autoResolveConditionState(d.id, d.hostname, clientLabel, lapsRule, false, d.tenant_id);
      }
    }
  }

  // 13. Evaluate Specialty & Network Appliances (cascading Global -> Client -> Site rules)
  const globalPol = db.prepare("SELECT * FROM policies WHERE tier = 'global' LIMIT 1").get() as any;
  const baseAppRules = parsePolicyAlertRules(globalPol?.alert_rules_json, 'global', null);

  for (const app of appliances) {
    if (isEntityInMaintenanceSuppression(null, app.tenant_id, null)) {
      suppressedByMaintenance++;
      continue;
    }

    let rules = baseAppRules;
    if (app.tenant_id) {
      const cPol = db
        .prepare("SELECT alert_rules_json FROM policies WHERE tier = 'client' AND target_id = ?")
        .get(app.tenant_id) as any;
      if (cPol?.alert_rules_json) rules = mergeAlertRules(rules, cPol.alert_rules_json);
    }
    if (app.site_id) {
      const sPol = db
        .prepare("SELECT alert_rules_json FROM policies WHERE tier = 'site' AND target_id = ?")
        .get(app.site_id) as any;
      if (sPol?.alert_rules_json) rules = mergeAlertRules(rules, sPol.alert_rules_json);
    }

    const appRule = rules.find((r) => r.conditionId === 'specialty_appliance_state');
    if (!appRule || !appRule.enabled) continue;

    const isHealthy = /^(healthy|online|up|normal)$/i.test(String(app.status || '').trim());
    const vendorModel =
      [app.manufacturer || app.vendor, app.model].filter(Boolean).join(' ') ||
      app.vendor_model ||
      app.appliance_type ||
      'Appliance';
    if (!isHealthy) {
      await dispatchConditionAlert(
        app.id,
        app.name,
        app.tenant_name || 'Unassigned Client',
        appRule,
        `Specialty appliance (${vendorModel}) reported status: ${app.status}`,
        15,
        app.tenant_id,
        true
      );
    } else {
      await autoResolveConditionState(
        app.id,
        app.name,
        app.tenant_name || 'Unassigned Client',
        appRule,
        true,
        app.tenant_id
      );
    }
  }

  return {
    success: true,
    evaluatedDevices: activeDevices.length,
    evaluatedAppliances: appliances.length,
    suppressedByMaintenance,
    autoResolvedTickets,
    triggeredConditions,
    webUiNotificationsCreated,
    emailsDispatched,
    psaTicketsCreated
  };
}
