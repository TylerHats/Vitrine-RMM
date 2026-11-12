import crypto from 'crypto';
import { db } from '../../db/index.js';
import { maskSecretValue, decryptVaultSecret, validateOutboundHostSafety } from '../vault/index.js';
import { sendAlertEmailUsingStoredSettings } from '../smtp/index.js';

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
  const defaults = getDefaultConditionAlertRules(tier, targetId);
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
  if (!overrideJson) return baseRules;
  try {
    const parsed = JSON.parse(overrideJson);
    if (!Array.isArray(parsed)) return baseRules;
    return baseRules.map((rule) => {
      const override = parsed.find((o: any) => o.conditionId === rule.conditionId);
      return override ? { ...rule, ...override } : rule;
    });
  } catch {
    return baseRules;
  }
}

export interface PolicyRule {
  id: string;
  name: string;
  tier: 'global' | 'client' | 'site' | 'role';
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

export function resolveEffectiveDevicePolicy(deviceId: string): EffectiveDevicePolicy {
  const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId) as any;
  if (!device) {
    throw new Error(`Device ${deviceId} not found`);
  }

  // 1. Base Global Policy
  const globalRow = db.prepare("SELECT * FROM policies WHERE tier = 'global' LIMIT 1").get() as any;
  const effective: EffectiveDevicePolicy = {
    id: 'effective-' + deviceId,
    name: 'Effective Policy for ' + device.hostname,
    tier: 'global',
    targetId: deviceId,
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
    alertRules: parsePolicyAlertRules(globalRow?.alert_rules_json, 'global', null),
    inheritanceChain: [{ tier: 'global', name: globalRow?.name || 'Global MSP Baseline' }]
  };

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

  // 5. Resolve dynamic template tokens in lapsAccountName ({ClientSlug}, {SiteSlug}, {Role})
  const tenantRow = device.tenant_id
    ? (db.prepare('SELECT name, slug FROM tenants WHERE id = ?').get(device.tenant_id) as
        | { name?: string; slug?: string }
        | undefined)
    : undefined;
  const siteRow = device.site_id
    ? (db.prepare('SELECT name FROM sites WHERE id = ?').get(device.site_id) as { name?: string } | undefined)
    : undefined;
  const clientSlugClean = (tenantRow?.slug || tenantRow?.name || 'Client').replace(/[^a-zA-Z0-9]/g, '');
  const siteSlugClean = (siteRow?.name || 'Site').replace(/[^a-zA-Z0-9]/g, '').slice(0, 12);
  const roleClean = (device.device_role || 'Endpoint').replace(/[^a-zA-Z0-9]/g, '').slice(0, 10);

  effective.lapsAccountName = (effective.lapsAccountName || 'LocalAdmin')
    .replace(/\{ClientSlug\}/gi, clientSlugClean)
    .replace(/\{ClientName\}/gi, clientSlugClean)
    .replace(/\{SiteSlug\}/gi, siteSlugClean)
    .replace(/\{Role\}/gi, roleClean);

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
  auto_patch_cve_min_cvss: 8.0
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

  // Only override a column if explicitly marked in overrides_json, OR (for legacy rows without overrides_json)
  // if the child column differs from the SQLite schema default!
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
  if (source.laps_static_password != null && source.laps_static_password !== '') {
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
  if (source.alert_rules_json) {
    target.alertRules = mergeAlertRules(target.alertRules, source.alert_rules_json);
  }
}

function isEntityInMaintenanceSuppression(deviceId?: string | null, tenantId?: string | null, maintenanceUntil?: string | null): boolean {
  const nowIso = new Date().toISOString();
  if (maintenanceUntil && new Date(maintenanceUntil).getTime() > Date.now()) {
    return true;
  }
  const activeWin = db
    .prepare(`
      SELECT id FROM maintenance_windows
      WHERE is_active = 1
        AND suppress_alerts = 1
        AND start_time <= ?
        AND end_time >= ?
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

async function syncTicketWithItflowIfConfigured(ticket: {
  ticketNumber: string;
  title: string;
  clientName: string;
  priority: string;
}): Promise<void> {
  try {
    const settings = db.prepare('SELECT itflow_url, itflow_api_key FROM settings WHERE id = 1').get() as any;
    const apiKey = decryptVaultSecret(settings?.itflow_api_key);
    if (!settings?.itflow_url || !apiKey || settings.itflow_url.includes('itflow.internal')) return;
    const hostCheck = await validateOutboundHostSafety(settings.itflow_url, { allowLoopback: true });
    if (!hostCheck.safe) return;
    await fetch(`${settings.itflow_url.replace(/\/$/, '')}/tickets/create.php`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        api_key: apiKey,
        ticket_subject: ticket.title,
        ticket_priority: ticket.priority,
        ticket_details: `Created automatically by Vitrine RMM Condition Engine (${ticket.ticketNumber}) for client ${ticket.clientName}.`
      }),
      signal: AbortSignal.timeout(5000)
    });
  } catch {
    // Non-fatal external PSA sync error
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

  const autoResolveConditionTickets = (entityName: string, rule: ConditionAlertRule) => {
    if (!rule.autoResolveTicket) return;
    const res = db
      .prepare(`
        UPDATE psa_tickets
        SET status = 'Resolved'
        WHERE status != 'Resolved'
          AND title LIKE ?
      `)
      .run(`[${rule.label}] ${entityName}:%`);
    if (res.changes > 0) {
      autoResolvedTickets += res.changes;
    }
  };

  const dispatchConditionAlert = async (
    entityId: string,
    entityName: string,
    clientName: string,
    rule: ConditionAlertRule,
    detail: string,
    flapGraceMinutes = 15,
    tenantId?: string | null
  ) => {
    if (!rule.enabled) return;

    const resolvedTenantId =
      tenantId !== undefined
        ? tenantId
        : ((db.prepare('SELECT tenant_id FROM devices WHERE id = ?').get(entityId) as { tenant_id?: string } | undefined)
            ?.tenant_id ??
          (
            db.prepare('SELECT tenant_id FROM network_appliances WHERE id = ?').get(entityId) as
              | { tenant_id?: string }
              | undefined
          )?.tenant_id ??
          null);

    // Deduplicate recent notifications within flapGraceMinutes so repeated runs don't spam duplicates
    const graceCutoffIso = new Date(Date.now() - Math.max(1, flapGraceMinutes) * 60 * 1000).toISOString();
    const expectedTitlePrefix = `[${rule.severity.toUpperCase()}] ${rule.label}: ${entityName}`;
    const recentNotif = db
      .prepare('SELECT id FROM notifications WHERE type = ? AND title = ? AND created_at >= ? LIMIT 1')
      .get(rule.conditionId, expectedTitlePrefix, graceCutoffIso) as { id?: string } | undefined;

    const channels: string[] = [];

    if (rule.notifyWebUi && !recentNotif) {
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

    if (rule.notifyEmail && !recentNotif) {
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

    if (rule.createPsaTicket) {
      const ticketPrefix = `[${rule.label}] ${entityName}:`;
      const existingOpenTicket = db
        .prepare("SELECT id FROM psa_tickets WHERE status != 'Resolved' AND title LIKE ? LIMIT 1")
        .get(`${ticketPrefix}%`) as { id?: string } | undefined;

      if (!existingOpenTicket) {
        channels.push('Direct PSA Ticket');
        psaTicketsCreated++;
        const ticketNum = `INC-${crypto.randomInt(10000, 99999)}`;
        const priority = rule.severity === 'critical' ? 'Critical' : rule.severity === 'warning' ? 'High' : 'Medium';
        const fullTitle = `${ticketPrefix} ${detail}`;

        db.prepare(`
          INSERT INTO psa_tickets (id, ticket_number, title, client_name, device_id, status, priority)
          VALUES (?, ?, ?, ?, ?, 'Open', ?)
        `).run(
          `tkt-cond-${crypto.randomUUID()}`,
          ticketNum,
          fullTitle,
          clientName || 'Global MSP',
          entityId.startsWith('app-') ? null : entityId,
          priority
        );

        await syncTicketWithItflowIfConfigured({
          ticketNumber: ticketNum,
          title: fullTitle,
          clientName: clientName || 'Global MSP',
          priority
        });
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

    // 1. Endpoint Offline > X Duration (Strictly enforces thresholdHours!)
    const offlineRule = findRule('endpoint_offline');
    if (offlineRule && offlineRule.enabled) {
      if (d.status !== 'online') {
        const lastSeenMs = d.last_seen ? new Date(d.last_seen).getTime() : Date.now();
        const offlineHours = Math.max(0, (Date.now() - lastSeenMs) / (1000 * 3600));
        const thresholdHours =
          offlineRule.thresholdUnit === 'days' ? offlineRule.thresholdValue * 24 : offlineRule.thresholdValue;
        if (offlineHours >= thresholdHours) {
          await dispatchConditionAlert(
            d.id,
            d.hostname,
            clientLabel,
            offlineRule,
            `Endpoint has been offline for ${offlineHours.toFixed(1)}h (threshold: > ${offlineRule.thresholdValue} ${offlineRule.thresholdUnit})`,
            graceMin
          );
        }
      } else {
        autoResolveConditionTickets(d.hostname, offlineRule);
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
          graceMin
        );
      } else {
        autoResolveConditionTickets(d.hostname, diskRule);
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
          graceMin
        );
      } else {
        autoResolveConditionTickets(d.hostname, smartRule);
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
          graceMin
        );
      } else {
        autoResolveConditionTickets(d.hostname, loadRule);
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
          graceMin
        );
      } else if (!edrBad) {
        autoResolveConditionTickets(d.hostname, edrRule);
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
          graceMin
        );
      } else if (d.bitlocker_status && /encrypted/i.test(d.bitlocker_status)) {
        autoResolveConditionTickets(d.hostname, bitRule);
      }
    }

    // 7. Pending Reboot Overdue > X Days
    const rebRule = findRule('pending_reboot_overdue');
    if (rebRule && rebRule.enabled) {
      if (d.pending_reboot === 1) {
        const sinceIso = d.pending_reboot_since || d.enrolled_at || d.created_at;
        const pendingDays = sinceIso ? (Date.now() - new Date(sinceIso).getTime()) / (1000 * 86400) : rebRule.thresholdValue;
        if (pendingDays >= rebRule.thresholdValue) {
          await dispatchConditionAlert(
            d.id,
            d.hostname,
            clientLabel,
            rebRule,
            `Pending reboot overdue for ${pendingDays.toFixed(1)} days (threshold: > ${rebRule.thresholdValue} days)`,
            graceMin
          );
        }
      } else {
        autoResolveConditionTickets(d.hostname, rebRule);
      }
    }

    // 8. Critical CVE Detected (CVSS >= X)
    const cveRule = findRule('critical_cve_detected');
    if (cveRule && cveRule.enabled) {
      const critPatch = db
        .prepare(
          "SELECT kb_id, cve_id, cvss_score FROM patches WHERE device_id = ? AND status != 'Installed' AND COALESCE(cvss_score, 0) >= ? ORDER BY cvss_score DESC LIMIT 1"
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
        await dispatchConditionAlert(d.id, d.hostname, clientLabel, cveRule, desc, graceMin);
      } else {
        autoResolveConditionTickets(d.hostname, cveRule);
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
          graceMin
        );
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
          graceMin
        );
      } else {
        autoResolveConditionTickets(d.hostname, netRule);
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
            graceMin
          );
        }
      }
    }

    // 12. LAPS Admin Secret Access / Break-Glass Audit Event (within last 15m)
    const lapsRule = findRule('laps_secret_access');
    if (lapsRule && lapsRule.enabled) {
      const recentCutoff = new Date(Date.now() - 15 * 60 * 1000).toISOString();
      const lapsAudit = db
        .prepare(
          "SELECT username, action FROM audit_logs WHERE device_id = ? AND action = 'LAPS Ephemeral Access' AND timestamp >= ? ORDER BY timestamp DESC LIMIT 1"
        )
        .get(d.id, recentCutoff) as { username?: string; action?: string } | undefined;
      if (lapsAudit) {
        await dispatchConditionAlert(
          d.id,
          d.hostname,
          clientLabel,
          lapsRule,
          `LAPS administrator credential accessed by '${lapsAudit.username}'`,
          graceMin
        );
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
    if (!isHealthy) {
      await dispatchConditionAlert(
        app.id,
        app.name,
        app.tenant_name || 'Unassigned Client',
        appRule,
        app.alert_summary || `Specialty appliance (${app.vendor_model}) reported status: ${app.status}`,
        15
      );
    } else {
      autoResolveConditionTickets(app.name, appRule);
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
