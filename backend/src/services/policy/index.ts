import { db } from '../../db/index.js';

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
  lapsAccountName: string;
  lapsPasswordLength: number;
  lapsComplexity: string;
  lapsRotationDays: number;
  lapsRotateOnAccess: boolean;
  lapsPostAccessGraceHours: number;
  requireMfaForSecrets: boolean;
  telemetryHistoryRetentionDays: number;
  hardwareAuditEnabled: boolean;
  networkDriftDetectionEnabled: boolean;
  selfHealingMaxHourlyRuns: number;
  selfHealingAlertPsa: boolean;
}

export interface EffectiveDevicePolicy extends PolicyRule {
  require_mfa_for_secrets?: boolean;
  inheritanceChain: Array<{ tier: string; name: string }>;
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
    lapsAccountName: globalRow?.laps_account_name || 'LocalAdmin',
    lapsPasswordLength: globalRow?.laps_password_length ?? 20,
    lapsComplexity: globalRow?.laps_complexity || 'alphanumeric_symbols',
    lapsRotationDays: globalRow?.laps_rotation_days ?? 30,
    lapsRotateOnAccess: Boolean(globalRow?.laps_rotate_on_access ?? 1),
    lapsPostAccessGraceHours: globalRow?.laps_post_access_grace_hours ?? 2,
    requireMfaForSecrets: Boolean(globalRow?.require_mfa_for_secrets ?? 1),
    require_mfa_for_secrets: Boolean(globalRow?.require_mfa_for_secrets ?? 1),
    telemetryHistoryRetentionDays: globalRow?.telemetry_history_retention_days ?? 90,
    hardwareAuditEnabled: Boolean(globalRow?.hardware_audit_enabled ?? 1),
    networkDriftDetectionEnabled: Boolean(globalRow?.network_drift_detection_enabled ?? 1),
    selfHealingMaxHourlyRuns: globalRow?.self_healing_max_hourly_runs ?? 3,
    selfHealingAlertPsa: Boolean(globalRow?.self_healing_alert_psa ?? 1),
    inheritanceChain: [{ tier: 'global', name: globalRow?.name || 'Global MSP Baseline' }]
  };

  // 2. Client Tier Override
  const clientPolicy = db.prepare("SELECT * FROM policies WHERE tier = 'client' AND target_id = ?").get(device.tenant_id) as any;
  if (clientPolicy) {
    applyOverrides(effective, clientPolicy);
    effective.inheritanceChain.push({ tier: 'client', name: clientPolicy.name });
  }

  // 3. Site Tier Override
  const sitePolicy = db.prepare("SELECT * FROM policies WHERE tier = 'site' AND target_id = ?").get(device.site_id) as any;
  if (sitePolicy) {
    applyOverrides(effective, sitePolicy);
    effective.inheritanceChain.push({ tier: 'site', name: sitePolicy.name });
  }

  // 4. Role Tier Override (e.g. Domain Controller / Server)
  const rolePolicy = db.prepare(
    "SELECT * FROM policies WHERE tier = 'role' AND (? = target_id OR ? LIKE '%' || target_id || '%') LIMIT 1"
  ).get(device.device_role, device.device_role) as any;
  if (rolePolicy) {
    applyOverrides(effective, rolePolicy);
    effective.inheritanceChain.push({ tier: 'role', name: rolePolicy.name });
  }

  return effective;
}

function applyOverrides(target: EffectiveDevicePolicy, source: any) {
  if (source.telemetry_interval_sec != null) target.telemetryIntervalSec = source.telemetry_interval_sec;
  if (source.require_remote_consent != null) target.requireRemoteConsent = Boolean(source.require_remote_consent);
  if (source.consent_timeout_sec != null) target.consentTimeoutSec = source.consent_timeout_sec;
  if (source.consent_timeout_action != null) target.consentTimeoutAction = source.consent_timeout_action;
  if (source.auto_lock_on_disconnect != null) target.autoLockOnDisconnect = Boolean(source.auto_lock_on_disconnect);
  if (source.patch_schedule != null) target.patchSchedule = source.patch_schedule;
  if (source.patch_reboot_enforcement != null) target.patchRebootEnforcement = source.patch_reboot_enforcement;
  if (source.self_healing_enabled != null) target.selfHealingEnabled = Boolean(source.self_healing_enabled);
  if (source.max_snooze_hours != null) target.maxSnoozeHours = Number(source.max_snooze_hours);
  if (source.force_reboot_after_snooze != null) target.forceRebootAfterSnooze = Boolean(source.force_reboot_after_snooze);
  if (source.final_countdown_sec != null) target.finalCountdownSec = Number(source.final_countdown_sec);
  if (source.laps_enabled != null) target.lapsEnabled = Boolean(source.laps_enabled);
  if (source.laps_account_name != null) target.lapsAccountName = source.laps_account_name;
  if (source.laps_password_length != null) target.lapsPasswordLength = Number(source.laps_password_length);
  if (source.laps_complexity != null) target.lapsComplexity = source.laps_complexity;
  if (source.laps_rotation_days != null) target.lapsRotationDays = Number(source.laps_rotation_days);
  if (source.laps_rotate_on_access != null) target.lapsRotateOnAccess = Boolean(source.laps_rotate_on_access);
  if (source.laps_post_access_grace_hours != null) target.lapsPostAccessGraceHours = Number(source.laps_post_access_grace_hours);
  if (source.require_mfa_for_secrets != null) {
    target.requireMfaForSecrets = Boolean(source.require_mfa_for_secrets);
    target.require_mfa_for_secrets = Boolean(source.require_mfa_for_secrets);
  }
  if (source.telemetry_history_retention_days != null) target.telemetryHistoryRetentionDays = Number(source.telemetry_history_retention_days);
  if (source.hardware_audit_enabled != null) target.hardwareAuditEnabled = Boolean(source.hardware_audit_enabled);
  if (source.network_drift_detection_enabled != null) target.networkDriftDetectionEnabled = Boolean(source.network_drift_detection_enabled);
  if (source.self_healing_max_hourly_runs != null) target.selfHealingMaxHourlyRuns = Number(source.self_healing_max_hourly_runs);
  if (source.self_healing_alert_psa != null) target.selfHealingAlertPsa = Boolean(source.self_healing_alert_psa);
}
