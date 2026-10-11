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
}

export interface EffectiveDevicePolicy extends PolicyRule {
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
  const rolePolicy = db.prepare("SELECT * FROM policies WHERE tier = 'role' AND target_id = ?").get(device.device_role) as any;
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
}
