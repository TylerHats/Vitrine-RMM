import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { db, RECORDINGS_DIR_PATH } from '../../db/index.js';
import { rotateLapsPasswordVerifiedAsync } from '../laps/index.js';
import { sweepPendingOffboards } from '../offboarding/index.js';
import { backupService, registerDatabaseSwapHooks } from '../backup/index.js';
import {
  evaluateFleetAlertConditions,
  isEntityInMaintenanceSuppression,
  resolveEffectiveDevicePolicy
} from '../policy/index.js';
import { executeScheduledAutomationNow, matchesCronExpression } from '../automation/index.js';
import { quoteBashLiteral, quotePowerShellLiteral } from '../agent/installerGenerator.js';
import { agentSocketHub } from '../agent/socketHub.js';
import { meshBridge } from '../meshcentral/index.js';
import { pruneTelemetryHistory } from '../telemetry/index.js';
import { decryptVaultSecret } from '../vault/index.js';
import { codeSigningService } from '../signing/index.js';
import { addItflowTicketNote, getItflowRuntimeConfig, pullItflowTicketUpdates, syncAllItflowAssets } from '../itflow/index.js';

let fastTimer: ReturnType<typeof setInterval> | null = null;
let conditionTimer: ReturnType<typeof setInterval> | null = null;
let tickInProgress = false;
let conditionTickInProgress = false;
let itflowAssetSyncInProgress = false;
let itflowTicketPullInProgress = false;
let lastItflowTicketPullAtMs = 0;
let schedulerPausedForDbSwap = false;

// Ensure atomic SQLite restores pause background ticks cleanly
registerDatabaseSwapHooks(
  () => {
    schedulerPausedForDbSwap = true;
  },
  () => {
    schedulerPausedForDbSwap = false;
  }
);

const hourlyWatchdogRuns = new Map<string, { hourBucket: number; count: number }>();
const monitorCooldownMap = new Map<string, number>();

function parseSafePathsArray(
  rawJson: string | null | undefined,
  isWindows: boolean,
  fallbackDefaults: string[]
): string[] {
  try {
    const parsed = typeof rawJson === 'string' ? JSON.parse(rawJson) : rawJson;
    if (Array.isArray(parsed)) {
      const valid = parsed
        .filter(
          (p): p is string =>
            typeof p === 'string' &&
            p.trim().length > 0 &&
            !/[\0\r\n]/.test(p) &&
            !p.trim().startsWith('-')
        )
        .map((p) => p.trim());
      const filtered = isWindows
        ? valid.filter((p) => /^[a-zA-Z]:\\|^\\\\/.test(p))
        : valid.filter((p) => p.startsWith('/'));
      if (filtered.length > 0) return filtered;
    }
  } catch {}
  return fallbackDefaults;
}

function buildBackupJobCommand(
  osType: string | undefined,
  engineRaw: string | undefined,
  targetRepoRaw: string | undefined,
  includePathsJson: string | undefined,
  jobId: string,
  excludePathsJson?: string | null,
  hasResticPassword = false
): { code: string; shell: 'powershell' | 'bash'; includePaths: string[]; excludePaths: string[] } {
  const isWindows = String(osType || '').toLowerCase() === 'windows';
  const engine = String(engineRaw || 'restic').toLowerCase();
  const targetRepo = String(targetRepoRaw || '').trim();
  const includePaths = parseSafePathsArray(includePathsJson, isWindows, isWindows ? ['C:\\Users'] : ['/etc', '/home']);
  const excludePaths = parseSafePathsArray(excludePathsJson, isWindows, []);
  const safeJobSlug = jobId.replace(/[^a-zA-Z0-9_-]/g, '');

  if (isWindows) {
    const psResticEnv = hasResticPassword
      ? 'if ($env:VITRINE_PARAM_RESTIC_PASSWORD) { $env:RESTIC_PASSWORD = $env:VITRINE_PARAM_RESTIC_PASSWORD }; '
      : '';
    if (engine === 'restic' && targetRepo) {
      const quotedRepo = quotePowerShellLiteral(targetRepo);
      const quotedPaths = includePaths.map((p) => quotePowerShellLiteral(p)).join(', ');
      const exArgs = excludePaths.map((p) => `'--exclude', ${quotePowerShellLiteral(p)}`).join(', ');
      const exDecl = exArgs ? `$exArgs = @(${exArgs}); ` : '$exArgs = @(); ';
      const code = `${psResticEnv}$repo = ${quotedRepo}; $paths = @(${quotedPaths}); ${exDecl}if (Get-Command restic -ErrorAction SilentlyContinue) { & restic -r $repo backup @paths @exArgs } else { vssadmin list shadows }`;
      return { code, shell: 'powershell', includePaths, excludePaths };
    }
    if (engine === 'vss' || !targetRepo) {
      return {
        code: `vssadmin list shadows`,
        shell: 'powershell',
        includePaths,
        excludePaths
      };
    }
    const quotedArchive = quotePowerShellLiteral(`C:\\ProgramData\\VitrineBackup-${safeJobSlug}.zip`);
    const quotedPaths = includePaths.map((p) => quotePowerShellLiteral(p)).join(', ');
    return {
      code: `Compress-Archive -Path @(${quotedPaths}) -DestinationPath ${quotedArchive} -Force -ErrorAction Stop; Write-Output "Snapshot saved: ${safeJobSlug}"`,
      shell: 'powershell',
      includePaths,
      excludePaths
    };
  }

  // POSIX (Linux / macOS)
  const quotedPaths = includePaths.map((p) => quoteBashLiteral(p)).join(' ');
  const tarExcludeArgs = excludePaths.map((p) => `--exclude=${quoteBashLiteral(p)}`).join(' ');
  const resticExcludeArgs = excludePaths.map((p) => `--exclude=${quoteBashLiteral(p)}`).join(' ');
  const bashResticEnv = hasResticPassword
    ? 'if [ -n "${VITRINE_PARAM_RESTIC_PASSWORD:-}" ]; then export RESTIC_PASSWORD="$VITRINE_PARAM_RESTIC_PASSWORD"; fi; '
    : '';

  if (engine === 'restic' && targetRepo) {
    const quotedRepo = quoteBashLiteral(targetRepo);
    const fallbackTar = quoteBashLiteral(`/tmp/vitrine-snap-${safeJobSlug}.tar.gz`);
    const tarExPart = tarExcludeArgs ? `${tarExcludeArgs} ` : '';
    const resticExPart = resticExcludeArgs ? ` ${resticExcludeArgs}` : '';
    return {
      code: `${bashResticEnv}if command -v restic >/dev/null 2>&1; then restic -r ${quotedRepo} backup${resticExPart} -- ${quotedPaths}; else tar -czf ${fallbackTar} ${tarExPart}-- ${quotedPaths} 2>/dev/null && ls -lh ${fallbackTar} && rm -f ${fallbackTar}; fi`,
      shell: 'bash',
      includePaths,
      excludePaths
    };
  }

  const archiveDest = targetRepo
    ? quoteBashLiteral(`${targetRepo.replace(/\/+$/, '')}/vitrine-snap-${safeJobSlug}.tar.gz`)
    : quoteBashLiteral(`/tmp/vitrine-snap-${safeJobSlug}.tar.gz`);
  const tarExPart = tarExcludeArgs ? `${tarExcludeArgs} ` : '';
  const cleanupTail = targetRepo ? '' : ` && rm -f ${archiveDest}`;
  return {
    code: `tar -czf ${archiveDest} ${tarExPart}-- ${quotedPaths} 2>/dev/null && ls -lh ${archiveDest}${cleanupTail}`,
    shell: 'bash',
    includePaths,
    excludePaths
  };
}

export async function runMaintenanceAndLifecycleTick(): Promise<{
  expiredMaintenanceCleared: number;
  lapsEvaluated: number;
  autoArchivedOffboards: number;
  scheduledBackupCreated: boolean;
  automationsTriggered: number;
}> {
  if (schedulerPausedForDbSwap) {
    return {
      expiredMaintenanceCleared: 0,
      lapsEvaluated: 0,
      autoArchivedOffboards: 0,
      scheduledBackupCreated: false,
      automationsTriggered: 0
    };
  }

  const now = new Date();
  const nowIso = now.toISOString();
  let expiredMaintenanceCleared = 0;
  let lapsEvaluated = 0;
  let autoArchivedOffboards = 0;
  let scheduledBackupCreated = false;
  let automationsTriggered = 0;

  // 1. Clear expired per-device maintenance_until flags & deactivate (do NOT delete!) completed maintenance windows
  try {
    const res = db
      .prepare(
        'UPDATE devices SET maintenance_until = NULL WHERE maintenance_until IS NOT NULL AND datetime(maintenance_until) <= datetime(?)'
      )
      .run(nowIso);
    expiredMaintenanceCleared += res.changes;

    db.prepare(
      'UPDATE maintenance_windows SET is_active = 0 WHERE is_active = 1 AND datetime(end_time) <= datetime(?)'
    ).run(nowIso);
  } catch {}

  // 2. Sweep pending offboard timeouts
  try {
    const sweep = sweepPendingOffboards();
    autoArchivedOffboards = sweep.autoArchivedCount;
  } catch {}

  // 3. Scheduled LAPS password expiry check & deferred online retry (verified live delivery before vault commit)
  try {
    const dueRows = db
      .prepare(`
        SELECT v.device_id
        FROM laps_vault v
        JOIN devices d ON d.id = v.device_id
        WHERE COALESCE(d.lifecycle_state, 'active') = 'active'
          AND (
            (COALESCE(v.rotation_pending_online, 0) = 1 AND d.status = 'online')
            OR (
              COALESCE(v.rotation_pending_online, 0) = 0
              AND v.expires_at IS NOT NULL
              AND datetime(v.expires_at) <= datetime(?)
            )
          )
      `)
      .all(nowIso) as Array<{ device_id: string }>;

    for (const row of dueRows) {
      try {
        await rotateLapsPasswordVerifiedAsync(row.device_id, { actorUsername: 'scheduler' });
        lapsEvaluated++;
      } catch {}
    }
  } catch {}

  // 3b. Companion auto-deploy sweep for online MS2-managed devices queued after OOBE
  try {
    const oobeRow = db.prepare('SELECT oobe_completed, is_onboarded FROM settings WHERE id = 1').get() as
      | { oobe_completed?: number; is_onboarded?: number }
      | undefined;
    if (oobeRow?.oobe_completed === 1 || oobeRow?.is_onboarded === 1) {
      const pendingCompanions = db
        .prepare(`
          SELECT id
          FROM devices
          WHERE COALESCE(companion_deploy_pending, 0) = 1
            AND COALESCE(companion_installed, 0) = 0
            AND COALESCE(lifecycle_state, 'active') = 'active'
            AND status = 'online'
            AND mesh_node_id IS NOT NULL
          LIMIT 5
        `)
        .all() as Array<{ id: string }>;
      if (pendingCompanions.length > 0) {
        const { meshBridge } = await import('../meshcentral/index.js');
        if (meshBridge.getStatus().connected) {
          for (const dev of pendingCompanions) {
            try {
              await meshBridge.deployCompanionOverMesh(dev.id);
            } catch {}
          }
        }
      }
    }
  } catch {}

  // 4. Prune expired auth sessions & aged session recordings (cleaning up .webm video files strictly inside RECORDINGS_DIR_PATH!)
  try {
    db.prepare('DELETE FROM auth_sessions WHERE datetime(expires_at) <= datetime(?)').run(nowIso);

    let retentionDays = 90;
    try {
      const settingsRow = db
        .prepare('SELECT session_recording_retention_days FROM settings WHERE id = 1')
        .get() as { session_recording_retention_days?: number } | undefined;
      if (settingsRow?.session_recording_retention_days && settingsRow.session_recording_retention_days > 0) {
        retentionDays = settingsRow.session_recording_retention_days;
      } else {
        const globalPol = db
          .prepare("SELECT session_recording_retention_days FROM policies WHERE tier = 'global' LIMIT 1")
          .get() as { session_recording_retention_days?: number } | undefined;
        if (globalPol?.session_recording_retention_days && globalPol.session_recording_retention_days > 0) {
          retentionDays = globalPol.session_recording_retention_days;
        }
      }
    } catch {}
    const cutoffIso = new Date(Date.now() - retentionDays * 86400 * 1000).toISOString();
    const expiredRecs = db
      .prepare('SELECT id, video_path FROM session_recordings WHERE datetime(created_at) <= datetime(?)')
      .all(cutoffIso) as Array<{ id: string; video_path?: string | null }>;

    const realRecordingsRoot = fs.existsSync(RECORDINGS_DIR_PATH) ? fs.realpathSync(RECORDINGS_DIR_PATH) : null;

    for (const rec of expiredRecs) {
      if (rec.video_path && realRecordingsRoot && fs.existsSync(rec.video_path)) {
        try {
          const rawStat = fs.lstatSync(rec.video_path);
          if (!rawStat.isSymbolicLink()) {
            const resolved = fs.realpathSync(rec.video_path);
            if (
              resolved.startsWith(realRecordingsRoot + path.sep) &&
              !fs.lstatSync(resolved).isSymbolicLink() &&
              fs.statSync(resolved).isFile()
            ) {
              fs.unlinkSync(resolved);
            }
          }
        } catch {}
      }
      db.prepare('DELETE FROM session_recordings WHERE id = ?').run(rec.id);
    }

    // Also prune aged telemetry history according to policy retention days
    pruneTelemetryHistory();
  } catch {}

  // 4b. Lightweight background live telemetry sampling for online managed devices
  // so RAM/CPU/Disk/Net usage & history charts remain accurate even without companion check-ins
  try {
    if (meshBridge.getStatus().connected) {
      const twoMinAgoIso = new Date(Date.now() - 2 * 60_000).toISOString();
      const staleOnline = db
        .prepare(`
          SELECT d.id
          FROM devices d
          WHERE d.status = 'online'
            AND COALESCE(d.lifecycle_state, 'active') = 'active'
            AND d.mesh_node_id IS NOT NULL
            AND NOT EXISTS (
              SELECT 1 FROM device_telemetry_history h
              WHERE h.device_id = d.id AND datetime(h.recorded_at) > datetime(?)
            )
          ORDER BY COALESCE(d.ram_used_gb, 0) ASC, d.last_seen DESC
          LIMIT 8
        `)
        .all(twoMinAgoIso) as Array<{ id: string }>;

      for (const dev of staleOnline) {
        try {
          await meshBridge.sampleLiveTelemetry(dev.id);
        } catch {}
      }
    }
  } catch {}

  // 4c. Periodic ITFlow Asset Sync (respecting configured interval)
  try {
    const itfCfg = getItflowRuntimeConfig();
    if (itfCfg.enabled && itfCfg.apiBase && itfCfg.apiKey && !itflowAssetSyncInProgress) {
      const rawTs = itfCfg.lastAssetSyncAt ? String(itfCfg.lastAssetSyncAt) : '';
      const normTs = rawTs ? (rawTs.includes('T') ? rawTs : `${rawTs.replace(' ', 'T')}Z`) : '';
      const lastMs = normTs ? new Date(normTs).getTime() : 0;
      const intervalMs = Math.max(5, Number(itfCfg.syncIntervalMin || 60)) * 60_000;
      if (!lastMs || Number.isNaN(lastMs) || Date.now() - lastMs >= intervalMs) {
        itflowAssetSyncInProgress = true;
        try {
          await syncAllItflowAssets({ force: false });
        } finally {
          itflowAssetSyncInProgress = false;
        }
      }
    }
  } catch {}

  // 4d. Periodic Bidirectional ITFlow Ticket & Reply Pull (every 5 minutes)
  try {
    const itfCfg = getItflowRuntimeConfig();
    if (
      itfCfg.enabled &&
      itfCfg.apiBase &&
      itfCfg.apiKey &&
      !itflowTicketPullInProgress &&
      Date.now() - lastItflowTicketPullAtMs >= 5 * 60_000
    ) {
      itflowTicketPullInProgress = true;
      lastItflowTicketPullAtMs = Date.now();
      try {
        await pullItflowTicketUpdates();
      } finally {
        itflowTicketPullInProgress = false;
      }
    }
  } catch {}

  // 5. Drift-Free Scheduled Backup Execution & Offsite Sync
  try {
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    if (settings.is_onboarded && settings.backup_schedule_enabled) {
      const freq: string = settings.backup_schedule_frequency || 'daily';
      const targetTime: string = settings.backup_schedule_time || '02:00';
      const [targetH, targetM] = targetTime.split(':').map((n: string) => parseInt(n, 10) || 0);

      const lastRow = db
        .prepare("SELECT created_at FROM system_backups WHERE trigger_type = 'scheduled' ORDER BY created_at DESC LIMIT 1")
        .get() as { created_at?: string } | undefined;
      const lastDateObj = lastRow?.created_at ? new Date(String(lastRow.created_at).replace(' ', 'T')) : null;
      const lastMs = lastDateObj && !Number.isNaN(lastDateObj.getTime()) ? lastDateObj.getTime() : 0;

      const todayTarget = new Date(now);
      todayTarget.setHours(targetH, targetM, 0, 0);

      let shouldRunBackup = false;
      if (freq === 'hourly') {
        shouldRunBackup = Date.now() - lastMs >= 58 * 60 * 1000;
      } else if (freq === 'weekly') {
        shouldRunBackup = Date.now() - lastMs >= 6.95 * 24 * 3600 * 1000 && now.getTime() >= todayTarget.getTime();
      } else {
        // Exact calendar-day comparison prevents daily 23h schedule drift!
        const sameCalendarDay =
          lastDateObj &&
          lastDateObj.getFullYear() === now.getFullYear() &&
          lastDateObj.getMonth() === now.getMonth() &&
          lastDateObj.getDate() === now.getDate();
        shouldRunBackup = !sameCalendarDay && now.getTime() >= todayTarget.getTime();
      }

      if (shouldRunBackup) {
        backupService.createBackup({
          triggerType: 'scheduled',
          notes: `Automated ${freq} scheduled backup`
        });
        scheduledBackupCreated = true;

        if (settings.backup_offsite_enabled) {
          await backupService.syncAllToOffsiteVault(false);
        }
      }
    }
  } catch {}

  // 6. Execute Scheduled Cron Automations (`scheduled_automations`)
  try {
    const automations = db
      .prepare('SELECT * FROM scheduled_automations WHERE enabled = 1')
      .all() as Array<any>;

    for (const auto of automations) {
      // Prevent firing twice within the same minute
      if (auto.last_run_at) {
        const lastRunMs = new Date(String(auto.last_run_at).replace(' ', 'T')).getTime();
        if (!Number.isNaN(lastRunMs) && Date.now() - lastRunMs < 55_000) continue;
      }

      if (auto.schedule_type === 'once') {
        const runAtMs = auto.next_run_at ? new Date(auto.next_run_at).getTime() : 0;
        if (runAtMs > 0 && Date.now() >= runAtMs && !auto.last_run_at) {
          await executeScheduledAutomationNow(auto.id, 'scheduler');
          db.prepare('UPDATE scheduled_automations SET enabled = 0 WHERE id = ?').run(auto.id);
          automationsTriggered++;
        }
      } else if (matchesCronExpression(auto.cron_expression || '0 3 * * *', now)) {
        await executeScheduledAutomationNow(auto.id, 'scheduler');
        automationsTriggered++;
      }
    }
  } catch {}

  // 7. Execute Scheduled Endpoint Backup Policies (`backup_policies`)
  try {
    const bPolicies = db.prepare('SELECT * FROM backup_policies WHERE enabled = 1').all() as Array<any>;
    for (const bp of bPolicies) {
      if (bp.last_run_at) {
        const lastRunMs = new Date(String(bp.last_run_at).replace(' ', 'T')).getTime();
        if (!Number.isNaN(lastRunMs) && Date.now() - lastRunMs < 55_000) continue;
      }
      if (!matchesCronExpression(bp.schedule_cron || '0 1 * * *', now)) continue;

      try {
        db.prepare('UPDATE backup_policies SET last_run_at = ? WHERE id = ?').run(nowIso, bp.id);
      } catch {}

      const onlineDevs = db
        .prepare(
          "SELECT id, tenant_id, os_type FROM devices WHERE status = 'online' AND COALESCE(lifecycle_state, 'active') = 'active' AND (? IS NULL OR tenant_id = ?)"
        )
        .all(bp.tenant_id || null, bp.tenant_id || null) as Array<{
        id: string;
        tenant_id: string;
        os_type?: string;
      }>;

      const rawResticPass =
        bp.restic_password_encrypted || bp.repo_password_encrypted || bp.password_encrypted || '';
      const resticPassword = rawResticPass ? decryptVaultSecret(rawResticPass) : '';

      for (const dev of onlineDevs) {
        const eff = resolveEffectiveDevicePolicy(dev.id);
        if (eff.backupPolicyId && eff.backupPolicyId !== bp.id) continue;
        const jobId = `bjob-${crypto.randomUUID()}`;
        const built = buildBackupJobCommand(
          dev.os_type,
          bp.engine,
          bp.target_repo,
          bp.include_paths_json,
          jobId,
          bp.exclude_paths_json,
          Boolean(resticPassword)
        );

        db.prepare(`
          INSERT INTO device_backup_jobs (id, device_id, policy_id, engine, status, details, executed_at)
          VALUES (?, ?, ?, ?, 'Queued', ?, ?)
        `).run(jobId, dev.id, bp.id, bp.engine || 'restic', `Scheduled backup policy: ${bp.name || bp.id}`, nowIso);

        const taskPayload = JSON.stringify({
          backupJobId: jobId,
          jobId,
          engine: bp.engine || 'restic',
          targetRepo: bp.target_repo || '',
          includePaths: built.includePaths,
          excludePaths: built.excludePaths,
          env: resticPassword ? { VITRINE_PARAM_RESTIC_PASSWORD: resticPassword } : {},
          shell: built.shell,
          language: built.shell,
          code: built.code
        });
        const taskId = `task-bak-${crypto.randomUUID()}`;
        try {
          db.prepare(`
            INSERT INTO agent_tasks (id, device_id, tenant_id, task_type, payload_json, status)
            VALUES (?, ?, ?, 'backup_job', ?, 'queued')
          `).run(taskId, dev.id, dev.tenant_id, taskPayload);
        } catch {
          db.prepare(`
            INSERT INTO agent_tasks (id, device_id, task_type, payload_json, status)
            VALUES (?, ?, 'backup_job', ?, 'queued')
          `).run(taskId, dev.id, taskPayload);
        }
        agentSocketHub.dispatchTaskIfConnected(dev.id, {
          id: taskId,
          task_type: 'backup_job',
          payload_json: taskPayload
        });
      }
    }
  } catch {}

  return {
    expiredMaintenanceCleared,
    lapsEvaluated,
    autoArchivedOffboards,
    scheduledBackupCreated,
    automationsTriggered
  };
}

export async function runSelfHealingWatchdogSweep(): Promise<void> {
  if (schedulerPausedForDbSwap) return;
  try {
    const hourBucket = Math.floor(Date.now() / 3600_000);
    // Prune stale hourly rate-limit buckets and expired cooldown entries (> 24h old)
    for (const [key, entry] of hourlyWatchdogRuns.entries()) {
      if (entry.hourBucket < hourBucket) {
        hourlyWatchdogRuns.delete(key);
      }
    }
    const staleCooldownCutoff = Date.now() - 24 * 3600_000;
    for (const [key, ts] of monitorCooldownMap.entries()) {
      if (ts < staleCooldownCutoff) {
        monitorCooldownMap.delete(key);
      }
    }

    const monitors = db.prepare('SELECT * FROM self_healing_monitors WHERE enabled = 1').all() as any[];
    if (monitors.length === 0) return;

    const onlineDevices = db
      .prepare("SELECT * FROM devices WHERE status = 'online' AND COALESCE(lifecycle_state, 'active') = 'active'")
      .all() as any[];

    for (const mon of monitors) {
      const condType = String(mon.condition_type || '').toLowerCase();
      const condValStr = String(mon.condition_value ?? mon.target_service ?? '').trim();
      const cooldownMs = Math.max(1, Number(mon.cooldown_min || 15)) * 60_000;
      const scriptRow = mon.remediation_script_id
        ? (db.prepare('SELECT id, name, language, code FROM scripts WHERE id = ?').get(mon.remediation_script_id) as
            | { id: string; name: string; language: string; code: string }
            | undefined)
        : undefined;

      for (const dev of onlineDevices) {
        if (mon.tenant_id && mon.tenant_id !== dev.tenant_id) continue;
        if (isEntityInMaintenanceSuppression(dev.id, dev.tenant_id, dev.maintenance_until)) continue;

        let eff: ReturnType<typeof resolveEffectiveDevicePolicy>;
        try {
          eff = resolveEffectiveDevicePolicy(dev.id);
        } catch {
          continue;
        }
        if (!eff.selfHealingEnabled) continue;

        const rateKey = `${mon.id}::${dev.id}`;
        const lastCooldownTs = monitorCooldownMap.get(rateKey) || 0;
        if (Date.now() - lastCooldownTs < cooldownMs) continue;

        const bucket = hourlyWatchdogRuns.get(rateKey);
        if (bucket && bucket.hourBucket === hourBucket && bucket.count >= (eff.selfHealingMaxHourlyRuns || 3)) {
          continue;
        }

        let triggered = false;
        let remStatus: 'Success' | 'Failed' = 'Success';
        let remOutput = '';

        const isWin = String(dev.os_type || '').toLowerCase() === 'windows';
        const scriptLang = scriptRow?.language === 'powershell' ? 'powershell' : scriptRow?.language === 'python' ? 'python' : 'bash';
        const isScriptCompatible = Boolean(
          scriptRow?.code && ((isWin && scriptLang === 'powershell') || (!isWin && scriptLang === 'bash') || scriptLang === 'python')
        );

        const runCompatibleRemediation = async (): Promise<{ ok: boolean; output: string; queued?: boolean }> => {
          if (!scriptRow?.code || !isScriptCompatible) {
            return { ok: false, output: 'No OS-compatible remediation script configured.' };
          }
          let codeToRun = scriptRow.code;
          if (isWin && scriptLang === 'powershell') {
            const wrapped = await codeSigningService.wrapPowerShellExecutionIfSigningEnabled(codeToRun);
            if (wrapped.error && !wrapped.command) {
              return { ok: false, output: wrapped.error };
            }
            codeToRun = wrapped.command;
          }
          const execRes = await meshBridge.executeCommandOnNode(dev.id, codeToRun, {
            shell: scriptLang,
            timeoutMs: 20000
          });
          return {
            ok: execRes.exitCode === 0 || Boolean(execRes.queued),
            output: execRes.output || `Executed remediation script ${scriptRow.name}.`,
            queued: execRes.queued
          };
        };

        if (condType === 'service_stopped' && condValStr) {
          const svcs = await meshBridge.getServices(dev.id);
          const match = svcs.find((s) => s.name.toLowerCase() === condValStr.toLowerCase());
          if (match && match.status === 'Stopped') {
            triggered = true;
            const svcOk = await meshBridge.manageService(dev.id, match.name, 'start', 'watchdog');
            remOutput = svcOk
              ? `Restarted stopped service '${match.name}'.`
              : `Failed to restart stopped service '${match.name}'.`;
            if (!svcOk) remStatus = 'Failed';

            if (isScriptCompatible) {
              const remRes = await runCompatibleRemediation();
              if (remRes.output) remOutput = `${remOutput}\n${remRes.output}`.trim();
              if (!remRes.ok) remStatus = 'Failed';
            }
          }
        } else if (
          (condType === 'disk_space_low' || condType === 'disk_low') &&
          dev.disk_total_gb > 0
        ) {
          const thresholdPct = Number(condValStr || 10);
          const freePct = (Number(dev.disk_free_gb || 0) / Number(dev.disk_total_gb)) * 100;
          if (freePct < thresholdPct && isScriptCompatible) {
            triggered = true;
            const remRes = await runCompatibleRemediation();
            remOutput = remRes.output;
            if (!remRes.ok) remStatus = 'Failed';
          }
        } else if (condType === 'cpu_high' || condType === 'high_cpu') {
          const thresholdPct = Number(condValStr || 90);
          if (Number(dev.cpu_usage || 0) >= thresholdPct && isScriptCompatible) {
            triggered = true;
            const remRes = await runCompatibleRemediation();
            remOutput = remRes.output;
            if (!remRes.ok) remStatus = 'Failed';
          }
        } else if (condType === 'ram_high' || condType === 'high_ram' || condType === 'memory_high') {
          const thresholdPct = Number(condValStr || 90);
          const ramPct = dev.ram_total_gb > 0 ? (Number(dev.ram_used_gb || 0) / Number(dev.ram_total_gb)) * 100 : 0;
          if (ramPct >= thresholdPct && isScriptCompatible) {
            triggered = true;
            const remRes = await runCompatibleRemediation();
            remOutput = remRes.output;
            if (!remRes.ok) remStatus = 'Failed';
          }
        }

        if (triggered) {
          monitorCooldownMap.set(rateKey, Date.now());
          hourlyWatchdogRuns.set(rateKey, {
            hourBucket,
            count: bucket && bucket.hourBucket === hourBucket ? bucket.count + 1 : 1
          });
          try {
            db.prepare(`
              INSERT INTO remediation_logs (
                id, monitor_id, monitor_name, device_id, hostname, script_id, status, output, executed_at
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
              `rem-${crypto.randomUUID()}`,
              mon.id,
              mon.name || mon.id,
              dev.id,
              dev.hostname || dev.id,
              mon.remediation_script_id || 'service-restart',
              remStatus,
              remOutput.slice(0, 4000),
              new Date().toISOString()
            );
          } catch {}
          try {
            const openTkt = db
              .prepare(
                "SELECT id FROM psa_tickets WHERE device_id = ? AND status NOT IN ('Resolved', 'Closed') AND external_provider = 'itflow' AND external_ticket_id IS NOT NULL ORDER BY created_at DESC LIMIT 1"
              )
              .get(dev.id) as { id?: string } | undefined;
            if (openTkt?.id) {
              await addItflowTicketNote({
                localTicketId: openTkt.id,
                author: 'Vitrine Self-Healing Watchdog',
                body: `[Self-Healing ${remStatus}] Monitor '${mon.name || condType}':\n${remOutput.slice(0, 1500)}`,
                noteType: 'Internal'
              });
            }
          } catch {}
          if (remStatus === 'Failed' && Boolean(mon.alert_on_failure)) {
            try {
              db.prepare(`
                INSERT INTO notifications (id, tenant_id, type, title, message, severity)
                VALUES (?, ?, 'self_healing_failure', ?, ?, 'warning')
              `).run(
                `notif-rem-${crypto.randomUUID()}`,
                dev.tenant_id || null,
                `Self-Healing Remediation Failed: ${mon.name || condType} on ${dev.hostname || dev.id}`,
                remOutput.slice(0, 500) || 'Watchdog remediation returned a failure status.'
              );
            } catch {}
          }
        }
      }
    }
  } catch {}
}

export function startScheduler(): void {
  if (fastTimer) return;

  // Run maintenance/LAPS/backup/cron automation sweep every 60 seconds
  fastTimer = setInterval(async () => {
    if (tickInProgress || schedulerPausedForDbSwap) return;
    tickInProgress = true;
    try {
      await runMaintenanceAndLifecycleTick();
    } catch {
      // Never crash daemon on background tick error
    } finally {
      tickInProgress = false;
    }
  }, 60_000);
  if (typeof fastTimer.unref === 'function') fastTimer.unref();

  // Run fleet alert condition evaluation + self-healing watchdogs every 5 minutes once onboarded
  conditionTimer = setInterval(async () => {
    if (conditionTickInProgress || schedulerPausedForDbSwap) return;
    conditionTickInProgress = true;
    try {
      const settings = db.prepare('SELECT is_onboarded FROM settings WHERE id = 1').get() as
        | { is_onboarded?: number }
        | undefined;
      if (settings?.is_onboarded) {
        await runSelfHealingWatchdogSweep();
        await evaluateFleetAlertConditions();
      }
    } catch {
      // Ignore
    } finally {
      conditionTickInProgress = false;
    }
  }, 5 * 60_000);
  if (typeof conditionTimer.unref === 'function') conditionTimer.unref();
}

export function stopScheduler(): void {
  if (fastTimer) {
    clearInterval(fastTimer);
    fastTimer = null;
  }
  if (conditionTimer) {
    clearInterval(conditionTimer);
    conditionTimer = null;
  }
}
