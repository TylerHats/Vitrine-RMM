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
import { meshBridge } from '../meshcentral/index.js';

let fastTimer: ReturnType<typeof setInterval> | null = null;
let conditionTimer: ReturnType<typeof setInterval> | null = null;
let tickInProgress = false;
let conditionTickInProgress = false;
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

function parseIncludePathsArray(rawJson?: string | null, isWindows = false): string[] {
  try {
    const parsed = typeof rawJson === 'string' ? JSON.parse(rawJson) : rawJson;
    if (Array.isArray(parsed)) {
      const valid = parsed
        .filter((p): p is string => typeof p === 'string' && p.trim().length > 0 && !p.includes('\0'))
        .map((p) => p.trim());
      if (valid.length > 0) {
        const filtered = isWindows
          ? valid.filter((p) => /^[a-zA-Z]:\\|^\\\\/.test(p))
          : valid.filter((p) => p.startsWith('/'));
        if (filtered.length > 0) return filtered;
        return valid;
      }
    }
  } catch {}
  return isWindows ? ['C:\\Users'] : ['/etc', '/home'];
}

function buildBackupJobCommand(
  osType: string | undefined,
  engineRaw: string | undefined,
  targetRepoRaw: string | undefined,
  includePathsJson: string | undefined,
  jobId: string
): { code: string; shell: 'powershell' | 'bash'; includePaths: string[] } {
  const isWindows = String(osType || '').toLowerCase() === 'windows';
  const engine = String(engineRaw || 'restic').toLowerCase();
  const targetRepo = String(targetRepoRaw || '').trim();
  const includePaths = parseIncludePathsArray(includePathsJson, isWindows);
  const safeJobSlug = jobId.replace(/[^a-zA-Z0-9_-]/g, '');

  if (isWindows) {
    if (engine === 'restic' && targetRepo) {
      const quotedRepo = quotePowerShellLiteral(targetRepo);
      const quotedPaths = includePaths.map((p) => quotePowerShellLiteral(p)).join(', ');
      const code = `$repo = ${quotedRepo}; $paths = @(${quotedPaths}); if (Get-Command restic -ErrorAction SilentlyContinue) { & restic -r $repo backup @paths } else { vssadmin list shadows }`;
      return { code, shell: 'powershell', includePaths };
    }
    if (engine === 'vss' || !targetRepo) {
      return {
        code: `vssadmin list shadows`,
        shell: 'powershell',
        includePaths
      };
    }
    const quotedArchive = quotePowerShellLiteral(`C:\\ProgramData\\VitrineBackup-${safeJobSlug}.zip`);
    const quotedPaths = includePaths.map((p) => quotePowerShellLiteral(p)).join(', ');
    return {
      code: `Compress-Archive -Path @(${quotedPaths}) -DestinationPath ${quotedArchive} -Force -ErrorAction Stop; Write-Output "Snapshot saved: ${safeJobSlug}"`,
      shell: 'powershell',
      includePaths
    };
  }

  // POSIX (Linux / macOS)
  if (engine === 'restic' && targetRepo) {
    const quotedRepo = quoteBashLiteral(targetRepo);
    const quotedPaths = includePaths.map((p) => quoteBashLiteral(p)).join(' ');
    const fallbackTar = quoteBashLiteral(`/tmp/vitrine-snap-${safeJobSlug}.tar.gz`);
    return {
      code: `if command -v restic >/dev/null 2>&1; then restic -r ${quotedRepo} backup ${quotedPaths}; else tar -czf ${fallbackTar} ${quotedPaths} 2>/dev/null && ls -lh ${fallbackTar} && rm -f ${fallbackTar}; fi`,
      shell: 'bash',
      includePaths
    };
  }

  const archiveDest = targetRepo
    ? quoteBashLiteral(`${targetRepo.replace(/\/+$/, '')}/vitrine-snap-${safeJobSlug}.tar.gz`)
    : quoteBashLiteral(`/tmp/vitrine-snap-${safeJobSlug}.tar.gz`);
  const quotedPaths = includePaths.map((p) => quoteBashLiteral(p)).join(' ');
  const cleanupTail = targetRepo ? '' : ` && rm -f ${archiveDest}`;
  return {
    code: `tar -czf ${archiveDest} ${quotedPaths} 2>/dev/null && ls -lh ${archiveDest}${cleanupTail}`,
    shell: 'bash',
    includePaths
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

  // 3. Scheduled LAPS password expiry check (verified live delivery before vault commit; offline-safe deferral)
  try {
    const dueRows = db
      .prepare(`
        SELECT v.device_id
        FROM laps_vault v
        JOIN devices d ON d.id = v.device_id
        WHERE COALESCE(d.lifecycle_state, 'active') = 'active'
          AND COALESCE(v.rotation_pending_online, 0) = 0
          AND v.expires_at IS NOT NULL
          AND datetime(v.expires_at) <= datetime(?)
      `)
      .all(nowIso) as Array<{ device_id: string }>;

    for (const row of dueRows) {
      try {
        await rotateLapsPasswordVerifiedAsync(row.device_id, { actorUsername: 'scheduler' });
        lapsEvaluated++;
      } catch {}
    }
  } catch {}

  // 4. Prune expired auth sessions & aged session recordings (cleaning up .webm video files strictly inside RECORDINGS_DIR_PATH!)
  try {
    db.prepare('DELETE FROM auth_sessions WHERE datetime(expires_at) <= datetime(?)').run(nowIso);

    let retentionDays = 90;
    try {
      const globalPol = db
        .prepare("SELECT session_recording_retention_days FROM policies WHERE tier = 'global' LIMIT 1")
        .get() as { session_recording_retention_days?: number } | undefined;
      if (globalPol?.session_recording_retention_days && globalPol.session_recording_retention_days > 0) {
        retentionDays = globalPol.session_recording_retention_days;
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

      for (const dev of onlineDevs) {
        const eff = resolveEffectiveDevicePolicy(dev.id);
        if (eff.backupPolicyId && eff.backupPolicyId !== bp.id) continue;
        const jobId = `bjob-${crypto.randomUUID()}`;
        const built = buildBackupJobCommand(dev.os_type, bp.engine, bp.target_repo, bp.include_paths_json, jobId);

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

            if (scriptRow?.code) {
              const isWin = String(dev.os_type || '').toLowerCase() === 'windows';
              const lang = scriptRow.language === 'powershell' ? 'powershell' : 'bash';
              if ((isWin && lang === 'powershell') || (!isWin && lang === 'bash')) {
                const execRes = await meshBridge.executeCommandOnNode(dev.id, scriptRow.code, {
                  shell: lang,
                  timeoutMs: 15000
                });
                if (execRes.output) remOutput = `${remOutput}\n${execRes.output}`.trim();
                if (execRes.exitCode !== 0 && !execRes.queued) remStatus = 'Failed';
              }
            }
          }
        } else if (
          (condType === 'disk_space_low' || condType === 'disk_low') &&
          dev.disk_total_gb > 0
        ) {
          const thresholdPct = Number(condValStr || 10);
          const freePct = (Number(dev.disk_free_gb || 0) / Number(dev.disk_total_gb)) * 100;
          if (freePct < thresholdPct && scriptRow?.code) {
            triggered = true;
            const isWin = String(dev.os_type || '').toLowerCase() === 'windows';
            const lang = isWin ? 'powershell' : 'bash';
            const execRes = await meshBridge.executeCommandOnNode(dev.id, scriptRow.code, {
              shell: lang,
              timeoutMs: 20000
            });
            remOutput = execRes.output || `Executed remediation script ${scriptRow.name}.`;
            if (execRes.exitCode !== 0 && !execRes.queued) remStatus = 'Failed';
          }
        } else if (condType === 'cpu_high' || condType === 'high_cpu') {
          const thresholdPct = Number(condValStr || 90);
          if (Number(dev.cpu_usage || 0) >= thresholdPct && scriptRow?.code) {
            triggered = true;
            const isWin = String(dev.os_type || '').toLowerCase() === 'windows';
            const lang = isWin ? 'powershell' : 'bash';
            const execRes = await meshBridge.executeCommandOnNode(dev.id, scriptRow.code, {
              shell: lang,
              timeoutMs: 20000
            });
            remOutput = execRes.output || `Executed CPU remediation script ${scriptRow.name}.`;
            if (execRes.exitCode !== 0 && !execRes.queued) remStatus = 'Failed';
          }
        } else if (condType === 'ram_high' || condType === 'high_ram' || condType === 'memory_high') {
          const thresholdPct = Number(condValStr || 90);
          const ramPct = dev.ram_total_gb > 0 ? (Number(dev.ram_used_gb || 0) / Number(dev.ram_total_gb)) * 100 : 0;
          if (ramPct >= thresholdPct && scriptRow?.code) {
            triggered = true;
            const isWin = String(dev.os_type || '').toLowerCase() === 'windows';
            const lang = isWin ? 'powershell' : 'bash';
            const execRes = await meshBridge.executeCommandOnNode(dev.id, scriptRow.code, {
              shell: lang,
              timeoutMs: 20000
            });
            remOutput = execRes.output || `Executed memory remediation script ${scriptRow.name}.`;
            if (execRes.exitCode !== 0 && !execRes.queued) remStatus = 'Failed';
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
