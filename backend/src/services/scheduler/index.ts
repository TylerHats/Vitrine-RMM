import { db } from '../../db/index.js';
import { rotateLapsPassword } from '../laps/index.js';
import { sweepPendingOffboards } from '../offboarding/index.js';
import { backupService } from '../backup/index.js';
import { evaluateFleetAlertConditions, resolveEffectiveDevicePolicy } from '../policy/index.js';

let fastTimer: ReturnType<typeof setInterval> | null = null;
let conditionTimer: ReturnType<typeof setInterval> | null = null;
let tickInProgress = false;

export async function runMaintenanceAndLifecycleTick(): Promise<{
  expiredMaintenanceCleared: number;
  lapsEvaluated: number;
  autoArchivedOffboards: number;
  scheduledBackupCreated: boolean;
}> {
  const nowIso = new Date().toISOString();
  let expiredMaintenanceCleared = 0;
  let lapsEvaluated = 0;
  let autoArchivedOffboards = 0;
  let scheduledBackupCreated = false;

  // 1. Clear expired per-device maintenance_until flags
  try {
    const res = db
      .prepare(
        'UPDATE devices SET maintenance_until = NULL WHERE maintenance_until IS NOT NULL AND maintenance_until <= ?'
      )
      .run(nowIso);
    expiredMaintenanceCleared += res.changes;

    db.prepare('DELETE FROM maintenance_windows WHERE end_time <= ?').run(nowIso);
  } catch {
    // Ignore if schema migrating
  }

  // 2. Sweep pending offboard timeouts
  try {
    const sweep = sweepPendingOffboards();
    autoArchivedOffboards = sweep.autoArchivedCount;
  } catch {
    // Non-fatal
  }

  // 3. Scheduled LAPS password expiry check (offline-safe: rotateLapsPassword defers if endpoint is offline)
  try {
    const dueRows = db
      .prepare(`
        SELECT v.device_id
        FROM laps_vault v
        JOIN devices d ON d.id = v.device_id
        WHERE COALESCE(d.lifecycle_state, 'active') = 'active'
          AND COALESCE(v.rotation_pending_online, 0) = 0
          AND v.expires_at IS NOT NULL
          AND v.expires_at <= ?
      `)
      .all(nowIso) as Array<{ device_id: string }>;

    for (const row of dueRows) {
      try {
        rotateLapsPassword(row.device_id, { actorUsername: 'scheduler' });
        lapsEvaluated++;
      } catch {
        // Non-fatal per device
      }
    }
  } catch {
    // Non-fatal
  }

  // 4. Prune expired auth sessions & aged session recordings
  try {
    db.prepare('DELETE FROM auth_sessions WHERE expires_at <= ?').run(nowIso);

    let retentionDays = 90;
    try {
      const globalPol = db
        .prepare("SELECT session_recording_retention_days FROM policies WHERE tier = 'global' LIMIT 1")
        .get() as { session_recording_retention_days?: number } | undefined;
      if (globalPol?.session_recording_retention_days && globalPol.session_recording_retention_days > 0) {
        retentionDays = globalPol.session_recording_retention_days;
      }
    } catch {
      // Default 90 days
    }
    const cutoffIso = new Date(Date.now() - retentionDays * 86400 * 1000).toISOString();
    db.prepare('DELETE FROM session_recordings WHERE created_at <= ?').run(cutoffIso);
  } catch {
    // Non-fatal
  }

  // 5. Scheduled Backup Execution & Offsite Sync
  try {
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    if (settings.is_onboarded && settings.backup_schedule_enabled) {
      const freq: string = settings.backup_schedule_frequency || 'daily';
      const targetTime: string = settings.backup_schedule_time || '02:00';
      const [targetH, targetM] = targetTime.split(':').map((n: string) => parseInt(n, 10) || 0);

      const lastRow = db
        .prepare("SELECT created_at FROM system_backups WHERE trigger_type = 'scheduled' ORDER BY created_at DESC LIMIT 1")
        .get() as { created_at?: string } | undefined;
      const lastMs = lastRow?.created_at ? new Date(lastRow.created_at).getTime() : 0;
      const elapsedMs = Date.now() - lastMs;

      const minIntervalMs =
        freq === 'hourly'
          ? 55 * 60 * 1000
          : freq === 'weekly'
            ? 6.9 * 24 * 3600 * 1000
            : 23 * 3600 * 1000;

      const now = new Date();
      const todayTarget = new Date(now);
      todayTarget.setHours(targetH, targetM, 0, 0);
      const timeWindowReached =
        freq === 'hourly' ||
        lastMs === 0 ||
        now.getTime() >= todayTarget.getTime();

      if (elapsedMs >= minIntervalMs && timeWindowReached) {
        backupService.createBackup({
          triggerType: 'scheduled',
          notes: `Automated ${freq} scheduled backup`
        });
        scheduledBackupCreated = true;

        if (settings.backup_offsite_enabled) {
          await backupService.syncAllToOffsiteVault();
        }
      }
    }
  } catch {
    // Non-fatal
  }

  // Suppress unused import warning while keeping policy helper warm
  void resolveEffectiveDevicePolicy;

  return {
    expiredMaintenanceCleared,
    lapsEvaluated,
    autoArchivedOffboards,
    scheduledBackupCreated
  };
}

export function startScheduler(): void {
  if (fastTimer) return;

  // Run maintenance/LAPS/backup sweep every 60 seconds
  fastTimer = setInterval(async () => {
    if (tickInProgress) return;
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

  // Run fleet alert condition evaluation every 5 minutes once onboarded
  conditionTimer = setInterval(async () => {
    try {
      const settings = db.prepare('SELECT is_onboarded FROM settings WHERE id = 1').get() as
        | { is_onboarded?: number }
        | undefined;
      if (settings?.is_onboarded) {
        await evaluateFleetAlertConditions();
      }
    } catch {
      // Ignore
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
