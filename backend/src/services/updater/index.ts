import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { execSync, execFileSync } from 'child_process';
import { fileURLToPath } from 'url';
import {
  db,
  APP_VERSION,
  APP_SCHEMA_VERSION,
  APP_INSTALLED_COMMIT,
  runDatabaseMigrations
} from '../../db/index.js';
import { backupService } from '../backup/index.js';
import { installerGenerator } from '../agent/installerGenerator.js';
import { sendAlertEmailUsingStoredSettings } from '../smtp/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface CommitInfo {
  sha: string;
  date: string;
  author: string;
  message: string;
  schemaVersion: number;
}

export interface ReleaseInfo {
  version: string;
  tag: string;
  commitSha: string;
  publishedAt: string;
  schemaVersion: number;
  title: string;
  releaseNotes: string;
}

const GITHUB_REPO = process.env.VITRINE_GITHUB_REPO || 'TylerHats/Vitrine-RMM';

export function isRunningInDocker(): boolean {
  if (process.env.VITRINE_DOCKER === 'true') return true;
  if (fs.existsSync('/.dockerenv')) return true;
  try {
    if (fs.existsSync('/proc/1/cgroup')) {
      const cgroup = fs.readFileSync('/proc/1/cgroup', 'utf8');
      if (cgroup.includes('docker') || cgroup.includes('containerd') || cgroup.includes('kubepods')) {
        return true;
      }
    }
  } catch {
    // Ignore
  }
  return false;
}

function compareSemver(a: string, b: string): number {
  const cleanA = String(a || '0.0.0').replace(/^v/i, '').split('-')[0].split('.').map((n) => parseInt(n, 10) || 0);
  const cleanB = String(b || '0.0.0').replace(/^v/i, '').split('-')[0].split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    const diff = (cleanA[i] || 0) - (cleanB[i] || 0);
    if (diff !== 0) return diff > 0 ? 1 : -1;
  }
  return 0;
}

// Baseline local commit & release metadata used before/without GitHub API connectivity
function buildBaselineCommits(): CommitInfo[] {
  try {
    const repoRoot = path.resolve(__dirname, '../../../..');
    const altRoot = path.resolve(__dirname, '../../..');
    const gitDir = fs.existsSync(path.join(altRoot, '.git'))
      ? altRoot
      : fs.existsSync(path.join(repoRoot, '.git'))
        ? repoRoot
        : null;
    if (gitDir) {
      const raw = execSync('git log -n 10 --pretty=format:"%h|%cI|%an|%s" --reverse', {
        cwd: gitDir,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore']
      });
      const parsed = raw
        .split(/\r?\n/)
        .filter(Boolean)
        .map((line) => {
          const [sha, date, author, ...msgParts] = line.split('|');
          return {
            sha: (sha || '').trim(),
            date: (date || new Date().toISOString()).trim(),
            author: (author || 'Vitrine Maintainer').trim(),
            message: msgParts.join('|').trim(),
            schemaVersion: APP_SCHEMA_VERSION
          };
        })
        .filter((c) => Boolean(c.sha));
      if (parsed.length > 0) return parsed;
    }
  } catch {
    // Fallback to static release history
  }

  return [
    {
      sha: '2ae86f1',
      date: '2026-11-05T23:17:22Z',
      author: 'Tyler Hatfield',
      message: 'feat: add 3-OS parity, SYSTEM/User PTY shell, OS-isolated Ghost desktops, and 5-tier WoL/AMT chain',
      schemaVersion: 14
    },
    {
      sha: APP_INSTALLED_COMMIT,
      date: new Date().toISOString(),
      author: 'Tyler Hatfield',
      message: 'release(v2.5.0): zero-trust RBAC/MFA auth, encrypted vault & atomic SQLite backups, live condition alerting, and full security hardening',
      schemaVersion: APP_SCHEMA_VERSION
    }
  ];
}

const BASELINE_STABLE_RELEASES: ReleaseInfo[] = [
  {
    version: '2.4.0',
    tag: 'v2.4.0',
    commitSha: '2ae86f1',
    publishedAt: '2026-11-05T23:30:00Z',
    schemaVersion: 14,
    title: 'Vitrine RMM v2.4.0 — 3-OS Parity, Ghost Desktops & 5-Tier WoL/AMT',
    releaseNotes: `### Highlights in v2.4.0
- **Interactive Remote Screen Control**: Standard KVM, OS-isolated Ghost Desktops, and Intel AMT Hardware KVM.
- **Dual-Context PTY Shell**: Toggle between SYSTEM/root and Logged-In User sessions.
- **Network Appliance Fleet**: Live probes and designated local agent relays.
- **5-Tier Peer-Relayed WoL & AMT**: Reachability chain across local and historical roaming subnets.`
  },
  {
    version: APP_VERSION,
    tag: `v${APP_VERSION}`,
    commitSha: APP_INSTALLED_COMMIT,
    publishedAt: new Date().toISOString(),
    schemaVersion: APP_SCHEMA_VERSION,
    title: `Vitrine RMM v${APP_VERSION} — Enterprise Security Hardening, Multi-MS2 Federation & Atomic Backups`,
    releaseNotes: `### Highlights in v${APP_VERSION} (Stable Release)
- **Zero-Trust Session Auth, RBAC & Step-Up MFA**: Scrypt password hashing, RFC 6238 TOTP with replay guard, one-time recovery codes, and tenant-scoped RBAC.
- **Per-Instance AES-256-GCM Secret Vault**: Encrypts LAPS, BitLocker recovery keys, MeshCentral tokens, SMTP, S3, and specialty vendor tokens at rest.
- **Atomic Self-Backup & Live SQLite Restore**: \`VACUUM INTO\` consistent database snapshots, optional AES-256-GCM archive encryption, AWS SigV4 S3/B2/R2 offsite sync, and schema compatibility checks.
- **4-Tier Policy Engine & 13 Condition Alert Rules**: Explicit per-field override tracking, maintenance-window suppression, live SMTP alerts, and ITFlow PSA ticket creation.`
  }
];

export class SystemUpdaterService {
  private cachedCommits: CommitInfo[] = buildBaselineCommits();
  private cachedReleases: ReleaseInfo[] = [...BASELINE_STABLE_RELEASES];
  private lastUpstreamFetchMs = 0;
  private upstreamSource: 'github_live' | 'local_git' = 'local_git';

  public async refreshUpstreamCatalog(force = false): Promise<void> {
    if (!force && Date.now() - this.lastUpstreamFetchMs < 60_000) {
      return;
    }
    this.lastUpstreamFetchMs = Date.now();

    try {
      const headers: Record<string, string> = {
        Accept: 'application/vnd.github+json',
        'User-Agent': `Vitrine-RMM/${APP_VERSION}`
      };

      const [relRes, comRes] = await Promise.allSettled([
        fetch(`https://api.github.com/repos/${GITHUB_REPO}/releases?per_page=10`, {
          headers,
          signal: AbortSignal.timeout(4500)
        }),
        fetch(`https://api.github.com/repos/${GITHUB_REPO}/commits?sha=main&per_page=15`, {
          headers,
          signal: AbortSignal.timeout(4500)
        })
      ]);

      if (comRes.status === 'fulfilled' && comRes.value.ok) {
        const comJson = (await comRes.value.json()) as any[];
        if (Array.isArray(comJson) && comJson.length > 0) {
          // GitHub returns newest -> oldest; store chronological oldest -> newest
          this.cachedCommits = comJson
            .slice()
            .reverse()
            .map((c: any) => ({
              sha: String(c.sha || '').slice(0, 7),
              date: String(c.commit?.committer?.date || c.commit?.author?.date || new Date().toISOString()),
              author: String(c.commit?.author?.name || c.author?.login || 'Maintainer'),
              message: String(c.commit?.message || '').split('\n')[0],
              schemaVersion: APP_SCHEMA_VERSION
            }));
          this.upstreamSource = 'github_live';
        }
      }

      if (relRes.status === 'fulfilled' && relRes.value.ok) {
        const relJson = (await relRes.value.json()) as any[];
        if (Array.isArray(relJson)) {
          const stableOnly = relJson.filter((r) => !r.draft && !r.prerelease);
          if (stableOnly.length > 0) {
            this.cachedReleases = stableOnly
              .slice()
              .reverse()
              .map((r: any) => {
                const tag = String(r.tag_name || 'v2.5.0');
                const ver = tag.replace(/^v/i, '');
                return {
                  version: ver,
                  tag,
                  commitSha: String(r.target_commitish || APP_INSTALLED_COMMIT).slice(0, 7),
                  publishedAt: String(r.published_at || new Date().toISOString()),
                  schemaVersion: APP_SCHEMA_VERSION,
                  title: String(r.name || `Vitrine RMM ${tag}`),
                  releaseNotes: String(r.body || '')
                };
              });
            this.upstreamSource = 'github_live';
          }
        }
      }
    } catch {
      // Offline or rate-limited: retain baseline catalog
    }
  }

  private findCommitIndex(sha: string): number {
    if (!sha) return -1;
    const short = sha.slice(0, 7).toLowerCase();
    return this.cachedCommits.findIndex((c) => c.sha.slice(0, 7).toLowerCase() === short);
  }

  public async getStatusAsync(forceRefresh = false) {
    await this.refreshUpstreamCatalog(forceRefresh);
    return this.getStatus();
  }

  public getStatus() {
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    const channel: 'stable' | 'alpha' = settings.update_channel === 'alpha' ? 'alpha' : 'stable';
    const installedVersion = String(settings.installed_version || APP_VERSION);
    const installedCommit = String(settings.installed_commit || APP_INSTALLED_COMMIT);
    const installedSchemaVersion = Number(settings.db_schema_version || APP_SCHEMA_VERSION);
    const deploymentMode: 'docker' | 'bare_metal' = isRunningInDocker() ? 'docker' : 'bare_metal';

    const latestStable =
      this.cachedReleases[this.cachedReleases.length - 1] || BASELINE_STABLE_RELEASES[BASELINE_STABLE_RELEASES.length - 1];
    const latestAlpha =
      this.cachedCommits[this.cachedCommits.length - 1] || {
        sha: APP_INSTALLED_COMMIT,
        date: new Date().toISOString(),
        author: 'Tyler Hatfield',
        message: `Vitrine RMM v${APP_VERSION}`,
        schemaVersion: APP_SCHEMA_VERSION
      };

    const currentIdx = this.findCommitIndex(installedCommit);
    const latestStableIdx = this.findCommitIndex(latestStable.commitSha);
    const latestAlphaIdx = this.cachedCommits.length - 1;

    const pendingAlphaCommits =
      currentIdx >= 0
        ? this.cachedCommits.slice(currentIdx + 1).reverse()
        : installedCommit.slice(0, 7) === latestAlpha.sha.slice(0, 7)
          ? []
          : this.cachedCommits.slice(-3).reverse();

    // Determine Alpha -> Stable eligibility safely even if commit SHAs came from a tag
    const isInstalledAlphaBuild = installedVersion.includes('-alpha');
    let canSwitchAlphaToStable = true;
    if (channel === 'alpha' || isInstalledAlphaBuild) {
      if (currentIdx >= 0 && latestStableIdx >= 0) {
        canSwitchAlphaToStable = currentIdx <= latestStableIdx;
      } else {
        canSwitchAlphaToStable = compareSemver(installedVersion, latestStable.version) <= 0 && !isInstalledAlphaBuild;
      }
    }

    const alphaToStableBlockReason = canSwitchAlphaToStable
      ? null
      : `Installed Alpha build (${installedVersion} @ ${installedCommit}) is ahead of the latest Stable release (${latestStable.tag}). Switching back to Stable is locked until a newer Stable release is published so the database schema never downgrades.`;

    let updateAvailable = false;
    if (channel === 'stable') {
      updateAvailable = compareSemver(installedVersion, latestStable.version) < 0;
    } else {
      if (currentIdx >= 0) {
        updateAvailable = currentIdx < latestAlphaIdx;
      } else {
        updateAvailable = installedCommit.slice(0, 7).toLowerCase() !== latestAlpha.sha.slice(0, 7).toLowerCase();
      }
    }

    const history = db.prepare('SELECT * FROM system_updates ORDER BY executed_at DESC LIMIT 20').all();
    const dbNewerThanSoftware = installedSchemaVersion > APP_SCHEMA_VERSION;

    return {
      channel,
      deploymentMode,
      upstreamSource: this.upstreamSource,
      dockerPullInstructions:
        deploymentMode === 'docker'
          ? 'docker compose pull && docker compose up -d'
          : null,
      installedVersion,
      installedCommit,
      installedSchemaVersion,
      targetSoftwareSchemaVersion: APP_SCHEMA_VERSION,
      dbNewerThanSoftware,
      updateAvailable,
      latestStable,
      latestAlpha,
      stableReleases: [...this.cachedReleases].reverse(),
      pendingAlphaCommits,
      allRecentCommits: [...this.cachedCommits].reverse(),
      canSwitchAlphaToStable,
      alphaToStableBlockReason,
      preferences: {
        autoBackup: Boolean(settings.update_auto_backup ?? 1),
        autoRollback: Boolean(settings.update_auto_rollback ?? 1),
        notifyWebUi: Boolean(settings.update_notify_webui ?? 1),
        notifyEmail: Boolean(settings.update_notify_email ?? 1),
        createPsaTicket: Boolean(settings.update_create_psa_ticket ?? 1)
      },
      history
    };
  }

  public setChannel(targetChannel: 'stable' | 'alpha') {
    const cleanTarget: 'stable' | 'alpha' = targetChannel === 'alpha' ? 'alpha' : 'stable';
    const status = this.getStatus();
    if (status.channel === 'alpha' && cleanTarget === 'stable' && !status.canSwitchAlphaToStable) {
      return {
        success: false,
        blockedByCommitGuard: true,
        error: status.alphaToStableBlockReason
      };
    }

    db.prepare('UPDATE settings SET update_channel = ? WHERE id = 1').run(cleanTarget);
    return {
      success: true,
      channel: cleanTarget,
      status: this.getStatus()
    };
  }

  public async notifyAdminsOfAvailableUpdate() {
    await this.refreshUpstreamCatalog(false);
    const status = this.getStatus();
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;

    const targetLabel =
      status.channel === 'stable'
        ? `${status.latestStable.tag} (${status.latestStable.commitSha})`
        : `Alpha Commit ${status.latestAlpha.sha}`;

    let notifCreated = false;
    let ticketCreated: string | null = null;
    let emailDispatched = false;

    const notifTitle = `System Update Available: ${targetLabel}`;
    const notifBody =
      status.channel === 'stable'
        ? `Stable release ${status.latestStable.title} is available.`
        : `${status.pendingAlphaCommits.length || 1} commit(s) available on the Alpha channel (${status.latestAlpha.message}).`;

    if (settings.update_notify_webui) {
      const existing = db
        .prepare("SELECT id FROM notifications WHERE type = 'system_update' AND title = ? AND is_read = 0 LIMIT 1")
        .get(notifTitle);
      if (!existing) {
        db.prepare(`
          INSERT INTO notifications (id, type, title, message, severity, is_read)
          VALUES (?, 'system_update', ?, ?, 'info', 0)
        `).run(`notif-upd-${crypto.randomUUID()}`, notifTitle, notifBody);
        notifCreated = true;
      }
    }

    if (settings.update_create_psa_ticket) {
      const ticketTitle = `[RMM Maintenance] Vitrine RMM Update Available: ${targetLabel}`;
      const existingTicket = db
        .prepare("SELECT ticket_number FROM psa_tickets WHERE title = ? AND status != 'Resolved' LIMIT 1")
        .get(ticketTitle) as { ticket_number?: string } | undefined;
      if (!existingTicket) {
        const ticketNum = `TKT-${crypto.randomInt(10000, 99999)}`;
        db.prepare(`
          INSERT INTO psa_tickets (id, ticket_number, title, client_name, status, priority)
          VALUES (?, ?, ?, 'Internal MSP Infrastructure', 'Open', 'Medium')
        `).run(`psa-upd-${crypto.randomUUID()}`, ticketNum, ticketTitle);
        ticketCreated = ticketNum;
      } else {
        ticketCreated = existingTicket.ticket_number || null;
      }
    }

    if (settings.update_notify_email) {
      const mailRes = await sendAlertEmailUsingStoredSettings({
        subject: `[Vitrine RMM] ${notifTitle}`,
        headline: notifTitle,
        bodyContent: `${notifBody}\n\nDeployment Mode: ${status.deploymentMode === 'docker' ? 'Docker Container (pull updated image)' : 'Bare-Metal Service'}`,
        severity: 'Info'
      });
      emailDispatched = mailRes.dispatched;
    }

    return {
      success: true,
      targetLabel,
      notifCreated,
      ticketCreated,
      emailDispatched
    };
  }

  public async executeUpdate(options?: { actorUsername?: string }) {
    await this.refreshUpstreamCatalog(true);
    const status = this.getStatus();
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    const actor = options?.actorUsername || 'admin';

    const fromVersion = status.installedVersion;
    const fromCommit = status.installedCommit;
    const targetVersion =
      status.channel === 'stable'
        ? status.latestStable.version
        : `${status.latestStable.version}-alpha.${status.latestAlpha.sha}`;
    const targetCommit =
      status.channel === 'stable' ? status.latestStable.commitSha : status.latestAlpha.sha;
    const targetNotes =
      status.channel === 'stable'
        ? status.latestStable.releaseNotes
        : status.pendingAlphaCommits.map((c) => `[${c.sha}] ${c.message}`).join('\n') || status.latestAlpha.message;

    // 1. Pre-Update Automatic Snapshot
    let preUpdateBackupId: string | null = null;
    if (settings.update_auto_backup) {
      const bak = backupService.createBackup({
        triggerType: 'pre-update',
        notes: `Automatic pre-update snapshot before upgrading ${fromVersion} (${fromCommit}) -> ${targetVersion} (${targetCommit})`
      });
      preUpdateBackupId = bak.id;
    }

    // 2. Containerized Docker Guard: Never mutate immutable container filesystem in-place!
    if (status.deploymentMode === 'docker') {
      runDatabaseMigrations();
      return {
        success: false,
        dockerManaged: true,
        rolledBack: false,
        preUpdateBackupId,
        instructions:
          'This Vitrine RMM instance is running inside an immutable Docker container. A pre-upgrade backup snapshot has been saved to your persistent /app/data/backups volume. To complete the upgrade, run `docker compose pull && docker compose up -d` on your Docker host.',
        error:
          'Containerized deployment detected: pull the updated `tylerhats/vitrine-rmm` Docker image on the host (`docker compose pull && docker compose up -d`). Pre-upgrade backup created.',
        status: this.getStatus()
      };
    }

    // 3. Bare-Metal Execution with Real Git Fetch + Build + Automatic Rollback on Any Error
    const repoCandidates = [path.resolve(__dirname, '../../..'), path.resolve(__dirname, '../../../..')];
    const repoRoot = repoCandidates.find((r) => fs.existsSync(path.join(r, '.git'))) || null;
    let preHeadSha: string | null = null;
    let gitUpdated = false;

    try {
      const gitSelfPullDisabled = process.env.VITRINE_DISABLE_GIT_SELF_PULL === 'true';
      const explicitGitSelfPull = process.env.VITRINE_ENABLE_GIT_SELF_PULL === 'true';

      if (repoRoot && !gitSelfPullDisabled && (explicitGitSelfPull || status.updateAvailable)) {
        const dirtyStatus = execFileSync('git', ['status', '--porcelain'], {
          cwd: repoRoot,
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
          timeout: 15000
        }).trim();

        if (dirtyStatus && !explicitGitSelfPull) {
          throw new Error(
            'Local repository has uncommitted modifications (`git status --porcelain` is non-empty). Commit or stash local changes before running bare-metal self-update.'
          );
        }

        preHeadSha = execFileSync('git', ['rev-parse', 'HEAD'], {
          cwd: repoRoot,
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
          timeout: 10000
        }).trim();

        const rawRef = status.channel === 'stable' ? status.latestStable.tag : 'origin/main';
        if (!/^[a-zA-Z0-9._/-]+$/.test(rawRef)) {
          throw new Error(`Invalid target git reference '${rawRef}'.`);
        }

        execFileSync('git', ['fetch', '--tags', 'origin'], {
          cwd: repoRoot,
          stdio: ['ignore', 'pipe', 'pipe'],
          timeout: 60000
        });

        if (status.channel === 'stable') {
          execFileSync('git', ['checkout', rawRef], {
            cwd: repoRoot,
            stdio: ['ignore', 'pipe', 'pipe'],
            timeout: 30000
          });
        } else {
          execFileSync('git', ['merge', '--ff-only', rawRef], {
            cwd: repoRoot,
            stdio: ['ignore', 'pipe', 'pipe'],
            timeout: 30000
          });
        }

        const postHeadSha = execFileSync('git', ['rev-parse', 'HEAD'], {
          cwd: repoRoot,
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
          timeout: 10000
        }).trim();

        if (postHeadSha !== preHeadSha || explicitGitSelfPull) {
          gitUpdated = postHeadSha !== preHeadSha;
          const npmBin = process.platform === 'win32' ? 'npm.cmd' : 'npm';
          for (const pkgDir of ['frontend', 'backend']) {
            execFileSync(npmBin, ['install', '--no-audit', '--no-fund', '--prefix', pkgDir], {
              cwd: repoRoot,
              stdio: ['ignore', 'pipe', 'pipe'],
              timeout: 180000
            });
            execFileSync(npmBin, ['run', 'build', '--prefix', pkgDir], {
              cwd: repoRoot,
              stdio: ['ignore', 'pipe', 'pipe'],
              timeout: 180000
            });
          }
        }
      }

      // Re-verify code signing pipeline for updated agent packages
      await installerGenerator.runSigningPipeline({
        os: 'windows',
        mode: 'permanent'
      });

      // Apply forward database migrations and record updated target
      runDatabaseMigrations();
      db.prepare(`
        UPDATE settings SET
          installed_version = ?,
          installed_commit = ?,
          db_schema_version = ?
        WHERE id = 1
      `).run(targetVersion, targetCommit, APP_SCHEMA_VERSION);

      const updateId = `upd-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`;
      db.prepare(`
        INSERT INTO system_updates (
          id, channel, from_version, to_version, from_commit, to_commit, status, backup_id, release_notes
        ) VALUES (?, ?, ?, ?, ?, ?, 'completed', ?, ?)
      `).run(
        updateId,
        status.channel,
        fromVersion,
        targetVersion,
        fromCommit,
        targetCommit,
        preUpdateBackupId,
        targetNotes
      );

      db.prepare(`
        INSERT INTO audit_logs (id, username, device_id, action, details)
        VALUES (?, ?, NULL, 'System Self-Update Completed', ?)
      `).run(
        `aud-upd-${crypto.randomUUID()}`,
        actor,
        `Updated on ${status.channel.toUpperCase()} channel: ${fromVersion} (${fromCommit}) -> ${targetVersion} (${targetCommit}). Pre-update backup: ${preUpdateBackupId || 'none'}.`
      );

      // If running under systemd and git compiled new server artifacts, schedule clean service restart after HTTP reply flushes
      const restartScheduled = Boolean(gitUpdated && (process.env.INVOCATION_ID || explicitGitSelfPull));
      if (restartScheduled) {
        setTimeout(() => {
          process.exit(0);
        }, 1500).unref();
      }

      return {
        success: true,
        rolledBack: false,
        gitUpdated,
        restartScheduled,
        fromVersion,
        toVersion: targetVersion,
        fromCommit,
        toCommit: targetCommit,
        preUpdateBackupId,
        ms2AgentsResigned: true,
        status: this.getStatus()
      };
    } catch (err: any) {
      const errorTrace = err?.stderr?.toString?.()?.slice(0, 400) || err?.message || 'Unexpected error during bare-metal update pipeline';
      let rolledBack = false;

      if (settings.update_auto_rollback) {
        // 1. Revert git working tree & recompile previous working build if git HEAD changed
        if (repoRoot && preHeadSha) {
          try {
            const npmBin = process.platform === 'win32' ? 'npm.cmd' : 'npm';
            execFileSync('git', ['reset', '--hard', preHeadSha], {
              cwd: repoRoot,
              stdio: ['ignore', 'pipe', 'pipe'],
              timeout: 30000
            });
            execFileSync(npmBin, ['run', 'build', '--prefix', 'frontend'], {
              cwd: repoRoot,
              stdio: ['ignore', 'pipe', 'pipe'],
              timeout: 180000
            });
            execFileSync(npmBin, ['run', 'build', '--prefix', 'backend'], {
              cwd: repoRoot,
              stdio: ['ignore', 'pipe', 'pipe'],
              timeout: 180000
            });
            rolledBack = true;
          } catch {
            // Continue to DB snapshot restore
          }
        }

        // 2. Restore pre-update atomic SQLite + Vault snapshot
        if (preUpdateBackupId) {
          try {
            backupService.restoreFromBackup(preUpdateBackupId, 'auto_migrate');
            rolledBack = true;
          } catch {
            rolledBack = false;
          }
        }
      }

      const updateId = `upd-fail-${Date.now()}`;
      db.prepare(`
        INSERT INTO system_updates (
          id, channel, from_version, to_version, from_commit, to_commit, status, backup_id, error_log, release_notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        updateId,
        status.channel,
        fromVersion,
        targetVersion,
        fromCommit,
        targetCommit,
        rolledBack ? 'rolled_back' : 'failed',
        preUpdateBackupId,
        errorTrace,
        targetNotes
      );

      db.prepare(`
        INSERT INTO notifications (id, type, title, message, severity, is_read)
        VALUES (?, 'update_rollback', ?, ?, 'critical', 0)
      `).run(
        `notif-rb-${crypto.randomUUID()}`,
        rolledBack ? 'Update Failed — Automatic Rollback Succeeded' : 'Update Failed',
        `${errorTrace}${rolledBack ? ` System database automatically restored to pre-update snapshot ${preUpdateBackupId}.` : ''}`
      );

      return {
        success: false,
        rolledBack,
        preUpdateBackupId,
        errorLog: errorTrace,
        status: this.getStatus()
      };
    }
  }
}

export const systemUpdaterService = new SystemUpdaterService();
