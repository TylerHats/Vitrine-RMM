import fs from 'fs';
import os from 'os';
import path from 'path';
import zlib from 'zlib';
import crypto from 'crypto';
import {
  db,
  DATA_DIR_PATH,
  BRANDING_DIR_PATH,
  DB_FILE_PATH,
  APP_VERSION,
  APP_SCHEMA_VERSION,
  APP_INSTALLED_COMMIT,
  closeDatabase,
  reopenDatabase,
  runDatabaseMigrations
} from '../../db/index.js';
import {
  encryptVaultSecret,
  decryptVaultSecret,
  encryptBufferAesGcm,
  decryptBufferAesGcm,
  isEncryptedArchiveBuffer,
  reloadVaultMasterKey,
  validateOutboundHostSafety
} from '../vault/index.js';

const MAX_GUNZIP_BYTES = 256 * 1024 * 1024; // 256 MiB anti-gzip-bomb limit

export interface BackupManifest {
  backupId: string;
  filename: string;
  createdAt: string;
  triggerType: 'manual' | 'scheduled' | 'pre-update' | 'pre-restore' | 'uploaded';
  appVersion: string;
  gitCommit: string;
  dbSchemaVersion: number;
  includesBranding: boolean;
  includesMeshConfig: boolean;
  encrypted: boolean;
  notes?: string;
  tableCounts: {
    tenants: number;
    devices: number;
    policies: number;
    lapsVault: number;
    meshServers: number;
  };
  sha256Hash: string;
}

export interface BackupCompatibilityReport {
  status: 'exact_match' | 'older_db_auto_migratable' | 'newer_db_warning';
  backupSchemaVersion: number;
  targetSoftwareSchemaVersion: number;
  backupAppVersion: string;
  targetAppVersion: string;
  backupGitCommit: string;
  canRestoreCleanly: boolean;
  requiresAdminResolution: boolean;
  message: string;
  resolutionOptions: Array<{
    id: 'auto_migrate' | 'upgrade_software_to_match' | 'compatibility_safe_import' | 'cancel';
    label: string;
    description: string;
    recommended?: boolean;
  }>;
}

export function sanitizeBackupFilename(rawName?: string | null): string {
  const base = path.basename(String(rawName || '')).replace(/[^a-zA-Z0-9._-]/g, '_');
  if (!base || base === '.' || base === '..') {
    return `vitrine-backup-${Date.now()}.vrmm-backup.gz`;
  }
  if (base.endsWith('.vrmm-backup.gz') || base.endsWith('.gz')) {
    return base;
  }
  return `${base}.vrmm-backup.gz`;
}

// AWS Signature V4 helper for S3 / Backblaze B2 / Cloudflare R2 / MinIO offsite PUT
async function uploadBufferToS3Compatible(params: {
  endpointUrl: string;
  bucket: string;
  objectKey: string;
  accessKeyId: string;
  secretAccessKey: string;
  body: Buffer;
  region?: string;
}): Promise<{ ok: boolean; location?: string; error?: string }> {
  try {
    const endpoint = new URL(params.endpointUrl.trim());
    if (endpoint.protocol !== 'https:' && endpoint.protocol !== 'http:') {
      return { ok: false, error: 'Offsite endpoint must use http or https.' };
    }
    const safety = await validateOutboundHostSafety(params.endpointUrl, { allowLoopback: true });
    if (!safety.safe) {
      return { ok: false, error: safety.reason || 'Offsite endpoint blocked by SSRF policy.' };
    }
    const region = params.region || 'us-east-1';
    const service = 's3';
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = amzDate.slice(0, 8);

    const cleanBucket = params.bucket.replace(/^\/+|\/+$/g, '');
    const cleanKey = params.objectKey.replace(/^\/+/, '');
    const targetUrl = new URL(
      `${endpoint.pathname.replace(/\/$/, '')}/${encodeURIComponent(cleanBucket)}/${encodeURIComponent(cleanKey)}`,
      endpoint.origin
    );

    const payloadHash = crypto.createHash('sha256').update(params.body).digest('hex');
    const canonicalHeaders =
      `host:${targetUrl.host}\n` + `x-amz-content-sha256:${payloadHash}\n` + `x-amz-date:${amzDate}\n`;
    const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
    const canonicalRequest = [
      'PUT',
      targetUrl.pathname,
      '',
      canonicalHeaders,
      signedHeaders,
      payloadHash
    ].join('\n');

    const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
    const stringToSign = [
      'AWS4-HMAC-SHA256',
      amzDate,
      credentialScope,
      crypto.createHash('sha256').update(canonicalRequest).digest('hex')
    ].join('\n');

    const hmac = (key: Buffer | string, data: string) =>
      crypto.createHmac('sha256', key).update(data, 'utf8').digest();
    const kDate = hmac(`AWS4${params.secretAccessKey}`, dateStamp);
    const kRegion = hmac(kDate, region);
    const kService = hmac(kRegion, service);
    const kSigning = hmac(kService, 'aws4_request');
    const signature = crypto.createHmac('sha256', kSigning).update(stringToSign, 'utf8').digest('hex');

    const authorization = `AWS4-HMAC-SHA256 Credential=${params.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    const res = await fetch(targetUrl.toString(), {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/octet-stream',
        'x-amz-content-sha256': payloadHash,
        'x-amz-date': amzDate,
        Authorization: authorization
      },
      body: new Uint8Array(params.body),
      signal: AbortSignal.timeout(20000)
    });

    if (!res.ok) {
      const txt = (await res.text()).slice(0, 200);
      return { ok: false, error: `Offsite S3 HTTP ${res.status}: ${txt}` };
    }

    return { ok: true, location: `s3://${cleanBucket}/${cleanKey}` };
  } catch (err: any) {
    return { ok: false, error: err?.message || 'Offsite upload failed' };
  }
}

export class BackupService {
  public getBackupsDir(): string {
    const backupsDir = path.join(DATA_DIR_PATH, 'backups');
    if (!fs.existsSync(backupsDir)) {
      fs.mkdirSync(backupsDir, { recursive: true, mode: 0o700 });
    }
    return backupsDir;
  }

  public resolveVerifiedBackupFilePath(filename: string): string {
    const backupsDir = fs.realpathSync(this.getBackupsDir());
    const safeName = sanitizeBackupFilename(filename);
    const candidate = path.resolve(backupsDir, safeName);
    if (!candidate.startsWith(backupsDir + path.sep)) {
      throw new Error('Invalid backup filename path.');
    }
    return candidate;
  }

  public isPathInsideBackupsDir(candidatePath?: string | null): boolean {
    if (!candidatePath) return false;
    try {
      const backupsDir = fs.realpathSync(this.getBackupsDir());
      const resolvedParent = fs.realpathSync(path.dirname(candidatePath));
      const finalPath = path.join(resolvedParent, path.basename(candidatePath));
      return finalPath.startsWith(backupsDir + path.sep);
    } catch {
      return false;
    }
  }

  private getBackupEncryptionPassphrase(): string {
    const settings = (db.prepare('SELECT backup_encryption_passphrase FROM settings WHERE id = 1').get() || {}) as any;
    return decryptVaultSecret(settings.backup_encryption_passphrase) || '';
  }

  public getOrGenerateRecoveryPassphrase(markAcknowledged = true): {
    passphrase: string;
    encryptionEnabled: boolean;
    acknowledged: boolean;
  } {
    const settings = (
      db
        .prepare(
          'SELECT backup_encryption_passphrase, backup_encryption_enabled, backup_key_acknowledged FROM settings WHERE id = 1'
        )
        .get() || {}
    ) as any;

    let pass = decryptVaultSecret(settings.backup_encryption_passphrase) || '';
    if (!pass) {
      pass = crypto.randomBytes(24).toString('base64url');
      db.prepare('UPDATE settings SET backup_encryption_passphrase = ? WHERE id = 1').run(encryptVaultSecret(pass));
    }
    if (markAcknowledged) {
      db.prepare('UPDATE settings SET backup_key_acknowledged = 1 WHERE id = 1').run();
    }
    return {
      passphrase: pass,
      encryptionEnabled: Boolean(settings.backup_encryption_enabled ?? 1),
      acknowledged: markAcknowledged ? true : Boolean(settings.backup_key_acknowledged)
    };
  }

  private unpackArchiveBuffer(rawBuf: Buffer, explicitPassphrase?: string): any {
    let gzBuf = rawBuf;
    if (isEncryptedArchiveBuffer(rawBuf)) {
      const pass = explicitPassphrase || this.getBackupEncryptionPassphrase();
      if (!pass) {
        throw new Error('Backup archive is AES-256-GCM encrypted, and no decryption passphrase is available.');
      }
      gzBuf = decryptBufferAesGcm(rawBuf, pass);
    }
    const jsonBuf = zlib.gunzipSync(gzBuf, { maxOutputLength: MAX_GUNZIP_BYTES });
    return JSON.parse(jsonBuf.toString('utf8'));
  }

  public inspectCompatibility(
    backupSchemaVersion: number,
    backupAppVersion: string,
    backupCommit: string
  ): BackupCompatibilityReport {
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    const currentAppVersion = settings.installed_version || APP_VERSION;

    if (backupSchemaVersion === APP_SCHEMA_VERSION) {
      return {
        status: 'exact_match',
        backupSchemaVersion,
        targetSoftwareSchemaVersion: APP_SCHEMA_VERSION,
        backupAppVersion,
        targetAppVersion: currentAppVersion,
        backupGitCommit: backupCommit,
        canRestoreCleanly: true,
        requiresAdminResolution: false,
        message: `Database schema v${backupSchemaVersion} matches installed software v${currentAppVersion} (Schema v${APP_SCHEMA_VERSION}) exactly.`,
        resolutionOptions: [
          {
            id: 'auto_migrate',
            label: 'Standard Atomic Restore',
            description: 'Atomically restore SQLite database, LAPS/BitLocker vault keys, branding assets, and MeshCentral bridge settings.',
            recommended: true
          }
        ]
      };
    }

    if (backupSchemaVersion < APP_SCHEMA_VERSION) {
      return {
        status: 'older_db_auto_migratable',
        backupSchemaVersion,
        targetSoftwareSchemaVersion: APP_SCHEMA_VERSION,
        backupAppVersion,
        targetAppVersion: currentAppVersion,
        backupGitCommit: backupCommit,
        canRestoreCleanly: true,
        requiresAdminResolution: false,
        message: `Backup DB is from an older schema (v${backupSchemaVersion}, App ${backupAppVersion}). Vitrine will automatically run forward schema migrations to upgrade the restored DB to v${APP_SCHEMA_VERSION} (${currentAppVersion}).`,
        resolutionOptions: [
          {
            id: 'auto_migrate',
            label: `Restore & Auto-Upgrade DB Schema (v${backupSchemaVersion} -> v${APP_SCHEMA_VERSION})`,
            description: 'Restores all data from the older backup and automatically applies forward non-destructive DDL migrations.',
            recommended: true
          }
        ]
      };
    }

    return {
      status: 'newer_db_warning',
      backupSchemaVersion,
      targetSoftwareSchemaVersion: APP_SCHEMA_VERSION,
      backupAppVersion,
      targetAppVersion: currentAppVersion,
      backupGitCommit: backupCommit,
      canRestoreCleanly: false,
      requiresAdminResolution: true,
      message: `WARNING: Backup Database Schema (v${backupSchemaVersion} from App ${backupAppVersion}, commit ${backupCommit}) is NEWER than the currently installed software target (Schema v${APP_SCHEMA_VERSION}, App ${currentAppVersion}).`,
      resolutionOptions: [
        {
          id: 'upgrade_software_to_match',
          label: `Update Vitrine Software First, Then Restore`,
          description: 'Upgrade the Vitrine RMM binary/image to match or exceed the backup schema version before restoring.',
          recommended: true
        },
        {
          id: 'compatibility_safe_import',
          label: `Force Compatibility Import into Schema v${APP_SCHEMA_VERSION}`,
          description: 'Creates a pre-restore snapshot and transactionally imports all matching tables/columns while ignoring unrecognized newer columns.',
          recommended: false
        },
        {
          id: 'cancel',
          label: 'Abort Restore',
          description: 'Keep the current database untouched and cancel restoration.'
        }
      ]
    };
  }

  private createConsistentSqliteSnapshotBuffer(): Buffer {
    const tmpSnapshot = path.join(os.tmpdir(), `vitrine-snap-${crypto.randomUUID()}.db`);
    try {
      const escapedPath = tmpSnapshot.replace(/'/g, "''");
      db.exec(`VACUUM INTO '${escapedPath}'`);
      return fs.readFileSync(tmpSnapshot);
    } catch {
      try {
        db.pragma('wal_checkpoint(TRUNCATE)');
      } catch {}
      return fs.existsSync(DB_FILE_PATH) ? fs.readFileSync(DB_FILE_PATH) : Buffer.alloc(0);
    } finally {
      try {
        if (fs.existsSync(tmpSnapshot)) fs.unlinkSync(tmpSnapshot);
      } catch {}
    }
  }

  private snapshotAllTables(): Record<string, any[]> {
    const tableRows = db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT IN ('system_backups', 'auth_sessions')"
      )
      .all() as Array<{ name: string }>;

    const snapshot: Record<string, any[]> = {};
    for (const { name } of tableRows) {
      if (/^[a-zA-Z0-9_]+$/.test(name)) {
        snapshot[name] = db.prepare(`SELECT * FROM "${name}"`).all();
      }
    }
    return snapshot;
  }

  public createBackup(options?: {
    triggerType?: 'manual' | 'scheduled' | 'pre-update' | 'pre-restore';
    notes?: string;
    actorUsername?: string;
  }) {
    const triggerType = options?.triggerType || 'manual';
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;

    const appVersion = APP_VERSION;
    const gitCommit = APP_INSTALLED_COMMIT;
    const dbSchemaVersion = APP_SCHEMA_VERSION;
    const includesBranding = Boolean(settings.backup_include_branding ?? 1);
    const includesMeshConfig = Boolean(settings.backup_include_mesh_config ?? 1);

    const backupId = `bak-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const timestampSlug = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const safeCommit = String(gitCommit).replace(/[^a-zA-Z0-9._-]/g, '').slice(0, 12) || 'head';
    const filename = sanitizeBackupFilename(
      `vitrine-backup-${triggerType}-${timestampSlug}-v${appVersion}-${safeCommit}.vrmm-backup.gz`
    );
    const filePath = this.resolveVerifiedBackupFilePath(filename);

    const tenantsCount = (db.prepare('SELECT COUNT(*) as c FROM tenants').get() as any)?.c || 0;
    const devicesCount = (db.prepare('SELECT COUNT(*) as c FROM devices').get() as any)?.c || 0;
    const policiesCount = (db.prepare('SELECT COUNT(*) as c FROM policies').get() as any)?.c || 0;
    const lapsCount = (db.prepare('SELECT COUNT(*) as c FROM laps_vault').get() as any)?.c || 0;
    const meshServersCount = (db.prepare('SELECT COUNT(*) as c FROM mesh_servers').get() as any)?.c || 0;

    // Bundle all branding files from canonical BRANDING_DIR_PATH
    let brandingLogoBase64: string | null = null;
    const brandingFiles: Record<string, string> = {};
    if (includesBranding && fs.existsSync(BRANDING_DIR_PATH)) {
      for (const entry of fs.readdirSync(BRANDING_DIR_PATH)) {
        const full = path.join(BRANDING_DIR_PATH, entry);
        try {
          if (fs.statSync(full).isFile() && fs.statSync(full).size <= 15 * 1024 * 1024) {
            const b64 = fs.readFileSync(full).toString('base64');
            brandingFiles[entry] = b64;
            if (entry === 'logo.png') brandingLogoBase64 = b64;
          }
        } catch {}
      }
    }

    // Read configured local MeshCentral config if readable (never modifying MS2)
    let meshConfigJson: string | null = null;
    if (includesMeshConfig) {
      const primaryServer = db
        .prepare('SELECT local_config_path FROM mesh_servers WHERE local_config_path IS NOT NULL LIMIT 1')
        .get() as { local_config_path?: string } | undefined;
      const mcCandidates = [
        primaryServer?.local_config_path,
        '/opt/meshcentral/meshcentral-data/config.json',
        path.resolve(process.cwd(), 'dev-meshcentral/meshcentral-data/config.json'),
        path.resolve(process.cwd(), '../dev-meshcentral/meshcentral-data/config.json')
      ].filter(Boolean) as string[];
      const mcPath = mcCandidates.find((p) => {
        try {
          return fs.existsSync(p) && fs.statSync(p).isFile();
        } catch {
          return false;
        }
      });
      if (mcPath) {
        try {
          meshConfigJson = fs.readFileSync(mcPath, 'utf8');
        } catch {}
      }
    }

    // Include .vault-key.json inside archive so LAPS & BitLocker ciphertexts self-restore cleanly on new hardware
    let vaultKeyJson: string | null = null;
    const vaultKeyPath = path.join(DATA_DIR_PATH, '.vault-key.json');
    if (fs.existsSync(vaultKeyPath)) {
      try {
        vaultKeyJson = fs.readFileSync(vaultKeyPath, 'utf8');
      } catch {}
    }

    const tablesSnapshot = this.snapshotAllTables();
    const rawDbBuffer = this.createConsistentSqliteSnapshotBuffer();
    const rawDbBase64 = rawDbBuffer.toString('base64');

    const encryptionRequested = Boolean(settings.backup_encryption_enabled ?? 1);
    const encryptionPassphrase = this.getBackupEncryptionPassphrase();
    const actuallyEncrypted = Boolean(encryptionRequested && encryptionPassphrase);

    const archivePayload = {
      format: 'VITRINE_RMM_UNIFIED_BACKUP_V2',
      manifest: {
        backupId,
        filename,
        createdAt: new Date().toISOString(),
        triggerType,
        appVersion,
        gitCommit,
        dbSchemaVersion,
        includesBranding,
        includesMeshConfig,
        encrypted: actuallyEncrypted,
        notes: options?.notes || `Automated ${triggerType} system snapshot`,
        tableCounts: {
          tenants: tenantsCount,
          devices: devicesCount,
          policies: policiesCount,
          lapsVault: lapsCount,
          meshServers: meshServersCount
        }
      },
      brandingLogoBase64,
      brandingFiles,
      meshConfigJson,
      vaultKeyJson,
      tablesSnapshot,
      rawDbBase64
    };

    const jsonBuffer = Buffer.from(JSON.stringify(archivePayload), 'utf8');
    const compressed = zlib.gzipSync(jsonBuffer);
    const finalDiskBuffer = actuallyEncrypted
      ? encryptBufferAesGcm(compressed, encryptionPassphrase)
      : compressed;

    const sha256Hash = crypto.createHash('sha256').update(finalDiskBuffer).digest('hex');
    fs.writeFileSync(filePath, finalDiskBuffer, { mode: 0o600 });
    const sizeBytes = finalDiskBuffer.length;

    db.prepare(`
      INSERT INTO system_backups (
        id, filename, file_path, size_bytes, trigger_type, app_version, git_commit,
        db_schema_version, sha256_hash, includes_branding, includes_mesh_config, notes,
        encrypted, offsite_synced, offsite_location
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'local-only')
    `).run(
      backupId,
      filename,
      filePath,
      sizeBytes,
      triggerType,
      appVersion,
      gitCommit,
      dbSchemaVersion,
      sha256Hash,
      includesBranding ? 1 : 0,
      includesMeshConfig ? 1 : 0,
      options?.notes || `System backup (${triggerType})`,
      actuallyEncrypted ? 1 : 0
    );

    this.enforceRetentionPolicy();

    return {
      id: backupId,
      filename,
      sizeBytes,
      triggerType,
      appVersion,
      gitCommit,
      dbSchemaVersion,
      sha256Hash,
      includesBranding,
      includesMeshConfig,
      encrypted: actuallyEncrypted,
      offsiteSynced: false,
      offsiteLocation: 'local-only',
      notes: options?.notes || `System backup (${triggerType})`,
      createdAt: archivePayload.manifest.createdAt
    };
  }

  public async syncAllToOffsiteVault(): Promise<{
    success: boolean;
    provider: string;
    bucket: string;
    syncedCount: number;
    encryptionCipher: string;
    message: string;
  }> {
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    const provider = settings.backup_offsite_provider || 's3';
    const endpoint = (settings.backup_offsite_endpoint || '').trim();
    const bucket = (settings.backup_offsite_bucket || '').trim();
    const accessKey = decryptVaultSecret(settings.backup_offsite_access_key);
    const secretKey = decryptVaultSecret(settings.backup_offsite_secret_key);

    if (!endpoint || !bucket || !accessKey || !secretKey) {
      return {
        success: false,
        provider,
        bucket: bucket || '(unconfigured)',
        syncedCount: 0,
        encryptionCipher: 'AES-256-GCM (Scrypt KDF)',
        message:
          'Offsite S3 vault credentials (Endpoint URL, Bucket Name, Access Key, and Secret Key) must be configured in Settings before syncing.'
      };
    }

    const all = db.prepare('SELECT * FROM system_backups ORDER BY created_at DESC').all() as any[];
    let syncedCount = 0;
    const errors: string[] = [];

    for (const b of all) {
      if (!this.isPathInsideBackupsDir(b.file_path) || !fs.existsSync(b.file_path)) continue;
      const body = fs.readFileSync(b.file_path);
      const up = await uploadBufferToS3Compatible({
        endpointUrl: endpoint,
        bucket,
        objectKey: b.filename,
        accessKeyId: accessKey,
        secretAccessKey: secretKey,
        body
      });
      if (up.ok && up.location) {
        db.prepare('UPDATE system_backups SET offsite_synced = 1, offsite_location = ? WHERE id = ?').run(
          up.location,
          b.id
        );
        syncedCount++;
      } else if (up.error) {
        errors.push(`${b.filename}: ${up.error}`);
      }
    }

    if (syncedCount === 0 && errors.length > 0) {
      return {
        success: false,
        provider,
        bucket,
        syncedCount: 0,
        encryptionCipher: 'AES-256-GCM (Scrypt KDF)',
        message: `Offsite sync failed: ${errors[0]}`
      };
    }

    return {
      success: true,
      provider,
      bucket,
      syncedCount,
      encryptionCipher: 'AES-256-GCM (Scrypt KDF)',
      message: `Uploaded ${syncedCount} backup archive(s) to offsite ${provider.toUpperCase()} bucket (${bucket}).`
    };
  }

  public enforceRetentionPolicy() {
    try {
      const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
      const maxCount = Math.max(2, Number(settings.backup_retention_count || 14));
      const maxStorageBytes = Math.max(64, Number(settings.backup_max_storage_mb || 2048)) * 1024 * 1024;

      const allBackups = db
        .prepare('SELECT * FROM system_backups ORDER BY created_at DESC')
        .all() as Array<any>;

      let runningBytes = 0;
      for (let idx = 0; idx < allBackups.length; idx++) {
        const b = allBackups[idx];
        runningBytes += Number(b.size_bytes || 0);
        // Always retain at least the 2 newest snapshots regardless of storage cap
        const exceedsCount = idx >= maxCount;
        const exceedsStorage = idx >= 2 && runningBytes > maxStorageBytes;

        if (exceedsCount || exceedsStorage) {
          if (this.isPathInsideBackupsDir(b.file_path) && fs.existsSync(b.file_path)) {
            try {
              fs.unlinkSync(b.file_path);
            } catch {}
          }
          db.prepare('DELETE FROM system_backups WHERE id = ?').run(b.id);
        }
      }
    } catch {
      // Ignore retention errors
    }
  }

  public listBackups() {
    const rows = db.prepare('SELECT * FROM system_backups ORDER BY created_at DESC').all() as Array<any>;
    const settings = (db.prepare('SELECT * FROM settings WHERE id = 1').get() || {}) as any;
    const maxStorageMb = Number(settings.backup_max_storage_mb || 2048);
    const retentionCount = Number(settings.backup_retention_count || 14);

    let totalBytes = 0;
    const items = rows.map((r) => {
      totalBytes += Number(r.size_bytes || 0);
      const compat = this.inspectCompatibility(
        Number(r.db_schema_version || APP_SCHEMA_VERSION),
        r.app_version || APP_VERSION,
        r.git_commit || APP_INSTALLED_COMMIT
      );
      return {
        ...r,
        compatibility: compat
      };
    });

    return {
      backups: items,
      storage: {
        usedBytes: totalBytes,
        usedMb: Number((totalBytes / (1024 * 1024)).toFixed(2)),
        maxStorageMb,
        retentionCount,
        currentSoftwareVersion: APP_VERSION,
        currentGitCommit: APP_INSTALLED_COMMIT,
        currentDbSchemaVersion: Number(settings.db_schema_version || APP_SCHEMA_VERSION),
        targetSoftwareSchemaVersion: APP_SCHEMA_VERSION
      }
    };
  }

  public restoreFromBackup(
    backupId: string,
    resolutionMode?: 'auto_migrate' | 'upgrade_software_to_match' | 'compatibility_safe_import',
    passphraseOverride?: string,
    actorUsername = 'admin'
  ) {
    const row = db.prepare('SELECT * FROM system_backups WHERE id = ?').get(backupId) as any;
    if (!row) {
      return { success: false, error: 'Backup record not found.' };
    }
    if (!this.isPathInsideBackupsDir(row.file_path) || !fs.existsSync(row.file_path)) {
      return { success: false, error: 'Backup archive file is missing or outside the managed backups directory.' };
    }

    const compat = this.inspectCompatibility(
      Number(row.db_schema_version || APP_SCHEMA_VERSION),
      row.app_version || APP_VERSION,
      row.git_commit || APP_INSTALLED_COMMIT
    );

    if (compat.requiresAdminResolution && !resolutionMode) {
      return {
        success: false,
        requiresResolution: true,
        compatibility: compat,
        message: compat.message
      };
    }

    if (resolutionMode === 'upgrade_software_to_match') {
      return {
        success: false,
        requiresSoftwareUpgrade: true,
        compatibility: compat,
        message: `Please upgrade Vitrine RMM software to ${row.app_version} (Schema v${row.db_schema_version}) via the Self-Updater or container pull first, then run Restore again.`
      };
    }

    // Read & verify backup archive BEFORE altering live database
    let parsed: any;
    try {
      const diskBytes = fs.readFileSync(row.file_path);
      parsed = this.unpackArchiveBuffer(diskBytes, passphraseOverride);
    } catch (err: any) {
      return {
        success: false,
        error: `Failed to decrypt or unpack backup archive: ${err?.message || 'Corrupted archive'}`
      };
    }

    // 1. Create a pre-restore safety snapshot first
    const safetyBackup = this.createBackup({
      triggerType: 'pre-restore',
      notes: `Automatic safety snapshot before restoring ${row.filename}`,
      actorUsername
    });

    // Capture current system_backups catalog and active auth_sessions so they survive atomic DB replacement
    const preservedBackups = db.prepare('SELECT * FROM system_backups').all() as any[];
    const preservedSessions = db.prepare('SELECT * FROM auth_sessions').all() as any[];

    let migrationsApplied = false;

    // 2A. Compatibility Safe Import (for newer-schema backups imported into current schema)
    if (resolutionMode === 'compatibility_safe_import' && parsed.tablesSnapshot) {
      db.pragma('foreign_keys = OFF');
      try {
        const importTx = db.transaction(() => {
          for (const [tableName, rows] of Object.entries(parsed.tablesSnapshot as Record<string, any[]>)) {
            if (!/^[a-zA-Z0-9_]+$/.test(tableName) || !Array.isArray(rows)) continue;
            if (tableName === 'system_backups' || tableName === 'auth_sessions') continue;

            const targetColsInfo = db.prepare(`PRAGMA table_info("${tableName}")`).all() as Array<{ name: string }>;
            if (targetColsInfo.length === 0) continue;
            const validCols = new Set(targetColsInfo.map((c) => c.name));

            db.prepare(`DELETE FROM "${tableName}"`).run();
            for (const item of rows) {
              const cols = Object.keys(item).filter((k) => validCols.has(k));
              if (cols.length === 0) continue;
              const colList = cols.map((c) => `"${c}"`).join(', ');
              const placeholders = cols.map(() => '?').join(', ');
              db.prepare(`INSERT OR REPLACE INTO "${tableName}" (${colList}) VALUES (${placeholders})`).run(
                ...cols.map((c) => item[c])
              );
            }
          }
        });
        importTx();
      } finally {
        db.pragma('foreign_keys = ON');
      }
    } else if (parsed.rawDbBase64) {
      // 2B. Full Atomic Binary SQLite Database + Vault Restoration
      const decodedDb = Buffer.from(parsed.rawDbBase64, 'base64');
      const sqliteHeader = decodedDb.subarray(0, 16).toString('ascii');
      if (!sqliteHeader.startsWith('SQLite format 3')) {
        return {
          success: false,
          error: 'Backup archive contains an invalid SQLite database image.'
        };
      }

      // Restore .vault-key.json if present so LAPS/BitLocker ciphertexts match, and reload in-memory master key cache!
      if (parsed.vaultKeyJson && typeof parsed.vaultKeyJson === 'string') {
        try {
          const vkPath = path.join(DATA_DIR_PATH, '.vault-key.json');
          fs.writeFileSync(vkPath, parsed.vaultKeyJson, { encoding: 'utf8', mode: 0o600 });
          reloadVaultMasterKey();
        } catch {}
      }

      const tempReplacePath = `${DB_FILE_PATH}.restore-${Date.now()}.tmp`;
      fs.writeFileSync(tempReplacePath, decodedDb, { mode: 0o600 });

      // Close live SQLite handle, purge WAL/SHM, swap DB atomically, and reopen proxy handle!
      closeDatabase();
      for (const suffix of ['-wal', '-shm', '-journal']) {
        const walFile = `${DB_FILE_PATH}${suffix}`;
        if (fs.existsSync(walFile)) {
          try {
            fs.unlinkSync(walFile);
          } catch {}
        }
      }
      fs.renameSync(tempReplacePath, DB_FILE_PATH);
      reopenDatabase();
      runDatabaseMigrations();
      migrationsApplied = compat.status === 'older_db_auto_migratable';

      // Re-register backup catalog & active sessions (whose user_id exists in restored DB)
      const insBak = db.prepare(`
        INSERT OR REPLACE INTO system_backups (
          id, filename, file_path, size_bytes, trigger_type, app_version, git_commit,
          db_schema_version, sha256_hash, includes_branding, includes_mesh_config, notes,
          encrypted, offsite_synced, offsite_location, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const b of preservedBackups) {
        insBak.run(
          b.id,
          b.filename,
          b.file_path,
          b.size_bytes,
          b.trigger_type,
          b.app_version,
          b.git_commit,
          b.db_schema_version,
          b.sha256_hash,
          b.includes_branding,
          b.includes_mesh_config,
          b.notes,
          b.encrypted ?? 0,
          b.offsite_synced ?? 0,
          b.offsite_location ?? 'local-only',
          b.created_at
        );
      }

      const insSess = db.prepare(`
        INSERT OR IGNORE INTO auth_sessions (token_hash, user_id, expires_at, mfa_verified_until, ip_address, user_agent, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      for (const s of preservedSessions) {
        const userStillExists = db.prepare('SELECT id FROM users WHERE id = ?').get(s.user_id);
        if (userStillExists) {
          insSess.run(
            s.token_hash,
            s.user_id,
            s.expires_at,
            s.mfa_verified_until,
            s.ip_address,
            s.user_agent,
            s.created_at
          );
        }
      }
    }

    // 3. Restore Branding Assets into canonical BRANDING_DIR_PATH
    try {
      if (!fs.existsSync(BRANDING_DIR_PATH)) {
        fs.mkdirSync(BRANDING_DIR_PATH, { recursive: true });
      }
      if (parsed.brandingFiles && typeof parsed.brandingFiles === 'object') {
        for (const [name, b64] of Object.entries(parsed.brandingFiles as Record<string, string>)) {
          const safeAsset = path.basename(name).replace(/[^a-zA-Z0-9._-]/g, '_');
          if (safeAsset && typeof b64 === 'string') {
            fs.writeFileSync(path.join(BRANDING_DIR_PATH, safeAsset), Buffer.from(b64, 'base64'));
          }
        }
      } else if (parsed.brandingLogoBase64) {
        fs.writeFileSync(
          path.join(BRANDING_DIR_PATH, 'logo.png'),
          Buffer.from(parsed.brandingLogoBase64, 'base64')
        );
      }
    } catch {
      // Non-fatal if branding dir is read-only
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, NULL, 'System Backup Restored', ?)
    `).run(
      `aud-restore-${crypto.randomUUID()}`,
      actorUsername,
      `Restored ${row.filename} atomically (Backup Schema v${row.db_schema_version} -> Target Schema v${APP_SCHEMA_VERSION}, Mode: ${resolutionMode || 'atomic_sqlite_replace'}).`
    );

    return {
      success: true,
      restoredBackup: row,
      preRestoreSafetyBackupId: safetyBackup.id,
      migrationsApplied,
      compatibility: compat,
      message: migrationsApplied
        ? `Restored ${row.filename} and automatically migrated database schema from v${row.db_schema_version} to v${APP_SCHEMA_VERSION}.`
        : resolutionMode === 'compatibility_safe_import'
        ? `Completed Compatibility-Safe Import of ${row.filename} into Schema v${APP_SCHEMA_VERSION}.`
        : `Successfully restored ${row.filename} (SQLite Database, LAPS/BitLocker Vault, and Branding Assets).`
    };
  }

  public importUploadedBackup(payload: {
    filename: string;
    base64Data?: string;
    passphrase?: string;
    notes?: string;
  }) {
    if (!payload.base64Data || typeof payload.base64Data !== 'string') {
      throw new Error('A valid base64-encoded .vrmm-backup.gz file payload is required.');
    }

    const backupId = `bak-upload-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`;
    const safeFilename = sanitizeBackupFilename(payload.filename);
    const filePath = this.resolveVerifiedBackupFilePath(safeFilename);
    const bufferToWrite = Buffer.from(payload.base64Data, 'base64');

    if (bufferToWrite.length < 32) {
      throw new Error('Uploaded backup file is empty or truncated.');
    }

    const encrypted = isEncryptedArchiveBuffer(bufferToWrite);
    let appVersion = APP_VERSION;
    let gitCommit = APP_INSTALLED_COMMIT;
    let dbSchemaVersion = APP_SCHEMA_VERSION;

    try {
      const parsed = this.unpackArchiveBuffer(bufferToWrite, payload.passphrase);
      if (parsed?.format !== 'VITRINE_RMM_UNIFIED_BACKUP_V2' || !parsed?.manifest) {
        throw new Error('Unrecognized Vitrine backup manifest format.');
      }
      appVersion = String(parsed.manifest.appVersion || appVersion);
      gitCommit = String(parsed.manifest.gitCommit || gitCommit);
      dbSchemaVersion = Number(parsed.manifest.dbSchemaVersion || dbSchemaVersion);
    } catch (err: any) {
      if (encrypted && !payload.passphrase && !this.getBackupEncryptionPassphrase()) {
        // Still allow staging encrypted archive if passphrase will be provided at restore time
      } else {
        throw new Error(`Invalid or corrupted backup archive: ${err?.message || 'Unable to parse manifest'}`);
      }
    }

    fs.writeFileSync(filePath, bufferToWrite, { mode: 0o600 });
    const sha256Hash = crypto.createHash('sha256').update(bufferToWrite).digest('hex');

    db.prepare(`
      INSERT INTO system_backups (
        id, filename, file_path, size_bytes, trigger_type, app_version, git_commit,
        db_schema_version, sha256_hash, includes_branding, includes_mesh_config, notes,
        encrypted, offsite_synced, offsite_location
      ) VALUES (?, ?, ?, ?, 'uploaded', ?, ?, ?, ?, 1, 1, ?, ?, 0, 'local-only')
    `).run(
      backupId,
      safeFilename,
      filePath,
      bufferToWrite.length,
      appVersion,
      gitCommit,
      dbSchemaVersion,
      sha256Hash,
      payload.notes || 'Uploaded external backup archive',
      encrypted ? 1 : 0
    );

    const compat = this.inspectCompatibility(dbSchemaVersion, appVersion, gitCommit);
    return {
      success: true,
      backupId,
      filename: safeFilename,
      encrypted,
      compatibility: compat
    };
  }

  public deleteBackup(id: string) {
    const row = db.prepare('SELECT * FROM system_backups WHERE id = ?').get(id) as any;
    if (row?.file_path && this.isPathInsideBackupsDir(row.file_path) && fs.existsSync(row.file_path)) {
      try {
        fs.unlinkSync(row.file_path);
      } catch {}
    }
    db.prepare('DELETE FROM system_backups WHERE id = ?').run(id);
    return { success: true };
  }
}

export const backupService = new BackupService();
