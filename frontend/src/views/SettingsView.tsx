import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Mail,
  Shield,
  Palette,
  CheckCircle2,
  Send,
  Video,
  KeyRound,
  RefreshCw,
  Clock,
  Users,
  Building,
  Plus,
  Trash2,
  Database,
  Download,
  Upload,
  AlertTriangle,
  Server,
  GitBranch,
  ExternalLink,
  Archive,
  CloudUpload,
  Lock,
  ListChecks,
  CalendarClock,
  Webhook,
  Copy,
  Check,
  Globe
} from 'lucide-react';
import {
  Settings,
  RbacUser,
  Tenant,
  MeshServer,
  SystemBackupItem,
  UpdaterStatus,
  MeshDiscoveryResult,
  CustomFieldDefinition,
  MaintenanceWindow
} from '../types/index.js';
import {
  updateSettings,
  uploadBrandLogo,
  testSmtp,
  syncMeshCentral,
  fetchUsers,
  createUser,
  deleteUser,
  fetchTenants,
  createTenant,
  createSite,
  offboardTenant,
  reactivateTenant,
  fetchMeshServers,
  createMeshServer,
  deleteMeshServer,
  testDiscoverMeshServer,
  importFromMeshServer,
  fetchSystemBackups,
  createSystemBackup,
  getBackupDownloadUrl,
  uploadSystemBackup,
  restoreSystemBackup,
  deleteSystemBackup,
  syncOffsiteBackups,
  fetchUpdaterStatus,
  setUpdaterChannel,
  executeSystemUpdate,
  fetchMfaEnrollment,
  regenerateMfaRecoveryCodes,
  fetchCustomFields,
  saveCustomField,
  deleteCustomField,
  fetchMaintenanceWindows,
  createMaintenanceWindow,
  deleteMaintenanceWindow,
  testOidcDiscovery,
  revealBackupRecoveryKey,
  acknowledgeBackupRecoveryKey
} from '../services/api.js';
import { MfaChallengeModal } from '../components/MfaChallengeModal.js';

interface SettingsViewProps {
  settings: Settings;
  onUpdated: (s: Settings) => void;
  onOpenWizard: () => void;
  tenants?: Tenant[];
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  settings,
  onUpdated,
  onOpenWizard,
  tenants: propTenants
}) => {
  const [formData, setFormData] = useState<Settings>({ ...settings });
  const [saving, setSaving] = useState(false);
  const [saveBanner, setSaveBanner] = useState<string | null>(null);
  const [smtpTestResult, setSmtpTestResult] = useState<string | null>(null);
  const [testingSmtp, setTestingSmtp] = useState(false);
  const [syncingMesh, setSyncingMesh] = useState(false);
  const [meshSyncResult, setMeshSyncResult] = useState<string | null>(null);

  // Logo & Backup file inputs
  const logoInputRef = useRef<HTMLInputElement | null>(null);
  const backupFileInputRef = useRef<HTMLInputElement | null>(null);
  const [uploadingLogo, setUploadingLogo] = useState(false);
  const [uploadingBackup, setUploadingBackup] = useState(false);

  // RBAC Users & Tenants management state
  const [users, setUsers] = useState<RbacUser[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>(propTenants || []);
  const [newUserEmail, setNewUserEmail] = useState('');
  const [newUserName, setNewUserName] = useState('');
  const [newUserPassword, setNewUserPassword] = useState('');
  const [newUserRole, setNewUserRole] = useState<'super_admin' | 'technician' | 'client_admin'>('technician');
  const [newUserTenantId, setNewUserTenantId] = useState('');
  const [userNotice, setUserNotice] = useState<string | null>(null);

  const [newTenantName, setNewTenantName] = useState('');
  const [newTenantContact, setNewTenantContact] = useState('');
  const [newSiteTenantId, setNewSiteTenantId] = useState(propTenants?.[0]?.id || '');
  const [newSiteName, setNewSiteName] = useState('');
  const [newSiteSubnet, setNewSiteSubnet] = useState('');
  const [clientActionNotice, setClientActionNotice] = useState<string | null>(null);
  const [syncingOffsite, setSyncingOffsite] = useState(false);

  // MFA Enrollment & Recovery Codes state
  const [mfaInfo, setMfaInfo] = useState<{
    totpEnabled: boolean;
    secretBase32: string;
    otpAuthUri: string;
    remainingRecoveryCodes: number;
  } | null>(null);
  const [showMfaSecret, setShowMfaSecret] = useState(false);
  const [regenTotpCode, setRegenTotpCode] = useState('');
  const [regeneratedCodes, setRegeneratedCodes] = useState<string[] | null>(null);
  const [mfaNotice, setMfaNotice] = useState<string | null>(null);

  // Custom Field Definitions & Maintenance Windows state
  const [customFieldDefs, setCustomFieldDefs] = useState<CustomFieldDefinition[]>([]);
  const [newFieldLabel, setNewFieldLabel] = useState('');
  const [newFieldCategory, setNewFieldCategory] = useState('Operations');
  const [newFieldType, setNewFieldType] = useState<'text' | 'dropdown' | 'checkbox' | 'secret'>('text');
  const [newFieldOptions, setNewFieldOptions] = useState('');

  const [maintenanceWindows, setMaintenanceWindows] = useState<MaintenanceWindow[]>([]);
  const [newWinTitle, setNewWinTitle] = useState('');
  const [newWinDuration, setNewWinDuration] = useState(120);
  const [newWinTenantId, setNewWinTenantId] = useState('');

  // Multi-Instance MeshCentral 2 Federation state
  const [meshServers, setMeshServers] = useState<MeshServer[]>([]);
  const [newMeshName, setNewMeshName] = useState('');
  const [newMeshUrl, setNewMeshUrl] = useState('');
  const [newMeshToken, setNewMeshToken] = useState('');
  const [discoveringServerId, setDiscoveringServerId] = useState<string | null>(null);
  const [discoveryPreview, setDiscoveryPreview] = useState<(MeshDiscoveryResult & { serverId?: string }) | null>(null);
  const [importingServerId, setImportingServerId] = useState<string | null>(null);

  // Unified Self-Backup & Restore state
  const [backups, setBackups] = useState<SystemBackupItem[]>([]);
  const [backupStorage, setBackupStorage] = useState<{
    usedBytes: number;
    quotaMb: number;
    retentionCount: number;
    currentAppSchemaVersion: number;
  }>({
    usedBytes: 0,
    quotaMb: 5120,
    retentionCount: 14,
    currentAppSchemaVersion: 16
  });
  const [creatingBackup, setCreatingBackup] = useState(false);
  const [backupNotice, setBackupNotice] = useState<string | null>(null);
  const [revealedBackupKey, setRevealedBackupKey] = useState<string | null>(null);
  const [showBackupKeyMfa, setShowBackupKeyMfa] = useState(false);
  const [copiedBackupKey, setCopiedBackupKey] = useState(false);
  const [testingOidc, setTestingOidc] = useState(false);
  const [oidcTestResult, setOidcTestResult] = useState<string | null>(null);
  const [schemaMismatchModal, setSchemaMismatchModal] = useState<{
    backup: SystemBackupItem;
    backupSchemaVersion: number;
    appSchemaVersion: number;
    warningMessage: string;
  } | null>(null);
  const [restoringBackupId, setRestoringBackupId] = useState<string | null>(null);

  // Self-Update Engine state
  const [updaterStatus, setUpdaterStatus] = useState<UpdaterStatus | null>(null);
  const [installingUpdate, setInstallingUpdate] = useState(false);
  const [updaterNotice, setUpdaterNotice] = useState<string | null>(null);
  const [channelGuardrailError, setChannelGuardrailError] = useState<string | null>(null);

  useEffect(() => {
    setFormData({ ...settings });
  }, [settings]);

  const loadAllAdminData = useCallback(() => {
    fetchUsers().then(setUsers).catch(() => {});
    fetchTenants()
      .then((list) => {
        setTenants(list);
        if (list.length > 0) {
          setNewSiteTenantId((prev) => prev || list[0].id);
          setNewUserTenantId((prev) => prev || list[0].id);
        }
      })
      .catch(() => {});
    fetchMeshServers().then(setMeshServers).catch(() => {});
    fetchCustomFields().then(setCustomFieldDefs).catch(() => {});
    fetchMaintenanceWindows().then(setMaintenanceWindows).catch(() => {});
    fetchMfaEnrollment().then(setMfaInfo).catch(() => {});
    fetchSystemBackups()
      .then((res) => {
        if (res.backups) setBackups(res.backups);
        if (res.storage) {
          setBackupStorage({
            usedBytes: res.storage.usedBytes,
            quotaMb: res.storage.maxStorageMb,
            retentionCount: res.storage.retentionCount,
            currentAppSchemaVersion: res.storage.targetSoftwareSchemaVersion
          });
        }
      })
      .catch(() => {});
    fetchUpdaterStatus().then(setUpdaterStatus).catch(() => {});
  }, []);

  useEffect(() => {
    loadAllAdminData();
  }, [loadAllAdminData]);
  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const res = await updateSettings(formData);
      if (res.success) {
        onUpdated(res.settings);
        setSaveBanner('Settings, White-Labeling, Vaulted Secrets & Compliance Policies saved successfully.');
        setTimeout(() => setSaveBanner(null), 4000);
      } else {
        setSaveBanner(`Error saving settings: ${res.error || 'Unknown error'}`);
      }
    } finally {
      setSaving(false);
    }
  };

  const handleLogoFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadingLogo(true);
    try {
      const base64Data = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
          const str = String(reader.result || '');
          const commaIdx = str.indexOf(',');
          resolve(commaIdx >= 0 ? str.slice(commaIdx + 1) : str);
        };
        reader.onerror = () => reject(new Error('Failed to read image file'));
        reader.readAsDataURL(file);
      });
      const res = await uploadBrandLogo(file.name, base64Data);
      if (res.success && res.brand_logo_url) {
        const next = { ...formData, brand_logo_url: res.brand_logo_url };
        setFormData(next);
        onUpdated(next);
        setSaveBanner(`Brand logo "${file.name}" uploaded and applied across Web UI & Portals.`);
        setTimeout(() => setSaveBanner(null), 4000);
      } else {
        setSaveBanner(`Logo upload rejected: ${res.error || 'Unsupported image format'}`);
      }
    } finally {
      setUploadingLogo(false);
      if (logoInputRef.current) logoInputRef.current.value = '';
    }
  };

  const handleOffboardClient = async (t: Tenant, mode: 'archive_preserve' | 'permanent_delete') => {
    const confirmMsg =
      mode === 'archive_preserve'
        ? `Offboard client "${t.name}" into the Data Archive Vault? All endpoints, BitLocker recovery keys, LAPS history, and notes will be preserved in their last-known state while online agents cleanly uninstall.`
        : `PERMANENTLY DELETE client "${t.name}"? A tombstone will be recorded so any sleeping agent that wakes up later will quietly offboard itself, and all client records will be permanently purged.`;
    if (!confirm(confirmMsg)) return;
    const res = await offboardTenant(t.id, {
      mode: mode === 'archive_preserve' ? 'archive_client' : 'delete_client_permanently',
      reason:
        mode === 'archive_preserve'
          ? 'Client offboarded to Data Archive Vault'
          : 'Explicit admin permanent client deletion'
    });
    if (res.success) {
      setClientActionNotice(`✓ ${res.message}`);
      loadAllAdminData();
    }
  };

  const handleReactivateClient = async (t: Tenant) => {
    const res = await reactivateTenant(t.id);
    if (res.success) {
      setClientActionNotice(`✓ ${res.message}`);
      loadAllAdminData();
    }
  };

  const handleSyncOffsiteVault = async () => {
    setSyncingOffsite(true);
    setBackupNotice(null);
    try {
      const res = await syncOffsiteBackups();
      setBackupNotice(res.success ? `✓ ${res.message}` : `Offsite replication failed: ${res.error || res.message}`);
      loadAllAdminData();
    } finally {
      setSyncingOffsite(false);
    }
  };

  const handleSyncMesh = async () => {
    setSyncingMesh(true);
    setMeshSyncResult(null);
    try {
      const res = await syncMeshCentral();
      if (res.success) {
        const importedCount = res.imported ?? 0;
        const updatedCount = res.updated ?? 0;
        const conflictsCount = (res.conflicts || []).length;
        setMeshSyncResult(
          `Sync Completed: ${importedCount} group(s) imported as Clients, ${updatedCount} client(s) updated. ${
            conflictsCount > 0
              ? `${conflictsCount} conflict alert(s) posted to Notifications.`
              : 'All group memberships matched.'
          }`
        );
        loadAllAdminData();
      } else {
        setMeshSyncResult('Sync encountered an issue: ' + (res.message || 'Check connection settings'));
      }
    } catch {
      setMeshSyncResult('Sync failed. Please verify MeshCentral URL and API token.');
    } finally {
      setSyncingMesh(false);
    }
  };

  const handleTestSmtp = async () => {
    setTestingSmtp(true);
    try {
      const res = await testSmtp({
        host: formData.smtp_host,
        port: formData.smtp_port,
        user: formData.smtp_user,
        pass: formData.smtp_pass,
        from: formData.smtp_from
      });
      setSmtpTestResult(res.message);
    } finally {
      setTestingSmtp(false);
    }
  };

  const handleRevealBackupKey = async () => {
    const res = await revealBackupRecoveryKey();
    if (res.mfaRequired) {
      setShowBackupKeyMfa(true);
      return;
    }
    if (res.success && res.passphrase) {
      setRevealedBackupKey(res.passphrase);
      const next = { ...formData, backup_key_acknowledged: 1 };
      setFormData(next);
      onUpdated(next);
    } else if (res.error) {
      setBackupNotice(`Unable to reveal recovery key: ${res.error}`);
    }
  };

  const handleAcknowledgeBackupKey = async () => {
    const res = await acknowledgeBackupRecoveryKey();
    if (res.success) {
      const next = { ...formData, backup_key_acknowledged: 1 };
      setFormData(next);
      onUpdated(next);
      setBackupNotice('✓ Backup Encryption Passphrase marked as escrowed offline.');
    }
  };

  const handleDownloadBackupKeyKit = (passphrase: string) => {
    const content = [
      `${formData.brand_name || 'Vitrine RMM'} — Disaster Recovery Backup Encryption Key`,
      `Generated: ${new Date().toISOString()}`,
      '',
      'IMPORTANT: Store this passphrase in an external vault (1Password, Bitwarden, Keeper).',
      'Required to decrypt .vrmm-backup.gz archives during bare-metal or cross-machine restoration.',
      '',
      'AES-256-GCM Backup Encryption Passphrase:',
      passphrase
    ].join('\n');
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'vitrine-rmm-backup-encryption-key.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleTestOidc = async () => {
    setTestingOidc(true);
    setOidcTestResult(null);
    try {
      const res = await testOidcDiscovery({
        issuerUrl: formData.oidc_issuer_url,
        clientId: formData.oidc_client_id
      });
      setOidcTestResult(
        res.success
          ? `✓ OIDC Discovery verified (${res.issuer}) — Authorization & Token endpoints active.`
          : `OIDC Discovery failed: ${res.error || 'Verify Issuer URL and network connectivity.'}`
      );
    } finally {
      setTestingOidc(false);
    }
  };

  const handleAddUser = async () => {
    setUserNotice(null);
    if (!newUserEmail.trim() || !newUserName.trim()) {
      setUserNotice('Name and email address are required.');
      return;
    }
    if (newUserPassword && newUserPassword.length < 10) {
      setUserNotice('Initial password must be at least 10 characters.');
      return;
    }
    const res = await createUser({
      username: newUserName.trim(),
      email: newUserEmail.trim(),
      password: newUserPassword || undefined,
      role: newUserRole,
      tenant_id: newUserRole === 'client_admin' ? newUserTenantId || null : null
    });
    if (res.success) {
      setNewUserEmail('');
      setNewUserName('');
      setNewUserPassword('');
      setUserNotice(
        res.recoveryCodes?.length
          ? `✓ Created ${res.user?.email} (${res.user?.role}). Initial MFA Recovery Codes: ${res.recoveryCodes.join(', ')}`
          : `✓ Created ${res.user?.email} (${res.user?.role}).`
      );
      loadAllAdminData();
    } else {
      setUserNotice(`Failed to create user: ${res.error || 'Unknown error'}`);
    }
  };

  const handleDeleteUser = async (id: string) => {
    const res = await deleteUser(id);
    if (!res.success && res.error) {
      setUserNotice(`Cannot delete user: ${res.error}`);
      return;
    }
    loadAllAdminData();
  };

  const handleAddTenant = async () => {
    if (!newTenantName.trim()) return;
    await createTenant({
      name: newTenantName.trim(),
      contact_email:
        newTenantContact.trim() || `it@${newTenantName.trim().toLowerCase().replace(/[^a-z0-9]/g, '')}.com`
    });
    setNewTenantName('');
    setNewTenantContact('');
    loadAllAdminData();
  };

  const handleAddSite = async () => {
    if (!newSiteName.trim() || !newSiteTenantId) return;
    await createSite({
      tenant_id: newSiteTenantId,
      name: newSiteName.trim(),
      subnet: newSiteSubnet.trim() || '10.50.0.0/24'
    });
    setNewSiteName('');
    setNewSiteSubnet('');
    loadAllAdminData();
  };

  const handleAddMeshServer = async () => {
    if (!newMeshName.trim() || !newMeshUrl.trim()) return;
    await createMeshServer({
      name: newMeshName.trim(),
      url: newMeshUrl.trim(),
      api_token: newMeshToken.trim(),
      auto_push_companion: 1
    });
    setNewMeshName('');
    setNewMeshUrl('');
    setNewMeshToken('');
    loadAllAdminData();
  };

  const handleDiscoverMesh = async (server: MeshServer) => {
    setDiscoveringServerId(server.id);
    try {
      const res = await testDiscoverMeshServer({
        server_id: server.id,
        url: server.url,
        api_token: server.api_token
      });
      setDiscoveryPreview({ ...res, serverId: server.id });
    } finally {
      setDiscoveringServerId(null);
    }
  };

  const handleImportDiscoveredMesh = async (serverId?: string) => {
    if (!discoveryPreview) return;
    setImportingServerId(serverId || 'primary');
    try {
      const res = await importFromMeshServer({
        mesh_server_id: serverId,
        import_new_groups: true,
        auto_deploy_companion: true,
        enforce_laps_on_import: true,
        lock_signed_binary_updates: true
      });
      if (res.success) {
        setMeshSyncResult(`✓ ${res.message}`);
        setDiscoveryPreview(null);
        loadAllAdminData();
      }
    } finally {
      setImportingServerId(null);
    }
  };

  const handleCreateBackup = async () => {
    setCreatingBackup(true);
    setBackupNotice(null);
    try {
      const res = await createSystemBackup({
        triggerType: 'manual',
        notes: 'Admin On-Demand Full Self-Restore Bundle (DB + LAPS Vault + Branding + Config)'
      });
      if (res.success) {
        setBackupNotice(
          '✓ Full self-restore backup bundle (.vrmm-backup.gz) created, encrypted, and verified with SHA-256 checksum.'
        );
        loadAllAdminData();
      }
    } finally {
      setCreatingBackup(false);
    }
  };

  const handleBackupFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadingBackup(true);
    setBackupNotice(null);
    try {
      const base64Data = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
          const str = String(reader.result || '');
          const commaIdx = str.indexOf(',');
          resolve(commaIdx >= 0 ? str.slice(commaIdx + 1) : str);
        };
        reader.onerror = () => reject(new Error('Failed to read backup archive file'));
        reader.readAsDataURL(file);
      });
      const res = await uploadSystemBackup({
        filename: file.name,
        base64Data,
        passphrase:
          formData.backup_encryption_passphrase && !formData.backup_encryption_passphrase.includes('••••')
            ? formData.backup_encryption_passphrase
            : undefined,
        notes: `Uploaded via Settings UI (${file.name})`
      });
      if (res.success) {
        setBackupNotice(
          `✓ Uploaded backup "${res.filename || file.name}" verified and registered in local vault.`
        );
        loadAllAdminData();
      } else {
        setBackupNotice(`Upload rejected: ${res.error || 'Invalid or corrupted .vrmm-backup.gz archive'}`);
      }
    } finally {
      setUploadingBackup(false);
      if (backupFileInputRef.current) backupFileInputRef.current.value = '';
    }
  };

  const handleInitiateRestore = async (backup: SystemBackupItem) => {
    if (backup.db_schema_version > backupStorage.currentAppSchemaVersion) {
      setSchemaMismatchModal({
        backup,
        backupSchemaVersion: backup.db_schema_version,
        appSchemaVersion: backupStorage.currentAppSchemaVersion,
        warningMessage:
          backup.compatibility?.message ||
          `Backup archive DB Schema (v${backup.db_schema_version}) is newer than the currently installed Vitrine software target (v${backupStorage.currentAppSchemaVersion}). Choose how you want to resolve this before restoring.`
      });
      return;
    }
    await executeRestore(
      backup.id,
      backup.db_schema_version < backupStorage.currentAppSchemaVersion ? 'auto_migrate' : undefined
    );
  };

  const executeRestore = async (
    backupId: string,
    resolutionOption?: 'auto_migrate' | 'upgrade_software_to_match' | 'compatibility_safe_import' | 'cancel'
  ) => {
    if (resolutionOption === 'cancel') {
      setSchemaMismatchModal(null);
      return;
    }
    setRestoringBackupId(backupId);
    try {
      const res = await restoreSystemBackup(backupId, resolutionOption);
      if (res.requiresResolution && res.compatibility) {
        const b = backups.find((item) => item.id === backupId);
        if (b) {
          setSchemaMismatchModal({
            backup: b,
            backupSchemaVersion: res.compatibility.backupSchemaVersion,
            appSchemaVersion: res.compatibility.targetSoftwareSchemaVersion,
            warningMessage: res.compatibility.message
          });
        }
        return;
      }
      if (res.success) {
        setBackupNotice(`✓ ${res.message}`);
        setSchemaMismatchModal(null);
        loadAllAdminData();
      } else {
        setBackupNotice(`Restore blocked: ${res.error || res.message}`);
      }
    } catch (e: any) {
      setBackupNotice(`Restore error: ${e.message}`);
    } finally {
      setRestoringBackupId(null);
    }
  };

  const handleSwitchChannel = async (targetChannel: 'stable' | 'alpha') => {
    setChannelGuardrailError(null);
    try {
      const res = await setUpdaterChannel(targetChannel);
      if (!res.success || res.blockedByCommitGuard) {
        setChannelGuardrailError(
          res.error ||
            'Cannot switch from Alpha to Stable until Stable commit is newer than current Alpha commit.'
        );
      } else {
        setFormData((prev) => ({ ...prev, update_channel: targetChannel }));
        loadAllAdminData();
      }
    } catch (e: any) {
      setChannelGuardrailError(e.message || 'Channel switch blocked by commit history guardrail.');
    }
  };

  const handleInstallUpdate = async () => {
    setInstallingUpdate(true);
    setUpdaterNotice(null);
    try {
      const res = await executeSystemUpdate();
      if (res.dockerManaged) {
        setUpdaterNotice(
          `ℹ️ Container Deployment Mode Detected: ${res.instructions || 'Pull tylerhats/vitrine-rmm:latest on the Docker host to update container image.'}`
        );
      } else if (res.rolledBack) {
        setUpdaterNotice(
          `⚠️ Update Failed & Auto-Rolled Back cleanly via pre-update backup (${res.preUpdateBackupId}): ${res.errorLog || res.error}`
        );
      } else if (res.success) {
        setUpdaterNotice(
          `✓ Updated cleanly from ${res.fromVersion} (${res.fromCommit}) -> ${res.toVersion} (${res.toCommit}). Pre-update backup: ${res.preUpdateBackupId || 'verified'}`
        );
      } else {
        setUpdaterNotice(`Update did not run: ${res.error || 'Already up to date'}`);
      }
      loadAllAdminData();
    } catch (e: any) {
      setUpdaterNotice(`Update error: ${e.message}`);
    } finally {
      setInstallingUpdate(false);
    }
  };

  const handleRegenerateRecoveryCodes = async () => {
    if (!regenTotpCode.trim()) return;
    setMfaNotice(null);
    const res = await regenerateMfaRecoveryCodes(regenTotpCode.trim());
    if (res.success && res.recoveryCodes) {
      setRegeneratedCodes(res.recoveryCodes);
      setRegenTotpCode('');
      setMfaNotice('✓ Generated 8 fresh single-use recovery codes. Store them offline now.');
      fetchMfaEnrollment().then(setMfaInfo).catch(() => {});
    } else {
      setMfaNotice(`Verification failed: ${res.error || 'Invalid 6-digit TOTP code'}`);
    }
  };

  const handleAddCustomField = async () => {
    if (!newFieldLabel.trim()) return;
    const key = newFieldLabel
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '_')
      .replace(/^_|_$/g, '');
    const opts =
      newFieldType === 'dropdown'
        ? JSON.stringify(
            newFieldOptions
              .split(',')
              .map((s) => s.trim())
              .filter(Boolean)
          )
        : undefined;
    const res = await saveCustomField({
      key,
      label: newFieldLabel.trim(),
      category: newFieldCategory.trim() || 'Operations',
      field_type: newFieldType,
      scope: 'device',
      options: opts
    });
    if (res.success) {
      setNewFieldLabel('');
      setNewFieldOptions('');
      fetchCustomFields().then(setCustomFieldDefs).catch(() => {});
    }
  };

  const handleAddMaintenanceWindow = async () => {
    if (!newWinTitle.trim()) return;
    const now = new Date();
    const end = new Date(now.getTime() + newWinDuration * 60 * 1000);
    const res = await createMaintenanceWindow({
      title: newWinTitle.trim(),
      tenant_id: newWinTenantId || null,
      start_time: now.toISOString(),
      end_time: end.toISOString(),
      suppress_alerts: 1,
      durationMinutes: newWinDuration
    });
    if (res.success) {
      setNewWinTitle('');
      fetchMaintenanceWindows().then(setMaintenanceWindows).catch(() => {});
    }
  };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="settings-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
            System Settings, RBAC &amp; White-Labeling
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Configure global branding, RBAC technicians, MFA security, Client tenants, Code Signing HSM API, Backups, and MeshCentral 2 link
          </span>
        </div>
        <button className="btn-glass btn-primary" onClick={onOpenWizard}>
          Launch Onboarding Wizard
        </button>
      </div>

      {saveBanner && (
        <div
          className="glass-card"
          style={{
            padding: '0.85rem 1.25rem',
            background: 'rgba(16, 185, 129, 0.12)',
            borderColor: 'rgba(16, 185, 129, 0.35)',
            color: 'var(--text-main)',
            fontSize: '0.85rem',
            fontWeight: 500
          }}
        >
          ✓ {saveBanner}
        </div>
      )}

      {(formData.backup_encryption_enabled ?? 1) !== 0 && !formData.backup_key_acknowledged && (
        <div
          className="glass-card"
          style={{
            padding: '1rem 1.25rem',
            background: 'rgba(245, 158, 11, 0.12)',
            borderColor: 'rgba(245, 158, 11, 0.45)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '0.85rem'
          }}
          id="backup-key-reminder-banner"
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flex: 1, minWidth: '280px' }}>
            <AlertTriangle size={22} color="#fbbf24" style={{ flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 700, fontSize: '0.88rem', color: '#fbbf24' }}>
                Action Recommended: Escrow Your Disaster Recovery Backup Encryption Key
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
                Encrypted <code>.vrmm-backup.gz</code> archives require your Backup Encryption Passphrase if you ever restore onto a new server. Reveal &amp; download the recovery kit (Step-Up MFA) or set a custom passphrase in Backups below.
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <button
              type="button"
              className="btn-glass btn-primary"
              style={{ fontSize: '0.76rem', padding: '0.4rem 0.8rem' }}
              onClick={handleRevealBackupKey}
            >
              <KeyRound size={14} /> Reveal / Export Recovery Key (MFA)
            </button>
            <button
              type="button"
              className="btn-glass"
              style={{ fontSize: '0.76rem', padding: '0.4rem 0.75rem' }}
              onClick={handleAcknowledgeBackupKey}
            >
              <CheckCircle2 size={14} /> I Have Escrowed My Key
            </button>
          </div>
        </div>
      )}

      {/* RBAC Technician Management & Client Tenants */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        {/* RBAC Technicians */}
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <Users size={20} color="var(--primary)" />
            <div>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 600, margin: 0 }}>Role-Based Access Control (RBAC)</h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Manage Super Admins, Technicians, and Scoped Client Admins</span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <input
              type="text"
              className="glass-input"
              style={{ flex: 1, minWidth: '115px', fontSize: '0.78rem' }}
              placeholder="Full Name"
              value={newUserName}
              onChange={(e) => setNewUserName(e.target.value)}
            />
            <input
              type="email"
              className="glass-input"
              style={{ flex: 1, minWidth: '135px', fontSize: '0.78rem' }}
              placeholder="Email Address"
              value={newUserEmail}
              onChange={(e) => setNewUserEmail(e.target.value)}
            />
            <input
              type="password"
              className="glass-input"
              style={{ flex: 1, minWidth: '130px', fontSize: '0.78rem' }}
              placeholder="Initial Password (10+ chars)"
              value={newUserPassword}
              onChange={(e) => setNewUserPassword(e.target.value)}
            />
            <select
              className="glass-select"
              style={{ width: 'auto', fontSize: '0.78rem' }}
              value={newUserRole}
              onChange={(e) => setNewUserRole(e.target.value as 'super_admin' | 'technician' | 'client_admin')}
            >
              <option value="technician">Technician</option>
              <option value="super_admin">MSP Super Admin</option>
              <option value="client_admin">Client Admin (Tenant Scoped)</option>
            </select>
            {newUserRole === 'client_admin' && (
              <select
                className="glass-select"
                style={{ width: 'auto', fontSize: '0.78rem' }}
                value={newUserTenantId}
                onChange={(e) => setNewUserTenantId(e.target.value)}
              >
                <option value="">-- Select Client --</option>
                {tenants.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            )}
            <button type="button" className="btn-glass btn-primary" style={{ fontSize: '0.78rem' }} onClick={handleAddUser}>
              <Plus size={14} /> Add
            </button>
          </div>

          {userNotice && (
            <div style={{ padding: '0.55rem 0.8rem', borderRadius: '6px', background: 'rgba(56, 189, 248, 0.12)', border: '1px solid rgba(56, 189, 248, 0.35)', fontSize: '0.75rem', color: 'var(--text-main)', wordBreak: 'break-word' }}>
              {userNotice}
            </div>
          )}

          <div className="table-wrapper">
            <table className="glass-table">
              <thead>
                <tr>
                  <th>Name / Email</th>
                  <th>Role</th>
                  <th>Scope</th>
                  <th style={{ textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>
                      <div style={{ fontWeight: 600, fontSize: '0.8rem' }}>{u.username}</div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>{u.email}</div>
                    </td>
                    <td>
                      <span className="status-pill status-reboot" style={{ fontSize: '0.68rem' }}>
                        {u.role}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: '0.72rem', color: '#10b981' }}>
                        {u.tenant_name || 'Global MSP'}
                      </span>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      {users.length > 1 && (
                        <button
                          type="button"
                          className="btn-glass btn-icon"
                          onClick={() => handleDeleteUser(u.id)}
                          title="Remove Account"
                        >
                          <Trash2 size={13} color="#ef4444" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Client Tenants & Sites Management */}
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <Building size={20} color="#f59e0b" />
            <div>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 600, margin: 0 }}>Client Tenants &amp; Branch Sites</h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Create multi-tenant organizations and branch subnets</span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <input
              type="text"
              className="glass-input"
              style={{ flex: 1, fontSize: '0.78rem' }}
              placeholder="New Client Organization Name"
              value={newTenantName}
              onChange={(e) => setNewTenantName(e.target.value)}
            />
            <input
              type="email"
              className="glass-input"
              style={{ flex: 1, fontSize: '0.78rem' }}
              placeholder="Primary Contact Email"
              value={newTenantContact}
              onChange={(e) => setNewTenantContact(e.target.value)}
            />
            <button type="button" className="btn-glass btn-primary" style={{ fontSize: '0.78rem' }} onClick={handleAddTenant}>
              <Plus size={14} /> Client
            </button>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <select
              className="glass-select"
              style={{ flex: 1, fontSize: '0.78rem' }}
              value={newSiteTenantId}
              onChange={(e) => setNewSiteTenantId(e.target.value)}
            >
              <option value="">-- Select Client --</option>
              {tenants.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
            <input
              type="text"
              className="glass-input"
              style={{ flex: 1, fontSize: '0.78rem' }}
              placeholder="New Site Name"
              value={newSiteName}
              onChange={(e) => setNewSiteName(e.target.value)}
            />
            <input
              type="text"
              className="glass-input"
              style={{ width: '130px', fontSize: '0.78rem' }}
              placeholder="Subnet CIDR"
              value={newSiteSubnet}
              onChange={(e) => setNewSiteSubnet(e.target.value)}
            />
            <button type="button" className="btn-glass" style={{ fontSize: '0.78rem' }} onClick={handleAddSite}>
              <Plus size={14} /> Site
            </button>
          </div>

          {clientActionNotice && (
            <div style={{ padding: '0.55rem 0.85rem', borderRadius: '6px', background: 'rgba(56, 189, 248, 0.12)', border: '1px solid rgba(56, 189, 248, 0.35)', fontSize: '0.76rem', color: 'var(--text-main)' }}>
              {clientActionNotice}
            </div>
          )}

          <div style={{ maxHeight: '230px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
            {tenants.map((t) => {
              const isArchived = t.lifecycle_state === 'archived';
              return (
                <div
                  key={t.id}
                  style={{
                    padding: '0.6rem 0.85rem',
                    borderRadius: '6px',
                    background: isArchived ? 'rgba(245, 158, 11, 0.06)' : 'rgba(148, 163, 184, 0.06)',
                    border: `1px solid ${isArchived ? 'rgba(245, 158, 11, 0.35)' : 'var(--glass-border)'}`,
                    fontSize: '0.78rem'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontWeight: 600, gap: '0.5rem', flexWrap: 'wrap' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                      <span>{t.name}</span>
                      <span className={`status-pill ${isArchived ? 'status-reboot' : 'status-online'}`} style={{ fontSize: '0.64rem' }}>
                        {isArchived ? 'Archived Vault (Last State Preserved)' : 'Active'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      <span style={{ color: 'var(--primary)', fontSize: '0.74rem' }}>{t.device_count} devices</span>
                      {!isArchived ? (
                        <button
                          type="button"
                          className="btn-glass"
                          style={{ padding: '0.2rem 0.5rem', fontSize: '0.68rem', borderColor: 'rgba(245, 158, 11, 0.45)', color: '#fbbf24' }}
                          title="Offboard client while keeping its entire last-known state (BitLocker keys, LAPS history, notes) in the Data Archive"
                          onClick={() => handleOffboardClient(t, 'archive_preserve')}
                        >
                          <Archive size={11} /> Offboard to Archive
                        </button>
                      ) : (
                        <button
                          type="button"
                          className="btn-glass"
                          style={{ padding: '0.2rem 0.5rem', fontSize: '0.68rem', borderColor: 'rgba(16, 185, 129, 0.45)', color: '#34d399' }}
                          title="Reactivate archived client organization"
                          onClick={() => handleReactivateClient(t)}
                        >
                          Reactivate
                        </button>
                      )}
                      <button
                        type="button"
                        className="btn-glass btn-icon"
                        title="Permanently delete client & record Quiet-Offboard tombstone so any sleeping agent that wakes up later quietly uninstalls itself"
                        onClick={() => handleOffboardClient(t, 'permanent_delete')}
                      >
                        <Trash2 size={12} color="#ef4444" />
                      </button>
                    </div>
                  </div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>
                    Sites: {(t.sites || []).map((s) => `${s.name} (${s.subnet})`).join(' • ') || 'None'}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Step-Up MFA Authenticator & Custom Field / Maintenance Window Schemas */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        {/* TOTP MFA & Single-Use Recovery Codes */}
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <Lock size={20} color="#34d399" />
              <div>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 600, margin: 0 }}>Step-Up TOTP MFA &amp; Recovery Vault</h3>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  RFC 6238 Authenticator enrollment for LAPS, BitLocker &amp; Break-Glass exports
                </span>
              </div>
            </div>
            <span className="status-pill status-online" style={{ fontSize: '0.68rem' }}>
              {mfaInfo ? `${mfaInfo.remainingRecoveryCodes} Recovery Codes Left` : 'Active'}
            </span>
          </div>

          {mfaInfo && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.6rem 0.85rem', borderRadius: '6px', background: 'rgba(148, 163, 184, 0.08)', border: '1px solid var(--glass-border)', fontSize: '0.78rem' }}>
                <div>
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem', display: 'block' }}>TOTP BASE32 SECRET</span>
                  <code style={{ color: 'var(--primary)', fontWeight: 600 }}>
                    {showMfaSecret ? mfaInfo.secretBase32 : '••••••••••••••••••••••••••••••••'}
                  </code>
                </div>
                <button type="button" className="btn-glass" style={{ fontSize: '0.72rem', padding: '0.25rem 0.6rem' }} onClick={() => setShowMfaSecret(!showMfaSecret)}>
                  {showMfaSecret ? 'Hide Secret' : 'Show Secret / URI'}
                </button>
              </div>
              {showMfaSecret && (
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                  URI: <code>{mfaInfo.otpAuthUri}</code>
                </div>
              )}

              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                <input
                  type="text"
                  className="glass-input"
                  style={{ flex: 1, fontSize: '0.78rem' }}
                  placeholder="Enter current 6-digit TOTP code to rotate recovery codes"
                  value={regenTotpCode}
                  onChange={(e) => setRegenTotpCode(e.target.value)}
                />
                <button type="button" className="btn-glass btn-primary" style={{ fontSize: '0.76rem' }} onClick={handleRegenerateRecoveryCodes}>
                  Regenerate Recovery Codes
                </button>
              </div>

              {mfaNotice && (
                <div style={{ fontSize: '0.76rem', color: 'var(--text-main)', padding: '0.5rem 0.75rem', borderRadius: '6px', background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.35)' }}>
                  {mfaNotice}
                </div>
              )}

              {regeneratedCodes && (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.35rem', padding: '0.6rem', borderRadius: '6px', background: 'rgba(148, 163, 184, 0.1)', fontFamily: 'var(--font-mono)', fontSize: '0.74rem' }}>
                  {regeneratedCodes.map((c) => (
                    <span key={c} style={{ color: 'var(--primary)', fontWeight: 600 }}>
                      {c}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Custom Field Definitions & Maintenance Windows */}
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <ListChecks size={20} color="var(--primary)" />
            <div>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 600, margin: 0 }}>Custom Attributes &amp; Maintenance Windows</h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Fleet-wide custom fields ({customFieldDefs.length}) &amp; scheduled alert mute windows ({maintenanceWindows.length})
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap' }}>
            <input
              type="text"
              className="glass-input"
              style={{ flex: 1.2, fontSize: '0.76rem' }}
              placeholder="New Custom Field Label"
              value={newFieldLabel}
              onChange={(e) => setNewFieldLabel(e.target.value)}
            />
            <select
              className="glass-select"
              style={{ width: 'auto', fontSize: '0.76rem' }}
              value={newFieldType}
              onChange={(e) => setNewFieldType(e.target.value as 'text' | 'dropdown' | 'checkbox' | 'secret')}
            >
              <option value="text">Text</option>
              <option value="secret">Encrypted Secret (Vaulted + MFA)</option>
              <option value="dropdown">Dropdown</option>
              <option value="checkbox">Checkbox</option>
            </select>
            {newFieldType === 'dropdown' && (
              <input
                type="text"
                className="glass-input"
                style={{ flex: 1, fontSize: '0.76rem' }}
                placeholder="Options (comma-separated)"
                value={newFieldOptions}
                onChange={(e) => setNewFieldOptions(e.target.value)}
              />
            )}
            <button type="button" className="btn-glass" style={{ fontSize: '0.76rem' }} onClick={handleAddCustomField}>
              <Plus size={13} /> Field
            </button>
          </div>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', maxHeight: '72px', overflowY: 'auto' }}>
            {customFieldDefs.map((cf) => (
              <span key={cf.id} style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', padding: '0.2rem 0.55rem', borderRadius: '6px', background: 'rgba(148, 163, 184, 0.08)', border: '1px solid var(--glass-border)', fontSize: '0.72rem' }}>
                <strong>{cf.label}</strong> ({cf.field_type})
                <button
                  type="button"
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#ef4444', padding: 0, display: 'inline-flex' }}
                  onClick={async () => {
                    await deleteCustomField(cf.id);
                    fetchCustomFields().then(setCustomFieldDefs).catch(() => {});
                  }}
                >
                  ×
                </button>
              </span>
            ))}
          </div>

          <div style={{ borderTop: '1px solid var(--glass-border)', paddingTop: '0.65rem', display: 'flex', gap: '0.45rem', flexWrap: 'wrap' }}>
            <CalendarClock size={16} color="#f59e0b" style={{ alignSelf: 'center' }} />
            <input
              type="text"
              className="glass-input"
              style={{ flex: 1.2, fontSize: '0.76rem' }}
              placeholder="Maintenance Window Title"
              value={newWinTitle}
              onChange={(e) => setNewWinTitle(e.target.value)}
            />
            <select
              className="glass-select"
              style={{ width: 'auto', fontSize: '0.76rem' }}
              value={newWinTenantId}
              onChange={(e) => setNewWinTenantId(e.target.value)}
            >
              <option value="">Global Fleet</option>
              {tenants.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
            <select
              className="glass-select"
              style={{ width: 'auto', fontSize: '0.76rem' }}
              value={newWinDuration}
              onChange={(e) => setNewWinDuration(Number(e.target.value))}
            >
              <option value={60}>1h</option>
              <option value={120}>2h</option>
              <option value={240}>4h</option>
              <option value={480}>8h</option>
            </select>
            <button type="button" className="btn-glass" style={{ fontSize: '0.76rem' }} onClick={handleAddMaintenanceWindow}>
              <Plus size={13} /> Window
            </button>
          </div>

          {maintenanceWindows.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem', maxHeight: '72px', overflowY: 'auto' }}>
              {maintenanceWindows.map((mw) => (
                <div key={mw.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.72rem', padding: '0.25rem 0.5rem', borderRadius: '5px', background: 'rgba(245, 158, 11, 0.08)' }}>
                  <span>
                    <strong>{mw.title}</strong> ({mw.tenant_id ? 'Tenant' : 'Global'}) — until {new Date(mw.end_time).toLocaleString()}
                  </span>
                  <button
                    type="button"
                    className="btn-glass btn-icon"
                    onClick={async () => {
                      await deleteMaintenanceWindow(mw.id);
                      fetchMaintenanceWindows().then(setMaintenanceWindows).catch(() => {});
                    }}
                  >
                    <Trash2 size={11} color="#ef4444" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
      <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {/* White-Labeling Card */}
        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <Palette size={20} color="var(--primary)" />
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0 }}>Global White-Labeling &amp; Branding</h3>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              {formData.brand_logo_url && (
                <img
                  src={formData.brand_logo_url}
                  alt="Brand Logo"
                  style={{ height: '28px', width: 'auto', borderRadius: '4px', objectFit: 'contain' }}
                />
              )}
              <input
                ref={logoInputRef}
                type="file"
                accept="image/png,image/jpeg,image/webp,image/gif"
                style={{ display: 'none' }}
                onChange={handleLogoFileSelect}
              />
              <button
                type="button"
                className="btn-glass"
                style={{ fontSize: '0.78rem' }}
                disabled={uploadingLogo}
                onClick={() => logoInputRef.current?.click()}
              >
                <Upload size={14} /> {uploadingLogo ? 'Uploading Logo...' : 'Upload Brand Logo'}
              </button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
            <div className="form-group">
              <label className="form-label">Brand Name</label>
              <input
                type="text"
                className="glass-input"
                value={formData.brand_name ?? ''}
                onChange={(e) => setFormData({ ...formData, brand_name: e.target.value })}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Custom Domain Routing</label>
              <input
                type="text"
                className="glass-input"
                value={formData.custom_domain ?? ''}
                onChange={(e) => setFormData({ ...formData, custom_domain: e.target.value })}
              />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
            <div className="form-group">
              <label className="form-label">Primary Theme Accent (Hex)</label>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <input
                  type="color"
                  value={formData.primary_color || '#00f2fe'}
                  onChange={(e) => setFormData({ ...formData, primary_color: e.target.value })}
                  style={{ width: '40px', height: '36px', borderRadius: '6px', border: 'none', background: 'transparent', cursor: 'pointer' }}
                />
                <input
                  type="text"
                  className="glass-input"
                  value={formData.primary_color ?? '#00f2fe'}
                  onChange={(e) => setFormData({ ...formData, primary_color: e.target.value })}
                />
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">Glassmorphic Blur Preset</label>
              <select
                className="glass-select"
                value={formData.glass_blur_level ?? 'high'}
                onChange={(e) => setFormData({ ...formData, glass_blur_level: e.target.value })}
              >
                <option value="high">High Specular (16px Blur)</option>
                <option value="medium">Medium Frosted (10px Blur)</option>
                <option value="low">Subtle Minimalist (4px Blur)</option>
              </select>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem', marginTop: '1rem' }}>
            <div className="form-group">
              <label className="form-label">Adaptive Light / Dark Mode (Web UI, Tray, Installer &amp; QuickSupport)</label>
              <select
                className="glass-select"
                value={formData.theme_mode ?? 'system'}
                onChange={(e) => setFormData({ ...formData, theme_mode: e.target.value as 'system' | 'dark' | 'light' })}
              >
                <option value="system">Auto-Detect OS / Browser Preference (prefers-color-scheme &amp; AppsUseLightTheme)</option>
                <option value="dark">Force Obsidian Dark Mode</option>
                <option value="light">Force High-Contrast Daylight Mode</option>
              </select>
            </div>

            <div className="form-group">
              <label className="form-label">Public Client QuickSupport Domain / Endpoint</label>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <input
                  type="text"
                  className="glass-input"
                  placeholder="remote.domain2.com (Also served at /remote & /temporarysession)"
                  value={formData.quicksupport_custom_domain ?? ''}
                  onChange={(e) => setFormData({ ...formData, quicksupport_custom_domain: e.target.value })}
                />
                <a
                  href={formData.quicksupport_url_path || '/remote'}
                  target="_blank"
                  rel="noreferrer"
                  className="btn-glass"
                  style={{ whiteSpace: 'nowrap', display: 'flex', alignItems: 'center', gap: '0.35rem', textDecoration: 'none' }}
                >
                  <ExternalLink size={14} /> {formData.quicksupport_url_path || '/remote'}
                </a>
              </div>
            </div>
          </div>
        </div>

        {/* Code Signing API Card */}
        <div className="glass-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1.25rem' }}>
            <KeyRound size={20} color="var(--primary)" />
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Windows Authenticode &amp; Code Signing API</h3>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Automates EV/OV code signing of generated agent EXEs, PowerShell companion runbooks, and .NET assemblies via Cloud HSM or SignPath.
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div className="form-group">
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-main)' }}>
                <input
                  type="checkbox"
                  checked={(formData.code_signing_enabled ?? 0) !== 0}
                  onChange={(e) => setFormData({ ...formData, code_signing_enabled: e.target.checked ? 1 : 0 })}
                />
                <span>Enable Automated Code Signing Pipeline</span>
              </label>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr', gap: '1rem' }}>
              <div className="form-group">
                <label className="form-label">Code Signing Webhook / API URL</label>
                <input
                  type="text"
                  className="glass-input"
                  placeholder="https://signer.internal/api/v1/sign"
                  value={formData.code_signing_url ?? ''}
                  onChange={(e) => setFormData({ ...formData, code_signing_url: e.target.value })}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Strict Authenticode Signature Gate</label>
                <select
                  className="glass-select"
                  value={(formData.code_signing_strict_verify ?? 1) !== 0 ? 'strict' : 'permissive'}
                  onChange={(e) => setFormData({ ...formData, code_signing_strict_verify: e.target.value === 'strict' ? 1 : 0 })}
                >
                  <option value="strict">Enforce Valid Authenticode Before Deploy</option>
                  <option value="permissive">Allow Unsigned Fallback When Unconfigured</option>
                </select>
              </div>
            </div>

            <div style={{ background: 'rgba(148, 163, 184, 0.06)', border: '1px solid var(--glass-border)', padding: '0.85rem 1rem', borderRadius: '8px', display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
              <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)' }}>SIGNING TARGET SCOPE</span>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.75rem' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem' }}>
                  <input
                    type="checkbox"
                    checked={(formData.code_signing_sign_agents ?? 1) !== 0}
                    onChange={(e) => setFormData({ ...formData, code_signing_sign_agents: e.target.checked ? 1 : 0 })}
                  />
                  <span>MeshAgent Binaries &amp; EXEs</span>
                </label>

                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem' }}>
                  <input
                    type="checkbox"
                    checked={(formData.code_signing_sign_scripts ?? 1) !== 0}
                    onChange={(e) => setFormData({ ...formData, code_signing_sign_scripts: e.target.checked ? 1 : 0 })}
                  />
                  <span>PowerShell (.ps1) Runbooks</span>
                </label>

                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem' }}>
                  <input
                    type="checkbox"
                    checked={(formData.code_signing_sign_assemblies ?? 1) !== 0}
                    onChange={(e) => setFormData({ ...formData, code_signing_sign_assemblies: e.target.checked ? 1 : 0 })}
                  />
                  <span>.NET GUI Tray Assemblies</span>
                </label>
              </div>
            </div>
          </div>
        </div>

        {/* Session Recording & Agent Installer Enforcement */}
        <div className="glass-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1.25rem' }}>
            <Video size={20} color="var(--primary)" />
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Compliance Recording, Installer Locks &amp; Maintenance Safety</h3>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Configure remote session recording, PSA ticket enforcement for installers, and automatic maintenance window expiry.
              </p>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
            <div className="form-group">
              <label className="form-label">Automatic Session Recording</label>
              <select
                className="glass-select"
                value={formData.session_recording_enabled ? 'enabled' : 'disabled'}
                onChange={(e) => setFormData({ ...formData, session_recording_enabled: e.target.value === 'enabled' ? 1 : 0 })}
              >
                <option value="enabled">Enabled (Record all remote sessions)</option>
                <option value="disabled">Disabled (Manual trigger only)</option>
              </select>
            </div>

            <div className="form-group">
              <label className="form-label">Retention Policy (Days)</label>
              <select
                className="glass-select"
                value={formData.session_recording_retention_days ?? 90}
                onChange={(e) => setFormData({ ...formData, session_recording_retention_days: parseInt(e.target.value, 10) })}
              >
                <option value={30}>30 Days (Standard)</option>
                <option value={90}>90 Days (HIPAA / SOC2 Recommended)</option>
                <option value={180}>180 Days (Extended)</option>
                <option value={365}>365 Days (1 Year Compliance Archive)</option>
              </select>
            </div>

            <div className="form-group">
              <label className="form-label">Encoding Quality</label>
              <select
                className="glass-select"
                value={formData.session_recording_quality ?? '720p_balanced'}
                onChange={(e) => setFormData({ ...formData, session_recording_quality: e.target.value })}
              >
                <option value="1080p_high">1080p 60fps (High Fidelity)</option>
                <option value="720p_balanced">720p 30fps VP8 (Recommended)</option>
                <option value="480p_compact">480p Compact</option>
              </select>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem' }}>
            <div className="form-group">
              <label className="form-label">Minimum Role to Download Installers</label>
              <select
                className="glass-select"
                value={formData.installer_download_role ?? 'technician'}
                onChange={(e) => setFormData({ ...formData, installer_download_role: e.target.value })}
              >
                <option value="technician">Technician+ (All Staff)</option>
                <option value="admin">MSP Super Admin Only</option>
              </select>
            </div>

            <div className="form-group">
              <label className="form-label">Require PSA Ticket # for Installer</label>
              <select
                className="glass-select"
                value={formData.installer_require_ticket ? 'required' : 'optional'}
                onChange={(e) => setFormData({ ...formData, installer_require_ticket: e.target.value === 'required' ? 1 : 0 })}
              >
                <option value="optional">Optional (Direct Download Allowed)</option>
                <option value="required">Strictly Enforced (Valid PSA Ticket #)</option>
              </select>
            </div>

            <div className="form-group">
              <label className="form-label">Auto-Clear Maintenance After</label>
              <select
                className="glass-select"
                value={formData.maintenance_auto_clear_hours ?? 24}
                onChange={(e) => setFormData({ ...formData, maintenance_auto_clear_hours: parseInt(e.target.value, 10) })}
              >
                <option value={12}>12 Hours Online</option>
                <option value={24}>24 Hours Online (Default)</option>
                <option value={48}>48 Hours Online</option>
                <option value={72}>72 Hours Online</option>
              </select>
            </div>
          </div>
        </div>

        {/* MeshCentral Bi-Directional Sync Card */}
        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <Shield size={20} color="var(--primary)" />
              <div>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0 }}>
                  MeshCentral 2 Bi-Directional Sync &amp; Multi-Instance Federation
                </h3>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: '0.2rem 0 0 0' }}>
                  Bi-directional mirroring of MeshCentral Device Groups &harr; Vitrine Clients with isolated sidecar safety
                </p>
              </div>
            </div>

            <button
              type="button"
              className="btn-glass"
              onClick={handleSyncMesh}
              disabled={syncingMesh}
              style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '0.8rem' }}
            >
              <RefreshCw size={14} className={syncingMesh ? 'spin' : ''} />
              <span>{syncingMesh ? 'Syncing with MeshCentral...' : 'Synchronize MeshCentral Now'}</span>
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.25rem', marginBottom: '1rem' }}>
            <div className="form-group">
              <label className="form-label">Primary MeshCentral Server URL</label>
              <input
                type="text"
                className="glass-input"
                value={formData.meshcentral_url ?? ''}
                onChange={(e) => setFormData({ ...formData, meshcentral_url: e.target.value })}
              />
            </div>

            <div className="form-group">
              <label className="form-label">API Key / Login Token (Vaulted)</label>
              <input
                type="password"
                className="glass-input"
                placeholder="••••••••••••••••"
                value={formData.meshcentral_api_token ?? ''}
                onChange={(e) => setFormData({ ...formData, meshcentral_api_token: e.target.value })}
              />
            </div>
          </div>

          <div style={{ background: 'rgba(148, 163, 184, 0.06)', border: '1px solid var(--glass-border)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.85rem' }}>
              <input
                type="checkbox"
                checked={Boolean(formData.mesh_sync_enabled)}
                onChange={(e) => setFormData({ ...formData, mesh_sync_enabled: e.target.checked ? 1 : 0 })}
              />
              <span style={{ fontWeight: 600 }}>Enable Continuous Bi-Directional Group &amp; Client Sync</span>
            </label>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
              <div className="form-group">
                <label className="form-label">Client Deletion Policy (Vitrine Side)</label>
                <select
                  className="glass-select"
                  value={formData.mesh_client_delete_action ?? 'move_to_unassigned'}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      mesh_client_delete_action: e.target.value as 'uninstall' | 'move_to_unassigned'
                    })
                  }
                >
                  <option value="move_to_unassigned">Move endpoints to Unassigned holding group (Safe - Recommended)</option>
                  <option value="uninstall">Mass uninstall Vitrine &amp; MeshCentral agents from endpoints</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">External MeshCentral Group Deletion Action</label>
                <select
                  className="glass-select"
                  value={formData.mesh_external_delete_prompt ?? 'prompt'}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      mesh_external_delete_prompt: e.target.value as 'prompt' | 'auto_unassigned'
                    })
                  }
                >
                  <option value="prompt">Prompt Admins via Notification System &amp; Email Alert</option>
                  <option value="auto_unassigned">Automatically migrate endpoints to Unassigned group</option>
                </select>
              </div>
            </div>
          </div>

          {meshSyncResult && (
            <div style={{ background: 'rgba(0, 242, 254, 0.1)', border: '1px solid rgba(0, 242, 254, 0.3)', padding: '0.75rem 1rem', borderRadius: '6px', fontSize: '0.8rem', color: 'var(--text-main)', marginTop: '1rem' }}>
              {meshSyncResult}
            </div>
          )}

          {/* Multi-Instance MeshCentral 2 Federation & Live Fleet Discovery/Import */}
          <div style={{ marginTop: '1.25rem', borderTop: '1px solid var(--glass-border)', paddingTop: '1.15rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
              <Server size={16} color="var(--primary)" />
              <strong style={{ fontSize: '0.92rem' }}>Federated MeshCentral 2 Instances ({meshServers.length}) &amp; Live Fleet Discovery</strong>
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.85rem' }}>
              <input
                type="text"
                className="glass-input"
                style={{ flex: 1, fontSize: '0.78rem' }}
                placeholder="Instance Label (e.g. Regional MS2 Cluster #2)"
                value={newMeshName}
                onChange={(e) => setNewMeshName(e.target.value)}
              />
              <input
                type="text"
                className="glass-input"
                style={{ flex: 1.4, fontSize: '0.78rem' }}
                placeholder="https://mesh2.msp-domain.com:4430"
                value={newMeshUrl}
                onChange={(e) => setNewMeshUrl(e.target.value)}
              />
              <input
                type="password"
                className="glass-input"
                style={{ flex: 1, fontSize: '0.78rem' }}
                placeholder="API Token / Login Key"
                value={newMeshToken}
                onChange={(e) => setNewMeshToken(e.target.value)}
              />
              <button type="button" className="btn-glass btn-primary" style={{ fontSize: '0.78rem' }} onClick={handleAddMeshServer}>
                <Plus size={14} /> Add MS2 Instance
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {meshServers.map((srv) => (
                <div
                  key={srv.id}
                  style={{
                    padding: '0.65rem 0.95rem',
                    borderRadius: '8px',
                    background: 'rgba(148, 163, 184, 0.06)',
                    border: '1px solid var(--glass-border)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    gap: '0.65rem'
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600, fontSize: '0.84rem' }}>
                      <span>{srv.name}</span>
                      {srv.is_primary === 1 && <span className="status-pill status-online" style={{ fontSize: '0.65rem' }}>Primary</span>}
                    </div>
                    <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                      {srv.url} • Auto-Push Signed Vitrine Companion: {srv.auto_push_companion ? 'Enabled' : 'Disabled'}
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ fontSize: '0.75rem', padding: '0.3rem 0.65rem' }}
                      disabled={discoveringServerId === srv.id}
                      onClick={() => handleDiscoverMesh(srv)}
                    >
                      <RefreshCw size={12} className={discoveringServerId === srv.id ? 'spin' : ''} />
                      <span>{discoveringServerId === srv.id ? 'Scanning...' : 'Test & Discover Fleet'}</span>
                    </button>
                    {srv.is_primary !== 1 && (
                      <button
                        type="button"
                        className="btn-glass btn-icon"
                        onClick={async () => {
                          await deleteMeshServer(srv.id);
                          loadAllAdminData();
                        }}
                      >
                        <Trash2 size={13} color="#ef4444" />
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>

            {discoveryPreview && (
              <div style={{ marginTop: '0.85rem', padding: '0.9rem 1.1rem', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.35)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <strong style={{ fontSize: '0.84rem', color: '#34d399' }}>
                    ✓ Live Discovery from {discoveryPreview.serverUrl}: {discoveryPreview.discoveredGroups.length} Device Groups &amp; {discoveryPreview.discoveredAgents.length} Agents Found
                  </strong>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <button
                      type="button"
                      className="btn-glass btn-primary"
                      style={{ fontSize: '0.75rem', padding: '0.3rem 0.75rem' }}
                      disabled={importingServerId !== null}
                      onClick={() => handleImportDiscoveredMesh(discoveryPreview.serverId)}
                    >
                      {importingServerId ? 'Importing & Queuing Add-Ons...' : 'Import Groups & Auto-Push Signed Companion'}
                    </button>
                    <button type="button" className="btn-glass" style={{ fontSize: '0.75rem', padding: '0.3rem 0.55rem' }} onClick={() => setDiscoveryPreview(null)}>
                      Close
                    </button>
                  </div>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Groups: {discoveryPreview.discoveredGroups.map((g) => `${g.name} (${g.agentCount} agents)`).join(' • ') || 'None'}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Self-Update Engine (Stable Releases vs. Alpha Commits + Pre-Update Backup & Watchdog Rollback) */}
        <div className="glass-card" id="self-updater-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <GitBranch size={20} color="var(--primary)" />
              <div>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0 }}>
                  Self-Update Engine (Stable Releases vs. Alpha Commits) &amp; Watchdog Auto-Rollback
                </h3>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: '0.2rem 0 0 0' }}>
                  Installed Version: <strong>v{updaterStatus?.installedVersion || formData.installed_version || '2.5.1'}</strong> • Installed Commit:{' '}
                  <code>{updaterStatus?.installedCommit || formData.installed_commit || 'HEAD'}</code> • DB Schema:{' '}
                  <code>v{backupStorage.currentAppSchemaVersion}</code> • Mode:{' '}
                  <strong>{updaterStatus?.deploymentMode === 'docker' ? 'Docker Container' : 'Bare-Metal Systemd'}</strong>
                </p>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <button
                type="button"
                className={`btn-glass ${(updaterStatus?.channel || formData.update_channel) === 'stable' ? 'btn-primary' : ''}`}
                style={{ fontSize: '0.78rem' }}
                onClick={() => handleSwitchChannel('stable')}
              >
                Stable Channel (GitHub Releases)
              </button>
              <button
                type="button"
                className={`btn-glass ${(updaterStatus?.channel || formData.update_channel) === 'alpha' ? 'btn-primary' : ''}`}
                style={{ fontSize: '0.78rem' }}
                onClick={() => handleSwitchChannel('alpha')}
              >
                Alpha Channel (Latest Commits)
              </button>
            </div>
          </div>

          {channelGuardrailError && (
            <div style={{ marginBottom: '1rem', padding: '0.75rem 1rem', borderRadius: '8px', background: 'rgba(245, 158, 11, 0.14)', border: '1px solid rgba(245, 158, 11, 0.45)', fontSize: '0.8rem', color: 'var(--text-main)' }}>
              <strong>⚠️ Alpha-to-Stable Guardrail Active:</strong> {channelGuardrailError}
            </div>
          )}

          {updaterStatus && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
              {updaterStatus.deploymentMode === 'docker' && (
                <div style={{ padding: '0.75rem 1rem', borderRadius: '8px', background: 'rgba(56, 189, 248, 0.1)', border: '1px solid rgba(56, 189, 248, 0.35)', fontSize: '0.78rem', color: 'var(--text-main)' }}>
                  <strong>🐳 Docker Container Mode:</strong> Persistent data in <code>/app/data</code> automatically upgrades its SQLite schema on container boot. Pull <code>tylerhats/vitrine-rmm:latest</code> (or Watchtower) on the host to upgrade container binaries.
                </div>
              )}

              {updaterStatus.channel === 'stable' ? (
                <div style={{ padding: '0.9rem 1.1rem', borderRadius: '8px', background: 'var(--glass-bg)', border: '1px solid var(--glass-border)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.45rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <strong style={{ fontSize: '0.88rem', color: '#38bdf8' }}>
                      Latest Stable Release: {updaterStatus.latestStable.title} (Commit <code>{updaterStatus.latestStable.commitSha}</code>)
                    </strong>
                    <span className="status-pill status-online" style={{ fontSize: '0.7rem' }}>
                      {updaterStatus.updateAvailable ? 'Update Available' : 'Up to Date'}
                    </span>
                  </div>
                  <pre style={{ margin: 0, whiteSpace: 'pre-wrap', fontSize: '0.76rem', color: 'var(--text-muted)', fontFamily: 'inherit' }}>
                    {updaterStatus.latestStable.releaseNotes}
                  </pre>
                </div>
              ) : (
                <div style={{ padding: '0.9rem 1.1rem', borderRadius: '8px', background: 'var(--glass-bg)', border: '1px solid var(--glass-border)' }}>
                  <strong style={{ fontSize: '0.86rem', color: '#c084fc', display: 'block', marginBottom: '0.5rem' }}>
                    Alpha Commits Since Installed Commit (<code>{updaterStatus.installedCommit}</code>):
                  </strong>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                    {updaterStatus.pendingAlphaCommits.length === 0 ? (
                      <div style={{ fontSize: '0.76rem', color: 'var(--text-dim)' }}>No newer commits pending on branch.</div>
                    ) : (
                      updaterStatus.pendingAlphaCommits.map((c) => (
                        <div key={c.sha} style={{ fontSize: '0.76rem', display: 'flex', justifyContent: 'space-between', gap: '0.75rem', padding: '0.35rem 0.5rem', background: 'rgba(148, 163, 184, 0.06)', borderRadius: '6px' }}>
                          <span>
                            <code style={{ color: '#38bdf8', marginRight: '0.5rem' }}>{c.sha}</code>
                            {c.message}
                          </span>
                          <span style={{ color: 'var(--text-dim)', whiteSpace: 'nowrap' }}>{c.author}</span>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.65rem' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={(formData.update_auto_backup ?? 1) !== 0}
                    onChange={(e) => setFormData({ ...formData, update_auto_backup: e.target.checked ? 1 : 0 })}
                  />
                  <span>Auto Pre-Update Full Backup (Unified Backup Engine)</span>
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={(formData.update_auto_rollback ?? 1) !== 0}
                    onChange={(e) => setFormData({ ...formData, update_auto_rollback: e.target.checked ? 1 : 0 })}
                  />
                  <span>Auto-Rollback Watchdog on Health Check Failure</span>
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={(formData.update_notify_webui ?? 1) !== 0}
                    onChange={(e) => setFormData({ ...formData, update_notify_webui: e.target.checked ? 1 : 0 })}
                  />
                  <span>Notify Admins in Web UI &amp; at Login</span>
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={Boolean(formData.update_notify_email)}
                    onChange={(e) => setFormData({ ...formData, update_notify_email: e.target.checked ? 1 : 0 })}
                  />
                  <span>Send Email Alert on New Update</span>
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.8rem' }}>
                  <input
                    type="checkbox"
                    checked={Boolean(formData.update_create_psa_ticket)}
                    onChange={(e) => setFormData({ ...formData, update_create_psa_ticket: e.target.checked ? 1 : 0 })}
                  />
                  <span>Auto-Create PSA Change Ticket on Update</span>
                </label>
              </div>

              <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="btn-glass btn-primary"
                  disabled={installingUpdate || updaterStatus.deploymentMode === 'docker'}
                  onClick={handleInstallUpdate}
                >
                  <RefreshCw size={14} className={installingUpdate ? 'spin' : ''} />
                  <span>
                    {installingUpdate
                      ? 'Running Pre-Update Backup & Installing...'
                      : updaterStatus.deploymentMode === 'docker'
                      ? 'Managed via Docker Image Pull'
                      : `Install Target Update (${updaterStatus.channel === 'stable' ? updaterStatus.latestStable.version : updaterStatus.latestAlpha.sha})`}
                  </span>
                </button>
              </div>

              {updaterNotice && (
                <div style={{ padding: '0.75rem 1rem', borderRadius: '8px', background: 'rgba(0, 242, 254, 0.1)', border: '1px solid rgba(0, 242, 254, 0.35)', fontSize: '0.8rem', color: 'var(--text-main)' }}>
                  {updaterNotice}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Unified Self-Backup, Local Storage Quota & Schema-Aware Restoration Card */}
        <div className="glass-card" id="unified-backups-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <Database size={20} color="#10b981" />
              <div>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0 }}>
                  Unified Self-Backup, Storage Management &amp; Schema-Aware Restoration
                </h3>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: '0.2rem 0 0 0' }}>
                  Full self-restore archives (<code>.vrmm-backup.gz</code>) bundling SQLite DB, AES-256-GCM Vault Master Key, White-Label Branding &amp; Manifest • Used:{' '}
                  <strong>{(backupStorage.usedBytes / (1024 * 1024)).toFixed(2)} MB</strong> / {backupStorage.quotaMb} MB
                </p>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <button
                type="button"
                className="btn-glass btn-primary"
                disabled={creatingBackup}
                onClick={handleCreateBackup}
              >
                <Database size={14} />
                <span>{creatingBackup ? 'Bundling Encrypted Archive...' : 'Create On-Demand Backup Now'}</span>
              </button>
              <input
                ref={backupFileInputRef}
                type="file"
                accept=".gz,.vrmm-backup.gz,application/gzip"
                style={{ display: 'none' }}
                onChange={handleBackupFileSelect}
              />
              <button
                type="button"
                className="btn-glass"
                style={{ fontSize: '0.78rem' }}
                disabled={uploadingBackup}
                onClick={() => backupFileInputRef.current?.click()}
              >
                <Upload size={14} /> {uploadingBackup ? 'Verifying Archive...' : 'Upload .vrmm-backup.gz'}
              </button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
            <div className="form-group">
              <label className="form-label">Automated Backup Schedule</label>
              <select
                className="glass-select"
                value={formData.backup_schedule_frequency ?? 'daily'}
                onChange={(e) => setFormData({ ...formData, backup_schedule_frequency: e.target.value as any })}
              >
                <option value="hourly">Hourly Snapshots</option>
                <option value="daily">Daily Snapshot (Recommended)</option>
                <option value="weekly">Weekly Snapshot</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">Retention Count (Auto-Prune)</label>
              <input
                type="number"
                min={1}
                className="glass-input"
                value={formData.backup_retention_count ?? 14}
                onChange={(e) => setFormData({ ...formData, backup_retention_count: parseInt(e.target.value, 10) || 1 })}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Local Storage Quota (MB)</label>
              <input
                type="number"
                min={128}
                className="glass-input"
                value={formData.backup_max_storage_mb ?? 5120}
                onChange={(e) => setFormData({ ...formData, backup_max_storage_mb: parseInt(e.target.value, 10) || 512 })}
              />
            </div>
          </div>
          {/* AES-256 Archive Encryption & Offsite S3 / Backblaze B2 / MinIO / SMB Vault */}
          <div style={{ marginBottom: '1rem', padding: '0.95rem 1.1rem', borderRadius: '8px', background: 'var(--glass-bg)', border: '1px solid var(--glass-border)', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.65rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '0.82rem', fontWeight: 600, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={(formData.backup_encryption_enabled ?? 1) !== 0}
                    onChange={(e) => setFormData({ ...formData, backup_encryption_enabled: e.target.checked ? 1 : 0 })}
                  />
                  <Lock size={14} color="#34d399" />
                  <span>AES-256-GCM Archive Encryption (VRMMENC1)</span>
                </label>

                <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '0.82rem', fontWeight: 600, cursor: 'pointer', marginLeft: '0.75rem' }}>
                  <input
                    type="checkbox"
                    checked={Boolean(formData.backup_offsite_enabled)}
                    onChange={(e) => setFormData({ ...formData, backup_offsite_enabled: e.target.checked ? 1 : 0 })}
                  />
                  <CloudUpload size={14} color="#38bdf8" />
                  <span>Auto-Replicate to Offsite Cloud / Local Path Vault</span>
                </label>
              </div>

              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.76rem', padding: '0.35rem 0.75rem', borderColor: 'rgba(245, 158, 11, 0.45)', color: '#fbbf24' }}
                  onClick={handleRevealBackupKey}
                >
                  <KeyRound size={13} />
                  <span>Reveal / Export Recovery Key (MFA)</span>
                </button>
                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.76rem', padding: '0.35rem 0.75rem', borderColor: 'rgba(56, 189, 248, 0.45)', color: '#38bdf8' }}
                  disabled={syncingOffsite}
                  onClick={handleSyncOffsiteVault}
                >
                  <CloudUpload size={13} />
                  <span>{syncingOffsite ? 'Replicating to Offsite Vault...' : 'Test & Sync Offsite Vault Now'}</span>
                </button>
              </div>
            </div>

            {revealedBackupKey && (
              <div
                style={{
                  padding: '0.75rem 0.95rem',
                  borderRadius: '8px',
                  background: 'rgba(245, 158, 11, 0.1)',
                  border: '1px solid rgba(245, 158, 11, 0.4)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  flexWrap: 'wrap'
                }}
              >
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#fbbf24' }}>
                  Recovery Passphrase:
                </span>
                <input
                  type="text"
                  readOnly
                  className="glass-input"
                  style={{ flex: 1, minWidth: '220px', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', fontWeight: 700, color: 'var(--primary)' }}
                  value={revealedBackupKey}
                />
                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.74rem', padding: '0.3rem 0.65rem' }}
                  onClick={() => {
                    navigator.clipboard.writeText(revealedBackupKey);
                    setCopiedBackupKey(true);
                    setTimeout(() => setCopiedBackupKey(false), 2000);
                  }}
                >
                  {copiedBackupKey ? <Check size={13} color="#10b981" /> : <Copy size={13} />}
                  <span>{copiedBackupKey ? 'Copied' : 'Copy'}</span>
                </button>
                <button
                  type="button"
                  className="btn-glass btn-primary"
                  style={{ fontSize: '0.74rem', padding: '0.3rem 0.7rem' }}
                  onClick={() => handleDownloadBackupKeyKit(revealedBackupKey)}
                >
                  <Download size={13} /> Download .txt Kit
                </button>
                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.74rem', padding: '0.3rem 0.6rem' }}
                  onClick={() => setRevealedBackupKey(null)}
                >
                  Hide
                </button>
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.2fr 1fr', gap: '0.75rem' }}>
              <div>
                <label className="form-label" style={{ fontSize: '0.72rem' }}>Archive Passphrase (Vaulted)</label>
                <input
                  type="password"
                  className="glass-input"
                  style={{ fontSize: '0.78rem' }}
                  placeholder="Optional custom passphrase"
                  value={formData.backup_encryption_passphrase ?? ''}
                  onChange={(e) => setFormData({ ...formData, backup_encryption_passphrase: e.target.value })}
                />
              </div>
              <div>
                <label className="form-label" style={{ fontSize: '0.72rem' }}>Offsite Target Provider</label>
                <select
                  className="glass-select"
                  style={{ fontSize: '0.78rem' }}
                  value={formData.backup_offsite_provider ?? 's3'}
                  onChange={(e) => setFormData({ ...formData, backup_offsite_provider: e.target.value as any })}
                >
                  <option value="s3">Amazon S3 / S3-Compatible (SigV4)</option>
                  <option value="backblaze_b2">Backblaze B2 S3 API</option>
                  <option value="minio">Self-Hosted MinIO Object Storage</option>
                  <option value="smb">Mounted SMB / NFS Local Directory</option>
                </select>
              </div>
              <div>
                <label className="form-label" style={{ fontSize: '0.72rem' }}>Offsite Endpoint URL</label>
                <input
                  type="text"
                  className="glass-input"
                  style={{ fontSize: '0.78rem' }}
                  placeholder="https://s3.us-east-005.backblazeb2.com"
                  value={formData.backup_offsite_endpoint ?? ''}
                  onChange={(e) => setFormData({ ...formData, backup_offsite_endpoint: e.target.value })}
                />
              </div>
              <div>
                <label className="form-label" style={{ fontSize: '0.72rem' }}>Bucket Name or Mounted Path</label>
                <input
                  type="text"
                  className="glass-input"
                  style={{ fontSize: '0.78rem' }}
                  placeholder="vitrine-rmm-backups or /mnt/nas"
                  value={formData.backup_offsite_bucket ?? ''}
                  onChange={(e) => setFormData({ ...formData, backup_offsite_bucket: e.target.value })}
                />
              </div>
            </div>

            {formData.backup_offsite_provider !== 'smb' && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div>
                  <label className="form-label" style={{ fontSize: '0.72rem' }}>S3 Access Key ID (Vaulted)</label>
                  <input
                    type="password"
                    className="glass-input"
                    style={{ fontSize: '0.78rem' }}
                    placeholder="AKIA..."
                    value={formData.backup_offsite_access_key ?? ''}
                    onChange={(e) => setFormData({ ...formData, backup_offsite_access_key: e.target.value })}
                  />
                </div>
                <div>
                  <label className="form-label" style={{ fontSize: '0.72rem' }}>S3 Secret Access Key (Vaulted)</label>
                  <input
                    type="password"
                    className="glass-input"
                    style={{ fontSize: '0.78rem' }}
                    placeholder="••••••••••••••••"
                    value={formData.backup_offsite_secret_key ?? ''}
                    onChange={(e) => setFormData({ ...formData, backup_offsite_secret_key: e.target.value })}
                  />
                </div>
              </div>
            )}
          </div>

          {backupNotice && (
            <div style={{ marginBottom: '1rem', padding: '0.75rem 1rem', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.35)', fontSize: '0.8rem', color: 'var(--text-main)' }}>
              {backupNotice}
            </div>
          )}

          <div className="table-wrapper">
            <table className="glass-table">
              <thead>
                <tr>
                  <th>Backup Archive</th>
                  <th>Type</th>
                  <th>App Target / DB Schema</th>
                  <th>Size</th>
                  <th>Created</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {backups.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-dim)', fontSize: '0.82rem' }}>
                      No backup archives created yet. Click &quot;Create On-Demand Backup Now&quot; to bundle a full encrypted self-restore archive.
                    </td>
                  </tr>
                ) : (
                  backups.map((b) => {
                    const isNewerSchema = b.db_schema_version > backupStorage.currentAppSchemaVersion;
                    const isOlderSchema = b.db_schema_version < backupStorage.currentAppSchemaVersion;
                    return (
                      <tr key={b.id}>
                        <td>
                          <div style={{ fontWeight: 600, fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                            <span>{b.filename}</span>
                            {b.encrypted !== 0 && (
                              <span className="status-pill status-online" style={{ fontSize: '0.62rem' }}>AES-256</span>
                            )}
                            {b.offsite_synced === 1 && (
                              <span className="status-pill" style={{ fontSize: '0.62rem', background: 'rgba(56, 189, 248, 0.14)', color: '#38bdf8' }}>
                                Offsite: {b.offsite_location || formData.backup_offsite_provider || 's3'}
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>{b.notes || 'DB + LAPS Vault + Branding + Config'}</div>
                        </td>
                        <td>
                          <span className="status-pill status-online" style={{ fontSize: '0.68rem' }}>
                            {b.trigger_type.toUpperCase()}
                          </span>
                        </td>
                        <td>
                          <div style={{ fontSize: '0.78rem', fontWeight: 600 }}>
                            App v{b.app_version} (<code>{b.git_commit}</code>)
                          </div>
                          <div style={{ fontSize: '0.72rem', color: isNewerSchema ? '#fbbf24' : isOlderSchema ? '#38bdf8' : '#10b981' }}>
                            DB Schema v{b.db_schema_version}{' '}
                            {isNewerSchema
                              ? '⚠️ Newer than installed software'
                              : isOlderSchema
                              ? '↪ Auto-migrates forward on restore'
                              : '✓ Matches installed target'}
                          </div>
                        </td>
                        <td style={{ fontSize: '0.78rem' }}>{(b.size_bytes / (1024 * 1024)).toFixed(2)} MB</td>
                        <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{new Date(b.created_at).toLocaleString()}</td>
                        <td style={{ textAlign: 'right' }}>
                          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.4rem' }}>
                            <a
                              href={getBackupDownloadUrl(b.id)}
                              download
                              className="btn-glass"
                              style={{ padding: '0.25rem 0.55rem', fontSize: '0.73rem', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}
                            >
                              <Download size={12} /> Download
                            </a>
                            <button
                              type="button"
                              className="btn-glass"
                              style={{
                                padding: '0.25rem 0.6rem',
                                fontSize: '0.73rem',
                                borderColor: isNewerSchema ? 'rgba(245, 158, 11, 0.5)' : undefined,
                                color: isNewerSchema ? '#fbbf24' : undefined
                              }}
                              disabled={restoringBackupId === b.id}
                              onClick={() => handleInitiateRestore(b)}
                            >
                              {restoringBackupId === b.id ? 'Restoring...' : 'Restore'}
                            </button>
                            <button
                              type="button"
                              className="btn-glass btn-icon"
                              onClick={async () => {
                                await deleteSystemBackup(b.id);
                                loadAllAdminData();
                              }}
                            >
                              <Trash2 size={12} color="#ef4444" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* PSA Webhook & OIDC Identity Provider Integration Card */}
        <div className="glass-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1.15rem' }}>
            <Webhook size={20} color="var(--primary)" />
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0 }}>PSA Bi-Directional Webhook &amp; OIDC Identity Provider</h3>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Configure HMAC-SHA256 PSA ticket dispatch (ITFlow, HaloPSA, Autotask) and OIDC SSO parameters
              </span>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: '1.25rem', marginBottom: '1rem' }}>
            <div className="form-group">
              <label className="form-label">PSA / ITFlow Base URL</label>
              <input
                type="text"
                className="glass-input"
                placeholder="https://psa.msp-domain.com/api/v1"
                value={formData.itflow_url ?? ''}
                onChange={(e) => setFormData({ ...formData, itflow_url: e.target.value })}
              />
            </div>
            <div className="form-group">
              <label className="form-label">PSA Outbound API Key (Vaulted)</label>
              <input
                type="password"
                className="glass-input"
                placeholder="••••••••••••••••"
                value={formData.itflow_api_key ?? ''}
                onChange={(e) => setFormData({ ...formData, itflow_api_key: e.target.value })}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Inbound PSA Webhook HMAC Secret (Vaulted)</label>
              <input
                type="password"
                className="glass-input"
                placeholder="••••••••••••••••"
                value={formData.psa_webhook_secret ?? ''}
                onChange={(e) => setFormData({ ...formData, psa_webhook_secret: e.target.value })}
              />
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.84rem', fontWeight: 600 }}>
              <input
                type="checkbox"
                checked={Boolean(formData.oidc_enabled)}
                onChange={(e) => setFormData({ ...formData, oidc_enabled: e.target.checked ? 1 : 0 })}
              />
              <span>Enable OpenID Connect (OIDC + S256 PKCE) Single Sign-On on Login Screen</span>
            </label>
            <button
              type="button"
              className="btn-glass"
              style={{ fontSize: '0.76rem', padding: '0.32rem 0.75rem' }}
              disabled={testingOidc || !formData.oidc_issuer_url}
              onClick={handleTestOidc}
            >
              <Globe size={13} /> {testingOidc ? 'Testing Discovery...' : 'Test OIDC Discovery'}
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: '1.25rem' }}>
            <div className="form-group">
              <label className="form-label">OIDC Issuer URL (Authentik / Entra ID)</label>
              <input
                type="text"
                className="glass-input"
                placeholder="https://auth.msp-domain.com/application/o/vitrine/"
                value={formData.oidc_issuer_url ?? ''}
                onChange={(e) => setFormData({ ...formData, oidc_issuer_url: e.target.value })}
              />
            </div>
            <div className="form-group">
              <label className="form-label">OIDC Client ID</label>
              <input
                type="text"
                className="glass-input"
                value={formData.oidc_client_id ?? ''}
                onChange={(e) => setFormData({ ...formData, oidc_client_id: e.target.value })}
              />
            </div>
            <div className="form-group">
              <label className="form-label">OIDC Client Secret (Vaulted)</label>
              <input
                type="password"
                className="glass-input"
                placeholder="••••••••••••••••"
                value={formData.oidc_client_secret ?? ''}
                onChange={(e) => setFormData({ ...formData, oidc_client_secret: e.target.value })}
              />
            </div>
          </div>

          {oidcTestResult && (
            <div style={{ marginTop: '0.85rem', padding: '0.7rem 0.95rem', borderRadius: '8px', background: 'rgba(0, 242, 254, 0.1)', border: '1px solid rgba(0, 242, 254, 0.35)', fontSize: '0.78rem', color: 'var(--text-main)' }}>
              {oidcTestResult}
            </div>
          )}
        </div>

        {/* Outbound SMTP Notifications Card */}
        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <Mail size={20} color="var(--primary)" />
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Outbound SMTP &amp; Alert Routing</h3>
            </div>
            <button type="button" className="btn-glass" onClick={handleTestSmtp} disabled={testingSmtp}>
              <Send size={14} /> {testingSmtp ? 'Testing SMTP...' : 'Send Test Dispatch'}
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 0.7fr 1.2fr', gap: '1.25rem' }}>
            <div className="form-group">
              <label className="form-label">SMTP Host</label>
              <input
                type="text"
                className="glass-input"
                placeholder="smtp.office365.com"
                value={formData.smtp_host ?? ''}
                onChange={(e) => setFormData({ ...formData, smtp_host: e.target.value })}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Port</label>
              <input
                type="number"
                className="glass-input"
                value={formData.smtp_port ?? 587}
                onChange={(e) => setFormData({ ...formData, smtp_port: parseInt(e.target.value, 10) || 587 })}
              />
            </div>
            <div className="form-group">
              <label className="form-label">From Address</label>
              <input
                type="email"
                className="glass-input"
                placeholder="alerts@msp-domain.com"
                value={formData.smtp_from ?? ''}
                onChange={(e) => setFormData({ ...formData, smtp_from: e.target.value })}
              />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
            <div className="form-group">
              <label className="form-label">Username</label>
              <input
                type="text"
                className="glass-input"
                value={formData.smtp_user ?? ''}
                onChange={(e) => setFormData({ ...formData, smtp_user: e.target.value })}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Password (Vaulted)</label>
              <input
                type="password"
                className="glass-input"
                placeholder="••••••••••••••••"
                value={formData.smtp_pass ?? ''}
                onChange={(e) => setFormData({ ...formData, smtp_pass: e.target.value })}
              />
            </div>
          </div>

          {smtpTestResult && (
            <div style={{ background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.3)', padding: '0.75rem 1rem', borderRadius: '6px', fontSize: '0.8rem', color: 'var(--text-main)' }}>
              {smtpTestResult}
            </div>
          )}
        </div>

        {/* Save Button */}
        <div>
          <button type="submit" className="btn-glass btn-primary" style={{ padding: '0.75rem 1.75rem' }} disabled={saving}>
            <CheckCircle2 size={16} /> {saving ? 'Saving Configuration...' : 'Save All Changes'}
          </button>
        </div>
      </form>

      {/* Database Schema Version vs. Installed Software Target Mismatch Modal */}
      {schemaMismatchModal && (
        <div className="modal-backdrop" onClick={() => setSchemaMismatchModal(null)}>
          <div className="glass-modal" style={{ maxWidth: '620px' }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title" style={{ color: '#fbbf24' }}>
                <AlertTriangle size={20} color="#fbbf24" />
                <span>Database Schema Newer Than Installed Software Target</span>
              </div>
            </div>
            <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ padding: '0.9rem 1.1rem', borderRadius: '8px', background: 'rgba(245, 158, 11, 0.14)', border: '1px solid rgba(245, 158, 11, 0.45)', fontSize: '0.84rem', color: 'var(--text-main)', lineHeight: 1.55 }}>
                <strong>⚠️ Schema Version Conflict Detected:</strong>
                <br />
                {schemaMismatchModal.warningMessage}
              </div>

              <div className="grid-2" style={{ gap: '0.85rem' }}>
                <div style={{ padding: '0.75rem', borderRadius: '8px', background: 'var(--glass-bg)', border: '1px solid var(--glass-border)' }}>
                  <div style={{ fontSize: '0.73rem', color: 'var(--text-muted)' }}>Backup Archive DB Schema</div>
                  <div style={{ fontSize: '1.05rem', fontWeight: 700, color: '#fbbf24' }}>
                    Schema v{schemaMismatchModal.backupSchemaVersion} (App v{schemaMismatchModal.backup.app_version})
                  </div>
                </div>
                <div style={{ padding: '0.75rem', borderRadius: '8px', background: 'var(--glass-bg)', border: '1px solid var(--glass-border)' }}>
                  <div style={{ fontSize: '0.73rem', color: 'var(--text-muted)' }}>Installed Software Target</div>
                  <div style={{ fontSize: '1.05rem', fontWeight: 700, color: '#38bdf8' }}>
                    Schema v{schemaMismatchModal.appSchemaVersion} (App v{updaterStatus?.installedVersion || '2.5.1'})
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                <button
                  type="button"
                  className="btn-glass btn-primary"
                  style={{ justifyContent: 'flex-start', padding: '0.85rem 1rem', textAlign: 'left' }}
                  disabled={restoringBackupId !== null}
                  onClick={() => executeRestore(schemaMismatchModal.backup.id, 'upgrade_software_to_match')}
                >
                  <div>
                    <div style={{ fontWeight: 700, fontSize: '0.86rem' }}>
                      Option 1 (Recommended): Auto-Update Vitrine Software to Match Backup Target &amp; Restore
                    </div>
                    <div style={{ fontSize: '0.75rem', opacity: 0.85, marginTop: '0.2rem' }}>
                      Pulls the matching software release/commit (Schema v{schemaMismatchModal.backupSchemaVersion}) first, then cleanly restores the database, LAPS vault, and branding.
                    </div>
                  </div>
                </button>

                <button
                  type="button"
                  className="btn-glass"
                  style={{ justifyContent: 'flex-start', padding: '0.85rem 1rem', textAlign: 'left', borderColor: 'rgba(56, 189, 248, 0.4)' }}
                  disabled={restoringBackupId !== null}
                  onClick={() => executeRestore(schemaMismatchModal.backup.id, 'compatibility_safe_import')}
                >
                  <div>
                    <div style={{ fontWeight: 700, fontSize: '0.86rem', color: '#38bdf8' }}>
                      Option 2: Compatibility Safe-Import (Strip Unknown Newer Columns &amp; Preserve Core Data)
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                      Takes a pre-restore safety snapshot first, then imports only columns recognized by Schema v{schemaMismatchModal.appSchemaVersion} without crashing.
                    </div>
                  </div>
                </button>

                <button
                  type="button"
                  className="btn-glass"
                  style={{ justifyContent: 'center' }}
                  onClick={() => setSchemaMismatchModal(null)}
                >
                  Option 3: Cancel Restore &amp; Keep Current Database Untouched
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <MfaChallengeModal
        isOpen={showBackupKeyMfa}
        onClose={() => setShowBackupKeyMfa(false)}
        onSuccess={() => {
          setShowBackupKeyMfa(false);
          handleRevealBackupKey();
        }}
        title="Step-Up MFA: Reveal Backup Encryption Key"
        description="Verify your 6-digit TOTP authenticator or single-use recovery code to view and export the Disaster Recovery Backup Encryption Passphrase."
        secretType="backup_recovery_key"
      />
    </div>
  );
};
