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
  Globe,
  Edit3,
  Activity,
  Laptop,
  HardDrive,
  BellRing,
  LogOut
} from 'lucide-react';
import {
  Settings,
  RbacUser,
  Tenant,
  MeshServer,
  SystemBackupItem,
  UpdaterStatus,
  MeshDiscoveryResult,
  LocalMeshCentralDetection,
  CustomFieldDefinition,
  MaintenanceWindow,
  CustomRole,
  ScopedApiKey,
  ActiveAuthSession,
  BackupPolicy,
  MdmProfile,
  Policy
} from '../types/index.js';
import {
  updateSettings,
  uploadBrandLogo,
  fetchPolicies,
  updatePolicy,
  uploadPolicyTrayIcon,
  testSmtp,
  syncMeshCentral,
  fetchUsers,
  createUser,
  updateUser,
  resetUserMfa,
  deleteUser,
  fetchActiveSessions,
  revokeActiveSession,
  verifyMfa,
  getLocalQrSvgUrl,
  fetchSystemHealth,
  fetchTenants,
  createTenant,
  updateTenant,
  createSite,
  offboardTenant,
  reactivateTenant,
  fetchMeshServers,
  createMeshServer,
  updateMeshServer,
  deleteMeshServer,
  testDiscoverMeshServer,
  importFromMeshServer,
  fetchLocalMeshCentralStatus,
  generateMeshCentralLoginToken,
  applyLocalMeshCentralConfig,
  fetchSystemBackups,
  createSystemBackup,
  getBackupDownloadUrl,
  uploadSystemBackup,
  restoreSystemBackup,
  deleteSystemBackup,
  syncOffsiteBackups,
  fetchOffsiteVaultObjects,
  pullOffsiteVaultObject,
  fetchUpdaterStatus,
  setUpdaterChannel,
  executeSystemUpdate,
  notifyAdminsOfUpdate,
  fetchMfaEnrollment,
  regenerateMfaRecoveryCodes,
  fetchCustomFields,
  saveCustomField,
  updateCustomField,
  deleteCustomField,
  fetchMaintenanceWindows,
  createMaintenanceWindow,
  updateMaintenanceWindow,
  deleteMaintenanceWindow,
  testOidcDiscovery,
  testCodeSigningPipeline,
  revealBackupRecoveryKey,
  acknowledgeBackupRecoveryKey,
  fetchCustomRoles,
  createCustomRole,
  updateCustomRole,
  deleteCustomRole,
  fetchScopedApiKeys,
  createScopedApiKey,
  revokeScopedApiKey,
  fetchBackupPolicies,
  createBackupPolicy,
  updateBackupPolicy,
  deleteBackupPolicy,
  fetchMdmProfiles,
  createMdmProfile,
  updateMdmProfile,
  deleteMdmProfile
} from '../services/api.js';
import { ALL_GRANULAR_PERMISSIONS } from '../utils/permissions.js';
import { copyToClipboard } from '../utils/clipboard.js';
import { sanitizeSafeUrl } from '../utils/urlSafety.js';
import { MfaChallengeModal } from '../components/MfaChallengeModal.js';
import { IconCropModal } from '../components/IconCropModal.js';

function isErrorMessage(msg?: string | null): boolean {
  if (!msg) return false;
  return /^(error|failed|unable|cannot|invalid|rejected|offsite|upload rejected|restore (blocked|error)|sync (encountered|failed)|oidc discovery failed|verification failed|update (did not|error)|must\b|enter\b|select\b|new password|missing|⚠️)/i.test(
    msg.trim()
  );
}

function formatFieldOptionsForEditor(raw?: string | null): string {
  if (!raw) return '';
  const trimmed = raw.trim();
  if (!trimmed) return '';
  if (trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed)) {
        return parsed.map((v) => String(v).trim()).filter(Boolean).join(', ');
      }
    } catch {
      // Fallback to raw text
    }
  }
  return trimmed;
}

function serializeFieldOptionsFromEditor(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return '[]';
  if (trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed)) {
        return JSON.stringify(parsed.map((v) => String(v).trim()).filter(Boolean));
      }
    } catch {
      // Treat as comma-separated list
    }
  }
  return JSON.stringify(
    trimmed
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
  );
}

interface SettingsViewProps {
  settings: Settings;
  onUpdated: (s: Settings) => void;
  onOpenWizard: () => void;
  tenants?: Tenant[];
}

function parseMeshTokenPair(raw?: string | null): {
  user: string;
  pass: string;
  isMasked: boolean;
  isCombinedOnly: boolean;
} {
  const trimmed = String(raw || '').trim();
  if (!trimmed) return { user: '', pass: '', isMasked: false, isCombinedOnly: false };
  if (/^[•*]{4,}$/.test(trimmed)) return { user: '', pass: '', isMasked: true, isCombinedOnly: false };
  if (trimmed.startsWith('~t:')) {
    const rest = trimmed.slice(3);
    const sepIdx = rest.search(/[:,\s]/);
    if (sepIdx > 0) {
      return {
        user: trimmed.slice(0, 3 + sepIdx),
        pass: rest.slice(sepIdx + 1).trim(),
        isMasked: false,
        isCombinedOnly: false
      };
    }
    return { user: trimmed, pass: '', isMasked: false, isCombinedOnly: false };
  }
  if (trimmed.includes(':') && !trimmed.startsWith('c=')) {
    const idx = trimmed.indexOf(':');
    return {
      user: trimmed.slice(0, idx),
      pass: trimmed.slice(idx + 1),
      isMasked: false,
      isCombinedOnly: false
    };
  }
  return { user: '', pass: '', isMasked: false, isCombinedOnly: true };
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  settings,
  onUpdated,
  onOpenWizard,
  tenants: propTenants
}) => {
  const [formData, setRawFormData] = useState<Settings>({ ...settings });
  const isDirtyRef = useRef(false);
  const lastSettingsSnapshotRef = useRef<string>(JSON.stringify(settings));
  const setFormData = useCallback((updater: React.SetStateAction<Settings>) => {
    isDirtyRef.current = true;
    setRawFormData(updater);
  }, []);
  const [localMesh, setLocalMesh] = useState<LocalMeshCentralDetection | null>(null);
  const initialMeshPair = parseMeshTokenPair(settings.meshcentral_api_token);
  const [meshTokenUser, setMeshTokenUser] = useState(initialMeshPair.user);
  const [meshTokenPass, setMeshTokenPass] = useState(initialMeshPair.pass);
  const [meshTokenHasSaved, setMeshTokenHasSaved] = useState(initialMeshPair.isMasked);
  const [useCombinedTokenMode, setUseCombinedTokenMode] = useState(initialMeshPair.isCombinedOnly);
  const [showAutoTokenGen, setShowAutoTokenGen] = useState(false);
  const [autoMs2User, setAutoMs2User] = useState('admin');
  const [autoMs2Pass, setAutoMs2Pass] = useState('');
  const [autoMs2Totp, setAutoMs2Totp] = useState('');
  const [autoMs2TotpRequired, setAutoMs2TotpRequired] = useState(false);
  const [generatingToken, setGeneratingToken] = useState(false);
  const [autoTokenMsg, setAutoTokenMsg] = useState<string | null>(null);
  const [autoTokenIsError, setAutoTokenIsError] = useState(false);
  const [optAllowFraming, setOptAllowFraming] = useState(true);
  const [optDisableAgentUpdate, setOptDisableAgentUpdate] = useState(false);
  const [applyingLocalCfg, setApplyingLocalCfg] = useState(false);
  const [localCfgMsg, setLocalCfgMsg] = useState<string | null>(null);
  const [localCfgIsError, setLocalCfgIsError] = useState(false);

  const [saving, setSaving] = useState(false);
  const [saveBanner, setSaveBanner] = useState<string | null>(null);
  const [saveBannerIsError, setSaveBannerIsError] = useState(false);
  const [smtpTestResult, setSmtpTestResult] = useState<string | null>(null);
  const [smtpTestSuccess, setSmtpTestSuccess] = useState(true);
  const [testingSmtp, setTestingSmtp] = useState(false);
  const [syncingMesh, setSyncingMesh] = useState(false);
  const [meshSyncResult, setMeshSyncResult] = useState<string | null>(null);

  // Logo & Backup file inputs + QuickSupport Dedicated Branding Profile
  const logoInputRef = useRef<HTMLInputElement | null>(null);
  const qsIconInputRef = useRef<HTMLInputElement | null>(null);
  const backupFileInputRef = useRef<HTMLInputElement | null>(null);
  const [cropIconRequest, setCropIconRequest] = useState<{ mode: 'global' | 'quicksupport'; file: File } | null>(null);
  const [uploadingLogo, setUploadingLogo] = useState(false);
  const [uploadingQsIcon, setUploadingQsIcon] = useState(false);
  const [savingQsProfile, setSavingQsProfile] = useState(false);
  const [qsProfileMsg, setQsProfileMsg] = useState<string | null>(null);
  const [qsProfileError, setQsProfileError] = useState(false);
  const [qsBrandName, setQsBrandName] = useState('');
  const [qsIconUrl, setQsIconUrl] = useState('');
  const [qsThemeMode, setQsThemeMode] = useState<'inherit' | 'system' | 'dark' | 'light'>('inherit');
  const [qsTooltip, setQsTooltip] = useState('');
  const [qsEnabled, setQsEnabled] = useState(true);
  const [uploadingBackup, setUploadingBackup] = useState(false);

  // RBAC Users & Tenants management state
  const [users, setUsers] = useState<RbacUser[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>(propTenants || []);
  const [newUserEmail, setNewUserEmail] = useState('');
  const [newUserName, setNewUserName] = useState('');
  const [newUserPassword, setNewUserPassword] = useState('');
  const [newUserRole, setNewUserRole] = useState<'super_admin' | 'technician' | 'client_admin' | 'auditor'>('technician');
  const [newUserCustomRoleId, setNewUserCustomRoleId] = useState('');
  const [newUserTenantId, setNewUserTenantId] = useState('');
  const [userNotice, setUserNotice] = useState<string | null>(null);
  const [editingUserId, setEditingUserId] = useState<string | null>(null);
  const [editUserRole, setEditUserRole] = useState<string>('technician');
  const [editUserCustomRoleId, setEditUserCustomRoleId] = useState<string>('');
  const [editUserTenantId, setEditUserTenantId] = useState<string>('');
  const [editUserPassword, setEditUserPassword] = useState<string>('');
  const [activeSessions, setActiveSessions] = useState<ActiveAuthSession[]>([]);
  const [currentSessionPrefix, setCurrentSessionPrefix] = useState<string | null>(null);
  const [showSessionsDrawer, setShowSessionsDrawer] = useState(false);

  // Custom RBAC Roles, Scoped API Keys, Backup Policies, MDM Profiles & Health
  const [customRoles, setCustomRoles] = useState<CustomRole[]>([]);
  const [availablePermissions, setAvailablePermissions] = useState<string[]>([]);
  const [newRoleName, setNewRoleName] = useState('');
  const [newRoleDesc, setNewRoleDesc] = useState('');
  const [newRolePerms, setNewRolePerms] = useState<string[]>(['devices:read', 'alerts:triage', 'docs:write']);
  const [roleNotice, setRoleNotice] = useState<string | null>(null);
  const [editingRoleId, setEditingRoleId] = useState<string | null>(null);
  const [editRoleName, setEditRoleName] = useState('');
  const [editRoleDesc, setEditRoleDesc] = useState('');
  const [editRoleTier, setEditRoleTier] = useState('technician');
  const [editRolePerms, setEditRolePerms] = useState<string[]>([]);

  const [editingTenantId, setEditingTenantId] = useState<string | null>(null);
  const [editTenantName, setEditTenantName] = useState('');
  const [editTenantEmail, setEditTenantEmail] = useState('');

  const [editingFieldId, setEditingFieldId] = useState<string | null>(null);
  const [editFieldLabel, setEditFieldLabel] = useState('');
  const [editFieldType, setEditFieldType] = useState<'text' | 'dropdown' | 'checkbox' | 'secret'>('text');
  const [editFieldOptions, setEditFieldOptions] = useState('');

  const [editingWinId, setEditingWinId] = useState<string | null>(null);
  const [editWinTitle, setEditWinTitle] = useState('');
  const [editWinTenantId, setEditWinTenantId] = useState('');
  const [editWinStartTime, setEditWinStartTime] = useState('');
  const [editWinEndTime, setEditWinEndTime] = useState('');

  const [editingBpId, setEditingBpId] = useState<string | null>(null);
  const [editBpName, setEditBpName] = useState('');
  const [editBpEngine, setEditBpEngine] = useState('restic');
  const [editBpRepo, setEditBpRepo] = useState('');
  const [editBpCron, setEditBpCron] = useState('0 2 * * *');
  const [editBpRetention, setEditBpRetention] = useState<number | ''>(30);

  const [editingMdmId, setEditingMdmId] = useState<string | null>(null);
  const [editMdmName, setEditMdmName] = useState('');
  const [editMdmPlatform, setEditMdmPlatform] = useState<'macos' | 'windows' | 'linux'>('macos');
  const [editMdmType, setEditMdmType] = useState('security_baseline');
  const [editMdmPayload, setEditMdmPayload] = useState('');

  const [activeSection, setActiveSection] = useState<
    'all' | 'users' | 'security' | 'branding' | 'agents' | 'policies' | 'notifications' | 'updates'
  >('users');
  const [testingSigning, setTestingSigning] = useState(false);
  const [signingTestMsg, setSigningTestMsg] = useState<string | null>(null);
  const [signingTestError, setSigningTestError] = useState(false);

  const [apiKeys, setApiKeys] = useState<ScopedApiKey[]>([]);
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyRole, setNewKeyRole] = useState<'technician' | 'auditor' | 'super_admin'>('technician');
  const [newKeyScopes, setNewKeyScopes] = useState<string[]>(['devices:read', 'alerts:triage', 'scripts:run']);
  const [newKeyTenantId, setNewKeyTenantId] = useState('');
  const [newKeyExpiresDays, setNewKeyExpiresDays] = useState(90);
  const [mintedRawApiKey, setMintedRawApiKey] = useState<string | null>(null);
  const [copiedApiKey, setCopiedApiKey] = useState(false);
  const [apiKeyNotice, setApiKeyNotice] = useState<string | null>(null);

  const [backupPolicies, setBackupPolicies] = useState<BackupPolicy[]>([]);
  const [newBpName, setNewBpName] = useState('');
  const [newBpEngine, setNewBpEngine] = useState('restic');
  const [newBpRepo, setNewBpRepo] = useState('');
  const [newBpCron, setNewBpCron] = useState('0 2 * * *');
  const [newBpRetention, setNewBpRetention] = useState<number | ''>(30);
  const [bpNotice, setBpNotice] = useState<string | null>(null);

  const [mdmProfiles, setMdmProfiles] = useState<MdmProfile[]>([]);
  const [newMdmName, setNewMdmName] = useState('');
  const [newMdmPlatform, setNewMdmPlatform] = useState<'macos' | 'windows' | 'linux'>('macos');
  const [newMdmType, setNewMdmType] = useState('security_baseline');
  const [newMdmPayload, setNewMdmPayload] = useState('');
  const [mdmNotice, setMdmNotice] = useState<string | null>(null);
  const [schemaFieldNotice, setSchemaFieldNotice] = useState<string | null>(null);

  const [systemHealth, setSystemHealth] = useState<{
    status: string;
    version: string;
    uptime: number;
    meshBridge: { connected: boolean; configured: boolean; activeTunnels: number };
  } | null>(null);
  const [pendingMfaAction, setPendingMfaAction] = useState<{
    title: string;
    secretType: string;
    onVerified: () => void;
  } | null>(null);

  const [newTenantName, setNewTenantName] = useState('');
  const [newTenantContact, setNewTenantContact] = useState('');
  const [newSiteTenantId, setNewSiteTenantId] = useState(propTenants?.[0]?.id || '');
  const [newSiteName, setNewSiteName] = useState('');
  const [newSiteSubnet, setNewSiteSubnet] = useState('');
  const [clientActionNotice, setClientActionNotice] = useState<string | null>(null);
  const [syncingOffsite, setSyncingOffsite] = useState(false);
  const [offsiteObjects, setOffsiteObjects] = useState<Array<{ key: string; sizeBytes: number; lastModified: string }> | null>(null);
  const [browsingOffsite, setBrowsingOffsite] = useState(false);

  // MFA Enrollment & Recovery Codes state
  const [mfaInfo, setMfaInfo] = useState<{
    totpEnabled: boolean;
    confirmed?: boolean;
    secretRedacted?: boolean;
    secretBase32: string | null;
    otpAuthUri: string | null;
    qrSvg?: string | null;
    remainingRecoveryCodes: number;
  } | null>(null);
  const [showMfaSecret, setShowMfaSecret] = useState(false);
  const [confirmTotpCode, setConfirmTotpCode] = useState('');
  const [regenTotpCode, setRegenTotpCode] = useState('');
  const [regeneratedCodes, setRegeneratedCodes] = useState<string[] | null>(null);
  const [mfaNotice, setMfaNotice] = useState<string | null>(null);

  // Custom Field Definitions & Maintenance Windows state
  const [customFieldDefs, setCustomFieldDefs] = useState<CustomFieldDefinition[]>([]);
  const [newFieldLabel, setNewFieldLabel] = useState('');
  const [newFieldCategory] = useState('Operations');
  const [newFieldType, setNewFieldType] = useState<'text' | 'dropdown' | 'checkbox' | 'secret'>('text');
  const [newFieldOptions, setNewFieldOptions] = useState('');

  const [maintenanceWindows, setMaintenanceWindows] = useState<MaintenanceWindow[]>([]);
  const [newWinTitle, setNewWinTitle] = useState('');
  const [newWinStartTime, setNewWinStartTime] = useState('');
  const [newWinDuration, setNewWinDuration] = useState(120);
  const [newWinTenantId, setNewWinTenantId] = useState('');

  // Multi-Instance MeshCentral 2 Federation state
  const [meshServers, setMeshServers] = useState<MeshServer[]>([]);
  const [newMeshName, setNewMeshName] = useState('');
  const [newMeshUrl, setNewMeshUrl] = useState('');
  const [newMeshToken, setNewMeshToken] = useState('');
  const [editingMeshId, setEditingMeshId] = useState<string | null>(null);
  const [editMeshName, setEditMeshName] = useState('');
  const [editMeshUrl, setEditMeshUrl] = useState('');
  const [editMeshToken, setEditMeshToken] = useState('');
  const [editMeshAutoPush, setEditMeshAutoPush] = useState(true);
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
    const nextSnapshot = JSON.stringify(settings);
    if (!isDirtyRef.current && nextSnapshot !== lastSettingsSnapshotRef.current) {
      lastSettingsSnapshotRef.current = nextSnapshot;
      setRawFormData({ ...settings });
      const parsed = parseMeshTokenPair(settings.meshcentral_api_token);
      setMeshTokenUser(parsed.user);
      setMeshTokenPass(parsed.pass);
      setMeshTokenHasSaved(parsed.isMasked);
      setUseCombinedTokenMode(parsed.isCombinedOnly);
    }
  }, [settings]);

  const loadAllAdminData = useCallback(() => {
    fetchLocalMeshCentralStatus()
      .then((info) => {
        setLocalMesh(info);
        if (info.detected) {
          if (info.allowFraming === true) setOptAllowFraming(false);
          if (info.disableAgentUpdate === true) setOptDisableAgentUpdate(false);
        }
      })
      .catch(() => {});
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
    fetchActiveSessions()
      .then((res) => {
        if (res.sessions) setActiveSessions(res.sessions);
        if (res.currentSessionPrefix !== undefined) setCurrentSessionPrefix(res.currentSessionPrefix || null);
      })
      .catch(() => {});
    fetchCustomRoles()
      .then((res) => {
        if (res.roles) setCustomRoles(res.roles);
        if (res.availablePermissions) setAvailablePermissions(res.availablePermissions);
      })
      .catch(() => {});
    fetchScopedApiKeys().then(setApiKeys).catch(() => {});
    fetchBackupPolicies().then(setBackupPolicies).catch(() => {});
    fetchMdmProfiles().then(setMdmProfiles).catch(() => {});
    fetchSystemHealth().then(setSystemHealth).catch(() => {});
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
    fetchPolicies()
      .then((list: Policy[]) => {
        const qs = list.find((p) => p.id === 'pol-quicksupport' || p.tier === 'quicksupport');
        if (qs) {
          setQsBrandName(qs.tray_brand_name || '');
          setQsIconUrl(qs.tray_icon_url || '');
          setQsThemeMode((qs.tray_theme_mode as any) || 'inherit');
          setQsTooltip(qs.tray_tooltip || '');
          setQsEnabled(qs.tray_enabled !== 0 && qs.tray_enabled !== false);
        }
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    loadAllAdminData();
  }, [loadAllAdminData]);
  const performSave = async () => {
    setSaving(true);
    const normalizedPayload: Settings = {
      ...formData,
      smtp_port: Number(formData.smtp_port) || 587,
      backup_retention_count: Math.max(1, Number(formData.backup_retention_count) || 14),
      backup_max_storage_mb: Math.max(128, Number(formData.backup_max_storage_mb) || 5120),
      session_idle_timeout_min:
        formData.session_idle_timeout_min !== undefined
          ? Math.max(5, Number(formData.session_idle_timeout_min) || 30)
          : undefined
    };
    try {
      const res = await updateSettings(normalizedPayload);
      if (res.mfaRequired) {
        setPendingMfaAction({
          title: 'Step-Up MFA: Save Global RMM Configuration',
          secretType: 'system_settings',
          onVerified: () => performSave()
        });
        return;
      }
      if (res.success) {
        isDirtyRef.current = false;
        lastSettingsSnapshotRef.current = JSON.stringify(res.settings);
        setRawFormData({ ...res.settings });
        onUpdated(res.settings);
        setSaveBannerIsError(false);
        setSaveBanner('Settings, White-Labeling, Vaulted Secrets & Compliance Policies saved successfully.');
        setTimeout(() => setSaveBanner(null), 4000);
      } else {
        setSaveBannerIsError(true);
        setSaveBanner(`Error saving settings: ${res.error || 'Unknown error'}`);
      }
    } catch (err: any) {
      setSaveBannerIsError(true);
      setSaveBanner(`Error saving settings: ${err?.message || 'Unknown error'}`);
    } finally {
      setSaving(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (formData.brand_logo_url && !sanitizeSafeUrl(formData.brand_logo_url)) {
      setSaveBannerIsError(true);
      setSaveBanner('Error: Brand logo URL must start with https://, http://, or a relative /path.');
      return;
    }
    const qsPath = String(formData.quicksupport_url_path || '').trim();
    if (qsPath && (!qsPath.startsWith('/') || qsPath.startsWith('//'))) {
      setSaveBannerIsError(true);
      setSaveBanner('Error: QuickSupport URL Path must be a valid single-slash route such as /remote.');
      return;
    }
    const smtpPortVal = formData.smtp_port;
    if (smtpPortVal !== undefined && String(smtpPortVal) !== '') {
      const p = Number(smtpPortVal);
      if (!Number.isInteger(p) || p < 1 || p > 65535) {
        setSaveBannerIsError(true);
        setSaveBanner('Error: Outbound SMTP Port must be between 1 and 65535.');
        return;
      }
    }
    const smtpFrom = String(formData.smtp_from || '').trim();
    if (smtpFrom && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(smtpFrom)) {
      setSaveBannerIsError(true);
      setSaveBanner('Error: Outbound SMTP From Address must be a valid email address.');
      return;
    }
    const retCount = formData.backup_retention_count;
    if (retCount !== undefined && String(retCount) !== '' && Number(retCount) < 1) {
      setSaveBannerIsError(true);
      setSaveBanner('Error: Backup Retention Count must be at least 1.');
      return;
    }
    const quotaMb = formData.backup_max_storage_mb;
    if (quotaMb !== undefined && String(quotaMb) !== '' && Number(quotaMb) < 128) {
      setSaveBannerIsError(true);
      setSaveBanner('Error: Local Backup Storage Quota must be at least 128 MB.');
      return;
    }
    await performSave();
  };

  const handleLogoFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (logoInputRef.current) logoInputRef.current.value = '';
    if (!file) return;
    setCropIconRequest({ mode: 'global', file });
  };

  const handleQsIconFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (qsIconInputRef.current) qsIconInputRef.current.value = '';
    if (!file) return;
    setCropIconRequest({ mode: 'quicksupport', file });
  };

  const handleCropModalConfirm = async (cropped: { filename: string; base64Data: string }) => {
    const targetMode = cropIconRequest?.mode;
    setCropIconRequest(null);
    if (!targetMode) return;

    if (targetMode === 'quicksupport') {
      setUploadingQsIcon(true);
      setQsProfileMsg(null);
      setQsProfileError(false);
      try {
        const res = await uploadPolicyTrayIcon('pol-quicksupport', cropped.filename, cropped.base64Data);
        if (res.success && res.tray_icon_url) {
          setQsIconUrl(res.tray_icon_url);
          setQsProfileMsg('Square QuickSupport icon uploaded & ready for QuickSupport EXEs and Portal.');
        } else {
          setQsProfileError(true);
          setQsProfileMsg(res.error || 'Failed to upload QuickSupport icon.');
        }
      } catch (err: any) {
        setQsProfileError(true);
        setQsProfileMsg(err?.message || 'Failed to upload QuickSupport icon.');
      } finally {
        setUploadingQsIcon(false);
      }
      return;
    }

    setUploadingLogo(true);
    try {
      const res = await uploadBrandLogo(cropped.filename, cropped.base64Data);
      if (res.success && res.brand_logo_url) {
        const next = { ...formData, brand_logo_url: res.brand_logo_url };
        setFormData(next);
        onUpdated(next);
        setSaveBannerIsError(false);
        setSaveBanner(`Square brand icon "${cropped.filename}" saved for Web UI, installers & tray defaults.`);
        setTimeout(() => setSaveBanner(null), 4000);
      } else {
        setSaveBannerIsError(true);
        setSaveBanner(`Logo upload rejected: ${res.error || 'Unsupported image format'}`);
      }
    } catch (err: any) {
      setSaveBannerIsError(true);
      setSaveBanner(`Logo upload rejected: ${err?.message || 'Unsupported image format'}`);
    } finally {
      setUploadingLogo(false);
    }
  };

  const handleSaveQsProfile = async () => {
    setSavingQsProfile(true);
    setQsProfileMsg(null);
    setQsProfileError(false);
    try {
      const res = await updatePolicy('pol-quicksupport', {
        name: 'QuickSupport On-Demand Profile',
        tray_brand_name: qsBrandName,
        tray_icon_url: qsIconUrl,
        tray_theme_mode: (qsThemeMode === 'inherit' ? '' : qsThemeMode) as any,
        tray_tooltip: qsTooltip,
        tray_enabled: qsEnabled ? 1 : 0
      });
      if (res.mfaRequired) {
        setPendingMfaAction({
          title: 'Step-Up MFA: Save QuickSupport Branding Profile',
          secretType: 'policy_governance',
          onVerified: () => handleSaveQsProfile()
        });
        return;
      }
      if (res.success) {
        setQsProfileMsg('QuickSupport branding & icon profile saved.');
      } else {
        setQsProfileError(true);
        setQsProfileMsg(res.error || 'Failed to save QuickSupport profile.');
      }
    } catch (err: any) {
      setQsProfileError(true);
      setQsProfileMsg(err?.message || 'Failed to save QuickSupport profile.');
    } finally {
      setSavingQsProfile(false);
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
    setSmtpTestResult(null);
    try {
      const res = await testSmtp({
        host: formData.smtp_host,
        port: formData.smtp_port,
        user: formData.smtp_user,
        pass: formData.smtp_pass,
        from: formData.smtp_from
      });
      setSmtpTestSuccess(Boolean(res.success));
      setSmtpTestResult(res.message || (res.success ? 'SMTP test succeeded.' : 'Failed to test SMTP relay.'));
    } catch (err: any) {
      setSmtpTestSuccess(false);
      setSmtpTestResult(`Failed to test SMTP relay: ${err?.message || 'Connection error'}`);
    } finally {
      setTestingSmtp(false);
    }
  };

  const handleRevealBackupKey = async () => {
    setBackupNotice(null);
    try {
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
      } else {
        setBackupNotice(`Unable to reveal recovery key: ${res.error || 'Unknown error'}`);
      }
    } catch (err: any) {
      setBackupNotice(`Unable to reveal recovery key: ${err?.message || 'Connection error'}`);
    }
  };

  const handleAcknowledgeBackupKey = async () => {
    setBackupNotice(null);
    try {
      const res = await acknowledgeBackupRecoveryKey();
      if (res.success) {
        const next = { ...formData, backup_key_acknowledged: 1 };
        setFormData(next);
        onUpdated(next);
        setBackupNotice('✓ Backup Encryption Passphrase marked as escrowed offline.');
      } else if (res.error) {
        setBackupNotice(`Unable to mark recovery key escrowed: ${res.error}`);
      }
    } catch (err: any) {
      setBackupNotice(`Unable to mark recovery key escrowed: ${err?.message || 'Connection error'}`);
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

  const handleTestSigningSettings = async () => {
    setTestingSigning(true);
    setSigningTestMsg(null);
    setSigningTestError(false);
    try {
      const res = await testCodeSigningPipeline(formData.code_signing_url);
      if (res.success) {
        setSigningTestError(false);
        setSigningTestMsg(`✓ Verified Signing Endpoint (${res.hsmStatus || 'Ready'}) • ${res.ms2AutoUpdateProtection || 'Connected'}`);
      } else {
        setSigningTestError(true);
        setSigningTestMsg(`Signing check failed: ${res.error || res.hsmStatus || 'Unreachable'}`);
      }
    } catch (err: any) {
      setSigningTestError(true);
      setSigningTestMsg(`Signing check failed: ${err?.message || 'Unreachable'}`);
    } finally {
      setTestingSigning(false);
    }
  };

  const handleAddUser = async () => {
    setUserNotice(null);
    if (!newUserEmail.trim() || !newUserName.trim()) {
      setUserNotice('Error: Name and email address are required.');
      return;
    }
    if (newUserPassword.length < 10) {
      setUserNotice('Error: Initial password must be at least 10 characters.');
      return;
    }
    try {
      const res = await createUser({
        username: newUserName.trim(),
        email: newUserEmail.trim(),
        password: newUserPassword,
        role: newUserRole,
        custom_role_id: newUserCustomRoleId || null,
        tenant_id: newUserRole === 'client_admin' ? newUserTenantId || null : null
      });
      if (res.mfaRequired) {
        setPendingMfaAction({
          title: 'Step-Up MFA: Provision RBAC Account',
          secretType: 'rbac_user_create',
          onVerified: () => handleAddUser()
        });
        return;
      }
      if (res.success) {
        setNewUserEmail('');
        setNewUserName('');
        setNewUserPassword('');
        setNewUserCustomRoleId('');
        setUserNotice(
          res.recoveryCodes?.length
            ? `✓ Created ${res.user?.email} (${res.user?.role}). Initial MFA Recovery Codes: ${res.recoveryCodes.join(', ')}`
            : `✓ Created ${res.user?.email} (${res.user?.role}).`
        );
        loadAllAdminData();
      } else {
        setUserNotice(`Failed to create user: ${res.error || 'Unknown error'}`);
      }
    } catch (err: any) {
      setUserNotice(`Failed to create user: ${err?.message || 'Unknown error'}`);
    }
  };

  const handleSaveEditUser = async (userId: string) => {
    setUserNotice(null);
    const payload: {
      role?: string;
      custom_role_id?: string | null;
      tenant_id?: string | null;
      password?: string;
    } = {
      role: editUserRole,
      custom_role_id: editUserCustomRoleId || null,
      tenant_id: editUserRole === 'client_admin' ? editUserTenantId || null : null
    };
    if (editUserPassword.trim()) {
      if (editUserPassword.trim().length < 10) {
        setUserNotice('New password must be at least 10 characters.');
        return;
      }
      payload.password = editUserPassword.trim();
    }
    const res = await updateUser(userId, payload);
    if (res.mfaRequired) {
      setPendingMfaAction({
        title: 'Step-Up MFA: Modify RBAC User Account',
        secretType: 'rbac_user_update',
        onVerified: () => handleSaveEditUser(userId)
      });
      return;
    }
    if (res.success) {
      setEditingUserId(null);
      setEditUserPassword('');
      setUserNotice(`✓ Updated account role & permissions for ${res.user?.email || userId}.`);
      loadAllAdminData();
    } else {
      setUserNotice(`Failed to update user: ${res.error || 'Unknown error'}`);
    }
  };

  const handleResetUserMfa = async (userId: string, username: string) => {
    const res = await resetUserMfa(userId);
    if (res.mfaRequired) {
      setPendingMfaAction({
        title: `Step-Up MFA: Reset Authenticator for ${username}`,
        secretType: 'rbac_reset_mfa',
        onVerified: () => handleResetUserMfa(userId, username)
      });
      return;
    }
    if (res.success) {
      setUserNotice(
        `✓ Reset TOTP MFA for ${username}. New Secret: ${res.totpSecret || 'provisioned'} • Recovery Codes: ${(res.recoveryCodes || []).join(', ')}`
      );
      loadAllAdminData();
    } else {
      setUserNotice(`Failed to reset MFA: ${res.error || 'Unknown error'}`);
    }
  };

  const handleDeleteUser = async (id: string) => {
    if (!confirm('Permanently delete this user account?')) return;
    setUserNotice(null);
    try {
      const res = await deleteUser(id);
      if (!res.success && res.error) {
        setUserNotice(`Cannot delete user: ${res.error}`);
        return;
      }
      setUserNotice('✓ User account removed.');
      loadAllAdminData();
    } catch (err: any) {
      setUserNotice(`Cannot delete user: ${err?.message || 'Unknown error'}`);
    }
  };

  const handleCreateCustomRole = async () => {
    setRoleNotice(null);
    const validCatalog =
      availablePermissions.filter((p) => p.includes(':')).length > 0
        ? availablePermissions.filter((p) => p.includes(':'))
        : [...ALL_GRANULAR_PERMISSIONS];
    const validSelectedPerms = newRolePerms.filter(
      (p) => p.includes(':') && (validCatalog.includes(p) || (ALL_GRANULAR_PERMISSIONS as readonly string[]).includes(p))
    );
    if (!newRoleName.trim() || validSelectedPerms.length === 0) {
      setRoleNotice('Error: Role name and at least one granular colon permission are required.');
      return;
    }
    try {
      const res = await createCustomRole({
        name: newRoleName.trim(),
        description: newRoleDesc.trim(),
        permissions: validSelectedPerms
      });
      if (res.success) {
        setNewRoleName('');
        setNewRoleDesc('');
        setRoleNotice(`✓ Custom RBAC Role "${res.role?.name}" created.`);
        loadAllAdminData();
      } else {
        setRoleNotice(`Failed to create role: ${res.error || 'Unknown error'}`);
      }
    } catch (err: any) {
      setRoleNotice(`Failed to create role: ${err?.message || 'Unknown error'}`);
    }
  };

  const handleSaveEditRole = async (role: CustomRole) => {
    setRoleNotice(null);
    if (!editRoleName.trim()) {
      setRoleNotice('Error: Role name is required.');
      return;
    }
    const isProtectedSuper = role.id === 'role-super-admin' || role.id === 'role-msp-super-admin';
    try {
      const res = await updateCustomRole(role.id, {
        name: editRoleName.trim(),
        description: editRoleDesc.trim(),
        ...(isProtectedSuper ? {} : { base_tier: editRoleTier, permissions: editRolePerms })
      });
      if (res.mfaRequired) {
        setPendingMfaAction({
          title: `Step-Up MFA: Update Role "${role.name}"`,
          secretType: 'rbac_role_update',
          onVerified: () => handleSaveEditRole(role)
        });
        return;
      }
      if (res.success) {
        setEditingRoleId(null);
        setRoleNotice(res.note ? `✓ ${res.note}` : `✓ Updated role "${res.role?.name || editRoleName.trim()}".`);
        loadAllAdminData();
      } else {
        setRoleNotice(`Failed to update role: ${res.error || 'Unknown error'}`);
      }
    } catch (err: any) {
      setRoleNotice(`Failed to update role: ${err?.message || 'Unknown error'}`);
    }
  };

  const handleSaveEditTenant = async (tenantId: string) => {
    setClientActionNotice(null);
    if (!editTenantName.trim()) {
      setClientActionNotice('Error: Client organization name is required.');
      return;
    }
    const res = await updateTenant(tenantId, {
      name: editTenantName.trim(),
      contact_email: editTenantEmail.trim()
    });
    if (res.success) {
      setEditingTenantId(null);
      setClientActionNotice(`✓ Updated client "${editTenantName.trim()}".`);
      loadAllAdminData();
    } else {
      setClientActionNotice(`Failed to update client: ${res.error || 'Unknown error'}`);
    }
  };

  const handleSaveEditField = async (fieldId: string) => {
    setSchemaFieldNotice(null);
    if (!editFieldLabel.trim()) {
      setSchemaFieldNotice('Error: Attribute label is required.');
      return;
    }
    const res = await updateCustomField(fieldId, {
      label: editFieldLabel.trim(),
      field_type: editFieldType,
      options: editFieldType === 'dropdown' ? serializeFieldOptionsFromEditor(editFieldOptions) : null
    });
    if (res.success) {
      setEditingFieldId(null);
      setSchemaFieldNotice(`✓ Updated custom attribute "${editFieldLabel.trim()}".`);
      fetchCustomFields().then(setCustomFieldDefs).catch(() => {});
    } else {
      setSchemaFieldNotice(`Failed to update attribute: ${res.error || 'Unknown error'}`);
    }
  };

  const handleSaveEditWindow = async (winId: string) => {
    setSchemaFieldNotice(null);
    if (!editWinTitle.trim()) {
      setSchemaFieldNotice('Error: Maintenance window title is required.');
      return;
    }
    const res = await updateMaintenanceWindow(winId, {
      title: editWinTitle.trim(),
      tenant_id: editWinTenantId || null,
      ...(editWinStartTime ? { start_time: new Date(editWinStartTime).toISOString() } : {}),
      ...(editWinEndTime ? { end_time: new Date(editWinEndTime).toISOString() } : {})
    });
    if (res.success) {
      setEditingWinId(null);
      setSchemaFieldNotice(`✓ Updated maintenance window "${editWinTitle.trim()}".`);
      fetchMaintenanceWindows().then(setMaintenanceWindows).catch(() => {});
    } else {
      setSchemaFieldNotice(`Failed to update maintenance window: ${res.error || 'Unknown error'}`);
    }
  };

  const handleSaveEditBackupPolicy = async (bpId: string) => {
    setBpNotice(null);
    if (!editBpName.trim() || !editBpRepo.trim()) {
      setBpNotice('Error: Policy name and repository target are required.');
      return;
    }
    const res = await updateBackupPolicy(bpId, {
      name: editBpName.trim(),
      engine: editBpEngine,
      repository_url: editBpRepo.trim(),
      schedule_cron: editBpCron.trim() || '0 2 * * *',
      retention_days: Math.max(1, Number(editBpRetention) || 30)
    });
    if (res.success) {
      setEditingBpId(null);
      setBpNotice(`✓ Updated backup policy "${editBpName.trim()}".`);
      loadAllAdminData();
    } else {
      setBpNotice(`Failed to update backup policy: ${res.error || 'Unknown error'}`);
    }
  };

  const handleSaveEditMdmProfile = async (mpId: string) => {
    setMdmNotice(null);
    if (!editMdmName.trim()) {
      setMdmNotice('Error: Profile name is required.');
      return;
    }
    const res = await updateMdmProfile(mpId, {
      name: editMdmName.trim(),
      platform: editMdmPlatform,
      profile_type: editMdmType,
      payload_xml: editMdmPayload
    });
    if (res.success) {
      setEditingMdmId(null);
      setMdmNotice(`✓ Updated MDM profile "${editMdmName.trim()}".`);
      loadAllAdminData();
    } else {
      setMdmNotice(`Failed to update MDM profile: ${res.error || 'Unknown error'}`);
    }
  };

  const handleMintScopedApiKey = async () => {
    setApiKeyNotice(null);
    const validScopes = newKeyScopes.filter((s) =>
      (ALL_GRANULAR_PERMISSIONS as readonly string[]).includes(s)
    );
    if (!newKeyName.trim() || validScopes.length === 0) {
      setApiKeyNotice('Error: API Key label and at least one permission scope are required.');
      return;
    }
    try {
      const res = await createScopedApiKey({
        name: newKeyName.trim(),
        role: newKeyRole,
        scopes: validScopes,
        tenant_id: newKeyTenantId || null,
        expiresInDays: newKeyExpiresDays > 0 ? newKeyExpiresDays : null
      });
      if (res.mfaRequired) {
        setPendingMfaAction({
          title: 'Step-Up MFA: Mint Scoped Public REST API Key',
          secretType: 'mint_api_key',
          onVerified: () => handleMintScopedApiKey()
        });
        return;
      }
      if (res.success && res.rawKey) {
        setMintedRawApiKey(res.rawKey);
        setNewKeyName('');
        setApiKeyNotice('✓ Scoped REST API Key minted. Copy it now — the raw token is never stored or shown again.');
        loadAllAdminData();
      } else {
        setApiKeyNotice(`Failed to mint API key: ${res.error || 'Unknown error'}`);
      }
    } catch (err: any) {
      setApiKeyNotice(`Failed to mint API key: ${err?.message || 'Unknown error'}`);
    }
  };

  const handleCreateBackupPolicy = async () => {
    setBpNotice(null);
    if (!newBpName.trim() || !newBpRepo.trim()) {
      setBpNotice('Error: Policy name and repository URL are required.');
      return;
    }
    try {
      const res = await createBackupPolicy({
        name: newBpName.trim(),
        engine: newBpEngine,
        repository_url: newBpRepo.trim(),
        schedule_cron: newBpCron.trim() || '0 2 * * *',
        retention_days: Math.max(1, Number(newBpRetention) || 30)
      });
      if (res.success) {
        setNewBpName('');
        setNewBpRepo('');
        setBpNotice('✓ Endpoint backup vault policy created.');
        loadAllAdminData();
      } else {
        setBpNotice(`Failed to create backup policy: ${(res as any).error || 'Unknown error'}`);
      }
    } catch (err: any) {
      setBpNotice(`Failed to create backup policy: ${err?.message || 'Unknown error'}`);
    }
  };

  const handleCreateMdmProfile = async () => {
    setMdmNotice(null);
    if (!newMdmName.trim()) {
      setMdmNotice('Error: MDM profile name is required.');
      return;
    }
    try {
      const res = await createMdmProfile({
        name: newMdmName.trim(),
        platform: newMdmPlatform,
        profile_type: newMdmType,
        payload_xml: newMdmPayload.trim() || undefined
      });
      if (res.success) {
        setNewMdmName('');
        setNewMdmPayload('');
        setMdmNotice('✓ MDM configuration profile created.');
        loadAllAdminData();
      } else {
        setMdmNotice(`Failed to create MDM profile: ${(res as any).error || 'Unknown error'}`);
      }
    } catch (err: any) {
      setMdmNotice(`Failed to create MDM profile: ${err?.message || 'Unknown error'}`);
    }
  };

  const handleSaveMeshServerEdit = async (id: string) => {
    setMeshSyncResult(null);
    try {
      const res = await updateMeshServer(id, {
        name: editMeshName.trim(),
        url: editMeshUrl.trim(),
        api_token: editMeshToken.trim() || undefined,
        auto_push_companion: editMeshAutoPush ? 1 : 0
      });
      if (res && (res as any).success === false) {
        setMeshSyncResult(`Failed to update MS2 instance: ${(res as any).error || 'Unknown error'}`);
        return;
      }
      setEditingMeshId(null);
      setEditMeshToken('');
      setMeshSyncResult('✓ Updated federated MeshCentral 2 instance configuration.');
      loadAllAdminData();
    } catch (err: any) {
      setMeshSyncResult(`Failed to update MS2 instance: ${err?.message || 'Unknown error'}`);
    }
  };

  const handleBrowseOffsiteVault = async () => {
    setBrowsingOffsite(true);
    setBackupNotice(null);
    try {
      const res = await fetchOffsiteVaultObjects();
      if (res.success) {
        setOffsiteObjects(res.objects || []);
      } else {
        setBackupNotice(`Offsite browse failed: ${res.error || 'Verify S3/SMB vault settings'}`);
      }
    } finally {
      setBrowsingOffsite(false);
    }
  };

  const handlePullOffsiteObject = async (key: string) => {
    setBackupNotice(null);
    const res = await pullOffsiteVaultObject(
      key,
      formData.backup_encryption_passphrase && !formData.backup_encryption_passphrase.includes('••••')
        ? formData.backup_encryption_passphrase
        : undefined
    );
    if (res.success) {
      setBackupNotice(`✓ Pulled "${key}" from Offsite Vault and registered in local restore table.`);
      loadAllAdminData();
    } else {
      setBackupNotice(`Failed to pull offsite archive: ${res.error || 'Unknown error'}`);
    }
  };

  const handleAddTenant = async () => {
    setClientActionNotice(null);
    if (!newTenantName.trim()) {
      setClientActionNotice('Error: Client organization name is required.');
      return;
    }
    try {
      const res = await createTenant({
        name: newTenantName.trim(),
        contact_email: newTenantContact.trim()
      });
      if (res && (res as any).success === false) {
        setClientActionNotice(`Failed to create client: ${(res as any).error || 'Unknown error'}`);
        return;
      }
      setNewTenantName('');
      setNewTenantContact('');
      setClientActionNotice('✓ Client organization created.');
      loadAllAdminData();
    } catch (err: any) {
      setClientActionNotice(`Failed to create client: ${err?.message || 'Unknown error'}`);
    }
  };

  const handleAddSite = async () => {
    setClientActionNotice(null);
    if (!newSiteName.trim() || !newSiteTenantId) {
      setClientActionNotice('Error: Select a client organization and enter a site name.');
      return;
    }
    try {
      const res = await createSite({
        tenant_id: newSiteTenantId,
        name: newSiteName.trim(),
        subnet: newSiteSubnet.trim()
      });
      if (res && (res as any).success === false) {
        setClientActionNotice(`Failed to create site: ${(res as any).error || 'Unknown error'}`);
        return;
      }
      setNewSiteName('');
      setNewSiteSubnet('');
      setClientActionNotice('✓ Branch site created.');
      loadAllAdminData();
    } catch (err: any) {
      setClientActionNotice(`Failed to create site: ${err?.message || 'Unknown error'}`);
    }
  };

  const handleAddMeshServer = async () => {
    setMeshSyncResult(null);
    if (!newMeshName.trim() || !newMeshUrl.trim()) {
      setMeshSyncResult('Error: Instance label and MeshCentral URL are required.');
      return;
    }
    try {
      const res = await createMeshServer({
        name: newMeshName.trim(),
        url: newMeshUrl.trim(),
        api_token: newMeshToken.trim(),
        auto_push_companion: 1
      });
      if (res && (res as any).success === false) {
        setMeshSyncResult(`Failed to add MS2 instance: ${(res as any).error || 'Unknown error'}`);
        return;
      }
      setNewMeshName('');
      setNewMeshUrl('');
      setNewMeshToken('');
      setMeshSyncResult('✓ Federated MeshCentral 2 instance registered.');
      loadAllAdminData();
    } catch (err: any) {
      setMeshSyncResult(`Failed to add MS2 instance: ${err?.message || 'Unknown error'}`);
    }
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

  const syncTwoFieldMeshToken = (nextUser: string, nextPass: string) => {
    const trimmedUser = nextUser.trim();
    if (trimmedUser && nextPass) {
      setFormData((prev) => ({ ...prev, meshcentral_api_token: `${trimmedUser}:${nextPass}` }));
    } else if (!trimmedUser && !nextPass && meshTokenHasSaved) {
      setFormData((prev) => ({ ...prev, meshcentral_api_token: settings.meshcentral_api_token }));
    } else {
      setFormData((prev) => ({ ...prev, meshcentral_api_token: '' }));
    }
  };

  const handleAutoGenerateMeshToken = async () => {
    const targetUrl = String(formData.meshcentral_url || localMesh?.detectedUrl || '').trim();
    if (!targetUrl || !autoMs2User.trim() || !autoMs2Pass) {
      setAutoTokenIsError(true);
      setAutoTokenMsg('Enter MeshCentral Server URL, admin username, and password.');
      return;
    }
    setGeneratingToken(true);
    setAutoTokenMsg(null);
    setAutoTokenIsError(false);
    try {
      const res = await generateMeshCentralLoginToken({
        url: targetUrl,
        username: autoMs2User.trim(),
        password: autoMs2Pass,
        totp: autoMs2Totp.trim() || undefined,
        tokenName: 'Vitrine RMM',
        allowSelfSigned: Boolean(formData.meshcentral_allow_self_signed)
      });
      if (!res.success || !res.tokenUser || !res.tokenPass) {
        setAutoTokenIsError(true);
        setAutoTokenMsg(res.error || 'Unable to generate MeshCentral Login Token.');
        if (res.totpRequired) setAutoMs2TotpRequired(true);
        return;
      }
      setUseCombinedTokenMode(false);
      setMeshTokenUser(res.tokenUser);
      setMeshTokenPass(res.tokenPass);
      const combined = res.combinedToken || `${res.tokenUser}:${res.tokenPass}`;
      setFormData((prev) => ({
        ...prev,
        meshcentral_url: prev.meshcentral_url || targetUrl,
        meshcentral_api_token: combined
      }));
      setAutoMs2Pass('');
      setAutoMs2Totp('');
      setAutoMs2TotpRequired(false);
      setAutoTokenIsError(false);
      setAutoTokenMsg('✓ Generated persistent Login Token and populated fields above. Click "Save All Settings" (top/bottom) to store it in the vault.');
    } catch (err: any) {
      setAutoTokenIsError(true);
      setAutoTokenMsg(err?.message || 'Failed to generate MeshCentral Login Token.');
    } finally {
      setGeneratingToken(false);
    }
  };

  const handleApplyLocalMeshConfig = async () => {
    setApplyingLocalCfg(true);
    setLocalCfgMsg(null);
    setLocalCfgIsError(false);
    try {
      const res = await applyLocalMeshCentralConfig({
        allowFraming: optAllowFraming,
        disableAgentUpdate: optDisableAgentUpdate
      });
      if (res.mfaRequired) {
        setPendingMfaAction({
          title: 'Step-Up MFA: Update Local MeshCentral config.json',
          secretType: 'system_settings',
          onVerified: () => handleApplyLocalMeshConfig()
        });
        return;
      }
      if (!res.success) {
        setLocalCfgIsError(true);
        setLocalCfgMsg(res.error || 'Failed to update local config.json.');
        return;
      }
      setLocalCfgIsError(false);
      setLocalCfgMsg(`✓ Updated ${res.configPath} (backup: ${res.backupPath}). ${res.restartHint || ''}`);
      fetchLocalMeshCentralStatus().then(setLocalMesh).catch(() => {});
    } catch (err: any) {
      setLocalCfgIsError(true);
      setLocalCfgMsg(err?.message || 'Failed to update local config.json.');
    } finally {
      setApplyingLocalCfg(false);
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
      const customPassphrase =
        formData.backup_encryption_passphrase &&
        formData.backup_encryption_passphrase.trim() !== '' &&
        formData.backup_encryption_passphrase !== '••••••••••••' &&
        !formData.backup_encryption_passphrase.includes('••••')
          ? formData.backup_encryption_passphrase
          : undefined;
      const res = await restoreSystemBackup(backupId, resolutionOption, customPassphrase);
      if (res.mfaRequired) {
        setPendingMfaAction({
          title: 'Step-Up MFA: Full System Backup Restoration',
          secretType: 'system_backup_restore',
          onVerified: () => executeRestore(backupId, resolutionOption)
        });
        return;
      }
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

  const handleNotifyAdminsOfUpdate = async () => {
    setUpdaterNotice(null);
    const res = await notifyAdminsOfUpdate();
    if (res.success) {
      setUpdaterNotice(
        `✓ Dispatched update alert for ${res.targetLabel} (WebUI: ${res.notifCreated ? 'Sent' : 'Skipped'}, Email: ${res.emailDispatched ? 'Sent' : 'Skipped'}, PSA Ticket: ${res.ticketCreated || 'None'}).`
      );
    }
  };

  const handleConfirmMfaEnrollment = async () => {
    if (!confirmTotpCode.trim()) return;
    setMfaNotice(null);
    const res = await verifyMfa(confirmTotpCode.trim(), 'mfa_enrollment_confirm');
    if (res.success) {
      setConfirmTotpCode('');
      setShowMfaSecret(false);
      setMfaNotice('✓ Authenticator verified & locked! Plaintext TOTP secret is now permanently redacted.');
      fetchMfaEnrollment().then(setMfaInfo).catch(() => {});
    } else {
      setMfaNotice(`Verification failed: ${res.error || 'Invalid 6-digit TOTP code'}`);
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
    setSchemaFieldNotice(null);
    if (!newFieldLabel.trim()) {
      setSchemaFieldNotice('Error: Custom field label is required.');
      return;
    }
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
    try {
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
        setSchemaFieldNotice('✓ Custom attribute definition saved.');
        fetchCustomFields().then(setCustomFieldDefs).catch(() => {});
      } else {
        setSchemaFieldNotice(`Failed to save custom field: ${(res as any).error || 'Unknown error'}`);
      }
    } catch (err: any) {
      setSchemaFieldNotice(`Failed to save custom field: ${err?.message || 'Unknown error'}`);
    }
  };

  const handleAddMaintenanceWindow = async () => {
    setSchemaFieldNotice(null);
    if (!newWinTitle.trim()) {
      setSchemaFieldNotice('Error: Maintenance window title is required.');
      return;
    }
    const baseStart = newWinStartTime ? new Date(newWinStartTime) : new Date();
    const validStart = Number.isNaN(baseStart.getTime()) ? new Date() : baseStart;
    const end = new Date(validStart.getTime() + newWinDuration * 60 * 1000);
    try {
      const res = await createMaintenanceWindow({
        title: newWinTitle.trim(),
        tenant_id: newWinTenantId || null,
        start_time: validStart.toISOString(),
        end_time: end.toISOString(),
        suppress_alerts: 1,
        durationMinutes: newWinDuration
      });
      if (res.success) {
        setNewWinTitle('');
        setNewWinStartTime('');
        setSchemaFieldNotice('✓ Maintenance window scheduled.');
        fetchMaintenanceWindows().then(setMaintenanceWindows).catch(() => {});
      } else {
        setSchemaFieldNotice(`Failed to create maintenance window: ${(res as any).error || 'Unknown error'}`);
      }
    } catch (err: any) {
      setSchemaFieldNotice(`Failed to create maintenance window: ${err?.message || 'Unknown error'}`);
    }
  };
  const showSection = (key: typeof activeSection) => activeSection === 'all' || activeSection === key;

  const renderSectionHeader = (
    sectionKey: Exclude<typeof activeSection, 'all'>,
    title: string,
    subtitle: string,
    accentColor = 'var(--primary)'
  ) =>
    showSection(sectionKey) ? (
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '1rem',
          paddingTop: '1.15rem',
          paddingBottom: '0.35rem',
          borderTop: '1px solid rgba(148, 163, 184, 0.2)',
          marginTop: '0.4rem'
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem' }}>
            <span
              style={{
                width: '4px',
                height: '18px',
                borderRadius: '4px',
                background: accentColor,
                display: 'inline-block'
              }}
            />
            <h3 style={{ margin: 0, fontSize: '1.08rem', fontWeight: 700, letterSpacing: '0.01em' }}>
              {title}
            </h3>
          </div>
          <p style={{ margin: '0.2rem 0 0 0.95rem', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            {subtitle}
          </p>
        </div>
      </div>
    ) : null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.35rem' }} id="settings-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>
            System Settings &amp; Administration
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Organize users, built-in &amp; custom roles, white-labeling, remote engine links, code signing, SSO, and backups
          </span>
        </div>
        <button className="btn-glass btn-primary" onClick={onOpenWizard}>
          Launch Setup Wizard
        </button>
      </div>

      {/* Section Navigation Pills */}
      <div
        className="glass-card"
        style={{
          padding: '0.65rem 0.85rem',
          display: 'flex',
          flexWrap: 'wrap',
          gap: '0.45rem',
          alignItems: 'center',
          position: 'sticky',
          top: 'calc(var(--topbar-height) + 0.5rem)',
          zIndex: 15
        }}
      >
        {(
          [
            { id: 'users', label: 'Users, Clients & Roles' },
            { id: 'branding', label: 'Branding & Portal' },
            { id: 'agents', label: 'Code Signing & Remote Engine' },
            { id: 'security', label: 'MFA & API Keys' },
            { id: 'policies', label: 'Fields, Backup Policies & MDM' },
            { id: 'notifications', label: 'SSO, PSA & SMTP' },
            { id: 'updates', label: 'Updates & System Backups' },
            { id: 'all', label: 'All Sections' }
          ] as const
        ).map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={`btn-glass ${activeSection === tab.id ? 'btn-primary' : ''}`}
            style={{ padding: '0.35rem 0.78rem', fontSize: '0.76rem', fontWeight: activeSection === tab.id ? 700 : 500 }}
            onClick={() => setActiveSection(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {saveBanner && (
        <div
          className="glass-card"
          style={{
            padding: '0.85rem 1.25rem',
            background:
              saveBannerIsError || isErrorMessage(saveBanner)
                ? 'rgba(239, 68, 68, 0.14)'
                : 'rgba(16, 185, 129, 0.12)',
            borderColor:
              saveBannerIsError || isErrorMessage(saveBanner)
                ? 'rgba(239, 68, 68, 0.35)'
                : 'rgba(16, 185, 129, 0.35)',
            color: saveBannerIsError || isErrorMessage(saveBanner) ? '#f87171' : '#34d399',
            fontSize: '0.85rem',
            fontWeight: 500
          }}
        >
          {saveBannerIsError || isErrorMessage(saveBanner) ? '⚠ ' : '✓ '}
          {saveBanner}
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

      {renderSectionHeader(
        'users',
        '1. Users, Client Organizations & Role Permissions',
        'Create and edit administrator/technician accounts, customize built-in or custom role permissions, and manage client organizations.',
        'var(--primary)'
      )}

      {/* RBAC Technician Management & Client Tenants */}
      {showSection('users') && (
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(460px, 1fr))', gap: '1.5rem' }}>
        {/* RBAC Technicians */}
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <Users size={20} color="var(--primary)" />
              <div>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 600, margin: 0 }}>Role-Based Access Control (RBAC)</h3>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Manage Super Admins, Technicians, Auditors &amp; Custom Roles</span>
              </div>
            </div>
            <button
              type="button"
              className="btn-glass"
              style={{ fontSize: '0.73rem', padding: '0.28rem 0.65rem' }}
              onClick={() => setShowSessionsDrawer(!showSessionsDrawer)}
            >
              <LogOut size={13} /> Active Sessions ({activeSessions.length})
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(175px, 1fr))', gap: '0.5rem', alignItems: 'center' }}>
            <input
              type="text"
              className="glass-input"
              style={{ fontSize: '0.78rem' }}
              placeholder="Full Name"
              value={newUserName}
              onChange={(e) => setNewUserName(e.target.value)}
            />
            <input
              type="email"
              className="glass-input"
              style={{ fontSize: '0.78rem' }}
              placeholder="Email Address"
              value={newUserEmail}
              onChange={(e) => setNewUserEmail(e.target.value)}
            />
            <input
              type="password"
              className="glass-input"
              style={{ fontSize: '0.78rem' }}
              placeholder="Password (10+ chars)"
              value={newUserPassword}
              onChange={(e) => setNewUserPassword(e.target.value)}
            />
            <select
              className="glass-select"
              style={{ fontSize: '0.78rem' }}
              value={newUserRole}
              onChange={(e) => setNewUserRole(e.target.value as 'super_admin' | 'technician' | 'client_admin' | 'auditor')}
            >
              <option value="technician">Technician</option>
              <option value="super_admin">MSP Super Admin</option>
              <option value="auditor">Read-Only Auditor</option>
              <option value="client_admin">Client Admin (Tenant Scoped)</option>
            </select>
            {customRoles.length > 0 && (
              <select
                className="glass-select"
                style={{ fontSize: '0.78rem' }}
                value={newUserCustomRoleId}
                onChange={(e) => setNewUserCustomRoleId(e.target.value)}
              >
                <option value="">Default Role Permissions</option>
                {customRoles.map((cr) => (
                  <option key={cr.id} value={cr.id}>
                    Custom: {cr.name}
                  </option>
                ))}
              </select>
            )}
            {newUserRole === 'client_admin' && (
              <select
                className="glass-select"
                style={{ fontSize: '0.78rem' }}
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
            <button type="button" className="btn-glass btn-primary" style={{ fontSize: '0.78rem', justifyContent: 'center' }} onClick={handleAddUser}>
              <Plus size={14} /> Add
            </button>
          </div>

          {userNotice && (
            <div
              style={{
                padding: '0.55rem 0.8rem',
                borderRadius: '6px',
                background: isErrorMessage(userNotice) ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
                border: `1px solid ${isErrorMessage(userNotice) ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                fontSize: '0.75rem',
                color: isErrorMessage(userNotice) ? '#f87171' : '#34d399',
                wordBreak: 'break-word'
              }}
            >
              {userNotice}
            </div>
          )}

          {showSessionsDrawer && (
            <div style={{ padding: '0.65rem 0.85rem', borderRadius: '8px', background: 'rgba(148, 163, 184, 0.08)', border: '1px solid var(--glass-border)', display: 'flex', flexDirection: 'column', gap: '0.4rem', maxHeight: '160px', overflowY: 'auto' }}>
              <strong style={{ fontSize: '0.75rem', color: 'var(--primary)' }}>Active Authenticated Sessions</strong>
              {activeSessions.map((sess) => (
                <div key={sess.sessionPrefix} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.72rem', gap: '0.5rem' }}>
                  <span>
                    <strong>{sess.username}</strong> ({sess.role}) • <code>{sess.sessionPrefix}</code>
                    {currentSessionPrefix === sess.sessionPrefix && (
                      <span style={{ color: '#10b981', marginLeft: '0.35rem', fontWeight: 700 }}>(Current)</span>
                    )}
                    {sess.ipAddress ? ` • ${sess.ipAddress}` : ''}
                  </span>
                  <button
                    type="button"
                    className="btn-glass"
                    style={{ padding: '0.15rem 0.45rem', fontSize: '0.68rem', color: '#ef4444' }}
                    onClick={async () => {
                      if (!confirm(`Revoke active session ${sess.sessionPrefix}?`)) return;
                      try {
                        const res = await revokeActiveSession(sess.sessionPrefix);
                        if (res && res.success === false) {
                          setUserNotice(`Failed to revoke session: ${(res as any).error || 'Request rejected'}`);
                          return;
                        }
                        setUserNotice('✓ Active session revoked.');
                        loadAllAdminData();
                      } catch (err: any) {
                        setUserNotice(`Failed to revoke session: ${err?.message || 'Unknown error'}`);
                      }
                    }}
                  >
                    Revoke
                  </button>
                </div>
              ))}
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
                  <React.Fragment key={u.id}>
                    <tr>
                      <td>
                        <div style={{ fontWeight: 600, fontSize: '0.8rem' }}>{u.username}</div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>{u.email}</div>
                      </td>
                      <td>
                        <span className="status-pill status-reboot" style={{ fontSize: '0.68rem' }}>
                          {u.role}
                        </span>
                        {u.custom_role_name && (
                          <div style={{ fontSize: '0.66rem', color: 'var(--primary)', marginTop: '0.15rem' }}>
                            +{u.custom_role_name}
                          </div>
                        )}
                      </td>
                      <td>
                        <span style={{ fontSize: '0.72rem', color: '#10b981' }}>
                          {u.tenant_name || 'Global MSP'}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.3rem' }}>
                          <button
                            type="button"
                            className="btn-glass btn-icon"
                            title="Edit Role / Reset Password"
                            onClick={() => {
                              if (editingUserId === u.id) {
                                setEditingUserId(null);
                              } else {
                                setEditingUserId(u.id);
                                setEditUserRole(u.role);
                                setEditUserCustomRoleId(u.custom_role_id || '');
                                setEditUserTenantId(u.tenant_id || '');
                                setEditUserPassword('');
                              }
                            }}
                          >
                            <Edit3 size={13} />
                          </button>
                          <button
                            type="button"
                            className="btn-glass btn-icon"
                            title="Reset User TOTP MFA"
                            onClick={() => handleResetUserMfa(u.id, u.username)}
                          >
                            <KeyRound size={13} color="#fbbf24" />
                          </button>
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
                        </div>
                      </td>
                    </tr>
                    {editingUserId === u.id && (
                      <tr>
                        <td colSpan={4} style={{ background: 'rgba(56, 189, 248, 0.06)' }}>
                          <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap', alignItems: 'center' }}>
                            <select
                              className="glass-select"
                              style={{ width: 'auto', fontSize: '0.74rem' }}
                              value={editUserRole}
                              onChange={(e) => setEditUserRole(e.target.value)}
                            >
                              <option value="technician">Technician</option>
                              <option value="super_admin">MSP Super Admin</option>
                              <option value="auditor">Read-Only Auditor</option>
                              <option value="client_admin">Client Admin</option>
                            </select>
                            <select
                              className="glass-select"
                              style={{ width: 'auto', fontSize: '0.74rem' }}
                              value={editUserCustomRoleId}
                              onChange={(e) => setEditUserCustomRoleId(e.target.value)}
                            >
                              <option value="">Default Role Matrix</option>
                              {customRoles.map((cr) => (
                                <option key={cr.id} value={cr.id}>
                                  Custom: {cr.name}
                                </option>
                              ))}
                            </select>
                            {editUserRole === 'client_admin' && (
                              <select
                                className="glass-select"
                                style={{ width: 'auto', fontSize: '0.74rem' }}
                                value={editUserTenantId}
                                onChange={(e) => setEditUserTenantId(e.target.value)}
                              >
                                <option value="">-- Client --</option>
                                {tenants.map((t) => (
                                  <option key={t.id} value={t.id}>
                                    {t.name}
                                  </option>
                                ))}
                              </select>
                            )}
                            <input
                              type="password"
                              className="glass-input"
                              style={{ flex: 1, minWidth: '140px', fontSize: '0.74rem' }}
                              placeholder="Optional new password (10+ chars)"
                              value={editUserPassword}
                              onChange={(e) => setEditUserPassword(e.target.value)}
                            />
                            <button
                              type="button"
                              className="btn-glass btn-primary"
                              style={{ fontSize: '0.73rem', padding: '0.28rem 0.65rem' }}
                              onClick={() => handleSaveEditUser(u.id)}
                            >
                              Save
                            </button>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
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

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(175px, 1fr))', gap: '0.5rem', alignItems: 'center' }}>
            <input
              type="text"
              className="glass-input"
              style={{ fontSize: '0.78rem' }}
              placeholder="Organization Name"
              value={newTenantName}
              onChange={(e) => setNewTenantName(e.target.value)}
            />
            <input
              type="email"
              className="glass-input"
              style={{ fontSize: '0.78rem' }}
              placeholder="Primary Contact Email"
              value={newTenantContact}
              onChange={(e) => setNewTenantContact(e.target.value)}
            />
            <button type="button" className="btn-glass btn-primary" style={{ fontSize: '0.78rem', justifyContent: 'center' }} onClick={handleAddTenant}>
              <Plus size={14} /> Client
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '0.5rem', alignItems: 'center' }}>
            <select
              className="glass-select"
              style={{ fontSize: '0.78rem' }}
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
              style={{ fontSize: '0.78rem' }}
              placeholder="Site Name"
              value={newSiteName}
              onChange={(e) => setNewSiteName(e.target.value)}
            />
            <input
              type="text"
              className="glass-input"
              style={{ fontSize: '0.78rem' }}
              placeholder="Subnet CIDR"
              value={newSiteSubnet}
              onChange={(e) => setNewSiteSubnet(e.target.value)}
            />
            <button type="button" className="btn-glass" style={{ fontSize: '0.78rem', justifyContent: 'center' }} onClick={handleAddSite}>
              <Plus size={14} /> Site
            </button>
          </div>

          {clientActionNotice && (
            <div
              style={{
                padding: '0.55rem 0.85rem',
                borderRadius: '6px',
                background: isErrorMessage(clientActionNotice)
                  ? 'rgba(239, 68, 68, 0.14)'
                  : 'rgba(16, 185, 129, 0.12)',
                border: `1px solid ${isErrorMessage(clientActionNotice) ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                fontSize: '0.76rem',
                color: isErrorMessage(clientActionNotice) ? '#f87171' : '#34d399'
              }}
            >
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
                        title="Edit Client Organization"
                        onClick={() => {
                          if (editingTenantId === t.id) {
                            setEditingTenantId(null);
                          } else {
                            setEditingTenantId(t.id);
                            setEditTenantName(t.name || '');
                            setEditTenantEmail(t.contact_email || '');
                          }
                        }}
                      >
                        <Edit3 size={12} />
                      </button>
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
                    {t.contact_email ? `${t.contact_email} • ` : ''}Sites: {(t.sites || []).map((s) => `${s.name} (${s.subnet})`).join(' • ') || 'None'}
                  </div>
                  {editingTenantId === t.id && (
                    <div style={{ marginTop: '0.55rem', display: 'flex', gap: '0.45rem', flexWrap: 'wrap', paddingTop: '0.5rem', borderTop: '1px solid var(--glass-border)' }}>
                      <input
                        type="text"
                        className="glass-input"
                        style={{ flex: 1, fontSize: '0.74rem' }}
                        value={editTenantName}
                        onChange={(e) => setEditTenantName(e.target.value)}
                        placeholder="Client Name"
                      />
                      <input
                        type="email"
                        className="glass-input"
                        style={{ flex: 1, fontSize: '0.74rem' }}
                        value={editTenantEmail}
                        onChange={(e) => setEditTenantEmail(e.target.value)}
                        placeholder="Contact Email"
                      />
                      <button type="button" className="btn-glass btn-primary" style={{ fontSize: '0.72rem', padding: '0.28rem 0.6rem' }} onClick={() => handleSaveEditTenant(t.id)}>
                        Save
                      </button>
                      <button type="button" className="btn-glass" style={{ fontSize: '0.72rem', padding: '0.28rem 0.55rem' }} onClick={() => setEditingTenantId(null)}>
                        Cancel
                      </button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
      )}

      {showSection('users') && (
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <Shield size={20} color="#a78bfa" />
            <div>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 600, margin: 0 }}>Built-In &amp; Custom RBAC Role Matrix</h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Edit permissions on built-in system roles or create custom granular permission profiles ({customRoles.length} total roles)
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <input
              type="text"
              className="glass-input"
              style={{ flex: 1, fontSize: '0.76rem' }}
              placeholder="Role Name (e.g. Tier-1 NOC Analyst)"
              value={newRoleName}
              onChange={(e) => setNewRoleName(e.target.value)}
            />
            <input
              type="text"
              className="glass-input"
              style={{ flex: 1.2, fontSize: '0.76rem' }}
              placeholder="Description"
              value={newRoleDesc}
              onChange={(e) => setNewRoleDesc(e.target.value)}
            />
            <button type="button" className="btn-glass btn-primary" style={{ fontSize: '0.76rem' }} onClick={handleCreateCustomRole}>
              <Plus size={13} /> Create Role
            </button>
          </div>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', maxHeight: '95px', overflowY: 'auto', padding: '0.45rem', borderRadius: '6px', background: 'rgba(148, 163, 184, 0.05)', border: '1px solid var(--glass-border)' }}>
            {(availablePermissions.filter((p) => p.includes(':')).length > 0
              ? availablePermissions.filter((p) => p.includes(':'))
              : [...ALL_GRANULAR_PERMISSIONS]
            ).map((perm) => {
              const checked = newRolePerms.includes(perm);
              return (
                <label key={perm} style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.7rem', padding: '0.15rem 0.45rem', borderRadius: '4px', background: checked ? 'rgba(167, 139, 250, 0.18)' : 'transparent', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={(e) =>
                      setNewRolePerms((prev) =>
                        e.target.checked ? [...prev, perm] : prev.filter((p) => p !== perm)
                      )
                    }
                  />
                  <code>{perm}</code>
                </label>
              );
            })}
          </div>

          {roleNotice && (
            <div
              style={{
                fontSize: '0.74rem',
                color: isErrorMessage(roleNotice) ? '#f87171' : '#34d399',
                padding: '0.45rem 0.7rem',
                borderRadius: '6px',
                background: isErrorMessage(roleNotice) ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
                border: `1px solid ${isErrorMessage(roleNotice) ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`
              }}
            >
              {roleNotice}
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', maxHeight: '340px', overflowY: 'auto' }}>
            {customRoles.map((cr) => {
              const isEditingThis = editingRoleId === cr.id;
              const isProtectedSuper = cr.id === 'role-super-admin' || cr.id === 'role-msp-super-admin';
              const permCatalog =
                availablePermissions.filter((p) => p.includes(':')).length > 0
                  ? availablePermissions.filter((p) => p.includes(':'))
                  : [...ALL_GRANULAR_PERMISSIONS];
              return (
                <div key={cr.id} style={{ padding: '0.55rem 0.75rem', borderRadius: '8px', background: 'rgba(148, 163, 184, 0.06)', border: '1px solid var(--glass-border)', fontSize: '0.76rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                    <div>
                      <strong>{cr.name}</strong>{' '}
                      {cr.is_system && (
                        <span className="status-pill" style={{ fontSize: '0.62rem', background: 'rgba(56, 189, 248, 0.14)', color: '#38bdf8', marginRight: '0.35rem' }}>
                          Built-in
                        </span>
                      )}
                      <span style={{ color: 'var(--text-dim)' }}>
                        ({cr.base_tier || 'technician'} • {cr.permissions.length} perms)
                      </span>
                      {cr.description && (
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
                          {cr.description}
                        </div>
                      )}
                    </div>
                    <div style={{ display: 'flex', gap: '0.35rem', alignItems: 'center' }}>
                      <button
                        type="button"
                        className="btn-glass"
                        style={{ padding: '0.22rem 0.55rem', fontSize: '0.72rem' }}
                        onClick={() => {
                          if (isEditingThis) {
                            setEditingRoleId(null);
                          } else {
                            setEditingRoleId(cr.id);
                            setEditRoleName(cr.name);
                            setEditRoleDesc(cr.description || '');
                            setEditRoleTier(cr.base_tier || 'technician');
                            setEditRolePerms(isProtectedSuper ? [...ALL_GRANULAR_PERMISSIONS] : [...(cr.permissions || [])]);
                          }
                        }}
                      >
                        <Edit3 size={12} /> {isEditingThis ? 'Close' : 'Edit'}
                      </button>
                      {!cr.is_system && (
                        <button
                          type="button"
                          className="btn-glass btn-icon"
                          onClick={async () => {
                            if (!confirm(`Delete custom role "${cr.name}"?`)) return;
                            try {
                              const res = await deleteCustomRole(cr.id);
                              if (res && res.success === false) {
                                setRoleNotice(`Failed to delete role: ${(res as any).error || 'Request rejected'}`);
                                return;
                              }
                              setRoleNotice(`✓ Deleted custom role "${cr.name}".`);
                              loadAllAdminData();
                            } catch (err: any) {
                              setRoleNotice(`Failed to delete role: ${err?.message || 'Unknown error'}`);
                            }
                          }}
                          title="Delete Custom Role"
                        >
                          <Trash2 size={12} color="#ef4444" />
                        </button>
                      )}
                    </div>
                  </div>

                  {isEditingThis && (
                    <div style={{ marginTop: '0.7rem', paddingTop: '0.65rem', borderTop: '1px solid var(--glass-border)', display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                        <input
                          type="text"
                          className="glass-input"
                          style={{ flex: 1, fontSize: '0.75rem' }}
                          value={editRoleName}
                          onChange={(e) => setEditRoleName(e.target.value)}
                          placeholder="Role Name"
                        />
                        <input
                          type="text"
                          className="glass-input"
                          style={{ flex: 1.5, fontSize: '0.75rem' }}
                          value={editRoleDesc}
                          onChange={(e) => setEditRoleDesc(e.target.value)}
                          placeholder="Description"
                        />
                        {!isProtectedSuper && (
                          <select
                            className="glass-select"
                            style={{ width: 'auto', fontSize: '0.75rem' }}
                            value={editRoleTier}
                            onChange={(e) => setEditRoleTier(e.target.value)}
                          >
                            <option value="technician">Technician Tier</option>
                            <option value="auditor">Auditor Tier</option>
                            <option value="client_admin">Client Admin Tier</option>
                          </select>
                        )}
                      </div>

                      {isProtectedSuper ? (
                        <div style={{ fontSize: '0.72rem', color: '#fbbf24' }}>
                          Full administrative permissions are locked on the primary Super Admin role to prevent lockout; Name and Description are editable.
                        </div>
                      ) : (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', padding: '0.45rem', borderRadius: '6px', background: 'rgba(0,0,0,0.2)', border: '1px solid var(--glass-border)' }}>
                          {permCatalog.map((perm) => {
                            const checked = editRolePerms.includes(perm);
                            return (
                              <label key={perm} style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.69rem', padding: '0.15rem 0.45rem', borderRadius: '4px', background: checked ? 'rgba(167, 139, 250, 0.22)' : 'transparent', cursor: 'pointer' }}>
                                <input
                                  type="checkbox"
                                  checked={checked}
                                  onChange={(e) =>
                                    setEditRolePerms((prev) =>
                                      e.target.checked ? [...prev, perm] : prev.filter((p) => p !== perm)
                                    )
                                  }
                                />
                                <code>{perm}</code>
                              </label>
                            );
                          })}
                        </div>
                      )}

                      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.45rem' }}>
                        <button type="button" className="btn-glass" style={{ fontSize: '0.73rem' }} onClick={() => setEditingRoleId(null)}>
                          Cancel
                        </button>
                        <button type="button" className="btn-glass btn-primary" style={{ fontSize: '0.73rem' }} onClick={() => handleSaveEditRole(cr)}>
                          Save Role Changes (MFA)
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {renderSectionHeader(
        'security',
        '2. Step-Up MFA Vault & Public API Keys',
        'Enroll or manage TOTP 2FA, one-time recovery codes, and scoped bearer tokens for external automation.',
        '#34d399'
      )}

      {/* Step-Up MFA Authenticator & Scoped REST API Keys */}
      {showSection('security') && (
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
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem', display: 'block' }}>
                    TOTP BASE32 SECRET {mfaInfo.confirmed || mfaInfo.secretRedacted ? '(CONFIRMED & LOCKED)' : '(UNCONFIRMED SETUP)'}
                  </span>
                  <code style={{ color: 'var(--primary)', fontWeight: 600 }}>
                    {showMfaSecret
                      ? mfaInfo.secretBase32 || 'REDACTED_AFTER_CONFIRMATION'
                      : '••••••••••••••••••••••••••••••••'}
                  </code>
                </div>
                <button type="button" className="btn-glass" style={{ fontSize: '0.72rem', padding: '0.25rem 0.6rem' }} onClick={() => setShowMfaSecret(!showMfaSecret)}>
                  {showMfaSecret ? 'Hide Secret' : 'Show QR / Secret'}
                </button>
              </div>
              {showMfaSecret && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.72rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                  {mfaInfo.otpAuthUri && !mfaInfo.secretRedacted ? (
                    <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
                      {mfaInfo.qrSvg ? (
                        <img
                          src={`data:image/svg+xml;utf8,${encodeURIComponent(mfaInfo.qrSvg)}`}
                          alt="TOTP QR Code"
                          style={{ width: '132px', height: '132px', background: '#fff', padding: '6px', borderRadius: '8px' }}
                        />
                      ) : (
                        <img
                          src={getLocalQrSvgUrl(mfaInfo.otpAuthUri)}
                          alt="TOTP QR"
                          style={{ width: '132px', height: '132px', background: '#fff', padding: '6px', borderRadius: '8px' }}
                        />
                      )}
                      <div style={{ flex: 1, minWidth: '180px' }}>
                        URI: <code>{mfaInfo.otpAuthUri}</code>
                      </div>
                    </div>
                  ) : (
                    <div>
                      Plaintext TOTP secret is permanently redacted once confirmed. Use Step-Up MFA verification or Reset MFA in RBAC above to provision a new device.
                    </div>
                  )}
                </div>
              )}

              {!mfaInfo.confirmed && !mfaInfo.secretRedacted && (
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                  <input
                    type="text"
                    className="glass-input"
                    style={{ flex: 1, fontSize: '0.78rem' }}
                    placeholder="Enter 6-digit TOTP code to confirm & lock secret"
                    value={confirmTotpCode}
                    onChange={(e) => setConfirmTotpCode(e.target.value)}
                  />
                  <button type="button" className="btn-glass" style={{ fontSize: '0.76rem', borderColor: 'rgba(16, 185, 129, 0.5)', color: '#34d399' }} onClick={handleConfirmMfaEnrollment}>
                    Confirm Enrollment
                  </button>
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
                <div
                  style={{
                    fontSize: '0.76rem',
                    color: isErrorMessage(mfaNotice) ? '#f87171' : '#34d399',
                    padding: '0.5rem 0.75rem',
                    borderRadius: '6px',
                    background: isErrorMessage(mfaNotice) ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
                    border: `1px solid ${isErrorMessage(mfaNotice) ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`
                  }}
                >
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

        {/* Scoped Public REST API Keys */}
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <KeyRound size={20} color="#38bdf8" />
            <div>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 600, margin: 0 }}>Scoped Public REST API Keys (<code>vrmm_live_...</code>)</h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                SHA-256 hashed bearer keys for CI/CD, SIEM &amp; external automation ({apiKeys.filter((k) => !k.revoked).length} active)
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap' }}>
            <input
              type="text"
              className="glass-input"
              style={{ flex: 1.2, fontSize: '0.76rem' }}
              placeholder="Key Label (e.g. HaloPSA Sync Bot)"
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
            />
            <select
              className="glass-select"
              style={{ width: 'auto', fontSize: '0.75rem' }}
              value={newKeyRole}
              onChange={(e) => setNewKeyRole(e.target.value as any)}
            >
              <option value="technician">Role: Technician</option>
              <option value="auditor">Role: Auditor</option>
              <option value="super_admin">Role: Super Admin</option>
            </select>
            <select
              className="glass-select"
              style={{ width: 'auto', fontSize: '0.75rem' }}
              value={newKeyTenantId}
              onChange={(e) => setNewKeyTenantId(e.target.value)}
            >
              <option value="">All Tenants</option>
              {tenants.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
            <select
              className="glass-select"
              style={{ width: 'auto', fontSize: '0.75rem' }}
              value={newKeyExpiresDays}
              onChange={(e) => setNewKeyExpiresDays(Number(e.target.value))}
            >
              <option value={30}>30 Days</option>
              <option value={90}>90 Days</option>
              <option value={365}>1 Year</option>
              <option value={0}>No Expiry</option>
            </select>
            <button type="button" className="btn-glass btn-primary" style={{ fontSize: '0.76rem' }} onClick={handleMintScopedApiKey}>
              <Plus size={13} /> Mint Key
            </button>
          </div>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', maxHeight: '72px', overflowY: 'auto' }}>
            {(ALL_GRANULAR_PERMISSIONS as readonly string[]).map((scope) => {
              const checked = newKeyScopes.includes(scope);
              return (
                <label key={scope} style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.68rem', padding: '0.12rem 0.4rem', borderRadius: '4px', background: checked ? 'rgba(56, 189, 248, 0.18)' : 'rgba(148,163,184,0.06)', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={(e) =>
                      setNewKeyScopes((prev) =>
                        e.target.checked ? [...prev, scope] : prev.filter((s) => s !== scope)
                      )
                    }
                  />
                  <code>{scope}</code>
                </label>
              );
            })}
          </div>

          {mintedRawApiKey && (
            <div style={{ padding: '0.65rem 0.85rem', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.14)', border: '1px solid rgba(16, 185, 129, 0.35)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
              <code style={{ fontSize: '0.74rem', color: '#34d399', wordBreak: 'break-all' }}>{mintedRawApiKey}</code>
              <button
                type="button"
                className="btn-glass"
                style={{ fontSize: '0.72rem', padding: '0.25rem 0.6rem' }}
                onClick={async () => {
                  await copyToClipboard(mintedRawApiKey);
                  setCopiedApiKey(true);
                  setTimeout(() => setCopiedApiKey(false), 2000);
                }}
              >
                {copiedApiKey ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                <span>{copiedApiKey ? 'Copied!' : 'Copy'}</span>
              </button>
            </div>
          )}

          {apiKeyNotice && (
            <div
              style={{
                fontSize: '0.74rem',
                color: isErrorMessage(apiKeyNotice) ? '#f87171' : '#34d399',
                padding: '0.45rem 0.7rem',
                borderRadius: '6px',
                background: isErrorMessage(apiKeyNotice) ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
                border: `1px solid ${isErrorMessage(apiKeyNotice) ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`
              }}
            >
              {apiKeyNotice}
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', maxHeight: '105px', overflowY: 'auto' }}>
            {apiKeys.map((k) => (
              <div key={k.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.4rem 0.65rem', borderRadius: '6px', background: 'rgba(148, 163, 184, 0.06)', border: '1px solid var(--glass-border)', fontSize: '0.73rem', opacity: k.revoked ? 0.55 : 1 }}>
                <div>
                  <strong>{k.name}</strong> • <code>{k.key_prefix}...</code> ({k.scopes.length} scopes)
                </div>
                {!k.revoked && (
                  <button
                    type="button"
                    className="btn-glass btn-icon"
                    onClick={async () => {
                      if (!confirm(`Revoke scoped API key "${k.name}"? Any integrations using it will immediately stop working.`)) return;
                      try {
                        const res = await revokeScopedApiKey(k.id);
                        if (res && res.success === false) {
                          setApiKeyNotice(`Failed to revoke API key: ${(res as any).error || 'Request rejected'}`);
                          return;
                        }
                        setApiKeyNotice(`✓ Revoked API key "${k.name}".`);
                        loadAllAdminData();
                      } catch (err: any) {
                        setApiKeyNotice(`Failed to revoke API key: ${err?.message || 'Unknown error'}`);
                      }
                    }}
                    title="Revoke API Key"
                  >
                    <Trash2 size={12} color="#ef4444" />
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
      )}

      {renderSectionHeader(
        'policies',
        '3. Custom Attributes, Maintenance Windows, Endpoint Backups & MDM Profiles',
        'Define custom metadata fields, fleet-wide alert suppression windows, endpoint backup repositories, and OS compliance baselines.',
        '#f59e0b'
      )}

      {/* Custom Field Definitions & Maintenance Windows */}
      {showSection('policies') && (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
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

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', maxHeight: '110px', overflowY: 'auto' }}>
            {customFieldDefs.map((cf) => (
              <span key={cf.id} style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', padding: '0.25rem 0.55rem', borderRadius: '6px', background: 'rgba(148, 163, 184, 0.08)', border: '1px solid var(--glass-border)', fontSize: '0.72rem' }}>
                <strong>{cf.label}</strong> ({cf.field_type})
                <button
                  type="button"
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--primary)', padding: 0, display: 'inline-flex' }}
                  title="Edit Custom Attribute"
                  onClick={() => {
                    if (editingFieldId === cf.id) {
                      setEditingFieldId(null);
                    } else {
                      setEditingFieldId(cf.id);
                      setEditFieldLabel(cf.label);
                      setEditFieldType((cf.field_type as any) || 'text');
                      setEditFieldOptions(formatFieldOptionsForEditor(cf.options));
                    }
                  }}
                >
                  <Edit3 size={11} />
                </button>
                <button
                  type="button"
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#ef4444', padding: 0, display: 'inline-flex' }}
                  onClick={async () => {
                    if (!confirm(`Delete custom field "${cf.label}"? Stored device values for this attribute will no longer be displayed.`)) return;
                    try {
                      const res = await deleteCustomField(cf.id);
                      if (res && res.success === false) {
                        setSchemaFieldNotice(`Failed to delete custom field: ${(res as any).error || 'Request rejected'}`);
                        return;
                      }
                      setSchemaFieldNotice(`✓ Deleted custom field "${cf.label}".`);
                      fetchCustomFields().then(setCustomFieldDefs).catch(() => {});
                    } catch (err: any) {
                      setSchemaFieldNotice(`Failed to delete custom field: ${err?.message || 'Unknown error'}`);
                    }
                  }}
                >
                  ×
                </button>
              </span>
            ))}
          </div>

          {editingFieldId && (
            <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap', padding: '0.55rem 0.7rem', borderRadius: '6px', background: 'rgba(56, 189, 248, 0.08)', border: '1px solid rgba(56, 189, 248, 0.25)' }}>
              <input
                type="text"
                className="glass-input"
                style={{ flex: 1, fontSize: '0.74rem' }}
                value={editFieldLabel}
                onChange={(e) => setEditFieldLabel(e.target.value)}
                placeholder="Attribute Label"
              />
              <select
                className="glass-select"
                style={{ width: 'auto', fontSize: '0.74rem' }}
                value={editFieldType}
                onChange={(e) => setEditFieldType(e.target.value as any)}
              >
                <option value="text">Text</option>
                <option value="secret">Encrypted Secret (Vaulted + MFA)</option>
                <option value="dropdown">Dropdown</option>
                <option value="checkbox">Checkbox</option>
              </select>
              {editFieldType === 'dropdown' && (
                <input
                  type="text"
                  className="glass-input"
                  style={{ flex: 1, fontSize: '0.74rem' }}
                  value={editFieldOptions}
                  onChange={(e) => setEditFieldOptions(e.target.value)}
                  placeholder="Options (comma-separated)"
                />
              )}
              <button type="button" className="btn-glass btn-primary" style={{ fontSize: '0.72rem', padding: '0.28rem 0.6rem' }} onClick={() => handleSaveEditField(editingFieldId)}>
                Save
              </button>
              <button type="button" className="btn-glass" style={{ fontSize: '0.72rem', padding: '0.28rem 0.55rem' }} onClick={() => setEditingFieldId(null)}>
                Cancel
              </button>
            </div>
          )}

          <div style={{ borderTop: '1px solid var(--glass-border)', paddingTop: '0.65rem', display: 'flex', gap: '0.45rem', flexWrap: 'wrap' }}>
            <CalendarClock size={16} color="#f59e0b" style={{ alignSelf: 'center' }} />
            <input
              type="text"
              className="glass-input"
              style={{ flex: 1.2, minWidth: '130px', fontSize: '0.76rem' }}
              placeholder="Maintenance Window Title"
              value={newWinTitle}
              onChange={(e) => setNewWinTitle(e.target.value)}
            />
            <input
              type="datetime-local"
              className="glass-input"
              style={{ width: 'auto', fontSize: '0.74rem' }}
              title="Optional scheduled start time (defaults to Now)"
              value={newWinStartTime}
              onChange={(e) => setNewWinStartTime(e.target.value)}
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

          {schemaFieldNotice && (
            <div
              style={{
                fontSize: '0.74rem',
                padding: '0.45rem 0.7rem',
                borderRadius: '6px',
                background: isErrorMessage(schemaFieldNotice) ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
                border: `1px solid ${isErrorMessage(schemaFieldNotice) ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                color: isErrorMessage(schemaFieldNotice) ? '#f87171' : '#34d399'
              }}
            >
              {schemaFieldNotice}
            </div>
          )}

          {maintenanceWindows.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', maxHeight: '165px', overflowY: 'auto' }}>
              {maintenanceWindows.map((mw) => (
                <div key={mw.id} style={{ padding: '0.35rem 0.55rem', borderRadius: '6px', background: 'rgba(245, 158, 11, 0.08)', border: '1px solid rgba(245, 158, 11, 0.18)', fontSize: '0.72rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem' }}>
                    <span>
                      <strong>{mw.title}</strong> ({mw.tenant_id ? tenants.find((t) => t.id === mw.tenant_id)?.name || 'Tenant' : 'Global'}) — {new Date(mw.start_time).toLocaleString()} &rarr; {new Date(mw.end_time).toLocaleString()}
                    </span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                      <button
                        type="button"
                        className="btn-glass btn-icon"
                        title="Edit Maintenance Window"
                        onClick={() => {
                          if (editingWinId === mw.id) {
                            setEditingWinId(null);
                          } else {
                            const toLocalInput = (iso: string) => {
                              const d = new Date(iso);
                              if (Number.isNaN(d.getTime())) return '';
                              const pad = (n: number) => String(n).padStart(2, '0');
                              return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
                            };
                            setEditingWinId(mw.id);
                            setEditWinTitle(mw.title);
                            setEditWinTenantId(mw.tenant_id || '');
                            setEditWinStartTime(toLocalInput(mw.start_time));
                            setEditWinEndTime(toLocalInput(mw.end_time));
                          }
                        }}
                      >
                        <Edit3 size={11} />
                      </button>
                      <button
                        type="button"
                        className="btn-glass btn-icon"
                        onClick={async () => {
                          if (!confirm(`Delete maintenance window "${mw.title}"?`)) return;
                          try {
                            const res = await deleteMaintenanceWindow(mw.id);
                            if (res && res.success === false) {
                              setSchemaFieldNotice(`Failed to delete maintenance window: ${(res as any).error || 'Request rejected'}`);
                              return;
                            }
                            setSchemaFieldNotice(`✓ Deleted maintenance window "${mw.title}".`);
                            fetchMaintenanceWindows().then(setMaintenanceWindows).catch(() => {});
                          } catch (err: any) {
                            setSchemaFieldNotice(`Failed to delete maintenance window: ${err?.message || 'Unknown error'}`);
                          }
                        }}
                      >
                        <Trash2 size={11} color="#ef4444" />
                      </button>
                    </div>
                  </div>
                  {editingWinId === mw.id && (
                    <div style={{ marginTop: '0.45rem', paddingTop: '0.45rem', borderTop: '1px solid var(--glass-border)', display: 'flex', gap: '0.4rem', flexWrap: 'wrap', alignItems: 'center' }}>
                      <input
                        type="text"
                        className="glass-input"
                        style={{ flex: 1.2, minWidth: '130px', fontSize: '0.72rem' }}
                        value={editWinTitle}
                        onChange={(e) => setEditWinTitle(e.target.value)}
                        placeholder="Window Title"
                      />
                      <select
                        className="glass-select"
                        style={{ width: 'auto', fontSize: '0.72rem' }}
                        value={editWinTenantId}
                        onChange={(e) => setEditWinTenantId(e.target.value)}
                      >
                        <option value="">Global Fleet</option>
                        {tenants.map((t) => (
                          <option key={t.id} value={t.id}>
                            {t.name}
                          </option>
                        ))}
                      </select>
                      <input
                        type="datetime-local"
                        className="glass-input"
                        style={{ width: 'auto', fontSize: '0.7rem' }}
                        value={editWinStartTime}
                        onChange={(e) => setEditWinStartTime(e.target.value)}
                      />
                      <input
                        type="datetime-local"
                        className="glass-input"
                        style={{ width: 'auto', fontSize: '0.7rem' }}
                        value={editWinEndTime}
                        onChange={(e) => setEditWinEndTime(e.target.value)}
                      />
                      <button type="button" className="btn-glass btn-primary" style={{ fontSize: '0.7rem', padding: '0.24rem 0.55rem' }} onClick={() => handleSaveEditWindow(mw.id)}>
                        Save
                      </button>
                      <button type="button" className="btn-glass" style={{ fontSize: '0.7rem', padding: '0.24rem 0.5rem' }} onClick={() => setEditingWinId(null)}>
                        Cancel
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

      {/* Endpoint Backup Policies & Cross-Platform MDM Configuration Profiles */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <HardDrive size={20} color="#10b981" />
            <div>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 600, margin: 0 }}>Endpoint Backup Vault Policies</h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Restic, Borg, Windows VSS &amp; Time Machine repositories ({backupPolicies.length})
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap' }}>
            <input
              type="text"
              className="glass-input"
              style={{ flex: 1, fontSize: '0.76rem' }}
              placeholder="Policy Name (e.g. Daily Restic S3)"
              value={newBpName}
              onChange={(e) => setNewBpName(e.target.value)}
            />
            <select
              className="glass-select"
              style={{ width: 'auto', fontSize: '0.76rem' }}
              value={newBpEngine}
              onChange={(e) => setNewBpEngine(e.target.value)}
            >
              <option value="restic">Restic (Cross-OS)</option>
              <option value="vss_wbadmin">Windows VSS / wbadmin</option>
              <option value="borg">BorgBackup (Linux)</option>
              <option value="timemachine">macOS Time Machine</option>
            </select>
            <input
              type="text"
              className="glass-input"
              style={{ flex: 1.3, fontSize: '0.76rem' }}
              placeholder="Repo Target (s3:https://.../bucket or \\nas\backups)"
              value={newBpRepo}
              onChange={(e) => setNewBpRepo(e.target.value)}
            />
            <input
              type="text"
              className="glass-input"
              style={{ width: '95px', fontSize: '0.76rem' }}
              placeholder="Cron"
              value={newBpCron}
              onChange={(e) => setNewBpCron(e.target.value)}
            />
            <input
              type="number"
              min={1}
              className="glass-input"
              style={{ width: '75px', fontSize: '0.76rem' }}
              title="Retention Days"
              placeholder="30"
              value={newBpRetention}
              onChange={(e) => setNewBpRetention(e.target.value === '' ? '' : parseInt(e.target.value, 10) || '')}
            />
            <button type="button" className="btn-glass btn-primary" style={{ fontSize: '0.76rem' }} onClick={handleCreateBackupPolicy}>
              <Plus size={13} /> Add
            </button>
          </div>

          {bpNotice && (
            <div
              style={{
                fontSize: '0.74rem',
                padding: '0.45rem 0.7rem',
                borderRadius: '6px',
                background: isErrorMessage(bpNotice) ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
                border: `1px solid ${isErrorMessage(bpNotice) ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                color: isErrorMessage(bpNotice) ? '#f87171' : '#34d399'
              }}
            >
              {bpNotice}
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', maxHeight: '185px', overflowY: 'auto' }}>
            {backupPolicies.map((bp) => (
              <div key={bp.id} style={{ padding: '0.45rem 0.65rem', borderRadius: '6px', background: 'rgba(148, 163, 184, 0.06)', border: '1px solid var(--glass-border)', fontSize: '0.73rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem' }}>
                  <div>
                    <strong>{bp.name}</strong> ({bp.engine}) • <code>{bp.schedule_cron}</code> • {bp.retention_days}d
                  </div>
                  <div style={{ display: 'flex', gap: '0.3rem' }}>
                    <button
                      type="button"
                      className="btn-glass btn-icon"
                      title="Edit Backup Policy"
                      onClick={() => {
                        if (editingBpId === bp.id) {
                          setEditingBpId(null);
                        } else {
                          setEditingBpId(bp.id);
                          setEditBpName(bp.name || '');
                          setEditBpEngine(bp.engine || 'restic');
                          setEditBpRepo(bp.repository_url || bp.target_repo || '');
                          setEditBpCron(bp.schedule_cron || '0 2 * * *');
                          setEditBpRetention(bp.retention_days || 30);
                        }
                      }}
                    >
                      <Edit3 size={12} />
                    </button>
                    <button
                      type="button"
                      className="btn-glass btn-icon"
                      onClick={async () => {
                        if (!confirm(`Delete endpoint backup policy "${bp.name}"?`)) return;
                        try {
                          const res = await deleteBackupPolicy(bp.id);
                          if (res && res.success === false) {
                            setBpNotice(`Failed to delete backup policy: ${(res as any).error || 'Request rejected'}`);
                            return;
                          }
                          setBpNotice(`✓ Deleted backup policy "${bp.name}".`);
                          loadAllAdminData();
                        } catch (err: any) {
                          setBpNotice(`Failed to delete backup policy: ${err?.message || 'Unknown error'}`);
                        }
                      }}
                    >
                      <Trash2 size={12} color="#ef4444" />
                    </button>
                  </div>
                </div>
                {editingBpId === bp.id && (
                  <div style={{ marginTop: '0.5rem', display: 'flex', gap: '0.4rem', flexWrap: 'wrap', alignItems: 'center', paddingTop: '0.45rem', borderTop: '1px solid var(--glass-border)' }}>
                    <input type="text" className="glass-input" style={{ flex: 1, fontSize: '0.72rem' }} value={editBpName} onChange={(e) => setEditBpName(e.target.value)} placeholder="Name" />
                    <select className="glass-select" style={{ width: 'auto', fontSize: '0.72rem' }} value={editBpEngine} onChange={(e) => setEditBpEngine(e.target.value)}>
                      <option value="restic">Restic</option>
                      <option value="vss_wbadmin">VSS</option>
                      <option value="borg">Borg</option>
                      <option value="timemachine">Time Machine</option>
                    </select>
                    <input type="text" className="glass-input" style={{ flex: 1.3, fontSize: '0.72rem' }} value={editBpRepo} onChange={(e) => setEditBpRepo(e.target.value)} placeholder="Repo URL" />
                    <input type="text" className="glass-input" style={{ width: '88px', fontSize: '0.72rem' }} value={editBpCron} onChange={(e) => setEditBpCron(e.target.value)} />
                    <input
                      type="number"
                      min={1}
                      className="glass-input"
                      style={{ width: '65px', fontSize: '0.72rem' }}
                      placeholder="30"
                      value={editBpRetention}
                      onChange={(e) => setEditBpRetention(e.target.value === '' ? '' : parseInt(e.target.value, 10) || '')}
                    />
                    <button type="button" className="btn-glass btn-primary" style={{ fontSize: '0.7rem', padding: '0.24rem 0.55rem' }} onClick={() => handleSaveEditBackupPolicy(bp.id)}>Save</button>
                    <button type="button" className="btn-glass" style={{ fontSize: '0.7rem', padding: '0.24rem 0.5rem' }} onClick={() => setEditingBpId(null)}>Cancel</button>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Cross-Platform MDM Profiles */}
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <Laptop size={20} color="#f59e0b" />
            <div>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 600, margin: 0 }}>MDM &amp; OS Configuration Profiles</h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                macOS <code>.mobileconfig</code>, Windows CSP &amp; Linux sysctl baselines ({mdmProfiles.length})
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap' }}>
            <input
              type="text"
              className="glass-input"
              style={{ flex: 1, fontSize: '0.76rem' }}
              placeholder="Profile Name (e.g. macOS FileVault & Firewall)"
              value={newMdmName}
              onChange={(e) => setNewMdmName(e.target.value)}
            />
            <select
              className="glass-select"
              style={{ width: 'auto', fontSize: '0.76rem' }}
              value={newMdmPlatform}
              onChange={(e) => setNewMdmPlatform(e.target.value as 'macos' | 'windows' | 'linux')}
            >
              <option value="macos">macOS (.mobileconfig)</option>
              <option value="windows">Windows (CSP / Policy)</option>
              <option value="linux">Linux (sysctl / systemd)</option>
            </select>
            <select
              className="glass-select"
              style={{ width: 'auto', fontSize: '0.76rem' }}
              value={newMdmType}
              onChange={(e) => setNewMdmType(e.target.value)}
            >
              <option value="security_baseline">Security Baseline</option>
              <option value="wifi_vpn">Wi-Fi / VPN Payload</option>
              <option value="disk_encryption">Disk Encryption</option>
              <option value="pppc_kiosk">PPPC / Kiosk Restrictions</option>
            </select>
            <button type="button" className="btn-glass btn-primary" style={{ fontSize: '0.76rem' }} onClick={handleCreateMdmProfile}>
              <Plus size={13} /> Profile
            </button>
          </div>

          <input
            type="text"
            className="glass-input"
            style={{ fontSize: '0.74rem' }}
            placeholder="Optional XML / plist / SyncML / JSON payload override"
            value={newMdmPayload}
            onChange={(e) => setNewMdmPayload(e.target.value)}
          />

          {mdmNotice && (
            <div
              style={{
                fontSize: '0.74rem',
                padding: '0.45rem 0.7rem',
                borderRadius: '6px',
                background: isErrorMessage(mdmNotice) ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
                border: `1px solid ${isErrorMessage(mdmNotice) ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                color: isErrorMessage(mdmNotice) ? '#f87171' : '#34d399'
              }}
            >
              {mdmNotice}
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', maxHeight: '185px', overflowY: 'auto' }}>
            {mdmProfiles.map((mp) => (
              <div key={mp.id} style={{ padding: '0.45rem 0.65rem', borderRadius: '6px', background: 'rgba(148, 163, 184, 0.06)', border: '1px solid var(--glass-border)', fontSize: '0.73rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem' }}>
                  <div>
                    <strong>{mp.name}</strong> ({mp.platform.toUpperCase()} • {mp.profile_type})
                  </div>
                  <div style={{ display: 'flex', gap: '0.3rem' }}>
                    <button
                      type="button"
                      className="btn-glass btn-icon"
                      title="Edit MDM Profile"
                      onClick={() => {
                        if (editingMdmId === mp.id) {
                          setEditingMdmId(null);
                        } else {
                          setEditingMdmId(mp.id);
                          setEditMdmName(mp.name || '');
                          setEditMdmPlatform(mp.platform || 'macos');
                          setEditMdmType(mp.profile_type || 'security_baseline');
                          setEditMdmPayload(mp.payload_xml || '');
                        }
                      }}
                    >
                      <Edit3 size={12} />
                    </button>
                    <button
                      type="button"
                      className="btn-glass btn-icon"
                      onClick={async () => {
                        if (!confirm(`Delete MDM profile "${mp.name}"?`)) return;
                        try {
                          const res = await deleteMdmProfile(mp.id);
                          if (res && res.success === false) {
                            setMdmNotice(`Failed to delete MDM profile: ${(res as any).error || 'Request rejected'}`);
                            return;
                          }
                          setMdmNotice(`✓ Deleted MDM profile "${mp.name}".`);
                          loadAllAdminData();
                        } catch (err: any) {
                          setMdmNotice(`Failed to delete MDM profile: ${err?.message || 'Unknown error'}`);
                        }
                      }}
                    >
                      <Trash2 size={12} color="#ef4444" />
                    </button>
                  </div>
                </div>
                {editingMdmId === mp.id && (
                  <div style={{ marginTop: '0.5rem', display: 'flex', flexDirection: 'column', gap: '0.4rem', paddingTop: '0.45rem', borderTop: '1px solid var(--glass-border)' }}>
                    <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                      <input type="text" className="glass-input" style={{ flex: 1, fontSize: '0.72rem' }} value={editMdmName} onChange={(e) => setEditMdmName(e.target.value)} />
                      <select className="glass-select" style={{ width: 'auto', fontSize: '0.72rem' }} value={editMdmPlatform} onChange={(e) => setEditMdmPlatform(e.target.value as any)}>
                        <option value="macos">macOS</option>
                        <option value="windows">Windows</option>
                        <option value="linux">Linux</option>
                      </select>
                      <select className="glass-select" style={{ width: 'auto', fontSize: '0.72rem' }} value={editMdmType} onChange={(e) => setEditMdmType(e.target.value)}>
                        <option value="security_baseline">Security Baseline</option>
                        <option value="wifi_vpn">Wi-Fi / VPN Payload</option>
                        <option value="disk_encryption">Disk Encryption</option>
                        <option value="pppc_kiosk">PPPC / Kiosk Restrictions</option>
                      </select>
                    </div>
                    <input type="text" className="glass-input" style={{ fontSize: '0.72rem' }} value={editMdmPayload} onChange={(e) => setEditMdmPayload(e.target.value)} placeholder="XML / JSON payload" />
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.4rem' }}>
                      <button type="button" className="btn-glass" style={{ fontSize: '0.7rem', padding: '0.24rem 0.5rem' }} onClick={() => setEditingMdmId(null)}>Cancel</button>
                      <button type="button" className="btn-glass btn-primary" style={{ fontSize: '0.7rem', padding: '0.24rem 0.55rem' }} onClick={() => handleSaveEditMdmProfile(mp.id)}>Save</button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
        </div>
      </div>
      )}

      <form noValidate onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {renderSectionHeader(
          'branding',
          '4. Branding, Theme & Public Portal',
          'Customize the application name, logo, colors, theme defaults, agent service name, and QuickSupport portal path.',
          '#a78bfa'
        )}

        {/* White-Labeling Card */}
        <div className="glass-card" style={{ display: showSection('branding') ? undefined : 'none' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <Palette size={20} color="var(--primary)" />
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0 }}>Global White-Labeling &amp; Branding</h3>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              {sanitizeSafeUrl(formData.brand_logo_url) && (
                <img
                  src={sanitizeSafeUrl(formData.brand_logo_url)!}
                  alt="Brand Logo"
                  style={{ height: '28px', width: 'auto', borderRadius: '4px', objectFit: 'contain' }}
                />
              )}
              <input
                ref={logoInputRef}
                type="file"
                accept="image/png,image/jpeg,image/webp,image/x-icon,.ico"
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
              <label className="form-label">Endpoint Companion Tray Default Theme</label>
              <select
                className="glass-select"
                value={formData.tray_theme_mode ?? 'system'}
                onChange={(e) => setFormData({ ...formData, tray_theme_mode: e.target.value as 'system' | 'dark' | 'light' })}
              >
                <option value="system">OS Registry Auto (AppsUseLightTheme / macOS / GNOME)</option>
                <option value="dark">Always Obsidian Dark Tray &amp; HUD</option>
                <option value="light">Always Crisp Daylight Tray &amp; HUD</option>
              </select>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1.25rem', marginTop: '1rem' }}>
            <div className="form-group">
              <label className="form-label">Custom Endpoint Service Name</label>
              <input
                type="text"
                className="glass-input"
                placeholder="VitrineAgent"
                value={formData.installer_service_name ?? 'VitrineAgent'}
                onChange={(e) => setFormData({ ...formData, installer_service_name: e.target.value })}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Installer &amp; Tray Welcome Banner Text</label>
              <input
                type="text"
                className="glass-input"
                placeholder="Managed by Enterprise IT Support"
                value={formData.installer_welcome_text ?? ''}
                onChange={(e) => setFormData({ ...formData, installer_welcome_text: e.target.value })}
              />
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
                {(() => {
                  const rawQsPath = (formData.quicksupport_url_path || '/remote').trim();
                  const safeQsHref = sanitizeSafeUrl(rawQsPath) || '/remote';
                  return (
                    <a
                      href={safeQsHref}
                      target="_blank"
                      rel="noreferrer"
                      className="btn-glass"
                      style={{ whiteSpace: 'nowrap', display: 'flex', alignItems: 'center', gap: '0.35rem', textDecoration: 'none' }}
                    >
                      <ExternalLink size={14} /> {safeQsHref}
                    </a>
                  );
                })()}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginTop: '0.65rem', flexWrap: 'wrap' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer', fontSize: '0.78rem', color: 'var(--text-main)' }}>
                  <input
                    type="checkbox"
                    checked={(formData.quicksupport_enabled ?? 1) !== 0}
                    onChange={(e) => setFormData({ ...formData, quicksupport_enabled: e.target.checked ? 1 : 0 })}
                  />
                  <span>Enable Public QuickSupport Portal</span>
                </label>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', flex: 1, minWidth: '170px' }}>
                  <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>URL Path:</span>
                  <input
                    type="text"
                    className="glass-input"
                    style={{ fontSize: '0.78rem', padding: '0.35rem 0.6rem' }}
                    placeholder="/remote"
                    value={formData.quicksupport_url_path ?? '/remote'}
                    onChange={(e) => setFormData({ ...formData, quicksupport_url_path: e.target.value })}
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Dedicated QuickSupport Branding Profile */}
          <div
            style={{
              marginTop: '1.35rem',
              paddingTop: '1.25rem',
              borderTop: '1px solid var(--glass-border)',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.95rem'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
              <div>
                <h4 style={{ margin: 0, fontSize: '0.96rem', fontWeight: 600, color: 'var(--primary)' }}>
                  QuickSupport Portal &amp; On-Demand Agent Profile
                </h4>
                <p style={{ margin: '0.2rem 0 0 0', fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                  Customize the dedicated icon, label, and tray theme embedded into QuickSupport launchers and the public <code>/remote</code> portal (inherits Global unless overridden).
                </p>
              </div>
              <button
                type="button"
                className="btn-glass btn-primary"
                style={{ fontSize: '0.78rem' }}
                disabled={savingQsProfile}
                onClick={handleSaveQsProfile}
              >
                {savingQsProfile ? 'Saving QuickSupport Profile...' : 'Save QuickSupport Profile'}
              </button>
            </div>

            {qsProfileMsg && (
              <div
                style={{
                  padding: '0.55rem 0.8rem',
                  borderRadius: '6px',
                  fontSize: '0.78rem',
                  background: qsProfileError ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
                  border: `1px solid ${qsProfileError ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                  color: qsProfileError ? '#f87171' : '#34d399'
                }}
              >
                {qsProfileMsg}
              </div>
            )}

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '0.85rem',
                padding: '0.7rem 0.9rem',
                borderRadius: '8px',
                background: 'rgba(255, 255, 255, 0.03)',
                border: '1px solid var(--glass-border)',
                flexWrap: 'wrap'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.7rem' }}>
                {sanitizeSafeUrl(qsIconUrl || formData.brand_logo_url) && (
                  <img
                    src={sanitizeSafeUrl(qsIconUrl || formData.brand_logo_url)!}
                    alt="QuickSupport Icon"
                    style={{ width: '34px', height: '34px', borderRadius: '6px', objectFit: 'contain', background: 'rgba(0,0,0,0.35)', padding: '2px' }}
                  />
                )}
                <div>
                  <div style={{ fontSize: '0.8rem', fontWeight: 600 }}>QuickSupport EXE, Portal &amp; Tray Icon</div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                    {qsIconUrl ? `Override: ${qsIconUrl}` : 'Currently inheriting Global Brand Logo'}
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <input
                  ref={qsIconInputRef}
                  type="file"
                  accept="image/png,image/jpeg,image/webp,image/x-icon,.ico"
                  style={{ display: 'none' }}
                  onChange={handleQsIconFileSelect}
                />
                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.76rem' }}
                  disabled={uploadingQsIcon}
                  onClick={() => qsIconInputRef.current?.click()}
                >
                  <Upload size={13} /> {uploadingQsIcon ? 'Uploading...' : 'Crop & Upload QuickSupport Icon'}
                </button>
                {qsIconUrl && (
                  <button
                    type="button"
                    className="btn-glass btn-danger"
                    style={{ fontSize: '0.74rem' }}
                    onClick={() => {
                      setQsIconUrl('');
                      setQsProfileMsg('Icon override cleared — click Save QuickSupport Profile to inherit Global logo.');
                      setQsProfileError(false);
                    }}
                  >
                    Clear Override
                  </button>
                )}
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem' }}>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">QuickSupport Brand / Portal Label</label>
                <input
                  type="text"
                  className="glass-input"
                  placeholder={`Inherit (${formData.brand_name || 'Vitrine RMM'})`}
                  value={qsBrandName}
                  onChange={(e) => setQsBrandName(e.target.value)}
                />
              </div>

              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">QuickSupport Portal &amp; Tray Theme</label>
                <select
                  className="glass-select"
                  value={qsThemeMode}
                  onChange={(e) => setQsThemeMode(e.target.value as any)}
                >
                  <option value="inherit">Inherit Global Theme</option>
                  <option value="system">OS Auto-Detect</option>
                  <option value="dark">Obsidian Dark</option>
                  <option value="light">Crisp Daylight</option>
                </select>
              </div>

              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">QuickSupport Tray Tooltip</label>
                <input
                  type="text"
                  className="glass-input"
                  placeholder="On-Demand IT Support Active"
                  value={qsTooltip}
                  onChange={(e) => setQsTooltip(e.target.value)}
                />
              </div>
            </div>

            <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', cursor: 'pointer', fontSize: '0.8rem', color: 'var(--text-main)' }}>
              <input
                type="checkbox"
                checked={qsEnabled}
                onChange={(e) => setQsEnabled(e.target.checked)}
              />
              <span>Show System Tray Icon During Active QuickSupport Sessions</span>
            </label>
          </div>
        </div>

        {renderSectionHeader(
          'agents',
          '5. Code Signing, Session Recording & Remote Engine Integration',
          'Configure automated code signing, session recording retention, installer policies, and connected remote engine instances.',
          '#38bdf8'
        )}

        {/* Code Signing API Card */}
        <div className="glass-card" style={{ display: showSection('agents') ? undefined : 'none' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <KeyRound size={20} color="var(--primary)" />
              <div>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0 }}>Code Signing API &amp; Package Integrity</h3>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: '0.15rem 0 0 0' }}>
                  Automates EV/OV code signing of generated agent installers, companion scripts, and tray utilities.
                </p>
              </div>
            </div>
            <button
              type="button"
              className="btn-glass"
              style={{ fontSize: '0.78rem' }}
              onClick={handleTestSigningSettings}
              disabled={testingSigning}
            >
              <Shield size={14} /> {testingSigning ? 'Testing Endpoint...' : 'Test Signing API'}
            </button>
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

            {signingTestMsg && (
              <div
                style={{
                  padding: '0.65rem 0.9rem',
                  borderRadius: '8px',
                  fontSize: '0.78rem',
                  background: signingTestError ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
                  border: `1px solid ${signingTestError ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                  color: signingTestError ? '#f87171' : '#34d399'
                }}
              >
                {signingTestMsg}
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr 1fr', gap: '1rem' }}>
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
                <label className="form-label">Code Signing API Key (Vaulted)</label>
                <input
                  type="password"
                  className="glass-input"
                  placeholder="••••••••••••••••"
                  value={formData.code_signing_api_key ?? ''}
                  onChange={(e) => setFormData({ ...formData, code_signing_api_key: e.target.value })}
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
                    checked={(formData.code_signing_sign_ms2_binary ?? 1) !== 0}
                    onChange={(e) => setFormData({ ...formData, code_signing_sign_ms2_binary: e.target.checked ? 1 : 0 })}
                  />
                  <span>Companion Tray &amp; MeshCentral Agent Payloads</span>
                </label>
              </div>
            </div>
          </div>
        </div>

        {/* Session Recording & Agent Installer Enforcement */}
        <div className="glass-card" style={{ display: showSection('agents') ? undefined : 'none' }}>
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

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
            <div className="form-group">
              <label className="form-label">Minimum Role to Download Installers</label>
              <select
                className="glass-select"
                value={
                  formData.installer_download_role === 'admin'
                    ? 'super_admin'
                    : formData.installer_download_role ?? 'technician'
                }
                onChange={(e) => setFormData({ ...formData, installer_download_role: e.target.value })}
              >
                <option value="technician">Technician+ (All Staff)</option>
                <option value="senior_tech">Senior Technician+</option>
                <option value="msp_admin">MSP Admin / Operations</option>
                <option value="super_admin">MSP Super Admin Only</option>
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

            <div className="form-group">
              <label className="form-label">Console Session Idle Timeout (Min)</label>
              <input
                type="number"
                min={5}
                className="glass-input"
                placeholder="30"
                value={formData.session_idle_timeout_min ?? 30}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    session_idle_timeout_min: e.target.value === '' ? ('' as any) : parseInt(e.target.value, 10) || '' as any
                  })
                }
              />
            </div>
          </div>
        </div>

        {/* MeshCentral Bi-Directional Sync Card */}
        <div className="glass-card" style={{ display: showSection('agents') ? undefined : 'none' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <Shield size={20} color="var(--primary)" />
              <div>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0 }}>
                  MeshCentral 2 Bi-Directional Sync &amp; Multi-Instance Federation
                </h3>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: '0.2rem 0 0 0' }}>
                  {localMesh?.detected
                    ? `Connected / Co-resident Mode: local MeshCentral 2 detected at ${localMesh.installDir || localMesh.serviceName} (isolated from Vitrine)`
                    : 'Bi-directional mirroring of MeshCentral Device Groups <-> Vitrine Clients across remote or local MeshCentral 2 instances'}
                </p>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <button
                type="button"
                className="btn-glass"
                onClick={() => setShowAutoTokenGen((v) => !v)}
                style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '0.8rem' }}
              >
                <KeyRound size={14} />
                <span>{showAutoTokenGen ? 'Hide Token Generator' : 'Auto-Generate Login Token'}</span>
              </button>
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
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: useCombinedTokenMode ? '1.3fr 1fr' : '1.3fr 1fr 1fr', gap: '1rem', marginBottom: '0.65rem' }}>
            <div className="form-group">
              <label className="form-label">Primary MeshCentral Server URL</label>
              <input
                type="text"
                className="glass-input"
                placeholder={localMesh?.detectedUrl || 'https://mesh.yourdomain.com'}
                value={formData.meshcentral_url ?? ''}
                onChange={(e) => setFormData({ ...formData, meshcentral_url: e.target.value })}
              />
            </div>

            {!useCombinedTokenMode ? (
              <>
                <div className="form-group">
                  <label className="form-label">Login Token Username (Vaulted)</label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder={meshTokenHasSaved ? 'Saved in vault (leave blank to keep)' : '~t:AbCdEf123456 (or admin)'}
                    value={meshTokenUser}
                    onChange={(e) => {
                      const val = e.target.value;
                      if (val.trim().startsWith('~t:')) {
                        const parsed = parseMeshTokenPair(val);
                        if (parsed.pass) {
                          setMeshTokenUser(parsed.user);
                          setMeshTokenPass(parsed.pass);
                          syncTwoFieldMeshToken(parsed.user, parsed.pass);
                          return;
                        }
                      }
                      setMeshTokenUser(val);
                      syncTwoFieldMeshToken(val, meshTokenPass);
                    }}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Login Token Password (Vaulted)</label>
                  <input
                    type="password"
                    className="glass-input"
                    placeholder={meshTokenHasSaved ? '•••••••••••• (leave blank to keep)' : 'Token Password'}
                    value={meshTokenPass}
                    onChange={(e) => {
                      const val = e.target.value;
                      setMeshTokenPass(val);
                      syncTwoFieldMeshToken(meshTokenUser, val);
                    }}
                  />
                </div>
              </>
            ) : (
              <div className="form-group">
                <label className="form-label">Combined Token / x-meshauth (Vaulted)</label>
                <input
                  type="password"
                  className="glass-input"
                  placeholder="~t:TokenUser:TokenPass or base64,base64"
                  value={formData.meshcentral_api_token ?? ''}
                  onChange={(e) => setFormData({ ...formData, meshcentral_api_token: e.target.value })}
                />
              </div>
            )}
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '1rem', fontSize: '0.74rem', color: 'var(--text-muted)' }}>
            <span>
              <button
                type="button"
                onClick={() => setUseCombinedTokenMode((v) => !v)}
                style={{
                  background: 'none',
                  border: 'none',
                  padding: 0,
                  color: '#38bdf8',
                  cursor: 'pointer',
                  textDecoration: 'underline',
                  fontSize: '0.74rem',
                  marginRight: '0.75rem'
                }}
              >
                {useCombinedTokenMode ? 'Use two-field Token Username + Password' : 'Enter raw base64 / combined token string'}
              </button>
              2FA accounts: use <strong>My Account → Login Tokens</strong> in MS2 or click <strong>Auto-Generate Login Token</strong>.
            </span>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', cursor: 'pointer', color: 'var(--text-main)' }}>
              <input
                type="checkbox"
                checked={Boolean(formData.meshcentral_allow_self_signed)}
                onChange={(e) => setFormData({ ...formData, meshcentral_allow_self_signed: e.target.checked ? 1 : 0 })}
              />
              <span>Allow self-signed TLS certificate</span>
            </label>
          </div>

          {showAutoTokenGen && (
            <div style={{ background: 'var(--surface-panel)', border: '1px solid var(--glass-border)', borderRadius: '8px', padding: '0.9rem 1rem', marginBottom: '1rem', display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
              <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                Mint a permanent 2FA-safe <code>Vitrine RMM</code> Login Token directly from your MeshCentral server (credentials are used once over WebSocket and immediately discarded):
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 0.8fr auto', gap: '0.6rem', alignItems: 'end' }}>
                <div className="form-group">
                  <label className="form-label" style={{ fontSize: '0.72rem' }}>MS2 Admin Username</label>
                  <input type="text" className="glass-input" value={autoMs2User} onChange={(e) => setAutoMs2User(e.target.value)} />
                </div>
                <div className="form-group">
                  <label className="form-label" style={{ fontSize: '0.72rem' }}>MS2 Admin Password</label>
                  <input type="password" className="glass-input" placeholder="Not stored" value={autoMs2Pass} onChange={(e) => setAutoMs2Pass(e.target.value)} />
                </div>
                <div className="form-group">
                  <label className="form-label" style={{ fontSize: '0.72rem', color: autoMs2TotpRequired ? '#fbbf24' : undefined }}>
                    {autoMs2TotpRequired ? '2FA TOTP Required' : '2FA Code (optional)'}
                  </label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="123456"
                    value={autoMs2Totp}
                    onChange={(e) => setAutoMs2Totp(e.target.value)}
                    style={autoMs2TotpRequired ? { borderColor: '#f59e0b' } : undefined}
                  />
                </div>
                <button
                  type="button"
                  className="btn-glass btn-primary"
                  disabled={generatingToken}
                  onClick={handleAutoGenerateMeshToken}
                  style={{ height: '38px', fontSize: '0.76rem', whiteSpace: 'nowrap' }}
                >
                  <KeyRound size={14} />
                  <span>{generatingToken ? 'Generating...' : 'Generate Token'}</span>
                </button>
              </div>
              {autoTokenMsg && (
                <div style={{ fontSize: '0.76rem', color: autoTokenIsError ? '#f87171' : '#34d399', fontWeight: 600 }}>
                  {autoTokenMsg}
                </div>
              )}
            </div>
          )}

          {localMesh?.detected && localMesh.configPath && (
            <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--glass-border)', borderRadius: '8px', padding: '0.85rem 1rem', marginBottom: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <div style={{ fontSize: '0.78rem', fontWeight: 600 }}>
                Local MeshCentral Config Options (<code>{localMesh.configPath}</code>)
              </div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                Current: <code>allowFraming</code> = <strong>{String(localMesh.allowFraming ?? 'unset')}</strong> •{' '}
                <code>disableAgentUpdate</code> = <strong>{String(localMesh.disableAgentUpdate ?? 'unset')}</strong>
              </div>
              {localMesh.configJsonValid && localMesh.configWritable ? (
                <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap', fontSize: '0.76rem' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer' }}>
                    <input type="checkbox" checked={optAllowFraming} onChange={(e) => setOptAllowFraming(e.target.checked)} />
                    <span>Set <code>&quot;allowFraming&quot;: true</code></span>
                  </label>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer' }}>
                    <input type="checkbox" checked={optDisableAgentUpdate} onChange={(e) => setOptDisableAgentUpdate(e.target.checked)} />
                    <span>Set <code>&quot;disableAgentUpdate&quot;: true</code></span>
                  </label>
                  <button
                    type="button"
                    className="btn-glass"
                    disabled={applyingLocalCfg || (!optAllowFraming && !optDisableAgentUpdate)}
                    onClick={handleApplyLocalMeshConfig}
                    style={{ fontSize: '0.74rem', padding: '0.3rem 0.65rem' }}
                  >
                    {applyingLocalCfg ? 'Applying...' : 'Backup & Apply to config.json'}
                  </button>
                  {localCfgMsg && (
                    <span style={{ fontSize: '0.74rem', color: localCfgIsError ? '#f87171' : '#34d399', fontWeight: 600 }}>
                      {localCfgMsg}
                    </span>
                  )}
                </div>
              ) : (
                <div style={{ fontSize: '0.73rem', color: '#fbbf24' }}>
                  config.json is read-only or contains non-standard comments; edit manually under <code>&quot;settings&quot;</code> if desired.
                </div>
              )}
            </div>
          )}

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
            <div
              style={{
                background: isErrorMessage(meshSyncResult) ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
                border: `1px solid ${isErrorMessage(meshSyncResult) ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                padding: '0.75rem 1rem',
                borderRadius: '6px',
                fontSize: '0.8rem',
                color: isErrorMessage(meshSyncResult) ? '#f87171' : '#34d399',
                marginTop: '1rem'
              }}
            >
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
                placeholder="Label (e.g. Regional MS2 #2)"
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
                    flexDirection: 'column',
                    gap: '0.55rem'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.65rem' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600, fontSize: '0.84rem' }}>
                        <span>{srv.name}</span>
                        {Boolean(srv.is_primary) && <span className="status-pill status-online" style={{ fontSize: '0.65rem' }}>Primary</span>}
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
                      <button
                        type="button"
                        className="btn-glass btn-icon"
                        title="Edit MS2 Instance"
                        onClick={() => {
                          if (editingMeshId === srv.id) {
                            setEditingMeshId(null);
                          } else {
                            setEditingMeshId(srv.id);
                            setEditMeshName(srv.name);
                            setEditMeshUrl(srv.url);
                            setEditMeshToken('');
                            setEditMeshAutoPush(Boolean(srv.auto_push_companion));
                          }
                        }}
                      >
                        <Edit3 size={13} />
                      </button>
                      {!srv.is_primary && (
                        <button
                          type="button"
                          className="btn-glass btn-icon"
                          onClick={async () => {
                            if (!confirm(`Remove federated MeshCentral instance "${srv.name}"?`)) return;
                            try {
                              const res = await deleteMeshServer(srv.id);
                              if (res && res.success === false) {
                                setMeshSyncResult(`Failed to remove MeshCentral instance: ${(res as any).error || 'Request rejected'}`);
                                return;
                              }
                              setMeshSyncResult(`✓ Removed federated MeshCentral instance "${srv.name}".`);
                              loadAllAdminData();
                            } catch (err: any) {
                              setMeshSyncResult(`Failed to remove MeshCentral instance: ${err?.message || 'Unknown error'}`);
                            }
                          }}
                        >
                          <Trash2 size={13} color="#ef4444" />
                        </button>
                      )}
                    </div>
                  </div>
                  {editingMeshId === srv.id && (
                    <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center', paddingTop: '0.45rem', borderTop: '1px solid var(--glass-border)' }}>
                      <input
                        type="text"
                        className="glass-input"
                        style={{ flex: 1, fontSize: '0.76rem' }}
                        value={editMeshName}
                        onChange={(e) => setEditMeshName(e.target.value)}
                      />
                      <input
                        type="text"
                        className="glass-input"
                        style={{ flex: 1.4, fontSize: '0.76rem' }}
                        value={editMeshUrl}
                        onChange={(e) => setEditMeshUrl(e.target.value)}
                      />
                      <input
                        type="password"
                        className="glass-input"
                        style={{ flex: 1, fontSize: '0.76rem' }}
                        placeholder="New API Token (leave blank to keep)"
                        value={editMeshToken}
                        onChange={(e) => setEditMeshToken(e.target.value)}
                      />
                      <label style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.75rem', cursor: 'pointer' }}>
                        <input
                          type="checkbox"
                          checked={editMeshAutoPush}
                          onChange={(e) => setEditMeshAutoPush(e.target.checked)}
                        />
                        <span>Auto-Push Companion</span>
                      </label>
                      <button
                        type="button"
                        className="btn-glass btn-primary"
                        style={{ fontSize: '0.75rem', padding: '0.28rem 0.65rem' }}
                        onClick={() => handleSaveMeshServerEdit(srv.id)}
                      >
                        Save MS2
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>

            {discoveryPreview && (!discoveryPreview.reachable || discoveryPreview.authenticated === false) && (
              <div
                style={{
                  marginTop: '0.85rem',
                  padding: '0.9rem 1.1rem',
                  borderRadius: '8px',
                  background: 'rgba(239, 68, 68, 0.14)',
                  border: '1px solid rgba(239, 68, 68, 0.35)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '0.75rem'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', fontSize: '0.82rem', color: '#f87171', fontWeight: 600 }}>
                  <AlertTriangle size={16} style={{ flexShrink: 0 }} />
                  <span>{discoveryPreview.error || discoveryPreview.summary || 'MeshCentral server unreachable'}</span>
                </div>
                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.75rem', padding: '0.3rem 0.55rem' }}
                  onClick={() => setDiscoveryPreview(null)}
                >
                  Close
                </button>
              </div>
            )}

            {discoveryPreview && discoveryPreview.reachable && discoveryPreview.authenticated !== false && (
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

        {renderSectionHeader(
          'updates',
          '6. System Updates & Disaster Recovery Backups',
          'Choose update release channels, configure automated encrypted backups, and restore or export recovery snapshots.',
          '#10b981'
        )}

        {/* Self-Update Engine (Stable Releases vs. Alpha Commits + Pre-Update Backup & Watchdog Rollback) */}
        <div className="glass-card" id="self-updater-card" style={{ display: showSection('updates') ? undefined : 'none' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <GitBranch size={20} color="var(--primary)" />
              <div>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0 }}>
                  Self-Update Engine (Stable Releases vs. Alpha Commits) &amp; Watchdog Auto-Rollback
                </h3>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: '0.2rem 0 0 0' }}>
                  Installed Version: <strong>v{updaterStatus?.installedVersion || formData.installed_version || '2.7.0'}</strong> • Installed Commit:{' '}
                  <code>{updaterStatus?.installedCommit || formData.installed_commit || 'HEAD'}</code> • DB Schema:{' '}
                  <code>v{backupStorage.currentAppSchemaVersion}</code> • Mode:{' '}
                  <strong>
                    {updaterStatus
                      ? updaterStatus.deploymentMode === 'docker'
                        ? 'Docker Container'
                        : 'Bare-Metal Systemd'
                      : 'Loading...'}
                  </strong>
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
                      Latest Stable Release: {updaterStatus.latestStable?.title || 'Unknown'} (Commit <code>{updaterStatus.latestStable?.commitSha || '—'}</code>)
                    </strong>
                    <span className="status-pill status-online" style={{ fontSize: '0.7rem' }}>
                      {updaterStatus.updateAvailable ? 'Update Available' : 'Up to Date'}
                    </span>
                  </div>
                  <pre style={{ margin: 0, whiteSpace: 'pre-wrap', fontSize: '0.76rem', color: 'var(--text-muted)', fontFamily: 'inherit' }}>
                    {updaterStatus.latestStable?.releaseNotes || 'No release notes available.'}
                  </pre>
                </div>
              ) : (
                <div style={{ padding: '0.9rem 1.1rem', borderRadius: '8px', background: 'var(--glass-bg)', border: '1px solid var(--glass-border)' }}>
                  <strong style={{ fontSize: '0.86rem', color: '#c084fc', display: 'block', marginBottom: '0.5rem' }}>
                    Alpha Commits Since Installed Commit (<code>{updaterStatus.installedCommit || 'HEAD'}</code>):
                  </strong>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                    {(updaterStatus.pendingAlphaCommits || []).length === 0 ? (
                      <div style={{ fontSize: '0.76rem', color: 'var(--text-dim)' }}>No newer commits pending on branch.</div>
                    ) : (
                      (updaterStatus.pendingAlphaCommits || []).map((c) => (
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

              <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
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
                      : `Install Target Update (${
                          updaterStatus.channel === 'stable'
                            ? updaterStatus.latestStable?.version || 'latest'
                            : updaterStatus.latestAlpha?.sha || 'HEAD'
                        })`}
                  </span>
                </button>
                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.78rem' }}
                  onClick={handleNotifyAdminsOfUpdate}
                >
                  <BellRing size={14} /> Notify Admins &amp; Dispatch Change Alert
                </button>
                {systemHealth && (
                  <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)', display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                    <Activity size={13} color="#10b981" />
                    Control Plane {systemHealth.status.toUpperCase()} • Uptime {Math.floor(systemHealth.uptime / 60)}m • Active Tunnels: {systemHealth.meshBridge?.activeTunnels ?? 0}
                  </span>
                )}
              </div>

              {updaterNotice && (
                <div
                  style={{
                    padding: '0.75rem 1rem',
                    borderRadius: '8px',
                    background: isErrorMessage(updaterNotice) ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
                    border: `1px solid ${isErrorMessage(updaterNotice) ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                    fontSize: '0.8rem',
                    color: isErrorMessage(updaterNotice) ? '#f87171' : '#34d399'
                  }}
                >
                  {updaterNotice}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Unified Self-Backup, Local Storage Quota & Schema-Aware Restoration Card */}
        <div className="glass-card" id="unified-backups-card" style={{ display: showSection('updates') ? undefined : 'none' }}>
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

          <div style={{ display: 'flex', gap: '1.25rem', alignItems: 'center', marginBottom: '0.85rem', flexWrap: 'wrap' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.84rem', fontWeight: 600, cursor: 'pointer', color: 'var(--text-main)' }}>
              <input
                type="checkbox"
                checked={(formData.backup_schedule_enabled ?? 1) !== 0}
                onChange={(e) => setFormData({ ...formData, backup_schedule_enabled: e.target.checked ? 1 : 0 })}
              />
              <span>Enable Automated Disaster Recovery Schedule</span>
            </label>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '1rem' }}>
            <div className="form-group">
              <label className="form-label">Automated Backup Frequency</label>
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
              <label className="form-label">Scheduled Run Time (UTC)</label>
              <input
                type="time"
                className="glass-input"
                value={formData.backup_schedule_time ?? '02:30'}
                onChange={(e) => setFormData({ ...formData, backup_schedule_time: e.target.value })}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Retention Count (Auto-Prune)</label>
              <input
                type="number"
                min={1}
                className="glass-input"
                placeholder="14"
                value={formData.backup_retention_count ?? 14}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    backup_retention_count: e.target.value === '' ? ('' as any) : parseInt(e.target.value, 10) || ('' as any)
                  })
                }
              />
            </div>
            <div className="form-group">
              <label className="form-label">Local Storage Quota (MB)</label>
              <input
                type="number"
                min={128}
                className="glass-input"
                placeholder="5120"
                value={formData.backup_max_storage_mb ?? 5120}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    backup_max_storage_mb: e.target.value === '' ? ('' as any) : parseInt(e.target.value, 10) || ('' as any)
                  })
                }
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
                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.76rem', padding: '0.35rem 0.75rem' }}
                  disabled={browsingOffsite}
                  onClick={handleBrowseOffsiteVault}
                >
                  <Download size={13} />
                  <span>{browsingOffsite ? 'Listing Vault...' : 'Browse & Pull Offsite Vault'}</span>
                </button>
              </div>
            </div>

            {offsiteObjects && (
              <div style={{ padding: '0.65rem 0.85rem', borderRadius: '8px', background: 'rgba(56, 189, 248, 0.08)', border: '1px solid rgba(56, 189, 248, 0.3)', display: 'flex', flexDirection: 'column', gap: '0.4rem', maxHeight: '140px', overflowY: 'auto' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <strong style={{ fontSize: '0.76rem', color: '#38bdf8' }}>
                    Offsite Vault Objects ({offsiteObjects.length})
                  </strong>
                  <button type="button" className="btn-glass" style={{ padding: '0.15rem 0.45rem', fontSize: '0.68rem' }} onClick={() => setOffsiteObjects(null)}>
                    Close
                  </button>
                </div>
                {offsiteObjects.length === 0 ? (
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-dim)' }}>No remote archives found in configured offsite bucket/path.</div>
                ) : (
                  offsiteObjects.map((obj) => (
                    <div key={obj.key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.73rem', gap: '0.5rem' }}>
                      <span>
                        <code>{obj.key}</code> ({(obj.sizeBytes / (1024 * 1024)).toFixed(2)} MB)
                      </span>
                      <button
                        type="button"
                        className="btn-glass btn-primary"
                        style={{ padding: '0.18rem 0.55rem', fontSize: '0.7rem' }}
                        onClick={() => handlePullOffsiteObject(obj.key)}
                      >
                        Pull to Local Vault
                      </button>
                    </div>
                  ))
                )}
              </div>
            )}

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
                  onClick={async () => {
                    const ok = await copyToClipboard(revealedBackupKey);
                    if (ok) {
                      setCopiedBackupKey(true);
                      setTimeout(() => setCopiedBackupKey(false), 2000);
                    }
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

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: '0.75rem' }}>
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
                <label className="form-label" style={{ fontSize: '0.72rem' }}>S3 Signing Region</label>
                <input
                  type="text"
                  className="glass-input"
                  style={{ fontSize: '0.78rem' }}
                  placeholder="us-east-1"
                  value={formData.backup_offsite_region ?? ''}
                  onChange={(e) => setFormData({ ...formData, backup_offsite_region: e.target.value })}
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
            <div
              style={{
                marginBottom: '1rem',
                padding: '0.75rem 1rem',
                borderRadius: '8px',
                background: isErrorMessage(backupNotice) ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
                border: `1px solid ${isErrorMessage(backupNotice) ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                fontSize: '0.8rem',
                color: isErrorMessage(backupNotice) ? '#f87171' : '#34d399'
              }}
            >
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
                                if (!confirm(`Delete recovery backup archive "${b.filename || b.id}"? This cannot be undone.`)) return;
                                try {
                                  const res = await deleteSystemBackup(b.id);
                                  if (res && res.success === false) {
                                    setBackupNotice(`Failed to delete backup: ${(res as any).error || 'Request rejected'}`);
                                    return;
                                  }
                                  setBackupNotice('✓ Deleted disaster recovery backup archive.');
                                  loadAllAdminData();
                                } catch (err: any) {
                                  setBackupNotice(`Failed to delete backup: ${err?.message || 'Unknown error'}`);
                                }
                              }}
                              title="Delete Backup"
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

        {renderSectionHeader(
          'notifications',
          '7. Single Sign-On (OIDC), PSA Integrations & Outbound SMTP',
          'Configure Enterprise OpenID Connect SSO, external PSA ticket bridges, and outbound email notification credentials.',
          '#fbbf24'
        )}

        {/* PSA Webhook & OIDC Identity Provider Integration Card */}
        <div className="glass-card" style={{ display: showSection('notifications') ? undefined : 'none' }}>
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
            <div
              style={{
                marginTop: '0.85rem',
                padding: '0.7rem 0.95rem',
                borderRadius: '8px',
                background: isErrorMessage(oidcTestResult) ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
                border: `1px solid ${isErrorMessage(oidcTestResult) ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                fontSize: '0.78rem',
                color: isErrorMessage(oidcTestResult) ? '#f87171' : '#34d399'
              }}
            >
              {oidcTestResult}
            </div>
          )}
        </div>

        {/* Outbound SMTP Notifications Card */}
        <div className="glass-card" style={{ display: showSection('notifications') ? undefined : 'none' }}>
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
                min={1}
                max={65535}
                className="glass-input"
                placeholder="587"
                value={formData.smtp_port ?? 587}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    smtp_port: e.target.value === '' ? ('' as any) : parseInt(e.target.value, 10) || ('' as any)
                  })
                }
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

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem', marginTop: '0.85rem' }}>
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

          <div style={{ marginTop: '0.75rem' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.82rem', cursor: 'pointer', color: 'var(--text-main)' }}>
              <input
                type="checkbox"
                checked={Boolean(formData.smtp_tls)}
                onChange={(e) => setFormData({ ...formData, smtp_tls: e.target.checked ? 1 : 0 })}
              />
              <span>Require TLS / Implicit SSL Encryption for Outbound SMTP Relay</span>
            </label>
          </div>

          {smtpTestResult && (
            <div
              style={{
                background:
                  !smtpTestSuccess || isErrorMessage(smtpTestResult)
                    ? 'rgba(239, 68, 68, 0.14)'
                    : 'rgba(16, 185, 129, 0.12)',
                border: `1px solid ${
                  !smtpTestSuccess || isErrorMessage(smtpTestResult)
                    ? 'rgba(239, 68, 68, 0.35)'
                    : 'rgba(16, 185, 129, 0.35)'
                }`,
                padding: '0.75rem 1rem',
                borderRadius: '6px',
                fontSize: '0.8rem',
                color: !smtpTestSuccess || isErrorMessage(smtpTestResult) ? '#f87171' : '#34d399'
              }}
            >
              {smtpTestResult}
            </div>
          )}
        </div>

        {/* Sticky Save Bar */}
        <div
          className="glass-card"
          style={{
            position: 'sticky',
            bottom: '0.75rem',
            zIndex: 20,
            padding: '0.85rem 1.25rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: '1rem',
            flexWrap: 'wrap',
            background: 'var(--surface-elevated)',
            backdropFilter: 'blur(16px)'
          }}
        >
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Changes to branding, code signing, SSO, SMTP, PSA &amp; updates apply upon saving.
          </span>
          <button type="submit" className="btn-glass btn-primary" style={{ padding: '0.68rem 1.65rem' }} disabled={saving}>
            <CheckCircle2 size={16} /> {saving ? 'Saving Configuration...' : 'Save All Settings'}
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
                    Schema v{schemaMismatchModal.appSchemaVersion} (App v{updaterStatus?.installedVersion || '2.7.0'})
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

      <MfaChallengeModal
        isOpen={Boolean(pendingMfaAction)}
        onClose={() => setPendingMfaAction(null)}
        onSuccess={() => {
          const action = pendingMfaAction;
          setPendingMfaAction(null);
          if (action) action.onVerified();
        }}
        title={pendingMfaAction?.title || 'Step-Up MFA Verification'}
        description="Verify your 6-digit TOTP authenticator or single-use recovery code to authorize this administrative security operation."
        secretType={pendingMfaAction?.secretType || 'admin_security_action'}
      />

      <IconCropModal
        isOpen={Boolean(cropIconRequest)}
        file={cropIconRequest?.file || null}
        title={cropIconRequest?.mode === 'quicksupport' ? 'Crop QuickSupport EXE & Portal Icon' : 'Crop Global Brand & EXE Icon'}
        onCancel={() => setCropIconRequest(null)}
        onConfirm={handleCropModalConfirm}
      />
    </div>
  );
};
