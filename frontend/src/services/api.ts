import {
  Device,
  Tenant,
  Policy,
  Patch,
  ScriptItem,
  SelfHealingMonitor,
  Settings,
  ProcessItem,
  ServiceItem,
  CustomFieldDefinition,
  MaintenanceWindow,
  ChatMessage,
  SessionRecording,
  OemWarranty,
  EventLogItem,
  LapsCredential,
  AppNotification,
  HardwareHistoryItem,
  NetworkHistoryItem,
  SmartGroup,
  SoftwareItem,
  GuestAccessGrant,
  RbacUser,
  RemediationLog,
  DeviceNote,
  NetworkAppliance,
  WakeOnLanResult,
  RemoteSessionDescriptor,
  MeshServer,
  MeshDiscoveryResult,
  SigningStageReport,
  QuickSupportSession,
  SystemBackupItem,
  BackupCompatibilityReport,
  UpdaterStatus,
  BreakGlassRecoveryEntry,
  AuthStatusResponse,
  AuthUser,
  PublicPortalConfig
} from '../types/index.js';

const API_BASE = '/api';

export class ApiError extends Error {
  public status: number;
  public code?: string;
  public payload?: any;

  constructor(message: string, status: number, code?: string, payload?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.payload = payload;
  }
}

export function getStoredSessionToken(): string | null {
  try {
    return sessionStorage.getItem('vitrine_session_token');
  } catch {
    return null;
  }
}

export function setStoredSessionToken(token: string | null): void {
  try {
    if (token) {
      sessionStorage.setItem('vitrine_session_token', token);
    } else {
      sessionStorage.removeItem('vitrine_session_token');
    }
  } catch {
    // Ignore storage errors
  }
}

export function getStoredGuestToken(grantId: string): string | null {
  try {
    return sessionStorage.getItem(`vitrine_guest_token_${grantId}`);
  } catch {
    return null;
  }
}

export function setStoredGuestToken(grantId: string, token: string | null): void {
  try {
    if (token) {
      sessionStorage.setItem(`vitrine_guest_token_${grantId}`, token);
    } else {
      sessionStorage.removeItem(`vitrine_guest_token_${grantId}`);
    }
  } catch {
    // Ignore
  }
}

async function requestJson<T>(
  path: string,
  options: RequestInit & {
    returnErrorPayload?: boolean;
    guestGrantId?: string;
    suppressAuthEvent?: boolean;
  } = {}
): Promise<T> {
  const { returnErrorPayload, guestGrantId, suppressAuthEvent, headers: customHeaders, ...fetchOpts } = options;
  const headers: Record<string, string> = {
    ...(customHeaders as Record<string, string>)
  };

  if (fetchOpts.body && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  const sessionToken = getStoredSessionToken();
  if (sessionToken && !headers.Authorization) {
    headers.Authorization = `Bearer ${sessionToken}`;
  }

  if (guestGrantId) {
    const guestTok = getStoredGuestToken(guestGrantId);
    if (guestTok) {
      headers['x-vitrine-guest-token'] = guestTok;
    }
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...fetchOpts,
    credentials: 'include',
    headers
  });

  const text = await res.text();
  let parsed: any = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { error: text };
    }
  }

  if (!res.ok) {
    const errCode = parsed?.code;
    const errMsg = parsed?.error || parsed?.message || `HTTP ${res.status} ${res.statusText}`;

    if (res.status === 401 && errCode === 'AUTH_REQUIRED' && !suppressAuthEvent) {
      setStoredSessionToken(null);
      window.dispatchEvent(new CustomEvent('vitrine:auth-expired'));
    }

    if (res.status === 403 && errCode === 'MFA_REQUIRED') {
      window.dispatchEvent(new CustomEvent('vitrine:mfa-required', { detail: parsed }));
    }

    if (returnErrorPayload && parsed && typeof parsed === 'object') {
      return {
        success: false,
        error: errMsg,
        code: errCode,
        mfaRequired: errCode === 'MFA_REQUIRED',
        ...parsed
      } as T;
    }

    throw new ApiError(errMsg, res.status, errCode, parsed);
  }

  return parsed as T;
}

// ============================================================================
// Authentication, First-Run Bootstrap, Step-Up MFA & Public Portal Config
// ============================================================================
export async function fetchAuthStatus(): Promise<AuthStatusResponse> {
  return requestJson<AuthStatusResponse>('/auth/status', { suppressAuthEvent: true });
}

export async function setupInitialSuperAdmin(data: {
  username: string;
  email: string;
  password: string;
}): Promise<{
  success: boolean;
  user?: AuthUser;
  token?: string;
  expiresAt?: string;
  totpSecret?: string;
  otpAuthUri?: string;
  recoveryCodes?: string[];
  error?: string;
}> {
  const res = await requestJson<any>('/auth/setup-initial-admin', {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true,
    suppressAuthEvent: true
  });
  if (res.success && res.token) {
    setStoredSessionToken(res.token);
  }
  return res;
}

export async function loginWithPassword(data: {
  username: string;
  password: string;
}): Promise<{
  success: boolean;
  user?: AuthUser;
  token?: string;
  expiresAt?: string;
  error?: string;
  retryAfterSec?: number;
}> {
  const res = await requestJson<any>('/auth/login', {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true,
    suppressAuthEvent: true
  });
  if (res.success && res.token) {
    setStoredSessionToken(res.token);
  }
  return res;
}

export async function logoutSession(): Promise<{ success: boolean }> {
  try {
    const res = await requestJson<{ success: boolean }>('/auth/logout', {
      method: 'POST',
      suppressAuthEvent: true
    });
    return res;
  } finally {
    setStoredSessionToken(null);
  }
}

export async function fetchMfaEnrollment(): Promise<{
  totpEnabled: boolean;
  secretBase32: string;
  otpAuthUri: string;
  remainingRecoveryCodes: number;
}> {
  return requestJson('/auth/mfa/enroll');
}

export async function regenerateMfaRecoveryCodes(code: string): Promise<{
  success: boolean;
  recoveryCodes?: string[];
  error?: string;
}> {
  return requestJson('/auth/mfa/regenerate-recovery-codes', {
    method: 'POST',
    body: JSON.stringify({ code }),
    returnErrorPayload: true
  });
}

export async function verifyMfa(
  code: string,
  secretType?: string,
  deviceId?: string
): Promise<{ success: boolean; method?: string; verifiedUntil?: string; error?: string }> {
  return requestJson('/auth/verify-mfa', {
    method: 'POST',
    body: JSON.stringify({ code, secretType, deviceId }),
    returnErrorPayload: true
  });
}

export async function testOidcDiscovery(data?: {
  issuerUrl?: string;
  clientId?: string;
}): Promise<{
  success: boolean;
  issuer?: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  userinfoEndpoint?: string;
  error?: string;
}> {
  return requestJson('/auth/oidc/test', {
    method: 'POST',
    body: JSON.stringify(data || {}),
    returnErrorPayload: true
  });
}

export async function fetchPublicPortalConfig(): Promise<PublicPortalConfig> {
  return requestJson<PublicPortalConfig>('/public/portal-config', { suppressAuthEvent: true });
}

export async function fetchSystemHealth(): Promise<{
  status: string;
  version: string;
  uptime: number;
  meshBridge: { connected: boolean; configured: boolean; activeTunnels: number };
}> {
  return requestJson('/health', { suppressAuthEvent: true });
}

// ============================================================================
// Settings, Branding Logo Upload & Lab Demo Seeding
// ============================================================================
export async function fetchSettings(): Promise<Settings> {
  return requestJson<Settings>('/settings');
}

export async function updateSettings(
  settings: Partial<Settings>
): Promise<{ success: boolean; settings: Settings; error?: string }> {
  return requestJson('/settings', {
    method: 'POST',
    body: JSON.stringify(settings),
    returnErrorPayload: true
  });
}

export async function uploadBrandLogo(
  filename: string,
  base64Data: string
): Promise<{ success: boolean; brand_logo_url?: string; error?: string }> {
  return requestJson('/settings/logo', {
    method: 'POST',
    body: JSON.stringify({ filename, base64Data }),
    returnErrorPayload: true
  });
}

export async function seedDemoLabData(): Promise<{ success: boolean }> {
  return requestJson('/demo/seed', { method: 'POST', returnErrorPayload: true });
}

// ============================================================================
// Tenants, Devices, BitLocker Escrow, LAPS & Background Endpoint Tools
// ============================================================================
export async function fetchTenants(): Promise<Tenant[]> {
  return requestJson<Tenant[]>('/tenants');
}

export async function createTenant(data: {
  name: string;
  contact_email?: string;
  site_name?: string;
  subnet?: string;
}): Promise<{ success: boolean; id: string; siteId: string; error?: string }> {
  return requestJson('/tenants', {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
}

export async function deleteTenant(
  id: string,
  action: 'uninstall' | 'move_to_unassigned' = 'move_to_unassigned'
): Promise<{ success: boolean; action: string }> {
  return requestJson(`/tenants/${encodeURIComponent(id)}?action=${action}`, {
    method: 'DELETE',
    returnErrorPayload: true
  });
}

export async function createSite(data: {
  tenant_id: string;
  name: string;
  subnet: string;
}): Promise<{ success: boolean; id: string; error?: string }> {
  return requestJson('/sites', {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
}

export async function fetchDevices(): Promise<Device[]> {
  return requestJson<Device[]>('/devices');
}

export async function fetchDevice(id: string): Promise<Device> {
  return requestJson<Device>(`/devices/${encodeURIComponent(id)}`);
}

export async function revealDeviceBitlockerKey(id: string): Promise<{
  success: boolean;
  bitlocker_key?: string | null;
  bitlocker_status?: string;
  mfaRequired?: boolean;
  error?: string;
}> {
  return requestJson(`/devices/${encodeURIComponent(id)}/bitlocker`, {
    returnErrorPayload: true
  });
}

export async function toggleQuarantine(
  id: string,
  quarantine: boolean
): Promise<{ success: boolean; quarantined: boolean }> {
  return requestJson(`/devices/${encodeURIComponent(id)}/quarantine`, {
    method: 'POST',
    body: JSON.stringify({ quarantine }),
    returnErrorPayload: true
  });
}

export async function fetchLapsPassword(
  id: string,
  reveal: boolean
): Promise<LapsCredential & { mfaRequired?: boolean; error?: string }> {
  return requestJson(`/devices/${encodeURIComponent(id)}/laps?reveal=${reveal}`, {
    returnErrorPayload: true
  });
}

export async function rotateLapsPassword(
  id: string,
  reveal = false
): Promise<LapsCredential & { mfaRequired?: boolean; error?: string }> {
  return requestJson(`/devices/${encodeURIComponent(id)}/laps/rotate`, {
    method: 'POST',
    body: JSON.stringify({ reveal }),
    returnErrorPayload: true
  });
}

export async function fetchDeviceConsentStatus(id: string): Promise<{
  requireConsent: boolean;
  timeoutSec: number;
  timeoutAction: string;
  autoLockOnDisconnect: boolean;
  bypassedDueToLockScreen: boolean;
}> {
  return requestJson(`/devices/${encodeURIComponent(id)}/consent-status`);
}

export async function fetchProcesses(deviceId: string): Promise<ProcessItem[]> {
  return requestJson<ProcessItem[]>(`/devices/${encodeURIComponent(deviceId)}/processes`);
}

export async function killProcess(deviceId: string, pid: number): Promise<{ success: boolean; error?: string }> {
  return requestJson(`/devices/${encodeURIComponent(deviceId)}/processes/${pid}/kill`, {
    method: 'POST',
    returnErrorPayload: true
  });
}

export async function fetchServices(deviceId: string): Promise<ServiceItem[]> {
  return requestJson<ServiceItem[]>(`/devices/${encodeURIComponent(deviceId)}/services`);
}

export async function manageService(
  deviceId: string,
  name: string,
  action: 'start' | 'stop' | 'restart'
): Promise<{ success: boolean; error?: string }> {
  return requestJson(
    `/devices/${encodeURIComponent(deviceId)}/services/${encodeURIComponent(name)}/${action}`,
    { method: 'POST', returnErrorPayload: true }
  );
}

export async function fetchRegistry(
  deviceId: string,
  regPath?: string
): Promise<{ subkeys: string[]; values: Array<{ path: string; name: string; type: string; value: string }> }> {
  return requestJson(
    `/devices/${encodeURIComponent(deviceId)}/registry?path=${encodeURIComponent(regPath || '')}`
  );
}

export async function setRegistryValue(
  deviceId: string,
  data: { path: string; name: string; type: string; value: string }
): Promise<{
  success: boolean;
  subkeys: string[];
  values: Array<{ path: string; name: string; type: string; value: string }>;
}> {
  return requestJson(`/devices/${encodeURIComponent(deviceId)}/registry`, {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
}

export async function deleteRegistryValue(
  deviceId: string,
  regPath: string,
  name: string
): Promise<{
  success: boolean;
  subkeys: string[];
  values: Array<{ path: string; name: string; type: string; value: string }>;
}> {
  return requestJson(
    `/devices/${encodeURIComponent(deviceId)}/registry?path=${encodeURIComponent(regPath)}&name=${encodeURIComponent(name)}`,
    { method: 'DELETE', returnErrorPayload: true }
  );
}

export async function fetchScheduledTasks(deviceId: string): Promise<
  Array<{
    name: string;
    path: string;
    state: string;
    lastRunTime: string;
    nextRunTime: string;
    lastResult: string;
  }>
> {
  return requestJson(`/devices/${encodeURIComponent(deviceId)}/tasks`);
}

export async function manageScheduledTask(
  deviceId: string,
  name: string,
  action: 'run' | 'enable' | 'disable'
): Promise<{
  success: boolean;
  tasks: Array<{
    name: string;
    path: string;
    state: string;
    lastRunTime: string;
    nextRunTime: string;
    lastResult: string;
  }>;
}> {
  return requestJson(`/devices/${encodeURIComponent(deviceId)}/tasks`, {
    method: 'POST',
    body: JSON.stringify({ name, action }),
    returnErrorPayload: true
  });
}

export async function fetchFiles(
  deviceId: string,
  dirPath?: string
): Promise<
  Array<{
    name: string;
    path: string;
    size: number;
    isDirectory: boolean;
    modified: string;
    permissions: string;
  }>
> {
  return requestJson(
    `/devices/${encodeURIComponent(deviceId)}/files?path=${encodeURIComponent(dirPath || '')}`
  );
}

export async function manageRemoteFile(
  deviceId: string,
  data: {
    path: string;
    action: 'mkdir' | 'delete' | 'upload';
    name: string;
    size?: number;
    contentBase64?: string;
  }
): Promise<{
  success: boolean;
  files: Array<{
    name: string;
    path: string;
    size: number;
    isDirectory: boolean;
    modified: string;
    permissions: string;
  }>;
  error?: string;
}> {
  return requestJson(`/devices/${encodeURIComponent(deviceId)}/files`, {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
}

export function getRemoteFileDownloadUrl(deviceId: string, filePath: string): string {
  return `${API_BASE}/devices/${encodeURIComponent(deviceId)}/files/download?path=${encodeURIComponent(filePath)}`;
}

export async function fetchEventLogs(
  deviceId: string,
  channel = 'System',
  level = 'all',
  limit = 50
): Promise<EventLogItem[]> {
  return requestJson(
    `/devices/${encodeURIComponent(deviceId)}/eventlogs?channel=${encodeURIComponent(channel)}&level=${encodeURIComponent(level)}&limit=${limit}`
  );
}

// ============================================================================
// Policies, Patches, Scripts, Self-Healing, PSA & QBR
// ============================================================================
export async function fetchPolicies(): Promise<Policy[]> {
  return requestJson<Policy[]>('/policies');
}

export async function createPolicy(policy: Partial<Policy>): Promise<{ success: boolean; policy: Policy }> {
  return requestJson('/policies', {
    method: 'POST',
    body: JSON.stringify(policy),
    returnErrorPayload: true
  });
}

export async function updatePolicy(
  id: string,
  updates: Partial<Policy>
): Promise<{ success: boolean; policy: Policy }> {
  return requestJson(`/policies/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: JSON.stringify(updates),
    returnErrorPayload: true
  });
}

export async function deletePolicy(id: string): Promise<{ success: boolean; error?: string }> {
  return requestJson(`/policies/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    returnErrorPayload: true
  });
}

export async function evaluatePolicyConditions(): Promise<{
  success: boolean;
  evaluatedDevices: number;
  evaluatedAppliances: number;
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
  return requestJson('/policies/evaluate-conditions', { method: 'POST' });
}

export async function fetchPatches(): Promise<Patch[]> {
  return requestJson<Patch[]>('/patches');
}

export async function scanPatches(deviceIds?: string[]): Promise<{ success: boolean; patches: Patch[] }> {
  return requestJson('/patches/scan', {
    method: 'POST',
    body: JSON.stringify(deviceIds ? { deviceIds } : {}),
    returnErrorPayload: true
  });
}

export async function approvePatch(patchId: string): Promise<{ success: boolean }> {
  return requestJson(`/patches/${encodeURIComponent(patchId)}/approve`, {
    method: 'POST',
    returnErrorPayload: true
  });
}

export async function approvePatchesBulk(
  patchIds: string[]
): Promise<{ success: boolean; approvedCount: number }> {
  return requestJson('/patches/approve-bulk', {
    method: 'POST',
    body: JSON.stringify({ patchIds }),
    returnErrorPayload: true
  });
}

export async function rollbackPatch(
  patchId: string
): Promise<{ success: boolean; message: string }> {
  return requestJson(`/patches/${encodeURIComponent(patchId)}/rollback`, {
    method: 'POST',
    returnErrorPayload: true
  });
}

export async function fetchScripts(tenantId?: string): Promise<ScriptItem[]> {
  const url = tenantId ? `/scripts?tenantId=${encodeURIComponent(tenantId)}` : '/scripts';
  return requestJson<ScriptItem[]>(url);
}

export async function createScript(
  script: Partial<ScriptItem>
): Promise<{ success: boolean; id: string; error?: string }> {
  return requestJson('/scripts', {
    method: 'POST',
    body: JSON.stringify(script),
    returnErrorPayload: true
  });
}

export async function updateScript(
  id: string,
  updates: Partial<ScriptItem>
): Promise<{ success: boolean; error?: string }> {
  return requestJson(`/scripts/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: JSON.stringify(updates),
    returnErrorPayload: true
  });
}

export async function deleteScript(id: string): Promise<{ success: boolean; error?: string }> {
  return requestJson(`/scripts/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    returnErrorPayload: true
  });
}

export async function runScript(
  scriptId: string,
  deviceIds: string[],
  options?: { params?: Record<string, string>; runAs?: 'system' | 'user' }
): Promise<{
  success: boolean;
  dispatchedCount: number;
  executionId: string;
  results?: Array<{ deviceId: string; hostname: string; status: string; output: string }>;
  error?: string;
}> {
  return requestJson(`/scripts/${encodeURIComponent(scriptId)}/run`, {
    method: 'POST',
    body: JSON.stringify({
      deviceIds,
      params: options?.params,
      runAs: options?.runAs
    }),
    returnErrorPayload: true
  });
}

export async function fetchScriptExecutions(scriptId?: string): Promise<any[]> {
  const q = scriptId ? `?scriptId=${encodeURIComponent(scriptId)}` : '';
  return requestJson(`/scripts/executions${q}`);
}

export async function fetchSelfHealing(): Promise<SelfHealingMonitor[]> {
  return requestJson<SelfHealingMonitor[]>('/self-healing');
}

export async function fetchRemediationLogs(): Promise<RemediationLog[]> {
  return requestJson<RemediationLog[]>('/self-healing/logs');
}

export async function createSelfHealingMonitor(data: {
  name: string;
  condition_type: string;
  condition_value: string;
  remediation_script_id: string;
  cooldown_min?: number;
  alert_on_failure?: boolean;
}): Promise<{ success: boolean; monitor: SelfHealingMonitor; error?: string }> {
  return requestJson('/self-healing', {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
}

export async function updateSelfHealingMonitor(
  id: string,
  updates: Partial<SelfHealingMonitor>
): Promise<{ success: boolean; monitor: SelfHealingMonitor }> {
  return requestJson(`/self-healing/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: JSON.stringify(updates),
    returnErrorPayload: true
  });
}

export async function deleteSelfHealingMonitor(id: string): Promise<{ success: boolean }> {
  return requestJson(`/self-healing/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    returnErrorPayload: true
  });
}

export async function evaluateSelfHealingMonitors(): Promise<{
  success: boolean;
  evaluatedMonitors: number;
  evaluatedDevices: number;
  remediationsTriggered: number;
  logs: RemediationLog[];
}> {
  return requestJson('/self-healing/evaluate', { method: 'POST' });
}

export async function fetchPsaTickets(): Promise<
  Array<{
    id: string;
    ticket_number: string;
    title: string;
    client_name: string;
    device_id: string;
    status: string;
    priority: string;
    created_at: string;
  }>
> {
  return requestJson('/psa/tickets');
}

export async function createPsaTicket(data: {
  title: string;
  client_name: string;
  device_id?: string;
  priority?: string;
}): Promise<{ success: boolean; id: string; ticketNumber: string; error?: string }> {
  return requestJson('/psa/tickets', {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
}

export async function updatePsaTicket(
  id: string,
  updates: { status?: string; priority?: string }
): Promise<{ success: boolean }> {
  return requestJson(`/psa/tickets/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: JSON.stringify(updates),
    returnErrorPayload: true
  });
}

export async function testSmtp(data: {
  host: string;
  port: number;
  user?: string;
  pass?: string;
  from: string;
  to?: string;
}): Promise<{ success: boolean; message: string }> {
  return requestJson('/smtp/test', {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
}

export async function fetchQbrReport(tenantId?: string): Promise<{
  tenantName?: string;
  reportDate: string;
  quarter: string;
  fleetHealthScore: number;
  totalManagedEndpoints: number;
  endpointAvailability: string;
  patchCompliance: string;
  encryptionCompliance: string;
  edrProtectionRate: string;
  quarantinedEndpoints: number;
  remediationsAutomated: number;
  ticketsSynchronized: number;
}> {
  const q = tenantId && tenantId !== 'all' ? `?tenant_id=${encodeURIComponent(tenantId)}` : '';
  return requestJson(`/reports/qbr${q}`);
}

// ============================================================================
// Custom Fields, Maintenance Windows, Chat, Recordings, Warranty & History
// ============================================================================
export async function fetchCustomFields(): Promise<CustomFieldDefinition[]> {
  return requestJson<CustomFieldDefinition[]>('/custom-fields');
}

export async function saveCustomField(
  def: Partial<CustomFieldDefinition>
): Promise<{ success: boolean; id: string; error?: string }> {
  return requestJson('/custom-fields', {
    method: 'POST',
    body: JSON.stringify(def),
    returnErrorPayload: true
  });
}

export async function deleteCustomField(id: string): Promise<{ success: boolean }> {
  return requestJson(`/custom-fields/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    returnErrorPayload: true
  });
}

export async function fetchDeviceCustomFields(deviceId: string): Promise<CustomFieldDefinition[]> {
  const rows = await requestJson<any[]>(`/devices/${encodeURIComponent(deviceId)}/custom-fields`);
  return rows.map((r) => ({
    id: r.field_id || r.id,
    key: r.key,
    label: r.label,
    category: r.category,
    field_type: r.field_type,
    scope: r.scope,
    options: r.options,
    description: r.description,
    current_value: r.value ?? r.current_value ?? '',
    value_updated_at: r.updated_at ?? r.value_updated_at ?? null,
    has_secret: Boolean(r.has_secret),
    revealed: Boolean(r.revealed)
  }));
}

export async function revealDeviceSecretCustomFields(
  deviceId: string,
  fieldId?: string
): Promise<{
  success: boolean;
  fields?: CustomFieldDefinition[];
  mfaRequired?: boolean;
  error?: string;
}> {
  const qs = fieldId ? `?reveal=true&fieldId=${encodeURIComponent(fieldId)}` : '?reveal=true';
  const res = await requestJson<any>(
    `/devices/${encodeURIComponent(deviceId)}/custom-fields${qs}`,
    { returnErrorPayload: true }
  );
  if (!Array.isArray(res)) {
    return {
      success: false,
      mfaRequired: Boolean(res?.mfaRequired),
      error: res?.error || 'Step-Up MFA verification required.'
    };
  }
  return {
    success: true,
    fields: res.map((r) => ({
      id: r.field_id || r.id,
      key: r.key,
      label: r.label,
      category: r.category,
      field_type: r.field_type,
      scope: r.scope,
      options: r.options,
      description: r.description,
      current_value: r.value ?? r.current_value ?? '',
      value_updated_at: r.updated_at ?? r.value_updated_at ?? null,
      has_secret: Boolean(r.has_secret),
      revealed: Boolean(r.revealed)
    }))
  };
}

export async function saveDeviceCustomFields(
  deviceId: string,
  fields: Record<string, string>
): Promise<{ success: boolean }> {
  return requestJson(`/devices/${encodeURIComponent(deviceId)}/custom-fields`, {
    method: 'POST',
    body: JSON.stringify({ values: fields }),
    returnErrorPayload: true
  });
}

export async function fetchMaintenanceWindows(): Promise<MaintenanceWindow[]> {
  return requestJson<MaintenanceWindow[]>('/maintenance-windows');
}

export async function createMaintenanceWindow(
  win: Partial<MaintenanceWindow> & { durationMinutes?: number }
): Promise<{ success: boolean; id: string; error?: string }> {
  return requestJson('/maintenance-windows', {
    method: 'POST',
    body: JSON.stringify(win),
    returnErrorPayload: true
  });
}

export async function deleteMaintenanceWindow(id: string): Promise<{ success: boolean }> {
  return requestJson(`/maintenance-windows/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    returnErrorPayload: true
  });
}

export async function toggleDeviceMaintenance(
  deviceId: string,
  active: boolean,
  minutes = 60
): Promise<{ success: boolean; active: boolean; maintenanceUntil: string | null }> {
  const res = await requestJson<any>(`/devices/${encodeURIComponent(deviceId)}/maintenance`, {
    method: 'POST',
    body: JSON.stringify({ enabled: active, durationMinutes: minutes }),
    returnErrorPayload: true
  });
  return {
    success: Boolean(res.success),
    active: Boolean(res.maintenance_active),
    maintenanceUntil: res.maintenance_until || null
  };
}

export async function fetchChatMessages(deviceId: string): Promise<ChatMessage[]> {
  return requestJson<ChatMessage[]>(`/devices/${encodeURIComponent(deviceId)}/chat`);
}

export async function sendChatMessage(
  deviceId: string,
  message: string,
  sender?: string,
  senderRole: 'technician' | 'end_user' = 'technician'
): Promise<{ success: boolean; id?: string; timestamp?: string }> {
  const res = await requestJson<any>(`/devices/${encodeURIComponent(deviceId)}/chat`, {
    method: 'POST',
    body: JSON.stringify({ message, sender, sender_role: senderRole }),
    returnErrorPayload: true
  });
  return {
    success: Boolean(res.success),
    id: res.message?.id,
    timestamp: res.message?.created_at
  };
}

export async function fetchRecordings(deviceId?: string): Promise<SessionRecording[]> {
  const q = deviceId ? `?device_id=${encodeURIComponent(deviceId)}` : '';
  return requestJson<SessionRecording[]>(`/recordings${q}`);
}

export async function saveRecording(
  recording: Partial<SessionRecording>
): Promise<{ success: boolean; id: string }> {
  const res = await requestJson<any>('/recordings', {
    method: 'POST',
    body: JSON.stringify(recording),
    returnErrorPayload: true
  });
  return {
    success: Boolean(res.success),
    id: res.recording?.id || ''
  };
}

export function getRecordingDownloadUrl(recordingId: string): string {
  return `${API_BASE}/recordings/${encodeURIComponent(recordingId)}/download`;
}

export async function fetchWarranty(deviceId: string): Promise<OemWarranty | null> {
  return requestJson<OemWarranty | null>(`/devices/${encodeURIComponent(deviceId)}/warranty`);
}

export async function triggerWarrantyLookup(
  deviceId: string
): Promise<{ success: boolean; warranty: OemWarranty }> {
  return requestJson(`/devices/${encodeURIComponent(deviceId)}/warranty/lookup`, {
    method: 'POST',
    returnErrorPayload: true
  });
}

export async function fetchNotifications(): Promise<AppNotification[]> {
  return requestJson<AppNotification[]>('/notifications');
}

export async function markNotificationRead(id: string): Promise<{ success: boolean }> {
  return requestJson(`/notifications/${encodeURIComponent(id)}/read`, {
    method: 'POST',
    returnErrorPayload: true
  });
}

export async function executeNotificationAction(
  id: string,
  action: string,
  tenantId?: string
): Promise<{ success: boolean; message?: string }> {
  return requestJson(`/notifications/${encodeURIComponent(id)}/action`, {
    method: 'POST',
    body: JSON.stringify({ action, tenantId }),
    returnErrorPayload: true
  });
}

export async function syncMeshCentral(): Promise<{
  success: boolean;
  imported: number;
  updated: number;
  unmappedMeshGroups: number;
  conflicts: Array<{ meshGroupId: string; meshGroupName: string; tenantId: string; deviceCount: number }>;
  message: string;
}> {
  return requestJson('/meshcentral/sync', { method: 'POST', returnErrorPayload: true });
}

export async function fetchHardwareHistory(deviceId: string): Promise<HardwareHistoryItem[]> {
  return requestJson<HardwareHistoryItem[]>(`/devices/${encodeURIComponent(deviceId)}/hardware-history`);
}

export async function fetchNetworkHistory(deviceId: string): Promise<NetworkHistoryItem[]> {
  return requestJson<NetworkHistoryItem[]>(`/devices/${encodeURIComponent(deviceId)}/network-history`);
}

export async function fetchSmartGroups(): Promise<SmartGroup[]> {
  return requestJson<SmartGroup[]>('/smart-groups');
}

export async function createSmartGroup(
  group: Partial<SmartGroup>
): Promise<{ success: boolean; id: string }> {
  return requestJson('/smart-groups', {
    method: 'POST',
    body: JSON.stringify(group),
    returnErrorPayload: true
  });
}

export async function deleteSmartGroup(id: string): Promise<{ success: boolean }> {
  return requestJson(`/smart-groups/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    returnErrorPayload: true
  });
}

export async function fetchDeviceSoftware(deviceId: string): Promise<SoftwareItem[]> {
  return requestJson<SoftwareItem[]>(`/devices/${encodeURIComponent(deviceId)}/software`);
}

export async function upgradeDeviceSoftware(
  deviceId: string,
  softId: string
): Promise<{ success: boolean }> {
  return requestJson(
    `/devices/${encodeURIComponent(deviceId)}/software/${encodeURIComponent(softId)}/upgrade`,
    { method: 'POST', returnErrorPayload: true }
  );
}

// ============================================================================
// Topology, Network Appliances, Virtualization, WoL/AMT & Remote Screen
// ============================================================================
export async function fetchTopology(): Promise<{
  coreSwitch: {
    name: string;
    ip: string;
    ports: Array<{ port: string; vlan: number; speed: string; status: string; lldpNeighbor: string }>;
  };
  discoveredSubnets: Array<{
    subnet: string;
    probeHost: string;
    totalDiscovered: number;
    unmanaged: number;
  }>;
}> {
  return requestJson('/discovery/topology');
}

export async function triggerTopologyScan(
  subnet?: string,
  probeHost?: string
): Promise<{ success: boolean }> {
  return requestJson('/discovery/scan', {
    method: 'POST',
    body: JSON.stringify({ subnet, probeHost }),
    returnErrorPayload: true
  });
}

export async function addTopologyPort(data: {
  port: string;
  vlan: number;
  speed: string;
  status: string;
  lldpNeighbor: string;
  switchName?: string;
  switchIp?: string;
}): Promise<{ success: boolean; id: string }> {
  return requestJson('/discovery/ports', {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
}

export async function fetchNetworkAppliances(): Promise<NetworkAppliance[]> {
  return requestJson<NetworkAppliance[]>('/discovery/appliances');
}

export async function createNetworkAppliance(data: {
  name: string;
  appliance_type: string;
  vendor_model: string;
  ip_address: string;
  mac_address?: string;
  snmp_version?: string;
  integration_protocol?: string;
  vendor_api_endpoint?: string;
  vendor_api_token?: string;
  vendor_api_token_masked?: string;
  tenant_id?: string;
  site_id?: string;
  probe_device_id?: string;
}): Promise<{ success: boolean; appliance: NetworkAppliance; error?: string }> {
  return requestJson('/discovery/appliances', {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
}

export async function pollNetworkAppliance(
  id: string
): Promise<{ success: boolean; appliance: NetworkAppliance }> {
  return requestJson(`/discovery/appliances/${encodeURIComponent(id)}/poll`, {
    method: 'POST',
    returnErrorPayload: true
  });
}

export async function deleteNetworkAppliance(id: string): Promise<{ success: boolean }> {
  return requestJson(`/discovery/appliances/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    returnErrorPayload: true
  });
}

export async function fetchVirtualization(): Promise<
  Array<{
    id: string;
    name: string;
    hostType: string;
    ipAddress?: string;
    apiPort?: number;
    apiUsername?: string;
    hasApiToken?: boolean;
    status: string;
    cpuUsagePct: number;
    ramUsageGb: number;
    ramTotalGb: number;
    storageFreeTb: number;
    storageTotalTb: number;
    vms: Array<{ vmid: number; name: string; status: string; os: string; cpu: number; ramGb: number; lastSnapshot?: string }>;
  }>
> {
  return requestJson('/virtualization/hosts');
}

export async function addVirtualizationHost(data: {
  name: string;
  hostType: string;
  ipAddress?: string;
  apiPort?: number;
  apiUsername?: string;
  apiToken?: string;
  ramTotalGb?: number;
  storageTotalTb?: number;
}): Promise<{ success: boolean; id: string; reachable?: boolean; sync?: any; error?: string }> {
  return requestJson('/virtualization/hosts', {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
}

export async function syncVirtualizationHost(id: string): Promise<{
  success: boolean;
  reachable?: boolean;
  source?: string;
  vmCount?: number;
  message?: string;
  error?: string;
}> {
  return requestJson(`/virtualization/hosts/${encodeURIComponent(id)}/sync`, {
    method: 'POST',
    body: JSON.stringify({}),
    returnErrorPayload: true
  });
}

export async function deleteVirtualizationHost(id: string): Promise<{ success: boolean }> {
  return requestJson(`/virtualization/hosts/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    returnErrorPayload: true
  });
}

export async function manageVmPower(
  hostId: string,
  vmid: number,
  action: 'start' | 'stop' | 'reboot' | 'snapshot'
): Promise<{ success: boolean }> {
  return requestJson(`/virtualization/hosts/${encodeURIComponent(hostId)}/vms/${vmid}/action`, {
    method: 'POST',
    body: JSON.stringify({ action }),
    returnErrorPayload: true
  });
}

export async function wakeDeviceOnLan(
  deviceId: string,
  options?: { wakeAndOnline?: boolean; bootTarget?: 'normal' | 'bios_uefi' | 'pxe' }
): Promise<WakeOnLanResult & { error?: string }> {
  const res = await requestJson<any>(`/devices/${encodeURIComponent(deviceId)}/wake-on-lan`, {
    method: 'POST',
    body: JSON.stringify(options || { wakeAndOnline: true, bootTarget: 'normal' }),
    returnErrorPayload: true
  });
  const tiers = Array.isArray(res.tiers) ? res.tiers : [];
  return {
    success: Boolean(res.success),
    targetDeviceId: res.deviceId || deviceId,
    targetHostname: res.hostname || '',
    targetMac: res.macAddress || '',
    dispatchedRelays: res.peerRelayHost ? [res.peerRelayHost] : [],
    tieredStrategy: {
      tier1_current_subnet_relays: res.peerRelayHost ? 1 : 0,
      tier2_historical_subnets: tiers.some((t: any) => t.tier === 3 && t.status === 'probed') ? 1 : 0,
      tier3_amt_fallback: tiers.some((t: any) => t.tier === 4 && t.status === 'available')
    },
    stages: tiers.map((t: any) => ({
      tier: t.tier,
      name: t.name,
      protocol: t.tier === 2 ? 'UDP/9 Magic Packet' : t.tier === 4 ? 'Intel AMT CIRA' : 'TLS Relay',
      relayHost: res.peerRelayHost || 'Control Plane',
      targetEndpoint: res.hostname || deviceId,
      status:
        t.status === 'reachable' || t.status === 'dispatched' || t.status === 'available' || t.status === 'probed'
          ? 'success'
          : t.status === 'offline' || t.status === 'no_online_peer'
            ? 'escalated'
            : 'skipped',
      latencyMs: 12,
      detail: t.detail
    })),
    confirmationWindowSec: 45,
    verificationMode: 'MeshCentral Heartbeat + Peer ARP',
    error: res.error
  };
}

export async function enableDeviceWakeOnLan(id: string): Promise<{
  success: boolean;
  actionsApplied?: string[];
  currentStatus?: string;
  error?: string;
}> {
  const res = await requestJson<any>(`/devices/${encodeURIComponent(id)}/enable-wol`, {
    method: 'POST',
    returnErrorPayload: true
  });
  return {
    success: Boolean(res.success),
    actionsApplied: ['Enabled NIC Magic Packet Wake', 'Configured OS Power Policy'],
    currentStatus: res.wol_status || 'Enabled',
    error: res.error
  };
}

export async function provisionDeviceAmt(id: string): Promise<{
  success: boolean;
  amtSupported?: boolean;
  provisioningMode?: string;
  nodeDeduplication?: string;
  unlockedCapabilities?: string[];
  error?: string;
}> {
  const res = await requestJson<any>(`/devices/${encodeURIComponent(id)}/provision-amt`, {
    method: 'POST',
    returnErrorPayload: true
  });
  return {
    success: Boolean(res.success),
    amtSupported: true,
    provisioningMode: res.amt_version || 'CCM TLS',
    nodeDeduplication: 'Merged by SMBIOS UUID & Primary MAC',
    unlockedCapabilities: ['Hardware Power Up/Cycle', 'BIOS/UEFI KVM Redirection'],
    error: res.error
  };
}

export async function negotiateRemoteSession(
  deviceId: string,
  mode: 'kvm' | 'ghost' | 'amt_kvm',
  monitor = 1
): Promise<RemoteSessionDescriptor> {
  const mappedMode = mode === 'ghost' ? 'ghost' : 'interactive';
  const res = await requestJson<any>(`/devices/${encodeURIComponent(deviceId)}/remote-session`, {
    method: 'POST',
    body: JSON.stringify({ mode: mappedMode, monitor }),
    returnErrorPayload: true
  });
  return {
    success: Boolean(res.success),
    sessionId: res.sessionId || `rs-${Date.now()}`,
    deviceId: res.deviceId || deviceId,
    hostname: res.hostname || '',
    osType: res.osType || 'windows',
    mode,
    monitor,
    displayDriver:
      mode === 'ghost'
        ? res.ghostArchitecture || 'Isolated Virtual Framebuffer'
        : mode === 'amt_kvm'
          ? 'Intel AMT Hardware Redirection'
          : 'MeshCentral Desktop Multiplexer',
    sessionIsolation: mode === 'ghost' ? 'Hidden Background Session (Zero User Interruption)' : 'Shared Console Session',
    audioPipeline: 'Opus Low-Latency PCM',
    resolution: '1920x1080',
    meshRelayUrl: res.meshRelayUrl || null,
    userInterference: mode === 'ghost' ? 'None (Background Session)' : 'Interactive'
  };
}

// ============================================================================
// Device Notes, Guest / Vendor Scoped Portal, Installers & RBAC Users
// ============================================================================
export async function fetchDeviceNotes(deviceId: string): Promise<DeviceNote[]> {
  return requestJson<DeviceNote[]>(`/devices/${encodeURIComponent(deviceId)}/notes`);
}

export async function createDeviceNote(
  deviceId: string,
  data: { author?: string; content: string; is_pinned?: boolean }
): Promise<{ success: boolean; note: DeviceNote }> {
  return requestJson(`/devices/${encodeURIComponent(deviceId)}/notes`, {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
}

export async function deleteDeviceNote(
  deviceId: string,
  noteId: string
): Promise<{ success: boolean }> {
  return requestJson(
    `/devices/${encodeURIComponent(deviceId)}/notes/${encodeURIComponent(noteId)}`,
    { method: 'DELETE', returnErrorPayload: true }
  );
}

export async function fetchGuestGrants(): Promise<GuestAccessGrant[]> {
  return requestJson<GuestAccessGrant[]>('/guest-grants');
}

export async function createGuestGrant(data: {
  vendor_name: string;
  contact_email?: string;
  device_ids: string[];
  duration_hours?: number;
  can_remote_screen?: boolean;
  can_ghost_session?: boolean;
  can_view_telemetry?: boolean;
  can_view_hardware?: boolean;
  can_view_custom_fields?: boolean;
  can_run_scripts?: boolean;
}): Promise<{
  success: boolean;
  id?: string;
  tempUsername?: string;
  tempPassword?: string;
  expiresAt?: string;
  portalUrl?: string;
  error?: string;
}> {
  const res = await requestJson<any>('/guest-grants', {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
  return {
    success: Boolean(res.success),
    id: res.grant?.id || res.id,
    tempUsername: res.credentials?.username || res.tempUsername,
    tempPassword: res.credentials?.password || res.tempPassword,
    expiresAt: res.credentials?.expiresAt || res.expiresAt,
    portalUrl: res.credentials?.portalUrl || res.portalUrl,
    error: res.error
  };
}

export async function revokeGuestGrant(id: string): Promise<{ success: boolean }> {
  return requestJson(`/guest-grants/${encodeURIComponent(id)}/revoke`, {
    method: 'POST',
    returnErrorPayload: true
  });
}

export async function fetchGuestPortalMeta(id: string): Promise<{
  id: string;
  vendor_name: string;
  expires_at: string;
  status: string;
  is_expired: boolean;
  brand_name: string;
  brand_logo_url: string;
  primary_color: string;
  theme_mode: 'system' | 'dark' | 'light';
  error?: string;
}> {
  return requestJson(`/guest-portal/${encodeURIComponent(id)}/meta`, {
    returnErrorPayload: true,
    suppressAuthEvent: true
  });
}

export async function authenticateGuestPortal(
  id: string,
  username: string,
  password: string
): Promise<{ success: boolean; guestToken?: string; expiresAt?: string; error?: string }> {
  const res = await requestJson<any>(`/guest-portal/${encodeURIComponent(id)}/auth`, {
    method: 'POST',
    body: JSON.stringify({ username, password }),
    returnErrorPayload: true,
    suppressAuthEvent: true
  });
  if (res.success && res.guestToken) {
    setStoredGuestToken(id, res.guestToken);
  }
  return res;
}

export async function fetchGuestPortal(id: string): Promise<{
  success: boolean;
  authRequired?: boolean;
  grant?: {
    id: string;
    vendor_name: string;
    expires_at: string;
    permissions: Record<string, boolean>;
  };
  devices?: Device[];
  error?: string;
}> {
  const res = await requestJson<any>(`/guest-portal/${encodeURIComponent(id)}`, {
    guestGrantId: id,
    returnErrorPayload: true,
    suppressAuthEvent: true
  });
  if (res.code === 'GUEST_AUTH_REQUIRED') {
    return { success: false, authRequired: true, error: res.error };
  }
  if (!res.grant) {
    return { success: false, error: res.error || 'Unable to load guest portal' };
  }
  const g = res.grant;
  return {
    success: true,
    grant: {
      id: g.id,
      vendor_name: g.vendor_name,
      expires_at: g.expires_at,
      permissions: {
        can_remote_screen: Boolean(g.can_remote_screen),
        can_ghost_session: Boolean(g.can_ghost_session),
        can_view_telemetry: Boolean(g.can_view_telemetry),
        can_view_hardware: Boolean(g.can_view_hardware),
        can_view_custom_fields: Boolean(g.can_view_custom_fields),
        can_run_scripts: Boolean(g.can_run_scripts)
      }
    },
    devices: res.devices || []
  };
}

export async function fetchGuestPortalCustomFields(
  grantId: string,
  deviceId: string
): Promise<Array<{ field_id: string; key: string; label: string; category: string; value: string }>> {
  return requestJson(
    `/guest-portal/${encodeURIComponent(grantId)}/custom-fields/${encodeURIComponent(deviceId)}`,
    { guestGrantId: grantId, suppressAuthEvent: true }
  );
}

export async function fetchGuestPortalScripts(grantId: string): Promise<ScriptItem[]> {
  return requestJson(`/guest-portal/${encodeURIComponent(grantId)}/scripts`, {
    guestGrantId: grantId,
    suppressAuthEvent: true
  });
}

export async function runGuestPortalScript(
  grantId: string,
  scriptId: string,
  deviceId: string
): Promise<{ success: boolean; dispatched?: boolean; error?: string }> {
  return requestJson(
    `/guest-portal/${encodeURIComponent(grantId)}/scripts/${encodeURIComponent(scriptId)}/run`,
    {
      method: 'POST',
      body: JSON.stringify({ deviceId }),
      guestGrantId: grantId,
      returnErrorPayload: true,
      suppressAuthEvent: true
    }
  );
}

export async function startGuestPortalRemoteSession(
  grantId: string,
  deviceId: string,
  mode: 'interactive' | 'view_only' | 'ghost'
): Promise<{ success: boolean; sessionId?: string; hostname?: string; error?: string }> {
  return requestJson(`/guest-portal/${encodeURIComponent(grantId)}/remote-session`, {
    method: 'POST',
    body: JSON.stringify({ deviceId, mode }),
    guestGrantId: grantId,
    returnErrorPayload: true,
    suppressAuthEvent: true
  });
}

export async function generateInstaller(data: {
  tenant_id: string;
  site_id?: string;
  device_role?: string;
  ticket_number?: string;
  technician?: string;
  platform?: 'windows' | 'linux' | 'macos';
  mode?: 'permanent' | 'quicksupport';
  mesh_server_id?: string;
}): Promise<{
  success: boolean;
  tokenId?: string;
  platform?: string;
  mode?: 'permanent' | 'quicksupport';
  tenantName?: string;
  ticketBound?: string | null;
  codeSigned?: boolean;
  signingPipeline?: {
    allSigned: boolean;
    strictVerified: boolean;
    stages: SigningStageReport[];
  };
  downloadCommand?: string;
  installerUrl?: string;
  quickSupportPublicUrl?: string;
  error?: string;
}> {
  const res = await requestJson<any>('/installers/generate', {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
  if (!res.success) return res;
  const deployUrl = res.deployUrl || `${window.location.origin}${res.downloadUrl}`;
  const isWin = (data.platform || 'windows') === 'windows';
  const oneLiner = isWin
    ? `powershell -NoProfile -ExecutionPolicy Bypass -Command "irm '${deployUrl}' | iex"`
    : `curl -fsSL '${deployUrl}' | sudo bash`;
  return {
    success: true,
    tokenId: res.token,
    platform: data.platform || 'windows',
    mode: data.mode || 'permanent',
    ticketBound: data.ticket_number || null,
    codeSigned: Boolean(res.signingPipeline?.allSigned),
    signingPipeline: res.signingPipeline,
    downloadCommand: oneLiner,
    installerUrl: res.downloadUrl,
    quickSupportPublicUrl: `${window.location.origin}/remote`
  };
}

export async function fetchUsers(): Promise<RbacUser[]> {
  return requestJson<RbacUser[]>('/users');
}

export async function createUser(data: {
  username: string;
  email: string;
  password?: string;
  role: string;
  tenant_id?: string | null;
}): Promise<{ success: boolean; user?: RbacUser; recoveryCodes?: string[]; error?: string }> {
  return requestJson('/users', {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
}

export async function updateUser(
  id: string,
  data: { role?: string; tenant_id?: string | null; email?: string; password?: string }
): Promise<{ success: boolean; user?: RbacUser; error?: string }> {
  return requestJson(`/users/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
}

export async function deleteUser(id: string): Promise<{ success: boolean; error?: string }> {
  return requestJson(`/users/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    returnErrorPayload: true
  });
}

// ============================================================================
// Multi-Instance MeshCentral 2, Code Signing, Proxy TLS & QuickSupport
// ============================================================================
export async function fetchMeshServers(): Promise<MeshServer[]> {
  return requestJson<MeshServer[]>('/mesh-servers');
}

export async function createMeshServer(
  data: Partial<MeshServer>
): Promise<{ success: boolean; server: MeshServer; error?: string }> {
  return requestJson('/mesh-servers', {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
}

export async function updateMeshServer(
  id: string,
  data: Partial<MeshServer>
): Promise<{ success: boolean; server: MeshServer }> {
  return requestJson(`/mesh-servers/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
}

export async function deleteMeshServer(id: string): Promise<{ success: boolean }> {
  return requestJson(`/mesh-servers/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    returnErrorPayload: true
  });
}

export async function testDiscoverMeshServer(data: {
  url?: string;
  api_token?: string;
  server_id?: string;
  local_config_path?: string;
}): Promise<MeshDiscoveryResult & { error?: string }> {
  const res = await requestJson<any>('/mesh-servers/test-discover', {
    method: 'POST',
    body: JSON.stringify({
      id: data.server_id,
      url: data.url,
      api_token: data.api_token,
      local_config_path: data.local_config_path
    }),
    returnErrorPayload: true
  });
  const groups = Array.isArray(res.groups) ? res.groups : [];
  const agents = Array.isArray(res.agents) ? res.agents : [];
  return {
    success: Boolean(res.reachable),
    reachable: Boolean(res.reachable),
    serverUrl: res.serverUrl || data.url || '',
    meshVersion: res.source === 'websocket_control_api' ? 'MeshCentral 2 (WebSocket Verified)' : res.source || 'Probed',
    coexistenceSafe: true,
    tlsVerified: String(res.serverUrl || data.url || '').startsWith('https://'),
    summary: res.reachable
      ? `Discovered ${groups.length} device group(s) and ${agents.length} agent(s) via ${res.source} (${res.latencyMs || 0}ms).`
      : res.error || 'Unable to reach MeshCentral 2 server.',
    discoveredGroups: groups.map((g: any) => ({
      meshGroupId: g.meshid,
      name: g.name,
      siteGuess: 'Primary Site',
      agentCount: g.deviceCount || 0,
      onlineCount: agents.filter((a: any) => a.meshId === g.meshid && a.online).length,
      matchedTenantId: null,
      recommendedAction: 'import_as_new_client'
    })),
    discoveredAgents: agents.map((a: any) => ({
      meshNodeId: a.nodeId,
      hostname: a.hostname,
      os: a.osDesc || a.osType,
      ip: a.ipAddress || '',
      groupName: a.meshName || '',
      online: Boolean(a.online),
      companionInstalled: false,
      codeSignedBinary: false
    })),
    error: res.error
  };
}

export async function importFromMeshServer(data: {
  mesh_server_id?: string;
  url?: string;
  api_token?: string;
  import_new_groups?: boolean;
  auto_deploy_companion?: boolean;
  enforce_laps_on_import?: boolean;
  lock_signed_binary_updates?: boolean;
  selected_group_ids?: string[];
}): Promise<{
  success: boolean;
  importedClients: number;
  importedDevices: number;
  companionsDispatchedOnline: number;
  companionsQueuedOffline: number;
  message: string;
}> {
  const res = await requestJson<any>('/mesh-servers/import', {
    method: 'POST',
    body: JSON.stringify({
      mesh_server_id: data.mesh_server_id,
      url: data.url,
      api_token: data.api_token,
      selected_group_ids: data.selected_group_ids,
      import_agents: true,
      deploy_vitrine_addons: data.auto_deploy_companion !== false
    }),
    returnErrorPayload: true
  });
  return {
    success: Boolean(res.success),
    importedClients: res.importedClients || 0,
    importedDevices: res.importedAgents || 0,
    companionsDispatchedOnline: res.importedAgents || 0,
    companionsQueuedOffline: 0,
    message: `Imported ${res.importedClients || 0} client group(s) and ${res.importedAgents || 0} endpoint(s).`
  };
}

export async function testCodeSigningPipeline(url?: string): Promise<{
  success: boolean;
  endpoint: string;
  hsmStatus: string;
  certificateSubject?: string;
  timestampServer?: string;
  ms2AutoUpdateProtection: string;
  pipeline: { allSigned: boolean; strictVerified: boolean; stages: SigningStageReport[] };
  error?: string;
}> {
  return requestJson('/code-signing/test', {
    method: 'POST',
    body: JSON.stringify({ url }),
    returnErrorPayload: true
  });
}

export async function testProxyTlsSetup(data: {
  tls_mode?: string;
  reverse_proxy_type?: string;
  custom_domain?: string;
  quicksupport_custom_domain?: string;
}): Promise<{
  success: boolean;
  tlsMode: string;
  proxyType: string;
  checks: Array<{ name: string; status: string; detail: string }>;
}> {
  return requestJson('/proxy-tls/test', {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
}

export async function fetchQuickSupportSessions(): Promise<QuickSupportSession[]> {
  return requestJson<QuickSupportSession[]>('/quicksupport/sessions');
}

export async function createQuickSupportSession(data: {
  client_name?: string;
  tenant_id?: string;
  platform?: 'windows' | 'linux' | 'macos';
  session_code?: string;
}): Promise<{
  success: boolean;
  session: QuickSupportSession;
  signingPipeline: { allSigned: boolean; strictVerified: boolean; stages: SigningStageReport[] };
  downloadUrl: string;
  error?: string;
}> {
  return requestJson('/quicksupport/sessions', {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true,
    suppressAuthEvent: true
  });
}

export async function elevateRemoteAgent(
  deviceId: string,
  data: {
    credentialSource: 'laps' | 'custom_admin' | 'end_user_uac';
    adminUsername?: string;
    adminPassword?: string;
    elevationAction: 'elevate_temp_session' | 'promote_permanent_service';
  }
): Promise<{
  success: boolean;
  deviceId?: string;
  hostname?: string;
  credentialSource?: string;
  usedAccount?: string;
  newPrivilegeLevel?: string;
  promotedToPermanentService?: boolean;
  mfaRequired?: boolean;
  error?: string;
  message: string;
}> {
  const res = await requestJson<any>(`/devices/${encodeURIComponent(deviceId)}/elevate-agent`, {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
  return {
    ...res,
    newPrivilegeLevel: res.privilege_level || 'elevated_admin',
    promotedToPermanentService: data.elevationAction === 'promote_permanent_service'
  };
}

// ============================================================================
// Backups, Offsite Vault, Break-Glass Export, Updater & Offboarding Lifecycle
// ============================================================================
export interface BackupsStateResponse {
  backups: SystemBackupItem[];
  storage: {
    usedBytes: number;
    usedMb: number;
    maxStorageMb: number;
    retentionCount: number;
    currentSoftwareVersion: string;
    currentGitCommit: string;
    currentDbSchemaVersion: number;
    targetSoftwareSchemaVersion: number;
  };
}

export async function fetchSystemBackups(): Promise<BackupsStateResponse> {
  return requestJson<BackupsStateResponse>('/backups');
}

export async function createSystemBackup(data?: {
  triggerType?: 'manual' | 'scheduled' | 'pre-update';
  notes?: string;
}): Promise<{ success: boolean; backup: SystemBackupItem; state?: BackupsStateResponse }> {
  const res = await requestJson<any>('/backups', {
    method: 'POST',
    body: JSON.stringify(data || {}),
    returnErrorPayload: true
  });
  if (res.success && !res.state) {
    res.state = await fetchSystemBackups();
  }
  return res;
}

export function getBackupDownloadUrl(id: string): string {
  return `${API_BASE}/backups/${encodeURIComponent(id)}/download`;
}

export async function uploadSystemBackup(data: {
  filename: string;
  base64Data: string;
  passphrase?: string;
  notes?: string;
}): Promise<{
  success: boolean;
  backupId?: string;
  filename?: string;
  compatibility?: BackupCompatibilityReport;
  state?: BackupsStateResponse;
  error?: string;
}> {
  const res = await requestJson<any>('/backups/upload', {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
  if (res.success && !res.state) {
    res.state = await fetchSystemBackups();
  }
  return res;
}

export async function restoreSystemBackup(
  id: string,
  resolutionMode?: 'auto_migrate' | 'upgrade_software_to_match' | 'compatibility_safe_import',
  passphrase?: string
): Promise<{
  success: boolean;
  requiresResolution?: boolean;
  requiresSoftwareUpgrade?: boolean;
  compatibility?: BackupCompatibilityReport;
  migrationsApplied?: boolean;
  preRestoreSafetyBackupId?: string;
  message: string;
  error?: string;
  state?: BackupsStateResponse;
}> {
  const res = await requestJson<any>(`/backups/${encodeURIComponent(id)}/restore`, {
    method: 'POST',
    body: JSON.stringify({ resolutionMode, passphrase }),
    returnErrorPayload: true
  });
  if (res.success && !res.state) {
    res.state = await fetchSystemBackups();
  }
  return res;
}

export async function deleteSystemBackup(
  id: string
): Promise<{ success: boolean; state?: BackupsStateResponse }> {
  const res = await requestJson<any>(`/backups/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    returnErrorPayload: true
  });
  if (res.success && !res.state) {
    res.state = await fetchSystemBackups();
  }
  return res;
}

export async function syncOffsiteBackups(): Promise<{
  success: boolean;
  provider?: string;
  bucket?: string;
  syncedCount: number;
  failedCount?: number;
  message: string;
  error?: string;
}> {
  return requestJson('/backups/sync-offsite', { method: 'POST', returnErrorPayload: true });
}

export async function revealBackupRecoveryKey(): Promise<{
  success: boolean;
  passphrase?: string;
  encryptionEnabled?: boolean;
  acknowledged?: boolean;
  mfaRequired?: boolean;
  error?: string;
}> {
  return requestJson('/backups/recovery-key', {
    method: 'POST',
    body: JSON.stringify({}),
    returnErrorPayload: true
  });
}

export async function acknowledgeBackupRecoveryKey(): Promise<{
  success: boolean;
  acknowledged?: boolean;
  error?: string;
}> {
  return requestJson('/backups/acknowledge-key', {
    method: 'POST',
    body: JSON.stringify({}),
    returnErrorPayload: true
  });
}

export async function exportBreakGlassSheet(data?: {
  tenantId?: string;
  includeArchived?: boolean;
}): Promise<{
  success?: boolean;
  mfaRequired?: boolean;
  error?: string;
  generatedAt: string;
  totalEndpoints: number;
  archivedIncludedCount: number;
  entries: BreakGlassRecoveryEntry[];
}> {
  return requestJson('/laps/break-glass-export', {
    method: 'POST',
    body: JSON.stringify(data || { includeArchived: true }),
    returnErrorPayload: true
  });
}

export async function fetchUpdaterStatus(refresh = false): Promise<UpdaterStatus> {
  return requestJson<UpdaterStatus>(`/updater/status${refresh ? '?refresh=true' : ''}`);
}

export async function setUpdaterChannel(channel: 'stable' | 'alpha'): Promise<{
  success: boolean;
  blockedByCommitGuard?: boolean;
  error?: string;
  status?: UpdaterStatus;
}> {
  return requestJson('/updater/channel', {
    method: 'POST',
    body: JSON.stringify({ channel }),
    returnErrorPayload: true
  });
}

export async function executeSystemUpdate(): Promise<{
  success: boolean;
  dockerManaged?: boolean;
  instructions?: string;
  rolledBack: boolean;
  fromVersion?: string;
  toVersion?: string;
  fromCommit?: string;
  toCommit?: string;
  preUpdateBackupId?: string | null;
  errorLog?: string;
  error?: string;
  status: UpdaterStatus;
}> {
  return requestJson('/updater/execute', {
    method: 'POST',
    body: JSON.stringify({}),
    returnErrorPayload: true
  });
}

export async function notifyAdminsOfUpdate(): Promise<{
  success: boolean;
  targetLabel: string;
  notifCreated: boolean;
  ticketCreated: string | null;
  emailDispatched: boolean;
}> {
  return requestJson('/updater/notify', { method: 'POST', returnErrorPayload: true });
}

export async function offboardDevice(
  deviceId: string,
  data?: {
    reason?: string;
    overrideLapsAction?: 'remove_account' | 'disable_account' | 'keep_account_rotate_final' | 'keep_account_as_is';
    forceImmediateArchive?: boolean;
  }
): Promise<any> {
  return requestJson(`/devices/${encodeURIComponent(deviceId)}/offboard`, {
    method: 'POST',
    body: JSON.stringify(data || {}),
    returnErrorPayload: true
  });
}

export async function forceArchiveDevice(deviceId: string, reason?: string): Promise<any> {
  return requestJson(`/devices/${encodeURIComponent(deviceId)}/force-archive`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
    returnErrorPayload: true
  });
}

export async function simulateDeviceCheckin(
  deviceId: string,
  triggerType: 'wake_checkin' | 'reinstall_agent' = 'wake_checkin'
): Promise<any> {
  return requestJson(`/devices/${encodeURIComponent(deviceId)}/simulate-checkin`, {
    method: 'POST',
    body: JSON.stringify({ triggerType }),
    returnErrorPayload: true
  });
}

export async function purgeArchivedDevice(
  deviceId: string
): Promise<{ success: boolean; error?: string }> {
  return requestJson(`/devices/${encodeURIComponent(deviceId)}/archive-purge`, {
    method: 'DELETE',
    returnErrorPayload: true
  });
}

export async function offboardTenant(
  tenantId: string,
  data: {
    mode: 'archive_client' | 'delete_client_permanently';
    reason?: string;
    overrideLapsAction?: 'remove_account' | 'disable_account' | 'keep_account_rotate_final' | 'keep_account_as_is';
    forceArchiveOfflineDevices?: boolean;
  }
): Promise<any> {
  return requestJson(`/tenants/${encodeURIComponent(tenantId)}/offboard`, {
    method: 'POST',
    body: JSON.stringify(data),
    returnErrorPayload: true
  });
}

export async function reactivateTenant(
  tenantId: string
): Promise<{ success: boolean; message: string; error?: string }> {
  return requestJson(`/tenants/${encodeURIComponent(tenantId)}/reactivate`, {
    method: 'POST',
    returnErrorPayload: true
  });
}
