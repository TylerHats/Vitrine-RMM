import crypto from 'crypto';
import { db } from '../../db/index.js';
import { decryptVaultSecret, safeOutboundFetch } from '../vault/index.js';

export interface ItflowConfigOptions {
  syncTicketsOnConditions: boolean;
  autoResolveClosedTickets: boolean;
  createNotesOnConditions: boolean;
  defaultNoteType: 'Internal' | 'Public';
  syncTimeEntries: boolean;
  preserveManualAssetNotes: boolean;
  autoSyncNewDevices: boolean;
  includeHardwareInNotes: boolean;
}

export interface ItflowClientRecord {
  client_id: number;
  client_name: string;
  client_type?: string;
  client_website?: string;
  client_notes?: string;
  primary_location_name?: string;
  primary_contact_email?: string;
}

export interface ItflowLocationRecord {
  location_id: number;
  location_name: string;
  location_client_id: number;
  location_address?: string;
  location_city?: string;
  location_state?: string;
  location_zip?: string;
  location_primary?: number;
}

export interface ItflowTenantMappingSuggestion {
  tenant_id: string;
  tenant_name: string;
  tenant_contact_email?: string;
  device_count: number;
  sites: Array<{ id: string; name: string }>;
  existing_mapping: {
    itflow_client_id: number | null;
    itflow_client_name: string | null;
    itflow_default_location_id: number | null;
    sync_enabled: boolean;
    synced_asset_count: number;
  } | null;
  suggested_client_id: number | null;
  suggested_client_name: string | null;
  confidence: number;
  match_reason: string;
}

export interface ItflowNewClientInput {
  name: string;
  type?: string;
  website?: string;
  phone?: string;
  email?: string;
  contactName?: string;
  locationName?: string;
  address?: string;
  city?: string;
  state?: string;
  zip?: string;
  country?: string;
  notes?: string;
}

export interface ItflowMappingAssignmentInput {
  tenantId: string;
  action: 'link' | 'create_new' | 'disable';
  itflowClientId?: number | null;
  itflowClientName?: string | null;
  defaultLocationId?: number | null;
  newClient?: ItflowNewClientInput;
  onExistingAssets?: 'move' | 'duplicate' | 'keep';
  siteMappings?: Array<{
    siteId: string;
    itflowLocationId?: number | null;
    createLocationName?: string;
  }>;
}

export const DEFAULT_ITFLOW_CONFIG_OPTIONS: ItflowConfigOptions = {
  syncTicketsOnConditions: true,
  autoResolveClosedTickets: true,
  createNotesOnConditions: true,
  defaultNoteType: 'Internal',
  syncTimeEntries: true,
  preserveManualAssetNotes: true,
  autoSyncNewDevices: true,
  includeHardwareInNotes: true
};

export function normalizeItflowApiBase(rawUrl: string): string {
  const trimmed = String(rawUrl || '').trim().replace(/\/+$/, '');
  if (!trimmed) return '';
  const phpMatch = trimmed.match(/^(https?:\/\/.+?\/api\/v1)\/.*\.php/i);
  if (phpMatch) return phpMatch[1];
  if (/\/api\/v1$/i.test(trimmed)) return trimmed;
  return `${trimmed}/api/v1`;
}

function isLoopbackAllowedForIntegrations(): boolean {
  return process.env.VITRINE_ALLOW_LOOPBACK_INTEGRATIONS === 'true';
}

export function getItflowRuntimeConfig(overrideCreds?: {
  url?: string;
  apiKey?: string;
  allowSelfSigned?: boolean;
}) {
  const row = (db
    .prepare(
      `SELECT itflow_url, itflow_api_key, itflow_enabled, itflow_setup_completed,
              itflow_sync_interval_min, itflow_last_asset_sync_at, itflow_last_asset_sync_summary,
              itflow_config_json, meshcentral_allow_self_signed, custom_domain
       FROM settings WHERE id = 1`
    )
    .get() || {}) as any;

  let parsedOptions: Partial<ItflowConfigOptions> = {};
  try {
    if (row.itflow_config_json) {
      parsedOptions = JSON.parse(row.itflow_config_json);
    }
  } catch {
    parsedOptions = {};
  }

  const storedKey = decryptVaultSecret(row.itflow_api_key || '');
  const candidateKey = overrideCreds?.apiKey !== undefined ? String(overrideCreds.apiKey).trim() : '';
  const effectiveKey = candidateKey && !candidateKey.includes('•') ? candidateKey : storedKey;
  const rawUrl = overrideCreds?.url !== undefined ? String(overrideCreds.url).trim() : String(row.itflow_url || '').trim();

  return {
    enabled: Boolean(row.itflow_enabled),
    setupCompleted: Boolean(row.itflow_setup_completed),
    rawUrl,
    apiBase: normalizeItflowApiBase(rawUrl),
    apiKey: effectiveKey,
    syncIntervalMin: Math.max(5, Math.min(1440, Number(row.itflow_sync_interval_min || 60))),
    lastAssetSyncAt: row.itflow_last_asset_sync_at || null,
    lastAssetSyncSummary: row.itflow_last_asset_sync_summary || null,
    allowSelfSigned: overrideCreds?.allowSelfSigned ?? Boolean(row.meshcentral_allow_self_signed),
    customDomain: String(row.custom_domain || '').trim(),
    options: {
      ...DEFAULT_ITFLOW_CONFIG_OPTIONS,
      ...parsedOptions
    }
  };
}

export async function itflowApiCall<T = any>(
  method: 'GET' | 'POST',
  endpoint: string,
  payload?: Record<string, any>,
  overrideCreds?: { url?: string; apiKey?: string; allowSelfSigned?: boolean }
): Promise<T & { _empty?: boolean }> {
  const cfg = getItflowRuntimeConfig(overrideCreds);
  if (!cfg.apiBase || !cfg.apiKey) {
    throw new Error('ITFlow URL and API key must both be configured.');
  }

  const cleanEp = endpoint.replace(/^\/+/, '');
  const url = new URL(`${cfg.apiBase}/${cleanEp}`);
  if (method === 'GET' && payload) {
    for (const [k, v] of Object.entries(payload)) {
      if (v !== undefined && v !== null && String(v) !== '') {
        url.searchParams.set(k, String(v));
      }
    }
  }

  const bodyStr =
    method === 'POST'
      ? JSON.stringify({
          ...(payload || {}),
          api_key: cfg.apiKey
        })
      : undefined;

  const res = await safeOutboundFetch(url.toString(), {
    method,
    headers: {
      'X-API-Key': cfg.apiKey,
      ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {})
    },
    body: bodyStr,
    timeoutMs: 12000,
    allowLoopback: isLoopbackAllowedForIntegrations(),
    allowPrivateLan: true,
    allowInsecureTls: cfg.allowSelfSigned
  });

  const rawText = res.text().trim();
  let parsed: any = null;
  if (rawText) {
    try {
      parsed = JSON.parse(rawText);
    } catch {
      throw new Error(`ITFlow ${cleanEp} returned non-JSON HTTP ${res.status}: ${rawText.slice(0, 180)}`);
    }
  }

  const msg = String(parsed?.message || '');
  const isEmptyListNotice =
    method === 'GET' &&
    (/no\s+(results|clients|locations|assets|tickets|records)/i.test(msg) ||
      (res.status === 404 && /no\s+/i.test(msg)));

  if (isEmptyListNotice) {
    return { ...(parsed || {}), data: [], _empty: true } as any;
  }

  if (res.status >= 400) {
    throw new Error(msg || `ITFlow ${cleanEp} failed with HTTP ${res.status}`);
  }

  const explicitFalse =
    parsed &&
    (parsed.success === false ||
      (typeof parsed.success === 'string' && parsed.success.toLowerCase() === 'false'));
  if (explicitFalse && !Array.isArray(parsed.data)) {
    throw new Error(msg || `ITFlow ${cleanEp} rejected request.`);
  }

  return (parsed || {}) as any;
}

export async function testItflowConnection(overrideCreds?: {
  url?: string;
  apiKey?: string;
  allowSelfSigned?: boolean;
}) {
  const cfg = getItflowRuntimeConfig(overrideCreds);
  if (!cfg.apiBase) {
    return { ok: false, apiBase: '', message: 'ITFlow base URL is required.', clientCount: 0, sampleClients: [] };
  }
  if (!cfg.apiKey) {
    return { ok: false, apiBase: cfg.apiBase, message: 'ITFlow API key is required.', clientCount: 0, sampleClients: [] };
  }

  try {
    const clientsRes = await itflowApiCall<any>('GET', 'clients/read.php', { limit: 500 }, overrideCreds);
    const list = Array.isArray(clientsRes?.data) ? clientsRes.data : [];
    const sampleClients = list.slice(0, 5).map((c: any) => ({
      client_id: Number(c.client_id),
      client_name: String(c.client_name || '')
    }));
    return {
      ok: true,
      apiBase: cfg.apiBase,
      clientCount: list.length,
      sampleClients,
      message: `Connected to ITFlow API (${list.length} client(s) discovered).`
    };
  } catch (err: any) {
    return {
      ok: false,
      apiBase: cfg.apiBase,
      clientCount: 0,
      sampleClients: [],
      message: err?.message || 'Unable to connect to ITFlow API.'
    };
  }
}

const CORP_SUFFIX_RE = /\b(llc|inc|incorporated|corp|corporation|ltd|limited|co|company|pllc|pc|lp|llp|group|holdings|services|solutions|it|the)\b/g;

function normalizeCompanyTokens(raw: string): { clean: string; tokens: string[] } {
  const lowered = String(raw || '')
    .toLowerCase()
    .replace(/&/g, ' and ')
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(CORP_SUFFIX_RE, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  const tokens = lowered ? lowered.split(' ').filter(Boolean) : [];
  return { clean: lowered, tokens };
}

function bigrams(s: string): string[] {
  const compact = s.replace(/\s+/g, '');
  if (compact.length < 2) return compact ? [compact] : [];
  const res: string[] = [];
  for (let i = 0; i < compact.length - 1; i++) {
    res.push(compact.slice(i, i + 2));
  }
  return res;
}

function diceSimilarity(a: string, b: string): number {
  if (!a || !b) return 0;
  if (a === b) return 1;
  const bgA = bigrams(a);
  const bgB = bigrams(b);
  if (bgA.length === 0 || bgB.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const x of bgA) counts.set(x, (counts.get(x) || 0) + 1);
  let matches = 0;
  for (const y of bgB) {
    const c = counts.get(y) || 0;
    if (c > 0) {
      matches++;
      counts.set(y, c - 1);
    }
  }
  return (2 * matches) / (bgA.length + bgB.length);
}

function extractDomain(emailOrUrl?: string): string {
  const v = String(emailOrUrl || '').trim().toLowerCase();
  if (!v) return '';
  if (v.includes('@')) return v.split('@').pop()?.trim() || '';
  try {
    const u = new URL(v.startsWith('http') ? v : `https://${v}`);
    return u.hostname.replace(/^www\./, '');
  } catch {
    return '';
  }
}

export function computeFuzzyClientMatch(
  tenantName: string,
  tenantEmail: string | undefined,
  itflowClient: ItflowClientRecord
): { score: number; reason: string } {
  const rawA = String(tenantName || '').trim().toLowerCase();
  const rawB = String(itflowClient.client_name || '').trim().toLowerCase();
  if (!rawA || !rawB) return { score: 0, reason: 'No match' };
  if (rawA === rawB) return { score: 100, reason: 'Exact name match' };

  const normA = normalizeCompanyTokens(tenantName);
  const normB = normalizeCompanyTokens(itflowClient.client_name);

  let score = 0;
  let reason = 'Low similarity';

  if (normA.clean && normA.clean === normB.clean) {
    score = 96;
    reason = 'Normalized business name match';
  } else if (normA.clean && normB.clean && (normA.clean.includes(normB.clean) || normB.clean.includes(normA.clean))) {
    const ratio = Math.min(normA.clean.length, normB.clean.length) / Math.max(normA.clean.length, normB.clean.length);
    score = Math.round(74 + ratio * 18);
    reason = 'Substring company name match';
  } else {
    const dice = diceSimilarity(normA.clean || rawA, normB.clean || rawB);
    const setB = new Set(normB.tokens);
    const overlap = normA.tokens.filter((t) => setB.has(t)).length;
    const jaccard =
      normA.tokens.length + normB.tokens.length > 0
        ? overlap / new Set([...normA.tokens, ...normB.tokens]).size
        : 0;
    score = Math.round(Math.max(dice * 85, jaccard * 88));
    if (score >= 70) reason = 'Strong fuzzy token similarity';
    else if (score >= 50) reason = 'Partial fuzzy match';
  }

  const tenantDom = extractDomain(tenantEmail);
  const clientSiteDom = extractDomain(itflowClient.client_website || itflowClient.primary_contact_email);
  if (tenantDom && clientSiteDom && tenantDom === clientSiteDom && !['gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com'].includes(tenantDom)) {
    score = Math.min(99, score + 20);
    reason = reason === 'Low similarity' ? 'Domain match' : `${reason} + domain match`;
  }

  return { score: Math.max(0, Math.min(100, score)), reason };
}

export async function discoverItflowClientsAndSuggestMappings(overrideCreds?: {
  url?: string;
  apiKey?: string;
  allowSelfSigned?: boolean;
}): Promise<{
  clients: ItflowClientRecord[];
  locations: ItflowLocationRecord[];
  suggestions: ItflowTenantMappingSuggestion[];
}> {
  const [clientsRes, locationsRes] = await Promise.all([
    itflowApiCall<any>('GET', 'clients/read.php', { limit: 1000 }, overrideCreds),
    itflowApiCall<any>('GET', 'locations/read.php', { limit: 1000 }, overrideCreds).catch(() => ({ data: [] }))
  ]);

  const rawClients: any[] = Array.isArray(clientsRes?.data) ? clientsRes.data : [];
  const rawLocations: any[] = Array.isArray(locationsRes?.data) ? locationsRes.data : [];

  const clients: ItflowClientRecord[] = rawClients
    .filter((c) => c && c.client_id !== undefined && c.client_name)
    .map((c) => ({
      client_id: Number(c.client_id),
      client_name: String(c.client_name || ''),
      client_type: c.client_type ? String(c.client_type) : undefined,
      client_website: c.client_website ? String(c.client_website) : undefined,
      client_notes: c.client_notes ? String(c.client_notes) : undefined,
      primary_location_name: c.location_name ? String(c.location_name) : undefined,
      primary_contact_email: c.contact_email ? String(c.contact_email) : undefined
    }));

  const locations: ItflowLocationRecord[] = rawLocations
    .filter((l) => l && l.location_id !== undefined && l.location_name)
    .map((l) => ({
      location_id: Number(l.location_id),
      location_name: String(l.location_name || ''),
      location_client_id: Number(l.location_client_id || l.client_id || 0),
      location_address: l.location_address ? String(l.location_address) : undefined,
      location_city: l.location_city ? String(l.location_city) : undefined,
      location_state: l.location_state ? String(l.location_state) : undefined,
      location_zip: l.location_zip ? String(l.location_zip) : undefined,
      location_primary: Number(l.location_primary || 0)
    }));

  const tenants = db
    .prepare(
      `SELECT t.id, t.name, t.contact_email,
              (SELECT COUNT(*) FROM devices d WHERE d.tenant_id = t.id AND COALESCE(d.status, 'online') != 'archived') as device_count
       FROM tenants t
       ORDER BY t.name ASC`
    )
    .all() as Array<{ id: string; name: string; contact_email: string; device_count: number }>;

  const allSites = db.prepare('SELECT id, tenant_id, name FROM sites ORDER BY name ASC').all() as Array<{
    id: string;
    tenant_id: string;
    name: string;
  }>;

  const existingMaps = db.prepare('SELECT * FROM itflow_tenant_mappings').all() as Array<{
    tenant_id: string;
    itflow_client_id: number | null;
    itflow_client_name: string | null;
    itflow_default_location_id: number | null;
    sync_enabled: number;
  }>;
  const mapByTenant = new Map(existingMaps.map((m) => [m.tenant_id, m]));

  const linkCounts = db
    .prepare(
      `SELECT d.tenant_id, COUNT(*) as cnt
       FROM itflow_asset_links l
       JOIN devices d ON d.id = l.device_id
       GROUP BY d.tenant_id`
    )
    .all() as Array<{ tenant_id: string; cnt: number }>;
  const syncedCountByTenant = new Map(linkCounts.map((r) => [r.tenant_id, Number(r.cnt || 0)]));

  const suggestions: ItflowTenantMappingSuggestion[] = tenants.map((t) => {
    const saved = mapByTenant.get(t.id) || null;
    const tenantSites = allSites.filter((s) => s.tenant_id === t.id).map((s) => ({ id: s.id, name: s.name }));

    let bestClient: ItflowClientRecord | null = null;
    let bestScore = 0;
    let bestReason = 'No confident match found';

    for (const c of clients) {
      const { score, reason } = computeFuzzyClientMatch(t.name, t.contact_email, c);
      if (score > bestScore) {
        bestScore = score;
        bestClient = c;
        bestReason = reason;
      }
    }

    const suggestThreshold = bestScore >= 50;
    return {
      tenant_id: t.id,
      tenant_name: t.name,
      tenant_contact_email: t.contact_email,
      device_count: Number(t.device_count || 0),
      sites: tenantSites,
      existing_mapping: saved
        ? {
            itflow_client_id: saved.itflow_client_id,
            itflow_client_name: saved.itflow_client_name,
            itflow_default_location_id: saved.itflow_default_location_id,
            sync_enabled: Boolean(saved.sync_enabled),
            synced_asset_count: syncedCountByTenant.get(t.id) || 0
          }
        : null,
      suggested_client_id: suggestThreshold && bestClient ? bestClient.client_id : null,
      suggested_client_name: suggestThreshold && bestClient ? bestClient.client_name : null,
      confidence: bestScore,
      match_reason: suggestThreshold ? bestReason : clients.length === 0 ? 'No ITFlow clients exist yet' : 'No confident fuzzy match'
    };
  });

  return { clients, locations, suggestions };
}

export function getTenantRemappingImpact(tenantId: string) {
  const existing = db
    .prepare('SELECT * FROM itflow_tenant_mappings WHERE tenant_id = ?')
    .get(tenantId) as any;
  const linkedAssets = db
    .prepare(
      `SELECT l.device_id, l.itflow_client_id, l.itflow_asset_id, d.hostname
       FROM itflow_asset_links l
       JOIN devices d ON d.id = l.device_id
       WHERE d.tenant_id = ?`
    )
    .all(tenantId) as Array<{
    device_id: string;
    itflow_client_id: number;
    itflow_asset_id: number;
    hostname: string;
  }>;

  return {
    tenantId,
    currentClientId: existing?.itflow_client_id ? Number(existing.itflow_client_id) : null,
    currentClientName: existing?.itflow_client_name || null,
    syncEnabled: Boolean(existing?.sync_enabled),
    syncedAssetCount: linkedAssets.length,
    sampleHostnames: linkedAssets.slice(0, 6).map((a) => a.hostname)
  };
}

export async function applyItflowMappings(
  assignments: ItflowMappingAssignmentInput[],
  overrideCreds?: { url?: string; apiKey?: string; allowSelfSigned?: boolean }
): Promise<{
  success: boolean;
  linkedTenants: number;
  createdClients: number;
  disabledTenants: number;
  locationsCreated: number;
  assetsMovedDeletedOld: number;
  assetsDuplicatedKeptOld: number;
  warnings: string[];
}> {
  const warnings: string[] = [];
  let linkedTenants = 0;
  let createdClients = 0;
  let disabledTenants = 0;
  let locationsCreated = 0;
  let assetsMovedDeletedOld = 0;
  let assetsDuplicatedKeptOld = 0;

  let cachedClients: ItflowClientRecord[] = [];
  if (assignments.some((a) => a.action === 'link')) {
    try {
      const clRes = await itflowApiCall<any>('GET', 'clients/read.php', { limit: 1000 }, overrideCreds);
      cachedClients = Array.isArray(clRes?.data)
        ? clRes.data.map((c: any) => ({
            client_id: Number(c.client_id),
            client_name: String(c.client_name || '')
          }))
        : [];
    } catch {
      cachedClients = [];
    }
  }

  for (const item of assignments) {
    if (!item.tenantId) continue;
    const tenantRow = db.prepare('SELECT id, name, contact_email FROM tenants WHERE id = ?').get(item.tenantId) as
      | { id: string; name: string; contact_email: string }
      | undefined;
    if (!tenantRow) {
      warnings.push(`Tenant ${item.tenantId} not found.`);
      continue;
    }

    const prevMap = db.prepare('SELECT * FROM itflow_tenant_mappings WHERE tenant_id = ?').get(item.tenantId) as any;
    const prevClientId = prevMap?.itflow_client_id ? Number(prevMap.itflow_client_id) : null;

    let targetClientId: number | null = null;
    let targetClientName: string | null = null;
    let targetDefaultLocId: number | null = item.defaultLocationId ? Number(item.defaultLocationId) : null;
    let syncEnabled = 0;
    let autoCreated = 0;

    if (item.action === 'create_new') {
      const nc = item.newClient || { name: tenantRow.name };
      const clientName = String(nc.name || tenantRow.name).trim();
      if (!clientName) {
        warnings.push(`Skipped creating client for ${tenantRow.name}: client name is required.`);
        continue;
      }

      const createClientRes = await itflowApiCall<any>(
        'POST',
        'clients/create.php',
        {
          client_name: clientName,
          client_type: String(nc.type || 'Business').trim() || 'Business',
          client_website: String(nc.website || '').trim(),
          client_notes: String(nc.notes || `Managed by Vitrine RMM (Tenant: ${tenantRow.name})`).trim()
        },
        overrideCreds
      );

      const newClientId = Number(createClientRes?.insert_id || createClientRes?.data?.insert_id || createClientRes?.client_id || 0);
      if (!newClientId) {
        throw new Error(`ITFlow did not return an insert_id when creating client '${clientName}'.`);
      }

      createdClients++;
      autoCreated = 1;
      syncEnabled = 1;
      targetClientId = newClientId;
      targetClientName = clientName;

      if (nc.contactName || nc.email || nc.phone) {
        try {
          await itflowApiCall(
            'POST',
            'contacts/create.php',
            {
              client_id: newClientId,
              contact_name: String(nc.contactName || `${clientName} Primary Contact`).trim(),
              contact_email: String(nc.email || tenantRow.contact_email || '').trim(),
              contact_phone: String(nc.phone || '').trim(),
              contact_primary: 1
            },
            overrideCreds
          );
        } catch (err: any) {
          warnings.push(`Client '${clientName}' created (#${newClientId}), but primary contact failed: ${err?.message}`);
        }
      }

      if (nc.locationName || nc.address || nc.city || nc.state || nc.zip) {
        try {
          const locRes = await itflowApiCall<any>(
            'POST',
            'locations/create.php',
            {
              client_id: newClientId,
              location_name: String(nc.locationName || 'Primary Office').trim(),
              location_address: String(nc.address || '').trim(),
              location_city: String(nc.city || '').trim(),
              location_state: String(nc.state || '').trim(),
              location_zip: String(nc.zip || '').trim(),
              location_country: String(nc.country || 'US').trim(),
              location_primary: 1
            },
            overrideCreds
          );
          const createdLocId = Number(locRes?.insert_id || locRes?.location_id || 0);
          if (createdLocId > 0) {
            targetDefaultLocId = createdLocId;
            locationsCreated++;
          }
        } catch (err: any) {
          warnings.push(`Client '${clientName}' created (#${newClientId}), but primary location failed: ${err?.message}`);
        }
      }
    } else if (item.action === 'link') {
      const chosenId = Number(item.itflowClientId || 0);
      if (!chosenId) {
        warnings.push(`Tenant ${tenantRow.name} selected link without an ITFlow client ID.`);
        continue;
      }
      const found = cachedClients.find((c) => c.client_id === chosenId);
      targetClientId = chosenId;
      targetClientName = item.itflowClientName || found?.client_name || `ITFlow Client #${chosenId}`;
      syncEnabled = 1;
      linkedTenants++;
    } else {
      syncEnabled = 0;
      targetClientId = null;
      targetClientName = null;
      targetDefaultLocId = null;
      disabledTenants++;
    }

    // Handle previously synced assets when switching ITFlow clients or disabling sync
    const priorLinks = db
      .prepare(
        `SELECT l.device_id, l.itflow_client_id, l.itflow_asset_id
         FROM itflow_asset_links l
         JOIN devices d ON d.id = l.device_id
         WHERE d.tenant_id = ?`
      )
      .all(item.tenantId) as Array<{ device_id: string; itflow_client_id: number; itflow_asset_id: number }>;

    const clientChanged = priorLinks.some((l) => l.itflow_client_id !== targetClientId);
    if (priorLinks.length > 0 && (clientChanged || (item.action === 'disable' && item.onExistingAssets === 'move'))) {
      const strategy = item.onExistingAssets || 'duplicate';
      if (strategy === 'move') {
        for (const lnk of priorLinks) {
          try {
            await itflowApiCall(
              'POST',
              'assets/delete.php',
              { asset_id: lnk.itflow_asset_id, client_id: lnk.itflow_client_id },
              overrideCreds
            );
            assetsMovedDeletedOld++;
          } catch (err: any) {
            warnings.push(`Failed removing old ITFlow asset #${lnk.itflow_asset_id} during move: ${err?.message}`);
          }
          db.prepare('DELETE FROM itflow_asset_links WHERE device_id = ?').run(lnk.device_id);
        }
      } else {
        assetsDuplicatedKeptOld += priorLinks.length;
        db.prepare('DELETE FROM itflow_asset_links WHERE device_id IN (SELECT id FROM devices WHERE tenant_id = ?)').run(
          item.tenantId
        );
      }
    }

    db.prepare(
      `INSERT INTO itflow_tenant_mappings (
         tenant_id, itflow_client_id, itflow_client_name, itflow_default_location_id,
         sync_enabled, auto_created, updated_at
       ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(tenant_id) DO UPDATE SET
         itflow_client_id = excluded.itflow_client_id,
         itflow_client_name = excluded.itflow_client_name,
         itflow_default_location_id = excluded.itflow_default_location_id,
         sync_enabled = excluded.sync_enabled,
         auto_created = CASE WHEN excluded.auto_created = 1 THEN 1 ELSE itflow_tenant_mappings.auto_created END,
         updated_at = CURRENT_TIMESTAMP`
    ).run(item.tenantId, targetClientId, targetClientName, targetDefaultLocId, syncEnabled, autoCreated);

    if (targetClientId && Array.isArray(item.siteMappings)) {
      for (const sm of item.siteMappings) {
        if (!sm.siteId) continue;
        let locId = sm.itflowLocationId ? Number(sm.itflowLocationId) : null;
        let locName: string | null = null;
        if (!locId && sm.createLocationName?.trim()) {
          try {
            const locRes = await itflowApiCall<any>(
              'POST',
              'locations/create.php',
              {
                client_id: targetClientId,
                location_name: sm.createLocationName.trim(),
                location_primary: 0
              },
              overrideCreds
            );
            const newLocId = Number(locRes?.insert_id || locRes?.location_id || 0);
            if (newLocId > 0) {
              locId = newLocId;
              locName = sm.createLocationName.trim();
              locationsCreated++;
            }
          } catch (err: any) {
            warnings.push(`Location '${sm.createLocationName}' creation failed: ${err?.message}`);
          }
        }

        if (locId) {
          db.prepare(
            `INSERT INTO itflow_site_mappings (site_id, tenant_id, itflow_client_id, itflow_location_id, itflow_location_name, updated_at)
             VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
             ON CONFLICT(site_id) DO UPDATE SET
               itflow_client_id = excluded.itflow_client_id,
               itflow_location_id = excluded.itflow_location_id,
               itflow_location_name = excluded.itflow_location_name,
               updated_at = CURRENT_TIMESTAMP`
          ).run(sm.siteId, item.tenantId, targetClientId, locId, locName);
        } else {
          db.prepare('DELETE FROM itflow_site_mappings WHERE site_id = ?').run(sm.siteId);
        }
      }
    } else if (item.action === 'disable') {
      db.prepare('DELETE FROM itflow_site_mappings WHERE tenant_id = ?').run(item.tenantId);
    }

    if (prevClientId !== targetClientId) {
      db.prepare('INSERT INTO audit_logs (id, username, action, details) VALUES (?, ?, ?, ?)').run(
        `aud-itf-${crypto.randomUUID().slice(0, 8)}`,
        'system',
        'ITFlow Client Mapping Updated',
        `Tenant ${tenantRow.name} -> ${targetClientId ? `${targetClientName} (#${targetClientId})` : 'Sync Disabled'}`
      );
    }
  }

  return {
    success: true,
    linkedTenants,
    createdClients,
    disabledTenants,
    locationsCreated,
    assetsMovedDeletedOld,
    assetsDuplicatedKeptOld,
    warnings
  };
}

function mapVitrineRoleToItflowAssetType(device: any): string {
  const role = String(device.device_role || '').toLowerCase();
  const os = String(device.os_type || '').toLowerCase();
  if (role.includes('virtual') || role.includes('vm')) return 'Virtual Machine';
  if (role.includes('server') || role.includes('domain controller') || role.includes('hypervisor')) return 'Server';
  if (role.includes('laptop')) return 'Laptop';
  if (role.includes('desktop') || role.includes('workstation')) return 'Desktop';
  if (os === 'macos') return 'Laptop';
  return 'Desktop';
}

function parseJsonSafe(raw: string | null | undefined, fallback: any) {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

export function buildItflowAssetPayload(device: any, cfg: ReturnType<typeof getItflowRuntimeConfig>, mapping: any, siteMap?: any) {
  const hw = parseJsonSafe(device.hardware_details_json, {});
  const sys = hw?.system || {};
  const locationId = Number(siteMap?.itflow_location_id || mapping?.itflow_default_location_id || 0);
  const publicBase = cfg.customDomain
    ? (cfg.customDomain.startsWith('http') ? cfg.customDomain : `https://${cfg.customDomain}`).replace(/\/+$/, '')
    : (process.env.VITRINE_PUBLIC_URL || '').replace(/\/+$/, '');
  const deepLink = publicBase ? `${publicBase}/?device=${encodeURIComponent(device.id)}` : '';

  const cfRows = db
    .prepare(
      `SELECT d.key, d.label, v.value
       FROM custom_field_values v
       JOIN custom_field_definitions d ON d.id = v.field_id
       WHERE v.entity_id = ? AND COALESCE(d.field_type, 'text') != 'secret'`
    )
    .all(device.id) as Array<{ key: string; label: string; value: string }>;
  const cfMap = new Map(cfRows.map((r) => [r.key.toLowerCase(), r.value]));

  const osString = [device.os_version || device.os_type, device.os_build ? `(${device.os_build})` : '']
    .filter(Boolean)
    .join(' ')
    .slice(0, 120);
  const make = String(device.manufacturer || sys.manufacturer || '').trim();
  const model = String(device.model || sys.model || '').trim();
  const serial = String(device.serial_number || sys.serialNumber || '').trim();

  const descParts = [
    device.cpu_model ? `CPU: ${device.cpu_model} (${device.cpu_cores || '?'}c)` : '',
    device.ram_total_gb ? `RAM: ${Number(device.ram_total_gb).toFixed(1)} GB` : '',
    device.disk_total_gb ? `Disk: ${Number(device.disk_total_gb).toFixed(0)} GB` : '',
    device.bios_version ? `BIOS: ${device.bios_version}` : '',
    device.edr_name || device.edr_status ? `EDR: ${device.edr_name || device.edr_status}` : '',
    device.bitlocker_status && device.bitlocker_status !== 'Unknown' ? `Disk Enc: ${device.bitlocker_status}` : '',
    device.logged_in_user ? `Last User: ${device.logged_in_user}` : ''
  ].filter(Boolean);

  const noteLines = [
    `Vitrine RMM Asset Telemetry (Synced ${new Date().toISOString().slice(0, 16)}Z)`,
    `Vitrine Device ID: ${device.id}`,
    `Role: ${device.device_role || 'Workstation'} | Status: ${device.status || 'online'}`,
    `Private IP: ${device.ip_address || 'N/A'} | Public IP: ${device.public_ip || 'N/A'}`,
    `CPU: ${device.cpu_model || 'N/A'} | RAM: ${device.ram_total_gb || 0} GB | Disk Free: ${device.disk_free_gb || 0}/${device.disk_total_gb || 0} GB`,
    `Pending Reboot: ${device.pending_reboot ? 'Yes' : 'No'} | Software Packages: ${Number(device.software_count || 0)} | Pending Patches: ${Number(device.pending_patch_count || 0)}`,
    ...(device.logged_in_user ? [`Logged-In User: ${device.logged_in_user}`] : []),
    ...(cfRows.slice(0, 6).map((c) => `${c.label}: ${c.value}`))
  ];

  const payload: Record<string, any> = {
    client_id: Number(mapping.itflow_client_id),
    asset_client_id: Number(mapping.itflow_client_id),
    asset_name: String(device.hostname || device.id),
    asset_type: mapVitrineRoleToItflowAssetType(device),
    asset_make: make,
    asset_model: model,
    asset_serial: serial,
    asset_os: osString,
    asset_ip: String(device.ip_address || ''),
    asset_nat_ip: String(device.public_ip || ''),
    asset_mac: String(device.mac_address || ''),
    asset_uri: deepLink,
    asset_location_id: locationId || 0,
    asset_status: device.status === 'decommissioned' || device.status === 'archived' ? 'Retired' : 'Deployed',
    asset_description: descParts.join(' | ').slice(0, 500),
    asset_warranty_expire: cfMap.get('warranty_expire') || cfMap.get('warranty_expiration') || '',
    asset_purchase_date: cfMap.get('purchase_date') || '',
    _vitrineNotesBlock: noteLines.join('\n')
  };

  // Stable comparison hash excluding current timestamp
  const hashInput = JSON.stringify({
    ...payload,
    _vitrineNotesBlock: noteLines.slice(1).join('\n')
  });
  const payloadHash = crypto.createHash('sha256').update(hashInput).digest('hex');

  return { payload, payloadHash };
}

export async function syncDeviceAssetToItflow(
  deviceId: string,
  options?: { force?: boolean }
): Promise<{ ok: boolean; action: 'created' | 'updated' | 'skipped' | 'failed'; assetId?: number; error?: string }> {
  const cfg = getItflowRuntimeConfig();
  if (!cfg.enabled || !cfg.apiBase || !cfg.apiKey) {
    return { ok: true, action: 'skipped', error: 'ITFlow integration disabled or incomplete.' };
  }

  const device = db
    .prepare('SELECT d.* FROM devices d WHERE d.id = ?')
    .get(deviceId) as any;
  if (!device) {
    return { ok: false, action: 'failed', error: 'Device not found' };
  }

  const mapping = db
    .prepare('SELECT * FROM itflow_tenant_mappings WHERE tenant_id = ?')
    .get(device.tenant_id) as any;
  if (!mapping || !mapping.sync_enabled || !mapping.itflow_client_id) {
    return { ok: true, action: 'skipped', error: 'Tenant ITFlow sync disabled.' };
  }

  const siteMap = device.site_id
    ? (db.prepare('SELECT * FROM itflow_site_mappings WHERE site_id = ?').get(device.site_id) as any)
    : null;
  const existingLink = db.prepare('SELECT * FROM itflow_asset_links WHERE device_id = ?').get(device.id) as any;

  const { payload, payloadHash } = buildItflowAssetPayload(device, cfg, mapping, siteMap);
  const { _vitrineNotesBlock, ...apiPayloadBase } = payload;

  if (!options?.force && existingLink && existingLink.last_payload_hash === payloadHash && existingLink.itflow_client_id === mapping.itflow_client_id) {
    return { ok: true, action: 'skipped', assetId: Number(existingLink.itflow_asset_id) };
  }

  try {
    if (existingLink && Number(existingLink.itflow_client_id) === Number(mapping.itflow_client_id)) {
      const assetId = Number(existingLink.itflow_asset_id);
      const updatePayload: Record<string, any> = {
        ...apiPayloadBase,
        asset_id: assetId
      };
      if (cfg.options.includeHardwareInNotes && !cfg.options.preserveManualAssetNotes) {
        updatePayload.asset_notes = _vitrineNotesBlock;
      }

      try {
        await itflowApiCall('POST', 'assets/update.php', updatePayload);
        db.prepare(
          `UPDATE itflow_asset_links
           SET last_payload_hash = ?, last_synced_at = CURRENT_TIMESTAMP, last_error = NULL
           WHERE device_id = ?`
        ).run(payloadHash, device.id);
        return { ok: true, action: 'updated', assetId };
      } catch (updateErr: any) {
        if (!/not found|404/i.test(String(updateErr?.message || ''))) {
          throw updateErr;
        }
        // Asset was removed inside ITFlow; fall through to re-create
        db.prepare('DELETE FROM itflow_asset_links WHERE device_id = ?').run(device.id);
      }
    }

    const createPayload: Record<string, any> = {
      ...apiPayloadBase,
      ...(cfg.options.includeHardwareInNotes ? { asset_notes: _vitrineNotesBlock } : {})
    };
    const createRes = await itflowApiCall<any>('POST', 'assets/create.php', createPayload);
    const newAssetId = Number(createRes?.insert_id || createRes?.data?.insert_id || createRes?.asset_id || 0);
    if (!newAssetId) {
      throw new Error('ITFlow assets/create.php did not return insert_id');
    }

    db.prepare(
      `INSERT INTO itflow_asset_links (device_id, itflow_client_id, itflow_asset_id, last_payload_hash, last_synced_at, last_error)
       VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, NULL)
       ON CONFLICT(device_id) DO UPDATE SET
         itflow_client_id = excluded.itflow_client_id,
         itflow_asset_id = excluded.itflow_asset_id,
         last_payload_hash = excluded.last_payload_hash,
         last_synced_at = CURRENT_TIMESTAMP,
         last_error = NULL`
    ).run(device.id, Number(mapping.itflow_client_id), newAssetId, payloadHash);

    db.prepare('UPDATE itflow_tenant_mappings SET last_synced_at = CURRENT_TIMESTAMP WHERE tenant_id = ?').run(device.tenant_id);
    return { ok: true, action: 'created', assetId: newAssetId };
  } catch (err: any) {
    const errMsg = String(err?.message || 'ITFlow asset sync failed');
    db.prepare(
      `UPDATE itflow_asset_links SET last_error = ? WHERE device_id = ?`
    ).run(errMsg, device.id);
    return { ok: false, action: 'failed', error: errMsg };
  }
}

export async function syncAllItflowAssets(options?: { force?: boolean; tenantId?: string }): Promise<{
  totalEligible: number;
  created: number;
  updated: number;
  skipped: number;
  failed: number;
  errors: Array<{ deviceId: string; hostname: string; error: string }>;
}> {
  const cfg = getItflowRuntimeConfig();
  if (!cfg.enabled || !cfg.apiBase || !cfg.apiKey) {
    return { totalEligible: 0, created: 0, updated: 0, skipped: 0, failed: 0, errors: [] };
  }

  const devices = db
    .prepare(
      `SELECT d.id, d.hostname
       FROM devices d
       JOIN itflow_tenant_mappings m ON m.tenant_id = d.tenant_id
       WHERE m.sync_enabled = 1 AND m.itflow_client_id IS NOT NULL
         AND COALESCE(d.status, 'online') != 'archived'
         ${options?.tenantId ? 'AND d.tenant_id = ?' : ''}`
    )
    .all(...(options?.tenantId ? [options.tenantId] : [])) as Array<{ id: string; hostname: string }>;

  let created = 0;
  let updated = 0;
  let skipped = 0;
  let failed = 0;
  const errors: Array<{ deviceId: string; hostname: string; error: string }> = [];

  for (const dev of devices) {
    const r = await syncDeviceAssetToItflow(dev.id, { force: options?.force });
    if (r.action === 'created') created++;
    else if (r.action === 'updated') updated++;
    else if (r.action === 'skipped') skipped++;
    else {
      failed++;
      if (r.error) errors.push({ deviceId: dev.id, hostname: dev.hostname, error: r.error });
    }
  }

  const summary = `Checked ${devices.length} endpoint(s): ${created} created, ${updated} updated, ${skipped} unchanged, ${failed} failed`;
  db.prepare(
    `UPDATE settings SET itflow_last_asset_sync_at = CURRENT_TIMESTAMP, itflow_last_asset_sync_summary = ? WHERE id = 1`
  ).run(summary);

  return {
    totalEligible: devices.length,
    created,
    updated,
    skipped,
    failed,
    errors: errors.slice(0, 20)
  };
}

export function resolveItflowClientIdForTicket(params: {
  tenantId?: string | null;
  deviceId?: string | null;
  clientName?: string | null;
}): number | null {
  let effectiveTenantId = params.tenantId || null;
  if (!effectiveTenantId && params.deviceId) {
    const dev = db.prepare('SELECT tenant_id FROM devices WHERE id = ?').get(params.deviceId) as { tenant_id?: string } | undefined;
    effectiveTenantId = dev?.tenant_id || null;
  }
  if (!effectiveTenantId && params.clientName) {
    const t = db
      .prepare('SELECT id FROM tenants WHERE LOWER(name) = LOWER(?) LIMIT 1')
      .get(String(params.clientName).trim()) as { id?: string } | undefined;
    effectiveTenantId = t?.id || null;
  }
  if (!effectiveTenantId) return null;

  const map = db
    .prepare('SELECT itflow_client_id, sync_enabled FROM itflow_tenant_mappings WHERE tenant_id = ?')
    .get(effectiveTenantId) as { itflow_client_id?: number; sync_enabled?: number } | undefined;
  if (!map || !map.sync_enabled || !map.itflow_client_id) return null;
  return Number(map.itflow_client_id);
}

function mapPriorityToItflow(p?: string): string {
  const s = String(p || 'Medium').toLowerCase();
  if (s === 'high' || s === 'critical' || s === 'urgent') return 'High';
  if (s === 'low' || s === 'info') return 'Low';
  return 'Medium';
}

function mapStatusToItflowCode(status?: string): number {
  const s = String(status || 'Open').toLowerCase();
  if (s === 'closed') return 5;
  if (s === 'resolved' || s === 'completed') return 4;
  if (s === 'in progress' || s === 'working' || s === 'active') return 2;
  return 1;
}

export async function createItflowTicket(params: {
  localTicketId: string;
  tenantId?: string | null;
  deviceId?: string | null;
  clientName?: string | null;
  subject: string;
  details: string;
  priority?: string;
}): Promise<{ ok: boolean; externalTicketId?: string; externalClientId?: number; externalAssetId?: number; error?: string }> {
  const cfg = getItflowRuntimeConfig();
  if (!cfg.enabled || !cfg.apiBase || !cfg.apiKey) {
    return { ok: false, error: 'ITFlow not enabled' };
  }

  const clientId = resolveItflowClientIdForTicket({
    tenantId: params.tenantId,
    deviceId: params.deviceId,
    clientName: params.clientName
  });
  if (!clientId) {
    return { ok: false, error: 'No ITFlow client mapping enabled for this tenant.' };
  }

  let assetId: number | undefined;
  if (params.deviceId) {
    let link = db.prepare('SELECT itflow_asset_id, itflow_client_id FROM itflow_asset_links WHERE device_id = ?').get(params.deviceId) as any;
    if (!link && cfg.options.autoSyncNewDevices) {
      const sr = await syncDeviceAssetToItflow(params.deviceId);
      if (sr.assetId) link = { itflow_asset_id: sr.assetId, itflow_client_id: clientId };
    }
    if (link && Number(link.itflow_client_id) === clientId && Number(link.itflow_asset_id) > 0) {
      assetId = Number(link.itflow_asset_id);
    }
  }

  try {
    const res = await itflowApiCall<any>('POST', 'tickets/create.php', {
      ticket_subject: params.subject,
      ticket_details: params.details,
      ticket_priority: mapPriorityToItflow(params.priority),
      ticket_client_id: clientId,
      ...(assetId ? { ticket_asset_id: assetId } : {})
    });
    const externalTicketId = String(res?.insert_id || res?.data?.insert_id || res?.ticket_id || '').trim();
    if (!externalTicketId) {
      throw new Error('ITFlow tickets/create.php did not return ticket insert_id');
    }

    db.prepare(
      `UPDATE psa_tickets
       SET external_provider = 'itflow',
           external_ticket_id = ?,
           external_client_id = ?,
           external_asset_id = ?,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`
    ).run(externalTicketId, Number(clientId), assetId ?? null, params.localTicketId);

    return { ok: true, externalTicketId, externalClientId: clientId, externalAssetId: assetId };
  } catch (err: any) {
    return { ok: false, error: err?.message || 'ITFlow ticket create failed' };
  }
}

export async function updateItflowTicket(
  localTicketId: string,
  patch: { subject?: string; status?: string; priority?: string }
): Promise<{ ok: boolean; error?: string }> {
  const cfg = getItflowRuntimeConfig();
  if (!cfg.enabled || !cfg.apiBase || !cfg.apiKey) return { ok: false, error: 'ITFlow disabled' };

  const ticket = db.prepare('SELECT * FROM psa_tickets WHERE id = ?').get(localTicketId) as any;
  if (!ticket || ticket.external_provider !== 'itflow' || !ticket.external_ticket_id) {
    return { ok: false, error: 'Ticket is not linked to ITFlow' };
  }

  try {
    await itflowApiCall('POST', 'tickets/update.php', {
      ticket_id: Number(ticket.external_ticket_id),
      ticket_subject: patch.subject || ticket.title,
      ticket_priority: mapPriorityToItflow(patch.priority || ticket.priority),
      ticket_status: mapStatusToItflowCode(patch.status || ticket.status)
    });
    db.prepare('UPDATE psa_tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(localTicketId);
    return { ok: true };
  } catch (err: any) {
    return { ok: false, error: err?.message || 'ITFlow ticket update failed' };
  }
}

function formatSecondsAsHhMmSs(totalSec: number): string {
  const sec = Math.max(0, Math.round(totalSec || 0));
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

export async function addItflowTicketNote(params: {
  localTicketId: string;
  author: string;
  body: string;
  noteType?: 'Internal' | 'Public';
  timeWorkedSec?: number;
  status?: string;
}): Promise<{ ok: boolean; noteId: string; syncedExternal: boolean; externalReplyId?: string; error?: string }> {
  const noteId = `note-${crypto.randomUUID().slice(0, 8)}`;
  const noteType: 'Internal' | 'Public' = params.noteType === 'Public' ? 'Public' : 'Internal';
  const workedSec = Math.max(0, Math.round(Number(params.timeWorkedSec || 0)));

  db.prepare(
    `INSERT INTO psa_ticket_notes (id, ticket_id, author, note_type, body, time_worked_sec, synced_external)
     VALUES (?, ?, ?, ?, ?, ?, 0)`
  ).run(noteId, params.localTicketId, params.author || 'system', noteType, params.body, workedSec);

  const cfg = getItflowRuntimeConfig();
  const ticket = db.prepare('SELECT * FROM psa_tickets WHERE id = ?').get(params.localTicketId) as any;
  if (!cfg.enabled || !cfg.apiBase || !cfg.apiKey || !ticket || ticket.external_provider !== 'itflow' || !ticket.external_ticket_id) {
    return { ok: true, noteId, syncedExternal: false };
  }

  try {
    const replyRes = await itflowApiCall<any>('POST', 'ticket_replies/create.php', {
      ticket_id: Number(ticket.external_ticket_id),
      ticket_reply: params.body,
      ticket_reply_type: noteType,
      ticket_reply_time_worked: formatSecondsAsHhMmSs(workedSec),
      ...(params.status ? { ticket_status: mapStatusToItflowCode(params.status) } : {})
    });
    const extReplyId = replyRes?.insert_id ? String(replyRes.insert_id) : undefined;
    db.prepare('UPDATE psa_ticket_notes SET synced_external = 1, external_reply_id = ? WHERE id = ?').run(extReplyId || null, noteId);
    db.prepare('UPDATE psa_tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(params.localTicketId);
    return { ok: true, noteId, syncedExternal: true, externalReplyId: extReplyId };
  } catch (err: any) {
    return { ok: true, noteId, syncedExternal: false, error: err?.message || 'External note sync failed' };
  }
}

export function mapItflowStatusToVitrine(rawStatus: any): string {
  const s = String(rawStatus ?? '').trim();
  const lower = s.toLowerCase();
  if (lower === '5' || lower === 'closed') return 'Closed';
  if (lower === '4' || lower === 'resolved' || lower === 'completed') return 'Resolved';
  if (lower === '3' || lower === 'on hold' || lower === 'hold' || lower === 'pending') return 'On Hold';
  if (lower === '2' || lower === 'working' || lower === 'in progress' || lower === 'active') return 'In Progress';
  if (lower === '1' || lower === 'open' || lower === 'new' || !lower) return 'Open';
  return s;
}

export function getDeviceItflowStatus(deviceId: string): {
  enabled: boolean;
  mappingEnabled: boolean;
  itflowClientId: number | null;
  itflowClientName: string | null;
  itflowAssetId: number | null;
  assetUrl: string | null;
  lastSyncedAt: string | null;
  lastError: string | null;
} {
  const cfg = getItflowRuntimeConfig();
  const device = db.prepare('SELECT id, tenant_id FROM devices WHERE id = ?').get(deviceId) as
    | { id: string; tenant_id: string }
    | undefined;
  if (!device) {
    return {
      enabled: cfg.enabled,
      mappingEnabled: false,
      itflowClientId: null,
      itflowClientName: null,
      itflowAssetId: null,
      assetUrl: null,
      lastSyncedAt: null,
      lastError: null
    };
  }

  const mapping = db
    .prepare('SELECT itflow_client_id, itflow_client_name, sync_enabled FROM itflow_tenant_mappings WHERE tenant_id = ?')
    .get(device.tenant_id) as any;
  const link = db.prepare('SELECT * FROM itflow_asset_links WHERE device_id = ?').get(deviceId) as any;

  const clientId = link?.itflow_client_id ? Number(link.itflow_client_id) : mapping?.itflow_client_id ? Number(mapping.itflow_client_id) : null;
  const assetId = link?.itflow_asset_id ? Number(link.itflow_asset_id) : null;
  const webBase = cfg.apiBase ? cfg.apiBase.replace(/\/api\/v1$/i, '') : '';
  const assetUrl =
    webBase && clientId && assetId
      ? `${webBase}/client_asset_details.php?client_id=${clientId}&asset_id=${assetId}`
      : null;

  return {
    enabled: cfg.enabled,
    mappingEnabled: Boolean(mapping?.sync_enabled),
    itflowClientId: clientId,
    itflowClientName: mapping?.itflow_client_name || null,
    itflowAssetId: assetId,
    assetUrl,
    lastSyncedAt: link?.last_synced_at || null,
    lastError: link?.last_error || null
  };
}

export async function pullItflowTicketUpdates(options?: { localTicketId?: string }): Promise<{
  ok: boolean;
  checked: number;
  updatedTickets: number;
  importedNotes: number;
  errors: string[];
}> {
  const cfg = getItflowRuntimeConfig();
  if (!cfg.enabled || !cfg.apiBase || !cfg.apiKey) {
    return { ok: false, checked: 0, updatedTickets: 0, importedNotes: 0, errors: ['ITFlow is not enabled or configured'] };
  }

  const linkedTickets = (
    options?.localTicketId
      ? db
          .prepare(
            `SELECT * FROM psa_tickets
             WHERE id = ? AND external_provider = 'itflow' AND external_ticket_id IS NOT NULL`
          )
          .all(options.localTicketId)
      : db
          .prepare(
            `SELECT * FROM psa_tickets
             WHERE external_provider = 'itflow' AND external_ticket_id IS NOT NULL
             ORDER BY updated_at DESC LIMIT 100`
          )
          .all()
  ) as any[];

  let updatedTickets = 0;
  let importedNotes = 0;
  const errors: string[] = [];

  for (const tk of linkedTickets) {
    const extId = String(tk.external_ticket_id || '').trim();
    if (!extId) continue;

    try {
      const tkRes = await itflowApiCall<any>('GET', 'tickets/read.php', { ticket_id: extId });
      const rows = Array.isArray(tkRes?.data) ? tkRes.data : tkRes?.data ? [tkRes.data] : [];
      const remote = rows.find((r: any) => String(r?.ticket_id || '') === extId) || rows[0];

      if (remote) {
        const nextStatus = mapItflowStatusToVitrine(remote.ticket_status_name ?? remote.ticket_status ?? tk.status);
        const nextPriority = mapPriorityToItflow(remote.ticket_priority ?? tk.priority);
        const nextSubject = String(remote.ticket_subject || tk.title || '').trim() || tk.title;

        if (nextStatus !== tk.status || nextPriority !== tk.priority || nextSubject !== tk.title) {
          db.prepare(
            `UPDATE psa_tickets
             SET status = ?, priority = ?, title = ?, updated_at = CURRENT_TIMESTAMP
             WHERE id = ?`
          ).run(nextStatus, nextPriority, nextSubject, tk.id);
          updatedTickets++;
        }
      }

      const repRes = await itflowApiCall<any>('GET', 'ticket_replies/read.php', { ticket_id: extId });
      const replies = Array.isArray(repRes?.data) ? repRes.data : [];
      let ticketGotNewReplies = false;

      for (const rep of replies) {
        const extReplyId = String(rep.ticket_reply_id ?? rep.reply_id ?? rep.id ?? '').trim();
        const rawBody = String(rep.ticket_reply ?? rep.reply_body ?? rep.body ?? '').trim();
        if (!rawBody) continue;

        if (extReplyId) {
          const existsByExt = db
            .prepare('SELECT id FROM psa_ticket_notes WHERE ticket_id = ? AND external_reply_id = ?')
            .get(tk.id, extReplyId);
          if (existsByExt) continue;
        } else {
          const existsByBody = db
            .prepare('SELECT id FROM psa_ticket_notes WHERE ticket_id = ? AND body = ? AND synced_external = 1')
            .get(tk.id, rawBody);
          if (existsByBody) continue;
        }

        const rawType = String(rep.ticket_reply_type || '').toLowerCase();
        const noteType: 'Internal' | 'Public' = rawType === 'public' || rawType === 'client' ? 'Public' : 'Internal';
        const author = String(rep.user_name || rep.contact_name || rep.ticket_reply_by_name || rep.author || 'ITFlow').trim();
        const createdAt = rep.ticket_reply_created_at ? String(rep.ticket_reply_created_at) : null;

        db.prepare(
          `INSERT INTO psa_ticket_notes (id, ticket_id, author, note_type, body, time_worked_sec, synced_external, external_reply_id, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 1, ?, COALESCE(?, CURRENT_TIMESTAMP))`
        ).run(
          `note-itf-${crypto.randomUUID().slice(0, 8)}`,
          tk.id,
          author,
          noteType,
          rawBody,
          0,
          extReplyId || null,
          createdAt
        );
        importedNotes++;
        ticketGotNewReplies = true;
      }

      if (ticketGotNewReplies) {
        db.prepare('UPDATE psa_tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(tk.id);
      }
    } catch (err: any) {
      errors.push(`Ticket ${tk.ticket_number || extId}: ${err?.message || 'pull error'}`);
    }
  }

  return { ok: true, checked: linkedTickets.length, updatedTickets, importedNotes, errors };
}
