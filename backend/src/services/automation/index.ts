import crypto from 'crypto';
import { db } from '../../db/index.js';
import { meshBridge } from '../meshcentral/index.js';
import { decryptVaultSecret } from '../vault/index.js';

export interface SmartGroupRule {
  field: string;
  operator: 'eq' | 'neq' | 'contains' | 'not_contains' | 'gt' | 'gte' | 'lt' | 'lte' | 'in';
  value: any;
}

export interface SmartGroupRuleSet {
  combinator?: 'AND' | 'OR';
  rules: SmartGroupRule[];
}

export function evaluateDeviceAgainstRule(device: any, rule: SmartGroupRule): boolean {
  const field = String(rule.field || '').trim();
  const op = rule.operator || 'eq';
  const targetVal = rule.value;

  let actual: any;
  switch (field) {
    case 'ram_usage_pct':
      actual = device.ram_total_gb > 0 ? Math.round((Number(device.ram_used_gb || 0) / Number(device.ram_total_gb)) * 100) : 0;
      break;
    case 'disk_free_pct':
      actual = device.disk_total_gb > 0 ? Math.round((Number(device.disk_free_gb || 0) / Number(device.disk_total_gb)) * 100) : 100;
      break;
    case 'tags':
      actual = String(device.tags_json || '[]');
      break;
    case 'installed_software': {
      const swName = String(targetVal || '').trim();
      if (!swName) return false;
      const found = db
        .prepare('SELECT 1 FROM software_inventory WHERE device_id = ? AND LOWER(name) LIKE ? LIMIT 1')
        .get(device.id, `%${swName.toLowerCase()}%`);
      return op === 'not_contains' || op === 'neq' ? !found : Boolean(found);
    }
    default:
      actual = device[field];
      break;
  }

  const numActual = Number(actual);
  const numTarget = Number(targetVal);

  switch (op as string) {
    case 'eq':
    case '=':
    case '==':
      return String(actual ?? '').toLowerCase() === String(targetVal ?? '').toLowerCase();
    case 'neq':
    case '!=':
    case '<>':
      return String(actual ?? '').toLowerCase() !== String(targetVal ?? '').toLowerCase();
    case 'contains':
      return String(actual ?? '').toLowerCase().includes(String(targetVal ?? '').toLowerCase());
    case 'not_contains':
      return !String(actual ?? '').toLowerCase().includes(String(targetVal ?? '').toLowerCase());
    case 'gt':
    case '>':
      return !Number.isNaN(numActual) && !Number.isNaN(numTarget) && numActual > numTarget;
    case 'gte':
    case '>=':
      return !Number.isNaN(numActual) && !Number.isNaN(numTarget) && numActual >= numTarget;
    case 'lt':
    case '<':
      return !Number.isNaN(numActual) && !Number.isNaN(numTarget) && numActual < numTarget;
    case 'lte':
    case '<=':
      return !Number.isNaN(numActual) && !Number.isNaN(numTarget) && numActual <= numTarget;
    case 'in': {
      const arr = Array.isArray(targetVal)
        ? targetVal.map((x) => String(x).toLowerCase())
        : String(targetVal ?? '')
            .split(',')
            .map((s) => s.trim().toLowerCase());
      return arr.includes(String(actual ?? '').toLowerCase());
    }
    default:
      return false;
  }
}

export function parseSmartGroupRuleSet(rawRulesJson?: string | null): SmartGroupRuleSet {
  if (!rawRulesJson) return { combinator: 'AND', rules: [] };
  try {
    const parsed = JSON.parse(rawRulesJson);
    if (Array.isArray(parsed)) {
      return {
        combinator: 'AND',
        rules: parsed.map((r: any) => ({
          field: r.field || 'os_type',
          operator: r.operator || r.op || 'eq',
          value: r.value
        }))
      };
    }
    if (parsed && typeof parsed === 'object' && Array.isArray(parsed.rules)) {
      const comb = String(parsed.combinator || parsed.logic || 'AND').toUpperCase();
      return {
        combinator: comb === 'OR' ? 'OR' : 'AND',
        rules: parsed.rules.map((r: any) => ({
          field: r.field || 'os_type',
          operator: r.operator || r.op || 'eq',
          value: r.value
        }))
      };
    }
    // Legacy simple key-value map support (e.g. {"os_type": "windows", "pending_reboot": 1})
    if (parsed && typeof parsed === 'object') {
      const rules: SmartGroupRule[] = Object.entries(parsed).map(([k, v]) => ({
        field: k,
        operator: 'eq',
        value: v
      }));
      return { combinator: 'AND', rules };
    }
  } catch {}
  return { combinator: 'AND', rules: [] };
}

export function evaluateSmartGroupDevices(rawRulesJson?: string | null, scopedTenantId?: string | null): any[] {
  let sql = "SELECT * FROM devices WHERE COALESCE(lifecycle_state, 'active') = 'active'";
  const params: any[] = [];
  if (scopedTenantId && scopedTenantId !== 'all') {
    sql += ' AND tenant_id = ?';
    params.push(scopedTenantId);
  }
  const candidates = db.prepare(sql).all(...params) as any[];
  const ruleSet = parseSmartGroupRuleSet(rawRulesJson);
  if (ruleSet.rules.length === 0) return candidates;

  return candidates.filter((dev) => {
    if (ruleSet.combinator === 'OR') {
      return ruleSet.rules.some((r) => evaluateDeviceAgainstRule(dev, r));
    }
    return ruleSet.rules.every((r) => evaluateDeviceAgainstRule(dev, r));
  });
}

export interface ScriptParameterDef {
  name: string;
  label?: string;
  type: 'string' | 'number' | 'boolean' | 'choice' | 'secret';
  required?: boolean;
  defaultValue?: string | number | boolean;
  choices?: string[];
}

/**
 * Safely validates typed script parameters and maps them exclusively to `VITRINE_PARAM_<NAME>`
 * environment variables — zero string interpolation into PowerShell/Bash code!
 */
export function buildSafeScriptEnvParams(
  parametersSchemaJson?: string | null,
  providedValues?: Record<string, unknown> | null
): Record<string, string> {
  const env: Record<string, string> = {};
  const input = providedValues && typeof providedValues === 'object' ? providedValues : {};

  let schema: ScriptParameterDef[] = [];
  if (parametersSchemaJson) {
    try {
      const parsed = JSON.parse(parametersSchemaJson);
      if (Array.isArray(parsed)) schema = parsed;
    } catch {}
  }

  for (const def of schema) {
    const cleanKey = String(def.name || '')
      .toUpperCase()
      .replace(/[^A-Z0-9_]/g, '')
      .slice(0, 48);
    if (!cleanKey) continue;
    const rawVal =
      input[def.name] !== undefined
        ? input[def.name]
        : def.defaultValue !== undefined
          ? def.defaultValue
          : (def as any).default;
    if ((rawVal === undefined || rawVal === null || rawVal === '') && def.required) {
      throw new Error(`Missing required script parameter: ${def.label || def.name}`);
    }
    if (rawVal === undefined || rawVal === null) continue;

    if (def.type === 'number') {
      const n = Number(rawVal);
      if (Number.isNaN(n)) throw new Error(`Script parameter '${def.name}' must be a valid number.`);
      env[`VITRINE_PARAM_${cleanKey}`] = String(n);
    } else if (def.type === 'boolean') {
      env[`VITRINE_PARAM_${cleanKey}`] = rawVal === true || rawVal === 'true' || rawVal === '1' ? 'true' : 'false';
    } else if (def.type === 'choice' && Array.isArray(def.choices) && def.choices.length > 0) {
      const s = String(rawVal);
      if (!def.choices.includes(s)) {
        throw new Error(`Invalid choice for '${def.name}'. Allowed: ${def.choices.join(', ')}`);
      }
      env[`VITRINE_PARAM_${cleanKey}`] = s;
    } else if (def.type === 'secret') {
      const strVal = String(rawVal);
      env[`VITRINE_PARAM_${cleanKey}`] = strVal.startsWith('enc:') ? decryptVaultSecret(strVal) : strVal;
    } else {
      env[`VITRINE_PARAM_${cleanKey}`] = String(rawVal).slice(0, 4096);
    }
  }

  // Also allow ad-hoc alphanumeric keys from `input` not listed in schema
  for (const [k, v] of Object.entries(input)) {
    const cleanKey = k
      .toUpperCase()
      .replace(/[^A-Z0-9_]/g, '')
      .slice(0, 48);
    if (!cleanKey || env[`VITRINE_PARAM_${cleanKey}`] !== undefined || v === undefined || v === null) continue;
    env[`VITRINE_PARAM_${cleanKey}`] = String(v).slice(0, 4096);
  }

  return env;
}

function matchesCronField(fieldExpr: string, value: number, min: number, max: number): boolean {
  const expr = fieldExpr.trim();
  if (expr === '*') return true;

  for (const part of expr.split(',')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith('*/')) {
      const step = parseInt(trimmed.slice(2), 10);
      if (step > 0 && (value - min) % step === 0) return true;
    } else if (trimmed.includes('-')) {
      const [rangePart, stepPart] = trimmed.split('/');
      const [startStr, endStr] = rangePart.split('-');
      const start = parseInt(startStr, 10);
      const end = parseInt(endStr, 10);
      const step = stepPart ? parseInt(stepPart, 10) : 1;
      if (value >= start && value <= end && (value - start) % Math.max(1, step) === 0) return true;
    } else {
      const exact = parseInt(trimmed, 10);
      if (exact === value || (max === 6 && exact === 7 && value === 0)) return true;
    }
  }
  return false;
}

export function matchesCronExpression(cronExpr: string, date = new Date()): boolean {
  const fields = String(cronExpr || '')
    .trim()
    .split(/\s+/);
  if (fields.length !== 5) return false;
  const [minF, hourF, domF, monF, dowF] = fields;
  return (
    matchesCronField(minF, date.getMinutes(), 0, 59) &&
    matchesCronField(hourF, date.getHours(), 0, 23) &&
    matchesCronField(domF, date.getDate(), 1, 31) &&
    matchesCronField(monF, date.getMonth() + 1, 1, 12) &&
    matchesCronField(dowF, date.getDay(), 0, 6)
  );
}

export function computeNextCronRunIso(cronExpr: string, fromDate = new Date()): string {
  const probe = new Date(fromDate.getTime());
  probe.setSeconds(0, 0);
  for (let i = 1; i <= 60 * 24 * 32; i++) {
    const candidate = new Date(probe.getTime() + i * 60_000);
    if (matchesCronExpression(cronExpr, candidate)) {
      return candidate.toISOString();
    }
  }
  return new Date(fromDate.getTime() + 3600_000).toISOString();
}

export async function executeScheduledAutomationNow(
  automationId: string,
  actorUsername = 'scheduler'
): Promise<{
  success: boolean;
  automationId: string;
  targetedDevices: number;
  succeededCount: number;
  failedCount: number;
}> {
  const auto = db.prepare('SELECT * FROM scheduled_automations WHERE id = ?').get(automationId) as any;
  if (!auto) throw new Error('Scheduled automation not found.');

  const script = db.prepare('SELECT * FROM scripts WHERE id = ?').get(auto.script_id) as any;
  if (!script) throw new Error('Linked script no longer exists.');

  let targetDevices: any[] = [];
  if (auto.target_type === 'tenant' && auto.target_id) {
    targetDevices = db
      .prepare("SELECT * FROM devices WHERE tenant_id = ? AND COALESCE(lifecycle_state, 'active') = 'active'")
      .all(auto.target_id) as any[];
  } else if (auto.target_type === 'site' && auto.target_id) {
    targetDevices = db
      .prepare("SELECT * FROM devices WHERE site_id = ? AND COALESCE(lifecycle_state, 'active') = 'active'")
      .all(auto.target_id) as any[];
  } else if (auto.target_type === 'device' && auto.target_id) {
    targetDevices = db
      .prepare("SELECT * FROM devices WHERE id = ? AND COALESCE(lifecycle_state, 'active') = 'active'")
      .all(auto.target_id) as any[];
  } else if (auto.target_type === 'smart_group' && auto.target_id) {
    const sg = db.prepare('SELECT * FROM smart_groups WHERE id = ?').get(auto.target_id) as any;
    if (sg) {
      targetDevices = evaluateSmartGroupDevices(sg.criteria_json, auto.tenant_id || sg.tenant_id || null);
    }
  } else if (auto.target_type === 'device_list' && auto.target_id) {
    let ids: string[] = [];
    try {
      ids = JSON.parse(auto.target_id);
    } catch {
      ids = String(auto.target_id)
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    }
    if (ids.length > 0) {
      const ph = ids.map(() => '?').join(',');
      targetDevices = db
        .prepare(`SELECT * FROM devices WHERE id IN (${ph}) AND COALESCE(lifecycle_state, 'active') = 'active'`)
        .all(...ids) as any[];
    }
  } else {
    targetDevices = evaluateSmartGroupDevices(null, auto.tenant_id || null);
  }

  if (auto.tenant_id && auto.tenant_id !== 'all') {
    targetDevices = targetDevices.filter((d) => d.tenant_id === auto.tenant_id);
  }

  let parsedParams: Record<string, unknown> = {};
  try {
    const rawParams = auto.params_json && auto.params_json !== '{}' ? auto.params_json : auto.parameters_json;
    parsedParams = rawParams ? JSON.parse(rawParams) : {};
  } catch {}
  const envParams = buildSafeScriptEnvParams(script.parameters_schema_json, parsedParams);

  let succeededCount = 0;
  let failedCount = 0;

  for (const dev of targetDevices) {
    const startMs = Date.now();
    const execId = `exec-${crypto.randomUUID()}`;
    const res = await meshBridge.executeCommandOnNode(dev.id, script.code, {
      runAs: auto.run_as === 'user' ? 'user' : 'system',
      shell: script.language === 'powershell' ? 'powershell' : script.language === 'python' ? 'python' : 'bash',
      timeoutMs: Math.max(5000, Number(script.timeout_sec || 120) * 1000),
      env: envParams
    });
    const durationMs = Math.max(1, Date.now() - startMs);
    const queued = Boolean(!res.live && (res.queued || res.output.startsWith('[Vitrine Companion Queue]')));
    const ok = res.live ? res.exitCode === 0 : queued;
    if (ok) succeededCount++;
    else failedCount++;
    const execStatus = res.live ? (res.exitCode === 0 ? 'Completed' : 'Failed') : queued ? 'Queued' : 'Failed';

    db.prepare(`
      INSERT INTO script_executions (
        id, script_id, script_name, device_id, hostname, triggered_by, run_as, params_json, status, exit_code, output, stdout, stderr, duration_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      execId,
      script.id,
      script.name,
      dev.id,
      dev.hostname,
      actorUsername,
      auto.run_as || 'system',
      JSON.stringify(parsedParams),
      execStatus,
      res.live ? res.exitCode : null,
      res.output || '',
      ok ? res.output : '',
      ok ? '' : res.output,
      durationMs
    );
  }

  const overallStatus =
    targetDevices.length === 0
      ? 'idle_no_targets'
      : failedCount === 0
      ? `succeeded (${succeededCount}/${targetDevices.length})`
      : `partial_or_failed (${succeededCount}/${targetDevices.length} ok)`;

  db.prepare(`
    UPDATE scheduled_automations
    SET last_run_at = ?, last_status = ?, run_count = COALESCE(run_count, 0) + 1
    WHERE id = ?
  `).run(new Date().toISOString(), overallStatus, automationId);

  return {
    success: failedCount === 0,
    automationId,
    targetedDevices: targetDevices.length,
    succeededCount,
    failedCount
  };
}

export const runScheduledAutomationNow = executeScheduledAutomationNow;
