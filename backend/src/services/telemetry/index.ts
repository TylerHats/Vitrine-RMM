import { db } from '../../db/index.js';
import {
  extractSignalsFromHardwareDetails,
  inferDeviceRole,
  shouldAutoUpdateDeviceRole
} from '../../utils/deviceRole.js';

export interface TelemetrySampleInput {
  cpuUsage?: number | null;
  ramUsedGb?: number | null;
  ramTotalGb?: number | null;
  diskFreeGb?: number | null;
  diskTotalGb?: number | null;
  netRxMbps?: number | null;
  netTxMbps?: number | null;
  uptimeSeconds?: number | null;
  loggedInUser?: string | null;
  hardwareDetails?: Record<string, any> | null;
  recordedAt?: string;
  forceHistoryInsert?: boolean;
}

export interface TelemetryHistoryPoint {
  recorded_at: string;
  cpu_usage: number;
  ram_used_gb: number;
  ram_total_gb: number;
  ram_used_pct: number;
  disk_used_pct: number;
  disk_free_gb: number;
  disk_total_gb: number;
  net_rx_mbps: number;
  net_tx_mbps: number;
  net_total_mbps: number;
}

export interface TelemetrySeriesStats {
  current: number;
  avg: number;
  max: number;
  min: number;
}

export interface TelemetryHistoryResponse {
  deviceId: string;
  range: string;
  sampleCount: number;
  current: {
    cpu_usage: number;
    ram_used_gb: number;
    ram_total_gb: number;
    ram_used_pct: number;
    disk_free_gb: number;
    disk_total_gb: number;
    disk_used_pct: number;
    net_rx_mbps: number;
    net_tx_mbps: number;
    uptime_seconds: number;
    logged_in_user: string;
    last_seen: string;
  } | null;
  summary: {
    cpu: TelemetrySeriesStats;
    ramPct: TelemetrySeriesStats;
    ramUsedGb: TelemetrySeriesStats;
    diskUsedPct: TelemetrySeriesStats;
    netMbps: TelemetrySeriesStats;
  };
  points: TelemetryHistoryPoint[];
}

function clamp(val: number, min: number, max: number): number {
  if (!Number.isFinite(val)) return min;
  return Math.min(max, Math.max(min, val));
}

function roundTo(val: number, decimals = 2): number {
  const factor = Math.pow(10, decimals);
  return Math.round(val * factor) / factor;
}

function isPlainObject(v: unknown): v is Record<string, any> {
  return Boolean(v) && typeof v === 'object' && !Array.isArray(v);
}

/**
 * Deep-merges incoming hardware metadata without overwriting previously discovered
 * sections (e.g., DIMM modules, storage drives, network adapters) with empty values.
 */
export function mergeHardwareDetailsJson(
  existingJson: string | null | undefined,
  incoming: Record<string, any> | null | undefined
): string {
  let existing: Record<string, any> = {};
  if (existingJson) {
    try {
      const parsed = JSON.parse(existingJson);
      if (isPlainObject(parsed)) existing = parsed;
    } catch {
      existing = {};
    }
  }
  if (!incoming || !isPlainObject(incoming)) {
    return JSON.stringify(existing);
  }

  const mergeObj = (base: Record<string, any>, patch: Record<string, any>): Record<string, any> => {
    const out: Record<string, any> = { ...base };
    for (const [key, val] of Object.entries(patch)) {
      if (val === undefined || val === null || val === '') continue;
      if (Array.isArray(val)) {
        if (val.length > 0 || !Array.isArray(out[key])) {
          out[key] = val;
        }
      } else if (isPlainObject(val)) {
        out[key] = mergeObj(isPlainObject(out[key]) ? out[key] : {}, val);
      } else {
        out[key] = val;
      }
    }
    return out;
  };

  return JSON.stringify(mergeObj(existing, incoming));
}

export function recordDeviceTelemetrySample(
  deviceId: string,
  sample: TelemetrySampleInput
): {
  recorded: boolean;
  insertedHistory: boolean;
  point?: TelemetryHistoryPoint;
} {
  const dev = db
    .prepare(`
      SELECT id, os_type, os_version, manufacturer, model, bios_version, device_role, device_role_manual,
             cpu_usage, ram_used_gb, ram_total_gb, disk_free_gb, disk_total_gb,
             net_rx_mbps, net_tx_mbps, uptime_seconds, logged_in_user, hardware_details_json
      FROM devices
      WHERE id = ?
    `)
    .get(deviceId) as any;

  if (!dev) {
    return { recorded: false, insertedHistory: false };
  }

  const nextCpu =
    sample.cpuUsage != null && Number.isFinite(Number(sample.cpuUsage))
      ? roundTo(clamp(Number(sample.cpuUsage), 0, 100), 1)
      : Number(dev.cpu_usage || 0);

  const nextRamTotal =
    sample.ramTotalGb != null && Number.isFinite(Number(sample.ramTotalGb)) && Number(sample.ramTotalGb) > 0
      ? roundTo(Number(sample.ramTotalGb), 2)
      : Number(dev.ram_total_gb || 0);

  const rawRamUsed =
    sample.ramUsedGb != null && Number.isFinite(Number(sample.ramUsedGb)) && Number(sample.ramUsedGb) >= 0
      ? roundTo(Number(sample.ramUsedGb), 2)
      : Number(dev.ram_used_gb || 0);
  const nextRamUsed = nextRamTotal > 0 ? roundTo(Math.min(rawRamUsed, nextRamTotal), 2) : rawRamUsed;

  const nextDiskTotal =
    sample.diskTotalGb != null && Number.isFinite(Number(sample.diskTotalGb)) && Number(sample.diskTotalGb) > 0
      ? roundTo(Number(sample.diskTotalGb), 2)
      : Number(dev.disk_total_gb || 0);

  const rawDiskFree =
    sample.diskFreeGb != null && Number.isFinite(Number(sample.diskFreeGb)) && Number(sample.diskFreeGb) >= 0
      ? roundTo(Number(sample.diskFreeGb), 2)
      : Number(dev.disk_free_gb || 0);
  const nextDiskFree = nextDiskTotal > 0 ? roundTo(Math.min(rawDiskFree, nextDiskTotal), 2) : rawDiskFree;

  const diskUsedPct =
    nextDiskTotal > 0
      ? roundTo(clamp(((nextDiskTotal - nextDiskFree) / nextDiskTotal) * 100, 0, 100), 1)
      : 0;

  const nextNetRx =
    sample.netRxMbps != null && Number.isFinite(Number(sample.netRxMbps))
      ? roundTo(Math.max(0, Number(sample.netRxMbps)), 3)
      : Number(dev.net_rx_mbps || 0);

  const nextNetTx =
    sample.netTxMbps != null && Number.isFinite(Number(sample.netTxMbps))
      ? roundTo(Math.max(0, Number(sample.netTxMbps)), 3)
      : Number(dev.net_tx_mbps || 0);

  const nextUptime =
    sample.uptimeSeconds != null && Number.isFinite(Number(sample.uptimeSeconds)) && Number(sample.uptimeSeconds) >= 0
      ? Math.floor(Number(sample.uptimeSeconds))
      : Number(dev.uptime_seconds || 0);

  const nextLoggedInUser =
    sample.loggedInUser !== undefined && sample.loggedInUser !== null
      ? String(sample.loggedInUser).trim().slice(0, 128)
      : String(dev.logged_in_user || '');

  const mergedHardwareJson = sample.hardwareDetails
    ? mergeHardwareDetailsJson(dev.hardware_details_json, {
        ...sample.hardwareDetails,
        lastHardwareScanAt: new Date().toISOString()
      })
    : dev.hardware_details_json || '{}';

  const hwSys = (sample.hardwareDetails?.system || {}) as Record<string, any>;
  const nextManufacturer = String(hwSys.manufacturer || dev.manufacturer || '').trim();
  const nextModel = String(hwSys.model || dev.model || '').trim();
  const nextBiosVersion = String(hwSys.biosVersion || dev.bios_version || '').trim();

  const roleSignals = extractSignalsFromHardwareDetails(mergedHardwareJson, {
    os_type: dev.os_type,
    os_version: dev.os_version,
    manufacturer: nextManufacturer,
    model: nextModel,
    bios_version: nextBiosVersion
  });
  const inferredRole = inferDeviceRole(roleSignals);
  const nextDeviceRole = shouldAutoUpdateDeviceRole(dev.device_role, dev.device_role_manual, inferredRole)
    ? (inferredRole as string)
    : dev.device_role;

  const recordedAt = sample.recordedAt || new Date().toISOString();

  db.prepare(`
    UPDATE devices
    SET cpu_usage = ?,
        ram_used_gb = ?,
        ram_total_gb = ?,
        disk_free_gb = ?,
        disk_total_gb = ?,
        net_rx_mbps = ?,
        net_tx_mbps = ?,
        uptime_seconds = ?,
        logged_in_user = ?,
        manufacturer = ?,
        model = ?,
        bios_version = ?,
        device_role = ?,
        hardware_details_json = ?,
        last_seen = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(
    nextCpu,
    nextRamUsed,
    nextRamTotal,
    nextDiskFree,
    nextDiskTotal,
    nextNetRx,
    nextNetTx,
    nextUptime,
    nextLoggedInUser,
    nextManufacturer,
    nextModel,
    nextBiosVersion,
    nextDeviceRole,
    mergedHardwareJson,
    deviceId
  );

  // Deduplicate rapid back-to-back history writes (< 10 seconds) unless forced
  let shouldInsert = Boolean(sample.forceHistoryInsert);
  if (!shouldInsert) {
    const latest = db
      .prepare(
        'SELECT recorded_at FROM device_telemetry_history WHERE device_id = ? ORDER BY recorded_at DESC, id DESC LIMIT 1'
      )
      .get(deviceId) as { recorded_at?: string } | undefined;
    if (!latest?.recorded_at) {
      shouldInsert = true;
    } else {
      const latestMs = new Date(String(latest.recorded_at).replace(' ', 'T')).getTime();
      const curMs = new Date(recordedAt.replace(' ', 'T')).getTime();
      if (Number.isNaN(latestMs) || Number.isNaN(curMs) || Math.abs(curMs - latestMs) >= 10_000) {
        shouldInsert = true;
      }
    }
  }

  if (shouldInsert) {
    db.prepare(`
      INSERT INTO device_telemetry_history (
        device_id, cpu_usage, ram_used_gb, ram_total_gb,
        disk_used_pct, disk_free_gb, disk_total_gb,
        net_rx_mbps, net_tx_mbps, recorded_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      deviceId,
      nextCpu,
      nextRamUsed,
      nextRamTotal,
      diskUsedPct,
      nextDiskFree,
      nextDiskTotal,
      nextNetRx,
      nextNetTx,
      recordedAt
    );
  }

  const ramUsedPct =
    nextRamTotal > 0 ? roundTo(clamp((nextRamUsed / nextRamTotal) * 100, 0, 100), 1) : 0;

  return {
    recorded: true,
    insertedHistory: shouldInsert,
    point: {
      recorded_at: recordedAt,
      cpu_usage: nextCpu,
      ram_used_gb: nextRamUsed,
      ram_total_gb: nextRamTotal,
      ram_used_pct: ramUsedPct,
      disk_used_pct: diskUsedPct,
      disk_free_gb: nextDiskFree,
      disk_total_gb: nextDiskTotal,
      net_rx_mbps: nextNetRx,
      net_tx_mbps: nextNetTx,
      net_total_mbps: roundTo(nextNetRx + nextNetTx, 3)
    }
  };
}

const RANGE_HOURS_MAP: Record<string, number> = {
  '1h': 1,
  '6h': 6,
  '24h': 24,
  '7d': 24 * 7,
  '30d': 24 * 30
};

function computeStats(values: number[], currentVal: number): TelemetrySeriesStats {
  if (values.length === 0) {
    const c = roundTo(currentVal, 2);
    return { current: c, avg: c, max: c, min: c };
  }
  let sum = 0;
  let max = -Infinity;
  let min = Infinity;
  for (const v of values) {
    sum += v;
    if (v > max) max = v;
    if (v < min) min = v;
  }
  return {
    current: roundTo(currentVal, 2),
    avg: roundTo(sum / values.length, 2),
    max: roundTo(max, 2),
    min: roundTo(min, 2)
  };
}

export function queryDeviceTelemetryHistory(
  deviceId: string,
  rawRange?: string
): TelemetryHistoryResponse {
  const range = rawRange && RANGE_HOURS_MAP[rawRange] ? rawRange : '24h';
  const hours = RANGE_HOURS_MAP[range];
  const cutoffIso = new Date(Date.now() - hours * 3600_000).toISOString();

  const dev = db
    .prepare(`
      SELECT id, cpu_usage, ram_used_gb, ram_total_gb, disk_free_gb, disk_total_gb,
             net_rx_mbps, net_tx_mbps, uptime_seconds, logged_in_user, last_seen
      FROM devices
      WHERE id = ?
    `)
    .get(deviceId) as any;

  const rawRows = db
    .prepare(`
      SELECT cpu_usage, ram_used_gb, ram_total_gb, disk_used_pct, disk_free_gb, disk_total_gb,
             net_rx_mbps, net_tx_mbps, recorded_at
      FROM device_telemetry_history
      WHERE device_id = ? AND datetime(recorded_at) >= datetime(?)
      ORDER BY datetime(recorded_at) ASC, id ASC
    `)
    .all(deviceId, cutoffIso) as any[];

  const mapped: TelemetryHistoryPoint[] = rawRows.map((r) => {
    const ramTotal = Number(r.ram_total_gb || 0);
    const ramUsed = Number(r.ram_used_gb || 0);
    const netRx = Number(r.net_rx_mbps || 0);
    const netTx = Number(r.net_tx_mbps || 0);
    return {
      recorded_at: String(r.recorded_at || ''),
      cpu_usage: roundTo(Number(r.cpu_usage || 0), 1),
      ram_used_gb: roundTo(ramUsed, 2),
      ram_total_gb: roundTo(ramTotal, 2),
      ram_used_pct: ramTotal > 0 ? roundTo(clamp((ramUsed / ramTotal) * 100, 0, 100), 1) : 0,
      disk_used_pct: roundTo(Number(r.disk_used_pct || 0), 1),
      disk_free_gb: roundTo(Number(r.disk_free_gb || 0), 2),
      disk_total_gb: roundTo(Number(r.disk_total_gb || 0), 2),
      net_rx_mbps: roundTo(netRx, 3),
      net_tx_mbps: roundTo(netTx, 3),
      net_total_mbps: roundTo(netRx + netTx, 3)
    };
  });

  // Downsample proportionally to max 180 points for clean SVG rendering
  const MAX_POINTS = 180;
  let points = mapped;
  if (mapped.length > MAX_POINTS) {
    const bucketSize = Math.ceil(mapped.length / MAX_POINTS);
    const downsampled: TelemetryHistoryPoint[] = [];
    for (let i = 0; i < mapped.length; i += bucketSize) {
      const slice = mapped.slice(i, i + bucketSize);
      const mid = slice[Math.floor(slice.length / 2)];
      const avgField = (getter: (p: TelemetryHistoryPoint) => number, dec = 2) =>
        roundTo(slice.reduce((acc, p) => acc + getter(p), 0) / slice.length, dec);
      downsampled.push({
        recorded_at: mid.recorded_at,
        cpu_usage: avgField((p) => p.cpu_usage, 1),
        ram_used_gb: avgField((p) => p.ram_used_gb, 2),
        ram_total_gb: avgField((p) => p.ram_total_gb, 2),
        ram_used_pct: avgField((p) => p.ram_used_pct, 1),
        disk_used_pct: avgField((p) => p.disk_used_pct, 1),
        disk_free_gb: avgField((p) => p.disk_free_gb, 2),
        disk_total_gb: avgField((p) => p.disk_total_gb, 2),
        net_rx_mbps: avgField((p) => p.net_rx_mbps, 3),
        net_tx_mbps: avgField((p) => p.net_tx_mbps, 3),
        net_total_mbps: avgField((p) => p.net_total_mbps, 3)
      });
    }
    points = downsampled;
  }

  const curCpu = Number(dev?.cpu_usage || 0);
  const curRamTotal = Number(dev?.ram_total_gb || 0);
  const curRamUsed = Number(dev?.ram_used_gb || 0);
  const curRamPct = curRamTotal > 0 ? roundTo(clamp((curRamUsed / curRamTotal) * 100, 0, 100), 1) : 0;
  const curDiskTotal = Number(dev?.disk_total_gb || 0);
  const curDiskFree = Number(dev?.disk_free_gb || 0);
  const curDiskPct =
    curDiskTotal > 0 ? roundTo(clamp(((curDiskTotal - curDiskFree) / curDiskTotal) * 100, 0, 100), 1) : 0;
  const curNetRx = Number(dev?.net_rx_mbps || 0);
  const curNetTx = Number(dev?.net_tx_mbps || 0);

  return {
    deviceId,
    range,
    sampleCount: mapped.length,
    current: dev
      ? {
          cpu_usage: roundTo(curCpu, 1),
          ram_used_gb: roundTo(curRamUsed, 2),
          ram_total_gb: roundTo(curRamTotal, 2),
          ram_used_pct: curRamPct,
          disk_free_gb: roundTo(curDiskFree, 2),
          disk_total_gb: roundTo(curDiskTotal, 2),
          disk_used_pct: curDiskPct,
          net_rx_mbps: roundTo(curNetRx, 3),
          net_tx_mbps: roundTo(curNetTx, 3),
          uptime_seconds: Number(dev.uptime_seconds || 0),
          logged_in_user: String(dev.logged_in_user || ''),
          last_seen: String(dev.last_seen || '')
        }
      : null,
    summary: {
      cpu: computeStats(mapped.map((p) => p.cpu_usage), curCpu),
      ramPct: computeStats(mapped.map((p) => p.ram_used_pct), curRamPct),
      ramUsedGb: computeStats(mapped.map((p) => p.ram_used_gb), curRamUsed),
      diskUsedPct: computeStats(mapped.map((p) => p.disk_used_pct), curDiskPct),
      netMbps: computeStats(mapped.map((p) => p.net_total_mbps), curNetRx + curNetTx)
    },
    points
  };
}

export function pruneTelemetryHistory(): number {
  let retentionDays = 90;
  try {
    const globalPol = db
      .prepare("SELECT telemetry_history_retention_days FROM policies WHERE tier = 'global' LIMIT 1")
      .get() as { telemetry_history_retention_days?: number } | undefined;
    if (globalPol?.telemetry_history_retention_days && globalPol.telemetry_history_retention_days > 0) {
      retentionDays = globalPol.telemetry_history_retention_days;
    }
  } catch {}
  const cutoffIso = new Date(Date.now() - retentionDays * 86400_000).toISOString();
  const res = db
    .prepare('DELETE FROM device_telemetry_history WHERE datetime(recorded_at) <= datetime(?)')
    .run(cutoffIso);
  return res.changes;
}

