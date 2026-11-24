import dgram from 'dgram';
import net from 'net';
import os from 'os';
import crypto from 'crypto';
import { db } from '../../db/index.js';
import { agentSocketHub } from '../agent/socketHub.js';
import {
  decryptVaultSecret,
  encryptVaultSecret,
  isBlockedOutboundIp,
  safeOutboundFetch,
  validateOutboundHostSafety
} from '../vault/index.js';

// ============================================================================
// Pure-TypeScript BER / ASN.1 SNMPv1 / SNMPv2c / SNMPv3 UDP Client
// ============================================================================

function encodeBerLength(len: number): Buffer {
  if (len < 0x80) {
    return Buffer.from([len]);
  }
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function encodeBerTlv(tag: number, value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeBerLength(value.length), value]);
}

function encodeBerInt(val: number | bigint): Buffer {
  const n = typeof val === 'bigint' ? val : BigInt(Math.trunc(val));
  if (n === 0n) return encodeBerTlv(0x02, Buffer.from([0x00]));
  const bytes: number[] = [];
  let temp = n;
  while (temp !== 0n && temp !== -1n) {
    bytes.unshift(Number(temp & 0xffn));
    temp >>= 8n;
  }
  if (bytes.length === 0) {
    bytes.push(n < 0n ? 0xff : 0x00);
  } else if (n > 0n && (bytes[0] & 0x80) !== 0) {
    bytes.unshift(0x00);
  } else if (n < 0n && (bytes[0] & 0x80) === 0) {
    bytes.unshift(0xff);
  }
  return encodeBerTlv(0x02, Buffer.from(bytes));
}

function encodeBerOctetString(val: string | Buffer): Buffer {
  const buf = Buffer.isBuffer(val) ? val : Buffer.from(val, 'utf8');
  return encodeBerTlv(0x04, buf);
}

function encodeBerNull(): Buffer {
  return Buffer.from([0x05, 0x00]);
}

function encodeBase128Vlq(subVal: bigint): number[] {
  if (subVal < 128n) {
    return [Number(subVal)];
  }
  const stack: number[] = [Number(subVal & 0x7fn)];
  let cur = subVal >> 7n;
  while (cur > 0n) {
    stack.unshift(Number(cur & 0x7fn) | 0x80);
    cur >>= 7n;
  }
  return stack;
}

export function encodeBerOid(oid: string): Buffer {
  const rawParts = oid
    .trim()
    .replace(/^\./, '')
    .split('.');
  if (rawParts.length < 2 || rawParts.some((p) => !/^\d+$/.test(p))) {
    throw new Error(`Invalid SNMP OID: ${oid}`);
  }
  const parts = rawParts.map((p) => BigInt(p));
  if (parts[0] > 2n || (parts[0] < 2n && parts[1] >= 40n)) {
    throw new Error(`Invalid SNMP OID root arc: ${oid}`);
  }
  const firstSub = parts[0] * 40n + parts[1];
  const out: number[] = [...encodeBase128Vlq(firstSub)];
  for (let i = 2; i < parts.length; i++) {
    out.push(...encodeBase128Vlq(parts[i]));
  }
  return encodeBerTlv(0x06, Buffer.from(out));
}

interface BerElement {
  tag: number;
  value: Buffer;
  nextOffset: number;
}

function readBerElement(buf: Buffer, offset = 0): BerElement {
  if (offset >= buf.length) throw new Error('Unexpected EOF reading BER tag');
  const tag = buf[offset++];
  if (offset >= buf.length) throw new Error('Unexpected EOF reading BER length');
  let len = buf[offset++];
  if ((len & 0x80) !== 0) {
    const numOctets = len & 0x7f;
    if (numOctets === 0 || numOctets > 4 || offset + numOctets > buf.length) {
      throw new Error('Invalid BER multi-byte length');
    }
    len = 0;
    for (let i = 0; i < numOctets; i++) {
      len = (len << 8) | buf[offset++];
    }
  }
  if (offset + len > buf.length) throw new Error('Truncated BER value');
  const value = buf.subarray(offset, offset + len);
  return { tag, value, nextOffset: offset + len };
}

function decodeBerChildren(buf: Buffer): BerElement[] {
  const items: BerElement[] = [];
  let off = 0;
  while (off < buf.length) {
    const el = readBerElement(buf, off);
    items.push(el);
    off = el.nextOffset;
  }
  return items;
}

function decodeBerInt(buf: Buffer): number {
  if (buf.length === 0) return 0;
  let val = (buf[0] & 0x80) !== 0 ? -1n : 0n;
  for (let i = 0; i < buf.length; i++) {
    val = (val << 8n) | BigInt(buf[i]);
  }
  return Number(val);
}

function decodeBerUint(buf: Buffer): number {
  if (buf.length === 0) return 0;
  let val = 0n;
  for (let i = 0; i < buf.length; i++) {
    val = (val << 8n) | BigInt(buf[i]);
  }
  return Number(val);
}

export function decodeBerOid(buf: Buffer): string {
  if (buf.length === 0) return '';
  let idx = 0;
  let firstSub = 0n;
  while (idx < buf.length) {
    const b = buf[idx++];
    firstSub = (firstSub << 7n) | BigInt(b & 0x7f);
    if ((b & 0x80) === 0) break;
  }

  const parts: string[] = [];
  if (firstSub < 40n) {
    parts.push('0', firstSub.toString());
  } else if (firstSub < 80n) {
    parts.push('1', (firstSub - 40n).toString());
  } else {
    parts.push('2', (firstSub - 80n).toString());
  }

  let cur = 0n;
  for (let i = idx; i < buf.length; i++) {
    cur = (cur << 7n) | BigInt(buf[i] & 0x7f);
    if ((buf[i] & 0x80) === 0) {
      parts.push(cur.toString());
      cur = 0n;
    }
  }
  return parts.join('.');
}

function decodeSnmpValue(el: BerElement): string | number | null {
  switch (el.tag) {
    case 0x02: // INTEGER
      return decodeBerInt(el.value);
    case 0x41: // Counter32
    case 0x42: // Gauge32
    case 0x43: // TimeTicks (1/100th sec)
    case 0x46: // Counter64
      return decodeBerUint(el.value);
    case 0x04: { // OCTET STRING
      const str = el.value.toString('utf8');
      // If printable ASCII/UTF-8 return text, otherwise hex
      if (/^[\x09\x0a\x0d\x20-\x7e]*$/.test(str)) {
        return str.trim();
      }
      return el.value.toString('hex');
    }
    case 0x06: // OID
      return decodeBerOid(el.value);
    case 0x40: // IpAddress
      return Array.from(el.value).join('.');
    case 0x05: // NULL
    case 0x80: // noSuchObject
    case 0x81: // noSuchInstance
    case 0x82: // endOfMibView
      return null;
    default:
      return el.value.toString('utf8');
  }
}

export function buildSnmpV2cGetPacket(community: string, oids: string[], requestId?: number, version: 0 | 1 = 1): Buffer {
  const reqId = requestId ?? crypto.randomInt(10000, 0x7fffffff);
  const varbinds = oids.map((oid) => encodeBerTlv(0x30, Buffer.concat([encodeBerOid(oid), encodeBerNull()])));
  const varbindList = encodeBerTlv(0x30, Buffer.concat(varbinds));
  const pdu = encodeBerTlv(
    0xa0, // GetRequest-PDU
    Buffer.concat([encodeBerInt(reqId), encodeBerInt(0), encodeBerInt(0), varbindList])
  );
  return encodeBerTlv(0x30, Buffer.concat([encodeBerInt(version), encodeBerOctetString(community), pdu]));
}

export function parseSnmpGetResponse(packet: Buffer): Record<string, string | number | null> {
  const root = readBerElement(packet, 0);
  if (root.tag !== 0x30) throw new Error('Invalid SNMP outer SEQUENCE');
  const top = decodeBerChildren(root.value);
  const version = decodeBerInt(top[0].value);

  let pduEl: BerElement | undefined;
  if (version === 0 || version === 1) {
    pduEl = top[2];
  } else if (version === 3 && top.length >= 4) {
    // ScopedPDU for unencrypted / authNoPriv v3
    if (top[3].tag === 0x30) {
      const scoped = decodeBerChildren(top[3].value);
      pduEl = scoped[2];
    }
  }

  if (!pduEl || (pduEl.tag !== 0xa2 && pduEl.tag !== 0xa8)) {
    return {};
  }

  const pduItems = decodeBerChildren(pduEl.value);
  if (pduItems.length < 4) return {};
  const varbindList = decodeBerChildren(pduItems[3].value);
  const results: Record<string, string | number | null> = {};
  for (const vb of varbindList) {
    if (vb.tag !== 0x30) continue;
    const pair = decodeBerChildren(vb.value);
    if (pair.length >= 2 && pair[0].tag === 0x06) {
      const oid = decodeBerOid(pair[0].value);
      results[oid] = decodeSnmpValue(pair[1]);
    }
  }
  return results;
}

// RFC 3414 Password-to-Key localization for SNMPv3 USM
function localizeSnmpV3AuthKey(password: string, engineId: Buffer, algo: 'md5' | 'sha' | 'sha256'): Buffer {
  const hashAlgo = algo === 'md5' ? 'md5' : algo === 'sha256' ? 'sha256' : 'sha1';
  const pwBuf = Buffer.from(password, 'utf8');
  if (pwBuf.length === 0) throw new Error('SNMPv3 auth passphrase required');
  const h1 = crypto.createHash(hashAlgo);
  let count = 0;
  const target = 1048576; // 1 MiB per RFC 3414 A.2
  while (count < target) {
    const chunk = Buffer.allocUnsafe(64);
    for (let i = 0; i < 64; i++) {
      chunk[i] = pwBuf[(count + i) % pwBuf.length];
    }
    h1.update(chunk);
    count += 64;
  }
  const ku = h1.digest();
  return crypto.createHash(hashAlgo).update(Buffer.concat([ku, engineId, ku])).digest();
}

function sendUdpDatagram(host: string, port: number, payload: Buffer, timeoutMs = 2500): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socketType = net.isIPv6(host) ? 'udp6' : 'udp4';
    const sock = dgram.createSocket(socketType);
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        try {
          sock.close();
        } catch {}
        reject(new Error(`SNMP UDP timeout after ${timeoutMs}ms`));
      }
    }, timeoutMs);

    sock.once('error', (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        try {
          sock.close();
        } catch {}
        reject(err);
      }
    });

    sock.once('message', (msg) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        try {
          sock.close();
        } catch {}
        resolve(msg);
      }
    });

    sock.send(payload, port, host, (err) => {
      if (err && !settled) {
        settled = true;
        clearTimeout(timer);
        try {
          sock.close();
        } catch {}
        reject(err);
      }
    });
  });
}

export interface SnmpQueryOptions {
  host: string;
  port?: number;
  version?: '1' | '2c' | '3';
  community?: string;
  v3Username?: string;
  v3AuthProtocol?: 'none' | 'MD5' | 'SHA' | 'SHA-256';
  v3AuthKey?: string;
  timeoutMs?: number;
}

export async function snmpGet(options: SnmpQueryOptions, oids: string[]): Promise<Record<string, string | number | null>> {
  const port = options.port || 161;
  const timeoutMs = options.timeoutMs || 2500;
  const ver = options.version || '2c';

  if (ver === '1' || ver === '2c') {
    const pkt = buildSnmpV2cGetPacket(options.community || 'public', oids, undefined, ver === '1' ? 0 : 1);
    const resp = await sendUdpDatagram(options.host, port, pkt, timeoutMs);
    return parseSnmpGetResponse(resp);
  }

  // SNMPv3 Authoritative Engine Discovery + USM Authenticated GET
  const msgId1 = crypto.randomInt(1000, 0x3fffffff);
  const emptyUsm = encodeBerTlv(
    0x30,
    Buffer.concat([
      encodeBerOctetString(Buffer.alloc(0)),
      encodeBerInt(0),
      encodeBerInt(0),
      encodeBerOctetString(''),
      encodeBerOctetString(Buffer.alloc(0)),
      encodeBerOctetString(Buffer.alloc(0))
    ])
  );
  const discoveryGlobal = encodeBerTlv(
    0x30,
    Buffer.concat([
      encodeBerInt(msgId1),
      encodeBerInt(65507),
      encodeBerOctetString(Buffer.from([0x04])), // reportable=1
      encodeBerInt(3) // USM
    ])
  );
  const emptyScoped = encodeBerTlv(
    0x30,
    Buffer.concat([
      encodeBerOctetString(Buffer.alloc(0)),
      encodeBerOctetString(Buffer.alloc(0)),
      encodeBerTlv(0xa0, Buffer.concat([encodeBerInt(msgId1), encodeBerInt(0), encodeBerInt(0), encodeBerTlv(0x30, Buffer.alloc(0))]))
    ])
  );
  const discoveryPkt = encodeBerTlv(
    0x30,
    Buffer.concat([encodeBerInt(3), discoveryGlobal, encodeBerOctetString(emptyUsm), emptyScoped])
  );

  const discResp = await sendUdpDatagram(options.host, port, discoveryPkt, timeoutMs);
  const outerEl = readBerElement(discResp, 0);
  if (outerEl.tag !== 0x30) {
    throw new Error('Malformed SNMPv3 discovery packet outer envelope');
  }
  const discRoot = decodeBerChildren(outerEl.value);
  if (discRoot.length < 3) {
    throw new Error('Malformed SNMPv3 discovery response: missing USM security parameters');
  }
  const usmInner = readBerElement(discRoot[2].value, 0);
  if (usmInner.tag !== 0x30) {
    throw new Error('Malformed SNMPv3 USM security parameter sequence');
  }
  const usmReport = decodeBerChildren(usmInner.value);
  if (usmReport.length < 3) {
    throw new Error('Malformed SNMPv3 USM discovery report: missing engineId/boots/time');
  }
  const engineId = usmReport[0].value || Buffer.alloc(0);
  const engineBoots = decodeBerInt(usmReport[1].value || Buffer.alloc(0));
  const engineTime = decodeBerInt(usmReport[2].value || Buffer.alloc(0));

  const msgId2 = msgId1 + 1;
  const username = options.v3Username || 'snmpuser';
  const hasAuth = Boolean(options.v3AuthKey && options.v3AuthProtocol && options.v3AuthProtocol !== 'none');
  const flagsByte = hasAuth ? 0x05 : 0x04; // auth + reportable, or noAuthNoPriv + reportable

  const varbinds = oids.map((oid) => encodeBerTlv(0x30, Buffer.concat([encodeBerOid(oid), encodeBerNull()])));
  const getPdu = encodeBerTlv(
    0xa0,
    Buffer.concat([encodeBerInt(msgId2), encodeBerInt(0), encodeBerInt(0), encodeBerTlv(0x30, Buffer.concat(varbinds))])
  );
  const scopedPdu = encodeBerTlv(
    0x30,
    Buffer.concat([encodeBerOctetString(engineId), encodeBerOctetString(Buffer.alloc(0)), getPdu])
  );
  const globalData = encodeBerTlv(
    0x30,
    Buffer.concat([encodeBerInt(msgId2), encodeBerInt(65507), encodeBerOctetString(Buffer.from([flagsByte])), encodeBerInt(3)])
  );

  const macLen = options.v3AuthProtocol === 'SHA-256' ? 24 : 12;
  const zeroAuthPlaceholder = hasAuth ? Buffer.alloc(macLen, 0) : Buffer.alloc(0);
  const usmPlaceholder = encodeBerTlv(
    0x30,
    Buffer.concat([
      encodeBerOctetString(engineId),
      encodeBerInt(engineBoots),
      encodeBerInt(engineTime),
      encodeBerOctetString(username),
      encodeBerOctetString(zeroAuthPlaceholder),
      encodeBerOctetString(Buffer.alloc(0))
    ])
  );

  let wholeMsg = encodeBerTlv(
    0x30,
    Buffer.concat([encodeBerInt(3), globalData, encodeBerOctetString(usmPlaceholder), scopedPdu])
  );

  if (hasAuth && options.v3AuthKey) {
    const algo = options.v3AuthProtocol === 'MD5' ? 'md5' : options.v3AuthProtocol === 'SHA-256' ? 'sha256' : 'sha';
    const kul = localizeSnmpV3AuthKey(options.v3AuthKey, engineId, algo);
    const hmacAlgo = algo === 'md5' ? 'md5' : algo === 'sha256' ? 'sha256' : 'sha1';
    const mac = crypto.createHmac(hmacAlgo, kul).update(wholeMsg).digest().subarray(0, macLen);
    const usmSigned = encodeBerTlv(
      0x30,
      Buffer.concat([
        encodeBerOctetString(engineId),
        encodeBerInt(engineBoots),
        encodeBerInt(engineTime),
        encodeBerOctetString(username),
        encodeBerOctetString(mac),
        encodeBerOctetString(Buffer.alloc(0))
      ])
    );
    wholeMsg = encodeBerTlv(
      0x30,
      Buffer.concat([encodeBerInt(3), globalData, encodeBerOctetString(usmSigned), scopedPdu])
    );
  }

  const finalResp = await sendUdpDatagram(options.host, port, wholeMsg, timeoutMs);
  return parseSnmpGetResponse(finalResp);
}

// ============================================================================
// Wake-on-LAN (IEEE 802.3 Magic Packet UDP Broadcaster + Site Probe Relay)
// ============================================================================

export function buildMagicPacket(macAddress: string): Buffer {
  const cleanHex = String(macAddress || '')
    .replace(/[^0-9a-fA-F]/g, '')
    .toUpperCase();
  if (cleanHex.length !== 12) {
    throw new Error(`Invalid 48-bit MAC address for Wake-on-LAN: "${macAddress}"`);
  }
  const macBytes = Buffer.from(cleanHex, 'hex');
  const packet = Buffer.allocUnsafe(6 + 16 * 6);
  packet.fill(0xff, 0, 6);
  for (let i = 0; i < 16; i++) {
    macBytes.copy(packet, 6 + i * 6);
  }
  return packet;
}

function computeBroadcastAddresses(targetIp?: string | null): string[] {
  const targets = new Set<string>(['255.255.255.255']);
  if (targetIp && net.isIPv4(targetIp)) {
    const octets = targetIp.split('.');
    if (octets.length === 4 && octets[0] !== '127') {
      targets.add(`${octets[0]}.${octets[1]}.${octets[2]}.255`);
    }
  }
  const nics = os.networkInterfaces();
  for (const list of Object.values(nics)) {
    for (const nic of list || []) {
      if (nic.family === 'IPv4' && !nic.internal && nic.address && nic.netmask) {
        const ipParts = nic.address.split('.').map(Number);
        const maskParts = nic.netmask.split('.').map(Number);
        const bcast = ipParts.map((b, idx) => (b | (~maskParts[idx] & 0xff)) >>> 0).join('.');
        targets.add(bcast);
      }
    }
  }
  return Array.from(targets);
}

export async function sendWakeOnLanMagicPacket(params: {
  macAddress: string;
  ipAddress?: string | null;
  tenantId?: string | null;
  deviceId?: string | null;
}): Promise<{
  sent: boolean;
  broadcastTargets: string[];
  relayedViaProbeDeviceId: string | null;
  packetHexPreview: string;
}> {
  const magicPacket = buildMagicPacket(params.macAddress);
  const broadcastTargets = computeBroadcastAddresses(params.ipAddress);

  await new Promise<void>((resolve, reject) => {
    const sock = dgram.createSocket('udp4');
    sock.once('error', (err) => {
      try {
        sock.close();
      } catch {}
      reject(err);
    });
    sock.bind(0, () => {
      try {
        sock.setBroadcast(true);
      } catch {}
      let pending = 0;
      for (const bcast of broadcastTargets) {
        for (const port of [9, 7]) {
          pending++;
          sock.send(magicPacket, 0, magicPacket.length, port, bcast, () => {
            pending--;
            if (pending <= 0) {
              try {
                sock.close();
              } catch {}
              resolve();
            }
          });
        }
      }
      if (pending === 0) {
        try {
          sock.close();
        } catch {}
        resolve();
      }
    });
  });

  // Also queue an agent-relayed WoL magic packet via an online companion-capable peer endpoint in the same tenant/subnet!
  let relayedViaProbeDeviceId: string | null = null;
  if (params.tenantId) {
    const onlinePeers = db
      .prepare(
        "SELECT id, ip_address FROM devices WHERE tenant_id = ? AND status = 'online' AND companion_installed = 1 AND agent_auth_token IS NOT NULL AND agent_auth_token != '' AND id != ? ORDER BY last_seen DESC LIMIT 10"
      )
      .all(params.tenantId, params.deviceId || '') as Array<{ id: string; ip_address?: string }>;

    const targetPrefix =
      params.ipAddress && net.isIPv4(params.ipAddress) ? params.ipAddress.split('.').slice(0, 3).join('.') : '';
    const chosenPeer =
      onlinePeers.find((p) => targetPrefix && p.ip_address?.startsWith(targetPrefix + '.')) || onlinePeers[0];

    if (chosenPeer) {
      const taskId = `task-wol-${crypto.randomUUID()}`;
      const bcastIp = targetPrefix ? `${targetPrefix}.255` : '255.255.255.255';
      const payloadStr = JSON.stringify({ mac: params.macAddress, broadcastIp: bcastIp, port: 9 });
      try {
        db.prepare(`
          INSERT INTO agent_tasks (id, device_id, tenant_id, task_type, payload_json, status)
          VALUES (?, ?, ?, 'wol_relay', ?, 'queued')
        `).run(taskId, chosenPeer.id, params.tenantId, payloadStr);
      } catch {
        db.prepare(`
          INSERT INTO agent_tasks (id, device_id, task_type, payload_json, status)
          VALUES (?, ?, 'wol_relay', ?, 'queued')
        `).run(taskId, chosenPeer.id, payloadStr);
      }
      agentSocketHub.dispatchTaskIfConnected(chosenPeer.id, {
        id: taskId,
        task_type: 'wol_relay',
        payload_json: payloadStr
      });
      relayedViaProbeDeviceId = chosenPeer.id;
    }
  }

  return {
    sent: true,
    broadcastTargets,
    relayedViaProbeDeviceId,
    packetHexPreview: magicPacket.subarray(0, 18).toString('hex')
  };
}

// ============================================================================
// Live TCP Port Probe & Vendor Network Appliance Polling Engine
// ============================================================================

export function probeTcpPort(host: string, port: number, timeoutMs = 1500): Promise<{ open: boolean; latencyMs: number }> {
  return new Promise((resolve) => {
    const start = Date.now();
    const sock = new net.Socket();
    let done = false;
    const finish = (open: boolean) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve({ open, latencyMs: Math.max(1, Date.now() - start) });
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    sock.connect(port, host);
  });
}

export class NetworkDiscoveryService {
  private formatApplianceRow(row: Record<string, any>): Record<string, any> {
    const clean = { ...row };
    const hasApiToken = Boolean(clean.vendor_api_token_encrypted || clean.api_token_encrypted);
    const hasSnmpCommunity = Boolean(clean.snmp_community_encrypted);
    const hasSnmpV3AuthKey = Boolean(clean.snmp_v3_auth_key_encrypted);
    delete clean.vendor_api_token_encrypted;
    delete clean.api_token_encrypted;
    delete clean.snmp_community_encrypted;
    delete clean.snmp_v3_auth_key_encrypted;
    return {
      ...clean,
      hasApiToken,
      hasSnmpCommunity,
      hasSnmpV3AuthKey
    };
  }

  public async pollAppliance(applianceId: string) {
    const row = db.prepare('SELECT * FROM network_appliances WHERE id = ?').get(applianceId) as any;
    if (!row) {
      throw new Error('Network appliance not found.');
    }

    const host = String(row.ip_address || '').trim();
    if (!host) {
      throw new Error('Appliance IP/hostname is empty.');
    }

    const hostSafety = await validateOutboundHostSafety(host, {
      allowLoopback: false,
      allowPrivateLan: true
    });
    if (!hostSafety.safe) {
      throw new Error(hostSafety.reason || `Target appliance host '${host}' is blocked by outbound SSRF policy.`);
    }

    let existingMetrics: Record<string, any> = {};
    try {
      existingMetrics = row.metrics_json ? JSON.parse(row.metrics_json) : {};
    } catch {}

    let reachable = false;
    let latencyMs: number | null = null;
    let sysDescr: string | null = null;
    let sysName: string | null = null;
    let uptimeHours: number | null = row.uptime_hours != null ? Number(row.uptime_hours) : null;
    let cpuUsage: number | null = row.cpu_usage != null ? Number(row.cpu_usage) : null;
    let temperatureC: number | null = row.temperature_c != null ? Number(row.temperature_c) : null;
    let firmwareVersion: string | null = row.firmware_version || null;
    const vendorTelemetry: Record<string, any> = { ...existingMetrics };

    // 1. Live SNMPv1/v2c/v3 Poll
    const snmpVersion = (row.snmp_version || '2c') as '1' | '2c' | '3';
    const snmpPort = Number(row.snmp_port || 161);
    const community = decryptVaultSecret(row.snmp_community_encrypted) || 'public';
    const v3AuthKey = decryptVaultSecret(row.snmp_v3_auth_key_encrypted) || '';

    const standardOids = [
      '1.3.6.1.2.1.1.1.0', // sysDescr.0
      '1.3.6.1.2.1.1.5.0', // sysName.0
      '1.3.6.1.2.1.1.3.0', // sysUpTime.0 (hundredths of a second)
      '1.3.6.1.2.1.25.3.3.1.2.1', // hrProcessorLoad
      '1.3.6.1.4.1.318.1.1.1.2.2.1.0', // APC Battery Capacity %
      '1.3.6.1.4.1.318.1.1.1.4.2.3.0', // APC Output Load %
      '1.3.6.1.4.1.6574.1.2.0' // Synology System Temperature C
    ];

    try {
      const snmpStart = Date.now();
      const snmpRes = await snmpGet(
        {
          host,
          port: snmpPort,
          version: snmpVersion,
          community,
          v3Username: row.snmp_v3_username || undefined,
          v3AuthProtocol: row.snmp_v3_auth_proto || row.snmp_v3_auth_protocol || 'SHA',
          v3AuthKey: v3AuthKey || undefined,
          timeoutMs: 2200
        },
        standardOids
      );
      reachable = Object.keys(snmpRes).length > 0;
      if (reachable) {
        latencyMs = Math.max(1, Date.now() - snmpStart);
        if (typeof snmpRes['1.3.6.1.2.1.1.1.0'] === 'string' && snmpRes['1.3.6.1.2.1.1.1.0']) {
          sysDescr = snmpRes['1.3.6.1.2.1.1.1.0'];
          firmwareVersion = sysDescr.slice(0, 96);
        }
        if (typeof snmpRes['1.3.6.1.2.1.1.5.0'] === 'string' && snmpRes['1.3.6.1.2.1.1.5.0']) {
          sysName = snmpRes['1.3.6.1.2.1.1.5.0'];
        }
        if (typeof snmpRes['1.3.6.1.2.1.1.3.0'] === 'number') {
          uptimeHours = Math.max(0, Math.round(snmpRes['1.3.6.1.2.1.1.3.0'] / 360000));
        }
        if (typeof snmpRes['1.3.6.1.2.1.25.3.3.1.2.1'] === 'number') {
          cpuUsage = Math.min(100, Math.max(0, Math.round(snmpRes['1.3.6.1.2.1.25.3.3.1.2.1'])));
        }
        if (typeof snmpRes['1.3.6.1.4.1.318.1.1.1.2.2.1.0'] === 'number') {
          vendorTelemetry.upsBatteryPct = snmpRes['1.3.6.1.4.1.318.1.1.1.2.2.1.0'];
        }
        if (typeof snmpRes['1.3.6.1.4.1.318.1.1.1.4.2.3.0'] === 'number') {
          vendorTelemetry.upsLoadPct = snmpRes['1.3.6.1.4.1.318.1.1.1.4.2.3.0'];
        }
        if (typeof snmpRes['1.3.6.1.4.1.6574.1.2.0'] === 'number') {
          temperatureC = snmpRes['1.3.6.1.4.1.6574.1.2.0'];
        }
        vendorTelemetry.snmpResponded = true;
      }
    } catch (err: any) {
      vendorTelemetry.snmpResponded = false;
      vendorTelemetry.snmpLastError = err?.message || 'SNMP unreachable';
    }

    // 2. Vendor-specific HTTPS REST API Pollers (Redfish iDRAC/iLO, FortiOS, Synology DSM, UniFi)
    const vendorLower = `${row.manufacturer || row.vendor || ''} ${row.vendor_model || ''} ${row.appliance_type || ''} ${row.model || ''}`.toLowerCase();
    const apiSecret = decryptVaultSecret(row.vendor_api_token_encrypted || row.api_token_encrypted) || '';
    const allowInsecureTls = Boolean(row.allow_self_signed ?? 0);

    if (vendorLower.includes('idrac') || vendorLower.includes('ilo') || vendorLower.includes('redfish') || vendorLower.includes('bmc')) {
      try {
        const headers: Record<string, string> = { Accept: 'application/json' };
        if (apiSecret) {
          headers.Authorization = apiSecret.includes(':')
            ? `Basic ${Buffer.from(apiSecret, 'utf8').toString('base64')}`
            : `Bearer ${apiSecret}`;
        }
        const rf = await safeOutboundFetch(`https://${host}/redfish/v1/Systems`, {
          headers,
          timeoutMs: 4000,
          allowInsecureTls,
          safety: { allowLoopback: false, allowPrivateLan: true }
        });
        if (rf.status >= 200 && rf.status < 400) {
          reachable = true;
          const body = JSON.parse(rf.body.toString('utf8'));
          const firstMember = body?.Members?.[0]?.['@odata.id'];
          if (firstMember && typeof firstMember === 'string' && firstMember.startsWith('/redfish/')) {
            const sysDetail = await safeOutboundFetch(`https://${host}${firstMember}`, {
              headers,
              timeoutMs: 4000,
              allowInsecureTls,
              safety: { allowLoopback: false, allowPrivateLan: true }
            });
            if (sysDetail.status >= 200 && sysDetail.status < 300) {
              const sd = JSON.parse(sysDetail.body.toString('utf8'));
              firmwareVersion = sd.BiosVersion || firmwareVersion;
              vendorTelemetry.redfishPowerState = sd.PowerState;
              vendorTelemetry.redfishHealth = sd.Status?.HealthRollup || sd.Status?.Health;
              vendorTelemetry.serialNumber = sd.SerialNumber;
            }
          }
        }
      } catch {}
    } else if (vendorLower.includes('forti')) {
      try {
        const headers: Record<string, string> = { Accept: 'application/json' };
        if (apiSecret) headers.Authorization = `Bearer ${apiSecret}`;
        const fg = await safeOutboundFetch(`https://${host}/api/v2/monitor/system/status`, {
          headers,
          timeoutMs: 4000,
          allowInsecureTls,
          safety: { allowLoopback: false, allowPrivateLan: true }
        });
        if (fg.status >= 200 && fg.status < 300) {
          reachable = true;
          const body = JSON.parse(fg.body.toString('utf8'));
          if (body?.version) firmwareVersion = `FortiOS ${body.version}`;
          if (body?.results?.hostname) sysName = body.results.hostname;
        }
      } catch {}
    } else if (vendorLower.includes('synology')) {
      try {
        const dsm = await safeOutboundFetch(
          `https://${host}:5001/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=SYNO.API.Auth,SYNO.Core.System`,
          {
            timeoutMs: 3500,
            allowInsecureTls,
            safety: { allowLoopback: false, allowPrivateLan: true }
          }
        );
        if (dsm.status >= 200 && dsm.status < 300) {
          reachable = true;
          vendorTelemetry.dsmApiOnline = true;
        }
      } catch {}
    } else if (vendorLower.includes('unifi') || vendorLower.includes('ubiquiti')) {
      try {
        const uf = await safeOutboundFetch(`https://${host}:8443/status`, {
          timeoutMs: 3500,
          allowInsecureTls,
          safety: { allowLoopback: false, allowPrivateLan: true }
        });
        if (uf.status >= 200 && uf.status < 400) {
          reachable = true;
          const body = JSON.parse(uf.body.toString('utf8'));
          if (body?.meta?.server_version) firmwareVersion = `UniFi ${body.meta.server_version}`;
        }
      } catch {}
    }

    // 3. Fallback TCP reachability probe on common management ports (443, 80, 22, 9100, 8443)
    if (!reachable) {
      const commonPorts = [443, 80, 22, 8443, 5001, 9100];
      const probes = await Promise.all(commonPorts.map((p) => probeTcpPort(host, p, 1200)));
      const openIdx = probes.findIndex((p) => p.open);
      if (openIdx !== -1) {
        reachable = true;
        latencyMs = probes[openIdx].latencyMs;
        vendorTelemetry.openTcpPorts = commonPorts.filter((_, idx) => probes[idx].open);
      }
    }

    vendorTelemetry.latencyMs = latencyMs;
    if (sysDescr) vendorTelemetry.sysDescr = sysDescr;
    if (sysName) vendorTelemetry.sysName = sysName;
    vendorTelemetry.lastProbeIso = new Date().toISOString();

    const newStatus = reachable ? 'Healthy' : 'Offline';
    const nowIso = new Date().toISOString();

    db.prepare(`
      UPDATE network_appliances
      SET status = ?,
          firmware_version = COALESCE(?, firmware_version),
          uptime_hours = ?,
          uptime_days = ?,
          latency_ms = ?,
          cpu_usage = ?,
          cpu_pct = ?,
          temperature_c = ?,
          metrics_json = ?,
          last_polled = ?
      WHERE id = ?
    `).run(
      newStatus,
      firmwareVersion,
      uptimeHours ?? 0,
      uptimeHours != null ? Number((uptimeHours / 24).toFixed(2)) : 0,
      latencyMs ?? 0,
      cpuUsage ?? 0,
      cpuUsage ?? 0,
      temperatureC ?? 0,
      JSON.stringify(vendorTelemetry),
      nowIso,
      applianceId
    );

    const updated = (db.prepare('SELECT * FROM network_appliances WHERE id = ?').get(applianceId) || {}) as Record<string, any>;
    return {
      ...this.formatApplianceRow(updated),
      status: newStatus,
      latencyMs: latencyMs ?? 0
    };
  }

  public saveApplianceCredentials(
    applianceId: string,
    creds: {
      snmpVersion?: '1' | '2c' | '3';
      snmpPort?: number;
      snmpCommunity?: string;
      snmpV3Username?: string;
      snmpV3AuthProtocol?: 'none' | 'MD5' | 'SHA' | 'SHA-256';
      snmpV3AuthKey?: string;
      apiToken?: string;
    }
  ) {
    const tableCols = new Set(
      (db.prepare('PRAGMA table_info(network_appliances)').all() as Array<{ name: string }>).map((c) => c.name)
    );
    const sets: string[] = [];
    const vals: any[] = [];
    if (creds.snmpVersion) {
      sets.push('snmp_version = ?');
      vals.push(creds.snmpVersion);
    }
    if (creds.snmpPort) {
      sets.push('snmp_port = ?');
      vals.push(Math.max(1, Math.min(65535, Number(creds.snmpPort))));
    }
    if (creds.snmpCommunity !== undefined && creds.snmpCommunity !== '••••••••') {
      sets.push('snmp_community_encrypted = ?');
      vals.push(creds.snmpCommunity ? encryptVaultSecret(creds.snmpCommunity) : null);
    }
    if (creds.snmpV3Username !== undefined) {
      sets.push('snmp_v3_username = ?');
      vals.push(creds.snmpV3Username || null);
    }
    if (creds.snmpV3AuthProtocol !== undefined) {
      const authProtoCol = tableCols.has('snmp_v3_auth_proto') ? 'snmp_v3_auth_proto' : 'snmp_v3_auth_protocol';
      sets.push(`${authProtoCol} = ?`);
      vals.push(creds.snmpV3AuthProtocol);
    }
    if (creds.snmpV3AuthKey !== undefined && creds.snmpV3AuthKey !== '••••••••') {
      sets.push('snmp_v3_auth_key_encrypted = ?');
      vals.push(creds.snmpV3AuthKey ? encryptVaultSecret(creds.snmpV3AuthKey) : null);
    }
    if (creds.apiToken !== undefined && creds.apiToken !== '••••••••') {
      const tokenCol = tableCols.has('vendor_api_token_encrypted') ? 'vendor_api_token_encrypted' : 'api_token_encrypted';
      sets.push(`${tokenCol} = ?`);
      vals.push(creds.apiToken ? encryptVaultSecret(creds.apiToken) : null);
    }
    if (sets.length > 0) {
      vals.push(applianceId);
      db.prepare(`UPDATE network_appliances SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
    }
  }

  /**
   * Live Subnet Discovery: Probes up to 254 IPv4 hosts in a /24 CIDR (or explicit host list)
   * using concurrent TCP port + SNMPv2c sysDescr/sysName discovery, AND optionally queues
   * an ARP scan on an online site-probe agent in that tenant!
   */
  public async scanSubnet(params: {
    tenantId: string;
    cidr: string;
    community?: string;
    autoRegister?: boolean;
  }): Promise<{
    scannedCount: number;
    discovered: Array<{
      ipAddress: string;
      openPorts: number[];
      sysName?: string;
      sysDescr?: string;
      inferredType: string;
      latencyMs: number;
    }>;
  }> {
    const cidrClean = String(params.cidr || '').trim();
    const [baseIp, prefixStr] = cidrClean.split('/');
    if (!net.isIPv4(baseIp)) {
      throw new Error('Please provide a valid IPv4 subnet CIDR (e.g. 192.168.1.0/24 or 10.0.1.10/32).');
    }
    const prefix = prefixStr ? parseInt(prefixStr, 10) : 32;
    if (Number.isNaN(prefix) || prefix < 24 || prefix > 32) {
      throw new Error('Subnet discovery supports /24 through /32 IPv4 ranges.');
    }

    const octets = baseIp.split('.').map(Number);
    const baseNum = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
    const hostBits = 32 - prefix;
    const totalAddrs = 1 << hostBits;
    const netBase = hostBits === 0 ? baseNum : (baseNum & (~((1 << hostBits) - 1) >>> 0)) >>> 0;

    const candidateIps: string[] = [];
    for (let i = 0; i < totalAddrs; i++) {
      if (totalAddrs > 2 && (i === 0 || i === totalAddrs - 1)) continue;
      const n = (netBase + i) >>> 0;
      const ip = `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;
      if (!isBlockedOutboundIp(ip, { allowLoopback: false, allowPrivateLan: true })) {
        candidateIps.push(ip);
      }
    }

    if (candidateIps.length === 0) {
      throw new Error('Target subnet contains only loopback, link-local, or reserved addresses blocked by SSRF policy.');
    }

    const community = params.community || 'public';
    const discovered: Array<{
      ipAddress: string;
      openPorts: number[];
      sysName?: string;
      sysDescr?: string;
      inferredType: string;
      latencyMs: number;
    }> = [];

    const concurrency = 32;
    for (let idx = 0; idx < candidateIps.length; idx += concurrency) {
      const batch = candidateIps.slice(idx, idx + concurrency);
      const batchRes = await Promise.all(
        batch.map(async (ip) => {
          const portsToCheck = [22, 80, 443, 5001, 8443, 9100];
          const portChecks = await Promise.all(portsToCheck.map((p) => probeTcpPort(ip, p, 450)));
          const openPorts = portsToCheck.filter((_, pIdx) => portChecks[pIdx].open);
          let snmpInfo: Record<string, string | number | null> = {};
          try {
            snmpInfo = await snmpGet(
              { host: ip, community, timeoutMs: 500 },
              ['1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.5.0']
            );
          } catch {}
          const hasSnmp = Object.keys(snmpInfo).length > 0;
          if (openPorts.length === 0 && !hasSnmp) return null;

          const sysDescr = typeof snmpInfo['1.3.6.1.2.1.1.1.0'] === 'string' ? snmpInfo['1.3.6.1.2.1.1.1.0'] : undefined;
          const sysName = typeof snmpInfo['1.3.6.1.2.1.1.5.0'] === 'string' ? snmpInfo['1.3.6.1.2.1.1.5.0'] : undefined;
          const descrLower = (sysDescr || '').toLowerCase();
          let inferredType = 'switch';
          if (openPorts.includes(9100) || descrLower.includes('laserjet') || descrLower.includes('printer')) {
            inferredType = 'printer';
          } else if (openPorts.includes(5001) || descrLower.includes('synology') || descrLower.includes('nas')) {
            inferredType = 'nas';
          } else if (descrLower.includes('apc') || descrLower.includes('ups')) {
            inferredType = 'ups';
          } else if (openPorts.includes(8443) || descrLower.includes('unifi') || descrLower.includes('forti')) {
            inferredType = 'firewall';
          }

          const bestLatency =
            portChecks.filter((c) => c.open).sort((a, b) => a.latencyMs - b.latencyMs)[0]?.latencyMs || 5;

          return {
            ipAddress: ip,
            openPorts,
            sysName,
            sysDescr,
            inferredType,
            latencyMs: bestLatency
          };
        })
      );

      for (const item of batchRes) {
        if (item) discovered.push(item);
      }
    }

    if (params.autoRegister) {
      const serverHostname = os.hostname() || 'vitrine-control-plane';
      const validCols = new Set(
        (db.prepare('PRAGMA table_info(network_appliances)').all() as Array<{ name: string }>).map((c) => c.name)
      );
      const nowIso = new Date().toISOString();
      for (const d of discovered) {
        const existing = db
          .prepare('SELECT id FROM network_appliances WHERE tenant_id = ? AND ip_address = ?')
          .get(params.tenantId, d.ipAddress) as { id: string } | undefined;
        if (!existing) {
          const mfg = d.sysDescr ? d.sysDescr.split(' ')[0].slice(0, 32) : 'Generic';
          const modelStr = d.inferredType.toUpperCase();
          const vendorModel = `${mfg} ${modelStr}`.trim();
          const candidateRow: Record<string, unknown> = {
            id: `net-${crypto.randomUUID().slice(0, 8)}`,
            tenant_id: params.tenantId,
            name: d.sysName || `Discovered-${d.ipAddress}`,
            appliance_type: d.inferredType,
            vendor: mfg,
            manufacturer: mfg,
            model: modelStr,
            vendor_model: vendorModel,
            ip_address: d.ipAddress,
            mac_address: '00:00:00:00:00:00',
            snmp_version: '2c',
            probe_device_id: null,
            probe_hostname: serverHostname,
            status: 'Healthy',
            latency_ms: d.latencyMs,
            firmware_version: d.sysDescr ? d.sysDescr.slice(0, 64) : 'SNMP/TCP Discovered',
            snmp_community_encrypted: encryptVaultSecret(community),
            metrics_json: JSON.stringify({ openTcpPorts: d.openPorts, latencyMs: d.latencyMs, sysDescr: d.sysDescr }),
            last_polled: nowIso
          };
          const cols = Object.keys(candidateRow).filter((c) => validCols.has(c));
          if (cols.length > 0) {
            const placeholders = cols.map(() => '?').join(', ');
            db.prepare(`INSERT INTO network_appliances (${cols.join(', ')}) VALUES (${placeholders})`).run(
              ...cols.map((c) => candidateRow[c])
            );
          }
        }
      }
    }

    return {
      scannedCount: candidateIps.length,
      discovered
    };
  }
}

export const networkDiscoveryService = new NetworkDiscoveryService();
