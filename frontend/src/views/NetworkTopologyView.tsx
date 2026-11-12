import React, { useState, useEffect, useCallback } from 'react';
import {
  Router,
  RefreshCw,
  Plus,
  X,
  Shield,
  BatteryCharging,
  HardDrive,
  Printer,
  Activity,
  Trash2,
  Wifi,
  Cpu,
  Camera,
  PhoneCall,
  Thermometer,
  Monitor,
  Globe,
  BookOpen,
  CheckCircle2
} from 'lucide-react';
import { NetworkAppliance } from '../types/index.js';
import {
  fetchTopology,
  triggerTopologyScan,
  addTopologyPort,
  fetchNetworkAppliances,
  createNetworkAppliance,
  pollNetworkAppliance,
  deleteNetworkAppliance
} from '../services/api.js';

interface SwitchPort {
  port: string;
  vlan: number | string;
  speed: string;
  status: string;
  lldpNeighbor: string;
}

interface CoreSwitch {
  name: string;
  ip: string;
  ports: SwitchPort[];
}

interface DiscoveredSubnet {
  subnet: string;
  probeHost: string;
  totalDiscovered: number;
  unmanaged: number;
}

interface TopologyData {
  coreSwitch: CoreSwitch;
  discoveredSubnets: DiscoveredSubnet[];
}

export const NetworkTopologyView: React.FC = () => {
  const [data, setData] = useState<TopologyData | null>(null);
  const [appliances, setAppliances] = useState<NetworkAppliance[]>([]);
  const [pollingId, setPollingId] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanMsg, setScanMsg] = useState<string | null>(null);

  // Add Switch Port Modal
  const [showAddPort, setShowAddPort] = useState(false);
  const [newPort, setNewPort] = useState('Gi1/0/5');
  const [newVlan, setNewVlan] = useState(10);
  const [newSpeed, setNewSpeed] = useState('1 Gbps');
  const [newNeighbor, setNewNeighbor] = useState('');

  // Add Network Appliance Modal
  const [showAddAppliance, setShowAddAppliance] = useState(false);
  const [appName, setAppName] = useState('');
  const [appType, setAppType] = useState<string>('wap');
  const [appVendor, setAppVendor] = useState('Ubiquiti UniFi Dream Machine Pro Max + U7-Pro APs');
  const [appIp, setAppIp] = useState('10.200.10.2');
  const [appProtocol, setAppProtocol] = useState<string>('ubiquiti_unifi_api');
  const [appApiEndpoint, setAppApiEndpoint] = useState('https://10.200.10.2/proxy/network/integration/v1/sites');
  const [appApiToken, setAppApiToken] = useState('');
  const [appSnmp, setAppSnmp] = useState('UniFi OS Local REST API (X-API-KEY) + SNMPv3');
  const [showSetupGuideModal, setShowSetupGuideModal] = useState(false);
  const [selectedGuideProtocol, setSelectedGuideProtocol] = useState<string>('ubiquiti_unifi_api');

  const VENDOR_SETUP_GUIDES: Record<
    string,
    {
      title: string;
      vendorBadge: string;
      defaultEndpoint: string;
      snmpLabel: string;
      supportedHardware: string;
      steps: string[];
      fallbackNote: string;
    }
  > = {
    ubiquiti_unifi_api: {
      title: 'Ubiquiti UniFi OS (Network, Switches, U7/U6 APs & UniFi Protect NVR/Cameras)',
      vendorBadge: 'Native Vendor REST API + SNMPv3',
      defaultEndpoint: 'https://10.200.10.2/proxy/network/integration/v1/sites',
      snmpLabel: 'UniFi OS Local REST API (X-API-KEY) + SNMPv3',
      supportedHardware: 'UDM-Pro / Pro Max, UCG-Ultra, Cloud Key Gen2+, USW Pro Switches, U6/U7 APs, UNVR / UNVR-Pro Protect Cameras & Door Access',
      steps: [
        '1. Log in locally to your UniFi OS Console (e.g., https://10.200.10.2) with an Owner or Super Admin account.',
        '2. Navigate to Control Plane (or Console Settings) → Integrations → Official UniFi Integration API.',
        '3. Click "Create New API Key", name it "Vitrine-RMM-Local-Probe", and copy the generated X-API-KEY token.',
        '4. (Optional for Layer-2 Switch Port & PoE OIDs) In UniFi Network → Settings → System → Advanced → SNMP, enable SNMPv3 and create a read-only username/passphrase.',
        '5. Paste the Console IP and X-API-KEY into Vitrine below. Your designated online Vitrine Agent on that LAN will poll the UniFi OS Console locally over HTTPS (port 443) without requiring cloud exposure!'
      ],
      fallbackNote: 'For older standalone EdgeMax / EdgeSwitch units without UniFi OS, select Generic SNMPv3 + ICMP Probe.'
    },
    redfish_idrac_ilo_api: {
      title: 'Dell iDRAC 9 / HPE iLO 5 & 6 / Supermicro BMC (DMTF Redfish REST API)',
      vendorBadge: 'DMTF Redfish v1 + IPMI 2.0',
      defaultEndpoint: 'https://10.200.10.240/redfish/v1/Systems/System.Embedded.1',
      snmpLabel: 'DMTF Redfish REST API v1 + IPMI / SNMPv3',
      supportedHardware: 'Dell PowerEdge (iDRAC 8/9), HPE ProLiant (iLO 5/6), Lenovo ThinkSystem XClarity, Supermicro Redfish BMC',
      steps: [
        '1. Open the out-of-band management web console (iDRAC / iLO) on your management VLAN.',
        '2. Navigate to iDRAC Settings → Users (or iLO Administration → User Administration) and create a dedicated "vitrine-probe" user with Read-Only / Operator Telemetry privileges.',
        '3. Ensure Redfish REST API is enabled under Services → Redfish (enabled by default on iDRAC 9 & iLO 5/6 over HTTPS 443).',
        '4. Enter the BMC IP address and read-only credentials below so the local Vitrine LAN Probe can monitor PSU redundancy, hardware RAID cache batteries, ECC DIMM errors, and thermal sensors even if the host OS BSODs.'
      ],
      fallbackNote: 'If Redfish is disabled on legacy servers, Vitrine automatically falls back to SNMPv3 / IPMI 2.0 chassis health polling.'
    },
    fortinet_fortios_api: {
      title: 'Fortinet FortiGate / Cisco Meraki / pfSense / OPNsense Firewall APIs',
      vendorBadge: 'Native Firewall REST API + SNMPv3',
      defaultEndpoint: 'https://10.200.10.254/api/v2/monitor/system/status',
      snmpLabel: 'FortiOS REST API Bearer Token + SNMPv3',
      supportedHardware: 'Fortinet FortiGate (FortiOS 7.x), Cisco Meraki MX/MS/MR, Netgate pfSense+, OPNsense, SonicWall',
      steps: [
        '1. In FortiGate GUI, go to System → Administrators → Create New → REST API Admin.',
        '2. Username: "vitrine_rmm_ro", Administrator Profile: Read-Only system/network profile.',
        '3. Restrict Trusted Hosts to the LAN IP of your designated Vitrine Probe Server (e.g., 10.200.10.10/32) for zero-trust isolation.',
        '4. Copy the generated API Bearer Token and paste it below to track WAN failover state, IPsec site-to-site tunnels, IPS status, and active session counts.'
      ],
      fallbackNote: 'For firewalls without a REST API, select Generic SNMPv3 + ICMP Probe to monitor IF-MIB interface throughput and WAN ping latency.'
    },
    synology_qnap_api: {
      title: 'Synology DSM / QNAP QTS / TrueNAS SAN & NAS Storage Arrays',
      vendorBadge: 'Storage REST API + SNMPv3 Storage MIBs',
      defaultEndpoint: 'https://192.168.40.20:5001/webapi/entry.cgi?api=SYNO.Storage.CGI.Storage',
      snmpLabel: 'Synology DSM / TrueNAS API + SNMPv3',
      supportedHardware: 'Synology RackStation / DiskStation (DSM 7.x), QNAP Enterprise QTS/QuTS hero, TrueNAS SCALE/CORE',
      steps: [
        '1. In Synology DSM, open Control Panel → Terminal & SNMP → Enable SNMPv3 service (and copy the Privacy/Auth credentials).',
        '2. For deep RAID pool, Btrfs scrub, and NVMe cache telemetry, create a read-only DSM service account or TrueNAS API Key (Settings → API Keys).',
        '3. Enter the NAS IP and token/SNMP credentials below to alert on degraded RAID pools, reallocated drive sectors, or storage pools exceeding policy thresholds.'
      ],
      fallbackNote: 'Standard SYNOLOGY-DISK-MIB / HOST-RESOURCES-MIB OIDs are also polled automatically via the local LAN agent probe.'
    },
    apc_eaton_ups_probe: {
      title: 'APC Smart-UPS (NMC3) / Eaton / CyberPower Battery & PDU Systems',
      vendorBadge: 'PowerNet MIB SNMPv3 + NMC REST Probe',
      defaultEndpoint: 'snmpv3://10.200.10.6:161 (PowerNet-MIB .1.3.6.1.4.1.318)',
      snmpLabel: 'APC NMC3 / Eaton PowerNet SNMPv3 (AES/SHA)',
      supportedHardware: 'APC Smart-UPS with AP9630/AP9640/AP9641 NMC3, Eaton 9PX/5PX, CyberPower Switched PDUs',
      steps: [
        '1. Log in to the APC Network Management Card (NMC3) web UI → Configuration → Network → SNMPv3 → Access.',
        '2. Enable SNMPv3 and configure User Profile 1 with Authentication Protocol SHA and Privacy Protocol AES-128/256.',
        '3. Under Access Control, allow your local subnet or the IP of your designated Vitrine Probe endpoint.',
        '4. Vitrine will continuously track On-Battery switchover events, runtime remaining (minutes), battery temperature, and overdue battery replacement flags.'
      ],
      fallbackNote: 'USB-connected UPS units attached directly to a Windows/Linux server are also auto-detected via the host Vitrine Agent.'
    },
    generic_snmp_v3: {
      title: 'Generic Network & Specialty Probes (Printers, VoIP PBX, Env Sensors, Kiosks, SSL/WAN)',
      vendorBadge: 'Universal Agent-Relayed Probe (SNMPv2c/v3 + TCP/HTTP/ICMP)',
      defaultEndpoint: 'snmpv3://10.200.10.250:161 + icmp + tcp',
      snmpLabel: 'SNMPv3 (AES-256 / SHA-2) + ICMP / TCP Port Probe',
      supportedHardware: 'HP/Brother/Ricoh Printers (Printer-MIB), 3CX/FreePBX/Yealink VoIP, AVTECH RoomAlert / APC NetBotz Sensors, POS Kiosks, HTTPS/SSL Endpoints',
      steps: [
        '1. When a specialty device does not offer a vendor REST API, Vitrine uses an online Managed Agent in the same site/subnet as a zero-config LAN Probe.',
        '2. Enable SNMPv3 (recommended) or read-only SNMPv2c on the target device (Printer, Environmental Sensor, Managed Switch, or VoIP Gateway).',
        '3. Even if the device does not support SNMP at all, Vitrine still monitors ICMP ping RTT, packet loss %, TCP service ports (e.g., 443, 5060 SIP, 554 RTSP, 9100 JetDirect), and SSL certificate expiration days!',
        '4. Any threshold breach automatically routes through your 4-Tier Condition & State Notification Matrix (Web UI, Email, and/or Direct PSA Ticket).'
      ],
      fallbackNote: 'Works with any IP-addressable appliance on the LAN without opening inbound firewall ports.'
    }
  };

  const loadTopology = useCallback(() => {
    fetchTopology().then((res) => setData(res as unknown as TopologyData));
    fetchNetworkAppliances().then(setAppliances).catch(console.error);
  }, []);

  useEffect(() => {
    loadTopology();
  }, [loadTopology]);

  const handleTriggerSweep = async () => {
    setScanning(true);
    try {
      await triggerTopologyScan();
      setScanMsg('ARP, LLDP & SNMPv3 local agent probe sweep complete.');
      loadTopology();
      setTimeout(() => setScanMsg(null), 4000);
    } finally {
      setScanning(false);
    }
  };

  const handlePollAppliance = async (id: string) => {
    setPollingId(id);
    try {
      const res = await pollNetworkAppliance(id);
      if (res.success && res.appliance) {
        setAppliances((prev) => prev.map((a) => (a.id === id ? res.appliance : a)));
        setScanMsg(`SNMP Probe ${res.appliance.probe_hostname} polled ${res.appliance.name} (${res.appliance.ip_address}): RTT ${res.appliance.latency_ms} ms`);
        setTimeout(() => setScanMsg(null), 4000);
      }
    } finally {
      setPollingId(null);
    }
  };

  const handleCreateAppliance = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!appName.trim() || !appIp.trim()) return;
    const guide = VENDOR_SETUP_GUIDES[appProtocol] || VENDOR_SETUP_GUIDES.generic_snmp_v3;
    const res = await createNetworkAppliance({
      name: appName.trim(),
      appliance_type: appType,
      vendor_model: appVendor.trim() || 'Enterprise Specialty Appliance',
      ip_address: appIp.trim(),
      snmp_version: appSnmp || guide.snmpLabel,
      integration_protocol: appProtocol,
      vendor_api_endpoint: appApiEndpoint.trim() || guide.defaultEndpoint,
      vendor_api_token: appApiToken.trim() || undefined
    });
    if (res.success) {
      loadTopology();
      setShowAddAppliance(false);
      setAppName('');
      setAppApiToken('');
    }
  };

  const handleDeleteAppliance = async (id: string, name: string) => {
    if (!confirm(`Remove network appliance monitor "${name}"?`)) return;
    await deleteNetworkAppliance(id);
    setAppliances((prev) => prev.filter((a) => a.id !== id));
  };

  const handleAddPort = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPort.trim() || !newNeighbor.trim()) return;
    await addTopologyPort({
      port: newPort.trim(),
      vlan: newVlan,
      speed: newSpeed,
      status: 'Up',
      lldpNeighbor: newNeighbor.trim()
    });
    loadTopology();
    setShowAddPort(false);
    setNewNeighbor('');
  };

  if (!data) return <div>Loading topology &amp; SNMP mappings...</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="network-topology-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
            Network Appliances, Specialty Endpoints &amp; Vendor API Probes
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Native Vendor APIs (Ubiquiti UniFi OS, Dell iDRAC / HPE iLO Redfish, FortiOS, Synology DSM, APC NMC3) + Generic LAN Agent Probes
          </span>
        </div>
        <div style={{ display: 'flex', gap: '0.65rem', flexWrap: 'wrap' }}>
          <button
            className="btn-glass"
            style={{ borderColor: 'rgba(56, 189, 248, 0.45)', color: '#38bdf8' }}
            onClick={() => setShowSetupGuideModal(true)}
          >
            <BookOpen size={15} /> Vendor API &amp; Probe Setup Guide
          </button>
          <button className="btn-glass" onClick={() => setShowAddAppliance(true)}>
            <Plus size={15} /> Add Specialty / Network Appliance
          </button>
          <button className="btn-glass" onClick={() => setShowAddPort(true)}>
            <Plus size={15} /> Map Switch Port
          </button>
          <button className="btn-glass btn-primary" onClick={handleTriggerSweep} disabled={scanning}>
            <RefreshCw size={15} /> {scanning ? 'Sweeping Subnets...' : 'Trigger Subnet Sweep'}
          </button>
        </div>
      </div>

      {scanMsg && (
        <div
          className="glass-card"
          style={{
            padding: '0.75rem 1.25rem',
            background: 'rgba(0, 242, 254, 0.12)',
            borderColor: 'rgba(0, 242, 254, 0.35)',
            color: '#38bdf8',
            fontSize: '0.85rem'
          }}
        >
          ✓ {scanMsg}
        </div>
      )}

      {/* Agent-Relayed Network Appliances & SNMP Infrastructure Monitors */}
      <div className="glass-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0 }}>
              Network Appliances &amp; SNMP Infrastructure Monitors ({appliances.length})
            </h3>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>
              Polled over LAN by designated online Managed Agent Probes in the same company &amp; subnet
            </span>
          </div>
          <span className="status-pill status-online">SNMPv3 + ICMP Probe Relay Active</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1rem' }}>
          {appliances.map((app) => {
            const tLower = (app.appliance_type || '').toLowerCase();
            const IconComp =
              tLower.includes('firewall')
                ? Shield
                : tLower.includes('wap') || tLower.includes('wireless')
                ? Wifi
                : tLower.includes('ups')
                ? BatteryCharging
                : tLower.includes('nas') || tLower.includes('san')
                ? HardDrive
                : tLower.includes('printer')
                ? Printer
                : tLower.includes('oob') || tLower.includes('bmc')
                ? Cpu
                : tLower.includes('nvr') || tLower.includes('camera')
                ? Camera
                : tLower.includes('voip') || tLower.includes('pbx')
                ? PhoneCall
                : tLower.includes('env') || tLower.includes('sensor')
                ? Thermometer
                : tLower.includes('pos') || tLower.includes('kiosk')
                ? Monitor
                : tLower.includes('wan') || tLower.includes('ssl')
                ? Globe
                : Router;
            const isWarning = app.status === 'warning' || app.status === 'Warning';
            const isHealthy = app.status === 'online' || app.status === 'Healthy';
            return (
              <div
                key={app.id}
                className="glass-card"
                style={{
                  padding: '1rem 1.15rem',
                  background: 'var(--glass-bg)',
                  border: `1px solid ${isWarning ? 'rgba(245, 158, 11, 0.4)' : 'var(--glass-border)'}`,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.7rem'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                    <IconComp size={20} color={isWarning ? '#fbbf24' : '#38bdf8'} />
                    <div>
                      <div style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '0.45rem', flexWrap: 'wrap' }}>
                        <span>{app.name}</span>
                        {app.integration_protocol && app.integration_protocol !== 'generic_snmp_v3' && (
                          <span
                            className="status-pill"
                            style={{ fontSize: '0.62rem', background: 'rgba(168, 85, 247, 0.18)', color: '#c084fc', cursor: 'pointer' }}
                            onClick={() => {
                              setSelectedGuideProtocol(app.integration_protocol || 'ubiquiti_unifi_api');
                              setShowSetupGuideModal(true);
                            }}
                            title="Click to view Vendor API integration guide"
                          >
                            ⚡ {app.integration_protocol.replace(/_/g, ' ').toUpperCase()}
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                        {app.vendor_model} • <code>{app.ip_address}</code>
                      </div>
                    </div>
                  </div>
                  <span
                    className={`status-pill ${
                      isHealthy ? 'status-online' : isWarning ? 'status-reboot' : 'status-isolated'
                    }`}
                    style={{ fontSize: '0.7rem' }}
                  >
                    {app.status.toUpperCase()}
                  </span>
                </div>

                {app.alert_summary && (
                  <div
                    style={{
                      padding: '0.45rem 0.65rem',
                      borderRadius: '6px',
                      background: 'rgba(245, 158, 11, 0.14)',
                      border: '1px solid rgba(245, 158, 11, 0.35)',
                      color: '#fbbf24',
                      fontSize: '0.74rem'
                    }}
                  >
                    ⚠️ {app.alert_summary}
                  </div>
                )}

                <div style={{ display: 'flex', gap: '0.9rem', flexWrap: 'wrap', fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                  <span>RTT: <strong style={{ color: '#10b981' }}>{app.latency_ms} ms</strong></span>
                  <span>CPU: <strong>{app.cpu_pct}%</strong></span>
                  <span>RAM: <strong>{app.memory_pct}%</strong></span>
                  <span>Uptime: <strong>{app.uptime_days}d</strong></span>
                </div>

                {/* Appliance-Specific SNMP OID Metrics */}
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                  {Object.entries(app.metrics || {}).map(([k, v]) => (
                    <span
                      key={k}
                      style={{
                        padding: '0.2rem 0.5rem',
                        borderRadius: '5px',
                        background: 'rgba(148, 163, 184, 0.1)',
                        border: '1px solid var(--border-color)',
                        fontSize: '0.71rem',
                        color: 'var(--text-main)'
                      }}
                    >
                      <span style={{ color: 'var(--text-dim)' }}>{k}:</span> <strong>{String(v)}</strong>
                    </span>
                  ))}
                </div>

                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    paddingTop: '0.45rem',
                    borderTop: '1px solid rgba(255, 255, 255, 0.06)',
                    fontSize: '0.72rem',
                    color: 'var(--text-dim)'
                  }}
                >
                  <span>
                    Probe Relay: <strong style={{ color: '#38bdf8' }}>{app.probe_hostname}</strong> ({app.snmp_version.split(' ')[0]})
                  </span>
                  <div style={{ display: 'flex', gap: '0.4rem' }}>
                    <button
                      className="btn-glass"
                      style={{ padding: '0.2rem 0.55rem', fontSize: '0.7rem' }}
                      onClick={() => handlePollAppliance(app.id)}
                      disabled={pollingId === app.id}
                    >
                      <Activity size={11} /> {pollingId === app.id ? 'Polling...' : 'Poll Probe'}
                    </button>
                    <button
                      className="btn-glass btn-danger"
                      style={{ padding: '0.2rem 0.45rem', fontSize: '0.7rem' }}
                      onClick={() => handleDeleteAppliance(app.id, app.name)}
                    >
                      <Trash2 size={11} />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Core Switch Card */}
      <div className="glass-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
            <Router size={24} color="var(--primary)" />
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>{data.coreSwitch.name}</h3>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>IP: {data.coreSwitch.ip} • Polled via Managed Probe</span>
            </div>
          </div>
          <span className="status-pill status-online">SNMP v3 Active</span>
        </div>

        <div className="table-wrapper">
          <table className="glass-table">
            <thead>
              <tr>
                <th>Port Interface</th>
                <th>VLAN</th>
                <th>Link Speed</th>
                <th>Link Status</th>
                <th>LLDP / CDP Discovered Neighbor</th>
              </tr>
            </thead>
            <tbody>
              {data.coreSwitch.ports.map((p: SwitchPort) => (
                <tr key={p.port}>
                  <td><strong>{p.port}</strong></td>
                  <td><span className="status-pill status-reboot" style={{ fontSize: '0.72rem' }}>VLAN {p.vlan}</span></td>
                  <td>{p.speed}</td>
                  <td><span className="status-pill status-online">{p.status}</span></td>
                  <td>
                    <span style={{ fontWeight: 600, color: 'var(--primary)' }}>
                      🖥️ {p.lldpNeighbor}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Subnet Sweep Probes */}
      <div className="glass-card">
        <h3 style={{ fontSize: '1.05rem', fontWeight: 600, marginBottom: '0.75rem' }}>
          Designated Subnet ARP &amp; IP Sweeps
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
          {data.discoveredSubnets.map((s: DiscoveredSubnet, idx: number) => (
            <div key={idx} className="glass-card" style={{ padding: '1rem', background: 'var(--glass-bg)' }}>
              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--primary)' }}>{s.subnet}</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>Probe Host: {s.probeHost}</div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.85rem', fontSize: '0.8rem' }}>
                <span>Discovered: <strong>{s.totalDiscovered} hosts</strong></span>
                <span style={{ color: '#fbbf24' }}>Unmanaged: <strong>{s.unmanaged} devices</strong></span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {showAddPort && (
        <div className="modal-overlay" onClick={() => setShowAddPort(false)}>
          <div className="glass-modal" style={{ maxWidth: '460px', padding: '1.5rem' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>Map Switch Port Neighbor</h3>
              <button className="btn-glass btn-icon" onClick={() => setShowAddPort(false)}>
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleAddPort} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Switch Port Interface
                  </label>
                  <input
                    type="text"
                    required
                    className="glass-input"
                    value={newPort}
                    onChange={(e) => setNewPort(e.target.value)}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    VLAN ID
                  </label>
                  <input
                    type="number"
                    className="glass-input"
                    value={newVlan}
                    onChange={(e) => setNewVlan(Number(e.target.value))}
                  />
                </div>
              </div>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Link Speed
                </label>
                <select className="glass-select" value={newSpeed} onChange={(e) => setNewSpeed(e.target.value)}>
                  <option value="1 Gbps">1 Gbps</option>
                  <option value="2.5 Gbps">2.5 Gbps</option>
                  <option value="10 Gbps">10 Gbps</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  LLDP / CDP Discovered Neighbor
                </label>
                <input
                  type="text"
                  required
                  className="glass-input"
                  placeholder="e.g. NAS-SYNOLOGY-BACKUP (10.20.4.80)"
                  value={newNeighbor}
                  onChange={(e) => setNewNeighbor(e.target.value)}
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button type="button" className="btn-glass" onClick={() => setShowAddPort(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-glass btn-primary">
                  Save Port Mapping
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
      {showAddAppliance && (
        <div className="modal-overlay" onClick={() => setShowAddAppliance(false)}>
          <div className="glass-modal" style={{ maxWidth: '620px', padding: '1.5rem' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>
                  Enroll Specialty / Network Appliance (Vendor API or LAN Probe)
                </h3>
                <span style={{ fontSize: '0.74rem', color: 'var(--text-dim)' }}>
                  Supports Native Vendor REST APIs (Ubiquiti UniFi, Redfish iDRAC/iLO, FortiOS, Synology) &amp; Generic SNMP/ICMP Probes
                </span>
              </div>
              <div style={{ display: 'flex', gap: '0.4rem' }}>
                <button
                  type="button"
                  className="btn-glass"
                  style={{ fontSize: '0.73rem', padding: '0.3rem 0.65rem', borderColor: 'rgba(56, 189, 248, 0.45)', color: '#38bdf8' }}
                  onClick={() => {
                    setSelectedGuideProtocol(appProtocol);
                    setShowSetupGuideModal(true);
                  }}
                >
                  <BookOpen size={13} /> Step-by-Step Setup Instructions
                </button>
                <button className="btn-glass btn-icon" onClick={() => setShowAddAppliance(false)}>
                  <X size={16} />
                </button>
              </div>
            </div>
            <form onSubmit={handleCreateAppliance} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Specialty Endpoint / Appliance Class
                  </label>
                  <select
                    className="glass-select"
                    value={appType}
                    onChange={(e) => {
                      const val = e.target.value;
                      setAppType(val);
                      if (val === 'wap' || val === 'nvr_camera') {
                        setAppProtocol('ubiquiti_unifi_api');
                        setAppVendor(val === 'wap' ? 'Ubiquiti UniFi UDM-Pro-Max + U7-Pro APs' : 'Ubiquiti UniFi Protect UNVR-Pro + G5 Cameras');
                        setAppApiEndpoint('https://10.200.10.2/proxy/network/integration/v1/sites');
                      } else if (val === 'oob_bmc') {
                        setAppProtocol('redfish_idrac_ilo_api');
                        setAppVendor('Dell PowerEdge R760 (iDRAC 9 Enterprise)');
                        setAppApiEndpoint('https://10.200.10.240/redfish/v1/Systems/System.Embedded.1');
                      } else if (val === 'firewall') {
                        setAppProtocol('fortinet_fortios_api');
                        setAppVendor('Fortinet FortiGate 200F (FortiOS 7.4)');
                        setAppApiEndpoint('https://10.200.10.254/api/v2/monitor/system/status');
                      } else if (val === 'nas') {
                        setAppProtocol('synology_qnap_api');
                        setAppVendor('Synology RackStation RS3621xs+ (DSM 7.2)');
                        setAppApiEndpoint('https://192.168.40.20:5001/webapi/entry.cgi');
                      } else if (val === 'ups') {
                        setAppProtocol('apc_eaton_ups_probe');
                        setAppVendor('APC Smart-UPS SRT 3000VA (NMC3)');
                        setAppApiEndpoint('snmpv3://10.200.10.6:161');
                      } else {
                        setAppProtocol('generic_snmp_v3');
                        setAppVendor('Enterprise SNMP / LAN Monitored Appliance');
                        setAppApiEndpoint('snmpv3://10.200.10.250:161');
                      }
                    }}
                  >
                    <option value="wap">Wireless Access Points &amp; WLAN Controller (UniFi / Meraki / Aruba)</option>
                    <option value="firewall">Firewall / UTM / SD-WAN Gateway</option>
                    <option value="switch">Managed Layer-2/3 PoE Switch</option>
                    <option value="oob_bmc">Out-of-Band Server BMC (Dell iDRAC / HPE iLO / IPMI)</option>
                    <option value="ups">Smart UPS / PDU Battery System (APC / Eaton / CyberPower)</option>
                    <option value="nas">SAN / NAS Storage Array (Synology / QNAP / TrueNAS)</option>
                    <option value="nvr_camera">NVR / IP Security Cameras &amp; Door Access (UniFi Protect / ONVIF)</option>
                    <option value="voip_pbx">VoIP PBX / SIP Trunk Gateway &amp; Conference System</option>
                    <option value="env_sensor">Server Room Environmental &amp; Leak IoT Sensor</option>
                    <option value="printer">Network Printer / MFP Fleet</option>
                    <option value="pos_kiosk">POS Terminal / Kiosk / Digital Signage</option>
                    <option value="wan_ssl_probe">WAN / ISP Circuit, SSL Certificate &amp; Domain Watchdog</option>
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Vendor API / Telemetry Probe Protocol
                  </label>
                  <select
                    className="glass-select"
                    value={appProtocol}
                    onChange={(e) => {
                      const proto = e.target.value;
                      setAppProtocol(proto);
                      const g = VENDOR_SETUP_GUIDES[proto];
                      if (g) {
                        setAppApiEndpoint(g.defaultEndpoint);
                        setAppSnmp(g.snmpLabel);
                      }
                    }}
                  >
                    <option value="ubiquiti_unifi_api">Ubiquiti UniFi OS Official Integration API (X-API-KEY) + SNMPv3</option>
                    <option value="redfish_idrac_ilo_api">DMTF Redfish REST API v1 (Dell iDRAC / HPE iLO / Supermicro)</option>
                    <option value="fortinet_fortios_api">Firewall REST API (FortiOS / Meraki / pfSense / OPNsense)</option>
                    <option value="synology_qnap_api">Storage Array API (Synology DSM / QNAP / TrueNAS) + SNMPv3</option>
                    <option value="apc_eaton_ups_probe">Smart-UPS PowerNet SNMPv3 &amp; NMC Telemetry Probe</option>
                    <option value="generic_snmp_v3">Generic Agent-Relayed Probe (SNMPv3 + ICMP + TCP/HTTPS)</option>
                  </select>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Appliance Hostname / Identifier
                  </label>
                  <input
                    type="text"
                    required
                    className="glass-input"
                    placeholder="e.g. UDM-PRO-MAX-BRANCH01"
                    value={appName}
                    onChange={(e) => setAppName(e.target.value)}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    LAN IPv4 / Hostname
                  </label>
                  <input
                    type="text"
                    required
                    className="glass-input"
                    value={appIp}
                    onChange={(e) => setAppIp(e.target.value)}
                  />
                </div>
              </div>

              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Vendor &amp; Hardware Model
                </label>
                <input
                  type="text"
                  required
                  className="glass-input"
                  placeholder="e.g. Ubiquiti UniFi Dream Machine Pro Max / Dell iDRAC 9"
                  value={appVendor}
                  onChange={(e) => setAppVendor(e.target.value)}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Vendor API Endpoint / SNMP Target URI
                  </label>
                  <input
                    type="text"
                    className="glass-input"
                    value={appApiEndpoint}
                    onChange={(e) => setAppApiEndpoint(e.target.value)}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    API Key / Read-Only Token / SNMPv3 Secret
                  </label>
                  <input
                    type="password"
                    className="glass-input"
                    placeholder="X-API-KEY / Redfish / SNMPv3 AuthPriv"
                    value={appApiToken}
                    onChange={(e) => setAppApiToken(e.target.value)}
                  />
                </div>
              </div>

              {/* Inline Quick Walkthrough Summary Box */}
              <div style={{ padding: '0.75rem 0.95rem', borderRadius: '8px', background: 'rgba(56, 189, 248, 0.08)', border: '1px solid rgba(56, 189, 248, 0.3)', fontSize: '0.75rem', color: 'var(--text-main)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.3rem' }}>
                  <strong>{(VENDOR_SETUP_GUIDES[appProtocol] || VENDOR_SETUP_GUIDES.generic_snmp_v3).title}</strong>
                  <button
                    type="button"
                    className="btn-glass"
                    style={{ padding: '0.15rem 0.5rem', fontSize: '0.7rem' }}
                    onClick={() => {
                      setSelectedGuideProtocol(appProtocol);
                      setShowSetupGuideModal(true);
                    }}
                  >
                    Open Full Walkthrough
                  </button>
                </div>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.72rem' }}>
                  {(VENDOR_SETUP_GUIDES[appProtocol] || VENDOR_SETUP_GUIDES.generic_snmp_v3).steps[0]}
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button type="button" className="btn-glass" onClick={() => setShowAddAppliance(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-glass btn-primary">
                  Enroll Specialty Appliance
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Interactive Step-by-Step Vendor API & Specialty Endpoint Setup Walkthrough Modal */}
      {showSetupGuideModal && (
        <div className="modal-backdrop" onClick={() => setShowSetupGuideModal(false)}>
          <div className="glass-modal" style={{ maxWidth: '720px' }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title" style={{ color: '#38bdf8' }}>
                <BookOpen size={20} color="#38bdf8" />
                <span>Step-by-Step Specialty Device &amp; Vendor API Setup Walkthrough</span>
              </div>
              <button className="btn-glass btn-icon" onClick={() => setShowSetupGuideModal(false)}>
                <X size={18} />
              </button>
            </div>
            <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <label className="form-label">Select Vendor Integration or Generic Probe Profile</label>
                <select
                  className="glass-select"
                  value={selectedGuideProtocol}
                  onChange={(e) => setSelectedGuideProtocol(e.target.value)}
                >
                  {Object.entries(VENDOR_SETUP_GUIDES).map(([key, g]) => (
                    <option key={key} value={key}>
                      {g.title}
                    </option>
                  ))}
                </select>
              </div>

              {(() => {
                const guide = VENDOR_SETUP_GUIDES[selectedGuideProtocol] || VENDOR_SETUP_GUIDES.ubiquiti_unifi_api;
                return (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                    <div style={{ padding: '0.8rem 1rem', borderRadius: '8px', background: 'var(--glass-bg)', border: '1px solid var(--glass-border)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                        <strong style={{ fontSize: '0.88rem', color: 'var(--text-main)' }}>{guide.title}</strong>
                        <span className="status-pill status-online" style={{ fontSize: '0.68rem' }}>
                          {guide.vendorBadge}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                        <strong>Supported Hardware:</strong> {guide.supportedHardware}
                      </div>
                      <div style={{ fontSize: '0.74rem', color: '#38bdf8', marginTop: '0.25rem' }}>
                        <strong>Default Endpoint Pattern:</strong> <code>{guide.defaultEndpoint}</code>
                      </div>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.55rem' }}>
                      {guide.steps.map((step, idx) => (
                        <div
                          key={idx}
                          style={{
                            padding: '0.65rem 0.9rem',
                            borderRadius: '8px',
                            background: 'rgba(148, 163, 184, 0.08)',
                            borderLeft: '3px solid #38bdf8',
                            fontSize: '0.8rem',
                            color: 'var(--text-main)',
                            lineHeight: 1.5
                          }}
                        >
                          {step}
                        </div>
                      ))}
                    </div>

                    <div style={{ padding: '0.7rem 0.95rem', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', fontSize: '0.76rem', color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '0.55rem' }}>
                      <CheckCircle2 size={16} color="#34d399" style={{ flexShrink: 0 }} />
                      <span>
                        <strong>Fallback &amp; Probe Note:</strong> {guide.fallbackNote}
                      </span>
                    </div>
                  </div>
                );
              })()}
            </div>
            <div className="modal-footer" style={{ display: 'flex', justifyContent: 'space-between' }}>
              <button
                className="btn-glass"
                onClick={() => {
                  const g = VENDOR_SETUP_GUIDES[selectedGuideProtocol] || VENDOR_SETUP_GUIDES.ubiquiti_unifi_api;
                  setAppProtocol(selectedGuideProtocol);
                  setAppApiEndpoint(g.defaultEndpoint);
                  setAppSnmp(g.snmpLabel);
                  setShowSetupGuideModal(false);
                  setShowAddAppliance(true);
                }}
              >
                Use This Profile in Enroll Modal
              </button>
              <button className="btn-glass btn-primary" onClick={() => setShowSetupGuideModal(false)}>
                Got It
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
