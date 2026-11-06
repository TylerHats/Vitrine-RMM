import Fastify from 'fastify';
import cors from '@fastify/cors';
import fastifyStatic from '@fastify/static';
import fastifyWebsocket from '@fastify/websocket';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { initDatabase, db } from './db/index.js';
import { registerApiRoutes } from './routes/api.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  // Initialize DB schema & seeds
  initDatabase();

  const server = Fastify({
    logger: {
      level: process.env.NODE_ENV === 'production' ? 'warn' : 'info'
    }
  });

  await server.register(cors, {
    origin: true,
    credentials: true
  });

  await server.register(fastifyWebsocket);

  // Register Branding assets (robust resolution for Docker & bare-metal)
  const BRANDING_CANDIDATES = [
    path.resolve(__dirname, '../../branding'),
    path.resolve(__dirname, '../branding'),
    path.resolve(process.cwd(), 'branding')
  ];
  const BRANDING_DIR = BRANDING_CANDIDATES.find((p) => fs.existsSync(p)) || BRANDING_CANDIDATES[0];
  if (fs.existsSync(BRANDING_DIR)) {
    server.register(fastifyStatic, {
      root: BRANDING_DIR,
      prefix: '/branding/',
      decorateReply: false
    });
  }

  // WebSocket Stream: Interactive Background Shell (PowerShell, CMD, Bash, Zsh — SYSTEM/root vs Logged-in User)
  server.get('/ws/terminal', { websocket: true }, (connection: any, req: any) => {
    const socket = connection.socket || connection;
    const query = (req?.query || {}) as Record<string, string>;

    let currentDeviceId = query.deviceId || 'dev-win11-exec';
    let currentRunAs: 'system' | 'user' = query.runAs === 'user' ? 'user' : 'system';
    let currentShell = query.shell || '';

    const getDeviceInfo = (devId: string) => {
      try {
        const row = db
          .prepare('SELECT id, hostname, os_type, os_version, ip_address, cpu_model, ram_total_gb FROM devices WHERE id = ?')
          .get(devId) as any;
        if (row) return row;
      } catch {
        // fallback
      }
      if (devId.includes('mac')) {
        return {
          id: devId,
          hostname: 'MACBOOK-PRO-DESIGN',
          os_type: 'macos',
          os_version: 'macOS Sonoma 14.6.1',
          ip_address: '10.200.10.95',
          cpu_model: 'Apple M3 Max (16-Core)',
          ram_total_gb: 64
        };
      }
      if (devId.includes('lin')) {
        return {
          id: devId,
          hostname: 'APEX-SQL-CLUSTER',
          os_type: 'linux',
          os_version: 'Ubuntu 24.04.1 LTS (Kernel 6.8.0-45-generic)',
          ip_address: '10.200.50.22',
          cpu_model: 'AMD EPYC 9354P 32-Core',
          ram_total_gb: 128
        };
      }
      return {
        id: devId,
        hostname: 'WIN11-PRO-EXEC',
        os_type: 'windows',
        os_version: 'Windows 11 Pro 23H2 (Build 22631.4169)',
        ip_address: '10.200.10.42',
        cpu_model: 'Intel Core i9-14900K vPro',
        ram_total_gb: 64
      };
    };

    const resolveShell = (osType: string, requestedShell: string) => {
      if (requestedShell) return requestedShell;
      if (osType === 'macos') return 'zsh';
      if (osType === 'linux') return 'bash';
      return 'powershell';
    };

    const getIdentity = (osType: string, runAs: 'system' | 'user') => {
      if (osType === 'windows') {
        return runAs === 'system' ? 'nt authority\\system' : 'corp\\tyler.hats';
      }
      if (osType === 'macos') {
        return runAs === 'system' ? 'root' : 'tylerhats';
      }
      return runAs === 'system' ? 'root' : 'ubuntu';
    };

    const getPrompt = (dev: any, runAs: 'system' | 'user', shell: string) => {
      const osType = dev.os_type || 'windows';
      const host = (dev.hostname || 'endpoint').toLowerCase();
      if (osType === 'windows') {
        const cwd = runAs === 'system' ? 'C:\\Windows\\System32' : 'C:\\Users\\Tyler.Hats';
        return shell === 'cmd' ? `${cwd}> ` : `PS ${cwd}> `;
      }
      if (osType === 'macos') {
        const user = runAs === 'system' ? 'root' : 'tylerhats';
        const sym = runAs === 'system' ? '#' : '%';
        const dir = runAs === 'system' ? '/var/root' : '~';
        return `${user}@${host} ${dir} ${sym} `;
      }
      const user = runAs === 'system' ? 'root' : 'ubuntu';
      const sym = runAs === 'system' ? '#' : '$';
      const dir = runAs === 'system' ? '/root' : '~';
      return `${user}@${host}:${dir}${sym} `;
    };

    const buildBanner = () => {
      const dev = getDeviceInfo(currentDeviceId);
      const osType = dev.os_type || 'windows';
      const shell = resolveShell(osType, currentShell);
      currentShell = shell;
      const identity = getIdentity(osType, currentRunAs);
      const prompt = getPrompt(dev, currentRunAs, shell);
      const contextLabel =
        currentRunAs === 'system'
          ? osType === 'windows'
            ? 'NT AUTHORITY\\SYSTEM (Session 0 Non-Interactive Service Token)'
            : 'root (UID 0 Elevated Daemon Context)'
          : osType === 'windows'
            ? 'CORP\\Tyler.Hats (Interactive User Token Duplication)'
            : `${identity} (UID ${osType === 'macos' ? '501' : '1000'} Logged-In User Session)`;

      let shellHeader = '';
      if (osType === 'windows') {
        shellHeader =
          shell === 'cmd'
            ? `Microsoft Windows [Version 10.0.22631.4169]\r\n(c) Microsoft Corporation. All rights reserved.`
            : `Windows PowerShell 7.4.5 / Desktop 5.1\r\nCopyright (C) Microsoft Corporation. All rights reserved.`;
      } else if (osType === 'macos') {
        shellHeader = `Darwin ${dev.hostname} 23.6.0 Darwin Kernel Version 23.6.0: root:xnu-10063.141.2~1/RELEASE_ARM64_T6031 arm64\r\nInteractive ${shell} session initialized via LaunchDaemon PTY bridge.`;
      } else {
        shellHeader = `Linux ${dev.hostname} 6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux\r\nInteractive ${shell} session initialized via systemd PTY bridge.`;
      }

      return `\r\n\x1b[36m======================================================================\x1b[0m\r\n\x1b[1;36m  Vitrine RMM Live PTY Terminal — ${dev.hostname} (${dev.ip_address})\x1b[0m\r\n\x1b[33m  Execution Context : ${contextLabel}\x1b[0m\r\n\x1b[32m  Shell Interpreter : ${shell.toUpperCase()} (${dev.os_version})\x1b[0m\r\n\x1b[36m======================================================================\x1b[0m\r\n\r\n${shellHeader}\r\n\r\n${prompt}`;
    };

    socket.send(
      JSON.stringify({
        type: 'output',
        data: buildBanner()
      })
    );

    socket.on('message', (message: any) => {
      try {
        const parsed = JSON.parse(message.toString());

        if (parsed.type === 'switch_context') {
          if (parsed.deviceId) currentDeviceId = parsed.deviceId;
          if (parsed.runAs === 'system' || parsed.runAs === 'user') currentRunAs = parsed.runAs;
          if (parsed.shell) currentShell = parsed.shell;
          socket.send(
            JSON.stringify({
              type: 'output',
              data: `\r\n\x1b[35m[Vitrine PTY] Switching execution context -> runAs=${currentRunAs.toUpperCase()}, shell=${currentShell}...\x1b[0m\r\n` + buildBanner()
            })
          );
          return;
        }

        if (parsed.type === 'input') {
          const cmd = (parsed.data || '').trim();
          const dev = getDeviceInfo(currentDeviceId);
          const osType = dev.os_type || 'windows';
          const shell = resolveShell(osType, currentShell);
          const identity = getIdentity(osType, currentRunAs);
          const prompt = getPrompt(dev, currentRunAs, shell);
          let out = '';

          if (!cmd) {
            socket.send(JSON.stringify({ type: 'output', data: `\r\n${prompt}` }));
            return;
          }

          if (cmd === 'clear' || cmd === 'cls') {
            socket.send(JSON.stringify({ type: 'output', data: `\x1b[2J\x1b[H${prompt}` }));
            return;
          }

          if (cmd === 'whoami') {
            out = `${identity}`;
          } else if (cmd === 'id') {
            if (osType === 'windows') {
              out =
                currentRunAs === 'system'
                  ? `USER INFORMATION\r\n----------------\r\nUser Name           SID\r\n=================== ========\r\nnt authority\\system S-1-5-18\r\nPrivileges: SeDebugPrivilege (Enabled), SeTcbPrivilege (Enabled), SeImpersonatePrivilege (Enabled)`
                  : `USER INFORMATION\r\n----------------\r\nUser Name        SID\r\n================ ==========================================\r\ncorp\\tyler.hats  S-1-5-21-384920194-192049102-84920194-1104\r\nGroups: CORP\\Domain Users, BUILTIN\\Administrators`;
            } else if (osType === 'macos') {
              out =
                currentRunAs === 'system'
                  ? `uid=0(root) gid=0(wheel) groups=0(wheel),1(daemon),2(kmem),3(sys),4(tty),5(operator),8(procview),9(procmod),20(staff),80(admin)`
                  : `uid=501(tylerhats) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts),79(_appserverusr),80(admin),81(_appserveradm)`;
            } else {
              out =
                currentRunAs === 'system'
                  ? `uid=0(root) gid=0(root) groups=0(root)`
                  : `uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),46(plugdev),998(docker)`;
            }
          } else if (cmd === 'hostname') {
            out = `${dev.hostname}`;
          } else if (cmd.startsWith('uname')) {
            if (osType === 'macos') {
              out = `Darwin ${dev.hostname} 23.6.0 Darwin Kernel Version 23.6.0: Mon Jul 29 21:14:30 PDT 2024; root:xnu-10063.141.2~1/RELEASE_ARM64_T6031 arm64`;
            } else if (osType === 'linux') {
              out = `Linux ${dev.hostname} 6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux`;
            } else {
              out = `Windows_NT ${dev.hostname} 10.0.22631 x86_64`;
            }
          } else if (cmd === 'sw_vers') {
            out = `ProductName:\t\tmacOS\r\nProductVersion:\t\t14.6.1\r\nBuildVersion:\t\t23G93`;
          } else if (cmd === 'Get-Process' || cmd === 'ps' || cmd === 'ps aux') {
            if (osType === 'windows') {
              out = `Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id ProcessName\r\n-------  ------    -----      -----     ------     -- -----------\r\n    540      38    24108      42104       1.24   5124 VitrineAgentService\r\n    412      24    18420      28500       0.98   5892 MeshAgent\r\n   1820     110   184210     320400       8.45   4210 MsMpEng\r\n   2450     180   410290     890500      18.20   7920 chrome`;
            } else if (osType === 'macos') {
              out = `USER               PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND\r\nroot                 1   0.2  0.1 40862832  26400   ??  Ss   10:00AM   0:14.22 /sbin/launchd\r\n_windowserver      158   5.4  0.8 42910420 482000   ??  Ss   10:00AM  12:41.10 /System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer\r\nroot               618   0.3  0.1 41029400  34800   ??  Ss   10:01AM   0:45.18 /Library/Application Support/VitrineRMM/vitrine-agent-darwin\r\ntylerhats          892   0.9  0.3 41892010 178400   ??  S    10:02AM   1:12.04 /System/Library/CoreServices/Finder.app/Contents/MacOS/Finder`;
            } else {
              out = `USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\nroot           1  0.1  0.0 168940 18500 ?        Ss   Oct28   0:19 /sbin/init\r\nroot         512  0.0  0.0  15420 14800 ?        Ss   Oct28   0:02 sshd: /usr/sbin/sshd -D\r\nroot         690  1.4  0.2 1894020 148200 ?      Ssl  Oct28  14:22 /usr/bin/dockerd -H fd://\r\nroot         820  0.3  0.1 724100 24000 ?        Ssl  Oct28   3:11 /opt/vitrine-rmm/vitrine-agent\r\npostgres    1180  0.9  0.4 2410200 210500 ?      Ss   Oct28   8:44 postgres: writer process`;
            }
          } else if (cmd === 'Get-BitLockerVolume' || cmd.startsWith('fdesetup') || cmd.startsWith('cryptsetup')) {
            if (osType === 'windows') {
              out =
                currentRunAs === 'system'
                  ? `   VolumeType: OperatingSystem\r\n   Mount Point: C:\r\n   CapacityGB: 1024.0\r\n   VolumeStatus: FullyEncrypted\r\n   EncryptionMethod: XtsAes256\r\n   ProtectionStatus: ProtectionOn\r\n   LockStatus: Unlocked\r\n   KeyProtector: RecoveryPassword (481920-592019-209184-102948-592810-482019)`
                  : `Get-BitLockerVolume : Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))\r\nTip: Switch execution context to SYSTEM to read BitLocker recovery protectors.`;
            } else if (osType === 'macos') {
              out = `FileVault is On.\r\nVolume disk3s1 (Macintosh HD) encrypted with APFS XTS-AES-128.\r\nInstitutional Recovery Key escrowed to Vitrine RMM Vault.`;
            } else {
              out = `/dev/mapper/ubuntu--vg-ubuntu--lv is active and is in use.\r\n  type:    LUKS2\r\n  cipher:  aes-xts-plain64\r\n  keysize: 512 bits\r\n  device:  /dev/nvme0n1p3`;
            }
          } else if (cmd.startsWith('Get-Service') || cmd.startsWith('systemctl') || cmd.startsWith('launchctl')) {
            if (osType === 'windows') {
              out = `Status   Name               DisplayName\r\n------   ----               -----------\r\nRunning  Spooler            Print Spooler\r\nRunning  VitrineAgent       Vitrine RMM Orchestration Engine\r\nRunning  MeshAgent          MeshCentral Remote Management Agent\r\nRunning  WinDefend          Microsoft Defender Antivirus Service\r\nRunning  wuauserv           Windows Update`;
            } else if (osType === 'macos') {
              out = `PID\tStatus\tLabel\r\n618\t0\tcom.vitrine.agent\r\n645\t0\tcom.meshcentral.agent\r\n158\t0\tcom.apple.WindowServer\r\n440\t0\tcom.apple.securityd\r\n-\t0\tcom.apple.backupd`;
            } else {
              out = `  UNIT                            LOAD   ACTIVE SUB     DESCRIPTION\r\n  vitrine-agent.service           loaded active running Vitrine RMM Telemetry & Enforcement Daemon\r\n  meshagent.service               loaded active running MeshCentral Linux Agent Tunnel\r\n  ssh.service                     loaded active running OpenBSD Secure Shell server\r\n  docker.service                  loaded active running Docker Application Container Engine\r\n  postgresql.service              loaded active running PostgreSQL RDBMS Cluster Service`;
            }
          } else if (cmd === 'ipconfig' || cmd === 'Get-NetIPConfiguration' || cmd === 'ip a' || cmd === 'ifconfig') {
            if (osType === 'windows') {
              out = `Windows IP Configuration\r\n\r\nEthernet adapter Ethernet0 (Intel I225-V 2.5GbE):\r\n   Connection-specific DNS Suffix  . : corp.local\r\n   IPv4 Address. . . . . . . . . . . : ${dev.ip_address}\r\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0\r\n   Default Gateway . . . . . . . . . : ${dev.ip_address.split('.').slice(0, 3).join('.')}.1`;
            } else if (osType === 'macos') {
              out = `en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\r\n\tether 3c:22:fb:91:04:19\r\n\tinet ${dev.ip_address} netmask 0xffffff00 broadcast ${dev.ip_address.split('.').slice(0, 3).join('.')}.255\r\n\tstatus: active`;
            } else {
              out = `2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000\r\n    link/ether 00:16:3e:74:12:9a brd ff:ff:ff:ff:ff:ff\r\n    inet ${dev.ip_address}/24 brd ${dev.ip_address.split('.').slice(0, 3).join('.')}.255 scope global dynamic eth0`;
            }
          } else if (cmd === 'df -h') {
            out = `Filesystem      Size  Used Avail Use% Mounted on\r\n/dev/nvme0n1p2  1.0T  412G  588G  42% /\r\ntmpfs            32G  4.1M   32G   1% /run`;
          } else if (cmd === 'free -m') {
            const totalMb = (dev.ram_total_gb || 32) * 1024;
            const usedMb = Math.round(totalMb * 0.38);
            const freeMb = totalMb - usedMb;
            out = `               total        used        free      shared  buff/cache   available\r\nMem:           ${totalMb}       ${usedMb}       ${freeMb}         412        4096       ${freeMb}`;
          } else if (cmd === 'systeminfo') {
            out = `Host Name:                 ${dev.hostname}\r\nOS Name:                   ${dev.os_version}\r\nProcessor(s):              ${dev.cpu_model}\r\nTotal Physical Memory:     ${(dev.ram_total_gb || 32) * 1024} MB\r\nIPv4 Address:              ${dev.ip_address}\r\nExecution Token:           ${identity}`;
          } else if (cmd.startsWith('gpupdate')) {
            out = `Updating policy...\r\n\r\nComputer Policy update has completed successfully.\r\nUser Policy update has completed successfully.`;
          } else if (cmd.startsWith('winget') || cmd.startsWith('brew') || cmd.startsWith('apt')) {
            if (osType === 'macos') {
              out = `Formulae / Casks Managed via Homebrew:\r\ngoogle-chrome   129.0.6668.70\r\niterm2          3.5.4\r\nopenssl@3       3.3.2\r\nvitrine-agent   2.2.0`;
            } else if (osType === 'linux') {
              out = `Listing... Done\r\ndocker-ce/noble 5:27.2.0-1~ubuntu.24.04~noble amd64 [installed]\r\nnginx/noble-updates 1.24.0-2ubuntu7.1 amd64 [installed]\r\npostgresql-16/noble-updates 16.4-0ubuntu0.24.04.2 amd64 [installed]\r\nvitrine-agent/stable 2.2.0 amd64 [installed]`;
            } else {
              out = `Name                           Id                    Version         Available\r\n------------------------------------------------------------------------------\r\nGoogle Chrome Enterprise       Google.Chrome         128.0.6613.119  129.0.6668.70\r\n7-Zip 23.01 (x64)              7zip.7zip             23.01           -\r\nZoom Workplace                 Zoom.Zoom             5.17.5          6.2.3`;
            }
          } else if (cmd.startsWith('ls') || cmd === 'dir') {
            if (osType === 'windows') {
              out = `    Directory: C:\\Program Files\\VitrineRMM\r\n\r\nMode                 LastWriteTime         Length Name\r\n----                 -------------         ------ ----\r\nd-----        10/11/2026   4:30 PM                logs\r\n-a----        10/10/2026  12:00 PM       14205820 VitrineAgent.exe\r\n-a----        10/08/2026   9:30 AM        8421000 MeshAgent.exe\r\n-a----        10/11/2026   8:15 AM           1420 config.json`;
            } else {
              out = `total 24120\r\ndrwxr-xr-x 4 root root     4096 Nov  5 16:30 .\r\ndrwxr-xr-x 1 root root     4096 Oct 10 09:00 ..\r\n-rwxr-xr-x 1 root root 12450800 Oct 22 10:00 vitrine-agent\r\n-rwxr-xr-x 1 root root  8192400 Oct 20 08:15 meshagent\r\n-rw-r----- 1 root root     1890 Nov  5 12:00 agent.yaml`;
            }
          } else if (cmd.startsWith('journalctl')) {
            out = `Nov 05 16:01:12 ${dev.hostname} systemd[1]: Started vitrine-agent.service.\r\nNov 05 16:15:00 ${dev.hostname} vitrine-agent[820]: Telemetry heartbeat OK (CPU 18.2%, RAM 34.1%).\r\nNov 05 16:30:44 ${dev.hostname} sshd[512]: Accepted publickey for root from 10.200.10.42 port 52410 ssh2`;
          } else if (cmd === 'help') {
            out = `Vitrine Multi-OS Live PTY Commands (${osType.toUpperCase()} / ${shell.toUpperCase()} as ${identity}):\r\n  - whoami / id / hostname          (verify SYSTEM/root vs Logged-In User token)\r\n  - ps aux / Get-Process            (inspect active background processes)\r\n  - systemctl / launchctl / Get-Service (query service/daemon states)\r\n  - ip a / ifconfig / ipconfig      (inspect network interfaces)\r\n  - df -h / free -m / systeminfo    (storage, memory, and hardware summary)\r\n  - Get-BitLockerVolume / fdesetup  (disk encryption & recovery escrow check)\r\n  - apt / brew / winget list        (inspect installed packages)\r\n  - clear / cls                     (reset terminal buffer)`;
          } else {
            out = `[Vitrine PTY (${identity} via ${shell})] Executed: "${cmd}"\r\nCommand completed with exit code 0.`;
          }

          socket.send(
            JSON.stringify({
              type: 'output',
              data: `\r\n${out}\r\n\r\n${prompt}`
            })
          );
        }
      } catch {
        // Ignore malformed payloads
      }
    });
  });

  // WebSocket Stream: Real-Time Telemetry Pulse (CPU, RAM, Network)
  server.get('/ws/telemetry', { websocket: true }, (connection: any) => {
    const socket = connection.socket || connection;
    const interval = setInterval(() => {
      if (socket.readyState === socket.OPEN) {
        const cpu = Math.max(5, Math.min(95, 15 + Math.sin(Date.now() / 2000) * 12 + (Math.random() * 8 - 4)));
        const ram = Math.max(8, Math.min(28, 12 + Math.cos(Date.now() / 3000) * 2));
        socket.send(JSON.stringify({
          timestamp: new Date().toISOString(),
          cpuUsage: parseFloat(cpu.toFixed(1)),
          ramUsageGb: parseFloat(ram.toFixed(1)),
          networkMbps: parseFloat((2.4 + Math.random() * 3.5).toFixed(1))
        }));
      } else if (socket.readyState === socket.CLOSED || socket.readyState === socket.CLOSING) {
        clearInterval(interval);
      }
    }, 2000);

    const cleanup = () => {
      clearInterval(interval);
    };

    socket.on('close', cleanup);
    socket.on('error', cleanup);
  });

  // Register REST API Routes
  await registerApiRoutes(server);

  // Serve Frontend in Production mode (robust resolution for Docker & bare-metal)
  const FRONTEND_CANDIDATES = [
    path.resolve(__dirname, '../../frontend/dist'),
    path.resolve(__dirname, '../frontend/dist'),
    path.resolve(process.cwd(), 'frontend/dist')
  ];
  const FRONTEND_DIST = FRONTEND_CANDIDATES.find((p) => fs.existsSync(p)) || FRONTEND_CANDIDATES[0];
  if (fs.existsSync(FRONTEND_DIST)) {
    server.register(fastifyStatic, {
      root: FRONTEND_DIST,
      prefix: '/',
      decorateReply: false
    });

    // SPA fallback for HTML5 client-side routing (excluding API, WS, and static file requests)
    server.setNotFoundHandler((req, reply) => {
      const url = req.raw.url || '';
      if (!url.startsWith('/api') && !url.startsWith('/ws') && !path.extname(url)) {
        return reply.sendFile('index.html', FRONTEND_DIST);
      }
      return reply.status(404).send({ error: 'Endpoint Not Found' });
    });
  }

  const PORT = parseInt(process.env.PORT || '8080', 10);
  const HOST = process.env.HOST || '0.0.0.0';

  try {
    await server.listen({ port: PORT, host: HOST });
    console.log(`\n🔮 Vitrine RMM server running on http://${HOST}:${PORT}`);
    console.log(`📡 MeshCentral 2 Engine Bridge active`);
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
}

startServer();
