import React, { useState, useEffect } from 'react';
import {
  Terminal,
  Cpu,
  Layers,
  FileCode,
  FolderTree,
  Calendar,
  X,
  Play,
  RotateCcw,
  Square,
  Trash2,
  RefreshCw,
  Folder,
  File,
  FileText,
  CornerLeftUp,
  Download
} from 'lucide-react';
import { Device, ProcessItem, ServiceItem, EventLogItem } from '../types/index.js';
import {
  fetchProcesses,
  killProcess,
  fetchServices,
  manageService,
  fetchRegistry,
  setRegistryValue,
  deleteRegistryValue,
  fetchScheduledTasks,
  manageScheduledTask,
  fetchFiles,
  manageRemoteFile,
  fetchEventLogs
} from '../services/api.js';

interface BackgroundToolsModalProps {
  device: Device;
  initialTab?: string;
  onClose: () => void;
}

export const BackgroundToolsModal: React.FC<BackgroundToolsModalProps> = ({
  device,
  initialTab = 'terminal',
  onClose
}) => {
  const [activeTab, setActiveTab] = useState(initialTab);
  const osType = device.os_type || 'windows';

  // Terminal state (Supports SYSTEM/root vs Logged-In User context & Multi-Shell selection)
  const [terminalOutput, setTerminalOutput] = useState<string[]>([]);
  const [terminalInput, setTerminalInput] = useState('');
  const [runAsContext, setRunAsContext] = useState<'system' | 'user'>('system');
  const [shellType, setShellType] = useState<string>(
    osType === 'macos' ? 'zsh' : osType === 'linux' ? 'bash' : 'powershell'
  );
  const [ws, setWs] = useState<WebSocket | null>(null);

  // Process state
  const [processes, setProcesses] = useState<ProcessItem[]>([]);
  const [procFilter, setProcFilter] = useState('');
  const [, setLoadingProcs] = useState(false);

  // Services state
  const [services, setServices] = useState<ServiceItem[]>([]);
  const [svcFilter, setSvcFilter] = useState('');
  const [, setLoadingSvcs] = useState(false);

  // Registry / sysctl / plist state
  const [regPath, setRegPath] = useState(
    osType === 'windows'
      ? 'HKLM\\SOFTWARE\\VitrineRMM'
      : osType === 'macos'
        ? '/Library/Preferences/com.vitrine.agent.plist'
        : '/etc/sysctl.d/99-vitrine-hardening.conf'
  );
  const [regData, setRegData] = useState<{ subkeys: string[]; values: Array<{ path: string; name: string; type: string; value: string }> }>({ subkeys: [], values: [] });
  const [newRegName, setNewRegName] = useState('');
  const [newRegType, setNewRegType] = useState('REG_SZ');
  const [newRegVal, setNewRegVal] = useState('');

  // Tasks state
  const [tasks, setTasks] = useState<Array<{ name: string; path: string; state: string; lastRunTime: string; nextRunTime: string; lastResult: string }>>([]);

  // Files state
  const [currentPath, setCurrentPath] = useState(osType === 'windows' ? 'C:\\' : '/');
  const [files, setFiles] = useState<Array<{ name: string; path: string; size: number; isDirectory: boolean; modified: string; permissions: string }>>([]);
  const [newFolderName, setNewFolderName] = useState('');

  // Event Viewer state
  const [eventLogs, setEventLogs] = useState<EventLogItem[]>([]);
  const [eventChannel, setEventChannel] = useState('All');
  const [eventLevel, setEventLevel] = useState('all');
  const [eventFilter, setEventFilter] = useState('');
  const [loadingEvents, setLoadingEvents] = useState(false);

  // Connect WebSocket for terminal with deviceId, runAs, and shell
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const socket = new WebSocket(
      `${protocol}//${host}/ws/terminal?deviceId=${encodeURIComponent(device.id)}&runAs=${runAsContext}&shell=${encodeURIComponent(shellType)}`
    );

    socket.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'output') {
          setTerminalOutput((prev) => [...prev, msg.data]);
        }
      } catch {
        setTerminalOutput((prev) => [...prev, event.data]);
      }
    };

    setWs(socket);

    return () => {
      socket.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [device.id]);

  const handleSwitchTerminalContext = (nextRunAs: 'system' | 'user', nextShell: string) => {
    setRunAsContext(nextRunAs);
    setShellType(nextShell);
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(
        JSON.stringify({
          type: 'switch_context',
          deviceId: device.id,
          runAs: nextRunAs,
          shell: nextShell
        })
      );
    }
  };

  // Load processes
  const loadProcesses = async () => {
    setLoadingProcs(true);
    try {
      const data = await fetchProcesses(device.id);
      setProcesses(data);
    } finally {
      setLoadingProcs(false);
    }
  };

  // Load services
  const loadServices = async () => {
    setLoadingSvcs(true);
    try {
      const data = await fetchServices(device.id);
      setServices(data);
    } finally {
      setLoadingSvcs(false);
    }
  };

  // Load registry
  const loadRegistry = async (path: string) => {
    const data = await fetchRegistry(device.id, path);
    setRegData(data);
    setRegPath(path);
  };

  // Load tasks
  const loadTasks = async () => {
    const data = await fetchScheduledTasks(device.id);
    setTasks(data);
  };

  // Load files
  const loadFiles = async (path: string) => {
    const data = await fetchFiles(device.id, path);
    setFiles(data);
    setCurrentPath(path);
  };

  // Load event logs
  const loadEvents = async (channel = eventChannel, level = eventLevel) => {
    setLoadingEvents(true);
    try {
      const data = await fetchEventLogs(device.id, channel, level, 100);
      setEventLogs(data);
    } finally {
      setLoadingEvents(false);
    }
  };

  const handleNavigateUp = () => {
    if (osType === 'linux' || osType === 'macos') {
      if (currentPath === '/' || !currentPath) return;
      const parts = currentPath.split('/').filter(Boolean);
      parts.pop();
      const parent = parts.length === 0 ? '/' : '/' + parts.join('/');
      loadFiles(parent);
    } else {
      if (currentPath === 'C:\\' || currentPath === 'C:/' || !currentPath) return;
      const normalized = currentPath.replace(/\\/g, '/');
      const parts = normalized.split('/').filter(Boolean);
      parts.pop();
      const parent = parts.length === 1 ? parts[0] + '\\' : parts.join('\\');
      loadFiles(parent);
    }
  };

  useEffect(() => {
    if (activeTab === 'processes') loadProcesses();
    if (activeTab === 'services') loadServices();
    if (activeTab === 'registry') loadRegistry(regPath);
    if (activeTab === 'tasks') loadTasks();
    if (activeTab === 'files') loadFiles(currentPath);
    if (activeTab === 'events') loadEvents(eventChannel, eventLevel);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  const promptLabel =
    osType === 'windows'
      ? shellType === 'cmd'
        ? runAsContext === 'system'
          ? 'C:\\Windows\\System32>'
          : 'C:\\Users\\Tyler.Hats>'
        : runAsContext === 'system'
          ? 'PS C:\\Windows\\System32>'
          : 'PS C:\\Users\\Tyler.Hats>'
      : osType === 'macos'
        ? `${runAsContext === 'system' ? 'root' : 'tylerhats'}@${device.hostname.toLowerCase()} ${runAsContext === 'system' ? '#' : '%'}`
        : `${runAsContext === 'system' ? 'root' : 'ubuntu'}@${device.hostname.toLowerCase()}:${runAsContext === 'system' ? '#' : '$'}`;

  const identityBadge =
    osType === 'windows'
      ? runAsContext === 'system'
        ? 'NT AUTHORITY\\SYSTEM'
        : 'CORP\\Tyler.Hats (User)'
      : osType === 'macos'
        ? runAsContext === 'system'
          ? 'root (UID 0 LaunchDaemon)'
          : 'tylerhats (UID 501 User)'
        : runAsContext === 'system'
          ? 'root (UID 0 systemd)'
          : 'ubuntu (UID 1000 User)';

  const handleTerminalSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!terminalInput.trim() || !ws) return;
    setTerminalOutput((prev) => [...prev, `${terminalInput}`]);
    ws.send(JSON.stringify({ type: 'input', data: terminalInput }));
    setTerminalInput('');
  };

  const handleSnippet = (cmd: string) => {
    if (!ws) return;
    setTerminalOutput((prev) => [...prev, `${cmd}`]);
    ws.send(JSON.stringify({ type: 'input', data: cmd }));
  };

  const handleKillProcess = async (pid: number) => {
    if (confirm(`Are you sure you want to silently terminate PID ${pid}?`)) {
      await killProcess(device.id, pid);
      setProcesses(processes.filter((p) => p.pid !== pid));
    }
  };

  const handleManageService = async (name: string, action: 'start' | 'stop' | 'restart') => {
    await manageService(device.id, name, action);
    loadServices();
  };

  const handleDownloadFile = (fileName: string, fileSize: number) => {
    alert(`Starting background transfer of ${fileName} (${(fileSize / 1024).toFixed(1)} KB) via MeshCentral micro-agent tunnel...`);
  };

  const handleSaveRegValue = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRegName.trim()) return;
    const res = await setRegistryValue(device.id, {
      path: regPath,
      name: newRegName.trim(),
      type: newRegType,
      value: newRegVal
    });
    if (res.success) {
      setRegData({ subkeys: res.subkeys, values: res.values });
      setNewRegName('');
      setNewRegVal('');
    }
  };

  const handleDeleteRegValue = async (name: string) => {
    const res = await deleteRegistryValue(device.id, regPath, name);
    if (res.success) {
      setRegData({ subkeys: res.subkeys, values: res.values });
    }
  };

  const handleCreateFolder = async () => {
    if (!newFolderName.trim()) return;
    const res = await manageRemoteFile(device.id, { path: currentPath, action: 'mkdir', name: newFolderName.trim() });
    if (res.success) {
      setFiles(res.files);
      setNewFolderName('');
    }
  };

  const handleDeleteFile = async (name: string) => {
    if (!confirm(`Delete ${name} from ${currentPath}?`)) return;
    const res = await manageRemoteFile(device.id, { path: currentPath, action: 'delete', name });
    if (res.success) {
      setFiles(res.files);
    }
  };

  const handleTaskAction = async (name: string, action: 'run' | 'enable' | 'disable') => {
    const res = await manageScheduledTask(device.id, name, action);
    if (res.success) {
      setTasks(res.tasks);
    }
  };

  return (
    <div className="modal-backdrop" id="background-tools-modal">
      <div className="glass-modal glass-modal-lg" style={{ height: '90vh' }}>
        {/* Header */}
        <div className="modal-header">
          <div className="modal-title">
            <Terminal size={20} style={{ color: '#00f2fe' }} />
            <span>Silent Background Management Suite — {device.hostname}</span>
            <span
              className={`status-pill ${runAsContext === 'system' ? 'status-online' : 'status-reboot'}`}
              style={{ fontSize: '0.72rem' }}
            >
              {identityBadge}
            </span>
            <span className="status-pill status-isolated" style={{ fontSize: '0.7rem', background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8' }}>
              {osType.toUpperCase()} Parity Engine
            </span>
          </div>
          <button className="btn-glass btn-icon" onClick={onClose} id="close-bg-tools-btn">
            <X size={18} />
          </button>
        </div>

        {/* Tab navigation (OS-Adaptive Titles for Windows, Linux, and macOS) */}
        <div style={{ padding: '0 1.5rem', background: 'rgba(0, 0, 0, 0.2)' }}>
          <div className="tab-list" style={{ marginBottom: 0 }}>
            <button
              className={`tab-btn ${activeTab === 'terminal' ? 'active' : ''}`}
              onClick={() => setActiveTab('terminal')}
              id="tab-btn-terminal"
            >
              <Terminal size={16} />
              <span>Live PTY Terminal</span>
            </button>
            <button
              className={`tab-btn ${activeTab === 'processes' ? 'active' : ''}`}
              onClick={() => setActiveTab('processes')}
              id="tab-btn-processes"
            >
              <Cpu size={16} />
              <span>Process Manager</span>
            </button>
            <button
              className={`tab-btn ${activeTab === 'services' ? 'active' : ''}`}
              onClick={() => setActiveTab('services')}
              id="tab-btn-services"
            >
              <Layers size={16} />
              <span>
                {osType === 'windows'
                  ? 'Windows Services'
                  : osType === 'macos'
                    ? 'launchd Daemons'
                    : 'systemd Services'}
              </span>
            </button>
            <button
              className={`tab-btn ${activeTab === 'events' ? 'active' : ''}`}
              onClick={() => setActiveTab('events')}
              id="tab-btn-events"
            >
              <FileText size={16} />
              <span>
                {osType === 'windows'
                  ? 'Event Viewer'
                  : osType === 'macos'
                    ? 'Unified Logs'
                    : 'journald / syslog'}
              </span>
            </button>
            <button
              className={`tab-btn ${activeTab === 'registry' ? 'active' : ''}`}
              onClick={() => setActiveTab('registry')}
              id="tab-btn-registry"
            >
              <FileCode size={16} />
              <span>
                {osType === 'windows'
                  ? 'Registry Editor'
                  : osType === 'macos'
                    ? 'plist / defaults'
                    : 'sysctl & /etc Config'}
              </span>
            </button>
            <button
              className={`tab-btn ${activeTab === 'files' ? 'active' : ''}`}
              onClick={() => setActiveTab('files')}
              id="tab-btn-files"
            >
              <FolderTree size={16} />
              <span>File Manager</span>
            </button>
            <button
              className={`tab-btn ${activeTab === 'tasks' ? 'active' : ''}`}
              onClick={() => setActiveTab('tasks')}
              id="tab-btn-tasks"
            >
              <Calendar size={16} />
              <span>
                {osType === 'windows'
                  ? 'Task Scheduler'
                  : osType === 'macos'
                    ? 'launchd Jobs'
                    : 'Cron & Timers'}
              </span>
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="modal-body" style={{ padding: '1.25rem' }}>
          {/* TAB 1: TERMINAL */}
          {activeTab === 'terminal' && (
            <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '0.85rem' }}>
              {/* Execution Context (SYSTEM/root vs Logged-In User) & Shell Selector Bar */}
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '0.75rem',
                  padding: '0.6rem 0.9rem',
                  background: 'rgba(15, 23, 42, 0.65)',
                  border: '1px solid var(--glass-border)',
                  borderRadius: '8px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', fontWeight: 600 }}>Run As Context:</span>
                  <button
                    type="button"
                    className={`btn-glass ${runAsContext === 'system' ? 'btn-primary' : ''}`}
                    style={{ padding: '0.22rem 0.65rem', fontSize: '0.74rem' }}
                    onClick={() => handleSwitchTerminalContext('system', shellType)}
                  >
                    {osType === 'windows' ? 'SYSTEM (NT AUTHORITY\\SYSTEM)' : 'root (UID 0 Daemon)'}
                  </button>
                  <button
                    type="button"
                    className={`btn-glass ${runAsContext === 'user' ? 'btn-primary' : ''}`}
                    style={{ padding: '0.22rem 0.65rem', fontSize: '0.74rem' }}
                    onClick={() => handleSwitchTerminalContext('user', shellType)}
                  >
                    {osType === 'windows'
                      ? 'Logged-In User (CORP\\Tyler.Hats)'
                      : osType === 'macos'
                        ? 'Logged-In User (tylerhats)'
                        : 'Logged-In User (ubuntu)'}
                  </button>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', fontWeight: 600 }}>Shell:</span>
                  {osType === 'windows' ? (
                    <>
                      <button
                        type="button"
                        className={`btn-glass ${shellType === 'powershell' ? 'btn-primary' : ''}`}
                        style={{ padding: '0.2rem 0.55rem', fontSize: '0.73rem' }}
                        onClick={() => handleSwitchTerminalContext(runAsContext, 'powershell')}
                      >
                        PowerShell 7 / 5.1
                      </button>
                      <button
                        type="button"
                        className={`btn-glass ${shellType === 'cmd' ? 'btn-primary' : ''}`}
                        style={{ padding: '0.2rem 0.55rem', fontSize: '0.73rem' }}
                        onClick={() => handleSwitchTerminalContext(runAsContext, 'cmd')}
                      >
                        CMD.exe
                      </button>
                    </>
                  ) : osType === 'macos' ? (
                    <>
                      <button
                        type="button"
                        className={`btn-glass ${shellType === 'zsh' ? 'btn-primary' : ''}`}
                        style={{ padding: '0.2rem 0.55rem', fontSize: '0.73rem' }}
                        onClick={() => handleSwitchTerminalContext(runAsContext, 'zsh')}
                      >
                        zsh (macOS Default)
                      </button>
                      <button
                        type="button"
                        className={`btn-glass ${shellType === 'bash' ? 'btn-primary' : ''}`}
                        style={{ padding: '0.2rem 0.55rem', fontSize: '0.73rem' }}
                        onClick={() => handleSwitchTerminalContext(runAsContext, 'bash')}
                      >
                        bash
                      </button>
                    </>
                  ) : (
                    <>
                      <button
                        type="button"
                        className={`btn-glass ${shellType === 'bash' ? 'btn-primary' : ''}`}
                        style={{ padding: '0.2rem 0.55rem', fontSize: '0.73rem' }}
                        onClick={() => handleSwitchTerminalContext(runAsContext, 'bash')}
                      >
                        bash
                      </button>
                      <button
                        type="button"
                        className={`btn-glass ${shellType === 'sh' ? 'btn-primary' : ''}`}
                        style={{ padding: '0.2rem 0.55rem', fontSize: '0.73rem' }}
                        onClick={() => handleSwitchTerminalContext(runAsContext, 'sh')}
                      >
                        POSIX sh
                      </button>
                    </>
                  )}
                </div>
              </div>

              {/* OS-Specific Quick Snippets */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', fontWeight: 600 }}>Quick Snippets:</span>
                <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('whoami')}>
                  whoami
                </button>
                <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('id')}>
                  id / token
                </button>
                {osType === 'windows' ? (
                  <>
                    <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('Get-Process')}>
                      Get-Process
                    </button>
                    <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('Get-BitLockerVolume')}>
                      Get-BitLockerVolume
                    </button>
                    <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('Get-Service')}>
                      Get-Service
                    </button>
                    <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('winget list')}>
                      winget list
                    </button>
                  </>
                ) : osType === 'macos' ? (
                  <>
                    <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('ps aux')}>
                      ps aux
                    </button>
                    <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('launchctl list')}>
                      launchctl list
                    </button>
                    <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('fdesetup status')}>
                      fdesetup (FileVault)
                    </button>
                    <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('brew list')}>
                      brew list
                    </button>
                  </>
                ) : (
                  <>
                    <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('ps aux')}>
                      ps aux
                    </button>
                    <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('systemctl list-units --type=service')}>
                      systemctl services
                    </button>
                    <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('df -h')}>
                      df -h
                    </button>
                    <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('journalctl -n 20')}>
                      journalctl
                    </button>
                  </>
                )}
                <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('clear')}>
                  clear
                </button>
              </div>

              <div className="terminal-window" style={{ flex: 1, minHeight: '350px' }} id="terminal-window-output">
                {terminalOutput.join('')}
              </div>

              <form onSubmit={handleTerminalSubmit} className="terminal-input-row">
                <span className="terminal-prompt">{promptLabel}</span>
                <input
                  type="text"
                  className="terminal-input"
                  placeholder={`Execute ${shellType.toUpperCase()} command as ${identityBadge}...`}
                  value={terminalInput}
                  onChange={(e) => setTerminalInput(e.target.value)}
                  autoFocus
                  id="terminal-cli-input"
                />
                <button type="submit" className="btn-glass btn-primary" style={{ padding: '0.35rem 0.85rem' }}>
                  Execute
                </button>
              </form>
            </div>
          )}

          {/* TAB 2: PROCESSES */}
          {activeTab === 'processes' && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
                <input
                  type="text"
                  className="glass-input"
                  style={{ width: '280px' }}
                  placeholder="Filter processes by name / PID..."
                  value={procFilter}
                  onChange={(e) => setProcFilter(e.target.value)}
                />
                <button className="btn-glass" onClick={loadProcesses}>
                  <RefreshCw size={14} /> Refresh
                </button>
              </div>

              <div className="table-wrapper">
                <table className="glass-table">
                  <thead>
                    <tr>
                      <th>PID</th>
                      <th>Process Name</th>
                      <th>User Account</th>
                      <th>CPU %</th>
                      <th>RAM (MB)</th>
                      <th>Threads</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {processes
                      .filter((p) => p.name.toLowerCase().includes(procFilter.toLowerCase()) || p.pid.toString().includes(procFilter))
                      .map((p) => (
                        <tr key={p.pid}>
                          <td><strong>{p.pid}</strong></td>
                          <td>{p.name}</td>
                          <td><span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{p.user}</span></td>
                          <td>
                            <span style={{ color: p.cpu > 10 ? '#ef4444' : '#10b981', fontWeight: 600 }}>
                              {p.cpu.toFixed(1)}%
                            </span>
                          </td>
                          <td>{p.memoryMb.toFixed(1)} MB</td>
                          <td>{p.threads}</td>
                          <td>
                            <button
                              className="btn-glass btn-danger"
                              style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
                              onClick={() => handleKillProcess(p.pid)}
                            >
                              <Trash2 size={12} /> Kill
                            </button>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 3: SERVICES */}
          {activeTab === 'services' && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
                <input
                  type="text"
                  className="glass-input"
                  style={{ width: '280px' }}
                  placeholder="Filter Windows services..."
                  value={svcFilter}
                  onChange={(e) => setSvcFilter(e.target.value)}
                />
                <button className="btn-glass" onClick={loadServices}>
                  <RefreshCw size={14} /> Refresh
                </button>
              </div>

              <div className="table-wrapper">
                <table className="glass-table">
                  <thead>
                    <tr>
                      <th>Service Name</th>
                      <th>Display Name</th>
                      <th>Status</th>
                      <th>Startup Type</th>
                      <th>Controls</th>
                    </tr>
                  </thead>
                  <tbody>
                    {services
                      .filter((s) => s.displayName.toLowerCase().includes(svcFilter.toLowerCase()) || s.name.toLowerCase().includes(svcFilter.toLowerCase()))
                      .map((s) => (
                        <tr key={s.name}>
                          <td><strong>{s.name}</strong></td>
                          <td>{s.displayName}</td>
                          <td>
                            <span className={`status-pill ${s.status === 'Running' ? 'status-online' : 'status-offline'}`}>
                              {s.status}
                            </span>
                          </td>
                          <td><span style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>{s.startType}</span></td>
                          <td>
                            <div className="action-group">
                              {s.status === 'Running' ? (
                                <>
                                  <button
                                    className="btn-glass"
                                    style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
                                    onClick={() => handleManageService(s.name, 'restart')}
                                  >
                                    <RotateCcw size={12} /> Restart
                                  </button>
                                  <button
                                    className="btn-glass btn-danger"
                                    style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
                                    onClick={() => handleManageService(s.name, 'stop')}
                                  >
                                    <Square size={12} /> Stop
                                  </button>
                                </>
                              ) : (
                                <button
                                  className="btn-glass btn-primary"
                                  style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
                                  onClick={() => handleManageService(s.name, 'start')}
                                >
                                  <Play size={12} /> Start
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 4: EVENT VIEWER */}
          {activeTab === 'events' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
                <div style={{ display: 'flex', gap: '0.65rem', alignItems: 'center' }}>
                  <select
                    className="glass-select"
                    value={eventChannel}
                    onChange={(e) => {
                      setEventChannel(e.target.value);
                      loadEvents(e.target.value, eventLevel);
                    }}
                    style={{ width: '170px' }}
                  >
                    <option value="All">All Log Channels</option>
                    {osType === 'windows' ? (
                      <>
                        <option value="System">System Log</option>
                        <option value="Application">Application Log</option>
                        <option value="Security">Security Log</option>
                      </>
                    ) : osType === 'macos' ? (
                      <>
                        <option value="system">system.log</option>
                        <option value="securityd">securityd (FileVault/Gatekeeper)</option>
                        <option value="kernel">kernel (Darwin/SMC)</option>
                        <option value="install">install.log</option>
                      </>
                    ) : (
                      <>
                        <option value="journald">systemd-journald</option>
                        <option value="auth">auth.log (PAM/SSH)</option>
                        <option value="kern">kern.log (Netfilter)</option>
                      </>
                    )}
                  </select>

                  <select
                    className="glass-select"
                    value={eventLevel}
                    onChange={(e) => {
                      setEventLevel(e.target.value);
                      loadEvents(eventChannel, e.target.value);
                    }}
                    style={{ width: '140px' }}
                  >
                    <option value="all">All Levels</option>
                    <option value="Critical">Critical</option>
                    <option value="Error">Error</option>
                    <option value="Warning">Warning</option>
                    <option value="Information">Information</option>
                  </select>

                  <input
                    type="text"
                    className="glass-input"
                    placeholder="Search Event ID, Source, keyword..."
                    value={eventFilter}
                    onChange={(e) => setEventFilter(e.target.value)}
                    style={{ width: '260px' }}
                  />
                </div>

                <button className="btn-glass" onClick={() => loadEvents(eventChannel, eventLevel)} disabled={loadingEvents}>
                  <RefreshCw size={14} /> Refresh Events
                </button>
              </div>

              <div className="table-wrapper">
                <table className="glass-table">
                  <thead>
                    <tr>
                      <th style={{ width: '140px' }}>Date / Time</th>
                      <th style={{ width: '110px' }}>Level</th>
                      <th style={{ width: '90px' }}>Event ID</th>
                      <th style={{ width: '220px' }}>Source Provider</th>
                      <th>Message Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {eventLogs
                      .filter((ev) => {
                        if (!eventFilter.trim()) return true;
                        const q = eventFilter.toLowerCase();
                        return (
                          ev.eventId.toString().includes(q) ||
                          ev.source.toLowerCase().includes(q) ||
                          ev.message.toLowerCase().includes(q)
                        );
                      })
                      .map((ev) => (
                        <tr key={ev.id}>
                          <td><span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{new Date(ev.timeGenerated).toLocaleTimeString()}</span></td>
                          <td>
                            <span
                              className={`status-pill ${
                                ev.level === 'Critical' || ev.level === 'Error'
                                  ? 'status-isolated'
                                  : ev.level === 'Warning'
                                  ? 'status-reboot'
                                  : 'status-online'
                              }`}
                              style={{ fontSize: '0.7rem' }}
                            >
                              {ev.level}
                            </span>
                          </td>
                          <td><strong>{ev.eventId}</strong></td>
                          <td><span style={{ fontSize: '0.8rem', fontWeight: 500 }}>{ev.source}</span></td>
                          <td><span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: 1.4 }}>{ev.message}</span></td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 5: REGISTRY */}
          {activeTab === 'registry' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'flex', gap: '0.65rem' }}>
                <input
                  type="text"
                  className="glass-input"
                  value={regPath}
                  onChange={(e) => setRegPath(e.target.value)}
                  placeholder="Registry Hive Path..."
                />
                <button className="btn-glass btn-primary" onClick={() => loadRegistry(regPath)}>
                  Browse
                </button>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: '1rem', minHeight: '360px' }}>
                <div className="glass-card" style={{ padding: '1rem' }}>
                  <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', marginBottom: '0.5rem' }}>SUBKEYS</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                    {regData.subkeys.map((sub) => (
                      <button
                        key={sub}
                        className="btn-glass"
                        style={{ textAlign: 'left', justifyContent: 'flex-start', padding: '0.4rem 0.65rem', fontSize: '0.78rem' }}
                        onClick={() => loadRegistry(sub.startsWith('/') ? sub : `${regPath}\\${sub}`)}
                      >
                        <Folder size={14} color="#00f2fe" />
                        <span>{sub}</span>
                      </button>
                    ))}
                  </div>
                </div>

                <div className="table-wrapper" style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  <form onSubmit={handleSaveRegValue} style={{ display: 'flex', gap: '0.5rem', padding: '0.75rem', background: 'rgba(255,255,255,0.02)', borderBottom: '1px solid var(--glass-border)' }}>
                    <input
                      type="text"
                      className="glass-input"
                      placeholder="Value Name (e.g. MaxTelemetryQueue)"
                      value={newRegName}
                      onChange={(e) => setNewRegName(e.target.value)}
                      style={{ flex: 1 }}
                    />
                    <select className="glass-select" value={newRegType} onChange={(e) => setNewRegType(e.target.value)} style={{ width: '140px' }}>
                      <option value="REG_SZ">REG_SZ</option>
                      <option value="REG_DWORD">REG_DWORD</option>
                      <option value="REG_MULTI_SZ">REG_MULTI_SZ</option>
                    </select>
                    <input
                      type="text"
                      className="glass-input"
                      placeholder="Value Data..."
                      value={newRegVal}
                      onChange={(e) => setNewRegVal(e.target.value)}
                      style={{ flex: 1 }}
                    />
                    <button type="submit" className="btn-glass btn-primary" style={{ fontSize: '0.78rem' }}>
                      + Set Value
                    </button>
                  </form>
                  <table className="glass-table">
                    <thead>
                      <tr>
                        <th>Value Name</th>
                        <th>Type</th>
                        <th>Data</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {regData.values.map((v, idx) => (
                        <tr key={idx}>
                          <td><strong>{v.name}</strong></td>
                          <td><span className="status-pill status-reboot" style={{ fontSize: '0.7rem' }}>{v.type}</span></td>
                          <td><code>{v.value}</code></td>
                          <td>
                            {v.name !== '(Default)' && (
                              <button
                                className="btn-glass btn-danger"
                                style={{ padding: '0.18rem 0.45rem', fontSize: '0.7rem' }}
                                onClick={() => handleDeleteRegValue(v.name)}
                              >
                                <Trash2 size={11} /> Delete
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 6: FILES */}
          {activeTab === 'files' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'flex', gap: '0.65rem', alignItems: 'center', flexWrap: 'wrap' }}>
                <button
                  className="btn-glass"
                  onClick={handleNavigateUp}
                  title="Navigate to parent directory"
                  style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', padding: '0.45rem 0.75rem' }}
                >
                  <CornerLeftUp size={16} />
                  <span>Up</span>
                </button>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>Location:</span>
                <input
                  type="text"
                  className="glass-input"
                  style={{ flex: 1 }}
                  value={currentPath}
                  onChange={(e) => setCurrentPath(e.target.value)}
                />
                <button className="btn-glass btn-primary" onClick={() => loadFiles(currentPath)}>
                  Go
                </button>
                <input
                  type="text"
                  className="glass-input"
                  style={{ width: '170px' }}
                  placeholder="New folder name..."
                  value={newFolderName}
                  onChange={(e) => setNewFolderName(e.target.value)}
                />
                <button className="btn-glass" onClick={handleCreateFolder}>
                  + New Folder
                </button>
              </div>

              <div className="table-wrapper">
                <table className="glass-table">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Size</th>
                      <th>Modified</th>
                      <th>Permissions</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {files.map((f, i) => (
                      <tr key={i}>
                        <td style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          {f.isDirectory ? <Folder size={16} color="#00f2fe" /> : <File size={16} color="#94a3b8" />}
                          <span
                            style={{ cursor: f.isDirectory ? 'pointer' : 'default', fontWeight: f.isDirectory ? 600 : 400 }}
                            onClick={() => f.isDirectory && loadFiles(f.path)}
                          >
                            {f.name}
                          </span>
                        </td>
                        <td>{f.isDirectory ? '--' : `${(f.size / 1024).toFixed(1)} KB`}</td>
                        <td>{f.modified}</td>
                        <td><code>{f.permissions}</code></td>
                        <td>
                          <div className="action-group">
                            {!f.isDirectory && (
                              <button
                                className="btn-glass"
                                style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                                onClick={() => handleDownloadFile(f.name, f.size)}
                              >
                                <Download size={12} /> Download
                              </button>
                            )}
                            <button
                              className="btn-glass btn-danger"
                              style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
                              onClick={() => handleDeleteFile(f.name)}
                            >
                              <Trash2 size={12} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 7: TASKS */}
          {activeTab === 'tasks' && (
            <div>
              <div className="table-wrapper">
                <table className="glass-table">
                  <thead>
                    <tr>
                      <th>Task Name</th>
                      <th>Path</th>
                      <th>State</th>
                      <th>Last Run</th>
                      <th>Next Run</th>
                      <th>Result</th>
                      <th>Controls</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tasks.map((t, i) => (
                      <tr key={i}>
                        <td><strong>{t.name}</strong></td>
                        <td>{t.path}</td>
                        <td>
                          <span className={`status-pill ${t.state === 'Disabled' ? 'status-offline' : 'status-online'}`}>
                            {t.state}
                          </span>
                        </td>
                        <td>{t.lastRunTime}</td>
                        <td>{t.nextRunTime}</td>
                        <td><code>{t.lastResult}</code></td>
                        <td>
                          <div className="action-group">
                            <button
                              className="btn-glass btn-primary"
                              style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
                              onClick={() => handleTaskAction(t.name, 'run')}
                            >
                              <Play size={11} /> Run Now
                            </button>
                            {t.state === 'Disabled' ? (
                              <button
                                className="btn-glass"
                                style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
                                onClick={() => handleTaskAction(t.name, 'enable')}
                              >
                                Enable
                              </button>
                            ) : (
                              <button
                                className="btn-glass"
                                style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
                                onClick={() => handleTaskAction(t.name, 'disable')}
                              >
                                Disable
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
