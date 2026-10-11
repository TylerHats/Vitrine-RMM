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
  CheckCircle,
  Plus
} from 'lucide-react';
import { Device, ProcessItem, ServiceItem } from '../types/index.js';
import {
  fetchProcesses,
  killProcess,
  fetchServices,
  manageService,
  fetchRegistry,
  fetchScheduledTasks,
  fetchFiles
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

  // Terminal state
  const [terminalOutput, setTerminalOutput] = useState<string[]>([]);
  const [terminalInput, setTerminalInput] = useState('');
  const [ws, setWs] = useState<WebSocket | null>(null);

  // Process state
  const [processes, setProcesses] = useState<ProcessItem[]>([]);
  const [procFilter, setProcFilter] = useState('');
  const [loadingProcs, setLoadingProcs] = useState(false);

  // Services state
  const [services, setServices] = useState<ServiceItem[]>([]);
  const [svcFilter, setSvcFilter] = useState('');
  const [loadingSvcs, setLoadingSvcs] = useState(false);

  // Registry state
  const [regPath, setRegPath] = useState('HKLM\\SOFTWARE\\VitrineRMM');
  const [regData, setRegData] = useState<{ subkeys: string[]; values: any[] }>({ subkeys: [], values: [] });

  // Tasks state
  const [tasks, setTasks] = useState<any[]>([]);

  // Files state
  const [currentPath, setCurrentPath] = useState(device.os_type === 'linux' ? '/etc' : 'C:\\');
  const [files, setFiles] = useState<any[]>([]);

  // Connect WebSocket for terminal
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const socket = new WebSocket(`${protocol}//${host}/ws/terminal`);

    socket.onopen = () => {
      // connected
    };

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
  }, []);

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

  useEffect(() => {
    if (activeTab === 'processes') loadProcesses();
    if (activeTab === 'services') loadServices();
    if (activeTab === 'registry') loadRegistry(regPath);
    if (activeTab === 'tasks') loadTasks();
    if (activeTab === 'files') loadFiles(currentPath);
  }, [activeTab]);

  const handleTerminalSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!terminalInput.trim() || !ws) return;
    setTerminalOutput((prev) => [...prev, `\r\nPS> ${terminalInput}`]);
    ws.send(JSON.stringify({ type: 'input', data: terminalInput }));
    setTerminalInput('');
  };

  const handleSnippet = (cmd: string) => {
    if (!ws) return;
    setTerminalOutput((prev) => [...prev, `\r\nPS> ${cmd}`]);
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

  return (
    <div className="modal-backdrop" id="background-tools-modal">
      <div className="glass-modal glass-modal-lg" style={{ height: '90vh' }}>
        {/* Header */}
        <div className="modal-header">
          <div className="modal-title">
            <Terminal size={20} style={{ color: '#00f2fe' }} />
            <span>Silent Background Management Suite — {device.hostname}</span>
            <span className="status-pill status-online" style={{ fontSize: '0.72rem' }}>
              NT AUTHORITY\SYSTEM
            </span>
          </div>
          <button className="btn-glass btn-icon" onClick={onClose} id="close-bg-tools-btn">
            <X size={18} />
          </button>
        </div>

        {/* Tab navigation */}
        <div style={{ padding: '0 1.5rem', background: 'rgba(0, 0, 0, 0.2)' }}>
          <div className="tab-list" style={{ marginBottom: 0 }}>
            <button
              className={`tab-btn ${activeTab === 'terminal' ? 'active' : ''}`}
              onClick={() => setActiveTab('terminal')}
              id="tab-btn-terminal"
            >
              <Terminal size={16} />
              <span>Interactive Shell</span>
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
              <span>Windows Services</span>
            </button>
            <button
              className={`tab-btn ${activeTab === 'registry' ? 'active' : ''}`}
              onClick={() => setActiveTab('registry')}
              id="tab-btn-registry"
            >
              <FileCode size={16} />
              <span>Registry Editor</span>
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
              <span>Task Scheduler</span>
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="modal-body" style={{ padding: '1.25rem' }}>
          {/* TAB 1: TERMINAL */}
          {activeTab === 'terminal' && (
            <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '1rem' }}>
              {/* Quick Snippets Bar */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', fontWeight: 600 }}>Quick Snippets:</span>
                <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('Get-Process')}>
                  Get-Process
                </button>
                <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('Get-BitLockerVolume')}>
                  Get-BitLockerVolume
                </button>
                <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('Get-Service Spooler')}>
                  Query Spooler
                </button>
                <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('whoami')}>
                  whoami
                </button>
                <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('clear')}>
                  clear
                </button>
              </div>

              {/* Console Output */}
              <div className="terminal-window" style={{ flex: 1, minHeight: '380px' }} id="terminal-window-output">
                {terminalOutput.join('')}
              </div>

              {/* Input Form */}
              <form onSubmit={handleTerminalSubmit} className="terminal-input-row">
                <span className="terminal-prompt">PS C:\&gt;</span>
                <input
                  type="text"
                  className="terminal-input"
                  placeholder="Enter PowerShell / CMD command..."
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
                      .filter((p) => p.name.toLowerCase().includes(procFilter.toLowerCase()))
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

          {/* TAB 4: REGISTRY */}
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
                        style={{ textAlign: 'left', justifyContent: 'flex-start', padding: '0.4rem 0.65rem', fontSize: '0.8rem' }}
                        onClick={() => loadRegistry(`${regPath}\\${sub}`)}
                      >
                        <Folder size={14} color="#00f2fe" />
                        <span>{sub}</span>
                      </button>
                    ))}
                  </div>
                </div>

                <div className="table-wrapper">
                  <table className="glass-table">
                    <thead>
                      <tr>
                        <th>Value Name</th>
                        <th>Type</th>
                        <th>Data</th>
                      </tr>
                    </thead>
                    <tbody>
                      {regData.values.map((v, idx) => (
                        <tr key={idx}>
                          <td><strong>{v.name}</strong></td>
                          <td><span className="status-pill status-reboot" style={{ fontSize: '0.7rem' }}>{v.type}</span></td>
                          <td><code>{v.value}</code></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: FILES */}
          {activeTab === 'files' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'flex', gap: '0.65rem', alignItems: 'center' }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>Location:</span>
                <input
                  type="text"
                  className="glass-input"
                  value={currentPath}
                  onChange={(e) => setCurrentPath(e.target.value)}
                />
                <button className="btn-glass btn-primary" onClick={() => loadFiles(currentPath)}>
                  Go
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
                          {!f.isDirectory && (
                            <button className="btn-glass" style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}>
                              Download
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 6: TASKS */}
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
                    </tr>
                  </thead>
                  <tbody>
                    {tasks.map((t, i) => (
                      <tr key={i}>
                        <td><strong>{t.name}</strong></td>
                        <td>{t.path}</td>
                        <td><span className="status-pill status-online">{t.state}</span></td>
                        <td>{t.lastRunTime}</td>
                        <td>{t.nextRunTime}</td>
                        <td><code>{t.lastResult}</code></td>
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
