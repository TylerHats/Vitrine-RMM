import React, { useState, useEffect, useRef } from 'react';
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
  Download,
  Upload
} from 'lucide-react';
import { Terminal as XTerm } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
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
  getRemoteFileDownloadUrl,
  fetchEventLogs,
  fetchWsTicket
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

  // Interactive PTY Terminal state (@xterm/xterm attached to /ws/terminal -> MS2 meshrelay.ashx)
  const [runAsContext, setRunAsContext] = useState<'system' | 'user'>('system');
  const [shellType, setShellType] = useState<string>(
    osType === 'macos' ? 'zsh' : osType === 'linux' ? 'bash' : 'powershell'
  );
  const runAsContextRef = useRef<'system' | 'user'>(runAsContext);
  const shellTypeRef = useRef<string>(shellType);
  runAsContextRef.current = runAsContext;
  shellTypeRef.current = shellType;
  const [ws, setWs] = useState<WebSocket | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const [wsState, setWsState] = useState<'connecting' | 'connected' | 'disconnected'>('connecting');
  const [terminalMode, setTerminalMode] = useState<'pty' | 'line_fallback' | 'connecting' | 'unconnected'>('connecting');
  const [terminalModeReason, setTerminalModeReason] = useState<string | null>(null);
  const [reconnectSeq, setReconnectSeq] = useState(0);
  const [toolError, setToolError] = useState<string | null>(null);

  const xtermContainerRef = useRef<HTMLDivElement | null>(null);
  const xtermRef = useRef<XTerm | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);

  // Process state
  const [processes, setProcesses] = useState<ProcessItem[]>([]);
  const [procFilter, setProcFilter] = useState('');
  const [loadingProcs, setLoadingProcs] = useState(false);

  // Services state
  const [services, setServices] = useState<ServiceItem[]>([]);
  const [svcFilter, setSvcFilter] = useState('');
  const [loadingSvcs, setLoadingSvcs] = useState(false);

  // Registry / sysctl / plist state
  const [regPath, setRegPath] = useState(
    osType === 'windows'
      ? 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
      : osType === 'macos'
        ? '/Library/Preferences/com.apple.SoftwareUpdate.plist'
        : 'kernel.'
  );
  const [regData, setRegData] = useState<{ subkeys: string[]; values: Array<{ path: string; name: string; type: string; value: string }> }>({ subkeys: [], values: [] });
  const [loadingReg, setLoadingReg] = useState(false);
  const [newRegName, setNewRegName] = useState('');
  const [newRegType, setNewRegType] = useState('REG_SZ');
  const [newRegVal, setNewRegVal] = useState('');

  // Tasks state
  const [tasks, setTasks] = useState<Array<{ name: string; path: string; state: string; lastRunTime: string; nextRunTime: string; lastResult: string }>>([]);
  const [loadingTasks, setLoadingTasks] = useState(false);

  // Files state
  const [currentPath, setCurrentPath] = useState(osType === 'windows' ? 'C:\\' : '/');
  const [files, setFiles] = useState<Array<{ name: string; path: string; size: number; isDirectory: boolean; modified: string; permissions: string }>>([]);
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');

  // Event Viewer state
  const [eventLogs, setEventLogs] = useState<EventLogItem[]>([]);
  const [eventChannel, setEventChannel] = useState('All');
  const [eventLevel, setEventLevel] = useState('all');
  const [eventFilter, setEventFilter] = useState('');
  const [loadingEvents, setLoadingEvents] = useState(false);
  const fileUploadInputRef = useRef<HTMLInputElement | null>(null);

  // Mount @xterm/xterm & connect WebSocket when on terminal tab
  useEffect(() => {
    if (activeTab !== 'terminal') return;
    const container = xtermContainerRef.current;
    if (!container) return;

    let cancelled = false;
    let activeSocket: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    const term = new XTerm({
      cursorBlink: true,
      fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      fontSize: 13,
      lineHeight: 1.35,
      scrollback: 5000,
      theme: {
        background: '#0a0f1c',
        foreground: '#e2e8f0',
        cursor: '#00f2fe',
        selectionBackground: 'rgba(0, 242, 254, 0.25)'
      }
    });
    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(container);
    try {
      fitAddon.fit();
    } catch {
      // Ignore fit timing errors before container layout settles
    }
    term.focus();

    xtermRef.current = term;
    fitAddonRef.current = fitAddon;

    const dataDisposable = term.onData((data) => {
      const s = wsRef.current;
      if (s && s.readyState === WebSocket.OPEN) {
        s.send(JSON.stringify({ type: 'data', data }));
      }
    });

    const resizeObserver = new ResizeObserver(() => {
      try {
        fitAddon.fit();
        const s = wsRef.current;
        if (s && s.readyState === WebSocket.OPEN) {
          s.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
        }
      } catch {
        // Ignore resize race on unmount
      }
    });
    resizeObserver.observe(container);

    const connectSocket = async () => {
      setWsState('connecting');
      setTerminalMode('connecting');
      setTerminalModeReason(null);
      let ticketParam = '';
      try {
        const tRes = await fetchWsTicket();
        if (tRes?.ticket) {
          ticketParam = `&ticket=${encodeURIComponent(tRes.ticket)}`;
        }
      } catch {
        // Same-origin HttpOnly cookie still authenticates WS upgrade
      }
      if (cancelled) return;

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.host;
      const cols = Math.max(40, term.cols || 120);
      const rows = Math.max(10, term.rows || 32);
      const socket = new WebSocket(
        `${protocol}//${host}/ws/terminal?deviceId=${encodeURIComponent(device.id)}&runAs=${runAsContextRef.current}&shell=${encodeURIComponent(shellTypeRef.current)}&cols=${cols}&rows=${rows}${ticketParam}`
      );
      activeSocket = socket;

      socket.onopen = () => {
        if (!cancelled) {
          wsRef.current = socket;
          setWs(socket);
          setWsState('connected');
          try {
            fitAddon.fit();
            socket.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
          } catch {
            // Ignore fit race during socket open
          }
          term.focus();
        }
      };

      socket.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'output' && typeof msg.data === 'string') {
            term.write(msg.data);
          } else if (msg.type === 'status' && msg.mode) {
            setTerminalMode(msg.mode);
            if (msg.reason) setTerminalModeReason(String(msg.reason));
          }
        } catch {
          term.write(String(event.data || ''));
        }
      };

      socket.onclose = (ev) => {
        if (cancelled) return;
        wsRef.current = null;
        setWsState('disconnected');
        setTerminalMode('unconnected');
        setWs(null);
        if (ev.code !== 1000 && ev.code !== 1008) {
          reconnectTimer = setTimeout(() => {
            if (!cancelled) setReconnectSeq((n) => n + 1);
          }, 2500);
        }
      };

      socket.onerror = () => {
        if (!cancelled) setWsState('disconnected');
      };

      setWs(socket);
    };

    connectSocket();

    return () => {
      cancelled = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      resizeObserver.disconnect();
      dataDisposable.dispose();
      wsRef.current = null;
      if (activeSocket) {
        try {
          activeSocket.close(1000, 'Modal closed');
        } catch {
          // Ignore close error on already-closed socket
        }
      }
      setWs(null);
      try {
        term.dispose();
      } catch {
        // Ignore xterm dispose error
      }
      xtermRef.current = null;
      fitAddonRef.current = null;
    };
  }, [device.id, activeTab, reconnectSeq]);

  const handleSwitchTerminalContext = (nextRunAs: 'system' | 'user', nextShell: string) => {
    setRunAsContext(nextRunAs);
    setShellType(nextShell);
    setTerminalMode('connecting');
    setTerminalModeReason(null);
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(
        JSON.stringify({
          type: 'switch_context',
          deviceId: device.id,
          runAs: nextRunAs,
          shell: nextShell,
          cols: xtermRef.current?.cols || 120,
          rows: xtermRef.current?.rows || 32
        })
      );
      xtermRef.current?.focus();
    }
  };

  // Load processes
  const loadProcesses = async () => {
    setLoadingProcs(true);
    setToolError(null);
    try {
      const data = await fetchProcesses(device.id);
      setProcesses(Array.isArray(data) ? data : []);
    } catch (err: any) {
      setProcesses([]);
      setToolError(err?.message || 'Failed to query remote processes.');
    } finally {
      setLoadingProcs(false);
    }
  };

  // Load services
  const loadServices = async () => {
    setLoadingSvcs(true);
    setToolError(null);
    try {
      const data = await fetchServices(device.id);
      setServices(Array.isArray(data) ? data : []);
    } catch (err: any) {
      setServices([]);
      setToolError(err?.message || 'Failed to query remote services.');
    } finally {
      setLoadingSvcs(false);
    }
  };

  // Load registry
  const loadRegistry = async (path: string) => {
    setLoadingReg(true);
    setToolError(null);
    try {
      const data = await fetchRegistry(device.id, path);
      setRegData({
        subkeys: Array.isArray(data?.subkeys) ? data.subkeys : [],
        values: Array.isArray(data?.values) ? data.values : []
      });
      setRegPath(path);
    } catch (err: any) {
      setRegData({ subkeys: [], values: [] });
      setToolError(err?.message || 'Failed to read remote registry/configuration path.');
    } finally {
      setLoadingReg(false);
    }
  };

  // Load tasks
  const loadTasks = async () => {
    setLoadingTasks(true);
    setToolError(null);
    try {
      const data = await fetchScheduledTasks(device.id);
      setTasks(Array.isArray(data) ? data : []);
    } catch (err: any) {
      setTasks([]);
      setToolError(err?.message || 'Failed to load scheduled tasks.');
    } finally {
      setLoadingTasks(false);
    }
  };

  // Load files
  const loadFiles = async (path: string) => {
    setLoadingFiles(true);
    setToolError(null);
    try {
      const data = await fetchFiles(device.id, path);
      setFiles(Array.isArray(data) ? data : []);
      setCurrentPath(path);
    } catch (err: any) {
      setFiles([]);
      setToolError(err?.message || 'Failed to list remote directory.');
    } finally {
      setLoadingFiles(false);
    }
  };

  // Load event logs
  const loadEvents = async (channel = eventChannel, level = eventLevel) => {
    setLoadingEvents(true);
    setToolError(null);
    try {
      const data = await fetchEventLogs(device.id, channel, level, 100);
      setEventLogs(Array.isArray(data) ? data : []);
    } catch (err: any) {
      setEventLogs([]);
      setToolError(err?.message || 'Failed to load endpoint event logs.');
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
      const trimmedPath = currentPath.trim();
      if (!trimmedPath || /^[a-zA-Z]:[\\/]?$/.test(trimmedPath)) return;
      const normalized = trimmedPath.replace(/\\/g, '/');
      const parts = normalized.split('/').filter(Boolean);
      parts.pop();
      if (parts.length === 0) return;
      const parent = parts.length === 1 ? parts[0] + '\\' : parts.join('\\');
      loadFiles(parent);
    }
  };

  useEffect(() => {
    setToolError(null);
    if (activeTab === 'processes') loadProcesses();
    if (activeTab === 'services') loadServices();
    if (activeTab === 'registry') loadRegistry(regPath);
    if (activeTab === 'tasks') loadTasks();
    if (activeTab === 'files') loadFiles(currentPath);
    if (activeTab === 'events') loadEvents(eventChannel, eventLevel);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  const interactiveLabel = device.logged_in_user
    ? `${device.logged_in_user} (Interactive User)`
    : 'Interactive User';
  const identityBadge =
    osType === 'windows'
      ? runAsContext === 'system'
        ? 'NT AUTHORITY\\SYSTEM'
        : interactiveLabel
      : osType === 'macos'
        ? runAsContext === 'system'
          ? 'root (UID 0 LaunchDaemon)'
          : interactiveLabel
        : runAsContext === 'system'
          ? 'root (UID 0 systemd)'
          : interactiveLabel;

  const handleSnippet = (cmd: string) => {
    if (cmd === 'clear') {
      xtermRef.current?.clear();
      xtermRef.current?.focus();
      return;
    }
    const active = wsRef.current;
    if (!active || active.readyState !== WebSocket.OPEN) return;
    active.send(JSON.stringify({ type: 'data', data: `${cmd}\r` }));
    xtermRef.current?.focus();
  };

  const handleKillProcess = async (pid: number) => {
    if (confirm(`Are you sure you want to silently terminate PID ${pid}?`)) {
      setToolError(null);
      try {
        const res = await killProcess(device.id, pid);
        if (!res.success) {
          setToolError(res.error || `Failed to terminate PID ${pid}.`);
          return;
        }
        setProcesses(processes.filter((p) => p.pid !== pid));
      } catch (err: any) {
        setToolError(err?.message || `Failed to terminate PID ${pid}.`);
      }
    }
  };

  const handleManageService = async (name: string, action: 'start' | 'stop' | 'restart') => {
    setToolError(null);
    try {
      const res = await manageService(device.id, name, action);
      if (!res.success) {
        setToolError(res.error || `Failed to ${action} service ${name}.`);
        return;
      }
      await loadServices();
    } catch (err: any) {
      setToolError(err?.message || `Failed to ${action} service ${name}.`);
    }
  };

  const handleDownloadFile = (filePath: string) => {
    window.open(getRemoteFileDownloadUrl(device.id, filePath), '_blank', 'noopener,noreferrer');
  };

  const handleUploadFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 10 * 1024 * 1024) {
      setToolError('File exceeds the 10 MB remote upload limit.');
      if (fileUploadInputRef.current) fileUploadInputRef.current.value = '';
      return;
    }
    const reader = new FileReader();
    reader.onerror = () => {
      setToolError('Failed to read selected file for upload.');
      if (fileUploadInputRef.current) fileUploadInputRef.current.value = '';
    };
    reader.onload = async () => {
      setToolError(null);
      try {
        const dataUrl = String(reader.result || '');
        const base64 = dataUrl.includes(',') ? dataUrl.split(',')[1] : dataUrl;
        const res = await manageRemoteFile(device.id, {
          path: currentPath,
          action: 'upload',
          name: file.name,
          size: file.size,
          contentBase64: base64
        });
        if (res.success) {
          setFiles(res.files);
        } else {
          setToolError(res.error || 'Failed to upload file.');
        }
      } catch (err: any) {
        setToolError(err?.message || 'Failed to upload file.');
      } finally {
        if (fileUploadInputRef.current) fileUploadInputRef.current.value = '';
      }
    };
    reader.readAsDataURL(file);
  };

  const handleSaveRegValue = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRegName.trim()) return;
    setToolError(null);
    try {
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
      } else {
        setToolError((res as any).error || 'Failed to set registry value.');
      }
    } catch (err: any) {
      setToolError(err?.message || 'Failed to set registry value.');
    }
  };

  const handleDeleteRegValue = async (name: string) => {
    setToolError(null);
    try {
      const res = await deleteRegistryValue(device.id, regPath, name);
      if (res.success) {
        setRegData({ subkeys: res.subkeys, values: res.values });
      } else {
        setToolError((res as any).error || 'Failed to delete registry value.');
      }
    } catch (err: any) {
      setToolError(err?.message || 'Failed to delete registry value.');
    }
  };

  const handleCreateFolder = async () => {
    if (!newFolderName.trim()) return;
    setToolError(null);
    try {
      const res = await manageRemoteFile(device.id, { path: currentPath, action: 'mkdir', name: newFolderName.trim() });
      if (res.success) {
        setFiles(res.files);
        setNewFolderName('');
      } else {
        setToolError(res.error || 'Failed to create folder.');
      }
    } catch (err: any) {
      setToolError(err?.message || 'Failed to create folder.');
    }
  };

  const handleDeleteFile = async (name: string) => {
    if (!confirm(`Delete ${name} from ${currentPath}?`)) return;
    setToolError(null);
    try {
      const res = await manageRemoteFile(device.id, { path: currentPath, action: 'delete', name });
      if (res.success) {
        setFiles(res.files);
      } else {
        setToolError(res.error || 'Failed to delete remote file.');
      }
    } catch (err: any) {
      setToolError(err?.message || 'Failed to delete remote file.');
    }
  };

  const handleTaskAction = async (name: string, action: 'run' | 'enable' | 'disable') => {
    setToolError(null);
    try {
      const res = await manageScheduledTask(device.id, name, action);
      if (res.success) {
        setTasks(res.tasks);
      } else {
        setToolError((res as any).error || `Failed to ${action} task ${name}.`);
      }
    } catch (err: any) {
      setToolError(err?.message || `Failed to ${action} task ${name}.`);
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
            <span className="status-pill status-info" style={{ fontSize: '0.7rem' }}>
              {osType.toUpperCase()} Live Tools
            </span>
            {activeTab === 'terminal' && (
              <>
                <span
                  className={`status-pill ${
                    wsState === 'connected'
                      ? 'status-online'
                      : wsState === 'connecting'
                        ? 'status-reboot'
                        : 'status-offline'
                  }`}
                  style={{ fontSize: '0.7rem', display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}
                >
                  <span>
                    {wsState === 'connected'
                      ? terminalMode === 'pty'
                        ? 'Live MS2 PTY'
                        : terminalMode === 'line_fallback'
                          ? 'Command Relay Mode'
                          : 'Connecting PTY...'
                      : wsState === 'connecting'
                        ? 'WS Connecting...'
                        : 'WS Disconnected'}
                  </span>
                  {wsState === 'disconnected' && (
                    <button
                      type="button"
                      onClick={() => setReconnectSeq((n) => n + 1)}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: 'inherit',
                        textDecoration: 'underline',
                        cursor: 'pointer',
                        fontSize: '0.7rem',
                        padding: 0
                      }}
                    >
                      Reconnect
                    </button>
                  )}
                </span>
              </>
            )}
          </div>
          <button
            type="button"
            className="btn-glass btn-icon"
            onClick={onClose}
            id="close-bg-tools-btn"
            aria-label="Close background tools"
            title="Close"
          >
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
          {toolError && (
            <div
              style={{
                marginBottom: '1rem',
                padding: '0.65rem 0.9rem',
                borderRadius: '8px',
                background: 'rgba(239, 68, 68, 0.14)',
                border: '1px solid rgba(239, 68, 68, 0.35)',
                color: '#f87171',
                fontSize: '0.8rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '0.75rem'
              }}
            >
              <span>⚠ {toolError}</span>
              <button
                type="button"
                className="btn-glass btn-icon"
                style={{ padding: '0.2rem' }}
                onClick={() => setToolError(null)}
              >
                <X size={13} />
              </button>
            </div>
          )}

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
                  background: 'var(--glass-bg)',
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
                      ? 'Logged-In User (Interactive)'
                      : osType === 'macos'
                        ? 'Logged-In User (Console)'
                        : 'Logged-In User (UID 1000)'}
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
                {osType !== 'windows' && (
                  <button className="btn-glass" style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleSnippet('id')}>
                    id
                  </button>
                )}
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

              <div
                ref={xtermContainerRef}
                className="xterm-terminal-host"
                onClick={() => xtermRef.current?.focus()}
                id="terminal-window-output"
              />

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.74rem', color: 'var(--text-dim)', flexWrap: 'wrap', gap: '0.5rem' }}>
                <span>
                  Click inside the terminal above and type directly (full Ctrl+C, Tab autocomplete, ANSI/ConPTY support as {identityBadge}).
                </span>
                {terminalMode === 'line_fallback' && (
                  <span style={{ color: '#fbbf24' }}>
                    Command relay fallback active ({terminalModeReason || 'PTY tunnel unavailable'}) — commands execute on Enter.
                  </span>
                )}
              </div>
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
                <button className="btn-glass" onClick={loadProcesses} disabled={loadingProcs}>
                  <RefreshCw size={14} className={loadingProcs ? 'spin' : ''} /> {loadingProcs ? 'Loading...' : 'Refresh'}
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
                    {loadingProcs && processes.length === 0 ? (
                      <tr>
                        <td colSpan={7} style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-dim)' }}>
                          Querying live processes from {device.hostname}...
                        </td>
                      </tr>
                    ) : processes.filter((p) => p.name.toLowerCase().includes(procFilter.toLowerCase()) || p.pid.toString().includes(procFilter)).length === 0 ? (
                      <tr>
                        <td colSpan={7} style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-dim)' }}>
                          No running processes returned{procFilter ? ' matching filter' : ''}.
                        </td>
                      </tr>
                    ) : processes
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
                  placeholder={osType === 'windows' ? 'Filter Windows services...' : 'Filter services / daemons...'}
                  value={svcFilter}
                  onChange={(e) => setSvcFilter(e.target.value)}
                />
                <button className="btn-glass" onClick={loadServices} disabled={loadingSvcs}>
                  <RefreshCw size={14} className={loadingSvcs ? 'spin' : ''} /> {loadingSvcs ? 'Loading...' : 'Refresh'}
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
                    {loadingSvcs && services.length === 0 ? (
                      <tr>
                        <td colSpan={5} style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-dim)' }}>
                          Querying live services from {device.hostname}...
                        </td>
                      </tr>
                    ) : services.filter((s) => s.displayName.toLowerCase().includes(svcFilter.toLowerCase()) || s.name.toLowerCase().includes(svcFilter.toLowerCase())).length === 0 ? (
                      <tr>
                        <td colSpan={5} style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-dim)' }}>
                          No services returned{svcFilter ? ' matching filter' : ''}.
                        </td>
                      </tr>
                    ) : services
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
                  <RefreshCw size={14} className={loadingEvents ? 'spin' : ''} /> {loadingEvents ? 'Loading...' : 'Refresh Events'}
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
                    {loadingEvents && eventLogs.length === 0 ? (
                      <tr>
                        <td colSpan={5} style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-dim)' }}>
                          Querying live logs from {device.hostname}...
                        </td>
                      </tr>
                    ) : eventLogs.filter((ev) => {
                        if (!eventFilter.trim()) return true;
                        const q = eventFilter.toLowerCase();
                        return (
                          ev.eventId.toString().includes(q) ||
                          ev.source.toLowerCase().includes(q) ||
                          ev.message.toLowerCase().includes(q)
                        );
                      }).length === 0 ? (
                      <tr>
                        <td colSpan={5} style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-dim)' }}>
                          No endpoint event logs returned for this filter.
                        </td>
                      </tr>
                    ) : eventLogs
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
                  placeholder="Registry Hive Path / sysctl prefix / plist path..."
                />
                <button className="btn-glass btn-primary" onClick={() => loadRegistry(regPath)} disabled={loadingReg}>
                  <RefreshCw size={14} className={loadingReg ? 'spin' : ''} /> {loadingReg ? 'Reading...' : 'Browse'}
                </button>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: '1rem', minHeight: '360px' }}>
                <div className="glass-card" style={{ padding: '1rem' }}>
                  <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', marginBottom: '0.5rem' }}>SUBKEYS</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                    {loadingReg && regData.subkeys.length === 0 ? (
                      <div style={{ fontSize: '0.76rem', color: 'var(--text-dim)' }}>Loading subkeys...</div>
                    ) : regData.subkeys.length === 0 ? (
                      <div style={{ fontSize: '0.76rem', color: 'var(--text-dim)' }}>No subkeys at this path.</div>
                    ) : regData.subkeys.map((sub) => (
                      <button
                        key={sub}
                        className="btn-glass"
                        style={{ textAlign: 'left', justifyContent: 'flex-start', padding: '0.4rem 0.65rem', fontSize: '0.78rem' }}
                        onClick={() => {
                          if (sub.startsWith('/')) {
                            loadRegistry(sub);
                          } else if (osType === 'windows') {
                            loadRegistry(`${regPath.replace(/\\+$/, '')}\\${sub}`);
                          } else if (osType === 'macos') {
                            loadRegistry(`${regPath.replace(/\/+$/, '')}/${sub}`);
                          } else {
                            loadRegistry(regPath ? `${regPath.replace(/\.+$/, '')}.${sub}` : sub);
                          }
                        }}
                      >
                        <Folder size={14} color="var(--primary)" />
                        <span>{sub}</span>
                      </button>
                    ))}
                  </div>
                </div>

                <div className="table-wrapper" style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {osType === 'windows' && (
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
                  )}
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
                      {loadingReg && regData.values.length === 0 ? (
                        <tr>
                          <td colSpan={4} style={{ textAlign: 'center', padding: '1.25rem', color: 'var(--text-dim)' }}>
                            Reading values from {device.hostname}...
                          </td>
                        </tr>
                      ) : regData.values.length === 0 ? (
                        <tr>
                          <td colSpan={4} style={{ textAlign: 'center', padding: '1.25rem', color: 'var(--text-dim)' }}>
                            No values found at {regPath || 'this path'}.
                          </td>
                        </tr>
                      ) : regData.values.map((v, idx) => (
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
                <button className="btn-glass btn-primary" onClick={() => loadFiles(currentPath)} disabled={loadingFiles}>
                  {loadingFiles ? 'Loading...' : 'Go'}
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
                <input
                  ref={fileUploadInputRef}
                  type="file"
                  style={{ display: 'none' }}
                  onChange={handleUploadFileSelect}
                />
                <button
                  className="btn-glass btn-primary"
                  onClick={() => fileUploadInputRef.current?.click()}
                >
                  <Upload size={14} /> Upload File
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
                    {loadingFiles && files.length === 0 ? (
                      <tr>
                        <td colSpan={5} style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-dim)' }}>
                          Listing directory {currentPath} on {device.hostname}...
                        </td>
                      </tr>
                    ) : files.length === 0 ? (
                      <tr>
                        <td colSpan={5} style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-dim)' }}>
                          Directory is empty or inaccessible.
                        </td>
                      </tr>
                    ) : files.map((f, i) => (
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
                                onClick={() => handleDownloadFile(f.path)}
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
              <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '0.85rem' }}>
                <button className="btn-glass" onClick={loadTasks} disabled={loadingTasks}>
                  <RefreshCw size={14} className={loadingTasks ? 'spin' : ''} /> {loadingTasks ? 'Loading...' : 'Refresh Tasks'}
                </button>
              </div>
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
                    {loadingTasks && tasks.length === 0 ? (
                      <tr>
                        <td colSpan={7} style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-dim)' }}>
                          Querying scheduled tasks from {device.hostname}...
                        </td>
                      </tr>
                    ) : tasks.length === 0 ? (
                      <tr>
                        <td colSpan={7} style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-dim)' }}>
                          No scheduled tasks returned by endpoint.
                        </td>
                      </tr>
                    ) : tasks.map((t, i) => (
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
