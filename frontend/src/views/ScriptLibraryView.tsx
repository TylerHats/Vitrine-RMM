import React, { useState, useEffect } from 'react';
import { Code2, Play, Terminal, CheckCircle2, Copy, FileText, Check } from 'lucide-react';
import { ScriptItem, Device } from '../types/index.js';
import { fetchScripts, runScript } from '../services/api.js';

interface ScriptLibraryViewProps {
  devices: Device[];
}

export const ScriptLibraryView: React.FC<ScriptLibraryViewProps> = ({ devices }) => {
  const [scripts, setScripts] = useState<ScriptItem[]>([]);
  const [selectedScript, setSelectedScript] = useState<ScriptItem | null>(null);
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<string[]>([]);
  const [copied, setCopied] = useState(false);
  const [running, setRunning] = useState(false);
  const [runResult, setRunResult] = useState<any>(null);

  useEffect(() => {
    fetchScripts().then((data) => {
      setScripts(data);
      if (data.length > 0) setSelectedScript(data[0]);
    });
  }, []);

  const handleCopyCode = () => {
    if (selectedScript) {
      navigator.clipboard.writeText(selectedScript.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleRunMass = async () => {
    if (!selectedScript) return;
    if (selectedDeviceIds.length === 0) {
      alert('Please select at least one target device for mass orchestration.');
      return;
    }

    setRunning(true);
    try {
      const res = await runScript(selectedScript.id, selectedDeviceIds);
      setRunResult(res);
    } finally {
      setRunning(false);
    }
  };

  const toggleDeviceSelection = (id: string) => {
    if (selectedDeviceIds.includes(id)) {
      setSelectedDeviceIds(selectedDeviceIds.filter((d) => d !== id));
    } else {
      setSelectedDeviceIds([...selectedDeviceIds, id]);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="script-library-view">
      <div>
        <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
          Centralized Scripting Library &amp; Mass Orchestration
        </h2>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          Version-controlled multi-language scripts (PowerShell, Batch, Bash, Python) with target attribute dispatch
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '1.5rem', minHeight: '520px' }}>
        {/* Scripts Selector List */}
        <div className="glass-card" style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', marginBottom: '0.35rem' }}>
            REPOSITORY SCRIPTS ({scripts.length})
          </div>
          {scripts.map((s) => {
            const isSelected = selectedScript?.id === s.id;
            return (
              <div
                key={s.id}
                onClick={() => { setSelectedScript(s); setRunResult(null); }}
                style={{
                  padding: '0.75rem 1rem',
                  borderRadius: '8px',
                  background: isSelected ? 'rgba(0, 242, 254, 0.12)' : 'rgba(255, 255, 255, 0.03)',
                  border: `1px solid ${isSelected ? 'rgba(0, 242, 254, 0.35)' : 'rgba(255, 255, 255, 0.06)'}`,
                  cursor: 'pointer',
                  transition: 'all 0.15s'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>{s.name}</span>
                  <span className="status-pill status-reboot" style={{ fontSize: '0.65rem' }}>{s.language}</span>
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.25rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {s.description}
                </div>
              </div>
            );
          })}
        </div>

        {/* Script Editor & Mass Orchestration Target Selector */}
        {selectedScript && (
          <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <h3 style={{ fontSize: '1.2rem', fontWeight: 600 }}>{selectedScript.name}</h3>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{selectedScript.description}</p>
              </div>

              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button className="btn-glass" onClick={handleCopyCode}>
                  {copied ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
                <button className="btn-glass btn-primary" onClick={handleRunMass} disabled={running}>
                  <Play size={14} />
                  <span>{running ? 'Dispatching...' : 'Mass Execute'}</span>
                </button>
              </div>
            </div>

            {/* Code Viewer */}
            <div className="terminal-window" style={{ height: '240px', color: '#7dd3fc' }}>
              {selectedScript.code}
            </div>

            {/* Target Devices Selector */}
            <div style={{ borderTop: '1px solid var(--glass-border)', paddingTop: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)' }}>
                  TARGET DISPATCH SCOPE ({selectedDeviceIds.length} of {devices.length} selected)
                </span>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button
                    className="btn-glass"
                    style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
                    onClick={() => setSelectedDeviceIds(devices.map((d) => d.id))}
                  >
                    Select All
                  </button>
                  <button
                    className="btn-glass"
                    style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
                    onClick={() => setSelectedDeviceIds([])}
                  >
                    Clear
                  </button>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: '0.65rem' }}>
                {devices.map((d) => {
                  const isChecked = selectedDeviceIds.includes(d.id);
                  return (
                    <label
                      key={d.id}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.5rem',
                        padding: '0.5rem 0.75rem',
                        background: isChecked ? 'rgba(0, 242, 254, 0.1)' : 'rgba(0, 0, 0, 0.2)',
                        border: `1px solid ${isChecked ? 'rgba(0, 242, 254, 0.3)' : 'var(--glass-border)'}`,
                        borderRadius: '6px',
                        cursor: 'pointer',
                        fontSize: '0.8rem'
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => toggleDeviceSelection(d.id)}
                      />
                      <span>{d.hostname}</span>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginLeft: 'auto' }}>{d.device_role}</span>
                    </label>
                  );
                })}
              </div>
            </div>

            {/* Mass Run Output Banner */}
            {runResult && (
              <div style={{ background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.3)', padding: '0.85rem 1.25rem', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <CheckCircle2 size={18} color="#10b981" />
                <div style={{ fontSize: '0.82rem', color: '#34d399' }}>
                  Execution Dispatched: Script successfully queued across <strong>{runResult.dispatchedCount} endpoints</strong>. Execution ID: <code>{runResult.executionId}</code>.
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
