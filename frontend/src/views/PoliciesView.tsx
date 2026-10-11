import React, { useState, useEffect } from 'react';
import { ShieldCheck, GitBranch, ArrowRight, CheckCircle2, Sliders, Layers } from 'lucide-react';
import { Policy, Device } from '../types/index.js';
import { fetchPolicies } from '../services/api.js';

interface PoliciesViewProps {
  devices: Device[];
}

export const PoliciesView: React.FC<PoliciesViewProps> = ({ devices }) => {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState<string>(devices[0]?.id || '');
  const [effectivePolicy, setEffectivePolicy] = useState<any>(null);

  useEffect(() => {
    fetchPolicies().then(setPolicies);
  }, []);

  useEffect(() => {
    if (!selectedDeviceId) return;
    fetch(`/api/policies/effective/${selectedDeviceId}`)
      .then((res) => res.json())
      .then(setEffectivePolicy);
  }, [selectedDeviceId]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }} id="policies-view">
      <div>
        <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700 }}>
          Hierarchical Policy Inheritance Engine
        </h2>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          Multi-tiered governance cascading from Global &rarr; Client Tenant &rarr; Site Location &rarr; Device Role
        </span>
      </div>

      {/* Inheritance Architecture Diagram */}
      <div className="glass-card" style={{ background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.7) 0%, rgba(30, 41, 59, 0.5) 100%)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-around', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ textAlign: 'center' }}>
            <div className="status-pill status-online" style={{ fontSize: '0.78rem', marginBottom: '0.5rem' }}>Tier 1: Global</div>
            <div style={{ fontWeight: 600 }}>MSP Default Baseline</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Applies to all tenants</div>
          </div>
          <ArrowRight size={20} color="var(--primary)" />
          <div style={{ textAlign: 'center' }}>
            <div className="status-pill status-reboot" style={{ fontSize: '0.78rem', marginBottom: '0.5rem' }}>Tier 2: Client</div>
            <div style={{ fontWeight: 600 }}>Tenant Specific Rules</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Overrides Global settings</div>
          </div>
          <ArrowRight size={20} color="var(--primary)" />
          <div style={{ textAlign: 'center' }}>
            <div className="status-pill status-isolated" style={{ fontSize: '0.78rem', marginBottom: '0.5rem', background: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa' }}>Tier 3: Site</div>
            <div style={{ fontWeight: 600 }}>Branch / Subnet Rules</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Overrides Client tier</div>
          </div>
          <ArrowRight size={20} color="var(--primary)" />
          <div style={{ textAlign: 'center' }}>
            <div className="status-pill status-isolated" style={{ fontSize: '0.78rem', marginBottom: '0.5rem', background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc' }}>Tier 4: Role</div>
            <div style={{ fontWeight: 600 }}>Device Role (DC/Server/POS)</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Highest precedence</div>
          </div>
        </div>
      </div>

      {/* Interactive Simulator */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        {/* Policy Definitions List */}
        <div className="glass-card" style={{ padding: 0 }}>
          <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--glass-border)' }}>
            <h3 style={{ fontSize: '1.05rem', fontWeight: 600 }}>Defined Tier Policies</h3>
          </div>
          <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
            <table className="glass-table">
              <thead>
                <tr>
                  <th>Tier</th>
                  <th>Policy Name</th>
                  <th>Telemetry</th>
                  <th>Consent Required</th>
                  <th>Patch Window</th>
                </tr>
              </thead>
              <tbody>
                {policies.map((p) => (
                  <tr key={p.id}>
                    <td>
                      <span className="status-pill status-online" style={{ fontSize: '0.7rem' }}>
                        {p.tier.toUpperCase()}
                      </span>
                    </td>
                    <td><strong>{p.name}</strong></td>
                    <td>{p.telemetry_interval_sec}s</td>
                    <td>{p.require_remote_consent ? 'Yes (Prompt)' : 'No (Instant)'}</td>
                    <td><span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>{p.patch_schedule}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Live Resolved Policy Inspector */}
        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
            <h3 style={{ fontSize: '1.05rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Sliders size={18} color="var(--primary)" />
              <span>Effective Device Policy Inspector</span>
            </h3>
            <select
              className="glass-select"
              style={{ width: '220px' }}
              value={selectedDeviceId}
              onChange={(e) => setSelectedDeviceId(e.target.value)}
            >
              {devices.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.hostname} ({d.device_role})
                </option>
              ))}
            </select>
          </div>

          {effectivePolicy ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ background: 'rgba(0, 242, 254, 0.08)', padding: '0.85rem 1rem', borderRadius: '8px', border: '1px solid rgba(0, 242, 254, 0.2)' }}>
                <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--primary)', marginBottom: '0.35rem' }}>
                  ACTIVE INHERITANCE CHAIN
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', fontSize: '0.78rem' }}>
                  {effectivePolicy.inheritanceChain.map((node: any, idx: number) => (
                    <React.Fragment key={idx}>
                      <span style={{ background: 'rgba(255, 255, 255, 0.1)', padding: '0.2rem 0.5rem', borderRadius: '4px' }}>
                        [{node.tier.toUpperCase()}] {node.name}
                      </span>
                      {idx < effectivePolicy.inheritanceChain.length - 1 && <ArrowRight size={12} color="var(--text-dim)" />}
                    </React.Fragment>
                  ))}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem', fontSize: '0.85rem' }}>
                <div className="glass-card" style={{ padding: '0.85rem' }}>
                  <div style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>Telemetry Rate</div>
                  <div style={{ fontWeight: 600, fontSize: '1.1rem', color: 'var(--primary)' }}>
                    Every {effectivePolicy.telemetryIntervalSec} seconds
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '0.85rem' }}>
                  <div style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>Remote Consent Rule</div>
                  <div style={{ fontWeight: 600, fontSize: '1.1rem', color: effectivePolicy.requireRemoteConsent ? '#fbbf24' : '#10b981' }}>
                    {effectivePolicy.requireRemoteConsent ? `Prompt (${effectivePolicy.consentTimeoutSec}s timeout)` : 'Instant Connect'}
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '0.85rem' }}>
                  <div style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>Disconnect Action</div>
                  <div style={{ fontWeight: 600, fontSize: '1.1rem' }}>
                    {effectivePolicy.autoLockOnDisconnect ? '🔒 Auto-Lock Screen' : 'Leave Active'}
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '0.85rem' }}>
                  <div style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>Patch Reboot Enforcement</div>
                  <div style={{ fontWeight: 600, fontSize: '0.95rem' }}>
                    {effectivePolicy.patchRebootEnforcement}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div>Loading effective policy cascade...</div>
          )}
        </div>
      </div>
    </div>
  );
};
