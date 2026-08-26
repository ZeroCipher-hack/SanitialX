'use client';

import { useEffect, useState } from 'react';
import { Zap, RefreshCw, Terminal, Lock, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { fetchHoneypots } from '@/lib/api';
import type { HoneypotSession } from '@/types/api';

export default function HoneypotsPage() {
  const [sessions, setSessions] = useState<HoneypotSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = () => {
    setLoading(true);
    setError('');
    fetchHoneypots()
      .then(setSessions)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  return (
    <main className="page">
      <div className="eyebrow">DECEPTION TECHNOLOGY</div>
      <div className="page-header">
        <div>
          <h1>Honeypot & Deception Vault</h1>
          <p>Active deception nodes, trap sessions, and attacker activity command logs.</p>
        </div>
        <button className="refresh" onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh Traps
        </button>
      </div>

      {error && <div className="api-warning">API Warning: {error}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16, marginBottom: 20 }}>
        <div className="panel" style={{ padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '11px', color: '#688290' }}>SSH DECOY NODE</span>
            <span style={{ fontSize: '10px', color: '#00e5ff', background: '#00e5ff12', padding: '2px 6px', borderRadius: 4 }}>ONLINE</span>
          </div>
          <h3 style={{ margin: '8px 0 4px', fontSize: '15px' }}>decoy-ssh-vault</h3>
          <p style={{ fontSize: '11px', color: '#688290', margin: 0 }}>IP: 10.0.0.99 (Traps unauthorized SSH attempts)</p>
        </div>

        <div className="panel" style={{ padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '11px', color: '#688290' }}>FAKE WEB PANEL</span>
            <span style={{ fontSize: '10px', color: '#00e5ff', background: '#00e5ff12', padding: '2px 6px', borderRadius: 4 }}>ONLINE</span>
          </div>
          <h3 style={{ margin: '8px 0 4px', fontSize: '15px' }}>fake-admin-portal</h3>
          <p style={{ fontSize: '11px', color: '#688290', margin: 0 }}>IP: 10.0.0.50/admin (Logs fake credential logins)</p>
        </div>

        <div className="panel" style={{ padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '11px', color: '#688290' }}>DECOY SECRETS FILE</span>
            <span style={{ fontSize: '10px', color: '#ffb703', background: '#ffb70312', padding: '2px 6px', borderRadius: 4 }}>TRAPPED</span>
          </div>
          <h3 style={{ margin: '8px 0 4px', fontSize: '15px' }}>/var/www/.env.honeypot</h3>
          <p style={{ fontSize: '11px', color: '#688290', margin: 0 }}>Fake credentials seed for tracking lateral movement</p>
        </div>
      </div>

      <div className="panel table-panel">
        <div className="table-meta">
          <span>{loading ? 'Loading honeypot sessions...' : `${sessions.length} trapped sessions`}</span>
          <span>Deception Telemetry Stream</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Attacker IP</th>
                <th>Target Service</th>
                <th>Attempted Credentials</th>
                <th>Commands Executed</th>
                <th>Files Accessed</th>
                <th>Duration</th>
                <th>Risk Score</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.session_id}>
                  <td className="mono">
                    <b style={{ color: '#ff4a4a' }}>{s.attacker_ip}</b>
                    <small>{s.session_id}</small>
                  </td>
                  <td>
                    <b>{s.service}</b>
                    <small>{new Date(s.started_at).toLocaleString()}</small>
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {s.credentials_attempted.map((c, i) => (
                        <span key={i} className="mono" style={{ background: '#05090d', border: '1px solid #1c2e39', padding: '1px 5px', borderRadius: 3, fontSize: '10px' }}>
                          {c}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td>
                    <div className="mono" style={{ fontSize: '11px', color: '#00e5ff' }}>
                      {s.commands_executed.slice(0, 3).join('; ')}
                      {s.commands_executed.length > 3 && '...'}
                    </div>
                  </td>
                  <td className="mono" style={{ fontSize: '11px' }}>
                    {s.files_accessed.join(', ') || 'None'}
                  </td>
                  <td className="mono">{s.duration_seconds}s</td>
                  <td>
                    <span className="badge critical">{s.risk_score}/100</span>
                  </td>
                </tr>
              ))}
              {!loading && sessions.length === 0 && (
                <tr>
                  <td colSpan={7}>
                    <div className="empty">No honeypot sessions recorded yet. Run an attack simulation to trigger honeypot traps.</div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </main>
  );
}
