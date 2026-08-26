'use client';

import { useEffect, useState } from 'react';
import { Cpu, RefreshCw, Server, Activity, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { fetchAgents } from '@/lib/api';
import type { Agent } from '@/types/api';

export default function AgentsPage() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = () => {
    setLoading(true);
    setError('');
    fetchAgents()
      .then(setAgents)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  return (
    <main className="page">
      <div className="eyebrow">ENVIRONMENT</div>
      <div className="page-header">
        <div>
          <h1>Endpoint Security Agents</h1>
          <p>Monitored virtual machines, containers, and agent telemetry status across the SanitialX cyber range.</p>
        </div>
        <button className="refresh" onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh Agents
        </button>
      </div>

      {error && <div className="api-warning">API Warning: {error}</div>}

      <div className="panel table-panel">
        <div className="table-meta">
          <span>{loading ? 'Loading agents...' : `${agents.length} active agents`}</span>
          <span>Agent Telemetry Status</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Agent Hostname</th>
                <th>IP Address</th>
                <th>OS Environment</th>
                <th>Status</th>
                <th>CPU Usage</th>
                <th>Memory Usage</th>
                <th>Risk Score</th>
                <th>Events Processed</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((a) => (
                <tr key={a.agent_id}>
                  <td>
                    <b>{a.hostname}</b>
                    <small>{a.agent_id}</small>
                  </td>
                  <td className="mono">{a.ip_address}</td>
                  <td>{a.os}</td>
                  <td>
                    <span
                      className={`badge ${
                        a.status === 'COMPROMISED'
                          ? 'critical'
                          : a.status === 'WARNING'
                          ? 'medium'
                          : 'low'
                      }`}
                    >
                      {a.status}
                    </span>
                  </td>
                  <td className="mono">{a.cpu_usage}%</td>
                  <td className="mono">{a.memory_usage}%</td>
                  <td>
                    <span className={`badge ${a.risk_score > 80 ? 'critical' : a.risk_score > 50 ? 'medium' : 'low'}`}>
                      {a.risk_score}/100
                    </span>
                  </td>
                  <td className="mono">{a.events_count}</td>
                </tr>
              ))}
              {!loading && agents.length === 0 && (
                <tr>
                  <td colSpan={8}>
                    <div className="empty">No agents registered. Run an attack simulation to seed agent telemetry.</div>
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
