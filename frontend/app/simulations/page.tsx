'use client';

import { useEffect, useState } from 'react';
import { Crosshair, Play, RefreshCw, CheckCircle2, ShieldAlert, Loader2, ArrowRight } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { fetchSimulations, runAttackSimulation } from '@/lib/api';
import type { AttackSimulation } from '@/types/api';

const SCENARIOS = [
  {
    id: 'WEB_APP_COMPROMISE',
    name: 'Web Application Compromise (Flagship)',
    difficulty: 'Intermediate',
    description: 'Full-chain attack: Reconnaissance -> Brute Force -> SSH Shell -> Honeypot Trap -> Priv Esc -> Fake DB Access -> Simulated Exfiltration.',
    stages: 7,
  },
  {
    id: 'BRUTE_FORCE_SSH',
    name: 'SSH Credential Brute Force',
    difficulty: 'Basic',
    description: 'Simulates automated password spraying and SSH credential guessing against internal Linux servers.',
    stages: 3,
  },
  {
    id: 'PRIVILEGE_ESCALATION',
    name: 'SUID Privilege Escalation',
    difficulty: 'Intermediate',
    description: 'Simulates local privilege escalation from unprivileged www-data user to root via vulnerable binary.',
    stages: 4,
  },
  {
    id: 'DATA_EXFILTRATION',
    name: 'Database Dumping & C2 Exfiltration',
    difficulty: 'Advanced',
    description: 'Simulates SQL data extraction from customer DB and encrypted egress transfer to external C2 IP.',
    stages: 5,
  },
];

export default function SimulationsPage() {
  const router = useRouter();
  const [simulations, setSimulations] = useState<AttackSimulation[]>([]);
  const [selectedScenario, setSelectedScenario] = useState('WEB_APP_COMPROMISE');
  const [running, setRunning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [lastIncidentId, setLastIncidentId] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    setError('');
    fetchSimulations()
      .then(setSimulations)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const handleStartSimulation = async () => {
    setRunning(true);
    setError('');
    setLastIncidentId(null);
    try {
      const res = await runAttackSimulation(selectedScenario);
      setSimulations((prev) => [res, ...prev]);
      if (res.generated_incident_id) {
        setLastIncidentId(res.generated_incident_id);
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Simulation failed';
      setError(msg);
    } finally {
      setRunning(false);
    }
  };

  return (
    <main className="page">
      <div className="eyebrow">CYBER RANGE</div>
      <div className="page-header">
        <div>
          <h1>Attack Simulator</h1>
          <p>Launch controlled attack scenarios in the isolated cyber range to test detection rules, honeypots, and AI investigation capabilities.</p>
        </div>
        <button className="refresh" onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh History
        </button>
      </div>

      {error && <div className="api-warning">Simulation Error: {error}</div>}

      {lastIncidentId && (
        <div style={{ background: '#00e5ff12', border: '1px solid #00e5ff', padding: '14px 18px', borderRadius: '8px', marginBottom: 20, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <strong style={{ color: '#00e5ff', display: 'flex', alignItems: 'center', gap: 6 }}>
              <CheckCircle2 size={16} /> Simulation Completed & Telemetry Generated!
            </strong>
            <span style={{ fontSize: '12px', color: '#dce8ec', marginTop: 4, display: 'block' }}>
              Incident created: <b>{lastIncidentId}</b>. Telemetry events, honeypot logs, attack path nodes, and AI reasoning report are now live.
            </span>
          </div>
          <button
            className="btn-primary"
            onClick={() => router.push(`/incidents?id=${lastIncidentId}`)}
            style={{ padding: '8px 14px', fontSize: '12px' }}
          >
            Inspect Incident <ArrowRight size={14} />
          </button>
        </div>
      )}

      <div className="panel" style={{ padding: 20, marginBottom: 24 }}>
        <h2 style={{ fontSize: '16px', margin: '0 0 12px' }}>Launch Attack Scenario</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 14, marginBottom: 20 }}>
          {SCENARIOS.map((s) => (
            <div
              key={s.id}
              onClick={() => setSelectedScenario(s.id)}
              style={{
                background: selectedScenario === s.id ? '#0a1622' : '#05090d',
                border: selectedScenario === s.id ? '1px solid #00e5ff' : '1px solid #1c2e39',
                borderRadius: '8px',
                padding: 16,
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span className="mono" style={{ fontSize: '10px', color: '#688290' }}>
                  {s.difficulty.toUpperCase()} • {s.stages} STAGES
                </span>
                {selectedScenario === s.id && <span style={{ fontSize: '10px', color: '#00e5ff', fontWeight: 'bold' }}>SELECTED</span>}
              </div>
              <h3 style={{ margin: '0 0 6px', fontSize: '14px', color: '#fff' }}>{s.name}</h3>
              <p style={{ margin: 0, fontSize: '11px', color: '#9eb4bf', lineHeight: 1.4 }}>{s.description}</p>
            </div>
          ))}
        </div>

        <button
          onClick={handleStartSimulation}
          disabled={running}
          className="btn-primary"
          style={{ padding: '12px 24px', fontSize: '14px', display: 'inline-flex', alignItems: 'center', gap: 8 }}
        >
          {running ? (
            <>
              <Loader2 size={16} className="animate-spin" /> Executing Simulation Scenario...
            </>
          ) : (
            <>
              <Play size={16} fill="#000" /> START CONTROLLED SIMULATION
            </>
          )}
        </button>
      </div>

      <div className="panel table-panel">
        <div className="table-meta">
          <span>{loading ? 'Loading history...' : `${simulations.length} historical simulations`}</span>
          <span>Cyber Range Execution Log</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Simulation ID</th>
                <th>Scenario Name</th>
                <th>Target Environment</th>
                <th>Status</th>
                <th>Generated Incident</th>
                <th>Events</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {simulations.map((sim) => (
                <tr key={sim.simulation_id}>
                  <td className="mono">
                    <b>{sim.simulation_id}</b>
                  </td>
                  <td>
                    <b>{sim.scenario_name}</b>
                  </td>
                  <td className="mono">{sim.target_environment}</td>
                  <td>
                    <span className="status enabled">{sim.status}</span>
                  </td>
                  <td>
                    {sim.generated_incident_id ? (
                      <button
                        className="refresh"
                        style={{ padding: '3px 8px', fontSize: '10px' }}
                        onClick={() => router.push(`/incidents?id=${sim.generated_incident_id}`)}
                      >
                        {sim.generated_incident_id}
                      </button>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="mono">{sim.events_generated}</td>
                  <td className="mono">{new Date(sim.started_at).toLocaleString()}</td>
                </tr>
              ))}
              {!loading && simulations.length === 0 && (
                <tr>
                  <td colSpan={7}>
                    <div className="empty">No simulation history. Click START CONTROLLED SIMULATION above.</div>
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
