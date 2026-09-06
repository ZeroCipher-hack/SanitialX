'use client';

import { useEffect, useMemo, useState } from 'react';
import { RefreshCw, Search, Wifi, ShieldAlert, Server, Boxes } from 'lucide-react';
import { api } from '@/lib/api';
import type { Agent } from '@/types/api';

type AssetSummary = {
  total_assets: number;
  critical_assets: number;
  internet_facing_assets: number;
  offline_assets: number;
  high_risk_assets: number;
  production_assets: number;
  managed_assets: number;
  retired_assets: number;
  stale_inventory_assets: number;
};

const EMPTY_SUMMARY: AssetSummary = {
  total_assets: 0,
  critical_assets: 0,
  internet_facing_assets: 0,
  offline_assets: 0,
  high_risk_assets: 0,
  production_assets: 0,
  managed_assets: 0,
  retired_assets: 0,
  stale_inventory_assets: 0,
};

export default function AgentsPage() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [summary, setSummary] = useState<AssetSummary>(EMPTY_SUMMARY);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [criticality, setCriticality] = useState('ALL');
  const [lifecycle, setLifecycle] = useState('ALL');
  const [environment, setEnvironment] = useState('ALL');

  const load = async () => {
    setLoading(true);
    setError('');
    const [agentsResult, summaryResult] = await Promise.allSettled([
      api<Agent[]>('/agents?limit=500'),
      api<AssetSummary>('/agents/summary'),
    ]);
    if (agentsResult.status === 'fulfilled') setAgents(agentsResult.value);
    else setError('Asset inventory unavailable.');
    if (summaryResult.status === 'fulfilled') setSummary(summaryResult.value);
    else setError((prev) => prev || 'Asset summary unavailable.');
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return agents.filter((asset) => {
      const matchesQuery = !needle || [asset.hostname, asset.ip_address, asset.os, asset.owner || '', ...(asset.tags || [])]
        .some((value) => value.toLowerCase().includes(needle));
      const matchesCriticality = criticality === 'ALL' || asset.criticality === criticality;
      const matchesLifecycle = lifecycle === 'ALL' || asset.lifecycle_status === lifecycle;
      const matchesEnvironment = environment === 'ALL' || asset.environment === environment;
      return matchesQuery && matchesCriticality && matchesLifecycle && matchesEnvironment;
    });
  }, [agents, query, criticality, lifecycle, environment]);

  return (
    <main className="page">
      <div className="eyebrow">ASSET MANAGEMENT</div>
      <div className="page-header">
        <div>
          <h1>Managed Asset Inventory</h1>
          <p>Endpoint identity, lifecycle, business criticality and exposure posture from one SOC inventory.</p>
        </div>
        <button className="refresh" onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh Assets
        </button>
      </div>

      {error && <div className="api-warning">{error}</div>}

      <section className="stats">
        <SummaryCard icon={<Boxes />} label="Total assets" value={summary.total_assets} detail={`${summary.managed_assets} managed`} />
        <SummaryCard icon={<ShieldAlert />} label="Critical assets" value={summary.critical_assets} detail={`${summary.high_risk_assets} high telemetry risk`} danger={summary.critical_assets > 0} />
        <SummaryCard icon={<Wifi />} label="Internet-facing" value={summary.internet_facing_assets} detail={`${summary.offline_assets} offline`} danger={summary.internet_facing_assets > 0} />
        <SummaryCard icon={<Server />} label="Inventory stale" value={summary.stale_inventory_assets} detail={`${summary.production_assets} production`} danger={summary.stale_inventory_assets > 0} />
      </section>

      <div className="toolbar">
        <label className="search">
          <Search size={14} />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Hostname, IP, OS, owner yoki tag..." />
        </label>
        <div className="select-wrap"><select value={criticality} onChange={(e) => setCriticality(e.target.value)}><option>ALL</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></div>
        <div className="select-wrap"><select value={environment} onChange={(e) => setEnvironment(e.target.value)}><option>ALL</option><option>PRODUCTION</option><option>STAGING</option><option>DEVELOPMENT</option><option>TEST</option><option>UNKNOWN</option></select></div>
        <div className="select-wrap"><select value={lifecycle} onChange={(e) => setLifecycle(e.target.value)}><option>ALL</option><option>DISCOVERED</option><option>MANAGED</option><option>RETIRED</option><option>EXCLUDED</option></select></div>
      </div>

      <div className="panel table-panel">
        <div className="table-meta">
          <span>{loading ? 'Loading assets...' : `${filtered.length} of ${agents.length} assets`}</span>
          <span>Asset + telemetry posture</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Asset</th><th>IP / OS</th><th>Type</th><th>Criticality</th><th>Environment</th><th>Lifecycle</th><th>Exposure</th><th>Telemetry</th><th>Risk</th></tr></thead>
            <tbody>
              {filtered.map((asset) => (
                <tr key={asset.agent_id}>
                  <td><b>{asset.hostname}</b><small>{asset.owner || 'No owner'} · {asset.agent_id}</small></td>
                  <td><span className="mono">{asset.ip_address}</span><small>{asset.os}</small></td>
                  <td>{asset.asset_type || 'ENDPOINT'}</td>
                  <td><span className={`badge ${(asset.criticality || 'MEDIUM').toLowerCase()}`}>{asset.criticality || 'MEDIUM'}</span></td>
                  <td>{asset.environment || 'UNKNOWN'}</td>
                  <td><span className="status enabled">{asset.lifecycle_status || 'DISCOVERED'}</span></td>
                  <td>{asset.internet_exposed ? <span className="badge high">PUBLIC</span> : <span className="badge low">PRIVATE</span>}</td>
                  <td><span className={`badge ${asset.status === 'COMPROMISED' ? 'critical' : asset.status === 'WARNING' ? 'medium' : asset.status === 'OFFLINE' ? 'high' : 'low'}`}>{asset.status}</span><small>{asset.inventory_updated_at ? `inventory ${new Date(asset.inventory_updated_at).toLocaleDateString()}` : 'inventory not reported'}</small></td>
                  <td><span className={`badge ${asset.risk_score >= 80 ? 'critical' : asset.risk_score >= 50 ? 'medium' : 'low'}`}>{asset.risk_score}/100</span></td>
                </tr>
              ))}
              {!loading && filtered.length === 0 && <tr><td colSpan={9}><div className="empty">No assets match the selected filters.</div></td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </main>
  );
}

function SummaryCard({ icon, label, value, detail, danger }: { icon: React.ReactNode; label: string; value: number; detail: string; danger?: boolean }) {
  return <div className="stat"><div className="stat-icon">{icon}</div><div className="stat-copy"><span>{label}</span><strong>{value}</strong><em className={danger ? 'bad' : ''}>{detail}</em></div></div>;
}
