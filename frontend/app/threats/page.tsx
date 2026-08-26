'use client';

import { useEffect, useMemo, useState } from 'react';
import { Search, RefreshCw, Eye, ChevronRight } from 'lucide-react';
import Link from 'next/link';
import { api } from '@/lib/api';
import type { Incident } from '@/types/api';

export default function Threats() {
  const [items, setItems] = useState<Incident[]>([]);
  const [q, setQ] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    setError('');
    api<Incident[]>('/incidents?limit=100')
      .then(setItems)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const threats = useMemo(
    () =>
      items
        .filter((x) => x.severity === 'CRITICAL' || x.severity === 'HIGH')
        .filter((x) =>
          `${x.title} ${x.incident_id} ${x.source_ip || ''} ${x.destination_ip || ''}`
            .toLowerCase()
            .includes(q.toLowerCase())
        ),
    [items, q]
  );

  return (
    <main className="page">
      <div className="eyebrow">THREAT MANAGEMENT</div>
      <div className="page-header">
        <div>
          <h1>Threats</h1>
          <p>High-confidence malicious activity derived from critical & high severity incident telemetry.</p>
        </div>
        <button className="refresh" onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {error && <div className="api-warning">API Error: {error}</div>}

      <div className="toolbar">
        <div className="search">
          <Search size={15} />
          <input
            placeholder="Search high-priority threat feed..."
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
      </div>

      <div className="panel table-panel">
        <div className="table-meta">
          <span>{loading ? 'Loading…' : `${threats.length} high-priority threats`}</span>
          <span>Derived from active incident telemetry</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Threat Activity</th>
                <th>Source IP</th>
                <th>Target IP</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {threats.map((x) => (
                <tr key={x.incident_id}>
                  <td>
                    <span className={`badge ${x.severity.toLowerCase()}`}>{x.severity}</span>
                  </td>
                  <td>
                    <b>{x.title}</b>
                    <small>{x.incident_id}</small>
                  </td>
                  <td className="mono">{x.source_ip || '—'}</td>
                  <td className="mono">{x.destination_ip || '—'}</td>
                  <td>
                    <span className={`status ${x.status.toLowerCase()}`}>{x.status}</span>
                  </td>
                  <td>
                    <Link
                      href={`/incidents?id=${x.incident_id}`}
                      className="refresh"
                      style={{ padding: '4px 8px', fontSize: '9px', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 4 }}
                    >
                      <Eye size={12} /> Inspect <ChevronRight size={12} />
                    </Link>
                  </td>
                </tr>
              ))}
              {!loading && !threats.length && (
                <tr>
                  <td colSpan={6}>
                    <div className="empty">No high-priority threats match current filters.</div>
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
