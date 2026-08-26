'use client';

import { useEffect, useState } from 'react';
import { Search, RefreshCw, Radio, Filter, ShieldAlert, X } from 'lucide-react';
import { fetchEvents } from '@/lib/api';
import type { SecurityEvent, Severity } from '@/types/api';

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export default function EventsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [q, setQ] = useState('');
  const [selectedSev, setSelectedSev] = useState<string>('ALL');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [activeEvent, setActiveEvent] = useState<SecurityEvent | null>(null);

  const load = () => {
    setLoading(true);
    setError('');
    fetchEvents()
      .then(setEvents)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const filtered = events.filter((x) => {
    const matchSev = selectedSev === 'ALL' || x.severity === selectedSev;
    const matchQ = `${x.event_id} ${x.event_type} ${x.source_ip || ''} ${x.destination_ip || ''} ${x.user || ''} ${x.mitre_technique || ''}`
      .toLowerCase()
      .includes(q.toLowerCase());
    return matchSev && matchQ;
  });

  return (
    <main className="page">
      <div className="eyebrow">MONITORING</div>
      <div className="page-header">
        <div>
          <h1>Security Telemetry Events</h1>
          <p>Real-time stream of security events collected from sensors and simulated cyber range telemetry.</p>
        </div>
        <button className="refresh" onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh Stream
        </button>
      </div>

      {error && <div className="api-warning">API Warning: {error}</div>}

      <div className="toolbar" style={{ flexWrap: 'wrap', gap: 12 }}>
        <div className="search" style={{ flex: 1, minWidth: 280 }}>
          <Search size={15} />
          <input
            placeholder="Search events by IP, user, MITRE technique, event type..."
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Filter size={14} className="muted-icon" />
          <select
            value={selectedSev}
            onChange={(e) => setSelectedSev(e.target.value)}
            style={{
              background: '#05090d',
              border: '1px solid #1c2e39',
              padding: '6px 12px',
              color: '#dce8ec',
              borderRadius: '6px',
              fontSize: '12px',
            }}
          >
            <option value="ALL">All Severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="panel table-panel">
        <div className="table-meta">
          <span>{loading ? 'Loading stream...' : `${filtered.length} telemetry events`}</span>
          <span>Live Ingestion Pipeline Connected</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Event Type</th>
                <th>Severity</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>User / Host</th>
                <th>MITRE</th>
                <th>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((e) => (
                <tr key={e.event_id}>
                  <td className="mono" style={{ fontSize: '11px' }}>
                    {new Date(e.timestamp).toLocaleString()}
                  </td>
                  <td>
                    <b>{e.event_type}</b>
                    <small>{e.event_id}</small>
                  </td>
                  <td>
                    <span className={`badge ${e.severity.toLowerCase()}`}>{e.severity}</span>
                  </td>
                  <td className="mono">{e.source_ip || '—'}</td>
                  <td className="mono">{e.destination_ip || '—'}</td>
                  <td>
                    <b>{e.user || '—'}</b>
                    <small>{e.host || '—'}</small>
                  </td>
                  <td>
                    {e.mitre_technique ? (
                      <span className="mono" style={{ color: '#00e5ff', background: '#00e5ff12', padding: '2px 6px', borderRadius: '4px', fontSize: '11px' }}>
                        {e.mitre_technique}
                      </span>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td>
                    <button
                      className="refresh"
                      style={{ padding: '3px 8px', fontSize: '9px' }}
                      onClick={() => setActiveEvent(e)}
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
              {!loading && filtered.length === 0 && (
                <tr>
                  <td colSpan={8}>
                    <div className="empty">No events matching filter. Run a simulation to generate telemetry.</div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {activeEvent && (
        <div className="modal-overlay" onClick={() => setActiveEvent(null)}>
          <div className="modal-box" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '650px' }}>
            <div className="modal-head">
              <div>
                <h2>Event Payload: {activeEvent.event_id}</h2>
                <p>{activeEvent.event_type}</p>
              </div>
              <button className="modal-close" onClick={() => setActiveEvent(null)}>
                <X size={18} />
              </button>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 12 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <small style={{ color: '#688290', fontSize: '10px' }}>SEVERITY</small>
                  <div>
                    <span className={`badge ${activeEvent.severity.toLowerCase()}`}>
                      {activeEvent.severity}
                    </span>
                  </div>
                </div>
                <div>
                  <small style={{ color: '#688290', fontSize: '10px' }}>RULE TRIGGERED</small>
                  <div className="mono" style={{ color: '#dce8ec', fontSize: '12px' }}>
                    {activeEvent.rule_id || 'N/A'}
                  </div>
                </div>
              </div>
              <div>
                <small style={{ color: '#688290', fontSize: '10px' }}>DETAILS</small>
                <div style={{ background: '#05090d', border: '1px solid #1c2e39', padding: '10px', borderRadius: '6px', color: '#dce8ec', fontSize: '12px' }}>
                  {activeEvent.details || 'No additional details provided.'}
                </div>
              </div>
              <div>
                <small style={{ color: '#688290', fontSize: '10px' }}>RAW PAYLOAD JSON</small>
                <textarea
                  readOnly
                  rows={8}
                  value={JSON.stringify(activeEvent.raw_payload || {}, null, 2)}
                  style={{
                    width: '100%',
                    background: '#04070b',
                    border: '1px solid #1c2e39',
                    padding: '10px',
                    color: '#9eb4bf',
                    borderRadius: '6px',
                    fontFamily: 'DM Mono, monospace',
                    fontSize: '11px',
                  }}
                />
              </div>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
