'use client';

import { Suspense, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { Search, RefreshCw, ChevronDown, Eye, X, Loader2, AlertCircle } from 'lucide-react';
import { api, updateIncidentStatus } from '@/lib/api';
import type { Incident, IncidentStatus, Severity } from '@/types/api';

const severities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const statuses: IncidentStatus[] = ['OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED'];

const ALLOWED_TRANSITIONS: Record<IncidentStatus, IncidentStatus[]> = {
  OPEN: ['INVESTIGATING', 'RESOLVED', 'CLOSED'],
  INVESTIGATING: ['RESOLVED', 'CLOSED'],
  RESOLVED: ['CLOSED', 'OPEN'],
  CLOSED: ['OPEN'],
};

function IncidentsContent() {
  const searchParams = useSearchParams();
  const targetId = searchParams.get('id');

  const [items, setItems] = useState<Incident[]>([]);
  const [q, setQ] = useState('');
  const [sev, setSev] = useState('ALL');
  const [status, setStatus] = useState('ALL');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  
  // Selected incident for modal
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  
  // Updating status state
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    setError('');
    api<Incident[]>('/incidents?limit=100')
      .then((data) => {
        setItems(data);
        if (targetId) {
          const match = data.find((x) => x.incident_id === targetId);
          if (match) setSelectedIncident(match);
        }
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, [targetId]);

  const handleStatusChange = async (incident: Incident, newStatus: IncidentStatus) => {
    if (incident.status === newStatus) return;
    setUpdatingId(incident.incident_id);
    setActionError(null);

    try {
      const updated = await updateIncidentStatus(incident.incident_id, newStatus, incident.version);
      setItems((prev) =>
        prev.map((item) => (item.incident_id === updated.incident_id ? updated : item))
      );
      if (selectedIncident?.incident_id === updated.incident_id) {
        setSelectedIncident(updated);
      }
    } catch (err: unknown) {
      let msg = 'Failed to update status.';
      if (err instanceof Error) {
        msg = err.message;
      }
      setActionError(`[${incident.incident_id}] ${msg}`);
    } finally {
      setUpdatingId(null);
    }
  };

  const filtered = useMemo(
    () =>
      items.filter(
        (x) =>
          (sev === 'ALL' || x.severity === sev) &&
          (status === 'ALL' || x.status === status) &&
          `${x.title} ${x.incident_id} ${x.source_ip || ''} ${x.destination_ip || ''}`
            .toLowerCase()
            .includes(q.toLowerCase())
      ),
    [items, q, sev, status]
  );

  return (
    <main className="page">
      <div className="eyebrow">INCIDENT RESPONSE</div>
      <div className="page-header">
        <div>
          <h1>Incidents</h1>
          <p>Investigate, contain and resolve security incidents.</p>
        </div>
        <button className="refresh" onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {error && <div className="api-warning">API Error: {error}</div>}
      {actionError && (
        <div className="inline-error" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <AlertCircle size={15} /> {actionError}
        </div>
      )}

      <div className="toolbar">
        <div className="search">
          <Search size={15} />
          <input
            placeholder="Search incidents, IPs or titles..."
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <Select value={sev} onChange={setSev} options={['ALL', ...severities]} />
        <Select value={status} onChange={setStatus} options={['ALL', ...statuses]} />
      </div>

      <div className="panel table-panel">
        <div className="table-meta">
          <span>{loading ? 'Loading…' : `${filtered.length} incidents`}</span>
          <span>Optimistic Concurrency Protected</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Incident</th>
                <th>Source → Target</th>
                <th>Status / Transition</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((x) => {
                const allowedNext = ALLOWED_TRANSITIONS[x.status] || [];
                const isUpdating = updatingId === x.incident_id;

                return (
                  <tr key={x.incident_id}>
                    <td>
                      <span className={`badge ${x.severity.toLowerCase()}`}>
                        {x.severity}
                      </span>
                    </td>
                    <td>
                      <b>{x.title}</b>
                      <small>{x.incident_id} (v{x.version})</small>
                    </td>
                    <td className="mono">
                      {x.source_ip || '—'} → {x.destination_ip || '—'}
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span className={`status ${x.status.toLowerCase()}`}>
                          {x.status}
                        </span>
                        {allowedNext.length > 0 && (
                          <div className="select-wrap" style={{ display: 'inline-block' }}>
                            <select
                              value={x.status}
                              disabled={isUpdating}
                              onChange={(e) =>
                                handleStatusChange(x, e.target.value as IncidentStatus)
                              }
                              style={{ padding: '4px 22px 4px 6px', fontSize: '9px' }}
                            >
                              <option value={x.status} disabled>
                                {isUpdating ? 'Updating...' : 'Change status...'}
                              </option>
                              {allowedNext.map((st) => (
                                <option key={st} value={st}>
                                  → {st}
                                </option>
                              ))}
                            </select>
                            <ChevronDown size={12} />
                          </div>
                        )}
                        {isUpdating && <Loader2 size={13} className="animate-spin text-cyan" />}
                      </div>
                    </td>
                    <td className="mono">{new Date(x.created_at).toLocaleString()}</td>
                    <td>
                      <button
                        className="refresh"
                        style={{ padding: '4px 8px', fontSize: '9px' }}
                        onClick={() => setSelectedIncident(x)}
                      >
                        <Eye size={13} /> View
                      </button>
                    </td>
                  </tr>
                );
              })}
              {!loading && !filtered.length && (
                <tr>
                  <td colSpan={6}>
                    <div className="empty">No incidents match the current filters.</div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Incident Detail Modal */}
      {selectedIncident && (
        <div className="modal-overlay" onClick={() => setSelectedIncident(null)}>
          <div className="modal-box" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <div>
                <h2>{selectedIncident.title}</h2>
                <p>Incident ID: {selectedIncident.incident_id} (Version {selectedIncident.version})</p>
              </div>
              <button className="modal-close" onClick={() => setSelectedIncident(null)}>
                <X size={18} />
              </button>
            </div>

            <div className="modal-grid">
              <div className="modal-field">
                <label>SEVERITY</label>
                <span className={`badge ${selectedIncident.severity.toLowerCase()}`}>
                  {selectedIncident.severity}
                </span>
              </div>

              <div className="modal-field">
                <label>STATUS</label>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 4 }}>
                  <span className={`status ${selectedIncident.status.toLowerCase()}`}>
                    {selectedIncident.status}
                  </span>
                  {(ALLOWED_TRANSITIONS[selectedIncident.status] || []).length > 0 && (
                    <div className="select-wrap">
                      <select
                        value={selectedIncident.status}
                        disabled={updatingId === selectedIncident.incident_id}
                        onChange={(e) =>
                          handleStatusChange(
                            selectedIncident,
                            e.target.value as IncidentStatus
                          )
                        }
                      >
                        <option value={selectedIncident.status} disabled>
                          Transition to...
                        </option>
                        {ALLOWED_TRANSITIONS[selectedIncident.status].map((st) => (
                          <option key={st} value={st}>
                            {st}
                          </option>
                        ))}
                      </select>
                      <ChevronDown size={14} />
                    </div>
                  )}
                </div>
              </div>

              <div className="modal-field">
                <label>SOURCE IP</label>
                <b>{selectedIncident.source_ip || 'None recorded'}</b>
              </div>

              <div className="modal-field">
                <label>DESTINATION IP</label>
                <b>{selectedIncident.destination_ip || 'None recorded'}</b>
              </div>

              <div className="modal-field">
                <label>CREATED AT</label>
                <b>{new Date(selectedIncident.created_at).toLocaleString()}</b>
              </div>

              <div className="modal-field">
                <label>UPDATED AT</label>
                <b>{new Date(selectedIncident.updated_at).toLocaleString()}</b>
              </div>

              <div className="modal-field full">
                <label>DESCRIPTION</label>
                <b>{selectedIncident.description || 'No description provided.'}</b>
              </div>

              <div className="modal-field full">
                <label>TRIGGERING DETECTION IDS</label>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 4 }}>
                  {selectedIncident.triggering_detection_ids?.length > 0 ? (
                    selectedIncident.triggering_detection_ids.map((id) => (
                      <span key={id} className="soon-badge" style={{ color: 'var(--cyan)' }}>
                        {id}
                      </span>
                    ))
                  ) : (
                    <span className="mono">None</span>
                  )}
                </div>
              </div>

              <div className="modal-field full">
                <label>CONTEXT / FORENSIC INFORMATION</label>
                <pre className="modal-code">
                  {JSON.stringify(selectedIncident.context || {}, null, 2)}
                </pre>
              </div>
            </div>

            <div className="modal-actions">
              <button className="btn-secondary" onClick={() => setSelectedIncident(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}

export default function Incidents() {
  return (
    <Suspense fallback={<div className="empty">Loading incidents workspace...</div>}>
      <IncidentsContent />
    </Suspense>
  );
}

function Select({
  value,
  onChange,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  options: string[];
}) {
  return (
    <div className="select-wrap">
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((x) => (
          <option key={x}>{x}</option>
        ))}
      </select>
      <ChevronDown size={14} />
    </div>
  );
}
