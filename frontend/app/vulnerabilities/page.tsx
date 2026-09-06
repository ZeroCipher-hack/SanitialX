'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Bug,
  CheckCircle2,
  Crosshair,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  X,
} from 'lucide-react';
import { api } from '@/lib/api';

type Vulnerability = {
  cve_id: string;
  summary: string;
  cvss_score: number | null;
  severity: string;
  published_at: string | null;
  modified_at: string | null;
  known_exploited: boolean;
  exploit_available: boolean;
  affected_products: Array<Record<string, unknown>>;
  references: string[];
  source: string;
  ingested_at: string;
};

type Exposure = {
  id: number;
  agent_id: string;
  cve_id: string;
  status: string;
  match_confidence: number;
  risk_score: number;
  internet_exposed: boolean;
  matched_software: Record<string, unknown>;
  rationale: string;
  first_seen: string;
  last_evaluated: string;
};

function fmtDate(value: string | null) {
  if (!value) return '—';
  return new Intl.DateTimeFormat('en-GB', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'UTC',
  }).format(new Date(value));
}

function riskClass(score: number) {
  if (score >= 90) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

export default function VulnerabilityCenter() {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [exposures, setExposures] = useState<Exposure[]>([]);
  const [selected, setSelected] = useState<Vulnerability | null>(null);
  const [q, setQ] = useState('');
  const [severity, setSeverity] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState('');
  const [syncMessage, setSyncMessage] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [vulns, exps] = await Promise.all([
        api<Vulnerability[]>('/vulnerabilities?limit=500'),
        api<Exposure[]>('/vulnerabilities/exposures?limit=500'),
      ]);
      setVulnerabilities(vulns);
      setExposures(exps);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Vulnerability ma’lumotlarini yuklab bo‘lmadi.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleSync = async () => {
    setSyncing(true);
    setSyncMessage('');
    try {
      const result = await api<Record<string, unknown>>('/vulnerabilities/sync?hours=24&max_pages=10', {
        method: 'POST',
      });
      const processed = Number(result.nvd_records_processed || 0);
      setSyncMessage(`Sync tugadi: ${processed} ta NVD yozuvi qayta ishladi.`);
      await load();
    } catch (e: unknown) {
      setSyncMessage(e instanceof Error ? `Sync xatosi: ${e.message}` : 'Sync bajarilmadi.');
    } finally {
      setSyncing(false);
    }
  };

  const exposureByCve = useMemo(() => {
    const map = new Map<string, Exposure[]>();
    for (const exposure of exposures) {
      const current = map.get(exposure.cve_id) || [];
      current.push(exposure);
      map.set(exposure.cve_id, current);
    }
    return map;
  }, [exposures]);

  const filtered = useMemo(() => {
    const needle = q.toLowerCase().trim();
    return vulnerabilities.filter((v) => {
      const matchesSeverity = severity === 'ALL' || v.severity === severity;
      const matchesSearch = !needle || `${v.cve_id} ${v.summary}`.toLowerCase().includes(needle);
      return matchesSeverity && matchesSearch;
    });
  }, [vulnerabilities, q, severity]);

  const critical = vulnerabilities.filter((v) => v.severity === 'CRITICAL').length;
  const kev = vulnerabilities.filter((v) => v.known_exploited).length;
  const affectedAssets = new Set(exposures.map((x) => x.agent_id)).size;
  const highRisk = exposures.filter((x) => x.risk_score >= 70).length;

  return (
    <main className="page">
      <div className="eyebrow">VULNERABILITY INTELLIGENCE</div>
      <div className="page-header">
        <div>
          <h1>Vulnerability Center</h1>
          <p>Yangi CVE’larni kuzating, real asset exposure’larini aniqlang va ustuvor xavflarni boshqaring.</p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="refresh" onClick={load} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Yangilash
          </button>
          <button className="demo-attack-btn" onClick={handleSync} disabled={syncing} title="NVD va CISA KEV bilan sync">
            <Sparkles size={14} /> {syncing ? 'SYNC...' : 'CVE SYNC'}
          </button>
        </div>
      </div>

      {error && <div className="api-warning">API Error: {error}</div>}
      {syncMessage && <div className="inline-error" style={{ marginBottom: 14 }}>{syncMessage}</div>}

      <div className="stat-grid" style={{ marginBottom: 18 }}>
        <div className="stat-card">
          <div className="stat-label"><ShieldAlert size={14} /> Critical CVE</div>
          <strong>{critical}</strong>
          <small>Saqlangan kritik zaifliklar</small>
        </div>
        <div className="stat-card">
          <div className="stat-label"><Crosshair size={14} /> Known Exploited</div>
          <strong>{kev}</strong>
          <small>CISA KEV katalogida mavjud</small>
        </div>
        <div className="stat-card">
          <div className="stat-label"><Bug size={14} /> Affected Assets</div>
          <strong>{affectedAssets}</strong>
          <small>Kamida bitta exposure topilgan asset</small>
        </div>
        <div className="stat-card">
          <div className="stat-label"><AlertTriangle size={14} /> High Risk Exposure</div>
          <strong>{highRisk}</strong>
          <small>Risk score 70 yoki undan yuqori</small>
        </div>
      </div>

      <div className="toolbar">
        <div className="search">
          <Search size={15} />
          <input
            placeholder="CVE ID yoki tavsif bo‘yicha qidiring..."
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <div className="select-wrap">
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map((x) => <option key={x}>{x}</option>)}
          </select>
        </div>
      </div>

      <div className="panel table-panel">
        <div className="table-meta">
          <span>{loading ? 'Loading…' : `${filtered.length} vulnerabilities`}</span>
          <span>{exposures.length} asset exposure records</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>CVE</th>
                <th>CVSS</th>
                <th>Threat Intel</th>
                <th>Affected Assets</th>
                <th>Max Risk</th>
                <th>Published</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((v) => {
                const cveExposures = exposureByCve.get(v.cve_id) || [];
                const maxRisk = cveExposures.reduce((max, x) => Math.max(max, x.risk_score), 0);
                return (
                  <tr key={v.cve_id}>
                    <td><span className={`badge ${v.severity.toLowerCase()}`}>{v.severity}</span></td>
                    <td>
                      <b className="mono">{v.cve_id}</b>
                      <small>{v.summary.length > 110 ? `${v.summary.slice(0, 110)}…` : v.summary}</small>
                    </td>
                    <td className="mono">{v.cvss_score ?? '—'}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                        {v.known_exploited && <span className="soon-badge" style={{ color: 'var(--red)' }}>CISA KEV</span>}
                        {v.exploit_available && <span className="soon-badge" style={{ color: 'var(--amber)' }}>EXPLOIT</span>}
                        {!v.known_exploited && !v.exploit_available && <span className="mono">NVD</span>}
                      </div>
                    </td>
                    <td><b>{new Set(cveExposures.map((x) => x.agent_id)).size}</b></td>
                    <td>{maxRisk ? <span className={`badge ${riskClass(maxRisk)}`}>{maxRisk}/100</span> : <span className="mono">—</span>}</td>
                    <td className="mono">{fmtDate(v.published_at)}</td>
                    <td><button className="refresh" onClick={() => setSelected(v)}>View</button></td>
                  </tr>
                );
              })}
              {!loading && filtered.length === 0 && (
                <tr><td colSpan={8}><div className="empty">Mos vulnerability topilmadi.</div></td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selected && (() => {
        const selectedExposures = exposureByCve.get(selected.cve_id) || [];
        return (
          <div className="modal-overlay" onClick={() => setSelected(null)}>
            <div className="modal-box" onClick={(e) => e.stopPropagation()}>
              <div className="modal-head">
                <div>
                  <h2>{selected.cve_id}</h2>
                  <p>Vulnerability intelligence detail</p>
                </div>
                <button className="modal-close" onClick={() => setSelected(null)}><X size={18} /></button>
              </div>

              <div className="modal-grid">
                <div className="modal-field"><label>SEVERITY</label><span className={`badge ${selected.severity.toLowerCase()}`}>{selected.severity}</span></div>
                <div className="modal-field"><label>CVSS</label><b>{selected.cvss_score ?? 'Unknown'}</b></div>
                <div className="modal-field"><label>CISA KEV</label><b>{selected.known_exploited ? 'YES — exploited in the wild' : 'No'}</b></div>
                <div className="modal-field"><label>EXPLOIT SIGNAL</label><b>{selected.exploit_available ? 'Available / detected' : 'Not recorded'}</b></div>
                <div className="modal-field"><label>PUBLISHED</label><b>{fmtDate(selected.published_at)}</b></div>
                <div className="modal-field"><label>MODIFIED</label><b>{fmtDate(selected.modified_at)}</b></div>
                <div className="modal-field full"><label>SUMMARY</label><b>{selected.summary}</b></div>

                <div className="modal-field full">
                  <label>ASSET EXPOSURES ({selectedExposures.length})</label>
                  {selectedExposures.length === 0 ? (
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 8 }}><ShieldCheck size={16} /> Hozircha managed asset exposure topilmadi.</div>
                  ) : (
                    <div style={{ display: 'grid', gap: 8, marginTop: 8 }}>
                      {selectedExposures.map((exposure) => (
                        <div key={exposure.id} className="rail-status-card" style={{ margin: 0 }}>
                          <div className="rail-status-row"><span>Agent</span><b>{exposure.agent_id}</b></div>
                          <div className="rail-status-row"><span>Status</span><b>{exposure.status}</b></div>
                          <div className="rail-status-row"><span>Risk</span><b>{exposure.risk_score}/100</b></div>
                          <div className="rail-status-row"><span>Confidence</span><b>{Math.round(exposure.match_confidence * 100)}%</b></div>
                          <div className="rail-status-row"><span>Internet exposed</span><b>{exposure.internet_exposed ? 'YES' : 'NO'}</b></div>
                          <small style={{ display: 'block', marginTop: 8 }}>{exposure.rationale}</small>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="modal-field full">
                  <label>AFFECTED PRODUCT DATA</label>
                  <pre className="modal-code">{JSON.stringify(selected.affected_products || [], null, 2)}</pre>
                </div>
              </div>

              <div className="modal-actions">
                <button className="btn-secondary" onClick={() => setSelected(null)}><CheckCircle2 size={14} /> Close</button>
              </div>
            </div>
          </div>
        );
      })()}
    </main>
  );
}
