'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle, Brain, Crosshair, Flame, Loader2, RefreshCw,
  Search, ShieldAlert, ShieldCheck, X, CheckCircle2,
} from 'lucide-react';
import { api } from '@/lib/api';

type Exposure = {
  id: number;
  agent_id: string;
  cve_id: string;
  status: string;
  match_confidence: number;
  risk_score: number;
  internet_exposed: boolean;
  active_threat: boolean;
  remediation_status: string;
  remediation_note: string;
  remediation_updated_by: string | null;
  matched_software: Record<string, unknown>;
  rationale: string;
  first_seen: string;
  last_evaluated: string;
  // Enriched CVE intel (joined server-side).
  cve_summary: string;
  cvss_score: number | null;
  epss_score: number | null;
  epss_percentile: number | null;
  severity: string;
  known_exploited: boolean;
  exploit_available: boolean;
  cve_published_at: string | null;
};

type AIAnalysis = {
  cve_id: string; asset_id: string; executive_summary: string; affected_status: string;
  confidence_score: number; risk_score: number; risk_factors: string[];
  remediation_actions: string[]; investigation_queries: string[]; evidence: string[];
  analyst_note: string;
};

function riskClass(score: number) {
  if (score >= 90) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

function fmtEpss(score: number | null) {
  if (score === null || score === undefined) return '—';
  return `${(score * 100).toFixed(1)}%`;
}

function epssColor(score: number | null) {
  if (score === null || score === undefined) return 'var(--muted)';
  if (score >= 0.5) return 'var(--red)';
  if (score >= 0.1) return 'var(--amber)';
  return 'var(--muted)';
}

const REMEDIATION: { value: string; label: string; color: string }[] = [
  { value: 'OPEN', label: 'Ochiq', color: 'var(--amber)' },
  { value: 'IN_PROGRESS', label: 'Jarayonda', color: 'var(--cyan)' },
  { value: 'RESOLVED', label: 'Hal qilindi', color: 'var(--cyan)' },
  { value: 'RISK_ACCEPTED', label: 'Risk qabul qilindi', color: 'var(--muted)' },
  { value: 'FALSE_POSITIVE', label: 'Noto‘g‘ri signal', color: 'var(--muted)' },
];

function remLabel(value: string): string {
  return REMEDIATION.find((r) => r.value === value)?.label ?? value;
}

function remColor(value: string): string {
  return REMEDIATION.find((r) => r.value === value)?.color ?? 'var(--muted)';
}

export default function ExposureCenter() {
  const [exposures, setExposures] = useState<Exposure[]>([]);
  const [selected, setSelected] = useState<Exposure | null>(null);
  const [q, setQ] = useState('');
  const [agent, setAgent] = useState('ALL');
  const [minRisk, setMinRisk] = useState('0');
  const [kevOnly, setKevOnly] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState('');
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysis | null>(null);
  const [remNote, setRemNote] = useState('');
  const [remSaving, setRemSaving] = useState(false);
  const [remError, setRemError] = useState('');

  const load = async () => {
    setLoading(true); setError('');
    try {
      // Enriched exposures are returned ordered by risk_score (highest first).
      const data = await api<Exposure[]>('/vulnerabilities/exposures?limit=500');
      setExposures(data);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Exposure ma’lumotlarini yuklab bo‘lmadi.');
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const handleRemediation = async (exposure: Exposure, status: string) => {
    setRemSaving(true); setRemError('');
    try {
      const updated = await api<Exposure>(
        `/vulnerabilities/exposures/${exposure.id}/remediation`,
        { method: 'PATCH', body: JSON.stringify({ status, note: remNote }) },
      );
      setExposures((prev) => prev.map((x) => (x.id === exposure.id ? { ...x, ...updated } : x)));
      setSelected((prev) => (prev && prev.id === exposure.id ? { ...prev, ...updated } : prev));
    } catch (e: unknown) {
      setRemError(e instanceof Error ? e.message : 'Remediation holatini saqlab bo‘lmadi.');
    } finally { setRemSaving(false); }
  };

  const handleAIAnalyze = async (exposure: Exposure) => {
    setAiLoading(true); setAiError(''); setAiAnalysis(null);
    try {
      const result = await api<AIAnalysis>(
        `/vulnerabilities/${encodeURIComponent(exposure.cve_id)}/analyze?agent_id=${encodeURIComponent(exposure.agent_id)}`,
        { method: 'POST' },
      );
      setAiAnalysis(result);
    } catch (e: unknown) {
      setAiError(e instanceof Error ? e.message : 'AI vulnerability analysis failed.');
    } finally { setAiLoading(false); }
  };

  const agents = useMemo(
    () => ['ALL', ...Array.from(new Set(exposures.map((x) => x.agent_id))).sort()],
    [exposures],
  );

  const filtered = useMemo(() => {
    const needle = q.toLowerCase().trim();
    const floor = Number(minRisk);
    return exposures.filter((x) =>
      (agent === 'ALL' || x.agent_id === agent) &&
      (!kevOnly || x.known_exploited) &&
      x.risk_score >= floor &&
      (!needle || `${x.cve_id} ${x.agent_id} ${x.cve_summary}`.toLowerCase().includes(needle)),
    );
  }, [exposures, q, agent, minRisk, kevOnly]);

  const criticalCount = exposures.filter((x) => x.risk_score >= 90).length;
  const kevCount = exposures.filter((x) => x.known_exploited).length;
  const likelyExploited = exposures.filter((x) => (x.epss_score ?? 0) >= 0.5).length;
  const assetsAtRisk = new Set(exposures.filter((x) => x.risk_score >= 70).map((x) => x.agent_id)).size;

  return (
    <main className="page">
      <div className="eyebrow">EXPOSURE MANAGEMENT</div>
      <div className="page-header">
        <div>
          <h1>Exposure</h1>
          <p>4000 ta CVE emas — bugun aynan sizning aktivlaringizga tegishli, EPSS va CISA KEV bo‘yicha ustuvorlashtirilgan xavflar.</p>
        </div>
        <button className="refresh" onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Yangilash
        </button>
      </div>

      {error && <div className="api-warning">API Error: {error}</div>}

      <div className="stat-grid" style={{ marginBottom: 18 }}>
        <div className="stat-card"><div className="stat-label"><ShieldAlert size={14} /> Kritik exposure</div><strong>{criticalCount}</strong><small>Risk 90+ — darhol e’tibor talab qiladi</small></div>
        <div className="stat-card"><div className="stat-label"><Crosshair size={14} /> KEV ta’sirida</div><strong>{kevCount}</strong><small>Tabiatda faol ekspluatatsiya qilinmoqda</small></div>
        <div className="stat-card"><div className="stat-label"><Flame size={14} /> Ehtimoli yuqori</div><strong>{likelyExploited}</strong><small>EPSS ≥ 50% ekspluatatsiya ehtimoli</small></div>
        <div className="stat-card"><div className="stat-label"><AlertTriangle size={14} /> Xavfdagi aktivlar</div><strong>{assetsAtRisk}</strong><small>Risk 70+ bo‘lgan noyob aktivlar</small></div>
      </div>

      <div className="toolbar">
        <div className="search"><Search size={15} /><input placeholder="CVE, aktiv yoki tavsif bo‘yicha qidiring..." value={q} onChange={(e) => setQ(e.target.value)} /></div>
        <div className="select-wrap"><select value={agent} onChange={(e) => setAgent(e.target.value)}>{agents.map((a) => <option key={a} value={a}>{a === 'ALL' ? 'Barcha aktivlar' : a}</option>)}</select></div>
        <div className="select-wrap"><select value={minRisk} onChange={(e) => setMinRisk(e.target.value)}>{[['0','Istalgan risk'],['40','Risk ≥ 40'],['70','Risk ≥ 70'],['90','Risk ≥ 90']].map(([v,l]) => <option key={v} value={v}>{l}</option>)}</select></div>
        <button className={`refresh ${kevOnly ? 'active' : ''}`} onClick={() => setKevOnly((v) => !v)} style={kevOnly ? { borderColor: 'var(--red)', color: 'var(--red)' } : undefined}>
          <Crosshair size={14} /> {kevOnly ? 'Faqat KEV ✓' : 'Faqat KEV'}
        </button>
      </div>

      <div className="panel table-panel">
        <div className="table-meta">
          <span>{loading ? 'Loading…' : `${filtered.length} ta ustuvorlashtirilgan exposure`}</span>
          <span>{exposures.length} ta jami asset exposure</span>
        </div>
        <div className="table-scroll"><table>
          <thead><tr>
            <th>#</th><th>Risk</th><th>Aktiv</th><th>CVE</th><th>Severity</th>
            <th>CVSS</th><th>EPSS</th><th>Threat Intel</th><th>Status</th><th>Action</th>
          </tr></thead>
          <tbody>
            {filtered.map((x, index) => (
              <tr key={x.id} style={{ cursor: 'pointer' }} onClick={() => { setSelected(x); setAiAnalysis(null); setAiError(''); setRemNote(x.remediation_note || ''); setRemError(''); }}>
                <td className="mono">{index + 1}</td>
                <td><span className={`badge ${riskClass(x.risk_score)}`}>{x.risk_score}/100</span></td>
                <td><b>{x.agent_id}</b>{x.internet_exposed && <small style={{ color: 'var(--amber)' }}>internetga ochiq</small>}</td>
                <td><b className="mono">{x.cve_id}</b><small>{x.cve_summary.length > 90 ? `${x.cve_summary.slice(0, 90)}…` : x.cve_summary}</small></td>
                <td><span className={`badge ${(x.severity || 'unknown').toLowerCase()}`}>{x.severity || 'UNKNOWN'}</span></td>
                <td className="mono">{x.cvss_score ?? '—'}</td>
                <td className="mono" style={{ color: epssColor(x.epss_score), fontWeight: 600 }}>{fmtEpss(x.epss_score)}</td>
                <td><div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {x.active_threat && <span className="soon-badge" style={{ color: '#fff', background: 'var(--red)', borderColor: 'var(--red)' }}>⚡ FAOL HUJUM</span>}
                  {x.known_exploited && <span className="soon-badge" style={{ color: 'var(--red)' }}>CISA KEV</span>}
                  {x.exploit_available && <span className="soon-badge" style={{ color: 'var(--amber)' }}>EXPLOIT</span>}
                  {!x.known_exploited && !x.exploit_available && !x.active_threat && <span className="mono">—</span>}
                </div></td>
                <td><small>{x.status}</small><small style={{ color: remColor(x.remediation_status), fontWeight: 600 }}>{remLabel(x.remediation_status)}</small></td>
                <td><button className="refresh" onClick={(e) => { e.stopPropagation(); setSelected(x); setAiAnalysis(null); setAiError(''); setRemNote(x.remediation_note || ''); setRemError(''); }}>Ko‘rish</button></td>
              </tr>
            ))}
            {!loading && filtered.length === 0 && (
              <tr><td colSpan={10}><div className="empty">
                {exposures.length === 0
                  ? 'Hali exposure topilmadi. Avval CVE sync qiling va aktivlarni baholang (Vulnerability Center).'
                  : 'Filtrga mos exposure topilmadi.'}
              </div></td></tr>
            )}
          </tbody>
        </table></div>
      </div>

      {selected && (
        <div className="modal-overlay" onClick={() => setSelected(null)}>
          <div className="modal-box" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <div><h2>{selected.cve_id}</h2><p>{selected.agent_id} · ustuvor exposure</p></div>
              <button className="modal-close" onClick={() => setSelected(null)}><X size={18} /></button>
            </div>
            <div className="modal-grid">
              <div className="modal-field"><label>RISK SCORE</label><span className={`badge ${riskClass(selected.risk_score)}`}>{selected.risk_score}/100</span></div>
              <div className="modal-field"><label>CVSS</label><b>{selected.cvss_score ?? 'Unknown'}</b></div>
              <div className="modal-field"><label>EPSS (ekspluatatsiya ehtimoli)</label><b style={{ color: epssColor(selected.epss_score) }}>{fmtEpss(selected.epss_score)}{selected.epss_percentile != null && <small style={{ display: 'block', marginTop: 4 }}>{(selected.epss_percentile * 100).toFixed(1)}-persentil</small>}</b></div>
              <div className="modal-field"><label>CISA KEV</label><b style={{ color: selected.known_exploited ? 'var(--red)' : undefined }}>{selected.known_exploited ? 'HA — tabiatda ekspluatatsiya qilinmoqda' : 'Yo‘q'}</b></div>
              <div className="modal-field"><label>MATCH CONFIDENCE</label><b>{Math.round(selected.match_confidence * 100)}%</b></div>
              <div className="modal-field"><label>INTERNETGA OCHIQ</label><b>{selected.internet_exposed ? 'HA' : 'Yo‘q'}</b></div>
              <div className="modal-field"><label>FAOL HUJUM (honeypot)</label><b style={{ color: selected.active_threat ? 'var(--red)' : undefined }}>{selected.active_threat ? 'HA — honeypot shu xizmatga hujumni qayd etdi' : 'Yo‘q'}</b></div>
              <div className="modal-field full"><label>CVE XULOSA</label><b>{selected.cve_summary}</b></div>
              <div className="modal-field full"><label>MOS KELISH SABABI</label><small>{selected.rationale || '—'}</small></div>
              <div className="modal-field full"><label>MOS DASTUR</label><pre className="modal-code">{JSON.stringify(selected.matched_software || {}, null, 2)}</pre></div>

              <div className="modal-field full">
                <label>REMEDIATION HOLATI</label>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 8 }}>
                  {REMEDIATION.map((r) => (
                    <button
                      key={r.value}
                      className="refresh"
                      disabled={remSaving}
                      onClick={() => handleRemediation(selected, r.value)}
                      style={selected.remediation_status === r.value
                        ? { borderColor: r.color, color: r.color, fontWeight: 600 }
                        : undefined}
                    >
                      {selected.remediation_status === r.value ? '✓ ' : ''}{r.label}
                    </button>
                  ))}
                </div>
                <textarea
                  value={remNote}
                  onChange={(e) => setRemNote(e.target.value)}
                  placeholder="Izoh (ixtiyoriy) — masalan: patch rejalashtirildi, yoki biznes risk qabul qildi"
                  rows={2}
                  style={{ width: '100%', marginTop: 10, background: '#05090d', color: 'var(--text, #E9EFF7)', border: '1px solid #28374F', borderRadius: 8, padding: 10, fontSize: 14, fontFamily: 'inherit' }}
                />
                {selected.remediation_updated_by && (
                  <small style={{ display: 'block', marginTop: 6, color: 'var(--muted)' }}>
                    Oxirgi o‘zgartirgan: {selected.remediation_updated_by}
                  </small>
                )}
                {remError && <div className="api-warning" style={{ marginTop: 8 }}>{remError}</div>}
              </div>

              <div className="modal-field full">
                <button className="demo-attack-btn" onClick={() => handleAIAnalyze(selected)} disabled={aiLoading}>
                  {aiLoading ? <Loader2 size={14} className="animate-spin" /> : <Brain size={14} />} AI REMEDIATION TAHLILI
                </button>
              </div>

              {aiError && <div className="modal-field full"><div className="api-warning">AI Error: {aiError}</div></div>}
              {aiAnalysis && (
                <div className="modal-field full"><label>AI VULNERABILITY ANALYST</label>
                  <div className="rail-status-card" style={{ marginTop: 8 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'center' }}>
                      <div><b style={{ color: 'var(--cyan)' }}>{aiAnalysis.asset_id}</b><small style={{ display: 'block', marginTop: 4 }}>{aiAnalysis.affected_status} · {aiAnalysis.confidence_score}% confidence</small></div>
                      <span className={`badge ${riskClass(aiAnalysis.risk_score)}`}>{aiAnalysis.risk_score}/100</span>
                    </div>
                    <p style={{ lineHeight: 1.6, marginTop: 12 }}>{aiAnalysis.executive_summary}</p>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginTop: 12 }}>
                      <div><b style={{ fontSize: 11 }}>Risk omillari</b>{aiAnalysis.risk_factors.map((v, i) => <small key={i} style={{ display: 'block', marginTop: 6 }}>• {v}</small>)}</div>
                      <div><b style={{ fontSize: 11 }}>Remediation</b>{aiAnalysis.remediation_actions.map((v, i) => <small key={i} style={{ display: 'block', marginTop: 6 }}><span style={{ color: 'var(--cyan)' }}>{i + 1}.</span> {v}</small>)}</div>
                    </div>
                    <small style={{ display: 'block', marginTop: 12, color: 'var(--muted)' }}>{aiAnalysis.analyst_note}</small>
                  </div>
                </div>
              )}
            </div>
            <div className="modal-actions">
              <button className="btn-secondary" onClick={() => setSelected(null)}><CheckCircle2 size={14} /> Yopish</button>
            </div>
          </div>
        </div>
      )}

      {!loading && exposures.length > 0 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 14, color: 'var(--muted)', fontSize: 12 }}>
          <ShieldCheck size={14} /> Ro‘yxat risk = CVSS × EPSS × KEV formulasi bo‘yicha ustuvorlashtirilgan.
        </div>
      )}
    </main>
  );
}
