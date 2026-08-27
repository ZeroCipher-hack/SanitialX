'use client';

import { useEffect, useState } from 'react';
import { AlertTriangle, ArrowRight, Brain, CheckCircle2, RefreshCw, ShieldCheck } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { api, fetchReportDetail } from '@/lib/api';
import type { Incident, InvestigationReport } from '@/types/api';

const panelStyle = {
  background: 'linear-gradient(145deg,#0c151e,#080e15)',
  border: '1px solid #1c2e39',
  borderRadius: 10,
  padding: 18,
};

const innerStyle = {
  background: '#05090d',
  border: '1px solid #1c2e39',
  borderRadius: 7,
  padding: 12,
};

export default function AIAnalysisPage() {
  const router = useRouter();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncId, setSelectedIncId] = useState('');
  const [report, setReport] = useState<InvestigationReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadReport = async (incidentId: string) => {
    if (!incidentId) return;
    setLoading(true);
    setError('');
    try {
      setReport(await fetchReportDetail(incidentId));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'AI analysis failed');
      setReport(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    api<Incident[]>('/incidents?limit=20')
      .then((data) => {
        setIncidents(data);
        if (data.length > 0) setSelectedIncId(data[0].incident_id);
      })
      .catch((e) => setError(e instanceof Error ? e.message : 'Failed to load incidents'))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (selectedIncId) loadReport(selectedIncId);
  }, [selectedIncId]);

  return (
    <main className="page">
      <div className="eyebrow">AI SECURITY REASONING</div>
      <div className="page-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
            <h1 style={{ marginBottom: 4 }}>AI Incident Analysis</h1>
            <span className="badge" style={{ color: '#45e0a2', borderColor: '#45e0a244' }}>
              GEMINI LIVE
            </span>
          </div>
          <p>Evidence-backed incident reasoning, risk scoring and remediation generated from SanitialX telemetry.</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <select
            value={selectedIncId}
            onChange={(e) => setSelectedIncId(e.target.value)}
            style={{ background: '#05090d', border: '1px solid #1c2e39', padding: '8px 12px', color: '#00e5ff', borderRadius: 6, fontSize: 12, fontWeight: 'bold', maxWidth: 420 }}
          >
            {incidents.map((inc) => (
              <option key={inc.incident_id} value={inc.incident_id}>
                {inc.incident_id} — {inc.title.substring(0, 42)}
              </option>
            ))}
          </select>
          <button className="btn-secondary" onClick={() => loadReport(selectedIncId)} disabled={loading || !selectedIncId} title="Run Gemini analysis again">
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
          </button>
        </div>
      </div>

      {error && (
        <div className="api-warning" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <AlertTriangle size={15} /> {error}
        </div>
      )}

      {loading && (
        <div className="panel" style={{ ...panelStyle, display: 'flex', alignItems: 'center', gap: 12, minHeight: 120 }}>
          <RefreshCw size={18} className="spin" color="#00e5ff" />
          <div>
            <b style={{ color: '#dce8ec', fontSize: 13 }}>Gemini is analyzing the incident…</b>
            <p style={{ margin: '4px 0 0', color: '#688290', fontSize: 11 }}>The model is constrained to the telemetry supplied by SanitialX.</p>
          </div>
        </div>
      )}

      {!loading && !report && !error && (
        <div className="panel" style={panelStyle}>No incidents are available for AI analysis.</div>
      )}

      {report && !loading && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr', gap: 14 }}>
            <section style={panelStyle}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, color: '#00e5ff' }}>
                <Brain size={18} />
                <h2 style={{ fontSize: 14, margin: 0 }}>Executive AI Summary</h2>
              </div>
              <p style={{ color: '#dce8ec', fontSize: 12, lineHeight: 1.65, margin: 0 }}>{report.executive_summary}</p>
            </section>

            <section style={{ ...panelStyle, textAlign: 'center', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <span style={{ fontSize: 9, color: '#688290', letterSpacing: 1 }}>RISK SCORE</span>
              <div style={{ fontSize: 38, fontWeight: 800, color: report.overall_risk_score >= 75 ? '#ff4a4a' : report.overall_risk_score >= 45 ? '#ffb703' : '#45e0a2', margin: '5px 0' }}>
                {report.overall_risk_score}<small style={{ fontSize: 14 }}>/100</small>
              </div>
              <span className={`badge ${report.severity.toLowerCase()}`} style={{ margin: '0 auto' }}>{report.severity}</span>
            </section>

            <section style={panelStyle}>
              <span style={{ fontSize: 9, color: '#688290', letterSpacing: 1 }}>THREAT ASSESSMENT</span>
              <div style={{ marginTop: 9, color: '#fff', fontWeight: 700, fontSize: 14 }}>{report.threat_classification}</div>
              <div style={{ marginTop: 12, height: 5, background: '#14232d', borderRadius: 8, overflow: 'hidden' }}>
                <div style={{ width: `${report.confidence_score}%`, height: '100%', background: '#00e5ff' }} />
              </div>
              <div style={{ marginTop: 5, font: '9px DM Mono', color: '#688290' }}>{report.confidence_score}% confidence</div>
            </section>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <section style={panelStyle}>
              <h3 style={{ margin: '0 0 10px', fontSize: 13, color: '#fff' }}>Key Findings</h3>
              {report.key_findings.length > 0 ? report.key_findings.map((item, i) => (
                <div key={i} style={{ ...innerStyle, marginTop: i ? 7 : 0, color: '#c5d4da', fontSize: 11, lineHeight: 1.55 }}>
                  <CheckCircle2 size={13} color="#45e0a2" style={{ verticalAlign: 'middle', marginRight: 7 }} />{item}
                </div>
              )) : <div style={{ ...innerStyle, color: '#688290', fontSize: 11 }}>No additional findings returned.</div>}
            </section>

            <section style={panelStyle}>
              <h3 style={{ margin: '0 0 10px', fontSize: 13, color: '#fff' }}>Indicators of Compromise</h3>
              {report.indicators_of_compromise.length > 0 ? report.indicators_of_compromise.map((ioc, i) => (
                <div key={i} className="mono" style={{ ...innerStyle, marginTop: i ? 7 : 0, color: '#00e5ff', fontSize: 11 }}>{ioc}</div>
              )) : <div style={{ ...innerStyle, color: '#688290', fontSize: 11 }}>No IOC was confidently extracted from the available telemetry.</div>}
            </section>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <section style={panelStyle}>
              <h3 style={{ margin: '0 0 10px', fontSize: 13, color: '#fff' }}>Attack Assessment</h3>
              <div style={{ ...innerStyle, marginBottom: 9 }}><span style={{ color: '#688290', fontSize: 9 }}>INITIAL ACCESS</span><div style={{ color: '#dce8ec', fontSize: 11, marginTop: 5 }}>{report.initial_access_vector}</div></div>
              <div style={{ ...innerStyle, marginBottom: 9 }}><span style={{ color: '#688290', fontSize: 9 }}>HONEYPOT</span><div style={{ color: '#ffb703', fontSize: 11, marginTop: 5 }}>{report.honeypot_engagement}</div></div>
              <div style={{ ...innerStyle }}><span style={{ color: '#688290', fontSize: 9 }}>SIMULATED IMPACT</span><div style={{ color: '#dce8ec', fontSize: 11, marginTop: 5 }}>{report.simulated_data_loss}</div></div>
            </section>

            <section style={panelStyle}>
              <h3 style={{ margin: '0 0 10px', fontSize: 13, color: '#fff' }}>MITRE ATT&CK & Assets</h3>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {report.observed_techniques.map((tech, i) => <span key={i} className="mono" style={{ background: '#00e5ff12', border: '1px solid #00e5ff44', color: '#00e5ff', padding: '5px 8px', borderRadius: 5, fontSize: 10 }}>{tech}</span>)}
                {report.observed_techniques.length === 0 && <span style={{ color: '#688290', fontSize: 11 }}>No technique confidently mapped.</span>}
              </div>
              <div style={{ marginTop: 14, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {report.affected_assets.map((asset, i) => <span key={i} style={{ background: '#0b151d', border: '1px solid #213640', color: '#c5d4da', padding: '5px 8px', borderRadius: 5, fontSize: 10 }}>{asset}</span>)}
              </div>
            </section>
          </div>

          <section style={panelStyle}>
            <h3 style={{ margin: '0 0 10px', fontSize: 13, color: '#fff', display: 'flex', alignItems: 'center', gap: 7 }}>
              <ShieldCheck size={16} color="#00e5ff" /> AI Prioritized Remediation
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {report.recommended_actions.map((action, i) => (
                <div key={i} style={{ ...innerStyle, color: '#dce8ec', fontSize: 11, lineHeight: 1.55 }}><b style={{ color: '#00e5ff', marginRight: 6 }}>{String(i + 1).padStart(2, '0')}</b>{action}</div>
              ))}
            </div>
            <div style={{ marginTop: 14, display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn-primary" onClick={() => router.push(`/reports?id=${report.incident_id}`)}>
                Open Investigation Report <ArrowRight size={14} />
              </button>
            </div>
          </section>
        </div>
      )}
    </main>
  );
}
