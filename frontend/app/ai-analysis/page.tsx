'use client';

import { useEffect, useState } from 'react';
import { Brain, RefreshCw, CheckCircle2, AlertTriangle, ShieldCheck, ArrowRight } from 'lucide-react';
import { api, fetchReportDetail } from '@/lib/api';
import type { Incident, InvestigationReport } from '@/types/api';
import { useRouter } from 'next/navigation';

export default function AIAnalysisPage() {
  const router = useRouter();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncId, setSelectedIncId] = useState<string>('');
  const [report, setReport] = useState<InvestigationReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    api<Incident[]>('/incidents?limit=20')
      .then((data) => {
        setIncidents(data);
        if (data.length > 0) {
          setSelectedIncId(data[0].incident_id);
        }
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!selectedIncId) return;
    setLoading(true);
    fetchReportDetail(selectedIncId)
      .then(setReport)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [selectedIncId]);

  return (
    <main className="page">
      <div className="eyebrow">AI SECURITY REASONING</div>
      <div className="page-header">
        <div>
          <h1>AI Incident Analysis</h1>
          <p>Automated threat intelligence, attack pattern reasoning, and risk calculation derived from telemetry.</p>
        </div>
        <select
          value={selectedIncId}
          onChange={(e) => setSelectedIncId(e.target.value)}
          style={{
            background: '#05090d',
            border: '1px solid #1c2e39',
            padding: '6px 12px',
            color: '#00e5ff',
            borderRadius: '6px',
            fontSize: '12px',
            fontWeight: 'bold',
          }}
        >
          {incidents.map((inc) => (
            <option key={inc.incident_id} value={inc.incident_id}>
              {inc.incident_id} — {inc.title.substring(0, 30)}
            </option>
          ))}
        </select>
      </div>

      {error && <div className="api-warning">AI Analysis Error: {error}</div>}

      {report && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Risk Score & Executive Summary */}
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 20 }}>
            <div className="panel" style={{ padding: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12, color: '#00e5ff' }}>
                <Brain size={20} />
                <h2 style={{ fontSize: '16px', margin: 0 }}>Executive AI Summary</h2>
              </div>
              <p style={{ color: '#dce8ec', fontSize: '13px', lineHeight: 1.6, margin: 0 }}>
                {report.executive_summary}
              </p>
            </div>

            <div className="panel" style={{ padding: 20, textAlign: 'center', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <span style={{ fontSize: '11px', color: '#688290' }}>OVERALL CALCULATED RISK</span>
              <div style={{ fontSize: '42px', fontWeight: 'bold', color: '#ff4a4a', margin: '6px 0' }}>
                {report.overall_risk_score}/100
              </div>
              <span className={`badge ${report.severity.toLowerCase()}`} style={{ margin: '0 auto' }}>
                {report.severity} RISK SCORE
              </span>
            </div>
          </div>

          {/* Initial Access & Techniques */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
            <div className="panel" style={{ padding: 20 }}>
              <h3 style={{ margin: '0 0 12px', fontSize: '14px', color: '#fff' }}>Initial Access Vector</h3>
              <div style={{ background: '#05090d', border: '1px solid #1c2e39', padding: 14, borderRadius: 6, color: '#dce8ec', fontSize: '12px' }}>
                {report.initial_access_vector}
              </div>

              <h3 style={{ margin: '16px 0 12px', fontSize: '14px', color: '#fff' }}>Honeypot Engagement</h3>
              <div style={{ background: '#05090d', border: '1px solid #1c2e39', padding: 14, borderRadius: 6, color: '#ffb703', fontSize: '12px' }}>
                {report.honeypot_engagement}
              </div>
            </div>

            <div className="panel" style={{ padding: 20 }}>
              <h3 style={{ margin: '0 0 12px', fontSize: '14px', color: '#fff' }}>Observed MITRE ATT&CK Techniques</h3>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {report.observed_techniques.map((tech, i) => (
                  <span key={i} className="mono" style={{ background: '#00e5ff12', border: '1px solid #00e5ff44', color: '#00e5ff', padding: '6px 10px', borderRadius: 6, fontSize: '11px' }}>
                    {tech}
                  </span>
                ))}
              </div>

              <h3 style={{ margin: '20px 0 12px', fontSize: '14px', color: '#fff' }}>Affected Environment Assets</h3>
              <ul style={{ margin: 0, paddingLeft: 18, color: '#9eb4bf', fontSize: '12px' }}>
                {report.affected_assets.map((asset, i) => (
                  <li key={i} style={{ marginBottom: 4 }}>
                    <b style={{ color: '#fff' }}>{asset}</b>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Remediation Actions */}
          <div className="panel" style={{ padding: 20 }}>
            <h3 style={{ margin: '0 0 14px', fontSize: '15px', color: '#fff', display: 'flex', alignItems: 'center', gap: 8 }}>
              <ShieldCheck size={18} color="#00e5ff" /> AI Prioritized Remediation Plan
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {report.recommended_actions.map((act, i) => (
                <div key={i} style={{ background: '#05090d', border: '1px solid #1c2e39', padding: '12px 16px', borderRadius: 6, color: '#dce8ec', fontSize: '13px' }}>
                  {act}
                </div>
              ))}
            </div>

            <div style={{ marginTop: 18, display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn-primary" onClick={() => router.push(`/reports?id=${report.incident_id}`)}>
                Generate Full Investigation PDF Report <ArrowRight size={14} />
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
