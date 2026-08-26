'use client';

import { useEffect, useState } from 'react';
import { FileText, Download, Printer, RefreshCw, Shield, AlertTriangle, CheckCircle2, ArrowRight } from 'lucide-react';
import { api, fetchReportDetail, fetchReports } from '@/lib/api';
import type { InvestigationReport } from '@/types/api';

export default function ReportsPage() {
  const [reportsList, setReportsList] = useState<InvestigationReport[]>([]);
  const [selectedIncId, setSelectedIncId] = useState<string>('');
  const [report, setReport] = useState<InvestigationReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchReports()
      .then((data) => {
        setReportsList(data);
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

  const handleExportPDF = () => {
    window.print();
  };

  const handleExportJSON = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SanitialX_Report_${report.incident_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <main className="page">
      <div className="eyebrow">AUTOMATED REPORTS</div>
      <div className="page-header">
        <div>
          <h1>Incident Investigation Reports</h1>
          <p>Professional automated security investigation reports for management, SOC analysts, and audit compliance.</p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
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
            {reportsList.map((rep) => (
              <option key={rep.incident_id} value={rep.incident_id}>
                {rep.report_id} — {rep.title.substring(0, 30)}
              </option>
            ))}
          </select>
          <button onClick={handleExportJSON} className="refresh" style={{ padding: '6px 12px' }}>
            <Download size={14} /> JSON Export
          </button>
          <button onClick={handleExportPDF} className="btn-primary" style={{ padding: '6px 14px' }}>
            <Printer size={14} /> Export PDF / Print
          </button>
        </div>
      </div>

      {error && <div className="api-warning">Report Error: {error}</div>}

      {report && (
        <div className="report-paper panel" style={{ padding: 32, background: '#05090d', border: '1px solid #1c2e39' }}>
          {/* Header */}
          <div style={{ borderBottom: '2px solid #00e5ff', paddingBottom: 20, marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ fontSize: '11px', letterSpacing: '1.5px', color: '#00e5ff', fontWeight: 'bold' }}>
                SANITIALX CYBER RANGE & SIEM • INVESTIGATION REPORT
              </div>
              <h1 style={{ margin: '8px 0 4px', fontSize: '22px', color: '#fff' }}>{report.title}</h1>
              <span className="mono" style={{ fontSize: '12px', color: '#688290' }}>
                Report ID: {report.report_id} • Incident: {report.incident_id}
              </span>
            </div>
            <div style={{ textAlign: 'right' }}>
              <span className={`badge ${report.severity.toLowerCase()}`} style={{ fontSize: '12px', padding: '6px 12px' }}>
                {report.severity} SEVERITY
              </span>
              <div className="mono" style={{ fontSize: '11px', color: '#9eb4bf', marginTop: 6 }}>
                Generated: {new Date(report.created_at).toLocaleString()}
              </div>
            </div>
          </div>

          {/* Key Metrics Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginBottom: 24 }}>
            <div style={{ background: '#081017', border: '1px solid #1c2e39', padding: 14, borderRadius: 6 }}>
              <span style={{ fontSize: '10px', color: '#688290' }}>INITIAL ATTACK SOURCE</span>
              <div className="mono" style={{ fontSize: '14px', fontWeight: 'bold', color: '#ff4a4a', marginTop: 4 }}>
                {report.source_ip || '10.0.0.21'}
              </div>
            </div>
            <div style={{ background: '#081017', border: '1px solid #1c2e39', padding: 14, borderRadius: 6 }}>
              <span style={{ fontSize: '10px', color: '#688290' }}>PRIMARY TARGET HOST</span>
              <div className="mono" style={{ fontSize: '14px', fontWeight: 'bold', color: '#00e5ff', marginTop: 4 }}>
                {report.destination_ip || '10.0.0.50'}
              </div>
            </div>
            <div style={{ background: '#081017', border: '1px solid #1c2e39', padding: 14, borderRadius: 6 }}>
              <span style={{ fontSize: '10px', color: '#688290' }}>OVERALL RISK INDEX</span>
              <div className="mono" style={{ fontSize: '14px', fontWeight: 'bold', color: '#ffb703', marginTop: 4 }}>
                {report.overall_risk_score} / 100
              </div>
            </div>
            <div style={{ background: '#081017', border: '1px solid #1c2e39', padding: 14, borderRadius: 6 }}>
              <span style={{ fontSize: '10px', color: '#688290' }}>HONEYPOT TRAPPED</span>
              <div className="mono" style={{ fontSize: '14px', fontWeight: 'bold', color: '#00e5ff', marginTop: 4 }}>
                YES (SSH Vault)
              </div>
            </div>
          </div>

          {/* Executive Summary */}
          <section style={{ marginBottom: 24 }}>
            <h2 style={{ fontSize: '15px', color: '#00e5ff', borderBottom: '1px solid #1c2e39', paddingBottom: 6 }}>
              1. Executive Summary
            </h2>
            <p style={{ color: '#dce8ec', fontSize: '13px', lineHeight: 1.6 }}>{report.executive_summary}</p>
          </section>

          {/* Initial Access Vector */}
          <section style={{ marginBottom: 24 }}>
            <h2 style={{ fontSize: '15px', color: '#00e5ff', borderBottom: '1px solid #1c2e39', paddingBottom: 6 }}>
              2. Initial Access Vector & Method
            </h2>
            <div style={{ background: '#081017', border: '1px solid #1c2e39', padding: 14, borderRadius: 6, color: '#dce8ec', fontSize: '12px' }}>
              {report.initial_access_vector}
            </div>
          </section>

          {/* MITRE Techniques & Affected Assets */}
          <section style={{ marginBottom: 24, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
            <div>
              <h2 style={{ fontSize: '15px', color: '#00e5ff', borderBottom: '1px solid #1c2e39', paddingBottom: 6 }}>
                3. MITRE ATT&CK Mapping
              </h2>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {report.observed_techniques.map((t, i) => (
                  <span key={i} className="mono" style={{ background: '#00e5ff12', border: '1px solid #00e5ff33', color: '#00e5ff', padding: '4px 8px', borderRadius: 4, fontSize: '11px' }}>
                    {t}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <h2 style={{ fontSize: '15px', color: '#00e5ff', borderBottom: '1px solid #1c2e39', paddingBottom: 6 }}>
                4. Affected Assets & Telemetry Nodes
              </h2>
              <ul style={{ margin: 0, paddingLeft: 18, color: '#dce8ec', fontSize: '12px' }}>
                {report.affected_assets.map((a, i) => (
                  <li key={i} style={{ marginBottom: 4 }}>
                    <b>{a}</b>
                  </li>
                ))}
              </ul>
            </div>
          </section>

          {/* Honeypot & Data Access */}
          <section style={{ marginBottom: 24, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
            <div>
              <h2 style={{ fontSize: '15px', color: '#00e5ff', borderBottom: '1px solid #1c2e39', paddingBottom: 6 }}>
                5. Deception & Honeypot Trap
              </h2>
              <div style={{ background: '#081017', border: '1px solid #1c2e39', padding: 12, borderRadius: 6, color: '#ffb703', fontSize: '12px' }}>
                {report.honeypot_engagement}
              </div>
            </div>
            <div>
              <h2 style={{ fontSize: '15px', color: '#00e5ff', borderBottom: '1px solid #1c2e39', paddingBottom: 6 }}>
                6. Simulated Data Access & Exfiltration
              </h2>
              <div style={{ background: '#081017', border: '1px solid #1c2e39', padding: 12, borderRadius: 6, color: '#dce8ec', fontSize: '12px' }}>
                {report.simulated_data_loss}
              </div>
            </div>
          </section>

          {/* Recommended Actions */}
          <section>
            <h2 style={{ fontSize: '15px', color: '#00e5ff', borderBottom: '1px solid #1c2e39', paddingBottom: 6 }}>
              7. Prioritized Remediation Plan
            </h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {report.recommended_actions.map((act, i) => (
                <div key={i} style={{ background: '#081017', border: '1px solid #1c2e39', padding: '10px 14px', borderRadius: 6, color: '#dce8ec', fontSize: '12px' }}>
                  {act}
                </div>
              ))}
            </div>
          </section>
        </div>
      )}
    </main>
  );
}
