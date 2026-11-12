'use client';

import { useEffect, useMemo, useState } from 'react';
import { RefreshCw, ScrollText, Brain, Loader2, AlertTriangle } from 'lucide-react';
import { api, fetchEvents } from '@/lib/api';
import type { SecurityEvent } from '@/types/api';

type LogAlert = { line: string; severity: string; reason: string };
type LogAnalysis = {
  mode: string;
  summary: string;
  overall_severity: string;
  alerts: LogAlert[];
  recommended_actions: string[];
  analyzed_lines: number;
};

function sevColor(sev: string): string {
  const s = (sev || '').toUpperCase();
  if (s === 'CRITICAL') return 'var(--red)';
  if (s === 'HIGH') return 'var(--red)';
  if (s === 'MEDIUM') return 'var(--amber)';
  return 'var(--muted)';
}

export default function LogsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [analysis, setAnalysis] = useState<LogAnalysis | null>(null);
  const [aiError, setAiError] = useState('');

  const load = async () => {
    setLoading(true); setError('');
    try { setEvents(await fetchEvents()); } catch (e) { setError(e instanceof Error ? e.message : 'Loglarni yuklab bo‘lmadi'); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const logText = useMemo(
    () => events.map((e) =>
      `${String(e.timestamp || '').replace('T', ' ').slice(0, 19)} ${e.severity || 'INFO'} ${e.event_type || ''} ${e.source_ip || ''} ${e.details || ''}`.trim(),
    ).join('\n'),
    [events],
  );

  const analyze = async () => {
    if (!logText.trim()) { setAiError('Tahlil qilish uchun log yo‘q.'); return; }
    setAnalyzing(true); setAiError(''); setAnalysis(null);
    try {
      setAnalysis(await api<LogAnalysis>('/logs/analyze', { method: 'POST', body: JSON.stringify({ logs: logText.slice(0, 20000) }) }));
    } catch (e: unknown) {
      setAiError(e instanceof Error ? e.message : 'AI log tahlili bajarilmadi.');
    } finally { setAnalyzing(false); }
  };

  return (
    <main className="page">
      <div className="eyebrow">MONITORING / LOGS</div>
      <div className="page-header">
        <div><h1>Tizim loglari</h1><p>Telemetriya oqimini kuzating va AI bilan izohlab, alert qatorlarini aniqlang.</p></div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="refresh" onClick={load} disabled={loading}><RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Yangilash</button>
          <button className="demo-attack-btn" onClick={analyze} disabled={analyzing || loading}>
            {analyzing ? <Loader2 size={14} className="animate-spin" /> : <Brain size={14} />} AI bilan izohlash
          </button>
        </div>
      </div>

      {error && <div className="api-warning">API xatosi: {error}</div>}
      {aiError && <div className="api-warning">AI xatosi: {aiError}</div>}

      {analysis && (
        <div className="panel" style={{ padding: 20, marginBottom: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Brain size={16} style={{ color: 'var(--cyan)' }} />
              <b style={{ fontSize: 15 }}>AI log triage</b>
              <span className="soon-badge">{analysis.mode === 'AI' ? 'Gemini' : 'Keyword fallback'}</span>
            </div>
            <span className="badge" style={{ color: sevColor(analysis.overall_severity), borderColor: sevColor(analysis.overall_severity) }}>
              {analysis.overall_severity}
            </span>
          </div>
          <p style={{ lineHeight: 1.6, marginTop: 12 }}>{analysis.summary}</p>
          <small style={{ color: 'var(--muted)' }}>{analysis.analyzed_lines} ta qator tahlil qilindi · {analysis.alerts.length} ta alert</small>

          {analysis.alerts.length > 0 && (
            <div style={{ marginTop: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
              {analysis.alerts.map((a, i) => (
                <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'flex-start', background: '#05090d', border: '1px solid #1c2e39', borderRadius: 8, padding: '10px 12px' }}>
                  <AlertTriangle size={16} style={{ color: sevColor(a.severity), flexShrink: 0, marginTop: 2 }} />
                  <div style={{ minWidth: 0 }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <span style={{ color: sevColor(a.severity), fontWeight: 600, fontSize: 12 }}>{a.severity}</span>
                      <span style={{ fontSize: 13 }}>{a.reason}</span>
                    </div>
                    <div className="mono" style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4, wordBreak: 'break-all' }}>{a.line}</div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {analysis.recommended_actions.length > 0 && (
            <div style={{ marginTop: 14 }}>
              <b style={{ fontSize: 12 }}>Tavsiyalar</b>
              {analysis.recommended_actions.map((r, i) => (
                <small key={i} style={{ display: 'block', marginTop: 6 }}><span style={{ color: 'var(--cyan)' }}>{i + 1}.</span> {r}</small>
              ))}
            </div>
          )}
        </div>
      )}

      <section className="panel" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="table-meta"><span><ScrollText size={13} /> EVENT TELEMETRY</span><span>{events.length} ta yozuv</span></div>
        {events.length === 0 && !loading ? <div className="empty">Hozircha log/hodisa topilmadi.</div> : events.map((event, i) => (
          <div className="log-line" key={event.event_id || i}>
            <span className="log-time">{String(event.timestamp || '').replace('T', ' ').slice(0, 19)}</span>
            <span className="log-level">{event.severity || 'INFO'}</span>
            <span className="log-message">{event.event_type || event.details || JSON.stringify(event)}</span>
          </div>
        ))}
      </section>
    </main>
  );
}
