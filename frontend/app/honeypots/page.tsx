'use client';

import { useEffect, useMemo, useState } from 'react';
import { RefreshCw, ShieldAlert, Crosshair, Flame, Users } from 'lucide-react';
import { fetchHoneypots } from '@/lib/api';
import type { HoneypotSession } from '@/types/api';

function isRecent(iso: string, hours = 24): boolean {
  const t = new Date(iso).getTime();
  return Number.isFinite(t) && Date.now() - t <= hours * 3600 * 1000;
}

export default function HoneypotsPage() {
  const [sessions, setSessions] = useState<HoneypotSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = () => {
    setLoading(true);
    setError('');
    fetchHoneypots()
      .then(setSessions)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const stats = useMemo(() => {
    const uniqueIps = new Set(sessions.map((s) => s.attacker_ip)).size;
    const services = new Set(sessions.map((s) => s.service)).size;
    const maxRisk = sessions.reduce((m, s) => Math.max(m, s.risk_score), 0);
    const activeServices = Array.from(
      new Set(sessions.filter((s) => isRecent(s.started_at)).map((s) => s.service)),
    );
    return { uniqueIps, services, maxRisk, activeServices };
  }, [sessions]);

  return (
    <main className="page">
      <div className="eyebrow">DECEPTION · LOKAL HUJUM SIGNALI</div>
      <div className="page-header">
        <div>
          <h1>Honeypot markazi</h1>
          <p>Tirik dekoylar tutgan hujum urinishlari. Oxirgi 24 soatdagi faollik Exposure’da aynan shu xizmatning riskini oshiradi.</p>
        </div>
        <button className="refresh" onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Yangilash
        </button>
      </div>

      {error && <div className="api-warning">API Warning: {error}</div>}

      <div className="stat-grid" style={{ marginBottom: 18 }}>
        <div className="stat-card"><div className="stat-label"><Crosshair size={14} /> Tutilgan sessiyalar</div><strong>{sessions.length}</strong><small>Jami qayd etilgan hujum urinishlari</small></div>
        <div className="stat-card"><div className="stat-label"><Users size={14} /> Noyob hujumchilar</div><strong>{stats.uniqueIps}</strong><small>Turli manba IP manzillari</small></div>
        <div className="stat-card"><div className="stat-label"><Flame size={14} /> Hujumdagi xizmatlar</div><strong>{stats.services}</strong><small>Hit olgan dekoy xizmatlar</small></div>
        <div className="stat-card"><div className="stat-label"><ShieldAlert size={14} /> Eng yuqori risk</div><strong>{stats.maxRisk}/100</strong><small>Eng xavfli sessiya bahosi</small></div>
      </div>

      <div className="panel" style={{ padding: 20, marginBottom: 18 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <Flame size={16} style={{ color: 'var(--red)' }} />
          <b style={{ fontSize: 15 }}>Faol hujum (oxirgi 24 soat)</b>
        </div>
        {stats.activeServices.length === 0 ? (
          <p style={{ margin: 0, color: '#688290', fontSize: 13 }}>Oxirgi 24 soatda dekoylarga hujum qayd etilmadi.</p>
        ) : (
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {stats.activeServices.map((svc) => (
              <span key={svc} className="soon-badge" style={{ color: '#fff', background: 'var(--red)', borderColor: 'var(--red)' }}>⚡ {svc}</span>
            ))}
          </div>
        )}
        <small style={{ display: 'block', marginTop: 10, color: '#688290' }}>
          Bu xizmatlardagi exposure’lar Exposure ekranida “FAOL HUJUM” sifatida belgilanadi va risk skori oshiriladi.
        </small>
      </div>

      <div className="panel table-panel">
        <div className="table-meta">
          <span>{loading ? 'Yuklanmoqda…' : `${sessions.length} ta tutilgan sessiya`}</span>
          <span>Deception telemetriya oqimi</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Hujumchi IP</th>
                <th>Xizmat</th>
                <th>Urinilgan parollar</th>
                <th>Qayd etilgan kirish</th>
                <th>Davomiylik</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.session_id}>
                  <td className="mono">
                    <b style={{ color: '#ff4a4a' }}>{s.attacker_ip}</b>
                    <small>{s.session_id.slice(0, 18)}</small>
                  </td>
                  <td>
                    <b>{s.service}</b>
                    <small>{new Date(s.started_at).toLocaleString()}</small>
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {s.credentials_attempted.length === 0 && <span className="mono" style={{ fontSize: 10, color: '#688290' }}>—</span>}
                      {s.credentials_attempted.map((c, i) => (
                        <span key={i} className="mono" style={{ background: '#05090d', border: '1px solid #1c2e39', padding: '1px 5px', borderRadius: 3, fontSize: '10px' }}>
                          {c}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td>
                    <div className="mono" style={{ fontSize: '11px', color: '#00e5ff' }}>
                      {s.commands_executed.slice(0, 3).join('; ')}
                      {s.commands_executed.length > 3 && '…'}
                      {s.commands_executed.length === 0 && <span style={{ color: '#688290' }}>—</span>}
                    </div>
                  </td>
                  <td className="mono">{s.duration_seconds}s</td>
                  <td>
                    <span className="badge critical">{s.risk_score}/100</span>
                  </td>
                </tr>
              ))}
              {!loading && sessions.length === 0 && (
                <tr>
                  <td colSpan={6}>
                    <div className="empty">Hali honeypot sessiyasi yo‘q. Dekoyni ishga tushiring (docker compose --profile honeypot up) yoki hujum simulyatsiyasini bajaring.</div>
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
