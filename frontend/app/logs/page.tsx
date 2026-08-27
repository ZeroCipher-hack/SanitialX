'use client';

import { useEffect, useState } from 'react';
import { RefreshCw, ScrollText } from 'lucide-react';
import { fetchEvents } from '@/lib/api';
import type { SecurityEvent } from '@/types/api';

export default function LogsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true); setError('');
    try { setEvents(await fetchEvents()); } catch (e) { setError(e instanceof Error ? e.message : 'Loglarni yuklab bo‘lmadi'); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  return <main className="page">
    <div className="eyebrow">MONITORING / LOGS</div>
    <div className="page-header"><div><h1>Tizim loglari</h1><p>Security telemetry va hodisalar oqimini kuzatish.</p></div><button className="refresh" onClick={load} disabled={loading}><RefreshCw size={14} className={loading ? 'animate-spin' : ''}/> Yangilash</button></div>
    {error && <div className="api-warning">API xatosi: {error}</div>}
    <section className="panel" style={{padding:0,overflow:'hidden'}}>
      <div className="table-meta"><span><ScrollText size={13}/> EVENT TELEMETRY</span><span>{events.length} ta yozuv</span></div>
      {events.length === 0 && !loading ? <div className="empty">Hozircha log/hodisa topilmadi.</div> : events.map((event, i) => <div className="log-line" key={event.event_id || i}>
        <span className="log-time">{String(event.timestamp || '').replace('T',' ').slice(0,19)}</span>
        <span className="log-level">{event.severity || 'INFO'}</span>
        <span className="log-message">{event.event_type || event.description || JSON.stringify(event)}</span>
      </div>)}
    </section>
    <div className="guide-card" style={{marginTop:12}}><h3>Izoh</h3><p>Bu sahifa hozirgi <code>/events</code> telemetry oqimini log ko‘rinishida beradi. Keyingi backend bosqichida Django application/security loglarini alohida saqlash va qidirish pipeline'i qo‘shiladi.</p></div>
  </main>;
}
