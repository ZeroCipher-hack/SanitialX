'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { Download, LifeBuoy, Send } from 'lucide-react';
import { api } from '@/lib/api';
import { currentRole } from '@/lib/session';

type Ticket = {
  id: number; category: 'QUESTION' | 'BUG' | 'FEATURE'; subject: string; message: string;
  status: 'OPEN' | 'ANSWERED' | 'CLOSED'; created_by: string; vendor_reply: string | null; created_at: string;
};

const CATEGORY: Record<Ticket['category'], string> = { QUESTION: 'Savol', BUG: 'Kamchilik', FEATURE: 'Taklif' };
const STATUS: Record<Ticket['status'], string> = { OPEN: 'Ochiq', ANSWERED: 'Javob berilgan', CLOSED: 'Yopilgan' };

export default function SupportPage() {
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [category, setCategory] = useState<Ticket['category']>('QUESTION');
  const [subject, setSubject] = useState('');
  const [message, setMessage] = useState('');
  const [replies, setReplies] = useState<Record<number, string>>({});
  const [error, setError] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);

  const load = useCallback(() => {
    api<Ticket[]>('/support/tickets').then(setTickets).catch((e) => setError(e.message));
  }, []);

  useEffect(() => { setIsAdmin(currentRole() === 'admin'); load(); }, [load]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError('');
    try {
      await api('/support/tickets', { method: 'POST', body: JSON.stringify({ category, subject, message }) });
      setSubject(''); setMessage('');
      load();
    } catch (err) { setError(err instanceof Error ? err.message : 'Yuborib bo‘lmadi'); }
  }

  async function act(path: string, body?: unknown) {
    setError('');
    try { await api(path, { method: 'POST', body: body ? JSON.stringify(body) : undefined }); load(); }
    catch (err) { setError(err instanceof Error ? err.message : 'Amal bajarilmadi'); }
  }

  async function exportOpen() {
    try {
      const data = await api<unknown>('/support/export');
      const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
      const a = document.createElement('a');
      a.href = url; a.download = 'sanitialx-support-export.json'; a.click();
      URL.revokeObjectURL(url);
    } catch (err) { setError(err instanceof Error ? err.message : 'Eksport amalga oshmadi'); }
  }

  return <main className="page">
    <div className="eyebrow">SANITIALX / YORDAM</div>
    <div className="page-header">
      <div><h1>Yordam markazi</h1><p>Savol bering, kamchilik haqida yozing yoki taklif yuboring. Murojaatlar faqat sizning tizimingizda saqlanadi.</p></div>
      {isAdmin && <button className="refresh" onClick={exportOpen}><Download size={15} /> Ochiq murojaatlarni eksport</button>}
    </div>

    {error && <div className="sp-error">{error}</div>}

    <section className="sp-card">
      <h3><LifeBuoy size={17} /> Yangi murojaat</h3>
      <form onSubmit={submit} className="sp-form">
        <div className="sp-row">
          <select value={category} onChange={(e) => setCategory(e.target.value as Ticket['category'])}>
            {Object.entries(CATEGORY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          <input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="Mavzu" minLength={3} maxLength={200} required />
        </div>
        <textarea value={message} onChange={(e) => setMessage(e.target.value)} placeholder="Batafsil yozing. Parol va maxfiy ma’lumot kiritmang." minLength={3} maxLength={5000} rows={4} required />
        <button type="submit" className="sp-btn"><Send size={15} /> Yuborish</button>
      </form>
    </section>

    <section className="sp-list">
      {tickets.length === 0 && <div className="sp-empty">Hozircha murojaatlar yo‘q.</div>}
      {tickets.map((t) => (
        <article key={t.id} className="sp-card">
          <div className="sp-head">
            <b>{t.subject}</b>
            <span className={`sp-tag ${t.category.toLowerCase()}`}>{CATEGORY[t.category]}</span>
            <span className={`sp-tag st-${t.status.toLowerCase()}`}>{STATUS[t.status]}</span>
          </div>
          <small>{t.created_by} · {new Date(t.created_at).toLocaleString('uz-UZ')}</small>
          <p>{t.message}</p>
          {t.vendor_reply && <div className="sp-reply"><b>Javob:</b> {t.vendor_reply}</div>}
          <div className="sp-actions">
            {t.status !== 'CLOSED' && <button className="sp-btn ghost" onClick={() => act(`/support/tickets/${t.id}/close`)}>Yopish</button>}
            {isAdmin && t.status === 'OPEN' && <>
              <input value={replies[t.id] ?? ''} onChange={(e) => setReplies({ ...replies, [t.id]: e.target.value })} placeholder="Vendor javobini kiriting" />
              <button className="sp-btn" disabled={!replies[t.id]} onClick={() => act(`/support/tickets/${t.id}/reply`, { reply: replies[t.id] })}>Javobni saqlash</button>
            </>}
          </div>
        </article>
      ))}
    </section>
  </main>;
}
