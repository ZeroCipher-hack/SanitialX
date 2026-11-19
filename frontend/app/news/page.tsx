'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { Megaphone } from 'lucide-react';
import { api } from '@/lib/api';
import { currentRole } from '@/lib/session';

type NewsItem = { id: number; category: 'RELEASE' | 'RULES' | 'NOTICE'; title: string; body: string; version: string | null; published_at: string };

const CATEGORY: Record<NewsItem['category'], string> = { RELEASE: 'Yangi versiya', RULES: 'Yangi qoidalar', NOTICE: 'E’lon' };

export default function NewsPage() {
  const [items, setItems] = useState<NewsItem[]>([]);
  const [category, setCategory] = useState<NewsItem['category']>('RELEASE');
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('');
  const [version, setVersion] = useState('');
  const [error, setError] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);

  const load = useCallback(() => {
    api<NewsItem[]>('/news').then(setItems).catch((e) => setError(e.message));
  }, []);

  useEffect(() => { setIsAdmin(currentRole() === 'admin'); load(); }, [load]);

  async function publish(e: FormEvent) {
    e.preventDefault();
    setError('');
    try {
      await api('/news', { method: 'POST', body: JSON.stringify({ category, title, body, version: version || null }) });
      setTitle(''); setBody(''); setVersion('');
      load();
    } catch (err) { setError(err instanceof Error ? err.message : 'Joylab bo‘lmadi'); }
  }

  return <main className="page">
    <div className="eyebrow">SANITIALX / YANGILIKLAR</div>
    <div className="page-header"><div><h1>Yangiliklar</h1><p>Yangi versiyalar, aniqlash qoidalari va muhim e’lonlar.</p></div></div>
    {error && <div className="sp-error">{error}</div>}

    {isAdmin && <section className="sp-card">
      <h3><Megaphone size={17} /> Yangilik qo‘shish (vendordan olingan)</h3>
      <form onSubmit={publish} className="sp-form">
        <div className="sp-row">
          <select value={category} onChange={(e) => setCategory(e.target.value as NewsItem['category'])}>
            {Object.entries(CATEGORY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Sarlavha" minLength={3} maxLength={200} required />
          <input value={version} onChange={(e) => setVersion(e.target.value)} placeholder="Versiya (ixtiyoriy)" maxLength={32} />
        </div>
        <textarea value={body} onChange={(e) => setBody(e.target.value)} placeholder="Matn" rows={3} required />
        <button type="submit" className="sp-btn">Joylash</button>
      </form>
    </section>}

    <section className="sp-list">
      {items.length === 0 && <div className="sp-empty">Hozircha yangiliklar yo‘q.</div>}
      {items.map((n) => (
        <article key={n.id} className="sp-card">
          <div className="sp-head">
            <b>{n.title}</b>
            <span className={`sp-tag nw-${n.category.toLowerCase()}`}>{CATEGORY[n.category]}</span>
            {n.version && <span className="sp-tag">v{n.version}</span>}
          </div>
          <small>{new Date(n.published_at).toLocaleDateString('uz-UZ')}</small>
          <p>{n.body}</p>
        </article>
      ))}
    </section>
  </main>;
}
