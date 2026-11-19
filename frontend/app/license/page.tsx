'use client';

import { ChangeEvent, useCallback, useEffect, useState } from 'react';
import { KeyRound, Upload } from 'lucide-react';
import { api } from '@/lib/api';
import { currentRole } from '@/lib/session';

type License = {
  state: 'VALID' | 'EXPIRED' | 'INVALID' | 'MISSING' | 'UNCONFIGURED'; reason: string; customer: string | null; plan: string | null;
  max_agents: number | null; features: string[]; issued_at: string | null; expires_at: string | null; days_left: number | null;
};

const STATE: Record<License['state'], string> = {
  VALID: 'Faol', EXPIRED: 'Muddati tugagan', INVALID: 'Yaroqsiz', MISSING: 'O‘rnatilmagan', UNCONFIGURED: 'Sozlanmagan',
};

export default function LicensePage() {
  const [lic, setLic] = useState<License | null>(null);
  const [error, setError] = useState('');
  const [info, setInfo] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);

  const load = useCallback(() => {
    api<License>('/license').then(setLic).catch((e) => setError(e.message));
  }, []);

  useEffect(() => { setIsAdmin(currentRole() === 'admin'); load(); }, [load]);

  async function upload(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    setError(''); setInfo('');
    try {
      const doc = JSON.parse(await file.text());
      setLic(await api<License>('/license', { method: 'POST', body: JSON.stringify(doc) }));
      setInfo('Litsenziya o‘rnatildi.');
    } catch (err) { setError(err instanceof Error ? err.message : 'Litsenziyani o‘rnatib bo‘lmadi'); }
  }

  const row = (k: string, v: React.ReactNode) => <div className="lic-row"><span>{k}</span><b>{v ?? '—'}</b></div>;

  return <main className="page">
    <div className="eyebrow">SANITIALX / LITSENZIYA</div>
    <div className="page-header"><div><h1>Litsenziya</h1><p>Litsenziya imzolangan fayl orqali internetsiz tekshiriladi.</p></div></div>
    {error && <div className="sp-error">{error}</div>}
    {info && <div className="lic-ok">{info}</div>}
    <section className="sp-card">
      <h3><KeyRound size={17} /> Holat: <span className={`sp-tag lic-${lic?.state.toLowerCase()}`}>{lic ? STATE[lic.state] : '…'}</span></h3>
      {lic?.reason && <p>{lic.reason}</p>}
      {lic && lic.state !== 'MISSING' && lic.state !== 'UNCONFIGURED' && lic.state !== 'INVALID' && <div className="lic-grid">
        {row('Mijoz', lic.customer)}{row('Reja', lic.plan)}{row('Maksimal agentlar', lic.max_agents)}
        {row('Amal qilish muddati', lic.expires_at ? new Date(lic.expires_at).toLocaleDateString('uz-UZ') : null)}
        {row('Qolgan kun', lic.days_left)}{row('Imkoniyatlar', lic.features.join(', '))}
      </div>}
      {isAdmin && <label className="sp-btn" style={{ marginTop: 14 }}><Upload size={15} /> Litsenziya faylini yuklash
        <input type="file" accept="application/json,.json" onChange={upload} hidden /></label>}
    </section>
  </main>;
}
