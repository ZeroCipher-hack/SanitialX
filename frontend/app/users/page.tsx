'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { KeyRound, UserPlus, UserX, UserCheck } from 'lucide-react';
import { api } from '@/lib/api';
import { currentRole } from '@/lib/session';

type User = { user_id: string; username: string; role: 'reader' | 'analyst' | 'admin'; is_active: boolean; created_at: string };

const ROLE: Record<User['role'], string> = { admin: 'Administrator', analyst: 'Analitik', reader: 'Kuzatuvchi' };
const ROLE_HINT = 'Administrator: hamma narsa. Analitik: hodisalar va javob amallari. Kuzatuvchi: faqat ko‘rish.';

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [isAdmin, setIsAdmin] = useState<boolean | null>(null);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<User['role']>('analyst');
  const [resetFor, setResetFor] = useState<string | null>(null);
  const [newPassword, setNewPassword] = useState('');
  const [error, setError] = useState('');
  const [info, setInfo] = useState('');
  const me = typeof window !== 'undefined' ? currentSubject() : '';

  const load = useCallback(() => {
    api<User[]>('/users').then(setUsers).catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    const admin = currentRole() === 'admin';
    setIsAdmin(admin);
    if (admin) load();
  }, [load]);

  async function run(action: () => Promise<unknown>, done: string) {
    setError(''); setInfo('');
    try { await action(); setInfo(done); load(); }
    catch (err) { setError(err instanceof Error ? err.message : 'Amal bajarilmadi'); }
  }

  function create(e: FormEvent) {
    e.preventDefault();
    run(async () => {
      await api('/users', { method: 'POST', body: JSON.stringify({ username, password, role }) });
      setUsername(''); setPassword('');
    }, 'Foydalanuvchi yaratildi.');
  }

  const patch = (u: User, body: Partial<Pick<User, 'role' | 'is_active'>>, done: string) =>
    run(() => api(`/users/${u.user_id}`, { method: 'PATCH', body: JSON.stringify(body) }), done);

  function reset(u: User) {
    run(async () => {
      await api(`/users/${u.user_id}/password`, { method: 'POST', body: JSON.stringify({ password: newPassword }) });
      setResetFor(null); setNewPassword('');
    }, `${u.username}: parol yangilandi, eski sessiyalar yopildi.`);
  }

  if (isAdmin === false) {
    return <main className="page"><div className="eyebrow">SANITIALX / FOYDALANUVCHILAR</div>
      <div className="page-header"><div><h1>Foydalanuvchilar</h1><p>Bu bo‘limga faqat administrator kira oladi.</p></div></div></main>;
  }

  return <main className="page">
    <div className="eyebrow">SANITIALX / FOYDALANUVCHILAR</div>
    <div className="page-header"><div><h1>Foydalanuvchilar</h1><p>Tizimga kiradigan xodimlarni yarating va ruxsatlarini boshqaring. Ommaviy ro‘yxatdan o‘tish yo‘q: faqat administrator qo‘sha oladi.</p></div></div>

    {error && <div className="sp-error">{error}</div>}
    {info && <div className="lic-ok">{info}</div>}

    <section className="sp-card">
      <h3><UserPlus size={17} /> Yangi foydalanuvchi</h3>
      <form onSubmit={create} className="sp-form">
        <div className="sp-row" style={{ gridTemplateColumns: '1fr 1fr auto' }}>
          <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Login (3–64 belgi: harf, raqam, . _ -)" minLength={3} maxLength={64} pattern="[A-Za-z0-9._\-]+" required autoComplete="off" />
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Parol (kamida 8 belgi)" minLength={8} maxLength={128} required autoComplete="new-password" />
          <select value={role} onChange={(e) => setRole(e.target.value as User['role'])}>
            {Object.entries(ROLE).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </div>
        <small style={{ color: '#587c98' }}>{ROLE_HINT}</small>
        <button type="submit" className="sp-btn"><UserPlus size={15} /> Yaratish</button>
      </form>
    </section>

    <section className="sp-card" style={{ padding: 0, overflow: 'hidden' }}>
      <table className="us-table">
        <thead><tr><th>Login</th><th>Rol</th><th>Holat</th><th>Yaratilgan</th><th>Amallar</th></tr></thead>
        <tbody>
          {users.map((u) => {
            const self = u.username === me;
            return <tr key={u.user_id} className={u.is_active ? '' : 'off'}>
              <td><b>{u.username}</b>{self && <span className="sp-tag" style={{ marginLeft: 10 }}>siz</span>}</td>
              <td><select value={u.role} disabled={self} onChange={(e) => patch(u, { role: e.target.value as User['role'] }, `${u.username}: rol o‘zgartirildi.`)}>
                {Object.entries(ROLE).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></td>
              <td><span className={`sp-tag ${u.is_active ? 'st-answered' : 'bug'}`}>{u.is_active ? 'Faol' : 'O‘chirilgan'}</span></td>
              <td className="mut">{new Date(u.created_at).toLocaleDateString('uz-UZ')}</td>
              <td>
                {resetFor === u.user_id ? <span className="us-reset">
                  <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="Yangi parol" minLength={8} autoComplete="new-password" />
                  <button className="sp-btn" disabled={newPassword.length < 8} onClick={() => reset(u)}>Saqlash</button>
                  <button className="sp-btn ghost" onClick={() => { setResetFor(null); setNewPassword(''); }}>Bekor</button>
                </span> : <span className="us-actions">
                  <button className="sp-btn ghost" onClick={() => setResetFor(u.user_id)}><KeyRound size={14} /> Parol</button>
                  {!self && (u.is_active
                    ? <button className="sp-btn ghost" onClick={() => patch(u, { is_active: false }, `${u.username}: o‘chirib qo‘yildi, kirish to‘xtatildi.`)}><UserX size={14} /> O‘chirish</button>
                    : <button className="sp-btn ghost" onClick={() => patch(u, { is_active: true }, `${u.username}: qayta yoqildi.`)}><UserCheck size={14} /> Yoqish</button>)}
                </span>}
              </td>
            </tr>;
          })}
          {users.length === 0 && <tr><td colSpan={5} className="sp-empty">Foydalanuvchilar yo‘q.</td></tr>}
        </tbody>
      </table>
    </section>
  </main>;
}

/** Username (JWT `sub`) of the signed-in user. UI hint only. */
function currentSubject(): string {
  try {
    const token = localStorage.getItem('access_token');
    if (!token) return '';
    const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    return typeof payload.sub === 'string' ? payload.sub : '';
  } catch { return ''; }
}
