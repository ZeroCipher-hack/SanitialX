'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { Shield, Activity, AlertTriangle, FileText, Sliders, LogOut, Bell, X, Play, Cpu, Layers, Zap, Radio, Share2, Crosshair, Box, Brain, CheckCircle2, Loader2, BookOpen, ScrollText } from 'lucide-react';
import { useEffect, useState, useRef } from 'react';
import { api, logout, runAttackSimulation } from '@/lib/api';
import type { Incident } from '@/types/api';

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [showNotifs, setShowNotifs] = useState(false);
  const [demoRunning, setDemoRunning] = useState(false);
  const [demoMessage, setDemoMessage] = useState('');
  const notifRef = useRef<HTMLDivElement>(null);

  const loadNotifications = () => {
    if (typeof window === 'undefined') return;
    const token = localStorage.getItem('access_token');
    if (!token) { setIncidents([]); return; }
    api<Incident[]>('/incidents?limit=50').then((data) => {
      setIncidents(data.filter((x) => x.severity === 'CRITICAL' || x.severity === 'HIGH'));
    }).catch(() => setIncidents([]));
  };

  useEffect(() => {
    if (pathname === '/login') return;
    loadNotifications();
    const interval = setInterval(loadNotifications, 15000);
    return () => clearInterval(interval);
  }, [pathname]);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(event.target as Node)) setShowNotifs(false);
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleRunDemoAttack = async () => {
    setDemoRunning(true);
    setDemoMessage('Kiber poligon hujumi simulyatsiyasi ishga tushmoqda...');
    try {
      const sim = await runAttackSimulation('WEB_APP_COMPROMISE');
      setDemoMessage(`Simulyatsiya tugadi. Hodisa yaratildi: ${sim.generated_incident_id}`);
      setTimeout(() => { setDemoMessage(''); router.push('/simulations'); }, 1500);
    } catch (e: unknown) {
      setDemoMessage(`Xatolik: ${e instanceof Error ? e.message : 'Simulyatsiya bajarilmadi'}`);
      setTimeout(() => setDemoMessage(''), 3000);
    } finally { setDemoRunning(false); }
  };

  if (pathname === '/login') return <>{children}</>;

  const activeIncidentsCount = incidents.filter((x) => x.status === 'OPEN' || x.status === 'INVESTIGATING').length;

  const item = (href: string, label: string, icon: React.ReactNode) => (
    <Link href={href} className={`nav-item ${pathname === href ? 'active' : ''}`}>{icon}<span>{label}</span></Link>
  );

  return (
    <div className="app-grid">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-logo"><Shield size={20} color="#00e5ff" /></div>
          <div className="brand-text"><strong>SANITIALX</strong><small>AI CYBER RANGE & SIEM</small></div>
        </div>

        <nav className="nav" aria-label="Asosiy navigatsiya">
          <div className="nav-group-title">UMUMIY KO‘RINISH</div>
          {item('/dashboard', 'Boshqaruv paneli', <Activity size={17} />)}

          <div className="nav-group-title">MONITORING</div>
          {item('/events', 'Xavfsizlik hodisalari', <Radio size={17} />)}
          {item('/incidents', 'Hodisa markazi', <AlertTriangle size={17} />)}
          {item('/logs', 'Tizim loglari', <ScrollText size={17} />)}

          <div className="nav-group-title">ANIQLASH</div>
          {item('/rules', 'Aniqlash qoidalari', <Sliders size={17} />)}
          {item('/techniques', 'MITRE ATT&CK', <Layers size={17} />)}

          <div className="nav-group-title">MUHIT</div>
          {item('/agents', 'Endpoint agentlar', <Cpu size={17} />)}
          {item('/assets', 'Kiber poligon aktivlari', <Box size={17} />)}

          <div className="nav-group-title">DECEPTION</div>
          {item('/honeypots', 'Honeypot markazi', <Zap size={17} />)}

          <div className="nav-group-title">SIMULYATSIYA</div>
          {item('/simulations', 'Hujum simulyatori', <Crosshair size={17} />)}

          <div className="nav-group-title">TAHLIL</div>
          {item('/attack-graph', 'Hujum yo‘li grafigi', <Share2 size={17} />)}
          {item('/ai-analysis', 'AI xavfsizlik tahlili', <Brain size={17} />)}
          {item('/reports', 'Avtomatik hisobotlar', <FileText size={17} />)}

          <div className="nav-group-title">YORDAM</div>
          {item('/guide', 'Qo‘llanma va test', <BookOpen size={17} />)}
        </nav>

        <div className="sidebar-footer">
          <button onClick={() => logout()} className="logout-btn"><LogOut size={15} /><span>Chiqish</span></button>
        </div>
      </aside>

      <div className="main-wrapper">
        <header className="topbar">
          <div className="topbar-left">
            <span className="environment-tag">KIBER POLIGON FAOL</span>
            {demoMessage && <span className="demo-banner"><CheckCircle2 size={14} /> {demoMessage}</span>}
          </div>
          <div className="topbar-right">
            <button onClick={handleRunDemoAttack} disabled={demoRunning} className="demo-attack-btn" title="End-to-end demo hujumini ishga tushirish">
              {demoRunning ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} fill="#00e5ff" />}
              DEMO HUJUMNI ISHGA TUSHIRISH
            </button>
            <div className="notif-wrapper" ref={notifRef}>
              <button className="icon-btn" onClick={() => setShowNotifs(!showNotifs)} title="Bildirishnomalar">
                <Bell size={18} />{activeIncidentsCount > 0 && <span className="badge-count">{activeIncidentsCount}</span>}
              </button>
              {showNotifs && <div className="notif-dropdown">
                <div className="notif-head"><span>Faol muhim ogohlantirishlar ({activeIncidentsCount})</span><button onClick={() => setShowNotifs(false)}><X size={14} /></button></div>
                <div className="notif-body">
                  {incidents.length === 0 ? <div className="notif-empty">Faol muhim ogohlantirishlar yo‘q.</div> : incidents.map((inc) => (
                    <div key={inc.incident_id} className="notif-item" onClick={() => { setShowNotifs(false); router.push(`/incidents?id=${inc.incident_id}`); }}>
                      <span className={`badge ${inc.severity.toLowerCase()}`}>{inc.severity}</span>
                      <div className="notif-title">{inc.title}</div><small>{inc.incident_id}</small>
                    </div>
                  ))}
                </div>
              </div>}
            </div>
          </div>
        </header>
        <section className="content">{children}</section>
      </div>
    </div>
  );
}
