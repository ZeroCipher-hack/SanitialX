'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  Shield, Activity, AlertTriangle, FileText, Sliders, LogOut, Bell, X, Play, Cpu,
  Layers, Zap, Radio, Share2, Crosshair, Box, Brain, CheckCircle2, Loader2,
  BookOpen, ScrollText, Bug, ChevronRight,
} from 'lucide-react';
import { useEffect, useState, useRef } from 'react';
import { api, logout, runAttackSimulation } from '@/lib/api';
import type { Incident } from '@/types/api';

type VulnerabilityAlert = {
  id: number;
  agent_id: string;
  cve_id: string;
  alert_type: string;
  severity: string;
  title: string;
  message: string;
  risk_score: number;
  acknowledged: boolean;
  created_at: string;
  updated_at: string;
};

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [vulnerabilityAlerts, setVulnerabilityAlerts] = useState<VulnerabilityAlert[]>([]);
  const [showNotifs, setShowNotifs] = useState(false);
  const [showQuickActions, setShowQuickActions] = useState(false);
  const [demoRunning, setDemoRunning] = useState(false);
  const [demoMessage, setDemoMessage] = useState('');
  const notifRef = useRef<HTMLDivElement>(null);
  const quickActionsRef = useRef<HTMLDivElement>(null);

  const loadNotifications = () => {
    if (typeof window === 'undefined') return;
    const token = localStorage.getItem('access_token');
    if (!token) {
      setIncidents([]);
      setVulnerabilityAlerts([]);
      return;
    }

    Promise.all([
      api<Incident[]>('/incidents?limit=50'),
      api<VulnerabilityAlert[]>('/vulnerability-alerts?unacknowledged_only=true&limit=50'),
    ]).then(([incidentData, alertData]) => {
      setIncidents(incidentData.filter((x) => x.severity === 'CRITICAL' || x.severity === 'HIGH'));
      setVulnerabilityAlerts(alertData);
    }).catch(() => {
      setIncidents([]);
      setVulnerabilityAlerts([]);
    });
  };

  useEffect(() => {
    if (pathname === '/login') return;
    loadNotifications();
    const interval = setInterval(loadNotifications, 15000);
    return () => clearInterval(interval);
  }, [pathname]);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Node;
      if (notifRef.current && !notifRef.current.contains(target)) setShowNotifs(false);
      if (quickActionsRef.current && !quickActionsRef.current.contains(target)) setShowQuickActions(false);
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
    } finally {
      setDemoRunning(false);
    }
  };

  const openVulnerabilityAlert = async (alert: VulnerabilityAlert) => {
    try {
      await api(`/vulnerability-alerts/${alert.id}/acknowledge`, { method: 'POST' });
      setVulnerabilityAlerts((prev) => prev.filter((item) => item.id !== alert.id));
    } catch {
      // Navigation still proceeds; acknowledgement can be retried on the next refresh.
    }
    setShowNotifs(false);
    router.push(`/vulnerabilities?cve=${encodeURIComponent(alert.cve_id)}&agent_id=${encodeURIComponent(alert.agent_id)}`);
  };

  if (pathname === '/login') return <>{children}</>;

  const activeIncidentsCount = incidents.filter((x) => x.status === 'OPEN' || x.status === 'INVESTIGATING').length;
  const totalNotificationCount = activeIncidentsCount + vulnerabilityAlerts.length;

  const item = (href: string, label: string, icon: React.ReactNode) => (
    <Link href={href} className={`nav-item ${pathname === href ? 'active' : ''}`}>{icon}<span>{label}</span></Link>
  );

  const closeQuickActions = () => setShowQuickActions(false);

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
          {item('/vulnerabilities', 'Vulnerability Center', <Bug size={17} />)}

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
                <Bell size={18} />{totalNotificationCount > 0 && <span className="badge-count">{totalNotificationCount}</span>}
              </button>
              {showNotifs && <div className="notif-dropdown">
                <div className="notif-head"><span>Faol muhim ogohlantirishlar ({totalNotificationCount})</span><button onClick={() => setShowNotifs(false)}><X size={14} /></button></div>
                <div className="notif-body">
                  {totalNotificationCount === 0 && <div className="notif-empty">Faol muhim ogohlantirishlar yo‘q.</div>}
                  {vulnerabilityAlerts.map((alert) => (
                    <div key={`vuln-${alert.id}`} className="notif-item" onClick={() => openVulnerabilityAlert(alert)}>
                      <span className={`badge ${alert.severity.toLowerCase()}`}>{alert.severity}</span>
                      <div className="notif-title">{alert.title}</div>
                      <small>{alert.cve_id} · {alert.agent_id} · risk {alert.risk_score}/100</small>
                    </div>
                  ))}
                  {incidents.filter((inc) => inc.status === 'OPEN' || inc.status === 'INVESTIGATING').map((inc) => (
                    <div key={`inc-${inc.incident_id}`} className="notif-item" onClick={() => { setShowNotifs(false); router.push(`/incidents?id=${inc.incident_id}`); }}>
                      <span className={`badge ${inc.severity.toLowerCase()}`}>{inc.severity}</span>
                      <div className="notif-title">{inc.title}</div><small>{inc.incident_id}</small>
                    </div>
                  ))}
                </div>
              </div>}
            </div>
          </div>
        </header>

        <div className="workspace-layout">
          <section className="content">{children}</section>

          <aside className="utility-rail" aria-label="Tezkor vositalar">
            <Link href="/ai-analysis" className="utility-icon" data-tooltip="AI tahlil" aria-label="AI tahlil">
              <Brain size={20} />
            </Link>

            <Link href="/logs" className="utility-icon" data-tooltip="Log oqimi" aria-label="Log oqimi">
              <ScrollText size={20} />
            </Link>

            <div className="utility-popover-wrap" ref={quickActionsRef}>
              <button
                type="button"
                className={`utility-icon ${showQuickActions ? 'active' : ''}`}
                data-tooltip="Tezkor amallar"
                aria-label="Tezkor amallar"
                aria-expanded={showQuickActions}
                onClick={() => setShowQuickActions((value) => !value)}
              >
                <Zap size={20} />
              </button>

              {showQuickActions && (
                <div className="utility-popover">
                  <div className="utility-popover-title">Tezkor amallar</div>
                  <Link href="/events" onClick={closeQuickActions}><span>Hodisalarni ko‘rish</span><ChevronRight size={14} /></Link>
                  <Link href="/vulnerabilities" onClick={closeQuickActions}><span>Zaifliklarni ko‘rish</span><ChevronRight size={14} /></Link>
                  <Link href="/simulations" onClick={closeQuickActions}><span>Simulyatsiyalar</span><ChevronRight size={14} /></Link>
                  <Link href="/guide" onClick={closeQuickActions}><span>Tizimni o‘rganish</span><ChevronRight size={14} /></Link>
                </div>
              )}
            </div>
          </aside>
        </div>
      </div>
    </div>
  );
}
