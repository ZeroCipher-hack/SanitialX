'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  Shield,
  Activity,
  AlertTriangle,
  FileText,
  Sliders,
  LogOut,
  Bell,
  X,
  Play,
  Cpu,
  Layers,
  Zap,
  Radio,
  Share2,
  Crosshair,
  Box,
  Brain,
  CheckCircle2,
  Loader2,
} from 'lucide-react';
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
    api<Incident[]>('/incidents?limit=50')
      .then((data) => {
        setIncidents(data.filter((x) => x.severity === 'CRITICAL' || x.severity === 'HIGH'));
      })
      .catch(() => {});
  };

  useEffect(() => {
    loadNotifications();
    const interval = setInterval(loadNotifications, 15000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(event.target as Node)) {
        setShowNotifs(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleRunDemoAttack = async () => {
    setDemoRunning(true);
    setDemoMessage('Running Cyber Range Attack Simulation...');
    try {
      const sim = await runAttackSimulation('WEB_APP_COMPROMISE');
      setDemoMessage(`Simulation Completed! Incident created: ${sim.generated_incident_id}`);
      setTimeout(() => {
        setDemoMessage('');
        router.push('/simulations');
      }, 1500);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Simulation failed';
      setDemoMessage(`Error: ${msg}`);
      setTimeout(() => setDemoMessage(''), 3000);
    } finally {
      setDemoRunning(false);
    }
  };

  if (pathname === '/login') return <>{children}</>;

  const activeIncidentsCount = incidents.filter(
    (x) => x.status === 'OPEN' || x.status === 'INVESTIGATING'
  ).length;

  return (
    <div className="app-grid">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-logo">
            <Shield size={18} color="#00e5ff" />
          </div>
          <div className="brand-text">
            <strong>SANITIALX</strong>
            <small>AI CYBER RANGE & SIEM</small>
          </div>
        </div>

        <nav className="nav">
          <div className="nav-group-title">OVERVIEW</div>
          <Link
            href="/dashboard"
            className={`nav-item ${pathname === '/dashboard' ? 'active' : ''}`}
          >
            <Activity size={16} /> Command Center
          </Link>

          <div className="nav-group-title">MONITORING</div>
          <Link
            href="/events"
            className={`nav-item ${pathname === '/events' ? 'active' : ''}`}
          >
            <Radio size={16} /> Security Events
          </Link>
          <Link
            href="/incidents"
            className={`nav-item ${pathname === '/incidents' ? 'active' : ''}`}
          >
            <AlertTriangle size={16} /> Incident Center
          </Link>

          <div className="nav-group-title">DETECTION</div>
          <Link
            href="/rules"
            className={`nav-item ${pathname === '/rules' ? 'active' : ''}`}
          >
            <Sliders size={16} /> Detection Rules
          </Link>
          <Link
            href="/techniques"
            className={`nav-item ${pathname === '/techniques' ? 'active' : ''}`}
          >
            <Layers size={16} /> MITRE ATT&CK
          </Link>

          <div className="nav-group-title">ENVIRONMENT</div>
          <Link
            href="/agents"
            className={`nav-item ${pathname === '/agents' ? 'active' : ''}`}
          >
            <Cpu size={16} /> Endpoint Agents
          </Link>
          <Link
            href="/assets"
            className={`nav-item ${pathname === '/assets' ? 'active' : ''}`}
          >
            <Box size={16} /> Cyber Range Assets
          </Link>

          <div className="nav-group-title">DECEPTION</div>
          <Link
            href="/honeypots"
            className={`nav-item ${pathname === '/honeypots' ? 'active' : ''}`}
          >
            <Zap size={16} /> Honeypot Vault
          </Link>

          <div className="nav-group-title">SIMULATION</div>
          <Link
            href="/simulations"
            className={`nav-item ${pathname === '/simulations' ? 'active' : ''}`}
          >
            <Crosshair size={16} /> Attack Simulator
          </Link>

          <div className="nav-group-title">INVESTIGATION</div>
          <Link
            href="/attack-graph"
            className={`nav-item ${pathname === '/attack-graph' ? 'active' : ''}`}
          >
            <Share2 size={16} /> Attack Path Graph
          </Link>
          <Link
            href="/ai-analysis"
            className={`nav-item ${pathname === '/ai-analysis' ? 'active' : ''}`}
          >
            <Brain size={16} /> AI Security Reasoning
          </Link>
          <Link
            href="/reports"
            className={`nav-item ${pathname === '/reports' ? 'active' : ''}`}
          >
            <FileText size={16} /> Automated Reports
          </Link>
        </nav>

        <div className="sidebar-footer">
          <button onClick={() => logout()} className="logout-btn">
            <LogOut size={15} /> Sign Out
          </button>
        </div>
      </aside>

      <div className="main-wrapper">
        <header className="topbar">
          <div className="topbar-left">
            <span className="environment-tag">CYBER RANGE ACTIVE</span>
            {demoMessage && (
              <span className="demo-banner">
                <CheckCircle2 size={14} /> {demoMessage}
              </span>
            )}
          </div>
          <div className="topbar-right">
            <button
              onClick={handleRunDemoAttack}
              disabled={demoRunning}
              className="demo-attack-btn"
              title="Execute flagship end-to-end attack simulation"
            >
              {demoRunning ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                <Play size={14} fill="#00e5ff" />
              )}
              RUN DEMO ATTACK
            </button>

            <div className="notif-wrapper" ref={notifRef}>
              <button
                className="icon-btn"
                onClick={() => setShowNotifs(!showNotifs)}
                title="Notifications"
              >
                <Bell size={18} />
                {activeIncidentsCount > 0 && (
                  <span className="badge-count">{activeIncidentsCount}</span>
                )}
              </button>

              {showNotifs && (
                <div className="notif-dropdown">
                  <div className="notif-head">
                    <span>Critical Alerts ({activeIncidentsCount})</span>
                    <button onClick={() => setShowNotifs(false)}>
                      <X size={14} />
                    </button>
                  </div>
                  <div className="notif-body">
                    {incidents.length === 0 ? (
                      <div className="notif-empty">No active critical alerts.</div>
                    ) : (
                      incidents.map((inc) => (
                        <div
                          key={inc.incident_id}
                          className="notif-item"
                          onClick={() => {
                            setShowNotifs(false);
                            router.push(`/incidents?id=${inc.incident_id}`);
                          }}
                        >
                          <span className={`badge ${inc.severity.toLowerCase()}`}>
                            {inc.severity}
                          </span>
                          <div className="notif-title">{inc.title}</div>
                          <small>{inc.incident_id}</small>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        </header>

        <section className="content">{children}</section>
      </div>
    </div>
  );
}
