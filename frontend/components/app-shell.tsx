'use client';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect } from 'react';
import { clearToken, getToken } from '@/lib/api';
import { Activity, Bell, BookOpen, Bug, ChevronDown, FileText, LayoutDashboard, Network, Settings, Shield, ShieldAlert, Target, Terminal, Users } from 'lucide-react';

const nav=[['/dashboard','Dashboard',LayoutDashboard],['/threats','Threats',ShieldAlert],['/incidents','Incidents',Bug],['/rules','Detection rules',Target]] as const;

export function AppShell({children}:{children:React.ReactNode}){
 const path=usePathname();
 useEffect(()=>{ if(path !== '/login' && !getToken()) window.location.href='/login'; },[path]);
 if(path === '/login') return <>{children}</>;
 return <div className="shell">
  <aside className="sidebar">
   <div className="brand"><div className="brand-mark"><Shield size={19}/></div><div><b>SENTINEL<span>X</span></b><small>SECURITY OPERATIONS</small></div></div>
   <div className="workspace"><div className="workspace-icon">SOC</div><div><span>Security workspace</span><b>Production</b></div><ChevronDown size={14}/></div>
   <nav>
    <label>OPERATIONS</label>
    {nav.map(([href,name,Icon])=><Link href={href} key={href} className={path===href?'selected':''}><Icon size={18}/><span>{name}</span>{name==='Incidents'&&<i className="nav-count">LIVE</i>}</Link>)}
    <label>VISIBILITY</label>
    <Link href="#"><Network size={18}/><span>Network</span></Link>
    <Link href="#"><Activity size={18}/><span>Threat intelligence</span></Link>
    <Link href="#"><Terminal size={18}/><span>Endpoints</span></Link>
    <label>MANAGEMENT</label>
    <Link href="#"><FileText size={18}/><span>Reports</span></Link>
    <Link href="#"><Users size={18}/><span>Analysts</span></Link>
   </nav>
   <div className="sidebar-bottom"><Link href="#"><BookOpen size={17}/> <span>Documentation</span></Link><Link href="#"><Settings size={17}/> <span>Settings</span></Link></div>
  </aside>
  <div className="content">
   <header className="topbar"><div className="crumb"><span>SentinelX</span><b>/</b><strong>{path.split('/')[1]||'dashboard'}</strong></div><div className="top-actions"><button className="icon-btn" aria-label="Notifications"><Bell size={18}/><i/></button><div className="user"><div className="avatar">TA</div><div><b>Security Analyst</b><span>{typeof window !== 'undefined' ? (localStorage.getItem('sanitialx_role') || 'analyst') : 'analyst'}</span></div><button className="logout-btn" onClick={()=>{clearToken();window.location.href='/login'}}>Logout</button></div></div></header>
   {children}
  </div>
 </div>;
}
