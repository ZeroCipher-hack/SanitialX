'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Activity, AlertTriangle, ArrowUpRight, CheckCircle2, Clock3, Cpu, RefreshCw, ShieldCheck, Target, Wifi } from 'lucide-react';
import { api } from '@/lib/api';
import type { Incident, SecurityEvent } from '@/types/api';

type TimeRange = '24H' | '7D' | '30D';
type AssetSummary = { total_assets:number; critical_assets:number; internet_facing_assets:number; offline_assets:number; high_risk_assets:number; production_assets:number; managed_assets:number; retired_assets:number; stale_inventory_assets:number };
type VulnerabilityAlert = { id:number; agent_id:string; cve_id:string; severity:string; title:string; risk_score:number; acknowledged:boolean; created_at:string };

const EMPTY_ASSETS: AssetSummary = { total_assets:0, critical_assets:0, internet_facing_assets:0, offline_assets:0, high_risk_assets:0, production_assets:0, managed_assets:0, retired_assets:0, stale_inventory_assets:0 };
const windowMs = (range: TimeRange) => range === '24H' ? 86400000 : range === '7D' ? 604800000 : 2592000000;

function ThreatChart({ incidents, timeRange }: { incidents: Incident[]; timeRange: TimeRange }) {
  const chartData = useMemo(() => {
    const buckets = timeRange === '24H' ? 24 : timeRange === '7D' ? 7 : 15;
    const counts = new Array(buckets).fill(0);
    const now = Date.now(); const span = windowMs(timeRange);
    incidents.forEach((inc) => { const age = now - new Date(inc.created_at).getTime(); if (age >= 0 && age <= span) counts[Math.min(buckets - 1, Math.floor(((span - age) / span) * buckets))]++; });
    const max = Math.max(...counts, 1);
    return counts.map((count, i) => ({ count, height: Math.max(4, (count / max) * 95), label: timeRange === '24H' ? (i % 4 === 0 ? `${String(i).padStart(2,'0')}:00` : '') : timeRange === '7D' ? `D${i+1}` : (i % 3 === 0 ? `D${i*2+1}` : '') }));
  }, [incidents, timeRange]);
  const max = Math.max(...chartData.map((x) => x.count), 1);
  return <div className="chart"><div className="chart-grid"><span>{max}</span><span>{Math.ceil(max*.75)}</span><span>{Math.ceil(max*.5)}</span><span>{Math.ceil(max*.25)}</span><span>0</span></div><div className="bars">{chartData.map((x,i)=><div className="bar-wrap" key={i} title={`${x.count} incidents`}><div className="bar" style={{height:`${x.height}%`}}/><span>{x.label}</span></div>)}</div></div>;
}

export default function Dashboard() {
  const [incidents,setIncidents]=useState<Incident[]>([]); const [events,setEvents]=useState<SecurityEvent[]>([]); const [assets,setAssets]=useState<AssetSummary>(EMPTY_ASSETS); const [vulnAlerts,setVulnAlerts]=useState<VulnerabilityAlert[]>([]);
  const [timeRange,setTimeRange]=useState<TimeRange>('24H'); const [loading,setLoading]=useState(true); const [errors,setErrors]=useState<string[]>([]); const [lastRefresh,setLastRefresh]=useState<Date|null>(null);

  const load = useCallback(async () => {
    const results = await Promise.allSettled([
      api<Incident[]>('/incidents?limit=250'), api<SecurityEvent[]>('/events?limit=250'), api<AssetSummary>('/agents/summary'), api<VulnerabilityAlert[]>('/vulnerability-alerts?unacknowledged_only=true&limit=100')
    ]);
    const nextErrors:string[]=[];
    if(results[0].status==='fulfilled') setIncidents(results[0].value); else nextErrors.push('incidents');
    if(results[1].status==='fulfilled') setEvents(results[1].value); else nextErrors.push('events');
    if(results[2].status==='fulfilled') setAssets(results[2].value); else nextErrors.push('assets');
    if(results[3].status==='fulfilled') setVulnAlerts(results[3].value); else nextErrors.push('vulnerabilities');
    setErrors(nextErrors); setLastRefresh(new Date()); setLoading(false);
  },[]);
  useEffect(()=>{ load(); const timer=setInterval(load,15000); return()=>clearInterval(timer); },[load]);

  const filtered=useMemo(()=>{const now=Date.now(), span=windowMs(timeRange); return incidents.filter(x=>{const age=now-new Date(x.created_at).getTime(); return age>=0&&age<=span;});},[incidents,timeRange]);
  const counts=useMemo(()=>({critical:filtered.filter(x=>x.severity==='CRITICAL').length,high:filtered.filter(x=>x.severity==='HIGH').length,medium:filtered.filter(x=>x.severity==='MEDIUM').length,low:filtered.filter(x=>x.severity==='LOW').length,active:filtered.filter(x=>x.status==='OPEN'||x.status==='INVESTIGATING').length}),[filtered]);
  const recentEvents=useMemo(()=>events.filter(e=>Date.now()-new Date(e.timestamp).getTime()<=windowMs(timeRange)),[events,timeRange]);
  const highVulns=vulnAlerts.filter(x=>x.severity==='CRITICAL'||x.severity==='HIGH').length;
  const riskIndex=Math.min(100, Math.round(counts.critical*12+counts.high*7+counts.active*4+assets.high_risk_assets*5+highVulns*3));
  const securityScore=Math.max(0,1000-riskIndex*10);
  const posture=riskIndex>=75?'CRITICAL':riskIndex>=50?'ELEVATED':riskIndex>=25?'MODERATE':'LOW';
  const sources=Array.from(filtered.filter(x=>x.source_ip).reduce<Map<string,number>>((m,x)=>m.set(x.source_ip!, (m.get(x.source_ip!)||0)+1),new Map()).entries()).sort((a,b)=>b[1]-a[1]).slice(0,5);

  return <main className="page">
    <header className="page-header"><div><div className="eyebrow">SECURITY OPERATIONS CENTER</div><h1>Command Center</h1><p>Live incidents, events, managed assets and vulnerability exposure in one SOC view.</p></div><div style={{display:'flex',gap:8,alignItems:'center'}}><div className="live"><span className="pulse"/> AUTO REFRESH <span className="live-time">15 SEC</span></div><button className="refresh" onClick={load} disabled={loading}><RefreshCw size={14}/>Refresh</button></div></header>
    {errors.length>0&&<div className="api-warning">Partial telemetry unavailable: {errors.join(', ')}. Healthy data sources continue updating.</div>}
    <section className="stats">
      <Stat icon={<ShieldCheck/>} label="Security score" value={String(securityScore)} suffix="/1000" trend={errors.length?'Partial telemetry':'Live telemetry'} good={!errors.length}/>
      <Stat icon={<AlertTriangle/>} label="Critical incidents" value={String(counts.critical).padStart(2,'0')} trend={`${timeRange} · ${counts.active} active`} danger={counts.critical>0}/>
      <Stat icon={<Target/>} label="Vulnerability alerts" value={String(vulnAlerts.length)} trend={`${highVulns} high / critical`} danger={highVulns>0}/>
      <Stat icon={<Cpu/>} label="Protected assets" value={String(assets.total_assets)} trend={`${assets.managed_assets} managed · ${assets.offline_assets} offline`} good={assets.offline_assets===0}/>
    </section>
    <section className="grid-main"><div className="panel threat-panel"><div className="panel-head"><div><h2>Incident activity ({timeRange})</h2><span>Real incident timestamps only — no synthetic chart fallback</span></div><div className="range">{(['24H','7D','30D'] as TimeRange[]).map(r=><button key={r} className={timeRange===r?'active':''} onClick={()=>setTimeRange(r)}>{r}</button>)}</div></div><ThreatChart incidents={filtered} timeRange={timeRange}/><div className="legend"><span><i className="dot critical"/>Critical {counts.critical}</span><span><i className="dot high"/>High {counts.high}</span><span><i className="dot medium"/>Medium {counts.medium}</span><span><i className="dot low"/>Low {counts.low}</span></div></div>
      <div className="panel score-panel"><div className="panel-head"><div><h2>Risk posture</h2><span>Deterministic SOC overview</span></div><Activity className="muted-icon"/></div><div className="gauge"><div className="gauge-ring"><div><strong>{posture}</strong><small>{riskIndex}/100 risk index</small></div></div></div><div className="risk-row"><span>High-risk assets</span><b>{assets.high_risk_assets}</b></div><div className="risk-row"><span>Internet-facing assets</span><b>{assets.internet_facing_assets}</b></div><div className="risk-row"><span>Stale inventories</span><b>{assets.stale_inventory_assets}</b></div></div></section>
    <section className="grid-bottom"><div className="panel events"><div className="panel-head"><div><h2>Live security events</h2><span>{recentEvents.length} events in selected range</span></div><a className="ghost" href="/events">View all <ArrowUpRight size={15}/></a></div>{events.slice(0,6).map((e)=><div className="event" key={e.event_id}><div className={`severity ${e.severity.toLowerCase()}`}/><div className="event-main"><b>{e.event_type}</b><span>{e.source_ip||'unknown'} <em>→</em> {e.destination_ip||e.host||'unknown'}{e.mitre_technique?` · ${e.mitre_technique}`:''}</span></div><span className={`badge ${e.severity.toLowerCase()}`}>{e.severity}</span><time>{new Date(e.timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}</time></div>)}{!events.length&&<div className="empty">No persisted security events yet.</div>}</div>
      <div className="panel sources"><div className="panel-head"><div><h2>Top attack sources</h2><span>Source IPs from current incident telemetry</span></div></div>{sources.map(([ip,n])=><div className="source" key={ip}><div className="source-top"><b>{ip}</b><span>Incident source</span><strong>{n}</strong></div><div className="progress"><i style={{width:`${Math.min(100,n/Math.max(sources[0]?.[1]||1,1)*100)}%`}}/></div></div>)}{!sources.length&&<div className="empty">No source IP telemetry in selected range.</div>}</div></section>
    <section className="footer-strip"><div><Wifi size={16}/><span>Telemetry</span><b className={errors.length?'':'ok'}>{errors.length?'Degraded':'Operational'}</b></div><div><Activity size={16}/><span>Persisted events</span><b>{events.length}</b></div><div><Clock3 size={16}/><span>Last refresh</span><b>{lastRefresh?lastRefresh.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'}):'—'}</b></div><div><CheckCircle2 size={16}/><span>Production assets</span><b className="ok">{assets.production_assets}</b></div></section>
  </main>;
}

function Stat({icon,label,value,suffix,trend,good,danger}:{icon:React.ReactNode;label:string;value:string;suffix?:string;trend:string;good?:boolean;danger?:boolean}){return <div className="stat"><div className="stat-icon">{icon}</div><div className="stat-copy"><span>{label}</span><strong>{value}<small>{suffix}</small></strong><em className={danger?'bad':good?'good':''}>{trend}</em></div></div>}
