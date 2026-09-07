'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  Brain,
  CheckCircle2,
  Clock3,
  Cpu,
  Database,
  RadioTower,
  RefreshCw,
  Server,
  ShieldCheck,
  Target,
  Wifi,
} from 'lucide-react';
import { api } from '@/lib/api';
import type { Incident, SecurityEvent } from '@/types/api';

type TimeRange = '24H' | '7D' | '30D';

type AssetSummary = {
  total_assets: number;
  critical_assets: number;
  internet_facing_assets: number;
  offline_assets: number;
  high_risk_assets: number;
  production_assets: number;
  managed_assets: number;
  retired_assets: number;
  stale_inventory_assets: number;
};

type VulnerabilityAlert = {
  id: number;
  agent_id: string;
  cve_id: string;
  severity: string;
  title: string;
  risk_score: number;
  acknowledged: boolean;
  created_at: string;
};

const EMPTY_ASSETS: AssetSummary = {
  total_assets: 0,
  critical_assets: 0,
  internet_facing_assets: 0,
  offline_assets: 0,
  high_risk_assets: 0,
  production_assets: 0,
  managed_assets: 0,
  retired_assets: 0,
  stale_inventory_assets: 0,
};

const MAP_POINTS = [
  { left: '23%', top: '41%' },
  { left: '43%', top: '34%' },
  { left: '57%', top: '43%' },
  { left: '70%', top: '49%' },
  { left: '79%', top: '68%' },
];

const windowMs = (range: TimeRange) =>
  range === '24H' ? 86_400_000 : range === '7D' ? 604_800_000 : 2_592_000_000;

function ActivityChart({ incidents, timeRange }: { incidents: Incident[]; timeRange: TimeRange }) {
  const chartData = useMemo(() => {
    const buckets = timeRange === '24H' ? 24 : timeRange === '7D' ? 7 : 15;
    const counts = new Array(buckets).fill(0);
    const now = Date.now();
    const span = windowMs(timeRange);

    incidents.forEach((incident) => {
      const age = now - new Date(incident.created_at).getTime();
      if (age < 0 || age > span) return;
      const bucket = Math.min(buckets - 1, Math.floor(((span - age) / span) * buckets));
      counts[bucket] += 1;
    });

    const max = Math.max(...counts, 1);
    return counts.map((count, index) => ({
      count,
      height: Math.max(4, (count / max) * 100),
      label:
        timeRange === '24H'
          ? index % 4 === 0
            ? `${String(index).padStart(2, '0')}:00`
            : ''
          : timeRange === '7D'
            ? `D${index + 1}`
            : index % 3 === 0
              ? `D${index * 2 + 1}`
              : '',
    }));
  }, [incidents, timeRange]);

  return (
    <div className="soc-chart">
      <div className="soc-chart-grid"><i /><i /><i /><i /></div>
      <div className="soc-bars">
        {chartData.map((item, index) => (
          <div className="soc-bar-wrap" key={index} title={`${item.count} incident`}>
            <div className="soc-bar" style={{ height: `${item.height}%` }} />
            <span>{item.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ThreatMap({ sources }: { sources: [string, number][] }) {
  return (
    <div className="soc-map">
      <svg className="soc-world" viewBox="0 0 1000 460" aria-hidden="true">
        <path className="gridline" d="M0 115H1000M0 230H1000M0 345H1000M250 0V460M500 0V460M750 0V460" />
        <path d="M78 122l48-45 66-13 63 17 32 34 41 5 22 28-24 38-44 20-28 47-45 6-34-31-45-12-22-43-38-16z" />
        <path d="M278 270l38 9 31 42-4 55-23 54-20-5-14-46-20-47z" />
        <path d="M440 106l43-22 46 8 27 25 27-8 34 12 28 35 54 8 42 34-15 35-51 9-21 38-52-7-31 26-45-17-11-39-39-16-30-43-26-9 9-44z" />
        <path d="M490 246l50 14 45 34-2 57-30 65-41-13-21-50-18-56z" />
        <path d="M742 315l44-24 56 8 41 32-8 35-48 15-49-14-29-24z" />
        <path d="M384 118l18-19 17 9-2 22-22 5zM865 195l18-12 16 15-9 17z" />
        {sources.slice(0, 4).map((_, index) => {
          const x1 = [230, 430, 570, 700][index];
          const y1 = [190, 155, 195, 220][index];
          return <path key={index} className="soc-arc" d={`M${x1} ${y1} Q500 ${45 + index * 18} 620 205`} />;
        })}
      </svg>

      {sources.slice(0, 5).map(([ip, count], index) => (
        <div key={ip} style={{ position: 'absolute', ...MAP_POINTS[index] }}>
          <span className="soc-map-point" />
          <div className="soc-map-label"><b>{ip}</b><strong>{count} incident</strong><br />source telemetry</div>
        </div>
      ))}

      {!sources.length && <div className="soc-map-empty">Hozircha source IP telemetriyasi mavjud emas.</div>}
      <div className="soc-map-legend">
        <span><i className="crit" />Kritik</span><span><i className="high" />Yuqori</span>
      </div>
      <div className="soc-map-note">Geo nuqtalar vizual · source IP ma’lumoti real</div>
    </div>
  );
}

export default function Dashboard() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [assets, setAssets] = useState<AssetSummary>(EMPTY_ASSETS);
  const [vulnAlerts, setVulnAlerts] = useState<VulnerabilityAlert[]>([]);
  const [timeRange, setTimeRange] = useState<TimeRange>('24H');
  const [loading, setLoading] = useState(true);
  const [errors, setErrors] = useState<string[]>([]);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const results = await Promise.allSettled([
      api<Incident[]>('/incidents?limit=250'),
      api<SecurityEvent[]>('/events?limit=250'),
      api<AssetSummary>('/agents/summary'),
      api<VulnerabilityAlert[]>('/vulnerability-alerts?unacknowledged_only=true&limit=100'),
    ]);

    const nextErrors: string[] = [];
    if (results[0].status === 'fulfilled') setIncidents(results[0].value);
    else nextErrors.push('incidents');
    if (results[1].status === 'fulfilled') setEvents(results[1].value);
    else nextErrors.push('events');
    if (results[2].status === 'fulfilled') setAssets(results[2].value);
    else nextErrors.push('assets');
    if (results[3].status === 'fulfilled') setVulnAlerts(results[3].value);
    else nextErrors.push('vulnerabilities');

    setErrors(nextErrors);
    setLastRefresh(new Date());
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, 15_000);
    return () => clearInterval(timer);
  }, [load]);

  const filtered = useMemo(() => {
    const now = Date.now();
    const span = windowMs(timeRange);
    return incidents.filter((incident) => {
      const age = now - new Date(incident.created_at).getTime();
      return age >= 0 && age <= span;
    });
  }, [incidents, timeRange]);

  const counts = useMemo(
    () => ({
      critical: filtered.filter((item) => item.severity === 'CRITICAL').length,
      high: filtered.filter((item) => item.severity === 'HIGH').length,
      medium: filtered.filter((item) => item.severity === 'MEDIUM').length,
      low: filtered.filter((item) => item.severity === 'LOW').length,
      active: filtered.filter((item) => item.status === 'OPEN' || item.status === 'INVESTIGATING').length,
    }),
    [filtered]
  );

  const recentEvents = useMemo(() => {
    const now = Date.now();
    const span = windowMs(timeRange);
    return events.filter((event) => {
      const age = now - new Date(event.timestamp).getTime();
      return age >= 0 && age <= span;
    });
  }, [events, timeRange]);

  const highVulns = vulnAlerts.filter((item) => item.severity === 'CRITICAL' || item.severity === 'HIGH').length;
  const riskIndex = Math.min(100, Math.round(
    counts.critical * 12 + counts.high * 7 + counts.active * 4 + assets.high_risk_assets * 5 + highVulns * 3
  ));
  const securityScore = Math.max(0, 100 - riskIndex);
  const managedCoverage = assets.total_assets ? Math.round((assets.managed_assets / assets.total_assets) * 100) : 0;

  const sources = Array.from(
    filtered
      .filter((item) => item.source_ip)
      .reduce<Map<string, number>>(
        (map, item) => map.set(item.source_ip!, (map.get(item.source_ip!) || 0) + 1),
        new Map()
      )
      .entries()
  ).sort((a, b) => b[1] - a[1]).slice(0, 5);

  const totalSeverity = Math.max(counts.critical + counts.high + counts.medium + counts.low, 1);
  const pct = (value: number) => Math.round((value / totalSeverity) * 100);
  const recentIncidents = [...filtered]
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, 6);

  const serviceHealth = [
    { name: 'Telemetriya API', icon: <Server />, degraded: errors.length > 0 },
    { name: 'Hodisalar oqimi', icon: <RadioTower />, degraded: errors.includes('events') },
    { name: 'Asset inventory', icon: <Cpu />, degraded: errors.includes('assets') },
    { name: 'CVE monitor', icon: <Database />, degraded: errors.includes('vulnerabilities') },
  ];

  return (
    <main className="soc-dashboard">
      <section className="soc-hero">
        <div>
          <div className="soc-kicker">SECURITY OPERATIONS CENTER</div>
          <h1>Xush kelibsiz, To‘lqin <span>👋</span></h1>
          <p>Real-time tahdidlar, hodisalar, endpointlar va zaifliklar bitta operatsion markazda.</p>
        </div>
        <div className="soc-hero-meta">
          <div className="soc-quote"><strong>SANITIALX</strong>Better detection. A safer tomorrow.</div>
          <div className="soc-live"><i />LIVE</div>
          <button className="soc-refresh" onClick={load} disabled={loading}><RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Yangilash</button>
        </div>
      </section>

      {errors.length > 0 && <div className="soc-warning">Qisman telemetriya mavjud emas: {errors.join(', ')}.</div>}

      <section className="soc-stats">
        <Stat variant="cyan" icon={<ShieldCheck />} label="Xavfsizlik holati" value={String(securityScore)} suffix="/100" trend={`${100 - riskIndex}% himoya indeksi`} />
        <Stat variant="red" icon={<AlertTriangle />} label="Kritik hodisalar" value={String(counts.critical)} trend={`${counts.active} faol hodisa`} />
        <Stat variant="orange" icon={<Target />} label="Faol zaifliklar" value={String(vulnAlerts.length)} trend={`${highVulns} yuqori / kritik`} />
        <Stat variant="purple" icon={<Cpu />} label="Endpoint agentlar" value={String(assets.total_assets)} trend={`${managedCoverage}% boshqarilmoqda`} />
      </section>

      <section className="soc-stage">
        <div className="soc-panel">
          <div className="soc-panel-head">
            <div><h2>Global Threat Map</h2><p>Source IP telemetriyasi va real incident oqimi</p></div>
            <div className="range">
              {(['24H', '7D', '30D'] as TimeRange[]).map((range) => (
                <button key={range} className={timeRange === range ? 'active' : ''} onClick={() => setTimeRange(range)}>{range}</button>
              ))}
            </div>
          </div>
          <ThreatMap sources={sources} />
        </div>

        <div className="soc-stack">
          <div className="soc-panel soc-ai">
            <div className="soc-ai-top">
              <div className="soc-ai-bot"><Brain size={23} /></div>
              <div><h3>AI SOC Analyst</h3><p>Hodisa va tahdidlarni AI yordamida tahlil qiling, keyingi qadamlarni tezroq toping.</p></div>
            </div>
            <a href="/ai-analysis" className="soc-ai-button"><span>AI tahlilni ochish</span><i><ArrowRight size={15} /></i></a>
          </div>

          <div className="soc-panel soc-incidents">
            <div className="soc-panel-head"><div><h2>So‘nggi hodisalar</h2><p>Tanlangan vaqt oralig‘i</p></div><a className="soc-panel-link" href="/incidents">Barchasi <ArrowUpRight size={13} /></a></div>
            {recentIncidents.map((incident) => (
              <a href={`/incidents?id=${incident.incident_id}`} className="soc-incident" key={incident.incident_id}>
                <span className={`soc-sev ${incident.severity.toLowerCase()}`}>{incident.severity}</span>
                <div className="soc-incident-copy"><b>{incident.title}</b><span>{incident.source_ip || incident.incident_id}</span></div>
                <time>{new Date(incident.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</time>
              </a>
            ))}
            {!recentIncidents.length && <div className="empty">Faol incident topilmadi.</div>}
          </div>
        </div>
      </section>

      <section className="soc-bottom">
        <div className="soc-panel">
          <div className="soc-panel-head"><div><h2>Hodisa faolligi ({timeRange})</h2><p>Persisted incident timestamp ma’lumotlari</p></div><Activity size={16} color="#1ed8ff" /></div>
          <div className="soc-activity-body"><ActivityChart incidents={filtered} timeRange={timeRange} /></div>
        </div>

        <div className="soc-panel">
          <div className="soc-panel-head"><div><h2>Tahdid darajalari</h2><p>Incident severity taqsimoti</p></div></div>
          <div className="soc-donut-wrap">
            <div style={{ position: 'relative' }}>
              <div className="soc-donut" style={{ '--critical': pct(counts.critical), '--high': pct(counts.high), '--medium': pct(counts.medium) } as React.CSSProperties} />
              <div className="soc-donut-center"><b>{filtered.length}</b><span>Jami</span></div>
            </div>
            <div className="soc-donut-legend">
              <LegendDot color="#ff405c" label="Kritik" value={pct(counts.critical)} />
              <LegendDot color="#ff9d2e" label="Yuqori" value={pct(counts.high)} />
              <LegendDot color="#ffd05a" label="O‘rta" value={pct(counts.medium)} />
              <LegendDot color="#2bbcff" label="Past" value={pct(counts.low)} />
            </div>
          </div>
        </div>

        <div className="soc-panel soc-health-panel">
          <div className="soc-panel-head"><div><h2>Tizim holati</h2><p>Frontend ko‘rayotgan backend servislar</p></div></div>
          <div className="soc-health">
            {serviceHealth.map((service) => (
              <div className="soc-health-row" key={service.name}>
                <div className="soc-health-name">{service.icon}<span>{service.name}</span></div>
                <div className={`soc-health-state ${service.degraded ? 'degraded' : ''}`}><i />{service.degraded ? 'Cheklangan' : 'Ishlayapti'}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="soc-footer">
        <div><Wifi /><span>Telemetriya</span><b className={errors.length ? '' : 'ok'}>{errors.length ? 'Degraded' : 'Operational'}</b></div>
        <div><Activity /><span>Eventlar</span><b>{recentEvents.length}</b></div>
        <div><Clock3 /><span>Yangilangan</span><b>{lastRefresh ? lastRefresh.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—'}</b></div>
        <div><CheckCircle2 /><span>Production asset</span><b className="ok">{assets.production_assets}</b></div>
      </section>
    </main>
  );
}

function LegendDot({ color, label, value }: { color: string; label: string; value: number }) {
  return <div><i style={{ background: color }} /><span>{label}</span><b>{value}%</b></div>;
}

function Stat({ variant, icon, label, value, suffix, trend }: { variant: 'cyan' | 'red' | 'orange' | 'purple'; icon: React.ReactNode; label: string; value: string; suffix?: string; trend: string }) {
  return (
    <div className={`soc-stat ${variant}`}>
      <div className="soc-stat-icon">{icon}</div>
      <div className="soc-stat-copy"><span>{label}</span><strong>{value}<small>{suffix}</small></strong><em>{trend}</em></div>
      <svg className="soc-mini-wave" viewBox="0 0 180 20" preserveAspectRatio="none" aria-hidden="true"><path d="M0 14 L12 9 L25 15 L38 5 L52 13 L65 8 L80 16 L94 10 L110 12 L125 4 L142 14 L158 8 L180 11" fill="none" stroke="currentColor" strokeWidth="1.5" /></svg>
    </div>
  );
}
