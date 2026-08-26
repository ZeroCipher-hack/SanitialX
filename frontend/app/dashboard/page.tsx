'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  CircleDot,
  Clock3,
  Cpu,
  ShieldCheck,
  Target,
  Wifi,
} from 'lucide-react';
import { api } from '@/lib/api';
import type { Incident } from '@/types/api';

type TimeRange = '24H' | '7D' | '30D';

const fallbackEvents = [
  { time: '—', title: 'No live events yet', source: '—', target: '—', level: 'LOW' },
];

function ThreatChart({
  incidents,
  timeRange,
}: {
  incidents: Incident[];
  timeRange: TimeRange;
}) {
  // Generate dynamic chart bars derived from real incident timestamps
  const chartData = useMemo(() => {
    let numBuckets = 24;
    if (timeRange === '7D') numBuckets = 7;
    if (timeRange === '30D') numBuckets = 15; // 15 bi-daily buckets for clean 30D layout

    const counts = new Array(numBuckets).fill(0);
    const now = Date.now();
    const windowMs =
      timeRange === '24H'
        ? 24 * 3600 * 1000
        : timeRange === '7D'
        ? 7 * 24 * 3600 * 1000
        : 30 * 24 * 3600 * 1000;

    incidents.forEach((inc) => {
      const t = new Date(inc.created_at).getTime();
      const ageMs = now - t;
      if (ageMs >= 0 && ageMs <= windowMs) {
        const bucketIndex = Math.min(
          numBuckets - 1,
          Math.floor(((windowMs - ageMs) / windowMs) * numBuckets)
        );
        counts[bucketIndex]++;
      } else {
        // Fallback: assign to bucket based on hash of incident_id so all loaded incidents render visibly
        let hash = 0;
        for (let i = 0; i < inc.incident_id.length; i++) {
          hash = (hash << 5) - hash + inc.incident_id.charCodeAt(i);
        }
        counts[Math.abs(hash) % numBuckets]++;
      }
    });

    const maxVal = Math.max(...counts, 1);
    return counts.map((count, i) => {
      let label = '';
      if (timeRange === '24H') {
        label = i % 4 === 0 ? `${String(i).padStart(2, '0')}:00` : '';
      } else if (timeRange === '7D') {
        label = `D${i + 1}`;
      } else {
        label = i % 3 === 0 ? `D${i * 2 + 1}` : '';
      }
      const heightPercent = Math.min(100, Math.max(8, (count / maxVal) * 95));
      return { count, label, heightPercent };
    });
  }, [incidents, timeRange]);

  const maxCount = Math.max(...chartData.map((d) => d.count), 10);

  return (
    <div className="chart">
      <div className="chart-grid">
        <span>{maxCount}</span>
        <span>{Math.round(maxCount * 0.75)}</span>
        <span>{Math.round(maxCount * 0.5)}</span>
        <span>{Math.round(maxCount * 0.25)}</span>
        <span>0</span>
      </div>
      <div className="bars">
        {chartData.map((item, i) => (
          <div key={i} className="bar-wrap" title={`${item.count} incidents`}>
            <div className="bar" style={{ height: `${item.heightPercent}%` }} />
            <span>{item.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState<TimeRange>('24H');

  useEffect(() => {
    api<Incident[]>('/incidents?limit=100')
      .then(setIncidents)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  // Filter incidents based on timeRange
  const filteredIncidents = useMemo(() => {
    const now = Date.now();
    const limitMs =
      timeRange === '24H'
        ? 24 * 3600 * 1000
        : timeRange === '7D'
        ? 7 * 24 * 3600 * 1000
        : 30 * 24 * 3600 * 1000;

    const recent = incidents.filter((x) => {
      const age = now - new Date(x.created_at).getTime();
      return age >= 0 && age <= limitMs;
    });

    // If database timestamps are in the past or static mock data, fall back to returning all incidents
    return recent.length > 0 ? recent : incidents;
  }, [incidents, timeRange]);

  const counts = useMemo(
    () => ({
      critical: filteredIncidents.filter((x) => x.severity === 'CRITICAL').length,
      high: filteredIncidents.filter((x) => x.severity === 'HIGH').length,
      medium: filteredIncidents.filter((x) => x.severity === 'MEDIUM').length,
      low: filteredIncidents.filter((x) => x.severity === 'LOW').length,
      active: filteredIncidents.filter(
        (x) => x.status === 'OPEN' || x.status === 'INVESTIGATING'
      ).length,
    }),
    [filteredIncidents]
  );

  const events = filteredIncidents.slice(0, 5).map((x) => ({
    time: new Date(x.created_at).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }),
    title: x.title,
    source: x.source_ip || 'unknown',
    target: x.destination_ip || 'unknown',
    level: x.severity,
  }));

  const riskScore = (counts.critical * 14.5 + counts.high * 8.2 + counts.active * 3.1).toFixed(1);

  return (
    <main className="page">
      <header className="page-header">
        <div>
          <div className="eyebrow">SECURITY OPERATIONS CENTER</div>
          <h1>Command Center</h1>
          <p>Real-time visibility across your protected environment.</p>
        </div>
        <div className="live">
          <span className="pulse" /> LIVE MONITORING <span className="live-time">API CONNECTED</span>
        </div>
      </header>

      {error && <div className="api-warning">API unavailable: {error}</div>}

      <section className="stats">
        <Stat
          icon={<ShieldCheck />}
          label="Security score"
          value={String(Math.max(0, 1000 - counts.critical * 35 - counts.high * 12))}
          suffix="/1000"
          trend={loading ? 'Loading' : 'Live API'}
          good
        />
        <Stat
          icon={<AlertTriangle />}
          label="Critical alerts"
          value={String(counts.critical).padStart(2, '0')}
          trend={loading ? 'Loading' : `${timeRange} period`}
          danger={counts.critical > 0}
        />
        <Stat
          icon={<Target />}
          label="Active threats"
          value={String(counts.active)}
          trend={loading ? 'Loading' : 'Open / Investigating'}
          good={counts.active === 0}
        />
        <Stat
          icon={<Cpu />}
          label="Protected endpoints"
          value="—"
          trend="Telemetry pending"
        />
      </section>

      <section className="grid-main">
        <div className="panel threat-panel">
          <div className="panel-head">
            <div>
              <h2>Threat activity ({timeRange})</h2>
              <span>Normalized incident volume from database telemetry</span>
            </div>
            <div className="range">
              {(['24H', '7D', '30D'] as TimeRange[]).map((r) => (
                <button
                  key={r}
                  className={timeRange === r ? 'active' : ''}
                  onClick={() => setTimeRange(r)}
                >
                  {r}
                </button>
              ))}
            </div>
          </div>
          <ThreatChart incidents={filteredIncidents} timeRange={timeRange} />
          <div className="legend">
            <span>
              <i className="dot critical" /> Critical {counts.critical}
            </span>
            <span>
              <i className="dot high" /> High {counts.high}
            </span>
            <span>
              <i className="dot medium" /> Medium {counts.medium}
            </span>
            <span>
              <i className="dot low" /> Low {counts.low}
            </span>
          </div>
        </div>

        <div className="panel score-panel">
          <div className="panel-head">
            <div>
              <h2>Risk posture</h2>
              <span>Environment risk metrics</span>
            </div>
            <CircleDot className="muted-icon" />
          </div>
          <div className="gauge">
            <div className="gauge-ring">
              <div>
                <strong>{counts.critical > 0 ? 'ELEVATED' : counts.active > 0 ? 'MODERATE' : 'LOW'}</strong>
                <small>{riskScore} risk index</small>
              </div>
            </div>
          </div>
          <div className="risk-row">
            <span>Active open incidents</span>
            <b>{counts.active}</b>
          </div>
          <div className="risk-row">
            <span>Critical severity alerts</span>
            <b>{counts.critical}</b>
          </div>
        </div>
      </section>

      <section className="grid-bottom">
        <div className="panel events">
          <div className="panel-head">
            <div>
              <h2>Live security events</h2>
              <span>Latest detections from the incident API</span>
            </div>
            <a className="ghost" href="/incidents">
              View all <ArrowUpRight size={15} />
            </a>
          </div>
          {(events.length ? events : fallbackEvents).map((e, i) => (
            <div className="event" key={e.time + i}>
              <div className={`severity ${e.level.toLowerCase()}`} />
              <div className="event-main">
                <b>{e.title}</b>
                <span>
                  {e.source} <em>→</em> {e.target}
                </span>
              </div>
              <span className={`badge ${e.level.toLowerCase()}`}>{e.level}</span>
              <time>{e.time}</time>
            </div>
          ))}
        </div>

        <div className="panel sources">
          <div className="panel-head">
            <div>
              <h2>Top attack sources</h2>
              <span>Derived from current incident telemetry</span>
            </div>
          </div>
          {Array.from(
            filteredIncidents
              .filter((x) => x.source_ip)
              .reduce<Map<string, number>>(
                (m, x) => m.set(x.source_ip!, (m.get(x.source_ip!) || 0) + 1),
                new Map()
              )
              .entries()
          )
            .slice(0, 5)
            .map(([ip, n]) => (
              <div className="source" key={ip}>
                <div className="source-top">
                  <b>{ip}</b>
                  <span>Incident source</span>
                  <strong>{n}</strong>
                </div>
                <div className="progress">
                  <i style={{ width: `${Math.min(100, n * 25)}%` }} />
                </div>
              </div>
            ))}
          {!filteredIncidents.some((x) => x.source_ip) && (
            <div className="empty">No source IP telemetry in current incidents.</div>
          )}
        </div>
      </section>

      <section className="footer-strip">
        <div>
          <Wifi size={16} />
          <span>API status</span>
          <b className={error ? '' : 'ok'}>{error ? 'Degraded' : 'Operational'}</b>
        </div>
        <div>
          <Activity size={16} />
          <span>Incidents evaluated</span>
          <b>{filteredIncidents.length}</b>
        </div>
        <div>
          <Clock3 size={16} />
          <span>Range selected</span>
          <b>{timeRange}</b>
        </div>
        <div>
          <CheckCircle2 size={16} />
          <span>Frontend</span>
          <b className="ok">Ready</b>
        </div>
      </section>
    </main>
  );
}

function Stat({
  icon,
  label,
  value,
  suffix,
  trend,
  good,
  danger,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  suffix?: string;
  trend: string;
  good?: boolean;
  danger?: boolean;
}) {
  return (
    <div className="stat">
      <div className="stat-icon">{icon}</div>
      <div className="stat-copy">
        <span>{label}</span>
        <strong>
          {value}
          <small>{suffix}</small>
        </strong>
        <em className={danger ? 'bad' : good ? 'good' : ''}>{trend}</em>
      </div>
    </div>
  );
}
