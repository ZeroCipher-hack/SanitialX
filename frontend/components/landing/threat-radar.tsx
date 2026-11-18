'use client';

import { useEffect, useRef, useState } from 'react';
import { ShieldCheck } from 'lucide-react';

type Threat = { name: string; status: string; tone: 'red' | 'yel' | 'grn' };

const THREATS: Threat[] = [
  { name: 'SSH brute-force', status: 'BLOKLANDI', tone: 'red' },
  { name: 'Port scan', status: 'TEKSHIRUVDA', tone: 'yel' },
  { name: 'SMB harakati', status: 'TASDIQ KUTILMOQDA', tone: 'grn' },
  { name: 'RDP brute-force', status: 'BLOKLANDI', tone: 'red' },
  { name: 'Honeypot ulanishi', status: 'IZOLYATSIYA', tone: 'yel' },
  { name: 'Zaif dastur (CVE)', status: 'OGOHLANTIRISH', tone: 'grn' },
];

/** Hero radar: chips rotate through threats, a ripple fires on each change, and the radar tilts toward the pointer. */
export function ThreatRadar() {
  const ref = useRef<HTMLDivElement>(null);
  const [idx, setIdx] = useState([0, 1, 2]);
  const [ripple, setRipple] = useState(0);
  const [reduce, setReduce] = useState(true);

  useEffect(() => {
    setReduce(window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  }, []);

  useEffect(() => {
    if (reduce) return;
    let slot = 0;
    const t = setInterval(() => {
      setIdx((cur) => {
        const next = [...cur];
        let candidate = (Math.max(...cur) + 1) % THREATS.length;
        while (cur.includes(candidate)) candidate = (candidate + 1) % THREATS.length;
        next[slot % 3] = candidate;
        slot += 1;
        return next;
      });
      setRipple((n) => n + 1);
    }, 3200);
    return () => clearInterval(t);
  }, [reduce]);

  useEffect(() => {
    if (reduce) return;
    const el = ref.current;
    if (!el) return;
    const move = (e: PointerEvent) => {
      const r = el.getBoundingClientRect();
      const x = (e.clientX - (r.left + r.width / 2)) / window.innerWidth;
      const y = (e.clientY - (r.top + r.height / 2)) / window.innerHeight;
      el.style.setProperty('--rx', `${(-y * 14).toFixed(2)}deg`);
      el.style.setProperty('--ry', `${(x * 18).toFixed(2)}deg`);
    };
    const leave = () => { el.style.setProperty('--rx', '0deg'); el.style.setProperty('--ry', '0deg'); };
    window.addEventListener('pointermove', move);
    document.addEventListener('pointerleave', leave);
    return () => { window.removeEventListener('pointermove', move); document.removeEventListener('pointerleave', leave); };
  }, [reduce]);

  return (
    <div className="lp-radar" ref={ref} aria-hidden>
      <i className="ring r1" /><i className="ring r2" /><i className="ring r3" />
      <i className="ticks" /><i className="dash" />
      <i className="cross h" /><i className="cross v" />
      <i className="sweep" />
      <i className="orbit o1"><b /></i><i className="orbit o2"><b /></i><i className="orbit o3"><b /></i>
      <svg className="links" viewBox="0 0 100 100"><path d="M50 50 L66 24 M50 50 L26 66 M50 50 L70 72" /></svg>
      <i className="blip b1" /><i className="blip b2" /><i className="blip b3" />
      <i key={ripple} className="wave" />
      {idx.map((t, i) => {
        const th = THREATS[t];
        return (
          <span key={`${i}-${t}`} className={`chip c${i + 1}`}>
            <span><i className={`dot ${th.tone}`} />{th.name}</span>
            <small>{th.status}</small>
          </span>
        );
      })}
      <span className="core"><ShieldCheck size={30} /></span>
    </div>
  );
}
