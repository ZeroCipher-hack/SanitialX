import Link from 'next/link';
import { Activity, ArrowRight, Bot, Bug, FileText, Radar, Siren, Workflow } from 'lucide-react';
import { LandingFooter, LandingNav } from '@/components/landing/landing-chrome';
import { Counter, Reveal } from '@/components/landing/reveal';
import { ThreatRadar } from '@/components/landing/threat-radar';

const features = [
  { icon: Radar, title: 'Real vaqt aniqlash', text: 'Tarmoq hodisalari normallashtiriladi va port skanerlash, SSH/RDP brute-force, SMB harakati kabi hujumlar soniyalarda topiladi.' },
  { icon: Siren, title: 'Hodisalarni boshqarish', text: 'Har bir ogohlantirish MITRE ATT&CK bilan bog\'langan hodisaga aylanadi: jarayon, dalil va vaqt chizig\'i bir joyda.' },
  { icon: Workflow, title: 'Tasdiqlanadigan SOAR', text: 'Javob amallari avval tasdiqlanadi, keyin agent orqali xavfsiz bajariladi. Hech narsa nazoratsiz ishlamaydi.' },
  { icon: Bug, title: 'Zaiflik kuzatuvi', text: 'Endpoint dasturlari inventarizatsiyasi CVE bilan solishtiriladi va muhim zaifliklar haqida darhol xabar beradi.' },
  { icon: Bot, title: 'AI tahlil', text: 'Gemini hodisani tushuntirib beradi va keyingi qadamlarni taklif qiladi. Kalit faqat serverda saqlanadi.' },
  { icon: FileText, title: 'Professional hisobotlar', text: 'Bir bosishda bosmaga tayyor SOC hodisa hisoboti: xulosa, xronologiya va tavsiyalar.' },
];

const steps = [
  { n: '01', title: 'Yig\'ish', text: 'Sensorlar va agentlar telemetriyani yuboradi.' },
  { n: '02', title: 'Korrelyatsiya', text: 'Qoidalar va ketma-ketliklar hujumni aniqlaydi.' },
  { n: '03', title: 'Tahlil', text: 'Hodisa boyitiladi, AI sharh beradi.' },
  { n: '04', title: 'Javob', text: 'Tasdiqdan so\'ng amal xavfsiz bajariladi.' },
];

const stats = [
  { to: 6, suffix: '', label: 'Detection qoidalari' },
  { to: 100, suffix: '%', label: 'Tasdiqlanadigan javob' },
  { to: 24, suffix: '/7', label: 'Doimiy monitoring' },
  { to: 0, suffix: '', label: 'Vendorga avtomatik yuboriladigan ma’lumot' },
];

export default function LandingPage() {
  return (
    <div className="lp">
      <div className="lp-bg" aria-hidden><i className="lp-grid" /><i className="lp-orb a" /><i className="lp-orb b" /></div>
      <LandingNav />

      <section className="lp-hero">
        <div className="lp-hero-copy">
          <span className="lp-badge"><Activity size={14} /> Xavfsizlik operatsiyalari platformasi</span>
          <h1>Hujumni <em>soniyalarda</em> toping, <em>xavfsiz</em> to&apos;xtating.</h1>
          <p>SanitialX tarmoq hodisalarini yig&apos;adi, tahdidlarni korrelyatsiya qiladi va tasdiqlanadigan avtomatik javobni boshqaradi. Bir paneldan.</p>
          <div className="lp-hero-cta">
            <Link href="/login" className="lp-btn primary lg">Panelga kirish <ArrowRight size={16} /></Link>
            <Link href="/pricing" className="lp-btn outline lg">Narxlarni ko&apos;rish</Link>
          </div>
        </div>
        <ThreatRadar />
      </section>

      <div className="lp-marquee" aria-hidden>
        <div className="lp-marquee-track">
          {[0, 1].map((k) => (
            <span key={k}>PORT SCAN · SSH BRUTE-FORCE · RDP BRUTE-FORCE · SMB LATERAL MOVEMENT · HONEYPOT · MITRE ATT&amp;CK · SOAR · CVE · </span>
          ))}
        </div>
      </div>

      <section className="lp-stats">
        {stats.map((s, i) => (
          <Reveal key={s.label} delay={i * 80}>
            <div className="lp-stat"><b><Counter to={s.to} suffix={s.suffix} /></b><span>{s.label}</span></div>
          </Reveal>
        ))}
      </section>

      <section id="features" className="lp-section">
        <Reveal><h2>Hamma kerakli narsa <em>bitta</em> joyda</h2><p className="lp-sub">Aniqlashdan hisobotgacha to&apos;liq SOC jarayoni.</p></Reveal>
        <div className="lp-cards">
          {features.map((f, i) => (
            <Reveal key={f.title} delay={(i % 3) * 90}>
              <article className="lp-card"><span className="lp-card-icon"><f.icon size={22} /></span><h3>{f.title}</h3><p>{f.text}</p></article>
            </Reveal>
          ))}
        </div>
      </section>

      <section id="flow" className="lp-section">
        <Reveal><h2>Qanday <em>ishlaydi</em></h2></Reveal>
        <div className="lp-steps">
          {steps.map((s, i) => (
            <Reveal key={s.n} delay={i * 110}>
              <div className="lp-step"><b>{s.n}</b><h3>{s.title}</h3><p>{s.text}</p></div>
            </Reveal>
          ))}
        </div>
      </section>

      <Reveal>
        <section className="lp-cta">
          <h2>Xavfsizlikni nazoratga oling</h2>
          <p>Hoziroq kiring va birinchi hodisani real vaqtda kuzating.</p>
          <Link href="/login" className="lp-btn primary lg">Boshlash <ArrowRight size={16} /></Link>
        </section>
      </Reveal>
      <LandingFooter />
    </div>
  );
}
