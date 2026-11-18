import Link from 'next/link';
import { Check } from 'lucide-react';
import { LandingFooter, LandingNav } from '@/components/landing/landing-chrome';
import { Reveal } from '@/components/landing/reveal';

const plans = [
  { name: 'Starter', price: 'Bepul', note: 'Sinov va kichik jamoalar', hot: false, items: ['5 tagacha endpoint', 'Asosiy detection qoidalari', 'Hodisalar paneli', 'Hodisa hisobotlari'] },
  { name: 'Pro', price: 'Kelishuv', note: 'O\'sib borayotgan SOC', hot: true, items: ['Cheksiz endpoint', 'Tasdiqlanadigan SOAR', 'AI hodisa tahlili', 'Zaiflik va CVE ogohlantirishlari', 'Ustuvor yordam'] },
  { name: 'Enterprise', price: 'Individual', note: 'Katta tashkilotlar', hot: false, items: ['Maxsus qoidalar', 'Alohida joylashtirish', 'SLA kafolati', 'Integratsiya yordami'] },
];

export default function PricingPage() {
  return (
    <div className="lp">
      <div className="lp-bg" aria-hidden><i className="lp-grid" /><i className="lp-orb a" /><i className="lp-orb b" /></div>
      <LandingNav />
      <section className="lp-section lp-pricing-head">
        <Reveal><h2>Sizga mos <em>reja</em></h2><p className="lp-sub">Oddiy va shaffof. Narxlar bo&apos;yicha biz bilan bog&apos;laning.</p></Reveal>
      </section>
      <div className="lp-plans">
        {plans.map((p, i) => (
          <Reveal key={p.name} delay={i * 100}>
            <article className={`lp-plan ${p.hot ? 'hot' : ''}`}>
              {p.hot && <span className="lp-plan-tag">Mashhur</span>}
              <h3>{p.name}</h3><div className="lp-price">{p.price}</div><p>{p.note}</p>
              <ul>{p.items.map((it) => <li key={it}><Check size={15} />{it}</li>)}</ul>
              <Link href="/login" className={`lp-btn ${p.hot ? 'primary' : 'ghost'} lg`}>Boshlash</Link>
            </article>
          </Reveal>
        ))}
      </div>
      <LandingFooter />
    </div>
  );
}
