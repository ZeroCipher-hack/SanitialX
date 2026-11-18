import Link from 'next/link';
import { Shield } from 'lucide-react';

export function LandingNav() {
  return (
    <header className="lp-nav">
      <Link href="/" className="lp-logo"><span className="lp-logo-mark"><Shield size={18} /></span><span>SANITIAL<b>X</b></span></Link>
      <nav className="lp-nav-links">
        <a href="/#features">Imkoniyatlar</a>
        <a href="/#flow">Qanday ishlaydi</a>
        <Link href="/pricing">Narxlar</Link>
      </nav>
      <div className="lp-nav-cta">
        <Link href="/login" className="lp-btn outline">Kirish</Link>
        <Link href="/pricing" className="lp-btn primary">Boshlash</Link>
      </div>
    </header>
  );
}

export function LandingFooter() {
  return (
    <footer className="lp-footer">
      <span>© {new Date().getFullYear()} SanitialX. Barcha huquqlar himoyalangan.</span>
      <span><Link href="/login">Kirish</Link> · <Link href="/pricing">Narxlar</Link></span>
    </footer>
  );
}
