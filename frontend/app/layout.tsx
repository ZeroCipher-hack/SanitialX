import type { Metadata } from 'next';
import './globals.css';
import './shell-overrides.css';
import { AppShell } from '@/components/app-shell';

export const metadata: Metadata = {
  title: 'SanitialX | Xavfsizlik operatsiyalari',
  description: 'SanitialX xavfsizlik monitoring va tahlil platformasi',
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="uz"><body><AppShell>{children}</AppShell></body></html>;
}
