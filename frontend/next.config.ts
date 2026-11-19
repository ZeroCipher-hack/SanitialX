import type { NextConfig } from 'next';

// The browser may only call the configured API origin (CSP connect-src), so derive it from the same
// variable the app uses instead of hard-coding hosts. Falls back to the built-in defaults when unset.
const apiOrigin = (() => {
  try {
    return new URL(process.env.NEXT_PUBLIC_API_URL || '').origin;
  } catch {
    return '';
  }
})();

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,

  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Content-Security-Policy',
            value:
              "default-src 'self'; " +
              "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
              "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
              "font-src 'self' https://fonts.gstatic.com data:; " +
              "img-src 'self' data: blob:; " +
              `connect-src 'self' https://sanitialx-backend.onrender.com http://localhost:8000 ${apiOrigin} ws://localhost:3000; ` +
              "frame-ancestors 'none'; " +
              "base-uri 'self'; " +
              "form-action 'self'",
          },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          {
            key: 'Permissions-Policy',
            value: 'geolocation=(), camera=(), microphone=()',
          },
        ],
      },
    ];
  },
};

export default nextConfig;
