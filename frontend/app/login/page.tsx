'use client';

import { FormEvent, useState } from 'react';
import { Shield, ArrowRight, LockKeyhole } from 'lucide-react';
import { login } from '@/lib/api';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();

    if (loading) return;

    setError('');
    setLoading(true);

    try {
      const token = await login(username.trim(), password);

      if (!token) {
        throw new Error('Authentication succeeded but no access token was returned.');
      }

      const savedToken = localStorage.getItem('access_token');

      if (!savedToken) {
        throw new Error('Authentication succeeded but the access token could not be stored.');
      }

      window.location.assign('/dashboard');
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Authentication failed'
      );
      setLoading(false);
    }
  }

  return (
    <div className="login-page">
      <div className="login-glow" />

      <div className="login-card">
        <div className="login-brand">
          <div className="brand-mark">
            <Shield size={22} />
          </div>

          <div>
            <b>
              SANITIEL<span>X</span>
            </b>
            <small>SECURITY PLATFORM</small>
          </div>
        </div>

        <div className="login-title">
          <div className="eyebrow">SECURE ACCESS</div>
          <h1>Command Center</h1>
          <p>Sign in to monitor and respond to security events.</p>
        </div>

        <form onSubmit={submit}>
          <label>
            Username
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              disabled={loading}
            />
          </label>

          <label>
            Password
            <input
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              type="password"
              autoComplete="current-password"
              placeholder="Enter password"
              disabled={loading}
            />
          </label>

          {error && <div className="form-error">{error}</div>}

          <button
            type="submit"
            className="login-button"
            disabled={loading}
          >
            {loading ? 'Authenticating...' : 'Enter command center'}
            {!loading && <ArrowRight size={16} />}
          </button>
        </form>

        <div className="login-note">
          <LockKeyhole size={14} />
          JWT protected API session
        </div>
      </div>
    </div>
  );
}
