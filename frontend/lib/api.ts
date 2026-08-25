const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000/api/v1';
let token: string | null = null;

export function setToken(value: string) {
  token = value;
  if (typeof window !== 'undefined') localStorage.setItem('sanitialx_token', value);
}
export function getToken() {
  if (token) return token;
  if (typeof window !== 'undefined') token = localStorage.getItem('sanitialx_token');
  return token;
}
export function clearToken() {
  token = null;
  if (typeof window !== 'undefined') localStorage.removeItem('sanitialx_token');
}
export async function api<T>(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  if (!(init.body instanceof FormData)) headers.set('Content-Type', 'application/json');
  const t = getToken();
  if (t) headers.set('Authorization', `Bearer ${t}`);
  const res = await fetch(`${API_URL}${path}`, { ...init, headers, cache: 'no-store' });
  if (res.status === 401) {
    if (typeof window !== 'undefined') window.location.href = '/login';
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    let message = `Request failed (${res.status})`;
    try { const body = await res.json(); message = body.detail ?? message; } catch {}
    throw new Error(message);
  }
  return res.json() as Promise<T>;
}
export async function login(username: string, password: string) {
  const result = await api<{access_token:string; token_type:string; role:string}>('/auth/token', {
    method: 'POST', body: JSON.stringify({ username, password })
  });
  setToken(result.access_token);
  if (typeof window !== 'undefined') localStorage.setItem('sanitialx_role', result.role);
  return result;
}
