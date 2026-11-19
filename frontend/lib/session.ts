/** Role from the stored JWT. UI hint only: the backend enforces permissions. */
export function currentRole(): string {
  if (typeof window === 'undefined') return '';
  try {
    const token = localStorage.getItem('access_token');
    if (!token) return '';
    const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    return typeof payload.role === 'string' ? payload.role : '';
  } catch {
    return '';
  }
}
