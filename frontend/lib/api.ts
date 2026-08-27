import type {
  Incident,
  IncidentStatus,
  DetectionRule,
  SecurityEvent,
  Agent,
  HoneypotSession,
  AttackSimulation,
  AttackGraphData,
  InvestigationReport,
} from '@/types/api';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

export async function api<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null;
  const headers = new Headers(options.headers || {});
  headers.set('Content-Type', 'application/json');
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    if (res.status === 401 && typeof window !== 'undefined') {
      localStorage.removeItem('access_token');
    }
    const errData = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(errData.detail || `API error: ${res.status}`);
  }

  return res.json();
}

export async function login(username: string, password: string): Promise<string> {
  const res = await fetch(`${API_BASE}/auth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });

  if (!res.ok) {
    const errData = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(errData.detail || 'Authentication failed');
  }

  const data = await res.json();

  if (typeof window !== 'undefined') {
    localStorage.setItem('access_token', data.access_token);
  }

  return data.access_token;
}

export async function logout(): Promise<void> {
  try {
    await api('/auth/logout', { method: 'POST' });
  } catch (e) {
    console.warn('Backend logout call failed or token expired:', e);
  } finally {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('access_token');
      window.location.href = '/login';
    }
  }
}

export async function updateIncidentStatus(
  incidentId: string,
  newStatus: IncidentStatus,
  expectedVersion: number
): Promise<Incident> {
  return api<Incident>(`/incidents/${incidentId}/status`, {
    method: 'PATCH',
    body: JSON.stringify({
      status: newStatus,
      expected_version: expectedVersion,
    }),
  });
}

export async function updateRule(
  ruleId: string,
  payload: Partial<DetectionRule>
): Promise<DetectionRule> {
  return api<DetectionRule>(`/rules/${ruleId}`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  });
}

export async function fetchEvents(): Promise<SecurityEvent[]> {
  return api<SecurityEvent[]>('/events?limit=100');
}

export async function fetchAgents(): Promise<Agent[]> {
  return api<Agent[]>('/agents');
}

export async function fetchHoneypots(): Promise<HoneypotSession[]> {
  return api<HoneypotSession[]>('/honeypots');
}

export async function fetchSimulations(): Promise<AttackSimulation[]> {
  return api<AttackSimulation[]>('/simulations');
}

export async function runAttackSimulation(scenarioName: string = 'WEB_APP_COMPROMISE'): Promise<AttackSimulation> {
  return api<AttackSimulation>('/simulations/run', {
    method: 'POST',
    body: JSON.stringify({ scenario_name: scenarioName }),
  });
}

export async function fetchAttackGraph(incidentId: string): Promise<AttackGraphData> {
  return api<AttackGraphData>(`/attack-graph/${incidentId}`);
}

export async function fetchReports(): Promise<InvestigationReport[]> {
  return api<InvestigationReport[]>('/reports');
}

export async function fetchReportDetail(incidentId: string): Promise<InvestigationReport> {
  return api<InvestigationReport>(`/reports/${incidentId}`);
}
