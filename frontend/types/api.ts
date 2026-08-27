export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'CLOSED';

export interface Incident {
  incident_id: string;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  version: number;
  created_at: string;
  updated_at: string;
  source_ip?: string;
  destination_ip?: string;
  triggering_detection_ids: string[];
  context: Record<string, unknown>;
}

export interface DetectionRule {
  rule_id: string;
  rule_name: string;
  description?: string;
  severity: string;
  enabled: boolean;
  parameters: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  event_type: string;
  severity: Severity;
  source_ip?: string;
  destination_ip?: string;
  user?: string;
  host?: string;
  rule_id?: string;
  mitre_technique?: string;
  details?: string;
  raw_payload?: Record<string, unknown>;
}

export interface Agent {
  agent_id: string;
  hostname: string;
  ip_address: string;
  os: string;
  status: 'ONLINE' | 'OFFLINE' | 'WARNING' | 'COMPROMISED';
  last_seen: string;
  cpu_usage: number;
  memory_usage: number;
  risk_score: number;
  events_count: number;
}

export interface HoneypotSession {
  session_id: string;
  attacker_ip: string;
  service: string;
  started_at: string;
  ended_at?: string;
  duration_seconds: number;
  credentials_attempted: string[];
  commands_executed: string[];
  files_accessed: string[];
  risk_score: number;
  notes?: string;
}

export interface AttackSimulation {
  simulation_id: string;
  scenario_name: string;
  target_environment: string;
  difficulty: string;
  status: 'RUNNING' | 'COMPLETED' | 'FAILED';
  started_at: string;
  completed_at?: string;
  generated_incident_id?: string;
  events_generated: number;
  details?: Record<string, unknown>;
}

export interface AttackGraphNode {
  id: string;
  label: string;
  type: 'attacker' | 'asset' | 'service' | 'deception' | 'exploit' | 'exfiltration';
  status: string;
  timestamp?: string;
  details?: string;
}

export interface AttackGraphEdge {
  source: string;
  target: string;
  label: string;
}

export interface AttackGraphData {
  incident_id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
}

export interface InvestigationReport {
  report_id: string;
  incident_id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  created_at: string;
  updated_at: string;
  source_ip?: string;
  destination_ip?: string;
  triggering_detection_ids?: string[];
  executive_summary: string;
  initial_access_vector: string;
  affected_assets: string[];
  observed_techniques: string[];
  honeypot_engagement: string;
  simulated_data_loss: string;
  overall_risk_score: number;
  recommended_actions: string[];
  graph_nodes?: AttackGraphNode[];
  graph_edges?: AttackGraphEdge[];
}
