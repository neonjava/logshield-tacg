export type SecurityEvent = {
  id: string;
  timestamp: string;
  event_type: string;
  source_ip?: string;
  destination_ip?: string;
  hostname?: string;
  username?: string;
  service?: string;
  result?: string;
  raw_message: string;
  origin?: string;
  request_id?: string;
  port?: number;
};
export type ProofStep = {
  timestamp: string;
  stage: string;
  detail: string;
  http_status?: number;
};
export type Incident = {
  id: string;
  created_at?: string;
  kind: string;
  source_ip?: string;
  target: string;
  risk: number;
  severity: string;
  status: string;
  confidence: number;
  score: Record<string, number>;
  reasons: string[];
  recommended_actions?: string[];
  events: SecurityEvent[];
  edges: { from: string; to: string; strength: number; reasons: string[] }[];
  response?: { result: string; proof: ProofStep[] };
};
export type Stats = {
  events_processed: number;
  active_incidents: number;
  critical_incidents: number;
  contained_incidents: number;
  response_failures: number;
  risk_distribution: Record<string, number>;
  host_activity: Record<string, number>;
};
export type Health = {
  gateway: boolean;
  sensor: boolean;
  tacg: boolean;
  database: boolean;
  attacker: boolean;
  force_response_failure: boolean;
  services_online: number;
  services_total: number;
  events_per_second: number;
  last_event?: string;
};
export type Entity = {
  kind: string;
  value: string;
  event_count: number;
  first_seen: string;
  last_seen: string;
};
export type Page =
  | "dashboard"
  | "incidents"
  | "events"
  | "sdk-logs"
  | "entities"
  | "responses"
  | "infrastructure"
  | "lab";
export type Notice = {
  id: number;
  title: string;
  message: string;
  tone: "danger" | "success" | "neutral";
  incidentId?: string;
  expires: number;
};
export type ImportResult = {
  accepted: number;
  duplicates: number;
  rejected: number;
  origin: string;
  automatic_response: boolean;
};
export type HttpResult = {
  status: number;
  action?: string;
  request_id?: string;
  body?: {
    token?: string;
    challenge_id?: string;
    demo_code?: string;
    authenticated?: boolean;
    mfa_required?: boolean;
    mfa_verified?: boolean;
    session_valid?: boolean;
    served_by?: string;
    blocked?: boolean;
    error?: string;
    incident_id?: string;
    [key: string]: unknown;
  };
};
export type ScenarioResult = {
  requests?: HttpResult[];
  attempt?: HttpResult;
  scenario?: string;
  [key: string]: unknown;
};
export type InfraHealth = {
  online: number;
  total: number;
  replicas: { name: string; online: boolean }[];
  agents: { name: string; online: boolean }[];
};
export type AppActivity = {
  id: string;
  created_at: string;
  username: string;
  service: string;
  replica: string;
};
