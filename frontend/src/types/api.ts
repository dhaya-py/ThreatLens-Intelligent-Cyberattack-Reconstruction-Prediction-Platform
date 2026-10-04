export interface HealthResponse {
  status: "ok" | "degraded";
  database: "ok" | "unavailable";
}

export type Severity = "low" | "medium" | "high" | "critical";

export interface IncidentSummary {
  id: number;
  reference: string;
  title: string;
  severity: Severity;
  status: string;
  first_seen: string;
  last_seen: string;
  risk_score: number;
  confidence: number;
  root_host: string | null;
  compromised_hosts: number;
  lateral_movements: number;
  technique_count: number;
}

export interface LateralMovement {
  source_host: string;
  destination_host: string;
  username: string | null;
  protocol: string;
  port: number | null;
  timestamp: string;
  confidence: number;
  reason: string;
}

export interface RootCause {
  host: string;
  first_seen: string;
  source_ip: string | null;
  confidence: number;
  explanation: string;
  evidence: string[];
  ranking: { host: string; score: number }[];
}

export interface IncidentDetail extends IncidentSummary {
  summary: string | null;
  root_cause: RootCause;
  movements: LateralMovement[];
}

export interface AttackStep {
  sequence: number;
  timestamp: string;
  host: string | null;
  tactic: string;
  technique_id: string;
  technique_name: string;
  confidence: number;
  description: string;
  evidence: string[];
  event_ids: string[];
}

export type NodeType = "host" | "user" | "ip" | "process" | "domain";

export interface GraphNode {
  key: string;
  type: NodeType;
  label: string;
  attributes: Record<string, unknown>;
}

export interface GraphEdge {
  source: string;
  destination: string;
  relationship: string;
  timestamp: string;
  username: string | null;
  protocol: string | null;
  port: number | null;
  confidence: number;
  evidence: string[];
  event_ids: string[];
}

export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface Technique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  confidence: number;
  hosts: string[];
}

export interface Mitre {
  techniques: Technique[];
  steps: AttackStep[];
}

export interface RiskFactor {
  name: string;
  points: number;
  evidence: string;
}

export interface HostRisk {
  host: string;
  score: number;
  status: string;
  factors: RiskFactor[];
}

export interface Risk {
  score: number;
  severity: Severity;
  hosts: HostRisk[];
}

export interface TargetPrediction {
  host: string;
  rank: number;
  score: number;
  reasons: string[];
}

export interface Prediction {
  top: TargetPrediction | null;
  ranking: TargetPrediction[];
}
