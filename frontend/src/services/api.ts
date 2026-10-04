import type {
  Graph,
  HealthResponse,
  IncidentDetail,
  IncidentSummary,
  Mitre,
  Prediction,
  Risk,
  AttackStep,
} from "../types/api";

const API_BASE = "/api/v1";

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    throw new Error(`${path} failed with HTTP ${response.status}`);
  }
  return (await response.json()) as T;
}

async function postJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, { method: "POST" });
  if (!response.ok) {
    throw new Error(`${path} failed with HTTP ${response.status}`);
  }
  return (await response.json()) as T;
}

export interface IncidentBundle {
  detail: IncidentDetail;
  timeline: AttackStep[];
  graph: Graph;
  mitre: Mitre;
  risk: Risk;
  prediction: Prediction;
}

export const api = {
  health: () => getJson<HealthResponse>("/health"),
  incidents: () => getJson<IncidentSummary[]>("/incidents"),
  runAnalysis: () => postJson<{ incidents: number; references: string[] }>("/analysis/run"),
  loadDemo: () => postJson<{ incident_reference: string | null }>("/demo/load"),

  async bundle(id: number): Promise<IncidentBundle> {
    const [detail, timeline, graph, mitre, risk, prediction] = await Promise.all([
      getJson<IncidentDetail>(`/incidents/${id}`),
      getJson<AttackStep[]>(`/incidents/${id}/timeline`),
      getJson<Graph>(`/incidents/${id}/graph`),
      getJson<Mitre>(`/incidents/${id}/mitre`),
      getJson<Risk>(`/incidents/${id}/risk`),
      getJson<Prediction>(`/incidents/${id}/prediction`),
    ]);
    return { detail, timeline, graph, mitre, risk, prediction };
  },
};
