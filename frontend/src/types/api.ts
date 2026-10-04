export interface HealthResponse {
  status: "ok" | "degraded";
  database: "ok" | "unavailable";
}
