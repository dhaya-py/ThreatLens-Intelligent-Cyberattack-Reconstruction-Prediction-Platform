import type { HealthResponse } from "../types/api";

const API_BASE = "/api/v1";

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    throw new Error(`${path} failed with HTTP ${response.status}`);
  }
  return (await response.json()) as T;
}

export const api = {
  health: () => getJson<HealthResponse>("/health"),
};
