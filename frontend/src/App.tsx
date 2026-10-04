import { useEffect, useState } from "react";

import { api } from "./services/api";
import type { HealthResponse } from "./types/api";

// Phase 1 shell: proves the frontend → API → database path end to end.
// The SOC dashboard replaces this in Phase 10.
export default function App() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.health().then(setHealth, (e: Error) => setError(e.message));
  }, []);

  return (
    <main className="mx-auto max-w-3xl px-4 py-16">
      <h1 className="text-3xl font-semibold tracking-tight text-white">ThreatLens</h1>
      <p className="mt-2 text-slate-400">
        Intelligent cyberattack reconstruction &amp; prediction platform
      </p>

      <section className="mt-10 rounded-lg border border-soc-border bg-soc-panel p-5">
        <h2 className="text-sm font-medium uppercase tracking-wider text-slate-400">
          Backend status
        </h2>
        <dl className="mt-3 grid grid-cols-2 gap-2 font-mono text-sm">
          <dt className="text-slate-500">API</dt>
          <dd>{error ? <span className="text-red-400">{error}</span> : (health?.status ?? "…")}</dd>
          <dt className="text-slate-500">Database</dt>
          <dd>{health?.database ?? "…"}</dd>
        </dl>
      </section>
    </main>
  );
}
