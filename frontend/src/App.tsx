import { type ReactNode, useCallback, useEffect, useState } from "react";

import { Dashboard } from "./features/Dashboard";
import { api, type IncidentBundle } from "./services/api";

type State =
  | { phase: "loading" }
  | { phase: "empty" }
  | { phase: "ready"; bundle: IncidentBundle }
  | { phase: "error"; message: string };

export default function App() {
  const [state, setState] = useState<State>({ phase: "loading" });
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setState({ phase: "loading" });
    try {
      const incidents = await api.incidents();
      if (incidents.length === 0) {
        setState({ phase: "empty" });
        return;
      }
      const bundle = await api.bundle(incidents[0].id);
      setState({ phase: "ready", bundle });
    } catch (e) {
      setState({ phase: "error", message: (e as Error).message });
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const runAnalysis = async () => {
    setBusy(true);
    try {
      await api.runAnalysis();
      await load();
    } catch (e) {
      setState({ phase: "error", message: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen bg-soc-bg">
      <header className="sticky top-0 z-20 border-b border-soc-border bg-soc-bg/90 backdrop-blur">
        <div className="mx-auto flex max-w-[1600px] items-center gap-3 px-5 py-3">
          <span className="text-lg font-bold tracking-tight text-white">
            Threat<span className="text-soc-accent">Lens</span>
          </span>
          <span className="hidden text-xs text-slate-500 sm:inline">
            Cyberattack reconstruction &amp; prediction
          </span>
          <button
            onClick={runAnalysis}
            disabled={busy}
            className="ml-auto rounded-lg border border-soc-accent/40 bg-soc-accent/10 px-3 py-1.5 text-sm font-medium text-soc-accent hover:bg-soc-accent/20 disabled:opacity-50"
          >
            {busy ? "Analyzing…" : "Re-run analysis"}
          </button>
        </div>
      </header>

      <main className="mx-auto max-w-[1600px] px-5 py-5">
        {state.phase === "loading" && <Centered>Loading incident…</Centered>}
        {state.phase === "error" && (
          <Centered>
            <span className="text-red-400">Failed to load: {state.message}</span>
          </Centered>
        )}
        {state.phase === "empty" && (
          <Centered>
            <div className="text-center">
              <p className="mb-3 text-slate-400">No incident analyzed yet.</p>
              <button
                onClick={runAnalysis}
                disabled={busy}
                className="rounded-lg bg-soc-accent px-4 py-2 font-medium text-soc-bg hover:bg-sky-300 disabled:opacity-50"
              >
                {busy ? "Analyzing…" : "Run analysis"}
              </button>
            </div>
          </Centered>
        )}
        {state.phase === "ready" && <Dashboard bundle={state.bundle} />}
      </main>
    </div>
  );
}

function Centered({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-[70vh] items-center justify-center text-slate-400">{children}</div>
  );
}
