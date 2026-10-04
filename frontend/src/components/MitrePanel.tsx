import { Panel } from "./ui/Panel";
import type { Technique } from "../types/api";

export function MitrePanel({ techniques }: { techniques: Technique[] }) {
  return (
    <Panel title="MITRE ATT&CK" icon="🎯" className="h-full">
      <div className="grid grid-cols-1 gap-2 overflow-y-auto sm:grid-cols-2">
        {techniques.map((t) => (
          <div
            key={t.technique_id}
            className="rounded-lg border border-soc-border bg-soc-bg/40 px-3 py-2"
          >
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-semibold text-soc-accent">
                {t.technique_id}
              </span>
              <span className="text-[10px] uppercase tracking-wider text-slate-500">
                {t.tactic}
              </span>
            </div>
            <div className="text-sm text-slate-200">{t.technique_name}</div>
            <div className="mt-1 text-[11px] text-slate-500">{t.hosts.join(", ")}</div>
          </div>
        ))}
      </div>
      <p className="mt-3 text-[11px] text-slate-600">
        Explainable prototype mapping from observed event patterns — not authoritative threat
        intelligence.
      </p>
    </Panel>
  );
}
