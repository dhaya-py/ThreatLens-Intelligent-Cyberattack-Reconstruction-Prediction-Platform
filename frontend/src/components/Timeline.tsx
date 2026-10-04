import { Panel } from "./ui/Panel";
import { timeOf } from "../lib/format";
import type { AttackStep } from "../types/api";

const TACTIC_COLOR: Record<string, string> = {
  "Initial Access": "bg-red-500",
  Execution: "bg-orange-500",
  "Credential Access": "bg-pink-500",
  Discovery: "bg-amber-500",
  "Lateral Movement": "bg-sky-500",
  Collection: "bg-violet-500",
  "Command and Control": "bg-emerald-500",
};

export function Timeline({
  steps,
  onSelectHost,
}: {
  steps: AttackStep[];
  onSelectHost?: (host: string) => void;
}) {
  return (
    <Panel title="Attack timeline" icon="🕑" className="h-full">
      <ol className="relative space-y-3 overflow-y-auto pr-1" style={{ maxHeight: "100%" }}>
        {steps.map((step) => (
          <li key={step.sequence} className="flex gap-3">
            <div className="flex flex-col items-center">
              <span
                className={`mt-1 h-2.5 w-2.5 rounded-full ${TACTIC_COLOR[step.tactic] ?? "bg-slate-500"}`}
              />
              {step.sequence < steps.length && <span className="w-px flex-1 bg-soc-border" />}
            </div>
            <button
              onClick={() => step.host && onSelectHost?.(step.host)}
              className="group -mt-0.5 flex-1 rounded-lg px-2 py-1 text-left hover:bg-soc-border/40"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs text-soc-accent">{timeOf(step.timestamp)}</span>
                <span className="text-[10px] uppercase tracking-wider text-slate-500">
                  {step.tactic}
                </span>
              </div>
              <div className="text-sm text-slate-200">
                {step.technique_name}
                {step.host && <span className="ml-1 text-slate-500">· {step.host}</span>}
              </div>
              <div className="font-mono text-[10px] text-slate-600">{step.technique_id}</div>
            </button>
          </li>
        ))}
      </ol>
    </Panel>
  );
}
