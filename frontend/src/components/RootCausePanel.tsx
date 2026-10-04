import { Panel } from "./ui/Panel";
import { timeOf } from "../lib/format";
import type { RootCause } from "../types/api";

export function RootCausePanel({
  rootCause,
  onSelectHost,
}: {
  rootCause: RootCause;
  onSelectHost?: (host: string) => void;
}) {
  return (
    <Panel title="Root cause" icon="🔍" className="h-full">
      <div className="flex items-baseline gap-3">
        <button
          onClick={() => onSelectHost?.(rootCause.host)}
          className="text-lg font-bold text-slate-100 hover:text-soc-accent"
        >
          {rootCause.host}
        </button>
        {rootCause.first_seen && (
          <span className="font-mono text-xs text-soc-accent">{timeOf(rootCause.first_seen)}</span>
        )}
        {rootCause.source_ip && (
          <span className="font-mono text-xs text-red-400">{rootCause.source_ip}</span>
        )}
      </div>
      <p className="mt-2 text-sm leading-relaxed text-slate-300">{rootCause.explanation}</p>
      <div className="mt-3">
        <div className="mb-1 text-[10px] uppercase tracking-wider text-slate-500">
          Supporting evidence
        </div>
        <ul className="space-y-1 text-xs text-slate-400">
          {rootCause.evidence.map((e, i) => (
            <li key={i} className="flex gap-2">
              <span className="text-emerald-500">✓</span>
              {e}
            </li>
          ))}
        </ul>
      </div>
      <div className="mt-2 text-[11px] text-slate-600">
        Confidence {(rootCause.confidence * 100).toFixed(0)}%
      </div>
    </Panel>
  );
}
