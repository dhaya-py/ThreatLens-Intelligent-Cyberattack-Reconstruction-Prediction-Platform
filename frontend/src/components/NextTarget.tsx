import { Panel } from "./ui/Panel";
import { riskColor } from "../lib/format";
import type { Prediction } from "../types/api";

export function NextTarget({
  prediction,
  onSelectHost,
}: {
  prediction: Prediction;
  onSelectHost?: (host: string) => void;
}) {
  const top = prediction.top;
  return (
    <Panel title="Likely next target" icon="🎯" className="h-full">
      {!top ? (
        <p className="text-sm text-slate-500">No prediction available.</p>
      ) : (
        <div>
          <button
            onClick={() => onSelectHost?.(top.host)}
            className="flex w-full items-baseline justify-between rounded-lg bg-soc-bg/50 px-3 py-2 text-left hover:bg-soc-border/40"
          >
            <span className="text-xl font-bold text-slate-100">{top.host}</span>
            <span className={`text-2xl font-bold ${riskColor(top.score)}`}>{top.score}</span>
          </button>
          <ol className="mt-3 space-y-1.5">
            {top.reasons.map((r, i) => (
              <li key={i} className="flex gap-2 text-xs text-slate-300">
                <span className="text-soc-accent">{i + 1}.</span>
                <span>{r}</span>
              </li>
            ))}
          </ol>
          {prediction.ranking.length > 1 && (
            <div className="mt-3 border-t border-soc-border pt-2">
              <div className="mb-1 text-[10px] uppercase tracking-wider text-slate-500">
                Other candidates
              </div>
              <div className="flex flex-wrap gap-2">
                {prediction.ranking.slice(1).map((t) => (
                  <span
                    key={t.host}
                    className="rounded border border-soc-border px-2 py-0.5 text-xs text-slate-400"
                  >
                    {t.host} · {t.score}
                  </span>
                ))}
              </div>
            </div>
          )}
          <p className="mt-3 text-[11px] text-slate-600">
            Heuristic exposure ranking, not a guaranteed forecast.
          </p>
        </div>
      )}
    </Panel>
  );
}
