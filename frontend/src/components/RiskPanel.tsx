import { useState } from "react";

import { Panel } from "./ui/Panel";
import { riskBar, riskColor, statusLabel } from "../lib/format";
import type { HostRisk } from "../types/api";

function HostRow({ host, onSelect }: { host: HostRisk; onSelect?: (h: string) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-lg border border-soc-border bg-soc-bg/40">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-3 px-3 py-2 text-left"
      >
        <span className="w-20 font-mono text-sm text-slate-200">{host.host}</span>
        <div className="h-2 flex-1 overflow-hidden rounded-full bg-soc-border">
          <div className={`h-full ${riskBar(host.score)}`} style={{ width: `${host.score}%` }} />
        </div>
        <span className={`w-8 text-right text-sm font-bold ${riskColor(host.score)}`}>
          {host.score}
        </span>
        <span className="w-24 text-right text-[10px] uppercase tracking-wide text-slate-500">
          {statusLabel[host.status] ?? host.status}
        </span>
      </button>
      {open && (
        <ul className="space-y-1 border-t border-soc-border px-3 py-2 text-xs">
          {host.factors.map((f, i) => (
            <li key={i} className="flex justify-between gap-2">
              <span className="text-slate-400">{f.name}</span>
              <span className="font-mono text-emerald-400">+{f.points}</span>
            </li>
          ))}
          {onSelect && (
            <li>
              <button
                onClick={() => onSelect(host.host)}
                className="mt-1 text-[11px] text-soc-accent hover:underline"
              >
                Show in graph →
              </button>
            </li>
          )}
        </ul>
      )}
    </div>
  );
}

export function RiskPanel({
  hosts,
  onSelectHost,
}: {
  hosts: HostRisk[];
  onSelectHost?: (host: string) => void;
}) {
  return (
    <Panel title="Host risk" icon="⚠" className="h-full">
      <div className="space-y-2 overflow-y-auto">
        {hosts.map((h) => (
          <HostRow key={h.host} host={h} onSelect={onSelectHost} />
        ))}
      </div>
    </Panel>
  );
}
