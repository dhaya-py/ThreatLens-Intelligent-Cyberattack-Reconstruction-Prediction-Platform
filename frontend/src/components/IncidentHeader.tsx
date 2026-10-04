import type { ReactNode } from "react";

import { SeverityBadge } from "./ui/SeverityBadge";
import { dateTimeOf, riskColor } from "../lib/format";
import type { IncidentDetail } from "../types/api";

function Stat({ label, value, accent }: { label: string; value: ReactNode; accent?: string }) {
  return (
    <div className="rounded-lg border border-soc-border bg-soc-panel/60 px-4 py-2">
      <div className="text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
      <div className={`text-lg font-bold ${accent ?? "text-slate-100"}`}>{value}</div>
    </div>
  );
}

export function IncidentHeader({ incident }: { incident: IncidentDetail }) {
  return (
    <div className="flex flex-wrap items-center gap-4">
      <div className="flex items-center gap-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-lg font-bold text-white">{incident.reference}</span>
            <SeverityBadge severity={incident.severity} />
          </div>
          <div className="text-sm text-slate-400">{incident.title}</div>
        </div>
      </div>
      <div className="ml-auto grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-6">
        <Stat
          label="Risk"
          value={`${incident.risk_score}/100`}
          accent={riskColor(incident.risk_score)}
        />
        <Stat label="Compromised" value={incident.compromised_hosts} />
        <Stat label="Movements" value={incident.lateral_movements} />
        <Stat label="Techniques" value={incident.technique_count} />
        <Stat label="Root" value={incident.root_host ?? "—"} />
        <Stat label="First seen" value={dateTimeOf(incident.first_seen)} />
      </div>
    </div>
  );
}
