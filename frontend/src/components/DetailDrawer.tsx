import type { ReactNode } from "react";

import type { GraphSelection } from "./AttackGraph";
import { dateTimeOf } from "../lib/format";

function Row({ label, value }: { label: string; value: ReactNode }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div className="flex justify-between gap-4 py-1 text-sm">
      <span className="text-slate-500">{label}</span>
      <span className="text-right font-mono text-slate-200">{value}</span>
    </div>
  );
}

export function DetailDrawer({
  selection,
  onClose,
}: {
  selection: GraphSelection | null;
  onClose: () => void;
}) {
  if (!selection) return null;

  return (
    <aside className="absolute right-0 top-0 z-10 flex h-full w-80 max-w-[85%] flex-col border-l border-soc-border bg-soc-panel shadow-2xl">
      <header className="flex items-center justify-between border-b border-soc-border px-4 py-3">
        <h3 className="text-sm font-semibold text-slate-200">
          {selection.kind === "node" ? "Entity details" : "Relationship details"}
        </h3>
        <button
          onClick={onClose}
          className="rounded px-2 text-slate-400 hover:bg-soc-border hover:text-slate-100"
          aria-label="Close"
        >
          ✕
        </button>
      </header>
      <div className="flex-1 overflow-y-auto px-4 py-3">
        {selection.kind === "node" ? (
          <NodeDetails selection={selection} />
        ) : (
          <EdgeDetails selection={selection} />
        )}
      </div>
    </aside>
  );
}

function NodeDetails({ selection }: { selection: Extract<GraphSelection, { kind: "node" }> }) {
  const { node } = selection;
  const attr = node.attributes;
  return (
    <div>
      <div className="mb-3">
        <div className="text-xs uppercase tracking-wider text-slate-500">{node.type}</div>
        <div className="text-lg font-semibold text-slate-100">{node.label}</div>
      </div>
      <Row label="IP address" value={attr.ip_address as string} />
      <Row label="OS" value={attr.operating_system as string} />
      <Row label="Department" value={attr.department as string} />
      <Row label="Criticality" value={attr.criticality ? `${attr.criticality}/5` : undefined} />
      <Row label="Risk" value={attr.risk as number} />
      <Row label="Status" value={attr.status as string} />
      <Row label="External" value={attr.external === true ? "yes" : undefined} />
      <Row label="Host" value={attr.host as string} />
    </div>
  );
}

function EdgeDetails({ selection }: { selection: Extract<GraphSelection, { kind: "edge" }> }) {
  const { edge } = selection;
  return (
    <div>
      <div className="mb-3">
        <div className="text-xs uppercase tracking-wider text-slate-500">
          {edge.relationship.replace(/_/g, " ")}
        </div>
        <div className="font-mono text-sm text-slate-200">
          {edge.source} → {edge.destination}
        </div>
      </div>
      <Row label="Timestamp" value={dateTimeOf(edge.timestamp)} />
      <Row label="User" value={edge.username} />
      <Row label="Protocol" value={edge.protocol?.toUpperCase()} />
      <Row label="Port" value={edge.port} />
      <Row label="Confidence" value={edge.confidence.toFixed(2)} />
      {edge.evidence.length > 0 && (
        <div className="mt-3">
          <div className="mb-1 text-xs uppercase tracking-wider text-slate-500">Evidence</div>
          <ul className="space-y-1 text-xs text-slate-300">
            {edge.evidence.map((e, i) => (
              <li key={i} className="rounded bg-soc-bg/60 px-2 py-1">
                {e}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
