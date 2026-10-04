import { useState } from "react";

import { AttackGraph, type GraphSelection } from "../components/AttackGraph";
import { DetailDrawer } from "../components/DetailDrawer";
import { IncidentHeader } from "../components/IncidentHeader";
import { MitrePanel } from "../components/MitrePanel";
import { NextTarget } from "../components/NextTarget";
import { Panel } from "../components/ui/Panel";
import { RiskPanel } from "../components/RiskPanel";
import { RootCausePanel } from "../components/RootCausePanel";
import { Timeline } from "../components/Timeline";
import type { IncidentBundle } from "../services/api";
import { hostKey } from "../lib/graph";

export function Dashboard({ bundle }: { bundle: IncidentBundle }) {
  const { detail, timeline, graph, mitre, risk, prediction } = bundle;
  const [selection, setSelection] = useState<GraphSelection | null>(null);

  const selectedKey = selection?.kind === "node" ? selection.node.key : null;

  const selectHost = (host: string) => {
    const node = graph.nodes.find((n) => n.key === hostKey(host));
    if (node) setSelection({ kind: "node", node });
  };

  return (
    <div className="flex flex-col gap-4">
      <IncidentHeader incident={detail} />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Hero: attack graph */}
        <Panel
          title="Attack graph"
          icon="🕸"
          className="relative h-[520px] lg:col-span-2"
        >
          <div className="absolute inset-0 top-10 overflow-hidden rounded-b-xl">
            <AttackGraph graph={graph} onSelect={setSelection} selectedKey={selectedKey} />
            <DetailDrawer selection={selection} onClose={() => setSelection(null)} />
          </div>
        </Panel>

        <div className="flex flex-col gap-4">
          <NextTarget prediction={prediction} onSelectHost={selectHost} />
          <RootCausePanel rootCause={detail.root_cause} onSelectHost={selectHost} />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="h-[360px]">
          <Timeline steps={timeline} onSelectHost={selectHost} />
        </div>
        <div className="h-[360px]">
          <RiskPanel hosts={risk.hosts} onSelectHost={selectHost} />
        </div>
        <div className="h-[360px]">
          <MitrePanel techniques={mitre.techniques} />
        </div>
      </div>
    </div>
  );
}
