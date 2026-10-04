import Dagre from "@dagrejs/dagre";
import {
  Background,
  Controls,
  type Edge,
  Handle,
  MarkerType,
  type Node,
  type NodeProps,
  Position,
  ReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useMemo } from "react";

import { riskColor } from "../lib/format";
import type { Graph, GraphEdge, GraphNode, NodeType } from "../types/api";

export type GraphSelection =
  | { kind: "node"; node: GraphNode }
  | { kind: "edge"; edge: GraphEdge };

const NODE_STYLE: Record<NodeType, { ring: string; icon: string; bg: string }> = {
  host: { ring: "border-sky-500/60", icon: "🖥", bg: "bg-slate-800" },
  ip: { ring: "border-red-500/60", icon: "🌐", bg: "bg-slate-800" },
  user: { ring: "border-violet-500/60", icon: "👤", bg: "bg-slate-800" },
  process: { ring: "border-emerald-500/50", icon: "⚙", bg: "bg-slate-800/80" },
  domain: { ring: "border-amber-500/50", icon: "✦", bg: "bg-slate-800/80" },
};

const REL_COLOR: Record<string, string> = {
  MOVED_TO: "#f87171",
  AUTHENTICATED_TO: "#38bdf8",
  CONNECTED_TO: "#64748b",
  SPAWNED: "#34d399",
  RESOLVED: "#fbbf24",
  ACCESSED: "#c084fc",
};

interface EntityData extends Record<string, unknown> {
  node: GraphNode;
}

function EntityNode({ data }: NodeProps<Node<EntityData>>) {
  const { node } = data;
  const style = NODE_STYLE[node.type];
  const risk = node.attributes.risk as number | undefined;
  return (
    <div
      className={`min-w-[90px] rounded-lg border ${style.ring} ${style.bg} px-3 py-2 text-center shadow-lg`}
    >
      <Handle type="target" position={Position.Left} className="!bg-slate-500" />
      <div className="text-[10px] uppercase tracking-wider text-slate-500">
        {style.icon} {node.type}
      </div>
      <div className="text-sm font-semibold text-slate-100">{node.label}</div>
      {typeof risk === "number" && (
        <div className={`text-xs font-bold ${riskColor(risk)}`}>risk {risk}</div>
      )}
      <Handle type="source" position={Position.Right} className="!bg-slate-500" />
    </div>
  );
}

const nodeTypes = { entity: EntityNode };

function layout(graph: Graph): { nodes: Node<EntityData>[]; edges: Edge[] } {
  const g = new Dagre.graphlib.Graph().setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "LR", nodesep: 45, ranksep: 110, marginx: 20, marginy: 20 });

  for (const n of graph.nodes) g.setNode(n.key, { width: 130, height: 60 });
  for (const e of graph.edges) g.setEdge(e.source, e.destination);
  Dagre.layout(g);

  const nodes: Node<EntityData>[] = graph.nodes.map((n) => {
    const pos = g.node(n.key);
    return {
      id: n.key,
      type: "entity",
      position: { x: pos.x - 65, y: pos.y - 30 },
      data: { node: n },
    };
  });

  const edges: Edge[] = graph.edges.map((e, i) => {
    const color = REL_COLOR[e.relationship] ?? "#64748b";
    const isMove = e.relationship === "MOVED_TO";
    return {
      id: `e${i}`,
      source: e.source,
      target: e.destination,
      label: e.relationship.replace(/_/g, " ").toLowerCase(),
      animated: isMove,
      data: { edge: e },
      style: { stroke: color, strokeWidth: isMove ? 2.5 : 1.3 },
      labelStyle: { fill: "#94a3b8", fontSize: 9 },
      labelBgStyle: { fill: "#0b0f17", fillOpacity: 0.7 },
      markerEnd: { type: MarkerType.ArrowClosed, color },
    };
  });
  return { nodes, edges };
}

interface AttackGraphProps {
  graph: Graph;
  onSelect: (selection: GraphSelection) => void;
  selectedKey?: string | null;
}

export function AttackGraph({ graph, onSelect, selectedKey }: AttackGraphProps) {
  const { nodes, edges } = useMemo(() => layout(graph), [graph]);

  const styledNodes = nodes.map((n) =>
    n.id === selectedKey ? { ...n, style: { outline: "2px solid #38bdf8", borderRadius: 10 } } : n,
  );

  return (
    <ReactFlow
      nodes={styledNodes}
      edges={edges}
      nodeTypes={nodeTypes}
      fitView
      minZoom={0.2}
      proOptions={{ hideAttribution: true }}
      onNodeClick={(_, node) => onSelect({ kind: "node", node: (node.data as EntityData).node })}
      onEdgeClick={(_, edge) => {
        const found = (edge.data as { edge: GraphEdge } | undefined)?.edge;
        if (found) onSelect({ kind: "edge", edge: found });
      }}
    >
      <Background color="#1f2937" gap={20} />
      <Controls className="!bg-soc-panel !border-soc-border" showInteractive={false} />
    </ReactFlow>
  );
}
