"""Attack graph construction from an incident's events.

Produces a typed node/edge graph derived entirely from the correlated events
(never hardcoded). Node types: host, user, ip, process, domain. Edge
relationships: AUTHENTICATED_TO, CONNECTED_TO, RESOLVED, SPAWNED, ACCESSED,
MOVED_TO. MOVED_TO edges come from the lateral-movement engine and form the
high-level overlay; the rest are derived per event.

Parallel edges of the same (source, destination, relationship, protocol) are
merged, keeping the earliest timestamp, max confidence and the union of evidence.
"""

from dataclasses import dataclass, field
from datetime import datetime

from app.engines.lateral_movement import LateralMovement
from app.engines.types import EventView, is_external_ip
from app.models.enums import EventOutcome, EventType, NodeType, Relationship


@dataclass(frozen=True)
class GraphNode:
    key: str
    type: str
    label: str
    attributes: dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    destination: str
    relationship: str
    timestamp: datetime
    confidence: float
    username: str | None = None
    protocol: str | None = None
    port: int | None = None
    evidence: list[str] = field(default_factory=list)
    event_ids: list = field(default_factory=list)


@dataclass
class AttackGraph:
    nodes: list[GraphNode]
    edges: list[GraphEdge]


def host_key(name: str) -> str:
    return f"host:{name}"


def _user_key(name: str) -> str:
    return f"user:{name}"


def _ip_key(ip: str) -> str:
    return f"ip:{ip}"


def _proc_key(host: str | None, proc: str) -> str:
    return f"process:{host or '?'}:{proc}"


def _domain_key(domain: str) -> str:
    return f"domain:{domain}"


class _GraphBuilder:
    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[tuple, GraphEdge] = {}

    def node(self, key: str, type_: str, label: str, **attrs) -> str:
        existing = self.nodes.get(key)
        if existing is None:
            self.nodes[key] = GraphNode(key, type_, label, dict(attrs))
        else:
            existing.attributes.update({k: v for k, v in attrs.items() if v is not None})
        return key

    def edge(
        self,
        source: str,
        destination: str,
        relationship: str,
        event: EventView,
        confidence: float,
        reason: str,
        *,
        username: str | None = None,
        protocol: str | None = None,
        port: int | None = None,
    ) -> None:
        if source == destination:
            return
        key = (source, destination, relationship, protocol)
        edge = self.edges.get(key)
        if edge is None:
            self.edges[key] = GraphEdge(
                source=source,
                destination=destination,
                relationship=relationship,
                timestamp=event.timestamp,
                confidence=round(confidence, 3),
                username=username,
                protocol=protocol,
                port=port,
                evidence=[reason],
                event_ids=[event.id],
            )
            return
        edge.timestamp = min(edge.timestamp, event.timestamp)
        edge.confidence = round(max(edge.confidence, confidence), 3)
        edge.username = edge.username or username
        edge.port = edge.port or port
        if event.id not in edge.event_ids:
            edge.event_ids.append(event.id)
        if reason not in edge.evidence:
            edge.evidence.append(reason)

    def build(self) -> AttackGraph:
        for edge in self.edges.values():
            edge.event_ids = edge.event_ids[:25]
            edge.evidence = edge.evidence[:5]
        # Drop nodes that ended up with no edges (keeps the graph readable).
        referenced = {e.source for e in self.edges.values()} | {
            e.destination for e in self.edges.values()
        }
        nodes = [n for n in self.nodes.values() if n.key in referenced]
        return AttackGraph(nodes=nodes, edges=list(self.edges.values()))


def build_graph(
    events: list[EventView],
    movements: list[LateralMovement] | None = None,
    *,
    signal_ids: set | None = None,
) -> AttackGraph:
    events = sorted(events, key=lambda e: (e.timestamp, str(e.id)))
    signal_ids = signal_ids or set()
    b = _GraphBuilder()

    # Hosts first, with first-seen and event counts.
    for e in events:
        for name in (e.host, e.dest_host, e.source_host):
            if name:
                b.node(host_key(name), NodeType.HOST, name)

    for e in events:
        confidence = 0.9 if e.id in signal_ids else 0.5
        _add_event_edges(b, e, confidence)

    for m in movements or ():
        src, dst = host_key(m.source_host), host_key(m.destination_host)
        b.node(src, NodeType.HOST, m.source_host)
        b.node(dst, NodeType.HOST, m.destination_host)
        key = (src, dst, Relationship.MOVED_TO, m.protocol)
        b.edges[key] = GraphEdge(
            source=src,
            destination=dst,
            relationship=Relationship.MOVED_TO,
            timestamp=m.timestamp,
            confidence=m.confidence,
            username=m.username,
            protocol=m.protocol,
            port=m.port,
            evidence=m.evidence[:5],
            event_ids=list(m.event_ids)[:25],
        )

    return b.build()


def _add_event_edges(b: _GraphBuilder, e: EventView, confidence: float) -> None:
    user = e.normalized_user

    if e.event_type == EventType.AUTHENTICATION and e.outcome == EventOutcome.SUCCESS and e.host:
        dst = b.node(host_key(e.host), NodeType.HOST, e.host)
        origin = _origin_key(b, e)
        if origin:
            b.edge(
                origin,
                dst,
                Relationship.AUTHENTICATED_TO,
                e,
                confidence,
                f"{e.username or 'logon'} authenticated to {e.host}",
                username=user,
                protocol=e.protocol,
                port=e.dest_port,
            )
        if user:
            b.node(_user_key(user), NodeType.USER, user)
            b.edge(
                _user_key(user),
                dst,
                Relationship.AUTHENTICATED_TO,
                e,
                confidence,
                f"{user} authenticated to {e.host}",
                username=user,
                protocol=e.protocol,
            )

    elif e.event_type == EventType.PROCESS and e.host and e.process:
        child = b.node(_proc_key(e.host, e.process), NodeType.PROCESS, e.process, host=e.host)
        if e.parent_process:
            parent = b.node(
                _proc_key(e.host, e.parent_process), NodeType.PROCESS, e.parent_process, host=e.host
            )
            b.edge(
                parent,
                child,
                Relationship.SPAWNED,
                e,
                confidence,
                f"{e.parent_process} spawned {e.process} on {e.host}",
                username=user,
            )
        else:
            b.edge(
                host_key(e.host),
                child,
                Relationship.SPAWNED,
                e,
                confidence,
                f"{e.host} ran {e.process}",
                username=user,
            )

    elif e.event_type == EventType.NETWORK:
        origin = _origin_key(b, e)
        target = _target_key(b, e)
        if origin and target:
            b.edge(
                origin,
                target,
                Relationship.CONNECTED_TO,
                e,
                confidence,
                f"connection to port {e.dest_port}",
                username=user,
                protocol=e.protocol,
                port=e.dest_port,
            )

    elif e.event_type == EventType.DNS and e.domain:
        b.node(_domain_key(e.domain), NodeType.DOMAIN, e.domain)
        origin = (
            _proc_key(e.host, e.process)
            if e.host and e.process
            else (host_key(e.host) if e.host else _origin_key(b, e))
        )
        if origin:
            b.edge(
                origin,
                _domain_key(e.domain),
                Relationship.RESOLVED,
                e,
                confidence,
                f"resolved {e.domain}",
                username=user,
            )

    elif e.event_type == EventType.DATABASE and e.host:
        origin = _origin_key(b, e) or (host_key(e.source_host) if e.source_host else None)
        dst = b.node(host_key(e.host), NodeType.HOST, e.host)
        if origin:
            b.edge(
                origin,
                dst,
                Relationship.ACCESSED,
                e,
                confidence,
                f"database access: {e.metadata.get('object') or 'query'}",
                username=user,
                protocol=e.protocol,
                port=e.dest_port,
            )

    elif e.event_type == EventType.FILE and e.host:
        dst = b.node(host_key(e.host), NodeType.HOST, e.host)
        origin = _origin_key(b, e)
        share = e.metadata.get("share") or ""
        target = e.metadata.get("relative_target") or "file"
        if origin:
            b.edge(
                origin,
                dst,
                Relationship.ACCESSED,
                e,
                confidence,
                f"accessed {share}\\{target}".strip("\\"),
                username=user,
            )


def _origin_key(b: _GraphBuilder, e: EventView) -> str | None:
    """Node the action originates from: source host, else external/source IP."""
    if e.source_host:
        return b.node(host_key(e.source_host), NodeType.HOST, e.source_host)
    if e.source_ip:
        external = is_external_ip(e.source_ip)
        return b.node(_ip_key(e.source_ip), NodeType.IP, e.source_ip, external=external)
    return None


def _target_key(b: _GraphBuilder, e: EventView) -> str | None:
    if e.dest_host:
        return b.node(host_key(e.dest_host), NodeType.HOST, e.dest_host)
    if e.dest_ip:
        external = is_external_ip(e.dest_ip)
        return b.node(_ip_key(e.dest_ip), NodeType.IP, e.dest_ip, external=external)
    return None
