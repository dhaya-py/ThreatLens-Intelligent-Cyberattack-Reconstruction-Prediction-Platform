"""Stage 2 of correlation: link signal events into incidents.

Signal events (from `detection`) are linked pairwise on shared host, pivot
(movement onto another host), shared user / source IP, process lineage and
credential flow, weighted by an exponential time decay. Connected components of
strong-enough links become incident clusters. Benign context events directly tied
to a cluster are then pulled in with a lower, derived confidence.
"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.engines.config import DEFAULT_CORRELATION, CorrelationConfig
from app.engines.detection import DEFAULT_DETECTION, DetectionResult, detect
from app.engines.types import EventView

_CRED_DETECTORS = {"lsass_access", "credential_file_access"}
_USES_CRED_DETECTORS = {
    "first_seen_remote_logon",
    "external_auth",
    "service_account_anomaly",
    "remote_exec_parent",
    "auth_success_after_failures",
    "service_execution",
}


@dataclass
class MemberEvent:
    event_id: int | str
    role: str  # "signal" | "context"
    confidence: float
    reasons: list[str] = field(default_factory=list)


@dataclass
class IncidentCluster:
    members: list[MemberEvent]
    detectors: set[str]
    first_seen: datetime
    last_seen: datetime

    @property
    def signal_event_ids(self) -> list:
        return [m.event_id for m in self.members if m.role == "signal"]

    @property
    def event_ids(self) -> list:
        return [m.event_id for m in self.members]


@dataclass
class CorrelationResult:
    clusters: list[IncidentCluster]
    detection: DetectionResult


class _UnionFind:
    def __init__(self, items):
        self.parent = {i: i for i in items}

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        self.parent[self.find(a)] = self.find(b)


def _link_score(a: EventView, b: EventView, da: set, db: set, config: CorrelationConfig) -> tuple:
    """Weighted feature score for an ordered pair (a before b), with reasons."""
    w = config.feature_weights
    total = 0.0
    reasons: list[str] = []

    if a.host and a.host == b.host:
        total += w["same_host"]
        reasons.append(f"same host {a.host}")
    if a.dest_host and a.dest_host == b.host:
        total += w["pivot"]
        reasons.append(f"pivot {a.host or a.source_ip} -> {b.host}")
    if a.normalized_user and a.normalized_user == b.normalized_user:
        total += w["same_user"]
        reasons.append(f"same user {a.normalized_user}")
    if a.source_ip and a.source_ip == b.source_ip:
        total += w["same_source_ip"]
        reasons.append(f"same source IP {a.source_ip}")
    if a.process and b.parent_process and a.host == b.host and a.process == b.parent_process:
        total += w["process_lineage"]
        reasons.append(f"process lineage {a.process} -> {b.process}")
    if (da & _CRED_DETECTORS) and (db & _USES_CRED_DETECTORS):
        total += w["credential_flow"]
        reasons.append("credential access followed by credential use")

    decay = math.exp(-(b.timestamp - a.timestamp).total_seconds() / config.decay_tau_seconds)
    return min(1.0, total) * decay, reasons


def correlate(
    events: list[EventView],
    detection: DetectionResult | None = None,
    config: CorrelationConfig = DEFAULT_CORRELATION,
) -> CorrelationResult:
    events = sorted(events, key=lambda e: (e.timestamp, str(e.id)))
    by_id = {e.id: e for e in events}
    detection = detection or detect(events, DEFAULT_DETECTION)

    signal_ids = detection.signal_event_ids(DEFAULT_DETECTION.signal_threshold)
    signal_events = [e for e in events if e.id in signal_ids]

    uf = _UnionFind(signal_ids)
    best_link: dict = defaultdict(float)
    reasons: dict = defaultdict(list)
    window = timedelta(seconds=config.window_seconds)

    for i, a in enumerate(signal_events):
        da = detection.detectors_for(a.id)
        for b in signal_events[i + 1 :]:
            dt = b.timestamp - a.timestamp
            if dt > window:
                break
            if dt.total_seconds() <= 0 and a.id == b.id:
                continue
            score, why = _link_score(a, b, da, detection.detectors_for(b.id), config)
            if score >= config.link_threshold:
                uf.union(a.id, b.id)
                if score > best_link[b.id]:
                    best_link[b.id], reasons[b.id] = score, why
                if score > best_link[a.id]:
                    best_link[a.id] = max(best_link[a.id], score)

    # Group signal events by component.
    components: dict = defaultdict(list)
    for sid in signal_ids:
        components[uf.find(sid)].append(sid)

    clusters: list[IncidentCluster] = []
    for member_ids in components.values():
        families = {d for sid in member_ids for d in detection.detectors_for(sid)}
        if len(member_ids) < config.min_signal_events:
            continue
        if len(families) < config.min_detector_families:
            continue
        clusters.append(_build_cluster(member_ids, by_id, detection, best_link, reasons, config))

    clusters.sort(key=lambda c: c.first_seen)
    return CorrelationResult(clusters=clusters, detection=detection)


def _build_cluster(member_ids, by_id, detection, best_link, reasons, config) -> IncidentCluster:
    members: list[MemberEvent] = []
    confidence: dict = {}
    for sid in member_ids:
        conf = round(max(best_link.get(sid, 0.0), detection.suspicion.get(sid, 0.0)), 4)
        confidence[sid] = conf
        why = reasons.get(sid, []) + [s.reason for s in detection.signals.get(sid, ())]
        members.append(MemberEvent(sid, "signal", conf, why[:5]))

    signal_set = set(member_ids)
    cluster_events = [by_id[sid] for sid in member_ids]
    context = _expand_context(cluster_events, by_id, signal_set, confidence, config)
    members.extend(context)

    timestamps = [by_id[m.event_id].timestamp for m in members]
    detectors = {d for sid in member_ids for d in detection.detectors_for(sid)}
    return IncidentCluster(
        members=members,
        detectors=detectors,
        first_seen=min(timestamps),
        last_seen=max(timestamps),
    )


def _expand_context(cluster_events, by_id, signal_set, confidence, config) -> list[MemberEvent]:
    """Pull in benign-looking events directly tied to a signal event."""
    ctx_window = timedelta(seconds=config.context_window_seconds)
    added: dict = {}
    for other in by_id.values():
        if other.id in signal_set or other.id in added:
            continue
        for sig in cluster_events:
            dt = abs((other.timestamp - sig.timestamp).total_seconds())
            if dt > ctx_window.total_seconds():
                continue
            same_proc = (
                other.host
                and other.host == sig.host
                and other.process
                and other.process == sig.process
            )
            # Network/DNS projection of the same malicious action.
            projection = other.event_type in ("network", "dns") and (
                (other.host == sig.host and other.dest_ip == sig.dest_ip)
                or (other.domain and other.domain == sig.domain)
                or (other.dest_host == sig.dest_host and sig.dest_host is not None)
            )
            if same_proc or projection:
                parent_conf = confidence.get(sig.id, 0.5)
                added[other.id] = MemberEvent(
                    other.id,
                    "context",
                    round(0.5 * parent_conf, 4),
                    [f"tied to signal event {sig.id}"],
                )
                break
    return list(added.values())
