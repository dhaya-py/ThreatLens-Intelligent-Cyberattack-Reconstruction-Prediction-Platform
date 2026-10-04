"""Explainable root-cause detection.

Scores each host involved in the incident on five transparent components and
selects the most likely initial compromised host:

    earliest suspicious activity   0.35   (rank-based across involved hosts)
    external source involvement    0.25
    has outbound lateral movement  0.20
    no inbound lateral movement    0.10
    mean correlation confidence    0.10

Returns the root host, the first suspicious timestamp, the external source IP, a
ranked breakdown, and a templated natural-language explanation.
"""

from dataclasses import dataclass, field
from datetime import datetime

from app.engines.detection import DEFAULT_DETECTION, DetectionResult, detect
from app.engines.lateral_movement import LateralMovement
from app.engines.types import EventView, is_external_ip

_W_EARLIEST = 0.35
_W_EXTERNAL = 0.25
_W_OUTBOUND = 0.20
_W_NO_INBOUND = 0.10
_W_MEAN_CONF = 0.10


@dataclass
class HostScore:
    host: str
    score: float
    first_signal: datetime
    source_ip: str | None
    factors: list[str] = field(default_factory=list)


@dataclass
class RootCauseResult:
    root_host: str | None
    first_seen: datetime | None
    source_ip: str | None
    confidence: float
    evidence: list[str]
    explanation: str
    ranking: list[HostScore] = field(default_factory=list)


def detect_root_cause(
    events: list[EventView],
    detection: DetectionResult | None = None,
    movements: list[LateralMovement] | None = None,
) -> RootCauseResult:
    detection = detection or detect(events, DEFAULT_DETECTION)
    movements = movements or []
    signal_ids = detection.signal_event_ids(DEFAULT_DETECTION.signal_threshold)

    # Collect per-host signal facts.
    by_host_signals: dict[str, list[EventView]] = {}
    for e in events:
        if e.id in signal_ids and e.host:
            by_host_signals.setdefault(e.host, []).append(e)
    if not by_host_signals:
        return RootCauseResult(None, None, None, 0.0, [], "No suspicious activity correlated.")

    earliest = {h: min(g, key=lambda e: e.timestamp).timestamp for h, g in by_host_signals.items()}
    hosts_by_time = sorted(earliest, key=lambda h: earliest[h])
    max_rank = max(len(hosts_by_time) - 1, 1)

    outbound = {m.source_host for m in movements}
    inbound = {m.destination_host for m in movements}

    ranking: list[HostScore] = []
    for host, group in by_host_signals.items():
        rank = hosts_by_time.index(host)
        earliest_component = _W_EARLIEST * (1 - rank / max_rank)
        external_ip = next((e.source_ip for e in group if is_external_ip(e.source_ip)), None)
        mean_conf = sum(detection.suspicion.get(e.id, 0.0) for e in group) / len(group)

        score = earliest_component
        factors = [f"earliest suspicious activity at {earliest[host]:%H:%M} (rank {rank + 1})"]
        if external_ip:
            score += _W_EXTERNAL
            factors.append(f"suspicious activity from external IP {external_ip}")
        if host in outbound:
            score += _W_OUTBOUND
            targets = ", ".join(
                sorted({m.destination_host for m in movements if m.source_host == host})
            )
            factors.append(f"origin of lateral movement toward {targets}")
        if host not in inbound:
            score += _W_NO_INBOUND
            factors.append("no inbound lateral movement (not reached from another host)")
        score += _W_MEAN_CONF * mean_conf
        factors.append(f"mean correlation confidence {mean_conf:.2f}")

        ranking.append(HostScore(host, round(score, 4), earliest[host], external_ip, factors))

    ranking.sort(key=lambda h: (-h.score, h.first_signal))
    root = ranking[0]
    return RootCauseResult(
        root_host=root.host,
        first_seen=root.first_signal,
        source_ip=root.source_ip,
        confidence=round(min(root.score, 1.0), 3),
        evidence=root.factors,
        explanation=_explain(root, movements),
        ranking=ranking,
    )


def _explain(root: HostScore, movements: list[LateralMovement]) -> str:
    parts = [
        f"{root.host} is identified as the likely initial compromised host because it "
        f"contains the earliest correlated suspicious activity (at {root.first_signal:%H:%M})"
    ]
    if root.source_ip:
        parts.append(f" originating from external IP {root.source_ip}")
    outbound = [m for m in movements if m.source_host == root.host]
    if outbound:
        first = min(outbound, key=lambda m: m.timestamp)
        parts.append(
            f", followed by credential access and lateral movement toward "
            f"{first.destination_host} over {first.protocol.upper()}"
        )
    return "".join(parts) + "."
