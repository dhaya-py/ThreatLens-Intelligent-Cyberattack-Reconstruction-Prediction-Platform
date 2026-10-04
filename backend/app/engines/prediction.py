"""Explainable next-target prediction.

Ranks every host that is not already compromised by combining five transparent,
data-derived components:

    reachability          0.30   compromised hosts that can reach the candidate
    credential_exposure   0.25   candidate's users exposed on compromised hosts
    criticality           0.20   asset value
    recent_probe          0.15   connection from a compromised host since the attack began
    chain_proximity       0.10   adjacency to the current attack frontier

The result is labelled "Likely Next Target" with its evidence — it is a heuristic
ranking of exposure, not a guaranteed forecast. Needs the *full* event history
(baseline + incident) so connectivity and credential baselines are available.
"""

from dataclasses import dataclass, field
from datetime import datetime

from app.engines.types import EventView
from app.models.enums import EventType

WEIGHTS = {
    "reachability": 0.30,
    "credential_exposure": 0.25,
    "criticality": 0.20,
    "recent_probe": 0.15,
    "chain_proximity": 0.10,
}
_ADMIN_PORTS = {22, 445, 3389, 5985, 5986, 135}
_PORT_PROTOCOL = {
    22: "ssh",
    445: "smb",
    3389: "rdp",
    5985: "winrm",
    5986: "winrm",
    135: "rpc",
    1433: "mssql",
}


def _protocol_label(conn: "_Connection") -> str | None:
    if conn.protocol and conn.protocol.lower() not in ("tcp", "udp"):
        return conn.protocol
    return _PORT_PROTOCOL.get(conn.port or -1, conn.protocol)


@dataclass
class TargetScore:
    host: str
    score: int  # 0..100
    rank: int
    reasons: list[str] = field(default_factory=list)
    components: dict[str, float] = field(default_factory=dict)


@dataclass
class PredictionResult:
    top: TargetScore | None
    ranking: list[TargetScore] = field(default_factory=list)


@dataclass
class _Connection:
    timestamp: datetime
    port: int | None
    protocol: str | None
    admin: bool


def predict_next_target(
    all_events: list[EventView],
    compromised: dict[str, datetime],
    criticality: dict[str, int],
    top_n: int = 5,
) -> PredictionResult:
    if not compromised:
        return PredictionResult(top=None)

    frontier = max(compromised, key=lambda h: compromised[h])
    since = min(compromised.values())
    # Attribute reachability/probe reasons to the most recently compromised host.
    by_recency = sorted(compromised, key=lambda h: compromised[h], reverse=True)

    conns = _connection_index(all_events)  # (src, dst) -> [_Connection]
    users_of, exposed_users = _credential_maps(all_events, compromised)

    candidates = [h for h in criticality if h not in compromised]
    scored: list[TargetScore] = []
    for host in candidates:
        comp = {}
        reasons: list[str] = []

        comp["reachability"] = _reachability(host, compromised, by_recency, conns, reasons)
        comp["credential_exposure"] = _credential_exposure(host, users_of, exposed_users, reasons)
        comp["criticality"] = _criticality(host, criticality, reasons)
        comp["recent_probe"] = _recent_probe(host, by_recency, conns, since, reasons)
        comp["chain_proximity"] = _chain_proximity(host, frontier, compromised, conns, reasons)

        total = sum(WEIGHTS[k] * v for k, v in comp.items())
        score = round(total * 100)
        if score > 0:
            scored.append(
                TargetScore(host, score, 0, reasons, {k: round(v, 3) for k, v in comp.items()})
            )

    scored.sort(key=lambda t: (-t.score, -criticality.get(t.host, 0), t.host))
    for i, t in enumerate(scored[:top_n], start=1):
        t.rank = i
    ranking = scored[:top_n]
    return PredictionResult(top=ranking[0] if ranking else None, ranking=ranking)


def _connection_index(events) -> dict[tuple[str, str], list[_Connection]]:
    index: dict[tuple[str, str], list[_Connection]] = {}
    for e in events:
        if e.event_type not in (EventType.NETWORK, EventType.AUTHENTICATION):
            continue
        src, dst = e.source_host, (e.dest_host or (e.host if e.source_host else None))
        if not src or not dst or src == dst:
            continue
        port = e.dest_port
        admin = (port in _ADMIN_PORTS) or (e.protocol in {"smb", "rdp", "winrm", "ssh", "rpc"})
        index.setdefault((src, dst), []).append(_Connection(e.timestamp, port, e.protocol, admin))
    return index


def _credential_maps(events, compromised) -> tuple[dict[str, set[str]], set[str]]:
    users_of: dict[str, set[str]] = {}
    exposed: set[str] = set()
    for e in events:
        if e.event_type != EventType.AUTHENTICATION or not e.normalized_user:
            continue
        user = e.normalized_user
        dst = e.dest_host or e.host
        if dst:
            users_of.setdefault(dst, set()).add(user)
        # A user operating from, or logging into, a compromised host is exposed.
        if e.source_host in compromised or (e.host in compromised) or (dst in compromised):
            exposed.add(user)
    return users_of, exposed


def _reachability(host, compromised, by_recency, conns, reasons) -> float:
    total = 0.0
    best_src, best_proto = None, None
    for c in by_recency:
        cs = conns.get((c, host), [])
        if not cs:
            continue
        admin = [x for x in cs if x.admin]
        total += 1.0 if admin else 0.6
        if admin and best_src is None:
            best_src = c
            best_proto = _protocol_label(admin[0])
    value = total / len(compromised) if compromised else 0.0
    if best_src:
        reasons.append(
            f"reachable from compromised {best_src}"
            + (f" over {best_proto.upper()}" if best_proto else "")
        )
    return value


def _credential_exposure(host, users_of, exposed_users, reasons) -> float:
    users = users_of.get(host, set())
    if not users:
        return 0.0
    hit = users & exposed_users
    if not hit:
        return 0.0
    who = sorted(hit)[0]
    reasons.append(f"credentials for {who} are exposed on a compromised host")
    return len(hit) / len(users)


def _criticality(host, criticality, reasons) -> float:
    crit = criticality.get(host, 0)
    value = crit / 5
    if crit >= 4:
        reasons.append(f"high-value asset (criticality {crit}/5)")
    return value


def _recent_probe(host, by_recency, conns, since, reasons) -> float:
    for c in by_recency:
        for x in sorted(conns.get((c, host), []), key=lambda y: y.timestamp, reverse=True):
            if x.timestamp >= since:
                proto = _protocol_label(x)
                reasons.append(
                    f"recent suspicious connection from {c}"
                    + (f" over {proto.upper()}" if proto else "")
                )
                return 1.0
    return 0.0


def _chain_proximity(host, frontier, compromised, conns, reasons) -> float:
    if conns.get((frontier, host)):
        reasons.append(f"adjacent to the current attack frontier ({frontier})")
        return 1.0
    if any(conns.get((c, host)) for c in compromised):
        return 0.5
    return 0.0
