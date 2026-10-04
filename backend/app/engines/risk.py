"""Transparent risk engine.

Produces a 0-100 score per host and for the incident as a whole. Every score is
the sum of named factors, each carrying the evidence that justifies it — nothing
is random. Weights live in `app.core.scoring` and are configurable.
"""

from dataclasses import dataclass, field

from app.core.scoring import DEFAULT_WEIGHTS, RiskWeights, severity_for
from app.engines.detection import DEFAULT_DETECTION, DetectionResult, detect
from app.engines.lateral_movement import LateralMovement
from app.engines.mitre import AttackStep
from app.engines.types import EventView
from app.models.enums import HostStatus

_UNUSUAL_AUTH_DETECTORS = {
    "external_auth",
    "first_seen_remote_logon",
    "auth_success_after_failures",
}
_CRED_DETECTORS = {"lsass_access", "credential_file_access", "auth_bruteforce"}


@dataclass
class RiskFactor:
    name: str
    points: int
    evidence: str


@dataclass
class HostRisk:
    host: str
    score: int
    status: str
    factors: list[RiskFactor] = field(default_factory=list)


@dataclass
class IncidentRisk:
    score: int
    severity: str
    host_risks: list[HostRisk] = field(default_factory=list)


def compute_risk(
    events: list[EventView],
    criticality: dict[str, int],
    detection: DetectionResult | None = None,
    movements: list[LateralMovement] | None = None,
    steps: list[AttackStep] | None = None,
    root_host: str | None = None,
    weights: RiskWeights = DEFAULT_WEIGHTS,
) -> IncidentRisk:
    detection = detection or detect(events, DEFAULT_DETECTION)
    movements = movements or []
    steps = steps or []
    signal_ids = detection.signal_event_ids(DEFAULT_DETECTION.signal_threshold)

    signals_by_host: dict[str, list[EventView]] = {}
    detectors_by_host: dict[str, set[str]] = {}
    for e in events:
        if e.id in signal_ids and e.host:
            signals_by_host.setdefault(e.host, []).append(e)
            detectors_by_host.setdefault(e.host, set()).update(detection.detectors_for(e.id))

    inbound = {m.destination_host for m in movements}
    outbound = {m.source_host for m in movements}
    cred_hosts = {s.host for s in steps if s.tactic == "Credential Access"}
    data_hosts = {s.host for s in steps if s.tactic == "Collection"}

    involved = set(signals_by_host) | inbound | outbound | {s.host for s in steps if s.host}
    involved.discard(None)

    # Chain-position ordering by earliest signal time (frontier scores highest).
    earliest = {h: min(g, key=lambda e: e.timestamp).timestamp for h, g in signals_by_host.items()}
    ordered = sorted(involved, key=lambda h: earliest.get(h, max(earliest.values(), default=None)))
    max_rank = max(len(ordered) - 1, 1)

    host_risks: list[HostRisk] = []
    for host in involved:
        factors = _host_factors(
            host,
            criticality.get(host),
            signals_by_host.get(host, []),
            detectors_by_host.get(host, set()),
            host in inbound,
            host in outbound,
            host in cred_hosts,
            host in data_hosts,
            ordered.index(host),
            max_rank,
            weights,
        )
        score = min(100, sum(f.points for f in factors))
        host_risks.append(
            HostRisk(host, score, _status(host, root_host, inbound, data_hosts), factors)
        )

    host_risks.sort(key=lambda h: -h.score)
    incident_score = _incident_score(host_risks, inbound, root_host, weights)
    return IncidentRisk(
        score=incident_score, severity=severity_for(incident_score), host_risks=host_risks
    )


def _host_factors(
    host,
    crit,
    signals,
    detectors,
    is_inbound,
    is_outbound,
    is_cred,
    is_data,
    rank,
    max_rank,
    weights,
) -> list[RiskFactor]:
    factors: list[RiskFactor] = []
    if crit:
        pts = min(weights.criticality_cap, crit * weights.criticality_multiplier)
        factors.append(RiskFactor("Asset criticality", pts, f"criticality level {crit}/5"))
    if signals:
        pts = min(weights.signal_cap, weights.per_signal * len(signals))
        factors.append(RiskFactor("Suspicious activity", pts, f"{len(signals)} suspicious events"))
    if is_cred or (detectors & _CRED_DETECTORS):
        factors.append(
            RiskFactor(
                "Credential access",
                weights.credential_access,
                "credential dumping / theft observed on host",
            )
        )
    if is_inbound:
        factors.append(
            RiskFactor(
                "Inbound lateral movement",
                weights.lateral_in,
                "host was moved into from a compromised host",
            )
        )
    if is_outbound:
        factors.append(
            RiskFactor(
                "Outbound lateral movement",
                weights.lateral_out,
                "host was used to move to another host",
            )
        )
    if detectors & _UNUSUAL_AUTH_DETECTORS:
        factors.append(
            RiskFactor(
                "Unusual authentication",
                weights.unusual_auth,
                "external or first-seen authentication",
            )
        )
    if is_data:
        factors.append(
            RiskFactor(
                "Sensitive data access", weights.data_access, "bulk/sensitive data read from host"
            )
        )
    chain_pts = round(weights.chain_position_max * (rank / max_rank))
    if chain_pts:
        factors.append(
            RiskFactor("Attack-chain proximity", chain_pts, "near the current attack frontier")
        )
    return factors


def _status(host, root_host, inbound, data_hosts) -> str:
    if host == root_host:
        return HostStatus.INITIAL_ENTRY
    if host in inbound:
        return HostStatus.COMPROMISED
    if host in data_hosts:
        return HostStatus.ACCESSED
    return HostStatus.OBSERVED


def _incident_score(host_risks, inbound, root_host, weights: RiskWeights) -> int:
    if not host_risks:
        return 0
    compromised = {root_host} | set(inbound)
    compromised.discard(None)
    extra = max(len(compromised) - 1, 0)
    return min(100, host_risks[0].score + weights.incident_per_extra_host * extra)
