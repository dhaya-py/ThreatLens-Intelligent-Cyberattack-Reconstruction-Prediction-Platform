"""Analysis pipeline: run the engines over persisted telemetry and store the
resulting incidents and all their analysis output.

A rebuild is delete-incidents + insert, so it is idempotent and reproducible: the
engines are deterministic, so the same events always yield the same incidents.
"""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.engines.correlation import correlate
from app.engines.graph import build_graph
from app.engines.lateral_movement import detect_lateral_movement
from app.engines.loader import from_db_events
from app.engines.mitre import map_attack_steps
from app.engines.prediction import predict_next_target
from app.engines.risk import compute_risk
from app.engines.root_cause import detect_root_cause
from app.models import (
    AttackEdge,
    AttackStep,
    HostRiskScore,
    Incident,
    IncidentEvent,
    LateralMovement,
    SecurityEvent,
    TargetPrediction,
)
from app.models.enums import IncidentStatus
from app.repositories.incidents import IncidentRepository
from app.repositories.inventory import HostRepository

_REFERENCE_BASE = 1042


@dataclass
class AnalysisSummary:
    incidents: int
    events_analyzed: int
    references: list[str]


class AnalysisService:
    def __init__(self, db: Session):
        self.db = db

    def rebuild(self) -> AnalysisSummary:
        hosts = HostRepository(self.db).all()
        name_to_host = {h.hostname: h for h in hosts}
        criticality = {h.hostname: h.criticality for h in hosts}

        events = list(
            self.db.scalars(
                select(SecurityEvent).order_by(SecurityEvent.timestamp, SecurityEvent.id)
            )
        )
        views = from_db_events(events)

        IncidentRepository(self.db).delete_all()
        self.db.flush()

        if not views:
            return AnalysisSummary(incidents=0, events_analyzed=0, references=[])

        correlation = correlate(views)
        detection = correlation.detection
        signal_ids = detection.signal_event_ids(0.4)
        movements_all = detect_lateral_movement(views, detection)

        references: list[str] = []
        for index, cluster in enumerate(correlation.clusters):
            incident_ids = set(cluster.event_ids)
            incident_views = [v for v in views if v.id in incident_ids]
            movements = [m for m in movements_all if set(m.event_ids) & incident_ids]

            steps = map_attack_steps(incident_views, detection, movements)
            root = detect_root_cause(incident_views, detection, movements)
            risk = compute_risk(
                incident_views, criticality, detection, movements, steps, root.root_host
            )

            compromised: dict[str, datetime] = {}
            if root.root_host and root.first_seen:
                compromised[root.root_host] = root.first_seen
            for m in movements:
                compromised[m.destination_host] = m.timestamp
            prediction = predict_next_target(views, compromised, criticality)

            graph = build_graph(incident_views, movements, signal_ids=signal_ids)

            reference = f"INC-{_REFERENCE_BASE + index}"
            references.append(reference)
            self._persist(
                reference,
                cluster,
                incident_views,
                steps,
                root,
                risk,
                prediction,
                graph,
                movements,
                detection,
                name_to_host,
            )

        self.db.flush()
        return AnalysisSummary(
            incidents=len(references), events_analyzed=len(views), references=references
        )

    def _persist(
        self,
        reference,
        cluster,
        incident_views,
        steps,
        root,
        risk,
        prediction,
        graph,
        movements,
        detection,
        name_to_host,
    ) -> None:
        signal_confs = [m.confidence for m in cluster.members if m.role == "signal"]
        confidence = round(sum(signal_confs) / len(signal_confs), 3) if signal_confs else 0.0
        root_host = name_to_host.get(root.root_host) if root.root_host else None

        incident = Incident(
            reference=reference,
            title=f"Multi-stage intrusion via {root.root_host or 'unknown host'}",
            severity=risk.severity,
            status=IncidentStatus.OPEN,
            first_seen=cluster.first_seen,
            last_seen=cluster.last_seen,
            root_host_id=root_host.id if root_host else None,
            risk_score=risk.score,
            confidence=confidence,
            summary=root.explanation,
            root_cause={
                "host": root.root_host,
                "first_seen": root.first_seen.isoformat() if root.first_seen else None,
                "source_ip": root.source_ip,
                "confidence": root.confidence,
                "explanation": root.explanation,
                "evidence": root.evidence,
                "ranking": [{"host": h.host, "score": h.score} for h in root.ranking],
            },
        )

        for member in cluster.members:
            incident.events.append(
                IncidentEvent(
                    event_id=member.event_id,
                    role=member.role,
                    correlation_confidence=member.confidence,
                    reasons=member.reasons,
                )
            )

        for step in steps:
            host = name_to_host.get(step.host) if step.host else None
            incident.steps.append(
                AttackStep(
                    sequence=step.sequence,
                    timestamp=step.timestamp,
                    host_id=host.id if host else None,
                    tactic=step.tactic,
                    technique_id=step.technique_id,
                    technique_name=step.technique_name,
                    confidence=step.confidence,
                    description=step.description,
                    evidence=step.evidence,
                    event_ids=[str(e) for e in step.event_ids],
                )
            )

        node_type = {n.key: n.type for n in graph.nodes}
        for edge in graph.edges:
            incident.edges.append(
                AttackEdge(
                    source_node=edge.source,
                    source_type=node_type.get(edge.source, "host"),
                    destination_node=edge.destination,
                    destination_type=node_type.get(edge.destination, "host"),
                    relationship_type=edge.relationship,
                    timestamp=edge.timestamp,
                    username=edge.username,
                    protocol=edge.protocol,
                    port=edge.port,
                    confidence=edge.confidence,
                    evidence=edge.evidence,
                    event_ids=[str(e) for e in edge.event_ids],
                )
            )

        for m in movements:
            src, dst = name_to_host.get(m.source_host), name_to_host.get(m.destination_host)
            if not src or not dst:
                continue
            incident.lateral_movements.append(
                LateralMovement(
                    source_host_id=src.id,
                    destination_host_id=dst.id,
                    username=m.username,
                    protocol=m.protocol,
                    port=m.port,
                    timestamp=m.timestamp,
                    confidence=m.confidence,
                    reason=m.reason,
                    evidence=m.evidence,
                    event_ids=[str(e) for e in m.event_ids],
                )
            )

        for hr in risk.host_risks:
            host = name_to_host.get(hr.host)
            if not host:
                continue
            incident.host_risks.append(
                HostRiskScore(
                    host_id=host.id,
                    score=hr.score,
                    status=hr.status,
                    factors=[
                        {"name": f.name, "points": f.points, "evidence": f.evidence}
                        for f in hr.factors
                    ],
                )
            )

        for target in prediction.ranking:
            host = name_to_host.get(target.host)
            if not host:
                continue
            incident.predictions.append(
                TargetPrediction(
                    host_id=host.id, rank=target.rank, score=target.score, reasons=target.reasons
                )
            )

        self.db.add(incident)
