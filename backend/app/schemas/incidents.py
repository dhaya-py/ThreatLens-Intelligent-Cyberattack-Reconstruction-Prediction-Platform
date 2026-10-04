from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.models import AttackEdge, AttackStep, Incident, LateralMovement


class IncidentSummary(BaseModel):
    id: int
    reference: str
    title: str
    severity: str
    status: str
    first_seen: datetime
    last_seen: datetime
    risk_score: int
    confidence: float
    root_host: str | None
    compromised_hosts: int
    lateral_movements: int
    technique_count: int

    @classmethod
    def from_incident(cls, incident: Incident) -> "IncidentSummary":
        compromised = sum(
            1 for hr in incident.host_risks if hr.status in ("initial_entry", "compromised")
        )
        techniques = {s.technique_id for s in incident.steps}
        return cls(
            id=incident.id,
            reference=incident.reference,
            title=incident.title,
            severity=incident.severity,
            status=incident.status,
            first_seen=incident.first_seen,
            last_seen=incident.last_seen,
            risk_score=incident.risk_score,
            confidence=incident.confidence,
            root_host=incident.root_host.hostname if incident.root_host else None,
            compromised_hosts=compromised,
            lateral_movements=len(incident.lateral_movements),
            technique_count=len(techniques),
        )


class LateralMovementRead(BaseModel):
    source_host: str
    destination_host: str
    username: str | None
    protocol: str
    port: int | None
    timestamp: datetime
    confidence: float
    reason: str

    @classmethod
    def from_model(cls, m: LateralMovement) -> "LateralMovementRead":
        return cls(
            source_host=m.source_host.hostname,
            destination_host=m.destination_host.hostname,
            username=m.username,
            protocol=m.protocol,
            port=m.port,
            timestamp=m.timestamp,
            confidence=m.confidence,
            reason=m.reason,
        )


class IncidentDetail(IncidentSummary):
    summary: str | None
    root_cause: dict[str, Any]
    movements: list[LateralMovementRead]

    @classmethod
    def from_incident(cls, incident: Incident) -> "IncidentDetail":
        base = IncidentSummary.from_incident(incident).model_dump()
        return cls(
            **base,
            summary=incident.summary,
            root_cause=incident.root_cause or {},
            movements=[LateralMovementRead.from_model(m) for m in incident.lateral_movements],
        )


class AttackStepRead(BaseModel):
    sequence: int
    timestamp: datetime
    host: str | None
    tactic: str
    technique_id: str
    technique_name: str
    confidence: float
    description: str
    evidence: list[str]
    event_ids: list[str]

    @classmethod
    def from_model(cls, s: AttackStep) -> "AttackStepRead":
        return cls(
            sequence=s.sequence,
            timestamp=s.timestamp,
            host=s.host.hostname if s.host else None,
            tactic=s.tactic,
            technique_id=s.technique_id,
            technique_name=s.technique_name,
            confidence=s.confidence,
            description=s.description,
            evidence=list(s.evidence or []),
            event_ids=list(s.event_ids or []),
        )


class GraphNodeRead(BaseModel):
    key: str
    type: str
    label: str
    attributes: dict[str, Any]


class GraphEdgeRead(BaseModel):
    source: str
    destination: str
    relationship: str
    timestamp: datetime
    username: str | None
    protocol: str | None
    port: int | None
    confidence: float
    evidence: list[str]
    event_ids: list[str]

    @classmethod
    def from_model(cls, e: AttackEdge) -> "GraphEdgeRead":
        return cls(
            source=e.source_node,
            destination=e.destination_node,
            relationship=e.relationship_type,
            timestamp=e.timestamp,
            username=e.username,
            protocol=e.protocol,
            port=e.port,
            confidence=e.confidence,
            evidence=list(e.evidence or []),
            event_ids=list(e.event_ids or []),
        )


class GraphRead(BaseModel):
    nodes: list[GraphNodeRead]
    edges: list[GraphEdgeRead]


class TechniqueRead(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    hosts: list[str]


class MitreRead(BaseModel):
    techniques: list[TechniqueRead]
    steps: list[AttackStepRead]


class RiskFactorRead(BaseModel):
    name: str
    points: int
    evidence: str


class HostRiskRead(BaseModel):
    host: str
    score: int
    status: str
    factors: list[RiskFactorRead]


class RiskRead(BaseModel):
    score: int
    severity: str
    hosts: list[HostRiskRead]


class TargetPredictionRead(BaseModel):
    host: str
    rank: int
    score: int
    reasons: list[str]


class PredictionRead(BaseModel):
    top: TargetPredictionRead | None
    ranking: list[TargetPredictionRead]


class AnalysisSummaryRead(BaseModel):
    incidents: int
    events_analyzed: int
    references: list[str]
