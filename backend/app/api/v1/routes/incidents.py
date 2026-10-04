from fastapi import APIRouter, HTTPException

from app.core.database import DbSession
from app.engines.types import is_external_ip
from app.repositories.incidents import IncidentRepository
from app.repositories.inventory import HostRepository
from app.schemas.incidents import (
    AttackStepRead,
    GraphEdgeRead,
    GraphNodeRead,
    GraphRead,
    HostRiskRead,
    IncidentDetail,
    IncidentSummary,
    MitreRead,
    PredictionRead,
    RiskRead,
    TargetPredictionRead,
    TechniqueRead,
)
from app.services.analysis import AnalysisService

router = APIRouter(prefix="/incidents", tags=["incidents"])
analysis_router = APIRouter(prefix="/analysis", tags=["analysis"])


@analysis_router.post("/run", summary="Run the analysis pipeline over ingested telemetry")
def run_analysis(db: DbSession) -> dict:
    summary = AnalysisService(db).rebuild()
    db.commit()
    return {
        "incidents": summary.incidents,
        "events_analyzed": summary.events_analyzed,
        "references": summary.references,
    }


@router.get("", response_model=list[IncidentSummary], summary="List incidents")
def list_incidents(db: DbSession) -> list[IncidentSummary]:
    return [IncidentSummary.from_incident(i) for i in IncidentRepository(db).list()]


def _get_or_404(db, incident_id: int):
    incident = IncidentRepository(db).get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident


@router.get("/{incident_id}", response_model=IncidentDetail, summary="Incident detail")
def get_incident(db: DbSession, incident_id: int) -> IncidentDetail:
    return IncidentDetail.from_incident(_get_or_404(db, incident_id))


@router.get("/{incident_id}/timeline", response_model=list[AttackStepRead], summary="Timeline")
def get_timeline(db: DbSession, incident_id: int) -> list[AttackStepRead]:
    _get_or_404(db, incident_id)
    return [AttackStepRead.from_model(s) for s in IncidentRepository(db).get_steps(incident_id)]


@router.get("/{incident_id}/graph", response_model=GraphRead, summary="Attack graph")
def get_graph(db: DbSession, incident_id: int) -> GraphRead:
    incident = _get_or_404(db, incident_id)
    edges = IncidentRepository(db).get_edges(incident_id)

    # Enrichment for host nodes: criticality + computed risk/status.
    hosts = {h.hostname: h for h in HostRepository(db).all()}
    risk_by_host = {hr.host.hostname: hr for hr in incident.host_risks}

    node_types: dict[str, str] = {}
    for e in edges:
        node_types[e.source_node] = e.source_type
        node_types[e.destination_node] = e.destination_type

    nodes = [
        GraphNodeRead(**_node_payload(key, type_, hosts, risk_by_host))
        for key, type_ in sorted(node_types.items())
    ]
    return GraphRead(nodes=nodes, edges=[GraphEdgeRead.from_model(e) for e in edges])


def _node_payload(key: str, type_: str, hosts, risk_by_host) -> dict:
    label = key.split(":", 1)[1] if ":" in key else key
    attributes: dict = {}
    if type_ == "host":
        host = hosts.get(label)
        if host:
            attributes = {
                "ip_address": host.ip_address,
                "operating_system": host.operating_system,
                "criticality": host.criticality,
                "department": host.department,
            }
            if label in risk_by_host:
                attributes["risk"] = risk_by_host[label].score
                attributes["status"] = risk_by_host[label].status
    elif type_ == "process":
        label = key.split(":")[-1]
        attributes = {"host": key.split(":")[1] if key.count(":") >= 2 else None}
    elif type_ == "ip":
        attributes = {"external": is_external_ip(label)}
    return {"key": key, "type": type_, "label": label, "attributes": attributes}


@router.get("/{incident_id}/mitre", response_model=MitreRead, summary="ATT&CK techniques")
def get_mitre(db: DbSession, incident_id: int) -> MitreRead:
    _get_or_404(db, incident_id)
    steps = IncidentRepository(db).get_steps(incident_id)

    grouped: dict[str, dict] = {}
    for s in steps:
        entry = grouped.setdefault(
            s.technique_id,
            {
                "technique_id": s.technique_id,
                "technique_name": s.technique_name,
                "tactic": s.tactic,
                "confidence": s.confidence,
                "hosts": [],
            },
        )
        entry["confidence"] = max(entry["confidence"], s.confidence)
        if s.host and s.host.hostname not in entry["hosts"]:
            entry["hosts"].append(s.host.hostname)

    return MitreRead(
        techniques=[TechniqueRead(**t) for t in grouped.values()],
        steps=[AttackStepRead.from_model(s) for s in steps],
    )


@router.get("/{incident_id}/risk", response_model=RiskRead, summary="Risk breakdown")
def get_risk(db: DbSession, incident_id: int) -> RiskRead:
    incident = _get_or_404(db, incident_id)
    hosts = sorted(incident.host_risks, key=lambda hr: -hr.score)
    return RiskRead(
        score=incident.risk_score,
        severity=incident.severity,
        hosts=[
            HostRiskRead(
                host=hr.host.hostname,
                score=hr.score,
                status=hr.status,
                factors=hr.factors or [],
            )
            for hr in hosts
        ],
    )


@router.get("/{incident_id}/prediction", response_model=PredictionRead, summary="Next target")
def get_prediction(db: DbSession, incident_id: int) -> PredictionRead:
    incident = _get_or_404(db, incident_id)
    ranking = sorted(incident.predictions, key=lambda p: p.rank)
    items = [
        TargetPredictionRead(
            host=p.host.hostname, rank=p.rank, score=p.score, reasons=list(p.reasons or [])
        )
        for p in ranking
    ]
    return PredictionRead(top=items[0] if items else None, ranking=items)
