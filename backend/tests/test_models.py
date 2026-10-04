from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import (
    AttackEdge,
    AttackStep,
    Host,
    HostRiskScore,
    Incident,
    IncidentEvent,
    LateralMovement,
    NetworkConnection,
    SecurityEvent,
    TargetPrediction,
)
from app.models.enums import EventRole, EventType, HostStatus, Relationship, Severity

T0 = datetime(2026, 3, 14, 10, 1, tzinfo=UTC)


def _host(name: str, ip: str, criticality: int = 3) -> Host:
    return Host(
        hostname=name,
        ip_address=ip,
        operating_system="Windows Server 2022",
        department="IT",
        criticality=criticality,
    )


def test_security_event_round_trips_metadata(db: Session) -> None:
    web = _host("WEB-01", "10.10.1.10")
    db.add(web)
    db.flush()
    event = SecurityEvent(
        external_id="evt-1",
        timestamp=T0,
        event_type=EventType.AUTHENTICATION,
        source="windows_security",
        host_id=web.id,
        username="webadmin",
        source_ip="203.0.113.66",
        outcome="success",
        event_metadata={"logon_type": 10},
    )
    db.add(event)
    db.commit()
    db.expire_all()

    stored = db.scalars(select(SecurityEvent)).one()
    assert stored.event_metadata == {"logon_type": 10}
    assert stored.host.hostname == "WEB-01"
    assert stored.ingested_at is not None


def test_host_criticality_is_constrained(db: Session) -> None:
    db.add(_host("BAD-01", "10.0.0.1", criticality=9))
    with pytest.raises(IntegrityError):
        db.commit()


def test_external_id_is_unique(db: Session) -> None:
    for _ in range(2):
        db.add(SecurityEvent(external_id="dup", timestamp=T0, event_type="dns", source="dns"))
    with pytest.raises(IntegrityError):
        db.commit()


def test_deleting_incident_cascades_analysis_output(db: Session) -> None:
    web, app = _host("WEB-01", "10.10.1.10"), _host("APP-01", "10.10.2.20", criticality=4)
    db.add_all([web, app])
    db.flush()
    event = SecurityEvent(timestamp=T0, event_type="process", source="sysmon", host_id=web.id)
    db.add(event)
    db.flush()
    db.add(
        NetworkConnection(
            event_id=event.id, timestamp=T0, source_host_id=web.id, destination_host_id=app.id
        )
    )

    incident = Incident(
        reference="INC-1",
        title="test",
        severity=Severity.CRITICAL,
        first_seen=T0,
        last_seen=T0,
        root_host_id=web.id,
    )
    incident.events.append(
        IncidentEvent(event_id=event.id, role=EventRole.SIGNAL, correlation_confidence=0.9)
    )
    incident.steps.append(
        AttackStep(
            sequence=1,
            timestamp=T0,
            host_id=web.id,
            tactic="Execution",
            technique_id="T1059.001",
            technique_name="PowerShell",
            confidence=0.8,
            description="encoded powershell",
            event_ids=[event.id],
        )
    )
    incident.edges.append(
        AttackEdge(
            source_node="host:WEB-01",
            source_type="host",
            destination_node="host:APP-01",
            destination_type="host",
            relationship_type=Relationship.MOVED_TO,
            timestamp=T0,
            confidence=0.9,
        )
    )
    incident.lateral_movements.append(
        LateralMovement(
            source_host_id=web.id,
            destination_host_id=app.id,
            protocol="winrm",
            timestamp=T0,
            confidence=0.9,
            reason="test",
        )
    )
    incident.host_risks.append(
        HostRiskScore(host_id=web.id, score=80, status=HostStatus.INITIAL_ENTRY)
    )
    incident.predictions.append(TargetPrediction(host_id=app.id, rank=1, score=70))
    db.add(incident)
    db.commit()

    db.delete(incident)
    db.commit()

    for model in (
        IncidentEvent,
        AttackStep,
        AttackEdge,
        LateralMovement,
        HostRiskScore,
        TargetPrediction,
    ):
        assert db.scalar(select(func.count()).select_from(model)) == 0, model.__name__
    # Telemetry is not analysis output and must survive an incident rebuild.
    assert db.scalar(select(func.count()).select_from(SecurityEvent)) == 1
    assert db.scalar(select(func.count()).select_from(NetworkConnection)) == 1
