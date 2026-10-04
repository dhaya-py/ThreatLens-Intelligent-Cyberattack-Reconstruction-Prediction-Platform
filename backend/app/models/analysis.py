"""Analysis output. Every table here is rebuilt by the analysis pipeline and
cascade-deletes from `incidents`, so a rebuild is delete-incidents + insert."""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.enums import IncidentStatus
from app.models.inventory import Host

_INCIDENT_FK = "incidents.id"


def _incident_fk() -> Mapped[int]:
    return mapped_column(ForeignKey(_INCIDENT_FK, ondelete="CASCADE"), index=True)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(32), unique=True)
    title: Mapped[str] = mapped_column(String(256))
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default=IncidentStatus.OPEN)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    root_host_id: Mapped[int | None] = mapped_column(ForeignKey("hosts.id"))
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    summary: Mapped[str | None] = mapped_column(Text)
    # Root-cause verdict: host, first suspicious timestamp, source IP, evidence, explanation.
    root_cause: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    root_host: Mapped[Host | None] = relationship()
    events: Mapped[list["IncidentEvent"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", passive_deletes=True
    )
    steps: Mapped[list["AttackStep"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="AttackStep.sequence",
    )
    edges: Mapped[list["AttackEdge"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", passive_deletes=True
    )
    lateral_movements: Mapped[list["LateralMovement"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="LateralMovement.timestamp",
    )
    host_risks: Mapped[list["HostRiskScore"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", passive_deletes=True
    )
    predictions: Mapped[list["TargetPrediction"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="TargetPrediction.rank",
    )


class IncidentEvent(Base):
    """Membership of a security event in an incident, with correlation confidence."""

    __tablename__ = "incident_events"

    incident_id: Mapped[int] = mapped_column(
        ForeignKey(_INCIDENT_FK, ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[int] = mapped_column(
        ForeignKey("security_events.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[str] = mapped_column(String(16))
    correlation_confidence: Mapped[float] = mapped_column(Float)
    reasons: Mapped[list[Any]] = mapped_column(default=list)

    incident: Mapped[Incident] = relationship(back_populates="events")


class AttackStep(Base):
    __tablename__ = "attack_steps"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = _incident_fk()
    sequence: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    host_id: Mapped[int | None] = mapped_column(ForeignKey("hosts.id"))
    tactic: Mapped[str] = mapped_column(String(64))
    technique_id: Mapped[str] = mapped_column(String(16))
    technique_name: Mapped[str] = mapped_column(String(128))
    confidence: Mapped[float] = mapped_column(Float)
    description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list[Any]] = mapped_column(default=list)
    event_ids: Mapped[list[Any]] = mapped_column(default=list)

    incident: Mapped[Incident] = relationship(back_populates="steps")
    host: Mapped[Host | None] = relationship()


class AttackEdge(Base):
    """An edge of the incident graph. Node keys are typed, e.g. `host:WEB-01`."""

    __tablename__ = "attack_edges"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = _incident_fk()
    source_node: Mapped[str] = mapped_column(String(320))
    source_type: Mapped[str] = mapped_column(String(16))
    destination_node: Mapped[str] = mapped_column(String(320))
    destination_type: Mapped[str] = mapped_column(String(16))
    relationship_type: Mapped[str] = mapped_column("relationship", String(32))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    username: Mapped[str | None] = mapped_column(String(128))
    protocol: Mapped[str | None] = mapped_column(String(16))
    port: Mapped[int | None] = mapped_column(Integer)
    confidence: Mapped[float] = mapped_column(Float)
    evidence: Mapped[list[Any]] = mapped_column(default=list)
    event_ids: Mapped[list[Any]] = mapped_column(default=list)

    incident: Mapped[Incident] = relationship(back_populates="edges")


class LateralMovement(Base):
    __tablename__ = "lateral_movements"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = _incident_fk()
    source_host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"))
    destination_host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"))
    username: Mapped[str | None] = mapped_column(String(128))
    protocol: Mapped[str] = mapped_column(String(16))
    port: Mapped[int | None] = mapped_column(Integer)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    confidence: Mapped[float] = mapped_column(Float)
    reason: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list[Any]] = mapped_column(default=list)
    event_ids: Mapped[list[Any]] = mapped_column(default=list)

    incident: Mapped[Incident] = relationship(back_populates="lateral_movements")
    source_host: Mapped[Host] = relationship(foreign_keys=[source_host_id])
    destination_host: Mapped[Host] = relationship(foreign_keys=[destination_host_id])


class HostRiskScore(Base):
    __tablename__ = "host_risk_scores"
    __table_args__ = (UniqueConstraint("incident_id", "host_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = _incident_fk()
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"))
    score: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16))
    # [{"name": ..., "points": ..., "evidence": [...]}, ...]
    factors: Mapped[list[Any]] = mapped_column(default=list)

    incident: Mapped[Incident] = relationship(back_populates="host_risks")
    host: Mapped[Host] = relationship()


class TargetPrediction(Base):
    __tablename__ = "target_predictions"
    __table_args__ = (UniqueConstraint("incident_id", "host_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = _incident_fk()
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"))
    rank: Mapped[int] = mapped_column(Integer)
    score: Mapped[int] = mapped_column(Integer)
    reasons: Mapped[list[Any]] = mapped_column(default=list)

    incident: Mapped[Incident] = relationship(back_populates="predictions")
    host: Mapped[Host] = relationship()
