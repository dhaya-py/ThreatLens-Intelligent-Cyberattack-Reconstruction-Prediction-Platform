"""ORM models. Importing this package registers every table on `Base.metadata`."""

from app.models.analysis import (
    AttackEdge,
    AttackStep,
    HostRiskScore,
    Incident,
    IncidentEvent,
    LateralMovement,
    TargetPrediction,
)
from app.models.base import Base
from app.models.inventory import Host, User
from app.models.telemetry import NetworkConnection, SecurityEvent

__all__ = [
    "AttackEdge",
    "AttackStep",
    "Base",
    "Host",
    "HostRiskScore",
    "Incident",
    "IncidentEvent",
    "LateralMovement",
    "NetworkConnection",
    "SecurityEvent",
    "TargetPrediction",
    "User",
]
