from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, selectinload

from app.models import (
    AttackEdge,
    AttackStep,
    HostRiskScore,
    Incident,
    LateralMovement,
    TargetPrediction,
)


class IncidentRepository:
    def __init__(self, db: Session):
        self.db = db

    def delete_all(self) -> None:
        # Children cascade via FK ondelete=CASCADE.
        self.db.execute(delete(Incident))

    def list(self) -> list[Incident]:
        return list(
            self.db.scalars(
                select(Incident)
                .options(
                    selectinload(Incident.root_host),
                    selectinload(Incident.host_risks),
                    selectinload(Incident.lateral_movements),
                    selectinload(Incident.steps),
                )
                .order_by(Incident.first_seen)
            )
        )

    def get(self, incident_id: int) -> Incident | None:
        return self.db.scalar(
            select(Incident)
            .where(Incident.id == incident_id)
            .options(
                selectinload(Incident.root_host),
                selectinload(Incident.host_risks).selectinload(HostRiskScore.host),
                selectinload(Incident.predictions).selectinload(TargetPrediction.host),
                selectinload(Incident.lateral_movements).selectinload(LateralMovement.source_host),
                selectinload(Incident.lateral_movements).selectinload(
                    LateralMovement.destination_host
                ),
                selectinload(Incident.steps).selectinload(AttackStep.host),
                selectinload(Incident.edges),
            )
        )

    def get_steps(self, incident_id: int) -> list[AttackStep]:
        return list(
            self.db.scalars(
                select(AttackStep)
                .where(AttackStep.incident_id == incident_id)
                .options(selectinload(AttackStep.host))
                .order_by(AttackStep.sequence)
            )
        )

    def get_edges(self, incident_id: int) -> list[AttackEdge]:
        return list(
            self.db.scalars(
                select(AttackEdge)
                .where(AttackEdge.incident_id == incident_id)
                .order_by(AttackEdge.timestamp)
            )
        )
