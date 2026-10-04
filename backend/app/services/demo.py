"""Deterministic demo mode.

`load()` resets all telemetry and analysis, re-seeds the inventory, regenerates
the synthetic dataset, ingests it, and runs the analysis pipeline — producing the
exact same incident every time. This is what the "Load Demo Incident" button
calls, so the hackathon demonstration is fully reproducible from one click.
"""

from dataclasses import dataclass

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.models import Incident, NetworkConnection, SecurityEvent
from app.services.analysis import AnalysisService
from app.services.ingestion import IngestionService
from app.services.seed import seed_inventory
from app.simulation.generator import generate_dataset


@dataclass
class DemoResult:
    incident_reference: str | None
    incidents: int
    events_analyzed: int


class DemoService:
    def __init__(self, db: Session):
        self.db = db

    def reset(self) -> None:
        # Incidents cascade to all analysis output and incident_events; deleting
        # security_events cascades to network_connections. Inventory is kept
        # (re-seeded below) so host IDs stay stable within a process.
        self.db.execute(delete(Incident))
        self.db.execute(delete(NetworkConnection))
        self.db.execute(delete(SecurityEvent))
        self.db.flush()

    def load(self) -> DemoResult:
        self.reset()
        seed_inventory(self.db)
        self.db.flush()

        dataset = generate_dataset()
        IngestionService(self.db).ingest(dataset.events)
        self.db.flush()

        summary = AnalysisService(self.db).rebuild()
        self.db.commit()
        return DemoResult(
            incident_reference=summary.references[0] if summary.references else None,
            incidents=summary.incidents,
            events_analyzed=summary.events_analyzed,
        )
