from fastapi import APIRouter
from pydantic import BaseModel

from app.core.database import DbSession
from app.services.demo import DemoService

router = APIRouter(prefix="/demo", tags=["demo"])


class DemoLoadResponse(BaseModel):
    incident_reference: str | None
    incidents: int
    events_analyzed: int


@router.post("/load", response_model=DemoLoadResponse, summary="Load the deterministic demo")
def load_demo(db: DbSession) -> DemoLoadResponse:
    """Reset, seed, ingest and analyze the synthetic scenario — reproducible every time."""
    result = DemoService(db).load()
    return DemoLoadResponse(
        incident_reference=result.incident_reference,
        incidents=result.incidents,
        events_analyzed=result.events_analyzed,
    )
