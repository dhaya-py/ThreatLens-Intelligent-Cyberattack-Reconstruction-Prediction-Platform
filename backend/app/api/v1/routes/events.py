from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, UploadFile

from app.core.database import DbSession
from app.schemas.events import EventPage, IngestResponse, SecurityEventRead
from app.services.ingestion import IngestionService, parse_csv, parse_json

router = APIRouter(prefix="/events", tags=["events"])


def _ingest(db: DbSession, records: list[dict]) -> IngestResponse:
    service = IngestionService(db)
    result = service.ingest(records)
    db.commit()
    return IngestResponse(**result.as_dict())


@router.post("/ingest", response_model=IngestResponse, summary="Ingest JSON telemetry")
async def ingest_events(db: DbSession, request: Request) -> IngestResponse:
    """Ingest a JSON array of raw telemetry records (or `{"events": [...]}`)."""
    body = (await request.body()).decode("utf-8")
    try:
        records = parse_json(body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid JSON payload: {exc}") from exc
    return _ingest(db, records)


@router.post("/ingest/file", response_model=IngestResponse, summary="Ingest a JSON or CSV file")
async def ingest_file(db: DbSession, file: UploadFile) -> IngestResponse:
    """Ingest an uploaded `.json` or `.csv` telemetry file."""
    text = (await file.read()).decode("utf-8")
    name = (file.filename or "").lower()
    try:
        records = parse_csv(text) if name.endswith(".csv") else parse_json(text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"could not parse file: {exc}") from exc
    return _ingest(db, records)


@router.get("", response_model=EventPage, summary="List security events")
def list_events(
    db: DbSession,
    event_type: Annotated[str | None, Query()] = None,
    source: Annotated[str | None, Query()] = None,
    host: Annotated[str | None, Query(description="hostname")] = None,
    username: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> EventPage:
    service = IngestionService(db)
    items, total = service.events.query(
        event_type=event_type,
        source=source,
        hostname=host,
        username=username,
        limit=limit,
        offset=offset,
    )
    return EventPage(
        items=[SecurityEventRead.from_event(e) for e in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{event_id}", response_model=SecurityEventRead, summary="Get one event")
def get_event(db: DbSession, event_id: int) -> SecurityEventRead:
    event = IngestionService(db).events.get(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="event not found")
    return SecurityEventRead.from_event(event)
