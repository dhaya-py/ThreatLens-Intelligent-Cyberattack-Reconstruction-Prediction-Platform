from fastapi import APIRouter
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.core.database import DbSession
from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(db: DbSession) -> HealthResponse:
    """Liveness plus a database round-trip."""
    try:
        db.execute(text("SELECT 1"))
        database = "ok"
    except SQLAlchemyError:
        database = "unavailable"
    return HealthResponse(status="ok" if database == "ok" else "degraded", database=database)
