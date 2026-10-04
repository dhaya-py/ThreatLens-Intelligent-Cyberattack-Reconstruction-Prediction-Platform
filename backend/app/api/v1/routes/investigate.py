from fastapi import APIRouter, HTTPException

from app.core.database import DbSession
from app.schemas.investigation import InvestigateRequest, InvestigateResponse
from app.services.investigation import InvestigationError, InvestigationService

router = APIRouter(tags=["investigation"])


@router.post("/investigate", response_model=InvestigateResponse, summary="Ask the assistant")
def investigate(db: DbSession, body: InvestigateRequest) -> InvestigateResponse:
    """Answer an analyst question from an incident's structured evidence only."""
    try:
        result = InvestigationService(db).investigate(body.incident_id, body.question)
    except InvestigationError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return InvestigateResponse(
        answer=result.answer,
        mode=result.mode,
        used_evidence=result.used_evidence,
        suggested_questions=result.suggested_questions,
    )
