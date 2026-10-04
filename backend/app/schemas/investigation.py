from pydantic import BaseModel, Field


class InvestigateRequest(BaseModel):
    incident_id: int
    question: str = Field(min_length=1, max_length=500)


class InvestigateResponse(BaseModel):
    answer: str
    mode: str  # "llm" | "deterministic"
    used_evidence: list[str]
    suggested_questions: list[str]
