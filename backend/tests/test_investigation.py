"""Tests for the AI investigation assistant (deterministic path)."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.services.analysis import AnalysisService
from app.services.ingestion import IngestionService
from app.services.investigation import (
    InvestigationError,
    InvestigationService,
    build_evidence_bundle,
)
from app.services.llm import AnthropicProvider, get_provider
from app.simulation.generator import generate_dataset


@pytest.fixture
def analyzed(seeded_db: Session) -> Session:
    IngestionService(seeded_db).ingest(generate_dataset().events)
    seeded_db.commit()
    AnalysisService(seeded_db).rebuild()
    seeded_db.commit()
    return seeded_db


def _ask(db: Session, question: str) -> str:
    # No provider => deterministic responder.
    result = InvestigationService(db, provider=None).investigate(1, question)
    assert result.mode == "deterministic"
    return result.answer


def test_entry_question_describes_root_cause(analyzed: Session):
    answer = _ask(analyzed, "How did the attacker enter the network?")
    assert "WEB-01" in answer
    assert "203.0.113.66" in answer


def test_risk_question_for_specific_host(analyzed: Session):
    answer = _ask(analyzed, "Why is DB-01 at risk?")
    assert "DB-01" in answer
    assert "criticality" in answer.lower()


def test_next_target_question(analyzed: Session):
    answer = _ask(analyzed, "What should the analyst investigate next?")
    assert "BACKUP-01" in answer


def test_lateral_movement_question_shows_path(analyzed: Session):
    answer = _ask(analyzed, "Show the lateral movement path.")
    assert "WEB-01" in answer and "APP-01" in answer and "FILE-01" in answer
    assert "→" in answer


def test_evidence_question_lists_support(analyzed: Session):
    answer = _ask(analyzed, "What evidence supports the root cause?")
    assert "WEB-01" in answer
    assert "T10" in answer  # cites ATT&CK technique IDs


def test_answer_does_not_invent_hosts(analyzed: Session):
    # The assistant must only reference hosts present in the evidence bundle.
    for q in [
        "How did the attacker enter?",
        "Show the lateral movement path.",
        "What should I investigate next?",
        "Summarise the incident.",
    ]:
        answer = _ask(analyzed, q)
        for token in ("SERVER-99", "DC-02", "MAIL-01", "VPN-01"):
            assert token not in answer  # never fabricates hosts


def test_evidence_bundle_is_self_contained(analyzed: Session):
    from app.repositories.incidents import IncidentRepository

    bundle = build_evidence_bundle(IncidentRepository(analyzed).get(1))
    assert bundle["root_cause"]["host"] == "WEB-01"
    assert bundle["timeline"] and bundle["lateral_movements"]
    assert bundle["prediction"][0]["host"] == "BACKUP-01"
    assert set(bundle["hosts"]) >= {"WEB-01", "APP-01", "FILE-01"}


def test_unknown_incident_raises(analyzed: Session):
    with pytest.raises(InvestigationError):
        InvestigationService(analyzed).investigate(999, "anything")


def test_empty_question_raises(analyzed: Session):
    with pytest.raises(InvestigationError):
        InvestigationService(analyzed).investigate(1, "   ")


def test_provider_is_none_without_api_key():
    from app.core.config import Settings

    assert get_provider(Settings(llm_api_key=None)) is None


def test_anthropic_provider_unavailable_without_key():
    assert AnthropicProvider("", "claude-sonnet-5-5").available() is False


def test_investigate_endpoint(seeded_client: TestClient):
    seeded_client.post("/api/v1/events/ingest", json=generate_dataset().events)
    seeded_client.post("/api/v1/analysis/run")
    resp = seeded_client.post(
        "/api/v1/investigate",
        json={"incident_id": 1, "question": "How did the attacker enter the network?"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["mode"] == "deterministic"
    assert "WEB-01" in body["answer"]
    assert len(body["suggested_questions"]) >= 3


def test_investigate_endpoint_unknown_incident(seeded_client: TestClient):
    resp = seeded_client.post("/api/v1/investigate", json={"incident_id": 999, "question": "hello"})
    assert resp.status_code == 404
