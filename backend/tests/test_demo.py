"""Demo mode: one call must reset, rebuild and produce the same incident every time."""

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Incident, NetworkConnection, SecurityEvent
from app.services.demo import DemoService


def _snapshot(client: TestClient, incident_id: int) -> dict:
    detail = client.get(f"/api/v1/incidents/{incident_id}").json()
    timeline = client.get(f"/api/v1/incidents/{incident_id}/timeline").json()
    prediction = client.get(f"/api/v1/incidents/{incident_id}/prediction").json()
    risk = client.get(f"/api/v1/incidents/{incident_id}/risk").json()
    return {
        "severity": detail["severity"],
        "risk_score": detail["risk_score"],
        "root_host": detail["root_host"],
        "techniques": [s["technique_id"] for s in timeline],
        "top_target": prediction["top"]["host"],
        "top_score": prediction["top"]["score"],
        "host_scores": {h["host"]: h["score"] for h in risk["hosts"]},
    }


def test_demo_load_builds_the_incident_from_empty(client: TestClient):
    result = client.post("/api/v1/demo/load").json()
    assert result["incident_reference"] == "INC-1042"
    assert result["incidents"] == 1
    assert result["events_analyzed"] == 989

    incidents = client.get("/api/v1/incidents").json()
    assert len(incidents) == 1
    snap = _snapshot(client, incidents[0]["id"])
    assert snap["severity"] == "critical"
    assert snap["root_host"] == "WEB-01"
    assert snap["top_target"] == "BACKUP-01"


def test_demo_is_reproducible(client: TestClient):
    first_id = client.post("/api/v1/demo/load").json()
    incidents = client.get("/api/v1/incidents").json()
    snap1 = _snapshot(client, incidents[0]["id"])

    # Load again: must reset and produce an identical result, not duplicate.
    client.post("/api/v1/demo/load")
    incidents = client.get("/api/v1/incidents").json()
    assert len(incidents) == 1  # no duplicate incident
    snap2 = _snapshot(client, incidents[0]["id"])

    assert snap1 == snap2
    assert first_id["incident_reference"] == "INC-1042"


def test_reset_clears_telemetry_and_analysis(seeded_db: Session):
    service = DemoService(seeded_db)
    service.load()
    assert seeded_db.scalar(select(func.count()).select_from(SecurityEvent)) == 989

    service.reset()
    seeded_db.flush()
    assert seeded_db.scalar(select(func.count()).select_from(SecurityEvent)) == 0
    assert seeded_db.scalar(select(func.count()).select_from(NetworkConnection)) == 0
    assert seeded_db.scalar(select(func.count()).select_from(Incident)) == 0


def test_demo_load_is_idempotent_on_event_count(seeded_db: Session):
    DemoService(seeded_db).load()
    first = seeded_db.scalar(select(func.count()).select_from(SecurityEvent))
    DemoService(seeded_db).load()
    second = seeded_db.scalar(select(func.count()).select_from(SecurityEvent))
    assert first == second == 989  # reset prevents accumulation
