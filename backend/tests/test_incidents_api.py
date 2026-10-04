"""End-to-end test: synthetic events -> ingest -> analyze -> incident APIs.

Exercises the whole backend over the test database through HTTP.
"""

import pytest
from fastapi.testclient import TestClient

from app.simulation.generator import generate_dataset


@pytest.fixture
def analyzed_client(seeded_client: TestClient) -> TestClient:
    dataset = generate_dataset()
    resp = seeded_client.post("/api/v1/events/ingest", json=dataset.events)
    assert resp.status_code == 200
    run = seeded_client.post("/api/v1/analysis/run")
    assert run.status_code == 200
    assert run.json()["incidents"] == 1
    return seeded_client


def test_incident_list_and_summary(analyzed_client: TestClient):
    incidents = analyzed_client.get("/api/v1/incidents").json()
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["reference"] == "INC-1042"
    assert inc["severity"] == "critical"
    assert inc["risk_score"] >= 80
    assert inc["root_host"] == "WEB-01"
    assert inc["compromised_hosts"] >= 3
    assert inc["lateral_movements"] == 2
    assert inc["technique_count"] >= 10


def test_incident_detail_has_root_cause(analyzed_client: TestClient):
    inc_id = analyzed_client.get("/api/v1/incidents").json()[0]["id"]
    detail = analyzed_client.get(f"/api/v1/incidents/{inc_id}").json()
    assert detail["root_cause"]["host"] == "WEB-01"
    assert detail["root_cause"]["source_ip"] == "203.0.113.66"
    assert "WEB-01" in detail["summary"]
    assert {m["source_host"] for m in detail["movements"]} == {"WEB-01", "APP-01"}


def test_timeline_is_ordered_kill_chain(analyzed_client: TestClient):
    inc_id = analyzed_client.get("/api/v1/incidents").json()[0]["id"]
    timeline = analyzed_client.get(f"/api/v1/incidents/{inc_id}/timeline").json()
    assert [s["sequence"] for s in timeline] == list(range(1, len(timeline) + 1))
    techniques = [s["technique_id"] for s in timeline]
    assert techniques[0] == "T1110.001"  # brute force first
    assert "T1021.006" in techniques  # WinRM lateral movement
    assert "T1213" in techniques  # database collection


def test_graph_endpoint_has_typed_nodes_and_edges(analyzed_client: TestClient):
    inc_id = analyzed_client.get("/api/v1/incidents").json()[0]["id"]
    graph = analyzed_client.get(f"/api/v1/incidents/{inc_id}/graph").json()
    node_types = {n["type"] for n in graph["nodes"]}
    assert {"host", "ip", "process"} <= node_types
    rels = {e["relationship"] for e in graph["edges"]}
    assert "MOVED_TO" in rels and "AUTHENTICATED_TO" in rels
    # Host nodes are enriched with criticality and computed risk.
    web = next(n for n in graph["nodes"] if n["key"] == "host:WEB-01")
    assert web["attributes"]["criticality"] == 3
    assert "risk" in web["attributes"]
    attacker = next(n for n in graph["nodes"] if n["type"] == "ip" and n["label"] == "203.0.113.66")
    assert attacker["attributes"]["external"] is True


def test_mitre_endpoint(analyzed_client: TestClient):
    inc_id = analyzed_client.get("/api/v1/incidents").json()[0]["id"]
    mitre = analyzed_client.get(f"/api/v1/incidents/{inc_id}/mitre").json()
    ids = {t["technique_id"] for t in mitre["techniques"]}
    assert {"T1110.001", "T1059.001", "T1003.001", "T1021.006", "T1213"} <= ids
    ps = next(t for t in mitre["techniques"] if t["technique_id"] == "T1059.001")
    assert set(ps["hosts"]) == {"WEB-01", "APP-01"}


def test_risk_endpoint_is_transparent(analyzed_client: TestClient):
    inc_id = analyzed_client.get("/api/v1/incidents").json()[0]["id"]
    risk = analyzed_client.get(f"/api/v1/incidents/{inc_id}/risk").json()
    assert risk["severity"] == "critical"
    db = next(h for h in risk["hosts"] if h["host"] == "DB-01")
    assert any(f["name"] == "Asset criticality" and f["points"] == 25 for f in db["factors"])
    for h in risk["hosts"]:
        assert h["score"] == min(100, sum(f["points"] for f in h["factors"]))


def test_prediction_endpoint_names_backup01(analyzed_client: TestClient):
    inc_id = analyzed_client.get("/api/v1/incidents").json()[0]["id"]
    pred = analyzed_client.get(f"/api/v1/incidents/{inc_id}/prediction").json()
    assert pred["top"]["host"] == "BACKUP-01"
    assert pred["top"]["score"] >= 80
    assert any("svc_backup" in r for r in pred["top"]["reasons"])


def test_analysis_is_idempotent(analyzed_client: TestClient):
    # Re-running analysis replaces incidents rather than duplicating them.
    again = analyzed_client.post("/api/v1/analysis/run").json()
    assert again["incidents"] == 1
    assert len(analyzed_client.get("/api/v1/incidents").json()) == 1


def test_unknown_incident_returns_404(analyzed_client: TestClient):
    assert analyzed_client.get("/api/v1/incidents/999").status_code == 404
    assert analyzed_client.get("/api/v1/incidents/999/timeline").status_code == 404
