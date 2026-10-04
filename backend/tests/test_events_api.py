import json

from fastapi.testclient import TestClient

from app.simulation.generator import generate_dataset

SAMPLE = [
    {
        "source": "windows_security",
        "external_id": "api-1",
        "TimeCreated": "2026-03-14T10:01:03.000Z",
        "EventID": 4624,
        "Computer": "WEB-01.corp.local",
        "TargetUserName": "webadmin",
        "LogonType": 10,
        "IpAddress": "203.0.113.66",
    },
    {
        "source": "sysmon",
        "external_id": "api-2",
        "UtcTime": "2026-03-14 10:03:05.000",
        "EventID": 1,
        "Computer": "WEB-01.corp.local",
        "User": "CORP\\webadmin",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "ParentImage": r"C:\Windows\explorer.exe",
        "CommandLine": "powershell.exe -enc AAAA",
        "ProcessId": 4820,
        "ParentProcessId": 3990,
    },
]


def test_ingest_json_then_list_and_get(seeded_client: TestClient) -> None:
    resp = seeded_client.post("/api/v1/events/ingest", json=SAMPLE)
    assert resp.status_code == 200
    body = resp.json()
    assert body["ingested"] == 2
    assert body["by_event_type"] == {"authentication": 1, "process": 1}

    listed = seeded_client.get("/api/v1/events").json()
    assert listed["total"] == 2
    assert [e["external_id"] for e in listed["items"]] == ["api-1", "api-2"]
    assert listed["items"][0]["hostname"] == "WEB-01"

    event_id = listed["items"][0]["id"]
    one = seeded_client.get(f"/api/v1/events/{event_id}").json()
    assert one["external_id"] == "api-1"
    assert one["metadata"]["logon_type"] == 10


def test_list_filters(seeded_client: TestClient) -> None:
    seeded_client.post("/api/v1/events/ingest", json=SAMPLE)
    assert (
        seeded_client.get("/api/v1/events", params={"event_type": "process"}).json()["total"] == 1
    )
    assert seeded_client.get("/api/v1/events", params={"source": "sysmon"}).json()["total"] == 1
    assert seeded_client.get("/api/v1/events", params={"host": "web-01"}).json()["total"] == 2
    assert seeded_client.get("/api/v1/events", params={"username": "nobody"}).json()["total"] == 0


def test_pagination(seeded_client: TestClient) -> None:
    seeded_client.post("/api/v1/events/ingest", json=SAMPLE)
    page = seeded_client.get("/api/v1/events", params={"limit": 1, "offset": 1}).json()
    assert page["total"] == 2
    assert len(page["items"]) == 1
    assert page["items"][0]["external_id"] == "api-2"


def test_unknown_event_returns_404(seeded_client: TestClient) -> None:
    assert seeded_client.get("/api/v1/events/999").status_code == 404


def test_duplicate_ingest_is_reported(seeded_client: TestClient) -> None:
    seeded_client.post("/api/v1/events/ingest", json=SAMPLE)
    again = seeded_client.post("/api/v1/events/ingest", json=SAMPLE).json()
    assert again["ingested"] == 0
    assert again["duplicates"] == 2


def test_csv_file_upload(seeded_client: TestClient) -> None:
    csv_text = generate_dataset().events_csv()
    files = {"file": ("events.csv", csv_text, "text/csv")}
    resp = seeded_client.post("/api/v1/events/ingest/file", files=files)
    assert resp.status_code == 200
    assert resp.json()["failed"] == 0


def test_json_file_upload(seeded_client: TestClient) -> None:
    payload = json.dumps(SAMPLE)
    files = {"file": ("events.json", payload, "application/json")}
    resp = seeded_client.post("/api/v1/events/ingest/file", files=files)
    assert resp.json()["ingested"] == 2


def test_hosts_endpoint(seeded_client: TestClient) -> None:
    hosts = seeded_client.get("/api/v1/hosts").json()
    assert len(hosts) == 14
    db01 = next(h for h in hosts if h["hostname"] == "DB-01")
    assert db01["criticality"] == 5
    assert seeded_client.get(f"/api/v1/hosts/{db01['id']}").json()["hostname"] == "DB-01"
    assert seeded_client.get("/api/v1/hosts/999").status_code == 404


def test_invalid_json_payload_returns_400(seeded_client: TestClient) -> None:
    resp = seeded_client.post(
        "/api/v1/events/ingest", content="{not json", headers={"content-type": "application/json"}
    )
    assert resp.status_code == 400
