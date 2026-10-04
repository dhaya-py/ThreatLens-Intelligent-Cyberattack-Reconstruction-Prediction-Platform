from fastapi.testclient import TestClient


def test_health_reports_database_ok(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


def test_openapi_is_published(client: TestClient) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert "/api/v1/health" in response.json()["paths"]
