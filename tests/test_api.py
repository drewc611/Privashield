from datetime import UTC, datetime

from fastapi.testclient import TestClient

from privashield_api.config import Settings
from privashield_api.main import create_app


def build_test_client() -> TestClient:
    settings = Settings(
        database_enabled=False,
        environment="test",
        enforcement_mode="observe",
    )
    return TestClient(create_app(settings))


def sample_event() -> dict:
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "suricata",
        "event_type": "alert",
        "severity": "high",
        "src_ip": "192.0.2.10",
        "src_port": 44321,
        "dst_ip": "198.51.100.20",
        "dst_port": 443,
        "protocol": "tcp",
        "direction": "outbound",
        "summary": "Suspicious outbound TLS connection",
        "metadata": {"signature_id": 900001},
    }


def test_health_and_status() -> None:
    with build_test_client() as client:
        health = client.get("/api/v1/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"

        status = client.get("/api/v1/system/status")
        assert status.status_code == 200
        assert status.json()["database"] == "memory"
        assert status.json()["enforcement_active"] is False


def test_ingest_query_and_stats() -> None:
    with build_test_client() as client:
        created = client.post("/api/v1/events/ingest", json=sample_event())
        assert created.status_code == 201
        event = created.json()
        event_id = event["id"]
        assert event["source"] == "suricata"
        assert event["severity"] == "high"

        fetched = client.get(f"/api/v1/events/{event_id}")
        assert fetched.status_code == 200
        assert fetched.json()["id"] == event_id

        listed = client.get("/api/v1/events", params={"severity": "high"})
        assert listed.status_code == 200
        assert len(listed.json()) == 1

        stats = client.get("/api/v1/events/stats")
        assert stats.status_code == 200
        assert stats.json()["total"] == 1
        assert stats.json()["by_severity"]["high"] == 1


def test_duplicate_event_is_rejected() -> None:
    with build_test_client() as client:
        first = client.post("/api/v1/events/ingest", json=sample_event())
        assert first.status_code == 201
        duplicate = client.post("/api/v1/events/ingest", json=first.json())
        assert duplicate.status_code == 409


def test_invalid_port_is_rejected() -> None:
    payload = sample_event()
    payload["src_port"] = 70000
    with build_test_client() as client:
        response = client.post("/api/v1/events/ingest", json=payload)
        assert response.status_code == 422
