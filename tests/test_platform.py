from datetime import UTC, datetime
from uuid import uuid4

from fastapi.testclient import TestClient

from privashield_api.config import Settings
from privashield_api.main import create_app


def client() -> TestClient:
    return TestClient(
        create_app(
            Settings(
                database_enabled=False,
                nats_enabled=False,
                ollama_enabled=False,
                audit_path=None,
                enforcement_mode="observe",
                environment="test",
            )
        )
    )


def event_payload() -> dict:
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "suricata",
        "event_type": "alert",
        "severity": "high",
        "src_ip": "192.0.2.1",
        "dst_ip": "198.51.100.1",
        "summary": "Test detection",
    }


def test_sensor_heartbeat_and_status() -> None:
    sensor_id = str(uuid4())
    with client() as api:
        response = api.post(
            "/api/v1/sensors/heartbeat",
            json={
                "sensor_id": sensor_id,
                "name": "suricata-local",
                "sensor_type": "suricata",
                "hostname": "localhost",
                "interface": "eth0",
                "capabilities": ["eve-json"],
            },
        )
        assert response.status_code == 200
        assert response.json()["active"] is True
        listed = api.get("/api/v1/sensors")
        assert listed.status_code == 200
        assert listed.json()[0]["sensor_id"] == sensor_id


def test_firewall_is_simulation_only_and_audited() -> None:
    with client() as api:
        config = api.patch(
            "/api/v1/firewall/config",
            json={"mode": "simulate", "threshold": 0.7},
        )
        assert config.status_code == 200
        result = api.post(
            "/api/v1/firewall/evaluate",
            json={"risk_score": 0.9, "reason": "synthetic high-risk pattern"},
        )
        assert result.status_code == 200
        assert result.json()["decision"] == "would_drop"
        assert result.json()["enforced"] is False
        verification = api.get("/api/v1/audit/verify")
        assert verification.status_code == 200
        assert verification.json()["valid"] is True
        assert verification.json()["entries"] == 2


def test_ai_is_advisory_and_disabled_by_default() -> None:
    with client() as api:
        created = api.post("/api/v1/events/ingest", json=event_payload()).json()
        status = api.get("/api/v1/ai/status")
        assert status.status_code == 200
        assert status.json()["authority"] == "advisory-only"
        response = api.post(
            "/api/v1/ai/analyze",
            json={"event_ids": [created["id"]]},
        )
        assert response.status_code == 503


def test_websocket_receives_ingested_event() -> None:
    with client() as api:
        with api.websocket_connect("/api/v1/ws/events") as socket:
            created = api.post("/api/v1/events/ingest", json=event_payload())
            assert created.status_code == 201
            message = socket.receive_json()
            assert message["type"] == "security.event"
            assert message["data"]["id"] == created.json()["id"]


def test_system_status_exposes_component_state() -> None:
    with client() as api:
        response = api.get("/api/v1/system/status")
        assert response.status_code == 200
        body = response.json()
        assert body["event_bus"] == "disabled"
        assert body["ai"] == "disabled"
        assert body["enforcement_active"] is False
