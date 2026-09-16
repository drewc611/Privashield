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
                environment="test",
            )
        )
    )


def ingest_event(api: TestClient) -> dict:
    response = api.post(
        "/api/v1/events/ingest",
        json={
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "suricata",
            "event_type": "alert",
            "severity": "high",
            "src_ip": "10.0.0.15",
            "dst_ip": "198.51.100.25",
            "summary": "Test IDS alert",
        },
    )
    assert response.status_code == 201
    return response.json()


def test_event_feedback_requires_existing_event() -> None:
    with client() as api:
        response = api.post(
            "/api/v1/feedback",
            json={
                "target_type": "event",
                "target_id": str(uuid4()),
                "label": "false_positive",
            },
        )
        assert response.status_code == 404
        assert response.json()["detail"] == "target event not found"


def test_create_event_feedback_is_structured_and_unverified() -> None:
    with client() as api:
        event = ingest_event(api)
        response = api.post(
            "/api/v1/feedback",
            json={
                "target_type": "event",
                "target_id": event["id"],
                "label": "true_positive",
                "detector": "suricata",
                "note": "Confirmed malicious test traffic.",
                "tags": ["validated", "ids"],
            },
        )
        assert response.status_code == 201
        body = response.json()
        assert body["target_id"] == event["id"]
        assert body["label"] == "true_positive"
        assert body["detector"] == "suricata"
        assert body["identity_verified"] is False
        assert set(body["tags"]) == {"validated", "ids"}


def test_incident_feedback_accepts_stable_correlation_identifier() -> None:
    correlation_id = str(uuid4())
    with client() as api:
        response = api.post(
            "/api/v1/feedback",
            json={
                "target_type": "incident",
                "target_id": correlation_id,
                "label": "needs_review",
                "note": "Escalate for additional host evidence.",
            },
        )
        assert response.status_code == 201
        assert response.json()["target_id"] == correlation_id
        assert response.json()["target_type"] == "incident"


def test_feedback_list_filters_and_stats() -> None:
    with client() as api:
        event = ingest_event(api)
        first = api.post(
            "/api/v1/feedback",
            json={
                "target_type": "event",
                "target_id": event["id"],
                "label": "true_positive",
            },
        )
        assert first.status_code == 201
        second = api.post(
            "/api/v1/feedback",
            json={
                "target_type": "incident",
                "target_id": str(uuid4()),
                "label": "benign",
            },
        )
        assert second.status_code == 201

        filtered = api.get("/api/v1/feedback", params={"label": "true_positive"})
        assert filtered.status_code == 200
        items = filtered.json()
        assert len(items) == 1
        assert items[0]["target_id"] == event["id"]

        stats = api.get("/api/v1/feedback/stats")
        assert stats.status_code == 200
        body = stats.json()
        assert body["total"] == 2
        assert body["by_label"]["true_positive"] == 1
        assert body["by_label"]["benign"] == 1
        assert body["by_target_type"]["event"] == 1
        assert body["by_target_type"]["incident"] == 1
