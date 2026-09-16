from datetime import UTC, datetime, timedelta
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


def ingest(
    api: TestClient,
    *,
    source: str,
    timestamp: datetime,
    asset_id: str | None = None,
    user_id: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    severity: str = "medium",
) -> dict:
    payload = {
        "timestamp": timestamp.isoformat(),
        "source": source,
        "event_type": f"{source}.signal",
        "severity": severity,
        "asset_id": asset_id,
        "user_id": user_id,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "summary": f"Test {source} signal",
    }
    response = api.post("/api/v1/events/ingest", json=payload)
    assert response.status_code == 201
    return response.json()


def test_candidates_correlate_shared_asset_across_sources() -> None:
    now = datetime.now(UTC)
    asset_id = str(uuid4())

    with client() as api:
        first = ingest(
            api,
            source="suricata",
            timestamp=now - timedelta(minutes=2),
            asset_id=asset_id,
            src_ip="10.0.0.25",
            dst_ip="198.51.100.20",
            severity="high",
        )
        second = ingest(
            api,
            source="host",
            timestamp=now - timedelta(minutes=1),
            asset_id=asset_id,
            src_ip="10.0.0.25",
            severity="medium",
        )

        response = api.get(
            "/api/v1/incidents/candidates",
            params={"lookback_minutes": 15, "max_time_gap_seconds": 300},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["evaluated_events"] == 2
        assert len(body["incidents"]) == 1

        incident = body["incidents"][0]
        assert incident["event_count"] == 2
        assert incident["source_count"] == 2
        assert set(incident["sources"]) == {"host", "suricata"}
        assert incident["severity"] == "high"
        assert incident["enforced"] is False
        assert incident["score"] >= 0.65
        assert set(incident["event_ids"]) == {first["id"], second["id"]}
        assert {item["indicator_type"] for item in incident["shared_indicators"]} >= {
            "asset_id",
            "ip",
        }


def test_same_source_events_do_not_become_cross_sensor_incident() -> None:
    now = datetime.now(UTC)
    asset_id = str(uuid4())

    with client() as api:
        ingest(api, source="suricata", timestamp=now, asset_id=asset_id)
        ingest(
            api,
            source="suricata",
            timestamp=now + timedelta(seconds=30),
            asset_id=asset_id,
        )

        response = api.get("/api/v1/incidents/candidates")
        assert response.status_code == 200
        assert response.json()["incidents"] == []


def test_time_gap_prevents_unrelated_cross_source_correlation() -> None:
    now = datetime.now(UTC)
    user_id = "analyst@example.com"

    with client() as api:
        first = ingest(api, source="identity", timestamp=now, user_id=user_id)
        second = ingest(
            api,
            source="waf",
            timestamp=now + timedelta(minutes=10),
            user_id=user_id,
        )

        response = api.post(
            "/api/v1/incidents/correlate",
            json={
                "event_ids": [first["id"], second["id"]],
                "max_time_gap_seconds": 60,
            },
        )
        assert response.status_code == 200
        assert response.json()["incidents"] == []


def test_selected_correlation_id_is_stable_across_input_order() -> None:
    now = datetime.now(UTC)

    with client() as api:
        first = ingest(
            api,
            source="zeek",
            timestamp=now,
            src_ip="10.10.10.5",
            dst_ip="203.0.113.44",
        )
        second = ingest(
            api,
            source="waf",
            timestamp=now + timedelta(seconds=15),
            src_ip="203.0.113.44",
        )

        forward = api.post(
            "/api/v1/incidents/correlate",
            json={"event_ids": [first["id"], second["id"]]},
        )
        reverse = api.post(
            "/api/v1/incidents/correlate",
            json={"event_ids": [second["id"], first["id"]]},
        )
        assert forward.status_code == 200
        assert reverse.status_code == 200
        assert forward.json()["incidents"][0]["correlation_id"] == reverse.json()["incidents"][0][
            "correlation_id"
        ]


def test_selected_correlation_rejects_missing_event() -> None:
    now = datetime.now(UTC)

    with client() as api:
        event = ingest(api, source="host", timestamp=now, user_id="operator@example.com")
        missing = str(uuid4())
        response = api.post(
            "/api/v1/incidents/correlate",
            json={"event_ids": [event["id"], missing]},
        )
        assert response.status_code == 404
        assert missing in response.text
