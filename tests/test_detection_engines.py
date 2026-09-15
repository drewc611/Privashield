from datetime import UTC, datetime, timedelta

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


def test_dlp_classifies_and_redacts_restricted_data() -> None:
    with client() as api:
        response = api.post(
            "/api/v1/dlp/classify",
            json={
                "text": "Contact drew@example.com. SSN 123-45-6789. Card 4111 1111 1111 1111.",
                "permission_tier": "internal",
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["sensitivity"] == "restricted"
        assert "ssn" in body["labels"]
        assert "payment_card" in body["labels"]
        assert "123-45-6789" not in body["redacted_text"]
        assert "4111 1111 1111 1111" not in body["redacted_text"]


def test_identity_engine_detects_impossible_travel() -> None:
    now = datetime.now(UTC)
    with client() as api:
        first = api.post(
            "/api/v1/anomaly/evaluate",
            json={
                "user_id": "analyst@example.com",
                "timestamp": now.isoformat(),
                "event_type": "login",
                "latitude": 40.7128,
                "longitude": -74.0060,
            },
        )
        assert first.status_code == 200
        second = api.post(
            "/api/v1/anomaly/evaluate",
            json={
                "user_id": "analyst@example.com",
                "timestamp": (now + timedelta(hours=1)).isoformat(),
                "event_type": "login",
                "latitude": 51.5072,
                "longitude": -0.1276,
            },
        )
        assert second.status_code == 200
        body = second.json()
        assert body["risk_score"] >= 0.65
        assert any("Impossible travel" in reason for reason in body["reasons"])


def test_ransomware_engine_flags_mass_encryption_behavior() -> None:
    with client() as api:
        response = api.post(
            "/api/v1/ransomware/evaluate",
            json={
                "window_seconds": 10,
                "file_operations": 500,
                "renamed_files": 250,
                "extension_changes": 200,
                "high_entropy_writes": 220,
                "distinct_directories": 30,
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["severity"] in {"high", "critical"}
        assert body["enforced"] is False


def test_file_risk_engine_detects_disguised_high_entropy_executable() -> None:
    with client() as api:
        response = api.post(
            "/api/v1/malware/evaluate",
            json={
                "filename": "invoice.pdf.exe",
                "size_bytes": 500000,
                "entropy": 7.9,
                "known_signature_match": False,
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["classification"] == "high-risk"
        assert body["risk_score"] >= 0.75
