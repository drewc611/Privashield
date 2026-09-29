import json

from fastapi.testclient import TestClient

from privashield_api.config import Settings
from privashield_api.limits import MAX_METADATA_BYTES
from privashield_api.main import create_app
from tests.test_api import sample_event


def build_client(max_bytes: int = 1_048_576) -> TestClient:
    settings = Settings(
        _env_file=None,
        database_enabled=False,
        nats_enabled=False,
        ollama_enabled=False,
        audit_path=None,
        environment="development",
        auth_mode="disabled",
        max_request_body_bytes=max_bytes,
    )
    return TestClient(create_app(settings))


def test_request_within_limit_is_accepted() -> None:
    with build_client() as client:
        response = client.post("/api/v1/events/ingest", json=sample_event())
        assert response.status_code == 201


def test_declared_oversized_body_is_rejected_with_413() -> None:
    with build_client(max_bytes=512) as client:
        response = client.post(
            "/api/v1/events/ingest",
            content=b"x" * 2048,
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413
        assert "512" in response.json()["detail"]


def test_streamed_oversized_body_is_rejected_with_413() -> None:
    def chunks():
        for _ in range(8):
            yield b"x" * 256

    with build_client(max_bytes=512) as client:
        response = client.post(
            "/api/v1/events/ingest",
            content=chunks(),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413


def test_oversized_metadata_is_rejected_with_422() -> None:
    event = sample_event()
    event["metadata"] = {"blob": "a" * (MAX_METADATA_BYTES + 1)}
    with build_client() as client:
        response = client.post("/api/v1/events/ingest", json=event)
        assert response.status_code == 422
        assert "metadata" in json.dumps(response.json())


def test_metadata_at_the_limit_is_accepted() -> None:
    event = sample_event()
    overhead = len(json.dumps({"blob": ""}))
    event["metadata"] = {"blob": "a" * (MAX_METADATA_BYTES - overhead)}
    with build_client() as client:
        response = client.post("/api/v1/events/ingest", json=event)
        assert response.status_code == 201
