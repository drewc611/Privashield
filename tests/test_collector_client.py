from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest

from privashield_api.schemas import EventSource, SecurityEvent, Severity
from privashield_collector.client import CollectorClient

SENSOR_ID = UUID("11111111-2222-3333-4444-555555555555")


def build_event() -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime(2026, 9, 15, 14, 0, tzinfo=UTC),
        source=EventSource.SURICATA,
        event_type="alert",
        severity=Severity.HIGH,
        sensor_id=SENSOR_ID,
        summary="Suspicious outbound TLS pattern",
    )


def mock_client(
    client: CollectorClient,
    handler: httpx.MockTransport | None = None,
    *,
    requests: list[httpx.Request] | None = None,
    status_code: int = 201,
) -> None:
    """Swap the collector's HTTP client for one backed by a mock transport."""

    def respond(request: httpx.Request) -> httpx.Response:
        if requests is not None:
            requests.append(request)
        return httpx.Response(status_code, json={"ok": True})

    existing_headers = client._client.headers
    client._client.close()
    client._client = httpx.Client(
        transport=handler or httpx.MockTransport(respond),
        headers=existing_headers,
    )


def test_endpoints_are_built_from_the_api_url() -> None:
    with CollectorClient("http://api.internal:8000") as client:
        assert client._event_endpoint == "http://api.internal:8000/api/v1/events/ingest"
        assert client._heartbeat_endpoint == "http://api.internal:8000/api/v1/sensors/heartbeat"


def test_trailing_slashes_do_not_produce_double_slashes() -> None:
    with CollectorClient("http://api.internal:8000///") as client:
        assert client._event_endpoint == "http://api.internal:8000/api/v1/events/ingest"


def test_api_token_is_sent_as_a_bearer_header() -> None:
    requests: list[httpx.Request] = []
    with CollectorClient("http://api.internal", api_token="secret-token") as client:
        mock_client(client, requests=requests)
        client.send(build_event())

    assert requests[0].headers["authorization"] == "Bearer secret-token"


def test_no_authorization_header_without_a_token() -> None:
    requests: list[httpx.Request] = []
    with CollectorClient("http://api.internal") as client:
        mock_client(client, requests=requests)
        client.send(build_event())

    assert "authorization" not in requests[0].headers


def test_send_posts_the_json_serialized_event() -> None:
    requests: list[httpx.Request] = []
    with CollectorClient("http://api.internal") as client:
        mock_client(client, requests=requests)
        client.send(build_event())

    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == "http://api.internal/api/v1/events/ingest"

    body: dict[str, Any] = json.loads(request.content)
    assert body["source"] == "suricata"
    assert body["severity"] == "high"
    assert body["sensor_id"] == str(SENSOR_ID)
    # mode="json" must serialize datetimes to strings, not leave them as objects.
    assert isinstance(body["timestamp"], str)


def test_heartbeat_posts_sensor_registration_details() -> None:
    requests: list[httpx.Request] = []
    with CollectorClient("http://api.internal") as client:
        mock_client(client, requests=requests)
        client.heartbeat(
            sensor_id=SENSOR_ID,
            name="suricata-edge-01",
            sensor_type="suricata",
            hostname="edge-01",
        )

    body: dict[str, Any] = json.loads(requests[0].content)
    assert str(requests[0].url) == "http://api.internal/api/v1/sensors/heartbeat"
    assert body["sensor_id"] == str(SENSOR_ID)
    assert body["name"] == "suricata-edge-01"
    assert body["sensor_type"] == "suricata"
    assert body["hostname"] == "edge-01"
    assert body["capabilities"] == ["json-normalization", "event-forwarding"]


@pytest.mark.parametrize("status_code", [400, 401, 422, 500])
def test_send_raises_on_error_responses(status_code: int) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json={"detail": "nope"})

    with CollectorClient("http://api.internal") as client:
        mock_client(client, handler=httpx.MockTransport(respond))
        with pytest.raises(httpx.HTTPStatusError):
            client.send(build_event())


def test_heartbeat_raises_on_error_responses() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"detail": "unavailable"})

    with CollectorClient("http://api.internal") as client:
        mock_client(client, handler=httpx.MockTransport(respond))
        with pytest.raises(httpx.HTTPStatusError):
            client.heartbeat(
                sensor_id=uuid4(),
                name="zeek-01",
                sensor_type="zeek",
                hostname="host-01",
            )


def test_context_manager_closes_the_underlying_client() -> None:
    client = CollectorClient("http://api.internal")
    with client:
        pass
    assert client._client.is_closed
