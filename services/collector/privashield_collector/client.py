from __future__ import annotations

from uuid import UUID

import httpx

from privashield_api.schemas import SecurityEvent


class CollectorClient:
    def __init__(
        self,
        api_url: str,
        *,
        api_token: str | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        base = api_url.rstrip("/")
        self._event_endpoint = f"{base}/api/v1/events/ingest"
        self._heartbeat_endpoint = f"{base}/api/v1/sensors/heartbeat"
        headers = {"Authorization": f"Bearer {api_token}"} if api_token else None
        self._client = httpx.Client(timeout=timeout_seconds, headers=headers)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> CollectorClient:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def send(self, event: SecurityEvent) -> None:
        response = self._client.post(
            self._event_endpoint,
            json=event.model_dump(mode="json"),
        )
        response.raise_for_status()

    def heartbeat(
        self,
        *,
        sensor_id: UUID,
        name: str,
        sensor_type: str,
        hostname: str,
    ) -> None:
        response = self._client.post(
            self._heartbeat_endpoint,
            json={
                "sensor_id": str(sensor_id),
                "name": name,
                "sensor_type": sensor_type,
                "hostname": hostname,
                "capabilities": ["json-normalization", "event-forwarding"],
            },
        )
        response.raise_for_status()
