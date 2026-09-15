from __future__ import annotations

import httpx

from privashield_api.schemas import SecurityEvent


class CollectorClient:
    def __init__(self, api_url: str, *, timeout_seconds: float = 10.0) -> None:
        self._endpoint = f"{api_url.rstrip('/')}/api/v1/events/ingest"
        self._client = httpx.Client(timeout=timeout_seconds)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> CollectorClient:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def send(self, event: SecurityEvent) -> None:
        response = self._client.post(
            self._endpoint,
            json=event.model_dump(mode="json"),
        )
        response.raise_for_status()
