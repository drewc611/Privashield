from __future__ import annotations

from typing import Protocol

import nats
from nats.aio.client import Client as NATS
from nats.js.client import JetStreamContext
from nats.js.errors import NotFoundError

from .schemas import SecurityEvent


class EventBus(Protocol):
    @property
    def status(self) -> str: ...

    async def publish_event(self, event: SecurityEvent) -> None: ...

    async def close(self) -> None: ...


class NullEventBus:
    @property
    def status(self) -> str:
        return "disabled"

    async def publish_event(self, event: SecurityEvent) -> None:
        return None

    async def close(self) -> None:
        return None


class NatsEventBus:
    def __init__(self, url: str, stream_name: str) -> None:
        self._url = url
        self._stream_name = stream_name
        self._client: NATS | None = None
        self._jetstream: JetStreamContext | None = None
        self._status = "disconnected"

    @property
    def status(self) -> str:
        return self._status

    async def connect(self) -> None:
        self._client = await nats.connect(self._url, connect_timeout=3)
        self._jetstream = self._client.jetstream()
        try:
            await self._jetstream.stream_info(self._stream_name)
        except NotFoundError:
            await self._jetstream.add_stream(
                name=self._stream_name,
                subjects=["privashield.events.>"],
            )
        self._status = "connected"

    async def publish_event(self, event: SecurityEvent) -> None:
        if self._jetstream is None:
            return
        subject = f"privashield.events.{event.source.value}.{event.event_type}"
        try:
            await self._jetstream.publish(subject, event.model_dump_json().encode())
            self._status = "connected"
        except Exception:
            self._status = "degraded"

    async def close(self) -> None:
        if self._client is not None:
            await self._client.drain()
        self._status = "closed"
