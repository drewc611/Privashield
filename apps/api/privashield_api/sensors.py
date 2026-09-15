from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from .schemas import SensorHeartbeat, SensorStatus


class SensorRegistry:
    def __init__(self, ttl_seconds: int = 60) -> None:
        self._ttl = timedelta(seconds=ttl_seconds)
        self._sensors: dict[UUID, tuple[SensorHeartbeat, datetime]] = {}

    def heartbeat(self, heartbeat: SensorHeartbeat) -> SensorStatus:
        now = datetime.now(UTC)
        self._sensors[heartbeat.sensor_id] = (heartbeat, now)
        return self._to_status(heartbeat, now, now)

    def list(self) -> list[SensorStatus]:
        now = datetime.now(UTC)
        return [
            self._to_status(heartbeat, last_seen, now)
            for heartbeat, last_seen in self._sensors.values()
        ]

    def _to_status(
        self,
        heartbeat: SensorHeartbeat,
        last_seen: datetime,
        now: datetime,
    ) -> SensorStatus:
        return SensorStatus(
            sensor_id=heartbeat.sensor_id,
            name=heartbeat.name,
            sensor_type=heartbeat.sensor_type,
            hostname=heartbeat.hostname,
            interface=heartbeat.interface,
            version=heartbeat.version,
            capabilities=heartbeat.capabilities,
            last_seen=last_seen,
            active=(now - last_seen) <= self._ttl,
        )
