from __future__ import annotations

from collections import Counter
from typing import Protocol
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .database import SecurityEventRecord
from .schemas import EventSource, EventStats, SecurityEvent, Severity


class EventRepository(Protocol):
    async def add(self, event: SecurityEvent) -> SecurityEvent: ...

    async def get(self, event_id: UUID) -> SecurityEvent | None: ...

    async def list(
        self,
        *,
        limit: int,
        offset: int,
        severity: Severity | None,
        source: EventSource | None,
    ) -> list[SecurityEvent]: ...

    async def stats(self) -> EventStats: ...


class InMemoryEventRepository:
    def __init__(self) -> None:
        self._events: dict[UUID, SecurityEvent] = {}

    async def add(self, event: SecurityEvent) -> SecurityEvent:
        self._events[event.id] = event
        return event

    async def get(self, event_id: UUID) -> SecurityEvent | None:
        return self._events.get(event_id)

    async def list(
        self,
        *,
        limit: int,
        offset: int,
        severity: Severity | None,
        source: EventSource | None,
    ) -> list[SecurityEvent]:
        events = sorted(self._events.values(), key=lambda item: item.timestamp, reverse=True)
        if severity is not None:
            events = [event for event in events if event.severity == severity]
        if source is not None:
            events = [event for event in events if event.source == source]
        return events[offset : offset + limit]

    async def stats(self) -> EventStats:
        events = list(self._events.values())
        severity_counts = Counter(event.severity for event in events)
        source_counts = Counter(event.source for event in events)
        return EventStats(
            total=len(events),
            by_severity={severity: severity_counts[severity] for severity in Severity},
            by_source={source: source_counts[source] for source in EventSource},
        )


class SqlEventRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def add(self, event: SecurityEvent) -> SecurityEvent:
        record = SecurityEventRecord.from_event(event)
        async with self._session_factory() as session:
            session.add(record)
            await session.commit()
        return event

    async def get(self, event_id: UUID) -> SecurityEvent | None:
        async with self._session_factory() as session:
            record = await session.get(SecurityEventRecord, event_id)
            return record.to_event() if record else None

    async def list(
        self,
        *,
        limit: int,
        offset: int,
        severity: Severity | None,
        source: EventSource | None,
    ) -> list[SecurityEvent]:
        statement = select(SecurityEventRecord).order_by(SecurityEventRecord.timestamp.desc())
        if severity is not None:
            statement = statement.where(SecurityEventRecord.severity == severity.value)
        if source is not None:
            statement = statement.where(SecurityEventRecord.source == source.value)
        statement = statement.offset(offset).limit(limit)
        async with self._session_factory() as session:
            records = (await session.scalars(statement)).all()
            return [record.to_event() for record in records]

    async def stats(self) -> EventStats:
        async with self._session_factory() as session:
            total = await session.scalar(select(func.count()).select_from(SecurityEventRecord))
            severity_rows = (
                await session.execute(
                    select(SecurityEventRecord.severity, func.count()).group_by(
                        SecurityEventRecord.severity
                    )
                )
            ).all()
            source_rows = (
                await session.execute(
                    select(SecurityEventRecord.source, func.count()).group_by(
                        SecurityEventRecord.source
                    )
                )
            ).all()

        severity_map = {Severity(name): count for name, count in severity_rows}
        source_map = {EventSource(name): count for name, count in source_rows}
        return EventStats(
            total=total or 0,
            by_severity={severity: severity_map.get(severity, 0) for severity in Severity},
            by_source={source: source_map.get(source, 0) for source in EventSource},
        )
