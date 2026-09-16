from __future__ import annotations

from typing import Protocol
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .database import PolicyHistoryRecord, PolicyRevisionRecord
from .policy_models import PolicyHistoryEvent, PolicyRevision, PolicyStatus


class PolicyRepository(Protocol):
    async def add_revision(self, revision: PolicyRevision) -> PolicyRevision: ...

    async def get_revision(self, policy_id: UUID, version: int) -> PolicyRevision | None: ...

    async def list_revisions(self, policy_id: UUID) -> list[PolicyRevision]: ...

    async def active_revision(self, policy_id: UUID) -> PolicyRevision | None: ...

    async def save_revisions(self, revisions: list[PolicyRevision]) -> None: ...

    async def append_history(self, events: list[PolicyHistoryEvent]) -> None: ...

    async def list_history(self, policy_id: UUID) -> list[PolicyHistoryEvent]: ...


class InMemoryPolicyRepository:
    def __init__(self) -> None:
        self._revisions: dict[tuple[UUID, int], PolicyRevision] = {}
        self._history: list[PolicyHistoryEvent] = []

    async def add_revision(self, revision: PolicyRevision) -> PolicyRevision:
        key = (revision.policy_id, revision.version)
        if key in self._revisions:
            raise ValueError("policy revision already exists")
        self._revisions[key] = revision.model_copy(deep=True)
        return revision.model_copy(deep=True)

    async def get_revision(self, policy_id: UUID, version: int) -> PolicyRevision | None:
        revision = self._revisions.get((policy_id, version))
        return revision.model_copy(deep=True) if revision else None

    async def list_revisions(self, policy_id: UUID) -> list[PolicyRevision]:
        revisions = [
            revision.model_copy(deep=True)
            for (candidate_id, _), revision in self._revisions.items()
            if candidate_id == policy_id
        ]
        return sorted(revisions, key=lambda item: item.version, reverse=True)

    async def active_revision(self, policy_id: UUID) -> PolicyRevision | None:
        for revision in self._revisions.values():
            if revision.policy_id == policy_id and revision.status is PolicyStatus.ACTIVE:
                return revision.model_copy(deep=True)
        return None

    async def save_revisions(self, revisions: list[PolicyRevision]) -> None:
        for revision in revisions:
            key = (revision.policy_id, revision.version)
            if key not in self._revisions:
                raise ValueError("policy revision does not exist")
        for revision in revisions:
            self._revisions[(revision.policy_id, revision.version)] = revision.model_copy(deep=True)

    async def append_history(self, events: list[PolicyHistoryEvent]) -> None:
        self._history.extend(event.model_copy(deep=True) for event in events)

    async def list_history(self, policy_id: UUID) -> list[PolicyHistoryEvent]:
        events = [
            event.model_copy(deep=True)
            for event in self._history
            if event.policy_id == policy_id
        ]
        return sorted(events, key=lambda item: item.created_at)


class SqlPolicyRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def add_revision(self, revision: PolicyRevision) -> PolicyRevision:
        async with self._session_factory() as session:
            session.add(PolicyRevisionRecord.from_revision(revision))
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                raise ValueError("policy revision already exists") from exc
        return revision.model_copy(deep=True)

    async def get_revision(self, policy_id: UUID, version: int) -> PolicyRevision | None:
        async with self._session_factory() as session:
            record = await session.get(PolicyRevisionRecord, (policy_id, version))
            return record.to_revision() if record else None

    async def list_revisions(self, policy_id: UUID) -> list[PolicyRevision]:
        statement = (
            select(PolicyRevisionRecord)
            .where(PolicyRevisionRecord.policy_id == policy_id)
            .order_by(PolicyRevisionRecord.version.desc())
        )
        async with self._session_factory() as session:
            records = (await session.scalars(statement)).all()
            return [record.to_revision() for record in records]

    async def active_revision(self, policy_id: UUID) -> PolicyRevision | None:
        statement = select(PolicyRevisionRecord).where(
            PolicyRevisionRecord.policy_id == policy_id,
            PolicyRevisionRecord.status == PolicyStatus.ACTIVE.value,
        )
        async with self._session_factory() as session:
            record = await session.scalar(statement)
            return record.to_revision() if record else None

    async def save_revisions(self, revisions: list[PolicyRevision]) -> None:
        async with self._session_factory() as session:
            for revision in revisions:
                record = await session.get(
                    PolicyRevisionRecord,
                    (revision.policy_id, revision.version),
                )
                if record is None:
                    raise ValueError("policy revision does not exist")
                record.apply_revision(revision)
            await session.commit()

    async def append_history(self, events: list[PolicyHistoryEvent]) -> None:
        async with self._session_factory() as session:
            session.add_all(PolicyHistoryRecord.from_event(event) for event in events)
            await session.commit()

    async def list_history(self, policy_id: UUID) -> list[PolicyHistoryEvent]:
        statement = (
            select(PolicyHistoryRecord)
            .where(PolicyHistoryRecord.policy_id == policy_id)
            .order_by(PolicyHistoryRecord.created_at.asc())
        )
        async with self._session_factory() as session:
            records = (await session.scalars(statement)).all()
            return [record.to_event() for record in records]
