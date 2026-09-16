from __future__ import annotations

from collections import Counter
from typing import Protocol
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .database import AnalystFeedbackRecord
from .feedback_models import (
    AnalystFeedback,
    FeedbackLabel,
    FeedbackSummary,
    FeedbackTargetType,
)


class FeedbackRepository(Protocol):
    async def add(self, feedback: AnalystFeedback) -> AnalystFeedback: ...

    async def list(
        self,
        *,
        limit: int,
        target_type: FeedbackTargetType | None,
        target_id: UUID | None,
        label: FeedbackLabel | None,
    ) -> list[AnalystFeedback]: ...

    async def stats(self) -> FeedbackSummary: ...


class InMemoryFeedbackRepository:
    def __init__(self) -> None:
        self._items: dict[UUID, AnalystFeedback] = {}

    async def add(self, feedback: AnalystFeedback) -> AnalystFeedback:
        self._items[feedback.id] = feedback.model_copy(deep=True)
        return feedback.model_copy(deep=True)

    async def list(
        self,
        *,
        limit: int,
        target_type: FeedbackTargetType | None,
        target_id: UUID | None,
        label: FeedbackLabel | None,
    ) -> list[AnalystFeedback]:
        items = sorted(
            self._items.values(),
            key=lambda item: item.created_at,
            reverse=True,
        )
        if target_type is not None:
            items = [item for item in items if item.target_type == target_type]
        if target_id is not None:
            items = [item for item in items if item.target_id == target_id]
        if label is not None:
            items = [item for item in items if item.label == label]
        return [item.model_copy(deep=True) for item in items[:limit]]

    async def stats(self) -> FeedbackSummary:
        items = list(self._items.values())
        label_counts = Counter(item.label for item in items)
        target_counts = Counter(item.target_type for item in items)
        return FeedbackSummary(
            total=len(items),
            by_label={label: label_counts[label] for label in FeedbackLabel},
            by_target_type={target: target_counts[target] for target in FeedbackTargetType},
        )


class SqlFeedbackRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def add(self, feedback: AnalystFeedback) -> AnalystFeedback:
        record = AnalystFeedbackRecord.from_feedback(feedback)
        async with self._session_factory() as session:
            session.add(record)
            await session.commit()
        return feedback

    async def list(
        self,
        *,
        limit: int,
        target_type: FeedbackTargetType | None,
        target_id: UUID | None,
        label: FeedbackLabel | None,
    ) -> list[AnalystFeedback]:
        statement = select(AnalystFeedbackRecord).order_by(AnalystFeedbackRecord.created_at.desc())
        if target_type is not None:
            statement = statement.where(AnalystFeedbackRecord.target_type == target_type.value)
        if target_id is not None:
            statement = statement.where(AnalystFeedbackRecord.target_id == target_id)
        if label is not None:
            statement = statement.where(AnalystFeedbackRecord.label == label.value)
        statement = statement.limit(limit)

        async with self._session_factory() as session:
            records = (await session.scalars(statement)).all()
            return [record.to_feedback() for record in records]

    async def stats(self) -> FeedbackSummary:
        async with self._session_factory() as session:
            total = await session.scalar(select(func.count()).select_from(AnalystFeedbackRecord))
            label_rows = (
                await session.execute(
                    select(AnalystFeedbackRecord.label, func.count()).group_by(
                        AnalystFeedbackRecord.label
                    )
                )
            ).all()
            target_rows = (
                await session.execute(
                    select(AnalystFeedbackRecord.target_type, func.count()).group_by(
                        AnalystFeedbackRecord.target_type
                    )
                )
            ).all()

        label_map = {FeedbackLabel(name): count for name, count in label_rows}
        target_map = {FeedbackTargetType(name): count for name, count in target_rows}
        return FeedbackSummary(
            total=total or 0,
            by_label={label: label_map.get(label, 0) for label in FeedbackLabel},
            by_target_type={target: target_map.get(target, 0) for target in FeedbackTargetType},
        )
