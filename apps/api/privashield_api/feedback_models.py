from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class FeedbackTargetType(StrEnum):
    EVENT = "event"
    INCIDENT = "incident"


class FeedbackLabel(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    NEEDS_REVIEW = "needs_review"


class FeedbackCreate(BaseModel):
    target_type: FeedbackTargetType
    target_id: UUID
    label: FeedbackLabel
    detector: str | None = Field(default=None, max_length=128)
    note: str | None = Field(default=None, max_length=2000)
    tags: list[str] = Field(default_factory=list, max_length=20)


class AnalystFeedback(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target_type: FeedbackTargetType
    target_id: UUID
    label: FeedbackLabel
    detector: str | None = None
    note: str | None = None
    tags: list[str] = Field(default_factory=list)
    identity_verified: bool = False
    schema_version: str = "1.0"


class FeedbackSummary(BaseModel):
    total: int
    by_label: dict[FeedbackLabel, int]
    by_target_type: dict[FeedbackTargetType, int]
