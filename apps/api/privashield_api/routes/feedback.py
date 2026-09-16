from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ..audit import AuditLedger
from ..dependencies import get_audit_ledger, get_event_repository, get_feedback_repository
from ..feedback_models import (
    AnalystFeedback,
    FeedbackCreate,
    FeedbackLabel,
    FeedbackSummary,
    FeedbackTargetType,
)
from ..feedback_repository import FeedbackRepository
from ..repository import EventRepository

router = APIRouter(prefix="/feedback", tags=["feedback"])
FeedbackRepositoryDependency = Annotated[FeedbackRepository, Depends(get_feedback_repository)]
EventRepositoryDependency = Annotated[EventRepository, Depends(get_event_repository)]
AuditDependency = Annotated[AuditLedger, Depends(get_audit_ledger)]


@router.post("", response_model=AnalystFeedback, status_code=status.HTTP_201_CREATED)
async def create_feedback(
    request: FeedbackCreate,
    feedback_repository: FeedbackRepositoryDependency,
    event_repository: EventRepositoryDependency,
    audit: AuditDependency,
) -> AnalystFeedback:
    if request.target_type is FeedbackTargetType.EVENT:
        event = await event_repository.get(request.target_id)
        if event is None:
            raise HTTPException(status_code=404, detail="target event not found")

    feedback = AnalystFeedback(**request.model_dump())
    created = await feedback_repository.add(feedback)
    await audit.append(
        actor="analyst-unverified",
        action="feedback.created",
        resource_type=f"{created.target_type.value}_feedback",
        resource_id=str(created.id),
        payload=created.model_dump(mode="json"),
    )
    return created


@router.get("/stats", response_model=FeedbackSummary)
async def feedback_stats(
    feedback_repository: FeedbackRepositoryDependency,
) -> FeedbackSummary:
    return await feedback_repository.stats()


@router.get("", response_model=list[AnalystFeedback])
async def list_feedback(
    feedback_repository: FeedbackRepositoryDependency,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    target_type: FeedbackTargetType | None = None,
    target_id: UUID | None = None,
    label: FeedbackLabel | None = None,
) -> list[AnalystFeedback]:
    return await feedback_repository.list(
        limit=limit,
        target_type=target_type,
        target_id=target_id,
        label=label,
    )
