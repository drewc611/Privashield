from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ..audit import AuditLedger
from ..auth_models import PrincipalContext
from ..config import Settings
from ..dependencies import (
    get_adaptive_detector,
    get_app_settings,
    get_audit_ledger,
    get_current_principal,
    get_event_repository,
    get_feedback_repository,
)
from ..feedback_models import (
    AnalystFeedback,
    FeedbackCreate,
    FeedbackLabel,
    FeedbackSummary,
    FeedbackTargetType,
)
from ..feedback_repository import FeedbackRepository
from ..learning.canary import learning_blocked_reason
from ..learning.engine import AdaptiveDetector
from ..repository import EventRepository

router = APIRouter(prefix="/feedback", tags=["feedback"])
FeedbackRepositoryDependency = Annotated[FeedbackRepository, Depends(get_feedback_repository)]
EventRepositoryDependency = Annotated[EventRepository, Depends(get_event_repository)]
AuditDependency = Annotated[AuditLedger, Depends(get_audit_ledger)]
PrincipalDependency = Annotated[PrincipalContext, Depends(get_current_principal)]
DetectorDependency = Annotated[AdaptiveDetector, Depends(get_adaptive_detector)]
SettingsDependency = Annotated[Settings, Depends(get_app_settings)]


@router.post("", response_model=AnalystFeedback, status_code=status.HTTP_201_CREATED)
async def create_feedback(
    request: FeedbackCreate,
    feedback_repository: FeedbackRepositoryDependency,
    event_repository: EventRepositoryDependency,
    audit: AuditDependency,
    principal: PrincipalDependency,
    detector: DetectorDependency,
    settings: SettingsDependency,
) -> AnalystFeedback:
    event = None
    if request.target_type is FeedbackTargetType.EVENT:
        event = await event_repository.get(request.target_id)
        if event is None:
            raise HTTPException(status_code=404, detail="target event not found")

    feedback = AnalystFeedback(
        **request.model_dump(),
        identity_verified=principal.credential_verified,
    )
    created = await feedback_repository.add(feedback)
    actor = principal.audit_actor if principal.credential_verified else "analyst-unverified"
    await audit.append(
        actor=actor,
        action="feedback.created",
        resource_type=f"{created.target_type.value}_feedback",
        resource_id=str(created.id),
        payload={
            **created.model_dump(mode="json"),
            "principal_role": principal.role.value,
        },
    )

    # This is what makes feedback a control loop rather than a record. The guard
    # decides whether it trains, and its refusals are recorded too: an analyst
    # whose feedback was capped, or a window that looked like a label flood, is
    # exactly what someone reviewing the model's history needs to see.
    blocked = learning_blocked_reason(
        detector,
        learning_enabled=settings.adaptive_learning_enabled,
        auth_mode=settings.auth_mode,
    )
    if blocked is None and event is not None:
        outcome = detector.learn(event, created, source=actor)
        await audit.append(
            actor=actor,
            action="learning.update.applied" if outcome.applied else "learning.update.refused",
            resource_type="adaptive_detector",
            resource_id=str(created.target_id),
            payload={
                **outcome.to_dict(),
                "feedback_id": str(created.id),
                "model_updates": detector.model.updates,
                "learning_frozen": detector.guard.frozen,
            },
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
