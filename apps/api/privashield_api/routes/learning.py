"""Operator surface for the adaptive detector.

Two endpoints, split by what they can do rather than by resource shape. Scoring
is read-only and advisory, so it is available whenever scoring is switched on.
Status exists because the poisoning defenses are only real when someone can see
whether they are armed: a detector learning without a canary corpus looks healthy
from every other angle (ADR-0004).

Training is not an endpoint. Feedback already has one, and giving learning its own
route would be a second way to move the model that does not pass the guard.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from ..config import Settings
from ..dependencies import (
    get_adaptive_detector,
    get_app_settings,
    get_event_repository,
)
from ..learning.canary import learning_blocked_reason
from ..learning.engine import AdaptiveDetector
from ..repository import EventRepository
from ..schemas import (
    AdaptiveAssessmentResponse,
    AdaptiveFeatureContribution,
    AdaptiveStatus,
)

router = APIRouter(prefix="/learning", tags=["learning"])
DetectorDependency = Annotated[AdaptiveDetector, Depends(get_adaptive_detector)]
RepositoryDependency = Annotated[EventRepository, Depends(get_event_repository)]
SettingsDependency = Annotated[Settings, Depends(get_app_settings)]


@router.get("/status", response_model=AdaptiveStatus)
async def learning_status(
    detector: DetectorDependency,
    settings: SettingsDependency,
) -> AdaptiveStatus:
    snapshot = detector.status()
    blocked = learning_blocked_reason(
        detector,
        learning_enabled=settings.adaptive_learning_enabled,
        auth_mode=settings.auth_mode,
    )
    return AdaptiveStatus(
        scoring_enabled=settings.adaptive_scoring_enabled,
        learning_enabled=settings.adaptive_learning_enabled,
        learning_effective=blocked is None,
        learning_blocked_reason=blocked,
        model_kind=str(snapshot["model_kind"]),
        updates=int(snapshot["updates"]),
        learning_frozen=bool(snapshot["learning_frozen"]),
        frozen_reason=snapshot["frozen_reason"],
        canary_enabled=bool(snapshot["canary_enabled"]),
        canary_baseline=float(snapshot["canary_baseline"]),
        canary_interval=int(snapshot["canary_interval"]),
        has_trusted_state=bool(snapshot["has_trusted_state"]),
        state_durable=bool(snapshot["state_durable"]),
        max_source_share=float(snapshot["max_source_share"]),
        max_source_updates=int(snapshot["max_source_updates"]),
        active_sources=int(snapshot["active_sources"]),
        window_sources=dict(snapshot["window_sources"]),
        top_features=list(snapshot["top_features"]),
    )


@router.get("/score/{event_id}", response_model=AdaptiveAssessmentResponse)
async def score_event(
    event_id: UUID,
    detector: DetectorDependency,
    repository: RepositoryDependency,
    settings: SettingsDependency,
) -> AdaptiveAssessmentResponse:
    if not settings.adaptive_scoring_enabled:
        raise HTTPException(status_code=503, detail="adaptive scoring is disabled")
    event = await repository.get(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="event not found")

    assessment = detector.score(event)
    return AdaptiveAssessmentResponse(
        event_id=event_id,
        score=assessment.score,
        confidence=assessment.confidence,
        model_kind=assessment.model_kind,
        model_updates=assessment.model_updates,
        contributions=[
            AdaptiveFeatureContribution(feature=name, contribution=value)
            for name, value in assessment.contributions
        ],
    )
