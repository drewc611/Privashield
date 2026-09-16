from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from ..correlation import CorrelationRequest, CorrelationResult, correlate_events
from ..dependencies import get_event_repository
from ..repository import EventRepository

router = APIRouter(prefix="/incidents", tags=["incidents"])
RepositoryDependency = Annotated[EventRepository, Depends(get_event_repository)]


@router.post("/correlate", response_model=CorrelationResult)
async def correlate_selected_events(
    request: CorrelationRequest,
    repository: RepositoryDependency,
) -> CorrelationResult:
    unique_ids = list(dict.fromkeys(request.event_ids))
    if len(unique_ids) < 2:
        raise HTTPException(status_code=422, detail="at least two unique event ids are required")

    events = []
    missing: list[UUID] = []
    for event_id in unique_ids:
        event = await repository.get(event_id)
        if event is None:
            missing.append(event_id)
        else:
            events.append(event)

    if missing:
        raise HTTPException(
            status_code=404,
            detail={"message": "one or more events were not found", "event_ids": [str(item) for item in missing]},
        )

    return correlate_events(events, max_time_gap_seconds=request.max_time_gap_seconds)


@router.get("/candidates", response_model=CorrelationResult)
async def correlation_candidates(
    repository: RepositoryDependency,
    lookback_minutes: Annotated[int, Query(ge=1, le=1440)] = 15,
    limit: Annotated[int, Query(ge=2, le=1000)] = 500,
    max_time_gap_seconds: Annotated[int, Query(ge=1, le=86400)] = 900,
) -> CorrelationResult:
    events = await repository.list(
        limit=limit,
        offset=0,
        severity=None,
        source=None,
    )
    cutoff = datetime.now(UTC) - timedelta(minutes=lookback_minutes)
    recent = [event for event in events if event.timestamp >= cutoff]
    return correlate_events(recent, max_time_gap_seconds=max_time_gap_seconds)
