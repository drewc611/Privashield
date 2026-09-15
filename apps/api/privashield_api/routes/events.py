from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ..dependencies import get_event_repository
from ..repository import EventRepository
from ..schemas import EventSource, EventStats, SecurityEvent, Severity

router = APIRouter(prefix="/events", tags=["events"])
RepositoryDependency = Annotated[EventRepository, Depends(get_event_repository)]


@router.post("/ingest", response_model=SecurityEvent, status_code=status.HTTP_201_CREATED)
async def ingest_event(event: SecurityEvent, repository: RepositoryDependency) -> SecurityEvent:
    existing = await repository.get(event.id)
    if existing is not None:
        raise HTTPException(status_code=409, detail="event id already exists")
    return await repository.add(event)


@router.get("/stats", response_model=EventStats)
async def event_stats(repository: RepositoryDependency) -> EventStats:
    return await repository.stats()


@router.get("", response_model=list[SecurityEvent])
async def list_events(
    repository: RepositoryDependency,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    severity: Severity | None = None,
    source: EventSource | None = None,
) -> list[SecurityEvent]:
    return await repository.list(
        limit=limit,
        offset=offset,
        severity=severity,
        source=source,
    )


@router.get("/{event_id}", response_model=SecurityEvent)
async def get_event(event_id: UUID, repository: RepositoryDependency) -> SecurityEvent:
    event = await repository.get(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="event not found")
    return event
