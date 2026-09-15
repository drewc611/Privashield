from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ..audit import AuditLedger
from ..bus import EventBus
from ..dependencies import (
    get_audit_ledger,
    get_event_bus,
    get_event_hub,
    get_event_repository,
)
from ..realtime import EventHub
from ..repository import EventRepository
from ..schemas import EventSource, EventStats, SecurityEvent, Severity

router = APIRouter(prefix="/events", tags=["events"])
RepositoryDependency = Annotated[EventRepository, Depends(get_event_repository)]
HubDependency = Annotated[EventHub, Depends(get_event_hub)]
BusDependency = Annotated[EventBus, Depends(get_event_bus)]
AuditDependency = Annotated[AuditLedger, Depends(get_audit_ledger)]


@router.post("/ingest", response_model=SecurityEvent, status_code=status.HTTP_201_CREATED)
async def ingest_event(
    event: SecurityEvent,
    repository: RepositoryDependency,
    hub: HubDependency,
    bus: BusDependency,
    audit: AuditDependency,
) -> SecurityEvent:
    existing = await repository.get(event.id)
    if existing is not None:
        raise HTTPException(status_code=409, detail="event id already exists")
    created = await repository.add(event)
    await bus.publish_event(created)
    await hub.broadcast({"type": "security.event", "data": created.model_dump(mode="json")})
    await audit.append(
        actor="sensor",
        action="event.ingested",
        resource_type="security_event",
        resource_id=str(created.id),
        payload=created.model_dump(mode="json"),
    )
    return created


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
