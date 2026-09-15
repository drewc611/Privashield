from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from ..audit import AuditLedger
from ..dependencies import get_audit_ledger, get_response_store
from ..response import ResponseStore
from ..response_models import (
    ApprovalRequest,
    ResponseAction,
    ResponseActionCreate,
    ResponseCapabilities,
)

router = APIRouter(prefix="/response", tags=["response"])
StoreDependency = Annotated[ResponseStore, Depends(get_response_store)]
AuditDependency = Annotated[AuditLedger, Depends(get_audit_ledger)]


@router.get("/capabilities", response_model=ResponseCapabilities)
async def capabilities(store: StoreDependency) -> ResponseCapabilities:
    return store.capabilities()


@router.post("/actions", response_model=ResponseAction, status_code=status.HTTP_201_CREATED)
async def create_action(
    request: ResponseActionCreate,
    store: StoreDependency,
    audit: AuditDependency,
) -> ResponseAction:
    action = store.create(request)
    await audit.append(
        actor="operator",
        action="response.action.requested",
        resource_type="response_action",
        resource_id=str(action.id),
        payload=action.model_dump(mode="json"),
    )
    return action


@router.get("/actions", response_model=list[ResponseAction])
async def list_actions(store: StoreDependency) -> list[ResponseAction]:
    return store.list()


@router.post("/actions/{action_id}/approve", response_model=ResponseAction)
async def approve_action(
    action_id: UUID,
    request: ApprovalRequest,
    store: StoreDependency,
    audit: AuditDependency,
) -> ResponseAction:
    action = store.approve(action_id, request.approved_by)
    if action is None:
        raise HTTPException(status_code=409, detail="action is not pending or does not exist")
    await audit.append(
        actor=request.approved_by,
        action="response.action.approved",
        resource_type="response_action",
        resource_id=str(action.id),
        payload=action.model_dump(mode="json"),
    )
    return action


@router.post("/actions/{action_id}/simulate", response_model=ResponseAction)
async def simulate_action(
    action_id: UUID,
    store: StoreDependency,
    audit: AuditDependency,
) -> ResponseAction:
    action = store.simulate(action_id)
    if action is None:
        raise HTTPException(status_code=409, detail="action must be explicitly approved first")
    await audit.append(
        actor="response-engine",
        action="response.action.simulated",
        resource_type="response_action",
        resource_id=str(action.id),
        payload=action.model_dump(mode="json"),
    )
    return action


@router.post("/actions/{action_id}/cancel", response_model=ResponseAction)
async def cancel_action(
    action_id: UUID,
    store: StoreDependency,
    audit: AuditDependency,
) -> ResponseAction:
    action = store.cancel(action_id)
    if action is None:
        raise HTTPException(status_code=409, detail="action cannot be cancelled")
    await audit.append(
        actor="operator",
        action="response.action.cancelled",
        resource_type="response_action",
        resource_id=str(action.id),
        payload=action.model_dump(mode="json"),
    )
    return action
