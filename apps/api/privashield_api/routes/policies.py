from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from ..audit import AuditLedger
from ..dependencies import get_audit_ledger, get_policy_service
from ..policy import (
    PolicyConfigurationError,
    PolicyConflictError,
    PolicyNotFoundError,
    PolicyService,
    PolicySignatureError,
)
from ..policy_models import (
    PolicyActivationRequest,
    PolicyApprovalRequest,
    PolicyCapabilities,
    PolicyHistoryEvent,
    PolicyRegisterRequest,
    PolicyRevision,
    PolicyRollbackRequest,
)

router = APIRouter(prefix="/policies", tags=["policies"])
PolicyDependency = Annotated[PolicyService, Depends(get_policy_service)]
AuditDependency = Annotated[AuditLedger, Depends(get_audit_ledger)]


def _raise_policy_error(exc: Exception) -> None:
    if isinstance(exc, PolicyConfigurationError):
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if isinstance(exc, PolicyNotFoundError):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if isinstance(exc, PolicySignatureError):
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if isinstance(exc, PolicyConflictError):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    raise exc


@router.get("/capabilities", response_model=PolicyCapabilities)
async def capabilities(service: PolicyDependency) -> PolicyCapabilities:
    return service.capabilities()


@router.post("/revisions", response_model=PolicyRevision, status_code=status.HTTP_201_CREATED)
async def register_revision(
    request: PolicyRegisterRequest,
    service: PolicyDependency,
    audit: AuditDependency,
) -> PolicyRevision:
    try:
        revision = await service.register(request.envelope, created_by=request.created_by)
    except Exception as exc:
        _raise_policy_error(exc)
        raise
    await audit.append(
        actor=request.created_by,
        action="policy.revision.registered",
        resource_type="policy_revision",
        resource_id=f"{revision.policy_id}:{revision.version}",
        payload={
            "policy_id": str(revision.policy_id),
            "version": revision.version,
            "content_digest": revision.content_digest,
            "key_id": revision.key_id,
            "status": revision.status.value,
            "enforced": False,
        },
    )
    return revision


@router.get("/{policy_id}/revisions", response_model=list[PolicyRevision])
async def list_revisions(
    policy_id: UUID,
    service: PolicyDependency,
) -> list[PolicyRevision]:
    return await service.list_versions(policy_id)


@router.get("/{policy_id}/active", response_model=PolicyRevision | None)
async def active_revision(
    policy_id: UUID,
    service: PolicyDependency,
) -> PolicyRevision | None:
    return await service.active(policy_id)


@router.get("/{policy_id}/history", response_model=list[PolicyHistoryEvent])
async def policy_history(
    policy_id: UUID,
    service: PolicyDependency,
) -> list[PolicyHistoryEvent]:
    return await service.history(policy_id)


@router.get("/{policy_id}/revisions/{version}", response_model=PolicyRevision)
async def get_revision(
    policy_id: UUID,
    version: int,
    service: PolicyDependency,
) -> PolicyRevision:
    try:
        return await service.get(policy_id, version)
    except Exception as exc:
        _raise_policy_error(exc)
        raise


@router.post("/{policy_id}/revisions/{version}/approve", response_model=PolicyRevision)
async def approve_revision(
    policy_id: UUID,
    version: int,
    request: PolicyApprovalRequest,
    service: PolicyDependency,
    audit: AuditDependency,
) -> PolicyRevision:
    try:
        revision = await service.approve(policy_id, version, approved_by=request.approved_by)
    except Exception as exc:
        _raise_policy_error(exc)
        raise
    await audit.append(
        actor=request.approved_by,
        action="policy.revision.approved",
        resource_type="policy_revision",
        resource_id=f"{policy_id}:{version}",
        payload={
            "content_digest": revision.content_digest,
            "signature_valid": revision.signature_valid,
            "status": revision.status.value,
            "identity_verified": False,
            "enforced": False,
        },
    )
    return revision


@router.post("/{policy_id}/revisions/{version}/activate", response_model=PolicyRevision)
async def activate_revision(
    policy_id: UUID,
    version: int,
    request: PolicyActivationRequest,
    service: PolicyDependency,
    audit: AuditDependency,
) -> PolicyRevision:
    try:
        revision = await service.activate(policy_id, version, activated_by=request.activated_by)
    except Exception as exc:
        _raise_policy_error(exc)
        raise
    await audit.append(
        actor=request.activated_by,
        action="policy.revision.activated",
        resource_type="policy_revision",
        resource_id=f"{policy_id}:{version}",
        payload={
            "content_digest": revision.content_digest,
            "status": revision.status.value,
            "activation_effect": "simulation-governance-only",
            "enforced": False,
        },
    )
    return revision


@router.post("/{policy_id}/rollback", response_model=PolicyRevision)
async def rollback_policy(
    policy_id: UUID,
    request: PolicyRollbackRequest,
    service: PolicyDependency,
    audit: AuditDependency,
) -> PolicyRevision:
    try:
        revision = await service.rollback(
            policy_id,
            request.target_version,
            actor=request.actor,
        )
    except Exception as exc:
        _raise_policy_error(exc)
        raise
    await audit.append(
        actor=request.actor,
        action="policy.revision.rolled_back",
        resource_type="policy_revision",
        resource_id=f"{policy_id}:{request.target_version}",
        payload={
            "content_digest": revision.content_digest,
            "status": revision.status.value,
            "activation_effect": "simulation-governance-only",
            "enforced": False,
        },
    )
    return revision
