from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from ..audit import AuditLedger
from ..auth_models import PrincipalContext
from ..dependencies import get_audit_ledger, get_current_principal, get_policy_service
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
PrincipalDependency = Annotated[PrincipalContext, Depends(get_current_principal)]


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


def _human_actor(principal: PrincipalContext, fallback: str) -> str:
    return principal.audit_actor if principal.credential_verified else fallback


@router.get("/capabilities", response_model=PolicyCapabilities)
async def capabilities(service: PolicyDependency) -> PolicyCapabilities:
    return service.capabilities()


@router.post("/revisions", response_model=PolicyRevision, status_code=status.HTTP_201_CREATED)
async def register_revision(
    request: PolicyRegisterRequest,
    service: PolicyDependency,
    audit: AuditDependency,
    principal: PrincipalDependency,
) -> PolicyRevision:
    actor = _human_actor(principal, request.created_by)
    try:
        revision = await service.register(
            request.envelope,
            created_by=actor,
            identity_verified=principal.credential_verified,
        )
    except Exception as exc:
        _raise_policy_error(exc)
        raise
    await audit.append(
        actor=actor,
        action="policy.revision.registered",
        resource_type="policy_revision",
        resource_id=f"{revision.policy_id}:{revision.version}",
        payload={
            "policy_id": str(revision.policy_id),
            "version": revision.version,
            "content_digest": revision.content_digest,
            "key_id": revision.key_id,
            "status": revision.status.value,
            "identity_verified": principal.credential_verified,
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
    principal: PrincipalDependency,
) -> PolicyRevision:
    actor = _human_actor(principal, request.approved_by)
    try:
        revision = await service.approve(
            policy_id,
            version,
            approved_by=actor,
            identity_verified=principal.credential_verified,
        )
    except Exception as exc:
        _raise_policy_error(exc)
        raise
    await audit.append(
        actor=actor,
        action="policy.revision.approved",
        resource_type="policy_revision",
        resource_id=f"{policy_id}:{version}",
        payload={
            "content_digest": revision.content_digest,
            "signature_valid": revision.signature_valid,
            "status": revision.status.value,
            "identity_verified": principal.credential_verified,
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
    principal: PrincipalDependency,
) -> PolicyRevision:
    actor = _human_actor(principal, request.activated_by)
    try:
        revision = await service.activate(
            policy_id,
            version,
            activated_by=actor,
            identity_verified=principal.credential_verified,
        )
    except Exception as exc:
        _raise_policy_error(exc)
        raise
    await audit.append(
        actor=actor,
        action="policy.revision.activated",
        resource_type="policy_revision",
        resource_id=f"{policy_id}:{version}",
        payload={
            "content_digest": revision.content_digest,
            "status": revision.status.value,
            "identity_verified": principal.credential_verified,
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
    principal: PrincipalDependency,
) -> PolicyRevision:
    actor = _human_actor(principal, request.actor)
    try:
        revision = await service.rollback(
            policy_id,
            request.target_version,
            actor=actor,
            identity_verified=principal.credential_verified,
        )
    except Exception as exc:
        _raise_policy_error(exc)
        raise
    await audit.append(
        actor=actor,
        action="policy.revision.rolled_back",
        resource_type="policy_revision",
        resource_id=f"{policy_id}:{request.target_version}",
        payload={
            "content_digest": revision.content_digest,
            "status": revision.status.value,
            "identity_verified": principal.credential_verified,
            "activation_effect": "simulation-governance-only",
            "enforced": False,
        },
    )
    return revision
