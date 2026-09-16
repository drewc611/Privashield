from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from ..audit import AuditLedger
from ..auth import AuthService, PrincipalConflictError, PrincipalNotFoundError
from ..auth_models import (
    AuthCapabilities,
    PrincipalContext,
    PrincipalCreate,
    PrincipalDisableRequest,
    PrincipalPublic,
    PrincipalRotateRequest,
    PrincipalTokenIssued,
)
from ..dependencies import get_audit_ledger, get_auth_service, get_current_principal

router = APIRouter(tags=["auth"])
AuthDependency = Annotated[AuthService, Depends(get_auth_service)]
PrincipalDependency = Annotated[PrincipalContext, Depends(get_current_principal)]
AuditDependency = Annotated[AuditLedger, Depends(get_audit_ledger)]


def _raise_principal_error(exc: Exception) -> None:
    if isinstance(exc, PrincipalNotFoundError):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if isinstance(exc, PrincipalConflictError):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    raise exc


@router.get("/auth/capabilities", response_model=AuthCapabilities)
async def auth_capabilities(service: AuthDependency) -> AuthCapabilities:
    return service.capabilities()


@router.get("/auth/me", response_model=PrincipalContext)
async def auth_me(principal: PrincipalDependency) -> PrincipalContext:
    return principal


@router.get("/principals", response_model=list[PrincipalPublic])
async def list_principals(service: AuthDependency) -> list[PrincipalPublic]:
    return await service.list_principals()


@router.post(
    "/principals",
    response_model=PrincipalTokenIssued,
    status_code=status.HTTP_201_CREATED,
)
async def create_principal(
    request: PrincipalCreate,
    service: AuthDependency,
    principal: PrincipalDependency,
    audit: AuditDependency,
) -> PrincipalTokenIssued:
    try:
        issued = await service.create_principal(request, created_by=principal.audit_actor)
    except Exception as exc:
        _raise_principal_error(exc)
        raise
    await audit.append(
        actor=principal.audit_actor,
        action="auth.principal.created",
        resource_type="local_principal",
        resource_id=str(issued.principal.id),
        payload={
            "name": issued.principal.name,
            "role": issued.principal.role.value,
            "token_prefix": issued.principal.token_prefix,
            "credential_verified": principal.credential_verified,
        },
    )
    return issued


@router.post("/principals/{principal_id}/rotate", response_model=PrincipalTokenIssued)
async def rotate_principal(
    principal_id: UUID,
    request: PrincipalRotateRequest,
    service: AuthDependency,
    principal: PrincipalDependency,
    audit: AuditDependency,
) -> PrincipalTokenIssued:
    try:
        issued = await service.rotate_principal(principal_id)
    except Exception as exc:
        _raise_principal_error(exc)
        raise
    await audit.append(
        actor=principal.audit_actor,
        action="auth.principal.token_rotated",
        resource_type="local_principal",
        resource_id=str(principal_id),
        payload={
            "name": issued.principal.name,
            "role": issued.principal.role.value,
            "token_prefix": issued.principal.token_prefix,
            "reason": request.reason,
            "credential_verified": principal.credential_verified,
        },
    )
    return issued


@router.post("/principals/{principal_id}/disable", response_model=PrincipalPublic)
async def disable_principal(
    principal_id: UUID,
    request: PrincipalDisableRequest,
    service: AuthDependency,
    principal: PrincipalDependency,
    audit: AuditDependency,
) -> PrincipalPublic:
    try:
        disabled = await service.disable_principal(
            principal_id,
            disabled_by=principal.audit_actor,
            requester_id=principal.principal_id,
        )
    except Exception as exc:
        _raise_principal_error(exc)
        raise
    await audit.append(
        actor=principal.audit_actor,
        action="auth.principal.disabled",
        resource_type="local_principal",
        resource_id=str(principal_id),
        payload={
            "name": disabled.name,
            "role": disabled.role.value,
            "reason": request.reason,
            "credential_verified": principal.credential_verified,
        },
    )
    return disabled
