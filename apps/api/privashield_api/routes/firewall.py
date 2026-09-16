from typing import Annotated

from fastapi import APIRouter, Depends

from ..audit import AuditLedger
from ..auth_models import PrincipalContext
from ..dependencies import get_audit_ledger, get_current_principal, get_firewall_controller
from ..firewall import FirewallController
from ..schemas import FirewallConfig, FirewallEvaluation, FirewallEvaluationRequest

router = APIRouter(prefix="/firewall", tags=["firewall"])
ControllerDependency = Annotated[FirewallController, Depends(get_firewall_controller)]
AuditDependency = Annotated[AuditLedger, Depends(get_audit_ledger)]
PrincipalDependency = Annotated[PrincipalContext, Depends(get_current_principal)]


@router.get("/config", response_model=FirewallConfig)
async def firewall_config(controller: ControllerDependency) -> FirewallConfig:
    return controller.config


@router.patch("/config", response_model=FirewallConfig)
async def update_firewall_config(
    config: FirewallConfig,
    controller: ControllerDependency,
    audit: AuditDependency,
    principal: PrincipalDependency,
) -> FirewallConfig:
    updated = controller.update(config)
    actor = principal.audit_actor if principal.credential_verified else "operator"
    await audit.append(
        actor=actor,
        action="firewall.config.updated",
        resource_type="firewall",
        resource_id="local",
        payload={
            **updated.model_dump(mode="json"),
            "identity_verified": principal.credential_verified,
            "principal_role": principal.role.value,
        },
    )
    return updated


@router.post("/evaluate", response_model=FirewallEvaluation)
async def evaluate(
    payload: FirewallEvaluationRequest,
    controller: ControllerDependency,
    audit: AuditDependency,
) -> FirewallEvaluation:
    decision = controller.evaluate(payload)
    await audit.append(
        actor="policy-engine",
        action="firewall.simulated_decision",
        resource_type="firewall_decision",
        resource_id=str(decision.decision_id),
        payload=decision.model_dump(mode="json"),
    )
    return decision
