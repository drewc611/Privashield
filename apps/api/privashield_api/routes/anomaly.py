from typing import Annotated

from fastapi import APIRouter, Depends

from ..anomaly import AnomalyEngine
from ..audit import AuditLedger
from ..dependencies import get_anomaly_engine, get_audit_ledger
from ..schemas import AnomalyAssessment, IdentityObservation

router = APIRouter(prefix="/anomaly", tags=["anomaly"])
EngineDependency = Annotated[AnomalyEngine, Depends(get_anomaly_engine)]
AuditDependency = Annotated[AuditLedger, Depends(get_audit_ledger)]


@router.post("/evaluate", response_model=AnomalyAssessment)
async def evaluate(
    observation: IdentityObservation,
    engine: EngineDependency,
    audit: AuditDependency,
) -> AnomalyAssessment:
    result = engine.evaluate(observation)
    await audit.append(
        actor="anomaly-engine",
        action="identity.anomaly.evaluated",
        resource_type="user",
        resource_id=observation.user_id,
        payload=result.model_dump(mode="json"),
    )
    return result
