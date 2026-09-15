from typing import Annotated

from fastapi import APIRouter, Depends

from ..audit import AuditLedger
from ..dependencies import get_audit_ledger
from ..ransomware import assess_ransomware
from ..schemas import RansomwareAssessment, RansomwareObservation

router = APIRouter(prefix="/ransomware", tags=["ransomware"])
AuditDependency = Annotated[AuditLedger, Depends(get_audit_ledger)]


@router.post("/evaluate", response_model=RansomwareAssessment)
async def evaluate(
    observation: RansomwareObservation,
    audit: AuditDependency,
) -> RansomwareAssessment:
    result = assess_ransomware(observation)
    await audit.append(
        actor="ransomware-engine",
        action="ransomware.behavior.evaluated",
        resource_type="filesystem_window",
        resource_id="local",
        payload=result.model_dump(mode="json"),
    )
    return result
