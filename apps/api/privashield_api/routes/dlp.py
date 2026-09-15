from typing import Annotated

from fastapi import APIRouter, Depends

from ..audit import AuditLedger
from ..dependencies import get_audit_ledger
from ..dlp import classify_text
from ..schemas import DLPClassification, DLPClassifyRequest

router = APIRouter(prefix="/dlp", tags=["dlp"])
AuditDependency = Annotated[AuditLedger, Depends(get_audit_ledger)]


@router.post("/classify", response_model=DLPClassification)
async def classify(request: DLPClassifyRequest, audit: AuditDependency) -> DLPClassification:
    result = classify_text(request.text, request.permission_tier)
    await audit.append(
        actor="dlp-engine",
        action="dlp.classification.completed",
        resource_type="text",
        resource_id="inline",
        payload={
            "sensitivity": result.sensitivity,
            "labels": result.labels,
            "match_count": len(result.matches),
            "permission_tier": request.permission_tier,
        },
    )
    return result
