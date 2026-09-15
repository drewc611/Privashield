from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ..audit import AuditLedger
from ..dependencies import get_audit_ledger
from ..schemas import AuditEntry, AuditVerification

router = APIRouter(prefix="/audit", tags=["audit"])
AuditDependency = Annotated[AuditLedger, Depends(get_audit_ledger)]


@router.get("", response_model=list[AuditEntry])
async def audit_entries(
    ledger: AuditDependency,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> list[AuditEntry]:
    return ledger.list(limit)


@router.get("/verify", response_model=AuditVerification)
async def verify_audit(ledger: AuditDependency) -> AuditVerification:
    return ledger.verify()
