from typing import Annotated

from fastapi import APIRouter, Depends

from ..audit import AuditLedger
from ..dependencies import get_audit_ledger, get_sensor_registry
from ..schemas import SensorHeartbeat, SensorStatus
from ..sensors import SensorRegistry

router = APIRouter(prefix="/sensors", tags=["sensors"])
RegistryDependency = Annotated[SensorRegistry, Depends(get_sensor_registry)]
AuditDependency = Annotated[AuditLedger, Depends(get_audit_ledger)]


@router.post("/heartbeat", response_model=SensorStatus)
async def heartbeat(
    payload: SensorHeartbeat,
    registry: RegistryDependency,
    audit: AuditDependency,
) -> SensorStatus:
    status = registry.heartbeat(payload)
    await audit.append(
        actor="sensor",
        action="sensor.heartbeat",
        resource_type="sensor",
        resource_id=str(payload.sensor_id),
        payload=payload.model_dump(mode="json"),
    )
    return status


@router.get("", response_model=list[SensorStatus])
async def sensors(registry: RegistryDependency) -> list[SensorStatus]:
    return registry.list()
