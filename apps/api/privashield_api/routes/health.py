from fastapi import APIRouter, Request

from .. import __version__
from ..schemas import HealthResponse, SystemStatus

router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", service="privashield-api", version=__version__)


@router.get("/system/status", response_model=SystemStatus)
async def system_status(request: Request) -> SystemStatus:
    settings = request.app.state.settings
    return SystemStatus(
        status="ok",
        environment=settings.environment,
        database="enabled" if settings.database_enabled else "memory",
        event_bus=request.app.state.event_bus.status,
        ai="enabled" if settings.ollama_enabled else "disabled",
        enforcement_mode=request.app.state.firewall_controller.config.mode,
        enforcement_active=False,
    )
