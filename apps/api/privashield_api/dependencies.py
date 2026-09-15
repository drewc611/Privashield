from fastapi import Request

from .ai import OllamaThreatAnalyzer
from .audit import AuditLedger
from .bus import EventBus
from .firewall import FirewallController
from .realtime import EventHub
from .repository import EventRepository
from .sensors import SensorRegistry


def get_event_repository(request: Request) -> EventRepository:
    return request.app.state.event_repository


def get_event_hub(request: Request) -> EventHub:
    return request.app.state.event_hub


def get_event_bus(request: Request) -> EventBus:
    return request.app.state.event_bus


def get_audit_ledger(request: Request) -> AuditLedger:
    return request.app.state.audit_ledger


def get_sensor_registry(request: Request) -> SensorRegistry:
    return request.app.state.sensor_registry


def get_firewall_controller(request: Request) -> FirewallController:
    return request.app.state.firewall_controller


def get_ai_analyzer(request: Request) -> OllamaThreatAnalyzer:
    return request.app.state.ai_analyzer
