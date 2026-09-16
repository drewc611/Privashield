from fastapi import Request

from .ai import OllamaThreatAnalyzer
from .anomaly import AnomalyEngine
from .audit import AuditLedger
from .bus import EventBus
from .feedback_repository import FeedbackRepository
from .firewall import FirewallController
from .policy import PolicyService
from .realtime import EventHub
from .repository import EventRepository
from .response import ResponseStore
from .sensors import SensorRegistry


def get_event_repository(request: Request) -> EventRepository:
    return request.app.state.event_repository


def get_feedback_repository(request: Request) -> FeedbackRepository:
    return request.app.state.feedback_repository


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


def get_anomaly_engine(request: Request) -> AnomalyEngine:
    return request.app.state.anomaly_engine


def get_response_store(request: Request) -> ResponseStore:
    return request.app.state.response_store


def get_policy_service(request: Request) -> PolicyService:
    return request.app.state.policy_service
