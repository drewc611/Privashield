from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import __version__
from .ai import OllamaProvider, ThreatAnalyzer
from .anomaly import AnomalyEngine
from .audit import AuditLedger
from .auth import AuthorizationPolicy, AuthService
from .auth_middleware import AuthMiddleware
from .auth_models import AuthMode
from .auth_repository import InMemoryPrincipalRepository, SqlPrincipalRepository
from .bus import NatsEventBus, NullEventBus
from .config import Settings, get_settings
from .database import build_engine, build_session_factory, initialize_schema
from .feedback_repository import InMemoryFeedbackRepository, SqlFeedbackRepository
from .firewall import FirewallController
from .learning.canary import CanaryCorpusError, arm_detector, load_canary_corpus
from .learning.engine import AdaptiveDetector
from .learning.guard import GuardConfig, PoisoningGuard
from .policy import PolicyService
from .policy_repository import InMemoryPolicyRepository, SqlPolicyRepository
from .policy_signing import load_public_key
from .realtime import EventHub
from .repository import InMemoryEventRepository, SqlEventRepository
from .response import ResponseStore
from .routes.ai import router as ai_router
from .routes.anomaly import router as anomaly_router
from .routes.audit import router as audit_router
from .routes.auth import router as auth_router
from .routes.dlp import router as dlp_router
from .routes.events import router as events_router
from .routes.feedback import router as feedback_router
from .routes.firewall import router as firewall_router
from .routes.health import router as health_router
from .routes.incidents import router as incidents_router
from .routes.learning import router as learning_router
from .routes.malware import router as malware_router
from .routes.policies import router as policies_router
from .routes.ransomware import router as ransomware_router
from .routes.realtime import router as realtime_router
from .routes.response import router as response_router
from .routes.sensors import router as sensors_router
from .sensors import SensorRegistry


def _build_adaptive_detector(settings: Settings) -> AdaptiveDetector:
    """Construct the detector, restore any saved state, and arm the canary.

    Arming is not optional decoration. ADR-0004 measured that the rate limits
    alone do not stop a determined poisoner, so a detector running without ground
    truth has no working defense. When the corpus cannot be loaded, learning is
    left unarmed and `status()` reports `canary_enabled` false, which is what
    makes that condition visible instead of assumed.
    """
    guard_config = GuardConfig(
        window=timedelta(hours=settings.adaptive_window_hours),
        max_source_share=settings.adaptive_max_source_share,
        even_split_slack=settings.adaptive_even_split_slack,
        max_source_updates=settings.adaptive_max_source_updates,
        min_updates_before_capping=settings.adaptive_min_updates_before_capping,
        label_flood_threshold=settings.adaptive_label_flood_threshold,
    )

    state_path = Path(settings.adaptive_state_path) if settings.adaptive_state_path else None
    if state_path is not None and state_path.exists():
        detector = AdaptiveDetector.load(state_path)
        # A reloaded detector carries the bounds it was saved with. Configuration
        # is the current intent, so it wins.
        detector.guard.config = guard_config
    else:
        detector = AdaptiveDetector(guard=PoisoningGuard(config=guard_config))
    detector.state_path = state_path

    try:
        corpus = load_canary_corpus(settings.adaptive_canary_path)
    except CanaryCorpusError:
        # Deliberately not fatal. Scoring is still useful and still advisory; it
        # is learning that needs the canary, and the status endpoint reports that
        # the corpus is absent.
        return detector

    return arm_detector(detector, corpus, interval=settings.adaptive_canary_interval)


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.settings = resolved_settings
        app.state.database_engine = None
        app.state.event_hub = EventHub()
        app.state.audit_ledger = AuditLedger(resolved_settings.audit_path)
        app.state.sensor_registry = SensorRegistry(resolved_settings.sensor_ttl_seconds)
        app.state.firewall_controller = FirewallController(resolved_settings.enforcement_mode)
        app.state.anomaly_engine = AnomalyEngine()
        app.state.response_store = ResponseStore()
        app.state.adaptive_detector = _build_adaptive_detector(resolved_settings)
        app.state.ai_analyzer = ThreatAnalyzer(
            provider=OllamaProvider(
                resolved_settings.ollama_base_url,
                resolved_settings.ollama_model,
                resolved_settings.ollama_enabled,
            )
        )

        if resolved_settings.database_enabled:
            engine = build_engine(resolved_settings.database_url)
            await initialize_schema(engine)
            session_factory = build_session_factory(engine)
            app.state.database_engine = engine
            app.state.event_repository = SqlEventRepository(session_factory)
            app.state.feedback_repository = SqlFeedbackRepository(session_factory)
            app.state.policy_repository = SqlPolicyRepository(session_factory)
            app.state.principal_repository = SqlPrincipalRepository(session_factory)
        else:
            app.state.event_repository = InMemoryEventRepository()
            app.state.feedback_repository = InMemoryFeedbackRepository()
            app.state.policy_repository = InMemoryPolicyRepository()
            app.state.principal_repository = InMemoryPrincipalRepository()

        bootstrap_secret = resolved_settings.bootstrap_admin_token
        bootstrap_token = (
            bootstrap_secret.get_secret_value() if bootstrap_secret is not None else None
        )
        app.state.auth_service = AuthService(
            app.state.principal_repository,
            mode=AuthMode(resolved_settings.auth_mode),
            bootstrap_admin_token=bootstrap_token,
        )
        app.state.authorization_policy = AuthorizationPolicy()

        public_key_text = resolved_settings.policy_verification_public_key
        verification_key = load_public_key(public_key_text) if public_key_text else None
        app.state.policy_service = PolicyService(
            app.state.policy_repository,
            verification_key=verification_key,
            key_id=resolved_settings.policy_verification_key_id,
        )

        if resolved_settings.nats_enabled:
            event_bus = NatsEventBus(resolved_settings.nats_url, resolved_settings.nats_stream)
            await event_bus.connect()
            app.state.event_bus = event_bus
        else:
            app.state.event_bus = NullEventBus()

        yield

        # Final flush. Checkpoints already happen on every verified canary, so
        # this only catches updates since the last one; a crash loses at most that
        # window rather than the whole model.
        app.state.adaptive_detector.flush()

        await app.state.event_bus.close()
        if app.state.database_engine is not None:
            await app.state.database_engine.dispose()

    app = FastAPI(
        title="PrivaShield API",
        version=__version__,
        description="Local-first PrivaShield control-plane API.",
        lifespan=lifespan,
    )

    # Auth is added before CORS so browser clients still receive CORS headers on 401/403 responses.
    app.add_middleware(AuthMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved_settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

    for router in (
        health_router,
        auth_router,
        events_router,
        sensors_router,
        firewall_router,
        ai_router,
        dlp_router,
        anomaly_router,
        ransomware_router,
        malware_router,
        incidents_router,
        feedback_router,
        learning_router,
        response_router,
        policies_router,
        audit_router,
        realtime_router,
    ):
        app.include_router(router, prefix=resolved_settings.api_prefix)

    @app.get("/", include_in_schema=False)
    async def root() -> dict[str, str]:
        return {
            "service": "PrivaShield API",
            "version": __version__,
            "docs": "/docs",
        }

    return app


app = create_app()
