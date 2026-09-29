from functools import lru_cache
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "PrivaShield"
    environment: str = "development"
    log_level: str = "INFO"
    api_prefix: str = "/api/v1"
    database_enabled: bool = True
    database_url: str = "postgresql+asyncpg://privashield:privashield@localhost:5432/privashield"
    enforcement_mode: Literal["observe", "simulate"] = "observe"
    auth_mode: Literal["disabled", "local"] = "disabled"
    bootstrap_admin_token: SecretStr | None = None
    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
    ]
    nats_enabled: bool = False
    nats_url: str = "nats://127.0.0.1:4222"
    nats_stream: str = "PRIVASHIELD_EVENTS"
    ollama_enabled: bool = False
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "gemma3"
    audit_path: str | None = None
    # Scoring is advisory and read-only, so it is on by default. Training is
    # opt-in: ADR-0004 treats a self-training detector as a trust-boundary
    # change, which is an operator's decision rather than a default.
    adaptive_scoring_enabled: bool = True
    adaptive_learning_enabled: bool = False
    adaptive_canary_path: str = "evaluation/adaptive-canary.json"
    adaptive_state_path: str | None = None
    adaptive_canary_interval: int = 20
    # Poisoning-guard bounds. Exposed because the influence cap interacts with
    # team size in a way no single default survives: a source holds roughly 1/N
    # of the window with N active analysts, so at 0.35 a team of three or fewer
    # stalls at about 20 updates and never trains further. Raising it weakens rate
    # limiting, which ADR-0004 already establishes is not the control that bounds
    # damage — the canary is. See docs/ADAPTIVE_DETECTION.md before changing it.
    adaptive_max_source_share: float = 0.35
    adaptive_min_updates_before_capping: int = 20
    adaptive_label_flood_threshold: int = 50
    adaptive_window_hours: int = 24
    sensor_ttl_seconds: int = 60
    policy_verification_public_key: str | None = None
    policy_verification_key_id: str = "local-v1"

    model_config = SettingsConfigDict(
        env_prefix="PRIVASHIELD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
