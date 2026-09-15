from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "PrivaShield"
    environment: str = "development"
    log_level: str = "INFO"
    api_prefix: str = "/api/v1"
    database_enabled: bool = True
    database_url: str = (
        "postgresql+asyncpg://privashield:privashield@localhost:5432/privashield"
    )
    enforcement_mode: Literal["observe", "simulate"] = "observe"
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
    sensor_ttl_seconds: int = 60

    model_config = SettingsConfigDict(
        env_prefix="PRIVASHIELD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
