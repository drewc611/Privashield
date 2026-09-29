from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "PrivaShield"
    # Anything other than "development" is treated as a deployment. The default is
    # not "development" so a missing variable fails closed.
    environment: str = "production"
    log_level: str = "INFO"
    api_prefix: str = "/api/v1"
    database_enabled: bool = True
    # No default: the URL carries the database password. Startup fails when
    # database_enabled is true and this is unset (see create_app).
    database_url: SecretStr | None = None
    enforcement_mode: Literal["observe", "simulate"] = "observe"
    auth_mode: Literal["disabled", "local"] = "local"
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
    max_request_body_bytes: int = Field(default=1_048_576, gt=0)
    sensor_ttl_seconds: int = 60
    policy_verification_public_key: str | None = None
    policy_verification_key_id: str = "local-v1"

    model_config = SettingsConfigDict(
        env_prefix="PRIVASHIELD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @model_validator(mode="after")
    def refuse_disabled_auth_outside_development(self) -> Self:
        if self.auth_mode == "disabled" and self.environment != "development":
            raise ValueError(
                "PRIVASHIELD_AUTH_MODE=disabled makes every request an administrator and is "
                "only allowed for local development. Set PRIVASHIELD_AUTH_MODE=local, or "
                "opt in explicitly with PRIVASHIELD_ENVIRONMENT=development "
                f"(current environment: {self.environment!r})."
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
