import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from privashield_api.config import Settings
from privashield_api.main import create_app


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    for name in list(os.environ):
        if name.startswith("PRIVASHIELD_"):
            monkeypatch.delenv(name)


def test_defaults_require_authentication_and_a_deployment_environment() -> None:
    settings = Settings(_env_file=None)
    assert settings.auth_mode == "local"
    assert settings.environment == "production"
    assert settings.database_url is None


@pytest.mark.parametrize("environment", ["production", "staging", "test", ""])
def test_disabled_auth_is_refused_outside_development(environment: str) -> None:
    with pytest.raises(ValidationError) as excinfo:
        Settings(_env_file=None, auth_mode="disabled", environment=environment)
    message = str(excinfo.value)
    assert "PRIVASHIELD_AUTH_MODE=disabled" in message
    assert "PRIVASHIELD_ENVIRONMENT=development" in message


def test_disabled_auth_is_allowed_with_explicit_development_opt_in() -> None:
    settings = Settings(_env_file=None, auth_mode="disabled", environment="development")
    assert settings.auth_mode == "disabled"


def test_disabled_auth_from_environment_variable_alone_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PRIVASHIELD_AUTH_MODE", "disabled")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_development_opt_in_from_environment_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PRIVASHIELD_AUTH_MODE", "disabled")
    monkeypatch.setenv("PRIVASHIELD_ENVIRONMENT", "development")
    assert Settings(_env_file=None).auth_mode == "disabled"


def test_local_auth_is_allowed_in_any_environment() -> None:
    settings = Settings(_env_file=None, auth_mode="local", environment="production")
    assert settings.auth_mode == "local"


def test_startup_fails_when_database_is_enabled_without_a_url() -> None:
    settings = Settings(
        _env_file=None,
        database_enabled=True,
        nats_enabled=False,
        ollama_enabled=False,
        audit_path=None,
    )
    with pytest.raises(RuntimeError, match="PRIVASHIELD_DATABASE_URL"):
        with TestClient(create_app(settings)):
            pass
