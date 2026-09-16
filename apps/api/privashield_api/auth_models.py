from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Role(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    ADMINISTRATOR = "administrator"
    AUDITOR = "auditor"


class AuthMode(StrEnum):
    DISABLED = "disabled"
    LOCAL = "local"


class PrincipalCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    role: Role


class PrincipalRotateRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=500)


class PrincipalDisableRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=500)


class LocalPrincipal(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(min_length=1, max_length=128)
    role: Role
    token_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    token_prefix: str = Field(min_length=4, max_length=24)
    enabled: bool = True
    created_by: str = Field(min_length=1, max_length=256)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    rotated_at: datetime | None = None
    disabled_at: datetime | None = None
    disabled_by: str | None = None


class PrincipalPublic(BaseModel):
    id: UUID
    name: str
    role: Role
    token_prefix: str
    enabled: bool
    created_by: str
    created_at: datetime
    rotated_at: datetime | None = None
    disabled_at: datetime | None = None
    disabled_by: str | None = None

    @classmethod
    def from_principal(cls, principal: LocalPrincipal) -> PrincipalPublic:
        return cls(**principal.model_dump(exclude={"token_digest"}))


class PrincipalTokenIssued(BaseModel):
    principal: PrincipalPublic
    token: str = Field(min_length=32)
    token_display: str = "shown-once"


class PrincipalContext(BaseModel):
    principal_id: UUID | None = None
    name: str
    role: Role
    credential_verified: bool
    bootstrap: bool = False

    @property
    def audit_actor(self) -> str:
        if self.principal_id is None:
            return self.name
        return f"{self.name}<{self.principal_id}>"


class AuthCapabilities(BaseModel):
    mode: AuthMode
    authentication_required: bool
    local_principals_supported: bool = True
    external_identity_provider_configured: bool = False
    bearer_token_storage: str = "sha256-digest-only"
    bootstrap_admin_configured: bool
