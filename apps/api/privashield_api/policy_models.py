from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator

from .response_models import ResponseActionType


class PolicyStatus(StrEnum):
    DRAFT = "draft"
    APPROVED = "approved"
    ACTIVE = "active"
    SUPERSEDED = "superseded"


class PolicyHistoryEventType(StrEnum):
    REGISTERED = "registered"
    APPROVED = "approved"
    ACTIVATED = "activated"
    SUPERSEDED = "superseded"
    ROLLED_BACK = "rolled_back"


class PolicyDocument(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    allowed_actions: list[ResponseActionType] = Field(default_factory=list, max_length=32)
    minimum_risk_score: float = Field(default=0.85, ge=0.0, le=1.0)
    require_human_approval: Literal[True] = True
    mode: Literal["observe", "simulate"] = "simulate"
    privileged_execution: Literal[False] = False
    schema_version: Literal["1.0"] = "1.0"

    @field_validator("allowed_actions")
    @classmethod
    def unique_actions(cls, value: list[ResponseActionType]) -> list[ResponseActionType]:
        if len(value) != len(set(value)):
            raise ValueError("allowed_actions must not contain duplicates")
        return value


class SignedPolicyEnvelope(BaseModel):
    policy_id: UUID
    version: int = Field(ge=1)
    document: PolicyDocument
    key_id: str = Field(min_length=1, max_length=128)
    algorithm: Literal["hmac-sha256"] = "hmac-sha256"
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")


class PolicyRegisterRequest(BaseModel):
    envelope: SignedPolicyEnvelope
    created_by: str = Field(min_length=1, max_length=256)


class PolicyApprovalRequest(BaseModel):
    approved_by: str = Field(min_length=1, max_length=256)


class PolicyActivationRequest(BaseModel):
    activated_by: str = Field(min_length=1, max_length=256)


class PolicyRollbackRequest(BaseModel):
    target_version: int = Field(ge=1)
    actor: str = Field(min_length=1, max_length=256)


class PolicyRevision(BaseModel):
    policy_id: UUID
    version: int
    document: PolicyDocument
    key_id: str
    algorithm: Literal["hmac-sha256"] = "hmac-sha256"
    signature: str
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: PolicyStatus = PolicyStatus.DRAFT
    created_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    approved_by: str | None = None
    approved_at: datetime | None = None
    activated_by: str | None = None
    activated_at: datetime | None = None
    signature_valid: bool = True
    enforced: Literal[False] = False

    @model_validator(mode="after")
    def preserve_non_enforcement(self) -> PolicyRevision:
        if self.document.privileged_execution is not False:
            raise ValueError("policy revisions cannot enable privileged execution")
        return self


class PolicyHistoryEvent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    policy_id: UUID
    version: int = Field(ge=1)
    event_type: PolicyHistoryEventType
    actor: str = Field(min_length=1, max_length=256)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, str | int | bool | None] = Field(default_factory=dict)


class PolicyCapabilities(BaseModel):
    signing_configured: bool
    signing_algorithm: Literal["hmac-sha256"] = "hmac-sha256"
    configured_key_id: str
    require_human_approval: Literal[True] = True
    privileged_execution: Literal[False] = False
    activation_effect: Literal["simulation-governance-only"] = "simulation-governance-only"
