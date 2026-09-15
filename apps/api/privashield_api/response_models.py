from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ResponseActionType(StrEnum):
    BLOCK_IP = "block_ip"
    ISOLATE_INTERFACE = "isolate_interface"
    TERMINATE_SESSION = "terminate_session"
    REVOKE_TOKEN = "revoke_token"
    QUARANTINE_FILE = "quarantine_file"
    STOP_PROCESS = "stop_process"


class ResponseStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    SIMULATED = "simulated"
    CANCELLED = "cancelled"


class ResponseActionCreate(BaseModel):
    action_type: ResponseActionType
    target: str = Field(min_length=1, max_length=1024)
    reason: str = Field(min_length=1, max_length=2000)
    detection_id: UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ResponseAction(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    action_type: ResponseActionType
    target: str
    reason: str
    detection_id: UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    status: ResponseStatus = ResponseStatus.PENDING
    requested_by: str = "operator"
    approved_by: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    execution_result: str | None = None
    enforced: bool = False


class ApprovalRequest(BaseModel):
    approved_by: str = Field(min_length=1, max_length=256)


class ResponseCapabilities(BaseModel):
    simulation: bool = True
    privileged_execution: bool = False
    supported_actions: list[ResponseActionType]
