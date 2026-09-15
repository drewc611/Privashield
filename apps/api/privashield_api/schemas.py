from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, IPvAnyAddress


class EventSource(StrEnum):
    ZEEK = "zeek"
    SURICATA = "suricata"
    HOST = "host"
    WAF = "waf"
    DLP = "dlp"
    IDENTITY = "identity"
    FIREWALL = "firewall"
    SYSTEM = "system"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Direction(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    LATERAL = "lateral"


class SecurityEvent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: EventSource
    event_type: str = Field(min_length=1, max_length=128)
    severity: Severity = Severity.INFO
    sensor_id: UUID | None = None
    asset_id: UUID | None = None
    src_ip: IPvAnyAddress | None = None
    src_port: int | None = Field(default=None, ge=1, le=65535)
    dst_ip: IPvAnyAddress | None = None
    dst_port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = Field(default=None, max_length=32)
    direction: Direction | None = None
    user_id: str | None = Field(default=None, max_length=256)
    process: str | None = Field(default=None, max_length=512)
    summary: str = Field(min_length=1, max_length=4096)
    raw_ref: UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    correlation_id: UUID | None = None
    schema_version: str = "1.0"


class EventStats(BaseModel):
    total: int
    by_severity: dict[Severity, int]
    by_source: dict[EventSource, int]


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


class SystemStatus(BaseModel):
    status: str
    environment: str
    database: str
    event_bus: str
    ai: str
    enforcement_mode: str
    enforcement_active: bool = False


class SensorHeartbeat(BaseModel):
    sensor_id: UUID
    name: str = Field(min_length=1, max_length=128)
    sensor_type: str = Field(min_length=1, max_length=64)
    hostname: str = Field(min_length=1, max_length=255)
    interface: str | None = Field(default=None, max_length=128)
    version: str | None = Field(default=None, max_length=64)
    capabilities: list[str] = Field(default_factory=list)


class SensorStatus(BaseModel):
    sensor_id: UUID
    name: str
    sensor_type: str
    hostname: str
    interface: str | None = None
    version: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    last_seen: datetime
    active: bool


class AIAnalysisRequest(BaseModel):
    event_ids: list[UUID] = Field(min_length=1, max_length=25)
    question: str | None = Field(default=None, max_length=2000)


class AIThreatAnalysis(BaseModel):
    summary: str = Field(min_length=1, max_length=4000)
    risk_level: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list, max_length=12)
    recommended_actions: list[str] = Field(default_factory=list, max_length=12)


class AIStatus(BaseModel):
    enabled: bool
    provider: str
    model: str
    authority: str = "advisory-only"


class FirewallConfig(BaseModel):
    mode: Literal["observe", "simulate"] = "observe"
    threshold: float = Field(default=0.85, ge=0.0, le=1.0)


class FirewallEvaluationRequest(BaseModel):
    src_ip: IPvAnyAddress | None = None
    dst_ip: IPvAnyAddress | None = None
    src_port: int | None = Field(default=None, ge=1, le=65535)
    dst_port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = Field(default=None, max_length=32)
    risk_score: float = Field(ge=0.0, le=1.0)
    reason: str = Field(min_length=1, max_length=1000)


class FirewallEvaluation(BaseModel):
    decision_id: UUID = Field(default_factory=uuid4)
    decision: Literal["would_allow", "would_drop"]
    threshold: float
    risk_score: float
    mode: Literal["observe", "simulate"]
    enforced: bool = False
    reason: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AuditEntry(BaseModel):
    sequence: int
    timestamp: datetime
    actor: str
    action: str
    resource_type: str
    resource_id: str
    payload_hash: str
    previous_hash: str
    entry_hash: str


class AuditVerification(BaseModel):
    valid: bool
    entries: int
    first_invalid_sequence: int | None = None
