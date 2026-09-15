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
    enforcement_mode: str
    enforcement_active: bool = False
