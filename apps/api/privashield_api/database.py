"""Persistence, and the conversions at its boundary.

Columns hold strings and JSON; the domain models hold enums, addresses and nested
models. Pydantic would coerce most of it silently, which is why this module
carried a blanket `arg-type` mypy exclusion: the annotations claimed one thing and
the values were another.

The conversions are explicit instead. That removes the exclusion, and it changes
what happens to a row whose stored value is outside the domain its column
promises — written by an older schema, by hand, or by something that is not this
API. Such a row now fails at the boundary naming the column and the value, rather
than surfacing later as a Pydantic error about a field the reader has no path back
to. `auth_repository.to_principal` already took this approach for stored roles.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Uuid
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .feedback_models import AnalystFeedback, FeedbackLabel, FeedbackTargetType
from .policy_models import (
    PolicyDocument,
    PolicyHistoryEvent,
    PolicyHistoryEventType,
    PolicyRevision,
    PolicyStatus,
)
from .schemas import Direction, EventSource, SecurityEvent, Severity


class StoredValueError(ValueError):
    """A stored value falls outside the domain its column promises.

    Loud on purpose. A security product that quietly reinterprets a row it cannot
    parse is worse than one that refuses to serve it.
    """


def _as_enum[E: StrEnum](enum_type: type[E], value: str, *, column: str) -> E:
    try:
        return enum_type(value)
    except ValueError as exc:
        permitted = ", ".join(sorted(member.value for member in enum_type))
        raise StoredValueError(
            f"{column}={value!r} is not a valid {enum_type.__name__} (permitted: {permitted})"
        ) from exc


def _as_optional_enum[E: StrEnum](
    enum_type: type[E], value: str | None, *, column: str
) -> E | None:
    return None if value is None else _as_enum(enum_type, value, column=column)


def _as_ip(value: str | None, *, column: str) -> IPv4Address | IPv6Address | None:
    if value is None:
        return None
    try:
        return ip_address(value)
    except ValueError as exc:
        raise StoredValueError(f"{column}={value!r} is not an IP address") from exc


def _as_signature_algorithm(value: str, *, column: str) -> Literal["ed25519"]:
    # Narrowed by hand because the domain type is a Literal rather than an enum.
    # A stored algorithm this build cannot verify must not be treated as one it
    # can: a signature checked with the wrong algorithm is not a checked signature.
    if value != "ed25519":
        raise StoredValueError(
            f"{column}={value!r} is not a signature algorithm this build verifies"
        )
    return "ed25519"


def _as_policy_document(value: Any, *, column: str) -> PolicyDocument:
    try:
        return PolicyDocument.model_validate(value)
    except ValueError as exc:
        raise StoredValueError(f"{column} does not hold a valid policy document") from exc


class Base(DeclarativeBase):
    pass


class SecurityEventRecord(Base):
    __tablename__ = "security_events"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String(32), index=True)
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    sensor_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True, index=True)
    asset_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True, index=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    direction: Mapped[str | None] = mapped_column(String(16), nullable=True)
    user_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    process: Mapped[str | None] = mapped_column(String(512), nullable=True)
    summary: Mapped[str] = mapped_column(String(4096))
    raw_ref: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    correlation_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), nullable=True, index=True
    )
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")

    @classmethod
    def from_event(cls, event: SecurityEvent) -> SecurityEventRecord:
        return cls(
            id=event.id,
            timestamp=event.timestamp,
            ingested_at=event.ingested_at,
            source=event.source.value,
            event_type=event.event_type,
            severity=event.severity.value,
            sensor_id=event.sensor_id,
            asset_id=event.asset_id,
            src_ip=str(event.src_ip) if event.src_ip else None,
            src_port=event.src_port,
            dst_ip=str(event.dst_ip) if event.dst_ip else None,
            dst_port=event.dst_port,
            protocol=event.protocol,
            direction=event.direction.value if event.direction else None,
            user_id=event.user_id,
            process=event.process,
            summary=event.summary,
            raw_ref=event.raw_ref,
            metadata_json=event.metadata,
            correlation_id=event.correlation_id,
            schema_version=event.schema_version,
        )

    def to_event(self) -> SecurityEvent:
        return SecurityEvent(
            id=self.id,
            timestamp=self.timestamp,
            ingested_at=self.ingested_at,
            source=_as_enum(EventSource, self.source, column="security_events.source"),
            event_type=self.event_type,
            severity=_as_enum(Severity, self.severity, column="security_events.severity"),
            sensor_id=self.sensor_id,
            asset_id=self.asset_id,
            src_ip=_as_ip(self.src_ip, column="security_events.src_ip"),
            src_port=self.src_port,
            dst_ip=_as_ip(self.dst_ip, column="security_events.dst_ip"),
            dst_port=self.dst_port,
            protocol=self.protocol,
            direction=_as_optional_enum(
                Direction, self.direction, column="security_events.direction"
            ),
            user_id=self.user_id,
            process=self.process,
            summary=self.summary,
            raw_ref=self.raw_ref,
            metadata=self.metadata_json or {},
            correlation_id=self.correlation_id,
            schema_version=self.schema_version,
        )


class AnalystFeedbackRecord(Base):
    __tablename__ = "analyst_feedback"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    target_type: Mapped[str] = mapped_column(String(32), index=True)
    target_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    label: Mapped[str] = mapped_column(String(32), index=True)
    detector: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    note: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    tags_json: Mapped[list[str]] = mapped_column("tags", JSON, default=list)
    identity_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")

    @classmethod
    def from_feedback(cls, feedback: AnalystFeedback) -> AnalystFeedbackRecord:
        return cls(
            id=feedback.id,
            created_at=feedback.created_at,
            target_type=feedback.target_type.value,
            target_id=feedback.target_id,
            label=feedback.label.value,
            detector=feedback.detector,
            note=feedback.note,
            tags_json=feedback.tags,
            identity_verified=feedback.identity_verified,
            schema_version=feedback.schema_version,
        )

    def to_feedback(self) -> AnalystFeedback:
        return AnalystFeedback(
            id=self.id,
            created_at=self.created_at,
            target_type=_as_enum(
                FeedbackTargetType, self.target_type, column="analyst_feedback.target_type"
            ),
            target_id=self.target_id,
            label=_as_enum(FeedbackLabel, self.label, column="analyst_feedback.label"),
            detector=self.detector,
            note=self.note,
            tags=self.tags_json or [],
            identity_verified=self.identity_verified,
            schema_version=self.schema_version,
        )


class PolicyRevisionRecord(Base):
    __tablename__ = "policy_revisions"

    policy_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    document_json: Mapped[dict[str, Any]] = mapped_column("document", JSON)
    key_id: Mapped[str] = mapped_column(String(128))
    algorithm: Mapped[str] = mapped_column(String(32))
    signature: Mapped[str] = mapped_column(String(128))
    content_digest: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    created_by: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    approved_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    activated_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    signature_valid: Mapped[bool] = mapped_column(Boolean, default=True)
    enforced: Mapped[bool] = mapped_column(Boolean, default=False)

    @classmethod
    def from_revision(cls, revision: PolicyRevision) -> PolicyRevisionRecord:
        return cls(
            policy_id=revision.policy_id,
            version=revision.version,
            document_json=revision.document.model_dump(mode="json"),
            key_id=revision.key_id,
            algorithm=revision.algorithm,
            signature=revision.signature,
            content_digest=revision.content_digest,
            status=revision.status.value,
            created_by=revision.created_by,
            created_at=revision.created_at,
            approved_by=revision.approved_by,
            approved_at=revision.approved_at,
            activated_by=revision.activated_by,
            activated_at=revision.activated_at,
            signature_valid=revision.signature_valid,
            enforced=False,
        )

    def apply_revision(self, revision: PolicyRevision) -> None:
        self.status = revision.status.value
        self.approved_by = revision.approved_by
        self.approved_at = revision.approved_at
        self.activated_by = revision.activated_by
        self.activated_at = revision.activated_at
        self.signature_valid = revision.signature_valid
        self.enforced = False

    def to_revision(self) -> PolicyRevision:
        return PolicyRevision(
            policy_id=self.policy_id,
            version=self.version,
            document=_as_policy_document(
                self.document_json, column="policy_revisions.document_json"
            ),
            key_id=self.key_id,
            algorithm=_as_signature_algorithm(self.algorithm, column="policy_revisions.algorithm"),
            signature=self.signature,
            content_digest=self.content_digest,
            status=_as_enum(PolicyStatus, self.status, column="policy_revisions.status"),
            created_by=self.created_by,
            created_at=self.created_at,
            approved_by=self.approved_by,
            approved_at=self.approved_at,
            activated_by=self.activated_by,
            activated_at=self.activated_at,
            signature_valid=self.signature_valid,
            enforced=False,
        )


class PolicyHistoryRecord(Base):
    __tablename__ = "policy_history"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    policy_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    version: Mapped[int] = mapped_column(Integer, index=True)
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    actor: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)

    @classmethod
    def from_event(cls, event: PolicyHistoryEvent) -> PolicyHistoryRecord:
        return cls(
            id=event.id,
            policy_id=event.policy_id,
            version=event.version,
            event_type=event.event_type.value,
            actor=event.actor,
            created_at=event.created_at,
            metadata_json=event.metadata,
        )

    def to_event(self) -> PolicyHistoryEvent:
        return PolicyHistoryEvent(
            id=self.id,
            policy_id=self.policy_id,
            version=self.version,
            event_type=_as_enum(
                PolicyHistoryEventType, self.event_type, column="policy_history.event_type"
            ),
            actor=self.actor,
            created_at=self.created_at,
            metadata=self.metadata_json or {},
        )


def build_engine(database_url: str) -> AsyncEngine:
    return create_async_engine(database_url, pool_pre_ping=True)


async def initialize_schema(engine: AsyncEngine) -> None:
    # Phase 1 bootstrap. This will be replaced by explicit Alembic migrations
    # before the schema is considered release-stable.
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


def build_session_factory(engine: AsyncEngine) -> async_sessionmaker:
    return async_sessionmaker(engine, expire_on_commit=False)
