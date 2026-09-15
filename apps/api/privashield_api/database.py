from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, DateTime, Integer, String, Uuid
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .schemas import SecurityEvent


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
    correlation_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True, index=True)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")

    @classmethod
    def from_event(cls, event: SecurityEvent) -> "SecurityEventRecord":
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
            source=self.source,
            event_type=self.event_type,
            severity=self.severity,
            sensor_id=self.sensor_id,
            asset_id=self.asset_id,
            src_ip=self.src_ip,
            src_port=self.src_port,
            dst_ip=self.dst_ip,
            dst_port=self.dst_port,
            protocol=self.protocol,
            direction=self.direction,
            user_id=self.user_id,
            process=self.process,
            summary=self.summary,
            raw_ref=self.raw_ref,
            metadata=self.metadata_json or {},
            correlation_id=self.correlation_id,
            schema_version=self.schema_version,
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
