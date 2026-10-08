from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from sqlalchemy import Boolean, DateTime, String, Uuid, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column

from .auth_models import LocalPrincipal, Role
from .database import Base


class LocalPrincipalRecord(Base):
    __tablename__ = "local_principals"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(32), index=True)
    token_digest: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    token_prefix: Mapped[str] = mapped_column(String(24))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_by: Mapped[str | None] = mapped_column(String(256), nullable=True)

    @classmethod
    def from_principal(cls, principal: LocalPrincipal) -> LocalPrincipalRecord:
        return cls(**principal.model_dump(mode="python"))

    def apply(self, principal: LocalPrincipal) -> None:
        self.name = principal.name
        self.role = principal.role.value
        self.token_digest = principal.token_digest
        self.token_prefix = principal.token_prefix
        self.enabled = principal.enabled
        self.created_by = principal.created_by
        self.created_at = principal.created_at
        self.rotated_at = principal.rotated_at
        self.disabled_at = principal.disabled_at
        self.disabled_by = principal.disabled_by

    def to_principal(self) -> LocalPrincipal:
        return LocalPrincipal(
            id=self.id,
            name=self.name,
            role=Role(self.role),
            token_digest=self.token_digest,
            token_prefix=self.token_prefix,
            enabled=self.enabled,
            created_by=self.created_by,
            created_at=self.created_at,
            rotated_at=self.rotated_at,
            disabled_at=self.disabled_at,
            disabled_by=self.disabled_by,
        )


class PrincipalRepository(Protocol):
    async def add(self, principal: LocalPrincipal) -> LocalPrincipal: ...

    async def list(self) -> list[LocalPrincipal]: ...

    async def get(self, principal_id: UUID) -> LocalPrincipal | None: ...

    async def get_by_digest(self, token_digest: str) -> LocalPrincipal | None: ...

    async def save(self, principal: LocalPrincipal) -> LocalPrincipal: ...


class InMemoryPrincipalRepository:
    def __init__(self) -> None:
        self._principals: dict[UUID, LocalPrincipal] = {}

    async def add(self, principal: LocalPrincipal) -> LocalPrincipal:
        if any(item.name == principal.name for item in self._principals.values()):
            raise ValueError("principal name already exists")
        if any(item.token_digest == principal.token_digest for item in self._principals.values()):
            raise ValueError("principal token already exists")
        self._principals[principal.id] = principal.model_copy(deep=True)
        return principal.model_copy(deep=True)

    async def list(self) -> list[LocalPrincipal]:
        return sorted(
            (item.model_copy(deep=True) for item in self._principals.values()),
            key=lambda item: item.created_at,
        )

    async def get(self, principal_id: UUID) -> LocalPrincipal | None:
        principal = self._principals.get(principal_id)
        return principal.model_copy(deep=True) if principal else None

    async def get_by_digest(self, token_digest: str) -> LocalPrincipal | None:
        for principal in self._principals.values():
            if principal.token_digest == token_digest:
                return principal.model_copy(deep=True)
        return None

    async def save(self, principal: LocalPrincipal) -> LocalPrincipal:
        if principal.id not in self._principals:
            raise ValueError("principal does not exist")
        for candidate in self._principals.values():
            if candidate.id != principal.id and candidate.name == principal.name:
                raise ValueError("principal name already exists")
            if candidate.id != principal.id and candidate.token_digest == principal.token_digest:
                raise ValueError("principal token already exists")
        self._principals[principal.id] = principal.model_copy(deep=True)
        return principal.model_copy(deep=True)


class SqlPrincipalRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def add(self, principal: LocalPrincipal) -> LocalPrincipal:
        async with self._session_factory() as session:
            session.add(LocalPrincipalRecord.from_principal(principal))
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                raise ValueError("principal name or token already exists") from exc
        return principal.model_copy(deep=True)

    async def list(self) -> list[LocalPrincipal]:
        statement = select(LocalPrincipalRecord).order_by(LocalPrincipalRecord.created_at.asc())
        async with self._session_factory() as session:
            rows = (await session.scalars(statement)).all()
            return [row.to_principal() for row in rows]

    async def get(self, principal_id: UUID) -> LocalPrincipal | None:
        async with self._session_factory() as session:
            row = await session.get(LocalPrincipalRecord, principal_id)
            return row.to_principal() if row else None

    async def get_by_digest(self, token_digest: str) -> LocalPrincipal | None:
        statement = select(LocalPrincipalRecord).where(
            LocalPrincipalRecord.token_digest == token_digest
        )
        async with self._session_factory() as session:
            row = await session.scalar(statement)
            return row.to_principal() if row else None

    async def save(self, principal: LocalPrincipal) -> LocalPrincipal:
        async with self._session_factory() as session:
            row = await session.get(LocalPrincipalRecord, principal.id)
            if row is None:
                raise ValueError("principal does not exist")
            row.apply(principal)
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                raise ValueError("principal name or token already exists") from exc
        return principal.model_copy(deep=True)
