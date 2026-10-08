from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime
from typing import Final
from uuid import UUID

from .auth_models import (
    AuthCapabilities,
    AuthMode,
    LocalPrincipal,
    PrincipalContext,
    PrincipalCreate,
    PrincipalPublic,
    PrincipalTokenIssued,
    Role,
)
from .auth_repository import PrincipalRepository

_TOKEN_PREFIX: Final[str] = "psh_"
_TOKEN_BYTES: Final[int] = 32

ALL_ROLES = frozenset(Role)
READ_ROLES = frozenset(Role)
ANALYST_ROLES = frozenset({Role.ANALYST, Role.OPERATOR, Role.ADMINISTRATOR})
OPERATOR_ROLES = frozenset({Role.OPERATOR, Role.ADMINISTRATOR})
ADMIN_ROLES = frozenset({Role.ADMINISTRATOR})
AUDIT_ROLES = frozenset({Role.AUDITOR, Role.ADMINISTRATOR})


class AuthenticationError(Exception):
    pass


class AuthorizationError(Exception):
    pass


class PrincipalConflictError(Exception):
    pass


class PrincipalNotFoundError(Exception):
    pass


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> str:
    return _TOKEN_PREFIX + secrets.token_urlsafe(_TOKEN_BYTES)


class AuthService:
    def __init__(
        self,
        repository: PrincipalRepository,
        *,
        mode: AuthMode,
        bootstrap_admin_token: str | None,
    ) -> None:
        self._repository = repository
        self._mode = mode
        self._bootstrap_digest = (
            token_digest(bootstrap_admin_token) if bootstrap_admin_token else None
        )

    @property
    def mode(self) -> AuthMode:
        return self._mode

    @property
    def bootstrap_configured(self) -> bool:
        return self._bootstrap_digest is not None

    def capabilities(self) -> AuthCapabilities:
        return AuthCapabilities(
            mode=self._mode,
            authentication_required=self._mode is AuthMode.LOCAL,
            bootstrap_admin_configured=self.bootstrap_configured,
        )

    def disabled_context(self) -> PrincipalContext:
        return PrincipalContext(
            name="local-development-unverified",
            role=Role.ADMINISTRATOR,
            credential_verified=False,
            bootstrap=True,
        )

    async def authenticate(self, token: str | None) -> PrincipalContext | None:
        if self._mode is AuthMode.DISABLED:
            return self.disabled_context()
        if not token:
            return None

        digest = token_digest(token)
        if self._bootstrap_digest is not None and hmac.compare_digest(
            digest,
            self._bootstrap_digest,
        ):
            return PrincipalContext(
                name="bootstrap-administrator",
                role=Role.ADMINISTRATOR,
                credential_verified=True,
                bootstrap=True,
            )

        principal = await self._repository.get_by_digest(digest)
        if principal is None or not principal.enabled:
            return None
        if not hmac.compare_digest(principal.token_digest, digest):
            return None
        return PrincipalContext(
            principal_id=principal.id,
            name=principal.name,
            role=principal.role,
            credential_verified=True,
            bootstrap=False,
        )

    async def list_principals(self) -> list[PrincipalPublic]:
        return [PrincipalPublic.from_principal(item) for item in await self._repository.list()]

    async def create_principal(
        self,
        request: PrincipalCreate,
        *,
        created_by: str,
    ) -> PrincipalTokenIssued:
        raw_token = generate_token()
        principal = LocalPrincipal(
            name=request.name,
            role=request.role,
            token_digest=token_digest(raw_token),
            token_prefix=raw_token[:12],
            created_by=created_by,
        )
        try:
            created = await self._repository.add(principal)
        except ValueError as exc:
            raise PrincipalConflictError(str(exc)) from exc
        return PrincipalTokenIssued(
            principal=PrincipalPublic.from_principal(created),
            token=raw_token,
        )

    async def rotate_principal(
        self,
        principal_id: UUID,
    ) -> PrincipalTokenIssued:
        principal = await self._repository.get(principal_id)
        if principal is None:
            raise PrincipalNotFoundError("principal does not exist")
        if not principal.enabled:
            raise PrincipalConflictError("disabled principal cannot be rotated")
        raw_token = generate_token()
        principal.token_digest = token_digest(raw_token)
        principal.token_prefix = raw_token[:12]
        principal.rotated_at = datetime.now(UTC)
        try:
            updated = await self._repository.save(principal)
        except ValueError as exc:
            raise PrincipalConflictError(str(exc)) from exc
        return PrincipalTokenIssued(
            principal=PrincipalPublic.from_principal(updated),
            token=raw_token,
        )

    async def disable_principal(
        self,
        principal_id: UUID,
        *,
        disabled_by: str,
        requester_id: UUID | None,
    ) -> PrincipalPublic:
        principal = await self._repository.get(principal_id)
        if principal is None:
            raise PrincipalNotFoundError("principal does not exist")
        if not principal.enabled:
            raise PrincipalConflictError("principal is already disabled")
        if requester_id is not None and requester_id == principal_id:
            raise PrincipalConflictError("administrators cannot disable their own active principal")

        if principal.role is Role.ADMINISTRATOR and not self.bootstrap_configured:
            enabled_admins = [
                candidate
                for candidate in await self._repository.list()
                if candidate.enabled and candidate.role is Role.ADMINISTRATOR
            ]
            if len(enabled_admins) <= 1:
                raise PrincipalConflictError("cannot disable the last enabled administrator")

        principal.enabled = False
        principal.disabled_at = datetime.now(UTC)
        principal.disabled_by = disabled_by
        try:
            updated = await self._repository.save(principal)
        except ValueError as exc:
            raise PrincipalConflictError(str(exc)) from exc
        return PrincipalPublic.from_principal(updated)


class AuthorizationPolicy:
    """Central server-side role policy for the v1 HTTP and WebSocket API."""

    def allowed_roles(self, method: str, path: str) -> frozenset[Role] | None:
        if path in {"/", "/api/v1/health"}:
            return None

        if path in {"/api/v1/auth/capabilities", "/api/v1/auth/me"}:
            return READ_ROLES

        if path.startswith("/api/v1/principals"):
            return ADMIN_ROLES

        if path.startswith("/api/v1/audit"):
            return AUDIT_ROLES

        if path.startswith("/api/v1/policies"):
            return (
                OPERATOR_ROLES
                if method not in {"GET", "HEAD", "OPTIONS"}
                else frozenset({Role.OPERATOR, Role.ADMINISTRATOR, Role.AUDITOR})
            )

        if path.startswith("/api/v1/firewall") or path.startswith("/api/v1/response"):
            return OPERATOR_ROLES if method not in {"GET", "HEAD", "OPTIONS"} else READ_ROLES

        if path.startswith("/api/v1/feedback"):
            return (
                ANALYST_ROLES
                if method not in {"GET", "HEAD", "OPTIONS"}
                else frozenset({Role.ANALYST, Role.OPERATOR, Role.ADMINISTRATOR, Role.AUDITOR})
            )

        if any(
            path.startswith(prefix)
            for prefix in (
                "/api/v1/ai",
                "/api/v1/dlp",
                "/api/v1/anomaly",
                "/api/v1/ransomware",
                "/api/v1/malware",
                "/api/v1/incidents",
            )
        ):
            return ANALYST_ROLES if method not in {"GET", "HEAD", "OPTIONS"} else READ_ROLES

        if path.startswith("/api/v1/events") or path.startswith("/api/v1/sensors"):
            return OPERATOR_ROLES if method not in {"GET", "HEAD", "OPTIONS"} else READ_ROLES

        if path.startswith("/api/v1/ws/"):
            return READ_ROLES

        if path.startswith("/api/v1/"):
            return READ_ROLES if method in {"GET", "HEAD", "OPTIONS"} else OPERATOR_ROLES

        # Documentation/schema endpoints are protected whenever local auth is enabled.
        return READ_ROLES

    def authorize(self, principal: PrincipalContext, method: str, path: str) -> None:
        allowed = self.allowed_roles(method, path)
        if allowed is None:
            return
        if principal.role not in allowed:
            raise AuthorizationError(
                f"role {principal.role.value!r} is not authorized for {method} {path}"
            )
