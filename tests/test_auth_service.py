from __future__ import annotations

import asyncio

from privashield_api.auth import AuthService, PrincipalConflictError
from privashield_api.auth_models import AuthMode, PrincipalCreate, Role
from privashield_api.auth_repository import InMemoryPrincipalRepository


def test_last_durable_administrator_cannot_be_disabled_without_bootstrap() -> None:
    async def scenario() -> None:
        service = AuthService(
            InMemoryPrincipalRepository(),
            mode=AuthMode.LOCAL,
            bootstrap_admin_token=None,
        )
        issued = await service.create_principal(
            PrincipalCreate(name="only-admin", role=Role.ADMINISTRATOR),
            created_by="setup",
        )
        try:
            await service.disable_principal(
                issued.principal.id,
                disabled_by="recovery-operator",
                requester_id=None,
            )
        except PrincipalConflictError as exc:
            assert "last enabled administrator" in str(exc)
        else:
            raise AssertionError("last administrator disablement should have been rejected")

    asyncio.run(scenario())
