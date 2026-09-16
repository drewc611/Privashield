from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .auth import AuthorizationError


def _headers(scope: Scope) -> dict[str, str]:
    return {
        key.decode("latin-1").lower(): value.decode("latin-1")
        for key, value in scope.get("headers", [])
    }


def _bearer_token(scope: Scope) -> str | None:
    headers = _headers(scope)
    authorization = headers.get("authorization", "")
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() == "bearer" and value:
        return value.strip()

    if scope["type"] == "websocket":
        protocols = headers.get("sec-websocket-protocol", "")
        for candidate in protocols.split(","):
            candidate = candidate.strip()
            prefix = "privashield.bearer."
            if candidate.startswith(prefix) and len(candidate) > len(prefix):
                return candidate[len(prefix) :]
    return None


async def _http_error(send: Send, status_code: int, detail: str) -> None:
    response = JSONResponse(
        status_code=status_code,
        content={"detail": detail},
        headers={"WWW-Authenticate": "Bearer"} if status_code == 401 else None,
    )
    await response({}, _empty_receive, send)


async def _empty_receive() -> Message:
    return {"type": "http.request", "body": b"", "more_body": False}


class AuthMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        app = scope.get("app")
        if app is None or not hasattr(app.state, "auth_service"):
            await self.app(scope, receive, send)
            return

        auth_service = app.state.auth_service
        authz_policy = app.state.authorization_policy
        path = scope.get("path", "")
        method = scope.get("method", "WEBSOCKET")
        token = _bearer_token(scope)
        principal = await auth_service.authenticate(token)

        allowed = authz_policy.allowed_roles(method, path)
        if allowed is None:
            if principal is None:
                principal = auth_service.disabled_context()
            scope.setdefault("state", {})["principal"] = principal
            await self.app(scope, receive, send)
            return

        if principal is None:
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 4401, "reason": "authentication required"})
            else:
                await _http_error(send, 401, "authentication required")
            return

        try:
            authz_policy.authorize(principal, method, path)
        except AuthorizationError as exc:
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 4403, "reason": "forbidden"})
            else:
                await _http_error(send, 403, str(exc))
            return

        scope.setdefault("state", {})["principal"] = principal
        await self.app(scope, receive, send)
