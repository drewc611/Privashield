from __future__ import annotations

import json
from typing import Annotated, Any

from pydantic import AfterValidator
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MAX_METADATA_BYTES = 16 * 1024


def _check_metadata_size(value: dict[str, Any]) -> dict[str, Any]:
    size = len(json.dumps(value, default=str).encode("utf-8"))
    if size > MAX_METADATA_BYTES:
        raise ValueError(
            f"metadata is {size} bytes when serialized; the limit is {MAX_METADATA_BYTES}"
        )
    return value


BoundedMetadata = Annotated[dict[str, Any], AfterValidator(_check_metadata_size)]


class _BodyTooLarge(Exception):
    pass


class BodySizeLimitMiddleware:
    """Rejects HTTP requests whose body exceeds max_bytes with 413.

    The Content-Length header is checked first so an honest oversized request is
    refused before any body is read. Chunked or understated bodies are counted as
    they stream in.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        for key, value in scope.get("headers", []):
            if key == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = 0
                if declared > self.max_bytes:
                    await self._reject(scope, receive, send)
                    return
                break

        received = 0
        exceeded = False
        response_started = False

        async def counting_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    exceeded = True
                    raise _BodyTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            # Frameworks turn a failed body read into their own 400; once the limit
            # is exceeded that response is dropped and a 413 is sent instead.
            if exceeded:
                return
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _BodyTooLarge:
            pass
        if exceeded and not response_started:
            await self._reject(scope, receive, send)

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse(
            status_code=413,
            content={"detail": f"Request body exceeds {self.max_bytes} bytes."},
        )
        await response(scope, receive, send)
