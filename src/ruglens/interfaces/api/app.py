"""FastAPI application factory and request-body limits."""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ruglens import __version__
from ruglens.core.config import RugLensSettings
from ruglens.interfaces.api.routes import router
from ruglens.orchestrator.engine import AssessmentEngine

logger = logging.getLogger(__name__)


class _PayloadTooLargeError(Exception):
    pass


class BodySizeLimitMiddleware:
    """Reject request bodies above a hard byte limit, including chunked bodies."""

    def __init__(self, app: ASGIApp, *, max_bytes: int = 32_768) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        raw_length = headers.get(b"content-length")
        if raw_length is not None:
            try:
                if int(raw_length) > self.max_bytes:
                    await self._reject(scope, receive, send)
                    return
            except ValueError:
                await self._reject(scope, receive, send, reason="Invalid Content-Length")
                return

        total = 0

        async def limited_receive() -> Message:
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_bytes:
                    raise _PayloadTooLargeError
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _PayloadTooLargeError:
            await self._reject(scope, receive, send)

    @staticmethod
    async def _reject(
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        reason: str = "Request body too large",
    ) -> None:
        response = JSONResponse(
            status_code=413,
            content={"detail": reason},
        )
        await response(scope, receive, send)


def create_app(
    settings: RugLensSettings | None = None,
    *,
    engine: AssessmentEngine | None = None,
) -> FastAPI:
    """Build the FastAPI application.

    Passing an engine is supported for tests and embeddings; the app will not
    close a caller-owned engine.
    """
    resolved = settings or RugLensSettings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> Any:
        app.state.settings = resolved
        app.state.started_at = time.monotonic()
        app.state.assessment_semaphore = asyncio.Semaphore(resolved.api_max_concurrent_assessments)
        owns_engine = engine is None
        if engine is None:
            app.state.engine = await AssessmentEngine.build(resolved)
        else:
            app.state.engine = engine
        try:
            yield
        finally:
            if owns_engine:
                await app.state.engine.close()

    application = FastAPI(
        title="RugLens API",
        version=__version__,
        description=(
            "Evidence-driven EVM token risk assessments. Reports are categorical, "
            "coverage-aware, and pinned to an exact block height."
        ),
        lifespan=lifespan,
    )
    application.state.settings = resolved
    application.state.engine = engine
    application.add_middleware(
        BodySizeLimitMiddleware,
        max_bytes=resolved.api_max_body_bytes,
    )
    application.include_router(router)

    @application.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled API error on %s", request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    return application
