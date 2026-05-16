"""Pure ASGI middleware: security headers + per-request lifecycle.

Migrated from BaseHTTPMiddleware (FastAPI @app.middleware decorator) for:
- Cleaner exception propagation (handler chain runs unwrapped)
- Lower per-request overhead (no Request/Response object construction)
- FastAPI/Starlette idiom alignment with _MCPIPForwardMiddleware
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable

from config import KEY_LENGTH, KEY_PREFIX
from starlette.types import ASGIApp, Message, Receive, Scope, Send


def _extract_key_from_scope(scope: Scope) -> str | None:
    """Scope-native equivalent of `auth.extract_key(request)`.

    Reads Authorization (Bearer) then X-API-Key (parity with
    auth.extract_key — no query param / cookie fallback). Used by
    RequestContextMiddleware for the rare nginx-tarpit edge case where
    429 is emitted before the auth path runs.
    """
    bearer_token: str | None = None
    apikey_token: str | None = None
    for name, value in scope.get("headers", ()):
        if name == b"authorization":
            auth = value.decode("latin-1")
            if auth.startswith("Bearer "):
                token = auth[7:].strip()
                if token.startswith(KEY_PREFIX) and len(token) == len(KEY_PREFIX) + KEY_LENGTH:
                    bearer_token = token
        elif name == b"x-api-key":
            token = value.decode("latin-1").strip()
            if token.startswith(KEY_PREFIX) and len(token) == len(KEY_PREFIX) + KEY_LENGTH:
                apikey_token = token
    return bearer_token or apikey_token


class SecurityHeadersMiddleware:
    """Append default security headers when the route did not set them.

    setdefault semantics: respects an upstream value (e.g., a route that
    overrides CSP for a specific page); only fills in the missing ones.
    """

    def __init__(self, app: ASGIApp, headers: dict[str, str]) -> None:
        self.app = app
        # Pre-encode for ASGI byte-list header format. Names lower-cased to
        # match Starlette's emit convention; setdefault check below normalizes
        # message["headers"] defensively.
        self._defaults: list[tuple[bytes, bytes]] = [
            (k.lower().encode("ascii"), v.encode("latin-1")) for k, v in headers.items()
        ]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        defaults = self._defaults

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers: list[tuple[bytes, bytes]] = message.setdefault("headers", [])
                existing = {name.lower() for name, _ in headers}
                for k_lower, v in defaults:
                    if k_lower not in existing:
                        headers.append((k_lower, v))
            await send(message)

        await self.app(scope, receive, send_wrapper)


class RequestContextMiddleware:
    """Per-request lifecycle: request-id, rate-limit headers, access log.

    Reads `scope["state"]["auth"]` populated by `auth.authenticate_sync` (Faz 3)
    via `request.state.auth = ctx` — Starlette exposes scope["state"] as
    request.state bidirectionally, so the AuthCtx stashed before 401/429 raises
    is visible here.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        upgrade_url: str,
        sanitize_path: Callable[[str], str],
        extract_key_fn: Callable[[Scope], str | None],
        record_metric: Callable[[str, int, int], None],
        logger: logging.Logger,
    ) -> None:
        self.app = app
        self.upgrade_url = upgrade_url
        self.sanitize_path = sanitize_path
        self.extract_key_fn = extract_key_fn
        self.record_metric = record_metric
        self.logger = logger

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid.uuid4().hex[:16]
        # FastAPI/Starlette Lifespan State pattern: scope["state"] is exposed
        # as request.state on Request, bidirectional read/write.
        scope.setdefault("state", {})["request_id"] = request_id
        start = time.time()

        # Default 500: if the downstream app raises and no exception handler
        # writes a response, http.response.start never fires. The finally block
        # still logs/records the metric with status=500 in that case.
        status_holder: dict[str, int] = {"code": 500}
        upgrade_url_b = self.upgrade_url.encode("latin-1")
        request_id_b = request_id.encode("ascii")

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_holder["code"] = message["status"]
                headers: list[tuple[bytes, bytes]] = message.setdefault("headers", [])
                headers.append((b"x-request-id", request_id_b))

                auth_ctx = scope["state"].get("auth")
                if auth_ctx is not None:
                    headers.append((b"x-ratelimit-limit", str(auth_ctx.ratelimit_limit).encode("ascii")))
                    headers.append((b"x-ratelimit-remaining", str(auth_ctx.ratelimit_remaining).encode("ascii")))
                    headers.append((b"x-ratelimit-reset", str(auth_ctx.ratelimit_reset).encode("ascii")))
                    headers.append((b"x-ratelimit-tier", auth_ctx.tier.encode("ascii")))
                    headers.append((b"x-ratelimit-cost", str(auth_ctx.ratelimit_cost).encode("ascii")))

                # Upgrade signal: only free-tier 429s. If auth_ctx is None
                # (nginx-tarpit edge: 429 emitted before our auth path), fall
                # back to scope-native extract_key — anonymous gets the CTA.
                if status_holder["code"] == 429:
                    is_free = (auth_ctx is not None and auth_ctx.tier == "free") or (
                        auth_ctx is None and self.extract_key_fn(scope) is None
                    )
                    if is_free:
                        headers.append((b"x-upgrade-url", upgrade_url_b))

            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed = int((time.time() - start) * 1000)
            path = scope.get("path", "")
            safe_path = self.sanitize_path(path)
            self.logger.info(
                "%s %s %s %dms [%s]",
                scope.get("method", ""),
                safe_path,
                status_holder["code"],
                elapsed,
                request_id,
            )
            self.record_metric(path, status_holder["code"], elapsed)
