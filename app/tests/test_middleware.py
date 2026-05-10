"""Faz 5 regression tests for pure ASGI middleware.

Three coverage gaps not covered by the existing 17 header tests in test_main.py:
1. WebSocket / non-HTTP scope passthrough (defensive — no WS endpoints today).
2. Exception-path X-Request-ID emission (500 from a route still gets the header).
3. Security-header setdefault parity (route-set CSP must NOT be overridden).
"""

import asyncio
import logging

import pytest
from fastapi import FastAPI, Response
from fastapi.testclient import TestClient
from middleware import (
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
    _extract_key_from_scope,
)
from starlette.exceptions import HTTPException as StarletteHTTPException


def _noop_metric(path: str, status: int, elapsed_ms: int) -> None:
    pass


def _identity_path(p: str) -> str:
    return p


def _build_test_app() -> FastAPI:
    """Mini FastAPI app with the same middleware stack but no auth/routes from main.py."""
    app = FastAPI()
    app.add_middleware(
        SecurityHeadersMiddleware,
        headers={
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
        },
    )
    app.add_middleware(
        RequestContextMiddleware,
        upgrade_url="https://example.com/upgrade",
        sanitize_path=_identity_path,
        extract_key_fn=_extract_key_from_scope,
        record_metric=_noop_metric,
        logger=logging.getLogger("test_middleware"),
    )

    @app.get("/boom")
    def boom():
        raise StarletteHTTPException(status_code=500, detail="kaboom")

    @app.get("/csp-override")
    def csp_override():
        return Response(
            content="ok",
            media_type="text/plain",
            headers={"Content-Security-Policy": "default-src 'none'"},
        )

    @app.get("/ok")
    def ok():
        return {"status": "ok"}

    return app


class TestWebSocketPassthrough:
    """Non-HTTP scopes (websocket, lifespan) must bypass middleware logic.

    Direct ASGI invocation — sends a minimal websocket scope; middleware should
    forward unchanged without inspecting headers or appending response data.
    """

    def test_security_headers_middleware_websocket_passthrough(self):
        forwarded: list[dict] = []

        async def downstream(scope, receive, send):
            forwarded.append(scope)

        mw = SecurityHeadersMiddleware(downstream, {"X-Frame-Options": "DENY"})

        async def receive():
            return {"type": "websocket.disconnect"}

        async def send(message):
            pass

        ws_scope = {"type": "websocket", "path": "/ws", "headers": []}
        asyncio.run(mw(ws_scope, receive, send))
        assert forwarded == [ws_scope], "websocket scope should pass through unmodified"

    def test_request_context_middleware_websocket_passthrough(self):
        forwarded: list[dict] = []

        async def downstream(scope, receive, send):
            forwarded.append(scope)

        mw = RequestContextMiddleware(
            downstream,
            upgrade_url="https://example.com/upgrade",
            sanitize_path=_identity_path,
            extract_key_fn=_extract_key_from_scope,
            record_metric=_noop_metric,
            logger=logging.getLogger("test_ws"),
        )

        async def receive():
            return {"type": "websocket.disconnect"}

        async def send(message):
            pass

        ws_scope = {"type": "websocket", "path": "/ws", "headers": []}
        asyncio.run(mw(ws_scope, receive, send))
        assert forwarded == [ws_scope]
        # request_id NOT added to websocket scope (would mutate the shared dict).
        assert "state" not in ws_scope or "request_id" not in ws_scope.get("state", {})


class TestExceptionPathRequestId:
    """500 responses must still carry X-Request-ID — exception handler chain
    runs after our middleware's send_wrapper, so the header is appended on the
    handler's http.response.start. This is a parity test against the prior
    BaseHTTPMiddleware behavior.
    """

    def test_500_response_carries_request_id(self):
        app = _build_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        r = client.get("/boom")
        assert r.status_code == 500
        rid = r.headers.get("X-Request-ID")
        assert rid is not None, "X-Request-ID missing on 500 response"
        assert len(rid) == 16, f"X-Request-ID should be 16 hex chars, got {rid!r}"


class TestSecurityHeaderSetdefaultParity:
    """A route that explicitly sets Content-Security-Policy must NOT have it
    overridden by the middleware. setdefault semantics, ASGI port parity with
    the prior `response.headers.setdefault(...)` implementation.
    """

    def test_route_csp_override_preserved(self):
        app = _build_test_app()
        client = TestClient(app)
        r = client.get("/csp-override")
        assert r.status_code == 200
        # Route-set value wins; middleware default must not clobber it.
        assert r.headers.get("Content-Security-Policy") == "default-src 'none'"

    def test_security_headers_added_when_route_silent(self):
        app = _build_test_app()
        client = TestClient(app)
        r = client.get("/ok")
        assert r.status_code == 200
        assert r.headers.get("X-Frame-Options") == "DENY"
        assert r.headers.get("Content-Security-Policy") == "default-src 'self'"


@pytest.mark.parametrize(
    "header_value,expected",
    [
        (b"Bearer cc_" + b"a" * 48, "cc_" + "a" * 48),
        (b"Bearer cc_short", None),
        (b"Basic xxx", None),
        (b"", None),
    ],
)
def test_extract_key_from_scope(header_value, expected):
    """Scope-native parity with auth.extract_key — Authorization header only."""
    scope = {"type": "http", "headers": [(b"authorization", header_value)] if header_value else []}
    assert _extract_key_from_scope(scope) == expected


def test_extract_key_from_scope_no_authorization():
    scope = {"type": "http", "headers": [(b"user-agent", b"curl/8")]}
    assert _extract_key_from_scope(scope) is None
