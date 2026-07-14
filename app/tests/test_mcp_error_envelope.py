"""Tests for mcp_server._extract_upstream_message — error envelope parsing.

Regression coverage for the post-1.22.2 nested envelope shape
(`{"error": {"code": "...", "message": "..."}}`) which the original implementation
treated as a non-string and silently dropped to `f"Error {status}"`.
"""

import json as json_lib

import httpx
import pytest

pytest.importorskip("mcp", reason="mcp package not installed")
from mcp_server import _extract_upstream_message


def _make_resp(status_code: int, body) -> httpx.Response:
    """Build an httpx.Response with the given status + body (dict / str / None)."""
    if isinstance(body, dict):
        return httpx.Response(
            status_code=status_code,
            content=json_lib.dumps(body).encode(),
            headers={"content-type": "application/json"},
        )
    if body is None:
        return httpx.Response(status_code=status_code, content=b"")
    return httpx.Response(
        status_code=status_code,
        content=body.encode(),
        headers={"content-type": "text/html"},
    )


def test_extract_message_from_nested_error_envelope():
    """Post-1.22.2 envelope: {error: {code, message}} — message should be extracted."""
    resp = _make_resp(
        400,
        {
            "error": {
                "code": "invalid_argument",
                "message": "Private/reserved IP rejected: 192.168.1.1. Public IPs only.",
            }
        },
    )
    assert _extract_upstream_message(resp) == "Private/reserved IP rejected: 192.168.1.1. Public IPs only."


def test_extract_message_legacy_string_envelope():
    """Pre-1.22.2 envelope: {error: 'string'} — backwards compat must still work."""
    resp = _make_resp(400, {"error": "Bad request"})
    assert _extract_upstream_message(resp) == "Bad request"


def test_extract_message_falls_back_to_hint_when_nested_message_empty():
    """404 nested envelope with empty message + hint — hint wins."""
    resp = _make_resp(
        404,
        {
            "error": {"code": "not_found", "message": ""},
            "hint": "Usage: /v1/cve/CVE-2024-3094",
        },
    )
    assert _extract_upstream_message(resp) == "Usage: /v1/cve/CVE-2024-3094"


def test_extract_message_status_fallback_when_unparseable():
    """Non-JSON body → 'Error N' fallback (defensive against HTML error pages)."""
    resp = _make_resp(500, "<html>500 Internal</html>")
    assert _extract_upstream_message(resp) == "Error 500"


class TestNoOpenTelemetryMiddleware:
    """The SDK installs an OTel tracing middleware by default; we opt out.

    Inert today (no exporter installed) but it must not sit in the dispatch
    chain: our own mcp_tools.jsonl is the audit log of record. RequestStateBoundary
    must survive the removal — it owns the request-state codec.
    """

    def test_drop_removes_tracer_and_keeps_request_state(self):
        """Deterministic: build a fresh v2 server and drop directly.

        No app fixture, so this never skips vacuously in an isolated or
        partitioned run. The pre-assert is the canary: if the SDK stops
        seeding a tracer (or renames its module), it fires instead of the
        opt-out quietly becoming a no-op.
        """
        pytest.importorskip("mcp.server.mcpserver", reason="v1 SDK has no middleware list")
        from core.mcp_proxy import _drop_otel_middleware
        from mcp.server.mcpserver import MCPServer

        server = MCPServer("otel-probe")
        seeded = [type(m) for m in server._lowlevel_server.middleware]
        assert any(t.__module__.startswith("mcp.server._otel") for t in seeded), (
            "SDK no longer seeds an OTel tracer — revisit the opt-out"
        )

        _drop_otel_middleware(server)

        kept = [type(m) for m in server._lowlevel_server.middleware]
        assert not any(t.__module__.startswith("mcp.server._otel") for t in kept)
        assert any(t.__name__ == "RequestStateBoundary" for t in kept)

    def test_mounted_instance_has_no_tracer(self):
        """The live mounted server — skips only when MCP isn't loaded at all."""
        from core import mcp_proxy

        mod = mcp_proxy.mcp_module()
        if mod is None or not getattr(mod, "_MCP_SDK_V2", False):
            pytest.skip("v1 SDK has no middleware list")
        names = [type(m).__name__ for m in mod.mcp._lowlevel_server.middleware]
        assert "OpenTelemetryMiddleware" not in names
        assert "RequestStateBoundary" in names
