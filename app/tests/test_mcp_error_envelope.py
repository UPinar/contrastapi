"""Tests for mcp_server._extract_upstream_message — error envelope parsing.

Regression coverage for the post-1.22.2 nested envelope shape
(`{"error": {"code": "...", "message": "..."}}`) which the original implementation
treated as a non-string and silently dropped to `f"Error {status}"`.
"""

import json as json_lib

import httpx
import pytest

mcp_server = pytest.importorskip("mcp_server", reason="mcp_server module not on path")
from mcp_server import _extract_upstream_message  # noqa: E402


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
