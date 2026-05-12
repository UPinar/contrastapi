"""Tests for MCP Streamable HTTP endpoint (/mcp/)"""

import pytest

mcp = pytest.importorskip("mcp", reason="mcp package not installed")

MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


# --- Initialize ---


def test_mcp_initialize(mcp_client):
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"},
            },
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["jsonrpc"] == "2.0"
    assert data["id"] == 1
    assert data["result"]["serverInfo"]["name"] == "contrastapi"
    assert "tools" in data["result"]["capabilities"]


# --- Tools list ---


def test_mcp_tools_list(mcp_client):
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        },
    )
    assert r.status_code == 200
    data = r.json()
    from config import MCP_TOOL_COUNT

    tools = data["result"]["tools"]
    assert len(tools) == MCP_TOOL_COUNT
    names = {t["name"] for t in tools}
    assert "domain_report" in names
    assert "cve_lookup" in names
    assert "check_secrets" in names
    # Feature-Gate Phase 1 tools
    assert "audit_domain" in names
    assert "threat_report" in names
    assert "bulk_cve_lookup" in names
    assert "bulk_ioc_lookup" in names


# --- Error handling ---


def test_mcp_missing_accept_header(mcp_client):
    """Middleware normalizes missing Accept header to the canonical value."""
    r = mcp_client.post(
        "/mcp/",
        headers={"Content-Type": "application/json"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"},
            },
        },
    )
    assert r.status_code == 200


def test_mcp_invalid_content_type(mcp_client):
    """Should return 400 for non-JSON Content-Type."""
    r = mcp_client.post(
        "/mcp/",
        headers={"Content-Type": "text/plain", "Accept": "application/json, text/event-stream"},
        content="not json",
    )
    assert r.status_code == 400


def test_mcp_unknown_method(mcp_client):
    """Should return JSON-RPC error for unknown method."""
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 99,
            "method": "nonexistent/method",
            "params": {},
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert "error" in data


# --- Tool schemas ---


def test_mcp_tool_has_input_schema(mcp_client):
    """Every tool should have a proper inputSchema."""
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": {},
        },
    )
    data = r.json()
    for tool in data["result"]["tools"]:
        assert "inputSchema" in tool, f"{tool['name']} missing inputSchema"
        assert tool["inputSchema"]["type"] == "object"


# --- Tool call ---


def test_mcp_tool_call_cve_lookup(mcp_client, monkeypatch):
    """tools/call invokes the tool and returns both text + structuredContent (v1.22.0)."""
    from core import mcp_proxy

    mod = mcp_proxy._mcp_mod

    async def mock_aget(path, params=None):
        return {"cve_id": "CVE-2024-0001", "summary": "HIGH — Test CVE for unit test"}

    monkeypatch.setattr(mod, "_aget", mock_aget)

    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": "cve_lookup", "arguments": {"cve_id": "CVE-2024-0001"}},
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == 10
    # v1.22.0 contract: success path emits both content[0].text (JSON) AND structuredContent (dict).
    assert "content" in data["result"]
    assert "structuredContent" in data["result"]
    sc = data["result"]["structuredContent"]["result"]
    assert sc["cve_id"] == "CVE-2024-0001"
    # text content is the JSON-serialised model (round-trips to the same dict).
    import json as _json

    parsed = _json.loads(data["result"]["content"][0]["text"])
    assert parsed["cve_id"] == "CVE-2024-0001"


def test_mcp_tool_call_whois_lookup_docstring_parity(mcp_client, monkeypatch):
    """whois_lookup docstring 'Returns {...}' field list must match actual response shape.

    Regression guard for schema/response drift: pre-fix, the docstring claimed
    expiration_date + dnssec — both wrong. Real fields are expiry_date + name_servers
    + raw_length, no dnssec. See WhoisInfoEmbedded in app/schemas.py.
    """
    from core import mcp_proxy

    mod = mcp_proxy._mcp_mod

    async def mock_aget(path, params=None):
        return {
            "domain": "example.com",
            "whois": {
                "registrar": "Test Registrar",
                "creation_date": "2020-01-01",
                "expiry_date": "2030-01-01",
                "updated_date": "2024-01-01",
                "name_servers": ["a.iana-servers.net"],
                "status": ["clientTransferProhibited"],
                "raw_length": 500,
                "error": None,
            },
            "summary": "example.com — Test Registrar — expires 2030-01-01",
        }

    monkeypatch.setattr(mod, "_aget", mock_aget)

    listing = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={"jsonrpc": "2.0", "id": 50, "method": "tools/list", "params": {}},
    ).json()
    whois_tool = next(t for t in listing["result"]["tools"] if t["name"] == "whois_lookup")
    desc = whois_tool["description"]
    assert "expiry_date" in desc, "docstring must advertise the real field name"
    assert "expiration_date" not in desc, "stale field name must not reappear"
    assert "dnssec" not in desc.lower(), "dnssec is not implemented; do not advertise it"

    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 51,
            "method": "tools/call",
            "params": {"name": "whois_lookup", "arguments": {"domain": "example.com"}},
        },
    )
    assert r.status_code == 200
    sc = r.json()["result"]["structuredContent"]["result"]
    whois = sc["whois"]
    assert "expiry_date" in whois
    assert "expiration_date" not in whois
    assert "dnssec" not in whois
    assert whois["expiry_date"] == "2030-01-01"


def test_mcp_tool_call_nonexistent_tool(mcp_client):
    """Calling a non-existent tool should return isError=true."""
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "no_such_tool", "arguments": {}},
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["result"]["isError"] is True


# --- Feature-Gate Phase 1 tool calls ---


def test_mcp_tool_call_audit_domain(mcp_client, monkeypatch):
    from core import mcp_proxy

    mod = mcp_proxy._mcp_mod

    async def mock_aget(path, params=None):
        return {"domain": "example.com", "summary": "audit ok"}

    monkeypatch.setattr(mod, "_aget", mock_aget)
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {"name": "audit_domain", "arguments": {"domain": "example.com"}},
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert "structuredContent" in data["result"]
    assert data["result"]["structuredContent"]["result"]["domain"] == "example.com"


def test_mcp_tool_call_audit_domain_invalid(mcp_client):
    """v1.22.0: validation errors surface as ErrorResponse with code='invalid_argument'."""
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {"name": "audit_domain", "arguments": {"domain": "not_a_domain"}},
        },
    )
    assert r.status_code == 200
    sc = r.json()["result"]["structuredContent"]["result"]
    assert sc["error"]["code"] == "invalid_argument"
    assert "Invalid domain" in sc["error"]["message"]


def test_mcp_tool_call_threat_report(mcp_client, monkeypatch):
    from core import mcp_proxy

    mod = mcp_proxy._mcp_mod

    async def mock_aget(path, params=None):
        return {"ip": "8.8.8.8", "summary": "threat ok"}

    monkeypatch.setattr(mod, "_aget", mock_aget)
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 22,
            "method": "tools/call",
            "params": {"name": "threat_report", "arguments": {"ip": "8.8.8.8"}},
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert "structuredContent" in data["result"]
    assert data["result"]["structuredContent"]["result"]["ip"] == "8.8.8.8"


def test_mcp_tool_call_threat_report_invalid_ip(mcp_client):
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 23,
            "method": "tools/call",
            "params": {"name": "threat_report", "arguments": {"ip": "not_an_ip"}},
        },
    )
    assert r.status_code == 200
    sc = r.json()["result"]["structuredContent"]["result"]
    assert sc["error"]["code"] == "invalid_argument"
    assert "Invalid IP" in sc["error"]["message"]


def test_mcp_tool_call_bulk_cve_lookup(mcp_client, monkeypatch):
    from core import mcp_proxy

    mod = mcp_proxy._mcp_mod

    async def mock_apost(path, json_body, params=None):
        return {"total": 2, "successful": 2, "failed": 0, "summary": "bulk cve ok"}

    monkeypatch.setattr(mod, "_apost", mock_apost)
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 24,
            "method": "tools/call",
            "params": {
                "name": "bulk_cve_lookup",
                "arguments": {"cve_ids": ["CVE-2024-0001", "CVE-2024-0002"]},
            },
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert "structuredContent" in data["result"]
    assert data["result"]["structuredContent"]["result"]["total"] == 2


def test_mcp_tool_call_bulk_cve_lookup_empty(mcp_client):
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 25,
            "method": "tools/call",
            "params": {"name": "bulk_cve_lookup", "arguments": {"cve_ids": []}},
        },
    )
    assert r.status_code == 200
    sc = r.json()["result"]["structuredContent"]["result"]
    assert sc["error"]["code"] == "invalid_argument"
    assert "non-empty list" in sc["error"]["message"]


def test_mcp_tool_call_bulk_ioc_lookup(mcp_client, monkeypatch):
    from core import mcp_proxy

    mod = mcp_proxy._mcp_mod

    async def mock_apost(path, json_body, params=None):
        return {"total": 2, "successful": 2, "failed": 0}

    monkeypatch.setattr(mod, "_apost", mock_apost)
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 26,
            "method": "tools/call",
            "params": {
                "name": "bulk_ioc_lookup",
                "arguments": {"indicators": ["8.8.8.8", "evil.com"]},
            },
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert "structuredContent" in data["result"]
    assert data["result"]["structuredContent"]["result"]["total"] == 2


def test_mcp_tool_call_bulk_ioc_lookup_empty(mcp_client):
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 27,
            "method": "tools/call",
            "params": {"name": "bulk_ioc_lookup", "arguments": {"indicators": []}},
        },
    )
    assert r.status_code == 200
    sc = r.json()["result"]["structuredContent"]["result"]
    assert sc["error"]["code"] == "invalid_argument"
    assert "non-empty list" in sc["error"]["message"]


# --- Docs mention MCP ---


def test_llms_txt_mentions_mcp(mcp_client):
    """llms.txt should document MCP endpoint."""
    r = mcp_client.get("/llms.txt")
    assert r.status_code == 200
    assert "MCP" in r.text
    assert "/mcp/" in r.text


# --- Accept header normalization (Chiark.ai probe compatibility) ---


def test_mcp_initialize_without_accept_header(mcp_client):
    r = mcp_client.post(
        "/mcp/",
        headers={"Content-Type": "application/json"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"},
            },
        },
    )
    assert r.status_code == 200
    assert r.json()["result"]["serverInfo"]["name"] == "contrastapi"


def test_mcp_initialize_with_wildcard_accept(mcp_client):
    r = mcp_client.post(
        "/mcp/",
        headers={"Content-Type": "application/json", "Accept": "*/*"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"},
            },
        },
    )
    assert r.status_code == 200


def test_mcp_get_returns_health(mcp_client):
    """GET /mcp/ returns a health JSON for crawlers and availability checks."""
    from config import MCP_TOOL_COUNT

    r = mcp_client.get("/mcp/")
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "ContrastAPI MCP Server"
    assert data["transport"] == "streamable-http"
    assert data["method"] == "POST"
    assert data["tools"] == MCP_TOOL_COUNT


def test_mcp_get_health_shape_for_nginx_split(mcp_client):
    """GET /mcp/ must return a complete buffered JSON response (Content-Length present).
    This pins the 'synchronous JSON health' contract that justifies the generous GET rate limit.
    A streaming response would drop Content-Length and break the nginx zone assumption."""
    from config import MCP_TOOL_COUNT

    r = mcp_client.get("/mcp/")
    assert r.status_code == 200
    assert "content-length" in r.headers, "Response must be buffered (Content-Length absent implies streaming)"
    assert r.headers.get("vary") == "Accept"
    data = r.json()
    assert data["name"] == "ContrastAPI MCP Server"
    assert data["transport"] == "streamable-http"
    assert data["method"] == "POST"
    assert data["tools"] == MCP_TOOL_COUNT


def test_mcp_get_no_trailing_slash_returns_health(mcp_client):
    """GET /mcp (no slash) — FastAPI may 307 redirect to /mcp/, TestClient follows."""
    from config import MCP_TOOL_COUNT

    r = mcp_client.get("/mcp")
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "ContrastAPI MCP Server"
    assert data["tools"] == MCP_TOOL_COUNT


def test_mcp_get_sse_accept_returns_retry_frame(mcp_client):
    """GET /mcp/ with Accept: text/event-stream returns an SSE priming frame
    with retry: 15000 — tells spec-compliant SSE clients (undici, EventSource)
    to wait 15s between reconnect attempts instead of the default 3s.
    Cuts undici-driven GET /mcp/ surge ~80%."""
    r = mcp_client.get("/mcp/", headers={"Accept": "text/event-stream"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "text/event-stream"
    assert r.headers.get("cache-control") == "no-cache"
    assert r.headers.get("x-mcp-keepalive-interval") == "15"
    assert r.headers.get("vary") == "Accept"
    assert r.text == "retry: 15000\n\n"


def test_mcp_get_sse_accept_no_trailing_slash(mcp_client):
    """GET /mcp (no trailing slash) with SSE Accept also returns the retry frame —
    FastAPI 307-redirects to /mcp/, TestClient follows."""
    r = mcp_client.get("/mcp", headers={"Accept": "text/event-stream"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "text/event-stream"
    assert "retry: 15000" in r.text


# --- /mcp.json discovery manifest (root-level alias) ---


def test_mcp_json_manifest_returns_server_card(mcp_client):
    """GET /mcp.json calls mcp_server_card() (same as /.well-known/mcp.json and /.well-known/mcp-server.json).
    Discovery crawlers (NotHumanSearch, TacaraBot, AgentSEO) probe this root-level path."""
    r = mcp_client.get("/mcp.json")
    assert r.status_code == 200
    data = r.json()
    assert data["serverInfo"]["name"] == "contrastapi"
    assert data["transport"][0]["type"] == "streamable-http"
    assert data["transport"][0]["url"].endswith("/mcp/")
    assert data["capabilities"]["tools"] is True


def test_mcp_json_equivalent_to_well_known_alias(mcp_client):
    """GET /mcp.json, /.well-known/mcp.json, and /.well-known/mcp-server.json return identical content
    (all three call mcp_server_card())."""
    r1 = mcp_client.get("/mcp.json")
    r2 = mcp_client.get("/.well-known/mcp.json")
    r3 = mcp_client.get("/.well-known/mcp-server.json")
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 200
    assert r1.json() == r2.json() == r3.json()


def test_mcp_server_card_has_cache_control_header(mcp_client):
    """CF edge cache: /.well-known/mcp/server-card.json deterministic, 10min TTL."""
    r = mcp_client.get("/.well-known/mcp/server-card.json")
    assert r.status_code == 200
    assert r.headers.get("cache-control") == "public, max-age=600"


def test_mcp_json_aliases_share_cache_control(mcp_client):
    """CF edge cache: /mcp.json + /.well-known/mcp.json + /.well-known/mcp-server.json carry same Cache-Control."""
    for path in ("/mcp.json", "/.well-known/mcp.json", "/.well-known/mcp-server.json"):
        r = mcp_client.get(path)
        assert r.status_code == 200, f"{path} not 200"
        assert r.headers.get("cache-control") == "public, max-age=600", f"{path} missing cache-control"


def test_mcp_get_static_info_has_cache_control_header(mcp_client):
    """CF edge cache: GET /mcp/ static server-info JSON, 5min TTL."""
    r = mcp_client.get("/mcp/")
    assert r.status_code == 200
    assert r.headers.get("cache-control") == "public, max-age=300"


def test_mcp_json_content_type_is_json(mcp_client):
    """GET /mcp.json must advertise application/json for strict discovery crawlers."""
    r = mcp_client.get("/mcp.json")
    assert r.status_code == 200
    assert "application/json" in r.headers.get("content-type", "")


# --- v1.22.0 exception hierarchy round-trip ---


def test_app_exception_to_error_detail_round_trip():
    """Each AppException subclass converts to ErrorDetail with the right code."""
    from app.exceptions import (
        AuthRequiredException,
        InvalidArgumentException,
        InvalidCveIdException,
        InvalidDomainException,
        InvalidHashException,
        InvalidIpException,
        NotFoundException,
        RateLimitExceededException,
        TierLimitException,
        UpstreamErrorException,
        UpstreamTimeoutException,
    )

    cases = [
        (InvalidArgumentException("bad arg"), "invalid_argument", 400),
        (InvalidCveIdException("bad cve"), "invalid_argument", 400),
        (InvalidDomainException("bad domain"), "invalid_argument", 400),
        (InvalidIpException("bad ip"), "invalid_argument", 400),
        (InvalidHashException("bad hash"), "invalid_argument", 400),
        (NotFoundException("missing"), "not_found", 404),
        (RateLimitExceededException("slow down"), "rate_limit_exceeded", 429),
        (AuthRequiredException("login"), "auth_required", 401),
        (TierLimitException("upgrade"), "tier_limit", 403),
        (UpstreamTimeoutException("slow upstream"), "upstream_timeout", 504),
        (UpstreamErrorException("upstream broke"), "upstream_error", 502),
    ]
    for exc, expected_code, expected_status in cases:
        assert exc.code == expected_code, f"{type(exc).__name__}: code mismatch"
        assert exc.status_code == expected_status, f"{type(exc).__name__}: status mismatch"
        detail = exc.to_error_detail()
        assert detail.code == expected_code
        assert detail.message == exc.message


def test_rate_limit_exception_carries_retry_and_upgrade():
    from app.exceptions import RateLimitExceededException

    exc = RateLimitExceededException(
        "rate limited",
        retry_after=60,
        upgrade_url="https://api.contrastcyber.com/pricing",
    )
    detail = exc.to_error_detail()
    assert detail.retry_after_seconds == 60
    assert detail.upgrade_url == "https://api.contrastcyber.com/pricing"


def test_tier_limit_exception_carries_upgrade_url():
    from app.exceptions import TierLimitException

    exc = TierLimitException("Pro feature", upgrade_url="https://api.contrastcyber.com/pricing")
    detail = exc.to_error_detail()
    assert detail.code == "tier_limit"
    assert detail.upgrade_url == "https://api.contrastcyber.com/pricing"


def test_app_exception_keyword_only_kwargs_enforced():
    """retry_after / upgrade_url / docs_url MUST be passed by keyword."""
    from app.exceptions import RateLimitExceededException

    with pytest.raises(TypeError):
        RateLimitExceededException("rate limited", 60)


# --- v1.22.0 mcp_tool_safe wrapper behaviour ---


def test_mcp_tool_safe_catches_app_exception(mcp_client):
    """validation error in a tool body becomes an ErrorResponse on the wire."""
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 80,
            "method": "tools/call",
            "params": {"name": "cve_lookup", "arguments": {"cve_id": "not-a-cve"}},
        },
    )
    assert r.status_code == 200
    sc = r.json()["result"]["structuredContent"]["result"]
    assert sc["error"]["code"] == "invalid_argument"
    assert "Invalid CVE" in sc["error"]["message"]


def test_mcp_tool_safe_catches_pydantic_validation_error(mcp_client, monkeypatch, caplog):
    """Upstream returns a body that does not match the response schema → ErrorResponse,
    not a Pydantic stack trace on the wire. Message is fixed-length, no upstream content
    leaks to wire OR to logs (regression guard for the v1.22 round-2 log-injection fix)."""
    import logging

    from core import mcp_proxy

    mod = mcp_proxy._mcp_mod

    async def mock_aget(path, params=None):
        # Distinctive marker keys/values; if any of these reach logs we have a
        # log-injection regression (raw ValidationError leaked into logger.warning).
        return {"completely": "wrong-leaky-marker", "shape": "for cve-leaky-marker"}

    monkeypatch.setattr(mod, "_aget", mock_aget)
    with caplog.at_level(logging.WARNING, logger="contrastapi.mcp"):
        r = mcp_client.post(
            "/mcp/",
            headers=MCP_HEADERS,
            json={
                "jsonrpc": "2.0",
                "id": 81,
                "method": "tools/call",
                "params": {"name": "cve_lookup", "arguments": {"cve_id": "CVE-2024-0001"}},
            },
        )
    assert r.status_code == 200
    sc = r.json()["result"]["structuredContent"]["result"]
    assert sc["error"]["code"] == "upstream_error"
    assert sc["error"]["message"] == "Upstream response validation failed"
    # Wire response carries NO upstream-controlled keys / values.
    body_text = r.text
    assert "leaky-marker" not in body_text, "upstream payload leaked to MCP wire"
    assert "completely" not in body_text, "upstream key leaked to MCP wire"
    # Logs carry the tool name only — no Pydantic ValidationError content.
    full_log = caplog.text
    assert "leaky-marker" not in full_log, "upstream payload leaked into log line"
    assert "completely" not in full_log, "upstream key leaked into log line"
    # Sanity: the warning DID fire and identifies which tool failed.
    assert any("cve_lookup" in r.message for r in caplog.records), "expected schema-validation warning for cve_lookup"


# --- v1.22.0 outputSchema invariant: every tool emits anyOf success+error ---


def test_every_tool_outputschema_is_anyof_union(mcp_client):
    """Each of the MCP_TOOL_COUNT tools should declare an outputSchema whose top-level shape
    is a Union of its specific response model and ErrorResponse, so MCP clients
    can validate either arm structurally."""
    from config import MCP_TOOL_COUNT

    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={"jsonrpc": "2.0", "id": 90, "method": "tools/list", "params": {}},
    )
    tools = r.json()["result"]["tools"]
    assert len(tools) == MCP_TOOL_COUNT
    missing = []
    not_anyof = []
    for t in tools:
        out = t.get("outputSchema") or {}
        if not out:
            missing.append(t["name"])
            continue
        defs = out.get("$defs") or {}
        if "ErrorResponse" not in defs and "ErrorResponse" not in str(out):
            not_anyof.append(t["name"])
    assert not missing, f"tools missing outputSchema: {missing}"
    assert not not_anyof, f"tools without ErrorResponse arm in outputSchema: {not_anyof}"


def test_closed_vs_open_world_split(mcp_client):
    """Plan §Annotation split: 24 closed-world (local DB) + 25 open-world (live) = 49."""
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={"jsonrpc": "2.0", "id": 91, "method": "tools/list", "params": {}},
    )
    tools = r.json()["result"]["tools"]
    closed = [t["name"] for t in tools if (t.get("annotations") or {}).get("openWorldHint") is False]
    open_ = [t["name"] for t in tools if (t.get("annotations") or {}).get("openWorldHint") is True]
    assert len(closed) == 24, f"expected 24 closed-world tools, got {len(closed)}: {closed}"
    assert len(open_) == 25, f"expected 25 open-world tools, got {len(open_)}: {open_}"


# --- v1.22.0 bulk length cap (defense-in-depth alongside Pydantic max_length=50) ---


def test_bulk_cve_lookup_rejects_oversized_list(mcp_client):
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 100,
            "method": "tools/call",
            "params": {"name": "bulk_cve_lookup", "arguments": {"cve_ids": ["CVE-2024-0001"] * 51}},
        },
    )
    assert r.status_code == 200
    sc = r.json()["result"]["structuredContent"]["result"]
    assert sc["error"]["code"] == "invalid_argument"
    assert "max 50" in sc["error"]["message"]


def test_bulk_ioc_lookup_rejects_oversized_list(mcp_client):
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {"name": "bulk_ioc_lookup", "arguments": {"indicators": ["8.8.8.8"] * 51}},
        },
    )
    assert r.status_code == 200
    sc = r.json()["result"]["structuredContent"]["result"]
    assert sc["error"]["code"] == "invalid_argument"
    assert "max 50" in sc["error"]["message"]


def test_bulk_atlas_technique_lookup_rejects_oversized_list(mcp_client):
    """Parity guard for the third bulk tool. NOTE: bulk_atlas_technique_lookup
    declares Field(max_length=50) on the technique_ids parameter, so FastMCP
    rejects oversized input at the schema layer BEFORE the body's defensive
    `if len(...) > 50` check ever runs — wire shape is `isError: true` with a
    text-only content block (not the structured ErrorResponse path the
    cve/ioc bulk variants take). Both layers are valid defense; this test
    pins the schema-layer rejection so a future drop of max_length wouldn't
    silently accept oversized input."""
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 102,
            "method": "tools/call",
            "params": {
                "name": "bulk_atlas_technique_lookup",
                "arguments": {"technique_ids": ["AML.T0051"] * 51},
            },
        },
    )
    assert r.status_code == 200
    result = r.json()["result"]
    assert result.get("isError") is True, "expected schema-layer rejection (isError=true)"
    text = result["content"][0]["text"]
    assert "too_long" in text or "at most 50" in text, f"expected schema-layer cap message, got: {text!r}"


# --- v1.22.0 regression guards for review-flagged invariants ---


def test_asn_lookup_error_preserves_original_user_input(mcp_client):
    """Round-1 fix: when neither validator accepts the target, the InvalidArgumentException
    message echoes the user's literal input (after .strip()) — NOT the partially-normalized
    form a failed validator would produce. Catches regressions that re-shadow `target` before
    the exception path runs."""
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 110,
            "method": "tools/call",
            "params": {"name": "asn_lookup", "arguments": {"target": "NOT_A_THING.@@@"}},
        },
    )
    assert r.status_code == 200
    sc = r.json()["result"]["structuredContent"]["result"]
    assert sc["error"]["code"] == "invalid_argument"
    # The literal user input must appear verbatim in the error message.
    assert "NOT_A_THING.@@@" in sc["error"]["message"], (
        f"original user input lost in error message: {sc['error']['message']!r}"
    )


def test_error_detail_message_max_length_enforced():
    """ErrorDetail.message has max_length=500 (Pydantic constraint). Regression guard:
    if a future patch drops the constraint, an oversized AppException message could
    bloat the wire / re-trigger ValidationError inside the mcp_tool_safe handler."""
    import pytest as _pytest
    from pydantic import ValidationError as _VE

    from app.schemas import ErrorDetail

    # 500-char message OK, 501-char rejected.
    ErrorDetail(code="upstream_error", message="x" * 500)
    with _pytest.raises(_VE):
        ErrorDetail(code="upstream_error", message="x" * 501)


def test_pivot_hint_tool_literal_covers_full_catalog():
    """PivotHint.tool is a Literal[...] of every legitimate MCP tool name. If a new
    tool is added to mcp_server.py without expanding the Literal, any pivot-hint
    generator that names that tool will raise ValidationError at runtime, silently
    breaking next_calls emission. This test fails loudly on drift."""
    import typing

    from config import MCP_TOOL_COUNT

    from app.schemas import PivotHint

    literal_args = typing.get_args(PivotHint.model_fields["tool"].annotation)
    assert len(literal_args) == MCP_TOOL_COUNT, (
        f"PivotHint.tool Literal has {len(literal_args)} entries but config.MCP_TOOL_COUNT "
        f"is {MCP_TOOL_COUNT}. Run /toolup or expand the Literal in app/schemas.py."
    )


def test_http_error_to_app_exception_caps_retry_after_at_3600():
    """B-hotfix invariant: a hostile/buggy upstream returning Retry-After: 999999999999
    must NOT propagate verbatim into ErrorDetail.retry_after_seconds (would trick
    agents that respect the value literally into multi-year backoffs). Cap is 3600s
    (1h); negatives clamp to 0. In-range values pass through."""
    import httpx

    from app.exceptions import RateLimitExceededException
    from mcp_server import _http_error_to_app_exception

    def mock_resp(status, headers=None):
        req = httpx.Request("GET", "http://x")
        return httpx.Response(status, json={"error": "rate limited"}, headers=headers or {}, request=req)

    cases = [
        ({"retry-after": "999999999999"}, 3600),  # absurd upstream → capped
        ({"retry-after": "120"}, 120),  # in range → unchanged
        ({"retry-after": "-50"}, 0),  # negative → clamped
        ({"retry-after": "garbage"}, 60),  # parse failure → default 60
        ({}, 60),  # header absent → default 60
    ]
    for headers, expected in cases:
        exc = _http_error_to_app_exception(mock_resp(429, headers))
        assert isinstance(exc, RateLimitExceededException), f"headers={headers!r} unexpected type"
        assert exc.retry_after == expected, f"headers={headers!r} expected {expected} got {exc.retry_after}"


def test_require_public_ip_rejects_unspecified_addresses():
    """B-hotfix SSRF guard parity: `_require_public_ip` must reject 0.0.0.0 and ::
    (unspecified) in addition to private/loopback/reserved/link-local/multicast.
    Used by threat_report which feeds the IP into Shodan + AbuseIPDB; an unspecified
    IP routes to the local interface in many backends — open SSRF if accepted."""
    from app.exceptions import InvalidIpException
    from mcp_server import _require_public_ip

    # Reject — unspecified
    for ip in ("0.0.0.0", "::"):
        with pytest.raises(InvalidIpException):
            _require_public_ip(ip)

    # Reject — already-covered guards (sanity that we didn't break them)
    for ip in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1"):
        with pytest.raises(InvalidIpException):
            _require_public_ip(ip)

    # Accept — global routables
    for ip in ("8.8.8.8", "1.1.1.1", "2606:4700::1111"):
        assert _require_public_ip(ip) == ip


# --- B4b v1.30.0: structured audit log + sanitize allowlist ---


class TestMcpToolAuditLog:
    """Sanitize allowlist + new ISO-timestamp shape for mcp_tools.jsonl."""

    def test_extract_tool_call_returns_name_and_sanitized_params(self):
        import json as _json

        from core.mcp_proxy import _extract_tool_call

        body = _json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "cve_search",
                    "arguments": {
                        "severity": "HIGH",  # metadata — kept
                        "kev": True,  # metadata — kept
                        "cve_id": "CVE-2021-44228",  # PII (query content) — dropped
                        "include_full_references": True,  # not allowlisted — dropped
                    },
                },
            }
        ).encode()
        extracted = _extract_tool_call(body)
        assert extracted is not None
        name, params = extracted
        assert name == "cve_search"
        assert params == {"severity": "HIGH", "kev": True}

    def test_extract_tool_call_redacts_secret_keys(self):
        import json as _json

        from core.mcp_proxy import _extract_tool_call

        body = _json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "domain_report",
                    "arguments": {
                        "domain": "example.com",  # PII (target) — dropped
                        "lite": True,  # metadata variant — kept
                        "Authorization": "Bearer leaked-token-xyz",
                        "api_key": "sk-secret-123",
                        "password": "hunter2",
                    },
                },
            }
        ).encode()
        extracted = _extract_tool_call(body)
        assert extracted is not None
        _, params = extracted
        assert params == {"lite": True}

    def test_extract_tool_call_truncates_oversized_string_values(self):
        import json as _json

        from core.mcp_proxy import _TOOL_PARAM_VALUE_MAX_LEN, _extract_tool_call

        big = "A" * 5000
        body = _json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "cve_search", "arguments": {"sort": big}},
            }
        ).encode()
        extracted = _extract_tool_call(body)
        assert extracted is not None
        _, params = extracted
        assert len(params["sort"]) == _TOOL_PARAM_VALUE_MAX_LEN

    def test_log_mcp_tool_writes_iso_timestamp_and_params(self, tmp_path, monkeypatch):
        import json as _json
        from datetime import datetime as _dt

        from core import mcp_proxy

        log_path = tmp_path / "mcp_tools.jsonl"
        monkeypatch.setattr(mcp_proxy, "_MCP_TOOL_LOG", str(log_path))
        mcp_proxy._log_mcp_tool("cve_search", {"severity": "HIGH", "kev": True})
        line = log_path.read_text().strip()
        record = _json.loads(line)
        assert record["tool"] == "cve_search"
        assert record["params"] == {"severity": "HIGH", "kev": True}
        # ISO 8601 with millisecond precision and explicit Z timezone
        ts = record["ts"]
        assert ts.endswith("Z")
        # parseable as a datetime
        _dt.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")

    def test_log_mcp_tool_omits_params_when_empty(self, tmp_path, monkeypatch):
        import json as _json

        from core import mcp_proxy

        log_path = tmp_path / "mcp_tools.jsonl"
        monkeypatch.setattr(mcp_proxy, "_MCP_TOOL_LOG", str(log_path))
        mcp_proxy._log_mcp_tool("kev_detail", {})
        record = _json.loads(log_path.read_text().strip())
        assert "params" not in record  # empty params dropped, keeps log compact
