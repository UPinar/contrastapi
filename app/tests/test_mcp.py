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
    import main

    mod = main._mcp_mod

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
    import main

    mod = main._mcp_mod

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
    import main

    mod = main._mcp_mod

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
    import main

    mod = main._mcp_mod

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
    import main

    mod = main._mcp_mod

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
        upgrade_url="https://contrastcyber.com/pricing",
    )
    detail = exc.to_error_detail()
    assert detail.retry_after_seconds == 60
    assert detail.upgrade_url == "https://contrastcyber.com/pricing"


def test_tier_limit_exception_carries_upgrade_url():
    from app.exceptions import TierLimitException

    exc = TierLimitException("Pro feature", upgrade_url="https://contrastcyber.com/pricing")
    detail = exc.to_error_detail()
    assert detail.code == "tier_limit"
    assert detail.upgrade_url == "https://contrastcyber.com/pricing"


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


def test_mcp_tool_safe_catches_pydantic_validation_error(mcp_client, monkeypatch):
    """Upstream returns a body that does not match the response schema → ErrorResponse,
    not a Pydantic stack trace on the wire. Message is fixed-length, no upstream content."""
    import main

    mod = main._mcp_mod

    async def mock_aget(path, params=None):
        return {"completely": "wrong", "shape": "for cve"}

    monkeypatch.setattr(mod, "_aget", mock_aget)
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


# --- v1.22.0 outputSchema invariant: every tool emits anyOf success+error ---


def test_every_tool_outputschema_is_anyof_union(mcp_client):
    """Each of the 42 tools should declare an outputSchema whose top-level shape
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
    """Plan §Annotation split: 22 closed-world (local DB) + 20 open-world (live) = 42."""
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={"jsonrpc": "2.0", "id": 91, "method": "tools/list", "params": {}},
    )
    tools = r.json()["result"]["tools"]
    closed = [t["name"] for t in tools if (t.get("annotations") or {}).get("openWorldHint") is False]
    open_ = [t["name"] for t in tools if (t.get("annotations") or {}).get("openWorldHint") is True]
    assert len(closed) == 22, f"expected 22 closed-world tools, got {len(closed)}: {closed}"
    assert len(open_) == 20, f"expected 20 open-world tools, got {len(open_)}: {open_}"


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
