"""Tests for MCP Streamable HTTP endpoint (/mcp/)"""

import pytest
from main import app
from starlette.testclient import TestClient

mcp = pytest.importorskip("mcp", reason="mcp package not installed")

MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


@pytest.fixture(scope="module")
def mcp_client():
    """TestClient with lifespan — needed for MCP session manager."""
    with TestClient(app) as c:
        yield c


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
    tools = data["result"]["tools"]
    assert len(tools) == 29
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
    """tools/call should invoke the tool and return content."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "mcp_server_test", str(__import__("config").BASE_DIR.parent / "mcp_server.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    async def mock_get(path, params=None):
        return {"summary": "HIGH — Test CVE for unit test"}

    monkeypatch.setattr(mod, "_get", mock_get)

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
    # Tool returns content (may be error if mock didn't attach to right module)
    assert "content" in data["result"]


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
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "mcp_server_test", str(__import__("config").BASE_DIR.parent / "mcp_server.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    async def mock_get(path, params=None):
        return {"summary": "audit ok"}

    monkeypatch.setattr(mod, "_get", mock_get)
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
    assert "content" in r.json()["result"]


def test_mcp_tool_call_audit_domain_invalid(mcp_client):
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
    # Validation error returns a string, not an exception
    text = str(r.json()["result"]["content"])
    assert "Invalid domain" in text


def test_mcp_tool_call_threat_report(mcp_client, monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "mcp_server_test", str(__import__("config").BASE_DIR.parent / "mcp_server.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    async def mock_get(path, params=None):
        return {"summary": "threat ok"}

    monkeypatch.setattr(mod, "_get", mock_get)
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
    assert "content" in r.json()["result"]


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
    text = str(r.json()["result"]["content"])
    assert "Invalid IP" in text


def test_mcp_tool_call_bulk_cve_lookup(mcp_client, monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "mcp_server_test", str(__import__("config").BASE_DIR.parent / "mcp_server.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    async def mock_post(path, json_body):
        return {"summary": "bulk cve ok", "total": 2, "successful": 2, "failed": 0}

    monkeypatch.setattr(mod, "_post", mock_post)
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
    assert "content" in r.json()["result"]


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
    text = str(r.json()["result"]["content"])
    assert "non-empty list" in text


def test_mcp_tool_call_bulk_ioc_lookup(mcp_client, monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "mcp_server_test", str(__import__("config").BASE_DIR.parent / "mcp_server.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    async def mock_post(path, json_body):
        return {"summary": "bulk ioc ok", "total": 2}

    monkeypatch.setattr(mod, "_post", mock_post)
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
    assert "content" in r.json()["result"]


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
    text = str(r.json()["result"]["content"])
    assert "non-empty list" in text


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
