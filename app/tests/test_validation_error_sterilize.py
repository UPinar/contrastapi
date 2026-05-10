"""Test that MCP tool argument validation strips Pydantic version leakage.

FastMCP's default ValidationError handling appends
'For further information visit https://errors.pydantic.dev/2.12/v/<code>'
to the error text — exposes the Pydantic minor version (CWE-200).
mcp_tool_safe must catch input validation errors and sterilize the message.
"""

import pytest

mcp = pytest.importorskip("mcp", reason="mcp package not installed")

MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


def _initialize(mcp_client):
    mcp_client.post(
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
    mcp_client.post("/mcp/", headers=MCP_HEADERS, json={"jsonrpc": "2.0", "method": "notifications/initialized"})


def test_mcp_tool_input_validation_no_pydantic_url_leak(mcp_client):
    """Wrong argument name must not leak 'pydantic.dev/2.X' link."""
    _initialize(mcp_client)
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "ip_lookup", "arguments": {"target": "8.8.8.8"}},
        },
    )
    assert r.status_code == 200
    body_text = r.text
    assert "pydantic.dev" not in body_text
    assert "For further information visit" not in body_text
