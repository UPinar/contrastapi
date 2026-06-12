"""MCP-side integration tests for sigma_rule_lookup + bulk_sigma_rule_lookup tools."""

import pytest
from tests.conftest import mcp_error_payload

mcp = pytest.importorskip("mcp", reason="mcp package not installed")

MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}

_SAMPLE_RULE = {
    "rule_id": "195e1b9d-bfc2-4ffa-ab4e-35aef69815f8",
    "title": "Suspicious Process Creation - Powershell",
    "status": "stable",
    "level": "high",
    "description": "Detects suspicious powershell invocation.",
    "author": "Florian Roth",
    "logsource": {"product": "windows", "category": "process_creation"},
    "detection": {"selection": {"Image": "powershell.exe"}, "condition": "selection"},
    "tags": ["attack.t1059"],
    "references": [],
    "date": None,
    "date_modified": None,
    "falsepositives": [],
}


# --- tools/list contains both new sigma tools ---


def test_mcp_tools_list_includes_sigma_tools(mcp_client):
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={"jsonrpc": "2.0", "id": 100, "method": "tools/list", "params": {}},
    )
    assert r.status_code == 200
    names = {t["name"] for t in r.json()["result"]["tools"]}
    assert "sigma_rule_lookup" in names
    assert "bulk_sigma_rule_lookup" in names


def test_mcp_tools_list_count_bumped_to_54(mcp_client):
    """MCP_TOOL_COUNT bumped 53 → 54 after Faz-2: contrast_scan (website scanner)."""
    from config import MCP_TOOL_COUNT

    assert MCP_TOOL_COUNT == 54
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={"jsonrpc": "2.0", "id": 101, "method": "tools/list", "params": {}},
    )
    tools = r.json()["result"]["tools"]
    assert len(tools) == MCP_TOOL_COUNT


# --- tools/call sigma_rule_lookup ---


def test_mcp_tool_call_sigma_rule_lookup(mcp_client, monkeypatch):
    from core import mcp_proxy

    mod = mcp_proxy._mcp_mod

    async def mock_aget(path, params=None):
        assert path == "/v1/sigma/195e1b9d-bfc2-4ffa-ab4e-35aef69815f8"
        return {"rule": _SAMPLE_RULE, "next_calls": None}

    monkeypatch.setattr(mod, "_aget", mock_aget)
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 110,
            "method": "tools/call",
            "params": {
                "name": "sigma_rule_lookup",
                "arguments": {"rule_id": "195e1b9d-bfc2-4ffa-ab4e-35aef69815f8"},
            },
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["result"].get("isError") is not True
    sc = data["result"]["structuredContent"]["result"]
    assert sc["rule"]["rule_id"] == "195e1b9d-bfc2-4ffa-ab4e-35aef69815f8"
    assert sc["rule"]["title"] == "Suspicious Process Creation - Powershell"


def test_mcp_tool_call_sigma_rule_lookup_rejects_invalid_uuid(mcp_client):
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 111,
            "method": "tools/call",
            "params": {
                "name": "sigma_rule_lookup",
                "arguments": {"rule_id": "not-a-uuid"},
            },
        },
    )
    assert r.status_code == 200
    err = mcp_error_payload(r)["error"]
    assert err["code"] == "invalid_argument"
    assert "UUID" in err["message"]


# --- tools/call bulk_sigma_rule_lookup ---


def test_mcp_tool_call_bulk_sigma_rule_lookup(mcp_client, monkeypatch):
    from core import mcp_proxy

    mod = mcp_proxy._mcp_mod

    async def mock_apost(path, json_body, params=None):
        assert path == "/v1/sigma/bulk"
        assert json_body == {"rule_ids": ["195e1b9d-bfc2-4ffa-ab4e-35aef69815f8"]}
        return {
            "results": [
                {"rule_id": "195e1b9d-bfc2-4ffa-ab4e-35aef69815f8", "status": "ok", "rule": _SAMPLE_RULE, "error": None}
            ],
            "total": 1,
            "successful": 1,
            "failed": 0,
            "partial": False,
            "summary": "1/1 rules found",
            "next_calls": None,
        }

    monkeypatch.setattr(mod, "_apost", mock_apost)
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 120,
            "method": "tools/call",
            "params": {
                "name": "bulk_sigma_rule_lookup",
                "arguments": {"rule_ids": ["195e1b9d-bfc2-4ffa-ab4e-35aef69815f8"]},
            },
        },
    )
    assert r.status_code == 200
    sc = r.json()["result"]["structuredContent"]["result"]
    assert sc["total"] == 1
    assert sc["successful"] == 1
    assert sc["results"][0]["rule_id"] == "195e1b9d-bfc2-4ffa-ab4e-35aef69815f8"


def test_mcp_tool_call_bulk_sigma_rejects_empty(mcp_client):
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 121,
            "method": "tools/call",
            "params": {"name": "bulk_sigma_rule_lookup", "arguments": {"rule_ids": []}},
        },
    )
    assert r.status_code == 200
    err = mcp_error_payload(r)["error"]
    assert err["code"] == "invalid_argument"
    assert "non-empty list" in err["message"]


def test_mcp_tool_call_bulk_sigma_rejects_oversize(mcp_client):
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 122,
            "method": "tools/call",
            "params": {
                "name": "bulk_sigma_rule_lookup",
                "arguments": {"rule_ids": ["00000000-0000-0000-0000-000000000000"] * 51},
            },
        },
    )
    assert r.status_code == 200
    assert r.json()["result"]["isError"] is True
