"""Integration tests for /v1/cvss/details error responses.

Pairs with v1.29.2 B1 fix in mcp_server._extract_upstream_message: the
HTTP layer's nested-envelope error must survive the MCP wrapper without
being collapsed to bare "Error 400".
"""

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_cvss_details_v2_vector_helpful_reject():
    r = client.get("/v1/cvss/details", params={"vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P"})
    assert r.status_code == 400
    msg = r.json()["error"]["message"].lower()
    assert "v2" in msg
    assert "v3" in msg


def test_cvss_details_empty_vector_clear_msg():
    r = client.get("/v1/cvss/details", params={"vector": ""})
    assert r.status_code == 400
    msg = r.json()["error"]["message"].lower()
    assert "cvss" in msg


def test_cvss_details_garbage_echoes_safely():
    r = client.get("/v1/cvss/details", params={"vector": "<script>alert(1)</script>"})
    assert r.status_code == 400
    msg = r.json()["error"]["message"]
    assert "<script>" not in msg
    assert "script" in msg.lower()
