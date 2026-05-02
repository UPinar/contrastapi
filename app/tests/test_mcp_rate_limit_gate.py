"""Tests for the /mcp/ app-layer rate-limit gate (added in v1.24.1).

Without the gate the MCP transport bypassed authenticate(), so a Free-tier
client could exceed 100/hr through MCP while the same hourly cap was
enforced on /v1/* HTTP routes. Each HTTP request to /mcp/ now consumes one
credit; on exhaustion the middleware emits a JSON-RPC error response with
HTTP 429 + Retry-After.
"""

import pytest

mcp = pytest.importorskip("mcp", reason="mcp package not installed")

MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}

INIT_PAYLOAD = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "rl-test", "version": "1.0"},
    },
}


def _free_store_key(client_ip: str = "testclient") -> str:
    """Mirror auth.authenticate() free-tier store key derivation."""
    from db import hash_client_ip

    return f"free:{hash_client_ip(client_ip)}"


def _reset_free_bucket() -> None:
    """Drop everything in the rate_limits table for the Free testclient bucket."""
    from db import get_api_db

    store_key = _free_store_key()
    with get_api_db() as con:
        con.execute("DELETE FROM rate_limits WHERE key = ?", (f"api:{store_key}",))


def _free_bucket_count() -> int:
    """Count active credits in the Free testclient bucket."""
    from db import get_api_db

    store_key = _free_store_key()
    with get_api_db() as con:
        row = con.execute(
            "SELECT COUNT(*) FROM rate_limits WHERE key = ?",
            (f"api:{store_key}",),
        ).fetchone()
        return int(row[0])


def test_mcp_initialize_consumes_credit(mcp_client):
    """A successful POST /mcp/ should burn one credit on the free bucket."""
    _reset_free_bucket()
    before = _free_bucket_count()

    r = mcp_client.post("/mcp/", headers=MCP_HEADERS, json=INIT_PAYLOAD)
    assert r.status_code == 200

    after = _free_bucket_count()
    assert after == before + 1, f"expected {before + 1}, got {after}"


def test_mcp_invalid_pro_key_returns_401_jsonrpc(mcp_client):
    """Authorization header with a bogus cc_ key must 401 with JSON-RPC error."""
    from config import KEY_LENGTH, KEY_PREFIX

    bad = KEY_PREFIX + "0" * KEY_LENGTH
    r = mcp_client.post(
        "/mcp/",
        headers={**MCP_HEADERS, "Authorization": f"Bearer {bad}"},
        json=INIT_PAYLOAD,
    )
    assert r.status_code == 401
    body = r.json()
    assert body["jsonrpc"] == "2.0"
    assert body["error"]["code"] == -32001
    assert "API key" in body["error"]["message"]


def test_mcp_free_tier_429_after_limit(mcp_client):
    """Once the free bucket fills, /mcp/ must return 429 with JSON-RPC + Retry-After."""
    import time

    from config import FREE_HOURLY_LIMIT
    from db import get_api_db

    _reset_free_bucket()
    store_key = _free_store_key()
    now = time.time()
    # Pre-fill the bucket so the next request trips the cap.
    with get_api_db() as con:
        con.executemany(
            "INSERT INTO rate_limits (key, ts) VALUES (?, ?)",
            [(f"api:{store_key}", now) for _ in range(FREE_HOURLY_LIMIT)],
        )

    r = mcp_client.post("/mcp/", headers=MCP_HEADERS, json=INIT_PAYLOAD)
    assert r.status_code == 429
    body = r.json()
    assert body["jsonrpc"] == "2.0"
    assert body["error"]["code"] == -32000
    assert "Rate limit exceeded" in body["error"]["message"]
    # Retry-After is the actual seconds until the bucket frees up (set by
    # auth.py:113 from get_reset_time). Pre-fill happens at "now", so the
    # delta is small but must be a positive integer.
    retry = r.headers.get("retry-after")
    assert retry is not None and retry.isdigit() and int(retry) >= 1

    _reset_free_bucket()


def test_mcp_get_also_gated(mcp_client):
    """GET /mcp/ (SSE listen / discovery) must consume a credit too — otherwise a
    client could spam GETs without burning the free bucket."""
    _reset_free_bucket()

    mcp_client.get("/mcp/", headers={"Accept": "application/json"})
    assert _free_bucket_count() >= 1


def test_mcp_pro_key_higher_limit(mcp_client):
    """A valid Pro key on /mcp/ should not 429 even past the free cap."""
    from auth import generate_key, hash_key
    from config import FREE_HOURLY_LIMIT
    from db import save_api_key

    raw = generate_key()
    save_api_key(hash_key(raw), order_id="mcp_gate_pro_test")

    pro_headers = {**MCP_HEADERS, "Authorization": f"Bearer {raw}"}
    statuses = set()
    for _ in range(FREE_HOURLY_LIMIT + 5):
        r = mcp_client.post("/mcp/", headers=pro_headers, json=INIT_PAYLOAD)
        statuses.add(r.status_code)
        if 429 in statuses:
            break
    assert 429 not in statuses
    assert 200 in statuses
