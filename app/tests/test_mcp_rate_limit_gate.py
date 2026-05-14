"""Tests for the /mcp/ app-layer rate-limit gate.

Only `tools/call` consumes a credit — metadata methods (initialize,
tools/list, resources/list, prompts/list, ping, notifications/*) are
free so registry indexers (Smithery / Glama / mcp.so / PulseMCP) and
normal MCP clients can probe capabilities without burning the hourly
quota. nginx mcp_post_keyless edge zone (2r/m burst=50) still throttles
abusive flood at the perimeter.
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

TOOLS_LIST_PAYLOAD = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
RESOURCES_LIST_PAYLOAD = {"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}}
PROMPTS_LIST_PAYLOAD = {"jsonrpc": "2.0", "id": 4, "method": "prompts/list", "params": {}}

TOOL_CALL_PAYLOAD = {
    "jsonrpc": "2.0",
    "id": 5,
    "method": "tools/call",
    "params": {"name": "cve_lookup", "arguments": {"cve_id": "CVE-1999-0001"}},
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


def test_mcp_initialize_is_free(mcp_client):
    """initialize is a metadata handshake — no credit cost. Registry
    indexers probe this on every refresh; gating it would 429 them out
    within minutes and break automated catalog discovery.
    """
    _reset_free_bucket()

    r = mcp_client.post("/mcp/", headers=MCP_HEADERS, json=INIT_PAYLOAD)
    assert r.status_code == 200
    assert _free_bucket_count() == 0


def test_mcp_tools_list_is_free(mcp_client):
    """tools/list returns the static tool catalog — no quota cost."""
    _reset_free_bucket()

    r = mcp_client.post("/mcp/", headers=MCP_HEADERS, json=TOOLS_LIST_PAYLOAD)
    assert r.status_code == 200
    assert _free_bucket_count() == 0


def test_mcp_resources_list_is_free(mcp_client):
    """resources/list returns the static resource catalog — no quota cost."""
    _reset_free_bucket()

    r = mcp_client.post("/mcp/", headers=MCP_HEADERS, json=RESOURCES_LIST_PAYLOAD)
    assert r.status_code == 200
    assert _free_bucket_count() == 0


def test_mcp_prompts_list_is_free(mcp_client):
    """prompts/list returns the static prompt catalog — no quota cost."""
    _reset_free_bucket()

    r = mcp_client.post("/mcp/", headers=MCP_HEADERS, json=PROMPTS_LIST_PAYLOAD)
    assert r.status_code == 200
    assert _free_bucket_count() == 0


def test_mcp_ping_is_free(mcp_client):
    """ping is a liveness probe — no quota cost."""
    _reset_free_bucket()

    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}},
    )
    # FastMCP may 200 (ping handler) or return a method-not-found error,
    # but either way the gate must not burn a credit.
    assert _free_bucket_count() == 0


def test_mcp_batch_request_rejected(mcp_client):
    """JSON-RPC batch (array body) must be rejected with HTTP 400.

    FastMCP doesn't process batches; treating a batch as "no method"
    would skip our gate while the downstream app could still attempt
    per-entry dispatch — a billable tools/call hidden in a batch of
    listing methods would otherwise pass untaxed.
    """
    _reset_free_bucket()

    batch_body = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "cve_lookup", "arguments": {"cve_id": "CVE-1999-0001"}},
        },
    ]
    r = mcp_client.post("/mcp/", headers=MCP_HEADERS, json=batch_body)
    assert r.status_code == 400
    body = r.json()
    assert body["error"]["code"] == -32600
    assert "Batch" in body["error"]["message"]
    # No credit burned (batch rejected at our middleware before gate).
    assert _free_bucket_count() == 0


def test_mcp_method_case_mismatch_does_not_bypass_gate(mcp_client):
    """Defense-in-depth: a mis-cased `Tools/Call` must not pass our gate
    as if it were a free metadata method. FastMCP method dispatch is
    case-sensitive (dict lookup) so this rejects downstream anyway, but
    verify our gate matches the same strictness.
    """
    _reset_free_bucket()

    payload = {**TOOL_CALL_PAYLOAD, "method": "Tools/Call"}
    r = mcp_client.post("/mcp/", headers=MCP_HEADERS, json=payload)
    # Gate sees method != "tools/call" → no credit. Downstream FastMCP
    # rejects (method-not-found). Either response is acceptable; the
    # invariant is "no credit burned for a malformed/unrecognized method
    # name regardless of casing".
    assert _free_bucket_count() == 0


def test_mcp_tools_call_consumes_credit(mcp_client):
    """tools/call runs a tool and consumes one credit on the free bucket."""
    _reset_free_bucket()
    before = _free_bucket_count()

    r = mcp_client.post("/mcp/", headers=MCP_HEADERS, json=TOOL_CALL_PAYLOAD)
    # tool may succeed (200) or return JSON-RPC error inside body, but the
    # gate has already burned the credit either way.
    assert r.status_code == 200

    after = _free_bucket_count()
    assert after == before + 1, f"expected {before + 1}, got {after}"


def test_mcp_invalid_pro_key_returns_401_jsonrpc(mcp_client):
    """Authorization header with a bogus cc_ key on tools/call must 401
    with JSON-RPC error. (Listing methods skip the gate entirely so they
    don't validate the bearer either — that's by design, the catalog is
    public.)
    """
    from config import KEY_LENGTH, KEY_PREFIX

    bad = KEY_PREFIX + "0" * KEY_LENGTH
    r = mcp_client.post(
        "/mcp/",
        headers={**MCP_HEADERS, "Authorization": f"Bearer {bad}"},
        json=TOOL_CALL_PAYLOAD,
    )
    assert r.status_code == 401
    body = r.json()
    assert body["jsonrpc"] == "2.0"
    assert body["error"]["code"] == -32001
    assert "API key" in body["error"]["message"]


def test_mcp_free_tier_429_after_limit(mcp_client):
    """Once the free bucket fills, a tools/call must return 429 with
    JSON-RPC + Retry-After.
    """
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

    r = mcp_client.post("/mcp/", headers=MCP_HEADERS, json=TOOL_CALL_PAYLOAD)
    assert r.status_code == 429
    body = r.json()
    assert body["jsonrpc"] == "2.0"
    assert body["error"]["code"] == -32000
    assert "Rate limit exceeded" in body["error"]["message"]
    retry = r.headers.get("retry-after")
    assert retry is not None and retry.isdigit() and int(retry) >= 1

    _reset_free_bucket()


def test_mcp_429_envelope_has_structured_data(mcp_client):
    """429 JSON-RPC error MUST carry `error.data` with tier/limit/upgrade_url
    so MCP agents can parse and present a tiered upsell prompt instead of
    just the string message. Mirrors REST 429 envelope.
    """
    import time

    from config import FREE_HOURLY_LIMIT, PRO_HOURLY_LIMIT, UPGRADE_URL
    from db import get_api_db

    _reset_free_bucket()
    store_key = _free_store_key()
    now = time.time()
    with get_api_db() as con:
        con.executemany(
            "INSERT INTO rate_limits (key, ts) VALUES (?, ?)",
            [(f"api:{store_key}", now) for _ in range(FREE_HOURLY_LIMIT)],
        )

    r = mcp_client.post("/mcp/", headers=MCP_HEADERS, json=TOOL_CALL_PAYLOAD)
    assert r.status_code == 429
    body = r.json()
    data = body["error"].get("data")
    assert data is not None, "429 must include error.data structured payload"
    assert data["tier"] == "free"
    assert data["limit"] == FREE_HOURLY_LIMIT
    assert data["pro_limit"] == PRO_HOURLY_LIMIT
    assert data["upgrade_url"] == UPGRADE_URL
    assert isinstance(data["retry_after_seconds"], int)
    assert data["retry_after_seconds"] >= 1

    _reset_free_bucket()


def test_mcp_non_429_error_has_no_data_field(mcp_client):
    """Non-rate-limit MCP gate errors (e.g. invalid bearer token → 401)
    must NOT carry the upsell `error.data` block — that field is reserved
    for 429 responses where upsell context is meaningful.
    """
    bad_headers = {**MCP_HEADERS, "Authorization": "Bearer cc_obviously_invalid"}
    r = mcp_client.post("/mcp/", headers=bad_headers, json=TOOL_CALL_PAYLOAD)
    assert r.status_code == 401
    body = r.json()
    assert body["error"]["code"] == -32001
    assert body["error"].get("data") is None


def test_mcp_get_is_exempt_from_gate(mcp_client):
    """GET /mcp/ — SSE listen + discovery info — must NOT consume a credit.

    A normal MCP client opens an SSE listen loop and reconnects every 15s
    (the retry directive we emit). 240 reconnects/hr would 429 a Free user
    in ~25 min before they ever invoke a tool. The GET responses are fixed
    (14-byte "retry: 15000" or a small JSON blob) and abuse is still capped
    by the nginx mcp_get zone (3,600/hr/IP).
    """
    _reset_free_bucket()

    mcp_client.get("/mcp/", headers={"Accept": "application/json"})
    assert _free_bucket_count() == 0


def test_mcp_get_sse_is_exempt_from_gate(mcp_client):
    """SSE-expecting GET — same exemption — must not burn the free bucket."""
    _reset_free_bucket()

    mcp_client.get("/mcp/", headers={"Accept": "text/event-stream"})
    assert _free_bucket_count() == 0


def test_mcp_pro_key_higher_limit(mcp_client):
    """A valid Pro key on tools/call should not 429 even past the free cap."""
    from auth import generate_key, hash_key
    from config import FREE_HOURLY_LIMIT
    from db import save_api_key

    raw = generate_key()
    save_api_key(hash_key(raw), order_id="mcp_gate_pro_test")

    pro_headers = {**MCP_HEADERS, "Authorization": f"Bearer {raw}"}
    statuses = set()
    for _ in range(FREE_HOURLY_LIMIT + 5):
        r = mcp_client.post("/mcp/", headers=pro_headers, json=TOOL_CALL_PAYLOAD)
        statuses.add(r.status_code)
        if 429 in statuses:
            break
    assert 429 not in statuses
    assert 200 in statuses


# v1.32.4 variable-cost infrastructure — composite tools (added in later
# batches) consume more than one credit per call. The map ships empty in
# this batch; tests below monkeypatch a known-good atomic tool into the
# map to exercise the lookup path without depending on a composite tool
# being registered yet.


def test_mcp_tool_cost_map_attribute_exists():
    """_TOOL_COST must be a module-level dict on mcp_proxy so later batches
    can register composite tools by name. Empty default in v1.32.4 Batch 1."""
    from core import mcp_proxy

    assert hasattr(mcp_proxy, "_TOOL_COST"), "mcp_proxy must expose _TOOL_COST dict"
    assert isinstance(mcp_proxy._TOOL_COST, dict)
    assert mcp_proxy._TOOL_COST == {}, "Batch 1 ships _TOOL_COST empty"


def test_mcp_unknown_tool_defaults_to_cost_1(mcp_client):
    """Tools not in _TOOL_COST keep the existing cost=1 behavior — the 52
    atomic tools shipping in v1.32.3 must not regress."""
    _reset_free_bucket()

    r = mcp_client.post("/mcp/", headers=MCP_HEADERS, json=TOOL_CALL_PAYLOAD)
    assert r.status_code == 200
    assert _free_bucket_count() == 1, "atomic tool call should consume exactly 1 credit"


def test_mcp_mapped_tool_consumes_mapped_cost(mcp_client, monkeypatch):
    """When a tool name appears in _TOOL_COST, the gate must withdraw that
    many credits in a single tools/call. Uses cve_lookup (real registered
    tool) monkeypatched to cost=5 — proves the lookup path works end-to-end
    before composite tools land in Batches 2 and 3."""
    from core import mcp_proxy

    _reset_free_bucket()
    monkeypatch.setitem(mcp_proxy._TOOL_COST, "cve_lookup", 5)

    r = mcp_client.post("/mcp/", headers=MCP_HEADERS, json=TOOL_CALL_PAYLOAD)
    assert r.status_code == 200
    assert _free_bucket_count() == 5, "single tools/call on a cost-5 tool must consume 5 credits"


def test_mcp_mapped_tool_429_after_fewer_calls(mcp_client, monkeypatch):
    """A cost=N tool exhausts the Free FREE_HOURLY_LIMIT bucket in
    floor(FREE_HOURLY_LIMIT/N) calls instead of FREE_HOURLY_LIMIT — the
    gate refuses the next call when current_consumed + N would exceed the
    cap. This is the revenue mechanism: composite tools accelerate the
    Free → Pro conversion funnel."""
    from config import FREE_HOURLY_LIMIT
    from core import mcp_proxy

    _reset_free_bucket()
    monkeypatch.setitem(mcp_proxy._TOOL_COST, "cve_lookup", 5)

    statuses = []
    for _ in range((FREE_HOURLY_LIMIT // 5) + 2):
        r = mcp_client.post("/mcp/", headers=MCP_HEADERS, json=TOOL_CALL_PAYLOAD)
        statuses.append(r.status_code)
        if r.status_code == 429:
            break

    assert 429 in statuses, "must 429 after the cost-weighted bucket fills"
    successful_calls = sum(1 for s in statuses if s == 200)
    assert successful_calls <= FREE_HOURLY_LIMIT // 5, (
        f"composite tool must not exceed {FREE_HOURLY_LIMIT // 5} successful calls on Free; got {successful_calls}"
    )


def test_mcp_malformed_tool_name_falls_back_to_cost_1(mcp_client, monkeypatch):
    """A tools/call body with a name that violates the validator (oversize,
    control chars, path traversal) must NOT match _TOOL_COST entries even if
    monkeypatched — the gate rejects it at the validation layer and falls
    back to cost=1. Closes the asymmetric-validation bypass where the gate
    is permissive but FastMCP downstream is strict (CWE-20 / CWE-770)."""
    from core import mcp_proxy

    # Inject a high-cost entry, then attempt to reach it via malformed names.
    monkeypatch.setitem(mcp_proxy._TOOL_COST, "cve_lookup", 5)

    malformed_payloads = [
        # Oversize name (>64 chars) — even if it could match a registered tool,
        # the gate strips it for safety.
        {"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": {"name": "a" * 100, "arguments": {}}},
        # Path traversal — non-alphanumeric (slash/dot)
        {"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": {"name": "../../etc/passwd", "arguments": {}}},
        # Whitespace-only — truthy but isalnum() fails after replace("_","")
        {"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": {"name": "   ", "arguments": {}}},
        # Non-string type
        {"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": {"name": ["cve_lookup"], "arguments": {}}},
    ]

    for payload in malformed_payloads:
        _reset_free_bucket()
        # The call itself likely 4xx/5xx from FastMCP (invalid tool name), but
        # the gate decision happens first — verify cost-1 was withdrawn, not 5.
        mcp_client.post("/mcp/", headers=MCP_HEADERS, json=payload)
        assert _free_bucket_count() <= 1, (
            f"malformed name {payload['params']['name']!r} must not trigger cost=5 lookup; "
            f"got {_free_bucket_count()} credits consumed"
        )
