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
    """_TOOL_COST is the module-level cost map consumed by the /mcp/ gate.
    Tools listed here must use Pattern B (call shared `_impl()` directly, no
    HTTP hop via `_aget()`). A wrapper still using `_aget()` MUST stay out —
    otherwise both REST and MCP gates fire on a single call (double-charge).
    v1.32.4 Batch 4: `audit_domain` switched to Pattern B, listed here.
    v1.32.4 Batch 5: `threat_report` switched to Pattern B, listed here.
    `domain_vulns` stays out — still HTTP-hops via `_aget()`."""
    from core import mcp_proxy

    assert hasattr(mcp_proxy, "_TOOL_COST"), "mcp_proxy must expose _TOOL_COST dict"
    assert isinstance(mcp_proxy._TOOL_COST, dict)
    # audit_domain + threat_report: Pattern B shipped — must be in the map.
    assert "audit_domain" in mcp_proxy._TOOL_COST
    assert "threat_report" in mcp_proxy._TOOL_COST
    # domain_vulns: still uses _aget() — must NOT appear (would double-charge).
    assert "domain_vulns" not in mcp_proxy._TOOL_COST


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


def test_cost_constants_match_plan_a_values():
    """Plan A pricing (2026-05-14, breaking change in v1.32.4): audit + threat
    + domain_vulns raised; new composite constants added. This test pins the
    exact integers so a silent regression (someone tweaks COST_AUDIT back to
    4) gets caught — pricing decisions live in research.md / release notes."""
    from config import (
        COST_AUDIT,
        COST_CVE_TIMELINE,
        COST_DEFAULT,
        COST_DOMAIN_VULNS,
        COST_GENERATE_RISK_REPORT,
        COST_PRIORITIZE_CVES,
        COST_TECH_CVE_AUDIT,
        COST_THREAT_REPORT,
        COST_TRENDING_CVES,
    )

    assert COST_DEFAULT == 1
    assert COST_AUDIT == 6, "Plan A: 4 -> 6 (breaking)"
    assert COST_THREAT_REPORT == 6, "Plan A: 4 -> 6 (breaking)"
    assert COST_DOMAIN_VULNS == 4, "Plan A: 1 -> 4 (composite re-pricing)"
    assert COST_TECH_CVE_AUDIT == 10, "Plan A: red team flagship"
    assert COST_GENERATE_RISK_REPORT == 15, "Plan A: Pro anchor, 2 calls/hr Free"
    assert COST_CVE_TIMELINE == 6
    assert COST_PRIORITIZE_CVES == 10
    assert COST_TRENDING_CVES == 5


def test_mcp_audit_domain_mcp_gate_consumes_six_after_pattern_b(mcp_client):
    """v1.32.4 Batch 4 Pattern B inversion: the MCP audit_domain wrapper now calls
    `_audit_domain_impl()` directly (no HTTP hop to /v1/audit/{domain}), so the
    REST gate is bypassed for MCP traffic. The MCP gate MUST therefore charge
    COST_AUDIT (6) via `_TOOL_COST["audit_domain"]` so the credit price matches
    the REST endpoint's. Replaces the pre-Batch-4 guard that asserted the OPPOSITE
    (`audit_domain` NOT in `_TOOL_COST`) — that contract was valid only while the
    wrapper still HTTP-hopped via `_aget()` and double-charging was the risk."""
    from config import COST_AUDIT
    from core import mcp_proxy

    assert mcp_proxy._TOOL_COST.get("audit_domain") == COST_AUDIT, (
        f"audit_domain must consume COST_AUDIT={COST_AUDIT} via the MCP gate post-Pattern-B; "
        f"got {mcp_proxy._TOOL_COST.get('audit_domain')!r}"
    )


def test_mcp_threat_report_mcp_gate_consumes_six_after_pattern_b(mcp_client):
    """v1.32.4 Batch 5/5 Pattern B inversion: the MCP threat_report wrapper now
    calls `_threat_report_impl()` directly (no HTTP hop to /v1/threat-report/{ip}),
    so the REST gate is bypassed for MCP traffic. The MCP gate MUST charge
    COST_THREAT_REPORT (6) via `_TOOL_COST["threat_report"]` so the credit price
    matches the REST endpoint's. Mirrors the audit_domain (Batch 4) guard."""
    from config import COST_THREAT_REPORT
    from core import mcp_proxy

    assert mcp_proxy._TOOL_COST.get("threat_report") == COST_THREAT_REPORT, (
        f"threat_report must consume COST_THREAT_REPORT={COST_THREAT_REPORT} via the MCP gate "
        f"post-Pattern-B; got {mcp_proxy._TOOL_COST.get('threat_report')!r}"
    )


def test_threat_report_impl_callable_directly():
    """Pattern B contract: `_threat_report_impl(ip, *, tier, client_ip)` MUST be
    importable from `app.domain.routes` and accept the three keyword arguments
    the MCP wrapper passes. Pure import-shape guard — does not invoke the function
    (would hit real DNS/AbuseIPDB/Shodan). Parity with the Batch 4 audit_domain
    shape test."""
    import inspect

    from app.domain.routes import _threat_report_impl

    sig = inspect.signature(_threat_report_impl)
    params = sig.parameters
    assert "ip" in params, "first positional must be `ip`"
    for kw in ("tier", "client_ip"):
        assert kw in params, f"_threat_report_impl must accept `{kw}` kwarg; missing"
    assert inspect.iscoroutinefunction(_threat_report_impl), "_threat_report_impl must be async"


def test_mcp_threat_report_wrapper_does_not_call_aget(mcp_client, monkeypatch):
    """Pattern B behavior: MCP threat_report MUST call `_threat_report_impl` and
    MUST NOT call `_aget("/v1/threat-report/...")`. Spy on both: assert _impl was
    called, assert _aget was NOT called with a threat-report path. Guards against
    accidental regression where someone re-introduces the HTTP hop and reactivates
    the double-charge risk."""
    from core import mcp_proxy

    _reset_free_bucket()

    mod = mcp_proxy._mcp_mod
    from app.domain import routes as _routes

    impl_calls: list[dict] = []
    aget_threat_calls: list[str] = []

    async def _spy_impl(ip, *, tier="pro", client_ip=""):
        impl_calls.append({"ip": ip, "tier": tier})
        return {
            "ip": ip,
            "ptr": None,
            "asn_name": None,
            "country": None,
            "cloud_provider": None,
            "is_datacenter": False,
            "tor_exit": False,
            "firehol": None,
            "risk_score": 0,
            "severity_label": "low",
            "enrichment": {"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": []},
            "abuseipdb": {"status": "error"},
            "shodan": {"status": "error"},
            "asn": {},
            "threat_level": "none",
            "summary": "threat ok",
        }

    real_aget = mod._aget

    async def _spy_aget(path, params=None):
        if path.startswith("/v1/threat-report/"):
            aget_threat_calls.append(path)
        return await real_aget(path, params=params)

    monkeypatch.setattr(_routes, "_threat_report_impl", _spy_impl)
    monkeypatch.setattr(mod, "_aget", _spy_aget)

    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 301,
            "method": "tools/call",
            "params": {"name": "threat_report", "arguments": {"ip": "8.8.8.8"}},
        },
    )

    assert r.status_code == 200, r.text
    assert len(impl_calls) == 1, f"_threat_report_impl must be called exactly once; got {len(impl_calls)}"
    assert impl_calls[0]["ip"] == "8.8.8.8"
    assert aget_threat_calls == [], (
        f"MCP threat_report wrapper must not HTTP-hop to /v1/threat-report/...; got {aget_threat_calls}"
    )


def test_audit_domain_impl_callable_directly():
    """Pattern B contract: `_audit_domain_impl(domain, *, include_all_txt, tier,
    client_ip)` MUST be importable from `app.domain.routes` and accept the four
    keyword arguments the MCP wrapper passes. Pure import-shape guard — does not
    invoke the function (would hit real DNS/HTTP). Batch 5/5 adds the analogous
    `_threat_report_impl` shape test."""
    import inspect

    from app.domain.routes import _audit_domain_impl

    sig = inspect.signature(_audit_domain_impl)
    params = sig.parameters
    assert "domain" in params, "first positional must be `domain`"
    for kw in ("include_all_txt", "tier", "client_ip"):
        assert kw in params, f"_audit_domain_impl must accept `{kw}` kwarg; missing"
    # Async coroutine — REST handler awaits it, MCP wrapper awaits it.
    assert inspect.iscoroutinefunction(_audit_domain_impl), "_audit_domain_impl must be async"


def test_mcp_audit_domain_wrapper_does_not_call_aget(mcp_client, monkeypatch):
    """Pattern B behavior: MCP audit_domain MUST call `_audit_domain_impl` and
    MUST NOT call `_aget("/v1/audit/...")`. Spy on both: assert _impl was called,
    assert _aget was NOT called with an audit path. Guards against accidental
    regression where someone re-introduces the HTTP hop and reactivates the
    double-charge risk."""
    from core import mcp_proxy

    _reset_free_bucket()

    mod = mcp_proxy._mcp_mod
    from app.domain import routes as _routes

    impl_calls: list[dict] = []
    aget_audit_calls: list[str] = []

    async def _spy_impl(domain, *, include_all_txt=False, tier="pro", client_ip=""):
        impl_calls.append({"domain": domain, "tier": tier, "include_all_txt": include_all_txt})
        return {
            "domain": domain,
            "report": {},
            "technologies": {"technologies": [], "categories": {}, "count": 0, "summary": ""},
            "live_headers": {},
            "summary": "audit ok",
            "next_calls": None,
        }

    real_aget = mod._aget

    async def _spy_aget(path, params=None):
        if path.startswith("/v1/audit/"):
            aget_audit_calls.append(path)
        return await real_aget(path, params=params)

    monkeypatch.setattr(_routes, "_audit_domain_impl", _spy_impl)
    monkeypatch.setattr(mod, "_aget", _spy_aget)

    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 300,
            "method": "tools/call",
            "params": {"name": "audit_domain", "arguments": {"domain": "example.com"}},
        },
    )

    assert r.status_code == 200, r.text
    assert len(impl_calls) == 1, f"_audit_domain_impl must be called exactly once; got {len(impl_calls)}"
    assert impl_calls[0]["domain"] == "example.com"
    assert aget_audit_calls == [], (
        f"MCP audit_domain wrapper must not HTTP-hop to /v1/audit/...; got {aget_audit_calls}"
    )


def test_mcp_user_tier_var_module_attribute_exists():
    """Pattern B foundation: mcp_server must expose a `_user_tier_var` ContextVar
    so the gate can propagate the caller's tier into MCP tool functions. Used by
    Batches 4/5 (audit_domain / threat_report Pattern B refactor) to gate Pro-only
    features inside `_impl()` helpers without an HTTP round-trip to the REST layer."""
    import contextvars

    import mcp_server

    assert hasattr(mcp_server, "_user_tier_var"), "mcp_server must expose _user_tier_var ContextVar"
    assert isinstance(mcp_server._user_tier_var, contextvars.ContextVar)
    # Default must be safe — "pro" so an unauthenticated MCP call (e.g. CLI/local
    # dev) does not silently degrade to Free-tier feature gating.
    assert mcp_server._user_tier_var.get() == "pro"


def test_mcp_get_user_tier_helper_exists():
    """Pattern B helper: `_get_user_tier()` reads the ContextVar with a safe
    fallback. MCP wrappers call this instead of touching the ContextVar directly,
    so future logic (e.g. tier inference from API key prefix) lives in one place."""
    import mcp_server

    assert hasattr(mcp_server, "_get_user_tier")
    # Default-context call must return "pro" (sane default).
    assert mcp_server._get_user_tier() == "pro"


def test_mcp_gate_publishes_tier_into_contextvar():
    from pathlib import Path

    proxy_src = Path(__file__).resolve().parent.parent / "core" / "mcp_proxy.py"
    content = proxy_src.read_text()
    assert "self._user_tier_var.set(" in content
    auth_idx = content.find("_mcp_authenticate(_gate_req")
    set_idx = content.find("self._user_tier_var.set(")
    assert set_idx > auth_idx > 0
    # v1.32.4 Batch 4 hardening: the token returned by .set() MUST be captured
    # and reset in a finally block so the tier cannot bleed past the request
    # scope (matches the _client_ip_var lifecycle below it in the middleware).
    # Guards against the asymmetry caught in the Batch 4 security review.
    assert "_tier_token = self._user_tier_var.set(" in content, (
        "tier ContextVar set must capture the token for request-scoped reset"
    )
    assert "self._user_tier_var.reset(_tier_token)" in content, (
        "tier ContextVar must be reset in finally to prevent cross-request leakage"
    )


def test_mcp_triggers_list_returns_empty_array(mcp_client):
    """v1.32.5: Smithery (and other catalog indexers) probe `triggers/list`
    as a scoring criterion. The MCP SDK does not implement that method, so
    without intervention FastMCP returns -32601/-32602 for every probe and
    Smithery decays the server score (observed 99→85 over ~5 days under
    their rolling window). The mcp_proxy middleware short-circuits with an
    empty-array result — keeps catalog rank intact and forward-compatible
    with the eventual spec adoption."""
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={"jsonrpc": "2.0", "id": 7777, "method": "triggers/list", "params": {}},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("id") == 7777
    assert body.get("result") == {"triggers": []}
    assert "error" not in body, f"triggers/list must not return JSON-RPC error: {body}"


def test_mcp_triggers_list_does_not_consume_credit(mcp_client):
    """triggers/list is a metadata / health probe — it must NOT consume
    rate-limit credits (would amplify the Smithery score penalty rather
    than fix it). The fast-path returns BEFORE the tools/call gate."""
    _reset_free_bucket()
    initial = _free_bucket_count()
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={"jsonrpc": "2.0", "id": 7778, "method": "triggers/list", "params": {}},
    )
    assert r.status_code == 200
    assert _free_bucket_count() == initial, (
        f"triggers/list must not consume credits; was {initial}, now {_free_bucket_count()}"
    )


def test_mcp_triggers_list_null_id_does_not_use_fast_path(mcp_client):
    """JSON-RPC §5.3 + spec ambiguity: requests with explicit `"id": null`
    are treated as notifications by some clients (intentional drop-response
    signal). The fast-path's null-id guard makes it fall through to FastMCP
    rather than reply with a non-null-id envelope — matches tools/list
    behaviour and avoids surprising clients that key off id=null."""
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={"jsonrpc": "2.0", "id": None, "method": "triggers/list", "params": {}},
    )
    # FastMCP returns 202 Accepted for null-id (notification interpretation)
    # or 200 with method-not-found from the SDK. The CONTRACT we're locking:
    # the fast-path's empty-array result MUST NOT be returned when id=null.
    if r.text:
        body = r.json()
        # Reject the fast-path-success shape: that would mean we ignored the
        # null-id guard and shipped {"triggers": []} despite the spec gap.
        assert body.get("result") != {"triggers": []}, f"fast-path must not fire on null id; got {body}"


def test_mcp_smithery_events_list_returns_empty_array(mcp_client):
    """v1.32.7: Smithery's actual scoring probe is `ai.smithery/events/list`
    (proprietary namespace), NOT `triggers/list` as the inspector's user-
    facing 'Failed to list triggers' text implies. Confirmed via S241
    SMITHERY_PROBE debug log capture in v1.32.6. The middleware fast-path
    short-circuits with {"events": []} so Smithery's rolling-window score
    stops decaying."""
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={"jsonrpc": "2.0", "id": 8888, "method": "ai.smithery/events/list", "params": {}},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("id") == 8888
    assert body.get("result") == {"events": []}
    assert "error" not in body, f"ai.smithery/events/list must not return JSON-RPC error: {body}"


def test_mcp_smithery_events_list_does_not_consume_credit(mcp_client):
    """Smithery probes ~100x/day. Each one must be free — burning credits
    on a passive health-check would tank Free-tier user quotas. The fast-
    path returns BEFORE the tools/call gate."""
    _reset_free_bucket()
    initial = _free_bucket_count()
    r = mcp_client.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={"jsonrpc": "2.0", "id": 8889, "method": "ai.smithery/events/list", "params": {}},
    )
    assert r.status_code == 200
    assert _free_bucket_count() == initial, (
        f"ai.smithery/events/list must not consume credits; was {initial}, now {_free_bucket_count()}"
    )
