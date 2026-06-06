"""Tests for the first-swipe free grant (v1.34.0) — Batch 1: storage + helper.

Isolation: conftest `_session_dbs` runs init_all_dbs() (creates the table) and
`temp_dbs` clears `first_swipe` between tests. No explicit fixtures needed.
"""

import pytest


def test_init_creates_first_swipe_table():
    import db
    import ratelimit

    ratelimit._init()  # first_swipe is created by ratelimit._ensure_table()
    with db.get_api_db() as con:
        rows = con.execute("PRAGMA table_info(first_swipe)").fetchall()
    # PRAGMA table_info columns: (cid, name, type, notnull, dflt_value, pk)
    by_name = {r[1]: r for r in rows}
    assert set(by_name) == {"store_key", "tool", "redeemed_at"}
    assert by_name["store_key"][2] == "TEXT" and by_name["store_key"][3] == 1
    assert by_name["tool"][2] == "TEXT" and by_name["tool"][3] == 1
    assert by_name["redeemed_at"][2] == "REAL" and by_name["redeemed_at"][3] == 1
    # composite PRIMARY KEY (store_key, tool); redeemed_at must NOT be in the PK
    assert by_name["store_key"][5] == 1 and by_name["tool"][5] == 2
    assert by_name["redeemed_at"][5] == 0


def test_maintenance_purges_old_first_swipe():
    import time

    import db
    from ratelimit import try_redeem_first_swipe

    # Fresh redemption (now) — must survive maintenance
    assert try_redeem_first_swipe("free:keep", "fresh_tool", 53) is True
    # Old redemption (~27 years ago, well past any TTL) — must be purged
    old_ts = time.time() - 10_000 * 86400
    with db.get_api_db() as con:
        con.execute(
            "INSERT INTO first_swipe (store_key, tool, redeemed_at) VALUES (?, ?, ?)",
            ("free:old", "old_tool", old_ts),
        )

    # Pre-validate both rows exist before maintenance (guard against false-positive)
    with db.get_api_db() as con:
        before = {r[0] for r in con.execute("SELECT store_key FROM first_swipe").fetchall()}
    assert {"free:keep", "free:old"} <= before

    stats = db.maintenance()
    assert stats.get("first_swipe_error") is None

    with db.get_api_db() as con:
        keys = {r[0] for r in con.execute("SELECT store_key FROM first_swipe").fetchall()}
    assert "free:keep" in keys
    assert "free:old" not in keys


def test_try_redeem_first_swipe_idempotent_per_tool():
    from ratelimit import try_redeem_first_swipe

    # First call to a tool for an identity → redeemed
    assert try_redeem_first_swipe("free:abc", "domain_report", 53) is True
    # Same (identity, tool) again → already redeemed
    assert try_redeem_first_swipe("free:abc", "domain_report", 53) is False
    # Distinct tool, same identity → redeemed
    assert try_redeem_first_swipe("free:abc", "dns_lookup", 53) is True
    # Same tool, different identity → independent
    assert try_redeem_first_swipe("free:xyz", "domain_report", 53) is True


def test_try_redeem_first_swipe_cap_enforced():
    from ratelimit import try_redeem_first_swipe

    # With a cap of 2, the first two distinct tools redeem, the third does not
    assert try_redeem_first_swipe("free:cap", "t1", 2) is True
    assert try_redeem_first_swipe("free:cap", "t2", 2) is True
    assert try_redeem_first_swipe("free:cap", "t3", 2) is False


def test_reset_clears_first_swipe():
    import db
    import ratelimit
    from ratelimit import try_redeem_first_swipe

    assert try_redeem_first_swipe("free:r", "t1", 53) is True
    ratelimit.reset()
    with db.get_api_db() as con:
        n = con.execute("SELECT COUNT(*) FROM first_swipe").fetchone()[0]
    assert n == 0


# --- Batch 2: MCP-only Free-tier first-swipe wiring (cost==1, IPv6 /64) ---


def _kreq(ip, headers=None):
    from unittest.mock import MagicMock

    req = MagicMock()
    req.headers = headers if headers is not None else {}
    req.client = MagicMock()
    req.client.host = ip
    return req


def _exhaust_free(ip):
    """Consume the keyless hourly limit for `ip` via REST-style calls (no swipe)."""
    from auth import authenticate_sync as authenticate
    from config import FREE_HOURLY_LIMIT

    for _ in range(FREE_HOURLY_LIMIT):
        authenticate(_kreq(ip), "/v1/test")


def test_swipe_ip_bucket():
    from validation import swipe_ip_bucket

    assert swipe_ip_bucket("2a01:4f8:1c1a:7f63::dead") == "2a01:4f8:1c1a:7f63::"
    assert swipe_ip_bucket("2a01:4f8:1c1a:7f63::1") == "2a01:4f8:1c1a:7f63::"
    assert swipe_ip_bucket("1.2.3.4") == "1.2.3.4"
    assert swipe_ip_bucket("not-an-ip") == "not-an-ip"
    # IPv4-mapped IPv6 must resolve to the embedded IPv4, NOT collapse to "::"
    assert swipe_ip_bucket("::ffff:1.2.3.4") == "1.2.3.4"
    assert swipe_ip_bucket("::ffff:1.2.3.5") == "1.2.3.5"


def test_free_first_mcp_call_exempt_at_limit():
    from auth import authenticate_sync as authenticate

    _exhaust_free("10.0.0.1")
    ctx = authenticate(_kreq("10.0.0.1"), "/mcp/", cost=1, mcp_tool="domain_report")
    assert ctx.tier == "free"


def test_free_repeat_same_tool_429():
    from auth import authenticate_sync as authenticate
    from fastapi import HTTPException

    _exhaust_free("10.0.0.2")
    authenticate(_kreq("10.0.0.2"), "/mcp/", cost=1, mcp_tool="dns_lookup")  # 1st: exempt
    with pytest.raises(HTTPException) as e:
        authenticate(_kreq("10.0.0.2"), "/mcp/", cost=1, mcp_tool="dns_lookup")  # 2nd: charged
    assert e.value.status_code == 429


def test_composite_cost_gt1_not_exempt():
    from auth import authenticate_sync as authenticate
    from fastapi import HTTPException

    _exhaust_free("10.0.0.3")
    with pytest.raises(HTTPException) as e:
        authenticate(_kreq("10.0.0.3"), "/mcp/", cost=6, mcp_tool="audit_domain")
    assert e.value.status_code == 429


def test_rest_path_not_exempt():
    from auth import authenticate_sync as authenticate
    from fastapi import HTTPException

    _exhaust_free("10.0.0.4")
    with pytest.raises(HTTPException) as e:
        authenticate(_kreq("10.0.0.4"), "/v1/test", cost=1, mcp_tool=None)
    assert e.value.status_code == 429


def test_swipe_disabled_flag(monkeypatch):
    import auth
    from auth import authenticate_sync as authenticate
    from fastapi import HTTPException

    monkeypatch.setattr(auth, "FIRST_SWIPE_ENABLED", False)
    _exhaust_free("10.0.0.5")
    with pytest.raises(HTTPException) as e:
        authenticate(_kreq("10.0.0.5"), "/mcp/", cost=1, mcp_tool="domain_report")
    assert e.value.status_code == 429


def test_pro_key_not_exempt():
    from auth import authenticate_sync as authenticate
    from auth import generate_key, hash_key
    from config import PRO_HOURLY_LIMIT
    from db import save_api_key
    from fastapi import HTTPException
    from ratelimit import consume_credits

    key = generate_key()
    save_api_key(hash_key(key))
    consume_credits("api", f"pro:{hash_key(key)}", PRO_HOURLY_LIMIT, PRO_HOURLY_LIMIT)
    req = _kreq("5.5.5.5", {"authorization": f"Bearer {key}"})
    with pytest.raises(HTTPException) as e:
        authenticate(req, "/mcp/", cost=1, mcp_tool="domain_report")
    assert e.value.status_code == 429


def test_swipe_ipv6_shared_across_64():
    from auth import authenticate_sync as authenticate
    from fastapi import HTTPException

    addr1 = "2a01:4f8:1c1a:7f63::1"
    addr2 = "2a01:4f8:1c1a:7f63::dead"  # same /64
    _exhaust_free(addr1)
    _exhaust_free(addr2)
    authenticate(_kreq(addr1), "/mcp/", cost=1, mcp_tool="domain_report")  # /64 redeems
    with pytest.raises(HTTPException) as e:
        authenticate(_kreq(addr2), "/mcp/", cost=1, mcp_tool="domain_report")  # already redeemed
    assert e.value.status_code == 429


def test_mcp_gate_first_swipe_exempts_then_charges(mcp_client):
    """End-to-end through the MCP ASGI gate: the first keyless call to a cost==1 tool
    is swipe-exempt (0 credits), the second is charged — proves mcp_proxy passes the
    tool name into the gate (closes the gap left by disabling swipe in the limiter tests)."""
    from db import get_api_db, hash_client_ip

    rl_key = f"api:free:{hash_client_ip('testclient')}"
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    payload = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {"name": "cve_lookup", "arguments": {"cve_id": "CVE-1999-0001"}},
    }

    def _count():
        with get_api_db() as con:
            return con.execute("SELECT COUNT(*) FROM rate_limits WHERE key = ?", (rl_key,)).fetchone()[0]

    with get_api_db() as con:
        con.execute("DELETE FROM rate_limits WHERE key = ?", (rl_key,))

    r1 = mcp_client.post("/mcp/", headers=headers, json=payload)
    assert r1.status_code == 200
    assert _count() == 0  # first call swipe-exempt

    r2 = mcp_client.post("/mcp/", headers=headers, json=payload)
    assert r2.status_code == 200
    assert _count() == 1  # second call charged (swipe already redeemed)


# --- Batch 2.1: review fixes (IPv4-mapped, unknown sentinel, fake-tool poison) ---


def _noclient_req(headers=None):
    from unittest.mock import MagicMock

    req = MagicMock()
    req.headers = headers if headers is not None else {}
    req.client = None  # get_client_ip → "unknown"
    return req


def test_swipe_skipped_for_unknown_client():
    """When client IP is the 'unknown' sentinel (request.client is None), swipe must
    NOT fire — unidentifiable callers fall through to the normal hourly limit so they
    can't pool a shared free grant."""
    from auth import authenticate_sync as authenticate
    from config import FREE_HOURLY_LIMIT
    from fastapi import HTTPException

    for _ in range(FREE_HOURLY_LIMIT):
        authenticate(_noclient_req(), "/v1/test")
    with pytest.raises(HTTPException) as e:
        authenticate(_noclient_req(), "/mcp/", cost=1, mcp_tool="domain_report")
    assert e.value.status_code == 429


def test_mcp_gate_fake_tool_not_swipe_exempt(mcp_client, monkeypatch):
    """A format-valid but non-registered tool name must NOT consume a swipe slot:
    at-limit it gets the normal 429 (not exempt) and writes no ledger row."""
    import time

    from config import FREE_HOURLY_LIMIT
    from db import get_api_db, hash_client_ip

    monkeypatch.setattr("core.mcp_proxy._TOOL_NAMES", frozenset({"cve_lookup"}), raising=False)
    rl_key = f"api:free:{hash_client_ip('testclient')}"
    with get_api_db() as con:
        con.execute("DELETE FROM rate_limits WHERE key = ?", (rl_key,))
        con.executemany(
            "INSERT INTO rate_limits (key, ts) VALUES (?, ?)",
            [(rl_key, time.time()) for _ in range(FREE_HOURLY_LIMIT)],
        )
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    payload = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {"name": "totally_fake_tool", "arguments": {}},
    }
    r = mcp_client.post("/mcp/", headers=headers, json=payload)
    assert r.status_code == 429  # fake tool not swipe-exempt → hits the limit
    with get_api_db() as con:
        n = con.execute("SELECT COUNT(*) FROM first_swipe WHERE tool = ?", ("totally_fake_tool",)).fetchone()[0]
    assert n == 0


def test_swipe_skipped_for_empty_client():
    """Empty-string client IP (request.client.host == '') is also unidentifiable —
    must NOT pool a shared swipe grant (guarded alongside 'unknown')."""
    from auth import authenticate_sync as authenticate
    from fastapi import HTTPException

    _exhaust_free("")
    with pytest.raises(HTTPException) as e:
        authenticate(_kreq(""), "/mcp/", cost=1, mcp_tool="domain_report")
    assert e.value.status_code == 429


def test_mcp_gate_unbuilt_tool_cache_fail_closed(mcp_client, monkeypatch):
    """If the tool-name cache is empty (build failed / not yet built), swipe must NOT
    fire even for a REAL tool name — fail-closed, not permissive."""
    import time

    from config import FREE_HOURLY_LIMIT
    from db import get_api_db, hash_client_ip

    monkeypatch.setattr("core.mcp_proxy._TOOL_NAMES", frozenset(), raising=False)
    rl_key = f"api:free:{hash_client_ip('testclient')}"
    with get_api_db() as con:
        con.execute("DELETE FROM rate_limits WHERE key = ?", (rl_key,))
        con.executemany(
            "INSERT INTO rate_limits (key, ts) VALUES (?, ?)",
            [(rl_key, time.time()) for _ in range(FREE_HOURLY_LIMIT)],
        )
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    payload = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {"name": "cve_lookup", "arguments": {"cve_id": "CVE-1999-0001"}},
    }
    r = mcp_client.post("/mcp/", headers=headers, json=payload)
    assert r.status_code == 429  # empty cache → no swipe even for a real tool
