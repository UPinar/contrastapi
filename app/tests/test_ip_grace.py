"""Tests for the single-shot 24h new-IP grace (replaces first_swipe ledger).

Isolation: conftest `temp_dbs` clears `new_ip_grace` between tests and calls
`ratelimit.reset()`. No explicit fixtures needed.
"""

import pytest

# --- storage + helper ---


def test_init_creates_new_ip_grace_table():
    import db
    import ratelimit

    ratelimit._init()
    with db.get_api_db() as con:
        rows = con.execute("PRAGMA table_info(new_ip_grace)").fetchall()
    by_name = {r[1]: r for r in rows}
    assert set(by_name) == {"store_key", "first_seen_at"}
    assert by_name["store_key"][2] == "TEXT" and by_name["store_key"][3] == 1
    assert by_name["first_seen_at"][2] == "REAL" and by_name["first_seen_at"][3] == 1
    # store_key is the sole PRIMARY KEY
    assert by_name["store_key"][5] == 1
    assert by_name["first_seen_at"][5] == 0


def test_is_ip_in_grace_new_identity_granted():
    from ratelimit import is_ip_in_grace

    # First contact → grace granted
    assert is_ip_in_grace("grace:new", 86400) is True
    # Same identity again, still inside the window → still granted (NOT one-time)
    assert is_ip_in_grace("grace:new", 86400) is True
    # Distinct identity → independent
    assert is_ip_in_grace("grace:other", 86400) is True


def test_is_ip_in_grace_expires_and_never_resets():
    import time

    import db
    from ratelimit import is_ip_in_grace

    # Seed a first_seen_at well in the past
    old_ts = time.time() - 10_000
    with db.get_api_db() as con:
        con.execute(
            "INSERT INTO new_ip_grace (store_key, first_seen_at) VALUES (?, ?)",
            ("grace:old", old_ts),
        )
    # Window of 3600s → expired
    assert is_ip_in_grace("grace:old", 3600) is False
    # Calling again must NOT reset first_seen_at (still expired) and must NOT
    # overwrite the stored timestamp.
    assert is_ip_in_grace("grace:old", 3600) is False
    with db.get_api_db() as con:
        stored = con.execute("SELECT first_seen_at FROM new_ip_grace WHERE store_key = ?", ("grace:old",)).fetchone()[0]
    assert abs(stored - old_ts) < 1.0  # unchanged


def test_maintenance_purges_old_grace():
    import time

    import db
    from ratelimit import is_ip_in_grace

    assert is_ip_in_grace("grace:keep", 86400) is True  # fresh (now)
    old_ts = time.time() - 10_000 * 86400  # ~27y ago, past the 365d TTL
    with db.get_api_db() as con:
        con.execute(
            "INSERT INTO new_ip_grace (store_key, first_seen_at) VALUES (?, ?)",
            ("grace:stale", old_ts),
        )
    with db.get_api_db() as con:
        before = {r[0] for r in con.execute("SELECT store_key FROM new_ip_grace").fetchall()}
    assert {"grace:keep", "grace:stale"} <= before

    stats = db.maintenance()
    assert stats.get("grace_error") is None

    with db.get_api_db() as con:
        keys = {r[0] for r in con.execute("SELECT store_key FROM new_ip_grace").fetchall()}
    assert "grace:keep" in keys
    assert "grace:stale" not in keys


def test_reset_clears_grace():
    import db
    import ratelimit
    from ratelimit import is_ip_in_grace

    assert is_ip_in_grace("grace:r", 86400) is True
    ratelimit.reset()
    with db.get_api_db() as con:
        n = con.execute("SELECT COUNT(*) FROM new_ip_grace").fetchone()[0]
    assert n == 0


def test_swipe_ip_bucket():
    from validation import swipe_ip_bucket

    assert swipe_ip_bucket("2a01:4f8:1c1a:7f63::dead") == "2a01:4f8:1c1a:7f63::"
    assert swipe_ip_bucket("2a01:4f8:1c1a:7f63::1") == "2a01:4f8:1c1a:7f63::"
    assert swipe_ip_bucket("1.2.3.4") == "1.2.3.4"
    assert swipe_ip_bucket("not-an-ip") == "not-an-ip"
    assert swipe_ip_bucket("::ffff:1.2.3.4") == "1.2.3.4"
    assert swipe_ip_bucket("::ffff:1.2.3.5") == "1.2.3.5"


# --- auth integration ---


def _kreq(ip, headers=None):
    from unittest.mock import MagicMock

    req = MagicMock()
    req.headers = headers if headers is not None else {}
    req.client = MagicMock()
    req.client.host = ip
    return req


def _noclient_req(headers=None):
    from unittest.mock import MagicMock

    req = MagicMock()
    req.headers = headers if headers is not None else {}
    req.client = None  # get_client_ip → "unknown"
    return req


def _exhaust_free(ip):
    """Consume the keyless 30/hr Free counter for `ip` via REST-style calls (no grace)."""
    from auth import authenticate_sync as authenticate
    from config import FREE_HOURLY_LIMIT

    for _ in range(FREE_HOURLY_LIMIT):
        authenticate(_kreq(ip), "/v1/test")


def test_new_ip_all_cost1_tools_free_at_limit():
    """A brand-new IP, even with the 30/hr Free counter exhausted, runs EVERY
    cost==1 MCP tool free during grace (the core fix — not 6-7 then 429)."""
    from auth import authenticate_sync as authenticate

    _exhaust_free("10.0.0.1")
    for tool in ("cve_lookup", "dns_lookup", "kev_detail", "cwe_lookup", "ssl_check", "whois_lookup"):
        ctx = authenticate(_kreq("10.0.0.1"), "/mcp/", cost=1, mcp_tool=tool)
        assert ctx.tier == "free"


def test_grace_repeat_same_tool_still_free():
    """Within grace, repeating the SAME tool is still free (old first_swipe 429'd
    the 2nd call — that was the returning-agent bug)."""
    from auth import authenticate_sync as authenticate

    _exhaust_free("10.0.0.2")
    c1 = authenticate(_kreq("10.0.0.2"), "/mcp/", cost=1, mcp_tool="dns_lookup")
    c2 = authenticate(_kreq("10.0.0.2"), "/mcp/", cost=1, mcp_tool="dns_lookup")
    assert c1.tier == "free" and c2.tier == "free"


def test_composite_cost_gt1_not_graced():
    from auth import authenticate_sync as authenticate
    from fastapi import HTTPException

    _exhaust_free("10.0.0.3")
    with pytest.raises(HTTPException) as e:
        authenticate(_kreq("10.0.0.3"), "/mcp/", cost=6, mcp_tool="audit_domain")
    assert e.value.status_code == 429


def test_rest_path_not_graced():
    from auth import authenticate_sync as authenticate
    from fastapi import HTTPException

    _exhaust_free("10.0.0.4")
    with pytest.raises(HTTPException) as e:
        authenticate(_kreq("10.0.0.4"), "/v1/test", cost=1, mcp_tool=None)
    assert e.value.status_code == 429


def test_grace_disabled_flag(monkeypatch):
    import auth
    from auth import authenticate_sync as authenticate
    from fastapi import HTTPException

    monkeypatch.setattr(auth, "FIRST_SWIPE_ENABLED", False)
    _exhaust_free("10.0.0.5")
    with pytest.raises(HTTPException) as e:
        authenticate(_kreq("10.0.0.5"), "/mcp/", cost=1, mcp_tool="dns_lookup")
    assert e.value.status_code == 429


def test_pro_key_not_graced():
    from auth import authenticate_sync as authenticate
    from auth import generate_key, hash_key
    from config import PRO_HOURLY_LIMIT
    from db import save_api_key
    from fastapi import HTTPException
    from ratelimit import consume_tokens

    key = generate_key()
    save_api_key(hash_key(key))
    consume_tokens("api", f"pro:{hash_key(key)}", PRO_HOURLY_LIMIT, PRO_HOURLY_LIMIT)
    req = _kreq("5.5.5.5", {"authorization": f"Bearer {key}"})
    with pytest.raises(HTTPException) as e:
        authenticate(req, "/mcp/", cost=1, mcp_tool="dns_lookup")
    assert e.value.status_code == 429


def test_grace_shared_across_ipv6_64():
    """Two /128 in the same /64 share ONE grace window: both calls are free AND
    the ledger holds exactly one row (the shared /64 bucket) — proving the
    addresses collapse to a single identity rather than each earning its own."""
    import db
    from auth import authenticate_sync as authenticate
    from db import hash_client_ip
    from validation import swipe_ip_bucket

    addr1 = "2a01:4f8:1c1a:7f63::1"
    addr2 = "2a01:4f8:1c1a:7f63::dead"  # same /64
    assert swipe_ip_bucket(addr1) == swipe_ip_bucket(addr2)
    _exhaust_free(addr1)
    _exhaust_free(addr2)
    c1 = authenticate(_kreq(addr1), "/mcp/", cost=1, mcp_tool="dns_lookup")
    c2 = authenticate(_kreq(addr2), "/mcp/", cost=1, mcp_tool="cve_lookup")
    assert c1.tier == "free" and c2.tier == "free"
    bucket_store = f"grace:{hash_client_ip(swipe_ip_bucket(addr1))}"
    with db.get_api_db() as con:
        rows = [r[0] for r in con.execute("SELECT store_key FROM new_ip_grace").fetchall()]
    assert rows == [bucket_store]  # exactly one row, keyed on the /64 bucket


def test_grace_window_boundary():
    """The window check is inclusive (<=): just inside stays in grace, just past
    does not (1s margins keep the test clock-robust)."""
    import time

    import db
    from ratelimit import is_ip_in_grace

    now = time.time()
    with db.get_api_db() as con:
        con.execute(
            "INSERT INTO new_ip_grace (store_key, first_seen_at) VALUES (?, ?)",
            ("grace:inside", now - 3599.0),
        )
        con.execute(
            "INSERT INTO new_ip_grace (store_key, first_seen_at) VALUES (?, ?)",
            ("grace:past", now - 3601.0),
        )
    assert is_ip_in_grace("grace:inside", 3600) is True
    assert is_ip_in_grace("grace:past", 3600) is False


def test_grace_skipped_for_unknown_client():
    from auth import authenticate_sync as authenticate
    from config import FREE_HOURLY_LIMIT
    from fastapi import HTTPException

    for _ in range(FREE_HOURLY_LIMIT):
        authenticate(_noclient_req(), "/v1/test")
    with pytest.raises(HTTPException) as e:
        authenticate(_noclient_req(), "/mcp/", cost=1, mcp_tool="dns_lookup")
    assert e.value.status_code == 429


def test_grace_skipped_for_empty_client():
    from auth import authenticate_sync as authenticate
    from fastapi import HTTPException

    _exhaust_free("")
    with pytest.raises(HTTPException) as e:
        authenticate(_kreq(""), "/mcp/", cost=1, mcp_tool="dns_lookup")
    assert e.value.status_code == 429


def test_grace_dos_ceiling_enforced():
    """Grace is not unlimited: inside the window a single bucket is capped at
    GRACE_HOURLY_LIMIT cost==1 calls, then 429 (DoS backstop)."""
    from auth import authenticate_sync as authenticate
    from config import GRACE_HOURLY_LIMIT
    from fastapi import HTTPException

    ip = "10.0.9.9"
    for _ in range(GRACE_HOURLY_LIMIT):
        ctx = authenticate(_kreq(ip), "/mcp/", cost=1, mcp_tool="dns_lookup")
        assert ctx.tier == "free"
    with pytest.raises(HTTPException) as e:
        authenticate(_kreq(ip), "/mcp/", cost=1, mcp_tool="dns_lookup")
    assert e.value.status_code == 429


def test_expired_grace_falls_to_hourly_limit():
    """Returning heavy user (grace window elapsed) falls to the normal 30/hr →
    429 once exhausted (upsell funnel intact; first_seen_at never reset)."""
    import time

    import db
    from auth import authenticate_sync as authenticate
    from db import hash_client_ip
    from fastapi import HTTPException
    from validation import swipe_ip_bucket

    ip = "10.0.8.8"
    # Seed an expired grace row (>24h old) for this IP's bucket
    grace_store = f"grace:{hash_client_ip(swipe_ip_bucket(ip))}"
    with db.get_api_db() as con:
        con.execute(
            "INSERT INTO new_ip_grace (store_key, first_seen_at) VALUES (?, ?)",
            (grace_store, time.time() - 200_000),  # ~55h ago > 24h
        )
    _exhaust_free(ip)  # exhaust the 30/hr Free counter
    with pytest.raises(HTTPException) as e:
        authenticate(_kreq(ip), "/mcp/", cost=1, mcp_tool="dns_lookup")
    assert e.value.status_code == 429


# --- MCP gate end-to-end ---


def test_mcp_gate_grace_exempts_repeat_calls(mcp_client):
    """Through the MCP ASGI gate: repeated keyless cost==1 calls stay grace-exempt
    (0 rows on the Free api counter) — proves grace covers a full discovery sweep,
    not just the first call."""
    from db import get_api_db, hash_client_ip

    rl_key = f"api:free:{hash_client_ip('testclient')}"
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    payload = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {"name": "cve_lookup", "arguments": {"cve_id": "CVE-1999-0001"}},
    }

    def _api_count():
        with get_api_db() as con:
            return con.execute("SELECT COUNT(*) FROM rate_limits WHERE key = ?", (rl_key,)).fetchone()[0]

    with get_api_db() as con:
        con.execute("DELETE FROM rate_limits WHERE key = ?", (rl_key,))

    r1 = mcp_client.post("/mcp/", headers=headers, json=payload)
    assert r1.status_code == 200
    r2 = mcp_client.post("/mcp/", headers=headers, json=payload)
    assert r2.status_code == 200
    assert _api_count() == 0  # both grace-exempt from the 30/hr Free counter


def test_mcp_gate_fake_tool_not_graced(mcp_client, monkeypatch):
    """A format-valid but non-registered tool name is NOT graced: at-limit it 429s
    and writes no new_ip_grace row (gate passes mcp_tool=None for unknown names)."""
    import time

    from config import FREE_HOURLY_LIMIT
    from db import get_api_db, hash_client_ip
    from validation import swipe_ip_bucket

    monkeypatch.setattr("core.mcp_proxy._TOOL_NAMES", frozenset({"cve_lookup"}), raising=False)
    rl_key = f"api:free:{hash_client_ip('testclient')}"
    grace_store = f"grace:{hash_client_ip(swipe_ip_bucket('testclient'))}"
    with get_api_db() as con:
        con.execute("DELETE FROM rate_limits WHERE key = ?", (rl_key,))
        con.execute("DELETE FROM new_ip_grace WHERE store_key = ?", (grace_store,))
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
    assert r.status_code == 429
    with get_api_db() as con:
        n = con.execute("SELECT COUNT(*) FROM new_ip_grace WHERE store_key = ?", (grace_store,)).fetchone()[0]
    assert n == 0


def test_mcp_gate_unbuilt_tool_cache_fail_closed(mcp_client, monkeypatch):
    """Empty tool-name cache → even a REAL tool name is not graced (fail-closed)."""
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
    assert r.status_code == 429
