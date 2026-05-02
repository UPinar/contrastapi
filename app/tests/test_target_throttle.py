"""Tests for target_throttle.py — per-eTLD+1 web-intel throttle."""

import os
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _reset_stores():
    from ratelimit import reset

    reset()
    # Clear daily-alert dedupe table so tests don't bleed into each other.
    from db import get_api_db

    with get_api_db() as con:
        try:
            con.execute("DELETE FROM target_throttle_alerts")
        except Exception:
            pass
    os.environ.pop("TARGET_THROTTLE_DISABLED", None)
    yield
    os.environ.pop("TARGET_THROTTLE_DISABLED", None)


# --- etld1 extraction ---


def test_etld1_strips_subdomain():
    from target_throttle import etld1

    assert etld1("a1.victim.com") == "victim.com"
    assert etld1("a.b.c.victim.com") == "victim.com"


def test_etld1_handles_multipart_tld():
    from target_throttle import etld1

    assert etld1("foo.victim.co.uk") == "victim.co.uk"


def test_etld1_distinct_for_different_tlds():
    from target_throttle import etld1

    assert etld1("victim.com") != etld1("victim.org")


def test_etld1_strips_port_and_path():
    from target_throttle import etld1

    assert etld1("victim.com:8080") == "victim.com"
    assert etld1("victim.com/path/x") == "victim.com"


def test_etld1_empty_input():
    from target_throttle import etld1

    assert etld1("") == ""


def test_etld1_ipv6_brackets_collapse_to_address_not_left_bracket():
    """[::1] must not collapse all IPv6 hosts to "[" — strip brackets first."""
    from target_throttle import etld1

    assert etld1("[::1]") == "::1"
    assert etld1("[2001:db8::1]") == "2001:db8::1"
    # Different IPv6 → different bucket key
    assert etld1("[::1]") != etld1("[2001:db8::1]")
    # Bracketed with port
    assert etld1("[2001:db8::1]:8080") == "2001:db8::1"


def test_etld1_ipv4_literal_uses_raw_ip_as_bucket():
    """IPv4 literals have no PSL match; per-IP throttling is the documented contract."""
    from target_throttle import etld1

    assert etld1("1.2.3.4") == "1.2.3.4"
    assert etld1("1.2.3.4:8080") == "1.2.3.4"
    assert etld1("1.2.3.4") != etld1("1.2.3.5")


# --- consume_target_throttle ---


def test_consume_under_cap_allowed():
    from config import TARGET_THROTTLE_PER_MIN
    from target_throttle import consume_target_throttle

    for _ in range(TARGET_THROTTLE_PER_MIN):
        allowed, retry = consume_target_throttle("victim.com")
        assert allowed is True
        assert retry == 0


def test_consume_at_cap_blocks():
    from config import TARGET_THROTTLE_PER_MIN
    from target_throttle import consume_target_throttle

    for _ in range(TARGET_THROTTLE_PER_MIN):
        consume_target_throttle("victim.com")
    allowed, retry = consume_target_throttle("victim.com")
    assert allowed is False
    assert retry >= 1


def test_subdomain_rotation_collapses_to_same_bucket():
    """a1.victim.com + a2.victim.com share the same eTLD+1 → same throttle."""
    from config import TARGET_THROTTLE_PER_MIN
    from target_throttle import consume_target_throttle

    half = TARGET_THROTTLE_PER_MIN // 2
    for _ in range(half):
        assert consume_target_throttle("a1.victim.com")[0] is True
    for _ in range(half):
        assert consume_target_throttle("a2.victim.com")[0] is True
    # 60th request from a third subdomain — eTLD+1 cap reached
    if TARGET_THROTTLE_PER_MIN % 2 == 0:
        allowed, retry = consume_target_throttle("a3.victim.com")
        assert allowed is False
        assert retry >= 1


def test_different_etlds_have_independent_buckets():
    from config import TARGET_THROTTLE_PER_MIN
    from target_throttle import consume_target_throttle

    for _ in range(TARGET_THROTTLE_PER_MIN):
        consume_target_throttle("victim.com")
    # victim.org untouched — should still allow
    allowed, _ = consume_target_throttle("victim.org")
    assert allowed is True


def test_disabled_env_bypasses_throttle():
    from config import TARGET_THROTTLE_PER_MIN
    from target_throttle import consume_target_throttle

    os.environ["TARGET_THROTTLE_DISABLED"] = "1"
    for _ in range(TARGET_THROTTLE_PER_MIN * 2):
        allowed, _ = consume_target_throttle("victim.com")
        assert allowed is True


def test_empty_host_passes_through():
    from target_throttle import consume_target_throttle

    allowed, retry = consume_target_throttle("")
    assert allowed is True
    assert retry == 0


# --- Daily alert (idempotent per day) ---


def test_daily_alert_fires_once_per_day():
    """Crossing TARGET_THROTTLE_DAILY_ALERT in a 24h window fires Telegram once."""
    import time as _t

    import target_throttle
    from config import TARGET_THROTTLE_DAILY_ALERT
    from db import get_api_db

    # Pre-load >=DAILY_ALERT rows into the daily-counter store. Fresh ts is
    # fine — this key prefix is independent from the 60s-window store, so the
    # next consume's 60s-DELETE can't wipe these.
    now = _t.time()
    n = TARGET_THROTTLE_DAILY_ALERT
    with get_api_db() as con:
        con.executemany(
            "INSERT INTO rate_limits (key, ts) VALUES (?, ?)",
            [("target_throttle_daily:victim.com", now) for _ in range(n)],
        )

    fire_calls = []
    with patch.object(target_throttle, "_fire_alert", side_effect=lambda e, c: fire_calls.append((e, c))):
        # First call: 60s bucket empty → allowed; 24h count > threshold → fires
        allowed, _ = target_throttle.consume_target_throttle("victim.com")
        assert allowed is True
        # Second call: same UTC-day → idempotent, no second fire
        target_throttle.consume_target_throttle("victim.com")

    assert len(fire_calls) == 1, f"expected exactly 1 alert, got {len(fire_calls)}: {fire_calls}"
    assert fire_calls[0][0] == "victim.com"


# --- /bot landing route ---


def test_bot_landing_route(mcp_client):
    """GET /bot serves the webmaster-info HTML."""
    r = mcp_client.get("/bot")
    assert r.status_code == 200
    body = r.text
    assert "ContrastAPI" in body
    assert "abuse" in body.lower() or "contact@contrastcyber.com" in body
    # UA self-id text shows the version+landing url pattern
    assert "+https://contrastcyber.com/bot" in body
