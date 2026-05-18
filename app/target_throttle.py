"""Per-target eTLD+1 sliding-window throttle for v1.25.0 web-intel endpoints.

Different from ratelimit.py (which gates the requester):
this module gates the *target host* so a Pro subscriber can't weaponise their
hourly quota against a single victim site. Subdomain rotation
(a1.victim.com, a2.victim.com, ...) collapses to the same eTLD+1 bucket.

Crossing TARGET_THROTTLE_DAILY_ALERT in a 24h window fires a one-shot Telegram
alert (idempotent per (etld1, UTC-day) via target_throttle_alerts table).
"""

from __future__ import annotations

import datetime
import logging
import time

import tldextract
from config import TARGET_THROTTLE_DAILY_ALERT, TARGET_THROTTLE_PER_MIN, settings
from db import get_api_db
from ratelimit import check_limit_with_count, get_reset_time

logger = logging.getLogger(__name__)

_STORE = "target_throttle"
_DAILY_STORE = "target_throttle_daily"  # separate key prefix → 86400s rows survive 60s DELETEs
# bundled PSL: avoid first-request network fetch + suffix-list cache pollution
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
_table_ready = [False]  # mutable container so a global rebind is unnecessary


def _ensure_alert_table() -> None:
    with get_api_db() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS target_throttle_alerts (
                etld1 TEXT NOT NULL,
                day TEXT NOT NULL,
                PRIMARY KEY (etld1, day)
            )
            """
        )


def _init() -> None:
    if not _table_ready[0]:
        _ensure_alert_table()
        _table_ready[0] = True


def etld1(host: str) -> str:
    """Extract eTLD+1 (registered domain) from a host. Lowercased.

    a1.victim.co.uk -> victim.co.uk
    IPv4 literal     -> the raw IP (no PSL match; throttled per-IP, not per-domain)
    IPv6 [::1] form  -> bracket-stripped IP (treated like IPv4 literal — per-IP bucket)
    Empty/invalid    -> "" (caller passes through, no throttle)
    """
    if not host:
        return ""
    h = host.strip().lower()
    # Strip URL path / port suffixes (handed in raw url-ish form by some callers)
    if "/" in h:
        h = h.split("/", 1)[0]
    # IPv6 bracket form must be stripped BEFORE the colon-port split, otherwise
    # "[::1]" splits to "[" and every IPv6 host collapses to the same bucket.
    if h.startswith("[") and "]" in h:
        h = h[1 : h.index("]")]
    elif ":" in h:
        h = h.split(":", 1)[0]
    parsed = _extract(h)
    return parsed.top_domain_under_public_suffix or h


def consume_target_throttle(host: str) -> tuple[bool, int]:
    """Atomically reserve one slot of the per-eTLD+1 60s window.

    Returns (allowed, retry_after_seconds). retry_after_seconds is best-effort
    (seconds until the oldest slot expires); 0 when allowed.

    Disabled when env TARGET_THROTTLE_DISABLED=1 (kill-switch for false-positive
    incidents — leaves the throttle layer logically present but pass-through).
    """
    if settings.target_throttle_disabled:
        return True, 0

    e = etld1(host)
    if not e:
        return True, 0

    allowed, _ = check_limit_with_count(_STORE, e, TARGET_THROTTLE_PER_MIN, window_seconds=60)
    if not allowed:
        return False, max(1, get_reset_time(_STORE, e, window_seconds=60))

    # Independent daily counter (separate key prefix so the 60s DELETE in
    # check_limit_with_count above can't wipe these rows). One row per allowed
    # request; idempotent Telegram alert when 24h count crosses threshold.
    daily = _bump_daily(e)
    if daily >= TARGET_THROTTLE_DAILY_ALERT:
        _maybe_alert(e, daily)
    return True, 0


def _bump_daily(etld1_value: str) -> int:
    """Insert one row into the 24h-window daily counter, return current count."""
    now = time.time()
    cutoff = now - 86400
    full_key = f"{_DAILY_STORE}:{etld1_value}"
    with get_api_db() as con:
        con.execute("DELETE FROM rate_limits WHERE key = ? AND ts <= ?", (full_key, cutoff))
        con.execute("INSERT INTO rate_limits (key, ts) VALUES (?, ?)", (full_key, now))
        row = con.execute(
            "SELECT COUNT(*) FROM rate_limits WHERE key = ? AND ts > ?",
            (full_key, cutoff),
        ).fetchone()
    return int(row[0]) if row else 0


def _maybe_alert(etld1_value: str, count: int) -> None:
    _init()
    today = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d")
    with get_api_db() as con:
        cur = con.execute(
            "INSERT OR IGNORE INTO target_throttle_alerts (etld1, day) VALUES (?, ?)",
            (etld1_value, today),
        )
        if cur.rowcount == 0:
            return  # already alerted today
    _fire_alert(etld1_value, count)


def _fire_alert(etld1_value: str, count: int) -> None:
    """Best-effort Telegram alert. Swallows all exceptions (never breaks request)."""
    try:
        from core.notify import notify_telegram as _notify_telegram
    except Exception as exc:  # pragma: no cover — import guard
        logger.warning("target_throttle alert: import notify_telegram failed (%s)", exc)
        return
    # Defense-in-depth length cap. tldextract output is already constrained to
    # PSL-valid characters [a-z0-9.-], but a malformed extract could in theory
    # carry junk; keep the Telegram payload bounded.
    safe = etld1_value[:100] if etld1_value else "?"
    try:
        _notify_telegram(f"🎯 target_throttle: {safe} hit {count} req/24h")
    except Exception as exc:  # pragma: no cover — best-effort
        logger.warning("target_throttle alert: notify failed for %s (%s)", safe, exc)
