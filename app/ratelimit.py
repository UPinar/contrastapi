"""SQLite-based rate limiting for ContrastAPI

Persistent sliding window rate limiter shared across all workers.
Uses api.db rate_limits table with WAL mode for concurrent access.

Replaces the previous in-memory limiter which:
  - Reset on worker restart
  - Was per-worker (2 workers = 2x the real limit)
"""

import time

from config import settings
from db import _get_conn, get_api_db
from fastapi.concurrency import run_in_threadpool


def _ensure_table():
    """Create rate_limits table if not exists."""
    with get_api_db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                key TEXT NOT NULL,
                ts REAL NOT NULL
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_rl_key_ts ON rate_limits(key, ts)")


_table_ready = False


def _init():
    global _table_ready
    if not _table_ready:
        _ensure_table()
        _table_ready = True


def check_limit_with_count(
    store_name: str, key: str, max_requests: int, window_seconds: int = 3600
) -> tuple[bool, int]:
    """Check rate limit and return (allowed, remaining) atomically.

    Uses atomic INSERT-SELECT to prevent TOCTOU race between workers.
    The INSERT only succeeds if the current count is below the limit.
    """
    _init()
    now = time.time()
    cutoff = now - window_seconds
    full_key = f"{store_name}:{key}"

    with get_api_db() as con:
        # Clean expired entries for this key
        con.execute("DELETE FROM rate_limits WHERE key = ? AND ts <= ?", (full_key, cutoff))

        # Atomic check-and-insert: only inserts if count < max_requests
        cur = con.execute(
            """
            INSERT INTO rate_limits (key, ts)
            SELECT ?, ?
            WHERE (SELECT COUNT(*) FROM rate_limits WHERE key = ? AND ts > ?) < ?
            """,
            (full_key, now, full_key, cutoff, max_requests),
        )

        if cur.rowcount == 0:
            return False, 0

        # Get remaining count
        row = con.execute(
            "SELECT COUNT(*) FROM rate_limits WHERE key = ? AND ts > ?",
            (full_key, cutoff),
        ).fetchone()
        count = row[0] if row else 0
        return True, max(0, max_requests - count)


def check_limit(store_name: str, key: str, max_requests: int, window_seconds: int = 3600) -> bool:
    """Check sliding window rate limit. Returns True if allowed."""
    allowed, _ = check_limit_with_count(store_name, key, max_requests, window_seconds)
    return allowed


async def acheck_limit(store_name: str, key: str, max_requests: int, window_seconds: int = 3600) -> bool:
    return await run_in_threadpool(check_limit, store_name, key, max_requests, window_seconds)


def get_count(store_name: str, key: str, window_seconds: int = 3600) -> int:
    """Get current request count for a key."""
    _init()
    cutoff = time.time() - window_seconds
    full_key = f"{store_name}:{key}"

    with get_api_db() as con:
        row = con.execute(
            "SELECT COUNT(*) FROM rate_limits WHERE key = ? AND ts > ?",
            (full_key, cutoff),
        ).fetchone()
        return row[0] if row else 0


def consume_bulk(store_name: str, key: str, count: int, max_requests: int, window_seconds: int = 3600) -> bool:
    """Atomically consume `count` rate limit slots. Returns True if all slots were available.

    Uses BEGIN IMMEDIATE to acquire a write lock upfront, preventing TOCTOU race
    between workers (same pattern as db.get_and_clear_pending_key).
    """
    _init()
    if count <= 0:
        return True
    now = time.time()
    cutoff = now - window_seconds
    full_key = f"{store_name}:{key}"

    con = _get_conn(str(settings.api_db))
    try:
        con.execute("BEGIN IMMEDIATE")
        con.execute("DELETE FROM rate_limits WHERE key = ? AND ts <= ?", (full_key, cutoff))
        row = con.execute(
            "SELECT COUNT(*) FROM rate_limits WHERE key = ? AND ts > ?",
            (full_key, cutoff),
        ).fetchone()
        current = row[0] if row else 0
        if current + count > max_requests:
            con.commit()
            return False
        con.executemany(
            "INSERT INTO rate_limits (key, ts) VALUES (?, ?)",
            [(full_key, now) for _ in range(count)],
        )
        con.commit()
        return True
    except Exception:
        con.rollback()
        raise


async def aconsume_bulk(store_name: str, key: str, count: int, max_requests: int, window_seconds: int = 3600) -> bool:
    return await run_in_threadpool(consume_bulk, store_name, key, count, max_requests, window_seconds)


def consume_credits(
    store_name: str, key: str, cost: int, max_requests: int, window_seconds: int = 3600
) -> tuple[bool, int]:
    """Atomically consume `cost` rate limit slots. Returns (allowed, remaining).

    For cost<=1 delegates to check_limit_with_count (backwards compat).
    For cost>1 uses BEGIN IMMEDIATE pattern to atomically check + insert cost rows.
    If the request would exceed the limit, no rows are inserted.
    """
    if cost <= 1:
        return check_limit_with_count(store_name, key, max_requests, window_seconds)

    _init()
    now = time.time()
    cutoff = now - window_seconds
    full_key = f"{store_name}:{key}"

    con = _get_conn(str(settings.api_db))
    try:
        con.execute("BEGIN IMMEDIATE")
        con.execute("DELETE FROM rate_limits WHERE key = ? AND ts <= ?", (full_key, cutoff))
        row = con.execute(
            "SELECT COUNT(*) FROM rate_limits WHERE key = ? AND ts > ?",
            (full_key, cutoff),
        ).fetchone()
        current = row[0] if row else 0
        if current + cost > max_requests:
            con.commit()
            return False, max(0, max_requests - current)
        con.executemany(
            "INSERT INTO rate_limits (key, ts) VALUES (?, ?)",
            [(full_key, now) for _ in range(cost)],
        )
        con.commit()
        return True, max(0, max_requests - current - cost)
    except Exception:
        con.rollback()
        raise


async def aconsume_credits(
    store_name: str, key: str, cost: int, max_requests: int, window_seconds: int = 3600
) -> tuple[bool, int]:
    return await run_in_threadpool(consume_credits, store_name, key, cost, max_requests, window_seconds)


def get_reset_time(store_name: str, key: str, window_seconds: int = 3600) -> int:
    """Seconds until the oldest request in the window expires."""
    _init()
    now = time.time()
    cutoff = now - window_seconds
    full_key = f"{store_name}:{key}"

    with get_api_db() as con:
        row = con.execute(
            "SELECT MIN(ts) FROM rate_limits WHERE key = ? AND ts > ?",
            (full_key, cutoff),
        ).fetchone()
        if not row or row[0] is None:
            return 0
        return max(0, int(row[0] + window_seconds - now))


async def aget_reset_time(store_name: str, key: str, window_seconds: int = 3600) -> int:
    return await run_in_threadpool(get_reset_time, store_name, key, window_seconds)


def reset(store_name: str | None = None) -> None:
    """Reset one or all stores (for testing)."""
    _init()
    with get_api_db() as con:
        if store_name:
            con.execute("DELETE FROM rate_limits WHERE key LIKE ?", (f"{store_name}:%",))
        else:
            con.execute("DELETE FROM rate_limits")


def refund(store_name: str, key: str) -> None:
    """Remove the most recent timestamp from a rate limit key (quota refund)."""
    _init()
    full_key = f"{store_name}:{key}"
    with get_api_db() as con:
        row = con.execute(
            "SELECT rowid FROM rate_limits WHERE key = ? ORDER BY ts DESC LIMIT 1",
            (full_key,),
        ).fetchone()
        if row:
            con.execute("DELETE FROM rate_limits WHERE rowid = ?", (row[0],))


async def arefund(store_name: str, key: str) -> None:
    await run_in_threadpool(refund, store_name, key)


def cleanup_expired(max_age_seconds: int = 7200) -> int:
    """Remove all expired entries older than max_age. Call periodically."""
    _init()
    cutoff = time.time() - max_age_seconds
    with get_api_db() as con:
        cur = con.execute("DELETE FROM rate_limits WHERE ts <= ?", (cutoff,))
        return cur.rowcount
