"""SQLite-based rate limiting for ContrastAPI

Persistent sliding window rate limiter shared across all workers.
Uses api.db rate_limits table with WAL mode for concurrent access.

Replaces the previous in-memory limiter which:
  - Reset on worker restart
  - Was per-worker (2 workers = 2x the real limit)
"""

import time

from db import get_api_db


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


def cleanup_expired(max_age_seconds: int = 7200) -> int:
    """Remove all expired entries older than max_age. Call periodically."""
    _init()
    cutoff = time.time() - max_age_seconds
    with get_api_db() as con:
        cur = con.execute("DELETE FROM rate_limits WHERE ts <= ?", (cutoff,))
        return cur.rowcount
