"""Thread-safe in-memory rate limiting for ContrastAPI

Sliding window rate limiter used for both API key and IP-based
rate limiting. Automatic cleanup of stale keys.
"""

import time
import threading
from collections import deque

_lock = threading.Lock()
_MAX_STORE_KEYS = 10000

# Generic sliding window stores: name → {key → deque of timestamps}
_stores: dict[str, dict[str, deque]] = {}


def _get_store(name: str) -> dict[str, deque]:
    """Get or create a named rate limit store."""
    if name not in _stores:
        _stores[name] = {}
    return _stores[name]


def _expire_deque(dq: deque, cutoff: float) -> None:
    """Remove expired timestamps from front of deque."""
    while dq and dq[0] < cutoff:
        dq.popleft()


def _cleanup_store(store: dict[str, deque], cutoff: float) -> None:
    """Remove stale keys and enforce max store size."""
    stale = [k for k, v in store.items() if not v or v[-1] < cutoff]
    for k in stale:
        del store[k]
    if len(store) > _MAX_STORE_KEYS:
        by_age = sorted(store.items(), key=lambda kv: kv[1][-1] if kv[1] else 0)
        for k, _ in by_age[:len(store) - _MAX_STORE_KEYS]:
            del store[k]


def check_limit(store_name: str, key: str, max_requests: int,
                window_seconds: int = 3600) -> bool:
    """Check sliding window rate limit. Returns True if allowed.

    Args:
        store_name: Name of the rate limit store (e.g. "domain", "endpoint")
        key: The key to rate limit (e.g. domain name, IP)
        max_requests: Maximum requests allowed in the window
        window_seconds: Window size in seconds (default: 1 hour)
    """
    now = time.time()
    cutoff = now - window_seconds

    with _lock:
        store = _get_store(store_name)
        _cleanup_store(store, cutoff)

        if key not in store:
            store[key] = deque()
        dq = store[key]
        _expire_deque(dq, cutoff)

        if len(dq) >= max_requests:
            return False
        dq.append(now)
        return True


def get_count(store_name: str, key: str, window_seconds: int = 3600) -> int:
    """Get current request count for a key in a store."""
    now = time.time()
    cutoff = now - window_seconds

    with _lock:
        store = _get_store(store_name)
        dq = store.get(key)
        if dq is None:
            return 0
        _expire_deque(dq, cutoff)
        return len(dq)


def get_reset_time(store_name: str, key: str, window_seconds: int = 3600) -> int:
    """Seconds until the oldest request in the window expires (i.e. a slot frees up)."""
    now = time.time()
    cutoff = now - window_seconds

    with _lock:
        store = _get_store(store_name)
        dq = store.get(key)
        if not dq:
            return 0
        _expire_deque(dq, cutoff)
        if not dq:
            return 0
        return max(0, int(dq[0] + window_seconds - now))


def reset(store_name: str | None = None) -> None:
    """Reset one or all stores (for testing)."""
    with _lock:
        if store_name:
            _stores.pop(store_name, None)
        else:
            _stores.clear()


def check_limit_with_count(store_name: str, key: str, max_requests: int,
                           window_seconds: int = 3600) -> tuple[bool, int]:
    """Check rate limit and return (allowed, remaining) atomically."""
    with _lock:
        store = _get_store(store_name)
        now = time.time()
        cutoff = now - window_seconds
        _cleanup_store(store, cutoff)
        if key not in store:
            store[key] = deque()
        dq = store[key]
        _expire_deque(dq, cutoff)
        if len(dq) >= max_requests:
            return False, 0
        dq.append(now)
        return True, max_requests - len(dq)


def refund(store_name: str, key: str) -> None:
    """Remove the most recent timestamp from a rate limit key (quota refund on failure)."""
    with _lock:
        store = _get_store(store_name)
        if key in store and store[key]:
            store[key].pop()
