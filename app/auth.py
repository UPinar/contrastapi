"""Authentication for ContrastAPI

Two modes:
  - Keyless: rate limited by IP (100 req/hr)
  - API key: cc_ prefixed key in Authorization header (1000 req/hr)
"""

import hashlib
import secrets

from config import FREE_HOURLY_LIMIT, KEY_LENGTH, KEY_PREFIX, PRO_HOURLY_LIMIT
from db import get_api_key, log_usage, touch_api_key
from fastapi import HTTPException, Request
from ratelimit import check_limit_with_count, get_reset_time


def generate_key() -> str:
    """Generate a new API key: cc_ + 48 hex chars."""
    return KEY_PREFIX + secrets.token_hex(KEY_LENGTH // 2)


def hash_key(key: str) -> str:
    """SHA-256 hash of the raw key."""
    return hashlib.sha256(key.encode()).hexdigest()


def _set_ratelimit_state(request: Request, limit: int, remaining: int, reset: int) -> None:
    """Store rate limit info on request.state for the middleware to read."""
    request.state.ratelimit_limit = limit
    request.state.ratelimit_remaining = max(0, remaining)
    request.state.ratelimit_reset = reset


def extract_key(request: Request) -> str | None:
    """Extract API key from Authorization: Bearer cc_xxx header."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        if token.startswith(KEY_PREFIX) and len(token) == len(KEY_PREFIX) + KEY_LENGTH:
            return token
    return None


def authenticate(request: Request, endpoint: str) -> dict:
    """Authenticate request. Returns auth context dict.

    For Pro keys: verifies key, checks hourly limit (1000/hr).
    For keyless: checks IP hourly limit (100/hr).

    Returns:
        {"tier": "pro"|"free", "key_hash": str|None, "client_ip": str}

    Raises:
        HTTPException 401 — invalid key
        HTTPException 429 — rate limit exceeded
    """
    from validation import get_client_ip

    client_ip = get_client_ip(request)
    raw_key = extract_key(request)

    localhost = client_ip in ("127.0.0.1", "::1")

    if raw_key:
        # Pro key authentication
        kh = hash_key(raw_key)
        key_row = get_api_key(kh)
        if key_row is None:
            raise HTTPException(status_code=401, detail="Invalid API key")

        limit = PRO_HOURLY_LIMIT
        advertised_limit = limit * 2
        store_key = f"pro:{kh}"

        if not localhost:
            # Check Pro rate limit (sliding window)
            allowed, remaining = check_limit_with_count("api", store_key, limit)
            if not allowed:
                _set_ratelimit_state(request, advertised_limit, 0, get_reset_time("api", store_key))
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded ({advertised_limit}/hr). Contact support for higher limits.",
                )
            _set_ratelimit_state(request, advertised_limit, remaining * 2, get_reset_time("api", store_key))
        else:
            _set_ratelimit_state(request, advertised_limit, advertised_limit, 0)

        touch_api_key(kh)
        log_usage(client_ip, endpoint, key_hash=kh)
        return {"tier": "pro", "key_hash": kh, "client_ip": client_ip}

    # Keyless — IP rate limit (sliding window)
    limit = FREE_HOURLY_LIMIT
    advertised_limit = limit * 2
    store_key = f"free:{client_ip}"

    if not localhost:
        allowed, remaining = check_limit_with_count("api", store_key, limit)
        if not allowed:
            _set_ratelimit_state(request, advertised_limit, 0, get_reset_time("api", store_key))
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded ({advertised_limit}/hr). "
                "Get a Pro key at api.contrastcyber.com for higher limits.",
            )
        _set_ratelimit_state(request, advertised_limit, remaining * 2, get_reset_time("api", store_key))
    else:
        _set_ratelimit_state(request, advertised_limit, advertised_limit, 0)

    log_usage(client_ip, endpoint)
    return {"tier": "free", "key_hash": None, "client_ip": client_ip}
