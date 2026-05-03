"""Authentication for ContrastAPI

Two modes:
  - Keyless: rate limited by IP (100 req/hr)
  - API key: cc_ prefixed key in Authorization header (1000 req/hr)

Faz 3 refactor:
  - AuthCtx frozen dataclass — type-safe auth context, replaces dict
  - authenticate_sync() — sync core, returns AuthCtx, sets request.state.auth
    BEFORE raising 401/429 (middleware reads from a single source of truth)
  - require_auth(endpoint, cost) — FastAPI dependency factory; routes use
    `Annotated[AuthCtx, Depends(require_auth("/v1/cve"))]`
  - authenticate() — legacy dict-returning wrapper, kept for un-migrated
    callers (MCP ASGI gate + tests + main.py meta routes); removed in Batch 3f
"""

import hashlib
import secrets
from dataclasses import dataclass
from typing import Literal

from config import FREE_HOURLY_LIMIT, KEY_LENGTH, KEY_PREFIX, PRO_HOURLY_LIMIT
from db import get_api_key, hash_client_ip, log_usage, touch_api_key
from fastapi import Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from ratelimit import consume_credits, get_reset_time

# OpenAPI security scheme. auto_error=False so /v1/* keyless endpoints stay
# reachable without an Authorization header — actual auth + rate-limit decision
# is in authenticate_sync(). FastAPI emits this scheme in /openapi.json
# securitySchemes and attaches `security: [{ContrastAPIKey: []}]` to every
# route that has require_auth() as a dependency.
_bearer_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="ContrastAPIKey",
    description=(
        "Optional. Pass `Authorization: Bearer cc_<48 hex>` for Pro tier "
        "(1000/hr). Omit for keyless Free tier (100/hr/IP). Get a key at "
        "https://contrastcyber.com/pricing."
    ),
)


@dataclass(frozen=True)
class AuthCtx:
    """Per-request authentication + rate-limit context.

    Populated by authenticate_sync() and stashed on request.state.auth.
    Frozen so route handlers can't mutate it. Middleware reads ratelimit_*
    fields to set X-RateLimit-* response headers.
    """

    tier: Literal["pro", "free"]
    key_hash: str | None
    client_ip: str
    ratelimit_limit: int
    ratelimit_remaining: int
    ratelimit_reset: int
    ratelimit_cost: int


def generate_key() -> str:
    """Generate a new API key: cc_ + 48 hex chars."""
    return KEY_PREFIX + secrets.token_hex(KEY_LENGTH // 2)


def hash_key(key: str) -> str:
    """SHA-256 hash of the raw key."""
    return hashlib.sha256(key.encode()).hexdigest()


def _set_ratelimit_state(request: Request, limit: int, remaining: int, reset: int) -> None:
    """Store rate limit info on request.state for the middleware to read.

    Kept during Faz 3 migration: main.py middleware (line 350+) still reads
    request.state.ratelimit_limit/remaining/reset/tier/cost. Batch 3f will
    migrate the middleware to read from request.state.auth.* exclusively and
    this helper will be deleted.
    """
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


def _privacy_opt_out(request: Request) -> bool:
    """True if the client sent DNT: 1 or Sec-GPC: 1 — skip analytics logging.

    Rate limiting still applies (abuse protection); only the hashed-IP usage row
    is suppressed. Promised in /privacy section 3.
    """
    return request.headers.get("dnt") == "1" or request.headers.get("sec-gpc") == "1"


def _stash(request: Request, ctx: AuthCtx) -> None:
    """Set both new (request.state.auth) and legacy (request.state.ratelimit_*)
    state. Legacy fields removed in Batch 3f when middleware migrates."""
    request.state.auth = ctx
    request.state.ratelimit_tier = ctx.tier
    request.state.ratelimit_cost = ctx.ratelimit_cost
    _set_ratelimit_state(request, ctx.ratelimit_limit, ctx.ratelimit_remaining, ctx.ratelimit_reset)


def authenticate_sync(request: Request, endpoint: str, cost: int = 1) -> AuthCtx:
    """Authenticate request synchronously. Returns AuthCtx.

    For Pro keys: verifies key, checks hourly limit (1000/hr).
    For keyless: checks IP hourly limit (100/hr).

    On 401/429: stashes a minimal AuthCtx on request.state.auth BEFORE raising
    (so middleware has a single source of truth — no extract_key() fallback).

    Raises:
        HTTPException 401 — invalid key
        HTTPException 429 — rate limit exceeded
    """
    from validation import get_client_ip

    client_ip = get_client_ip(request)
    raw_key = extract_key(request)
    localhost = client_ip in ("127.0.0.1", "::1")

    if raw_key:
        kh = hash_key(raw_key)
        key_row = get_api_key(kh)
        if key_row is None:
            # 401 path — populate auth state for middleware before raising.
            ctx = AuthCtx(
                tier="pro",
                key_hash=kh,
                client_ip=client_ip,
                ratelimit_limit=PRO_HOURLY_LIMIT,
                ratelimit_remaining=0,
                ratelimit_reset=0,
                ratelimit_cost=cost,
            )
            _stash(request, ctx)
            raise HTTPException(status_code=401, detail="Invalid API key")

        limit = PRO_HOURLY_LIMIT
        store_key = f"pro:{kh}"

        if not localhost:
            allowed, remaining = consume_credits("api", store_key, cost, limit)
            reset_at = get_reset_time("api", store_key)
            if not allowed:
                ctx = AuthCtx(
                    tier="pro",
                    key_hash=kh,
                    client_ip=client_ip,
                    ratelimit_limit=limit,
                    ratelimit_remaining=0,
                    ratelimit_reset=reset_at,
                    ratelimit_cost=cost,
                )
                _stash(request, ctx)
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded ({limit}/hr). Contact support for higher limits.",
                )
        else:
            remaining = limit
            reset_at = 0

        touch_api_key(kh)
        if not localhost and not _privacy_opt_out(request):
            log_usage(client_ip, endpoint, key_hash=kh)

        ctx = AuthCtx(
            tier="pro",
            key_hash=kh,
            client_ip=client_ip,
            ratelimit_limit=limit,
            ratelimit_remaining=remaining,
            ratelimit_reset=reset_at,
            ratelimit_cost=cost,
        )
        _stash(request, ctx)
        return ctx

    # Keyless — IP rate limit (sliding window). Hash IP to keep rate_limits
    # table privacy-safe (raw IP would otherwise sit on disk for up to 1h).
    limit = FREE_HOURLY_LIMIT
    store_key = f"free:{hash_client_ip(client_ip)}"

    if not localhost:
        allowed, remaining = consume_credits("api", store_key, cost, limit)
        reset_at = get_reset_time("api", store_key)
        if not allowed:
            ctx = AuthCtx(
                tier="free",
                key_hash=None,
                client_ip=client_ip,
                ratelimit_limit=limit,
                ratelimit_remaining=0,
                ratelimit_reset=reset_at,
                ratelimit_cost=cost,
            )
            _stash(request, ctx)
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded ({limit}/hr). Upgrade to Pro (1000/hr): https://contrastcyber.com/pricing",
            )
    else:
        remaining = limit
        reset_at = 0

    if not localhost and not _privacy_opt_out(request):
        log_usage(client_ip, endpoint)

    ctx = AuthCtx(
        tier="free",
        key_hash=None,
        client_ip=client_ip,
        ratelimit_limit=limit,
        ratelimit_remaining=remaining,
        ratelimit_reset=reset_at,
        ratelimit_cost=cost,
    )
    _stash(request, ctx)
    return ctx


def require_auth(endpoint: str, cost: int = 1):
    """FastAPI dependency factory: returns an async dep that authenticates
    + rate-limits the request and yields an AuthCtx.

    Usage:
        @router.get("/v1/cve/{cve_id}")
        def cve_lookup(
            cve_id: str,
            auth: Annotated[AuthCtx, Depends(require_auth("/v1/cve"))],
        ):
            ...

    The closure is created once at function-definition time, so FastAPI's
    per-request dependency cache uses the same callable identity across
    requests — multiple Depends() of the same endpoint string don't re-run.

    The sync work (DB lookup, sliding-window rate limit) runs in a threadpool
    so async event-loop isn't blocked. Faz 4 plans to make this natively async.
    """

    async def _dep(
        request: Request,
        # Bound to surface ContrastAPIKey scheme in /openapi.json. We intentionally
        # ignore the parsed credential here — authenticate_sync() re-extracts via
        # extract_key() (validates length + cc_ prefix). Two-pass parse keeps the
        # security UI signal without changing the keyless code path.
        _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    ) -> AuthCtx:
        return await run_in_threadpool(authenticate_sync, request, endpoint, cost)

    _dep.__name__ = f"require_auth({endpoint})"
    return _dep


def authenticate(request: Request, endpoint: str, cost: int = 1) -> dict:
    """Legacy dict-returning wrapper. Use authenticate_sync() (returns AuthCtx)
    or require_auth() (FastAPI dep) instead.

    Kept during Faz 3 migration for:
      - main.py meta routes /v1/usage, /v1/privacy/my-data (Batch 3f)
      - main.py MCP ASGI gate at line 1808 (Batch 3f)
      - tests/test_auth.py (Batch 3f)

    REMOVED in Batch 3f. NO permanent backward-compat.
    """
    ctx = authenticate_sync(request, endpoint, cost)
    return {"tier": ctx.tier, "key_hash": ctx.key_hash, "client_ip": ctx.client_ip}
