"""Authentication for ContrastAPI

Two modes:
  - Keyless: rate limited by IP (FREE_HOURLY_LIMIT req/hr — see config.py)
  - API key: cc_ prefixed key in Authorization header (PRO_HOURLY_LIMIT req/hr)

Architecture (Faz 3 + Faz 4):
  - AuthCtx frozen dataclass — type-safe auth context, single source of truth
    for tier/key_hash/client_ip + 4 ratelimit_* fields. Stashed on
    request.state.auth before raising 401/429.
  - aauthenticate() — async core used by require_auth's FastAPI dep. Awaits
    aget_api_key / aconsume_credits / aget_reset_time / atouch_api_key /
    alog_usage; pure-CPU helpers (hash_key, hash_client_ip, extract_key,
    _privacy_opt_out, _stash) stay direct calls.
  - authenticate_sync() — sync core preserved for the MCP ASGI gate (sync
    inside ASGI middleware where async I/O isn't available) and for
    test_auth.py's direct sync-core invariants.
  - require_auth(endpoint, cost) — FastAPI dependency factory used by every
    public REST route. Routes write `auth: Annotated[AuthCtx, Depends(require_auth("/v1/<path>"))]`
    to receive a populated AuthCtx + auto-emit ContrastAPIKey security in OpenAPI.

Legacy `authenticate()` wrapper removed in Batch 3f (2026-05-03); Batch 4e
(2026-05-03) replaced `require_auth`'s `run_in_threadpool(authenticate_sync,
...)` dispatch with a direct `await aauthenticate(...)`. Mid-migration shims
only — never permanent backward-compat.
"""

import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Literal

from config import (
    FIRST_SWIPE_ENABLED,
    FIRST_SWIPE_MAX_TOOLS,
    FREE_HOURLY_LIMIT,
    KEY_LENGTH,
    KEY_PREFIX,
    PRO_HOURLY_LIMIT,
    UPGRADE_URL,
)
from db import (
    aget_api_key,
    alog_usage,
    atouch_api_key,
    get_api_key,
    hash_client_ip,
    log_usage,
    touch_api_key,
)
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from ratelimit import aconsume_credits, aget_reset_time, consume_credits, get_reset_time, try_redeem_first_swipe

# OpenAPI security scheme. auto_error=False so /v1/* keyless endpoints stay
# reachable without an Authorization header — actual auth + rate-limit decision
# is in authenticate_sync(). FastAPI emits this scheme in /openapi.json
# securitySchemes and attaches `security: [{ContrastAPIKey: []}]` to every
# route that has require_auth() as a dependency.
_bearer_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="ContrastAPIKey",
    description=(
        f"Optional. Pass `Authorization: Bearer cc_<48 hex>` (or "
        f"`X-API-Key: cc_<48 hex>`) for Pro tier ({PRO_HOURLY_LIMIT}/hr). "
        f"Omit for keyless Free tier ({FREE_HOURLY_LIMIT}/hr/IP). "
        f"Get a key at {UPGRADE_URL}."
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
    # SHA-256 (not bcrypt/argon2) is deliberate: `key` is a high-entropy
    # random token, and key_hash is a deterministic DB lookup index. Salted
    # KDFs add no security for a ~192-bit random input and break indexed
    # lookup. CodeQL py/weak-sensitive-data-hashing #109 dismissed (won't fix).
    return hashlib.sha256(key.encode()).hexdigest()


# v1.33.x Opt 2 — per-process random token marking a trusted in-process hop
# (mcp_server._aget() -> /v1/*). Never logged, never in any response, never
# sent to external clients. os.environ-backed so the value is identical
# across the codebase's dual import paths (bare `auth` vs `app.auth`
# sys.path trap) AND across the 4 uvicorn workers (--workers 2 x @8002/
# @8003); a plain module-level secrets call differs per module instance /
# per process and silently breaks the trust check (v1.33.2 prod incident).
# CONTRASTAPI_INTERNAL_TOKEN is pre-populated in production via systemd
# EnvironmentFile; random fallback only fires in dev/test (single process).
INTERNAL_TRUST_TOKEN = os.environ.setdefault("CONTRASTAPI_INTERNAL_TOKEN", secrets.token_urlsafe(32))


def _is_trusted_internal(request: Request) -> str | None:
    """Return the already-resolved tier iff this is a trusted in-process hop.

    True only when X-Internal-Auth matches the process-shared token
    (timing-safe compare) AND X-Internal-Tier is "pro"/"free". The TCP peer
    is NOT checked: uvicorn's proxy_headers rewrites request.client.host
    from X-Forwarded-For on the in-process hop, so a loopback test fails for
    the forwarded request. nginx strips inbound X-Internal-* on every public
    location (the external-injection boundary); the secret token (never
    logged/echoed) is the sole, sufficient control. Returns tier else None.
    """
    tok = request.headers.get("x-internal-auth", "")
    if not tok or not secrets.compare_digest(tok, INTERNAL_TRUST_TOKEN):
        return None
    tier = request.headers.get("x-internal-tier", "")
    if tier not in ("pro", "free"):
        return None
    return tier


def extract_key(request: Request) -> str | None:
    """Extract API key from Authorization: Bearer cc_xxx or X-API-Key: cc_xxx header."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        if token.startswith(KEY_PREFIX) and len(token) == len(KEY_PREFIX) + KEY_LENGTH:
            return token
    api_key = request.headers.get("x-api-key", "").strip()
    if api_key.startswith(KEY_PREFIX) and len(api_key) == len(KEY_PREFIX) + KEY_LENGTH:
        return api_key
    return None


def _saw_bearer_attempt(request: Request) -> bool:
    # Distinguishes "user attempted Bearer cc_ but length wrong" (→ 401)
    # from "no Authorization header at all" (→ free tier). Without this,
    # malformed keys silently degrade to free tier and the customer never learns.
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return False
    return auth[7:].strip().startswith(KEY_PREFIX)


def _saw_apikey_attempt(request: Request) -> bool:
    # X-API-Key parity with _saw_bearer_attempt: a malformed X-API-Key
    # (starts cc_ but wrong length) must 401, not silently degrade to free.
    api_key = request.headers.get("x-api-key", "").strip()
    if not api_key:
        return False
    return api_key.startswith(KEY_PREFIX)


def _privacy_opt_out(request: Request) -> bool:
    """True if the client sent DNT: 1 or Sec-GPC: 1 — skip analytics logging.

    Rate limiting still applies (abuse protection); only the hashed-IP usage row
    is suppressed. Promised in /privacy section 3.
    """
    return request.headers.get("dnt") == "1" or request.headers.get("sec-gpc") == "1"


def _stash(request: Request, ctx: AuthCtx) -> None:
    """Stash AuthCtx on request.state for the middleware to read.

    Single source of truth — main.py middleware reads ratelimit_* fields from
    request.state.auth.* exclusively (no fallback after Batch 3f).
    """
    request.state.auth = ctx


def authenticate_sync(request: Request, endpoint: str, cost: int = 1, mcp_tool: str | None = None) -> AuthCtx:
    """Authenticate request synchronously. Returns AuthCtx.

    For Pro keys: verifies key, checks hourly limit (PRO_HOURLY_LIMIT).
    For keyless: checks IP hourly limit (FREE_HOURLY_LIMIT).

    On 401/429: stashes a minimal AuthCtx on request.state.auth BEFORE raising
    (so middleware has a single source of truth — no extract_key() fallback).

    Raises:
        HTTPException 401 — invalid key
        HTTPException 429 — rate limit exceeded
    """
    from validation import get_client_ip

    _trusted_tier = _is_trusted_internal(request)
    if _trusted_tier is not None:
        _lim = PRO_HOURLY_LIMIT if _trusted_tier == "pro" else FREE_HOURLY_LIMIT
        _ctx = AuthCtx(
            tier=_trusted_tier,
            key_hash=None,
            client_ip="127.0.0.1",
            ratelimit_limit=_lim,
            ratelimit_remaining=_lim,
            ratelimit_reset=0,
            ratelimit_cost=cost,
        )
        _stash(request, _ctx)
        return _ctx

    client_ip = get_client_ip(request)
    raw_key = extract_key(request)
    localhost = client_ip in ("127.0.0.1", "::1")

    if not raw_key and (_saw_bearer_attempt(request) or _saw_apikey_attempt(request)):
        ctx = AuthCtx(
            tier="pro",
            key_hash=None,
            client_ip=client_ip,
            ratelimit_limit=PRO_HOURLY_LIMIT,
            ratelimit_remaining=0,
            ratelimit_reset=0,
            ratelimit_cost=cost,
        )
        _stash(request, ctx)
        raise HTTPException(status_code=401, detail="Invalid API key")

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

    # v1.34.0 First-swipe: first keyless call to each distinct cost==1 MCP tool is
    # exempt from the hourly counter (one-time). mcp_tool is non-None only on the MCP
    # tools/call path (REST passes None). cost>1 composites excluded (real upstream $).
    # Identity buckets IPv6 to /64 so one /64 can't farm unlimited grants.
    from validation import swipe_ip_bucket

    swipe_key = f"free:{hash_client_ip(swipe_ip_bucket(client_ip))}"
    swipe = (
        not localhost
        and client_ip not in ("unknown", "")  # unidentifiable caller → no shared free grant
        and mcp_tool is not None
        and cost == 1
        and FIRST_SWIPE_ENABLED
        and try_redeem_first_swipe(swipe_key, mcp_tool, FIRST_SWIPE_MAX_TOOLS)
    )

    if not localhost and not swipe:
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
                detail=f"Rate limit exceeded ({limit}/hr). Upgrade to Pro ({PRO_HOURLY_LIMIT}/hr): {UPGRADE_URL}",
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


async def aauthenticate(request: Request, endpoint: str, cost: int = 1) -> AuthCtx:
    """Async authentication path used by require_auth's FastAPI dep.

    REST-only: intentionally has NO `mcp_tool` param and NO first-swipe logic — the
    swipe is MCP-only and the MCP gate uses the sync `authenticate_sync`. Do not port
    the swipe branch here without re-evaluating the MCP-only invariant.

    Mirrors authenticate_sync but awaits the aXxx helpers directly, eliminating
    the run_in_threadpool wrapper layer that previously dispatched the entire
    sync function. Pure-CPU helpers (hash_key, hash_client_ip, extract_key,
    _privacy_opt_out, _stash) stay direct calls — threadpool overhead would
    dwarf their sub-microsecond work.
    """
    from validation import get_client_ip

    _trusted_tier = _is_trusted_internal(request)
    if _trusted_tier is not None:
        _lim = PRO_HOURLY_LIMIT if _trusted_tier == "pro" else FREE_HOURLY_LIMIT
        _ctx = AuthCtx(
            tier=_trusted_tier,
            key_hash=None,
            client_ip="127.0.0.1",
            ratelimit_limit=_lim,
            ratelimit_remaining=_lim,
            ratelimit_reset=0,
            ratelimit_cost=cost,
        )
        _stash(request, _ctx)
        return _ctx

    client_ip = get_client_ip(request)
    raw_key = extract_key(request)
    localhost = client_ip in ("127.0.0.1", "::1")

    if not raw_key and (_saw_bearer_attempt(request) or _saw_apikey_attempt(request)):
        ctx = AuthCtx(
            tier="pro",
            key_hash=None,
            client_ip=client_ip,
            ratelimit_limit=PRO_HOURLY_LIMIT,
            ratelimit_remaining=0,
            ratelimit_reset=0,
            ratelimit_cost=cost,
        )
        _stash(request, ctx)
        raise HTTPException(status_code=401, detail="Invalid API key")

    if raw_key:
        kh = hash_key(raw_key)
        key_row = await aget_api_key(kh)
        if key_row is None:
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
            allowed, remaining = await aconsume_credits("api", store_key, cost, limit)
            reset_at = await aget_reset_time("api", store_key)
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

        await atouch_api_key(kh)
        if not localhost and not _privacy_opt_out(request):
            await alog_usage(client_ip, endpoint, key_hash=kh)

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

    limit = FREE_HOURLY_LIMIT
    store_key = f"free:{hash_client_ip(client_ip)}"

    if not localhost:
        allowed, remaining = await aconsume_credits("api", store_key, cost, limit)
        reset_at = await aget_reset_time("api", store_key)
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
                detail=f"Rate limit exceeded ({limit}/hr). Upgrade to Pro ({PRO_HOURLY_LIMIT}/hr): {UPGRADE_URL}",
            )
    else:
        remaining = limit
        reset_at = 0

    if not localhost and not _privacy_opt_out(request):
        await alog_usage(client_ip, endpoint)

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

    Batch 4e: dispatches to aauthenticate() which awaits the aXxx DB and
    rate-limit helpers directly. The previous run_in_threadpool wrapper that
    moved the whole sync function off the event loop is no longer needed —
    each individual I/O call now offloads independently.
    """

    async def _dep(
        request: Request,
        # Bound to surface ContrastAPIKey scheme in /openapi.json. We intentionally
        # ignore the parsed credential here — aauthenticate() re-extracts via
        # extract_key() (validates length + cc_ prefix). Two-pass parse keeps the
        # security UI signal without changing the keyless code path.
        _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    ) -> AuthCtx:
        return await aauthenticate(request, endpoint, cost)

    _dep.__name__ = f"require_auth({endpoint})"
    return _dep
