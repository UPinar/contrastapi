"""HTTP/validation/generic exception handlers.

Call `register_exception_handlers(app)` to wire them onto a FastAPI app.

Error envelope shape mirrors MCP `ErrorDetail`
(`{"error": {"code", "message", "retry_after_seconds", "upgrade_url",
"docs_url"}}`). Top-level extension fields (`hint`, `tier`, `limit`,
`upgrade`, `field`, `received`, `suggestion`, `support`, `reset_in`) keep
their pre-1.22.2 names so existing consumers continue parsing them.
"""

import logging

from auth import AuthCtx, extract_key
from config import FREE_HOURLY_LIMIT, PRO_HOURLY_LIMIT, UPGRADE_URL
from core.metrics import _sanitize_path
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("contrastapi")

ENDPOINT_HINTS = [
    ("/v1/code/", "Did you mean /v1/check/secrets or /v1/check/injection?"),
    ("/v1/domain/http", "Don't include http:// — use just the domain: /v1/domain/example.com"),
    ("/v1/domain/", "Include a domain: /v1/domain/example.com"),
    ("/v1/cve/", "Usage: /v1/cve/CVE-2024-3094 or /v1/cves?keyword=apache"),
    ("/v1/exploit/", "Include a CVE ID: /v1/exploit/CVE-2024-3094"),
    ("/v1/tech/", "Include a domain: /v1/tech/example.com"),
    ("/v1/dns/", "Include a domain: /v1/dns/example.com"),
    ("/v1/ssl/", "Include a domain: /v1/ssl/example.com"),
    ("/v1/whois/", "Include a domain: /v1/whois/example.com"),
    ("/v1/subdomains/", "Include a domain: /v1/subdomains/example.com"),
    ("/v1/certs/", "Include a domain: /v1/certs/example.com"),
    ("/v1/threat/", "Include a domain: /v1/threat/example.com"),
    ("/v1/monitor/", "Include a domain: /v1/monitor/example.com"),
    ("/v1/ip/", "Include an IP address: /v1/ip/8.8.8.8"),
    ("/v1/asn/", "Include an ASN or IP: /v1/asn/AS13335 or /v1/asn/8.8.8.8"),
    ("/v1/ioc/", "Include an indicator (IP, domain, or hash): /v1/ioc/1.2.3.4"),
    ("/v1/hash/", "Include a file hash (MD5/SHA1/SHA256): /v1/hash/abc123..."),
    ("/v1/password/", "GET /v1/password/{sha1_hash} — provide full SHA1 hash (40 hex chars)"),
    ("/v1/phishing/", "GET /v1/phishing/{url} — e.g., /v1/phishing/https://example.com"),
    ("/v1/phone/", "Include a phone number with country code: /v1/phone/+905551234567"),
    ("/v1/email/", "Include an email: /v1/email/mx/user@example.com or /v1/email/disposable/user@example.com"),
    ("/v1/check/", "POST endpoints: /v1/check/secrets, /v1/check/headers, /v1/check/injection, /v1/check/dependencies"),
    ("/v1/scan/", "GET /v1/scan/headers/{domain} — e.g., /v1/scan/headers/example.com"),
    (
        "/v1/",
        "Full docs: https://github.com/UPinar/contrastapi/blob/main/docs/ENDPOINTS.md — "
        "Try: /v1/domain/example.com, /v1/cve/CVE-2024-3094, /v1/ip/8.8.8.8",
    ),
]
ENDPOINT_HINT_DEFAULT = ENDPOINT_HINTS[-1][1]


def _upgrade_cta() -> dict:
    return {
        "pro_limit": PRO_HOURLY_LIMIT,
        "url": UPGRADE_URL,
        "message": f"Designed for automation — unlock {PRO_HOURLY_LIMIT} req/hr with Pro ($15/mo).",
    }


_STATUS_TO_ERROR_CODE: dict[int, str] = {
    400: "invalid_argument",
    401: "auth_required",
    403: "tier_limit",
    404: "not_found",
    405: "invalid_argument",
    422: "invalid_argument",
    429: "rate_limit_exceeded",
    500: "internal_error",
    502: "upstream_error",
    504: "upstream_timeout",
}
_DOCS_URL = "https://github.com/UPinar/contrastapi/blob/main/docs/ENDPOINTS.md"
# ErrorDetail.message has max_length=500 (schemas.py); HTTPException.detail is
# free-form so guard at the wire boundary, mirroring MCP's `mcp_tool_safe`.
_ERROR_MESSAGE_MAX_LEN = 500
# Mirror mcp_server.py's retry-after cap: 3600s prevents hostile upstream from
# pinning a client into multi-hour backoff.
_RETRY_AFTER_MAX_SECONDS = 3600


def _error_envelope(
    *,
    code: str,
    message: str,
    retry_after_seconds: int | None = None,
    upgrade_url: str | None = None,
    docs_url: str | None = None,
) -> dict:
    body: dict = {"code": code, "message": message[:_ERROR_MESSAGE_MAX_LEN]}
    if retry_after_seconds is not None:
        body["retry_after_seconds"] = max(0, min(retry_after_seconds, _RETRY_AFTER_MAX_SECONDS))
    if upgrade_url is not None:
        body["upgrade_url"] = upgrade_url
    if docs_url is not None:
        body["docs_url"] = docs_url
    return body


async def api_error_handler(request: Request, exc: StarletteHTTPException):
    """All errors return JSON with helpful hints."""
    code = _STATUS_TO_ERROR_CODE.get(exc.status_code, "upstream_error")
    message = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    path = request.url.path

    error_kwargs: dict = {"code": code, "message": message}
    content: dict = {}

    if exc.status_code == 404:
        for prefix, hint in ENDPOINT_HINTS:
            if path.startswith(prefix):
                content["hint"] = hint
                break
        else:
            content["hint"] = ENDPOINT_HINT_DEFAULT

    if exc.status_code == 405:
        content["hint"] = f"Method {request.method} not allowed. Try POST for /v1/check/* endpoints."

    if exc.status_code == 429:
        # A per-target throttle (robots_txt / seo_audit / brand_assets /
        # redirect_chain / contrast_scan) raises HTTPException(429, headers=
        # {"Retry-After": "<=60>"}) — a SERVER-side per-domain limit, NOT the
        # caller's hourly quota. The caller already passed require_auth, so
        # request.state.auth holds the *hourly* reset (~3599); honoring that here
        # would tell a client to back off ~1h for a sub-minute throttle and
        # mislabel it as a rate-limit with a Pro upsell. Detect the throttle by
        # its explicit Retry-After header (caller-quota 429s never set one) and
        # pass it through verbatim.
        throttle_retry = (exc.headers or {}).get("Retry-After")
        if throttle_retry is not None:
            retry_seconds = int(throttle_retry)
            error_kwargs["retry_after_seconds"] = retry_seconds
            content["error_code"] = "target_throttle"
            content["reset_in"] = retry_seconds
            content["error"] = _error_envelope(**error_kwargs)
            resp = JSONResponse(status_code=429, content=content)
            resp.headers["Retry-After"] = str(retry_seconds)
            return resp

        # Faz 3: read from request.state.auth (AuthCtx) — populated by
        # authenticate_sync BEFORE the 429 raise. Fallback for non-auth 429s
        # (nginx tarpit zone) where AuthCtx wasn't built.
        auth_ctx_429: AuthCtx | None = getattr(request.state, "auth", None)
        reset_seconds = auth_ctx_429.ratelimit_reset if auth_ctx_429 else 0
        error_kwargs["retry_after_seconds"] = reset_seconds
        content["error_code"] = "rate_limit"
        content["reset_in"] = reset_seconds
        is_free = (auth_ctx_429.tier == "free") if auth_ctx_429 else (extract_key(request) is None)
        if is_free:
            content["tier"] = "free"
            content["limit"] = FREE_HOURLY_LIMIT
            content["upgrade"] = _upgrade_cta()
            error_kwargs["upgrade_url"] = UPGRADE_URL
        else:
            content["tier"] = "pro"
            content["limit"] = PRO_HOURLY_LIMIT
            content["support"] = "Contact us for higher limits: contact@contrastcyber.com"
        content["error"] = _error_envelope(**error_kwargs)
        resp = JSONResponse(status_code=429, content=content)
        resp.headers["Retry-After"] = str(reset_seconds)
        return resp

    content["error"] = _error_envelope(**error_kwargs)
    return JSONResponse(status_code=exc.status_code, content=content)


async def validation_error_handler(request: Request, exc: RequestValidationError):
    err = exc.errors()[0] if exc.errors() else {}
    loc = err.get("loc", ())
    field = loc[-1] if loc else None
    received = err.get("input")
    reason = err.get("msg", "Validation failed").removeprefix("Value error, ")[:_ERROR_MESSAGE_MAX_LEN]
    path = request.url.path
    suggestion = ENDPOINT_HINT_DEFAULT
    for prefix, hint in ENDPOINT_HINTS:
        if path.startswith(prefix):
            suggestion = hint
            break
    content: dict = {
        "error": _error_envelope(
            code="invalid_argument",
            message=reason,
            docs_url=_DOCS_URL,
        ),
        "reason": reason,
        "suggestion": suggestion,
        "docs": _DOCS_URL,
    }
    if field:
        content["field"] = field
    if received is not None and isinstance(received, str) and len(received) < 200:
        content["received"] = received
    if extract_key(request) is None:
        content["upgrade"] = _upgrade_cta()
        content["error"]["upgrade_url"] = UPGRADE_URL
    return JSONResponse(status_code=422, content=content)


async def generic_error_handler(request: Request, exc: Exception):
    """Catch-all — never leak stack traces, internal paths, or upstream URLs."""
    logger.error(
        "Unhandled error on %s %s: %s",
        request.method,
        _sanitize_path(request.url.path),
        type(exc).__name__,
    )
    return JSONResponse(
        status_code=500,
        content={"error": _error_envelope(code="internal_error", message="Internal server error")},
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Wire the three handlers onto a FastAPI app."""
    app.add_exception_handler(StarletteHTTPException, api_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(Exception, generic_error_handler)
