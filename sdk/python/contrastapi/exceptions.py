"""Exception hierarchy for ContrastAPI SDK.

Mirrors the server-side `app.exceptions.AppException` tree so SDK users can
catch typed exceptions instead of inspecting status codes. Each instance carries
the parsed `ErrorDetail` envelope (dict) from the wire — `.code`, `.message`,
`.retry_after_seconds`, `.upgrade_url`, `.docs_url`.
"""

from __future__ import annotations

from typing import Any

# Wire-boundary defensive caps mirror server-side `_ERROR_MESSAGE_MAX_LEN` /
# `_RETRY_AFTER_MAX_SECONDS` (see app/main.py). Server already enforces these,
# but the SDK refuses to trust an untrusted response payload.
_MESSAGE_MAX_LEN = 500
_RETRY_AFTER_MAX_SECONDS = 3600


class ContrastAPIError(Exception):
    """Base exception for all ContrastAPI SDK errors."""

    code: str = "internal_error"
    status_code: int | None = None

    def __init__(
        self,
        message: Any,
        *,
        status_code: int | None = None,
        code: str | None = None,
        retry_after_seconds: int | None = None,
        upgrade_url: str | None = None,
        docs_url: str | None = None,
        extras: dict[str, Any] | None = None,
    ) -> None:
        # CRIT (review): coerce to str — server response could send None / int / dict.
        coerced = "" if message is None else str(message)
        if len(coerced) > _MESSAGE_MAX_LEN:
            coerced = coerced[:_MESSAGE_MAX_LEN]
        super().__init__(coerced)
        self.message = coerced
        if status_code is not None:
            self.status_code = status_code
        if code is not None:
            self.code = code
        self.retry_after_seconds = _coerce_retry_after(retry_after_seconds)
        self.upgrade_url = upgrade_url
        self.docs_url = docs_url
        self.extras = extras or {}


def _coerce_retry_after(value: Any) -> int | None:
    """Validate + clamp retry_after_seconds to [0, 3600].

    Server sends int per ErrorDetail schema, but a malformed/proxied response
    could deliver str/float/list/bool/inf/NaN. Defensive: ignore garbage
    rather than crash user code that does `time.sleep(exc.retry_after_seconds)`.
    """
    if value is None:
        return None
    # Reject bool early — `int(True) == 1` would silently produce 1-second
    # sleeps from a `{"retry_after_seconds": true}` upstream response. bool
    # is also a subclass of int, so the `isinstance(value, bool)` guard must
    # run before the int() coercion below.
    if isinstance(value, bool):
        return None
    # Reject NaN — `int(float('nan'))` raises ValueError but inf raises
    # OverflowError; both must be silently dropped to None per defensive policy.
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        return None
    try:
        as_int = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return max(0, min(as_int, _RETRY_AFTER_MAX_SECONDS))


class InvalidArgumentError(ContrastAPIError):
    code = "invalid_argument"
    status_code = 400


class AuthRequiredError(ContrastAPIError):
    code = "auth_required"
    status_code = 401


class TierLimitError(ContrastAPIError):
    code = "tier_limit"
    status_code = 403


class NotFoundError(ContrastAPIError):
    code = "not_found"
    status_code = 404


class RateLimitError(ContrastAPIError):
    code = "rate_limit_exceeded"
    status_code = 429


class UpstreamError(ContrastAPIError):
    code = "upstream_error"
    status_code = 502


class UpstreamTimeoutError(ContrastAPIError):
    code = "upstream_timeout"
    status_code = 504


class TransportError(ContrastAPIError):
    """Raised when the HTTP layer fails before a response is received
    (DNS error, connection refused, client timeout, TLS handshake fail).
    """

    code = "transport_error"


_CODE_TO_EXCEPTION: dict[str, type[ContrastAPIError]] = {
    "invalid_argument": InvalidArgumentError,
    "auth_required": AuthRequiredError,
    "tier_limit": TierLimitError,
    "not_found": NotFoundError,
    "rate_limit_exceeded": RateLimitError,
    "upstream_error": UpstreamError,
    "upstream_timeout": UpstreamTimeoutError,
}


_STATUS_TO_EXCEPTION: dict[int, type[ContrastAPIError]] = {
    400: InvalidArgumentError,
    401: AuthRequiredError,
    403: TierLimitError,
    404: NotFoundError,
    422: InvalidArgumentError,
    429: RateLimitError,
    502: UpstreamError,
    504: UpstreamTimeoutError,
}


def _parse_error(status_code: int, body: Any) -> ContrastAPIError:
    """Convert a wire error envelope into the right typed exception.

    Wire shape (v1.22.2+):
        {"error": {"code": "...", "message": "...", "retry_after_seconds": 60,
                   "upgrade_url": "...", "docs_url": "..."}, ...top-level extensions}

    Falls back to status-code mapping if the body lacks a parseable envelope.
    """
    if not isinstance(body, dict):
        cls = _STATUS_TO_EXCEPTION.get(status_code, ContrastAPIError)
        return cls(f"HTTP {status_code}", status_code=status_code)

    err = body.get("error") if isinstance(body.get("error"), dict) else None
    if err is None:
        message = body.get("detail") or body.get("message") or f"HTTP {status_code}"
        cls = _STATUS_TO_EXCEPTION.get(status_code, ContrastAPIError)
        return cls(str(message), status_code=status_code, extras=body)

    code = err.get("code") or "upstream_error"
    message = err.get("message") or f"HTTP {status_code}"
    cls = _CODE_TO_EXCEPTION.get(code, _STATUS_TO_EXCEPTION.get(status_code, ContrastAPIError))
    extras = {k: v for k, v in body.items() if k != "error"}
    return cls(
        str(message),
        status_code=status_code,
        code=code,
        retry_after_seconds=err.get("retry_after_seconds"),
        upgrade_url=err.get("upgrade_url"),
        docs_url=err.get("docs_url"),
        extras=extras,
    )
