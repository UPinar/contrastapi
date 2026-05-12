"""Domain exception hierarchy for ContrastAPI MCP tools.

Each subclass carries an MCP wire `code` (matches schemas.ErrorDetail.code) and
an HTTP `status_code` for HTTP route translation. The MCP layer's
`mcp_tool_safe` decorator catches AppException and converts it into an
ErrorResponse via `to_error_detail()`.

Adapted from erhan/ozgurkon `app/core/exceptions.py` pattern.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.schemas import ErrorDetail


class AppException(Exception):
    """Base for all domain exceptions raised by MCP tool helpers.

    Subclasses pin `code` (ErrorDetail.code Literal) and `status_code` (HTTP).
    Optional fields (`retry_after`, `upgrade_url`, `docs_url`) propagate to
    ErrorDetail so the agent sees actionable hints instead of a bare message.
    """

    code: str = "internal_error"
    status_code: int = 500

    def __init__(
        self,
        message: str,
        *,
        retry_after: int | None = None,
        upgrade_url: str | None = None,
        docs_url: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message[:500]
        self.retry_after = retry_after
        self.upgrade_url = upgrade_url
        self.docs_url = docs_url

    def to_error_detail(self) -> ErrorDetail:
        from app.schemas import ErrorDetail

        return ErrorDetail(
            code=self.code,  # type: ignore[arg-type]
            message=self.message,
            retry_after_seconds=self.retry_after,
            upgrade_url=self.upgrade_url,
            docs_url=self.docs_url,
        )


# === Validation (input) ===


class InvalidArgumentException(AppException):
    code = "invalid_argument"
    status_code = 400


class InvalidCveIdException(InvalidArgumentException):
    pass


class InvalidDomainException(InvalidArgumentException):
    pass


class InvalidIpException(InvalidArgumentException):
    pass


class InvalidHashException(InvalidArgumentException):
    pass


# === Upstream / authorization ===


class NotFoundException(AppException):
    code = "not_found"
    status_code = 404


class RateLimitExceededException(AppException):
    code = "rate_limit_exceeded"
    status_code = 429


class AuthRequiredException(AppException):
    code = "auth_required"
    status_code = 401


class TierLimitException(AppException):
    code = "tier_limit"
    status_code = 403


class UpstreamTimeoutException(AppException):
    code = "upstream_timeout"
    status_code = 504


class UpstreamErrorException(AppException):
    code = "upstream_error"
    status_code = 502
