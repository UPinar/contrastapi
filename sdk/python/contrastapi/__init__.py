"""ContrastAPI Python SDK.

>>> from contrastapi import ContrastAPI
>>> client = ContrastAPI()
>>> client.cve.lookup("CVE-2021-44228")
"""

from ._version import __version__
from .client import AsyncContrastAPI, ContrastAPI
from .exceptions import (
    AuthRequiredError,
    ContrastAPIError,
    InvalidArgumentError,
    NotFoundError,
    RateLimitError,
    TierLimitError,
    TransportError,
    UpstreamError,
    UpstreamTimeoutError,
)
from .shortcuts import audit_full, enrich_batch, triage_ioc

__all__ = [
    "AsyncContrastAPI",
    "AuthRequiredError",
    "ContrastAPI",
    "ContrastAPIError",
    "InvalidArgumentError",
    "NotFoundError",
    "RateLimitError",
    "TierLimitError",
    "TransportError",
    "UpstreamError",
    "UpstreamTimeoutError",
    "__version__",
    "audit_full",
    "enrich_batch",
    "triage_ioc",
]
