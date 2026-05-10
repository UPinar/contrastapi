"""Transport-layer tests — base URL parsing, headers, error envelope, response cap."""

from __future__ import annotations

import httpx
import pytest
import respx
from contrastapi import (
    AsyncContrastAPI,
    AuthRequiredError,
    ContrastAPI,
    ContrastAPIError,
    InvalidArgumentError,
    NotFoundError,
    RateLimitError,
    TierLimitError,
    TransportError,
    UpstreamError,
    UpstreamTimeoutError,
    __version__,
)


def test_version_is_pinned():
    assert __version__ == "1.22.5"


def test_default_base_url_is_https():
    client = ContrastAPI()
    assert client._transport.base_url == "https://api.contrastcyber.com"
    client.close()


def test_http_base_url_rejected_by_default():
    with pytest.raises(ValueError, match="HTTPS"):
        ContrastAPI(base_url="http://localhost:8000")


def test_http_base_url_allowed_with_flag():
    client = ContrastAPI(base_url="http://localhost:8000", allow_insecure=True)
    assert client._transport.base_url == "http://localhost:8000"
    client.close()


def test_unsupported_scheme_rejected():
    with pytest.raises(ValueError, match="Unsupported scheme"):
        ContrastAPI(base_url="ftp://api.contrastcyber.com")


def test_api_key_over_http_rejected_at_call_time():
    """API key + insecure transport must error at request time, not silently leak."""
    client = ContrastAPI(api_key="cc_test", base_url="http://localhost:8000", allow_insecure=True)
    with pytest.raises(ValueError, match="insecure connection"):
        client.cve.lookup("CVE-2021-44228")
    client.close()


@respx.mock
def test_get_returns_json_body():
    route = respx.get("https://api.contrastcyber.com/v1/cve/CVE-2021-44228").mock(
        return_value=httpx.Response(200, json={"cve_id": "CVE-2021-44228", "kev": {"in_kev": True}})
    )
    with ContrastAPI() as client:
        result = client.cve.lookup("CVE-2021-44228")
    assert route.called
    assert result["cve_id"] == "CVE-2021-44228"
    assert result["kev"]["in_kev"] is True


@respx.mock
def test_user_agent_header_sent():
    route = respx.get("https://api.contrastcyber.com/v1/status").mock(
        return_value=httpx.Response(200, json={"status": "ok", "version": "1.22.5"})
    )
    with ContrastAPI() as client:
        client.status()
    request = route.calls.last.request
    assert request.headers["user-agent"] == f"contrastapi-python/{__version__}"
    assert request.headers["accept"] == "application/json"
    assert "x-api-key" not in request.headers


@respx.mock
def test_api_key_header_sent_when_provided():
    route = respx.get("https://api.contrastcyber.com/v1/usage").mock(
        return_value=httpx.Response(200, json={"requests_remaining": 1000})
    )
    with ContrastAPI(api_key="cc_test_key") as client:
        client.usage()
    assert route.calls.last.request.headers["x-api-key"] == "cc_test_key"


@respx.mock
def test_400_raises_invalid_argument_error_with_envelope():
    respx.get("https://api.contrastcyber.com/v1/cve/INVALID-ID").mock(
        return_value=httpx.Response(
            400,
            json={
                "error": {
                    "code": "invalid_argument",
                    "message": "Invalid CVE ID format",
                    "docs_url": "https://api.contrastcyber.com/docs",
                },
            },
        )
    )
    with ContrastAPI() as client, pytest.raises(InvalidArgumentError) as exc_info:
        client.cve.lookup("INVALID-ID")
    err = exc_info.value
    assert err.status_code == 400
    assert err.code == "invalid_argument"
    assert err.message == "Invalid CVE ID format"
    assert err.docs_url == "https://api.contrastcyber.com/docs"


@respx.mock
def test_404_raises_not_found_error():
    respx.get("https://api.contrastcyber.com/v1/cve/CVE-9999-99999").mock(
        return_value=httpx.Response(404, json={"error": {"code": "not_found", "message": "CVE not found"}})
    )
    with ContrastAPI() as client, pytest.raises(NotFoundError) as exc_info:
        client.cve.lookup("CVE-9999-99999")
    assert exc_info.value.status_code == 404


@respx.mock
def test_401_raises_auth_required_error():
    respx.get("https://api.contrastcyber.com/v1/cve/CVE-2021-44228").mock(
        return_value=httpx.Response(401, json={"error": {"code": "auth_required", "message": "API key required"}})
    )
    with ContrastAPI() as client, pytest.raises(AuthRequiredError):
        client.cve.lookup("CVE-2021-44228")


@respx.mock
def test_403_raises_tier_limit_error():
    respx.get("https://api.contrastcyber.com/v1/cve/CVE-2021-44228").mock(
        return_value=httpx.Response(403, json={"error": {"code": "tier_limit", "message": "Pro feature"}})
    )
    with ContrastAPI() as client, pytest.raises(TierLimitError):
        client.cve.lookup("CVE-2021-44228")


@respx.mock
def test_429_raises_rate_limit_error_with_retry_after():
    respx.get("https://api.contrastcyber.com/v1/cve/CVE-2021-44228").mock(
        return_value=httpx.Response(
            429,
            json={
                "error": {
                    "code": "rate_limit_exceeded",
                    "message": "Hourly limit reached",
                    "retry_after_seconds": 60,
                    "upgrade_url": "https://contrastcyber.com/pricing",
                },
            },
        )
    )
    with ContrastAPI() as client, pytest.raises(RateLimitError) as exc_info:
        client.cve.lookup("CVE-2021-44228")
    err = exc_info.value
    assert err.retry_after_seconds == 60
    assert err.upgrade_url == "https://contrastcyber.com/pricing"


@respx.mock
def test_502_raises_upstream_error():
    respx.get("https://api.contrastcyber.com/v1/cve/CVE-2021-44228").mock(
        return_value=httpx.Response(502, json={"error": {"code": "upstream_error", "message": "NVD upstream failed"}})
    )
    with ContrastAPI() as client, pytest.raises(UpstreamError):
        client.cve.lookup("CVE-2021-44228")


@respx.mock
def test_504_raises_upstream_timeout_error():
    respx.get("https://api.contrastcyber.com/v1/cve/CVE-2021-44228").mock(
        return_value=httpx.Response(504, json={"error": {"code": "upstream_timeout", "message": "Upstream timed out"}})
    )
    with ContrastAPI() as client, pytest.raises(UpstreamTimeoutError):
        client.cve.lookup("CVE-2021-44228")


@respx.mock
def test_unknown_status_falls_back_to_base_error():
    respx.get("https://api.contrastcyber.com/v1/cve/CVE-2021-44228").mock(
        return_value=httpx.Response(418, json={"detail": "I'm a teapot"})
    )
    with ContrastAPI() as client, pytest.raises(ContrastAPIError) as exc_info:
        client.cve.lookup("CVE-2021-44228")
    assert exc_info.value.status_code == 418


@respx.mock
def test_invalid_json_response_raises_contrast_api_error():
    respx.get("https://api.contrastcyber.com/v1/cve/CVE-2021-44228").mock(
        return_value=httpx.Response(200, content=b"<html>not json</html>")
    )
    with ContrastAPI() as client, pytest.raises(ContrastAPIError, match="Invalid JSON"):
        client.cve.lookup("CVE-2021-44228")


@respx.mock
def test_oversized_response_rejected():
    big_payload = b"a" * (10 * 1024 * 1024 + 1)  # 10 MB + 1 byte
    respx.get("https://api.contrastcyber.com/v1/cve/CVE-2021-44228").mock(
        return_value=httpx.Response(200, content=big_payload)
    )
    with ContrastAPI() as client, pytest.raises(ContrastAPIError, match="Response too large"):
        client.cve.lookup("CVE-2021-44228")


@respx.mock
def test_non_envelope_error_body_falls_back_to_status_mapping():
    """If a 404 response has no `error` key, status code still drives exception type."""
    respx.get("https://api.contrastcyber.com/v1/cve/CVE-2021-44228").mock(
        return_value=httpx.Response(404, json={"detail": "Not found"})
    )
    with ContrastAPI() as client, pytest.raises(NotFoundError) as exc_info:
        client.cve.lookup("CVE-2021-44228")
    assert exc_info.value.message == "Not found"


@respx.mock
def test_envelope_top_level_extras_preserved():
    """Back-compat top-level fields survive into `exc.extras`."""
    respx.get("https://api.contrastcyber.com/v1/cve/CVE-2021-44228").mock(
        return_value=httpx.Response(
            429,
            json={
                "error": {
                    "code": "rate_limit_exceeded",
                    "message": "Limit",
                    "retry_after_seconds": 30,
                },
                "tier": "free",
                "limit": 100,
            },
        )
    )
    with ContrastAPI() as client, pytest.raises(RateLimitError) as exc_info:
        client.cve.lookup("CVE-2021-44228")
    assert exc_info.value.extras == {"tier": "free", "limit": 100}


def test_timeout_clamped_to_minimum():
    client = ContrastAPI(timeout=0.001)
    assert client._transport.timeout == 1.0
    client.close()


def test_timeout_clamped_to_maximum():
    client = ContrastAPI(timeout=999)
    assert client._transport.timeout == 120.0
    client.close()


@respx.mock
def test_transport_error_on_connection_failure():
    respx.get("https://api.contrastcyber.com/v1/cve/CVE-2021-44228").mock(
        side_effect=httpx.ConnectError("connection refused")
    )
    with ContrastAPI() as client, pytest.raises(TransportError):
        client.cve.lookup("CVE-2021-44228")


# ---------------------------------------------------------------------------
# Async parity smoke tests
# ---------------------------------------------------------------------------


@respx.mock
async def test_async_get_returns_json_body():
    respx.get("https://api.contrastcyber.com/v1/cve/CVE-2021-44228").mock(
        return_value=httpx.Response(200, json={"cve_id": "CVE-2021-44228"})
    )
    async with AsyncContrastAPI() as client:
        result = await client.cve.lookup("CVE-2021-44228")
    assert result["cve_id"] == "CVE-2021-44228"


@respx.mock
async def test_async_404_raises_not_found_error():
    respx.get("https://api.contrastcyber.com/v1/cve/CVE-9999-99999").mock(
        return_value=httpx.Response(404, json={"error": {"code": "not_found", "message": "CVE not found"}})
    )
    async with AsyncContrastAPI() as client:
        with pytest.raises(NotFoundError):
            await client.cve.lookup("CVE-9999-99999")
