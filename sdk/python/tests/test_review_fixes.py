"""Regression tests for the v1.22.3 review fix pass.

CRIT: ContrastAPIError must coerce non-string `message` to str (no
AttributeError downstream).

LOW (security): retry_after_seconds must be clamped to [0, 3600] and reject
non-integer values defensively.

MEDIUM: D3FEND `kind` parameter dropped (server doesn't support it).
MEDIUM: ATLAS + D3FEND `q` is back-compat alias for `keyword`; passing both
raises.
HIGH: domain.report `lite` flag goes through query params, not URL string.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from contrastapi import ContrastAPI, ContrastAPIError, RateLimitError

# ---------------------------------------------------------------------------
# CRIT: message coercion
# ---------------------------------------------------------------------------


def test_message_coerced_to_string_when_none():
    exc = ContrastAPIError(None)  # type: ignore[arg-type]
    assert exc.message == ""
    assert isinstance(exc.message, str)
    assert str(exc) == ""


def test_message_coerced_to_string_when_int():
    exc = ContrastAPIError(42)  # type: ignore[arg-type]
    assert exc.message == "42"
    assert isinstance(exc.message, str)


def test_message_coerced_to_string_when_dict():
    exc = ContrastAPIError({"foo": "bar"})  # type: ignore[arg-type]
    assert exc.message == "{'foo': 'bar'}"
    assert isinstance(exc.message, str)


def test_message_truncated_to_500_chars():
    huge = "x" * 5000
    exc = ContrastAPIError(huge)
    assert len(exc.message) == 500


# ---------------------------------------------------------------------------
# LOW (security): retry_after clamp + type validation
# ---------------------------------------------------------------------------


def test_retry_after_clamped_to_3600():
    exc = ContrastAPIError("x", retry_after_seconds=999999)  # type: ignore[arg-type]
    assert exc.retry_after_seconds == 3600


def test_retry_after_clamped_to_zero_floor():
    exc = ContrastAPIError("x", retry_after_seconds=-50)  # type: ignore[arg-type]
    assert exc.retry_after_seconds == 0


def test_retry_after_normal_value_passes_through():
    exc = ContrastAPIError("x", retry_after_seconds=60)
    assert exc.retry_after_seconds == 60


def test_retry_after_string_coerced_to_int():
    exc = ContrastAPIError("x", retry_after_seconds="120")  # type: ignore[arg-type]
    assert exc.retry_after_seconds == 120


def test_retry_after_garbage_silently_dropped():
    exc = ContrastAPIError("x", retry_after_seconds="not-a-number")  # type: ignore[arg-type]
    assert exc.retry_after_seconds is None


def test_retry_after_list_silently_dropped():
    exc = ContrastAPIError("x", retry_after_seconds=[60, 120])  # type: ignore[arg-type]
    assert exc.retry_after_seconds is None


@respx.mock
def test_429_response_with_huge_retry_after_clamped_via_parser():
    """Wire-level: server (or attacker controlling it) sends 999999 → SDK exposes 3600."""
    respx.get("https://api.contrastcyber.com/v1/cve/CVE-2021-44228").mock(
        return_value=httpx.Response(
            429,
            json={
                "error": {
                    "code": "rate_limit_exceeded",
                    "message": "Limit",
                    "retry_after_seconds": 999999,
                }
            },
        )
    )
    with ContrastAPI() as client, pytest.raises(RateLimitError) as exc_info:
        client.cve.lookup("CVE-2021-44228")
    assert exc_info.value.retry_after_seconds == 3600


# ---------------------------------------------------------------------------
# MEDIUM: D3FEND kind parameter dropped
# ---------------------------------------------------------------------------


def test_d3fend_search_no_kind_kwarg():
    """Server route doesn't accept `kind`; SDK silently dropped values would
    be confusing. The signature simply doesn't expose it."""
    with ContrastAPI() as client, pytest.raises(TypeError, match="kind"):
        client.d3fend.defense_search(kind="Harden")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# MEDIUM: q is back-compat alias for keyword
# ---------------------------------------------------------------------------


@respx.mock
def test_d3fend_search_q_aliased_to_keyword():
    """Old Node-style `q=` still works; SDK renames it to `keyword=` on the wire."""
    route = respx.get("https://api.contrastcyber.com/v1/d3fend/defenses").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    with ContrastAPI() as client:
        client.d3fend.defense_search(q="encryption")
    assert dict(route.calls.last.request.url.params) == {"keyword": "encryption"}


@respx.mock
def test_atlas_search_q_aliased_to_keyword():
    route = respx.get("https://api.contrastcyber.com/v1/atlas/techniques").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    with ContrastAPI() as client:
        client.atlas.technique_search(q="prompt injection")
    assert dict(route.calls.last.request.url.params) == {"keyword": "prompt injection"}


def test_d3fend_search_q_and_keyword_together_rejected():
    with ContrastAPI() as client, pytest.raises(ValueError, match="back-compat"):
        client.d3fend.defense_search(keyword="x", q="y")


def test_atlas_search_q_and_keyword_together_rejected():
    with ContrastAPI() as client, pytest.raises(ValueError, match="back-compat"):
        client.atlas.technique_search(keyword="x", q="y")


# ---------------------------------------------------------------------------
# HIGH: domain.report lite goes through params, not URL string
# ---------------------------------------------------------------------------


@respx.mock
def test_domain_report_default_no_query_string():
    route = respx.get("https://api.contrastcyber.com/v1/domain/example.com").mock(
        return_value=httpx.Response(200, json={"domain": "example.com"})
    )
    with ContrastAPI() as client:
        client.domain.report("example.com")
    assert dict(route.calls.last.request.url.params) == {}


@respx.mock
def test_domain_report_lite_emits_query_param():
    route = respx.get("https://api.contrastcyber.com/v1/domain/example.com").mock(
        return_value=httpx.Response(200, json={"domain": "example.com"})
    )
    with ContrastAPI() as client:
        client.domain.report("example.com", lite=True)
    assert dict(route.calls.last.request.url.params) == {"lite": "true"}
