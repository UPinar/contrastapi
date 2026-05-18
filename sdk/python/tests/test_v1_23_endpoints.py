"""v1.23.0 — tests for the 8 endpoints added for API-surface parity:
domain.robots / redirect / brand / seo, email.security_posture / verify,
sigma.lookup / bulk. Mirrors test_namespaces.py: URL construction + body shape,
sync + async parity samples.
"""

from __future__ import annotations

import httpx
import respx
from contrastapi import AsyncContrastAPI, ContrastAPI

BASE = "https://api.contrastcyber.com"
RULE_ID = "11111111-2222-3333-4444-555555555555"


# --- domain web-intel ---------------------------------------------------------


@respx.mock
def test_domain_robots_url():
    route = respx.get(f"{BASE}/v1/robots/example.com").mock(
        return_value=httpx.Response(200, json={"domain": "example.com"})
    )
    with ContrastAPI() as client:
        client.domain.robots("example.com")
    assert route.called


@respx.mock
def test_domain_redirect_preserves_path_separators():
    """`/v1/redirect/{url:path}` — slashes in the URL survive the path encoder."""
    target = "https://bit.ly/3xyz"
    route = respx.get(url__regex=rf"{BASE}/v1/redirect/.+").mock(
        return_value=httpx.Response(200, json={"hops": []})
    )
    with ContrastAPI() as client:
        client.domain.redirect(target)
    request_url = str(route.calls.last.request.url)
    assert "bit.ly/3xyz" in request_url


@respx.mock
def test_domain_brand_url():
    route = respx.get(f"{BASE}/v1/brand/example.com").mock(
        return_value=httpx.Response(200, json={"domain": "example.com"})
    )
    with ContrastAPI() as client:
        client.domain.brand("example.com")
    assert route.called


@respx.mock
def test_domain_seo_url():
    route = respx.get(f"{BASE}/v1/seo/example.com").mock(
        return_value=httpx.Response(200, json={"domain": "example.com"})
    )
    with ContrastAPI() as client:
        client.domain.seo("example.com")
    assert route.called


# --- email -------------------------------------------------------------------


@respx.mock
def test_email_security_posture_url():
    route = respx.get(f"{BASE}/v1/email/security-posture/example.com").mock(
        return_value=httpx.Response(200, json={"domain": "example.com"})
    )
    with ContrastAPI() as client:
        client.email.security_posture("example.com")
    assert route.called
    assert dict(route.calls.last.request.url.params) == {}


@respx.mock
def test_email_security_posture_selectors_query():
    route = respx.get(f"{BASE}/v1/email/security-posture/example.com").mock(
        return_value=httpx.Response(200, json={"domain": "example.com"})
    )
    with ContrastAPI() as client:
        client.email.security_posture("example.com", selectors="selector1,selector2")
    assert dict(route.calls.last.request.url.params) == {"selectors": "selector1,selector2"}


@respx.mock
def test_email_verify_url():
    route = respx.get(f"{BASE}/v1/email/verify/user%40example.com").mock(
        return_value=httpx.Response(200, json={"email": "user@example.com"})
    )
    with ContrastAPI() as client:
        client.email.verify("user@example.com")
    assert route.called


# --- sigma -------------------------------------------------------------------


@respx.mock
def test_sigma_lookup_url():
    route = respx.get(f"{BASE}/v1/sigma/{RULE_ID}").mock(
        return_value=httpx.Response(200, json={"rule": {}})
    )
    with ContrastAPI() as client:
        client.sigma.lookup(RULE_ID)
    assert route.called


@respx.mock
def test_sigma_bulk_body():
    route = respx.post(f"{BASE}/v1/sigma/bulk").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    with ContrastAPI() as client:
        client.sigma.bulk([RULE_ID, "bad-id"])
    import json

    assert json.loads(route.calls.last.request.content) == {"rule_ids": [RULE_ID, "bad-id"]}


# --- async parity ------------------------------------------------------------


@respx.mock
async def test_async_sigma_lookup_url():
    route = respx.get(f"{BASE}/v1/sigma/{RULE_ID}").mock(
        return_value=httpx.Response(200, json={"rule": {}})
    )
    async with AsyncContrastAPI() as client:
        await client.sigma.lookup(RULE_ID)
    assert route.called


@respx.mock
async def test_async_domain_seo_url():
    route = respx.get(f"{BASE}/v1/seo/example.com").mock(
        return_value=httpx.Response(200, json={"domain": "example.com"})
    )
    async with AsyncContrastAPI() as client:
        await client.domain.seo("example.com")
    assert route.called


@respx.mock
async def test_async_email_security_posture_url():
    route = respx.get(f"{BASE}/v1/email/security-posture/example.com").mock(
        return_value=httpx.Response(200, json={"domain": "example.com"})
    )
    async with AsyncContrastAPI() as client:
        await client.email.security_posture("example.com")
    assert route.called
