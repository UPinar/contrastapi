"""S251 pattern-B leak hardening — RED-first regression tests.

Asserts: streaming endpoints aclose() their response even when the body
iterator is cancelled mid-stream, the shared _ssrf_http pool timeout is
12.0s, and tech/vulns routes wrap fetch_live_page in asyncio.wait_for(13.0).
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


class _CancelResp:
    """A streaming Response whose body iterator raises CancelledError."""

    def __init__(self):
        self.status_code = 200
        self.url = httpx.URL("https://example.com/")
        self.headers = httpx.Headers([("Content-Type", "text/html")])
        self.aclose_calls = 0

    async def aiter_bytes(self):
        for _ in range(0):
            yield b""
        raise asyncio.CancelledError

    async def aclose(self):
        self.aclose_calls += 1


class _CancelClient:
    def __init__(self, resp):
        self._resp = resp
        self.timeout = httpx.Timeout(5.0, connect=5.0, pool=12.0)

    def build_request(self, method, url, **kw):
        m = MagicMock()
        m.method = method
        m.url = url
        return m

    async def send(self, request, *, stream=False, follow_redirects=False):
        return self._resp


def test_ssrf_http_pool_timeout_is_12s():
    from domain.recon import _ssrf_http

    assert _ssrf_http.timeout.pool == 12.0


def test_ssrf_http_pool_reaps_idle_keepalive():
    """Regression: the custom _SSRFSafeAsyncTransport skips super().__init__, so a
    BARE AsyncConnectionPool defaulted to keepalive_expiry=None — idle keepalive
    connections were never reaped, so server-closed sockets lingered in CLOSE_WAIT
    and accumulated over uptime until the bounded pool exhausted (live-fetch routes
    -> PoolTimeout -> 504, cleared only by the daily restart). The pool MUST set a
    finite keepalive_expiry explicitly."""
    from domain.recon import _ssrf_http

    pool = _ssrf_http._transport._pool
    assert pool._keepalive_expiry == 5.0, "idle keepalive must be reaped (was None -> CLOSE_WAIT leak)"
    assert pool._max_keepalive_connections == 5
    assert pool._max_connections == 10


def test_fetch_live_page_acloses_on_midstream_cancel():
    from domain.recon import fetch_live_page

    resp = _CancelResp()
    with patch("domain.recon._ssrf_http", _CancelClient(resp)):
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(fetch_live_page("example.com"))
    assert resp.aclose_calls >= 1


def test_fetch_robots_txt_acloses_on_midstream_cancel():
    from domain.robots import fetch_robots_txt

    resp = _CancelResp()
    with patch("domain.robots._ssrf_http", _CancelClient(resp)):
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(fetch_robots_txt("example.com"))
    assert resp.aclose_calls >= 1


def test_fetch_homepage_html_acloses_on_midstream_cancel():
    from domain.brand_assets import fetch_homepage_html

    resp = _CancelResp()
    with patch("domain.brand_assets._ssrf_http", _CancelClient(resp)):
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(fetch_homepage_html("example.com"))
    assert resp.aclose_calls >= 1


def _wait_for_spy(captured):
    real_wf = asyncio.wait_for

    async def fake_wf(aw, timeout):
        captured["timeout"] = timeout
        if timeout == 13.0:
            aw.close()
            raise asyncio.TimeoutError
        return await real_wf(aw, timeout)

    return fake_wf


def test_tech_route_wraps_fetch_in_wait_for_13s():
    captured = {}
    with (
        patch("domain.routes.asyncio.wait_for", _wait_for_spy(captured)),
        patch("domain.routes._validate_domain_input", return_value=("example.com", "1.2.3.4")),
        patch("domain.routes.fetch_live_page", new_callable=AsyncMock),
    ):
        r = client.get("/v1/tech/example.com")
    assert captured.get("timeout") == 13.0
    assert r.status_code == 504


def test_domain_vulns_route_wraps_fetch_in_wait_for_13s():
    captured = {}
    with (
        patch("domain.routes.asyncio.wait_for", _wait_for_spy(captured)),
        patch("domain.routes._validate_domain_input", return_value=("example.com", "1.2.3.4")),
        patch("domain.routes.fetch_live_page", new_callable=AsyncMock),
    ):
        r = client.get("/v1/domain/example.com/vulns")
    assert captured.get("timeout") == 13.0
    assert r.status_code == 504
