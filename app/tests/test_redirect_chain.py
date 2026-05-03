"""Tests for /v1/redirect/{url:path} + walk_redirect_chain in domain/redirect_chain.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


# === _validate_url ===


class TestValidateUrl:
    def test_https_ok(self):
        from domain.redirect_chain import _validate_url

        assert _validate_url("https://example.com/path") == ("https", "example.com")

    def test_http_ok(self):
        from domain.redirect_chain import _validate_url

        assert _validate_url("http://example.com") == ("http", "example.com")

    def test_file_scheme_rejected(self):
        from domain.redirect_chain import _validate_url

        with pytest.raises(ValueError, match="http/https"):
            _validate_url("file:///etc/passwd")

    def test_gopher_scheme_rejected(self):
        from domain.redirect_chain import _validate_url

        with pytest.raises(ValueError, match="http/https"):
            _validate_url("gopher://internal:25/")

    def test_no_host_rejected(self):
        from domain.redirect_chain import _validate_url

        with pytest.raises(ValueError, match="host"):
            _validate_url("https:///just-path")

    def test_control_chars_rejected(self):
        from domain.redirect_chain import _validate_url

        with pytest.raises(ValueError, match="control characters"):
            _validate_url("https://example.com/\x00bad")

    def test_ipv6_bracketed_host_accepted_by_validator(self):
        """IPv6 bracket form is structurally valid; SSRF guard rejects loopback at TCP-connect time."""
        from domain.redirect_chain import _validate_url

        scheme, host = _validate_url("http://[::1]/")
        assert scheme == "http"
        assert host == "::1"

        scheme, host = _validate_url("https://[2001:db8::1]:8080/path")
        assert scheme == "https"
        assert host == "2001:db8::1"


# === walk_redirect_chain via mocked _ssrf_http ===


def _make_resp(status: int, location: str | None = None, url: str = "https://a.com/"):
    """Build an async-context-manager-shaped mock that mimics httpx.AsyncClient.stream()."""
    resp = MagicMock()
    resp.status_code = status
    resp.url = url
    resp.headers = {}
    if location:
        resp.headers["location"] = location
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=resp)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


class TestWalkRedirectChain:
    def test_terminal_200_no_redirect(self):
        from domain import redirect_chain as rc

        with patch.object(rc._ssrf_http, "stream", side_effect=[_make_resp(200, url="https://a.com/")]):
            out = asyncio.run(rc.walk_redirect_chain("https://a.com/"))
        assert out["hop_count"] == 1
        assert out["loop_detected"] is False
        assert out["truncated"] is False
        assert out["final_status"] == 200
        assert out["hops"][0]["status_code"] == 200
        assert out["hops"][0]["location"] is None

    def test_three_hop_chain(self):
        from domain import redirect_chain as rc

        responses = [
            _make_resp(301, location="https://b.com/", url="https://a.com/"),
            _make_resp(302, location="https://c.com/", url="https://b.com/"),
            _make_resp(200, url="https://c.com/"),
        ]
        with patch.object(rc._ssrf_http, "stream", side_effect=responses):
            out = asyncio.run(rc.walk_redirect_chain("https://a.com/"))
        assert out["hop_count"] == 3
        assert out["final_url"] == "https://c.com/"
        assert out["final_status"] == 200
        assert [h["status_code"] for h in out["hops"]] == [301, 302, 200]

    def test_loop_detected_aborts_before_duplicate_fetch(self):
        from domain import redirect_chain as rc

        responses = [
            _make_resp(302, location="https://b.com/", url="https://a.com/"),
            _make_resp(302, location="https://a.com/", url="https://b.com/"),  # loop back
        ]
        with patch.object(rc._ssrf_http, "stream", side_effect=responses):
            out = asyncio.run(rc.walk_redirect_chain("https://a.com/"))
        assert out["loop_detected"] is True
        assert out["hop_count"] == 2  # only 2 fetches (a, b) — third would have re-fetched a
        assert out["truncated"] is False

    def test_max_hops_truncates(self):
        from domain import redirect_chain as rc

        # 11 sequential redirects to fresh hosts — should truncate at hop 10
        responses = [_make_resp(302, location=f"https://h{i + 1}.com/", url=f"https://h{i}.com/") for i in range(11)]
        with patch.object(rc._ssrf_http, "stream", side_effect=responses):
            out = asyncio.run(rc.walk_redirect_chain("https://h0.com/", max_hops=10))
        assert out["truncated"] is True
        assert out["hop_count"] == 10

    def test_relative_location_resolved_against_response_url(self):
        from domain import redirect_chain as rc

        responses = [
            _make_resp(302, location="/new-path", url="https://a.com/old-path"),
            _make_resp(200, url="https://a.com/new-path"),
        ]
        with patch.object(rc._ssrf_http, "stream", side_effect=responses):
            out = asyncio.run(rc.walk_redirect_chain("https://a.com/old-path"))
        assert out["hops"][0]["location"] == "https://a.com/new-path"

    def test_30x_with_no_location_terminates(self):
        from domain import redirect_chain as rc

        with patch.object(rc._ssrf_http, "stream", side_effect=[_make_resp(304, url="https://a.com/")]):
            out = asyncio.run(rc.walk_redirect_chain("https://a.com/"))
        assert out["hop_count"] == 1
        assert out["truncated"] is False
        assert out["loop_detected"] is False
        assert out["hops"][0]["location"] is None

    def test_redirect_to_file_scheme_blocked(self):
        """A target redirecting us to file:/// must not be followed."""
        from domain import redirect_chain as rc

        responses = [_make_resp(302, location="file:///etc/passwd", url="https://a.com/")]
        with patch.object(rc._ssrf_http, "stream", side_effect=responses):
            out = asyncio.run(rc.walk_redirect_chain("https://a.com/"))
        # The bad scheme is silently dropped (location=None) → terminal at 1 hop
        assert out["hop_count"] == 1
        assert out["hops"][0]["location"] is None

    def test_redirect_to_ipv6_loopback_uri_form_blocked_at_validator(self):
        """A redirect Location: http://[::1]/ should be parsed and reach the SSRF guard.

        We don't reject IPv6 brackets at _validate_url (they're structurally valid);
        the actual block happens at TCP-connect time via _SSRFSafeAsyncBackend. This
        test verifies that the URL passes validation (so we don't pre-emptively
        drop a public IPv6 redirect target by mistake).
        """
        from domain.redirect_chain import _validate_url

        scheme, host = _validate_url("http://[::1]/")
        assert host == "::1"  # downstream SSRF guard rejects ::1 at connect

    def test_invalid_start_url_raises(self):
        from domain import redirect_chain as rc

        with pytest.raises(ValueError):
            asyncio.run(rc.walk_redirect_chain("file:///etc/passwd"))

    def test_cross_host_throttle_consumed_at_each_new_host(self):
        from domain import redirect_chain as rc
        from ratelimit import reset

        reset()
        responses = [
            _make_resp(302, location="https://b.com/", url="https://a.com/"),
            _make_resp(302, location="https://c.com/", url="https://b.com/"),
            _make_resp(200, url="https://c.com/"),
        ]
        with patch.object(rc._ssrf_http, "stream", side_effect=responses):
            with patch("target_throttle.consume_target_throttle", return_value=(True, 0)) as mock_throttle:
                asyncio.run(rc.walk_redirect_chain("https://a.com/"))
        # Hop 0 (start) is consumed by the route handler (NOT this function);
        # hop 1 = b.com, hop 2 = c.com → 2 throttle calls inside the walker.
        assert mock_throttle.call_count == 2
        called_hosts = [c.args[0] for c in mock_throttle.call_args_list]
        assert called_hosts == ["b.com", "c.com"]

    def test_cross_host_throttle_429_raises_clean_exception(self):
        from domain import redirect_chain as rc
        from domain.redirect_chain import TargetThrottleHopExceeded

        responses = [
            _make_resp(302, location="https://b.com/", url="https://a.com/"),
        ]
        with patch.object(rc._ssrf_http, "stream", side_effect=responses):
            with patch("target_throttle.consume_target_throttle", return_value=(False, 17)):
                with pytest.raises(TargetThrottleHopExceeded) as exc_info:
                    asyncio.run(rc.walk_redirect_chain("https://a.com/"))
        assert exc_info.value.host == "b.com"
        assert exc_info.value.retry_after == 17


# === Route /v1/redirect/{url:path} ===


_OK_RESULT = {
    "start_url": "https://a.com/",
    "final_url": "https://c.com/",
    "hops": [
        {"url": "https://a.com/", "status_code": 301, "location": "https://b.com/", "latency_ms": 5},
        {"url": "https://b.com/", "status_code": 302, "location": "https://c.com/", "latency_ms": 4},
        {"url": "https://c.com/", "status_code": 200, "location": None, "latency_ms": 6},
    ],
    "hop_count": 3,
    "final_status": 200,
    "loop_detected": False,
    "truncated": False,
}


class TestRedirectChainRoute:
    @patch("domain.redirect_chain.walk_redirect_chain", new_callable=AsyncMock, return_value=dict(_OK_RESULT))
    @patch("db.get_cached_domain", return_value=None)
    @patch("db.save_cached_domain")
    def test_redirect_200(self, mock_save, mock_cache, mock_walk):
        r = client.get("/v1/redirect/https://a.com/")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["hop_count"] == 3
        assert data["final_url"] == "https://c.com/"
        assert "summary" in data and "3-hop" in data["summary"]

    def test_redirect_invalid_scheme_400(self):
        r = client.get("/v1/redirect/file:///etc/passwd")
        assert r.status_code == 400

    def test_redirect_no_host_400(self):
        r = client.get("/v1/redirect/https:///")
        assert r.status_code == 400

    @patch("domain.redirect_chain.walk_redirect_chain", new_callable=AsyncMock)
    @patch("db.get_cached_domain", return_value=None)
    def test_redirect_fetch_failure_502(self, mock_cache, mock_walk):
        class TimeoutException(Exception):
            pass

        mock_walk.side_effect = TimeoutException("read timeout")
        r = client.get("/v1/redirect/https://hangs.example.com/")
        assert r.status_code == 502
        body = r.json()
        assert "redirect_chain fetch failed" in body["error"]["message"]
        assert "timeout" in body["error"]["message"]

    @patch("domain.redirect_chain.walk_redirect_chain", new_callable=AsyncMock)
    @patch("db.get_cached_domain", return_value=None)
    def test_redirect_mid_chain_throttle_429(self, mock_cache, mock_walk):
        from domain.redirect_chain import TargetThrottleHopExceeded

        mock_walk.side_effect = TargetThrottleHopExceeded("evil.com", 23)
        r = client.get("/v1/redirect/https://a.com/")
        assert r.status_code == 429
        # Retry-After header is overridden by the global ratelimit middleware
        # to the request's rate-limit-reset value, but it must be present.
        assert "Retry-After" in r.headers
        body = r.json()
        assert "evil.com" in body["error"]["message"]


def test_redirect_chain_mcp_tool_registered(mcp_client):
    pytest.importorskip("mcp")
    r = mcp_client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream", "Content-Type": "application/json"},
    )
    assert r.status_code == 200
    assert "redirect_chain" in r.text
