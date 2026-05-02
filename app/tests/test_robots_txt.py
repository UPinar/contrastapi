"""Tests for /v1/robots/{domain} + the parser in domain/robots.py."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


# === Parser unit tests ===


class TestParseRobotsTxt:
    def test_basic_user_agent_disallow(self):
        from domain.robots import parse_robots_txt

        body = "User-agent: *\nDisallow: /admin\nDisallow: /private"
        out = parse_robots_txt(body)
        assert out["user_agents"]["*"]["disallow"] == ["/admin", "/private"]
        assert out["user_agents"]["*"]["allow"] == []

    def test_multiple_ua_blocks(self):
        from domain.robots import parse_robots_txt

        body = (
            "User-agent: Googlebot\nDisallow: /no-google\n\n"
            "User-agent: Bingbot\nDisallow: /no-bing\n"
            "Allow: /bing-allowed\n"
        )
        out = parse_robots_txt(body)
        assert out["user_agents"]["Googlebot"]["disallow"] == ["/no-google"]
        assert out["user_agents"]["Bingbot"]["disallow"] == ["/no-bing"]
        assert out["user_agents"]["Bingbot"]["allow"] == ["/bing-allowed"]

    def test_grouped_user_agents_share_rules(self):
        """Two UA lines without intervening rules form one group (RFC 9309 §2.1)."""
        from domain.robots import parse_robots_txt

        body = "User-agent: A\nUser-agent: B\nDisallow: /shared\n"
        out = parse_robots_txt(body)
        assert out["user_agents"]["A"]["disallow"] == ["/shared"]
        assert out["user_agents"]["B"]["disallow"] == ["/shared"]

    def test_sitemap_directive_global(self):
        from domain.robots import parse_robots_txt

        body = (
            "Sitemap: https://example.com/sitemap.xml\n"
            "User-agent: *\nDisallow: /\n"
            "Sitemap: https://example.com/sitemap-news.xml\n"
        )
        out = parse_robots_txt(body)
        assert out["sitemaps"] == [
            "https://example.com/sitemap.xml",
            "https://example.com/sitemap-news.xml",
        ]

    def test_crawl_delay_parsed_as_float(self):
        from domain.robots import parse_robots_txt

        body = "User-agent: *\nCrawl-delay: 1.5\nDisallow: /\n"
        out = parse_robots_txt(body)
        assert out["user_agents"]["*"]["crawl_delay"] == 1.5

    def test_crawl_delay_invalid_dropped(self):
        from domain.robots import parse_robots_txt

        body = "User-agent: *\nCrawl-delay: forever\nDisallow: /\n"
        out = parse_robots_txt(body)
        assert out["user_agents"]["*"]["crawl_delay"] is None

    def test_crawl_delay_out_of_bounds_dropped(self):
        """Negative, NaN, and >24h crawl-delay are nonsense — drop them."""
        from domain.robots import parse_robots_txt

        for v in ("-1", "1e10", "nan", "999999"):
            out = parse_robots_txt(f"User-agent: *\nCrawl-delay: {v}\nDisallow: /\n")
            assert out["user_agents"]["*"]["crawl_delay"] is None, f"crawl-delay={v} should be dropped"

    def test_crawl_delay_at_boundary_kept(self):
        """86400 (24h) and 0 are valid edge cases."""
        from domain.robots import parse_robots_txt

        for v, expected in (("86400", 86400.0), ("0", 0.0), ("0.5", 0.5)):
            out = parse_robots_txt(f"User-agent: *\nCrawl-delay: {v}\nDisallow: /\n")
            assert out["user_agents"]["*"]["crawl_delay"] == expected, f"crawl-delay={v}"

    def test_inline_comments_stripped(self):
        from domain.robots import parse_robots_txt

        body = "User-agent: *  # all bots\nDisallow: /admin # secret area\n"
        out = parse_robots_txt(body)
        assert "*" in out["user_agents"]
        assert out["user_agents"]["*"]["disallow"] == ["/admin"]

    def test_host_directive(self):
        from domain.robots import parse_robots_txt

        out = parse_robots_txt("Host: example.com\nUser-agent: *\nDisallow: /\n")
        assert out["host"] == "example.com"

    def test_unknown_directives_silently_dropped(self):
        from domain.robots import parse_robots_txt

        body = "User-agent: *\nDisallow: /a\nClean-param: x /b\nVisit-time: 0500-0845\n"
        out = parse_robots_txt(body)
        assert out["user_agents"]["*"]["disallow"] == ["/a"]

    def test_empty_body_no_rules(self):
        from domain.robots import parse_robots_txt

        out = parse_robots_txt("")
        assert out == {"user_agents": {}, "sitemaps": [], "host": None}

    def test_trojan_source_bidi_stripped(self):
        """Bidi/RTL characters must not survive into the API surface."""
        from domain.robots import parse_robots_txt

        # ‮ = right-to-left override (Trojan-Source vector)
        body = "User-agent: *\nDisallow: /‮evil\n"
        out = parse_robots_txt(body)
        for path in out["user_agents"]["*"]["disallow"]:
            assert "‮" not in path


# === _is_same_or_subdomain ===


class TestIsSameOrSubdomain:
    def test_exact_match(self):
        from domain.robots import _is_same_or_subdomain

        assert _is_same_or_subdomain("example.com", "example.com") is True

    def test_subdomain(self):
        from domain.robots import _is_same_or_subdomain

        assert _is_same_or_subdomain("api.example.com", "example.com") is True

    def test_unrelated(self):
        from domain.robots import _is_same_or_subdomain

        assert _is_same_or_subdomain("evil.com", "example.com") is False

    def test_partial_string_match_not_subdomain(self):
        from domain.robots import _is_same_or_subdomain

        # "fakeexample.com" must NOT match "example.com" (boundary check)
        assert _is_same_or_subdomain("fakeexample.com", "example.com") is False


# === Route /v1/robots/{domain} ===


_PARSED_OK = {
    "domain": "example.com",
    "fetched_url": "https://example.com/robots.txt",
    "status_code": 200,
    "user_agents": {"*": {"allow": [], "disallow": ["/admin"], "crawl_delay": None}},
    "sitemaps": ["https://example.com/sitemap.xml"],
    "host": None,
    "truncated": False,
}


class TestRobotsTxtRoute:
    @patch("domain.robots.fetch_robots_txt", return_value=dict(_PARSED_OK))
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_robots_200(self, mock_validate, mock_save, mock_cache, mock_fetch):
        r = client.get("/v1/robots/example.com")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["domain"] == "example.com"
        assert data["status_code"] == 200
        assert data["sitemaps"] == ["https://example.com/sitemap.xml"]
        assert "*" in data["user_agents"]
        assert data["summary"].startswith("example.com")
        # Cache was written for our key. Don't assert call_count — the
        # mock can pick up writes from background ThreadPoolExecutor tasks
        # spawned by sibling tests in the full pytest run.
        keys = [c.args[0] for c in mock_save.call_args_list]
        assert "robots:example.com" in keys

    @patch("domain.robots.fetch_robots_txt")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_robots_404_implicit_allow_all(self, mock_validate, mock_save, mock_cache, mock_fetch):
        mock_fetch.return_value = {
            **_PARSED_OK,
            "status_code": 404,
            "user_agents": {},
            "sitemaps": [],
        }
        r = client.get("/v1/robots/no-robots.example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["status_code"] == 404
        assert data["user_agents"] == {}
        assert "implicit allow-all" in data["summary"]

    @patch("domain.routes.get_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_robots_cache_hit_short_circuits(self, mock_validate, mock_cache):
        mock_cache.return_value = dict(_PARSED_OK, summary="cached")
        with patch("domain.robots.fetch_robots_txt") as mock_fetch:
            r = client.get("/v1/robots/example.com")
            assert r.status_code == 200
            mock_fetch.assert_not_called()
        assert r.json()["summary"] == "cached"

    @patch("domain.robots.fetch_robots_txt", side_effect=RuntimeError("connect failed"))
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_robots_fetch_failure_502(self, mock_validate, mock_cache, mock_fetch):
        r = client.get("/v1/robots/blackhole.example.com")
        assert r.status_code == 502
        body = r.json()
        # v1.22.0 unified envelope: {"error": {"code", "message"}}
        assert "error" in body
        msg = body["error"]["message"]
        assert "robots.txt fetch failed" in msg
        # Structured error code from _exception_kind
        assert "unknown_error" in msg

    @patch("domain.robots.fetch_robots_txt")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_robots_5xx_upstream_502_no_cache(self, mock_validate, mock_save, mock_cache, mock_fetch):
        """RFC 9309 §2.4: 5xx is transient — surface as 502, do NOT cache empty rules."""
        mock_fetch.return_value = {
            **_PARSED_OK,
            "status_code": 503,
            "user_agents": {},
            "sitemaps": [],
        }
        r = client.get("/v1/robots/wobbly.example.com")
        assert r.status_code == 502
        body = r.json()
        assert "transient" in body["error"]["message"].lower()
        # Critical: must NOT have cached the empty-rules response
        mock_save.assert_not_called()

    @patch("domain.routes.validate_domain", return_value=None)
    def test_robots_unresolvable_domain_422(self, mock_validate):
        r = client.get("/v1/robots/nonexistent.invalid")
        assert r.status_code == 422

    def test_robots_invalid_domain_400(self):
        r = client.get("/v1/robots/not_a_domain")
        assert r.status_code == 400

    def test_robots_ip_rejected(self):
        r = client.get("/v1/robots/8.8.8.8")
        assert r.status_code == 400

    @patch("domain.robots.fetch_robots_txt", return_value=dict(_PARSED_OK))
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_robots_target_throttle_429(self, mock_validate, mock_save, mock_cache, mock_fetch):
        """61st request to the same eTLD+1 within 60s gets 429 from target_throttle."""
        from config import TARGET_THROTTLE_PER_MIN
        from ratelimit import reset

        reset()
        for _ in range(TARGET_THROTTLE_PER_MIN):
            r = client.get("/v1/robots/example.com")
            assert r.status_code == 200, r.text
        r = client.get("/v1/robots/example.com")
        assert r.status_code == 429
        assert "Retry-After" in r.headers


# === MCP tool surface ===


# === _exception_kind classifier ===


class TestExceptionKind:
    def test_timeout_exceptions(self):
        from domain.robots import _exception_kind

        class ConnectTimeout(Exception):
            pass

        class ReadTimeout(Exception):
            pass

        assert _exception_kind(ConnectTimeout()) == "timeout"
        assert _exception_kind(ReadTimeout()) == "timeout"

    def test_tls_exceptions(self):
        from domain.robots import _exception_kind

        class CertificateVerifyFailed(Exception):
            pass

        class SSLError(Exception):
            pass

        assert _exception_kind(CertificateVerifyFailed()) == "tls_error"
        assert _exception_kind(SSLError()) == "tls_error"

    def test_connect_error(self):
        from domain.robots import _exception_kind

        class ConnectError(Exception):
            pass

        assert _exception_kind(ConnectError()) == "connect_error"

    def test_unknown_error_fallback(self):
        from domain.robots import _exception_kind

        assert _exception_kind(RuntimeError("?")) == "unknown_error"


def test_robots_txt_mcp_tool_registered(mcp_client):
    """The MCP tools/list endpoint must include robots_txt after Batch 2."""
    pytest.importorskip("mcp")
    r = mcp_client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream", "Content-Type": "application/json"},
    )
    assert r.status_code == 200
    # Response is SSE-ish; tool name should appear somewhere in the body.
    assert "robots_txt" in r.text
