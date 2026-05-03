"""Tests for /v1/brand/{domain} + helpers in domain/brand_assets.py."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


# === _pattern_matches (RFC 9309 §2.2.3 prefix + wildcard + $ anchor) ===


class TestPatternMatches:
    def test_empty_pattern_never_matches(self):
        from domain.brand_assets import _pattern_matches

        # Per RFC 9309: empty Disallow value is allow-all signal — handled at
        # the caller level, but the matcher itself should refuse to match.
        assert _pattern_matches("", "/") is False
        assert _pattern_matches("", "/admin") is False

    def test_root_disallow_blocks_root(self):
        from domain.brand_assets import _pattern_matches

        assert _pattern_matches("/", "/") is True

    def test_path_disallow_does_not_block_root(self):
        from domain.brand_assets import _pattern_matches

        # `/admin` does not match `/` — that's the whole point of robots.
        assert _pattern_matches("/admin", "/") is False

    def test_wildcard_matches(self):
        from domain.brand_assets import _pattern_matches

        assert _pattern_matches("/*", "/") is True
        assert _pattern_matches("/*.pdf", "/foo.pdf") is True
        assert _pattern_matches("/*.pdf", "/foo.html") is False

    def test_dollar_anchor_exact_match(self):
        from domain.brand_assets import _pattern_matches

        assert _pattern_matches("/$", "/") is True
        # `/admin` does not equal `/` so anchor rejects it
        assert _pattern_matches("/$", "/admin") is False

    def test_regex_special_chars_escaped(self):
        from domain.brand_assets import _pattern_matches

        # `.` and `+` etc. in robots are LITERAL — must not be regex-active.
        assert _pattern_matches("/foo.bar", "/foozbar") is False
        assert _pattern_matches("/foo.bar", "/foo.bar") is True


# === homepage_allowed (RFC 9309 §2.2.1 group selection + longest match) ===


class TestHomepageAllowed:
    def test_no_robots_data_allows(self):
        from domain.brand_assets import homepage_allowed

        assert homepage_allowed({"user_agents": {}}) == (True, None)
        assert homepage_allowed({}) == (True, None)

    def test_wildcard_disallow_root_blocks(self):
        from domain.brand_assets import homepage_allowed

        parsed = {"user_agents": {"*": {"allow": [], "disallow": ["/"], "crawl_delay": None}}}
        ok, pat = homepage_allowed(parsed)
        assert ok is False
        assert pat == "/"

    def test_wildcard_disallow_path_does_not_block_homepage(self):
        from domain.brand_assets import homepage_allowed

        parsed = {"user_agents": {"*": {"allow": [], "disallow": ["/admin"], "crawl_delay": None}}}
        ok, _ = homepage_allowed(parsed)
        assert ok is True

    def test_specific_ua_block_overrides_wildcard(self):
        """RFC 9309 §2.2.1: groups are NOT merged. The most specific
        match wins; wildcard is consulted only when no specific block
        applies. Even a permissive ContrastAPI block must override a
        restrictive `*`."""
        from domain.brand_assets import homepage_allowed

        parsed = {
            "user_agents": {
                "*": {"allow": [], "disallow": ["/"], "crawl_delay": None},
                "ContrastAPI": {"allow": [], "disallow": [], "crawl_delay": None},
            }
        }
        ok, _ = homepage_allowed(parsed)
        assert ok is True  # specific group has no Disallow → allow

    def test_specific_ua_disallow_blocks_us_even_if_wildcard_allows(self):
        from domain.brand_assets import homepage_allowed

        parsed = {
            "user_agents": {
                "*": {"allow": [], "disallow": [], "crawl_delay": None},
                "ContrastAPI": {"allow": [], "disallow": ["/"], "crawl_delay": None},
            }
        }
        ok, pat = homepage_allowed(parsed)
        assert ok is False
        assert pat == "/"

    def test_case_insensitive_ua_match(self):
        from domain.brand_assets import homepage_allowed

        parsed = {"user_agents": {"contrastapi": {"allow": [], "disallow": ["/"], "crawl_delay": None}}}
        ok, _ = homepage_allowed(parsed)
        assert ok is False

    def test_partial_ua_token_match(self):
        """`User-agent: Contrast` (operator wrote a short version) should
        still bind to our `contrastapi` token — substring match in either
        direction per RFC 9309 §2.2.1's case-insensitive product-token rule."""
        from domain.brand_assets import homepage_allowed

        parsed = {"user_agents": {"Contrast": {"allow": [], "disallow": ["/"], "crawl_delay": None}}}
        ok, _ = homepage_allowed(parsed)
        assert ok is False

    def test_empty_disallow_is_allow_all(self):
        """`Disallow:` with empty value means allow-all per RFC 9309."""
        from domain.brand_assets import homepage_allowed

        parsed = {"user_agents": {"*": {"allow": [], "disallow": [""], "crawl_delay": None}}}
        ok, _ = homepage_allowed(parsed)
        assert ok is True

    def test_allow_overrides_disallow_on_longer_match(self):
        """Longest match wins. `Allow: /index.html` beats `Disallow: /` for `/index.html`,
        but for path `/` the only matching pattern is the disallow → block."""
        from domain.brand_assets import homepage_allowed

        # For root path, /index.html does NOT match — only / does.
        parsed = {"user_agents": {"*": {"allow": ["/index.html"], "disallow": ["/"], "crawl_delay": None}}}
        ok, _ = homepage_allowed(parsed)
        assert ok is False  # /index.html doesn't match path "/"

    def test_allow_root_with_disallow_root_tie_allow_wins(self):
        """Tie-break: when Allow and Disallow have equal-length matches,
        Allow wins (Google's behaviour, safer for site operators)."""
        from domain.brand_assets import homepage_allowed

        parsed = {"user_agents": {"*": {"allow": ["/"], "disallow": ["/"], "crawl_delay": None}}}
        ok, _ = homepage_allowed(parsed)
        assert ok is True


# === _abs_url ===


class TestAbsUrl:
    def test_relative_resolved(self):
        from domain.brand_assets import _abs_url

        assert _abs_url("/favicon.ico", "https://x.com/page") == "https://x.com/favicon.ico"

    def test_absolute_passthrough(self):
        from domain.brand_assets import _abs_url

        assert _abs_url("https://cdn.x.com/logo.png", "https://x.com/") == "https://cdn.x.com/logo.png"

    def test_javascript_scheme_dropped(self):
        from domain.brand_assets import _abs_url

        assert _abs_url("javascript:alert(1)", "https://x.com/") is None

    def test_data_scheme_dropped(self):
        from domain.brand_assets import _abs_url

        assert _abs_url("data:text/html,<script>", "https://x.com/") is None

    def test_vbscript_scheme_dropped(self):
        from domain.brand_assets import _abs_url

        assert _abs_url("vbscript:msgbox(1)", "https://x.com/") is None
        # case-insensitive prefix check
        assert _abs_url("VBScript:msgbox(1)", "https://x.com/") is None

    def test_file_scheme_dropped(self):
        from domain.brand_assets import _abs_url

        assert _abs_url("file:///etc/passwd", "https://x.com/") is None

    def test_javascript_uppercase_dropped(self):
        from domain.brand_assets import _abs_url

        # Trivial bypass attempts must not slip through
        assert _abs_url("JAVASCRIPT:alert(1)", "https://x.com/") is None
        assert _abs_url("JaVaScRiPt:alert(1)", "https://x.com/") is None

    def test_empty_returns_none(self):
        from domain.brand_assets import _abs_url

        assert _abs_url("", "https://x.com/") is None
        assert _abs_url(None, "https://x.com/") is None

    def test_control_chars_stripped(self):
        from domain.brand_assets import _abs_url

        # Trojan-Source bidi RTL override should be stripped before urljoin.
        out = _abs_url("/logo‮png", "https://x.com/")
        assert out is not None
        assert "‮" not in out


# === extract_brand_assets ===


class TestExtractBrandAssets:
    def test_full_meta_set(self):
        from domain.brand_assets import extract_brand_assets

        html = """
        <html><head>
        <link rel="icon" href="/favicon.ico">
        <meta property="og:image" content="https://cdn.example.com/og.png">
        <meta name="theme-color" content="#0066cc">
        <meta property="og:site_name" content="Example Inc">
        <script type="application/ld+json">
        {"@context":"https://schema.org","@type":"Organization","logo":"https://example.com/logo.png"}
        </script>
        </head><body></body></html>
        """
        out = extract_brand_assets(html, "https://example.com/")
        assert out["favicon_url"] == "https://example.com/favicon.ico"
        assert out["og_image_url"] == "https://cdn.example.com/og.png"
        assert out["theme_color"] == "#0066cc"
        assert out["site_name"] == "Example Inc"
        assert out["logo_url"] == "https://example.com/logo.png"

    def test_only_favicon(self):
        from domain.brand_assets import extract_brand_assets

        html = '<html><head><link rel="icon" href="/icon.png"></head></html>'
        out = extract_brand_assets(html, "https://example.com/")
        assert out["favicon_url"] == "https://example.com/icon.png"
        assert out["og_image_url"] is None
        assert out["theme_color"] is None
        assert out["logo_url"] is None

    def test_favicon_fallback_to_default(self):
        from domain.brand_assets import extract_brand_assets

        # No <link rel="icon"> at all → fall back to /favicon.ico
        html = "<html><head></head></html>"
        out = extract_brand_assets(html, "https://example.com/")
        assert out["favicon_url"] == "https://example.com/favicon.ico"

    def test_apple_touch_icon_fallback(self):
        from domain.brand_assets import extract_brand_assets

        html = '<html><head><link rel="apple-touch-icon" href="/apple.png"></head></html>'
        out = extract_brand_assets(html, "https://example.com/")
        assert out["favicon_url"] == "https://example.com/apple.png"

    def test_jsonld_imageobject_logo(self):
        """JSON-LD allows logo to be an ImageObject with a url field."""
        from domain.brand_assets import extract_brand_assets

        html = """
        <html><head><script type="application/ld+json">
        {"@type":"Organization","logo":{"@type":"ImageObject","url":"https://x.com/logo.png"}}
        </script></head></html>
        """
        out = extract_brand_assets(html, "https://x.com/")
        assert out["logo_url"] == "https://x.com/logo.png"

    def test_jsonld_graph_array_unrolled(self):
        """JSON-LD `@graph` should be walked as a list of entities."""
        from domain.brand_assets import extract_brand_assets

        html = """
        <html><head><script type="application/ld+json">
        {"@context":"https://schema.org","@graph":[
          {"@type":"WebSite","url":"https://x.com/"},
          {"@type":"Organization","logo":"https://x.com/g-logo.png"}
        ]}
        </script></head></html>
        """
        out = extract_brand_assets(html, "https://x.com/")
        assert out["logo_url"] == "https://x.com/g-logo.png"

    def test_jsonld_malformed_silently_skipped(self):
        from domain.brand_assets import extract_brand_assets

        html = '<html><head><script type="application/ld+json">{ this is not valid json</script></head></html>'
        out = extract_brand_assets(html, "https://x.com/")
        assert out["logo_url"] is None  # parse failure → no logo, no exception

    def test_title_fallback_for_site_name(self):
        from domain.brand_assets import extract_brand_assets

        html = "<html><head><title>Acme Corp — Industrial Anvils</title></head></html>"
        out = extract_brand_assets(html, "https://acme.com/")
        assert out["site_name"] == "Acme Corp — Industrial Anvils"

    def test_theme_color_oversize_dropped(self):
        from domain.brand_assets import extract_brand_assets

        # 65-char "color" — almost certainly an SEO injection or paste error.
        html = f'<html><head><meta name="theme-color" content="{"x" * 65}"></head></html>'
        out = extract_brand_assets(html, "https://x.com/")
        assert out["theme_color"] is None

    def test_site_name_capped_at_200_chars(self):
        from domain.brand_assets import extract_brand_assets

        long_name = "A" * 500
        html = f'<html><head><meta property="og:site_name" content="{long_name}"></head></html>'
        out = extract_brand_assets(html, "https://x.com/")
        assert len(out["site_name"]) == 200

    def test_javascript_logo_url_dropped(self):
        from domain.brand_assets import extract_brand_assets

        html = """
        <html><head><script type="application/ld+json">
        {"@type":"Organization","logo":"javascript:alert(1)"}
        </script></head></html>
        """
        out = extract_brand_assets(html, "https://x.com/")
        assert out["logo_url"] is None

    def test_base_tag_does_not_redirect_url_resolution(self):
        """A malicious target setting `<base href="javascript:...">` must
        NOT influence our URL resolution. urljoin uses our explicit
        `base_url` (the response final URL); BeautifulSoup's `<base>`
        is irrelevant — we never read it."""
        from domain.brand_assets import extract_brand_assets

        html = """
        <html><head>
        <base href="javascript:alert('xss')">
        <link rel="icon" href="/favicon.ico">
        <meta property="og:image" content="/og.png">
        </head></html>
        """
        out = extract_brand_assets(html, "https://example.com/")
        # Both must resolve against https://example.com/, NOT against the <base> href
        assert out["favicon_url"] == "https://example.com/favicon.ico"
        assert out["og_image_url"] == "https://example.com/og.png"
        assert "javascript:" not in (out["favicon_url"] or "")
        assert "javascript:" not in (out["og_image_url"] or "")

    def test_jsonld_block_count_capped_at_20(self):
        """A page emitting 25 JSON-LD blocks must NOT have all 25 parsed
        — only the first _MAX_JSONLD_BLOCKS=20 are scanned. The 21st
        block (which carries the only Organization.logo) must NOT win,
        because we never reach it."""
        from domain.brand_assets import extract_brand_assets

        decoy_blocks = "\n".join(
            f'<script type="application/ld+json">{{"@type":"WebSite","name":"d{i}"}}</script>' for i in range(20)
        )
        # Block #21 (index 20) is where the Organization+logo lives — past the cap.
        late_logo = (
            '<script type="application/ld+json">{"@type":"Organization","logo":"https://x.com/late.png"}</script>'
        )
        html = f"<html><head>{decoy_blocks}{late_logo}</head></html>"
        out = extract_brand_assets(html, "https://x.com/")
        assert out["logo_url"] is None  # blocked by the cap

    def test_jsonld_oversize_block_skipped(self):
        """A single >256KB block is skipped, not parsed."""
        from domain.brand_assets import extract_brand_assets

        # 300KB padding inside a syntactically-valid JSON document.
        padding = "x" * (300 * 1024)
        html = (
            f'<html><head><script type="application/ld+json">'
            f'{{"@type":"Organization","logo":"https://x.com/big.png","_pad":"{padding}"}}'
            f"</script></head></html>"
        )
        out = extract_brand_assets(html, "https://x.com/")
        assert out["logo_url"] is None  # block exceeded byte cap → skipped

    def test_malformed_html_does_not_crash(self):
        from domain.brand_assets import extract_brand_assets

        # Unclosed tags + garbage bytes — BeautifulSoup is lenient but we
        # still want a graceful return.
        html = "<<<head><meta property='og:image' content='https://x.com/img.png'></head"
        out = extract_brand_assets(html, "https://x.com/")
        # og:image should still extract despite mangled outer tags
        assert out["og_image_url"] == "https://x.com/img.png"


# === Route /v1/brand/{domain} ===


_NO_ROBOTS = {
    "domain": "corp.com",
    "fetched_url": "https://corp.com/robots.txt",
    "status_code": 404,
    "user_agents": {},
    "sitemaps": [],
    "host": None,
    "truncated": False,
}

_GOOD_PAGE = {
    "html": (
        "<html><head>"
        '<link rel="icon" href="/fav.ico">'
        '<meta property="og:image" content="https://cdn.corp.com/og.png">'
        '<meta property="og:site_name" content="Corp Inc">'
        "</head></html>"
    ),
    "url": "https://corp.com/",
    "status_code": 200,
    "cache_control": "",
}


class TestBrandAssetsRoute:
    @patch("db.get_cached_domain", side_effect=[None, _NO_ROBOTS])
    @patch("db.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.brand_assets.fetch_homepage_html", return_value=_GOOD_PAGE)
    def test_brand_assets_200(self, mock_fetch, mock_validate, mock_save, mock_cache):
        r = client.get("/v1/brand/corp.com")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["domain"] == "corp.com"
        assert data["favicon_url_untrusted"] == "https://corp.com/fav.ico"
        assert data["og_image_url_untrusted"] == "https://cdn.corp.com/og.png"
        assert data["site_name_untrusted"] == "Corp Inc"
        assert data["cache_respected"] is True

    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_robots_disallow_returns_403(self, mock_validate):
        blocked_robots = {
            "domain": "blocked.com",
            "fetched_url": "https://blocked.com/robots.txt",
            "status_code": 200,
            "user_agents": {"*": {"allow": [], "disallow": ["/"], "crawl_delay": None}},
            "sitemaps": [],
            "host": None,
            "truncated": False,
        }
        with patch("db.get_cached_domain", side_effect=[None, blocked_robots]):
            with patch("domain.brand_assets.fetch_homepage_html") as mock_fetch:
                r = client.get("/v1/brand/blocked.com")
                assert r.status_code == 403
                assert "robots_txt_disallow" in r.text
                # Critical: we must NOT have fetched the homepage.
                mock_fetch.assert_not_called()

    @patch("db.get_cached_domain", side_effect=[None, _NO_ROBOTS])
    @patch("db.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch(
        "domain.brand_assets.fetch_homepage_html",
        return_value={
            "html": _GOOD_PAGE["html"],
            "url": "https://corp.com/",
            "status_code": 200,
            "cache_control": "no-store",
        },
    )
    def test_cache_control_no_store_skips_cache_write(self, mock_fetch, mock_validate, mock_save, mock_cache):
        r = client.get("/v1/brand/corp.com")
        assert r.status_code == 200
        data = r.json()
        assert data["cache_respected"] is False
        # Walk the save_cached_domain calls — there must be NO entry for
        # `brand:corp.com` (the robots cache write may still happen).
        keys_written = [c.args[0] for c in mock_save.call_args_list]
        assert "brand:corp.com" not in keys_written

    @patch("db.get_cached_domain", side_effect=[None, _NO_ROBOTS])
    @patch("db.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.brand_assets.fetch_homepage_html", side_effect=Exception("connect failed"))
    def test_homepage_fetch_failure_502(self, mock_fetch, mock_validate, mock_save, mock_cache):
        r = client.get("/v1/brand/corp.com")
        assert r.status_code == 502
        assert "brand_assets fetch failed" in r.text

    def test_fetch_homepage_html_sends_accept_encoding_identity(self):
        """Compression-bomb DoS guard: `_MAX_HOMEPAGE_BYTES` only bounds
        decompressed bytes (httpx auto-decodes gzip/br/zstd in
        iter_bytes). We MUST send `Accept-Encoding: identity` so the
        server cannot send a 1KB gzip blob that decompresses to 500MB
        in our RAM before the byte cap fires."""
        from unittest.mock import MagicMock

        from domain.brand_assets import fetch_homepage_html

        captured: dict = {}

        class _FakeResp:
            def __init__(self, headers):
                self.headers = {"Content-Type": "text/html", **headers}
                self.status_code = 200
                self.url = "https://example.com/"

            def iter_bytes(self):
                yield b"<html><head></head></html>"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_stream(method, url, **kwargs):
            captured["headers"] = kwargs.get("headers", {})
            return _FakeResp({})

        with patch("domain.brand_assets._ssrf_http") as mock_http:
            mock_http.stream = MagicMock(side_effect=fake_stream)
            fetch_homepage_html("example.com")

        assert captured["headers"].get("Accept-Encoding") == "identity"

    @patch("db.get_cached_domain", side_effect=[None, _NO_ROBOTS])
    @patch("db.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_ssrf_blocked_redirect_surfaces_as_502(self, mock_validate, mock_save, mock_cache):
        """If the homepage fetch ends up trying to connect to a private
        IP (whether the original target resolved private OR a redirect
        landed there), `_ssrf_http` raises a connect error — the route
        must surface this as a clean 502, not 200 with empty assets."""
        from httpx import ConnectError

        with patch(
            "domain.brand_assets.fetch_homepage_html",
            side_effect=ConnectError("SSRF blocked: 127.0.0.1"),
        ):
            r = client.get("/v1/brand/corp.com")
            assert r.status_code == 502
            assert "fetch failed" in r.text

    def test_robots_fetch_failure_does_not_block(self):
        """Fail-open on robots.txt fetch failure: a transient DNS / TLS
        outage on robots must not poison every brand_assets call. We
        treat it as 'no rules' and proceed."""
        with patch("db.get_cached_domain", return_value=None):
            with patch("db.save_cached_domain"):
                with patch("domain.routes.validate_domain", return_value="93.184.216.34"):
                    with patch("domain.robots.fetch_robots_txt", side_effect=Exception("dns boom")):
                        with patch("domain.brand_assets.fetch_homepage_html", return_value=_GOOD_PAGE):
                            r = client.get("/v1/brand/corp.com")
                            assert r.status_code == 200, r.text
                            data = r.json()
                            assert data["domain"] == "corp.com"

    @patch(
        "db.get_cached_domain",
        return_value={
            "domain": "corp.com",
            "fetched_url": "https://corp.com/",
            "status_code": 200,
            "favicon_url_untrusted": "https://corp.com/fav.ico",
            "summary": "cached",
            "cache_respected": True,
        },
    )
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_cache_hit_short_circuits_robots_and_fetch(self, mock_validate, mock_cache):
        """Cache hit on `brand:{domain}` must NOT trigger robots.txt
        fetch or homepage fetch — neither network round-trip happens."""
        with patch("domain.brand_assets.fetch_homepage_html") as mock_fetch:
            with patch("domain.robots.fetch_robots_txt") as mock_robots:
                r = client.get("/v1/brand/corp.com")
                assert r.status_code == 200
                mock_fetch.assert_not_called()
                mock_robots.assert_not_called()


def test_brand_assets_mcp_tool_registered(mcp_client):
    pytest.importorskip("mcp")
    r = mcp_client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream", "Content-Type": "application/json"},
    )
    assert r.status_code == 200
    assert "brand_assets" in r.text
