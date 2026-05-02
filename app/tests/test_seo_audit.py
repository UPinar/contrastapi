"""Tests for /v1/seo/{domain} + the parser/scorer in domain/seo_audit.py."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


# === _same_registrable (cheap eTLD-aware compare) ===


class TestSameRegistrable:
    def test_identical_hosts(self):
        from domain.seo_audit import _same_registrable

        assert _same_registrable("example.com", "example.com") is True

    def test_subdomain_of_base(self):
        from domain.seo_audit import _same_registrable

        assert _same_registrable("blog.example.com", "example.com") is True
        assert _same_registrable("example.com", "www.example.com") is True

    def test_different_registrable(self):
        from domain.seo_audit import _same_registrable

        assert _same_registrable("example.com", "other.com") is False

    def test_empty_inputs_safe(self):
        from domain.seo_audit import _same_registrable

        assert _same_registrable("", "example.com") is False
        assert _same_registrable("example.com", "") is False

    def test_case_insensitive(self):
        from domain.seo_audit import _same_registrable

        assert _same_registrable("Example.COM", "example.com") is True

    def test_psl_co_uk_distinct_registrables(self):
        """Two distinct UK companies on `.co.uk` MUST split as external —
        the round-1 review caught a last-2-labels false positive that
        merged them ('co.uk' shared) and inflated internal_link_count
        for any UK-domain audit."""
        from domain.seo_audit import _same_registrable

        assert _same_registrable("bbc.co.uk", "theguardian.co.uk") is False
        assert _same_registrable("www.bbc.co.uk", "bbc.co.uk") is True
        assert _same_registrable("news.bbc.co.uk", "sport.bbc.co.uk") is True

    def test_psl_edu_au_distinct(self):
        from domain.seo_audit import _same_registrable

        assert _same_registrable("anu.edu.au", "sydney.edu.au") is False

    def test_psl_long_suffix_gov_uk(self):
        from domain.seo_audit import _same_registrable

        # `gov.uk` is a public suffix → service.gov.uk and another.gov.uk
        # are distinct registrables, NOT siblings.
        assert _same_registrable("service.gov.uk", "another.gov.uk") is False


# === _extract_seo (pure parser) ===


_PERFECT_HTML = """
<html lang="en"><head>
<title>Example Inc — Premium Industrial Anvils Online</title>
<meta name="description" content="Example Inc has been crafting premium industrial-grade anvils for over a century. Free shipping over $50, 30-day returns. (123 chars)">
<link rel="canonical" href="https://example.com/">
<meta property="og:title" content="Example Inc">
<meta property="og:description" content="Anvils.">
<meta property="og:image" content="https://example.com/og.png">
<meta property="og:url" content="https://example.com/">
<script type="application/ld+json">{"@type":"Organization"}</script>
</head><body>
<h1>Welcome to Example Inc</h1>
<h2>Products</h2>
<h2>About</h2>
<h3>Contact</h3>
<img src="/a.png" alt="A logo">
<img src="/b.png" alt="A photo">
<a href="/about">About</a>
<a href="https://other.com/x">External</a>
<a href="https://blog.example.com/post">Internal subdomain</a>
<a href="mailto:hi@example.com">Mail</a>
<a href="#contact">Anchor</a>
</body></html>
"""


class TestExtractSeo:
    def test_full_extraction(self):
        from domain.seo_audit import _extract_seo

        out = _extract_seo(_PERFECT_HTML, "https://example.com/")
        assert out["title_untrusted"].startswith("Example Inc")
        assert "Example Inc has been crafting" in out["meta_description_untrusted"]
        assert out["canonical_url"] == "https://example.com/"
        assert out["h1_count"] == 1
        assert out["h1_untrusted"] == ["Welcome to Example Inc"]
        assert out["h2_count"] == 2
        assert out["h3_count"] == 1
        assert out["images_total"] == 2
        assert out["images_missing_alt"] == 0
        # /about (internal), https://blog.example.com/post (internal subdomain), https://other.com/x (external)
        assert out["internal_link_count"] == 2
        assert out["external_link_count"] == 1
        assert len(out["og_tags"]) == 4
        assert out["og_tags"]["og:title"] == "Example Inc"
        assert out["json_ld_present"] is True

    def test_empty_html(self):
        from domain.seo_audit import _extract_seo

        out = _extract_seo("", "https://x.com/")
        assert out["title_untrusted"] is None
        assert out["meta_description_untrusted"] is None
        assert out["h1_count"] == 0
        assert out["images_total"] == 0
        assert out["json_ld_present"] is False

    def test_h1_count_uncapped_for_scoring(self):
        """The h1_untrusted LIST is capped at 20 entries, but h1_count
        must reflect the true total — the scorer needs to detect
        H1-spam pages."""
        from domain.seo_audit import _extract_seo

        html = "<html><body>" + ("<h1>x</h1>" * 30) + "</body></html>"
        out = _extract_seo(html, "https://x.com/")
        assert out["h1_count"] == 30
        assert len(out["h1_untrusted"]) == 20  # list capped

    def test_image_missing_alt_counted(self):
        from domain.seo_audit import _extract_seo

        html = '<img src="/a"><img src="/b" alt=""><img src="/c" alt="real">'
        out = _extract_seo(html, "https://x.com/")
        assert out["images_total"] == 3
        # No alt + empty alt both count as "missing meaningful alt"
        assert out["images_missing_alt"] == 2

    def test_javascript_links_excluded(self):
        from domain.seo_audit import _extract_seo

        html = '<a href="javascript:alert(1)">X</a><a href="/real">Y</a>'
        out = _extract_seo(html, "https://x.com/")
        # Only /real counts, javascript: is dropped
        assert out["internal_link_count"] == 1
        assert out["external_link_count"] == 0

    def test_anchor_only_links_excluded(self):
        from domain.seo_audit import _extract_seo

        html = '<a href="#top">Top</a><a href="#section">Section</a>'
        out = _extract_seo(html, "https://x.com/")
        assert out["internal_link_count"] == 0
        assert out["external_link_count"] == 0

    def test_og_tags_only_og_namespace(self):
        from domain.seo_audit import _extract_seo

        html = """
        <meta property="og:title" content="A">
        <meta property="twitter:title" content="B">
        <meta property="article:author" content="C">
        """
        out = _extract_seo(html, "https://x.com/")
        assert out["og_tags"] == {"og:title": "A"}

    def test_og_tag_value_capped(self):
        from domain.seo_audit import _extract_seo

        long_val = "x" * 1000
        html = f'<meta property="og:title" content="{long_val}">'
        out = _extract_seo(html, "https://x.com/")
        assert len(out["og_tags"]["og:title"]) == 500

    def test_og_tag_key_bidi_stripped(self):
        """A malicious target embedding U+202E (RTL override) in the
        property name MUST NOT inject the bidi char into our dict key.
        Round-1 security review caught this gap — keys must pass
        through `_strip_control_chars` just like values."""
        from domain.seo_audit import _extract_seo

        html = '<meta property="og:‮title" content="x">'
        out = _extract_seo(html, "https://x.com/")
        # The bidi char must be absent from every key
        for key in out["og_tags"]:
            assert "‮" not in key

    def test_control_chars_stripped_from_title(self):
        from domain.seo_audit import _extract_seo

        # Trojan-Source RTL override embedded in title text — must be stripped
        html = "<title>Safe‮Title</title>"
        out = _extract_seo(html, "https://x.com/")
        assert "‮" not in (out["title_untrusted"] or "")

    def test_canonical_resolved_to_absolute(self):
        from domain.seo_audit import _extract_seo

        html = '<link rel="canonical" href="/canonical-path">'
        out = _extract_seo(html, "https://example.com/page/")
        assert out["canonical_url"] == "https://example.com/canonical-path"

    def test_malformed_html_does_not_crash(self):
        from domain.seo_audit import _extract_seo

        html = "<<<<title>X</title<<>"
        out = _extract_seo(html, "https://x.com/")
        # BS4 is lenient — at minimum should not raise
        assert isinstance(out["title_untrusted"], (str, type(None)))


# === _score (composite 0-100) ===


class TestScore:
    def test_perfect_score(self):
        from domain.seo_audit import _extract_seo, _score

        score, missing = _score(_extract_seo(_PERFECT_HTML, "https://example.com/"), "https://example.com/")
        assert score == 100
        assert missing == []

    def test_no_https_loses_10(self):
        from domain.seo_audit import _extract_seo, _score

        score, missing = _score(_extract_seo(_PERFECT_HTML, "http://example.com/"), "http://example.com/")
        assert score == 90
        assert "not_https" in missing

    def test_missing_title_loses_20(self):
        """No title → loses 'title present' (10) AND 'title length' (10)."""
        from domain.seo_audit import _extract_seo, _score

        html = _PERFECT_HTML.replace("<title>Example Inc — Premium Industrial Anvils Online</title>", "")
        score, missing = _score(_extract_seo(html, "https://example.com/"), "https://example.com/")
        assert score == 80
        assert "title_missing" in missing
        # title_length_off should NOT fire when title is fully absent (only when off-window)
        assert "title_length_off" not in missing

    def test_multiple_h1_flagged(self):
        from domain.seo_audit import _extract_seo, _score

        html = _PERFECT_HTML.replace("<h1>Welcome to Example Inc</h1>", "<h1>A</h1><h1>B</h1>")
        score, missing = _score(_extract_seo(html, "https://example.com/"), "https://example.com/")
        assert "h1_multiple" in missing
        assert score < 100

    def test_zero_images_does_not_penalise(self):
        """A page with no images gets full credit on the alt-coverage rule —
        we have nothing to ding."""
        from domain.seo_audit import _extract_seo, _score

        # Perfect HTML minus the <img> tags
        html = _PERFECT_HTML
        for img in [
            '<img src="/a.png" alt="A logo">',
            '<img src="/b.png" alt="A photo">',
        ]:
            html = html.replace(img, "")
        score, missing = _score(_extract_seo(html, "https://example.com/"), "https://example.com/")
        assert score == 100
        assert "images_missing_alt" not in missing

    def test_title_length_boundaries(self):
        """30-60 char window is inclusive on both ends — verify the
        edges (29/30/60/61) so a future refactor that flips `<=` to `<`
        is caught immediately."""
        from domain.seo_audit import _score

        for n, should_credit in ((29, False), (30, True), (60, True), (61, False)):
            parsed = {"title_untrusted": "x" * n, "h1_count": 0}
            score, missing = _score(parsed, "https://x.com/")
            if should_credit:
                assert "title_length_off" not in missing, f"len={n} should credit"
            else:
                assert "title_length_off" in missing, f"len={n} should NOT credit"

    def test_meta_description_length_boundaries(self):
        """50-160 char window is inclusive — same boundary discipline
        as title."""
        from domain.seo_audit import _score

        for n, should_credit in ((49, False), (50, True), (160, True), (161, False)):
            parsed = {"meta_description_untrusted": "x" * n, "h1_count": 0}
            score, missing = _score(parsed, "https://x.com/")
            if should_credit:
                assert "meta_description_length_off" not in missing, f"len={n} should credit"
            else:
                assert "meta_description_length_off" in missing, f"len={n} should NOT credit"

    def test_alt_coverage_rounding_4_images_1_missing(self):
        """4 images, 1 missing alt → coverage = 0.75 → round(7.5) = 8
        on Python's banker's rounding (8 is even, would round to 8 only
        for 7.5; round(7.5) actually = 8 because the int 8 is even).
        Lock the actual contribution number so future changes to the
        formula are caught."""
        from domain.seo_audit import _score

        parsed = {
            "title_untrusted": "X" * 45,  # full credit on title (10) + length (10)
            "meta_description_untrusted": "y" * 100,  # full credit (10+10)
            "h1_count": 1,  # full credit (10)
            "canonical_url": "https://x.com/",  # full credit (10)
            "og_tags": {"og:a": "1", "og:b": "2", "og:c": "3"},  # full credit (10)
            "json_ld_present": True,  # full credit (10)
            "images_total": 4,
            "images_missing_alt": 1,  # coverage 0.75 → 8 pts (round(7.5)=8)
        }
        score, missing = _score(parsed, "https://x.com/")
        # 80 (other 8 rules) + 8 (alt) + 10 (https) = 98
        assert score == 98
        assert "images_missing_alt" in missing

    def test_images_partial_alt_proportional(self):
        from domain.seo_audit import _extract_seo, _score

        # 4 images, 1 missing alt → coverage = 0.75 → 7-8 pts (round)
        html = '<img src="/a"><img src="/b" alt="x"><img src="/c" alt="y"><img src="/d" alt="z">'
        parsed = _extract_seo(html, "https://x.com/")
        score, missing = _score(parsed, "https://x.com/")
        # Almost everything else missing — title/desc/h1/canonical/og/jsonld absent.
        # Just verify the alt-coverage signal flagged + rounded correctly.
        assert "images_missing_alt" in missing


# === Route /v1/seo/{domain} ===


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
    "html": _PERFECT_HTML,
    "url": "https://corp.com/",
    "status_code": 200,
    "cache_control": "",
}


class TestSeoAuditRoute:
    @patch("domain.routes.get_cached_domain", side_effect=[None, _NO_ROBOTS])
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.brand_assets.fetch_homepage_html", return_value=_GOOD_PAGE)
    def test_seo_audit_200_with_score(self, mock_fetch, mock_validate, mock_save, mock_cache):
        r = client.get("/v1/seo/corp.com")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["domain"] == "corp.com"
        assert isinstance(data["score"], int)
        assert 0 <= data["score"] <= 100
        assert "title_untrusted" in data
        assert "missing_signals" in data

    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_robots_disallow_returns_403_no_fetch(self, mock_validate):
        blocked_robots = {
            "domain": "blocked.com",
            "fetched_url": "https://blocked.com/robots.txt",
            "status_code": 200,
            "user_agents": {"*": {"allow": [], "disallow": ["/"], "crawl_delay": None}},
            "sitemaps": [],
            "host": None,
            "truncated": False,
        }
        with patch("domain.routes.get_cached_domain", side_effect=[None, blocked_robots]):
            with patch("domain.brand_assets.fetch_homepage_html") as mock_fetch:
                r = client.get("/v1/seo/blocked.com")
                assert r.status_code == 403
                assert "robots_txt_disallow" in r.text
                mock_fetch.assert_not_called()

    @patch("domain.routes.get_cached_domain", side_effect=[None, _NO_ROBOTS])
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch(
        "domain.brand_assets.fetch_homepage_html",
        return_value={**_GOOD_PAGE, "cache_control": "no-store"},
    )
    def test_cache_control_no_store_skips_cache_write(self, mock_fetch, mock_validate, mock_save, mock_cache):
        r = client.get("/v1/seo/corp.com")
        assert r.status_code == 200
        data = r.json()
        assert data["cache_respected"] is False
        keys_written = [c.args[0] for c in mock_save.call_args_list]
        assert "seo:corp.com" not in keys_written

    @patch("domain.routes.get_cached_domain", side_effect=[None, _NO_ROBOTS])
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.brand_assets.fetch_homepage_html", side_effect=Exception("boom"))
    def test_homepage_fetch_failure_502(self, mock_fetch, mock_validate, mock_save, mock_cache):
        r = client.get("/v1/seo/corp.com")
        assert r.status_code == 502
        assert "seo_audit fetch failed" in r.text


def test_seo_audit_mcp_tool_registered(mcp_client):
    pytest.importorskip("mcp")
    r = mcp_client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream", "Content-Type": "application/json"},
    )
    assert r.status_code == 200
    assert "seo_audit" in r.text
