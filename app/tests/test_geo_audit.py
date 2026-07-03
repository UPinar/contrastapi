"""Tests for /v1/geo/{domain} + the parser/scorer in domain/geo_audit.py."""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


_PERFECT_GEO_HTML = """
<html lang="en"><head>
<title>Acme — Best CRM Software</title>
<link rel="canonical" href="https://acme.com/">
<meta property="og:title" content="Acme CRM">
<meta property="og:description" content="CRM for teams">
<script type="application/ld+json">{"@type":"Organization","name":"Acme"}</script>
<script type="application/ld+json">{"@type":"Product","name":"Acme CRM"}</script>
</head><body>
<h1>Acme CRM Platform</h1>
<h2>Why choose Acme</h2>
<h2>Acme vs Salesforce</h2>
<p>See how Acme compares to alternatives like Salesforce and HubSpot. This detailed
comparison of the best CRM alternative options helps growing teams pick real features
and real support instead of guessing between vendors in a crowded market.</p>
</body></html>
"""

_SPA_HTML = (
    '<html><head></head><body><div id="__next"></div><script>window.__NEXT_DATA__ = {"props":{}}</script></body></html>'
)


# === _extract_geo (pure parser) ===


class TestExtractGeo:
    def test_full_extraction(self):
        from domain.geo_audit import _extract_geo

        out = _extract_geo(_PERFECT_GEO_HTML)
        assert set(out["schema_types"]) == {"Organization", "Product"}
        assert out["client_side_rendered"] is False
        assert out["render_framework"] is None
        assert out["has_canonical"] is True
        assert out["og_tag_count"] == 2
        assert out["h1_count"] == 1
        assert out["h2_count"] == 2
        assert out["comparison_content"] is True

    def test_empty_html(self):
        from domain.geo_audit import _extract_geo

        out = _extract_geo("")
        assert out["schema_types"] == []
        assert out["client_side_rendered"] is False
        assert out["has_canonical"] is False
        assert out["og_tag_count"] == 0
        assert out["h1_count"] == 0
        assert out["comparison_content"] is False

    def test_spa_detected(self):
        """SPA framework marker + near-empty server HTML → client_side_rendered."""
        from domain.geo_audit import _extract_geo

        out = _extract_geo(_SPA_HTML)
        assert out["client_side_rendered"] is True
        assert out["render_framework"] == "__NEXT_DATA__"

    def test_ssr_not_flagged_despite_marker(self):
        """A content-rich page is NOT flagged even if it carries a framework
        marker — high visible-text ratio means AI crawlers see content."""
        from domain.geo_audit import _extract_geo

        html = _PERFECT_GEO_HTML.replace("</body>", "<script>window.__NEXT_DATA__={}</script></body>")
        out = _extract_geo(html)
        assert out["client_side_rendered"] is False

    def test_schema_types_none_when_no_jsonld(self):
        from domain.geo_audit import _extract_geo

        out = _extract_geo("<html><body><h1>x</h1></body></html>")
        assert out["schema_types"] == []

    def test_schema_types_graph_form(self):
        """@graph-wrapped JSON-LD must still yield the inner @types."""
        from domain.geo_audit import _extract_geo

        html = '<script type="application/ld+json">{"@graph":[{"@type":"FAQPage"}]}</script>'
        out = _extract_geo(html)
        assert "FAQPage" in out["schema_types"]

    def test_malformed_jsonld_does_not_crash(self):
        from domain.geo_audit import _extract_geo

        html = '<script type="application/ld+json">{not valid json</script>'
        out = _extract_geo(html)
        assert out["schema_types"] == []

    def test_spa_mount_react_vite_detected(self):
        """Modern React (Vite/CRA) serves an empty <div id="root"> + a JS
        bundle and NO framework string — the empty-mount heuristic must catch
        it (the old marker list did not: false-negative on rule 4)."""
        from domain.geo_audit import _extract_geo

        html = '<html><head><script type="module" src="/assets/index-Ck2.js"></script></head><body><div id="root"></div></body></html>'
        out = _extract_geo(html)
        assert out["client_side_rendered"] is True
        assert out["render_framework"] == "#root"

    def test_spa_mount_vue_detected(self):
        from domain.geo_audit import _extract_geo

        html = '<html><body><div id="app"></div><script type="module" src="/x.js"></script></body></html>'
        out = _extract_geo(html)
        assert out["client_side_rendered"] is True
        assert out["render_framework"] == "#app"

    def test_ssr_react_with_content_not_flagged(self):
        """A populated mount (server-rendered content inside #root) is SSR —
        must NOT be flagged even though #root exists."""
        from domain.geo_audit import _extract_geo

        body = "<div id='root'><h1>Real Product Page</h1><p>" + ("content " * 200) + "</p></div>"
        out = _extract_geo(f"<html><body>{body}</body></html>")
        assert out["client_side_rendered"] is False

    def test_ng_app_substring_not_false_matched(self):
        """A hyphenated word like 'shopping-app' must NOT trip the Angular
        marker (old code matched `ng-app` as a bare substring)."""
        from domain.geo_audit import _extract_geo

        html = '<html><body><a class="shopping-app">Shop</a><style>' + ("x{a:b}" * 500) + "</style></body></html>"
        out = _extract_geo(html)
        assert out["render_framework"] is None
        assert out["client_side_rendered"] is False

    def test_deeply_nested_jsonld_no_recursion_crash(self):
        """A hostile deeply-nested JSON-LD array (json.loads accepts it, the
        recursive walker overflowed the Python recursion limit → uncaught
        RecursionError → HTTP 500). The iterative walker must not raise."""
        from domain.geo_audit import _extract_geo

        payload = "[" * 1500 + '{"@type":"Organization"}' + "]" * 1500
        html = f'<script type="application/ld+json">{payload}</script>'
        out = _extract_geo(html)  # must not raise RecursionError
        assert isinstance(out["schema_types"], list)

    def test_ssr_with_huge_hydration_blob_not_flagged(self):
        """A server-rendered page whose __NEXT_DATA__ hydration blob dwarfs the
        visible text must NOT be flagged as a client-only SPA — the text ratio is
        measured against script-stripped markup, not the raw html that carries the
        blob (regression: raw-html denominator gave a false client_side_rendered)."""
        from domain.geo_audit import _extract_geo

        blob = '{"props":{"pageProps":{"x":"' + ("z" * 200000) + '"}}}'
        body = "<h1>Real SSR Product Page</h1><p>" + ("Genuine server-rendered marketing copy. " * 40) + "</p>"
        html = f'<html><body>{body}<script id="__NEXT_DATA__" type="application/json">{blob}</script></body></html>'
        out = _extract_geo(html)
        assert out["render_framework"] == "__NEXT_DATA__"
        assert out["client_side_rendered"] is False


# === _llms_txt_valid (llms.txt content-type guard) ===


class TestLlmsTxtValid:
    def test_plain_text_200_is_valid(self):
        from domain.geo_audit import _llms_txt_valid

        assert _llms_txt_valid(200, "text/plain; charset=utf-8", b"# llms.txt\nAllow") is True

    def test_markdown_200_is_valid(self):
        from domain.geo_audit import _llms_txt_valid

        assert _llms_txt_valid(200, "text/markdown", b"data") is True

    def test_html_200_rejected_soft_404(self):
        """SPA catch-all / soft-404 serves 200 text/html — must NOT count."""
        from domain.geo_audit import _llms_txt_valid

        assert _llms_txt_valid(200, "text/html; charset=utf-8", b"<!doctype html><html>x</html>") is False

    def test_non_200_rejected(self):
        from domain.geo_audit import _llms_txt_valid

        assert _llms_txt_valid(404, "text/plain", b"Not found") is False

    def test_empty_body_rejected(self):
        from domain.geo_audit import _llms_txt_valid

        assert _llms_txt_valid(200, "text/plain", b"   \n  ") is False


# === evaluate_ai_crawlers ===


class TestAiCrawlers:
    def test_all_allowed_when_no_robots(self):
        from domain.geo_audit import evaluate_ai_crawlers

        total, allowed, blocked = evaluate_ai_crawlers({"user_agents": {}, "sitemaps": [], "host": None})
        assert allowed == total
        assert blocked == []

    def test_gptbot_blocked(self):
        from domain.geo_audit import evaluate_ai_crawlers

        robots = {
            "user_agents": {"gptbot": {"allow": [], "disallow": ["/"], "crawl_delay": None}},
            "sitemaps": [],
            "host": None,
        }
        total, allowed, blocked = evaluate_ai_crawlers(robots)
        assert "GPTBot" in blocked
        assert allowed == total - 1

    def test_star_block_disallows_all(self):
        from domain.geo_audit import evaluate_ai_crawlers

        robots = {
            "user_agents": {"*": {"allow": [], "disallow": ["/"], "crawl_delay": None}},
            "sitemaps": [],
            "host": None,
        }
        total, allowed, blocked = evaluate_ai_crawlers(robots)
        assert allowed == 0
        assert len(blocked) == total


# === _score_geo (composite 0-100) ===


_PERFECT_PARSED = {
    "llms_txt_present": True,
    "ai_crawlers_total": 9,
    "ai_crawlers_allowed": 9,
    "ai_crawlers_blocked": [],
    "schema_types": ["Organization", "Product"],
    "client_side_rendered": False,
    "has_canonical": True,
    "og_tag_count": 2,
    "sitemap_count": 1,
    "h1_count": 1,
    "h2_count": 2,
    "comparison_content": True,
}


class TestScoreGeo:
    def test_perfect_score(self):
        from domain.geo_audit import _score_geo

        score, missing = _score_geo(dict(_PERFECT_PARSED))
        assert score == 100
        assert missing == []

    def test_llms_missing_loses_15(self):
        from domain.geo_audit import _score_geo

        parsed = dict(_PERFECT_PARSED, llms_txt_present=False)
        score, missing = _score_geo(parsed)
        assert score == 85
        assert "llms_txt_missing" in missing

    def test_spa_loses_15(self):
        from domain.geo_audit import _score_geo

        parsed = dict(_PERFECT_PARSED, client_side_rendered=True)
        score, missing = _score_geo(parsed)
        assert score == 85
        assert "client_side_rendered" in missing

    def test_all_crawlers_blocked_loses_25(self):
        from domain.geo_audit import _score_geo

        parsed = dict(_PERFECT_PARSED, ai_crawlers_allowed=0, ai_crawlers_blocked=["GPTBot"])
        score, missing = _score_geo(parsed)
        assert score == 75
        assert "ai_crawlers_blocked" in missing

    def test_one_crawler_blocked_proportional(self):
        """8/9 allowed → round(8/9*25)=22 → 100-25+22 = 97."""
        from domain.geo_audit import _score_geo

        parsed = dict(_PERFECT_PARSED, ai_crawlers_allowed=8, ai_crawlers_blocked=["GPTBot"])
        score, _missing = _score_geo(parsed)
        assert score == 97

    def test_schema_sparse_loses_10(self):
        from domain.geo_audit import _score_geo

        parsed = dict(_PERFECT_PARSED, schema_types=["Organization"])
        score, missing = _score_geo(parsed)
        assert score == 90
        assert "schema_org_sparse" in missing

    def test_schema_missing_loses_20(self):
        from domain.geo_audit import _score_geo

        parsed = dict(_PERFECT_PARSED, schema_types=[])
        score, missing = _score_geo(parsed)
        assert score == 80
        assert "schema_org_missing" in missing

    def test_no_comparison_loses_5(self):
        from domain.geo_audit import _score_geo

        parsed = dict(_PERFECT_PARSED, comparison_content=False)
        score, missing = _score_geo(parsed)
        assert score == 95
        assert "comparison_content_missing" in missing


# === Route /v1/geo/{domain} ===


_NO_ROBOTS = {
    "domain": "corp.com",
    "fetched_url": "https://corp.com/robots.txt",
    "status_code": 404,
    "user_agents": {},
    "sitemaps": ["https://corp.com/sitemap.xml"],
    "host": None,
    "truncated": False,
}

_GOOD_GEO_PAGE = {
    "html": _PERFECT_GEO_HTML,
    "url": "https://corp.com/",
    "status_code": 200,
    "cache_control": "",
}


class TestGeoAuditRoute:
    @patch("db.get_cached_domain", side_effect=[None, _NO_ROBOTS])
    @patch("db.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.geo_audit.fetch_llms_txt", new_callable=AsyncMock, return_value=True)
    @patch("domain.brand_assets.fetch_homepage_html", new_callable=AsyncMock, return_value=_GOOD_GEO_PAGE)
    def test_geo_audit_200_with_score(self, mock_fetch, mock_llms, mock_validate, mock_save, mock_cache):
        r = client.get("/v1/geo/corp.com")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["domain"] == "corp.com"
        assert isinstance(data["score"], int)
        assert 0 <= data["score"] <= 100
        assert "missing_signals" in data
        assert "ai_crawlers_total" in data

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
        with patch("db.get_cached_domain", side_effect=[None, blocked_robots]):
            with patch("domain.brand_assets.fetch_homepage_html", new_callable=AsyncMock) as mock_fetch:
                with patch("domain.geo_audit.fetch_llms_txt", new_callable=AsyncMock) as mock_llms:
                    r = client.get("/v1/geo/blocked.com")
                    assert r.status_code == 403
                    assert "robots_txt_disallow" in r.text
                    mock_fetch.assert_not_called()
                    mock_llms.assert_not_called()

    @patch("db.get_cached_domain", side_effect=[None, _NO_ROBOTS])
    @patch("db.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.geo_audit.fetch_llms_txt", new_callable=AsyncMock, return_value=False)
    @patch(
        "domain.brand_assets.fetch_homepage_html",
        new_callable=AsyncMock,
        return_value={**_GOOD_GEO_PAGE, "cache_control": "no-store"},
    )
    def test_cache_control_no_store_skips_cache_write(
        self, mock_fetch, mock_llms, mock_validate, mock_save, mock_cache
    ):
        r = client.get("/v1/geo/corp.com")
        assert r.status_code == 200
        data = r.json()
        assert data["cache_respected"] is False
        keys_written = [c.args[0] for c in mock_save.call_args_list]
        assert "geo:corp.com" not in keys_written

    @patch("db.get_cached_domain", side_effect=[None, _NO_ROBOTS])
    @patch("db.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.geo_audit.fetch_llms_txt", new_callable=AsyncMock, return_value=False)
    @patch("domain.brand_assets.fetch_homepage_html", new_callable=AsyncMock, side_effect=Exception("boom"))
    def test_homepage_fetch_failure_502(self, mock_fetch, mock_llms, mock_validate, mock_save, mock_cache):
        r = client.get("/v1/geo/corp.com")
        assert r.status_code == 502
        assert "geo_audit fetch failed" in r.text


def test_geo_audit_mcp_tool_registered(mcp_client):
    pytest.importorskip("mcp")
    r = mcp_client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream", "Content-Type": "application/json"},
    )
    assert r.status_code == 200
    assert "geo_audit" in r.text
