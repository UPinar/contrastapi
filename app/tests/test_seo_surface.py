"""Tests for the search-indexable surface of api.contrastcyber.com.

Three invariants keep a crawler from splitting one page across several URLs:
  * every indexable HTML page declares the canonical it should consolidate onto,
  * trailing-slash variants answer 301, not the framework default 307 — a
    temporary redirect is re-crawled instead of folded into the bare path,
  * the sitemap lists HTML pages only. The .txt/.json discovery surfaces are
    reachable from robots.txt and /.well-known; crawlers fetch but never index
    them, so a sitemap entry can never resolve to an indexed page.
"""

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

# Every HTML page a crawler is meant to index, with the canonical it must declare.
CANONICAL_PAGES = {
    "/": "https://api.contrastcyber.com/",
    "/quickstart": "https://api.contrastcyber.com/quickstart",
    "/mcp-setup": "https://api.contrastcyber.com/mcp-setup",
    "/pricing": "https://api.contrastcyber.com/pricing",
    "/terms": "https://api.contrastcyber.com/terms",
    "/privacy": "https://api.contrastcyber.com/privacy",
    "/cn/": "https://api.contrastcyber.com/cn/",
}

# Pages whose trailing-slash variant must 301 (not 307) onto the bare path.
SLASH_REDIRECT_PAGES = ("quickstart", "mcp-setup", "pricing", "terms", "privacy")


def test_indexable_pages_declare_canonical():
    for path, canonical in CANONICAL_PAGES.items():
        r = client.get(path)
        assert r.status_code == 200, f"{path} returned {r.status_code}"
        assert f'rel="canonical" href="{canonical}"' in r.text, f"{path} missing canonical {canonical}"


def test_indexable_pages_declare_meta_description():
    for path in CANONICAL_PAGES:
        body = client.get(path).text
        marker = '<meta name="description" content="'
        assert marker in body, f"{path} declares no meta description"
        content = body.split(marker, 1)[1].split('"', 1)[0]
        assert len(content) >= 50, f"{path} meta description is too thin to be a search snippet"


def test_trailing_slash_redirects_are_permanent():
    no_redirect = TestClient(app, follow_redirects=False)
    for page in SLASH_REDIRECT_PAGES:
        r = no_redirect.get(f"/{page}/")
        assert r.status_code == 301, f"/{page}/ returned {r.status_code}, expected 301"
        assert r.headers["location"] == f"/{page}"


def test_sitemap_lists_only_indexable_html_pages():
    body = client.get("/sitemap.xml").text
    locs = [chunk.split("</loc>")[0] for chunk in body.split("<loc>")[1:]]

    assert locs, "sitemap has no <loc> entries"
    # .txt/.json are agent-discovery surfaces (robots.txt, /.well-known) — crawlers
    # fetch but never index them, so a sitemap entry can never resolve to a result.
    for loc in locs:
        assert not loc.endswith((".txt", ".json")), f"sitemap advertises non-indexable {loc}"
        assert loc in CANONICAL_PAGES.values(), f"sitemap lists {loc}, which declares no canonical"
    # And the reverse: an indexable page missing from the sitemap is left to be
    # discovered by chance.
    assert set(locs) == set(CANONICAL_PAGES.values()), (
        f"sitemap is missing {sorted(set(CANONICAL_PAGES.values()) - set(locs))}"
    )
