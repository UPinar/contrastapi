"""GEO-readiness (AI-visibility) audit scorer.

Scores whether AI assistants (ChatGPT, Claude, Perplexity, Google AI)
can discover, crawl, and recommend a domain — the AI-native cousin of
`seo_audit`. Deterministic + structural ONLY: no LLM is queried. Signals:
llms.txt presence, robots.txt AI-crawler access, schema.org @type
coverage, server-side vs client-only rendering, OG/canonical/sitemap
discovery signals, semantic headings, comparison content.

Shares seo_audit/brand_assets infra: the SSRF-safe HTTP client, robots
ethical floor, per-target throttle, cache, `_strip_control_chars`. We DO
NOT crawl past "/".
"""

from __future__ import annotations

import asyncio
import json
import logging

from bs4 import BeautifulSoup
from domain.brand_assets import homepage_allowed
from domain.recon import _ssrf_http, _strip_control_chars

logger = logging.getLogger("contrastapi")

# AI crawler product-tokens — a 9-token subset of the AI-bot roster in
# app/api/discovery.py (the highest-signal recommendation/answer bots).
# Blocking any of these in robots.txt = invisible to that AI surface.
AI_CRAWLERS = (
    "GPTBot",
    "OAI-SearchBot",
    "ChatGPT-User",
    "ClaudeBot",
    "Claude-SearchBot",
    "anthropic-ai",
    "PerplexityBot",
    "Google-Extended",
    "CCBot",
)

# schema.org @types that signal AI-recommendable structured data.
_VALUABLE_SCHEMA_TYPES = frozenset(
    {"Organization", "Product", "FAQPage", "SoftwareApplication", "WebSite", "BreadcrumbList"}
)

# JS-bundle markers that appear in SERVED HTML (not runtime-only DOM
# properties). Presence + a low visible-text ratio => the server sends
# near-empty HTML that AI crawlers without JS execution cannot read.
# NB: the earlier list included runtime-only signals (`_reactRootContainer`,
# `__vue__`) and SSR markers (`data-reactroot`) that never/wrongly appear
# in served HTML — dropped. Modern React/Vue/Angular are caught via the
# empty-mount check below, not a served string.
_SPA_BUNDLE_MARKERS = (
    "__NEXT_DATA__",
    "/_next/static/",
    "__NUXT__",
    "___gatsby",
    "__remixContext",
)

# Empty client-side-render mount points — modern React (Vite/CRA), Vue 3,
# and Angular 2+ serve an empty root element + a JS bundle; content only
# exists after hydration, so an AI crawler without JS sees nothing.
_SPA_MOUNT_IDS = ("root", "app", "__next", "__nuxt", "___gatsby")

_COMPARISON_TOKENS = (" vs ", " vs.", "versus", "compare", "comparison", "alternative")

_MAX_JSONLD_BLOCKS = 20
_MAX_JSONLD_BYTES = 262144  # 256 KB per block
_MAX_JSONLD_NODES = 2000  # bound total nodes walked per block (recursion/DoS guard)
_MAX_SCHEMA_TYPES = 50
_MAX_OG_TAGS = 50
_SPA_TEXT_RATIO_THRESHOLD = 0.05  # visible-text / html-length below this + a marker => SPA
_LLMS_MAX_BYTES = 65536  # 64 KB cap for the llms.txt probe


def _iter_jsonld_nodes(data):
    """Yield dict nodes from a JSON-LD payload, unrolling lists and any
    nested `@graph`. Iterative (explicit heap stack) + a total-node cap so a
    hostile deeply-nested payload cannot exhaust the Python recursion limit
    — the earlier recursive form raised an uncaught RecursionError on a
    ~4 KB nested-array block that json.loads happily accepts."""
    stack = [data]
    walked = 0
    while stack and walked < _MAX_JSONLD_NODES:
        node = stack.pop()
        walked += 1
        if isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, dict):
            yield node
            graph = node.get("@graph")
            if isinstance(graph, list):
                stack.extend(graph)


def _extract_schema_types(soup: BeautifulSoup) -> list[str]:
    """Collect distinct valuable schema.org @types from JSON-LD blocks.

    Hardened: block cap, per-block byte cap, blanket except on malformed
    JSON, and a bounded iterative walk (`_iter_jsonld_nodes`) that cannot
    overflow the recursion limit on a hostile nested payload.
    """
    found: list[str] = []
    seen: set[str] = set()
    blocks = soup.find_all("script", type="application/ld+json", limit=_MAX_JSONLD_BLOCKS)
    for block in blocks:
        raw = block.string or block.get_text() or ""
        if len(raw) > _MAX_JSONLD_BYTES:
            continue
        try:
            data = json.loads(raw)
        except Exception:
            continue
        for node in _iter_jsonld_nodes(data):
            if not isinstance(node, dict):
                continue
            t = node.get("@type")
            types = t if isinstance(t, list) else [t]
            for tv in types:
                if isinstance(tv, str) and tv in _VALUABLE_SCHEMA_TYPES and tv not in seen:
                    seen.add(tv)
                    found.append(tv)
                    if len(found) >= _MAX_SCHEMA_TYPES:
                        return found
    return found


def _detect_render_framework(soup: BeautifulSoup, html: str) -> str | None:
    """Return a client-render signal label — a JS-bundle marker in the
    served HTML, an Angular `ng-app` attribute, or an EMPTY SPA mount
    element (`<div id='root'>`, `<app-root>`, …) — or None. The caller
    combines this with the visible-text ratio: a marker present alongside
    real content means SSR, not a client-only render.
    """
    for marker in _SPA_BUNDLE_MARKERS:
        if marker in html:
            return marker
    # `ng-app` as an ATTRIBUTE (not a bare substring — avoids matching
    # hyphenated words like "shopping-app" in class names / copy).
    if soup.find(attrs={"ng-app": True}) is not None:
        return "ng-app"
    app_root = soup.find("app-root")
    if app_root is not None and not app_root.get_text(strip=True):
        return "app-root"
    for mid in _SPA_MOUNT_IDS:
        el = soup.find(id=mid)
        if el is not None and not el.get_text(strip=True):
            return f"#{mid}"
    return None


def _extract_geo(html: str) -> dict:
    """Pure parser — no network. Pulls GEO-relevant structural fields out
    of `html`. The route merges in llms.txt / AI-crawler / sitemap fields
    before scoring.
    """
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception as exc:
        logger.debug("geo_audit: BeautifulSoup parse failed: %s", exc)
        soup = BeautifulSoup("", "html.parser")

    # schema.org @types — extract BEFORE stripping <script> below.
    schema_types = _extract_schema_types(soup)

    # Strip non-content tags so the visible-text ratio (and the empty-mount
    # check) reflect what an AI crawler without JS execution would see.
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()

    # Client-render signal: a bundle marker in the raw html, an ng-app
    # attribute, or an empty SPA mount element (post-decompose soup).
    render_framework = _detect_render_framework(soup, html)

    canon = soup.find("link", rel=lambda v: v and "canonical" in (v if isinstance(v, list) else [v]))
    has_canonical = bool(canon and canon.get("href"))

    og_count = 0
    for meta in soup.find_all("meta", limit=300):
        prop = _strip_control_chars(meta.get("property") or "").strip()
        if prop.startswith("og:"):
            og_count += 1

    h1_count = len(soup.find_all("h1"))
    h2_count = len(soup.find_all("h2"))

    visible_text = soup.get_text(" ", strip=True)
    # Ratio denominator is the script-stripped markup (soup is post-decompose),
    # NOT the raw html: a large hydration blob (e.g. __NEXT_DATA__) on an SSR
    # page must not deflate the ratio into a false client_side_rendered flag.
    stripped_len = len(str(soup))
    text_ratio = len(visible_text) / max(stripped_len, 1)
    client_side_rendered = render_framework is not None and text_ratio < _SPA_TEXT_RATIO_THRESHOLD

    lowered = visible_text.lower()
    comparison_content = any(tok in lowered for tok in _COMPARISON_TOKENS)

    return {
        "schema_types": schema_types,
        "client_side_rendered": client_side_rendered,
        "render_framework": render_framework,
        "has_canonical": has_canonical,
        "og_tag_count": min(og_count, _MAX_OG_TAGS),
        "h1_count": h1_count,
        "h2_count": h2_count,
        "comparison_content": comparison_content,
    }


def evaluate_ai_crawlers(robots_payload: dict) -> tuple[int, int, list[str]]:
    """For each AI crawler token, decide if path `/` is allowed by the
    target's robots.txt. Returns (total, allowed_count, blocked_tokens)."""
    blocked: list[str] = []
    for bot in AI_CRAWLERS:
        allowed, _pat = homepage_allowed(robots_payload, ua_token=bot.lower())
        if not allowed:
            blocked.append(bot)
    total = len(AI_CRAWLERS)
    return total, total - len(blocked), blocked


def _llms_txt_valid(status_code: int, content_type: str, body: bytes) -> bool:
    """A real llms.txt is a 200 with a non-empty body that is NOT text/html.
    An HTML 200 is a SPA catch-all / soft-404 rewrite (`/* -> index.html`)
    or a redirect to the homepage, not a genuine llms.txt file — it must not
    earn the score (llms.txt is served as text/plain or markdown)."""
    if status_code != 200:
        return False
    if "text/html" in (content_type or "").lower():
        return False
    return len(body.strip()) > 0


async def fetch_llms_txt(domain: str) -> bool:
    """Probe https://<domain>/llms.txt (HTTP fallback). True iff a 200
    non-HTML non-empty body is served. Shared SSRF-safe client, identity
    encoding, 64 KB cap. Any failure → False (absence, not error)."""
    no_compression = {"Accept-Encoding": "identity"}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/llms.txt"
        try:
            req = _ssrf_http.build_request("GET", url, headers=no_compression)
            resp = await _ssrf_http.send(req, stream=True, follow_redirects=True)
            try:
                status_code = resp.status_code
                content_type = resp.headers.get("Content-Type") or ""
                buf = bytearray()
                async for chunk in resp.aiter_bytes():
                    buf += chunk
                    if len(buf) >= _LLMS_MAX_BYTES:
                        break
            finally:
                await asyncio.shield(resp.aclose())
            return _llms_txt_valid(status_code, content_type, bytes(buf))
        except Exception as exc:
            logger.debug("geo_audit: llms.txt fetch failed %s://%s/llms.txt: %s", scheme, domain, exc)
            continue
    return False


def _score_geo(parsed: dict) -> tuple[int, list[str]]:
    """Compute a 0-100 GEO-readiness score from the merged parsed fields.

    7 weighted rules (total 100): llms.txt (15), AI-crawler access (25,
    proportional), schema.org @types (20), server-side rendering (15),
    discovery og/canonical/sitemap (10), semantic headings (10),
    comparison content (5). Returns (score, missing_signals).
    """
    score = 0
    missing: list[str] = []

    # 1. llms.txt present (15)
    if parsed.get("llms_txt_present"):
        score += 15
    else:
        missing.append("llms_txt_missing")

    # 2. AI-crawler robots access (proportional, 0-25) — the dominant signal
    total = parsed.get("ai_crawlers_total", 0)
    allowed = parsed.get("ai_crawlers_allowed", 0)
    if total > 0:
        score += round(allowed / total * 25)
        if allowed < total:
            missing.append("ai_crawlers_blocked")
    else:
        score += 25  # no robots data → nobody blocked → full credit

    # 3. schema.org @type coverage (0 / 10 / 20)
    found = len(parsed.get("schema_types") or [])
    score += round(min(found, 2) / 2 * 20)
    if found == 0:
        missing.append("schema_org_missing")
    elif found == 1:
        missing.append("schema_org_sparse")

    # 4. Server-side rendered (15) — a JS-only SPA serves AI crawlers empty HTML
    if parsed.get("client_side_rendered"):
        missing.append("client_side_rendered")
    else:
        score += 15

    # 5. Discovery signals: og (4) + canonical (3) + sitemap (3)
    if parsed.get("og_tag_count", 0) > 0:
        score += 4
    else:
        missing.append("og_missing")
    if parsed.get("has_canonical"):
        score += 3
    else:
        missing.append("canonical_missing")
    if parsed.get("sitemap_count", 0) > 0:
        score += 3
    else:
        missing.append("sitemap_missing")

    # 6. Semantic headings: single H1 (5) + H2 structure (5)
    if parsed.get("h1_count", 0) == 1:
        score += 5
    else:
        missing.append("h1_not_single")
    if parsed.get("h2_count", 0) > 0:
        score += 5
    else:
        missing.append("no_h2_structure")

    # 7. Comparison content (5)
    if parsed.get("comparison_content"):
        score += 5
    else:
        missing.append("comparison_content_missing")

    score = max(0, min(100, score))
    return score, missing
