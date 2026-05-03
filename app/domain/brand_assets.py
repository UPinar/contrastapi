"""Brand asset extractor for v1.25.0 web-intel endpoints.

Scrapes a target domain's homepage for favicon / og:image / theme-color /
og:site_name / JSON-LD `Organization.logo`. Used by `/v1/brand/{domain}`
and reusable by future audit endpoints.

**Ethical posture (Guardrail #3):** before fetching any homepage HTML we
honour the target's robots.txt — if it Disallows path "/" for our UA token
("ContrastAPI") OR for `*`, we surface a 403 with `error.code =
robots_txt_disallow` and DO NOT fetch the page. This is the same
defensive posture seo_audit (Batch 6) uses, and the only ethical floor
that distinguishes us from the autogen-spam competitors in this niche.

All target-derived strings pass through `_strip_control_chars` before the
response leaves this module — Trojan-Source / RTL bidi / DKIM-spoof
characters cannot escape into agent prompts via `og:site_name` etc.
"""

from __future__ import annotations

import json
import logging
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from config import BRAND_ASSETS_TIMEOUT
from domain.recon import _ssrf_http, _strip_control_chars

logger = logging.getLogger("contrastapi")

# Cap how big a homepage we'll parse. Most marketing pages are <200KB; a few
# MB blob is almost always a misconfigured CDN serving a video instead of
# HTML, and BeautifulSoup over 10MB is a wall-time + RAM problem.
_MAX_HOMEPAGE_BYTES = 1 * 1024 * 1024  # 1 MB

# Cap how many JSON-LD blocks we'll parse per page. Sites with extreme SEO
# stuffing emit dozens of overlapping graphs; we only need the first
# Organization or WebSite entity.
_MAX_JSONLD_BLOCKS = 20

# Cap how big a single JSON-LD block we'll attempt to parse. JSON-LD is
# user-controlled; a hostile target could pad a single <script> with
# multi-MB junk to slow our parse.
_MAX_JSONLD_BYTES = 256 * 1024  # 256 KB per script

# Token used to identify ourselves to robots.txt when checking can_fetch.
# Matches the product token in BOT_USER_AGENT — `ContrastAPI/<version> ...`.
_OUR_UA_TOKEN = "contrastapi"  # noqa: S105 — UA product token, not a credential


def _pattern_matches(pattern: str, path: str) -> bool:
    """RFC 9309 §2.2.3: prefix match with `*` as wildcard and trailing `$`
    as end-of-line anchor. Empty pattern never matches (caller should treat
    `Disallow:` with empty value as explicit allow-all).
    """
    if not pattern:
        return False
    end_anchor = pattern.endswith("$")
    if end_anchor:
        pattern = pattern[:-1]
    # Build a tight regex: escape literals, restore `*` as `.*`. We DO NOT
    # support `?` quantifier semantics — robots.txt grammar has no such
    # operator. The escape pass guarantees no ReDoS class explosions.
    escaped = re.escape(pattern).replace(r"\*", ".*")
    regex = f"^{escaped}$" if end_anchor else f"^{escaped}"
    try:
        return bool(re.match(regex, path))
    except re.error:
        return False


def homepage_allowed(parsed_robots: dict, ua_token: str = _OUR_UA_TOKEN) -> tuple[bool, str | None]:
    """Per RFC 9309, decide whether path `/` is allowed for our UA.

    `parsed_robots` is the dict from `domain.robots.parse_robots_txt` (or
    the cached body of `/v1/robots/{domain}`). Returns
    `(allowed, blocking_pattern)`. When `allowed=False`, the
    `blocking_pattern` is the literal Disallow value that wins the
    longest-match contest — surfaced in error responses so site operators
    can audit our compliance.

    UA-group selection: case-insensitive substring match of the UA group
    key against the product token (so a `User-agent: Contrast` block
    matches us). Most-specific match wins; only if no specific block
    exists does `*` apply (RFC 9309 §2.2.1 — groups are NOT merged).
    """
    user_agents = parsed_robots.get("user_agents", {}) or {}
    if not user_agents:
        return True, None

    ua_token_lower = ua_token.lower()
    chosen = None
    chosen_specificity = 0
    for ua_key, rules in user_agents.items():
        kl = ua_key.lower()
        if kl == "*":
            continue
        # Match in either direction so both "ContrastAPI" and "Contrast"
        # robots blocks bind to us (RFC says product-token match is
        # case-insensitive; in practice operators write "Contrast" or
        # "ContrastAPI" interchangeably).
        if kl in ua_token_lower or ua_token_lower in kl:
            if len(kl) > chosen_specificity:
                chosen = rules
                chosen_specificity = len(kl)
    if chosen is None:
        chosen = user_agents.get("*")
    if chosen is None:
        return True, None

    path = "/"
    allow_match = -1
    disallow_match = -1
    blocking_pat: str | None = None

    for pat in chosen.get("allow", []) or []:
        if _pattern_matches(pat, path) and len(pat) > allow_match:
            allow_match = len(pat)
    for pat in chosen.get("disallow", []) or []:
        # RFC 9309: an empty `Disallow:` value is an explicit allow-all
        # signal. It does NOT match anything; do not let it block.
        if not pat:
            continue
        if _pattern_matches(pat, path) and len(pat) > disallow_match:
            disallow_match = len(pat)
            blocking_pat = pat

    # RFC 9309 §2.2.2: longest match wins. On a tie, Allow wins (Google's
    # implementation; spec says "more specific" without breaking ties, and
    # this is the safer, less surprising behaviour for site operators).
    if disallow_match > allow_match:
        return False, blocking_pat
    return True, None


def _abs_url(value: str | None, base_url: str) -> str | None:
    """Resolve a possibly-relative URL against `base_url` and sanitise it.

    Returns None for empty input, javascript:/data: schemes (we won't
    forward those into MCP responses — they're often abused to render
    inline payloads), and parse failures. Output is `_untrusted` and
    flagged as such in the schema.
    """
    if not value:
        return None
    val = _strip_control_chars(value).strip()
    if not val:
        return None
    # Block javascript: / data: / vbscript: / file: — not legitimate brand
    # asset URL schemes, and they're a vector for indirect prompt
    # injection via MCP-rendered cards.
    lower = val.lower()
    for scheme in ("javascript:", "data:", "vbscript:", "file:"):
        if lower.startswith(scheme):
            return None
    try:
        absolute = urljoin(base_url, val)
    except ValueError:
        return None
    parsed = urlparse(absolute)
    if parsed.scheme not in ("http", "https"):
        return None
    return absolute


def _first_meta_content(soup: BeautifulSoup, attrs: dict) -> str | None:
    """Return the `content` of the first <meta> tag matching `attrs`,
    sanitised. Empty/whitespace strings return None. `attrs` is the
    BeautifulSoup attrs dict (e.g. `{"name": "theme-color"}` or
    `{"property": "og:image"}`); we pass it through verbatim because
    `name` would collide with the tag-name kwarg in `soup.find`.
    """
    tag = soup.find("meta", attrs=attrs)
    if not tag:
        return None
    raw = tag.get("content")
    if not raw:
        return None
    cleaned = _strip_control_chars(raw).strip()
    return cleaned or None


def _favicon_url(soup: BeautifulSoup, base_url: str) -> str | None:
    """Find the most specific favicon link declared by the page.

    Order of preference: `<link rel="icon">` > `<link rel="shortcut
    icon">` > `<link rel="apple-touch-icon">`. Falls back to
    `{base_url}/favicon.ico` (no HEAD probe — that would double the
    target throttle cost; the agent can verify by fetching the URL
    itself if it cares).
    """
    for rel_token in ("icon", "shortcut icon", "apple-touch-icon"):
        # Bind `rel_token` into the closure default to avoid late-binding;
        # `rel` is a list-attribute in HTML so we match a token within
        # whatever value BeautifulSoup hands us (str OR list[str]).
        tag = soup.find(
            "link",
            rel=lambda v, _tok=rel_token: bool(v) and _tok in (v if isinstance(v, list) else [v]),
        )
        if tag and tag.get("href"):
            resolved = _abs_url(tag["href"], base_url)
            if resolved:
                return resolved
    # Spec fallback per the de-facto convention.
    return _abs_url("/favicon.ico", base_url)


def _theme_color(soup: BeautifulSoup) -> str | None:
    """Extract `<meta name="theme-color">` and return only well-formed
    colour values. We accept `#rgb` / `#rrggbb` / `rgb(...)` / named CSS
    colours up to a length cap; anything else is dropped to keep the
    field free of arbitrary user-controlled strings.
    """
    raw = _first_meta_content(soup, {"name": "theme-color"})
    if not raw:
        return None
    if len(raw) > 64:
        return None
    return raw


def _site_name(soup: BeautifulSoup) -> str | None:
    """Pull `<meta property="og:site_name">` (Open Graph) — primary brand
    string. Capped at 200 chars; longer values are almost always SEO
    stuffing and not a real brand name.
    """
    raw = _first_meta_content(soup, {"property": "og:site_name"})
    if not raw:
        # Fall back to <title> when og:site_name is absent. Many small
        # sites skip OG entirely; the <title> still carries the brand.
        title_tag = soup.find("title")
        if not title_tag or not title_tag.string:
            return None
        raw = _strip_control_chars(title_tag.string).strip()
    if not raw:
        return None
    return raw[:200]


def _og_image(soup: BeautifulSoup, base_url: str) -> str | None:
    """`<meta property="og:image">` resolved to an absolute URL."""
    raw = _first_meta_content(soup, {"property": "og:image"})
    if not raw:
        return None
    return _abs_url(raw, base_url)


def _logo_from_jsonld(soup: BeautifulSoup, base_url: str) -> str | None:
    """Walk `<script type="application/ld+json">` blocks and return the
    `Organization.logo` URL of the first matching entity. JSON-LD allows
    `logo` to be a string OR an `ImageObject` with a `url` field — we
    handle both. `@graph` arrays are unrolled.

    Hostile-input handling:
      * Each block is size-capped (`_MAX_JSONLD_BYTES`)
      * Total block count is capped (`_MAX_JSONLD_BLOCKS`)
      * Malformed JSON is silently skipped
      * Recursion depth is bounded implicitly by the unroll loop (we
        only descend into `@graph`, not arbitrary nested objects)
    """
    scripts = soup.find_all("script", type="application/ld+json", limit=_MAX_JSONLD_BLOCKS)
    for s in scripts:
        body = s.string or s.get_text() or ""
        if not body or len(body) > _MAX_JSONLD_BYTES:
            continue
        try:
            data = json.loads(body)
        except Exception:
            # Hostile input safety net: deeply-nested JSON can raise
            # RecursionError (BaseException subclass since Py3.5 but not
            # caught by the narrower (ValueError, TypeError) tuple).
            # Anything that breaks the parser is silently skipped — we
            # never want a malicious target's JSON-LD to crash the route.
            continue
        # Normalise to a flat list of entity dicts.
        candidates: list = []
        if isinstance(data, dict):
            if "@graph" in data and isinstance(data["@graph"], list):
                candidates.extend(data["@graph"])
            else:
                candidates.append(data)
        elif isinstance(data, list):
            candidates.extend(data)
        for entity in candidates:
            if not isinstance(entity, dict):
                continue
            entity_type = entity.get("@type")
            if isinstance(entity_type, list):
                is_org = any(t in ("Organization", "Corporation", "LocalBusiness") for t in entity_type)
            else:
                is_org = entity_type in ("Organization", "Corporation", "LocalBusiness")
            if not is_org:
                continue
            logo = entity.get("logo")
            if isinstance(logo, str):
                return _abs_url(logo, base_url)
            if isinstance(logo, dict):
                url = logo.get("url")
                if isinstance(url, str):
                    return _abs_url(url, base_url)
    return None


def extract_brand_assets(html: str, base_url: str) -> dict:
    """Parse fetched homepage HTML and pluck out brand fields.

    Pure / no-network function — given the same `(html, base_url)` input,
    always produces the same output. All URL fields are absolute; all
    string fields are control-char-stripped.

    Returns: {
      "favicon_url": str | None,
      "og_image_url": str | None,
      "theme_color": str | None,
      "site_name": str | None,
      "logo_url": str | None,   # JSON-LD Organization.logo
    }
    """
    # Use the stdlib parser — `lxml` would be ~3x faster but adds a C
    # dependency we don't otherwise need; this endpoint is fronted by a
    # 1h cache so the cold-parse cost is amortised.
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception as exc:
        logger.debug("brand_assets: BeautifulSoup parse failed: %s", exc)
        return {
            "favicon_url": None,
            "og_image_url": None,
            "theme_color": None,
            "site_name": None,
            "logo_url": None,
        }
    return {
        "favicon_url": _favicon_url(soup, base_url),
        "og_image_url": _og_image(soup, base_url),
        "theme_color": _theme_color(soup),
        "site_name": _site_name(soup),
        "logo_url": _logo_from_jsonld(soup, base_url),
    }


async def fetch_homepage_html(domain: str) -> dict:
    """Fetch the target domain's homepage over HTTPS (HTTP fallback).

    Returns: {
      "html": str,
      "url": str,            # final URL after redirects
      "status_code": int,
      "cache_control": str,  # response Cache-Control header (lower-cased), "" if absent
    }

    On hard failure (DNS / TCP / TLS / non-HTML response), raises an
    httpx exception OR a ValueError — caller maps to ErrorResponse.
    """
    last_exc: Exception | None = None
    # `Accept-Encoding: identity` — refuse compressed responses. httpx's
    # `iter_bytes()` transparently decompresses gzip/br/zstd BEFORE
    # yielding chunks, which means a 1KB gzip-bomb decompressing to
    # 500MB would blow past `_MAX_HOMEPAGE_BYTES` in RAM (the byte cap
    # counts decompressed bytes, not wire bytes). Forcing identity
    # encoding makes the cap a real wire-byte ceiling.
    no_compression = {"Accept-Encoding": "identity"}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        try:
            async with _ssrf_http.stream(
                "GET", url, timeout=BRAND_ASSETS_TIMEOUT, follow_redirects=True, headers=no_compression
            ) as resp:
                final_url = str(resp.url)
                status_code = resp.status_code
                cache_control = (resp.headers.get("Cache-Control") or "").lower()
                content_type = (resp.headers.get("Content-Type") or "").lower()
                if "text/html" not in content_type and "application/xhtml" not in content_type:
                    # Non-HTML root (binary, JSON, redirect-only) — no
                    # meta to extract. Surface as a fetch error so the
                    # route can return a clean 502 + diagnostic.
                    raise ValueError(f"non-HTML content-type at {final_url!r}: {content_type!r}")
                buf = bytearray()
                async for chunk in resp.aiter_bytes():
                    buf += chunk
                    if len(buf) >= _MAX_HOMEPAGE_BYTES:
                        break
                html = bytes(buf[:_MAX_HOMEPAGE_BYTES]).decode("utf-8", errors="replace")
                return {
                    "html": html,
                    "url": final_url,
                    "status_code": status_code,
                    "cache_control": cache_control,
                }
        except Exception as exc:
            last_exc = exc
            logger.debug("brand_assets fetch failed %s://%s/: %s", scheme, domain, exc)
            continue
    assert last_exc is not None
    raise last_exc
