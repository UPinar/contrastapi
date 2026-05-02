"""SEO audit scorer for v1.25.0 web-intel endpoints.

Pulls a target domain's homepage HTML and produces a structured SEO
audit: title, meta description, H1/H2/H3 counts, image alt-text
coverage, internal/external link split, canonical, Open Graph tags,
JSON-LD presence, and a 0-100 composite score.

Same ethical floor as `brand_assets` — robots.txt is honoured before
fetch, Cache-Control: no-store/private skips our cache, per-target
eTLD+1 throttle is consumed at the route level. We DO NOT crawl past
path "/"; this is a single-page audit, not a sitemap walk.

The fetcher is shared with `brand_assets` (homepage HTML, 1 MB cap,
identity encoding to defeat gzip-bombs); the parser/scorer is
seo-specific.
"""

from __future__ import annotations

import logging
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from domain.brand_assets import (
    _abs_url,
    _strip_control_chars,
    fetch_homepage_html,  # noqa: F401 — re-exported for test patching
    homepage_allowed,  # noqa: F401 — re-exported for the route handler's import path
)

logger = logging.getLogger("contrastapi")

# Caps — every list field has a hard ceiling so a hostile target can't
# blow past JSON wire size. The numbers are picked so that a real-world
# page (Shopify product, news article, marketing landing) fits inside
# the cap and only adversarial / scraping-target pages get clipped.
_MAX_H1 = 20  # >20 H1s is itself a red flag, surfaced in score
_MAX_H_COUNT = 200  # bound on H2/H3 counts in the response
_MAX_IMAGES_COUNTED = 1000  # we count, don't store; bound is for parse cost
_MAX_LINKS_COUNTED = 2000  # same — count only, no per-link payload
_MAX_OG_TAGS = 50  # og:* meta-tag map cap
_MAX_TITLE_LEN = 300  # raw cap on title text BEFORE the score check
_MAX_META_DESC_LEN = 500  # raw cap on description BEFORE the score check


def _same_registrable(host_a: str, host_b: str) -> bool:
    """Cheap eTLD-aware comparison for internal/external link split.

    We don't pull tldextract here for two reasons: (1) the throttle
    layer already runs eTLD+1 logic at the route level, and (2) we
    want to keep `seo_audit` free of network calls during scoring (the
    Public Suffix List bundled with tldextract loads at import time and
    is fine, but the function is hot-pathed across thousands of links
    on long pages).

    Falls back to last-2-labels match when both hosts share at least
    two labels — wrong for `.co.uk` etc. but OK for the rough split
    we surface here. The exact internal/external boundary is a
    judgement call no SEO tool gets right 100% anyway.
    """
    if not host_a or not host_b:
        return False
    a = host_a.lower().strip(".")
    b = host_b.lower().strip(".")
    if a == b:
        return True
    if a.endswith("." + b) or b.endswith("." + a):
        return True
    a_parts = a.split(".")
    b_parts = b.split(".")
    if len(a_parts) >= 2 and len(b_parts) >= 2:
        return a_parts[-2:] == b_parts[-2:]
    return False


def _extract_seo(html: str, base_url: str) -> dict:
    """Pure parser — no network. Pulls every SEO-relevant field out of
    `html` and returns a dict matching `SeoAuditResponse` (minus the
    `score` and `summary`, which the route handler computes).

    All target-derived strings pass through `_strip_control_chars`.
    """
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception as exc:
        logger.debug("seo_audit: BeautifulSoup parse failed: %s", exc)
        soup = BeautifulSoup("", "html.parser")

    # --- title ---
    title_tag = soup.find("title")
    raw_title = title_tag.string if title_tag and title_tag.string else None
    title = _strip_control_chars(raw_title).strip() if raw_title else None
    if title and len(title) > _MAX_TITLE_LEN:
        title = title[:_MAX_TITLE_LEN]

    # --- meta description ---
    desc_tag = soup.find("meta", attrs={"name": "description"})
    desc = None
    if desc_tag and desc_tag.get("content"):
        desc = _strip_control_chars(desc_tag["content"]).strip() or None
        if desc and len(desc) > _MAX_META_DESC_LEN:
            desc = desc[:_MAX_META_DESC_LEN]

    # --- canonical ---
    canon_tag = soup.find("link", rel=lambda v: v and "canonical" in (v if isinstance(v, list) else [v]))
    canonical = None
    if canon_tag and canon_tag.get("href"):
        canonical = _abs_url(canon_tag["href"], base_url)

    # --- headings ---
    h1_tags = soup.find_all("h1")
    h1: list[str] = []
    for h in h1_tags[:_MAX_H1]:
        text = _strip_control_chars(h.get_text()).strip()
        if text:
            h1.append(text[:_MAX_TITLE_LEN])
    h1_count = len(h1_tags)
    h2_count = min(len(soup.find_all("h2")), _MAX_H_COUNT)
    h3_count = min(len(soup.find_all("h3")), _MAX_H_COUNT)

    # --- images ---
    img_tags = soup.find_all("img", limit=_MAX_IMAGES_COUNTED)
    images_total = len(img_tags)
    images_missing_alt = 0
    for img in img_tags:
        # Empty alt="" IS valid per WCAG (decorative image), but we
        # count it as "missing meaningful alt" because in SEO context
        # nearly every image should have descriptive text. Surfacing
        # both numbers lets the agent decide.
        alt = img.get("alt")
        if alt is None or not str(alt).strip():
            images_missing_alt += 1

    # --- links — internal/external split ---
    internal = 0
    external = 0
    base_host = (urlparse(base_url).hostname or "").lower()
    for a in soup.find_all("a", limit=_MAX_LINKS_COUNTED):
        href = a.get("href")
        if not href:
            continue
        href = _strip_control_chars(href).strip()
        if not href or href.startswith("#") or href.startswith("javascript:"):
            continue
        try:
            absolute = urljoin(base_url, href)
        except ValueError:
            continue
        link_host = (urlparse(absolute).hostname or "").lower()
        if not link_host:
            # mailto:, tel:, etc.
            continue
        if _same_registrable(link_host, base_host):
            internal += 1
        else:
            external += 1

    # --- Open Graph tags (og:*) ---
    og_tags: dict[str, str] = {}
    for meta in soup.find_all("meta", limit=300):
        prop = meta.get("property") or ""
        if not prop.startswith("og:"):
            continue
        if len(og_tags) >= _MAX_OG_TAGS:
            break
        content = meta.get("content")
        if content is None:
            continue
        value = _strip_control_chars(content).strip()
        if value and prop not in og_tags:
            og_tags[prop] = value[:500]

    # --- JSON-LD presence ---
    json_ld_present = soup.find("script", type="application/ld+json") is not None

    return {
        "title_untrusted": title,
        "meta_description_untrusted": desc,
        "canonical_url": canonical,
        "h1_untrusted": h1,
        "h1_count": h1_count,
        "h2_count": h2_count,
        "h3_count": h3_count,
        "images_total": images_total,
        "images_missing_alt": images_missing_alt,
        "internal_link_count": internal,
        "external_link_count": external,
        "og_tags": og_tags,
        "json_ld_present": json_ld_present,
    }


def _score(parsed: dict, fetched_url: str) -> tuple[int, list[str]]:
    """Compute a 0-100 composite SEO score from the parsed fields.

    Each rule contributes 0-10 points, checked in isolation so the
    formula stays auditable. Returns (score, missing_signals) where
    missing_signals is a list of human-readable rule IDs that did NOT
    fire — surfaced in the response so agents can act on the gap.
    """
    score = 0
    missing: list[str] = []

    # 1. Title present (10)
    title = parsed.get("title_untrusted") or ""
    if title:
        score += 10
    else:
        missing.append("title_missing")

    # 2. Title length 30-60 chars (10) — Google's typical SERP truncation window
    if 30 <= len(title) <= 60:
        score += 10
    elif title:  # title exists but length off
        missing.append("title_length_off")

    # 3. Meta description present (10)
    desc = parsed.get("meta_description_untrusted") or ""
    if desc:
        score += 10
    else:
        missing.append("meta_description_missing")

    # 4. Meta description length 50-160 (10)
    if 50 <= len(desc) <= 160:
        score += 10
    elif desc:
        missing.append("meta_description_length_off")

    # 5. Exactly one H1 (10) — multiple H1s is an SEO smell
    h1_count = parsed.get("h1_count", 0)
    if h1_count == 1:
        score += 10
    elif h1_count == 0:
        missing.append("h1_missing")
    else:
        missing.append("h1_multiple")

    # 6. Canonical link (10)
    if parsed.get("canonical_url"):
        score += 10
    else:
        missing.append("canonical_missing")

    # 7. ≥3 OG tags (10) — proxy for "social-share is wired up"
    if len(parsed.get("og_tags") or {}) >= 3:
        score += 10
    else:
        missing.append("og_tags_sparse")

    # 8. JSON-LD present (10)
    if parsed.get("json_ld_present"):
        score += 10
    else:
        missing.append("json_ld_missing")

    # 9. Image alt-text coverage (proportional, 0-10)
    images_total = parsed.get("images_total", 0)
    images_missing_alt = parsed.get("images_missing_alt", 0)
    if images_total == 0:
        # No images on the page — full credit (no failure mode to ding).
        score += 10
    else:
        coverage = (images_total - images_missing_alt) / images_total
        score += round(coverage * 10)
        if images_missing_alt > 0:
            missing.append("images_missing_alt")

    # 10. HTTPS (10)
    if fetched_url.startswith("https://"):
        score += 10
    else:
        missing.append("not_https")

    # Score is 0-100 by construction, but clamp for safety against
    # future rule additions that could overshoot.
    score = max(0, min(100, score))
    return score, missing
