"""Tests for /pricing, /terms, /privacy HTML pages on api.contrastcyber.com.

These pages were split off from contrastcyber.com (where they bundled both
products) to give ContrastAPI its own legal surface and a self-hosted pricing
page. Verifies: routes serve HTML 200, sentinel content is present, footer
links are relative (so they resolve to api.contrastcyber.com), and the
crypto-checkout JS is wired into the pricing page.
"""

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def _get_html(path: str):
    r = client.get(path)
    assert r.status_code == 200, f"{path} returned {r.status_code}"
    assert "text/html" in r.headers["content-type"]
    return r.text


def test_pricing_page_renders_with_tiers_and_crypto_checkout():
    body = _get_html("/pricing")
    # Title + canonical
    assert "<title>Pricing | ContrastAPI</title>" in body
    assert 'rel="canonical" href="https://api.contrastcyber.com/pricing"' in body
    # Both tiers + key prices
    assert ">Free<" in body
    assert ">Pro<" in body
    assert "$0" in body
    assert "$15" in body
    # CTA: Lemon Squeezy + crypto button
    assert "lemonsqueezy.com/checkout/buy/" in body
    assert 'id="crypto-checkout-btn"' in body
    assert "/static/js/crypto-checkout.js" in body
    # MCP positioning
    assert "49 MCP tools" in body or "49 MCP" in body
    # Pricing page must NOT advertise the scanner — it's a separate property
    assert "https://contrastcyber.com/pricing" not in body
    assert 'https://contrastcyber.com"' not in body
    assert "shared across both services" not in body


def test_terms_page_renders_api_only_content():
    body = _get_html("/terms")
    assert "<title>Terms of Service | ContrastAPI</title>" in body
    assert 'rel="canonical" href="https://api.contrastcyber.com/terms"' in body
    assert "Last updated: May 4, 2026" in body
    # ContrastAPI-only framing — the scanner-section bullet from the old
    # combined page (a `<li><strong>ContrastScan</strong>` describing the
    # scanner as a co-equal service) must not appear here. A passing mention
    # of ContrastScan in the joint-quota disclosure is allowed.
    assert "ContrastAPI" in body
    assert "<strong>ContrastScan</strong>" not in body
    # Pro plan + processors
    assert "Lemon Squeezy" in body
    assert "NOWPayments" in body
    # Per-target throttle is API-specific
    assert "eTLD+1" in body


def test_privacy_page_renders_api_only_content():
    body = _get_html("/privacy")
    assert "<title>Privacy Policy | ContrastAPI</title>" in body
    assert 'rel="canonical" href="https://api.contrastcyber.com/privacy"' in body
    # Transparency endpoint must be advertised — it's the USP of the API
    assert "/v1/privacy/my-data" in body
    # Both payment processors disclosed
    assert "Lemon Squeezy" in body
    assert "NOWPayments" in body
    # GDPR + KVKK sections
    assert "GDPR" in body
    assert "KVKK" in body


def test_legal_pages_footer_links_are_relative():
    """All three new pages must footer-link to the SAME-domain /terms and
    /privacy, so the footer doesn't bounce users to contrastcyber.com.
    """
    for path in ("/pricing", "/terms", "/privacy"):
        body = _get_html(path)
        assert '<a href="/terms">Terms</a>' in body, f"{path}: footer Terms link not relative"
        assert '<a href="/privacy">Privacy</a>' in body, f"{path}: footer Privacy link not relative"
        # Negative: there must be no hardcoded contrastcyber.com/{terms,privacy} anywhere
        # (the canonical/og:url metadata uses api.contrastcyber.com, which is fine)
        assert "https://contrastcyber.com/terms" not in body, f"{path}: leftover hardcoded terms link"
        # privacy.html intentionally cross-links to scanner privacy in its intro;
        # tolerate that ONE reference in /privacy but reject it elsewhere.
        if path != "/privacy":
            assert "https://contrastcyber.com/privacy" not in body, f"{path}: leftover hardcoded privacy link"


def test_nav_pricing_link_is_relative():
    """/pricing in nav.html must be same-domain (no cross-domain hop)."""
    body = _get_html("/pricing")
    assert '<a href="/pricing">Pricing</a>' in body
    assert 'href="https://contrastcyber.com/pricing"' not in body
