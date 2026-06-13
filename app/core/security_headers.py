"""Security headers + CSP policy. JSON-LD hash computation uses the rendered
templates so the CSP `script-src` token matches the actual blob FastAPI ships.

Exports `SECURITY_HEADERS` consumed by SecurityHeadersMiddleware in main.py.
"""

import base64
import hashlib
import re
from pathlib import Path


def _compute_jsonld_hash(template_path: Path) -> str:
    """Return 'sha256-BASE64' CSP token for the first JSON-LD block in the file, or '' if none."""
    try:
        content = template_path.read_text(encoding="utf-8")
    except OSError:
        return ""
    m = re.search(
        r'<script type="application/ld\+json">(.*?)</script>',
        content,
        re.DOTALL,
    )
    if not m:
        return ""
    digest = hashlib.sha256(m.group(1).encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def _compute_style_hash(template_path: Path) -> str:
    """Return 'sha256-BASE64' CSP token for the first inline <style> block (anti-FOUC), or ''.

    The block holds the body hidden until CSS loads, so it must be inline (it has
    to apply before the stylesheet). Auto-hashing keeps style-src strict (no
    'unsafe-inline') and never goes stale when the block is edited.
    """
    try:
        content = template_path.read_text(encoding="utf-8")
    except OSError:
        return ""
    m = re.search(r"<style>(.*?)</style>", content, re.DOTALL)
    if not m:
        return ""
    digest = hashlib.sha256(m.group(1).encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
_JSONLD_HASHES = " ".join(
    h
    for h in (
        _compute_jsonld_hash(_TEMPLATES_DIR / "index.html"),
        _compute_jsonld_hash(_TEMPLATES_DIR / "index_cn.html"),
    )
    if h
)
_STYLE_HASHES = " ".join(
    dict.fromkeys(  # index + index_cn share the same anti-FOUC block — dedupe
        h
        for h in (
            _compute_style_hash(_TEMPLATES_DIR / "index.html"),
            _compute_style_hash(_TEMPLATES_DIR / "index_cn.html"),
        )
        if h
    )
)

_CSP_POLICY = (
    "default-src 'self'; "
    f"style-src 'self' {_STYLE_HASHES} https://cdn.jsdelivr.net; "
    f"script-src 'self' {_JSONLD_HASHES} https://cdn.jsdelivr.net https://static.cloudflareinsights.com; "
    "img-src 'self' https://fastapi.tiangolo.com; "
    "connect-src 'self' https://cloudflareinsights.com; "
    "font-src 'self'; "
    "object-src 'none'; "
    "frame-src 'none'; "
    "child-src 'none'; "
    "worker-src 'self'; "
    "manifest-src 'self'; "
    "media-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none';"
)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Cross-Origin-Embedder-Policy": "credentialless",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": _CSP_POLICY,
}
