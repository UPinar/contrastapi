"""
api.contrastcyber.com — Security Intelligence API

Three modules:
  /v1/cve/*     — CVE Intelligence (NVD + EPSS + KEV)
  /v1/domain/*  — Domain Intelligence (DNS, WHOIS, SSL, subdomains)
  /v1/check/*   — Code Security Verification (secrets, injection, headers)

Modules:
  config.py      — constants, paths, limits
  db.py          — SQLite operations (3 databases)
  auth.py        — IP-based and API key authentication
  ratelimit.py   — in-memory sliding window rate limiting
  validation.py  — input sanitization, IP detection
"""

import base64
import hashlib
import logging
import re
from pathlib import Path

from config import (
    BASE_DIR,
    UPGRADE_URL,
    VERSION,
)
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)  # suppress HTTP request logs (API keys in URLs)
logger = logging.getLogger("contrastapi")


from core import mcp_proxy
from core.lifespan import make_lifespan

app = FastAPI(
    title="ContrastAPI",
    description="Security intelligence API for AI models and developers. "
    "CVE lookup, domain intelligence, and code security verification.",
    version=VERSION,
    servers=[{"url": "https://api.contrastcyber.com"}],
    docs_url=None,
    redoc_url=None,
    openapi_url="/openapi.json",
    lifespan=make_lifespan(lambda: mcp_proxy.session_mgr),
)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

# CORS — narrowly scoped to the billing endpoints called from the marketing
# site (contrastcyber.com). The rest of the API is consumed by server-side
# clients (curl, SDKs, MCP clients) that do not send an Origin header.
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://contrastcyber.com"],
    allow_origin_regex=r"^https://([a-z0-9-]+\.)?contrastcyber\.com$",
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Content-Type"],
    max_age=600,
)


from core.metrics import _sanitize_path
from core.metrics import record_metric as _record_metric

# --- Security headers (set on every response; replaces nginx snippet) ---


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


_TEMPLATES_DIR = Path(__file__).parent / "templates"
_JSONLD_HASHES = " ".join(
    h
    for h in (
        _compute_jsonld_hash(_TEMPLATES_DIR / "index.html"),
        _compute_jsonld_hash(_TEMPLATES_DIR / "index_cn.html"),
    )
    if h
)

_CSP_POLICY = (
    "default-src 'self'; "
    "style-src 'self' https://cdn.jsdelivr.net; "
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

_SECURITY_HEADERS = {
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


# Middleware stack — registered via add_middleware (LIFO: last added = outermost).
# Final outer→inner order: RequestContextMiddleware → SecurityHeadersMiddleware → CORS → routes.
# CORS already registered at line 190 (innermost wrapping).
from middleware import (
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
    _extract_key_from_scope,
)

app.add_middleware(SecurityHeadersMiddleware, headers=_SECURITY_HEADERS)
app.add_middleware(
    RequestContextMiddleware,
    upgrade_url=UPGRADE_URL,
    sanitize_path=_sanitize_path,
    extract_key_fn=_extract_key_from_scope,
    record_metric=_record_metric,
    logger=logger,
)


from core.exception_handlers import register_exception_handlers

register_exception_handlers(app)


# --- Inline routes split into app/api/* (Faz 6 Batch 7) ---
from api.diagnostics import router as diagnostics_router
from api.discovery import router as discovery_router
from api.landing import router as landing_router
from api.main import api_router
from crypto_billing import router as crypto_billing_router
from webhooks import router as webhooks_router

# Order matters for OpenAPI tag insertion + 404 hint matching.
app.include_router(api_router)
app.include_router(landing_router)
app.include_router(diagnostics_router)
app.include_router(discovery_router)
app.include_router(webhooks_router)
app.include_router(crypto_billing_router)

# --- MCP Streamable HTTP endpoint ---
mcp_proxy.init_mcp(app)
