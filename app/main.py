"""api.contrastcyber.com — Security Intelligence API

Thin shell after Faz 6 split. Behavior lives in:

  app/api/      — route packages (cve, domain, codesec, ioc, atlas, d3fend) +
                  per-surface routers (landing, meta, diagnostics, discovery)
                  aggregated under /v1 in api/main.py
  app/core/     — cross-cutting wiring: lifespan, exception handlers, MCP
                  proxy, metrics, templates, security headers, telegram notify
  app/middleware.py — security headers + request context (pure ASGI)
"""

import logging

from api.diagnostics import router as diagnostics_router
from api.discovery import router as discovery_router
from api.landing import router as landing_router
from api.main import api_router
from config import BASE_DIR, UPGRADE_URL, VERSION
from core import mcp_proxy
from core.exception_handlers import register_exception_handlers
from core.lifespan import make_lifespan
from core.metrics import _sanitize_path
from core.metrics import record_metric as _record_metric
from core.security_headers import SECURITY_HEADERS
from crypto_billing import router as crypto_billing_router
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from middleware import (
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
    _extract_key_from_scope,
)
from webhooks import router as webhooks_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)  # suppress HTTP request logs (API keys in URLs)
logger = logging.getLogger("contrastapi")


app = FastAPI(
    title="ContrastAPI",
    description="Security intelligence API for AI models and developers. "
    "CVE lookup, domain intelligence, and code security verification.",
    version=VERSION,
    servers=[{"url": "https://api.contrastcyber.com"}],
    docs_url=None,
    redoc_url=None,
    openapi_url="/openapi.json",
    lifespan=make_lifespan(mcp_proxy.mcp_session_mgr),
)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

# Middleware stack — registered via add_middleware (LIFO: last added = outermost).
# Final outer→inner order: RequestContextMiddleware → SecurityHeadersMiddleware → CORS → routes.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://contrastcyber.com"],
    allow_origin_regex=r"^https://([a-z0-9-]+\.)?contrastcyber\.com$",
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Content-Type"],
    max_age=600,
)
app.add_middleware(SecurityHeadersMiddleware, headers=SECURITY_HEADERS)
app.add_middleware(
    RequestContextMiddleware,
    upgrade_url=UPGRADE_URL,
    sanitize_path=_sanitize_path,
    extract_key_fn=_extract_key_from_scope,
    record_metric=_record_metric,
    logger=logger,
)

register_exception_handlers(app)

# Order matters for OpenAPI tag insertion + 404 hint matching.
app.include_router(api_router)
app.include_router(landing_router)
app.include_router(diagnostics_router)
app.include_router(discovery_router)
app.include_router(webhooks_router)
app.include_router(crypto_billing_router)

# MCP Streamable HTTP endpoint — must mount AFTER all FastAPI routes are registered.
mcp_proxy.init_mcp(app)
