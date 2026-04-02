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

import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager

from config import BASE_DIR, VERSION
from db import get_and_clear_pending_key, get_sync_status, get_total_requests, init_all_dbs
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from ratelimit import check_limit
from validation import get_client_ip

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)  # suppress HTTP request logs (API keys in URLs)
logger = logging.getLogger("contrastapi")


@asynccontextmanager
async def lifespan(app):
    import asyncio

    init_all_dbs()
    logger.info("ContrastAPI started — databases initialized")

    # Periodic DB maintenance (every hour)
    async def _periodic_maintenance():
        while True:
            await asyncio.sleep(3600)
            try:
                from db import maintenance
                from ratelimit import cleanup_expired

                stats = maintenance()
                expired = cleanup_expired()
                logger.info("DB maintenance: %s, rate_limits cleaned: %d", stats, expired)
            except Exception as e:
                logger.warning("DB maintenance failed: %s", e)

    task = asyncio.create_task(_periodic_maintenance())

    yield

    # Stop maintenance task
    task.cancel()
    # Shut down thread pools
    from domain.routes import _bulk_pool, _reputation_pool

    try:
        _reputation_pool.shutdown(wait=False)
    except Exception:
        pass
    try:
        _bulk_pool.shutdown(wait=False)
    except Exception:
        pass
    # Close HTTP clients
    from cve.routes import _exploit_client
    from cve.sync import _client as sync_client
    from domain.recon import _http as recon_client
    from domain.reputation import _client as rep_client
    from domain.routes import _ripe_client
    from domain.threat import _client as threat_client
    from ioc.lookup import _client as ioc_client
    from ioc.password import _client as password_client
    from ioc.routes import _phish_client

    for c in (
        rep_client,
        threat_client,
        recon_client,
        sync_client,
        _exploit_client,
        _phish_client,
        ioc_client,
        password_client,
        _ripe_client,
    ):
        try:
            c.close()
        except Exception:
            pass
    # Close thread-local DB connections
    from db import close_thread_connections

    close_thread_connections()


app = FastAPI(
    title="ContrastAPI",
    description="Security intelligence API for AI models and developers. "
    "CVE lookup, domain intelligence, and code security verification.",
    version=VERSION,
    servers=[{"url": "https://api.contrastcyber.com"}],
    docs_url=None,
    redoc_url=None,
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


# --- In-memory metrics ---

import threading

_metrics_lock = threading.Lock()
_metrics = {
    "requests_total": 0,
    "requests_by_status": {},
    "requests_by_path": {},
    "errors_total": 0,
    "latency_sum_ms": 0,
}


_PATH_NORMALIZE = re.compile(
    r"/v1/(cve|domain|dns|whois|subdomains|certs|ssl|threat|ip|epss|exploit|scan/headers|monitor|ioc|hash|password|asn|phishing|tech)/[^/]+(?:/(changes|vulns))?"
)

_MAX_TRACKED_PATHS = 200


def _normalize_path(path: str) -> str:
    """Normalize dynamic path segments to prevent unbounded memory growth."""
    m = _PATH_NORMALIZE.match(path)
    if m:
        return f"/v1/{m.group(1)}/{{id}}"
    return path


def _record_metric(path: str, status: int, elapsed_ms: int):
    with _metrics_lock:
        _metrics["requests_total"] += 1
        _metrics["latency_sum_ms"] += elapsed_ms
        status_key = str(status)
        _metrics["requests_by_status"][status_key] = _metrics["requests_by_status"].get(status_key, 0) + 1
        if path.startswith("/v1/"):
            norm = _normalize_path(path)
            if len(_metrics["requests_by_path"]) < _MAX_TRACKED_PATHS or norm in _metrics["requests_by_path"]:
                _metrics["requests_by_path"][norm] = _metrics["requests_by_path"].get(norm, 0) + 1
        if status >= 400:
            _metrics["errors_total"] += 1


# --- Middleware: Request ID + Rate Limit Headers + Logging ---


@app.middleware("http")
async def request_middleware(request: Request, call_next):
    request_id = uuid.uuid4().hex[:16]
    request.state.request_id = request_id
    start = time.time()

    response = await call_next(request)

    # Request ID header
    response.headers["X-Request-ID"] = request_id

    # Rate limit headers (set by auth.authenticate via request.state)
    limit = getattr(request.state, "ratelimit_limit", None)
    if limit is not None:
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(getattr(request.state, "ratelimit_remaining", 0))
        response.headers["X-RateLimit-Reset"] = str(getattr(request.state, "ratelimit_reset", 0))

    # Request logging + metrics
    elapsed = int((time.time() - start) * 1000)
    safe_path = request.url.path.replace("\n", "").replace("\r", "")
    logger.info("%s %s %s %dms [%s]", request.method, safe_path, response.status_code, elapsed, request_id)
    _record_metric(request.url.path, response.status_code, elapsed)

    return response


# --- Error handler ---


@app.exception_handler(HTTPException)
async def api_error_handler(request: Request, exc: HTTPException):
    """All errors return JSON (this is an API, no HTML error pages)."""
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    """Catch-all — never leak stack traces or internal paths."""
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


# --- Landing page ---


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def landing_page(request: Request):
    total = get_total_requests()
    return templates.TemplateResponse(request, "index.html", {"total_requests": total})


@app.get("/welcome", response_class=HTMLResponse, include_in_schema=False)
def welcome_page(request: Request, order_id: str = ""):
    if not order_id:
        raise HTTPException(status_code=400, detail="Missing order_id")

    # Validate order_id is a UUID
    try:
        uuid.UUID(order_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid order_id format") from None

    # Rate limit: 5 req/min per IP
    client_ip = get_client_ip(request)
    if not check_limit("welcome", client_ip, max_requests=5, window_seconds=60):
        raise HTTPException(status_code=429, detail="Too many requests")

    api_key = get_and_clear_pending_key(order_id)
    error = None if api_key else "Key already claimed or invalid order"

    try:
        return templates.TemplateResponse(
            request,
            "welcome.html",
            {
                "api_key": api_key,
                "error": error,
            },
        )
    except Exception:
        if api_key:
            logger.error("Template render failed for order %s, returning plain text fallback", order_id)
            return PlainTextResponse(
                f"Your API key: {api_key}\n\nSave this key now. It will not be shown again.",
                media_type="text/plain",
            )
        raise


@app.get("/docs", response_class=HTMLResponse, include_in_schema=False)
def custom_docs():
    return HTMLResponse(
        content="""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>API Docs | ContrastAPI</title>
  <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
  <style>
    @font-face {
      font-family: 'Geist Mono';
      font-style: normal;
      font-weight: 100 900;
      font-display: swap;
      src: url('/static/fonts/geist-mono.woff2') format('woff2');
    }
    body { margin: 0; background: #09090b; }
    /* Top bar */
    .swagger-ui .topbar { display: none; }
    /* Custom header */
    .docs-header {
      position: sticky;
      top: 0;
      z-index: 999;
      background: #09090b;
      border-bottom: 1px solid #27272a;
      padding: 0.75rem 2rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-family: 'Geist Mono', monospace;
    }
    .docs-header .logo { color: #fafafa; font-weight: 700; font-size: 1.1rem; text-decoration: none; }
    .docs-header .logo span { color: #3b82f6; }
    .docs-nav { display: flex; gap: 1.5rem; }
    .docs-nav a { color: #a1a1aa; text-decoration: none; font-size: 0.85rem; }
    .docs-nav a:hover { color: #fafafa; }
    /* Dark theme overrides */
    .swagger-ui { background: #09090b; font-family: 'Geist Mono', -apple-system, monospace; }
    .swagger-ui .wrapper { max-width: 1100px; padding: 1rem 2rem; }
    .swagger-ui .info { margin: 1.5rem 0; }
    .swagger-ui .info .title { color: #fafafa; font-family: 'Geist Mono', monospace; }
    .swagger-ui .info .description, .swagger-ui .info p { color: #a1a1aa; }
    .swagger-ui .info a { color: #3b82f6; }
    .swagger-ui .scheme-container { background: #09090b; border-bottom: 1px solid #27272a; box-shadow: none; }
    .swagger-ui .opblock-tag { color: #fafafa; border-bottom: 1px solid #1c1c1f; font-family: 'Geist Mono', monospace; }
    .swagger-ui .opblock-tag:hover { background: rgba(39,39,42,0.4); }
    .swagger-ui .opblock-tag small { color: #71717a; }
    /* GET blocks */
    .swagger-ui .opblock.opblock-get { background: rgba(59,130,246,0.05); border-color: rgba(59,130,246,0.3); }
    .swagger-ui .opblock.opblock-get .opblock-summary-method { background: #3b82f6; }
    .swagger-ui .opblock.opblock-get .opblock-summary { border-color: rgba(59,130,246,0.3); }
    /* POST blocks */
    .swagger-ui .opblock.opblock-post { background: rgba(34,197,94,0.05); border-color: rgba(34,197,94,0.3); }
    .swagger-ui .opblock.opblock-post .opblock-summary-method { background: #22c55e; }
    .swagger-ui .opblock.opblock-post .opblock-summary { border-color: rgba(34,197,94,0.3); }
    /* Summary text */
    .swagger-ui .opblock .opblock-summary-description { color: #a1a1aa; }
    .swagger-ui .opblock .opblock-summary-path { color: #fafafa; }
    .swagger-ui .opblock .opblock-summary-path__deprecated { color: #71717a; }
    /* Expanded content */
    .swagger-ui .opblock-body { background: #0a0a0c; }
    .swagger-ui .opblock-description-wrapper p { color: #a1a1aa; }
    .swagger-ui table thead tr th { color: #a1a1aa; border-bottom: 1px solid #27272a; }
    .swagger-ui table tbody tr td { color: #fafafa; border-bottom: 1px solid #1c1c1f; }
    .swagger-ui .parameter__name { color: #fafafa; }
    .swagger-ui .parameter__type { color: #71717a; }
    .swagger-ui .parameter__in { color: #71717a; }
    /* Response */
    .swagger-ui .responses-inner h4, .swagger-ui .responses-inner h5 { color: #fafafa; }
    .swagger-ui .response-col_status { color: #22c55e; }
    .swagger-ui .response-col_description { color: #a1a1aa; }
    /* Models */
    .swagger-ui section.models { border: 1px solid #27272a; }
    .swagger-ui section.models h4 { color: #fafafa; }
    .swagger-ui .model-box { background: #0a0a0c; }
    .swagger-ui .model { color: #a1a1aa; }
    .swagger-ui .prop-type { color: #3b82f6; }
    /* Try it out */
    .swagger-ui .btn.execute { background: #3b82f6; border-color: #3b82f6; color: #fff; }
    .swagger-ui .btn.execute:hover { background: #2563eb; }
    .swagger-ui .btn { color: #a1a1aa; border-color: #27272a; }
    .swagger-ui .btn:hover { color: #fafafa; }
    .swagger-ui .btn.try-out__btn { border-color: #3b82f6; color: #3b82f6; }
    /* Code blocks */
    .swagger-ui .highlight-code, .swagger-ui .microlight { background: #0a0a0c !important; color: #fafafa; border-radius: 0.375rem; }
    .swagger-ui .copy-to-clipboard { background: #1c1c1f; }
    /* Inputs */
    .swagger-ui input[type=text], .swagger-ui textarea, .swagger-ui select {
      background: #0a0a0c; color: #fafafa; border: 1px solid #27272a; border-radius: 0.375rem;
    }
    .swagger-ui select { color: #fafafa; }
    /* Scrollbar */
    .swagger-ui ::-webkit-scrollbar { width: 6px; height: 6px; }
    .swagger-ui ::-webkit-scrollbar-track { background: #09090b; }
    .swagger-ui ::-webkit-scrollbar-thumb { background: #27272a; border-radius: 3px; }
    /* Loading */
    .swagger-ui .loading-container { background: #09090b; }
    .swagger-ui .loading-container .loading::after { color: #a1a1aa; }
    /* Auth */
    .swagger-ui .auth-wrapper { background: #09090b; }
    .swagger-ui .dialog-ux .modal-ux { background: #18181b; border: 1px solid #27272a; }
    .swagger-ui .dialog-ux .modal-ux-header h3 { color: #fafafa; }
    .swagger-ui .dialog-ux .modal-ux-content p { color: #a1a1aa; }
  </style>
</head>
<body>
  <div class="docs-header">
    <a href="/" class="logo">Contrast<span>API</span></a>
    <div class="docs-nav">
      <a href="/docs">Docs</a>
      <a href="https://contrastcyber.com">Scan</a>
      <a href="https://contrastcyber.com/pricing">Pricing</a>
    </div>
  </div>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: '/openapi.json',
      dom_id: '#swagger-ui',
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: 'BaseLayout',
      deepLinking: true,
      defaultModelsExpandDepth: -1,
      docExpansion: 'list',
      filter: true,
      syntaxHighlight: { theme: 'monokai' }
    });
  </script>
  <footer style="background:#09090b;border-top:1px solid #27272a;padding:1.5rem;text-align:center;font-family:'Geist Mono',monospace;font-size:0.8rem">
    <div style="display:flex;justify-content:center;gap:1.5rem;flex-wrap:wrap;margin-bottom:0.75rem">
      <a href="https://contrastcyber.com/terms" style="color:#a1a1aa;text-decoration:none">Terms</a>
      <a href="https://contrastcyber.com/privacy" style="color:#a1a1aa;text-decoration:none">Privacy</a>
      <a href="mailto:contact@contrastcyber.com" style="color:#a1a1aa;text-decoration:none">Contact</a>
      <a href="https://github.com/UPinar/contrastapi" style="color:#a1a1aa;text-decoration:none">GitHub</a>
    </div>
    <p style="color:#71717a;margin:0">&copy; 2026 ContrastCyber</p>
  </footer>
</body>
</html>"""
    )


# --- Meta endpoints ---


@app.get("/v1/status", operation_id="api_status", tags=["Meta"])
def api_status():
    """API health check and data freshness."""
    sync = get_sync_status()
    return {
        "status": "ok",
        "version": VERSION,
        "total_requests": get_total_requests(),
        "data_sources": {
            source: {
                "last_sync": info.get("last_sync"),
                "records": info.get("records_count"),
                "status": info.get("status"),
            }
            for source, info in sync.items()
        },
    }


@app.get("/metrics", response_class=PlainTextResponse, include_in_schema=False)
def metrics(request: Request):
    """Prometheus-style metrics endpoint (localhost only)."""
    client_ip = request.client.host if request.client else "unknown"
    allowed = {"127.0.0.1", "::1"}
    if os.getenv("TESTING"):
        allowed.add("testclient")
    if client_ip not in allowed:
        raise HTTPException(status_code=403, detail="Metrics only available from localhost")
    with _metrics_lock:
        m = {k: v if not isinstance(v, dict) else dict(v) for k, v in _metrics.items()}

    lines = [
        "# HELP contrastapi_requests_total Total HTTP requests",
        "# TYPE contrastapi_requests_total counter",
        f"contrastapi_requests_total {m['requests_total']}",
        "# HELP contrastapi_errors_total Total HTTP errors (4xx+5xx)",
        "# TYPE contrastapi_errors_total counter",
        f"contrastapi_errors_total {m['errors_total']}",
        "# HELP contrastapi_latency_sum_ms Total response time in ms",
        "# TYPE contrastapi_latency_sum_ms counter",
        f"contrastapi_latency_sum_ms {m['latency_sum_ms']}",
    ]

    avg = round(m["latency_sum_ms"] / m["requests_total"]) if m["requests_total"] > 0 else 0
    lines.append("# HELP contrastapi_latency_avg_ms Average response time in ms")
    lines.append("# TYPE contrastapi_latency_avg_ms gauge")
    lines.append(f"contrastapi_latency_avg_ms {avg}")

    lines.append("# HELP contrastapi_requests_by_status HTTP requests by status code")
    lines.append("# TYPE contrastapi_requests_by_status counter")
    for status, count in sorted(m["requests_by_status"].items()):
        lines.append(f'contrastapi_requests_by_status{{status="{status}"}} {count}')

    lines.append("# HELP contrastapi_requests_by_path HTTP requests by path")
    lines.append("# TYPE contrastapi_requests_by_path counter")
    top_paths = sorted(m["requests_by_path"].items(), key=lambda x: -x[1])[:20]
    for path, count in top_paths:
        safe_path = path.replace("\\", "").replace('"', "").replace("\n", "")
        lines.append(f'contrastapi_requests_by_path{{path="{safe_path}"}} {count}')

    return "\n".join(lines) + "\n"


@app.get("/v1/usage", operation_id="api_usage", tags=["Meta"])
def api_usage(request: Request):
    """Usage statistics for API key holders."""
    from auth import authenticate, extract_key
    from config import PRO_HOURLY_LIMIT
    from db import get_key_usage_stats

    raw_key = extract_key(request)
    if not raw_key:
        raise HTTPException(status_code=401, detail="API key required. Pass Authorization: Bearer cc_xxx")

    # Authenticate (validates key + rate limit)
    auth_ctx = authenticate(request, "/v1/usage")
    kh = auth_ctx["key_hash"]

    stats = get_key_usage_stats(kh)
    stats["hourly_limit"] = PRO_HOURLY_LIMIT
    stats["hourly_remaining"] = max(0, PRO_HOURLY_LIMIT - stats["last_1h"])
    return stats


@app.get("/llms.txt", response_class=PlainTextResponse, include_in_schema=False)
def llms_txt():
    """LLM discovery file — concise version for quick context."""
    return """\
# ContrastAPI

> Security intelligence API for AI models and developers. Free to use, no API key required.

- [API Documentation](https://api.contrastcyber.com/docs)
- [OpenAPI Spec](https://api.contrastcyber.com/openapi.json)
- [Full API Reference](https://api.contrastcyber.com/llms-full.txt)


## When to Use This API

Use ContrastAPI when you need to:
- Look up CVE details, severity, CVSS breakdown, EPSS exploit probability, or CISA KEV status
- Investigate a domain's DNS, WHOIS, SSL certificate, subdomains, email security (SPF/DMARC/DKIM)
- Get a domain security risk score (A-F grade, 100-point scale)
- Detect WAF/CDN protection on a target domain
- Check a domain for malware/threat intelligence (URLhaus)
- Scan a live domain's HTTP security headers
- Scan code for hardcoded secrets, SQL/command injection, or missing security headers
- Check software dependencies against the CVE database
- Enrich an IP address with open ports, vulnerabilities, and hostnames (Shodan InternetDB)

## Authentication

No API key needed. Free: 100 requests/hour per IP.
API key (1000 req/hr): pass `Authorization: Bearer cc_xxx` header.
Rate limit headers returned: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset.

## Endpoints (20 tools)

### CVE Intelligence
- GET /v1/cve/{cve_id} — Full CVE details with EPSS score, KEV status, CVSS breakdown
- GET /v1/cves?product=&severity=&days= — Search CVEs by product, severity, date
- GET /v1/cves/recent?hours=24 — Recently published CVEs
- GET /v1/cves/kev — CISA Known Exploited Vulnerabilities
- GET /v1/epss/{cve_id} — EPSS exploit probability score

### Domain Intelligence
- GET /v1/domain/{domain} — Full domain report (DNS + WHOIS + SSL + subdomains + WAF + email security + threat intel + risk score)
- GET /v1/dns/{domain} — DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
- GET /v1/whois/{domain} — WHOIS registration data
- GET /v1/subdomains/{domain} — Subdomain enumeration (DNS brute + CT logs)
- GET /v1/certs/{domain} — Certificate Transparency log entries
- GET /v1/ip/{ip} — IP intelligence (reverse DNS, open ports, vulns, hostnames via Shodan)
- GET /v1/threat/{domain} — Threat intelligence (URLhaus malware URL lookup)
- GET /v1/tech/{domain} — Technology fingerprinting (CMS, frameworks, servers, CDN, analytics)
- GET /v1/scan/headers/{domain} — Live HTTP security header scan and analysis

### Code Security
- POST /v1/check/headers — Validate HTTP security headers (JSON body: {"headers": {...}})
- POST /v1/check/secrets — Detect hardcoded secrets (JSON body: {"code": "...", "language": "python"})
- POST /v1/check/injection — SQL/command/path injection detection (JSON body: {"code": "...", "language": "python"})
- POST /v1/check/dependencies — Check packages against CVE DB (JSON body: {"packages": [{"name": "...", "version": "..."}]})

### Meta
- GET /v1/status — API health check and data freshness
- GET /v1/usage — Usage statistics (Pro key required)

## Quick Examples

### CVE Lookup
GET https://api.contrastcyber.com/v1/cve/CVE-2024-3094
→ Returns severity, CVSS, CVSS breakdown, description, EPSS score, KEV status, affected products

### Domain Report with Risk Score
GET https://api.contrastcyber.com/v1/domain/example.com
→ Returns DNS, WHOIS, SSL (graded A-F), subdomains, WAF, email security, threat intel, risk score (A-F)

### Threat Intelligence
GET https://api.contrastcyber.com/v1/threat/example.com
→ Returns URLhaus malware URLs, threat types, online/offline status

### Live Header Scan
GET https://api.contrastcyber.com/v1/scan/headers/example.com
→ Fetches live headers, analyzes CSP/HSTS/X-Frame-Options, returns score and grade

### IP Intelligence
GET https://api.contrastcyber.com/v1/ip/93.184.216.34
→ Returns reverse DNS, open ports, known vulnerabilities, hostnames

### Technology Fingerprinting
GET https://api.contrastcyber.com/v1/tech/example.com
→ Returns detected technologies (CMS, frameworks, servers, CDN, analytics) with versions

### Secret Detection
POST https://api.contrastcyber.com/v1/check/secrets
Body: {"code": "aws_key = 'AKIAIOSFODNN7EXAMPLE'", "language": "python"}
→ Returns findings with severity, line number, remediation advice
"""


@app.get("/llms-full.txt", response_class=PlainTextResponse, include_in_schema=False)
def llms_full_txt():
    """Full API reference for LLM context — detailed parameter and response docs."""
    return """\
# ContrastAPI — Full API Reference

> Security intelligence API for AI models and developers.
> Base URL: https://api.contrastcyber.com
> Auth: None required (100 req/hr). Pro key: Authorization: Bearer cc_xxx (1000 req/hr).
> All responses are JSON. All endpoints include a "summary" field optimized for LLM consumption.

---

## CVE Intelligence

### GET /v1/cve/{cve_id}
Look up a single CVE by ID. Returns full details with EPSS score and KEV status.

**Parameters:**
- cve_id (path, required): CVE ID in format CVE-YYYY-NNNNN (e.g., CVE-2024-3094)

**Response:**
{
  "cve_id": "CVE-2024-3094",
  "summary": "CRITICAL (CWE-506) — Malicious code in xz/liblzma. CVSS 10.0. Actively exploited (CISA KEV). EPSS 93% exploitation probability.",
  "description": "...",
  "severity": "CRITICAL",
  "cvss_v3": 10.0,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "cwe_id": "CWE-506",
  "epss": {"score": 0.93, "percentile": 0.99},
  "kev": {"in_kev": true, "date_added": "2024-03-29"},
  "affected_products": ["xz-utils"],
  "published": "2024-03-29T00:00:00",
  "modified": "2024-04-01T00:00:00",
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"]
}

**Errors:** 400 (invalid CVE format), 404 (CVE not found)

---

### GET /v1/cves
Search CVEs by product, severity, and/or date range.

**Parameters:**
- product (query, optional): Filter by product name, min 2 chars (e.g., "nginx", "apache")
- severity (query, optional): CRITICAL, HIGH, MEDIUM, or LOW
- days (query, optional): CVEs published within N days (1-365)
- limit (query, optional): Max results, default 50 (1-200)

**Example:** GET /v1/cves?product=nginx&severity=HIGH&days=90&limit=10

**Response:**
{
  "count": 3,
  "summary": "3 CVEs found (nginx, HIGH, last 90d)",
  "results": [...]
}

---

### GET /v1/cves/recent
Get recently published CVEs.

**Parameters:**
- hours (query, optional): CVEs from last N hours, default 24 (1-168)
- limit (query, optional): Max results, default 50 (1-200)

**Response:**
{
  "count": 15,
  "hours": 24,
  "summary": "15 CVEs published in the last 24 hours",
  "results": [...]
}

---

### GET /v1/cves/kev
CISA Known Exploited Vulnerabilities — actively exploited CVEs.

**Parameters:**
- limit (query, optional): Max results, default 100 (1-500)

**Response:**
{
  "count": 50,
  "summary": "50 actively exploited CVEs (CISA KEV)",
  "results": [...]
}

---

### GET /v1/epss/{cve_id}
EPSS (Exploit Prediction Scoring System) score for a CVE.

**Parameters:**
- cve_id (path, required): CVE ID (e.g., CVE-2024-3094)

**Response:**
{
  "cve_id": "CVE-2024-3094",
  "epss_score": 0.93,
  "epss_percentile": 0.99
}

---

## Domain Intelligence

### GET /v1/domain/{domain}
Full domain intelligence report — runs all checks in parallel.

**Parameters:**
- domain (path, required): Domain name (e.g., example.com)

**Response:**
{
  "domain": "example.com",
  "summary": "example.com resolves to 93.184.216.34. Security grade B (72/100). SSL grade A by DigiCert. No WAF detected. Email security: B. 3 subdomains found.",
  "dns": {"a": ["93.184.216.34"], "mx": [...], "ns": [...], "txt": [...]},
  "reverse_dns": {"ip": "93.184.216.34", "ptr": "..."},
  "whois": {"registrar": "...", "creation_date": "1995-08-14", "expiry_date": "2025-08-13"},
  "ssl": {"common_name": "...", "issuer": "DigiCert", "not_after": "...", "san": [...], "grade": "A", "tls_version": "TLSv1.3", "days_remaining": 120},
  "email_security": {"spf": "v=spf1 ...", "dmarc": "v=DMARC1 ...", "dkim_selectors": ["default"], "grade": "A"},
  "subdomains": {"subdomains": ["www.example.com", "mail.example.com"], "count": 2},
  "certificates": {"total_certificates": 15, "certificates": [...]},
  "waf": {"detected": [], "waf_present": false},
  "threat": {"urlhaus_status": "clean", "urls_online": 0, "url_count": 0},
  "risk": {"score": 72, "max_score": 100, "grade": "B", "factors": [...]}
}

---

### GET /v1/dns/{domain}
DNS records only (A, AAAA, MX, NS, TXT, CNAME, SOA).

**Parameters:**
- domain (path, required): Domain name

**Response:**
{
  "domain": "example.com",
  "records": {"a": ["93.184.216.34"], "mx": [{"priority": 10, "host": "mail.example.com"}], ...}
}

---

### GET /v1/whois/{domain}
WHOIS registration data.

**Parameters:**
- domain (path, required): Domain name

**Response:**
{
  "domain": "example.com",
  "whois": {"registrar": "...", "creation_date": "...", "expiry_date": "...", "name_servers": [...]}
}

---

### GET /v1/subdomains/{domain}
Subdomain enumeration via DNS brute force + Certificate Transparency logs.

**Parameters:**
- domain (path, required): Domain name

**Response:**
{
  "domain": "example.com",
  "subdomains": ["www.example.com", "mail.example.com", "api.example.com"],
  "count": 3
}

---

### GET /v1/certs/{domain}
Certificate Transparency log entries from crt.sh.

**Parameters:**
- domain (path, required): Domain name

**Response:**
{
  "domain": "example.com",
  "total_certificates": 42,
  "certificates": [{"issuer": "...", "not_before": "...", "not_after": "...", "common_name": "..."}]
}

---

### GET /v1/ip/{ip}
IP intelligence — reverse DNS, open ports, vulnerabilities, hostnames via Shodan InternetDB.

**Parameters:**
- ip (path, required): IPv4 or IPv6 address (no private/reserved IPs)

**Response:**
{
  "ip": "93.184.216.34",
  "ptr": "example.com",
  "ports": [80, 443, 8080],
  "hostnames": ["example.com"],
  "vulns": ["CVE-2024-1234"],
  "cpes": ["cpe:/a:apache:httpd:2.4.51"],
  "tags": ["http", "https"],
  "summary": "93.184.216.34 → example.com. 3 open ports. 1 known vulnerability."
}

---

### GET /v1/threat/{domain}
Threat intelligence — check domain against URLhaus for known malware URLs.

**Parameters:**
- domain (path, required): Domain name

**Response:**
{
  "domain": "example.com",
  "urlhaus_status": "clean",
  "urls_online": 0,
  "url_count": 0,
  "threat_types": [],
  "tags": [],
  "urls": [],
  "summary": "example.com — no threats found in URLhaus"
}

---

### GET /v1/scan/headers/{domain}
Fetch a live domain's HTTP headers and analyze security posture.

**Parameters:**
- domain (path, required): Domain name

**Response:**
{
  "domain": "example.com",
  "status_code": 200,
  "url": "https://example.com/",
  "score": 65,
  "grade": "C",
  "findings": [{"header": "Content-Security-Policy", "present": false, "severity": "high", ...}],
  "headers_present": ["Strict-Transport-Security", "X-Content-Type-Options"],
  "headers_missing": ["Content-Security-Policy", "Permissions-Policy"]
}

---

## Code Security

### POST /v1/check/secrets
Detect hardcoded secrets in source code (14 patterns: AWS keys, GitHub tokens, JWTs, etc.).

**Request Body:**
{
  "code": "api_key = 'AKIAIOSFODNN7EXAMPLE'",
  "language": "python"
}

**Response:**
{
  "findings": [
    {
      "type": "aws_access_key",
      "severity": "critical",
      "line": 1,
      "match": "AKIAIOSFODNN7EXAMPLE",
      "description": "AWS Access Key ID detected",
      "remediation": "Use environment variables or AWS IAM roles"
    }
  ],
  "summary": "Found 1 hardcoded secret (1 critical)",
  "total": 1,
  "by_severity": {"critical": 1}
}

---

### POST /v1/check/injection
Detect SQL injection, command injection, and path traversal patterns.

**Request Body:**
{
  "code": "query = f'SELECT * FROM users WHERE id = {user_id}'",
  "language": "python"
}

**Response:**
{
  "findings": [{"type": "sql_injection", "severity": "high", "line": 1, ...}],
  "summary": "Found 1 injection pattern (1 high)",
  "total": 1,
  "by_severity": {"high": 1}
}

---

### POST /v1/check/headers
Validate HTTP security headers against best practices.

**Request Body:**
{
  "headers": {
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=()"
  }
}

**Response:**
{
  "findings": [],
  "summary": "All 6 security headers present — score 100/100 (grade A)",
  "score": 100,
  "grade": "A",
  "headers_present": 6,
  "headers_missing": 0
}

---

### POST /v1/check/dependencies
Check software packages against the CVE database.

**Request Body:**
{
  "packages": [
    {"name": "lodash", "version": "4.17.15"},
    {"name": "express", "version": "4.17.1"}
  ]
}

**Response:**
{
  "findings": [{"package": "lodash", "version": "4.17.15", "cve_id": "CVE-2020-28500", ...}],
  "summary": "Found 1 CVE across 1 of 2 packages (1 high)",
  "total_cves": 1,
  "packages_affected": 1,
  "packages_clean": 1
}

---

## Error Responses

All errors return JSON:
{"error": "description of the error"}

Common status codes:
- 400: Invalid input (bad CVE format, invalid domain, missing fields)
- 401: Invalid API key
- 404: Resource not found (CVE not in database, no EPSS data)
- 429: Rate limit exceeded

---

## Rate Limits

- Keyless: 100 requests/hour per IP address (sliding window)
- Pro key: 1000 requests/hour per key (sliding window)
- Every response includes: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset headers
- Every response includes: X-Request-ID header for request tracing

### GET /v1/usage
Usage statistics for Pro key holders. Requires `Authorization: Bearer cc_xxx`.

**Response:**
{
  "total_requests": 1523,
  "last_24h": 89,
  "last_1h": 12,
  "hourly_limit": 1000,
  "hourly_remaining": 988,
  "top_endpoints": [{"endpoint": "/v1/cve/CVE-2024-3094", "count": 45}, ...]
}

---

## Data Sources

- NVD: 340,000+ CVEs (synced every 2 hours)
- EPSS: 323,000+ exploit probability scores (synced every 2 hours)
- CISA KEV: 1,500+ actively exploited vulnerabilities (synced every 2 hours)
- Shodan InternetDB: IP enrichment (ports, vulns, hostnames — free, no key)
- URLhaus (abuse.ch): Malware URL database (free, live queries)
- crt.sh: Certificate Transparency logs (live queries)
- DNS/WHOIS/SSL: Live queries per request
"""


# Module routers
from cve.routes import router as cve_router
from domain.routes import router as domain_router

app.include_router(domain_router)
app.include_router(cve_router)

from codesec.routes import router as codesec_router

app.include_router(codesec_router)

from ioc.routes import router as ioc_router

app.include_router(ioc_router)

from webhooks import router as webhooks_router

app.include_router(webhooks_router)

# --- AI Discovery endpoints ---


@app.get("/.well-known/ai-plugin.json", include_in_schema=False)
def ai_plugin():
    """ChatGPT/AI plugin discovery manifest."""
    return {
        "schema_version": "v1",
        "name_for_human": "ContrastAPI — Security Intelligence",
        "name_for_model": "contrastapi",
        "description_for_human": "CVE lookup, domain intelligence, and code security checks.",
        "description_for_model": (
            "Use ContrastAPI when the user asks about CVE vulnerabilities, EPSS exploit "
            "probability, CISA KEV status, domain security (DNS, WHOIS, SSL, subdomains, "
            "WAF detection), or code security (hardcoded secrets, SQL/command injection, "
            "HTTP security headers). No API key needed for basic use (100 req/hr)."
        ),
        "auth": {"type": "none"},
        "api": {
            "type": "openapi",
            "url": "https://api.contrastcyber.com/openapi.json",
        },
        "logo_url": "https://api.contrastcyber.com/static/logo.png",
        "contact_email": "info@contrastcyber.com",
        "legal_info_url": "https://contrastcyber.com",
    }


@app.get("/robots.txt", response_class=PlainTextResponse, include_in_schema=False)
def robots_txt():
    """Allow AI crawlers and point to llms.txt."""
    return (
        "User-agent: *\n"
        "Allow: /\n"
        "\n"
        "User-agent: GPTBot\n"
        "Allow: /\n"
        "\n"
        "User-agent: ClaudeBot\n"
        "Allow: /\n"
        "\n"
        "User-agent: Google-Extended\n"
        "Allow: /\n"
        "\n"
        "Sitemap: https://api.contrastcyber.com/sitemap.xml\n"
    )


@app.get("/sitemap.xml", include_in_schema=False)
def sitemap_xml():
    from datetime import UTC, datetime

    today = datetime.now(UTC).strftime("%Y-%m-%d")
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://api.contrastcyber.com/</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>1.0</priority></url>
  <url><loc>https://api.contrastcyber.com/docs</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>
  <url><loc>https://api.contrastcyber.com/llms.txt</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>0.7</priority></url>
  <url><loc>https://api.contrastcyber.com/llms-full.txt</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>0.7</priority></url>
</urlset>"""
    return Response(content=xml, media_type="application/xml")
