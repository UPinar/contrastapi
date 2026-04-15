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
from db import (
    get_and_clear_pending_key,
    get_key_by_order_id,
    get_sync_status,
    get_total_requests,
    has_pending_key,
    init_all_dbs,
)
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from ratelimit import check_limit
from starlette.exceptions import HTTPException as StarletteHTTPException
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

    # MCP session manager needs a running task group (skip if mcp not installed)
    if _mcp_session_mgr is not None:
        async with _mcp_session_mgr.run():
            logger.info("MCP Streamable HTTP endpoint ready at /mcp")
            yield
    else:
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
    r"/v1/(cve|domain|dns|whois|subdomains|certs|ssl|threat|ip|epss|exploit|scan/headers|monitor|ioc|hash|password|asn|phishing|tech|email/mx|email/disposable|phone)/[^/]+(?:/(changes|vulns))?"
)

_MAX_TRACKED_PATHS = 200

_LOG_SANITIZE = re.compile(
    r"/v1/(phone|email/mx|email/disposable|ip|domain|dns|whois|subdomains|certs|ssl|threat|tech|monitor|ioc|phishing|scan/headers|asn|password|archive|username|cve|cves|exploit|hash|epss)/[^/?]+"
)


def _sanitize_path(path: str) -> str:
    """Redact PII (domains, IPs, emails, phones) from request paths for safe logging."""
    safe = re.sub(r"[\x00-\x1f\x7f]", "", path)
    return _LOG_SANITIZE.sub(r"/v1/\1/***", safe)


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

    # Tier header (set by auth.authenticate via request.state)
    tier = getattr(request.state, "ratelimit_tier", None)
    if tier:
        response.headers["X-RateLimit-Tier"] = tier

    # Credit cost header (set by auth.authenticate via request.state)
    cost = getattr(request.state, "ratelimit_cost", None)
    if cost is not None:
        response.headers["X-RateLimit-Cost"] = str(cost)

    # Request logging + metrics
    elapsed = int((time.time() - start) * 1000)
    safe_path = _sanitize_path(request.url.path)
    logger.info("%s %s %s %dms [%s]", request.method, safe_path, response.status_code, elapsed, request_id)
    _record_metric(request.url.path, response.status_code, elapsed)

    return response


# --- Error handler ---


ENDPOINT_HINTS = [
    ("/v1/code/", "Did you mean /v1/check/secrets or /v1/check/injection?"),
    ("/v1/domain/http", "Don't include http:// — use just the domain: /v1/domain/example.com"),
    ("/v1/domain/", "Include a domain: /v1/domain/example.com"),
    ("/v1/cve/", "Usage: /v1/cve/CVE-2024-3094 or /v1/cves?keyword=apache"),
    ("/v1/epss/", "Include a CVE ID: /v1/epss/CVE-2024-3094"),
    ("/v1/exploit/", "Include a CVE ID: /v1/exploit/CVE-2024-3094"),
    ("/v1/tech/", "Include a domain: /v1/tech/example.com"),
    ("/v1/dns/", "Include a domain: /v1/dns/example.com"),
    ("/v1/ssl/", "Include a domain: /v1/ssl/example.com"),
    ("/v1/whois/", "Include a domain: /v1/whois/example.com"),
    ("/v1/subdomains/", "Include a domain: /v1/subdomains/example.com"),
    ("/v1/certs/", "Include a domain: /v1/certs/example.com"),
    ("/v1/threat/", "Include a domain: /v1/threat/example.com"),
    ("/v1/monitor/", "Include a domain: /v1/monitor/example.com"),
    ("/v1/ip/", "Include an IP address: /v1/ip/8.8.8.8"),
    ("/v1/asn/", "Include an ASN or IP: /v1/asn/AS13335 or /v1/asn/8.8.8.8"),
    ("/v1/ioc/", "Include an indicator (IP, domain, or hash): /v1/ioc/1.2.3.4"),
    ("/v1/hash/", "Include a file hash (MD5/SHA1/SHA256): /v1/hash/abc123..."),
    ("/v1/password/", "GET /v1/password/{sha1_hash} — provide full SHA1 hash (40 hex chars)"),
    ("/v1/phishing/", "GET /v1/phishing/{url} — e.g., /v1/phishing/https://example.com"),
    ("/v1/phone/", "Include a phone number with country code: /v1/phone/+905551234567"),
    ("/v1/email/", "Include an email: /v1/email/mx/user@example.com or /v1/email/disposable/user@example.com"),
    ("/v1/check/", "POST endpoints: /v1/check/secrets, /v1/check/headers, /v1/check/injection, /v1/check/dependencies"),
    ("/v1/scan/", "GET /v1/scan/headers/{domain} — e.g., /v1/scan/headers/example.com"),
    (
        "/v1/",
        "Full docs: https://github.com/UPinar/contrastapi/blob/main/docs/ENDPOINTS.md — "
        "Try: /v1/domain/example.com, /v1/cve/CVE-2024-3094, /v1/ip/8.8.8.8",
    ),
]
ENDPOINT_HINT_DEFAULT = ENDPOINT_HINTS[-1][1]


@app.exception_handler(StarletteHTTPException)
async def api_error_handler(request: Request, exc: StarletteHTTPException):
    """All errors return JSON with helpful hints."""
    content = {"error": exc.detail}
    path = request.url.path

    if exc.status_code == 404:
        for prefix, hint in ENDPOINT_HINTS:
            if path.startswith(prefix):
                content["hint"] = hint
                break
        else:
            content["hint"] = ENDPOINT_HINT_DEFAULT

    if exc.status_code == 405:
        content["hint"] = f"Method {request.method} not allowed. Try POST for /v1/check/* endpoints."

    return JSONResponse(status_code=exc.status_code, content=content)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    err = exc.errors()[0] if exc.errors() else {}
    loc = err.get("loc", ())
    field = loc[-1] if loc else None
    received = err.get("input")
    reason = err.get("msg", "Validation failed").removeprefix("Value error, ")
    path = request.url.path
    suggestion = ENDPOINT_HINT_DEFAULT
    for prefix, hint in ENDPOINT_HINTS:
        if path.startswith(prefix):
            suggestion = hint
            break
    content = {
        "error": "Validation failed",
        "reason": reason,
        "suggestion": suggestion,
        "docs": "https://github.com/UPinar/contrastapi/blob/main/docs/ENDPOINTS.md",
    }
    if field:
        content["field"] = field
    if received is not None and isinstance(received, str) and len(received) < 200:
        content["received"] = received
    return JSONResponse(status_code=422, content=content)


@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    """Catch-all — never leak stack traces or internal paths."""
    logger.exception("Unhandled error on %s %s", request.method, _sanitize_path(request.url.path))
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


# --- Landing page ---


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def landing_page(request: Request):
    total = get_total_requests()
    return templates.TemplateResponse(request, "index.html", {"total_requests": total})


@app.get("/cn/", response_class=HTMLResponse, include_in_schema=False)
@app.get("/cn", response_class=HTMLResponse, include_in_schema=False)
def landing_page_cn(request: Request):
    total = get_total_requests()
    return templates.TemplateResponse(request, "index_cn.html", {"total_requests": total})


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

    if api_key:
        context = {"api_key": api_key, "error": None, "polling": False, "order_id": order_id}
    elif get_key_by_order_id(order_id):
        # Order exists but pending_key already consumed — already claimed
        context = {
            "api_key": None,
            "error": "This API key has already been claimed. If you lost your key, please contact support.",
            "polling": False,
            "order_id": order_id,
        }
    else:
        # Order not in DB yet — webhook may not have arrived, show polling spinner
        context = {"api_key": None, "error": None, "polling": True, "order_id": order_id}

    try:
        return templates.TemplateResponse(
            request,
            "welcome.html",
            context,
        )
    except (ValueError, OSError) as exc:
        if api_key:
            logger.error("Template render failed for order %s: %s, returning plain text fallback", order_id, exc)
            return PlainTextResponse(
                f"Your API key: {api_key}\n\nSave this key now. It will not be shown again.",
                media_type="text/plain",
            )
        raise


@app.get("/api/check-key", include_in_schema=False)
def check_key_ready(request: Request, order_id: str = ""):
    """Poll endpoint: returns whether a pending key is ready for the given order."""
    if not order_id:
        raise HTTPException(status_code=400, detail="Missing order_id")
    try:
        uuid.UUID(order_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid order_id format") from None

    client_ip = get_client_ip(request)
    if not check_limit("check_key", client_ip, max_requests=10, window_seconds=60):
        raise HTTPException(status_code=429, detail="Too many requests")

    return {"ready": has_pending_key(order_id)}


@app.get("/quickstart", response_class=HTMLResponse, include_in_schema=False)
def quickstart():
    return HTMLResponse(
        content="""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Quick Start | ContrastAPI</title>
  <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
  <link rel="stylesheet" href="/static/style.css?v=18">
  <style>
    .page { max-inline-size: 52rem; margin-inline: auto; padding: 3rem 2rem; position: relative; z-index: 1; }
    .page h1 { font-size: 2.25rem; font-weight: 800; letter-spacing: -0.04em; margin-block-end: 0.5rem; }
    .page h1 span { background: linear-gradient(135deg, var(--primary), var(--purple)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .page .subtitle { color: var(--text-dim); margin: 0 0 3rem; max-width: none; }
    .page h2 { font-size: 1.1rem; margin: 2.5rem 0 1rem; padding-block-end: 0.5rem; border-block-end: 1px solid var(--border); }
    .page h2 .num { color: var(--primary); }
    .page p { color: var(--text-muted); margin-block-end: 1rem; }
    .code-block { position: relative; background: var(--bg-card); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1rem 1.25rem; margin-block-end: 1.5rem; overflow-x: auto; }
    .code-block code { color: #e4e4e7; font-size: 0.75rem; white-space: pre; font-family: var(--font-mono); }
    .code-block .lang { position: absolute; top: 0.5rem; right: 0.75rem; color: var(--primary); font-size: 0.7rem; text-transform: uppercase; }
    .pill-inline { display: inline-block; background: rgba(59,130,246,0.1); color: var(--primary); border: 1px solid rgba(59,130,246,0.2); border-radius: 4px; padding: 0.1rem 0.5rem; font-size: 0.7rem; }
    .pill-inline.green { background: rgba(34,197,94,0.1); color: var(--green); border-color: rgba(34,197,94,0.2); }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
    .grid .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1.25rem; }
    .grid .card h3 { font-size: 0.95rem; margin-block-end: 0.5rem; }
    .grid .card p { font-size: 0.85rem; margin: 0; }
    .grid .card a { color: var(--primary); }
    .grid .card a:visited { color: var(--primary); }
    @media (max-width: 600px) { .grid { grid-template-columns: 1fr; } .page h1 { font-size: 1.75rem; } }
  </style>
</head>
<body>
  <div class="glow"></div>

  <nav>
    <a href="/" class="logo">Contrast<span>API</span></a>
    <button class="hamburger" aria-label="Menu" aria-expanded="false" onclick="const o=this.getAttribute('aria-expanded')==='true';this.setAttribute('aria-expanded',String(!o));document.querySelector('.nav-links').classList.toggle('open')"><span class="hamburger__lines" aria-hidden="true"></span></button>
    <div class="nav-links">
      <a href="/quickstart">API Start</a>
      <a href="/mcp-setup">MCP Setup</a>
      <a href="/playground">Playground</a>
      <a href="https://contrastcyber.com/pricing">Pricing</a>
      <a href="https://github.com/UPinar/contrastapi" class="gh-star" target="_blank" rel="noopener">★ GitHub</a>
    </div>
  </nav>

  <div class="page">
    <h1>Quick <span>Start</span></h1>
    <p class="subtitle">From zero to first API call in 30 seconds. No signup, no API key required.</p>

    <h2><span class="num">1</span> cURL</h2>
    <p>Copy, paste, run.</p>
    <div class="code-block"><span class="lang">bash</span><code>curl https://api.contrastcyber.com/v1/domain/example.com</code></div>

    <div class="code-block"><span class="lang">bash</span><code># CVE lookup
curl https://api.contrastcyber.com/v1/cve/CVE-2024-3094

# Live header scan
curl https://api.contrastcyber.com/v1/scan/headers/example.com

# IP intelligence
curl https://api.contrastcyber.com/v1/ip/8.8.8.8

# Code secrets scan
curl -X POST https://api.contrastcyber.com/v1/check/secrets \\
  -H "Content-Type: application/json" \\
  -d '{"code": "aws_key = AKIAIOSFODNN7EXAMPLE"}'</code></div>

    <h2><span class="num">2</span> Node.js / JavaScript</h2>
    <p><span class="pill-inline">npm</span> No SDK needed — just fetch.</p>
    <div class="code-block"><span class="lang">javascript</span><code>// Domain security report
const res = await fetch('https://api.contrastcyber.com/v1/domain/example.com');
const data = await res.json();
console.log(data.risk_score);   // { grade: "B", score: 72, ... }
console.log(data.ssl.grade);    // "A"
console.log(data.dns.records);  // [{ type: "A", value: "93.184.216.34" }, ...]

// CVE lookup
const cve = await fetch('https://api.contrastcyber.com/v1/cve/CVE-2024-3094');
const vuln = await cve.json();
console.log(vuln.severity);     // "critical"
console.log(vuln.epss_score);   // 0.94</code></div>

    <h2><span class="num">3</span> Python</h2>
    <div class="code-block"><span class="lang">python</span><code>import requests

# Domain report
r = requests.get('https://api.contrastcyber.com/v1/domain/example.com')
data = r.json()
print(data['risk_score']['grade'])  # "B"

# Scan code for secrets
r = requests.post('https://api.contrastcyber.com/v1/check/secrets',
    json={'code': 'password = "hunter2"'})
print(r.json()['findings'])</code></div>

    <h2><span class="num">4</span> CI/CD (GitHub Actions)</h2>
    <div class="code-block"><span class="lang">yaml</span><code># .github/workflows/security.yml
- name: Security header check
  run: |
    GRADE=$(curl -s https://api.contrastcyber.com/v1/scan/headers/$DOMAIN | jq -r '.grade')
    if [ "$GRADE" = "F" ]; then echo "Security grade F!" && exit 1; fi</code></div>

    <h2>What's next?</h2>
    <div class="grid">
      <div class="card">
        <h3>Playground</h3>
        <p>Try all 29 endpoints from your browser. <a href="/playground">Open playground &rarr;</a></p>
      </div>
      <div class="card">
        <h3>Rate Limits</h3>
        <p><span class="pill-inline green">Free</span> 100 req/hr &middot; <span class="pill-inline">Pro</span> 1000 req/hr. <a href="https://contrastcyber.com/pricing">Pricing &rarr;</a></p>
      </div>
      <div class="card">
        <h3>MCP Setup</h3>
        <p>Use with Claude, Cursor, VS Code. <a href="/mcp-setup">Setup guide &rarr;</a></p>
      </div>
      <div class="card">
        <h3>GitHub</h3>
        <p>Star, issues, contributions. <a href="https://github.com/UPinar/contrastapi">Repository &rarr;</a></p>
      </div>
    </div>
  </div>

  <footer>
    <div class="footer-links">
      <a href="https://contrastcyber.com/terms">Terms</a>
      <a href="https://contrastcyber.com/privacy">Privacy</a>
      <a href="mailto:contact@contrastcyber.com">Contact</a>
      <a href="https://github.com/UPinar/contrastapi">GitHub</a>
    </div>
    <p>&copy; 2026 ContrastCyber</p>
  </footer>
</body>
</html>"""
    )


@app.get("/mcp-setup", response_class=HTMLResponse, include_in_schema=False)
def mcp_setup():
    return HTMLResponse(
        content="""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP Setup | ContrastAPI</title>
  <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
  <link rel="stylesheet" href="/static/style.css?v=18">
  <style>
    .page { max-inline-size: 52rem; margin-inline: auto; padding: 3rem 2rem; position: relative; z-index: 1; }
    .page h1 { font-size: 2.25rem; font-weight: 800; letter-spacing: -0.04em; margin-block-end: 0.5rem; }
    .page h1 span { background: linear-gradient(135deg, var(--primary), var(--purple)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .page .subtitle { color: var(--text-dim); margin: 0 0 3rem; max-width: none; }
    .page h2 { font-size: 1.1rem; margin: 2.5rem 0 1rem; padding-block-end: 0.5rem; border-block-end: 1px solid var(--border); }
    .page h2 .num { color: var(--primary); }
    .page p { color: var(--text-muted); margin-block-end: 1rem; }
    .code-block { position: relative; background: var(--bg-card); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1rem 1.25rem; margin-block-end: 1.5rem; overflow-x: auto; }
    .code-block code { color: #e4e4e7; font-size: 0.75rem; white-space: pre; font-family: var(--font-mono); }
    .code-block .lang { position: absolute; top: 0.5rem; right: 0.75rem; color: var(--primary); font-size: 0.7rem; text-transform: uppercase; }
    .try-box { background: var(--bg-card); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1.25rem; margin: 1.5rem 0; }
    .try-box h3 { font-size: 0.95rem; margin-block-end: 0.75rem; color: var(--primary); }
    .try-box p { font-size: 0.85rem; color: var(--text-muted); margin-block-end: 0.5rem; }
    .try-box em { color: var(--text); font-style: normal; }
    .tools-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; margin: 1rem 0; }
    .tool { background: var(--bg-card); border: 1px solid var(--border-dim); border-radius: 0.375rem; padding: 0.5rem 0.75rem; font-size: 0.8rem; }
    .tool .name { color: var(--primary); }
    .tool .desc { color: var(--text-dim); font-size: 0.75rem; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
    .grid .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1.25rem; }
    .grid .card h3 { font-size: 0.95rem; margin-block-end: 0.5rem; }
    .grid .card p { font-size: 0.85rem; margin: 0; }
    .grid .card a { color: var(--primary); }
    .grid .card a:visited { color: var(--primary); }
    @media (max-width: 600px) { .grid { grid-template-columns: 1fr; } .tools-grid { grid-template-columns: 1fr; } .page h1 { font-size: 1.75rem; } }
  </style>
</head>
<body>
  <div class="glow"></div>

  <nav>
    <a href="/" class="logo">Contrast<span>API</span></a>
    <button class="hamburger" aria-label="Menu" aria-expanded="false" onclick="const o=this.getAttribute('aria-expanded')==='true';this.setAttribute('aria-expanded',String(!o));document.querySelector('.nav-links').classList.toggle('open')"><span class="hamburger__lines" aria-hidden="true"></span></button>
    <div class="nav-links">
      <a href="/quickstart">API Start</a>
      <a href="/mcp-setup">MCP Setup</a>
      <a href="/playground">Playground</a>
      <a href="https://contrastcyber.com/pricing">Pricing</a>
      <a href="https://github.com/UPinar/contrastapi" class="gh-star" target="_blank" rel="noopener">★ GitHub</a>
    </div>
  </nav>

  <div class="page">
    <h1>MCP <span>Setup</span></h1>
    <p class="subtitle">Give your AI agent 29 security tools. One config, zero signup.</p>

    <h2><span class="num">1</span> Claude Desktop</h2>
    <p>Edit <code>~/.claude/claude_desktop_config.json</code>:</p>
    <div class="code-block"><span class="lang">json</span><code>{
  "mcpServers": {
    "contrastapi": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://api.contrastcyber.com/mcp/"]
    }
  }
}</code></div>
    <p>Restart Claude Desktop. Done.</p>

    <h2><span class="num">2</span> Cursor</h2>
    <p>Add to <code>.cursor/mcp.json</code> in your project root:</p>
    <div class="code-block"><span class="lang">json</span><code>{
  "mcpServers": {
    "contrastapi": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://api.contrastcyber.com/mcp/"]
    }
  }
}</code></div>

    <h2><span class="num">3</span> VS Code (Claude Code)</h2>
    <p>Add to <code>.mcp.json</code> in your project root:</p>
    <div class="code-block"><span class="lang">json</span><code>{
  "mcpServers": {
    "contrastapi": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://api.contrastcyber.com/mcp/"]
    }
  }
}</code></div>

    <h2><span class="num">4</span> Windsurf</h2>
    <p>Add to <code>~/.codeium/windsurf/mcp_config.json</code>:</p>
    <div class="code-block"><span class="lang">json</span><code>{
  "mcpServers": {
    "contrastapi": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://api.contrastcyber.com/mcp/"]
    }
  }
}</code></div>

    <h2><span class="num">5</span> Any MCP Client (HTTP)</h2>
    <p>Use the remote HTTP transport directly:</p>
    <div class="code-block"><span class="lang">http</span><code>POST https://api.contrastcyber.com/mcp/
Content-Type: application/json
Accept: application/json, text/event-stream

{"jsonrpc":"2.0","id":1,"method":"initialize",
 "params":{"protocolVersion":"2025-03-26",
   "capabilities":{},
   "clientInfo":{"name":"my-app","version":"1.0"}}}</code></div>

    <div class="try-box">
      <h3>Try it now</h3>
      <p>After setup, ask your AI:</p>
      <p><em>"Run a full security audit on example.com"</em></p>
      <p><em>"Is the SSL certificate on example.com expiring soon?"</em></p>
      <p><em>"What technologies does example.com use?"</em></p>
      <p><em>"Look up CVE-2024-3094 &mdash; is it being exploited in the wild?"</em></p>
      <p><em>"Find critical Apache vulnerabilities from the last 6 months"</em></p>
      <p><em>"Is 8.8.8.8 malicious? Check its reputation"</em></p>
      <p><em>"What ASN does 1.1.1.1 belong to?"</em></p>
      <p><em>"Enrich this IOC: 185.220.101.1"</em></p>
      <p><em>"Check if http://evil-example.test/login is a phishing URL"</em></p>
      <p><em>"Has this password been exposed in a data breach?"</em></p>
      <p><em>"Check this code for hardcoded API keys and secrets"</em></p>
      <p><em>"Is user@example.com a disposable email?"</em></p>
    </div>

    <h2>29 Tools</h2>
    <div class="tools-grid">
      <div class="tool"><span class="name">domain_report</span> <span class="desc">Full domain security audit</span></div>
      <div class="tool"><span class="name">audit_domain</span> <span class="desc">Report + tech + live headers (one call)</span></div>
      <div class="tool"><span class="name">dns_lookup</span> <span class="desc">DNS records</span></div>
      <div class="tool"><span class="name">whois_lookup</span> <span class="desc">Registration data</span></div>
      <div class="tool"><span class="name">ssl_check</span> <span class="desc">Certificate analysis</span></div>
      <div class="tool"><span class="name">subdomain_enum</span> <span class="desc">Subdomain discovery</span></div>
      <div class="tool"><span class="name">tech_fingerprint</span> <span class="desc">CMS/framework detection</span></div>
      <div class="tool"><span class="name">threat_intel</span> <span class="desc">Malware/URLhaus lookup</span></div>
      <div class="tool"><span class="name">wayback_lookup</span> <span class="desc">Web archive history</span></div>
      <div class="tool"><span class="name">scan_headers</span> <span class="desc">Live header analysis</span></div>
      <div class="tool"><span class="name">email_mx</span> <span class="desc">SPF/DMARC/DKIM check</span></div>
      <div class="tool"><span class="name">email_disposable</span> <span class="desc">Disposable email detection</span></div>
      <div class="tool"><span class="name">ip_lookup</span> <span class="desc">IP intelligence (Shodan)</span></div>
      <div class="tool"><span class="name">threat_report</span> <span class="desc">IP threat report (AbuseIPDB + Shodan + ASN)</span></div>
      <div class="tool"><span class="name">asn_lookup</span> <span class="desc">ASN/network info</span></div>
      <div class="tool"><span class="name">cve_lookup</span> <span class="desc">CVE + EPSS + KEV</span></div>
      <div class="tool"><span class="name">cve_search</span> <span class="desc">Search CVEs by product</span></div>
      <div class="tool"><span class="name">bulk_cve_lookup</span> <span class="desc">Bulk CVE lookup (up to 50)</span></div>
      <div class="tool"><span class="name">exploit_lookup</span> <span class="desc">Public exploits</span></div>
      <div class="tool"><span class="name">ioc_lookup</span> <span class="desc">IOC enrichment</span></div>
      <div class="tool"><span class="name">bulk_ioc_lookup</span> <span class="desc">Bulk IOC lookup (up to 50)</span></div>
      <div class="tool"><span class="name">hash_lookup</span> <span class="desc">File hash reputation</span></div>
      <div class="tool"><span class="name">password_check</span> <span class="desc">Breach database check</span></div>
      <div class="tool"><span class="name">phishing_check</span> <span class="desc">URL phishing detection</span></div>
      <div class="tool"><span class="name">phone_lookup</span> <span class="desc">Phone number OSINT</span></div>
      <div class="tool"><span class="name">username_lookup</span> <span class="desc">Username OSINT across 16 platforms</span></div>
      <div class="tool"><span class="name">check_secrets</span> <span class="desc">Hardcoded secret scan</span></div>
      <div class="tool"><span class="name">check_injection</span> <span class="desc">SQL/command injection</span></div>
      <div class="tool"><span class="name">check_headers</span> <span class="desc">Header validation</span></div>
    </div>

    <h2>What's next?</h2>
    <div class="grid">
      <div class="card">
        <h3>REST API</h3>
        <p>Use without MCP — cURL, Node.js, Python. <a href="/quickstart">API Quick Start &rarr;</a></p>
      </div>
      <div class="card">
        <h3>Playground</h3>
        <p>Try all 29 endpoints from your browser. <a href="/playground">Open playground &rarr;</a></p>
      </div>
    </div>
  </div>

  <footer>
    <div class="footer-links">
      <a href="https://contrastcyber.com/terms">Terms</a>
      <a href="https://contrastcyber.com/privacy">Privacy</a>
      <a href="mailto:contact@contrastcyber.com">Contact</a>
      <a href="https://github.com/UPinar/contrastapi">GitHub</a>
    </div>
    <p>&copy; 2026 ContrastCyber</p>
  </footer>
</body>
</html>"""
    )


@app.get("/playground", response_class=HTMLResponse, include_in_schema=False)
def playground(request: Request):
    return templates.TemplateResponse(request, "playground.html")


@app.get("/docs", include_in_schema=False)
def custom_docs():
    return JSONResponse(
        status_code=404,
        content={
            "error": "Not found",
            "hint": "See https://github.com/UPinar/contrastapi for API documentation.",
        },
    )


# --- Meta endpoints ---


@app.get("/v1/status", operation_id="api_status", tags=["Meta"])
def api_status():
    """API health check and data freshness."""
    sync = get_sync_status()
    return {
        "status": "ok",
        "version": VERSION,
        "data_sources": {source: {"status": info.get("status")} for source, info in sync.items()},
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


@app.get("/v1/privacy/my-data", operation_id="privacy_my_data", tags=["Meta"])
def privacy_my_data(request: Request):
    """Return everything this API has stored about you. GDPR-style transparency.

    Shows the hashed IP, Pro key record (if any), and last-24h endpoint usage.
    The raw domains, IPs, CVEs, hashes, or code you submitted are NEVER stored —
    path parameters are stripped before any DB write (see db.normalize_endpoint).
    """
    from auth import authenticate
    from config import FREE_HOURLY_LIMIT, PRO_HOURLY_LIMIT
    from db import get_privacy_data

    auth_ctx = authenticate(request, "/v1/privacy/my-data")
    data = get_privacy_data(auth_ctx["client_ip"], auth_ctx["key_hash"])

    tier = auth_ctx["tier"]
    limit = PRO_HOURLY_LIMIT if tier == "pro" else FREE_HOURLY_LIMIT
    remaining = getattr(request.state, "ratelimit_remaining", None)

    return {
        "tier": tier,
        "rate_limit": {
            "hourly_limit": limit,
            "remaining_in_window": remaining,
            "window_seconds": 3600,
        },
        **data,
        "not_stored": [
            "Your raw IP address. Only a salted HMAC hash is stored, used for anonymized analytics.",
            "The domain names, IP addresses, CVE IDs, file hashes, emails, phone numbers, usernames, or source code you submit. Path parameters are stripped before logging — see db.normalize_endpoint at https://github.com/UPinar/contrastapi/blob/main/app/db.py",
            "Response contents. Domain and IP lookups use a 1-hour performance cache keyed by the queried target (not by you); everything else is processed in real time.",
            "Your name, email, phone, or any personal identifier. No signup, no accounts.",
            "Tracking cookies, third-party analytics, or fingerprinting data.",
        ],
        "source_code": {
            "hashing": "https://github.com/UPinar/contrastapi/blob/main/app/db.py (hash_client_ip)",
            "endpoint_normalization": "https://github.com/UPinar/contrastapi/blob/main/app/db.py (normalize_endpoint)",
            "this_endpoint": "https://github.com/UPinar/contrastapi/blob/main/app/main.py (privacy_my_data)",
        },
        "privacy_policy": "https://contrastcyber.com/privacy",
        "contact": "contact@contrastcyber.com",
    }


@app.get("/v1/capabilities", operation_id="api_capabilities", tags=["Meta"])
def api_capabilities():
    """Machine-readable catalog of all 29 MCP tools and REST endpoints."""
    return {
        "schema_version": "1.0",
        "api_version": VERSION,
        "base_url": "https://api.contrastcyber.com",
        "total_tools": 29,
        "verdict_metadata": True,
        "auth": {
            "type": "none_required",
            "free_tier": {"requests_per_hour": 100},
            "pro_tier": {"requests_per_hour": 1000, "header": "Authorization: Bearer cc_xxx"},
        },
        "rate_limit_headers": [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "X-RateLimit-Cost",
            "X-RateLimit-Tier",
        ],
        "blast_radius_legend": {
            "zero": "Local DB or pure computation. No outbound network to target.",
            "low": "Third-party API lookup or passive DNS/WHOIS/CT. Does not contact target host.",
            "high": "Actively contacts target host (live HTTP, TLS handshake, DNS brute force).",
        },
        "categories": {
            "cve": {
                "description": "CVE intelligence, EPSS scores, CISA KEV, exploit search",
                "tools": [
                    {
                        "name": "cve_lookup",
                        "method": "GET",
                        "path": "/v1/cve/{cve_id}",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "Full CVE details with EPSS score, KEV status, CVSS breakdown",
                        "response_keys": [
                            "cve_id",
                            "summary",
                            "severity",
                            "cvss_v3",
                            "epss",
                            "kev",
                            "affected_products",
                        ],
                    },
                    {
                        "name": "cve_search",
                        "method": "GET",
                        "path": "/v1/cves",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "Search CVEs by product, severity, date",
                        "params": {"product": "str", "severity": "str", "days": "int", "limit": "int"},
                        "response_keys": ["count", "summary", "results"],
                    },
                    {
                        "name": None,
                        "method": "GET",
                        "path": "/v1/cves/recent",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "Recently published CVEs",
                        "params": {"hours": "int (default 24)", "limit": "int"},
                        "response_keys": ["count", "hours", "summary", "results"],
                    },
                    {
                        "name": None,
                        "method": "GET",
                        "path": "/v1/cves/kev",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "CISA Known Exploited Vulnerabilities list",
                        "params": {"limit": "int"},
                        "response_keys": ["count", "summary", "results"],
                    },
                    {
                        "name": None,
                        "method": "GET",
                        "path": "/v1/epss/{cve_id}",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "EPSS exploit probability score",
                        "response_keys": ["cve_id", "score", "percentile", "summary"],
                    },
                    {
                        "name": "exploit_lookup",
                        "method": "GET",
                        "path": "/v1/exploit/{cve_id}",
                        "credit_cost": 1,
                        "blast_radius": "low",
                        "description": "Public exploits from GitHub Advisory and ExploitDB",
                        "response_keys": ["cve_id", "exploits_found", "sources", "has_public_exploit", "summary"],
                    },
                    {
                        "name": "bulk_cve_lookup",
                        "method": "POST",
                        "path": "/v1/cves/bulk",
                        "credit_cost": 1,
                        "credit_cost_note": "1 credit per item in request",
                        "blast_radius": "zero",
                        "description": "Bulk CVE lookup",
                        "body": {"cve_ids": "list[str] (max 10 free, 50 pro)"},
                        "response_keys": ["results", "total", "successful", "failed", "summary"],
                    },
                ],
            },
            "domain": {
                "description": "Domain intelligence: DNS, WHOIS, SSL, subdomains, WAF, email security, threat intel, risk scoring",
                "tools": [
                    {
                        "name": "domain_report",
                        "method": "GET",
                        "path": "/v1/domain/{domain}",
                        "credit_cost": 1,
                        "blast_radius": "high",
                        "description": "Full domain report: DNS, WHOIS, SSL, subdomains, WAF, email security, threat intel, risk score",
                        "params": {"lite": "bool (fast subset ~250ms)"},
                        "response_keys": [
                            "domain",
                            "summary",
                            "dns",
                            "whois",
                            "ssl",
                            "email_security",
                            "subdomains",
                            "waf",
                            "threat",
                            "risk",
                        ],
                    },
                    {
                        "name": "audit_domain",
                        "method": "GET",
                        "path": "/v1/audit/{domain}",
                        "credit_cost": 4,
                        "blast_radius": "high",
                        "description": "Orchestrated domain audit: full report + tech fingerprint + live HTTP headers in one call",
                        "response_keys": ["domain", "report", "technologies", "live_headers", "summary"],
                    },
                    {
                        "name": "threat_report",
                        "method": "GET",
                        "path": "/v1/threat-report/{ip}",
                        "credit_cost": 4,
                        "blast_radius": "low",
                        "description": "Orchestrated IP threat report: Shodan + AbuseIPDB + ASN. No private IPs.",
                        "response_keys": ["ip", "enrichment", "abuseipdb", "shodan", "asn", "threat_level", "summary"],
                    },
                    {
                        "name": "dns_lookup",
                        "method": "GET",
                        "path": "/v1/dns/{domain}",
                        "credit_cost": 1,
                        "blast_radius": "low",
                        "description": "DNS records: A, AAAA, MX, NS, TXT, CNAME, SOA",
                        "response_keys": ["domain", "records", "summary"],
                    },
                    {
                        "name": "whois_lookup",
                        "method": "GET",
                        "path": "/v1/whois/{domain}",
                        "credit_cost": 1,
                        "blast_radius": "low",
                        "description": "WHOIS registration data",
                        "response_keys": ["domain", "whois", "summary"],
                    },
                    {
                        "name": "ssl_check",
                        "method": "GET",
                        "path": "/v1/ssl/{domain}",
                        "credit_cost": 1,
                        "blast_radius": "high",
                        "description": "SSL/TLS certificate analysis: cipher, chain, expiry, grade",
                        "response_keys": [
                            "domain",
                            "valid",
                            "issuer",
                            "grade",
                            "days_remaining",
                            "protocol",
                            "cipher",
                            "summary",
                        ],
                    },
                    {
                        "name": "subdomain_enum",
                        "method": "GET",
                        "path": "/v1/subdomains/{domain}",
                        "credit_cost": 1,
                        "blast_radius": "high",
                        "description": "Subdomain enumeration via DNS brute force and CT logs",
                        "response_keys": ["domain", "subdomains", "count", "summary"],
                    },
                    {
                        "name": None,
                        "method": "GET",
                        "path": "/v1/certs/{domain}",
                        "credit_cost": 1,
                        "blast_radius": "low",
                        "description": "Certificate Transparency log entries",
                        "response_keys": ["domain", "total_certificates", "certificates", "summary"],
                    },
                    {
                        "name": "ip_lookup",
                        "method": "GET",
                        "path": "/v1/ip/{ip}",
                        "credit_cost": 1,
                        "blast_radius": "low",
                        "description": "IP intelligence via Shodan InternetDB. No private/reserved IPs.",
                        "response_keys": ["ip", "ptr", "ports", "hostnames", "vulns", "cpes", "tags", "summary"],
                    },
                    {
                        "name": "asn_lookup",
                        "method": "GET",
                        "path": "/v1/asn/{target}",
                        "credit_cost": 1,
                        "blast_radius": "low",
                        "description": "ASN lookup. Accepts domain or IP.",
                        "response_keys": [
                            "target",
                            "resolved_ip",
                            "asn",
                            "asn_name",
                            "ipv4_prefixes",
                            "ipv6_prefixes",
                            "summary",
                        ],
                    },
                    {
                        "name": "threat_intel",
                        "method": "GET",
                        "path": "/v1/threat/{domain}",
                        "credit_cost": 1,
                        "blast_radius": "low",
                        "description": "Threat intelligence via URLhaus malware URL lookup",
                        "response_keys": [
                            "domain",
                            "urlhaus_status",
                            "urls_online",
                            "url_count",
                            "threat_types",
                            "summary",
                        ],
                    },
                    {
                        "name": "tech_fingerprint",
                        "method": "GET",
                        "path": "/v1/tech/{domain}",
                        "credit_cost": 1,
                        "blast_radius": "high",
                        "description": "Technology fingerprinting: CMS, frameworks, servers, CDN, analytics",
                        "response_keys": ["domain", "technologies", "categories", "count", "summary"],
                    },
                    {
                        "name": "scan_headers",
                        "method": "GET",
                        "path": "/v1/scan/headers/{domain}",
                        "credit_cost": 1,
                        "blast_radius": "high",
                        "description": "Live HTTP security header scan and analysis",
                        "response_keys": [
                            "domain",
                            "status_code",
                            "score",
                            "grade",
                            "findings",
                            "headers_present",
                            "headers_missing",
                            "summary",
                        ],
                    },
                    {
                        "name": "email_mx",
                        "method": "GET",
                        "path": "/v1/email/mx/{domain}",
                        "credit_cost": 1,
                        "blast_radius": "low",
                        "description": "Email MX analysis: provider, SPF/DMARC/DKIM, security grade",
                        "response_keys": ["domain", "mx_records", "mail_provider", "email_security", "summary"],
                    },
                    {
                        "name": "email_disposable",
                        "method": "GET",
                        "path": "/v1/email/disposable/{email}",
                        "credit_cost": 1,
                        "blast_radius": "low",
                        "description": "Check if email uses a disposable/temporary provider",
                        "response_keys": ["email", "domain", "disposable", "provider", "risk_level", "summary"],
                    },
                    {
                        "name": "phone_lookup",
                        "method": "GET",
                        "path": "/v1/phone/{number}",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "Phone number validation and OSINT. Include country code e.g. +14155551234.",
                        "response_keys": [
                            "valid",
                            "number",
                            "format",
                            "country_code",
                            "country_name",
                            "type",
                            "carrier",
                            "timezone",
                            "summary",
                        ],
                    },
                    {
                        "name": "username_lookup",
                        "method": "GET",
                        "path": "/v1/username/{username}",
                        "credit_cost": 1,
                        "blast_radius": "high",
                        "description": "Username OSINT across 16 platforms (3-39 chars)",
                        "response_keys": ["username", "found_count", "checked_count", "results", "summary"],
                    },
                    {
                        "name": "wayback_lookup",
                        "method": "GET",
                        "path": "/v1/archive/{domain}",
                        "credit_cost": 1,
                        "blast_radius": "low",
                        "description": "Wayback Machine historical snapshots",
                        "response_keys": [
                            "domain",
                            "total_snapshots",
                            "first_seen",
                            "last_seen",
                            "years_online",
                            "snapshots",
                            "archive_url",
                            "summary",
                        ],
                    },
                ],
            },
            "ioc": {
                "description": "IOC enrichment, hash reputation, password breach, phishing detection",
                "tools": [
                    {
                        "name": "ioc_lookup",
                        "method": "GET",
                        "path": "/v1/ioc/{indicator}",
                        "credit_cost": 1,
                        "blast_radius": "low",
                        "description": "Unified IOC enrichment. Auto-detects IP/domain/URL/hash. Sources: ThreatFox, URLhaus, Feodo.",
                        "response_keys": ["indicator", "type", "threat_level", "sources", "summary"],
                    },
                    {
                        "name": "hash_lookup",
                        "method": "GET",
                        "path": "/v1/hash/{file_hash}",
                        "credit_cost": 1,
                        "blast_radius": "low",
                        "description": "Malware hash reputation via MalwareBazaar. MD5/SHA1/SHA256.",
                        "response_keys": [
                            "hash",
                            "hash_type",
                            "found",
                            "malware_family",
                            "file_type",
                            "tags",
                            "summary",
                        ],
                    },
                    {
                        "name": "password_check",
                        "method": "GET",
                        "path": "/v1/password/{sha1_hash}",
                        "credit_cost": 1,
                        "blast_radius": "low",
                        "description": "Password breach check via HIBP k-anonymity. Pass full SHA1 hash.",
                        "response_keys": ["hash_prefix", "found", "breach_count", "summary"],
                    },
                    {
                        "name": "phishing_check",
                        "method": "GET",
                        "path": "/v1/phishing/{url}",
                        "credit_cost": 1,
                        "blast_radius": "low",
                        "description": "Phishing/malware URL check via URLhaus. URL must start with http(s)://.",
                        "response_keys": ["url", "host", "is_malicious", "threat_level", "summary"],
                    },
                    {
                        "name": "bulk_ioc_lookup",
                        "method": "POST",
                        "path": "/v1/iocs/bulk",
                        "credit_cost": 1,
                        "credit_cost_note": "1 credit per item in request",
                        "blast_radius": "low",
                        "description": "Bulk IOC enrichment",
                        "body": {"indicators": "list[str] (max 10 free, 50 pro)"},
                        "response_keys": ["results", "total", "successful", "failed", "summary"],
                    },
                ],
            },
            "code_security": {
                "description": "Static code analysis: secrets detection, injection detection, header validation, dependency CVE check",
                "tools": [
                    {
                        "name": "check_secrets",
                        "method": "POST",
                        "path": "/v1/check/secrets",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "Detect hardcoded secrets (14 patterns: API keys, tokens, passwords)",
                        "body": {"code": "str", "language": "str"},
                        "response_keys": ["findings", "total", "by_severity", "summary"],
                    },
                    {
                        "name": "check_injection",
                        "method": "POST",
                        "path": "/v1/check/injection",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "SQL, command, and path injection detection",
                        "body": {"code": "str", "language": "str"},
                        "response_keys": ["findings", "total", "by_severity", "summary"],
                    },
                    {
                        "name": "check_headers",
                        "method": "POST",
                        "path": "/v1/check/headers",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "Validate HTTP security headers",
                        "body": {"headers": "dict[str, str]"},
                        "response_keys": [
                            "findings",
                            "total",
                            "by_severity",
                            "score",
                            "grade",
                            "headers_present",
                            "headers_missing",
                            "summary",
                        ],
                    },
                    {
                        "name": None,
                        "method": "POST",
                        "path": "/v1/check/dependencies",
                        "credit_cost": 1,
                        "credit_cost_note": "1 credit per package in request",
                        "blast_radius": "zero",
                        "description": "Check packages against CVE database",
                        "body": {"packages": "list[{name: str, version: str}]"},
                        "response_keys": ["findings", "total", "by_severity", "summary"],
                    },
                ],
            },
            "meta": {
                "description": "API status, usage statistics, capabilities",
                "tools": [
                    {
                        "name": None,
                        "method": "GET",
                        "path": "/v1/status",
                        "credit_cost": 0,
                        "description": "API health check and data freshness",
                    },
                    {
                        "name": None,
                        "method": "GET",
                        "path": "/v1/usage",
                        "credit_cost": 0,
                        "description": "Usage statistics for authenticated API key holders",
                        "auth_required": True,
                    },
                    {
                        "name": None,
                        "method": "GET",
                        "path": "/v1/capabilities",
                        "credit_cost": 0,
                        "description": "This endpoint — machine-readable tool catalog",
                    },
                ],
            },
        },
    }


@app.get("/llms.txt", response_class=PlainTextResponse, include_in_schema=False)
def llms_txt():
    """LLM discovery file — concise version for quick context."""
    return """\
# ContrastAPI

> Security intelligence API for AI models and developers. Free to use, no API key required.

- [Quick Start](https://api.contrastcyber.com/quickstart)
- [MCP Setup](https://api.contrastcyber.com/mcp-setup)
- [API Documentation](https://github.com/UPinar/contrastapi/blob/main/docs/ENDPOINTS.md)
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
Rate limit headers returned: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-RateLimit-Cost, X-RateLimit-Tier.

## Credit Costs

Most endpoints cost 1 credit per call. Aggregating endpoints that fan out to multiple upstream sources cost more:
- `GET /v1/audit/{domain}` — 4 credits (domain report + live headers + tech fingerprint)
- `GET /v1/threat-report/{ip}` — 4 credits (Shodan + AbuseIPDB + full Shodan + ASN)
- `POST /v1/cves/bulk`, `POST /v1/iocs/bulk` — 1 credit per item in the request
- All other endpoints — 1 credit

Every authenticated response includes X-RateLimit-Cost so clients can budget calls transparently.

## Endpoints (29 MCP tools)

### CVE Intelligence
- GET /v1/cve/{cve_id} — Full CVE details with EPSS score, KEV status, CVSS breakdown
- GET /v1/cves?product=&severity=&days= — Search CVEs by product, severity, date
- GET /v1/cves/recent?hours=24 — Recently published CVEs
- GET /v1/cves/kev — CISA Known Exploited Vulnerabilities
- GET /v1/epss/{cve_id} — EPSS exploit probability score
- GET /v1/exploit/{cve_id} — Public exploits and advisories (GitHub Advisory, ExploitDB)
- POST /v1/cves/bulk — Bulk CVE lookup (10 free, 50 pro per request)

### Domain Intelligence
- GET /v1/domain/{domain} — Full domain report (DNS + WHOIS + SSL + subdomains + WAF + email security + threat intel + risk score)
- GET /v1/audit/{domain} — Orchestrated domain audit (full report + tech fingerprint + live headers in one call)
- GET /v1/threat-report/{ip} — Orchestrated IP threat report (Shodan + AbuseIPDB + ASN + enrichment)
- GET /v1/dns/{domain} — DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
- GET /v1/whois/{domain} — WHOIS registration data
- GET /v1/ssl/{domain} — SSL/TLS certificate analysis (cipher, chain, expiry, grade)
- GET /v1/subdomains/{domain} — Subdomain enumeration (DNS brute + CT logs)
- GET /v1/certs/{domain} — Certificate Transparency log entries
- GET /v1/ip/{ip} — IP intelligence (reverse DNS, open ports, vulns, hostnames via Shodan)
- GET /v1/asn/{target} — ASN lookup (AS number, holder, prefixes). Accepts domain or IP
- GET /v1/threat/{domain} — Threat intelligence (URLhaus malware URL lookup)
- GET /v1/tech/{domain} — Technology fingerprinting (CMS, frameworks, servers, CDN, analytics)
- GET /v1/scan/headers/{domain} — Live HTTP security header scan and analysis
- GET /v1/email/mx/{domain} — Email MX analysis (provider, SPF/DMARC/DKIM, security grade)
- GET /v1/email/disposable/{email} — Check if email uses disposable/temporary provider
- GET /v1/phone/{number} — Phone number validation (format, country, type, carrier, timezone)
- GET /v1/username/{username} — Username OSINT across 16 platforms
- GET /v1/archive/{domain} — Wayback Machine historical snapshots

### Threat Intelligence / IOC
- GET /v1/ioc/{indicator} — Unified IOC enrichment (IP, domain, URL, hash → ThreatFox/URLhaus/Feodo)
- GET /v1/hash/{file_hash} — Malware hash reputation via MalwareBazaar
- GET /v1/password/{sha1_hash} — Password breach check via HIBP (k-anonymity)
- GET /v1/phishing/{url} — Phishing/malware URL check via URLhaus
- POST /v1/iocs/bulk — Bulk IOC enrichment (10 free, 50 pro per request)

### Code Security
- POST /v1/check/headers — Validate HTTP security headers (JSON body: {"headers": {...}})
- POST /v1/check/secrets — Detect hardcoded secrets (JSON body: {"code": "...", "language": "python"})
- POST /v1/check/injection — SQL/command/path injection detection (JSON body: {"code": "...", "language": "python"})
- POST /v1/check/dependencies — Check packages against CVE DB (JSON body: {"packages": [{"name": "...", "version": "..."}]})

### Meta
- GET /v1/status — API health check and data freshness
- GET /v1/usage — Usage statistics (Pro key required)
- GET /v1/privacy/my-data — GDPR transparency: returns everything the DB has about the caller (hashed IP, 24h endpoint usage, Pro key record if any). Query parameters are never stored. No auth required.

## MCP (Model Context Protocol)

ContrastAPI is available as an MCP server with 29 tools.
MCP tools: domain_report, audit_domain, dns_lookup, whois_lookup, ssl_check, subdomain_enum,
tech_fingerprint, threat_intel, scan_headers, email_mx, email_disposable,
phone_lookup, username_lookup, wayback_lookup, ip_lookup, asn_lookup, threat_report,
cve_lookup, cve_search, exploit_lookup, bulk_cve_lookup, ioc_lookup, hash_lookup,
password_check, phishing_check, bulk_ioc_lookup, check_secrets, check_injection, check_headers.

### HTTP Transport (remote)
POST https://api.contrastcyber.com/mcp/
Headers: Content-Type: application/json, Accept: application/json, text/event-stream
Body: JSON-RPC 2.0 (initialize, tools/list, tools/call)

### Stdio Transport (local)
Add to .mcp.json:
{"mcpServers": {"contrastapi": {"command": "python3", "args": ["/path/to/mcp_server.py"]}}}

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
    """Full API reference for LLM context — compact format, under 200 lines."""
    return """\
# ContrastAPI — Full API Reference

> Security intelligence API. 29 MCP tools. Base URL: https://api.contrastcyber.com
> Auth: None required (100 req/hr). Pro: Authorization: Bearer cc_xxx (1000 req/hr).
> All responses JSON with a "summary" field optimized for LLM consumption.
> OpenAPI spec: https://api.contrastcyber.com/openapi.json

## CVE Intelligence

GET /v1/cve/{cve_id} — Full CVE details with EPSS + KEV + CVSS breakdown.
  Response keys: cve_id, summary, description, severity, cvss_v3, cvss_breakdown, cwe_id, epss:{score,percentile}, kev:{in_kev,date_added}, affected_products, published, modified, references
  Errors: 400, 404

GET /v1/cves?product=&severity=&days=&limit= — Search CVEs by product/severity/date.
  Response keys: count, summary, results

GET /v1/cves/recent?hours=24&limit=50 — Recently published CVEs.
  Response keys: count, hours, summary, results

GET /v1/cves/kev?limit=100 — CISA Known Exploited Vulnerabilities.
  Response keys: count, summary, results

GET /v1/epss/{cve_id} — EPSS exploit probability score.
  Response keys: cve_id, score, percentile, summary

GET /v1/exploit/{cve_id} — Public exploits (GitHub Advisory + ExploitDB).
  Response keys: cve_id, exploits_found, sources:{github:{found,count,advisories},exploitdb:{found,count,results}}, has_public_exploit, summary

POST /v1/cves/bulk — Bulk CVE lookup. Body: {"cve_ids":["CVE-2024-1234",...]} (max 10 free, 50 pro).
  Response keys: results:[{cve_id,status,cve,error}], total, successful, failed, summary

## Domain Intelligence

GET /v1/domain/{domain} — Full domain report (DNS+WHOIS+SSL+subdomains+WAF+email+threat+risk). Supports ?lite=true.
  Response keys: domain, summary, dns, reverse_dns, whois, ssl, email_security, subdomains, certificates, waf, threat, risk:{score,grade,factors}

GET /v1/audit/{domain} — Orchestrated audit: full domain report + tech fingerprint + live HTTP headers in one call.
  Response keys: domain, report (full domain intel), technologies:{technologies,categories,count,summary}, live_headers, summary

GET /v1/threat-report/{ip} — Orchestrated IP threat report: Shodan InternetDB + AbuseIPDB + Shodan full + ASN. No private IPs.
  Response keys: ip, enrichment:{ports,hostnames,vulns,cpes,tags}, abuseipdb, shodan, asn:{asn,prefix}, threat_level, summary

GET /v1/dns/{domain} — DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA).
  Response keys: domain, records:{a,aaaa,mx,ns,txt,cname,soa}, summary

GET /v1/whois/{domain} — WHOIS registration data.
  Response keys: domain, whois:{registrar,creation_date,expiry_date,name_servers}, summary

GET /v1/ssl/{domain} — SSL/TLS certificate analysis.
  Response keys: domain, valid, issuer, subject, not_before, not_after, days_remaining, san, protocol, cipher:{name,bits}, chain, grade, summary

GET /v1/subdomains/{domain} — Subdomain enumeration (DNS brute + CT logs).
  Response keys: domain, subdomains, count, summary

GET /v1/certs/{domain} — Certificate Transparency log entries.
  Response keys: domain, total_certificates, certificates:[{issuer,not_before,not_after,common_name}], summary

GET /v1/ip/{ip} — IP intelligence (Shodan InternetDB). No private/reserved IPs.
  Response keys: ip, ptr, ports, hostnames, vulns, cpes, tags, summary

GET /v1/asn/{target} — ASN lookup. Accepts domain or IP.
  Response keys: target, resolved_ip, asn, asn_name, ipv4_prefixes, ipv6_prefixes, ipv4_count, ipv6_count, summary

GET /v1/threat/{domain} — Threat intelligence (URLhaus).
  Response keys: domain, urlhaus_status, urls_online, url_count, threat_types, tags, urls, summary

GET /v1/tech/{domain} — Technology fingerprinting (CMS, frameworks, CDN).
  Response keys: domain, technologies:[{name,category,source,version}], categories, count, summary

GET /v1/scan/headers/{domain} — Live HTTP security header scan.
  Response keys: domain, status_code, url, score, grade, findings, headers_present, headers_missing, summary

GET /v1/email/mx/{domain} — Email MX analysis (provider + SPF/DMARC/DKIM).
  Response keys: domain, mx_records, mail_provider, email_security:{spf,dmarc,dkim_selectors,grade,issues}, summary

GET /v1/email/disposable/{email} — Disposable email check.
  Response keys: email, domain, disposable, provider, mx_disposable, risk_level, summary

GET /v1/phone/{number} — Phone validation. Include country code (e.g. +14155551234).
  Response keys: valid, number, format:{e164,international,national}, country_code, country_name, type, carrier, timezone, summary

GET /v1/username/{username} — Username OSINT across 16 platforms (3-39 chars).
  Response keys: username, found_count, checked_count, results:[{platform,url,status}], summary

GET /v1/archive/{domain} — Wayback Machine history.
  Response keys: domain, total_snapshots, first_seen, last_seen, years_online, snapshots, archive_url, summary

## Threat Intelligence / IOC

GET /v1/ioc/{indicator} — Unified IOC enrichment. Auto-detects IP/domain/URL/hash.
  Response keys: indicator, type, threat_level, sources:{threatfox,feodo,urlhaus}, summary

GET /v1/hash/{file_hash} — Malware hash (MalwareBazaar). MD5/SHA1/SHA256.
  Response keys: hash, hash_type, found, malware_family, file_type, file_size, first_seen, tags, file_name, summary

GET /v1/password/{sha1_hash} — Password breach check (HIBP k-anonymity). Full SHA1 hash.
  Response keys: hash_prefix, found, breach_count, summary

GET /v1/phishing/{url} — Phishing/malware URL check (URLhaus). Must start with http(s)://.
  Response keys: url, host, is_malicious, urlhaus_host:{found,urls_online,url_count}, urlhaus_url:{found,threat,tags}, threat_level, summary

POST /v1/iocs/bulk — Bulk IOC enrichment. Body: {"indicators":["8.8.8.8","evil.com",...]} (max 10 free, 50 pro).
  Response keys: results:[{indicator,status,ioc:{type,threat_level,sources},error}], total, successful, failed, timed_out, partial, summary

## Code Security

POST /v1/check/secrets — Detect hardcoded secrets (14 patterns). Body: {"code":"...","language":"python"}
  Response keys: findings:[{type,severity,line,match,description,remediation}], total, by_severity, summary

POST /v1/check/injection — SQL/command/path injection. Body: {"code":"...","language":"python"}
  Response keys: findings:[{type,severity,line,match,description,remediation}], total, by_severity, summary

POST /v1/check/headers — Validate security headers. Body: {"headers":{"header-name":"value"}}
  Response keys: findings, total, by_severity, score, grade, headers_present:[], headers_missing:[], summary

POST /v1/check/dependencies — Check packages for CVEs. Body: {"packages":[{"name":"...","version":"..."}]}
  Response keys: findings:[{package,version,cve_id,severity,cvss_v3,epss_score,in_kev,remediation}], total, by_severity, summary

## Meta

GET /v1/status — Health check. Response: {status, version, data_sources}
GET /v1/usage — Pro key stats (requires auth). Response: {total_requests, last_24h, last_1h, hourly_limit, hourly_remaining, top_endpoints}
GET /v1/privacy/my-data — GDPR transparency. Returns every row the DB has about the caller — hashed IP, 24h endpoint usage (normalized, no query params), Pro key record if any. Free and Pro tier both supported. No auth required. Response: {tier, rate_limit, client_ip_hash, api_key_record, usage_last_24h:{total_requests,by_endpoint}, not_stored, source_code, privacy_policy}

## Example: CVE Lookup

GET /v1/cve/CVE-2024-3094 →
{"cve_id":"CVE-2024-3094", "summary":"CRITICAL — xz/liblzma backdoor. CVSS 10.0. CISA KEV. EPSS 93%.",
 "severity":"CRITICAL", "cvss_v3":10.0, "epss":{"score":0.93}, "kev":{"in_kev":true}}

## Example: Domain Report

GET /v1/domain/example.com →
{"domain":"example.com", "summary":"Grade B (72/100). SSL A (DigiCert, TLSv1.3). 3 subdomains. No threats.",
 "risk":{"score":72,"grade":"B"}, "ssl":{"grade":"A","days_remaining":120}}

## Rate Limits & Data Sources

Keyless: 100 req/hr per IP. Pro: 1000 req/hr. Headers: X-RateLimit-{Limit,Remaining,Reset,Cost,Tier}, X-Request-ID.
Credit costs: most endpoints = 1, /v1/audit and /v1/threat-report = 4, bulk endpoints = N (one per item).
Data: NVD (340K+ CVEs), EPSS (323K+), CISA KEV (1500+), Shodan, URLhaus, ThreatFox, MalwareBazaar,
GitHub Advisory DB, HIBP, Wayback Machine, crt.sh. CVE/EPSS/KEV synced every 2h. Others live.
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


@app.get("/mcp/debug", include_in_schema=False)
def mcp_debug():
    """Human-readable MCP handshake guide — helps crawlers and developers debug 400 errors."""
    return JSONResponse(
        {
            "endpoint": "https://api.contrastcyber.com/mcp/",
            "protocol": "MCP Streamable HTTP",
            "protocol_version": "2024-11-05",
            "required_headers": {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            "valid_initialize_request": {
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "your-client", "version": "1.0"},
                },
                "id": 1,
            },
            "common_errors": [
                {
                    "symptom": "HTTP 400",
                    "cause": "Missing or malformed JSON-RPC fields",
                    "fix": "Body must include jsonrpc='2.0', method, id, and params",
                },
                {
                    "symptom": "HTTP 400",
                    "cause": "Missing Accept header",
                    "fix": "Add 'Accept: application/json, text/event-stream'",
                },
                {
                    "symptom": "HTTP 200 + RPC error -32602",
                    "cause": "params.clientInfo missing",
                    "fix": "Add clientInfo: {name: 'your-client', version: '1.0'} to params",
                },
            ],
            "tools_count": 29,
            "docs": "https://github.com/UPinar/contrastapi/blob/main/docs/ENDPOINTS.md",
            "setup_guide": "https://api.contrastcyber.com/mcp-setup",
        }
    )


# --- MCP Streamable HTTP endpoint ---
_mcp_session_mgr = None
try:
    import importlib.util as _imputil

    _spec = _imputil.spec_from_file_location("mcp_server", str(BASE_DIR.parent / "mcp_server.py"))
    _mcp_mod = _imputil.module_from_spec(_spec)
    _spec.loader.exec_module(_mcp_mod)
    _mcp_instance = _mcp_mod.mcp
    _mcp_client_ip_var = _mcp_mod._client_ip_var
    _mcp_safe_ip = _mcp_mod._safe_ip

    class _MCPIPForwardMiddleware:
        """ASGI middleware that sets the real client IP in contextvars
        so MCP tool calls forward it to internal API requests."""

        def __init__(self, asgi_app):
            self.app = asgi_app

        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                raw_headers = scope.get("headers", [])
                headers_map = dict(raw_headers)
                # Priority: CF-Connecting-IP (Cloudflare) > X-Real-IP (nginx) > XFF
                ip = (headers_map.get(b"cf-connecting-ip") or b"").decode().strip()
                if not ip:
                    ip = (headers_map.get(b"x-real-ip") or b"").decode().strip()
                if not ip:
                    xff = (headers_map.get(b"x-forwarded-for") or b"").decode()
                    ip = xff.split(",")[0].strip() if xff else ""
                # GET/HEAD → return health JSON for crawlers/availability checks
                if scope.get("method") in ("GET", "HEAD"):
                    import json as _json

                    body = _json.dumps(
                        {
                            "name": "ContrastAPI MCP Server",
                            "version": VERSION,
                            "transport": "streamable-http",
                            "method": "POST",
                            "tools": 29,
                            "docs": "https://api.contrastcyber.com/mcp-setup",
                        }
                    ).encode()
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 200,
                            "headers": [
                                [b"content-type", b"application/json"],
                                [b"content-length", str(len(body)).encode()],
                            ],
                        }
                    )
                    await send({"type": "http.response.body", "body": body if scope.get("method") == "GET" else b""})
                    return
                # Normalize Accept header for POST only — tolerant probes
                # (Chiark, etc.) may omit it on initialize.
                if scope.get("method") == "POST":
                    new_headers = list(raw_headers)
                    accept_idx = next(
                        (i for i, (k, _) in enumerate(new_headers) if k.lower() == b"accept"),
                        None,
                    )
                    current = new_headers[accept_idx][1].decode("latin-1").lower() if accept_idx is not None else ""
                    if "application/json" not in current or "text/event-stream" not in current:
                        canonical = (b"accept", b"application/json, text/event-stream")
                        if accept_idx is not None:
                            new_headers[accept_idx] = canonical
                        else:
                            new_headers.append(canonical)
                        scope = dict(scope)
                        scope["headers"] = new_headers
                # Validate IP before storing — reject spoofed/malformed values
                token = _mcp_client_ip_var.set(_mcp_safe_ip(ip))
                try:
                    await self.app(scope, receive, send)
                finally:
                    _mcp_client_ip_var.reset(token)
            else:
                await self.app(scope, receive, send)

    _mcp_starlette = _mcp_instance.streamable_http_app()
    _mcp_session_mgr = _mcp_instance.session_manager
    app.mount("/mcp", _MCPIPForwardMiddleware(_mcp_starlette))
except ImportError:
    logger.warning("MCP server not available (mcp package not installed)")

# --- AI Discovery endpoints ---


@app.get("/.well-known/mcp.json", include_in_schema=False)
@app.get("/.well-known/mcp-server.json", include_in_schema=False)
def mcp_server_card_alias():
    """Aliases for MCP discovery crawlers probing non-SEP-2127 paths (e.g. NotHumanSearch)."""
    return mcp_server_card()


@app.get("/.well-known/mcp/server-card.json", include_in_schema=False)
def mcp_server_card():
    """MCP server discovery card (draft spec)."""
    return {
        "$schema": "https://modelcontextprotocol.io/schemas/server-card.json",
        "version": "1.0",
        "protocolVersion": "2024-11-05",
        "serverInfo": {
            "name": "contrastapi",
            "title": "ContrastAPI \u2014 Security Intelligence",
            "description": (
                "Security intelligence MCP server with 29 tools: CVE lookup with EPSS/KEV "
                "enrichment, domain recon (DNS, WHOIS, SSL, subdomains, WAF), IP/ASN lookup, "
                "email/phone/username OSINT, IOC/threat intel, exploit search, tech "
                "fingerprinting, orchestrated audit + threat reports, bulk lookups, code "
                "security checks."
            ),
            "version": "1.0.0",
            "homepage": "https://github.com/UPinar/contrastapi",
            "repository": "https://github.com/UPinar/contrastapi",
        },
        "transport": [
            {
                "type": "streamable-http",
                "url": "https://api.contrastcyber.com/mcp/",
            }
        ],
        "capabilities": {
            "tools": True,
            "resources": False,
            "prompts": False,
        },
        "provider": {
            "name": "ContrastCyber",
            "url": "https://contrastcyber.com",
        },
        "auth": "none",
        "tools_count": 29,
        "documentation": "https://github.com/UPinar/contrastapi/blob/main/docs/ENDPOINTS.md",
    }


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


@app.get("/.well-known/glama.json", include_in_schema=False)
def glama_manifest():
    """Glama.ai MCP aggregator discovery manifest (served from /opt/contrastapi/glama.json)."""
    return FileResponse(
        "/opt/contrastapi/glama.json",
        media_type="application/json",
    )


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
  <url><loc>https://api.contrastcyber.com/quickstart</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>0.9</priority></url>
  <url><loc>https://api.contrastcyber.com/mcp-setup</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>0.9</priority></url>
  <url><loc>https://api.contrastcyber.com/cn/</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>
  <url><loc>https://api.contrastcyber.com/llms.txt</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>0.7</priority></url>
  <url><loc>https://api.contrastcyber.com/llms-full.txt</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>0.7</priority></url>
  <url><loc>https://api.contrastcyber.com/.well-known/mcp/server-card.json</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>0.6</priority></url>
</urlset>"""
    return Response(content=xml, media_type="application/xml")
