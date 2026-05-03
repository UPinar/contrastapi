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
import uuid
from pathlib import Path
from typing import Annotated

from auth import AuthCtx, require_auth
from config import (
    ATLAS_CASE_STUDY_COUNT,
    ATLAS_TECHNIQUE_COUNT,
    BASE_DIR,
    D3FEND_DEFENSE_COUNT,
    ENDPOINT_COUNT,
    FREE_HOURLY_LIMIT,
    MCP_PROMPT_COUNT,
    MCP_RESOURCE_COUNT,
    MCP_TOOL_COUNT,
    PRO_HOURLY_LIMIT,
    TARGET_THROTTLE_PER_MIN,
    TEST_COUNT,
    UPGRADE_URL,
    VERSION,
    settings,
)
from db import (
    get_and_clear_pending_key,
    get_key_by_order_id,
    get_sync_status,
    get_total_requests,
    has_pending_key,
    hash_client_ip,
)
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from ratelimit import check_limit
from validation import get_client_ip

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
from core.templates import templates

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
from core.metrics import metrics as _metrics
from core.metrics import metrics_lock as _metrics_lock
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


# --- Landing page ---


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def landing_page(request: Request):
    total = get_total_requests()
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "total_requests": total,
            "tool_count": MCP_TOOL_COUNT,
            "resource_count": MCP_RESOURCE_COUNT,
            "prompt_count": MCP_PROMPT_COUNT,
            "endpoint_count": ENDPOINT_COUNT,
            "test_count": TEST_COUNT,
            "atlas_technique_count": ATLAS_TECHNIQUE_COUNT,
            "atlas_case_study_count": ATLAS_CASE_STUDY_COUNT,
            "d3fend_defense_count": D3FEND_DEFENSE_COUNT,
        },
    )


@app.get("/bot", response_class=HTMLResponse, include_in_schema=False)
def bot_landing(request: Request):
    response = templates.TemplateResponse(
        request,
        "bot.html",
        {
            "version": VERSION,
            "throttle_per_min": TARGET_THROTTLE_PER_MIN,
        },
    )
    response.headers["Cache-Control"] = "no-store, must-revalidate"
    return response


@app.get("/cn/", response_class=HTMLResponse, include_in_schema=False)
@app.get("/cn", response_class=HTMLResponse, include_in_schema=False)
def landing_page_cn(request: Request):
    total = get_total_requests()
    return templates.TemplateResponse(
        request,
        "index_cn.html",
        {
            "total_requests": total,
            "tool_count": MCP_TOOL_COUNT,
            "resource_count": MCP_RESOURCE_COUNT,
            "prompt_count": MCP_PROMPT_COUNT,
            "endpoint_count": ENDPOINT_COUNT,
            "test_count": TEST_COUNT,
            "atlas_technique_count": ATLAS_TECHNIQUE_COUNT,
            "atlas_case_study_count": ATLAS_CASE_STUDY_COUNT,
            "d3fend_defense_count": D3FEND_DEFENSE_COUNT,
        },
    )


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
    if not check_limit("welcome", hash_client_ip(client_ip), max_requests=5, window_seconds=60):
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
    if not check_limit("check_key", hash_client_ip(client_ip), max_requests=10, window_seconds=60):
        raise HTTPException(status_code=429, detail="Too many requests")

    return {"ready": has_pending_key(order_id)}


@app.get("/quickstart", response_class=HTMLResponse, include_in_schema=False)
def quickstart(request: Request):
    return templates.TemplateResponse(
        request,
        "quickstart.html",
        {
            "tool_count": MCP_TOOL_COUNT,
            "resource_count": MCP_RESOURCE_COUNT,
            "prompt_count": MCP_PROMPT_COUNT,
        },
    )


@app.get("/mcp-setup", response_class=HTMLResponse, include_in_schema=False)
def mcp_setup(request: Request):
    return templates.TemplateResponse(
        request,
        "mcp_setup.html",
        {
            "tool_count": MCP_TOOL_COUNT,
            "resource_count": MCP_RESOURCE_COUNT,
            "prompt_count": MCP_PROMPT_COUNT,
        },
    )


@app.get("/playground", response_class=HTMLResponse, include_in_schema=False)
def playground(request: Request):
    return templates.TemplateResponse(
        request,
        "playground.html",
        {
            "atlas_technique_count": ATLAS_TECHNIQUE_COUNT,
            "atlas_case_study_count": ATLAS_CASE_STUDY_COUNT,
            "d3fend_defense_count": D3FEND_DEFENSE_COUNT,
        },
    )


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
    if settings.testing:
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
def api_usage(auth: Annotated[AuthCtx, Depends(require_auth("/v1/usage"))]):
    """Usage statistics for API key holders."""
    from db import get_key_usage_stats

    if auth.tier != "pro" or not auth.key_hash:
        raise HTTPException(status_code=401, detail="API key required. Pass Authorization: Bearer cc_xxx")

    stats = get_key_usage_stats(auth.key_hash)
    stats["hourly_limit"] = PRO_HOURLY_LIMIT
    stats["hourly_remaining"] = max(0, PRO_HOURLY_LIMIT - stats["last_1h"])
    return stats


@app.get("/v1/privacy/my-data", operation_id="privacy_my_data", tags=["Meta"])
def privacy_my_data(auth: Annotated[AuthCtx, Depends(require_auth("/v1/privacy/my-data"))]):
    """Return everything this API has stored about you. GDPR-style transparency.

    Shows the hashed IP, Pro key record (if any), and last-24h endpoint usage.
    The raw domains, IPs, CVEs, hashes, or code you submitted are NEVER stored —
    path parameters are stripped before any DB write (see db.normalize_endpoint).
    """
    from db import get_privacy_data

    data = get_privacy_data(auth.client_ip, auth.key_hash)

    tier = auth.tier
    limit = PRO_HOURLY_LIMIT if tier == "pro" else FREE_HOURLY_LIMIT
    remaining = auth.ratelimit_remaining

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
    """Machine-readable catalog of all MCP tools and REST endpoints."""
    return {
        "schema_version": "1.0",
        "api_version": VERSION,
        "base_url": "https://api.contrastcyber.com",
        "total_tools": MCP_TOOL_COUNT,
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
        "upgrade_signal": {
            "header": "X-Upgrade-URL",
            "emitted_when": "Only on HTTP 429 responses for free-tier clients",
            "value": UPGRADE_URL,
        },
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
                        "name": "cve_leading",
                        "method": "GET",
                        "path": "/v1/cve/leading",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "CVEs indexed from MITRE/GHSA before NVD — early-warning feed",
                        "params": {"limit": "int", "offset": "int"},
                        "response_keys": ["count", "total", "summary", "results"],
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
                    {
                        "name": "kev_detail",
                        "method": "GET",
                        "path": "/v1/kev/{cve_id}",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "CISA KEV detail: federal patch deadline, required action, ransomware association, CWE list",
                        "response_keys": [
                            "cve_id",
                            "vendor_project",
                            "product",
                            "vulnerability_name",
                            "due_date",
                            "required_action",
                            "known_ransomware_use",
                            "cwes",
                            "next_calls",
                        ],
                    },
                    {
                        "name": "cwe_lookup",
                        "method": "GET",
                        "path": "/v1/cwe/{cwe_id}",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "MITRE CWE catalog (research view 1000): description, mitigations, parent/child weakness chain, CVE count",
                        "response_keys": [
                            "cwe_id",
                            "name",
                            "description",
                            "abstract_type",
                            "mitigations",
                            "parent_cwe",
                            "child_cwes",
                            "cve_count",
                            "next_calls",
                        ],
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
                        "name": "email_verify",
                        "method": "GET",
                        "path": "/v1/email/verify/{email}",
                        "credit_cost": 1,
                        "blast_radius": "low",
                        "description": "Combined email validation: syntax + MX + disposable + role + free-provider (NO SMTP probe)",
                        "response_keys": [
                            "email",
                            "domain",
                            "syntax_valid",
                            "mx_records",
                            "disposable",
                            "disposable_provider",
                            "role_address",
                            "role_type",
                            "free_provider",
                            "summary",
                        ],
                    },
                    {
                        "name": "robots_txt",
                        "method": "GET",
                        "path": "/v1/robots/{domain}",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "Fetch + parse target domain's robots.txt (sitemaps, per-UA rules, crawl-delay)",
                        "response_keys": [
                            "domain",
                            "fetched_url",
                            "status_code",
                            "sitemaps",
                            "user_agents",
                            "host",
                            "truncated",
                            "summary",
                        ],
                    },
                    {
                        "name": "redirect_chain",
                        "method": "GET",
                        "path": "/v1/redirect/{url:path}",
                        "credit_cost": 1,
                        "blast_radius": "low",
                        "description": "Walk a URL's HTTP redirect chain hop-by-hop (deobfuscate URL shorteners, trace tracking redirects)",
                        "response_keys": [
                            "start_url",
                            "final_url",
                            "hops",
                            "hop_count",
                            "final_status",
                            "loop_detected",
                            "truncated",
                            "summary",
                        ],
                    },
                    {
                        "name": "brand_assets",
                        "method": "GET",
                        "path": "/v1/brand/{domain}",
                        "credit_cost": 2,
                        "blast_radius": "low",
                        "description": "Scrape a domain's homepage <head> for public brand assets (favicon, og:image, theme-color, og:site_name, JSON-LD logo). Honours robots.txt — Disallow: / returns 403 robots_txt_disallow.",
                        "response_keys": [
                            "domain",
                            "fetched_url",
                            "status_code",
                            "favicon_url_untrusted",
                            "og_image_url_untrusted",
                            "theme_color",
                            "site_name_untrusted",
                            "logo_url_untrusted",
                            "cache_respected",
                            "summary",
                        ],
                    },
                    {
                        "name": "seo_audit",
                        "method": "GET",
                        "path": "/v1/seo/{domain}",
                        "credit_cost": 2,
                        "blast_radius": "low",
                        "description": "One-page SEO audit of a domain's homepage with a 0-100 composite score (10 rules: title, meta description, H1, canonical, OG tags, JSON-LD, alt coverage, HTTPS). Honours robots.txt.",
                        "response_keys": [
                            "domain",
                            "fetched_url",
                            "status_code",
                            "title_untrusted",
                            "meta_description_untrusted",
                            "canonical_url",
                            "h1_untrusted",
                            "h1_count",
                            "h2_count",
                            "h3_count",
                            "images_total",
                            "images_missing_alt",
                            "internal_link_count",
                            "external_link_count",
                            "og_tags",
                            "json_ld_present",
                            "score",
                            "missing_signals",
                            "cache_respected",
                            "summary",
                        ],
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
                        "description": "Username OSINT across 16 platforms (3-39 chars). Retries on rate-limit/block; check verdict.sources_unavailable for platforms that couldn't be reached.",
                        "response_keys": ["username", "found_count", "checked_count", "results", "summary", "verdict"],
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
                        "name": "check_dependencies",
                        "method": "POST",
                        "path": "/v1/check/dependencies",
                        "credit_cost": 1,
                        "credit_cost_note": "1 credit per package in request",
                        "blast_radius": "zero",
                        "description": "Check packages against CVE database",
                        "body": {"packages": "list[{name: str, version: str}] (max 10 free, 50 pro)"},
                        "response_keys": ["findings", "total", "by_severity", "summary"],
                    },
                ],
            },
            "d3fend": {
                "description": "MITRE D3FEND — defense technique catalog mapped to ATT&CK (149 defenses, ~3k mappings)",
                "tools": [
                    {
                        "name": "d3fend_defense_lookup",
                        "method": "GET",
                        "path": "/v1/d3fend/{defense_id}",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "Lookup D3FEND defense by slug (e.g. TokenBinding) — returns tactic, artifact, mapped ATT&CK T-codes",
                        "response_keys": [
                            "defense_id",
                            "label",
                            "uri",
                            "parent_label",
                            "tactic",
                            "artifact",
                            "attack_techniques",
                            "next_calls",
                        ],
                    },
                    {
                        "name": "d3fend_defense_search",
                        "method": "GET",
                        "path": "/v1/d3fend/defenses",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "Search D3FEND defenses by keyword, tactic, or targeted artifact",
                        "response_keys": ["query", "total", "results", "next_calls"],
                    },
                    {
                        "name": "d3fend_defense_for_attack",
                        "method": "GET",
                        "path": "/v1/d3fend/attack/{attack_technique_id}",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "Reverse lookup: given an ATT&CK T-code, return all D3FEND defenses that mitigate it",
                        "response_keys": [
                            "attack_technique_id",
                            "total",
                            "defenses",
                            "coverage_by_tactic",
                            "next_calls",
                        ],
                    },
                    {
                        "name": "d3fend_attack_coverage",
                        "method": "POST",
                        "path": "/v1/d3fend/coverage",
                        "credit_cost": 1,
                        "credit_cost_note": "1 credit per request (not per T-code)",
                        "blast_radius": "zero",
                        "description": "Batch coverage breakdown: count defenses per tactic + identify undefended ATT&CK techniques",
                        "body": {"attack_technique_ids": "list[str] (max 500)"},
                        "response_keys": [
                            "queried_techniques",
                            "coverage_by_tactic",
                            "defended_techniques",
                            "undefended_techniques",
                            "next_calls",
                        ],
                    },
                ],
            },
            "atlas": {
                "description": "MITRE ATLAS — AI/ML adversarial attack catalog (techniques + case studies)",
                "tools": [
                    {
                        "name": "atlas_technique_lookup",
                        "method": "GET",
                        "path": "/v1/atlas/{technique_id}",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "Lookup ATLAS technique by id (AML.T#### or AML.T####.###)",
                        "response_keys": [
                            "technique_id",
                            "name",
                            "description",
                            "tactics",
                            "maturity",
                            "attack_reference_id",
                            "next_calls",
                        ],
                    },
                    {
                        "name": "atlas_technique_search",
                        "method": "GET",
                        "path": "/v1/atlas/techniques",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "Search ATLAS technique catalog by keyword, tactic, or maturity",
                        "response_keys": ["query", "total", "results", "next_calls"],
                    },
                    {
                        "name": "bulk_atlas_technique_lookup",
                        "method": "POST",
                        "path": "/v1/atlas/techniques/bulk",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "Bulk lookup up to 50 ATLAS technique ids in one request (drill case study techniques_used in one call)",
                        "response_keys": [
                            "results",
                            "total",
                            "successful",
                            "failed",
                            "partial",
                            "summary",
                        ],
                    },
                    {
                        "name": "atlas_case_study_lookup",
                        "method": "GET",
                        "path": "/v1/atlas/case-studies/{case_study_id}",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "Lookup ATLAS case study (real-world AI/ML incident) by id",
                        "response_keys": [
                            "case_study_id",
                            "name",
                            "description",
                            "techniques_used",
                            "next_calls",
                        ],
                    },
                    {
                        "name": "atlas_case_study_search",
                        "method": "GET",
                        "path": "/v1/atlas/case-studies",
                        "credit_cost": 1,
                        "blast_radius": "zero",
                        "description": "Search ATLAS case studies by keyword or referenced technique",
                        "response_keys": ["query", "total", "results", "next_calls"],
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
def llms_txt(request: Request):
    """LLM discovery file — concise version for quick context."""
    return templates.TemplateResponse(
        request,
        "llms.txt.j2",
        {"MCP_TOOL_COUNT": MCP_TOOL_COUNT},
        media_type="text/plain; charset=utf-8",
    )


@app.get("/llms-full.txt", response_class=PlainTextResponse, include_in_schema=False)
def llms_full_txt(request: Request):
    """Full API reference for LLM context."""
    return templates.TemplateResponse(
        request,
        "llms-full.txt.j2",
        {"MCP_TOOL_COUNT": MCP_TOOL_COUNT},
        media_type="text/plain; charset=utf-8",
    )


# /v1 aggregator (cve, domain, codesec, ioc, atlas, d3fend)
from api.main import api_router
from crypto_billing import router as crypto_billing_router
from webhooks import router as webhooks_router

app.include_router(api_router)
app.include_router(webhooks_router)
app.include_router(crypto_billing_router)


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
            "tools_count": MCP_TOOL_COUNT,
            "docs": "https://github.com/UPinar/contrastapi/blob/main/docs/ENDPOINTS.md",
            "setup_guide": "https://api.contrastcyber.com/mcp-setup",
        }
    )


# --- MCP Streamable HTTP endpoint ---
mcp_proxy.init_mcp(app)

# --- AI Discovery endpoints ---


# Rate-limit: nginx `api` zone (global limit_req); no FastAPI-layer guard.
@app.get("/mcp.json", include_in_schema=False)
@app.get("/.well-known/mcp.json", include_in_schema=False)
@app.get("/.well-known/mcp-server.json", include_in_schema=False)
def mcp_server_card_alias():
    """Aliases for MCP discovery crawlers probing non-SEP-2127 paths (e.g. NotHumanSearch, TacaraBot, AgentSEO)."""
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
                f"Security intelligence MCP server with {MCP_TOOL_COUNT} tools: CVE lookup with EPSS/KEV "
                "enrichment, domain recon (DNS, WHOIS, SSL, subdomains, WAF), IP/ASN lookup, "
                "email/phone/username OSINT, IOC/threat intel, exploit search, tech "
                "fingerprinting, orchestrated audit + threat reports, bulk lookups, code "
                "security checks."
            ),
            "version": VERSION,
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
        "tools_count": MCP_TOOL_COUNT,
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
        "contact_email": "contact@contrastcyber.com",
        "legal_info_url": "https://contrastcyber.com",
    }


@app.get("/.well-known/glama.json", include_in_schema=False)
def glama_manifest():
    """Glama.ai MCP aggregator discovery manifest (served from /opt/contrastapi/glama.json)."""
    return FileResponse(
        "/opt/contrastapi/glama.json",
        media_type="application/json",
    )


# --- OAuth discovery stubs (RFC 9728 / RFC 8414) ---
# MCP SDKs (undici, TypeScript, Python) probe these paths per session.
# ContrastAPI uses custom Bearer cc_* tokens, not OAuth. Empty
# authorization_servers signals "Bearer optional, no OAuth server".

_OAUTH_PROTECTED_RESOURCE_METADATA = {
    "resource": "https://api.contrastcyber.com",
    "authorization_servers": [],
    "bearer_methods_supported": ["header"],
    "scopes_supported": [],
}


@app.get("/.well-known/oauth-protected-resource", include_in_schema=False)
@app.get("/.well-known/oauth-protected-resource/mcp", include_in_schema=False)
def oauth_protected_resource():
    """RFC 9728 — auth_servers=[] signals OAuth not required."""
    return _OAUTH_PROTECTED_RESOURCE_METADATA


@app.get("/.well-known/oauth-authorization-server", include_in_schema=False)
def oauth_authorization_server():
    """No OAuth server; structured 404 per RFC 8414 absence."""
    return JSONResponse(
        status_code=404,
        content={
            "error": "not_found",
            "error_description": "no OAuth authorization server",
        },
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
