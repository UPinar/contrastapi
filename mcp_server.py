"""
ContrastAPI MCP Server — stdio + Streamable HTTP transport

Exposes ContrastAPI endpoints as MCP tools for Claude Code / Claude Desktop.
Calls the live API at api.contrastcyber.com (no local server needed).

Stdio usage (.mcp.json):
{
  "mcpServers": {
    "contrastapi": {
      "command": "python3",
      "args": ["/path/to/contrastapi/mcp_server.py"]
    }
  }
}

HTTP usage: POST https://api.contrastcyber.com/mcp
"""

import contextvars
import ipaddress
import json
import logging
import os
import re
from typing import Annotated
from urllib.parse import quote

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import Field

# Shared annotations — all tools are read-only API lookups
_RO = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)

logger = logging.getLogger("contrastapi.mcp")

# Carries the real client IP from MCP HTTP handler to internal API calls,
# so backend rate limiting sees the original IP instead of localhost.
_client_ip_var: contextvars.ContextVar[str] = contextvars.ContextVar("mcp_client_ip", default="")

mcp = FastMCP(
    "contrastapi",
    stateless_http=True,
    json_response=True,  # JSON instead of SSE — Cloudflare compatible
    # Mounted at /mcp in FastAPI — sub-app route must be "/"
    streamable_http_path="/",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,  # nginx handles this
    ),
)

# Use local API if running on the server, otherwise use public API
API_BASE = os.environ.get("CONTRASTAPI_URL", "http://localhost:8002")
API_KEY = os.environ.get("CONTRASTAPI_KEY", "")
TIMEOUT = 30.0

_LOG_SANITIZE = re.compile(
    r"/v1/(phone|email/mx|email/disposable|ip|domain|dns|whois|subdomains|certs|ssl|threat|tech|monitor|ioc|phishing|scan/headers|asn|password|archive|username|cve|cves|exploit|hash|epss)(?:/(lookup|search|leading|bulk|report))?/[^?]+",
    re.IGNORECASE,
)


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _safe_path(path: str) -> str:
    """Redact PII from API paths for safe logging."""
    safe = _CONTROL_CHARS.sub("", path)
    query_idx = safe.find("?")
    if query_idx >= 0:
        safe = safe[:query_idx]
    return _LOG_SANITIZE.sub(
        lambda m: (
            f"/v1/{m.group(1).lower()}/{m.group(2).lower()}/***" if m.group(2) else f"/v1/{m.group(1).lower()}/***"
        ),
        safe,
    )


def _safe_ip(ip: str) -> str:
    """Validate and sanitize client IP — reject spoofed/malformed values."""
    ip = _CONTROL_CHARS.sub("", ip).strip()
    if not ip:
        return ""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ""


def _headers() -> dict:
    h = {"Accept": "application/json"}
    if API_KEY:
        h["Authorization"] = f"Bearer {API_KEY}"
    # Forward real client IP so backend applies correct rate limits
    client_ip = _safe_ip(_client_ip_var.get())
    if client_ip:
        h["X-Forwarded-For"] = client_ip
    return h


_http_client: httpx.AsyncClient | None = None


def _get_client() -> httpx.AsyncClient:
    """Return a shared httpx client with connection pooling."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(base_url=API_BASE, timeout=TIMEOUT)
    return _http_client


def _log_ip() -> str:
    """Return sanitized client IP for logging."""
    return _safe_ip(_client_ip_var.get()) or "unknown"


def _format_error(response: httpx.Response) -> str:
    """Extract useful error fields from API JSON body; fall back to status code.

    Preserves detail so the AI agent sees *why* the call failed (rate-limit tier,
    validation field, upgrade CTA) instead of a bare `Error 429`.
    """
    status = response.status_code
    try:
        body = response.json()
    except (ValueError, json.JSONDecodeError):
        return f"Error {status}"
    if not isinstance(body, dict):
        return f"Error {status}"

    parts = [f"Error {status}"]
    msg = body.get("error") or body.get("detail") or body.get("message")
    if isinstance(msg, str) and msg:
        parts.append(f": {msg[:500]}")
    reason = body.get("reason")
    if isinstance(reason, str) and reason:
        parts.append(f" ({reason[:200]})")
    field = body.get("field")
    if isinstance(field, str) and field:
        parts.append(f" [field: {field}]")
    hint = body.get("hint") or body.get("suggestion") or body.get("upgrade")
    if isinstance(hint, str) and hint:
        parts.append(f" — {hint[:200]}")
    elif isinstance(hint, dict):
        msg = hint.get("message")
        if isinstance(msg, str) and msg:
            parts.append(f" — {msg[:200]}")
    return "".join(parts)


async def _get(path: str, params: dict | None = None) -> dict | str:
    client_ip = _log_ip()
    try:
        resp = await _get_client().get(path, params=params, headers=_headers())
        resp.raise_for_status()
        logger.info("mcp_tool GET %s %d %s", _safe_path(path), resp.status_code, client_ip)
        return resp.json()
    except httpx.HTTPStatusError as e:
        logger.info("mcp_tool GET %s %d %s", _safe_path(path), e.response.status_code, client_ip)
        return _format_error(e.response)
    except httpx.HTTPError:
        logger.info("mcp_tool GET %s err %s", _safe_path(path), client_ip)
        return "Request failed"


async def _post(path: str, json_body: dict) -> dict | str:
    client_ip = _log_ip()
    try:
        resp = await _get_client().post(path, json=json_body, headers=_headers())
        resp.raise_for_status()
        logger.info("mcp_tool POST %s %d %s", _safe_path(path), resp.status_code, client_ip)
        return resp.json()
    except httpx.HTTPStatusError as e:
        logger.info("mcp_tool POST %s %d %s", _safe_path(path), e.response.status_code, client_ip)
        return _format_error(e.response)
    except httpx.HTTPError:
        logger.info("mcp_tool POST %s err %s", _safe_path(path), client_ip)
        return "Request failed"


MAX_RESPONSE_CHARS = 8000


def _pro_only_hint(data: dict) -> str | None:
    """Detect pro_only enrichment stubs and return a user-facing upgrade hint.

    Fires when free-tier tool responses include the tier-gated stub for
    AbuseIPDB / Shodan enrichment. Handles two response shapes:
    - nested: data["reputation"]["abuseipdb"|"shodan"].status
    - flat (threat_report): data["abuseipdb"|"shodan"].status
    """
    if not isinstance(data, dict):
        return None
    gated = []
    rep = data.get("reputation")
    sources = [rep] if isinstance(rep, dict) else []
    sources.append(data)
    seen = set()
    for src in sources:
        for field in ("abuseipdb", "shodan"):
            if field in seen:
                continue
            val = src.get(field)
            if isinstance(val, dict) and val.get("status") == "pro_only":
                gated.append(field)
                seen.add(field)
    if not gated:
        return None
    names = " + ".join(f.title() if f != "abuseipdb" else "AbuseIPDB" for f in gated)
    return (
        f"⚠️  {names} enrichment requires a Pro API key. "
        f"Set CONTRASTAPI_API_KEY=cc_... (stdio) or Authorization: Bearer cc_... header (HTTP/SSE). "
        f"Get a key at https://contrastcyber.com/pricing ($7/mo) — or email contact@contrastcyber.com."
    )


def _fmt(data: dict | str) -> str:
    if isinstance(data, str):
        return data
    hint = _pro_only_hint(data) if isinstance(data, dict) else None
    suffix = f"\n\n{hint}" if hint else ""
    budget = MAX_RESPONSE_CHARS - len(suffix)
    summary = data.get("summary", "") if isinstance(data, dict) else ""
    if summary:
        detail_data = {k: v for k, v in data.items() if k != "summary"}
        detail = json.dumps(detail_data, indent=2, default=str)
        body = f"{summary}\n\n{detail}"[:budget]
    else:
        body = json.dumps(data, indent=2, default=str)[:budget]
    return body + suffix


# --- Input validation ---
_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


def _validate_domain(domain: str) -> str | None:
    """Return error message if domain is invalid, else None."""
    domain = domain.strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(domain):
        return f"Invalid domain format: {domain!r}. Expected format: example.com"
    return None


def _validate_ip(ip: str) -> str | None:
    """Return error message if IP is invalid, else None."""
    try:
        ipaddress.ip_address(ip.strip())
        return None
    except ValueError:
        return f"Invalid IP address: {ip!r}. Expected IPv4 (1.2.3.4) or IPv6."


def _validate_public_ip(ip: str) -> str | None:
    """Return error message if IP is invalid OR private/reserved, else None.

    Used by tools that hit external services (Shodan, AbuseIPDB) where private IPs
    are pointless and could enable SSRF-like probing. Defense-in-depth — backend
    also rejects private IPs, but failing fast at the MCP layer avoids wasted requests.
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return f"Invalid IP address: {ip!r}. Expected IPv4 (1.2.3.4) or IPv6."
    if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local or addr.is_multicast:
        return f"Private/reserved IP addresses are not allowed: {ip!r}"
    return None


def _validate_cve(cve_id: str) -> str | None:
    """Return error message if CVE ID is invalid, else None."""
    if not _CVE_RE.match(cve_id.strip()):
        return f"Invalid CVE ID: {cve_id!r}. Expected format: CVE-2024-1234"
    return None


_CWE_RE = re.compile(r"^(?:CWE[- ]?)?\d{1,6}$", re.IGNORECASE)


def _validate_cwe(cwe_id: str) -> str | None:
    """Return error message if CWE ID is invalid, else None.

    Server normalizes 'CWE-79', 'cwe-79', 'CWE 79', and bare '79' to canonical
    form, so accept any of those.
    """
    if not _CWE_RE.match((cwe_id or "").strip()):
        return f"Invalid CWE ID: {cwe_id!r}. Expected format: CWE-79 (or just '79')"
    return None


# === Domain Intelligence ===


@mcp.tool(annotations=_RO)
async def domain_report(
    domain: Annotated[
        str, Field(description="Root domain to analyze, without protocol or path (e.g. 'example.com', 'shopify.com')")
    ],
    include_all_txt: Annotated[
        bool,
        Field(
            description="Return every TXT record (default: False, only SPF/DMARC/DKIM/MTA-STS/TLS-RPT kept). dns.total_txt_records is always emitted with the honest pre-filter count. Default filter strips vendor verification strings (google-site-verification, ms=, facebook-domain-verification, etc.) that bloat the response without security signal. Set True only when you need the raw TXT inventory."
        ),
    ] = False,
) -> str:
    """Query DNS, WHOIS, SSL, subdomains, and threat intel for a domain in one call. By default dns.txt is filtered to security-relevant entries (SPF, DMARC, DKIM, MTA-STS, TLS-RPT) and dns.total_txt_records reports the honest pre-filter count; pass include_all_txt=true for the raw TXT list. Use as a starting point for domain investigations; use audit_domain for live headers + tech stack. Free: 100/hr, Pro: 1000/hr. Returns domain report with DNS records, WHOIS data, SSL cert, risk score, email config, threat status, and recommendation."""
    if err := _validate_domain(domain):
        return err
    params = {"include_all_txt": "true"} if include_all_txt else None
    return _fmt(await _get(f"/v1/domain/{domain}", params))


@mcp.tool(annotations=_RO)
async def audit_domain(
    domain: Annotated[
        str,
        Field(description="Root domain to audit, without protocol or path (e.g. 'example.com', 'shopify.com')"),
    ],
) -> str:
    """Perform comprehensive domain audit: combines domain_report + live HTTP security headers + technology fingerprinting. Use when you need the full picture (recon + active checks); use domain_report for passive-only assessment. Free: 100/hr (costs 4 credits), Pro: 1000/hr. Returns {domain, report, technologies, live_headers, summary}."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/audit/{domain}"))


@mcp.tool(annotations=_RO)
async def threat_report(
    ip: Annotated[
        str,
        Field(
            description="Public IPv4 or IPv6 address to investigate (e.g. '8.8.8.8', '1.1.1.1'). Private/reserved IPs are rejected."
        ),
    ],
) -> str:
    """Query comprehensive threat profile for an IP: Shodan host data, AbuseIPDB reputation, ASN/geolocation, and open ports. Use for IP investigation and SOC alert triage; for domain data use domain_report. Free: 100/hr (costs 4 credits), Pro: 1000/hr. Returns {ip, enrichment, abuseipdb, shodan, asn, threat_level}."""
    if err := _validate_public_ip(ip):
        return err
    return _fmt(await _get(f"/v1/threat-report/{ip}"))


@mcp.tool(annotations=_RO)
async def dns_lookup(
    domain: Annotated[
        str, Field(description="Root domain to query, without protocol or path (e.g. 'example.com', 'cloudflare.com')")
    ],
) -> str:
    """Query all DNS record types (A, AAAA, MX, NS, TXT, CNAME, SOA) for a domain. Use for mail routing inspection, nameserver verification, or SPF/DMARC checks; for full overview use domain_report. Free: 100/hr, Pro: 1000/hr. Returns {records: [{type, value, ttl}]} array."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/dns/{domain}"))


@mcp.tool(annotations=_RO)
async def whois_lookup(
    domain: Annotated[str, Field(description="Root domain to query WHOIS for (e.g. 'example.com', 'github.com')")],
) -> str:
    """Retrieve WHOIS registration data: registrar, registrant, creation/expiry dates, nameservers, DNSSEC status. Use to verify domain ownership, age, expiration; for full audit use domain_report. Free: 100/hr, Pro: 1000/hr. Returns {registrar, creation_date, expiration_date, updated_date, nameservers, status, dnssec}."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/whois/{domain}"))


@mcp.tool(annotations=_RO)
async def ssl_check(
    domain: Annotated[
        str, Field(description="Domain to check SSL/TLS certificate for (e.g. 'example.com', 'api.stripe.com')")
    ],
) -> str:
    """Analyze SSL/TLS certificate: grade (A-F), protocol version, cipher suite, chain, expiry, Subject Alternative Names. Use to audit certificate validity and detect expiring certs; for full domain audit use audit_domain. Free: 100/hr, Pro: 1000/hr. Returns {grade, protocol, cipher, issuer, subject, not_before, not_after, chain, san}."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/ssl/{domain}"))


@mcp.tool(annotations=_RO)
async def subdomain_enum(
    domain: Annotated[
        str, Field(description="Root domain to enumerate subdomains for (e.g. 'example.com', 'tesla.com')")
    ],
) -> str:
    """Discover subdomains using passive methods: Certificate Transparency logs + DNS brute-force (no active probing). Use to map organization's attack surface; non-intrusive. Free: 100/hr, Pro: 1000/hr. Returns {subdomains: [{hostname, resolved_ips}]}."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/subdomains/{domain}"))


@mcp.tool(annotations=_RO)
async def tech_fingerprint(
    domain: Annotated[str, Field(description="Domain to fingerprint (e.g. 'example.com', 'shopify.com')")],
) -> str:
    """Detect website technology stack: CMS, frameworks, CDN, analytics tools, web servers, languages (via HTTP headers + HTML analysis). Use for passive reconnaissance; for full audit use audit_domain. Free: 100/hr, Pro: 1000/hr. Returns {technologies: [{name, category, confidence%, version}]}."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/tech/{domain}"))


@mcp.tool(annotations=_RO)
async def threat_intel(
    domain: Annotated[
        str, Field(description="Domain to check for threats (e.g. 'suspicious-site.com', 'example.com')")
    ],
) -> str:
    """Check domain for known malware distribution, botnet C2, phishing activity via URLhaus + abuse.ch feeds. Use for threat assessment; use phishing_check for specific URLs. Free: 100/hr, Pro: 1000/hr. Returns {malware_urls, threat_tags, threat_status, summary}."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/threat/{domain}"))


@mcp.tool(annotations=_RO)
async def wayback_lookup(
    domain: Annotated[str, Field(description="Domain to look up in web archives (e.g. 'example.com', 'archive.org')")],
) -> str:
    """Retrieve Wayback Machine snapshots for a domain: first capture, latest, total count, yearly breakdown. Use to investigate domain history and age; for full audit use domain_report. Free: 100/hr, Pro: 1000/hr. Returns {first_snapshot, last_snapshot, total_snapshots, yearly_breakdown}."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/archive/{domain}"))


@mcp.tool(annotations=_RO)
async def scan_headers(
    domain: Annotated[
        str, Field(description="Domain to scan live HTTP headers for (e.g. 'example.com', 'api.github.com')")
    ],
) -> str:
    """Perform live HTTP GET and analyze security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy. Use to audit live website headers; use check_headers to validate headers you already have. Free: 100/hr, Pro: 1000/hr. Returns {headers_present, headers_missing, findings, total_score}."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/scan/headers/{domain}"))


@mcp.tool(annotations=_RO)
async def email_mx(
    domain: Annotated[
        str, Field(description="Domain to analyze email configuration for (e.g. 'example.com', 'google.com')")
    ],
) -> str:
    """Analyze email security: MX records, SPF policy, DMARC policy, DKIM selectors, mail provider ID, grade (A-F). Use to verify email authentication setup and phishing risk; for full audit use domain_report. Free: 100/hr, Pro: 1000/hr. Returns {mx_records, provider, spf, dmarc, dkim, grade}."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/email/mx/{domain}"))


@mcp.tool(annotations=_RO)
async def email_disposable(
    email: Annotated[
        str, Field(description="Full email address to check (e.g. 'user@tempmail.com', 'test@guerrillamail.com')")
    ],
) -> str:
    """Check if email address uses a known disposable/temporary provider (Guerrilla Mail, Temp Mail, Mailinator, etc.). Use for input validation to detect throwaway signups; for domain reputation use threat_intel. Free: 100/hr, Pro: 1000/hr. Returns {disposable, domain, provider}."""
    return _fmt(await _get(f"/v1/email/disposable/{quote(email, safe='')}"))


@mcp.tool(annotations=_RO)
async def phone_lookup(
    number: Annotated[
        str,
        Field(
            description="Phone number in E.164 format: + followed by country code and number, no spaces or dashes. Examples: '+14155552671' (US), '+905551234567' (TR), '+442071234567' (UK). Wrong: '0555-123-4567', '(415) 555-2671'"
        ),
    ],
) -> str:
    """Validate and analyze phone number: country, region, carrier, line type (mobile/landline/VoIP), timezone, formatted versions. Use to verify phone legitimacy and detect fraud risks. Requires E.164 format (+1234567890). Free: 100/hr, Pro: 1000/hr. Returns {valid, country, region, carrier, line_type, timezone, formats}."""
    return _fmt(await _get(f"/v1/phone/{quote(number, safe='')}"))


# === IP Intelligence ===


@mcp.tool(annotations=_RO)
async def ip_lookup(
    ip: Annotated[str, Field(description="IPv4 or IPv6 address to investigate (e.g. '8.8.8.8', '2606:4700::1111')")],
) -> str:
    """Query comprehensive IP intelligence: reverse DNS, ASN + holder name + country inline (RIPE Stat, Phase 1), open ports, hostnames, vulnerabilities (Shodan InternetDB), cloud provider, Tor exit status, and reputation. cloud_provider uses two-tier detection: published cloud CIDR ranges (AWS/GCP/Cloudflare) first, then an ASN-to-provider fallback map for anycast/public-service IPs outside published ranges (e.g. 8.8.8.8 → AS15169 → 'Google'). Reputation: FireHOL level1 blocklist on Free tier; +AbuseIPDB + Shodan on Pro (Phase 4). Use for IP investigation; for orchestrated IP+reputation use threat_report. Response is null-explicit: every field is always present (cloud_provider=null when neither tier matches; tor_exit=false when not listed or upstream fetch failed — check verdict.sources_unavailable to disambiguate fetch failure from genuine absence). Free: 100/hr, Pro: 1000/hr. Returns {ip, ptr, geo, asn, asn_name, country, ports, hostnames, vulns, cloud_provider, tor_exit, reputation, risk_score, verdict}."""
    if err := _validate_ip(ip):
        return err
    return _fmt(await _get(f"/v1/ip/{ip}"))


@mcp.tool(annotations=_RO)
async def asn_lookup(
    target: Annotated[
        str, Field(description="Domain or IP address to look up ASN for (e.g. 'cloudflare.com', '8.8.8.8')")
    ],
) -> str:
    """Look up Autonomous System Number (ASN) for a domain or IP: AS number, organization, IPv4/IPv6 prefixes. Use to identify network operator and IP range ownership. Free: 100/hr, Pro: 1000/hr. Returns {asn, holder, prefixes_v4, prefixes_v6}."""
    if _validate_domain(target) and _validate_ip(target):
        return f"Invalid input: {target!r}. Expected a domain (example.com) or IP address (8.8.8.8)."
    return _fmt(await _get(f"/v1/asn/{target}"))


# === CVE Intelligence ===


@mcp.tool(annotations=_RO)
async def cve_lookup(
    cve_id: Annotated[
        str, Field(description="CVE identifier in format CVE-YYYY-NNNNN (e.g. 'CVE-2024-3094', 'CVE-2023-44487')")
    ],
    include_affected_products: Annotated[
        bool,
        Field(
            description="Return the full affected_products list (default: False, returns first 20). Set True for bulk audits or dependency scanning of Log4j-class CVEs with 50+ products."
        ),
    ] = False,
    include_full_references: Annotated[
        bool,
        Field(
            description="Return the full references list (default: False, returns first 10). total_references is always emitted with the honest count; patch URL detection always runs against the full list, so patch_url/patch_available are unaffected by the cap. Set True only when you need the complete advisory URL set (older + high-profile CVEs accumulate 30-60+)."
        ),
    ] = False,
) -> str:
    """Retrieve detailed CVE data by ID: description, CVSS v3.1 + vector, EPSS score + percentile, CISA KEV status, affected products (CPE), references, patch availability, related CVEs. By default affected_products is truncated to the first 20 entries (total_products reports the honest count) and references to the first 10 (total_references reports the honest count). Pass include_affected_products=true and/or include_full_references=true for the complete lists (needed for bulk audits / dependency scanners; Log4j-class CVEs can carry 50+ products and 30+ refs). Use for single-CVE details; use cve_search for queries by product/severity. Response carries next_calls — chain with kev_detail when kev.in_kev=true for the CISA federal patch deadline + required action, with cwe_lookup on cwe_id for the weakness category, and with exploit_lookup for public PoC availability. Free: 100/hr, Pro: 1000/hr. Returns {cve_id, description, cvss_score, cvss_vector, epss, kev, affected_products (first 20 by default), total_products, references (first 10 by default), total_references, patch_available, related_cves, verdict, next_calls}."""
    if err := _validate_cve(cve_id):
        return err
    params = {}
    if include_affected_products:
        params["include_affected_products"] = "true"
    if include_full_references:
        params["include_full_references"] = "true"
    return _fmt(await _get(f"/v1/cve/{cve_id}", params=params or None))


@mcp.tool(annotations=_RO)
async def cve_search(
    product: Annotated[
        str,
        Field(
            description="Product or vendor name to filter by. EXACT match (case-insensitive) against the canonical product/vendor token stored in NVD CPE data — not a substring or fuzzy search. Use the short canonical name exactly as vendors publish it: 'nginx' (not 'nginx web server'), 'apache' (not 'Apache HTTP Server'), 'linux_kernel' (not 'Linux Kernel'), 'microsoft' (vendor). If unsure of the exact token, try the lowercase project name first; if 0 results, try the vendor name. Omit to search all products."
        ),
    ] = "",
    severity: Annotated[
        str,
        Field(
            description="CVSS severity level. Must be one of: CRITICAL, HIGH, MEDIUM, LOW. Omit for all severities.",
            json_schema_extra={"enum": ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"]},
        ),
    ] = "",
    published_after: Annotated[
        str,
        Field(
            description="Inclusive lower bound on publish date as YYYY-MM-DD (UTC). Pick this when the user names a starting point, e.g. 'since 2015' → '2015-01-01', 'after March 2024' → '2024-03-01'. Omit to not bound the lower edge. Combine with published_before for ranges."
        ),
    ] = "",
    published_before: Annotated[
        str,
        Field(
            description="Inclusive upper bound on publish date as YYYY-MM-DD (UTC). Pick this when the user names an ending point, e.g. 'before 2020' → '2019-12-31', 'up to 2023' → '2023-12-31'. Omit to not bound the upper edge. Combine with published_after for ranges."
        ),
    ] = "",
    kev: Annotated[
        bool,
        Field(
            description="If true, return only CVEs in the CISA Known Exploited Vulnerabilities (KEV) catalog — these are actively exploited in the wild."
        ),
    ] = False,
    epss_min: Annotated[
        float,
        Field(
            description="Minimum EPSS score filter (0.0-1.0). EPSS predicts exploitation probability. 0.5 = top ~5% most likely to be exploited. 0.0 = no filter.",
            ge=0.0,
            le=1.0,
        ),
    ] = 0.0,
    sort: Annotated[
        str,
        Field(
            description="Sort order for results. Must be one of: published_desc (newest first), epss_desc (most exploitable first), cvss_desc (most severe first). Omit for newest first.",
            json_schema_extra={"enum": ["", "published_desc", "epss_desc", "cvss_desc"]},
        ),
    ] = "",
    limit: Annotated[int, Field(description="Maximum results to return. Range: 1-200.", ge=1, le=200)] = 50,
    offset: Annotated[
        int, Field(description="Skip N results for pagination. Use with limit to page through results.", ge=0, le=5000)
    ] = 0,
    cwe_id: Annotated[
        str,
        Field(
            description="Filter by CWE weakness ID. Exact match, case-insensitive. Common values: CWE-79 (XSS), CWE-89 (SQL injection), CWE-120 (buffer overflow), CWE-78 (command injection). Format: CWE-<number>. Omit to not filter by CWE."
        ),
    ] = "",
    cvss_min: Annotated[
        float,
        Field(
            description="Minimum CVSS v3 base score (0.0-10.0). Default 0.0 = no filter (sentinel, not applied). Set > 0 to filter — CVEs with null CVSS are excluded when active. Use 7.0 for high+critical, 9.0 for critical only.",
            ge=0.0,
            le=10.0,
        ),
    ] = 0.0,
    cvss_max: Annotated[
        float,
        Field(
            description="Maximum CVSS v3 base score (0.0-10.0). Default 10.0 = no filter (sentinel, not applied). Set < 10.0 to filter — CVEs with null CVSS are excluded when active. Combine with cvss_min for a range.",
            ge=0.0,
            le=10.0,
        ),
    ] = 10.0,
    vendor: Annotated[
        str,
        Field(
            description="Filter by vendor name (case-insensitive). When combined with product, both must match the same CPE row — prevents cross-row false matches. Example: vendor=apache, product=struts."
        ),
    ] = "",
    include: Annotated[
        str,
        Field(
            description="Per-result detail level. Default (omit) returns slim list items (cve_id, summary, severity, cvss_v3, cwe_id, epss, kev, total_products, published, modified, sources, verdict). Pass 'full' to also return description, cvss_breakdown, affected_products, references, first_seen_source, first_seen_at — only do this when the user explicitly wants drill-down on every result. For single-CVE detail prefer cve_lookup; slim default keeps token cost ~70% lower on Log4j-class queries.",
            json_schema_extra={"enum": ["", "full"]},
        ),
    ] = "",
) -> str:
    """Search CVE database with filters: product/vendor, severity, published date range, EPSS score, CWE, CVSS range, CISA KEV status. Default response is SLIM per-result (cve_id, summary, severity, cvss_v3, cwe_id, epss, kev, total_products, published, modified, sources, verdict) — pass include='full' for description, cvss_breakdown, affected_products, references, first_seen_*. Use for vulnerability discovery by criteria; pass cwe_id (e.g. CWE-79) to enumerate every CVE in our database mapped to a weakness — pair with cwe_lookup for the category description and mitigations. Use cve_lookup for single CVE by ID, kev_detail when kev=true filtering and the agent needs federal patch deadlines per result. Free: 100/hr, Pro: 1000/hr. Returns {count, total, truncated, results, query_echo}."""
    params = {"limit": limit}
    if product:
        params["product"] = product
    if vendor:
        params["vendor"] = vendor
    if severity:
        params["severity"] = severity
    if published_after:
        params["published_after"] = published_after
    if published_before:
        params["published_before"] = published_before
    if kev:
        params["kev"] = "true"
    if epss_min > 0:
        params["epss_min"] = epss_min
    if sort:
        params["sort"] = sort
    if offset > 0:
        params["offset"] = offset
    if cwe_id:
        params["cwe_id"] = cwe_id
    if cvss_min > 0:
        params["cvss_min"] = cvss_min
    if cvss_max < 10.0:
        params["cvss_max"] = cvss_max
    if include:
        params["include"] = include
    return _fmt(await _get("/v1/cves", params))


@mcp.tool(annotations=_RO)
async def cve_leading(
    limit: Annotated[int, Field(description="Maximum results to return. Range: 1-200.", ge=1, le=200)] = 50,
    offset: Annotated[int, Field(description="Skip N results for pagination.", ge=0, le=5000)] = 0,
) -> str:
    """List CVEs indexed from MITRE/GHSA BEFORE NVD publication (early-warning, freshest data). Use for threat intelligence on emerging CVEs; use cve_search for published NVD data. Free: 100/hr, Pro: 1000/hr. Returns {count, total, results, sources, first_seen_source}."""
    params: dict = {"limit": limit}
    if offset > 0:
        params["offset"] = offset
    return _fmt(await _get("/v1/cve/leading", params))


@mcp.tool(annotations=_RO)
async def exploit_lookup(
    cve_id: Annotated[
        str, Field(description="CVE identifier in format CVE-YYYY-NNNNN (e.g. 'CVE-2024-3094', 'CVE-2023-44487')")
    ],
) -> str:
    """Search public exploits/PoC for a specific CVE across three sources: (1) GitHub Advisory Database (sources.github.advisories[]), (2) Shodan CVEDB references (sources.shodan_refs.results[] — packetstorm/seclists/vendor URLs cited by Shodan), (3) ExploitDB CSV mirror (exploits[] array, with edb_id + author + verified flag — these are the actual ExploitDB entries). Use to assess if a vulnerability has weaponized exploits in the wild; run after cve_lookup to evaluate real-world risk. When the CVE is also in CISA KEV (kev.in_kev=true on cve_lookup), pair with kev_detail for federal patch deadline; pair with cwe_lookup on cwe_id for the underlying weakness category and mitigations. Free: 100/hr, Pro: 1000/hr. Returns {cve_id, exploits_found, has_public_exploit, sources: {github, shodan_refs}, exploits: [{edb_id, cve_id, date_published, author, type, platform, url, verified, description}], verdict}."""
    if err := _validate_cve(cve_id):
        return err
    return _fmt(await _get(f"/v1/exploit/{cve_id}"))


@mcp.tool(annotations=_RO)
async def bulk_cve_lookup(
    cve_ids: Annotated[
        list[str],
        Field(
            description="List of CVE identifiers in format CVE-YYYY-NNNNN (e.g. ['CVE-2024-3094', 'CVE-2021-44228', 'CVE-2023-44487']). Maximum 10 per request for free tier, 50 for Pro."
        ),
    ],
    include_affected_products: Annotated[
        bool,
        Field(
            description="Return the full affected_products list for each CVE in the batch (default: False, each CVE returns first 20). Set True for bulk dependency audits."
        ),
    ] = False,
    include_full_references: Annotated[
        bool,
        Field(
            description="Return the full references list for each CVE in the batch (default: False, each CVE returns first 10). total_references is always emitted. Set True only when you need every advisory URL for every CVE in the batch."
        ),
    ] = False,
) -> str:
    """Batch query multiple CVEs (up to 10 free/50 pro): retrieve full CVE details for all in 1 request instead of N. By default each CVE's affected_products is truncated to the first 20 entries (total_products reports honest count) and references to the first 10 (total_references reports honest count); pass include_affected_products=true / include_full_references=true to return full lists. Use for dependency audits or bulk vulnerability enrichment; use cve_lookup for single CVE. Each successful item carries next_calls — chain with kev_detail (when kev.in_kev=true), cwe_lookup (when cwe_id is present), or exploit_lookup. Free: 100/hr (1 per item), Pro: 1000/hr. Returns {results, total, successful, failed, timed_out, partial, summary}."""
    if not isinstance(cve_ids, list) or not cve_ids:
        return "cve_ids must be a non-empty list"
    if not all(isinstance(cid, str) for cid in cve_ids):
        return "All cve_ids must be strings"
    body = {
        "cve_ids": cve_ids,
        "include_affected_products": include_affected_products,
        "include_full_references": include_full_references,
    }
    return _fmt(await _post("/v1/cves/bulk", body))


@mcp.tool(annotations=_RO)
async def kev_detail(
    cve_id: Annotated[
        str,
        Field(description="CVE identifier in format CVE-YYYY-NNNNN (e.g. 'CVE-2021-44228', 'CVE-2024-3094')"),
    ],
) -> str:
    """Look up CISA KEV (Known Exploited Vulnerabilities) full record for a CVE. Returns federal patch deadline (due_date), CISA-specified required_action remediation, known ransomware association, vendor/product, the CISA-given common name (e.g. 'Log4Shell'), and CISA-reported CWE list. Returns 404 when the CVE is not in the KEV catalog — use cve_lookup for non-KEV CVEs. Best follow-up after cve_lookup or cve_search(kev=true) when an in_kev=true CVE is identified; chain with cwe_lookup on each returned CWE to investigate the weakness category. Free: 100/hr, Pro: 1000/hr. Returns {cve_id, vendor_project, product, vulnerability_name, date_added, due_date, required_action, known_ransomware_use, notes, cwes, verdict, next_calls}."""
    if err := _validate_cve(cve_id):
        return err
    return _fmt(await _get(f"/v1/kev/{cve_id}"))


@mcp.tool(annotations=_RO)
async def cwe_lookup(
    cwe_id: Annotated[
        str,
        Field(
            description="CWE identifier — accepts 'CWE-79', 'cwe-79', or bare '79'. Common values: CWE-79 (XSS), CWE-89 (SQL injection), CWE-78 (command injection), CWE-502 (deserialization), CWE-22 (path traversal), CWE-120 (buffer overflow)."
        ),
    ],
) -> str:
    """Look up MITRE CWE (Common Weakness Enumeration) catalog record from research view 1000. Returns description, abstract type (Pillar/Class/Base/Variant/Compound), status (Stable/Draft/Incomplete/Deprecated), exploit likelihood, recommended mitigations, observed example CVEs, parent_cwe (walk up the hierarchy), child_cwes (drill down to more specific weaknesses), and cve_count (LOWER BOUND — counts only CVEs whose primary CWE matches; CVEs with multiple CWEs may not be counted). Use after cve_lookup or kev_detail to understand the underlying weakness category; chain with cve_search(cwe_id=...) to enumerate all matching CVEs. Returns 404 when the CWE is not in research view 1000. Free: 100/hr, Pro: 1000/hr. Returns {cwe_id, name, description, extended_description, abstract_type, status, likelihood, mitigations, examples, parent_cwe, child_cwes, cve_count, updated_at, verdict, next_calls}."""
    if err := _validate_cwe(cwe_id):
        return err
    return _fmt(await _get(f"/v1/cwe/{cwe_id}"))


# === Threat Intelligence / IOC ===


@mcp.tool(annotations=_RO)
async def ioc_lookup(
    indicator: Annotated[
        str,
        Field(
            description="Indicator of Compromise: IP address, domain, full URL, or file hash in MD5/SHA1/SHA256 format (e.g. '8.8.8.8', 'evil.com', 'https://evil.com/malware.exe', 'd41d8cd98f00b204e9800998ecf8427e')"
        ),
    ],
) -> str:
    """Enrich Indicator of Compromise (IP/domain/URL/hash) by auto-detecting type and querying abuse.ch feeds (ThreatFox, URLhaus, Feodo). Use as primary IOC triage tool when type unknown; use threat_intel for domain-only, hash_lookup for hash-only. Free: 100/hr, Pro: 1000/hr. Returns {indicator, type, found, threat_type, malware_family, tags, confidence, source}."""
    return _fmt(await _get(f"/v1/ioc/{quote(indicator, safe='')}"))


@mcp.tool(annotations=_RO)
async def hash_lookup(
    file_hash: Annotated[
        str,
        Field(
            description="File hash to look up. Accepts MD5 (32 chars), SHA-1 (40 chars), or SHA-256 (64 chars). Lowercase hex only, no spaces. Example: 'd41d8cd98f00b204e9800998ecf8427e'"
        ),
    ],
) -> str:
    """Query MalwareBazaar for file hash (MD5/SHA1/SHA256): malware family, file type, size, tags, first/last seen, download count. Use to check if file hash is known malware; use ioc_lookup for auto-detection of all IOC types. Free: 100/hr, Pro: 1000/hr. Returns {found, malware_family, file_type, file_size, tags, first_seen, last_seen, signature}."""
    if not _HASH_RE.match(file_hash.strip()):
        return "Invalid hash format. Expected MD5 (32), SHA-1 (40), or SHA-256 (64) hex characters."
    return _fmt(await _get(f"/v1/hash/{file_hash}"))


@mcp.tool(annotations=_RO)
async def password_check(
    sha1_hash: Annotated[
        str,
        Field(
            description="Full SHA-1 hash of the password as 40 lowercase hexadecimal characters (e.g. '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' for 'password')"
        ),
    ],
) -> str:
    """Check if SHA-1 hash appears in Have I Been Pwned (HIBP) breach dataset using k-anonymity (5-char prefix only, full hash never leaves tool). Use for password breach audits; read-only, no data stored. Free: 100/hr, Pro: 1000/hr. Returns {found, count}."""
    if not re.match(r"^[a-fA-F0-9]{40}$", sha1_hash.strip()):
        return "Invalid SHA-1 hash. Expected exactly 40 hexadecimal characters."
    return _fmt(await _get(f"/v1/password/{sha1_hash}"))


@mcp.tool(annotations=_RO)
async def phishing_check(
    url: Annotated[
        str,
        Field(
            description="Full URL to check, including protocol (e.g. 'https://suspicious-login.com/verify', 'http://evil.com/payload.exe')"
        ),
    ],
) -> str:
    """Query URLhaus for specific URL: detect if it's a known phishing page or malware distribution site, online/offline status, tags, date added. Use for URL-level threat assessment; use threat_intel for domain-level checks. Free: 100/hr, Pro: 1000/hr. Returns {found, threat_type, status, tags, date_added, source}."""
    return _fmt(await _get(f"/v1/phishing/{quote(url, safe='')}"))


@mcp.tool(annotations=_RO)
async def bulk_ioc_lookup(
    indicators: Annotated[
        list[str],
        Field(
            description="List of indicators of compromise: IP addresses, domains, URLs, or file hashes (e.g. ['8.8.8.8', 'evil.com', 'd41d8cd98f00b204e9800998ecf8427e']). Maximum 10 per request for free tier, 50 for Pro. Each indicator type is auto-detected."
        ),
    ],
) -> str:
    """Batch query multiple IOCs (IP/domain/URL/hash, up to 10 free/50 pro) in 1 request: auto-detects type + queries abuse.ch feeds. Use for SOC alert triage or batch enrichment; use ioc_lookup for single indicator. Free: 100/hr (1 per item), Pro: 1000/hr. Returns {results, total, successful, failed, timed_out, partial, summary}."""
    if not isinstance(indicators, list) or not indicators:
        return "indicators must be a non-empty list"
    return _fmt(await _post("/v1/iocs/bulk", {"indicators": indicators}))


# === Code Security ===


@mcp.tool(annotations=_RO)
async def check_secrets(
    code: Annotated[
        str,
        Field(description="Source code string to scan for secrets (can be a single file or code snippet)"),
    ],
    language: Annotated[
        str,
        Field(
            description="Programming language of the code. Must be one of: python, javascript, typescript, java, go, ruby, shell, bash, generic. Use 'generic' if unsure.",
            json_schema_extra={
                "enum": ["python", "javascript", "typescript", "java", "go", "ruby", "shell", "bash", "generic"]
            },
        ),
    ] = "generic",
) -> str:
    """Scan source code (or snippet) for hardcoded secrets: AWS keys, API tokens, connection strings, private keys, passwords. Supports Python, JavaScript, TypeScript, Java, Go, Ruby, Shell, Bash. Use to detect leaked credentials before commit; for injection detection use check_injection. Free: 100/hr, Pro: 1000/hr. Returns {total, by_severity, findings}. No data stored."""
    return _fmt(await _post("/v1/check/secrets", {"code": code, "language": language}))


@mcp.tool(annotations=_RO)
async def check_injection(
    code: Annotated[
        str,
        Field(
            description="Source code string to scan for injection vulnerabilities (can be a single file or code snippet)"
        ),
    ],
    language: Annotated[
        str,
        Field(
            description="Programming language of the code. Must be one of: python, javascript, typescript, java, go, ruby, shell, bash, generic. Use 'generic' if unsure.",
            json_schema_extra={
                "enum": ["python", "javascript", "typescript", "java", "go", "ruby", "shell", "bash", "generic"]
            },
        ),
    ] = "generic",
) -> str:
    """Scan source code for injection vulnerabilities: SQL injection, command injection, path traversal via unsafe string concatenation/unsanitized input. Supports Python, JavaScript, TypeScript, Java, Go, Ruby, Shell, Bash. Use to detect input-handling bugs; for secrets use check_secrets. Free: 100/hr, Pro: 1000/hr. Returns {total, by_severity, findings}. No data stored."""
    return _fmt(await _post("/v1/check/injection", {"code": code, "language": language}))


@mcp.tool(annotations=_RO)
async def check_dependencies(
    packages: Annotated[
        list[dict],
        Field(
            description="List of dependency packages to audit. Each item is an object with 'name' (required, max 200 chars, e.g. 'lodash', 'django', 'log4j-core') and optional 'version' (max 100 chars, e.g. '4.17.0', '2.14.1'). Only 'name' and 'version' fields are used; extra fields are ignored. Example: [{\"name\": \"lodash\", \"version\": \"4.17.0\"}, {\"name\": \"django\"}]. Maximum 10 per request for free tier, 50 for Pro."
        ),
    ],
) -> str:
    """Audit project dependencies (npm/PyPI/Maven/RubyGems/etc.) against CVE database: find known vulnerabilities in your package list. Bulk query up to 10 free/50 pro packages. Use for dependency security scanning; use cve_lookup for single CVE. Free: 100/hr (1 per package), Pro: 1000/hr. Returns {findings, total, by_severity, summary}."""
    if not isinstance(packages, list) or not packages:
        return "packages must be a non-empty list"
    if len(packages) > 50:
        return "Too many packages. Maximum 50 per request (Pro tier) or 10 (free tier)."
    for pkg in packages:
        if not isinstance(pkg, dict):
            return f'Each package must be an object like {{"name": "lodash", "version": "4.17.0"}}, got: {type(pkg).__name__}'
        name = pkg.get("name")
        if not isinstance(name, str) or not name.strip():
            return "Each package must have a non-empty 'name' string field"
        if len(name) > 200:
            return "'name' must be at most 200 characters"
        version = pkg.get("version")
        if version is not None and not isinstance(version, str):
            return f"'version' must be a string or null, got: {type(version).__name__}"
        if isinstance(version, str) and len(version) > 100:
            return "'version' must be at most 100 characters"
    return _fmt(await _post("/v1/check/dependencies", {"packages": packages}))


@mcp.tool(annotations=_RO)
async def username_lookup(
    username: Annotated[
        str,
        Field(
            description="Username string to search across platforms, without @ prefix (e.g. 'torvalds', 'johndoe', 'elonmusk')"
        ),
    ],
) -> str:
    """Search for username across 15+ social/dev platforms (GitHub, Reddit, X/Twitter, LinkedIn, Instagram, TikTok, Discord, YouTube, Keybase, HackerOne, etc.). Use for OSINT investigations and identity verification. Free: 100/hr, Pro: 1000/hr. Returns {username, total_found, platforms: [{name, exists, url, status_code}]}."""
    return _fmt(await _get(f"/v1/username/{quote(username, safe='')}"))


@mcp.tool(annotations=_RO)
async def check_headers(
    headers: Annotated[
        str,
        Field(
            description='JSON string of HTTP header name-value pairs to validate. Example: \'{"Strict-Transport-Security": "max-age=31536000", "X-Frame-Options": "DENY"}\'. Include only security-relevant headers you want to analyze.'
        ),
    ],
) -> str:
    """Validate HTTP security headers you provide (JSON): CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy against best practices. Use to test header config before deployment or validate non-public servers; use scan_headers to fetch live. Free: 100/hr, Pro: 1000/hr. Returns {total, by_severity, findings}. No external requests."""
    try:
        h = json.loads(headers)
    except json.JSONDecodeError:
        return "Invalid JSON. Provide headers as JSON object."
    return _fmt(await _post("/v1/check/headers", {"headers": h}))


# === Prompts ===


@mcp.prompt()
def security_audit(domain: Annotated[str, Field(description="Target domain to audit")]) -> str:
    """Run a full security audit on a domain — combines domain report, SSL, headers, and threat intel."""
    return f"""Perform a comprehensive security audit for {domain}:

1. Run domain_report for full overview
2. Run ssl_check for certificate details
3. Run scan_headers for HTTP security headers
4. Run threat_intel for malware/threat checks
5. Run email_mx for email security (SPF/DMARC/DKIM)

Summarize findings with severity ratings and actionable recommendations."""


@mcp.prompt()
def vulnerability_check(
    product: Annotated[str, Field(description="Product name to check (e.g. nginx, apache)")],
) -> str:
    """Check recent vulnerabilities and exploits for a product."""
    return f"""Check vulnerabilities for {product}:

1. Run cve_search with product="{product}" and published_after set to 90 days ago (YYYY-MM-DD)
2. For any CRITICAL or HIGH CVEs found, run exploit_lookup to check for public exploits
3. Summarize: total CVEs, severity breakdown, exploitable ones, and patch recommendations."""


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
