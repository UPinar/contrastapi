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
            f"/v1/{m.group(1).lower()}/{m.group(2).lower()}/***"
            if m.group(2)
            else f"/v1/{m.group(1).lower()}/***"
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


def _fmt(data: dict | str) -> str:
    if isinstance(data, str):
        return data
    summary = data.get("summary", "") if isinstance(data, dict) else ""
    if summary:
        detail_data = {k: v for k, v in data.items() if k != "summary"}
        detail = json.dumps(detail_data, indent=2, default=str)
        return f"{summary}\n\n{detail}"[:MAX_RESPONSE_CHARS]
    return json.dumps(data, indent=2, default=str)[:MAX_RESPONSE_CHARS]


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


# === Domain Intelligence ===


@mcp.tool(annotations=_RO)
async def domain_report(
    domain: Annotated[
        str, Field(description="Root domain to analyze, without protocol or path (e.g. 'example.com', 'shopify.com')")
    ],
) -> str:
    """Comprehensive domain security report combining DNS, WHOIS, SSL/TLS, subdomain discovery, email security, WAF detection, and threat reputation in a single call. Use this as the first step when investigating a domain; for deeper analysis of a specific area, follow up with the dedicated tool (ssl_check, dns_lookup, email_mx, threat_intel, etc.). Returns JSON with fields: domain, dns, reverse_dns, whois, ssl, subdomains, certificates (CT log entries), email_security (SPF/DMARC/DKIM with grade), waf (detected vendors), threat (URLhaus malware status), risk (nested: score 0-100, max_score, grade A-F, factors list with per-component breakdown), risk_score (top-level integer alias = risk.score, for backward-compat with old consumers), reputation (abuseipdb, shodan; omitted in lite mode, when IP unavailable, or when daily IP enrichment quota is exhausted), summary, and verdict (data quality metadata — includes sources_queried, sources_unavailable listing sources skipped in lite mode or, in full mode, URLhaus when its fetch errors, and completeness). Append ?lite=true to skip WHOIS, subdomains, CT logs, URLhaus, and reputation for ~10x faster response (~250ms) — use when polling or when only DNS/SSL/email/WAF needed. Read-only lookup, no authentication required."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/domain/{domain}"))


@mcp.tool(annotations=_RO)
async def audit_domain(
    domain: Annotated[
        str,
        Field(description="Root domain to audit, without protocol or path (e.g. 'example.com', 'shopify.com')"),
    ],
) -> str:
    """Comprehensive domain audit in a single call — combines a full domain report (DNS, WHOIS, SSL, subdomains, WAF, threat intel, risk score), live HTTP security headers, and technology stack fingerprinting. Use this when you want a complete picture of a target without making multiple requests. For investigations that need only one aspect (e.g. just DNS or just SSL), use the dedicated tool instead. Returns JSON with fields: domain, report (full domain intel), technologies (detected tech stack with categories and count), live_headers (HTTP response headers from the live site), and a combined summary. Read-only orchestrated lookup, no authentication required."""
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
    """Comprehensive IP threat report in a single call — combines Shodan InternetDB enrichment (open ports, hostnames, vulnerabilities, CPEs), AbuseIPDB reputation (abuse score, country, ISP), full Shodan lookup (organization, OS, geolocation), and ASN ownership (AS number, prefix). Use this for SOC triage and threat hunting when you need a complete IP profile without making 4+ separate requests. Returns JSON with fields: ip, enrichment, abuseipdb, shodan, asn, threat_level (none/low/medium/high), and a summary. Read-only orchestrated lookup, no authentication required."""
    if err := _validate_public_ip(ip):
        return err
    return _fmt(await _get(f"/v1/threat-report/{ip}"))


@mcp.tool(annotations=_RO)
async def dns_lookup(
    domain: Annotated[
        str, Field(description="Root domain to query, without protocol or path (e.g. 'example.com', 'cloudflare.com')")
    ],
) -> str:
    """Retrieve all DNS records for a domain including A, AAAA, MX, NS, TXT, CNAME, and SOA record types. Use this when you need to inspect mail routing (MX), verify nameserver delegation (NS), check SPF/DMARC policies (TXT), or confirm IP resolution (A/AAAA). For a broader security overview that includes DNS, use domain_report instead. Returns JSON with a records array, each containing type, value, and TTL fields. Read-only DNS query, no authentication required."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/dns/{domain}"))


@mcp.tool(annotations=_RO)
async def whois_lookup(
    domain: Annotated[str, Field(description="Root domain to query WHOIS for (e.g. 'example.com', 'github.com')")],
) -> str:
    """Retrieve WHOIS registration data for a domain including registrar name, registrant organization, creation date, expiry date, last updated date, and authoritative nameservers. Use this to determine domain ownership, age, or expiration status. For a full security overview that includes WHOIS, use domain_report instead. Returns JSON with fields: registrar, creation_date, expiration_date, updated_date, nameservers, status, and dnssec. Read-only WHOIS query, no authentication required."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/whois/{domain}"))


@mcp.tool(annotations=_RO)
async def ssl_check(
    domain: Annotated[
        str, Field(description="Domain to check SSL/TLS certificate for (e.g. 'example.com', 'api.stripe.com')")
    ],
) -> str:
    """Analyze the SSL/TLS certificate and connection security of a domain by connecting to port 443 and inspecting the certificate chain, cipher suite, protocol version, and expiry date. Use this to verify certificate validity, detect expiring certificates, or audit TLS configuration strength. Returns JSON with fields: grade (A-F), protocol, cipher, issuer, subject, not_before, not_after, chain (array of certificates), and san (Subject Alternative Names). Read-only TLS handshake, no authentication required."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/ssl/{domain}"))


@mcp.tool(annotations=_RO)
async def subdomain_enum(
    domain: Annotated[
        str, Field(description="Root domain to enumerate subdomains for (e.g. 'example.com', 'tesla.com')")
    ],
) -> str:
    """Discover subdomains of a domain using passive methods: Certificate Transparency log searches and DNS common-name brute-forcing. Use this to map an organization's attack surface or find forgotten/exposed services. This is a passive, non-intrusive enumeration — it does not actively probe discovered hosts. Returns JSON with a subdomains array of discovered hostnames and their resolved IP addresses. Read-only lookup, no authentication required."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/subdomains/{domain}"))


@mcp.tool(annotations=_RO)
async def tech_fingerprint(
    domain: Annotated[str, Field(description="Domain to fingerprint (e.g. 'example.com', 'shopify.com')")],
) -> str:
    """Identify the technology stack of a website by analyzing HTTP headers, HTML meta tags, and JavaScript includes. Detects CMS (WordPress, Drupal), frameworks (React, Angular), CDN providers (Cloudflare, Akamai), analytics tools, web servers, and programming languages. Use this for reconnaissance to understand what software a target runs. Returns JSON with a technologies array, each containing name, category, confidence percentage, and version (when detectable). Read-only HTTP request, no authentication required."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/tech/{domain}"))


@mcp.tool(annotations=_RO)
async def threat_intel(
    domain: Annotated[
        str, Field(description="Domain to check for threats (e.g. 'suspicious-site.com', 'example.com')")
    ],
) -> str:
    """Check if a domain is associated with malware distribution, botnet C2, or other malicious activity by querying URLhaus and abuse.ch threat feeds. Use this to assess whether a domain is safe to visit or interact with. For checking a specific URL (not just domain), use phishing_check instead. For file-based IOC lookups, use ioc_lookup. Returns JSON with fields: malware_urls (count of active malicious URLs), threat_tags, threat_status, and a summary assessment. Read-only threat feed query, no authentication required."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/threat/{domain}"))


@mcp.tool(annotations=_RO)
async def wayback_lookup(
    domain: Annotated[str, Field(description="Domain to look up in web archives (e.g. 'example.com', 'archive.org')")],
) -> str:
    """Retrieve historical web archive snapshots for a domain from the Wayback Machine, showing when the site was first captured, the most recent snapshot, and total snapshot count over time. Use this to investigate domain history, verify how long a site has existed, or detect changes in content over time. For a broader security overview of a domain, use domain_report instead. Returns JSON with fields: first_snapshot (date + URL), last_snapshot (date + URL), total_snapshots, and a yearly_breakdown of capture counts. Read-only query to the Internet Archive API, no authentication required."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/archive/{domain}"))


@mcp.tool(annotations=_RO)
async def scan_headers(
    domain: Annotated[
        str, Field(description="Domain to scan live HTTP headers for (e.g. 'example.com', 'api.github.com')")
    ],
) -> str:
    """Perform a live HTTP request to a domain and analyze the security headers in the response, checking for Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, and Referrer-Policy. Use this to audit a live website's header configuration. Unlike check_headers (which validates headers you already have), this tool fetches headers directly from the target. Returns JSON with fields: headers_present (list), headers_missing (list), findings (array with severity and recommendation per header), and a total score. Read-only HTTP GET request to the target domain, no authentication required."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/scan/headers/{domain}"))


@mcp.tool(annotations=_RO)
async def email_mx(
    domain: Annotated[
        str, Field(description="Domain to analyze email configuration for (e.g. 'example.com', 'google.com')")
    ],
) -> str:
    """Analyze the email security configuration of a domain by checking MX records, SPF policy, DMARC policy, and DKIM selectors. Identifies the mail provider (Google Workspace, Microsoft 365, etc.) and grades the overall email security posture. Use this to verify email authentication setup or assess phishing risk for a domain. Returns JSON with fields: mx_records, provider, spf (record + validity), dmarc (record + policy), dkim (selector results), and grade (A-F with 0-100 score). Read-only DNS queries, no authentication required."""
    if err := _validate_domain(domain):
        return err
    return _fmt(await _get(f"/v1/email/mx/{domain}"))


@mcp.tool(annotations=_RO)
async def email_disposable(
    email: Annotated[
        str, Field(description="Full email address to check (e.g. 'user@tempmail.com', 'test@guerrillamail.com')")
    ],
) -> str:
    """Check whether an email address uses a known disposable or temporary email provider (e.g. Guerrilla Mail, Temp Mail, Mailinator). Use this for input validation to detect throwaway signups or to assess the legitimacy of a contact email. Returns JSON with fields: disposable (boolean), domain, and provider (name of the disposable service if detected). Read-only lookup against a local database of disposable domains, no authentication required."""
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
    """Validate and analyze a phone number to determine its country, region, carrier, line type (mobile/landline/VoIP), and timezone. Use this to verify phone number legitimacy, identify the carrier or country of origin, or detect VoIP numbers that may indicate fraud. The number must include the country code prefix. Returns JSON with fields: valid (boolean), country, region, carrier, line_type, timezone, and formatted versions (national, international, E.164). Read-only lookup, no authentication required."""
    return _fmt(await _get(f"/v1/phone/{quote(number, safe='')}"))


# === IP Intelligence ===


@mcp.tool(annotations=_RO)
async def ip_lookup(
    ip: Annotated[str, Field(description="IPv4 or IPv6 address to investigate (e.g. '8.8.8.8', '2606:4700::1111')")],
) -> str:
    """Retrieve comprehensive intelligence about an IP address including geolocation, PTR record, open ports, associated hostnames, known vulnerabilities, abuse reports, and reputation score. Use this to investigate suspicious IPs from logs, identify the owner of an IP, or assess whether an IP is malicious. For network-level info (ASN, IP ranges), use asn_lookup instead. Returns JSON with fields: ip, ptr, geo (country, city, org), ports (array), hostnames, vulns (array), reputation (score + categories), abuse_contacts. Also returns: cloud_provider (AWS/GCP/Cloudflare; omitted if not a known cloud range), tor_exit: true if IP is a Tor exit node (omitted when not), risk_score (0-100 composite — higher = riskier; always present). Read-only lookup, no authentication required."""
    if err := _validate_ip(ip):
        return err
    return _fmt(await _get(f"/v1/ip/{ip}"))


@mcp.tool(annotations=_RO)
async def asn_lookup(
    target: Annotated[
        str, Field(description="Domain or IP address to look up ASN for (e.g. 'cloudflare.com', '8.8.8.8')")
    ],
) -> str:
    """Look up the Autonomous System Number (ASN) for a domain or IP address, returning the AS number, organization name, and all announced IPv4/IPv6 prefixes. Use this to identify which network operator owns an IP range, or to understand the network infrastructure behind a domain. For detailed IP-level intelligence (ports, reputation), use ip_lookup instead. Returns JSON with fields: asn (number), holder (organization name), prefixes_v4 (array of CIDR blocks), and prefixes_v6. Read-only lookup, no authentication required."""
    if _validate_domain(target) and _validate_ip(target):
        return f"Invalid input: {target!r}. Expected a domain (example.com) or IP address (8.8.8.8)."
    return _fmt(await _get(f"/v1/asn/{target}"))


# === CVE Intelligence ===


@mcp.tool(annotations=_RO)
async def cve_lookup(
    cve_id: Annotated[
        str, Field(description="CVE identifier in format CVE-YYYY-NNNNN (e.g. 'CVE-2024-3094', 'CVE-2023-44487')")
    ],
) -> str:
    """Retrieve detailed information about a specific CVE vulnerability including description, CVSS v3.1 base score and vector, EPSS exploitation probability score, CISA KEV (Known Exploited Vulnerabilities) status, affected products (CPE), and reference URLs. Use this when you have a specific CVE ID and need full details. To search for CVEs by product or severity, use cve_search instead. To find public exploits for a CVE, use exploit_lookup. Returns JSON with fields: cve_id, description, cvss_score, cvss_vector, cvss_breakdown, epss (score + percentile), kev (boolean + due_date), affected_products, and references. Read-only database lookup, no authentication required."""
    if err := _validate_cve(cve_id):
        return err
    return _fmt(await _get(f"/v1/cve/{cve_id}"))


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
        bool, Field(description="If true, return only CVEs in the CISA Known Exploited Vulnerabilities (KEV) catalog — these are actively exploited in the wild.")
    ] = False,
    epss_min: Annotated[
        float, Field(description="Minimum EPSS score filter (0.0-1.0). EPSS predicts exploitation probability. 0.5 = top ~5% most likely to be exploited. 0.0 = no filter.", ge=0.0, le=1.0)
    ] = 0.0,
    sort: Annotated[
        str,
        Field(
            description="Sort order for results. Must be one of: published_desc (newest first), epss_desc (most exploitable first), cvss_desc (most severe first). Omit for newest first.",
            json_schema_extra={"enum": ["", "published_desc", "epss_desc", "cvss_desc"]},
        ),
    ] = "",
    limit: Annotated[int, Field(description="Maximum results to return. Range: 1-200.", ge=1, le=200)] = 50,
    offset: Annotated[int, Field(description="Skip N results for pagination. Use with limit to page through results.", ge=0, le=5000)] = 0,
    cwe_id: Annotated[
        str,
        Field(
            description="Filter by CWE weakness ID. Exact match, case-insensitive. Common values: CWE-79 (XSS), CWE-89 (SQL injection), CWE-120 (buffer overflow), CWE-78 (command injection). Format: CWE-<number>. Omit to not filter by CWE."
        ),
    ] = "",
    cvss_min: Annotated[
        float, Field(description="Minimum CVSS v3 base score (0.0-10.0). Default 0.0 = no filter (sentinel, not applied). Set > 0 to filter — CVEs with null CVSS are excluded when active. Use 7.0 for high+critical, 9.0 for critical only.", ge=0.0, le=10.0)
    ] = 0.0,
    cvss_max: Annotated[
        float, Field(description="Maximum CVSS v3 base score (0.0-10.0). Default 10.0 = no filter (sentinel, not applied). Set < 10.0 to filter — CVEs with null CVSS are excluded when active. Combine with cvss_min for a range.", ge=0.0, le=10.0)
    ] = 10.0,
    vendor: Annotated[
        str,
        Field(
            description="Filter by vendor name (case-insensitive). When combined with product, both must match the same CPE row — prevents cross-row false matches. Example: vendor=apache, product=struts."
        ),
    ] = "",
) -> str:
    """Search the CVE database with filters. Returns matching vulnerabilities with CVSS scores, EPSS exploit probability, and KEV status.

Common queries:
- Critical CVEs this week: severity=CRITICAL, published_after=<today-7d>
- Actively exploited: kev=true
- Most exploitable nginx CVEs: product=nginx, sort=epss_desc
- Old nginx CVEs (2015-2018): product=nginx, published_after=2015-01-01, published_before=2018-12-31
- High-risk CVEs (EPSS>50%): epss_min=0.5, sort=epss_desc
- XSS CVEs: cwe_id=CWE-79
- High-severity range: cvss_min=7.0, cvss_max=9.0

Returns: count (returned), total (matching), truncated (true = more pages available),
next_offset (auto-computed — use as offset for next page, null if last page),
query_echo (echo of parameters you sent), results array.
Default limit is 50 (max 200). For a specific CVE ID, use cve_lookup instead."""
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
    return _fmt(await _get("/v1/cves", params))


@mcp.tool(annotations=_RO)
async def cve_leading(
    limit: Annotated[int, Field(description="Maximum results to return. Range: 1-200.", ge=1, le=200)] = 50,
    offset: Annotated[int, Field(description="Skip N results for pagination.", ge=0, le=5000)] = 0,
) -> str:
    """List CVEs that ContrastAPI indexed from MITRE/GHSA BEFORE NVD has published them. These are early-warning vulnerabilities — we have the data, NVD doesn't yet. Use this to find the freshest, most actionable CVEs that other tools miss. Returns the same format as cve_search: count, total, truncated, offset, results array. Each result includes sources and first_seen_source fields showing which upstream (mitre/ghsa) first reported it."""
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
    """Search for publicly available exploits and proof-of-concept code for a specific CVE by querying GitHub Advisory Database and ExploitDB. Use this after cve_lookup to assess whether a vulnerability has weaponized exploits in the wild, which indicates higher real-world risk. Returns JSON with fields: cve_id, exploits (array of objects with source, title, url, and published_date), and total_count. An empty exploits array means no public exploits were found. Read-only lookup, no authentication required."""
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
) -> str:
    """Look up multiple CVEs in a single request — efficient for vulnerability scanning, dependency audits, and threat intelligence pipelines that need to enrich many CVE IDs at once. Each CVE returns full details (severity, CVSS breakdown, EPSS score, KEV status, description, references). Use bulk_cve_lookup instead of calling cve_lookup repeatedly when you have a list of 5+ CVEs to check. Invalid CVE IDs are returned per-item with status='invalid_format' rather than failing the whole batch. For a single CVE, use cve_lookup. Returns JSON with fields: results (array with per-item status), total, successful, failed, timed_out, partial, and summary. Read-only database lookup, free tier allows 10 IDs per request, Pro allows 50."""
    if not isinstance(cve_ids, list) or not cve_ids:
        return "cve_ids must be a non-empty list"
    if not all(isinstance(cid, str) for cid in cve_ids):
        return "All cve_ids must be strings"
    return _fmt(await _post("/v1/cves/bulk", {"cve_ids": cve_ids}))


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
    """Enrich an Indicator of Compromise (IOC) by auto-detecting its type (IP, domain, URL, or file hash) and querying abuse.ch threat feeds: ThreatFox for malware indicators, URLhaus for malicious URLs, and Feodo for botnet C2 servers. Use this as the primary tool for threat hunting when you have a suspicious indicator but don't know its type. For malware-specific hash lookups with file metadata, use hash_lookup instead. For domain-only threat checks, use threat_intel. Returns JSON with fields: indicator, type (auto-detected), found (boolean), threat_type, malware_family, tags, confidence, source, and references. Read-only threat feed query, no authentication required."""
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
    """Look up a file hash in the MalwareBazaar database to check if it is a known malware sample. Returns malware family name, file type, file size, tags, first/last seen dates, and download count. Use this when you have a suspicious file hash from logs, alerts, or forensic analysis and need to determine if it is malicious. For general IOC lookups that auto-detect indicator type, use ioc_lookup instead. Returns JSON with fields: found (boolean), malware_family, file_type, file_size, tags, first_seen, last_seen, and signature. Read-only database query, no authentication required."""
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
    """Check if a SHA-1 hash appears in the Have I Been Pwned (HIBP) breach dataset using k-anonymity (only a 5-character prefix is sent to HIBP, the full hash never leaves this tool). This is a read-only lookup — no data is stored, no files are accessed, no system state is modified. Input must be a 40-char hex SHA-1 digest. Returns JSON with fields: found (boolean) and count (number of breach appearances). A count of 0 means the hash has not been seen in any known breaches."""
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
    """Check if a specific URL is a known phishing page or malware distribution URL by querying the URLhaus database. Use this when you have a full URL (not just a domain) that you suspect may be malicious — for example, from a phishing email or suspicious link. For domain-level threat assessment, use threat_intel instead. For general IOC enrichment, use ioc_lookup. Returns JSON with fields: found (boolean), threat_type (phishing/malware/none), status (online/offline), tags, date_added, and source. Read-only database query, no authentication required."""
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
    """Enrich multiple Indicators of Compromise in a single request — auto-detects each indicator type (IP/domain/URL/hash) and queries threat feeds (ThreatFox, URLhaus, Feodo) in parallel. Use this for SOC alert triage, threat hunting, or batch enrichment when you have many suspicious indicators to investigate at once. For a single indicator, use ioc_lookup. Returns JSON with fields: results (array with indicator, type, threat_level, sources), total, successful, failed, timed_out, partial (true if some indicators hit the overall timeout), and summary. Read-only threat feed query, free tier allows 10 indicators per request, Pro allows 50."""
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
            json_schema_extra={"enum": ["python", "javascript", "typescript", "java", "go", "ruby", "shell", "bash", "generic"]},
        ),
    ] = "generic",
) -> str:
    """Scan code for hardcoded secrets (AWS keys, API tokens, connection strings, private keys).

Examples: pass a Python file to find leaked AWS_SECRET_ACCESS_KEY, or a .env snippet to find exposed tokens.

Returns: total (count), by_severity (CRITICAL/HIGH/MEDIUM/LOW), findings array. Read-only, code is not stored. For injection detection, use check_injection instead."""
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
            json_schema_extra={"enum": ["python", "javascript", "typescript", "java", "go", "ruby", "shell", "bash", "generic"]},
        ),
    ] = "generic",
) -> str:
    """Scan code for injection vulnerabilities: SQL injection, command injection, and path traversal.

Detects unsafe patterns like string concatenation in SQL queries, unsanitized input in shell commands, and user input in file paths.

Returns: total (count), by_severity (CRITICAL/HIGH/MEDIUM/LOW), findings array. Read-only, code is not stored. For hardcoded secrets, use check_secrets instead."""
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
    """Audit a list of project dependencies (npm/PyPI/Maven/RubyGems/etc.) against the CVE database for known vulnerabilities.

Use this to scan a requirements.txt, package.json, pom.xml, or Gemfile.lock when you want to check many packages at once. For a single vulnerability by ID, use cve_lookup. For searching CVEs by product without version, use cve_search.

Returns JSON with fields: findings (array — each with package name, version, cve_id, severity, cvss_score, description), total (count of vulnerable packages), by_severity (CRITICAL/HIGH/MEDIUM/LOW counts), summary (human-readable one-line digest). An empty findings array means no known CVEs match the provided packages+versions. Read-only lookup, no authentication required."""
    if not isinstance(packages, list) or not packages:
        return "packages must be a non-empty list"
    if len(packages) > 50:
        return "Too many packages. Maximum 50 per request (Pro tier) or 10 (free tier)."
    for pkg in packages:
        if not isinstance(pkg, dict):
            return f"Each package must be an object like {{\"name\": \"lodash\", \"version\": \"4.17.0\"}}, got: {type(pkg).__name__}"
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
    """Search for a username across multiple social media and developer platforms (GitHub, Reddit, X/Twitter, Instagram, LinkedIn, TikTok, Facebook, YouTube, Pinterest, Telegram, Discord, Mastodon, Keybase, HackerOne, GitLab, Medium) to check if accounts exist. Use this for OSINT investigations to map a person's online presence or verify identity claims. Returns JSON with fields: username, total_found (count), and platforms (array of objects with name, exists (boolean), url, and status_code). Read-only HTTP checks to public profile pages, no authentication required."""
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
    """Validate a set of HTTP security headers that you already have (e.g. copied from browser DevTools, a curl response, or an existing configuration). Checks Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, and Referrer-Policy against security best practices. Unlike scan_headers (which fetches headers live from a domain), this tool analyzes headers you provide directly — useful for testing configurations before deployment or validating headers from non-public servers. Returns JSON with fields: total (finding count), by_severity (counts), and findings (array with severity, header_name, issue, and recommendation). Read-only validation, no external requests made."""
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
