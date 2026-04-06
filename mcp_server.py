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
import logging
import os
import sys

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger("contrastapi-mcp")

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


def _headers() -> dict:
    h = {"Accept": "application/json"}
    if API_KEY:
        h["Authorization"] = f"Bearer {API_KEY}"
    # Forward real client IP so backend applies correct rate limits
    client_ip = _client_ip_var.get()
    if client_ip:
        h["X-Forwarded-For"] = client_ip
    return h


async def _get(path: str, params: dict | None = None) -> dict | str:
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"{API_BASE}{path}",
                params=params,
                timeout=TIMEOUT,
                headers=_headers(),
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            return f"Error {e.response.status_code}"
        except httpx.HTTPError as e:
            return f"Request failed: {e}"


async def _post(path: str, json_body: dict) -> dict | str:
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{API_BASE}{path}",
                json=json_body,
                timeout=TIMEOUT,
                headers=_headers(),
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            return f"Error {e.response.status_code}"
        except httpx.HTTPError as e:
            return f"Request failed: {e}"


def _fmt(data: dict | str) -> str:
    if isinstance(data, str):
        return data
    summary = data.get("summary", "")
    if summary:
        return summary
    import json

    return json.dumps(data, indent=2, default=str)[:8000]


# === Domain Intelligence ===


@mcp.tool()
async def domain_report(domain: str) -> str:
    """Full security report for a domain — DNS, WHOIS, SSL, subdomains, reputation, risk score.

    Args:
        domain: Target domain (e.g. example.com)
    """
    return _fmt(await _get(f"/v1/domain/{domain}"))


@mcp.tool()
async def dns_lookup(domain: str) -> str:
    """DNS records for a domain — A, AAAA, MX, NS, TXT, CNAME, SOA.

    Args:
        domain: Target domain
    """
    return _fmt(await _get(f"/v1/dns/{domain}"))


@mcp.tool()
async def whois_lookup(domain: str) -> str:
    """WHOIS registration data — registrar, creation date, expiry, nameservers.

    Args:
        domain: Target domain
    """
    return _fmt(await _get(f"/v1/whois/{domain}"))


@mcp.tool()
async def ssl_check(domain: str) -> str:
    """SSL/TLS certificate analysis — cipher suite, chain, expiry, grade.

    Args:
        domain: Target domain
    """
    return _fmt(await _get(f"/v1/ssl/{domain}"))


@mcp.tool()
async def subdomain_enum(domain: str) -> str:
    """Subdomain enumeration via DNS brute-force and certificate transparency.

    Args:
        domain: Target domain
    """
    return _fmt(await _get(f"/v1/subdomains/{domain}"))


@mcp.tool()
async def tech_fingerprint(domain: str) -> str:
    """Technology fingerprinting — CMS, frameworks, CDN, analytics, server.

    Args:
        domain: Target domain
    """
    return _fmt(await _get(f"/v1/tech/{domain}"))


@mcp.tool()
async def threat_intel(domain: str) -> str:
    """Threat intelligence for a domain — URLhaus malware URL check.

    Args:
        domain: Target domain
    """
    return _fmt(await _get(f"/v1/threat/{domain}"))


@mcp.tool()
async def wayback_lookup(domain: str) -> str:
    """Web archive history — snapshots from the Wayback Machine showing when a domain was first seen and how it changed over time.

    Args:
        domain: Target domain (e.g. example.com)
    """
    return _fmt(await _get(f"/v1/archive/{domain}"))


@mcp.tool()
async def scan_headers(domain: str) -> str:
    """Live HTTP security header scan — CSP, HSTS, X-Frame-Options, etc.

    Args:
        domain: Target domain
    """
    return _fmt(await _get(f"/v1/scan/headers/{domain}"))


@mcp.tool()
async def email_mx(domain: str) -> str:
    """Email MX analysis — mail provider detection, SPF/DMARC/DKIM check, security grade.

    Args:
        domain: Target domain (e.g. example.com)
    """
    return _fmt(await _get(f"/v1/email/mx/{domain}"))


@mcp.tool()
async def email_disposable(email: str) -> str:
    """Check if an email uses a disposable/temporary email provider.

    Args:
        email: Email address to check (e.g. user@tempmail.com)
    """
    from urllib.parse import quote

    return _fmt(await _get(f"/v1/email/disposable/{quote(email, safe='')}"))


@mcp.tool()
async def phone_lookup(number: str) -> str:
    """Phone number validation and intelligence — format, country, type, carrier, timezone.

    Args:
        number: Phone number with country code (e.g. +905551234567)
    """
    from urllib.parse import quote

    return _fmt(await _get(f"/v1/phone/{quote(number, safe='')}"))


# === IP Intelligence ===


@mcp.tool()
async def ip_lookup(ip: str) -> str:
    """IP intelligence — PTR, ports, hostnames, vulnerabilities, reputation.

    Args:
        ip: IPv4 or IPv6 address
    """
    return _fmt(await _get(f"/v1/ip/{ip}"))


@mcp.tool()
async def asn_lookup(target: str) -> str:
    """ASN lookup — AS number, holder, IPv4/IPv6 prefixes.

    Args:
        target: Domain or IP address
    """
    return _fmt(await _get(f"/v1/asn/{target}"))


# === CVE Intelligence ===


@mcp.tool()
async def cve_lookup(cve_id: str) -> str:
    """CVE details — description, CVSS, EPSS score, KEV status, affected products.

    Args:
        cve_id: CVE identifier (e.g. CVE-2024-1234)
    """
    return _fmt(await _get(f"/v1/cve/{cve_id}"))


@mcp.tool()
async def cve_search(product: str = "", severity: str = "", days: int = 30, limit: int = 10) -> str:
    """Search CVEs by product, severity, or date range.

    Args:
        product: Filter by product name (e.g. nginx, apache)
        severity: CRITICAL, HIGH, MEDIUM, or LOW
        days: CVEs from last N days (1-365, default 30)
        limit: Max results (default 10, max 200)
    """
    params = {"limit": limit, "days": days}
    if product:
        params["product"] = product
    if severity:
        params["severity"] = severity
    return _fmt(await _get("/v1/cves", params))


@mcp.tool()
async def exploit_lookup(cve_id: str) -> str:
    """Find public exploits for a CVE — GitHub Advisory, ExploitDB.

    Args:
        cve_id: CVE identifier
    """
    return _fmt(await _get(f"/v1/exploit/{cve_id}"))


# === Threat Intelligence / IOC ===


@mcp.tool()
async def ioc_lookup(indicator: str) -> str:
    """IOC enrichment — auto-detects IP, domain, URL, or file hash and queries ThreatFox/URLhaus/Feodo.

    Args:
        indicator: IP, domain, URL, or file hash (MD5/SHA1/SHA256)
    """
    return _fmt(await _get(f"/v1/ioc/{indicator}"))


@mcp.tool()
async def hash_lookup(file_hash: str) -> str:
    """Malware hash reputation via MalwareBazaar — family, file type, tags.

    Args:
        file_hash: MD5, SHA1, or SHA256 hash
    """
    return _fmt(await _get(f"/v1/hash/{file_hash}"))


@mcp.tool()
async def password_check(sha1_hash: str) -> str:
    """Check if a password has been exposed in data breaches via HIBP (k-anonymity, safe).

    Args:
        sha1_hash: Full SHA1 hash of the password (40 hexadecimal characters)
    """
    return _fmt(await _get(f"/v1/password/{sha1_hash}"))


@mcp.tool()
async def phishing_check(url: str) -> str:
    """Check if a URL is a known phishing/malware URL via URLhaus.

    Args:
        url: URL to check
    """
    return _fmt(await _get(f"/v1/phishing/{url}"))


# === Code Security ===


@mcp.tool()
async def check_secrets(code: str, language: str = "generic") -> str:
    """Detect hardcoded secrets in source code — AWS keys, tokens, passwords.

    Args:
        code: Source code to scan
        language: Programming language (python, javascript, go, etc.)
    """
    return _fmt(await _post("/v1/check/secrets", {"code": code, "language": language}))


@mcp.tool()
async def check_injection(code: str, language: str = "generic") -> str:
    """Detect SQL injection, command injection, and path traversal vulnerabilities.

    Args:
        code: Source code to scan
        language: Programming language
    """
    return _fmt(await _post("/v1/check/injection", {"code": code, "language": language}))


@mcp.tool()
async def check_headers(headers: str) -> str:
    """Validate HTTP security headers — CSP, HSTS, X-Frame-Options, etc.

    Args:
        headers: JSON string of header name-value pairs, e.g. {"Content-Security-Policy": "default-src 'self'"}
    """
    import json

    try:
        h = json.loads(headers)
    except json.JSONDecodeError:
        return "Invalid JSON. Provide headers as JSON object."
    return _fmt(await _post("/v1/check/headers", {"headers": h}))


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
