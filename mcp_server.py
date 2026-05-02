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
import functools
import ipaddress
import json
import logging
import os
import pathlib
import re
import sys
from typing import Annotated, Literal
from urllib.parse import quote

# v1.22.1 — when main.py loads this file via importlib.util.spec_from_file_location,
# the spec loader does NOT add the parent directory to sys.path the way `python
# mcp_server.py` would. Without this, `from app.exceptions import ...` below
# raises ModuleNotFoundError, main.py silently catches it, and the MCP route is
# never mounted (production /mcp/ → 404). Adding the repo root explicitly makes
# the `app.*` package importable in BOTH execution contexts (pytest + spec load).
_REPO_ROOT = str(pathlib.Path(__file__).parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import httpx  # noqa: E402  (must follow sys.path patch above)
from mcp.server.fastmcp import FastMCP  # noqa: E402
from mcp.server.transport_security import TransportSecuritySettings  # noqa: E402
from mcp.types import ToolAnnotations  # noqa: E402
from pydantic import Field, ValidationError  # noqa: E402

from app.exceptions import (  # noqa: E402
    AppException,
    AuthRequiredException,
    InvalidArgumentException,
    InvalidCveIdException,
    InvalidDomainException,
    InvalidHashException,
    InvalidIpException,
    NotFoundException,
    RateLimitExceededException,
    TierLimitException,
    UpstreamErrorException,
    UpstreamTimeoutException,
)
from app.schemas import (  # noqa: E402
    AsnResponse,
    AtlasCaseStudyResponse,
    AtlasCaseStudySearchResponse,
    AtlasTechniqueResponse,
    AtlasTechniqueSearchResponse,
    AuditResponse,
    BrandAssetsResponse,
    BulkAtlasTechniqueResponse,
    BulkCveResponse,
    BulkIocResponse,
    CheckHeadersResponse,
    CodeCheckResponse,
    CveResponse,
    CveSearchResponse,
    CweLookupResponse,
    D3fendCoverageResponse,
    D3fendDefenseResponse,
    D3fendDefenseSearchResponse,
    D3fendForAttackResponse,
    DependenciesResponse,
    DisposableResponse,
    DnsResponse,
    DomainReportResponse,
    EmailMxResponse,
    EmailVerifyResponse,
    ErrorResponse,
    ExploitResponse,
    HashResponse,
    IocResponse,
    IpLookupResponse,
    KevDetailResponse,
    PasswordResponse,
    PhishingResponse,
    PhoneLookupResponse,
    RedirectChainResponse,
    RobotsTxtResponse,
    ScanHeadersResponse,
    SeoAuditResponse,
    SslResponse,
    SubdomainsResponse,
    TechResponse,
    ThreatReportResponse,
    ThreatResponse,
    UsernameLookupResponse,
    WaybackResponse,
    WhoisResponse,
)

# Shared annotations — all tools are read-only API lookups.
# v1.22.0 splits the legacy `_RO` (open-world default) into closed/open world
# variants so agents can reason about latency and retry semantics:
#   _RO_CLOSED_WORLD — local DB lookups (CVE/CWE/ATLAS/D3FEND catalog, codesec
#                      regex), deterministic, no external network.
#   _RO_OPEN_WORLD  — live external fetches (DNS/WHOIS/SSL, Shodan/AbuseIPDB,
#                      crt.sh, etc.), may time out or rate-limit.
# `_RO` retained as an alias for legacy callsites until Commit C swaps them.
_RO_CLOSED_WORLD = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
_RO_OPEN_WORLD = ToolAnnotations(
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
# FastMCP doesn't accept a `version` kwarg, so the lowlevel Server falls back
# to the installed `mcp` package version (currently 1.27.0) for serverInfo.
# Pin it to OUR application version so MCP clients and indexers can tell which
# release of ContrastAPI they're talking to. We poke the private `_mcp_server`
# attribute because FastMCP does not expose a setter; if a future SDK upgrade
# renames or restructures it, log the failure (don't block startup) so we can
# notice the silent revert to the package version.
try:
    from app.config import VERSION as _APP_VERSION

    mcp._mcp_server.version = _APP_VERSION
except Exception as _ver_pin_exc:  # pragma: no cover - metadata, never block startup
    logger.warning(
        "Failed to pin MCP serverInfo.version to app.config.VERSION (%s); "
        "serverInfo will fall back to the installed mcp package version.",
        _ver_pin_exc,
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


# === v1.22.0 raise-pattern infrastructure ====================================
#
# Coexists with the legacy `_get`/`_post`/`_validate_*` helpers above. Commit C
# swaps every tool body to the new helpers and deletes the legacy ones; until
# then both surfaces are live so the suite stays green at every commit boundary.


def _extract_upstream_message(resp: httpx.Response) -> str:
    """Pull a useful, length-capped error message out of an upstream JSON body.

    Mirrors the field-priority of legacy `_format_error` but returns a single
    string suitable for `ErrorDetail.message` (which itself enforces
    max_length=500). Falls back to bare 'Error <status>' on parse failure.
    """
    status = resp.status_code
    try:
        body = resp.json()
    except (ValueError, json.JSONDecodeError):
        return f"Error {status}"
    if not isinstance(body, dict):
        return f"Error {status}"
    msg = body.get("error") or body.get("detail") or body.get("message")
    if isinstance(msg, str) and msg:
        return msg[:500]
    hint = body.get("hint") or body.get("suggestion") or body.get("upgrade")
    if isinstance(hint, str) and hint:
        return hint[:500]
    if isinstance(hint, dict):
        inner = hint.get("message")
        if isinstance(inner, str) and inner:
            return inner[:500]
    return f"Error {status}"


def _http_error_to_app_exception(resp: httpx.Response) -> AppException:
    """Map an upstream `httpx.Response` to the appropriate `AppException` subclass.

    Status -> exception:
      400, 422  -> InvalidArgumentException
      401       -> AuthRequiredException
      403       -> TierLimitException (carries upgrade_url)
      404       -> NotFoundException
      429       -> RateLimitExceededException (carries retry_after + upgrade_url)
      504       -> UpstreamTimeoutException
      anything else -> UpstreamErrorException

    Centralizing the mapping means tool bodies never branch on status code.
    """
    status = resp.status_code
    detail = _extract_upstream_message(resp)
    upgrade = "https://contrastcyber.com/pricing"
    if status == 404:
        return NotFoundException(detail)
    if status == 429:
        try:
            retry = int(resp.headers.get("retry-after", "60"))
        except (TypeError, ValueError):
            retry = 60
        # Cap at 1h — agents that respect retry_after literally must not get
        # tricked into multi-year backoffs by a hostile/buggy upstream header.
        retry = max(0, min(retry, 3600))
        return RateLimitExceededException(detail, retry_after=retry, upgrade_url=upgrade)
    if status == 401:
        return AuthRequiredException(detail)
    if status == 403:
        return TierLimitException(detail, upgrade_url=upgrade)
    if status == 504:
        return UpstreamTimeoutException(detail)
    if status in (400, 422):
        return InvalidArgumentException(detail)
    return UpstreamErrorException(detail)


async def _aget(path: str, params: dict | None = None) -> dict:
    """v1.22 raise-pattern GET. Returns the JSON dict on success; raises an
    `AppException` subclass on any failure (mapping in `_http_error_to_app_exception`).
    Network/timeout failures collapse to `UpstreamTimeoutException`.
    """
    client_ip = _log_ip()
    try:
        resp = await _get_client().get(path, params=params, headers=_headers())
        resp.raise_for_status()
        logger.info("mcp_tool GET %s %d %s", _safe_path(path), resp.status_code, client_ip)
        return resp.json()
    except httpx.HTTPStatusError as e:
        logger.info("mcp_tool GET %s %d %s", _safe_path(path), e.response.status_code, client_ip)
        raise _http_error_to_app_exception(e.response) from e
    except httpx.HTTPError as e:
        logger.info("mcp_tool GET %s err %s", _safe_path(path), client_ip)
        raise UpstreamTimeoutException("Request failed") from e


async def _apost(path: str, json_body: dict, params: dict | None = None) -> dict:
    """v1.22 raise-pattern POST. See `_aget`."""
    client_ip = _log_ip()
    try:
        resp = await _get_client().post(path, json=json_body, params=params, headers=_headers())
        resp.raise_for_status()
        logger.info("mcp_tool POST %s %d %s", _safe_path(path), resp.status_code, client_ip)
        return resp.json()
    except httpx.HTTPStatusError as e:
        logger.info("mcp_tool POST %s %d %s", _safe_path(path), e.response.status_code, client_ip)
        raise _http_error_to_app_exception(e.response) from e
    except httpx.HTTPError as e:
        logger.info("mcp_tool POST %s err %s", _safe_path(path), client_ip)
        raise UpstreamTimeoutException("Request failed") from e


# --- Raise-pattern input validators (v1.22.0) ---
#
# Mirror the legacy `_validate_*` helpers above but raise an
# `InvalidArgumentException` subclass on bad input and return the normalized
# value on success. Tool bodies in Commit C use these directly, so the body
# can be a single line: `return CveResponse(**await _aget(f"/v1/cve/{_require_cve(cve_id)}"))`.


def _require_domain(domain: str) -> str:
    """Validate + normalize. Raises InvalidDomainException on bad input."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(domain):
        raise InvalidDomainException(f"Invalid domain format: {domain!r}. Expected format: example.com")
    return domain


def _require_ip(ip: str) -> str:
    """Validate any IP (public or private). Raises InvalidIpException on bad input."""
    ip = (ip or "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError as e:
        raise InvalidIpException(f"Invalid IP address: {ip!r}. Expected IPv4 (1.2.3.4) or IPv6.") from e
    return ip


def _require_public_ip(ip: str) -> str:
    """Validate IP and reject private/reserved ranges. Raises InvalidIpException.

    Mirrors `app/validation.py:is_private_ip()` SSRF guard: rejects unspecified
    (0.0.0.0, ::) in addition to private / loopback / reserved / link-local /
    multicast — keeps MCP-layer validation in lockstep with the HTTP layer.
    """
    ip = (ip or "").strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as e:
        raise InvalidIpException(f"Invalid IP address: {ip!r}. Expected IPv4 (1.2.3.4) or IPv6.") from e
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_reserved
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
    ):
        raise InvalidIpException(f"Private/reserved IP addresses are not allowed: {ip!r}")
    return ip


def _require_cve(cve_id: str) -> str:
    cve_id = (cve_id or "").strip()
    if not _CVE_RE.match(cve_id):
        raise InvalidCveIdException(f"Invalid CVE ID: {cve_id!r}. Expected format: CVE-2024-1234")
    return cve_id.upper()


def _require_cwe(cwe_id: str) -> str:
    cwe_id = (cwe_id or "").strip()
    if not _CWE_RE.match(cwe_id):
        raise InvalidArgumentException(f"Invalid CWE ID: {cwe_id!r}. Expected format: CWE-79 (or just '79')")
    return cwe_id


def _require_hash(file_hash: str) -> str:
    file_hash = (file_hash or "").strip()
    if not _HASH_RE.match(file_hash):
        raise InvalidHashException(
            f"Invalid hash: {file_hash!r}. Expected MD5 (32 hex), SHA-1 (40 hex), or SHA-256 (64 hex)."
        )
    return file_hash.lower()


def _require_atlas_technique(value: str) -> str:
    value = (value or "").strip()
    if not _ATLAS_TECHNIQUE_RE.match(value):
        raise InvalidArgumentException(
            f"Invalid ATLAS technique id: {value!r}. Expected 'AML.T####' or 'AML.T####.###' (e.g. AML.T0000)"
        )
    return value.upper()


def _require_atlas_case_study(value: str) -> str:
    value = (value or "").strip()
    if not _ATLAS_CASE_STUDY_RE.match(value):
        raise InvalidArgumentException(
            f"Invalid ATLAS case study id: {value!r}. Expected 'AML.CS####' (e.g. AML.CS0000)"
        )
    return value.upper()


def _require_atlas_tactic(value: str) -> str:
    value = (value or "").strip()
    if not _ATLAS_TACTIC_RE.match(value):
        raise InvalidArgumentException(f"Invalid ATLAS tactic id: {value!r}. Expected 'AML.TA####' (e.g. AML.TA0002)")
    return value.upper()


def _require_d3fend_defense(value: str) -> str:
    value = (value or "").strip()
    if not _D3FEND_DEFENSE_RE.match(value):
        raise InvalidArgumentException(
            f"Invalid D3FEND defense_id: {value!r}. Expected CamelCase slug (e.g. 'TokenBinding')"
        )
    return value


def _require_attack_technique(value: str) -> str:
    value = (value or "").strip()
    if not _ATTACK_TECHNIQUE_RE.match(value):
        raise InvalidArgumentException(
            f"Invalid ATT&CK technique id: {value!r}. Expected 'T####' or 'T####.###' (e.g. T1059, T1550.001)"
        )
    return value.upper()


def mcp_tool_safe(*, annotations: ToolAnnotations):
    """v1.22.0 tool decorator. Wraps `@mcp.tool` so AppException (and Pydantic
    ValidationError raised when the upstream response body does not match the
    declared response model) is caught and returned as a structured
    `ErrorResponse`. Enables single-line tool bodies in Commit C.

    Sets `structured_output=True` so FastMCP emits both `content[0].text` (JSON)
    and `structuredContent` (dict) on success — matching MCP 1.0 spec for tools
    whose output is a Pydantic model union.
    """

    def decorator(fn):
        @functools.wraps(fn)
        async def wrapped(*args, **kwargs):
            try:
                return await fn(*args, **kwargs)
            except AppException as e:
                return ErrorResponse(error=e.to_error_detail())
            except ValidationError:
                # Upstream returned a body that does not match our Pydantic schema
                # (cache poisoning / sync drift / partial JSON). Surface as
                # UpstreamErrorException with a fixed-length, sanitized message —
                # the raw ValidationError carries upstream-controlled values that
                # we MUST NOT log verbatim (CRLF injection into plain-text sinks)
                # nor ship to the MCP wire (would re-trigger ErrorDetail.message
                # max_length=500 if oversized, raising a second unhandled error).
                logger.warning("mcp_tool %s upstream response failed schema validation", fn.__name__)
                exc = UpstreamErrorException("Upstream response validation failed")
                return ErrorResponse(error=exc.to_error_detail())

        return mcp.tool(annotations=annotations, structured_output=True)(wrapped)

    return decorator


# --- Input validation ---
_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


_CWE_RE = re.compile(r"^(?:CWE[- ]?)?\d{1,6}$", re.IGNORECASE)


_ATLAS_TECHNIQUE_RE = re.compile(r"^AML\.T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_ATLAS_CASE_STUDY_RE = re.compile(r"^AML\.CS\d{4}$", re.IGNORECASE)
_ATLAS_TACTIC_RE = re.compile(r"^AML\.TA\d{4}$", re.IGNORECASE)


_D3FEND_DEFENSE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,63}$")
_ATTACK_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_D3FEND_TACTICS = {"Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"}


# v1.23.0 — target-type auto-detection for contrast_triage prompt.
# Order matters: most-specific patterns first so an ATLAS sub-technique like
# "AML.T0000.000" cannot be misclassified as an ATT&CK T-code (which it isn't).
TargetType = Literal[
    "cve",
    "atlas_technique",
    "attack_technique",
    "cwe",
    "hash",
    "ip",
    "domain",
    "unknown",
]


def _detect_target_type(target: str) -> TargetType:
    """Classify a triage target string by format.

    Used by `contrast_triage` Prompt to pick the right tool chain.
    Domains and IPs share dotted notation; resolution order:
      1. CVE-YYYY-NNNN
      2. ATLAS technique (AML.T#### or AML.T####.###)
      3. ATT&CK T-code (T#### / T####.###)
      4. CWE-#### (or bare 'CWE-79')
      5. Hash (32/40/64 hex)
      6. IP (ipaddress.ip_address — covers IPv4 + IPv6)
      7. Domain (FQDN regex)
    Returns 'unknown' when nothing matches.
    """
    s = (target or "").strip()
    if not s:
        return "unknown"
    if _CVE_RE.match(s):
        return "cve"
    if _ATLAS_TECHNIQUE_RE.match(s):
        return "atlas_technique"
    if _ATTACK_TECHNIQUE_RE.match(s):
        return "attack_technique"
    if "CWE" in s.upper() and _CWE_RE.match(s):
        # _CWE_RE alone would also match a bare digit string ("79"), which is
        # ambiguous — could be an ASN, port, or IP octet. Triage classifies as
        # CWE only when the 'CWE' prefix is explicit.
        return "cwe"
    if _HASH_RE.match(s):
        return "hash"
    try:
        ipaddress.ip_address(s)
        return "ip"
    except ValueError:
        pass
    if _DOMAIN_RE.match(s):
        return "domain"
    return "unknown"


# === Domain Intelligence ===


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
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
) -> DomainReportResponse | ErrorResponse:
    """Query DNS, WHOIS, SSL, subdomains, and threat intel for a domain in one call. By default dns.txt is filtered to security-relevant entries (SPF, DMARC, DKIM, MTA-STS, TLS-RPT) and dns.total_txt_records reports the honest pre-filter count; pass include_all_txt=true for the raw TXT list. Use as a starting point for domain investigations; use audit_domain for live headers + tech stack. Response carries next_calls — chain with subdomain_enum (always emitted), ssl_check + tech_fingerprint (when an A record resolves) for the standard recon depth without re-prompting. Free: 100/hr, Pro: 1000/hr. Returns domain report with DNS records, WHOIS data, SSL cert, risk score, email config, threat status, recommendation, and next_calls."""
    params = {"include_all_txt": "true"} if include_all_txt else None
    return DomainReportResponse(**await _aget(f"/v1/domain/{_require_domain(domain)}", params=params))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def audit_domain(
    domain: Annotated[
        str,
        Field(description="Root domain to audit, without protocol or path (e.g. 'example.com', 'shopify.com')"),
    ],
    include_all_txt: Annotated[
        bool,
        Field(
            description="Return every TXT record under report.dns.txt (default: False, only SPF/DMARC/DKIM/MTA-STS/TLS-RPT kept). report.dns.total_txt_records is always emitted with the honest pre-filter count. Default filter strips vendor verification strings (google-site-verification, ms=, facebook-domain-verification, etc.) that bloat the response without security signal. Set True only when you need the raw TXT inventory."
        ),
    ] = False,
) -> AuditResponse | ErrorResponse:
    """Perform comprehensive domain audit: combines domain_report + live HTTP security headers + technology fingerprinting. By default report.dns.txt is filtered to security-relevant entries (SPF, DMARC, DKIM, MTA-STS, TLS-RPT) and report.dns.total_txt_records reports the honest pre-filter count; pass include_all_txt=true for the raw TXT list. Use when you need the full picture (recon + active checks); use domain_report for passive-only assessment. Response carries next_calls — chain with subdomain_enum (always emitted) and ssl_check (when an A record resolves) for the residual recon depth (tech_fingerprint already inline as `technologies`). Free: 100/hr (costs 4 credits), Pro: 1000/hr. Returns {domain, report, technologies, live_headers, summary, next_calls}."""
    params = {"include_all_txt": "true"} if include_all_txt else None
    return AuditResponse(**await _aget(f"/v1/audit/{_require_domain(domain)}", params=params))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def threat_report(
    ip: Annotated[
        str,
        Field(
            description="Public IPv4 or IPv6 address to investigate (e.g. '8.8.8.8', '1.1.1.1'). Private/reserved IPs are rejected."
        ),
    ],
) -> ThreatReportResponse | ErrorResponse:
    """Query comprehensive threat profile for an IP: Shodan host data, AbuseIPDB reputation, ASN/geolocation, and open ports. Use for IP investigation and SOC alert triage; for domain data use domain_report. Note: nested asn block always returns at most 50 IPv4/IPv6 prefixes — call asn_lookup with include_full_prefixes=True for the full announced-prefixes list. enrichment.vulns is severity-aware list[VulnInfo] (cve_id + severity + cvss_v3) — Phase 2 v1.16.0 BREAKING; pre-1.16 it was list[str] of CVE IDs. Free: 100/hr (costs 4 credits), Pro: 1000/hr. Returns {ip, enrichment, abuseipdb, shodan, asn, threat_level}."""
    return ThreatReportResponse(**await _aget(f"/v1/threat-report/{_require_public_ip(ip)}"))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def dns_lookup(
    domain: Annotated[
        str, Field(description="Root domain to query, without protocol or path (e.g. 'example.com', 'cloudflare.com')")
    ],
) -> DnsResponse | ErrorResponse:
    """Query all DNS record types (A, AAAA, MX, NS, TXT, CNAME, SOA) for a domain. Use for mail routing inspection, nameserver verification, or SPF/DMARC checks; for full overview use domain_report. TXT records are returned raw (no filter) — `total_txt_records` always carries the honest count (use domain_report for the security-only filtered TXT view). Free: 100/hr, Pro: 1000/hr. Returns {domain, records: {a, aaaa, mx, ns, txt, total_txt_records, cname, soa}, summary}."""
    return DnsResponse(**await _aget(f"/v1/dns/{_require_domain(domain)}"))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def whois_lookup(
    domain: Annotated[str, Field(description="Root domain to query WHOIS for (e.g. 'example.com', 'github.com')")],
) -> WhoisResponse | ErrorResponse:
    """Retrieve WHOIS registration data: registrar, creation/expiry dates, nameservers, status. Use to verify domain ownership, age, expiration; for full audit use domain_report. Free: 100/hr, Pro: 1000/hr. Returns {domain, whois: {registrar, creation_date, expiry_date, updated_date, name_servers, status, raw_length, error}, summary}."""
    return WhoisResponse(**await _aget(f"/v1/whois/{_require_domain(domain)}"))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def ssl_check(
    domain: Annotated[
        str, Field(description="Domain to check SSL/TLS certificate for (e.g. 'example.com', 'api.stripe.com')")
    ],
) -> SslResponse | ErrorResponse:
    """Analyze SSL/TLS certificate: grade (A/B/C/D/F), protocol version, cipher suite, chain, expiry, Subject Alternative Names, and structured validation findings. Invalid certs (expired, self-signed, hostname mismatch, untrusted root) are reported as findings via valid=false + validation_errors[] rather than as endpoint failures, so an unreachable cert still returns useful intel. Grade D = cert readable but invalid; F = expired, legacy TLS, or probe failure. Use to audit certificate validity and detect expiring certs; for full domain audit use audit_domain. Free: 100/hr, Pro: 1000/hr. Returns {grade, valid, validation_errors, protocol, cipher, issuer, subject, not_before, not_after, days_remaining, chain, san, warnings}."""
    return SslResponse(**await _aget(f"/v1/ssl/{_require_domain(domain)}"))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def subdomain_enum(
    domain: Annotated[
        str, Field(description="Root domain to enumerate subdomains for (e.g. 'example.com', 'tesla.com')")
    ],
) -> SubdomainsResponse | ErrorResponse:
    """Discover subdomains using passive methods: Certificate Transparency logs + DNS brute-force (no active probing). Use to map organization's attack surface; non-intrusive. Response carries next_calls — capped at 5 ssl_check hints (one per first-five subdomain) so triage scales to large enumerations without token bloat; pull tail entries by name when needed. Free: 100/hr, Pro: 1000/hr. Returns {domain, count, subdomains, sources, found_via_wordlist, found_via_crtsh, crtsh_status, warnings, summary, next_calls}. Always check crtsh_status: 'ok' means the CT lookup completed (so a low count is real); 'timeout' / 'rate_limited' / 'unavailable' / 'error' means CT logs did not respond and the count is wordlist-only — the actual attack surface is likely larger, retry later or surface the limitation to the user."""
    return SubdomainsResponse(**await _aget(f"/v1/subdomains/{_require_domain(domain)}"))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def tech_fingerprint(
    domain: Annotated[str, Field(description="Domain to fingerprint (e.g. 'example.com', 'shopify.com')")],
) -> TechResponse | ErrorResponse:
    """Detect website technology stack: CMS, frameworks, CDN, analytics tools, web servers, languages (via HTTP headers + HTML analysis). Use for passive reconnaissance; for full audit use audit_domain. Free: 100/hr, Pro: 1000/hr. Returns {technologies: [{name, category, confidence%, version}]}."""
    return TechResponse(**await _aget(f"/v1/tech/{_require_domain(domain)}"))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def threat_intel(
    domain: Annotated[
        str, Field(description="Domain to check for threats (e.g. 'suspicious-site.com', 'example.com')")
    ],
) -> ThreatResponse | ErrorResponse:
    """Check domain against abuse.ch URLhaus for known malware-distribution URLs (single source — for multi-feed correlation use ioc_lookup which adds ThreatFox and, for IPs, Feodo Tracker). Use for fast domain-level threat assessment; use phishing_check for specific URLs. Free: 100/hr, Pro: 1000/hr. Returns {malware_urls, threat_tags, threat_status, summary}."""
    return ThreatResponse(**await _aget(f"/v1/threat/{_require_domain(domain)}"))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def wayback_lookup(
    domain: Annotated[str, Field(description="Domain to look up in web archives (e.g. 'example.com', 'archive.org')")],
) -> WaybackResponse | ErrorResponse:
    """Retrieve Wayback Machine snapshots for a domain: first capture, latest, total count, snapshot list. Use to investigate domain history and age; for full audit use domain_report. Free: 100/hr, Pro: 1000/hr. status='ok' means the count is authoritative (even when 0 → confirmed no archives). status='unavailable' means CDX timed out/rate-limited/5xx — total_snapshots is OMITTED (unknown, NOT zero) and the agent should NOT report "no snapshots"; the warnings[] array carries the cdx_* error code (cdx_timeout/cdx_rate_limited/cdx_unavailable/cdx_error/cdx_parse_error/cdx_body_too_large). Heavy domains (kernel.org, microsoft.com, archive.org itself) frequently time out the CDX endpoint despite having millions of snapshots — fall back to archive_url for manual inspection. Returns {domain, status, total_snapshots, first_seen, last_seen, years_online, snapshots, archive_url, summary, warnings}."""
    return WaybackResponse(**await _aget(f"/v1/archive/{_require_domain(domain)}"))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def scan_headers(
    domain: Annotated[
        str, Field(description="Domain to scan live HTTP headers for (e.g. 'example.com', 'api.github.com')")
    ],
    include: Annotated[
        str,
        Field(
            description=(
                "Detail level. Default ('') returns slim findings — raw header values capped at 500 chars "
                "with total_value_length carrying the honest pre-truncation length. Pass 'full' to restore "
                "the full raw value (useful for inspecting full CSP directives on sites like GitHub where "
                "the CSP header exceeds 4 KB). Allowed: '' or 'full'."
            ),
            json_schema_extra={"enum": ["", "full"]},
        ),
    ] = "",
) -> ScanHeadersResponse | ErrorResponse:
    """Perform live HTTP GET and analyze security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy. Use to audit live website headers; use check_headers to validate headers you already have. Free: 100/hr, Pro: 1000/hr. By default header values are truncated to 500 chars (CSP can exceed 4 KB on large sites); pass include='full' for the full raw value. Returns {headers_present, headers_missing, findings, total_score}."""
    if include not in ("", "full"):
        raise InvalidArgumentException("Invalid include. Allowed values: '' (slim default) or 'full'.")
    params = {"include": "full"} if include == "full" else None
    return ScanHeadersResponse(**await _aget(f"/v1/scan/headers/{_require_domain(domain)}", params=params))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def email_mx(
    domain: Annotated[
        str, Field(description="Domain to analyze email configuration for (e.g. 'example.com', 'google.com')")
    ],
) -> EmailMxResponse | ErrorResponse:
    """Analyze email security: MX records, SPF policy, DMARC policy, DKIM probe across common+date-based selectors, mail provider, grade. Use to verify email-auth setup and phishing risk; for full audit use domain_report. Free: 100/hr, Pro: 1000/hr. email_security.dkim_status reports honest evidence: 'verified' iff at least one selector responded, else 'unverifiable' (custom selectors cannot be discovered without prior knowledge). Grade: when DKIM verified, A=SPF+DMARC+DKIM/B=2of3/C=1of3; when DKIM unverifiable, A=SPF+DMARC/B=one/F=neither — DKIM absence is NOT penalized because it is unprovable in DNS. Returns {mx_records, mail_provider, email_security:{spf, dmarc, dkim_selectors, dkim_status, grade, issues}, summary}."""
    return EmailMxResponse(**await _aget(f"/v1/email/mx/{_require_domain(domain)}"))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def email_disposable(
    email: Annotated[
        str, Field(description="Full email address to check (e.g. 'user@tempmail.com', 'test@guerrillamail.com')")
    ],
) -> DisposableResponse | ErrorResponse:
    """Check if email address uses a known disposable/temporary provider (Guerrilla Mail, Temp Mail, Mailinator, etc.). Use for input validation to detect throwaway signups; for domain reputation use threat_intel. Companion email-investigation tools: email_mx (deliverability + MX trust), domain_report on the email's domain (full recon), threat_intel (malware-distribution signal on the domain). Free: 100/hr, Pro: 1000/hr. Returns {disposable, domain, provider}."""
    return DisposableResponse(**await _aget(f"/v1/email/disposable/{quote(email, safe='')}"))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def email_verify(
    email: Annotated[
        str,
        Field(
            description="Full email address to verify (e.g. 'admin@example.com', 'user@gmail.com'). Must contain '@'."
        ),
    ],
) -> EmailVerifyResponse | ErrorResponse:
    """One-call email validation combining syntax + MX records + disposable check + role-address detection (admin@/info@/...) + free-provider classification (gmail/outlook/yahoo/...). Use BEFORE adding an email to a contact list, sending an outbound message, or auditing a lead-list dump — replaces 2-3 tool calls (email_mx + email_disposable + manual role parse) with one structured response. Deliberately does NOT do SMTP `RCPT TO` deliverability probing — Hunter.io / NeverBounce-style mailbox enumeration is an ethical grey area we declined; use those services if you need that specific signal. role_address=true on `admin@`, `info@`, `noreply@`, `support@`, etc. (Gmail-style `+tag` is stripped before classification). free_provider=true on consumer-mailbox domains (B2B detection signal — a 'work' email at `@gmail.com` likely isn't a corporate user). Free: 100/hr, Pro: 1000/hr. Returns {email, domain, syntax_valid, mx_records, disposable, disposable_provider, role_address, role_type, free_provider, summary}."""
    return EmailVerifyResponse(**await _aget(f"/v1/email/verify/{quote(email, safe='')}"))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def robots_txt(
    domain: Annotated[
        str,
        Field(
            description="Registrable domain to fetch robots.txt for (e.g. 'example.com', 'github.com'). No scheme, no path, no port. Subdomains accepted; the bot fetches https://<domain>/robots.txt with HTTP fallback."
        ),
    ],
) -> RobotsTxtResponse | ErrorResponse:
    """Fetch + parse the target domain's robots.txt — sitemaps, per-User-agent allow/disallow rules, crawl-delay, Host directive. Use BEFORE crawling/scraping a target site (seo_audit, brand_assets, redirect_chain) to honour the site's published rules. status_code=404 means no robots.txt exists = implicit allow-all per RFC 9309 §2.4. ContrastAPI fetches with `User-agent: ContrastAPI/<version> (+https://contrastcyber.com/bot)` so site operators can identify + opt out via robots.txt; we honour `Disallow: /` for our UA in seo_audit and brand_assets. Per-target eTLD+1 throttle (60 req/min) prevents weaponising this endpoint against a single site; subdomain rotation collapses to the same bucket. Free: 100/hr, Pro: 1000/hr. Returns {domain, fetched_url, status_code, sitemaps, user_agents:{ua:{allow,disallow,crawl_delay}}, host, truncated, summary}. Returns 502 ErrorResponse if the target rejected the connection (DNS/TCP/TLS failure); the agent should NOT assume "no robots" in that case — it's an upstream-failure signal."""
    return RobotsTxtResponse(**await _aget(f"/v1/robots/{_require_domain(domain)}"))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def redirect_chain(
    url: Annotated[
        str,
        Field(
            description="Full URL whose redirect chain to walk, e.g. 'https://bit.ly/3xyz' or 'http://example.com/old-path'. Must start with http:// or https://. Pass the URL exactly as you'd `curl -L` it; the server handles encoding."
        ),
    ],
) -> RedirectChainResponse | ErrorResponse:
    """Walk an HTTP redirect chain hop-by-hop, returning per-hop {url, status_code, location, latency_ms}. Use to deobfuscate URL shorteners (bit.ly / t.co / lnkd.in), audit suspicious links from phishing investigations, or trace marketing tracking redirects. SSRF-guarded: each redirect target's resolved IP is re-validated before connecting (private IPs and non-HTTP schemes rejected). Up to 10 hops; loop_detected=true if a hop would revisit a previously-seen URL (we abort before the duplicate fetch); truncated=true if the chain still had a 30x at hop 10. Per-target eTLD+1 throttle (60 req/min) consumed once for the start host AND once per new host reached — a chain across 11 unrelated domains cannot bypass the cap. Free: 100/hr, Pro: 1000/hr. Returns {start_url, final_url, hops, hop_count, final_status, loop_detected, truncated, summary}. Returns 502 ErrorResponse on hard fetch failure (timeout / TLS / connect); 429 with Retry-After if a hop's eTLD+1 throttle is exceeded mid-chain."""
    from urllib.parse import quote

    # Percent-encode `?` and `#` so the API's query parser can't swallow them
    # — keeping them in `safe` would strip a URL like
    # `https://bit.ly/x?utm_source=a` down to `https://bit.ly/x` before the
    # handler ever sees the full URL. Other URL-syntax characters stay raw
    # so the path-param decode round-trips.
    _url_safe = ":/@!$&'()*+,;=[]"
    return RedirectChainResponse(**await _aget(f"/v1/redirect/{quote(url, safe=_url_safe)}"))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def brand_assets(
    domain: Annotated[
        str,
        Field(
            description="Registrable domain to scrape brand assets for (e.g. 'github.com', 'stripe.com'). No scheme, no path, no port. The bot fetches https://<domain>/ with HTTP fallback."
        ),
    ],
) -> BrandAssetsResponse | ErrorResponse:
    """Scrape a domain's homepage `<head>` for public brand assets — favicon, og:image, theme-color, og:site_name, JSON-LD `Organization.logo`. Use to enrich CRM records, build company-card UIs, or correlate a lead's site to their visual identity (no manual screenshot required). Strictly homepage-only (path `/`); we do NOT crawl. Ethical floor: target's robots.txt is honoured — `Disallow: /` for ContrastAPI OR `*` returns 403 `error.code = robots_txt_disallow` and we DO NOT fetch. `Cache-Control: no-store` / `private` from the target is respected (response is built but NOT written to our cache; `cache_respected=false` flags this). Per-target eTLD+1 throttle (60 req/min) prevents weaponising via subdomain rotation. All URL fields are absolute and `_untrusted` (DO NOT execute or shell-out — the target controls these strings). Free: 100/hr, Pro: 1000/hr. Returns {domain, fetched_url, status_code, favicon_url_untrusted, og_image_url_untrusted, theme_color, site_name_untrusted, logo_url_untrusted, cache_respected, summary}. Returns 502 on DNS/TCP/TLS failure; 403 `robots_txt_disallow` when the target opted out."""
    return BrandAssetsResponse(**await _aget(f"/v1/brand/{_require_domain(domain)}"))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def seo_audit(
    domain: Annotated[
        str,
        Field(
            description="Registrable domain to audit SEO for (e.g. 'example.com', 'shopify.com'). No scheme, no path, no port. Strictly homepage-only — the bot fetches https://<domain>/ with HTTP fallback and audits that single page (we do NOT crawl)."
        ),
    ],
) -> SeoAuditResponse | ErrorResponse:
    """One-shot SEO audit of a domain's homepage with a 0-100 composite score + a `missing_signals` list of concrete fixes. Use BEFORE pitching SEO work to a prospect, when triaging a lead's marketing maturity, or as a structured pre-flight before deeper auditing tools (Lighthouse / SEMrush). 10 audit rules each worth 10 pts: title present, title length 30-60 chars (Google SERP truncation window), meta description present, meta description length 50-160, exactly one H1, canonical link, ≥3 OG tags, JSON-LD present, image alt-text coverage (proportional), HTTPS. Strictly homepage-only — we do NOT crawl the site. Ethical floor: target's robots.txt is honoured — `Disallow: /` for ContrastAPI OR `*` returns 403 `error.code = robots_txt_disallow` and we DO NOT fetch. `Cache-Control: no-store`/`private` skips our cache write (`cache_respected=false` in the response). Per-target eTLD+1 throttle (60 req/min) prevents weaponising via subdomain rotation. All target-derived strings/lists are `_untrusted`. Free: 100/hr, Pro: 1000/hr. Returns {domain, fetched_url, status_code, title_untrusted, meta_description_untrusted, canonical_url, h1_untrusted, h1_count, h2_count, h3_count, images_total, images_missing_alt, internal_link_count, external_link_count, og_tags, json_ld_present, score, missing_signals, cache_respected, summary}. Returns 502 on DNS/TCP/TLS failure; 403 `robots_txt_disallow` when the target opted out."""
    return SeoAuditResponse(**await _aget(f"/v1/seo/{_require_domain(domain)}"))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def phone_lookup(
    number: Annotated[
        str,
        Field(
            description="Phone number in E.164 format: + followed by country code and number, no spaces or dashes. Examples: '+14155552671' (US), '+905551234567' (TR), '+442071234567' (UK). Wrong: '0555-123-4567', '(415) 555-2671'"
        ),
    ],
) -> PhoneLookupResponse | ErrorResponse:
    """Validate and analyze phone number: country, region, carrier, line type (mobile/landline/VoIP), timezone, formatted versions. Use to verify phone legitimacy and detect fraud risks. Requires E.164 format (+1234567890). Companion OSINT identity-investigation tools: username_lookup (social-platform handle correlation), email_disposable (throwaway-mail signal on associated email). Free: 100/hr, Pro: 1000/hr. Returns {valid, country, region, carrier, carrier_status, line_type, timezone, formats}. carrier is omitted from the wire when libphonenumber has no mapping for the region (US/CA/GB and other MNP-restricted regions); always read carrier_status — 'known' means carrier is present, 'unsupported_region' means we cannot identify the carrier (do not infer the number lacks one)."""
    return PhoneLookupResponse(**await _aget(f"/v1/phone/{quote(number, safe='')}"))


# === IP Intelligence ===


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def ip_lookup(
    ip: Annotated[str, Field(description="IPv4 or IPv6 address to investigate (e.g. '8.8.8.8', '2606:4700::1111')")],
) -> IpLookupResponse | ErrorResponse:
    """Query comprehensive IP intelligence: reverse DNS, ASN + holder name + country inline (RIPE Stat, Phase 1), open ports, hostnames, vulnerabilities (Shodan InternetDB enriched with severity + cvss_v3 from local cve.db — Phase 2 v1.16.0 BREAKING; vulns is now list[VulnInfo] {cve_id, severity, cvss_v3} dicts, pre-1.16 it was list[str] of CVE IDs; unknown CVEs emit severity='UNKNOWN' / cvss_v3=null — do NOT infer benign), cloud provider, Tor exit status, and reputation. cloud_provider uses two-tier detection: published cloud CIDR ranges (AWS/GCP/Cloudflare) first, then an ASN-to-provider fallback map for anycast/public-service IPs outside published ranges (e.g. 8.8.8.8 → AS15169 → 'Google'). Reputation: FireHOL level1 blocklist on Free tier; +AbuseIPDB + Shodan on Pro (Phase 4). Use for IP investigation; for orchestrated IP+reputation use threat_report. Response is null-explicit: every field is always present (cloud_provider=null when neither tier matches; tor_exit=false when not listed or upstream fetch failed — check verdict.sources_unavailable to disambiguate fetch failure from genuine absence). Response carries next_calls (conditional) — asn_lookup when ASN is populated, ioc_lookup when reputation is FireHOL-listed or AbuseIPDB confidence>50, threat_report on Pro tier for orchestrated profile. Free: 100/hr, Pro: 1000/hr. Returns {ip, ptr, geo, asn, asn_name, country, ports, hostnames, vulns, cloud_provider, tor_exit, reputation, risk_score, verdict, next_calls}."""
    return IpLookupResponse(**await _aget(f"/v1/ip/{_require_ip(ip)}"))


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
async def asn_lookup(
    target: Annotated[
        str, Field(description="Domain or IP address to look up ASN for (e.g. 'cloudflare.com', '8.8.8.8')")
    ],
    include_full_prefixes: Annotated[
        bool,
        Field(
            description="Return the full announced-prefixes list (default: False, returns first 50). ipv4_count and ipv6_count are always honest pre-truncation totals. Set True for network mapping or BGP route audits — Cloudflare AS13335 announces 2500+ prefixes."
        ),
    ] = False,
) -> AsnResponse | ErrorResponse:
    """Look up Autonomous System Number (ASN) for a domain or IP: AS number, organization, IPv4/IPv6 prefixes. Use to identify network operator and IP range ownership. Default returns first 50 prefixes per family — set include_full_prefixes=True for full list. Free: 100/hr, Pro: 1000/hr. Returns {asn, asn_name, ipv4_prefixes, ipv6_prefixes, ipv4_count, ipv6_count}."""
    original = (target or "").strip()
    # asn accepts EITHER a domain OR an IP; try each and only fail if both reject.
    # `original` is preserved so the error message reflects what the user actually
    # sent, not the partially-normalized form from a failed validator.
    try:
        target = _require_domain(original)
    except InvalidDomainException:
        try:
            target = _require_ip(original)
        except InvalidIpException as e:
            raise InvalidArgumentException(
                f"Invalid input: {original!r}. Expected a domain (example.com) or IP address (8.8.8.8).",
            ) from e
    params = {"include_full_prefixes": "true"} if include_full_prefixes else None
    return AsnResponse(**await _aget(f"/v1/asn/{target}", params=params))


# === CVE Intelligence ===


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
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
) -> CveResponse | ErrorResponse:
    """Retrieve detailed CVE data by ID: description, CVSS v3.1 + vector, EPSS score + percentile, CISA KEV status, affected products (CPE), references, patch availability, related CVEs. By default affected_products is truncated to the first 20 entries (total_products reports the honest count) and references to the first 10 (total_references reports the honest count). Pass include_affected_products=true and/or include_full_references=true for the complete lists (needed for bulk audits / dependency scanners; Log4j-class CVEs can carry 50+ products and 30+ refs). Use for single-CVE details; use cve_search for queries by product/severity. Response carries next_calls — chain with kev_detail when kev.in_kev=true for the CISA federal patch deadline + required action, with cwe_lookup on cwe_id for the weakness category, and with exploit_lookup for public PoC availability. Free: 100/hr, Pro: 1000/hr. Returns {cve_id, description, cvss_score, cvss_vector, epss, kev, affected_products (first 20 by default), total_products, references (first 10 by default), total_references, patch_available, related_cves, verdict, next_calls}."""
    params: dict = {}
    if include_affected_products:
        params["include_affected_products"] = "true"
    if include_full_references:
        params["include_full_references"] = "true"
    return CveResponse(**await _aget(f"/v1/cve/{_require_cve(cve_id)}", params=params or None))


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
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
) -> CveSearchResponse | ErrorResponse:
    """Search CVE database with filters: product/vendor, severity, published date range, EPSS score, CWE, CVSS range, CISA KEV status. Default response is SLIM per-result (cve_id, summary, severity, cvss_v3, cwe_id, epss, kev, total_products, published, modified, sources, verdict) — pass include='full' for description, cvss_breakdown, affected_products, references, first_seen_*. Use for vulnerability discovery by criteria; pass cwe_id (e.g. CWE-79) to enumerate every CVE in our database mapped to a weakness — pair with cwe_lookup for the category description and mitigations. Use cve_lookup for single CVE by ID, kev_detail when kev=true filtering and the agent needs federal patch deadlines per result. Response carries a global hint pointing at cve_lookup — drill into any returned cve_id for full detail and chained pivots (exploit_lookup, kev_detail, cwe_lookup). Free: 100/hr, Pro: 1000/hr. Returns {count, total, truncated, results, query_echo, hint}."""
    params: dict = {"limit": limit}
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
    return CveSearchResponse(**await _aget("/v1/cves", params=params))


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
async def cve_leading(
    limit: Annotated[int, Field(description="Maximum results to return. Range: 1-200.", ge=1, le=200)] = 50,
    offset: Annotated[int, Field(description="Skip N results for pagination.", ge=0, le=5000)] = 0,
    include: Annotated[
        str,
        Field(
            description=(
                "Per-result detail level. Default ('') returns slim list items (cve_id, summary, "
                "severity, cvss_v3, cwe_id, epss, kev, total_products, published, modified, sources, "
                "verdict). Pass 'full' to also return description, cvss_breakdown, affected_products, "
                "references, first_seen_source, first_seen_at. Slim default avoids description/summary "
                "duplication that bloats 50-item leading lists. Allowed: '' or 'full'."
            ),
            json_schema_extra={"enum": ["", "full"]},
        ),
    ] = "",
) -> CveSearchResponse | ErrorResponse:
    """List CVEs indexed from MITRE/GHSA BEFORE NVD publication (early-warning, freshest data). By default each result is slim (no description, no cvss_breakdown, no affected_products list, no references) — pass include='full' for the same payload shape as cve_lookup; for drill-down on a single CVE prefer cve_lookup. Use for threat intelligence on emerging CVEs; use cve_search for published NVD data. Response carries a global hint pointing at cve_lookup — drill into any returned cve_id for full detail and chained pivots (exploit_lookup, kev_detail, cwe_lookup). Free: 100/hr, Pro: 1000/hr. Returns {count, total, truncated, offset, summary, results, hint}."""
    if include not in ("", "full"):
        raise InvalidArgumentException("Invalid include. Allowed values: '' (slim default) or 'full'.")
    params: dict = {"limit": limit}
    if offset > 0:
        params["offset"] = offset
    if include == "full":
        params["include"] = "full"
    return CveSearchResponse(**await _aget("/v1/cve/leading", params=params))


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
async def exploit_lookup(
    cve_id: Annotated[
        str, Field(description="CVE identifier in format CVE-YYYY-NNNNN (e.g. 'CVE-2024-3094', 'CVE-2023-44487')")
    ],
) -> ExploitResponse | ErrorResponse:
    """Search public exploits/PoC for a specific CVE across three sources: (1) GitHub Advisory Database (sources.github.advisories[]), (2) Shodan CVEDB references (sources.shodan_refs.results[] — packetstorm/seclists/vendor URLs cited by Shodan), (3) ExploitDB CSV mirror (exploits[] array, with edb_id + author + verified flag — these are the actual ExploitDB entries). Use to assess if a vulnerability has weaponized exploits in the wild; run after cve_lookup to evaluate real-world risk. When the CVE is also in CISA KEV (kev.in_kev=true on cve_lookup), pair with kev_detail for federal patch deadline; pair with cwe_lookup on cwe_id for the underlying weakness category and mitigations. Response carries next_calls — single cve_lookup pivot for full context (KEV status, CWE chain, CVSS, EPSS); cve_lookup's own next_calls then surface kev_detail and cwe_lookup automatically (this endpoint has no in_kev/cwe_id schema, so blind emission of those pivots is intentionally avoided). Free: 100/hr, Pro: 1000/hr. Returns {cve_id, exploits_found, has_public_exploit, sources: {github, shodan_refs}, exploits: [{edb_id, cve_id, date_published, author, type, platform, url, verified, description}], verdict, next_calls}."""
    return ExploitResponse(**await _aget(f"/v1/exploit/{_require_cve(cve_id)}"))


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
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
) -> BulkCveResponse | ErrorResponse:
    """Batch query multiple CVEs (up to 10 free/50 pro): retrieve full CVE details for all in 1 request instead of N. By default each CVE's affected_products is truncated to the first 20 entries (total_products reports honest count) and references to the first 10 (total_references reports honest count); pass include_affected_products=true / include_full_references=true to return full lists. Use for dependency audits or bulk vulnerability enrichment; use cve_lookup for single CVE. Each successful item carries next_calls — chain with kev_detail (when kev.in_kev=true), cwe_lookup (when cwe_id is present), or exploit_lookup. Free: 100/hr (1 per item), Pro: 1000/hr. Returns {results, total, successful, failed, timed_out, partial, summary}."""
    if not isinstance(cve_ids, list) or not cve_ids:
        raise InvalidArgumentException("cve_ids must be a non-empty list")
    if len(cve_ids) > 50:
        raise InvalidArgumentException("Too many cve_ids — max 50 per request (Pro tier) or 10 (free tier).")
    if not all(isinstance(cid, str) for cid in cve_ids):
        raise InvalidArgumentException("All cve_ids must be strings")
    body = {
        "cve_ids": cve_ids,
        "include_affected_products": include_affected_products,
        "include_full_references": include_full_references,
    }
    return BulkCveResponse(**await _apost("/v1/cves/bulk", body))


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
async def kev_detail(
    cve_id: Annotated[
        str,
        Field(description="CVE identifier in format CVE-YYYY-NNNNN (e.g. 'CVE-2021-44228', 'CVE-2024-3094')"),
    ],
) -> KevDetailResponse | ErrorResponse:
    """Look up CISA KEV (Known Exploited Vulnerabilities) full record for a CVE. Returns federal patch deadline (due_date), CISA-specified required_action remediation, known ransomware association, vendor/product, the CISA-given common name (e.g. 'Log4Shell'), and CISA-reported CWE list. Returns 404 when the CVE is not in the KEV catalog — use cve_lookup for non-KEV CVEs. Best follow-up after cve_lookup or cve_search(kev=true) when an in_kev=true CVE is identified; chain with cwe_lookup on each returned CWE to investigate the weakness category. Free: 100/hr, Pro: 1000/hr. Returns {cve_id, vendor_project, product, vulnerability_name, date_added, due_date, required_action, known_ransomware_use, notes, cwes, verdict, next_calls}."""
    return KevDetailResponse(**await _aget(f"/v1/kev/{_require_cve(cve_id)}"))


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
async def cwe_lookup(
    cwe_id: Annotated[
        str,
        Field(
            description="CWE identifier — accepts 'CWE-79', 'cwe-79', or bare '79'. Common values: CWE-79 (XSS), CWE-89 (SQL injection), CWE-78 (command injection), CWE-502 (deserialization), CWE-22 (path traversal), CWE-120 (buffer overflow)."
        ),
    ],
    include: Annotated[
        str,
        Field(
            description="Detail level. Default ('') returns slim record (first 3 mitigations, first 3 examples, no extended_description). total_mitigations / total_examples are always honest pre-truncation counts. Pass 'full' to restore extended_description and the full mitigations + examples lists.",
            json_schema_extra={"enum": ["", "full"]},
        ),
    ] = "",
) -> CweLookupResponse | ErrorResponse:
    """Look up MITRE CWE (Common Weakness Enumeration) catalog record from research view 1000. Default response is SLIM (first 3 mitigations, first 3 examples, no extended_description) — pass include='full' for the verbose record. Returns description, abstract type (Pillar/Class/Base/Variant/Compound), status (Stable/Draft/Incomplete/Deprecated), exploit likelihood, recommended mitigations, observed example CVEs, parent_cwe (walk up the hierarchy), child_cwes (drill down to more specific weaknesses), and cve_count (LOWER BOUND — counts only CVEs whose primary CWE matches; CVEs with multiple CWEs may not be counted). Use after cve_lookup or kev_detail to understand the underlying weakness category; chain with cve_search(cwe_id=...) to enumerate all matching CVEs. Returns 404 when the CWE is not in research view 1000. Free: 100/hr, Pro: 1000/hr. Returns {cwe_id, name, description, abstract_type, status, likelihood, mitigations (first 3 by default), total_mitigations, examples (first 3 by default), total_examples, parent_cwe, child_cwes, cve_count, updated_at, verdict, next_calls; +extended_description on include='full'}."""
    cwe_id = _require_cwe(cwe_id)
    if include not in ("", "full"):
        raise InvalidArgumentException(f"Invalid include: {include!r}. Use '' (slim default) or 'full'.")
    params = {"include": "full"} if include == "full" else None
    return CweLookupResponse(**await _aget(f"/v1/cwe/{cwe_id}", params=params))


# === MITRE ATLAS (AI/ML attack catalog) ===


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
async def atlas_technique_lookup(
    technique_id: Annotated[
        str,
        Field(
            description="MITRE ATLAS technique id, format 'AML.T####' or 'AML.T####.###' for sub-techniques (e.g. 'AML.T0000', 'AML.T0051' LLM Prompt Injection, 'AML.T0000.000')."
        ),
    ],
) -> AtlasTechniqueResponse | ErrorResponse:
    """Look up a MITRE ATLAS technique — the AI/ML adversarial attack catalog. ATLAS catalogues TTPs targeting machine learning systems: prompt injection, model evasion, training data poisoning, model theft, etc. Roughly 80% of ATLAS techniques are AI/ML-specific (no ATT&CK bridge); 20% mirror an enterprise ATT&CK technique via attack_reference_id — use that to pivot to D3FEND defenses (d3fend_defense_for_attack) and CVE search. Sub-techniques inherit `tactics` from the parent (inherited_tactics=true flag) when ATLAS upstream leaves them empty. Use this tool when the user asks about AI/ML threats, LLM red-teaming, or adversarial ML; for multiple techniques in one call (e.g. drilling into a case study's techniques_used), prefer bulk_atlas_technique_lookup. Returns 404 when the id is not in the synced ATLAS catalog. Free: 100/hr, Pro: 1000/hr. Returns {technique_id, name, description, tactics, inherited_tactics, maturity (demonstrated|feasible|realized), attack_reference_id, attack_reference_url, subtechnique_of, created_date, modified_date, next_calls}."""
    return AtlasTechniqueResponse(**await _aget(f"/v1/atlas/{_require_atlas_technique(technique_id)}"))


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
async def bulk_atlas_technique_lookup(
    technique_ids: Annotated[
        list[str],
        Field(
            description="List of MITRE ATLAS technique ids in format 'AML.T####' or 'AML.T####.###' (e.g. ['AML.T0051', 'AML.T0043', 'AML.T0000.000']). Up to 50 per call. Case-insensitive; normalized + de-duplicated server-side. Each id counts as 1 request toward the rate limit.",
            max_length=50,
        ),
    ],
) -> BulkAtlasTechniqueResponse | ErrorResponse:
    """Bulk ATLAS technique lookup — retrieve full records for up to 50 techniques in a single request instead of N separate atlas_technique_lookup calls. Designed as the natural follow-up to atlas_case_study_lookup, whose techniques_used array can be passed directly. Each item is the same shape as atlas_technique_lookup, including parent-tactics inheritance for sub-techniques (inherited_tactics=true flag) and per-item next_calls (D3FEND bridge when attack_reference_id present, sibling-technique search by tactic, parent lookup for sub-techniques). Free: 100/hr (1 per item), Pro: 1000/hr. Returns {results [{technique_id, status (ok|not_found|invalid_format), technique, error}], total, successful, failed, partial, summary}."""
    if not isinstance(technique_ids, list) or not technique_ids:
        raise InvalidArgumentException("technique_ids must be a non-empty list")
    if len(technique_ids) > 50:
        raise InvalidArgumentException("Too many technique_ids — max 50 per request (Pro tier) or 10 (free tier).")
    if not all(isinstance(tid, str) for tid in technique_ids):
        raise InvalidArgumentException("All technique_ids must be strings")
    return BulkAtlasTechniqueResponse(**await _apost("/v1/atlas/techniques/bulk", {"technique_ids": technique_ids}))


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
async def atlas_technique_search(
    keyword: Annotated[
        str,
        Field(
            description="Substring match against technique name + description (case-insensitive). Min 2 chars. Example: 'prompt injection', 'model evasion', 'poisoning'. Omit to list all."
        ),
    ] = "",
    tactic: Annotated[
        str,
        Field(
            description="Filter by ATLAS tactic id, format 'AML.TA####'. Examples: 'AML.TA0002' (Reconnaissance), 'AML.TA0007' (ML Attack Staging). Omit for all tactics."
        ),
    ] = "",
    maturity: Annotated[
        str,
        Field(
            description="Filter by maturity: 'demonstrated' (observed in real attacks), 'feasible' (theoretical), or 'realized' (newer ATLAS classification, treat similar to demonstrated). Omit for all.",
            json_schema_extra={"enum": ["", "demonstrated", "feasible", "realized"]},
        ),
    ] = "",
    limit: Annotated[int, Field(description="Max results to return. Range: 1-200.", ge=1, le=200)] = 50,
    include: Annotated[
        str,
        Field(
            description="Detail level. Default ('') returns slim records (description truncated to 240 chars; drill via atlas_technique_lookup for full text). Pass 'full' for full description on every row — large catalogs (167 techniques) can return ~100KB at full.",
            json_schema_extra={"enum": ["", "full"]},
        ),
    ] = "",
    exclude_id: Annotated[
        str,
        Field(
            description="Optional ATLAS technique id to exclude from results, format 'AML.T####' or 'AML.T####.###'. Useful when chaining from atlas_technique_lookup to fetch siblings without echoing self in the same-tactic search."
        ),
    ] = "",
) -> AtlasTechniqueSearchResponse | ErrorResponse:
    """Search the MITRE ATLAS catalog of AI/ML attack techniques by keyword, tactic, or maturity. Default response is SLIM (description truncated to 240 chars per row); pass include='full' for the verbose record. Pass exclude_id when chaining from atlas_technique_lookup to skip self in sibling-tactic searches. Use this to discover techniques matching a threat-model question, e.g. 'what techniques target LLM serving infrastructure?'. Drill into atlas_technique_lookup with any returned technique_id for the full description, ATT&CK bridge, and pivot hints. For broader cross-referencing: when a result has attack_reference_id, that bridges to D3FEND mitigations via d3fend_defense_for_attack. Free: 100/hr, Pro: 1000/hr. Returns {query (echoed filters), total, results [{technique_id, name, description (truncated by default), tactics, inherited_tactics, maturity, attack_reference_id, subtechnique_of}], next_calls}."""
    if maturity and maturity not in ("demonstrated", "feasible", "realized"):
        raise InvalidArgumentException(
            f"Invalid maturity: {maturity!r}. Use 'demonstrated', 'feasible', or 'realized'."
        )
    if include not in ("", "full"):
        raise InvalidArgumentException(f"Invalid include: {include!r}. Use '' (slim default) or 'full'.")
    params: dict = {"limit": limit}
    if keyword:
        params["keyword"] = keyword
    if tactic:
        params["tactic"] = _require_atlas_tactic(tactic)
    if maturity:
        params["maturity"] = maturity
    if exclude_id:
        params["exclude_id"] = _require_atlas_technique(exclude_id)
    if include == "full":
        params["include"] = "full"
    return AtlasTechniqueSearchResponse(**await _aget("/v1/atlas/techniques", params=params))


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
async def atlas_case_study_lookup(
    case_study_id: Annotated[
        str,
        Field(description="MITRE ATLAS case study id, format 'AML.CS####' (e.g. 'AML.CS0000', 'AML.CS0014')."),
    ],
    include: Annotated[
        str,
        Field(
            description="Detail level. Default (omit/empty) returns slim (description truncated to 240 chars). Pass 'full' for the verbose narrative — case-study descriptions can run 1-3KB.",
            json_schema_extra={"enum": ["", "full"]},
        ),
    ] = "",
) -> AtlasCaseStudyResponse | ErrorResponse:
    """Look up a MITRE ATLAS case study — a documented real-world AI/ML attack incident. Each case study links a sequence of ATLAS techniques (techniques_used) to the incident. Default response is SLIM (description truncated to 240 chars); pass include='full' for the verbose narrative. Use this after atlas_technique_search to find which incidents have exercised a given technique. Drill into the full techniques_used array via bulk_atlas_technique_lookup in a single call (next_calls emits exactly that hint). Returns 404 when the id is not in the synced catalog. Free: 100/hr, Pro: 1000/hr. Returns {case_study_id, name, description, techniques_used, next_calls}."""
    if include not in ("", "full"):
        raise InvalidArgumentException(f"Invalid include: {include!r}. Use '' (slim default) or 'full'.")
    params: dict = {}
    if include == "full":
        params["include"] = "full"
    return AtlasCaseStudyResponse(
        **await _aget(
            f"/v1/atlas/case-studies/{_require_atlas_case_study(case_study_id)}",
            params=params or None,
        )
    )


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
async def atlas_case_study_search(
    keyword: Annotated[
        str,
        Field(
            description="Substring match against case study name + description (case-insensitive). Min 2 chars. Example: 'evasion', 'data poisoning'. Omit to list all."
        ),
    ] = "",
    technique_id: Annotated[
        str,
        Field(
            description="Filter to case studies that include this ATLAS technique id, format 'AML.T####' or 'AML.T####.###' (e.g. 'AML.T0051'). Omit for any technique."
        ),
    ] = "",
    limit: Annotated[int, Field(description="Max results to return. Range: 1-200.", ge=1, le=200)] = 50,
    include: Annotated[
        str,
        Field(
            description="Detail level. Default ('') returns slim records (description truncated to 240 chars). Pass 'full' for full description on every row.",
            json_schema_extra={"enum": ["", "full"]},
        ),
    ] = "",
) -> AtlasCaseStudySearchResponse | ErrorResponse:
    """Search ATLAS case studies (real-world AI/ML attack incidents) by keyword or referenced technique. Default response is SLIM (description truncated to 240 chars per row); pass include='full' for the verbose summary. Useful when the user has a technique in hand and wants to see incidents that exercised it. Drill via atlas_case_study_lookup for the full procedure list. Free: 100/hr, Pro: 1000/hr. Returns {query, total, results [{case_study_id, name, description (truncated by default), techniques_used}], next_calls}."""
    if include not in ("", "full"):
        raise InvalidArgumentException(f"Invalid include: {include!r}. Use '' (slim default) or 'full'.")
    params: dict = {"limit": limit}
    if keyword:
        params["keyword"] = keyword
    if technique_id:
        params["technique_id"] = _require_atlas_technique(technique_id)
    if include == "full":
        params["include"] = "full"
    return AtlasCaseStudySearchResponse(**await _aget("/v1/atlas/case-studies", params=params))


# === MITRE D3FEND (defense technique catalog) ===


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
async def d3fend_defense_lookup(
    defense_id: Annotated[
        str,
        Field(
            description="D3FEND defense slug from the ontology URI fragment (CamelCase), e.g. 'TokenBinding', 'FileHashing', 'CertificatePinning'."
        ),
    ],
) -> D3fendDefenseResponse | ErrorResponse:
    """Look up a MITRE D3FEND defense technique. D3FEND is the canonical defensive counterpart to ATT&CK — each defense is classified into one of 7 tactics (Model/Harden/Detect/Isolate/Deceive/Evict/Restore) and may target a specific digital artifact (e.g. 'Access Token'). Response includes attack_techniques: the list of ATT&CK T-codes this defense mitigates. Use after d3fend_defense_search for the full record + ATT&CK chain. Returns 404 when the slug is not in the synced D3FEND catalog. Free: 100/hr, Pro: 1000/hr. Returns {defense_id, label, uri, parent_label, description, tactic, artifact, attack_techniques, next_calls}."""
    return D3fendDefenseResponse(**await _aget(f"/v1/d3fend/{_require_d3fend_defense(defense_id)}"))


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
async def d3fend_defense_search(
    keyword: Annotated[
        str,
        Field(
            description="Substring match against defense label, description, or parent_label (case-insensitive). Min 2 chars. Example: 'token', 'hashing', 'sandbox'. Omit to list all."
        ),
    ] = "",
    tactic: Annotated[
        str,
        Field(
            description="Filter by D3FEND tactic. One of: Model, Harden, Detect, Isolate, Deceive, Evict, Restore. Omit for all tactics.",
            json_schema_extra={"enum": ["", "Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"]},
        ),
    ] = "",
    artifact: Annotated[
        str,
        Field(
            description="Filter by exact targeted digital artifact (case-insensitive), e.g. 'Access Token', 'File', 'Process'. Omit for any artifact."
        ),
    ] = "",
    limit: Annotated[int, Field(description="Max results to return. Range: 1-200.", ge=1, le=200)] = 50,
    include: Annotated[
        str,
        Field(
            description="Detail level. Default (omit/empty) returns slim rows (drops the deterministic ontology `uri` field, ~60 chars/row saved). Pass 'full' to get `uri` back on every row. The slug `defense_id` is always returned and uniquely identifies the defense.",
            json_schema_extra={"enum": ["", "full"]},
        ),
    ] = "",
    exclude_id: Annotated[
        str,
        Field(
            description="Optional D3FEND defense slug (CamelCase, e.g. 'TokenBinding') to omit from results. Useful when chaining from d3fend_defense_lookup so the originating defense is not echoed back in its own siblings list. Omit when not needed."
        ),
    ] = "",
) -> D3fendDefenseSearchResponse | ErrorResponse:
    """Search the MITRE D3FEND catalog of defensive techniques by keyword, tactic, or targeted artifact. Default response is SLIM (drops `uri` from each row — saves ~60 chars/row, ~30% on popular drills); pass include='full' for the verbose record. Pass exclude_id when chaining from d3fend_defense_lookup to skip self in sibling-artifact searches. Use to discover defenses applicable to a given threat model — e.g. 'what defenses harden access tokens?' (tactic=Harden + artifact='Access Token'). Drill into d3fend_defense_lookup with any returned defense_id for the ATT&CK technique mappings. Free: 100/hr, Pro: 1000/hr. Returns {query, total, results [{defense_id, label, uri (only when include=full), parent_label, tactic, artifact}], next_calls}."""
    if tactic and tactic not in _D3FEND_TACTICS:
        raise InvalidArgumentException(f"Invalid tactic: {tactic!r}. Use one of {sorted(_D3FEND_TACTICS)}.")
    if include not in ("", "full"):
        raise InvalidArgumentException(f"Invalid include: {include!r}. Use '' (slim default) or 'full'.")
    params: dict = {"limit": limit}
    if keyword:
        params["keyword"] = keyword
    if tactic:
        params["tactic"] = tactic
    if artifact:
        params["artifact"] = artifact
    if include == "full":
        params["include"] = "full"
    if exclude_id:
        params["exclude_id"] = exclude_id
    return D3fendDefenseSearchResponse(**await _aget("/v1/d3fend/defenses", params=params))


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
async def d3fend_defense_for_attack(
    attack_technique_id: Annotated[
        str,
        Field(
            description="ATT&CK technique id matching 'T####' or 'T####.###' (e.g. 'T1059', 'T1550.001'). Use this to bridge from CVE/ATLAS findings to D3FEND mitigations."
        ),
    ],
    limit: Annotated[
        int,
        Field(
            description="Cap on `defenses` array length. Default 30; popular T-codes (T1059, T1078) map to 30-50+ defenses. `total` and `coverage_by_tactic` always reflect the honest pre-truncation count.",
            ge=1,
            le=200,
        ),
    ] = 30,  # keep in sync with app/d3fend/routes.py:_FOR_ATTACK_DEFAULT_LIMIT
    include: Annotated[
        str,
        Field(
            description="Detail level. Default (omit/empty) returns slim rows (drops the deterministic ontology `uri` — popular T-codes with 15+ defenses save ~900 chars). Pass 'full' to get `uri` back on every row.",
            json_schema_extra={"enum": ["", "full"]},
        ),
    ] = "",
    exclude_id: Annotated[
        str,
        Field(
            description="Optional D3FEND defense slug to omit from the defenses list. Used when chaining from d3fend_defense_lookup so the originating defense is not echoed back in its own 'see also' results."
        ),
    ] = "",
) -> D3fendForAttackResponse | ErrorResponse:
    """Reverse lookup: given an ATT&CK T-code, return D3FEND defenses that mitigate it. This is the bridge from offensive intelligence (ATT&CK / ATLAS / CVE) to defensive playbook. Pair with cve_lookup or atlas_technique_lookup output — when those carry an ATT&CK id, call this tool to surface the mitigations. `defenses` is capped at `limit` (default 30) for token efficiency; `total` is the honest pre-truncation count and `truncated=true` flags when the cap was hit. `coverage_by_tactic` always aggregates the FULL set, not the slice. Default response is SLIM (drops `uri` from each row); pass include='full' for the verbose record. Pass exclude_id when drilling from d3fend_defense_lookup to skip self in the 'see also' list. Returns 200 with empty defenses list when the T-code has no D3FEND mapping (the gap is itself a signal). Free: 100/hr, Pro: 1000/hr. Returns {attack_technique_id, total, truncated, defenses [{defense_id, label, uri (only when include=full), parent_label, tactic, artifact, attack_label, attack_tactic}], coverage_by_tactic, next_calls}."""
    if include not in ("", "full"):
        raise InvalidArgumentException(f"Invalid include: {include!r}. Use '' (slim default) or 'full'.")
    params: dict = {"limit": limit}
    if include == "full":
        params["include"] = "full"
    if exclude_id:
        params["exclude_id"] = exclude_id
    return D3fendForAttackResponse(
        **await _aget(
            f"/v1/d3fend/attack/{_require_attack_technique(attack_technique_id)}",
            params=params,
        )
    )


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
async def d3fend_attack_coverage(
    attack_technique_ids: Annotated[
        list[str],
        Field(
            description="List of ATT&CK technique ids (T#### or T####.###) to assess. Capped at 500 — extra entries are dropped server-side. Example: ['T1059', 'T1550.001', 'T1190', 'T9999'].",
            max_length=500,
        ),
    ],
) -> D3fendCoverageResponse | ErrorResponse:
    """Batch coverage breakdown: given a list of ATT&CK T-codes, return distinct defense counts per D3FEND tactic + identify which techniques have NO D3FEND mapping (undefended_techniques). Use to assess the defensive posture of an entire attack campaign or threat model in one call. defended_techniques is the subset with at least one D3FEND defense; undefended_techniques are gaps worth flagging. Pair with cve_search per gap to identify exploit availability. Free: 100/hr, Pro: 1000/hr. Returns {queried_techniques, coverage_by_tactic, defended_techniques, undefended_techniques, next_calls}."""
    if not attack_technique_ids:
        raise InvalidArgumentException("Provide at least one ATT&CK technique id.")
    if len(attack_technique_ids) > 500:
        raise InvalidArgumentException("Too many ids — max 500. Truncate input client-side.")
    return D3fendCoverageResponse(**await _apost("/v1/d3fend/coverage", {"attack_technique_ids": attack_technique_ids}))


# === Threat Intelligence / IOC ===


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def ioc_lookup(
    indicator: Annotated[
        str,
        Field(
            description="Indicator of Compromise: IP address, domain, full URL, or file hash in MD5/SHA1/SHA256 format (e.g. '8.8.8.8', 'evil.com', 'https://evil.com/malware.exe', 'd41d8cd98f00b204e9800998ecf8427e')"
        ),
    ],
) -> IocResponse | ErrorResponse:
    """Enrich Indicator of Compromise (IP/domain/URL/hash) by auto-detecting type and querying abuse.ch feeds. Per-type source coverage: hash → ThreatFox only (Feodo and URLhaus do not index hashes); IP → ThreatFox + Feodo Tracker + URLhaus; domain / URL → ThreatFox + URLhaus. verdict.sources_queried lists what actually ran; verdict.sources_unavailable lists what failed (timeout / upstream error). Use as primary IOC triage tool when type unknown; use threat_intel for domain-only, hash_lookup for richer MalwareBazaar hash data. Free: 100/hr, Pro: 1000/hr. Returns {indicator, type, threat_level, sources, summary, verdict}."""
    return IocResponse(**await _aget(f"/v1/ioc/{quote(indicator, safe='')}"))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def hash_lookup(
    file_hash: Annotated[
        str,
        Field(
            description="File hash to look up. Accepts MD5 (32 chars), SHA-1 (40 chars), or SHA-256 (64 chars). Lowercase hex only, no spaces. Example: 'd41d8cd98f00b204e9800998ecf8427e'"
        ),
    ],
) -> HashResponse | ErrorResponse:
    """Query MalwareBazaar for file hash (MD5/SHA1/SHA256): malware family, file type, size, tags, first/last seen, download count. Use to check if file hash is known malware; use ioc_lookup for auto-detection of all IOC types. Companion malware-investigation tools: ioc_lookup (multi-source: ThreatFox + Feodo Tracker + URLhaus), threat_intel (domain-level URLhaus check), exploit_lookup (link a known CVE to PoC code if the hash maps to an exploit binary). Free: 100/hr, Pro: 1000/hr. Returns {found, malware_family, file_type, file_size, tags, first_seen, last_seen, signature}."""
    return HashResponse(**await _aget(f"/v1/hash/{_require_hash(file_hash)}"))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def password_check(
    sha1_hash: Annotated[
        str,
        Field(
            description="Full SHA-1 hash of the password as 40 lowercase hexadecimal characters (e.g. '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' for 'password')"
        ),
    ],
) -> PasswordResponse | ErrorResponse:
    """Check if SHA-1 hash appears in Have I Been Pwned (HIBP) breach dataset using k-anonymity (5-char prefix only, full hash never leaves tool). Use for password breach audits; read-only, no data stored. Companion OSINT investigation tools: hash_lookup (file-hash malware family lookup, different namespace), email_disposable (throwaway-mail signal on associated accounts), username_lookup (social-platform exposure on associated handles). Free: 100/hr, Pro: 1000/hr. Returns {found, count}."""
    sha1 = (sha1_hash or "").strip()
    if not re.match(r"^[a-fA-F0-9]{40}$", sha1):
        raise InvalidArgumentException("Invalid SHA-1 hash. Expected exactly 40 hexadecimal characters.")
    return PasswordResponse(**await _aget(f"/v1/password/{sha1}"))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def phishing_check(
    url: Annotated[
        str,
        Field(
            description="Full URL to check, including protocol (e.g. 'https://suspicious-login.com/verify', 'http://evil.com/payload.exe')"
        ),
    ],
) -> PhishingResponse | ErrorResponse:
    """Query URLhaus for a specific URL and its host. is_malicious is True only when there is ACTIVE evidence — exact URL match with url_status='online' (or unknown) OR host has urls_online > 0. URLhaus retains historical records forever, so a host can have url_count > 0 with urls_online == 0; in that case is_malicious=False, is_stale=True, threat_level='low'. Use for URL-level threat assessment; use threat_intel for domain-level checks. Companion threat-investigation tools: ioc_lookup (multi-source IOC: ThreatFox + URLhaus + Feodo Tracker, auto-detect type), hash_lookup (file-hash malware family, MalwareBazaar), threat_intel (domain-level URLhaus only). Free: 100/hr, Pro: 1000/hr. Returns {url, host, is_malicious, is_stale, urlhaus_host:{found,urls_online,url_count}, urlhaus_url:{found,threat,tags,status}, threat_level, summary}."""
    return PhishingResponse(**await _aget(f"/v1/phishing/{quote(url, safe='')}"))


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
async def bulk_ioc_lookup(
    indicators: Annotated[
        list[str],
        Field(
            description="List of indicators of compromise: IP addresses, domains, URLs, or file hashes (e.g. ['8.8.8.8', 'evil.com', 'd41d8cd98f00b204e9800998ecf8427e']). Maximum 10 per request for free tier, 50 for Pro. Each indicator type is auto-detected."
        ),
    ],
) -> BulkIocResponse | ErrorResponse:
    """Batch query multiple IOCs (IP/domain/URL/hash, up to 10 free/50 pro) in 1 request: auto-detects type + queries abuse.ch feeds per-indicator. Per-type source coverage matches ioc_lookup: hash → ThreatFox only; IP → ThreatFox + Feodo + URLhaus; domain / URL → ThreatFox + URLhaus. Each result item carries its own verdict.sources_queried / sources_unavailable so partial failures are visible per indicator. Use for SOC alert triage or batch enrichment; use ioc_lookup for single indicator. Free: 100/hr (1 per item), Pro: 1000/hr. Returns {results, total, successful, failed, timed_out, partial, summary}."""
    if not isinstance(indicators, list) or not indicators:
        raise InvalidArgumentException("indicators must be a non-empty list")
    if len(indicators) > 50:
        raise InvalidArgumentException("Too many indicators — max 50 per request (Pro tier) or 10 (free tier).")
    return BulkIocResponse(**await _apost("/v1/iocs/bulk", {"indicators": indicators}))


# === Code Security ===


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
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
) -> CodeCheckResponse | ErrorResponse:
    """Scan source code (or snippet) for hardcoded secrets — cloud provider keys, API tokens, connection strings, private keys, passwords. Supports Python, JavaScript, TypeScript, Java, Go, Ruby, Shell, Bash. Use to detect leaked credentials before commit; for injection detection use check_injection. Free: 100/hr, Pro: 1000/hr. Returns {total, by_severity, findings}. No data stored. The generic password-assignment rule is suppressed when a more-specific credential rule fires on the same line — one targeted finding per leaked secret, not two."""
    return CodeCheckResponse(**await _apost("/v1/check/secrets", {"code": code, "language": language}))


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
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
) -> CodeCheckResponse | ErrorResponse:
    """Scan source code for injection vulnerabilities: SQL injection, command injection, path traversal via unsafe string concatenation/unsanitized input. Supports Python, JavaScript, TypeScript, Java, Go, Ruby, Shell, Bash. Use to detect input-handling bugs; for secrets use check_secrets. Companion code-security tools: check_secrets (hard-coded credential detection), check_dependencies (known-CVE vulnerability audit), check_headers (live HTTP security-header validation), scan_headers (live HTTP scan via domain). Free: 100/hr, Pro: 1000/hr. Returns {total, by_severity, findings}. No data stored."""
    return CodeCheckResponse(**await _apost("/v1/check/injection", {"code": code, "language": language}))


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
async def check_dependencies(
    packages: Annotated[
        list[dict],
        Field(
            description="List of dependency packages to audit. Each item is an object with 'name' (required, max 200 chars, e.g. 'lodash', 'django', 'log4j-core') and optional 'version' (max 100 chars, e.g. '4.17.0', '2.14.1'). Only 'name' and 'version' fields are used; extra fields are ignored. Example: [{\"name\": \"lodash\", \"version\": \"4.17.0\"}, {\"name\": \"django\"}]. Maximum 10 per request for free tier, 50 for Pro."
        ),
    ],
) -> DependenciesResponse | ErrorResponse:
    """Audit project dependencies (npm/PyPI/Maven/RubyGems/etc.) against CVE database: find known vulnerabilities in your package list. Bulk query up to 10 free/50 pro packages. Use for dependency security scanning; use cve_lookup for single CVE. Free: 100/hr (1 per package), Pro: 1000/hr. Returns {findings, total, by_severity, summary}. Each finding includes fixed_in (first patched version per NVD/MITRE version range) when a version range matched — omitted from wire when the range is open-ended or no input version was supplied; remediation copy then says 'Check if ... is affected ... and upgrade if so' instead of 'Upgrade to X.Y.Z or later'."""
    if not isinstance(packages, list) or not packages:
        raise InvalidArgumentException("packages must be a non-empty list")
    if len(packages) > 50:
        raise InvalidArgumentException("Too many packages. Maximum 50 per request (Pro tier) or 10 (free tier).")
    for pkg in packages:
        if not isinstance(pkg, dict):
            raise InvalidArgumentException(
                f'Each package must be an object like {{"name": "lodash", "version": "4.17.0"}}, got: {type(pkg).__name__}'
            )
        name = pkg.get("name")
        if not isinstance(name, str) or not name.strip():
            raise InvalidArgumentException("Each package must have a non-empty 'name' string field")
        if len(name) > 200:
            raise InvalidArgumentException("'name' must be at most 200 characters")
        version = pkg.get("version")
        if version is not None and not isinstance(version, str):
            raise InvalidArgumentException(f"'version' must be a string or null, got: {type(version).__name__}")
        if isinstance(version, str) and len(version) > 100:
            raise InvalidArgumentException("'version' must be at most 100 characters")
    return DependenciesResponse(**await _apost("/v1/check/dependencies", {"packages": packages}))


@mcp_tool_safe(annotations=_RO_OPEN_WORLD)
async def username_lookup(
    username: Annotated[
        str,
        Field(
            description="Username string to search across platforms, without @ prefix (e.g. 'torvalds', 'johndoe', 'elonmusk')"
        ),
    ],
) -> UsernameLookupResponse | ErrorResponse:
    """Search for username across 15+ social/dev platforms (GitHub, Reddit, X/Twitter, LinkedIn, Instagram, TikTok, Discord, YouTube, Keybase, HackerOne, etc.). Use for OSINT investigations and identity verification. Free: 100/hr, Pro: 1000/hr. Returns {username, total_found, platforms: [{name, exists, url, status_code}]}."""
    return UsernameLookupResponse(**await _aget(f"/v1/username/{quote(username, safe='')}"))


@mcp_tool_safe(annotations=_RO_CLOSED_WORLD)
async def check_headers(
    headers: Annotated[
        str,
        Field(
            description='JSON string of HTTP header name-value pairs to validate. Example: \'{"Strict-Transport-Security": "max-age=31536000", "X-Frame-Options": "DENY"}\'. Include only security-relevant headers you want to analyze.'
        ),
    ],
    include: Annotated[
        str,
        Field(
            description=(
                "Detail level. Default ('') returns slim findings — raw header values capped at 500 chars "
                "with total_value_length carrying the honest pre-truncation length. Pass 'full' to restore "
                "the full raw value. Allowed: '' or 'full'."
            ),
            json_schema_extra={"enum": ["", "full"]},
        ),
    ] = "",
) -> CheckHeadersResponse | ErrorResponse:
    """Validate HTTP security headers you provide (JSON): CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy against best practices. Use to test header config before deployment or validate non-public servers; use scan_headers to fetch live. Free: 100/hr, Pro: 1000/hr. By default header values are truncated to 500 chars; pass include='full' for the full raw value. Returns {total, by_severity, findings}. No external requests."""
    try:
        h = json.loads(headers)
    except json.JSONDecodeError as e:
        raise InvalidArgumentException("Invalid JSON. Provide headers as JSON object.") from e
    if include not in ("", "full"):
        raise InvalidArgumentException("Invalid include. Allowed values: '' (slim default) or 'full'.")
    params = {"include": "full"} if include == "full" else None
    return CheckHeadersResponse(**await _apost("/v1/check/headers", {"headers": h}, params=params))


# === Resources ===
#
# v1.23.0 — MCP Resources expose ATLAS / D3FEND / CWE catalogs as readable URIs.
# Resources differ from tools: they are pure local-DB lookups (no upstream API,
# no rate limit, no auth) so a client can browse the catalog without burning
# the agent's tool budget. Catalog summaries are slim (id + name + key fields)
# so even the 944-row CWE table fits in a single read.


def _resource_not_found(kind: str, ident: str) -> ValueError:
    """FastMCP surfaces ValueError from a resource as a not-found error.

    Centralized here so the message format stays consistent across all four
    detail-resource handlers and so it never embeds raw user input verbatim
    (the validator-normalized id is used). The id is hard-capped at 100 chars
    to mirror the v1.22.0 ErrorDetail.message length-cap discipline — a
    future validator that loosens its regex must not be able to smuggle a
    multi-KB string through this error sink unbounded.
    """
    return ValueError(f"{kind} not found: {ident[:100]}")


@mcp.resource(
    uri="atlas://technique/{technique_id}",
    name="atlas_technique",
    description="ATLAS technique by id (e.g. atlas://technique/AML.T0000). Returns full record including tactics, maturity, attack reference.",
    mime_type="application/json",
)
def atlas_technique_resource(technique_id: str) -> str:
    """Read an ATLAS technique. Validates id format; raises if not in catalog."""
    from app.db import get_atlas_technique

    normalized = _require_atlas_technique(technique_id)
    record = get_atlas_technique(normalized)
    if record is None:
        raise _resource_not_found("ATLAS technique", normalized)
    return json.dumps(record, default=str, ensure_ascii=False)


@mcp.resource(
    uri="atlas://case-study/{case_study_id}",
    name="atlas_case_study",
    description="ATLAS case study by id (e.g. atlas://case-study/AML.CS0000). Returns name, description, techniques_used.",
    mime_type="application/json",
)
def atlas_case_study_resource(case_study_id: str) -> str:
    from app.db import get_atlas_case_study

    normalized = _require_atlas_case_study(case_study_id)
    record = get_atlas_case_study(normalized)
    if record is None:
        raise _resource_not_found("ATLAS case study", normalized)
    return json.dumps(record, default=str, ensure_ascii=False)


@mcp.resource(
    uri="atlas://catalog",
    name="atlas_catalog",
    description="ATLAS catalog summary: all techniques (id+name+tactics) and case studies (id+name).",
    mime_type="application/json",
)
def atlas_catalog_resource() -> str:
    from app.db import (
        CATALOG_LISTING_MAX,
        count_atlas_case_studies,
        count_atlas_techniques,
        search_atlas_case_studies,
        search_atlas_techniques,
    )

    techniques = search_atlas_techniques(limit=CATALOG_LISTING_MAX)
    case_studies = search_atlas_case_studies(limit=CATALOG_LISTING_MAX)
    total_t = count_atlas_techniques()
    total_c = count_atlas_case_studies()
    payload = {
        "techniques": [
            {
                "technique_id": t["technique_id"],
                "name": t["name"],
                "tactics": t["tactics"],
                "subtechnique_of": t["subtechnique_of"],
            }
            for t in techniques
        ],
        "case_studies": [{"case_study_id": c["case_study_id"], "name": c["name"]} for c in case_studies],
        "totals": {"techniques": total_t, "case_studies": total_c},
        # Honest truncation flag: search_* clamps internally to 200 today; if upstream
        # catalog grows past that, surface the gap so clients can paginate via the
        # search tool instead of relying on the catalog being complete.
        "truncated": len(techniques) < total_t or len(case_studies) < total_c,
    }
    return json.dumps(payload, default=str, ensure_ascii=False)


@mcp.resource(
    uri="d3fend://defense/{defense_id}",
    name="d3fend_defense",
    description="D3FEND defense by CamelCase slug (e.g. d3fend://defense/TokenBinding). Returns label, tactic, artifact, attack_techniques mapped.",
    mime_type="application/json",
)
def d3fend_defense_resource(defense_id: str) -> str:
    from app.db import get_d3fend_defense

    normalized = _require_d3fend_defense(defense_id)
    record = get_d3fend_defense(normalized)
    if record is None:
        raise _resource_not_found("D3FEND defense", normalized)
    return json.dumps(record, default=str, ensure_ascii=False)


@mcp.resource(
    uri="d3fend://catalog",
    name="d3fend_catalog",
    description="D3FEND catalog summary: all defenses (id+label+tactic+artifact).",
    mime_type="application/json",
)
def d3fend_catalog_resource() -> str:
    from app.db import CATALOG_LISTING_MAX, count_d3fend_defenses, search_d3fend_defenses

    defenses = search_d3fend_defenses(limit=CATALOG_LISTING_MAX)
    total = count_d3fend_defenses()
    payload = {
        "defenses": [
            {
                "defense_id": d["defense_id"],
                "label": d["label"],
                "tactic": d["tactic"],
                "artifact": d["artifact"],
                "parent_label": d["parent_label"],
            }
            for d in defenses
        ],
        "totals": {"defenses": total},
        "truncated": len(defenses) < total,
    }
    return json.dumps(payload, default=str, ensure_ascii=False)


@mcp.resource(
    uri="cwe://weakness/{cwe_id}",
    name="cwe_weakness",
    description="CWE weakness by id (e.g. cwe://weakness/CWE-79 or cwe://weakness/79). Returns name, description, mitigations, examples, parent/child links.",
    mime_type="application/json",
)
def cwe_weakness_resource(cwe_id: str) -> str:
    from app.db import get_cwe

    normalized = _require_cwe(cwe_id)
    if not normalized.upper().startswith("CWE-"):
        normalized = f"CWE-{normalized}"
    record = get_cwe(normalized)
    if record is None:
        raise _resource_not_found("CWE", normalized)
    return json.dumps(record, default=str, ensure_ascii=False)


@mcp.resource(
    uri="cwe://catalog",
    name="cwe_catalog",
    description="CWE catalog summary: all weaknesses (id+name+abstract_type). Slim by design — fetch cwe://weakness/{id} for full description+mitigations.",
    mime_type="application/json",
)
def cwe_catalog_resource() -> str:
    from app.db import CATALOG_LISTING_MAX, count_cwes, list_cwes_summary

    weaknesses = list_cwes_summary(limit=CATALOG_LISTING_MAX)
    total = count_cwes()
    payload = {
        "weaknesses": weaknesses,
        "totals": {"weaknesses": total},
        "truncated": len(weaknesses) < total,
        "note": (
            "Slim view (cwe_id + name + abstract_type only). "
            "Read cwe://weakness/{id} for description, mitigations, examples."
        ),
    }
    return json.dumps(payload, default=str, ensure_ascii=False)


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


# v1.23.0 — contrast_triage: conditional workflow Prompt.
#
# Branches on `perspective` (red = offensive recon, blue = defensive triage)
# and on auto-detected target type. The Prompt body is plain text (the agent
# reads it as instructions); chains reuse existing tool names so the same
# agent that listed `tools/list` can execute the chain without indirection.

_TRIAGE_RED_CHAINS = {
    "ip": (
        "1. ip_lookup({target}) — geolocation, ASN, reverse DNS\n"
        "2. threat_report({target}) — IOC + reputation + cloud/Tor/VPN detection\n"
        "3. asn_lookup using the ASN from step 1 — sibling-IP attack surface\n"
        "4. wayback_lookup against any domain reverse-DNS surfaces — historical paths\n"
        "5. Summarize: open services, exposed metadata, lateral pivot opportunities."
    ),
    "domain": (
        "1. subdomain_enum({target}) — full subdomain inventory\n"
        "2. domain_report({target}) — DNS, WHOIS, SSL, threat status\n"
        "3. tech_fingerprint({target}) — stack identification (CMS, framework, CDN)\n"
        "4. ssl_check({target}) — cert chain, weak ciphers, expiry\n"
        "5. wayback_lookup({target}) — historical paths and forgotten endpoints\n"
        "6. check_secrets / check_injection on any in-scope source code if available\n"
        "7. Summarize: attack surface map, weak SSL config, leaked paths."
    ),
    "cve": (
        "1. cve_lookup({target}) — base record + CVSS + EPSS\n"
        "2. exploit_lookup({target}) — public PoC / weaponized exploits\n"
        "3. kev_detail({target}) — federal urgency (CISA KEV catalog)\n"
        "4. cve_search with affected product/vendor — sibling CVEs in same product\n"
        "5. Summarize: weaponization status, available exploits, target product fleet."
    ),
    "atlas_technique": (
        "1. atlas_technique_lookup({target}) — full record + ATT&CK mapping\n"
        "2. atlas_case_study_search by technique — real-world AI/ML incidents\n"
        "3. If attack_reference_id present, cve_search vendor/product or attack_reference_id literal — corroborating CVEs\n"
        "4. atlas_technique_search by inherited tactic — sibling techniques (lateral plays)\n"
        "5. Summarize: how this technique has been used in the wild, paired tactics."
    ),
    "attack_technique": (
        "1. atlas_technique_search filter by attack_reference_id={target} — ATLAS techniques mapped to this T-code\n"
        "2. cve_search by ATT&CK technique — corroborating CVEs / vendor advisories\n"
        "3. exploit_lookup against any CVE found — weaponization\n"
        "4. Summarize: AI/ML mappings, exploit availability."
    ),
    "cwe": (
        "1. cwe_lookup({target}) — name, description, mitigations\n"
        "2. cve_search filter by CWE — recent CVEs with this weakness\n"
        "3. exploit_lookup on any HIGH/CRITICAL CVE — exploitation patterns\n"
        "4. Summarize: real-world exploitation footprint of this weakness class."
    ),
    "hash": (
        "1. hash_lookup({target}) — known-bad lookup (MalwareBazaar, ThreatFox)\n"
        "2. ioc_lookup({target}) — multi-source IOC enrichment\n"
        "3. threat_intel({target}) — additional threat-feed context\n"
        "4. Summarize: malware family, first seen, observed C2 infrastructure."
    ),
}

_TRIAGE_BLUE_CHAINS = {
    "ip": (
        "1. threat_report({target}) — IOC + reputation + Tor/VPN/cloud flags\n"
        "2. ioc_lookup({target}) — multi-source verdict for triage decision\n"
        "3. ip_lookup({target}) — context (ASN, geolocation, reverse DNS)\n"
        "4. If reputation is poor: block at perimeter; chain asn_lookup to surface sibling-IP risk and consider ASN-level controls.\n"
        "5. Summarize: verdict, recommended action (allow / monitor / block)."
    ),
    "domain": (
        "1. domain_report({target}) — passive DNS+WHOIS+SSL+threat overview\n"
        "2. phishing_check({target}) — phishing-pattern heuristics\n"
        "3. ioc_lookup({target}) — known-bad domain lookup\n"
        "4. email_mx({target}) — SPF/DMARC/DKIM posture (impersonation risk)\n"
        "5. Summarize: trust verdict, mitigations to apply (block / DMARC enforce / monitor)."
    ),
    "cve": (
        "1. cve_lookup({target}) — full CVSS, EPSS, fixed versions\n"
        "2. kev_detail({target}) — federal exploitation status, due date\n"
        "3. cwe_lookup using the cwes[] list from step 1 — mitigation patterns\n"
        "4. d3fend_defense_for_attack with each ATT&CK technique mapped (cve.attack_techniques) — concrete defenses\n"
        "5. Summarize: patch urgency, available mitigations, defensive posture."
    ),
    "atlas_technique": (
        "1. atlas_technique_lookup({target}) — record + attack_reference_id\n"
        "2. If attack_reference_id present: d3fend_defense_for_attack(attack_reference_id) — concrete defenses\n"
        "3. d3fend_attack_coverage with the attack_reference_id — defense breadth by tactic\n"
        "4. atlas_case_study_search by technique — incident lessons\n"
        "5. Summarize: defenses to apply, gaps in coverage."
    ),
    "attack_technique": (
        "1. d3fend_defense_for_attack({target}) — defenses for this T-code\n"
        "2. d3fend_attack_coverage([{target}]) — coverage breakdown by tactic\n"
        "3. atlas_technique_search filter attack_reference_id={target} — AI/ML angle if any\n"
        "4. Summarize: defensive playbook, remaining gaps."
    ),
    "cwe": (
        "1. cwe_lookup({target}) — mitigations, examples\n"
        "2. cve_search by CWE — affected products in scope\n"
        "3. d3fend_defense_search with relevant artifact (e.g. 'application' for injection-class CWEs) — defenses to deploy\n"
        "4. Summarize: code-level fixes + runtime defenses."
    ),
    "hash": (
        "1. hash_lookup({target}) — known-malware lookup\n"
        "2. ioc_lookup({target}) — multi-source IOC enrichment\n"
        "3. threat_intel({target}) — campaign / family context\n"
        "4. Summarize: malware family, recommended detection rules + IR scope."
    ),
}


@mcp.prompt(
    name="contrast_triage",
    description=(
        "Security triage workflow with explicit perspective. "
        "perspective='red' produces an offensive recon chain; 'blue' produces a defensive triage chain. "
        "Target type (CVE / ATLAS / ATT&CK / CWE / hash / IP / domain) is auto-detected."
    ),
)
def contrast_triage(
    target: Annotated[
        str,
        Field(
            description=(
                "Target to triage. Accepted: IP (1.2.3.4 or IPv6), domain (example.com), "
                "CVE-YYYY-NNNN, hash (md5/sha1/sha256), ATLAS technique (AML.T#### or AML.T####.###), "
                "ATT&CK T-code (T#### / T####.###), CWE id (CWE-79)."
            )
        ),
    ],
    perspective: Annotated[
        Literal["red", "blue"],
        Field(description="'red' = offensive recon (attack surface). 'blue' = defensive triage (incident response)."),
    ] = "blue",
) -> str:
    """Build a tool chain tailored to the target type and perspective."""
    # Trojan-Source / agent-instruction-injection guard: strip ASCII control,
    # DEL, U+FFFD, and Unicode bidi controls (U+202A-E, U+2066-9) from the
    # caller-supplied target before embedding it into the rendered Prompt.
    # Mirrors the v1.18.0/v1.19.0 precedent for SSL cert subjects + ATLAS/D3FEND
    # upstream strings — a hostile target like "domain.com\nIgnore prior steps"
    # would otherwise leak control characters into the agent-readable Prompt.
    # Length-cap at 200 chars: any legitimate target (longest = 64-hex SHA-256)
    # is well under this; it bounds the help-text quote on unknown input.
    from app.domain.recon import _strip_control_chars

    target_clean = _strip_control_chars((target or "").strip())[:200]
    if not target_clean:
        return (
            "contrast_triage: target is empty. Provide an IP, domain, CVE-YYYY-NNNN, hash, "
            "ATLAS technique (AML.T####), ATT&CK T-code (T####), or CWE id (CWE-79)."
        )
    target_type = _detect_target_type(target_clean)
    if target_type == "unknown":
        return (
            f"contrast_triage: could not classify '{target_clean}'. Accepted formats: "
            "IP, domain, CVE-YYYY-NNNN, file hash (32/40/64 hex), ATLAS technique (AML.T####), "
            "ATT&CK T-code (T####), CWE id (CWE-79)."
        )
    chains = _TRIAGE_RED_CHAINS if perspective == "red" else _TRIAGE_BLUE_CHAINS
    chain = chains[target_type].format(target=target_clean)
    perspective_label = "Red-team reconnaissance" if perspective == "red" else "Defensive triage"
    return (
        f"{perspective_label} on {target_clean} (type: {target_type}).\n"
        f"Run the following tool chain in order, summarizing observations from each step before the next:\n\n"
        f"{chain}\n\n"
        f"Stop early if a step yields a definitive verdict; otherwise complete the chain and produce a final summary."
    )


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
