"""Domain Intelligence API routes — /v1/domain/*, /v1/dns/*, /v1/whois/*, etc."""

import atexit
import logging
import socket
import ssl as _ssl
import threading
import time as _time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Annotated
from urllib.parse import urlparse as _urlparse


class AsnUpstreamError(Exception):
    def __init__(self, upstream: str, reason: str):
        self.upstream = upstream
        self.reason = reason
        super().__init__(f"{upstream}: {reason}")


from fastapi import APIRouter, HTTPException, Path, Query, Request

_reputation_pool = ThreadPoolExecutor(max_workers=3)
_aia_pool = ThreadPoolExecutor(max_workers=2)
# Dedicated pool for _fetch_asn_country inner fan-out (country + holder), keeps
# _reputation_pool free for top-level submissions and avoids nested-submit
# deadlock when many ip_lookup requests arrive concurrently.
_ip_enrichment_pool = ThreadPoolExecutor(max_workers=4)
# atexit runs handlers in LIFO order. _ip_enrichment_pool receives submits from
# tasks running inside _reputation_pool (nested fan-out), so it must shut down
# LAST — register it FIRST.
atexit.register(_ip_enrichment_pool.shutdown, wait=False)
atexit.register(_aia_pool.shutdown, wait=False)
atexit.register(_reputation_pool.shutdown, wait=False)

import httpx as _httpx
import ratelimit

_ripe_client = _httpx.Client(timeout=_httpx.Timeout(7.0, connect=3.0), follow_redirects=False)
from auth import authenticate
from config import (
    BULK_OVERALL_TIMEOUT,
    BULK_PER_DOMAIN_TIMEOUT,
    COST_AUDIT,
    COST_THREAT_REPORT,
    ENRICHMENT_DAILY_LIMIT,
    RECON_TIMEOUT,
    UPGRADE_URL,
)
from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID
from db import get_cached_domain, get_cached_domain_with_age, get_cached_ip_with_age, save_cached_domain, save_cached_ip
from domain.archive import wayback_lookup
from domain.ip_intel import check_cloud_provider, check_firehol, check_tor_exit, score_ip
from domain.recon import (
    _ssl_grade,
    _ssrf_http,
    check_ct_logs,
    check_disposable,
    detect_mail_provider,
    dns_lookup,
    email_security,
    enumerate_subdomains,
    fetch_live_page,
    full_domain_report,
    ip_enrichment,
    phone_lookup,
    quick_dns_a,
    ssl_info,
    whois_lookup,
)
from domain.reputation import check_abuseipdb, check_shodan
from domain.threat import check_urlhaus
from domain.username import username_lookup
from pydantic import BaseModel, Field
from schemas import (
    AsnResponse,
    AuditResponse,
    BulkDomainResponse,
    CertsResponse,
    DisposableResponse,
    DnsResponse,
    DomainReportResponse,
    EmailMxResponse,
    IpLookupResponse,
    MonitorResponse,
    PhoneLookupResponse,
    SslResponse,
    SubdomainsResponse,
    TechResponse,
    ThreatReportResponse,
    ThreatResponse,
    UsernameLookupResponse,
    Verdict,
    VulnsResponse,
    WaybackResponse,
    WhoisResponse,
)
from validation import _is_valid_format, clean_domain, get_client_ip, is_private_ip, is_valid_ip, validate_domain

logger = logging.getLogger("contrastapi")


# === Canonical path-param type aliases (reused across MCP-exposed routes) ===

DomainPath = Annotated[
    str,
    Path(
        description=(
            "Registrable domain name, e.g. 'example.com'. No scheme, no path, no port. "
            "Punycode (xn--*) and IDNs accepted; subdomains allowed (e.g. 'api.example.com'). "
            "Validated by validate_domain() — wildcard '*' and raw IPs rejected."
        ),
    ),
]

IpPath = Annotated[
    str,
    Path(
        description=(
            "IPv4 or IPv6 address, e.g. '8.8.8.8' or '2001:4860:4860::8888'. "
            "Private/reserved/loopback/link-local ranges are rejected with 400."
        ),
    ),
]


def _safe_rdn(s: str) -> str:
    """Strip control chars from RFC 4514 DN strings to prevent log/response injection."""
    return "".join(c for c in s if c >= " " and c != "\x7f")[:512]


def _safe_url(url: str) -> str:
    """Strip CRLF / control chars from URLs before logging or returning in responses."""
    return "".join(c for c in url if c >= " " and c != "\x7f")[:2048]


def _fetch_intermediate(url):
    resp = _ssrf_http.get(url, timeout=5.0)
    if resp.status_code != 200:
        raise ValueError(f"HTTP {resp.status_code}")
    body = resp.content[:10240]
    for loader in (x509.load_der_x509_certificate, x509.load_pem_x509_certificate):
        try:
            return loader(body)
        except Exception:
            continue
    raise ValueError("cert parse failed: unsupported format")


# Headers stripped from audit response to prevent leaking target-site secrets
# into API output (e.g. user auditing their own site with active session).
_AUDIT_SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-session-token",
    }
)

router = APIRouter(prefix="/v1", tags=["Domain Intelligence"])


@router.get("/", include_in_schema=False)
def api_root(request: Request):
    """Available endpoints when someone hits /v1/ directly."""
    authenticate(request, "/v1")
    return {
        "api": "ContrastAPI",
        "docs": "https://github.com/UPinar/contrastapi/blob/main/docs/ENDPOINTS.md",
        "endpoints": {
            "domain": {"path": "/v1/domain/example.com", "method": "GET", "description": "Full security report"},
            "dns": {"path": "/v1/dns/example.com", "method": "GET", "description": "DNS records"},
            "ssl": {"path": "/v1/ssl/example.com", "method": "GET", "description": "SSL/TLS analysis"},
            "whois": {"path": "/v1/whois/example.com", "method": "GET", "description": "WHOIS data"},
            "subdomains": {
                "path": "/v1/subdomains/example.com",
                "method": "GET",
                "description": "Subdomain enumeration",
            },
            "tech": {"path": "/v1/tech/example.com", "method": "GET", "description": "Technology fingerprint"},
            "ip": {
                "path": "/v1/ip/8.8.8.8",
                "method": "GET",
                "description": "IP reputation (expects IP address, not domain)",
            },
            "cve": {"path": "/v1/cve/CVE-2024-3094", "method": "GET", "description": "CVE lookup with EPSS/KEV"},
            "cve_search": {"path": "/v1/cves?keyword=apache", "method": "GET", "description": "Search CVEs by keyword"},
            "check_secrets": {"path": "/v1/check/secrets", "method": "POST", "description": "Detect secrets in code"},
            "check_headers": {"path": "/v1/check/headers", "method": "POST", "description": "Validate HTTP headers"},
            "check_injection": {
                "path": "/v1/check/injection",
                "method": "POST",
                "description": "Detect injection flaws",
            },
        },
        "quick_start": "curl https://api.contrastcyber.com/v1/domain/example.com",
    }


def _validate_and_auth(request: Request, raw_domain: str) -> tuple[str, str, dict]:
    """Authenticate, clean domain, validate domain. Returns (domain, resolved_ip, auth_ctx).

    Auth runs first to reject unauthenticated/rate-limited requests before DNS resolution.
    """
    domain = clean_domain(raw_domain)
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain")
    if is_valid_ip(raw_domain):
        raise HTTPException(
            status_code=400,
            detail=f"'{raw_domain}' is an IP address, not a domain. Use /v1/ip/{raw_domain} instead.",
        )
    if not _is_valid_format(domain):
        raise HTTPException(status_code=400, detail="Invalid domain")
    auth_ctx = authenticate(request, request.url.path)
    resolved_ip = validate_domain(domain)
    if not resolved_ip:
        raise HTTPException(status_code=422, detail="Could not resolve this domain. DNS resolution failed.")
    return domain, resolved_ip, auth_ctx


def _dns_summary(records: dict, domain: str) -> str:
    """Build a one-line DNS record summary."""
    parts = []
    for rtype in ("a", "aaaa", "ns", "mx", "txt", "cname", "soa"):
        recs = records.get(rtype)
        if recs:
            count = len(recs) if isinstance(recs, list) else 1
            parts.append(f"{count} {rtype.upper()}")
    return (", ".join(parts) + f" records for {domain}") if parts else f"No records for {domain}"


def _whois_summary(whois: dict, domain: str) -> str:
    """Build a one-line WHOIS summary."""
    parts = [domain]
    if whois.get("registrar"):
        parts.append(whois["registrar"])
    if whois.get("expiry_date"):
        parts.append(f"expires {whois['expiry_date']}")
    return " — ".join(parts)


def _domain_verdict(report: dict, age_seconds: int, lite: bool) -> Verdict:
    """Build verdict metadata for domain_report responses."""
    queried = ["dns", "ssl"]
    unavailable: list[str] = []
    if not lite:
        queried.extend(["whois", "subdomains", "ct_logs", "urlhaus"])
        threat = report.get("threat", {}) or {}
        if threat.get("urlhaus_status") == "error":
            unavailable.append("urlhaus")
        if "reputation" in report:
            queried.append("reputation")
            # If reputation fetch failed, report["reputation"] is absent — we cannot
            # distinguish quota-blocked from fetch-failed from this signal alone.
    else:
        unavailable.extend(["whois", "subdomains", "ct_logs", "urlhaus", "reputation"])
    return Verdict(
        deterministic=True,
        falsifiable_fields=["dns", "whois", "ssl", "subdomains", "certificates"],
        data_age_seconds=age_seconds,
        sources_queried=queried,
        sources_unavailable=unavailable,
        completeness="complete" if (not unavailable or lite) else "partial",
    )


def _ip_verdict(
    age_seconds: int | None,
    internetdb_failed: bool,
    reputation_attempted: bool,
    reputation_failed: bool,
    ripe_failed: bool = False,
    firehol_attempted: bool = False,
    firehol_failed: bool = False,
) -> Verdict:
    """Build verdict metadata for ip_lookup responses."""
    queried = ["internetdb", "ripe_stat"]
    if firehol_attempted:
        queried.append("firehol")
    if reputation_attempted:
        queried.append("reputation")
    unavailable: list[str] = []
    if internetdb_failed:
        unavailable.append("internetdb")
    if ripe_failed:
        unavailable.append("ripe_stat")
    if firehol_attempted and firehol_failed:
        unavailable.append("firehol")
    if reputation_attempted and reputation_failed:
        unavailable.append("reputation")
    return Verdict(
        deterministic=True,
        falsifiable_fields=[
            "ptr",
            "asn",
            "asn_name",
            "country",
            "ports",
            "vulns",
            "hostnames",
            "cloud_provider",
            "tor_exit",
            "risk_score",
        ],
        data_age_seconds=age_seconds,
        sources_queried=queried,
        sources_unavailable=unavailable,
        completeness="partial" if unavailable else "complete",
    )


def _threat_verdict(unavailable: bool = False) -> Verdict:
    """Build verdict metadata for threat_intel responses (live URLhaus query, age=0)."""
    unavailable_list = ["urlhaus"] if unavailable else []
    return Verdict(
        deterministic=True,
        falsifiable_fields=["urlhaus_status", "url_count", "urls_online", "threat_types"],
        data_age_seconds=0,
        sources_queried=["urlhaus"],
        sources_unavailable=unavailable_list,
        completeness="partial" if unavailable else "complete",
    )


def _from_cache(domain: str, key: str, tier: str) -> dict | None:
    """Try to extract a section from a cached full domain report.

    Matches the tier-prefixed cache keys used by domain_report/bulk/audit —
    otherwise sub-endpoints (dns/whois/subdomains/certs) would always miss.
    """
    cached = get_cached_domain(f"{tier}:{domain}")
    if cached and key in cached:
        return cached[key]
    return None


@router.get(
    "/domain/{domain}",
    operation_id="domain_report",
    response_model=DomainReportResponse,
    response_model_exclude_none=True,
)
@router.post(
    "/domain/{domain}",
    operation_id="domain_report_post",
    response_model=DomainReportResponse,
    response_model_exclude_none=True,
    include_in_schema=False,
)
def domain_report(
    domain: DomainPath,
    request: Request,
    lite: Annotated[
        bool,
        Query(
            description=(
                "Fast subset mode. When true, skips WHOIS, subdomains, CT logs, URLhaus, and reputation. "
                "Returns in ~250ms instead of 3-10s. Use for high-volume triage."
            ),
        ),
    ] = False,
):
    """Full domain intelligence report with DNS, WHOIS, SSL, subdomains, WAF. Use ?lite=true for fast subset."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)

    # Separate cache keys for lite vs full, segregated by tier to prevent
    # free-tier pro_only stubs from poisoning Pro reads (and vice versa).
    tier = auth_ctx["tier"]
    cache_key = f"{tier}:lite:{domain}" if lite else f"{tier}:{domain}"
    hit = get_cached_domain_with_age(cache_key)
    if hit is not None:
        cached, age = hit
        return {**cached, "verdict": _domain_verdict(cached, age, lite=lite)}

    client_ip = get_client_ip(request)
    try:
        result = full_domain_report(domain, resolved_ip=resolved_ip, client_ip=client_ip, lite=lite, tier=tier)
    except FuturesTimeoutError:
        raise HTTPException(status_code=504, detail="Domain report timed out — upstream services too slow") from None
    save_cached_domain(cache_key, result)
    return {**result, "verdict": _domain_verdict(result, 0, lite=lite)}


@router.get("/dns/{domain}", operation_id="dns_records", response_model=DnsResponse, response_model_exclude_none=True)
def dns_records(domain: DomainPath, request: Request):
    """DNS record lookup: A, AAAA, MX, NS, TXT, CNAME, SOA."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)
    cached = _from_cache(domain, "dns", auth_ctx["tier"])
    if cached:
        return {"domain": domain, "records": cached, "summary": _dns_summary(cached, domain)}
    records = dns_lookup(domain)
    if not records:
        raise HTTPException(status_code=404, detail=f"No DNS records found for '{domain}'")
    return {"domain": domain, "records": records, "summary": _dns_summary(records, domain)}


@router.get(
    "/email/mx/{domain}",
    operation_id="email_mx",
    response_model=EmailMxResponse,
    response_model_exclude_none=True,
)
def email_mx(domain: DomainPath, request: Request):
    """Email MX analysis — mail provider detection, SPF/DMARC/DKIM check, security grade."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)

    # Check cache
    cache_key = f"email_mx:{domain}"
    cached = get_cached_domain(cache_key)
    if cached:
        return {**cached}

    # Fetch DNS records for MX + TXT (SPF)
    records = dns_lookup(domain)
    mx_records = records.get("mx", [])
    txt_records = records.get("txt", [])

    # Detect mail provider
    provider = detect_mail_provider(mx_records)

    # Email security check (SPF/DMARC/DKIM) — run in thread with timeout
    # to prevent DKIM probing from blocking a worker (up to 19 selectors x 5s each)
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        security = pool.submit(email_security, domain, txt_records).result(timeout=RECON_TIMEOUT * 2)
    except FuturesTimeoutError:
        security = {
            "spf": None,
            "dmarc": None,
            "dkim_selectors": [],
            "grade": "F",
            "issues": ["Email security check timed out"],
        }
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    # Build summary
    parts = [domain]
    if provider:
        parts.append(f"uses {provider}")
    elif mx_records:
        parts.append(f"{len(mx_records)} MX record{'s' if len(mx_records) != 1 else ''}")
    else:
        parts.append("no MX records")

    configured = []
    if security.get("spf"):
        configured.append("SPF")
    if security.get("dmarc"):
        configured.append("DMARC")
    if security.get("dkim_selectors"):
        configured.append("DKIM")
    if configured:
        parts.append("+".join(configured) + " configured")

    parts.append(f"Grade: {security.get('grade', 'F')}")
    summary = " — ".join(parts)

    result = {
        "domain": domain,
        "mx_records": mx_records,
        "mail_provider": provider,
        "email_security": security,
        "summary": summary,
    }
    save_cached_domain(cache_key, result)
    return {**result}


def _disposable_summary(email: str, result: dict) -> str:
    """Build a one-line summary for the disposable email check."""
    if result.get("disposable"):
        provider_str = f" ({result['provider']})" if result.get("provider") else ""
        return f"{email} — disposable{provider_str}, risk: {result.get('risk_level', 'high')}"
    return f"{email} — not disposable, risk: low"


@router.get(
    "/email/disposable/{email}",
    operation_id="email_disposable",
    response_model=DisposableResponse,
    response_model_exclude_none=True,
)
def email_disposable(
    email: Annotated[
        str,
        Path(
            description=(
                "Email address to check, e.g. 'user@example.com'. "
                "The local-part is preserved in the response but only the domain is checked against "
                "the disposable-provider database and MX records."
            ),
        ),
    ],
    request: Request,
):
    """Check if an email uses a disposable/temporary email provider."""
    if "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email — must contain @")
    local_part, raw_domain = email.rsplit("@", 1)
    if not local_part or len(local_part) > 254 or any(ord(c) < 32 or ord(c) == 127 for c in local_part):
        raise HTTPException(status_code=400, detail="Invalid email local-part")
    domain = clean_domain(raw_domain)
    if not domain or not _is_valid_format(domain):
        raise HTTPException(status_code=400, detail="Invalid email domain")
    authenticate(request, request.url.path)

    # Check cache (keyed by domain — rebuild summary with current email on hit)
    cache_key = f"email_disp:{domain}"
    cached = get_cached_domain(cache_key)
    if cached:
        summary = _disposable_summary(email, cached)
        return {**cached, "email": email, "summary": summary}

    resolved_ip = validate_domain(domain)
    if not resolved_ip:
        raise HTTPException(status_code=422, detail="Could not resolve email domain. DNS resolution failed.")

    result = check_disposable(email, domain=domain)
    result["summary"] = _disposable_summary(email, result)

    save_cached_domain(cache_key, result)
    return {**result}


@router.get(
    "/phone/{number}",
    operation_id="phone_lookup",
    response_model=PhoneLookupResponse,
    response_model_exclude_none=True,
    include_in_schema=True,
)
def phone_endpoint(
    number: Annotated[
        str,
        Path(
            description=(
                "Phone number in any format (E.164 preferred, e.g. '+14155552671'; '+' URL-encoded as '%2B'). "
                "Max 50 chars. International prefix strongly recommended — without it, the country cannot be inferred."
            ),
        ),
    ],
    request: Request,
):
    """Phone number validation and intelligence — format, country, type, carrier, timezone."""
    authenticate(request, request.url.path)
    result = phone_lookup(number)
    return result


@router.get(
    "/username/{username}",
    operation_id="username_lookup",
    response_model=UsernameLookupResponse,
    response_model_exclude_none=True,
    include_in_schema=True,
)
def username_endpoint(
    username: Annotated[
        str,
        Path(
            description=(
                "Username to search across platforms. Validated against [a-z0-9._-]{1,39} — "
                "lowercased server-side. Non-matching inputs return an error in the response body "
                "(not a 400) so the agent still sees the shape."
            ),
        ),
    ],
    request: Request,
):
    """Username OSINT — check if a username exists on 16 platforms (GitHub, Reddit, X, etc.)."""
    authenticate(request, request.url.path)
    return username_lookup(username)


@router.get(
    "/whois/{domain}", operation_id="whois_lookup", response_model=WhoisResponse, response_model_exclude_none=True
)
def whois_endpoint(domain: DomainPath, request: Request):
    """WHOIS registration data for a domain."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)
    cached = _from_cache(domain, "whois", auth_ctx["tier"])
    if cached and "error" not in cached:
        return {"domain": domain, "whois": cached, "summary": _whois_summary(cached, domain)}
    result = whois_lookup(domain)
    if "error" in result:
        raise HTTPException(status_code=504, detail=result["error"])
    return {"domain": domain, "whois": result, "summary": _whois_summary(result, domain)}


@router.get(
    "/subdomains/{domain}",
    operation_id="subdomain_enum",
    response_model=SubdomainsResponse,
    response_model_exclude_none=True,
)
def subdomains(domain: DomainPath, request: Request):
    """Subdomain enumeration via DNS brute force + certificate transparency."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)
    cached = _from_cache(domain, "subdomains", auth_ctx["tier"])
    if cached:
        return {"domain": domain, **cached}
    result = enumerate_subdomains(domain)
    return {"domain": domain, **result}


@router.get("/certs/{domain}", operation_id="ct_logs", response_model=CertsResponse, response_model_exclude_none=True)
def certs(domain: DomainPath, request: Request):
    """Certificate transparency log lookup."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)
    cached = _from_cache(domain, "certificates", auth_ctx["tier"])
    if cached:
        total = cached.get("total_certificates", 0)
        summary = f"{total} certificate{'s' if total != 1 else ''} in CT logs for {domain}"
        return {"domain": domain, **cached, "summary": summary}
    result = check_ct_logs(domain)
    total = result.get("total_certificates", 0)
    summary = f"{total} certificate{'s' if total != 1 else ''} in CT logs for {domain}"
    return {"domain": domain, **result, "summary": summary}


@router.get(
    "/ssl/{domain}", operation_id="ssl_certificate", response_model=SslResponse, response_model_exclude_none=True
)
def ssl_certificate(domain: DomainPath, request: Request):
    """SSL certificate details with grade, chain, cipher, and protocol information."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)

    # Check cache (keyed as ssl:<domain> in domain_cache)
    cached = get_cached_domain(f"ssl:{domain}")
    if cached:
        return {**cached}

    try:
        ctx = _ssl.create_default_context()
        connect_host = resolved_ip or domain
        with socket.create_connection((connect_host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version() or "unknown"
                cipher_info = ssock.cipher()  # (name, protocol, bits)

                subject_dict = dict(x[0] for x in cert.get("subject", ()))
                issuer_dict = dict(x[0] for x in cert.get("issuer", ()))

                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")
                days_remaining = None
                valid = True
                if not_after:
                    try:
                        expiry_ts = _ssl.cert_time_to_seconds(not_after)
                        days_remaining = int((expiry_ts - _time.time()) / 86400)
                        if days_remaining < 0:
                            valid = False
                    except (ValueError, OverflowError):
                        pass

                san = [v for _, v in cert.get("subjectAltName", ())]

                # Grade
                grade = _ssl_grade(tls_version, days_remaining)

                # Chain: leaf from handshake, intermediates via AIA caIssuers
                chain = []
                warnings = []
                leaf_cert = None
                try:
                    der = ssock.getpeercert(binary_form=True)
                    leaf_cert = x509.load_der_x509_certificate(der)
                    chain.append(
                        {
                            "subject": _safe_rdn(leaf_cert.subject.rfc4514_string()),
                            "issuer": _safe_rdn(leaf_cert.issuer.rfc4514_string()),
                            "not_after": leaf_cert.not_valid_after_utc.replace(tzinfo=None).isoformat(),
                            "source": "handshake",
                        }
                    )
                except (ValueError, TypeError, AttributeError) as e:
                    warnings.append(f"leaf cert parse failed: {type(e).__name__}")
                    leaf_cert = None

                if leaf_cert is not None:
                    # Collect AIA caIssuers URLs (http/https only, cap at 2)
                    aia_urls: list[str] = []
                    try:
                        aia = leaf_cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
                        for desc in aia.value:
                            if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                                url = desc.access_location.value
                                if not isinstance(url, str) or len(url) > 2048:
                                    continue
                                if _urlparse(url).scheme in ("http", "https"):
                                    aia_urls.append(url)
                                if len(aia_urls) >= 2:
                                    break
                    except x509.ExtensionNotFound:
                        pass

                    if aia_urls:
                        futures = {_aia_pool.submit(_fetch_intermediate, u): u for u in aia_urls}
                        for fut, url in futures.items():
                            try:
                                ic = fut.result(timeout=7)
                                chain.append(
                                    {
                                        "subject": _safe_rdn(ic.subject.rfc4514_string()),
                                        "issuer": _safe_rdn(ic.issuer.rfc4514_string()),
                                        "not_after": ic.not_valid_after_utc.replace(tzinfo=None).isoformat(),
                                        "source": "aia_fetch",
                                    }
                                )
                            except _httpx.TimeoutException:
                                warnings.append(f"AIA fetch timeout: {_safe_url(url)}")
                            except _httpx.HTTPError:
                                warnings.append(f"AIA fetch error: {_safe_url(url)}")
                            except (ValueError, TypeError):
                                warnings.append(f"AIA parse failed: {_safe_url(url)}")
                            except Exception:
                                warnings.append(f"AIA fetch error: {_safe_url(url)}")

                cipher_dict = {}
                if cipher_info:
                    cipher_dict = {"name": cipher_info[0], "bits": cipher_info[2]}

                # Build summary
                parts = [f"{domain} — {grade}"]
                parts.append(f"{tls_version}, {issuer_dict.get('organizationName', 'unknown issuer')}")
                if days_remaining is not None:
                    parts.append(f"{days_remaining} days remaining")
                if not valid:
                    parts.append("EXPIRED")
                if warnings:
                    parts.append("(partial: chain incomplete)")

                result = {
                    "domain": domain,
                    "valid": valid,
                    "issuer": issuer_dict.get("organizationName", ""),
                    "subject": subject_dict.get("commonName", ""),
                    "not_before": not_before,
                    "not_after": not_after,
                    "days_remaining": days_remaining,
                    "serial_number": cert.get("serialNumber", ""),
                    "signature_algorithm": None,
                    "san": san,
                    "protocol": tls_version,
                    "cipher": cipher_dict,
                    "chain": chain,
                    "grade": grade,
                    "warnings": warnings,
                    "summary": ". ".join(parts),
                }

                save_cached_domain(f"ssl:{domain}", result)
                return {**result}

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.warning("SSL connection failed: %s", type(e).__name__)
        raise HTTPException(status_code=504, detail=f"Could not establish SSL connection to {domain}") from None
    except Exception as e:
        logger.warning("SSL inspection failed: %s", type(e).__name__)
        raise HTTPException(status_code=504, detail=f"SSL inspection failed for {domain}") from None


@router.get(
    "/threat/{domain}", operation_id="threat_intel", response_model=ThreatResponse, response_model_exclude_none=True
)
def threat_intel(domain: DomainPath, request: Request):
    """Threat intelligence — check domain against URLhaus for known malware URLs."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)
    result = check_urlhaus(domain)
    urlhaus_unavailable = result.get("urlhaus_status") == "error"
    urls_online = result["urls_online"]
    url_count = result["url_count"]
    if url_count == 0:
        summary = f"{domain} — no threats found in URLhaus"
    else:
        summary = f"{domain} — {url_count} URL{'s' if url_count != 1 else ''} in URLhaus ({urls_online} online)"
    return {"domain": domain, **result, "summary": summary, "verdict": _threat_verdict(unavailable=urlhaus_unavailable)}


@router.get(
    "/archive/{domain}",
    operation_id="wayback_lookup",
    response_model=WaybackResponse,
    response_model_exclude_none=True,
)
def wayback_lookup_route(domain: DomainPath, request: Request):
    """Web archive lookup — historical snapshots from the Wayback Machine."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)
    return wayback_lookup(domain)


def _ripe_country_for_ip(ip: str) -> str:
    """Fetch RIR allocation country for `ip` via RIPE Stat. Empty on failure."""
    try:
        r = _ripe_client.get(
            "https://stat.ripe.net/data/rir-stats-country/data.json",
            params={"resource": ip},
            timeout=2.5,
        )
        r.raise_for_status()
        located = r.json().get("data", {}).get("located_resources", [])
        if located:
            loc = ((located[0].get("location", "") or "").strip())[:8]
            if loc and loc != "?":
                return loc
    except Exception as e:
        logger.debug("_ripe_country_for_ip rir-stats-country failed: %s", type(e).__name__)
    return ""


def _ripe_holder_for_asn(asn_val: int) -> str:
    """Fetch holder (org name) for AS`asn_val` via RIPE Stat. Empty on failure."""
    try:
        r = _ripe_client.get(
            "https://stat.ripe.net/data/as-overview/data.json",
            params={"resource": f"AS{asn_val}"},
            timeout=2.5,
        )
        r.raise_for_status()
        return (r.json().get("data", {}).get("holder", "") or "")[:256]
    except Exception as e:
        logger.debug("_ripe_holder_for_asn as-overview failed: %s", type(e).__name__)
        return ""


def _fetch_asn_country(ip: str) -> dict:
    """Best-effort RIPE Stat ASN + country fetch for ip_lookup inline enrichment.

    Returns dict with keys:
      asn (int|None), asn_name (str), country (str), failed (bool).

    `failed=True` means RIPE Stat produced no usable data (all three fields
    empty) — callers use this to mark sources_unavailable honestly. Never
    raises. Critical path: main thread blocks ~2.5s on network-info; on
    success, two parallel futures run in `_ip_enrichment_pool` with 3.0s
    timeouts (country + holder). Cache hit with all fields populated
    short-circuits to ~0ms; partial cache hit (asn known but name or country
    missing) triggers fan-out only for the missing field(s).
    """
    cached = get_cached_domain(f"asn:{ip}")
    if cached:
        raw_cached_asn = cached.get("asn")
        # Defensive: cache writer (asn_lookup) normalises asn to int, but guard
        # against corrupted/hand-written entries — only trust plain ints in the
        # valid ASN range (0..2**32-1). `isinstance(..., int)` alone accepts
        # bool (bool subclasses int); exclude it explicitly.
        cached_asn: int | None = (
            raw_cached_asn
            if (
                isinstance(raw_cached_asn, int)
                and not isinstance(raw_cached_asn, bool)
                and 0 <= raw_cached_asn <= 0xFFFFFFFF
            )
            else None
        )
        cached_name = (cached.get("asn_name") or "")[:256]
        cached_country = ((cached.get("country") or "").strip())[:8]

        # Full cache hit — short-circuit.
        if cached_asn is not None and cached_name and cached_country:
            return {
                "asn": cached_asn,
                "asn_name": cached_name,
                "country": cached_country,
                "failed": False,
            }

        # Partial cache hit — we have asn, fill only the missing side(s) via
        # RIPE. Closes the stale-cache poisoning case where asn_lookup wrote
        # {asn, asn_name=""} without country during a transient RIPE outage.
        if cached_asn is not None:
            f_country = _ip_enrichment_pool.submit(_ripe_country_for_ip, ip) if not cached_country else None
            f_name = _ip_enrichment_pool.submit(_ripe_holder_for_asn, cached_asn) if not cached_name else None

            country_out = cached_country
            name_out = cached_name
            if f_country is not None:
                try:
                    country_out = f_country.result(timeout=3.0)
                except Exception:
                    country_out = ""
            if f_name is not None:
                try:
                    name_out = f_name.result(timeout=3.0)
                except Exception:
                    name_out = ""
            # Same honesty rule as cache-miss path: `failed` only when NO
            # useful field survives. asn from cache counts, so partial branch
            # typically stays failed=False even if refills fail — consistent
            # with cache-miss semantics where any populated field clears the
            # flag.
            return {
                "asn": cached_asn,
                "asn_name": name_out,
                "country": country_out,
                "failed": not (cached_asn or name_out or country_out),
            }

    asn: int | None = None
    country = ""
    asn_name = ""

    try:
        r = _ripe_client.get(
            "https://stat.ripe.net/data/network-info/data.json",
            params={"resource": ip},
            timeout=2.5,
        )
        r.raise_for_status()
        asns = r.json().get("data", {}).get("asns", [])
        if asns and asns[0] is not None:
            raw = str(asns[0]).strip()
            # Strict: ASCII digits only (no +/-, no unicode). Python's
            # str.isdigit() rejects sign prefixes; combined with isascii() it
            # excludes unicode-digit spoofing. ASN range 0..4294967295 fits.
            if raw.isascii() and raw.isdigit():
                try:
                    asn = int(raw)
                except (ValueError, TypeError):
                    asn = None
    except Exception:
        logger.debug("_fetch_asn_country network-info request failed")

    f_country = _ip_enrichment_pool.submit(_ripe_country_for_ip, ip)
    f_name = _ip_enrichment_pool.submit(_ripe_holder_for_asn, asn) if asn else None

    try:
        country = f_country.result(timeout=3.0)
    except Exception:
        country = ""
    if f_name is not None:
        try:
            asn_name = f_name.result(timeout=3.0)
        except Exception:
            asn_name = ""

    failed = not (asn or asn_name or country)
    return {"asn": asn, "asn_name": asn_name, "country": country, "failed": failed}


@router.get("/ip/{ip}", operation_id="ip_lookup", response_model=IpLookupResponse, response_model_exclude_none=True)
def ip_lookup(ip: IpPath, request: Request):
    """IP intelligence — reverse DNS, ASN + country (RIPE Stat), open ports, vulnerabilities, hostnames (Shodan InternetDB), cloud provider, Tor exit detection, and reputation (FireHOL level1 blocklist on Free tier; +AbuseIPDB + Shodan on Pro)."""
    if not is_valid_ip(ip):
        if "." in ip and not ip.replace(".", "").isdigit():
            raise HTTPException(
                status_code=400, detail=f"'{ip}' looks like a domain, not an IP. Use /v1/domain/{ip} instead."
            )
        raise HTTPException(status_code=400, detail="Invalid IP address")
    if is_private_ip(ip):
        raise HTTPException(status_code=400, detail="Private/reserved IP addresses are not allowed")
    auth_ctx = authenticate(request, "/v1/ip")
    client_ip = get_client_ip(request)

    # Kick ASN/country fetch in parallel with the rest of the critical path.
    f_asn_country = _reputation_pool.submit(_fetch_asn_country, ip)

    try:
        from domain.recon import _dns_call_with_timeout

        addr_result, addr_err = _dns_call_with_timeout(socket.gethostbyaddr, ip)
        ptr = addr_result[0] if addr_result and not addr_err else None
    except (socket.herror, socket.gaierror, OSError):
        ptr = None

    enrichment = ip_enrichment(ip)
    internetdb_failed = enrichment.pop("internetdb_status", "ok") == "error"
    ports = enrichment.get("ports", [])
    vulns = enrichment.get("vulns", [])
    hostnames = enrichment.get("hostnames", [])

    # Reputation enrichment (rate-limited per client IP)
    reputation = {}
    rep_age: int | None = None
    reputation_attempted = False
    reputation_failed = False
    firehol_attempted = False
    firehol_failed = False
    hit = get_cached_ip_with_age(ip)
    if hit is not None:
        reputation, rep_age = hit
        reputation_attempted = True
    elif auth_ctx["tier"] == "pro" and ratelimit.check_limit(
        store_name="enrichment",
        key=client_ip,
        max_requests=ENRICHMENT_DAILY_LIMIT,
        window_seconds=86400,
    ):
        reputation_attempted = True
        firehol_attempted = True
        try:
            f_ab = _reputation_pool.submit(check_abuseipdb, ip)
            f_sh = _reputation_pool.submit(check_shodan, ip)
            f_fh = _ip_enrichment_pool.submit(check_firehol, ip)
            firehol_result = f_fh.result(timeout=RECON_TIMEOUT + 2)
            reputation = {
                "firehol": firehol_result,
                "abuseipdb": f_ab.result(timeout=RECON_TIMEOUT + 2),
                "shodan": f_sh.result(timeout=RECON_TIMEOUT + 2),
            }
            if firehol_result.get("status") == "unavailable":
                firehol_failed = True
            save_cached_ip(ip, reputation)
            rep_age = 0
        except Exception as e:
            logger.warning("Reputation enrichment failed: %s", type(e).__name__)
            reputation = {}
            reputation_failed = True
            ratelimit.refund("enrichment", client_ip)
    elif auth_ctx["tier"] != "pro":
        firehol_result = check_firehol(ip)
        firehol_attempted = True
        reputation = {
            "firehol": firehol_result,
            "abuseipdb": {
                "status": "pro_only",
                "reason": "AbuseIPDB enrichment requires Pro tier",
                "upgrade_url": UPGRADE_URL,
            },
            "shodan": {
                "status": "pro_only",
                "reason": "Shodan enrichment requires Pro tier",
                "upgrade_url": UPGRADE_URL,
            },
        }
        if firehol_result.get("status") == "unavailable":
            firehol_failed = True
        reputation_attempted = True

    try:
        cloud_provider = check_cloud_provider(ip)
    except Exception:
        cloud_provider = None
    try:
        tor_exit = check_tor_exit(ip)
    except Exception:
        tor_exit = False

    try:
        asn_data = f_asn_country.result(timeout=6.0)
    except Exception:
        logger.debug("_fetch_asn_country future timed out or failed")
        asn_data = {"asn": None, "asn_name": "", "country": "", "failed": True}

    asn_val = asn_data.get("asn")
    asn_name_val = asn_data.get("asn_name") or ""
    country_val = asn_data.get("country") or ""
    ripe_failed = bool(asn_data.get("failed"))

    parts = [f"{ip} → {ptr}" if ptr else f"{ip} — no PTR record"]
    if asn_val:
        parts.append(f"AS{asn_val} ({asn_name_val})" if asn_name_val else f"AS{asn_val}")
    if country_val:
        parts.append(country_val)
    if ports:
        parts.append(f"{len(ports)} open ports")
    if vulns:
        parts.append(f"{len(vulns)} known vulnerabilities")
    if hostnames:
        parts.append(f"{len(hostnames)} hostnames")
    if cloud_provider:
        parts.append(f"hosted on {cloud_provider}")
    if tor_exit:
        parts.append("Tor exit node")

    result = {
        "ip": ip,
        "ptr": ptr,
        "asn": asn_val,
        "asn_name": asn_name_val or None,
        "country": country_val or None,
        **enrichment,
        "cloud_provider": cloud_provider,
        "tor_exit": tor_exit if tor_exit else None,
        "risk_score": score_ip(reputation or None, ports, ptr, cloud_provider, tor_exit),
        "summary": ". ".join(parts),
    }
    if reputation:
        result["reputation"] = reputation
    result["verdict"] = _ip_verdict(
        rep_age,
        internetdb_failed,
        reputation_attempted,
        reputation_failed,
        ripe_failed,
        firehol_attempted=firehol_attempted,
        firehol_failed=firehol_failed,
    )
    return result


@router.get(
    "/tech/{domain}", operation_id="tech_fingerprint", response_model=TechResponse, response_model_exclude_none=True
)
def tech_fingerprint(domain: DomainPath, request: Request):
    """Technology fingerprinting — detect CMS, frameworks, servers, CDNs, analytics."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)
    page = fetch_live_page(domain)
    if "error" in page:
        raise HTTPException(status_code=504, detail=page["error"])
    from domain.tech import detect_technologies

    result = detect_technologies(page["headers"], page.get("html"))
    return {"domain": domain, **result}


@router.get(
    "/monitor/{domain}", operation_id="domain_monitor", response_model=MonitorResponse, response_model_exclude_none=True
)
def domain_monitor(domain: DomainPath, request: Request):
    """Lightweight health check — DNS up/down, SSL status, risk grade from cache. Designed for high-frequency polling."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)

    # Quick DNS A record check
    dns_a = quick_dns_a(domain)
    is_up = dns_a is not None and len(dns_a) > 0

    # SSL info (single TLS handshake)
    ssl_days = None
    ssl_grade = None
    try:
        ssl_result = ssl_info(domain, resolved_ip)
        if "error" not in ssl_result:
            ssl_days = ssl_result.get("days_remaining")
            ssl_grade = ssl_result.get("grade")
    except Exception as e:
        logger.debug("ssl_info failed: %s", type(e).__name__)

    # Compare against cached full report
    dns_changed = None
    risk_grade = None
    risk_score = None
    last_full_report = None
    cached = get_cached_domain(f"{auth_ctx['tier']}:{domain}")
    if cached:
        last_full_report = cached.get("fetched_at")
        risk = cached.get("risk", {})
        risk_grade = risk.get("grade")
        risk_score = risk.get("score")
        cached_a = cached.get("dns", {}).get("a")
        if cached_a is not None and dns_a is not None:
            dns_changed = sorted(dns_a) != sorted(cached_a)

    # Build summary
    parts = [f"{domain} is {'up' if is_up else 'DOWN'}"]
    if ssl_grade and ssl_days is not None:
        parts.append(f"SSL {ssl_grade} ({ssl_days} days)")
    if risk_grade:
        parts.append(f"Grade {risk_grade}")
    if dns_changed is True:
        parts.append("DNS CHANGED")
    elif dns_changed is False:
        parts.append("DNS unchanged")

    return {
        "domain": domain,
        "is_up": is_up,
        "ssl_days_remaining": ssl_days,
        "ssl_grade": ssl_grade,
        "dns_a": dns_a,
        "dns_changed": dns_changed,
        "risk_grade": risk_grade,
        "risk_score": risk_score,
        "last_full_report": last_full_report,
        "summary": ". ".join(parts),
    }


@router.get(
    "/domain/{domain}/vulns",
    operation_id="domain_vulns",
    response_model=VulnsResponse,
    response_model_exclude_none=True,
)
def domain_vulns(domain: DomainPath, request: Request):
    """Tech stack vulnerability scan — detect technologies, then look up CVEs for each."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)

    page = fetch_live_page(domain)
    if "error" in page:
        raise HTTPException(status_code=504, detail=page["error"])

    from db import search_cves_by_product
    from domain.tech import detect_technologies

    tech_result = detect_technologies(page["headers"], page.get("html"))
    technologies = tech_result.get("technologies", [])

    vulnerabilities = []
    total_cves = 0
    techs_with_cves = 0

    for tech in technologies:
        name = tech["name"]
        version = tech.get("version")
        limit = 10 if version else 5
        cves = search_cves_by_product(name, version=version, limit=limit)

        cve_items = [
            {
                "cve_id": c["cve_id"],
                "severity": c.get("severity"),
                "cvss_v3": c.get("cvss_v3"),
                "epss_score": c.get("epss_score"),
                "in_kev": bool(c.get("in_kev")),
            }
            for c in cves
        ]
        if cve_items:
            techs_with_cves += 1
        total_cves += len(cve_items)
        vulnerabilities.append(
            {
                "technology": name,
                "version": version,
                "cve_count": len(cve_items),
                "cves": cve_items,
            }
        )

    scanned = len(technologies)
    if total_cves:
        summary = f"{total_cves} CVEs found across {techs_with_cves} of {scanned} technologies scanned"
    else:
        summary = f"No known CVEs found across {scanned} technologies scanned"

    return {
        "domain": domain,
        "technologies_scanned": scanned,
        "total_cves": total_cves,
        "vulnerabilities": vulnerabilities,
        "summary": summary,
    }


@router.get("/asn/{target}", operation_id="asn_lookup", response_model=AsnResponse, response_model_exclude_none=True)
def asn_lookup(
    target: Annotated[
        str,
        Path(
            description=(
                "ASN or IP. Accepts 'AS13335', '13335', or an IPv4/IPv6 address. "
                "For IP input, the response resolves the containing ASN via RIPE Stat."
            ),
        ),
    ],
    request: Request,
):
    """ASN lookup — resolve target (domain or IP) to its Autonomous System Number, holder name, and announced prefixes."""
    import ipaddress

    authenticate(request, "/v1/asn")

    # Determine IP from target
    resolved_ip = None
    ip = None
    if is_valid_ip(target):
        if is_private_ip(target):
            raise HTTPException(status_code=400, detail="Private/reserved IP addresses are not allowed")
        ip = target
    else:
        domain = clean_domain(target)
        if not domain:
            raise HTTPException(status_code=400, detail="Invalid domain or IP address")
        a_records = quick_dns_a(domain)
        if not a_records:
            raise HTTPException(status_code=422, detail=f"Could not resolve domain '{target}' to an IP address")
        ip = a_records[0]
        resolved_ip = ip

    # Check cache
    cache_key = f"asn:{ip}"
    cached = get_cached_domain(cache_key)
    if cached:
        result = {**cached, "target": target}
        if resolved_ip:
            result["resolved_ip"] = resolved_ip
        elif "resolved_ip" in result:
            del result["resolved_ip"]
        return result

    # Fetch ASN from RIPE Stat
    try:
        r1 = _ripe_client.get(
            "https://stat.ripe.net/data/network-info/data.json",
            params={"resource": ip},
            timeout=5.0,
        )
        r1.raise_for_status()
        asn_data = r1.json().get("data", {})
        asn_raw = asn_data.get("asns", [None])
        if not asn_raw or not asn_raw[0]:
            raise HTTPException(status_code=404, detail=f"No ASN found for {ip}")
        try:
            asn = int(asn_raw[0])
        except (ValueError, TypeError):
            raise HTTPException(status_code=404, detail=f"Invalid ASN value for {ip}") from None
    except HTTPException:
        raise
    except Exception as e:
        logger.warning("RIPE network-info failed: %s", type(e).__name__)
        raise HTTPException(status_code=504, detail="Failed to look up ASN from RIPE Stat") from None

    # Fetch ASN holder name and prefixes in parallel
    asn_name = ""
    ipv4_prefixes = []
    ipv6_prefixes = []

    def _fetch_overview():
        try:
            r = _ripe_client.get(
                "https://stat.ripe.net/data/as-overview/data.json",
                params={"resource": f"AS{asn}"},
                timeout=5.0,
            )
            r.raise_for_status()
            asn_name_val = r.json().get("data", {}).get("holder", "")
            return asn_name_val
        except (_httpx.HTTPError, _httpx.TimeoutException, ValueError, KeyError, TypeError) as e:
            raise AsnUpstreamError("as-overview", type(e).__name__) from e

    def _fetch_prefixes():
        try:
            r = _ripe_client.get(
                "https://stat.ripe.net/data/announced-prefixes/data.json",
                params={"resource": f"AS{asn}"},
                timeout=5.0,
            )
            r.raise_for_status()
            prefixes = r.json().get("data", {}).get("prefixes", [])
            v4 = []
            v6 = []
            for p in prefixes:
                prefix = p.get("prefix", "")
                if not prefix:
                    continue
                try:
                    net = ipaddress.ip_network(prefix, strict=False)
                    if net.version == 4:
                        v4.append({"prefix": prefix})
                    else:
                        v6.append({"prefix": prefix})
                except ValueError:
                    continue
            return v4, v6
        except (_httpx.HTTPError, _httpx.TimeoutException, ValueError, KeyError, TypeError) as e:
            raise AsnUpstreamError("announced-prefixes", type(e).__name__) from e

    f_overview = _reputation_pool.submit(_fetch_overview)
    f_prefixes = _reputation_pool.submit(_fetch_prefixes)

    warnings: list[str] = []

    try:
        asn_name = f_overview.result(timeout=7)
    except AsnUpstreamError as e:
        asn_name = ""
        warnings.append(f"{e.upstream}: {e.reason}")
        logger.warning("ASN upstream failure: %s %s", e.upstream, e.reason)
    except FuturesTimeoutError:
        asn_name = ""
        warnings.append("as-overview: timeout")
        logger.warning("ASN upstream failure: as-overview FuturesTimeoutError")

    try:
        ipv4_prefixes, ipv6_prefixes = f_prefixes.result(timeout=7)
    except AsnUpstreamError as e:
        ipv4_prefixes, ipv6_prefixes = [], []
        warnings.append(f"{e.upstream}: {e.reason}")
        logger.warning("ASN upstream failure: %s %s", e.upstream, e.reason)
    except FuturesTimeoutError:
        ipv4_prefixes, ipv6_prefixes = [], []
        warnings.append("announced-prefixes: timeout")
        logger.warning("ASN upstream failure: announced-prefixes FuturesTimeoutError")

    parts = [f"AS{asn}"]
    if asn_name:
        parts[0] += f" ({asn_name})"
    parts.append(f"{len(ipv4_prefixes)} IPv4 and {len(ipv6_prefixes)} IPv6 prefixes")
    if resolved_ip:
        parts.append(f"resolved from {target}")

    summary = ". ".join(parts)
    if warnings:
        summary += " (partial: metadata unavailable)"

    # Defensive cap — asn_name also read by ip_lookup cache-hit path which caps
    # at 256; write in the same bound so both endpoints agree on payload size.
    result = {
        "target": target,
        "asn": asn,
        "asn_name": asn_name[:256],
        "ipv4_prefixes": ipv4_prefixes,
        "ipv6_prefixes": ipv6_prefixes,
        "ipv4_count": len(ipv4_prefixes),
        "ipv6_count": len(ipv6_prefixes),
        "summary": summary,
        "warnings": warnings,
    }
    if resolved_ip:
        result["resolved_ip"] = resolved_ip

    save_cached_domain(cache_key, result)
    return {**result}


class _BulkRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1, max_length=50)


_bulk_pool = ThreadPoolExecutor(max_workers=5)
_bulk_semaphore = threading.Semaphore(2)  # per-worker limit; with workers=2 actual max is 4


def _run_single_report(raw_domain: str, client_ip: str, tier: str = "free") -> dict:
    """Run full_domain_report for one domain, returning a result dict."""
    domain = clean_domain(raw_domain)
    resolved_ip = validate_domain(domain) if domain else None
    if not domain or not resolved_ip:
        return {
            "domain": raw_domain,
            "status": "error",
            "report": None,
            "error": "Invalid domain or DNS resolution failed",
        }
    try:
        cache_key = f"{tier}:{domain}"
        cached = get_cached_domain(cache_key)
        if cached:
            return {"domain": domain, "status": "ok", "report": {**cached}, "error": None}
        report = full_domain_report(domain, resolved_ip=resolved_ip, client_ip=client_ip, tier=tier)
        save_cached_domain(cache_key, report)
        return {"domain": domain, "status": "ok", "report": {**report}, "error": None}
    except Exception as e:
        logger.warning("Bulk report failed: %s", type(e).__name__)
        return {"domain": domain, "status": "error", "report": None, "error": "Domain report failed"}


@router.post(
    "/domains/bulk",
    operation_id="bulk_domain_report",
    response_model=BulkDomainResponse,
    response_model_exclude_none=True,
)
def bulk_domain_report(body: _BulkRequest, request: Request):
    """Bulk domain intelligence — up to 10 domains (free) or 50 (pro). Each domain counts as 1 request toward rate limit."""
    auth_ctx = authenticate(request, "/v1/domains/bulk")
    client_ip = get_client_ip(request)

    # Tier-based bulk limit
    from config import FREE_BULK_LIMIT, PRO_BULK_LIMIT

    bulk_limit = PRO_BULK_LIMIT if auth_ctx["tier"] == "pro" else FREE_BULK_LIMIT

    # Deduplicate domains (preserve order)
    domains = list(dict.fromkeys(body.domains))
    count = len(domains)

    if count > bulk_limit:
        raise HTTPException(
            status_code=422,
            detail=f"Too many domains. Limit: {bulk_limit} (your tier: {auth_ctx['tier']})",
        )

    # Check remaining quota before starting (each domain = 1 request)
    raw_key = None
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        from auth import extract_key, hash_key

        raw_key = extract_key(request)

    if raw_key:
        from auth import hash_key
        from config import PRO_HOURLY_LIMIT

        store_key = f"pro:{hash_key(raw_key)}"
        limit = PRO_HOURLY_LIMIT
    else:
        from config import FREE_HOURLY_LIMIT

        store_key = f"free:{client_ip}"
        limit = FREE_HOURLY_LIMIT

    # Atomic check-and-consume: authenticate() already consumed 1, we need (count - 1) more
    if count > 1 and not ratelimit.consume_bulk("api", store_key, count - 1, limit):
        raise HTTPException(
            status_code=429,
            detail=f"Insufficient rate limit quota for {count} domains.",
        )

    # Limit concurrent bulk requests to prevent thread pool exhaustion
    if not _bulk_semaphore.acquire(blocking=False):
        raise HTTPException(
            status_code=503,
            detail="Too many concurrent bulk requests. Please retry shortly.",
        )

    try:
        # Run reports in parallel, preserving input order
        ordered_futures = [(_bulk_pool.submit(_run_single_report, d, client_ip, auth_ctx["tier"]), d) for d in domains]
        results = []
        timed_out = 0
        partial = False
        deadline = _time.monotonic() + BULK_OVERALL_TIMEOUT

        for future, domain in ordered_futures:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                # Overall timeout exceeded — cancel remaining futures, return partial results
                future.cancel()
                logger.warning("Bulk overall timeout — skipping remaining domains")
                results.append({"domain": domain, "status": "error", "report": None, "error": "Bulk request timed out"})
                timed_out += 1
                partial = True
                continue
            per_domain = min(BULK_PER_DOMAIN_TIMEOUT, remaining)
            try:
                results.append(future.result(timeout=per_domain))
            except FuturesTimeoutError:
                future.cancel()
                logger.warning("Bulk report timed out")
                results.append(
                    {"domain": domain, "status": "error", "report": None, "error": "Domain report timed out"}
                )
                timed_out += 1
            except Exception as exc:
                logger.warning("Bulk report failed: %s", type(exc).__name__)
                results.append({"domain": domain, "status": "error", "report": None, "error": "Domain report failed"})
    finally:
        _bulk_semaphore.release()

    successful = sum(1 for r in results if r["status"] == "ok")
    failed = len(results) - successful - timed_out

    if partial:
        summary = f"{successful}/{count} domains scanned (partial — overall timeout reached)"
    elif failed == 0 and timed_out == 0:
        summary = f"All {count} domains scanned successfully"
    elif successful == 0:
        summary = f"All {count} domains failed"
    else:
        parts = [f"{successful}/{count} domains scanned"]
        if failed:
            parts.append(f"{failed} failed")
        if timed_out:
            parts.append(f"{timed_out} timed out")
        summary = ", ".join(parts)

    return {
        "results": results,
        "total": count,
        "successful": successful,
        "failed": failed,
        "timed_out": timed_out,
        "partial": partial,
        "summary": summary,
    }


@router.get(
    "/audit/{domain}",
    operation_id="audit_domain",
    response_model=AuditResponse,
    response_model_exclude_none=True,
)
def audit_domain(domain: str, request: Request):
    """Comprehensive domain audit — full intelligence report + technology fingerprint + live HTTP headers in a single call.

    Aggregates DNS, SSL, WHOIS, subdomains, threat intelligence, technology detection,
    HTTP security headers, and reputation data. Designed for AI agents and security
    automation that need a complete picture in one request.
    """
    from domain.recon import fetch_live_headers
    from domain.tech import detect_technologies

    auth_ctx = authenticate(request, "/v1/audit", cost=COST_AUDIT)

    domain = clean_domain(domain)
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain")

    client_ip = get_client_ip(request)
    tier = auth_ctx["tier"]
    cache_key = f"{tier}:{domain}"

    cached = get_cached_domain(cache_key)
    if cached:
        report = cached
    else:
        # Hard timeout guard — full_domain_report can hang on slow upstream
        # fail-overs (WHOIS, CT logs, subdomain enum). Cap at BULK_PER_DOMAIN_TIMEOUT.
        with ThreadPoolExecutor(max_workers=1) as _pool:
            _fut = _pool.submit(full_domain_report, domain, client_ip=client_ip, tier=tier)
            try:
                report = _fut.result(timeout=BULK_PER_DOMAIN_TIMEOUT)
            except FuturesTimeoutError:
                logger.warning("audit_domain: full_domain_report timed out")
                raise HTTPException(status_code=504, detail="Domain audit timed out — target upstream slow") from None
            except Exception as e:
                logger.warning("audit_domain: full_domain_report failed: %s", type(e).__name__)
                raise HTTPException(status_code=502, detail="Domain audit failed") from None
        save_cached_domain(cache_key, report)

    try:
        live = fetch_live_headers(domain)
    except Exception as e:
        logger.warning("audit_domain: fetch_live_headers failed: %s", type(e).__name__)
        live = {}
    headers = live.get("headers", {}) if isinstance(live, dict) else {}
    if not isinstance(headers, dict):
        headers = {}
    # Filter sensitive headers before they leave the server. Lowercase keys for
    # case-insensitive matching (HTTP headers are case-insensitive).
    headers = {k: v for k, v in headers.items() if k.lower() not in _AUDIT_SENSITIVE_HEADERS}
    tech = (
        detect_technologies(headers) if headers else {"technologies": [], "categories": {}, "count": 0, "summary": ""}
    )

    summary_parts = []
    if report.get("summary"):
        summary_parts.append(report["summary"])
    if tech.get("count"):
        summary_parts.append(f"{tech['count']} technologies detected")
    summary = " · ".join(summary_parts) if summary_parts else f"Audit completed for {domain}"

    return {
        "domain": domain,
        "report": report,
        "technologies": tech,
        "live_headers": headers,
        "summary": summary,
    }


@router.get(
    "/threat-report/{ip}",
    operation_id="threat_report",
    response_model=ThreatReportResponse,
    response_model_exclude_none=True,
)
def threat_report(ip: IpPath, request: Request):
    """Comprehensive IP threat report — Shodan InternetDB + AbuseIPDB + Shodan full + ASN in a single call.

    Aggregates open ports, vulnerabilities, abuse reports, geolocation, ASN ownership,
    and reputation across multiple sources. Designed for SOC triage and threat hunting
    where a complete IP profile is needed without making 4+ separate API calls.
    """
    auth_ctx = authenticate(request, "/v1/threat-report", cost=COST_THREAT_REPORT)

    if not is_valid_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")
    if is_private_ip(ip):
        raise HTTPException(status_code=400, detail="Private/reserved IP addresses are not allowed")

    with ThreadPoolExecutor(max_workers=4) as pool:
        f_enrich = pool.submit(ip_enrichment, ip)
        if auth_ctx["tier"] == "pro":
            f_abuse = pool.submit(check_abuseipdb, ip)
            f_shodan = pool.submit(check_shodan, ip)
        else:
            f_abuse = None
            f_shodan = None

        try:
            enrichment = f_enrich.result(timeout=10)
        except Exception as e:
            logger.warning("threat_report: ip_enrichment failed: %s", type(e).__name__)
            f_enrich.cancel()
            enrichment = {"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": []}
        if f_abuse is not None:
            try:
                abuseipdb = f_abuse.result(timeout=10)
            except Exception as e:
                logger.warning("threat_report: check_abuseipdb failed: %s", type(e).__name__)
                f_abuse.cancel()
                abuseipdb = {"status": "error"}
        else:
            abuseipdb = {
                "status": "pro_only",
                "reason": "AbuseIPDB enrichment requires Pro tier",
                "upgrade_url": UPGRADE_URL,
            }
        if f_shodan is not None:
            try:
                shodan_data = f_shodan.result(timeout=10)
            except Exception as e:
                logger.warning("threat_report: check_shodan failed: %s", type(e).__name__)
                f_shodan.cancel()
                shodan_data = {"status": "error"}
        else:
            shodan_data = {
                "status": "pro_only",
                "reason": "Shodan enrichment requires Pro tier",
                "upgrade_url": UPGRADE_URL,
            }

    if not isinstance(enrichment, dict):
        enrichment = {"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": []}
    if not isinstance(abuseipdb, dict):
        abuseipdb = {"status": "error"}
    if not isinstance(shodan_data, dict):
        shodan_data = {"status": "error"}

    asn_data = {}
    try:
        cache_key = f"asn:{ip}"
        cached_asn = get_cached_domain(cache_key)
        if cached_asn:
            asn_data = cached_asn
        else:
            r = _ripe_client.get(
                "https://stat.ripe.net/data/network-info/data.json",
                params={"resource": ip},
                timeout=5.0,
            )
            r.raise_for_status()
            data = r.json().get("data", {})
            asns = data.get("asns", [])
            if asns and asns[0]:
                asn_data = {"asn": int(asns[0]), "prefix": data.get("prefix", "")}
                save_cached_domain(cache_key, asn_data)
    except Exception as e:
        logger.warning("threat_report: ASN lookup failed: %s", type(e).__name__)
        asn_data = {"error": "lookup_failed"}

    threat_level = "none"
    raw_score = abuseipdb.get("abuse_score")
    abuse_score = raw_score if isinstance(raw_score, int) else None
    if shodan_data.get("vulns") or enrichment.get("vulns") or (abuse_score is not None and abuse_score >= 50):
        threat_level = "high"
    elif abuse_score is not None and abuse_score >= 25:
        threat_level = "medium"
    elif enrichment.get("ports"):
        threat_level = "low"

    summary_parts = [f"IP {ip}"]
    if isinstance(asn_data.get("asn"), int):
        summary_parts.append(f"AS{asn_data['asn']}")
    if enrichment.get("ports"):
        summary_parts.append(f"{len(enrichment['ports'])} open ports")
    if enrichment.get("vulns") or shodan_data.get("vulns"):
        all_vulns = set(enrichment.get("vulns", [])) | set(shodan_data.get("vulns", []))
        summary_parts.append(f"{len(all_vulns)} known vulns")
    summary_parts.append(f"threat level: {threat_level}")
    summary = " · ".join(summary_parts)

    return {
        "ip": ip,
        "enrichment": enrichment,
        "abuseipdb": abuseipdb,
        "shodan": shodan_data,
        "asn": asn_data,
        "threat_level": threat_level,
        "summary": summary,
    }
