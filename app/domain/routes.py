"""Domain Intelligence API routes — /v1/domain/*, /v1/dns/*, /v1/whois/*, etc."""

import asyncio
import atexit
import logging
import re
import socket
import ssl as _ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Annotated
from urllib.parse import urlparse as _urlparse

from fastapi.concurrency import run_in_threadpool


class AsnUpstreamError(Exception):
    def __init__(self, upstream: str, reason: str):
        self.upstream = upstream
        self.reason = reason
        super().__init__(f"{upstream}: {reason}")


from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response

_aia_pool = ThreadPoolExecutor(max_workers=2)
# Dedicated pool for _fetch_asn_country inner fan-out (country + holder).
# Faz 4 migration moved the top-level reputation fan-out to asyncio.gather +
# run_in_threadpool, so the former _reputation_pool is gone — _ip_enrichment_pool
# is now the only remaining dedicated pool, used by sync helpers running under
# run_in_threadpool from async routes.
_ip_enrichment_pool = ThreadPoolExecutor(max_workers=4)
atexit.register(_ip_enrichment_pool.shutdown, wait=False)
atexit.register(_aia_pool.shutdown, wait=False)

import httpx as _httpx
import ratelimit

_ripe_client = _httpx.Client(timeout=_httpx.Timeout(7.0, connect=3.0), follow_redirects=False)
from auth import AuthCtx, require_auth
from config import (
    BULK_OVERALL_TIMEOUT,
    BULK_PER_DOMAIN_TIMEOUT,
    COST_AUDIT,
    COST_THREAT_REPORT,
    DOMAIN_BURST_LIMIT,
    DOMAIN_BURST_WINDOW,
    DOMAIN_HARD_TIMEOUT,
    ENRICHMENT_DAILY_LIMIT,
    MAX_ASN_PREFIXES_DEFAULT,
    RECON_TIMEOUT,
    UPGRADE_URL,
)
from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID
from db import (
    aenrich_cves_by_ids,
    aget_cached_domain,
    aget_cached_domain_with_age,
    aget_cached_ip_with_age,
    asave_cached_domain,
    asave_cached_ip,
    get_cached_domain,
    hash_client_ip,
    save_cached_domain,
)
from domain.archive import wayback_lookup
from domain.ip_intel import (
    check_cloud_provider,
    check_firehol,
    check_tor_exit,
    is_datacenter,
    score_ip,
    severity_label,
    tor_cache_status,
)
from domain.recon import (
    _classify_ssl_verify_error,
    _dns_call_with_timeout,
    _hostname_matches,
    _parse_cert_der,
    _ssl_grade,
    _ssrf_http,
    _strip_control_chars,
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
from domain.schemas import (
    AsnResponse,
    AuditResponse,
    BrandAssetsResponse,
    BulkDomainResponse,
    CertsResponse,
    DisposableResponse,
    DnsResponse,
    DomainReportResponse,
    EmailMxResponse,
    EmailVerifyResponse,
    IpLookupResponse,
    MonitorResponse,
    PhoneLookupResponse,
    RedirectChainResponse,
    RobotsTxtResponse,
    SeoAuditResponse,
    SslResponse,
    SubdomainsResponse,
    TechResponse,
    ThreatReportResponse,
    ThreatResponse,
    UsernameLookupResponse,
    VulnsResponse,
    WaybackResponse,
    WhoisResponse,
)
from domain.threat import check_urlhaus
from domain.username import username_lookup
from pydantic import BaseModel, Field
from schemas import PivotHint, Verdict
from validation import _is_valid_format, clean_domain, is_private_ip, is_valid_ip, validate_domain

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
    """Strip ASCII control + Unicode bidi/format controls from RFC 4514 DN strings.

    Cert subject/issuer come from a remote-controlled X.509 blob and may carry
    Unicode bidi overrides (U+202A-U+202E, U+2066-U+2069). Without bidi stripping
    they survive into JSON responses and reverse the visual rendering order in
    bidi-aware terminals/UIs (Trojan-Source CVE-2021-42574). _strip_control_chars
    is the canonical helper, capped at 512 here for DN length.
    """
    return _strip_control_chars(s)[:512]


def _safe_url(url: str) -> str:
    """Strip CRLF / control chars from URLs before logging or returning in responses."""
    return "".join(c for c in url if c >= " " and c != "\x7f")[:2048]


def _clean_shodan_str_list(items) -> list[str]:
    """Trojan-Source guard: strip bidi / control chars from a Shodan-supplied
    str-array (vulns, hostnames, cpes, tags) before it flows into the JSON
    response. Non-strings are silently dropped (defensive — upstream contract
    violation, must not crash the request)."""
    return [_strip_control_chars(v) for v in (items or []) if isinstance(v, str)]


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
def api_root(auth: Annotated[AuthCtx, Depends(require_auth("/v1"))]):
    """Available endpoints when someone hits /v1/ directly."""
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


def _validate_domain_input(raw_domain: str) -> tuple[str, str]:
    """Clean + validate the raw domain input, then DNS-resolve. Returns (domain, resolved_ip).

    Faz 3: auth no longer happens here — routes acquire AuthCtx via
    Annotated[AuthCtx, Depends(require_auth(...))] which runs BEFORE the
    handler body, so callers see auth-rejected requests as 401/429 before
    reaching this helper at all.
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
    resolved_ip = validate_domain(domain)
    if not resolved_ip:
        raise HTTPException(status_code=422, detail="Could not resolve this domain. DNS resolution failed.")
    return domain, resolved_ip


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


def _is_security_txt_record(value: str) -> bool:
    """True for SPF / DMARC / DKIM / MTA-STS / TLS-RPT / DNSSEC verification TXT values.

    Filters out vendor verification strings (google-site-verification, ms=,
    facebook-domain-verification, etc.) and arbitrary marketing TXT records that
    bloat domain_report responses without security signal.
    """
    if not isinstance(value, str):
        return False
    v = value.strip().lower()
    if v.startswith("v=spf"):
        return True
    if v.startswith("v=dmarc"):
        return True
    if v.startswith("v=dkim"):
        return True
    if v.startswith("v=stsv"):
        return True
    return v.startswith("v=tlsrptv")


def _apply_txt_filter(report: dict, include_all_txt: bool) -> dict:
    """Return a shallow-copied report with dns.txt filtered to security records.

    Sets dns.total_txt_records to the honest pre-filter count. Caller must pass a
    fresh dict (from cache or full_domain_report) — this function copies the dns
    sub-dict so mutating the returned report does not poison the cache. When
    include_all_txt=True the txt list is left untouched but total_txt_records is
    still surfaced.
    """
    dns_block = report.get("dns")
    if not isinstance(dns_block, dict):
        return report
    txt = dns_block.get("txt")
    if not isinstance(txt, list):
        return report
    new_dns = dict(dns_block)
    new_dns["total_txt_records"] = len(txt)
    if not include_all_txt:
        new_dns["txt"] = [t for t in txt if _is_security_txt_record(t)]
    new_report = dict(report)
    new_report["dns"] = new_dns
    return new_report


def _domain_verdict(report: dict, age_seconds: int, lite: bool) -> Verdict:
    """Build verdict metadata for domain_report responses."""
    queried = ["dns", "ssl"]
    unavailable: list[str] = []
    if not lite:
        queried.extend(["whois", "subdomains", "ct_logs", "urlhaus"])
        threat = report.get("threat", {}) or {}
        if threat.get("urlhaus_status") == "error":
            unavailable.append("urlhaus")
        certs = report.get("certificates", {}) or {}
        if certs.get("error"):
            unavailable.append("ct_logs")
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
    tor_status: str = "ok",
) -> Verdict:
    """Build verdict metadata for ip_lookup responses.

    `tor_status` mirrors `_tor_cache["fetch_status"]` so a downstream agent
    can tell `tor_exit=false because not in list` from `tor_exit=false
    because we never got the list` (Bug NEW-B). Anything other than "ok"
    surfaces "tor" in sources_unavailable.
    """
    queried = ["internetdb", "ripe_stat", "tor"]
    if firehol_attempted:
        queried.append("firehol")
    if reputation_attempted:
        queried.append("reputation")
    unavailable: list[str] = []
    if internetdb_failed:
        unavailable.append("internetdb")
    if ripe_failed:
        unavailable.append("ripe_stat")
    if tor_status != "ok":
        unavailable.append("tor")
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
            "is_datacenter",
            "tor_exit",
            "firehol",
            "risk_score",
            "severity_label",
        ],
        data_age_seconds=age_seconds,
        sources_queried=queried,
        sources_unavailable=unavailable,
        completeness="partial" if unavailable else "complete",
    )


def _asn_verdict(warnings: list[str], age_seconds: int | None) -> Verdict:
    """Build verdict metadata for asn_lookup responses (Bug I2 — pattern parity
    with ip_lookup / threat_report).

    Maps the route's `warnings` list (e.g. 'as-overview: timeout',
    'announced-prefixes: timeout') back into the canonical sub-source name
    so agents can tell *which* RIPE Stat sub-endpoint failed instead of
    parsing the human-readable warning string.
    """
    queried = ["ripe_stat:network-info", "ripe_stat:as-overview", "ripe_stat:announced-prefixes"]
    unavailable: list[str] = []
    # Prefix-match (not substring) so a warning whose `:reason` half happens
    # to contain the literal text "announced-prefixes" cannot forge a
    # sources_unavailable entry. Both upstream tags are produced by our own
    # AsnUpstreamError, but anchoring on the prefix is the safer pattern.
    for w in warnings:
        if w.startswith("as-overview:"):
            unavailable.append("ripe_stat:as-overview")
        elif w.startswith("announced-prefixes:"):
            unavailable.append("ripe_stat:announced-prefixes")
    return Verdict(
        deterministic=True,
        falsifiable_fields=["asn", "asn_name", "ipv4_prefixes", "ipv6_prefixes"],
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


async def _from_cache(domain: str, key: str, tier: str) -> dict | None:
    """Try to extract a section from a cached full domain report.

    Matches the tier-prefixed cache keys used by domain_report/bulk/audit —
    otherwise sub-endpoints (dns/whois/subdomains/certs) would always miss.
    """
    cached = await aget_cached_domain(f"{tier}:{domain}")
    if cached and key in cached:
        return cached[key]
    return None


def _ip_pivot_hints(ip: str, asn: int | None, reputation: dict, tier: str) -> list[PivotHint]:
    """Build cascade hints for an ip_lookup response.

    Conditional emission:
    - asn_lookup: whenever asn is populated (RIPE returned a number) — gives CIDR detail.
    - ioc_lookup: when firehol.listed=True OR abuseipdb confidence>50 — threat-indicator drill.
    - threat_report: Pro tier only — orchestrated Shodan + AbuseIPDB; free-tier upgrade-CTA noise
      lives elsewhere, don't shove it into a pivot hint.
    """
    hints: list[PivotHint] = []
    if asn:
        hints.append(
            PivotHint(
                tool="asn_lookup",
                input=ip,
                reason=f"AS{asn} infrastructure: announced IPv4/IPv6 CIDR prefixes, network size, BGP routes.",
            )
        )

    firehol_listed = isinstance(reputation, dict) and reputation.get("firehol", {}).get("listed") is True
    abuse_score = 0
    if isinstance(reputation, dict):
        abuse = reputation.get("abuseipdb") or {}
        if isinstance(abuse, dict) and abuse.get("status") not in ("pro_only", "error", "unavailable"):
            try:
                abuse_score = int(abuse.get("abuse_confidence_score") or 0)
            except (TypeError, ValueError):
                abuse_score = 0
    if firehol_listed or abuse_score > 50:
        trigger = "FireHOL-listed" if firehol_listed else f"AbuseIPDB confidence {abuse_score}"
        hints.append(
            PivotHint(
                tool="ioc_lookup",
                input=ip,
                reason=f"{trigger} — query ThreatFox / Feodo Tracker / URLhaus for active threat status.",
            )
        )

    if tier == "pro":
        hints.append(
            PivotHint(
                tool="threat_report",
                input=ip,
                reason="Pro orchestrated profile: Shodan host, AbuseIPDB reports, open ports, known vulns.",
            )
        )
    return hints


def _domain_pivot_hints(report: dict, domain: str) -> list[PivotHint]:
    """Build cascade hints for a full domain report.

    subdomain_enum is always emitted — attack-surface mapping is a near-universal
    next step on any recon. ssl_check + tech_fingerprint are conditional on the
    domain having a resolvable A record (otherwise they would just 404 / NXDOMAIN
    and waste an agent call). When the domain has no DNS at all (NXDOMAIN), no
    pivots are returned.
    """
    dns_block = report.get("dns") or {}
    has_a = bool(dns_block.get("a") or dns_block.get("aaaa"))
    if not has_a and not dns_block:
        return []

    hints: list[PivotHint] = [
        PivotHint(
            tool="subdomain_enum",
            input=domain,
            reason="Map attack surface — enumerate subdomains via crt.sh CT logs + DNS wordlist (passive).",
        )
    ]
    if has_a:
        hints.append(
            PivotHint(
                tool="ssl_check",
                input=domain,
                reason="Inspect TLS certificate: grade, protocol, cipher, expiry, AIA chain, OCSP status.",
            )
        )
        hints.append(
            PivotHint(
                tool="tech_fingerprint",
                input=domain,
                reason="Detect website tech stack (CMS, framework, CDN, analytics, web server) from live headers.",
            )
        )
    return hints


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
async def domain_report(
    domain: DomainPath,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/domain"))],
    response: Response,
    lite: Annotated[
        bool,
        Query(
            description=(
                "Fast subset mode. When true, skips WHOIS, subdomains, CT logs, URLhaus, and reputation. "
                "Returns in ~250ms instead of 3-10s. Use for high-volume triage."
            ),
        ),
    ] = False,
    include_all_txt: Annotated[
        bool,
        Query(
            description=(
                "Return every TXT record (default: only SPF, DMARC, DKIM, MTA-STS, TLS-RPT). "
                "total_txt_records under dns.* is always emitted with the honest pre-filter count. "
                "Default filter strips vendor verification strings (google-site-verification, ms=, "
                "facebook-domain-verification, etc.) that bloat reports without security signal. "
                "Pass include_all_txt=true only when you need the raw TXT inventory — for SPF/DMARC "
                "auditing the default is sufficient."
            ),
        ),
    ] = False,
):
    """Full domain intelligence report with DNS, WHOIS, SSL, subdomains, WAF. Use ?lite=true for fast subset."""
    # RFC 8594 — top-level risk_score alias is deprecated; clients should read risk.score instead.
    # Field still emitted for back-compat through v1.x; will be removed in v2.0.0.
    response.headers["Deprecation"] = "true"
    response.headers["Sunset"] = "Wed, 01 Sep 2026 00:00:00 GMT"
    response.headers["Link"] = '<https://github.com/UPinar/contrastapi/releases>; rel="deprecation"'
    domain, resolved_ip = _validate_domain_input(domain)
    tier = auth.tier
    client_ip = auth.client_ip

    # Behavioral burst throttle (Free tier only). UA-rotating bot fleets
    # bypass the nginx UA blocklist by querying many distinct domains rapidly;
    # this catches the pattern at the application layer regardless of UA.
    if tier == "free" and client_ip:
        if not await ratelimit.acheck_limit(
            "domain_burst",
            hash_client_ip(client_ip),
            max_requests=DOMAIN_BURST_LIMIT,
            window_seconds=DOMAIN_BURST_WINDOW,
        ):
            raise HTTPException(
                status_code=429,
                detail=(
                    f"Too many domain queries — max {DOMAIN_BURST_LIMIT} per "
                    f"{DOMAIN_BURST_WINDOW}s per client. Pro tier removes this throttle."
                ),
            )

    # Separate cache keys for lite vs full, segregated by tier to prevent
    # free-tier pro_only stubs from poisoning Pro reads (and vice versa).
    cache_key = f"{tier}:lite:{domain}" if lite else f"{tier}:{domain}"
    hit = await aget_cached_domain_with_age(cache_key)
    if hit is not None:
        cached, age = hit
        emitted = _apply_txt_filter(cached, include_all_txt)
        return {
            **emitted,
            "verdict": _domain_verdict(emitted, age, lite=lite),
            "next_calls": _domain_pivot_hints(emitted, domain) or None,
        }

    # Hard timeout guard — full_domain_report can hang on slow upstream
    # fail-overs (WHOIS, CT logs, subdomain enum). asyncio.wait_for cancels
    # the awaitable cleanly without blocking the event loop on a timed-out
    # background thread (anyio's run_in_threadpool worker is reusable).
    try:
        result = await asyncio.wait_for(
            run_in_threadpool(
                full_domain_report, domain, resolved_ip=resolved_ip, client_ip=client_ip, lite=lite, tier=tier
            ),
            timeout=DOMAIN_HARD_TIMEOUT,
        )
    except (asyncio.TimeoutError, TimeoutError):
        raise HTTPException(status_code=504, detail="Domain report timed out — upstream services too slow") from None
    await asave_cached_domain(cache_key, result)
    emitted = _apply_txt_filter(result, include_all_txt)
    return {
        **emitted,
        "verdict": _domain_verdict(emitted, 0, lite=lite),
        "next_calls": _domain_pivot_hints(emitted, domain) or None,
    }


@router.get("/dns/{domain}", operation_id="dns_records", response_model=DnsResponse, response_model_exclude_none=True)
async def dns_records(
    domain: DomainPath,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/dns"))],
):
    """DNS record lookup: A, AAAA, MX, NS, TXT, CNAME, SOA."""
    domain, resolved_ip = _validate_domain_input(domain)
    cached = await _from_cache(domain, "dns", auth.tier)
    if cached:
        return {"domain": domain, "records": cached, "summary": _dns_summary(cached, domain)}
    records = await run_in_threadpool(dns_lookup, domain)
    if not records:
        raise HTTPException(status_code=404, detail=f"No DNS records found for '{domain}'")
    return {"domain": domain, "records": records, "summary": _dns_summary(records, domain)}


@router.get(
    "/email/mx/{domain}",
    operation_id="email_mx",
    response_model=EmailMxResponse,
    response_model_exclude_none=True,
)
async def email_mx(
    domain: DomainPath,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/email/mx"))],
):
    """Email MX analysis — mail provider detection, SPF/DMARC/DKIM check, security grade."""
    domain, resolved_ip = _validate_domain_input(domain)

    # Check cache
    cache_key = f"email_mx:{domain}"
    cached = await aget_cached_domain(cache_key)
    if cached:
        return {**cached}

    # Fetch DNS records for MX + TXT (SPF)
    records = await run_in_threadpool(dns_lookup, domain)
    mx_records = records.get("mx", [])
    txt_records = records.get("txt", [])

    # Detect mail provider
    provider = detect_mail_provider(mx_records)

    # Email security check (SPF/DMARC/DKIM) — bound by overall deadline so
    # DKIM probing (up to 19 selectors x 5s each) can't pin a worker.
    try:
        security = await asyncio.wait_for(
            run_in_threadpool(email_security, domain, txt_records),
            timeout=RECON_TIMEOUT * 2,
        )
    except (asyncio.TimeoutError, TimeoutError):
        security = {
            "spf": None,
            "dmarc": None,
            "dkim_selectors": [],
            "dkim_status": "unverifiable",
            "grade": "F",
            "issues": ["Email security check timed out"],
        }

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
    await asave_cached_domain(cache_key, result)
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
async def email_disposable(
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
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/email/disposable"))],
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

    # Check cache (keyed by domain — rebuild summary with current email on hit)
    cache_key = f"email_disp:{domain}"
    cached = await aget_cached_domain(cache_key)
    if cached:
        summary = _disposable_summary(email, cached)
        return {**cached, "email": email, "summary": summary}

    resolved_ip = validate_domain(domain)
    if not resolved_ip:
        raise HTTPException(status_code=422, detail="Could not resolve email domain. DNS resolution failed.")

    result = await run_in_threadpool(check_disposable, email, domain=domain)
    result["summary"] = _disposable_summary(email, result)

    await asave_cached_domain(cache_key, result)
    return {**result}


@router.get(
    "/email/verify/{email}",
    operation_id="email_verify",
    response_model=EmailVerifyResponse,
    response_model_exclude_none=True,
)
async def email_verify_endpoint(
    email: Annotated[
        str,
        Path(
            description=(
                "Email address to verify, e.g. 'admin@example.com'. The local-part "
                "is preserved (lowercased) in the response; only the domain is hit "
                "for MX resolution + disposable lookup. NO SMTP RCPT TO probe is "
                "performed — see EmailVerifyResponse docstring."
            ),
        ),
    ],
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/email/verify"))],
):
    """Combined email validation: syntax + MX + disposable + role + free-provider.

    Combines `email_mx` (MX resolution) and `email_disposable` (disposable check)
    into a single call so AI agents auditing a contact list don't need to
    interleave two tools. Adds role-address detection (admin@, info@, ...) and
    free-provider classification (gmail/outlook/yahoo/...).

    Deliberately does NOT do SMTP `RCPT TO` deliverability probing — see the
    response model docstring for the rationale.
    """
    from domain.email_verify import is_free_provider, parse_email, role_classification

    parsed = parse_email(email or "")
    if not parsed:
        # We still surface the input so an agent can reflect it back to the user.
        # Domain may be empty if the email had no `@` at all.
        local = ""
        domain = email.rsplit("@", 1)[1].lower() if "@" in email else ""
        # Auth was already consumed by require_auth before we got here.
        return {
            "email": email[:254],  # cap so a 100KB pasteload can't bloat the response
            "domain": domain,
            "syntax_valid": False,
            "mx_records": [],
            "disposable": False,
            "role_address": False,
            "free_provider": False,
            "summary": f"{email[:80]} — invalid syntax",
        }

    local, domain = parsed

    cache_key = f"email_verify:{domain}"
    cached = await aget_cached_domain(cache_key)
    if cached:
        # Per-email facets (role, syntax_valid) depend on the local-part, not
        # cached. Only domain-level facets (mx, disposable, free) come from cache.
        is_role, role_type = role_classification(local)
        return {
            **cached,
            "email": f"{local}@{domain}",
            "syntax_valid": True,
            "role_address": is_role,
            "role_type": role_type,
            "summary": _email_verify_summary(local, domain, cached, is_role, role_type),
        }

    resolved = validate_domain(domain)
    if not resolved:
        # Domain doesn't resolve at all — return what we know with empty MX.
        is_role, role_type = role_classification(local)
        return {
            "email": f"{local}@{domain}",
            "domain": domain,
            "syntax_valid": True,
            "mx_records": [],
            "disposable": False,
            "role_address": is_role,
            "role_type": role_type,
            "free_provider": is_free_provider(domain),
            "summary": f"{local}@{domain} — domain does not resolve",
        }

    # Domain-level facets we cache.
    records = await run_in_threadpool(dns_lookup, domain)
    mx_records = records.get("mx", [])
    disposable_info = await run_in_threadpool(check_disposable, f"{local}@{domain}", domain=domain)
    is_disposable = bool(disposable_info.get("disposable"))
    disposable_provider = disposable_info.get("provider") if is_disposable else None
    free = is_free_provider(domain)

    cached_payload = {
        "domain": domain,
        "mx_records": mx_records,
        "disposable": is_disposable,
        "disposable_provider": disposable_provider,
        "free_provider": free,
    }
    await asave_cached_domain(cache_key, cached_payload)

    is_role, role_type = role_classification(local)
    return {
        "email": f"{local}@{domain}",
        **cached_payload,
        "syntax_valid": True,
        "role_address": is_role,
        "role_type": role_type,
        "summary": _email_verify_summary(local, domain, cached_payload, is_role, role_type),
    }


def _email_verify_summary(local: str, domain: str, payload: dict, is_role: bool, role_type: str | None) -> str:
    """One-line human summary for email_verify."""
    parts = [f"{local}@{domain}"]
    if payload.get("disposable"):
        parts.append(f"disposable ({payload.get('disposable_provider') or 'unknown'})")
    elif payload.get("free_provider"):
        parts.append("free provider")
    elif payload.get("mx_records"):
        parts.append(f"{len(payload['mx_records'])} MX")
    else:
        parts.append("no MX")
    if is_role:
        parts.append(f"role:{role_type}")
    return " — ".join(parts)


@router.get(
    "/robots/{domain}",
    operation_id="robots_txt",
    response_model=RobotsTxtResponse,
    response_model_exclude_none=True,
)
async def robots_txt_endpoint(
    domain: DomainPath,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/robots"))],
):
    """Fetch + parse the target domain's robots.txt file.

    Returns sitemaps, per-User-agent allow/disallow rules, crawl-delay, and the
    Host directive. Status 404 from the target = no robots.txt = implicit
    allow-all (RFC 9309 §2.4); the response carries `status_code: 404`,
    `user_agents: {}`, and an empty `sitemaps`/`host`.

    Per-target eTLD+1 throttle (60 req/min): a single Pro key cannot weaponise
    the API against one site by spamming this endpoint; subdomain rotation
    collapses to the same eTLD+1 bucket.
    """
    from target_throttle import consume_target_throttle

    cleaned, _resolved_ip = _validate_domain_input(domain)

    allowed, retry_after = consume_target_throttle(cleaned)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Target throttle: {cleaned} exceeded the per-domain limit. retry_after={retry_after}s",
            headers={"Retry-After": str(retry_after)},
        )

    cache_key = f"robots:{cleaned}"
    cached = await aget_cached_domain(cache_key)
    if cached:
        return cached

    from domain.robots import _exception_kind, fetch_robots_txt

    try:
        result = await run_in_threadpool(fetch_robots_txt, cleaned)
    except Exception as exc:
        kind = _exception_kind(exc)
        logger.info("robots.txt fetch failed for %s [%s]: %s", cleaned, kind, exc)
        raise HTTPException(
            status_code=502,
            detail=f"robots.txt fetch failed: {kind}",
        ) from exc

    # RFC 9309 §2.4: 5xx is a temporary failure. Don't cache the empty rule
    # set for a full hour — that would let seo_audit/brand_assets misread an
    # outage as "no robots, allow-all". Surface as 502 instead.
    sc = result["status_code"]
    if 500 <= sc < 600:
        raise HTTPException(
            status_code=502,
            detail=f"robots.txt upstream {sc} (transient — RFC 9309 §2.4)",
        )

    ua_count = len(result["user_agents"])
    sm_count = len(result["sitemaps"])
    if sc == 404:
        result["summary"] = f"{cleaned} — no robots.txt (implicit allow-all)"
    elif sc != 200:
        result["summary"] = f"{cleaned} — HTTP {sc} fetching robots.txt"
    else:
        result["summary"] = f"{cleaned} — {ua_count} UA blocks, {sm_count} sitemaps"

    await asave_cached_domain(cache_key, result)
    return result


@router.get(
    "/redirect/{url:path}",
    operation_id="redirect_chain",
    response_model=RedirectChainResponse,
    response_model_exclude_none=True,
)
async def redirect_chain_endpoint(
    url: str,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/redirect"))],
):
    """Walk a URL's HTTP redirect chain hop-by-hop, returning each (status, Location, latency).

    Up to 10 hops; SSRF-safe (private IPs and non-HTTP schemes rejected at every
    hop, not just the start). Per-target eTLD+1 throttle (60 req/min) is consumed
    once for the start URL and once for every *new* host reached in the chain —
    a chain across 11 unrelated domains can't bypass the cap.

    Pass the URL inline in the path (greedy-matched), e.g.
    GET /v1/redirect/https://bit.ly/3xyz — FastAPI accepts the literal `://`.
    """
    from urllib.parse import urlparse as _urlparse_local

    from domain.redirect_chain import (
        TargetThrottleHopExceeded,
        _validate_url,
        walk_redirect_chain,
    )
    from target_throttle import consume_target_throttle

    # Validate input URL upfront so we get a clean 400 (not 502) on garbage.
    try:
        _validate_url(url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Auth + 1 API credit was consumed by require_auth. Apply the *start* host's throttle.
    start_host = (_urlparse_local(url).hostname or "").lower()
    if start_host:
        allowed, retry = consume_target_throttle(start_host)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail=f"Target throttle: {start_host} exceeded the per-domain limit. retry_after={retry}s",
                headers={"Retry-After": str(retry)},
            )

    cache_key = f"redirect:{url}"
    cached = await aget_cached_domain(cache_key)
    if cached:
        return cached

    try:
        result = await run_in_threadpool(walk_redirect_chain, url)
    except TargetThrottleHopExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail=f"Target throttle: hop host {exc.host} exceeded the per-domain limit. retry_after={exc.retry_after}s",
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc
    except ValueError as exc:
        # Mid-chain malformed Location — still return what we walked so far would
        # be nicer, but `walk_redirect_chain` already records hops up to the
        # bad target and just sets `location=None`, so a ValueError here means
        # the *start* URL was invalid (caught above) — defensive fallback.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        from domain.robots import _exception_kind

        kind = _exception_kind(exc)
        logger.info("redirect_chain fetch failed for %s [%s]: %s", url, kind, exc)
        raise HTTPException(status_code=502, detail=f"redirect_chain fetch failed: {kind}") from exc

    hop_count = result["hop_count"]
    if result["loop_detected"]:
        result["summary"] = f"{hop_count}-hop chain — loop detected (would revisit a previous URL)"
    elif result["truncated"]:
        result["summary"] = f"chain truncated at {hop_count} hops without reaching a terminal response"
    else:
        result["summary"] = f"{hop_count}-hop chain — final {result['final_status']} at {result['final_url']}"

    await asave_cached_domain(cache_key, result)
    return result


@router.get(
    "/brand/{domain}",
    operation_id="brand_assets",
    response_model=BrandAssetsResponse,
    response_model_exclude_none=True,
)
async def brand_assets_endpoint(
    domain: DomainPath,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/brand"))],
):
    """Scrape the target domain's homepage `<head>` for public brand assets:
    favicon, og:image, theme-color, og:site_name, JSON-LD Organization.logo.

    Ethical floor (Guardrail #3 in v1.25.0 plan): we honour the target's
    robots.txt — `Disallow: /` for our UA token ("ContrastAPI") OR for `*`
    returns 403 + `error.code = robots_txt_disallow` and we DO NOT fetch
    the page. Per-target eTLD+1 throttle (60 req/min) protects the site
    from being scraped via subdomain rotation. `Cache-Control: no-store`
    or `private` from the target is honoured — we DO NOT write to cache
    on those responses (Guardrail #4).
    """
    from target_throttle import consume_target_throttle

    cleaned, _resolved_ip = _validate_domain_input(domain)

    allowed, retry_after = consume_target_throttle(cleaned)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Target throttle: {cleaned} exceeded the per-domain limit. retry_after={retry_after}s",
            headers={"Retry-After": str(retry_after)},
        )

    cache_key = f"brand:{cleaned}"
    cached = await aget_cached_domain(cache_key)
    if cached:
        return cached

    # Robots.txt respect — reuse the robots cache, fall through to a fresh
    # fetch if absent. Failure-mode policy: on robots.txt FETCH failure
    # (DNS/TCP/TLS/upstream-5xx) we DO NOT block — robots is a courtesy
    # signal, not an authentication boundary, and a transient outage
    # should not poison every brand_assets call for an hour.
    from domain.brand_assets import (
        extract_brand_assets,
        fetch_homepage_html,
        homepage_allowed,
    )
    from domain.robots import _exception_kind, fetch_robots_txt

    robots_payload = await aget_cached_domain(f"robots:{cleaned}")
    if robots_payload is None:
        try:
            robots_payload = await run_in_threadpool(fetch_robots_txt, cleaned)
            sc = robots_payload.get("status_code", 0)
            # RFC 9309 §2.4: 5xx is transient — do not cache.
            if not (500 <= sc < 600):
                await asave_cached_domain(f"robots:{cleaned}", robots_payload)
        except Exception as exc:
            logger.debug(
                "brand_assets: robots.txt fetch failed (allow-fail-open) %s [%s]", cleaned, _exception_kind(exc)
            )
            robots_payload = {"user_agents": {}, "sitemaps": [], "host": None}

    allowed, blocking_pat = homepage_allowed(robots_payload)
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=f"robots_txt_disallow: target site forbids '{blocking_pat}' for ContrastAPI; we will not fetch /",
        )

    try:
        page = await run_in_threadpool(fetch_homepage_html, cleaned)
    except Exception as exc:
        kind = _exception_kind(exc)
        logger.info("brand_assets fetch failed for %s [%s]: %s", cleaned, kind, exc)
        raise HTTPException(
            status_code=502,
            detail=f"brand_assets fetch failed: {kind}",
        ) from exc

    assets = extract_brand_assets(page["html"], page["url"])

    # Guardrail #4: honour Cache-Control: no-store / private. We still
    # build + return the response; we just don't persist it. Surface the
    # decision in the response so callers can see what we did.
    cc = page["cache_control"]
    cache_respected = not any(token in cc for token in ("no-store", "private"))

    parts: list[str] = []
    if assets["site_name"]:
        parts.append(f"site:{assets['site_name'][:60]}")
    if assets["favicon_url"]:
        parts.append("favicon")
    if assets["og_image_url"]:
        parts.append("og:image")
    if assets["logo_url"]:
        parts.append("jsonld:logo")
    summary = f"{cleaned} — " + (", ".join(parts) if parts else "no public brand assets found")

    result = {
        "domain": cleaned,
        "fetched_url": page["url"],
        "status_code": page["status_code"],
        "favicon_url_untrusted": assets["favicon_url"],
        "og_image_url_untrusted": assets["og_image_url"],
        "theme_color": assets["theme_color"],
        "site_name_untrusted": assets["site_name"],
        "logo_url_untrusted": assets["logo_url"],
        "cache_respected": cache_respected,
        "summary": summary,
    }

    if cache_respected:
        await asave_cached_domain(cache_key, result)
    return result


@router.get(
    "/seo/{domain}",
    operation_id="seo_audit",
    response_model=SeoAuditResponse,
    response_model_exclude_none=True,
)
async def seo_audit_endpoint(
    domain: DomainPath,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/seo"))],
):
    """Audit a domain's homepage for SEO health and emit a 0-100 composite score.

    10 audit rules (each 0-10 pts): title present, title length 30-60,
    meta description present, meta description length 50-160, exactly
    one H1, canonical link, ≥3 OG tags, JSON-LD present, image alt-text
    coverage proportional, HTTPS. `missing_signals` lists rules that did
    not contribute so the agent has a concrete fix list.

    Same ethical floor as `brand_assets`: target's robots.txt is
    honoured (Disallow `/` for our UA → 403, no fetch); per-target
    eTLD+1 throttle (60 req/min) consumed BEFORE the cache lookup;
    `Cache-Control: no-store`/`private` from the target skips the
    cache write (cache_respected=false flags it).
    """
    from target_throttle import consume_target_throttle

    cleaned, _resolved_ip = _validate_domain_input(domain)

    allowed, retry_after = consume_target_throttle(cleaned)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Target throttle: {cleaned} exceeded the per-domain limit. retry_after={retry_after}s",
            headers={"Retry-After": str(retry_after)},
        )

    cache_key = f"seo:{cleaned}"
    cached = await aget_cached_domain(cache_key)
    if cached:
        return cached

    from domain.brand_assets import fetch_homepage_html, homepage_allowed
    from domain.robots import _exception_kind, fetch_robots_txt
    from domain.seo_audit import _extract_seo, _score

    # Robots respect — same fail-open posture as brand_assets: a transient
    # robots.txt outage must not poison every seo_audit call.
    robots_payload = await aget_cached_domain(f"robots:{cleaned}")
    if robots_payload is None:
        try:
            robots_payload = await run_in_threadpool(fetch_robots_txt, cleaned)
            sc = robots_payload.get("status_code", 0)
            if not (500 <= sc < 600):
                await asave_cached_domain(f"robots:{cleaned}", robots_payload)
        except Exception as exc:
            logger.debug("seo_audit: robots.txt fetch failed (allow-fail-open) %s [%s]", cleaned, _exception_kind(exc))
            robots_payload = {"user_agents": {}, "sitemaps": [], "host": None}

    allowed_path, blocking_pat = homepage_allowed(robots_payload)
    if not allowed_path:
        raise HTTPException(
            status_code=403,
            detail=f"robots_txt_disallow: target site forbids '{blocking_pat}' for ContrastAPI; we will not fetch /",
        )

    try:
        page = await run_in_threadpool(fetch_homepage_html, cleaned)
    except Exception as exc:
        kind = _exception_kind(exc)
        logger.info("seo_audit fetch failed for %s [%s]: %s", cleaned, kind, exc)
        raise HTTPException(
            status_code=502,
            detail=f"seo_audit fetch failed: {kind}",
        ) from exc

    parsed = _extract_seo(page["html"], page["url"])
    score, missing = _score(parsed, page["url"])

    cc = page["cache_control"]
    cache_respected = not any(token in cc for token in ("no-store", "private"))

    summary_parts: list[str] = [f"{cleaned} score={score}/100"]
    if missing:
        summary_parts.append(f"missing:{','.join(missing[:5])}{'...' if len(missing) > 5 else ''}")
    summary = " — ".join(summary_parts)

    result = {
        "domain": cleaned,
        "fetched_url": page["url"],
        "status_code": page["status_code"],
        **parsed,
        "score": score,
        "missing_signals": missing,
        "cache_respected": cache_respected,
        "summary": summary,
    }

    if cache_respected:
        await asave_cached_domain(cache_key, result)
    return result


@router.get(
    "/phone/{number}",
    operation_id="phone_lookup",
    response_model=PhoneLookupResponse,
    response_model_exclude_none=True,
    include_in_schema=True,
)
async def phone_endpoint(
    number: Annotated[
        str,
        Path(
            description=(
                "Phone number in any format (E.164 preferred, e.g. '+14155552671'; '+' URL-encoded as '%2B'). "
                "Max 50 chars. International prefix strongly recommended — without it, the country cannot be inferred."
            ),
        ),
    ],
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/phone"))],
):
    """Phone number validation and intelligence — format, country, type, carrier, timezone."""
    result = await run_in_threadpool(phone_lookup, number)
    return result


@router.get(
    "/username/{username}",
    operation_id="username_lookup",
    response_model=UsernameLookupResponse,
    response_model_exclude_none=True,
    include_in_schema=True,
)
async def username_endpoint(
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
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/username"))],
):
    """Username OSINT — check if a username exists on 16 platforms (GitHub, Reddit, X, etc.)."""
    return await run_in_threadpool(username_lookup, username)


@router.get(
    "/whois/{domain}", operation_id="whois_lookup", response_model=WhoisResponse, response_model_exclude_none=True
)
async def whois_endpoint(
    domain: DomainPath,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/whois"))],
):
    """WHOIS registration data for a domain."""
    domain, resolved_ip = _validate_domain_input(domain)
    cached = await _from_cache(domain, "whois", auth.tier)
    if cached and "error" not in cached:
        return {"domain": domain, "whois": cached, "summary": _whois_summary(cached, domain)}
    result = await run_in_threadpool(whois_lookup, domain)
    if "error" in result:
        raise HTTPException(status_code=504, detail=result["error"])
    return {"domain": domain, "whois": result, "summary": _whois_summary(result, domain)}


_SUBDOMAIN_PIVOT_CAP = 10
# RFC 1123 hostname charset — letters/digits/hyphen/dot only. CT-log SANs are
# third-party data and have been observed carrying literal newlines / control
# chars; rejecting non-conforming labels at the hint boundary prevents control
# bytes from reaching PivotHint.reason where downstream renderers (docs, MCP UI)
# could mis-render them as injection vectors.
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")


def _subdomain_pivot_hints(subdomains: list[str] | None) -> list[PivotHint]:
    """Build ssl_check pivot hints for the first N RFC-1123-valid subdomains.

    Cap=10 keeps the response token-cheap on large enumerations (Cloudflare-class
    domains can return 1000+ subdomains; 1000 hints would dominate the payload).
    Bumped from 5 → 10 (Action #12) — agents batch ssl_check easily and the head
    of the list is the high-value triage zone.
    Subdomains failing hostname-charset validation are dropped — CT logs deliver
    third-party-controlled strings and a maliciously-issued cert SAN can carry
    control chars (newline / tab / 0x7f) that would otherwise reach the hint
    reason field. The cap is intentional — agents triage the head of the list
    and re-call subdomain_enum or ssl_check on tail entries by name.
    """
    if not subdomains:
        return []
    safe = [s for s in subdomains if isinstance(s, str) and _HOSTNAME_RE.match(s)]
    head = safe[:_SUBDOMAIN_PIVOT_CAP]
    return [
        PivotHint(
            tool="ssl_check",
            input=sub,
            reason=f"Inspect TLS posture of discovered subdomain {sub} (grade, expiry, cipher).",
        )
        for sub in head
    ]


def _asn_pivot_hints(resolved_ip: str | None) -> list[PivotHint]:
    """Emit an ip_lookup pivot when asn_lookup was given a domain that resolved to an IP.

    asn_lookup deliberately returns only ASN/holder/prefix data even when the
    target was a domain — cloud-provider, Tor-exit, FireHOL and reputation
    enrichment live in ip_lookup. Without this hint the agent has to guess that
    a follow-up lookup exists. No hint when the input was already an IP (the
    agent has no new information to act on) or when resolution failed.
    """
    if not resolved_ip or not isinstance(resolved_ip, str):
        return []
    return [
        PivotHint(
            tool="ip_lookup",
            input=resolved_ip,
            reason=(
                "Pull cloud-provider / Tor-exit / FireHOL reputation context for the "
                "resolved IP — asn_lookup intentionally omits these to stay focused."
            ),
        )
    ]


@router.get(
    "/subdomains/{domain}",
    operation_id="subdomain_enum",
    response_model=SubdomainsResponse,
    response_model_exclude_none=True,
)
async def subdomains(
    domain: DomainPath,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/subdomains"))],
):
    """Subdomain enumeration via DNS brute force + certificate transparency."""
    domain, resolved_ip = _validate_domain_input(domain)
    # Tier-agnostic: DNS+CT data is the same regardless of caller, flat key maximises hits.
    cached = await aget_cached_domain(f"subdomains:{domain}")
    if cached is None:
        cached = await _from_cache(domain, "subdomains", auth.tier)
    if cached:
        sub_list = cached.get("subdomains") or []
        return {"domain": domain, **cached, "next_calls": _subdomain_pivot_hints(sub_list) or None}
    result = await run_in_threadpool(enumerate_subdomains, domain)
    await asave_cached_domain(f"subdomains:{domain}", result)
    sub_list = result.get("subdomains") or []
    return {"domain": domain, **result, "next_calls": _subdomain_pivot_hints(sub_list) or None}


@router.get("/certs/{domain}", operation_id="ct_logs", response_model=CertsResponse, response_model_exclude_none=True)
async def certs(
    domain: DomainPath,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/certs"))],
):
    """Certificate transparency log lookup."""
    domain, resolved_ip = _validate_domain_input(domain)
    # Tier-agnostic: CT log data is the same regardless of caller, flat key maximises hits.
    cached = await aget_cached_domain(f"certificates:{domain}")
    if cached is None:
        cached = await _from_cache(domain, "certificates", auth.tier)
    if cached:
        total = cached.get("total_certificates", 0)
        summary = f"{total} certificate{'s' if total != 1 else ''} in CT logs for {domain}"
        return {"domain": domain, **cached, "summary": summary}
    result = await run_in_threadpool(check_ct_logs, domain)
    await asave_cached_domain(f"certificates:{domain}", result)
    total = result.get("total_certificates", 0)
    summary = f"{total} certificate{'s' if total != 1 else ''} in CT logs for {domain}"
    return {"domain": domain, **result, "summary": summary}


@router.get(
    "/ssl/{domain}", operation_id="ssl_certificate", response_model=SslResponse, response_model_exclude_none=True
)
async def ssl_certificate(
    domain: DomainPath,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/ssl"))],
):
    """SSL certificate details with grade, chain, cipher, and protocol information."""
    domain, resolved_ip = _validate_domain_input(domain)

    # Check cache (keyed as ssl:<domain> in domain_cache)
    cached = await aget_cached_domain(f"ssl:{domain}")
    if cached:
        return {**cached}

    connect_host = resolved_ip or domain
    cert_der: bytes | None = None
    cipher_info: tuple | None = None
    tls_version: str = ""
    chain_verified = False
    validation_errors: list[str] = []

    # Pass 1: verified context — happy path
    try:
        ctx = _ssl.create_default_context()
        with socket.create_connection((connect_host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version() or "unknown"
                cipher_info = ssock.cipher()
                chain_verified = True
    except _ssl.SSLCertVerificationError as e:
        verify_msg = getattr(e, "verify_message", "") or str(e)
        validation_errors = _classify_ssl_verify_error(verify_msg)
    except (socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError, _ssl.SSLError) as e:
        logger.warning("SSL connection failed: %s", type(e).__name__)
        raise HTTPException(status_code=504, detail=f"Could not establish SSL connection to {domain}") from None

    # Pass 2: if verification failed, retry unverified to fetch cert + cipher
    if cert_der is None:
        try:
            unverified = _ssl.create_default_context()
            unverified.check_hostname = False
            unverified.verify_mode = _ssl.CERT_NONE
            with socket.create_connection((connect_host, 443), timeout=5) as sock:
                with unverified.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    tls_version = ssock.version() or "unknown"
                    cipher_info = ssock.cipher()
        except Exception as e:
            logger.warning("SSL unverified retry failed: %s", type(e).__name__)
            raise HTTPException(status_code=504, detail=f"SSL inspection failed for {domain}") from None

    parsed = _parse_cert_der(cert_der) if cert_der else None
    if parsed is None:
        raise HTTPException(status_code=504, detail=f"SSL cert parse failed for {domain}") from None

    # Independent expiry check
    if parsed["days_remaining"] is not None and parsed["days_remaining"] < 0 and "expired" not in validation_errors:
        validation_errors.append("expired")

    # Independent hostname check (only when chain wasn't already verified)
    if not chain_verified and "hostname_mismatch" not in validation_errors:
        if not _hostname_matches(parsed["san"], parsed["common_name"], domain):
            validation_errors.append("hostname_mismatch")

    cert_valid = chain_verified and not validation_errors
    grade = _ssl_grade(tls_version, parsed["days_remaining"], cert_valid, validation_errors)

    # Chain enrichment via AIA (best-effort, on parsed leaf)
    chain: list[dict] = []
    warnings: list[str] = []
    try:
        leaf_cert = x509.load_der_x509_certificate(cert_der)
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
        cipher_dict = {
            "name": cipher_info[0],
            "protocol": cipher_info[1],
            "bits": cipher_info[2],
        }

    # Surface validation issues as human-readable warnings too
    for tag in validation_errors:
        warnings.append(f"cert {tag.replace('_', ' ')}")

    parts = [f"{domain} — {grade}"]
    parts.append(f"{tls_version}, {parsed['issuer'] or 'unknown issuer'}")
    if parsed["days_remaining"] is not None:
        parts.append(f"{parsed['days_remaining']} days remaining")
    if validation_errors:
        parts.append(f"INVALID: {', '.join(validation_errors)}")
    if any("AIA" in w for w in warnings):
        parts.append("(partial: chain incomplete)")

    result = {
        "domain": domain,
        "valid": cert_valid,
        "issuer": parsed["issuer"],
        "subject": parsed["common_name"],
        "not_before": parsed["not_before"],
        "not_after": parsed["not_after"],
        "days_remaining": parsed["days_remaining"],
        "serial_number": parsed["serial_number"],
        "signature_algorithm": None,
        "san": parsed["san"],
        "protocol": tls_version,
        "cipher": cipher_dict,
        "chain": chain,
        "grade": grade,
        "validation_errors": validation_errors,
        "warnings": warnings[:10],
        "summary": ". ".join(parts),
    }

    await asave_cached_domain(f"ssl:{domain}", result)
    return {**result}


@router.get(
    "/threat/{domain}", operation_id="threat_intel", response_model=ThreatResponse, response_model_exclude_none=True
)
async def threat_intel(
    domain: DomainPath,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/threat"))],
):
    """Threat intelligence — check domain against URLhaus for known malware URLs."""
    domain, resolved_ip = _validate_domain_input(domain)
    result = await run_in_threadpool(check_urlhaus, domain)
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
async def wayback_lookup_route(
    domain: DomainPath,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/archive"))],
):
    """Web archive lookup — historical snapshots from the Wayback Machine."""
    domain, resolved_ip = _validate_domain_input(domain)
    return await run_in_threadpool(wayback_lookup, domain)


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


@router.get("/ip/{ip}", operation_id="ip_lookup", response_model=IpLookupResponse, response_model_exclude_none=False)
async def ip_lookup(
    ip: IpPath,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/ip"))],
):
    """IP intelligence — reverse DNS, ASN + country (RIPE Stat), open ports, vulnerabilities, hostnames (Shodan InternetDB), cloud provider + is_datacenter flag, Tor exit detection, severity_label, and reputation (FireHOL level1 blocklist on Free tier; +AbuseIPDB + Shodan on Pro)."""
    if not is_valid_ip(ip):
        if "." in ip and not ip.replace(".", "").isdigit():
            raise HTTPException(
                status_code=400, detail=f"'{ip}' looks like a domain, not an IP. Use /v1/domain/{ip} instead."
            )
        raise HTTPException(status_code=400, detail="Invalid IP address")
    if is_private_ip(ip):
        raise HTTPException(status_code=400, detail="Private/reserved IP addresses are not allowed")
    client_ip = auth.client_ip

    # Kick ASN/country fetch in parallel with the rest of the critical path.
    asn_country_task = asyncio.create_task(run_in_threadpool(_fetch_asn_country, ip))

    try:
        addr_result, addr_err = await run_in_threadpool(_dns_call_with_timeout, socket.gethostbyaddr, ip)
        # Reverse DNS is owner-controlled; strip control / bidi chars before
        # echoing into the JSON response (Trojan Source CVE-2021-42574 class).
        ptr = _strip_control_chars(addr_result[0]) if addr_result and not addr_err else None
    except (socket.herror, socket.gaierror, OSError):
        ptr = None

    enrichment = await run_in_threadpool(ip_enrichment, ip)
    internetdb_failed = enrichment.pop("internetdb_status", "ok") == "error"
    ports = enrichment.get("ports", [])
    # Shodan InternetDB is upstream-controlled — a poisoned feed could smuggle
    # Trojan-Source bidi overrides into any of the free-text fields that flow
    # into the JSON response (vulns, hostnames, cpes, tags). Strip bidi /
    # control chars on every str-array field before any of them reach the
    # wire (or, for vulns, the cve.db lookup).
    enrichment["hostnames"] = _clean_shodan_str_list(enrichment.get("hostnames"))
    enrichment["cpes"] = _clean_shodan_str_list(enrichment.get("cpes"))
    enrichment["tags"] = _clean_shodan_str_list(enrichment.get("tags"))
    # Phase 2 IP enrichment (v1.16.0 BREAKING): replace the flat list[str] of
    # CVE IDs from Shodan InternetDB with severity-aware list[VulnInfo] so
    # agents can triage without a fan-out cve_lookup per CVE. See
    # db.enrich_cves_by_ids docstring for the unknown-CVE contract.
    raw_vulns = _clean_shodan_str_list(enrichment.get("vulns"))
    vulns = await aenrich_cves_by_ids(raw_vulns)
    enrichment["vulns"] = vulns
    hostnames = enrichment.get("hostnames", [])

    # Reputation enrichment (rate-limited per client IP)
    reputation = {}
    rep_age: int | None = None
    reputation_attempted = False
    reputation_failed = False
    firehol_attempted = False
    firehol_failed = False
    hit = await aget_cached_ip_with_age(ip)
    if hit is not None:
        reputation, rep_age = hit
        reputation_attempted = True
    elif auth.tier == "pro" and await ratelimit.acheck_limit(
        store_name="enrichment",
        key=hash_client_ip(client_ip),
        max_requests=ENRICHMENT_DAILY_LIMIT,
        window_seconds=86400,
    ):
        reputation_attempted = True
        firehol_attempted = True
        # Credit-refund correctness: acheck_limit consumed 1 enrichment credit.
        # If the gather() fails OR the request is cancelled mid-await (client
        # disconnect → asyncio.CancelledError, which is NOT an Exception
        # subclass on Python 3.8+), we must refund before propagating, else
        # repeated client-side cancels exhaust the user's daily quota for free.
        enrichment_succeeded = False
        try:
            ab_res, sh_res, fh_res = await asyncio.wait_for(
                asyncio.gather(
                    run_in_threadpool(check_abuseipdb, ip),
                    run_in_threadpool(check_shodan, ip),
                    run_in_threadpool(check_firehol, ip),
                ),
                timeout=RECON_TIMEOUT + 2,
            )
            reputation = {
                "firehol": fh_res,
                "abuseipdb": ab_res,
                "shodan": sh_res,
            }
            if fh_res.get("status") == "unavailable":
                firehol_failed = True
            await asave_cached_ip(ip, reputation)
            rep_age = 0
            enrichment_succeeded = True
        except Exception as e:
            logger.warning("Reputation enrichment failed: %s", type(e).__name__)
            reputation = {}
            reputation_failed = True
        finally:
            if not enrichment_succeeded:
                # Refund must run on BaseException too (CancelledError) — pre-Faz-4
                # the sync .submit/.result chain raised CancelledError up through
                # this except block as a generic Exception; on async it bypasses.
                await ratelimit.arefund("enrichment", client_ip)
    elif auth.tier != "pro":
        firehol_result = await run_in_threadpool(check_firehol, ip)
        firehol_attempted = True
        # Bug I4: free tier used to ship two ~13-field pro_only stubs
        # (abuseipdb + shodan, every property null) — ~150 token of pure
        # negative space telling the agent "Pro only". The verdict block
        # already lists abuseipdb / shodan in sources_unavailable on free
        # tier, the response now carries a single compact upgrade hint.
        reputation = {
            "firehol": firehol_result,
            "upgrade": {
                "pro_only_sources": ["abuseipdb", "shodan"],
                "upgrade_url": UPGRADE_URL,
                "reason": "AbuseIPDB and Shodan enrichment require the Pro tier",
            },
        }
        if firehol_result.get("status") == "unavailable":
            firehol_failed = True
        reputation_attempted = True

    try:
        tor_exit = await run_in_threadpool(check_tor_exit, ip)
    except Exception:
        tor_exit = False
    tor_status = tor_cache_status()

    try:
        asn_data = await asyncio.wait_for(asn_country_task, timeout=6.0)
    except Exception:
        logger.debug("_fetch_asn_country future timed out or failed")
        asn_data = {"asn": None, "asn_name": "", "country": "", "failed": True}

    asn_val = asn_data.get("asn")
    asn_name_val = asn_data.get("asn_name") or ""
    country_val = asn_data.get("country") or ""
    ripe_failed = bool(asn_data.get("failed"))

    # cloud_provider after asn so the ASN-map fallback can fire when the IP isn't
    # in a published CIDR range (e.g. 8.8.8.8 → AS15169 → "Google").
    try:
        cloud_provider = check_cloud_provider(ip, asn=asn_val)
    except Exception:
        cloud_provider = None

    is_datacenter_flag = is_datacenter(ip, asn=asn_val, cloud_provider=cloud_provider)

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

    firehol_for_score = reputation.get("firehol") if reputation else None
    _risk = score_ip(
        reputation or None,
        ports,
        ptr,
        cloud_provider,
        tor_exit,
        vulns=vulns,
        is_datacenter=is_datacenter_flag,
        firehol=firehol_for_score,
    )
    result = {
        "ip": ip,
        "ptr": ptr,
        "asn": asn_val,
        "asn_name": asn_name_val or None,
        "country": country_val or None,
        **enrichment,
        "cloud_provider": cloud_provider,
        "is_datacenter": is_datacenter_flag,
        "tor_exit": tor_exit,
        "risk_score": _risk,
        "severity_label": severity_label(_risk),
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
        tor_status=tor_status,
    )
    pivot_hints = _ip_pivot_hints(ip, asn_val, reputation, auth.tier)
    if pivot_hints:
        result["next_calls"] = pivot_hints
    return result


@router.get(
    "/tech/{domain}", operation_id="tech_fingerprint", response_model=TechResponse, response_model_exclude_none=True
)
async def tech_fingerprint(
    domain: DomainPath,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/tech"))],
):
    """Technology fingerprinting — detect CMS, frameworks, servers, CDNs, analytics."""
    domain, resolved_ip = _validate_domain_input(domain)
    page = await run_in_threadpool(fetch_live_page, domain)
    if "error" in page:
        raise HTTPException(status_code=504, detail=page["error"])
    from domain.tech import detect_technologies

    result = detect_technologies(page["headers"], page.get("html"))
    return {"domain": domain, **result}


@router.get(
    "/monitor/{domain}", operation_id="domain_monitor", response_model=MonitorResponse, response_model_exclude_none=True
)
async def domain_monitor(
    domain: DomainPath,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/monitor"))],
):
    """Lightweight health check — DNS up/down, SSL status, risk grade from cache. Designed for high-frequency polling."""
    domain, resolved_ip = _validate_domain_input(domain)

    # Quick DNS A record check
    dns_a = await run_in_threadpool(quick_dns_a, domain)
    is_up = dns_a is not None and len(dns_a) > 0

    # SSL info (single TLS handshake)
    ssl_days = None
    ssl_grade = None
    try:
        ssl_result = await run_in_threadpool(ssl_info, domain, resolved_ip)
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
    cached = await aget_cached_domain(f"{auth.tier}:{domain}")
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
async def domain_vulns(
    domain: DomainPath,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/domain/vulns"))],
):
    """Tech stack vulnerability scan — detect technologies, then look up CVEs for each."""
    domain, resolved_ip = _validate_domain_input(domain)

    page = await run_in_threadpool(fetch_live_page, domain)
    if "error" in page:
        raise HTTPException(status_code=504, detail=page["error"])

    from db import asearch_cves_by_products_bulk, normalize_product, parse_version
    from domain.tech import detect_technologies

    tech_result = detect_technologies(page["headers"], page.get("html"))
    technologies = tech_result.get("technologies", [])

    # Cap defensive bounds against malicious upstream HTML (header injection, meta-tag
    # spam): truncate tech name (256), version (128), and total product count (500 —
    # the bulk function's hard limit; trim here so we never raise instead of degrading).
    MAX_TECHS = 500
    product_names = [(t["name"] or "")[:256] for t in technologies[:MAX_TECHS] if t.get("name")]
    bulk = await asearch_cves_by_products_bulk(product_names, limit_per_product=10) if product_names else {}

    vulnerabilities = []
    total_cves = 0
    techs_with_cves = 0

    for tech in technologies[:MAX_TECHS]:
        name = (tech["name"] or "")[:256]
        version = tech.get("version")
        if version and len(version) > 128:
            version = None
        limit = 10 if version else 5
        key = (normalize_product(name) or name).strip().lower()
        raw = bulk.get(key, [])

        parsed_ver = parse_version(version) if version else None
        filtered = []
        for cve in raw:
            if parsed_ver:
                matched = False
                for prod in cve.get("affected_products", []):
                    if key not in (prod.get("product") or "").lower():
                        continue
                    vs, ve = prod.get("version_start"), prod.get("version_end")
                    try:
                        if vs and parsed_ver < parse_version(vs):
                            continue
                        if ve and parsed_ver >= parse_version(ve):
                            continue
                    except TypeError:
                        continue
                    matched = True
                    break
                if not matched and cve.get("affected_products"):
                    continue
            filtered.append(cve)
            if len(filtered) >= limit:
                break

        cve_items = [
            {
                "cve_id": c["cve_id"],
                "severity": c.get("severity"),
                "cvss_v3": c.get("cvss_v3"),
                "epss_score": c.get("epss_score"),
                "in_kev": bool(c.get("in_kev")),
            }
            for c in filtered
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


def _truncate_asn_prefixes(result: dict, include_full: bool) -> dict:
    """Return a shallow copy of an asn_lookup result with prefix lists truncated.

    Cache stores full prefixes; responses truncate to MAX_ASN_PREFIXES_DEFAULT
    unless include_full is True. ipv4_count/ipv6_count remain honest pre-truncation.
    """
    if include_full:
        return result
    out = dict(result)
    v4 = out.get("ipv4_prefixes")
    v6 = out.get("ipv6_prefixes")
    if isinstance(v4, list) and len(v4) > MAX_ASN_PREFIXES_DEFAULT:
        out["ipv4_prefixes"] = v4[:MAX_ASN_PREFIXES_DEFAULT]
    if isinstance(v6, list) and len(v6) > MAX_ASN_PREFIXES_DEFAULT:
        out["ipv6_prefixes"] = v6[:MAX_ASN_PREFIXES_DEFAULT]
    return out


@router.get("/asn/{target}", operation_id="asn_lookup", response_model=AsnResponse, response_model_exclude_none=True)
async def asn_lookup(
    target: Annotated[
        str,
        Path(
            description=(
                "ASN or IP. Accepts 'AS13335', '13335', or an IPv4/IPv6 address. "
                "For IP input, the response resolves the containing ASN via RIPE Stat."
            ),
        ),
    ],
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/asn"))],
    include_full_prefixes: Annotated[
        bool,
        Query(
            description=(
                f"Return the full announced-prefixes list (default: false, returns first {MAX_ASN_PREFIXES_DEFAULT}). "
                "ipv4_count and ipv6_count are always honest pre-truncation totals. "
                "Set true for network mapping or BGP route audits."
            ),
        ),
    ] = False,
):
    """ASN lookup — resolve target (domain or IP) to its Autonomous System Number, holder name, and announced prefixes."""
    import ipaddress

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
        a_records = await run_in_threadpool(quick_dns_a, domain)
        if not a_records:
            raise HTTPException(status_code=422, detail=f"Could not resolve domain '{target}' to an IP address")
        ip = a_records[0]
        resolved_ip = ip

    # Check cache
    cache_key = f"asn:{ip}"
    cached = await aget_cached_domain(cache_key)
    if cached:
        result = {**cached, "target": target}
        if resolved_ip:
            result["resolved_ip"] = resolved_ip
        elif "resolved_ip" in result:
            del result["resolved_ip"]
        # Cache entries written before Bug I1 carry [{"prefix": str}] wrappers;
        # the new response_model expects list[str] and would 500 on those for
        # the full TTL after deploy. Coerce here so old entries serve cleanly
        # until they expire and get rewritten in the new shape.
        for key in ("ipv4_prefixes", "ipv6_prefixes"):
            seq = result.get(key) or []
            if seq and isinstance(seq[0], dict):
                result[key] = [p.get("prefix", "") for p in seq if p.get("prefix")]
        # Rebuild the verdict from cached warnings — older cache entries
        # written before Bug I2 do not carry one, and even fresh entries
        # should report data_age_seconds=None on a cache hit (we do not
        # track exact age in the asn cache).
        result["verdict"] = _asn_verdict(cached.get("warnings") or [], age_seconds=None)
        result["next_calls"] = _asn_pivot_hints(resolved_ip) or None
        return _truncate_asn_prefixes(result, include_full_prefixes)

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
            v4: list[str] = []
            v6: list[str] = []
            for p in prefixes:
                prefix = p.get("prefix", "")
                if not prefix:
                    continue
                try:
                    net = ipaddress.ip_network(prefix, strict=False)
                    if net.version == 4:
                        v4.append(prefix)
                    else:
                        v6.append(prefix)
                except ValueError:
                    continue
            return v4, v6
        except (_httpx.HTTPError, _httpx.TimeoutException, ValueError, KeyError, TypeError) as e:
            raise AsnUpstreamError("announced-prefixes", type(e).__name__) from e

    warnings: list[str] = []

    overview_task = asyncio.create_task(run_in_threadpool(_fetch_overview))
    prefixes_task = asyncio.create_task(run_in_threadpool(_fetch_prefixes))

    try:
        asn_name = await asyncio.wait_for(overview_task, timeout=7)
    except AsnUpstreamError as e:
        asn_name = ""
        warnings.append(f"{e.upstream}: {e.reason}")
        logger.warning("ASN upstream failure: %s %s", e.upstream, e.reason)
    except (asyncio.TimeoutError, TimeoutError):
        asn_name = ""
        warnings.append("as-overview: timeout")
        logger.warning("ASN upstream failure: as-overview timeout")

    try:
        ipv4_prefixes, ipv6_prefixes = await asyncio.wait_for(prefixes_task, timeout=7)
    except AsnUpstreamError as e:
        ipv4_prefixes, ipv6_prefixes = [], []
        warnings.append(f"{e.upstream}: {e.reason}")
        logger.warning("ASN upstream failure: %s %s", e.upstream, e.reason)
    except (asyncio.TimeoutError, TimeoutError):
        ipv4_prefixes, ipv6_prefixes = [], []
        warnings.append("announced-prefixes: timeout")
        logger.warning("ASN upstream failure: announced-prefixes timeout")

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

    # Empty-cache poisoning guard (Bug NEW-A): when both RIPE futures fail at
    # write time we end up with asn populated (network-info gave us a number)
    # but asn_name="" and both prefix lists []. Caching that for the full TTL
    # keeps serving the empty payload forever — any future caller sees
    # AS<num> with no holder name. Skip the write in that two-failure case
    # so the next request re-hits RIPE. Partial success (e.g. holder OK,
    # prefixes failed) is still cacheable: at least one piece of metadata
    # made it through and is worth preserving.
    #
    # The verdict is built *after* the cache write so we never persist a
    # Pydantic model into the JSON cache (json.dumps would TypeError) and
    # so the cache-hit path can rebuild a fresh verdict with
    # data_age_seconds=None instead of forwarding a stale age=0.
    both_metadata_futures_failed = bool(warnings) and not asn_name and not ipv4_prefixes and not ipv6_prefixes
    if not both_metadata_futures_failed:
        await asave_cached_domain(cache_key, result)
    out = {
        **result,
        "verdict": _asn_verdict(warnings, age_seconds=0),
        "next_calls": _asn_pivot_hints(resolved_ip) or None,
    }
    return _truncate_asn_prefixes(out, include_full_prefixes)


class _BulkRequest(BaseModel):
    domains: list[str] = Field(
        ...,
        min_length=1,
        max_length=50,
        description=(
            "List of registrable domain names to report on (e.g. ['example.com', 'api.example.com']). "
            "No scheme, no path, no port. Punycode/IDN accepted; subdomains allowed. Each domain "
            "counts as 1 request toward the rate limit (4 credits per domain)."
        ),
    )


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
async def bulk_domain_report(
    body: _BulkRequest,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/domains/bulk"))],
):
    """Bulk domain intelligence — up to 10 domains (free) or 50 (pro). Each domain counts as 1 request toward rate limit."""
    client_ip = auth.client_ip

    # Tier-based bulk limit
    from config import FREE_BULK_LIMIT, PRO_BULK_LIMIT

    bulk_limit = PRO_BULK_LIMIT if auth.tier == "pro" else FREE_BULK_LIMIT

    # Deduplicate domains (preserve order)
    domains = list(dict.fromkeys(body.domains))
    count = len(domains)

    if count > bulk_limit:
        raise HTTPException(
            status_code=422,
            detail=f"Too many domains. Limit: {bulk_limit} (your tier: {auth.tier})",
        )

    # Check remaining quota before starting (each domain = 1 request)
    if auth.tier == "pro":
        from config import PRO_HOURLY_LIMIT

        store_key = f"pro:{auth.key_hash}"
        limit = PRO_HOURLY_LIMIT
    else:
        from config import FREE_HOURLY_LIMIT

        store_key = f"free:{hash_client_ip(client_ip)}"
        limit = FREE_HOURLY_LIMIT

    # Order matters: acquire the concurrency slot BEFORE consuming bulk quota.
    # The opposite order leaves a window where (count-1) credits are debited
    # but the request 503s on semaphore exhaustion — credits silently lost.
    if not _bulk_semaphore.acquire(blocking=False):
        raise HTTPException(
            status_code=503,
            detail="Too many concurrent bulk requests. Please retry shortly.",
        )

    # Atomic check-and-consume: require_auth already consumed 1, we need (count - 1) more
    if count > 1 and not await ratelimit.aconsume_bulk("api", store_key, count - 1, limit):
        _bulk_semaphore.release()
        raise HTTPException(
            status_code=429,
            detail=f"Insufficient rate limit quota for {count} domains.",
        )

    try:
        # Run reports in parallel, preserving input order. Per-domain timeout
        # caps each individual report; the overall deadline cancels any task
        # that hasn't completed when the global window closes (those become
        # "Bulk request timed out" + partial=True, mirroring the pre-async
        # for-loop behaviour).
        per_domain_tasks = [
            asyncio.create_task(
                asyncio.wait_for(
                    run_in_threadpool(_run_single_report, d, client_ip, auth.tier),
                    timeout=BULK_PER_DOMAIN_TIMEOUT,
                )
            )
            for d in domains
        ]
        done, pending = await asyncio.wait(per_domain_tasks, timeout=BULK_OVERALL_TIMEOUT)

        timed_out = 0
        partial = False
        results: list[dict] = []
        for d, task in zip(domains, per_domain_tasks, strict=True):
            if task in pending:
                task.cancel()
                logger.warning("Bulk overall timeout — skipping remaining domains")
                results.append({"domain": d, "status": "error", "report": None, "error": "Bulk request timed out"})
                timed_out += 1
                partial = True
                continue
            try:
                results.append(task.result())
            except (asyncio.TimeoutError, TimeoutError):
                logger.warning("Bulk report timed out")
                results.append({"domain": d, "status": "error", "report": None, "error": "Domain report timed out"})
                timed_out += 1
            except Exception as exc:
                logger.warning("Bulk report failed: %s", type(exc).__name__)
                results.append({"domain": d, "status": "error", "report": None, "error": "Domain report failed"})
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
async def audit_domain(
    domain: str,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/audit", cost=COST_AUDIT))],
    include_all_txt: Annotated[
        bool,
        Query(
            description=(
                "Return every TXT record under report.dns.txt (default: only SPF, DMARC, DKIM, "
                "MTA-STS, TLS-RPT). report.dns.total_txt_records is always emitted with the honest "
                "pre-filter count. Mirrors /v1/domain/{domain}'s include_all_txt — default keeps "
                "the audit response slim by stripping vendor verification strings."
            ),
        ),
    ] = False,
):
    """Comprehensive domain audit — full intelligence report + technology fingerprint + live HTTP headers in a single call.

    Aggregates DNS, SSL, WHOIS, subdomains, threat intelligence, technology detection,
    HTTP security headers, and reputation data. Designed for AI agents and security
    automation that need a complete picture in one request.
    """
    from domain.recon import fetch_live_headers
    from domain.tech import detect_technologies

    domain = clean_domain(domain)
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain")

    client_ip = auth.client_ip
    tier = auth.tier
    cache_key = f"{tier}:{domain}"

    cached = await aget_cached_domain(cache_key)
    if cached:
        report = cached
    else:
        # Hard timeout guard — full_domain_report can hang on slow upstream
        # fail-overs (WHOIS, CT logs, subdomain enum). Cap at BULK_PER_DOMAIN_TIMEOUT.
        try:
            report = await asyncio.wait_for(
                run_in_threadpool(full_domain_report, domain, client_ip=client_ip, tier=tier),
                timeout=BULK_PER_DOMAIN_TIMEOUT,
            )
        except (asyncio.TimeoutError, TimeoutError):
            logger.warning("audit_domain: full_domain_report timed out")
            raise HTTPException(status_code=504, detail="Domain audit timed out — target upstream slow") from None
        except Exception as e:
            logger.warning("audit_domain: full_domain_report failed: %s", type(e).__name__)
            raise HTTPException(status_code=502, detail="Domain audit failed") from None
        await asave_cached_domain(cache_key, report)

    # Apply the TXT filter AFTER caching the unfiltered report so the cache stays
    # canonical and ?include_all_txt=true on a subsequent request can serve the
    # full TXT list without a re-fetch. _apply_txt_filter shallow-copies the dns
    # block, so this does not mutate the cached entry.
    report = _apply_txt_filter(report, include_all_txt)

    try:
        live = await run_in_threadpool(fetch_live_headers, domain)
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

    # Audit already bundles tech_fingerprint + live_headers — emit subdomain_enum
    # (always) + ssl_check (when an A record resolves), skip tech_fingerprint.
    audit_hints: list[PivotHint] = []
    dns_block = report.get("dns") or {}
    has_a = bool(dns_block.get("a") or dns_block.get("aaaa"))
    if dns_block or has_a:
        audit_hints.append(
            PivotHint(
                tool="subdomain_enum",
                input=domain,
                reason="Map attack surface — enumerate subdomains via crt.sh CT logs + DNS wordlist (passive).",
            )
        )
        if has_a:
            audit_hints.append(
                PivotHint(
                    tool="ssl_check",
                    input=domain,
                    reason="Inspect TLS certificate: grade, protocol, cipher, expiry, AIA chain, OCSP status.",
                )
            )

    return {
        "domain": domain,
        "report": report,
        "technologies": tech,
        "live_headers": headers,
        "summary": summary,
        "next_calls": audit_hints or None,
    }


@router.get(
    "/threat-report/{ip}",
    operation_id="threat_report",
    response_model=ThreatReportResponse,
    response_model_exclude_none=True,
)
async def threat_report(
    ip: IpPath,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/threat-report", cost=COST_THREAT_REPORT))],
):
    """Comprehensive IP threat report — Shodan InternetDB + AbuseIPDB + Shodan full + ASN in a single call.

    Aggregates open ports, vulnerabilities, abuse reports, geolocation, ASN ownership,
    and reputation across multiple sources. Designed for SOC triage and threat hunting
    where a complete IP profile is needed without making 4+ separate API calls.
    """
    if not is_valid_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")
    if is_private_ip(ip):
        raise HTTPException(status_code=400, detail="Private/reserved IP addresses are not allowed")

    enrich_task = asyncio.create_task(run_in_threadpool(ip_enrichment, ip))
    if auth.tier == "pro":
        abuse_task = asyncio.create_task(run_in_threadpool(check_abuseipdb, ip))
        shodan_task = asyncio.create_task(run_in_threadpool(check_shodan, ip))
    else:
        abuse_task = None
        shodan_task = None

    try:
        enrichment = await asyncio.wait_for(enrich_task, timeout=10)
    except Exception as e:
        logger.warning("threat_report: ip_enrichment failed: %s", type(e).__name__)
        enrich_task.cancel()
        enrichment = {"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": []}
    if abuse_task is not None:
        try:
            abuseipdb = await asyncio.wait_for(abuse_task, timeout=10)
        except Exception as e:
            logger.warning("threat_report: check_abuseipdb failed: %s", type(e).__name__)
            abuse_task.cancel()
            abuseipdb = {"status": "error"}
    else:
        abuseipdb = {
            "status": "pro_only",
            "reason": "AbuseIPDB enrichment requires Pro tier",
            "upgrade_url": UPGRADE_URL,
        }
    if shodan_task is not None:
        try:
            shodan_data = await asyncio.wait_for(shodan_task, timeout=10)
        except Exception as e:
            logger.warning("threat_report: check_shodan failed: %s", type(e).__name__)
            shodan_task.cancel()
            shodan_data = {"status": "error"}
    else:
        shodan_data = {
            "status": "pro_only",
            "reason": "Shodan enrichment requires Pro tier",
            "upgrade_url": UPGRADE_URL,
        }

    if not isinstance(enrichment, dict):
        enrichment = {"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": []}
    # Trojan-Source guard parity with ip_lookup: strip bidi / control chars
    # from every Shodan-supplied str-array before enrichment + serialization.
    enrichment["hostnames"] = _clean_shodan_str_list(enrichment.get("hostnames"))
    enrichment["cpes"] = _clean_shodan_str_list(enrichment.get("cpes"))
    enrichment["tags"] = _clean_shodan_str_list(enrichment.get("tags"))
    # Phase 2 IP enrichment parity: threat_report.enrichment.vulns ships the
    # same severity-aware list[VulnInfo] shape as ip_lookup.vulns (v1.16.0
    # BREAKING). Pre-1.16 this was list[str].
    enrichment["vulns"] = await aenrich_cves_by_ids(_clean_shodan_str_list(enrichment.get("vulns")))
    if not isinstance(abuseipdb, dict):
        abuseipdb = {"status": "error"}
    if not isinstance(shodan_data, dict):
        shodan_data = {"status": "error"}

    asn_data = {}
    try:
        cache_key = f"asn:{ip}"
        cached_asn = await aget_cached_domain(cache_key)
        if cached_asn:
            asn_data = _truncate_asn_prefixes(cached_asn, include_full=False)
        # Use the shared _fetch_asn_country helper that ip_lookup runs so
        # threat_report sees the same asn_name + country enrichment instead
        # of reinventing a network-info-only fetch (Bug I3 — passive intel
        # parity with ip_lookup).
        country_payload = await run_in_threadpool(_fetch_asn_country, ip)
        if country_payload.get("asn") and not asn_data.get("asn"):
            asn_data["asn"] = country_payload["asn"]
        if country_payload.get("asn_name") and not asn_data.get("asn_name"):
            asn_data["asn_name"] = country_payload["asn_name"]
        if country_payload.get("country") and not asn_data.get("country"):
            asn_data["country"] = country_payload["country"]
        if country_payload.get("failed") and not asn_data:
            asn_data = {"error": "lookup_failed"}
    except Exception as e:
        logger.warning("threat_report: ASN lookup failed: %s", type(e).__name__)
        asn_data = {"error": "lookup_failed"}

    # Bug I3: threat_report (Pro, 4-credit) used to return strictly LESS
    # passive intel than ip_lookup (1-credit) — no PTR, asn_name, country,
    # cloud_provider, tor_exit, firehol, risk_score, or verdict. Bring it up
    # to ip_lookup parity by embedding the cheap-to-fetch passive fields here
    # so SOC triage callers do not need a second ip_lookup call to fill in
    # the basics.
    try:
        ptr_result, _ = await run_in_threadpool(_dns_call_with_timeout, socket.gethostbyaddr, ip)
        # Reverse DNS is owner-controlled; strip control / bidi chars before
        # echoing into the JSON response (same pattern as DNS TXT / DKIM).
        ptr = _strip_control_chars(ptr_result[0]) if ptr_result else None
    except Exception:
        ptr = None

    asn_name = ""
    country = ""
    if isinstance(asn_data, dict):
        asn_name = asn_data.get("asn_name") or ""
        country = asn_data.get("country") or ""

    try:
        tor_exit = await run_in_threadpool(check_tor_exit, ip)
    except Exception:
        tor_exit = False
    tor_status = tor_cache_status()

    asn_val = asn_data.get("asn") if isinstance(asn_data, dict) else None
    try:
        cloud_provider = await run_in_threadpool(check_cloud_provider, ip, asn=asn_val)
    except Exception:
        cloud_provider = None

    is_datacenter_flag = is_datacenter(ip, asn=asn_val, cloud_provider=cloud_provider)

    try:
        firehol = await run_in_threadpool(check_firehol, ip)
    except Exception:
        firehol = {"status": "unavailable"}

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
        # enrichment.vulns is now list[VulnInfo dict] (v1.16.0); shodan_data.vulns
        # is still raw list[str] from the Pro Shodan API. Extract IDs for the
        # summary count so the dedupe still works across both shapes.
        enrichment_ids = {v["cve_id"] for v in enrichment.get("vulns", []) if isinstance(v, dict)}
        shodan_ids = set(shodan_data.get("vulns", []) or [])
        all_vulns = enrichment_ids | shodan_ids
        summary_parts.append(f"{len(all_vulns)} known vulns")
    summary_parts.append(f"threat level: {threat_level}")
    summary = " · ".join(summary_parts)

    # Build the same shape ip_lookup uses for risk + reputation so a
    # downstream score_ip call agrees with whatever ip_lookup would emit.
    rep_for_score = {
        "firehol": firehol,
        "abuseipdb": abuseipdb if abuseipdb.get("status") not in ("pro_only", "error") else None,
    }
    rep_for_score = {k: v for k, v in rep_for_score.items() if v is not None}
    risk = score_ip(
        rep_for_score or None,
        enrichment.get("ports") or [],
        ptr,
        cloud_provider,
        tor_exit,
        vulns=enrichment.get("vulns"),
        is_datacenter=is_datacenter_flag,
        firehol=firehol if isinstance(firehol, dict) else None,
    )

    return {
        "ip": ip,
        "ptr": ptr,
        "asn_name": asn_name or None,
        "country": country or None,
        "cloud_provider": cloud_provider,
        "is_datacenter": is_datacenter_flag,
        "tor_exit": tor_exit,
        "firehol": firehol,
        "risk_score": risk,
        "severity_label": severity_label(risk),
        "enrichment": enrichment,
        "abuseipdb": abuseipdb,
        "shodan": shodan_data,
        "asn": asn_data,
        "threat_level": threat_level,
        "summary": summary,
        "verdict": Verdict(
            deterministic=True,
            falsifiable_fields=[
                "ptr",
                "asn",
                "asn_name",
                "country",
                "cloud_provider",
                "is_datacenter",
                "tor_exit",
                "firehol",
                "enrichment",
                "abuseipdb",
                "shodan",
                "risk_score",
                "severity_label",
            ],
            data_age_seconds=0,
            sources_queried=[
                "ripe_stat",
                "internetdb",
                "tor",
                "firehol",
                *(("abuseipdb", "shodan") if auth.tier == "pro" else ()),
            ],
            sources_unavailable=[
                *(["abuseipdb"] if auth.tier != "pro" else []),
                *(["shodan"] if auth.tier != "pro" else []),
                *(["tor"] if tor_status != "ok" else []),
                *(["firehol"] if firehol.get("status") == "unavailable" else []),
                *(["asn"] if isinstance(asn_data, dict) and asn_data.get("error") == "lookup_failed" else []),
            ],
            completeness="partial" if auth.tier != "pro" else "complete",
        ),
    }
