"""Domain Intelligence API routes — /v1/domain/*, /v1/dns/*, /v1/whois/*, etc."""

import logging
import socket
import ssl as _ssl
import threading
import time as _time
from concurrent.futures import ThreadPoolExecutor, TimeoutError

from fastapi import APIRouter, HTTPException, Request

_reputation_pool = ThreadPoolExecutor(max_workers=3)

import httpx as _httpx
import ratelimit

_ripe_client = _httpx.Client(timeout=_httpx.Timeout(7.0, connect=3.0), follow_redirects=False)
from auth import authenticate
from config import BULK_OVERALL_TIMEOUT, BULK_PER_DOMAIN_TIMEOUT, ENRICHMENT_DAILY_LIMIT, RECON_TIMEOUT
from db import get_cached_domain, get_cached_ip, save_cached_domain, save_cached_ip
from domain.archive import wayback_lookup
from domain.recon import (
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
    ThreatResponse,
    UsernameLookupResponse,
    VulnsResponse,
    WaybackResponse,
    WhoisResponse,
)
from validation import _is_valid_format, clean_domain, get_client_ip, is_private_ip, is_valid_ip, validate_domain

logger = logging.getLogger("contrastapi")

router = APIRouter(prefix="/v1", tags=["Domain Intelligence"])


@router.get("/", include_in_schema=False)
def api_root(request: Request):
    """Available endpoints when someone hits /v1/ directly."""
    authenticate(request, "/v1")
    return {
        "api": "ContrastAPI",
        "docs": "https://github.com/UPinar/contrastapi#endpoints",
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
            "epss": {"path": "/v1/epss/CVE-2024-3094", "method": "GET", "description": "Exploit probability score"},
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


def _from_cache(domain: str, key: str) -> dict | None:
    """Try to extract a section from a cached full domain report."""
    cached = get_cached_domain(domain)
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
def domain_report(domain: str, request: Request, lite: bool = False):
    """Full domain intelligence report with DNS, WHOIS, SSL, subdomains, WAF. Use ?lite=true for fast subset."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)

    # Separate cache keys for lite vs full
    cache_key = f"lite:{domain}" if lite else domain
    cached = get_cached_domain(cache_key)
    if cached:
        return {**cached, "cached": True}

    client_ip = get_client_ip(request)
    try:
        result = full_domain_report(domain, resolved_ip=resolved_ip, client_ip=client_ip, lite=lite)
    except TimeoutError:
        raise HTTPException(status_code=504, detail="Domain report timed out — upstream services too slow") from None
    save_cached_domain(cache_key, result)
    return {**result, "cached": False}


@router.get("/dns/{domain}", operation_id="dns_records", response_model=DnsResponse, response_model_exclude_none=True)
def dns_records(domain: str, request: Request):
    """DNS record lookup: A, AAAA, MX, NS, TXT, CNAME, SOA."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)
    cached = _from_cache(domain, "dns")
    if cached:
        return {"domain": domain, "records": cached, "summary": _dns_summary(cached, domain), "cached": True}
    records = dns_lookup(domain)
    if not records:
        raise HTTPException(status_code=404, detail=f"No DNS records found for '{domain}'")
    return {"domain": domain, "records": records, "summary": _dns_summary(records, domain), "cached": False}


@router.get(
    "/email/mx/{domain}",
    operation_id="email_mx",
    response_model=EmailMxResponse,
    response_model_exclude_none=True,
)
def email_mx(domain: str, request: Request):
    """Email MX analysis — mail provider detection, SPF/DMARC/DKIM check, security grade."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)

    # Check cache
    cache_key = f"email_mx:{domain}"
    cached = get_cached_domain(cache_key)
    if cached:
        return {**cached, "cached": True}

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
    except TimeoutError:
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
    return {**result, "cached": False}


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
def email_disposable(email: str, request: Request):
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
        return {**cached, "email": email, "summary": summary, "cached": True}

    resolved_ip = validate_domain(domain)
    if not resolved_ip:
        raise HTTPException(status_code=422, detail="Could not resolve email domain. DNS resolution failed.")

    result = check_disposable(email, domain=domain)
    result["summary"] = _disposable_summary(email, result)

    save_cached_domain(cache_key, result)
    return {**result, "cached": False}


@router.get(
    "/phone/{number}",
    operation_id="phone_lookup",
    response_model=PhoneLookupResponse,
    response_model_exclude_none=True,
    include_in_schema=True,
)
def phone_endpoint(number: str, request: Request):
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
def username_endpoint(username: str, request: Request):
    """Username OSINT — check if a username exists on 19 platforms (GitHub, Reddit, X, etc.)."""
    authenticate(request, request.url.path)
    return username_lookup(username)


@router.get(
    "/whois/{domain}", operation_id="whois_lookup", response_model=WhoisResponse, response_model_exclude_none=True
)
def whois_endpoint(domain: str, request: Request):
    """WHOIS registration data for a domain."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)
    cached = _from_cache(domain, "whois")
    if cached and "error" not in cached:
        return {"domain": domain, "whois": cached, "summary": _whois_summary(cached, domain), "cached": True}
    result = whois_lookup(domain)
    if "error" in result:
        raise HTTPException(status_code=504, detail=result["error"])
    return {"domain": domain, "whois": result, "summary": _whois_summary(result, domain), "cached": False}


@router.get(
    "/subdomains/{domain}",
    operation_id="subdomain_enum",
    response_model=SubdomainsResponse,
    response_model_exclude_none=True,
)
def subdomains(domain: str, request: Request):
    """Subdomain enumeration via DNS brute force + certificate transparency."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)
    cached = _from_cache(domain, "subdomains")
    if cached:
        count = cached.get("count", len(cached.get("subdomains", [])))
        summary = f"{count} subdomain{'s' if count != 1 else ''} found for {domain}"
        return {"domain": domain, **cached, "summary": summary, "cached": True}
    result = enumerate_subdomains(domain)
    count = result.get("count", len(result.get("subdomains", [])))
    summary = f"{count} subdomain{'s' if count != 1 else ''} found for {domain}"
    return {"domain": domain, **result, "summary": summary, "cached": False}


@router.get("/certs/{domain}", operation_id="ct_logs", response_model=CertsResponse, response_model_exclude_none=True)
def certs(domain: str, request: Request):
    """Certificate transparency log lookup."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)
    cached = _from_cache(domain, "certificates")
    if cached:
        total = cached.get("total_certificates", 0)
        summary = f"{total} certificate{'s' if total != 1 else ''} in CT logs for {domain}"
        return {"domain": domain, **cached, "summary": summary, "cached": True}
    result = check_ct_logs(domain)
    total = result.get("total_certificates", 0)
    summary = f"{total} certificate{'s' if total != 1 else ''} in CT logs for {domain}"
    return {"domain": domain, **result, "summary": summary, "cached": False}


@router.get(
    "/ssl/{domain}", operation_id="ssl_certificate", response_model=SslResponse, response_model_exclude_none=True
)
def ssl_certificate(domain: str, request: Request):
    """SSL certificate details with grade, chain, cipher, and protocol information."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)

    # Check cache (keyed as ssl:<domain> in domain_cache)
    cached = get_cached_domain(f"ssl:{domain}")
    if cached:
        return {**cached, "cached": True}

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
                if not valid:
                    grade = "F"
                elif tls_version == "TLSv1.3" and days_remaining is not None and days_remaining > 90:
                    grade = "A"
                elif tls_version in ("TLSv1.2", "TLSv1.3") and (days_remaining is None or days_remaining > 30):
                    grade = "B"
                else:
                    grade = "C"

                # Chain from OCSP stapling / peer cert chain
                chain = []
                try:
                    chain_certs = ssock.get_verified_chain() or []
                    for c in chain_certs:
                        chain.append(
                            {
                                "subject": c.get("subject", ""),
                                "issuer": c.get("issuer", ""),
                                "not_after": c.get("notAfter", ""),
                            }
                        )
                except (AttributeError, Exception):
                    # get_verified_chain not available in all Python versions
                    pass

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
                    "summary": ". ".join(parts),
                }

                save_cached_domain(f"ssl:{domain}", result)
                return {**result, "cached": False}

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.warning("SSL connection failed for %s: %s", domain, e)
        raise HTTPException(status_code=504, detail=f"Could not establish SSL connection to {domain}") from None
    except Exception as e:
        logger.warning("SSL inspection failed for %s: %s", domain, e)
        raise HTTPException(status_code=504, detail=f"SSL inspection failed for {domain}") from None


@router.get(
    "/threat/{domain}", operation_id="threat_intel", response_model=ThreatResponse, response_model_exclude_none=True
)
def threat_intel(domain: str, request: Request):
    """Threat intelligence — check domain against URLhaus for known malware URLs."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)
    result = check_urlhaus(domain)
    urls_online = result["urls_online"]
    url_count = result["url_count"]
    if url_count == 0:
        summary = f"{domain} — no threats found in URLhaus"
    else:
        summary = f"{domain} — {url_count} URL{'s' if url_count != 1 else ''} in URLhaus ({urls_online} online)"
    return {"domain": domain, **result, "summary": summary}


@router.get(
    "/archive/{domain}",
    operation_id="wayback_lookup",
    response_model=WaybackResponse,
    response_model_exclude_none=True,
)
def wayback_lookup_route(domain: str, request: Request):
    """Web archive lookup — historical snapshots from the Wayback Machine."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)
    return wayback_lookup(domain)


@router.get("/ip/{ip}", operation_id="ip_lookup", response_model=IpLookupResponse, response_model_exclude_none=True)
def ip_lookup(ip: str, request: Request):
    """IP intelligence — reverse DNS, open ports, vulnerabilities, hostnames (via Shodan InternetDB) + reputation."""
    if not is_valid_ip(ip):
        if "." in ip and not ip.replace(".", "").isdigit():
            raise HTTPException(
                status_code=400, detail=f"'{ip}' looks like a domain, not an IP. Use /v1/domain/{ip} instead."
            )
        raise HTTPException(status_code=400, detail="Invalid IP address")
    if is_private_ip(ip):
        raise HTTPException(status_code=400, detail="Private/reserved IP addresses are not allowed")
    authenticate(request, "/v1/ip")
    client_ip = get_client_ip(request)

    try:
        from domain.recon import _dns_call_with_timeout

        addr_result, addr_err = _dns_call_with_timeout(socket.gethostbyaddr, ip)
        ptr = addr_result[0] if addr_result and not addr_err else None
    except (socket.herror, socket.gaierror, OSError):
        ptr = None

    enrichment = ip_enrichment(ip)
    ports = enrichment.get("ports", [])
    vulns = enrichment.get("vulns", [])
    hostnames = enrichment.get("hostnames", [])

    # Reputation enrichment (rate-limited per client IP)
    reputation = {}
    cached_rep = get_cached_ip(ip)
    if cached_rep is not None:
        reputation = cached_rep
    elif ratelimit.check_limit(
        store_name="enrichment",
        key=client_ip,
        max_requests=ENRICHMENT_DAILY_LIMIT,
        window_seconds=86400,
    ):
        try:
            f_ab = _reputation_pool.submit(check_abuseipdb, ip)
            f_sh = _reputation_pool.submit(check_shodan, ip)
            reputation = {
                "abuseipdb": f_ab.result(timeout=RECON_TIMEOUT + 2),
                "shodan": f_sh.result(timeout=RECON_TIMEOUT + 2),
            }
            save_cached_ip(ip, reputation)
        except Exception as e:
            logger.warning("Reputation enrichment failed for %s: %s", ip, type(e).__name__)
            reputation = {}
            ratelimit.refund("enrichment", client_ip)

    parts = [f"{ip} → {ptr}" if ptr else f"{ip} — no PTR record"]
    if ports:
        parts.append(f"{len(ports)} open ports")
    if vulns:
        parts.append(f"{len(vulns)} known vulnerabilities")
    if hostnames:
        parts.append(f"{len(hostnames)} hostnames")

    result = {
        "ip": ip,
        "ptr": ptr,
        **enrichment,
        "summary": ". ".join(parts),
    }
    if reputation:
        result["reputation"] = reputation
    return result


@router.get(
    "/tech/{domain}", operation_id="tech_fingerprint", response_model=TechResponse, response_model_exclude_none=True
)
def tech_fingerprint(domain: str, request: Request):
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
def domain_monitor(domain: str, request: Request):
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
        logger.debug("ssl_info failed for %s: %s", domain, e)

    # Compare against cached full report
    dns_changed = None
    risk_grade = None
    risk_score = None
    last_full_report = None
    cached = get_cached_domain(domain)
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
def domain_vulns(domain: str, request: Request):
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
def asn_lookup(target: str, request: Request):
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
        result = {**cached, "target": target, "cached": True}
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
        logger.warning("RIPE network-info failed for %s: %s", ip, e)
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
        except Exception as e:
            logger.warning("RIPE as-overview failed for AS%s: %s", asn, e)
            return ""

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
        except Exception as e:
            logger.warning("RIPE announced-prefixes failed for AS%s: %s", asn, e)
            return [], []

    f_overview = _reputation_pool.submit(_fetch_overview)
    f_prefixes = _reputation_pool.submit(_fetch_prefixes)
    asn_name = f_overview.result(timeout=7)
    ipv4_prefixes, ipv6_prefixes = f_prefixes.result(timeout=7)

    parts = [f"AS{asn}"]
    if asn_name:
        parts[0] += f" ({asn_name})"
    parts.append(f"{len(ipv4_prefixes)} IPv4 and {len(ipv6_prefixes)} IPv6 prefixes")
    if resolved_ip:
        parts.append(f"resolved from {target}")

    result = {
        "target": target,
        "asn": asn,
        "asn_name": asn_name,
        "ipv4_prefixes": ipv4_prefixes,
        "ipv6_prefixes": ipv6_prefixes,
        "ipv4_count": len(ipv4_prefixes),
        "ipv6_count": len(ipv6_prefixes),
        "summary": ". ".join(parts),
    }
    if resolved_ip:
        result["resolved_ip"] = resolved_ip

    save_cached_domain(cache_key, result)
    return {**result, "cached": False}


class _BulkRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1, max_length=50)


_bulk_pool = ThreadPoolExecutor(max_workers=5)
_bulk_semaphore = threading.Semaphore(2)  # per-worker limit; with workers=2 actual max is 4


def _run_single_report(raw_domain: str, client_ip: str) -> dict:
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
        cached = get_cached_domain(domain)
        if cached:
            return {"domain": domain, "status": "ok", "report": {**cached, "cached": True}, "error": None}
        report = full_domain_report(domain, resolved_ip=resolved_ip, client_ip=client_ip)
        save_cached_domain(domain, report)
        return {"domain": domain, "status": "ok", "report": {**report, "cached": False}, "error": None}
    except Exception as e:
        logger.warning("Bulk report failed for %s: %s", domain, e)
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
        ordered_futures = [(_bulk_pool.submit(_run_single_report, d, client_ip), d) for d in domains]
        results = []
        timed_out = 0
        partial = False
        deadline = _time.monotonic() + BULK_OVERALL_TIMEOUT

        for future, domain in ordered_futures:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                # Overall timeout exceeded — cancel remaining futures, return partial results
                future.cancel()
                logger.warning("Bulk overall timeout — skipping %s", domain)
                results.append({"domain": domain, "status": "error", "report": None, "error": "Bulk request timed out"})
                timed_out += 1
                partial = True
                continue
            per_domain = min(BULK_PER_DOMAIN_TIMEOUT, remaining)
            try:
                results.append(future.result(timeout=per_domain))
            except TimeoutError:
                future.cancel()
                logger.warning("Bulk report timed out for %s", domain)
                results.append(
                    {"domain": domain, "status": "error", "report": None, "error": "Domain report timed out"}
                )
                timed_out += 1
            except Exception as exc:
                logger.warning("Bulk report failed for %s: %s", domain, exc)
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
