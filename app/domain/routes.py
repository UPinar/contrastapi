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
from config import ENRICHMENT_DAILY_LIMIT, RECON_TIMEOUT
from db import get_cached_domain, get_cached_ip, save_cached_domain, save_cached_ip
from domain.recon import (
    check_ct_logs,
    dns_lookup,
    enumerate_subdomains,
    fetch_live_page,
    full_domain_report,
    ip_enrichment,
    quick_dns_a,
    ssl_info,
    whois_lookup,
)
from domain.reputation import check_abuseipdb, check_greynoise, check_shodan
from domain.threat import check_urlhaus
from pydantic import BaseModel, Field
from schemas import (
    AsnResponse,
    BulkDomainResponse,
    DnsResponse,
    DomainReportResponse,
    IpLookupResponse,
    MonitorResponse,
    SslResponse,
    TechResponse,
    ThreatResponse,
    VulnsResponse,
)
from validation import _is_valid_format, clean_domain, get_client_ip, is_private_ip, is_valid_ip, validate_domain

logger = logging.getLogger("contrastapi")

router = APIRouter(prefix="/v1", tags=["Domain Intelligence"])


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
def domain_report(domain: str, request: Request):
    """Full domain intelligence report with DNS, WHOIS, SSL, subdomains, WAF."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)

    # Check cache
    cached = get_cached_domain(domain)
    if cached:
        return {**cached, "cached": True}

    client_ip = get_client_ip(request)
    result = full_domain_report(domain, resolved_ip=resolved_ip, client_ip=client_ip)
    result["cached"] = False
    save_cached_domain(domain, result)
    return result


@router.get("/dns/{domain}", operation_id="dns_records", response_model=DnsResponse, response_model_exclude_none=True)
def dns_records(domain: str, request: Request):
    """DNS record lookup: A, AAAA, MX, NS, TXT, CNAME, SOA."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)
    cached = _from_cache(domain, "dns")
    if cached:
        return {"domain": domain, "records": cached, "cached": True}
    records = dns_lookup(domain)
    if not records:
        raise HTTPException(status_code=404, detail=f"No DNS records found for '{domain}'")
    return {"domain": domain, "records": records}


@router.get("/whois/{domain}", operation_id="whois_lookup")
def whois_endpoint(domain: str, request: Request):
    """WHOIS registration data for a domain."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)
    cached = _from_cache(domain, "whois")
    if cached and "error" not in cached:
        return {"domain": domain, "whois": cached, "cached": True}
    result = whois_lookup(domain)
    if "error" in result:
        raise HTTPException(status_code=502, detail=result["error"])
    return {"domain": domain, "whois": result}


@router.get("/subdomains/{domain}", operation_id="subdomain_enum")
def subdomains(domain: str, request: Request):
    """Subdomain enumeration via DNS brute force + certificate transparency."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)
    cached = _from_cache(domain, "subdomains")
    if cached:
        return {"domain": domain, **cached, "cached": True}
    result = enumerate_subdomains(domain)
    return {"domain": domain, **result}


@router.get("/certs/{domain}", operation_id="ct_logs")
def certs(domain: str, request: Request):
    """Certificate transparency log lookup."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)
    cached = _from_cache(domain, "certificates")
    if cached:
        return {"domain": domain, **cached, "cached": True}
    result = check_ct_logs(domain)
    return {"domain": domain, **result}


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
                    "summary": ". ".join(parts) + ".",
                }

                save_cached_domain(f"ssl:{domain}", result)
                return {**result, "cached": False}

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.warning("SSL connection failed for %s: %s", domain, e)
        raise HTTPException(status_code=502, detail=f"Could not establish SSL connection to {domain}") from None
    except Exception as e:
        logger.warning("SSL inspection failed for %s: %s", domain, e)
        raise HTTPException(status_code=502, detail=f"SSL inspection failed for {domain}") from None


@router.get("/threat/{domain}", operation_id="threat_intel", response_model=ThreatResponse)
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
    except Exception:
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
            f_gn = _reputation_pool.submit(check_greynoise, ip)
            f_ab = _reputation_pool.submit(check_abuseipdb, ip)
            f_sh = _reputation_pool.submit(check_shodan, ip)
            reputation = {
                "greynoise": f_gn.result(timeout=RECON_TIMEOUT + 2),
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
        "summary": ". ".join(parts) + ".",
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
    page = fetch_live_page(domain, resolved_ip)
    if "error" in page:
        raise HTTPException(status_code=502, detail=page["error"])
    from domain.tech import detect_technologies

    result = detect_technologies(page["headers"], page.get("html"))
    return {"domain": domain, **result}


@router.get("/monitor/{domain}", operation_id="domain_monitor", response_model=MonitorResponse)
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
        "summary": ". ".join(parts) + ".",
    }


@router.get("/domain/{domain}/vulns", operation_id="domain_vulns", response_model=VulnsResponse)
def domain_vulns(domain: str, request: Request):
    """Tech stack vulnerability scan — detect technologies, then look up CVEs for each."""
    domain, resolved_ip, auth_ctx = _validate_and_auth(request, domain)

    page = fetch_live_page(domain, resolved_ip)
    if "error" in page:
        raise HTTPException(status_code=502, detail=page["error"])

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
        # Update target/resolved_ip for the actual request
        cached["target"] = target
        if resolved_ip:
            cached["resolved_ip"] = resolved_ip
        elif "resolved_ip" in cached:
            del cached["resolved_ip"]
        return {**cached, "cached": True}

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
        raise HTTPException(status_code=502, detail="Failed to look up ASN from RIPE Stat") from None

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
        "summary": ". ".join(parts) + ".",
    }
    if resolved_ip:
        result["resolved_ip"] = resolved_ip

    save_cached_domain(cache_key, result)
    return {**result, "cached": False}


class _BulkRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1, max_length=50)


_bulk_pool = ThreadPoolExecutor(max_workers=5)
_bulk_rate_lock = threading.Lock()


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
        report["cached"] = False
        save_cached_domain(domain, report)
        return {"domain": domain, "status": "ok", "report": report, "error": None}
    except Exception as e:
        logger.warning("Bulk report failed for %s: %s", domain, e)
        return {"domain": domain, "status": "error", "report": None, "error": "Domain report failed"}


@router.post("/domains/bulk", operation_id="bulk_domain_report", response_model=BulkDomainResponse)
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

    # Atomic check-and-consume to prevent race conditions
    with _bulk_rate_lock:
        current = ratelimit.get_count("api", store_key)
        # authenticate() already consumed 1, so we need (count - 1) more slots
        remaining = limit - current
        if remaining < count - 1:
            raise HTTPException(
                status_code=429,
                detail=f"Insufficient rate limit quota. Need {count} slots, {remaining + 1} available.",
            )
        # Consume the extra (count - 1) rate limit slots
        for _ in range(count - 1):
            if not ratelimit.check_limit("api", store_key, limit):
                raise HTTPException(
                    status_code=429,
                    detail="Rate limit exceeded while reserving bulk quota.",
                )

    # Run reports in parallel, preserving input order
    ordered_futures = [(_bulk_pool.submit(_run_single_report, d, client_ip), d) for d in domains]
    results = []
    for future, domain in ordered_futures:
        try:
            results.append(future.result(timeout=RECON_TIMEOUT + 10))
        except TimeoutError:
            future.cancel()
            logger.warning("Bulk report timed out for %s", domain)
            results.append({"domain": domain, "status": "error", "report": None, "error": "Domain report timed out"})
        except Exception as exc:
            logger.warning("Bulk report failed for %s: %s", domain, exc)
            results.append({"domain": domain, "status": "error", "report": None, "error": "Domain report failed"})

    successful = sum(1 for r in results if r["status"] == "ok")
    failed = len(results) - successful

    if failed == 0:
        summary = f"All {count} domains scanned successfully"
    elif successful == 0:
        summary = f"All {count} domains failed"
    else:
        summary = f"{successful}/{count} domains scanned, {failed} failed"

    return {
        "results": results,
        "total": count,
        "successful": successful,
        "failed": failed,
        "summary": summary,
    }
