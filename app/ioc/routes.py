"""IOC / Threat Intelligence API routes — /v1/ioc/*, /v1/hash/*, /v1/password/*, /v1/phishing/*"""

import logging
import re
import socket
import time as _time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from typing import Annotated
from urllib.parse import urlparse

import httpx
from auth import authenticate
from config import URLHAUS_API_KEY
from db import get_cached_domain, save_cached_domain
from domain.ip_intel import check_tor_exit, tor_cache_status
from domain.recon import _dns_call_with_timeout
from domain.threat import check_urlhaus
from fastapi import APIRouter, HTTPException, Path, Request
from ioc.lookup import (
    detect_indicator_type,
    query_feodo,
    query_malwarebazaar,
    query_threatfox,
)
from ioc.password import is_valid_sha1, query_pwned_hash
from pydantic import BaseModel, Field
from schemas import BulkIocResponse, HashResponse, IocResponse, PasswordResponse, PhishingResponse, Verdict
from validation import is_private_ip, is_valid_ip

logger = logging.getLogger("contrastapi")

_phish_headers = {"Auth-Key": URLHAUS_API_KEY} if URLHAUS_API_KEY else {}
_phish_client = httpx.Client(timeout=httpx.Timeout(5.0, connect=3.0), follow_redirects=False, headers=_phish_headers)

router = APIRouter(prefix="/v1", tags=["Threat Intelligence"])

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_HASH_LENS = {32: "md5", 40: "sha1", 64: "sha256"}

# ThreatFox honeypot/demo entries carry these tags; cap their threat_level to avoid
# false escalation when an agent triages benign sample IOCs (e.g. example.com).
_TEST_IOC_TAGS: frozenset[str] = frozenset({"test", "example", "demo", "sandbox", "appleseed"})


def _ioc_verdict(queried: list[str], unavailable: list[str]) -> Verdict:
    """Build verdict metadata for ioc_lookup responses (live threat-feed queries, age=0)."""
    return Verdict(
        deterministic=True,
        falsifiable_fields=["type", "threat_level", "sources"],
        data_age_seconds=0,
        sources_queried=queried,
        sources_unavailable=unavailable,
        completeness="partial" if unavailable else "complete",
    )


@router.get(
    "/ioc/{indicator:path}", operation_id="ioc_lookup", response_model=IocResponse, response_model_exclude_none=True
)
def ioc_lookup(
    indicator: Annotated[
        str,
        Path(
            description=(
                "Indicator of compromise — auto-detected type. Accepts: IP (IPv4/IPv6), domain, URL "
                "(with scheme), or file hash (MD5/SHA1/SHA256/SHA512, hex). Max 2048 chars."
            ),
        ),
    ],
    request: Request,
):
    """Unified IOC enrichment — auto-detects type and queries abuse.ch feeds.

    Source coverage by type: hash → ThreatFox only; IP → ThreatFox + Feodo + URLhaus;
    domain / URL → ThreatFox + URLhaus. Feodo and URLhaus do not index hashes.
    """
    authenticate(request, "/v1/ioc")
    indicator = indicator.strip()
    if not indicator or len(indicator) > 2048:
        raise HTTPException(status_code=400, detail="Invalid indicator")
    # Sanitize indicator for safe inclusion in response summary (prevent XSS in consumers)
    indicator = re.sub(r"[<>&\"']", "", indicator)

    ioc_type = detect_indicator_type(indicator)
    if ioc_type == "unknown":
        raise HTTPException(
            status_code=400, detail="Could not detect indicator type. Provide an IP, domain, URL, or file hash."
        )

    # Cache full response for ≤1h. Threat-feed pulls (ThreatFox/Feodo/URLhaus)
    # cost 2-10s each in the cold path; the same IOC re-queried within the hour
    # returns identical content. Key is lowercased so case-variant hashes/IPs
    # share a slot. Tor cache lookup (free, in-memory) is bundled in cache too.
    cache_key = f"ioc:{indicator.lower()}"
    cached = get_cached_domain(cache_key)
    if cached:
        return {**cached}

    sources = {}
    threat_parts = []
    queried_sources: list[str] = []
    unavailable_sources: list[str] = []

    # Validate before submitting to pool
    urlhaus_target = None
    if ioc_type == "ip":
        if is_private_ip(indicator):
            raise HTTPException(status_code=400, detail="Private/reserved IP addresses are not allowed")
        urlhaus_target = indicator
    elif ioc_type == "domain":
        urlhaus_target = indicator
    elif ioc_type == "url":
        host = urlparse(indicator).hostname
        if host:
            if is_valid_ip(host):
                if is_private_ip(host):
                    raise HTTPException(status_code=400, detail="Private/reserved IP addresses are not allowed")
            else:
                addrs, _ = _dns_call_with_timeout(socket.getaddrinfo, host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                if addrs and any(is_private_ip(addr[4][0]) for addr in addrs):
                    raise HTTPException(status_code=400, detail="Private/reserved IP addresses are not allowed")
            urlhaus_target = host

    # Fire all lookups in parallel
    with ThreadPoolExecutor(max_workers=4) as pool:
        f_tf = pool.submit(query_threatfox, indicator)
        f_feodo = pool.submit(query_feodo, indicator) if ioc_type == "ip" else None
        f_urlhaus = pool.submit(check_urlhaus, urlhaus_target) if urlhaus_target else None
        # Bug I5: ioc_lookup on an IP indicator now also asks the local Tor
        # cache (free, in-memory, no upstream request). ip_lookup of the same
        # IP already exposed tor_exit; without this hop a SOC agent triaging
        # an IP IOC had to make a second ip_lookup call just to learn the
        # IP was a Tor exit.
        f_tor = pool.submit(check_tor_exit, indicator) if ioc_type == "ip" else None

        queried_sources.append("threatfox")
        try:
            tf = f_tf.result(timeout=10)
        except Exception:
            logger.debug("ThreatFox lookup failed")
            tf = {"found": False}
            unavailable_sources.append("threatfox")
        sources["threatfox"] = tf
        if tf.get("found"):
            threat_parts.append(f"{tf.get('malware', 'unknown')} ({tf.get('threat_type', 'unknown')}) via ThreatFox")

        if f_feodo is not None:
            queried_sources.append("feodo")
            try:
                feodo = f_feodo.result(timeout=10)
            except Exception:
                logger.debug("Feodo lookup failed")
                feodo = {"found": False}
                unavailable_sources.append("feodo")
            sources["feodo"] = feodo
            if feodo.get("found"):
                threat_parts.append(f"{feodo.get('malware', 'unknown')} via Feodo Tracker")

        if f_urlhaus is not None:
            queried_sources.append("urlhaus")
            try:
                urlhaus = f_urlhaus.result(timeout=10)
            except Exception:
                logger.debug("URLhaus lookup failed")
                urlhaus = {"url_count": 0, "urls_online": 0}
                unavailable_sources.append("urlhaus")
            sources["urlhaus"] = {
                "found": urlhaus.get("url_count", 0) > 0,
                "urls_online": urlhaus.get("urls_online", 0),
            }
            if sources["urlhaus"]["found"]:
                threat_parts.append(f"{urlhaus['url_count']} malware URLs via URLhaus")

        if f_tor is not None:
            queried_sources.append("tor")
            tor_state = tor_cache_status()
            try:
                tor_listed = bool(f_tor.result(timeout=2))
            except Exception:
                logger.debug("Tor list lookup failed")
                tor_listed = False
                tor_state = "failed"
            if tor_state != "ok":
                unavailable_sources.append("tor")
            sources["tor"] = {"listed": tor_listed, "fetch_status": tor_state}
            if tor_listed:
                threat_parts.append("known Tor exit node")

    # Determine threat level
    found_count = sum(1 for s in sources.values() if s.get("found"))
    if found_count >= 2:
        threat_level = "high"
    elif found_count == 1:
        threat_level = "medium"
    else:
        threat_level = "none"

    # Cap test/demo entries: ThreatFox honeypot tags should not trigger high/medium.
    tf_tags = {(t or "").lower().strip() for t in (sources.get("threatfox", {}).get("tags") or [])}
    if tf_tags & _TEST_IOC_TAGS and threat_level in ("high", "medium"):
        threat_level = "low"
        threat_parts.append("(capped — ThreatFox test/demo tag)")

    if threat_parts:
        summary = f"{indicator} flagged as malicious: " + ", ".join(threat_parts)
    else:
        summary = f"{indicator} — no threats found across {len(sources)} sources"

    response = {
        "indicator": indicator,
        "type": ioc_type,
        "threat_level": threat_level,
        "sources": sources,
        "summary": summary,
        "verdict": _ioc_verdict(queried_sources, unavailable_sources).model_dump(),
    }
    save_cached_domain(cache_key, response)
    return response


@router.get(
    "/hash/{file_hash}", operation_id="hash_lookup", response_model=HashResponse, response_model_exclude_none=True
)
def hash_lookup(
    file_hash: Annotated[
        str,
        Path(
            description=(
                "File hash (hex, case-insensitive). Accepted lengths: MD5=32, SHA1=40, SHA256=64. "
                "Other lengths or non-hex characters return 400."
            ),
        ),
    ],
    request: Request,
):
    """Malware file hash reputation lookup via MalwareBazaar."""
    authenticate(request, "/v1/hash")
    file_hash = file_hash.strip().lower()

    if not _HEX_RE.match(file_hash) or len(file_hash) not in _HASH_LENS:
        raise HTTPException(
            status_code=400,
            detail="Invalid hash. Provide MD5 (32 chars), SHA1 (40 chars), or SHA256 (64 chars).",
        )

    hash_type = _HASH_LENS[len(file_hash)]
    result = query_malwarebazaar(file_hash)

    if result.get("found"):
        family = result.get("malware_family", "unknown")
        first_seen = result.get("first_seen", "unknown")
        tags = result.get("tags", [])
        tag_str = f" ({', '.join(tags[:3])})" if tags else ""
        summary = f"{file_hash[:16]}... is {family}{tag_str}. First seen {first_seen}."
    else:
        summary = "No malware data found for this hash"

    return {
        "hash": file_hash,
        "hash_type": hash_type,
        "found": result.get("found", False),
        "malware_family": result.get("malware_family"),
        "file_type": result.get("file_type"),
        "file_size": result.get("file_size"),
        "first_seen": result.get("first_seen"),
        "tags": result.get("tags", []),
        "file_name": result.get("file_name"),
        "summary": summary,
    }


@router.get(
    "/password/{sha1_hash}",
    operation_id="password_check",
    response_model=PasswordResponse,
    response_model_exclude_none=True,
)
def password_check(
    sha1_hash: Annotated[
        str,
        Path(
            description=(
                "Full SHA-1 hash of the password (40 hex chars, case-insensitive). "
                "k-anonymity is applied server-side: only the first 5 chars are sent to HIBP."
            ),
        ),
    ],
    request: Request,
):
    """Password breach check via HIBP Pwned Passwords (k-anonymity). Send full SHA1 hash, get found + breach count."""
    authenticate(request, "/v1/password")

    if not is_valid_sha1(sha1_hash):
        raise HTTPException(
            status_code=400,
            detail="Provide the full SHA1 hash (40 hexadecimal characters).",
        )

    result = query_pwned_hash(sha1_hash)
    count = result.get("breach_count", 0)
    if result.get("found"):
        summary = f"This password appeared in {count:,} data breaches."
    else:
        summary = "This password has not been found in any known data breaches."

    return {**result, "summary": summary}


def _query_urlhaus_url(url: str) -> dict:
    """Query URLhaus for an exact URL match."""
    try:
        resp = _phish_client.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") != "ok":
            return {"found": False, "threat": None, "tags": [], "status": None}
        raw_status = (data.get("url_status") or "").strip().lower()
        normalized_status = raw_status if raw_status in {"online", "offline"} else "unknown"
        return {
            "found": True,
            "threat": data.get("threat") or "unknown",
            "tags": data.get("tags") or [],
            "status": normalized_status,
        }
    except Exception as e:
        logger.warning("URLhaus URL check failed: %s", type(e).__name__)
        return {"found": False, "threat": None, "tags": [], "status": None}


@router.get(
    "/phishing/{url:path}",
    operation_id="phishing_check",
    response_model=PhishingResponse,
    response_model_exclude_none=True,
)
def phishing_check(
    url: Annotated[
        str,
        Path(
            description=(
                "Full URL to check (must include scheme, e.g. 'https://example.com/path'). "
                "URL-encode any '?' or '#' chars the agent wants preserved into the path component. "
                "Checked against URLhaus for both exact URL and host-level matches."
            ),
        ),
    ],
    request: Request,
):
    """Check if a URL is malicious via URLhaus (host + exact URL lookup)."""
    authenticate(request, "/v1/phishing")
    url = url.strip()

    if not url.startswith(("http://", "https://")) or len(url) > 2048:
        raise HTTPException(
            status_code=400, detail="Invalid URL. Must start with http:// or https:// and be at most 2048 characters."
        )

    # Extract and validate hostname
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        host = ""
    if not host:
        raise HTTPException(status_code=400, detail="Could not extract hostname from URL.")
    if is_valid_ip(host):
        if is_private_ip(host):
            raise HTTPException(status_code=400, detail="Private/reserved IP addresses are not allowed.")
    else:
        # Resolve domain and check for private IPs (consistent with /v1/ioc)
        addr_result, _ = _dns_call_with_timeout(socket.getaddrinfo, host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if addr_result and any(is_private_ip(addr[4][0]) for addr in addr_result):
            raise HTTPException(status_code=400, detail="Private/reserved IP addresses are not allowed.")

    # URLhaus host lookup
    uh_host = check_urlhaus(host)
    urlhaus_host = {
        "found": uh_host.get("url_count", 0) > 0,
        "urls_online": uh_host.get("urls_online", 0),
        "url_count": uh_host.get("url_count", 0),
    }

    # URLhaus exact URL lookup
    urlhaus_url = _query_urlhaus_url(url)

    # Distinguish active (live serving malware) from stale (historical only) findings.
    # URLhaus keeps host records forever; urls_online == 0 means every malware URL on
    # that host is now offline, so the host is not currently a live threat. Same for
    # an exact URL match with url_status == "offline". Only "online" or "unknown"
    # status counts as active (conservative — upstream sometimes omits status).
    url_active = urlhaus_url["found"] and urlhaus_url.get("status") in (None, "online", "unknown")
    host_active = urlhaus_host["urls_online"] > 0
    any_evidence = urlhaus_url["found"] or urlhaus_host["found"]

    is_malicious = url_active or host_active
    is_stale = any_evidence and not is_malicious

    if url_active and host_active:
        threat_level = "high"
    elif url_active or host_active:
        threat_level = "medium"
    elif is_stale:
        threat_level = "low"
    else:
        threat_level = "none"

    # Build summary
    parts = []
    if urlhaus_url["found"]:
        if url_active:
            parts.append(f"exact URL listed ({urlhaus_url['threat']})")
        else:
            parts.append(f"exact URL listed but offline ({urlhaus_url['threat']})")
    if urlhaus_host["found"]:
        if host_active:
            parts.append(f"host has {urlhaus_host['url_count']} malware URLs ({urlhaus_host['urls_online']} online)")
        else:
            parts.append(f"host has {urlhaus_host['url_count']} historical malware URLs (0 online)")
    if is_malicious:
        summary = f"{url} — malicious: " + ", ".join(parts)
    elif is_stale:
        summary = f"{url} — stale historical evidence only: " + ", ".join(parts)
    else:
        summary = f"{url} — not found in threat databases"

    return {
        "url": url,
        "host": host,
        "is_malicious": is_malicious,
        "is_stale": is_stale,
        "urlhaus_host": urlhaus_host,
        "urlhaus_url": urlhaus_url,
        "threat_level": threat_level,
        "summary": summary,
    }


# === Bulk IOC Lookup ===

_BULK_IOC_PER_TIMEOUT = 10
_BULK_IOC_OVERALL_TIMEOUT = 120


class _BulkIocRequest(BaseModel):
    indicators: list[str] = Field(..., min_length=1, max_length=50)


def _run_single_ioc(indicator: str) -> dict:
    """Lookup a single IOC via threatfox + feodo (if IP) + urlhaus."""
    indicator = indicator.strip()
    if not indicator:
        return {"indicator": indicator, "status": "error", "ioc": None, "error": "Empty indicator"}
    # Strip control chars (newlines, tabs, bidi overrides, etc.) — str.isprintable()
    # returns False for \n, \r, \t and Unicode control chars but True for normal space.
    indicator = "".join(c for c in indicator if c.isprintable())
    indicator = re.sub(r"[<>&\"']", "", indicator)

    ioc_type = detect_indicator_type(indicator)
    if ioc_type == "unknown":
        return {"indicator": indicator, "status": "error", "ioc": None, "error": "Unknown indicator type"}

    if ioc_type == "ip" and is_private_ip(indicator):
        return {"indicator": indicator, "status": "error", "ioc": None, "error": "Private IP not allowed"}

    # Determine target for urlhaus host lookup (mirror single /v1/ioc behavior)
    urlhaus_target = None
    if ioc_type in ("ip", "domain"):
        urlhaus_target = indicator
    elif ioc_type == "url":
        host = urlparse(indicator).hostname
        if host:
            if is_valid_ip(host) and is_private_ip(host):
                return {"indicator": indicator, "status": "error", "ioc": None, "error": "Private IP not allowed"}
            urlhaus_target = host

    sources = {}
    threat_level = "none"
    try:
        tf = query_threatfox(indicator)
        sources["threatfox"] = tf
        if tf.get("found"):
            threat_level = "high"
    except Exception:
        sources["threatfox"] = {"found": False}

    if ioc_type == "ip":
        try:
            feodo = query_feodo(indicator)
            sources["feodo"] = feodo
            if feodo.get("found"):
                threat_level = "high"
        except Exception:
            sources["feodo"] = {"found": False}

    if urlhaus_target:
        try:
            urlhaus = check_urlhaus(urlhaus_target)
            if urlhaus:
                sources["urlhaus"] = urlhaus
                if urlhaus.get("urlhaus_status") == "found":
                    threat_level = "high"
        except Exception:
            pass

    return {
        "indicator": indicator,
        "status": "ok",
        "ioc": {"type": ioc_type, "threat_level": threat_level, "sources": sources},
        "error": None,
    }


@router.post(
    "/iocs/bulk",
    operation_id="bulk_ioc_lookup",
    response_model=BulkIocResponse,
    response_model_exclude_none=True,
)
def bulk_ioc_lookup(body: _BulkIocRequest, request: Request):
    """Bulk IOC enrichment — up to 10 indicators (free) or 50 (pro). Each indicator counts as 1 request toward rate limit."""
    import ratelimit
    from auth import extract_key, hash_key
    from config import FREE_BULK_LIMIT, FREE_HOURLY_LIMIT, PRO_BULK_LIMIT, PRO_HOURLY_LIMIT
    from db import hash_client_ip
    from validation import get_client_ip

    auth_ctx = authenticate(request, "/v1/iocs/bulk")
    client_ip = get_client_ip(request)

    bulk_limit = PRO_BULK_LIMIT if auth_ctx["tier"] == "pro" else FREE_BULK_LIMIT

    indicators = list(dict.fromkeys(i.strip() for i in body.indicators if i.strip()))
    count = len(indicators)

    if count == 0:
        raise HTTPException(status_code=400, detail="indicators must contain at least one value")
    if count > bulk_limit:
        raise HTTPException(
            status_code=422,
            detail=f"Too many indicators. Limit: {bulk_limit} (your tier: {auth_ctx['tier']})",
        )

    raw_key = extract_key(request)
    if raw_key:
        store_key = f"pro:{hash_key(raw_key)}"
        limit = PRO_HOURLY_LIMIT
    else:
        store_key = f"free:{hash_client_ip(client_ip)}"
        limit = FREE_HOURLY_LIMIT

    if count > 1 and not ratelimit.consume_bulk("api", store_key, count - 1, limit):
        raise HTTPException(
            status_code=429,
            detail=f"Insufficient rate limit quota for {count} indicators.",
        )

    results = []
    timed_out = 0
    partial = False
    deadline = _time.monotonic() + _BULK_IOC_OVERALL_TIMEOUT

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [(pool.submit(_run_single_ioc, ind), ind) for ind in indicators]
        for future, ind in futures:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                future.cancel()
                results.append(
                    {"indicator": ind, "status": "error", "ioc": None, "error": "Request processing took too long"}
                )
                timed_out += 1
                partial = True
                continue
            per_ind = min(_BULK_IOC_PER_TIMEOUT, remaining)
            try:
                results.append(future.result(timeout=per_ind))
            except TimeoutError:
                future.cancel()
                results.append(
                    {"indicator": ind, "status": "error", "ioc": None, "error": "Request processing took too long"}
                )
                timed_out += 1
            except Exception as e:
                # Log type only — never expose exception detail in response or full message
                logger.warning("Bulk IOC lookup failed: %s", type(e).__name__)
                results.append({"indicator": ind, "status": "error", "ioc": None, "error": "Lookup failed"})

    successful = sum(1 for r in results if r["status"] == "ok")
    failed = count - successful - timed_out

    if partial:
        summary = f"{successful}/{count} indicators processed (partial — overall timeout)"
    elif failed == 0 and timed_out == 0:
        summary = f"All {count} indicators processed"
    else:
        parts = [f"{successful}/{count} processed"]
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
