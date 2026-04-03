"""IOC / Threat Intelligence API routes — /v1/ioc/*, /v1/hash/*, /v1/password/*, /v1/phishing/*"""

import logging
import re
import socket
from urllib.parse import urlparse

import httpx
from auth import authenticate
from domain.recon import _dns_call_with_timeout
from domain.threat import check_urlhaus
from fastapi import APIRouter, HTTPException, Request
from ioc.lookup import (
    detect_indicator_type,
    query_feodo,
    query_malwarebazaar,
    query_threatfox,
)
from ioc.password import is_valid_sha1, query_pwned_hash
from schemas import HashResponse, IocResponse, PasswordResponse, PhishingResponse
from validation import is_private_ip, is_valid_ip

logger = logging.getLogger("contrastapi")

_phish_client = httpx.Client(timeout=httpx.Timeout(5.0, connect=3.0), follow_redirects=False)

router = APIRouter(prefix="/v1", tags=["Threat Intelligence"])

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_HASH_LENS = {32: "md5", 40: "sha1", 64: "sha256"}


@router.get("/ioc/{indicator:path}", operation_id="ioc_lookup", response_model=IocResponse, response_model_exclude_none=True)
def ioc_lookup(indicator: str, request: Request):
    """Unified IOC enrichment — auto-detects IP, domain, URL, or hash and queries threat feeds."""
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

    sources = {}
    threat_parts = []

    # ThreatFox — works for all types
    tf = query_threatfox(indicator)
    sources["threatfox"] = tf
    if tf.get("found"):
        threat_parts.append(f"{tf.get('malware', 'unknown')} ({tf.get('threat_type', 'unknown')}) via ThreatFox")

    # Type-specific lookups
    if ioc_type == "ip":
        if is_private_ip(indicator):
            raise HTTPException(status_code=400, detail="Private/reserved IP addresses are not allowed")
        feodo = query_feodo(indicator)
        sources["feodo"] = feodo
        if feodo.get("found"):
            threat_parts.append(f"{feodo.get('malware', 'unknown')} via Feodo Tracker")
        urlhaus = check_urlhaus(indicator)
        sources["urlhaus"] = {"found": urlhaus.get("url_count", 0) > 0, "urls_online": urlhaus.get("urls_online", 0)}
        if sources["urlhaus"]["found"]:
            threat_parts.append(f"{urlhaus['url_count']} malware URLs via URLhaus")

    elif ioc_type == "domain":
        urlhaus = check_urlhaus(indicator)
        sources["urlhaus"] = {"found": urlhaus.get("url_count", 0) > 0, "urls_online": urlhaus.get("urls_online", 0)}
        if sources["urlhaus"]["found"]:
            threat_parts.append(f"{urlhaus['url_count']} malware URLs via URLhaus")

    elif ioc_type == "url":
        # URLhaus can check URLs too (via host extraction)
        host = urlparse(indicator).hostname
        if host:
            if is_valid_ip(host):
                if is_private_ip(host):
                    raise HTTPException(status_code=400, detail="Private/reserved IP addresses are not allowed")
            else:
                # Resolve hostname with timeout and check all addresses for SSRF
                addrs, _ = _dns_call_with_timeout(socket.getaddrinfo, host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                if addrs and any(is_private_ip(addr[4][0]) for addr in addrs):
                    raise HTTPException(status_code=400, detail="Private/reserved IP addresses are not allowed")
            urlhaus = check_urlhaus(host)
            sources["urlhaus"] = {
                "found": urlhaus.get("url_count", 0) > 0,
                "urls_online": urlhaus.get("urls_online", 0),
            }
            if sources["urlhaus"]["found"]:
                threat_parts.append(f"{urlhaus['url_count']} malware URLs via URLhaus")

    # Determine threat level
    found_count = sum(1 for s in sources.values() if s.get("found"))
    if found_count >= 2:
        threat_level = "high"
    elif found_count == 1:
        threat_level = "medium"
    else:
        threat_level = "none"

    if threat_parts:
        summary = f"{indicator} flagged as malicious: " + ", ".join(threat_parts)
    else:
        summary = f"{indicator} — no threats found across {len(sources)} sources"

    return {
        "indicator": indicator,
        "type": ioc_type,
        "threat_level": threat_level,
        "sources": sources,
        "summary": summary,
    }


@router.get("/hash/{file_hash}", operation_id="hash_lookup", response_model=HashResponse, response_model_exclude_none=True)
def hash_lookup(file_hash: str, request: Request):
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


@router.get("/password/{sha1_hash}", operation_id="password_check", response_model=PasswordResponse, response_model_exclude_none=True)
def password_check(sha1_hash: str, request: Request):
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
            return {"found": False, "threat": None, "tags": []}
        return {
            "found": True,
            "threat": data.get("threat") or "unknown",
            "tags": data.get("tags") or [],
        }
    except Exception as e:
        logger.warning("URLhaus URL check failed for %s: %s", url, e)
        return {"found": False, "threat": None, "tags": []}


@router.get("/phishing/{url:path}", operation_id="phishing_check", response_model=PhishingResponse, response_model_exclude_none=True)
def phishing_check(url: str, request: Request):
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
    except Exception:
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

    is_malicious = urlhaus_url["found"] or urlhaus_host["found"]

    # Determine threat level
    if urlhaus_url["found"] and urlhaus_host["found"]:
        threat_level = "high"
    elif urlhaus_url["found"] or urlhaus_host["found"]:
        threat_level = "medium"
    else:
        threat_level = "none"

    # Build summary
    parts = []
    if urlhaus_url["found"]:
        parts.append(f"exact URL listed ({urlhaus_url['threat']})")
    if urlhaus_host["found"]:
        parts.append(f"host has {urlhaus_host['url_count']} malware URLs ({urlhaus_host['urls_online']} online)")
    if parts:
        summary = f"{url} — malicious: " + ", ".join(parts)
    else:
        summary = f"{url} — not found in threat databases"

    return {
        "url": url,
        "host": host,
        "is_malicious": is_malicious,
        "urlhaus_host": urlhaus_host,
        "urlhaus_url": urlhaus_url,
        "threat_level": threat_level,
        "summary": summary,
    }
