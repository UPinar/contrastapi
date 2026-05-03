"""IP reputation checks — AbuseIPDB, Shodan full API."""

import logging

import httpx
from config import (
    ABUSEIPDB_API_URL,
    RECON_TIMEOUT,
    SHODAN_API_URL,
    settings,
)
from db import get_cached_ip, save_cached_ip

logger = logging.getLogger("contrastapi")

_client = httpx.Client(
    timeout=httpx.Timeout(RECON_TIMEOUT, connect=5.0),
    headers={"Accept": "application/json"},
    follow_redirects=False,
)


def check_abuseipdb(ip: str) -> dict:
    """Check IP against AbuseIPDB."""
    if not settings.abuseipdb_api_key:
        return {"status": "skipped", "reason": "no API key"}
    cache_key = f"abuseipdb:{ip}"
    cached = get_cached_ip(cache_key)
    if cached is not None:
        return cached
    try:
        resp = _client.get(
            f"{ABUSEIPDB_API_URL}",
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"Key": settings.abuseipdb_api_key},
        )
        if resp.status_code == 429:
            return {"status": "rate_limited", "reason": "AbuseIPDB API rate limit exceeded"}
        resp.raise_for_status()
        raw = resp.json()
        data = raw.get("data", {})
        result = {
            "status": "ok",
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "usage_type": data.get("usageType", ""),
            "is_tor": data.get("isTor", False),
        }
        save_cached_ip(cache_key, result)
        return result
    except httpx.HTTPStatusError as e:
        logger.warning("AbuseIPDB check failed: HTTP %d", e.response.status_code)
        return {"status": "error", "reason": f"AbuseIPDB API returned HTTP {e.response.status_code}"}
    except httpx.RequestError:
        logger.warning("AbuseIPDB check failed: connection error")
        return {"status": "error", "reason": "AbuseIPDB API connection failed"}


def check_shodan(ip: str) -> dict:
    """Check IP against Shodan full API (more detail than InternetDB)."""
    if not settings.shodan_api_key:
        return {"status": "skipped", "reason": "no API key"}
    cache_key = f"shodan:{ip}"
    cached = get_cached_ip(cache_key)
    if cached is not None:
        return cached
    try:
        resp = _client.get(
            f"{SHODAN_API_URL}/{ip}",
            params={"key": settings.shodan_api_key},
        )
        if resp.status_code == 403:
            return {"status": "restricted", "reason": "IP not available on free tier"}
        if resp.status_code == 429:
            return {"status": "rate_limited", "reason": "Shodan API rate limit exceeded"}
        resp.raise_for_status()
        data = resp.json()
        result = {
            "status": "ok",
            "os": data.get("os"),
            "org": data.get("org", ""),
            "isp": data.get("isp", ""),
            "asn": data.get("asn", ""),
            "ports": data.get("ports", []),
            "vulns": list(data.get("vulns", {}).keys())
            if isinstance(data.get("vulns"), dict)
            else data.get("vulns", []),
            "hostnames": data.get("hostnames", []),
            "city": data.get("city", ""),
            "country_name": data.get("country_name", ""),
            "last_update": data.get("last_update", ""),
        }
        save_cached_ip(cache_key, result)
        return result
    except httpx.HTTPStatusError as e:
        logger.warning("Shodan check failed: HTTP %d", e.response.status_code)
        return {"status": "error", "reason": f"Shodan API returned HTTP {e.response.status_code}"}
    except httpx.RequestError:
        logger.warning("Shodan check failed: connection error")
        return {"status": "error", "reason": "Shodan API connection failed"}
