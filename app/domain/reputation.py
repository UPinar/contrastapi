"""IP reputation checks — GreyNoise, AbuseIPDB, Shodan full API."""

import logging
import httpx

from config import (
    RECON_TIMEOUT, GREYNOISE_API_KEY, GREYNOISE_API_URL,
    ABUSEIPDB_API_KEY, ABUSEIPDB_API_URL, SHODAN_API_KEY, SHODAN_API_URL,
)
from db import get_cached_domain, save_cached_domain

logger = logging.getLogger("contrastapi")

_client = httpx.Client(
    timeout=httpx.Timeout(RECON_TIMEOUT, connect=5.0),
    headers={"Accept": "application/json"},
    follow_redirects=False,
)


def check_greynoise(ip: str) -> dict:
    """Check IP against GreyNoise Community API."""
    if not GREYNOISE_API_KEY:
        return {"status": "skipped", "reason": "no API key"}
    cache_key = f"greynoise:{ip}"
    cached = get_cached_domain(cache_key)
    if cached is not None:
        return cached
    try:
        resp = _client.get(
            f"{GREYNOISE_API_URL}/{ip}",
            headers={"key": GREYNOISE_API_KEY},
        )
        if resp.status_code in (400, 404):
            result = {"status": "not_found", "reason": "IP not in dataset"}
            save_cached_domain(cache_key, result)
            return result
        if resp.status_code == 429:
            # Cache rate_limited for 24h (DOMAIN_CACHE_TTL) — GreyNoise daily limit resets overnight
            result = {"status": "rate_limited", "reason": "GreyNoise API rate limit exceeded"}
            save_cached_domain(cache_key, result)
            return result
        resp.raise_for_status()
        data = resp.json()
        result = {
            "status": "ok",
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "classification": data.get("classification", "unknown"),
            "name": data.get("name", ""),
            "last_seen": data.get("last_seen", ""),
        }
        save_cached_domain(cache_key, result)
        return result
    except httpx.HTTPStatusError as e:
        logger.warning("GreyNoise check failed for %s: HTTP %d", ip, e.response.status_code)
        return {"status": "error", "reason": f"GreyNoise API returned HTTP {e.response.status_code}"}
    except Exception:
        logger.warning("GreyNoise check failed for %s", ip)
        return {"status": "error", "reason": "GreyNoise API connection failed"}


def check_abuseipdb(ip: str) -> dict:
    """Check IP against AbuseIPDB."""
    if not ABUSEIPDB_API_KEY:
        return {"status": "skipped", "reason": "no API key"}
    try:
        resp = _client.get(
            f"{ABUSEIPDB_API_URL}",
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"Key": ABUSEIPDB_API_KEY},
        )
        if resp.status_code == 429:
            return {"status": "rate_limited", "reason": "AbuseIPDB API rate limit exceeded"}
        resp.raise_for_status()
        raw = resp.json()
        data = raw.get("data", {})
        return {
            "status": "ok",
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "usage_type": data.get("usageType", ""),
            "is_tor": data.get("isTor", False),
        }
    except httpx.HTTPStatusError as e:
        logger.warning("AbuseIPDB check failed for %s: HTTP %d", ip, e.response.status_code)
        return {"status": "error", "reason": f"AbuseIPDB API returned HTTP {e.response.status_code}"}
    except Exception:
        logger.warning("AbuseIPDB check failed for %s", ip)
        return {"status": "error", "reason": "AbuseIPDB API connection failed"}


def check_shodan(ip: str) -> dict:
    """Check IP against Shodan full API (more detail than InternetDB)."""
    if not SHODAN_API_KEY:
        return {"status": "skipped", "reason": "no API key"}
    cache_key = f"shodan:{ip}"
    cached = get_cached_domain(cache_key)
    if cached is not None:
        return cached
    try:
        resp = _client.get(
            f"{SHODAN_API_URL}/{ip}",
            params={"key": SHODAN_API_KEY},
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
            "vulns": list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else data.get("vulns", []),
            "hostnames": data.get("hostnames", []),
            "city": data.get("city", ""),
            "country_name": data.get("country_name", ""),
            "last_update": data.get("last_update", ""),
        }
        save_cached_domain(cache_key, result)
        return result
    except httpx.HTTPStatusError as e:
        logger.warning("Shodan check failed for %s: HTTP %d", ip, e.response.status_code)
        return {"status": "error", "reason": f"Shodan API returned HTTP {e.response.status_code}"}
    except Exception:
        logger.warning("Shodan check failed for %s", ip)
        return {"status": "error", "reason": "Shodan API connection failed"}
