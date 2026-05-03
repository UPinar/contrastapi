"""IOC enrichment — ThreatFox, Feodo Tracker, MalwareBazaar lookups.

All upstream APIs are free (abuse.ch), Auth-Key required since 2026.
Failures return partial data with error fields, never raise exceptions.
"""

import asyncio
import logging
import re
import time

import httpx
from config import FEODO_MAX_BYTES, FEODO_TTL, settings

logger = logging.getLogger("contrastapi")

_TIMEOUT = httpx.Timeout(5.0, connect=3.0)
_auth_headers = {"Auth-Key": settings.urlhaus_api_key} if settings.urlhaus_api_key else {}
_client = httpx.AsyncClient(
    timeout=_TIMEOUT,
    follow_redirects=False,
    headers=_auth_headers,
    cookies=httpx.Cookies(),
    limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
)

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
FEODO_BLOCKLIST = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"

# In-memory Feodo blocklist cache (refreshed every hour)
_feodo_cache: dict = {"data": {}, "fetched_at": 0}
_feodo_lock = asyncio.Lock()

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_HASH_LENS = {32, 40, 64}  # MD5, SHA1, SHA256
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def detect_indicator_type(indicator: str) -> str:
    """Auto-detect IOC type: ip, domain, url, hash, or unknown."""
    indicator = indicator.strip()
    if "://" in indicator:
        return "url"
    if _IP_RE.match(indicator):
        return "ip"
    if _HEX_RE.match(indicator) and len(indicator) in _HASH_LENS:
        return "hash"
    if "." in indicator and "/" not in indicator:
        return "domain"
    return "unknown"


async def query_threatfox(indicator: str) -> dict:
    """Query ThreatFox for any IOC type (IP, domain, URL, hash)."""
    try:
        resp = await _client.post(
            THREATFOX_API,
            json={"query": "search_ioc", "search_term": indicator},
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") != "ok" or not data.get("data"):
            return {"found": False}
        entries = data["data"]
        first = entries[0]
        return {
            "found": True,
            "malware": first.get("malware_printable", "unknown"),
            "threat_type": first.get("threat_type", "unknown"),
            "confidence": first.get("confidence_level"),
            "tags": first.get("tags") or [],
            "first_seen": first.get("first_seen_utc"),
            "ioc_count": len(entries),
        }
    except httpx.TimeoutException:
        logger.warning("ThreatFox query timed out")
        return {"found": False, "error": "upstream timeout"}
    except httpx.HTTPStatusError as e:
        logger.warning("ThreatFox query failed: HTTP %d", e.response.status_code)
        return {"found": False, "error": "upstream error"}
    except Exception as e:
        logger.warning("ThreatFox query failed: %s", type(e).__name__)
        return {"found": False, "error": "upstream error"}


async def _refresh_feodo_cache() -> dict:
    """Download Feodo Tracker blocklist and cache it (loop-safe, size-limited)."""
    global _feodo_cache
    now = time.time()
    if now - _feodo_cache["fetched_at"] < FEODO_TTL and _feodo_cache["data"]:
        return _feodo_cache["data"]
    async with _feodo_lock:
        # Re-check inside lock — another task may have refreshed while we waited
        if now - _feodo_cache["fetched_at"] < FEODO_TTL and _feodo_cache["data"]:
            return _feodo_cache["data"]
        try:
            resp = await _client.get(FEODO_BLOCKLIST)
            resp.raise_for_status()
            if len(resp.content) > FEODO_MAX_BYTES:
                logger.warning("Feodo blocklist too large (%d bytes), skipping", len(resp.content))
                return _feodo_cache.get("data", {})
            entries = resp.json()
            ip_map = {}
            for entry in entries:
                ip = entry.get("ip_address")
                if ip:
                    ip_map[ip] = {
                        "malware": entry.get("malware", "unknown"),
                        "first_seen": entry.get("first_seen_utc"),
                        "last_online": entry.get("last_online"),
                        "status": entry.get("status"),
                    }
            _feodo_cache = {"data": ip_map, "fetched_at": time.time()}
            return ip_map
        except Exception as e:
            logger.warning("Feodo blocklist fetch failed: %s", type(e).__name__)
            return _feodo_cache.get("data", {})


async def query_feodo(ip: str) -> dict:
    """Check IP against Feodo Tracker C2 blocklist."""
    blocklist = await _refresh_feodo_cache()
    entry = blocklist.get(ip)
    if entry:
        return {"found": True, **entry}
    return {"found": False}


async def query_malwarebazaar(file_hash: str) -> dict:
    """Query MalwareBazaar for file hash reputation."""
    try:
        resp = await _client.post(
            MALWAREBAZAAR_API,
            data={"query": "get_info", "hash": file_hash},
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") != "ok" or not data.get("data"):
            return {"found": False}
        entry = data["data"][0] if isinstance(data["data"], list) else data["data"]
        return {
            "found": True,
            "malware_family": entry.get("signature") or entry.get("malware_family") or "unknown",
            "file_type": entry.get("file_type"),
            "file_size": entry.get("file_size"),
            "first_seen": entry.get("first_seen"),
            "tags": entry.get("tags") or [],
            "file_name": entry.get("file_name"),
        }
    except httpx.TimeoutException:
        logger.warning("MalwareBazaar query timed out")
        return {"found": False, "error": "upstream timeout"}
    except httpx.HTTPStatusError as e:
        logger.warning("MalwareBazaar query failed: HTTP %d", e.response.status_code)
        return {"found": False, "error": "upstream error"}
    except Exception as e:
        logger.warning("MalwareBazaar query failed: %s", type(e).__name__)
        return {"found": False, "error": "upstream error"}
