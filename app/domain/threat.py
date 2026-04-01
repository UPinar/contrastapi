"""Threat intelligence — URLhaus integration for malware/threat data."""

import logging

import httpx
from config import RECON_TIMEOUT, URLHAUS_API_KEY, URLHAUS_API_URL

logger = logging.getLogger("contrastapi")

_client = httpx.Client(
    timeout=httpx.Timeout(RECON_TIMEOUT, connect=5.0),
    headers={"Auth-Key": URLHAUS_API_KEY} if URLHAUS_API_KEY else {},
    follow_redirects=False,
)


def check_urlhaus(domain: str) -> dict:
    """Check a domain against URLhaus for known malware URLs.

    Returns:
        Dict with urls_online, url_count, threat_types, tags, and urls list.
    """
    try:
        resp = _client.post(
            f"{URLHAUS_API_URL}/host/",
            data={"host": domain},
        )
        resp.raise_for_status()
        result = resp.json()

        if result.get("query_status") == "no_results":
            return {
                "urlhaus_status": "clean",
                "urls_online": 0,
                "url_count": 0,
                "threat_types": [],
                "tags": [],
                "urls": [],
            }

        urls = result.get("urls", [])
        urls_online = sum(1 for u in urls if u.get("url_status") == "online")
        threat_types = list({u.get("threat", "unknown") for u in urls if u.get("threat")})
        tags = list({t for u in urls for t in (u.get("tags") or []) if t})

        url_list = []
        for u in urls[:20]:
            url_list.append(
                {
                    "url": u.get("url", ""),
                    "status": u.get("url_status", "unknown"),
                    "threat": u.get("threat", "unknown"),
                    "date_added": u.get("date_added"),
                    "tags": u.get("tags") or [],
                }
            )

        return {
            "urlhaus_status": "listed" if urls else "clean",
            "urls_online": urls_online,
            "url_count": len(urls),
            "threat_types": threat_types,
            "tags": tags[:20],
            "urls": url_list,
        }
    except Exception as e:
        logger.warning("URLhaus check failed for %s: %s", domain, e)
        return {
            "urlhaus_status": "error",
            "urls_online": 0,
            "url_count": 0,
            "threat_types": [],
            "tags": [],
            "urls": [],
        }
