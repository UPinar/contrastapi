"""HIBP Pwned Passwords — k-anonymity breach check.

Uses the free Have I Been Pwned Pwned Passwords API.
Client sends full SHA1 hash → we extract prefix, query HIBP range API,
check for match internally, and return only found + breach count.
The full suffix list is never exposed — preserves true k-anonymity.
No API key required, no rate limit.
"""

import logging
import re

import httpx

from config import HIBP_URL

logger = logging.getLogger("contrastapi")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_TIMEOUT = httpx.Timeout(5.0, connect=3.0)
_client = httpx.Client(
    timeout=_TIMEOUT,
    headers={"User-Agent": "contrastapi", "Add-Padding": "true"},
)


def is_valid_sha1(sha1_hash: str) -> bool:
    return bool(_SHA1_RE.match(sha1_hash))


def query_pwned_hash(sha1_hash: str) -> dict:
    """Check a SHA1 hash against HIBP Pwned Passwords. Returns found + breach count only."""
    sha1_hash = sha1_hash.upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    try:
        resp = _client.get(f"{HIBP_URL}/{prefix}")
        resp.raise_for_status()
        for line in resp.text.strip().split("\n"):
            parts = line.strip().split(":")
            if len(parts) == 2 and parts[0] == suffix:
                count = int(parts[1])
                if count > 0:
                    return {
                        "hash_prefix": prefix,
                        "found": True,
                        "breach_count": count,
                    }
        return {"hash_prefix": prefix, "found": False, "breach_count": 0}
    except Exception as e:
        logger.warning("HIBP query failed for prefix %s: %s", prefix, type(e).__name__)
        return {
            "hash_prefix": prefix,
            "found": False,
            "breach_count": 0,
            "error": "upstream timeout",
        }
