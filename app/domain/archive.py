"""Wayback Machine / Web Archive lookup — historical snapshots via CDX API."""

import json
import logging
import threading
import time

import httpx
from config import (
    WAYBACK_CACHE_MAX,
    WAYBACK_CACHE_TTL,
    WAYBACK_CDX_MAX_BYTES,
    WAYBACK_CDX_MAX_RESULTS,
    WAYBACK_CDX_TIMEOUT,
)

logger = logging.getLogger("contrastapi")

USER_AGENT = "contrastapi/1.0"
WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"

_client = httpx.Client(
    timeout=httpx.Timeout(WAYBACK_CDX_TIMEOUT, connect=5.0),
    follow_redirects=False,
    headers={"User-Agent": USER_AGENT},
)

_wayback_cache: dict[str, tuple[dict, float]] = {}
_wayback_cache_lock = threading.Lock()


def _parse_date(ts: str) -> str:
    """Parse CDX timestamp like '20260401123045' into 'YYYY-MM-DD'."""
    if len(ts) >= 8:
        return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
    return ts


def _fetch_cdx(domain: str) -> tuple[list | None, str | None]:
    """Returns (rows, error_msg). error_msg is None on success."""
    try:
        resp = _client.get(
            WAYBACK_CDX_URL,
            params={
                "url": domain,
                "output": "json",
                "fl": "timestamp,statuscode,mimetype,digest",
                "collapse": "timestamp:8",
                "limit": WAYBACK_CDX_MAX_RESULTS,
                "sort": "reverse",
            },
        )
        if resp.status_code == 429:
            return None, "cdx_rate_limited"
        if resp.status_code >= 500:
            return None, "cdx_unavailable"
        resp.raise_for_status()

        if len(resp.content) > WAYBACK_CDX_MAX_BYTES:
            return None, "cdx_body_too_large"

        rows = resp.json()
        return rows, None
    except httpx.TimeoutException:
        return None, "cdx_timeout"
    except httpx.HTTPStatusError as e:
        if e.response.status_code >= 500:
            return None, "cdx_unavailable"
        return None, "cdx_error"
    except (ValueError, json.JSONDecodeError):
        return None, "cdx_parse_error"
    except httpx.HTTPError:
        return None, "cdx_error"


def _empty_response(domain: str, warnings: list[str]) -> dict:
    return {
        "domain": domain,
        "total_snapshots": 0,
        "first_seen": None,
        "last_seen": None,
        "years_online": 0,
        "snapshots": [],
        "archive_url": f"https://web.archive.org/web/*/{domain}",
        "summary": f"{domain} — no archived snapshots found",
        "warnings": warnings,
    }


def _build_response(domain: str, rows: list, warnings: list[str]) -> dict:
    snapshots = []
    for row in rows[1:]:
        if len(row) != 4:
            continue
        ts, status, mimetype, _digest = row
        snapshots.append(
            {
                "timestamp": ts[:8],
                "date": _parse_date(ts),
                "status": status or "-",
                "mimetype": mimetype or "-",
                "url": f"https://web.archive.org/web/{ts}/https://{domain}",
            }
        )

    snapshots.sort(key=lambda s: s["timestamp"], reverse=True)

    total = len(snapshots)
    first_seen = snapshots[-1]["date"]
    last_seen = snapshots[0]["date"]

    first_year = int(first_seen[:4])
    last_year = int(last_seen[:4])
    years_online = max(last_year - first_year, 1) if total > 0 else 0

    summary = (
        f"{domain} — {total} snapshot{'s' if total != 1 else ''} "
        f"from {first_seen[:4]} to {last_seen[:4]} ({years_online} year{'s' if years_online != 1 else ''}). "
        f"Last archived {last_seen}."
    )

    return {
        "domain": domain,
        "total_snapshots": total,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "years_online": years_online,
        "snapshots": snapshots,
        "archive_url": f"https://web.archive.org/web/*/{domain}",
        "summary": summary,
        "warnings": warnings,
    }


def wayback_lookup(domain: str) -> dict:
    now = time.time()
    with _wayback_cache_lock:
        cached = _wayback_cache.get(domain)
        if cached and (now - cached[1]) < WAYBACK_CACHE_TTL:
            return cached[0]

    warnings: list[str] = []
    rows, err = _fetch_cdx(domain)

    if err:
        warnings.append(err)
        result = _empty_response(domain, warnings)
    elif not rows or len(rows) < 2:
        result = _empty_response(domain, warnings)
    else:
        result = _build_response(domain, rows, warnings)

    with _wayback_cache_lock:
        if len(_wayback_cache) >= WAYBACK_CACHE_MAX:
            oldest_key = min(_wayback_cache, key=lambda k: _wayback_cache[k][1])
            del _wayback_cache[oldest_key]
        _wayback_cache[domain] = (result, now)

    return result
