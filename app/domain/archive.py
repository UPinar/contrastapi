"""Wayback Machine / Web Archive lookup — historical snapshots via CDX API."""

import logging

import httpx
from config import RECON_TIMEOUT

logger = logging.getLogger("contrastapi")

WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"

_client = httpx.Client(timeout=httpx.Timeout(RECON_TIMEOUT + 5, connect=5.0), follow_redirects=False)


def _parse_date(ts: str) -> str:
    """Parse CDX timestamp like '20260401123045' into 'YYYY-MM-DD'."""
    if len(ts) >= 8:
        return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
    return ts


def wayback_lookup(domain: str) -> dict:
    """Query Wayback Machine CDX API for archived snapshots of a domain.

    Returns:
        Dict with total_snapshots, first_seen, last_seen, years_online,
        snapshots list, archive_url, and summary.
    """
    archive_url = f"https://web.archive.org/web/*/{domain}"
    error_result = {
        "domain": domain,
        "total_snapshots": 0,
        "first_seen": None,
        "last_seen": None,
        "years_online": 0,
        "snapshots": [],
        "archive_url": archive_url,
        "summary": f"{domain} — no archived snapshots found",
    }

    try:
        resp = _client.get(
            WAYBACK_CDX_URL,
            params={
                "url": domain,
                "output": "json",
                "fl": "timestamp,statuscode,mimetype,digest",
                "collapse": "timestamp:8",
                "limit": -20,
            },
        )
        resp.raise_for_status()
        rows = resp.json()
    except Exception as e:
        logger.warning("Wayback CDX lookup failed for %s: %s", domain, e)
        return error_result

    # First row is column headers — skip it
    if not rows or len(rows) < 2:
        return error_result

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

    # Sort newest first
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
        "archive_url": archive_url,
        "summary": summary,
    }
