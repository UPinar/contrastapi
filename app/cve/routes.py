"""CVE Intelligence API routes — /v1/cve/*, /v1/cves/*, /v1/epss/*, /v1/exploit/*"""

import logging

import httpx
from auth import authenticate
from db import get_cached_domain, get_cve, get_epss, get_kev_cves, get_recent_cves, save_cached_domain, search_cves
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from schemas import (
    BulkCveResponse,
    CveKevResponse,
    CveRecentResponse,
    CveResponse,
    CveSearchResponse,
    EpssResponse,
    ExploitResponse,
)
from validation import is_valid_ip, validate_cve_id

logger = logging.getLogger("contrastapi")

router = APIRouter(prefix="/v1", tags=["CVE Intelligence"])

_exploit_client = httpx.Client(timeout=httpx.Timeout(5.0, connect=3.0), follow_redirects=True)


def _check_cve_input(cve_id: str):
    """Validate CVE ID and give helpful hints for wrong input types."""
    if is_valid_ip(cve_id):
        raise HTTPException(
            status_code=400, detail=f"'{cve_id}' is an IP address, not a CVE ID. Use /v1/ip/{cve_id} instead."
        )
    if "." in cve_id and not cve_id.startswith("CVE"):
        raise HTTPException(
            status_code=400, detail=f"'{cve_id}' looks like a domain, not a CVE ID. Use /v1/domain/{cve_id} instead."
        )
    if not validate_cve_id(cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE ID format (expected CVE-YYYY-NNNNN)")


@router.get("/cve/{cve_id}", operation_id="cve_lookup", response_model=CveResponse, response_model_exclude_none=True)
def cve_lookup(cve_id: str, request: Request):
    """Look up a single CVE by ID. Returns full details with EPSS score and KEV status."""
    cve_id = cve_id.strip().upper()
    _check_cve_input(cve_id)

    authenticate(request, request.url.path)

    result = get_cve(cve_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

    return _format_cve(result)


@router.get("/cves", operation_id="cve_search", response_model=CveSearchResponse, response_model_exclude_none=True)
def cve_search(
    request: Request,
    product: str | None = Query(
        None, min_length=2, max_length=100, description="Filter by product name (e.g. 'nginx', 'apache')"
    ),
    severity: str | None = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    days: int | None = Query(None, ge=1, le=365, description="CVEs published within N days"),
    limit: int = Query(50, ge=1, le=200, description="Max results"),
):
    """Search CVEs by product, severity, and/or date range."""
    authenticate(request, request.url.path)

    if severity and severity.upper() not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        raise HTTPException(status_code=400, detail="severity must be CRITICAL, HIGH, MEDIUM, or LOW")

    results = search_cves(product=product, severity=severity, days=days, limit=limit)
    count = len(results)
    filters = [f for f in [product, severity, f"last {days}d" if days else None] if f]
    summary = f"{count} CVE{'s' if count != 1 else ''} found" + (f" ({', '.join(filters)})" if filters else "")
    return {
        "count": count,
        "summary": summary,
        "results": [_format_cve(r) for r in results],
    }


@router.get(
    "/cves/recent", operation_id="cve_recent", response_model=CveRecentResponse, response_model_exclude_none=True
)
def cve_recent(
    request: Request,
    hours: int = Query(24, ge=1, le=168, description="CVEs published within N hours (max 168 = 7 days)"),
    limit: int = Query(50, ge=1, le=200, description="Max results"),
):
    """Get recently published CVEs."""
    authenticate(request, request.url.path)
    results = get_recent_cves(hours=hours, limit=limit)
    count = len(results)
    return {
        "count": count,
        "hours": hours,
        "summary": f"{count} CVE{'s' if count != 1 else ''} published in the last {hours} hour{'s' if hours != 1 else ''}",
        "results": [_format_cve(r) for r in results],
    }


@router.get("/cves/kev", operation_id="cve_kev", response_model=CveKevResponse, response_model_exclude_none=True)
def cve_kev(
    request: Request,
    limit: int = Query(100, ge=1, le=500, description="Max results"),
):
    """CISA Known Exploited Vulnerabilities — actively exploited CVEs."""
    authenticate(request, request.url.path)
    results = get_kev_cves(limit=limit)
    count = len(results)
    return {
        "count": count,
        "summary": f"{count} actively exploited CVE{'s' if count != 1 else ''} (CISA KEV)",
        "results": [_format_cve(r) for r in results],
    }


@router.get("/epss/{cve_id}", operation_id="epss_score", response_model=EpssResponse, response_model_exclude_none=True)
def epss_score(cve_id: str, request: Request):
    """EPSS (Exploit Prediction Scoring System) score for a CVE."""
    cve_id = cve_id.strip().upper()
    _check_cve_input(cve_id)

    authenticate(request, request.url.path)

    result = get_epss(cve_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"No EPSS data for {cve_id}")

    score = result.get("score")
    if score is not None:
        summary = f"{cve_id}: {score:.0%} exploitation probability"
    else:
        summary = f"{cve_id}: no EPSS score available"
    return {**result, "summary": summary}


def _format_cve(row: dict) -> dict:
    """Format a raw CVE db row into API response format."""
    return {
        "cve_id": row["cve_id"],
        "summary": row.get("summary") or _generate_summary(row),
        "description": row.get("description"),
        "severity": row.get("severity"),
        "cvss_v3": row.get("cvss_v3"),
        "cvss_breakdown": _parse_cvss_vector(row.get("cvss_vector")),
        "cwe_id": row.get("cwe_id"),
        "epss": {
            "score": row.get("epss_score"),
            "percentile": row.get("epss_percentile"),
        },
        "kev": {
            "in_kev": bool(row.get("in_kev")),
            "date_added": row.get("kev_date_added"),
        },
        "affected_products": row.get("affected_products", []),
        "published": row.get("published"),
        "modified": row.get("modified"),
        "references": row.get("refs", []),
    }


_CVSS_METRICS = {
    "AV": {
        "name": "attack_vector",
        "values": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    },
    "AC": {
        "name": "attack_complexity",
        "values": {"L": "Low", "H": "High"},
    },
    "PR": {
        "name": "privileges_required",
        "values": {"N": "None", "L": "Low", "H": "High"},
    },
    "UI": {
        "name": "user_interaction",
        "values": {"N": "None", "R": "Required"},
    },
    "S": {
        "name": "scope",
        "values": {"U": "Unchanged", "C": "Changed"},
    },
    "C": {
        "name": "confidentiality",
        "values": {"N": "None", "L": "Low", "H": "High"},
    },
    "I": {
        "name": "integrity",
        "values": {"N": "None", "L": "Low", "H": "High"},
    },
    "A": {
        "name": "availability",
        "values": {"N": "None", "L": "Low", "H": "High"},
    },
}


def _parse_cvss_vector(vector: str | None) -> dict | None:
    """Parse CVSS v3 vector string into human-readable breakdown."""
    if not vector or not vector.startswith("CVSS:3"):
        return None
    parts = vector.split("/")
    result = {}
    for part in parts[1:]:
        if ":" not in part:
            continue
        key, val = part.split(":", 1)
        metric = _CVSS_METRICS.get(key)
        if metric:
            result[metric["name"]] = metric["values"].get(val, val)
    return result if result else None


def _generate_summary(row: dict) -> str:
    """Auto-generate a one-line summary from structured fields."""
    parts = []
    severity = row.get("severity")
    if severity:
        parts.append(f"{severity}")

    cwe = row.get("cwe_id")
    if cwe:
        parts.append(f"({cwe})")

    desc = row.get("description", "")
    if desc:
        short = desc[:120].rsplit(" ", 1)[0] if len(desc) > 120 else desc
        parts.append(f"— {short}")

    cvss = row.get("cvss_v3")
    if cvss:
        parts.append(f"CVSS {cvss}.")

    if row.get("in_kev"):
        parts.append("Actively exploited (CISA KEV).")

    epss = row.get("epss_score")
    if epss is not None:
        parts.append(f"EPSS {epss:.0%} exploitation probability.")

    return " ".join(parts) if parts else row.get("cve_id", "")


def _search_github_advisories(cve_id: str) -> dict:
    """Search GitHub Advisory Database for advisories related to a CVE."""
    try:
        resp = _exploit_client.get(
            "https://api.github.com/advisories",
            params={"cve_id": cve_id},
            headers={"Accept": "application/vnd.github+json"},
        )
        resp.raise_for_status()
        data = resp.json()
        advisories = []
        for item in data[:20]:
            raw_refs = item.get("references") or []
            refs = [
                r if isinstance(r, str) else r.get("url", "") for r in raw_refs if (isinstance(r, str) or r.get("url"))
            ]
            advisories.append(
                {
                    "ghsa_id": item.get("ghsa_id", ""),
                    "summary": item.get("summary", ""),
                    "severity": item.get("severity"),
                    "published_at": item.get("published_at"),
                    "references": refs[:10],
                }
            )
        return {"found": len(advisories) > 0, "count": len(advisories), "advisories": advisories}
    except httpx.TimeoutException:
        logger.warning("GitHub Advisory search timed out for %s", cve_id)
        return {"found": False, "count": 0, "advisories": [], "error": "upstream timeout"}
    except httpx.HTTPStatusError as e:
        logger.warning("GitHub Advisory search failed for %s: HTTP %d", cve_id, e.response.status_code)
        return {"found": False, "count": 0, "advisories": [], "error": "upstream error"}
    except Exception as e:
        logger.warning("GitHub Advisory search failed for %s: %s", cve_id, type(e).__name__)
        return {"found": False, "count": 0, "advisories": [], "error": "upstream error"}


def _search_exploitdb(cve_id: str) -> dict:
    """Search Shodan CVEDB for exploit/vuln info related to a CVE."""
    try:
        resp = _exploit_client.get(
            f"https://cvedb.shodan.io/cve/{cve_id}",
        )
        if resp.status_code == 404:
            return {"found": False, "count": 0, "results": []}
        resp.raise_for_status()
        data = resp.json()
        refs = data.get("references", [])
        results = []
        for url in refs[:20]:
            results.append(
                {
                    "id": cve_id,
                    "description": url if isinstance(url, str) else str(url),
                    "source": "cvedb.shodan.io",
                }
            )
        return {"found": len(results) > 0, "count": len(results), "results": results}
    except httpx.TimeoutException:
        logger.warning("ExploitDB/Shodan search timed out for %s", cve_id)
        return {"found": False, "count": 0, "results": [], "error": "upstream timeout"}
    except httpx.HTTPStatusError as e:
        logger.warning("ExploitDB/Shodan search failed for %s: HTTP %d", cve_id, e.response.status_code)
        return {"found": False, "count": 0, "results": [], "error": "upstream error"}
    except Exception as e:
        logger.warning("ExploitDB/Shodan search failed for %s: %s", cve_id, type(e).__name__)
        return {"found": False, "count": 0, "results": [], "error": "upstream error"}


@router.get(
    "/exploit/{cve_id}", operation_id="exploit_lookup", response_model=ExploitResponse, response_model_exclude_none=True
)
def exploit_lookup(cve_id: str, request: Request):
    """Search for public exploits and advisories related to a CVE."""
    cve_id = cve_id.strip().upper()
    _check_cve_input(cve_id)
    authenticate(request, "/v1/exploit")

    # Check cache
    cache_key = f"exploit:{cve_id}"
    cached = get_cached_domain(cache_key)
    if cached:
        return {**cached}

    github = _search_github_advisories(cve_id)
    exploitdb = _search_exploitdb(cve_id)

    exploits_found = github["count"] + exploitdb["count"]
    has_public_exploit = github["found"] or exploitdb["found"]

    # Build summary
    parts = []
    if github["found"]:
        parts.append(f"{github['count']} GitHub advisory(ies)")
    if exploitdb["found"]:
        parts.append(f"{exploitdb['count']} exploit(s)")
    if parts:
        summary = f"{cve_id} — {exploits_found} public exploit(s) found: " + ", ".join(parts)
    else:
        summary = f"{cve_id} — no public exploits found"

    result = {
        "cve_id": cve_id,
        "exploits_found": exploits_found,
        "sources": {"github": github, "exploitdb": exploitdb},
        "has_public_exploit": has_public_exploit,
        "summary": summary,
    }

    save_cached_domain(cache_key, result)
    return {**result}


# === Bulk CVE Lookup ===


class _BulkCveRequest(BaseModel):
    cve_ids: list[str] = Field(..., min_length=1, max_length=50)


@router.post(
    "/cves/bulk",
    operation_id="bulk_cve_lookup",
    response_model=BulkCveResponse,
    response_model_exclude_none=True,
)
def bulk_cve_lookup(body: _BulkCveRequest, request: Request):
    """Bulk CVE lookup — up to 10 CVEs (free) or 50 (pro). Each CVE counts as 1 request toward rate limit."""
    import ratelimit
    from auth import extract_key, hash_key
    from config import FREE_BULK_LIMIT, FREE_HOURLY_LIMIT, PRO_BULK_LIMIT, PRO_HOURLY_LIMIT
    from validation import get_client_ip

    auth_ctx = authenticate(request, "/v1/cves/bulk")
    client_ip = get_client_ip(request)

    bulk_limit = PRO_BULK_LIMIT if auth_ctx["tier"] == "pro" else FREE_BULK_LIMIT

    cve_ids = list(dict.fromkeys(c.strip().upper() for c in body.cve_ids if c.strip()))
    count = len(cve_ids)

    if count == 0:
        raise HTTPException(status_code=400, detail="cve_ids must contain at least one valid CVE ID")
    if count > bulk_limit:
        raise HTTPException(
            status_code=422,
            detail=f"Too many CVE IDs. Limit: {bulk_limit} (your tier: {auth_ctx['tier']})",
        )

    for cid in cve_ids:
        if not validate_cve_id(cid):
            raise HTTPException(status_code=400, detail=f"Invalid CVE ID format: {cid}")

    raw_key = extract_key(request)
    if raw_key:
        store_key = f"pro:{hash_key(raw_key)}"
        limit = PRO_HOURLY_LIMIT
    else:
        store_key = f"free:{client_ip}"
        limit = FREE_HOURLY_LIMIT

    if count > 1 and not ratelimit.consume_bulk("api", store_key, count - 1, limit):
        raise HTTPException(
            status_code=429,
            detail=f"Insufficient rate limit quota for {count} CVE IDs.",
        )

    results = []
    successful = 0
    for cid in cve_ids:
        try:
            row = get_cve(cid)
            if row is None:
                results.append({"cve_id": cid, "status": "not_found", "cve": None, "error": f"CVE {cid} not found"})
            else:
                results.append({"cve_id": cid, "status": "ok", "cve": _format_cve(row), "error": None})
                successful += 1
        except Exception as e:
            logger.warning("Bulk CVE lookup failed for %s: %s", cid, type(e).__name__)
            results.append({"cve_id": cid, "status": "error", "cve": None, "error": "Lookup failed"})

    failed = count - successful
    if failed == 0:
        summary = f"All {count} CVEs found"
    elif successful == 0:
        summary = f"No CVEs found in {count} lookups"
    else:
        summary = f"{successful}/{count} CVEs found, {failed} not found or failed"

    return {
        "results": results,
        "total": count,
        "successful": successful,
        "failed": failed,
        "summary": summary,
    }
