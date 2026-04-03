"""CVE Intelligence API routes — /v1/cve/*, /v1/cves/*, /v1/epss/*, /v1/exploit/*"""

import logging

import httpx
from auth import authenticate
from db import get_cached_domain, get_cve, get_epss, get_kev_cves, get_recent_cves, save_cached_domain, search_cves
from fastapi import APIRouter, HTTPException, Query, Request
from schemas import CveKevResponse, CveRecentResponse, CveResponse, CveSearchResponse, EpssResponse, ExploitResponse
from validation import is_valid_ip, validate_cve_id

logger = logging.getLogger("contrastapi")

router = APIRouter(prefix="/v1", tags=["CVE Intelligence"])

_exploit_client = httpx.Client(timeout=httpx.Timeout(5.0, connect=3.0), follow_redirects=False)


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


@router.get("/cves/recent", operation_id="cve_recent", response_model=CveRecentResponse, response_model_exclude_none=True)
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
        "cvss_vector": row.get("cvss_vector"),
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
            refs = [r.get("url", "") for r in (item.get("references") or []) if r.get("url")]
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
    except Exception as e:
        logger.warning("GitHub Advisory search failed for %s: %s", cve_id, e)
        return {"found": False, "count": 0, "advisories": []}


def _search_exploitdb(cve_id: str) -> dict:
    """Search Shodan Exploits API for exploit-db entries related to a CVE."""
    try:
        resp = _exploit_client.get(
            "https://exploits.shodan.io/api/search",
            params={"query": cve_id},
        )
        resp.raise_for_status()
        data = resp.json()
        matches = data.get("matches", [])
        results = []
        for item in matches[:20]:
            results.append(
                {
                    "id": str(item.get("_id", "")),
                    "description": item.get("description", ""),
                    "source": item.get("source", ""),
                }
            )
        return {"found": len(results) > 0, "count": len(results), "results": results}
    except Exception as e:
        logger.warning("ExploitDB/Shodan search failed for %s: %s", cve_id, e)
        return {"found": False, "count": 0, "results": []}


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
        return {**cached, "cached": True}

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
    return {**result, "cached": False}
