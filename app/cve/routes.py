"""CVE Intelligence API routes — /v1/cve/*, /v1/cves/*, /v1/exploit/*"""

import logging
import re
from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import unquote

import httpx
from auth import authenticate
from db import (
    get_cached_domain,
    get_cve,
    get_cve_sources,
    get_last_successful_sync,
    get_leading_cves,
    get_related_cves_by_product,
    save_cached_domain,
    search_cves,
    search_exploits_by_cve,
)
from fastapi import APIRouter, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field, StringConstraints
from schemas import (
    BulkCveResponse,
    CveResponse,
    CveSearchResponse,
    Exploit,
    ExploitResponse,
    Verdict,
)
from validation import is_valid_ip, validate_cve_id

logger = logging.getLogger("contrastapi")

router = APIRouter(prefix="/v1", tags=["CVE Intelligence"])

# Default cap on affected_products in API responses. Log4j-class CVEs can carry
# 50+ Siemens products — the full list is available via ?include_affected_products=true.
# TODO: consider unifying with the hardcoded 20 used for refs in cve.sync._parse_nvd_cve
# and the 20 limit in codesec/routes.py matched_cves guard (future refactor).
MAX_AFFECTED_PRODUCTS_DEFAULT = 20

_exploit_client = httpx.Client(timeout=httpx.Timeout(5.0, connect=3.0), follow_redirects=True)

_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_MIN_DATE = "1970-01-01"
_MAX_DATE = "2099-12-31"

_PATCH_URL_PATTERNS = (
    re.compile(r"github\.com/advisories/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE),
    re.compile(r"github\.com/[^/]+/[^/]+/(?:commit|pull)/[a-f0-9]{7,}", re.IGNORECASE),
    re.compile(r"(?:access\.)?redhat\.com/(?:errata|security/cve)/(?:RHSA|RHBA)-", re.IGNORECASE),
    re.compile(r"ubuntu\.com/security/notices/USN-", re.IGNORECASE),
    re.compile(r"debian\.org/security/(?:dla|dsa)-", re.IGNORECASE),
    re.compile(r"portal\.msrc\.microsoft\.com/(?:[^/]+/)?security-guidance(?:$|[/?#])", re.IGNORECASE),
    re.compile(
        r"security\.(?:adobe|apple|cisco|google|hp|ibm|intel|microsoft|mozilla|oracle|paloaltonetworks|redhat|samsung|sap|vmware)\.(?:com|net|org)/",
        re.IGNORECASE,
    ),  # known-vendor security advisory subdomain
)

# Open-redirect guard: reject URLs whose path/query looks like a redirector,
# even if the host matches an allowlisted vendor. Prevents NVD-poisoned refs
# like security.microsoft.com/redirect?to=attacker from surfacing as patch_url.
_REDIRECT_BLOCKLIST = re.compile(
    r"/(?:redirect|redir|goto|out|r)(?:[/?]|$)|[?&](?:url|u|to|dest|target|goto|next|return|ref|link|continue)=",
    re.IGNORECASE,
)


def _extract_patch_url(references: list[str]) -> tuple[bool, str | None]:
    """Detect patch/advisory URL from references list (open-redirect-guarded)."""
    for pattern in _PATCH_URL_PATTERNS:
        for url in references:
            # double-unquote to defeat %2F/%3F + %252F double-encoding tricks on the blocklist
            if pattern.search(url) and not _REDIRECT_BLOCKLIST.search(unquote(unquote(url))):
                return True, url
    return False, None


def _parse_date(value: str, name: str) -> str:
    """Validate YYYY-MM-DD (ASCII, 1970-2099) and return the canonical date string."""
    if not _DATE_RE.match(value):
        raise HTTPException(status_code=400, detail=f"{name} must be a valid YYYY-MM-DD date (UTC)")
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"{name} must be a valid YYYY-MM-DD date (UTC)") from e
    if value < _MIN_DATE or value > _MAX_DATE:
        raise HTTPException(status_code=400, detail=f"{name} must be between {_MIN_DATE} and {_MAX_DATE}")
    return value


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


@router.get(
    "/cve/leading",
    operation_id="cve_leading",
    response_model=CveSearchResponse,
    response_model_exclude_none=True,
)
def cve_leading(
    request: Request,
    limit: int = Query(50, ge=1, le=200, description="Max results per page"),
    offset: int = Query(0, ge=0, le=5000, description="Number of results to skip (for pagination)"),
):
    """CVEs indexed from MITRE/GHSA before NVD has enriched them. These are
    vulnerabilities we know about that NVD hasn't published yet — our unique
    early-warning feed."""
    authenticate(request, request.url.path)

    results, total = get_leading_cves(limit=limit, offset=offset)
    count = len(results)
    truncated = total > offset + count
    summary = f"{count} leading CVE{'s' if count != 1 else ''} returned, {total} total (indexed before NVD)"
    verdict = _cve_verdict(sources=["mitre_cache", "ghsa_cache"], completeness="complete")
    formatted_results = []
    for row in results:
        fr = _format_cve(row)
        fr["verdict"] = verdict
        formatted_results.append(fr)
    return {
        "count": count,
        "total": total,
        "truncated": truncated,
        "offset": offset,
        "summary": summary,
        "results": formatted_results,
    }


@router.get("/cve/{cve_id}", operation_id="cve_lookup", response_model=CveResponse, response_model_exclude_none=True)
def cve_lookup(
    cve_id: Annotated[
        str,
        Path(
            description=(
                "CVE identifier in canonical form 'CVE-YYYY-NNNN+' (case-insensitive; normalized to upper-case server-side). "
                "Examples: 'CVE-2021-44228', 'CVE-2014-0160'."
            ),
        ),
    ],
    request: Request,
    include_affected_products: bool = Query(
        False,
        description="Return full affected_products list (default: first 20). Use for bulk audits or dependency scans.",
    ),
):
    """Look up a single CVE by ID. Returns full details with EPSS score and KEV status."""
    cve_id = cve_id.strip().upper()
    _check_cve_input(cve_id)

    authenticate(request, request.url.path)

    result = get_cve(cve_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

    formatted = _format_cve(result, include_enrichment=True, include_full_products=include_affected_products)
    is_minimal = not (result.get("severity") or result.get("cvss_v3") or result.get("description"))
    completeness = "minimal" if is_minimal else "complete"
    sources_for_verdict = [f"{s}_cache" for s in formatted["sources"]]
    if not sources_for_verdict and not is_minimal:
        sources_for_verdict = ["nvd_cache"]
    formatted["verdict"] = _cve_verdict(sources=sources_for_verdict, completeness=completeness)
    return formatted


@router.get("/cves", operation_id="cve_search", response_model=CveSearchResponse, response_model_exclude_none=True)
def cve_search(
    request: Request,
    product: str | None = Query(
        None,
        min_length=2,
        max_length=100,
        description="Filter by product/vendor name. Exact match (case-insensitive) against NVD CPE tokens — not substring. Use canonical names: 'nginx', 'apache', 'linux_kernel'.",
    ),
    severity: str | None = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    published_after: str | None = Query(
        None,
        description="Inclusive lower bound on publish date (YYYY-MM-DD, UTC). Example: 2015-01-01 returns CVEs published on or after that day.",
    ),
    published_before: str | None = Query(
        None,
        description="Inclusive upper bound on publish date (YYYY-MM-DD, UTC). Example: 2020-12-31 returns CVEs published on or before that day.",
    ),
    kev: bool = Query(False, description="Filter to CISA KEV entries only"),
    epss_min: float | None = Query(None, ge=0.0, le=1.0, description="Minimum EPSS score (0.0-1.0)"),
    sort: str | None = Query(None, description="Sort order: epss_desc, cvss_desc, published_desc (default)"),
    limit: int = Query(50, ge=1, le=200, description="Max results per page"),
    offset: int = Query(0, ge=0, le=5000, description="Number of results to skip (for pagination)"),
    cwe_id: str | None = Query(None, description="Filter by CWE ID (e.g. CWE-79, CWE-89, CWE-120)"),
    cvss_min: float | None = Query(
        None, ge=0.0, le=10.0, description="Minimum CVSS v3 score (0.0-10.0). CVEs with null CVSS are excluded."
    ),
    cvss_max: float | None = Query(
        None, ge=0.0, le=10.0, description="Maximum CVSS v3 score (0.0-10.0). CVEs with null CVSS are excluded."
    ),
    vendor: str | None = Query(
        None,
        min_length=2,
        max_length=100,
        description="Filter by vendor name (case-insensitive). When combined with product, both must match the same cpe row.",
    ),
):
    """Search CVEs by product, severity, date range, KEV status, and EPSS score."""
    authenticate(request, request.url.path)

    if severity and severity.upper() not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        raise HTTPException(status_code=400, detail="severity must be CRITICAL, HIGH, MEDIUM, or LOW")
    if sort and sort not in ("epss_desc", "cvss_desc", "published_desc"):
        raise HTTPException(status_code=400, detail="sort must be epss_desc, cvss_desc, or published_desc")
    if cwe_id is not None:
        if not re.fullmatch(r"CWE-\d+", cwe_id, re.IGNORECASE):
            raise HTTPException(status_code=400, detail="cwe_id must match pattern CWE-<number> (e.g. CWE-79)")
    if cvss_min is not None and cvss_max is not None and cvss_min > cvss_max:
        raise HTTPException(status_code=400, detail="cvss_min must be <= cvss_max")

    after_date = _parse_date(published_after, "published_after") if published_after else None
    before_date = _parse_date(published_before, "published_before") if published_before else None
    if after_date and before_date and after_date > before_date:
        raise HTTPException(status_code=400, detail="published_after must be <= published_before")

    results, total = search_cves(
        product=product,
        severity=severity,
        published_after=after_date,
        published_before=before_date,
        kev=kev,
        epss_min=epss_min,
        sort=sort,
        limit=limit,
        offset=offset,
        cwe_id=cwe_id,
        cvss_min=cvss_min,
        cvss_max=cvss_max,
        vendor=vendor,
    )
    count = len(results)
    truncated = total > offset + count
    range_label = None
    if published_after and published_before:
        range_label = f"{published_after}..{published_before}"
    elif published_after:
        range_label = f"since {published_after}"
    elif published_before:
        range_label = f"until {published_before}"
    filters = [
        f
        for f in [
            product,
            vendor,
            severity,
            range_label,
            "KEV" if kev else None,
            f"EPSS>={epss_min}" if epss_min is not None else None,
            cwe_id,
            f"CVSS>={cvss_min}" if cvss_min is not None else None,
            f"CVSS<={cvss_max}" if cvss_max is not None else None,
        ]
        if f
    ]
    summary = f"{count} CVE{'s' if count != 1 else ''} returned, {total} total" + (
        f" ({', '.join(filters)})" if filters else ""
    )
    query_echo = {
        k: v
        for k, v in {
            "product": product,
            "vendor": vendor,
            "severity": severity,
            "cwe_id": cwe_id,
            "published_after": published_after,
            "published_before": published_before,
            "kev": True if kev else None,
            "epss_min": epss_min,
            "cvss_min": cvss_min,
            "cvss_max": cvss_max,
            "sort": sort,
            "limit": limit,
            "offset": offset if offset else None,
        }.items()
        if v is not None and v != ""
    }
    verdict = _cve_verdict(sources=["nvd_cache"], completeness="complete")
    formatted_results = []
    for row in results:
        fr = _format_cve(row)
        fr["verdict"] = verdict
        formatted_results.append(fr)
    next_offset = offset + count if truncated else None
    return {
        "count": count,
        "total": total,
        "truncated": truncated,
        "offset": offset,
        "summary": summary,
        "results": formatted_results,
        "query_echo": query_echo,
        "next_offset": next_offset,
    }


def _cve_verdict(sources: list[str] | None = None, completeness: str = "complete") -> Verdict:
    """Build a verdict metadata block for cve_lookup responses."""
    last = get_last_successful_sync("nvd")
    age: int | None = None
    if last:
        try:
            age = int((datetime.now(UTC) - datetime.fromisoformat(last)).total_seconds())
            if age < 0:
                age = None
        except ValueError:
            age = None
    return Verdict(
        deterministic=True,
        falsifiable_fields=["cve_id", "severity", "cvss_v3", "published", "references"],
        data_age_seconds=age,
        sources_queried=["nvd_cache"] if sources is None else sources,
        sources_unavailable=[],
        completeness=completeness,  # type: ignore[arg-type]
    )


def _sync_age_seconds(source: str) -> int | None:
    """Return seconds since last successful sync for a source, or None."""
    last = get_last_successful_sync(source)
    if not last:
        return None
    try:
        age = int((datetime.now(UTC) - datetime.fromisoformat(last)).total_seconds())
        return age if age >= 0 else None
    except ValueError:
        return None


def _exploit_lookup_verdict(github_error: bool, shodan_error: bool, offline_found: bool) -> Verdict:
    """Build a Verdict for exploit_lookup responses."""
    sources_queried = ["github_advisory", "shodan_cvedb", "exploitdb_csv"]
    unavailable = []
    if github_error:
        unavailable.append("github_advisory")
    if shodan_error:
        unavailable.append("shodan_cvedb")
    exploitdb_age = _sync_age_seconds("exploitdb")
    if exploitdb_age is not None and exploitdb_age > 7 * 86400:
        unavailable.append("exploitdb_csv")

    if not unavailable:
        completeness = "complete"
    elif offline_found:
        completeness = "partial"
    else:
        completeness = "minimal"

    return Verdict(
        deterministic=True,
        falsifiable_fields=["cve_id", "edb_id", "date_published", "url"],
        data_age_seconds=exploitdb_age,
        sources_queried=sources_queried,
        sources_unavailable=unavailable,
        completeness=completeness,  # type: ignore[arg-type]
    )


def _format_cve(row: dict, include_enrichment: bool = False, include_full_products: bool = False) -> dict:
    """Format a raw CVE db row into API response format.

    When include_enrichment=True (single-CVE lookup only), adds patch_available,
    patch_url, and related_cves. related_cves uses affected_products[0] only —
    multi-product CVEs are not UNIONed (simpler, 95% sufficient). Enrichment is
    gated off by default to avoid N+1 queries in search/bulk call sites.

    affected_products is truncated to the first MAX_AFFECTED_PRODUCTS_DEFAULT
    entries by default (Log4j-class CVEs can carry 50+ Siemens products and bloat
    MCP responses). total_products always reflects the honest full count. Pass
    include_full_products=True to return the complete list.

    Naming: the internal flag is `include_full_products` (emphasis: return all of
    them); the public API param in cve_lookup / _BulkCveRequest is
    `include_affected_products` (emphasis: the field being expanded). Keep the
    divergence — it matches how each audience reads the contract.

    related_cves uses the RAW DB `row.get("affected_products")` regardless of
    truncation, so enrichment is O(1) and never missed because of the cap.
    """
    sources_rows = get_cve_sources(row["cve_id"])
    source_names = [s["source"] for s in sources_rows]
    references = row.get("refs", [])
    all_products = row.get("affected_products", []) or []
    total_products = len(all_products)
    products = all_products if include_full_products else all_products[:MAX_AFFECTED_PRODUCTS_DEFAULT]
    result = {
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
        "affected_products": products,
        "total_products": total_products,
        "published": row.get("published"),
        "modified": row.get("modified"),
        "references": references,
        "sources": source_names,
        "first_seen_source": source_names[0] if source_names else None,
        "first_seen_at": sources_rows[0]["first_seen_at"] if sources_rows else None,
    }
    if include_enrichment:
        patch_available, patch_url = _extract_patch_url(references)
        result["patch_available"] = patch_available
        result["patch_url"] = patch_url
        affected = row.get("affected_products") or []
        if affected and (first := affected[0]).get("product"):
            result["related_cves"] = get_related_cves_by_product(
                product=first["product"],
                vendor=first.get("vendor"),
                limit=5,
                exclude_cve_id=row["cve_id"],
            )
        else:
            result["related_cves"] = []
    return result


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
        logger.warning("GitHub Advisory search timed out")
        return {"found": False, "count": 0, "advisories": [], "error": "upstream timeout"}
    except httpx.HTTPStatusError as e:
        logger.warning("GitHub Advisory search failed: HTTP %d", e.response.status_code)
        return {"found": False, "count": 0, "advisories": [], "error": "upstream error"}
    except Exception as e:
        logger.warning("GitHub Advisory search failed: %s", type(e).__name__)
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
        logger.warning("ExploitDB/Shodan search timed out")
        return {"found": False, "count": 0, "results": [], "error": "upstream timeout"}
    except httpx.HTTPStatusError as e:
        logger.warning("ExploitDB/Shodan search failed: HTTP %d", e.response.status_code)
        return {"found": False, "count": 0, "results": [], "error": "upstream error"}
    except Exception as e:
        logger.warning("ExploitDB/Shodan search failed: %s", type(e).__name__)
        return {"found": False, "count": 0, "results": [], "error": "upstream error"}


@router.get(
    "/exploit/{cve_id}", operation_id="exploit_lookup", response_model=ExploitResponse, response_model_exclude_none=True
)
def exploit_lookup(
    cve_id: Annotated[
        str,
        Path(
            description=(
                "CVE identifier 'CVE-YYYY-NNNN+' (case-insensitive; normalized to upper-case server-side). "
                "Example: 'CVE-2021-44228'."
            ),
        ),
    ],
    request: Request,
):
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
    offline, offline_truncated = search_exploits_by_cve(cve_id)

    exploits_found = len(offline) + github["count"] + exploitdb["count"]
    has_public_exploit = len(offline) > 0 or github["found"] or exploitdb["found"]

    # Build summary
    parts = []
    if github["found"]:
        parts.append(f"{github['count']} GitHub advisory(ies)")
    if exploitdb["found"]:
        parts.append(f"{exploitdb['count']} Shodan reference(s)")
    if offline:
        parts.append(f"{len(offline)} ExploitDB entry(ies)")
    if parts:
        summary = f"{cve_id} — {exploits_found} public exploit(s) found: " + ", ".join(parts)
    else:
        summary = f"{cve_id} — no public exploits found"

    structured_exploits = [
        Exploit(
            edb_id=row["edb_id"],
            cve_id=row["cve_id"],
            date_published=row.get("date_published"),
            author=row.get("author"),
            type=row.get("type"),
            platform=row.get("platform"),
            url=row.get("source_url") or f"https://www.exploit-db.com/exploits/{row['edb_id']}",
            verified=bool(row.get("verified")),
            description=row.get("description"),
        )
        for row in offline
    ]

    verdict = _exploit_lookup_verdict(
        github_error=github.get("error") is not None,
        shodan_error=exploitdb.get("error") is not None,
        offline_found=len(offline) > 0,
    )
    if offline_truncated and verdict.completeness == "complete":
        verdict.completeness = "partial"

    result = {
        "cve_id": cve_id,
        "exploits_found": exploits_found,
        "sources": {"github": github, "exploitdb": exploitdb},
        "has_public_exploit": has_public_exploit,
        "exploits": [e.model_dump() for e in structured_exploits],
        "verdict": verdict.model_dump(),
        "summary": summary,
    }

    save_cached_domain(cache_key, result)
    return {**result}


# === Bulk CVE Lookup ===


class _BulkCveRequest(BaseModel):
    cve_ids: list[Annotated[str, StringConstraints(max_length=64)]] = Field(..., min_length=1, max_length=50)
    include_affected_products: bool = Field(
        False,
        description="Return full affected_products list for each CVE (default: first 20).",
    )


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
        if not validate_cve_id(cid):
            results.append(
                {
                    "cve_id": cid,
                    "status": "invalid_format",
                    "cve": None,
                    "error": f"Invalid CVE ID format: {cid}",
                }
            )
            continue
        try:
            row = get_cve(cid)
            if row is None:
                results.append({"cve_id": cid, "status": "not_found", "cve": None, "error": f"CVE {cid} not found"})
            else:
                formatted = _format_cve(row, include_full_products=body.include_affected_products)
                is_minimal = not (row.get("severity") or row.get("cvss_v3") or row.get("description"))
                completeness = "minimal" if is_minimal else "complete"
                sources_for_verdict = [f"{s}_cache" for s in formatted["sources"]]
                if not sources_for_verdict and not is_minimal:
                    sources_for_verdict = ["nvd_cache"]
                formatted["verdict"] = _cve_verdict(sources=sources_for_verdict, completeness=completeness)
                results.append({"cve_id": cid, "status": "ok", "cve": formatted, "error": None})
                successful += 1
        except Exception as e:
            logger.warning("Bulk CVE lookup failed: %s", type(e).__name__)
            results.append({"cve_id": cid, "status": "error", "cve": None, "error": "Lookup failed"})

    failed = count - successful
    partial = failed > 0

    if failed == 0:
        summary = f"All {count} CVEs found"
    elif successful == 0:
        summary = f"No CVEs found in {count} lookups"
    else:
        summary = f"{successful}/{count} CVEs found, {failed} invalid, not found or failed"

    return {
        "results": results,
        "total": count,
        "successful": successful,
        "failed": failed,
        "timed_out": 0,
        "partial": partial,
        "summary": summary,
    }
