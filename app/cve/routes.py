"""CVE Intelligence API routes — /v1/cve/*, /v1/cves/*, /v1/exploit/*"""

import logging
import re
from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import unquote

import httpx
from auth import authenticate
from db import (
    count_cves_for_cwe,
    get_cached_domain,
    get_cve,
    get_cve_sources,
    get_cwe,
    get_kev_details,
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
    CweLookupResponse,
    Exploit,
    ExploitResponse,
    KevDetailResponse,
    PivotHint,
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

# Description-pattern signals that a fix shipped, even when the references list
# carries no canonical patch URL. Conservative: each pattern requires both a
# remediation verb AND a version-shaped token, so generic "fix" mentions don't
# false-positive. Catches Log4Shell-class CVEs whose NVD refs are all blog
# posts / packetstorm advisories with no GHSA / vendor-errata URL.
#
# Trade-off: this is a description-pattern signal, not ground truth. Pattern #3
# can match vendor-recommended actions ("Users should upgrade to version 5.0")
# even when the version is forward-looking. Acceptable because `patch_available`
# is not listed in verdict.falsifiable_fields and URL-based detection takes
# precedence; this fallback is informational. ReDoS-safe (pattern #1 lazy
# .{0,200}? bounded; 5000-char input matches in <0.0001s per Sonnet review).
_PATCH_DESCRIPTION_PATTERNS = (
    # "From version 2.16.0 ... has been completely removed" / "From log4j 2.15.0, this behavior has been disabled".
    # DOTALL is intentional: NVD descriptions occasionally span multiple sentences between the version anchor
    # and the remediation verb, but the 200-char window keeps the match tight enough to avoid cross-paragraph drift.
    re.compile(
        r"\bfrom\s+(?:\w+\s+)?(?:version\s+|v)?\d+\.\d+(?:\.\d+)?[,.\s)].{0,200}?"
        r"\b(?:disabled|removed|fixed|patched|resolved|addressed|mitigated)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    # "fixed in version 2.16.0" / "patched in 9.2.3"
    re.compile(
        r"\b(?:fixed|patched|resolved|addressed)\s+in\s+(?:version\s+|v)?\d+\.\d+(?:\.\d+)?",
        re.IGNORECASE,
    ),
    # "upgrade to version 2.16.0" / "update to 9.2". Permissive: catches vendor-recommended actions
    # ("Users should upgrade to ..."); may match forward-looking advisories. URL-based detection
    # takes precedence in the callsite, so this is a fallback only.
    re.compile(
        r"\b(?:upgrade|update)\s+to\s+(?:version\s+|v)?\d+\.\d+(?:\.\d+)?",
        re.IGNORECASE,
    ),
)

# Cap to keep the regex match O(n) bounded even if a future upstream publishes a
# pathologically long description (NVD's free-text field has no enforced cap).
_PATCH_DESCRIPTION_MAX_LEN = 10_000


def _describes_patch(description: str | None) -> bool:
    """Detect 'a fix shipped' from the CVE description text.

    Used as a fallback when references list has no canonical patch URL but the
    description spells out the fix version (Log4Shell pattern).
    """
    if not description or len(description) > _PATCH_DESCRIPTION_MAX_LEN:
        return False
    return any(p.search(description) for p in _PATCH_DESCRIPTION_PATTERNS)


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
    formatted["next_calls"] = _cve_pivot_hints(formatted)
    return formatted


def _cve_pivot_hints(record: dict) -> list[PivotHint]:
    """Build the suggested-next-call list for a CVE response (single + bulk items).

    Always emits exploit_lookup (every CVE could have public PoC). Adds kev_detail
    when kev.in_kev=True, and cwe_lookup when cwe_id is a canonical 'CWE-...' string.
    Intentionally NOT emitted on cve_search / cve_leading list items — agents pivot
    by calling cve_lookup on the result they care about, which then surfaces hints.
    """
    cve_id = record["cve_id"]
    hints: list[PivotHint] = [
        PivotHint(
            tool="exploit_lookup",
            input=cve_id,
            reason="Public exploits / PoC availability (GitHub Advisory + ExploitDB).",
        )
    ]
    kev = record.get("kev") or {}
    if isinstance(kev, dict) and kev.get("in_kev"):
        hints.append(
            PivotHint(
                tool="kev_detail",
                input=cve_id,
                reason="CISA KEV record: federal patch deadline, required action, ransomware association.",
            )
        )
    cwe_id = record.get("cwe_id")
    if cwe_id and isinstance(cwe_id, str) and cwe_id.startswith("CWE-"):
        hints.append(
            PivotHint(
                tool="cwe_lookup",
                input=cwe_id,
                reason=f"Weakness category for {cwe_id}: description, mitigations, parent/child chain.",
            )
        )
    return hints


def _kev_pivot_hints(record: dict) -> list[PivotHint]:
    """Build the suggested-next-call list for a KEV detail response.

    Order matters: agents tend to follow the array head-first, so we surface the
    most actionable pivot (full CVE detail) before the per-CWE category lookups.
    """
    cve_id = record["cve_id"]
    hints: list[PivotHint] = [
        PivotHint(
            tool="cve_lookup",
            input=cve_id,
            reason="Full CVE details: CVSS vector, EPSS probability, affected products, references, patch URL.",
        ),
        PivotHint(
            tool="exploit_lookup",
            input=cve_id,
            reason="Public exploits / PoC availability (GitHub Advisory + ExploitDB).",
        ),
    ]
    for cwe_id in record.get("cwes") or []:
        if not cwe_id or not str(cwe_id).startswith("CWE-"):
            continue
        hints.append(
            PivotHint(
                tool="cwe_lookup",
                input=cwe_id,
                reason=f"Weakness category for {cwe_id}: description, mitigations, parent/child chain.",
            )
        )
    return hints


@router.get(
    "/kev/{cve_id}",
    operation_id="kev_detail",
    response_model=KevDetailResponse,
    response_model_exclude_none=True,
)
def kev_detail(
    cve_id: Annotated[
        str,
        Path(
            description=(
                "CVE identifier in canonical form 'CVE-YYYY-NNNN+' (case-insensitive; normalized "
                "server-side). Returns 404 when the CVE is not in the CISA KEV catalog — use "
                "cve_lookup for non-KEV CVEs."
            ),
        ),
    ],
    request: Request,
):
    """Look up CISA KEV (Known Exploited Vulnerabilities) full record for a CVE.

    Returns federal patch deadline (due_date), CISA-specified remediation
    (required_action), known ransomware association, vendor/product, common
    vulnerability name (e.g. 'Log4Shell'), and CISA-reported CWE list. 404 when
    the CVE is not in the KEV catalog; use cve_lookup for non-KEV CVEs.
    """
    cve_id = cve_id.strip().upper()
    _check_cve_input(cve_id)

    authenticate(request, request.url.path)

    record = get_kev_details(cve_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} is not in the CISA KEV catalog")

    record["verdict"] = _cve_verdict(sources=["cisa_kev_cache"], completeness="complete")
    record["next_calls"] = _kev_pivot_hints(record)
    return record


_CWE_RE = re.compile(r"^CWE-(\d{1,6})$")


def _normalize_cwe(raw: str) -> str:
    """Normalize user input to canonical 'CWE-<digits>' form.

    Accepts: 'CWE-79', 'cwe-79', 'CWE 79', '79'. Raises HTTPException(400)
    on anything that doesn't yield 1-6 digits after stripping.
    """
    s = (raw or "").strip().upper().replace(" ", "")
    if not s.startswith("CWE-"):
        if s.startswith("CWE"):
            s = "CWE-" + s[3:]
        elif s.isdigit():
            s = f"CWE-{s}"
    if not _CWE_RE.match(s):
        raise HTTPException(status_code=400, detail="Invalid CWE format. Expected 'CWE-<digits>' (e.g. 'CWE-79').")
    return s


def _cwe_pivot_hints(record: dict, cve_count: int) -> list[PivotHint]:
    """Build the suggested-next-call list for a CWE lookup response.

    Order: cve_search (broadest exploration), parent walk, then children for drill-down.
    """
    cwe_id = record["cwe_id"]
    hints: list[PivotHint] = []
    if cve_count > 0:
        hints.append(
            PivotHint(
                tool="cve_search",
                input=cwe_id,
                reason=f"Enumerate the {cve_count} CVE(s) in our database mapped to this weakness (pass as cwe filter).",
            )
        )
    parent = record.get("parent_cwe")
    if parent and isinstance(parent, str) and parent.startswith("CWE-"):
        hints.append(
            PivotHint(
                tool="cwe_lookup",
                input=parent,
                reason=f"Walk up the weakness hierarchy: parent of {cwe_id} is {parent}.",
            )
        )
    for child in (record.get("child_cwes") or [])[:10]:
        if not child or not str(child).startswith("CWE-"):
            continue
        hints.append(
            PivotHint(
                tool="cwe_lookup",
                input=child,
                reason=f"Drill down to a more specific weakness: {child} is a child of {cwe_id}.",
            )
        )
    return hints


@router.get(
    "/cwe/{cwe_id}",
    operation_id="cwe_lookup",
    response_model=CweLookupResponse,
    response_model_exclude_none=True,
)
def cwe_lookup(
    cwe_id: Annotated[
        str,
        Path(
            description=(
                "CWE identifier in canonical form 'CWE-<digits>'. Tolerant of 'cwe-79', "
                "'CWE 79', or bare '79'. Returns 404 when the CWE is not in MITRE's "
                "research view 1000."
            ),
        ),
    ],
    request: Request,
):
    """Look up a MITRE CWE (Common Weakness Enumeration) catalog record.

    Returns description, abstract type, status, likelihood of exploit, recommended
    mitigations, observed example CVEs, and parent/child weakness chain. Use this
    after cve_lookup or kev_detail to understand the underlying weakness category.
    """
    normalized = _normalize_cwe(cwe_id)

    authenticate(request, request.url.path)

    record = get_cwe(normalized)
    if record is None:
        raise HTTPException(
            status_code=404, detail=f"{normalized} is not in the MITRE CWE catalog (research view 1000)"
        )

    cve_count = count_cves_for_cwe(normalized)
    record["cve_count"] = cve_count
    record["verdict"] = _cve_verdict(sources=["mitre_cwe_cache"], completeness="complete")
    record["next_calls"] = _cwe_pivot_hints(record, cve_count)
    return record


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
    include: str | None = Query(
        None,
        description=(
            "Per-result detail level. Default returns slim list items (cve_id, summary, severity, "
            "cvss_v3, cwe_id, epss, kev, total_products, published, modified, sources, verdict). "
            "Pass include=full to also return description, cvss_breakdown, affected_products, "
            "references, first_seen_source, first_seen_at. Slim default keeps token cost low when "
            "agents are filtering or paginating; for drill-down on a single CVE prefer cve_lookup."
        ),
    ),
):
    """Search CVEs by product, severity, date range, KEV status, and EPSS score."""
    authenticate(request, request.url.path)

    if severity and severity.upper() not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        raise HTTPException(status_code=400, detail="severity must be CRITICAL, HIGH, MEDIUM, or LOW")
    if sort and sort not in ("epss_desc", "cvss_desc", "published_desc"):
        raise HTTPException(status_code=400, detail="sort must be epss_desc, cvss_desc, or published_desc")
    if include not in (None, "", "full"):
        raise HTTPException(status_code=400, detail="include must be 'full' (omit for slim default)")
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
    full = include == "full"
    formatter = _format_cve if full else _format_cve_slim
    formatted_results = []
    for row in results:
        fr = formatter(row)
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
        if not patch_available and _describes_patch(row.get("description")):
            patch_available = True
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


def _format_cve_slim(row: dict) -> dict:
    """Slim formatter for cve_search list items.

    Drops description, cvss_breakdown, affected_products, references, first_seen_source,
    first_seen_at vs _format_cve(). Keeps fields agents need to triage and pivot:
    cve_id, summary, severity, cvss_v3, cwe_id, epss, kev, total_products, published,
    modified, sources. ~70% token reduction vs full payload on Log4j-class CVEs. Use
    cve_lookup or cve_search?include=full for drill-down.
    """
    sources_rows = get_cve_sources(row["cve_id"])
    source_names = [s["source"] for s in sources_rows]
    all_products = row.get("affected_products", []) or []
    return {
        "cve_id": row["cve_id"],
        "summary": row.get("summary") or _generate_summary(row),
        "severity": row.get("severity"),
        "cvss_v3": row.get("cvss_v3"),
        "cwe_id": row.get("cwe_id"),
        "epss": {
            "score": row.get("epss_score"),
            "percentile": row.get("epss_percentile"),
        },
        "kev": {
            "in_kev": bool(row.get("in_kev")),
            "date_added": row.get("kev_date_added"),
        },
        "total_products": len(all_products),
        "published": row.get("published"),
        "modified": row.get("modified"),
        "sources": source_names,
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
        logger.warning("GitHub Advisory search timed out")
        return {"found": False, "count": 0, "advisories": [], "error": "upstream timeout"}
    except httpx.HTTPStatusError as e:
        logger.warning("GitHub Advisory search failed: HTTP %d", e.response.status_code)
        return {"found": False, "count": 0, "advisories": [], "error": "upstream error"}
    except Exception as e:
        logger.warning("GitHub Advisory search failed: %s", type(e).__name__)
        return {"found": False, "count": 0, "advisories": [], "error": "upstream error"}


def _search_shodan_refs(cve_id: str) -> dict:
    """Fetch Shodan CVEDB references for a CVE (NOT ExploitDB — those come from the offline CSV)."""
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
        logger.warning("Shodan CVEDB search timed out")
        return {"found": False, "count": 0, "results": [], "error": "upstream timeout"}
    except httpx.HTTPStatusError as e:
        logger.warning("Shodan CVEDB search failed: HTTP %d", e.response.status_code)
        return {"found": False, "count": 0, "results": [], "error": "upstream error"}
    except Exception as e:
        logger.warning("Shodan CVEDB search failed: %s", type(e).__name__)
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
    shodan_refs = _search_shodan_refs(cve_id)
    offline, offline_truncated = search_exploits_by_cve(cve_id)

    exploits_found = len(offline) + github["count"] + shodan_refs["count"]
    has_public_exploit = len(offline) > 0 or github["found"] or shodan_refs["found"]

    # Build summary
    parts = []
    if github["found"]:
        parts.append(f"{github['count']} GitHub advisory(ies)")
    if shodan_refs["found"]:
        parts.append(f"{shodan_refs['count']} Shodan reference(s)")
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
        shodan_error=shodan_refs.get("error") is not None,
        offline_found=len(offline) > 0,
    )
    if offline_truncated and verdict.completeness == "complete":
        verdict.completeness = "partial"

    result = {
        "cve_id": cve_id,
        "exploits_found": exploits_found,
        "sources": {"github": github, "shodan_refs": shodan_refs},
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
                formatted["next_calls"] = _cve_pivot_hints(formatted)
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
