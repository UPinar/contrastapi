"""CVE Intelligence API routes — /v1/cve/*, /v1/cves/*, /v1/exploit/*"""

import hashlib
import json
import logging
import re
from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import unquote

import httpx
from auth import AuthCtx, require_auth
from config import settings
from cve.cvss_parser import parse_cvss_vector
from cve.risk_scorer import compute_risk_score
from cve.schemas import (
    BulkCveResponse,
    CveResponse,
    CveSearchResponse,
    CvssDetailsResponse,
    CweLookupResponse,
    Exploit,
    ExploitResponse,
    KevDetailResponse,
    RiskScoreResponse,
)
from db import (
    acount_cves_for_cwe,
    aget_cached_domain,
    aget_cve,
    aget_cve_sources,
    aget_cwe,
    aget_exploitdb_synced_at,
    aget_kev_details,
    aget_last_successful_sync,
    aget_leading_cves,
    aget_related_cves_by_product,
    asave_cached_domain,
    asearch_cves,
    asearch_exploits_by_cve,
    hash_client_ip,
)
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field, StringConstraints
from schemas import PivotHint, SearchHint, Verdict
from validation import is_valid_ip, sanitize_echo, validate_cve_id

logger = logging.getLogger("contrastapi")

router = APIRouter(tags=["CVE Intelligence"])

# Default cap on affected_products in API responses. Log4j-class CVEs can carry
# 50+ Siemens products — the full list is available via ?include_affected_products=true.
# TODO: consider unifying with the hardcoded 20 used for refs in cve.sync._parse_nvd_cve
# and the 20 limit in codesec/routes.py matched_cves guard (future refactor).
MAX_AFFECTED_PRODUCTS_DEFAULT = 20

# Default cap on references in API responses. Older CVEs and high-profile bugs
# (Log4Shell, Heartbleed) can carry 30-60+ advisory URLs; agents only need the
# first handful for triage. Full list is available via ?include_full_references=true.
MAX_REFERENCES_DEFAULT = 10

# cwe_lookup slim defaults. CWE-79 ships 12 mitigations of 500-1000 chars each
# (~10 KB) and 12+ example CVEs — both blow MCP context. Slim default returns
# first 3 of each + honest total_* counts; ?include=full restores the full lists
# and extended_description.
MAX_CWE_MITIGATIONS_DEFAULT = 3
MAX_CWE_EXAMPLES_DEFAULT = 3

_exploit_client = httpx.AsyncClient(
    timeout=httpx.Timeout(5.0, connect=3.0),
    follow_redirects=True,
    cookies=httpx.Cookies(),
    limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
    headers={"Accept-Encoding": "identity"},
)

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
    # Microsoft MSRC modern advisory (e.g. msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30040)
    re.compile(r"msrc\.microsoft\.com/update-guide/vulnerability/", re.IGNORECASE),
    # Apple support article — legacy HT format (e.g. support.apple.com/en-us/HT214055)
    re.compile(r"support\.apple\.com/en-us/HT\d+", re.IGNORECASE),
    # Apple support article — modern 6-digit format (e.g. support.apple.com/en-us/121752)
    re.compile(r"support\.apple\.com/en-us/\d{6}", re.IGNORECASE),
    # Fortinet PSIRT advisory (e.g. fortiguard.com/psirt/FG-IR-24-015)
    re.compile(r"fortiguard\.com/psirt/FG-IR-", re.IGNORECASE),
    # Linux kernel.org git commit with ?id=<sha> (e.g. git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f342de4e)
    re.compile(r"git\.kernel\.org/pub/scm/.*?\bcommit\b.*?\?id=[a-f0-9]{7,}", re.IGNORECASE),
    # kernel.dance shortlink for kernel commits (e.g. kernel.dance/<sha>)
    re.compile(r"kernel\.dance/[a-f0-9]{7,}", re.IGNORECASE),
    # Cisco modern security advisory host (e.g. sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z)
    re.compile(r"sec\.cloudapps\.cisco\.com/security/center/content/CiscoSecurityAdvisory/", re.IGNORECASE),
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


def _extract_patch_url(
    refs_with_tags: list[dict] | None,
    references: list[str],
) -> tuple[bool, str | None]:
    """Detect patch/advisory URL: tag-first (NVD Patch/Vendor Advisory) then Batch 1 regex fallback.
    Tag-first runs against refs_with_tags (6A structured shape). Regex fallback runs against
    references (legacy URL list) when refs_with_tags is None (legacy cached row) or when no tag matches.
    Open-redirect-guarded on both tag-first and regex paths (unquote double-decode)."""
    if refs_with_tags:
        for r in refs_with_tags:
            url = r.get("url")
            if not isinstance(url, str) or not url:
                continue
            tags_raw = r.get("tags") or []
            tags_lower = {(t or "").lower() for t in tags_raw if isinstance(t, str)}
            if "patch" in tags_lower or "vendor advisory" in tags_lower:
                if not _REDIRECT_BLOCKLIST.search(unquote(unquote(url))):
                    return True, url
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
    # Sanitize for echo: cve_id is raw path-param, may carry CRLF / Trojan-Source / HTML.
    safe_cve_id = sanitize_echo(cve_id)
    if is_valid_ip(cve_id):
        raise HTTPException(
            status_code=400,
            detail=f"'{safe_cve_id}' is an IP address, not a CVE ID. Use /v1/ip/{safe_cve_id} instead.",
        )
    if "." in cve_id and not cve_id.startswith("CVE"):
        raise HTTPException(
            status_code=400,
            detail=f"'{safe_cve_id}' looks like a domain, not a CVE ID. Use /v1/domain/{safe_cve_id} instead.",
        )
    if not validate_cve_id(cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE ID format (expected CVE-YYYY-NNNNN)")


@router.get(
    "/cve/leading",
    operation_id="cve_leading",
    response_model=CveSearchResponse,
    response_model_exclude_none=True,
)
async def cve_leading(
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/cve/leading"))],
    limit: int = Query(50, ge=1, le=200, description="Max results per page"),
    offset: int = Query(0, ge=0, le=5000, description="Number of results to skip (for pagination)"),
    include: str | None = Query(
        None,
        description=(
            "Per-result detail level. Default returns slim list items (cve_id, summary, severity, "
            "cvss_v3, cwe_id, epss, kev, total_products, published, modified, sources, verdict). "
            "Pass include=full to also return description, cvss_breakdown, affected_products, "
            "references, first_seen_source, first_seen_at. Slim default avoids the description/"
            "summary duplication that bloats 50-item leading lists; for drill-down prefer cve_lookup."
        ),
    ),
):
    """CVEs indexed from MITRE/GHSA before NVD has enriched them. These are
    vulnerabilities we know about that NVD hasn't published yet — our unique
    early-warning feed."""

    if include not in (None, "", "full"):
        raise HTTPException(status_code=400, detail="include must be 'full' (omit for slim default)")

    cache_key = f"cve_leading:{limit}:{offset}:{'full' if include == 'full' else 'slim'}"
    cached = await aget_cached_domain(cache_key)
    if cached:
        leading_unavailable = await _cve_leading_sources_unavailable()
        cached["verdict"] = (
            await _cve_verdict(
                sources=["mitre_cache", "ghsa_cache"],
                completeness="complete",
                primary_source="mitre",
                sources_unavailable=leading_unavailable,
            )
        ).model_dump()
        return cached

    results, total = await aget_leading_cves(limit=limit, offset=offset)
    count = len(results)
    truncated = total > offset + count
    next_offset = offset + count if truncated else None
    summary = f"{count} leading CVE{'s' if count != 1 else ''} returned, {total} total (indexed before NVD)"
    formatter = _format_cve if include == "full" else _format_cve_slim
    formatted_results = [await formatter(row) for row in results]
    hint = _cve_list_hint(count)
    next_calls = _cve_leading_pivot_hints(formatted_results)
    response = {
        "count": count,
        "total": total,
        "truncated": truncated,
        "offset": offset,
        "summary": summary,
        "results": formatted_results,
        "next_offset": next_offset,
        "hint": hint.model_dump() if hint else None,
        "next_calls": [h.model_dump() for h in next_calls] if next_calls else None,
    }
    await asave_cached_domain(cache_key, response)
    leading_unavailable = await _cve_leading_sources_unavailable()
    response["verdict"] = (
        await _cve_verdict(
            sources=["mitre_cache", "ghsa_cache"],
            completeness="complete",
            primary_source="mitre",
            sources_unavailable=leading_unavailable,
        )
    ).model_dump()
    return response


@router.get("/cve/{cve_id}", operation_id="cve_lookup", response_model=CveResponse, response_model_exclude_none=True)
async def cve_lookup(
    cve_id: Annotated[
        str,
        Path(
            description=(
                "CVE identifier in canonical form 'CVE-YYYY-NNNN+' (case-insensitive; normalized to upper-case server-side). "
                "Examples: 'CVE-2021-44228', 'CVE-2014-0160'."
            ),
        ),
    ],
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/cve"))],
    include_affected_products: bool = Query(
        False,
        description="Return full affected_products list (default: first 20). Use for bulk audits or dependency scans.",
    ),
    include_full_references: bool = Query(
        False,
        description="Return full references list (default: first 10). total_references is always emitted with the honest count. Patch URL detection always runs against the full list, so patch_url/patch_available are unaffected by the cap.",
    ),
    include_reference_tags: bool = Query(
        False,
        description="Return structured `references_full` field with [{url, tags, source}] objects (NVD reference tags + source provenance). Default False keeps `references` as plain URL list (backward compat). Combine with include_full_references=true for full untruncated structured list.",
    ),
    include_severity_breakdown: bool = Query(
        False,
        description="Return severity_sources/severity_consensus/severity_disagreement (multi-source severity breakdown). Default False keeps response shape backward-compat. Set True to inspect vendor disputes (e.g. CVE-2023-38545 NVD-CRITICAL vs GHSA-HIGH). cvss_v2 / cvss_v2_vector are always emitted (additive non-opt-in).",
    ),
):
    """Look up a single CVE by ID. Returns full details with EPSS score and KEV status."""
    cve_id = cve_id.strip().upper()
    _check_cve_input(cve_id)

    # Cache key embeds the four opt-in flags that change response shape.
    # 16 variants per CVE; the (False, False, False, False) default dominates in practice.
    # verdict is NEVER stored in the cached payload — it's rebuilt on every
    # response so data_age_seconds reflects current NVD sync, not write-time.
    cache_key = f"cve_lookup:{cve_id}:{int(include_affected_products)}{int(include_full_references)}{int(include_reference_tags)}{int(include_severity_breakdown)}"
    cached = await aget_cached_domain(cache_key)
    if cached:
        sources, completeness, populated_fields, has_references, vuln_status = _cve_lookup_verdict_inputs(cached)
        cached["verdict"] = (
            await _cve_verdict(
                sources=sources,
                completeness=completeness,
                populated_fields=populated_fields,
                has_references=has_references,
                vulnerability_status=vuln_status,
            )
        ).model_dump()
        return cached

    result = await aget_cve(cve_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

    formatted = await _format_cve(
        result,
        include_enrichment=True,
        include_full_products=include_affected_products,
        include_full_references=include_full_references,
        include_reference_tags=include_reference_tags,
        include_severity_breakdown=include_severity_breakdown,
    )
    formatted["next_calls"] = [h.model_dump() for h in _cve_pivot_hints(formatted)]
    await asave_cached_domain(cache_key, formatted)
    sources, completeness, populated_fields, has_references, vuln_status = _cve_lookup_verdict_inputs(formatted)
    formatted["verdict"] = (
        await _cve_verdict(
            sources=sources,
            completeness=completeness,
            populated_fields=populated_fields,
            has_references=has_references,
            vulnerability_status=vuln_status,
        )
    ).model_dump()
    return formatted


@router.get(
    "/cve/{cve_id}/risk_score",
    operation_id="calculate_risk_score",
    response_model=RiskScoreResponse,
    response_model_exclude_none=True,
)
async def calculate_risk_score(
    cve_id: Annotated[
        str,
        Path(
            description=(
                "CVE identifier 'CVE-YYYY-NNNN+' (case-insensitive; normalized to upper-case server-side). "
                "Example: 'CVE-2021-44228'."
            ),
        ),
    ],
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/cve"))],
):
    """Composite CVE risk score (0-100) — fuses CVSS, EPSS, KEV, and PoC signals.

    Formula: CVSS*0.20 + EPSS*0.35 + KEV*0.30 + PoC*0.15 (each component
    rescaled to 0-100 before weighting), with multiplicative boosters for
    KEV+PoC combo, critical-severity high-EPSS, and recent publication.
    Returns score, label (CRITICAL/HIGH/MEDIUM/LOW), urgency, and a
    one-sentence remediation hint — agent-friendly triage signal in a
    single call.

    PoC signal here is the local ExploitDB mirror only. For full
    multi-source exploit detail (GitHub Advisory + Shodan refs +
    ExploitDB), call exploit_lookup separately.

    Methodology adapted from mukul975/cve-mcp-server (Apache-2.0):
    https://github.com/mukul975/cve-mcp-server.
    """
    cve_id = cve_id.strip().upper()
    _check_cve_input(cve_id)

    record = await aget_cve(cve_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

    offline, _truncated = await asearch_exploits_by_cve(cve_id)
    has_poc = len(offline) > 0
    in_kev = bool(record.get("in_kev"))

    result = compute_risk_score(
        cvss_v3=record.get("cvss_v3"),
        epss_score=record.get("epss_score"),
        in_kev=in_kev,
        has_poc=has_poc,
        published_at=record.get("published"),
    )

    cvss_display = record.get("cvss_v3") if record.get("cvss_v3") is not None else "n/a"
    epss_display = record.get("epss_score") if record.get("epss_score") is not None else "n/a"
    summary = (
        f"{cve_id} - risk_score={result.score} ({result.label}). "
        f"CVSS={cvss_display}, EPSS={epss_display}, KEV={in_kev}, PoC={has_poc}."
    )

    next_calls: list[PivotHint] = [
        PivotHint(
            tool="cve_lookup",
            input=cve_id,
            reason="Full CVE context: CVSS breakdown, affected products, references, patch URL.",
        ),
        PivotHint(
            tool="exploit_lookup",
            input=cve_id,
            reason="Multi-source PoC detail (GitHub Advisory + Shodan refs + ExploitDB) - this score uses ExploitDB only.",
        ),
    ]
    if in_kev:
        next_calls.append(
            PivotHint(
                tool="kev_detail",
                input=cve_id,
                reason="CISA KEV record: federal patch deadline, required action, ransomware association.",
            )
        )
    cwe_id = record.get("cwe_id")
    if cwe_id and isinstance(cwe_id, str) and cwe_id.startswith("CWE-"):
        next_calls.append(
            PivotHint(
                tool="cwe_lookup",
                input=cwe_id,
                reason=f"Weakness category for {cwe_id}: description, mitigations, parent/child chain.",
            )
        )

    return RiskScoreResponse(
        cve_id=cve_id,
        score=result.score,
        label=result.label,
        urgency=result.urgency,
        has_public_poc=has_poc,
        components=result.components,
        boosters_applied=result.boosters_applied,
        recommendation=result.recommendation,
        summary=summary,
        next_calls=next_calls,
    )


@router.get(
    "/cvss/details",
    operation_id="get_cvss_details",
    response_model=CvssDetailsResponse,
    response_model_exclude_none=True,
)
async def get_cvss_details(
    vector: Annotated[
        str,
        Query(
            max_length=500,
            description=(
                "CVSS v3.0 or v3.1 vector string, e.g. "
                "'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'. Real vectors are "
                "~80-150 chars; the 500-char cap is a defensive ceiling."
            ),
        ),
    ],
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/cve"))],
):
    """Parse a CVSS v3.x vector string into per-metric breakdown + recomputed base score.

    Use this to translate a raw vector (e.g. from a CVE record) into a
    human-readable / agent-friendly structure: attack_vector, attack_complexity,
    privileges_required, user_interaction, scope, and the three impact metrics
    (C/I/A). Also re-derives base_score and base_severity from the vector so
    callers can verify upstream NVD scoring.
    """
    safe_vector = sanitize_echo(vector)
    try:
        parsed = parse_cvss_vector(vector)
    except ValueError:
        # Don't echo the upstream `cvss` library exception message — it can
        # carry parser-internal context (CWE-209). Construct a fixed, safe
        # error string from the sanitized input instead.
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unrecognized or malformed CVSS v3 vector: '{safe_vector[:80]}'. "
                "Expected 'CVSS:3.0/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...' "
                "or the equivalent CVSS:3.1 form. v2 vectors are not supported."
            ),
        ) from None

    summary = (
        f"CVSS v{parsed['version']} {parsed['base_severity']} ({parsed['base_score']}). "
        f"AV={parsed['metrics']['attack_vector']}, "
        f"AC={parsed['metrics']['attack_complexity']}, "
        f"PR={parsed['metrics']['privileges_required']}, "
        f"UI={parsed['metrics']['user_interaction']}, "
        f"Scope={parsed['metrics']['scope']}."
    )

    return CvssDetailsResponse(
        version=parsed["version"],
        vector=parsed["vector"],
        base_score=parsed["base_score"],
        base_severity=parsed["base_severity"],
        metrics=parsed["metrics"],
        temporal_score=parsed["temporal_score"],
        environmental_score=parsed["environmental_score"],
        summary=f"{safe_vector[:80]} → {summary}" if safe_vector != parsed["vector"] else summary,
    )


def _cve_list_hint(count: int) -> SearchHint | None:
    """Build a global footer hint for CVE list responses (cve_search, cve_leading).

    Slim list items omit description / affected_products / references / cvss_breakdown
    to keep tokens low when agents paginate. The hint reminds the agent that
    cve_lookup on any returned cve_id surfaces the full detail plus exploit/KEV/CWE
    pivots — without per-item next_calls bloat (3 hints x 50 items would dominate
    the response). Suppressed when count==0 (nothing to drill into).
    """
    if count <= 0:
        return None
    return SearchHint(
        tool="cve_lookup",
        reason=(
            "Call cve_lookup with any cve_id above for full description, affected_products, "
            "references, and chained pivots (exploit_lookup, kev_detail, cwe_lookup)."
        ),
    )


def _cve_leading_pivot_hints(results: list[dict]) -> list[PivotHint]:
    """Top-5 iteration: cve_lookup + calculate_risk_score per item; +kev_detail when any KEV present."""
    if not results:
        return []
    hints: list[PivotHint] = []
    for item in results[:5]:
        cve_id = item.get("cve_id") or ""
        if not cve_id:
            continue
        hints.append(
            PivotHint(
                tool="cve_lookup",
                input=cve_id,
                reason="Full CVE record: CVSS, affected products, references, patch URLs.",
            )
        )
        hints.append(
            PivotHint(
                tool="calculate_risk_score",
                input=cve_id,
                reason="Composite risk score (CVSS+EPSS+KEV+PoC fusion) for triage prioritization.",
            )
        )
    kev_cve = next(
        (item.get("cve_id") for item in results if item.get("cve_id") and (item.get("kev") or {}).get("in_kev")),
        None,
    )
    if kev_cve:
        hints.append(
            PivotHint(
                tool="kev_detail",
                input=kev_cve,
                reason="CISA Known Exploited Vulnerabilities — federal patch deadline + required action.",
            )
        )
    return hints


def _bulk_cve_lookup_outer_hints(results: list[dict]) -> list[PivotHint]:
    """Outer envelope: exploit_lookup (any cvss_v3>=7.0) + kev_detail (any in_kev). Per-item hints in results[]."""
    if not results:
        return []
    hints: list[PivotHint] = []
    high_cve = next(
        (
            item.get("cve_id")
            for item in results
            if item.get("status") == "ok" and ((item.get("cve") or {}).get("cvss_v3") or 0) >= 7.0
        ),
        None,
    )
    if high_cve:
        hints.append(
            PivotHint(
                tool="exploit_lookup",
                input=high_cve,
                reason="Public exploits / PoC availability for high-severity CVEs in this batch.",
            )
        )
    kev_cve = next(
        (
            item.get("cve_id")
            for item in results
            if item.get("status") == "ok" and ((item.get("cve") or {}).get("kev") or {}).get("in_kev")
        ),
        None,
    )
    if kev_cve:
        hints.append(
            PivotHint(
                tool="kev_detail",
                input=kev_cve,
                reason="CISA Known Exploited Vulnerabilities — federal patch deadline + required action.",
            )
        )
    return hints


def _exploit_pivot_hints(cve_id: str) -> list[PivotHint]:
    """Build the suggested-next-call list for an exploit_lookup response.

    ExploitResponse carries no kev/cwe metadata, so we cannot conditionally emit
    kev_detail/cwe_lookup without risking 404 / missing-input wasted calls. Instead
    we surface a single pivot — cve_lookup — which itself emits kev_detail (when
    in_kev) and cwe_lookup (when cwe_id is present), so the chain stays full-fidelity
    without depending on schema fields exploit_lookup does not own.

    Defensively re-validates cve_id even though the route already does — keeps the
    helper safe to call from refactors / tests / future code paths that may not
    pass the route guard. Returns [] on invalid IDs rather than emitting a hint
    that would steer the agent to a guaranteed 400/404.
    """
    if not cve_id or not validate_cve_id(cve_id):
        return []
    return [
        PivotHint(
            tool="cve_lookup",
            input=cve_id,
            reason=(
                "Full CVE context: CVSS / EPSS / KEV status / CWE chain. cve_lookup's own "
                "next_calls then surfaces kev_detail (when in_kev) and cwe_lookup (when cwe_id is set)."
            ),
        ),
        PivotHint(
            tool="calculate_risk_score",
            input=cve_id,
            reason="Composite risk score (CVSS+EPSS+KEV+PoC fusion) for triage prioritization.",
        ),
    ]


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
        ),
        PivotHint(
            tool="calculate_risk_score",
            input=cve_id,
            reason="Composite risk score (CVSS+EPSS+KEV+PoC fusion) for triage prioritization.",
        ),
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
    cwes = record.get("cwes") or []
    if cwes:
        for cwe in cwes[:3]:
            if cwe and isinstance(cwe, str) and cwe.startswith("CWE-"):
                hints.append(
                    PivotHint(
                        tool="cwe_lookup",
                        input=cwe,
                        reason=f"Weakness category for {cwe}: description, mitigations, parent/child chain.",
                    )
                )
    else:
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
        PivotHint(
            tool="calculate_risk_score",
            input=cve_id,
            reason="Composite risk score (CVSS+EPSS+KEV+PoC fusion) for triage prioritization.",
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
async def kev_detail(
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
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/kev"))],
):
    """Look up CISA KEV (Known Exploited Vulnerabilities) full record for a CVE.

    Returns federal patch deadline (due_date), CISA-specified remediation
    (required_action), known ransomware association, vendor/product, common
    vulnerability name (e.g. 'Log4Shell'), and CISA-reported CWE list. 404 when
    the CVE is not in the KEV catalog; use cve_lookup for non-KEV CVEs.
    """
    cve_id = cve_id.strip().upper()
    _check_cve_input(cve_id)

    cache_key = f"kev:{cve_id}"
    cached = await aget_cached_domain(cache_key)
    if cached:
        cached["verdict"] = (
            await _cve_verdict(
                sources=["cisa_kev_cache"],
                completeness="complete",
                primary_source="kev",
            )
        ).model_dump()
        return cached

    record = await aget_kev_details(cve_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} is not in the CISA KEV catalog")

    record["next_calls"] = [h.model_dump() for h in _kev_pivot_hints(record)]
    await asave_cached_domain(cache_key, record)
    record["verdict"] = (
        await _cve_verdict(
            sources=["cisa_kev_cache"],
            completeness="complete",
            primary_source="kev",
        )
    ).model_dump()
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


def _format_cwe_slim(record: dict) -> dict:
    """Return a shallow copy of a CWE record with verbose fields capped.

    Drops extended_description; truncates mitigations to MAX_CWE_MITIGATIONS_DEFAULT
    and examples to MAX_CWE_EXAMPLES_DEFAULT. total_mitigations / total_examples are
    always emitted with honest pre-truncation counts so agents can decide whether to
    refetch with include=full.
    """
    out = dict(record)
    mitigations = out.get("mitigations") or []
    examples = out.get("examples") or []
    out["total_mitigations"] = len(mitigations)
    out["total_examples"] = len(examples)
    out.pop("extended_description", None)
    if len(mitigations) > MAX_CWE_MITIGATIONS_DEFAULT:
        out["mitigations"] = mitigations[:MAX_CWE_MITIGATIONS_DEFAULT]
    if len(examples) > MAX_CWE_EXAMPLES_DEFAULT:
        out["examples"] = examples[:MAX_CWE_EXAMPLES_DEFAULT]
    return out


@router.get(
    "/cwe/{cwe_id}",
    operation_id="cwe_lookup",
    response_model=CweLookupResponse,
    response_model_exclude_none=True,
)
async def cwe_lookup(
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
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/cwe"))],
    include: Annotated[
        str | None,
        Query(
            description=(
                f"Detail level. Default returns slim record (first {MAX_CWE_MITIGATIONS_DEFAULT} "
                f"mitigations, first {MAX_CWE_EXAMPLES_DEFAULT} examples, no extended_description). "
                "total_mitigations / total_examples are always honest pre-truncation counts. "
                "Pass include=full to restore extended_description and the full mitigations + examples lists."
            ),
        ),
    ] = None,
):
    """Look up a MITRE CWE (Common Weakness Enumeration) catalog record.

    Returns description, abstract type, status, likelihood of exploit, recommended
    mitigations, observed example CVEs, and parent/child weakness chain. Use this
    after cve_lookup or kev_detail to understand the underlying weakness category.
    """
    normalized = _normalize_cwe(cwe_id)

    if include not in (None, "", "full"):
        raise HTTPException(status_code=400, detail="include must be 'full' (omit for slim default)")

    cache_key = f"cwe:{normalized}:{'full' if include == 'full' else 'slim'}"
    cached = await aget_cached_domain(cache_key)
    if cached:
        cached["verdict"] = (
            await _cve_verdict(
                sources=["mitre_cwe_cache"],
                completeness="complete",
                primary_source="cwe",
            )
        ).model_dump()
        return cached

    record = await aget_cwe(normalized)
    if record is None:
        raise HTTPException(
            status_code=404, detail=f"{normalized} is not in the MITRE CWE catalog (research view 1000)"
        )

    cve_count = await acount_cves_for_cwe(normalized)
    record["cve_count"] = cve_count
    record["next_calls"] = [h.model_dump() for h in _cwe_pivot_hints(record, cve_count)]

    if include == "full":
        record["total_mitigations"] = len(record.get("mitigations") or [])
        record["total_examples"] = len(record.get("examples") or [])
        response = record
    else:
        response = _format_cwe_slim(record)
    await asave_cached_domain(cache_key, response)
    response["verdict"] = (
        await _cve_verdict(
            sources=["mitre_cwe_cache"],
            completeness="complete",
            primary_source="cwe",
        )
    ).model_dump()
    return response


@router.get("/cves", operation_id="cve_search", response_model=CveSearchResponse, response_model_exclude_none=True)
async def cve_search(
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/cves"))],
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
    tagged: bool = Query(
        False,
        description=(
            "Default False — only return CVEs where the queried product is the actually-vulnerable "
            "component (NVD CPE vulnerable=true). Set True to broaden: include CVEs where the product "
            "appears as a target dependency (target_hw / target_sw) — e.g. product=linux_kernel with "
            "tagged=true also returns CVEs in apps that run on Linux. Rows synced before v1.30.0 have "
            "vulnerable=NULL and are treated as vulnerable=true for back-compat."
        ),
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

    # Top-traffic tool (~1k calls/mo). Cache full response by query-tuple — same
    # filters return identical results until NVD sync runs (DOMAIN_CACHE_TTL=1h).
    # verdict is NEVER cached; it's rebuilt on every response so data_age_seconds
    # reflects current NVD sync, not write-time.
    # Key uses canonical JSON + sha256 (16 hex chars) so free-text product/vendor
    # cannot collide via delimiter injection.
    _key_payload = json.dumps(
        {
            "product": (product or "").lower(),
            "vendor": (vendor or "").lower(),
            "severity": (severity or "").upper(),
            "cwe_id": (cwe_id or "").upper(),
            "published_after": published_after or "",
            "published_before": published_before or "",
            "kev": bool(kev),
            "epss_min": epss_min,
            "cvss_min": cvss_min,
            "cvss_max": cvss_max,
            "sort": sort or "",
            "limit": limit,
            "offset": offset,
            "include": "full" if include == "full" else "slim",
            "tagged": bool(tagged),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    cache_key = "cve_search:" + hashlib.sha256(_key_payload.encode()).hexdigest()[:16]
    cached = await aget_cached_domain(cache_key)
    if cached:
        cached["verdict"] = (await _cve_verdict(sources=["nvd_cache"], completeness="complete")).model_dump()
        return cached

    results, total = await asearch_cves(
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
        tagged=tagged,
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
            "tagged": True if tagged else None,
        }.items()
        if v is not None and v != ""
    }
    full = include == "full"
    formatter = _format_cve if full else _format_cve_slim
    formatted_results = [await formatter(row) for row in results]
    next_offset = offset + count if truncated else None
    hint = _cve_list_hint(count)
    response = {
        "count": count,
        "total": total,
        "truncated": truncated,
        "offset": offset,
        "summary": summary,
        "results": formatted_results,
        "query_echo": query_echo,
        "next_offset": next_offset,
        "hint": hint.model_dump() if hint else None,
    }
    await asave_cached_domain(cache_key, response)
    response["verdict"] = (await _cve_verdict(sources=["nvd_cache"], completeness="complete")).model_dump()
    return response


_FALSIFIABLE_BASE = [
    "cve_id",
    "severity",
    "cvss_v3",
    "cvss_v2",
    "cvss_breakdown",
    "published",
    "modified",
    "references",
    "cwe_id",
    "cwes",
    "patch_url",
    "summary",
    "vulnerability_status",
    "cve_tags",
]


async def _cve_verdict(
    *,
    sources: list[str] | None = None,
    completeness: str = "complete",
    primary_source: str = "nvd",
    populated_fields: list[str] | None = None,
    has_references: bool | None = None,
    sources_unavailable: list[str] | None = None,
    vulnerability_status: str | None = None,
) -> Verdict:
    """Build a verdict metadata block for cve_lookup responses.

    primary_source picks the sync_status row used for data_age_seconds (kev for
    kev_detail, cwe for cwe_lookup, mitre for cve_leading). populated_fields and
    has_references let callers honestly downgrade falsifiable_fields/completeness
    when the underlying CVE has gaps. vulnerability_status downgrades completeness
    to 'partial' when NVD marked the CVE Rejected/Withdrawn/Awaiting Analysis."""
    last = await aget_last_successful_sync(primary_source)
    age: int | None = None
    if last:
        try:
            age = int((datetime.now(UTC) - datetime.fromisoformat(last)).total_seconds())
            if age < 0:
                age = None
        except ValueError:
            age = None
    if populated_fields is None:
        falsifiable_fields = ["cve_id", "severity", "cvss_v3", "published", "references"]
    else:
        populated_set = set(populated_fields)
        falsifiable_fields = [f for f in _FALSIFIABLE_BASE if f in populated_set]
        if "cve_id" not in falsifiable_fields:
            falsifiable_fields.insert(0, "cve_id")
    queried = ["nvd_cache"] if sources is None else sources
    final_completeness = completeness
    if final_completeness == "complete" and (not queried or has_references is False):
        final_completeness = "partial"
    if (vulnerability_status or "").lower() in ("rejected", "withdrawn", "awaiting analysis"):
        final_completeness = "partial"
    return Verdict(
        deterministic=True,
        falsifiable_fields=falsifiable_fields,
        data_age_seconds=age,
        sources_queried=queried,
        sources_unavailable=sources_unavailable or [],
        completeness=final_completeness,  # type: ignore[arg-type]
    )


def _cve_lookup_verdict_inputs(formatted: dict) -> tuple[list[str], str, list[str], bool, str | None]:
    """Derive (sources, completeness, populated_fields, has_references, vulnerability_status)
    for a formatted cve_lookup dict. Used on both cache miss and cache hit so
    verdict.data_age_seconds stays fresh without re-fetching the underlying row.
    populated_fields lists the BASE-eligible fields whose values are non-empty;
    has_references is True when the formatted dict has at least one reference;
    vulnerability_status threads NVD lifecycle status to completeness degrade."""
    is_minimal = not (formatted.get("severity") or formatted.get("cvss_v3") or formatted.get("description"))
    completeness = "minimal" if is_minimal else "complete"
    sources = [f"{s}_cache" for s in (formatted.get("sources") or [])]
    if not sources and not is_minimal:
        sources = ["nvd_cache"]
    populated_fields: list[str] = []
    for field in _FALSIFIABLE_BASE:
        value = formatted.get(field)
        if value is None or value == "" or value == [] or value == {}:
            continue
        populated_fields.append(field)
    has_references = bool(formatted.get("references"))
    vulnerability_status = formatted.get("vulnerability_status")
    return sources, completeness, populated_fields, has_references, vulnerability_status


async def _sync_age_seconds(source: str) -> int | None:
    """Return seconds since last successful sync for a source, or None."""
    last = await aget_last_successful_sync(source)
    if not last:
        return None
    try:
        age = int((datetime.now(UTC) - datetime.fromisoformat(last)).total_seconds())
        return age if age >= 0 else None
    except ValueError:
        return None


_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


def _severity_label_from_score(score: float) -> str | None:
    """CVSS score → bucket label. v3 thresholds applied to both v2 and v3 here for
    bucket-diff comparison; intentional simplification — the goal is detecting
    cross-version disagreement, not source-faithful labeling."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def _compute_severity_consensus(severity_sources: list[dict]) -> tuple[str | None, bool]:
    """Compute (consensus, disagreement) from severity_sources entries.

    Consensus: majority-bucket vote across severity labels; on a tie, highest
    severity wins (CRITICAL > HIGH > MEDIUM > LOW > NONE). Returns None when no
    source reported a severity label and no scores were comparable.

    Disagreement: True when 2+ distinct buckets appear — counts both across-source
    variance (NVD CRITICAL vs GHSA HIGH) and within-source v2-vs-v3 variance
    (cvss_v2=7.5 HIGH vs cvss_v3=5.5 MEDIUM on the same NVD entry)."""
    buckets: list[str] = []
    for entry in severity_sources or []:
        if not isinstance(entry, dict):
            continue
        sev = entry.get("severity")
        if isinstance(sev, str) and sev.upper() in _SEVERITY_RANK:
            buckets.append(sev.upper())
        cvss_v3 = entry.get("cvss_v3")
        cvss_v2 = entry.get("cvss_v2")
        if (
            isinstance(cvss_v3, (int, float))
            and not isinstance(cvss_v3, bool)
            and isinstance(cvss_v2, (int, float))
            and not isinstance(cvss_v2, bool)
        ):
            v3_bucket = _severity_label_from_score(cvss_v3)
            v2_bucket = _severity_label_from_score(cvss_v2)
            if v3_bucket and v2_bucket and v3_bucket != v2_bucket:
                buckets.extend([v3_bucket, v2_bucket])
    if not buckets:
        return None, False
    counts: dict[str, int] = {}
    for b in buckets:
        counts[b] = counts.get(b, 0) + 1
    max_count = max(counts.values())
    top_buckets = [b for b, c in counts.items() if c == max_count]
    consensus = max(top_buckets, key=lambda b: _SEVERITY_RANK.get(b, -1))
    disagreement = len(set(buckets)) > 1
    return consensus, disagreement


async def _exploit_lookup_verdict(github_error: bool, shodan_error: bool, offline_found: bool) -> Verdict:
    """Build a Verdict for exploit_lookup responses."""
    sources_queried = ["github_advisory", "shodan_cvedb", "exploitdb_csv"]
    unavailable = []
    if github_error:
        unavailable.append("github_advisory")
    if shodan_error:
        unavailable.append("shodan_cvedb")
    github_age = await _sync_age_seconds("github_advisory")
    shodan_age = await _sync_age_seconds("shodan_cvedb")
    exploitdb_meta_ts = await aget_exploitdb_synced_at()
    if exploitdb_meta_ts:
        try:
            exploitdb_age = int((datetime.now(UTC) - datetime.fromisoformat(exploitdb_meta_ts)).total_seconds())
            if exploitdb_age < 0:
                exploitdb_age = None
        except ValueError:
            exploitdb_age = await _sync_age_seconds("exploitdb")
    else:
        exploitdb_age = await _sync_age_seconds("exploitdb")
    if exploitdb_age is not None and exploitdb_age > 7 * 86400:
        unavailable.append("exploitdb_csv")
    ages = [a for a in (github_age, shodan_age, exploitdb_age) if a is not None]
    data_age = max(ages) if ages else None

    if not unavailable:
        completeness = "complete"
    elif offline_found:
        completeness = "partial"
    else:
        completeness = "minimal"

    return Verdict(
        deterministic=True,
        falsifiable_fields=["cve_id", "edb_id", "date_published", "url"],
        data_age_seconds=data_age,
        sources_queried=sources_queried,
        sources_unavailable=unavailable,
        completeness=completeness,  # type: ignore[arg-type]
    )


async def _exploit_verdict_for_response(result: dict, offline_truncated: bool) -> Verdict:
    """Build an exploit_lookup Verdict from a formatted result dict.
    Re-derives github_error / shodan_error / offline_found from the cached/just-built
    response so verdict.data_age_seconds stays fresh on cache hit."""
    sources_dict = result.get("sources") or {}
    github_error = (sources_dict.get("github") or {}).get("error") is not None
    shodan_error = (sources_dict.get("shodan_refs") or {}).get("error") is not None
    offline_found = len(result.get("exploits") or []) > 0
    verdict = await _exploit_lookup_verdict(
        github_error=github_error,
        shodan_error=shodan_error,
        offline_found=offline_found,
    )
    if offline_truncated and verdict.completeness == "complete":
        verdict.completeness = "partial"
    return verdict


async def _cve_leading_sources_unavailable() -> list[str]:
    """Mark mitre_cache / ghsa_cache as unavailable when the corresponding
    sync_status row is older than 7 days (matches _exploit_lookup_verdict pattern)."""
    unavailable: list[str] = []
    mitre_age = await _sync_age_seconds("mitre")
    ghsa_age = await _sync_age_seconds("ghsa")
    if mitre_age is not None and mitre_age > 7 * 86400:
        unavailable.append("mitre_cache")
    if ghsa_age is not None and ghsa_age > 7 * 86400:
        unavailable.append("ghsa_cache")
    return unavailable


async def _format_cve(
    row: dict,
    include_enrichment: bool = False,
    include_full_products: bool = False,
    include_full_references: bool = False,
    include_reference_tags: bool = False,
    include_severity_breakdown: bool = False,
) -> dict:
    """Format a raw CVE db row into API response format.

    When include_enrichment=True (single-CVE lookup only), adds patch_available,
    patch_url, and related_cves. related_cves uses affected_products[0] only —
    multi-product CVEs are not UNIONed (simpler, 95% sufficient). Enrichment is
    gated off by default to avoid N+1 queries in search/bulk call sites.

    affected_products is truncated to the first MAX_AFFECTED_PRODUCTS_DEFAULT
    entries by default (Log4j-class CVEs can carry 50+ Siemens products and bloat
    MCP responses). total_products always reflects the honest full count. Pass
    include_full_products=True to return the complete list.

    references is truncated to the first MAX_REFERENCES_DEFAULT entries by default
    (older + high-profile CVEs accumulate 30-60+ advisory URLs and agents only need
    a handful for triage). total_references is the honest full count. Pass
    include_full_references=True to return the complete list. Patch URL detection
    runs against the FULL list before truncation, so the patch_url field is never
    missed because of the cap.

    Naming: the internal flag is `include_full_products` (emphasis: return all of
    them); the public API param in cve_lookup / _BulkCveRequest is
    `include_affected_products` (emphasis: the field being expanded). Keep the
    divergence — it matches how each audience reads the contract. Same for
    references.

    related_cves uses the RAW DB `row.get("affected_products")` regardless of
    truncation, so enrichment is O(1) and never missed because of the cap.
    """
    sources_rows = await aget_cve_sources(row["cve_id"])
    source_names = [s["source"] for s in sources_rows]
    all_references = row.get("refs", []) or []
    total_references = len(all_references)
    references = all_references if include_full_references else all_references[:MAX_REFERENCES_DEFAULT]
    all_products = row.get("affected_products", []) or []
    total_products = len(all_products)
    products = all_products if include_full_products else all_products[:MAX_AFFECTED_PRODUCTS_DEFAULT]
    kev_nested = await _build_kev_block(row)
    result = {
        "cve_id": row["cve_id"],
        "summary": row.get("summary") or _generate_summary(row),
        "description": row.get("description"),
        "severity": row.get("severity"),
        "cvss_v3": row.get("cvss_v3"),
        "cvss_v2": row.get("cvss_v2"),
        "cvss_v2_vector": row.get("cvss_v2_vector"),
        "cvss_breakdown": _parse_cvss_vector(row.get("cvss_vector")),
        "cwe_id": row.get("cwe_id"),
        "cwes": row.get("cwes"),
        "vulnerability_status": row.get("vulnerability_status"),
        "cve_tags": row.get("cve_tags"),
        "epss": {
            "score": row.get("epss_score"),
            "percentile": row.get("epss_percentile"),
        },
        "kev": kev_nested,
        "affected_products": products,
        "total_products": total_products,
        "published": row.get("published"),
        "modified": row.get("modified"),
        "references": references,
        "total_references": total_references,
        "total_references_unique": (len(row["refs_with_tags"]) if row.get("refs_with_tags") is not None else None),
        "references_full": (
            (row["refs_with_tags"] if include_full_references else row["refs_with_tags"][:MAX_REFERENCES_DEFAULT])
            if include_reference_tags and row.get("refs_with_tags") is not None
            else None
        ),
        "sources": source_names,
        "first_seen_source": source_names[0] if source_names else None,
        "first_seen_at": sources_rows[0]["first_seen_at"] if sources_rows else None,
    }
    if include_severity_breakdown and row.get("severity_sources") is not None:
        sev_sources = row["severity_sources"]
        result["severity_sources"] = sev_sources
        consensus, disagreement = _compute_severity_consensus(sev_sources)
        result["severity_consensus"] = consensus
        result["severity_disagreement"] = disagreement
    if include_enrichment:
        patch_available, patch_url = _extract_patch_url(row.get("refs_with_tags"), all_references)
        if not patch_available and _describes_patch(row.get("description")):
            patch_available = True
        result["patch_available"] = patch_available
        result["patch_url"] = patch_url
        affected = row.get("affected_products") or []
        if affected and (first := affected[0]).get("product"):
            result["related_cves"] = await aget_related_cves_by_product(
                product=first["product"],
                vendor=first.get("vendor"),
                limit=5,
                exclude_cve_id=row["cve_id"],
            )
        else:
            result["related_cves"] = []
    return result


async def _build_kev_block(row: dict) -> dict:
    """Build the nested KEV block emitted by cve_lookup AND cve_search items.

    When in_kev=False: returns {"in_kev": False} (date_added is None and gets
    excluded by response_model_exclude_none — keeps the slim shape one-field).
    When in_kev=True: enriches with the full kev_details record so agents can
    triage in one round-trip without a follow-up kev_detail call (B3 v1.30.0).
    """
    block: dict = {
        "in_kev": bool(row.get("in_kev")),
        "date_added": row.get("kev_date_added"),
    }
    if row.get("in_kev"):
        kev_full = await aget_kev_details(row["cve_id"])
        if kev_full is not None:
            block.update(
                {
                    "due_date": kev_full.get("due_date"),
                    "required_action": kev_full.get("required_action"),
                    "known_ransomware_use": kev_full.get("known_ransomware_use"),
                    "vendor_project": kev_full.get("vendor_project"),
                    "product": kev_full.get("product"),
                    "vulnerability_name": kev_full.get("vulnerability_name"),
                    "short_description": kev_full.get("short_description"),
                    "notes": kev_full.get("notes"),
                    "cwes": kev_full.get("cwes"),
                    "date_removed": kev_full.get("date_removed"),
                }
            )
    return block


async def _format_cve_slim(row: dict) -> dict:
    """Slim formatter for cve_search list items.

    Drops description, cvss_breakdown, affected_products, references, first_seen_source,
    first_seen_at vs _format_cve(). Keeps fields agents need to triage and pivot:
    cve_id, summary, severity, cvss_v3, cwe_id, cwes, epss, kev, total_products,
    references_count, published, modified, sources. ~70% token reduction vs full payload
    on Log4j-class CVEs. Use cve_lookup or cve_search?include=full for drill-down.

    references_count (B2 v1.30.0) is the honest count of upstream refs, so agents can
    decide whether a cve_lookup chain is worthwhile without paying the per-item ref-list
    payload tax. cwes (multi) mirrors v1.28.0 cve_lookup; cwe_id legacy preserved.
    kev block expands to the full CISA record when in_kev=True (B3 v1.30.0); collapses
    to {"in_kev": False} otherwise (response_model_exclude_none drops null fields).
    """
    sources_rows = await aget_cve_sources(row["cve_id"])
    source_names = [s["source"] for s in sources_rows]
    all_products = row.get("affected_products", []) or []
    return {
        "cve_id": row["cve_id"],
        "summary": row.get("summary") or _generate_summary(row),
        "severity": row.get("severity"),
        "cvss_v3": row.get("cvss_v3"),
        "cwe_id": row.get("cwe_id"),
        "cwes": row.get("cwes"),
        "epss": {
            "score": row.get("epss_score"),
            "percentile": row.get("epss_percentile"),
        },
        "kev": await _build_kev_block(row),
        "total_products": len(all_products),
        "references_count": len(row.get("refs", []) or []),
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
    """Auto-generate a one-line summary from structured fields.

    Batch 5: switched from desc[:120] truncation to first-sentence regex extraction
    so NVD's NOTE/duplicate sentences are preserved intact. When cve_tags contains
    'disputed', the summary is prefixed with [DISPUTED]."""
    parts = []
    cve_tags = row.get("cve_tags") or []
    if any((t or "").lower() == "disputed" for t in cve_tags):
        parts.append("[DISPUTED]")

    severity = row.get("severity")
    if severity:
        parts.append(f"{severity}")

    cwe = row.get("cwe_id")
    if cwe:
        parts.append(f"({cwe})")

    desc = row.get("description") or ""
    if desc:
        m = re.match(r"^([^.!?]+[.!?])", desc.strip())
        sentence = m.group(1).strip() if m else (desc[:200].rsplit(" ", 1)[0] if len(desc) > 200 else desc)
        parts.append(f"— {sentence}")

    cvss = row.get("cvss_v3")
    if cvss:
        parts.append(f"CVSS {cvss}.")

    if row.get("in_kev"):
        parts.append("Actively exploited (CISA KEV).")

    epss = row.get("epss_score")
    if epss is not None:
        parts.append(f"EPSS {epss:.0%} exploitation probability.")

    return " ".join(parts) if parts else row.get("cve_id", "")


async def _search_github_advisories(cve_id: str) -> dict:
    """Search GitHub Advisory Database for advisories related to a CVE."""
    try:
        resp = await _exploit_client.get(
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


_EDB_URL_RE = re.compile(r"exploit-db\.com/exploits/(\d+)", re.IGNORECASE)


def _shodan_edb_ids(shodan_refs: dict) -> set[str]:
    """Extract EDB-IDs from Shodan CVEDB reference URLs (description field carries the URL)."""
    ids: set[str] = set()
    for ref in shodan_refs.get("results", []) or []:
        if not isinstance(ref, dict):
            continue
        url = ref.get("description")
        if not isinstance(url, str):
            continue
        m = _EDB_URL_RE.search(url)
        if m:
            ids.add(m.group(1))
    return ids


async def _search_shodan_refs(cve_id: str) -> dict:
    """Fetch Shodan CVEDB references for a CVE (NOT ExploitDB — those come from the offline CSV)."""
    try:
        # cve_id is enforced to match ^CVE-\d{4}-\d{4,7}$ via _check_cve_input() at every caller —
        # only digits and hyphens, no URL-special chars, so the host segment cannot be manipulated.
        resp = await _exploit_client.get(
            f"https://cvedb.shodan.io/cve/{cve_id}",
        )
        if resp.status_code == 404:
            return {"found": False, "count": 0, "truncated": False, "results": []}
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            data = {}
        refs = data.get("references", [])
        if not isinstance(refs, list):
            refs = []
        cap = settings.shodan_refs_limit
        total = len(refs)
        results = []
        for url in refs[:cap]:
            results.append(
                {
                    "id": cve_id,
                    "description": url if isinstance(url, str) else str(url),
                    "source": "cvedb.shodan.io",
                }
            )
        return {"found": total > 0, "count": total, "truncated": total > cap, "results": results}
    except httpx.TimeoutException:
        logger.warning("Shodan CVEDB search timed out")
        return {"found": False, "count": 0, "truncated": False, "results": [], "error": "upstream timeout"}
    except httpx.HTTPStatusError as e:
        logger.warning("Shodan CVEDB search failed: HTTP %d", e.response.status_code)
        return {"found": False, "count": 0, "truncated": False, "results": [], "error": "upstream error"}
    except Exception as e:
        logger.warning("Shodan CVEDB search failed: %s", type(e).__name__)
        return {"found": False, "count": 0, "truncated": False, "results": [], "error": "upstream error"}


@router.get(
    "/exploit/{cve_id}", operation_id="exploit_lookup", response_model=ExploitResponse, response_model_exclude_none=True
)
async def exploit_lookup(
    cve_id: Annotated[
        str,
        Path(
            description=(
                "CVE identifier 'CVE-YYYY-NNNN+' (case-insensitive; normalized to upper-case server-side). "
                "Example: 'CVE-2021-44228'."
            ),
        ),
    ],
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/exploit"))],
):
    """Search for public exploits and advisories related to a CVE."""
    cve_id = cve_id.strip().upper()
    _check_cve_input(cve_id)

    # Check cache. verdict is NEVER cached — rebuilt on every response so
    # data_age_seconds reflects current ExploitDB sync, not write-time.
    # _offline_truncated is stashed inside the cached payload so the
    # "completeness=partial" override can be re-applied on hot reads.
    cache_key = f"exploit:{cve_id}"
    cached = await aget_cached_domain(cache_key)
    if cached:
        cached_truncated = bool(cached.pop("_offline_truncated", False))
        cached["verdict"] = (await _exploit_verdict_for_response(cached, cached_truncated)).model_dump()
        return cached

    # GitHub Advisory + Shodan CVEDB are independent HTTP fan-outs; run in parallel.
    # Local SQLite (asearch_exploits_by_cve) stays on the event loop via threadpool wrapper.
    import asyncio

    github, shodan_refs, (offline, offline_truncated) = await asyncio.gather(
        _search_github_advisories(cve_id),
        _search_shodan_refs(cve_id),
        asearch_exploits_by_cve(cve_id),
    )

    # EDB-ID dedup: ExploitDB CSV mirror and Shodan CVEDB sometimes list the same exploit
    # twice (Shodan refs include exploit-db.com URLs). Strip overlap from Shodan count.
    offline_edb_ids = {str(row["edb_id"]) for row in offline if row.get("edb_id") is not None}
    shodan_edb_overlap = offline_edb_ids & _shodan_edb_ids(shodan_refs)
    if len(shodan_edb_overlap) > shodan_refs["count"]:
        logger.warning(
            "EDB dedup overlap exceeds Shodan count for %s: overlap=%d shodan_count=%d",
            cve_id,
            len(shodan_edb_overlap),
            shodan_refs["count"],
        )
    shodan_unique_count = max(0, shodan_refs["count"] - len(shodan_edb_overlap))

    exploits_found = len(offline) + github["count"] + shodan_unique_count
    has_public_exploit = len(offline) > 0 or github["found"] or shodan_refs["found"]

    # Build summary
    parts = []
    if github["found"]:
        parts.append(f"{github['count']} GitHub advisory(ies)")
    if shodan_refs["found"] and shodan_unique_count > 0:
        parts.append(f"{shodan_unique_count} Shodan reference(s)")
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

    result = {
        "cve_id": cve_id,
        "exploits_found": exploits_found,
        "sources": {"github": github, "shodan_refs": shodan_refs},
        "has_public_exploit": has_public_exploit,
        "exploits": [e.model_dump() for e in structured_exploits],
        "summary": summary,
        "next_calls": [h.model_dump() for h in _exploit_pivot_hints(cve_id)],
        "_offline_truncated": offline_truncated,
    }

    await asave_cached_domain(cache_key, result)
    result.pop("_offline_truncated", None)
    result["verdict"] = (await _exploit_verdict_for_response(result, offline_truncated)).model_dump()
    return result


# === Bulk CVE Lookup ===


class _BulkCveRequest(BaseModel):
    cve_ids: list[Annotated[str, StringConstraints(max_length=64)]] = Field(
        default_factory=list,
        max_length=50,
        description=(
            "List of CVE identifiers in canonical form 'CVE-YYYY-NNNN+' (case-insensitive; "
            "normalized to upper-case + de-duplicated server-side). Each CVE counts as 1 "
            "request toward the rate limit; ids beyond the caller's remaining hourly quota "
            "land in `skipped_due_to_rate_limit`. Max 50 ids per call (Pydantic input cap). "
            "Empty list returns 200 + empty results (parity with bulk_atlas + bulk_ioc)."
        ),
    )
    include_affected_products: bool = Field(
        False,
        description="Return full affected_products list for each CVE (default: first 20).",
    )
    include_full_references: bool = Field(
        False,
        description="Return full references list for each CVE (default: first 10). total_references is always emitted.",
    )
    include_reference_tags: bool = Field(
        False,
        description="Return structured references_full per CVE in batch [{url, tags, source}]. Same shape as cve_lookup. Default False (backward compat).",
    )
    include_severity_breakdown: bool = Field(
        False,
        description="Return severity_sources/consensus/disagreement per CVE in batch. Same shape as cve_lookup. Default False (backward compat). cvss_v2 / cvss_v2_vector are always emitted (additive non-opt-in).",
    )


@router.post(
    "/cves/bulk",
    operation_id="bulk_cve_lookup",
    response_model=BulkCveResponse,
    response_model_exclude_none=True,
)
async def bulk_cve_lookup(
    body: _BulkCveRequest,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/cves/bulk"))],
):
    """Bulk CVE lookup — up to 50 CVEs per call (Pydantic input cap). Each CVE consumes 1 unit
    of the per-hour quota; ids beyond the caller's remaining quota land in
    `skipped_due_to_rate_limit` instead of failing the whole batch (v1.27 dynamic budget)."""
    import ratelimit
    from config import FREE_HOURLY_LIMIT, PRO_HOURLY_LIMIT

    cve_ids = list(dict.fromkeys(c.strip().upper() for c in body.cve_ids if c.strip()))
    count = len(cve_ids)

    if count == 0:
        # v1.21.0 parity with bulk_atlas_technique_lookup + bulk_ioc_lookup: empty list → 200 +
        # empty results (not 400). Consistent with the "all bulk endpoints behave identically
        # on edge cases" contract; caller already paid 1 quota via require_auth.
        return {
            "results": [],
            "total": 0,
            "processed": 0,
            "skipped_due_to_rate_limit": [],
            "successful": 0,
            "failed": 0,
            "timed_out": 0,
            "partial": False,
            "summary": "0/0 CVEs found",
            "next_calls": None,
        }

    if auth.tier == "pro":
        store_key = f"pro:{auth.key_hash}"
        limit = PRO_HOURLY_LIMIT
    else:
        store_key = f"free:{hash_client_ip(auth.client_ip)}"
        limit = FREE_HOURLY_LIMIT

    available_budget = auth.ratelimit_remaining + 1
    processable = min(count, available_budget)
    extra = processable - 1

    if extra > 0 and not await ratelimit.aconsume_bulk("api", store_key, extra, limit):
        # Race: another worker drained quota between require_auth and here.
        # Fall back to processing only the unit require_auth already paid for.
        processable = 1

    skipped_ids = [sanitize_echo(s) for s in cve_ids[processable:]]
    cve_ids = cve_ids[:processable]

    results = []
    successful = 0
    for cid in cve_ids:
        if not validate_cve_id(cid):
            safe_cid = sanitize_echo(cid)
            results.append(
                {
                    "cve_id": safe_cid,
                    "status": "invalid_format",
                    "cve": None,
                    "error": f"Invalid CVE ID format: {safe_cid}",
                }
            )
            continue
        try:
            row = await aget_cve(cid)
            if row is None:
                # cid is regex-validated here, but sanitize defensively for echo
                safe_cid = sanitize_echo(cid)
                results.append(
                    {"cve_id": safe_cid, "status": "not_found", "cve": None, "error": f"CVE {safe_cid} not found"}
                )
            else:
                formatted = await _format_cve(
                    row,
                    include_enrichment=True,
                    include_full_products=body.include_affected_products,
                    include_full_references=body.include_full_references,
                    include_reference_tags=body.include_reference_tags,
                    include_severity_breakdown=body.include_severity_breakdown,
                )
                sources_for_verdict, bulk_completeness, bulk_populated, bulk_has_refs, bulk_vuln_status = (
                    _cve_lookup_verdict_inputs(formatted)
                )
                formatted["verdict"] = (
                    await _cve_verdict(
                        sources=sources_for_verdict,
                        completeness=bulk_completeness,
                        populated_fields=bulk_populated,
                        has_references=bulk_has_refs,
                        vulnerability_status=bulk_vuln_status,
                    )
                ).model_dump()
                formatted["next_calls"] = [h.model_dump() for h in _cve_pivot_hints(formatted)]
                results.append({"cve_id": cid, "status": "ok", "cve": formatted, "error": None})
                successful += 1
        except Exception as e:
            logger.warning("Bulk CVE lookup failed: %s", type(e).__name__)
            results.append({"cve_id": cid, "status": "error", "cve": None, "error": "Lookup failed"})

    processed = len(cve_ids)
    skipped_count = len(skipped_ids)
    total = processed + skipped_count
    failed = processed - successful
    partial = failed > 0 or skipped_count > 0

    if failed == 0 and skipped_count == 0:
        summary = f"All {total} CVEs found"
    elif successful == 0:
        summary = f"No CVEs found in {processed} lookups"
    else:
        summary = f"{successful}/{total} CVEs found, {failed} invalid, not found or failed"

    outer_hints = _bulk_cve_lookup_outer_hints(results)
    return {
        "results": results,
        "total": total,
        "processed": processed,
        "skipped_due_to_rate_limit": skipped_ids,
        "successful": successful,
        "failed": failed,
        "timed_out": 0,
        "partial": partial,
        "summary": summary,
        "next_calls": [h.model_dump() for h in outer_hints] if outer_hints else None,
    }
