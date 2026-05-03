"""MITRE ATLAS API routes — /v1/atlas/* (AI/ML attack catalog).

Static catalog endpoints sourced from the synced ATLAS YAML. All credit-cost = 1
(default). Free tier: no API key required.

Route order is significant: `/techniques`, `/case-studies`, and `/case-studies/{id}`
are registered BEFORE the catch-all `/{technique_id}` — otherwise FastAPI would
treat 'techniques' as a path parameter value.
"""

import logging
import re
from typing import Annotated

from atlas.schemas import (
    AtlasCaseStudyResponse,
    AtlasCaseStudySearchResponse,
    AtlasTechniqueResponse,
    AtlasTechniqueSearchResponse,
    BulkAtlasTechniqueResponse,
)
from auth import AuthCtx, require_auth
from db import (
    aget_atlas_case_study,
    aget_atlas_technique,
    asearch_atlas_case_studies,
    asearch_atlas_techniques,
)
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field
from schemas import PivotHint

logger = logging.getLogger("contrastapi")

router = APIRouter(prefix="/atlas", tags=["MITRE ATLAS"])

_TECHNIQUE_RE = re.compile(r"^AML\.T\d{4}(?:\.\d{3})?$")
_CASE_STUDY_RE = re.compile(r"^AML\.CS\d{4}$")
_TACTIC_RE = re.compile(r"^AML\.TA\d{4}$")

_PIVOT_CAP = 5
_SEARCH_DESCRIPTION_PREVIEW = 240  # chars; full text via _lookup drill or include=full


async def _inherit_tactics_from_parent(record: dict, _cache: dict | None = None) -> dict:
    """Backfill `tactics` from the parent technique when this is a sub-technique with empty tactics.

    ATLAS upstream does not propagate tactics down to sub-techniques (e.g. AML.T0051.002
    has tactics:[] while parent AML.T0051 carries ['AML.TA0005']). We fill from the parent
    and flag with `inherited_tactics=True` so callers can distinguish source.

    `_cache` is an optional per-call dict keyed by parent_id so repeat lookups within
    a single search response do only one DB hit per parent.
    """
    if record.get("tactics"):
        return record
    parent_id = record.get("subtechnique_of")
    if not parent_id:
        return record
    if _cache is not None and parent_id in _cache:
        parent = _cache[parent_id]
    else:
        parent = await aget_atlas_technique(parent_id)
        if _cache is not None:
            _cache[parent_id] = parent
    if not parent:
        return record
    parent_tactics = parent.get("tactics") or []
    if parent_tactics:
        record["tactics"] = list(parent_tactics)
        record["inherited_tactics"] = True
    return record


def _validate_technique_id(value: str) -> str:
    v = value.strip().upper()
    if not _TECHNIQUE_RE.match(v):
        raise HTTPException(
            status_code=400,
            detail="technique_id must match 'AML.T####' or 'AML.T####.###' (e.g. AML.T0000, AML.T0000.000)",
        )
    return v


def _validate_case_study_id(value: str) -> str:
    v = value.strip().upper()
    if not _CASE_STUDY_RE.match(v):
        raise HTTPException(
            status_code=400,
            detail="case_study_id must match 'AML.CS####' (e.g. AML.CS0000)",
        )
    return v


def _atlas_technique_pivot_hints(record: dict) -> list[PivotHint]:
    hints: list[PivotHint] = []
    technique_id = record.get("technique_id")
    if technique_id:
        hints.append(
            PivotHint(
                tool="atlas_case_study_search",
                input=technique_id,
                reason="Find real-world AI/ML incidents that used this technique.",
            )
        )
    attack_id = record.get("attack_reference_id")
    if attack_id:
        hints.append(
            PivotHint(
                tool="d3fend_defense_for_attack",
                input=attack_id,
                reason="Bridge: this ATLAS technique mirrors an ATT&CK TTP — surface D3FEND mitigations.",
            )
        )
    parent = record.get("subtechnique_of")
    if parent:
        hints.append(
            PivotHint(
                tool="atlas_technique_lookup",
                input=parent,
                reason="Look up the parent technique for broader context.",
            )
        )
    tactics = record.get("tactics") or []
    if tactics and technique_id:
        hints.append(
            PivotHint(
                tool="atlas_technique_search",
                input=tactics[0],
                reason=f"Find sibling techniques in the same ATLAS tactic ({tactics[0]}), excluding self.",
                params={"exclude_id": technique_id},
            )
        )
    return hints[:_PIVOT_CAP]


def _atlas_case_study_pivot_hints(record: dict) -> list[PivotHint]:
    techniques = record.get("techniques_used") or []
    if not techniques:
        return []
    # v1.20.0: collapse N atlas_technique_lookup hints (~700 bytes for 5) into a single
    # bulk_atlas_technique_lookup hint that drills into ALL techniques in one call.
    # The full list lives in techniques_used so the agent has the array it needs.
    return [
        PivotHint(
            tool="bulk_atlas_technique_lookup",
            input=",".join(techniques),
            reason=(
                f"Drill into all {len(techniques)} ATLAS technique(s) used in this incident in a "
                "single call. The full id list is in techniques_used."
            ),
        )
    ]


# --- Search routes (registered before catch-all) ---


@router.get(
    "/techniques",
    operation_id="atlas_technique_search",
    response_model=AtlasTechniqueSearchResponse,
    response_model_exclude_none=True,
)
async def atlas_technique_search(
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/atlas/techniques"))],
    keyword: Annotated[
        str | None,
        Query(
            min_length=2,
            max_length=100,
            description="Substring match against technique name + description (case-insensitive).",
        ),
    ] = None,
    tactic: Annotated[
        str | None,
        Query(
            description="Filter by ATLAS tactic id, e.g. 'AML.TA0002' (Reconnaissance). Format 'AML.TA####'.",
        ),
    ] = None,
    maturity: Annotated[
        str | None,
        Query(
            description="Filter by maturity: 'demonstrated' (observed in real attacks) or 'feasible' (theoretical).",
        ),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=200, description="Max results to return.")] = 50,
    include: Annotated[
        str | None,
        Query(
            description=(
                f"Detail level. Default returns slim records (description truncated to "
                f"{_SEARCH_DESCRIPTION_PREVIEW} chars; drill via atlas_technique_lookup for full text). "
                "Pass include=full for the verbose description on every row — large catalogs "
                "(167 techniques) can return ~100KB at full."
            ),
        ),
    ] = None,
    exclude_id: Annotated[
        str | None,
        Query(
            description=(
                "Optional ATLAS technique id to exclude from the results, format 'AML.T####' or "
                "'AML.T####.###'. Useful when paired with a tactic filter to fetch siblings without "
                "the originating technique itself (e.g. when atlas_technique_lookup's next_calls hint "
                "leads here)."
            ),
        ),
    ] = None,
):
    """Search the MITRE ATLAS technique catalog by keyword, tactic, or maturity.

    Use this to discover AI/ML attack techniques relevant to a given threat
    model. Drill into atlas_technique_lookup with the returned technique_id for
    full description, ATT&CK bridge, and next_calls pivot hints.
    """
    if include not in (None, "", "full"):
        raise HTTPException(status_code=400, detail="include must be 'full' (omit for slim default)")
    if exclude_id is not None:
        exclude_id = exclude_id.strip().upper()
        if exclude_id and not _TECHNIQUE_RE.match(exclude_id):
            raise HTTPException(
                status_code=400,
                detail="exclude_id must match 'AML.T####' or 'AML.T####.###'",
            )

    if keyword is not None:
        stripped = keyword.strip()
        if len(stripped) < 2:
            raise HTTPException(
                status_code=400,
                detail="keyword must be at least 2 non-whitespace characters",
            )
        keyword = stripped

    if tactic is not None:
        tactic = tactic.strip().upper()
        if tactic and not _TACTIC_RE.match(tactic):
            raise HTTPException(
                status_code=400,
                detail="tactic must match 'AML.TA####' (e.g. AML.TA0002)",
            )
    if maturity is not None:
        maturity = maturity.strip().lower()
        if maturity and maturity not in ("demonstrated", "feasible", "realized"):
            raise HTTPException(
                status_code=400,
                detail="maturity must be 'demonstrated', 'feasible', or 'realized'",
            )

    rows = await asearch_atlas_techniques(
        keyword=keyword,
        tactic=tactic or None,
        maturity=maturity or None,
        limit=limit,
    )

    if exclude_id:
        rows = [r for r in rows if r.get("technique_id") != exclude_id]

    parent_cache: dict = {}
    for r in rows:
        await _inherit_tactics_from_parent(r, _cache=parent_cache)

    if include != "full":
        for r in rows:
            desc = r.get("description")
            if desc and len(desc) > _SEARCH_DESCRIPTION_PREVIEW:
                r["description"] = desc[:_SEARCH_DESCRIPTION_PREVIEW] + "..."

    next_calls: list[PivotHint] | None = None
    if rows:
        next_calls = [
            PivotHint(
                tool="atlas_technique_lookup",
                input=rows[0]["technique_id"],
                reason="Drill into the top hit for full description + ATT&CK bridge.",
            )
        ]

    return {
        "query": {"keyword": keyword, "tactic": tactic, "maturity": maturity},
        "total": len(rows),
        "results": rows,
        "next_calls": next_calls,
    }


@router.get(
    "/case-studies",
    operation_id="atlas_case_study_search",
    response_model=AtlasCaseStudySearchResponse,
    response_model_exclude_none=True,
)
async def atlas_case_study_search(
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/atlas/case-studies"))],
    keyword: Annotated[
        str | None,
        Query(
            min_length=2,
            max_length=100,
            description="Substring match against case study name + description (case-insensitive).",
        ),
    ] = None,
    technique_id: Annotated[
        str | None,
        Query(
            description="Filter to case studies that include this ATLAS technique id, e.g. 'AML.T0000'.",
        ),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=200, description="Max results to return.")] = 50,
    include: Annotated[
        str | None,
        Query(
            description=(
                f"Detail level. Default returns slim records (description truncated to "
                f"{_SEARCH_DESCRIPTION_PREVIEW} chars). Pass include=full for the verbose "
                "summary on every row."
            ),
        ),
    ] = None,
):
    """Search ATLAS case studies by keyword or referenced technique.

    Useful when you've already identified a technique and want to see real-world
    incidents that exercised it. Returns slim records; drill via
    atlas_case_study_lookup for the full procedure list.
    """
    if include not in (None, "", "full"):
        raise HTTPException(status_code=400, detail="include must be 'full' (omit for slim default)")

    if keyword is not None:
        stripped = keyword.strip()
        if len(stripped) < 2:
            raise HTTPException(
                status_code=400,
                detail="keyword must be at least 2 non-whitespace characters",
            )
        keyword = stripped

    if technique_id is not None:
        technique_id = technique_id.strip().upper()
        if technique_id and not _TECHNIQUE_RE.match(technique_id):
            raise HTTPException(
                status_code=400,
                detail="technique_id must match 'AML.T####' or 'AML.T####.###'",
            )

    rows = await asearch_atlas_case_studies(
        keyword=keyword,
        technique_id=technique_id or None,
        limit=limit,
    )

    if include != "full":
        for r in rows:
            desc = r.get("description")
            if desc and len(desc) > _SEARCH_DESCRIPTION_PREVIEW:
                r["description"] = desc[:_SEARCH_DESCRIPTION_PREVIEW] + "..."

    next_calls: list[PivotHint] | None = None
    if rows:
        next_calls = [
            PivotHint(
                tool="atlas_case_study_lookup",
                input=rows[0]["case_study_id"],
                reason="Drill into the top hit for the full procedure + technique chain.",
            )
        ]

    return {
        "query": {"keyword": keyword, "technique_id": technique_id},
        "total": len(rows),
        "results": rows,
        "next_calls": next_calls,
    }


@router.get(
    "/case-studies/{case_study_id}",
    operation_id="atlas_case_study_lookup",
    response_model=AtlasCaseStudyResponse,
    response_model_exclude_none=True,
)
async def atlas_case_study_lookup(
    case_study_id: Annotated[
        str,
        Path(
            description=(
                "Canonical ATLAS case study id matching 'AML.CS####', e.g. 'AML.CS0000'. "
                "Returns 404 when the id is not in the synced catalog."
            ),
        ),
    ],
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/atlas/case-studies"))],
    include: Annotated[
        str | None,
        Query(
            description=(
                f"Detail level. Default returns slim (description truncated to "
                f"{_SEARCH_DESCRIPTION_PREVIEW} chars). Pass include=full for the verbose "
                "incident summary; case-study descriptions can run 1-3KB."
            ),
        ),
    ] = None,
):
    """Look up a MITRE ATLAS case study — a real-world AI/ML attack incident.

    Each case study links a sequence of ATLAS techniques (techniques_used) to a
    documented incident. Use atlas_technique_lookup on each id (or
    bulk_atlas_technique_lookup for the whole list) to expand into
    technique-level detail.

    Default response is SLIM (description truncated). Pass include=full for
    the verbose narrative.
    """
    normalized = _validate_case_study_id(case_study_id)
    if include not in (None, "", "full"):
        raise HTTPException(status_code=400, detail="include must be 'full' (omit for slim default)")

    record = await aget_atlas_case_study(normalized)
    if record is None:
        raise HTTPException(status_code=404, detail=f"{normalized} is not in the MITRE ATLAS case study catalog")

    if include != "full":
        desc = record.get("description")
        if desc and len(desc) > _SEARCH_DESCRIPTION_PREVIEW:
            record["description"] = desc[:_SEARCH_DESCRIPTION_PREVIEW] + "..."

    record["next_calls"] = _atlas_case_study_pivot_hints(record)
    return record


# --- Bulk technique lookup (POST, registered before catch-all GET /{technique_id}) ---


_BULK_ATLAS_MAX_IDS = 50


class _BulkAtlasTechniqueRequest(BaseModel):
    technique_ids: list[str] = Field(
        default_factory=list,
        description=(
            "List of ATLAS technique ids in canonical form 'AML.T####' or 'AML.T####.###' "
            "(case-insensitive; normalized to upper-case + de-duplicated server-side). "
            f"Truncated to {_BULK_ATLAS_MAX_IDS} entries before lookup."
        ),
        max_length=_BULK_ATLAS_MAX_IDS,
    )


@router.post(
    "/techniques/bulk",
    operation_id="bulk_atlas_technique_lookup",
    response_model=BulkAtlasTechniqueResponse,
    response_model_exclude_none=True,
)
async def bulk_atlas_technique_lookup(
    body: _BulkAtlasTechniqueRequest,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/atlas/techniques/bulk"))],
):
    """Bulk ATLAS technique lookup — up to 10 (free) / 50 (pro) technique ids in one call.

    Designed as the natural follow-up to atlas_case_study_lookup (which carries
    a list of techniques_used) — drill into all techniques in a single request
    instead of N separate atlas_technique_lookup calls. Each entry's record is
    the same shape as /v1/atlas/{technique_id}, including parent-tactics
    inheritance for sub-techniques (inherited_tactics flag set when applicable).

    Rate-limit accounting matches bulk_cve_lookup: each id consumes 1 unit of
    the per-hour quota.
    """
    import ratelimit
    from config import FREE_BULK_LIMIT, FREE_HOURLY_LIMIT, PRO_BULK_LIMIT, PRO_HOURLY_LIMIT
    from db import hash_client_ip

    # Normalize, de-dup preserving order, cap.
    seen: dict[str, None] = {}
    for raw in body.technique_ids:
        if not isinstance(raw, str):
            continue
        v = raw.strip().upper()
        if v and v not in seen:
            seen[v] = None
        if len(seen) >= _BULK_ATLAS_MAX_IDS:
            break
    ids = list(seen.keys())
    count = len(ids)

    if count == 0:
        return {
            "results": [],
            "total": 0,
            "successful": 0,
            "failed": 0,
            "partial": False,
            "summary": "0/0 techniques found",
        }

    # Tier-aware bulk cap: free=10, pro=50. (Pydantic max_length=50 already
    # caps the absolute upper bound; this enforces the free-tier ceiling.)
    bulk_cap = PRO_BULK_LIMIT if auth.tier == "pro" else FREE_BULK_LIMIT
    if count > bulk_cap:
        raise HTTPException(
            status_code=422,
            detail=f"Too many technique IDs. Limit: {bulk_cap} (your tier: {auth.tier})",
        )

    # Per-id quota consumption (mirror bulk_cve_lookup). The first id is already
    # accounted for by require_auth on this request; consume count-1.
    if auth.tier == "pro":
        store_key = f"pro:{auth.key_hash}"
        hourly_limit = PRO_HOURLY_LIMIT
    else:
        store_key = f"free:{hash_client_ip(auth.client_ip)}"
        hourly_limit = FREE_HOURLY_LIMIT

    if count > 1 and not await ratelimit.aconsume_bulk("api", store_key, count - 1, hourly_limit):
        raise HTTPException(
            status_code=429,
            detail=f"Insufficient rate limit quota for {count} technique IDs.",
        )

    parent_cache: dict = {}
    results = []
    successful = 0
    for tid in ids:
        if not _TECHNIQUE_RE.match(tid):
            results.append(
                {
                    "technique_id": tid,
                    "status": "invalid_format",
                    "technique": None,
                    "error": (f"Invalid ATLAS technique id format: {tid!r}. Expected 'AML.T####' or 'AML.T####.###'."),
                }
            )
            continue
        # v1.21.0: per-id error path (DB I/O exception). Schema defines 'error' alongside
        # 'ok'/'not_found'/'invalid_format' for parity with bulk_cve_lookup + bulk_ioc_lookup.
        try:
            record = await aget_atlas_technique(tid)
        except Exception as e:
            logger.warning("Bulk ATLAS technique lookup failed for %s: %s", tid, type(e).__name__)
            results.append(
                {
                    "technique_id": tid,
                    "status": "error",
                    "technique": None,
                    "error": "Lookup failed (transient)",
                }
            )
            continue
        if record is None:
            results.append(
                {
                    "technique_id": tid,
                    "status": "not_found",
                    "technique": None,
                    "error": f"{tid} is not in the MITRE ATLAS catalog",
                }
            )
            continue
        await _inherit_tactics_from_parent(record, _cache=parent_cache)
        record["next_calls"] = _atlas_technique_pivot_hints(record)
        results.append(
            {
                "technique_id": tid,
                "status": "ok",
                "technique": record,
                "error": None,
            }
        )
        successful += 1

    failed = len(results) - successful
    return {
        "results": results,
        "total": len(results),
        "successful": successful,
        "failed": failed,
        "partial": failed > 0,
        "summary": f"{successful}/{len(results)} techniques found",
    }


# --- Catch-all technique lookup (registered LAST) ---


@router.get(
    "/{technique_id}",
    operation_id="atlas_technique_lookup",
    response_model=AtlasTechniqueResponse,
    response_model_exclude_none=True,
)
async def atlas_technique_lookup(
    technique_id: Annotated[
        str,
        Path(
            description=(
                "Canonical ATLAS technique id matching 'AML.T####' or 'AML.T####.###' "
                "(sub-technique), e.g. 'AML.T0000', 'AML.T0000.000'. Returns 404 when "
                "the id is not in the synced ATLAS catalog."
            ),
        ),
    ],
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/atlas"))],
):
    """Look up a MITRE ATLAS technique (AI/ML attack catalog).

    ATLAS catalogues adversarial techniques targeting AI/ML systems — LLM prompt
    injection, model evasion, training data poisoning, and similar TTPs. About
    20% of ATLAS techniques bridge to ATT&CK via attack_reference_id; use that
    to pivot to D3FEND defenses through d3fend_defense_for_attack.
    """
    normalized = _validate_technique_id(technique_id)

    record = await aget_atlas_technique(normalized)
    if record is None:
        raise HTTPException(status_code=404, detail=f"{normalized} is not in the MITRE ATLAS catalog")

    await _inherit_tactics_from_parent(record)
    record["next_calls"] = _atlas_technique_pivot_hints(record)
    return record
