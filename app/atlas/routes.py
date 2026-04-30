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

from auth import authenticate
from db import (
    get_atlas_case_study,
    get_atlas_technique,
    search_atlas_case_studies,
    search_atlas_techniques,
)
from fastapi import APIRouter, HTTPException, Path, Query, Request
from schemas import (
    AtlasCaseStudyResponse,
    AtlasCaseStudySearchResponse,
    AtlasTechniqueResponse,
    AtlasTechniqueSearchResponse,
    PivotHint,
)

logger = logging.getLogger("contrastapi")

router = APIRouter(prefix="/v1/atlas", tags=["MITRE ATLAS"])

_TECHNIQUE_RE = re.compile(r"^AML\.T\d{4}(?:\.\d{3})?$")
_CASE_STUDY_RE = re.compile(r"^AML\.CS\d{4}$")
_TACTIC_RE = re.compile(r"^AML\.TA\d{4}$")

_PIVOT_CAP = 5
_SEARCH_DESCRIPTION_PREVIEW = 240  # chars; full text via _lookup drill or include=full


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
    if tactics:
        hints.append(
            PivotHint(
                tool="atlas_technique_search",
                input=tactics[0],
                reason=f"Find sibling techniques in the same ATLAS tactic ({tactics[0]}).",
            )
        )
    return hints[:_PIVOT_CAP]


def _atlas_case_study_pivot_hints(record: dict) -> list[PivotHint]:
    hints: list[PivotHint] = []
    for tid in (record.get("techniques_used") or [])[:_PIVOT_CAP]:
        hints.append(
            PivotHint(
                tool="atlas_technique_lookup",
                input=tid,
                reason="Look up the ATLAS technique used in this incident.",
            )
        )
    return hints


# --- Search routes (registered before catch-all) ---


@router.get(
    "/techniques",
    operation_id="atlas_technique_search",
    response_model=AtlasTechniqueSearchResponse,
    response_model_exclude_none=True,
)
def atlas_technique_search(
    request: Request,
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
):
    """Search the MITRE ATLAS technique catalog by keyword, tactic, or maturity.

    Use this to discover AI/ML attack techniques relevant to a given threat
    model. Drill into atlas_technique_lookup with the returned technique_id for
    full description, ATT&CK bridge, and next_calls pivot hints.
    """
    authenticate(request, request.url.path)
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

    rows = search_atlas_techniques(
        keyword=keyword,
        tactic=tactic or None,
        maturity=maturity or None,
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
def atlas_case_study_search(
    request: Request,
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
    authenticate(request, request.url.path)
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

    rows = search_atlas_case_studies(
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
def atlas_case_study_lookup(
    request: Request,
    case_study_id: Annotated[
        str,
        Path(
            description=(
                "Canonical ATLAS case study id matching 'AML.CS####', e.g. 'AML.CS0000'. "
                "Returns 404 when the id is not in the synced catalog."
            ),
        ),
    ],
):
    """Look up a MITRE ATLAS case study — a real-world AI/ML attack incident.

    Each case study links a sequence of ATLAS techniques (techniques_used) to a
    documented incident. Use atlas_technique_lookup on each id to expand into
    technique-level detail.
    """
    normalized = _validate_case_study_id(case_study_id)
    authenticate(request, request.url.path)

    record = get_atlas_case_study(normalized)
    if record is None:
        raise HTTPException(status_code=404, detail=f"{normalized} is not in the MITRE ATLAS case study catalog")

    record["next_calls"] = _atlas_case_study_pivot_hints(record)
    return record


# --- Catch-all technique lookup (registered LAST) ---


@router.get(
    "/{technique_id}",
    operation_id="atlas_technique_lookup",
    response_model=AtlasTechniqueResponse,
    response_model_exclude_none=True,
)
def atlas_technique_lookup(
    request: Request,
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
):
    """Look up a MITRE ATLAS technique (AI/ML attack catalog).

    ATLAS catalogues adversarial techniques targeting AI/ML systems — LLM prompt
    injection, model evasion, training data poisoning, and similar TTPs. About
    20% of ATLAS techniques bridge to ATT&CK via attack_reference_id; use that
    to pivot to D3FEND defenses through d3fend_defense_for_attack.
    """
    normalized = _validate_technique_id(technique_id)
    authenticate(request, request.url.path)

    record = get_atlas_technique(normalized)
    if record is None:
        raise HTTPException(status_code=404, detail=f"{normalized} is not in the MITRE ATLAS catalog")

    record["next_calls"] = _atlas_technique_pivot_hints(record)
    return record
