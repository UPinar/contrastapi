"""MITRE D3FEND API routes — /v1/d3fend/* (defense technique catalog).

Static catalog endpoints sourced from the synced D3FEND mappings JSON. Free tier:
no API key required, credit-cost = 1.

Route order is significant: `/defenses`, `/attack/{id}`, `/coverage` are registered
BEFORE the catch-all `/{defense_id}` — otherwise FastAPI would treat 'defenses' or
'attack' as a defense slug.
"""

import logging
import re
from typing import Annotated

from auth import authenticate
from db import (
    D3FEND_COVERAGE_MAX_IDS,
    get_d3fend_coverage,
    get_d3fend_defense,
    get_d3fend_defenses_for_attack,
    search_d3fend_defenses,
)
from fastapi import APIRouter, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field
from schemas import (
    D3fendCoverageResponse,
    D3fendDefenseResponse,
    D3fendDefenseSearchResponse,
    D3fendForAttackResponse,
    PivotHint,
)

logger = logging.getLogger("contrastapi")

router = APIRouter(prefix="/v1/d3fend", tags=["MITRE D3FEND"])

_DEFENSE_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,63}$")
_ATTACK_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_VALID_TACTICS = {"Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"}

_PIVOT_CAP = 5
_UNDEFENDED_PIVOT_CAP = 3
_FOR_ATTACK_DEFAULT_LIMIT = 30  # popular ATT&CK T-codes can map to 30+ defenses


def _validate_defense_id(value: str) -> str:
    v = (value or "").strip()
    if not _DEFENSE_ID_RE.match(v):
        raise HTTPException(
            status_code=400,
            detail="defense_id must be a CamelCase slug 1-64 chars (alphanumeric, e.g. 'TokenBinding')",
        )
    return v


def _validate_attack_technique(value: str) -> str:
    v = (value or "").strip().upper()
    if not _ATTACK_TECHNIQUE_RE.match(v):
        raise HTTPException(
            status_code=400,
            detail="attack_technique_id must match 'T####' or 'T####.###' (e.g. T1059, T1550.001)",
        )
    return v


def _d3fend_defense_pivot_hints(record: dict) -> list[PivotHint]:
    hints: list[PivotHint] = []
    label = record.get("label")
    if label:
        hints.append(
            PivotHint(
                tool="atlas_technique_search",
                input=label,
                reason="Find AI/ML attack techniques relevant to this defense.",
            )
        )
    return hints[:_PIVOT_CAP]


def _d3fend_for_attack_pivot_hints(_attack_id: str) -> list[PivotHint]:
    # No automatic pivots: cve_search/atlas_technique_search both reject ATT&CK
    # T-codes as input. Caller can use the returned defense_id list to drill
    # via d3fend_defense_lookup directly.
    return []


def _d3fend_coverage_pivot_hints(undefended: list[str]) -> list[PivotHint]:
    return [
        PivotHint(
            tool="d3fend_defense_for_attack",
            input=tcode,
            reason="Confirm no D3FEND mitigation exists for this ATT&CK technique.",
        )
        for tcode in undefended[:_UNDEFENDED_PIVOT_CAP]
    ]


# --- Search + reverse-lookup + coverage routes (registered before catch-all) ---


@router.get(
    "/defenses",
    operation_id="d3fend_defense_search",
    response_model=D3fendDefenseSearchResponse,
    response_model_exclude_none=True,
)
def d3fend_defense_search(
    request: Request,
    keyword: Annotated[
        str | None,
        Query(
            min_length=2,
            max_length=100,
            description="Substring match against defense label, description, or parent_label (case-insensitive).",
        ),
    ] = None,
    tactic: Annotated[
        str | None,
        Query(
            description="Filter by D3FEND tactic. One of: Model, Harden, Detect, Isolate, Deceive, Evict, Restore.",
        ),
    ] = None,
    artifact: Annotated[
        str | None,
        Query(
            min_length=2,
            max_length=100,
            description="Filter by exact digital artifact targeted by the defense, e.g. 'Access Token', 'File'.",
        ),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=200, description="Max results to return.")] = 50,
):
    """Search MITRE D3FEND defenses by keyword, tactic, or targeted artifact.

    Use this to discover defensive techniques relevant to a threat model. Drill
    via d3fend_defense_lookup with the returned defense_id for the full record
    + the list of ATT&CK T-codes the defense mitigates.
    """
    authenticate(request, request.url.path)

    if keyword is not None:
        stripped = keyword.strip()
        if len(stripped) < 2:
            raise HTTPException(status_code=400, detail="keyword must be at least 2 non-whitespace characters")
        keyword = stripped

    if tactic is not None:
        tactic = tactic.strip().capitalize()
        if tactic and tactic not in _VALID_TACTICS:
            raise HTTPException(
                status_code=400,
                detail=f"tactic must be one of {sorted(_VALID_TACTICS)}",
            )

    if artifact is not None:
        stripped_a = artifact.strip()
        if len(stripped_a) < 2:
            raise HTTPException(status_code=400, detail="artifact must be at least 2 non-whitespace characters")
        artifact = stripped_a

    rows = search_d3fend_defenses(
        keyword=keyword,
        tactic=tactic or None,
        artifact=artifact or None,
        limit=limit,
    )

    next_calls: list[PivotHint] | None = None
    if rows:
        next_calls = [
            PivotHint(
                tool="d3fend_defense_lookup",
                input=rows[0]["defense_id"],
                reason="Drill into the top hit for the full record + ATT&CK technique list.",
            )
        ]

    return {
        "query": {"keyword": keyword, "tactic": tactic, "artifact": artifact},
        "total": len(rows),
        "results": rows,
        "next_calls": next_calls,
    }


@router.get(
    "/attack/{attack_technique_id}",
    operation_id="d3fend_defense_for_attack",
    response_model=D3fendForAttackResponse,
    response_model_exclude_none=True,
)
def d3fend_defense_for_attack(
    request: Request,
    attack_technique_id: Annotated[
        str,
        Path(
            description=(
                "ATT&CK technique id matching 'T####' or 'T####.###' (e.g. 'T1059', 'T1550.001'). "
                "Returns 200 with empty defenses list when the T-code has no D3FEND mapping."
            ),
        ),
    ],
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=200,
            description=(
                f"Cap on `defenses` array length. Default {_FOR_ATTACK_DEFAULT_LIMIT}; "
                "popular T-codes (e.g. T1059, T1078) map to 30-50+ D3FEND techniques. "
                "`total` and `coverage_by_tactic` always reflect the honest pre-truncation counts."
            ),
        ),
    ] = _FOR_ATTACK_DEFAULT_LIMIT,
):
    """Reverse lookup: given an ATT&CK T-code, list every D3FEND defense that mitigates it.

    This is the bridge from offensive intelligence (ATT&CK / ATLAS / CVE) to
    defensive playbook. Pair with cve_lookup or atlas_technique_lookup output —
    when those carry an ATT&CK id, call this tool to surface the mitigations.
    Returns 200 with empty defenses on no match (the gap itself is signal).

    `defenses` is capped at `limit` (default 30) for token efficiency; `total`
    is the honest count and `coverage_by_tactic` aggregates ALL matching
    defenses, not just the truncated slice.
    """
    normalized = _validate_attack_technique(attack_technique_id)
    authenticate(request, request.url.path)

    defenses = get_d3fend_defenses_for_attack(normalized)

    coverage_by_tactic: dict[str, int] = {}
    seen: dict[str, set] = {}
    for d in defenses:
        t = d.get("tactic")
        if not t:
            continue
        seen.setdefault(t, set()).add(d["defense_id"])
    coverage_by_tactic = {t: len(s) for t, s in seen.items()}

    total = len(defenses)
    truncated = total > limit
    capped_defenses = defenses[:limit]

    return {
        "attack_technique_id": normalized,
        "total": total,
        "truncated": truncated,
        "defenses": capped_defenses,
        "coverage_by_tactic": coverage_by_tactic,
        "next_calls": _d3fend_for_attack_pivot_hints(normalized) or None,
    }


class D3fendCoverageBody(BaseModel):
    """POST body for /v1/d3fend/coverage — accepts a batch of ATT&CK T-codes."""

    attack_technique_ids: list[str] = Field(
        default_factory=list,
        description=(
            f"List of ATT&CK T-codes (T####, T####.###). Truncated to {D3FEND_COVERAGE_MAX_IDS} entries before query."
        ),
        max_length=D3FEND_COVERAGE_MAX_IDS,
    )


@router.post(
    "/coverage",
    operation_id="d3fend_attack_coverage",
    response_model=D3fendCoverageResponse,
    response_model_exclude_none=True,
)
def d3fend_attack_coverage(
    request: Request,
    body: D3fendCoverageBody,
):
    """Batch coverage breakdown: given a list of ATT&CK T-codes, return defense counts per tactic + identify undefended techniques.

    Use this to assess the defensive posture of an entire campaign or threat
    model in one call. Defended_techniques is the subset that has at least one
    D3FEND mapping; undefended_techniques are the gaps. coverage_by_tactic
    counts DISTINCT defenses per D3FEND tactic across the whole input set.
    """
    authenticate(request, request.url.path)

    normalized: list[str] = []
    for raw in body.attack_technique_ids[:D3FEND_COVERAGE_MAX_IDS]:
        if not isinstance(raw, str):
            continue
        v = raw.strip().upper()
        if _ATTACK_TECHNIQUE_RE.match(v):
            normalized.append(v)
    # de-dup preserving order
    normalized = list(dict.fromkeys(normalized))

    if not normalized:
        return {
            "queried_techniques": [],
            "coverage_by_tactic": {},
            "defended_techniques": [],
            "undefended_techniques": [],
            "next_calls": None,
        }

    cov = get_d3fend_coverage(normalized)
    return {
        "queried_techniques": normalized,
        "coverage_by_tactic": cov["coverage_by_tactic"],
        "defended_techniques": cov["defended_techniques"],
        "undefended_techniques": cov["undefended_techniques"],
        "next_calls": _d3fend_coverage_pivot_hints(cov["undefended_techniques"]) or None,
    }


# --- Catch-all defense lookup (registered LAST) ---


@router.get(
    "/{defense_id}",
    operation_id="d3fend_defense_lookup",
    response_model=D3fendDefenseResponse,
    response_model_exclude_none=True,
)
def d3fend_defense_lookup(
    request: Request,
    defense_id: Annotated[
        str,
        Path(
            description=(
                "D3FEND defense slug (CamelCase from the ontology URI fragment), "
                "e.g. 'TokenBinding', 'FileHashing'. Returns 404 when not in catalog."
            ),
        ),
    ],
):
    """Look up a MITRE D3FEND defense technique by slug.

    Returns the defense's tactic (one of 7 D3FEND tactics), targeted digital
    artifact, and the list of ATT&CK T-codes it mitigates (attack_techniques).
    Use this after d3fend_defense_search or as a follow-up to
    d3fend_defense_for_attack to inspect a specific defense in detail.
    """
    normalized = _validate_defense_id(defense_id)
    authenticate(request, request.url.path)

    record = get_d3fend_defense(normalized)
    if record is None:
        raise HTTPException(status_code=404, detail=f"defense_id {normalized!r} not in MITRE D3FEND catalog")

    record["next_calls"] = _d3fend_defense_pivot_hints(record)
    return record
