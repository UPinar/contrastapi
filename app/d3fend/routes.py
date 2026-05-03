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

from auth import AuthCtx, require_auth
from d3fend.schemas import (
    D3fendCoverageResponse,
    D3fendDefenseResponse,
    D3fendDefenseSearchResponse,
    D3fendForAttackResponse,
)
from db import (
    D3FEND_COVERAGE_MAX_IDS,
    aget_d3fend_coverage,
    aget_d3fend_defense,
    aget_d3fend_defenses_for_attack,
    asearch_d3fend_defenses,
)
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field
from schemas import PivotHint

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


_REVERSE_LOOKUP_CAP = 3  # top N attack_techniques to reverse-pivot from defense_lookup


def _d3fend_defense_pivot_hints(record: dict) -> list[PivotHint]:
    hints: list[PivotHint] = []
    self_id = record.get("defense_id")
    label = record.get("label")
    if label:
        hints.append(
            PivotHint(
                tool="atlas_technique_search",
                input=label,
                reason="Find AI/ML attack techniques relevant to this defense.",
            )
        )
    artifact = record.get("artifact")
    if artifact and self_id:
        hints.append(
            PivotHint(
                tool="d3fend_defense_search",
                input=artifact,
                reason=f"Find sibling defenses targeting the same artifact ({artifact!r}), excluding self.",
                params={"exclude_id": self_id},
            )
        )
    for tcode in (record.get("attack_techniques") or [])[:_REVERSE_LOOKUP_CAP]:
        hints.append(
            PivotHint(
                tool="d3fend_defense_for_attack",
                input=tcode,
                reason="See other defenses that also mitigate this ATT&CK technique (excluding self).",
                params={"exclude_id": self_id} if self_id else None,
            )
        )
    return hints[:_PIVOT_CAP]


def _d3fend_for_attack_pivot_hints(_attack_id: str, defenses: list[dict]) -> list[PivotHint]:
    # Empty defenses → no drill possible; the gap itself is the signal.
    # d3fend_attack_coverage takes a LIST of T-codes (POST body), not a single
    # value, and for a single T-code it just echoes the coverage_by_tactic
    # already in this response — no value-add. Skip it.
    if not defenses:
        return []
    top = defenses[0]
    return [
        PivotHint(
            tool="d3fend_defense_lookup",
            input=top["defense_id"],
            reason=f"Drill into the top defense ({top.get('label') or top['defense_id']!r}) for the full record.",
        )
    ]


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
async def d3fend_defense_search(
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/d3fend/defenses"))],
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
    include: Annotated[
        str | None,
        Query(
            description=(
                "Detail level. Default returns slim rows (drops the deterministic ontology `uri` "
                "field — saves ~60 chars/row, ~30% on popular T-code drills). Pass include=full to "
                "get the `uri` back. The slug `defense_id` is always returned and uniquely identifies "
                "the defense; `uri` is reconstructible from it."
            ),
        ),
    ] = None,
    exclude_id: Annotated[
        str | None,
        Query(
            description=(
                "Optional D3FEND defense slug to exclude from results (CamelCase, e.g. 'TokenBinding'). "
                "Useful when paired with an artifact filter to fetch siblings without the originating "
                "defense itself (chained from d3fend_defense_lookup's next_calls)."
            ),
        ),
    ] = None,
):
    """Search MITRE D3FEND defenses by keyword, tactic, or targeted artifact.

    Use this to discover defensive techniques relevant to a threat model. Drill
    via d3fend_defense_lookup with the returned defense_id for the full record
    + the list of ATT&CK T-codes the defense mitigates.

    Default response is SLIM (drops `uri` from each row). Pass `include=full`
    for the verbose record on every row.
    """
    if include not in (None, "", "full"):
        raise HTTPException(status_code=400, detail="include must be 'full' (omit for slim default)")
    if exclude_id is not None:
        exclude_id = exclude_id.strip()
        if exclude_id and not _DEFENSE_ID_RE.match(exclude_id):
            raise HTTPException(
                status_code=400,
                detail="exclude_id must be a CamelCase D3FEND defense slug (e.g. 'TokenBinding')",
            )

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

    rows = await asearch_d3fend_defenses(
        keyword=keyword,
        tactic=tactic or None,
        artifact=artifact or None,
        limit=limit,
    )

    if exclude_id:
        rows = [r for r in rows if r.get("defense_id") != exclude_id]

    if include != "full":
        for r in rows:
            r.pop("uri", None)

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
async def d3fend_defense_for_attack(
    attack_technique_id: Annotated[
        str,
        Path(
            description=(
                "ATT&CK technique id matching 'T####' or 'T####.###' (e.g. 'T1059', 'T1550.001'). "
                "Returns 200 with empty defenses list when the T-code has no D3FEND mapping."
            ),
        ),
    ],
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/d3fend/attack"))],
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
    include: Annotated[
        str | None,
        Query(
            description=(
                "Detail level. Default returns slim rows (drops the deterministic ontology `uri` "
                "field — popular T-codes with 15+ defenses save ~900 chars). Pass include=full to "
                "get `uri` back on every row. The slug `defense_id` is always returned."
            ),
        ),
    ] = None,
    exclude_id: Annotated[
        str | None,
        Query(
            description=(
                "Optional D3FEND defense slug to exclude from results. Used by chain pivots from "
                "d3fend_defense_lookup so the agent does not see itself in the 'see also' list."
            ),
        ),
    ] = None,
):
    """Reverse lookup: given an ATT&CK T-code, list every D3FEND defense that mitigates it.

    This is the bridge from offensive intelligence (ATT&CK / ATLAS / CVE) to
    defensive playbook. Pair with cve_lookup or atlas_technique_lookup output —
    when those carry an ATT&CK id, call this tool to surface the mitigations.
    Returns 200 with empty defenses on no match (the gap itself is signal).

    `defenses` is capped at `limit` (default 30) for token efficiency; `total`
    is the honest count and `coverage_by_tactic` aggregates ALL matching
    defenses, not just the truncated slice. `next_calls` emits a single
    drill hint into the top defense via d3fend_defense_lookup; empty defense
    list emits no pivot (the gap is the signal).

    Default response is SLIM (drops `uri` from each row). Pass `include=full`
    for the verbose record.
    """
    normalized = _validate_attack_technique(attack_technique_id)
    if include not in (None, "", "full"):
        raise HTTPException(status_code=400, detail="include must be 'full' (omit for slim default)")
    if exclude_id is not None:
        exclude_id = exclude_id.strip()
        if exclude_id and not _DEFENSE_ID_RE.match(exclude_id):
            raise HTTPException(
                status_code=400,
                detail="exclude_id must be a CamelCase D3FEND defense slug (e.g. 'TokenBinding')",
            )

    defenses = await aget_d3fend_defenses_for_attack(normalized)
    if exclude_id:
        defenses = [d for d in defenses if d.get("defense_id") != exclude_id]

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

    if include != "full":
        for d in capped_defenses:
            d.pop("uri", None)

    return {
        "attack_technique_id": normalized,
        "total": total,
        "truncated": truncated,
        "defenses": capped_defenses,
        "coverage_by_tactic": coverage_by_tactic,
        "next_calls": _d3fend_for_attack_pivot_hints(normalized, capped_defenses),
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
async def d3fend_attack_coverage(
    body: D3fendCoverageBody,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/d3fend/coverage"))],
):
    """Batch coverage breakdown: given a list of ATT&CK T-codes, return defense counts per tactic + identify undefended techniques.

    Use this to assess the defensive posture of an entire campaign or threat
    model in one call. Defended_techniques is the subset that has at least one
    D3FEND mapping; undefended_techniques are the gaps. coverage_by_tactic
    counts DISTINCT defenses per D3FEND tactic across the whole input set.
    """
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

    cov = await aget_d3fend_coverage(normalized)
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
async def d3fend_defense_lookup(
    defense_id: Annotated[
        str,
        Path(
            description=(
                "D3FEND defense slug (CamelCase from the ontology URI fragment), "
                "e.g. 'TokenBinding', 'FileHashing'. Returns 404 when not in catalog."
            ),
        ),
    ],
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/d3fend"))],
):
    """Look up a MITRE D3FEND defense technique by slug.

    Returns the defense's tactic (one of 7 D3FEND tactics), targeted digital
    artifact, and the list of ATT&CK T-codes it mitigates (attack_techniques).
    Use this after d3fend_defense_search or as a follow-up to
    d3fend_defense_for_attack to inspect a specific defense in detail.
    """
    normalized = _validate_defense_id(defense_id)

    record = await aget_d3fend_defense(normalized)
    if record is None:
        raise HTTPException(status_code=404, detail=f"defense_id {normalized!r} not in MITRE D3FEND catalog")

    record["next_calls"] = _d3fend_defense_pivot_hints(record)
    return record
