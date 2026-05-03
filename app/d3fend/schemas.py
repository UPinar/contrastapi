"""Pydantic response models for MITRE D3FEND endpoints."""

from __future__ import annotations

from pydantic import BaseModel, Field
from schemas import BaseSuccessResponse


class D3fendDefenseResponse(BaseSuccessResponse):
    """MITRE D3FEND defense technique record.

    D3FEND catalogues defensive techniques against ATT&CK TTPs. Each defense is
    classified into one of 7 tactics (Model, Harden, Detect, Isolate, Deceive,
    Evict, Restore) and may target a specific digital artifact (e.g. 'Access
    Token', 'Process'). Use attack_techniques to see which ATT&CK T-codes this
    defense mitigates.
    """

    model_config = {"extra": "allow"}

    defense_id: str = Field(
        description="Slug derived from the D3FEND ontology URI fragment, e.g. 'TokenBinding', 'FileHashing'."
    )
    label: str = Field(description="Human-readable defense name, e.g. 'Token Binding', 'File Hashing'.")
    uri: str = Field(
        description="Full D3FEND ontology URI, e.g. 'http://d3fend.mitre.org/ontologies/d3fend.owl#TokenBinding'."
    )
    parent_label: str | None = Field(
        default=None,
        description="Parent defense category, e.g. 'Credential Hardening' for 'Token Binding'.",
    )
    description: str | None = Field(
        default=None, description="D3FEND-published description of the defense (may be null in current sync)."
    )
    tactic: str = Field(
        description="One of seven D3FEND tactics: Model, Harden, Detect, Isolate, Deceive, Evict, Restore.",
    )
    artifact: str | None = Field(
        default=None,
        description="Digital artifact the defense targets, e.g. 'Access Token', 'File', 'Process'.",
    )
    attack_techniques: list[str] = Field(
        default_factory=list,
        description="ATT&CK T-codes this defense mitigates, e.g. ['T1550.001', 'T1539']. Drill via cve_search or d3fend_defense_for_attack to bridge.",
    )


class D3fendDefenseListItem(BaseModel):
    """Slim D3FEND defense row for search results (no attack_techniques list)."""

    model_config = {"extra": "allow"}

    defense_id: str = Field(description="D3FEND defense slug.")
    label: str = Field(description="Human-readable defense name.")
    uri: str | None = Field(
        default=None,
        description="Full D3FEND ontology URI. Omitted in slim default; pass include=full to get it back.",
    )
    parent_label: str | None = Field(default=None, description="Parent defense category.")
    tactic: str = Field(description="D3FEND tactic.")
    artifact: str | None = Field(default=None, description="Targeted digital artifact.")


class D3fendDefenseSearchResponse(BaseSuccessResponse):
    """List response for d3fend_defense_search."""

    model_config = {"extra": "allow"}

    query: dict = Field(default_factory=dict, description="Echo of input filters (keyword/tactic/artifact).")
    total: int = Field(default=0, description="Number of defenses returned (capped at 200).")
    results: list[D3fendDefenseListItem] = Field(default_factory=list, description="Matching D3FEND defenses.")


class D3fendDefenseForAttackItem(BaseModel):
    """One defense entry in a reverse-lookup result."""

    model_config = {"extra": "allow"}

    defense_id: str = Field(description="D3FEND defense slug.")
    label: str = Field(description="Human-readable defense name.")
    uri: str | None = Field(
        default=None,
        description="Full D3FEND ontology URI. Omitted in slim default; pass include=full to get it back.",
    )
    parent_label: str | None = Field(default=None, description="Parent defense category.")
    tactic: str = Field(description="D3FEND tactic — one of Model/Harden/Detect/Isolate/Deceive/Evict/Restore.")
    artifact: str | None = Field(default=None, description="Targeted digital artifact.")
    attack_label: str | None = Field(default=None, description="Original ATT&CK technique label as published by MITRE.")
    attack_tactic: str | None = Field(default=None, description="ATT&CK tactic the technique sits under.")


class D3fendForAttackResponse(BaseSuccessResponse):
    """Reverse lookup response: given an ATT&CK T-code, list mitigating D3FEND defenses."""

    model_config = {"extra": "allow"}

    attack_technique_id: str = Field(description="The ATT&CK T-code that was queried, e.g. 'T1059'.")
    total: int = Field(
        default=0,
        description="Honest pre-truncation count of D3FEND defenses that mitigate this technique.",
    )
    truncated: bool = Field(
        default=False,
        description="True when defenses[] was capped at `limit`. Inspect `total` for the full count and re-call with a higher `limit` if needed.",
    )
    defenses: list[D3fendDefenseForAttackItem] = Field(
        default_factory=list,
        description="D3FEND defenses mapped to this ATT&CK technique (capped at request `limit`, default 30).",
    )
    coverage_by_tactic: dict[str, int] = Field(
        default_factory=dict,
        description="Defense count per D3FEND tactic for this single technique, e.g. {'Harden': 3, 'Detect': 5}.",
    )


class D3fendCoverageResponse(BaseSuccessResponse):
    """Batch coverage breakdown for a list of ATT&CK T-codes."""

    model_config = {"extra": "allow"}

    queried_techniques: list[str] = Field(
        default_factory=list,
        description="The ATT&CK T-codes the caller queried (truncated to 500 if larger).",
    )
    coverage_by_tactic: dict[str, int] = Field(
        default_factory=dict,
        description=(
            "Distinct D3FEND defenses per tactic across all queried techniques. "
            "Keys are tactics (Harden/Detect/Isolate/...), values are counts."
        ),
    )
    defended_techniques: list[str] = Field(
        default_factory=list,
        description="Subset of queried techniques that have at least one D3FEND defense.",
    )
    undefended_techniques: list[str] = Field(
        default_factory=list,
        description="Subset of queried techniques with NO D3FEND mapping — gap candidates.",
    )
