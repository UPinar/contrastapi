"""Pydantic response models for MITRE ATLAS endpoints."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field
from schemas import BaseSuccessResponse


class AtlasTechniqueResponse(BaseSuccessResponse):
    """MITRE ATLAS technique record (AI/ML attack catalog).

    ATLAS catalogues adversarial techniques targeting AI/ML systems (LLM prompt
    injection, model poisoning, evasion). About 80% of techniques have no ATT&CK
    bridge — ATLAS is the canonical reference for AI/ML-specific TTPs.
    """

    model_config = {"extra": "allow"}

    technique_id: str = Field(description="Canonical ATLAS technique id, e.g. 'AML.T0000', 'AML.T0000.000'.")
    name: str = Field(description="Human-readable technique name, e.g. 'Search Open Technical Databases'.")
    description: str | None = Field(
        default=None,
        description="Full technique description as published by MITRE ATLAS. May be multi-paragraph.",
    )
    tactics: list[str] = Field(
        default_factory=list,
        description=(
            "ATLAS tactic ids that this technique belongs to, e.g. ['AML.TA0002'] (Reconnaissance). "
            "Sub-techniques have empty tactics in upstream ATLAS; we backfill from the parent and "
            "set inherited_tactics=true when this happens."
        ),
    )
    inherited_tactics: bool | None = Field(
        default=None,
        description=(
            "True when `tactics` was inherited from the parent technique (this is a sub-technique). "
            "Omitted when tactics are native to the record."
        ),
    )
    maturity: str | None = Field(
        default=None,
        description="MITRE ATLAS maturity classification: 'demonstrated' (observed in real attacks) or 'feasible' (theoretical).",
    )
    attack_reference_id: str | None = Field(
        default=None,
        description=(
            "Bridged ATT&CK technique id when ATLAS cites a parallel enterprise TTP, e.g. 'T1596'. "
            "About 20% of ATLAS techniques carry an ATT&CK reference; use this to pivot to D3FEND defenses."
        ),
    )
    attack_reference_url: str | None = Field(
        default=None,
        description="Canonical ATT&CK URL for the bridged technique, e.g. 'https://attack.mitre.org/techniques/T1596/'.",
    )
    subtechnique_of: str | None = Field(
        default=None,
        description="Parent technique id when this is a sub-technique, e.g. 'AML.T0000' for 'AML.T0000.000'.",
    )
    created_date: str | None = Field(
        default=None,
        description="ISO-8601 date the technique was first published in ATLAS.",
    )
    modified_date: str | None = Field(
        default=None,
        description="ISO-8601 date of the most recent ATLAS update for this technique.",
    )


class AtlasTechniqueListItem(BaseModel):
    """Slim ATLAS technique row for search results."""

    model_config = {"extra": "allow"}

    technique_id: str = Field(description="Canonical ATLAS technique id.")
    name: str = Field(description="Human-readable technique name.")
    description: str | None = Field(
        default=None, description="Full description; consider drilling into atlas_technique_lookup for context."
    )
    tactics: list[str] = Field(
        default_factory=list,
        description=(
            "ATLAS tactic ids covering this technique. Sub-techniques inherit from parent; see inherited_tactics."
        ),
    )
    inherited_tactics: bool | None = Field(
        default=None,
        description="True when tactics were inherited from the parent technique. Omitted when native.",
    )
    maturity: str | None = Field(default=None, description="'demonstrated' or 'feasible'.")
    attack_reference_id: str | None = Field(default=None, description="Bridged ATT&CK id or null.")
    subtechnique_of: str | None = Field(default=None, description="Parent technique id when applicable.")


class AtlasTechniqueSearchResponse(BaseSuccessResponse):
    """List response for atlas_technique_search."""

    model_config = {"extra": "allow"}

    query: dict = Field(default_factory=dict, description="Echo of the input filters (keyword/tactic/maturity).")
    total: int = Field(default=0, description="Number of techniques returned (capped at 200).")
    results: list[AtlasTechniqueListItem] = Field(default_factory=list, description="Matching ATLAS techniques.")


class BulkAtlasTechniqueItem(BaseModel):
    """One ATLAS technique outcome inside a bulk_atlas_technique_lookup response."""

    model_config = {"extra": "allow"}

    technique_id: str = Field(description="Echoed input ATLAS technique id (upper-cased + de-duplicated).")
    status: Literal["ok", "error", "not_found", "invalid_format"] = Field(
        default="ok",
        description=(
            "Per-item outcome (v1.21.0+ unified across bulk_cve/bulk_ioc/bulk_atlas): 'ok' = "
            "technique populated; 'not_found' = id not in synced ATLAS catalog; 'invalid_format' = "
            "id failed AML.T#### / AML.T####.### regex; 'error' = transient lookup failure (DB I/O "
            "exception) — rare, server-side fallback only."
        ),
    )
    technique: AtlasTechniqueResponse | None = Field(
        default=None,
        description="Full ATLAS technique record when status='ok'. Same shape as /v1/atlas/{technique_id}.",
    )
    error: str | None = Field(
        default=None,
        description="Human-readable error message when status is 'not_found' or 'invalid_format'.",
    )


class BulkAtlasTechniqueResponse(BaseSuccessResponse):
    model_config = {"extra": "allow"}

    results: list[BulkAtlasTechniqueItem] = Field(
        default_factory=list,
        description="Per-technique outcome list, preserving input order after upper-case de-duplication.",
    )
    total: int = Field(
        default=0,
        description="Total number of unique technique IDs submitted (== processed + len(skipped_due_to_rate_limit)).",
    )
    processed: int = Field(
        default=0,
        description="Count of items actually looked up (== len(results)). Equal to total unless dynamic-budget partial-fill kicked in.",
    )
    skipped_due_to_rate_limit: list[str] = Field(
        default_factory=list,
        description=(
            "Technique IDs that were not processed because the caller's remaining hourly quota "
            "was smaller than the input list. Empty when full budget was available."
        ),
    )
    successful: int = Field(default=0, description="Count of items with status='ok'.")
    failed: int = Field(default=0, description="Count of items with status='not_found' or 'invalid_format'.")
    partial: bool = Field(
        default=False,
        description="True when at least one item was not_found, invalid_format, or skipped due to rate limit.",
    )
    summary: str = Field(default="", description="One-line aggregate summary (e.g. '4/5 techniques found').")


class AtlasCaseStudyResponse(BaseSuccessResponse):
    """MITRE ATLAS case study record — real-world AI/ML incidents."""

    model_config = {"extra": "allow"}

    case_study_id: str = Field(description="Canonical ATLAS case study id, e.g. 'AML.CS0000'.")
    name: str = Field(description="Short title of the incident, e.g. 'Evasion of Deep Learning Detector'.")
    description: str | None = Field(
        default=None, description="Narrative summary of the incident as published by MITRE ATLAS."
    )
    techniques_used: list[str] = Field(
        default_factory=list,
        description="ATLAS technique ids used in this incident's procedure, in observed order.",
    )


class AtlasCaseStudySearchResponse(BaseSuccessResponse):
    """List response for atlas_case_study_search."""

    model_config = {"extra": "allow"}

    query: dict = Field(default_factory=dict, description="Echo of input filters (keyword/technique_id).")
    total: int = Field(default=0, description="Number of case studies returned (capped at 200).")
    results: list[AtlasCaseStudyResponse] = Field(default_factory=list, description="Matching case studies.")
