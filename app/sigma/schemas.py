"""Pydantic response models for Sigma detection rules."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field
from schemas import BaseSuccessResponse, PivotHint


class SigmaDetection(BaseModel):
    """Nested detection block — preserve raw YAML structure."""

    selections: dict = Field(
        default_factory=dict,
        description="Selection blocks keyed by name (e.g., {'selection_img': {...}, 'selection_cmd': {...}})",
    )
    condition: str = Field(
        default="unknown",
        description="Boolean condition syntax (e.g., 'all of selection_*', 'selection_a and selection_b')",
    )


class SigmaRule(BaseSuccessResponse):
    """Full Sigma detection rule parsed from YAML."""

    # Sigma spec allows vendor extensions (e.g. `fields`); drop them silently
    # so attacker-supplied YAML cannot smuggle arbitrary keys into the MCP
    # response that reaches an LLM agent (CWE-116).
    model_config = {"extra": "ignore"}

    rule_id: str = Field(description="UUID of the rule (unique identifier)")
    title: str = Field(description="Human-readable rule title")
    status: Literal["test", "stable", "experimental", "unsupported", "deprecated"] = Field(
        default="test",
        description="Rule maturity level",
    )
    level: Literal["informational", "low", "medium", "high", "critical"] = Field(
        default="medium",
        description="Detection alert severity",
    )
    description: str | None = Field(
        default=None,
        description="Multi-line rule description; may be None if omitted in YAML",
    )
    author: str | None = Field(
        default=None,
        description="Rule author(s); defaults to 'Unknown' if missing",
    )
    date: str | None = Field(
        default=None,
        description="ISO-8601 creation date",
    )
    modified: str | None = Field(
        default=None,
        description="ISO-8601 last modification date",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Flattened tags list (attack.t1059, cve.2024-1234, detection.threat_hunting, etc.)",
    )
    logsource: dict = Field(
        default_factory=dict,
        description="Logsource metadata: {product, service, category, definition}",
    )
    detection: SigmaDetection = Field(description="Nested detection block with selections and condition")
    detection_summary: str = Field(
        default="",
        description="Human-readable summary (e.g., '2 selections, condition: all of selection_*')",
    )
    references: list[str] = Field(
        default_factory=list,
        description="List of reference URLs from the rule",
    )
    falsepositives: list[str] = Field(
        default_factory=list,
        description="Known false-positive scenarios",
    )
    license: str = Field(
        default="DRL 1.1",
        description="Detection Rule License version",
    )
    source_url: str = Field(
        default="",
        description="GitHub URL to the rule in SigmaHQ repository (set by indexer)",
    )
    updated_at: str = Field(
        default="",
        description="ISO-8601 timestamp when ContrastAPI last synced this rule",
    )


class SigmaRuleLookupResponse(BaseSuccessResponse):
    """Single rule lookup response."""

    model_config = {"extra": "forbid"}

    rule: SigmaRule = Field(description="Full Sigma rule record")


class BulkSigmaRuleLookupItem(BaseModel):
    """Single item in bulk lookup response."""

    model_config = {"extra": "forbid"}

    rule_id: str = Field(description="Echoed input rule UUID")
    status: Literal["ok", "not_found", "invalid_format"] = Field(
        description="'ok' = rule found; 'not_found' = UUID not in index; 'invalid_format' = invalid UUID"
    )
    rule: SigmaRule | None = Field(
        default=None,
        description="Full rule when status='ok'",
    )
    error: str | None = Field(
        default=None,
        description="Error message when status != 'ok'",
    )


class BulkSigmaRuleLookupResponse(BaseSuccessResponse):
    """Bulk rule lookup response."""

    model_config = {"extra": "forbid"}

    results: list[BulkSigmaRuleLookupItem] = Field(
        default_factory=list,
        description="Per-rule outcome, preserving input order",
    )
    total: int = Field(
        default=0,
        description="Total unique rule IDs submitted",
    )
    successful: int = Field(
        default=0,
        description="Count of items with status='ok'",
    )
    failed: int = Field(
        default=0,
        description="Count of items with status != 'ok'",
    )
    partial: bool = Field(
        default=False,
        description="True when at least one item was not_found or invalid_format",
    )
    summary: str = Field(
        default="",
        description="One-line aggregate (e.g., '3/5 rules found')",
    )
    next_calls: list[PivotHint] | None = Field(
        default=None,
        description="Suggested follow-up tool calls (atlas_technique_lookup, cve_lookup, etc.)",
    )


class SigmaRuleSearchResponse(BaseSuccessResponse):
    """Multi-rule search response (GET /v1/sigma/search)."""

    model_config = {"extra": "forbid"}

    rules: list[SigmaRule] = Field(
        default_factory=list,
        description="Matching rules, capped by limit (default 50, max 200)",
    )
    total_matches: int = Field(
        default=0,
        description="Total candidates before limit/offset slicing",
    )
    limit: int = Field(default=50, description="Effective limit applied to this response")
    offset: int = Field(default=0, description="Offset into the matched set")
    truncated: bool = Field(
        default=False,
        description="True when total_matches > offset + limit (more pages available)",
    )
    next_calls: list[PivotHint] | None = Field(
        default=None,
        description="Suggested follow-up tool calls based on first result",
    )


class BulkSigmaRuleLookupRequest(BaseModel):
    """POST /v1/sigma/bulk request body."""

    model_config = {"extra": "forbid"}

    rule_ids: list[str] = Field(
        min_length=1,
        max_length=50,
        description="UUIDs to look up (1-50)",
    )
