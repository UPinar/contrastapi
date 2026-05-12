"""Shared Pydantic base classes used by every endpoint package."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    """Structured failure body. Codes mirror app/exceptions.AppException
    subclasses; agent retry / upgrade decisions key off `code`, not `message`.
    """

    code: Literal[
        "invalid_argument",
        "not_found",
        "rate_limit_exceeded",
        "auth_required",
        "tier_limit",
        "upstream_timeout",
        "upstream_error",
        "internal_error",
    ] = Field(description="Stable machine-readable failure category. Agents key retry/upgrade decisions off this.")
    message: str = Field(
        max_length=500,
        description="Human-readable detail. Free text — never parse. Capped at 500 chars to prevent oversized upstream errors from bloating responses.",
    )
    retry_after_seconds: int | None = Field(
        default=None,
        description="When code='rate_limit_exceeded', the minimum seconds to wait before retrying.",
    )
    upgrade_url: str | None = Field(
        default=None,
        description="Pricing/upgrade URL when code='tier_limit' or 'rate_limit_exceeded' on the Free tier.",
    )
    docs_url: str | None = Field(
        default=None,
        description="Documentation pointer (e.g. tool input contract) when code='invalid_argument'.",
    )


class ErrorResponse(BaseModel):
    """MCP error envelope. Tool return type is always
    `SpecificResponse | ErrorResponse` — Union flag tells the agent which arm
    arrived without parsing the inner body.
    """

    error: ErrorDetail


class PivotHint(BaseModel):
    """A suggested follow-up MCP tool call. Surfaced inside response.next_calls so
    LLM agents can chain related lookups without manual prompting. Each hint names
    the tool, the input value to pass, and a short reason explaining why this
    pivot adds value in the current context."""

    model_config = {"extra": "allow"}

    tool: Literal[
        "cve_lookup",
        "cve_search",
        "cve_leading",
        "bulk_cve_lookup",
        "calculate_risk_score",
        "get_cvss_details",
        "exploit_lookup",
        "kev_detail",
        "cwe_lookup",
        "subdomain_enum",
        "ssl_check",
        "tech_fingerprint",
        "asn_lookup",
        "ip_lookup",
        "ioc_lookup",
        "bulk_ioc_lookup",
        "hash_lookup",
        "threat_intel",
        "threat_report",
        "audit_domain",
        "domain_report",
        "dns_lookup",
        "whois_lookup",
        "wayback_lookup",
        "scan_headers",
        "check_headers",
        "check_secrets",
        "check_injection",
        "check_dependencies",
        "email_mx",
        "email_security_posture",
        "email_disposable",
        "email_verify",
        "robots_txt",
        "redirect_chain",
        "brand_assets",
        "seo_audit",
        "phone_lookup",
        "username_lookup",
        "password_check",
        "phishing_check",
        "atlas_technique_lookup",
        "atlas_technique_search",
        "bulk_atlas_technique_lookup",
        "atlas_case_study_lookup",
        "atlas_case_study_search",
        "d3fend_defense_lookup",
        "d3fend_defense_search",
        "d3fend_defense_for_attack",
        "d3fend_attack_coverage",
    ] = Field(
        description=(
            "Canonical MCP tool name to call next. Constrained to known operation_ids in "
            "tools/list — adding a new tool here requires expanding the Literal."
        ),
    )
    input: str = Field(
        description=(
            "Suggested input value to pass to the tool — typically a CVE ID, CWE ID, "
            "domain, or IP. Pre-populated from the current response so the agent can "
            "call the next tool without re-deriving the argument."
        ),
    )
    reason: str = Field(
        description=(
            "Short rationale (one sentence) for why this follow-up call adds value, "
            "e.g. 'Federal patch deadline + ransomware association', 'Public exploits / PoC availability'."
        ),
    )
    params: dict[str, str] | None = Field(
        default=None,
        description=(
            "Optional extra kwargs to pass alongside `input`. Used by pivot generators when the next "
            "call benefits from a secondary parameter, e.g. {'exclude_id': 'AML.T0051'} to skip the "
            "originating technique from a sibling-tactic search. Omitted when no extra args are needed."
        ),
    )


class SearchHint(BaseModel):
    """Footer hint emitted on list responses (cve_search, cve_leading) to point
    LLM agents at the natural drill-down tool. Distinct from PivotHint: there is
    no `input` field because the hint is global to the list — the agent picks a
    result of interest and passes its ID to the named tool."""

    model_config = {"extra": "allow"}

    tool: Literal["cve_lookup"] = Field(
        description=(
            "Drill-down tool to call with any result ID from the list. Constrained to "
            "cve_lookup today; expand the Literal as new list endpoints get list-level hints."
        ),
    )
    reason: str = Field(
        description=(
            "Short rationale explaining what the drill-down tool adds beyond the slim list "
            "items (e.g. full description, affected_products, references, exploit/KEV/CWE pivots)."
        ),
    )


class Verdict(BaseModel):
    deterministic: bool = Field(
        description=(
            "True when the response is fully reproducible from the listed sources "
            "for the same input at the same moment (no randomness, no model inference). "
            "False for endpoints that include probabilistic scoring or LLM output."
        ),
    )
    falsifiable_fields: list[str] = Field(
        default_factory=list,
        description=(
            "Top-level response fields whose values a caller can independently re-derive "
            "from the named upstream sources (e.g. 'dns', 'ssl', 'whois'). "
            "Fields not in this list are derived/computed and cannot be directly re-verified."
        ),
    )
    data_age_seconds: int | None = Field(
        default=None,
        description=(
            "Seconds elapsed since the oldest cached source was fetched, or null when "
            "every source was queried live for this request. Use to judge freshness."
        ),
    )
    sources_queried: list[str] = Field(
        default_factory=list,
        description=(
            "Canonical source identifiers successfully consulted for this response "
            "(e.g. 'ripe_stat', 'shodan_internetdb', 'firehol'). Agent-readable list, "
            "order not significant."
        ),
    )
    sources_unavailable: list[str] = Field(
        default_factory=list,
        description=(
            "Sources that were expected but not returned — either intentionally skipped "
            "(lite mode, tier gating) or failed (quota, timeout, upstream down). "
            "Empty list means every planned source produced data."
        ),
    )
    completeness: Literal["complete", "partial", "minimal"] = Field(
        default="complete",
        description=(
            "'complete' = every planned source returned data; "
            "'partial' = at least one source in sources_unavailable failed or was skipped; "
            "'minimal' = only the primary/required source returned, optional enrichment missing."
        ),
    )


class BaseSuccessResponse(BaseModel):
    """Common base for every MCP tool success response.

    Carries shared fields (`verdict`, `next_calls`) that nearly every tool
    surfaces. Subclasses extend with endpoint-specific data. Subclass
    `model_config` overrides this base when set; otherwise extras are dropped
    (Pydantic default), matching pre-v1.22 behaviour for response models that
    did not declare their own model_config.
    """

    verdict: Verdict | None = Field(
        default=None,
        description=(
            "Falsifiability metadata: sources_queried, sources_unavailable, "
            "completeness, deterministic flag. Lets agents distinguish 'no data' "
            "from 'source failed' without re-running the call."
        ),
    )
    next_calls: list[PivotHint] | None = Field(
        default=None,
        description=(
            "Suggested follow-up MCP tool calls. Ordered by relevance; agents "
            "should chain these without re-prompting the user."
        ),
    )
