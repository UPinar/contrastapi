"""Pydantic response models for code-security endpoints (secrets/injection/headers/dependencies)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field
from schemas import BaseSuccessResponse


class CodeFinding(BaseModel):
    type: str = Field(
        default="",
        description="Rule identifier that fired (e.g. 'aws_secret_key', 'sql_injection'). Stable across releases.",
    )
    severity: Literal["critical", "high", "medium", "low"] = Field(
        default="medium",
        description="Impact bucket assigned by the rule. 'critical'/'high' are typically actionable; 'low' is advisory.",
    )
    line: int | None = Field(
        default=None,
        description="1-indexed line number in the submitted code where the rule matched. Null if line cannot be determined.",
    )
    match: str | None = Field(
        default=None,
        description="Snippet of the matching text (truncated for ReDoS safety). Null when the rule does not capture text.",
    )
    description: str = Field(default="", description="Human-readable explanation of what the rule detects.")
    remediation: str = Field(default="", description="Actionable fix or mitigation guidance.")


class CodeCheckResponse(BaseSuccessResponse):
    findings: list[CodeFinding] = Field(
        default_factory=list,
        description="Per-rule findings emitted by the scanner. Empty when the code is clean.",
    )
    total: int = Field(default=0, description="Total number of findings (== len(findings)).")
    by_severity: dict[str, int] = Field(
        default_factory=dict,
        description="Finding counts bucketed by severity, e.g. {'critical': 1, 'high': 2, 'medium': 0, 'low': 1}.",
    )
    summary: str = Field(default="", description="One-line summary aggregating finding counts by severity.")


class HeaderFinding(BaseModel):
    header: str = Field(
        description="Canonical header name as defined by the ruleset (e.g. 'Strict-Transport-Security', 'Content-Security-Policy').",
    )
    severity: Literal["high", "medium", "low"] = Field(
        description=(
            "Impact weight assigned by the ruleset: 'high' (25 pts), 'medium' (15 pts), 'low' (10 pts). "
            "Drives the overall score/grade — missing a 'high' header costs more than missing a 'low' one."
        ),
    )
    present: bool = Field(
        description="True when the response sent this header at all (regardless of whether the value is valid).",
    )
    valid: bool = Field(
        default=False,
        description=(
            "Value-level validation result. True when the header is present AND its value passes the "
            "header-specific validator (e.g. HSTS max-age >= 1 year + includeSubDomains; CSP has no "
            "wildcard source in script-src). True also when the header is present but no validator exists "
            "for it. False when the header is absent, or present-but-invalid. Inspect `issues` for the "
            "specific reasons a present-but-invalid header failed."
        ),
    )
    value: str | None = Field(
        default=None,
        description=(
            "Raw header value as sent by the origin, when the header is present AND a validator exists for it. "
            "Null when the header is absent, or when it's present but no validator applies to it. "
            "By default the value is capped at the first 500 chars (CSP headers can exceed 4 KB); "
            "inspect total_value_length to see if truncation occurred and refetch with include=full to "
            "restore the full value."
        ),
    )
    total_value_length: int | None = Field(
        default=None,
        description=(
            "Honest pre-truncation char length of the raw header value. Only emitted when the value was "
            "actually truncated (raw length > 500). Null when no truncation occurred, when no validator "
            "applies, or when the header is absent."
        ),
    )
    issues: list[str] = Field(
        default_factory=list,
        description=(
            "Machine-readable issue codes emitted by the validator for present-but-invalid headers "
            "(e.g. 'hsts_max_age_too_short', 'csp_wildcard_script_src', 'xfo_allowall'). "
            "Empty when the header is absent, valid, or has no validator."
        ),
    )
    description: str = Field(
        default="",
        description="Human-readable explanation of what this header protects against.",
    )
    remediation: str = Field(
        default="",
        description="Concrete recommended header value or configuration snippet.",
    )
    reference: str = Field(
        default="",
        description="URL to authoritative spec/documentation (MDN, OWASP, RFC).",
    )


class ScanHeadersResponse(BaseSuccessResponse):
    domain: str = Field(description="Queried domain (lowercased, no scheme).")
    status_code: int = Field(
        default=0, description="HTTP status code returned by the live origin during the header probe."
    )
    url: str = Field(default="", description="Final URL the probe landed on (after redirects).")
    score: int = Field(
        default=0, description="Aggregate header-posture score (0-100) summed from per-finding severity weights."
    )
    grade: Literal["A", "B", "C", "D", "F"] = Field(
        default="F",
        description="Letter grade derived from score: A=90+, B=75+, C=60+, D=40+, else F.",
    )
    findings: list[HeaderFinding] = Field(
        default_factory=list,
        description="Per-header validation findings — one entry per header in the ruleset (present or missing).",
    )
    summary: str = Field(default="", description="One-line human-readable summary of grade + key gaps.")
    headers_present: list[str] = Field(
        default_factory=list,
        description="Names of security-relevant headers the origin actually sent.",
    )
    headers_missing: list[str] = Field(
        default_factory=list,
        description="Names of security-relevant headers the origin did NOT send.",
    )


class CheckHeadersResponse(BaseSuccessResponse):
    findings: list[HeaderFinding] = Field(
        default_factory=list,
        description="Per-header validation findings — one entry per header you submitted that the validator recognized.",
    )
    total: int = Field(default=0, description="Total number of findings emitted (== len(findings)).")
    by_severity: dict[str, int] = Field(
        default_factory=dict,
        description="Finding counts bucketed by severity, e.g. {'high': 2, 'medium': 1, 'low': 0}.",
    )
    summary: str = Field(default="", description="One-line human-readable summary of grade + key issues.")
    score: int = Field(
        default=0, description="Aggregate header-posture score (0-100) computed from per-finding severity weights."
    )
    grade: Literal["A", "B", "C", "D", "F"] = Field(
        default="F",
        description="Letter grade derived from score: A=90+, B=75+, C=60+, D=40+, else F.",
    )
    headers_present: list[str] = Field(
        default_factory=list,
        description="Header names from the submitted set that the validator recognized as present.",
    )
    headers_missing: list[str] = Field(
        default_factory=list,
        description="Header names the ruleset expects but were not present in the submitted set.",
    )


class DepFinding(BaseModel):
    package: str
    version: str | None = None
    cve_id: str
    severity: str = "unknown"
    cvss_v3: float | None = None
    description: str = ""
    epss_score: float | None = None
    in_kev: bool = False
    fixed_in: str | None = Field(
        default=None,
        description=(
            "First patched release per NVD/MITRE version range data (CVE affected_products[].version_end). "
            "Excluded from the wire (response_model_exclude_none=True) when the matched range is open-ended "
            "or no input version was supplied — in those cases inspect remediation copy."
        ),
    )
    remediation: str = ""


class DependenciesResponse(BaseSuccessResponse):
    findings: list[DepFinding] = Field(default_factory=list)
    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    summary: str = ""
