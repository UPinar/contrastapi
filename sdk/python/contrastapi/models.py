"""Lightweight TypedDict response models — IDE autocomplete, zero runtime cost.

Every TypedDict mirrors the corresponding `app/schemas.py` Pydantic class on the
server. Field names are wire-exact (kept in sync via the v1.22.3 round-2 audit
against `app/schemas.py`). Drift here = silent KeyError downstream, so the rule
is: **if the server schema doesn't have it, the TypedDict doesn't either**.

Why TypedDict (not Pydantic)?
  * No additional dependency beyond `httpx`.
  * Zero validation overhead — server already validates on response.
  * `total=False` everywhere — every key is optional from the SDK's perspective
    so omitted fields (Pydantic `response_model_exclude_none=True`) don't
    trigger spurious type errors.

Coverage strategy: top-level keys only. Nested complex fields (`kev`, `cvss`,
`reputation`, `verdict.falsifiable_fields`, `pivot_hint.params`, etc.) stay as
`dict[str, Any]` so server-side schema drift on internal subtrees doesn't
break IDE completion for SDK consumers.

For richer typing (full nested validation), use the server's `app.schemas`
Pydantic models directly — they remain the wire-contract source of truth.
"""

from __future__ import annotations

from typing import Any, TypedDict

# --- Cross-cutting shapes ---


class ErrorBody(TypedDict, total=False):
    code: str
    message: str
    retry_after_seconds: int | None
    upgrade_url: str | None
    docs_url: str | None


class ErrorEnvelope(TypedDict, total=False):
    """Wire-level error response (v1.22.2+)."""

    error: ErrorBody
    # Top-level back-compat extensions: hint, tier, limit, upgrade, field,
    # received, suggestion, support, reset_in, error_code, docs.


class Verdict(TypedDict, total=False):
    deterministic: bool
    falsifiable_fields: list[str]
    sources_queried: list[str]
    sources_unavailable: list[str]
    completeness: str


class PivotHint(TypedDict, total=False):
    tool: str
    value: str
    reason: str
    params: dict[str, Any]


# --- CVE / KEV / CWE / Exploit ---


class CveResponse(TypedDict, total=False):
    cve_id: str
    summary: str
    description: str
    severity: str
    cvss_v3: float
    cvss_breakdown: dict[str, Any]
    cwe_id: str
    cwes: list[str]  # v1.28.0 (B4A) — all CWE identifiers, Primary first
    vulnerability_status: str  # v1.29.0 (B5) — NVD lifecycle (Analyzed/Modified/Rejected/...)
    cve_tags: list[str]  # v1.29.0 (B5) — NVD cveTags (e.g. 'disputed')
    epss: dict[str, Any]
    kev: dict[str, Any]
    affected_products: list[dict[str, Any]]
    total_products: int
    published: str
    modified: str
    references: list[str]
    total_references: int
    total_references_unique: int  # v1.29.0 (B6A) — unique-URL count from refs_with_tags
    references_full: list[dict[str, Any]]  # v1.29.0 (B6B) — [{url, tags, source}] when ?include_reference_tags=true
    patch_available: bool
    patch_url: str
    sources: list[str]
    cvss_v2: float  # v1.29.0 (B7) — CVSS v2.0 base score (always emitted)
    cvss_v2_vector: str  # v1.29.0 (B7) — CVSS v2.0 vector string
    severity_sources: list[dict[str, Any]]  # v1.29.0 (B7) — per-source severity breakdown
    severity_consensus: str  # v1.29.0 (B7) — majority-bucket consensus
    severity_disagreement: bool  # v1.29.0 (B7) — true when sources disagree
    verdict: Verdict
    next_calls: list[PivotHint]


class CveSearchResponse(TypedDict, total=False):
    count: int
    total: int
    truncated: bool
    offset: int
    summary: str
    results: list[dict[str, Any]]
    query_echo: dict[str, Any]
    next_offset: int | None
    hint: dict[str, Any]
    verdict: Verdict
    next_calls: list[PivotHint]


class KevDetailResponse(TypedDict, total=False):
    cve_id: str
    in_kev: bool
    date_added: str
    date_updated: str  # v1.29.0 (B5) — feed update timestamp
    date_removed: str  # v1.29.0 (B5) — soft-delete lifecycle (null when still active)
    due_date: str
    required_action: str
    known_ransomware_use: bool
    vendor_project: str
    product: str
    vulnerability_name: str
    short_description: str
    notes: str
    cwes: list[str]
    verdict: Verdict
    next_calls: list[PivotHint]


class CweLookupResponse(TypedDict, total=False):
    cwe_id: str
    name: str
    description: str
    extended_description: str
    abstract_type: str
    status: str
    likelihood: str
    mitigations: list[str]
    examples: list[str]
    parent_cwe: str
    child_cwes: list[str]
    cve_count: int
    total_mitigations: int | None
    total_examples: int | None
    updated_at: str
    verdict: Verdict
    next_calls: list[PivotHint]


class ExploitResponse(TypedDict, total=False):
    cve_id: str
    exploits_found: int
    sources: dict[str, Any]
    has_public_exploit: bool
    exploits: list[dict[str, Any]]
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


# --- v1.29.1: composite risk score + CVSS v3.x parser ---


class CvssMetrics(TypedDict, total=False):
    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    scope: str
    confidentiality_impact: str
    integrity_impact: str
    availability_impact: str


class CvssDetailsResponse(TypedDict, total=False):
    """v1.29.1 — `GET /v1/cvss/details?vector=...`."""

    version: str
    vector: str
    base_score: float
    base_severity: str
    metrics: CvssMetrics
    temporal_score: float | None
    environmental_score: float | None
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class RiskScoreResponse(TypedDict, total=False):
    """v1.29.1 — `GET /v1/cve/{cve_id}/risk_score`."""

    cve_id: str
    score: float
    label: str  # CRITICAL / HIGH / MEDIUM / LOW
    urgency: str
    has_public_poc: bool
    components: dict[str, Any]
    boosters_applied: list[str]
    recommendation: str
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


# --- Bulk parity (v1.21.0+ unified status enum: ok/error/not_found/invalid_format) ---


class BulkCveItem(TypedDict, total=False):
    cve_id: str
    status: str
    cve: CveResponse | None
    error: str


class BulkCveResponse(TypedDict, total=False):
    results: list[BulkCveItem]
    total: int
    successful: int
    failed: int
    timed_out: int
    not_found: int
    partial: bool
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class BulkIocItem(TypedDict, total=False):
    indicator: str
    status: str
    ioc: dict[str, Any]
    error: str


class BulkIocResponse(TypedDict, total=False):
    results: list[BulkIocItem]
    total: int
    successful: int
    failed: int
    timed_out: int
    not_found: int
    invalid: int
    partial: bool
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class BulkAtlasTechniqueItem(TypedDict, total=False):
    technique_id: str
    status: str
    technique: dict[str, Any]
    error: str


class BulkAtlasTechniqueResponse(TypedDict, total=False):
    results: list[BulkAtlasTechniqueItem]
    total: int
    successful: int
    failed: int
    partial: bool
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


# --- IOC / Hash / Phishing / Password ---


class IocResponse(TypedDict, total=False):
    indicator: str
    type: str  # ip | domain | url | hash | unknown
    threat_level: str  # none | low | medium | high
    sources: dict[str, Any]
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class HashResponse(TypedDict, total=False):
    hash: str
    hash_type: str
    found: bool
    malware_family: str | None
    file_type: str | None
    file_size: int | None
    first_seen: str | None
    tags: list[str]
    verdict: Verdict
    next_calls: list[PivotHint]


class PhishingResponse(TypedDict, total=False):
    url: str
    host: str
    is_malicious: bool
    is_stale: bool
    sources: dict[str, Any]
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class PasswordResponse(TypedDict, total=False):
    hash_prefix: str
    found: bool
    pwned_count: int
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


# --- Domain ---


class DomainReportResponse(TypedDict, total=False):
    domain: str
    dns: dict[str, Any]
    reverse_dns: dict[str, Any]
    whois: dict[str, Any]
    ssl: dict[str, Any]
    subdomains: dict[str, Any]
    certificates: dict[str, Any]
    email_security: dict[str, Any]
    waf: dict[str, Any]
    threat: dict[str, Any]
    risk: dict[str, Any]
    risk_score: int | None  # DEPRECATED (Sunset 2026-09-01); use risk.score
    reputation: dict[str, Any]
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class DnsResponse(TypedDict, total=False):
    domain: str
    records: dict[str, Any]
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class WhoisResponse(TypedDict, total=False):
    domain: str
    whois: dict[str, Any]
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class SubdomainsResponse(TypedDict, total=False):
    domain: str
    count: int
    subdomains: list[str]
    summary: str
    sources: list[str]
    warnings: list[str]
    found_via_wordlist: int
    found_via_crtsh: int
    verdict: Verdict
    next_calls: list[PivotHint]


class CertsResponse(TypedDict, total=False):
    domain: str
    total_certificates: int
    certificates: list[dict[str, Any]]
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class SslResponse(TypedDict, total=False):
    domain: str
    valid: bool
    cert_valid: bool
    grade: str
    validation_errors: list[str]
    issuer: dict[str, Any]
    subject: dict[str, Any]
    san: list[str]
    not_before: str
    not_after: str
    days_until_expiry: int
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class TechResponse(TypedDict, total=False):
    domain: str
    technologies: list[dict[str, Any]]
    categories: dict[str, list[str]]
    count: int
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class ThreatResponse(TypedDict, total=False):
    domain: str
    urlhaus_status: str
    urls_online: int
    url_count: int
    threat_types: list[str]
    tags: list[str]
    urls: list[dict[str, Any]]
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class WaybackResponse(TypedDict, total=False):
    domain: str
    status: str  # 'ok' | 'unavailable'
    snapshots: list[dict[str, Any]]
    total_snapshots: int
    earliest: str
    latest: str
    warnings: list[str]
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class AuditResponse(TypedDict, total=False):
    domain: str
    report: DomainReportResponse | None
    headers: dict[str, Any]
    tech: TechResponse | None
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class BulkDomainResponse(TypedDict, total=False):
    results: list[dict[str, Any]]
    total: int
    successful: int
    failed: int
    timed_out: int
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


# --- IP / ASN / Threat report ---


class IpLookupResponse(TypedDict, total=False):
    ip: str
    ptr: str | None
    asn: int | None
    asn_name: str | None
    country: str | None
    ports: list[int]
    hostnames: list[str]
    vulns: list[dict[str, Any]]
    cpes: list[str]
    tags: list[str]
    reputation: dict[str, Any]
    cloud_provider: str | None
    is_datacenter: bool
    tor_exit: bool
    risk_score: int
    severity_label: str  # low | medium | high | critical
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class AsnResponse(TypedDict, total=False):
    target: str
    resolved_ip: str | None
    asn: int
    asn_name: str
    country: str | None
    prefixes: list[str]
    prefix_count: int
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class ThreatReportResponse(TypedDict, total=False):
    ip: str
    enrichment: dict[str, Any]
    abuseipdb: dict[str, Any]
    shodan: dict[str, Any]
    asn_info: dict[str, Any]
    risk_score: int
    severity_label: str
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


# --- Email / Phone / Username ---


class EmailMxResponse(TypedDict, total=False):
    domain: str
    mx_records: list[dict[str, Any]]
    mail_provider: str | None
    email_security: dict[str, Any]
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class DisposableResponse(TypedDict, total=False):
    email: str
    domain: str
    disposable: bool
    provider: str | None
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class PhoneLookupResponse(TypedDict, total=False):
    valid: bool
    number: str
    country: str | None
    region: str | None
    carrier: str | None
    line_type: str | None
    format: dict[str, Any]
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class UsernameLookupResponse(TypedDict, total=False):
    username: str
    found_count: int
    platforms: list[dict[str, Any]]
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


# --- ATLAS ---


class AtlasTechniqueResponse(TypedDict, total=False):
    technique_id: str
    name: str
    description: str
    tactics: list[str]
    inherited_tactics: bool
    maturity: str
    attack_reference_id: str
    attack_reference_url: str
    subtechnique_of: str
    created_date: str
    modified_date: str
    verdict: Verdict
    next_calls: list[PivotHint]


class AtlasTechniqueListItem(TypedDict, total=False):
    technique_id: str
    name: str
    description: str
    tactics: list[str]
    inherited_tactics: bool
    maturity: str
    attack_reference_id: str
    subtechnique_of: str


class AtlasTechniqueSearchResponse(TypedDict, total=False):
    query: dict[str, Any]
    total: int
    results: list[AtlasTechniqueListItem]
    verdict: Verdict
    next_calls: list[PivotHint]


class AtlasCaseStudyResponse(TypedDict, total=False):
    case_study_id: str
    name: str
    description: str
    techniques_used: list[str]
    verdict: Verdict
    next_calls: list[PivotHint]


class AtlasCaseStudySearchResponse(TypedDict, total=False):
    query: dict[str, Any]
    total: int
    results: list[AtlasCaseStudyResponse]
    verdict: Verdict
    next_calls: list[PivotHint]


# --- D3FEND ---


class D3fendDefenseResponse(TypedDict, total=False):
    defense_id: str
    label: str
    uri: str
    parent_label: str
    description: str
    tactic: str  # singular
    artifact: str
    attack_techniques: list[str]
    verdict: Verdict
    next_calls: list[PivotHint]


class D3fendDefenseListItem(TypedDict, total=False):
    defense_id: str
    label: str
    uri: str
    parent_label: str
    tactic: str
    artifact: str


class D3fendDefenseSearchResponse(TypedDict, total=False):
    query: dict[str, Any]
    total: int
    results: list[D3fendDefenseListItem]
    verdict: Verdict
    next_calls: list[PivotHint]


class D3fendDefenseForAttackItem(TypedDict, total=False):
    defense_id: str
    label: str
    uri: str
    parent_label: str
    tactic: str
    artifact: str
    attack_label: str
    attack_tactic: str


class D3fendForAttackResponse(TypedDict, total=False):
    attack_technique_id: str
    total: int
    truncated: bool
    defenses: list[D3fendDefenseForAttackItem]
    coverage_by_tactic: dict[str, int]
    verdict: Verdict
    next_calls: list[PivotHint]


class D3fendCoverageResponse(TypedDict, total=False):
    queried_techniques: list[str]
    coverage_by_tactic: dict[str, int]
    defended_techniques: list[str]
    undefended_techniques: list[str]
    verdict: Verdict
    next_calls: list[PivotHint]


# --- Code-security checks + scan ---


class CodeCheckResponse(TypedDict, total=False):
    findings: list[dict[str, Any]]
    total: int
    by_severity: dict[str, int]
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class CheckHeadersResponse(TypedDict, total=False):
    findings: list[dict[str, Any]]
    total: int
    by_severity: dict[str, int]
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class ScanHeadersResponse(TypedDict, total=False):
    domain: str
    status_code: int
    url: str
    score: int
    grade: str
    findings: list[dict[str, Any]]
    headers: dict[str, str]
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class ScanResponse(TypedDict, total=False):
    domain: str
    resolved_ip: str
    total_score: int
    max_score: int
    grade: str
    findings: list[dict[str, Any]]
    findings_count: dict[str, int]
    headers: dict[str, Any]
    ssl: dict[str, Any]
    dns: dict[str, Any]
    redirect: dict[str, Any]
    disclosure: dict[str, Any]
    cookies: dict[str, Any]
    dnssec: dict[str, Any]
    methods: dict[str, Any]
    cors: dict[str, Any]
    html: dict[str, Any]
    csp_analysis: dict[str, Any]
    enterprise: dict[str, Any]
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


class DependenciesResponse(TypedDict, total=False):
    findings: list[dict[str, Any]]
    total: int
    by_severity: dict[str, int]
    summary: str
    verdict: Verdict
    next_calls: list[PivotHint]


# --- Meta ---


class StatusResponse(TypedDict, total=False):
    status: str
    version: str
    uptime_seconds: int


class UsageResponse(TypedDict, total=False):
    requests_remaining: int
    window_seconds: int
    tier: str
