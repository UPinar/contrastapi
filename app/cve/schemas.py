"""Pydantic response models for CVE/Exploit/CWE/KEV endpoints."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field
from schemas import BaseSuccessResponse, SearchHint


class EpssInfo(BaseModel):
    score: float | None = Field(
        default=None,
        description="EPSS probability (0.0-1.0) that this CVE will be exploited in the next 30 days.",
    )
    percentile: float | None = Field(
        default=None,
        description="EPSS percentile rank (0.0-100.0) relative to all scored CVEs; higher = more at-risk.",
    )


class KevInfo(BaseModel):
    in_kev: bool = Field(
        default=False,
        description="True when CISA has confirmed this CVE is being actively exploited in the wild.",
    )
    date_added: str | None = Field(
        default=None,
        description="ISO 8601 date this CVE was added to CISA's Known Exploited Vulnerabilities catalog.",
    )


class KevDetailResponse(BaseSuccessResponse):
    """Full CISA KEV catalog record for a single CVE.

    Text fields (required_action, notes, vulnerability_name, short_description) are
    sourced verbatim from CISA's official feed and JSON-encoded — safe for
    JSON consumers, but downstream callers that render into HTML must apply their
    own escaping.

    `extra="allow"` is set for forward-compat (Tier 2 audit pattern, Session 171).
    Only PivotHint objects in `next_calls` and CISA-sourced DB columns appear in extras.
    """

    model_config = {"extra": "allow"}

    cve_id: str = Field(description="Canonical CVE identifier, e.g. 'CVE-2021-44228'.")
    in_kev: bool = Field(
        default=True,
        description="Always True for this endpoint — 404 is returned when the CVE is not in the KEV catalog.",
    )
    date_added: str | None = Field(
        default=None,
        description="ISO 8601 date CISA added this CVE to the Known Exploited Vulnerabilities catalog.",
    )
    due_date: str | None = Field(
        default=None,
        description=(
            "Federal patch deadline (ISO 8601). Null for older entries from before CISA enforced "
            "remediation due dates (BOD 22-01, Nov 2021)."
        ),
    )
    required_action: str | None = Field(
        default=None,
        description="CISA-specified remediation action text, e.g. 'Apply updates per vendor instructions'.",
    )
    known_ransomware_use: bool = Field(
        default=False,
        description=(
            "True when CISA has linked this CVE to a known ransomware campaign. "
            "Derived from CISA's 'knownRansomwareCampaignUse=Known' field."
        ),
    )
    vendor_project: str | None = Field(
        default=None,
        description="Vendor or project name as published by CISA, e.g. 'Apache', 'Microsoft', 'Atlassian'.",
    )
    product: str | None = Field(
        default=None,
        description="Affected product name as published by CISA, e.g. 'Log4j2', 'Exchange Server'.",
    )
    vulnerability_name: str | None = Field(
        default=None,
        description="Short common name of the vulnerability when one is assigned, e.g. 'Log4Shell', 'ProxyShell'.",
    )
    short_description: str | None = Field(
        default=None,
        description="CISA's one-sentence summary of the vulnerability.",
    )
    notes: str | None = Field(
        default=None,
        description="Reference URLs published by CISA, separated by '; '.",
    )
    cwes: list[str] = Field(
        default_factory=list,
        max_length=100,
        description=(
            "CWE identifiers CISA reports for this CVE. May differ from the NVD-assigned CWE. "
            "Call cwe_lookup with each entry to fetch weakness category, mitigations, and parent/child chain."
        ),
    )


class CweLookupResponse(BaseSuccessResponse):
    """MITRE CWE catalog record (research view 1000).

    Text fields are sourced verbatim from MITRE's published CSV and JSON-encoded —
    safe for JSON consumers, but downstream callers that render into HTML must apply
    their own escaping. `extra="allow"` is set for forward-compat (Tier 2 audit pattern,
    Session 171).
    """

    model_config = {"extra": "allow"}

    cwe_id: str = Field(description="Canonical CWE identifier, e.g. 'CWE-79', 'CWE-502'.")
    name: str = Field(
        description="Short human-readable weakness name, e.g. 'Improper Neutralization of Input During Web Page Generation'."
    )
    description: str | None = Field(
        default=None,
        description="MITRE one-paragraph summary of the weakness.",
    )
    extended_description: str | None = Field(
        default=None,
        description="MITRE's longer-form explanation including consequences and typical exploitation paths.",
    )
    abstract_type: str | None = Field(
        default=None,
        description=(
            "MITRE 'Weakness Abstraction' level: 'Pillar' (most abstract), 'Class', 'Base', "
            "'Variant' (most specific), or 'Compound'."
        ),
    )
    status: str | None = Field(
        default=None,
        description=(
            "Catalog lifecycle status: 'Stable', 'Draft', 'Incomplete', 'Deprecated', "
            "or 'Obsolete'. Prefer Stable when chaining to other tools."
        ),
    )
    likelihood: str | None = Field(
        default=None,
        description=("MITRE's 'Likelihood of Exploit' rating: 'High', 'Medium', 'Low', or null when unrated."),
    )
    mitigations: list[str] = Field(
        default_factory=list,
        max_length=30,
        description=(
            "Recommended mitigations as 'Phase — Description' strings, parsed from MITRE's "
            "'Potential Mitigations' field (Architecture and Design, Implementation, etc.)."
        ),
    )
    examples: list[str] = Field(
        default_factory=list,
        max_length=50,
        description=(
            "Observed example CVEs as 'CVE-x: description' strings. These are MITRE-curated "
            "exemplars, not an exhaustive list — use cve_search?cwe= for the full list."
        ),
    )
    parent_cwe: str | None = Field(
        default=None,
        description=(
            "Direct parent CWE in research view 1000 (Primary ChildOf), e.g. 'CWE-707'. "
            "Call cwe_lookup with this value to traverse up the weakness hierarchy."
        ),
    )
    child_cwes: list[str] = Field(
        default_factory=list,
        max_length=50,
        description=(
            "Direct child CWEs in research view 1000 (ParentOf entries). Call cwe_lookup on "
            "any entry to traverse down to a more specific weakness."
        ),
    )
    cve_count: int = Field(
        default=0,
        description=(
            "Number of CVEs in our database whose primary cwe_id equals this CWE. "
            "Lower bound — upstream CVEs may map to multiple CWEs but our schema stores "
            "only the primary. Use cve_search?cwe=<id> for the actual list."
        ),
    )
    total_mitigations: int | None = Field(
        default=None,
        description=(
            "Honest pre-truncation count of mitigation entries from MITRE. "
            "When the slim default is used, mitigations is capped to the first 3 — "
            "compare to total_mitigations to decide whether to refetch with include=full."
        ),
    )
    total_examples: int | None = Field(
        default=None,
        description=(
            "Honest pre-truncation count of example CVEs from MITRE. "
            "When the slim default is used, examples is capped to the first 3 — "
            "compare to total_examples to decide whether to refetch with include=full."
        ),
    )
    updated_at: str | None = Field(
        default=None,
        description="ISO 8601 timestamp of the last sync from MITRE's CSV catalog.",
    )


class CveResponse(BaseSuccessResponse):
    cve_id: str = Field(description="Canonical CVE identifier, e.g. 'CVE-2021-44228'.")
    summary: str | None = Field(
        default=None,
        description="Human-readable one-line summary built from severity, CVSS, KEV status, and EPSS.",
    )
    description: str | None = Field(
        default=None,
        description="Full vulnerability description sourced from NVD/MITRE/GHSA.",
    )
    severity: str | None = Field(
        default=None,
        description="CVSS v3 severity label: 'critical', 'high', 'medium', 'low', or 'none'.",
    )
    cvss_v3: float | None = Field(
        default=None,
        description="CVSS v3.x base score (0.0-10.0). Null if no CVSS data available.",
    )
    cvss_breakdown: dict | None = Field(
        default=None,
        description=(
            "Per-metric CVSS v3 breakdown (attack_vector, attack_complexity, "
            "privileges_required, user_interaction, scope, confidentiality, integrity, "
            "availability). Keys present only when parsed from vector string."
        ),
    )
    cwe_id: str | None = Field(
        default=None,
        description="Primary CWE identifier, e.g. 'CWE-502'. First CWE when multiple are assigned.",
    )
    epss: EpssInfo = Field(
        default_factory=EpssInfo,
        description="Exploit Prediction Scoring System: score (0.0-1.0 probability) and percentile (0.0-100.0).",
    )
    kev: KevInfo = Field(
        default_factory=KevInfo,
        description="CISA Known Exploited Vulnerabilities catalog: in_kev flag and date_added (ISO 8601).",
    )
    affected_products: list[dict] = Field(
        default_factory=list,
        description=(
            "CPE affected products. Truncated to first 20 by default. "
            "For GET /v1/cve/{cve_id}, use ?include_affected_products=true; "
            'for POST /v1/cves/bulk, set body field "include_affected_products": true.'
        ),
    )
    total_products: int = Field(
        default=0,
        description=(
            "Honest count of all affected products in the CVE database. Always present "
            "(emitted even when 0); matches len(affected_products) when not truncated."
        ),
    )
    published: str | None = Field(
        default=None,
        description="ISO 8601 publication timestamp from NVD/MITRE.",
    )
    modified: str | None = Field(
        default=None,
        description="ISO 8601 last-modified timestamp; advances on NVD/MITRE revisions.",
    )
    references: list[str] = Field(
        default_factory=list,
        description=(
            "Advisory URLs (vendor bulletins, patch commits, exploit PoCs, analysis writeups). "
            "Truncated to first 10 by default. For GET /v1/cve/{cve_id}, use ?include_full_references=true; "
            'for POST /v1/cves/bulk, set body field "include_full_references": true. Patch URL detection '
            "always runs against the full list — patch_url/patch_available are unaffected by the cap."
        ),
    )
    total_references: int = Field(
        default=0,
        description=(
            "Honest count of all references in the CVE database. Always present (emitted even when 0); "
            "matches len(references) when not truncated."
        ),
    )
    sources: list[str] = Field(
        default_factory=list,
        description=(
            "Data sources that wrote the CVE record itself: 'nvd', 'mitre', 'ghsa', 'osv'. "
            "EPSS and KEV are tracked separately — see the top-level epss.* and kev.* fields, "
            "not this list."
        ),
    )
    first_seen_source: str | None = Field(
        default=None,
        description="First source that introduced this CVE into the local DB (for provenance/auditing).",
    )
    first_seen_at: str | None = Field(
        default=None,
        description="ISO 8601 timestamp when this CVE was first ingested locally.",
    )
    patch_available: bool | None = Field(
        default=None,
        description=(
            "True when a vendor patch URL was detected in references (allowlisted vendor patterns). "
            "Null when enrichment was not requested."
        ),
    )
    patch_url: str | None = Field(
        default=None,
        description=(
            "First matched vendor patch/advisory URL (conservative: RedHat, MSRC, Apache, Ubuntu, "
            "Debian, GitHub commits, GitLab commits). Null when no match."
        ),
    )
    related_cves: list[dict] | None = Field(
        default=None,
        description=(
            "Up to 5 CVEs sharing affected products, ordered by severity DESC. "
            "Each item: {cve_id, severity, cvss_v3}. Null when enrichment was not requested."
        ),
    )


class GhsaAdvisory(BaseModel):
    ghsa_id: str = ""
    summary: str = ""
    severity: str | None = None
    published_at: str | None = None
    references: list[str] = Field(default_factory=list)


class GithubExploitSource(BaseModel):
    found: bool = False
    count: int = 0
    advisories: list[GhsaAdvisory] = Field(default_factory=list)
    error: str | None = None


class ShodanRefItem(BaseModel):
    id: str = ""
    description: str = ""
    source: str = ""


class ShodanRefSource(BaseModel):
    found: bool = False
    count: int = 0
    results: list[ShodanRefItem] = Field(default_factory=list)
    error: str | None = None


class ExploitSources(BaseModel):
    github: GithubExploitSource = Field(default_factory=GithubExploitSource)
    shodan_refs: ShodanRefSource = Field(default_factory=ShodanRefSource)


class Exploit(BaseModel):
    edb_id: int
    cve_id: str
    date_published: str | None = None
    author: str | None = None
    type: str | None = None
    platform: str | None = None
    url: str
    verified: bool = False
    description: str | None = None


class ExploitResponse(BaseSuccessResponse):
    model_config = {"extra": "ignore"}

    cve_id: str
    exploits_found: int = 0
    sources: ExploitSources = Field(default_factory=ExploitSources)
    has_public_exploit: bool = False
    exploits: list[Exploit] = Field(default_factory=list)
    summary: str = ""


class CveSearchItem(BaseModel):
    """Slim per-result shape for cve_search list items.

    Default cve_search response uses this shape (description / cvss_breakdown /
    affected_products / references / first_seen_* are dropped). Pass cve_search
    ?include=full to get the full CveResponse shape — extra="allow" lets the
    full-mode fields pass through without a schema fork.
    """

    model_config = {"extra": "allow"}

    cve_id: str = Field(description="Canonical CVE identifier, e.g. 'CVE-2021-44228'.")
    summary: str | None = Field(default=None, description="Human-readable one-line summary.")
    severity: str | None = Field(default=None, description="CVSS v3 severity label.")
    cvss_v3: float | None = Field(default=None, description="CVSS v3.x base score (0.0-10.0).")
    cwe_id: str | None = Field(default=None, description="Primary CWE identifier.")
    epss: EpssInfo = Field(default_factory=EpssInfo, description="EPSS score + percentile.")
    kev: KevInfo = Field(default_factory=KevInfo, description="CISA KEV status.")
    total_products: int = Field(default=0, description="Honest count of affected products in DB.")
    published: str | None = Field(default=None, description="ISO 8601 publication timestamp.")
    modified: str | None = Field(default=None, description="ISO 8601 last-modified timestamp.")
    sources: list[str] = Field(default_factory=list, description="Source feeds for this CVE row.")


class CveSearchResponse(BaseSuccessResponse):
    count: int = Field(default=0, description="Number of CVEs in this page (== len(results)). Capped by `limit`.")
    total: int = Field(
        default=0,
        description="Total CVE matches in the database for the query — the honest pre-pagination count.",
    )
    truncated: bool = Field(
        default=False,
        description="True when total > offset + count (more pages available — use next_offset).",
    )
    offset: int = Field(default=0, description="Offset of the first item in this page (echoed from input).")
    summary: str = Field(
        default="",
        description="One-line summary like '50 CVEs returned, 1234 total (product=nginx, severity=HIGH)'.",
    )
    results: list[CveSearchItem] = Field(default_factory=list, description="Per-CVE slim records — see CveSearchItem.")
    query_echo: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Echoed search filters with empty values stripped. Keys: product, vendor, severity, "
            "cwe_id, published_after, published_before, kev, epss_min, sort, limit, offset. "
            "Useful for verifying the parsed query matched the intent."
        ),
    )
    next_offset: int | None = Field(
        default=None,
        description="Offset to pass on the next page. Null when truncated=False (no more results).",
    )
    hint: SearchHint | None = Field(
        default=None,
        description="Pivot/refine hint emitted when the query returned 0 results or is overly broad.",
    )


class BulkCveItem(BaseModel):
    cve_id: str = Field(description="Echoed input CVE identifier (upper-cased + de-duplicated).")
    status: Literal["ok", "error", "not_found", "invalid_format"] = Field(
        default="ok",
        description=(
            "Per-item outcome. 'ok' = cve populated; 'not_found' = CVE not in local cve.db (likely "
            "reserved or post-cutoff); 'invalid_format' = ID failed CVE-YYYY-NNNN+ regex; "
            "'error' = lookup failed (transient)."
        ),
    )
    cve: CveResponse | None = Field(
        default=None,
        description="Full CVE record when status='ok'. Same shape as /v1/cve/{cve_id}.",
    )
    error: str | None = Field(
        default=None,
        description="Human-readable error message when status is 'error' or 'not_found'.",
    )


class BulkCveResponse(BaseSuccessResponse):
    results: list[BulkCveItem] = Field(
        default_factory=list,
        description="Per-CVE outcome list, preserving input order after upper-case de-duplication.",
    )
    total: int = Field(default=0, description="Total number of unique CVE IDs processed (== len(results)).")
    successful: int = Field(default=0, description="Count of items with status='ok'.")
    failed: int = Field(default=0, description="Count of items with status='error' (transient lookup failure).")
    timed_out: int = Field(default=0, description="Count of items that hit the per-CVE or overall timeout.")
    partial: bool = Field(default=False, description="True when at least one item failed, timed out, or was not_found.")
    summary: str = Field(default="", description="One-line aggregate summary (e.g. '45/50 CVEs found').")
