"""Response models for the website-scanner endpoints (Faz-2: /v1/scan + MCP contrast_scan).

Top level stays FLAT (S259/#38/#42 outputSchema contract): scalar fields plus
dict-typed section blocks. `_leanify_output_schema` (app/core/mcp_proxy.py)
post-processes the advertised MCP outputSchema on the wire, so no special
wiring is needed here — but do NOT nest typed sub-models at the top level.
"""

from pydantic import Field
from schemas import BaseSuccessResponse


class ScanResponse(BaseSuccessResponse):
    """Envelope for the ContrastScan engine result (scan/engine.py contrast_scan()).

    Mirrors the engine dict 1:1. The eleven section blocks are dict-typed —
    their inner shape ({score, max, details, ...}) is owned by the C binary
    (scanner/src/contrastscan.c); findings-enrichment fields come from
    scan/findings.py. `verdict` + `next_calls` are inherited from
    BaseSuccessResponse.
    """

    domain: str = Field(description="Scanned domain (lowercased, no scheme/path/port).")
    resolved_ip: str | None = Field(
        default=None,
        description=(
            "IP the scanner pinned for the scan (SSRF defense — DNS resolved once, "
            "pre-validated; '127.0.0.1' for the self-domain bypass)."
        ),
    )
    total_score: int = Field(default=0, description="Aggregate security score across all scanner modules.")
    max_score: int = Field(default=0, description="Maximum achievable score for the modules that ran.")
    grade: str = Field(default="", description="Letter grade (A-F) derived from total_score/max_score.")
    findings: list[dict] = Field(
        default_factory=list,
        description=(
            "Vulnerability findings sorted by severity (critical first). Each entry "
            "carries severity/category/title plus category-specific detail fields."
        ),
    )
    findings_count: dict[str, int] = Field(
        default_factory=dict,
        description="Finding counts keyed by severity: {critical, high, medium, low}.",
    )
    headers: dict = Field(default_factory=dict, description="HTTP security-headers module block (score, max, details).")
    ssl: dict = Field(default_factory=dict, description="SSL/TLS module block (score, max, details).")
    dns: dict = Field(default_factory=dict, description="DNS / email-security module block (score, max, details).")
    redirect: dict = Field(default_factory=dict, description="Redirect-chain module block (score, max, details).")
    disclosure: dict = Field(
        default_factory=dict, description="Information-disclosure module block (score, max, details)."
    )
    cookies: dict = Field(default_factory=dict, description="Cookie-flags module block (score, max, details).")
    dnssec: dict = Field(default_factory=dict, description="DNSSEC module block (score, max, details).")
    methods: dict = Field(default_factory=dict, description="HTTP-methods module block (score, max, details).")
    cors: dict = Field(default_factory=dict, description="CORS-policy module block (score, max, details).")
    html: dict = Field(default_factory=dict, description="HTML-hygiene module block (score, max, details).")
    csp_analysis: dict = Field(
        default_factory=dict, description="Deep CSP-analysis module block (score, max, details)."
    )
    enterprise: dict | None = Field(
        default=None,
        description=(
            "Present only for known enterprise domains: {is_enterprise, company, note} "
            "scoring caveat (large-org infra legitimately omits some checks)."
        ),
    )
    summary: str = Field(
        default="",
        description="One-line scan summary (reserved — empty until a summarizer is wired).",
    )

    model_config = {"extra": "ignore"}
