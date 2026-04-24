"""Pydantic response models for ContrastAPI endpoints."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, computed_field

# === Domain Report ===


class DomainReportResponse(BaseModel):
    domain: str
    dns: dict = Field(default_factory=dict)
    reverse_dns: dict = Field(default_factory=dict)
    whois: dict = Field(default_factory=dict)
    ssl: dict = Field(default_factory=dict)
    subdomains: dict = Field(default_factory=dict)
    certificates: dict = Field(default_factory=dict)
    email_security: dict = Field(default_factory=dict)
    waf: dict = Field(default_factory=dict)
    threat: dict = Field(default_factory=dict)
    risk: dict = Field(default_factory=dict)

    @computed_field
    @property
    def risk_score(self) -> int | None:
        """Top-level alias for risk.score — backward-compat with old docstring consumers."""
        s = self.risk.get("score")
        return s if isinstance(s, int) else None

    reputation: dict | None = None
    summary: str = ""
    verdict: Verdict | None = None

    model_config = {"extra": "ignore"}


# === DNS ===


class DnsResponse(BaseModel):
    domain: str
    records: dict
    summary: str | None = None


# === IP Lookup ===


class IpLookupResponse(BaseModel):
    ip: str
    ptr: str | None = None
    ports: list[int] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    vulns: list[str] = Field(default_factory=list)
    cpes: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    reputation: dict | None = None
    cloud_provider: str | None = None
    tor_exit: bool | None = None
    risk_score: int = 0
    summary: str = ""
    verdict: Verdict | None = None

    model_config = {"extra": "ignore"}


# === Threat Intelligence ===


class ThreatUrl(BaseModel):
    url: str = ""
    status: str = "unknown"
    threat: str = "unknown"
    date_added: str | None = None
    tags: list[str] = Field(default_factory=list)


class ThreatResponse(BaseModel):
    domain: str
    urlhaus_status: str
    urls_online: int = 0
    url_count: int = 0
    threat_types: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    urls: list[ThreatUrl] = Field(default_factory=list)
    summary: str = ""
    verdict: Verdict | None = None

    model_config = {"extra": "ignore"}


# === Wayback Machine / Web Archive ===


class WaybackSnapshot(BaseModel):
    timestamp: str
    date: str
    status: str
    mimetype: str
    url: str


class WaybackResponse(BaseModel):
    domain: str
    total_snapshots: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    years_online: int = 0
    snapshots: list[WaybackSnapshot] = Field(default_factory=list)
    archive_url: str = ""
    summary: str = ""
    warnings: list[str] = Field(default_factory=list)


# === Technology Fingerprinting ===


class TechItem(BaseModel):
    name: str
    category: str
    source: str
    version: str | None = None


class TechResponse(BaseModel):
    domain: str
    technologies: list[TechItem] = Field(default_factory=list)
    categories: dict[str, list[str]] = Field(default_factory=dict)
    count: int = 0
    summary: str = ""


# === SSL Certificate ===


class SslChainItem(BaseModel):
    subject: str = ""
    issuer: str = ""
    not_after: str = ""
    source: str = "handshake"


class SslResponse(BaseModel):
    domain: str
    valid: bool = False
    issuer: str = ""
    subject: str = ""
    not_before: str = ""
    not_after: str = ""
    days_remaining: int | None = None
    serial_number: str = ""
    signature_algorithm: str | None = None
    san: list[str] = Field(default_factory=list)
    protocol: str = ""
    cipher: dict = Field(default_factory=dict)
    chain: list[SslChainItem] = Field(default_factory=list)
    grade: str = "F"
    warnings: list[str] = Field(default_factory=list, max_length=10)
    summary: str = ""


# === Monitor (lightweight health check) ===


class MonitorResponse(BaseModel):
    domain: str
    is_up: bool
    ssl_days_remaining: int | None = None
    ssl_grade: str | None = None
    dns_a: list[str] | None = None
    dns_changed: bool | None = None
    risk_grade: str | None = None
    risk_score: int | None = None
    last_full_report: str | None = None
    summary: str = ""


# === Domain Vulnerabilities (tech stack CVEs) ===


class CveVulnItem(BaseModel):
    cve_id: str
    severity: str | None = None
    cvss_v3: float | None = None
    epss_score: float | None = None
    in_kev: bool = False


class TechVulnItem(BaseModel):
    technology: str
    version: str | None = None
    cve_count: int = 0
    cves: list[CveVulnItem] = Field(default_factory=list)


class VulnsResponse(BaseModel):
    domain: str
    technologies_scanned: int = 0
    total_cves: int = 0
    vulnerabilities: list[TechVulnItem] = Field(default_factory=list)
    summary: str = ""


# === IOC Enrichment ===


class IocResponse(BaseModel):
    indicator: str
    type: str
    threat_level: str = "none"
    sources: dict = Field(default_factory=dict)
    summary: str = ""
    verdict: Verdict | None = None

    model_config = {"extra": "ignore"}


# === Malware Hash ===


class HashResponse(BaseModel):
    hash: str
    hash_type: str
    found: bool = False
    malware_family: str | None = None
    file_type: str | None = None
    file_size: int | None = None
    first_seen: str | None = None
    tags: list[str] = Field(default_factory=list)
    file_name: str | None = None
    summary: str = ""


# === Password Breach Check ===


class PasswordResponse(BaseModel):
    hash_prefix: str
    found: bool = False
    breach_count: int = 0
    summary: str = ""

    model_config = {"extra": "ignore"}


# === Phishing / Malicious URL Check ===


class UrlhausHostDetail(BaseModel):
    found: bool = False
    urls_online: int = 0
    url_count: int = 0


class UrlhausUrlDetail(BaseModel):
    found: bool = False
    threat: str | None = None
    tags: list[str] = Field(default_factory=list)


class PhishingResponse(BaseModel):
    url: str
    host: str
    is_malicious: bool = False
    urlhaus_host: UrlhausHostDetail = Field(default_factory=UrlhausHostDetail)
    urlhaus_url: UrlhausUrlDetail = Field(default_factory=UrlhausUrlDetail)
    threat_level: str = "none"
    summary: str = ""


# === Bulk Domain Report ===


class BulkDomainItem(BaseModel):
    domain: str
    status: str = "ok"
    report: dict | None = None
    error: str | None = None


class BulkDomainResponse(BaseModel):
    results: list[BulkDomainItem] = Field(default_factory=list)
    total: int = 0
    successful: int = 0
    failed: int = 0
    timed_out: int = 0
    partial: bool = False
    summary: str = ""


# === Verdict ===


class Verdict(BaseModel):
    deterministic: bool
    falsifiable_fields: list[str]
    data_age_seconds: int | None = None
    sources_queried: list[str] = Field(default_factory=list)
    sources_unavailable: list[str] = Field(default_factory=list)
    completeness: Literal["complete", "partial", "minimal"] = "complete"


# === CVE ===


class EpssInfo(BaseModel):
    score: float | None = None
    percentile: float | None = None


class KevInfo(BaseModel):
    in_kev: bool = False
    date_added: str | None = None


class CveResponse(BaseModel):
    cve_id: str
    summary: str | None = None
    description: str | None = None
    severity: str | None = None
    cvss_v3: float | None = None
    cvss_breakdown: dict | None = None
    cwe_id: str | None = None
    epss: EpssInfo = Field(default_factory=EpssInfo)
    kev: KevInfo = Field(default_factory=KevInfo)
    affected_products: list[dict] = Field(default_factory=list)
    published: str | None = None
    modified: str | None = None
    references: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    first_seen_source: str | None = None
    first_seen_at: str | None = None
    verdict: Verdict | None = None
    patch_available: bool | None = None
    patch_url: str | None = None
    related_cves: list[dict] | None = None


# === Exploit Lookup ===


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


class ExploitDbItem(BaseModel):
    id: str = ""
    description: str = ""
    source: str = ""


class ExploitDbSource(BaseModel):
    found: bool = False
    count: int = 0
    results: list[ExploitDbItem] = Field(default_factory=list)
    error: str | None = None


class ExploitSources(BaseModel):
    github: GithubExploitSource = Field(default_factory=GithubExploitSource)
    exploitdb: ExploitDbSource = Field(default_factory=ExploitDbSource)


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


class ExploitResponse(BaseModel):
    model_config = {"extra": "ignore"}

    cve_id: str
    exploits_found: int = 0
    sources: ExploitSources = Field(default_factory=ExploitSources)
    has_public_exploit: bool = False
    exploits: list[Exploit] = Field(default_factory=list)
    verdict: Verdict | None = None
    summary: str = ""


# === ASN Lookup ===


class AsnPrefix(BaseModel):
    prefix: str


class AsnResponse(BaseModel):
    target: str
    resolved_ip: str | None = None
    asn: int
    asn_name: str = ""
    ipv4_prefixes: list[AsnPrefix] = Field(default_factory=list)
    ipv6_prefixes: list[AsnPrefix] = Field(default_factory=list)
    ipv4_count: int = 0
    ipv6_count: int = 0
    summary: str = ""
    warnings: list[str] = Field(default_factory=list)


# === WHOIS ===


class WhoisResponse(BaseModel):
    domain: str
    whois: dict
    summary: str = ""


# === Subdomains ===


class SubdomainsResponse(BaseModel):
    domain: str
    count: int = 0
    subdomains: list[str] = Field(default_factory=list)
    summary: str = ""
    sources: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    found_via_wordlist: int = 0
    found_via_crtsh: int = 0

    model_config = {"extra": "ignore"}


# === Certificate Transparency ===


class CertsResponse(BaseModel):
    domain: str
    total_certificates: int = 0
    certificates: list[dict] = Field(default_factory=list)
    summary: str = ""

    model_config = {"extra": "ignore"}


# === CVE Search / Recent / KEV ===


class CveSearchResponse(BaseModel):
    count: int = 0
    total: int = 0
    truncated: bool = False
    offset: int = 0
    summary: str = ""
    results: list[CveResponse] = Field(default_factory=list)
    query_echo: dict[str, Any] | None = None
    next_offset: int | None = None


# === Code Security ===


class CodeFinding(BaseModel):
    type: str = ""
    severity: str = "medium"
    line: int | None = None
    match: str | None = None
    description: str = ""
    remediation: str = ""


class CodeCheckResponse(BaseModel):
    findings: list[CodeFinding] = Field(default_factory=list)
    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    summary: str = ""


class HeaderFinding(BaseModel):
    header: str
    severity: str
    present: bool
    valid: bool = False
    value: str | None = None
    issues: list[str] = Field(default_factory=list)
    description: str = ""
    remediation: str = ""
    reference: str = ""


class ScanHeadersResponse(BaseModel):
    domain: str
    status_code: int = 0
    url: str = ""
    score: int = 0
    grade: str = "F"
    findings: list[HeaderFinding] = Field(default_factory=list)
    summary: str = ""
    headers_present: list[str] = Field(default_factory=list)
    headers_missing: list[str] = Field(default_factory=list)


class CheckHeadersResponse(BaseModel):
    findings: list[HeaderFinding] = Field(default_factory=list)
    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    summary: str = ""
    score: int = 0
    grade: str = "F"
    headers_present: list[str] = Field(default_factory=list)
    headers_missing: list[str] = Field(default_factory=list)


class DepFinding(BaseModel):
    package: str
    version: str | None = None
    cve_id: str
    severity: str = "unknown"
    cvss_v3: float | None = None
    description: str = ""
    epss_score: float | None = None
    in_kev: bool = False
    remediation: str = ""


class DependenciesResponse(BaseModel):
    findings: list[DepFinding] = Field(default_factory=list)
    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    summary: str = ""


# === Email MX ===


class MxRecord(BaseModel):
    priority: int
    host: str


class EmailSecurityDetail(BaseModel):
    spf: str | None = None
    dmarc: str | None = None
    dkim_selectors: list[str] = Field(default_factory=list)
    grade: str = "F"
    issues: list[str] = Field(default_factory=list)


class EmailMxResponse(BaseModel):
    domain: str
    mx_records: list[MxRecord] = Field(default_factory=list)
    mail_provider: str | None = None
    email_security: EmailSecurityDetail = Field(default_factory=EmailSecurityDetail)
    summary: str = ""


# === Phone Lookup ===


class PhoneFormat(BaseModel):
    e164: str = ""
    international: str = ""
    national: str = ""


class PhoneLookupResponse(BaseModel):
    valid: bool = False
    number: str = ""
    format: PhoneFormat | None = None
    country_code: str = ""
    country_name: str = ""
    type: str = "unknown"
    carrier: str = ""
    timezone: list[str] = Field(default_factory=list)
    summary: str = ""
    error: str | None = None

    model_config = {"extra": "ignore"}


# === Disposable Email ===


class DisposableResponse(BaseModel):
    email: str
    domain: str
    disposable: bool = False
    provider: str | None = None
    mx_disposable: bool = False
    risk_level: str = "low"
    mx_records: list[MxRecord] = Field(default_factory=list)
    summary: str = ""


# === Username Lookup ===


class UsernameMatch(BaseModel):
    platform: str = ""
    url: str = ""
    status: str = ""  # "found" | "not_found" | "rate_limited" | "blocked" | "timeout" | "error"


class UsernameLookupResponse(BaseModel):
    username: str = ""
    found_count: int = 0
    checked_count: int = 0
    results: list[UsernameMatch] = Field(default_factory=list)
    summary: str = ""
    error: str | None = None
    verdict: Verdict | None = None

    model_config = {"extra": "ignore"}


# === Audit (orchestrated domain intel) ===


class AuditResponse(BaseModel):
    domain: str
    report: dict = Field(default_factory=dict)
    technologies: dict = Field(default_factory=dict)
    live_headers: dict = Field(default_factory=dict)
    summary: str = ""

    model_config = {"extra": "ignore"}


# === Threat Report (orchestrated IP intel) ===


class ThreatReportResponse(BaseModel):
    ip: str
    enrichment: dict = Field(default_factory=dict)
    abuseipdb: dict = Field(default_factory=dict)
    shodan: dict = Field(default_factory=dict)
    asn: dict = Field(default_factory=dict)
    threat_level: str = "none"
    summary: str = ""

    model_config = {"extra": "ignore"}


# === Bulk CVE ===


class BulkCveItem(BaseModel):
    cve_id: str
    status: str = "ok"
    cve: dict | None = None
    error: str | None = None


class BulkCveResponse(BaseModel):
    results: list[BulkCveItem] = Field(default_factory=list)
    total: int = 0
    successful: int = 0
    failed: int = 0
    timed_out: int = 0
    partial: bool = False
    summary: str = ""


# === Bulk IOC ===


class BulkIocItem(BaseModel):
    indicator: str
    status: str = "ok"
    ioc: dict | None = None
    error: str | None = None


class BulkIocResponse(BaseModel):
    results: list[BulkIocItem] = Field(default_factory=list)
    total: int = 0
    successful: int = 0
    failed: int = 0
    timed_out: int = 0
    partial: bool = False
    summary: str = ""
