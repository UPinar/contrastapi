"""Pydantic response models for ContrastAPI endpoints."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


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
    reputation: dict | None = None
    summary: str = ""
    cached: bool | None = None

    model_config = {"extra": "allow"}


# === DNS ===

class DnsResponse(BaseModel):
    domain: str
    records: dict
    cached: bool | None = None


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
    summary: str = ""

    model_config = {"extra": "allow"}


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
    cached: bool | None = None


# === SSL Certificate ===

class SslChainItem(BaseModel):
    subject: str = ""
    issuer: str = ""
    not_after: str = ""


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
    summary: str = ""
    cached: bool | None = None


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

    model_config = {"extra": "allow"}


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

    model_config = {"extra": "allow"}


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
    summary: str = ""


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
    cvss_vector: str | None = None
    cvss_breakdown: dict | None = None
    cwe_id: str | None = None
    epss: EpssInfo = Field(default_factory=EpssInfo)
    kev: KevInfo = Field(default_factory=KevInfo)
    affected_products: list[dict] = Field(default_factory=list)
    published: str | None = None
    modified: str | None = None
    references: list[str] = Field(default_factory=list)


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


class ExploitDbItem(BaseModel):
    id: str = ""
    description: str = ""
    source: str = ""


class ExploitDbSource(BaseModel):
    found: bool = False
    count: int = 0
    results: list[ExploitDbItem] = Field(default_factory=list)


class ExploitSources(BaseModel):
    github: GithubExploitSource = Field(default_factory=GithubExploitSource)
    exploitdb: ExploitDbSource = Field(default_factory=ExploitDbSource)


class ExploitResponse(BaseModel):
    cve_id: str
    exploits_found: int = 0
    sources: ExploitSources = Field(default_factory=ExploitSources)
    has_public_exploit: bool = False
    summary: str = ""
    cached: bool | None = None


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
    cached: bool | None = None
