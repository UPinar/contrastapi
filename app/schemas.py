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


class FireholInfo(BaseModel):
    """FireHOL level1 blocklist check (Free tier and Pro)."""

    status: Literal["ok", "skipped", "unavailable"] = Field(
        description=(
            "'ok' = trie lookup succeeded; 'skipped' = private/reserved/loopback/link-local IP, "
            "not meaningful to check; 'unavailable' = FireHOL feed could not be fetched (be honest with agent)."
        ),
    )
    listed: bool = Field(
        default=False,
        description="True if the IP matches any range in firehol_level1 (known-bad aggregated blocklist).",
    )
    lists_matched: list[str] = Field(
        default_factory=list,
        description="List identifiers matched. Currently ['firehol_level1'] when listed, else empty.",
    )

    model_config = {"extra": "ignore"}


class AbuseIpdbInfo(BaseModel):
    """AbuseIPDB reputation check (Pro tier only)."""

    status: Literal["ok", "skipped", "rate_limited", "error", "pro_only"] = Field(
        description=(
            "'ok' = data fetched; 'skipped' = API key not configured; 'rate_limited' = AbuseIPDB "
            "quota exceeded; 'error' = transient HTTP/network failure; 'pro_only' = returned on "
            "Free tier as upsell hint (see upgrade_url)."
        ),
    )
    abuse_score: int | None = Field(
        default=None,
        description="AbuseIPDB confidence-of-abuse score (0-100). Only present when status='ok'.",
    )
    total_reports: int | None = Field(
        default=None,
        description="Number of reports submitted against this IP in the last 90 days.",
    )
    country: str | None = Field(
        default=None,
        description="ISO 3166-1 alpha-2 country code from AbuseIPDB geolocation (may differ from RIPE).",
    )
    isp: str | None = Field(
        default=None,
        description="ISP name as reported by AbuseIPDB.",
    )
    usage_type: str | None = Field(
        default=None,
        description="AbuseIPDB usage classification: 'Data Center/Web Hosting/Transit', 'ISP', 'Mobile ISP', etc.",
    )
    is_tor: bool | None = Field(
        default=None,
        description="AbuseIPDB's Tor exit flag (cross-reference with top-level tor_exit field).",
    )
    reason: str | None = Field(
        default=None,
        description="Human-readable reason string. Present when status is skipped/rate_limited/error/pro_only.",
    )
    upgrade_url: str | None = Field(
        default=None,
        description="Upgrade link returned when status='pro_only'.",
    )

    model_config = {"extra": "ignore"}


class ShodanRepInfo(BaseModel):
    """Shodan full API enrichment (Pro tier only). Richer than InternetDB fields at top level."""

    status: Literal["ok", "skipped", "restricted", "rate_limited", "error", "pro_only"] = Field(
        description=(
            "'ok' = data fetched; 'skipped' = API key not configured; 'restricted' = 403 "
            "(IP not available on free Shodan tier); 'rate_limited' = 429 quota exceeded; "
            "'error' = transient HTTP/network failure; 'pro_only' = returned on Free tier as upsell hint."
        ),
    )
    os: str | None = Field(
        default=None, description="Shodan-detected operating system (fingerprint-based, best-effort)."
    )
    org: str | None = Field(default=None, description="Organization name owning the IP per Shodan.")
    isp: str | None = Field(default=None, description="ISP per Shodan (may differ from AbuseIPDB/RIPE).")
    asn: str | None = Field(
        default=None, description="ASN string per Shodan (e.g. 'AS13335'); may differ from top-level asn int."
    )
    ports: list[int] = Field(
        default_factory=list,
        description="Open ports observed by Shodan full scan (superset of top-level InternetDB ports).",
    )
    vulns: list[str] = Field(default_factory=list, description="CVE IDs Shodan has associated with banners on this IP.")
    hostnames: list[str] = Field(default_factory=list, description="Hostnames observed pointing to this IP per Shodan.")
    city: str | None = Field(default=None, description="City name per Shodan geolocation.")
    country_name: str | None = Field(default=None, description="Country name per Shodan geolocation.")
    last_update: str | None = Field(
        default=None, description="ISO 8601 timestamp of Shodan's most recent data point for this IP."
    )
    reason: str | None = Field(
        default=None,
        description="Human-readable reason. Present when status is skipped/restricted/rate_limited/error/pro_only.",
    )
    upgrade_url: str | None = Field(default=None, description="Upgrade link returned when status='pro_only'.")

    model_config = {"extra": "ignore"}


class ReputationInfo(BaseModel):
    """Multi-source IP reputation. Sources present depend on tier (Free: firehol only; Pro: all three)."""

    firehol: FireholInfo | None = Field(
        default=None,
        description="FireHOL level1 blocklist membership. Available on Free tier.",
    )
    abuseipdb: AbuseIpdbInfo | None = Field(
        default=None,
        description="AbuseIPDB abuse confidence. Pro tier only; status='pro_only' stub on Free.",
    )
    shodan: ShodanRepInfo | None = Field(
        default=None,
        description="Shodan full API enrichment. Pro tier only; status='pro_only' stub on Free.",
    )

    model_config = {"extra": "ignore"}


class IpLookupResponse(BaseModel):
    ip: str = Field(description="Queried IP address (IPv4 or IPv6, echoed back verbatim).")
    ptr: str | None = Field(
        default=None,
        description="Reverse-DNS PTR record. Null when no PTR is published.",
    )
    asn: int | None = Field(
        default=None,
        description="Autonomous System Number from RIPE Stat network-info (e.g. 13335 for Cloudflare).",
    )
    asn_name: str | None = Field(
        default=None,
        max_length=256,
        description="Human-readable AS name from RIPE Stat as-overview (e.g. 'CLOUDFLARENET').",
    )
    country: str | None = Field(
        default=None,
        max_length=8,
        description="ISO 3166-1 alpha-2 country code from RIPE Stat rir-stats-country (RIR-allocated).",
    )
    ports: list[int] = Field(
        default_factory=list,
        description="Open ports observed by Shodan InternetDB (free, no API key; superseded by reputation.shodan.ports on Pro).",
    )
    hostnames: list[str] = Field(
        default_factory=list,
        description="Hostnames observed pointing to this IP per Shodan InternetDB.",
    )
    vulns: list[str] = Field(
        default_factory=list,
        description="CVE IDs Shodan InternetDB has associated with banners on this IP.",
    )
    cpes: list[str] = Field(
        default_factory=list,
        description="CPE 2.3 strings for services detected on this IP per Shodan InternetDB.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Shodan InternetDB classification tags (e.g. 'cdn', 'cloud', 'vpn', 'tor', 'self-signed').",
    )
    reputation: ReputationInfo | None = Field(
        default=None,
        description=(
            "Multi-source reputation. Free tier: firehol populated, abuseipdb/shodan return "
            "status='pro_only' upsell stubs. Pro tier: all three live."
        ),
    )
    cloud_provider: str | None = Field(
        default=None,
        description="Cloud provider name when IP is in a published cloud CIDR range (aws/gcp/azure/cloudflare/etc). Null otherwise.",
    )
    tor_exit: bool | None = Field(
        default=None,
        description="True if IP appears in the Tor Project's exit node list. Null when list fetch failed.",
    )
    risk_score: int = Field(
        default=0,
        description=(
            "Composite 0-100 risk score. Penalties: AbuseIPDB confidence (cap 60), Tor exit (+20), "
            "open ports (+2 each, cap 10). Bonuses: known cloud provider (-10), published PTR (-5)."
        ),
    )
    summary: str = Field(
        default="",
        description="One-line human-readable summary built from IP, PTR, ASN, country, ports, vulns.",
    )
    verdict: Verdict | None = Field(
        default=None,
        description="Falsifiability metadata: sources queried, sources unavailable, data age, completeness tier.",
    )

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
    subject: str = Field(
        default="",
        description="Subject DN of the chain certificate, e.g. 'CN=*.example.com'.",
    )
    issuer: str = Field(
        default="",
        description="Issuer DN of the chain certificate (the CA that signed it).",
    )
    not_after: str = Field(
        default="",
        description="Certificate's expiry timestamp (ISO 8601, UTC).",
    )
    source: str = Field(
        default="handshake",
        description="How this chain entry was discovered: 'handshake' (server-sent) or 'aia_fetch' (AIA chase-up).",
    )


class SslResponse(BaseModel):
    domain: str = Field(description="Queried domain (echoed). SNI-matched against the leaf cert.")
    valid: bool = Field(
        default=False,
        description=(
            "True when TLS handshake succeeded AND cert is unexpired AND chain verified. "
            "False on any failure (handshake error, expired, hostname mismatch, untrusted CA)."
        ),
    )
    issuer: str = Field(
        default="",
        description="Issuer DN of the leaf cert, e.g. \"CN=Let's Encrypt R3, O=Let's Encrypt, C=US\".",
    )
    subject: str = Field(
        default="",
        description="Subject DN of the leaf cert, e.g. 'CN=example.com'.",
    )
    not_before: str = Field(
        default="",
        description="Leaf cert's notBefore timestamp (ISO 8601, UTC) — earliest valid moment.",
    )
    not_after: str = Field(
        default="",
        description="Leaf cert's notAfter timestamp (ISO 8601, UTC) — expiry moment.",
    )
    days_remaining: int | None = Field(
        default=None,
        description=(
            "Days until leaf cert expires (negative if already expired). Null when not_after could not be parsed."
        ),
    )
    serial_number: str = Field(
        default="",
        description="Hex-encoded leaf cert serial number.",
    )
    signature_algorithm: str | None = Field(
        default=None,
        description="Signature algorithm name, e.g. 'sha256WithRSAEncryption', 'ecdsa-with-SHA384'.",
    )
    san: list[str] = Field(
        default_factory=list,
        description="Subject Alternative Names — all DNS names the cert is valid for (including CN when distinct).",
    )
    protocol: str = Field(
        default="",
        description=(
            "Negotiated TLS protocol version string as reported by OpenSSL: 'TLSv1.3', 'TLSv1.2', "
            "'TLSv1.1', 'TLSv1'. Empty on handshake failure. Grade F is forced for TLSv1/TLSv1.1."
        ),
    )
    cipher: dict = Field(
        default_factory=dict,
        description=(
            "Negotiated cipher suite dict: {name: str, version: str, bits: int}. Empty dict on handshake failure."
        ),
    )
    chain: list[SslChainItem] = Field(
        default_factory=list,
        description="Full cert chain from leaf upward (excluding system root). Includes AIA-fetched intermediates when needed.",
    )
    grade: Literal["A", "B", "C", "F"] = Field(
        default="F",
        description=(
            "Overall SSL configuration grade. 'A' (TLSv1.3 + >=30 days remaining), "
            "'B' (TLSv1.3 <30d OR TLSv1.2 healthy), 'C' (TLSv1.2 <14d OR TLSv1.3 <7d OR unknown protocol), "
            "'F' (TLSv1/TLSv1.1 OR expired). Canonical grader is _ssl_grade() in domain/recon.py; "
            "same helper powers /v1/domain/ ssl section (single source of truth)."
        ),
    )
    warnings: list[str] = Field(
        default_factory=list,
        max_length=10,
        description="Human-readable warnings: deprecated protocol, near-expiry, self-signed chain, weak signature algorithm, etc.",
    )
    summary: str = Field(
        default="",
        description="One-line human summary, e.g. 'example.com valid until 2026-07-04 (71 days) · TLSv1.3 · grade A'.",
    )


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


class CveResponse(BaseModel):
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
        description="Advisory URLs (vendor bulletins, patch commits, exploit PoCs, analysis writeups).",
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
    verdict: Verdict | None = Field(
        default=None,
        description="Falsifiability metadata: sources queried, sources unavailable, data age, completeness tier.",
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
    asn_name: str = Field(default="", max_length=256)
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
    e164: str = Field(
        default="",
        description="E.164 canonical format, e.g. '+14155552671'. Empty when parse fails.",
    )
    international: str = Field(
        default="",
        description="Human-readable international format, e.g. '+1 415-555-2671'.",
    )
    national: str = Field(
        default="",
        description="Domestic format for the number's country, e.g. '(415) 555-2671'.",
    )


class PhoneLookupResponse(BaseModel):
    valid: bool = Field(
        default=False,
        description="True only when phonenumbers.is_valid_number() passes (correct length, valid prefix for region).",
    )
    number: str = Field(
        default="",
        description="Echoed input, normalized. Prefer format.e164 for downstream lookups.",
    )
    format: PhoneFormat | None = Field(
        default=None,
        description="E.164, international, and national representations. Null when the number could not be parsed at all.",
    )
    country_code: str = Field(
        default="",
        description="ISO 3166-1 alpha-2 region code (e.g. 'US', 'TR'). Empty when region cannot be inferred.",
    )
    country_name: str = Field(
        default="",
        description="Full country name from libphonenumber geocoder. Empty when region cannot be inferred.",
    )
    type: str = Field(
        default="unknown",
        description=(
            "Phone number type: 'mobile', 'fixed_line', 'fixed_line_or_mobile', 'voip', "
            "'toll_free', 'premium_rate', 'shared_cost', 'personal_number', 'pager', 'uan', "
            "or 'unknown'."
        ),
    )
    carrier: str = Field(
        default="",
        description="Carrier/network name from libphonenumber carrier DB (best-effort, not all regions supported).",
    )
    timezone: list[str] = Field(
        default_factory=list,
        description="IANA timezone identifiers associated with the number's geography (e.g. ['America/Los_Angeles']).",
    )
    summary: str = Field(
        default="",
        description="One-line human summary, e.g. '+14155552671 United States mobile AT&T'.",
    )
    error: str | None = Field(
        default=None,
        description="Parse/validation error message. Null on successful lookups.",
    )

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
    platform: str = Field(
        default="",
        description="Platform identifier, e.g. 'github', 'twitter', 'reddit'.",
    )
    url: str = Field(
        default="",
        description="Canonical profile URL for this platform+username (may 200/redirect even when not_found).",
    )
    status: Literal["found", "not_found", "rate_limited", "blocked", "timeout", "error"] = Field(
        default="error",
        description=(
            "Per-platform outcome. 'found'/'not_found' are terminal factual answers. "
            "'rate_limited' (429), 'blocked' (403 — often Cloudflare/bot detection), "
            "'timeout' (network), and 'error' (5xx/other) are unavailability states — "
            "the platform's answer is unknown, NOT 'user does not exist'. "
            "Agents should treat these four as sources_unavailable, not negative evidence."
        ),
    )


class UsernameLookupResponse(BaseModel):
    username: str = Field(
        default="",
        description="Echoed normalized username (lowercased, validated against [a-z0-9._-]).",
    )
    found_count: int = Field(
        default=0,
        description="Number of platforms where status=='found'.",
    )
    checked_count: int = Field(
        default=0,
        description="Number of platforms actually checked (may be less than total platforms if early-exit).",
    )
    results: list[UsernameMatch] = Field(
        default_factory=list,
        description="Per-platform results, sorted: found first, then alphabetical by platform.",
    )
    summary: str = Field(
        default="",
        description="One-line human-readable summary, e.g. 'username \"x\" found on 6/20 platforms (3 unavailable)'.",
    )
    error: str | None = Field(
        default=None,
        description="Input validation error (empty username, invalid chars, too long). Null on successful lookups.",
    )
    verdict: Verdict | None = Field(
        default=None,
        description=(
            "Falsifiability metadata. sources_unavailable lists platforms where status was "
            "rate_limited/blocked/timeout/error so agents can distinguish 'absence' from 'unknown'."
        ),
    )

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
