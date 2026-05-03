"""Pydantic response models for domain/DNS/SSL/IP/audit endpoints."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, computed_field
from schemas import BaseSuccessResponse


class MxDnsRecord(BaseModel):
    """Single MX record embedded inside DomainReportResponse.dns.mx."""

    priority: int | None = Field(default=None, description="MX preference (lower = higher priority).")
    host: str | None = Field(default=None, description="MX hostname (trailing dot stripped).")


class SoaInfo(BaseModel):
    """SOA record embedded inside DomainDnsInfo.soa."""

    mname: str | None = Field(default=None, description="Primary nameserver (SOA MNAME).")
    rname: str | None = Field(default=None, description="Responsible party mailbox (SOA RNAME).")
    serial: int | None = Field(default=None, description="Zone serial number.")

    model_config = {"extra": "allow"}


class DomainDnsInfo(BaseModel):
    """DNS records per type. Keys are omitted (not null) when the lookup for that type fails."""

    a: list[str] | None = Field(default=None, description="A records (IPv4 addresses).")
    aaaa: list[str] | None = Field(default=None, description="AAAA records (IPv6 addresses).")
    mx: list[MxDnsRecord] | None = Field(default=None, description="MX records as {priority, host} list.")
    ns: list[str] | None = Field(default=None, description="NS records (nameserver hostnames).")
    txt: list[str] | None = Field(
        default=None,
        description=(
            "TXT records. By default in domain_report, filtered to security-relevant entries "
            "(SPF v=spf, DMARC v=DMARC, DKIM v=DKIM, MTA-STS v=STSv, TLS-RPT v=TLSRPTv). "
            "Pass ?include_all_txt=true to return every TXT including vendor verification strings."
        ),
    )
    total_txt_records: int | None = Field(
        default=None,
        description=(
            "Honest pre-filter TXT record count. Always emitted (domain_report, audit_domain, /v1/dns). "
            "Equals len(txt) when include_all_txt=true or on /v1/dns/{domain} (raw, unfiltered). "
            "0 when no TXT records exist. Null only when the field is absent (older cached entries)."
        ),
    )
    cname: list[str] | None = Field(default=None, description="CNAME records.")
    soa: SoaInfo | None = Field(default=None, description="SOA record (zone authority).")

    model_config = {"extra": "allow"}


class ReverseDnsInfo(BaseModel):
    ip: str | None = Field(
        default=None, description="Resolved IPv4 for the domain. Null when DNS fails or IP is private."
    )
    ptr: str | None = Field(
        default=None, description="PTR (reverse-DNS) hostname for the IP. Null when no PTR is published."
    )
    shared_hosting: bool | None = Field(
        default=None,
        description="True when PTR hostname differs from the queried domain (shared hosting signal). Absent when PTR lookup fails.",
    )

    model_config = {"extra": "allow"}


class WhoisInfoEmbedded(BaseModel):
    """WHOIS subset embedded in the domain report. Fields are best-effort regex extracts from the raw WHOIS text."""

    registrar: str | None = Field(default=None, description="Registrar name as reported by the WHOIS server.")
    creation_date: str | None = Field(default=None, description="Domain creation date (format depends on registrar).")
    expiry_date: str | None = Field(default=None, description="Domain expiry date (format depends on registrar).")
    updated_date: str | None = Field(default=None, description="Last-updated timestamp from WHOIS.")
    name_servers: list[str] | None = Field(default=None, description="Authoritative nameservers per WHOIS.")
    status: str | list[str] | None = Field(
        default=None,
        description="EPP domain status (e.g. 'clientTransferProhibited'). String or list depending on registrar.",
    )
    raw_length: int | None = Field(default=None, description="Byte length of raw WHOIS response (sanity indicator).")
    error: str | None = Field(
        default=None,
        description="Populated when the WHOIS TCP query failed (e.g. no WHOIS server for TLD, socket timeout).",
    )

    model_config = {"extra": "allow"}


class SslInfoEmbedded(BaseModel):
    """SSL subset embedded in the domain report. See top-level SslResponse for live SSL endpoint shape."""

    common_name: str | None = Field(default=None, description="Leaf cert Subject CN.")
    issuer: str | None = Field(default=None, description="Leaf cert issuer organization name.")
    not_before: str | None = Field(default=None, description="notBefore timestamp (ISO 8601 / UTC).")
    not_after: str | None = Field(default=None, description="notAfter (expiry) timestamp (ISO 8601 / UTC).")
    serial_number: str | None = Field(default=None, description="Hex-encoded cert serial number.")
    version: int | str | None = Field(
        default=None,
        description="X.509 version as returned by the ssl module (int 3 for v3; empty string on some parse paths).",
    )
    tls_version: str | None = Field(
        default=None,
        description="Negotiated TLS protocol (e.g. 'TLSv1.3', 'TLSv1.2'). Empty on handshake failure.",
    )
    alpn: str | None = Field(default=None, description="Negotiated ALPN protocol (e.g. 'http/1.1', 'h2').")
    san: list[str] | None = Field(default=None, description="Subject Alternative Names.")
    days_remaining: int | None = Field(default=None, description="Days until expiry. Negative when already expired.")
    grade: Literal["A", "B", "C", "D", "F"] | None = Field(
        default=None,
        description="SSL grade. A/B/C: cert_valid AND TLS modern. D: cert readable but invalid (self-signed, hostname mismatch, untrusted root). F: probe failure, expired, or legacy TLS.",
    )
    cert_valid: bool | None = Field(
        default=None,
        description="True only when chain verified AND hostname matches AND not expired. False when cert is readable but fails one or more validation checks (see validation_errors).",
    )
    validation_errors: list[str] | None = Field(
        default=None,
        description="Canonical validation failure tags when cert_valid is False. Values: 'expired', 'self_signed', 'hostname_mismatch', 'untrusted_root', 'chain_incomplete'. Empty/null when cert_valid is True.",
    )
    error: str | None = Field(
        default=None,
        description="Populated only on probe failure (timeout, connection refused, no port 443). Cert validation issues are NOT errors here — see cert_valid + validation_errors instead.",
    )

    model_config = {"extra": "allow"}


class SubdomainsInfo(BaseModel):
    subdomains: list[str] | None = Field(default=None, description="Sorted unique subdomain list.")
    count: int | None = Field(default=None, description="Total subdomains discovered.")
    sources: list[str] | None = Field(
        default=None,
        description="Sources that produced hits (subset of ['wordlist', 'crt_sh']).",
    )
    found_via_wordlist: int | None = Field(default=None, description="Count discovered via DNS brute-force wordlist.")
    found_via_crtsh: int | None = Field(default=None, description="Count discovered via crt.sh CT log query.")
    warnings: list[str] | None = Field(
        default=None,
        description="Non-fatal warnings (e.g. 'crt.sh timeout', 'result truncated').",
    )
    summary: str | None = Field(default=None, description="One-line human-readable summary.")

    model_config = {"extra": "allow"}


class CertificateSummary(BaseModel):
    """Single cert entry inside CertificatesInfo.certificates."""

    issuer: str | None = Field(default=None, description="Cert issuer CN or O.")
    not_before: str | None = Field(default=None, description="notBefore timestamp.")
    not_after: str | None = Field(default=None, description="notAfter timestamp.")
    common_name: str | None = Field(default=None, description="Cert Subject CN.")

    model_config = {"extra": "allow"}


class CertificatesInfo(BaseModel):
    total_certificates: int | None = Field(default=None, description="Total cert count from crt.sh (pre-dedup).")
    certificates: list[CertificateSummary] | None = Field(
        default=None,
        description="Up to CT_MAX_CERTS recent unique certs (deduped by serial).",
    )
    error: str | None = Field(
        default=None,
        description=(
            "Populated when the crt.sh fetch failed (e.g. 'crt_sh_timeout', "
            "'crt_sh_rate_limited', 'crt_sh_unavailable'). Distinguishes 'no certs found' "
            "from 'fetch failed'; risk_score skips the CT factor when this is set."
        ),
    )
    crtsh_status: Literal["ok", "timeout", "rate_limited", "unavailable", "error"] | None = Field(
        default=None,
        description=(
            "Status of the crt.sh fetch behind certificates. Mirrors subdomains.crtsh_status "
            "so both halves of a domain_report agree on whether CT logs delivered. 'ok' means "
            "the upstream responded — total_certificates=0 with status='ok' is a real empty "
            "result. Anything else (timeout / rate_limited / unavailable / error) means the "
            "upstream did not deliver and the cert list may be missing entries."
        ),
    )

    model_config = {"extra": "allow"}


class ThreatUrlEntry(BaseModel):
    """Single offending URL entry inside ThreatInfo.urls."""

    url: str | None = Field(default=None, description="Offending URL observed in URLhaus.")
    status: str | None = Field(default=None, description="URLhaus status for this URL ('online', 'offline').")
    threat: str | None = Field(default=None, description="Threat class (e.g. 'malware_download', 'phishing').")
    date_added: str | None = Field(default=None, description="When URLhaus first saw this URL.")
    tags: list[str] | None = Field(default=None, description="Tags assigned by URLhaus (malware family, kit, etc.).")

    model_config = {"extra": "allow"}


class ThreatInfo(BaseModel):
    urlhaus_status: Literal["clean", "listed", "error", "skipped"] | None = Field(
        default=None,
        description="URLhaus lookup outcome. 'skipped' in lite mode; 'error' on API failure (treat as unavailable, not clean).",
    )
    url_count: int | None = Field(default=None, description="Total URLs URLhaus has seen for this domain.")
    urls_online: int | None = Field(default=None, description="Subset of url_count currently marked online.")
    threat_types: list[str] | None = Field(default=None, description="Deduped list of threat classes across all URLs.")
    tags: list[str] | None = Field(default=None, description="Deduped list of tags (up to 20).")
    urls: list[ThreatUrlEntry] | None = Field(default=None, description="Up to 20 offending URL entries.")

    model_config = {"extra": "allow"}


class EmailSecurityInfo(BaseModel):
    spf: str | None = Field(default=None, description="SPF record string (v=spf1 ...). Null when no SPF is published.")
    dmarc: str | None = Field(
        default=None,
        description="DMARC record string (v=DMARC1; p=...; ...). Null when no DMARC record is published at _dmarc.<domain>.",
    )
    dkim_selectors: list[str] | None = Field(
        default=None,
        description="DKIM selectors that responded to probing (e.g. ['google', 'selector1']). Empty when none found.",
    )
    dkim_status: Literal["verified", "unverifiable"] | None = Field(
        default=None,
        description=(
            "Honest evidence label for DKIM. 'verified' when at least one selector responded "
            "(see dkim_selectors). 'unverifiable' when no probed selector matched — DKIM keys "
            "live at arbitrary operator-chosen selector names, so absence under common+date-based "
            "probes does not prove absence. Grade does not penalize 'unverifiable'."
        ),
    )
    grade: Literal["A", "B", "C", "F"] | None = Field(
        default=None,
        description=(
            "Email-auth grade. When DKIM is verified: A=SPF+DMARC+DKIM, B=2 of 3, C=1 of 3. "
            "When DKIM is unverifiable: A=SPF+DMARC, B=one of SPF/DMARC, F=neither — DKIM "
            "absence is not penalized because it cannot be proven without selector knowledge."
        ),
    )
    issues: list[str] | None = Field(
        default=None, description="Human-readable issues (missing SPF, weak DMARC policy, etc.)."
    )

    model_config = {"extra": "allow"}


class WafInfo(BaseModel):
    detected: list[str] | None = Field(
        default=None,
        description="WAF product names detected from response headers (e.g. ['Cloudflare', 'AWS CloudFront']).",
    )
    waf_present: bool | None = Field(default=None, description="True when `detected` is non-empty.")

    model_config = {"extra": "allow"}


class RiskFactor(BaseModel):
    name: str | None = Field(
        default=None, description="Factor label (e.g. 'SSL/TLS', 'Email Security', 'IP Reputation')."
    )
    score: int | None = Field(default=None, description="Points earned by this factor (can be negative for penalties).")
    max: int | None = Field(default=None, description="Maximum possible points for this factor.")
    detail: str | None = Field(default=None, description="Human-readable justification for the score.")


class RiskInfo(BaseModel):
    score: int | None = Field(default=None, description="Cumulative risk score (0-100).")
    max_score: int | None = Field(
        default=None,
        description=(
            "Maximum achievable score (100 by default; drops by the corresponding factor's max "
            "when an upstream source fails — e.g. crt.sh timeout excludes the CT factor and "
            "max_score becomes 90, so grade is computed against the available signals)."
        ),
    )
    grade: Literal["A", "B", "C", "D", "F"] | None = Field(default=None, description="Letter grade derived from score.")
    factors: list[RiskFactor] | None = Field(
        default=None, description="Per-factor scoring breakdown (typically 8-9 factors)."
    )

    model_config = {"extra": "allow"}


class DomainReputationInfo(BaseModel):
    """Reputation block inside DomainReportResponse (IP-level enrichment of the resolved A record).

    Differs from IpLookupResponse.reputation: no firehol block here (FireHOL is IP-only).
    """

    abuseipdb: AbuseIpdbInfo | None = Field(
        default=None,
        description="AbuseIPDB enrichment for the domain's resolved IP. Pro tier only — free tier returns {status:'pro_only', reason, upgrade_url} stub.",
    )
    shodan: ShodanRepInfo | None = Field(
        default=None,
        description="Shodan enrichment for the domain's resolved IP. Pro tier only — free tier returns {status:'pro_only', reason, upgrade_url} stub.",
    )

    model_config = {"extra": "allow"}


class DomainReportResponse(BaseSuccessResponse):
    domain: str = Field(description="Queried domain (echoed, lowercased).")
    dns: DomainDnsInfo | None = Field(
        default=None,
        description="Forward DNS record set (A/AAAA/MX/NS/TXT/CNAME/SOA). Empty dict when all lookups fail.",
    )
    reverse_dns: ReverseDnsInfo | None = Field(
        default=None,
        description="Reverse-DNS resolution of the domain's primary IPv4 (PTR + shared-hosting signal).",
    )
    whois: WhoisInfoEmbedded | None = Field(
        default=None,
        description="WHOIS extract (registrar, dates, nameservers, EPP status). Skipped in lite mode. Error branch populates `error`.",
    )
    ssl: SslInfoEmbedded | None = Field(
        default=None,
        description="SSL/TLS certificate subset (CN, issuer, validity, grade). Full shape at top-level /v1/ssl/{domain}.",
    )
    subdomains: SubdomainsInfo | None = Field(
        default=None,
        description="Subdomain enumeration (wordlist + crt.sh). Skipped in lite mode (returns {subdomains:[], count:0}).",
    )
    certificates: CertificatesInfo | None = Field(
        default=None,
        description="Certificate transparency log entries from crt.sh. Skipped in lite mode.",
    )
    email_security: EmailSecurityInfo | None = Field(
        default=None,
        description="SPF/DMARC/DKIM posture of the domain (email authentication grade).",
    )
    waf: WafInfo | None = Field(
        default=None,
        description="WAF detection from live response headers (Cloudflare, AWS CloudFront, Akamai, Sucuri, etc.).",
    )
    threat: ThreatInfo | None = Field(
        default=None,
        description="URLhaus threat intelligence for the domain (malware / phishing URL listings). Skipped in lite mode.",
    )
    risk: RiskInfo | None = Field(
        default=None,
        description="Composite risk scoring (0-100) with per-factor breakdown — drives the top-level risk_score alias.",
    )

    @computed_field(
        description=(
            "DEPRECATED — use `risk.score` instead. Top-level alias for risk.score, "
            "retained for backward compatibility. Will be removed in v2.0.0 "
            "(Sunset: 2026-09-01). Routes that emit DomainReportResponse return "
            "RFC 8594 `Deprecation: true` + `Sunset` headers."
        )
    )
    @property
    def risk_score(self) -> int | None:
        if self.risk is None:
            return None
        s = self.risk.score if hasattr(self.risk, "score") else None
        return s if isinstance(s, int) else None

    reputation: DomainReputationInfo | None = Field(
        default=None,
        description=(
            "IP-level reputation of the domain's resolved A record. "
            "Absent in lite mode AND when no A record resolves. "
            "On Free tier inner blocks carry {status:'pro_only'} stubs (agents should not treat as clean)."
        ),
    )
    summary: str = Field(
        default="", description="One-line human summary aggregating IP, grade, WAF, and subdomain count."
    )

    model_config = {"extra": "ignore"}


class DnsResponse(BaseSuccessResponse):
    domain: str = Field(description="Queried domain (lowercased, no scheme).")
    records: DomainDnsInfo = Field(
        description=(
            "DNS records keyed by type (a, aaaa, mx, ns, txt, cname, soa). Keys are omitted "
            "(not null) when the lookup for that type fails. Same shape as DomainReportResponse.dns."
        ),
    )
    summary: str | None = Field(
        default=None,
        description="One-line human-readable record summary (e.g. 'A, MX, TXT records for example.com').",
    )


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


class VulnInfo(BaseModel):
    """Severity-enriched CVE entry attached to /v1/ip and /v1/threat_report.

    Phase 2 IP enrichment (v1.16.0 BREAKING): Shodan InternetDB returns a flat
    list of CVE IDs with no severity context, forcing agents to fan out
    cve_lookup calls for triage. We resolve severity + cvss_v3 against the
    local cve.db in a single SQL batch so the agent can prioritise without
    extra round-trips. Unknown CVEs are emitted with severity='UNKNOWN' /
    cvss_v3=null so the ID is preserved (the agent must not infer 'benign'
    from the absence of a row).
    """

    cve_id: str = Field(description="CVE identifier (e.g. 'CVE-2021-44228').")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] = Field(
        description=(
            "NVD CVSS v3 severity bucket from local cve.db. 'UNKNOWN' when the CVE "
            "is not in our database (NVD may not have classified it yet, or the ID "
            "is reserved). Treat UNKNOWN as 'do not assume benign — call cve_lookup "
            "for fresh upstream data.'"
        ),
    )
    cvss_v3: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="CVSS v3 base score (0.0-10.0). Null when severity='UNKNOWN' or NVD has no v3 score.",
    )


class IpEnrichmentInfo(BaseModel):
    """Shodan InternetDB enrichment subset (free, no API key) embedded in /v1/threat_report.

    Mirrors the {ports, hostnames, vulns, cpes, tags} block at the top of ip_lookup,
    plus an internetdb_status field that surfaces the upstream fetch outcome —
    extracted as a sub-model so MCP clients see a typed schema instead of an opaque dict slot.
    """

    ports: list[int] = Field(
        default_factory=list,
        description="Open ports observed by Shodan InternetDB. Empty on upstream failure (treat as 'no data', not 'closed').",
    )
    hostnames: list[str] = Field(
        default_factory=list,
        description="Hostnames Shodan InternetDB has observed pointing to this IP.",
    )
    vulns: list[VulnInfo] = Field(
        default_factory=list,
        description=(
            "CVEs Shodan InternetDB has associated with banners on this IP, enriched with "
            "severity + cvss_v3 from local cve.db (Phase 2 IP enrichment, v1.16.0 BREAKING). "
            "Pre-1.16 this was a flat list[str] of CVE IDs. Unknown CVEs emit severity='UNKNOWN'."
        ),
    )
    cpes: list[str] = Field(
        default_factory=list,
        description="CPE 2.3 strings for services detected on this IP per Shodan InternetDB.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Shodan InternetDB classification tags (e.g. 'cdn', 'cloud', 'vpn', 'tor', 'self-signed').",
    )
    internetdb_status: Literal["ok", "error"] | None = Field(
        default=None,
        description="Outcome of the InternetDB fetch. 'error' indicates upstream failure; absent on cached/legacy paths.",
    )

    model_config = {"extra": "ignore"}


class ReputationUpgradeHint(BaseModel):
    """Compact pointer that replaces the verbose pro_only sub-stubs for Free tier.

    Bug I4: previously the abuseipdb/shodan slots carried full Pydantic models
    with every field null + a status='pro_only' marker — ~150 tokens of pure
    negative space per Free-tier ip_lookup response. The verdict block already
    lists those sources in sources_unavailable on Free; this hint just points
    callers at the upgrade page in one line.
    """

    pro_only_sources: list[str] = Field(default_factory=list)
    upgrade_url: str | None = Field(default=None)
    reason: str | None = Field(default=None)


class ReputationInfo(BaseModel):
    """Multi-source IP reputation. Sources present depend on tier (Free: firehol only; Pro: all three)."""

    firehol: FireholInfo | None = Field(
        default=None,
        description="FireHOL level1 blocklist membership. Available on Free tier.",
    )
    abuseipdb: AbuseIpdbInfo | None = Field(
        default=None,
        description="AbuseIPDB abuse confidence. Pro tier only — omitted from the response on Free.",
    )
    shodan: ShodanRepInfo | None = Field(
        default=None,
        description="Shodan full API enrichment. Pro tier only — omitted from the response on Free.",
    )
    # Bug I4: free tier replaces abuseipdb/shodan stubs with this single hint.
    upgrade: ReputationUpgradeHint | None = Field(
        default=None,
        description="Free-tier-only pointer to the Pro-only sources that were skipped.",
    )

    model_config = {"extra": "ignore"}


class IpLookupResponse(BaseSuccessResponse):
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
    vulns: list[VulnInfo] = Field(
        default_factory=list,
        description=(
            "CVEs Shodan InternetDB has associated with banners on this IP, enriched "
            "with severity + cvss_v3 from local cve.db (Phase 2 IP enrichment, v1.16.0 "
            "BREAKING). Pre-1.16 this was a flat list[str] of CVE IDs. Order is "
            "preserved from Shodan (meaningful — Shodan ranks confidence). Unknown "
            "CVEs emit severity='UNKNOWN'; do NOT infer 'benign' from UNKNOWN."
        ),
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
        description=(
            "Cloud provider name resolved via two-tier detection: (1) published cloud CIDR ranges "
            "(AWS/GCP/Cloudflare), (2) ASN-to-provider map fallback for anycast/public-service IPs "
            "outside published ranges (e.g. 8.8.8.8 → AS15169 → 'Google'). Null when neither matches. "
            "Always present in response (route emits null-explicit so agents can disambiguate "
            "'not detected' from 'field absent')."
        ),
    )
    is_datacenter: bool = Field(
        default=False,
        description=(
            "True if IP is hosted on a known datacenter / cloud provider. Detection: (1) "
            "cloud_provider populated (CIDR or ASN map hit covering AWS/GCP/Cloudflare/"
            "DigitalOcean/Hetzner/OVH/Linode/Vultr/Microsoft Azure), (2) ASN in tier-1 "
            "datacenter set (adds Oracle/Alibaba/Tencent on top of the cloud_provider map). "
            "Use for Nuclei matchers + bug-bounty triage where datacenter targets warrant "
            "different scan policy than residential IPs. Always present — never null."
        ),
    )
    tor_exit: bool = Field(
        default=False,
        description=(
            "True if IP appears in the Tor Project's exit node list. False when not listed or when "
            "the upstream list fetch failed (check verdict.sources_unavailable for 'tor' to "
            "distinguish). Always present in response — never null."
        ),
    )
    risk_score: int = Field(
        default=0,
        description=(
            "Composite 0-100 risk score (v1.17.0 formula). Additive components: ports "
            "(10 * min(count, 5) = 0-50), tor_exit (+30), firehol.listed (+20), AbuseIPDB "
            "confidence (round(15 * score / 100) = 0-15), is_datacenter (+10), known vulns "
            "(5 * min(count, 4) = 0-20). Datacenter membership now adds risk (was a -10 "
            "trust bonus pre-1.17). Use severity_label for thresholding."
        ),
    )
    severity_label: Literal["low", "medium", "high", "critical"] = Field(
        default="low",
        description=(
            "Coarse risk band derived from risk_score (>=75 critical, >=50 high, >=25 medium, "
            "else low). Use this for Nuclei matchers and MCP agent triage when you don't want "
            "to re-implement the threshold logic; risk_score is the canonical numeric source."
        ),
    )
    summary: str = Field(
        default="",
        description="One-line human-readable summary built from IP, PTR, ASN, country, ports, vulns.",
    )

    model_config = {"extra": "ignore"}


class ThreatUrl(BaseModel):
    url: str = ""
    status: str = "unknown"
    threat: str = "unknown"
    date_added: str | None = None
    tags: list[str] = Field(default_factory=list)


class ThreatResponse(BaseSuccessResponse):
    domain: str
    urlhaus_status: str
    urls_online: int = 0
    url_count: int = 0
    threat_types: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    urls: list[ThreatUrl] = Field(default_factory=list)
    summary: str = ""

    model_config = {"extra": "ignore"}


class WaybackSnapshot(BaseModel):
    timestamp: str
    date: str
    status: str
    mimetype: str
    url: str


class WaybackResponse(BaseSuccessResponse):
    domain: str
    status: Literal["ok", "unavailable"] = Field(
        default="ok",
        description=(
            "'ok' when the CDX request returned a parseable response (even if zero snapshots); "
            "'unavailable' when CDX timed out, rate-limited, 5xx-failed, or returned malformed "
            "data. On 'unavailable' total_snapshots is omitted (unknown) — DO NOT interpret "
            "absence as zero. See warnings[] for the specific cdx_* error code."
        ),
    )
    total_snapshots: int | None = Field(
        default=None,
        description=(
            "Snapshot count when status='ok'. Omitted (null) when status='unavailable' — the "
            "count is unknown, NOT zero. Use the archive_url to check manually in that case."
        ),
    )
    first_seen: str | None = None
    last_seen: str | None = None
    years_online: int | None = Field(
        default=None,
        description="Years between first_seen and last_seen. Omitted when status='unavailable'.",
    )
    snapshots: list[WaybackSnapshot] = Field(default_factory=list)
    archive_url: str = ""
    summary: str = ""
    warnings: list[str] = Field(default_factory=list)


class TechItem(BaseModel):
    name: str
    category: str
    source: str
    version: str | None = None


class TechResponse(BaseSuccessResponse):
    domain: str
    technologies: list[TechItem] = Field(default_factory=list)
    categories: dict[str, list[str]] = Field(default_factory=dict)
    count: int = 0
    summary: str = ""


class RobotsRules(BaseModel):
    """Per-User-agent rule block parsed from a robots.txt file."""

    model_config = {"extra": "allow"}

    allow: list[str] = Field(
        default_factory=list,
        description="Paths the target site explicitly Allows for this UA. Each entry is verbatim from robots.txt (`_untrusted` — DO NOT execute or shell-out).",
    )
    disallow: list[str] = Field(
        default_factory=list,
        description="Paths the target site Disallows for this UA. Empty Disallow per spec means allow-all.",
    )
    crawl_delay: float | None = Field(
        default=None,
        description="Crawl-delay seconds for this UA, if specified.",
    )


class RobotsTxtResponse(BaseSuccessResponse):
    """Parsed robots.txt for the target domain."""

    domain: str = Field(description="Queried domain (echoed).")
    fetched_url: str = Field(description="Final URL we fetched, e.g. https://example.com/robots.txt.")
    status_code: int = Field(
        description="HTTP status returned by the target. 404 = no robots.txt = implicit allow-all."
    )
    sitemaps: list[str] = Field(
        default_factory=list,
        description="`Sitemap:` directives (URLs). Global, not per-UA. `_untrusted` — fetch only via SSRF-safe path.",
    )
    user_agents: dict[str, RobotsRules] = Field(
        default_factory=dict,
        description="Per-`User-agent:` rule blocks. Wildcard `*` is one of the keys when present.",
    )
    host: str | None = Field(
        default=None,
        description="`Host:` directive (Yandex extension), if present. `_untrusted`.",
    )
    truncated: bool = Field(
        default=False,
        description="True if the robots.txt body exceeded ROBOTS_MAX_BYTES and was truncated before parsing.",
    )
    summary: str = Field(default="", description="One-line human-readable summary.")


class EmailVerifyResponse(BaseSuccessResponse):
    """Combined email validation: syntax + MX + disposable + role + free-provider.

    What we DO NOT do: SMTP `RCPT TO` deliverability probing. Hunter.io-style
    mailbox-existence checks are an ethical grey area (mailbox enumeration +
    Hetzner ToS risk on unsolicited SMTP from datacenter IPs). Use Hunter.io /
    NeverBounce / ZeroBounce when you need that specific signal.
    """

    email: str = Field(description="Echo of the input email (lowercased, control-chars stripped).")
    domain: str = Field(description="The domain part (after `@`).")
    syntax_valid: bool = Field(
        description="True iff the email passes the same RFC-aware regex used by /v1/email/disposable."
    )
    mx_records: list[MxDnsRecord] = Field(
        default_factory=list,
        description="MX records for the domain, sorted by priority. Empty list = no MX = mail cannot be delivered.",
    )
    disposable: bool = Field(
        default=False,
        description="True iff the domain matches our disposable-provider database OR a known disposable MX host.",
    )
    disposable_provider: str | None = Field(
        default=None,
        description="Name of the disposable provider when `disposable=true` (e.g. 'Mailinator'). Null otherwise.",
    )
    role_address: bool = Field(
        default=False,
        description="True iff the local-part is a generic role address (admin@, info@, support@, etc.) — not a specific person.",
    )
    role_type: str | None = Field(
        default=None,
        description="The role keyword when role_address=true (e.g. 'admin', 'noreply'). Null otherwise.",
    )
    free_provider: bool = Field(
        default=False,
        description="True iff the domain is a known consumer-mailbox provider (gmail/outlook/yahoo/proton/icloud). B2B detection signal.",
    )
    summary: str = Field(default="", description="One-line human-readable summary.")


class RedirectHop(BaseModel):
    """Single hop in a redirect chain."""

    model_config = {"extra": "allow"}

    url: str = Field(
        description="The URL fetched at this hop (absolute, control-chars stripped). `_untrusted` — DO NOT execute or shell-out."
    )
    status_code: int = Field(description="HTTP status returned at this hop.")
    location: str | None = Field(
        default=None,
        description="Resolved Location header for this hop's response (absolute, against this hop's final URL). None when status is not a redirect or no Location was sent. `_untrusted`.",
    )
    latency_ms: int = Field(description="Round-trip time in milliseconds for this single hop fetch.")


class RedirectChainResponse(BaseSuccessResponse):
    """Manual hop-by-hop walk through HTTP redirects. SSRF-guarded at each hop."""

    start_url: str = Field(description="Echo of the input URL after sanitisation.")
    final_url: str = Field(
        description="The URL of the terminal (non-redirect) response, or the last redirect target reached if the chain was truncated. `_untrusted`."
    )
    hops: list[RedirectHop] = Field(
        default_factory=list,
        description="Ordered list of hops, one entry per HTTP request issued. hops[0].url == start_url.",
    )
    hop_count: int = Field(description="Total fetches performed (= len(hops)). Capped at REDIRECT_MAX_HOPS=10.")
    final_status: int = Field(
        description="HTTP status of the last hop, or 0 if the chain failed before any successful response."
    )
    loop_detected: bool = Field(
        default=False,
        description="True if a hop's Location pointed back to a URL already visited (the duplicate fetch was NOT performed).",
    )
    truncated: bool = Field(
        default=False,
        description="True if the chain still had a 30x at hop_count == REDIRECT_MAX_HOPS — the next hop was NOT followed.",
    )
    summary: str = Field(default="", description="One-line human-readable summary.")


class BrandAssetsResponse(BaseSuccessResponse):
    """Public brand-identity assets scraped from a domain's homepage.

    What we DO: GET `https://{domain}/` (HTTP fallback), parse `<head>` for
    favicon, `og:image`, `theme-color`, `og:site_name`, and JSON-LD
    `Organization.logo`. All URL fields are absolute and `_untrusted` (DO
    NOT execute, shell-out, or fetch from inside an LLM tool-use turn).

    Ethical floor: we honour the target site's robots.txt — if it
    Disallows path "/" for our UA token ("ContrastAPI") OR for `*`, we
    return 403 `error.code = robots_txt_disallow` and DO NOT fetch.
    """

    domain: str = Field(description="Queried domain (echoed).")
    fetched_url: str = Field(description="Final URL we fetched, e.g. https://example.com/ (post-redirects).")
    status_code: int = Field(description="HTTP status returned by the homepage fetch.")
    favicon_url_untrusted: str | None = Field(
        default=None,
        description="Resolved favicon URL (`<link rel='icon'>`, `shortcut icon`, `apple-touch-icon`, then `/favicon.ico` fallback). Absolute. `_untrusted`.",
    )
    og_image_url_untrusted: str | None = Field(
        default=None,
        description="`<meta property='og:image'>` resolved to an absolute URL. Used as the social-share thumbnail. `_untrusted`.",
    )
    theme_color: str | None = Field(
        default=None,
        description="`<meta name='theme-color'>` value (verbatim, capped at 64 chars). Useful for matching brand chrome.",
    )
    site_name_untrusted: str | None = Field(
        default=None,
        description="`<meta property='og:site_name'>` (preferred) or `<title>` fallback. Capped at 200 chars. `_untrusted`.",
    )
    logo_url_untrusted: str | None = Field(
        default=None,
        description="`Organization.logo` from the first matching JSON-LD block (`<script type='application/ld+json'>`). Resolved to absolute URL. `_untrusted`.",
    )
    cache_respected: bool = Field(
        default=True,
        description="True if we wrote the result to our cache. False when the target sent `Cache-Control: no-store` or `private` and we honoured it (Guardrail #4 — we don't cache content the target asked us not to).",
    )
    summary: str = Field(default="", description="One-line human-readable summary.")


class SeoAuditResponse(BaseSuccessResponse):
    """One-page SEO audit of a domain's homepage with a 0-100 composite score.

    Strictly homepage-only (path `/`); we do NOT crawl the site. Same
    ethical floor as `brand_assets`: target's robots.txt is honoured
    (Disallow `/` for our UA → 403, no fetch). All target-derived
    string/list fields are `_untrusted` (DO NOT execute or shell-out —
    the page author controls these contents).

    Score (0-100) is the sum of 10 audit rules, each worth 0-10 points.
    `missing_signals` lists the rule-IDs that did NOT fire so agents
    can surface concrete fixes ("title_missing", "h1_multiple", etc.).
    """

    domain: str = Field(description="Queried domain (echoed).")
    fetched_url: str = Field(description="Final URL we fetched (post-redirects).")
    status_code: int = Field(description="HTTP status returned by the homepage fetch.")

    title_untrusted: str | None = Field(
        default=None,
        description="`<title>` text, control-char stripped, capped at 300 chars. `_untrusted`.",
    )
    meta_description_untrusted: str | None = Field(
        default=None,
        description="`<meta name='description'>` content, capped at 500 chars. `_untrusted`.",
    )
    canonical_url: str | None = Field(
        default=None,
        description="`<link rel='canonical'>` href, resolved to an absolute URL.",
    )
    h1_untrusted: list[str] = Field(
        default_factory=list,
        description="Text of each `<h1>` (capped at 20 entries, 300 chars each). `_untrusted`.",
    )
    h1_count: int = Field(default=0, description="Total number of `<h1>` tags found (NOT capped — for scoring).")
    h2_count: int = Field(default=0, description="`<h2>` tag count, capped at 200.")
    h3_count: int = Field(default=0, description="`<h3>` tag count, capped at 200.")

    images_total: int = Field(default=0, description="Total `<img>` tags on the page (parser bound: 1000).")
    images_missing_alt: int = Field(
        default=0,
        description="Number of `<img>` tags with no `alt` attribute OR an empty/whitespace `alt`. Counts toward the score's accessibility rule.",
    )

    internal_link_count: int = Field(
        default=0,
        description="`<a href>` count where the target host shares the registrable domain. Cheap eTLD-aware compare; not perfect on suffixes like .co.uk.",
    )
    external_link_count: int = Field(
        default=0,
        description="`<a href>` count to a different registrable domain. Excludes mailto:, tel:, javascript:, in-page anchors.",
    )

    og_tags: dict[str, str] = Field(
        default_factory=dict,
        description="`<meta property='og:*'>` map, capped at 50 entries. Values capped at 500 chars each. All `_untrusted`.",
    )
    json_ld_present: bool = Field(
        default=False,
        description="True if at least one `<script type='application/ld+json'>` block exists (parser does NOT validate the JSON, only counts tag presence — score considers tag presence sufficient for structured-data signal).",
    )

    score: int = Field(
        description="Composite 0-100 SEO score: 10 rules x 10 points each (title present, title length, meta description present, meta description length, single H1, canonical, >=3 OG tags, JSON-LD present, image alt coverage proportional, HTTPS).",
    )
    missing_signals: list[str] = Field(
        default_factory=list,
        description="Rule-IDs that did NOT contribute their points. Subset of: title_missing, title_length_off, meta_description_missing, meta_description_length_off, h1_missing, h1_multiple, canonical_missing, og_tags_sparse, json_ld_missing, images_missing_alt, not_https.",
    )

    cache_respected: bool = Field(
        default=True,
        description="True if we wrote the result to our cache. False when the target sent `Cache-Control: no-store` or `private` and we honoured it.",
    )
    summary: str = Field(default="", description="One-line human-readable summary.")


class CipherInfo(BaseModel):
    model_config = {"extra": "allow"}

    name: str | None = Field(
        default=None,
        description=(
            "Cipher suite name as reported by OpenSSL, e.g. 'TLS_AES_256_GCM_SHA384' (TLS 1.3) "
            "or 'ECDHE-RSA-AES256-GCM-SHA384' (TLS 1.2). Null on handshake failure."
        ),
    )
    protocol: str | None = Field(
        default=None,
        description=(
            "TLS protocol version negotiated for this cipher, e.g. 'TLSv1.3', 'TLSv1.2'. "
            "Mirrors SslResponse.protocol and is null on handshake failure."
        ),
    )
    bits: int | None = Field(
        default=None,
        description=("Effective symmetric key length in bits (e.g. 256 for AES-256-GCM). Null on handshake failure."),
    )


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


class SslResponse(BaseSuccessResponse):
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
    cipher: CipherInfo = Field(
        default_factory=CipherInfo,
        description=(
            "Negotiated cipher suite with name, negotiated TLS protocol, and key length. "
            "All fields are null on handshake failure (empty CipherInfo)."
        ),
    )
    chain: list[SslChainItem] = Field(
        default_factory=list,
        description="Full cert chain from leaf upward (excluding system root). Includes AIA-fetched intermediates when needed.",
    )
    grade: Literal["A", "B", "C", "D", "F"] = Field(
        default="F",
        description=(
            "Overall SSL configuration grade. 'A' (cert_valid + TLSv1.3 + >=30 days remaining), "
            "'B' (cert_valid + (TLSv1.3 <30d OR TLSv1.2 healthy)), 'C' (cert_valid + (TLSv1.2 <14d OR TLSv1.3 <7d OR unknown protocol)), "
            "'D' (cert readable but invalid: hostname_mismatch / untrusted_root / self_signed), "
            "'F' (probe failure, expired, OR TLSv1/TLSv1.1). Canonical grader is _ssl_grade() in domain/recon.py; "
            "same helper powers /v1/domain/ ssl section (single source of truth)."
        ),
    )
    validation_errors: list[str] = Field(
        default_factory=list,
        max_length=10,
        description=(
            "Canonical cert validation failure tags when cert is readable but invalid. "
            "Values: 'expired', 'self_signed', 'hostname_mismatch', 'untrusted_root', 'chain_incomplete'. "
            "Empty when cert validates cleanly. See also: 'valid' (boolean overall) and 'warnings' (human-readable)."
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


class MonitorResponse(BaseSuccessResponse):
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


class VulnsResponse(BaseSuccessResponse):
    domain: str
    technologies_scanned: int = 0
    total_cves: int = 0
    vulnerabilities: list[TechVulnItem] = Field(default_factory=list)
    summary: str = ""


class BulkDomainItem(BaseModel):
    domain: str = Field(description="Echoed input domain (lowercased).")
    status: Literal["ok", "error"] = Field(
        default="ok",
        description="Per-item outcome. 'ok' = report populated; 'error' = error populated (timeout / lookup failed / invalid).",
    )
    report: DomainReportResponse | None = Field(
        default=None,
        description="Full domain intelligence report when status='ok'. Same shape as /v1/domain/{domain}.",
    )
    error: str | None = Field(
        default=None,
        description="Human-readable error message when status='error' (timeout, validation failure, upstream error).",
    )


class BulkDomainResponse(BaseSuccessResponse):
    results: list[BulkDomainItem] = Field(
        default_factory=list,
        description="Per-domain outcome list, preserving the input order.",
    )
    total: int = Field(default=0, description="Total number of input domains processed (== len(results)).")
    successful: int = Field(default=0, description="Count of items with status='ok'.")
    failed: int = Field(default=0, description="Count of items with status='error' from non-timeout failures.")
    timed_out: int = Field(default=0, description="Count of items that hit the per-domain or overall timeout.")
    partial: bool = Field(default=False, description="True when at least one item failed or timed out.")
    summary: str = Field(default="", description="One-line aggregate summary (e.g. '8/10 domains succeeded').")


class AsnResponse(BaseSuccessResponse):
    target: str
    resolved_ip: str | None = None
    asn: int
    asn_name: str = Field(default="", max_length=256)
    # Bug I1: prefix lists used to wrap each entry in {"prefix": "x.x.x.x/y"}
    # — pure overhead with one key. Flat list[str] of CIDR strings halves the
    # byte size on AS-rich responses (Cloudflare AS13335 carries ~2500
    # prefixes; the wrapper alone added ~25 KB). Schema-breaking change
    # — ship in v1.15.0.
    ipv4_prefixes: list[str] = Field(default_factory=list)
    ipv6_prefixes: list[str] = Field(default_factory=list)
    ipv4_count: int = 0
    ipv6_count: int = 0
    summary: str = ""
    warnings: list[str] = Field(default_factory=list)


class WhoisResponse(BaseSuccessResponse):
    domain: str = Field(description="Queried domain (lowercased, no scheme).")
    whois: WhoisInfoEmbedded = Field(
        description=(
            "WHOIS extract — registrar, dates, nameservers, EPP status. Same shape as "
            "DomainReportResponse.whois. Populates `error` when the WHOIS query failed "
            "(no WHOIS server for TLD, socket timeout, etc.)."
        ),
    )
    summary: str = Field(
        default="",
        description="One-line human-readable summary (registrar + expiry hint).",
    )


class SubdomainsResponse(BaseSuccessResponse):
    domain: str
    count: int = 0
    subdomains: list[str] = Field(default_factory=list)
    summary: str = ""
    sources: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    found_via_wordlist: int = 0
    found_via_crtsh: int = 0
    crtsh_status: Literal["ok", "timeout", "rate_limited", "unavailable", "error"] = Field(
        default="ok",
        description=(
            "Status of the crt.sh certificate-transparency lookup that feeds found_via_crtsh. "
            "'ok' means the upstream responded — found_via_crtsh=0 with status='ok' is a real "
            "empty result. Anything else means the upstream did not deliver (timeout / "
            "rate_limited / unavailable / error); count and subdomains are then wordlist-only "
            "and an unknown number of CT-log subdomains may be missing."
        ),
    )

    model_config = {"extra": "ignore"}


class CertsResponse(BaseSuccessResponse):
    domain: str
    total_certificates: int = 0
    certificates: list[dict] = Field(default_factory=list)
    summary: str = ""

    model_config = {"extra": "ignore"}


class MxRecord(BaseModel):
    priority: int
    host: str


class EmailSecurityDetail(BaseModel):
    spf: str | None = None
    dmarc: str | None = None
    dkim_selectors: list[str] = Field(default_factory=list)
    dkim_status: Literal["verified", "unverifiable"] | None = Field(
        default=None,
        description=(
            "'verified' when at least one DKIM selector responded; 'unverifiable' when none "
            "of the probed common/date-based selectors matched. Custom selectors cannot be "
            "discovered without prior knowledge."
        ),
    )
    grade: str = "F"
    issues: list[str] = Field(default_factory=list)


class EmailMxResponse(BaseSuccessResponse):
    domain: str
    mx_records: list[MxRecord] = Field(default_factory=list)
    mail_provider: str | None = None
    email_security: EmailSecurityDetail = Field(default_factory=EmailSecurityDetail)
    summary: str = ""


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


class PhoneLookupResponse(BaseSuccessResponse):
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
    carrier: str | None = Field(
        default=None,
        description=(
            "Carrier/network name from libphonenumber carrier DB. Excluded from the wire "
            "(response_model_exclude_none=True) when no carrier mapping exists for the region — "
            "inspect carrier_status to distinguish 'known' vs 'unsupported_region' (US/CA/GB and "
            "other MNP-restricted regions are commonly unsupported)."
        ),
    )
    carrier_status: Literal["known", "unsupported_region"] | None = Field(
        default=None,
        description=(
            "'known' when libphonenumber returned a carrier name; 'unsupported_region' when the "
            "carrier DB has no mapping for this region (do not treat the absent carrier field as "
            "evidence the number lacks a carrier — it just means we cannot identify it). Null on "
            "invalid/unparseable input."
        ),
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


class DisposableResponse(BaseSuccessResponse):
    email: str = Field(description="Echoed input email (local-part preserved; domain lowercased).")
    domain: str = Field(description="Lowercased domain extracted from the email's right-of-@.")
    disposable: bool = Field(
        default=False, description="True when the domain matches the disposable-provider database."
    )
    provider: str | None = Field(
        default=None,
        description="Disposable-provider name when known (e.g. 'mailinator', 'tempmail.com'). Null when not disposable.",
    )
    mx_disposable: bool = Field(
        default=False,
        description="True when the domain's MX records point to a known disposable mail host (catches custom domains fronting disposable backends).",
    )
    risk_level: Literal["low", "medium", "high"] = Field(
        default="low",
        description=(
            "Combined risk band. 'high' = domain is on the disposable list; 'medium' = MX points to a "
            "disposable backend but the domain itself is not listed; 'low' = neither match (legitimate)."
        ),
    )
    mx_records: list[MxRecord] = Field(
        default_factory=list,
        description="Resolved MX records for the email's domain (priority + host).",
    )
    summary: str = Field(
        default="", description="One-line human-readable summary including risk_level + provider hint."
    )


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


class UsernameLookupResponse(BaseSuccessResponse):
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

    model_config = {"extra": "ignore"}


class AuditTechInfo(BaseModel):
    """Technology fingerprint subset embedded in /v1/audit (no domain echo — outer AuditResponse carries it)."""

    technologies: list[TechItem] = Field(
        default_factory=list,
        description="Detected technologies (name + category) inferred from response headers (e.g. Server, X-Powered-By).",
    )
    categories: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Technologies grouped by category (e.g. {'cdn': ['Cloudflare'], 'webserver': ['nginx']}).",
    )
    count: int = Field(default=0, description="Total number of detected technologies (== sum of categories).")
    summary: str = Field(default="", description="One-line summary of the detected stack.")

    model_config = {"extra": "ignore"}


class AuditResponse(BaseSuccessResponse):
    domain: str = Field(description="Queried domain (lowercased, no scheme).")
    report: DomainReportResponse | None = Field(
        default=None,
        description=(
            "Full domain intelligence report — same shape as /v1/domain/{domain}. Contains DNS, "
            "WHOIS, SSL, subdomains, threat intel, reputation, and verdict. See DomainReportResponse."
        ),
    )
    technologies: AuditTechInfo = Field(
        default_factory=AuditTechInfo,
        description="Technology fingerprint detected from live response headers. See AuditTechInfo.",
    )
    live_headers: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Filtered HTTP response headers from the origin (lowercased keys). Sensitive headers "
            "(Set-Cookie, Authorization, etc.) are stripped before serialization."
        ),
    )
    summary: str = Field(
        default="",
        description="One-line audit summary combining domain report summary + technology count.",
    )

    model_config = {"extra": "ignore"}


class ThreatReportResponse(BaseSuccessResponse):
    ip: str = Field(description="Queried IP address (IPv4 or IPv6, echoed back verbatim).")
    enrichment: IpEnrichmentInfo = Field(
        default_factory=IpEnrichmentInfo,
        description=(
            "Shodan InternetDB free-tier enrichment (ports, hostnames, vulns, cpes, tags). "
            "Available on all tiers. See IpEnrichmentInfo for the exact field shape. "
            "Returned with all-empty lists on upstream failure — treat as 'no data', not 'clean'."
        ),
    )
    abuseipdb: AbuseIpdbInfo = Field(
        default_factory=lambda: AbuseIpdbInfo(status="error"),
        description=(
            "AbuseIPDB abuse-confidence enrichment. Pro tier returns live data; Free tier "
            "returns a {status:'pro_only', reason, upgrade_url} upsell stub (NOT an error). "
            "Pro failure paths emit status='error' / 'rate_limited' / 'skipped'. See AbuseIpdbInfo."
        ),
    )
    shodan: ShodanRepInfo = Field(
        default_factory=lambda: ShodanRepInfo(status="error"),
        description=(
            "Shodan full-API enrichment (richer than the InternetDB enrichment block). "
            "Pro tier returns live data; Free tier returns a {status:'pro_only', reason, "
            "upgrade_url} upsell stub. Pro failure paths emit status='error' / 'rate_limited' "
            "/ 'restricted' / 'skipped'. See ShodanRepInfo."
        ),
    )
    asn: dict = Field(
        default_factory=dict,
        description=(
            "ASN ownership from RIPE Stat network-info: {asn: int, prefix: str}. "
            "Empty dict when RIPE has no allocation; {error:'lookup_failed'} on fetch failure."
        ),
    )
    threat_level: Literal["none", "low", "medium", "high"] = Field(
        default="none",
        description=(
            "Heuristic threat tier. 'high' when any vulns present OR abuse_score>=50; "
            "'medium' when abuse_score>=25; 'low' when open ports observed; 'none' otherwise. "
            "On Free tier threat_level is necessarily conservative — abuse_score is unknown."
        ),
    )
    summary: str = Field(
        default="",
        description="One-line human summary combining threat_level, port count, vuln count, and abuse signal.",
    )
    # Bug I3: passive intel parity with ip_lookup. threat_report (Pro,
    # 4-credit) used to omit fields that the cheaper ip_lookup (1-credit)
    # already returned, so SOC triage callers needed a second hop just to
    # see PTR / asn_name / country / cloud / Tor / FireHOL / risk_score.
    ptr: str | None = Field(default=None, description="Reverse DNS PTR for the IP, or null when unresolvable.")
    asn_name: str | None = Field(default=None, description="ASN holder name from RIPE Stat as-overview, or null.")
    country: str | None = Field(default=None, description="Country code from RIPE Stat rir-stats-country, or null.")
    cloud_provider: str | None = Field(
        default=None,
        description="Cloud / hosting provider name when the IP sits in a known CIDR or maps to a tier-1 ASN.",
    )
    is_datacenter: bool = Field(
        default=False,
        description=(
            "True if IP is hosted on a known datacenter / cloud provider (parity with "
            "ip_lookup.is_datacenter). Same two-tier detection — cloud_provider hit OR "
            "tier-1 datacenter ASN. Always present — never null."
        ),
    )
    tor_exit: bool = Field(
        default=False,
        description="True if IP appears in the Tor Project bulk exit list (verdict.sources_unavailable['tor'] when fetch failed).",
    )
    firehol: dict | None = Field(
        default=None,
        description="FireHOL Level1 listing status: {status, listed, lists_matched}. Available on all tiers.",
    )
    risk_score: int = Field(
        default=0,
        description=(
            "Composite 0-100 score (parity with ip_lookup.risk_score). v1.17.0 additive "
            "components: ports (10 * min(count, 5) = 0-50), tor_exit (+30), firehol.listed "
            "(+20), AbuseIPDB confidence (round(15 * score / 100) = 0-15), is_datacenter "
            "(+10), known vulns (5 * min(count, 4) = 0-20). Use severity_label for thresholding."
        ),
    )
    severity_label: Literal["low", "medium", "high", "critical"] = Field(
        default="low",
        description=(
            "Coarse risk band derived from risk_score (parity with ip_lookup.severity_label). "
            "Pre-1.17 the route emitted this field and advertised it in verdict.falsifiable_fields "
            "but the schema didn't declare it, so Pydantic silently dropped it from the wire. "
            "Same thresholds: >=75 critical, >=50 high, >=25 medium, else low."
        ),
    )

    model_config = {"extra": "ignore"}
