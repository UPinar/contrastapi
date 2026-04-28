"""Pydantic response models for ContrastAPI endpoints."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, computed_field

# === Domain Report — nested sub-models (agent discovery) ===
#
# Each sub-model uses `model_config = {"extra": "allow"}` so that upstream producers
# in app/domain/recon.py can emit additional keys without breaking the API contract
# (forward-compat). Every field is `Type | None = None` so that FastAPI's
# `response_model_exclude_none=True` preserves the prior wire format — absent keys
# in producer dicts do not materialize as `null` in the serialized JSON.


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
            "Honest pre-filter TXT record count (always emitted on domain_report). Equals len(txt) when "
            "include_all_txt=true. Null on /v1/dns/{domain} where TXT is not filtered."
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
    grade: Literal["A", "B", "C", "F"] | None = Field(
        default=None,
        description="SSL grade A/B/C/F. Same ladder as SslResponse.grade (TLS version x days_remaining).",
    )
    error: str | None = Field(default=None, description="Populated on handshake / connection failure.")

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


# === Domain Report (top-level) ===


class DomainReportResponse(BaseModel):
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

    @computed_field
    @property
    def risk_score(self) -> int | None:
        """Top-level alias for risk.score — backward-compat with old docstring consumers."""
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
    verdict: Verdict | None = Field(
        default=None,
        description=(
            "Falsifiability metadata. sources_queried / sources_unavailable let agents distinguish "
            "'no data' from 'source failed' — critical for SOC / agent chain-of-thought integrity."
        ),
    )
    next_calls: list[PivotHint] | None = Field(
        default=None,
        description=(
            "Suggested follow-up MCP tool calls. Conditional on what the report surfaced — "
            "subdomain_enum (always — attack-surface map), ssl_check (when an A record resolves), "
            "tech_fingerprint (when an A record resolves). Agents should chain these without "
            "re-prompting the user."
        ),
    )

    model_config = {"extra": "ignore"}


# === DNS ===


class DnsResponse(BaseModel):
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
    verdict: Verdict | None = Field(
        default=None,
        description="Falsifiability metadata: sources queried, sources unavailable, data age, completeness tier.",
    )
    next_calls: list[PivotHint] | None = Field(
        default=None,
        description=(
            "Suggested follow-up MCP tool calls. Conditional cascade: asn_lookup (whenever asn is "
            "populated — CIDR detail), ioc_lookup (when reputation.firehol.listed=True or "
            "abuseipdb confidence>50 — threat indicator drill-down), threat_report (Pro tier only — "
            "orchestrated Shodan + AbuseIPDB profile)."
        ),
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


class ThreatFoxSource(BaseModel):
    """ThreatFox abuse.ch source entry inside IocResponse.sources.threatfox."""

    found: bool = Field(description="True when ThreatFox returned at least one IOC entry for the indicator.")
    malware: str | None = Field(
        default=None, description="Malware family name (e.g. 'Cobalt Strike'). Null when found=False."
    )
    threat_type: str | None = Field(
        default=None,
        description="Threat classification (e.g. 'botnet_cc', 'payload_delivery'). Null when found=False.",
    )
    confidence: int | None = Field(
        default=None,
        description="ThreatFox confidence score (0-100). Null when found=False or not provided upstream.",
    )
    tags: list[str] = Field(
        default_factory=list, description="ThreatFox tags. May include 'test'/'demo' for honeypot entries."
    )
    first_seen: str | None = Field(
        default=None,
        description="ISO timestamp of first ThreatFox observation. Null when found=False.",
    )
    ioc_count: int | None = Field(
        default=None,
        description="Total ThreatFox IOC entries matching this indicator. Null when found=False.",
    )
    error: str | None = Field(
        default=None,
        description="'upstream timeout' or 'upstream error' when ThreatFox query failed; absent on success.",
    )

    model_config = {"extra": "ignore"}


class FeodoSource(BaseModel):
    """Feodo Tracker C2 blocklist entry inside IocResponse.sources.feodo (IP only)."""

    found: bool = Field(description="True when the IP appears on the Feodo Tracker C2 blocklist.")
    malware: str | None = Field(
        default=None, description="Malware family attributed by Feodo (e.g. 'Emotet'). Null when found=False."
    )
    first_seen: str | None = Field(
        default=None,
        description="ISO timestamp of first Feodo observation. Null when found=False.",
    )
    last_online: str | None = Field(
        default=None,
        description="ISO timestamp the C2 was last seen online. Null when found=False.",
    )
    status: str | None = Field(
        default=None,
        description="C2 lifecycle status per Feodo (e.g. 'online', 'offline'). Null when found=False.",
    )

    model_config = {"extra": "ignore"}


class UrlhausSource(BaseModel):
    """URLhaus abuse.ch source entry inside IocResponse.sources.urlhaus."""

    found: bool = Field(description="True when URLhaus has at least one URL for the indicator.")
    urls_online: int = Field(default=0, description="Subset of URLhaus URLs currently marked online.")

    model_config = {"extra": "ignore"}


class TorSource(BaseModel):
    """Tor exit list entry inside IocResponse.sources.tor (IP only)."""

    listed: bool = Field(description="True when the IP appears in the Tor Project's bulk exit list.")
    fetch_status: Literal["initial", "ok", "failed", "capped"] = Field(
        description=(
            "Cache state of the Tor exit list snapshot used for the lookup. "
            "'initial' = no refresh has run yet; 'ok' = fresh fetch; 'failed' = upstream "
            "fetch failed (treat listed=False as 'unknown', not 'safe'); 'capped' = upstream "
            "response exceeded the size cap and was rejected."
        ),
    )

    model_config = {"extra": "ignore"}


class IocSourcesInfo(BaseModel):
    """Per-source lookup results inside IocResponse. Keys present depend on indicator type.

    - hash → only `threatfox` (Feodo and URLhaus do not index hashes).
    - ip → `threatfox` + `feodo` + `urlhaus` + `tor`.
    - domain / url → `threatfox` + `urlhaus`.
    """

    threatfox: ThreatFoxSource | None = Field(default=None, description="ThreatFox lookup result. Always queried.")
    feodo: FeodoSource | None = Field(
        default=None, description="Feodo Tracker C2 blocklist lookup. IP indicators only."
    )
    urlhaus: UrlhausSource | None = Field(default=None, description="URLhaus URL/host match. IP/domain/URL indicators.")
    tor: TorSource | None = Field(default=None, description="Tor exit list membership. IP indicators only.")

    model_config = {"extra": "ignore"}


class IocResponse(BaseModel):
    indicator: str = Field(description="Echoed input indicator (sanitized; control chars stripped).")
    type: Literal["ip", "domain", "url", "hash", "unknown"] = Field(
        description="Auto-detected indicator type. 'unknown' is rejected at route level (400).",
    )
    threat_level: Literal["none", "low", "medium", "high"] = Field(
        default="none",
        description=(
            "Heuristic threat tier from cross-source agreement. 'high' = >=2 sources flagged; "
            "'medium' = 1 source flagged; 'none' = no source flagged. 'low' is a soft cap applied "
            "when the only flag came from a ThreatFox test/demo honeypot tag."
        ),
    )
    sources: IocSourcesInfo = Field(
        default_factory=IocSourcesInfo,
        description="Per-source lookup results. See IocSourcesInfo for which sources apply per indicator type.",
    )
    summary: str = Field(default="", description="One-line human summary aggregating threat indicators across sources.")
    verdict: Verdict | None = Field(
        default=None,
        description="Falsifiability metadata. sources_unavailable lists feeds that timed out or errored.",
    )

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
    hash_prefix: str = Field(
        description=(
            "First 5 chars of the SHA-1 hash (the only data sent upstream — k-anonymity). "
            "The full hash never leaves the server."
        ),
    )
    found: bool = Field(
        default=False,
        description="True when the full SHA-1 was matched in HIBP's breach corpus.",
    )
    breach_count: int = Field(
        default=0,
        description="Number of breach corpora that contained this password. 0 when found=False.",
    )
    summary: str = Field(
        default="",
        description="One-line human-readable result (e.g. 'This password appeared in 12,345 data breaches').",
    )

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
    status: str | None = Field(
        default=None,
        description=(
            "URLhaus url_status for the exact URL match: 'online' (active threat), "
            "'offline' (historical, threat may be cleaned up), or 'unknown'. Null when "
            "the URL was not found."
        ),
    )


class PhishingResponse(BaseModel):
    url: str
    host: str
    is_malicious: bool = False
    is_stale: bool = Field(
        default=False,
        description=(
            "True when the only URLhaus evidence is historical (host has url_count > 0 "
            "but urls_online == 0, OR exact URL match has status == 'offline'). The host "
            "or URL was once flagged but no live malware is currently being served — useful "
            "for distinguishing past compromise from active threat."
        ),
    )
    urlhaus_host: UrlhausHostDetail = Field(default_factory=UrlhausHostDetail)
    urlhaus_url: UrlhausUrlDetail = Field(default_factory=UrlhausUrlDetail)
    threat_level: Literal["none", "low", "medium", "high"] = Field(
        default="none",
        description=(
            "Aggregate severity. 'high' = exact URL active AND host has live malware URLs. "
            "'medium' = exactly one of those active. 'low' = only stale historical evidence "
            "(is_stale=True). 'none' = no URLhaus listing for either."
        ),
    )
    summary: str = ""


# === Bulk Domain Report ===


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


class BulkDomainResponse(BaseModel):
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


# === Pivot hints (agent workflow chains) ===


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
        "exploit_lookup",
        "kev_detail",
        "cwe_lookup",
        "subdomain_enum",
        "ssl_check",
        "tech_fingerprint",
        "asn_lookup",
        "ip_lookup",
        "ioc_lookup",
        "threat_report",
        "audit_domain",
        "domain_report",
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


# === Verdict ===


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


class KevDetailResponse(BaseModel):
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
    verdict: Verdict | None = Field(
        default=None,
        description="Provenance + completeness metadata for this response.",
    )
    next_calls: list[PivotHint] | None = Field(
        default=None,
        description=(
            "Suggested follow-up MCP tool calls based on this KEV record. Typical chain: "
            "cve_lookup for full CVE details, cwe_lookup for each entry in cwes, "
            "exploit_lookup for public PoC availability."
        ),
    )


class CweLookupResponse(BaseModel):
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
    verdict: Verdict | None = Field(
        default=None,
        description="Provenance + completeness metadata for this response.",
    )
    next_calls: list[PivotHint] | None = Field(
        default=None,
        description=(
            "Suggested follow-up MCP tool calls based on this CWE record. Typical chain: "
            "cve_search?cwe=<cwe_id> to enumerate CVEs that map to this weakness, "
            "cwe_lookup on parent_cwe to walk up the hierarchy, cwe_lookup on each child "
            "to drill down."
        ),
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
    next_calls: list[PivotHint] | None = Field(
        default=None,
        description=(
            "Suggested follow-up MCP tool calls. Always includes exploit_lookup; adds "
            "kev_detail when kev.in_kev=true and cwe_lookup when cwe_id is set. Emitted "
            "on single-CVE lookups (cve_lookup) and bulk lookup items, NOT on cve_search "
            "/ cve_leading list rows — agents pivot via cve_lookup on the chosen result."
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


class ExploitResponse(BaseModel):
    model_config = {"extra": "ignore"}

    cve_id: str
    exploits_found: int = 0
    sources: ExploitSources = Field(default_factory=ExploitSources)
    has_public_exploit: bool = False
    exploits: list[Exploit] = Field(default_factory=list)
    verdict: Verdict | None = None
    summary: str = ""
    next_calls: list[PivotHint] | None = Field(
        default=None,
        description=(
            "Suggested follow-up MCP tool calls. Always emits a single pivot — cve_lookup — "
            "for full CVE context (CVSS, EPSS, KEV status, CWE chain). Agent then chains "
            "cve_lookup's own next_calls (kev_detail when in_kev, cwe_lookup when cwe_id set). "
            "exploit_lookup itself does not carry kev/cwe schema, so blind emission of those "
            "pivots is intentionally avoided — would risk 404 / missing-input wasted calls."
        ),
    )


# === ASN Lookup ===


class AsnResponse(BaseModel):
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
    # Bug I2: every other live-fetch tool emits a verdict block (sources_queried
    # / sources_unavailable / completeness / falsifiable_fields). Pattern parity
    # — agents can now treat asn_lookup the same way they treat ip_lookup or
    # threat_report when checking source provenance.
    verdict: Verdict | None = Field(
        default=None,
        description="Source provenance for the ASN response (RIPE Stat sub-endpoints).",
    )
    next_calls: list[PivotHint] | None = Field(
        default=None,
        description=(
            "Suggested follow-up MCP tool calls. Emitted when the input was a domain "
            "and resolution produced an IP — agents are pointed at ip_lookup on the "
            "resolved IP to pull cloud / Tor / threat-intel context that asn_lookup "
            "deliberately does not duplicate."
        ),
    )


# === WHOIS ===


class WhoisResponse(BaseModel):
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
    next_calls: list[PivotHint] | None = Field(
        default=None,
        description=(
            "Suggested follow-up MCP tool calls. Capped at 10 ssl_check pivots (one per first-ten "
            "subdomain) — large result sets stay token-cheap, agents pick up the cert-grade triage "
            "without fanning out 100+ hints. Omitted entirely when subdomains is empty."
        ),
    )

    model_config = {"extra": "ignore"}


# === Certificate Transparency ===


class CertsResponse(BaseModel):
    domain: str
    total_certificates: int = 0
    certificates: list[dict] = Field(default_factory=list)
    summary: str = ""

    model_config = {"extra": "ignore"}


# === CVE Search / Recent / KEV ===


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
    verdict: Verdict | None = Field(default=None, description="Falsifiability metadata.")


class CveSearchResponse(BaseModel):
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


# === Code Security ===


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


class CodeCheckResponse(BaseModel):
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


class ScanHeadersResponse(BaseModel):
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


class CheckHeadersResponse(BaseModel):
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


# === Disposable Email ===


class DisposableResponse(BaseModel):
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


class AuditResponse(BaseModel):
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
    next_calls: list[PivotHint] | None = Field(
        default=None,
        description=(
            "Suggested follow-up MCP tool calls. audit_domain already bundles tech_fingerprint + "
            "live_headers, so cascade emits subdomain_enum (always — broader attack surface) and "
            "ssl_check (when an A record resolves) for the residual recon depth."
        ),
    )

    model_config = {"extra": "ignore"}


# === Threat Report (orchestrated IP intel) ===


class ThreatReportResponse(BaseModel):
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
    verdict: Verdict | None = Field(
        default=None,
        description="Source provenance — Pro tier marks the AbuseIPDB/Shodan slots in queried; Free tier marks them unavailable.",
    )

    model_config = {"extra": "ignore"}


# === Bulk CVE ===


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


class BulkCveResponse(BaseModel):
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


# === Bulk IOC ===


class BulkIocItem(BaseModel):
    indicator: str = Field(description="Echoed input indicator (sanitized; type auto-detected per-item).")
    status: Literal["ok", "error"] = Field(
        default="ok",
        description="Per-item outcome. 'ok' = ioc populated; 'error' = lookup failed / invalid / timeout.",
    )
    ioc: dict | None = Field(
        default=None,
        description=(
            "Slim IOC enrichment when status='ok' — keys: type, threat_level, sources. "
            "Bulk endpoint omits indicator/summary/verdict (use /v1/ioc/{indicator} for the "
            "full IocResponse shape). Per-source dicts may carry richer fields than the single "
            "endpoint (raw urlhaus dict instead of {found, urls_online})."
        ),
    )
    error: str | None = Field(
        default=None,
        description="Human-readable error message when status='error' (timeout, invalid indicator, upstream error).",
    )


class BulkIocResponse(BaseModel):
    results: list[BulkIocItem] = Field(
        default_factory=list,
        description="Per-indicator outcome list, preserving input order.",
    )
    total: int = Field(default=0, description="Total number of input indicators processed (== len(results)).")
    successful: int = Field(default=0, description="Count of items with status='ok'.")
    failed: int = Field(default=0, description="Count of items with status='error' from non-timeout failures.")
    timed_out: int = Field(default=0, description="Count of items that hit the per-IOC or overall timeout.")
    partial: bool = Field(default=False, description="True when at least one item failed or timed out.")
    summary: str = Field(default="", description="One-line aggregate summary (e.g. '12/15 indicators enriched').")
