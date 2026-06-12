# ContrastAPI Endpoints

Full list of 57+ REST endpoints. Base URL: `https://api.contrastcyber.com`

- **Free tier:** 30 credits/hour, no API key required
- **Pro tier:** 500 credits/hour ([Get API Key](https://contrastcyber.com/pricing))
- **Credit costs:** most endpoints cost 1 credit; see [Credit Costs](#credit-costs) below
- **Burst gate:** an additional per-IP burst limit (~10 concurrent for `/v1/cve/*` and `/v1/check/*`, 100 for `POST /mcp/`) returns HTTP 429 immediately when exceeded. Full table + best practices: [RATE_LIMITS.md](RATE_LIMITS.md).

## Domain Intelligence

```
GET  /v1/domain/{domain}          Full domain report (DNS + WHOIS + SSL + subs + WAF + reputation)
GET  /v1/audit/{domain}           Comprehensive audit (full report + tech fingerprint + live headers)  [cost: 4]
GET  /v1/scan/{domain}            Active website security scan — C engine (11 modules) + severity-ranked findings + grade  [cost: 6]
GET  /v1/dns/{domain}             DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
GET  /v1/whois/{domain}           WHOIS registration data
GET  /v1/subdomains/{domain}      Subdomain enumeration via wordlist DNS brute-force + Certificate Transparency logs (crt.sh)
GET  /v1/certs/{domain}           Certificate transparency logs
GET  /v1/ssl/{domain}             SSL/TLS analysis (cipher, cert chain, grade A-F)
GET  /v1/tech/{domain}            Technology fingerprinting (CMS, frameworks, CDN, analytics)
GET  /v1/threat/{domain}          Threat intelligence (URLhaus malware URLs)
GET  /v1/archive/{domain}         Web archive history (Wayback Machine snapshots)
GET  /v1/scan/headers/{domain}    Live HTTP security header scan
GET  /v1/monitor/{domain}         Lightweight domain health check
GET  /v1/domain/{domain}/vulns    Tech stack CVE scan
POST /v1/domains/bulk             Bulk domain scan (max 50/call, same Free and Pro)  [cost: 1 per domain]
```

## IP & Network

```
GET /v1/ip/{ip}                   IP intel — PTR, ASN+name+country (inline), open ports, hostnames,
                                  severity-aware vulns (cve_id+severity+cvss_v3, v1.16.0 BREAKING),
                                  cloud provider, Tor exit, FireHOL reputation (free), AbuseIPDB+Shodan (pro),
                                  composite risk_score (0-100) + severity_label (low/medium/high/critical)
GET /v1/threat-report/{ip}        Orchestrated IP profile — InternetDB enrichment + AbuseIPDB + Shodan + ASN
                                  with full ip_lookup parity (PTR, ASN+name+country, cloud, Tor, FireHOL,
                                  risk_score). Severity-aware vulns shape matches /v1/ip.  [cost: 4]
GET /v1/asn/{target}              ASN lookup (AS number or IP) — IPv4/IPv6 prefixes, holder name
```

**Schema notes:**
- `vulns` is `list[{cve_id, severity, cvss_v3}]` — `severity='UNKNOWN'` means the CVE is not in our local cve.db (do not infer "benign").
- `cloud_provider` uses two-tier detection: published cloud CIDRs first, then ASN-to-provider fallback (e.g. `8.8.8.8 → AS15169 → 'Google'`).
- `tor_exit=false` is null-explicit — check `verdict.sources_unavailable` for `'tor'` to disambiguate "not listed" from "fetch failed".

## CVE Intelligence

```
GET  /v1/cve/leading              CVEs indexed before NVD (MITRE/GHSA-only)
GET  /v1/cve/{cve_id}             CVE details + EPSS + KEV  (affected_products truncated to 20 by default; ?include_affected_products=true for full list; total_products has honest count)
GET  /v1/cve/{cve_id}/risk_score  Composite risk score (CVSS+EPSS+KEV+PoC fusion, 0-100) with label (CRITICAL/HIGH/MEDIUM/LOW), urgency, recommendation
GET  /v1/cvss/details?vector=     Parse a CVSS v3.x vector string into per-metric breakdown + recomputed base score
GET  /v1/cves?product=&severity=&kev=&epss_min=&sort=&offset=  Search CVEs (with pagination)
GET  /v1/exploit/{cve_id}         Public exploit search (GitHub Advisory + Shodan)
POST /v1/cves/bulk                Bulk CVE lookup (max 50/call, same Free and Pro)  [cost: 1 per item]  (body supports include_affected_products: bool)
GET  /v1/kev/{cve_id}             CISA KEV detail (federal patch deadline, required action, ransomware association, CWE list)
GET  /v1/cwe/{cwe_id}             MITRE CWE catalog (research view 1000) — description, mitigations, parent/child weakness chain, CVE count
```

`total_products` is always emitted on CVE responses (even when `0`) and reflects the true count of affected products in the CVE database — independent of whether `affected_products` was truncated. The opt-in `include_affected_products=true` is available on both free and pro tiers; full-list requests on Log4j-class CVEs (50+ products) can return ~25 KB per item, so bulk callers should prefer the default for summary scans and opt in only for dependency audits.

```
```

## Threat Intelligence / IOC

```
GET  /v1/ioc/{indicator}          Unified IOC enrichment (IP, domain, URL, hash)
GET  /v1/hash/{hash}              Malware hash reputation (MalwareBazaar)
GET  /v1/password/{sha1}          Password breach check (HIBP, k-anonymity)
GET  /v1/phishing/{url}           Phishing/malware URL check (URLhaus)
POST /v1/iocs/bulk                Bulk IOC enrichment (max 50/call, same Free and Pro)  [cost: 1 per item]
```

## OSINT

```
GET /v1/email/mx/{domain}         Mail provider detection + email security grade
GET /v1/email/disposable/{email}  Disposable/temporary email check
GET /v1/email/verify/{email}      Combined: syntax + MX + disposable + role + free-provider (no SMTP probe)  [v1.25.0]
GET /v1/phone/{number}            Phone number OSINT (carrier, type, country)
GET /v1/username/{username}       Username OSINT (16 platforms, account discovery)
```

## Web Intelligence (v1.25.0)

Single-page audits with explicit ethical floor: per-target eTLD+1 throttle (60/min), self-identifying UA (`ContrastAPI/<version> (+https://api.contrastcyber.com/bot)`), robots.txt respected, Cache-Control honoured, no SMTP probing.

```
GET /v1/robots/{domain}           Parsed robots.txt — sitemaps, per-UA allow/disallow, crawl-delay (RFC 9309)
GET /v1/redirect/{url:path}       Walk URL redirect chain hop-by-hop, SSRF-guarded at every hop
GET /v1/brand/{domain}            Public brand assets from homepage <head>: favicon, og:image, theme-color, og:site_name, JSON-LD logo  [cost: 2]
GET /v1/seo/{domain}              One-page SEO audit + 0-100 composite score (10 rules) + missing_signals  [cost: 2]
```

**Ethics & guardrails:**
- robots.txt is honoured — `Disallow: /` for our UA OR `*` returns 403 `error.code = robots_txt_disallow` and we DO NOT fetch.
- `Cache-Control: no-store`/`private` from the target skips our cache write (`cache_respected=false` flags it).
- Per-target throttle uses eTLD+1 — subdomain rotation (`a1.victim.com` / `a2.victim.com`) collapses to the same bucket.
- All target-derived strings are control-char stripped (Trojan-Source / RTL bidi guard) and flagged `_untrusted` in the schema (DO NOT execute or shell-out).
- `email_verify` deliberately does NOT do SMTP RCPT TO probing — Hunter.io / NeverBounce-style mailbox enumeration is an ethical grey area we declined.

## Code Security

```
POST /v1/check/headers            Validate HTTP security headers
POST /v1/check/secrets            Detect hardcoded secrets
POST /v1/check/injection          SQL/cmd injection patterns
POST /v1/check/dependencies       Check packages for known CVEs
```

## MITRE ATLAS (AI/ML attack catalog)

```
GET  /v1/atlas/{technique_id}                Lookup ATLAS technique (AML.T#### or AML.T####.###); sub-techniques inherit parent tactics (inherited_tactics flag)
GET  /v1/atlas/techniques?keyword=&tactic=&maturity=&exclude_id=    Search techniques (keyword / AML.TA tactic / demonstrated|feasible|realized / optional self-exclude)
POST /v1/atlas/techniques/bulk               Bulk lookup up to 50 ATLAS technique ids in one call (drill case-study techniques_used in a single request)
GET  /v1/atlas/case-studies/{case_study_id}  Lookup ATLAS case study (AML.CS####); ?include=full for verbose narrative
GET  /v1/atlas/case-studies?keyword=&technique_id=      Search case studies (keyword / referenced AML.T technique)
```

## MITRE D3FEND (defense technique catalog)

```
GET  /v1/d3fend/{defense_id}                 Lookup D3FEND defense by slug (e.g. TokenBinding, ContentFiltering) — returns tactic, artifact, mapped ATT&CK T-codes
GET  /v1/d3fend/defenses?keyword=&tactic=&artifact=&include=&exclude_id=  Search defenses (keyword / 7 D3FEND tactics / targeted artifact / slim-default uri-drop / optional self-exclude)
GET  /v1/d3fend/attack/{attack_technique_id} Reverse: ATT&CK T-code -> mitigating D3FEND defenses (?include=full for uri; ?exclude_id= for self-skip; returns 200 with empty list when no mapping; gap is signal)
POST /v1/d3fend/coverage                     Batch coverage breakdown for a list of ATT&CK T-codes (max 500); identifies undefended techniques
```

## Sigma Detection Rules (v1.32.0 — SigmaHQ corpus, daily sync)

```
GET  /v1/sigma/{rule_id}                     Lookup Sigma rule by UUID — full rule with title, level, logsource, detection, tags (attack.t#### / cve.YYYY-####)
GET  /v1/sigma/search?technique=&cve_id=&logsource_product=&logsource_category=&query=&status=&level=&limit=&offset=  Search 3,200+ rules by ATT&CK technique, CVE, logsource, freetext (capped 1-200/page)
POST /v1/sigma/bulk                          Bulk lookup up to 50 Sigma rule UUIDs in one call (per-item status: ok / not_found / invalid_format)
```

## Meta

```
GET /v1/status                    Health check + version + data source status
GET /v1/usage                     Current rate limit usage (requires API key)
```

---

## Credit Costs

Most endpoints consume **1 credit** per call. Aggregating endpoints that fan out to multiple upstream sources cost more:

| Endpoint | Cost | Reason |
|---|---|---|
| Most endpoints | 1 | Single upstream call or cache hit |
| `GET /v1/audit/{domain}` | 4 | Full report + tech fingerprint + live headers (parallel fan-out) |
| `GET /v1/scan/{domain}` | 6 | C scanner engine (11 modules: headers/SSL/DNS/CSP/cookies/CORS/...) + severity-ranked findings |
| `GET /v1/threat-report/{ip}` | 4 | Shodan + AbuseIPDB + ASN aggregated |
| `GET /v1/brand/{domain}` | 2 | Homepage fetch + robots.txt fetch (parallel) + BS4 parse |
| `GET /v1/seo/{domain}` | 2 | Homepage fetch + robots.txt fetch (parallel) + 10-rule scorer |
| `POST /v1/cves/bulk` | N | One credit per CVE ID in the batch |
| `POST /v1/iocs/bulk` | N | One credit per indicator in the batch |

Every authenticated response includes an `X-RateLimit-Cost` header alongside `X-RateLimit-Remaining` so you can track usage transparently.

Bulk endpoints enforce atomic consumption: either the whole batch fits in your remaining quota or the request is rejected with `429` before any work runs.

## Data Sources

| Source | Records | Update Frequency |
|---|---|---|
| NVD (NIST) | 340k+ CVEs | Every 2 hours |
| CISA KEV | 1,500+ exploited vulns | Every 2 hours |
| FIRST EPSS | 323k+ exploit scores | Every 2 hours |
| URLhaus (abuse.ch) | Malware URLs | Real-time |
| MalwareBazaar | Malware hashes | Real-time |
| AbuseIPDB | IP reputation | Real-time |
| Shodan InternetDB | IP + ASN | Real-time |
| HIBP (Pwned Passwords) | 850M+ breached hashes | Monthly |

## Response Format

All endpoints return JSON with a consistent envelope. Example (`GET /v1/cve/CVE-2024-3094`):

```json
{
  "cve_id": "CVE-2024-3094",
  "severity": "CRITICAL",
  "cvss_v3": 10.0,
  "epss": { "score": 0.84976, "percentile": 0.99346 },
  "kev": { "in_kev": false },
  "summary": "CRITICAL (CWE-506) — Malicious code in xz upstream tarballs (5.6.0/5.6.1). Supply chain attack affecting liblzma. CVSS 10.0, EPSS 85%."
}
```

The `summary` field is **LLM-optimized** — AI agents can reason about the result without parsing nested JSON.

### Verdict & next_calls

Most response models include two MCP-friendly metadata blocks:

- **`verdict`** — Falsifiability metadata: `{deterministic, falsifiable_fields, sources_queried, sources_unavailable, completeness, data_age_seconds}`. Lets agents distinguish "no data" from "source failed" — critical for chain-of-thought integrity.
- **`next_calls`** — Conditional pivot hints suggesting follow-up MCP tools (e.g. `kev_detail` when `kev.in_kev=true`, `exploit_lookup` when `cwe_id` is set, `asn_lookup` when an ASN is populated).

### Typed sub-models

All nested fields use typed Pydantic sub-models (no opaque dicts). Notable shapes:

- `IpEnrichmentInfo` — Shodan InternetDB block on `/v1/threat-report` (mirrors top-level `/v1/ip` enrichment).
- `IocSourcesInfo` — `{threatfox, feodo, urlhaus, tor}` per-source results (which keys are present depends on indicator type — see `/v1/ioc`).
- `AbuseIpdbInfo` / `ShodanRepInfo` — Pro-tier reputation blocks. On Free tier these emit `{status:'pro_only', reason, upgrade_url}` upsell stubs (NOT errors).
- `VulnInfo` — `{cve_id, severity, cvss_v3}` shape used by `vulns` arrays in `/v1/ip` and `/v1/threat-report` (Phase 2 IP enrichment, v1.16.0 BREAKING).

## OpenAPI Spec

Machine-readable spec (for codegen, OpenAPI clients, etc.):

```
https://api.contrastcyber.com/openapi.json
```
