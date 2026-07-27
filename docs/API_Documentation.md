# ContrastAPI — API Documentation

**Version:** 1.33.19  
**Base URL:** `https://api.contrastcyber.com`

## Endpoint Index

**Domain Intelligence**

- [Full Domain Report — `GET /v1/domain/{domain}`](#full-domain-report--get-v1domaindomain)
- [Domain Audit — `GET /v1/audit/{domain}` &nbsp;`[cost: 6]`](#domain-audit--get-v1auditdomain-cost-6)
- [Website Security Scan — `GET /v1/scan/{domain}` &nbsp;`[cost: 6]`](#website-security-scan--get-v1scandomain-cost-6)
- [DNS Records — `GET /v1/dns/{domain}`](#dns-records--get-v1dnsdomain)
- [WHOIS — `GET /v1/whois/{domain}`](#whois--get-v1whoisdomain)
- [Subdomain Enumeration — `GET /v1/subdomains/{domain}`](#subdomain-enumeration--get-v1subdomainsdomain)
- [Certificate Transparency — `GET /v1/certs/{domain}`](#certificate-transparency--get-v1certsdomain)
- [SSL/TLS Analysis — `GET /v1/ssl/{domain}`](#ssltls-analysis--get-v1ssldomain)
- [Technology Fingerprint — `GET /v1/tech/{domain}`](#technology-fingerprint--get-v1techdomain)
- [URLhaus Domain Threat — `GET /v1/threat/{domain}`](#urlhaus-domain-threat--get-v1threatdomain)
- [Wayback History — `GET /v1/archive/{domain}`](#wayback-history--get-v1archivedomain)
- [HTTP Security Headers (live) — `GET /v1/scan/headers/{domain}`](#http-security-headers-live--get-v1scanheadersdomain)
- [Domain Health Monitor — `GET /v1/monitor/{domain}`](#domain-health-monitor--get-v1monitordomain)
- [Tech-Stack CVE Scan — `GET /v1/domain/{domain}/vulns` &nbsp;`[cost: 4]`](#tech-stack-cve-scan--get-v1domaindomainvulns-cost-4)
- [Bulk Domain Scan — `POST /v1/domains/bulk` &nbsp;`[cost: 1 per domain]`](#bulk-domain-scan--post-v1domainsbulk-cost-1-per-domain)
- [Email Security Posture — `GET /v1/email/security-posture/{domain}`](#email-security-posture--get-v1emailsecurity-posturedomain)
- [Email Verify — `GET /v1/email/verify/{email}`](#email-verify--get-v1emailverifyemail)
- [Mail Provider / MX — `GET /v1/email/mx/{domain}`](#mail-provider--mx--get-v1emailmxdomain)
- [Disposable Email Check — `GET /v1/email/disposable/{email}`](#disposable-email-check--get-v1emaildisposableemail)
- [robots.txt — `GET /v1/robots/{domain}`](#robotstxt--get-v1robotsdomain)
- [Redirect Chain — `GET /v1/redirect/{url:path}`](#redirect-chain--get-v1redirecturlpath)
- [Brand Assets — `GET /v1/brand/{domain}` &nbsp;`[cost: 1]`](#brand-assets--get-v1branddomain-cost-1)
- [SEO Audit — `GET /v1/seo/{domain}` &nbsp;`[cost: 1]`](#seo-audit--get-v1seodomain-cost-1)
- [GEO Audit — `GET /v1/geo/{domain}` &nbsp;`[cost: 1]`](#geo-audit--get-v1geodomain-cost-1)

**IP & Network Intelligence**

- [IP Intelligence — `GET /v1/ip/{ip}`](#ip-intelligence--get-v1ipip)
- [IP Threat Report — `GET /v1/threat-report/{ip}` &nbsp;`[cost: 6]`](#ip-threat-report--get-v1threat-reportip-cost-6)
- [ASN Lookup — `GET /v1/asn/{target}`](#asn-lookup--get-v1asntarget)

**CVE Intelligence**

- [CVE Details — `GET /v1/cve/{cve_id}`](#cve-details--get-v1cvecve_id)
- [CVE Risk Score — `GET /v1/cve/{cve_id}/risk_score`](#cve-risk-score--get-v1cvecve_idrisk_score)
- [CVSS Vector Parser — `GET /v1/cvss/details?vector=`](#cvss-vector-parser--get-v1cvssdetailsvector)
- [CVE Search — `GET /v1/cves`](#cve-search--get-v1cves)
- [Leading CVEs — `GET /v1/cve/leading`](#leading-cves--get-v1cveleading)
- [Exploit Lookup — `GET /v1/exploit/{cve_id}`](#exploit-lookup--get-v1exploitcve_id)
- [KEV Detail — `GET /v1/kev/{cve_id}`](#kev-detail--get-v1kevcve_id)
- [CWE Lookup — `GET /v1/cwe/{cwe_id}`](#cwe-lookup--get-v1cwecwe_id)
- [Bulk CVE Lookup — `POST /v1/cves/bulk` &nbsp;`[cost: 1 per ID]`](#bulk-cve-lookup--post-v1cvesbulk-cost-1-per-id)

**Threat Intelligence / IOC**

- [IOC Lookup — `GET /v1/ioc/{indicator}`](#ioc-lookup--get-v1iocindicator)
- [Hash Reputation — `GET /v1/hash/{hash}`](#hash-reputation--get-v1hashhash)
- [Password Breach — `GET /v1/password/{sha1}`](#password-breach--get-v1passwordsha1)
- [Phishing Check — `GET /v1/phishing/{url}`](#phishing-check--get-v1phishingurl)
- [Bulk IOC — `POST /v1/iocs/bulk` &nbsp;`[cost: 1 per indicator]`](#bulk-ioc--post-v1iocsbulk-cost-1-per-indicator)

**OSINT**

- [Phone Lookup — `GET /v1/phone/{number}`](#phone-lookup--get-v1phonenumber)
- [Username Lookup — `GET /v1/username/{username}`](#username-lookup--get-v1usernameusername)

**Code Security**

- [Validate Security Headers — `POST /v1/check/headers`](#validate-security-headers--post-v1checkheaders)
- [Detect Secrets — `POST /v1/check/secrets`](#detect-secrets--post-v1checksecrets)
- [Detect Injection — `POST /v1/check/injection`](#detect-injection--post-v1checkinjection)
- [Check Dependencies — `POST /v1/check/dependencies`](#check-dependencies--post-v1checkdependencies)

**MITRE ATLAS**

- [ATLAS Technique — `GET /v1/atlas/{technique_id}`](#atlas-technique--get-v1atlastechnique_id)
- [ATLAS Technique Search — `GET /v1/atlas/techniques`](#atlas-technique-search--get-v1atlastechniques)
- [Bulk ATLAS Technique — `POST /v1/atlas/techniques/bulk` &nbsp;`[cost: 1 per ID]`](#bulk-atlas-technique--post-v1atlastechniquesbulk-cost-1-per-id)
- [ATLAS Case Study — `GET /v1/atlas/case-studies/{case_study_id}`](#atlas-case-study--get-v1atlascase-studiescase_study_id)
- [ATLAS Case Study Search — `GET /v1/atlas/case-studies`](#atlas-case-study-search--get-v1atlascase-studies)

**MITRE D3FEND**

- [D3FEND Defense — `GET /v1/d3fend/{defense_id}`](#d3fend-defense--get-v1d3fenddefense_id)
- [D3FEND Defense Search — `GET /v1/d3fend/defenses`](#d3fend-defense-search--get-v1d3fenddefenses)
- [Defenses for Attack — `GET /v1/d3fend/attack/{attack_technique_id}`](#defenses-for-attack--get-v1d3fendattackattack_technique_id)
- [D3FEND Coverage — `POST /v1/d3fend/coverage` &nbsp;`[cost: 1 per T-code]`](#d3fend-coverage--post-v1d3fendcoverage-cost-1-per-t-code)

**Sigma Detection Rules**

- [Sigma Rule — `GET /v1/sigma/{rule_id}`](#sigma-rule--get-v1sigmarule_id)
- [Sigma Search — `GET /v1/sigma/search`](#sigma-search--get-v1sigmasearch)
- [Bulk Sigma — `POST /v1/sigma/bulk` &nbsp;`[cost: 1 per UUID]`](#bulk-sigma--post-v1sigmabulk-cost-1-per-uuid)

**Meta**

- [Status — `GET /v1/status`](#status--get-v1status)
- [Usage — `GET /v1/usage`](#usage--get-v1usage)

## Authentication

```
Authorization: Bearer cc_<48-hex-chars>
```

Omit the header for free-tier (anonymous) access tracked by client IP. Malformed key format returns `401`.

## Rate Limiting

| Tier | Limit | Identity |
|---|---|---|
| Free | 30 tokens / hour | Client IP |
| Pro | 500 tokens / hour | API key |

**Burst gate:** ~10 concurrent requests/second on `/v1/cve/*` and `/v1/check/*`; 100 on `POST /mcp/`. Exceeding burst returns `429` immediately, independent of the hourly quota.

**Per-target throttle:** 60 requests/minute per eTLD+1 for all web-intelligence endpoints (robots, redirect, brand, seo, geo, domain, audit, scan). Subdomain rotation (`a1.victim.com` / `a2.victim.com`) maps to the same bucket.

### Rate-limit response headers

| Header | Type | Description |
|---|---|---|
| `X-RateLimit-Cost` | integer | Tokens consumed by this request |
| `X-RateLimit-Remaining` | integer | Tokens remaining in the current hour |
| `Retry-After` | integer | Seconds until window resets (429 responses only) |

### 429 body

```json
{
  "error": {
    "code": "rate_limit_exceeded",
    "message": "Rate limit exceeded (30/hr). Upgrade to Pro (500/hr): https://api.contrastcyber.com/pricing",
    "retry_after_seconds": 1847
  }
}
```

### Best practices

- Honour `Retry-After` — sleep at least that many seconds before retrying.
- Watch `X-RateLimit-Remaining` proactively. Slow down when it falls below your concurrency level.
- Use bulk endpoints for batch work — `POST /v1/cves/bulk`, `POST /v1/iocs/bulk`, `POST /v1/atlas/techniques/bulk`. Single HTTP round-trip, N tokens.
- Bulk requests are all-or-nothing: if the batch cost exceeds remaining quota, the entire request is rejected with `429` before any work runs.

---

## Token Costs

| Endpoint | Cost | Reason |
|---|---|---|
| Most endpoints | 1 | Single upstream source |
| `GET /v1/audit/{domain}` | 6 | DNS + WHOIS + SSL + CT + subdomains + tech + headers + email (9–11 sources) |
| `GET /v1/scan/{domain}` | 6 | C scanner engine — 11 active modules (headers/SSL/DNS/CSP/cookies/CORS/DNSSEC/methods/redirect/disclosure/HTML) + findings |
| `GET /v1/threat-report/{ip}` | 6 | IP enrich + AbuseIPDB + Shodan + ASN + Tor + cloud + FireHOL + CVE (8 sources) |
| `GET /v1/domain/{domain}/vulns` | 4 | Tech fingerprint + bulk CVE per product |
| `GET /v1/brand/{domain}` | 1 | Homepage fetch + robots.txt |
| `GET /v1/seo/{domain}` | 1 | Homepage fetch + robots.txt + 10-rule scorer |
| `GET /v1/geo/{domain}` | 1 | Homepage + robots.txt + llms.txt fetch + 7-rule GEO scorer |
| `POST /v1/cves/bulk` | N | 1 token per CVE ID (max 50) |
| `POST /v1/iocs/bulk` | N | 1 token per indicator (max 50) |
| `POST /v1/domains/bulk` | N | 1 token per domain (max 50) |
| `POST /v1/atlas/techniques/bulk` | N | 1 token per technique ID (max 50) |
| `POST /v1/sigma/bulk` | N | 1 token per rule UUID (max 50) |
| `POST /v1/d3fend/coverage` | N | 1 token per ATT&CK T-code (max 500) |

---

## Response Format

All endpoints return JSON. Every response includes a `summary` string — a human-readable one-liner optimised for LLM reasoning without JSON parsing.

Most endpoints also include:

- **`verdict`** — Falsifiability metadata:
  ```json
  {
    "deterministic": true,
    "falsifiable_fields": ["cvss_v3", "epss.score"],
    "sources_queried": ["nvd", "epss", "kev"],
    "sources_unavailable": [],
    "completeness": 1.0,
    "data_age_seconds": 3712
  }
  ```
  Use `sources_unavailable` to distinguish "not listed" from "source failed".

- **`next_calls`** — Conditional pivot hints for chained workflows:
  ```json
  [{"tool": "kev_detail", "input": "CVE-2026-20182", "reason": "in_kev=true"}]
  ```

### Error envelope

```json
{
  "error": {
    "code": "not_found",
    "message": "CVE-2099-99999 not found in database"
  }
}
```

---

## Endpoints

> Every endpoint accepts an API key via **either** `Authorization: Bearer cc_...` **or** `X-API-Key: cc_...` (see [Authentication](#authentication)); omit the header for free-tier access. Examples below show one representative call — swap the auth header freely. All example responses are **live production output** (trimmed where arrays are long; `… (N total)` marks truncation).

---

## Domain Intelligence

Ethical guardrails apply to all web-intel endpoints (robots, redirect, brand, seo, geo, domain, audit, scan, tech):

- `robots.txt Disallow` for our UA or `*` → `403 error.code=robots_txt_disallow`, no fetch performed.
- `Cache-Control: no-store` / `private` from the target skips our cache write (`cache_respected=false`).
- Target-derived strings are control-char stripped (Trojan-Source / RTL bidi guard) and marked `_untrusted`.
- Self-identifying user agent: `ContrastAPI/<version> (+https://contrastcyber.com/bot)`.

---

### Full Domain Report — `GET /v1/domain/{domain}`

One-call domain profile: DNS + reverse DNS + WHOIS + SSL + subdomains + Certificate Transparency + email security + WAF + URLhaus threat + composite risk grade + IP reputation. `verdict.sources_unavailable` flags any source that failed (CT logs frequently time out — see `certificates.crtsh_status`).

```bash
# Free tier (no key, 30 tokens/hr):
curl https://api.contrastcyber.com/v1/domain/contrastcyber.com

# Pro (500 tokens/hr):
curl https://api.contrastcyber.com/v1/domain/contrastcyber.com \
  -H "Authorization: Bearer $KEY"
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `domain` | string | Queried domain |
| `dns` | object | `a`, `aaaa`, `mx`, `ns`, `txt`, `total_txt_records`, `soa` |
| `reverse_dns` | object | `ip`, `ptr`, `shared_hosting` |
| `whois` | object | `registrar`, `creation_date`, `expiry_date`, `updated_date`, `name_servers`, `status`, `raw_length` |
| `ssl` | object | `common_name`, `issuer`, `not_after`, `tls_version`, `san`, `days_remaining`, `grade`, `cert_valid` |
| `subdomains` | object | `subdomains`, `count`, `found_via_wordlist`, `found_via_crtsh`, `crtsh_status` |
| `certificates` | object | `total_certificates`, `certificates`, `error`, `crtsh_status` |
| `email_security` | object | `spf`, `dmarc`, `dkim_selectors`, `dkim_status`, `grade`, `issues` |
| `waf` | object | `detected` (array), `waf_present` (bool) |
| `threat` | object | URLhaus: `urlhaus_status`, `url_count`, `urls_online`, `threat_types`, `tags`, `urls` |
| `risk` | object | `score`, `max_score`, `grade`, `factors[]` (per-dimension scoring). `max_score` is **not always 100** — a dimension we could not measure is dropped from the denominator instead of penalizing the domain, so observed values are 100, 95, 90, 85, 80 and 75 (crt.sh failure drops the CT factor, an unverifiable DKIM selector trims the email factor, wildcard DNS can drop the subdomain factor). Always compute percentages against `max_score`, never against a literal 100. |
| `risk_score` | integer | Composite 0–`max_score` (top-level convenience copy) |
| `reputation` | object | `abuseipdb` (Pro), `shodan` (Pro) |
| `verdict` | object | Falsifiability metadata; `sources_unavailable`, `completeness` |
| `summary` | string | Human/LLM one-liner |

#### Example response

```json
{
  "verdict": {
    "deterministic": true,
    "falsifiable_fields": ["dns", "whois", "ssl", "subdomains", "certificates"],
    "data_age_seconds": 0,
    "sources_queried": ["dns", "ssl", "whois", "subdomains", "ct_logs", "urlhaus", "reputation"],
    "sources_unavailable": ["ct_logs"],
    "completeness": "partial"
  },
  "domain": "contrastcyber.com",
  "dns": {
    "a": ["188.114.96.3", "188.114.97.3"],
    "aaaa": ["2a06:98c1:3121::3", "2a06:98c1:3120::3"],
    "mx": [{"priority": 5, "host": "mta-gw.infomaniak.ch"}],
    "ns": ["zita.ns.cloudflare.com.", "kanye.ns.cloudflare.com."],
    "txt": ["v=spf1 include:spf.infomaniak.ch -all", "v=MCPv1; k=ed25519; p=6HIhN2HONPc8ccMSEUR+i9xAebYbvFic56MhswPX73M=", "google-site-verification=Rvk38xUF…"],
    "total_txt_records": 3,
    "soa": {"mname": "zita.ns.cloudflare.com", "rname": "dns.cloudflare.com"}
  },
  "reverse_dns": {"ip": "188.114.97.3"},
  "whois": {
    "registrar": "Cloudflare, Inc.",
    "creation_date": "2026-03-19T04:33:26Z",
    "expiry_date": "2027-03-19T04:33:26Z",
    "updated_date": "2026-03-25T13:21:57Z",
    "name_servers": ["kanye.ns.cloudflare.com", "zita.ns.cloudflare.com"],
    "status": ["clientTransferProhibited https://icann.org/epp#clientTransferProhibited"],
    "raw_length": 3184
  },
  "ssl": {
    "common_name": "contrastcyber.com",
    "issuer": "Let's Encrypt",
    "not_after": "Aug 15 08:29:33 2026 GMT",
    "tls_version": "TLSv1.3",
    "san": ["*.contrastcyber.com", "contrastcyber.com"],
    "days_remaining": 80,
    "grade": "A",
    "cert_valid": true
  },
  "subdomains": {
    "subdomains": ["api.contrastcyber.com", "www.contrastcyber.com"],
    "count": 2,
    "found_via_wordlist": 2,
    "found_via_crtsh": 0,
    "crtsh_status": "ok"
  },
  "certificates": {"total_certificates": 0, "certificates": [], "crtsh_status": "timeout"},
  "email_security": {
    "spf": "v=spf1 include:spf.infomaniak.ch -all",
    "dmarc": "v=DMARC1; p=reject; rua=mailto:…",
    "dkim_selectors": [],
    "dkim_status": "unverifiable",
    "grade": "A",
    "issues": []
  },
  "waf": {"detected": ["Cloudflare"], "waf_present": true},
  "threat": {"urlhaus_status": "clean", "url_count": 0, "urls_online": 0, "threat_types": [], "tags": [], "urls": []},
  "risk": {
    "score": 85,
    "max_score": 90,
    "grade": "A",
    "factors": [
      {"name": "SSL/TLS", "score": 20, "max": 20, "detail": "TLS 1.3, valid certificate"},
      {"name": "WAF", "score": 10, "max": 10, "detail": "Cloudflare detected"},
      {"name": "Email Security", "score": 25, "max": 25, "detail": "SPF, DMARC"}
    ]
  },
  "reputation": {},
  "risk_score": 85,
  "summary": "contrastcyber.com resolves to 188.114.97.3. Security grade A (85/100). SSL grade A by Let's Encrypt. Behind Cloudflare. Email security: A. 2 subdomains found"
}
```

---

### Domain Audit — `GET /v1/audit/{domain}` &nbsp;`[cost: 6]`

Everything in the Full Domain Report **plus** technology fingerprint and the raw live response headers. Returns `report` (same shape as `GET /v1/domain/{domain}`), `technologies`, and `live_headers`.

```bash
# Free tier (no key, 30 tokens/hr):
curl https://api.contrastcyber.com/v1/audit/contrastcyber.com

# Pro (500 tokens/hr):
curl https://api.contrastcyber.com/v1/audit/contrastcyber.com \
  -H "Authorization: Bearer $KEY"
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `report` | object | Full domain report (identical shape to `GET /v1/domain/{domain}`) |
| `technologies` | object | `technologies[]`, `categories`, `count` (see Technology Fingerprint) |
| `live_headers` | object | Raw HTTP response headers from the live homepage fetch |
| `summary` | string | Inherited from the report |

#### Example response

```json
{
  "domain": "contrastcyber.com",
  "report": { "…": "identical to GET /v1/domain/{domain}" },
  "technologies": {"technologies": [{"name": "Cloudflare", "category": "CDN", "source": "header"}], "categories": {"CDN": ["Cloudflare"]}, "count": 1, "summary": "1 technologies detected: Cloudflare"},
  "live_headers": {
    "content-type": "text/html; charset=utf-8",
    "server": "cloudflare",
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy": "…",
    "x-frame-options": "…",
    "permissions-policy": "…",
    "cross-origin-opener-policy": "…",
    "cf-cache-status": "…",
    "cf-ray": "…"
  },
  "summary": "contrastcyber.com resolves to 188.114.97.3. Security grade A (85/100). SSL grade A by Let's Encrypt. Behind Cloudflare. …"
}
```

---

### Website Security Scan — `GET /v1/scan/{domain}` &nbsp;`[cost: 6]`

Active website security scan: runs the ContrastScan C engine against the live site across **11 modules** — HTTP security headers, SSL/TLS, DNS, redirect chain, information disclosure, cookie flags, DNSSEC, HTTP methods, CORS, HTML hygiene, and deep CSP analysis — then enriches the raw result with **severity-ranked findings** and a **letter grade**. Use this for a hands-on misconfiguration scan; use `GET /v1/audit/{domain}` for passive recon (DNS/WHOIS/SSL/threat intel) and `GET /v1/scan/headers/{domain}` for headers only.

The domain is DNS-resolved once and the scan is pinned to that IP (SSRF defense — bare IPs and private-resolving domains are rejected). Because the scan makes active outbound requests, a **per-target eTLD+1 throttle (60 req/min)** applies on top of your rate limit.

```bash
# Free tier (no key, 30 tokens/hr):
curl https://api.contrastcyber.com/v1/scan/contrastcyber.com

# Pro (500 tokens/hr):
curl https://api.contrastcyber.com/v1/scan/contrastcyber.com \
  -H "Authorization: Bearer $KEY"
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `domain` | string | Scanned domain (lowercased, no scheme/path/port) |
| `resolved_ip` | string | IP the scanner pinned for the scan (`127.0.0.1` for the self-domain bypass) |
| `total_score` / `max_score` | integer | Aggregate security score across all modules / max achievable |
| `grade` | string | Letter grade A–F derived from `total_score / max_score` |
| `findings` | array | Severity-sorted findings (critical first); each carries `severity`, `category`, `title` + category-specific detail |
| `findings_count` | object | Counts by severity: `{critical, high, medium, low}` |
| `headers`, `ssl`, `dns`, `redirect`, `disclosure`, `cookies`, `dnssec`, `methods`, `cors`, `html`, `csp_analysis` | object | Per-module blocks: `{score, max, details}` |
| `enterprise` | object \| null | Present only for known enterprise domains (large-org scoring caveat) |
| `summary` | string | One-line scan summary |
| `next_calls` | array | Pivot hints → `subdomain_enum`, `tech_fingerprint`, `audit_domain` |

#### Example response

```json
{
  "domain": "contrastcyber.com",
  "resolved_ip": "188.114.97.3",
  "total_score": 85,
  "max_score": 100,
  "grade": "A",
  "findings": [
    {"severity": "medium", "category": "headers", "title": "Permissions-Policy not set", "recommendation": "…"}
  ],
  "findings_count": {"critical": 0, "high": 0, "medium": 1, "low": 2},
  "headers": {"score": 18, "max": 20, "details": {"…": "…"}},
  "ssl": {"score": 10, "max": 10, "details": {"grade": "A", "…": "…"}},
  "dns": {"score": 8, "max": 10, "details": {"…": "…"}},
  "csp_analysis": {"score": 7, "max": 10, "details": {"…": "…"}},
  "summary": "contrastcyber.com — security grade A (85/100), 0 critical / 0 high findings.",
  "next_calls": [
    {"tool": "subdomain_enum", "input": "contrastcyber.com", "reason": "Map attack surface — enumerate subdomains via crt.sh CT logs + DNS wordlist (passive)."}
  ]
}
```

> Active scan, self-identifying UA. It deliberately omits passive recon (WHOIS / subdomains / fingerprint) — chain `next_calls` or `GET /v1/audit/{domain}` for that.

---

### DNS Records — `GET /v1/dns/{domain}`

Resolves A, AAAA, MX, NS, TXT, CNAME, SOA records.

```bash
curl https://api.contrastcyber.com/v1/dns/contrastcyber.com
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `domain` | string | Queried domain |
| `records.a` / `records.aaaa` | array | IPv4 / IPv6 addresses |
| `records.mx` | array | `[{priority, host}]` |
| `records.ns` | array | Nameserver hostnames |
| `records.txt` | array | TXT records (SPF, verification tokens, …) |
| `records.total_txt_records` | integer | Honest count (records.txt may be truncated) |
| `records.soa` | object | `mname`, `rname`, `serial` |
| `summary` | string | Record-count one-liner |

#### Example response

```json
{
  "domain": "contrastcyber.com",
  "records": {
    "a": ["188.114.96.3", "188.114.97.3"],
    "aaaa": ["2a06:98c1:3121::3", "2a06:98c1:3120::3"],
    "mx": [{"priority": 5, "host": "mta-gw.infomaniak.ch"}],
    "ns": ["zita.ns.cloudflare.com.", "kanye.ns.cloudflare.com."],
    "txt": [
      "v=spf1 include:spf.infomaniak.ch -all",
      "v=MCPv1; k=ed25519; p=6HIhN2HONPc8ccMSEUR+i9xAebYbvFic56MhswPX73M=",
      "google-site-verification=Rvk38xUF…"
    ],
    "total_txt_records": 3,
    "soa": {"mname": "zita.ns.cloudflare.com", "rname": "dns.cloudflare.com"}
  },
  "summary": "2 A, 2 AAAA, 2 NS, 1 MX, 3 TXT, 1 SOA records for contrastcyber.com"
}
```

> The `v=MCPv1; k=ed25519; p=…` TXT record is an MCP-server DNS verification key — proof the domain operates a verified MCP endpoint.

---

### WHOIS — `GET /v1/whois/{domain}`

Registration data: registrar, key dates, nameservers, EPP status codes. Privacy-shielded registrant fields are not returned.

```bash
curl https://api.contrastcyber.com/v1/whois/contrastcyber.com
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `whois.registrar` | string | Registrar name |
| `whois.creation_date` | string (datetime) | Registration date |
| `whois.expiry_date` | string (datetime) | Expiry date |
| `whois.updated_date` | string (datetime) | Last update |
| `whois.name_servers` | array | Authoritative nameservers |
| `whois.status` | array | EPP status codes |
| `whois.raw_length` | integer | Length of raw WHOIS text (not returned in full) |
| `summary` | string | `domain — registrar — expires DATE` |

#### Example response

```json
{
  "domain": "contrastcyber.com",
  "whois": {
    "registrar": "Cloudflare, Inc.",
    "creation_date": "2026-03-19T04:33:26Z",
    "expiry_date": "2027-03-19T04:33:26Z",
    "updated_date": "2026-03-25T13:21:57Z",
    "name_servers": ["kanye.ns.cloudflare.com", "zita.ns.cloudflare.com"],
    "status": ["clientTransferProhibited https://icann.org/epp#clientTransferProhibited"],
    "raw_length": 3184
  },
  "summary": "contrastcyber.com — Cloudflare, Inc. — expires 2027-03-19T04:33:26Z"
}
```

---

### Subdomain Enumeration — `GET /v1/subdomains/{domain}`

Passive subdomain discovery: DNS wordlist brute-force + Certificate Transparency (crt.sh). `crtsh_status` distinguishes a clean `ok` from a `timeout` (crt.sh is frequently slow — wordlist results are still returned).

```bash
curl https://api.contrastcyber.com/v1/subdomains/contrastcyber.com
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `subdomains` | array | Discovered subdomains |
| `count` | integer | Total found |
| `sources` | array | `wordlist`, `crtsh` |
| `found_via_wordlist` | integer | Count from DNS brute-force |
| `found_via_crtsh` | integer | Count from CT logs |
| `wildcard_status` | string | `absent` \| `present` \| `undetermined` — result of two synthetic negative-control DNS probes. Anything other than `absent` means `count` is unverified: under `present` the wordlist plane is discarded and `count` is a CT-log lower bound. |
| `crtsh_status` | string | `ok` / `timeout` |
| `summary` | string | Count one-liner |

#### Example response

```json
{
  "domain": "contrastcyber.com",
  "count": 2,
  "subdomains": ["api.contrastcyber.com", "www.contrastcyber.com"],
  "sources": ["wordlist"],
  "found_via_wordlist": 2,
  "found_via_crtsh": 0,
  "crtsh_status": "ok",
  "summary": "2 subdomain(s) found for contrastcyber.com"
}
```

---

### Certificate Transparency — `GET /v1/certs/{domain}`

CT log certificate records (crt.sh). Returns `crtsh_status: timeout` + empty list when the upstream is slow — this is signal, not an error (HTTP stays 200).

```bash
curl https://api.contrastcyber.com/v1/certs/contrastcyber.com
```

#### Example response

```json
{
  "domain": "contrastcyber.com",
  "total_certificates": 0,
  "certificates": [],
  "summary": "0 certificates in CT logs for contrastcyber.com"
}
```

---

### SSL/TLS Analysis — `GET /v1/ssl/{domain}`

Live TLS handshake inspection: certificate chain (handshake + AIA fetch), protocol, cipher, validity window, SAN list, and an A–F grade.

```bash
curl https://api.contrastcyber.com/v1/ssl/contrastcyber.com
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `valid` | boolean | Certificate currently valid |
| `issuer` | string | Issuing CA |
| `subject` | string | Certificate subject |
| `not_before` / `not_after` | string | Validity window |
| `days_remaining` | integer | Days until expiry |
| `serial_number` | string | Cert serial (hex) |
| `san` | array | Subject Alternative Names |
| `protocol` | string | Negotiated TLS version |
| `cipher` | object | `name`, `protocol`, `bits` |
| `chain` | array | `[{subject, issuer, not_after, source}]` (`handshake` / `aia_fetch`) |
| `grade` | string | A–F |
| `validation_errors` / `warnings` | array | Issues found |

#### Example response

```json
{
  "domain": "contrastcyber.com",
  "valid": true,
  "issuer": "Let's Encrypt",
  "subject": "contrastcyber.com",
  "not_before": "May 17 08:29:34 2026 GMT",
  "not_after": "Aug 15 08:29:33 2026 GMT",
  "days_remaining": 80,
  "serial_number": "646110B7ACA9F9FD4B185802099A8C2E09D",
  "san": ["*.contrastcyber.com", "contrastcyber.com"],
  "protocol": "TLSv1.3",
  "cipher": {"name": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3", "bits": 256},
  "chain": [
    {"subject": "CN=contrastcyber.com", "issuer": "CN=E7,O=Let's Encrypt,C=US", "not_after": "2026-08-15T08:29:33", "source": "handshake"}
  ],
  "grade": "A",
  "validation_errors": [],
  "warnings": [],
  "summary": "contrastcyber.com — A. TLSv1.3, Let's Encrypt. 80 days remaining"
}
```

---

### Technology Fingerprint — `GET /v1/tech/{domain}`

Detects CMS, frameworks, CDN, analytics, web server, and fonts from live headers + HTML. Each technology carries its detection `source` (`header` / `html`). Sites behind a CDN that strip backend fingerprints legitimately return only the CDN (e.g. `contrastcyber.com` → just `Cloudflare`).

> The example below uses `wordpress.com` because it exposes a richer multi-technology stack — most production sites behind Cloudflare (including `contrastcyber.com`) return only the CDN.

```bash
curl https://api.contrastcyber.com/v1/tech/wordpress.com
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `technologies` | array | `[{name, category, source}]` |
| `categories` | object | Category → technology names |
| `count` | integer | Number detected |
| `summary` | string | One-liner |

#### Example response

```json
{
  "domain": "wordpress.com",
  "technologies": [
    {"name": "Nginx", "category": "Server", "source": "header"},
    {"name": "WordPress", "category": "CMS", "source": "html"},
    {"name": "Google Fonts", "category": "Font", "source": "html"}
  ],
  "categories": {"Server": ["Nginx"], "CMS": ["WordPress"], "Font": ["Google Fonts"]},
  "count": 3,
  "summary": "3 technologies detected: Nginx, WordPress, Google Fonts"
}
```

---

### URLhaus Domain Threat — `GET /v1/threat/{domain}`

Malware-URL lookup against abuse.ch URLhaus. Lists URLs hosted on the domain that are flagged as malware distribution. `urls_online` counts those still live. A clean domain returns `urlhaus_status: "clean"` with empty `urls`/`tags`.

> The example below uses `github.com` because it currently hosts flagged malware URLs (abused as free file hosting) and therefore populates every field — a clean domain such as `contrastcyber.com` returns empty arrays.

```bash
curl https://api.contrastcyber.com/v1/threat/github.com
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `urlhaus_status` | string | `listed` / `clean` |
| `url_count` | integer | Total flagged URLs |
| `urls_online` | integer | Currently online |
| `threat_types` | array | e.g. `malware_download` |
| `tags` | array | Malware family / campaign tags |
| `urls` | array | `[{url, status, threat, date_added, tags}]` (truncated) |

#### Example response

```json
{
  "domain": "github.com",
  "urlhaus_status": "listed",
  "url_count": 100,
  "urls_online": 2,
  "threat_types": ["malware_download"],
  "tags": ["dropped-by-amadey", "Smoke Loader", "RemcosRAT", "QuasarRAT", "stealer", "… (20 total)"],
  "urls": [
    {"url": "https://github.com/<redacted-path>/loader.ps1", "status": "offline", "threat": "malware_download", "date_added": "2026-05-19 09:43:11 UTC", "tags": ["RemcosRAT"]}
  ],
  "summary": "github.com — 100 URLs in URLhaus (2 online)"
}
```

---

### Wayback History — `GET /v1/archive/{domain}`

Internet Archive (Wayback Machine) coverage: first/last snapshot, total count, years online. `snapshots` can be very large for old domains.

```bash
curl https://api.contrastcyber.com/v1/archive/contrastcyber.com
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `status` | string | `ok` |
| `total_snapshots` | integer | Snapshot count |
| `first_seen` / `last_seen` | string (date) | Coverage window |
| `years_online` | integer | Span in years |
| `snapshots` | array | Snapshot timestamps (large) |
| `archive_url` | string | Wayback calendar URL |
| `summary` | string | One-liner |

#### Example response

```json
{
  "domain": "contrastcyber.com",
  "status": "ok",
  "total_snapshots": 1,
  "first_seen": "2026-03-28",
  "last_seen": "2026-03-28",
  "years_online": 1,
  "snapshots": ["20260328…"],
  "archive_url": "https://web.archive.org/web/*/contrastcyber.com",
  "summary": "contrastcyber.com — 1 snapshot from 2026 to 2026 (1 year). Last archived 2026-03-28."
}
```

---

### HTTP Security Headers (live) — `GET /v1/scan/headers/{domain}`

Fetches the live homepage and grades its security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy). Each finding includes severity, validity, the observed value, concrete issues, and remediation. (For validating a header set you already have, use `POST /v1/check/headers`.)

```bash
curl https://api.contrastcyber.com/v1/scan/headers/contrastcyber.com
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `status_code` | integer | HTTP status of the fetched page |
| `url` | string | Final fetched URL |
| `score` | integer | 0–100 |
| `grade` | string | A–F |
| `findings` | array | `[{header, severity, present, valid, value, issues, description, remediation, reference}]` |
| `headers_present` / `headers_missing` | array | Quick lists |
| `summary` | string | One-liner |

#### Example response

```json
{
  "domain": "contrastcyber.com",
  "status_code": 200,
  "url": "https://contrastcyber.com/",
  "score": 100,
  "grade": "A",
  "findings": [
    {"header": "Content-Security-Policy", "severity": "high", "present": true, "valid": true, "value": "…", "issues": []},
    {"header": "Strict-Transport-Security", "severity": "high", "present": true, "valid": true, "value": "max-age=63072000; includeSubDomains; preload", "issues": []},
    {"header": "Permissions-Policy", "severity": "low", "present": true, "valid": true, "value": "…", "issues": []}
  ],
  "headers_present": ["Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"],
  "headers_missing": [],
  "summary": "6/6 security headers present — score 100/100 (grade A)"
}
```

---

### Domain Health Monitor — `GET /v1/monitor/{domain}`

Lightweight liveness probe: DNS resolves + HTTP reachable + SSL grade/expiry + composite risk grade. Cheaper and faster than the full report for uptime checks.

```bash
curl https://api.contrastcyber.com/v1/monitor/contrastcyber.com
```

#### Example response

```json
{
  "domain": "contrastcyber.com",
  "is_up": true,
  "ssl_days_remaining": 80,
  "ssl_grade": "A",
  "dns_a": ["188.114.96.3", "188.114.97.3"],
  "dns_changed": false,
  "risk_grade": "A",
  "risk_score": 85,
  "summary": "contrastcyber.com is up. SSL A (80 days). Grade A. DNS unchanged"
}
```

---

### Tech-Stack CVE Scan — `GET /v1/domain/{domain}/vulns` &nbsp;`[cost: 4]`

Fingerprints the tech stack, then bulk-looks-up known CVEs per detected technology. `severity='UNKNOWN'` means the CVE is not in the local DB — do not infer "benign". Domains that expose no fingerprint (e.g. behind a CDN) return `0 technologies scanned`.

> The example below uses `wordpress.com` because its detectable stack (Nginx, WordPress) yields multiple CVEs including a KEV entry — a CDN-only target returns few or none.

```bash
# Free tier (no key, 30 tokens/hr):
curl https://api.contrastcyber.com/v1/domain/wordpress.com/vulns

# Pro (500 tokens/hr):
curl https://api.contrastcyber.com/v1/domain/wordpress.com/vulns \
  -H "Authorization: Bearer $KEY"
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `technologies_scanned` | integer | Number of detected technologies |
| `total_cves` | integer | CVEs across all technologies |
| `vulnerabilities` | array | `[{technology, cve_count, cves[]}]` |
| `vulnerabilities[].cves[]` | array | `{cve_id, severity, cvss_v3, epss_score, in_kev}` |

#### Example response

```json
{
  "domain": "wordpress.com",
  "technologies_scanned": 3,
  "total_cves": 9,
  "vulnerabilities": [
    {
      "technology": "Nginx",
      "cve_count": 5,
      "cves": [
        {"cve_id": "CVE-2023-44487", "severity": "HIGH", "cvss_v3": 7.5, "epss_score": 0.9445, "in_kev": true},
        {"cve_id": "CVE-2025-23419", "severity": "MEDIUM", "cvss_v3": 4.3, "epss_score": 0.02857, "in_kev": false}
      ]
    },
    {
      "technology": "WordPress",
      "cve_count": 4,
      "cves": [
        {"cve_id": "CVE-2024-4439", "severity": "HIGH", "cvss_v3": 7.2, "epss_score": 0.90981, "in_kev": false}
      ]
    },
    {"technology": "Google Fonts", "cve_count": 0, "cves": []}
  ],
  "summary": "9 CVEs found across 2 of 3 technologies scanned"
}
```

---

### Bulk Domain Scan — `POST /v1/domains/bulk` &nbsp;`[cost: 1 per domain]`

Scans up to **50** domains in one request. All-or-nothing on budget: if the batch cost exceeds remaining quota, the whole request is rejected with `429` before any work runs.

```bash
# Free tier: omit the Authorization header (anonymous, 30 tokens/hr).
curl -X POST https://api.contrastcyber.com/v1/domains/bulk \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"domains":["contrastcyber.com","example.com"]}'
```

#### Request body

| Field | Type | Required | Description |
|---|---|---|---|
| `domains` | array of string | yes | Domains to scan (1–50) |

#### Response fields

| Field | Type | Description |
|---|---|---|
| `total` / `processed` / `successful` / `failed` | integer | Batch counters |
| `results` | array | Per-domain report (same shape as `GET /v1/domain/{domain}`) |

---

### Email Security Posture — `GET /v1/email/security-posture/{domain}`

Deep SPF + DKIM + DMARC audit with a 0–100 posture score and per-check findings (severity + fix hint). SPF mechanisms are parsed individually; DKIM probes a list of common selectors — a domain using a custom selector cannot be probed without the selector name, which yields `dkim_status: "unverifiable"` and lowers the grade.

```bash
curl https://api.contrastcyber.com/v1/email/security-posture/contrastcyber.com
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `spf` | object | `present`, `record`, `all_policy` (`strict`/`soft_fail`/…), `mechanisms[]` |
| `dmarc` | object | `present`, `record`, `policy`, `subdomain_policy`, `pct`, `rua_uris`, `ruf_uris`, `fo` |
| `dkim` | object | `status`, `verified_selectors`, `tested_selectors`, `findings[]` |
| `posture_score` | integer | 0–100 |
| `posture_grade` | string | A–F |
| `all_findings` | array | `[{check, status, severity, description, fix_hint}]` |
| `summary` | string | One-liner |

#### Example response

```json
{
  "domain": "contrastcyber.com",
  "spf": {"present": true, "record": "v=spf1 include:spf.infomaniak.ch -all", "all_policy": "strict"},
  "dmarc": {"present": true, "record": "v=DMARC1; p=reject; rua=mailto:…", "policy": "reject"},
  "dkim": {"status": "unverifiable", "verified_selectors": []},
  "posture_score": 65,
  "posture_grade": "C",
  "all_findings": [
    {"check": "SPF all policy", "status": "pass", "severity": "low", "description": "SPF uses '-all' - strict.", "fix_hint": ""},
    {"check": "DKIM", "status": "warn", "severity": "medium", "description": "DKIM not found under common selectors.", "fix_hint": "Publish a known selector or document it"}
  ],
  "summary": "contrastcyber.com - SPF strict - DMARC reject - DKIM unverifiable - Grade: C"
}
```

> `posture_grade: C` here reflects only that DKIM uses a custom selector our prober can't guess (SPF `-all` strict + DMARC `p=reject` are both strong). DKIM verification is a known limitation when the selector name is private.

---

### Email Verify — `GET /v1/email/verify/{email}`

Address-level validation: syntax + MX existence + disposable + role-address + free-provider. **No SMTP probe** is performed (no mailbox knock).

```bash
curl https://api.contrastcyber.com/v1/email/verify/test@gmail.com
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `email` / `domain` | string | Input + extracted domain |
| `syntax_valid` | boolean | RFC syntax check |
| `mx_records` | array | `[{priority, host}]` |
| `disposable` | boolean | Temporary-email provider |
| `role_address` | boolean | e.g. `info@`, `admin@` |
| `free_provider` | boolean | gmail / outlook / … |
| `summary` | string | One-liner |

#### Example response

```json
{
  "email": "test@gmail.com",
  "domain": "gmail.com",
  "syntax_valid": true,
  "mx_records": [
    {"priority": 5, "host": "gmail-smtp-in.l.google.com"},
    {"priority": 10, "host": "alt1.gmail-smtp-in.l.google.com"}
  ],
  "disposable": false,
  "role_address": false,
  "free_provider": true,
  "summary": "test@gmail.com — free provider"
}
```

---

### Mail Provider / MX — `GET /v1/email/mx/{domain}`

Detects the mail provider from MX records and grades the domain's email security (SPF + DMARC + DKIM).

```bash
curl https://api.contrastcyber.com/v1/email/mx/contrastcyber.com
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `mx_records` | array | `[{priority, host}]` |
| `mail_provider` | string | e.g. `Infomaniak`, `Microsoft 365`, `Google Workspace` |
| `email_security` | object | `spf`, `dmarc`, `dkim_selectors`, `dkim_status`, `grade`, `issues` |
| `summary` | string | One-liner |

#### Example response

```json
{
  "domain": "contrastcyber.com",
  "mx_records": [{"priority": 5, "host": "mta-gw.infomaniak.ch"}],
  "mail_provider": "Infomaniak",
  "email_security": {
    "spf": "v=spf1 include:spf.infomaniak.ch -all",
    "dmarc": "v=DMARC1; p=reject; rua=mailto:…",
    "dkim_selectors": [],
    "dkim_status": "unverifiable",
    "grade": "A",
    "issues": ["DKIM not found under common selectors — domains using custom DKIM selectors cannot be probed without prior knowledge of the selector name"]
  },
  "summary": "contrastcyber.com — uses Infomaniak — SPF+DMARC configured — Grade: A"
}
```

---

### Disposable Email Check — `GET /v1/email/disposable/{email}`

Checks the address domain against a disposable/temporary-provider blocklist (and an MX-based heuristic).

```bash
curl https://api.contrastcyber.com/v1/email/disposable/foo@mailinator.com
```

#### Example response

```json
{
  "email": "foo@mailinator.com",
  "domain": "mailinator.com",
  "disposable": true,
  "provider": "Mailinator",
  "mx_disposable": false,
  "risk_level": "high",
  "mx_records": [
    {"priority": 1, "host": "mail.mailinator.com"},
    {"priority": 1, "host": "mail2.mailinator.com"}
  ],
  "summary": "foo@mailinator.com — disposable (Mailinator), risk: high"
}
```

---

### robots.txt — `GET /v1/robots/{domain}`

Parses `robots.txt` per RFC 9309: sitemaps, per-user-agent allow/disallow rules, crawl-delay.

```bash
curl https://api.contrastcyber.com/v1/robots/contrastcyber.com
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `fetched_url` | string | robots.txt URL |
| `status_code` | integer | HTTP status |
| `sitemaps` | array | Declared sitemap URLs |
| `user_agents` | object | UA → `{allow[], disallow[]}` |
| `summary` | string | One-liner |

#### Example response

```json
{
  "domain": "contrastcyber.com",
  "fetched_url": "https://contrastcyber.com/robots.txt",
  "status_code": 200,
  "sitemaps": ["https://contrastcyber.com/sitemap.xml"],
  "user_agents": {
    "*": {"allow": [], "disallow": []},
    "GPTBot": {"allow": [], "disallow": []},
    "ClaudeBot": {"allow": [], "disallow": []},
    "PerplexityBot": {"allow": [], "disallow": []}
  }
}
```

> `contrastcyber.com` declares explicit per-UA rules for AI crawlers (`GPTBot`, `ClaudeBot`, `anthropic-ai`, `PerplexityBot`, `Google-Extended`, `CCBot`, `Applebot-Extended`, `OAI-SearchBot`).

---

### Redirect Chain — `GET /v1/redirect/{url:path}`

Walks an HTTP redirect chain hop-by-hop (max 10 hops, SSRF-guarded at every hop). Multi-hop chains are a phishing signature.

```bash
curl https://api.contrastcyber.com/v1/redirect/http://contrastcyber.com
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `start_url` / `final_url` | string | First + landing URL |
| `hops` | array | `[{url, status_code, location, latency_ms}]` |
| `hop_count` | integer | Number of hops |
| `final_status` | integer | Final HTTP status |
| `loop_detected` / `truncated` | boolean | Loop guard / hop-cap hit |
| `summary` | string | One-liner |

#### Example response

```json
{
  "start_url": "http://contrastcyber.com",
  "final_url": "https://contrastcyber.com/",
  "hops": [
    {"url": "http://contrastcyber.com", "status_code": 301, "location": "https://contrastcyber.com/", "latency_ms": 62},
    {"url": "https://contrastcyber.com/", "status_code": 200, "latency_ms": 118}
  ],
  "hop_count": 2,
  "final_status": 200,
  "loop_detected": false,
  "truncated": false,
  "summary": "2-hop chain — final 200 at https://contrastcyber.com/"
}
```

---

### Brand Assets — `GET /v1/brand/{domain}` &nbsp;`[cost: 1]`

Extracts brand assets from the homepage: favicon, `og:image`, `og:site_name`, theme-color. Target-derived strings carry the `_untrusted` suffix — do not execute or shell-out. `cache_respected=false` flags a `no-store`/`private` target.

```bash
# Free tier (no key, 30 tokens/hr):
curl https://api.contrastcyber.com/v1/brand/contrastcyber.com

# Pro (500 tokens/hr):
curl https://api.contrastcyber.com/v1/brand/contrastcyber.com \
  -H "Authorization: Bearer $KEY"
```

#### Example response

```json
{
  "domain": "contrastcyber.com",
  "fetched_url": "https://contrastcyber.com/",
  "status_code": 200,
  "favicon_url_untrusted": "https://contrastcyber.com/static/favicon.svg",
  "og_image_url_untrusted": "https://contrastcyber.com/static/og-image.png?v=2",
  "theme_color": "#09090b",
  "site_name_untrusted": "ContrastScan",
  "cache_respected": true,
  "summary": "contrastcyber.com — site:ContrastScan, favicon, og:image"
}
```

---

### SEO Audit — `GET /v1/seo/{domain}` &nbsp;`[cost: 1]`

10-rule composite SEO score (0–100) + `missing_signals`. Inspects title, meta description, heading structure, image alt coverage, link counts, OG tags, JSON-LD.

```bash
# Free tier (no key, 30 tokens/hr):
curl https://api.contrastcyber.com/v1/seo/contrastcyber.com

# Pro (500 tokens/hr):
curl https://api.contrastcyber.com/v1/seo/contrastcyber.com \
  -H "Authorization: Bearer $KEY"
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `title_untrusted` / `meta_description_untrusted` | string | Page title + meta description |
| `canonical_url` | string | Canonical link |
| `h1_untrusted` / `h1_count` / `h2_count` / `h3_count` | array / int | Heading structure |
| `images_total` / `images_missing_alt` | integer | Image accessibility |
| `internal_link_count` / `external_link_count` | integer | Link profile |
| `og_tags` | object | Open Graph tags |
| `json_ld_present` | boolean | Structured-data presence |
| `score` | integer | 0–100 composite |
| `missing_signals` | array | Failed rules |

#### Example response

```json
{
  "domain": "contrastcyber.com",
  "fetched_url": "https://contrastcyber.com/",
  "status_code": 200,
  "title_untrusted": "ContrastScan — Free Security Scanner",
  "meta_description_untrusted": "Check your website's security in 3 seconds. Get a single A-F grade covering 11 security checks…",
  "canonical_url": "https://contrastcyber.com",
  "h1_count": 1,
  "og_tags": {"og:title": "ContrastScan — Free Security Scanner", "og:site_name": "ContrastScan", "og:type": "website"},
  "json_ld_present": true,
  "score": 90,
  "missing_signals": ["meta_description_length_off"]
}
```

---

### GEO Audit — `GET /v1/geo/{domain}` &nbsp;`[cost: 1]`

Deterministic GEO / AI-visibility readiness score (0–100) + `missing_signals` — answers "can AI assistants (ChatGPT, Claude, Perplexity, Google AI) discover, crawl, and recommend this site?" using structural signals ONLY. **No LLM is queried.** 7 weighted rules: llms.txt present (15), AI-crawler robots.txt access (25), schema.org @type coverage (20), server-side rendering vs client-only SPA (15), OG/canonical/sitemap discovery signals (10), semantic headings (10), competitor-comparison content (5). Same ethical floor as `seo_audit` — robots.txt honoured (Disallow `/` → 403, no fetch).

```bash
# Free tier (no key, 30 tokens/hr):
curl https://api.contrastcyber.com/v1/geo/contrastcyber.com

# Pro (500 tokens/hr):
curl https://api.contrastcyber.com/v1/geo/contrastcyber.com \
  -H "Authorization: Bearer $KEY"
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `llms_txt_present` | boolean | `/llms.txt` served with a non-empty body |
| `ai_crawlers_total` / `ai_crawlers_allowed` | integer | AI crawlers checked vs. permitted at path `/` |
| `ai_crawlers_blocked` | array | AI crawler tokens disallowed by robots.txt (e.g. `GPTBot`) |
| `schema_types` | array | schema.org @types found in JSON-LD (Organization, Product, FAQPage…) |
| `client_side_rendered` | boolean | Homepage is a client-only SPA (AI crawlers may see empty content) |
| `render_framework` | string | SPA framework marker detected, if any (informational) |
| `has_canonical` / `og_tag_count` / `sitemap_count` | boolean / int | Discovery signals |
| `h1_count` / `h2_count` | integer | Semantic heading structure |
| `comparison_content` | boolean | Competitor-comparison signals ("vs", "alternative") present |
| `score` | integer | 0–100 composite |
| `missing_signals` | array | Failed rules (concrete fix list) |

#### Example response

```json
{
  "domain": "api.contrastcyber.com",
  "fetched_url": "https://api.contrastcyber.com/",
  "status_code": 200,
  "llms_txt_present": true,
  "ai_crawlers_total": 9,
  "ai_crawlers_allowed": 9,
  "ai_crawlers_blocked": [],
  "schema_types": ["WebSite", "Organization"],
  "client_side_rendered": false,
  "has_canonical": true,
  "og_tag_count": 6,
  "sitemap_count": 1,
  "h1_count": 1,
  "h2_count": 13,
  "comparison_content": true,
  "score": 100,
  "missing_signals": []
}
```

---

## IP & Network Intelligence

**Schema notes:**
- `vulns` shape: `[{cve_id, severity, cvss_v3}]` — `severity='UNKNOWN'` means the CVE is not in the local DB; do **not** infer "benign".
- `cloud_provider`: published CIDRs first, then ASN→provider fallback (e.g. `8.8.8.8 → AS15169 → 'Google'`).
- `tor_exit=false` is null-explicit — check `verdict.sources_unavailable` for `'tor'` to distinguish "not listed" from "fetch failed".
- Pro-tier reputation (`abuseipdb`, `shodan`) returns real data on Pro; on Free they emit `{status:'pro_only', reason, upgrade_url}` stubs (not errors). `shodan.status='restricted'` means the IP isn't in the public Shodan index.

---

### IP Intelligence — `GET /v1/ip/{ip}`

Comprehensive IP profile: reverse DNS, ASN + holder, country, open ports, hostnames, known vulns (Shodan InternetDB enriched with local CVE severity), cloud provider, Tor-exit status, reputation (FireHOL on Free; +AbuseIPDB + Shodan on Pro), and a composite `risk_score` (0–100).

```bash
# Free tier (no key, 30 tokens/hr):
curl https://api.contrastcyber.com/v1/ip/8.8.8.8

# Pro (500 tokens/hr):
curl https://api.contrastcyber.com/v1/ip/8.8.8.8 \
  -H "Authorization: Bearer $KEY"
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `ip` / `ptr` | string | IP + reverse DNS |
| `asn` / `asn_name` | int / string | Autonomous System + holder |
| `country` | string | ISO country |
| `ports` | array | Open ports (Shodan InternetDB) |
| `hostnames` | array | Associated hostnames |
| `vulns` | array | `[{cve_id, severity, cvss_v3}]` |
| `cloud_provider` | string\|null | Cloud/anycast provider (null if neither tier matches) |
| `is_datacenter` | boolean | Datacenter/hosting IP |
| `tor_exit` | boolean | Tor exit node |
| `reputation.firehol` | object | `listed`, `lists_matched` (Free) |
| `reputation.abuseipdb` | object | `abuse_score`, `total_reports`, `isp`, `usage_type` (Pro) |
| `reputation.shodan` | object | `org`, `city`, `ports`, `vulns`, `last_update` (Pro) |
| `risk_score` / `severity_label` | int / string | 0–100 + label |
| `verdict` / `summary` | object / string | Falsifiability metadata + one-liner |

#### Example response

```json
{
  "verdict": {
    "deterministic": true,
    "sources_queried": ["internetdb", "ripe_stat", "tor", "reputation"],
    "sources_unavailable": [],
    "completeness": "complete",
    "data_age_seconds": 544
  },
  "ip": "8.8.8.8",
  "ptr": "dns.google",
  "asn": 15169,
  "asn_name": "GOOGLE - Google LLC",
  "country": "US",
  "ports": [53, 443],
  "hostnames": ["dns.google"],
  "vulns": [],
  "reputation": {
    "firehol": {"status": "ok", "listed": false, "lists_matched": []},
    "abuseipdb": {"status": "ok", "abuse_score": 0, "total_reports": 105, "country": "US", "isp": "Google LLC", "usage_type": "Content Delivery Network", "is_tor": false},
    "shodan": {"status": "ok", "org": "Google LLC", "asn": "AS15169", "ports": [443, 53], "vulns": [], "city": "Mountain View", "country_name": "United States", "last_update": "2026-05-26T15:35:49.747240"}
  },
  "cloud_provider": "Google",
  "is_datacenter": true,
  "tor_exit": false,
  "risk_score": 30,
  "severity_label": "medium",
  "summary": "8.8.8.8 → dns.google. AS15169 (GOOGLE - Google LLC). US. 2 open ports. 1 hostnames. hosted on Google"
}
```

---

### IP Threat Report — `GET /v1/threat-report/{ip}` &nbsp;`[cost: 6]`

Orchestrated IP profile in one call: InternetDB enrichment + AbuseIPDB + Shodan + ASN (full prefix list) + Tor + cloud + FireHOL. Full parity with `GET /v1/ip` plus the announced-prefix ASN block.

```bash
# Free tier (no key, 30 tokens/hr):
curl https://api.contrastcyber.com/v1/threat-report/8.8.8.8

# Pro (500 tokens/hr):
curl https://api.contrastcyber.com/v1/threat-report/8.8.8.8 \
  -H "Authorization: Bearer $KEY"
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `enrichment` | object | `ports`, `hostnames`, `vulns`, `cpes`, `tags`, `internetdb_status` |
| `abuseipdb` | object | `abuse_score`, `total_reports`, `isp`, `usage_type` |
| `shodan` | object | `org`, `asn`, `ports`, `vulns`, `city`, `last_update` |
| `asn` | object | `asn`, `asn_name`, `ipv4_prefixes`/`ipv6_prefixes` (capped 50), `ipv4_count`, `ipv6_count` |
| `cloud_provider` / `is_datacenter` / `tor_exit` / `firehol` | mixed | Same semantics as `/v1/ip` |
| `risk_score` / `severity_label` / `summary` | mixed | Composite + one-liner |

#### Example response

```json
{
  "verdict": {"deterministic": true, "sources_queried": ["ripe_stat", "internetdb", "tor", "firehol", "abuseipdb", "shodan"], "completeness": "complete"},
  "ip": "8.8.8.8",
  "enrichment": {"ports": [53, 443], "hostnames": ["dns.google"], "vulns": [], "cpes": [], "tags": [], "internetdb_status": "ok"},
  "abuseipdb": {"status": "ok", "abuse_score": 0, "total_reports": 105, "country": "US", "isp": "Google LLC", "usage_type": "Content Delivery Network", "is_tor": false},
  "shodan": {"status": "ok", "org": "Google LLC", "asn": "AS15169", "ports": [443, 53], "vulns": [], "city": "Mountain View", "last_update": "2026-05-26T15:35:49.747240"},
  "asn": {
    "target": "8.8.8.8",
    "asn": 15169,
    "asn_name": "GOOGLE - Google LLC",
    "ipv4_prefixes": ["34.0.128.0/19", "74.125.141.0/24", "… (capped at 50)"],
    "ipv6_prefixes": ["2001:4860:482d::/48", "… (capped at 50)"],
    "ipv4_count": 1215,
    "ipv6_count": 175,
    "country": "US"
  },
  "cloud_provider": "Google",
  "is_datacenter": true,
  "tor_exit": false,
  "firehol": {"status": "ok", "listed": false, "lists_matched": []},
  "risk_score": 30,
  "severity_label": "medium",
  "summary": "IP 8.8.8.8 · AS15169 · 2 open ports · threat level: low"
}
```

---

### ASN Lookup — `GET /v1/asn/{target}`

Resolves a target to its Autonomous System and returns announced IPv4/IPv6 prefixes (each list **capped at 50**; `ipv4_count`/`ipv6_count` report the honest totals) + holder name.

> **`target` must be an IP address or domain** — it is resolved to the owning ASN. A bare AS-number string (`AS15169` / `15169`) is **not** accepted and returns `422 invalid_argument`.

```bash
curl https://api.contrastcyber.com/v1/asn/8.8.8.8
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `target` | string | Input IP/domain |
| `asn` / `asn_name` | int / string | AS number + holder |
| `ipv4_prefixes` / `ipv6_prefixes` | array | Announced prefixes (capped at 50) |
| `ipv4_count` / `ipv6_count` | integer | Honest prefix totals |
| `country` | string | Holder country |
| `summary` | string | One-liner |

#### Example response

```json
{
  "verdict": {"deterministic": true, "sources_queried": ["ripe_stat:network-info", "ripe_stat:as-overview", "ripe_stat:announced-prefixes"], "completeness": "complete"},
  "target": "8.8.8.8",
  "asn": 15169,
  "asn_name": "GOOGLE - Google LLC",
  "ipv4_prefixes": ["34.0.128.0/19", "74.125.141.0/24", "192.178.225.0/24", "… (capped at 50)"],
  "ipv6_prefixes": ["2001:4860:482d::/48", "2404:6800:480e::/48", "… (capped at 50)"],
  "ipv4_count": 1215,
  "ipv6_count": 175,
  "summary": "AS15169 (GOOGLE - Google LLC). 1215 IPv4 and 175 IPv6 prefixes"
}
```

---

## CVE Intelligence

**Notes:**
- `total_products` / `total_references` always report the honest count, independent of truncation. `affected_products` is truncated to 20 and `references` to 10 by default — pass `include_affected_products=true` / `include_full_references=true` for the full lists (a CVE spanning a large product line can carry 350+ products → ~25 KB).
- `severity='UNKNOWN'` (in tech/IP vuln lists) means the CVE is not in the local DB — never infer "benign".
- Examples below feature **CVE-2026-20182** (Cisco Catalyst SD-WAN authentication bypass, CVSS 10.0, CISA KEV, EPSS 77%, CISA Emergency Directive 26-03) — a current, actively-exploited flagship CVE.

---

### CVE Details — `GET /v1/cve/{cve_id}`

Full CVE record: description, CVSS v3.1 (+ breakdown) and v2, EPSS, CISA KEV block, NVD status, CWEs, affected products (CPE), references, patch availability, related CVEs. `404` if the ID is unknown.

| Query param | Default | Description |
|---|---|---|
| `include_affected_products` | `false` | Return full `affected_products` (else first 20) |
| `include_full_references` | `true` | Return full `references` |

```bash
curl https://api.contrastcyber.com/v1/cve/CVE-2026-20182
```

#### Response fields (selected)

| Field | Type | Description |
|---|---|---|
| `cve_id` / `severity` | string | Identifier + CRITICAL…NONE |
| `cvss_v3` / `cvss_breakdown` / `cvss_v2` / `cvss_v2_vector` | mixed | Scores + per-metric breakdown (`cvss_v2` may be `null` for newer CVEs) |
| `cwe_id` / `cwes` | string / array | Primary + all CWEs |
| `epss` | object | `score`, `percentile` |
| `kev` | object | Full KEV block (see KEV Detail) |
| `vulnerability_status` | string | NVD status (`Analyzed`, `Modified`, …) |
| `affected_products` / `total_products` | array / int | CPE list (truncated 20) + honest count |
| `references` / `total_references` / `total_references_unique` | array / int | Refs (truncated 10) + counts |
| `patch_available` / `patch_url` | bool / string | Patch detection |
| `related_cves` | array | `[{cve_id, severity, cvss_v3}]` |
| `published` / `modified` | string | NVD timestamps |
| `sources` / `first_seen_source` / `first_seen_at` | mixed | Provenance |

#### Example response

```json
{
  "verdict": {"deterministic": true, "sources_queried": [], "completeness": "complete"},
  "cve_id": "CVE-2026-20182",
  "summary": "CRITICAL (CWE-287) — Cisco Catalyst SD-WAN Controller & Manager authentication bypass. CVSS 10.0. Actively exploited (CISA KEV).",
  "description": "Cisco Catalyst SD-WAN Controller & Manager contain an authentication bypass vulnerability that allows an unauthenticated, remote attacker to bypass authentication and obtain administrative privileges on an affected system.",
  "severity": "CRITICAL",
  "cvss_v3": 10.0,
  "cvss_breakdown": {"attack_vector": "Network", "attack_complexity": "Low", "privileges_required": "None", "user_interaction": "None", "scope": "Changed", "confidentiality": "High", "integrity": "High", "availability": "High"},
  "cvss_v2": null,
  "cwe_id": "CWE-287",
  "cwes": ["CWE-287"],
  "vulnerability_status": "Analyzed",
  "epss": {"score": 0.77324, "percentile": 0.99},
  "kev": {"in_kev": true, "date_added": "2026-05-14", "due_date": "2026-05-17", "known_ransomware_use": false, "vendor_project": "Cisco", "product": "Catalyst SD-WAN"},
  "affected_products": [{"vendor": "cisco", "product": "catalyst_sd-wan_manager", "version_end": "20.9.9.1", "cpe_part": "a", "vulnerable": true}, "… (16 total)"],
  "total_products": 16,
  "references": ["https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa2-v69WY2SW", "… (3 total)"],
  "total_references": 3,
  "patch_available": true,
  "patch_url": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa2-v69WY2SW",
  "published": "2026-05-14T17:16:19.387",
  "sources": ["nvd"]
}
```

---

### CVE Risk Score — `GET /v1/cve/{cve_id}/risk_score`

Composite 0–100 score fusing CVSS + EPSS + KEV + public-PoC, with a weighted breakdown, applied "boosters", an urgency line, and a remediation recommendation.

```bash
curl https://api.contrastcyber.com/v1/cve/CVE-2026-20182/risk_score
```

#### Example response

```json
{
  "cve_id": "CVE-2026-20182",
  "score": 84.8,
  "label": "HIGH",
  "urgency": "Patch immediately — actively exploited (CISA KEV).",
  "has_public_poc": false,
  "components": {
    "cvss_v3": 10.0,
    "epss_score": 0.7732,
    "in_kev": true,
    "has_public_poc": false,
    "weighted_breakdown": {"cvss": 20.0, "epss": 27.06, "kev": 30.0, "poc": 0.0}
  },
  "boosters_applied": ["critical_severity_high_epss"],
  "recommendation": "Active exploitation confirmed by CISA — apply the vendor patch now and review intrusion telemetry for the affected service.",
  "summary": "CVE-2026-20182 - risk_score=84.8 (HIGH). CVSS=10.0, EPSS=0.77324, KEV=True, PoC=False."
}
```

> Note the score is 84.8 (not 100) despite CVSS 10.0 + KEV: the `poc` component contributes `0.0` because no public PoC was found (`has_public_poc: false`). The weighted model rewards confirmed exploitability separately from severity.

---

### CVSS Vector Parser — `GET /v1/cvss/details?vector=`

Parses a CVSS v3.x vector string into a per-metric breakdown and recomputes the base score. Pure computation — no DB lookup.

```bash
curl "https://api.contrastcyber.com/v1/cvss/details?vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
```

#### Example response

```json
{
  "version": "3.1",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "base_score": 10.0,
  "base_severity": "CRITICAL",
  "metrics": {"attack_vector": "NETWORK", "attack_complexity": "LOW", "privileges_required": "NONE", "user_interaction": "NONE", "scope": "CHANGED", "confidentiality_impact": "HIGH", "integrity_impact": "HIGH", "availability_impact": "HIGH"},
  "temporal_score": 10.0,
  "environmental_score": 10.0,
  "summary": "CVSS v3.1 CRITICAL (10.0). AV=NETWORK, AC=LOW, PR=NONE, UI=NONE, Scope=CHANGED."
}
```

---

### CVE Search — `GET /v1/cves`

Filtered, paginated CVE search.

| Query param | Description |
|---|---|
| `vendor` / `product` | Case-insensitive partial match |
| `severity` | CRITICAL / HIGH / MEDIUM / LOW / NONE |
| `min_cvss` / `min_epss` | Numeric thresholds |
| `kev` | `true` → CISA KEV only |
| `cwe_id` | Filter by weakness class |
| `published_after` / `published_before` | `YYYY-MM-DD` |
| `sort` | `epss_desc` / `cvss_desc` / `published_desc` (default); an invalid value returns `400` |
| `limit` / `offset` | Page size (1–100, default 20) + paging |

```bash
# Actively-exploited critical CVEs — the SOC morning-brief query
curl "https://api.contrastcyber.com/v1/cves?severity=CRITICAL&kev=true&limit=2"
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `count` / `total` | integer | Returned this page / total matches |
| `truncated` / `offset` / `next_offset` | mixed | Paging state |
| `results` | array | CVE summary records |
| `query_echo` | object | Echoed filters |

#### Example response

```json
{
  "count": 2,
  "total": 546,
  "truncated": true,
  "offset": 0,
  "next_offset": 2,
  "results": [
    {
      "cve_id": "CVE-2026-48172",
      "summary": "CRITICAL (CWE-266) — LiteSpeed User-End cPanel Plugin privilege escalation. CVSS 9.8. Actively exploited (CISA KEV).",
      "severity": "CRITICAL",
      "cvss_v3": 9.8,
      "cwe_id": "CWE-266",
      "epss": {"score": 0.00014, "percentile": 0.02696},
      "kev": {"in_kev": true, "vendor_project": "LiteSpeed", "product": "cPanel Plugin"},
      "total_products": 2,
      "published": "2026-05-21T02:16:33.760"
    },
    {
      "cve_id": "CVE-2026-20182",
      "summary": "CRITICAL (CWE-287) — Cisco Catalyst SD-WAN Controller authentication bypass. CVSS 10.0. Actively exploited (CISA KEV).",
      "severity": "CRITICAL",
      "cvss_v3": 10.0,
      "cwe_id": "CWE-287",
      "epss": {"score": 0.77324, "percentile": 0.99},
      "kev": {"in_kev": true, "vendor_project": "Cisco", "product": "Catalyst SD-WAN"},
      "total_products": 16,
      "published": "2026-05-14T17:16:19.387"
    }
  ],
  "summary": "2 CVEs returned, 546 total (CRITICAL, KEV)"
}
```

---

### Leading CVEs — `GET /v1/cve/leading`

CVEs indexed by MITRE/GHSA **ahead of NVD** (ordered by first-seen). Surfaces fresh disclosures before they graduate into NVD — so `cvss_v3`/`epss` are frequently `null` (NVD has not scored them yet). Same paging shape as `/v1/cves`.

```bash
curl "https://api.contrastcyber.com/v1/cve/leading?limit=2"
```

#### Example response

```json
{
  "count": 2,
  "total": 435,
  "results": [
    {
      "cve_id": "CVE-2026-41207",
      "summary": "— netty-incubator-codec-ohttp's HPKEContext operations are vulnerable to timing side-channels",
      "cvss_v3": null,
      "epss": {},
      "kev": {"in_kev": false},
      "total_products": 0,
      "published": "2026-05-26T…",
      "sources": ["ghsa"]
    },
    {
      "cve_id": "CVE-2026-48048",
      "summary": "— XWiki Platform's Livetable results still allow reconstructing password hashes using 768 requests",
      "cvss_v3": null,
      "epss": {},
      "kev": {"in_kev": false},
      "total_products": 0,
      "published": "2026-05-26T…",
      "sources": ["ghsa"]
    }
  ]
}
```

---

### Exploit Lookup — `GET /v1/exploit/{cve_id}`

Public exploit / PoC search across ExploitDB + GitHub Security Advisory + Shodan references.

```bash
curl https://api.contrastcyber.com/v1/exploit/CVE-2026-20182
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `exploits_found` | integer | Total PoC/exploit/advisory references |
| `has_public_exploit` | boolean | Any public reference exists |
| `sources.github` | object | `{found, count, advisories:[{ghsa_id, summary, severity, published_at, references}]}` |
| `sources.shodan_refs` | object | `{found, count, results}` |
| `exploits` | array | ExploitDB entries `[{edb_id, date_published, author, type, platform, url}]` (empty when none) |
| `summary` | string | One-liner |

#### Example response

```json
{
  "cve_id": "CVE-2026-20182",
  "exploits_found": 1,
  "has_public_exploit": true,
  "sources": {
    "github": {
      "found": true,
      "count": 1,
      "advisories": [
        {"ghsa_id": "GHSA-p83j-mxpw-gqpj", "severity": "critical", "published_at": "2026-05-14T18:32:56Z", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-20182", "https://github.com/advisories/GHSA-p83j-mxpw-gqpj"]}
      ]
    },
    "shodan_refs": {"found": false, "count": 0, "results": []}
  },
  "exploits": [],
  "summary": "CVE-2026-20182 — 1 public exploit(s) found: 1 GitHub advisory(ies)"
}
```

> For a CVE with public ExploitDB entries, `exploits[]` is populated with `{edb_id, author, type, platform, url}` objects; here only a GitHub Security Advisory exists, so `exploits[]` is empty while `sources.github.advisories` carries the reference.

---

### KEV Detail — `GET /v1/kev/{cve_id}`

CISA Known Exploited Vulnerabilities record: date added, federal due date, required action, ransomware association, vendor/product, and CWE list.

```bash
curl https://api.contrastcyber.com/v1/kev/CVE-2026-20182
```

#### Example response

```json
{
  "verdict": {"deterministic": true, "sources_queried": ["cisa_kev_cache"], "completeness": "complete"},
  "cve_id": "CVE-2026-20182",
  "in_kev": true,
  "date_added": "2026-05-14",
  "due_date": "2026-05-17",
  "required_action": "Please adhere to CISA's guidelines to assess exposure and mitigate risks associated with Cisco SD-WAN devices as outlined in CISA's Emergency Directive 26-03 … or discontinue use of the product if mitigations are not available.",
  "known_ransomware_use": false,
  "vendor_project": "Cisco",
  "product": "Catalyst SD-WAN",
  "vulnerability_name": "Cisco Catalyst SD-WAN Controller Authentication Bypass Vulnerability",
  "short_description": "Cisco Catalyst SD-WAN Controller & Manager contain an authentication bypass vulnerability that allows an unauthenticated, remote attacker to bypass authentication and obtain administrative privileges on an affected system.",
  "cwes": ["CWE-287"]
}
```

*(When `in_kev=false`, the record collapses to `{cve_id, in_kev: false}`.)*

---

### CWE Lookup — `GET /v1/cwe/{cwe_id}`

MITRE CWE weakness: description, mitigations, real-CVE examples, parent/child chain, and aggregate CVE statistics.

```bash
curl https://api.contrastcyber.com/v1/cwe/CWE-79
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `cwe_id` / `name` / `description` | string | Identifier + title + text |
| `abstract_type` / `status` | string | e.g. `Base` / `Stable` |
| `mitigations` / `total_mitigations` | array / int | Mitigation strategies (truncated) |
| `examples` / `total_examples` | array / int | Real CVE examples |
| `parent_cwe` / `child_cwes` | mixed | Hierarchy |
| `cve_count` | integer | CVEs mapped to this weakness |

#### Example response

```json
{
  "cwe_id": "CWE-79",
  "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
  "description": "The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output …",
  "abstract_type": "Base",
  "status": "Stable",
  "mitigations": ["Architecture and Design — Use a vetted library or framework that does not allow this weakness to occur …"],
  "total_mitigations": 12,
  "examples": ["CVE-2024-49038: XSS in AI assistant", "CVE-2024-54142: Plugin … leading to XSS"],
  "total_examples": 20,
  "parent_cwe": "CWE-74",
  "child_cwes": [],
  "cve_count": 44039
}
```

---

### Bulk CVE Lookup — `POST /v1/cves/bulk` &nbsp;`[cost: 1 per ID]`

Looks up up to **50** CVE IDs in one request (flat cap, all tiers). Invalid-format IDs are skipped without a DB query. Always returns `200`; use the counters to interpret. All-or-nothing on budget.

> **Body field is `cve_ids`** (not `ids`).

```bash
# Free tier: omit the Authorization header (anonymous, 30 tokens/hr).
curl -X POST https://api.contrastcyber.com/v1/cves/bulk \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"cve_ids":["CVE-2026-20182","CVE-2026-42208","CVE-2099-99999"]}'
```

#### Request body

| Field | Type | Required | Description |
|---|---|---|---|
| `cve_ids` | array of string | yes | CVE IDs (1–50) |
| `include_affected_products` | boolean | no | Full product lists per item (default false) |

#### Response fields

| Field | Type | Description |
|---|---|---|
| `total` / `processed` / `successful` / `failed` | integer | Batch counters |
| `partial` | boolean | Some IDs not found |
| `results` | array | Full CVE records (same shape as `GET /v1/cve/{cve_id}`) |

#### Example response

```json
{
  "total": 3,
  "processed": 3,
  "successful": 2,
  "failed": 1,
  "partial": true,
  "results": [
    {"cve_id": "CVE-2026-20182", "severity": "CRITICAL", "cvss_v3": 10.0, "…": "full record"}
  ],
  "summary": "2/3 CVEs found"
}
```

---

## Threat Intelligence / IOC

`sources` keys (`threatfox`, `feodo`, `urlhaus`, `tor`) vary by indicator type — `tor` only appears for IPs, `urlhaus` for URLs/domains/IPs.

---

### IOC Lookup — `GET /v1/ioc/{indicator}`

Unified indicator enrichment with auto-detection of IP / domain / URL / hash. Correlates ThreatFox + Feodo Tracker + URLhaus + Tor.

```bash
curl https://api.contrastcyber.com/v1/ioc/8.8.8.8
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `indicator` / `type` | string | Input + detected type (`ip`/`domain`/`url`/`hash`) |
| `threat_level` | string | `none` / `low` / `medium` / `high` |
| `sources` | object | Per-source match (`threatfox`, `feodo`, `urlhaus`, `tor`) |
| `summary` | string | One-liner |

#### Example response

```json
{
  "verdict": {"deterministic": true, "sources_queried": ["threatfox", "feodo", "urlhaus", "tor"], "completeness": "complete"},
  "indicator": "8.8.8.8",
  "type": "ip",
  "threat_level": "none",
  "sources": {
    "threatfox": {"found": false, "tags": []},
    "feodo": {"found": false},
    "urlhaus": {"found": false, "urls_online": 0},
    "tor": {"listed": false, "fetch_status": "ok"}
  },
  "summary": "8.8.8.8 — no threats found across 4 sources"
}
```

---

### Hash Reputation — `GET /v1/hash/{hash}`

Malware hash lookup (MalwareBazaar). Accepts MD5/SHA1/SHA256 (auto-detected via `hash_type`). `found: false` for clean/unknown hashes.

```bash
curl https://api.contrastcyber.com/v1/hash/44d88612fea8a8f36de82e1278abb02f
```

#### Example response

```json
{
  "hash": "44d88612fea8a8f36de82e1278abb02f",
  "hash_type": "md5",
  "found": false,
  "tags": [],
  "summary": "No malware data found for this hash"
}
```

*(When found, adds `file_name`, `file_type`, `signature`, `first_seen`, malware-family `tags`.)*

---

### Password Breach — `GET /v1/password/{sha1}`

HIBP Pwned Passwords check via **k-anonymity** — only the first 5 chars of the SHA-1 are sent upstream; the full hash and plaintext never leave the client. Returns presence + breach count only.

```bash
# SHA1 of the candidate password (here: "password")
curl https://api.contrastcyber.com/v1/password/5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
```

#### Example response

```json
{
  "hash_prefix": "5BAA6",
  "found": true,
  "breach_count": 52256179,
  "summary": "This password appeared in 52,256,179 data breaches."
}
```

---

### Phishing Check — `GET /v1/phishing/{url}`

Phishing / malware-URL check against URLhaus (host + exact-URL). `is_stale` flags an aged entry.

```bash
curl https://api.contrastcyber.com/v1/phishing/http://example.com
```

#### Example response

```json
{
  "url": "http://example.com",
  "host": "example.com",
  "is_malicious": false,
  "is_stale": false,
  "urlhaus_host": {"found": false, "urls_online": 0, "url_count": 0},
  "urlhaus_url": {"found": false, "tags": []},
  "threat_level": "none",
  "summary": "http://example.com — not found in threat databases"
}
```

---

### Bulk IOC — `POST /v1/iocs/bulk` &nbsp;`[cost: 1 per indicator]`

Enriches up to **50** indicators in one request (mixed types allowed). All-or-nothing on budget.

```bash
# Free tier: omit the Authorization header (anonymous, 30 tokens/hr).
curl -X POST https://api.contrastcyber.com/v1/iocs/bulk \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"indicators":["8.8.8.8","example.com"]}'
```

#### Request body

| Field | Type | Required | Description |
|---|---|---|---|
| `indicators` | array of string | yes | IOCs to enrich (1–50, mixed types) |

#### Response fields

| Field | Type | Description |
|---|---|---|
| `total` / `processed` / `successful` / `failed` / `invalid` | integer | Batch counters |
| `results` | array | `[{indicator, status, ioc{...}}]` (per-indicator enrichment) |

#### Example response

```json
{
  "total": 2,
  "processed": 2,
  "successful": 2,
  "failed": 0,
  "invalid": 0,
  "partial": false,
  "results": [
    {"indicator": "8.8.8.8", "status": "ok", "ioc": {"type": "ip", "threat_level": "none", "sources": {"threatfox": {"found": false}, "urlhaus": {"urlhaus_status": "clean"}}}}
  ],
  "summary": "All 2 indicators processed"
}
```

---

## OSINT

---

### Phone Lookup — `GET /v1/phone/{number}`

Phone-number OSINT: validity, E.164/international/national formatting, country, line type, timezone, carrier (where supported).

```bash
curl https://api.contrastcyber.com/v1/phone/+14155552671
```

#### Example response

```json
{
  "valid": true,
  "number": "+14155552671",
  "format": {"e164": "+14155552671", "international": "+1 415-555-2671", "national": "(415) 555-2671"},
  "country_code": "US",
  "country_name": "United States",
  "type": "fixed_line_or_mobile",
  "carrier_status": "unsupported_region",
  "timezone": ["America/Los_Angeles"],
  "summary": "+14155552671 — United States — fixed_line_or_mobile"
}
```

---

### Username Lookup — `GET /v1/username/{username}`

Account-discovery across 16+ platforms (GitHub, Bitbucket, Reddit, Steam, npm, Keybase, …). `verdict.sources_unavailable` lists platforms that could not be checked this run (`completeness: partial`).

```bash
curl https://api.contrastcyber.com/v1/username/torvalds
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `username` | string | Queried handle |
| `found_count` / `checked_count` | integer | Hits / platforms probed |
| `results` | array | `[{platform, url, status}]` (`found` / `not_found`) |
| `verdict.sources_unavailable` | array | Platforms skipped this run |

#### Example response

```json
{
  "verdict": {"deterministic": false, "sources_unavailable": ["medium", "npm", "reddit", "twitch", "twitter"], "completeness": "partial"},
  "username": "torvalds",
  "found_count": 6,
  "checked_count": 16,
  "results": [
    {"platform": "bitbucket", "url": "https://bitbucket.org/torvalds/", "status": "found"},
    {"platform": "dockerhub", "url": "https://hub.docker.com/u/torvalds", "status": "found"}
  ],
  "summary": "torvalds — found on 6/16 platforms (bitbucket, dockerhub, github, keybase, steam +1 more) (5 source(s) unavailable)"
}
```

---

## Code Security

Static checks against submitted code/headers/packages. No target is fetched.

---

### Validate Security Headers — `POST /v1/check/headers`

Grades a header set you already have (vs `GET /v1/scan/headers/{domain}` which fetches a live target). Same finding shape as the live scan.

```bash
curl -X POST https://api.contrastcyber.com/v1/check/headers \
  -H "Content-Type: application/json" \
  -d '{"headers":{"Content-Type":"text/html","X-Frame-Options":"DENY"}}'
```

#### Request body

| Field | Type | Required | Description |
|---|---|---|---|
| `headers` | object (string→string) | yes | HTTP response headers to evaluate |

#### Example response

```json
{
  "findings": [
    {"header": "Content-Security-Policy", "severity": "high", "present": false, "valid": false, "remediation": "Add a Content-Security-Policy header with a strict policy; start with default-src 'self'", "reference": "https://owasp.org/www-project-secure-headers/#content-security-policy"},
    {"header": "X-Frame-Options", "severity": "medium", "present": true, "valid": true, "value": "DENY", "issues": []}
  ]
}
```

---

### Detect Secrets — `POST /v1/check/secrets`

Regex-based hardcoded-secret detection (API keys, tokens, passwords) in a code snippet. Matches are masked in the response.

```bash
curl -X POST https://api.contrastcyber.com/v1/check/secrets \
  -H "Content-Type: application/json" \
  -d '{"code":"aws_key = \"AKIA...\"\npassword = \"hunter2\"","language":"python"}'
```

#### Request body

| Field | Type | Required | Description |
|---|---|---|---|
| `code` | string | yes | Source to scan |
| `language` | string | yes | Language hint (e.g. `python`) |

#### Example response

```json
{
  "findings": [
    {"type": "AWS Access Key", "severity": "critical", "line": 1, "match": "AKIA...LE", "description": "AWS access key ID detected", "remediation": "Use IAM roles or environment variables instead of hardcoded AWS keys"},
    {"type": "Password Assignment", "severity": "high", "line": 2, "match": "pass...2\"", "description": "Hardcoded password or secret assignment detected", "remediation": "Use environment variables or a secrets manager for credentials"}
  ],
  "total": 2,
  "by_severity": {"critical": 1, "high": 1},
  "summary": "Found 2 hardcoded secrets (1 critical, 1 high)"
}
```

---

### Detect Injection — `POST /v1/check/injection`

Pattern detection for SQL / command / path-traversal injection in a code snippet.

```bash
curl -X POST https://api.contrastcyber.com/v1/check/injection \
  -H "Content-Type: application/json" \
  -d '{"code":"query = \"SELECT * FROM users WHERE id = \" + user_input","language":"python"}'
```

#### Request body

| Field | Type | Required | Description |
|---|---|---|---|
| `code` | string | yes | Source to scan |
| `language` | string | yes | Language hint |

#### Example response

```json
{
  "findings": [
    {"type": "SQL Injection: string concatenation in query", "severity": "high", "line": 1, "match": "\"SELECT * FROM users...", "description": "SQL query built with string concatenation", "remediation": "Use parameterized queries or an ORM instead of concatenating user input into SQL"}
  ],
  "total": 1,
  "by_severity": {"high": 1},
  "summary": "Found 1 injection pattern (1 high)"
}
```

---

### Check Dependencies — `POST /v1/check/dependencies`

Checks a package list against known CVEs (npm / pip / Maven / etc.), up to **50** packages. Returns per-CVE severity, EPSS, KEV flag, and the fixed version.

```bash
curl -X POST https://api.contrastcyber.com/v1/check/dependencies \
  -H "Content-Type: application/json" \
  -d '{"packages":[{"name":"log4j-core","version":"2.14.1"},{"name":"lodash","version":"4.17.20"}]}'
```

#### Request body

| Field | Type | Required | Description |
|---|---|---|---|
| `packages` | array | yes | `[{name, version}]` (1–50; `version` optional) |

#### Response fields

| Field | Type | Description |
|---|---|---|
| `findings` | array | `[{package, version, cve_id, severity, cvss_v3, epss_score, in_kev, fixed_in, remediation}]` |
| `total` / `processed` | integer | CVEs found / packages scanned |
| `by_severity` | object | Severity histogram |

#### Example response

```json
{
  "findings": [
    {"package": "log4j-core", "version": "2.14.1", "cve_id": "CVE-2026-34481", "severity": "high", "cvss_v3": 7.5, "epss_score": 0.00055, "in_kev": false, "fixed_in": "2.25.4", "remediation": "Upgrade log4j-core to 2.25.4 or later (current: 2.14.1) to patch CVE-2026-34481"}
  ],
  "total": 15,
  "processed": 2,
  "by_severity": {"critical": 2, "high": 6, "medium": 7},
  "summary": "Found 15 CVEs across 2 of 2 packages (2 critical, 6 high, 7 medium)"
}
```

---

## MITRE ATLAS

Adversarial Threat Landscape for AI Systems — AI/ML attack technique catalog (techniques + real-world case studies). Sub-techniques (`AML.T####.###`) inherit their parent's tactics.

---

### ATLAS Technique — `GET /v1/atlas/{technique_id}`

Full ATLAS technique record: description, tactics, maturity, dates. Accepts `AML.T####` or `AML.T####.###`.

```bash
curl https://api.contrastcyber.com/v1/atlas/AML.T0051
```

#### Example response

```json
{
  "technique_id": "AML.T0051",
  "name": "LLM Prompt Injection",
  "description": "An adversary may craft malicious prompts as inputs to an LLM that cause the LLM to act in unintended ways …",
  "tactics": ["AML.TA0005"],
  "maturity": "realized",
  "created_date": "2023-10-25",
  "modified_date": "2025-11-05"
}
```

---

### ATLAS Technique Search — `GET /v1/atlas/techniques`

Search techniques by keyword/tactic/maturity.

| Query param | Description |
|---|---|
| `keyword` | Free-text match on name/description |
| `tactic` | Filter by ATLAS tactic (`AML.TA####`) |
| `maturity` | `demonstrated` / `feasible` / `realized` |
| `exclude_id` | Omit a technique (sibling discovery) |
| `limit` / `offset` | Paging |

```bash
curl "https://api.contrastcyber.com/v1/atlas/techniques?keyword=prompt&limit=2"
```

#### Example response

```json
{
  "query": {"keyword": "prompt", "tactic": null, "maturity": null},
  "total": 2,
  "results": [
    {"technique_id": "AML.T0002.002", "name": "AI Agent Configuration", "tactics": ["AML.TA0003"], "inherited_tactics": true, "maturity": "demonstrated", "subtechnique_of": "AML.T0002"},
    {"technique_id": "AML.T0010.005", "name": "AI Agent Tool", "tactics": ["AML.TA0004"], "maturity": "demonstrated", "subtechnique_of": "AML.T0010"}
  ]
}
```

---

### Bulk ATLAS Technique — `POST /v1/atlas/techniques/bulk` &nbsp;`[cost: 1 per ID]`

Looks up up to **50** technique IDs in one call.

```bash
# Free tier: omit the Authorization header (anonymous, 30 tokens/hr).
curl -X POST https://api.contrastcyber.com/v1/atlas/techniques/bulk \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"technique_ids":["AML.T0051","AML.T0043"]}'
```

#### Request body

| Field | Type | Required | Description |
|---|---|---|---|
| `technique_ids` | array of string | yes | ATLAS technique IDs (1–50) |

#### Example response

```json
{
  "total": 2,
  "processed": 2,
  "successful": 2,
  "failed": 0,
  "partial": false,
  "results": [
    {"technique_id": "AML.T0051", "status": "ok", "technique": {"name": "LLM Prompt Injection", "tactics": ["AML.TA0005"], "maturity": "realized"}}
  ],
  "summary": "2/2 techniques found"
}
```

---

### ATLAS Case Study — `GET /v1/atlas/case-studies/{case_study_id}`

Real-world AI/ML incident (`AML.CS####`): narrative + the techniques used. `?include=full` for the verbose procedure chain.

```bash
curl https://api.contrastcyber.com/v1/atlas/case-studies/AML.CS0000
```

#### Example response

```json
{
  "case_study_id": "AML.CS0000",
  "name": "Evasion of Deep Learning Detector for Malware C&C Traffic",
  "description": "The Palo Alto Networks Security AI research team tested a deep learning model for malware command and control (C&C) traffic detection …",
  "techniques_used": ["AML.T0000.001", "AML.T0002.000", "AML.T0005", "AML.T0043.003", "AML.T0042", "AML.T0015"]
}
```

---

### ATLAS Case Study Search — `GET /v1/atlas/case-studies`

Search case studies by keyword or technique used.

| Query param | Description |
|---|---|
| `keyword` | Free-text match |
| `technique_id` | Case studies that used a given technique |
| `limit` / `offset` | Paging |

```bash
curl "https://api.contrastcyber.com/v1/atlas/case-studies?limit=2"
```

#### Example response

```json
{
  "query": {"keyword": null, "technique_id": null},
  "total": 2,
  "results": [
    {"case_study_id": "AML.CS0000", "name": "Evasion of Deep Learning Detector for Malware C&C Traffic", "techniques_used": ["AML.T0000.001", "AML.T0002.000", "… "]}
  ]
}
```

---

## MITRE D3FEND

Defensive technique catalog mapped to ATT&CK. 7 tactics: **Detect, Harden, Isolate, Deceive, Decoy/Deceive, Evict, Restore**.

---

### D3FEND Defense — `GET /v1/d3fend/{defense_id}`

Defense by slug (e.g. `AccountLocking`): tactic, target artifact, parent technique, and the ATT&CK T-codes it mitigates.

```bash
curl https://api.contrastcyber.com/v1/d3fend/AccountLocking
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `defense_id` / `label` | string | Slug + human label |
| `uri` | string | D3FEND ontology URI |
| `parent_label` | string | Parent defense class |
| `tactic` | string | D3FEND tactic |
| `artifact` | string | Target digital artifact |
| `attack_techniques` | array | Mitigated ATT&CK T-codes |

#### Example response

```json
{
  "defense_id": "AccountLocking",
  "label": "Account Locking",
  "uri": "http://d3fend.mitre.org/ontologies/d3fend.owl#AccountLocking",
  "parent_label": "Credential Eviction",
  "tactic": "Evict",
  "artifact": "User Account",
  "attack_techniques": ["T1078", "T1078.001", "T1078.002", "T1078.003", "… (17 total)"]
}
```

---

### D3FEND Defense Search — `GET /v1/d3fend/defenses`

Search defenses by keyword / tactic / artifact.

| Query param | Description |
|---|---|
| `keyword` | Free-text match |
| `tactic` | Detect / Harden / Isolate / … |
| `artifact` | Target artifact |
| `exclude_id` | Omit a defense (sibling discovery) |
| `limit` / `offset` | Paging |

```bash
curl "https://api.contrastcyber.com/v1/d3fend/defenses?limit=3"
```

#### Example response

```json
{
  "total": 149,
  "results": [
    {"defense_id": "AccessModeling", "label": "Access Modeling", "tactic": "Harden", "artifact": "…"},
    {"defense_id": "AccountLocking", "label": "Account Locking", "tactic": "Evict", "artifact": "User Account"}
  ]
}
```

---

### Defenses for Attack — `GET /v1/d3fend/attack/{attack_technique_id}`

ATT&CK T-code → mitigating D3FEND defenses, with a per-tactic coverage histogram. Returns `200` with an **empty list** when no mapping exists — the gap is signal, not an error.

```bash
curl https://api.contrastcyber.com/v1/d3fend/attack/T1059
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `attack_technique_id` | string | Queried ATT&CK T-code |
| `total` | integer | Mitigating defenses found |
| `defenses` | array | `[{defense_id, label, tactic, artifact, attack_label, attack_tactic}]` |
| `coverage_by_tactic` | object | Defense count per D3FEND tactic |

#### Example response

```json
{
  "attack_technique_id": "T1059",
  "total": 15,
  "truncated": false,
  "defenses": [
    {"defense_id": "ContentFiltering", "label": "Content Filtering", "tactic": "Isolate", "artifact": "File", "attack_label": "Command and Scripting Interpreter", "attack_tactic": "Execution"}
  ],
  "coverage_by_tactic": {"Isolate": 7, "Detect": 4, "Deceive": 1, "Harden": 1, "Evict": 1, "Restore": 1}
}
```

---

### D3FEND Coverage — `POST /v1/d3fend/coverage` &nbsp;`[cost: 1 per T-code]`

Batch coverage breakdown for up to **500** ATT&CK T-codes — identifies which are defended vs undefended. Ideal for gap analysis against an ATT&CK navigator layer.

```bash
# Free tier: omit the Authorization header (anonymous, 30 tokens/hr).
curl -X POST https://api.contrastcyber.com/v1/d3fend/coverage \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"attack_technique_ids":["T1110","T1059","T9999"]}'
```

#### Request body

| Field | Type | Required | Description |
|---|---|---|---|
| `attack_technique_ids` | array of string | yes | ATT&CK T-codes (1–500) |

#### Example response

```json
{
  "queried_techniques": ["T1110", "T1059", "T9999"],
  "coverage_by_tactic": {"Deceive": 1, "Detect": 4, "Evict": 1, "Harden": 1, "Isolate": 7, "Restore": 1},
  "defended_techniques": ["T1059"],
  "undefended_techniques": ["T1110", "T9999"]
}
```

---

## Sigma Detection Rules

SigmaHQ corpus (3,200+ rules, daily sync). Rules are keyed by UUID and carry the full detection logic, log source, level, and ATT&CK / CVE tags.

---

### Sigma Rule — `GET /v1/sigma/{rule_id}`

Full rule by UUID: title, level, status, log source, detection block, references, false positives, license.

```bash
curl https://api.contrastcyber.com/v1/sigma/c7d33b50-f690-4b51-8cfb-0fb912a31e57
```

#### Response fields (`rule` object)

| Field | Type | Description |
|---|---|---|
| `rule_id` | string (UUID) | Sigma rule ID |
| `title` / `description` | string | Name + detection intent |
| `status` / `level` | string | `stable`/`test`/… + `critical`…`informational` |
| `author` / `date` | string | Provenance |
| `tags` | array | `attack.*`, `cve.*` tags |
| `logsource` | object | `{product, category, service}` |
| `detection` | object | Selection logic + condition |
| `detection_summary` | string | Human-readable condition |
| `references` / `falsepositives` / `license` | array/string | Context |

#### Example response

```json
{
  "rule": {
    "rule_id": "c7d33b50-f690-4b51-8cfb-0fb912a31e57",
    "title": "HackTool - SharpDPAPI Execution",
    "status": "test",
    "level": "high",
    "description": "Detects the execution of the SharpDPAPI tool based on CommandLine flags and PE metadata. SharpDPAPI is a C# port of some DPAPI functionality from the Mimikatz project.",
    "author": "Nasreddine Bencherchali (Nextron Systems)",
    "date": "2024-06-26",
    "tags": ["attack.privilege-escalation", "attack.stealth", "attack.t1134.001", "attack.t1134.003"],
    "logsource": {"product": "windows", "category": "process_creation"},
    "detection": {"selections": {"selection_img": [{"Image|endswith": "\\SharpDPAPI.exe"}]}, "condition": "…"},
    "detection_summary": "4 selections, condition: selection_img or (selection_other_cli and 1 of selection_other_options_*)",
    "references": ["https://github.com/GhostPack/SharpDPAPI"],
    "falsepositives": ["Unknown"],
    "license": "DRL 1.1"
  }
}
```

---

### Sigma Search — `GET /v1/sigma/search`

Search the corpus by ATT&CK technique, CVE, log source, status, level, or free text. Returns `rules` (1–200 per page).

| Query param | Description |
|---|---|
| `query` | Free-text match |
| `technique` | ATT&CK T-code |
| `cve_id` | Rules tagged with a CVE |
| `logsource_product` / `logsource_category` | e.g. `windows` / `process_creation` |
| `status` / `level` | Rule status / severity |
| `limit` / `offset` | Page size (1–200) + paging |

```bash
curl "https://api.contrastcyber.com/v1/sigma/search?query=mimikatz&limit=2"
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `rules` | array | Matching rules (full rule objects) |
| `total_matches` | integer | Total hits |
| `limit` / `offset` / `truncated` | mixed | Paging state |

#### Example response

```json
{
  "total_matches": 17,
  "limit": 2,
  "offset": 0,
  "truncated": true,
  "rules": [
    {
      "rule_id": "c7d33b50-f690-4b51-8cfb-0fb912a31e57",
      "title": "HackTool - SharpDPAPI Execution",
      "status": "test",
      "level": "high",
      "tags": ["attack.privilege-escalation", "attack.t1134.001"],
      "logsource": {"product": "windows", "category": "process_creation"}
    }
  ]
}
```

---

### Bulk Sigma — `POST /v1/sigma/bulk` &nbsp;`[cost: 1 per UUID]`

Looks up up to **50** rule UUIDs in one call. Per-item `status`: `ok` / `not_found` / `invalid_format`.

```bash
# Free tier: omit the Authorization header (anonymous, 30 tokens/hr).
curl -X POST https://api.contrastcyber.com/v1/sigma/bulk \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"rule_ids":["c7d33b50-f690-4b51-8cfb-0fb912a31e57"]}'
```

#### Request body

| Field | Type | Required | Description |
|---|---|---|---|
| `rule_ids` | array of string | yes | Sigma rule UUIDs (1–50) |

#### Example response

```json
{
  "total": 2,
  "processed": 2,
  "successful": 1,
  "failed": 1,
  "partial": true,
  "results": [
    {"rule_id": "c7d33b50-f690-4b51-8cfb-0fb912a31e57", "status": "ok", "rule": {"title": "HackTool - SharpDPAPI Execution", "level": "high"}},
    {"rule_id": "not-a-uuid", "status": "invalid_format"}
  ],
  "summary": "1/2 rules found"
}
```

---

## Meta

---

### Status — `GET /v1/status`

Health check: API version + per-source data freshness. No auth required.

```bash
curl https://api.contrastcyber.com/v1/status
```

#### Example response

```json
{
  "status": "ok",
  "version": "1.33.19",
  "data_sources": {
    "nvd": {"status": "ok"},
    "mitre": {"status": "ok"},
    "osv": {"status": "ok"},
    "kev": {"status": "ok"},
    "cwe": {"status": "ok"},
    "epss": {"status": "ok"},
    "exploitdb": {"status": "ok"},
    "atlas": {"status": "ok"},
    "d3fend": {"status": "ok"},
    "ghsa": {"status": "ok"}
  }
}
```

---

### Usage — `GET /v1/usage`

Current rate-limit usage for the calling key (requires an API key). Use it to pace bulk work against `hourly_remaining`.

```bash
curl https://api.contrastcyber.com/v1/usage \
  -H "Authorization: Bearer $KEY"
```

#### Response fields

| Field | Type | Description |
|---|---|---|
| `total_requests` | integer | Lifetime requests for this key |
| `last_24h` / `last_1h` | integer | Recent request counts |
| `top_endpoints` | array | `[{endpoint, count}]` |
| `hourly_limit` / `hourly_remaining` | integer | Quota + remaining tokens |

#### Example response

```json
{
  "total_requests": 1234,
  "last_24h": 71,
  "last_1h": 12,
  "top_endpoints": [
    {"endpoint": "/v1/cve", "count": 40},
    {"endpoint": "/v1/ip", "count": 18}
  ],
  "hourly_limit": 500,
  "hourly_remaining": 488
}
```

---

## MCP Server

Exposes **54 tools**, **7 resources**, and **3 prompts** over two transports:

| Transport | Use case |
|---|---|
| **stdio** | Claude Desktop, Cursor, VS Code (Claude Code), Windsurf, Cline — subprocess |
| **HTTP streaming** | `POST /mcp/` — LM Studio, OpenClaw, generic HTTP clients |

**Resources (local DB, cost 0):**
- `atlas://catalog`, `atlas://technique/{id}`, `atlas://case-study/{id}`
- `d3fend://catalog`, `d3fend://defense/{id}`
- `cwe://catalog`, `cwe://weakness/{id}`

**Built-in prompts:**
- `security_audit` — Full domain + IP audit chain
- `vulnerability_check` — CVE risk assessment
- `contrast_triage` — Auto-detect target type + perspective (red/blue) for chained workflows

---

## Data Sources & Freshness

| Source | Records | Update frequency |
|---|---|---|
| NVD (NIST) | 340k+ CVEs | Every 2 hours |
| CISA KEV | 1,500+ exploited vulns | Every 2 hours |
| FIRST EPSS | 323k+ exploit scores | Every 2 hours |
| GitHub Security Advisories | ~20k+ OSS CVEs | Hours ahead of NVD |
| MITRE ATLAS | 167 techniques + 57 case studies | ~6 months |
| MITRE D3FEND | 149 defenses | ~yearly |
| MITRE CWE | 944 weaknesses | ~weekly |
| SigmaHQ | 3,200+ detection rules | Daily |
| URLhaus (abuse.ch) | Malware URLs | Real-time |
| MalwareBazaar | Malware hashes | Real-time |
| AbuseIPDB | IP reputation | Real-time (Pro) |
| Shodan InternetDB | IP + ASN | Real-time |
| HIBP (Pwned Passwords) | 850M+ hashes | Monthly |
| FireHOL | Spam / botnet blocklist | Daily (6h cache) |
| Tor exit list | Relay endpoints | Hourly |

---

## SDKs

### Python
```python
pip install contrastapi

from contrastapi import ContrastAPI
with ContrastAPI(api_key="cc_...") as client:
    cve  = client.cve.lookup("CVE-2026-20182")
    risk = client.cve.risk_score("CVE-2026-20182")
    audit = client.domain.audit("example.com")
```

### Node / TypeScript
```bash
npm install contrastapi
```
```javascript
import { ContrastAPI } from "contrastapi";
const client = new ContrastAPI("cc_...");
const cve = await client.cve.lookup("CVE-2026-20182");
```

Both SDKs: typed responses, exception hierarchy (`RateLimitError`, `TierLimitError`, `NotFoundError`, …), multi-call shortcuts (`triage_ioc()`, `audit_full()`, `enrich_batch()`).

---

## OpenAPI Spec

```
GET https://api.contrastcyber.com/openapi.json
```
