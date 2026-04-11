# ContrastAPI Endpoints

Full list of 39+ REST endpoints. Base URL: `https://api.contrastcyber.com`

- **Free tier:** 100 credits/hour, no API key required
- **Pro tier:** 1,000 credits/hour ([Get API Key](https://contrastcyber.com/pricing))
- **Credit costs:** most endpoints cost 1 credit; see [Credit Costs](#credit-costs) below

## Domain Intelligence

```
GET  /v1/domain/{domain}          Full domain report (DNS + WHOIS + SSL + subs + WAF + reputation)
GET  /v1/audit/{domain}           Comprehensive audit (full report + tech fingerprint + live headers)  [cost: 4]
GET  /v1/dns/{domain}             DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
GET  /v1/whois/{domain}           WHOIS registration data
GET  /v1/subdomains/{domain}      Subdomain enumeration (DNS brute + CT logs)
GET  /v1/certs/{domain}           Certificate transparency logs
GET  /v1/ssl/{domain}             SSL/TLS analysis (cipher, cert chain, grade A-F)
GET  /v1/tech/{domain}            Technology fingerprinting (CMS, frameworks, CDN, analytics)
GET  /v1/threat/{domain}          Threat intelligence (URLhaus malware URLs)
GET  /v1/archive/{domain}         Web archive history (Wayback Machine snapshots)
GET  /v1/scan/headers/{domain}    Live HTTP security header scan
GET  /v1/monitor/{domain}         Lightweight domain health check
GET  /v1/domain/{domain}/vulns    Tech stack CVE scan
POST /v1/domains/bulk             Bulk domain scan (10 free, 50 pro)
```

## IP & Network

```
GET /v1/ip/{ip}                   IP intel + reputation (AbuseIPDB, Shodan)
GET /v1/threat-report/{ip}        Orchestrated threat report (Shodan + AbuseIPDB + ASN)  [cost: 4]
GET /v1/asn/{target}              ASN lookup (AS number or IP)
```

## CVE Intelligence

```
GET  /v1/cve/{cve_id}             CVE details + EPSS + KEV
GET  /v1/cves?product=&severity=  Search CVEs
GET  /v1/cves/recent?hours=24     Latest CVEs
GET  /v1/cves/kev                 CISA exploited vulns
GET  /v1/epss/{cve_id}            Exploit probability
GET  /v1/exploit/{cve_id}         Public exploit search (GitHub Advisory + Shodan)
POST /v1/cves/bulk                Bulk CVE lookup (10 free, 50 pro)  [cost: N per item]
```

## Threat Intelligence / IOC

```
GET  /v1/ioc/{indicator}          Unified IOC enrichment (IP, domain, URL, hash)
GET  /v1/hash/{hash}              Malware hash reputation (MalwareBazaar)
GET  /v1/password/{sha1}          Password breach check (HIBP, k-anonymity)
GET  /v1/phishing/{url}           Phishing/malware URL check (URLhaus)
POST /v1/iocs/bulk                Bulk IOC enrichment (10 free, 50 pro)  [cost: N per item]
```

## OSINT

```
GET /v1/email/mx/{domain}         Mail provider detection + email security grade
GET /v1/email/disposable/{email}  Disposable/temporary email check
GET /v1/phone/{number}            Phone number OSINT (carrier, type, country)
GET /v1/username/{username}       Username OSINT (16 platforms, account discovery)
```

## Code Security

```
POST /v1/check/headers            Validate HTTP security headers
POST /v1/check/secrets            Detect hardcoded secrets
POST /v1/check/injection          SQL/cmd injection patterns
POST /v1/check/dependencies       Check packages for known CVEs
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
| `GET /v1/threat-report/{ip}` | 4 | Shodan + AbuseIPDB + ASN aggregated |
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

## OpenAPI Spec

Machine-readable spec (for codegen, OpenAPI clients, etc.):

```
https://api.contrastcyber.com/openapi.json
```
