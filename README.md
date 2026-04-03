# ContrastAPI

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-595_passing-brightgreen.svg)](https://github.com/UPinar/contrastapi/actions)
[![RapidAPI](https://img.shields.io/badge/RapidAPI-Available-blue.svg)](https://rapidapi.com/UPinar/api/contrastapi)

**Security intelligence API for AI agents and developers.** 30+ endpoints: CVE lookup with EPSS/KEV enrichment, domain reconnaissance, SSL analysis, IP reputation (AbuseIPDB, Shodan), IOC/malware lookup, exploit search, technology fingerprinting, and code security verification. Free, no signup required.

**Live:** [api.contrastcyber.com](https://api.contrastcyber.com) | **Scanner:** [contrastcyber.com](https://contrastcyber.com)

## Why ContrastAPI?

- **One call, full picture** — domain report returns DNS + WHOIS + SSL + subdomains + WAF + IP reputation in a single response
- **CVE intelligence** — 340K+ CVEs enriched with EPSS exploit probability and CISA KEV status
- **IP reputation** — AbuseIPDB, Shodan enrichment with 24-hour cache
- **Tech fingerprinting** — detect CMS, frameworks, CDN, analytics from headers + HTML
- **AI-native** — LLM-optimized summaries, structured JSON, OpenAPI spec
- **Free forever** — 100 req/hr, no API key, no signup

## Quick Start

```bash
# Domain intelligence
curl "https://api.contrastcyber.com/v1/domain/example.com"

# CVE lookup with EPSS + KEV
curl "https://api.contrastcyber.com/v1/cve/CVE-2024-3094"

# Search CVEs
curl "https://api.contrastcyber.com/v1/cves?product=apache&severity=critical"

# SSL analysis
curl "https://api.contrastcyber.com/v1/ssl/example.com"

# IOC lookup (IP, domain, URL, or hash)
curl "https://api.contrastcyber.com/v1/ioc/8.8.8.8"

# Public exploit search
curl "https://api.contrastcyber.com/v1/exploit/CVE-2024-3400"

# Check code for secrets
curl -X POST "https://api.contrastcyber.com/v1/check/secrets" \
  -H "Content-Type: application/json" \
  -d '{"code": "password = \"admin123\"", "language": "python"}'
```

## Endpoints

### Domain Intelligence

```
GET  /v1/domain/{domain}       Full domain report (DNS + WHOIS + SSL + subs + WAF + reputation)
GET  /v1/dns/{domain}          DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
GET  /v1/whois/{domain}        WHOIS registration data
GET  /v1/subdomains/{domain}   Subdomain enumeration (DNS brute + CT logs)
GET  /v1/certs/{domain}        Certificate transparency logs
GET  /v1/ssl/{domain}          SSL/TLS analysis (cipher, cert chain, grade A-F)
GET  /v1/ip/{ip}               IP intel + reputation (AbuseIPDB, Shodan)
GET  /v1/tech/{domain}         Technology fingerprinting (CMS, frameworks, CDN, analytics)
GET  /v1/threat/{domain}       Threat intelligence (URLhaus malware URLs)
GET  /v1/scan/headers/{domain} Live HTTP security header scan
GET  /v1/monitor/{domain}      Lightweight domain health check
GET  /v1/domain/{domain}/vulns Tech stack CVE scan
POST /v1/domains/bulk          Bulk domain scan (10 free, 50 pro)
```

### CVE Intelligence

```
GET /v1/cve/{cve_id}           CVE details + EPSS + KEV
GET /v1/cves?product=&severity= Search CVEs
GET /v1/cves/recent?hours=24   Latest CVEs
GET /v1/cves/kev               CISA exploited vulns
GET /v1/epss/{cve_id}          Exploit probability
GET /v1/exploit/{cve_id}       Public exploit search (GitHub Advisory + Shodan)
```

### Threat Intelligence

```
GET /v1/ioc/{indicator}        Unified IOC enrichment (IP, domain, URL, hash)
GET /v1/hash/{hash}            Malware hash reputation (MalwareBazaar)
GET /v1/password/{sha1}        Password breach check (HIBP, k-anonymity)
GET /v1/phishing/{url}         Phishing/malware URL check (URLhaus)
```

### Code Security

```
POST /v1/check/headers         Validate HTTP security headers
POST /v1/check/secrets         Detect hardcoded secrets
POST /v1/check/injection       SQL/cmd injection patterns
POST /v1/check/dependencies    Check packages for known CVEs
```

## Rate Limits

| Tier | Limit | API Key |
|------|-------|---------|
| Free | 100 req/hr | Not required |
| Pro | 1,000 req/hr | [Get API Key](https://contrastcyber.com/pricing) |

## Data Sources

| Source | Records | Update |
|--------|---------|--------|
| NVD (NIST) | 340k+ CVEs | Every 2 hours |
| CISA KEV | 1,500+ exploited vulns | Every 2 hours |
| FIRST EPSS | 323k+ exploit scores | Every 2 hours |

## Docs

- **Swagger UI:** https://api.contrastcyber.com/docs
- **OpenAPI spec:** https://api.contrastcyber.com/openapi.json
- **LLM discovery:** https://api.contrastcyber.com/llms.txt

## Self-Hosting

```bash
git clone https://github.com/UPinar/contrastapi.git
cd contrastapi
python3 -m venv venv
venv/bin/pip install -r requirements.txt
cd app
../venv/bin/uvicorn main:app --host 127.0.0.1 --port 8002
```

## Tests

```bash
cd app && PYTHONPATH=. python -m pytest tests/ -v
```

595 tests covering auth, rate limiting, validation, database operations, domain intelligence, CVE intelligence, threat intelligence, code security, tech fingerprinting, IP reputation, and API routes.

## Stack

- **Runtime:** Python 3.12, FastAPI, uvicorn
- **Database:** SQLite (WAL mode, 3 databases)
- **DNS:** dnspython
- **HTTP:** httpx

## Also Available On

- **RapidAPI:** [rapidapi.com/UPinar/api/contrastapi](https://rapidapi.com/UPinar/api/contrastapi)
- **Product Hunt:** [contrastapi](https://www.producthunt.com/posts/contrastapi)

## License

MIT
