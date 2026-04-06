# ContrastAPI

<p align="center">
  <img src="app/static/banner.png" alt="ContrastAPI Banner" width="100%">
</p>

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-721_passing-brightgreen.svg)](https://github.com/UPinar/contrastapi/actions)
[![MCP](https://img.shields.io/badge/MCP-23_tools-purple.svg)](https://modelcontextprotocol.io)
[![RapidAPI](https://img.shields.io/badge/RapidAPI-Available-blue.svg)](https://rapidapi.com/UPinar/api/contrastapi)
[![npm](https://img.shields.io/npm/v/contrastapi.svg)](https://www.npmjs.com/package/contrastapi)

**Security intelligence API and MCP server for AI agents.** 29 tools / 35+ endpoints: CVE lookup with EPSS/KEV enrichment, domain reconnaissance, SSL analysis, IP reputation (AbuseIPDB, Shodan), IOC/malware lookup, exploit search, technology fingerprinting, email security, phone validation, and code security scanning. Free, no API key required.

**English** | [中文](README_CN.md)

**Live:** [api.contrastcyber.com](https://api.contrastcyber.com) | **Quick Start:** [API](https://api.contrastcyber.com/quickstart) · [MCP](https://api.contrastcyber.com/mcp-setup) | **Docs:** [Endpoints](#endpoints) | **Scanner:** [contrastcyber.com](https://contrastcyber.com) | **Blog:** [I Built 23 Security Tools That AI Agents Can Use](https://dev.to/contrastcyber/i-built-23-security-tools-that-ai-agents-can-use-4he7)

## Use with AI Agents

Setup for Claude Desktop, Cursor, VS Code, Windsurf: **[MCP Setup Guide](https://api.contrastcyber.com/mcp-setup)**

Then ask your AI:

- *"Scan example.com for security issues"*
- *"Look up CVE-2024-3094"*
- *"Is 8.8.8.8 malicious?"*
- *"Find subdomains of example.com"*
- *"Check this code for hardcoded secrets"*
- *"What's the EPSS score for CVE-2021-44228?"*

## Quick Start

### Node.js SDK

```bash
npm install contrastapi
```

```javascript
const api = require("contrastapi")();

const report = await api.domain.report("example.com");
const cve = await api.cve.lookup("CVE-2024-3094");
const ssl = await api.domain.ssl("example.com");
const headers = await api.scan.headers("example.com");
```

With API key (Pro): `const api = require("contrastapi")({ apiKey: "your-key" });`

Full SDK docs: [sdk/node/](sdk/node/)

### cURL

```bash
curl https://api.contrastcyber.com/v1/domain/example.com
```

More examples: **[API Quick Start](https://api.contrastcyber.com/quickstart)** (cURL, Node.js, Python, CI/CD)

## Why ContrastAPI?

- **One call, full picture** — domain report returns DNS + WHOIS + SSL + subdomains + WAF + IP reputation in a single response
- **CVE intelligence** — 340K+ CVEs enriched with EPSS exploit probability and CISA KEV status
- **IP reputation** — AbuseIPDB, Shodan enrichment with 24-hour cache
- **Tech fingerprinting** — detect CMS, frameworks, CDN, analytics from headers + HTML
- **AI-native** — LLM-optimized summaries, structured JSON, OpenAPI spec
- **Free forever** — 100 req/hr, no API key, no signup

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
GET  /v1/asn/{target}          ASN lookup (AS number or IP)
GET  /v1/tech/{domain}         Technology fingerprinting (CMS, frameworks, CDN, analytics)
GET  /v1/threat/{domain}       Threat intelligence (URLhaus malware URLs)
GET  /v1/scan/headers/{domain} Live HTTP security header scan
GET  /v1/monitor/{domain}      Lightweight domain health check
GET  /v1/domain/{domain}/vulns Tech stack CVE scan
GET  /v1/email/mx/{domain}     Mail provider detection + email security grade
GET  /v1/email/disposable/{email} Disposable/temporary email check
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
GET /v1/phone/{number}         Phone number OSINT (carrier, type, country)
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

- **API Quick Start:** https://api.contrastcyber.com/quickstart
- **MCP Setup:** https://api.contrastcyber.com/mcp-setup
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

721 tests covering auth, rate limiting, validation, database operations, domain intelligence, CVE intelligence, threat intelligence, code security (ReDoS protection, concurrency limits), tech fingerprinting, IP reputation, email security, phone validation, MCP endpoint, and API routes.

## Stack

- **Runtime:** Python 3.12, FastAPI, uvicorn
- **Database:** SQLite (WAL mode, 3 databases)
- **DNS:** dnspython
- **HTTP:** httpx

## Also Available On

- **Awesome OSINT MCP Servers:** [soxoj/awesome-osint-mcp-servers](https://github.com/soxoj/awesome-osint-mcp-servers)
- **RapidAPI:** [rapidapi.com/UPinar/api/contrastapi](https://rapidapi.com/UPinar/api/contrastapi)
- **Product Hunt:** [contrastapi](https://www.producthunt.com/posts/contrastapi)

## License

MIT
