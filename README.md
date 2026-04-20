# ContrastAPI — 31 Security Tools for AI Agents

<p align="center">
  <img src="app/static/banner.png" alt="ContrastAPI Banner" width="100%">
</p>

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-1104_passing-brightgreen.svg)](https://github.com/UPinar/contrastapi/actions)
[![MCP](https://img.shields.io/badge/MCP-31_tools-purple.svg)](https://modelcontextprotocol.io)
[![Smithery](https://img.shields.io/badge/Smithery-96%2F100-orange.svg)](https://smithery.ai/servers/contrastcyber/contrastapi)
[![npm](https://img.shields.io/npm/v/contrastapi.svg)](https://www.npmjs.com/package/contrastapi)
[![VS Code](https://img.shields.io/badge/VS_Code-Marketplace-007ACC.svg)](https://marketplace.visualstudio.com/items?itemName=ContrastAPI.contrastapi)

**Security intelligence API and MCP server for AI agents.** Domain audit, CVE lookup with EPSS+KEV, IP threat reports, IOC enrichment, tech fingerprinting, and 25 more. **Free, no API key, 100 credits/hour.**

**English** | [中文](README_CN.md) · **Live:** [api.contrastcyber.com](https://api.contrastcyber.com)

---

## 30-Second Setup

Pick your integration:

### Option 1: MCP (Claude Desktop / Cursor / VS Code / Windsurf / OpenClaw)

Add to your MCP config:

    {
      "mcpServers": {
        "contrastapi": {
          "command": "npx",
          "args": ["-y", "mcp-remote", "https://api.contrastcyber.com/mcp/"]
        }
      }
    }

Restart your agent. Done. Full setup guide: **[api.contrastcyber.com/mcp-setup](https://api.contrastcyber.com/mcp-setup)**

### Option 2: Node.js SDK

```bash
npm install contrastapi
```

```javascript
const api = require("contrastapi")();

const audit = await api.domain.audit("example.com");        // full audit
const cve   = await api.cve.lookup("CVE-2024-3094");        // EPSS + KEV
const ip    = await api.ip.threatReport("8.8.8.8");         // Shodan + AbuseIPDB + ASN
const bulk  = await api.cve.bulk(["CVE-2021-44228", "CVE-2024-3094"]);
```

Zero dependencies, Node 14+. Full SDK docs: [sdk/node/](sdk/node/)

### Option 3: cURL

```bash
curl https://api.contrastcyber.com/v1/cve/CVE-2024-3094
curl https://api.contrastcyber.com/v1/audit/example.com
curl https://api.contrastcyber.com/v1/threat-report/8.8.8.8
```

More examples: **[API Quick Start](https://api.contrastcyber.com/quickstart)** (cURL, Node.js, Python, CI/CD)

### Option 4: VS Code Extension

Install **[ContrastAPI — Security Intelligence](https://marketplace.visualstudio.com/items?itemName=ContrastAPI.contrastapi)** from the Marketplace. 29 commands, sidebar tree, right-click context menu. No API key required.

---

## Try It Now

After setup, ask your AI agent:

- *"Is CVE-2024-3094 being exploited in the wild? Check EPSS + KEV."*
- *"Show me CVEs indexed before NVD — what's leading right now?"*
- *"Audit example.com, then look up CVEs for every technology detected"*

More example prompts: [docs/PROMPTS.md](docs/PROMPTS.md) · [/playground](https://api.contrastcyber.com/playground) (interactive tester)

---

## What's Inside

- **31 MCP tools** across 6 categories — full list: **[docs/ENDPOINTS.md](docs/ENDPOINTS.md)**
- **340K+ CVEs** from NVD + MITRE cvelistV5 + GitHub Security Advisories, enriched with EPSS + CISA KEV. `cve_lookup` exposes `sources`, `first_seen_source`, `first_seen_at` — agents detect CVEs indexed before NVD publishes. `cve_search` supports `kev`, `epss_min`, `sort`, and `offset` pagination — agents can filter to actively exploited CVEs, sort by exploit probability, and page through large result sets.
- **Weighted credits** — 1 for simple calls, 4 for heavy orchestration (audit, threat report), N for bulk lookups
- **LLM-optimized summaries** — every response includes a `summary` field so agents reason without parsing nested JSON
- **Distribution** — [npm SDK](https://www.npmjs.com/package/contrastapi) · [VS Code Extension](https://marketplace.visualstudio.com/items?itemName=ContrastAPI.contrastapi) · [Smithery MCP](https://smithery.ai/servers/contrastcyber/contrastapi) (96/100 quality) · REST API

## Docs & Links

- **API Quick Start:** [api.contrastcyber.com/quickstart](https://api.contrastcyber.com/quickstart)
- **MCP Setup:** [api.contrastcyber.com/mcp-setup](https://api.contrastcyber.com/mcp-setup)
- **Full endpoint list:** [docs/ENDPOINTS.md](docs/ENDPOINTS.md)
- **OpenAPI spec:** [api.contrastcyber.com/openapi.json](https://api.contrastcyber.com/openapi.json)
- **LLM discovery:** [api.contrastcyber.com/llms.txt](https://api.contrastcyber.com/llms.txt)
- **Interactive playground:** [api.contrastcyber.com/playground](https://api.contrastcyber.com/playground)

<details>
<summary><strong>Self-Hosting</strong></summary>

```bash
git clone https://github.com/UPinar/contrastapi.git
cd contrastapi
python3 -m venv venv
venv/bin/pip install -r requirements.txt
cd app
../venv/bin/uvicorn main:app --host 127.0.0.1 --port 8002
```

Requires Python 3.12. SQLite databases auto-initialize on first run. See [docs/ENDPOINTS.md](docs/ENDPOINTS.md) for the full endpoint reference.

</details>

<details>
<summary><strong>Tests</strong></summary>

```bash
cd app && PYTHONPATH=. python -m pytest tests/ -v
```

**1104 tests, 36/36 smoke-test coverage** on every 15-minute cron. Covers auth, rate limiting, validation, database ops, domain intelligence, CVE intelligence, threat intelligence, code security (ReDoS protection, concurrency limits), tech fingerprinting, IP reputation, email security, phone validation, web archive, MCP endpoint, bulk endpoints, weighted credit system, and API routes.

</details>

<details>
<summary><strong>Stack & Architecture</strong></summary>

- **Runtime:** Python 3.12, FastAPI, uvicorn (2 workers)
- **MCP:** Official `mcp-python-sdk` with Streamable HTTP transport, mounted as sub-app at `/mcp`
- **Domain audit:** 8+ parallel checks (SSL, DNS, WHOIS, SPF/DMARC/DKIM, CT logs, tech fingerprint, security headers) via `ThreadPoolExecutor`, with 1-hour SQLite caching for warm-path responses
- **Database:** SQLite with WAL mode (3 databases: API rate-limit, CVE cache, domain cache)
- **DNS:** dnspython with `_SSRFSafeBackend` (custom httpcore backend that validates all resolved IPs before connecting — catches DNS rebinding)
- **HTTP:** httpx
- **Rate limiting:** SQLite sliding window, shared across workers via WAL mode
- **Weighted credits:** Atomic `BEGIN IMMEDIATE` consumption — either the whole N-credit batch fits or the request is rejected

</details>

<details>
<summary><strong>Also Available On</strong></summary>

- **Smithery:** [smithery.ai/servers/contrastcyber/contrastapi](https://smithery.ai/servers/contrastcyber/contrastapi) (96/100 quality score)
- **npm:** [npmjs.com/package/contrastapi](https://www.npmjs.com/package/contrastapi)
- **VS Code Marketplace:** [ContrastAPI — Security Intelligence](https://marketplace.visualstudio.com/items?itemName=ContrastAPI.contrastapi)
- **Awesome OSINT MCP Servers:** [soxoj/awesome-osint-mcp-servers](https://github.com/soxoj/awesome-osint-mcp-servers)
- **RapidAPI:** [rapidapi.com/UPinar/api/contrastapi](https://rapidapi.com/UPinar/api/contrastapi)

</details>

## Multi-Agent Usage

ContrastAPI responses include a `verdict` metadata block on key endpoints
(`cve_lookup`, `domain_report`, `ip_lookup`, `threat_intel`, `ioc_lookup`):

```json
{
  "verdict": {
    "deterministic": true,
    "falsifiable_fields": ["cve_id", "severity", "cvss_v3", "published", "references"],
    "data_age_seconds": 1834,
    "sources_queried": ["mitre_cache", "nvd_cache"],
    "sources_unavailable": [],
    "completeness": "complete"
  },
  "sources": ["mitre", "nvd"],
  "first_seen_source": "mitre",
  "first_seen_at": "2024-06-01T03:22:00Z"
}
```

This lets an orchestrator run Agent A (calling ContrastAPI) and Agent B
(independently verifying a subset of `falsifiable_fields` against the upstream
authority — NVD, RDAP, CT logs, URLhaus). `deterministic: true` means the same
query will return the same answer; `data_age_seconds` is the distance from the
latest upstream sync (or `0` for live fetches).

`sources_queried` lists upstream providers consulted for this response; `sources_unavailable` lists any that failed (timeout, parse error, rate-limit, upstream 5xx). `completeness` is `"partial"` whenever `sources_unavailable` is non-empty — agents should treat partial responses as best-effort and re-query later.

`sources` lists which upstream feeds have indexed this CVE (ordered by first observation). `first_seen_source` and `first_seen_at` reveal which feed saw it earliest — during 0-day bursts, MITRE and GHSA typically lead NVD by hours to weeks. `completeness: "minimal"` means only MITRE/GHSA have the CVE so far (no severity/CVSS from NVD yet).

Probe `GET /v1/capabilities` — responses with `"verdict_metadata": true` support
this pattern across the endpoints listed above.

## License

MIT
