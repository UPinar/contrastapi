# ContrastAPI — 53 Security Tools + 7 MCP Resources for AI Agents

<p align="center">
  <img src="app/static/banner.png" alt="ContrastAPI Banner" width="100%">
</p>

[![MCP](https://img.shields.io/badge/MCP-53_tools-purple.svg)](https://modelcontextprotocol.io)
[![smithery badge](https://smithery.ai/badge/contrastcyber/contrastapi)](https://smithery.ai/servers/contrastcyber/contrastapi)
[![contrastapi MCP server](https://glama.ai/mcp/servers/UPinar/contrastapi/badges/score.svg)](https://glama.ai/mcp/servers/UPinar/contrastapi)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Security intelligence MCP server for AI agents.** CVE/KEV/CWE lookup with EPSS, **composite risk scoring (CVSS+EPSS+KEV+PoC fusion — v1.29.1)**, **CVSS v3.x vector parser (v1.29.1)**, domain audit, IP threat reports, IOC enrichment, code security, **MITRE ATLAS (AI/ML attacks) + D3FEND (defenses)**, **web intelligence (robots.txt, redirect-chain, email validation, brand-assets, SEO audit — v1.25.0)**. **53 tools + 7 Resources (ATLAS+D3FEND+CWE catalog browsing) + 3 Prompts (security audit, vulnerability check, conditional triage), free, no API key, 30 credits/hour.**

[中文](README_CN.md) · **Live:** [api.contrastcyber.com](https://api.contrastcyber.com)

---

## Setup (MCP)

```json
{
  "mcpServers": {
    "contrastapi": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://api.contrastcyber.com/mcp/"]
    }
  }
}
```

Restart your agent. Other clients (Python SDK, Node SDK, cURL, VS Code): **[mcp-setup](https://api.contrastcyber.com/mcp-setup)** · **[quickstart](https://api.contrastcyber.com/quickstart)**

## SDKs

```bash
pip install contrastapi      # Python 3.10+ — sync + async, typed responses, shortcut helpers
npm install contrastapi      # Node 14+ — concrete TypeScript types, 14 namespaces
```

Both SDKs cover all 60+ HTTP endpoints / 53 MCP tools (CVE/KEV/CWE, ATLAS, D3FEND, Sigma rules, email security posture, domain, IP, IOC, code-security, web-intel, etc.) with the same wire-exact response shapes and a typed exception hierarchy mirroring the v1.22.2+ error envelope. v1.23.0 adds MCP Resources (ATLAS+D3FEND+CWE catalog browsing — see [docs/resources.md](docs/resources.md)) and a conditional triage Prompt (see [docs/PROMPTS.md#contrast-triage-v1230](docs/PROMPTS.md)). v1.25.0 adds 5 web-intelligence tools (`robots_txt`, `redirect_chain`, `email_verify`, `brand_assets`, `seo_audit`) with explicit ethical-floor guardrails (per-target eTLD+1 throttle, robots.txt respected, no SMTP probing).

## Try it

```bash
curl 'https://api.contrastcyber.com/v1/cves?product=openssl&kev=true'  # cve_search — CVEs by product, KEV-only filter
curl https://api.contrastcyber.com/v1/domain/example.com         # domain_report — DNS+WHOIS+SSL+subdomains+intel, one call
curl https://api.contrastcyber.com/v1/cve/CVE-2021-44228         # cve_lookup — full record (CVSS+EPSS+KEV+CWE)
curl https://api.contrastcyber.com/v1/exploit/CVE-2021-44228     # exploit_lookup — public PoC / exploit availability
curl https://api.contrastcyber.com/v1/ip/1.1.1.1                 # ip_lookup — reputation, geo, ASN, threat intel
```

Or ask your agent:

- *"Search for KEV-listed OpenSSL CVEs, then pull the full record for the highest-EPSS one."*
- *"Run a full domain report for example.com — DNS, WHOIS, SSL, subdomains, and threat intel in one call."*
- *"Does CVE-2021-44228 have a public exploit or PoC available?"*
- *"What's the reputation, country, and ASN for 1.1.1.1 — is it flagged in any threat feed?"*

## Links

**Endpoints:** [docs/ENDPOINTS.md](docs/ENDPOINTS.md) · **OpenAPI:** [openapi.json](https://api.contrastcyber.com/openapi.json) · **Playground:** [/playground](https://api.contrastcyber.com/playground)

<details>
<summary>Also available on</summary>

[Smithery](https://smithery.ai/servers/contrastcyber/contrastapi) · [npm](https://www.npmjs.com/package/contrastapi) · [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=ContrastAPI.contrastapi) · [Awesome OSINT MCP](https://github.com/soxoj/awesome-osint-mcp-servers) · [RapidAPI](https://rapidapi.com/UPinar/api/contrastapi)

</details>

<details>
<summary>Multi-agent verdict metadata</summary>

Responses include a `verdict` block — `deterministic`, `falsifiable_fields`, `data_age_seconds`, `sources_queried` / `sources_unavailable`, `completeness` — so a verifier agent can independently re-derive specific fields from the upstream authority (NVD, RDAP, CT logs, URLhaus). Probe `GET /v1/capabilities` for `"verdict_metadata": true`.

CVE responses also embed `next_calls: list[PivotHint]` — `{tool, input, reason}` triples that suggest the next MCP tool to call (e.g. `kev_detail` when `kev.in_kev=true`, `cwe_lookup` when `cwe_id` is set). Agents chain workflows without manual prompting.

</details>

MIT
