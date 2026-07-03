# ContrastAPI — 55 Security Tools + 7 MCP Resources for AI Agents

<p align="center">
  <img src="app/static/banner.png" alt="ContrastAPI Banner" width="100%">
</p>

[![MCP](https://img.shields.io/badge/MCP-54_tools-purple.svg)](https://modelcontextprotocol.io)
[![Install in Claude Desktop](https://img.shields.io/badge/Claude_Desktop-Install_Extension-d97757.svg)](https://github.com/UPinar/contrastapi/releases/latest)
[![smithery badge](https://smithery.ai/badge/contrastcyber/contrastapi)](https://smithery.ai/servers/contrastcyber/contrastapi)
[![contrastapi MCP server](https://glama.ai/mcp/servers/UPinar/contrastapi/badges/score.svg)](https://glama.ai/mcp/servers/UPinar/contrastapi)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Security intelligence, built for AI agents.** Give your agent grounded answers about vulnerabilities, threats, and attack surface — backed by authoritative sources (NVD, CISA KEV, FIRST EPSS, MITRE ATLAS & D3FEND), never guesswork. CVE/KEV/CWE lookup with EPSS exploit-probability and composite risk scoring, domain & IP investigation, IOC enrichment, code-security checks, and live web intelligence. **55 tools, 7 Resources, and 3 Prompts — free, no API key, no signup.**

[中文](README_CN.md) · **Live:** [api.contrastcyber.com](https://api.contrastcyber.com)

---

## Documentation

- **[API Documentation](docs/API_Documentation.md)** — REST reference: 60+ endpoints, authentication, rate limits, token costs, and response envelope.
- **[MCP Documentation](docs/MCP_Documentation.md)** — MCP tool-selection guide, 7 Resources, 3 Prompts, and copy-paste agent prompts.

## Setup (MCP)

### Any MCP client

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

### Claude Desktop — one-click extension

Grab the `.mcpb` file from the **[latest release](https://github.com/UPinar/contrastapi/releases/latest)** and double-click it (or Claude Desktop → **Settings → Extensions → Install Extension…**). No signup, no API key — all 55 tools ready immediately.

## SDKs

```bash
pip install contrastapi      # Python 3.10+ — sync + async, typed responses, shortcut helpers
npm install contrastapi      # Node 14+ — concrete TypeScript types, 14 namespaces
```

Both SDKs cover every HTTP endpoint and MCP tool — CVE/KEV/CWE, ATLAS, D3FEND, Sigma rules, email security posture, domain, IP, IOC, code security, and web intelligence — with wire-exact response shapes and a typed exception hierarchy that mirrors the API error envelope. They also expose MCP Resources for browsing the ATLAS, D3FEND, and CWE catalogs (see [docs/MCP_Documentation.md](docs/MCP_Documentation.md#mcp-resources)) and a conditional triage Prompt (see [docs/MCP_Documentation.md#contrast-triage](docs/MCP_Documentation.md#contrast-triage)). Web-intelligence tools — `robots_txt`, `redirect_chain`, `email_verify`, `brand_assets`, `seo_audit`, `geo_audit` — ship with an explicit ethical floor: per-target throttling, robots.txt respected, no SMTP probing.

## Links

**OpenAPI:** [openapi.json](https://api.contrastcyber.com/openapi.json)

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
