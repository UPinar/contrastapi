# ContrastAPI — 41 Security Tools for AI Agents

<p align="center">
  <img src="app/static/banner.png" alt="ContrastAPI Banner" width="100%">
</p>

[![MCP](https://img.shields.io/badge/MCP-41_tools-purple.svg)](https://modelcontextprotocol.io)
[![smithery badge](https://smithery.ai/badge/contrastcyber/contrastapi)](https://smithery.ai/servers/contrastcyber/contrastapi)
[![contrastapi MCP server](https://glama.ai/mcp/servers/UPinar/contrastapi/badges/score.svg)](https://glama.ai/mcp/servers/UPinar/contrastapi)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Security intelligence MCP server for AI agents.** CVE/KEV/CWE lookup with EPSS, domain audit, IP threat reports, IOC enrichment, code security, **MITRE ATLAS (AI/ML attacks) + D3FEND (defenses)**. **41 tools, free, no API key, 100 credits/hour.**

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

Restart your agent. Other clients (Node SDK, cURL, VS Code): **[mcp-setup](https://api.contrastcyber.com/mcp-setup)** · **[quickstart](https://api.contrastcyber.com/quickstart)**

## Try it

```bash
curl https://api.contrastcyber.com/v1/cve/CVE-2021-44228
curl https://api.contrastcyber.com/v1/atlas/AML.T0051            # MITRE ATLAS — LLM Prompt Injection
curl https://api.contrastcyber.com/v1/d3fend/attack/T1059        # D3FEND defenses for ATT&CK T1059
```

Or ask your agent:

- *"Is CVE-2024-3094 exploited in the wild? Check EPSS + KEV, then look up the underlying CWE."*
- *"Explain LLM Prompt Injection in MITRE ATLAS and bridge it to D3FEND defenses."*
- *"For these ATT&CK techniques [T1059, T1190, T1550.001, T9999], which have NO D3FEND mitigation?"*

## Links

**Endpoints:** [docs/ENDPOINTS.md](docs/ENDPOINTS.md) · **OpenAPI:** [openapi.json](https://api.contrastcyber.com/openapi.json) · **Playground:** [/playground](https://api.contrastcyber.com/playground)

<details>
<summary>Self-host / tests / stack</summary>

```bash
git clone https://github.com/UPinar/contrastapi.git
cd contrastapi && python3 -m venv venv && venv/bin/pip install -r requirements.txt
cd app && ../venv/bin/uvicorn main:app --port 8002
cd app && python -m pytest tests/ -q  # 1263 tests
```

Python 3.12 · FastAPI · uvicorn · `mcp-python-sdk` Streamable HTTP at `/mcp` · SQLite WAL · dnspython with SSRF-safe backend.

</details>

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
