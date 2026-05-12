# ContrastAPI — 为 AI 智能体打造的 52 个安全工具 + 7 个 MCP 资源

<p align="center">
  <img src="app/static/banner.png" alt="ContrastAPI Banner" width="100%">
</p>

[![MCP](https://img.shields.io/badge/MCP-52_tools-purple.svg)](https://modelcontextprotocol.io)
[![smithery badge](https://smithery.ai/badge/contrastcyber/contrastapi)](https://smithery.ai/servers/contrastcyber/contrastapi)
[![contrastapi MCP server](https://glama.ai/mcp/servers/UPinar/contrastapi/badges/score.svg)](https://glama.ai/mcp/servers/UPinar/contrastapi)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**面向 AI 智能体的安全情报 MCP 服务器。** CVE/KEV/CWE 查询（含 EPSS）、**综合风险评分（CVSS+EPSS+KEV+PoC 融合 — v1.29.1）**、**CVSS v3.x 向量解析（v1.29.1）**、域名审计、IP 威胁报告、IOC 增强、代码安全检查、**MITRE ATLAS（AI/ML 攻击）+ D3FEND（防御技术）**、**网站情报（robots.txt 解析、重定向链、邮箱校验、品牌资源、SEO 审计 — v1.25.0）**。**52 个工具 + 7 个 MCP 资源（ATLAS+D3FEND+CWE 目录浏览）+ 条件式分诊 Prompt，免费使用，无需 API 密钥，每小时 30 信用额度。**

[English](README.md) · **在线服务：** [api.contrastcyber.com](https://api.contrastcyber.com)

支持 **DeepSeek**、**Qwen（通义千问）** 等支持 MCP 协议的 AI 模型。

---

## 快速接入（MCP）

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

重启智能体即可。其他客户端（Python SDK、Node SDK、cURL、VS Code）：**[mcp-setup](https://api.contrastcyber.com/mcp-setup)** · **[quickstart](https://api.contrastcyber.com/quickstart)**

## SDK

```bash
pip install contrastapi      # Python 3.10+ — 同步 + 异步、类型化响应、快捷助手
npm install contrastapi      # Node 14+ — 具体 TypeScript 类型、14 个命名空间
```

两个 SDK 均覆盖全部 60+ HTTP 端点 / 52 个 MCP 工具（CVE/KEV/CWE、ATLAS、D3FEND、Sigma 检测规则、邮箱安全姿态、域名、IP、IOC、代码安全、网站情报等），响应结构与服务端完全一致，并提供与 v1.22.2+ 错误信封对应的类型化异常层级。v1.23.0 新增 MCP 资源（ATLAS+D3FEND+CWE 目录浏览，详见 [docs/resources.md](docs/resources.md)）和条件式分诊 Prompt（详见 [docs/PROMPTS.md#contrast-triage-v1230](docs/PROMPTS.md)）。v1.25.0 新增 5 个网站情报工具（`robots_txt`、`redirect_chain`、`email_verify`、`brand_assets`、`seo_audit`），并明确声明伦理底线（按目标 eTLD+1 限速、遵守 robots.txt、不进行 SMTP 探测）。

## 立即试用

```bash
curl https://api.contrastcyber.com/v1/cve/CVE-2021-44228
curl https://api.contrastcyber.com/v1/cve/CVE-2021-44228/risk_score   # 综合风险评分（CVSS+EPSS+KEV+PoC）
curl 'https://api.contrastcyber.com/v1/cvss/details?vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
curl https://api.contrastcyber.com/v1/atlas/AML.T0051            # MITRE ATLAS — LLM 提示注入
curl https://api.contrastcyber.com/v1/d3fend/attack/T1059        # D3FEND 针对 ATT&CK T1059 的防御技术
```

或者直接问智能体：

- *"为 CVE-2021-44228 计算综合风险评分 — 融合 CVSS、EPSS、KEV 和 PoC。"*
- *"CVE-2024-3094 是否已被野外利用？查 EPSS 和 KEV，然后查它对应的 CWE 弱点类别。"*
- *"在 MITRE ATLAS 中解释 LLM 提示注入，并桥接到对应的 D3FEND 防御技术。"*
- *"在这些 ATT&CK 技术中 [T1059, T1190, T1550.001, T9999]，哪些没有 D3FEND 缓解？"*

## 文档

**接口列表：** [docs/ENDPOINTS.md](docs/ENDPOINTS.md) · **OpenAPI：** [openapi.json](https://api.contrastcyber.com/openapi.json) · **Playground：** [/playground](https://api.contrastcyber.com/playground)

<details>
<summary>自部署 / 测试 / 技术栈</summary>

```bash
git clone https://github.com/UPinar/contrastapi.git
cd contrastapi && python3 -m venv venv && venv/bin/pip install -r requirements.txt
cd app && ../venv/bin/uvicorn main:app --port 8002
cd app && python -m pytest tests/ -q  # 1886 个测试
```

Python 3.12 · FastAPI · uvicorn · `mcp-python-sdk` Streamable HTTP 挂载于 `/mcp` · SQLite WAL · dnspython + SSRF 安全后端。

</details>

<details>
<summary>其他平台</summary>

[Smithery](https://smithery.ai/servers/contrastcyber/contrastapi) · [npm](https://www.npmjs.com/package/contrastapi) · [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=ContrastAPI.contrastapi) · [Awesome OSINT MCP](https://github.com/soxoj/awesome-osint-mcp-servers) · [RapidAPI](https://rapidapi.com/UPinar/api/contrastapi)

</details>

<details>
<summary>多智能体可证伪元数据</summary>

响应包含 `verdict` 块 — `deterministic`（确定性）、`falsifiable_fields`（可证伪字段）、`data_age_seconds`（数据陈旧度）、`sources_queried` / `sources_unavailable`（已查询/不可用的上游源）、`completeness`（完整性）— 验证智能体可独立从上游权威源（NVD、RDAP、CT 日志、URLhaus）重新派生指定字段。探测 `GET /v1/capabilities` 中的 `"verdict_metadata": true`。

CVE 响应还内嵌 `next_calls: list[PivotHint]` — `{tool, input, reason}` 三元组，建议下一个 MCP 工具调用（例如 `kev.in_kev=true` 时建议 `kev_detail`，存在 `cwe_id` 时建议 `cwe_lookup`）。智能体无需手动提示即可串联工作流。

</details>

MIT
