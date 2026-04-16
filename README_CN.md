# ContrastAPI — 为 AI 智能体打造的 29 个安全工具

<p align="center">
  <img src="app/static/banner.png" alt="ContrastAPI Banner" width="100%">
</p>

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-893_passing-brightgreen.svg)](https://github.com/UPinar/contrastapi/actions)
[![MCP](https://img.shields.io/badge/MCP-29_tools-purple.svg)](https://modelcontextprotocol.io)
[![Smithery](https://img.shields.io/badge/Smithery-96%2F100-orange.svg)](https://smithery.ai/servers/contrastcyber/contrastapi)
[![npm](https://img.shields.io/npm/v/contrastapi.svg)](https://www.npmjs.com/package/contrastapi)
[![VS Code](https://img.shields.io/badge/VS_Code-Marketplace-007ACC.svg)](https://marketplace.visualstudio.com/items?itemName=ContrastAPI.contrastapi)

**安全情报 API 和 AI 智能体 MCP 服务器。** 域名审计、CVE 查询（含 EPSS+KEV）、IP 威胁报告、IOC 增强、技术栈识别，以及其他 23 个工具。**免费使用，无需 API 密钥，每小时 100 信用额度。**

[English](README.md) | **中文** · **在线服务：** [api.contrastcyber.com](https://api.contrastcyber.com)

也支持 **DeepSeek**、**Qwen（通义千问）** 等支持 MCP 协议的中国 AI 模型。

---

## 30 秒快速配置

选择你的集成方式：

### 方式 1：MCP（Claude Desktop / Cursor / VS Code / Windsurf / OpenClaw）

添加到你的 MCP 配置：

    {
      "mcpServers": {
        "contrastapi": {
          "command": "npx",
          "args": ["-y", "mcp-remote", "https://api.contrastcyber.com/mcp/"]
        }
      }
    }

重启你的 AI 智能体。完成。完整配置指南：**[api.contrastcyber.com/mcp-setup](https://api.contrastcyber.com/mcp-setup)**

### 方式 2：Node.js SDK

```bash
npm install contrastapi
```

```javascript
const api = require("contrastapi")();

const audit = await api.domain.audit("example.com");        // 完整审计
const cve   = await api.cve.lookup("CVE-2024-3094");        // EPSS + KEV
const ip    = await api.ip.threatReport("8.8.8.8");         // Shodan + AbuseIPDB + ASN
const bulk  = await api.cve.bulk(["CVE-2021-44228", "CVE-2024-3094"]);
```

零依赖，支持 Node 14+。完整 SDK 文档：[sdk/node/](sdk/node/)

### 方式 3：cURL

```bash
curl https://api.contrastcyber.com/v1/cve/CVE-2024-3094
curl https://api.contrastcyber.com/v1/audit/example.com
curl https://api.contrastcyber.com/v1/threat-report/8.8.8.8
```

更多示例：**[API 快速入门](https://api.contrastcyber.com/quickstart)**（cURL、Node.js、Python、CI/CD）

### 方式 4：VS Code 扩展

从 Marketplace 安装 **[ContrastAPI — Security Intelligence](https://marketplace.visualstudio.com/items?itemName=ContrastAPI.contrastapi)**。29 个命令、侧边栏树状菜单、右键上下文菜单。无需 API 密钥。

---

## 立即试用

配置完成后，向你的 AI 智能体提问：

- *"CVE-2024-3094 是否正在被利用？检查 EPSS + KEV"*
- *"显示 NVD 之前收录的 CVE — 目前有哪些领先漏洞？"*
- *"审计 example.com，然后查找检测到的每项技术的 CVE"*

更多示例提示词：[docs/PROMPTS.md](docs/PROMPTS.md) · [/playground](https://api.contrastcyber.com/playground)（交互式测试工具）

---

## 功能一览

- **30 个 MCP 工具**，覆盖 6 个类别 — 完整列表：**[docs/ENDPOINTS.md](docs/ENDPOINTS.md)**
- **34 万+ CVE** 来自 NVD + MITRE cvelistV5 + GitHub Security Advisories，每 2 小时同步，整合 EPSS 漏洞利用概率 + CISA KEV 状态。`cve_lookup` 返回 `sources`、`first_seen_source`、`first_seen_at` — 智能体可检测 NVD 发布前已收录的 CVE。`cve_search` 支持 `kev`、`epss_min`、`sort` 和 `offset` 分页 — 智能体可筛选活跃利用漏洞、按利用概率排序并翻页浏览大型结果集。
- **加权信用额度** — 简单调用 1 个信用，重度编排调用（audit、threat_report）4 个,批量调用 N 个
- **LLM 优化摘要** — 每个响应都包含 `summary` 字段，智能体无需解析嵌套 JSON 即可推理
- **分发渠道** — [npm SDK](https://www.npmjs.com/package/contrastapi) · [VS Code 扩展](https://marketplace.visualstudio.com/items?itemName=ContrastAPI.contrastapi) · [Smithery MCP](https://smithery.ai/servers/contrastcyber/contrastapi)（96/100 质量评分）· REST API

## 为什么选择 ContrastAPI？

- **一次调用，全貌呈现** — `audit` 接口在单个响应中返回完整报告 + 技术指纹 + 实时响应头
- **机器可读** — 结构化 JSON、LLM 优化摘要、OpenAPI 规范、MCP 优先
- **永久免费** — 每小时 100 信用额度，无需 API 密钥，无需注册，无需信用卡

## 文档与链接

- **API 快速入门：** [api.contrastcyber.com/quickstart](https://api.contrastcyber.com/quickstart)
- **MCP 配置：** [api.contrastcyber.com/mcp-setup](https://api.contrastcyber.com/mcp-setup)
- **完整接口列表：** [docs/ENDPOINTS.md](docs/ENDPOINTS.md)
- **OpenAPI 规范：** [api.contrastcyber.com/openapi.json](https://api.contrastcyber.com/openapi.json)
- **LLM 发现：** [api.contrastcyber.com/llms.txt](https://api.contrastcyber.com/llms.txt)
- **交互式 Playground：** [api.contrastcyber.com/playground](https://api.contrastcyber.com/playground)

<details>
<summary><strong>自托管部署</strong></summary>

```bash
git clone https://github.com/UPinar/contrastapi.git
cd contrastapi
python3 -m venv venv
venv/bin/pip install -r requirements.txt
cd app
../venv/bin/uvicorn main:app --host 127.0.0.1 --port 8002
```

需要 Python 3.12。SQLite 数据库首次运行时自动初始化。完整接口参考请查看 [docs/ENDPOINTS.md](docs/ENDPOINTS.md)。

</details>

<details>
<summary><strong>测试</strong></summary>

```bash
cd app && PYTHONPATH=. python -m pytest tests/ -v
```

**893 个测试**，每 15 分钟执行一次 **36/36 冒烟测试**。覆盖认证、速率限制、验证、数据库操作、域名情报、CVE 情报、威胁情报、代码安全（ReDoS 防护、并发限制）、技术指纹、IP 信誉、邮件安全、电话验证、Web 归档、MCP 端点、批量接口、加权信用系统以及 API 路由。

</details>

<details>
<summary><strong>技术栈与架构</strong></summary>

- **运行时：** Python 3.12、FastAPI、uvicorn（2 workers）
- **MCP：** 官方 `mcp-python-sdk`，Streamable HTTP 传输，挂载为 `/mcp` 子应用
- **域名审计：** 通过 `ThreadPoolExecutor` 并行运行 8+ 项检查（SSL、DNS、WHOIS、SPF/DMARC/DKIM、CT 日志、技术栈识别、安全响应头），配合 1 小时 SQLite 缓存加速热路径响应
- **数据库：** SQLite + WAL 模式（3 个数据库：API 速率限制、CVE 缓存、域名缓存）
- **DNS：** dnspython + `_SSRFSafeBackend`（定制 httpcore 后端，连接前验证所有解析的 IP — 防御 DNS 重绑定）
- **HTTP：** httpx
- **速率限制：** SQLite 滑动窗口，通过 WAL 模式在多 worker 间共享
- **加权信用：** 原子性 `BEGIN IMMEDIATE` 消耗 — 要么整个 N 信用批次适配，要么请求被拒绝

</details>

<details>
<summary><strong>也可通过以下渠道获取</strong></summary>

- **Smithery：** [smithery.ai/servers/contrastcyber/contrastapi](https://smithery.ai/servers/contrastcyber/contrastapi)（96/100 质量评分）
- **npm：** [npmjs.com/package/contrastapi](https://www.npmjs.com/package/contrastapi)
- **VS Code Marketplace：** [ContrastAPI — Security Intelligence](https://marketplace.visualstudio.com/items?itemName=ContrastAPI.contrastapi)
- **Awesome OSINT MCP Servers：** [soxoj/awesome-osint-mcp-servers](https://github.com/soxoj/awesome-osint-mcp-servers)
- **RapidAPI：** [rapidapi.com/UPinar/api/contrastapi](https://rapidapi.com/UPinar/api/contrastapi)

</details>

## 许可证

MIT
