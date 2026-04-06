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

**安全情报 API 和 AI 智能体 MCP 服务器。** 29 个工具 / 35+ 个端点：CVE 查询（含 EPSS/KEV 增强）、域名侦察、SSL 分析、IP 信誉（AbuseIPDB、Shodan）、IOC/恶意软件查询、漏洞利用搜索、技术指纹识别、电子邮件安全、电话号码验证和代码安全扫描。免费使用，无需 API 密钥。

**在线服务：** [api.contrastcyber.com](https://api.contrastcyber.com) | **快速入门：** [API](https://api.contrastcyber.com/quickstart) · [MCP](https://api.contrastcyber.com/mcp-setup) | **文档：** [接口列表](#接口列表) | **扫描器：** [contrastcyber.com](https://contrastcyber.com)

---

[English](README.md) | **中文**

---

## 与 AI 智能体配合使用

支持 Claude Desktop、Cursor、VS Code、Windsurf 等工具：**[MCP 配置指南](https://api.contrastcyber.com/mcp-setup)**

也支持 **DeepSeek**、**Qwen（通义千问）** 等支持 MCP 协议的中国 AI 模型。

配置完成后，直接向 AI 提问：

**侦察与域名**
- *"对 example.com 进行全面安全审计"*
- *"example.com 的 DNS 记录有哪些？"*
- *"example.com 的 SSL 证书是否即将过期？"*
- *"example.com 使用了哪些技术？"*
- *"检查 example.com 的安全响应头"*
- *"枚举 example.com 的所有子域名"*
- *"example.com 的注册信息和到期时间？"*
- *"example.com 是否正确配置了 SPF 和 DMARC？"*

**CVE 与漏洞利用**
- *"查询 CVE-2024-3094 — 是否正在被利用？"*
- *"查找过去 6 个月内 Apache 的严重漏洞"*
- *"CVE-2021-44228 是否有公开的漏洞利用？"*

**IP 与网络**
- *"8.8.8.8 是否为恶意 IP？检查其信誉"*
- *"1.1.1.1 属于哪个 ASN？"*

**威胁情报**
- *"检查 example.com 是否存在已知恶意 URL"*
- *"查询此 IOC 的情报：185.220.101.1"*
- *"检查 http://evil-example.test/login 是否为钓鱼网站"*
- *"此密码是否在数据泄露中出现过？"*
- *"此文件哈希是否为已知恶意软件？a1b2c3d4..."*

**代码安全**
- *"检查代码中是否有硬编码的 API 密钥和凭证"*
- *"扫描此函数是否存在 SQL 注入漏洞"*
- *"验证这些 HTTP 安全响应头：Content-Security-Policy、X-Frame-Options"*

**联系方式验证**
- *"user@example.com 是否为一次性邮箱？"*
- *"查询此电话号码：+86-138-0000-0000"*

## 快速入门

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

使用 API 密钥（Pro 版）：`const api = require("contrastapi")({ apiKey: "your-key" });`

完整 SDK 文档：[sdk/node/](sdk/node/)

### Python

```python
import httpx

resp = httpx.get("https://api.contrastcyber.com/v1/domain/example.com")
print(resp.json())
```

### cURL

```bash
curl https://api.contrastcyber.com/v1/domain/example.com
```

更多示例：**[API 快速入门](https://api.contrastcyber.com/quickstart)**（cURL、Node.js、Python、CI/CD）

## 为什么选择 ContrastAPI？

- **一次调用，全面报告** — 域名报告包含 DNS + WHOIS + SSL + 子域名 + WAF + IP 信誉
- **CVE 情报** — 34 万+ CVE 漏洞，含 EPSS 利用概率和 CISA KEV 状态
- **IP 信誉查询** — AbuseIPDB、Shodan 数据增强，24 小时缓存
- **技术指纹识别** — 通过 HTTP 头和 HTML 检测 CMS、框架、CDN、分析工具
- **AI 原生设计** — LLM 优化摘要、结构化 JSON、OpenAPI 规范
- **永久免费** — 100 次请求/小时，无需 API 密钥，无需注册

## 接口列表

### 域名情报

```
GET  /v1/domain/{domain}       完整域名报告（DNS + WHOIS + SSL + 子域名 + WAF + 信誉）
GET  /v1/dns/{domain}          DNS 记录（A、AAAA、MX、NS、TXT、CNAME、SOA）
GET  /v1/whois/{domain}        WHOIS 注册信息
GET  /v1/subdomains/{domain}   子域名枚举（DNS 爆破 + CT 日志）
GET  /v1/certs/{domain}        证书透明度日志
GET  /v1/ssl/{domain}          SSL/TLS 分析（密码套件、证书链、A-F 评级）
GET  /v1/ip/{ip}               IP 情报 + 信誉（AbuseIPDB、Shodan）
GET  /v1/asn/{target}          ASN 查询（AS 号或 IP）
GET  /v1/tech/{domain}         技术指纹识别（CMS、框架、CDN、分析工具）
GET  /v1/threat/{domain}       威胁情报（URLhaus 恶意 URL）
GET  /v1/archive/{domain}      网站历史存档（Wayback Machine 快照）
GET  /v1/scan/headers/{domain} HTTP 安全头实时扫描
GET  /v1/monitor/{domain}      轻量级域名健康检查
GET  /v1/domain/{domain}/vulns 技术栈 CVE 扫描
GET  /v1/email/mx/{domain}     邮件服务商检测 + 电子邮件安全评级
GET  /v1/email/disposable/{email} 一次性/临时邮箱检测
POST /v1/domains/bulk          批量域名扫描（免费 10 个，Pro 50 个）
```

### CVE 情报

```
GET /v1/cve/{cve_id}           CVE 详情 + EPSS + KEV
GET /v1/cves?product=&severity= CVE 搜索
GET /v1/cves/recent?hours=24   最新 CVE
GET /v1/cves/kev               CISA 已利用漏洞
GET /v1/epss/{cve_id}          漏洞利用概率
GET /v1/exploit/{cve_id}       公开漏洞利用搜索（GitHub Advisory + Shodan）
```

### 威胁情报

```
GET /v1/ioc/{indicator}        统一 IOC 查询（IP、域名、URL、哈希）
GET /v1/hash/{hash}            恶意软件哈希信誉（MalwareBazaar）
GET /v1/password/{sha1}        密码泄露检查（HIBP，k-匿名）
GET /v1/phishing/{url}         钓鱼/恶意 URL 检查（URLhaus）
GET /v1/phone/{number}         电话号码 OSINT（运营商、类型、国家）
```

### 代码安全

```
POST /v1/check/headers         验证 HTTP 安全头
POST /v1/check/secrets         检测硬编码密钥
POST /v1/check/injection       SQL/命令注入模式检测
POST /v1/check/dependencies    检查依赖包已知 CVE
```

## 速率限制

| 套餐 | 限制 | API 密钥 |
|------|------|----------|
| 免费版 | 100 次请求/小时 | 不需要 |
| Pro 版 | 1,000 次请求/小时 | [获取 API 密钥](https://contrastcyber.com/pricing) |

## 数据来源

| 来源 | 记录数 | 更新频率 |
|------|--------|----------|
| NVD (NIST) | 34 万+ CVE | 每 2 小时 |
| CISA KEV | 1,500+ 已利用漏洞 | 每 2 小时 |
| FIRST EPSS | 32.3 万+ 利用评分 | 每 2 小时 |

## 文档

- **API 快速入门：** https://api.contrastcyber.com/quickstart
- **MCP 配置指南：** https://api.contrastcyber.com/mcp-setup
- **OpenAPI 规范：** https://api.contrastcyber.com/openapi.json
- **LLM 发现：** https://api.contrastcyber.com/llms.txt

## 自行部署

```bash
git clone https://github.com/UPinar/contrastapi.git
cd contrastapi
python3 -m venv venv
venv/bin/pip install -r requirements.txt
cd app
../venv/bin/uvicorn main:app --host 127.0.0.1 --port 8002
```

## 测试

```bash
cd app && PYTHONPATH=. python -m pytest tests/ -v
```

721 个测试，覆盖认证、速率限制、验证、数据库操作、域名情报、CVE 情报、威胁情报、代码安全（ReDoS 防护、并发限制）、技术指纹识别、IP 信誉、电子邮件安全、电话号码验证、MCP 端点和 API 路由。

## 技术栈

- **运行环境：** Python 3.12、FastAPI、uvicorn
- **数据库：** SQLite（WAL 模式，3 个数据库）
- **DNS：** dnspython
- **HTTP：** httpx

## 其他平台

- **Awesome OSINT MCP Servers：** [soxoj/awesome-osint-mcp-servers](https://github.com/soxoj/awesome-osint-mcp-servers)
- **RapidAPI：** [rapidapi.com/UPinar/api/contrastapi](https://rapidapi.com/UPinar/api/contrastapi)
- **Product Hunt：** [contrastapi](https://www.producthunt.com/posts/contrastapi)

## 许可证

MIT
