# ContrastAPI — MCP Dizin Listeleme Materyali (中文)

Bu dosya mcpmarket.com, LobeHub, MCPdb vb. dizinlere submit ederken kullanılacak Çince içerikleri barındırır.

---

## Kısa Açıklama (一句话介绍)

**EN:** Security intelligence MCP server — 25 tools for CVE, domain, IP, threat intel, code security. Free, no API key.

**CN:** 安全情报 MCP 服务器 — 25 个工具，覆盖 CVE 查询、域名侦察、IP 信誉、威胁情报、代码安全。免费，无需 API 密钥。

---

## Detaylı Açıklama (详细描述)

### English

ContrastAPI is a security intelligence MCP server with 25 tools covering CVE lookup (EPSS/KEV enrichment), domain reconnaissance, SSL analysis, IP reputation (AbuseIPDB + Shodan), IOC/malware lookup, exploit search, technology fingerprinting, email security, phone validation, and code security scanning.

- **Free tier:** 100 req/hr, no API key, no signup
- **Transport:** Streamable HTTP (`https://api.contrastcyber.com/mcp/`) + stdio
- **Compatible with:** Claude Desktop, Cursor, VS Code, Windsurf, DeepSeek, Qwen, and any MCP-compatible client
- **Data:** 340K+ CVEs (NVD), 1500+ CISA KEV, 323K+ EPSS scores — synced every 2 hours

### 中文

ContrastAPI 是一个安全情报 MCP 服务器，提供 25 个安全工具，覆盖 CVE 漏洞查询（含 EPSS/KEV 增强）、域名侦察、SSL 分析、IP 信誉查询（AbuseIPDB + Shodan）、IOC/恶意软件查询、漏洞利用搜索、技术指纹识别、电子邮件安全检测、电话号码验证和代码安全扫描。

- **免费使用：** 100 次请求/小时，无需 API 密钥，无需注册
- **传输协议：** Streamable HTTP (`https://api.contrastcyber.com/mcp/`) + stdio
- **兼容：** Claude Desktop、Cursor、VS Code、Windsurf、DeepSeek、通义千问（Qwen）等支持 MCP 的客户端
- **数据：** 34 万+ CVE（NVD）、1500+ CISA KEV、32.3 万+ EPSS 评分 — 每 2 小时同步

---

## 工具列表 (Tool List)

| # | 工具名 | 中文描述 |
|---|--------|----------|
| 1 | `domain_report` | 完整域名报告（DNS + WHOIS + SSL + 子域名 + WAF + 信誉） |
| 2 | `dns_lookup` | DNS 记录查询 |
| 3 | `whois_lookup` | WHOIS 注册信息 |
| 4 | `ssl_check` | SSL/TLS 证书分析和评级 |
| 5 | `subdomain_enum` | 子域名枚举 |
| 6 | `ip_lookup` | IP 情报 + 信誉（AbuseIPDB、Shodan） |
| 7 | `asn_lookup` | ASN 自治系统查询 |
| 8 | `tech_fingerprint` | 技术指纹识别（CMS、框架、CDN） |
| 9 | `scan_headers` | HTTP 安全头实时扫描 |
| 10 | `threat_intel` | URLhaus 威胁情报 |
| 11 | `cve_lookup` | CVE 漏洞详情 + EPSS + KEV |
| 12 | `cve_search` | CVE 搜索（按产品/严重级别） |
| 13 | `exploit_lookup` | 公开漏洞利用搜索 |
| 14 | `ioc_lookup` | 统一 IOC 查询 |
| 15 | `hash_lookup` | 恶意软件哈希信誉 |
| 16 | `password_check` | 密码泄露检查（HIBP） |
| 17 | `phishing_check` | 钓鱼/恶意 URL 检查 |
| 18 | `check_headers` | 验证 HTTP 安全头 |
| 19 | `check_secrets` | 检测硬编码密钥 |
| 20 | `check_injection` | SQL/命令注入检测 |
| 21 | `email_mx` | 邮件服务商检测 + 安全评级 |
| 22 | `email_disposable` | 一次性邮箱检测 |
| 23 | `phone_lookup` | 电话号码 OSINT |
| 24 | `username_lookup` | 用户名 OSINT（16 个平台） |
| 25 | `wayback_lookup` | Wayback Machine 历史快照 |

---

## MCP 配置示例 (Configuration)

### Claude Desktop / Cursor / VS Code

```json
{
  "mcpServers": {
    "contrastapi": {
      "url": "https://api.contrastcyber.com/mcp/"
    }
  }
}
```

### DeepSeek + MCP (如支持)

```json
{
  "mcpServers": {
    "contrastapi": {
      "url": "https://api.contrastcyber.com/mcp/"
    }
  }
}
```

---

## 标签 (Tags)

`security` `cybersecurity` `CVE` `vulnerability` `domain` `SSL` `IP-reputation` `threat-intelligence` `OSINT` `MCP` `AI-agent` `code-security` `free`

---

## 提交链接 (Submit URLs)

- **mcpmarket.com:** https://mcpmarket.com — Submit 按钮
- **LobeHub:** https://github.com/lobehub/lobe-chat-agents — PR to add
- **MCPdb:** https://mcpdb.org — Submit
- **Smithery:** https://smithery.ai — Already listed
- **mcp.so:** https://mcp.so — Already listed

---

## 截图建议 (Screenshots)

1. Landing page (api.contrastcyber.com/cn/)
2. MCP tool list in Claude Desktop
3. Example: domain report JSON response
4. Example: CVE lookup with EPSS enrichment
