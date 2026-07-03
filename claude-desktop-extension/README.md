# ContrastAPI Security Tools — Claude Desktop Extension

55 security tools for Claude, with **no signup and no API key required**. This extension is a thin local bridge to the hosted [ContrastAPI](https://api.contrastcyber.com) MCP server (`https://api.contrastcyber.com/mcp/`).

## What you get

All 55 tools are **read-only** lookups — no writes, no destructive actions — and each carries a human-readable title (e.g. `cve_lookup` → "CVE Lookup").

- **Vulnerability intelligence** — `cve_lookup`, `cve_search`, `cve_leading`, `bulk_cve_lookup`, `kev_detail`, `exploit_lookup`, `get_cvss_details`, `cwe_lookup`, `calculate_risk_score`
- **Threat intelligence** — `ioc_lookup`, `bulk_ioc_lookup`, `hash_lookup`, `ip_lookup`, `threat_intel`, `threat_report`, `phishing_check`
- **Infrastructure & web recon** — `dns_lookup`, `whois_lookup`, `ssl_check`, `subdomain_enum`, `tech_fingerprint`, `scan_headers`, `check_headers`, `redirect_chain`, `wayback_lookup`, `asn_lookup`, `robots_txt`, `seo_audit`, `brand_assets`, `domain_report`, `audit_domain`, `contrast_scan`
- **Email security** — `email_verify`, `email_mx`, `email_disposable`, `email_security_posture`
- **OSINT / identity** — `username_lookup`, `phone_lookup`, `password_check` (HIBP k-anonymity)
- **Code security** — `check_secrets`, `check_injection`, `check_dependencies`, `tech_stack_cve_audit`
- **Detection engineering** — `sigma_rule_lookup`, `bulk_sigma_rule_lookup`, MITRE ATLAS & D3FEND lookups + ATT&CK→D3FEND mapping
- Plus 3 guided Prompts and MCP Resources (ATLAS / D3FEND / CWE catalog browsing).

## Installation

1. Download `contrastapi-<version>.mcpb`.
2. Double-click it (or in Claude Desktop: **Settings → Extensions → Install Extension…**) and confirm.
3. Done — ask Claude e.g. *"Check CVE-2025-1234 and whether it's in KEV"* or *"Audit the security headers and TLS of example.com"*.

## Configuration

No configuration is required. Optionally, set **Pro API key** in the extension settings to raise rate limits (keys look like `cc_…`; see [pricing](https://api.contrastcyber.com)). The key is stored by Claude Desktop as a sensitive value and sent only to `api.contrastcyber.com` as an `X-API-Key` header.

## Rate limits

The free keyless tier is rate-limited per IP and returns a clear message when exhausted. A Pro key raises the limit substantially.

## Privacy Policy

Full policy: **https://api.contrastcyber.com/privacy**

Summary of how this extension handles data:

- **What is sent:** only your tool queries (e.g. a domain, IP, hash, CVE ID you ask about) and, if configured, your API key — over HTTPS to `api.contrastcyber.com`. Nothing else on your machine is read or transmitted.
- **What is stored locally:** nothing is written to disk — no cache, no files. The bridge emits diagnostic lines to stderr (which Claude Desktop captures in its extension log); these never include your API key or the contents of your queries.
- **Service-side handling:** queries are processed to produce the answer; standard operational logs are kept briefly for abuse prevention and are not sold or shared with third parties. Details, retention periods, and contact information are in the policy linked above.
- **Contact:** contact@contrastcyber.com

## Support

- Issues: https://github.com/UPinar/contrastapi/issues
- Email: contact@contrastcyber.com

## License

MIT
