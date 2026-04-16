# Example Prompts for AI Agents

Copy-paste these into Claude Desktop, Cursor, VS Code, or any MCP-enabled agent after configuring ContrastAPI ([setup guide](https://api.contrastcyber.com/mcp-setup)).

## Recon & Domain

- *"Run a full security audit on example.com"*
- *"What are the DNS records for example.com?"*
- *"Is the SSL certificate on example.com expiring soon?"*
- *"What technologies does example.com use?"*
- *"Check the security headers on example.com"*
- *"Find all subdomains of example.com"*
- *"Who registered example.com and when does it expire?"*
- *"Does example.com have proper SPF and DMARC records?"*
- *"Show me the Wayback Machine snapshots for example.com"*

## CVE & Exploits

- *"Look up CVE-2024-3094 — is it being exploited in the wild?"*
- *"Find critical Apache vulnerabilities from the last 6 months"*
- *"Show me all CISA KEV entries from the last 30 days"*
- *"Find CVEs with EPSS score above 0.9 — what's most likely to be exploited?"*
- *"Search for critical Linux kernel CVEs, sorted by exploit probability"*
- *"Are there public exploits for CVE-2021-44228?"*
- *"What's the EPSS score for CVE-2023-4863?"*
- *"Check these CVEs in bulk: CVE-2024-3094, CVE-2021-44228, CVE-2023-4863"*
- *"Show me CVEs that were indexed before NVD — what's leading right now?"*

## IP & Network

- *"Is 8.8.8.8 malicious? Pull reputation from AbuseIPDB and Shodan."*
- *"Generate a threat report for 8.8.8.8 — include Shodan, AbuseIPDB, and ASN data"*
- *"What ASN does 1.1.1.1 belong to?"*
- *"Check these IPs in bulk: 8.8.8.8, 1.1.1.1, 9.9.9.9"*

## Threat Intelligence / IOC

- *"Check example.com for known malware URLs"*
- *"Enrich this IOC: 185.220.101.1"*
- *"Check if http://evil-example.test/login is a phishing URL"*
- *"Has this password been exposed in a data breach?"*
- *"Is this file hash known malware? a1b2c3d4e5f6..."*
- *"Bulk check these indicators: 1.2.3.4, evil.com, bad.exe"*

## Code Security

- *"Check this code for hardcoded API keys and secrets"*
- *"Scan this function for SQL injection vulnerabilities"*
- *"Validate these HTTP security headers: Content-Security-Policy, X-Frame-Options"*
- *"Here are my server's response headers — grade them for security misconfigurations"*
- *"Check if these npm dependencies have known CVEs: lodash@4.17.0, axios@0.21.0"*

## Contact Validation / OSINT

- *"Is user@example.com a disposable email?"*
- *"Look up this phone number: +1-555-0123"*
- *"Find accounts for username 'johndoe' across platforms"*
- *"Check the email security grade for example.com (SPF/DMARC/DKIM)"*

## Chained Workflows

Agents can chain tools naturally. Example single-prompt workflows:

- *"Audit example.com, then look up CVEs for every technology detected"*
  → Agent runs `audit_domain` → parses `technologies` array → chains `cve_search` for each
- *"Find all subdomains of example.com, check the SSL on each, and report any expiring in the next 30 days"*
  → Agent runs `subdomain_enum` → loops `ssl_check` → filters by `days_remaining < 30`
- *"Enrich these 20 IPs and tell me which ones are in AbuseIPDB's high-risk bucket"*
  → Agent runs `bulk_ioc_lookup` → filters by `abuse_confidence_score > 75`
- *"Given this dependency list, check each package for known CVEs and sort by EPSS score"*
  → Agent runs `check_dependencies` → chains `cve_lookup` + `epss` → sorts
- *"List leading CVEs and check if any have public exploits"*
  → Agent runs `cve_leading` → loops `exploit_lookup` for each → flags actionable ones

The `summary` field in every response lets the agent reason about results without parsing nested JSON — cuts token usage and improves chaining quality.
