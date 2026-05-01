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
- *"Pull the CISA KEV record for CVE-2021-44228 — what's the federal patch deadline and required action?"*
- *"Look up CWE-79 — describe the weakness, list common mitigations, and tell me how many CVEs are mapped to it"*

## IP & Network

- *"Is 8.8.8.8 malicious? Pull reputation from AbuseIPDB and Shodan."*
- *"Generate a threat report for 8.8.8.8 — include Shodan, AbuseIPDB, and ASN data"*
- *"What ASN does 1.1.1.1 belong to?"*
- *"Check these IPs in bulk: 8.8.8.8, 1.1.1.1, 9.9.9.9"*
- *"Triage 45.33.32.156 — list any CRITICAL or HIGH severity vulns with CVSS scores; skip UNKNOWN unless that's all there is"*
- *"Look up this IP and tell me if it's a Tor exit, a known cloud provider, or hosting any actively-exploited CVEs"*

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

## MITRE ATLAS (AI/ML attacks)

- *"What is AML.T0051? Explain LLM Prompt Injection in MITRE ATLAS"*
- *"Find ATLAS techniques about training data poisoning"*
- *"Search ATLAS for techniques targeting LLM agents and AI tools"*
- *"List demonstrated AI/ML attacks (maturity=demonstrated) related to model evasion"*
- *"Show me real-world ATLAS case studies of deep learning evasion"*
- *"Look up case study AML.CS0000 and walk me through the attack chain"*

## MITRE D3FEND (defense techniques)

- *"What D3FEND defenses mitigate ATT&CK T1059 (Command and Scripting Interpreter)?"*
- *"Look up D3FEND TokenBinding — what does it harden, and which ATT&CK T-codes does it cover?"*
- *"Find D3FEND defenses that target Access Tokens"*
- *"Search D3FEND for Detect-tactic defenses against file-based attacks"*
- *"For these ATT&CK techniques, tell me which have NO D3FEND mapping: T1059, T1190, T1550.001, T9999"*
- *"Audit D3FEND coverage across this campaign's TTPs and flag the gaps"*

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
- *"Pivot from a CVE: pull CWE category, CISA KEV deadline, and any public exploits"*
  → Agent runs `cve_lookup` → reads `next_calls` → chains `cwe_lookup` (weakness pattern) + `kev_detail` (federal deadline) + `exploit_lookup` (PoC availability)
- *"Triage this IP for SOC: enrich it, then deep-dive any CRITICAL/HIGH vulns"*
  → Agent runs `ip_lookup` → filters `vulns[]` where `severity in ('CRITICAL','HIGH')` → chains `cve_lookup` for each → optionally `kev_detail` if `kev.in_kev=true`
- *"Bridge an AI/ML technique to the defense: look up an ATLAS technique with an ATT&CK reference, then list mitigating D3FEND defenses"*
  → Agent runs `atlas_technique_lookup` → reads `attack_reference_id` → chains `d3fend_defense_for_attack` → optionally `cve_search` for known exploits of that ATT&CK TTP
- *"Pull the 'Evasion of Deep Learning Detector' ATLAS case study and drill into every technique it used"*
  → Agent runs `atlas_case_study_lookup` → reads `techniques_used` (often 5-10 ids) → chains `bulk_atlas_technique_lookup` with the full list (one call instead of N) → for each technique with `attack_reference_id` set, chains `d3fend_defense_for_attack` for mitigations
- *"Red-team an LLM serving stack: list the AI/ML attack surface for prompt injection, find sibling techniques in the same tactic, and surface defenses"*
  → Agent runs `atlas_technique_lookup(AML.T0051)` → reads `next_calls` → chains `atlas_technique_search(tactic=AML.TA0005, exclude_id=AML.T0051)` for siblings → for each sibling with an ATT&CK bridge, chains `d3fend_defense_for_attack(exclude_id=...)` so the same defense is not echoed back

The `summary` field in every response lets the agent reason about results without parsing nested JSON — cuts token usage and improves chaining quality.

The `next_calls` field in most responses surfaces conditional pivot hints (e.g. "chain `kev_detail` because kev.in_kev=true") so agents don't have to guess the next step.

## /contrast-triage (v1.23.0)

The `contrast_triage` Prompt is a slash-command shortcut that picks a tool chain by perspective (red / blue) and auto-detects the target type (CVE / ATLAS / ATT&CK / CWE / hash / IP / domain). Use it to skip the planning step on common triage workflows.

- `/contrast-triage 8.8.8.8 blue` — defensive IP triage (threat_report → ioc_lookup → ip_lookup)
- `/contrast-triage example.com red` — offensive domain recon (subdomain_enum → domain_report → tech_fingerprint → ssl_check → wayback_lookup)
- `/contrast-triage CVE-2021-44228 red` — exploit-availability check (cve_lookup → exploit_lookup → kev_detail → cve_search)
- `/contrast-triage CVE-2021-44228 blue` — patch-urgency triage (cve_lookup → kev_detail → cwe_lookup → d3fend_defense_for_attack)
- `/contrast-triage AML.T0051 red` — ATLAS technique recon (atlas_technique_lookup → atlas_case_study_search → cve_search)
- `/contrast-triage AML.T0051 blue` — ATLAS defensive mapping (atlas_technique_lookup → d3fend_defense_for_attack → d3fend_attack_coverage)
- `/contrast-triage T1059 blue` — ATT&CK defensive playbook (d3fend_defense_for_attack → d3fend_attack_coverage)
- `/contrast-triage CWE-79 blue` — weakness-class hardening (cwe_lookup → cve_search → d3fend_defense_search)
- `/contrast-triage 44d88612fea8a8f36de82e1278abb02f red` — malware hash drill (hash_lookup → ioc_lookup → threat_intel)

`perspective` defaults to `blue` — invoke without a value when you want defensive triage.

## MCP Resources (v1.23.0)

Agents that support `resources/read` can browse ATLAS / D3FEND / CWE catalogs without burning a tool slot:

- `atlas://catalog` — all 167 techniques (id+name+tactics) + 57 case studies (id+name)
- `atlas://technique/{id}` — full record for one technique (e.g. `atlas://technique/AML.T0051`)
- `atlas://case-study/{id}` — full case study (e.g. `atlas://case-study/AML.CS0000`)
- `d3fend://catalog` — 149 defenses (id+label+tactic+artifact)
- `d3fend://defense/{id}` — full record (e.g. `d3fend://defense/TokenBinding`)
- `cwe://catalog` — slim listing of all CWEs (id+name+abstract_type)
- `cwe://weakness/{id}` — full record (e.g. `cwe://weakness/CWE-79` or `cwe://weakness/79`)

Catalog reads are local DB lookups — no rate limit, no upstream API call. Use them for browse-style queries and reach for the tools (`atlas_technique_search`, `d3fend_defense_search`, etc.) when you need filtering / pivots.
