# ContrastAPI — MCP Documentation

**MCP endpoint:** `https://api.contrastcyber.com/mcp/` (Streamable HTTP, JSON-RPC 2.0)
**Surface:** 55 tools + 7 Resources + 3 Prompts.
**Auth:** Keyless Free tier — 30 tokens/hour per IP, no API key. Pro — 500 tokens/hour with an `Authorization: Bearer cc_…` (or `X-API-Key: cc_…`) header.
**Setup:** [MCP setup guide](https://api.contrastcyber.com/mcp-setup). REST reference for the same data plane: [API_Documentation.md](API_Documentation.md).

Most tools cost **1 token** per call; composite tools that fan out to multiple upstream sources cost more (see the [cost cheat sheet](#cost-cheat-sheet)). **Resources are free** — they are pure local-DB reads with no token cost, no rate limit, and no auth.

---

## Tool Selection Guide

> 55 MCP tools, 60+ HTTP endpoints. This section answers "which tool for which question" in four decision trees. Agents read tool docstrings — humans read this.

### "Is this domain / IP / hash bad?"

```
type unknown                       → ioc_lookup       (auto-detects IP/domain/hash/URL)
type known: IP                     → threat_report    (IP-focused: AbuseIPDB+Shodan+ASN+FireHOL)
type known: domain                 → threat_intel     (URLhaus single-source, fast)
type known: hash                   → hash_lookup      (MalwareBazaar primary)
need full posture (DNS+SSL+stack)  → audit_domain     (recon + tech fingerprint + live headers, costs 6)
need a security scan + grade       → contrast_scan    (11 active modules + severity findings + A–F grade, costs 6)
need passive recon only            → domain_report    (DNS+WHOIS+SSL+threat status)
```

| Tool | Best for | Skip if you have |
|---|---|---|
| `ioc_lookup` | "I have an indicator but don't know the type" | Already know it's IP → use `threat_report` |
| `threat_intel` | "Quick URLhaus check on a domain" | Need multi-feed correlation → use `ioc_lookup` |
| `threat_report` | "IP investigation with vulns + datacenter detection" | Domain-only target → use `domain_report` |
| `domain_report` | "Passive DNS + WHOIS + SSL summary" | Need live HTTP headers / tech stack → use `audit_domain` |
| `audit_domain` | "Full recon + active checks (live headers + tech)" | Just need DNS/threat status → use `domain_report` (cheaper) |
| `contrast_scan` | "Active security scan: 11 modules, severity findings, A–F grade" | Just want recon/headers → use `audit_domain` / `scan_headers` |
| `hash_lookup` | "Is this MD5/SHA1/SHA256 known malware?" | IOC type unknown → use `ioc_lookup` |

**Rule of thumb:** if you'd ask a SOC analyst "is X malicious?", pass X to `ioc_lookup` first. Drill into a specific tool only when the type is obvious.

### "Tell me about a CVE"

```
single CVE, full context                  → cve_lookup       (CVSS + EPSS + KEV + CWE + sources)
multiple CVEs (1 round-trip, save quota)  → bulk_cve_lookup  (up to 50 IDs)
search by vendor/product/keyword          → cve_search       (filter + cursor pagination)
"what's hot this week / this month"       → cve_leading      (top by EPSS + KEV)
KEV detail: federal patch deadline + remediation → kev_detail
underlying CWE category + mitigations     → cwe_lookup       (MITRE CWE 944-entry catalog)
public exploits / PoC code for this CVE   → exploit_lookup   (Exploit-DB + GitHub PoC)
CVEs affecting a domain's whole tech stack → tech_stack_cve_audit (1 call: fingerprint→CVE→KEV→exploit, cost 10)
```

**Cascading workflow** (the canonical CVE drill-down):

1. `cve_lookup` returns `next_calls` with chain hints
2. If `kev.in_kev=true` → chain `kev_detail` (federal patch deadline)
3. Drill `cwe_lookup` on each `cwes[]` entry (weakness mitigation)
4. If exploit hint surfaces → `exploit_lookup` (PoC availability)

The agent doesn't need to plan this — `next_calls` does.

### "I need to validate / scan something"

```
JSON of HTTP headers (test data)          → check_headers     (validate against best practices)
live URL — fetch headers and grade        → scan_headers      (HTTP fetch + per-header analysis)
SSL/TLS cert validation + grade           → ssl_check         (A-F grade, cert chain, ciphers)
package list (npm/pip/etc) for CVEs       → check_dependencies
source code: detect secrets               → check_secrets     (regex + entropy)
source code: detect injection patterns    → check_injection   (SQLi/XSS/path traversal)
```

**`check_headers` vs `scan_headers`:**
- `check_headers` takes a JSON body of headers you ALREADY HAVE — useful when scoring captured traffic.
- `scan_headers` takes a URL and FETCHES the headers itself — useful for live external assessment.

### "AI/ML threat modeling (ATLAS + D3FEND)"

```
known ATLAS technique id (AML.T####)   → atlas_technique_lookup
search ATLAS by keyword/tactic/maturity → atlas_technique_search
real-world AI/ML incident (AML.CS####) → atlas_case_study_lookup
search incidents                       → atlas_case_study_search
drill many techniques in one call      → bulk_atlas_technique_lookup  ← v1.20.0+

known D3FEND defense slug              → d3fend_defense_lookup        (e.g. TokenBinding)
search defenses by tactic/artifact     → d3fend_defense_search
ATT&CK T-code → defenses that mitigate → d3fend_defense_for_attack    (reverse lookup)
multiple T-codes coverage assessment   → d3fend_attack_coverage       (campaign / threat-model gap analysis)
```

**Bridge pattern** (offensive → defensive):

```
atlas_technique_lookup(AML.T0051) → has attack_reference_id ('T1059')
                                  ↓
d3fend_defense_for_attack(T1059)  → list of mitigating defenses
                                  ↓
d3fend_defense_lookup(top_defense_id) → full record + ATT&CK chain
```

Use `exclude_id=` on search/reverse-lookup endpoints to skip the originating record (avoids self-loops in chained calls).

### Common confusion → quick answers

| You want to... | Use this tool, NOT that one |
|---|---|
| Know if an IP is in AbuseIPDB | `threat_report` (multi-feed). Not `ioc_lookup` (IP-via-auto-detect, but `threat_report` returns richer reputation data). |
| Validate HTTPS cert grade | `ssl_check`. Not `audit_domain` (returns SSL summary inline but no per-cipher detail). |
| Get all subdomains | `subdomain_enum` (CT logs + wordlist). Not `dns_lookup` (single domain DNS only). |
| Test if a password leaked | `password_check` (HIBP k-anonymity, never sends plaintext). Not `ioc_lookup` (no password type). |
| Sort 100 packages by risk | `check_dependencies` first (returns CVE list per package), then sort client-side by EPSS + KEV. Don't loop `cve_lookup` — that's 100 round-trips; use `bulk_cve_lookup` (up to 50 in one call) or batch + filter client-side. |
| Find AI/ML attacks against my LLM | `atlas_technique_search(keyword="prompt injection")`. Not `cve_search` (CVEs are software bugs; AI/ML TTPs are in ATLAS). |
| Get defense for a CVE | `cve_lookup` → read `cwes[]` → `cwe_lookup` (mitigations field) **OR** if the CVE bridges to ATT&CK, use `d3fend_defense_for_attack`. |

### Bulk tools (when N round-trips become 1)

All bulk tools share **one fixed input cap of 50 ids per call** (Pydantic `max_length=50`), **identical for Free and Pro** — there is no tier-dependent batch size. The only per-tier difference is the hourly quota itself (Free 30/hr, Pro 500/hr): every bulk tool consumes 1 token per id, so ids beyond the caller's remaining quota land in `skipped_due_to_rate_limit` rather than the batch being rejected.

| Tool | Max ids/call | Per-id token consume |
|---|---:|---|
| `bulk_cve_lookup` | 50 | yes (1 token/CVE) |
| `bulk_ioc_lookup` | 50 | yes (1 token/indicator) |
| `bulk_atlas_technique_lookup` | 50 | yes (1 token/technique) — v1.20.0+ |
| `bulk_sigma_rule_lookup` | 50 | yes (1 token/rule) — v1.32.0+ |

**Empty input → 200 + empty results** on cve/ioc/atlas (v1.21.0+ unified); `bulk_sigma_rule_lookup` requires ≥1 id (empty → 422).

**Per-item status enum** (4-state, unified across all 3 bulk tools v1.21.0+):
- `ok` — populated successfully
- `error` — transient lookup failure (timeout / upstream / DB exception)
- `not_found` — id not in catalog (CVE, ATLAS technique); IOC variant rare (treat ≈ ok with empty sources)
- `invalid_format` — input failed regex / type detection / private-IP rejection

### Cost cheat sheet

| Tool | Token cost | Why |
|---|---:|---|
| `audit_domain` | 6 | DNS+WHOIS+SSL+CT+subdom+headers+tech+email+cache (9-11 sources) |
| `threat_report` | 6 | IP enrich+AbuseIPDB+Shodan+ASN+Tor+cloud+FireHOL+CVE (8 sources) |
| `tech_stack_cve_audit` (`domain_vulns`) | 10 / 4 | full tech-stack CVE audit (`tech_stack_cve_audit` = 10); `/v1/domain/{domain}/vulns` = 4 (tech_fingerprint + bulk_cve per product) |
| `brand_assets`, `seo_audit` | 2 | homepage fetch + robots.txt fetch + parse |
| `geo_audit` | 1 | homepage + robots.txt + llms.txt fetch + 7-rule GEO scorer |
| Most catalog lookups (`cve_lookup`, `cwe_lookup`, `kev_detail`, ATLAS, D3FEND) | 1 | DB read |
| Web-intel singles (`robots_txt`, `redirect_chain`, `email_verify`) | 1 | one fetch + parse |
| Search/listing tools | 1 | DB query |
| `password_check` | 1 | HIBP k-anonymity |

Free tier: 30 tokens/hour (no API key). Pro: 500/hr ($15/mo at https://api.contrastcyber.com/pricing).

### Web Intelligence chains (v1.25.0)

Five web-intel tools share a per-target eTLD+1 throttle (60/min) and a strict ethical floor — robots.txt is honoured (Disallow `/` for our UA → 403 `error.code = robots_txt_disallow`, no fetch), Cache-Control `no-store`/`private` skips our cache write, all target-derived strings are stripped of control chars and flagged `_untrusted`. Common chain patterns:

| Goal | Chain |
|---|---|
| Deobfuscate a phishing-suspect link | `redirect_chain(url)` → final host → `domain_report(host)` → `phishing_check(final_url)` |
| Lead enrichment from email | `email_verify(email)` (replaces `email_mx` + `email_disposable`) → `domain_report(domain)` → `brand_assets(domain)` |
| SEO pre-pitch audit | `seo_audit(domain)` → `missing_signals` map → follow-up with the customer |
| AI-visibility / GEO readiness | `geo_audit(domain)` → `missing_signals` → fix llms.txt / AI-crawler robots / schema.org / SSR |
| Crawl-courtesy pre-flight | `robots_txt(domain)` BEFORE `seo_audit` / `brand_assets` to honour user-agent rules at the call site (server enforces it anyway, but client-side awareness saves a 403 round-trip) |

### When in doubt

- **Read `next_calls`** in any response — it tells the agent what to call next, with the right input value, and why.
- **Check `verdict.sources_queried`** — confirms which upstream feeds actually responded; `verdict.sources_unavailable` flags transient issues so you can retry.
- **Don't loop tool calls when bulk exists** — burns quota for no gain.
- **`include=full` opt-in** for verbose output (CWE, ATLAS search, ATLAS case_study, D3FEND search, D3FEND for_attack) — slim default saves ~30-80% tokens.
- **`exclude_id`** on ATLAS/D3FEND search + D3FEND for_attack — used by `next_calls` to skip self in sibling/reverse-lookup chains.
- **`email_verify` is one call, not three** — combines `email_mx` + `email_disposable` + role/free-provider classification. Use it instead of chaining the older two.

---

## MCP Resources

ContrastAPI exposes the ATLAS / D3FEND / CWE catalogs as MCP `resources/*` so agents can browse **without spending a tool slot**. Resources are pure local-DB lookups — no token cost, no rate limit, no upstream API, no auth.

### URI map

| URI | Type | Returns |
|---|---|---|
| `atlas://catalog` | static | All ATLAS techniques + case studies (slim summary) |
| `atlas://technique/{technique_id}` | template | Full ATLAS technique record |
| `atlas://case-study/{case_study_id}` | template | Full ATLAS case study |
| `d3fend://catalog` | static | All D3FEND defenses (slim summary) |
| `d3fend://defense/{defense_id}` | template | Full D3FEND defense + ATT&CK mappings |
| `cwe://catalog` | static | All CWE weaknesses (id+name+abstract_type) |
| `cwe://weakness/{cwe_id}` | template | Full CWE record incl. mitigations + examples |

`{technique_id}` accepts ATLAS format `AML.T####` or `AML.T####.###`. `{cwe_id}` accepts `CWE-79` or just `79` (auto-prefixed). All MIME types are `application/json`.

### Why resources, not tools?

- **Resources** — "I know exactly which catalog row I want." Browse-style. Free. No filtering / pivots.
- **Tools** (`atlas_technique_search`, `d3fend_defense_search`, `cwe_lookup`, ...) — "I want to filter / pivot / chain." Carries a token budget but supports parameters and emits `next_calls` pivot hints.

Reach for resources when an agent already has a CWE id or a D3FEND slug from a prior tool call and you want to drill the full record without re-running the search.

### Discovery

```bash
# List static resources (3 catalogs)
curl -X POST https://api.contrastcyber.com/mcp/ \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{}}'

# List URI templates (4 detail-resource templates)
curl -X POST https://api.contrastcyber.com/mcp/ \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"resources/templates/list","params":{}}'
```

### Read

```bash
# Full ATLAS technique
curl -X POST https://api.contrastcyber.com/mcp/ \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"atlas://technique/AML.T0051"}}'

# CWE-79 (bare-number form auto-prefixes)
curl -X POST https://api.contrastcyber.com/mcp/ \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"cwe://weakness/79"}}'

# Full D3FEND catalog (149 defenses, slim)
curl -X POST https://api.contrastcyber.com/mcp/ \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"d3fend://catalog"}}'
```

### Catalog payload shape (slim by design)

The CWE catalog has 944 rows in production; full descriptions blow past most agent context budgets. Catalog responses therefore carry **only** `id + name + key fields` per row. Use the per-id template URI when you need the full record.

```json
// atlas://catalog
{
  "techniques": [{"technique_id": "AML.T0051", "name": "LLM Prompt Injection", "tactics": ["AML.TA0011"], "subtechnique_of": null}, ...],
  "case_studies": [{"case_study_id": "AML.CS0000", "name": "Evasion of Deep Learning Detector"}, ...],
  "totals": {"techniques": 167, "case_studies": 57},
  "truncated": false
}

// d3fend://catalog
{
  "defenses": [{"defense_id": "TokenBinding", "label": "Token Binding", "tactic": "Harden", "artifact": "Token", "parent_label": "Authentication"}, ...],
  "totals": {"defenses": 149},
  "truncated": false
}

// cwe://catalog
{
  "weaknesses": [{"cwe_id": "CWE-79", "name": "Improper Neutralization of Input ...", "abstract_type": "Base"}, ...],
  "totals": {"weaknesses": 944},
  "truncated": false,
  "note": "Slim view (cwe_id + name + abstract_type only). Read cwe://weakness/{id} for description, mitigations, examples."
}
```

The `truncated` boolean is true when the in-memory listing length is below the table count — surfaced honestly so clients fall back to the search tools (`atlas_technique_search`, `d3fend_defense_search`) instead of trusting an incomplete catalog. Today it is always false in production (catalog sizes well within the listing cap); the flag is forward-compatible.

### Errors

A well-formed but unknown id surfaces as a JSON-RPC error response (not a 200-with-empty-body) so agents can branch on it cleanly:

- `atlas://technique/AML.T9999` (well-formed, not in catalog) → JSON-RPC error
- `atlas://technique/not-an-id` (malformed) → JSON-RPC error (validator rejects before DB lookup)
- `cwe://weakness/0` (well-formed, not in catalog) → JSON-RPC error

### Cache strategy

Catalog data ships with the server (synced from upstream on a schedule — ATLAS ~6 months, D3FEND ~yearly, CWE ~weekly). Resources read directly from SQLite on each call; no MCP-layer cache, no TTL. Upstream sync cadence is the only cache.

---

## MCP Prompts

ContrastAPI ships **3 Prompts**: `security_audit`, `vulnerability_check`, and `contrast_triage`. Prompts are slash-command shortcuts that pre-plan a tool chain so agents can skip the planning step on common workflows.

### /contrast-triage

The `contrast_triage` Prompt picks a tool chain by perspective (red / blue) and auto-detects the target type (CVE / ATLAS / ATT&CK / CWE / hash / IP / domain).

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

---

## Example Prompts for AI Agents

Copy-paste these into Claude Desktop, Cursor, VS Code, or any MCP-enabled agent after configuring ContrastAPI ([setup guide](https://api.contrastcyber.com/mcp-setup)).

### Recon & Domain

- *"Run a full security audit on example.com"*
- *"What are the DNS records for example.com?"*
- *"Is the SSL certificate on example.com expiring soon?"*
- *"What technologies does example.com use?"*
- *"Check the security headers on example.com"*
- *"Find all subdomains of example.com"*
- *"Who registered example.com and when does it expire?"*
- *"Does example.com have proper SPF and DMARC records?"*
- *"Show me the Wayback Machine snapshots for example.com"*
- *"Why don't AI assistants recommend example.com? Score its GEO / AI-visibility readiness"*
- *"Is example.com blocking GPTBot or ClaudeBot in robots.txt?"*

### CVE & Exploits

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
- *"Audit example.com's tech stack for known CVEs — fingerprint the technologies, map CVEs per product, flag KEV-listed ones with patch deadlines, and note which have public exploits"*

### IP & Network

- *"Is 8.8.8.8 malicious? Pull reputation from AbuseIPDB and Shodan."*
- *"Generate a threat report for 8.8.8.8 — include Shodan, AbuseIPDB, and ASN data"*
- *"What ASN does 1.1.1.1 belong to?"*
- *"Check these IPs in bulk: 8.8.8.8, 1.1.1.1, 9.9.9.9"*
- *"Triage 45.33.32.156 — list any CRITICAL or HIGH severity vulns with CVSS scores; skip UNKNOWN unless that's all there is"*
- *"Look up this IP and tell me if it's a Tor exit, a known cloud provider, or hosting any actively-exploited CVEs"*

### Threat Intelligence / IOC

- *"Check example.com for known malware URLs"*
- *"Enrich this IOC: 185.220.101.1"*
- *"Check if http://evil-example.test/login is a phishing URL"*
- *"Has this password been exposed in a data breach?"*
- *"Is this file hash known malware? a1b2c3d4e5f6..."*
- *"Bulk check these indicators: 1.2.3.4, evil.com, bad.exe"*

### Code Security

- *"Check this code for hardcoded API keys and secrets"*
- *"Scan this function for SQL injection vulnerabilities"*
- *"Validate these HTTP security headers: Content-Security-Policy, X-Frame-Options"*
- *"Here are my server's response headers — grade them for security misconfigurations"*
- *"Check if these npm dependencies have known CVEs: lodash@4.17.0, axios@0.21.0"*

### Contact Validation / OSINT

- *"Is user@example.com a disposable email?"*
- *"Look up this phone number: +1-555-0123"*
- *"Find accounts for username 'johndoe' across platforms"*
- *"Check the email security grade for example.com (SPF/DMARC/DKIM)"*

### MITRE ATLAS (AI/ML attacks)

- *"What is AML.T0051? Explain LLM Prompt Injection in MITRE ATLAS"*
- *"Find ATLAS techniques about training data poisoning"*
- *"Search ATLAS for techniques targeting LLM agents and AI tools"*
- *"List demonstrated AI/ML attacks (maturity=demonstrated) related to model evasion"*
- *"Show me real-world ATLAS case studies of deep learning evasion"*
- *"Look up case study AML.CS0000 and walk me through the attack chain"*

### MITRE D3FEND (defense techniques)

- *"What D3FEND defenses mitigate ATT&CK T1059 (Command and Scripting Interpreter)?"*
- *"Look up D3FEND TokenBinding — what does it harden, and which ATT&CK T-codes does it cover?"*
- *"Find D3FEND defenses that target Access Tokens"*
- *"Search D3FEND for Detect-tactic defenses against file-based attacks"*
- *"For these ATT&CK techniques, tell me which have NO D3FEND mapping: T1059, T1190, T1550.001, T9999"*
- *"Audit D3FEND coverage across this campaign's TTPs and flag the gaps"*

### Chained Workflows

Agents can chain tools naturally. Example single-prompt workflows:

- *"Audit example.com, then look up CVEs for every technology detected"*
  → Agent runs `audit_domain` → parses `technologies` array → chains `cve_search` for each
- *"Scan example.com for security misconfigurations, then map its attack surface and CVE-audit its tech stack"*
  → Agent runs `contrast_scan` → reads `next_calls` → chains `subdomain_enum` (attack surface) + `tech_fingerprint` → `tech_stack_cve_audit`
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
