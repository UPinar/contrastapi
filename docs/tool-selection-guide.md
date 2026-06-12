# Tool Selection Guide

> 54 MCP tools, 60+ HTTP endpoints. This guide answers "which tool for which question" in 4 decision trees. Skim this once; agents read tool docstrings — humans read this.

---

## "Is this domain / IP / hash bad?"

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

---

## "Tell me about a CVE"

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

---

## "I need to validate / scan something"

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

---

## "AI/ML threat modeling (ATLAS + D3FEND)"

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

---

## Common confusion → quick answers

| You want to... | Use this tool, NOT that one |
|---|---|
| Know if an IP is in AbuseIPDB | `threat_report` (multi-feed). Not `ioc_lookup` (IP-via-auto-detect, but `threat_report` returns richer reputation data). |
| Validate HTTPS cert grade | `ssl_check`. Not `audit_domain` (returns SSL summary inline but no per-cipher detail). |
| Get all subdomains | `subdomain_enum` (CT logs + wordlist). Not `dns_lookup` (single domain DNS only). |
| Test if a password leaked | `password_check` (HIBP k-anonymity, never sends plaintext). Not `ioc_lookup` (no password type). |
| Sort 100 packages by risk | `check_dependencies` first (returns CVE list per package), then sort client-side by EPSS + KEV. Don't loop `cve_lookup` — that's 100 round-trips; use `bulk_cve_lookup` (up to 50 in one call) or batch + filter client-side. |
| Find AI/ML attacks against my LLM | `atlas_technique_search(keyword="prompt injection")`. Not `cve_search` (CVEs are software bugs; AI/ML TTPs are in ATLAS). |
| Get defense for a CVE | `cve_lookup` → read `cwes[]` → `cwe_lookup` (mitigations field) **OR** if the CVE bridges to ATT&CK, use `d3fend_defense_for_attack`. |

---

## Bulk endpoints (when N round-trips become 1)

All bulk endpoints share **one fixed input cap of 50 ids per call** (Pydantic `max_length=50`), **identical for Free and Pro** — there is no tier-dependent batch size. The only per-tier difference is the hourly quota itself (Free 30/hr, Pro 500/hr): every bulk endpoint consumes 1 unit per id, so ids beyond the caller's remaining quota land in `skipped_due_to_rate_limit` rather than the batch being rejected.

| Tool | Max ids/call | Per-id rate-limit consume |
|---|---:|---|
| `bulk_cve_lookup` | 50 | yes (1 unit/CVE) |
| `bulk_ioc_lookup` | 50 | yes (1 unit/indicator) |
| `bulk_atlas_technique_lookup` | 50 | yes (1 unit/technique) — v1.20.0+ |
| `bulk_sigma_rule_lookup` | 50 | yes (1 unit/rule) — v1.32.0+ |

**Empty input → 200 + empty results** on cve/ioc/atlas (v1.21.0+ unified); `bulk_sigma_rule_lookup` requires ≥1 id (empty → 422).

**Per-item status enum** (4-state, unified across all 3 bulk endpoints v1.21.0+):
- `ok` — populated successfully
- `error` — transient lookup failure (timeout / upstream / DB exception)
- `not_found` — id not in catalog (CVE, ATLAS technique); IOC variant rare (treat ≈ ok with empty sources)
- `invalid_format` — input failed regex / type detection / private-IP rejection

---

## Cost cheat sheet

| Tool | Credit cost | Why |
|---|---:|---|
| `audit_domain` | 6 | v1.32.4 Plan A: DNS+WHOIS+SSL+CT+subdom+headers+tech+email+cache (9-11 sources) |
| `threat_report` | 6 | v1.32.4 Plan A: IP enrich+AbuseIPDB+Shodan+ASN+Tor+cloud+FireHOL+CVE (8 sources) |
| `domain_vulns` | 4 | v1.32.4 Plan A: tech_fingerprint + bulk_cve per product |
| `brand_assets`, `seo_audit` | 2 | homepage fetch + robots.txt fetch + parse |
| Most catalog lookups (`cve_lookup`, `cwe_lookup`, `kev_detail`, ATLAS, D3FEND) | 1 | DB read |
| Web-intel singles (`robots_txt`, `redirect_chain`, `email_verify`) | 1 | one fetch + parse |
| Search/listing tools | 1 | DB query |
| `password_check` | 1 | HIBP k-anonymity |

Free tier: 30 credits/hour (no API key). Pro: 500/hr ($15/mo at https://contrastcyber.com/pricing).

---

## v1.25.0 Web Intelligence chains

Five new tools shipped in v1.25.0 share a per-target eTLD+1 throttle (60/min) and a strict ethical floor — robots.txt is honoured (Disallow `/` for our UA → 403 `error.code = robots_txt_disallow`, no fetch), Cache-Control `no-store`/`private` skips our cache write, all target-derived strings are stripped of control chars and flagged `_untrusted`. Common chain patterns:

| Goal | Chain |
|---|---|
| Deobfuscate a phishing-suspect link | `redirect_chain(url)` → final host → `domain_report(host)` → `phishing_check(final_url)` |
| Lead enrichment from email | `email_verify(email)` (replaces `email_mx` + `email_disposable`) → `domain_report(domain)` → `brand_assets(domain)` |
| SEO pre-pitch audit | `seo_audit(domain)` → `missing_signals` map → follow-up with the customer |
| Crawl-courtesy pre-flight | `robots_txt(domain)` BEFORE `seo_audit` / `brand_assets` to honour user-agent rules at the call site (server enforces it anyway, but client-side awareness saves a 403 round-trip) |

---

## When in doubt

- **Read `next_calls`** in any response — it tells the agent what to call next, with the right input value, and why.
- **Check `verdict.sources_queried`** — confirms which upstream feeds actually responded; `verdict.sources_unavailable` flags transient issues so you can retry.
- **Don't loop tool calls when bulk exists** — burns quota for no gain.
- **`include=full` opt-in** for verbose output (CWE, ATLAS search, ATLAS case_study, D3FEND search, D3FEND for_attack) — slim default saves ~30-80% tokens.
- **`exclude_id`** on ATLAS/D3FEND search + D3FEND for_attack — used by `next_calls` to skip self in sibling/reverse-lookup chains.
- **`email_verify` is one call, not three** — combines `email_mx` + `email_disposable` + role/free-provider classification. Use it instead of chaining the older two.

---

**Last updated:** v1.25.0 (2 May 2026).
