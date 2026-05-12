# Data Source Attribution

ContrastAPI aggregates vulnerability intelligence from the following sources:

| Source | License | Notes |
|--------|---------|-------|
| [NVD (National Vulnerability Database)](https://nvd.nist.gov/) | Public domain | NIST — U.S. government work |
| [GHSA (GitHub Security Advisories)](https://github.com/advisories) | CC-BY-4.0 | |
| [OSV.dev](https://osv.dev/) | Apache-2.0 / various | Upstream advisories carry their own licenses |
| [EPSS](https://www.first.org/epss/) | CC-BY-4.0 | FIRST.org |
| [KEV (CISA Known Exploited Vulnerabilities)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Public domain | CISA — U.S. government work |
| [ExploitDB](https://gitlab.com/exploit-database/exploitdb) | GPL-2.0 | Metadata only (edb_id, author, type, platform, date, source URL). Exploit payloads are **not** stored or redistributed. |
| [SigmaHQ rules](https://github.com/SigmaHQ/sigma) | [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License) | Sigma detection rule corpus served via `/v1/sigma/*` and `sigma_rule_lookup` MCP tool. Rules surfaced as-is with full attribution metadata (`author`, `references`, `rule_id`). |
