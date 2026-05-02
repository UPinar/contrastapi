# CLAUDE.md — ContrastAPI

## Project
Security intelligence API. 47 MCP tools, 7 MCP Resources (ATLAS+D3FEND+CWE catalog browsing), 3 MCP Prompts (incl. contrast_triage red/blue conditional), 55+ endpoints: CVE/EPSS/KEV, MITRE CWE catalog, KEV detail, domain recon, IOC/threat intel, OSINT, code security, MITRE ATLAS (AI/ML attack catalog + bulk technique drill), MITRE D3FEND (defense technique catalog mapped to ATT&CK), web intelligence (robots.txt parser, redirect-chain walker, email validation, brand-asset scraper, SEO audit).
Live: api.contrastcyber.com | GitHub: UPinar/contrastapi

## Quick Reference
- **Run tests:** `cd app && python -m pytest tests/ -v`
- **Deploy:** git clone + venv + pip install
- **Server path:** `/opt/contrastapi/`
- **DB:** `/var/lib/contrastapi/api.db`, `cve.db`, `domain_cache.db`
- **CVE sync:** `cd app && python -m cve.sync` (delta) or `--full` (initial)
- **1886 tests, 95% coverage**

## Architecture
- `app/main.py` — FastAPI app, middleware, meta endpoints, lifespan (periodic maintenance)
- `app/cve/` — CVE lookup, NVD/MITRE/GHSA/EPSS/KEV sync
- `app/domain/` — DNS, WHOIS, SSL, subdomains, reputation, tech fingerprint, threat intel, scoring; v1.25.0 web-intel: `robots.py`, `redirect_chain.py`, `email_verify.py`, `brand_assets.py`, `seo_audit.py`
- `app/codesec/` — secrets detection, injection detection, header validation
- `app/codesec/utils.py` — shared is_comment + safe_line (ReDoS protection)
- `app/target_throttle.py` — v1.25.0 per-eTLD+1 throttle (60/min) + daily Telegram alert (>500/day)
- Function index: `FUNCTION_TEST_INDEX.md`

## Key Rules
- VERSION constant in config.py — single source of truth
- EPSS/KEV sync uses targeted UPDATE (update_epss/update_kev), not full read+upsert
- _SSRFSafeBackend (httpcore) validates all DNS-resolved IPs before connecting; IPv4-first fallback
- /v1/domain/ supports ?lite=true for fast subset (~250ms vs 3-10s)
- Cache reads don't write (no DELETE in get_cached_domain/get_cached_ip)
- API keys: env vars in systemd service, never in code
- v1.25.0 web-intel ethics: robots.txt respected (Disallow `/` for our UA → 403); Cache-Control no-store/private skips cache write; Accept-Encoding: identity to defeat gzip-bomb DoS; per-target throttle consumed BEFORE cache lookup so cache-bypass attacks can't burn it
- v1.25.0 fetcher hot-path uses `Accept-Encoding: identity` — httpx's `iter_bytes()` decodes Content-Encoding BEFORE yielding chunks, so byte caps are otherwise ineffective against gzip-bombs (1KB blob → 500MB RAM)
