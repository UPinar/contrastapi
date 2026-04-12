# CLAUDE.md — ContrastAPI

## Project
Security intelligence API. 29 MCP tools, 39+ endpoints: CVE/EPSS/KEV, domain recon, IOC/threat intel, OSINT, code security.
Live: api.contrastcyber.com | GitHub: UPinar/contrastapi

## Quick Reference
- **Run tests:** `cd app && python -m pytest tests/ -v`
- **Deploy:** git clone + venv + pip install
- **Server path:** `/opt/contrastapi/`
- **DB:** `/var/lib/contrastapi/api.db`, `cve.db`, `domain_cache.db`
- **CVE sync:** `cd app && python -m cve.sync` (delta) or `--full` (initial)
- **853 tests, 95% coverage**

## Architecture
- `app/main.py` — FastAPI app, middleware, meta endpoints, lifespan (periodic maintenance)
- `app/cve/` — CVE lookup, NVD/EPSS/KEV sync
- `app/domain/` — DNS, WHOIS, SSL, subdomains, reputation, tech fingerprint, threat intel, scoring
- `app/codesec/` — secrets detection, injection detection, header validation
- `app/codesec/utils.py` — shared is_comment + safe_line (ReDoS protection)
- Function index: `FUNCTION_TEST_INDEX.md`

## Key Rules
- VERSION constant in config.py — single source of truth
- EPSS/KEV sync uses targeted UPDATE (update_epss/update_kev), not full read+upsert
- _SSRFSafeBackend (httpcore) validates all DNS-resolved IPs before connecting; IPv4-first fallback
- /v1/domain/ supports ?lite=true for fast subset (~250ms vs 3-10s)
- Cache reads don't write (no DELETE in get_cached_domain/get_cached_ip)
- API keys: env vars in systemd service, never in code
