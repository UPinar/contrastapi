# Contributing to ContrastAPI

Thanks for your interest in contributing! ContrastAPI is a security intelligence API with 49 MCP tools and 57+ endpoints.

## Quick Start

```bash
git clone https://github.com/UPinar/contrastapi.git
cd contrastapi
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cd app && python -m pytest tests/ -v
```

Python 3.12+ required.

## Project Structure

```
app/
├── main.py            # FastAPI app, middleware, meta endpoints
├── config.py          # VERSION, rate limits, API keys (env vars)
├── domain/            # DNS, WHOIS, SSL, subdomains, IP, ASN, tech fingerprint
│   ├── routes.py      # Domain intelligence endpoints
│   └── models.py      # Pydantic response models
├── cve/               # CVE lookup, NVD/EPSS/KEV sync
│   ├── routes.py      # CVE intelligence endpoints
│   └── sync.py        # NVD database sync
├── ioc/               # IOC lookup, hash lookup, threat intel, phishing
│   └── routes.py      # Threat intelligence endpoints
├── codesec/           # Secret scanning, injection detection, headers
│   ├── routes.py      # Code security endpoints
│   └── utils.py       # Shared helpers (ReDoS-safe)
├── atlas/             # MITRE ATLAS catalog (AI/ML attack techniques + case studies)
│   ├── routes.py      # ATLAS endpoints
│   └── sync.py        # ATLAS YAML sync
├── d3fend/            # MITRE D3FEND catalog (defense techniques mapped to ATT&CK)
│   ├── routes.py      # D3FEND endpoints
│   └── sync.py        # D3FEND mappings sync
├── mcp/               # MCP server (49 tools)
│   └── server.py      # Tool definitions + handlers
├── templates/         # HTML templates (landing, docs, quickstart)
├── static/            # CSS, JS, images
└── tests/             # 1100+ tests, pytest
```

## Adding a New Endpoint

1. **Pick the right module:** `domain/` for recon, `cve/` for vulnerability data, `ioc/` for threat intel, `codesec/` for code analysis
2. **Add the route** in the module's `routes.py`
3. **Add Pydantic models** in `models.py` for request/response validation
4. **Add the MCP tool** in `app/mcp/server.py` — every API endpoint should have a matching MCP tool
5. **Write tests** — aim for happy path + error cases + edge cases
6. **Run the full suite:** `cd app && python -m pytest tests/ -v`

### Endpoint Checklist

- [ ] Route with `operation_id` and proper `tags`
- [ ] Pydantic response model with `response_model_exclude_none=True`
- [ ] Input validation (domain format, CVE format, IP format)
- [ ] SSRF protection — use `_SSRFSafeBackend` for any outbound HTTP
- [ ] Rate limit aware — external API calls should be cached
- [ ] Matching MCP tool in `mcp/server.py`
- [ ] Tests (minimum 3: success, invalid input, upstream error)
- [ ] Added to README.md endpoints table

### Example: Adding a New Lookup Endpoint

```python
# In the appropriate routes.py
@router.get(
    "/newlookup/{target}",
    operation_id="new_lookup",
    response_model=NewLookupResponse,
    response_model_exclude_none=True,
)
async def new_lookup(target: str, request: Request):
    # 1. Validate input
    # 2. Check cache
    # 3. Call upstream API (with SSRF protection)
    # 4. Parse and return structured response
    ...
```

## Code Style

- **Formatter:** `ruff format`
- **Linter:** `ruff check`
- **No unused imports** — ruff enforces this
- **Type hints** on all function signatures
- **Pydantic models** for all API responses — no raw dicts

## Testing

```bash
cd app && python -m pytest tests/ -v          # full suite
cd app && python -m pytest tests/ -x -q       # stop on first failure
cd app && python -m pytest tests/test_cve.py  # single module
```

All tests must pass before submitting a PR. No mocking of external APIs in integration tests.

## Security

- Never commit API keys or secrets — use environment variables
- All outbound HTTP must go through `_SSRFSafeBackend` (validates DNS-resolved IPs)
- Input validation on all user-facing parameters
- `is_comment()` and `safe_line()` in `codesec/utils.py` are ReDoS-protected

If you find a security vulnerability, please email instead of opening a public issue.

## Bug Reports & Issues

Found a bug? An endpoint returning wrong data? Open an issue on [GitHub Issues](https://github.com/UPinar/contrastapi/issues).

**Good bug report includes:**
- Which endpoint / MCP tool
- Input you sent
- What you expected vs what you got
- Error message (if any)

Feature requests, questions, and endpoint suggestions are also welcome as issues.

## Pull Requests

- One feature per PR
- Descriptive commit message: what changed + why
- Tests must pass
- Run `ruff check . && ruff format --check .` before submitting
- **Code review required** — all PRs need at least one approved review before merging
- Address all review comments before requesting re-review

## Ideas for Contributions

### New Endpoints
- `breach_check` — Check if email/domain appears in known breaches
- `noise_check` — GreyNoise integration for IP noise/RIOT classification
- `urlscan` — URL scanning via urlscan.io
- `osint_lookup` — Aggregated OSINT from multiple sources

### Improvements
- Response caching improvements
- Better error messages for upstream API failures
- Additional MCP tool parameter descriptions for AI agents
- Documentation and examples

## License

MIT — see [LICENSE](LICENSE).
