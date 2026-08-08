# ContrastAPI Python SDK

Official Python client for [ContrastAPI](https://api.contrastcyber.com) — security intelligence for developers and AI agents.

55 MCP tools / 60+ HTTP endpoints: CVE / EPSS / KEV / CWE, MITRE ATLAS (AI/ML attacks) + bulk drill, MITRE D3FEND defenses, domain audit, IOC + threat intel, OSINT, code-security checks, and more. No API key required for the free tier (30 req/hr).

## Install

```bash
pip install contrastapi
```

Requires Python 3.10+. Depends only on `httpx>=0.25`.

## Quickstart

### Sync

```python
from contrastapi import ContrastAPI
from contrastapi.models import CveResponse, AuditResponse

with ContrastAPI() as client:                    # keyless, free tier
    cve: CveResponse = client.cve.lookup("CVE-2021-44228")
    print(cve["kev"]["in_kev"])                  # True (IDE autocompletes "kev", "epss"...)

    techs = client.atlas.bulk_technique_lookup(["AML.T0051", "AML.T0043"])
    print(techs["successful"])                   # 2

    audit: AuditResponse = client.domain.audit("example.com")
    print(audit["score"])
```

Every response method has a typed return — `client.cve.lookup(...)` returns `CveResponse`, `client.atlas.technique(...)` returns `AtlasTechniqueResponse`, etc. You never need to write the type annotation; IDEs (VSCode/PyCharm) infer it from the method signature and offer autocomplete on response keys. Import from `contrastapi.models` only if you want to annotate explicitly or pass responses across function boundaries.

### Async

```python
import asyncio
from contrastapi import AsyncContrastAPI

async def main():
    async with AsyncContrastAPI(api_key="cc_...") as client:
        defenses = await client.d3fend.defense_for_attack("T1059")
        print(len(defenses["defenses"]))

asyncio.run(main())
```

### Shortcuts (multi-call helpers)

```python
from contrastapi import ContrastAPI, audit_full, enrich_batch, triage_ioc

with ContrastAPI() as client:
    # Auto-route IP/hash/domain to the right enrichment leg
    report = triage_ioc(client, "8.8.8.8")              # ioc + threat_report

    # Audit + subdomains + tech + per-subdomain SSL (capped)
    audit = audit_full(client, "example.com", ssl_subdomains=5)

    # Auto-detect CVE vs IOC and bulk-route
    enriched = enrich_batch(client, ["CVE-2021-44228", "8.8.8.8", "evil.com"])
```

Shortcuts swallow per-leg `ContrastAPIError` so partial failures still return whatever succeeded — see `result["errors"]` for the failure map.

## Authentication

Pass an API key as the first positional argument or as `api_key=`:

```python
client = ContrastAPI("cc_<your-key>")            # 500 req/hr (Pro tier)
```

Get a key at [api.contrastcyber.com/pricing](https://api.contrastcyber.com/pricing).

## Exception model

The SDK maps server error codes (v1.22.2+ wire envelope) to typed exceptions:

| Exception | Status | Server code |
| --- | --- | --- |
| `InvalidArgumentError` | 400, 422 | `invalid_argument` |
| `AuthRequiredError` | 401 | `auth_required` |
| `TierLimitError` | 403 | `tier_limit` |
| `NotFoundError` | 404 | `not_found` |
| `RateLimitError` | 429 | `rate_limit_exceeded` |
| `UpstreamError` | 502 | `upstream_error` |
| `UpstreamTimeoutError` | 504 | `upstream_timeout` |
| `TransportError` | n/a | (network failure, before HTTP) |
| `ContrastAPIError` | * | base / unknown |

Every exception carries the parsed envelope:

```python
from contrastapi import ContrastAPI, RateLimitError

try:
    client.cve.lookup("CVE-2021-44228")
except RateLimitError as exc:
    print(exc.message)                  # "Hourly limit reached"
    print(exc.retry_after_seconds)      # 60 (capped at 3600)
    print(exc.upgrade_url)              # "https://api.contrastcyber.com/pricing"
    print(exc.extras)                   # back-compat top-level fields (tier, limit, ...)
```

## Namespaces

| Namespace | Methods |
| --- | --- |
| `cve` | `lookup`, `search`, `leading`, `kev`, `exploit`, `bulk` |
| `cwe` | `lookup` |
| `ioc` | `lookup`, `hash`, `phishing`, `bulk` |
| `atlas` | `technique`, `technique_search`, `bulk_technique_lookup`, `case_study`, `case_study_search` |
| `d3fend` | `defense`, `defense_search`, `defense_for_attack`, `coverage` |
| `domain` | `report`, `dns`, `whois`, `subdomains`, `certs`, `ssl`, `tech`, `threat`, `monitor`, `vulns`, `audit`, `wayback`, `robots`, `redirect`, `brand`, `seo`, `bulk` |
| `ip` | `lookup`, `threat_report` |
| `asn` | `lookup` |
| `email` | `mx`, `disposable`, `security_posture`, `verify` |
| `phone` | `lookup` |
| `password` | `check` (k-anonymity SHA-1 prefix) |
| `username` | `lookup` |
| `check` | `secrets`, `injection`, `headers`, `dependencies` |
| `scan` | `headers` (live HTTP scan) |
| `sigma` | `lookup` (by UUID), `bulk` (≤50 rule IDs) |

The async client (`AsyncContrastAPI`) exposes the same namespace surface 1:1 — every method is `async def`.

## Parity with the Node SDK

| Surface | Node SDK | Python SDK |
| --- | --- | --- |
| Sync | ✅ (Promise-based) | ✅ (`ContrastAPI`) |
| Async | (Promise model) | ✅ (`AsyncContrastAPI`) |
| Namespace count | 13 | 15 (adds `username`, `sigma`) |
| `bulk_technique_lookup` (ATLAS) | (added in v1.4.0) | ✅ |
| `wayback` archive lookup | (added in v1.4.0) | ✅ |
| Typed errors | `Error` subclasses | full hierarchy with envelope fields |
| Shortcuts | — | ✅ `triage_ioc`, `audit_full`, `enrich_batch` |
| Response models | `Promise<any>` | ✅ `TypedDict` (IDE autocomplete, no runtime cost) |

## Configuration

```python
client = ContrastAPI(
    api_key="cc_...",                  # optional; keyless = free tier
    base_url="https://api.contrastcyber.com",  # override for self-host
    timeout=30.0,                       # seconds; clamped to [1, 120]
    allow_insecure=False,               # set True to allow http:// (dev only)
)
```

The transport hard-caps response bodies at 10 MB, sends a `User-Agent: contrastapi-python/<version>` header, and refuses to send your API key over plaintext HTTP even when `allow_insecure=True`.

## Links

- API docs: https://api.contrastcyber.com/docs
- Pricing & API key: https://api.contrastcyber.com/pricing
- Source: https://github.com/UPinar/contrastapi
- Issues: https://github.com/UPinar/contrastapi/issues

## License

MIT — see [LICENSE](../../LICENSE).
