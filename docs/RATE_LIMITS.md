# Rate Limits

ContrastAPI applies two independent rate limits. The strictest one wins.

## 1. Hourly quota (app layer)

Sliding 1-hour window per client. Used by the application's `consume_credits()`
backed by a SQLite log of timestamped consumption rows.

| Tier | Limit | Identity |
|---|---|---|
| Free | **100 credits/hour** | client IP (hashed) |
| Pro  | **1,000 credits/hour** | API key |

Most endpoints cost 1 credit; aggregating endpoints cost more (see
[ENDPOINTS.md → Credit Costs](ENDPOINTS.md#credit-costs)).

When the quota is exhausted the response is HTTP 429 with:

```json
{"error": {
  "code": "rate_limit_exceeded",
  "message": "...",
  "retry_after_seconds": <seconds until oldest entry leaves the window>
}}
```

Headers on every authenticated response:

```
X-RateLimit-Cost:      <credits this call cost>
X-RateLimit-Remaining: <credits left in the current window>
Retry-After:           <seconds, on 429 only>
```

## 2. Burst gate (nginx layer)

Front-edge burst control on the request rate **per IP** to absorb traffic
spikes without overloading the app. Implemented with `limit_req` zones.
The gate uses `nodelay` — over-burst requests get HTTP 429 **immediately**,
no queue, no retry-after smoothing.

### Zones

| Zone | Sustained | Key |
|---|---|---|
| `api` | 2 req/s | `$binary_remote_addr` |
| `mcp_get`  | 60 req/min (1/s) | per-session for SSE polling |
| `mcp_post` | 300 req/min (5/s) | per-session for tool calls |

### Per-path burst caps

| Path prefix | Zone | Burst | Notes |
|---|---|---|---|
| `GET  /mcp/` | mcp_get | **30** | SSE polling loops |
| `POST /mcp/` | mcp_post | **100** | tool-call handshake + tool/call |
| `/v1/cve/`   | api | **10** | `cve_lookup`, `cve_leading`, etc. |
| `/v1/check/` | api | **10** | code-security `check_*` endpoints |
| `/v1/domain/`| api | **20** | passive domain recon |
| `/mcp-setup` | api | **20** | onboarding page |
| `/v1/status` | api | **300** | uptime monitors / Smithery health pings |
| `/v1/`       | api | **10** | wildcard for everything else under `/v1/` |
| `/`          | api | **20** | site root and any non-API path |

The `api` zone is **shared across paths** — all `limit_req zone=api` blocks
draw from the same per-IP token bucket. The `burst=N` value at each location
is the maximum instantaneous accept depth at that location, not a private
quota.

### Concrete consequence — 46 concurrent tool calls from one client

Calls hitting `/mcp/` (tool entry) pass easily — `mcp_post burst=100` is
plenty. But MCP tools that fan out to `/v1/cve/*`, `/v1/check/*`,
`/v1/exploit/*`, `/v1/kev/*` (etc.) all draw from the same `api` zone.
With burst=10 on those locations, only the first ~10 over-rate requests
are accepted instantly; everything beyond that returns 429 immediately.

## Best practices for batch / parallel callers

- **Parallel cap of 10 for `/v1/cve/*` and `/v1/check/*`.** Above that,
  expect 429s. The sustained refill is 2 req/s, so a 50-item batch needs
  about 25 seconds of staggered submission, or roughly 5 parallel workers
  with 1 s gaps.
- **For bulk work prefer the bulk endpoints** — `POST /v1/cves/bulk`,
  `POST /v1/iocs/bulk`, `POST /v1/atlas/techniques/bulk`. They cost N
  credits but are a single HTTP request, so the burst gate is hit once.
- **Honour `Retry-After`.** When you see HTTP 429 with the
  `retry_after_seconds` field, sleep at least that long before retrying
  the same endpoint.
- **Don't retry without backoff.** A retry storm against a per-IP zone
  just keeps hitting the same gate. Exponential backoff (e.g. 1 s, 2 s,
  4 s) recovers cleanly.
- **Watch `X-RateLimit-Remaining` proactively.** Once remaining is
  below your concurrency level, slow new requests rather than letting
  them race into 429s.

## Distinguishing the two layers in practice

You can tell which layer rejected a request from the response shape:

- **App layer:** structured JSON `{"error": {"code": "rate_limit_exceeded", "retry_after_seconds": N}}`. The hourly quota is exhausted; wait for it to slide.
- **Nginx burst:** `Retry-After: <seconds>` header on a generic 429 (FastAPI's exception handler may still wrap this into the same JSON envelope, so check `X-RateLimit-Remaining` — if it's still positive, it was a burst rejection, not a quota rejection).
