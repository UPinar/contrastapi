# Rate Limits

ContrastAPI applies a per-IP / per-key hourly quota. Burst spikes are also
absorbed at the edge to protect the service, but the published contract is
the hourly quota.

## Hourly quota

| Tier | Limit | Identity |
|---|---|---|
| Free | **30 credits/hour** | client IP |
| Pro  | **500 credits/hour** | API key |

Most endpoints cost 1 credit; aggregating endpoints (`audit_domain`,
`threat_report`, bulk endpoints) cost more — see
[ENDPOINTS.md → Credit Costs](ENDPOINTS.md#credit-costs).

## 429 response

When the quota is exhausted the response is HTTP 429 with:

```json
{"error": {
  "code": "rate_limit_exceeded",
  "message": "Rate limit exceeded (30/hr). Upgrade to Pro (500/hr): ...",
  "retry_after_seconds": <seconds until oldest entry leaves the window>
}}
```

Headers on every authenticated response:

```
X-RateLimit-Cost:      <credits this call cost>
X-RateLimit-Remaining: <credits left in the current window>
Retry-After:           <seconds, on 429 only>
```

## Best practices

- **Honour `Retry-After`.** When you see 429, sleep at least that long
  before retrying.
- **Don't retry without backoff.** Exponential backoff (1 s, 2 s, 4 s)
  recovers cleanly.
- **Watch `X-RateLimit-Remaining` proactively.** Slow new requests once
  remaining is below your concurrency level.
- **Prefer bulk endpoints for batch work** — `POST /v1/cves/bulk`,
  `POST /v1/iocs/bulk`, `POST /v1/atlas/techniques/bulk`. They cost N
  credits but are a single HTTP request.
- **Edge burst protection exists** — sending dozens of requests per
  second from one IP can also trip a per-IP burst gate independently of
  the hourly quota. Stagger high-concurrency batches; well-behaved
  clients (≤10 parallel) do not hit it.
