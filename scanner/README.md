# contrastscan

A fast, single-binary security scanner written in C. Runs 7 security checks on any domain and returns a single A-F grade with a 100-point score.

Used by [contrastcyber.com](https://contrastcyber.com) — free security scorecard for any website.

## Features

- **SSL/TLS** (25 pts) — protocol version, cipher strength, certificate validity & chain verification
- **HTTP Security Headers** (30 pts) — CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- **DNS Security** (20 pts) — SPF, DKIM (28 selectors including date-based), DMARC
- **HTTP → HTTPS Redirect** (10 pts) — checks if HTTP automatically redirects to HTTPS
- **Information Disclosure** (5 pts) — Server and X-Powered-By header exposure
- **Cookie Security** (5 pts) — Secure, HttpOnly, SameSite flags on all cookies
- **DNSSEC** (5 pts) — DNS response authenticity via DNSKEY records
- **Single A-F grade** — 100 points max, weighted by importance
- **JSON output** — easy to parse, pipe, or integrate
- **Enterprise detection** — identifies major companies (Google, Facebook, etc.) with a context note

## Build

### Dependencies

```bash
# Debian/Ubuntu
apt install gcc libcurl4-openssl-dev libssl-dev libcjson-dev

# Fedora/RHEL
dnf install gcc libcurl-devel openssl-devel cjson-devel
```

### Compile

```bash
make
```

### Run

```bash
./contrastscan example.com
```

## Output

```json
{
  "domain": "contrastcyber.com",
  "total_score": 100,
  "max_score": 100,
  "grade": "A",
  "headers": {
    "score": 30,
    "max": 30,
    "details": [
      { "header": "content-security-policy", "present": true },
      { "header": "strict-transport-security", "present": true },
      { "header": "x-content-type-options", "present": true },
      { "header": "x-frame-options", "present": true },
      { "header": "referrer-policy", "present": true },
      { "header": "permissions-policy", "present": true }
    ]
  },
  "ssl": {
    "score": 25,
    "max": 25,
    "details": {
      "tls_version": "TLSv1.3",
      "cipher": "TLS_AES_256_GCM_SHA384",
      "cert_valid": true,
      "chain_valid": true,
      "days_remaining": 83
    }
  },
  "dns": {
    "score": 20,
    "max": 20,
    "details": {
      "spf": true,
      "dmarc": true,
      "dkim": true
    }
  },
  "redirect": {
    "score": 10,
    "max": 10,
    "details": { "redirects_to_https": true }
  },
  "disclosure": {
    "score": 5,
    "max": 5,
    "details": {
      "server_exposed": true,
      "server_value": "cloudflare",
      "powered_by_exposed": false
    }
  },
  "cookies": {
    "score": 5,
    "max": 5,
    "details": { "cookies_found": 0 }
  },
  "dnssec": {
    "score": 5,
    "max": 5,
    "details": { "dnssec_enabled": true }
  }
}
```

## Scoring

| Category | Max | What's Checked |
|----------|-----|----------------|
| Security Headers | 30 | 6 headers (5 pts each) |
| SSL/TLS | 25 | TLS version (9), cipher (8), cert validity (8) |
| DNS Security | 20 | SPF (7), DKIM (7), DMARC (6) |
| HTTP Redirect | 10 | HTTP → HTTPS redirect |
| Info Disclosure | 5 | Server / X-Powered-By exposure |
| Cookie Security | 5 | Secure, HttpOnly, SameSite flags |
| DNSSEC | 5 | DNSKEY record presence |
| **Total** | **100** | |

### Grades

| Grade | Score |
|-------|-------|
| A | 90-100 |
| B | 75-89 |
| C | 60-74 |
| D | 40-59 |
| F | 0-39 |

## Tests

```bash
make test              # 159 unit tests (scoring, parsing, CDN detection)
make test-integration  # 53 integration tests (live domain validation)
```

## Libraries

| Library | Purpose |
|---------|---------|
| libcurl | HTTP requests for headers and redirect checking |
| OpenSSL | TLS handshake, cipher negotiation, certificate chain verification |
| libresolv | DNS queries (SPF/DKIM/DMARC/DNSKEY) |
| cJSON | JSON output generation |

## API

contrastscan is the engine behind [contrastcyber.com](https://contrastcyber.com). You can also use the free JSON API:

### Scan a domain

```bash
curl https://contrastcyber.com/api/scan?domain=example.com
```

Returns the full scan result with all 7 modules plus vulnerability findings:

```json
{
  "domain": "example.com",
  "total_score": 85,
  "max_score": 100,
  "grade": "B",
  "headers":    { "score": 25, "max": 30, "details": [...] },
  "ssl":        { "score": 25, "max": 25, "details": { "tls_version": "TLSv1.3", ... } },
  "dns":        { "score": 20, "max": 20, "details": { "spf": true, "dmarc": true, "dkim": true } },
  "redirect":   { "score": 10, "max": 10, "details": { "redirects_to_https": true } },
  "disclosure": { "score": 5,  "max": 5,  "details": { "server_exposed": false, "powered_by_exposed": false } },
  "cookies":    { "score": 5,  "max": 5,  "details": { "cookies_found": 0 } },
  "dnssec":     { "score": 0,  "max": 5,  "details": { "dnssec_enabled": false } },
  "findings": [
    {
      "category": "dnssec",
      "severity": "low",
      "attack_vector": "DNS cache poisoning, DNS spoofing",
      "description": "DNSSEC is not enabled.",
      "remediation": "Enable DNSSEC at your domain registrar.",
      "reference": "https://www.icann.org/..."
    }
  ],
  "findings_count": { "critical": 0, "high": 0, "medium": 0, "low": 1 }
}
```

### Download plain-text report

```bash
curl -O https://contrastcyber.com/report/{scan_id}.txt
```

Returns a human-readable `.txt` report with module breakdown, findings, and remediation steps.

### Other endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/scan?domain=X` | JSON scan result |
| `GET /report/{scan_id}.txt` | Downloadable text report |
| `GET /badge/{domain}.svg` | Dynamic SVG grade badge |
| `GET /result/{scan_id}` | Web result page |
| `GET /stats` | Aggregate scan statistics |

### Rate limits

- **API:** 100 requests/hour per IP
- **Web:** 5 new domains/day, 20 rescans/hour per IP
- **Per domain:** 10 scans/hour (all IPs combined)

No API key needed.

## License

MIT
