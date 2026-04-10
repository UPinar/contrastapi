# ContrastAPI Node.js SDK

Official Node.js SDK for [ContrastAPI](https://api.contrastcyber.com) — security intelligence for developers and AI agents.

Zero dependencies. Works with Node.js 14+.

## Install

```bash
npm install contrastapi
```

## Quick Start

```javascript
const ContrastAPI = require("contrastapi");
const api = ContrastAPI();

async function main() {
  // Domain intelligence
  const report = await api.domain.report("example.com");

  // CVE lookup
  const cve = await api.cve.lookup("CVE-2024-3094");

  // SSL certificate check
  const ssl = await api.domain.ssl("example.com");

  // Scan HTTP security headers (live)
  const headers = await api.scan.headers("example.com");

  // Check code for secrets
  const secrets = await api.check.secrets("const key = 'AKIA...'", "javascript");
}

main();
```

## With API Key (Pro)

```javascript
const api = ContrastAPI({ apiKey: "your-api-key" });
```

## All Methods

### Credit Costs

Most endpoints cost 1 credit. Heavy orchestration endpoints cost more:

| Endpoint | Cost |
| --- | --- |
| `domain.audit()` | 4× |
| `ip.threatReport()` | 4× |
| `cve.bulk([...])` | N× (per item) |
| `ioc.bulk([...])` | N× (per item) |

Bulk endpoints: free tier up to 10 items per call, Pro tier up to 50. Free tier: 100 credits/hour. Pro tier: 1000 credits/hour.

### Domain Intelligence
```javascript
api.domain.report("example.com")           // Full domain report
api.domain.report("example.com", {lite: true}) // Fast lite report
api.domain.dns("example.com")              // DNS records
api.domain.whois("example.com")            // WHOIS data
api.domain.subdomains("example.com")       // Subdomain enumeration
api.domain.certs("example.com")            // Certificate transparency
api.domain.ssl("example.com")              // SSL/TLS analysis
api.domain.tech("example.com")             // Technology fingerprint
api.domain.threat("example.com")           // Threat intelligence
api.domain.monitor("example.com")          // Domain monitoring
api.domain.vulns("example.com")            // Known vulnerabilities
api.domain.bulk(["a.com", "b.com"])        // Bulk domain reports
api.domain.audit("example.com")            // Full audit (report + tech + headers) — 4 credits
```

### IP & ASN
```javascript
api.ip.lookup("8.8.8.8")                   // IP intelligence
api.ip.threatReport("8.8.8.8")             // Threat report (AbuseIPDB + Shodan + ASN) — 4 credits
api.asn.lookup("google.com")               // ASN lookup
```

### CVE Intelligence
```javascript
api.cve.lookup("CVE-2024-3094")            // Single CVE
api.cve.search({product: "apache", severity: "critical"})
api.cve.recent()                           // Recently published
api.cve.kev()                              // Known exploited (CISA KEV)
api.cve.epss("CVE-2024-3094")              // EPSS score
api.cve.exploit("CVE-2024-3094")           // Public exploits
api.cve.bulk(["CVE-2024-3094", "CVE-2021-44228"])  // Bulk CVE lookup — N credits
```

### Threat Intelligence
```javascript
api.ioc.lookup("evil.com")                 // IOC enrichment (auto-detect type)
api.ioc.hash("abc123...")                  // Malware hash lookup
api.ioc.phishing("https://evil.com/login") // Phishing check
api.ioc.bulk(["8.8.8.8", "evil.com"])      // Bulk IOC lookup — N credits
```

### Email & Phone
```javascript
api.email.mx("example.com")               // MX + SPF/DMARC/DKIM
api.email.disposable("user@tempmail.com")  // Disposable email check
api.phone.lookup("+1234567890")            // Phone validation
```

### Password
```javascript
api.password.check("5baa61e4...")           // HIBP breach check (SHA1)
```

### Code Security
```javascript
api.check.secrets(code, "python")          // Detect hardcoded secrets
api.check.injection(code, "javascript")    // SQL/command injection
api.check.headers({"Content-Security-Policy": "..."})  // Header validation
api.check.dependencies([{name: "lodash", version: "4.17.0"}])  // CVE check
api.scan.headers("example.com")            // Live header scan
```

### Meta
```javascript
api.status()                               // API health
api.usage()                                // Usage stats (Pro)
```

## Error Handling

```javascript
try {
  const result = await api.cve.lookup("CVE-9999-0000");
} catch (err) {
  console.log(err.status);    // 404
  console.log(err.message);   // "CVE not found"
}
```

## License

MIT
