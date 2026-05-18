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

Bulk endpoints: up to 50 items per call (same cap for Free and Pro). Free tier: 30 credits/hour. Pro tier: 500 credits/hour.

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
api.domain.robots("example.com")           // v1.5.0: robots.txt parser
api.domain.redirect("https://bit.ly/3xyz") // v1.5.0: redirect-chain walker
api.domain.brand("example.com")            // v1.5.0: brand assets (favicon/logo/OG)
api.domain.seo("example.com")              // v1.5.0: SEO audit
```

### IP & ASN
```javascript
api.ip.lookup("8.8.8.8")                   // IP intelligence
api.ip.threatReport("8.8.8.8")             // Threat report (AbuseIPDB + Shodan + ASN) — 4 credits
api.asn.lookup("google.com")               // ASN lookup
```

### CVE Intelligence
```javascript
api.cve.lookup("CVE-2024-3094")            // Single CVE — full record
api.cve.search({product: "apache", severity: "critical"})
api.cve.leading({limit: 50})               // Fresh CVEs from MITRE/GHSA before NVD enrichment
api.cve.kev("CVE-2021-44228")              // CISA KEV detail (404 if not in catalog)
api.cve.exploit("CVE-2024-3094")           // Public exploits + advisories
api.cve.bulk(["CVE-2024-3094", "CVE-2021-44228"])  // Bulk CVE lookup — N credits
```

### CWE (MITRE Weakness Catalog)
```javascript
api.cwe.lookup("CWE-79")                   // CWE detail (description, mitigations, CVE count)
```

### MITRE ATLAS (AI/ML Attack Catalog)
```javascript
api.atlas.technique("AML.T0043")           // ATLAS technique detail
api.atlas.techniqueSearch({keyword: "prompt", tactic: "AML.TA0011", limit: 20})
api.atlas.bulkTechniqueLookup(["AML.T0051", "AML.T0043"])  // v1.4.0: bulk drill
api.atlas.caseStudy("AML.CS0000")          // Case study detail
api.atlas.caseStudySearch({keyword: "GPT", limit: 10})
```

> **v1.4.0 note:** server param renamed from `q` → `keyword`. `q` is still
> accepted as a back-compat alias on `techniqueSearch` and `caseStudySearch`,
> but passing both at once throws. Prefer `keyword`.

### MITRE D3FEND (Defense Technique Catalog)
```javascript
api.d3fend.defense("CertificatePinning")           // Defense technique detail
api.d3fend.defenseSearch({keyword: "encryption", tactic: "Harden", limit: 20})
api.d3fend.defenseForAttack("T1059", {include: "full"})  // v1.4.0: include + exclude_id supported
api.d3fend.coverage(["T1059", "T1078", "T1190"])   // Batch coverage analysis
```

> **v1.4.0 note:** `kind` parameter dropped from `defenseSearch` (server doesn't
> accept it — silently ignored before, removed for clarity). `defenseForAttack`
> now accepts an optional `{ include, exclude_id }` second argument.

### Threat Intelligence
```javascript
api.ioc.lookup("evil.com")                 // IOC enrichment (auto-detect type)
api.ioc.hash("abc123...")                  // Malware hash lookup
api.ioc.phishing("https://evil.com/login") // Phishing check
api.ioc.bulk(["8.8.8.8", "evil.com"])      // Bulk IOC lookup — N credits
```

### Email & Phone & Username
```javascript
api.email.mx("example.com")                // MX + SPF/DMARC/DKIM
api.email.disposable("user@tempmail.com")  // Disposable email check
api.email.securityPosture("example.com")   // v1.5.0: SPF/DMARC/DKIM posture + score
api.email.securityPosture("example.com", {selectors: "s1,s2"}) // custom DKIM selectors
api.email.verify("user@example.com")       // v1.5.0: deliverability / mailbox verify
api.phone.lookup("+1234567890")            // Phone validation
api.username.lookup("octocat")             // v1.4.0: cross-platform username lookup
```

### Password
```javascript
api.password.check("5baa61e4...")          // HIBP breach check (SHA1)
```

### Wayback Archive (v1.4.0)
```javascript
api.domain.wayback("example.com")          // CDX snapshot history
```

### Sigma Detection Rules (v1.5.0)
```javascript
api.sigma.lookup("5013636e-7f4c-...")      // Sigma rule by UUID
api.sigma.bulk(["uuid1", "uuid2"])         // Bulk lookup (≤50 rule IDs)
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

## TypeScript

Full typings ship in `index.d.ts`. As of v1.4.0 every namespace method declares
a concrete return type (e.g. `Promise<CveResponse>` instead of `Promise<any>`),
so IDEs autocomplete on response keys and TypeScript catches typos at compile
time.

```typescript
import ContrastAPI, { CveResponse, AuditResponse } from "contrastapi";

const api = ContrastAPI();
const cve: CveResponse = await api.cve.lookup("CVE-2021-44228");
console.log(cve.kev?.in_kev);   // boolean | undefined
```

## License

MIT
