# ContrastAPI

ContrastAPI serves security data and monitoring to AI agents and to people. It answers as
a REST API and as an MCP server. Every endpoint works without an API key, within a free
hourly credit budget, except monitoring and the saving of your own vendor keys, which need
a Pro API key.
Ask about a CVE, a package version, a domain or an IP address, and get an answer built
from public sources such as NVD, CISA KEV, FIRST EPSS, OSV and MITRE. Put CVEs, packages,
domains and IP addresses on a watchlist, and read the changes to them as events.

This repository holds the server. It is written in C and reads its data from PostgreSQL.

Live service: [api.contrastcyber.com](https://api.contrastcyber.com)

## When to use

Each row names the MCP tool. The REST endpoint has the same name.

| You want to | Use |
|---|---|
| Read one CVE: CVSS, EPSS, CISA KEV, CWE, affected products and a risk score | `cve_lookup`, `cve_lookup_bulk`, `cve_products`, `cve_risk_score` |
| Read a CISA KEV entry or a CWE weakness | `kev_lookup`, `cwe_lookup` |
| Decode and score a CVSS v3 vector | `cvss_calculator` |
| See whether a CVE has public exploits or a Metasploit module | `cve_exploit` |
| Rank the CVEs of a vendor or product by risk | `cpe_search` for the name, then `cve_triage`, `cve_triage_bulk` or `product_exposure` |
| Find CVEs by severity, CWE, EPSS, KEV or date | `cve_search`, `cve_leading` |
| Check a dependency version for advisories and malicious packages | `package_check`, `package_check_bulk` (npm, PyPI, Maven, Go, NuGet, RubyGems, crates.io, Packagist, SwiftURL) |
| Check a domain: DNS, mail auth (SPF, DKIM, DMARC), TLS, security headers, WHOIS | `dns_lookup`, `email_auth_check`, `ssl_check`, `headers_check`, `whois_lookup` |
| Check an email address: does its domain take mail, is it disposable | `email_address_check` |
| List the Wayback Machine captures of a host name | `wayback_lookup` |
| Find subdomains, or a subdomain open to takeover | `subdomain_enum`, `cert_search`, `dns_takeover_check` |
| Look up an IP address or an ASN | `ip_lookup`, `asn_lookup` |
| Find the D3FEND defenses for an ATT&CK technique | `d3fend_for_attack` |
| Check a Windows driver against LOLDrivers | `driver_lookup`, `driver_lookup_bulk` |
| Check whether a password hash is in a breach list | `password_check` (it takes the SHA-1, never the password) |
| Get told when a CVE, package, domain or IP you watch changes | `watchlist_edit`, `watchlist_events` (Pro API key) |
| Read the metadata of an image file | `POST /image_inspect` (REST only, not an MCP tool) |
| Save your own Shodan and AbuseIPDB keys for `ip_lookup` | `vendor_key_edit` (Pro API key) |
| Check the server and its data feeds, or what it keeps about you | `health`, `privacy_my_data` |

When not to use it:

- It does not scan a target for vulnerabilities or run exploits. It reports what public
  sources say, and what a domain's own DNS, TLS and HTTP answers show.
- It serves no exploit code. `cve_exploit` lists references to it.
- An answer is as fresh as its source's last sync, not live. `/health` shows when each
  feed was last updated.

## Documentation

- [API documentation](docs/API_Documentation.md): every REST endpoint, its parameters,
  its answer and its errors, and the credit cost of each call.
- [MCP documentation](docs/MCP_Documentation.md): the MCP tools, the protocol versions the
  server speaks, and how to connect a client.
- [contrastapi-clients](https://github.com/UPinar/contrastapi-clients): the SDKs for Python
  and Node, the Claude Desktop extension and the VS Code extension, under the MIT license.

## Where the data comes from

The sources and their licenses are listed in
[Data sources and licenses](docs/API_Documentation.md#data-sources-and-licenses).

## Contributing

Bug reports and pull requests are welcome. Read [CONTRIBUTING.md](.github/CONTRIBUTING.md) first.
A pull request needs a signed [Contributor License Agreement](.github/CLA.md). Report a security
problem as [SECURITY.md](.github/SECURITY.md) describes, not in a public issue.

## License

The server is licensed under the [GNU Affero General Public License v3.0](LICENSE).
If you run a changed copy as a network service, the AGPL asks you to offer its source
to the users of that service.

Code, word lists and fonts by other authors keep their own licenses. [NOTICE](NOTICE)
lists them.
