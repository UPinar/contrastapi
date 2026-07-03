# ContrastAPI — Third-Party Dependencies & Function Reference

All third-party libraries, their functions we use, signatures, and what they do.
**Update this file when adding new library imports.**

---

## Web Framework

### fastapi 0.135.3
ASGI web framework for building APIs.

| Function / Class | Signature | What it does | Used in |
|-----------------|-----------|--------------|---------|
| `FastAPI()` | `FastAPI(title, description, version, lifespan, openapi_url, docs_url)` | Creates the ASGI application | main.py |
| `APIRouter()` | `APIRouter(prefix, tags)` | Groups related routes under a URL prefix | domain/routes.py, cve/routes.py, codesec/routes.py, ioc/routes.py |
| `HTTPException` | `HTTPException(status_code, detail)` | Raises HTTP error response with JSON detail | auth.py, all routes |
| `Request` | `request.headers`, `request.url.path`, `request.state`, `request.client.host` | Access request data (headers, path, client IP) | auth.py, all routes |
| `Query()` | `Query(default, ge, le, description)` | Declares query parameter with validation | cve/routes.py |
| `HTMLResponse` | `HTMLResponse(content, status_code)` | Returns HTML content type | main.py |
| `JSONResponse` | `JSONResponse(status_code, content)` | Returns JSON with custom status code | main.py |
| `StaticFiles` | `StaticFiles(directory)` | Serves static files (CSS/JS/images) | main.py |

### starlette 1.0.0
ASGI toolkit — FastAPI's foundation.

| Function / Class | Signature | What it does | Used in |
|-----------------|-----------|--------------|---------|
| `StarletteHTTPException` | `from starlette.exceptions import HTTPException` | Base exception class — used for 404/405 error handler registration | main.py |

### jinja2 3.1.6
HTML template engine.

| Function / Class | Signature | What it does | Used in |
|-----------------|-----------|--------------|---------|
| `Jinja2Templates` | `Jinja2Templates(directory="templates")` | Loads and renders HTML templates | main.py |
| `.TemplateResponse()` | `templates.TemplateResponse(request, "index.html", context)` | Returns rendered HTML template as response | main.py |

### pydantic 2.12.5
Data validation and serialization.

| Function / Class | Signature | What it does | Used in |
|-----------------|-----------|--------------|---------|
| `BaseModel` | `class MyModel(BaseModel): field: type = default` | Defines response/request schema with validation | schemas.py, codesec/routes.py |
| `Field()` | `Field(default, description, examples)` | Adds metadata and validation to model fields | schemas.py |

---

## HTTP / Network

### httpx 0.28.1
Sync and async HTTP client with connection pooling.

| Function / Class | Signature | What it does | Used in |
|-----------------|-----------|--------------|---------|
| `httpx.Client()` | `httpx.Client(timeout, headers, follow_redirects, transport)` | Creates sync HTTP client with connection pool | recon.py, reputation.py, threat.py, cve/routes.py, ioc/routes.py |
| `httpx.AsyncClient()` | `httpx.AsyncClient(timeout, headers)` | Creates async HTTP client | mcp_server.py |
| `client.get()` | `client.get(url, params, headers) -> Response` | HTTP GET request | recon.py, reputation.py, all routes |
| `client.post()` | `client.post(url, json, headers) -> Response` | HTTP POST request | codesec/routes.py |
| `response.json()` | `response.json() -> dict` | Parse JSON response body | everywhere |
| `response.raise_for_status()` | `response.raise_for_status()` | Raises HTTPStatusError if 4xx/5xx | reputation.py, cve/routes.py |
| `httpx.Timeout()` | `httpx.Timeout(total, connect=5.0)` | Configures request timeout | recon.py, reputation.py |
| `httpx.HTTPStatusError` | `except httpx.HTTPStatusError as e: e.response.status_code` | Catches non-2xx responses | reputation.py, mcp_server.py |
| `httpx.RequestError` | `except httpx.RequestError` | Catches connection/network errors | reputation.py |
| `httpx.TimeoutException` | `except httpx.TimeoutException` | Catches timeout errors | cve/routes.py |

### httpcore 1.0.9
Low-level HTTP transport — subclassed for SSRF protection.

| Function / Class | Signature | What it does | Used in |
|-----------------|-----------|--------------|---------|
| `httpcore.SyncBackend` | `class _SSRFSafeBackend(httpcore.SyncBackend)` | Base class for DNS validation before connecting | recon.py |
| `httpcore.ConnectError` | `raise httpcore.ConnectError(msg)` | Raised when connection to private/internal IP detected | recon.py |

### dnspython 2.8.0
DNS resolution and record queries.

| Function / Class | Signature | What it does | Used in |
|-----------------|-----------|--------------|---------|
| `dns.resolver.Resolver()` | `resolver = dns.resolver.Resolver(); resolver.nameservers = [...]` | Creates DNS resolver with custom nameservers | recon.py |
| `dns.resolver.resolve()` | `dns.resolver.resolve(domain, rdtype) -> Answer` | Queries DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) | recon.py, validation.py |
| `dns.exception.DNSException` | `except dns.exception.DNSException` | Catches all DNS errors (NXDOMAIN, timeout, no answer) | recon.py, validation.py |

---

## Cryptography / X.509

### cryptography 46.0.7
X.509 certificate parsing. Used by Bug F AIA (Authority Information Access) intermediate fetch in `/v1/ssl/{domain}`.

| Function / Class | Signature | What it does | Used in |
|-----------------|-----------|--------------|---------|
| `x509.load_der_x509_certificate()` | `x509.load_der_x509_certificate(der_bytes) -> Certificate` | Parse DER-encoded cert (TLS handshake output + most AIA responses) | domain/routes.py:ssl_certificate |
| `x509.load_pem_x509_certificate()` | `x509.load_pem_x509_certificate(pem_bytes) -> Certificate` | Parse PEM-encoded cert (AIA fallback when body is `-----BEGIN CERTIFICATE-----`) | domain/routes.py:ssl_certificate |
| `cert.subject.rfc4514_string()` | `Name.rfc4514_string() -> str` | Distinguished Name as RFC 4514 string (`CN=...,O=...`) | domain/routes.py:ssl_certificate |
| `cert.issuer.rfc4514_string()` | same | Issuer DN as RFC 4514 string | domain/routes.py:ssl_certificate |
| `cert.not_valid_after` | `datetime` property | Certificate expiry timestamp | domain/routes.py:ssl_certificate |
| `cert.extensions.get_extension_for_class()` | `extensions.get_extension_for_class(x509.AuthorityInformationAccess) -> Extension` | Look up AIA extension on leaf cert to find CA Issuers URLs | domain/routes.py:ssl_certificate |
| `x509.ExtensionNotFound` | `except x509.ExtensionNotFound` | Raised when cert has no AIA extension (self-signed / missing) | domain/routes.py:ssl_certificate |
| `AuthorityInformationAccessOID.CA_ISSUERS` | OID constant | Filters AIA access descriptions to caIssuers URLs (ignores OCSP) | domain/routes.py:ssl_certificate |
| `x509.CertificateBuilder()` | `.subject_name().issuer_name().public_key().serial_number().not_valid_before().not_valid_after().add_extension().sign()` | Builds synthetic cert for tests | tests/test_domain_bulk.py |
| `x509.Name()` / `x509.NameAttribute()` | `Name([NameAttribute(NameOID.COMMON_NAME, "example.com")])` | Build DN for test certs | tests/test_domain_bulk.py |
| `x509.SubjectAlternativeName()` / `x509.DNSName()` | extension body | SAN extension for test certs | tests/test_domain_bulk.py |
| `x509.AuthorityInformationAccess()` / `x509.AccessDescription()` / `x509.UniformResourceIdentifier()` | AIA extension body | Attach AIA URL for test fixtures | tests/test_domain_bulk.py |
| `x509.random_serial_number()` | `-> int` | RFC 5280 serial number generator for test certs | tests/test_domain_bulk.py |
| `NameOID.COMMON_NAME`, `NameOID.ORGANIZATION_NAME` | OID constants | DN attribute types for Name() | tests/test_domain_bulk.py |
| `hashes.SHA256()` | algorithm instance | Signature hash for `CertificateBuilder.sign()` | tests/test_domain_bulk.py |
| `serialization.Encoding.DER` / `.PEM` | enum | Output encoding for `cert.public_bytes()` when feeding mocked handshakes/AIA responses | tests/test_domain_bulk.py |
| `rsa.generate_private_key()` | `rsa.generate_private_key(public_exponent=65537, key_size=2048)` | Key pair for test certs | tests/test_domain_bulk.py |

---

## IP / CIDR

### pytricia 1.3.0
C-backed radix trie (patricia) for fast longest-prefix-match CIDR lookup. Used to check whether an IP belongs to AWS/GCP/Cloudflare published ranges in `/v1/ip/{ip}`.

| Function / Class | Signature | What it does | Used in |
|-----------------|-----------|--------------|---------|
| `pytricia.PyTricia()` | `pytricia.PyTricia(32)` for v4, `pytricia.PyTricia(128)` for v6 | Creates a radix trie keyed on IP prefix length | domain/ip_intel.py |
| `trie[cidr] = value` | `trie["3.0.0.0/8"] = "AWS"` | Inserts CIDR → provider label | domain/ip_intel.py |
| `trie.get(ip)` | `trie.get("3.5.140.2") -> str \| None` | Longest-prefix lookup, returns value of covering CIDR or None | domain/ip_intel.py:check_cloud_provider |
| `list(trie)` | iterates inserted CIDR prefixes | Snapshot of keys — used to preserve previous entries when a source fails | domain/ip_intel.py:_refresh_cloud_cache |

---

## Data / Parsing

### cvss 3.6
CVSS (Common Vulnerability Scoring System) v2/v3/v4 vector parsing. Used to recompute base scores when OSV.dev returns only a vector string (no numeric score) in `_parse_cvss_vector_score()`. Imported lazily to keep cold-path modules off the critical import graph.

| Function / Class | Signature | What it does | Used in |
|-----------------|-----------|--------------|---------|
| `CVSS3()` | `CVSS3(vector_string) -> CVSS3` | Parses `CVSS:3.0`/`CVSS:3.1` vector string; raises on malformed input | cve/sync.py:_parse_cvss_vector_score |
| `.base_score` | `CVSS3(v).base_score -> Decimal` | Computed base score (0.0–10.0) derived from vector metrics | cve/sync.py:_parse_cvss_vector_score |

### phonenumbers 9.0.27
Phone number parsing, validation, and carrier/geo lookup (Google libphonenumber).

| Function / Class | Signature | What it does | Used in |
|-----------------|-----------|--------------|---------|
| `phonenumbers.parse()` | `phonenumbers.parse(number_str, region=None) -> PhoneNumber` | Parses string into PhoneNumber object | recon.py:phone_lookup |
| `phonenumbers.is_valid_number()` | `phonenumbers.is_valid_number(parsed) -> bool` | Validates number for region (length, format) | recon.py:phone_lookup |
| `phonenumbers.format_number()` | `phonenumbers.format_number(parsed, PhoneNumberFormat.E164) -> str` | Formats to E.164 (+905321234567), international, national | recon.py:phone_lookup |
| `phonenumbers.region_code_for_number()` | `phonenumbers.region_code_for_number(parsed) -> str` | Returns ISO country code ("TR", "US") | recon.py:phone_lookup |
| `phonenumbers.number_type()` | `phonenumbers.number_type(parsed) -> PhoneNumberType` | Returns type enum (MOBILE, FIXED_LINE, VOIP...) | recon.py:phone_lookup |
| `geocoder.description_for_number()` | `geocoder.description_for_number(parsed, "en") -> str` | Returns country/region name ("Turkey", "California") | recon.py:phone_lookup |
| `carrier.name_for_number()` | `carrier.name_for_number(parsed, "en") -> str` | Returns carrier name ("Turkcell", "Vodafone") | recon.py:phone_lookup |
| `timezone.time_zones_for_number()` | `timezone.time_zones_for_number(parsed) -> tuple[str]` | Returns IANA timezone list ("Europe/Istanbul") | recon.py:phone_lookup |
| `PhoneNumberFormat.E164` | enum: `E164`, `INTERNATIONAL`, `NATIONAL` | Format constants for format_number() | recon.py:phone_lookup |
| `PhoneNumberType.MOBILE` | enum: `MOBILE`, `FIXED_LINE`, `VOIP`, `TOLL_FREE`, `PREMIUM_RATE`, etc. | Number type constants | recon.py:phone_lookup |
| `NumberParseException` | `except phonenumbers.NumberParseException` | Raised on unparseable input | recon.py:phone_lookup |

---

## MCP (Model Context Protocol)

### mcp 1.27.0
MCP server framework for AI agent tool integration.

| Function / Class | Signature | What it does | Used in |
|-----------------|-----------|--------------|---------|
| `FastMCP()` | `FastMCP(name, instructions, stateless_http=True)` | Creates MCP server with tool registry | mcp_server.py |
| `@mcp.tool()` | `@mcp.tool() async def my_tool(param: str) -> str` | Registers function as MCP tool (55 tools) | mcp_server.py |
| `TransportSecuritySettings` | `TransportSecuritySettings(enable_dns_rebinding_protection=False)` | Configures transport security for public API | mcp_server.py |

---

## v1.25.0 Web Intelligence

### tldextract >=5.0
Public Suffix List-aware domain parser. Bundled PSL snapshot — no network refresh on the hot path.

| Function / Class | Signature | What it does | Used in |
|-----------------|-----------|--------------|---------|
| `tldextract.TLDExtract()` | `TLDExtract(suffix_list_urls=())` | Constructs an extractor with bundled PSL (network refresh disabled) | target_throttle.py, domain/seo_audit.py |
| `extract(host)` | `extract('news.bbc.co.uk') -> ExtractResult` | Splits a hostname into subdomain / domain / suffix using PSL | target_throttle.py (eTLD+1 buckets), seo_audit._same_registrable |
| `.top_domain_under_public_suffix` | `result.top_domain_under_public_suffix -> 'bbc.co.uk'` | Registrable domain (eTLD+1); correct for multi-label suffixes (.co.uk, .edu.au, .gov.uk) where last-2-labels heuristic fails | target_throttle, seo_audit |

### beautifulsoup4 >=4.12
Lenient HTML parser for homepage scraping (brand_assets + seo_audit).

| Function / Class | Signature | What it does | Used in |
|-----------------|-----------|--------------|---------|
| `BeautifulSoup()` | `BeautifulSoup(html, "html.parser")` | Parses HTML with the stdlib parser (no lxml C dep) | domain/brand_assets.py, domain/seo_audit.py |
| `.find()` / `.find_all()` | `soup.find_all("meta", attrs={"property":"og:image"}, limit=20)` | DOM lookup with limit=N to bound traversal cost | brand_assets, seo_audit |
| `tag.get(attr)` | `tag.get("content")` | Safe attribute access (returns None if missing) | brand_assets, seo_audit |

---

## Not Directly Imported (Transitive / Runtime)

| Package | Version | Role |
|---------|---------|------|
| **pydantic-settings** | 2.13.1 | Settings management extension (available, not imported) |
| **python-whois** | 0.9.6 | WHOIS library — **unused**, project has own raw-socket WHOIS client in recon.py. Consider removing. |
| **requests** | 2.33.1 | HTTP client; transitive dep, httpx used instead |
| **PyJWT** | 2.12.1 | JWT encoding/decoding; reserved for future auth features |
| **sse-starlette** | 3.3.4 | Server-Sent Events; required by MCP HTTP transport at runtime |
| **python-dotenv** | 1.2.2 | .env file loading; env vars loaded via systemd on production |
| **fastapi-mcp** | 0.4.0 | FastAPI-MCP integration; not imported (standalone mcp package used) |

---

## Import Map by Module

| Module | Third-Party Imports |
|--------|-------------------|
| `app/main.py` | fastapi, starlette, jinja2, re |
| `app/domain/recon.py` | dnspython, httpcore, httpx, phonenumbers |
| `app/domain/routes.py` | fastapi, httpx, pydantic, cryptography |
| `app/domain/ip_intel.py` | httpx, pytricia |
| `app/domain/reputation.py` | httpx |
| `app/domain/threat.py` | httpx |
| `app/cve/routes.py` | fastapi, httpx |
| `app/cve/sync.py` | httpx, cvss (lazy) |
| `app/codesec/routes.py` | fastapi, pydantic |
| `app/ioc/routes.py` | fastapi, httpx |
| `app/auth.py` | fastapi |
| `app/validation.py` | dnspython, fastapi |
| `app/ratelimit.py` | _(stdlib only)_ |
| `app/db.py` | _(stdlib only)_ |
| `mcp_server.py` | httpx, mcp |
