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

## Data / Parsing

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
| `@mcp.tool()` | `@mcp.tool() async def my_tool(param: str) -> str` | Registers function as MCP tool (30 tools) | mcp_server.py |
| `TransportSecuritySettings` | `TransportSecuritySettings(enable_dns_rebinding_protection=False)` | Configures transport security for public API | mcp_server.py |

---

## Not Directly Imported (Transitive / Runtime)

| Package | Version | Role |
|---------|---------|------|
| **pydantic-settings** | 2.13.1 | Settings management extension (available, not imported) |
| **python-whois** | 0.9.6 | WHOIS library — **unused**, project has own raw-socket WHOIS client in recon.py. Consider removing. |
| **cryptography** | 46.0.6 | TLS/crypto primitives; transitive dep of Python's ssl module and httpx |
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
| `app/domain/routes.py` | fastapi, httpx, pydantic |
| `app/domain/reputation.py` | httpx |
| `app/domain/threat.py` | httpx |
| `app/cve/routes.py` | fastapi, httpx |
| `app/codesec/routes.py` | fastapi, pydantic |
| `app/ioc/routes.py` | fastapi, httpx |
| `app/auth.py` | fastapi |
| `app/validation.py` | dnspython, fastapi |
| `app/ratelimit.py` | _(stdlib only)_ |
| `app/db.py` | _(stdlib only)_ |
| `mcp_server.py` | httpx, mcp |
