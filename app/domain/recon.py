"""Domain intelligence — passive recon for ContrastAPI

Extracted from contrastcyber recon.py, adapted for API responses.
All functions return structured dicts with summary fields.
"""

import logging
import re
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC

import dns.exception
import dns.resolver
import httpcore
import httpx
import ratelimit
from config import CRTSH_TIMEOUT, ENRICHMENT_DAILY_LIMIT, RECON_TIMEOUT
from validation import is_private_ip

logger = logging.getLogger("contrastapi")

USER_AGENT = "contrastapi/1.0"

# Module-level client for simple HTTP calls (connection pooling)
_http = httpx.Client(
    timeout=httpx.Timeout(RECON_TIMEOUT, connect=5.0),
    headers={"User-Agent": USER_AGENT},
    follow_redirects=False,
)

WAF_SIGNATURES = {
    "Cloudflare": {"header": "server", "contains": "cloudflare"},
    "AWS CloudFront": {"header": "x-amz-cf-id"},
    "Sucuri": {"header": "x-sucuri-id"},
    "Akamai": {"header": "x-akamai-transformed"},
    "ModSecurity": {"header": "server", "contains": "mod_security"},
    "F5 BIG-IP": {"header": "server", "contains": "bigip"},
    "Imperva": {"header": "x-iinfo"},
    "Fastly": {"header": "x-fastly-request-id"},
    "Varnish": {"header": "x-varnish"},
}

COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "ftp",
    "api",
    "dev",
    "staging",
    "test",
    "admin",
    "blog",
    "shop",
    "store",
    "cdn",
    "media",
    "static",
    "assets",
    "app",
    "portal",
    "dashboard",
    "cpanel",
    "webmail",
    "ns1",
    "ns2",
    "mx",
    "smtp",
    "imap",
    "pop",
    "vpn",
    "remote",
    "git",
    "ci",
]

WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
    "dev": None,
    "app": None,
    "xyz": "whois.nic.xyz",
    "info": "whois.afilias.net",
    "me": "whois.nic.me",
    "tr": "whois.trabis.gov.tr",
    "de": "whois.denic.de",
    "uk": "whois.nic.uk",
    "fr": "whois.nic.fr",
    "nl": "whois.sidn.nl",
    "ru": "whois.tcinet.ru",
    "br": "whois.registro.br",
    "au": "whois.auda.org.au",
    "jp": "whois.jprs.jp",
    "kr": "whois.kr",
    "cn": "whois.cnnic.cn",
    "in": "whois.registry.in",
}

CT_MAX_ENTRIES = 20
CT_MAX_CERTS = 10

# In-memory TTL cache for crt.sh responses (thread-safe)
_crtsh_cache: dict[str, tuple[list, float]] = {}
_crtsh_cache_lock = threading.Lock()
_CRTSH_CACHE_TTL = 3600  # 1 hour
_CRTSH_CACHE_MAX = 1000


# === DNS ===


def quick_dns_a(domain: str) -> list[str] | None:
    """Lightweight A-record-only lookup with 3s timeout. For /v1/monitor."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    try:
        answers = resolver.resolve(domain, "A")
        return [str(r) for r in answers if not is_private_ip(str(r))]
    except dns.exception.DNSException:
        return None


def dns_lookup(domain: str) -> dict:
    """Full DNS record lookup: A, AAAA, MX, NS, TXT, CNAME, SOA."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10
    records = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            answers = resolver.resolve(domain, rtype)
            if rtype == "MX":
                records[rtype.lower()] = [
                    {"priority": r.preference, "host": str(r.exchange).rstrip(".")} for r in answers
                ]
            elif rtype == "SOA":
                soa = answers[0]
                records["soa"] = {
                    "mname": str(soa.mname).rstrip("."),
                    "rname": str(soa.rname).rstrip("."),
                    "serial": soa.serial,
                }
            else:
                records[rtype.lower()] = [str(r).strip('"') for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
    return records


def _dns_call_with_timeout(func, *args, timeout: int = 3):
    """Run a blocking DNS call in a thread with timeout. Returns result or None."""
    result_box = [None]
    exc_box = [None]

    def _run():
        try:
            result_box[0] = func(*args)
        except Exception as e:
            exc_box[0] = e

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=timeout)
    if t.is_alive():
        return None, TimeoutError("DNS call timed out")
    if exc_box[0] is not None:
        return None, exc_box[0]
    return result_box[0], None


def reverse_dns(domain: str) -> dict:
    """Reverse DNS lookup — PTR record from IP."""
    try:
        result, err = _dns_call_with_timeout(socket.gethostbyname, domain)
        if err or not result:
            return {"ip": None, "ptr": None}
        ip = result
        if is_private_ip(ip):
            return {"ip": None, "ptr": None}
        addr_result, addr_err = _dns_call_with_timeout(socket.gethostbyaddr, ip)
        if addr_err or not addr_result:
            return {"ip": ip, "ptr": None}
        hostname = addr_result[0]
        return {"ip": ip, "ptr": hostname, "shared_hosting": hostname != domain}
    except Exception as e:
        logger.warning("reverse_dns failed for %s: %s", domain, e)
        return {"ip": None, "ptr": None}


# === WHOIS ===


def whois_lookup(domain: str) -> dict:
    """Raw WHOIS query via port 43."""
    try:
        parts = domain.split(".")
        tld = parts[-1]
        tld2 = ".".join(parts[-2:]) if len(parts) >= 2 else tld
        server = WHOIS_SERVERS.get(tld2, WHOIS_SERVERS.get(tld, f"whois.nic.{tld}"))
        if server is None:
            return {"error": f"No WHOIS server for .{tld} (RDAP only)"}

        with socket.create_connection((server, 43), timeout=RECON_TIMEOUT) as sock:
            sock.settimeout(RECON_TIMEOUT)
            # Sanitize domain to prevent CRLF injection into WHOIS protocol
            safe_domain = domain.replace("\r", "").replace("\n", "")
            sock.sendall(f"{safe_domain}\r\n".encode())
            response = bytearray()
            deadline = time.time() + RECON_TIMEOUT
            while True:
                if time.time() > deadline:
                    break
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) >= 32768:
                    break

        text = bytes(response).decode("utf-8", errors="ignore")
        info = _parse_whois(text)
        info["raw_length"] = len(text)
        return info
    except Exception as e:
        logger.warning("whois_lookup failed for %s: %s", domain, e)
        return {"error": "WHOIS lookup failed"}


def _parse_whois(text: str) -> dict:
    """Parse WHOIS response with regex patterns."""
    result = {}
    patterns = {
        "registrar": r"Registrar:\s*(.+)",
        "creation_date": r"(?:Creat(?:ion|ed)\s*Date|Registered\s*on|Registration\s*Date):\s*(.+)",
        "expiry_date": r"(?:Expir(?:y|ation)\s*Date|Registry Expiry Date|Expiry\s*date|Renewal\s*date):\s*(.+)",
        "updated_date": r"(?:Updated\s*Date|Last\s*updated):\s*(.+)",
        "name_servers": r"(?:Name\s*Server|Name\s*servers):\s*(.+)",
        "status": r"(?:Domain\s*)?Status:\s*(.+)",
    }
    for key, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            if key == "name_servers":
                result[key] = [m.strip().lower() for m in matches[:4]]
            elif key == "status":
                result[key] = [m.strip() for m in matches[:5]]
            else:
                result[key] = matches[0].strip()
    return result


# === Subdomains ===


def enumerate_subdomains(domain: str, crtsh_data: list | None = None) -> dict:
    """Enumerate subdomains via DNS brute force + crt.sh CT logs."""
    found = set()

    def _resolve_sub(sub):
        fqdn = f"{sub}.{domain}"
        result, err = _dns_call_with_timeout(socket.gethostbyname, fqdn)
        if result and not err and not is_private_ip(result):
            return fqdn
        return None

    with ThreadPoolExecutor(max_workers=10) as dns_pool:
        futures = {dns_pool.submit(_resolve_sub, sub): sub for sub in COMMON_SUBDOMAINS}
        for fut in futures:
            result = fut.result()
            if result:
                found.add(result)

    ct_subs = _crtsh_subdomains(domain, crtsh_data)
    found.update(ct_subs)

    unique = sorted(found)
    return {"subdomains": unique, "count": len(unique)}


def _fetch_crtsh(query: str) -> list:
    """Fetch certificate data from crt.sh (with 1h in-memory TTL cache)."""
    now = time.time()
    with _crtsh_cache_lock:
        if query in _crtsh_cache:
            result, ts = _crtsh_cache[query]
            if now - ts < _CRTSH_CACHE_TTL:
                return list(result)
    try:
        resp = _http.get(
            "https://crt.sh/",
            params={"q": query, "output": "json"},
            timeout=CRTSH_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()[:CT_MAX_ENTRIES]
    except Exception as e:
        logger.debug("crt.sh fetch failed for %s: %s", query, e)
        return []
    if not data:
        return []
    with _crtsh_cache_lock:
        _crtsh_cache[query] = (data, now)
        if len(_crtsh_cache) > _CRTSH_CACHE_MAX:
            oldest_key = min(_crtsh_cache, key=lambda k: _crtsh_cache[k][1])
            del _crtsh_cache[oldest_key]
    return data


def _crtsh_subdomains(domain: str, data: list | None = None) -> list:
    """Extract subdomain names from crt.sh data."""
    if data is None:
        data = _fetch_crtsh(f"%.{domain}")
    subs = set()
    for entry in data:
        name = entry.get("name_value", "")
        for n in name.split("\n"):
            n = n.strip().lower()
            if n.endswith(f".{domain}") and "*" not in n:
                subs.add(n)
    return list(subs)[:50]


# === CT Logs ===


def check_ct_logs(domain: str, crtsh_data: list | None = None) -> dict:
    """Certificate transparency log lookup via crt.sh."""
    try:
        data = crtsh_data if crtsh_data is not None else _fetch_crtsh(domain)
        if not data:
            return {"total_certificates": 0, "certificates": []}

        certs = []
        seen: set[str] = set()
        for entry in data[:CT_MAX_ENTRIES]:
            serial = entry.get("serial_number") or entry.get("id") or str(len(seen))
            if serial in seen:
                continue
            seen.add(serial)
            certs.append(
                {
                    "issuer": entry.get("issuer_name", ""),
                    "not_before": entry.get("not_before", ""),
                    "not_after": entry.get("not_after", ""),
                    "common_name": entry.get("common_name", ""),
                }
            )

        return {
            "total_certificates": len(data),
            "certificates": certs[:CT_MAX_CERTS],
        }
    except Exception as e:
        logger.debug("CT log check failed: %s", e)
        return {"total_certificates": 0, "certificates": []}


# === WAF Detection ===


def detect_waf(headers: dict) -> dict:
    """Detect WAF from HTTP response headers."""
    detected = []
    for waf_name, sig in WAF_SIGNATURES.items():
        if "contains" in sig:
            header_val = (headers.get(sig["header"]) or "").lower()
            if sig["contains"] in header_val:
                detected.append(waf_name)
        elif sig["header"] in headers:
            detected.append(waf_name)
    return {"detected": detected, "waf_present": len(detected) > 0}


# === SSL Info ===


def ssl_info(domain: str, resolved_ip: str | None = None) -> dict:
    """Get SSL certificate details with grade and TLS version."""
    try:
        ctx = ssl.create_default_context()
        connect_host = resolved_ip or domain
        with socket.create_connection((connect_host, 443), timeout=RECON_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                alpn = ssock.selected_alpn_protocol()
                tls_version = ssock.version() or "unknown"
                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))

                not_after = cert.get("notAfter", "")
                days_remaining = None
                if not_after:
                    try:
                        expiry_ts = ssl.cert_time_to_seconds(not_after)
                        days_remaining = int((expiry_ts - time.time()) / 86400)
                    except (ValueError, OverflowError):
                        pass

                grade = _ssl_grade(tls_version, days_remaining)

                return {
                    "common_name": subject.get("commonName", ""),
                    "issuer": issuer.get("organizationName", ""),
                    "not_before": cert.get("notBefore", ""),
                    "not_after": not_after,
                    "serial_number": cert.get("serialNumber", ""),
                    "version": cert.get("version", ""),
                    "tls_version": tls_version,
                    "alpn": alpn or "http/1.1",
                    "san": [v for _, v in cert.get("subjectAltName", ())],
                    "days_remaining": days_remaining,
                    "grade": grade,
                }
    except Exception as e:
        logger.warning("ssl_info failed for %s: %s", domain, e)
        return {"error": "SSL lookup failed", "grade": "F"}


def _ssl_grade(tls_version: str, days_remaining: int | None) -> str:
    """Grade SSL configuration A-F."""
    if days_remaining is not None and days_remaining < 0:
        return "F"
    if tls_version in ("TLSv1", "TLSv1.1"):
        return "F"
    if tls_version == "TLSv1.2":
        if days_remaining is not None and days_remaining < 14:
            return "C"
        return "B"
    if tls_version == "TLSv1.3":
        if days_remaining is not None and days_remaining < 7:
            return "C"
        if days_remaining is not None and days_remaining < 30:
            return "B"
        return "A"
    return "C"


# === Email Security ===

DKIM_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "mail",
    "dkim",
    "s1",
    "s2",
    "mandrill",
    "everlytickey1",
    "mxvault",
]


def email_security(domain: str, txt_records: list | None = None) -> dict:
    """Check SPF, DMARC, and DKIM records for email security."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    # SPF — check existing TXT records
    spf = None
    if txt_records:
        for txt in txt_records:
            if txt.lower().startswith("v=spf1"):
                spf = txt
                break

    # DMARC — query _dmarc.domain
    dmarc = None
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            val = str(r).strip('"')
            if val.lower().startswith("v=dmarc1"):
                dmarc = val
                break
    except dns.exception.DNSException:
        pass  # No DMARC record is common, not an error

    # DKIM — try common selectors + date-based (YYYYMMDD for last 60 days)
    dkim_found = []
    from datetime import datetime, timedelta

    date_selectors = []
    today = datetime.now(UTC)
    for i in range(7):
        date_selectors.append((today - timedelta(days=i)).strftime("%Y%m%d"))
    all_selectors = list(DKIM_SELECTORS) + date_selectors
    for selector in all_selectors:
        try:
            answers = resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            dkim_found.append(selector)
            if len(dkim_found) >= 3:
                break
        except dns.exception.DNSException:
            pass  # Most selectors won't exist

    issues = []
    if not spf:
        issues.append("No SPF record — domain vulnerable to email spoofing")
    if not dmarc:
        issues.append("No DMARC record — email receivers cannot verify sender authenticity")
    if not dkim_found:
        issues.append("No DKIM record found — email content cannot be verified")

    score = sum([bool(spf), bool(dmarc), bool(dkim_found)])
    grade = "A" if score == 3 else "B" if score == 2 else "C" if score == 1 else "F"

    return {
        "spf": spf,
        "dmarc": dmarc,
        "dkim_selectors": dkim_found,
        "grade": grade,
        "issues": issues,
    }


# === Live Header Fetch ===


class _SSRFSafeBackend(httpcore.SyncBackend):
    """Network backend that validates all resolved IPs before connecting.

    Resolves DNS once, rejects private IPs, then connects to the validated IP.
    httpcore uses the request hostname (not the connect IP) for TLS SNI and
    certificate verification, so SSL works correctly with IP pinning.
    """

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        result, err = _dns_call_with_timeout(
            socket.getaddrinfo,
            host,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )
        if err or not result:
            raise httpcore.ConnectError(f"DNS resolution failed for {host}")
        for _family, _stype, _proto, _canonname, sockaddr in result:
            if is_private_ip(sockaddr[0]):
                raise httpcore.ConnectError(f"SSRF blocked: {host} resolves to private IP")
        # Prefer IPv4 over IPv6 for reliability, try each validated IP
        sorted_results = sorted(result, key=lambda r: (r[0] != socket.AF_INET,))
        last_err = None
        for _family, _stype, _proto, _canonname, sockaddr in sorted_results:
            try:
                return super().connect_tcp(
                    sockaddr[0],
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except Exception as e:
                last_err = e
        raise httpcore.ConnectError(f"All addresses failed for {host}: {last_err}")


class _SSRFSafeTransport(httpx.HTTPTransport):
    """HTTP transport with SSRF protection at the connection level.

    Skips super().__init__() to avoid creating a default ConnectionPool
    that would immediately be discarded. Only self._pool is needed.
    """

    def __init__(self):
        self._pool = httpcore.ConnectionPool(network_backend=_SSRFSafeBackend())


_ssrf_http = httpx.Client(
    transport=_SSRFSafeTransport(),
    timeout=httpx.Timeout(RECON_TIMEOUT, connect=5.0),
    headers={"User-Agent": USER_AGENT},
    # follow_redirects set per-request by callers
    max_redirects=5,
)


def _safe_urlopen(domain: str, scheme: str, timeout: int, follow_redirects: bool = True):
    """SSRF-safe HTTP request. Validates all IPs (including redirect targets) before connecting."""
    return _ssrf_http.get(
        f"{scheme}://{domain}/",
        timeout=timeout,
        follow_redirects=follow_redirects,
    )


def fetch_live_headers(domain: str) -> dict:
    """Fetch HTTP response headers from a live domain (follows redirects safely)."""
    try:
        resp = _safe_urlopen(domain, "https", RECON_TIMEOUT)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return {"headers": headers, "status_code": resp.status_code, "url": str(resp.url)}
    except Exception as https_err:
        try:
            resp = _safe_urlopen(domain, "http", RECON_TIMEOUT)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return {"headers": headers, "status_code": resp.status_code, "url": str(resp.url)}
        except Exception as http_err:
            logger.warning(
                "fetch_live_headers failed for %s: HTTPS=%s, HTTP=%s",
                domain,
                type(https_err).__name__,
                type(http_err).__name__,
            )
            return {"error": f"Could not connect to {domain}"}


MAX_HTML_SIZE = 65536  # 64KB


def fetch_live_page(domain: str) -> dict:
    """Fetch HTTP headers AND HTML body (first 64KB) from a live domain."""

    def _fetch(scheme):
        with _ssrf_http.stream(
            "GET",
            f"{scheme}://{domain}/",
            timeout=RECON_TIMEOUT,
            follow_redirects=True,
        ) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            html = None
            content_type = headers.get("content-type", "")
            if "text/html" in content_type or "application/xhtml" in content_type:
                chunks = []
                remaining = MAX_HTML_SIZE
                for chunk in resp.iter_bytes():
                    chunks.append(chunk[:remaining])
                    remaining -= len(chunks[-1])
                    if remaining <= 0:
                        break
                raw = b"".join(chunks)
                html = raw.decode("utf-8", errors="ignore")
            return {"headers": headers, "html": html, "status_code": resp.status_code, "url": str(resp.url)}

    try:
        return _fetch("https")
    except Exception as https_err:
        try:
            return _fetch("http")
        except Exception as http_err:
            logger.warning(
                "fetch_live_page failed for %s: HTTPS=%s, HTTP=%s",
                domain,
                type(https_err).__name__,
                type(http_err).__name__,
            )
            return {"error": f"Could not connect to {domain}"}


# === IP Enrichment (Shodan InternetDB) ===

INTERNETDB_URL = "https://internetdb.shodan.io/"


def ip_enrichment(ip: str) -> dict:
    """Enrich IP with open ports, hostnames, vulns from Shodan InternetDB (free, no key)."""
    try:
        resp = _http.get(f"{INTERNETDB_URL}{ip}")
        resp.raise_for_status()
        data = resp.json()
        return {
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "vulns": data.get("vulns", []),
            "cpes": data.get("cpes", []),
            "tags": data.get("tags", []),
        }
    except Exception as e:
        logger.debug("ip_enrichment failed for %s: %s", ip, e)
        return {"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": []}


# === Full Domain Report ===


def full_domain_report(domain: str, resolved_ip: str | None = None, client_ip: str | None = None) -> dict:
    """Run all domain intelligence checks in parallel, return combined report."""
    report = {"domain": domain}

    from db import get_cached_ip, save_cached_ip
    from domain.reputation import check_abuseipdb, check_shodan
    from domain.threat import check_urlhaus

    # Determine whether reputation enrichment is allowed
    enrich = False
    if resolved_ip:
        cached_rep = get_cached_ip(resolved_ip)
        if cached_rep is not None:
            enrich = True  # cache hit, no quota consumed
        elif client_ip and ratelimit.check_limit(
            store_name="enrichment",
            key=client_ip,
            max_requests=ENRICHMENT_DAILY_LIMIT,
            window_seconds=86400,
        ):
            enrich = True
            cached_rep = None
        else:
            cached_rep = None

    with ThreadPoolExecutor(max_workers=10) as pool:
        # Submit all independent tasks immediately — no blocking waits
        f_crtsh = pool.submit(_fetch_crtsh, f"%.{domain}")
        f_dns = pool.submit(dns_lookup, domain)
        f_rdns = pool.submit(reverse_dns, domain)
        f_whois = pool.submit(whois_lookup, domain)
        f_ssl = pool.submit(ssl_info, domain, resolved_ip)
        f_threat = pool.submit(check_urlhaus, domain)
        f_headers = pool.submit(fetch_live_headers, domain)

        # Subdomains: reuse crtsh data to avoid duplicate HTTP call
        def _subs_with_crtsh():
            data = f_crtsh.result(timeout=CRTSH_TIMEOUT + 2)
            return enumerate_subdomains(domain, crtsh_data=data)

        f_subs = pool.submit(_subs_with_crtsh)

        # CT logs: wrapper waits for crtsh inside the pool, not on main thread
        def _ct_with_crtsh():
            data = f_crtsh.result(timeout=CRTSH_TIMEOUT + 2)
            return check_ct_logs(domain, data)

        f_certs = pool.submit(_ct_with_crtsh)

        # Reputation checks for resolved IP (rate-limited per client IP)
        f_ab = f_sh = None
        if enrich and cached_rep is None and resolved_ip:
            f_ab = pool.submit(check_abuseipdb, resolved_ip)
            f_sh = pool.submit(check_shodan, resolved_ip)

        report["dns"] = f_dns.result(timeout=RECON_TIMEOUT * 3)
        report["reverse_dns"] = f_rdns.result(timeout=RECON_TIMEOUT * 2)
        report["whois"] = f_whois.result(timeout=RECON_TIMEOUT * 2)
        report["ssl"] = f_ssl.result(timeout=RECON_TIMEOUT * 2)
        report["subdomains"] = f_subs.result(timeout=CRTSH_TIMEOUT + RECON_TIMEOUT + 4)
        report["certificates"] = f_certs.result(timeout=CRTSH_TIMEOUT + RECON_TIMEOUT + 4)
        report["threat"] = f_threat.result(timeout=RECON_TIMEOUT * 2)

        if enrich and cached_rep is not None:
            report["reputation"] = cached_rep
        elif f_ab is not None:
            try:
                reputation = {
                    "abuseipdb": f_ab.result(timeout=RECON_TIMEOUT + 2),
                    "shodan": f_sh.result(timeout=RECON_TIMEOUT + 2),
                }
                save_cached_ip(resolved_ip, reputation)
                report["reputation"] = reputation
            except Exception as e:
                logger.warning("Reputation enrichment failed for %s: %s", resolved_ip, type(e).__name__)
                if client_ip:
                    ratelimit.refund("enrichment", client_ip)

        # Email security uses DNS TXT records from dns_lookup
        txt_records = report["dns"].get("txt", [])
        f_email = pool.submit(email_security, domain, txt_records)
        report["email_security"] = f_email.result(timeout=RECON_TIMEOUT * 2)

        # Detect WAF from headers (already fetched in parallel)
        header_result = f_headers.result(timeout=RECON_TIMEOUT * 2)

    if "headers" in header_result:
        report["waf"] = detect_waf(header_result["headers"])
    else:
        report["waf"] = {"detected": [], "waf_present": False}

    # Build summary
    ip = report["reverse_dns"].get("ip", "unknown")
    sub_count = report["subdomains"].get("count", 0)
    waf_list = report["waf"].get("detected", [])
    waf_str = f"Behind {', '.join(waf_list)}." if waf_list else "No WAF detected."
    ssl_issuer = report["ssl"].get("issuer", "unknown")
    ssl_grade = report["ssl"].get("grade", "?")
    email_grade = report["email_security"].get("grade", "?")
    # Risk score
    from domain.scoring import score_domain

    report["risk"] = score_domain(report)
    risk_grade = report["risk"]["grade"]
    risk_score = report["risk"]["score"]

    threat_count = report.get("threat", {}).get("url_count", 0)
    threat_str = f"WARNING: {threat_count} URLhaus entries" if threat_count > 0 else ""

    report["summary"] = (
        f"{domain} resolves to {ip}. "
        f"Security grade {risk_grade} ({risk_score}/100). "
        f"SSL grade {ssl_grade} by {ssl_issuer}. "
        f"{waf_str} "
        f"Email security: {email_grade}. "
        f"{sub_count} subdomains found"
        f"{'. ' + threat_str if threat_str else ''}"
    )

    return report
