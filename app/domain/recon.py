"""Domain intelligence — passive recon for ContrastAPI

Extracted from contrastcyber recon.py, adapted for API responses.
All functions return structured dicts with summary fields.
"""

import asyncio
import functools
import json
import logging
import re
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta

import dns.exception
import dns.resolver
import httpcore
import httpx
import ratelimit
from config import (
    BOT_USER_AGENT,
    CRTSH_MAX_BYTES,
    CRTSH_MAX_RESULTS,
    CRTSH_TIMEOUT,
    ENRICHMENT_DAILY_LIMIT,
    RECON_TIMEOUT,
    UPGRADE_URL,
)
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from fastapi.concurrency import run_in_threadpool
from validation import is_private_ip

logger = logging.getLogger("contrastapi")

# Self-identifying UA so target site operators can recognise + contact us.
# Version-pinned to app.config.VERSION; landing at /bot lists abuse contact.
USER_AGENT = BOT_USER_AGENT


# Unicode bidirectional / format control codepoints that are >U+0020 yet still
# unsafe to emit verbatim — Trojan Source (CVE-2021-42574) and DKIM/DMARC
# spoofing both abuse these to reverse the visual rendering order of an
# untrusted DNS / crt.sh string. Literal lookup is faster than
# unicodedata.category here because it runs in the request hot path.
_BIDI_CONTROL_CHARS = frozenset(
    {
        "‪",  # LRE
        "‫",  # RLE
        "‬",  # PDF
        "‭",  # LRO
        "‮",  # RLO
        "⁦",  # LRI
        "⁧",  # RLI
        "⁨",  # FSI
        "⁩",  # PDI
    }
)


def _strip_control_chars(s: str) -> str:
    """Drop ASCII control + DEL + Unicode bidi/format controls + replacement
    char so untrusted-source strings (DNS TXT, crt.sh subject names, DKIM/
    DMARC tags) cannot smuggle `\\x00`, `\\x7f`, RTL overrides, or U+FFFD
    passthrough into wire payloads.

    Single canonical helper for: TXT chunk reassembly, _crtsh_subdomains
    `name_value` parsing, DMARC TXT, DKIM TXT fallback. errors='replace'
    upstream produces U+FFFD which we also drop here so a single bad UTF-8
    sequence does not stay in the response. Bidi controls (U+202A-U+202E,
    U+2066-U+2069) are >U+0020 - without the explicit set check they would
    pass the `c >= " "` guard and survive into the response, leaking a
    Trojan-Source-style display attack to anyone reading the JSON in a
    bidi-aware terminal or UI.
    """
    return "".join(c for c in s if c >= " " and c != "\x7f" and c != "�" and c not in _BIDI_CONTROL_CHARS)


# Module-level client for simple HTTP calls (connection pooling)
_http = httpx.AsyncClient(
    timeout=httpx.Timeout(RECON_TIMEOUT, connect=5.0),
    headers={"User-Agent": USER_AGENT},
    follow_redirects=False,
    cookies=httpx.Cookies(),
    limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
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

# In-memory TTL cache for crt.sh responses (async-safe)
_crtsh_cache: dict[str, tuple[list, float]] = {}
_crtsh_cache_lock = asyncio.Lock()
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
                # RFC 7505 null MX (priority=0, exchange='.') and malformed
                # records both rstrip to host='' here. Emitting them as
                # {priority: N, host: ''} is meaningless to downstream consumers
                # (mail_provider detection, disposable-MX scan, audit_domain
                # summary) and used to leak a phantom MX into responses. Filter
                # them out — the resulting empty mx list is an honest signal
                # that the domain does not accept mail.
                # Order matters: strip() first so a stray '. ' (whitespace-padded
                # null MX) collapses to '.' before rstrip drops the trailing dot.
                # Otherwise rstrip would skip the dot (trailing char is space)
                # and the record would survive with host='.'.
                records[rtype.lower()] = [
                    {"priority": r.preference, "host": host}
                    for r in answers
                    if (host := str(r.exchange).strip().rstrip("."))
                ]
            elif rtype == "SOA":
                soa = answers[0]
                records["soa"] = {
                    "mname": str(soa.mname).rstrip("."),
                    "rname": str(soa.rname).rstrip("."),
                    "serial": soa.serial,
                }
            elif rtype == "TXT":
                records["txt"] = [
                    _strip_control_chars(b"".join(r.strings).decode("utf-8", errors="replace")) for r in answers
                ]
            else:
                records[rtype.lower()] = [str(r).strip('"') for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            # Missing record / NXDOMAIN / timeout is normal for many domains — skip this rtype.
            pass
    records["total_txt_records"] = len(records.get("txt") or [])
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
        logger.warning("reverse_dns failed: %s", type(e).__name__)
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
        logger.warning("whois_lookup failed: %s", type(e).__name__)
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


async def enumerate_subdomains(domain: str, crtsh_data: list | None = None) -> dict:
    """Enumerate subdomains via DNS brute force + crt.sh CT logs."""
    found_wordlist: set[str] = set()
    warnings: list[str] = []

    def _resolve_sub(sub):
        fqdn = f"{sub}.{domain}"
        result, err = _dns_call_with_timeout(socket.gethostbyname, fqdn)
        if result and not err and not is_private_ip(result):
            return fqdn
        return None

    dns_results = await asyncio.gather(
        *[run_in_threadpool(_resolve_sub, sub) for sub in COMMON_SUBDOMAINS],
        return_exceptions=False,
    )
    for result in dns_results:
        if result:
            found_wordlist.add(result)

    found_crtsh, crtsh_warnings, crtsh_status = await _crtsh_subdomains(domain, crtsh_data)
    warnings.extend(crtsh_warnings)

    all_found = sorted(found_wordlist | set(found_crtsh))

    sources = []
    if found_wordlist:
        sources.append("wordlist")
    if found_crtsh:
        sources.append("crt_sh")

    summary = f"{len(all_found)} subdomain(s) found for {domain}"
    if found_wordlist and found_crtsh:
        summary += f" ({len(found_wordlist)} via wordlist, {len(found_crtsh)} via CT logs)"
    elif found_crtsh:
        summary += " (all via CT logs)"
    if crtsh_status != "ok" and not found_crtsh:
        # Be explicit in the human summary so agents reading it know the count
        # is wordlist-only, not the full picture.
        summary += f" (CT logs {crtsh_status})"
    if warnings:
        summary += f" [{'; '.join(warnings)}]"

    return {
        "subdomains": all_found,
        "count": len(all_found),
        "sources": sources,
        "found_via_wordlist": len(found_wordlist),
        "found_via_crtsh": len(found_crtsh),
        "crtsh_status": crtsh_status,
        "warnings": warnings,
        "summary": summary,
    }


async def _fetch_crtsh(query: str) -> tuple[list, str | None]:
    """Fetch certificate data from crt.sh (with 1h in-memory TTL cache).

    Returns:
        (data, error_msg) where error_msg is None on success or one of:
        "crt_sh_timeout" | "crt_sh_rate_limited" | "crt_sh_unavailable" |
        "parse_error" | "crt_sh_error"
    """
    now = time.time()
    async with _crtsh_cache_lock:
        if query in _crtsh_cache:
            result, ts = _crtsh_cache[query]
            if now - ts < _CRTSH_CACHE_TTL:
                return (list(result), None)
    try:
        resp = await _http.get(
            "https://crt.sh/",
            params={"q": query, "output": "json"},
            timeout=CRTSH_TIMEOUT,
        )
        if resp.status_code == 429:
            return ([], "crt_sh_rate_limited")
        resp.raise_for_status()
        if len(resp.content) > CRTSH_MAX_BYTES:
            return ([], "crt_sh_unavailable")
        data = resp.json()[:CRTSH_MAX_RESULTS]
    except httpx.TimeoutException:
        return ([], "crt_sh_timeout")
    except httpx.HTTPStatusError as e:
        if e.response.status_code >= 500:
            return ([], "crt_sh_unavailable")
        return ([], "crt_sh_error")
    except (ValueError, json.JSONDecodeError):
        return ([], "parse_error")
    except Exception as e:
        logger.debug("crt.sh fetch failed: %s", type(e).__name__)
        return ([], "crt_sh_error")
    if not data:
        return ([], None)
    async with _crtsh_cache_lock:
        _crtsh_cache[query] = (data, now)
        if len(_crtsh_cache) > _CRTSH_CACHE_MAX:
            oldest_key = min(_crtsh_cache, key=lambda k: _crtsh_cache[k][1])
            del _crtsh_cache[oldest_key]
    return (data, None)


_CRTSH_STATUS_BY_ERROR = {
    "crt_sh_timeout": "timeout",
    "crt_sh_rate_limited": "rate_limited",
    "crt_sh_unavailable": "unavailable",
    "crt_sh_error": "error",
    "parse_error": "error",
}


async def _crtsh_subdomains(domain: str, data: list | None = None) -> tuple[list, list, str]:
    """Extract subdomain names from crt.sh data.

    Returns:
        (subdomains, warnings, status) — status is one of "ok" / "timeout" /
        "rate_limited" / "unavailable" / "error". The third return value lets
        callers distinguish "CT lookup confirmed empty" from "CT lookup failed";
        the legacy (subs, warnings) shape conflated the two and downstream tools
        could not tell the difference between an actually-tiny domain and a
        crt.sh outage.
    """
    warnings: list[str] = []
    status = "ok"
    if data is None:
        data, fetch_error = await _fetch_crtsh(f"%.{domain}")
        if fetch_error:
            warnings.append(fetch_error)
            status = _CRTSH_STATUS_BY_ERROR.get(fetch_error, "error")
        if not data:
            return ([], warnings, status)

    subs: set[str] = set()
    parse_errors = 0
    for entry in data:
        try:
            name = entry.get("name_value", "")
            for n in name.split("\n"):
                n = _strip_control_chars(n).strip().lower()
                if "*" in n:
                    n = n.replace("*.", "")
                if n.endswith(f".{domain}") and n != domain:
                    subs.add(n)
        except Exception:
            parse_errors += 1

    if parse_errors > 0:
        warnings.append(f"parse_error: {parse_errors} entries")

    return (sorted(subs)[:50], warnings, status)


# === CT Logs ===


async def check_ct_logs(domain: str, crtsh_data: list | None = None, crtsh_error: str | None = None) -> dict:
    """Certificate transparency log lookup via crt.sh.

    Returns dict with `error` field populated (e.g. "crt_sh_timeout") when the
    upstream fetch failed — distinguishes "no certs found" from "fetch failed"
    so the caller can mark the source unavailable instead of penalizing the
    domain in scoring. `crtsh_status` mirrors the Literal taxonomy used by
    `_crtsh_subdomains` so both halves of the recon report agree on whether
    crt.sh delivered.

    The optional `crtsh_error` argument lets full_domain_report's pre-fetched
    crt.sh path propagate fetch failures without re-fetching: when the caller
    already paid the round-trip cost via _fetch_crtsh, it can pass the error
    string through so the certificates branch is just as honest as the
    subdomains branch (Bug B3 — previously `error` was always None on this
    path even when crt.sh had failed).
    """
    fetch_error: str | None = crtsh_error
    if crtsh_data is None:
        data, fetch_error = await _fetch_crtsh(domain)
    else:
        data = crtsh_data
    # Pattern parity with _crtsh_subdomains: an unrecognised error string is
    # surfaced as 'error' rather than masquerading as 'ok' — the latter would
    # let new upstream failure modes silently look like clean empty results.
    status = _CRTSH_STATUS_BY_ERROR.get(fetch_error, "error") if fetch_error else "ok"
    try:
        if not data:
            return {
                "total_certificates": 0,
                "certificates": [],
                "error": fetch_error,
                "crtsh_status": status,
            }

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
            "error": None,
            "crtsh_status": status,
        }
    except Exception as e:
        logger.debug("CT log parse failed: %s", type(e).__name__)
        return {
            "total_certificates": 0,
            "certificates": [],
            "error": "parse_error",
            "crtsh_status": "error",
        }


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


def _classify_ssl_verify_error(verify_message: str) -> list[str]:
    """Map OpenSSL verify error message to canonical validation_errors tags.

    Precedence matters: "self signed certificate in certificate chain" (verify_code 19)
    means an intermediate/root in the chain is self-signed and not in our trust store —
    that's "untrusted_root", NOT a leaf "self_signed". Plain "self signed certificate"
    (verify_code 18) means the leaf itself is self-signed.
    """
    msg = (verify_message or "").lower()
    if ("self signed" in msg or "self-signed" in msg) and ("chain" in msg or "in certificate" in msg):
        return ["untrusted_root"]
    if "unable to get local issuer" in msg or "unable to get issuer" in msg:
        return ["untrusted_root"]
    if "self signed" in msg or "self-signed" in msg:
        return ["self_signed"]
    if "has expired" in msg or "certificate has expired" in msg or "cert has expired" in msg:
        return ["expired"]
    if "hostname mismatch" in msg or "doesn't match" in msg or "name does not match" in msg:
        return ["hostname_mismatch"]
    return ["chain_incomplete"]


_SAN_LIST_CAP = 100


def _parse_cert_der(cert_der: bytes) -> dict | None:
    """Parse DER-encoded cert into stable dict; returns None on parse failure.

    Cert subject/issuer/SAN strings come from a remote-controlled X.509 blob
    and may carry Unicode bidi controls (Trojan-Source CVE-2021-42574). All
    user-visible string fields are passed through _strip_control_chars before
    return. SAN list is capped at _SAN_LIST_CAP entries to bound response size.
    """
    try:
        cert = x509.load_der_x509_certificate(cert_der)

        common_name = ""
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME:
                common_name = _strip_control_chars(str(attr.value))
                break

        issuer = ""
        for attr in cert.issuer:
            if attr.oid == NameOID.ORGANIZATION_NAME:
                issuer = _strip_control_chars(str(attr.value))
                break
        if not issuer:
            for attr in cert.issuer:
                if attr.oid == NameOID.COMMON_NAME:
                    issuer = _strip_control_chars(str(attr.value))
                    break

        try:
            not_before_dt = cert.not_valid_before_utc
            not_after_dt = cert.not_valid_after_utc
        except AttributeError:
            not_before_dt = cert.not_valid_before.replace(tzinfo=UTC)
            not_after_dt = cert.not_valid_after.replace(tzinfo=UTC)

        not_before = not_before_dt.strftime("%b %d %H:%M:%S %Y GMT")
        not_after = not_after_dt.strftime("%b %d %H:%M:%S %Y GMT")
        days_remaining = int((not_after_dt - datetime.now(UTC)).total_seconds() / 86400)

        try:
            serial = format(cert.serial_number, "X")
        except Exception:
            serial = ""

        try:
            version = cert.version.value + 1
        except Exception:
            version = 3

        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            raw_san = san_ext.value.get_values_for_type(x509.DNSName)
            san_list = [_strip_control_chars(str(name)) for name in raw_san[:_SAN_LIST_CAP]]
        except x509.ExtensionNotFound:
            san_list = []

        return {
            "common_name": common_name,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "serial_number": serial,
            "version": version,
            "san": san_list,
            "days_remaining": days_remaining,
        }
    except Exception as e:
        logger.warning("cert parse failed: %s", type(e).__name__)
        return None


def _hostname_matches(san_list: list[str], common_name: str, hostname: str) -> bool:
    """Match hostname against cert SAN/CN with single-label wildcard support (RFC 6125)."""
    candidates = list(san_list) if san_list else []
    if not candidates and common_name:
        candidates = [common_name]
    hostname = hostname.lower().strip(".")
    for pattern in candidates:
        pattern = pattern.lower().strip(".")
        if pattern == hostname:
            return True
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if "." not in hostname:
                continue
            host_first, host_rest = hostname.split(".", 1)
            if host_first and host_rest == suffix:
                return True
    return False


def ssl_info(domain: str, resolved_ip: str | None = None) -> dict:
    """Get SSL certificate details, TLS version, and validation findings.

    Cert validation issues (expired, self-signed, hostname mismatch, untrusted root)
    are reported as findings via cert_valid=False + validation_errors[].
    Only true probe failures (timeout, connection refused, no port 443) return error.
    """
    connect_host = resolved_ip or domain
    validation_errors: list[str] = []
    cert_der: bytes | None = None
    tls_version: str = ""
    alpn: str | None = None
    chain_verified = False

    # Pass 1: verified context (chain + hostname check by OpenSSL)
    # SSL fingerprint scanner — intentionally probes target's TLS config; default
    # context already enforces TLS 1.2+ but downstream scanner reports the version.
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((connect_host, 443), timeout=RECON_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                alpn = ssock.selected_alpn_protocol()
                tls_version = ssock.version() or "unknown"
                chain_verified = True
    except ssl.SSLCertVerificationError as e:
        verify_msg = getattr(e, "verify_message", "") or str(e)
        validation_errors = _classify_ssl_verify_error(verify_msg)
    except (TimeoutError, socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError, ssl.SSLError) as e:
        logger.warning("ssl_info failed: %s", type(e).__name__)
        return {"error": "SSL lookup failed", "grade": "F", "cert_valid": False, "validation_errors": []}
    except Exception as e:
        logger.warning("ssl_info failed: %s", type(e).__name__)
        return {"error": "SSL lookup failed", "grade": "F", "cert_valid": False, "validation_errors": []}

    # Pass 2: if verification failed, retry unverified to fetch cert details
    # Scanner needs to inspect expired/misconfigured certs for diagnostic output.
    if cert_der is None:
        try:
            unverified = ssl.create_default_context()
            unverified.check_hostname = False
            unverified.verify_mode = ssl.CERT_NONE
            with socket.create_connection((connect_host, 443), timeout=RECON_TIMEOUT) as sock:
                with unverified.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    alpn = ssock.selected_alpn_protocol()
                    tls_version = ssock.version() or "unknown"
        except Exception as e:
            logger.warning("ssl_info unverified retry failed: %s", type(e).__name__)
            return {
                "error": "SSL lookup failed",
                "grade": "F",
                "cert_valid": False,
                "validation_errors": validation_errors,
            }

    parsed = _parse_cert_der(cert_der) if cert_der else None
    if parsed is None:
        return {
            "error": "SSL cert parse failed",
            "grade": "F",
            "cert_valid": False,
            "validation_errors": validation_errors,
        }

    # Independent expiry check (catches edge: not_after < now even if openssl chain still trusted)
    if parsed["days_remaining"] is not None and parsed["days_remaining"] < 0 and "expired" not in validation_errors:
        validation_errors.append("expired")

    # Hostname check independent of chain — only when chain wasn't already verified by OpenSSL
    if not chain_verified and "hostname_mismatch" not in validation_errors:
        if not _hostname_matches(parsed["san"], parsed["common_name"], domain):
            validation_errors.append("hostname_mismatch")

    cert_valid = chain_verified and not validation_errors
    grade = _ssl_grade(tls_version, parsed["days_remaining"], cert_valid, validation_errors)

    return {
        "common_name": parsed["common_name"],
        "issuer": parsed["issuer"],
        "not_before": parsed["not_before"],
        "not_after": parsed["not_after"],
        "serial_number": parsed["serial_number"],
        "version": parsed["version"],
        "tls_version": tls_version,
        "alpn": alpn or "http/1.1",
        "san": parsed["san"],
        "days_remaining": parsed["days_remaining"],
        "grade": grade,
        "cert_valid": cert_valid,
        "validation_errors": validation_errors,
    }


def _ssl_grade(
    tls_version: str,
    days_remaining: int | None,
    cert_valid: bool = True,
    validation_errors: list[str] | None = None,
) -> str:
    """Grade SSL configuration A/B/C/D/F.

    A/B/C: cert_valid AND modern TLS.
    D: cert readable but invalid (hostname_mismatch / untrusted_root / self_signed / chain_incomplete).
    F: probe failure, expired, OR legacy TLS (TLSv1/TLSv1.1).
    """
    validation_errors = validation_errors or []
    # F precedence: legacy TLS or expired cert is most severe
    if tls_version in ("TLSv1", "TLSv1.1"):
        return "F"
    if "expired" in validation_errors:
        return "F"
    if days_remaining is not None and days_remaining < 0:
        return "F"
    # D: cert readable but failed non-expiry validation
    if not cert_valid:
        return "D"
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


# === Disposable Email Detection ===


def check_disposable(email: str, domain: str | None = None) -> dict:
    """Check if an email uses a disposable/temporary email provider.

    Args:
        email: Full email address.
        domain: Pre-extracted and cleaned domain. If None, extracted from email.
    """
    from domain.disposable_domains import DISPOSABLE_DOMAINS, DISPOSABLE_MX_HOSTS, DISPOSABLE_PROVIDERS

    if domain is None:
        if "@" not in email:
            return {
                "email": email,
                "domain": "",
                "disposable": False,
                "provider": None,
                "mx_disposable": False,
                "risk_level": "low",
                "mx_records": [],
            }
        domain = email.rsplit("@", 1)[1].lower()

    is_disposable = domain in DISPOSABLE_DOMAINS
    provider = DISPOSABLE_PROVIDERS.get(domain) if is_disposable else None

    # MX lookup to catch domains sharing disposable MX infrastructure
    records = dns_lookup(domain)
    mx_records = records.get("mx", [])
    mx_disposable = False
    for mx in mx_records:
        host = mx.get("host", "").lower().rstrip(".")
        if host in DISPOSABLE_MX_HOSTS:
            mx_disposable = True
            break

    disposable = is_disposable or mx_disposable
    if is_disposable:
        risk_level = "high"
    elif mx_disposable:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "email": email,
        "domain": domain,
        "disposable": disposable,
        "provider": provider,
        "mx_disposable": mx_disposable,
        "risk_level": risk_level,
        "mx_records": mx_records,
    }


# === Email Security ===

# DKIM tag-list separator: start-of-string, ';', or whitespace before 'p='.
# Anchors the public-key tag so substrings like '?p=1' (vendor URL) or 'sp=' do
# not satisfy the content check in _check_dkim.
_DKIM_PTAG_RE = re.compile(r"(?:^|[;\s])p=")

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

DKIM_DATE_WINDOW_DAYS = 14  # how many days back to probe date-based DKIM selectors

_MAIL_PROVIDERS = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "outlook.de": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365",
    "pphosted.com": "Proofpoint",
    "mimecast.com": "Mimecast",
    "barracudanetworks.com": "Barracuda",
    "messagelabs.com": "Symantec",
    "zoho.com": "Zoho Mail",
    "zoho.eu": "Zoho Mail",
    "secureserver.net": "GoDaddy",
    "emailsrvr.com": "Rackspace",
    "yahoodns.net": "Yahoo Mail",
    "icloud.com": "Apple iCloud",
    "mail.me.com": "Apple iCloud",
    "ovh.net": "OVH",
    "yandex.net": "Yandex Mail",
    "yandex.ru": "Yandex Mail",
    "mailgun.org": "Mailgun",
    "amazonaws.com": "Amazon SES",
    "sophos.com": "Sophos",
    "forcepoint.com": "Forcepoint",
    "fireeyecloud.com": "FireEye",
    "ess.barracuda.com": "Barracuda",
    "kundenserver.de": "IONOS",
    "registrar-servers.com": "Namecheap",
    "pair.com": "pair Networks",
    "fastmail.com": "Fastmail",
    "migadu.com": "Migadu",
    "tutanota.de": "Tutanota",
    "protonmail.ch": "ProtonMail",
    "infomaniak.ch": "Infomaniak",
}


def detect_mail_provider(mx_records: list[dict]) -> str | None:
    """Detect mail provider from MX record hostnames."""
    if not mx_records:
        return None
    # Use highest-priority (lowest number) MX record
    sorted_mx = sorted(mx_records, key=lambda r: r.get("priority", 99))
    for mx in sorted_mx:
        host = mx.get("host", "").lower().rstrip(".")
        # Match against known provider domains (check suffix)
        for domain_suffix, provider in _MAIL_PROVIDERS.items():
            if host == domain_suffix or host.endswith("." + domain_suffix):
                return provider
    return None


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
            val = _strip_control_chars(b"".join(r.strings).decode("utf-8", errors="replace"))
            if val.lower().startswith("v=dmarc1"):
                dmarc = val
                break
    except dns.exception.DNSException:
        pass  # No DMARC record is common, not an error

    # DKIM — try common selectors + date-based (YYYYMMDD for last DKIM_DATE_WINDOW_DAYS days)
    dkim_found = []
    today = datetime.now(UTC)
    date_selectors = [(today - timedelta(days=i)).strftime("%Y%m%d") for i in range(DKIM_DATE_WINDOW_DAYS)]
    all_selectors = list(DKIM_SELECTORS) + date_selectors

    def _check_dkim(selector: str) -> str | None:
        # Only treat the selector as verified when at least one TXT record at
        # `{selector}._domainkey.{domain}` actually carries a DKIM-shaped value.
        # RFC 6376: the public-key tag p= is required; the version tag v=DKIM1
        # is recommended but not strictly mandatory, so p= alone is enough.
        # Wildcards, vendor verification strings, and stale records resolve to
        # something — without this content check they would all be reported as
        # DKIM verified, which is the bug we are fixing. We also reject
        # misplaced DMARC/SPF records (which carry their own p= or v= tags) so
        # they do not slip through the substring match.
        try:
            r = dns.resolver.Resolver()
            r.timeout = 2
            r.lifetime = 3
            answers = r.resolve(f"{selector}._domainkey.{domain}", "TXT")
        except dns.exception.DNSException:
            return None
        for rec in answers:
            try:
                value = _strip_control_chars(b"".join(rec.strings).decode("utf-8", errors="replace")).lower()
            except (AttributeError, UnicodeDecodeError):
                # rec.strings is the canonical TXT idiom; str(rec) on multi-string
                # TXT yields '"chunk1" "chunk2"' which corrupts DKIM tag parsing.
                value = _strip_control_chars(str(rec).replace('" "', "").strip('"')).lower()
            if "v=dmarc1" in value or "v=spf1" in value:
                continue
            if "v=dkim1" in value:
                return selector
            # Bare p= without a version tag — accept only when surrounded by
            # tag-list punctuation (start, ';', or whitespace) to avoid matching
            # query-string fragments like '?p=1' inside vendor verification URLs.
            if _DKIM_PTAG_RE.search(value):
                return selector
        return None

    pool = ThreadPoolExecutor(max_workers=10)
    try:
        futures = {pool.submit(_check_dkim, s): s for s in all_selectors}
        for future in as_completed(futures, timeout=8):
            result = future.result(timeout=4)
            if result:
                dkim_found.append(result)
                if len(dkim_found) >= 3:
                    break
    except TimeoutError:
        # DKIM probe deadline exceeded — return whatever selectors resolved so far.
        pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    issues = []
    if not spf:
        issues.append("No SPF record — domain vulnerable to email spoofing")
    if not dmarc:
        issues.append("No DMARC record — email receivers cannot verify sender authenticity")
    if not dkim_found:
        issues.append(
            "DKIM not found under common selectors — domains using custom DKIM selectors "
            "cannot be probed without prior knowledge of the selector name"
        )

    # DKIM existence is unverifiable in DNS without knowing the selector name (selectors
    # are arbitrary strings chosen by the operator). When our probe of common + recent
    # date-based selectors comes back empty, we cannot conclude DKIM is missing — only
    # that we did not find it. Mark this honestly and do not penalize the letter grade
    # for an unverifiable signal. SPF and DMARC are at well-known names, so their
    # absence IS verifiable and continues to drive the grade.
    spf_present = bool(spf)
    dmarc_present = bool(dmarc)
    dkim_verified = bool(dkim_found)
    dkim_status = "verified" if dkim_verified else "unverifiable"

    if dkim_verified:
        score = int(spf_present) + int(dmarc_present) + 1
        grade = "A" if score == 3 else "B" if score == 2 else "C"
    else:
        if spf_present and dmarc_present:
            grade = "A"
        elif spf_present or dmarc_present:
            grade = "B"
        else:
            grade = "F"

    return {
        "spf": spf,
        "dmarc": dmarc,
        "dkim_selectors": dkim_found,
        "dkim_status": dkim_status,
        "grade": grade,
        "issues": issues,
    }


# === Live Header Fetch ===


# Dedicated executor for DNS resolution. Isolates the SSRF backend's DNS calls
# from asyncio's default ThreadPoolExecutor, so a slow getaddrinfo cannot
# saturate the shared pool that other async tasks depend on.
_DNS_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="ssrf-dns")


async def _resolve_dns_async(host: str, timeout: float = 3.0):
    """getaddrinfo on a dedicated executor with an asyncio-level timeout.
    Single-thread layer (no double-threading). On timeout the inner thread
    is left to finish under OS DNS bounds — bounded by max_workers=8.
    """
    loop = asyncio.get_running_loop()
    fn = functools.partial(socket.getaddrinfo, host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    return await asyncio.wait_for(loop.run_in_executor(_DNS_EXECUTOR, fn), timeout=timeout)


class _SSRFSafeAsyncBackend(httpcore.AnyIOBackend):
    """Async network backend that validates all resolved IPs before connecting.

    Resolves DNS once via a dedicated executor (single thread layer, isolated
    from asyncio's default pool), rejects private IPs, prefers IPv4, and falls
    through to IPv6 only on IPv4 failure. httpcore uses the request hostname
    (not the connect IP) for TLS SNI and certificate verification, so SSL works
    correctly with IP pinning.
    """

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        try:
            result = await _resolve_dns_async(host, timeout=3.0)
        except asyncio.TimeoutError as e:
            raise httpcore.ConnectError(f"DNS resolution timed out for {host}") from e
        except (socket.gaierror, OSError) as e:
            raise httpcore.ConnectError(f"DNS resolution failed for {host}: {type(e).__name__}") from e
        if not result:
            raise httpcore.ConnectError(f"DNS resolution returned no addresses for {host}")
        for _family, _stype, _proto, _canonname, sockaddr in result:
            if is_private_ip(sockaddr[0]):
                raise httpcore.ConnectError(f"SSRF blocked: {host} resolves to private IP")
        sorted_results = sorted(result, key=lambda r: (r[0] != socket.AF_INET,))
        last_err = None
        for _family, _stype, _proto, _canonname, sockaddr in sorted_results:
            try:
                return await super().connect_tcp(
                    sockaddr[0],
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except Exception as e:
                last_err = e
        raise httpcore.ConnectError(f"All addresses failed for {host}: {last_err}")


class _SSRFSafeAsyncTransport(httpx.AsyncHTTPTransport):
    """SSRF-safe async HTTP transport. Skips super().__init__ to avoid
    spinning up a default `AsyncConnectionPool` we'd immediately discard.
    """

    def __init__(self):
        self._pool = httpcore.AsyncConnectionPool(network_backend=_SSRFSafeAsyncBackend())


_ssrf_http = httpx.AsyncClient(
    transport=_SSRFSafeAsyncTransport(),
    timeout=httpx.Timeout(RECON_TIMEOUT, connect=5.0),
    headers={"User-Agent": USER_AGENT},
    # follow_redirects set per-request by callers
    max_redirects=5,
)


async def _safe_urlopen(domain: str, scheme: str, timeout: int, follow_redirects: bool = True):
    """SSRF-safe HTTP request. Validates all IPs (including redirect targets) before connecting."""
    return await _ssrf_http.get(
        f"{scheme}://{domain}/",
        timeout=timeout,
        follow_redirects=follow_redirects,
    )


async def fetch_live_headers(domain: str) -> dict:
    """Fetch HTTP response headers from a live domain (HTTPS/HTTP in parallel, first wins)."""

    async def _try_scheme(scheme):
        resp = await _safe_urlopen(domain, scheme, RECON_TIMEOUT)
        return {
            "headers": {k.lower(): v for k, v in resp.headers.items()},
            "status_code": resp.status_code,
            "url": str(resp.url),
        }

    https_t = asyncio.create_task(_try_scheme("https"))
    http_t = asyncio.create_task(_try_scheme("http"))
    errors: dict[str, str] = {}

    done, pending = await asyncio.wait({https_t, http_t}, return_when=asyncio.FIRST_COMPLETED)

    if https_t in done:
        # HTTPS finished first — return it (or fall back to HTTP on failure).
        try:
            result = https_t.result()
            for p in pending:
                p.cancel()
            return result
        except Exception as e:
            errors["https"] = type(e).__name__
            try:
                return await http_t
            except Exception as e2:
                errors["http"] = type(e2).__name__
    else:
        # HTTP finished first — give HTTPS up to 1s grace (matches sync semantics).
        try:
            http_result = http_t.result()
        except Exception as e:
            errors["http"] = type(e).__name__
            try:
                return await https_t
            except Exception as e2:
                errors["https"] = type(e2).__name__
        else:
            try:
                # asyncio.shield: 1s wait_for cancels the waiter, NOT the inner
                # task — preserves the sync `https_future.result(timeout=1.0)`
                # behaviour where HTTPS keeps running regardless.
                return await asyncio.wait_for(asyncio.shield(https_t), timeout=1.0)
            except (asyncio.TimeoutError, Exception):
                if not https_t.done():
                    https_t.cancel()
                return http_result

    logger.warning(
        "fetch_live_headers failed: HTTPS=%s, HTTP=%s",
        errors.get("https", "?"),
        errors.get("http", "?"),
    )
    return {"error": f"Could not connect to {domain}"}


MAX_HTML_SIZE = 65536  # 64KB


async def fetch_live_page(domain: str) -> dict:
    """Fetch HTTP headers AND HTML body (first 64KB) from a live domain (HTTPS/HTTP in parallel)."""

    async def _fetch(scheme):
        async with _ssrf_http.stream(
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
                async for chunk in resp.aiter_bytes():
                    chunks.append(chunk[:remaining])
                    remaining -= len(chunks[-1])
                    if remaining <= 0:
                        break
                raw = b"".join(chunks)
                html = raw.decode("utf-8", errors="ignore")
            return {"headers": headers, "html": html, "status_code": resp.status_code, "url": str(resp.url)}

    https_t = asyncio.create_task(_fetch("https"))
    http_t = asyncio.create_task(_fetch("http"))
    errors: dict[str, str] = {}

    done, pending = await asyncio.wait({https_t, http_t}, return_when=asyncio.FIRST_COMPLETED)

    if https_t in done:
        try:
            result = https_t.result()
            for p in pending:
                p.cancel()
            return result
        except Exception as e:
            errors["https"] = type(e).__name__
            try:
                return await http_t
            except Exception as e2:
                errors["http"] = type(e2).__name__
    else:
        try:
            http_result = http_t.result()
        except Exception as e:
            errors["http"] = type(e).__name__
            try:
                return await https_t
            except Exception as e2:
                errors["https"] = type(e2).__name__
        else:
            try:
                return await asyncio.wait_for(asyncio.shield(https_t), timeout=1.0)
            except (asyncio.TimeoutError, Exception):
                if not https_t.done():
                    https_t.cancel()
                return http_result

    logger.warning(
        "fetch_live_page failed: HTTPS=%s, HTTP=%s",
        errors.get("https", "?"),
        errors.get("http", "?"),
    )
    return {"error": f"Could not connect to {domain}"}


# === IP Enrichment (Shodan InternetDB) ===

INTERNETDB_URL = "https://internetdb.shodan.io/"


async def ip_enrichment(ip: str) -> dict:
    """Enrich IP with open ports, hostnames, vulns from Shodan InternetDB (free, no key)."""
    try:
        resp = await _http.get(f"{INTERNETDB_URL}{ip}")
        resp.raise_for_status()
        data = resp.json()
        return {
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "vulns": data.get("vulns", []),
            "cpes": data.get("cpes", []),
            "tags": data.get("tags", []),
            "internetdb_status": "ok",
        }
    except Exception as e:
        logger.debug("ip_enrichment failed: %s", type(e).__name__)
        return {"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": [], "internetdb_status": "error"}


# === Phone Lookup ===


def phone_lookup(number: str) -> dict:
    """Validate and extract intelligence from a phone number.

    Args:
        number: Phone number with or without + prefix (e.g. +905551234567).
    """
    if len(number) > 50:
        return {"valid": False, "number": "", "error": "Input too long (max 50 chars)"}

    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone

    try:
        parsed = phonenumbers.parse(number, None)
    except phonenumbers.NumberParseException:
        # Try with + prefix if missing
        if not number.startswith("+"):
            try:
                parsed = phonenumbers.parse("+" + number, None)
            except phonenumbers.NumberParseException:
                return {
                    "valid": False,
                    "number": number,
                    "error": "Could not parse phone number",
                }
        else:
            return {
                "valid": False,
                "number": number,
                "error": "Could not parse phone number",
            }

    valid = phonenumbers.is_valid_number(parsed)
    if not valid:
        return {
            "valid": False,
            "number": number,
            "error": "Phone number is not valid",
        }

    # Number formats
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    international = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)

    # Country
    region = phonenumbers.region_code_for_number(parsed)
    country_name = geocoder.country_name_for_number(parsed, "en") or ""

    # Number type
    num_type = phonenumbers.number_type(parsed)
    type_map = {
        phonenumbers.PhoneNumberType.MOBILE: "mobile",
        phonenumbers.PhoneNumberType.FIXED_LINE: "fixed_line",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
        phonenumbers.PhoneNumberType.VOIP: "voip",
        phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
        phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium_rate",
        phonenumbers.PhoneNumberType.SHARED_COST: "shared_cost",
        phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal_number",
        phonenumbers.PhoneNumberType.PAGER: "pager",
        phonenumbers.PhoneNumberType.UAN: "uan",
    }
    type_str = type_map.get(num_type, "unknown")

    # Carrier — libphonenumber's carrier DB is regional; US/CA/GB return empty
    # because mobile-number-portability rules forbid carrier inference. Distinguish
    # "no carrier mapping for this region" (unsupported_region) from a real carrier
    # name so agents do not interpret an empty string as the carrier's actual name.
    carrier_name = carrier.name_for_number(parsed, "en") or ""
    carrier_status = "known" if carrier_name else "unsupported_region"

    # Timezone
    tz_list = list(timezone.time_zones_for_number(parsed))

    # Summary
    parts = [e164]
    if country_name:
        parts.append(country_name)
    parts.append(type_str)
    if carrier_name:
        parts.append(carrier_name)
    summary = " — ".join(parts)

    return {
        "valid": True,
        "number": e164,
        "format": {
            "e164": e164,
            "international": international,
            "national": national,
        },
        "country_code": region or "",
        "country_name": country_name,
        "type": type_str,
        "carrier": carrier_name or None,
        "carrier_status": carrier_status,
        "timezone": tz_list,
        "summary": summary,
    }


# === Full Domain Report ===


async def full_domain_report(
    domain: str, resolved_ip: str | None = None, client_ip: str | None = None, lite: bool = False, tier: str = "free"
) -> dict:
    """Run domain intelligence checks in parallel, return combined report.

    When lite=True, only fast modules run (DNS, reverse DNS, email security,
    headers/WAF, SSL). Slow modules (crt.sh, subdomains, CT logs, WHOIS,
    live page, URLhaus, reputation) are skipped and return empty defaults.
    """
    report = {"domain": domain}

    from db import get_cached_ip, hash_client_ip, save_cached_ip
    from domain.reputation import check_abuseipdb, check_shodan
    from domain.threat import check_urlhaus

    # Determine whether reputation enrichment is allowed (skip in lite mode)
    enrich = False
    cached_rep = None
    if not lite and resolved_ip:
        cached_rep = get_cached_ip(resolved_ip)  # sync sqlite OK in async — microsecond IO
        if cached_rep is not None:
            enrich = True  # cache hit, no quota consumed
        elif client_ip and ratelimit.check_limit(
            store_name="enrichment",
            key=hash_client_ip(client_ip),
            max_requests=ENRICHMENT_DAILY_LIMIT,
            window_seconds=86400,
        ):
            enrich = True
            cached_rep = None

    # Fast modules (always run) — sync helpers in threadpool, async helpers awaited
    f_dns = asyncio.create_task(run_in_threadpool(dns_lookup, domain))
    f_rdns = asyncio.create_task(run_in_threadpool(reverse_dns, domain))
    f_ssl = asyncio.create_task(run_in_threadpool(ssl_info, domain, resolved_ip))
    f_headers = asyncio.create_task(fetch_live_headers(domain))

    # Slow modules (skip in lite mode)
    f_crtsh = f_whois = f_threat = f_subs = f_certs = None
    f_ab = f_sh = None
    if not lite:
        f_crtsh = asyncio.create_task(_fetch_crtsh(f"%.{domain}"))
        f_whois = asyncio.create_task(run_in_threadpool(whois_lookup, domain))
        f_threat = asyncio.create_task(check_urlhaus(domain))

        async def _subs_with_crtsh():
            # asyncio.shield prevents cancellation of f_crtsh from propagating
            # back into the shared crtsh task — both _subs and _ct depend on it.
            data, _ = await asyncio.wait_for(asyncio.shield(f_crtsh), timeout=CRTSH_TIMEOUT + 2)
            return await enumerate_subdomains(domain, crtsh_data=data)

        async def _ct_with_crtsh():
            data, fetch_error = await asyncio.wait_for(asyncio.shield(f_crtsh), timeout=CRTSH_TIMEOUT + 2)
            return await check_ct_logs(domain, data, crtsh_error=fetch_error)

        f_subs = asyncio.create_task(_subs_with_crtsh())
        f_certs = asyncio.create_task(_ct_with_crtsh())

        if enrich and cached_rep is None and resolved_ip and tier == "pro":
            f_ab = asyncio.create_task(check_abuseipdb(resolved_ip))
            f_sh = asyncio.create_task(check_shodan(resolved_ip))

    report["dns"] = await asyncio.wait_for(f_dns, timeout=RECON_TIMEOUT * 3)
    report["reverse_dns"] = await asyncio.wait_for(f_rdns, timeout=RECON_TIMEOUT * 2)
    report["ssl"] = await asyncio.wait_for(f_ssl, timeout=RECON_TIMEOUT * 2)

    if lite:
        report["whois"] = {}
        report["subdomains"] = {"subdomains": [], "count": 0}
        report["certificates"] = {"total_certificates": 0, "certificates": []}
        report["threat"] = {
            "urlhaus_status": "skipped",
            "url_count": 0,
            "urls_online": 0,
            "threat_types": [],
            "tags": [],
            "urls": [],
        }
    else:
        report["whois"] = await asyncio.wait_for(f_whois, timeout=RECON_TIMEOUT * 2)
        report["subdomains"] = await asyncio.wait_for(f_subs, timeout=CRTSH_TIMEOUT + RECON_TIMEOUT + 4)
        report["certificates"] = await asyncio.wait_for(f_certs, timeout=CRTSH_TIMEOUT + RECON_TIMEOUT + 4)
        report["threat"] = await asyncio.wait_for(f_threat, timeout=RECON_TIMEOUT * 2)

    if enrich and cached_rep is not None:
        report["reputation"] = cached_rep
    elif f_ab is not None:
        try:
            reputation = {
                "abuseipdb": await asyncio.wait_for(f_ab, timeout=RECON_TIMEOUT + 2),
                "shodan": await asyncio.wait_for(f_sh, timeout=RECON_TIMEOUT + 2),
            }
            save_cached_ip(resolved_ip, reputation)  # sync sqlite OK in async — microsecond IO
            report["reputation"] = reputation
        except Exception as e:
            logger.warning("Reputation enrichment failed: %s", type(e).__name__)
            if client_ip:
                await ratelimit.arefund("enrichment", hash_client_ip(client_ip))
    elif not lite and resolved_ip and tier != "pro":
        report["reputation"] = {
            "abuseipdb": {
                "status": "pro_only",
                "reason": "AbuseIPDB enrichment requires Pro tier",
                "upgrade_url": UPGRADE_URL,
            },
            "shodan": {
                "status": "pro_only",
                "reason": "Shodan enrichment requires Pro tier",
                "upgrade_url": UPGRADE_URL,
            },
        }

    # Email security uses DNS TXT records from dns_lookup (sequenced after f_dns)
    txt_records = report["dns"].get("txt", [])
    report["email_security"] = await asyncio.wait_for(
        run_in_threadpool(email_security, domain, txt_records), timeout=RECON_TIMEOUT * 2
    )

    # Detect WAF from headers (already fetched in parallel)
    header_result = await asyncio.wait_for(f_headers, timeout=RECON_TIMEOUT * 2)

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
