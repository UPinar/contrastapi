"""Input validation and IP detection for ContrastAPI"""

import ipaddress
import logging
import re
import socket
from urllib.parse import urlparse

import dns.exception
import dns.resolver
from config import MAX_DOMAIN_LENGTH
from fastapi import Request

logger = logging.getLogger("contrastapi")

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$")

# O(1) domain character validation
_DOMAIN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-")

# B4a v1.30.0 — defense-in-depth allowlist for upstream API hosts we sync from.
# Last-mile guard: even if a config var is poisoned or a feed payload tampered,
# we refuse to fetch from an unknown host. NOT applicable to user-input fetchers
# (redirect_chain / brand_assets / robots) — those use the SSRF private-IP guard
# in domain.recon._SSRFSafeBackend instead, and by design accept arbitrary hosts.
ALLOWED_UPSTREAM_HOSTS = frozenset(
    {
        # CVE intel feeds
        "services.nvd.nist.gov",
        "nvd.nist.gov",
        "cveawg.mitre.org",
        "www.cve.org",
        "cwe.mitre.org",
        "api.github.com",
        "raw.githubusercontent.com",
        "api.osv.dev",
        "osv.dev",
        # Severity / exploit feeds
        "api.first.org",
        "epss.cyentia.com",
        "epss.empiricalsecurity.com",
        "www.cisa.gov",
        "www.exploit-db.com",
        # Threat / IP intel
        "api.shodan.io",
        "cvedb.shodan.io",
        "internetdb.shodan.io",
        "api.abuseipdb.com",
        "threatfox-api.abuse.ch",
        "feodotracker.abuse.ch",
        "urlhaus-api.abuse.ch",
        "mb-api.abuse.ch",
        "iplists.firehol.org",
        "check.torproject.org",
        "otx.alienvault.com",
        "ip-ranges.amazonaws.com",
        "www.gstatic.com",
        # Misc
        "api.pwnedpasswords.com",
        "api.cloudflare.com",
        "crt.sh",
        "web.archive.org",
        "archive.org",
    }
)


def assert_upstream_host_allowed(url: str) -> None:
    """Raise ValueError if url's host is not in ALLOWED_UPSTREAM_HOSTS.

    Defense-in-depth on internal sync clients (NVD/EPSS/KEV/MITRE/...) where the
    URL is supposed to point at a known upstream API. Any tampering — env var
    poisoning, dependency hijack, feed payload exfil-via-redirect — flags before
    the TCP connect happens.

    DO NOT call from user-input fetchers (redirect_chain, brand_assets, robots)
    — those legitimately accept arbitrary hosts and rely on _SSRFSafeBackend
    private-IP rejection instead.
    """
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Malformed URL: {exc}") from exc
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Refusing non-HTTP scheme: {parsed.scheme!r}")
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("URL is missing a hostname")
    if host not in ALLOWED_UPSTREAM_HOSTS:
        raise ValueError(f"Upstream host not in allowlist: {host}")


def clean_domain(raw: str) -> str:
    """Normalize domain input: strip protocol, userinfo, path, port, trailing dot."""
    d = raw.strip().lower()
    d = d.replace("\x00", "")
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix) :]
    # Strip userinfo (user:pass@host)
    if "@" in d:
        d = d.split("@", 1)[1]
    d = d.split("/")[0]
    d = d.split(":")[0]
    d = d.split("#")[0]
    d = d.rstrip(".")
    return d


def is_private_ip(ip_str: str) -> bool:
    """Check if IP is private, reserved, or non-global."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return (
            addr.is_private
            or addr.is_reserved
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
            or not addr.is_global
        )
    except ValueError:
        return True


def _dns_fallback(domain: str) -> str | None:
    """Fallback DNS resolution via dnspython with public resolvers."""
    for ns in ("8.8.8.8", "1.1.1.1"):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ns]
            resolver.timeout = 2
            resolver.lifetime = 3
            answers = resolver.resolve(domain, "A")
            ip = str(answers[0])
            if is_private_ip(ip):
                return None
            logger.info("DNS fallback resolved via dnspython")
            return ip
        except (dns.exception.DNSException, OSError):
            continue
    return None


def resolve_and_check(domain: str) -> str | None:
    """Resolve DNS and verify IP is not private. Return first valid IP or None."""
    # Try system resolver first with strict timeout
    import threading

    result_box = [None]
    exc_box = [None]

    def _resolve():
        try:
            result_box[0] = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
        except Exception as e:
            exc_box[0] = e

    t = threading.Thread(target=_resolve, daemon=True)
    t.start()
    t.join(timeout=3)
    if t.is_alive() or exc_box[0] is not None:
        return _dns_fallback(domain)
    results = result_box[0]
    if not results:
        return _dns_fallback(domain)
    # Check ALL resolved IPs — reject if any is private (prevents mixed-result bypass)
    for _family, _stype, _proto, _canonname, sockaddr in results:
        if is_private_ip(sockaddr[0]):
            return None
    # Return first resolved IP (all verified non-private)
    return results[0][4][0]


def _is_valid_format(domain: str) -> bool:
    """Check domain format without DNS resolution."""
    if not domain or len(domain) > MAX_DOMAIN_LENGTH:
        return False
    if "." not in domain:
        return False
    if not all(c in _DOMAIN_CHARS for c in domain):
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            return False
    return True


def validate_domain(domain: str) -> str | None:
    """Validate domain and return resolved IP, or None if invalid."""
    if not _is_valid_format(domain):
        return None
    return resolve_and_check(domain)


def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_cve_id(cve_id: str) -> bool:
    """Validate CVE ID format: CVE-YYYY-NNNNN"""
    return bool(CVE_ID_PATTERN.match(cve_id))


# v1.27 dynamic-budget bulk endpoints echo the un-processed input back in
# `skipped_due_to_rate_limit`. Raw input may carry CRLF, NUL, Trojan-Source bidi
# overrides, ANSI escapes, etc. — JSON encodes them safely, but downstream
# renderers (terminals, CLI tools, dashboards) interpret control chars. Strip
# non-printable codepoints and HTML-injection chars before echoing.
_ECHO_STRIP_PATTERN = re.compile(r"[<>&\"']")
_MAX_ECHO_LEN = 256


def sanitize_echo(value: str) -> str:
    """Sanitize a user-supplied string before echoing it back in a response.

    Drops non-printable Unicode (control chars, bidi overrides, NUL, CRLF) and
    common HTML-injection characters. Caps length so a 256-char input cannot
    inflate the response payload.
    """
    if not isinstance(value, str):
        return ""
    cleaned = "".join(c for c in value if c.isprintable())
    cleaned = _ECHO_STRIP_PATTERN.sub("", cleaned)
    return cleaned[:_MAX_ECHO_LEN]


_TRUSTED_PROXIES = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}


def swipe_ip_bucket(ip: str) -> str:
    """First-swipe identity bucket: IPv6 → its /64 network, IPv4 → exact.

    A single attacker typically controls a whole IPv6 /64, so per-address keying
    would make the one-time grant effectively unbounded. Malformed input falls
    through unchanged (defensive)."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 6:
            # IPv4-mapped (::ffff:a.b.c.d) → embedded IPv4; otherwise every mapped
            # address would /64-collapse to "::" and share one bucket.
            if addr.ipv4_mapped is not None:
                return str(addr.ipv4_mapped)
            return str(ipaddress.ip_network(f"{ip}/64", strict=False).network_address)
    except ValueError:
        pass
    return ip


def get_client_ip(request: Request) -> str:
    """Client IP — trust CF-Connecting-IP, X-Real-IP, X-Forwarded-For from known proxies."""
    direct_ip = request.client.host if request.client else "unknown"

    if direct_ip not in _TRUSTED_PROXIES:
        return direct_ip

    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        ip = cf_ip.strip()
        if is_valid_ip(ip):
            return ip
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        ip = real_ip.strip()
        if is_valid_ip(ip):
            return ip
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
        if is_valid_ip(ip):
            return ip
    return direct_ip
