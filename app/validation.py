"""Input validation and IP detection for ContrastAPI"""

import ipaddress
import logging
import re
import socket

import dns.resolver
from config import MAX_DOMAIN_LENGTH
from fastapi import Request

logger = logging.getLogger("contrastapi")

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

# O(1) domain character validation
_DOMAIN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-")


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
            logger.info("DNS fallback resolved %s via dnspython", domain)
            return ip
        except Exception:
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


_TRUSTED_PROXIES = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}


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
