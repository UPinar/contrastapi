"""Domain validation + SSRF defense for the website-scanner engine.

Ported from ContrastScan ``app/validation.py``, trimmed to what the scan
engine needs. Pure helpers — no FastAPI request handling here.
"""

import ipaddress
import socket

# Domains hosted on this server — scanning their public IP would loop through
# Cloudflare, so the engine scans them via localhost instead.
SELF_DOMAINS = frozenset({"contrastcyber.com", "www.contrastcyber.com"})


def clean_domain(domain: str) -> str:
    """Normalize raw user input to a bare lowercase hostname.

    Strips the http(s):// scheme, any path (everything after the first ``/``)
    and any ``:port`` suffix. Raises ``ValueError`` when nothing remains.
    """
    d = (domain or "").strip().lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix) :]
    d = d.split("/")[0]
    d = d.split(":")[0]
    if not d:
        raise ValueError("Empty domain")
    return d


def is_private_ip(ip: str) -> bool:
    """True when ``ip`` is RFC1918-private, loopback, or link-local.

    Returns False when the string does not parse as an IP address — the
    caller decides what a non-IP value means.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def validate_domain(domain: str) -> str:
    """Clean + validate ``domain``; return its resolved public IPv4 address.

    SSRF defense: rejects IP-literal input outright, resolves via the system
    resolver (IPv4 only), and rejects domains that resolve to a private,
    loopback, or link-local address. Raises ``ValueError`` on any failure.
    """
    cleaned = clean_domain(domain)
    try:
        ipaddress.ip_address(cleaned)
    except ValueError:
        pass  # not an IP literal — expected for a domain name
    else:
        raise ValueError("IP addresses are not allowed; provide a domain name")
    try:
        results = socket.getaddrinfo(cleaned, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError) as exc:
        raise ValueError(f"Could not resolve domain: {cleaned}") from exc
    if not results:
        raise ValueError(f"Could not resolve domain: {cleaned}")
    resolved_ip = results[0][4][0]
    if is_private_ip(resolved_ip):
        raise ValueError("Domain resolves to a private address")
    return resolved_ip


def get_resolved_ip_with_bypass(domain: str, resolved_ip: str | None = None) -> str | None:
    """Self-hosted domains bypass DNS and always scan via localhost."""
    if domain in SELF_DOMAINS:
        return "127.0.0.1"
    return resolved_ip
