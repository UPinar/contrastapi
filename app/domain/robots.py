"""robots.txt fetcher + parser for v1.25.0 web-intel endpoints.

Used directly by the `/v1/robots/{domain}` route, and reused by `seo_audit` /
`brand_assets` (Batch 5+6) to honour Disallow rules on homepage HTML fetches.

Parser: bespoke, because urllib.robotparser does not expose per-UA rule blocks
or sitemap lists in a format that cleanly maps to an MCP tool response. Robots
syntax is line-oriented and trivial; the spec lives at
https://www.rfc-editor.org/rfc/rfc9309. Unrecognised directives are dropped.

All fetched values pass through `_strip_control_chars` before they are stored
in the response — Trojan-Source / RTL bidi / DKIM-spoof characters cannot
escape the API surface.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from config import ROBOTS_MAX_BYTES, ROBOTS_TIMEOUT
from domain.recon import _ssrf_http, _strip_control_chars

logger = logging.getLogger("contrastapi")

# Spec-listed comment marker (RFC 9309 §2.4). Anything from `#` to EOL is dropped.
_COMMENT = "#"


def _split_directive(line: str) -> tuple[str, str] | None:
    """Return (directive_lowercase, value_stripped) or None if the line is
    blank/comment/malformed. Strips inline `# comment` tails per RFC 9309.
    """
    # Strip inline comment, then surrounding whitespace.
    if _COMMENT in line:
        line = line.split(_COMMENT, 1)[0]
    line = line.strip()
    if not line or ":" not in line:
        return None
    directive, _, value = line.partition(":")
    directive = directive.strip().lower()
    value = _strip_control_chars(value.strip())
    if not directive:
        return None
    return directive, value


def parse_robots_txt(body: str) -> dict:
    """Parse a robots.txt body into a dict matching `RobotsTxtResponse`.

    Returns: {
      "user_agents": {ua: {"allow": [...], "disallow": [...], "crawl_delay": float|None}, ...},
      "sitemaps":   [...],
      "host":       str|None,
    }
    """
    user_agents: dict[str, dict] = {}
    sitemaps: list[str] = []
    host: str | None = None

    # Per RFC 9309: a User-agent line opens a "group". Subsequent UA lines
    # *without* an intervening Allow/Disallow extend the same group; once a
    # rule appears, the group is "closed" and a new UA line opens a new group.
    current_uas: list[str] = []
    group_has_rules = False

    def _block(ua: str) -> dict:
        return user_agents.setdefault(ua, {"allow": [], "disallow": [], "crawl_delay": None})

    for raw_line in body.splitlines():
        parsed = _split_directive(raw_line)
        if not parsed:
            continue
        directive, value = parsed

        if directive == "user-agent":
            if not value:
                continue
            if group_has_rules:
                current_uas = []
                group_has_rules = False
            current_uas.append(value)
            _block(value)
        elif directive == "allow":
            for ua in current_uas:
                _block(ua)["allow"].append(value)
            group_has_rules = True
        elif directive == "disallow":
            for ua in current_uas:
                _block(ua)["disallow"].append(value)
            group_has_rules = True
        elif directive == "crawl-delay":
            try:
                cd = float(value)
            except (TypeError, ValueError):
                continue
            # Spec is silent on bounds; Google ignores Crawl-delay altogether
            # and most crawlers cap at sane values. Drop nonsense (negative,
            # NaN, > 24h) to avoid misleading agents into "wait 10 billion s".
            if cd != cd or cd < 0 or cd > 86400:
                continue
            for ua in current_uas:
                _block(ua)["crawl_delay"] = cd
            group_has_rules = True
        elif directive == "sitemap":
            if value:
                sitemaps.append(value)
        elif directive == "host":
            if value and host is None:
                host = value
        # Unrecognised directives silently ignored.

    return {"user_agents": user_agents, "sitemaps": sitemaps, "host": host}


def fetch_robots_txt(domain: str) -> dict:
    """Fetch + parse robots.txt for `domain` over HTTPS (HTTP fallback).

    Returns: {
      "domain": str,
      "fetched_url": str,
      "status_code": int,
      "user_agents": dict, "sitemaps": list, "host": str|None,
      "truncated": bool,
    }

    On hard fetch failure (DNS / TCP / TLS), raises an httpx exception — caller
    handles it and surfaces an `ErrorResponse`.
    """
    last_exc: Exception | None = None
    fetched_url = f"https://{domain}/robots.txt"
    status_code = 0
    body = ""
    truncated = False

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/robots.txt"
        try:
            with _ssrf_http.stream("GET", url, timeout=ROBOTS_TIMEOUT, follow_redirects=True) as resp:
                fetched_url = str(resp.url)
                status_code = resp.status_code
                # iter_bytes() returns RAW bytes (httpx does NOT auto-decompress
                # gzip/br on this path — only on iter_text/.text). The
                # ROBOTS_MAX_BYTES cap therefore bounds compressed-on-wire
                # bytes, which is what we want as a DoS guard against
                # decompression bombs. DO NOT switch to iter_text() without
                # adding a separate decompressed-size cap.
                buf = bytearray()
                for chunk in resp.iter_bytes():
                    buf += chunk
                    if len(buf) >= ROBOTS_MAX_BYTES:
                        truncated = True
                        break
                # Best-effort decode — robots.txt MUST be UTF-8 per RFC 9309 §2.2.
                body = bytes(buf[:ROBOTS_MAX_BYTES]).decode("utf-8", errors="replace")
            break  # success on https; do not fall back to http
        except Exception as exc:
            last_exc = exc
            logger.debug("robots.txt fetch failed for %s://%s/robots.txt: %s", scheme, domain, exc)
            continue
    else:
        # Both schemes raised — surface to caller.
        assert last_exc is not None
        raise last_exc

    parsed = (
        parse_robots_txt(body)
        if status_code == 200
        else {
            "user_agents": {},
            "sitemaps": [],
            "host": None,
        }
    )

    # Final URL must still belong to the queried domain — if the target served
    # a redirect to a different host, do NOT trust it as authoritative robots.
    final_host = (urlparse(fetched_url).hostname or "").lower()
    if status_code == 200 and final_host and not _is_same_or_subdomain(final_host, domain):
        # Reset to "no robots" rather than honouring a cross-host redirect.
        parsed = {"user_agents": {}, "sitemaps": [], "host": None}

    return {
        "domain": domain,
        "fetched_url": fetched_url,
        "status_code": status_code,
        "user_agents": parsed["user_agents"],
        "sitemaps": parsed["sitemaps"],
        "host": parsed["host"],
        "truncated": truncated,
    }


def _is_same_or_subdomain(candidate: str, base: str) -> bool:
    """True if `candidate` equals `base` or is a subdomain of it. Both lowercased."""
    candidate = candidate.lower().strip(".")
    base = base.lower().strip(".")
    return candidate == base or candidate.endswith("." + base)


def _exception_kind(exc: BaseException) -> str:
    """Map an httpx fetch exception to a coarse, agent-friendly category.

    Lets MCP agents distinguish transient failures (timeout, connect_reset)
    from permanent ones (tls_error, dns_failure) without parsing raw class
    names that may shift between httpx versions.
    """
    name = type(exc).__name__
    if "Timeout" in name:
        return "timeout"
    if "TLS" in name or "SSL" in name or "Certificate" in name:
        return "tls_error"
    if "ConnectError" in name or "Connect" in name:
        return "connect_error"
    if "Read" in name or "Stream" in name:
        return "read_error"
    return "unknown_error"
