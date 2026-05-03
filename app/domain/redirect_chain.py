"""Manual redirect-chain walker for v1.25.0 web-intel endpoints.

httpx supports `follow_redirects=True` natively, but that hides each hop from
us. We need each hop visible so:

1. The SSRF guard re-validates the resolved IP at every Location target —
   a target that 302s to 127.0.0.1 must be aborted, not silently followed.
2. `target_throttle` consumes one slot per *target host* visited — a chain
   that crosses 10 unrelated domains (`a.com -> b.com -> c.com -> ...`)
   counts against each domain's per-eTLD+1 cap, so the redirect endpoint
   can't be turned into a free-for-all anonymity layer.
3. The agent gets a structured per-hop record (status, latency, Location)
   it can show the user, not just "final URL".

Each hop's URL + Location is passed through `_strip_control_chars` so
Trojan-Source / RTL bidi / ANSI-escape characters in attacker-controlled
Location headers can't leak into the JSON response.
"""

from __future__ import annotations

import logging
import time
from urllib.parse import urljoin, urlparse

from config import REDIRECT_MAX_HOPS, REDIRECT_TIMEOUT
from domain.recon import _ssrf_http, _strip_control_chars


class TargetThrottleHopExceeded(Exception):
    """Raised mid-chain when a hop's eTLD+1 has exhausted its 60/min cap.

    Carries the offending host + retry_after_seconds so the route handler can
    return a clean 429 response with a Retry-After header.
    """

    def __init__(self, host: str, retry_after: int):
        self.host = host
        self.retry_after = retry_after
        super().__init__(f"target_throttle: hop host {host!r} exceeded per-domain limit")


logger = logging.getLogger("contrastapi")


def _validate_url(url: str) -> tuple[str, str]:
    """Return (scheme, host) or raise ValueError. Rejects non-HTTP schemes and
    URLs without a host so a malicious target can't redirect us to
    `file:///etc/passwd` or `gopher://internal:25`.
    """
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in url):
        raise ValueError("URL contains control characters")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Only http/https schemes allowed (got {parsed.scheme!r})")
    if not parsed.hostname:
        raise ValueError("URL must have a host")
    return parsed.scheme, parsed.hostname


async def walk_redirect_chain(start_url: str, max_hops: int = REDIRECT_MAX_HOPS) -> dict:
    """Hop-by-hop redirect walk. Up to `max_hops` HTTP fetches.

    Returns: {
      "start_url": str,
      "final_url": str,
      "hops": [{"url", "status_code", "location", "latency_ms"}, ...],
      "hop_count": int,
      "final_status": int,
      "loop_detected": bool,
      "truncated": bool,
    }

    Raises ValueError on malformed start_url. Hard fetch failures (DNS / TCP /
    TLS / SSRF rejection) propagate as httpx exceptions — the route handler
    decides how to surface them.

    SSRF / DNS-rebind note: `_ssrf_http`'s connection pool reuses connections
    keyed by (scheme, host, port). Within a single chain we never revisit the
    same URL (visited-set break), but multiple *invocations* against the same
    host could in theory share a pooled connection that was opened against an
    initially-public IP and later DNS-rebound. The IP is re-validated at TCP
    connect time, so a *new* connection always sees the current resolution;
    pool reuse only matters if a public→private rebind happens after the
    initial validate AND the keep-alive socket is still open. httpx's default
    keep-alive idle is ~5s, so the practical rebind window is small.
    Acceptable risk for a per-target-throttled (60/min/eTLD+1) endpoint
    backed by a 1h domain cache; revisit if customer reports surface.
    """
    _validate_url(start_url)

    # Lazy import — target_throttle pulls config + ratelimit which would
    # circular-import via routes.py at module-load time.
    from target_throttle import consume_target_throttle

    hops: list[dict] = []
    visited: set[str] = set()
    seen_hosts: set[str] = set()  # hosts that already counted toward target_throttle this call
    current_url = start_url
    truncated = False
    loop_detected = False

    for hop_num in range(max_hops):
        if current_url in visited:
            loop_detected = True
            break
        visited.add(current_url)

        # Per-target throttle on each *new* host reached in the chain. The
        # first host's throttle slot is consumed by the route handler before
        # this function runs; subsequent hops to a different host must
        # consume their own slot so a chain across many domains can't
        # weaponise the API as an open redirector.
        host = (urlparse(current_url).hostname or "").lower()
        if host and host not in seen_hosts and hop_num > 0:
            allowed, retry = consume_target_throttle(host)
            if not allowed:
                raise TargetThrottleHopExceeded(host, retry)
        if host:
            seen_hosts.add(host)

        # stream=True so we don't pull the body of a final 200 response —
        # redirect chains rarely care about the terminal page content, and
        # skipping the body saves us from gigabyte-sized HTML pages on
        # hop_count == 1 single-fetch lookups.
        t0 = time.time()
        async with _ssrf_http.stream("GET", current_url, follow_redirects=False, timeout=REDIRECT_TIMEOUT) as resp:
            latency_ms = int((time.time() - t0) * 1000)
            status_code = resp.status_code
            raw_location = resp.headers.get("location")
            response_url = str(resp.url)
            # Drain just enough to release the connection cleanly. httpx will
            # close the body on context exit so we don't actually need to
            # iterate. Belt-and-braces — `resp.close()` is implicit on exit.

        absolute_location: str | None = None
        if raw_location:
            try:
                absolute_location = urljoin(response_url, raw_location)
                # Re-validate the redirect target's scheme/host BEFORE we follow.
                # The SSRF guard catches private IPs at TCP-connect time, but
                # rejecting non-HTTP schemes here gives a cleaner error path.
                _validate_url(absolute_location)
            except ValueError as exc:
                logger.info("redirect_chain: rejecting hop %d redirect (%s)", hop_num + 1, exc)
                absolute_location = None

        hops.append(
            {
                "url": _strip_control_chars(current_url),
                "status_code": status_code,
                "location": _strip_control_chars(absolute_location) if absolute_location else None,
                "latency_ms": latency_ms,
            }
        )

        is_redirect = 300 <= status_code < 400 and absolute_location is not None
        if not is_redirect:
            break  # terminal response

        if hop_num == max_hops - 1:
            truncated = True
            break

        current_url = absolute_location

    if hops:
        last = hops[-1]
        if loop_detected or truncated:
            # Final URL is "where we would have gone" — useful for the agent
            # but we did NOT actually fetch it.
            final_url = last["location"] or last["url"]
        elif 300 <= last["status_code"] < 400 and last["location"]:
            final_url = last["location"]
        else:
            final_url = last["url"]
        final_status = last["status_code"]
    else:
        final_url = start_url
        final_status = 0

    return {
        "start_url": _strip_control_chars(start_url),
        "final_url": _strip_control_chars(final_url),
        "hops": hops,
        "hop_count": len(hops),
        "final_status": final_status,
        "loop_detected": loop_detected,
        "truncated": truncated,
    }
