"""Username OSINT lookup — check if a username exists on 16 platforms."""

import asyncio
import logging
import random
import re

import httpx
from config import (
    MAX_USERNAME_LENGTH,
    USERNAME_BACKOFF_INITIAL,
    USERNAME_BACKOFF_MULTIPLIER,
    USERNAME_LOOKUP_TIMEOUT,
    USERNAME_MAX_RETRIES,
)

logger = logging.getLogger("contrastapi")

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]+$")

# Browser-like UAs rotated across retry attempts to dodge naive per-UA rate-limit buckets
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]

# Per-platform extra request headers (e.g. Cloudflare WAF wants Referer on npm)
_PLATFORM_EXTRA_HEADERS: dict[str, dict[str, str]] = {
    "npm": {"Referer": "https://www.npmjs.com/"},
}

_client = httpx.AsyncClient(
    timeout=httpx.Timeout(USERNAME_LOOKUP_TIMEOUT, connect=3.0),
    headers={"User-Agent": _USER_AGENTS[0], "Accept": "text/html,application/xhtml+xml"},
    follow_redirects=False,
    limits=httpx.Limits(max_connections=30, max_keepalive_connections=10),
)

# Platform definitions: (name, display_url, check_url|None, method, body_indicator)
# check_url: if different from display_url (e.g. Reddit JSON API). None = use display_url.
# method: "head" for simple 200/404 check, "get" when body inspection needed
# body_indicator: if set, presence of this string in body means NOT found
#   prefix with "!" to invert: "!needle" means needle MUST be present = found
PLATFORMS: list[tuple[str, str, str | None, str, str | None]] = [
    ("github", "https://github.com/{u}", None, "head", None),
    ("bitbucket", "https://bitbucket.org/{u}/", None, "head", None),
    ("reddit", "https://www.reddit.com/user/{u}", "https://www.reddit.com/user/{u}/about.json", "get", '"error"'),
    ("twitter", "https://x.com/{u}", None, "head", None),
    ("tiktok", "https://www.tiktok.com/@{u}", None, "get", 'statusCode":10221'),
    ("pinterest", "https://www.pinterest.com/{u}/", None, "get", "404"),
    ("telegram", "https://t.me/{u}", None, "get", "!tgme_page_extra"),
    ("steam", "https://steamcommunity.com/id/{u}", None, "get", "could not be found"),
    ("twitch", "https://www.twitch.tv/{u}", None, "head", None),
    ("medium", "https://medium.com/@{u}", None, "head", None),
    ("devto", "https://dev.to/{u}", None, "head", None),
    ("keybase", "https://keybase.io/{u}", None, "head", None),
    ("hackerone", "https://hackerone.com/{u}", None, "head", None),
    ("dockerhub", "https://hub.docker.com/u/{u}", None, "head", None),
    ("npm", "https://www.npmjs.com/~{u}", None, "head", None),
    ("mastodon", "https://mastodon.social/@{u}", None, "head", None),
]


def _request_headers(platform: str, attempt: int) -> dict[str, str]:
    """Build per-attempt headers: rotated UA + optional platform-specific extras."""
    headers = {"User-Agent": _USER_AGENTS[attempt % len(_USER_AGENTS)]}
    extra = _PLATFORM_EXTRA_HEADERS.get(platform)
    if extra:
        headers.update(extra)
    return headers


def _parse_200(indicator: str | None, method: str, body: str) -> str:
    """Classify a 200 response using the optional body indicator."""
    if indicator and method == "get":
        if indicator.startswith("!"):
            return "found" if indicator[1:] in body else "not_found"
        return "not_found" if indicator in body else "found"
    return "found"


async def _check_platform(
    name: str,
    display_url: str,
    check_url: str,
    method: str,
    indicator: str | None,
) -> dict:
    """Check a single platform with retry + UA rotation.

    Returns {"platform", "url", "status"} where status is one of:
    "found" | "not_found" | "rate_limited" | "blocked" | "timeout" | "error".
    """
    backoff = USERNAME_BACKOFF_INITIAL
    last_transient = "error"
    for attempt in range(USERNAME_MAX_RETRIES + 1):
        headers = _request_headers(name, attempt)
        try:
            if method == "get":
                resp = await _client.get(check_url, headers=headers)
            else:
                resp = await _client.head(check_url, headers=headers)

            code = resp.status_code

            if code == 200:
                status = _parse_200(indicator, method, resp.text)
                return {"platform": name, "url": display_url, "status": status}

            if code in (404, 410):
                return {"platform": name, "url": display_url, "status": "not_found"}

            if code in (301, 302, 303, 307, 308):
                return {"platform": name, "url": display_url, "status": "found"}

            if code == 429:
                last_transient = "rate_limited"
            elif code == 403:
                last_transient = "blocked"
            elif 500 <= code < 600:
                last_transient = "error"
            else:
                return {"platform": name, "url": display_url, "status": "error"}

        except httpx.TimeoutException:
            last_transient = "timeout"
        except (httpx.RequestError, OSError) as exc:
            logger.debug("username check %s failed: %s", name, type(exc).__name__)
            last_transient = "error"

        if attempt < USERNAME_MAX_RETRIES:
            await asyncio.sleep(backoff + random.uniform(0.1, 0.5))  # noqa: S311 — jitter only, not crypto
            backoff *= USERNAME_BACKOFF_MULTIPLIER

    return {"platform": name, "url": display_url, "status": last_transient}


async def username_lookup(username: str) -> dict:
    """Check if a username exists on 16 platforms.

    Args:
        username: The username to search for (alphanumeric, dot, underscore, hyphen).
    """
    raw = username.strip()
    if raw.startswith("@"):
        raw = raw[1:]

    if not raw:
        return {"username": "", "error": "Username is required"}

    if not _USERNAME_RE.match(raw):
        return {"error": "Invalid characters (allowed: a-z, 0-9, dot, underscore, hyphen)"}

    if len(raw) > MAX_USERNAME_LENGTH:
        return {"error": f"Input too long (max {MAX_USERNAME_LENGTH} chars)"}

    results = []
    seen_platforms: set[str] = set()

    plans: list[tuple[str, str, str, str, str | None]] = []
    for name, display_tpl, check_tpl, method, indicator in PLATFORMS:
        display_url = display_tpl.format(u=raw)
        check_url = check_tpl.format(u=raw) if check_tpl else display_url
        plans.append((name, display_url, check_url, method, indicator))

    # Wrap each coroutine in a Task so we can correlate done/pending back to the plan
    tasks: dict[asyncio.Task, tuple[str, str]] = {}
    for name, display_url, check_url, method, indicator in plans:
        task = asyncio.create_task(_check_platform(name, display_url, check_url, method, indicator))
        tasks[task] = (name, display_url)

    # Parity with the previous as_completed(timeout=...) semantics: collect any
    # task that finished before the deadline, mark the rest as error. Cancel
    # pending tasks so they do not leak past this call. Hard ceiling of 120s
    # defends against a misconfigured USERNAME_LOOKUP_TIMEOUT amplifying into
    # connection-pool exhaustion (16 platform tasks * runaway timeout).
    total_timeout = min(USERNAME_LOOKUP_TIMEOUT * 2 + 5, 120)
    done, pending = await asyncio.wait(tasks.keys(), timeout=total_timeout)
    for task in pending:
        task.cancel()

    for task in done:
        name, display_url = tasks[task]
        try:
            result = task.result()
            results.append(result)
            seen_platforms.add(result["platform"])
        except (httpx.TimeoutException, httpx.RequestError, OSError):
            results.append({"platform": name, "url": display_url, "status": "error"})
            seen_platforms.add(name)

    # Add missing platforms (cancelled-on-timeout or not yet completed)
    for name, display_tpl, *_ in PLATFORMS:
        if name not in seen_platforms:
            results.append({"platform": name, "url": display_tpl.format(u=raw), "status": "error"})

    # Sort: found first, then alphabetical
    results.sort(key=lambda r: (r["status"] != "found", r["platform"]))

    found = [r for r in results if r["status"] == "found"]
    found_count = len(found)
    checked_count = len(results)

    unavailable_statuses = {"rate_limited", "blocked", "timeout", "error"}
    unavailable = [r["platform"] for r in results if r["status"] in unavailable_statuses]
    queried = [p[0] for p in PLATFORMS]

    if found_count:
        platform_names = ", ".join(r["platform"] for r in found[:5])
        extra = f" +{found_count - 5} more" if found_count > 5 else ""
        summary = f"{raw} — found on {found_count}/{checked_count} platforms ({platform_names}{extra})"
    else:
        summary = f"{raw} — not found on any of {checked_count} platforms checked"
    if unavailable:
        summary += f" ({len(unavailable)} source(s) unavailable)"

    verdict = {
        "deterministic": False,
        "falsifiable_fields": ["found_count", "results"],
        "data_age_seconds": 0,
        "sources_queried": queried,
        "sources_unavailable": unavailable,
        "completeness": "partial" if unavailable else "complete",
    }

    return {
        "username": raw,
        "found_count": found_count,
        "checked_count": checked_count,
        "results": results,
        "summary": summary,
        "verdict": verdict,
    }
