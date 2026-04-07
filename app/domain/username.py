"""Username OSINT lookup — check if a username exists on 16 platforms."""

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
from config import MAX_USERNAME_LENGTH, USERNAME_LOOKUP_TIMEOUT

logger = logging.getLogger("contrastapi")

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]+$")

# Browser-like UA to avoid bot blocks
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

_client = httpx.Client(
    timeout=httpx.Timeout(USERNAME_LOOKUP_TIMEOUT, connect=3.0),
    headers={"User-Agent": _UA, "Accept": "text/html,application/xhtml+xml"},
    follow_redirects=False,
)

# Shared pool across requests — cap total threads to avoid exhaustion
_pool = ThreadPoolExecutor(max_workers=30)

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


def _check_platform(
    name: str,
    display_url: str,
    check_url: str,
    method: str,
    indicator: str | None,
) -> dict:
    """Check a single platform. Returns {"platform", "url", "status"}."""
    try:
        if method == "get":
            resp = _client.get(check_url)
        else:
            resp = _client.head(check_url)

        if resp.status_code == 200:
            if indicator and method == "get":
                # "!needle" = needle MUST be present for "found" (inverted)
                if indicator.startswith("!"):
                    needle = indicator[1:]
                    status = "found" if needle in resp.text else "not_found"
                else:
                    # Normal: needle present means NOT found
                    status = "not_found" if indicator in resp.text else "found"
                return {"platform": name, "url": display_url, "status": status}
            return {"platform": name, "url": display_url, "status": "found"}

        if resp.status_code in (404, 410):
            return {"platform": name, "url": display_url, "status": "not_found"}

        # 301/302 without follow = treat as found (profile exists, site redirects)
        if resp.status_code in (301, 302, 303, 307, 308):
            return {"platform": name, "url": display_url, "status": "found"}

        # 403/429/5xx = unreliable, report as error
        return {"platform": name, "url": display_url, "status": "error"}

    except (httpx.TimeoutException, httpx.RequestError, OSError) as exc:
        logger.debug("username check %s failed: %s", name, type(exc).__name__)
        return {"platform": name, "url": display_url, "status": "error"}


def username_lookup(username: str) -> dict:
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

    futures = {}
    for name, display_tpl, check_tpl, method, indicator in PLATFORMS:
        display_url = display_tpl.format(u=raw)
        check_url = check_tpl.format(u=raw) if check_tpl else display_url
        fut = _pool.submit(_check_platform, name, display_url, check_url, method, indicator)
        futures[fut] = name

    try:
        for fut in as_completed(futures, timeout=USERNAME_LOOKUP_TIMEOUT * 2 + 5):
            try:
                result = fut.result()
                results.append(result)
                seen_platforms.add(result["platform"])
            except (httpx.TimeoutException, httpx.RequestError, OSError):
                pname = futures[fut]
                results.append({"platform": pname, "url": "", "status": "error"})
                seen_platforms.add(pname)
    except TimeoutError:
        pass

    # Add missing platforms that timed out at the as_completed level
    for name, display_tpl, *_ in PLATFORMS:
        if name not in seen_platforms:
            results.append({"platform": name, "url": display_tpl.format(u=raw), "status": "error"})

    # Sort: found first, then alphabetical
    results.sort(key=lambda r: (r["status"] != "found", r["platform"]))

    found = [r for r in results if r["status"] == "found"]
    found_count = len(found)
    checked_count = len(results)

    if found_count:
        platform_names = ", ".join(r["platform"] for r in found[:5])
        extra = f" +{found_count - 5} more" if found_count > 5 else ""
        summary = f"{raw} — found on {found_count}/{checked_count} platforms ({platform_names}{extra})"
    else:
        summary = f"{raw} — not found on any of {checked_count} platforms checked"

    return {
        "username": raw,
        "found_count": found_count,
        "checked_count": checked_count,
        "results": results,
        "summary": summary,
    }
