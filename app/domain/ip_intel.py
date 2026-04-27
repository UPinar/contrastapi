"""IP intelligence caches: cloud provider CIDR lookup, Tor exit node detection, risk scoring."""

import ipaddress
import json
import logging
import threading
import time

import pytricia
from config import (
    AWS_IP_RANGES_URL,
    CF_IP_RANGES_URL,
    CLOUD_IP_MAX_BYTES,
    CLOUD_IP_TTL,
    FIREHOL_FAILURE_BACKOFF_SEC,
    FIREHOL_FAILURE_THRESHOLD,
    FIREHOL_LEVEL1_URL,
    FIREHOL_MAX_BYTES,
    FIREHOL_TTL,
    GCP_IP_RANGES_URL,
    TOR_EXIT_LIST_URL,
    TOR_EXIT_MAX_BYTES,
    TOR_EXIT_TTL,
)

logger = logging.getLogger("contrastapi")

# Cloud range cache: separate tries for IPv4 (32-bit) and IPv6 (128-bit)
_cloud_cache: dict = {"v4": None, "v6": None, "fetched_at": 0.0}
_cloud_lock = threading.Lock()

_tor_cache: dict = {
    "data": frozenset(),
    "fetched_at": 0.0,
    # Honesty metadata for the verdict layer (Bug NEW-B): without this every
    # `tor_exit=false` was indistinguishable from "fetch failed, list is
    # empty" — a known-Tor-exit IP would silently report tor_exit=false and
    # the agent had no way to tell. fetch_status is one of:
    # "initial" | "ok" | "failed" | "capped".
    "fetch_status": "initial",
    "line_count": 0,
}
_tor_lock = threading.Lock()

_firehol_cache: dict = {
    "v4": None,
    "v6": None,
    "fetched_at": 0.0,
    "consecutive_failures": 0,
    "last_failure_at": 0.0,
}
_firehol_lock = threading.Lock()


def _make_http_client():
    import httpx

    # follow_redirects=False: upstream URLs are hardcoded constants; a rogue
    # redirect (CDN compromise, DNS hijack) could otherwise steer us toward
    # loopback / cloud metadata endpoints.
    return httpx.Client(timeout=15.0, follow_redirects=False, verify=True)


def _fetch_capped(client, url: str, max_bytes: int) -> bytes | None:
    """Fetch URL with streaming early-abort when body exceeds max_bytes.

    Checks Content-Length header first, then enforces cap chunk-by-chunk.
    Returns raw body bytes on success, None if over the cap.
    """
    with client.stream("GET", url) as resp:
        resp.raise_for_status()
        cl = resp.headers.get("content-length")
        try:
            if cl is not None and int(cl) > max_bytes:
                return None
        except (TypeError, ValueError):
            pass
        buf = bytearray()
        for chunk in resp.iter_bytes():
            buf.extend(chunk)
            if len(buf) > max_bytes:
                return None
        return bytes(buf)


def _safe_insert(trie, cidr: str, value: str) -> None:
    """Insert CIDR into trie, skip with debug log if malformed."""
    try:
        trie[cidr] = value
    except (ValueError, TypeError) as e:
        logger.debug("skip malformed CIDR %s (%s): %s", cidr, value, type(e).__name__)


def _refresh_cloud_cache() -> tuple:
    """Fetch AWS/GCP/Cloudflare IP ranges and populate two PyTricia tries (v4, v6).

    Per-source failures preserve that source's prefixes from the previous cache.
    Total failure preserves previous cache entirely.
    """
    global _cloud_cache
    if time.time() - _cloud_cache["fetched_at"] < CLOUD_IP_TTL and _cloud_cache["v4"] is not None:
        return _cloud_cache["v4"], _cloud_cache["v6"]
    with _cloud_lock:
        if time.time() - _cloud_cache["fetched_at"] < CLOUD_IP_TTL and _cloud_cache["v4"] is not None:
            return _cloud_cache["v4"], _cloud_cache["v6"]

        prev_v4 = _cloud_cache.get("v4")
        prev_v6 = _cloud_cache.get("v6")

        v4 = pytricia.PyTricia(32)
        v6 = pytricia.PyTricia(128)
        loaded: set[str] = set()

        client = _make_http_client()
        try:
            # AWS — prefixes[].ip_prefix / ipv6_prefixes[].ipv6_prefix
            try:
                body = _fetch_capped(client, AWS_IP_RANGES_URL, CLOUD_IP_MAX_BYTES)
                if body is None:
                    logger.warning("AWS IP ranges exceeded cap (%d bytes)", CLOUD_IP_MAX_BYTES)
                else:
                    data = json.loads(body)
                    for p in data.get("prefixes") or []:
                        cidr = p.get("ip_prefix")
                        if cidr:
                            _safe_insert(v4, cidr, "AWS")
                    for p in data.get("ipv6_prefixes") or []:
                        cidr = p.get("ipv6_prefix")
                        if cidr:
                            _safe_insert(v6, cidr, "AWS")
                    loaded.add("AWS")
            except Exception as e:
                logger.warning("AWS IP ranges fetch failed: %s", type(e).__name__)

            # GCP — prefixes[].ipv4Prefix / ipv6Prefix
            try:
                body = _fetch_capped(client, GCP_IP_RANGES_URL, CLOUD_IP_MAX_BYTES)
                if body is None:
                    logger.warning("GCP IP ranges exceeded cap (%d bytes)", CLOUD_IP_MAX_BYTES)
                else:
                    data = json.loads(body)
                    for p in data.get("prefixes") or []:
                        cidr4 = p.get("ipv4Prefix")
                        if cidr4:
                            _safe_insert(v4, cidr4, "GCP")
                        cidr6 = p.get("ipv6Prefix")
                        if cidr6:
                            _safe_insert(v6, cidr6, "GCP")
                    loaded.add("GCP")
            except Exception as e:
                logger.warning("GCP IP ranges fetch failed: %s", type(e).__name__)

            # Cloudflare — result.ipv4_cidrs / result.ipv6_cidrs (ignore result.tor_ips)
            try:
                body = _fetch_capped(client, CF_IP_RANGES_URL, CLOUD_IP_MAX_BYTES)
                if body is None:
                    logger.warning("CF IP ranges exceeded cap (%d bytes)", CLOUD_IP_MAX_BYTES)
                else:
                    data = json.loads(body)
                    result = data.get("result") or {}
                    for cidr in result.get("ipv4_cidrs") or []:
                        _safe_insert(v4, cidr, "Cloudflare")
                    for cidr in result.get("ipv6_cidrs") or []:
                        _safe_insert(v6, cidr, "Cloudflare")
                    loaded.add("Cloudflare")
            except Exception as e:
                logger.warning("CF IP ranges fetch failed: %s", type(e).__name__)

        finally:
            client.close()

        # Preserve previous prefixes for any failed source.
        # Snapshot prefix lists before iterating: concurrent readers may still
        # be calling check_cloud_provider() against prev_v4/prev_v6 (no lock on
        # read path), and PyTricia's C-extension iterator is not documented
        # reentrant-safe against concurrent lookups.
        failed = {"AWS", "GCP", "Cloudflare"} - loaded
        if failed and prev_v4 is not None:
            prev_v4_keys = list(prev_v4)
            prev_v6_keys = list(prev_v6) if prev_v6 is not None else []
            for src in failed:
                for prefix in prev_v4_keys:
                    if prev_v4[prefix] == src:
                        _safe_insert(v4, prefix, src)
                for prefix in prev_v6_keys:
                    if prev_v6[prefix] == src:
                        _safe_insert(v6, prefix, src)

        _cloud_cache = {"v4": v4, "v6": v6, "fetched_at": time.time()}
        logger.info("Cloud IP ranges loaded: %s (failed→prev: %s)", sorted(loaded), sorted(failed))
        return v4, v6


def _refresh_tor_cache() -> frozenset:
    """Fetch Tor bulk exit list (one IP per line). Returns frozenset of exit IPs.

    TTL gating is based on fetched_at (not data truthiness) so a first-fetch
    failure does not perpetually skip retries. On failure returns previously
    cached set (or empty frozenset).
    """
    global _tor_cache
    if time.time() - _tor_cache["fetched_at"] < TOR_EXIT_TTL and _tor_cache["fetched_at"] > 0:
        return _tor_cache["data"]
    with _tor_lock:
        if time.time() - _tor_cache["fetched_at"] < TOR_EXIT_TTL and _tor_cache["fetched_at"] > 0:
            return _tor_cache["data"]
        client = _make_http_client()
        try:
            body = _fetch_capped(client, TOR_EXIT_LIST_URL, TOR_EXIT_MAX_BYTES)
            if body is None:
                logger.warning("Tor exit list exceeded cap (%d bytes)", TOR_EXIT_MAX_BYTES)
                _tor_cache = {
                    **_tor_cache,
                    "fetch_status": "capped",
                    # bump fetched_at so we honour the TTL — otherwise every
                    # request hammers the upstream while it is misbehaving.
                    "fetched_at": time.time(),
                }
                return _tor_cache.get("data", frozenset())
            ips_set: set[str] = set()
            for line in body.decode("utf-8", errors="replace").splitlines():
                candidate = line.strip()
                if not candidate or candidate.startswith("#"):
                    continue
                try:
                    ipaddress.ip_address(candidate)
                except ValueError:
                    logger.debug("skip malformed Tor exit line: %r", candidate[:64])
                    continue
                ips_set.add(candidate)
            ips = frozenset(ips_set)
            _tor_cache = {
                "data": ips,
                "fetched_at": time.time(),
                "fetch_status": "ok",
                "line_count": len(ips),
            }
            logger.info("Tor exit list loaded: %d IPs", len(ips))
            return ips
        except Exception as e:
            logger.warning("Tor exit list fetch failed: %s", type(e).__name__)
            _tor_cache = {
                **_tor_cache,
                "fetch_status": "failed",
                "fetched_at": time.time(),
            }
            return _tor_cache.get("data", frozenset())
        finally:
            client.close()


def tor_cache_status() -> str:
    """Expose `_tor_cache["fetch_status"]` for the verdict layer.

    Returns one of "initial" | "ok" | "failed" | "capped". The route handler
    uses this to add "tor" to verdict.sources_unavailable when the upstream
    list is missing — so a downstream agent can tell `tor_exit=false because
    not in list` from `tor_exit=false because we never got the list`.

    Holds `_tor_lock` to keep the read consistent with the dict-replace
    pattern used by `_refresh_tor_cache`. CPython's GIL makes a single
    `dict.get` atomic, but reading without the lock would still let a status
    appear stale across a concurrent refresh on a non-GIL runtime.
    """
    with _tor_lock:
        return _tor_cache.get("fetch_status", "initial")


def _strip_zone(ip: str) -> str:
    # pytricia rejects IPv6 zone IDs (fe80::1%eth0); ipaddress accepts them.
    # Strip so a zone-scoped input becomes a plain lookup instead of an exception.
    return ip.split("%", 1)[0] if "%" in ip else ip


# ASN-to-provider fallback map — used when an IP isn't in the published cloud
# CIDR ranges (AWS/GCP/Cloudflare) but the ASN is unambiguously owned by a
# known provider. Covers Google's anycast DNS infra (8.8.8.8 / AS15169) which
# isn't in the GCP cloud range list, plus other major hosters.
#
# Selection criteria: tier-1 cloud / DNS / hosting operators whose ASN ownership
# is unambiguous and stable. Source: IANA RIR allocations + vendor docs.
# Last audit: 2026-04-25. ASN reassignments are rare but possible (M&A, RIR
# transfers); revisit quarterly. ASN comes from RIPE Stat (authoritative BGP
# origin) — if BGP is hijacked, cloud_provider will reflect the attacker's
# advertised ASN, not the true operator. Acceptable: we report current BGP
# state, and the verdict block carries source provenance.
_ASN_TO_CLOUD_PROVIDER: dict[int, str] = {
    15169: "Google",
    396982: "Google",
    16509: "AWS",
    14618: "AWS",
    8075: "Microsoft",
    13335: "Cloudflare",
    14061: "DigitalOcean",
    24940: "Hetzner",
    16276: "OVH",
    63949: "Linode",
    20473: "Vultr",
}


def check_cloud_provider(ip: str, asn: int | None = None) -> str | None:
    """Return cloud provider name if IP is in a known cloud CIDR range OR its
    ASN is in the static map; else None.

    The CIDR-based lookup (AWS/GCP/Cloudflare) is authoritative when it matches.
    The ASN map is a fallback for providers whose anycast / public-service IPs
    sit outside their published cloud ranges (e.g. 8.8.8.8 is AS15169 Google
    but not in the GCP IP range list).
    """
    try:
        ip_clean = _strip_zone(ip)
        v4, v6 = _refresh_cloud_cache()
        trie = v6 if ":" in ip_clean else v4
        if trie is not None:
            cidr_match = trie.get(ip_clean)
            if cidr_match:
                return cidr_match
    except Exception as e:
        logger.warning("check_cloud_provider CIDR lookup failed: %s", type(e).__name__)
    # bool⊂int in Python; reject bool. Also reject zero/negative ASNs (real
    # ASNs are positive 32-bit ints) so a corrupt upstream value can't hit
    # the dict and silently miss without log signal.
    if isinstance(asn, int) and not isinstance(asn, bool) and asn > 0:
        return _ASN_TO_CLOUD_PROVIDER.get(asn)
    return None


def check_tor_exit(ip: str) -> bool:
    """Return True if IP is a known Tor exit node."""
    try:
        exits = _refresh_tor_cache()
        return _strip_zone(ip) in exits
    except Exception as e:
        logger.warning("check_tor_exit failed: %s", type(e).__name__)
        return False


def _refresh_firehol_cache() -> tuple:
    """Fetch FireHOL level1 netset, build PyTricia tries (v4 + v6).

    Returns (v4_trie, v6_trie). On fetch failure returns previously cached
    tries (or (None, None) on cold failure). TTL guards thrashing on success;
    a consecutive-failure counter trips a short backoff to avoid amplifying
    upstream outages (free tier calls this inline per request).

    Line format: one CIDR or bare IP per line; '#' comments skipped; blanks
    skipped. IPv6 CIDRs occur but are rare in level1.
    """
    global _firehol_cache
    now = time.time()
    if now - _firehol_cache["fetched_at"] < FIREHOL_TTL and _firehol_cache["fetched_at"] > 0:
        return _firehol_cache["v4"], _firehol_cache["v6"]
    if (
        _firehol_cache["consecutive_failures"] >= FIREHOL_FAILURE_THRESHOLD
        and now - _firehol_cache["last_failure_at"] < FIREHOL_FAILURE_BACKOFF_SEC
    ):
        return _firehol_cache.get("v4"), _firehol_cache.get("v6")
    with _firehol_lock:
        now = time.time()
        if now - _firehol_cache["fetched_at"] < FIREHOL_TTL and _firehol_cache["fetched_at"] > 0:
            return _firehol_cache["v4"], _firehol_cache["v6"]
        if (
            _firehol_cache["consecutive_failures"] >= FIREHOL_FAILURE_THRESHOLD
            and now - _firehol_cache["last_failure_at"] < FIREHOL_FAILURE_BACKOFF_SEC
        ):
            return _firehol_cache.get("v4"), _firehol_cache.get("v6")
        client = _make_http_client()
        try:
            body = _fetch_capped(client, FIREHOL_LEVEL1_URL, FIREHOL_MAX_BYTES)
            if body is None:
                logger.warning("FireHOL level1 exceeded cap (%d bytes)", FIREHOL_MAX_BYTES)
                _firehol_cache["consecutive_failures"] += 1
                _firehol_cache["last_failure_at"] = time.time()
                return _firehol_cache.get("v4"), _firehol_cache.get("v6")
            v4 = pytricia.PyTricia(32)
            v6 = pytricia.PyTricia(128)
            count_v4 = count_v6 = 0
            for line in body.decode("utf-8", errors="replace").splitlines():
                candidate = line.strip()
                if not candidate or candidate.startswith("#"):
                    continue
                try:
                    net = ipaddress.ip_network(candidate, strict=False)
                except ValueError:
                    logger.debug("skip malformed FireHOL line: %r", candidate[:64])
                    continue
                if net.version == 4:
                    v4[str(net)] = True
                    count_v4 += 1
                else:
                    v6[str(net)] = True
                    count_v6 += 1
            _firehol_cache = {
                "v4": v4,
                "v6": v6,
                "fetched_at": time.time(),
                "consecutive_failures": 0,
                "last_failure_at": 0.0,
            }
            logger.info("FireHOL level1 loaded: %d v4 / %d v6 prefixes", count_v4, count_v6)
            return v4, v6
        except Exception as e:
            logger.warning("FireHOL level1 fetch failed: %s", type(e).__name__)
            _firehol_cache["consecutive_failures"] += 1
            _firehol_cache["last_failure_at"] = time.time()
            return _firehol_cache.get("v4"), _firehol_cache.get("v6")
        finally:
            client.close()


def check_firehol(ip: str) -> dict:
    """Check FireHOL level1 blocklist membership.

    Returns one of:
        {"status":"ok",          "listed": bool, "lists_matched": [...]}
        {"status":"skipped",     "listed": False, "lists_matched": []}  # private/reserved
        {"status":"unavailable", "listed": False, "lists_matched": []}  # fetch never succeeded
    """
    stripped = _strip_zone(ip)
    try:
        addr = ipaddress.ip_address(stripped)
        if addr.is_private or addr.is_reserved or addr.is_loopback or addr.is_link_local:
            return {"status": "skipped", "listed": False, "lists_matched": []}
    except ValueError:
        return {"status": "skipped", "listed": False, "lists_matched": []}

    try:
        v4, v6 = _refresh_firehol_cache()
        trie = v6 if ":" in stripped else v4
        if trie is None:
            return {"status": "unavailable", "listed": False, "lists_matched": []}
        listed = stripped in trie
        return {
            "status": "ok",
            "listed": listed,
            "lists_matched": ["firehol_level1"] if listed else [],
        }
    except Exception as e:
        logger.warning("check_firehol failed: %s", type(e).__name__)
        return {"status": "unavailable", "listed": False, "lists_matched": []}


def score_ip(
    reputation: dict | None,
    ports: list,
    ptr: str | None,
    cloud_provider: str | None,
    tor_exit: bool,
) -> int:
    """Compute 0-100 composite risk score. Higher = riskier."""
    abuse_score = 0
    if reputation:
        try:
            abuse_score = int(reputation.get("abuseipdb", {}).get("abuse_score", 0) or 0)
        except (TypeError, ValueError):
            abuse_score = 0

    penalty_abuse = min(abuse_score, 60)
    penalty_tor = 20 if tor_exit else 0
    penalty_ports = min(len(ports) * 2, 10) if ports else 0
    bonus_cloud = 10 if cloud_provider else 0
    bonus_ptr = 5 if ptr else 0

    score = penalty_abuse + penalty_tor + penalty_ports - bonus_cloud - bonus_ptr
    return max(0, min(100, score))
