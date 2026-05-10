"""High-level convenience helpers that compose multiple namespace calls.

These wrap common multi-call patterns so callers don't have to glue endpoints
together by hand. Each helper accepts a `ContrastAPI` (sync) instance; async
variants are intentionally omitted in this batch — call the async client's
namespace methods directly with `asyncio.gather` if you need parallelism.

Convention: shortcuts swallow per-leg ContrastAPIError instances and report
them in the returned dict under `errors[<key>]` so a partial failure doesn't
nuke the whole report. The caller still gets every leg that succeeded.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .client import ContrastAPI
from .exceptions import ContrastAPIError, TransportError

_HEX64 = re.compile(r"^[0-9a-fA-F]{32,128}$")


def _record_or_reraise(out: dict[str, Any], key: str, exc: ContrastAPIError) -> None:
    """Record a per-leg failure into the helper's error dict — but propagate
    `TransportError` (network/MITM/DNS-poison) so security incidents aren't
    masked as opaque error strings. Application-layer errors (4xx/5xx) keep
    the swallow-and-report behaviour callers depend on for partial-success
    reports.
    """
    if isinstance(exc, TransportError):
        raise exc
    out["errors"][key] = exc.message


def _classify_ioc(value: str) -> str:
    """Best-effort IOC type detection: 'ip' | 'hash' | 'domain' | 'unknown'.

    Mirrors the server's input router so callers see the same routing the API
    would apply. Domain is the broad fallback (anything with a dot or letters).
    """
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if _HEX64.match(value):
        return "hash"
    if "." in value or value.replace("-", "").isalnum():
        return "domain"
    return "unknown"


def triage_ioc(client: ContrastAPI, indicator: str) -> dict[str, Any]:
    """Run the right enrichment for a single IOC.

    For an IP: ioc_lookup + threat_report.
    For a domain: ioc_lookup + domain_report.
    For a hash: ioc_lookup + hash_lookup.
    Any unrecognised input still gets ioc_lookup (the server is the final word).

    Returns:
        {"indicator": ..., "kind": ..., "ioc": {...}, "threat_report"|"domain_report"|"hash": {...},
         "errors": {<leg>: <error message>}}
    """
    kind = _classify_ioc(indicator)
    out: dict[str, Any] = {"indicator": indicator, "kind": kind, "errors": {}}

    try:
        out["ioc"] = client.ioc.lookup(indicator)
    except ContrastAPIError as exc:
        _record_or_reraise(out, "ioc", exc)

    if kind == "ip":
        try:
            out["threat_report"] = client.ip.threat_report(indicator)
        except ContrastAPIError as exc:
            _record_or_reraise(out, "threat_report", exc)
    elif kind == "domain":
        try:
            out["domain_report"] = client.domain.report(indicator)
        except ContrastAPIError as exc:
            _record_or_reraise(out, "domain_report", exc)
    elif kind == "hash":
        try:
            out["hash"] = client.ioc.hash(indicator)
        except ContrastAPIError as exc:
            _record_or_reraise(out, "hash", exc)

    return out


def audit_full(
    client: ContrastAPI,
    domain: str,
    *,
    ssl_subdomains: int = 5,
) -> dict[str, Any]:
    """Run a deep audit on a domain.

    Composes `audit_domain` + `subdomain_enum` (top-N) + `tech_fingerprint` +
    per-subdomain `ssl_check` (capped at `ssl_subdomains` to keep credit cost
    bounded — default 5).

    Returns a dict with `audit`, `subdomains`, `tech`, `ssl` (per-subdomain
    map), and `errors` (per-leg failure messages).
    """
    if ssl_subdomains < 0:
        raise ValueError("ssl_subdomains must be >= 0")

    out: dict[str, Any] = {"domain": domain, "errors": {}, "ssl": {}}

    try:
        out["audit"] = client.domain.audit(domain)
    except ContrastAPIError as exc:
        _record_or_reraise(out, "audit", exc)

    subdomains: list[str] = []
    try:
        sub_response = client.domain.subdomains(domain)
        out["subdomains"] = sub_response
        # Server response shape: {"subdomains": [...], "count": N, ...}
        candidates = sub_response.get("subdomains") or []
        subdomains = [s for s in candidates if isinstance(s, str)][:ssl_subdomains]
    except ContrastAPIError as exc:
        _record_or_reraise(out, "subdomains", exc)

    try:
        out["tech"] = client.domain.tech(domain)
    except ContrastAPIError as exc:
        _record_or_reraise(out, "tech", exc)

    for sub in subdomains:
        try:
            out["ssl"][sub] = client.domain.ssl(sub)
        except ContrastAPIError as exc:
            _record_or_reraise(out, f"ssl:{sub}", exc)

    return out


def enrich_batch(client: ContrastAPI, items: list[str]) -> dict[str, Any]:
    """Auto-detect IOC vs CVE for each item and route to the right bulk endpoint.

    Items matching the `CVE-YYYY-NNNN+` pattern go to `cve.bulk`; everything
    else goes to `ioc.bulk`. If both buckets are non-empty the helper makes two
    calls; if only one bucket has items it makes a single call. Returns:

        {"cve": <bulk_cve_response or None>, "ioc": <bulk_ioc_response or None>,
         "routed": {"cve": [...], "ioc": [...]}, "errors": {...}}
    """
    if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
        raise ValueError("items must be a list of strings")

    # Match server-side validator: uppercase canonical, NVD spec allows 3+
    # digit suffix (e.g. CVE-2024-123 is valid). Lowercase routes to IOC bucket.
    cve_pattern = re.compile(r"^CVE-\d{4}-\d{3,}$")
    cves = [i for i in items if cve_pattern.match(i)]
    iocs = [i for i in items if not cve_pattern.match(i)]

    out: dict[str, Any] = {
        "cve": None,
        "ioc": None,
        "routed": {"cve": cves, "ioc": iocs},
        "errors": {},
    }

    if cves:
        try:
            out["cve"] = client.cve.bulk(cves)
        except ContrastAPIError as exc:
            _record_or_reraise(out, "cve", exc)

    if iocs:
        try:
            out["ioc"] = client.ioc.bulk(iocs)
        except ContrastAPIError as exc:
            _record_or_reraise(out, "ioc", exc)

    return out
