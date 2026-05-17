"""CVE data sync engine — fetches from NVD, MITRE, GHSA, OSV, EPSS, and CISA KEV

Usage:
    python -m cve.sync                 # delta sync (NVD + MITRE + GHSA + OSV + KEV + EPSS)
    python -m cve.sync --full          # full initial NVD sync (~250k CVEs) + delta others
    python -m cve.sync --resume        # resume a crashed full NVD sync from checkpoint
    python -m cve.sync --mitre         # MITRE cvelistV5 delta only
    python -m cve.sync --ghsa          # GitHub Security Advisories delta only
    python -m cve.sync --source osv    # OSV.dev backfill delta only
    python -m cve.sync --epss          # EPSS scores only
    python -m cve.sync --kev           # KEV list only

Designed to run via systemd timer every 2 hours.
Crash recovery: full syncs save a checkpoint after each page. Use --resume to continue.
"""

import asyncio
import csv
import gzip
import io
import json
import logging
import math
import re
import sys
import zipfile
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import httpx
from config import (
    CWE_ZIP_URL,
    GHSA_API_URL,
    KEV_URL,
    MITRE_RELEASES_URL,
    NVD_API_URL,
    NVD_PAGE_SIZE,
    settings,
)
from db import (
    aget_kev_active_cve_ids,
    amark_kev_removed,
    get_cve,
    get_cves_needing_osv_backfill,
    get_last_successful_sync,
    get_sync_checkpoint,
    init_all_dbs,
    record_cve_source,
    set_exploitdb_synced_at,
    update_epss,
    update_kev,
    update_sync_status,
    upsert_cve,
    upsert_cve_if_absent,
    upsert_cwe,
    upsert_exploits,
    upsert_kev_details,
)
from validation import validate_cve_id

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("contrastapi")

# NVD rate limits: 5 req/30s without key, 50 req/30s with key
NVD_DELAY = 0.6 if settings.nvd_api_key else 6.0
HTTP_TIMEOUT = 30
MAX_RETRIES = 3
USER_AGENT = "ContrastAPI/1.0 (api.contrastcyber.com)"

_client = httpx.AsyncClient(
    timeout=httpx.Timeout(HTTP_TIMEOUT, connect=10.0),
    headers={"User-Agent": USER_AGENT},
    follow_redirects=True,
    limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
    cookies=httpx.Cookies(),
)

OSV_API_URL = "https://api.osv.dev/v1/vulns/{cve_id}"
OSV_MAX_PER_RUN = 500
OSV_INTER_REQUEST_SLEEP = 0.1

# CWE catalog views (organizational groupings, NOT real weakness CWEs) — filtered
# from both NVD weaknesses parser and KEV cwes list before storage. The 1-6 digit
# bound mirrors routes._CWE_RE (cwe_lookup _normalize_cwe rejects longer values
# with HTTP 400) — keep the validation contract symmetric across write/read.
_CWE_VIEW_IDS = frozenset({"CWE-699", "CWE-1000", "CWE-1003"})
_CWE_RE = re.compile(r"^CWE-\d{1,6}$")
_CWE_MAX_PER_CVE = 50

_OSV_ECOSYSTEM_VENDOR: dict[str, str] = {
    "npm": "nodejs",
    "PyPI": "python",
    "Maven": "apache",
    "Go": "golang",
    "RubyGems": "ruby-lang",
    "NuGet": "microsoft",
    "crates.io": "rust-lang",
    "Packagist": "php",
    "Hex": "erlang",
    "Pub": "google",
    "SwiftURL": "apple",
}


# --- NVD Sync ---


async def _nvd_request(params: dict) -> dict:
    """Make a single NVD API request with retries."""
    headers = {"Accept": "application/json"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    for attempt in range(MAX_RETRIES):
        try:
            resp = await _client.get(NVD_API_URL, params=params, headers=headers)
            if resp.status_code == 403:
                wait = 30 * (attempt + 1)
                log.warning("NVD 403 rate limit, waiting %ds...", wait)
                await asyncio.sleep(wait)
                continue
            if resp.status_code == 503:
                wait = 10 * (attempt + 1)
                log.warning("NVD 503 service unavailable, waiting %ds...", wait)
                await asyncio.sleep(wait)
                continue
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            log.error("NVD HTTP error %d", e.response.status_code)
            raise
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                log.warning("NVD request failed (attempt %d): %s", attempt + 1, e)
                await asyncio.sleep(5)
            else:
                raise

    return {}


def _parse_nvd_cve(item: dict) -> dict:
    """Parse a single NVD CVE item into our DB format."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")

    # Description (English)
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    # CVSS v3.1 or v3.0
    severity = None
    cvss_v3 = None
    cvss_vector = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            raw_score = cvss_data.get("baseScore")
            cvss_v3 = raw_score if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool) else None
            raw_vector = cvss_data.get("vectorString")
            cvss_vector = raw_vector if isinstance(raw_vector, str) else None
            raw_sev = cvss_data.get("baseSeverity", "")
            severity = raw_sev.upper() if isinstance(raw_sev, str) and raw_sev else None
            break

    # CVSSv2: extract numeric score + vector + (fallback) severity. Was severity-only.
    cvss_v2 = None
    cvss_v2_vector = None
    v2_list = metrics.get("cvssMetricV2", [])
    if isinstance(v2_list, list) and v2_list and isinstance(v2_list[0], dict):
        v2_data = v2_list[0].get("cvssData", {})
        if isinstance(v2_data, dict):
            raw_v2 = v2_data.get("baseScore")
            cvss_v2 = raw_v2 if isinstance(raw_v2, (int, float)) and not isinstance(raw_v2, bool) else None
            raw_v2_vec = v2_data.get("vectorString")
            cvss_v2_vector = raw_v2_vec if isinstance(raw_v2_vec, str) else None
        if not severity:
            v2_sev = (
                v2_list[0].get("baseSeverity")
                or (v2_data.get("baseSeverity") if isinstance(v2_data, dict) else None)
                or ""
            )
            severity = v2_sev.upper() if isinstance(v2_sev, str) and v2_sev else None

    severity_sources = [{"source": "nvd", "severity": severity, "cvss_v3": cvss_v3, "cvss_v2": cvss_v2}]

    # CWE — group weaknesses by type (Primary first, Secondary next, fallback last);
    # enforce ^CWE-\d+$ format (defense against poisoned upstream feeds);
    # filter NVD organizational view-IDs (CWE-699/1000/1003 are catalog views, not real CWEs);
    # dedupe across buckets; cap total at _CWE_MAX_PER_CVE; cwe_id = cwes[0] (primary).
    _cwe_primary: list[str] = []
    _cwe_secondary: list[str] = []
    _cwe_other: list[str] = []
    for weakness in cve.get("weaknesses", []):
        wtype = weakness.get("type") or ""
        if wtype == "Primary":
            bucket = _cwe_primary
        elif wtype == "Secondary":
            bucket = _cwe_secondary
        else:
            bucket = _cwe_other
        for wd in weakness.get("description", []):
            val = wd.get("value", "")
            if _CWE_RE.match(val) and val not in _CWE_VIEW_IDS and val not in bucket:
                bucket.append(val)
    cwes: list[str] = []
    for c in _cwe_primary + _cwe_secondary + _cwe_other:
        if c not in cwes:
            cwes.append(c)
    cwes = cwes[:_CWE_MAX_PER_CVE]
    cwe_id = cwes[0] if cwes else None

    # Affected products from CPE configurations.
    # batch g v1.30.0: capture CPE part ('a' app / 'o' os / 'h' hardware) and
    # NVD's `vulnerable` flag — search defaults to vulnerable=true rows so a
    # product=linux_kernel query stops returning Chrome-on-Linux dependency CVEs.
    products = []
    seen = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5:
                    cpe_part = parts[2] if parts[2] in ("a", "o", "h") else None
                    vendor = parts[3] if parts[3] != "*" else None
                    product = parts[4] if parts[4] != "*" else None
                    if not (vendor or product):
                        continue
                    ver_start = match.get("versionStartIncluding")
                    ver_end = match.get("versionEndExcluding") or match.get("versionEndIncluding")
                    # Fallback: extract version from CPE string (field 6)
                    if not ver_start and not ver_end and len(parts) >= 6:
                        cpe_ver = parts[5]
                        if cpe_ver and cpe_ver not in ("*", "-"):
                            ver_start = cpe_ver
                            ver_end = None
                    vulnerable = bool(match.get("vulnerable", True))
                    key = (vendor, product, ver_start, ver_end, vulnerable)
                    if key in seen:
                        continue
                    seen.add(key)
                    products.append(
                        {
                            "vendor": vendor,
                            "product": product,
                            "version_start": ver_start,
                            "version_end": ver_end,
                            "cpe_part": cpe_part,
                            "vulnerable": vulnerable,
                        }
                    )

    # References — Batch 6A: structured shape {url, tags, source}, dedup by URL.
    raw_refs = cve.get("references", []) or []
    if not isinstance(raw_refs, list):
        raw_refs = []
    total_references_upstream = len(raw_refs)
    seen_urls: set[str] = set()
    refs_with_tags: list[dict] = []
    for r in raw_refs:
        if not isinstance(r, dict):
            continue
        url = r.get("url")
        if not isinstance(url, str) or not url or url in seen_urls:
            continue
        seen_urls.add(url)
        tags_raw = r.get("tags") or []
        tags = [t for t in tags_raw if isinstance(t, str)] if isinstance(tags_raw, list) else []
        source = r.get("source")
        if not isinstance(source, str):
            source = None
        refs_with_tags.append({"url": url, "tags": tags, "source": source})
    refs = [r["url"] for r in refs_with_tags]

    # Dates
    published = cve.get("published")
    modified = cve.get("lastModified")

    # NVD lifecycle status + cveTags (Batch 5). Defensive isinstance guards against
    # malformed feed payloads (CWE-704 type confusion).
    vuln_status = cve.get("vulnStatus")
    cve_tags_raw = cve.get("cveTags") or []
    cve_tags: list[str] = []
    if isinstance(cve_tags_raw, list):
        for tag_obj in cve_tags_raw:
            if not isinstance(tag_obj, dict):
                continue
            for t in tag_obj.get("tags", []):
                if isinstance(t, str) and t not in cve_tags:
                    cve_tags.append(t)

    return {
        "cve_id": cve_id,
        "description": desc,
        "severity": severity or None,
        "cvss_v3": cvss_v3,
        "cvss_vector": cvss_vector,
        "cvss_v2": cvss_v2,
        "cvss_v2_vector": cvss_v2_vector,
        "cwe_id": cwe_id,
        "cwes": cwes,
        "published": published,
        "modified": modified,
        "affected_products": products,
        "refs": refs[:20],
        "refs_with_tags": refs_with_tags,
        "total_references_upstream": total_references_upstream,
        "vulnerability_status": vuln_status,
        "cve_tags": cve_tags,
        "severity_sources": severity_sources,
    }


async def sync_nvd(full: bool = False, resume: bool = False) -> int:
    """Sync CVEs from NVD. Returns count of CVEs processed.

    Args:
        full: Fetch all CVEs (not just recent changes).
        resume: Resume a crashed full sync from its last checkpoint.
    """
    params = {"resultsPerPage": NVD_PAGE_SIZE}

    # --- Determine start_index (resume support) ---
    total_processed = 0
    start_index = 0

    if full and resume:
        raw = get_sync_checkpoint("nvd")
        if raw:
            try:
                cp = json.loads(raw)
                if not isinstance(cp, dict):
                    raise ValueError("checkpoint is not a dict")
                si = cp.get("start_index", 0)
                tp = cp.get("total_processed", 0)
                if isinstance(si, int) and si >= 0 and isinstance(tp, int) and tp >= 0:
                    start_index = si
                    total_processed = tp
                    log.info(
                        "Resuming NVD full sync from startIndex=%d (already processed %d)", start_index, total_processed
                    )
                else:
                    log.warning(
                        "Invalid checkpoint values (start_index=%r, total_processed=%r), starting from scratch", si, tp
                    )
            except (ValueError, TypeError, AttributeError):
                log.warning("Invalid NVD checkpoint, starting from scratch")

    # --- Build date filter for delta sync ---
    if not full:
        # Use last successful sync time with 30min overlap; fallback to 2.5h
        last_ok = get_last_successful_sync("nvd")
        if last_ok:
            try:
                last_dt = datetime.fromisoformat(last_ok)
                since = last_dt - timedelta(minutes=30)
            except ValueError:
                since = datetime.now(UTC) - timedelta(hours=2, minutes=30)
        else:
            since = datetime.now(UTC) - timedelta(hours=2, minutes=30)
        params["lastModStartDate"] = since.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["lastModEndDate"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000")
        log.info("NVD delta sync since %s", params["lastModStartDate"])
    else:
        log.info("NVD full sync starting (startIndex=%d)...", start_index)

    # Mark as in_progress
    update_sync_status("nvd", total_processed, "in_progress")

    completed_normally = False

    while True:
        params["startIndex"] = start_index
        data = await _nvd_request(params)
        if not data:
            log.error("Empty NVD response at startIndex=%d", start_index)
            break

        total_results = data.get("totalResults", 0)
        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            # No vulnerabilities but we reached here = end of results
            completed_normally = True
            break

        for item in vulnerabilities:
            try:
                cve_data = _parse_nvd_cve(item)
                if cve_data["cve_id"]:
                    # Preserve existing EPSS/KEV data with targeted read
                    existing = get_cve(cve_data["cve_id"])
                    if existing:
                        for key in ("epss_score", "epss_percentile", "in_kev", "kev_date_added"):
                            cve_data.setdefault(key, existing.get(key))
                    upsert_cve(cve_data)
                    record_cve_source(
                        cve_data["cve_id"],
                        "nvd",
                        f"https://nvd.nist.gov/vuln/detail/{cve_data['cve_id']}",
                    )
                    total_processed += 1
            except Exception as e:
                log.warning("Failed to process CVE: %s", e)

        start_index += len(vulnerabilities)
        log.info("NVD: processed %d/%d", total_processed, total_results)

        # Save checkpoint after each page (full sync only — delta is fast)
        if full:
            cp = json.dumps({"start_index": start_index, "total_processed": total_processed})
            update_sync_status("nvd", total_processed, "in_progress", checkpoint=cp)

        if start_index >= total_results:
            completed_normally = True
            break

        await asyncio.sleep(NVD_DELAY)

    # Only clear checkpoint and mark "ok" if sync finished all pages
    if completed_normally or not full:
        status = "ok" if (total_processed > 0 or not full) else "error"
        update_sync_status("nvd", total_processed, status, checkpoint=None)
    else:
        # Partial failure: preserve checkpoint for --resume
        log.warning("NVD sync interrupted after %d CVEs, checkpoint preserved for --resume", total_processed)
        cp = json.dumps({"start_index": start_index, "total_processed": total_processed})
        update_sync_status("nvd", total_processed, "error", checkpoint=cp)

    log.info("NVD sync complete: %d CVEs processed", total_processed)
    return total_processed


# --- MITRE cvelistV5 Sync ---

# Cap on JSON files decoded per release to keep memory bounded against zip-bomb
# style release assets. Real deltaCves.zip carries ~hundreds of files.
MITRE_MAX_ENTRIES = 50_000
MITRE_MAX_DECOMPRESSED = 500 * 1024 * 1024  # 500MB total across all members


def _github_headers() -> dict:
    """Headers for GitHub REST API calls. Unauthenticated — 60/hr per IP is ample
    for our cadence (1 MITRE call per 2h sync, ≤3 GHSA calls per 15min sync)."""
    return {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


def _severity_from_score(score: float | None) -> str | None:
    """Derive CVSS v3 severity label from numeric base score."""
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "NONE"


def _parse_mitre_cve(item: dict) -> dict:
    """Parse a single CVE Record Format v5.1 JSON into our DB format. Extracts CVSS/CWE/CPE from CNA container."""
    meta = item.get("cveMetadata", {}) or {}
    cve_id = meta.get("cveId", "") or ""

    if not validate_cve_id(cve_id):
        return {"cve_id": cve_id, "_skip": True}

    state = meta.get("state", "")

    # Skip rejected/reserved records — nothing to store
    if state and state != "PUBLISHED":
        return {"cve_id": cve_id, "_skip": True}

    containers = item.get("containers", {}) or {}
    cna = containers.get("cna", {}) or {}

    # English description
    desc = ""
    for d in cna.get("descriptions", []) or []:
        if d.get("lang", "").lower().startswith("en"):
            desc = (d.get("value", "") or "")[:4096]
            break

    # CVSS v3.1 → v3.0, skip other/v2
    severity = None
    cvss_v3 = None
    cvss_vector = None
    severity_sources: list[dict] = []
    for metric in cna.get("metrics", []) or []:
        if not isinstance(metric, dict):
            continue
        cvss_data = None
        for key in ("cvssV3_1", "cvssV3_0"):
            val = metric.get(key)
            if isinstance(val, dict):
                cvss_data = val
                break
        if cvss_data:
            raw_score = cvss_data.get("baseScore")
            cvss_v3 = raw_score if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool) else None
            raw_vector = cvss_data.get("vectorString")
            cvss_vector = raw_vector if isinstance(raw_vector, str) else None
            raw_sev = cvss_data.get("baseSeverity")
            if isinstance(raw_sev, str):
                severity = raw_sev.upper()
            else:
                severity = _severity_from_score(cvss_v3)
            severity_sources.append({"source": "mitre", "severity": severity, "cvss_v3": cvss_v3, "cvss_v2": None})
            break

    # CWE — first cweId matching CWE-<digits>
    cwe_id = None
    for pt in cna.get("problemTypes", []) or []:
        for wd in pt.get("descriptions", []) or []:
            val = wd.get("cweId", "")
            if isinstance(val, str) and re.match(r"^CWE-\d+$", val):
                cwe_id = val
                break
        if cwe_id:
            break

    # Affected products from CNA affected[] — cap iteration for DoS protection
    products = []
    seen = set()
    for aff in (cna.get("affected", []) or [])[:100]:
        if not isinstance(aff, dict):
            continue
        vendor = aff.get("vendor") or ""
        if not isinstance(vendor, str):
            vendor = ""
        if vendor.lower() == "n/a":
            continue
        product = aff.get("product") or ""
        if not isinstance(product, str):
            product = ""
        vendor = vendor[:256]
        product = product[:256]
        versions = aff.get("versions", []) or []
        cpes = aff.get("cpes", []) or []

        if versions:
            for v in versions[:50]:
                if not isinstance(v, dict):
                    continue
                if v.get("status", "affected") == "unaffected":
                    continue
                ver_start = v.get("version") or None
                ver_end = v.get("lessThan") or v.get("lessThanOrEqual") or None
                if isinstance(ver_start, str):
                    ver_start = ver_start[:256]
                elif ver_start is not None:
                    ver_start = None
                if isinstance(ver_end, str):
                    ver_end = ver_end[:256]
                elif ver_end is not None:
                    ver_end = None
                key = (vendor, product, ver_start, ver_end)
                if key in seen:
                    continue
                seen.add(key)
                products.append(
                    {
                        "vendor": vendor or None,
                        "product": product or None,
                        "version_start": ver_start,
                        "version_end": ver_end,
                    }
                )
        elif cpes:
            # CPE fallback: extract version from field index 5 (0-based)
            for cpe in cpes[:20]:
                if not isinstance(cpe, str):
                    continue
                parts = cpe.split(":")
                if len(parts) >= 6:
                    cpe_ver = parts[5][:256]
                    if cpe_ver and cpe_ver not in ("*", "-"):
                        ver_start = cpe_ver
                        ver_end = None
                        key = (vendor, product, ver_start, ver_end)
                        if key in seen:
                            continue
                        seen.add(key)
                        products.append(
                            {
                                "vendor": vendor or None,
                                "product": product or None,
                                "version_start": ver_start,
                                "version_end": ver_end,
                            }
                        )

    # References — Batch 6A: structured shape, source="mitre", dedup by URL.
    raw_refs = cna.get("references", []) or []
    if not isinstance(raw_refs, list):
        raw_refs = []
    total_references_upstream = len(raw_refs)
    seen_urls: set[str] = set()
    refs_with_tags: list[dict] = []
    for r in raw_refs:
        if not isinstance(r, dict):
            continue
        url = r.get("url")
        if not isinstance(url, str) or not url:
            continue
        url = url[:2048]
        if url in seen_urls:
            continue
        seen_urls.add(url)
        refs_with_tags.append({"url": url, "tags": [], "source": "mitre"})
    refs = [r["url"] for r in refs_with_tags][:20]

    # CISA Vulnrichment (ADP) — backfill only empty CNA fields; CNA always wins.
    for adp in (containers.get("adp", []) or [])[:10]:
        if not isinstance(adp, dict):
            continue
        if not desc:
            for d in adp.get("descriptions", []) or []:
                if d.get("lang", "").lower().startswith("en"):
                    desc = (d.get("value", "") or "")[:4096]
                    break
        for metric in adp.get("metrics", []) or []:
            if not isinstance(metric, dict):
                continue
            cvss_data = None
            for key in ("cvssV3_1", "cvssV3_0"):
                val = metric.get(key)
                if isinstance(val, dict):
                    cvss_data = val
                    break
            if cvss_data:
                raw_score = cvss_data.get("baseScore")
                adp_cvss_v3 = (
                    raw_score if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool) else None
                )
                raw_vector = cvss_data.get("vectorString")
                adp_cvss_vector = raw_vector if isinstance(raw_vector, str) else None
                raw_sev = cvss_data.get("baseSeverity")
                if isinstance(raw_sev, str):
                    adp_severity = raw_sev.upper()
                else:
                    adp_severity = _severity_from_score(adp_cvss_v3)
                if not any(s["source"] == "cisa-adp" for s in severity_sources):
                    severity_sources.append(
                        {"source": "cisa-adp", "severity": adp_severity, "cvss_v3": adp_cvss_v3, "cvss_v2": None}
                    )
                if severity is None:
                    severity = adp_severity
                    cvss_v3 = adp_cvss_v3
                    cvss_vector = adp_cvss_vector
                break
        if cwe_id is None:
            for pt in adp.get("problemTypes", []) or []:
                for wd in pt.get("descriptions", []) or []:
                    val = wd.get("cweId", "")
                    if isinstance(val, str) and re.match(r"^CWE-\d+$", val):
                        cwe_id = val
                        break
                if cwe_id:
                    break
        for aff in (adp.get("affected", []) or [])[:100]:
            if not isinstance(aff, dict):
                continue
            vendor = aff.get("vendor") or ""
            if not isinstance(vendor, str):
                vendor = ""
            if vendor.lower() == "n/a":
                continue
            product = aff.get("product") or ""
            if not isinstance(product, str):
                product = ""
            vendor = vendor[:256]
            product = product[:256]
            versions = aff.get("versions", []) or []
            cpes = aff.get("cpes", []) or []
            if versions:
                for v in versions[:50]:
                    if not isinstance(v, dict):
                        continue
                    if v.get("status", "affected") == "unaffected":
                        continue
                    ver_start = v.get("version") or None
                    ver_end = v.get("lessThan") or v.get("lessThanOrEqual") or None
                    if isinstance(ver_start, str):
                        ver_start = ver_start[:256]
                    elif ver_start is not None:
                        ver_start = None
                    if isinstance(ver_end, str):
                        ver_end = ver_end[:256]
                    elif ver_end is not None:
                        ver_end = None
                    key = (vendor, product, ver_start, ver_end)
                    if key in seen:
                        continue
                    seen.add(key)
                    products.append(
                        {
                            "vendor": vendor or None,
                            "product": product or None,
                            "version_start": ver_start,
                            "version_end": ver_end,
                        }
                    )
            elif cpes:
                for cpe in cpes[:20]:
                    if not isinstance(cpe, str):
                        continue
                    parts = cpe.split(":")
                    if len(parts) >= 6:
                        cpe_ver = parts[5][:256]
                        if cpe_ver and cpe_ver not in ("*", "-"):
                            ver_start = cpe_ver
                            ver_end = None
                            key = (vendor, product, ver_start, ver_end)
                            if key in seen:
                                continue
                            seen.add(key)
                            products.append(
                                {
                                    "vendor": vendor or None,
                                    "product": product or None,
                                    "version_start": ver_start,
                                    "version_end": ver_end,
                                }
                            )
        for r in (adp.get("references", []) or [])[:20]:
            if not isinstance(r, dict):
                continue
            url = r.get("url")
            if not isinstance(url, str) or not url:
                continue
            url = url[:2048]
            if url in seen_urls:
                continue
            seen_urls.add(url)
            refs_with_tags.append({"url": url, "tags": [], "source": "cisa-adp"})
    refs = [r["url"] for r in refs_with_tags][:20]

    published = meta.get("datePublished")
    modified = meta.get("dateUpdated") or meta.get("dateReserved")

    return {
        "cve_id": cve_id,
        "description": desc,
        "severity": severity,
        "cvss_v3": cvss_v3,
        "cvss_vector": cvss_vector,
        "cwe_id": cwe_id,
        "published": published,
        "modified": modified,
        "affected_products": products,
        "refs": refs,
        "refs_with_tags": refs_with_tags,
        "total_references_upstream": total_references_upstream,
        "severity_sources": severity_sources,
    }


MITRE_API_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"


async def _fetch_mitre_cve(cve_id: str) -> dict | None:
    """Fetch a single CVE record from cveawg.mitre.org.

    Returns parsed JSON dict on 200, None on 404/timeout/parse_error.
    Raises httpx.HTTPStatusError for 429 (caller handles backoff).
    Honors RateLimit-Remaining header — sleeps until reset when low.
    """
    try:
        resp = await _client.get(MITRE_API_URL.format(cve_id=cve_id), timeout=7.0)
    except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError) as e:
        log.warning("MITRE network error for %s: %s", cve_id, type(e).__name__)
        return None

    if resp.status_code == 404:
        log.warning("MITRE 404 for %s", cve_id)
        return None
    if resp.status_code == 429:
        resp.raise_for_status()  # caller handles
    if resp.status_code >= 400:
        log.warning("MITRE %d for %s", resp.status_code, cve_id)
        return None

    # Defensive rate-limit budgeting
    try:
        remaining = int(resp.headers.get("RateLimit-Remaining", "999"))
        reset = int(resp.headers.get("RateLimit-Reset", "0"))
        if remaining < 10 and reset > 0:
            log.info("MITRE rate-limit low (remaining=%d); sleeping %ds", remaining, reset)
            await asyncio.sleep(min(reset, 60))
    except (ValueError, TypeError):
        # Malformed rate-limit headers — skip budgeting; main request already succeeded.
        pass

    try:
        return resp.json()
    except json.JSONDecodeError:
        log.warning("MITRE parse error for %s", cve_id)
        return None


async def sync_mitre(full: bool = False) -> int:
    """Sync CVEs from MITRE cvelistV5 via the nightly GitHub release.

    v1 scope: delta only. Fetches the `latest` release, picks the smallest
    delta asset (deltaCves.zip), extracts each JSON, upserts via
    upsert_cve_if_absent (NVD strong fields always win; empty fields may be backfilled from MITRE/GHSA), and records source observation.

    `full=True` is reserved for a future v1.1 — raises NotImplementedError.
    Returns count of CVEs processed.
    """
    if full:
        raise NotImplementedError("MITRE full sync not implemented yet — use NVD full, MITRE delta")

    log.info("MITRE delta sync starting...")
    update_sync_status("mitre", 0, "in_progress")

    try:
        # Discover the latest release tarball
        resp = await _client.get(MITRE_RELEASES_URL, headers=_github_headers(), timeout=30)
        resp.raise_for_status()
        release = resp.json()
        tag = release.get("tag_name", "unknown")

        # Pick the delta asset (e.g. "2026-04-16_delta_CVEs_at_0100Z.zip")
        asset = None
        for a in release.get("assets", []) or []:
            name = (a.get("name") or "").lower()
            if "delta" in name and name.endswith(".zip"):
                asset = a
                break
        if asset is None:
            log.warning("MITRE: no delta asset in release %s", tag)
            update_sync_status("mitre", 0, "ok", checkpoint=tag)
            return 0

        dl_url = asset.get("browser_download_url")
        if not dl_url:
            log.error("MITRE: delta asset missing download URL")
            update_sync_status("mitre", 0, "error")
            return 0

        # Download the zip. GitHub release assets are unauthenticated, browser-like.
        zresp = await _client.get(dl_url, timeout=120)
        zresp.raise_for_status()
        zdata = zresp.content

        count = 0
        decompressed = 0
        with zipfile.ZipFile(io.BytesIO(zdata)) as zf:
            members = [m for m in zf.infolist() if m.filename.lower().endswith(".json")]
            if len(members) > MITRE_MAX_ENTRIES:
                log.warning("MITRE: release has %d entries, capping at %d", len(members), MITRE_MAX_ENTRIES)
                members = members[:MITRE_MAX_ENTRIES]

            for info in members:
                if info.is_dir():
                    continue
                remaining = MITRE_MAX_DECOMPRESSED - decompressed
                if remaining <= 0:
                    log.warning("MITRE: decompressed size exceeds limit, stopping")
                    break
                try:
                    with zf.open(info) as fh:
                        # Read at most remaining+1 bytes so an oversized member trips the cap
                        # instead of trusting info.file_size metadata (zip-bomb hardening).
                        raw = fh.read(remaining + 1)
                    if len(raw) > remaining:
                        log.warning("MITRE: decompressed size exceeds limit, stopping")
                        break
                    decompressed += len(raw)
                    record = json.loads(raw.decode("utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
                    log.warning("MITRE: failed to decode %s: %s", info.filename, e)
                    continue

                try:
                    cve_data = _parse_mitre_cve(record)
                except Exception as e:
                    log.warning("MITRE: parse error in %s: %s", info.filename, e)
                    continue

                if not cve_data.get("cve_id") or cve_data.get("_skip"):
                    continue

                upsert_cve_if_absent(cve_data)
                record_cve_source(
                    cve_data["cve_id"],
                    "mitre",
                    f"https://www.cve.org/CVERecord?id={cve_data['cve_id']}",
                )
                count += 1

        update_sync_status("mitre", count, "ok", checkpoint=tag)
        log.info("MITRE sync complete: %d CVEs processed (release %s)", count, tag)
        return count

    except httpx.HTTPError as e:
        log.error("MITRE sync HTTP error: %s", e)
        update_sync_status("mitre", 0, "error")
        return 0
    except zipfile.BadZipFile as e:
        log.error("MITRE sync bad zip: %s", e)
        update_sync_status("mitre", 0, "error")
        return 0
    except Exception as e:
        log.error("MITRE sync failed: %s", e)
        update_sync_status("mitre", 0, "error")
        return 0


# --- GHSA (GitHub Security Advisories) Sync ---

GHSA_MAX_PAGES = 20
_GHSA_LINK_NEXT_RE = re.compile(r'<([^>]+)>\s*;\s*rel="next"')


def _parse_ghsa_advisory(item: dict) -> dict:
    """Parse GHSA advisory: description, references, timestamps, severity_sources entry.

    severity/cvss_v3/cvss_vector remain None on the cves row (NVD/MITRE own them
    via COALESCE in upsert_cve_if_absent); GHSA's own severity is captured in
    severity_sources for the multi-source breakdown."""
    cve_id = item.get("cve_id")
    if not cve_id or not validate_cve_id(cve_id):
        return {"cve_id": cve_id or "", "_skip": True}

    desc = (item.get("summary") or "").strip()
    if not desc:
        desc = (item.get("description") or "").strip()
    if len(desc) > 2000:
        desc = desc[:2000]

    raw_refs = item.get("references") or []
    if not isinstance(raw_refs, list):
        raw_refs = []
    total_references_upstream = len(raw_refs)
    seen_urls: set[str] = set()
    refs_with_tags: list[dict] = []
    for url in raw_refs:
        if not isinstance(url, str) or not url or url in seen_urls:
            continue
        seen_urls.add(url)
        refs_with_tags.append({"url": url, "tags": [], "source": "ghsa"})
    refs = [r["url"] for r in refs_with_tags][:20]

    raw_ghsa_sev = item.get("severity")
    ghsa_severity = raw_ghsa_sev.upper() if isinstance(raw_ghsa_sev, str) and raw_ghsa_sev else None
    severity_sources = [{"source": "ghsa", "severity": ghsa_severity, "cvss_v3": None, "cvss_v2": None}]

    return {
        "cve_id": cve_id,
        "description": desc,
        "severity": None,
        "cvss_v3": None,
        "cvss_vector": None,
        "cwe_id": None,
        "published": item.get("published_at"),
        "modified": item.get("updated_at"),
        "affected_products": [],
        "refs": refs,
        "refs_with_tags": refs_with_tags,
        "total_references_upstream": total_references_upstream,
        "severity_sources": severity_sources,
    }


def _ghsa_next_link(headers) -> str | None:
    """Extract the rel=next URL from a GitHub Link header, if any."""
    link = headers.get("link") if headers else None
    if not link:
        return None
    m = _GHSA_LINK_NEXT_RE.search(link)
    if not m:
        return None
    url = m.group(1)
    if not url.startswith("https://api.github.com/"):
        log.warning("GHSA: ignoring non-GitHub pagination URL: %s", url)
        return None
    return url


async def sync_ghsa(full: bool = False) -> int:
    """Sync CVEs from GitHub Security Advisories.

    Delta-only: walks /advisories sorted by updated desc until we reach the
    last-seen checkpoint (ISO8601 updated_at of the newest advisory from the
    previous run). Unauth GitHub: 60 req/hr per IP is ample for a 2h cron.

    Returns count of CVE-bearing advisories processed.
    """
    if full:
        raise NotImplementedError("GHSA full sync not implemented yet — delta keeps up")

    log.info("GHSA delta sync starting...")
    # Read checkpoint BEFORE marking in_progress — update_sync_status uses
    # INSERT OR REPLACE and would otherwise wipe the stored value.
    checkpoint = get_sync_checkpoint("ghsa")
    update_sync_status("ghsa", 0, "in_progress", checkpoint=checkpoint)
    newest_seen: str | None = None
    count = 0

    try:
        url = GHSA_API_URL
        params: dict | None = {"per_page": 100, "sort": "updated", "direction": "desc"}
        stop = False

        for _page_num in range(GHSA_MAX_PAGES):
            resp = await _client.get(url, params=params, headers=_github_headers(), timeout=30)
            resp.raise_for_status()
            advisories = resp.json() or []

            if not advisories:
                break

            for adv in advisories:
                updated_at = adv.get("updated_at")
                if updated_at and (newest_seen is None or updated_at > newest_seen):
                    newest_seen = updated_at

                if checkpoint and updated_at and updated_at <= checkpoint:
                    stop = True
                    break

                if not adv.get("cve_id"):
                    continue

                try:
                    cve_data = _parse_ghsa_advisory(adv)
                except Exception as e:
                    log.warning("GHSA: parse error: %s", e)
                    continue

                if not cve_data.get("cve_id") or cve_data.get("_skip"):
                    continue

                upsert_cve_if_absent(cve_data)
                record_cve_source(cve_data["cve_id"], "ghsa", adv.get("html_url"))
                count += 1

            if stop:
                break

            # Rate-limit awareness
            remaining = resp.headers.get("x-ratelimit-remaining")
            if remaining is not None:
                try:
                    if int(remaining) <= 2:
                        log.warning("GHSA: rate limit remaining=%s, breaking to resume next cron", remaining)
                        break
                except ValueError:
                    # Non-numeric x-ratelimit-remaining header — proceed; next page check will retry.
                    pass

            next_url = _ghsa_next_link(resp.headers)
            if not next_url:
                break
            url = next_url
            params = None  # next link already has the query string

        new_checkpoint = newest_seen or checkpoint
        update_sync_status("ghsa", count, "ok", checkpoint=new_checkpoint)
        log.info("GHSA sync complete: %d CVE-bearing advisories processed", count)
        return count

    except httpx.HTTPError as e:
        log.error("GHSA sync HTTP error: %s", e)
        update_sync_status("ghsa", 0, "error")
        return 0
    except Exception as e:
        log.error("GHSA sync failed: %s", e)
        update_sync_status("ghsa", 0, "error")
        return 0


# --- EPSS Sync ---


async def sync_epss() -> int:
    """Sync EPSS scores from FIRST.org CSV bulk download. Returns count updated."""
    log.info("EPSS sync starting (CSV bulk)...")
    update_sync_status("epss", 0, "in_progress")
    count = 0
    epss_csv_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"

    max_decompressed = 200 * 1024 * 1024  # 200MB

    try:
        resp = await _client.get(epss_csv_url, headers={"Accept-Encoding": "gzip"}, timeout=120)
        resp.raise_for_status()
        raw = resp.content

        # Streaming decompression with size limit
        decompressed_size = 0
        header_passed = False
        for line in gzip.GzipFile(fileobj=io.BytesIO(raw)):
            decompressed_size += len(line)
            if decompressed_size > max_decompressed:
                log.warning("EPSS decompressed size exceeds 200MB limit, stopping")
                break

            line = line.decode("utf-8").strip()
            if not line:
                continue

            # Skip comment and header lines
            if not header_passed:
                if line.startswith("#"):
                    continue
                if line.startswith("cve,"):
                    header_passed = True
                    continue
                continue

            # --- process CSV data lines ---
            parts = line.split(",")
            if len(parts) < 3:
                continue
            cve_id, score_str, percentile_str = parts[0], parts[1], parts[2]
            if not cve_id.startswith("CVE-"):
                continue

            try:
                s = float(score_str)
                p = float(percentile_str)
                if math.isnan(s) or math.isinf(s):
                    s = None
                if math.isnan(p) or math.isinf(p):
                    p = None
            except (ValueError, TypeError):
                continue
            if update_epss(cve_id, s, p):
                count += 1

    except Exception as e:
        log.error("EPSS sync failed: %s", e)
        update_sync_status("epss", count, "error")
        return count

    update_sync_status("epss", count, "ok")
    log.info("EPSS sync complete: %d scores updated", count)
    return count


# --- KEV Sync ---


async def sync_kev() -> int:
    """Sync CISA Known Exploited Vulnerabilities. Returns count updated.

    Writes the boolean flag + date to cves and the full record to kev_details.
    """
    log.info("KEV sync starting...")
    update_sync_status("kev", 0, "in_progress")
    count = 0

    try:
        # Pre-sync snapshot: cve_ids currently flagged in_kev=1. Used post-loop to
        # soft-delete CVEs that dropped out of the feed (Batch 5 lifecycle).
        previously_active = await aget_kev_active_cve_ids()
        current_set: set[str] = set()

        resp = await _client.get(KEV_URL, headers={"Accept": "application/json"}, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID")
            if not cve_id:
                continue

            date_added = vuln.get("dateAdded")
            short_description = vuln.get("shortDescription")

            # Try targeted UPDATE first; create minimal entry only if CVE not in DB
            if not update_kev(cve_id, date_added):
                upsert_cve(
                    {
                        "cve_id": cve_id,
                        "description": short_description,
                        "in_kev": 1,
                        "kev_date_added": date_added,
                        "summary": f"CISA KEV: {short_description or cve_id}",
                    }
                )

            ransomware_raw = (vuln.get("knownRansomwareCampaignUse") or "").strip().lower()
            cwes = vuln.get("cwes") or []
            if not isinstance(cwes, list):
                cwes = []

            upsert_kev_details(
                cve_id,
                due_date=vuln.get("dueDate"),
                required_action=vuln.get("requiredAction"),
                known_ransomware_use=(ransomware_raw == "known"),
                vendor_project=vuln.get("vendorProject"),
                product=vuln.get("product"),
                vulnerability_name=vuln.get("vulnerabilityName"),
                short_description=short_description,
                notes=vuln.get("notes"),
                cwes=[str(c) for c in cwes if c and _CWE_RE.match(str(c)) and str(c) not in _CWE_VIEW_IDS],
                date_updated=vuln.get("dateUpdated"),
            )
            current_set.add(cve_id)
            count += 1

        # Soft-delete: CVEs in pre-sync snapshot but NOT in current feed.
        removed = previously_active - current_set
        if removed:
            now_iso = datetime.now(UTC).isoformat()
            for removed_id in removed:
                await amark_kev_removed(removed_id, now_iso)

    except Exception as e:
        log.error("KEV sync failed: %s", e)
        update_sync_status("kev", count, "error")
        return count

    update_sync_status("kev", count, "ok")
    log.info("KEV sync complete: %d entries", count)
    return count


# --- CWE Sync ---

CWE_ZIP_MAX_BYTES = 25 * 1024 * 1024  # 25 MB compressed cap (current ~1.5 MB)
CWE_CSV_MAX_BYTES = 100 * 1024 * 1024  # 100 MB uncompressed cap (current ~12 MB)


def _parse_cwe_related(raw: str | None) -> tuple[str | None, list[str]]:
    """Parse MITRE 'Related Weaknesses' field into (parent_cwe, child_cwes).

    Field format (one entry per chain, separated by '::'):
        ::NATURE:ChildOf:CWE ID:118:VIEW ID:1000:ORDINAL:Primary::
        ::NATURE:ParentOf:CWE ID:121:VIEW ID:1000::

    Only VIEW ID 1000 (research view) is consulted. Returns the first
    Primary ChildOf parent (fallback: first ChildOf in view 1000) plus
    all ParentOf children.
    """
    if not raw:
        return None, []
    parent_primary: str | None = None
    parent_fallback: str | None = None
    children: list[str] = []
    for entry in raw.split("::"):
        entry = entry.strip()
        if not entry:
            continue
        parts = [p.strip() for p in entry.split(":")]
        kv = {parts[i]: parts[i + 1] for i in range(0, len(parts) - 1, 2) if parts[i]}
        nature = kv.get("NATURE")
        cwe_num = kv.get("CWE ID")
        view = kv.get("VIEW ID")
        ordinal = kv.get("ORDINAL")
        if not (nature and cwe_num and cwe_num.isdigit() and view == "1000"):
            continue
        cwe_full = f"CWE-{cwe_num}"
        if nature == "ChildOf":
            if ordinal == "Primary" and parent_primary is None:
                parent_primary = cwe_full
            elif parent_fallback is None:
                parent_fallback = cwe_full
        elif nature == "ParentOf" and cwe_full not in children:
            children.append(cwe_full)
    return parent_primary or parent_fallback, children[:50]


def _parse_cwe_mitigations(raw: str | None) -> list[str]:
    """Parse 'Potential Mitigations' field into a list of human-readable strings.

    Format: ::PHASE:Architecture and Design:DESCRIPTION:Use a vetted library...::
    Each entry yields one combined "Phase — Description" string. Returns up to 30.
    """
    if not raw:
        return []
    out: list[str] = []
    for entry in raw.split("::"):
        entry = entry.strip()
        if not entry:
            continue
        phase = None
        description = None
        # Greedy KEY:VALUE walk that tolerates colons in DESCRIPTION values
        i = 0
        tokens = entry.split(":")
        while i < len(tokens) - 1:
            key = tokens[i].strip()
            if key == "PHASE":
                phase = tokens[i + 1].strip()
                i += 2
            elif key == "DESCRIPTION":
                # DESCRIPTION may contain colons; consume rest until next known key
                rest = []
                j = i + 1
                while j < len(tokens):
                    candidate = tokens[j].strip()
                    if candidate in ("PHASE", "STRATEGY", "EFFECTIVENESS", "EFFECTIVENESS NOTES", "MITIGATION ID"):
                        break
                    rest.append(tokens[j])
                    j += 1
                description = ":".join(rest).strip()
                i = j
            else:
                i += 1
        if description:
            label = f"{phase} — {description}" if phase else description
            out.append(label[:1000])
        if len(out) >= 30:
            break
    return out


def _parse_cwe_examples(raw: str | None) -> list[str]:
    """Parse 'Observed Examples' field into a list of "CVE-x: description" strings.

    Format: ::REFERENCE:CVE-2018-1234:DESCRIPTION:Buffer overflow in...:LINK:https://...::
    """
    if not raw:
        return []
    out: list[str] = []
    for entry in raw.split("::"):
        entry = entry.strip()
        if not entry:
            continue
        ref = None
        description = None
        tokens = entry.split(":")
        i = 0
        while i < len(tokens) - 1:
            key = tokens[i].strip()
            if key == "REFERENCE":
                ref = tokens[i + 1].strip()
                i += 2
            elif key == "DESCRIPTION":
                rest = []
                j = i + 1
                while j < len(tokens):
                    candidate = tokens[j].strip()
                    if candidate in ("REFERENCE", "LINK"):
                        break
                    rest.append(tokens[j])
                    j += 1
                description = ":".join(rest).strip()
                i = j
            else:
                i += 1
        if ref:
            out.append(f"{ref}: {description}" if description else ref)
        if len(out) >= 50:
            break
    return out


async def sync_cwe() -> int:
    """Sync MITRE CWE catalog (research view 1000). Returns count upserted.

    Downloads the public ZIP, extracts the CSV, parses each row into the cwes
    table. Idempotent — runs weekly. Tolerant of malformed rows: bad rows are
    logged and skipped.
    """
    log.info("CWE sync starting...")
    update_sync_status("cwe", 0, "in_progress")
    count = 0

    try:
        resp = await _client.get(CWE_ZIP_URL, headers={"Accept": "application/zip"}, timeout=60)
        resp.raise_for_status()
        if len(resp.content) > CWE_ZIP_MAX_BYTES:
            log.error("CWE ZIP exceeds %d bytes (%d) — refusing", CWE_ZIP_MAX_BYTES, len(resp.content))
            update_sync_status("cwe", 0, "error")
            return 0

        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            csv_members = [m for m in zf.namelist() if m.lower().endswith(".csv")]
            if not csv_members:
                log.error("CWE ZIP contains no CSV file")
                update_sync_status("cwe", 0, "error")
                return 0
            member = csv_members[0]
            info = zf.getinfo(member)
            if info.file_size > CWE_CSV_MAX_BYTES:
                log.error("CWE CSV uncompressed size %d exceeds %d", info.file_size, CWE_CSV_MAX_BYTES)
                update_sync_status("cwe", 0, "error")
                return 0
            with zf.open(member) as fh:
                reader = csv.DictReader(io.TextIOWrapper(fh, encoding="utf-8", errors="replace"))
                for row in reader:
                    cwe_num = (row.get("CWE-ID") or "").strip()
                    name = (row.get("Name") or "").strip()
                    if not cwe_num or not cwe_num.isdigit() or not name:
                        continue
                    cwe_id = f"CWE-{cwe_num}"
                    parent_cwe, child_cwes = _parse_cwe_related(row.get("Related Weaknesses"))
                    mitigations = _parse_cwe_mitigations(row.get("Potential Mitigations"))
                    examples = _parse_cwe_examples(row.get("Observed Examples"))
                    try:
                        upsert_cwe(
                            cwe_id,
                            name=name[:512],
                            description=(row.get("Description") or "").strip()[:8000] or None,
                            extended_description=(row.get("Extended Description") or "").strip()[:16000] or None,
                            abstract_type=(row.get("Weakness Abstraction") or "").strip() or None,
                            status=(row.get("Status") or "").strip() or None,
                            likelihood=(row.get("Likelihood of Exploit") or "").strip() or None,
                            mitigations=mitigations,
                            examples=examples,
                            parent_cwe=parent_cwe,
                            child_cwes=child_cwes,
                        )
                        count += 1
                    except Exception as e:
                        log.warning("CWE upsert failed for %s: %s", cwe_id, type(e).__name__)

    except Exception as e:
        log.error("CWE sync failed: %s", e)
        update_sync_status("cwe", count, "error")
        return count

    update_sync_status("cwe", count, "ok")
    log.info("CWE sync complete: %d entries", count)
    return count


# --- OSV Sync ---


def _parse_cvss_vector_score(vector: str) -> tuple[float | None, str | None]:
    """Parse a CVSS:3.x vector string → (base_score, vector). Returns (None, vector) on error."""
    if not isinstance(vector, str) or not vector.startswith("CVSS:3"):
        return None, vector if isinstance(vector, str) else None
    try:
        from cvss import CVSS3

        c = CVSS3(vector)
        return float(c.base_score), vector
    except Exception as e:
        log.warning("CVSS3 parse error for vector %r: %s", vector[:80], type(e).__name__)
        return None, vector


def _extract_products_from_osv_affected(affected: list) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple] = set()
    for a in (affected or [])[:100]:
        if not isinstance(a, dict):
            continue
        pkg = a.get("package") or {}
        ecosystem = pkg.get("ecosystem") or ""
        name = pkg.get("name") or ""
        if not isinstance(name, str) or not name:
            continue
        vendor = _OSV_ECOSYSTEM_VENDOR.get(ecosystem, (ecosystem or "").lower()) or None
        product = name[:256]

        ver_start: str | None = None
        ver_end: str | None = None
        for rng in (a.get("ranges") or [])[:10]:
            for ev in (rng.get("events") or [])[:20]:
                if isinstance(ev, dict):
                    if "introduced" in ev and not ver_start:
                        v = ev.get("introduced")
                        if isinstance(v, str) and v not in ("0", ""):
                            ver_start = v[:256]
                    if "fixed" in ev and not ver_end:
                        v = ev.get("fixed")
                        if isinstance(v, str):
                            ver_end = v[:256]
        key = (vendor, product, ver_start, ver_end)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "vendor": vendor,
                "product": product,
                "version_start": ver_start,
                "version_end": ver_end,
            }
        )
    return out


def _parse_osv_vulnerability(vuln: dict) -> dict:
    """Parse an OSV vulnerability object into upsert_cve_if_absent's dict contract."""
    if not isinstance(vuln, dict):
        return {"cve_id": "", "_skip": True}

    aliases = vuln.get("aliases") or []
    cve_id = ""
    for a in aliases:
        if isinstance(a, str) and a.startswith("CVE-") and validate_cve_id(a):
            cve_id = a
            break
    if not cve_id:
        return {"cve_id": "", "_skip": True}

    desc = (vuln.get("summary") or "").strip()
    if not desc:
        desc = (vuln.get("details") or "").strip()
    if len(desc) > 2000:
        desc = desc[:2000]

    severity = None
    cvss_v3 = None
    cvss_vector = None
    for sev in vuln.get("severity") or []:
        if not isinstance(sev, dict):
            continue
        if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
            score, vector = _parse_cvss_vector_score(sev.get("score"))
            if score is not None:
                cvss_v3 = score
                cvss_vector = vector
                severity = _severity_from_score(score)
            break

    cwe_id = None
    cwes = (vuln.get("database_specific") or {}).get("cwe_ids") or []
    for c in cwes:
        if isinstance(c, str) and re.match(r"^CWE-\d+$", c):
            cwe_id = c
            break

    raw_refs = vuln.get("references") or []
    total_references_upstream = len(raw_refs) if isinstance(raw_refs, list) else 0
    seen_urls: set[str] = set()
    refs_with_tags: list[dict] = []
    if isinstance(raw_refs, list):
        for r in raw_refs:
            if not isinstance(r, dict):
                continue
            url = r.get("url")
            if not isinstance(url, str) or not url or url in seen_urls:
                continue
            seen_urls.add(url)
            refs_with_tags.append({"url": url, "tags": [], "source": "osv"})
    refs = [r["url"] for r in refs_with_tags][:20]

    severity_sources = [{"source": "osv", "severity": severity, "cvss_v3": cvss_v3, "cvss_v2": None}]

    return {
        "cve_id": cve_id,
        "description": desc,
        "severity": severity,
        "cvss_v3": cvss_v3,
        "cvss_vector": cvss_vector,
        "cwe_id": cwe_id,
        "published": vuln.get("published"),
        "modified": vuln.get("modified"),
        "affected_products": _extract_products_from_osv_affected(vuln.get("affected") or []),
        "refs": refs,
        "refs_with_tags": refs_with_tags,
        "total_references_upstream": total_references_upstream,
        "severity_sources": severity_sources,
    }


async def _fetch_osv_vulnerability(cve_id: str) -> dict | None:
    """Fetch a single CVE from OSV.dev. Returns parsed JSON dict on 200, None on 404/error."""
    try:
        resp = await _client.get(OSV_API_URL.format(cve_id=cve_id), timeout=10.0)
    except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError) as e:
        log.warning("OSV network error for %s: %s", cve_id, type(e).__name__)
        return None

    if resp.status_code == 404:
        return None
    if resp.status_code >= 400:
        log.warning("OSV %d for %s", resp.status_code, cve_id)
        return None
    if len(resp.content) > 5 * 1024 * 1024:
        log.warning("OSV response too large for %s: %d bytes", cve_id, len(resp.content))
        return None
    try:
        return resp.json()
    except json.JSONDecodeError:
        log.warning("OSV parse error for %s", cve_id)
        return None


async def sync_osv(full: bool = False) -> int:
    """Backfill CVE enrichment from OSV.dev for post-NVD-gap CVEs.

    Delta-only: selects CVEs with incomplete CVSS/CWE published on/after
    2026-04-15, fetches per-CVE, upserts via upsert_cve_if_absent (NVD strong
    fields always win). `full=True` raises NotImplementedError.

    Returns count of CVEs with non-empty OSV data merged.
    """
    if full:
        raise NotImplementedError("OSV full sync not implemented — delta keeps up")

    log.info("OSV delta sync starting...")
    update_sync_status("osv", 0, "in_progress")
    count = 0

    try:
        cve_ids = get_cves_needing_osv_backfill(limit=OSV_MAX_PER_RUN)
        if not cve_ids:
            update_sync_status("osv", 0, "ok")
            log.info("OSV sync complete: 0 CVEs needed backfill")
            return 0

        for cve_id in cve_ids:
            vuln = await _fetch_osv_vulnerability(cve_id)
            if vuln is None:
                await asyncio.sleep(OSV_INTER_REQUEST_SLEEP)
                continue

            try:
                cve_data = _parse_osv_vulnerability(vuln)
            except Exception as e:
                log.warning("OSV parse error for %s: %s", cve_id, e)
                await asyncio.sleep(OSV_INTER_REQUEST_SLEEP)
                continue

            if not cve_data.get("cve_id") or cve_data.get("_skip"):
                await asyncio.sleep(OSV_INTER_REQUEST_SLEEP)
                continue

            upsert_cve_if_absent(cve_data)
            record_cve_source(
                cve_data["cve_id"],
                "osv",
                f"https://osv.dev/vulnerability/{vuln.get('id') or cve_data['cve_id']}",
            )
            count += 1
            await asyncio.sleep(OSV_INTER_REQUEST_SLEEP)

        update_sync_status("osv", count, "ok")
        log.info("OSV sync complete: %d CVEs enriched", count)
        return count

    except Exception as e:
        log.error("OSV sync failed: %s", e)
        update_sync_status("osv", count, "error")
        return count


# --- ExploitDB CSV Sync ---

EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
EXPLOITDB_ALLOWED_HOSTS = frozenset({"gitlab.com", "raw.githubusercontent.com", "codeload.github.com"})
EXPLOITDB_CHUNK_SIZE = 1000
EXPLOITDB_MAX_BYTES = 50 * 1024 * 1024  # 50 MiB guard
EXPLOITDB_CVE_PATTERN = re.compile(r"^CVE-(19|20)\d{2}-\d{4,7}$")


def _safe_http_url(raw: str | None, fallback: str) -> str:
    """Return raw URL if it is an http(s) URL, else fallback. Guards against javascript:/data:/file: schemes."""
    if not raw:
        return fallback
    try:
        scheme = urlparse(raw).scheme.lower()
    except ValueError:
        return fallback
    return raw if scheme in ("http", "https") else fallback


def _parse_exploitdb_row(row: dict) -> list[dict]:
    """Parse one ExploitDB CSV row into one dict per CVE in the codes column."""
    codes_str = (row.get("codes") or "").strip()
    if not codes_str:
        return []
    edb_id_raw = row.get("id")
    if not edb_id_raw or not str(edb_id_raw).strip().isdigit():
        return []
    edb_id = int(str(edb_id_raw).strip())
    fallback_url = f"https://www.exploit-db.com/exploits/{edb_id}"
    out = []
    for raw in codes_str.split(";"):
        cve_id = raw.strip()
        if not EXPLOITDB_CVE_PATTERN.match(cve_id):
            continue
        port_raw = (row.get("port") or "").strip()
        out.append(
            {
                "edb_id": edb_id,
                "cve_id": cve_id,
                "date_published": row.get("date_published"),
                "author": (row.get("author") or "")[:200] or None,
                "type": (row.get("type") or "")[:50] or None,
                "platform": (row.get("platform") or "")[:100] or None,
                "port": int(port_raw) if port_raw.isdigit() else None,
                "verified": 1 if (row.get("verified") or "").strip() == "1" else 0,
                "description": (row.get("description") or "")[:2000],
                "source_url": _safe_http_url(row.get("source_url"), fallback_url),
                "date_added": row.get("date_added"),
                "date_updated": row.get("date_updated"),
                "tags": (row.get("tags") or "")[:500],
            }
        )
    return out


async def sync_exploitdb(full: bool = False) -> int:
    """Download ExploitDB CSV and upsert into the exploits table.

    Delta mode skips the download when Last-Modified matches the stored checkpoint.
    Full mode forces a complete re-upsert regardless of checkpoint.
    """
    log.info("ExploitDB sync starting (full=%s)...", full)
    update_sync_status("exploitdb", 0, "in_progress")
    checkpoint = None if full else get_sync_checkpoint("exploitdb")
    try:
        head = await _client.head(EXPLOITDB_CSV_URL, timeout=10, follow_redirects=True)
        if head.url.host not in EXPLOITDB_ALLOWED_HOSTS:
            raise ValueError(f"ExploitDB HEAD redirected to unexpected host: {head.url.host}")
        last_mod = head.headers.get("last-modified")
        if checkpoint and last_mod and last_mod <= checkpoint:
            log.info("ExploitDB sync skipped — Last-Modified unchanged (%s)", last_mod)
            update_sync_status("exploitdb", 0, "ok", checkpoint=checkpoint)
            set_exploitdb_synced_at()
            return 0

        resp = await _client.get(
            EXPLOITDB_CSV_URL,
            timeout=120,
            follow_redirects=True,
            headers={"Accept-Encoding": "identity"},
        )
        resp.raise_for_status()
        if resp.url.host not in EXPLOITDB_ALLOWED_HOSTS:
            raise ValueError(f"ExploitDB GET redirected to unexpected host: {resp.url.host}")
        if len(resp.content) > EXPLOITDB_MAX_BYTES:
            raise ValueError(f"CSV too large: {len(resp.content)} bytes (limit {EXPLOITDB_MAX_BYTES})")

        reader = csv.DictReader(io.StringIO(resp.text))
        batch: list[dict] = []
        count = 0
        skipped = 0

        for row in reader:
            parsed_rows = _parse_exploitdb_row(row)
            if not parsed_rows:
                skipped += 1
                continue
            for parsed in parsed_rows:
                batch.append(parsed)
                if len(batch) >= EXPLOITDB_CHUNK_SIZE:
                    upsert_exploits(batch)
                    count += len(batch)
                    batch = []

        if batch:
            upsert_exploits(batch)
            count += len(batch)

        update_sync_status("exploitdb", count, "ok", checkpoint=last_mod)
        set_exploitdb_synced_at()
        log.info("ExploitDB sync complete: %d rows processed, %d rows skipped", count, skipped)
        return count

    except Exception as e:
        log.exception("ExploitDB sync failed: %s", e)
        update_sync_status("exploitdb", 0, "error")
        return 0


# --- Main ---


async def sync_all(full: bool = False):
    """Run all sync tasks. MITRE, GHSA, OSV, and CWE run delta-only regardless of `full`."""
    from atlas.sync import sync_atlas
    from d3fend.sync import sync_d3fend

    init_all_dbs()
    await sync_nvd(full=full)
    await sync_mitre(full=False)
    await sync_ghsa(full=False)
    await sync_osv(full=False)
    await sync_kev()
    await sync_cwe()
    await sync_epss()
    await sync_exploitdb(full=False)
    await sync_atlas()
    await sync_d3fend()


async def _main_cli(args: list[str]) -> None:
    """CLI dispatcher — extracted from __main__ to be awaitable."""
    init_all_dbs()

    if "--resume" in args:
        await sync_nvd(full=True, resume=True)
        await sync_mitre(full=False)
        await sync_ghsa(full=False)
        await sync_osv(full=False)
        await sync_kev()
        await sync_cwe()
        await sync_epss()
    elif "--full" in args:
        await sync_nvd(full=True)
        await sync_mitre(full=False)
        await sync_ghsa(full=False)
        await sync_osv(full=False)
        await sync_kev()
        await sync_cwe()
        await sync_epss()
    elif "--source" in args:
        src = args[args.index("--source") + 1] if args.index("--source") + 1 < len(args) else ""
        if src == "mitre":
            await sync_mitre(full=False)
        elif src == "ghsa":
            await sync_ghsa(full=False)
        elif src == "osv":
            await sync_osv(full=False)
        elif src == "epss":
            await sync_epss()
        elif src == "kev":
            await sync_kev()
        elif src == "cwe":
            await sync_cwe()
        elif src == "nvd":
            await sync_nvd(full=False)
        elif src == "exploitdb":
            await sync_exploitdb(full="--full" in args)
        elif src == "atlas":
            from atlas.sync import sync_atlas

            await sync_atlas()
        elif src == "d3fend":
            from d3fend.sync import sync_d3fend

            await sync_d3fend()
        else:
            print(f"Unknown source: {src}. Options: nvd, mitre, ghsa, osv, epss, kev, cwe, exploitdb, atlas, d3fend")
    else:
        await sync_all()


if __name__ == "__main__":
    asyncio.run(_main_cli(sys.argv[1:]))
