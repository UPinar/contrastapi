"""CVE data sync engine — fetches from NVD, EPSS, and CISA KEV

Usage:
    python -m cve.sync                 # delta sync (last 2 hours)
    python -m cve.sync --full          # full initial sync (~250k CVEs)
    python -m cve.sync --epss          # EPSS scores only
    python -m cve.sync --kev           # KEV list only

Designed to run via systemd timer every 2 hours.
"""

import gzip
import io
import logging
import math
import sys
import time
from datetime import UTC, datetime, timedelta

import httpx
from config import KEV_URL, NVD_API_KEY, NVD_API_URL, NVD_PAGE_SIZE
from db import get_cve, init_all_dbs, update_epss, update_kev, update_sync_status, upsert_cve

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("contrastapi")

# NVD rate limits: 5 req/30s without key, 50 req/30s with key
NVD_DELAY = 0.6 if NVD_API_KEY else 6.0
HTTP_TIMEOUT = 30
MAX_RETRIES = 3
USER_AGENT = "ContrastAPI/1.0 (api.contrastcyber.com)"

_client = httpx.Client(
    timeout=httpx.Timeout(HTTP_TIMEOUT, connect=10.0),
    headers={"User-Agent": USER_AGENT},
    follow_redirects=True,
)


# --- NVD Sync ---


def _nvd_request(params: dict) -> dict:
    """Make a single NVD API request with retries."""
    headers = {"Accept": "application/json"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    for attempt in range(MAX_RETRIES):
        try:
            resp = _client.get(NVD_API_URL, params=params, headers=headers)
            if resp.status_code == 403:
                wait = 30 * (attempt + 1)
                log.warning("NVD 403 rate limit, waiting %ds...", wait)
                time.sleep(wait)
                continue
            if resp.status_code == 503:
                wait = 10 * (attempt + 1)
                log.warning("NVD 503 service unavailable, waiting %ds...", wait)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            log.error("NVD HTTP error %d", e.response.status_code)
            raise
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                log.warning("NVD request failed (attempt %d): %s", attempt + 1, e)
                time.sleep(5)
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
            cvss_v3 = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            severity = cvss_data.get("baseSeverity", "").upper()
            break

    # Fallback to v2 severity if no v3
    if not severity:
        v2_list = metrics.get("cvssMetricV2", [])
        if v2_list:
            severity = v2_list[0].get("baseSeverity", "").upper()

    # CWE
    cwe_id = None
    for weakness in cve.get("weaknesses", []):
        for wd in weakness.get("description", []):
            val = wd.get("value", "")
            if val.startswith("CWE-"):
                cwe_id = val
                break
        if cwe_id:
            break

    # Affected products from CPE configurations
    products = []
    seen = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5:
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
                    key = (vendor, product, ver_start, ver_end)
                    if key in seen:
                        continue
                    seen.add(key)
                    products.append(
                        {
                            "vendor": vendor,
                            "product": product,
                            "version_start": ver_start,
                            "version_end": ver_end,
                        }
                    )

    # References
    refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]

    # Dates
    published = cve.get("published")
    modified = cve.get("lastModified")

    return {
        "cve_id": cve_id,
        "description": desc,
        "severity": severity or None,
        "cvss_v3": cvss_v3,
        "cvss_vector": cvss_vector,
        "cwe_id": cwe_id,
        "published": published,
        "modified": modified,
        "affected_products": products,
        "refs": refs[:20],
    }


def sync_nvd(full: bool = False) -> int:
    """Sync CVEs from NVD. Returns count of CVEs processed."""
    params = {"resultsPerPage": NVD_PAGE_SIZE}

    if not full:
        # Delta: last 2.5 hours to overlap with timer interval
        since = datetime.now(UTC) - timedelta(hours=2, minutes=30)
        params["lastModStartDate"] = since.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["lastModEndDate"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000")
        log.info("NVD delta sync since %s", params["lastModStartDate"])
    else:
        log.info("NVD full sync starting...")

    total_processed = 0
    start_index = 0

    while True:
        params["startIndex"] = start_index
        data = _nvd_request(params)
        if not data:
            log.error("Empty NVD response at startIndex=%d", start_index)
            break

        total_results = data.get("totalResults", 0)
        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
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
                    total_processed += 1
            except Exception as e:
                log.warning("Failed to process CVE: %s", e)

        log.info("NVD: processed %d/%d", total_processed, total_results)

        start_index += len(vulnerabilities)
        if start_index >= total_results:
            break

        time.sleep(NVD_DELAY)

    # Delta sync with 0 results is normal (no new CVEs in window), not an error
    status = "ok" if (total_processed > 0 or not full) else "error"
    update_sync_status("nvd", total_processed, status)
    log.info("NVD sync complete: %d CVEs processed", total_processed)
    return total_processed


# --- EPSS Sync ---


def sync_epss() -> int:
    """Sync EPSS scores from FIRST.org CSV bulk download. Returns count updated."""
    log.info("EPSS sync starting (CSV bulk)...")
    count = 0
    epss_csv_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"

    max_decompressed = 200 * 1024 * 1024  # 200MB

    try:
        resp = _client.get(epss_csv_url, headers={"Accept-Encoding": "gzip"}, timeout=120)
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


def sync_kev() -> int:
    """Sync CISA Known Exploited Vulnerabilities. Returns count updated."""
    log.info("KEV sync starting...")
    count = 0

    try:
        resp = _client.get(KEV_URL, headers={"Accept": "application/json"}, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID")
            if not cve_id:
                continue

            date_added = vuln.get("dateAdded")
            # Try targeted UPDATE first; create minimal entry only if CVE not in DB
            if not update_kev(cve_id, date_added):
                upsert_cve(
                    {
                        "cve_id": cve_id,
                        "description": vuln.get("shortDescription"),
                        "in_kev": 1,
                        "kev_date_added": date_added,
                        "summary": f"CISA KEV: {vuln.get('shortDescription', cve_id)}",
                    }
                )
            count += 1

    except Exception as e:
        log.error("KEV sync failed: %s", e)
        update_sync_status("kev", count, "error")
        return count

    update_sync_status("kev", count, "ok")
    log.info("KEV sync complete: %d entries", count)
    return count


# --- Main ---


def sync_all(full: bool = False):
    """Run all sync tasks."""
    init_all_dbs()
    sync_nvd(full=full)
    sync_kev()
    sync_epss()


if __name__ == "__main__":
    args = sys.argv[1:]

    init_all_dbs()

    if "--full" in args:
        sync_nvd(full=True)
        sync_kev()
        sync_epss()
    elif "--epss" in args:
        sync_epss()
    elif "--kev" in args:
        sync_kev()
    else:
        sync_all()
