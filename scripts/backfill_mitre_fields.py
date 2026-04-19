#!/usr/bin/env python3
"""Backfill empty MITRE fields for CVEs whose NVD enrichment was halted.

Scope: CVEs where affected_products IS NULL OR '[]' OR cwe_id IS NULL OR cvss_v3 IS NULL.
Source: cveawg.mitre.org/api/cve/{id} (per-CVE).

Idempotent via upsert_cve_if_absent selective overwrite.
Resume via state file: {"last_cve_id": "CVE-yyyy-nnnnn", "timestamp": "..."}.
"""

import argparse
import json
import logging
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

# Add contrastapi/app/ to sys.path so bare `db` / `cve.sync` imports resolve
# (matches the test environment's sys.path, ensuring the same module instances)
_app_dir = str(Path(__file__).resolve().parent.parent / "app")
if _app_dir not in sys.path:
    sys.path.insert(0, _app_dir)

from cve.sync import _fetch_mitre_cve, _parse_mitre_cve  # noqa: E402
from db import get_cve_db, init_all_dbs, record_cve_source, upsert_cve_if_absent  # noqa: E402
from validation import validate_cve_id  # noqa: E402

DEFAULT_STATE_FILE = "/var/lib/contrastapi/backfill_mitre_state.json"
EMPTY_CVE_SQL = """
SELECT cve_id FROM cves
WHERE cve_id > ?
  AND (affected_products IS NULL
       OR affected_products = '[]'
       OR cwe_id IS NULL
       OR cvss_v3 IS NULL)
ORDER BY cve_id
LIMIT ?
"""
BASE_THROTTLE = 0.05  # 50ms
MAX_RETRIES_429 = 3
BACKOFF_SCHEDULE = (1.0, 2.0, 4.0)

log = logging.getLogger("backfill_mitre")


def load_state(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        return json.loads(path.read_text()).get("last_cve_id", "")
    except (json.JSONDecodeError, OSError):
        log.warning("State file unreadable, starting from beginning")
        return ""


def save_state(path: Path, last_cve_id: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "last_cve_id": last_cve_id,
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )
    )


def query_batch(last_id: str, batch_size: int) -> list[str]:
    with get_cve_db() as con:
        rows = [row[0] for row in con.execute(EMPTY_CVE_SQL, (last_id, batch_size)).fetchall()]
    valid = [c for c in rows if validate_cve_id(c)]
    if len(valid) != len(rows):
        log.warning("skipped %d malformed cve_ids", len(rows) - len(valid))
    return valid


def fetch_with_backoff(cve_id: str) -> dict | None:
    """Wrap _fetch_mitre_cve with 429 exp-backoff. Returns parsed dict or None.

    Non-429 HTTPStatusError → logged + None.
    429 → retried (1s/2s/4s), then None after MAX_RETRIES_429 attempts.
    """
    for attempt in range(MAX_RETRIES_429):
        try:
            return _fetch_mitre_cve(cve_id)
        except httpx.HTTPStatusError as e:
            if e.response.status_code != 429:
                log.warning("MITRE %d for %s (no retry)", e.response.status_code, cve_id)
                return None
            delay = BACKOFF_SCHEDULE[attempt]
            log.warning("MITRE 429 for %s — backoff %.1fs (attempt %d)", cve_id, delay, attempt + 1)
            time.sleep(delay)
    log.warning("MITRE 429 for %s — giving up after %d retries", cve_id, MAX_RETRIES_429)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill empty MITRE fields for CVEs.")
    parser.add_argument("--dry-run", action="store_true", help="preview, no writes")
    parser.add_argument("--reset", action="store_true", help="ignore checkpoint, start from beginning")
    parser.add_argument("--limit", type=int, default=0, help="cap total updates (0 = unlimited)")
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--state-file", default=DEFAULT_STATE_FILE)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    init_all_dbs()

    state_path = Path(args.state_file)
    last_id = "" if args.reset else load_state(state_path)
    log.info("Starting backfill (dry_run=%s, last_id=%r, limit=%d)", args.dry_run, last_id, args.limit)

    start = time.monotonic()
    total_updated = total_skipped = total_failed = 0
    batch_num = 0

    while True:
        if args.limit and total_updated >= args.limit:
            log.info("Reached --limit=%d, stopping", args.limit)
            break

        cve_ids = query_batch(last_id, args.batch_size)
        if not cve_ids:
            log.info("No more empty CVEs; done.")
            break

        batch_num += 1
        batch_start = time.monotonic()

        for cve_id in cve_ids:
            if args.limit and total_updated >= args.limit:
                break

            record = fetch_with_backoff(cve_id)
            if record is None:
                total_failed += 1
                last_id = cve_id
                continue

            try:
                parsed = _parse_mitre_cve(record)
            except (ValueError, KeyError, TypeError, AttributeError) as e:
                log.warning("parse_mitre failed for %s: %s", cve_id, e)
                total_failed += 1
                last_id = cve_id
                continue

            if not parsed.get("cve_id") or parsed.get("_skip"):
                total_skipped += 1
                last_id = cve_id
                continue

            if args.dry_run:
                log.info(
                    "[DRY RUN] would upsert %s (cwe=%s cvss=%s ap=%d)",
                    cve_id,
                    parsed.get("cwe_id"),
                    parsed.get("cvss_v3"),
                    len(parsed.get("affected_products") or []),
                )
            else:
                upsert_cve_if_absent(parsed)
                record_cve_source(cve_id, "mitre", f"https://www.cve.org/CVERecord?id={cve_id}")

            total_updated += 1
            last_id = cve_id
            time.sleep(BASE_THROTTLE)

        if not args.dry_run:
            save_state(state_path, last_id)

        elapsed = time.monotonic() - batch_start
        rate = len(cve_ids) / elapsed if elapsed > 0 else 0
        log.info(
            "batch=%d processed=%d updated=%d skipped=%d failed=%d elapsed=%.1fs rate=%.1fcve/s",
            batch_num,
            len(cve_ids),
            total_updated,
            total_skipped,
            total_failed,
            elapsed,
            rate,
        )

    total_elapsed = time.monotonic() - start
    log.info(
        "DONE total_updated=%d total_skipped=%d total_failed=%d elapsed=%.1fs",
        total_updated,
        total_skipped,
        total_failed,
        total_elapsed,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
