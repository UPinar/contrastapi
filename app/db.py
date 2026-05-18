"""Database operations for ContrastAPI

Three SQLite databases:
  api.db         — API keys + usage tracking
  cve.db         — CVE/EPSS/KEV data
  domain_cache.db — domain intel cache (24h TTL)
"""

import hashlib
import hmac
import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from config import (
    CACHE_MAX_BYTES,
    DOMAIN_CACHE_TTL,
    IP_CACHE_TTL,
    VERSION,
    settings,
)
from fastapi.concurrency import run_in_threadpool

logger = logging.getLogger("contrastapi")

# Map common Maven artifactIds to NVD canonical product names.
PRODUCT_ALIAS: dict[str, str] = {
    # Log4j
    "log4j-core": "log4j",
    "log4j-api": "log4j",
    # Logback
    "logback-core": "logback",
    "logback-classic": "logback",
    # Spring Framework
    "spring-core": "spring_framework",
    "spring-web": "spring_framework",
    "spring-beans": "spring_framework",
    "spring-context": "spring_framework",
    "spring-webmvc": "spring_framework",
    # Spring Boot
    "spring-boot": "spring_boot",
    "spring-boot-autoconfigure": "spring_boot",
    # Tomcat
    "tomcat-embed-core": "tomcat",
    "tomcat-embed-websocket": "tomcat",
    # Apache Commons
    "commons-text": "commons_text",
    "commons-fileupload": "commons_fileupload",
    # Struts
    "struts2-core": "struts",
}


def _normalize_product(name: str | None) -> str | None:
    """Map common Maven artifactIds to NVD canonical product names.
    Case-insensitive lookup. Returns input unchanged if no alias exists."""
    if not name:
        return name
    return PRODUCT_ALIAS.get(name.strip().lower(), name)


# Public aliases for cross-module use (callers should not depend on _-prefixed names).
normalize_product = _normalize_product


# Resolve HMAC key once at import time (settings.hash_secret guarantees non-empty fallback)
_hmac_key = settings.hash_secret.encode()

_local = threading.local()


def _get_conn(db_path: str) -> sqlite3.Connection:
    """Return a reusable per-thread connection for the given DB."""
    attr = f"conn_{db_path}"
    conn = getattr(_local, attr, None)
    if conn is None:
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-8000")
        conn.execute("PRAGMA mmap_size=67108864")
        setattr(_local, attr, conn)
    return conn


@contextmanager
def get_api_db():
    """Thread-safe connection to api.db"""
    con = _get_conn(str(settings.api_db))
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise


@contextmanager
def get_cve_db():
    """Thread-safe connection to cve.db"""
    con = _get_conn(str(settings.cve_db))
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise


@contextmanager
def get_cache_db():
    """Thread-safe connection to domain_cache.db"""
    con = _get_conn(str(settings.cache_db))
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise


def close_thread_connections():
    """Close all thread-local connections (for cleanup/testing)."""
    for attr in list(vars(_local)):
        if attr.startswith("conn_"):
            conn = getattr(_local, attr)
            if conn is not None:
                conn.close()
            delattr(_local, attr)


def init_api_db():
    """Create api.db tables: api_keys, api_usage, ip_limits"""
    with get_api_db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY,
                key_hash TEXT UNIQUE NOT NULL,
                order_id TEXT,
                active INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                pending_key TEXT,
                pending_key_created_at TEXT
            )
        """)
        # Migration: add pending_key_created_at if missing (existing installs)
        cols = {r[1] for r in con.execute("PRAGMA table_info(api_keys)").fetchall()}
        if "pending_key_created_at" not in cols:
            con.execute("ALTER TABLE api_keys ADD COLUMN pending_key_created_at TEXT")
        # Migration: add expires_at for one-time crypto keys (NULL = no expiry,
        # used by Lemon Squeezy subscriptions which deactivate via webhook)
        if "expires_at" not in cols:
            con.execute("ALTER TABLE api_keys ADD COLUMN expires_at TEXT")
        con.execute("""
            CREATE TABLE IF NOT EXISTS api_usage (
                id INTEGER PRIMARY KEY,
                key_hash TEXT,
                client_ip TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                called_at TEXT NOT NULL
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_usage_ip ON api_usage(client_ip, called_at)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_usage_key ON api_usage(key_hash, called_at)")
        con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_keys_order ON api_keys(order_id) WHERE order_id IS NOT NULL")


def init_cve_db():
    """Create cve.db tables: cves, cve_products, sync_status"""
    with get_cve_db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_v3 REAL,
                cvss_vector TEXT,
                cwe_id TEXT,
                cwes TEXT,
                published TEXT,
                modified TEXT,
                epss_score REAL,
                epss_percentile REAL,
                in_kev INTEGER DEFAULT 0,
                kev_date_added TEXT,
                affected_products TEXT,
                refs TEXT,
                summary TEXT,
                synced_at TEXT
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_cves_epss ON cves(epss_score)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(in_kev)")
        # Migration: add cwes JSON-array column if missing (existing installs); backfill from cwe_id.
        cve_cols = {row[1] for row in con.execute("PRAGMA table_info(cves)")}
        if "cwes" not in cve_cols:
            con.execute("ALTER TABLE cves ADD COLUMN cwes TEXT")
            con.execute("UPDATE cves SET cwes = json_array(cwe_id) WHERE cwe_id IS NOT NULL AND cwes IS NULL")
        # Batch 5 v1.29.0: NVD vulnerability_status + cve_tags columns.
        if "vulnerability_status" not in cve_cols:
            con.execute("ALTER TABLE cves ADD COLUMN vulnerability_status TEXT")
        if "cve_tags" not in cve_cols:
            con.execute("ALTER TABLE cves ADD COLUMN cve_tags TEXT")
        # Batch 6A v1.29.x: NVD references[].tags adoption + total_references honesty.
        if "refs_with_tags" not in cve_cols:
            con.execute("ALTER TABLE cves ADD COLUMN refs_with_tags TEXT")
        if "total_references_upstream" not in cve_cols:
            con.execute("ALTER TABLE cves ADD COLUMN total_references_upstream INTEGER")
        # Batch 7 v1.29.x: CVSSv2 storage + multi-source severity merge columns.
        if "cvss_v2" not in cve_cols:
            con.execute("ALTER TABLE cves ADD COLUMN cvss_v2 REAL")
        if "cvss_v2_vector" not in cve_cols:
            con.execute("ALTER TABLE cves ADD COLUMN cvss_v2_vector TEXT")
        if "severity_sources" not in cve_cols:
            con.execute("ALTER TABLE cves ADD COLUMN severity_sources TEXT")
        con.execute("""
            CREATE TABLE IF NOT EXISTS cve_products (
                id INTEGER PRIMARY KEY,
                cve_id TEXT NOT NULL,
                vendor TEXT,
                product TEXT,
                version_start TEXT,
                version_end TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_products_vendor ON cve_products(vendor, product)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_products_product_lower ON cve_products(LOWER(product))")
        con.execute("CREATE INDEX IF NOT EXISTS idx_products_cve_id ON cve_products(cve_id)")
        # batch g v1.30.0: NVD CPE part awareness (a/o/h) + vulnerable flag.
        # Existing rows have NULL until a full NVD re-sync runs — the search
        # filter uses COALESCE(vulnerable, 1) = 1 so unset rows keep matching.
        prod_cols = {row[1] for row in con.execute("PRAGMA table_info(cve_products)")}
        if "cpe_part" not in prod_cols:
            con.execute("ALTER TABLE cve_products ADD COLUMN cpe_part TEXT")
        if "vulnerable" not in prod_cols:
            con.execute("ALTER TABLE cve_products ADD COLUMN vulnerable INTEGER")
        # Functional index on LOWER(product) so the planner can serve the cve_search
        # filter (LOWER(product)=? AND COALESCE(vulnerable,1)=1) in one lookup.
        # Plain `product` column would not bind to LOWER(?) — picking idx_products_cve_id
        # instead and forcing a per-row scan of the joined products.
        con.execute("CREATE INDEX IF NOT EXISTS idx_products_vuln ON cve_products(LOWER(product), vulnerable)")
        con.execute("""
            CREATE TABLE IF NOT EXISTS sync_status (
                source TEXT PRIMARY KEY,
                last_sync TEXT,
                records_count INTEGER,
                status TEXT,
                checkpoint TEXT
            )
        """)
        # Migration: add checkpoint column if missing (existing installs)
        cols = {row[1] for row in con.execute("PRAGMA table_info(sync_status)")}
        if "checkpoint" not in cols:
            con.execute("ALTER TABLE sync_status ADD COLUMN checkpoint TEXT")
        con.execute("""
            CREATE TABLE IF NOT EXISTS cve_sources (
                cve_id TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                source_url TEXT,
                PRIMARY KEY (cve_id, source)
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_cve_sources_first_seen ON cve_sources(first_seen_at DESC)")
        con.execute("""
            CREATE TABLE IF NOT EXISTS exploits (
                edb_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                date_published TEXT,
                author TEXT,
                type TEXT,
                platform TEXT,
                port INTEGER,
                verified INTEGER DEFAULT 0,
                description TEXT,
                source_url TEXT,
                date_added TEXT,
                date_updated TEXT,
                tags TEXT,
                synced_at TEXT,
                PRIMARY KEY (edb_id, cve_id)
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_exploits_cve_id ON exploits(cve_id)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_exploits_author ON exploits(author)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_exploits_type ON exploits(type)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_exploits_verified ON exploits(verified)")
        # Batch 7: exploitdb_meta singleton (id=1) — per-feed sync timestamp,
        # distinct from sync_status.last_sync. Updated by sync_exploitdb on success;
        # read by _exploit_lookup_verdict for data_age_seconds.
        con.execute("""
            CREATE TABLE IF NOT EXISTS exploitdb_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                synced_at TEXT
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS kev_details (
                cve_id TEXT PRIMARY KEY,
                due_date TEXT,
                required_action TEXT,
                known_ransomware_use INTEGER DEFAULT 0,
                vendor_project TEXT,
                product TEXT,
                vulnerability_name TEXT,
                short_description TEXT,
                notes TEXT,
                cwes TEXT,
                updated_at TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_kev_details_ransomware ON kev_details(known_ransomware_use)")
        # Batch 5 v1.29.0: KEV catalog dateUpdated + soft-delete date_removed columns.
        kev_cols = {row[1] for row in con.execute("PRAGMA table_info(kev_details)")}
        if "date_updated" not in kev_cols:
            con.execute("ALTER TABLE kev_details ADD COLUMN date_updated TEXT")
        if "date_removed" not in kev_cols:
            con.execute("ALTER TABLE kev_details ADD COLUMN date_removed TEXT")
        con.execute("""
            CREATE TABLE IF NOT EXISTS cwes (
                cwe_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                extended_description TEXT,
                abstract_type TEXT,
                status TEXT,
                likelihood TEXT,
                mitigations TEXT,
                examples TEXT,
                parent_cwe TEXT,
                child_cwes TEXT,
                updated_at TEXT
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_cwes_parent ON cwes(parent_cwe)")
        con.execute("""
            CREATE TABLE IF NOT EXISTS atlas_techniques (
                technique_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                tactics TEXT,
                maturity TEXT,
                attack_reference_id TEXT,
                attack_reference_url TEXT,
                subtechnique_of TEXT,
                created_date TEXT,
                modified_date TEXT,
                updated_at TEXT
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_atlas_attack_ref ON atlas_techniques(attack_reference_id)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_atlas_subtech ON atlas_techniques(subtechnique_of)")
        con.execute("""
            CREATE TABLE IF NOT EXISTS atlas_case_studies (
                case_study_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                techniques_used TEXT,
                updated_at TEXT
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS d3fend_defenses (
                defense_id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                uri TEXT NOT NULL,
                parent_label TEXT,
                description TEXT,
                tactic TEXT NOT NULL,
                artifact TEXT,
                updated_at TEXT
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_d3fend_tactic ON d3fend_defenses(tactic)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_d3fend_parent ON d3fend_defenses(parent_label)")
        con.execute("""
            CREATE TABLE IF NOT EXISTS d3fend_attack_mappings (
                defense_id TEXT NOT NULL,
                attack_technique_id TEXT NOT NULL,
                attack_label TEXT,
                attack_tactic TEXT,
                PRIMARY KEY (defense_id, attack_technique_id)
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_d3fend_attack_id ON d3fend_attack_mappings(attack_technique_id)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_d3fend_def_id ON d3fend_attack_mappings(defense_id)")
        # One-shot backfill: mark all existing CVEs as source='nvd' (guarded by empty check)
        already = con.execute("SELECT 1 FROM cve_sources LIMIT 1").fetchone()
        if not already:
            con.execute(
                "INSERT OR IGNORE INTO cve_sources (cve_id, source, first_seen_at, last_seen_at, source_url) "
                "SELECT cve_id, 'nvd', synced_at, synced_at, 'https://nvd.nist.gov/vuln/detail/' || cve_id "
                "FROM cves WHERE synced_at IS NOT NULL"
            )


def init_cache_db():
    """Create domain_cache.db table"""
    with get_cache_db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS domain_cache (
                domain TEXT PRIMARY KEY,
                result_json TEXT NOT NULL,
                fetched_at TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS ip_cache (
                ip TEXT PRIMARY KEY,
                result_json TEXT NOT NULL,
                fetched_at TEXT NOT NULL
            )
        """)


def init_all_dbs():
    """Initialize all three databases."""
    init_api_db()
    init_cve_db()
    init_cache_db()


# --- API key operations ---


def save_api_key(key_hash: str, order_id: str | None = None, expires_at: str | None = None) -> None:
    """Insert a new API key row.

    expires_at: ISO-8601 UTC timestamp at which the key stops authorising
    requests. NULL = no expiry (used by Lemon Squeezy subscriptions which
    deactivate via the cancel/expire webhook). Crypto one-time invoices set
    this to (now + 30 days).
    """
    now = datetime.now(UTC).isoformat()
    with get_api_db() as con:
        con.execute(
            "INSERT INTO api_keys (key_hash, order_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (key_hash, order_id, now, expires_at),
        )


def get_api_key(key_hash: str) -> dict | None:
    """Return the row for an active, non-expired key.

    A key with expires_at IS NULL never expires (subscription model).
    A key with expires_at <= now is treated as inactive (one-time payment lapsed).
    """
    now = datetime.now(UTC).isoformat()
    with get_api_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        row = cur.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? AND active = 1 AND (expires_at IS NULL OR expires_at > ?)",
            (key_hash, now),
        ).fetchone()
        return dict(row) if row else None


def touch_api_key(key_hash: str) -> None:
    now = datetime.now(UTC).isoformat()
    with get_api_db() as con:
        con.execute("UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?", (now, key_hash))


async def aget_api_key(key_hash: str) -> dict | None:
    return await run_in_threadpool(get_api_key, key_hash)


async def atouch_api_key(key_hash: str) -> None:
    await run_in_threadpool(touch_api_key, key_hash)


def get_key_by_order_id(order_id: str) -> dict | None:
    """Look up an API key by Lemon Squeezy order ID."""
    with get_api_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        row = cur.execute("SELECT * FROM api_keys WHERE order_id = ?", (order_id,)).fetchone()
        return dict(row) if row else None


def save_pending_key(order_id: str, raw_key: str) -> None:
    """Store raw API key temporarily so the welcome page can show it once."""
    with get_api_db() as con:
        con.execute(
            "UPDATE api_keys SET pending_key = ?, pending_key_created_at = ? WHERE order_id = ?",
            (raw_key, datetime.now(UTC).isoformat(), order_id),
        )


def save_api_key_with_pending(
    key_hash: str,
    raw_key: str,
    order_id: str,
    expires_at: str | None = None,
) -> None:
    """Atomically insert a new API key row WITH its one-time pending raw key.

    Single INSERT (one transaction) — guarantees we never end up with an
    api_keys row whose pending_key is NULL because a follow-up UPDATE crashed
    between two statements. The welcome-page polling flow assumes that an
    existing api_keys row implies pending_key is either populated or already
    consumed; the previous two-statement pattern violated that invariant on
    `save_pending_key` failure (disk full, lock contention, process kill).

    UNIQUE constraint on order_id is enforced; caller catches IntegrityError
    for the concurrent-IPN race path.
    """
    now = datetime.now(UTC).isoformat()
    with get_api_db() as con:
        con.execute(
            "INSERT INTO api_keys "
            "(key_hash, order_id, created_at, expires_at, pending_key, pending_key_created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (key_hash, order_id, now, expires_at, raw_key, now),
        )


def has_pending_key(order_id: str) -> bool:
    """Check if a pending key exists for the order (without revealing or clearing it)."""
    with get_api_db() as con:
        row = con.execute(
            "SELECT 1 FROM api_keys WHERE order_id = ? AND pending_key IS NOT NULL", (order_id,)
        ).fetchone()
        return row is not None


def cleanup_expired_pending_keys(max_age_hours: int = 24) -> int:
    """Remove pending keys older than max_age_hours. Returns count of cleared keys."""
    cutoff = (datetime.now(UTC) - timedelta(hours=max_age_hours)).isoformat()
    with get_api_db() as con:
        cur = con.execute(
            "UPDATE api_keys SET pending_key = NULL, pending_key_created_at = NULL "
            "WHERE pending_key IS NOT NULL AND pending_key_created_at < ?",
            (cutoff,),
        )
        return cur.rowcount


def get_and_clear_pending_key(order_id: str) -> str | None:
    """Atomically return and clear the pending raw key.

    BEGIN IMMEDIATE acquires a write lock upfront, preventing concurrent
    readers from seeing the key between SELECT and UPDATE (no TOCTOU window).
    """
    con = _get_conn(str(settings.api_db))
    try:
        con.execute("BEGIN IMMEDIATE")
        row = con.execute(
            "SELECT pending_key FROM api_keys WHERE order_id = ? AND pending_key IS NOT NULL",
            (order_id,),
        ).fetchone()
        if row is None:
            con.commit()
            return None
        con.execute(
            "UPDATE api_keys SET pending_key = NULL, pending_key_created_at = NULL WHERE order_id = ?",
            (order_id,),
        )
        con.commit()
        return row[0]
    except Exception:
        con.rollback()
        raise


def deactivate_api_key(order_id: str) -> int:
    with get_api_db() as con:
        cur = con.execute("UPDATE api_keys SET active = 0, pending_key = NULL WHERE order_id = ?", (order_id,))
        return cur.rowcount


# --- Usage tracking ---


def hash_client_ip(ip: str) -> str:
    """Hash a client IP with HMAC for privacy-safe analytics. Returns 16-char hex digest."""
    return hmac.new(_hmac_key, ip.encode(), hashlib.sha256).hexdigest()[:16]


def normalize_endpoint(endpoint: str) -> str:
    """Strip path parameters from endpoint paths for privacy-safe logging.

    /v1/domain/example.com → /v1/domain
    /v1/ip/8.8.8.8 → /v1/ip
    /v1/cve/CVE-2024-1234 → /v1/cve
    /v1/email/mx/user@x.com → /v1/email/mx
    /v1/email/disposable/x.com → /v1/email/disposable
    /v1/scan/headers/x.com → /v1/scan/headers
    /v1/phone/+905551234 → /v1/phone
    """
    ep = endpoint.rstrip("/")

    # 3-segment routes with path param at position 4
    _three_seg = ("/v1/email/mx/", "/v1/email/disposable/", "/v1/scan/headers/")
    for prefix in _three_seg:
        if endpoint.startswith(prefix):
            return prefix.rstrip("/")

    # 2-segment routes that take a path param at position 3
    _parameterized = (
        "domain",
        "ip",
        "cve",
        "phone",
        "asn",
        "exploit",
        "dns",
        "whois",
        "subdomains",
        "certs",
        "ssl",
        "threat",
        "tech",
        "monitor",
    )
    parts = ep.split("/")
    # /v1/domain/example.com → ["", "v1", "domain", "example.com"]
    if len(parts) > 3 and parts[1] == "v1" and parts[2] in _parameterized:
        return "/".join(parts[:3])

    return ep


def log_usage(client_ip: str, endpoint: str, key_hash: str | None = None) -> None:
    now = datetime.now(UTC).isoformat()
    ip_hash = hash_client_ip(client_ip)
    endpoint = normalize_endpoint(endpoint)
    with get_api_db() as con:
        con.execute(
            "INSERT INTO api_usage (key_hash, client_ip, endpoint, called_at) VALUES (?, ?, ?, ?)",
            (key_hash, ip_hash, endpoint, now),
        )


async def alog_usage(client_ip: str, endpoint: str, key_hash: str | None = None) -> None:
    await run_in_threadpool(log_usage, client_ip, endpoint, key_hash)


def get_total_requests() -> int:
    """Get total API call count from api_usage table."""
    with get_api_db() as con:
        return con.execute("SELECT COUNT(*) FROM api_usage").fetchone()[0]


def get_key_usage_stats(key_hash: str) -> dict:
    """Get usage statistics for a Pro API key."""
    with get_api_db() as con:
        # Total requests
        total = con.execute("SELECT COUNT(*) FROM api_usage WHERE key_hash = ?", (key_hash,)).fetchone()[0]

        # Last 24h
        cutoff_24h = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
        last_24h = con.execute(
            "SELECT COUNT(*) FROM api_usage WHERE key_hash = ? AND called_at >= ?", (key_hash, cutoff_24h)
        ).fetchone()[0]

        # Last 1h
        cutoff_1h = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        last_1h = con.execute(
            "SELECT COUNT(*) FROM api_usage WHERE key_hash = ? AND called_at >= ?", (key_hash, cutoff_1h)
        ).fetchone()[0]

        # Top endpoints
        rows = con.execute(
            "SELECT endpoint, COUNT(*) as cnt FROM api_usage WHERE key_hash = ? "
            "GROUP BY endpoint ORDER BY cnt DESC LIMIT 10",
            (key_hash,),
        ).fetchall()
        top_endpoints = [{"endpoint": r[0], "count": r[1]} for r in rows]

        return {
            "total_requests": total,
            "last_24h": last_24h,
            "last_1h": last_1h,
            "top_endpoints": top_endpoints,
        }


def get_privacy_data(client_ip: str, key_hash: str | None = None) -> dict:
    """Return everything the DB has about a caller — for /v1/privacy/my-data transparency endpoint.

    Looks up api_usage by hashed IP (if free) or key_hash (if pro), plus the api_keys row
    for pro. Query parameters (domains, IPs, CVEs, etc.) are never stored, so they cannot
    appear here — see normalize_endpoint() above.
    """
    ip_hash = hash_client_ip(client_ip)
    cutoff_24h = (datetime.now(UTC) - timedelta(hours=24)).isoformat()

    with get_api_db() as con:
        if key_hash:
            filter_col = "key_hash"
            filter_val = key_hash
        else:
            filter_col = "client_ip"
            filter_val = ip_hash

        total_24h = con.execute(
            f"SELECT COUNT(*) FROM api_usage WHERE {filter_col} = ? AND called_at >= ?",
            (filter_val, cutoff_24h),
        ).fetchone()[0]

        rows = con.execute(
            f"SELECT endpoint, COUNT(*) as cnt, MAX(called_at) as last "
            f"FROM api_usage WHERE {filter_col} = ? AND called_at >= ? "
            f"GROUP BY endpoint ORDER BY cnt DESC LIMIT 20",
            (filter_val, cutoff_24h),
        ).fetchall()
        by_endpoint = [{"endpoint": r[0], "count": r[1], "last_called_at": r[2]} for r in rows]

        api_key_record = None
        if key_hash:
            row = con.execute(
                "SELECT order_id, active, created_at, last_used_at FROM api_keys WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()
            if row:
                api_key_record = {
                    "order_id": row[0],
                    "active": bool(row[1]),
                    "created_at": row[2],
                    "last_used_at": row[3],
                }

    return {
        "client_ip_hash": ip_hash,
        "api_key_record": api_key_record,
        "usage_last_24h": {
            "total_requests": total_24h,
            "by_endpoint": by_endpoint,
        },
    }


# --- Domain cache ---


def maintenance() -> dict:
    """Run database maintenance: purge old data + ANALYZE. Each unit is independently guarded so one SQLITE_BUSY does not abort the rest."""
    stats = {}

    # Unit 1: Purge usage older than 90 days + normalize legacy endpoint paths
    try:
        cutoff = (datetime.now(UTC) - timedelta(days=90)).isoformat()
        with get_api_db() as con:
            # Raise busy_timeout only for this maintenance run, then restore in
            # finally. The thread-local connection is shared with the event-loop
            # thread's ratelimit.py / log_usage path, so a leaked 30s timeout
            # would stall the hot request path under lock contention.
            con.execute("PRAGMA busy_timeout=30000")
            try:
                cur = con.execute("DELETE FROM api_usage WHERE called_at < ?", (cutoff,))
                stats["usage_purged"] = cur.rowcount

                # Retroactive normalize: strip path params from old records
                rows = con.execute("SELECT DISTINCT endpoint FROM api_usage").fetchall()
                normalized_count = 0
                for (ep,) in rows:
                    clean = normalize_endpoint(ep)
                    if clean != ep:
                        con.execute("UPDATE api_usage SET endpoint = ? WHERE endpoint = ?", (clean, ep))
                        normalized_count += 1
                stats["endpoints_normalized"] = normalized_count
                con.execute("ANALYZE")
            finally:
                # lock-free metadata reset; never let it mask the unit's error
                try:
                    con.execute("PRAGMA busy_timeout=5000")
                except Exception:
                    pass
    except Exception as e:
        stats["api_error"] = type(e).__name__

    # Unit 2: Clear unclaimed pending keys older than 24 hours
    try:
        stats["pending_keys_cleared"] = cleanup_expired_pending_keys(max_age_hours=24)
    except Exception as e:
        stats["pending_keys_error"] = type(e).__name__

    # Unit 3: Purge expired domain cache and IP cache
    try:
        with get_cache_db() as con:
            con.execute("PRAGMA busy_timeout=30000")
            try:
                now = datetime.now(UTC)

                cache_cutoff = (now - timedelta(seconds=DOMAIN_CACHE_TTL)).isoformat()
                cur = con.execute("DELETE FROM domain_cache WHERE fetched_at < ?", (cache_cutoff,))
                stats["cache_purged"] = cur.rowcount

                ip_cutoff = (now - timedelta(seconds=IP_CACHE_TTL)).isoformat()
                cur = con.execute("DELETE FROM ip_cache WHERE fetched_at < ?", (ip_cutoff,))
                stats["ip_cache_purged"] = cur.rowcount
                con.execute("ANALYZE")
            finally:
                # lock-free metadata reset; never let it mask the unit's error
                try:
                    con.execute("PRAGMA busy_timeout=5000")
                except Exception:
                    pass
    except Exception as e:
        stats["cache_error"] = type(e).__name__

    # Unit 4: ANALYZE on CVE db
    try:
        with get_cve_db() as con:
            con.execute("PRAGMA busy_timeout=30000")
            try:
                con.execute("ANALYZE")
            finally:
                # lock-free metadata reset; never let it mask the unit's error
                try:
                    con.execute("PRAGMA busy_timeout=5000")
                except Exception:
                    pass
    except Exception as e:
        stats["cve_error"] = type(e).__name__

    # Status: "ok" if no unit errored, else "partial"
    stats["status"] = "ok" if not any(k.endswith("_error") for k in stats) else "partial"
    return stats


def _versioned(key: str) -> str:
    """Prefix cache keys with the running VERSION so a release auto-invalidates stale
    response shapes. Old entries without the version prefix become orphans and expire
    naturally via TTL — maintenance() will purge them. Eliminates the post-deploy
    "stale cache returns old fields/tags" debugging trap.
    """
    return f"{VERSION}:{key}"


def get_cached_domain(domain: str) -> dict | None:
    """Get cached domain result if not expired."""
    key = _versioned(domain)
    with get_cache_db() as con:
        row = con.execute("SELECT result_json, fetched_at FROM domain_cache WHERE domain = ?", (key,)).fetchone()
        if row is None:
            return None
        fetched = datetime.fromisoformat(row[1])
        age = (datetime.now(UTC) - fetched).total_seconds()
        if age > DOMAIN_CACHE_TTL:
            return None  # expired — maintenance() handles cleanup
        return json.loads(row[0])


def get_cached_domain_with_age(key: str) -> tuple[dict, int] | None:
    """Get cached domain result + age in seconds. Returns None if missing/expired."""
    versioned_key = _versioned(key)
    with get_cache_db() as con:
        row = con.execute(
            "SELECT result_json, fetched_at FROM domain_cache WHERE domain = ?", (versioned_key,)
        ).fetchone()
        if row is None or row[1] is None:
            return None
        try:
            fetched = datetime.fromisoformat(row[1])
        except (ValueError, TypeError):
            logger.warning("domain cache: malformed fetched_at")
            return None
        age = int((datetime.now(UTC) - fetched).total_seconds())
        if age > DOMAIN_CACHE_TTL:
            return None
        if age < 0:
            age = 0
        return json.loads(row[0]), age


def save_cached_domain(domain: str, result: dict) -> None:
    key = _versioned(domain)
    now = datetime.now(UTC).isoformat()
    result_str = json.dumps(result)
    if len(result_str) > CACHE_MAX_BYTES:
        logger.warning("domain cache entry too large (%d bytes), skipping", len(result_str))
        return
    with get_cache_db() as con:
        con.execute(
            "INSERT OR REPLACE INTO domain_cache (domain, result_json, fetched_at) VALUES (?, ?, ?)",
            (key, result_str, now),
        )


async def aget_cached_domain(domain: str) -> dict | None:
    return await run_in_threadpool(get_cached_domain, domain)


async def asave_cached_domain(domain: str, result: dict) -> None:
    await run_in_threadpool(save_cached_domain, domain, result)


# --- IP cache ---


def get_cached_ip(ip: str) -> dict | None:
    """Get cached IP reputation result if not expired."""
    key = _versioned(ip)
    with get_cache_db() as con:
        row = con.execute("SELECT result_json, fetched_at FROM ip_cache WHERE ip = ?", (key,)).fetchone()
        if row is None:
            return None
        fetched = datetime.fromisoformat(row[1])
        age = (datetime.now(UTC) - fetched).total_seconds()
        if age > IP_CACHE_TTL:
            return None  # expired — maintenance() handles cleanup
        return json.loads(row[0])


def get_cached_ip_with_age(ip: str) -> tuple[dict, int] | None:
    """Get cached IP reputation result + age in seconds. Returns None if missing/expired."""
    key = _versioned(ip)
    with get_cache_db() as con:
        row = con.execute("SELECT result_json, fetched_at FROM ip_cache WHERE ip = ?", (key,)).fetchone()
        if row is None or row[1] is None:
            return None
        try:
            fetched = datetime.fromisoformat(row[1])
        except (ValueError, TypeError):
            logger.warning("ip cache: malformed fetched_at")
            return None
        age = int((datetime.now(UTC) - fetched).total_seconds())
        if age > IP_CACHE_TTL:
            return None
        if age < 0:
            age = 0
        return json.loads(row[0]), age


def save_cached_ip(ip: str, result: dict) -> None:
    key = _versioned(ip)
    now = datetime.now(UTC).isoformat()
    result_str = json.dumps(result)
    if len(result_str) > CACHE_MAX_BYTES:
        logger.warning("IP cache entry too large (%d bytes), skipping", len(result_str))
        return
    with get_cache_db() as con:
        con.execute(
            "INSERT OR REPLACE INTO ip_cache (ip, result_json, fetched_at) VALUES (?, ?, ?)", (key, result_str, now)
        )


async def aget_cached_domain_with_age(key: str) -> tuple[dict, int] | None:
    return await run_in_threadpool(get_cached_domain_with_age, key)


async def aget_cached_ip(ip: str) -> dict | None:
    return await run_in_threadpool(get_cached_ip, ip)


async def aget_cached_ip_with_age(ip: str) -> tuple[dict, int] | None:
    return await run_in_threadpool(get_cached_ip_with_age, ip)


async def asave_cached_ip(ip: str, result: dict) -> None:
    await run_in_threadpool(save_cached_ip, ip, result)


# --- CVE operations ---


def upsert_cve(cve_data: dict) -> None:
    now = datetime.now(UTC).isoformat()
    with get_cve_db() as con:
        con.execute(
            """
            INSERT OR REPLACE INTO cves
            (cve_id, description, severity, cvss_v3, cvss_vector, cwe_id, cwes,
             published, modified, epss_score, epss_percentile,
             in_kev, kev_date_added, affected_products, refs, summary,
             vulnerability_status, cve_tags, refs_with_tags, total_references_upstream,
             cvss_v2, cvss_v2_vector, severity_sources, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                cve_data["cve_id"],
                cve_data.get("description"),
                cve_data.get("severity"),
                cve_data.get("cvss_v3"),
                cve_data.get("cvss_vector"),
                cve_data.get("cwe_id"),
                json.dumps(cve_data["cwes"]) if cve_data.get("cwes") is not None else None,
                cve_data.get("published"),
                cve_data.get("modified"),
                cve_data.get("epss_score"),
                cve_data.get("epss_percentile"),
                cve_data.get("in_kev", 0),
                cve_data.get("kev_date_added"),
                json.dumps(cve_data.get("affected_products", [])),
                json.dumps(cve_data.get("refs", [])),
                cve_data.get("summary"),
                cve_data.get("vulnerability_status"),
                json.dumps(cve_data["cve_tags"]) if cve_data.get("cve_tags") is not None else None,
                json.dumps(cve_data["refs_with_tags"]) if cve_data.get("refs_with_tags") is not None else None,
                cve_data.get("total_references_upstream"),
                cve_data.get("cvss_v2"),
                cve_data.get("cvss_v2_vector"),
                json.dumps(cve_data["severity_sources"]) if cve_data.get("severity_sources") is not None else None,
                now,
            ),
        )
        con.execute("DELETE FROM cve_products WHERE cve_id = ?", (cve_data["cve_id"],))
        for p in cve_data.get("affected_products", []):
            vendor = p.get("vendor")
            product = p.get("product")
            if not vendor and not product:
                continue
            con.execute(
                "INSERT INTO cve_products (cve_id, vendor, product, version_start, version_end, cpe_part, vulnerable) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    cve_data["cve_id"],
                    vendor,
                    product,
                    p.get("version_start"),
                    p.get("version_end"),
                    p.get("cpe_part"),
                    1 if p.get("vulnerable", True) else 0,
                ),
            )


def _deserialize_cve(row: sqlite3.Row) -> dict:
    """Convert a CVE row to dict with JSON fields parsed."""
    d = dict(row)
    d["affected_products"] = json.loads(d["affected_products"]) if d["affected_products"] else []
    d["refs"] = json.loads(d["refs"]) if d["refs"] else []
    d["cwes"] = json.loads(d["cwes"]) if d.get("cwes") else None
    d["cve_tags"] = json.loads(d["cve_tags"]) if d.get("cve_tags") else None
    d["refs_with_tags"] = json.loads(d["refs_with_tags"]) if d.get("refs_with_tags") else None
    if d.get("severity_sources"):
        try:
            d["severity_sources"] = json.loads(d["severity_sources"])
        except (json.JSONDecodeError, ValueError):
            logger.warning("malformed severity_sources JSON for CVE %s", d.get("cve_id"))
            d["severity_sources"] = None
    else:
        d["severity_sources"] = None
    return d


def set_exploitdb_synced_at(ts: str | None = None) -> None:
    """Singleton setter for exploitdb_meta.synced_at; defaults to now (UTC ISO)."""
    when = ts or datetime.now(UTC).isoformat()
    with get_cve_db() as con:
        con.execute(
            "INSERT INTO exploitdb_meta (id, synced_at) VALUES (1, ?) "
            "ON CONFLICT(id) DO UPDATE SET synced_at = excluded.synced_at",
            (when,),
        )


def get_exploitdb_synced_at() -> str | None:
    """Singleton reader; returns ISO timestamp or None when never synced."""
    with get_cve_db() as con:
        row = con.execute("SELECT synced_at FROM exploitdb_meta WHERE id = 1").fetchone()
        return row[0] if row else None


async def aget_exploitdb_synced_at() -> str | None:
    return await run_in_threadpool(get_exploitdb_synced_at)


def get_cve(cve_id: str) -> dict | None:
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        row = cur.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()
        return _deserialize_cve(row) if row else None


async def aget_cve(cve_id: str) -> dict | None:
    return await run_in_threadpool(get_cve, cve_id)


def get_leading_cves(limit: int = 50, offset: int = 0) -> tuple[list[dict], int]:
    """Return CVEs that exist in MITRE/GHSA but NOT yet in NVD.
    These are 'leading' CVEs — indexed before NVD enriches them."""
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row

        where = (
            "EXISTS (SELECT 1 FROM cve_sources cs WHERE cs.cve_id = c.cve_id AND cs.source IN ('mitre', 'ghsa')) "
            "AND NOT EXISTS (SELECT 1 FROM cve_sources cs WHERE cs.cve_id = c.cve_id AND cs.source = 'nvd')"
        )
        total = cur.execute(f"SELECT COUNT(*) FROM cves c WHERE {where}").fetchone()[0]
        rows = cur.execute(
            f"SELECT c.* FROM cves c WHERE {where} "
            "ORDER BY (SELECT MIN(first_seen_at) FROM cve_sources WHERE cve_id = c.cve_id) DESC "
            "LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [_deserialize_cve(row) for row in rows], total


async def aget_leading_cves(limit: int = 50, offset: int = 0) -> tuple[list[dict], int]:
    return await run_in_threadpool(get_leading_cves, limit, offset)


def search_cves(
    product: str | None = None,
    severity: str | None = None,
    published_after: str | None = None,
    published_before: str | None = None,
    kev: bool = False,
    epss_min: float | None = None,
    sort: str | None = None,
    limit: int = 50,
    offset: int = 0,
    cwe_id: str | None = None,
    cvss_min: float | None = None,
    cvss_max: float | None = None,
    vendor: str | None = None,
    tagged: bool = False,
) -> tuple[list[dict], int]:
    conditions = []
    params = []
    # batch g v1.30.0: default filter excludes cve_products rows where the product
    # appears as a CPE target_sw / target_hw (vulnerable=0) — only the actually-
    # vulnerable component matches. tagged=True restores the legacy broad behavior.
    # `(vulnerable = 1 OR vulnerable IS NULL)` keeps pre-migration NULL rows in the
    # default set AND remains index-friendly — COALESCE(vulnerable, 1) hides the
    # column behind a function call so SQLite's planner can't bind it to
    # idx_products_vuln.
    vuln_clause = "" if tagged else " AND (vulnerable = 1 OR vulnerable IS NULL)"
    if product and vendor:
        product_norm = _normalize_product(product)
        conditions.append(
            "cve_id IN (SELECT cve_id FROM cve_products WHERE LOWER(product) = LOWER(?) "
            f"AND LOWER(vendor) = LOWER(?){vuln_clause})"
        )
        params.extend([product_norm, vendor])
    elif product:
        product = _normalize_product(product)
        conditions.append(f"cve_id IN (SELECT cve_id FROM cve_products WHERE LOWER(product) = LOWER(?){vuln_clause})")
        params.append(product)
    # vendor: no alias normalization (cve_products.vendor assumed canonical; audit pending)
    elif vendor:
        conditions.append(f"cve_id IN (SELECT cve_id FROM cve_products WHERE LOWER(vendor) = LOWER(?){vuln_clause})")
        params.append(vendor)
    if severity:
        conditions.append("severity = ?")
        params.append(severity.upper())
    if published_after:
        conditions.append("published >= ?")
        params.append(published_after)
    if published_before:
        next_day = (datetime.strptime(published_before, "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")
        conditions.append("published < ?")
        params.append(next_day)
    if kev:
        conditions.append("in_kev = 1")
    if epss_min is not None:
        conditions.append("epss_score >= ?")
        params.append(epss_min)
    if cwe_id is not None:
        conditions.append("UPPER(cwe_id) = UPPER(?)")
        params.append(cwe_id)
    if cvss_min is not None:
        conditions.append("cvss_v3 >= ?")
        params.append(cvss_min)
    if cvss_max is not None:
        conditions.append("cvss_v3 <= ?")
        params.append(cvss_max)

    order_clauses = {
        "epss_desc": "CASE WHEN epss_score IS NULL THEN 1 ELSE 0 END, epss_score DESC",
        "cvss_desc": "CASE WHEN cvss_v3 IS NULL THEN 1 ELSE 0 END, cvss_v3 DESC",
        "published_desc": "published DESC",
    }
    order_by = order_clauses.get(sort, "published DESC")

    where = " AND ".join(conditions) if conditions else "1=1"

    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        total = cur.execute(f"SELECT COUNT(*) FROM cves WHERE {where}", params).fetchone()[0]
        query_params = [*params, limit, offset]
        rows = cur.execute(
            f"SELECT * FROM cves WHERE {where} ORDER BY {order_by} LIMIT ? OFFSET ?", query_params
        ).fetchall()
        return [_deserialize_cve(row) for row in rows], total


async def asearch_cves(**kwargs) -> tuple[list[dict], int]:
    return await run_in_threadpool(search_cves, **kwargs)


def _parse_version(v: str) -> tuple:
    """Parse version string into numeric tuple for correct comparison.
    '2.14.1' → (2, 14, 1), handles non-numeric parts gracefully."""
    parts = []
    for p in v.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(p)
    return tuple(parts)


parse_version = _parse_version


def get_related_cves_by_product(
    product: str,
    vendor: str | None = None,
    limit: int = 5,
    exclude_cve_id: str | None = None,
) -> list[dict]:
    """Return other CVEs affecting the same product, severity DESC."""
    product_norm = _normalize_product(product)
    conditions = ["LOWER(cp.product) = LOWER(?)"]
    params: list = [product_norm]
    if vendor:
        conditions.append("LOWER(cp.vendor) = LOWER(?)")
        params.append(vendor)
    if exclude_cve_id:
        conditions.append("c.cve_id != ?")
        params.append(exclude_cve_id)
    where = " AND ".join(conditions)
    params.append(limit)
    sql = f"""
        SELECT DISTINCT c.cve_id, c.severity, c.cvss_v3
        FROM cves c
        JOIN cve_products cp ON cp.cve_id = c.cve_id
        WHERE {where}
        ORDER BY
          CASE c.severity
            WHEN 'CRITICAL' THEN 1
            WHEN 'HIGH' THEN 2
            WHEN 'MEDIUM' THEN 3
            WHEN 'LOW' THEN 4
            ELSE 5
          END,
          CASE WHEN c.cvss_v3 IS NULL THEN 1 ELSE 0 END,
          c.cvss_v3 DESC
        LIMIT ?
    """
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        rows = cur.execute(sql, tuple(params)).fetchall()
        return [{"cve_id": r["cve_id"], "severity": r["severity"], "cvss_v3": r["cvss_v3"]} for r in rows]


async def aget_related_cves_by_product(**kwargs) -> list[dict]:
    return await run_in_threadpool(get_related_cves_by_product, **kwargs)


def enrich_cves_by_ids(cve_ids: list[str]) -> list[dict]:
    """Look up severity + cvss_v3 for a batch of CVE IDs in a single query.

    Used by /v1/ip and /v1/threat_report to convert ham CVE-ID lists from
    Shodan InternetDB into severity-aware triage payloads (Phase 2 IP
    enrichment). Unknown CVEs are returned as severity='UNKNOWN', cvss_v3=None
    so the agent can still see the CVE ID without inferring it is benign.

    Returned ordering: input list order preserved (deterministic output for
    the agent — Shodan's ordering is meaningful, do not re-sort here).

    Defense in depth: each emitted cve_id is run through
    `_strip_control_chars` before being placed in the output dict. Callers
    are expected to pre-clean their input (Trojan-Source guard at the
    request boundary), but this helper also re-cleans on the way out so a
    forgetful future caller cannot leak bidi overrides into the response.
    Per-item cap: CVE IDs longer than 64 chars are truncated to bound the
    cost of the strip pass + JSON serialization on poisoned upstream input.
    """
    if not cve_ids:
        return []
    # Late import to avoid a domain.recon ↔ db circular at module load.
    from domain.recon import _strip_control_chars

    def _safe(cid: str) -> str:
        # Per-item length bound (real CVE IDs are ~15 chars; 64 is generous).
        return _strip_control_chars(cid)[:64]

    # Defensive cap: Shodan can return tens of vulns per IP, but absurd lists
    # (1000+) blow up SQL parameter limits and waste tokens. Cap at 100;
    # callers can fan out if they really need more.
    cve_ids = cve_ids[:100]
    placeholders = ",".join("?" * len(cve_ids))
    sql = f"""
        SELECT cve_id, severity, cvss_v3
        FROM cves
        WHERE cve_id IN ({placeholders})
    """
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        rows = cur.execute(sql, tuple(cve_ids)).fetchall()
    found = {r["cve_id"]: {"severity": r["severity"], "cvss_v3": r["cvss_v3"]} for r in rows}
    out: list[dict] = []
    for cve_id in cve_ids:
        clean = _safe(cve_id)
        # Look up using the original (caller-supplied) ID so a pre-cleaned
        # caller still hits the same row; emit the re-cleaned form on output.
        hit = found.get(cve_id)
        if hit:
            out.append(
                {
                    "cve_id": clean,
                    "severity": (hit["severity"] or "UNKNOWN").upper(),
                    "cvss_v3": hit["cvss_v3"],
                }
            )
        else:
            out.append({"cve_id": clean, "severity": "UNKNOWN", "cvss_v3": None})
    return out


async def aenrich_cves_by_ids(cve_ids: list[str]) -> list[dict]:
    return await run_in_threadpool(enrich_cves_by_ids, cve_ids)


def search_cves_by_product(product: str, version: str | None = None, limit: int = 20) -> list[dict]:
    """Search CVEs via cve_products table with optional version range check."""
    product = _normalize_product(product)
    escaped = product.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        # Match against cve_products.product (exact or LIKE for partial)
        rows = cur.execute(
            "SELECT DISTINCT c.* FROM cves c "
            "JOIN cve_products p ON c.cve_id = p.cve_id "
            "WHERE p.product LIKE ? ESCAPE '\\' "
            "ORDER BY c.published DESC LIMIT ?",
            (f"%{escaped}%", limit * 3),  # over-fetch to filter by version
        ).fetchall()

    results = []
    parsed_ver = _parse_version(version) if version else None
    for row in rows:
        cve = _deserialize_cve(row)
        if parsed_ver:
            # Check version ranges from affected_products using numeric comparison
            matched = False
            for prod in cve.get("affected_products", []):
                if product.lower() not in (prod.get("product") or "").lower():
                    continue
                vs = prod.get("version_start")
                ve = prod.get("version_end")
                try:
                    if vs and parsed_ver < _parse_version(vs):
                        continue
                    if ve and parsed_ver >= _parse_version(ve):
                        continue
                except TypeError:
                    continue  # incomparable version formats
                matched = True
                break
            if not matched and cve.get("affected_products"):
                continue  # version not in any affected range
        results.append(cve)
        if len(results) >= limit:
            break
    return results


def search_cves_by_products_bulk(products: list[str], limit_per_product: int = 20) -> dict[str, list[dict]]:
    """Bulk variant of search_cves_by_product.

    Given a list of product names, returns a dict mapping
    **NVD canonical product name (lowercase, post-alias)** -> list of CVE rows
    (deserialized, most recent first).

    IMPORTANT: Inputs are passed through _normalize_product() before the query,
    so Maven artifactIds like "log4j-core" are resolved to NVD canonical names
    like "log4j". Callers looking up results in the returned dict MUST apply
    _normalize_product().strip().lower() to their lookup key, or they will
    receive an empty list for any aliased input. See PRODUCT_ALIAS for the
    full alias map.

    Uses exact lowercase match against cve_products.product (indexed by
    idx_products_product_lower), not LIKE substring match. Callers that
    need substring matching must use search_cves_by_product.

    Over-fetches limit_per_product * 3 per product so callers can apply
    additional filtering (e.g. version ranges) without losing results.
    """
    products_lower = list({_normalize_product(p).strip().lower() for p in products if p and p.strip()})
    if not products_lower:
        return {}
    if len(products_lower) > 500:
        raise ValueError(f"Too many products for bulk lookup: {len(products_lower)} (max 500)")
    placeholders = ",".join(["?"] * len(products_lower))
    sql = f"""
        WITH ranked AS (
          SELECT c.*, LOWER(p.product) AS matched,
                 ROW_NUMBER() OVER (
                   PARTITION BY LOWER(p.product)
                   ORDER BY c.published DESC
                 ) AS rn
          FROM cves c
          JOIN cve_products p ON c.cve_id = p.cve_id
          WHERE LOWER(p.product) IN ({placeholders})
        )
        SELECT * FROM ranked WHERE rn <= ?
    """
    params = [*products_lower, limit_per_product * 3]
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        rows = cur.execute(sql, params).fetchall()

    result: dict[str, list[dict]] = {}
    seen: dict[str, set[str]] = {}
    for row in rows:
        matched = row["matched"]
        cve_id = row["cve_id"]
        if matched not in seen:
            seen[matched] = set()
            result[matched] = []
        if cve_id in seen[matched]:
            continue
        seen[matched].add(cve_id)
        result[matched].append(_deserialize_cve(row))
    return result


async def asearch_cves_by_products_bulk(products: list[str], limit_per_product: int = 20) -> dict[str, list[dict]]:
    return await run_in_threadpool(search_cves_by_products_bulk, products, limit_per_product)


def update_epss(cve_id: str, epss_score: float | None, epss_percentile: float | None) -> bool:
    """Update only EPSS fields for a CVE. Returns True if row existed."""
    with get_cve_db() as con:
        cur = con.execute(
            "UPDATE cves SET epss_score=?, epss_percentile=? WHERE cve_id=?", (epss_score, epss_percentile, cve_id)
        )
        return cur.rowcount > 0


def update_kev(cve_id: str, date_added: str | None) -> bool:
    """Update only KEV fields for a CVE. Returns True if row existed."""
    with get_cve_db() as con:
        cur = con.execute("UPDATE cves SET in_kev=1, kev_date_added=? WHERE cve_id=?", (date_added, cve_id))
        return cur.rowcount > 0


def upsert_kev_details(
    cve_id: str,
    *,
    due_date: str | None = None,
    required_action: str | None = None,
    known_ransomware_use: bool = False,
    vendor_project: str | None = None,
    product: str | None = None,
    vulnerability_name: str | None = None,
    short_description: str | None = None,
    notes: str | None = None,
    cwes: list[str] | None = None,
    date_updated: str | None = None,
) -> None:
    """Upsert full CISA KEV record details. Idempotent."""
    now = datetime.now(UTC).isoformat()
    cwes_json = json.dumps(cwes) if cwes else None
    with get_cve_db() as con:
        con.execute(
            """
            INSERT INTO kev_details
                (cve_id, due_date, required_action, known_ransomware_use,
                 vendor_project, product, vulnerability_name, short_description,
                 notes, cwes, date_updated, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                due_date = excluded.due_date,
                required_action = excluded.required_action,
                known_ransomware_use = excluded.known_ransomware_use,
                vendor_project = excluded.vendor_project,
                product = excluded.product,
                vulnerability_name = excluded.vulnerability_name,
                short_description = excluded.short_description,
                notes = excluded.notes,
                cwes = excluded.cwes,
                date_updated = excluded.date_updated,
                updated_at = excluded.updated_at
            """,
            (
                cve_id,
                due_date,
                required_action,
                1 if known_ransomware_use else 0,
                vendor_project,
                product,
                vulnerability_name,
                short_description,
                notes,
                cwes_json,
                date_updated,
                now,
            ),
        )


def get_kev_details(cve_id: str) -> dict | None:
    """Fetch CISA KEV full record. Returns None when the CVE is not in the KEV
    catalog or the kev_details row is missing (sync race / partial write).

    Uses INNER JOIN to require both rows; agents that get a 200 can trust the
    response is fully populated for the fields CISA emits.
    """
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        row = cur.execute(
            """
            SELECT c.cve_id, c.in_kev, c.kev_date_added,
                   k.due_date, k.required_action, k.known_ransomware_use,
                   k.vendor_project, k.product, k.vulnerability_name,
                   k.short_description, k.notes, k.cwes,
                   k.date_updated, k.date_removed, k.updated_at
            FROM cves c
            INNER JOIN kev_details k ON k.cve_id = c.cve_id
            WHERE c.cve_id = ? AND c.in_kev = 1
            """,
            (cve_id,),
        ).fetchone()

    if row is None:
        return None

    cwes_raw = row["cwes"]
    cwes: list[str] = []
    if cwes_raw:
        try:
            decoded = json.loads(cwes_raw)
            if isinstance(decoded, list):
                cwes = [str(c) for c in decoded if c]
        except (json.JSONDecodeError, TypeError):
            cwes = []

    return {
        "cve_id": row["cve_id"],
        "in_kev": True,
        "date_added": row["kev_date_added"],
        "due_date": row["due_date"],
        "required_action": row["required_action"],
        "known_ransomware_use": bool(row["known_ransomware_use"]) if row["known_ransomware_use"] is not None else False,
        "vendor_project": row["vendor_project"],
        "product": row["product"],
        "vulnerability_name": row["vulnerability_name"],
        "short_description": row["short_description"],
        "notes": row["notes"],
        "cwes": cwes,
        "date_updated": row["date_updated"],
        "date_removed": row["date_removed"],
        "updated_at": row["updated_at"],
    }


async def aget_kev_details(cve_id: str) -> dict | None:
    return await run_in_threadpool(get_kev_details, cve_id)


def get_kev_active_cve_ids() -> set[str]:
    """Return cve_ids currently flagged in_kev=1. Pre-sync snapshot for KEV soft-delete diff."""
    with get_cve_db() as con:
        return {row[0] for row in con.execute("SELECT cve_id FROM cves WHERE in_kev = 1")}


async def aget_kev_active_cve_ids() -> set[str]:
    return await run_in_threadpool(get_kev_active_cve_ids)


def mark_kev_removed(cve_id: str, removed_at: str) -> None:
    """Soft-delete: set in_kev=0 + kev_details.date_removed when CVE drops out of feed.
    Idempotent — only updates rows still flagged in_kev=1; re-running on already-removed
    rows is a no-op (date_removed not bumped twice)."""
    with get_cve_db() as con:
        cur = con.execute("UPDATE cves SET in_kev = 0 WHERE cve_id = ? AND in_kev = 1", (cve_id,))
        if cur.rowcount > 0:
            con.execute(
                "UPDATE kev_details SET date_removed = ? WHERE cve_id = ? AND date_removed IS NULL",
                (removed_at, cve_id),
            )


async def amark_kev_removed(cve_id: str, removed_at: str) -> None:
    await run_in_threadpool(mark_kev_removed, cve_id, removed_at)


def upsert_cwe(
    cwe_id: str,
    *,
    name: str,
    description: str | None = None,
    extended_description: str | None = None,
    abstract_type: str | None = None,
    status: str | None = None,
    likelihood: str | None = None,
    mitigations: list[str] | None = None,
    examples: list[str] | None = None,
    parent_cwe: str | None = None,
    child_cwes: list[str] | None = None,
) -> None:
    """Idempotent UPSERT into cwes table. Lists are JSON-encoded."""
    mitigations_json = json.dumps(mitigations) if mitigations else None
    examples_json = json.dumps(examples) if examples else None
    child_cwes_json = json.dumps(child_cwes) if child_cwes else None
    now = datetime.now(UTC).isoformat()
    with get_cve_db() as con:
        con.execute(
            """
            INSERT INTO cwes (
                cwe_id, name, description, extended_description, abstract_type,
                status, likelihood, mitigations, examples, parent_cwe, child_cwes,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cwe_id) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                extended_description = excluded.extended_description,
                abstract_type = excluded.abstract_type,
                status = excluded.status,
                likelihood = excluded.likelihood,
                mitigations = excluded.mitigations,
                examples = excluded.examples,
                parent_cwe = excluded.parent_cwe,
                child_cwes = excluded.child_cwes,
                updated_at = excluded.updated_at
            """,
            (
                cwe_id,
                name,
                description,
                extended_description,
                abstract_type,
                status,
                likelihood,
                mitigations_json,
                examples_json,
                parent_cwe,
                child_cwes_json,
                now,
            ),
        )


def get_cwe(cwe_id: str) -> dict | None:
    """Fetch CWE record. Returns None when not found.

    Lists (mitigations, examples, child_cwes) are JSON-decoded; malformed JSON
    degrades to empty list rather than raising.
    """
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        row = cur.execute(
            """
            SELECT cwe_id, name, description, extended_description, abstract_type,
                   status, likelihood, mitigations, examples, parent_cwe, child_cwes,
                   updated_at
            FROM cwes WHERE cwe_id = ?
            """,
            (cwe_id,),
        ).fetchone()

    if row is None:
        return None

    return {
        "cwe_id": row["cwe_id"],
        "name": row["name"],
        "description": row["description"],
        "extended_description": row["extended_description"],
        "abstract_type": row["abstract_type"],
        "status": row["status"],
        "likelihood": row["likelihood"],
        "mitigations": _decode_json_list(row["mitigations"]),
        "examples": _decode_json_list(row["examples"]),
        "parent_cwe": row["parent_cwe"],
        "child_cwes": _decode_json_list(row["child_cwes"]),
        "updated_at": row["updated_at"],
    }


async def aget_cwe(cwe_id: str) -> dict | None:
    return await run_in_threadpool(get_cwe, cwe_id)


def count_cves_for_cwe(cwe_id: str) -> int:
    """Return number of CVEs whose cwe_id equals the given CWE.

    Uses an exact match on the cves.cwe_id column. CVEs may map to multiple
    CWEs upstream, but our schema stores only the primary; this count is a
    lower bound when the column is sparse.
    """
    with get_cve_db() as con:
        row = con.execute(
            "SELECT COUNT(*) FROM cves WHERE cwe_id = ?",
            (cwe_id,),
        ).fetchone()
    return int(row[0]) if row else 0


async def acount_cves_for_cwe(cwe_id: str) -> int:
    return await run_in_threadpool(count_cves_for_cwe, cwe_id)


def upsert_cve_if_absent(cve_data: dict) -> bool:
    """Insert a new CVE row if absent; fill empty fields on an existing row.

    NVD strong fields always win; empty fields may be backfilled from MITRE/GHSA.
    Scalar fields (description, severity, cvss_vector, cwe_id, published, modified)
    are filled only when NULL; empty-string inputs are ignored (treated as NULL).
    cvss_v3 (REAL) is filled only when NULL. JSON array fields (affected_products,
    refs) are filled when NULL or a valid empty JSON array (tolerant of whitespace).
    Fields owned by dedicated writers (epss_score, epss_percentile, in_kev,
    kev_date_added, summary, synced_at) are never touched on update.

    cve_products is populated from cve_data["affected_products"] when the CVE is
    newly inserted, OR when the existing row had empty products and zero cve_products
    rows exist for it.

    Returns True only when a new row was inserted.
    """
    now = datetime.now(UTC).isoformat()
    cve_id = cve_data["cve_id"]
    products = cve_data.get("affected_products", [])
    products_json = json.dumps(products)
    refs_json = json.dumps(cve_data.get("refs", []))

    with get_cve_db() as con:
        cur = con.execute(
            """
            INSERT OR IGNORE INTO cves
            (cve_id, description, severity, cvss_v3, cvss_vector, cwe_id,
             published, modified, epss_score, epss_percentile,
             in_kev, kev_date_added, affected_products, refs, summary, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cve_id,
                cve_data.get("description"),
                cve_data.get("severity"),
                cve_data.get("cvss_v3"),
                cve_data.get("cvss_vector"),
                cve_data.get("cwe_id"),
                cve_data.get("published"),
                cve_data.get("modified"),
                cve_data.get("epss_score"),
                cve_data.get("epss_percentile"),
                cve_data.get("in_kev", 0),
                cve_data.get("kev_date_added"),
                products_json,
                refs_json,
                cve_data.get("summary"),
                now,
            ),
        )
        inserted = cur.rowcount > 0
        if inserted:
            for p in products:
                vendor = p.get("vendor")
                product = p.get("product")
                if not vendor and not product:
                    continue
                con.execute(
                    "INSERT INTO cve_products (cve_id, vendor, product, version_start, version_end, cpe_part, vulnerable) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        cve_id,
                        vendor,
                        product,
                        p.get("version_start"),
                        p.get("version_end"),
                        p.get("cpe_part"),
                        1 if p.get("vulnerable", True) else 0,
                    ),
                )
        else:
            con.execute(
                """
                UPDATE cves SET
                  description       = COALESCE(description,  NULLIF(?, '')),
                  severity          = COALESCE(severity,     NULLIF(?, '')),
                  cvss_v3           = COALESCE(cvss_v3,      ?),
                  cvss_vector       = COALESCE(cvss_vector,  NULLIF(?, '')),
                  cwe_id            = COALESCE(cwe_id,       NULLIF(?, '')),
                  published         = COALESCE(published,    NULLIF(?, '')),
                  modified          = COALESCE(modified,     NULLIF(?, '')),
                  affected_products = CASE
                    WHEN affected_products IS NULL
                      OR affected_products = '[]'
                      OR (json_valid(affected_products) = 1 AND json_array_length(affected_products) = 0)
                    THEN ? ELSE affected_products END,
                  refs = CASE
                    WHEN refs IS NULL
                      OR refs = '[]'
                      OR (json_valid(refs) = 1 AND json_array_length(refs) = 0)
                    THEN ? ELSE refs END
                WHERE cve_id = ?
                """,
                (
                    cve_data.get("description"),
                    cve_data.get("severity"),
                    cve_data.get("cvss_v3"),
                    cve_data.get("cvss_vector"),
                    cve_data.get("cwe_id"),
                    cve_data.get("published"),
                    cve_data.get("modified"),
                    products_json,
                    refs_json,
                    cve_id,
                ),
            )
            existing_products = con.execute("SELECT COUNT(*) FROM cve_products WHERE cve_id = ?", (cve_id,)).fetchone()[
                0
            ]
            if existing_products == 0 and products:
                for p in products:
                    vendor = p.get("vendor")
                    product = p.get("product")
                    if not vendor and not product:
                        continue
                    con.execute(
                        "INSERT INTO cve_products (cve_id, vendor, product, version_start, version_end, cpe_part, vulnerable) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            cve_id,
                            vendor,
                            product,
                            p.get("version_start"),
                            p.get("version_end"),
                            p.get("cpe_part"),
                            1 if p.get("vulnerable", True) else 0,
                        ),
                    )
        incoming_sev = cve_data.get("severity_sources") or []
        if incoming_sev:
            allowed_sources = {"nvd", "mitre", "ghsa", "osv", "cisa-adp"}
            row = con.execute("SELECT severity_sources FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()
            existing_sev = []
            if row and row[0]:
                try:
                    existing_sev = json.loads(row[0]) or []
                except (json.JSONDecodeError, TypeError):
                    existing_sev = []
            if not isinstance(existing_sev, list):
                existing_sev = []
            by_source = {
                s["source"]: s for s in existing_sev if isinstance(s, dict) and s.get("source") in allowed_sources
            }
            for s in incoming_sev:
                if isinstance(s, dict) and s.get("source") in allowed_sources:
                    by_source[s["source"]] = s
            con.execute(
                "UPDATE cves SET severity_sources = ? WHERE cve_id = ?",
                (json.dumps(list(by_source.values())), cve_id),
            )
        return inserted


def backfill_cve_products(batch_size: int = 1000, start_after: str = "") -> int:
    """Populate cve_products from existing cves.affected_products JSON.
    Idempotent: deletes per-cve_id before insert. Returns total rows inserted.
    start_after: resume from CVE id (exclusive); empty string starts from beginning."""
    total = 0
    last_id = start_after
    with get_cve_db() as con:
        while True:
            rows = con.execute(
                "SELECT cve_id, affected_products FROM cves WHERE cve_id > ? ORDER BY cve_id LIMIT ?",
                (last_id, batch_size),
            ).fetchall()
            if not rows:
                break
            for cve_id, ap_json in rows:
                con.execute("DELETE FROM cve_products WHERE cve_id = ?", (cve_id,))
                if not ap_json:
                    continue
                try:
                    products = json.loads(ap_json)
                except (json.JSONDecodeError, TypeError):
                    continue
                for p in products or []:
                    vendor = p.get("vendor")
                    product = p.get("product")
                    if not vendor and not product:
                        continue
                    con.execute(
                        "INSERT INTO cve_products (cve_id, vendor, product, version_start, version_end, cpe_part, vulnerable) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            cve_id,
                            vendor,
                            product,
                            p.get("version_start"),
                            p.get("version_end"),
                            p.get("cpe_part"),
                            1 if p.get("vulnerable", True) else 0,
                        ),
                    )
                    total += 1
            last_id = rows[-1][0]
    return total


def record_cve_source(cve_id: str, source: str, source_url: str | None = None) -> None:
    """Record that a CVE was seen from a given source. Preserves first_seen_at on
    repeat observations, always bumps last_seen_at."""
    now = datetime.now(UTC).isoformat()
    with get_cve_db() as con:
        con.execute(
            "INSERT INTO cve_sources (cve_id, source, first_seen_at, last_seen_at, source_url) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(cve_id, source) DO UPDATE SET last_seen_at = excluded.last_seen_at",
            (cve_id, source, now, now, source_url),
        )


def get_cve_sources(cve_id: str) -> list[dict]:
    """Return all source observations for a CVE, ordered by first_seen_at ASC."""
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        rows = cur.execute(
            "SELECT source, first_seen_at, last_seen_at, source_url "
            "FROM cve_sources WHERE cve_id = ? ORDER BY first_seen_at ASC",
            (cve_id,),
        ).fetchall()
        return [dict(row) for row in rows]


async def aget_cve_sources(cve_id: str) -> list[dict]:
    return await run_in_threadpool(get_cve_sources, cve_id)


def update_sync_status(source: str, count: int, status: str = "ok", checkpoint: str | None = None) -> None:
    now = datetime.now(UTC).isoformat()
    with get_cve_db() as con:
        con.execute(
            "INSERT OR REPLACE INTO sync_status (source, last_sync, records_count, status, checkpoint) VALUES (?, ?, ?, ?, ?)",
            (source, now, count, status, checkpoint),
        )


def get_sync_status() -> dict:
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        rows = cur.execute("SELECT * FROM sync_status").fetchall()
        return {row["source"]: dict(row) for row in rows}


def get_sync_checkpoint(source: str) -> str | None:
    """Return the checkpoint value for a source, or None."""
    with get_cve_db() as con:
        row = con.execute("SELECT checkpoint FROM sync_status WHERE source = ?", (source,)).fetchone()
        return row[0] if row else None


def get_last_successful_sync(source: str) -> str | None:
    """Return the last_sync timestamp for a source if status was 'ok'."""
    with get_cve_db() as con:
        row = con.execute("SELECT last_sync FROM sync_status WHERE source = ? AND status = 'ok'", (source,)).fetchone()
        return row[0] if row else None


async def aget_last_successful_sync(source: str) -> str | None:
    return await run_in_threadpool(get_last_successful_sync, source)


def get_cves_needing_osv_backfill(limit: int = 500, since: str = "2026-04-15") -> list[str]:
    """Return CVE IDs with incomplete NVD enrichment eligible for OSV backfill.

    Targets CVEs published on/after `since` that have NULL cvss_v3 OR NULL cwe_id.
    Ordered by published DESC to prioritize recent gaps.
    """
    with get_cve_db() as con:
        rows = con.execute(
            """
            SELECT cve_id FROM cves
            WHERE (cvss_v3 IS NULL OR cwe_id IS NULL)
              AND published >= ?
            ORDER BY published DESC
            LIMIT ?
            """,
            (since, limit),
        ).fetchall()
    return [r[0] for r in rows]


def upsert_exploits(batch: list[dict]) -> int:
    """Batch-upsert ExploitDB rows. Returns number of rows written."""
    if not batch:
        return 0
    now = datetime.now(UTC).isoformat()
    with get_cve_db() as con:
        con.executemany(
            """
            INSERT INTO exploits
                (edb_id, cve_id, date_published, author, type, platform, port,
                 verified, description, source_url, date_added, date_updated, tags, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(edb_id, cve_id) DO UPDATE SET
                date_published = excluded.date_published,
                author         = excluded.author,
                type           = excluded.type,
                platform       = excluded.platform,
                port           = excluded.port,
                verified       = excluded.verified,
                description    = excluded.description,
                source_url     = excluded.source_url,
                date_added     = excluded.date_added,
                date_updated   = excluded.date_updated,
                tags           = excluded.tags,
                synced_at      = excluded.synced_at
            """,
            [
                (
                    r["edb_id"],
                    r["cve_id"],
                    r.get("date_published"),
                    r.get("author"),
                    r.get("type"),
                    r.get("platform"),
                    r.get("port"),
                    r.get("verified", 0),
                    r.get("description"),
                    r.get("source_url"),
                    r.get("date_added"),
                    r.get("date_updated"),
                    r.get("tags", ""),
                    now,
                )
                for r in batch
            ],
        )
    return len(batch)


def search_exploits_by_cve(cve_id: str, limit: int = 100) -> tuple[list[dict], bool]:
    """Return (rows, truncated) for a CVE's ExploitDB entries, newest first.

    Fetches limit+1 to detect truncation; returns only `limit` rows and a flag.
    """
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        rows = cur.execute(
            "SELECT * FROM exploits WHERE cve_id = ? "
            "ORDER BY date_published IS NULL, date_published DESC, edb_id DESC LIMIT ?",
            (cve_id, limit + 1),
        ).fetchall()
        truncated = len(rows) > limit
        return [dict(r) for r in rows[:limit]], truncated


async def asearch_exploits_by_cve(cve_id: str, limit: int = 100) -> tuple[list[dict], bool]:
    return await run_in_threadpool(search_exploits_by_cve, cve_id, limit)


# --- ATLAS helpers ---


def upsert_atlas_technique(
    technique_id: str,
    *,
    name: str,
    description: str | None = None,
    tactics: list[str] | None = None,
    maturity: str | None = None,
    attack_reference_id: str | None = None,
    attack_reference_url: str | None = None,
    subtechnique_of: str | None = None,
    created_date: str | None = None,
    modified_date: str | None = None,
) -> None:
    """Idempotent UPSERT into atlas_techniques."""
    tactics_json = json.dumps(tactics) if tactics else None
    now = datetime.now(UTC).isoformat()
    with get_cve_db() as con:
        con.execute(
            """
            INSERT INTO atlas_techniques (
                technique_id, name, description, tactics, maturity,
                attack_reference_id, attack_reference_url, subtechnique_of,
                created_date, modified_date, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(technique_id) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                tactics = excluded.tactics,
                maturity = excluded.maturity,
                attack_reference_id = excluded.attack_reference_id,
                attack_reference_url = excluded.attack_reference_url,
                subtechnique_of = excluded.subtechnique_of,
                created_date = excluded.created_date,
                modified_date = excluded.modified_date,
                updated_at = excluded.updated_at
            """,
            (
                technique_id,
                name,
                description,
                tactics_json,
                maturity,
                attack_reference_id,
                attack_reference_url,
                subtechnique_of,
                created_date,
                modified_date,
                now,
            ),
        )


def upsert_atlas_case_study(
    case_study_id: str,
    *,
    name: str,
    description: str | None = None,
    techniques_used: list[str] | None = None,
) -> None:
    """Idempotent UPSERT into atlas_case_studies."""
    techniques_json = json.dumps(techniques_used) if techniques_used else None
    now = datetime.now(UTC).isoformat()
    with get_cve_db() as con:
        con.execute(
            """
            INSERT INTO atlas_case_studies (case_study_id, name, description, techniques_used, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(case_study_id) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                techniques_used = excluded.techniques_used,
                updated_at = excluded.updated_at
            """,
            (case_study_id, name, description, techniques_json, now),
        )


def _decode_json_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        decoded = json.loads(raw)
        if isinstance(decoded, list):
            return [str(x) for x in decoded if x]
    except (json.JSONDecodeError, TypeError):
        # Corrupt JSON column — treat as empty rather than crashing the read path.
        pass
    return []


def _escape_like(s: str) -> str:
    """Escape LIKE metacharacters (%, _, \\). Pair with `ESCAPE '\\'` clause."""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def get_atlas_technique(technique_id: str) -> dict | None:
    """Fetch ATLAS technique by id (e.g., 'AML.T0000'). Returns None when not found."""
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        row = cur.execute(
            "SELECT * FROM atlas_techniques WHERE technique_id = ?",
            (technique_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "technique_id": row["technique_id"],
        "name": row["name"],
        "description": row["description"],
        "tactics": _decode_json_list(row["tactics"]),
        "maturity": row["maturity"],
        "attack_reference_id": row["attack_reference_id"],
        "attack_reference_url": row["attack_reference_url"],
        "subtechnique_of": row["subtechnique_of"],
        "created_date": row["created_date"],
        "modified_date": row["modified_date"],
        "updated_at": row["updated_at"],
    }


async def aget_atlas_technique(technique_id: str) -> dict | None:
    return await run_in_threadpool(get_atlas_technique, technique_id)


def search_atlas_techniques(
    keyword: str | None = None,
    tactic: str | None = None,
    maturity: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """Search ATLAS techniques. tactics column is JSON; LIKE-match for tactic filter."""
    clauses = []
    params: list = []
    if keyword:
        clauses.append("(LOWER(name) LIKE ? ESCAPE '\\' OR LOWER(description) LIKE ? ESCAPE '\\')")
        kw = f"%{_escape_like(keyword.lower())}%"
        params.extend([kw, kw])
    if tactic:
        clauses.append("tactics LIKE ? ESCAPE '\\'")
        params.append(f'%"{_escape_like(tactic)}"%')
    if maturity:
        clauses.append("maturity = ?")
        params.append(maturity)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(min(max(limit, 1), 200))
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        rows = cur.execute(
            f"SELECT * FROM atlas_techniques{where} ORDER BY technique_id LIMIT ?",
            params,
        ).fetchall()
    out = []
    for row in rows:
        out.append(
            {
                "technique_id": row["technique_id"],
                "name": row["name"],
                "description": row["description"],
                "tactics": _decode_json_list(row["tactics"]),
                "maturity": row["maturity"],
                "attack_reference_id": row["attack_reference_id"],
                "subtechnique_of": row["subtechnique_of"],
            }
        )
    return out


async def asearch_atlas_techniques(**kwargs) -> list[dict]:
    return await run_in_threadpool(search_atlas_techniques, **kwargs)


def get_atlas_case_study(case_study_id: str) -> dict | None:
    """Fetch ATLAS case study by id. Returns None when not found."""
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        row = cur.execute(
            "SELECT * FROM atlas_case_studies WHERE case_study_id = ?",
            (case_study_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "case_study_id": row["case_study_id"],
        "name": row["name"],
        "description": row["description"],
        "techniques_used": _decode_json_list(row["techniques_used"]),
        "updated_at": row["updated_at"],
    }


async def aget_atlas_case_study(case_study_id: str) -> dict | None:
    return await run_in_threadpool(get_atlas_case_study, case_study_id)


def search_atlas_case_studies(
    keyword: str | None = None,
    technique_id: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """Search ATLAS case studies by keyword or by referenced technique."""
    clauses = []
    params: list = []
    if keyword:
        clauses.append("(LOWER(name) LIKE ? ESCAPE '\\' OR LOWER(description) LIKE ? ESCAPE '\\')")
        kw = f"%{_escape_like(keyword.lower())}%"
        params.extend([kw, kw])
    if technique_id:
        clauses.append("techniques_used LIKE ? ESCAPE '\\'")
        params.append(f'%"{_escape_like(technique_id)}"%')
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(min(max(limit, 1), 200))
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        rows = cur.execute(
            f"SELECT * FROM atlas_case_studies{where} ORDER BY case_study_id LIMIT ?",
            params,
        ).fetchall()
    return [
        {
            "case_study_id": r["case_study_id"],
            "name": r["name"],
            "description": r["description"],
            "techniques_used": _decode_json_list(r["techniques_used"]),
        }
        for r in rows
    ]


async def asearch_atlas_case_studies(**kwargs) -> list[dict]:
    return await run_in_threadpool(search_atlas_case_studies, **kwargs)


# --- D3FEND helpers ---


def upsert_d3fend_defense(
    defense_id: str,
    *,
    label: str,
    uri: str,
    parent_label: str | None = None,
    description: str | None = None,
    tactic: str,
    artifact: str | None = None,
) -> None:
    """Idempotent UPSERT into d3fend_defenses."""
    now = datetime.now(UTC).isoformat()
    with get_cve_db() as con:
        con.execute(
            """
            INSERT INTO d3fend_defenses (
                defense_id, label, uri, parent_label, description, tactic, artifact, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(defense_id) DO UPDATE SET
                label = excluded.label,
                uri = excluded.uri,
                parent_label = excluded.parent_label,
                description = excluded.description,
                tactic = excluded.tactic,
                artifact = excluded.artifact,
                updated_at = excluded.updated_at
            """,
            (defense_id, label, uri, parent_label, description, tactic, artifact, now),
        )


def upsert_d3fend_attack_mappings(batch: list[dict]) -> int:
    """Batch-upsert (defense_id, attack_technique_id) join rows.

    Each dict must have: defense_id, attack_technique_id. Optional: attack_label, attack_tactic.
    Returns number of rows written.
    """
    if not batch:
        return 0
    with get_cve_db() as con:
        con.executemany(
            """
            INSERT INTO d3fend_attack_mappings (defense_id, attack_technique_id, attack_label, attack_tactic)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(defense_id, attack_technique_id) DO UPDATE SET
                attack_label = excluded.attack_label,
                attack_tactic = excluded.attack_tactic
            """,
            [
                (
                    r["defense_id"],
                    r["attack_technique_id"],
                    r.get("attack_label"),
                    r.get("attack_tactic"),
                )
                for r in batch
            ],
        )
    return len(batch)


def get_d3fend_defense(defense_id: str) -> dict | None:
    """Fetch D3FEND defense by slug id (e.g., 'TokenBinding'). Returns None when not found.

    Includes attack_techniques list (joined from d3fend_attack_mappings).
    """
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        row = cur.execute(
            "SELECT * FROM d3fend_defenses WHERE defense_id = ?",
            (defense_id,),
        ).fetchone()
        if row is None:
            return None
        attacks = cur.execute(
            "SELECT attack_technique_id FROM d3fend_attack_mappings WHERE defense_id = ? ORDER BY attack_technique_id",
            (defense_id,),
        ).fetchall()
    return {
        "defense_id": row["defense_id"],
        "label": row["label"],
        "uri": row["uri"],
        "parent_label": row["parent_label"],
        "description": row["description"],
        "tactic": row["tactic"],
        "artifact": row["artifact"],
        "attack_techniques": [a["attack_technique_id"] for a in attacks],
        "updated_at": row["updated_at"],
    }


async def aget_d3fend_defense(defense_id: str) -> dict | None:
    return await run_in_threadpool(get_d3fend_defense, defense_id)


def search_d3fend_defenses(
    keyword: str | None = None,
    tactic: str | None = None,
    artifact: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """Search D3FEND defenses by keyword (label/description), tactic, or artifact."""
    clauses = []
    params: list = []
    if keyword:
        clauses.append(
            "(LOWER(label) LIKE ? ESCAPE '\\' OR LOWER(description) LIKE ? ESCAPE '\\' "
            "OR LOWER(parent_label) LIKE ? ESCAPE '\\')"
        )
        kw = f"%{_escape_like(keyword.lower())}%"
        params.extend([kw, kw, kw])
    if tactic:
        clauses.append("tactic = ?")
        params.append(tactic)
    if artifact:
        clauses.append("LOWER(artifact) = ?")
        params.append(artifact.lower())
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(min(max(limit, 1), 200))
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        rows = cur.execute(
            f"SELECT * FROM d3fend_defenses{where} ORDER BY label LIMIT ?",
            params,
        ).fetchall()
    return [
        {
            "defense_id": r["defense_id"],
            "label": r["label"],
            "uri": r["uri"],
            "parent_label": r["parent_label"],
            "tactic": r["tactic"],
            "artifact": r["artifact"],
        }
        for r in rows
    ]


async def asearch_d3fend_defenses(**kwargs) -> list[dict]:
    return await run_in_threadpool(search_d3fend_defenses, **kwargs)


def get_d3fend_defenses_for_attack(attack_technique_id: str) -> list[dict]:
    """Reverse lookup: given an ATT&CK T-code, return all D3FEND defenses that mitigate it."""
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        rows = cur.execute(
            """
            SELECT d.defense_id, d.label, d.uri, d.parent_label, d.tactic, d.artifact, m.attack_label, m.attack_tactic
            FROM d3fend_attack_mappings m
            JOIN d3fend_defenses d ON d.defense_id = m.defense_id
            WHERE m.attack_technique_id = ?
            ORDER BY d.label
            """,
            (attack_technique_id,),
        ).fetchall()
    return [
        {
            "defense_id": r["defense_id"],
            "label": r["label"],
            "uri": r["uri"],
            "parent_label": r["parent_label"],
            "tactic": r["tactic"],
            "artifact": r["artifact"],
            "attack_label": r["attack_label"],
            "attack_tactic": r["attack_tactic"],
        }
        for r in rows
    ]


async def aget_d3fend_defenses_for_attack(attack_technique_id: str) -> list[dict]:
    return await run_in_threadpool(get_d3fend_defenses_for_attack, attack_technique_id)


D3FEND_COVERAGE_MAX_IDS = 500


def get_d3fend_coverage(attack_technique_ids: list[str]) -> dict:
    """Batch coverage breakdown: for given ATT&CK T-codes, count defenses per tactic + list undefended."""
    if not attack_technique_ids:
        return {"coverage_by_tactic": {}, "defended_techniques": [], "undefended_techniques": []}
    if len(attack_technique_ids) > D3FEND_COVERAGE_MAX_IDS:
        attack_technique_ids = attack_technique_ids[:D3FEND_COVERAGE_MAX_IDS]
    placeholders = ",".join("?" * len(attack_technique_ids))
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        tactic_rows = cur.execute(
            f"""
            SELECT d.tactic AS tactic, COUNT(DISTINCT d.defense_id) AS cnt
            FROM d3fend_attack_mappings m
            JOIN d3fend_defenses d ON d.defense_id = m.defense_id
            WHERE m.attack_technique_id IN ({placeholders})
            GROUP BY d.tactic
            """,
            attack_technique_ids,
        ).fetchall()
        defended_rows = cur.execute(
            f"SELECT DISTINCT attack_technique_id FROM d3fend_attack_mappings WHERE attack_technique_id IN ({placeholders})",
            attack_technique_ids,
        ).fetchall()
    defended = {r["attack_technique_id"] for r in defended_rows}
    undefended = [t for t in attack_technique_ids if t not in defended]
    return {
        "coverage_by_tactic": {r["tactic"]: int(r["cnt"]) for r in tactic_rows},
        "defended_techniques": sorted(defended),
        "undefended_techniques": undefended,
    }


async def aget_d3fend_coverage(attack_technique_ids: list[str]) -> dict:
    return await run_in_threadpool(get_d3fend_coverage, attack_technique_ids)


# === v1.23.0 catalog browsing helpers (feeds MCP Resources) ====================
#
# Resources surface ATLAS / D3FEND / CWE catalogs as `*://catalog` URIs so MCP
# clients can browse without a tool call. Listings are slim summaries (id+name
# +key fields) so a 944-row CWE catalog fits in a single resource read.


CATALOG_LISTING_MAX = 1000  # hard cap on rows returned per catalog request


def count_atlas_techniques() -> int:
    """Row count for atlas_techniques. Cheap COUNT(*) — backs catalog `total`."""
    with get_cve_db() as con:
        return int(con.execute("SELECT COUNT(*) FROM atlas_techniques").fetchone()[0])


def count_atlas_case_studies() -> int:
    with get_cve_db() as con:
        return int(con.execute("SELECT COUNT(*) FROM atlas_case_studies").fetchone()[0])


def count_d3fend_defenses() -> int:
    with get_cve_db() as con:
        return int(con.execute("SELECT COUNT(*) FROM d3fend_defenses").fetchone()[0])


def count_cwes() -> int:
    with get_cve_db() as con:
        return int(con.execute("SELECT COUNT(*) FROM cwes").fetchone()[0])


def list_cwes_summary(limit: int = CATALOG_LISTING_MAX) -> list[dict]:
    """Slim CWE listing for catalog browsing: cwe_id + name + abstract_type only.

    Description and the long `extended_description` are excluded — clients
    looking up a single CWE should hit `cwe://weakness/{id}` for the full row.
    """
    limit = max(1, min(int(limit), CATALOG_LISTING_MAX))
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        rows = cur.execute(
            "SELECT cwe_id, name, abstract_type FROM cwes ORDER BY CAST(SUBSTR(cwe_id, 5) AS INTEGER) LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        {
            "cwe_id": r["cwe_id"],
            "name": r["name"],
            "abstract_type": r["abstract_type"],
        }
        for r in rows
    ]
