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

from config import API_DB_PATH, CACHE_DB_PATH, CACHE_MAX_BYTES, CVE_DB_PATH, DOMAIN_CACHE_TTL, HASH_SECRET, IP_CACHE_TTL

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


# Resolve HMAC key once at import time (config.py guarantees non-empty fallback)
_hmac_key = HASH_SECRET.encode()

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
    con = _get_conn(str(API_DB_PATH))
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise


@contextmanager
def get_cve_db():
    """Thread-safe connection to cve.db"""
    con = _get_conn(str(CVE_DB_PATH))
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise


@contextmanager
def get_cache_db():
    """Thread-safe connection to domain_cache.db"""
    con = _get_conn(str(CACHE_DB_PATH))
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


def save_api_key(key_hash: str, order_id: str | None = None) -> None:
    now = datetime.now(UTC).isoformat()
    with get_api_db() as con:
        con.execute("INSERT INTO api_keys (key_hash, order_id, created_at) VALUES (?, ?, ?)", (key_hash, order_id, now))


def get_api_key(key_hash: str) -> dict | None:
    with get_api_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        row = cur.execute("SELECT * FROM api_keys WHERE key_hash = ? AND active = 1", (key_hash,)).fetchone()
        return dict(row) if row else None


def touch_api_key(key_hash: str) -> None:
    now = datetime.now(UTC).isoformat()
    with get_api_db() as con:
        con.execute("UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?", (now, key_hash))


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
    con = _get_conn(str(API_DB_PATH))
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
    """Run database maintenance: VACUUM, ANALYZE, purge old data."""
    stats = {}

    # Purge usage older than 90 days + normalize legacy endpoint paths
    cutoff = (datetime.now(UTC) - timedelta(days=90)).isoformat()
    with get_api_db() as con:
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

    # Clear unclaimed pending keys older than 24 hours
    stats["pending_keys_cleared"] = cleanup_expired_pending_keys(max_age_hours=24)

    # Purge expired domain cache and IP cache
    with get_cache_db() as con:
        now = datetime.now(UTC)

        cache_cutoff = (now - timedelta(seconds=DOMAIN_CACHE_TTL)).isoformat()
        cur = con.execute("DELETE FROM domain_cache WHERE fetched_at < ?", (cache_cutoff,))
        stats["cache_purged"] = cur.rowcount

        ip_cutoff = (now - timedelta(seconds=IP_CACHE_TTL)).isoformat()
        cur = con.execute("DELETE FROM ip_cache WHERE fetched_at < ?", (ip_cutoff,))
        stats["ip_cache_purged"] = cur.rowcount
        con.execute("ANALYZE")

    # ANALYZE on CVE db
    with get_cve_db() as con:
        con.execute("ANALYZE")

    stats["status"] = "ok"
    return stats


def get_cached_domain(domain: str) -> dict | None:
    """Get cached domain result if not expired."""
    with get_cache_db() as con:
        row = con.execute("SELECT result_json, fetched_at FROM domain_cache WHERE domain = ?", (domain,)).fetchone()
        if row is None:
            return None
        fetched = datetime.fromisoformat(row[1])
        age = (datetime.now(UTC) - fetched).total_seconds()
        if age > DOMAIN_CACHE_TTL:
            return None  # expired — maintenance() handles cleanup
        return json.loads(row[0])


def get_cached_domain_with_age(key: str) -> tuple[dict, int] | None:
    """Get cached domain result + age in seconds. Returns None if missing/expired."""
    with get_cache_db() as con:
        row = con.execute("SELECT result_json, fetched_at FROM domain_cache WHERE domain = ?", (key,)).fetchone()
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
    now = datetime.now(UTC).isoformat()
    result_str = json.dumps(result)
    if len(result_str) > CACHE_MAX_BYTES:
        logger.warning("domain cache entry too large (%d bytes), skipping", len(result_str))
        return
    with get_cache_db() as con:
        con.execute(
            "INSERT OR REPLACE INTO domain_cache (domain, result_json, fetched_at) VALUES (?, ?, ?)",
            (domain, result_str, now),
        )


# --- IP cache ---


def get_cached_ip(ip: str) -> dict | None:
    """Get cached IP reputation result if not expired."""
    with get_cache_db() as con:
        row = con.execute("SELECT result_json, fetched_at FROM ip_cache WHERE ip = ?", (ip,)).fetchone()
        if row is None:
            return None
        fetched = datetime.fromisoformat(row[1])
        age = (datetime.now(UTC) - fetched).total_seconds()
        if age > IP_CACHE_TTL:
            return None  # expired — maintenance() handles cleanup
        return json.loads(row[0])


def get_cached_ip_with_age(ip: str) -> tuple[dict, int] | None:
    """Get cached IP reputation result + age in seconds. Returns None if missing/expired."""
    with get_cache_db() as con:
        row = con.execute("SELECT result_json, fetched_at FROM ip_cache WHERE ip = ?", (ip,)).fetchone()
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
    now = datetime.now(UTC).isoformat()
    result_str = json.dumps(result)
    if len(result_str) > CACHE_MAX_BYTES:
        logger.warning("IP cache entry too large (%d bytes), skipping", len(result_str))
        return
    with get_cache_db() as con:
        con.execute(
            "INSERT OR REPLACE INTO ip_cache (ip, result_json, fetched_at) VALUES (?, ?, ?)", (ip, result_str, now)
        )


# --- CVE operations ---


def upsert_cve(cve_data: dict) -> None:
    now = datetime.now(UTC).isoformat()
    with get_cve_db() as con:
        con.execute(
            """
            INSERT OR REPLACE INTO cves
            (cve_id, description, severity, cvss_v3, cvss_vector, cwe_id,
             published, modified, epss_score, epss_percentile,
             in_kev, kev_date_added, affected_products, refs, summary, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                cve_data["cve_id"],
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
                json.dumps(cve_data.get("affected_products", [])),
                json.dumps(cve_data.get("refs", [])),
                cve_data.get("summary"),
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
                "INSERT INTO cve_products (cve_id, vendor, product, version_start, version_end) VALUES (?, ?, ?, ?, ?)",
                (cve_data["cve_id"], vendor, product, p.get("version_start"), p.get("version_end")),
            )


def _deserialize_cve(row: sqlite3.Row) -> dict:
    """Convert a CVE row to dict with JSON fields parsed."""
    d = dict(row)
    d["affected_products"] = json.loads(d["affected_products"]) if d["affected_products"] else []
    d["refs"] = json.loads(d["refs"]) if d["refs"] else []
    return d


def get_cve(cve_id: str) -> dict | None:
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        row = cur.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()
        return _deserialize_cve(row) if row else None


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
) -> tuple[list[dict], int]:
    conditions = []
    params = []
    if product:
        product = _normalize_product(product)
        conditions.append("cve_id IN (SELECT cve_id FROM cve_products WHERE LOWER(product) = LOWER(?))")
        params.append(product)
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
                    "INSERT INTO cve_products (cve_id, vendor, product, version_start, version_end) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (cve_id, vendor, product, p.get("version_start"), p.get("version_end")),
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
                        "INSERT INTO cve_products (cve_id, vendor, product, version_start, version_end) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (cve_id, vendor, product, p.get("version_start"), p.get("version_end")),
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
                        "INSERT INTO cve_products (cve_id, vendor, product, version_start, version_end) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (cve_id, vendor, product, p.get("version_start"), p.get("version_end")),
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
