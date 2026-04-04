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

from config import API_DB_PATH, CACHE_DB_PATH, CVE_DB_PATH, DOMAIN_CACHE_TTL, HASH_SECRET, IP_CACHE_TTL

logger = logging.getLogger("contrastapi")

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


def log_usage(client_ip: str, endpoint: str, key_hash: str | None = None) -> None:
    now = datetime.now(UTC).isoformat()
    ip_hash = hash_client_ip(client_ip)
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


# --- Domain cache ---


def maintenance() -> dict:
    """Run database maintenance: VACUUM, ANALYZE, purge old data."""
    stats = {}

    # Purge usage older than 90 days
    cutoff = (datetime.now(UTC) - timedelta(days=90)).isoformat()
    with get_api_db() as con:
        cur = con.execute("DELETE FROM api_usage WHERE called_at < ?", (cutoff,))
        stats["usage_purged"] = cur.rowcount
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


def save_cached_domain(domain: str, result: dict) -> None:
    now = datetime.now(UTC).isoformat()
    result_str = json.dumps(result)
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


def save_cached_ip(ip: str, result: dict) -> None:
    now = datetime.now(UTC).isoformat()
    result_str = json.dumps(result)
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


def search_cves(
    product: str | None = None, severity: str | None = None, days: int | None = None, limit: int = 50
) -> list[dict]:
    conditions = []
    params = []
    if product:
        escaped = product.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        conditions.append("(description LIKE ? ESCAPE '\\' OR affected_products LIKE ? ESCAPE '\\')")
        params.extend([f"%{escaped}%", f"%{escaped}%"])
    if severity:
        conditions.append("severity = ?")
        params.append(severity.upper())
    if days:
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        conditions.append("published >= ?")
        params.append(cutoff)

    where = " AND ".join(conditions) if conditions else "1=1"
    params.append(limit)

    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        rows = cur.execute(f"SELECT * FROM cves WHERE {where} ORDER BY published DESC LIMIT ?", params).fetchall()
        return [_deserialize_cve(row) for row in rows]


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


def get_recent_cves(hours: int = 24, limit: int = 50) -> list[dict]:

    cutoff = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        rows = cur.execute(
            "SELECT * FROM cves WHERE published >= ? ORDER BY published DESC LIMIT ?", (cutoff, limit)
        ).fetchall()
        return [_deserialize_cve(row) for row in rows]


def get_kev_cves(limit: int = 100) -> list[dict]:
    with get_cve_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        rows = cur.execute(
            "SELECT * FROM cves WHERE in_kev = 1 ORDER BY kev_date_added DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_deserialize_cve(row) for row in rows]


def get_epss(cve_id: str) -> dict | None:
    with get_cve_db() as con:
        row = con.execute("SELECT epss_score, epss_percentile FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()
        if row is None:
            return None
        return {"cve_id": cve_id, "score": row[0], "percentile": row[1]}


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
