"""Tests for db.py"""

from datetime import UTC, datetime, timedelta

import pytest

# --- init ---


def test_init_all_dbs_creates_tables():
    from db import get_api_db, get_cache_db, get_cve_db

    with get_api_db() as con:
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        assert "api_keys" in tables
        assert "api_usage" in tables

    with get_cve_db() as con:
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        assert "cves" in tables
        assert "cve_products" in tables
        assert "sync_status" in tables

    with get_cache_db() as con:
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        assert "domain_cache" in tables


# --- API key operations ---


def test_save_and_get_api_key():
    from db import get_api_key, save_api_key

    save_api_key("abc123hash", order_id="order_1")
    row = get_api_key("abc123hash")
    assert row is not None
    assert row["key_hash"] == "abc123hash"
    assert row["active"] == 1
    assert row["order_id"] == "order_1"


def test_get_api_key_not_found():
    from db import get_api_key

    assert get_api_key("nonexistent") is None


def test_touch_api_key():
    from db import get_api_key, save_api_key, touch_api_key

    save_api_key("touch_hash")
    row = get_api_key("touch_hash")
    assert row["last_used_at"] is None
    touch_api_key("touch_hash")
    row = get_api_key("touch_hash")
    assert row["last_used_at"] is not None


def test_deactivate_api_key():
    from db import deactivate_api_key, get_api_key, save_api_key

    save_api_key("deact_hash", order_id="order_deact")
    assert deactivate_api_key("order_deact") == 1
    assert get_api_key("deact_hash") is None  # active=0


def test_deactivate_nonexistent_order():
    from db import deactivate_api_key

    assert deactivate_api_key("no_order") == 0


# --- Usage tracking ---


def test_log_usage():
    from db import log_usage

    log_usage("1.2.3.4", "/v1/cve/test")
    log_usage("1.2.3.4", "/v1/cve/test2", key_hash="keyhash1")
    # Should not raise


# --- Domain cache ---


def test_cache_save_and_get():
    from db import get_cached_domain, save_cached_domain

    data = {"dns": {"a": ["1.2.3.4"]}, "whois": {"registrar": "test"}}
    save_cached_domain("example.com", data)
    cached = get_cached_domain("example.com")
    assert cached is not None
    assert cached["dns"]["a"] == ["1.2.3.4"]


def test_cache_miss():
    from db import get_cached_domain

    assert get_cached_domain("nonexistent.com") is None


def test_cache_expired(monkeypatch):
    from db import get_cache_db, get_cached_domain, save_cached_domain

    save_cached_domain("expired.com", {"data": True})
    # Manually set fetched_at to 25 hours ago
    old_time = (datetime.now(UTC) - timedelta(hours=25)).isoformat()
    with get_cache_db() as con:
        con.execute("UPDATE domain_cache SET fetched_at = ? WHERE domain = ?", (old_time, "expired.com"))
    assert get_cached_domain("expired.com") is None


# --- CVE operations ---


def test_upsert_and_get_cve():
    from db import get_cve, upsert_cve

    cve = {
        "cve_id": "CVE-2024-1234",
        "description": "Test vuln",
        "severity": "HIGH",
        "cvss_v3": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-79",
        "published": "2024-01-01T00:00:00Z",
        "modified": "2024-01-02T00:00:00Z",
        "epss_score": 0.5,
        "epss_percentile": 0.85,
        "in_kev": 1,
        "kev_date_added": "2024-01-03",
        "affected_products": [{"vendor": "test", "product": "app"}],
        "refs": ["https://example.com"],
        "summary": "High XSS in test app",
    }
    upsert_cve(cve)
    result = get_cve("CVE-2024-1234")
    assert result is not None
    assert result["severity"] == "HIGH"
    assert result["cvss_v3"] == 8.8
    assert result["in_kev"] == 1
    assert len(result["affected_products"]) == 1
    assert result["refs"] == ["https://example.com"]


def test_get_cve_not_found():
    from db import get_cve

    assert get_cve("CVE-9999-0000") is None


def test_upsert_cve_updates():
    from db import get_cve, upsert_cve

    upsert_cve({"cve_id": "CVE-2024-5555", "description": "v1", "severity": "LOW"})
    upsert_cve({"cve_id": "CVE-2024-5555", "description": "v2", "severity": "HIGH"})
    result = get_cve("CVE-2024-5555")
    assert result["description"] == "v2"
    assert result["severity"] == "HIGH"


def test_search_cves_by_severity():
    from db import search_cves, upsert_cve

    upsert_cve({"cve_id": "CVE-2024-0001", "severity": "CRITICAL", "published": "2024-06-01T00:00:00Z"})
    upsert_cve({"cve_id": "CVE-2024-0002", "severity": "LOW", "published": "2024-06-01T00:00:00Z"})
    results = search_cves(severity="CRITICAL")
    assert len(results) >= 1
    assert all(r["severity"] == "CRITICAL" for r in results)


def test_search_cves_by_product():
    from db import search_cves, upsert_cve

    upsert_cve(
        {
            "cve_id": "CVE-2024-9001",
            "description": "Buffer overflow in nginx",
            "severity": "HIGH",
            "published": "2024-06-01T00:00:00Z",
        }
    )
    results = search_cves(product="nginx")
    assert len(results) >= 1


def test_get_kev_cves():
    from db import get_kev_cves, upsert_cve

    upsert_cve({"cve_id": "CVE-2024-7001", "in_kev": 1, "kev_date_added": "2024-03-01"})
    upsert_cve({"cve_id": "CVE-2024-7002", "in_kev": 0})
    results = get_kev_cves()
    assert len(results) >= 1
    assert all(r["in_kev"] == 1 for r in results)


def test_get_epss():
    from db import get_epss, upsert_cve

    upsert_cve({"cve_id": "CVE-2024-8001", "epss_score": 0.92, "epss_percentile": 0.99})
    result = get_epss("CVE-2024-8001")
    assert result["score"] == 0.92
    assert result["percentile"] == 0.99


def test_get_epss_not_found():
    from db import get_epss

    assert get_epss("CVE-9999-9999") is None


# --- Sync status ---


def test_sync_status():
    from db import get_sync_status, update_sync_status

    update_sync_status("nvd", 250000, "ok")
    update_sync_status("epss", 200000, "ok")
    status = get_sync_status()
    assert "nvd" in status
    assert status["nvd"]["records_count"] == 250000
    assert "epss" in status


def test_sync_status_updates():
    from db import get_sync_status, update_sync_status

    update_sync_status("kev", 100, "ok")
    update_sync_status("kev", 150, "ok")
    status = get_sync_status()
    assert status["kev"]["records_count"] == 150


# --- get_recent_cves ---


def test_get_recent_cves():
    from db import get_recent_cves, upsert_cve

    now = datetime.now(UTC).isoformat()
    old = (datetime.now(UTC) - timedelta(hours=48)).isoformat()
    upsert_cve({"cve_id": "CVE-2024-REC1", "published": now, "severity": "HIGH"})
    upsert_cve({"cve_id": "CVE-2024-REC2", "published": old, "severity": "LOW"})
    results = get_recent_cves(hours=24)
    cve_ids = [r["cve_id"] for r in results]
    assert "CVE-2024-REC1" in cve_ids
    assert "CVE-2024-REC2" not in cve_ids


def test_get_recent_cves_respects_limit():
    from db import get_recent_cves, upsert_cve

    now = datetime.now(UTC).isoformat()
    for i in range(5):
        upsert_cve({"cve_id": f"CVE-2024-LIM{i}", "published": now})
    results = get_recent_cves(hours=24, limit=3)
    assert len(results) <= 3


# --- Maintenance ---


def test_maintenance_runs():
    from db import log_usage, maintenance

    log_usage("1.2.3.4", "/v1/test")
    result = maintenance()
    assert result["status"] == "ok"
    assert "usage_purged" in result
    assert "cache_purged" in result


# --- Usage stats ---


def test_get_key_usage_stats():
    from db import get_key_usage_stats, log_usage

    log_usage("5.5.5.5", "/v1/cve/test", key_hash="stats_key")
    log_usage("5.5.5.5", "/v1/domain/test", key_hash="stats_key")
    log_usage("5.5.5.5", "/v1/cve/test", key_hash="stats_key")
    stats = get_key_usage_stats("stats_key")
    assert stats["total_requests"] == 3
    assert stats["last_24h"] == 3
    assert stats["last_1h"] == 3
    assert len(stats["top_endpoints"]) == 2
    assert stats["top_endpoints"][0]["endpoint"] == "/v1/cve/test"
    assert stats["top_endpoints"][0]["count"] == 2


# --- log_usage assertion tests ---


class TestLogUsageAssertions:
    def test_records_inserted(self):
        from db import get_api_db, log_usage

        log_usage("1.2.3.4", "/v1/cve/test")
        log_usage("1.2.3.4", "/v1/cve/test2", key_hash="keyhash1")
        with get_api_db() as con:
            count = con.execute("SELECT COUNT(*) FROM api_usage").fetchone()[0]
            assert count >= 2


# --- maintenance purge test ---


class TestMaintenancePurge:
    def test_purges_old_usage(self):
        from datetime import datetime, timedelta

        from db import get_api_db, log_usage, maintenance

        log_usage("old.ip", "/v1/test")
        old_time = (datetime.now(UTC) - timedelta(days=91)).isoformat()
        with get_api_db() as con:
            con.execute("UPDATE api_usage SET called_at = ?", (old_time,))
        result = maintenance()
        assert result["usage_purged"] >= 1


# --- duplicate key_hash test ---


class TestDuplicateKeyHash:
    def test_duplicate_raises(self):
        import sqlite3

        from db import save_api_key

        save_api_key("unique_hash_test_1")
        with pytest.raises(sqlite3.IntegrityError):
            save_api_key("unique_hash_test_1")
