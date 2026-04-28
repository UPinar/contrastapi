"""Tests for db.py"""

from datetime import UTC, datetime, timedelta

import pytest
from config import CACHE_MAX_BYTES, DOMAIN_CACHE_TTL, IP_CACHE_TTL

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
    results, total = search_cves(severity="CRITICAL")
    assert len(results) >= 1
    assert total >= 1
    assert all(r["severity"] == "CRITICAL" for r in results)


def test_enrich_cves_by_ids_empty_input():
    from db import enrich_cves_by_ids

    assert enrich_cves_by_ids([]) == []


def test_enrich_cves_by_ids_known_and_unknown():
    from db import enrich_cves_by_ids, upsert_cve

    upsert_cve(
        {
            "cve_id": "CVE-2099-0001",
            "severity": "CRITICAL",
            "cvss_v3": 9.8,
            "published": "2099-01-01T00:00:00Z",
        }
    )
    upsert_cve(
        {
            "cve_id": "CVE-2099-0002",
            "severity": "high",  # lower-case in source row
            "cvss_v3": 7.5,
            "published": "2099-01-01T00:00:00Z",
        }
    )

    out = enrich_cves_by_ids(["CVE-2099-0001", "CVE-9999-NOPE", "CVE-2099-0002"])

    # Input order preserved (Shodan ordering is meaningful).
    assert [v["cve_id"] for v in out] == ["CVE-2099-0001", "CVE-9999-NOPE", "CVE-2099-0002"]
    # Known row enrichment.
    assert out[0]["severity"] == "CRITICAL"
    assert out[0]["cvss_v3"] == 9.8
    # Unknown CVE keeps the ID but emits UNKNOWN/None — agent must not infer benign.
    assert out[1]["severity"] == "UNKNOWN"
    assert out[1]["cvss_v3"] is None
    # Severity normalised to upper-case.
    assert out[2]["severity"] == "HIGH"


def test_search_cves_by_product():
    from db import search_cves, upsert_cve

    upsert_cve(
        {
            "cve_id": "CVE-2024-9001",
            "description": "Buffer overflow in nginx",
            "severity": "HIGH",
            "published": "2024-06-01T00:00:00Z",
            "affected_products": [{"vendor": "nginx", "product": "nginx"}],
        }
    )
    results, total = search_cves(product="nginx")
    assert len(results) >= 1
    assert total >= 1


def test_search_cves_by_products_bulk():
    from db import search_cves_by_products_bulk, upsert_cve

    upsert_cve(
        {
            "cve_id": "CVE-2024-BULK1",
            "description": "Bulk test CVE A",
            "severity": "HIGH",
            "published": "2024-01-01T00:00:00Z",
            "affected_products": [{"vendor": "acme", "product": "widget"}],
        }
    )
    upsert_cve(
        {
            "cve_id": "CVE-2024-BULK2",
            "description": "Bulk test CVE B",
            "severity": "MEDIUM",
            "published": "2024-02-01T00:00:00Z",
            "affected_products": [{"vendor": "acme", "product": "gadget"}],
        }
    )

    result = search_cves_by_products_bulk(["widget", "gadget"])
    assert "widget" in result
    assert "gadget" in result
    assert any(c["cve_id"] == "CVE-2024-BULK1" for c in result["widget"])
    assert any(c["cve_id"] == "CVE-2024-BULK2" for c in result["gadget"])

    result = search_cves_by_products_bulk(["WIDGET"])
    assert "widget" in result

    result = search_cves_by_products_bulk(["nonexistent-xyz"])
    assert "nonexistent-xyz" not in result

    assert search_cves_by_products_bulk([]) == {}


def test_normalize_product_helper():
    from db import _normalize_product

    # Alias hit (case-insensitive + strip)
    assert _normalize_product("log4j-core") == "log4j"
    assert _normalize_product("Log4j-Core") == "log4j"
    assert _normalize_product("  log4j-core  ") == "log4j"
    assert _normalize_product("spring-web") == "spring_framework"
    assert _normalize_product("tomcat-embed-core") == "tomcat"

    # Miss → unchanged
    assert _normalize_product("nginx") == "nginx"
    assert _normalize_product("UnknownLib") == "UnknownLib"

    # Empty / falsy
    assert _normalize_product("") == ""


def test_search_cves_with_product_alias():
    from db import search_cves, search_cves_by_products_bulk, upsert_cve

    upsert_cve(
        {
            "cve_id": "CVE-2021-44228",
            "description": "Log4Shell RCE",
            "severity": "CRITICAL",
            "published": "2021-12-10T00:00:00Z",
            "affected_products": [{"vendor": "apache", "product": "log4j"}],
        }
    )
    upsert_cve(
        {
            "cve_id": "CVE-2022-22965",
            "description": "Spring4Shell RCE",
            "severity": "CRITICAL",
            "published": "2022-03-31T00:00:00Z",
            "affected_products": [{"vendor": "pivotal_software", "product": "spring_framework"}],
        }
    )

    # Maven artifactId should resolve to NVD canonical name via alias
    results, total = search_cves(product="log4j-core")
    assert total >= 1
    assert any(r["cve_id"] == "CVE-2021-44228" for r in results)

    results, total = search_cves(product="spring-web")
    assert total >= 1
    assert any(r["cve_id"] == "CVE-2022-22965" for r in results)

    # Bulk variant also normalizes
    bulk = search_cves_by_products_bulk(["log4j-core", "spring-web"])
    assert "log4j" in bulk
    assert "spring_framework" in bulk


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

    log_usage("5.5.5.5", "/v1/cve/CVE-2024-1234", key_hash="stats_key")
    log_usage("5.5.5.5", "/v1/domain/example.com", key_hash="stats_key")
    log_usage("5.5.5.5", "/v1/cve/CVE-2024-5678", key_hash="stats_key")
    stats = get_key_usage_stats("stats_key")
    assert stats["total_requests"] == 3
    assert stats["last_24h"] == 3
    assert stats["last_1h"] == 3
    assert len(stats["top_endpoints"]) == 2
    # Path params stripped: /v1/cve/CVE-2024-1234 → /v1/cve
    assert stats["top_endpoints"][0]["endpoint"] == "/v1/cve"
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


# --- normalize_endpoint tests ---


class TestNormalizeEndpoint:
    def test_strips_domain(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/domain/example.com") == "/v1/domain"

    def test_strips_ip(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/ip/8.8.8.8") == "/v1/ip"

    def test_strips_cve_id(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/cve/CVE-2024-1234") == "/v1/cve"

    def test_strips_email_mx(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/email/mx/user@test.com") == "/v1/email/mx"

    def test_strips_email_disposable(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/email/disposable/test.com") == "/v1/email/disposable"

    def test_strips_scan_headers(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/scan/headers/example.com") == "/v1/scan/headers"

    def test_strips_phone(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/phone/+905551234567") == "/v1/phone"

    def test_strips_dns(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/dns/example.com") == "/v1/dns"

    def test_strips_whois(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/whois/example.com") == "/v1/whois"

    def test_strips_subdomains(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/subdomains/example.com") == "/v1/subdomains"

    def test_strips_certs(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/certs/example.com") == "/v1/certs"

    def test_strips_ssl(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/ssl/example.com") == "/v1/ssl"

    def test_strips_threat(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/threat/example.com") == "/v1/threat"

    def test_strips_tech(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/tech/example.com") == "/v1/tech"

    def test_strips_monitor(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/monitor/example.com") == "/v1/monitor"

    def test_strips_asn(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/asn/AS13335") == "/v1/asn"

    def test_strips_exploit(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/exploit/CVE-2024-1234") == "/v1/exploit"

    def test_keeps_clean_endpoints(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/check/secrets") == "/v1/check/secrets"
        assert normalize_endpoint("/v1/check/injection") == "/v1/check/injection"
        assert normalize_endpoint("/v1/check/headers") == "/v1/check/headers"
        assert normalize_endpoint("/v1/check/dependencies") == "/v1/check/dependencies"
        assert normalize_endpoint("/v1/ioc") == "/v1/ioc"
        assert normalize_endpoint("/v1/hash") == "/v1/hash"
        assert normalize_endpoint("/v1/password") == "/v1/password"
        assert normalize_endpoint("/v1/phishing") == "/v1/phishing"
        assert normalize_endpoint("/v1/usage") == "/v1/usage"
        assert normalize_endpoint("/v1/domains/bulk") == "/v1/domains/bulk"
        assert normalize_endpoint("/v1") == "/v1"

    def test_strips_trailing_slash(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/domain/example.com/") == "/v1/domain"

    def test_domain_vulns_4segment(self):
        from db import normalize_endpoint

        assert normalize_endpoint("/v1/domain/example.com/vulns") == "/v1/domain"


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


# --- Domain cache TTL ---


class TestDomainCacheTTL:
    """Verify domain cache entries expire after DOMAIN_CACHE_TTL (24h)."""

    def _backdate_domain(self, domain: str, seconds_ago: int):
        from db import get_cache_db

        ts = (datetime.now(UTC) - timedelta(seconds=seconds_ago)).isoformat()
        with get_cache_db() as con:
            con.execute("UPDATE domain_cache SET fetched_at = ? WHERE domain = ?", (ts, domain))

    def test_fresh_entry_is_hit(self):
        from db import get_cached_domain, save_cached_domain

        save_cached_domain("fresh.com", {"score": 85})
        assert get_cached_domain("fresh.com") == {"score": 85}

    def test_expired_entry_is_miss(self):
        from db import get_cached_domain, save_cached_domain

        save_cached_domain("old.com", {"score": 50})
        self._backdate_domain("old.com", DOMAIN_CACHE_TTL + 1)
        assert get_cached_domain("old.com") is None

    def test_boundary_just_before_ttl_is_hit(self):
        from db import get_cached_domain, save_cached_domain

        save_cached_domain("boundary.com", {"score": 70})
        self._backdate_domain("boundary.com", DOMAIN_CACHE_TTL - 1)
        assert get_cached_domain("boundary.com") is not None

    def test_boundary_just_after_ttl_is_miss(self):
        from db import get_cached_domain, save_cached_domain

        save_cached_domain("boundary2.com", {"score": 70})
        self._backdate_domain("boundary2.com", DOMAIN_CACHE_TTL + 1)
        assert get_cached_domain("boundary2.com") is None

    def test_overwrite_resets_ttl(self):
        from db import get_cached_domain, save_cached_domain

        save_cached_domain("reset.com", {"v": 1})
        self._backdate_domain("reset.com", DOMAIN_CACHE_TTL + 1)
        assert get_cached_domain("reset.com") is None
        save_cached_domain("reset.com", {"v": 2})
        assert get_cached_domain("reset.com") == {"v": 2}


# --- IP cache TTL ---


class TestIPCacheTTL:
    """Verify IP cache entries expire after IP_CACHE_TTL (4h = 14400s)."""

    def _backdate_ip(self, ip: str, seconds_ago: int):
        from db import get_cache_db

        ts = (datetime.now(UTC) - timedelta(seconds=seconds_ago)).isoformat()
        with get_cache_db() as con:
            con.execute("UPDATE ip_cache SET fetched_at = ? WHERE ip = ?", (ts, ip))

    def test_fresh_ip_is_hit(self):
        from db import get_cached_ip, save_cached_ip

        save_cached_ip("1.2.3.4", {"abuse_score": 10})
        assert get_cached_ip("1.2.3.4") == {"abuse_score": 10}

    def test_ip_miss_when_not_cached(self):
        from db import get_cached_ip

        assert get_cached_ip("9.9.9.9") is None

    def test_expired_ip_is_miss(self):
        from db import get_cached_ip, save_cached_ip

        save_cached_ip("5.5.5.5", {"abuse_score": 80})
        self._backdate_ip("5.5.5.5", IP_CACHE_TTL + 1)
        assert get_cached_ip("5.5.5.5") is None

    def test_boundary_just_before_ip_ttl_is_hit(self):
        from db import get_cached_ip, save_cached_ip

        save_cached_ip("6.6.6.6", {"abuse_score": 20})
        self._backdate_ip("6.6.6.6", IP_CACHE_TTL - 1)
        assert get_cached_ip("6.6.6.6") is not None

    def test_boundary_just_after_ip_ttl_is_miss(self):
        from db import get_cached_ip, save_cached_ip

        save_cached_ip("7.7.7.7", {"abuse_score": 30})
        self._backdate_ip("7.7.7.7", IP_CACHE_TTL + 1)
        assert get_cached_ip("7.7.7.7") is None

    def test_ip_overwrite_resets_ttl(self):
        from db import get_cached_ip, save_cached_ip

        save_cached_ip("8.8.8.8", {"v": 1})
        self._backdate_ip("8.8.8.8", IP_CACHE_TTL + 1)
        assert get_cached_ip("8.8.8.8") is None
        save_cached_ip("8.8.8.8", {"v": 2})
        assert get_cached_ip("8.8.8.8") == {"v": 2}


# --- Maintenance cache purge ---


class TestMaintenanceCachePurge:
    """Verify maintenance() purges expired domain and IP cache entries."""

    def _backdate_all_domains(self, seconds_ago: int):
        from db import get_cache_db

        ts = (datetime.now(UTC) - timedelta(seconds=seconds_ago)).isoformat()
        with get_cache_db() as con:
            con.execute("UPDATE domain_cache SET fetched_at = ?", (ts,))

    def _backdate_all_ips(self, seconds_ago: int):
        from db import get_cache_db

        ts = (datetime.now(UTC) - timedelta(seconds=seconds_ago)).isoformat()
        with get_cache_db() as con:
            con.execute("UPDATE ip_cache SET fetched_at = ?", (ts,))

    def test_purges_expired_domain_cache(self):
        from db import maintenance, save_cached_domain

        save_cached_domain("purge1.com", {"x": 1})
        save_cached_domain("purge2.com", {"x": 2})
        self._backdate_all_domains(DOMAIN_CACHE_TTL + 1)
        result = maintenance()
        assert result["cache_purged"] >= 2

    def test_keeps_fresh_domain_cache(self):
        from db import get_cached_domain, maintenance, save_cached_domain

        save_cached_domain("keep.com", {"keep": True})
        maintenance()
        assert get_cached_domain("keep.com") is not None

    def test_purges_expired_ip_cache(self):
        from db import maintenance, save_cached_ip

        save_cached_ip("10.0.0.1", {"rep": "bad"})
        save_cached_ip("10.0.0.2", {"rep": "ok"})
        self._backdate_all_ips(IP_CACHE_TTL + 1)
        result = maintenance()
        assert result["ip_cache_purged"] >= 2

    def test_keeps_fresh_ip_cache(self):
        from db import get_cached_ip, maintenance, save_cached_ip

        save_cached_ip("10.0.0.3", {"rep": "clean"})
        maintenance()
        assert get_cached_ip("10.0.0.3") is not None

    def test_mixed_expired_and_fresh(self):
        from db import get_cache_db, get_cached_domain, get_cached_ip, maintenance, save_cached_domain, save_cached_ip

        save_cached_domain("expired.com", {"x": 1})
        save_cached_domain("fresh.com", {"x": 2})
        save_cached_ip("10.1.1.1", {"y": 1})
        save_cached_ip("10.1.1.2", {"y": 2})
        expired_domain = (datetime.now(UTC) - timedelta(seconds=DOMAIN_CACHE_TTL + 1)).isoformat()
        expired_ip = (datetime.now(UTC) - timedelta(seconds=IP_CACHE_TTL + 1)).isoformat()
        with get_cache_db() as con:
            con.execute("UPDATE domain_cache SET fetched_at = ? WHERE domain = ?", (expired_domain, "expired.com"))
            con.execute("UPDATE ip_cache SET fetched_at = ? WHERE ip = ?", (expired_ip, "10.1.1.1"))
        result = maintenance()
        assert result["cache_purged"] >= 1
        assert result["ip_cache_purged"] >= 1
        assert get_cached_domain("fresh.com") is not None
        assert get_cached_ip("10.1.1.2") is not None
        assert get_cached_domain("expired.com") is None
        assert get_cached_ip("10.1.1.1") is None


# --- Cache size limit ---


class TestCacheSizeLimit:
    """Verify oversized cache entries are silently dropped."""

    def test_domain_cache_rejects_oversized(self):
        from db import get_cached_domain, save_cached_domain

        huge = {"data": "x" * (CACHE_MAX_BYTES + 1)}
        save_cached_domain("huge.com", huge)
        assert get_cached_domain("huge.com") is None

    def test_domain_cache_accepts_within_limit(self):
        from db import get_cached_domain, save_cached_domain

        normal = {"data": "x" * 1000}
        save_cached_domain("normal.com", normal)
        assert get_cached_domain("normal.com") is not None

    def test_ip_cache_rejects_oversized(self):
        from db import get_cached_ip, save_cached_ip

        huge = {"data": "x" * (CACHE_MAX_BYTES + 1)}
        save_cached_ip("1.1.1.1", huge)
        assert get_cached_ip("1.1.1.1") is None

    def test_ip_cache_accepts_within_limit(self):
        from db import get_cached_ip, save_cached_ip

        normal = {"data": "x" * 1000}
        save_cached_ip("2.2.2.2", normal)
        assert get_cached_ip("2.2.2.2") is not None
