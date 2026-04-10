"""Tests for SSL certificate, bulk domain report, ASN lookup, and response model filtering."""

from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

MOCK_DNS_RESULT = {"a": ["93.184.216.34"], "ns": ["a.iana-servers.net"]}
MOCK_WHOIS_RESULT = {"registrar": "Test Registrar", "creation_date": "2020-01-01", "raw_length": 500}
MOCK_CT_RESULT = {"total_certificates": 1, "certificates": [{"issuer": "LE", "common_name": "example.com"}]}


# =========== /v1/ssl/{domain} tests ===========


class TestSslCertificate:
    _MOCK_CERT = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Let's Encrypt"),),),
        "notBefore": "Jan  1 00:00:00 2025 GMT",
        "notAfter": "Dec 31 23:59:59 2026 GMT",
        "serialNumber": "0123456789ABCDEF",
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
    }

    def _make_mock_ssock(self, cert=None, version="TLSv1.3", cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)):
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = cert or dict(self._MOCK_CERT)
        mock_ssock.version.return_value = version
        mock_ssock.cipher.return_value = cipher
        mock_ssock.get_verified_chain.side_effect = AttributeError
        mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ssock.__exit__ = MagicMock(return_value=False)
        return mock_ssock

    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes._validate_and_auth")
    def test_ssl_valid_cert(self, mock_validate, mock_cache_get, mock_cache_save):
        mock_validate.return_value = ("example.com", "93.184.216.34", {"tier": "free"})
        mock_ssock = self._make_mock_ssock()
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        with (
            patch("domain.routes.socket.create_connection", return_value=mock_sock),
            patch("domain.routes._ssl.create_default_context") as mock_ctx,
        ):
            mock_ctx.return_value.wrap_socket.return_value = mock_ssock
            r = client.get("/v1/ssl/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "example.com"
        assert data["valid"] is True
        assert data["issuer"] == "Let's Encrypt"
        assert data["subject"] == "example.com"
        assert data["protocol"] == "TLSv1.3"
        assert data["cipher"]["name"] == "TLS_AES_256_GCM_SHA384"
        assert data["cipher"]["bits"] == 256
        assert "example.com" in data["san"]
        assert "www.example.com" in data["san"]
        assert data["grade"] in ("A", "B")
        assert data["serial_number"] == "0123456789ABCDEF"
        assert data["cached"] is False

    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes._validate_and_auth")
    def test_ssl_expired_cert(self, mock_validate, mock_cache_get, mock_cache_save):
        mock_validate.return_value = ("expired.com", "1.2.3.4", {"tier": "free"})
        expired_cert = dict(self._MOCK_CERT)
        expired_cert["notAfter"] = "Jan  1 00:00:00 2020 GMT"
        mock_ssock = self._make_mock_ssock(cert=expired_cert)
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        with (
            patch("domain.routes.socket.create_connection", return_value=mock_sock),
            patch("domain.routes._ssl.create_default_context") as mock_ctx,
        ):
            mock_ctx.return_value.wrap_socket.return_value = mock_ssock
            r = client.get("/v1/ssl/expired.com")
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is False
        assert data["grade"] == "F"
        assert "EXPIRED" in data["summary"]

    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes._validate_and_auth")
    def test_ssl_connection_refused(self, mock_validate, mock_cache_get):
        mock_validate.return_value = ("nossl.com", "1.2.3.4", {"tier": "free"})
        with patch("domain.routes.socket.create_connection", side_effect=ConnectionRefusedError("Connection refused")):
            r = client.get("/v1/ssl/nossl.com")
        assert r.status_code == 504

    @patch("domain.routes._validate_and_auth")
    def test_ssl_cached(self, mock_validate):
        mock_validate.return_value = ("cached.com", "1.2.3.4", {"tier": "free"})
        cached_result = {
            "domain": "cached.com",
            "valid": True,
            "issuer": "DigiCert",
            "subject": "cached.com",
            "grade": "A",
            "summary": "cached.com — A",
        }
        with patch("domain.routes.get_cached_domain", return_value=cached_result):
            r = client.get("/v1/ssl/cached.com")
        assert r.status_code == 200
        data = r.json()
        assert data["cached"] is True
        assert data["grade"] == "A"


# =========== /v1/domains/bulk tests ===========


class TestBulkDomainReport:
    _MOCK_REPORT = {
        "domain": "example.com",
        "dns": {"a": ["93.184.216.34"]},
        "reverse_dns": {},
        "whois": {},
        "ssl": {},
        "subdomains": {},
        "certificates": {},
        "email_security": {},
        "waf": {},
        "threat": {},
        "risk": {"grade": "A", "score": 10},
        "summary": "example.com — healthy",
    }

    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_bulk_valid(self, mock_validate, mock_report, mock_cache_get, mock_cache_save):
        mock_report.return_value = dict(self._MOCK_REPORT)
        r = client.post("/v1/domains/bulk", json={"domains": ["example.com", "test.org"]})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 2
        assert data["successful"] == 2
        assert data["failed"] == 0
        assert len(data["results"]) == 2
        assert all(item["status"] == "ok" for item in data["results"])
        assert "All 2 domains" in data["summary"]

    def test_bulk_empty_list(self):
        r = client.post("/v1/domains/bulk", json={"domains": []})
        assert r.status_code == 422  # pydantic min_length=1

    def test_bulk_over_free_limit(self):
        r = client.post("/v1/domains/bulk", json={"domains": [f"d{i}.com" for i in range(11)]})
        assert r.status_code == 422  # free tier: max 10 domains

    def test_bulk_over_max_limit(self):
        r = client.post("/v1/domains/bulk", json={"domains": [f"d{i}.com" for i in range(51)]})
        assert r.status_code == 422  # pydantic max_length=50

    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.validate_domain")
    def test_bulk_partial_failure(self, mock_validate, mock_report, mock_cache_get, mock_cache_save):
        """One valid domain, one invalid → partial success."""

        def validate_side_effect(domain):
            if domain == "good.com":
                return "1.2.3.4"
            return None  # bad domain

        mock_validate.side_effect = validate_side_effect
        mock_report.return_value = dict(self._MOCK_REPORT)
        r = client.post("/v1/domains/bulk", json={"domains": ["good.com", "!!!invalid"]})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 2
        assert data["successful"] == 1
        assert data["failed"] == 1
        ok_items = [i for i in data["results"] if i["status"] == "ok"]
        err_items = [i for i in data["results"] if i["status"] == "error"]
        assert len(ok_items) == 1
        assert len(err_items) == 1
        assert err_items[0]["error"] is not None

    @patch("domain.routes.ratelimit.consume_bulk", return_value=False)
    @patch("domain.routes.authenticate", return_value={"tier": "free", "key_hash": None, "client_ip": "127.0.0.1"})
    def test_bulk_rate_limit_exceeded(self, mock_auth, mock_consume):
        """Requesting 5 domains with insufficient quota → 429."""
        r = client.post("/v1/domains/bulk", json={"domains": [f"d{i}.com" for i in range(5)]})
        assert r.status_code == 429

    @patch("domain.routes.get_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_bulk_cached(self, mock_validate, mock_cache):
        """Cached domains should be returned without calling full_domain_report."""
        mock_cache.return_value = dict(self._MOCK_REPORT)
        r = client.post("/v1/domains/bulk", json={"domains": ["cached.com"]})
        assert r.status_code == 200
        data = r.json()
        assert data["successful"] == 1
        assert data["results"][0]["report"]["cached"] is True

    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_bulk_deduplicates_domains(self, mock_validate, mock_report, mock_cache_get, mock_cache_save):
        """Duplicate domains should be deduplicated — only unique ones processed."""
        mock_report.return_value = dict(self._MOCK_REPORT)
        r = client.post("/v1/domains/bulk", json={"domains": ["example.com", "example.com", "example.com"]})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 1
        assert len(data["results"]) == 1
        assert data["results"][0]["domain"] == "example.com"

    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch(
        "domain.routes.full_domain_report",
        side_effect=RuntimeError("/opt/contrastapi/app/domain/recon.py line 42: connection pool exhausted"),
    )
    @patch("domain.routes.validate_domain", return_value="1.2.3.4")
    def test_bulk_error_sanitized(self, mock_validate, mock_report, mock_cache_get, mock_cache_save):
        """Internal error details (paths, stack traces) must not leak to client."""
        r = client.post("/v1/domains/bulk", json={"domains": ["fail.com"]})
        assert r.status_code == 200
        data = r.json()
        err_item = data["results"][0]
        assert err_item["status"] == "error"
        assert err_item["error"] == "Domain report failed"
        assert "/opt" not in err_item["error"]
        assert "recon.py" not in err_item["error"]

    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.authenticate", return_value={"tier": "pro", "key_hash": "abc", "client_ip": "127.0.0.1"})
    def test_bulk_pro_allows_up_to_50(self, mock_auth, mock_validate, mock_report, mock_cache_get, mock_cache_save):
        """Pro tier should accept up to 50 domains without 422."""
        mock_report.return_value = dict(self._MOCK_REPORT)
        r = client.post("/v1/domains/bulk", json={"domains": [f"d{i}.com" for i in range(50)]})
        # Should not get 422 (may get 429 due to rate limit, but not validation error)
        assert r.status_code != 422

    @patch("domain.routes.authenticate", return_value={"tier": "pro", "key_hash": "abc", "client_ip": "127.0.0.1"})
    def test_bulk_pro_rejects_over_50(self, mock_auth):
        """Pro tier should reject more than 50 domains."""
        # 51 domains hits pydantic max_length=50 first
        r = client.post("/v1/domains/bulk", json={"domains": [f"d{i}.com" for i in range(51)]})
        assert r.status_code == 422

    @patch("domain.routes.authenticate", return_value={"tier": "free", "key_hash": None, "client_ip": "127.0.0.1"})
    def test_bulk_free_rejects_over_10(self, mock_auth):
        """Free tier should reject more than 10 domains."""
        r = client.post("/v1/domains/bulk", json={"domains": [f"d{i}.com" for i in range(11)]})
        assert r.status_code == 422
        assert "Limit: 10" in r.json().get("detail", r.json().get("error", ""))

    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.authenticate", return_value={"tier": "free", "key_hash": None, "client_ip": "127.0.0.1"})
    def test_bulk_free_allows_exactly_10(self, mock_auth, mock_validate, mock_report, mock_cache_get, mock_cache_save):
        """Free tier should accept exactly 10 domains."""
        mock_report.return_value = dict(self._MOCK_REPORT)
        r = client.post("/v1/domains/bulk", json={"domains": [f"d{i}.com" for i in range(10)]})
        assert r.status_code != 422

    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.authenticate", return_value={"tier": "pro", "key_hash": "abc", "client_ip": "127.0.0.1"})
    def test_bulk_pro_20_domains_success(self, mock_auth, mock_validate, mock_report, mock_cache_get, mock_cache_save):
        """Pro tier can process 20 domains (impossible for free tier)."""
        mock_report.return_value = dict(self._MOCK_REPORT)
        domains = [f"site{i}.com" for i in range(20)]
        r = client.post("/v1/domains/bulk", json={"domains": domains})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 20
        assert data["successful"] == 20

    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.validate_domain", return_value="1.2.3.4")
    def test_bulk_per_domain_timeout(self, mock_validate, mock_report, mock_cache_get, mock_cache_save):
        """Per-domain timeout returns timed_out count."""
        import time

        def slow_report(*args, **kwargs):
            time.sleep(5)
            return dict(self._MOCK_REPORT)

        mock_report.side_effect = slow_report
        with patch("domain.routes.BULK_PER_DOMAIN_TIMEOUT", 0.1):
            r = client.post("/v1/domains/bulk", json={"domains": ["slow.com"]})
        assert r.status_code == 200
        data = r.json()
        assert data["timed_out"] == 1
        assert data["failed"] == 0  # timed_out is separate from failed
        assert data["results"][0]["error"] == "Domain report timed out"

    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.validate_domain", return_value="1.2.3.4")
    def test_bulk_overall_timeout_partial(self, mock_validate, mock_report, mock_cache_get, mock_cache_save):
        """Overall timeout triggers partial results for remaining domains."""
        import time

        call_count = 0

        def slow_report(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                time.sleep(5)  # first domain exceeds overall timeout
            return dict(self._MOCK_REPORT)

        mock_report.side_effect = slow_report
        with patch("domain.routes.BULK_OVERALL_TIMEOUT", 0.1):
            r = client.post("/v1/domains/bulk", json={"domains": ["a.com", "b.com", "c.com"]})
        assert r.status_code == 200
        data = r.json()
        assert data["partial"] is True
        assert data["timed_out"] >= 1
        assert "partial" in data["summary"]

    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.validate_domain", return_value="1.2.3.4")
    def test_bulk_response_has_timeout_fields(self, mock_validate, mock_report, mock_cache_get, mock_cache_save):
        """Successful bulk response includes timed_out=0 and partial=False."""
        mock_report.return_value = dict(self._MOCK_REPORT)
        r = client.post("/v1/domains/bulk", json={"domains": ["ok.com"]})
        assert r.status_code == 200
        data = r.json()
        assert data["timed_out"] == 0
        assert data["partial"] is False

    def test_bulk_semaphore_rejects_when_full(self):
        """When bulk semaphore is exhausted, return 503."""
        from domain.routes import _bulk_semaphore

        # Exhaust both semaphore slots
        _bulk_semaphore.acquire()
        _bulk_semaphore.acquire()
        try:
            r = client.post("/v1/domains/bulk", json={"domains": ["a.com"]})
            assert r.status_code == 503
            body = r.json()
            msg = body.get("detail", body.get("error", ""))
            assert "concurrent" in msg.lower()
        finally:
            _bulk_semaphore.release()
            _bulk_semaphore.release()

    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.validate_domain", return_value="1.2.3.4")
    def test_bulk_semaphore_released_on_error(self, mock_validate, mock_report, mock_cache_get, mock_cache_save):
        """Semaphore is released even if domain processing raises."""
        from domain.routes import _bulk_semaphore

        mock_report.side_effect = RuntimeError("boom")
        # Verify semaphore is available before and after (acquire+release probe)
        assert _bulk_semaphore.acquire(blocking=False) is True
        _bulk_semaphore.release()
        r = client.post("/v1/domains/bulk", json={"domains": ["crash.com"]})
        assert r.status_code == 200  # errors are caught, not raised
        # Semaphore should still be acquirable (was released in finally)
        assert _bulk_semaphore.acquire(blocking=False) is True
        _bulk_semaphore.release()


class TestConsumeBulk:
    """Tests for ratelimit.consume_bulk atomic operation."""

    def setup_method(self):
        import ratelimit

        ratelimit.reset()

    def test_consume_bulk_success(self):
        """Consuming slots within limit succeeds."""
        import ratelimit

        assert ratelimit.consume_bulk("api", "test_key", 5, 10) is True
        assert ratelimit.get_count("api", "test_key") == 5

    def test_consume_bulk_exceeds_limit(self):
        """Consuming more slots than available fails without partial insert."""
        import ratelimit

        # Fill 8 of 10 slots
        for _ in range(8):
            ratelimit.check_limit("api", "test_key", 10)
        # Try to consume 5 more — should fail (8 + 5 > 10)
        assert ratelimit.consume_bulk("api", "test_key", 5, 10) is False
        # Count should remain 8 (no partial insert)
        assert ratelimit.get_count("api", "test_key") == 8

    def test_consume_bulk_exact_fit(self):
        """Consuming exactly the remaining slots succeeds."""
        import ratelimit

        for _ in range(7):
            ratelimit.check_limit("api", "test_key", 10)
        assert ratelimit.consume_bulk("api", "test_key", 3, 10) is True
        assert ratelimit.get_count("api", "test_key") == 10

    def test_consume_bulk_zero(self):
        """Consuming 0 slots always succeeds."""
        import ratelimit

        assert ratelimit.consume_bulk("api", "test_key", 0, 10) is True


# =========== ASN Lookup ===========

MOCK_RIPE_NETWORK_INFO = {"data": {"asns": ["13335"], "prefix": "1.1.1.0/24"}}
MOCK_RIPE_OVERVIEW = {"data": {"holder": "CLOUDFLARENET", "resource": "AS13335"}}
MOCK_RIPE_PREFIXES = {
    "data": {
        "prefixes": [
            {"prefix": "1.1.1.0/24"},
            {"prefix": "104.16.0.0/13"},
            {"prefix": "2606:4700::/32"},
        ]
    }
}


class TestAsnRoute:
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.authenticate", return_value={"tier": "free"})
    def test_asn_with_ip(self, mock_auth, mock_cache_get, mock_cache_save):
        """ASN lookup with direct IP input."""

        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.raise_for_status = MagicMock()
            if "network-info" in url:
                resp.json.return_value = MOCK_RIPE_NETWORK_INFO
            elif "as-overview" in url:
                resp.json.return_value = MOCK_RIPE_OVERVIEW
            elif "announced-prefixes" in url:
                resp.json.return_value = MOCK_RIPE_PREFIXES
            return resp

        with patch("domain.routes._ripe_client.get", side_effect=mock_get) as mock_httpx:
            r = client.get("/v1/asn/1.1.1.1")
            assert r.status_code == 200
            data = r.json()
            assert data["target"] == "1.1.1.1"
            assert data["asn"] == 13335
            assert data["asn_name"] == "CLOUDFLARENET"
            assert data["ipv4_count"] == 2
            assert data["ipv6_count"] == 1
            assert data.get("resolved_ip") is None
            assert "AS13335" in data["summary"]

    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.quick_dns_a", return_value=["1.1.1.1"])
    @patch("domain.routes.clean_domain", return_value="example.com")
    @patch("domain.routes.is_valid_ip", return_value=False)
    @patch("domain.routes.authenticate", return_value={"tier": "free"})
    def test_asn_with_domain(self, mock_auth, mock_is_ip, mock_clean, mock_dns, mock_cache_get, mock_cache_save):
        """ASN lookup with domain input — should resolve to IP first."""

        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.raise_for_status = MagicMock()
            if "network-info" in url:
                resp.json.return_value = MOCK_RIPE_NETWORK_INFO
            elif "as-overview" in url:
                resp.json.return_value = MOCK_RIPE_OVERVIEW
            elif "announced-prefixes" in url:
                resp.json.return_value = MOCK_RIPE_PREFIXES
            return resp

        with patch("domain.routes._ripe_client.get", side_effect=mock_get):
            r = client.get("/v1/asn/example.com")
            assert r.status_code == 200
            data = r.json()
            assert data["target"] == "example.com"
            assert data["resolved_ip"] == "1.1.1.1"
            assert data["asn"] == 13335

    def test_asn_private_ip_rejected(self):
        """Private IP should be rejected with 400."""
        r = client.get("/v1/asn/192.168.1.1")
        assert r.status_code == 400
        assert "Private" in r.json()["error"] or "private" in r.json()["error"].lower()

    @patch("domain.routes.authenticate", return_value={"tier": "free"})
    def test_asn_cached_result(self, mock_auth):
        """Cached ASN result should be returned with cached=True."""
        cached_data = {
            "target": "1.1.1.1",
            "asn": 13335,
            "asn_name": "CLOUDFLARENET",
            "ipv4_prefixes": [{"prefix": "1.1.1.0/24"}],
            "ipv6_prefixes": [],
            "ipv4_count": 1,
            "ipv6_count": 0,
            "summary": "AS13335 (CLOUDFLARENET). 1 IPv4 and 0 IPv6 prefixes",
        }
        with patch("domain.routes.get_cached_domain", return_value=cached_data):
            r = client.get("/v1/asn/1.1.1.1")
            assert r.status_code == 200
            data = r.json()
            assert data["cached"] is True
            assert data["asn"] == 13335


# =========== response_model filtering tests ===========


class TestResponseModelFiltering:
    """Verify response_model_exclude_none and extra='ignore' behavior."""

    # --- dns: cached=False on fresh fetch ---
    @patch("domain.routes._from_cache", return_value=None)
    @patch("domain.routes.dns_lookup", return_value=MOCK_DNS_RESULT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_dns_cached_false_on_fresh(self, mock_validate, mock_dns, mock_cache):
        r = client.get("/v1/dns/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["cached"] is False

    # --- dns: response shape ---
    @patch("domain.routes._from_cache", return_value=None)
    @patch("domain.routes.dns_lookup", return_value=MOCK_DNS_RESULT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_dns_response_shape(self, mock_validate, mock_dns, mock_cache):
        r = client.get("/v1/dns/example.com")
        assert r.status_code == 200
        assert set(r.json().keys()) == {"domain", "records", "summary", "cached"}

    # --- whois: cached=False on fresh fetch ---
    @patch("domain.routes._from_cache", return_value=None)
    @patch("domain.routes.whois_lookup", return_value=MOCK_WHOIS_RESULT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_whois_exclude_none(self, mock_validate, mock_whois, mock_cache):
        r = client.get("/v1/whois/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["cached"] is False

    # --- subdomains: exclude_none ---
    @patch("domain.routes._from_cache", return_value=None)
    @patch(
        "domain.routes.enumerate_subdomains",
        return_value={"subdomains": ["www.example.com"], "count": 1},
    )
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_subdomains_exclude_none(self, mock_validate, mock_subs, mock_cache):
        r = client.get("/v1/subdomains/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["cached"] is False

    # --- subdomains: extra='ignore' drops unknown fields ---
    @patch("domain.routes._from_cache", return_value=None)
    @patch(
        "domain.routes.enumerate_subdomains",
        return_value={"subdomains": ["www.example.com"], "count": 1, "_debug_internal": "secret"},
    )
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_subdomains_extra_ignored(self, mock_validate, mock_subs, mock_cache):
        r = client.get("/v1/subdomains/example.com")
        assert r.status_code == 200
        data = r.json()
        assert "_debug_internal" not in data

    # --- certs: exclude_none ---
    @patch("domain.routes._from_cache", return_value=None)
    @patch("domain.routes.check_ct_logs", return_value=MOCK_CT_RESULT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_certs_exclude_none(self, mock_validate, mock_ct, mock_cache):
        r = client.get("/v1/certs/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["cached"] is False

    # --- certs: extra='ignore' drops unknown fields ---
    @patch("domain.routes._from_cache", return_value=None)
    @patch(
        "domain.routes.check_ct_logs",
        return_value={**MOCK_CT_RESULT, "_raw_response": {"leaked": True}},
    )
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_certs_extra_ignored(self, mock_validate, mock_ct, mock_cache):
        r = client.get("/v1/certs/example.com")
        assert r.status_code == 200
        data = r.json()
        assert "_raw_response" not in data

    # --- response_shape: exact key set validation ---

    @patch("domain.routes._from_cache", return_value=None)
    @patch("domain.routes.whois_lookup", return_value=MOCK_WHOIS_RESULT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_whois_response_shape(self, mock_validate, mock_whois, mock_cache):
        r = client.get("/v1/whois/example.com")
        assert r.status_code == 200
        assert set(r.json().keys()) == {"domain", "whois", "summary", "cached"}

    @patch("domain.routes._from_cache", return_value=None)
    @patch(
        "domain.routes.enumerate_subdomains",
        return_value={"subdomains": ["www.example.com"], "count": 1},
    )
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_subdomains_response_shape(self, mock_validate, mock_subs, mock_cache):
        r = client.get("/v1/subdomains/example.com")
        assert r.status_code == 200
        assert set(r.json().keys()) == {"domain", "subdomains", "count", "summary", "cached"}

    @patch("domain.routes._from_cache", return_value=None)
    @patch("domain.routes.check_ct_logs", return_value=MOCK_CT_RESULT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_certs_response_shape(self, mock_validate, mock_ct, mock_cache):
        r = client.get("/v1/certs/example.com")
        assert r.status_code == 200
        assert set(r.json().keys()) == {"domain", "total_certificates", "certificates", "summary", "cached"}


# =========== /v1/audit/{domain} tests ===========


class TestAuditDomain:
    """Tests for GET /v1/audit/{domain}"""

    _MOCK_REPORT = {
        "domain": "example.com",
        "dns": {"a": ["93.184.216.34"]},
        "ssl": {"valid": True, "grade": "A"},
        "summary": "example.com - healthy",
    }

    _MOCK_LIVE = {"headers": {"server": "nginx/1.18", "x-frame-options": "DENY"}}

    @patch("domain.tech.detect_technologies")
    @patch("domain.recon.fetch_live_headers")
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.clean_domain", return_value="example.com")
    def test_audit_success(self, mock_clean, mock_report, mock_get, mock_save, mock_live, mock_tech):
        mock_report.return_value = dict(self._MOCK_REPORT)
        mock_live.return_value = dict(self._MOCK_LIVE)
        mock_tech.return_value = {
            "technologies": [{"name": "nginx", "category": "Web Server", "source": "header"}],
            "categories": {"Web Server": ["nginx"]},
            "count": 1,
            "summary": "1 technology",
        }
        r = client.get("/v1/audit/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "example.com"
        assert data["report"]["dns"]["a"] == ["93.184.216.34"]
        assert data["technologies"]["count"] == 1
        assert data["live_headers"]["server"] == "nginx/1.18"
        assert "example.com" in data["summary"]

    @patch("domain.routes.clean_domain", return_value=None)
    def test_audit_invalid_domain(self, mock_clean):
        r = client.get("/v1/audit/!!!")
        assert r.status_code == 400

    @patch("domain.tech.detect_technologies")
    @patch("domain.recon.fetch_live_headers", side_effect=RuntimeError("connection refused"))
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.clean_domain", return_value="example.com")
    def test_audit_live_headers_failure(self, mock_clean, mock_report, mock_get, mock_save, mock_live, mock_tech):
        """fetch_live_headers exception must NOT crash audit - returns empty headers/tech."""
        mock_report.return_value = dict(self._MOCK_REPORT)
        mock_tech.return_value = {"technologies": [], "categories": {}, "count": 0, "summary": ""}
        r = client.get("/v1/audit/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["report"]["dns"]["a"] == ["93.184.216.34"]
        assert data["live_headers"] == {}
        assert data["technologies"]["count"] == 0

    @patch("domain.tech.detect_technologies")
    @patch("domain.recon.fetch_live_headers")
    @patch("domain.routes.get_cached_domain")
    @patch("domain.routes.clean_domain", return_value="cached.com")
    def test_audit_uses_cache(self, mock_clean, mock_get, mock_live, mock_tech):
        """Cache hit should NOT call full_domain_report."""
        cached = dict(self._MOCK_REPORT)
        cached["domain"] = "cached.com"
        mock_get.return_value = cached
        mock_live.return_value = {"headers": {}}
        mock_tech.return_value = {"technologies": [], "categories": {}, "count": 0, "summary": ""}
        with patch("domain.routes.full_domain_report") as mock_full:
            r = client.get("/v1/audit/cached.com")
            mock_full.assert_not_called()
        assert r.status_code == 200


# =========== /v1/threat-report/{ip} tests ===========


class TestThreatReport:
    """Tests for GET /v1/threat-report/{ip}"""

    @patch("domain.routes._ripe_client")
    @patch("domain.routes.check_shodan")
    @patch("domain.routes.check_abuseipdb")
    @patch("domain.routes.ip_enrichment")
    def test_threat_report_success(self, mock_enrich, mock_abuse, mock_shodan, mock_ripe):
        mock_enrich.return_value = {
            "ports": [80, 443],
            "hostnames": ["dns.google"],
            "vulns": [],
            "cpes": [],
            "tags": [],
        }
        mock_abuse.return_value = {"status": "ok", "abuse_score": 0, "country": "US"}
        mock_shodan.return_value = {"status": "ok", "org": "Google LLC", "ports": [80, 443], "vulns": []}
        mock_ripe_resp = MagicMock()
        mock_ripe_resp.json.return_value = {"data": {"asns": [15169], "prefix": "8.8.8.0/24"}}
        mock_ripe_resp.raise_for_status = MagicMock()
        mock_ripe.get.return_value = mock_ripe_resp

        with patch("domain.routes.get_cached_domain", return_value=None), patch("domain.routes.save_cached_domain"):
            r = client.get("/v1/threat-report/8.8.8.8")
        assert r.status_code == 200
        data = r.json()
        assert data["ip"] == "8.8.8.8"
        assert data["enrichment"]["ports"] == [80, 443]
        assert data["abuseipdb"]["abuse_score"] == 0
        assert data["shodan"]["org"] == "Google LLC"
        assert data["asn"]["asn"] == 15169
        assert data["threat_level"] == "low"
        assert "AS15169" in data["summary"]

    def test_threat_report_invalid_ip(self):
        r = client.get("/v1/threat-report/not-an-ip")
        assert r.status_code == 400

    def test_threat_report_private_ip(self):
        r = client.get("/v1/threat-report/192.168.1.1")
        assert r.status_code == 400
        body = r.json()
        assert "Private" in (body.get("detail") or body.get("error") or "")

    @patch("domain.routes._ripe_client")
    @patch("domain.routes.check_shodan", side_effect=RuntimeError("upstream down"))
    @patch("domain.routes.check_abuseipdb")
    @patch("domain.routes.ip_enrichment")
    def test_threat_report_partial_failure(self, mock_enrich, mock_abuse, mock_shodan, mock_ripe):
        """Shodan failure should not crash endpoint - returns error dict."""
        mock_enrich.return_value = {"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": []}
        mock_abuse.return_value = {"status": "ok", "abuse_score": 75}
        mock_ripe_resp = MagicMock()
        mock_ripe_resp.json.return_value = {"data": {"asns": [12345], "prefix": "1.2.3.0/24"}}
        mock_ripe_resp.raise_for_status = MagicMock()
        mock_ripe.get.return_value = mock_ripe_resp

        with patch("domain.routes.get_cached_domain", return_value=None), patch("domain.routes.save_cached_domain"):
            r = client.get("/v1/threat-report/1.2.3.4")
        assert r.status_code == 200
        data = r.json()
        assert data["shodan"]["status"] == "error"
        assert data["threat_level"] == "high"

    @patch("domain.routes._ripe_client")
    @patch("domain.routes.check_shodan")
    @patch("domain.routes.check_abuseipdb")
    @patch("domain.routes.ip_enrichment")
    def test_threat_report_asn_failure(self, mock_enrich, mock_abuse, mock_shodan, mock_ripe):
        """RIPE failure should not crash - asn_data has error key."""
        mock_enrich.return_value = {"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": []}
        mock_abuse.return_value = {"status": "ok"}
        mock_shodan.return_value = {"status": "ok"}
        mock_ripe.get.side_effect = RuntimeError("RIPE timeout")

        with patch("domain.routes.get_cached_domain", return_value=None):
            r = client.get("/v1/threat-report/1.2.3.4")
        assert r.status_code == 200
        data = r.json()
        assert data["asn"] == {"error": "lookup_failed"}

    @patch("domain.routes._ripe_client")
    @patch(
        "domain.routes.check_shodan",
        side_effect=RuntimeError("/opt/contrastapi/app/domain/reputation.py line 73: connection refused"),
    )
    @patch("domain.routes.check_abuseipdb")
    @patch("domain.routes.ip_enrichment")
    def test_threat_report_no_exception_leakage(self, mock_enrich, mock_abuse, mock_shodan, mock_ripe):
        """Internal error details (paths, exception messages) must NOT leak in response."""
        mock_enrich.return_value = {"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": []}
        mock_abuse.return_value = {"status": "ok"}
        mock_ripe_resp = MagicMock()
        mock_ripe_resp.json.return_value = {"data": {"asns": [12345], "prefix": "1.2.3.0/24"}}
        mock_ripe_resp.raise_for_status = MagicMock()
        mock_ripe.get.return_value = mock_ripe_resp

        with patch("domain.routes.get_cached_domain", return_value=None), patch("domain.routes.save_cached_domain"):
            r = client.get("/v1/threat-report/1.2.3.4")
        assert r.status_code == 200
        body_text = r.text
        # Production should NOT echo internal paths or full exception messages
        assert "/opt" not in body_text
        assert "reputation.py" not in body_text
        assert "connection refused" not in body_text


# =========== /v1/audit additional edge cases ===========


class TestAuditDomainEdgeCases:
    """Additional edge case tests for audit_domain."""

    _MOCK_REPORT = {
        "domain": "example.com",
        "dns": {"a": ["93.184.216.34"]},
        "summary": "example.com - healthy",
    }

    @patch("domain.tech.detect_technologies")
    @patch("domain.recon.fetch_live_headers")
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.clean_domain", return_value="example.com")
    def test_audit_empty_headers(self, mock_clean, mock_report, mock_get, mock_save, mock_live, mock_tech):
        """When fetch_live_headers returns empty headers, tech detection is skipped."""
        mock_report.return_value = dict(self._MOCK_REPORT)
        mock_live.return_value = {"headers": {}}
        r = client.get("/v1/audit/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["live_headers"] == {}
        assert data["technologies"]["count"] == 0
        # detect_technologies should NOT be called when headers are empty
        mock_tech.assert_not_called()

    @patch("domain.tech.detect_technologies")
    @patch("domain.recon.fetch_live_headers")
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.clean_domain", return_value="example.com")
    def test_audit_malformed_live_headers(self, mock_clean, mock_report, mock_get, mock_save, mock_live, mock_tech):
        """When fetch_live_headers returns a non-dict 'headers' field, audit must not crash."""
        mock_report.return_value = dict(self._MOCK_REPORT)
        # Malformed: headers is a string instead of dict
        mock_live.return_value = {"headers": "not-a-dict"}
        r = client.get("/v1/audit/example.com")
        assert r.status_code == 200
        data = r.json()
        # Type guard should reset to empty dict
        assert data["live_headers"] == {}
        assert data["technologies"]["count"] == 0
