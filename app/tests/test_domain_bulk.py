"""Tests for SSL certificate, bulk domain report, ASN lookup, and response model filtering."""

import asyncio
import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from auth import AuthCtx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

# Routes use Annotated[AuthCtx, Depends(require_auth(...))]; require_auth's
# dep awaits auth.aauthenticate (Faz 4 batch 4e), so patches target
# auth.aauthenticate with new_callable=AsyncMock.
_AUTH_FREE = AuthCtx(
    tier="free",
    key_hash=None,
    client_ip="127.0.0.1",
    ratelimit_limit=100,
    ratelimit_remaining=99,
    ratelimit_reset=0,
    ratelimit_cost=1,
)
_AUTH_PRO = AuthCtx(
    tier="pro",
    key_hash="abc",
    client_ip="127.0.0.1",
    ratelimit_limit=1000,
    ratelimit_remaining=999,
    ratelimit_reset=0,
    ratelimit_cost=1,
)

MOCK_DNS_RESULT = {"a": ["93.184.216.34"], "ns": ["a.iana-servers.net"]}
MOCK_WHOIS_RESULT = {"registrar": "Test Registrar", "creation_date": "2020-01-01", "raw_length": 500}
MOCK_CT_RESULT = {"total_certificates": 1, "certificates": [{"issuer": "LE", "common_name": "example.com"}]}


def _build_test_cert(
    include_aia_url: str | None = None,
    days_until_expiry: int = 365,
) -> tuple[bytes, bytes]:
    """Return (der_bytes, pem_bytes) for a self-signed leaf cert."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Let's Encrypt")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=30))
        .not_valid_after(now + datetime.timedelta(days=days_until_expiry))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com"), x509.DNSName("www.example.com")]),
            critical=False,
        )
    )
    if include_aia_url:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier(include_aia_url),
                    )
                ]
            ),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    return (
        cert.public_bytes(serialization.Encoding.DER),
        cert.public_bytes(serialization.Encoding.PEM),
    )


# Pre-build certs once at module level to avoid repeated key gen in tests
_LEAF_DER, _LEAF_PEM = _build_test_cert()
_LEAF_AIA_DER, _LEAF_AIA_PEM = _build_test_cert(include_aia_url="http://ca.example.com/intermediate.crt")
_INTER_DER, _INTER_PEM = _build_test_cert()  # reuse as a stand-in intermediate
_LEAF_EXPIRED_DER, _LEAF_EXPIRED_PEM = _build_test_cert(days_until_expiry=-30)


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

    def _make_mock_ssock(
        self, cert=None, version="TLSv1.3", cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), leaf_der=None
    ):
        mock_ssock = MagicMock()
        base_cert = cert if cert is not None else dict(self._MOCK_CERT)
        der = leaf_der if leaf_der is not None else _LEAF_DER

        def _getpeercert(binary_form=False):
            return der if binary_form else base_cert

        mock_ssock.getpeercert.side_effect = _getpeercert
        mock_ssock.version.return_value = version
        mock_ssock.cipher.return_value = cipher
        mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ssock.__exit__ = MagicMock(return_value=False)
        return mock_ssock

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes._validate_domain_input")
    def test_ssl_valid_cert(self, mock_validate, mock_cache_get, mock_cache_save):
        mock_validate.return_value = ("example.com", "93.184.216.34")
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
        assert data["cipher"]["protocol"] == "TLSv1.3"
        assert data["cipher"]["bits"] == 256
        assert "example.com" in data["san"]
        assert "www.example.com" in data["san"]
        assert data["grade"] in ("A", "B")
        # serial_number now parsed from real DER; assert it's a non-empty hex string
        assert data["serial_number"] and all(c in "0123456789ABCDEF" for c in data["serial_number"])
        assert data["warnings"] == []
        assert data["validation_errors"] == []
        assert len(data["chain"]) == 1
        assert data["chain"][0]["source"] == "handshake"

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes._validate_domain_input")
    def test_ssl_expired_cert(self, mock_validate, mock_cache_get, mock_cache_save):
        mock_validate.return_value = ("expired.com", "1.2.3.4")
        # Real expired DER triggers our independent expiry check (cert_valid=False, grade F)
        mock_ssock = self._make_mock_ssock(leaf_der=_LEAF_EXPIRED_DER)
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
        assert "expired" in data["validation_errors"]
        assert "INVALID: expired" in data["summary"]

    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes._validate_domain_input")
    def test_ssl_connection_refused(self, mock_validate, mock_cache_get):
        mock_validate.return_value = ("nossl.com", "1.2.3.4")
        with patch("domain.routes.socket.create_connection", side_effect=ConnectionRefusedError("Connection refused")):
            r = client.get("/v1/ssl/nossl.com")
        assert r.status_code == 504

    @patch("domain.routes._validate_domain_input")
    def test_ssl_cached(self, mock_validate):
        mock_validate.return_value = ("cached.com", "1.2.3.4")
        cached_result = {
            "domain": "cached.com",
            "valid": True,
            "issuer": "DigiCert",
            "subject": "cached.com",
            "grade": "A",
            "summary": "cached.com — A",
        }
        with patch("db.get_cached_domain", return_value=cached_result):
            r = client.get("/v1/ssl/cached.com")
        assert r.status_code == 200
        data = r.json()
        assert data["grade"] == "A"

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes._validate_domain_input")
    def test_ssl_chain_no_aia_extension(self, mock_validate, mock_cache_get, mock_cache_save):
        mock_validate.return_value = ("example.com", "93.184.216.34")
        mock_ssock = self._make_mock_ssock(leaf_der=_LEAF_DER)
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
        assert len(data["chain"]) == 1
        assert data["warnings"] == []
        assert "partial" not in data["summary"]

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes._validate_domain_input")
    def test_ssl_chain_with_aia_success(self, mock_validate, mock_cache_get, mock_cache_save):
        mock_validate.return_value = ("example.com", "93.184.216.34")
        mock_ssock = self._make_mock_ssock(leaf_der=_LEAF_AIA_DER)
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = _INTER_DER
        with (
            patch("domain.routes.socket.create_connection", return_value=mock_sock),
            patch("domain.routes._ssl.create_default_context") as mock_ctx,
            patch("domain.routes._ssrf_http") as mock_http,
        ):
            mock_ctx.return_value.wrap_socket.return_value = mock_ssock
            mock_http.get = AsyncMock(return_value=mock_resp)
            r = client.get("/v1/ssl/example.com")
        assert r.status_code == 200
        data = r.json()
        assert len(data["chain"]) == 2
        assert data["chain"][1]["source"] == "aia_fetch"
        assert data["warnings"] == []
        assert "partial" not in data["summary"]

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes._validate_domain_input")
    def test_ssl_chain_aia_timeout(self, mock_validate, mock_cache_get, mock_cache_save):
        mock_validate.return_value = ("example.com", "93.184.216.34")
        mock_ssock = self._make_mock_ssock(leaf_der=_LEAF_AIA_DER)
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        with (
            patch("domain.routes.socket.create_connection", return_value=mock_sock),
            patch("domain.routes._ssl.create_default_context") as mock_ctx,
            patch("domain.routes._ssrf_http") as mock_http,
        ):
            mock_ctx.return_value.wrap_socket.return_value = mock_ssock
            mock_http.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
            r = client.get("/v1/ssl/example.com")
        assert r.status_code == 200
        data = r.json()
        assert len(data["chain"]) == 1
        assert data["chain"][0]["source"] == "handshake"
        assert len(data["warnings"]) == 1
        assert "timeout" in data["warnings"][0].lower()
        assert "partial" in data["summary"]

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes._validate_domain_input")
    def test_ssl_chain_aia_malformed(self, mock_validate, mock_cache_get, mock_cache_save):
        mock_validate.return_value = ("example.com", "93.184.216.34")
        mock_ssock = self._make_mock_ssock(leaf_der=_LEAF_AIA_DER)
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"not a cert at all"
        with (
            patch("domain.routes.socket.create_connection", return_value=mock_sock),
            patch("domain.routes._ssl.create_default_context") as mock_ctx,
            patch("domain.routes._ssrf_http") as mock_http,
        ):
            mock_ctx.return_value.wrap_socket.return_value = mock_ssock
            mock_http.get = AsyncMock(return_value=mock_resp)
            r = client.get("/v1/ssl/example.com")
        assert r.status_code == 200
        data = r.json()
        assert len(data["chain"]) == 1
        assert len(data["warnings"]) == 1
        assert "parse" in data["warnings"][0].lower()
        assert "partial" in data["summary"]


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

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
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

    def test_bulk_over_max_limit(self):
        r = client.post("/v1/domains/bulk", json={"domains": [f"d{i}.com" for i in range(51)]})
        assert r.status_code == 422  # pydantic max_length=50

    def test_asn_get_unresolvable_echo_sanitized(self):
        """Single GET /v1/asn/{target} unresolvable-domain error must sanitize echoed target."""
        with patch("domain.routes.quick_dns_a", return_value=[]):
            # %0d%0a = CRLF, %3C = '<', %E2%80%AE = U+202E
            r = client.get("/v1/asn/evil.com%0d%0aINJ%3Cscript%3E%E2%80%AE")
        assert r.status_code == 422
        detail = r.json()["error"]["message"]
        assert "\r" not in detail
        assert "\n" not in detail
        assert "<" not in detail
        assert "‮" not in detail

    def test_bulk_invalid_domain_echo_sanitized(self):
        """Pre-existing surface fixed alongside v1.27 CRITICAL: invalid domain echoed in
        results[].domain on validation failure must not carry CRLF / bidi / HTML payloads."""
        evil = "ev\r\nil.com<script>‮"
        r = client.post("/v1/domains/bulk", json={"domains": [evil]})
        assert r.status_code == 200
        item = r.json()["results"][0]
        assert item["status"] == "error"
        assert "\r" not in item["domain"]
        assert "\n" not in item["domain"]
        assert "<" not in item["domain"]
        assert "‮" not in item["domain"]

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
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

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.ratelimit.consume_bulk", return_value=False)
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_bulk_rate_limit_race_falls_back_to_one(
        self, mock_auth, mock_consume, mock_validate, mock_report, mock_cache_get, mock_cache_save
    ):
        """v1.27: when aconsume_bulk loses the race, partial-fill processes 1 (require_auth's
        already-paid unit) and surfaces the rest as skipped — no 429 for the batch."""
        mock_report.return_value = dict(self._MOCK_REPORT)
        r = client.post("/v1/domains/bulk", json={"domains": [f"d{i}.com" for i in range(5)]})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 5
        assert data["processed"] == 1
        assert len(data["skipped_due_to_rate_limit"]) == 4

    @patch("db.get_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_bulk_cached(self, mock_validate, mock_cache):
        """Cached domains should be returned without calling full_domain_report."""
        mock_cache.return_value = dict(self._MOCK_REPORT)
        r = client.post("/v1/domains/bulk", json={"domains": ["cached.com"]})
        assert r.status_code == 200
        data = r.json()
        assert data["successful"] == 1

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
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

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch(
        "domain.routes.full_domain_report",
        side_effect=RuntimeError("internal/recon.py line 42: connection pool exhausted"),
        new_callable=AsyncMock,
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

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_PRO)
    def test_bulk_pro_allows_up_to_50(self, mock_auth, mock_validate, mock_report, mock_cache_get, mock_cache_save):
        """Pro tier should accept up to 50 domains without 422."""
        mock_report.return_value = dict(self._MOCK_REPORT)
        r = client.post("/v1/domains/bulk", json={"domains": [f"d{i}.com" for i in range(50)]})
        # Should not get 422 (may get 429 due to rate limit, but not validation error)
        assert r.status_code != 422

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_PRO)
    def test_bulk_pro_rejects_over_50(self, mock_auth):
        """Server-wide cap: more than 50 domains is rejected by Pydantic max_length=50."""
        r = client.post("/v1/domains/bulk", json={"domains": [f"d{i}.com" for i in range(51)]})
        assert r.status_code == 422

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_bulk_free_partial_fill_when_quota_low(
        self, mock_auth, mock_validate, mock_report, mock_cache_get, mock_cache_save
    ):
        """v1.27: free tier with 11 domains — old behaviour was 422; new behaviour is partial-fill."""
        mock_report.return_value = dict(self._MOCK_REPORT)
        # _AUTH_FREE.ratelimit_remaining=99, so 11 domains all fit in budget — returns 200, not 422.
        r = client.post("/v1/domains/bulk", json={"domains": [f"d{i}.com" for i in range(11)]})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 11
        assert data["processed"] == 11
        assert data["skipped_due_to_rate_limit"] == []

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_bulk_free_allows_exactly_10(self, mock_auth, mock_validate, mock_report, mock_cache_get, mock_cache_save):
        """Free tier should accept exactly 10 domains."""
        mock_report.return_value = dict(self._MOCK_REPORT)
        r = client.post("/v1/domains/bulk", json={"domains": [f"d{i}.com" for i in range(10)]})
        assert r.status_code != 422

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_PRO)
    def test_bulk_pro_20_domains_success(self, mock_auth, mock_validate, mock_report, mock_cache_get, mock_cache_save):
        """Pro tier can process 20 domains (impossible for free tier)."""
        mock_report.return_value = dict(self._MOCK_REPORT)
        domains = [f"site{i}.com" for i in range(20)]
        r = client.post("/v1/domains/bulk", json={"domains": domains})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 20
        assert data["successful"] == 20

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="1.2.3.4")
    def test_bulk_per_domain_timeout(self, mock_validate, mock_report, mock_cache_get, mock_cache_save):
        """Per-domain timeout returns timed_out count."""

        async def slow_report(*args, **kwargs):
            await asyncio.sleep(5)
            return dict(self._MOCK_REPORT)

        mock_report.side_effect = slow_report
        with patch("domain.routes.BULK_PER_DOMAIN_TIMEOUT", 0.1):
            r = client.post("/v1/domains/bulk", json={"domains": ["slow.com"]})
        assert r.status_code == 200
        data = r.json()
        assert data["timed_out"] == 1
        assert data["failed"] == 0  # timed_out is separate from failed
        assert data["results"][0]["error"] == "Domain report timed out"

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="1.2.3.4")
    def test_bulk_overall_timeout_partial(self, mock_validate, mock_report, mock_cache_get, mock_cache_save):
        """Overall timeout triggers partial results for remaining domains."""

        async def slow_report(*args, **kwargs):
            await asyncio.sleep(5)  # all domains block past overall timeout
            return dict(self._MOCK_REPORT)

        mock_report.side_effect = slow_report
        with patch("domain.routes.BULK_OVERALL_TIMEOUT", 0.1):
            r = client.post("/v1/domains/bulk", json={"domains": ["a.com", "b.com", "c.com"]})
        assert r.status_code == 200
        data = r.json()
        assert data["partial"] is True
        assert data["timed_out"] >= 1
        assert "partial" in data["summary"]

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
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
            assert "concurrent" in r.json()["error"]["message"].lower()
        finally:
            _bulk_semaphore.release()
            _bulk_semaphore.release()

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
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
    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
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

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=mock_get) as mock_httpx:
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

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.quick_dns_a", return_value=["1.1.1.1"])
    @patch("domain.routes.clean_domain", return_value="example.com")
    @patch("domain.routes.is_valid_ip", return_value=False)
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
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

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/asn/example.com")
            assert r.status_code == 200
            data = r.json()
            assert data["target"] == "example.com"
            assert data["resolved_ip"] == "1.1.1.1"
            assert data["asn"] == 13335
            # Domain input → ip_lookup pivot hint pre-populated with resolved IP.
            assert data.get("next_calls"), "domain input must emit ip_lookup pivot"
            assert any(h["tool"] == "ip_lookup" and h["input"] == "1.1.1.1" for h in data["next_calls"])

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_asn_with_ip_input_emits_no_pivot(self, mock_auth, mock_cache_get, mock_cache_save):
        """IP input → no ip_lookup pivot (agent already has the IP)."""

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

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/asn/1.1.1.1")
            assert r.status_code == 200
            data = r.json()
            # response_model_exclude_none=True drops next_calls when None.
            assert "next_calls" not in data

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_asn_cached_domain_input_still_emits_pivot(self, mock_auth):
        """Cache-hit path must also surface the ip_lookup pivot (regression: Action #11)."""
        cached_data = {
            "target": "1.1.1.1",
            "asn": 13335,
            "asn_name": "CLOUDFLARENET",
            "ipv4_prefixes": ["1.1.1.0/24"],
            "ipv6_prefixes": [],
            "ipv4_count": 1,
            "ipv6_count": 0,
            "summary": "AS13335 (CLOUDFLARENET). 1 IPv4 and 0 IPv6 prefixes",
            "warnings": [],
        }
        with (
            patch("domain.routes.is_valid_ip", return_value=False),
            patch("domain.routes.clean_domain", return_value="example.com"),
            patch("domain.routes.quick_dns_a", return_value=["1.1.1.1"]),
            patch("db.get_cached_domain", return_value=cached_data),
        ):
            r = client.get("/v1/asn/example.com")
            assert r.status_code == 200
            data = r.json()
            assert data["resolved_ip"] == "1.1.1.1"
            assert data.get("next_calls")
            assert any(h["tool"] == "ip_lookup" and h["input"] == "1.1.1.1" for h in data["next_calls"])

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_asn_lookup_overview_upstream_timeout(self, mock_auth, mock_cache_get, mock_cache_save):
        """as-overview timeout degrades gracefully: asn_name empty, prefixes populated, warnings signal failure."""

        def mock_get(url, **kwargs):
            if "as-overview" in url:
                raise httpx.TimeoutException("timeout")
            resp = MagicMock()
            resp.status_code = 200
            resp.raise_for_status = MagicMock()
            if "network-info" in url:
                resp.json.return_value = MOCK_RIPE_NETWORK_INFO
            elif "announced-prefixes" in url:
                resp.json.return_value = MOCK_RIPE_PREFIXES
            return resp

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/asn/1.1.1.1")
            assert r.status_code == 200
            data = r.json()
            assert data["asn"] == 13335
            assert data["asn_name"] == ""
            assert len(data["ipv4_prefixes"]) == 2
            assert any("as-overview" in w.lower() and "timeout" in w.lower() for w in data["warnings"])
            assert "partial" in data["summary"].lower()

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_asn_lookup_prefixes_upstream_5xx(self, mock_auth, mock_cache_get, mock_cache_save):
        """announced-prefixes HTTP 503 degrades gracefully: asn_name populated, prefixes empty, warnings signal failure."""

        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.raise_for_status = MagicMock()
            if "network-info" in url:
                resp.json.return_value = MOCK_RIPE_NETWORK_INFO
            elif "as-overview" in url:
                resp.json.return_value = MOCK_RIPE_OVERVIEW
            elif "announced-prefixes" in url:
                resp.status_code = 503
                resp.raise_for_status.side_effect = httpx.HTTPStatusError(
                    "503 Service Unavailable",
                    request=MagicMock(),
                    response=MagicMock(),
                )
            return resp

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/asn/1.1.1.1")
            assert r.status_code == 200
            data = r.json()
            assert data["asn_name"] == "CLOUDFLARENET"
            assert data["ipv4_prefixes"] == []
            assert data["ipv6_prefixes"] == []
            assert any("announced-prefixes" in w.lower() for w in data["warnings"])

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_asn_lookup_clean_success_no_warnings(self, mock_auth, mock_cache_get, mock_cache_save):
        """All upstreams succeed — warnings is empty, response shape unchanged."""

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

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/asn/1.1.1.1")
            assert r.status_code == 200
            data = r.json()
            assert data["asn"] == 13335
            assert data["asn_name"] == "CLOUDFLARENET"
            assert data["ipv4_count"] == 2
            assert data["ipv6_count"] == 1
            assert data["warnings"] == []
            assert "partial" not in data["summary"].lower()

    def test_asn_private_ip_rejected(self):
        """Private IP should be rejected with 400, and the input IP echoed back."""
        r = client.get("/v1/asn/192.168.1.1")
        assert r.status_code == 400
        msg = r.json()["error"]["message"]
        assert "Private" in msg or "private" in msg.lower()
        assert "192.168.1.1" in msg, f"input echo missing: {msg}"

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_asn_lookup_skips_cache_when_both_metadata_futures_failed(self, mock_auth, mock_cache_get, mock_cache_save):
        """Bug NEW-A: when both as-overview and announced-prefixes fail at write
        time, asn_name='' and prefix lists are empty. Caching that empty
        payload poisons the entry for the full TTL — every later request
        sees AS<num> with no holder name. Skip the write so the next caller
        can re-hit RIPE."""

        def mock_get(url, **kwargs):
            if "network-info" in url:
                resp = MagicMock()
                resp.status_code = 200
                resp.raise_for_status = MagicMock()
                resp.json.return_value = MOCK_RIPE_NETWORK_INFO
                return resp
            # both metadata calls fail
            raise httpx.TimeoutException("timeout")

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/asn/1.1.1.1")
            assert r.status_code == 200
            data = r.json()
            assert data["asn"] == 13335
            assert data["asn_name"] == ""
            assert data["ipv4_prefixes"] == []
            assert data["ipv6_prefixes"] == []
            mock_cache_save.assert_not_called()

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_asn_lookup_caches_when_only_one_metadata_future_failed(self, mock_auth, mock_cache_get, mock_cache_save):
        """Partial success is still cacheable — only the empty-and-empty
        case poisons. as-overview succeeded → asn_name='CLOUDFLARENET',
        prefixes failed → write the holder so the next caller has it."""

        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.raise_for_status = MagicMock()
            if "network-info" in url:
                resp.json.return_value = MOCK_RIPE_NETWORK_INFO
            elif "as-overview" in url:
                resp.json.return_value = MOCK_RIPE_OVERVIEW
            elif "announced-prefixes" in url:
                raise httpx.TimeoutException("timeout")
            return resp

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/asn/1.1.1.1")
            assert r.status_code == 200
            data = r.json()
            assert data["asn_name"] == "CLOUDFLARENET"
            assert data["ipv4_prefixes"] == []
            mock_cache_save.assert_called_once()

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_asn_cached_result(self, mock_auth):
        """Cached ASN result should be returned successfully."""
        cached_data = {
            "target": "1.1.1.1",
            "asn": 13335,
            "asn_name": "CLOUDFLARENET",
            "ipv4_prefixes": ["1.1.1.0/24"],
            "ipv6_prefixes": [],
            "ipv4_count": 1,
            "ipv6_count": 0,
            "summary": "AS13335 (CLOUDFLARENET). 1 IPv4 and 0 IPv6 prefixes",
            "warnings": [],
        }
        with patch("db.get_cached_domain", return_value=cached_data):
            r = client.get("/v1/asn/1.1.1.1")
            assert r.status_code == 200
            data = r.json()
            assert data["asn"] == 13335
            assert data.get("warnings") == []

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_asn_prefixes_truncated_by_default(self, mock_auth):
        """Cache returns 100 prefixes; response truncates to 50 and ipv4_count stays honest."""
        from config import MAX_ASN_PREFIXES_DEFAULT

        big_v4 = [f"10.{i}.0.0/24" for i in range(100)]
        cached_data = {
            "target": "1.1.1.1",
            "asn": 13335,
            "asn_name": "CLOUDFLARENET",
            "ipv4_prefixes": big_v4,
            "ipv6_prefixes": [],
            "ipv4_count": 100,
            "ipv6_count": 0,
            "summary": "AS13335 (CLOUDFLARENET). 100 IPv4 and 0 IPv6 prefixes",
            "warnings": [],
        }
        with patch("db.get_cached_domain", return_value=cached_data):
            r = client.get("/v1/asn/1.1.1.1")
            assert r.status_code == 200
            data = r.json()
            assert len(data["ipv4_prefixes"]) == MAX_ASN_PREFIXES_DEFAULT
            assert data["ipv4_count"] == 100  # honest pre-truncation
            assert data["ipv4_prefixes"][0] == "10.0.0.0/24"

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_asn_include_full_prefixes_returns_full(self, mock_auth):
        """include_full_prefixes=true returns the full cached list, ipv4_count unchanged."""
        big_v4 = [f"10.{i}.0.0/24" for i in range(100)]
        cached_data = {
            "target": "1.1.1.1",
            "asn": 13335,
            "asn_name": "CLOUDFLARENET",
            "ipv4_prefixes": big_v4,
            "ipv6_prefixes": [],
            "ipv4_count": 100,
            "ipv6_count": 0,
            "summary": "AS13335 (CLOUDFLARENET). 100 IPv4 and 0 IPv6 prefixes",
            "warnings": [],
        }
        with patch("db.get_cached_domain", return_value=cached_data):
            r = client.get("/v1/asn/1.1.1.1?include_full_prefixes=true")
            assert r.status_code == 200
            data = r.json()
            assert len(data["ipv4_prefixes"]) == 100
            assert data["ipv4_count"] == 100

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_asn_short_list_not_truncated(self, mock_auth):
        """5 prefixes < default cap: response equals cache."""
        small = [f"1.1.{i}.0/24" for i in range(5)]
        cached_data = {
            "target": "1.1.1.1",
            "asn": 13335,
            "asn_name": "CLOUDFLARENET",
            "ipv4_prefixes": small,
            "ipv6_prefixes": [],
            "ipv4_count": 5,
            "ipv6_count": 0,
            "summary": "AS13335 (CLOUDFLARENET). 5 IPv4 and 0 IPv6 prefixes",
            "warnings": [],
        }
        with patch("db.get_cached_domain", return_value=cached_data):
            r = client.get("/v1/asn/1.1.1.1")
            assert r.status_code == 200
            assert len(r.json()["ipv4_prefixes"]) == 5

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_asn_truncation_does_not_mutate_cache(self, mock_auth):
        """Two consecutive calls (default + include_full) share one cache entry — no mutation."""
        big_v4 = [f"10.{i}.0.0/24" for i in range(100)]
        cached_data = {
            "target": "1.1.1.1",
            "asn": 13335,
            "asn_name": "CLOUDFLARENET",
            "ipv4_prefixes": big_v4,
            "ipv6_prefixes": [],
            "ipv4_count": 100,
            "ipv6_count": 0,
            "summary": "AS13335 (CLOUDFLARENET). 100 IPv4 and 0 IPv6 prefixes",
            "warnings": [],
        }
        with patch("db.get_cached_domain", return_value=cached_data):
            r1 = client.get("/v1/asn/1.1.1.1")
            r2 = client.get("/v1/asn/1.1.1.1?include_full_prefixes=true")
            assert len(r1.json()["ipv4_prefixes"]) == 50
            assert len(r2.json()["ipv4_prefixes"]) == 100
            # Cache itself untouched
            assert len(cached_data["ipv4_prefixes"]) == 100

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_asn_lookup_verdict_complete_on_clean_success(self, mock_auth, mock_cache_get, mock_cache_save):
        """Bug I2: asn_lookup now emits a verdict block. On clean success
        every RIPE Stat sub-endpoint is in sources_queried and none in
        sources_unavailable; completeness='complete'."""

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

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/asn/1.1.1.1")
            assert r.status_code == 200
            v = r.json()["verdict"]
            assert v["deterministic"] is True
            assert "ripe_stat:network-info" in v["sources_queried"]
            assert "ripe_stat:as-overview" in v["sources_queried"]
            assert "ripe_stat:announced-prefixes" in v["sources_queried"]
            assert v["sources_unavailable"] == []
            assert v["completeness"] == "complete"
            assert v["data_age_seconds"] == 0  # fresh fetch

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_asn_lookup_verdict_partial_on_overview_timeout(self, mock_auth, mock_cache_get, mock_cache_save):
        """as-overview fails → ripe_stat:as-overview in sources_unavailable,
        completeness='partial'. The other sub-endpoints stay in queried."""

        def mock_get(url, **kwargs):
            if "as-overview" in url:
                raise httpx.TimeoutException("timeout")
            resp = MagicMock()
            resp.status_code = 200
            resp.raise_for_status = MagicMock()
            if "network-info" in url:
                resp.json.return_value = MOCK_RIPE_NETWORK_INFO
            elif "announced-prefixes" in url:
                resp.json.return_value = MOCK_RIPE_PREFIXES
            return resp

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/asn/1.1.1.1")
            assert r.status_code == 200
            v = r.json()["verdict"]
            assert "ripe_stat:as-overview" in v["sources_unavailable"]
            assert "ripe_stat:announced-prefixes" not in v["sources_unavailable"]
            assert v["completeness"] == "partial"

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_asn_lookup_does_not_persist_pydantic_verdict_to_cache(self, mock_auth, mock_cache_get, mock_cache_save):
        """The verdict is a Pydantic model — calling json.dumps on the
        cache payload would TypeError if we ever stored it. Verify the
        write payload is plain JSON and contains no 'verdict' key."""

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

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/asn/1.1.1.1")
            assert r.status_code == 200
            mock_cache_save.assert_called_once()
            _, written_payload = mock_cache_save.call_args[0]
            assert "verdict" not in written_payload
            # And the response itself still carries the verdict.
            assert "verdict" in r.json()

    def test_asn_verdict_substring_injection_does_not_forge_unavailable(self):
        """CRITICAL fix: warning strings are matched by prefix anchor
        (`startswith('as-overview:')`), not naive substring `in`. A
        warning whose `:reason` half happens to mention 'as-overview'
        cannot forge a sources_unavailable entry."""
        from domain.routes import _asn_verdict

        # Substring of upstream tag inside the reason — must NOT trigger
        # the unavailable mapping.
        v = _asn_verdict(["custom: SomeError mentioning as-overview internals"], age_seconds=0)
        assert "ripe_stat:as-overview" not in v.sources_unavailable
        # Real upstream prefix DOES trigger.
        v2 = _asn_verdict(["as-overview: timeout"], age_seconds=0)
        assert "ripe_stat:as-overview" in v2.sources_unavailable

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_asn_lookup_verdict_rebuilt_from_cached_warnings(self, mock_auth):
        """Cache-hit path rebuilds the verdict from cached warnings — older
        entries written before I2 do not carry one. data_age_seconds=None
        because the asn cache does not track per-entry age."""
        cached_data = {
            "target": "1.1.1.1",
            "asn": 13335,
            "asn_name": "CLOUDFLARENET",
            "ipv4_prefixes": ["1.1.1.0/24"],
            "ipv6_prefixes": [],
            "ipv4_count": 1,
            "ipv6_count": 0,
            "summary": "AS13335",
            "warnings": ["announced-prefixes: timeout"],
        }
        with patch("db.get_cached_domain", return_value=cached_data):
            r = client.get("/v1/asn/1.1.1.1")
            assert r.status_code == 200
            v = r.json()["verdict"]
            assert "ripe_stat:announced-prefixes" in v["sources_unavailable"]
            assert v["completeness"] == "partial"
            # data_age_seconds=None is dropped by response_model_exclude_none
            assert "data_age_seconds" not in v

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_asn_lookup_coerces_legacy_wrapper_cache_entries(self, mock_auth):
        """Bug I1 cache backward-compat: pre-1.15.0 entries hold
        [{'prefix': str}] wrappers. The cache-hit path must coerce them
        back to flat strings before the response_model rejects them with a
        500. Without this every cached AS lookup would 500 for the full TTL
        post-deploy."""
        legacy_cache = {
            "target": "1.1.1.1",
            "asn": 13335,
            "asn_name": "CLOUDFLARENET",
            "ipv4_prefixes": [{"prefix": "1.1.1.0/24"}, {"prefix": "1.0.0.0/24"}],
            "ipv6_prefixes": [{"prefix": "2606:4700::/32"}],
            "ipv4_count": 2,
            "ipv6_count": 1,
            "summary": "AS13335",
            "warnings": [],
        }
        with patch("db.get_cached_domain", return_value=legacy_cache):
            r = client.get("/v1/asn/1.1.1.1")
            assert r.status_code == 200
            data = r.json()
            assert data["ipv4_prefixes"] == ["1.1.1.0/24", "1.0.0.0/24"]
            assert data["ipv6_prefixes"] == ["2606:4700::/32"]
            assert all(isinstance(p, str) for p in data["ipv4_prefixes"])

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_asn_prefix_format_is_flat_string_list(self, mock_auth):
        """Bug I1: prefixes are now plain CIDR strings, not {'prefix': str} wrappers.
        Halves the byte size on AS-rich responses (CF AS13335 ~2500 prefixes)."""
        cached_data = {
            "target": "1.1.1.1",
            "asn": 13335,
            "asn_name": "CLOUDFLARENET",
            "ipv4_prefixes": ["1.1.1.0/24", "1.0.0.0/24"],
            "ipv6_prefixes": ["2606:4700::/32"],
            "ipv4_count": 2,
            "ipv6_count": 1,
            "summary": "AS13335",
            "warnings": [],
        }
        with patch("db.get_cached_domain", return_value=cached_data):
            r = client.get("/v1/asn/1.1.1.1")
            assert r.status_code == 200
            data = r.json()
            assert data["ipv4_prefixes"] == ["1.1.1.0/24", "1.0.0.0/24"]
            assert data["ipv6_prefixes"] == ["2606:4700::/32"]
            # Each entry is a plain string, not a dict
            assert all(isinstance(p, str) for p in data["ipv4_prefixes"])


# =========== response_model filtering tests ===========


class TestResponseModelFiltering:
    """Verify response_model_exclude_none and extra='ignore' behavior."""

    # --- dns: fresh fetch (not from cache) ---
    @patch("domain.routes._from_cache", return_value=None)
    @patch("domain.routes.dns_lookup", return_value=MOCK_DNS_RESULT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_dns_fresh_fetch(self, mock_validate, mock_dns, mock_cache):
        r = client.get("/v1/dns/example.com")
        assert r.status_code == 200
        data = r.json()

    # --- dns: response shape ---
    @patch("domain.routes._from_cache", return_value=None)
    @patch("domain.routes.dns_lookup", return_value=MOCK_DNS_RESULT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_dns_response_shape(self, mock_validate, mock_dns, mock_cache):
        r = client.get("/v1/dns/example.com")
        assert r.status_code == 200
        assert set(r.json().keys()) == {"domain", "records", "summary", "next_calls"}

    # --- whois: fresh fetch (not from cache) ---
    @patch("domain.routes._from_cache", return_value=None)
    @patch("domain.routes.whois_lookup", return_value=MOCK_WHOIS_RESULT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_whois_exclude_none(self, mock_validate, mock_whois, mock_cache):
        r = client.get("/v1/whois/example.com")
        assert r.status_code == 200
        data = r.json()

    # --- subdomains: exclude_none ---
    @patch("domain.routes._from_cache", return_value=None)
    @patch(
        "domain.routes.enumerate_subdomains",
        return_value={"subdomains": ["www.example.com"], "count": 1},
        new_callable=AsyncMock,
    )
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_subdomains_exclude_none(self, mock_validate, mock_subs, mock_cache):
        r = client.get("/v1/subdomains/example.com")
        assert r.status_code == 200
        data = r.json()

    # --- subdomains: extra='ignore' drops unknown fields ---
    @patch("domain.routes._from_cache", return_value=None)
    @patch(
        "domain.routes.enumerate_subdomains",
        return_value={"subdomains": ["www.example.com"], "count": 1, "_debug_internal": "secret"},
        new_callable=AsyncMock,
    )
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_subdomains_extra_ignored(self, mock_validate, mock_subs, mock_cache):
        r = client.get("/v1/subdomains/example.com")
        assert r.status_code == 200
        data = r.json()
        assert "_debug_internal" not in data

    # --- certs: exclude_none ---
    @patch("domain.routes._from_cache", return_value=None)
    @patch("domain.routes.check_ct_logs", return_value=MOCK_CT_RESULT, new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_certs_exclude_none(self, mock_validate, mock_ct, mock_cache):
        r = client.get("/v1/certs/example.com")
        assert r.status_code == 200
        data = r.json()

    # --- certs: extra='ignore' drops unknown fields ---
    @patch("domain.routes._from_cache", return_value=None)
    @patch(
        "domain.routes.check_ct_logs",
        return_value={**MOCK_CT_RESULT, "_raw_response": {"leaked": True}},
        new_callable=AsyncMock,
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
        assert set(r.json().keys()) == {"domain", "whois", "summary", "next_calls"}

    @patch("domain.routes._from_cache", return_value=None)
    @patch(
        "domain.routes.enumerate_subdomains",
        return_value={"subdomains": ["www.example.com"], "count": 1},
        new_callable=AsyncMock,
    )
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_subdomains_response_shape(self, mock_validate, mock_subs, mock_cache):
        r = client.get("/v1/subdomains/example.com")
        assert r.status_code == 200
        assert set(r.json().keys()) == {
            "domain",
            "subdomains",
            "count",
            "summary",
            "sources",
            "warnings",
            "found_via_wordlist",
            "found_via_crtsh",
            "crtsh_status",
            "next_calls",
        }

    @patch("domain.routes._from_cache", return_value=None)
    @patch("domain.routes.check_ct_logs", return_value=MOCK_CT_RESULT, new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_certs_response_shape(self, mock_validate, mock_ct, mock_cache):
        r = client.get("/v1/certs/example.com")
        assert r.status_code == 200
        assert set(r.json().keys()) == {"domain", "total_certificates", "certificates", "summary"}


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
    @patch("domain.recon.fetch_live_headers", new_callable=AsyncMock)
    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
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
    @patch("domain.recon.fetch_live_headers", new_callable=AsyncMock, side_effect=RuntimeError("connection refused"))
    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
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
    @patch("domain.recon.fetch_live_headers", new_callable=AsyncMock)
    @patch("db.get_cached_domain")
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

    @patch("domain.tech.detect_technologies")
    @patch("domain.recon.fetch_live_headers", new_callable=AsyncMock)
    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
    @patch("domain.routes.clean_domain", return_value="example.com")
    def test_audit_next_calls_subdomain_and_ssl(
        self, mock_clean, mock_report, mock_get, mock_save, mock_live, mock_tech
    ):
        """Cascade (v1.30.2 Batch 4): audit emits subdomain_enum + ssl_check + domain_report + scan_headers (skips tech_fingerprint — already inline)."""
        mock_report.return_value = dict(self._MOCK_REPORT)
        mock_live.return_value = dict(self._MOCK_LIVE)
        mock_tech.return_value = {"technologies": [], "categories": {}, "count": 0, "summary": ""}
        r = client.get("/v1/audit/example.com")
        assert r.status_code == 200
        next_calls = r.json().get("next_calls")
        assert next_calls is not None
        tools = [hint["tool"] for hint in next_calls]
        assert tools == ["subdomain_enum", "ssl_check", "domain_report", "scan_headers"]
        assert "tech_fingerprint" not in tools  # already inline as `technologies`


# =========== /v1/threat-report/{ip} tests ===========


class TestThreatReport:
    """Tests for GET /v1/threat-report/{ip}"""

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_PRO)
    @patch("domain.routes._ripe_client", new_callable=AsyncMock)
    @patch("domain.routes.check_shodan", new_callable=AsyncMock)
    @patch("domain.routes.check_abuseipdb", new_callable=AsyncMock)
    @patch("domain.routes.ip_enrichment", new_callable=AsyncMock)
    @patch(
        "domain.routes._fetch_asn_country",
        new_callable=AsyncMock,
        return_value={"asn": 15169, "asn_name": "GOOGLE", "country": "US", "failed": False},
    )
    @patch("domain.routes.check_firehol", return_value={"status": "ok", "listed": False, "lists_matched": []})
    @patch("domain.routes.check_cloud_provider", return_value="Google")
    @patch("domain.routes.check_tor_exit", return_value=False)
    @patch("domain.routes.tor_cache_status", return_value="ok")
    def test_threat_report_success(
        self,
        mock_tor_status,
        mock_tor,
        mock_cloud,
        mock_firehol,
        mock_country,
        mock_enrich,
        mock_abuse,
        mock_shodan,
        mock_ripe,
        mock_auth,
    ):
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
        mock_ripe.get = AsyncMock(return_value=mock_ripe_resp)

        with patch("db.get_cached_domain", return_value=None), patch("db.save_cached_domain"):
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
        # Bug I3 — passive intel parity with ip_lookup
        assert data["asn_name"] == "GOOGLE"
        assert data["country"] == "US"
        assert data["cloud_provider"] == "Google"
        assert data["tor_exit"] is False
        assert data["firehol"]["status"] == "ok"
        assert "verdict" in data
        assert "ripe_stat" in data["verdict"]["sources_queried"]

    def test_threat_report_invalid_ip(self):
        r = client.get("/v1/threat-report/not-an-ip")
        assert r.status_code == 400

    def test_threat_report_private_ip(self):
        r = client.get("/v1/threat-report/192.168.1.1")
        assert r.status_code == 400
        msg = r.json()["error"]["message"]
        assert "Private" in msg
        assert "192.168.1.1" in msg, f"input echo missing: {msg}"

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_PRO)
    @patch("domain.routes._ripe_client", new_callable=AsyncMock)
    @patch("domain.routes.check_shodan", side_effect=RuntimeError("upstream down"), new_callable=AsyncMock)
    @patch("domain.routes.check_abuseipdb", new_callable=AsyncMock)
    @patch("domain.routes.ip_enrichment", new_callable=AsyncMock)
    def test_threat_report_partial_failure(self, mock_enrich, mock_abuse, mock_shodan, mock_ripe, mock_auth):
        """Shodan failure should not crash endpoint - returns error dict."""
        mock_enrich.return_value = {"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": []}
        mock_abuse.return_value = {"status": "ok", "abuse_score": 75}
        mock_ripe_resp = MagicMock()
        mock_ripe_resp.json.return_value = {"data": {"asns": [12345], "prefix": "1.2.3.0/24"}}
        mock_ripe_resp.raise_for_status = MagicMock()
        mock_ripe.get = AsyncMock(return_value=mock_ripe_resp)

        with patch("db.get_cached_domain", return_value=None), patch("db.save_cached_domain"):
            r = client.get("/v1/threat-report/1.2.3.4")
        assert r.status_code == 200
        data = r.json()
        assert data["shodan"]["status"] == "error"
        assert data["threat_level"] == "high"

    @patch("domain.routes._ripe_client", new_callable=AsyncMock)
    @patch("domain.routes.check_shodan", new_callable=AsyncMock)
    @patch("domain.routes.check_abuseipdb", new_callable=AsyncMock)
    @patch("domain.routes.ip_enrichment", new_callable=AsyncMock)
    @patch(
        "domain.routes._fetch_asn_country",
        new_callable=AsyncMock,
        return_value={"asn": None, "asn_name": "", "country": "", "failed": True},
    )
    def test_threat_report_asn_failure(self, mock_country, mock_enrich, mock_abuse, mock_shodan, mock_ripe):
        """RIPE failure should not crash - asn_data has error key."""
        mock_enrich.return_value = {"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": []}
        mock_abuse.return_value = {"status": "ok"}
        mock_shodan.return_value = {"status": "ok"}
        mock_ripe.get = AsyncMock(side_effect=RuntimeError("RIPE timeout"))

        with patch("db.get_cached_domain", return_value=None):
            r = client.get("/v1/threat-report/1.2.3.4")
        assert r.status_code == 200
        data = r.json()
        assert data["asn"] == {"error": "lookup_failed"}

    @patch("domain.routes._ripe_client", new_callable=AsyncMock)
    @patch(
        "domain.routes.check_shodan",
        side_effect=RuntimeError("internal/reputation.py line 73: connection refused"),
        new_callable=AsyncMock,
    )
    @patch("domain.routes.check_abuseipdb", new_callable=AsyncMock)
    @patch("domain.routes.ip_enrichment", new_callable=AsyncMock)
    def test_threat_report_no_exception_leakage(self, mock_enrich, mock_abuse, mock_shodan, mock_ripe):
        """Internal error details (paths, exception messages) must NOT leak in response."""
        mock_enrich.return_value = {"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": []}
        mock_abuse.return_value = {"status": "ok"}
        mock_ripe_resp = MagicMock()
        mock_ripe_resp.json.return_value = {"data": {"asns": [12345], "prefix": "1.2.3.0/24"}}
        mock_ripe_resp.raise_for_status = MagicMock()
        mock_ripe.get = AsyncMock(return_value=mock_ripe_resp)

        with patch("db.get_cached_domain", return_value=None), patch("db.save_cached_domain"):
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
    @patch("domain.recon.fetch_live_headers", new_callable=AsyncMock)
    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
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
    @patch("domain.recon.fetch_live_headers", new_callable=AsyncMock)
    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
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


class TestAuditDomainTxtFilter:
    """audit_domain must apply the same dns.txt filter as /v1/domain/{domain}.

    The cached report may contain vendor verification strings (google-site-verification,
    facebook-domain-verification, ms=...) that bloat the audit response without security
    signal. Default response strips them; ?include_all_txt=true restores the full list.
    """

    _TXT_REPORT = {
        "domain": "example.com",
        "dns": {
            "a": ["93.184.216.34"],
            "txt": [
                "v=spf1 include:_spf.google.com ~all",
                "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
                "google-site-verification=abc123xyz",
                "MS=ms123456",
                "facebook-domain-verification=zzzz",
                "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN",
                "atlassian-domain-verification=foobar",
                "stripe-verification=zzz",
            ],
        },
        "summary": "example.com - healthy",
    }

    @patch("domain.tech.detect_technologies")
    @patch("domain.recon.fetch_live_headers", new_callable=AsyncMock)
    @patch("db.get_cached_domain")
    @patch("domain.routes.clean_domain", return_value="example.com")
    def test_audit_domain_txt_filter_default(self, mock_clean, mock_get, mock_live, mock_tech):
        # Cached object — audit must not mutate it
        cached_obj = {**self._TXT_REPORT, "dns": dict(self._TXT_REPORT["dns"])}
        cached_obj["dns"]["txt"] = list(self._TXT_REPORT["dns"]["txt"])
        mock_get.return_value = cached_obj
        mock_live.return_value = {"headers": {}}
        mock_tech.return_value = {"technologies": [], "categories": {}, "count": 0, "summary": ""}

        r = client.get("/v1/audit/example.com")
        assert r.status_code == 200
        dns = r.json()["report"]["dns"]
        assert dns["total_txt_records"] == 8
        kept = dns["txt"]
        assert len(kept) == 3
        assert any(t.startswith("v=spf1") for t in kept)
        assert any(t.startswith("v=DMARC1") for t in kept)
        assert any(t.startswith("v=DKIM1") for t in kept)
        for v in kept:
            assert "google-site-verification" not in v
            assert "facebook-domain-verification" not in v

    @patch("domain.tech.detect_technologies")
    @patch("domain.recon.fetch_live_headers", new_callable=AsyncMock)
    @patch("db.get_cached_domain")
    @patch("domain.routes.clean_domain", return_value="example.com")
    def test_audit_domain_txt_include_all(self, mock_clean, mock_get, mock_live, mock_tech):
        cached_obj = {**self._TXT_REPORT, "dns": dict(self._TXT_REPORT["dns"])}
        cached_obj["dns"]["txt"] = list(self._TXT_REPORT["dns"]["txt"])
        mock_get.return_value = cached_obj
        mock_live.return_value = {"headers": {}}
        mock_tech.return_value = {"technologies": [], "categories": {}, "count": 0, "summary": ""}

        r = client.get("/v1/audit/example.com?include_all_txt=true")
        assert r.status_code == 200
        dns = r.json()["report"]["dns"]
        assert dns["total_txt_records"] == 8
        assert len(dns["txt"]) == 8

    @patch("domain.tech.detect_technologies")
    @patch("domain.recon.fetch_live_headers", new_callable=AsyncMock)
    @patch("db.get_cached_domain")
    @patch("domain.routes.clean_domain", return_value="example.com")
    def test_audit_domain_txt_filter_does_not_mutate_cache(self, mock_clean, mock_get, mock_live, mock_tech):
        # Two back-to-back calls hitting the same cached object — second call must
        # see the original 8-entry list (i.e. filter must not mutate cache).
        cached_obj = {**self._TXT_REPORT, "dns": dict(self._TXT_REPORT["dns"])}
        cached_obj["dns"]["txt"] = list(self._TXT_REPORT["dns"]["txt"])
        mock_get.return_value = cached_obj
        mock_live.return_value = {"headers": {}}
        mock_tech.return_value = {"technologies": [], "categories": {}, "count": 0, "summary": ""}

        r1 = client.get("/v1/audit/example.com")
        assert r1.status_code == 200
        assert len(r1.json()["report"]["dns"]["txt"]) == 3

        r2 = client.get("/v1/audit/example.com?include_all_txt=true")
        assert r2.status_code == 200
        assert len(r2.json()["report"]["dns"]["txt"]) == 8
