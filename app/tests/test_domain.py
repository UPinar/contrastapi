"""Tests for domain intelligence module — recon.py + routes.py"""

import asyncio
import itertools
import json
import socket
import ssl
from datetime import UTC
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.resolver
import httpx
import pytest
from auth import AuthCtx
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


# =========== recon.py unit tests ===========

# --- _parse_whois ---


class TestParseWhois:
    def test_parse_registrar(self):
        from domain.recon import _parse_whois

        text = "Registrar: Example Registrar Inc.\nCreation Date: 2020-01-01"
        result = _parse_whois(text)
        assert result["registrar"] == "Example Registrar Inc."

    def test_parse_creation_date(self):
        from domain.recon import _parse_whois

        text = "Creation Date: 2020-01-15T00:00:00Z"
        result = _parse_whois(text)
        assert "2020-01-15" in result["creation_date"]

    def test_parse_expiry_date(self):
        from domain.recon import _parse_whois

        text = "Registry Expiry Date: 2025-01-15T00:00:00Z"
        result = _parse_whois(text)
        assert "2025-01-15" in result["expiry_date"]

    def test_parse_name_servers(self):
        from domain.recon import _parse_whois

        text = "Name Server: ns1.example.com\nName Server: ns2.example.com"
        result = _parse_whois(text)
        assert len(result["name_servers"]) == 2

    def test_parse_status(self):
        from domain.recon import _parse_whois

        text = "Domain Status: clientTransferProhibited\nDomain Status: clientDeleteProhibited"
        result = _parse_whois(text)
        assert len(result["status"]) == 2

    def test_parse_empty(self):
        from domain.recon import _parse_whois

        assert _parse_whois("") == {}

    def test_parse_updated_date(self):
        from domain.recon import _parse_whois

        text = "Updated Date: 2024-06-01T12:00:00Z"
        result = _parse_whois(text)
        assert "2024-06-01" in result["updated_date"]

    def test_parse_created_date_variant(self):
        from domain.recon import _parse_whois

        text = "Created Date: 2020-03-10T00:00:00Z"
        result = _parse_whois(text)
        assert "2020-03-10" in result["creation_date"]

    def test_parse_expiry_date_variant(self):
        from domain.recon import _parse_whois

        text = "Expiration Date: 2026-03-10T00:00:00Z"
        result = _parse_whois(text)
        assert "2026-03-10" in result["expiry_date"]

    def test_parse_last_updated_variant(self):
        from domain.recon import _parse_whois

        text = "Last updated: 2025-01-15"
        result = _parse_whois(text)
        assert "2025-01-15" in result["updated_date"]


# --- _crtsh_subdomains ---


class TestCrtshSubdomains:
    def test_extracts_subdomains(self):
        from domain.recon import _crtsh_subdomains

        data = [
            {"name_value": "www.example.com"},
            {"name_value": "mail.example.com\napi.example.com"},
        ]
        subs, warnings, _status = asyncio.run(_crtsh_subdomains("example.com", data))
        assert "www.example.com" in subs
        assert "api.example.com" in subs

    def test_filters_wildcards(self):
        from domain.recon import _crtsh_subdomains

        data = [{"name_value": "*.example.com"}]
        subs, warnings, _status = asyncio.run(_crtsh_subdomains("example.com", data))
        assert len(subs) == 0

    def test_filters_other_domains(self):
        from domain.recon import _crtsh_subdomains

        data = [{"name_value": "sub.other.com"}]
        subs, warnings, _status = asyncio.run(_crtsh_subdomains("example.com", data))
        assert len(subs) == 0

    def test_limits_to_50(self):
        from domain.recon import _crtsh_subdomains

        data = [{"name_value": f"sub{i}.example.com"} for i in range(100)]
        subs, warnings, _status = asyncio.run(_crtsh_subdomains("example.com", data))
        assert len(subs) <= 50

    def test_empty_data(self):
        from domain.recon import _crtsh_subdomains

        subs, warnings, _status = asyncio.run(_crtsh_subdomains("example.com", []))
        assert subs == []


# --- _fetch_crtsh error handling ---


class TestFetchCrtsh:
    def test_fetch_crtsh_timeout(self):
        from domain.recon import _fetch_crtsh

        with patch("domain.recon._http") as mock_http:
            mock_http.get = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
            data, err = asyncio.run(_fetch_crtsh("%.example.com"))
            assert data == []
            assert err == "crt_sh_timeout"

    def test_fetch_crtsh_429(self):
        from domain.recon import _fetch_crtsh

        mock_resp = MagicMock()
        mock_resp.status_code = 429
        with patch("domain.recon._http") as mock_http:
            mock_http.get = AsyncMock(return_value=mock_resp)
            data, err = asyncio.run(_fetch_crtsh("%.example.com"))
            assert data == []
            assert err == "crt_sh_rate_limited"

    def test_fetch_crtsh_malformed_json(self):
        from domain.recon import _fetch_crtsh

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.side_effect = json.JSONDecodeError("bad json", "", 0)
        with patch("domain.recon._http") as mock_http:
            mock_http.get = AsyncMock(return_value=mock_resp)
            data, err = asyncio.run(_fetch_crtsh("%.example.com"))
            assert data == []
            assert err == "parse_error"

    def test_enumerate_subdomains_crtsh_down(self):
        from domain.recon import enumerate_subdomains

        with patch("domain.recon._fetch_crtsh", return_value=([], "crt_sh_timeout")):
            with patch(
                "domain.recon.socket.gethostbyname",
                side_effect=socket.gaierror(socket.EAI_NONAME, "not found"),
            ):
                result = asyncio.run(enumerate_subdomains("example.com"))
        assert result["warnings"] == ["crt_sh_timeout"]
        assert result["sources"] == []
        assert result["subdomains"] == []
        assert result["crtsh_status"] == "timeout"
        assert "CT logs timeout" in result["summary"]

    def test_enumerate_subdomains_no_crtsh_results(self):
        from domain.recon import enumerate_subdomains

        with patch("domain.recon._fetch_crtsh", return_value=([], None)):
            with patch(
                "domain.recon.socket.gethostbyname",
                side_effect=socket.gaierror(socket.EAI_NONAME, "not found"),
            ):
                result = asyncio.run(enumerate_subdomains("example.com"))
        assert result["warnings"] == []
        # Bug N: confirmed-empty path emits crtsh_status='ok' so agents can trust the count
        assert result["crtsh_status"] == "ok"
        assert "CT logs" not in result["summary"] or "via CT logs" in result["summary"]

    def test_crtsh_wildcard_dedup(self):
        from domain.recon import _crtsh_subdomains

        data = [{"name_value": "*.api.example.com\napi.example.com"}]
        subs, warnings, _status = asyncio.run(_crtsh_subdomains("example.com", data))
        assert subs.count("api.example.com") == 1
        assert warnings == []

    def test_enumerate_subdomains_cap_large_result(self):
        from domain.recon import CRTSH_MAX_RESULTS, enumerate_subdomains

        large_data = [{"name_value": f"sub{i}.example.com"} for i in range(2000)]
        assert len(large_data) > CRTSH_MAX_RESULTS

        with patch("domain.recon._fetch_crtsh", return_value=(large_data[:CRTSH_MAX_RESULTS], None)):
            with patch(
                "domain.recon.socket.gethostbyname",
                side_effect=socket.gaierror(socket.EAI_NONAME, "not found"),
            ):
                result = asyncio.run(enumerate_subdomains("example.com"))
        assert len(result["subdomains"]) <= 50


class TestSubdomainEnumCrtshStatus:
    """Bug N: count + found_via_crtsh=0 was ambiguous between 'CT confirmed empty'
    and 'CT lookup failed'. crtsh_status now disambiguates."""

    @pytest.mark.parametrize(
        "fetch_error,expected_status",
        [
            ("crt_sh_timeout", "timeout"),
            ("crt_sh_rate_limited", "rate_limited"),
            ("crt_sh_unavailable", "unavailable"),
            ("crt_sh_error", "error"),
            ("parse_error", "error"),
        ],
    )
    def test_status_maps_fetch_error(self, fetch_error, expected_status):
        from domain.recon import enumerate_subdomains

        with patch("domain.recon._fetch_crtsh", return_value=([], fetch_error)):
            with patch(
                "domain.recon.socket.gethostbyname",
                side_effect=socket.gaierror(socket.EAI_NONAME, "not found"),
            ):
                result = asyncio.run(enumerate_subdomains("example.com"))
        assert result["crtsh_status"] == expected_status
        assert fetch_error in result["warnings"]

    def test_status_ok_when_crtsh_data_supplied_directly(self):
        # full_domain_report fetches once and passes data in — that path skips
        # the fetch and must report status='ok' regardless of empty/non-empty.
        from domain.recon import enumerate_subdomains

        with patch(
            "domain.recon.socket.gethostbyname",
            side_effect=socket.gaierror(socket.EAI_NONAME, "not found"),
        ):
            result = asyncio.run(enumerate_subdomains("example.com", crtsh_data=[]))
        assert result["crtsh_status"] == "ok"

    def test_status_ok_with_real_crtsh_results(self):
        from domain.recon import enumerate_subdomains

        data = [{"name_value": "api.example.com\nweb.example.com"}]
        with patch("domain.recon._fetch_crtsh", return_value=(data, None)):
            with patch(
                "domain.recon.socket.gethostbyname",
                side_effect=socket.gaierror(socket.EAI_NONAME, "not found"),
            ):
                result = asyncio.run(enumerate_subdomains("example.com"))
        assert result["crtsh_status"] == "ok"
        assert result["found_via_crtsh"] >= 1

    def test_route_emits_crtsh_status(self):
        from unittest.mock import AsyncMock
        from unittest.mock import patch as _patch

        with _patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE):
            with _patch(
                "domain.routes.enumerate_subdomains",
                return_value={
                    "subdomains": [],
                    "count": 0,
                    "sources": [],
                    "found_via_wordlist": 0,
                    "found_via_crtsh": 0,
                    "crtsh_status": "timeout",
                    "warnings": ["crt_sh_timeout"],
                    "summary": "0 subdomain(s) found for example.com (CT logs timeout)",
                },
            ):
                with _patch("domain.routes._validate_domain_input", return_value=("example.com", "1.2.3.4")):
                    with _patch("domain.routes._from_cache", return_value=None):
                        r = client.get("/v1/subdomains/example.com")
                        assert r.status_code == 200
                        data = r.json()
                        assert data["crtsh_status"] == "timeout"


# --- detect_waf ---


class TestDetectWaf:
    def test_detects_cloudflare(self):
        from domain.recon import detect_waf

        result = detect_waf({"server": "cloudflare"})
        assert "Cloudflare" in result["detected"]
        assert result["waf_present"] is True

    def test_detects_fastly(self):
        from domain.recon import detect_waf

        result = detect_waf({"x-fastly-request-id": "abc123"})
        assert "Fastly" in result["detected"]

    def test_no_waf(self):
        from domain.recon import detect_waf

        result = detect_waf({"server": "nginx"})
        assert result["waf_present"] is False
        assert result["detected"] == []

    def test_multiple_waf(self):
        from domain.recon import detect_waf

        result = detect_waf({"server": "cloudflare", "x-fastly-request-id": "abc"})
        assert len(result["detected"]) >= 2


# --- check_ct_logs ---


class TestCheckCtLogs:
    def test_with_data(self):
        from domain.recon import check_ct_logs

        data = [
            {
                "serial_number": "001",
                "issuer_name": "Let's Encrypt",
                "not_before": "2024-01-01",
                "not_after": "2024-04-01",
                "common_name": "example.com",
            },
            {
                "serial_number": "002",
                "issuer_name": "DigiCert",
                "not_before": "2024-02-01",
                "not_after": "2024-05-01",
                "common_name": "www.example.com",
            },
        ]
        result = asyncio.run(check_ct_logs("example.com", data))
        assert result["total_certificates"] == 2
        assert len(result["certificates"]) == 2

    def test_deduplicates_by_serial(self):
        from domain.recon import check_ct_logs

        data = [
            {"serial_number": "001", "issuer_name": "LE", "not_before": "", "not_after": "", "common_name": "a.com"},
            {"serial_number": "001", "issuer_name": "LE", "not_before": "", "not_after": "", "common_name": "a.com"},
        ]
        result = asyncio.run(check_ct_logs("a.com", data))
        assert len(result["certificates"]) == 1

    def test_empty_data(self):
        from domain.recon import check_ct_logs

        result = asyncio.run(check_ct_logs("x.com", []))
        assert result["total_certificates"] == 0

    def test_limits_certificates(self):
        from domain.recon import check_ct_logs

        data = [
            {"serial_number": str(i), "issuer_name": "LE", "not_before": "", "not_after": "", "common_name": "x.com"}
            for i in range(25)
        ]
        result = asyncio.run(check_ct_logs("x.com", data))
        assert len(result["certificates"]) <= 10


# --- dns_lookup (mocked) ---


class TestDnsLookup:
    @patch("domain.recon.dns.resolver.resolve")
    def test_returns_records(self, mock_resolve):
        from domain.recon import dns_lookup

        mock_a = MagicMock()
        mock_a.__str__ = lambda self: "93.184.216.34"
        mock_a.__iter__ = lambda self: iter([mock_a])

        def side_effect(domain, rtype):
            if rtype == "A":
                return [mock_a]
            raise dns.resolver.NoAnswer()

        import dns.resolver

        mock_resolve.side_effect = side_effect
        result = dns_lookup("example.com")
        assert "a" in result

    @patch("domain.recon.dns.resolver.Resolver")
    def test_total_txt_records_matches_txt_length(self, mock_resolver_cls):
        """dns_lookup() always emits total_txt_records — honest count of TXT answers."""
        import dns.resolver
        from domain.recon import dns_lookup

        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        rec1 = MagicMock()
        rec1.strings = [b"v=spf1 -all"]
        rec2 = MagicMock()
        rec2.strings = [b"google-site-verification=abc"]

        def resolve_side_effect(name, rtype):
            if rtype == "TXT":
                return [rec1, rec2]
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = resolve_side_effect
        result = dns_lookup("example.com")
        assert len(result["txt"]) == 2
        assert result["total_txt_records"] == 2

    @patch("domain.recon.dns.resolver.Resolver")
    def test_total_txt_records_zero_when_no_txt(self, mock_resolver_cls):
        """No TXT records → total_txt_records=0, not null (regression guard)."""
        import dns.resolver
        from domain.recon import dns_lookup

        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()

        result = dns_lookup("example.com")
        assert result.get("txt") in (None, [])
        assert result["total_txt_records"] == 0


# --- reverse_dns (mocked) ---


class TestReverseDns:
    @patch("domain.recon.socket.gethostbyaddr")
    @patch("domain.recon.socket.gethostbyname")
    def test_reverse_dns_success(self, mock_name, mock_addr):
        from domain.recon import reverse_dns

        mock_name.return_value = "93.184.216.34"
        mock_addr.return_value = ("example.com", [], [])
        result = reverse_dns("example.com")
        assert result["ip"] == "93.184.216.34"
        assert result["ptr"] == "example.com"

    @patch("domain.recon.socket.gethostbyname", side_effect=Exception("fail"))
    def test_reverse_dns_failure(self, mock_name):
        from domain.recon import reverse_dns

        result = reverse_dns("nonexistent.invalid")
        assert result["ip"] is None


# =========== routes.py integration tests (mocked) ===========

MOCK_DNS_RESULT = {"a": ["93.184.216.34"], "ns": ["a.iana-servers.net"]}
MOCK_WHOIS_RESULT = {
    "registrar": "Test Registrar",
    "creation_date": "2020-01-01",
    "expiry_date": "2030-01-01",
    "updated_date": "2024-01-01",
    "name_servers": ["a.iana-servers.net", "b.iana-servers.net"],
    "status": ["clientTransferProhibited"],
    "raw_length": 500,
}
MOCK_SUBDOMAIN_RESULT = {"subdomains": ["www.example.com"], "count": 1}
MOCK_CT_RESULT = {"total_certificates": 1, "certificates": [{"issuer": "LE", "common_name": "example.com"}]}
MOCK_FULL_REPORT = {
    "domain": "example.com",
    "dns": MOCK_DNS_RESULT,
    "reverse_dns": {"ip": "93.184.216.34", "ptr": "example.com"},
    "whois": MOCK_WHOIS_RESULT,
    "ssl": {"issuer": "DigiCert", "common_name": "example.com"},
    "subdomains": MOCK_SUBDOMAIN_RESULT,
    "certificates": MOCK_CT_RESULT,
    "threat": {
        "urlhaus_status": "clean",
        "url_count": 0,
        "urls_online": 0,
        "threat_types": [],
        "tags": [],
        "urls": [],
    },
    "waf": {"detected": [], "waf_present": False},
    "risk": {"score": 85, "max_score": 100, "grade": "B", "factors": []},
    "summary": "example.com resolves to 93.184.216.34",
}


class TestDomainRoutes:
    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT, new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age", return_value=None)
    def test_domain_report_200(self, mock_cache, mock_validate, mock_report):
        """validate_domain is called in _validate_and_auth for all routes."""
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "example.com"
        assert "dns" in data
        assert "summary" in data

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT, new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age", return_value=None)
    def test_domain_report_post(self, mock_cache, mock_validate, mock_report):
        """POST returns same result as GET (Salesforce SFDC-Callout compat)."""
        r = client.post("/v1/domain/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "example.com"

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT, new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age", return_value=None)
    def test_domain_report_post_with_body(self, mock_cache, mock_validate, mock_report):
        """POST with JSON body is ignored (body not read)."""
        r = client.post("/v1/domain/example.com", json={"extra": "ignored"})
        assert r.status_code == 200

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT, new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age", return_value=None)
    def test_domain_report_risk_score_alias(self, mock_cache, mock_validate, mock_report):
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        data = r.json()
        assert "risk" in data
        assert "risk_score" in data
        assert isinstance(data["risk_score"], int)
        assert data["risk_score"] == data["risk"]["score"]

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT, new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age", return_value=None)
    def test_domain_report_emits_rfc8594_deprecation_headers(self, mock_cache, mock_validate, mock_report):
        """v1.21.1: top-level risk_score alias is deprecated; route emits Deprecation/Sunset."""
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        assert r.headers.get("Deprecation") == "true"
        assert r.headers.get("Sunset") == "Wed, 01 Sep 2026 00:00:00 GMT"
        assert "deprecation" in r.headers.get("Link", "")
        # Link must resolve — pointing to GitHub releases (which lists v1.21.1 deprecation note)
        assert "github.com/UPinar/contrastapi/releases" in r.headers.get("Link", "")

    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age", return_value=(MOCK_FULL_REPORT, 1800))
    def test_domain_report_emits_deprecation_headers_on_cache_hit(self, mock_cache, mock_validate, mock_report):
        """v1.21.1: deprecation headers must fire on BOTH cache-miss AND cache-hit paths."""
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        assert mock_report.call_count == 0  # confirms cache-hit path
        assert r.headers.get("Deprecation") == "true"
        assert r.headers.get("Sunset") == "Wed, 01 Sep 2026 00:00:00 GMT"

    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age", return_value=(MOCK_FULL_REPORT, 3600))
    def test_domain_report_cached(self, mock_cache, mock_validate, mock_report):
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        data = r.json()
        assert mock_report.call_count == 0

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT, new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age", return_value=None)
    def test_domain_report_lite(self, mock_cache, mock_validate, mock_report):
        """?lite=true passes lite=True to full_domain_report and uses separate cache key."""
        r = client.get("/v1/domain/example.com?lite=true")
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "example.com"
        mock_report.assert_called_once()
        _, kwargs = mock_report.call_args
        assert kwargs["lite"] is True
        # Cache key is tier-prefixed (free-tier unauthenticated test client)
        mock_cache.assert_called_once_with("free:lite:example.com")

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT, new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_domain_report_lite_and_full_use_distinct_cache_keys(self, mock_validate, mock_report):
        """Regression for B4: a lite-cached entry must NOT be served to a full
        request and vice versa. The two modes have different response shapes
        (full includes WHOIS / subdomains / CT logs / URLhaus / reputation
        that lite skips); cross-serving would silently downgrade a full
        consumer to lite-shape data."""
        from unittest.mock import patch as _patch

        keys_seen: list[str] = []

        def fake_get(key: str):
            keys_seen.append(key)
            return None

        with _patch("db.get_cached_domain_with_age", side_effect=fake_get):
            client.get("/v1/domain/example.com?lite=true")
            client.get("/v1/domain/example.com")
        assert keys_seen == ["free:lite:example.com", "free:example.com"]
        # full_domain_report fired twice (no cross-mode cache reuse)
        assert mock_report.call_count == 2

    @patch("domain.routes._is_valid_format", return_value=False)
    @patch("domain.routes.validate_domain", return_value=None)
    @patch("db.get_cached_domain_with_age", return_value=None)
    def test_domain_report_invalid_domain(self, mock_cache, mock_validate, mock_format):
        r = client.get("/v1/domain/nonexistent.invalid")
        assert r.status_code == 400

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT, new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age", return_value=None)
    def test_domain_report_verdict(self, mock_cache, mock_validate, mock_report):
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        body = r.json()
        assert "verdict" in body
        v = body["verdict"]
        assert v["deterministic"] is True
        assert set(v["falsifiable_fields"]) >= {"dns", "whois", "ssl"}
        if "data_age_seconds" in v:
            assert isinstance(v["data_age_seconds"], int)
            assert v["data_age_seconds"] >= 0

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT, new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age", return_value=None)
    def test_domain_report_verdict_complete_full_mode(self, mock_cache, mock_validate, mock_report):
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        v = r.json()["verdict"]
        assert set(v["sources_queried"]) >= {"dns", "ssl", "whois", "subdomains", "ct_logs", "urlhaus"}
        assert "urlhaus" in v["sources_queried"]  # threat key present + status != "error"
        assert v["completeness"] == "complete"
        assert v["sources_unavailable"] == []

    @patch(
        "domain.routes.full_domain_report",
        return_value={
            **MOCK_FULL_REPORT,
            "threat": {
                "urlhaus_status": "error",
                "url_count": 0,
                "urls_online": 0,
                "threat_types": [],
                "tags": [],
                "urls": [],
            },
        },
        new_callable=AsyncMock,
    )
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age", return_value=None)
    def test_domain_report_verdict_partial_on_urlhaus_error(self, mock_cache, mock_validate, mock_report):
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        v = r.json()["verdict"]
        assert "urlhaus" in v["sources_unavailable"]
        assert v["completeness"] == "partial"

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT, new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age", return_value=None)
    def test_domain_report_verdict_lite_mode(self, mock_cache, mock_validate, mock_report):
        r = client.get("/v1/domain/example.com?lite=true")
        assert r.status_code == 200
        v = r.json()["verdict"]
        assert v["sources_queried"] == ["dns", "ssl"]
        assert "whois" not in v["sources_queried"]
        assert "urlhaus" not in v["sources_queried"]
        assert set(v["sources_unavailable"]) == {"whois", "subdomains", "ct_logs", "urlhaus", "reputation"}
        assert v["completeness"] == "complete"

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT, new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age", return_value=None)
    def test_domain_report_next_calls_full_chain(self, mock_cache, mock_validate, mock_report):
        """Cascade: domain has A record → subdomain_enum + ssl_check + tech_fingerprint."""
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        next_calls = r.json().get("next_calls")
        assert next_calls is not None
        tools = [hint["tool"] for hint in next_calls]
        assert tools == ["subdomain_enum", "ssl_check", "tech_fingerprint"]
        for hint in next_calls:
            assert hint["input"] == "example.com"
            assert hint["reason"]

    def test_domain_pivot_hints_no_a_record_drops_ssl_and_tech(self):
        from domain.routes import _domain_pivot_hints

        # Domain with DNS block but no A/AAAA → only subdomain_enum
        report = {"dns": {"mx": [{"exchange": "mx.example.com"}]}}
        hints = _domain_pivot_hints(report, "example.com")
        tools = [h.tool for h in hints]
        assert tools == ["subdomain_enum"]

    def test_domain_pivot_hints_nxdomain_returns_empty(self):
        from domain.routes import _domain_pivot_hints

        # NXDOMAIN: no dns block at all → no hints (don't waste agent calls)
        hints = _domain_pivot_hints({}, "nonexistent.invalid")
        assert hints == []

    @patch("domain.routes.dns_lookup", return_value=MOCK_DNS_RESULT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_dns_records_200(self, mock_validate, mock_dns):
        r = client.get("/v1/dns/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "example.com"
        assert "records" in data

    @patch("domain.routes.dns_lookup", return_value={})
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_dns_records_404(self, mock_validate, mock_dns):
        r = client.get("/v1/dns/nonexistent.invalid")
        assert r.status_code == 404

    @patch("domain.recon.whois_lookup", return_value=MOCK_WHOIS_RESULT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_whois_200(self, mock_validate, mock_whois):
        r = client.get("/v1/whois/example.com")
        assert r.status_code == 200
        data = r.json()
        assert "whois" in data
        whois = data["whois"]
        assert "expiry_date" in whois
        assert "expiration_date" not in whois
        assert "dnssec" not in whois
        assert whois["expiry_date"] == "2030-01-01"
        assert "name_servers" in whois
        assert whois["registrar"] == "Test Registrar"

    @patch("domain.recon.whois_lookup", return_value={"error": "No WHOIS server"})
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_whois_error(self, mock_validate, mock_whois):
        r = client.get("/v1/whois/example.dev")
        assert r.status_code == 504

    @patch("domain.routes.enumerate_subdomains", return_value=MOCK_SUBDOMAIN_RESULT, new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_subdomains_200(self, mock_validate, mock_subs):
        r = client.get("/v1/subdomains/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 1

    @patch("domain.routes.check_ct_logs", return_value=MOCK_CT_RESULT, new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_certs_200(self, mock_validate, mock_ct):
        r = client.get("/v1/certs/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["total_certificates"] == 1

    @patch("domain.routes.check_ct_logs", return_value=MOCK_CT_RESULT, new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_certs_second_call_served_from_cache(self, mock_validate, mock_ct):
        # Cold call writes to dedicated `certificates:{domain}` cache.
        r1 = client.get("/v1/certs/example.com")
        assert r1.status_code == 200
        # Hot call must NOT re-invoke check_ct_logs (CT log fetch can take 10s+).
        r2 = client.get("/v1/certs/example.com")
        assert r2.status_code == 200
        assert r2.json()["total_certificates"] == 1
        assert mock_ct.call_count == 1

    @patch(
        "domain.routes.ip_enrichment",
        return_value={
            "ports": [22, 80],
            "hostnames": [],
            "vulns": [],
            "cpes": [],
            "tags": [],
            "internetdb_status": "ok",
        },
        new_callable=AsyncMock,
    )
    @patch("domain.routes.socket.gethostbyaddr", return_value=("example.com", [], []))
    def test_ip_lookup_200(self, mock_ptr, mock_enrich):
        r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        data = r.json()
        assert data["ip"] == "93.184.216.34"
        assert data["ptr"] == "example.com"

    @patch(
        "domain.routes.ip_enrichment",
        return_value={"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": [], "internetdb_status": "ok"},
        new_callable=AsyncMock,
    )
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_lookup_no_ptr(self, mock_ptr, mock_enrich):
        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200
        data = r.json()
        assert data.get("ptr") is None

    @patch(
        "domain.routes.ip_enrichment",
        return_value={
            "ports": [22, 80],
            "hostnames": [],
            "vulns": [],
            "cpes": [],
            "tags": [],
            "internetdb_status": "ok",
        },
        new_callable=AsyncMock,
    )
    @patch("domain.routes.socket.gethostbyaddr", return_value=("example.com", [], []))
    def test_ip_lookup_verdict(self, mock_ptr, mock_enrich):
        r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        body = r.json()
        assert "verdict" in body
        v = body["verdict"]
        assert v["deterministic"] is True
        assert set(v["falsifiable_fields"]) >= {"ptr", "ports", "vulns"}
        if v.get("data_age_seconds") is not None:
            assert isinstance(v["data_age_seconds"], int)
            assert v["data_age_seconds"] >= 0

    @patch(
        "domain.routes.ip_enrichment",
        return_value={"ports": [80], "hostnames": [], "vulns": [], "cpes": [], "tags": [], "internetdb_status": "ok"},
        new_callable=AsyncMock,
    )
    @patch("domain.routes.socket.gethostbyaddr", return_value=("example.com", [], []))
    def test_ip_lookup_verdict_complete_happy_path(self, mock_ptr, mock_enrich):
        r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        body = r.json()
        v = body["verdict"]
        assert "internetdb" in v["sources_queried"]
        assert v["completeness"] == "complete"
        assert v["sources_unavailable"] == []
        assert "internetdb_status" not in body

    @patch(
        "domain.routes.ip_enrichment",
        return_value={"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": [], "internetdb_status": "error"},
        new_callable=AsyncMock,
    )
    @patch("domain.routes.socket.gethostbyaddr", return_value=("example.com", [], []))
    def test_ip_lookup_verdict_partial_on_internetdb_error(self, mock_ptr, mock_enrich):
        r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        v = r.json()["verdict"]
        assert "internetdb" in v["sources_unavailable"]
        assert v["completeness"] == "partial"

    @patch(
        "domain.routes.ip_enrichment",
        return_value={"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": [], "internetdb_status": "ok"},
        new_callable=AsyncMock,
    )
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_lookup_verdict_includes_tor_when_cache_ok(self, mock_ptr, mock_enrich):
        """NEW-B: tor source is always queried; with a healthy cache it must
        appear in sources_queried and never in sources_unavailable."""
        with patch("domain.routes.tor_cache_status", return_value="ok"):
            r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        v = r.json()["verdict"]
        assert "tor" in v["sources_queried"]
        assert "tor" not in v["sources_unavailable"]

    @patch(
        "domain.routes.ip_enrichment",
        return_value={"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": [], "internetdb_status": "ok"},
        new_callable=AsyncMock,
    )
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_lookup_verdict_marks_tor_unavailable_when_fetch_failed(self, mock_ptr, mock_enrich):
        """NEW-B: a silent Tor list fetch failure must surface in the verdict
        — agents can then treat tor_exit=false as 'unknown' instead of
        'definitively not a Tor exit'."""
        with patch("domain.routes.tor_cache_status", return_value="failed"):
            r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        v = r.json()["verdict"]
        assert "tor" in v["sources_queried"]
        assert "tor" in v["sources_unavailable"]
        assert v["completeness"] == "partial"

    @patch(
        "domain.routes.ip_enrichment",
        return_value={"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": [], "internetdb_status": "ok"},
        new_callable=AsyncMock,
    )
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_lookup_verdict_marks_tor_unavailable_on_initial_status(self, mock_ptr, mock_enrich):
        """First-request-after-restart: tor cache is still 'initial' (never
        refreshed). Mark as unavailable so the response does not pretend
        the Tor list answered."""
        with patch("domain.routes.tor_cache_status", return_value="initial"):
            r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        v = r.json()["verdict"]
        assert "tor" in v["sources_unavailable"]

    _enrich_empty = {
        "ports": [],
        "hostnames": [],
        "vulns": [],
        "cpes": [],
        "tags": [],
        "internetdb_status": "ok",
    }

    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value="AWS")
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty}, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_cloud_provider_aws(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/3.5.140.2")
        assert r.status_code == 200
        data = r.json()
        assert data["cloud_provider"] == "AWS"
        # tor_exit is always present as a bool (response_model_exclude_none=False on /ip/{ip})
        assert data["tor_exit"] is False

    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value=None)
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty}, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_cloud_provider_none(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200
        data = r.json()
        # cloud_provider is always present (null when neither CIDR nor ASN map matches)
        assert data["cloud_provider"] is None

    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value=None)
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=True)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty}, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_tor_exit_true(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200
        data = r.json()
        assert data["tor_exit"] is True

    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value=None)
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty}, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_risk_score_present(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200
        data = r.json()
        assert "risk_score" in data
        assert 0 <= data["risk_score"] <= 100

    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value="GCP")
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch(
        "domain.routes.ip_enrichment",
        return_value={"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": [], "internetdb_status": "ok"},
        new_callable=AsyncMock,
    )
    @patch("domain.routes.socket.gethostbyaddr", return_value=("dns.google", [], []))
    def test_ip_risk_score_low_clean_cloud(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/8.8.8.8")
        assert r.status_code == 200
        data = r.json()
        # cloud bonus + ptr bonus, no abuse, no tor → low score
        assert data["risk_score"] <= 30

    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value=None)
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=True)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty}, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_risk_score_high_tor(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200
        data = r.json()
        # tor_exit=True → at least 20 penalty
        assert data["risk_score"] >= 20

    # --- Phase 2 IP enrichment (v1.16.0) ---
    # /v1/ip/{ip}.vulns ships severity-aware list[VulnInfo] instead of flat
    # list[str] of CVE IDs. Three contracts under test: known-CVE enrichment,
    # unknown-CVE honesty (UNKNOWN/null, not absent), Shodan input order
    # preservation.

    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value=None)
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch(
        "domain.routes.ip_enrichment",
        return_value={
            "ports": [80],
            "hostnames": [],
            "vulns": ["CVE-2099-IP-CRIT", "CVE-2099-IP-HIGH"],
            "cpes": [],
            "tags": [],
            "internetdb_status": "ok",
        },
        new_callable=AsyncMock,
    )
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_lookup_vulns_enriched_with_severity(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        from db import upsert_cve

        upsert_cve(
            {"cve_id": "CVE-2099-IP-CRIT", "severity": "CRITICAL", "cvss_v3": 9.8, "published": "2099-01-01T00:00:00Z"}
        )
        upsert_cve(
            {"cve_id": "CVE-2099-IP-HIGH", "severity": "HIGH", "cvss_v3": 7.5, "published": "2099-01-01T00:00:00Z"}
        )

        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200
        vulns = r.json()["vulns"]
        assert len(vulns) == 2
        assert all(isinstance(v, dict) for v in vulns), "Phase 2: vulns must be list[VulnInfo], not list[str]"
        assert {v["cve_id"] for v in vulns} == {"CVE-2099-IP-CRIT", "CVE-2099-IP-HIGH"}
        crit = next(v for v in vulns if v["cve_id"] == "CVE-2099-IP-CRIT")
        assert crit["severity"] == "CRITICAL"
        assert crit["cvss_v3"] == 9.8

    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value=None)
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch(
        "domain.routes.ip_enrichment",
        return_value={
            "ports": [80],
            "hostnames": [],
            "vulns": ["CVE-9999-NOT-IN-DB"],
            "cpes": [],
            "tags": [],
            "internetdb_status": "ok",
        },
        new_callable=AsyncMock,
    )
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_lookup_unknown_cve_marked_unknown(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200
        vulns = r.json()["vulns"]
        assert len(vulns) == 1
        # Honesty: ID kept, severity='UNKNOWN', cvss_v3=null. Agent must NOT
        # infer 'benign' from absence of a database row.
        assert vulns[0]["cve_id"] == "CVE-9999-NOT-IN-DB"
        assert vulns[0]["severity"] == "UNKNOWN"
        assert vulns[0]["cvss_v3"] is None

    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value=None)
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch(
        "domain.routes.ip_enrichment",
        return_value={
            "ports": [80],
            # Trojan-Source guard: simulated poisoned Shodan feed slipping
            # bidi format chars (U+202E RLO + U+2066 LRI) + NULL into every
            # str-array. All four (vulns, hostnames, cpes, tags) must be
            # echoed clean — agents may render any of these in a bidi-aware
            # terminal / UI.
            "vulns": ["CVE-2099-IP-BIDI‮⁦suffix\x00"],
            "hostnames": ["evil.example‮com"],
            "cpes": ["cpe:2.3:a:bad:thing‮suffix:1.0"],
            "tags": ["cdn‮"],
            "internetdb_status": "ok",
        },
        new_callable=AsyncMock,
    )
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_lookup_vulns_strips_bidi_controls(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200
        body = r.json()

        # vulns: enriched + cleaned.
        assert len(body["vulns"]) == 1
        cid = body["vulns"][0]["cve_id"]
        assert "‮" not in cid and "⁦" not in cid and "\x00" not in cid
        assert "suffix" in cid  # plain-text payload preserved.

        # hostnames / cpes / tags also stripped (sister-field parity).
        for field in ("hostnames", "cpes", "tags"):
            for val in body.get(field, []):
                assert "‮" not in val and "⁦" not in val, f"{field} leaked bidi"

    # --- Phase 5 mini (v1.16.1) — severity_label inline ---

    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value=None)
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=True)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty}, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_lookup_severity_label_emitted(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200
        data = r.json()
        # severity_label must be present and a valid bucket.
        assert "severity_label" in data
        assert data["severity_label"] in ("low", "medium", "high", "critical")
        # v1.17.0: tor_exit alone gives +30 component (was +20 pre-refactor) → 30 → medium.
        assert data["severity_label"] == "medium"
        # falsifiable_fields advertises severity_label (verdict honesty).
        assert "severity_label" in data["verdict"]["falsifiable_fields"]

    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value=None)
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty}, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_verdict_falsifiable_includes_is_datacenter(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        # Phase 6 (v1.17.0): is_datacenter is now a top-level response field
        # and must be advertised in verdict.falsifiable_fields so agents can
        # audit drift instead of inferring datacenter status from cloud_provider.
        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200
        fields = r.json()["verdict"]["falsifiable_fields"]
        assert "is_datacenter" in fields

    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value=None)
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty}, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_verdict_falsifiable_includes_firehol(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        # Phase 6: firehol surfaces under reputation but the verdict block is
        # the contract that lists every field an agent may audit. Pre-1.17 the
        # entry was missing even though Free tier always emits firehol data.
        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200
        fields = r.json()["verdict"]["falsifiable_fields"]
        assert "firehol" in fields

    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value=None)
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch(
        "domain.routes.ip_enrichment",
        return_value={
            "ports": [80],
            "hostnames": [],
            "vulns": ["CVE-2099-IP-ORDER-2", "CVE-2099-IP-ORDER-1", "CVE-9999-IP-UNKNOWN"],
            "cpes": [],
            "tags": [],
            "internetdb_status": "ok",
        },
        new_callable=AsyncMock,
    )
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_lookup_vulns_preserves_shodan_order(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        from db import upsert_cve

        upsert_cve(
            {"cve_id": "CVE-2099-IP-ORDER-1", "severity": "LOW", "cvss_v3": 3.1, "published": "2099-01-01T00:00:00Z"}
        )
        upsert_cve(
            {"cve_id": "CVE-2099-IP-ORDER-2", "severity": "MEDIUM", "cvss_v3": 5.4, "published": "2099-01-01T00:00:00Z"}
        )

        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200
        # Shodan ranks confidence — preserve input order, do not sort by severity.
        order = [v["cve_id"] for v in r.json()["vulns"]]
        assert order == ["CVE-2099-IP-ORDER-2", "CVE-2099-IP-ORDER-1", "CVE-9999-IP-UNKNOWN"]

    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value="AWS")
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty}, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_verdict_extended_falsifiable_fields(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/3.5.140.2")
        assert r.status_code == 200
        fields = r.json()["verdict"]["falsifiable_fields"]
        assert "cloud_provider" in fields
        assert "tor_exit" in fields
        assert "risk_score" in fields

    @patch("domain.routes.check_cloud_provider", side_effect=Exception("upstream down"))
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty}, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_intel_cache_failure_resilient(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200  # must not 500

    @patch(
        "domain.routes._fetch_asn_country",
        return_value={"asn": 13335, "asn_name": "CLOUDFLARENET", "country": "US", "failed": False},
    )
    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value="Cloudflare")
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty}, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", return_value=("one.one.one.one", [], []))
    def test_ip_lookup_returns_asn_country(self, mock_ptr, mock_enrich, mock_tor, mock_cloud, mock_asn):
        r = client.get("/v1/ip/1.1.1.1")
        assert r.status_code == 200
        data = r.json()
        assert data["asn"] == 13335
        assert data["asn_name"] == "CLOUDFLARENET"
        assert data["country"] == "US"
        assert "AS13335" in data["summary"]
        assert "CLOUDFLARENET" in data["summary"]
        assert "US" in data["summary"]
        # Helper returned data → ripe_stat stays in queried, NOT in unavailable
        v = data["verdict"]
        assert "ripe_stat" in v["sources_queried"]
        assert "ripe_stat" not in v["sources_unavailable"]

    @patch(
        "domain.routes._fetch_asn_country",
        return_value={"asn": None, "asn_name": "", "country": "", "failed": True},
    )
    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value=None)
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty}, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_lookup_asn_fetch_failure_graceful(self, mock_ptr, mock_enrich, mock_tor, mock_cloud, mock_asn):
        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200
        data = r.json()
        # /ip/{ip} now emits null-explicit (response_model_exclude_none=False) so agents
        # can disambiguate "field absent" from "fetch failed". Verdict carries the why.
        assert data["asn"] is None
        assert data["asn_name"] is None
        assert data["country"] is None
        # Verdict honesty: when helper failed, ripe_stat moves to unavailable
        v = data["verdict"]
        assert "ripe_stat" in v["sources_unavailable"]
        assert v["completeness"] == "partial"

    @patch(
        "domain.routes._fetch_asn_country",
        return_value={"asn": 15169, "asn_name": "", "country": "US", "failed": False},
    )
    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value="GCP")
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty}, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", return_value=("dns.google", [], []))
    def test_ip_lookup_asn_name_missing_still_renders(self, mock_ptr, mock_enrich, mock_tor, mock_cloud, mock_asn):
        r = client.get("/v1/ip/8.8.8.8")
        assert r.status_code == 200
        data = r.json()
        assert data["asn"] == 15169
        # Empty asn_name → None — explicitly emitted now (was excluded by exclude_none=True before Bug #4)
        assert data["asn_name"] is None
        assert data["country"] == "US"
        assert "AS15169" in data["summary"]

    @patch(
        "domain.routes._fetch_asn_country",
        return_value={"asn": 13335, "asn_name": "CLOUDFLARENET", "country": "US", "failed": False},
    )
    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value="Cloudflare")
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty}, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", return_value=("one.one.one.one", [], []))
    def test_ip_lookup_verdict_includes_asn_fields(self, mock_ptr, mock_enrich, mock_tor, mock_cloud, mock_asn):
        r = client.get("/v1/ip/1.1.1.1")
        assert r.status_code == 200
        v = r.json()["verdict"]
        fields = v["falsifiable_fields"]
        assert "asn" in fields
        assert "asn_name" in fields
        assert "country" in fields
        assert "ripe_stat" in v["sources_queried"]

    @patch(
        "domain.routes._fetch_asn_country",
        return_value={"asn": 15169, "asn_name": "GOOGLE", "country": "US", "failed": False},
    )
    @patch("domain.routes.check_cloud_provider", new_callable=AsyncMock, return_value="Google")
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty}, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", return_value=("dns.google", [], []))
    def test_ip_lookup_ipv6_enrichment_path(self, mock_ptr, mock_enrich, mock_tor, mock_cloud, mock_asn):
        """B6 verify: IPv6 input traverses the same enrichment pipeline as IPv4
        — _fetch_asn_country, check_cloud_provider, check_tor_exit, and
        ip_enrichment all receive the IPv6 string unmodified, and asn/asn_name/
        country surface in the response. RIPE Stat (network-info, rir-stats-
        country, as-overview) accepts IPv6 resources upstream."""
        r = client.get("/v1/ip/2001:4860:4860::8888")
        assert r.status_code == 200
        data = r.json()
        # IPv6 echoed back (no IPv4 conversion / IPv6-mapped surprise)
        assert data["ip"] == "2001:4860:4860::8888"
        # ASN enrichment surfaces in the response
        assert data["asn"] == 15169
        assert data["asn_name"] == "GOOGLE"
        assert data["country"] == "US"
        # Helpers were called with the IPv6 string verbatim
        mock_asn.assert_called_once_with("2001:4860:4860::8888")
        mock_cloud.assert_called_once()
        cloud_args, _ = mock_cloud.call_args
        assert cloud_args[0] == "2001:4860:4860::8888"
        mock_tor.assert_called_once_with("2001:4860:4860::8888")
        mock_enrich.assert_called_once_with("2001:4860:4860::8888")

    def test_check_cloud_provider_asn_map_fallback_google(self):
        """8.8.8.8 isn't in the GCP CIDR list but AS15169 is in the ASN map → 'Google'."""
        import asyncio
        from unittest.mock import AsyncMock, patch

        from domain.ip_intel import check_cloud_provider

        # Force CIDR lookup to return None (mimic GCP range list missing 8.8.8.8)
        with patch("domain.ip_intel._refresh_cloud_cache", new_callable=AsyncMock, return_value=(None, None)):
            assert asyncio.run(check_cloud_provider("8.8.8.8", asn=15169)) == "Google"
            assert asyncio.run(check_cloud_provider("104.16.1.1", asn=13335)) == "Cloudflare"
            assert asyncio.run(check_cloud_provider("1.2.3.4", asn=99999)) is None  # unknown ASN
            assert asyncio.run(check_cloud_provider("1.2.3.4", asn=None)) is None  # no ASN provided

    def test_check_cloud_provider_cidr_takes_precedence_over_asn(self):
        """CIDR lookup is authoritative; ASN map only fires when CIDR misses."""
        import asyncio
        from unittest.mock import AsyncMock, MagicMock, patch

        from domain.ip_intel import check_cloud_provider

        fake_v4 = MagicMock()
        fake_v4.get.return_value = "AWS"  # CIDR says AWS
        with patch("domain.ip_intel._refresh_cloud_cache", new_callable=AsyncMock, return_value=(fake_v4, None)):
            # Even with asn=15169 (Google in map), CIDR's AWS wins
            assert asyncio.run(check_cloud_provider("3.5.140.2", asn=15169)) == "AWS"

    @patch(
        "domain.routes._fetch_asn_country",
        return_value={"asn": 15169, "asn_name": "GOOGLE - Google LLC", "country": "US", "failed": False},
    )
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty}, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", return_value=("dns.google", [], []))
    def test_ip_lookup_asn_map_resolves_google_for_8888(self, mock_ptr, mock_enrich, mock_tor, mock_asn):
        """End-to-end: 8.8.8.8 resolves cloud_provider='Google' via ASN-map fallback (Bug #4 audit fix)."""
        # Don't mock check_cloud_provider — let the real implementation use the ASN
        with patch("domain.ip_intel._refresh_cloud_cache", return_value=(None, None)):
            r = client.get("/v1/ip/8.8.8.8")
        assert r.status_code == 200
        data = r.json()
        assert data["asn"] == 15169
        assert data["cloud_provider"] == "Google"
        assert data["tor_exit"] is False  # always present, never null

    @patch(
        "domain.routes._fetch_asn_country",
        return_value={"asn": 15169, "asn_name": "GOOGLE - Google LLC", "country": "US", "failed": False},
    )
    @patch("domain.routes.check_tor_exit", new_callable=AsyncMock, return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty}, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", return_value=("ec2-3-5-140-2.amazonaws.com", [], []))
    def test_ip_lookup_cidr_match_overrides_asn_map(self, mock_ptr, mock_enrich, mock_tor, mock_asn):
        """End-to-end CIDR precedence: even when ASN says Google, a CIDR hit (e.g. AWS) wins.

        Locks in the ordering invariant — a future refactor that swaps the order would fail this test.
        """
        from unittest.mock import MagicMock

        fake_v4 = MagicMock()
        fake_v4.get.return_value = "AWS"  # CIDR trie says AWS
        with patch("domain.ip_intel._refresh_cloud_cache", return_value=(fake_v4, None)):
            r = client.get("/v1/ip/3.5.140.2")
        assert r.status_code == 200
        data = r.json()
        assert data["asn"] == 15169  # asn from RIPE mock — Google
        assert data["cloud_provider"] == "AWS"  # but CIDR wins → AWS


class TestIpLookupPivotHints:
    """Phase 3 cascade: ip_lookup conditional next_calls."""

    def test_ip_pivot_asn_only_when_clean(self):
        """asn populated, no firehol/abuseipdb hit, free tier → just asn_lookup."""
        from domain.routes import _ip_pivot_hints

        hints = _ip_pivot_hints("8.8.8.8", asn=15169, reputation={"firehol": {"listed": False}}, tier="free")
        tools = [h.tool for h in hints]
        assert tools == ["asn_lookup"]
        assert hints[0].input == "8.8.8.8"
        assert "AS15169" in hints[0].reason

    def test_ip_pivot_firehol_listed_adds_ioc(self):
        from domain.routes import _ip_pivot_hints

        hints = _ip_pivot_hints("1.2.3.4", asn=12345, reputation={"firehol": {"listed": True}}, tier="free")
        tools = [h.tool for h in hints]
        assert "ioc_lookup" in tools
        assert "asn_lookup" in tools

    def test_ip_pivot_abuseipdb_high_score_adds_ioc(self):
        from domain.routes import _ip_pivot_hints

        rep = {"firehol": {"listed": False}, "abuseipdb": {"abuse_confidence_score": 75, "status": "ok"}}
        hints = _ip_pivot_hints("1.2.3.4", asn=12345, reputation=rep, tier="free")
        tools = [h.tool for h in hints]
        assert "ioc_lookup" in tools

    def test_ip_pivot_abuseipdb_low_score_no_ioc(self):
        from domain.routes import _ip_pivot_hints

        rep = {"firehol": {"listed": False}, "abuseipdb": {"abuse_confidence_score": 30, "status": "ok"}}
        hints = _ip_pivot_hints("1.2.3.4", asn=12345, reputation=rep, tier="free")
        tools = [h.tool for h in hints]
        assert "ioc_lookup" not in tools

    def test_ip_pivot_pro_adds_threat_report(self):
        from domain.routes import _ip_pivot_hints

        hints = _ip_pivot_hints("1.2.3.4", asn=12345, reputation={"firehol": {"listed": False}}, tier="pro")
        tools = [h.tool for h in hints]
        assert "threat_report" in tools

    def test_ip_pivot_no_asn_no_hint_no_threat(self):
        """No ASN, no rep hits, free tier → empty list (no garbage hints)."""
        from domain.routes import _ip_pivot_hints

        hints = _ip_pivot_hints("0.0.0.1", asn=None, reputation={}, tier="free")
        assert hints == []

    def test_ip_pivot_abuseipdb_pro_only_stub_ignored(self):
        """Free-tier reputation has abuseipdb={status:'pro_only'} stub — must not trigger ioc_lookup."""
        from domain.routes import _ip_pivot_hints

        rep = {"firehol": {"listed": False}, "abuseipdb": {"status": "pro_only"}}
        hints = _ip_pivot_hints("1.2.3.4", asn=12345, reputation=rep, tier="free")
        tools = [h.tool for h in hints]
        assert "ioc_lookup" not in tools


class TestSubdomainPivotHints:
    """Phase 4 cascade: subdomain_enum next_calls capped ssl_check pivots."""

    def test_subdomain_pivot_emits_ssl_check_per_subdomain_capped_at_10(self):
        from domain.routes import _SUBDOMAIN_PIVOT_CAP, _subdomain_pivot_hints

        subs = [f"sub{i}.example.com" for i in range(15)]
        hints = _subdomain_pivot_hints(subs)
        assert len(hints) == _SUBDOMAIN_PIVOT_CAP == 10
        assert all(h.tool == "ssl_check" for h in hints)
        assert [h.input for h in hints] == subs[:10]

    def test_subdomain_pivot_under_cap_emits_all(self):
        from domain.routes import _subdomain_pivot_hints

        subs = ["www.example.com", "api.example.com"]
        hints = _subdomain_pivot_hints(subs)
        assert [h.input for h in hints] == subs

    def test_subdomain_pivot_empty_returns_empty_list(self):
        from domain.routes import _subdomain_pivot_hints

        assert _subdomain_pivot_hints([]) == []
        assert _subdomain_pivot_hints(None) == []  # robust against missing key

    def test_subdomain_pivot_rejects_control_chars_from_ct_logs(self):
        """CT-log SANs are third-party data — a maliciously-issued cert can carry
        newline / tab / 0x7f in name_value. Reject anything that fails RFC 1123
        hostname charset before it reaches PivotHint.reason (where downstream
        renderers could mis-render control bytes as injection)."""
        from domain.routes import _subdomain_pivot_hints

        malicious = [
            "api.example.com",  # legit
            "admin.example.com\nphish.example.com",  # CRLF injection attempt
            "tab\tsub.example.com",  # tab
            "del\x7fsub.example.com",  # DEL
            "lf\nsub.example.com",  # bare LF
            "ok.example.com",  # legit
        ]
        hints = _subdomain_pivot_hints(malicious)
        inputs = [h.input for h in hints]
        assert inputs == ["api.example.com", "ok.example.com"]
        for h in hints:
            assert "\n" not in h.reason
            assert "\t" not in h.reason
            assert "\x7f" not in h.reason

    @patch(
        "domain.routes.enumerate_subdomains",
        return_value={
            "subdomains": [f"s{i}.example.com" for i in range(8)],
            "count": 8,
            "summary": "8 subdomains",
            "found_via_wordlist": 4,
            "found_via_crtsh": 4,
            "sources": ["wordlist", "crtsh"],
            "warnings": [],
            "crtsh_status": "ok",
        },
        new_callable=AsyncMock,
    )
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_subdomains_endpoint_emits_capped_next_calls(self, mock_validate, mock_enum):
        r = client.get("/v1/subdomains/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 8
        next_calls = data.get("next_calls")
        assert next_calls is not None
        # Cap=10 (Action #12), 8 subdomains → all emit (no truncation).
        assert len(next_calls) == 8
        assert all(hint["tool"] == "ssl_check" for hint in next_calls)

    @patch(
        "domain.routes.enumerate_subdomains",
        return_value={
            "subdomains": [f"s{i}.example.com" for i in range(15)],
            "count": 15,
            "summary": "15 subdomains",
            "found_via_wordlist": 5,
            "found_via_crtsh": 10,
            "sources": ["wordlist", "crtsh"],
            "warnings": [],
            "crtsh_status": "ok",
        },
        new_callable=AsyncMock,
    )
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_subdomains_endpoint_cap_truncates_oversize_at_10(self, mock_validate, mock_enum):
        """Cap=10 (Action #12) — 15 subdomains → exactly 10 ssl_check pivots emitted."""
        r = client.get("/v1/subdomains/example.com")
        assert r.status_code == 200
        next_calls = r.json().get("next_calls") or []
        assert len(next_calls) == 10
        # Head-of-list ordering preserved.
        assert [h["input"] for h in next_calls] == [f"s{i}.example.com" for i in range(10)]

    @patch(
        "domain.routes.enumerate_subdomains",
        return_value={
            "subdomains": ["api.example.com"],
            "count": 1,
            "summary": "1 subdomain",
            "found_via_wordlist": 1,
            "found_via_crtsh": 0,
            "sources": ["wordlist"],
            "warnings": [],
            "crtsh_status": "ok",
        },
        new_callable=AsyncMock,
    )
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_subdomains_second_call_served_from_cache(self, mock_validate, mock_enum):
        # Cold call writes to dedicated `subdomains:{domain}` cache.
        r1 = client.get("/v1/subdomains/example.com")
        assert r1.status_code == 200
        # Hot call must NOT re-invoke enumerate_subdomains (which is the expensive
        # DNS-brute + crt.sh path; CT logs alone can take 10s).
        r2 = client.get("/v1/subdomains/example.com")
        assert r2.status_code == 200
        assert r2.json()["count"] == 1
        assert mock_enum.call_count == 1


class TestDnsLookupPivotHints:
    """Batch 2: dns_lookup conditional next_calls (A/AAAA → ssl_check, MX → email_mx)."""

    def test_dns_lookup_pivot_with_a_and_mx_emits_all_four(self):
        from domain.routes import _dns_lookup_pivot_hints

        record = {
            "domain": "example.com",
            "records": {
                "a": ["93.184.216.34"],
                "mx": [{"priority": 10, "host": "mail.example.com"}],
            },
        }
        hints = _dns_lookup_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert tools == ["whois_lookup", "subdomain_enum", "ssl_check", "email_mx"]
        for h in hints:
            assert h.input == "example.com"
            assert h.reason

    def test_dns_lookup_pivot_no_a_drops_ssl_check(self):
        from domain.routes import _dns_lookup_pivot_hints

        record = {"domain": "example.com", "records": {"mx": [{"priority": 10, "host": "x"}]}}
        hints = _dns_lookup_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert "ssl_check" not in tools
        assert "email_mx" in tools
        assert "whois_lookup" in tools
        assert "subdomain_enum" in tools

    def test_dns_lookup_pivot_no_mx_drops_email_mx(self):
        from domain.routes import _dns_lookup_pivot_hints

        record = {"domain": "example.com", "records": {"a": ["93.184.216.34"]}}
        hints = _dns_lookup_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert "email_mx" not in tools
        assert "ssl_check" in tools

    def test_dns_lookup_pivot_neither_a_nor_mx_emits_base_only(self):
        from domain.routes import _dns_lookup_pivot_hints

        record = {"domain": "example.com", "records": {"txt": ["v=spf1 -all"]}}
        hints = _dns_lookup_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert tools == ["whois_lookup", "subdomain_enum"]


class TestWhoisLookupPivotHints:
    """Batch 2: whois_lookup always emits 3 hints (dns_lookup, subdomain_enum, ssl_check)."""

    def test_whois_lookup_pivot_emits_three_fixed_hints(self):
        from domain.routes import _whois_lookup_pivot_hints

        record = {"domain": "example.com", "whois": {"registrar": "Test"}}
        hints = _whois_lookup_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert tools == ["dns_lookup", "subdomain_enum", "ssl_check"]
        for h in hints:
            assert h.input == "example.com"
            assert h.reason


class TestSslCheckPivotHints:
    """Batch 2: ssl_check emits 3 base hints; threat_report is Pro-tier-gated.

    Tests use exact-equality (allowlist) instead of negation-only assertion so any
    future shift in hint composition — e.g. a new Pro-only tool added unconditionally,
    or scan_headers being Pro-gated later — fails the test rather than passing silently.
    """

    FREE_TIER_HINTS = ["tech_fingerprint", "scan_headers", "dns_lookup"]
    PRO_TIER_HINTS = [*FREE_TIER_HINTS, "threat_report"]

    def test_ssl_check_pivot_pro_emits_four_with_threat_report(self):
        from domain.routes import _ssl_check_pivot_hints

        record = {"domain": "example.com", "valid": True, "grade": "A"}
        hints = _ssl_check_pivot_hints(record, tier="pro")
        tools = [h.tool for h in hints]
        assert tools == self.PRO_TIER_HINTS
        for h in hints:
            assert h.input == "example.com"
            assert h.reason

    def test_ssl_check_pivot_free_drops_threat_report(self):
        from domain.routes import _ssl_check_pivot_hints

        record = {"domain": "example.com", "valid": True, "grade": "A"}
        hints = _ssl_check_pivot_hints(record, tier="free")
        tools = [h.tool for h in hints]
        assert tools == self.FREE_TIER_HINTS


class TestTechFingerprintPivotHints:
    """Batch 2: tech_fingerprint always emits 4 hints (scan_headers, ssl_check, seo_audit, robots_txt)."""

    def test_tech_fingerprint_pivot_emits_four_fixed_hints(self):
        from domain.routes import _tech_fingerprint_pivot_hints

        record = {"domain": "example.com", "technologies": [], "count": 0}
        hints = _tech_fingerprint_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert tools == ["scan_headers", "ssl_check", "seo_audit", "robots_txt"]
        for h in hints:
            assert h.input == "example.com"
            assert h.reason


class TestRobotsTxtPivotHints:
    """Batch 3: robots_txt always emits 3 hints (seo_audit, tech_fingerprint, domain_report)."""

    def test_robots_txt_pivot_emits_three_fixed_hints(self):
        from domain.routes import _robots_txt_pivot_hints

        record = {"domain": "example.com", "status_code": 200, "user_agents": {}, "sitemaps": []}
        hints = _robots_txt_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert tools == ["seo_audit", "tech_fingerprint", "domain_report"]
        for h in hints:
            assert h.input == "example.com"
            assert h.reason


class TestRedirectChainPivotHints:
    """Batch 3: redirect_chain conditional next_calls (host extraction + HTTPS + multi-hop)."""

    def test_redirect_chain_https_single_hop(self):
        from domain.routes import _redirect_chain_pivot_hints

        record = {"start_url": "https://example.com/", "final_url": "https://example.com/landing", "hop_count": 1}
        hints = _redirect_chain_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert tools[0] == "ssl_check"
        assert "tech_fingerprint" in tools
        assert "phishing_check" not in tools
        for h in hints:
            assert h.input == "example.com"
            assert h.reason

    def test_redirect_chain_http_no_ssl_check(self):
        from domain.routes import _redirect_chain_pivot_hints

        record = {"start_url": "http://example.com/", "final_url": "http://example.com/landing", "hop_count": 1}
        hints = _redirect_chain_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert "ssl_check" not in tools
        assert "tech_fingerprint" in tools

    def test_redirect_chain_multi_hop_emits_phishing_check(self):
        from domain.routes import _redirect_chain_pivot_hints

        record = {
            "start_url": "https://a.example/",
            "final_url": "https://b.example/landing",
            "hop_count": 3,
        }
        hints = _redirect_chain_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert "phishing_check" in tools

    def test_redirect_chain_unparseable_final_url_returns_empty(self):
        from domain.routes import _redirect_chain_pivot_hints

        record = {"start_url": "https://x/", "final_url": "", "hop_count": 0}
        hints = _redirect_chain_pivot_hints(record)
        assert hints == []


class TestEmailVerifyPivotHints:
    """Batch 3: email_verify conditional next_calls (disposable gating + mx_records gating)."""

    def test_email_verify_trusted_with_mx_emits_three(self):
        from domain.routes import _email_verify_pivot_hints

        record = {
            "domain": "example.com",
            "mx_records": [{"priority": 10, "host": "mail.example.com"}],
            "disposable": False,
        }
        hints = _email_verify_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert "email_disposable" in tools
        assert "email_mx" in tools
        assert "domain_report" in tools
        for h in hints:
            assert h.input == "example.com"
            assert h.reason

    def test_email_verify_disposable_drops_trust_pivots(self):
        from domain.routes import _email_verify_pivot_hints

        record = {
            "domain": "10minutemail.com",
            "mx_records": [{"priority": 10, "host": "mx.10minutemail.com"}],
            "disposable": True,
        }
        hints = _email_verify_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert tools == ["email_disposable"]

    def test_email_verify_no_mx_drops_email_mx(self):
        from domain.routes import _email_verify_pivot_hints

        record = {"domain": "nomx.example", "mx_records": [], "disposable": False}
        hints = _email_verify_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert "email_mx" not in tools
        assert "email_disposable" in tools
        assert "domain_report" in tools

    def test_email_verify_no_domain_returns_empty(self):
        from domain.routes import _email_verify_pivot_hints

        hints = _email_verify_pivot_hints({"domain": ""})
        assert hints == []


class TestBrandAssetsPivotHints:
    """Batch 3: brand_assets always emits 4 hints (seo_audit, tech_fingerprint, ssl_check, scan_headers)."""

    def test_brand_assets_pivot_emits_four_fixed_hints(self):
        from domain.routes import _brand_assets_pivot_hints

        record = {"domain": "example.com", "fetched_url": "https://example.com/", "status_code": 200}
        hints = _brand_assets_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert tools == ["seo_audit", "tech_fingerprint", "ssl_check", "scan_headers"]
        for h in hints:
            assert h.input == "example.com"
            assert h.reason


class TestSeoAuditPivotHints:
    """Batch 3: seo_audit conditional next_calls (score<50 → +brand_assets)."""

    def test_seo_audit_high_score_emits_three(self):
        from domain.routes import _seo_audit_pivot_hints

        record = {"domain": "example.com", "score": 85}
        hints = _seo_audit_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert tools == ["robots_txt", "tech_fingerprint", "scan_headers"]
        for h in hints:
            assert h.input == "example.com"
            assert h.reason

    def test_seo_audit_low_score_appends_brand_assets(self):
        from domain.routes import _seo_audit_pivot_hints

        record = {"domain": "weak.example", "score": 30}
        hints = _seo_audit_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert tools == ["robots_txt", "tech_fingerprint", "scan_headers", "brand_assets"]

    def test_seo_audit_zero_score_appends_brand_assets(self):
        from domain.routes import _seo_audit_pivot_hints

        record = {"domain": "empty.example", "score": 0}
        hints = _seo_audit_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert tools == ["robots_txt", "tech_fingerprint", "scan_headers", "brand_assets"]


class TestEmailMxPivotHints:
    """Batch 3: email_mx always emits 3 hints (email_verify, email_disposable, dns_lookup)."""

    def test_email_mx_pivot_emits_three_fixed_hints(self):
        from domain.routes import _email_mx_pivot_hints

        record = {"domain": "example.com", "mx_records": [], "email_security": {"grade": "F"}}
        hints = _email_mx_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert tools == ["email_verify", "email_disposable", "dns_lookup"]
        for h in hints:
            assert h.input == "example.com"
            assert h.reason


class TestEmailDisposablePivotHints:
    """Batch 3: email_disposable conditional next_calls (disposable=true → empty)."""

    def test_email_disposable_trusted_emits_two(self):
        from domain.routes import _email_disposable_pivot_hints

        record = {"domain": "example.com", "disposable": False}
        hints = _email_disposable_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert tools == ["email_mx", "email_verify"]
        for h in hints:
            assert h.input == "example.com"
            assert h.reason

    def test_email_disposable_disposable_returns_empty(self):
        from domain.routes import _email_disposable_pivot_hints

        record = {"domain": "10minutemail.com", "disposable": True}
        hints = _email_disposable_pivot_hints(record)
        assert hints == []

    def test_email_disposable_no_domain_returns_empty(self):
        from domain.routes import _email_disposable_pivot_hints

        hints = _email_disposable_pivot_hints({"domain": "", "disposable": False})
        assert hints == []


class TestDomainReportTxtFilter:
    _TXT_REPORT = {
        "domain": "example.com",
        "dns": {
            "a": ["93.184.216.34"],
            "ns": ["a.iana-servers.net"],
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
        "whois": MOCK_WHOIS_RESULT,
        "ssl": {"issuer": "DigiCert", "common_name": "example.com"},
        "subdomains": MOCK_SUBDOMAIN_RESULT,
        "certificates": MOCK_CT_RESULT,
        "threat": {
            "urlhaus_status": "clean",
            "url_count": 0,
            "urls_online": 0,
            "threat_types": [],
            "tags": [],
            "urls": [],
        },
        "waf": {"detected": [], "waf_present": False},
        "risk": {"score": 85, "max_score": 100, "grade": "B", "factors": []},
        "summary": "example.com",
    }

    def test_is_security_txt_record_classifier(self):
        from domain.routes import _is_security_txt_record

        for keep in (
            "v=spf1 include:_spf.google.com ~all",
            "v=DMARC1; p=reject;",
            "v=DKIM1; k=rsa; p=...",
            "v=STSv1; id=20240101;",
            "v=TLSRPTv1; rua=mailto:tlsrpt@example.com",
            "  V=SPF1 -all  ",  # case + whitespace tolerant
        ):
            assert _is_security_txt_record(keep), f"expected security record kept: {keep!r}"
        for drop in (
            "google-site-verification=abc123",
            "MS=ms123456",
            "facebook-domain-verification=foo",
            "atlassian-domain-verification=bar",
            "stripe-verification=zzz",
            "",
            None,
            12345,
        ):
            assert not _is_security_txt_record(drop), f"expected non-security record dropped: {drop!r}"

    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age")
    def test_domain_report_txt_filter_default(self, mock_cache, mock_validate, mock_report):
        mock_cache.return_value = (self._TXT_REPORT, 60)
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        dns = r.json()["dns"]
        assert dns["total_txt_records"] == 8
        kept = dns["txt"]
        assert len(kept) == 3
        assert any(t.startswith("v=spf1") for t in kept)
        assert any(t.startswith("v=DMARC1") for t in kept)
        assert any(t.startswith("v=DKIM1") for t in kept)
        for v in kept:
            assert "google-site-verification" not in v
            assert "facebook-domain-verification" not in v

    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age")
    def test_domain_report_txt_include_all(self, mock_cache, mock_validate, mock_report):
        mock_cache.return_value = (self._TXT_REPORT, 60)
        r = client.get("/v1/domain/example.com?include_all_txt=true")
        assert r.status_code == 200
        dns = r.json()["dns"]
        assert dns["total_txt_records"] == 8
        assert len(dns["txt"]) == 8

    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age")
    def test_domain_report_txt_filter_does_not_mutate_cache(self, mock_cache, mock_validate, mock_report):
        # Two calls back-to-back hitting the same cached object — second call must
        # see the original 8-entry list (i.e. filter must copy, not mutate).
        cached_obj = {**self._TXT_REPORT, "dns": dict(self._TXT_REPORT["dns"])}
        cached_obj["dns"]["txt"] = list(self._TXT_REPORT["dns"]["txt"])
        mock_cache.return_value = (cached_obj, 60)

        r1 = client.get("/v1/domain/example.com")
        assert r1.status_code == 200
        assert len(r1.json()["dns"]["txt"]) == 3

        r2 = client.get("/v1/domain/example.com?include_all_txt=true")
        assert r2.status_code == 200
        assert len(r2.json()["dns"]["txt"]) == 8

    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age")
    def test_domain_report_txt_filter_no_txt_section(self, mock_cache, mock_validate, mock_report):
        no_txt = {**self._TXT_REPORT, "dns": {"a": ["93.184.216.34"]}}
        mock_cache.return_value = (no_txt, 60)
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        dns = r.json()["dns"]
        assert "txt" not in dns
        assert "total_txt_records" not in dns

    @patch("domain.routes.full_domain_report", new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age")
    def test_domain_report_txt_filter_empty_txt(self, mock_cache, mock_validate, mock_report):
        empty_txt = {**self._TXT_REPORT, "dns": {"a": ["93.184.216.34"], "txt": []}}
        mock_cache.return_value = (empty_txt, 60)
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        dns = r.json()["dns"]
        assert dns["total_txt_records"] == 0
        assert dns.get("txt") in (None, [])

    @patch(
        "domain.routes.dns_lookup",
        return_value={
            "a": ["1.2.3.4"],
            "txt": ["google-site-verification=xyz", "v=spf1 -all"],
            "total_txt_records": 2,
        },
    )
    @patch("domain.routes.validate_domain", return_value="1.2.3.4")
    @patch("domain.routes._from_cache", return_value=None)
    def test_dns_records_endpoint_keeps_all_txt(self, mock_cache, mock_validate, mock_dns):
        # /v1/dns/{domain} is the explicit raw-DNS endpoint — filter must NOT apply.
        r = client.get("/v1/dns/example.com")
        assert r.status_code == 200
        records = r.json()["records"]
        assert len(records["txt"]) == 2
        assert records["total_txt_records"] == 2

    @patch(
        "domain.routes.dns_lookup",
        return_value={"a": ["1.2.3.4"], "total_txt_records": 0},
    )
    @patch("domain.routes.validate_domain", return_value="1.2.3.4")
    @patch("domain.routes._from_cache", return_value=None)
    def test_dns_records_endpoint_no_txt_emits_zero(self, mock_cache, mock_validate, mock_dns):
        # Honest count: 0 when no TXT records exist — never null on cache miss.
        r = client.get("/v1/dns/example.com")
        assert r.status_code == 200
        records = r.json()["records"]
        assert records["total_txt_records"] == 0
        assert records.get("txt") in (None, [])


@pytest.mark.real_asn_country
class TestFetchAsnCountry:
    """Unit tests for _fetch_asn_country helper — direct mocking of _ripe_client."""

    def test_happy_path_all_three_fields(self):
        from unittest.mock import MagicMock, patch

        def _mock_get(url, params=None, timeout=None):
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if "network-info" in url:
                resp.json.return_value = {"data": {"asns": ["13335"], "prefix": "1.1.1.0/24"}}
            elif "rir-stats-country" in url:
                resp.json.return_value = {"data": {"located_resources": [{"resource": "1.1.1.0/24", "location": "AU"}]}}
            elif "as-overview" in url:
                resp.json.return_value = {"data": {"holder": "CLOUDFLARENET"}}
            return resp

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=_mock_get):
            from domain.routes import _fetch_asn_country

            out = asyncio.run(_fetch_asn_country("198.51.100.1"))
        assert out == {"asn": 13335, "asn_name": "CLOUDFLARENET", "country": "AU", "failed": False}

    def test_network_info_failure_returns_empty(self):
        from unittest.mock import patch

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=Exception("network down")):
            from domain.routes import _fetch_asn_country

            out = asyncio.run(_fetch_asn_country("198.51.100.2"))
        assert out == {"asn": None, "asn_name": "", "country": "", "failed": True}

    def test_country_unknown_sentinel_treated_as_empty(self):
        from unittest.mock import MagicMock, patch

        def _mock_get(url, params=None, timeout=None):
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if "network-info" in url:
                resp.json.return_value = {"data": {"asns": ["13335"]}}
            elif "rir-stats-country" in url:
                resp.json.return_value = {"data": {"located_resources": [{"location": "?"}]}}
            elif "as-overview" in url:
                resp.json.return_value = {"data": {"holder": "CLOUDFLARENET"}}
            return resp

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=_mock_get):
            from domain.routes import _fetch_asn_country

            out = asyncio.run(_fetch_asn_country("198.51.100.3"))
        assert out["asn"] == 13335
        assert out["asn_name"] == "CLOUDFLARENET"
        assert out["country"] == ""  # "?" sentinel normalized
        assert out["failed"] is False  # asn + name present → not failed

    def test_partial_as_overview_failure(self):
        from unittest.mock import MagicMock, patch

        def _mock_get(url, params=None, timeout=None):
            if "as-overview" in url:
                raise Exception("holder lookup failed")
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if "network-info" in url:
                resp.json.return_value = {"data": {"asns": ["13335"]}}
            elif "rir-stats-country" in url:
                resp.json.return_value = {"data": {"located_resources": [{"location": "AU"}]}}
            return resp

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=_mock_get):
            from domain.routes import _fetch_asn_country

            out = asyncio.run(_fetch_asn_country("198.51.100.4"))
        assert out["asn"] == 13335
        assert out["asn_name"] == ""
        assert out["country"] == "AU"
        assert out["failed"] is False

    def test_cache_hit_short_circuits_ripe(self):
        """When asn:{ip} cache is warm, helper skips all outbound RIPE calls."""
        from unittest.mock import patch

        from db import save_cached_domain

        ip = "198.51.100.5"
        save_cached_domain(
            f"asn:{ip}",
            {"asn": 64512, "asn_name": "CACHED-HOLDER", "country": "JP"},
        )
        with patch(
            "domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=AssertionError("should not hit RIPE")
        ):
            from domain.routes import _fetch_asn_country

            out = asyncio.run(_fetch_asn_country(ip))
        assert out["asn"] == 64512
        assert out["asn_name"] == "CACHED-HOLDER"
        assert out["country"] == "JP"
        assert out["failed"] is False

    def test_partial_cache_fills_missing_country_from_ripe(self):
        """Stale asn_lookup cache (asn + name, no country) triggers country-only RIPE fetch."""
        from unittest.mock import MagicMock, patch

        from db import save_cached_domain

        ip = "198.51.100.7"
        save_cached_domain(
            f"asn:{ip}",
            {"asn": 15169, "asn_name": "GOOGLE - Google LLC"},  # country missing
        )

        def _mock_get(url, params=None, timeout=None):
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if "rir-stats-country" in url:
                resp.json.return_value = {"data": {"located_resources": [{"location": "US"}]}}
                return resp
            raise AssertionError(f"should not hit {url} on partial-cache-fill for missing country")

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=_mock_get):
            from domain.routes import _fetch_asn_country

            out = asyncio.run(_fetch_asn_country(ip))
        assert out["asn"] == 15169
        assert out["asn_name"] == "GOOGLE - Google LLC"
        assert out["country"] == "US"
        assert out["failed"] is False

    def test_partial_cache_fills_missing_name_from_ripe(self):
        """Stale cache (asn + country, empty name) triggers as-overview-only RIPE fetch."""
        from unittest.mock import MagicMock, patch

        from db import save_cached_domain

        ip = "198.51.100.8"
        save_cached_domain(
            f"asn:{ip}",
            {"asn": 15169, "asn_name": "", "country": "US"},  # name empty
        )

        def _mock_get(url, params=None, timeout=None):
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if "as-overview" in url:
                resp.json.return_value = {"data": {"holder": "GOOGLE - Google LLC"}}
                return resp
            raise AssertionError(f"should not hit {url} on partial-cache-fill for missing name")

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=_mock_get):
            from domain.routes import _fetch_asn_country

            out = asyncio.run(_fetch_asn_country(ip))
        assert out["asn"] == 15169
        assert out["asn_name"] == "GOOGLE - Google LLC"
        assert out["country"] == "US"
        assert out["failed"] is False

    def test_partial_cache_fills_both_missing_from_ripe(self):
        """Cache has only asn; both name + country refetched in parallel."""
        from unittest.mock import MagicMock, patch

        from db import save_cached_domain

        ip = "198.51.100.9"
        save_cached_domain(f"asn:{ip}", {"asn": 15169})  # only asn

        seen_urls = []

        def _mock_get(url, params=None, timeout=None):
            seen_urls.append(url)
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if "rir-stats-country" in url:
                resp.json.return_value = {"data": {"located_resources": [{"location": "US"}]}}
            elif "as-overview" in url:
                resp.json.return_value = {"data": {"holder": "GOOGLE - Google LLC"}}
            elif "network-info" in url:
                raise AssertionError("network-info should not be called when asn is cached")
            return resp

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=_mock_get):
            from domain.routes import _fetch_asn_country

            out = asyncio.run(_fetch_asn_country(ip))
        assert out["asn"] == 15169
        assert out["asn_name"] == "GOOGLE - Google LLC"
        assert out["country"] == "US"
        assert out["failed"] is False
        assert any("rir-stats-country" in u for u in seen_urls)
        assert any("as-overview" in u for u in seen_urls)

    def test_partial_cache_refill_both_fail_keeps_asn_failed_false(self):
        """When both refills fail but asn is cached, still failed=False (asn is useful data)."""
        from unittest.mock import patch

        from db import save_cached_domain

        ip = "198.51.100.10"
        save_cached_domain(f"asn:{ip}", {"asn": 15169})

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=Exception("RIPE down")):
            from domain.routes import _fetch_asn_country

            out = asyncio.run(_fetch_asn_country(ip))
        assert out["asn"] == 15169
        assert out["asn_name"] == ""
        assert out["country"] == ""
        # asn alone is useful — same honesty rule as cache-miss path
        assert out["failed"] is False

    def test_cache_corrupted_asn_type_ignored(self):
        """Defensive: non-int/out-of-range cached asn is discarded, falls through."""
        from unittest.mock import MagicMock, patch

        from db import save_cached_domain

        ip = "198.51.100.11"
        # String asn (corrupted / hand-written cache entry)
        save_cached_domain(f"asn:{ip}", {"asn": "13335", "asn_name": "X", "country": "US"})

        def _mock_get(url, params=None, timeout=None):
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if "network-info" in url:
                resp.json.return_value = {"data": {"asns": ["13335"]}}
            elif "rir-stats-country" in url:
                resp.json.return_value = {"data": {"located_resources": [{"location": "AU"}]}}
            elif "as-overview" in url:
                resp.json.return_value = {"data": {"holder": "CLOUDFLARENET"}}
            return resp

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=_mock_get):
            from domain.routes import _fetch_asn_country

            out = asyncio.run(_fetch_asn_country(ip))
        # Corrupted entry ignored → cache-miss path, fresh fetch
        assert out["asn"] == 13335
        assert out["asn_name"] == "CLOUDFLARENET"
        assert out["country"] == "AU"
        assert out["failed"] is False

    def test_holder_oversized_string_truncated(self):
        """Defensive cap: hostile/compromised RIPE response with huge holder is truncated."""
        from unittest.mock import MagicMock, patch

        huge = "X" * 5000

        def _mock_get(url, params=None, timeout=None):
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if "network-info" in url:
                resp.json.return_value = {"data": {"asns": ["13335"]}}
            elif "rir-stats-country" in url:
                resp.json.return_value = {"data": {"located_resources": [{"location": "AU"}]}}
            elif "as-overview" in url:
                resp.json.return_value = {"data": {"holder": huge}}
            return resp

        with patch("domain.routes._ripe_client.get", new_callable=AsyncMock, side_effect=_mock_get):
            from domain.routes import _fetch_asn_country

            out = asyncio.run(_fetch_asn_country("198.51.100.6"))
        assert len(out["asn_name"]) == 256
        assert out["asn_name"] == "X" * 256


class TestDomainRoutesBadInput:
    def test_empty_domain_400(self):
        r = client.get("/v1/domain/ ")
        assert r.status_code == 400

    def test_dns_empty_400(self):
        r = client.get("/v1/dns/ ")
        assert r.status_code == 400

    def test_whois_empty_400(self):
        r = client.get("/v1/whois/ ")
        assert r.status_code == 400

    def test_ip_lookup_invalid_ip_400(self):
        r = client.get("/v1/ip/not-an-ip")
        assert r.status_code == 400
        msg = r.json()["error"]["message"]
        assert "not-an-ip" in msg, f"input echo missing: {msg}"

    def test_ip_lookup_private_ip_400(self):
        r = client.get("/v1/ip/127.0.0.1")
        assert r.status_code == 400
        msg = r.json()["error"]["message"]
        assert "127.0.0.1" in msg, f"input echo missing: {msg}"
        assert "Private" in msg or "private" in msg.lower()

    @patch("domain.routes._is_valid_format", return_value=False)
    @patch("domain.routes.validate_domain", return_value=None)
    def test_domain_ssrf_rejected(self, mock_validate, mock_format):
        r = client.get("/v1/dns/internal.evil.com")
        assert r.status_code == 400

    @patch("domain.routes._is_valid_format", return_value=True)
    @patch("domain.routes.validate_domain", return_value=None)
    def test_domain_dns_failure_422(self, mock_validate, mock_format):
        r = client.get("/v1/domain/motomax.com.tr")
        assert r.status_code == 422
        assert "Could not resolve" in r.json()["error"]["message"]


class TestIpEnrichment:
    @patch("domain.recon._http")
    def test_enrichment_success(self, mock_http):
        mock_http.get = AsyncMock(
            return_value=_mock_httpx_response(
                200,
                {
                    "ports": [22, 80, 443],
                    "hostnames": ["example.com"],
                    "vulns": ["CVE-2024-1234"],
                    "cpes": ["cpe:/a:nginx:nginx"],
                    "tags": ["cloud"],
                },
            )
        )

        from domain.recon import ip_enrichment

        result = asyncio.run(ip_enrichment("93.184.216.34"))
        assert result["ports"] == [22, 80, 443]
        assert "CVE-2024-1234" in result["vulns"]
        assert "example.com" in result["hostnames"]

    @patch("domain.recon._http")
    def test_enrichment_failure_graceful(self, mock_http):
        mock_http.get = AsyncMock(side_effect=Exception("timeout"))
        from domain.recon import ip_enrichment

        result = asyncio.run(ip_enrichment("1.2.3.4"))
        assert result["ports"] == []
        assert result["vulns"] == []


class TestDomainScoring:
    def test_perfect_score(self):
        from domain.scoring import score_domain

        report = {
            "ssl": {"grade": "A"},
            "email_security": {"spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject", "dkim_selectors": ["google"]},
            "waf": {"waf_present": True, "detected": ["Cloudflare"]},
            "dns": {"ns": ["ns1.example.com"], "mx": [{"host": "mail.example.com"}], "a": ["1.2.3.4"]},
            "whois": {"registrar": "Example Registrar", "creation_date": "2020-01-01"},
            "subdomains": {"count": 3},
            "certificates": {"total_certificates": 10},
        }
        result = score_domain(report)
        assert result["grade"] == "A"
        assert result["score"] >= 85

    def test_poor_score(self):
        from domain.scoring import score_domain

        report = {
            "ssl": {"error": "SSL lookup failed"},
            "email_security": {},
            "waf": {"waf_present": False},
            "dns": {},
            "whois": {"error": "WHOIS lookup failed"},
            "subdomains": {"count": 50},
            "certificates": {"total_certificates": 0},
        }
        result = score_domain(report)
        assert result["grade"] in ("D", "F")
        assert result["score"] < 40

    def test_grade_boundaries(self):
        from domain.scoring import _score_to_grade

        assert _score_to_grade(100) == "A"
        assert _score_to_grade(85) == "A"
        assert _score_to_grade(70) == "B"
        assert _score_to_grade(55) == "C"
        assert _score_to_grade(40) == "D"
        assert _score_to_grade(20) == "F"

    def test_factors_present(self):
        from domain.scoring import score_domain

        report = {
            "ssl": {"grade": "B"},
            "email_security": {"spf": "v=spf1"},
            "waf": {"waf_present": False},
            "dns": {"a": ["1.2.3.4"]},
            "whois": {},
            "subdomains": {"count": 10},
            "certificates": {"total_certificates": 5},
        }
        result = score_domain(report)
        assert len(result["factors"]) == 9
        assert all("name" in f and "score" in f and "max" in f for f in result["factors"])

    def test_ct_fetch_failure_excludes_factor_from_max(self):
        """When crt.sh upstream fails, CT factor max=0 so domain isn't penalized."""
        from domain.scoring import score_domain

        report = {
            "ssl": {"grade": "A"},
            "email_security": {"spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject", "dkim_selectors": ["google"]},
            "waf": {"waf_present": False},
            "dns": {"ns": ["a.ns"], "mx": [{"host": "m"}], "a": ["1.2.3.4"]},
            "whois": {"registrar": "MarkMonitor", "creation_date": "2007-01-01"},
            "subdomains": {"count": 6},
            "certificates": {"total_certificates": 0, "certificates": [], "error": "crt_sh_timeout"},
        }
        result = score_domain(report)
        ct_factor = next(f for f in result["factors"] if f["name"] == "Certificate Transparency")
        assert ct_factor["max"] == 0, "CT factor must be excluded from max when fetch fails"
        assert "CT logs unavailable" in ct_factor["detail"]
        assert "crt_sh_timeout" in ct_factor["detail"]
        # max_score drops from 100 to 90 (CT 10pt removed)
        assert result["max_score"] == 90
        # Domain with everything else ok should NOT be penalized for our outage
        assert result["grade"] in ("A", "B"), f"got {result['grade']} score={result['score']}/{result['max_score']}"

    _WILDCARD_BASE = {
        "ssl": {"grade": "A"},
        "email_security": {"spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject", "dkim_selectors": ["google"]},
        "waf": {"waf_present": False},
        "dns": {"ns": ["a.ns"], "mx": [{"host": "m"}], "a": ["1.2.3.4"]},
        "whois": {"registrar": "MarkMonitor", "creation_date": "2007-01-01"},
        "certificates": {"total_certificates": 3, "certificates": []},
    }

    def test_wildcard_low_count_excludes_factor_from_max(self):
        """Wildcard + low surviving count: excluding beats awarding a bogus
        'Minimal subdomain exposure' 10/10 to a zone we could not enumerate."""
        from domain.scoring import score_domain

        report = {**self._WILDCARD_BASE, "subdomains": {"count": 3, "wildcard_status": "present"}}
        result = score_domain(report)
        sub_factor = next(f for f in result["factors"] if f["name"] == "Subdomain Exposure")
        assert sub_factor["max"] == 0, "wildcard + low count must exclude the factor from max"
        assert sub_factor["score"] == 0
        assert "Wildcard DNS" in sub_factor["detail"]
        assert "Minimal" not in sub_factor["detail"], "must not award an unmeasurable zone"
        assert result["max_score"] == 90

    def test_wildcard_high_count_still_penalizes_ct_attested_sprawl(self):
        """One-sided: under wildcard the wordlist is already discarded upstream, so a
        high count is CT-attested evidence — a lower bound. Excluding it would let a
        sprawling zone outrank a measured one (monotonicity inversion)."""
        from domain.scoring import score_domain

        report = {**self._WILDCARD_BASE, "subdomains": {"count": 200, "wildcard_status": "present"}}
        result = score_domain(report)
        sub_factor = next(f for f in result["factors"] if f["name"] == "Subdomain Exposure")
        assert sub_factor["max"] == 10, "CT-attested sprawl must stay in the denominator"
        assert sub_factor["score"] == 2
        assert "lower bound" in sub_factor["detail"]
        assert result["max_score"] == 100

    def test_wildcard_undetermined_low_count_excludes_factor_from_max(self):
        """Probe guarded or timed out and nothing much survived — exclude rather than
        award 'Minimal subdomain exposure' for a zone we could not verify."""
        from domain.scoring import score_domain

        report = {**self._WILDCARD_BASE, "subdomains": {"count": 3, "wildcard_status": "undetermined"}}
        result = score_domain(report)
        sub_factor = next(f for f in result["factors"] if f["name"] == "Subdomain Exposure")
        assert sub_factor["max"] == 0
        assert "undetermined" in sub_factor["detail"].lower()
        assert result["max_score"] == 90

    def test_wildcard_undetermined_high_count_still_penalizes(self):
        """Symmetry with 'present': the exclusion is one-sided for BOTH non-absent
        states, so an unverifiable zone cannot upgrade its grade by staying
        unverifiable. Excluding here made 'undetermined' the grade-optimal state for a
        sprawling zone, which any target could reach by dropping our probes."""
        from domain.scoring import score_domain

        report = {**self._WILDCARD_BASE, "subdomains": {"count": 200, "wildcard_status": "undetermined"}}
        result = score_domain(report)
        sub_factor = next(f for f in result["factors"] if f["name"] == "Subdomain Exposure")
        assert sub_factor["max"] == 10, "unverified sprawl must stay in the denominator"
        assert sub_factor["score"] == 2
        assert "lower bound" in sub_factor["detail"]
        assert result["max_score"] == 100

    def test_no_wildcard_keeps_subdomain_threshold_ladder(self):
        """Regression: with wildcard absent the existing threshold ladder is unchanged."""
        from domain.scoring import score_domain

        report = {**self._WILDCARD_BASE, "subdomains": {"count": 30, "wildcard_status": "absent"}}
        result = score_domain(report)
        sub_factor = next(f for f in result["factors"] if f["name"] == "Subdomain Exposure")
        assert sub_factor["max"] == 10
        assert sub_factor["score"] == 4
        assert sub_factor["detail"] == "30 subdomains (high exposure)"

    def test_missing_wildcard_key_defaults_to_absent_ladder(self):
        """Legacy/cached report sections have no wildcard_status — must fall back to
        the ladder, not to an exclusion."""
        from domain.scoring import score_domain

        report = {**self._WILDCARD_BASE, "subdomains": {"count": 30}}
        result = score_domain(report)
        sub_factor = next(f for f in result["factors"] if f["name"] == "Subdomain Exposure")
        assert sub_factor["max"] == 10
        assert result["max_score"] == 100

    @staticmethod
    def _pct(result):
        return round(result["score"] * 100 / result["max_score"])

    def _score_at(self, count, status):
        from domain.scoring import score_domain

        return score_domain({**self._WILDCARD_BASE, "subdomains": {"count": count, "wildcard_status": status}})

    def test_unmeasurable_never_beats_measured_grade_at_same_posture(self):
        """An unmeasurable zone must never outscore the same zone measured. Covers BOTH
        non-absent states — excluding only 'present' left 'undetermined' as a free
        grade upgrade for any target that drops negative-control queries."""
        for status in ("present", "undetermined"):
            for count in (0, 3, 5, 6, 16, 31, 200):
                measured = self._pct(self._score_at(count, "absent"))
                unknown = self._pct(self._score_at(count, status))
                assert unknown <= measured, f"{status} at count={count}: {unknown}% must not beat measured {measured}%"

    def test_more_subdomains_never_improves_grade_within_a_status(self):
        """Count-monotonicity: acquiring another subdomain must never raise the score.
        The exclusion threshold is a cliff, so a mismatched boundary makes count=6
        outscore count=5 in the very branch meant to prevent that."""
        for status in ("absent", "present", "undetermined"):
            pcts = [self._pct(self._score_at(c, status)) for c in (0, 3, 5, 6, 16, 31, 200)]
            for lower, higher in itertools.pairwise(pcts):
                assert higher <= lower, f"status={status}: more subdomains raised the score ({pcts})"

    def test_email_dkim_unverifiable_excludes_5pt_from_max(self):
        """When dkim_status=='unverifiable', email factor max drops 25→20.

        Mirrors email_mx grading honesty: DKIM keys live at operator-chosen
        selector names; absence under common/date-based probes does not prove
        absence, so domain_report must not penalize 5 points for an unverifiable
        signal.
        """
        from domain.scoring import score_domain

        report = {
            "ssl": {"grade": "A"},
            "email_security": {
                "spf": "v=spf1 -all",
                "dmarc": "v=DMARC1; p=reject",
                "dkim_selectors": [],
                "dkim_status": "unverifiable",
            },
            "waf": {"waf_present": True, "detected": ["Cloudflare"]},
            "dns": {"ns": ["a.ns"], "mx": [{"host": "m"}], "a": ["1.2.3.4"]},
            "whois": {"registrar": "MarkMonitor", "creation_date": "2007-01-01"},
            "subdomains": {"count": 3},
            "certificates": {"total_certificates": 5},
        }
        result = score_domain(report)
        email_factor = next(f for f in result["factors"] if f["name"] == "Email Security")
        assert email_factor["score"] == 20  # SPF 10 + DMARC 10
        assert email_factor["max"] == 20, "Unverifiable DKIM must not be in factor max"
        assert "DKIM unverifiable" in email_factor["detail"]
        # Total max_score drops by 5 (25→20 for email factor)
        assert result["max_score"] == 95
        # Domain is full credit on every verifiable factor → grade A
        assert result["grade"] == "A"

    def test_email_dkim_verified_keeps_25pt_max(self):
        """When DKIM is found, email factor max stays at 25 (the legacy ceiling)."""
        from domain.scoring import score_domain

        report = {
            "ssl": {"grade": "A"},
            "email_security": {
                "spf": "v=spf1 -all",
                "dmarc": "v=DMARC1; p=reject",
                "dkim_selectors": ["google"],
                "dkim_status": "verified",
            },
            "waf": {"waf_present": False},
            "dns": {"a": ["1.2.3.4"]},
            "whois": {},
            "subdomains": {"count": 3},
            "certificates": {"total_certificates": 5},
        }
        result = score_domain(report)
        email_factor = next(f for f in result["factors"] if f["name"] == "Email Security")
        assert email_factor["score"] == 25
        assert email_factor["max"] == 25

    def test_ct_zero_certs_when_fetch_succeeded_still_penalizes(self):
        """When crt.sh fetch succeeds but returns 0 certs, CT factor still counts (0/10)."""
        from domain.scoring import score_domain

        report = {
            "ssl": {"grade": "A"},
            "email_security": {"spf": "v=spf1"},
            "waf": {"waf_present": False},
            "dns": {"a": ["1.2.3.4"]},
            "whois": {},
            "subdomains": {"count": 3},
            "certificates": {"total_certificates": 0, "certificates": [], "error": None},
        }
        result = score_domain(report)
        ct_factor = next(f for f in result["factors"] if f["name"] == "Certificate Transparency")
        assert ct_factor["max"] == 10
        assert ct_factor["detail"] == "No CT log entries"
        assert result["max_score"] == 100


class TestStripControlChars:
    """Single canonical helper that drops ASCII control + DEL + Unicode
    replacement char from untrusted upstream strings (DNS TXT / DKIM /
    DMARC / crt.sh). Replaces four ad-hoc errors='replace' passthrough
    sites that previously let `\\x00`, `\\x7f`, RTL overrides, and
    U+FFFD into wire payloads."""

    def test_strips_null_byte(self):
        from domain.recon import _strip_control_chars

        assert _strip_control_chars("v=spf1\x00 -all") == "v=spf1 -all"

    def test_strips_del_byte(self):
        from domain.recon import _strip_control_chars

        assert _strip_control_chars("foo\x7fbar") == "foobar"

    def test_strips_rtl_override_via_replacement_char(self):
        from domain.recon import _strip_control_chars

        # RTL override is U+202E in source; after errors='replace' UTF-8
        # decode it can show up as the U+FFFD replacement character.
        assert _strip_control_chars("subdomain�.example.com") == "subdomain.example.com"

    def test_strips_unicode_bidi_controls(self):
        """Trojan-Source class — bidi controls are >U+0020 so the simple
        `c >= ' '` guard would let them through. Each must be filtered."""
        from domain.recon import _strip_control_chars

        # U+202A LRE, U+202B RLE, U+202C PDF, U+202D LRO, U+202E RLO,
        # U+2066 LRI, U+2067 RLI, U+2068 FSI, U+2069 PDI.
        for codepoint in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069):
            payload = f"v=DKIM1; p=AAA{chr(codepoint)}BBB"
            cleaned = _strip_control_chars(payload)
            assert chr(codepoint) not in cleaned, f"bidi U+{codepoint:04X} survived"
            assert cleaned == "v=DKIM1; p=AAABBB"

    def test_preserves_printable_unicode(self):
        from domain.recon import _strip_control_chars

        assert _strip_control_chars("v=DKIM1; p=ABCD/EFG+1234=") == "v=DKIM1; p=ABCD/EFG+1234="

    def test_strips_tab_and_lf(self):
        from domain.recon import _strip_control_chars

        assert _strip_control_chars("a\tb\nc") == "abc"

    def test_empty_string(self):
        from domain.recon import _strip_control_chars

        assert _strip_control_chars("") == ""


class TestCtLogsErrorPropagation:
    """check_ct_logs surfaces _fetch_crtsh errors so the scorer can detect them."""

    def test_check_ct_logs_propagates_timeout(self):
        from unittest.mock import patch

        from domain.recon import check_ct_logs

        with patch("domain.recon._fetch_crtsh", return_value=([], "crt_sh_timeout")):
            result = asyncio.run(check_ct_logs("example.com"))
        assert result["error"] == "crt_sh_timeout"
        assert result["total_certificates"] == 0
        assert result["crtsh_status"] == "timeout"

    def test_check_ct_logs_clears_error_on_success(self):
        from unittest.mock import patch

        from domain.recon import check_ct_logs

        fake_data = [{"serial_number": "abc", "issuer_name": "X", "common_name": "example.com"}]
        with patch("domain.recon._fetch_crtsh", return_value=(fake_data, None)):
            result = asyncio.run(check_ct_logs("example.com"))
        assert result["error"] is None
        assert result["total_certificates"] == 1
        assert result["crtsh_status"] == "ok"

    def test_check_ct_logs_pre_fetched_error_propagates(self):
        """Bug B3: full_domain_report passes pre-fetched data + crtsh_error so the
        certificates branch is as honest as the subdomains branch — previously
        `error` was always None on this path even when crt.sh had failed."""
        from domain.recon import check_ct_logs

        result = asyncio.run(check_ct_logs("example.com", crtsh_data=[], crtsh_error="crt_sh_unavailable"))
        assert result["error"] == "crt_sh_unavailable"
        assert result["crtsh_status"] == "unavailable"
        assert result["total_certificates"] == 0

    def test_check_ct_logs_pre_fetched_data_no_error_is_ok(self):
        from domain.recon import check_ct_logs

        fake_data = [{"serial_number": "x", "issuer_name": "Y", "common_name": "example.com"}]
        result = asyncio.run(check_ct_logs("example.com", crtsh_data=fake_data, crtsh_error=None))
        assert result["error"] is None
        assert result["crtsh_status"] == "ok"
        assert result["total_certificates"] == 1

    def test_check_ct_logs_status_mirrors_subdomains_for_each_error(self):
        """Pattern parity: every _fetch_crtsh error string maps to the same
        Literal in CertificatesInfo.crtsh_status as in SubdomainsInfo.crtsh_status."""
        from domain.recon import check_ct_logs

        cases = {
            "crt_sh_timeout": "timeout",
            "crt_sh_rate_limited": "rate_limited",
            "crt_sh_unavailable": "unavailable",
            "crt_sh_error": "error",
            "parse_error": "error",
        }
        for fetch_error, expected_status in cases.items():
            result = asyncio.run(check_ct_logs("example.com", crtsh_data=[], crtsh_error=fetch_error))
            assert result["crtsh_status"] == expected_status, fetch_error


class TestSslGrade:
    def test_grade_a_tls13(self):
        from domain.recon import _ssl_grade

        assert _ssl_grade("TLSv1.3", 90) == "A"

    def test_grade_b_tls13_short_expiry(self):
        from domain.recon import _ssl_grade

        assert _ssl_grade("TLSv1.3", 20) == "B"

    def test_grade_c_tls13_very_short(self):
        from domain.recon import _ssl_grade

        assert _ssl_grade("TLSv1.3", 5) == "C"

    def test_grade_b_tls12(self):
        from domain.recon import _ssl_grade

        assert _ssl_grade("TLSv1.2", 90) == "B"

    def test_grade_c_tls12_short(self):
        from domain.recon import _ssl_grade

        assert _ssl_grade("TLSv1.2", 10) == "C"

    def test_grade_f_tls10(self):
        from domain.recon import _ssl_grade

        assert _ssl_grade("TLSv1", 90) == "F"

    def test_grade_f_tls11(self):
        from domain.recon import _ssl_grade

        assert _ssl_grade("TLSv1.1", 90) == "F"

    def test_grade_f_expired(self):
        from domain.recon import _ssl_grade

        assert _ssl_grade("TLSv1.3", -5) == "F"


class TestSslGradeConsistency:
    """Lock contract: /v1/ssl/ and /v1/audit/ must return identical grade for identical (tls_version, days_remaining)."""

    def test_tls13_45days_is_A(self):
        from domain.recon import _ssl_grade

        assert _ssl_grade("TLSv1.3", 45) == "A"

    def test_tls11_is_F(self):
        from domain.recon import _ssl_grade

        assert _ssl_grade("TLSv1.1", 90) == "F"

    def test_tls12_10days_is_C(self):
        from domain.recon import _ssl_grade

        assert _ssl_grade("TLSv1.2", 10) == "C"


class TestEmailSecurity:
    @patch("domain.recon.dns.resolver.Resolver")
    def test_all_present(self, mock_resolver_cls):
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        # DMARC query returns result
        dmarc_rec = MagicMock()
        dmarc_rec.strings = (b"v=DMARC1; p=reject",)
        mock_dmarc = MagicMock()
        mock_dmarc.__iter__ = lambda s: iter([dmarc_rec])
        # DKIM query returns a TXT answer with valid DKIM content (Bug L: content must match)
        rec_dkim = MagicMock()
        rec_dkim.strings = [b"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ"]
        mock_dkim_answer = [rec_dkim]

        def resolve_side_effect(name, rtype):
            if "_dmarc." in name:
                return mock_dmarc
            if "_domainkey." in name:
                return mock_dkim_answer
            raise Exception("unexpected")

        mock_resolver.resolve.side_effect = resolve_side_effect

        from domain.recon import email_security

        result = email_security("example.com", txt_records=["v=spf1 include:_spf.google.com -all"])
        assert result["spf"] is not None
        assert result["dmarc"] is not None
        assert len(result["dkim_selectors"]) > 0
        assert result["grade"] == "A"
        assert len(result["issues"]) == 0

    def test_no_spf(self):
        from domain.recon import email_security

        with patch("domain.recon.dns.resolver.Resolver") as mock_cls:
            mock_resolver = MagicMock()
            mock_cls.return_value = mock_resolver
            mock_resolver.resolve.side_effect = dns.exception.DNSException("no record")
            result = email_security("example.com", txt_records=[])
        assert result["spf"] is None
        assert result["grade"] in ("C", "F")
        assert any("SPF" in i for i in result["issues"])

    def test_spf_detected_from_txt(self):
        from domain.recon import email_security

        with patch("domain.recon.dns.resolver.Resolver") as mock_cls:
            mock_resolver = MagicMock()
            mock_cls.return_value = mock_resolver
            mock_resolver.resolve.side_effect = dns.exception.DNSException("no record")
            result = email_security("example.com", txt_records=["v=spf1 -all", "some other txt"])
        assert result["spf"] == "v=spf1 -all"


class TestDkimParallelDetection:
    """Tests for parallel DKIM selector probing in email_security()."""

    _SPF_TXT = "v=spf1 include:_spf.google.com -all"

    def _mock_dmarc(self):
        inner = MagicMock()
        inner.strings = (b"v=DMARC1; p=reject",)
        rec = MagicMock()
        rec.__iter__ = lambda s: iter([inner])
        return rec

    @staticmethod
    def _mock_dkim_answer(txt_value: bytes = b"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ"):
        """Mock a TXT answer that passes Bug L's DKIM content validation."""
        rec = MagicMock()
        rec.strings = [txt_value]
        return [rec]

    @patch("domain.recon.dns.resolver.Resolver")
    def test_dkim_date_selector_found(self, mock_cls):
        from datetime import datetime, timedelta

        target_selector = (datetime.now() - timedelta(days=1)).strftime("%Y%m%d")

        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver

        def resolve_side_effect(name, rtype):
            if "_dmarc." in name:
                return self._mock_dmarc()
            if f"{target_selector}._domainkey." in name:
                return self._mock_dkim_answer()
            if "_domainkey." in name:
                raise dns.exception.DNSException("NXDOMAIN")
            raise dns.exception.DNSException("unexpected")

        mock_resolver.resolve.side_effect = resolve_side_effect

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[self._SPF_TXT])
        assert target_selector in result["dkim_selectors"]
        assert result["grade"] == "A"

    @patch("domain.recon.dns.resolver.Resolver")
    def test_dkim_named_selector_found(self, mock_cls):
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver

        def resolve_side_effect(name, rtype):
            if "_dmarc." in name:
                return self._mock_dmarc()
            if "google._domainkey." in name:
                return self._mock_dkim_answer()
            if "_domainkey." in name:
                raise dns.exception.DNSException("NXDOMAIN")
            raise dns.exception.DNSException("unexpected")

        mock_resolver.resolve.side_effect = resolve_side_effect

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[self._SPF_TXT])
        assert "google" in result["dkim_selectors"]

    @patch("domain.recon.dns.resolver.Resolver")
    def test_dkim_early_exit_at_3(self, mock_cls):
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver

        # 5 selectors will match — only 3 should be collected
        match_selectors = {"default", "google", "selector1", "k1", "mail"}

        def resolve_side_effect(name, rtype):
            if "_dmarc." in name:
                return self._mock_dmarc()
            if "_domainkey." in name:
                selector = name.split("._domainkey.")[0]
                if selector in match_selectors:
                    return self._mock_dkim_answer()
                raise dns.exception.DNSException("NXDOMAIN")
            raise dns.exception.DNSException("unexpected")

        mock_resolver.resolve.side_effect = resolve_side_effect

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[self._SPF_TXT])
        assert len(result["dkim_selectors"]) == 3
        assert set(result["dkim_selectors"]).issubset(match_selectors)

    @patch("domain.recon.dns.resolver.Resolver")
    def test_dkim_timeout_no_crash(self, mock_cls):
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver

        def resolve_side_effect(name, rtype):
            if "_dmarc." in name:
                return self._mock_dmarc()
            if "_domainkey." in name:
                raise dns.exception.Timeout("timeout")
            raise dns.exception.DNSException("unexpected")

        mock_resolver.resolve.side_effect = resolve_side_effect

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[self._SPF_TXT])
        assert result["dkim_selectors"] == []
        assert result["dkim_status"] == "unverifiable"
        # SPF + DMARC present, DKIM unverifiable → grade A (DKIM absence not penalized)
        assert result["grade"] == "A"
        assert any("DKIM" in i for i in result["issues"])

    @patch("domain.recon.dns.resolver.Resolver")
    def test_dkim_no_selectors_found(self, mock_cls):
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver

        def resolve_side_effect(name, rtype):
            if "_dmarc." in name:
                return self._mock_dmarc()
            if "_domainkey." in name:
                raise dns.resolver.NXDOMAIN("no record")
            raise dns.exception.DNSException("unexpected")

        mock_resolver.resolve.side_effect = resolve_side_effect

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[self._SPF_TXT])
        assert result["dkim_selectors"] == []
        assert result["dkim_status"] == "unverifiable"
        # SPF + DMARC present, DKIM unverifiable → grade A
        assert result["grade"] == "A"
        assert any("DKIM not found under common selectors" in i for i in result["issues"])

    @patch("domain.recon.dns.resolver.Resolver")
    def test_dkim_mixed_results(self, mock_cls):
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver

        from datetime import datetime, timedelta

        today = datetime.now(UTC)
        date_sel = (today - timedelta(days=1)).strftime("%Y%m%d")

        def resolve_side_effect(name, rtype):
            if "_dmarc." in name:
                return self._mock_dmarc()
            if "_domainkey." in name:
                selector = name.split("._domainkey.")[0]
                if selector in ("default", date_sel):
                    return self._mock_dkim_answer()
                raise dns.exception.DNSException("NXDOMAIN")
            raise dns.exception.DNSException("unexpected")

        mock_resolver.resolve.side_effect = resolve_side_effect

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[self._SPF_TXT])
        assert "default" in result["dkim_selectors"]
        assert date_sel in result["dkim_selectors"]
        assert len(result["dkim_selectors"]) == 2


class TestDkimStatusHonesty:
    """DKIM cannot be falsified without selector knowledge — grade must reflect that.

    Pin: when DKIM probe finds nothing, dkim_status='unverifiable' and the letter
    grade is driven only by SPF/DMARC. Domain operators using custom selectors
    must not be penalized for a signal we cannot prove absent.
    """

    _SPF_TXT = "v=spf1 include:_spf.google.com -all"

    def _mock_dmarc(self):
        inner = MagicMock()
        inner.strings = (b"v=DMARC1; p=reject",)
        rec = MagicMock()
        rec.__iter__ = lambda s: iter([inner])
        return rec

    @staticmethod
    def _mock_dkim_answer(txt_value: bytes = b"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ"):
        rec = MagicMock()
        rec.strings = [txt_value]
        return [rec]

    @patch("domain.recon.dns.resolver.Resolver")
    def test_dkim_status_verified_when_selector_found(self, mock_cls):
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver

        def resolve_side_effect(name, rtype):
            if "_dmarc." in name:
                return self._mock_dmarc()
            if "google._domainkey." in name:
                return self._mock_dkim_answer()
            if "_domainkey." in name:
                raise dns.exception.DNSException("NXDOMAIN")
            raise dns.exception.DNSException("unexpected")

        mock_resolver.resolve.side_effect = resolve_side_effect

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[self._SPF_TXT])
        assert result["dkim_status"] == "verified"
        assert result["grade"] == "A"

    @patch("domain.recon.dns.resolver.Resolver")
    def test_dkim_unverifiable_with_spf_dmarc_yields_grade_a(self, mock_cls):
        # Regression: prior versions returned grade=B when DKIM was unverifiable
        # despite SPF + DMARC being present. That penalized custom-selector domains.
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver

        def resolve_side_effect(name, rtype):
            if "_dmarc." in name:
                return self._mock_dmarc()
            if "_domainkey." in name:
                raise dns.resolver.NXDOMAIN("no record")
            raise dns.exception.DNSException("unexpected")

        mock_resolver.resolve.side_effect = resolve_side_effect

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[self._SPF_TXT])
        assert result["dkim_status"] == "unverifiable"
        assert result["grade"] == "A"

    @patch("domain.recon.dns.resolver.Resolver")
    def test_dkim_unverifiable_with_only_spf_yields_grade_b(self, mock_cls):
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver

        def resolve_side_effect(name, rtype):
            # No DMARC, no DKIM
            raise dns.resolver.NXDOMAIN("no record")

        mock_resolver.resolve.side_effect = resolve_side_effect

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[self._SPF_TXT])
        assert result["dkim_status"] == "unverifiable"
        assert result["spf"] is not None
        assert result["dmarc"] is None
        assert result["grade"] == "B"

    @patch("domain.recon.dns.resolver.Resolver")
    def test_dkim_unverifiable_with_neither_spf_nor_dmarc_yields_grade_f(self, mock_cls):
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN("no record")

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[])
        assert result["dkim_status"] == "unverifiable"
        assert result["grade"] == "F"

    @patch("domain.recon.dns.resolver.Resolver")
    def test_dkim_verified_with_only_spf_yields_grade_b(self, mock_cls):
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver

        def resolve_side_effect(name, rtype):
            if "_dmarc." in name:
                raise dns.resolver.NXDOMAIN("no record")
            if "google._domainkey." in name:
                return self._mock_dkim_answer()
            if "_domainkey." in name:
                raise dns.exception.DNSException("NXDOMAIN")
            raise dns.exception.DNSException("unexpected")

        mock_resolver.resolve.side_effect = resolve_side_effect

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[self._SPF_TXT])
        assert result["dkim_status"] == "verified"
        assert result["dmarc"] is None
        assert result["grade"] == "B"

    @patch("domain.recon.dns.resolver.Resolver")
    def test_dkim_unverifiable_issue_message_is_honest(self, mock_cls):
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN("no record")

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[])
        dkim_msgs = [i for i in result["issues"] if "DKIM" in i]
        assert len(dkim_msgs) == 1
        # honest framing: not "no DKIM", but "could not find under probed selectors"
        assert "common selectors" in dkim_msgs[0]
        assert "custom" in dkim_msgs[0].lower()


class TestDkimContentValidation:
    """Bug L: only treat selector as verified when TXT content is DKIM-shaped.

    Pin: a TXT record at `{selector}._domainkey.{domain}` that resolves but
    carries unrelated content (vendor verification strings, wildcards) must
    NOT be reported as DKIM verified — only DKIM-shaped values (v=DKIM1 or p=)
    count.
    """

    _SPF_TXT = "v=spf1 -all"

    def _mock_dmarc(self):
        inner = MagicMock()
        inner.strings = (b"v=DMARC1; p=reject",)
        rec = MagicMock()
        rec.__iter__ = lambda s: iter([inner])
        return rec

    @staticmethod
    def _mock_txt_answer(txt_value: bytes):
        rec = MagicMock()
        rec.strings = [txt_value]
        return [rec]

    @patch("domain.recon.dns.resolver.Resolver")
    def test_dkim1_version_tag_counts_as_verified(self, mock_cls):
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver

        def side_effect(name, rtype):
            if "_dmarc." in name:
                return self._mock_dmarc()
            if "default._domainkey." in name:
                return self._mock_txt_answer(b"v=DKIM1; k=rsa; p=MIGfMA0...")
            raise dns.exception.DNSException("NXDOMAIN")

        mock_resolver.resolve.side_effect = side_effect

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[self._SPF_TXT])
        assert "default" in result["dkim_selectors"]
        assert result["dkim_status"] == "verified"

    @patch("domain.recon.dns.resolver.Resolver")
    def test_p_tag_only_counts_as_verified(self, mock_cls):
        # Some DKIM records omit the v=DKIM1 tag but still carry the mandatory p= public key
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver

        def side_effect(name, rtype):
            if "_dmarc." in name:
                return self._mock_dmarc()
            if "default._domainkey." in name:
                return self._mock_txt_answer(b"k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ")
            raise dns.exception.DNSException("NXDOMAIN")

        mock_resolver.resolve.side_effect = side_effect

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[self._SPF_TXT])
        assert "default" in result["dkim_selectors"]
        assert result["dkim_status"] == "verified"

    @patch("domain.recon.dns.resolver.Resolver")
    def test_unrelated_txt_is_not_verified(self, mock_cls):
        # A TXT at default._domainkey that is clearly not DKIM (e.g. a vendor
        # verification string or a stale CNAME-like record) must not count.
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver

        def side_effect(name, rtype):
            if "_dmarc." in name:
                return self._mock_dmarc()
            if "_domainkey." in name:
                # Same unrelated content for every selector — wildcard scenario
                return self._mock_txt_answer(b"google-site-verification=abc123")
            raise dns.exception.DNSException("unexpected")

        mock_resolver.resolve.side_effect = side_effect

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[self._SPF_TXT])
        assert result["dkim_selectors"] == []
        assert result["dkim_status"] == "unverifiable"

    @patch("domain.recon.dns.resolver.Resolver")
    def test_misplaced_dmarc_at_domainkey_is_not_verified(self, mock_cls):
        # If a domain misconfigures and parks a DMARC record at the DKIM name,
        # the legacy substring check would have matched on 'p=reject'. Reject.
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver

        def side_effect(name, rtype):
            if "_dmarc." in name:
                return self._mock_dmarc()
            if "_domainkey." in name:
                return self._mock_txt_answer(b"v=DMARC1; p=reject; rua=mailto:dmarc@example.com")
            raise dns.exception.DNSException("unexpected")

        mock_resolver.resolve.side_effect = side_effect

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[self._SPF_TXT])
        assert result["dkim_selectors"] == []
        assert result["dkim_status"] == "unverifiable"

    @patch("domain.recon.dns.resolver.Resolver")
    def test_url_with_p_query_param_is_not_verified(self, mock_cls):
        # Vendor verification TXT containing '?p=1' must not be matched by the
        # bare-'p=' branch — the regex requires a tag-list boundary.
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver

        def side_effect(name, rtype):
            if "_dmarc." in name:
                return self._mock_dmarc()
            if "_domainkey." in name:
                return self._mock_txt_answer(b"verification=https://example.com/?p=1")
            raise dns.exception.DNSException("unexpected")

        mock_resolver.resolve.side_effect = side_effect

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[self._SPF_TXT])
        assert result["dkim_selectors"] == []

    @patch("domain.recon.dns.resolver.Resolver")
    def test_mixed_records_only_dkim_counts(self, mock_cls):
        # Multiple TXT records at the selector — only one is DKIM-shaped
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver

        def side_effect(name, rtype):
            if "_dmarc." in name:
                return self._mock_dmarc()
            if "default._domainkey." in name:
                rec_junk = MagicMock()
                rec_junk.strings = [b"some-verification-token"]
                rec_dkim = MagicMock()
                rec_dkim.strings = [b"v=DKIM1; k=rsa; p=MIGf"]
                return [rec_junk, rec_dkim]
            raise dns.exception.DNSException("NXDOMAIN")

        mock_resolver.resolve.side_effect = side_effect

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[self._SPF_TXT])
        assert "default" in result["dkim_selectors"]


class TestOpenApiDomainRoutes:
    def test_openapi_has_domain_operations(self):
        r = client.get("/openapi.json")
        data = r.json()
        operation_ids = set()
        for path_data in data.get("paths", {}).values():
            for method_data in path_data.values():
                if isinstance(method_data, dict) and "operationId" in method_data:
                    operation_ids.add(method_data["operationId"])
        assert "domain_report" in operation_ids
        assert "dns_records" in operation_ids
        assert "whois_lookup" in operation_ids
        assert "subdomain_enum" in operation_ids
        assert "ct_logs" in operation_ids
        assert "ip_lookup" in operation_ids
        assert "threat_intel" in operation_ids
        assert "scan_headers" in operation_ids


# =========== threat.py unit tests ===========


class TestCheckUrlhaus:
    @patch("domain.threat._client")
    def test_clean_domain(self, mock_client):
        from domain.threat import check_urlhaus

        mock_client.post = AsyncMock(return_value=_mock_httpx_response(200, {"query_status": "no_results"}))
        result = asyncio.run(check_urlhaus("clean-example.com"))
        assert result["urlhaus_status"] == "clean"
        assert result["url_count"] == 0

    @patch("domain.threat._client")
    def test_listed_domain(self, mock_client):
        from domain.threat import check_urlhaus

        mock_client.post = AsyncMock(
            return_value=_mock_httpx_response(
                200,
                {
                    "query_status": "ok",
                    "urls": [
                        {
                            "url": "http://bad.com/mal.exe",
                            "url_status": "online",
                            "threat": "malware_download",
                            "date_added": "2026-01-01",
                            "tags": ["elf"],
                        },
                        {
                            "url": "http://bad.com/old.exe",
                            "url_status": "offline",
                            "threat": "malware_download",
                            "date_added": "2025-06-01",
                            "tags": None,
                        },
                    ],
                },
            )
        )
        result = asyncio.run(check_urlhaus("bad.com"))
        assert result["urlhaus_status"] == "listed"
        assert result["url_count"] == 2
        assert result["urls_online"] == 1
        assert "malware_download" in result["threat_types"]
        assert len(result["urls"]) == 2

    @patch("domain.threat._client")
    def test_error_graceful(self, mock_client):
        from domain.threat import check_urlhaus

        mock_client.post = AsyncMock(side_effect=Exception("timeout"))
        result = asyncio.run(check_urlhaus("timeout.com"))
        assert result["urlhaus_status"] == "error"
        assert result["url_count"] == 0


# =========== fetch_live_headers unit tests ===========


class TestFetchLiveHeaders:
    @patch("domain.recon._ssrf_http.get", new_callable=AsyncMock)
    def test_success(self, mock_get):
        from domain.recon import fetch_live_headers

        resp = MagicMock()
        resp.headers = httpx.Headers([("Content-Type", "text/html"), ("X-Frame-Options", "DENY")])
        resp.status_code = 200
        resp.url = httpx.URL("https://example.com/")
        mock_get.return_value = resp
        result = asyncio.run(fetch_live_headers("example.com"))
        assert "headers" in result
        assert result["status_code"] == 200
        assert "x-frame-options" in result["headers"]

    @patch("domain.recon._ssrf_http.get", new_callable=AsyncMock, side_effect=Exception("conn refused"))
    def test_failure(self, mock_get):
        from domain.recon import fetch_live_headers

        result = asyncio.run(fetch_live_headers("unreachable.test"))
        assert "error" in result


# =========== fetch_live_headers sequential (S253 race-and-cancel leak fix) ===========


class TestFetchLiveHeadersSequential:
    """v1.33.12: fetch_live_headers must be sequential HTTPS-first, HTTP-fallback.
    Race-and-cancel pattern leaks _ssrf_http pool slots on cancel-mid-.get().
    Same shape as v1.33.7 fetch_live_page fix."""

    def test_https_success_skips_http(self):
        from domain.recon import fetch_live_headers

        resp = MagicMock()
        resp.headers = httpx.Headers([("Content-Type", "text/html")])
        resp.status_code = 200
        resp.url = httpx.URL("https://example.com/")
        with patch("domain.recon._ssrf_http.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = resp
            result = asyncio.run(fetch_live_headers("example.com"))
        assert "headers" in result
        assert result["status_code"] == 200
        assert mock_get.call_count == 1, (
            f"sequential: HTTPS success must skip HTTP, got call_count={mock_get.call_count}"
        )
        assert "https://" in str(mock_get.call_args.args[0])

    def test_https_fails_falls_back_to_http(self):
        from domain.recon import fetch_live_headers

        http_resp = MagicMock()
        http_resp.headers = httpx.Headers([("Content-Type", "text/html")])
        http_resp.status_code = 200
        http_resp.url = httpx.URL("http://example.com/")
        calls = []

        async def _side_effect(url, **_kw):
            calls.append(str(url))
            if str(url).startswith("https://"):
                raise httpx.ConnectError("HTTPS refused")
            return http_resp

        with patch("domain.recon._ssrf_http.get", side_effect=_side_effect):
            result = asyncio.run(fetch_live_headers("example.com"))
        assert "headers" in result
        assert result["status_code"] == 200
        assert len(calls) == 2, f"expected HTTPS+HTTP fallback, got {calls}"
        assert calls[0].startswith("https://") and calls[1].startswith("http://")

    def test_both_fail_returns_error(self):
        from domain.recon import fetch_live_headers

        with patch("domain.recon._ssrf_http.get", side_effect=httpx.ConnectError("denied")):
            result = asyncio.run(fetch_live_headers("unreachable.test"))
        assert "error" in result


# =========== full_domain_report orphan-task cleanup (S253 amplifier fix) ===========


class TestFullDomainReportOrphanCleanup:
    """v1.33.12: when an early await raises (e.g., f_subs TimeoutError on slow crt.sh),
    full_domain_report MUST cancel all remaining create_task'd tasks via try/finally
    guard. Otherwise tasks orphan, hold pool slots, and re-fire 'Task exception was
    never retrieved' (8x logged in prod 21:31:37)."""

    def test_no_pending_tasks_after_early_failure(self, monkeypatch):
        async def _hang(*_a, **_kw):
            await asyncio.Event().wait()

        async def _quick_crtsh(_q):
            return ([], None)

        async def _fail_enum(*_a, **_kw):
            raise asyncio.TimeoutError("simulated crtsh slowness")

        monkeypatch.setattr("domain.recon.dns_lookup", lambda d: {"a": [], "txt": [], "mx": [], "ns": []})
        monkeypatch.setattr("domain.recon.reverse_dns", lambda d: {"ip": None})
        monkeypatch.setattr("domain.recon.ssl_info", lambda d, ip: {})
        monkeypatch.setattr("domain.recon.whois_lookup", lambda d: {})
        monkeypatch.setattr("domain.recon.email_security", lambda d, txt: {"grade": "F"})
        monkeypatch.setattr("domain.recon._fetch_crtsh", _quick_crtsh)
        monkeypatch.setattr("domain.recon.enumerate_subdomains", _fail_enum)
        monkeypatch.setattr("domain.recon.check_ct_logs", _hang)
        monkeypatch.setattr("domain.threat.check_urlhaus", _hang)
        monkeypatch.setattr("domain.recon.fetch_live_headers", _hang)

        from domain.recon import full_domain_report

        async def _run():
            before = set(asyncio.all_tasks())
            try:
                await full_domain_report("example.com")
            except Exception:
                pass
            await asyncio.sleep(0)  # let cancellation propagate one tick
            after = set(asyncio.all_tasks())
            new = after - before
            return [t for t in new if not t.done()]

        pending = asyncio.run(_run())
        assert not pending, (
            f"orphan tasks not cancelled: {[t.get_name() for t in pending]} "
            f"(coros: {[t.get_coro().__qualname__ for t in pending]})"
        )


class TestCtCrtshInnerTimeoutOrphan:
    """Regression for S253 #1 (113/24h prod orphan logs). When _fetch_crtsh
    is slow enough that the INNER asyncio.wait_for(asyncio.shield(f_crtsh),
    timeout=CRTSH_TIMEOUT+2) times out FIRST, the TimeoutError must be
    caught INSIDE _ct_with_crtsh() and _subs_with_crtsh() so f_certs/f_subs
    complete cleanly with partial results. Pre-fix: TimeoutError propagates
    to f_certs task, outer wait_for at line ~1488 fails the whole report,
    and asyncio logs 'Task exception was never retrieved'."""

    def test_inner_crtsh_timeout_returns_partial_certificates(self, monkeypatch):
        async def _hang_crtsh(_q):
            await asyncio.Event().wait()
            return ([], None)

        async def _ok_threat(*_a, **_kw):
            return {
                "urlhaus_status": "ok",
                "url_count": 0,
                "urls_online": 0,
                "threat_types": [],
                "tags": [],
                "urls": [],
            }

        async def _ok_headers(*_a, **_kw):
            return {"headers": {}, "status": 200}

        monkeypatch.setattr("domain.recon.CRTSH_TIMEOUT", 0)
        monkeypatch.setattr("domain.recon.dns_lookup", lambda d: {"a": [], "txt": [], "mx": [], "ns": []})
        monkeypatch.setattr("domain.recon.reverse_dns", lambda d: {"ip": None})
        monkeypatch.setattr("domain.recon.ssl_info", lambda d, ip: {})
        monkeypatch.setattr("domain.recon.whois_lookup", lambda d: {})
        monkeypatch.setattr("domain.recon.email_security", lambda d, txt: {"grade": "F"})
        monkeypatch.setattr("domain.recon._fetch_crtsh", _hang_crtsh)
        monkeypatch.setattr("domain.recon.fetch_live_headers", _ok_headers)
        monkeypatch.setattr("domain.threat.check_urlhaus", _ok_threat)

        from domain.recon import full_domain_report

        result = asyncio.run(full_domain_report("example.com"))

        assert result["certificates"]["error"] == "crt_sh_timeout"
        assert result["certificates"]["crtsh_status"] == "timeout"
        assert result["certificates"]["total_certificates"] == 0
        assert result["subdomains"]["crtsh_status"] == "timeout"


# =========== fetch_live_page connection-release (cancel-without-await leak) ===========


class _FakeStreamResp:
    def __init__(self, scheme, exits, *, block):
        self._scheme = scheme
        self._exits = exits
        self._block = block
        self.status_code = 200
        self.url = httpx.URL(f"{scheme}://example.com/")
        self.headers = httpx.Headers([("Content-Type", "text/html")] if block else [("Content-Type", "text/plain")])

    async def aiter_bytes(self):
        if self._block:
            await asyncio.Event().wait()
        for _ in range(0):
            yield b""

    async def aclose(self):
        self._exits.append(self._scheme)


class _FakeSsrf:
    def __init__(self, factory):
        self._factory = factory
        self.sent_urls = []
        self.timeout = httpx.Timeout(5.0, connect=5.0, pool=12.0)

    def build_request(self, method, url, **kw):
        r = MagicMock()
        r.method = method
        r.url = url
        return r

    async def send(self, request, *, stream=False, follow_redirects=False):
        self.sent_urls.append(str(request.url))
        return self._factory(request.method, str(request.url))


def _make_stream(blocking_scheme, exits):
    def _factory(method, url, **kw):
        scheme = "https" if url.startswith("https://") else "http"
        return _FakeStreamResp(scheme, exits, block=(scheme == blocking_scheme))

    return _factory


class TestFetchLivePageSequential:
    def test_https_success_skips_http(self):
        from domain.recon import fetch_live_page

        exits = []
        fake = _FakeSsrf(_make_stream("none", exits))
        with patch("domain.recon._ssrf_http", fake):
            res = asyncio.run(fetch_live_page("example.com"))
        assert "headers" in res
        assert fake.sent_urls and all(u.startswith("https://") for u in fake.sent_urls)
        assert exits == ["https"]

    def test_https_failure_falls_back_to_http(self):
        from domain.recon import fetch_live_page

        exits = []

        def _factory(method, url, **kw):
            if url.startswith("https://"):
                raise httpx.ConnectError("https down")
            return _FakeStreamResp("http", exits, block=False)

        with patch("domain.recon._ssrf_http", _FakeSsrf(_factory)):
            res = asyncio.run(fetch_live_page("example.com"))
        assert "headers" in res
        assert exits == ["http"]

    def test_both_schemes_fail_returns_error(self):
        from domain.recon import fetch_live_page

        def _factory(method, url, **kw):
            raise httpx.ConnectError("down")

        with patch("domain.recon._ssrf_http", _FakeSsrf(_factory)):
            res = asyncio.run(fetch_live_page("example.com"))
        assert res == {"error": "Could not connect to example.com"}


class TestSsrfHttpPoolTimeout:
    def test_pool_timeout_is_explicit(self):
        from domain.recon import _ssrf_http

        assert _ssrf_http.timeout.pool == 12.0
        assert _ssrf_http.timeout.connect == 5.0


# =========== scoring threat factor tests ===========


class TestThreatScoring:
    def test_no_threat_no_penalty(self):
        from domain.scoring import score_domain

        report = {
            "ssl": {"grade": "A"},
            "email_security": {"spf": True, "dmarc": True, "dkim_selectors": ["default"]},
            "waf": {"waf_present": True, "detected": ["cloudflare"]},
            "dns": {"ns": ["ns1"], "mx": ["mx1"], "a": ["1.2.3.4"]},
            "whois": {"registrar": "Test"},
            "subdomains": {"count": 3},
            "certificates": {"total_certificates": 5},
            "threat": {"url_count": 0, "urls_online": 0},
        }
        result = score_domain(report)
        threat_factor = [f for f in result["factors"] if f["name"] == "Threat Intelligence"][0]
        assert threat_factor["score"] == 0

    def test_active_threat_penalty(self):
        from domain.scoring import score_domain

        report = {
            "ssl": {"grade": "A"},
            "email_security": {"spf": True, "dmarc": True, "dkim_selectors": ["default"]},
            "waf": {"waf_present": True, "detected": ["cloudflare"]},
            "dns": {"ns": ["ns1"], "mx": ["mx1"], "a": ["1.2.3.4"]},
            "whois": {"registrar": "Test"},
            "subdomains": {"count": 3},
            "certificates": {"total_certificates": 5},
            "threat": {"url_count": 5, "urls_online": 2},
        }
        result = score_domain(report)
        threat_factor = [f for f in result["factors"] if f["name"] == "Threat Intelligence"][0]
        assert threat_factor["score"] < 0

    def test_historic_threat_small_penalty(self):
        from domain.scoring import score_domain

        report = {
            "ssl": {"grade": "A"},
            "email_security": {"spf": True, "dmarc": True, "dkim_selectors": ["default"]},
            "waf": {"waf_present": True, "detected": ["cloudflare"]},
            "dns": {"ns": ["ns1"], "mx": ["mx1"], "a": ["1.2.3.4"]},
            "whois": {"registrar": "Test"},
            "subdomains": {"count": 3},
            "certificates": {"total_certificates": 5},
            "threat": {"url_count": 3, "urls_online": 0},
        }
        result = score_domain(report)
        threat_factor = [f for f in result["factors"] if f["name"] == "Threat Intelligence"][0]
        assert -5 <= threat_factor["score"] < 0


# =========== reputation.py unit tests ===========


def _mock_httpx_response(status_code=200, json_data=None):
    """Helper to create a mock httpx response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.raise_for_status.return_value = None
    if status_code >= 400:
        import httpx

        resp.raise_for_status.side_effect = httpx.HTTPStatusError("error", request=MagicMock(), response=resp)
    return resp


class TestReputation:
    @patch("domain.reputation._client")
    @patch("config.settings.abuseipdb_api_key", "test-key")
    def test_abuseipdb_success(self, mock_client):
        from domain.reputation import check_abuseipdb

        mock_client.get = AsyncMock(
            return_value=_mock_httpx_response(
                200,
                {
                    "data": {
                        "abuseConfidenceScore": 85,
                        "totalReports": 50,
                        "countryCode": "DE",
                        "isp": "Test ISP",
                        "usageType": "Hosting",
                        "isTor": False,
                    }
                },
            )
        )
        result = asyncio.run(check_abuseipdb("1.2.3.4"))
        assert result["status"] == "ok"
        assert result["abuse_score"] == 85
        assert result["total_reports"] == 50
        assert result["country"] == "DE"
        assert result["isp"] == "Test ISP"
        assert result["is_tor"] is False

    @patch("config.settings.abuseipdb_api_key", "")
    def test_abuseipdb_no_key(self):
        from domain.reputation import check_abuseipdb

        result = asyncio.run(check_abuseipdb("1.2.3.4"))
        assert result["status"] == "skipped"

    @patch("domain.reputation._client")
    @patch("config.settings.abuseipdb_api_key", "test-key")
    def test_abuseipdb_error(self, mock_client):
        from domain.reputation import check_abuseipdb

        mock_client.get = AsyncMock(side_effect=httpx.RequestError("connection refused"))
        result = asyncio.run(check_abuseipdb("1.2.3.4"))
        assert result["status"] == "error"

    @patch("domain.reputation._client")
    @patch("config.settings.shodan_api_key", "test-key")
    def test_shodan_success(self, mock_client):
        from domain.reputation import check_shodan

        mock_client.get = AsyncMock(
            return_value=_mock_httpx_response(
                200,
                {
                    "os": "Linux",
                    "org": "Example Corp",
                    "isp": "Test ISP",
                    "asn": "AS12345",
                    "ports": [22, 80, 443],
                    "vulns": {"CVE-2024-1111": {}, "CVE-2024-2222": {}},
                    "hostnames": ["example.com"],
                    "city": "Berlin",
                    "country_name": "Germany",
                    "last_update": "2026-03-01",
                },
            )
        )
        result = asyncio.run(check_shodan("1.2.3.4"))
        assert result["status"] == "ok"
        assert result["ports"] == [22, 80, 443]
        assert result["org"] == "Example Corp"
        assert "CVE-2024-1111" in result["vulns"]
        assert result["hostnames"] == ["example.com"]

    @patch("config.settings.shodan_api_key", "")
    def test_shodan_no_key(self):
        from domain.reputation import check_shodan

        result = asyncio.run(check_shodan("1.2.3.4"))
        assert result["status"] == "skipped"

    @patch("domain.reputation._client")
    @patch("config.settings.shodan_api_key", "test-key")
    def test_shodan_403(self, mock_client):
        from domain.reputation import check_shodan

        mock_client.get = AsyncMock(return_value=_mock_httpx_response(403))
        result = asyncio.run(check_shodan("1.2.3.4"))
        assert result["status"] == "restricted"

    @patch("domain.reputation._client")
    @patch("config.settings.shodan_api_key", "test-key")
    def test_shodan_error(self, mock_client):
        from domain.reputation import check_shodan

        mock_client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        result = asyncio.run(check_shodan("1.2.3.4"))
        assert result["status"] == "error"


# =========== scoring.py reputation penalty tests ===========

# Base report with perfect scores (used as template for reputation scoring tests)
_BASE_REPORT = {
    "ssl": {"grade": "A"},
    "email_security": {"spf": True, "dmarc": True, "dkim_selectors": ["default"]},
    "waf": {"waf_present": True, "detected": ["cloudflare"]},
    "dns": {"ns": ["ns1"], "mx": ["mx1"], "a": ["1.2.3.4"]},
    "whois": {"registrar": "Test"},
    "subdomains": {"count": 3},
    "certificates": {"total_certificates": 5},
    "threat": {"url_count": 0, "urls_online": 0},
}


def _report_with_reputation(reputation: dict) -> dict:
    return {**_BASE_REPORT, "reputation": reputation}


def _get_rep_factor(result: dict) -> dict | None:
    factors = [f for f in result["factors"] if f["name"] == "IP Reputation"]
    return factors[0] if factors else None


class TestReputationScoring:
    def test_no_reputation_no_penalty(self):
        from domain.scoring import score_domain

        result = score_domain({**_BASE_REPORT})
        factor = _get_rep_factor(result)
        assert factor is not None
        assert factor["score"] == 0
        assert factor["detail"] == "Reputation data unavailable"

    def test_abuseipdb_high_penalty(self):
        from domain.scoring import score_domain

        report = _report_with_reputation(
            {
                "abuseipdb": {"status": "ok", "abuse_score": 90},
                "shodan": {"status": "ok"},
            }
        )
        result = score_domain(report)
        factor = _get_rep_factor(result)
        assert factor["score"] == -10

    def test_abuseipdb_moderate_penalty(self):
        from domain.scoring import score_domain

        report = _report_with_reputation(
            {
                "abuseipdb": {"status": "ok", "abuse_score": 50},
                "shodan": {"status": "ok"},
            }
        )
        result = score_domain(report)
        factor = _get_rep_factor(result)
        assert factor["score"] == -5

    def test_combined_penalty_capped(self):
        from domain.scoring import score_domain

        report = _report_with_reputation(
            {
                "abuseipdb": {"status": "ok", "abuse_score": 90},
                "shodan": {"status": "ok"},
            }
        )
        result = score_domain(report)
        factor = _get_rep_factor(result)
        # 10 (abuse score 90) — no GreyNoise anymore
        assert factor["score"] == -10

    def test_clean_reputation_no_penalty(self):
        from domain.scoring import score_domain

        report = _report_with_reputation(
            {
                "abuseipdb": {"status": "ok", "abuse_score": 0},
                "shodan": {"status": "ok"},
            }
        )
        result = score_domain(report)
        factor = _get_rep_factor(result)
        assert factor["score"] == 0


# =========== full_domain_report unit tests ===========


class TestFullDomainReport:
    """Unit tests for full_domain_report — all sub-functions mocked."""

    @patch("domain.scoring.score_domain")
    @patch("domain.recon.fetch_live_headers", new_callable=AsyncMock)
    @patch("domain.recon.email_security")
    @patch("domain.threat.check_urlhaus", new_callable=AsyncMock)
    @patch("domain.recon.check_ct_logs", new_callable=AsyncMock)
    @patch("domain.recon.enumerate_subdomains", new_callable=AsyncMock)
    @patch("domain.recon._fetch_crtsh", return_value=([], None), new_callable=AsyncMock)
    @patch("domain.recon.ssl_info")
    @patch("domain.recon.whois_lookup")
    @patch("domain.recon.reverse_dns")
    @patch("domain.recon.dns_lookup")
    def test_data_assembly(
        self, m_dns, m_rdns, m_whois, m_ssl, m_crtsh, m_subs, m_ct, m_threat, m_email, m_headers, m_score
    ):
        from domain.recon import full_domain_report

        m_dns.return_value = {"a": ["1.2.3.4"]}
        m_rdns.return_value = {"ip": "1.2.3.4", "ptr": "host.example.com"}
        m_whois.return_value = {"registrar": "Reg Inc."}
        m_ssl.return_value = {"issuer": "LE", "grade": "A"}
        m_subs.return_value = {"subdomains": ["www.example.com"], "count": 1}
        m_ct.return_value = {"total_certificates": 2, "certificates": []}
        m_threat.return_value = {"url_count": 0, "urls_online": 0}
        m_email.return_value = {"grade": "B"}
        m_headers.return_value = {"headers": {"server": "nginx"}}
        m_score.return_value = {"grade": "A", "score": 90, "max_score": 100, "factors": []}

        result = asyncio.run(full_domain_report("example.com", resolved_ip="1.2.3.4", client_ip="10.0.0.1"))
        assert result["domain"] == "example.com"
        assert result["dns"] == {"a": ["1.2.3.4"]}
        assert result["whois"]["registrar"] == "Reg Inc."
        assert result["ssl"]["grade"] == "A"
        assert result["subdomains"]["count"] == 1
        assert "summary" in result

    @patch("domain.scoring.score_domain", return_value={"grade": "B", "score": 70, "max_score": 100, "factors": []})
    @patch("domain.recon.fetch_live_headers", new_callable=AsyncMock, return_value={"headers": {}})
    @patch("domain.recon.email_security", return_value={"grade": "C"})
    @patch("domain.threat.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}, new_callable=AsyncMock)
    @patch(
        "domain.recon.check_ct_logs", return_value={"total_certificates": 0, "certificates": []}, new_callable=AsyncMock
    )
    @patch("domain.recon.enumerate_subdomains", return_value={"subdomains": [], "count": 0}, new_callable=AsyncMock)
    @patch("domain.recon._fetch_crtsh", return_value=([], None), new_callable=AsyncMock)
    @patch("domain.recon.ssl_info", return_value={"issuer": "LE", "grade": "B"})
    @patch("domain.recon.whois_lookup", return_value={})
    @patch("domain.recon.reverse_dns", return_value={"ip": "1.2.3.4", "ptr": None})
    @patch("domain.recon.dns_lookup", return_value={"a": ["1.2.3.4"]})
    @patch("domain.recon.ratelimit")
    @patch("db.get_cached_ip", return_value=None)
    def test_reputation_gating_no_quota(
        self,
        m_cache_ip,
        m_rl,
        m_dns,
        m_rdns,
        m_whois,
        m_ssl,
        m_crtsh,
        m_subs,
        m_ct,
        m_threat,
        m_email,
        m_headers,
        m_score,
    ):
        """Free tier always gets pro_only stub regardless of quota."""
        from domain.recon import full_domain_report

        m_rl.check_limit.return_value = False
        result = asyncio.run(
            full_domain_report("example.com", resolved_ip="1.2.3.4", client_ip="10.0.0.1", tier="free")
        )
        assert result["reputation"]["abuseipdb"]["status"] == "pro_only"
        assert result["reputation"]["shodan"]["status"] == "pro_only"

    @patch("domain.scoring.score_domain", return_value={"grade": "A", "score": 90, "max_score": 100, "factors": []})
    @patch("domain.recon.fetch_live_headers", new_callable=AsyncMock, return_value={"headers": {}})
    @patch("domain.recon.email_security", return_value={"grade": "A"})
    @patch("domain.threat.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}, new_callable=AsyncMock)
    @patch(
        "domain.recon.check_ct_logs", return_value={"total_certificates": 0, "certificates": []}, new_callable=AsyncMock
    )
    @patch("domain.recon.enumerate_subdomains", return_value={"subdomains": [], "count": 0}, new_callable=AsyncMock)
    @patch("domain.recon._fetch_crtsh", return_value=([], None), new_callable=AsyncMock)
    @patch("domain.recon.ssl_info", return_value={"issuer": "LE", "grade": "A"})
    @patch("domain.recon.whois_lookup", return_value={})
    @patch("domain.recon.reverse_dns", return_value={"ip": "1.2.3.4", "ptr": None})
    @patch("domain.recon.dns_lookup", return_value={"a": ["1.2.3.4"]})
    @patch("domain.recon.ratelimit")
    @patch("db.save_cached_ip")
    @patch("db.get_cached_ip", return_value=None)
    @patch("domain.reputation.check_shodan", side_effect=Exception("timeout"), new_callable=AsyncMock)
    @patch("domain.reputation.check_abuseipdb", return_value={"status": "ok"}, new_callable=AsyncMock)
    def test_reputation_failure_refunds(
        self,
        m_ab,
        m_sh,
        m_cache_ip,
        m_save_ip,
        m_rl,
        m_dns,
        m_rdns,
        m_whois,
        m_ssl,
        m_crtsh,
        m_subs,
        m_ct,
        m_threat,
        m_email,
        m_headers,
        m_score,
    ):
        """Pro tier: on reputation failure, rate limit quota is refunded."""
        from db import hash_client_ip
        from domain.recon import full_domain_report

        m_rl.check_limit.return_value = True
        m_rl.arefund = AsyncMock()
        result = asyncio.run(full_domain_report("example.com", resolved_ip="1.2.3.4", client_ip="10.0.0.1", tier="pro"))
        m_rl.arefund.assert_called_once_with("enrichment", hash_client_ip("10.0.0.1"))
        assert "reputation" not in result

    @patch("domain.scoring.score_domain")
    @patch("domain.recon.fetch_live_headers", new_callable=AsyncMock)
    @patch("domain.recon.email_security", return_value={"grade": "A"})
    @patch("domain.threat.check_urlhaus", return_value={"url_count": 3, "urls_online": 1}, new_callable=AsyncMock)
    @patch(
        "domain.recon.check_ct_logs", return_value={"total_certificates": 0, "certificates": []}, new_callable=AsyncMock
    )
    @patch(
        "domain.recon.enumerate_subdomains",
        return_value={"subdomains": ["a.example.com", "b.example.com"], "count": 2},
        new_callable=AsyncMock,
    )
    @patch("domain.recon._fetch_crtsh", return_value=([], None), new_callable=AsyncMock)
    @patch("domain.recon.ssl_info", return_value={"issuer": "DigiCert", "grade": "B"})
    @patch("domain.recon.whois_lookup", return_value={})
    @patch("domain.recon.reverse_dns", return_value={"ip": "5.5.5.5", "ptr": None})
    @patch("domain.recon.dns_lookup", return_value={"a": ["5.5.5.5"]})
    def test_summary_contains_key_info(
        self, m_dns, m_rdns, m_whois, m_ssl, m_crtsh, m_subs, m_ct, m_threat, m_email, m_headers, m_score
    ):
        from domain.recon import full_domain_report

        m_headers.return_value = {"headers": {"server": "cloudflare"}}
        m_score.return_value = {"grade": "C", "score": 55, "max_score": 100, "factors": []}
        result = asyncio.run(full_domain_report("example.com", resolved_ip="5.5.5.5"))
        summary = result["summary"]
        assert "example.com" in summary
        assert "5.5.5.5" in summary
        assert "2 subdomains" in summary
        assert "URLhaus" in summary


# =========== ssl_info unit tests ===========


def _build_ssl_test_cert(
    common_name: str = "example.com",
    san: list[str] | None = None,
    days_until_expiry: int = 365,
    issuer_org: str = "Let's Encrypt",
) -> bytes:
    """Build a self-signed cert and return DER bytes (used by ssl_info tests)."""
    import datetime as _dt

    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _dt.datetime.now(_dt.UTC)
    san_names = san if san is not None else [common_name, f"www.{common_name}"]
    cert = (
        _x509.CertificateBuilder()
        .subject_name(_x509.Name([_x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(_x509.Name([_x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org)]))
        .public_key(key.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=30))
        .not_valid_after(now + _dt.timedelta(days=days_until_expiry))
        .add_extension(
            _x509.SubjectAlternativeName([_x509.DNSName(name) for name in san_names]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _make_ssl_mock_ssock(
    cert_der: bytes,
    tls_version: str = "TLSv1.3",
    alpn: str = "h2",
):
    """Build a mock TLS-wrapped socket that returns the given DER on getpeercert(binary_form=True)."""
    mock_ssock = MagicMock()
    mock_ssock.getpeercert.side_effect = lambda binary_form=False: cert_der if binary_form else {}
    mock_ssock.selected_alpn_protocol.return_value = alpn
    mock_ssock.version.return_value = tls_version
    mock_ssock.__enter__ = lambda s: s
    mock_ssock.__exit__ = MagicMock(return_value=False)
    return mock_ssock


def _make_ssl_verified_ctx(mock_ssock):
    """Verified context that returns a passing mock ssock (cert_valid path)."""
    ctx = MagicMock()
    ctx.wrap_socket.return_value = mock_ssock
    return ctx


def _make_ssl_failing_ctx(verify_message: str):
    """Verified context that raises SSLCertVerificationError on wrap_socket (invalid cert path)."""
    ctx = MagicMock()
    err = ssl.SSLCertVerificationError(verify_message)
    err.verify_message = verify_message
    ctx.wrap_socket.side_effect = err
    return ctx


class TestSslInfo:
    def _patch_socket(self, mock_conn):
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock
        return mock_sock

    @patch("domain.recon.ssl.create_default_context")
    @patch("domain.recon.socket.create_connection")
    def test_successful_cert_parsing(self, mock_conn, mock_ctx):
        from domain.recon import ssl_info

        self._patch_socket(mock_conn)
        cert_der = _build_ssl_test_cert(common_name="example.com")
        mock_ssock = _make_ssl_mock_ssock(cert_der)
        mock_ctx.return_value = _make_ssl_verified_ctx(mock_ssock)

        result = ssl_info("example.com", resolved_ip="1.2.3.4")
        assert result["common_name"] == "example.com"
        assert result["issuer"] == "Let's Encrypt"
        assert result["tls_version"] == "TLSv1.3"
        assert result["alpn"] == "h2"
        assert "www.example.com" in result["san"]
        assert result["grade"] == "A"
        assert result["cert_valid"] is True
        assert result["validation_errors"] == []
        assert "error" not in result

    @patch("domain.recon.ssl.create_default_context")
    @patch("domain.recon.socket.create_connection")
    def test_expired_cert_grade_f(self, mock_conn, mock_ctx):
        from domain.recon import ssl_info

        self._patch_socket(mock_conn)
        cert_der = _build_ssl_test_cert(common_name="expired.com", days_until_expiry=-30)
        mock_ssock = _make_ssl_mock_ssock(cert_der)
        # First call (verified) raises with "has expired" message; second call (unverified) succeeds
        mock_ctx.side_effect = [
            _make_ssl_failing_ctx("certificate has expired"),
            _make_ssl_verified_ctx(mock_ssock),
        ]

        result = ssl_info("expired.com")
        assert result["grade"] == "F"
        assert result["days_remaining"] < 0
        assert result["cert_valid"] is False
        assert "expired" in result["validation_errors"]
        # cert details still populated even though invalid
        assert result["common_name"] == "expired.com"
        assert "error" not in result

    @patch("domain.recon.ssl.create_default_context")
    @patch("domain.recon.socket.create_connection")
    def test_self_signed_cert_grade_d(self, mock_conn, mock_ctx):
        from domain.recon import ssl_info

        self._patch_socket(mock_conn)
        cert_der = _build_ssl_test_cert(common_name="self-signed.test")
        mock_ssock = _make_ssl_mock_ssock(cert_der)
        mock_ctx.side_effect = [
            _make_ssl_failing_ctx("self signed certificate"),
            _make_ssl_verified_ctx(mock_ssock),
        ]

        result = ssl_info("self-signed.test")
        assert result["grade"] == "D"
        assert result["cert_valid"] is False
        assert "self_signed" in result["validation_errors"]
        # cert still readable
        assert result["common_name"] == "self-signed.test"

    @patch("domain.recon.ssl.create_default_context")
    @patch("domain.recon.socket.create_connection")
    def test_untrusted_root_grade_d(self, mock_conn, mock_ctx):
        from domain.recon import ssl_info

        self._patch_socket(mock_conn)
        cert_der = _build_ssl_test_cert(common_name="custom-ca.test")
        mock_ssock = _make_ssl_mock_ssock(cert_der)
        mock_ctx.side_effect = [
            _make_ssl_failing_ctx("unable to get local issuer certificate"),
            _make_ssl_verified_ctx(mock_ssock),
        ]

        result = ssl_info("custom-ca.test")
        assert result["grade"] == "D"
        assert result["cert_valid"] is False
        assert "untrusted_root" in result["validation_errors"]

    def test_classify_self_signed_in_chain_is_untrusted_root(self):
        """OpenSSL verify_code 19 ('self signed certificate in certificate chain') is an
        untrusted_root (root in chain not in trust store), NOT a leaf self_signed."""
        from domain.recon import _classify_ssl_verify_error

        # verify_code 19 — chain contains self-signed root (untrusted-root.badssl.com case)
        assert _classify_ssl_verify_error("self signed certificate in certificate chain") == ["untrusted_root"]
        # verify_code 18 — leaf itself is self-signed (self-signed.badssl.com case)
        assert _classify_ssl_verify_error("self signed certificate") == ["self_signed"]
        # verify_code 20 — issuer not locally available
        assert _classify_ssl_verify_error("unable to get local issuer certificate") == ["untrusted_root"]

    @patch("domain.recon.ssl.create_default_context")
    @patch("domain.recon.socket.create_connection")
    def test_hostname_mismatch_grade_d(self, mock_conn, mock_ctx):
        from domain.recon import ssl_info

        self._patch_socket(mock_conn)
        # Cert is for example.com but we ask for wrong.test
        cert_der = _build_ssl_test_cert(common_name="example.com", san=["example.com"])
        mock_ssock = _make_ssl_mock_ssock(cert_der)
        mock_ctx.side_effect = [
            _make_ssl_failing_ctx("hostname 'wrong.test' doesn't match 'example.com'"),
            _make_ssl_verified_ctx(mock_ssock),
        ]

        result = ssl_info("wrong.test")
        assert result["grade"] == "D"
        assert result["cert_valid"] is False
        assert "hostname_mismatch" in result["validation_errors"]

    @patch("domain.recon.socket.create_connection", side_effect=ConnectionRefusedError("refused"))
    def test_connection_refused_returns_error(self, mock_conn):
        from domain.recon import ssl_info

        result = ssl_info("unreachable.test")
        assert result["error"] == "SSL lookup failed"
        assert result["grade"] == "F"
        assert result["cert_valid"] is False
        assert result["validation_errors"] == []

    @patch("domain.recon.socket.create_connection", side_effect=TimeoutError("timeout"))
    def test_timeout_returns_error(self, mock_conn):
        from domain.recon import ssl_info

        result = ssl_info("slow.test")
        assert result["error"] == "SSL lookup failed"
        assert result["grade"] == "F"
        assert result["cert_valid"] is False

    @patch("domain.recon.ssl.create_default_context")
    @patch("domain.recon.socket.create_connection")
    def test_wildcard_san_match(self, mock_conn, mock_ctx):
        """Sanity: wildcard SAN matches a single subdomain label (RFC 6125)."""
        from domain.recon import _hostname_matches

        assert _hostname_matches(["*.example.com"], "", "api.example.com") is True
        assert _hostname_matches(["*.example.com"], "", "deep.api.example.com") is False
        assert _hostname_matches(["*.example.com"], "", "example.com") is False
        assert _hostname_matches([], "example.com", "example.com") is True

    def test_parse_cert_strips_bidi_controls(self):
        """Trojan-Source guard: cert CN/issuer with U+202E (RLO) must be stripped before return.

        Note: cryptography rejects Unicode in DNSName (must be A-label IDN), so SAN bidi
        attack vector is blocked at cert build time. CN and issuer org-name are RFC 4514
        UTF-8 free-form fields where bidi controls can survive into JSON.
        """
        import datetime as _dt

        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        from domain.recon import _parse_cert_der

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = _dt.datetime.now(_dt.UTC)
        cn = "evil‮com.example"  # RLO embedded
        issuer_name = "T‪rust CA"  # LRE embedded
        cert = (
            _x509.CertificateBuilder()
            .subject_name(_x509.Name([_x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(_x509.Name([_x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_name)]))
            .public_key(key.public_key())
            .serial_number(_x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1))
            .not_valid_after(now + _dt.timedelta(days=30))
            .add_extension(_x509.SubjectAlternativeName([_x509.DNSName("example.com")]), critical=False)
            .sign(key, hashes.SHA256())
        )
        parsed = _parse_cert_der(cert.public_bytes(serialization.Encoding.DER))
        assert parsed is not None
        assert "‮" not in parsed["common_name"]
        assert "‪" not in parsed["issuer"]

    def test_parse_cert_san_list_capped(self):
        """Defense: SAN list is capped at 100 entries to bound response size."""
        import datetime as _dt

        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        from domain.recon import _parse_cert_der

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = _dt.datetime.now(_dt.UTC)
        san_names = [_x509.DNSName(f"sub{i}.example.com") for i in range(250)]
        cert = (
            _x509.CertificateBuilder()
            .subject_name(_x509.Name([_x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]))
            .issuer_name(_x509.Name([_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA")]))
            .public_key(key.public_key())
            .serial_number(_x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1))
            .not_valid_after(now + _dt.timedelta(days=30))
            .add_extension(_x509.SubjectAlternativeName(san_names), critical=False)
            .sign(key, hashes.SHA256())
        )
        parsed = _parse_cert_der(cert.public_bytes(serialization.Encoding.DER))
        assert parsed is not None
        assert len(parsed["san"]) == 100


# =========== /v1/scan/headers/{domain} route tests ===========


class TestScanHeadersRoute:
    @patch("codesec.routes.fetch_live_headers", new_callable=AsyncMock)
    @patch("codesec.routes.validate_domain", return_value="93.184.216.34")
    def test_scan_headers_200(self, mock_validate, mock_fetch):
        mock_fetch.return_value = {
            "headers": {"content-type": "text/html", "x-frame-options": "DENY"},
            "status_code": 200,
            "url": "https://example.com/",
        }
        r = client.get("/v1/scan/headers/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "example.com"
        assert data["status_code"] == 200

    @patch("codesec.routes.validate_domain", return_value=None)
    def test_scan_headers_invalid_domain_400(self, mock_validate):
        r = client.get("/v1/scan/headers/not-valid")
        assert r.status_code == 400

    @patch("codesec.routes.fetch_live_headers", new_callable=AsyncMock)
    @patch("codesec.routes.validate_domain", return_value="1.2.3.4")
    def test_scan_headers_connection_failure_504(self, mock_validate, mock_fetch):
        mock_fetch.return_value = {"error": "Could not connect to fail.test"}
        r = client.get("/v1/scan/headers/fail.test")
        assert r.status_code == 504


# =========== enumerate_subdomains unit tests ===========


class TestEnumerateSubdomains:
    @patch("domain.recon._fetch_crtsh", return_value=([{"name_value": "ct.example.com"}], None), new_callable=AsyncMock)
    @patch("domain.recon.socket.gethostbyname")
    def test_dns_brute_and_crtsh_merge(self, mock_resolve, mock_crtsh):
        from domain.recon import enumerate_subdomains

        def gethostbyname_side(fqdn):
            if fqdn == "www.example.com":
                return "93.184.216.34"
            if fqdn == "api.example.com":
                return "93.184.216.35"
            raise socket.gaierror(socket.EAI_NONAME, "not found")

        mock_resolve.side_effect = gethostbyname_side
        result = asyncio.run(enumerate_subdomains("example.com"))
        subs = result["subdomains"]
        assert "www.example.com" in subs
        assert "api.example.com" in subs
        assert "ct.example.com" in subs
        assert result["count"] == 3

    @patch("domain.recon._fetch_crtsh", return_value=([], None), new_callable=AsyncMock)
    @patch("domain.recon.socket.gethostbyname")
    def test_private_ip_filtered(self, mock_resolve, mock_crtsh):
        from domain.recon import enumerate_subdomains

        def gethostbyname_side(fqdn):
            if fqdn == "www.example.com":
                return "192.168.1.1"  # private
            if fqdn == "api.example.com":
                return "8.8.8.8"  # public
            raise socket.gaierror(socket.EAI_NONAME, "not found")

        mock_resolve.side_effect = gethostbyname_side
        result = asyncio.run(enumerate_subdomains("example.com"))
        assert "www.example.com" not in result["subdomains"]
        assert "api.example.com" in result["subdomains"]

    @patch(
        "domain.recon._fetch_crtsh",
        return_value=(
            [
                {"name_value": "www.example.com"},
                {"name_value": "www.example.com"},
            ],
            None,
        ),
        new_callable=AsyncMock,
    )
    @patch("domain.recon.socket.gethostbyname")
    def test_set_deduplication(self, mock_resolve, mock_crtsh):
        from domain.recon import enumerate_subdomains

        def gethostbyname_side(fqdn):
            if fqdn == "www.example.com":
                return "93.184.216.34"
            raise socket.gaierror(socket.EAI_NONAME, "not found")

        mock_resolve.side_effect = gethostbyname_side
        result = asyncio.run(enumerate_subdomains("example.com"))
        assert result["subdomains"].count("www.example.com") == 1


class TestSubdomainWildcardDetection:
    """Wildcard DNS (*.domain) makes DNS brute-force meaningless — every wordlist
    label 'resolves'. Two synthetic negative-control probes detect it, and the result
    is tri-state because a guarded or timed-out probe proves nothing either way."""

    @pytest.mark.asyncio
    async def test_wildcard_present_discards_wordlist_and_flags(self):
        from domain.recon import enumerate_subdomains

        with patch("domain.recon._dns_call_with_timeout", return_value=("93.184.216.34", None)):
            result = await enumerate_subdomains("example.com", crtsh_data=[])
        assert result["wildcard_status"] == "present"
        assert "wildcard_detected" not in result, "tri-state replaces the boolean"
        assert result["found_via_wordlist"] == 0
        assert "wildcard_dns" in result["warnings"]
        assert "wildcard DNS" in result["summary"]

    @pytest.mark.asyncio
    async def test_wildcard_absent_keeps_wordlist(self):
        from domain.recon import enumerate_subdomains

        def _fake(func, *args):
            fqdn = args[0]
            if fqdn.startswith("www."):
                return "93.184.216.34", None
            return None, socket.gaierror(socket.EAI_NONAME, "NXDOMAIN")

        with patch("domain.recon._dns_call_with_timeout", side_effect=_fake):
            result = await enumerate_subdomains("example.com", crtsh_data=[])
        assert result["wildcard_status"] == "absent"
        assert result["found_via_wordlist"] == 1
        assert "www.example.com" in result["subdomains"]
        assert "wildcard_dns" not in result["warnings"]

    @pytest.mark.asyncio
    async def test_two_probes_issued_with_distinct_labels(self):
        from domain.recon import COMMON_SUBDOMAINS, enumerate_subdomains

        seen = []

        def _fake(func, *args):
            seen.append(args[0])
            return None, socket.gaierror(socket.EAI_NONAME, "NXDOMAIN")

        with patch("domain.recon._dns_call_with_timeout", side_effect=_fake):
            await enumerate_subdomains("example.com", crtsh_data=[])
        assert len(seen) == len(COMMON_SUBDOMAINS) + 2, "exactly two extra probe lookups"
        probes = [s for s in seen if not any(s.startswith(f"{c}.") for c in COMMON_SUBDOMAINS)]
        assert len(probes) == 2
        assert probes[0] != probes[1], "one cached answer must not be able to decide both probes"
        for p in probes:
            label = p.split(".")[0]
            assert p.endswith(".example.com")
            assert len(label) <= 63 and label[0].isalpha() and label.isalnum()

    @pytest.mark.asyncio
    async def test_probe_timeout_is_undetermined_not_absent(self):
        """Fail-CLOSED: a timed-out probe must not be read as 'no wildcard'.
        _dns_call_with_timeout returns a sentinel, so timeout and NXDOMAIN arrive
        identically unless the error is inspected."""
        from domain.recon import COMMON_SUBDOMAINS, enumerate_subdomains

        wordlist_prefixes = tuple(f"{c}." for c in COMMON_SUBDOMAINS)

        def _fake(func, *args):
            fqdn = args[0]
            if fqdn.startswith(wordlist_prefixes):
                return None, socket.gaierror(socket.EAI_NONAME, "NXDOMAIN")
            return None, TimeoutError("DNS call timed out")

        with patch("domain.recon._dns_call_with_timeout", side_effect=_fake):
            result = await enumerate_subdomains("example.com", crtsh_data=[])
        assert result["wildcard_status"] == "undetermined"
        assert "wildcard_undetermined" in result["warnings"]
        assert "could not be determined" in result["summary"]
        assert result["found_via_wordlist"] == 0, "an unverified catch-all must not publish wordlist hits"

    @pytest.mark.asyncio
    async def test_oversized_probe_fqdn_is_undetermined_not_absent(self):
        """The 253-octet bypass: a long target made the probe locally invalid, which
        read as 'no wildcard' and restored the fabricated-count bug."""
        from domain.recon import enumerate_subdomains

        long_domain = ".".join(["a" * 59] * 4) + ".com"
        assert 236 <= len(long_domain) <= 249, f"fixture must sit in the bypass window, got {len(long_domain)}"
        with patch("domain.recon._dns_call_with_timeout", return_value=("93.184.216.34", None)) as m:
            result = await enumerate_subdomains(long_domain, crtsh_data=[])
        assert result["wildcard_status"] == "undetermined"
        assert "wildcard_undetermined" in result["warnings"]
        probed = [c.args[1] for c in m.call_args_list]
        assert all(len(p) <= 253 for p in probed), "must not emit a name the resolver rejects locally"

    @pytest.mark.asyncio
    async def test_private_ip_catchall_IS_wildcard(self):
        """An RFC1918 answer to a name that cannot exist still proves a catch-all.
        Private-IP filtering is right for wordlist hits, wrong for the control."""
        from domain.recon import enumerate_subdomains

        with patch("domain.recon._dns_call_with_timeout", return_value=("10.0.0.1", None)):
            result = await enumerate_subdomains("example.com", crtsh_data=[])
        assert result["wildcard_status"] == "present"
        assert result["found_via_wordlist"] == 0


# =========== whois_lookup success path tests ===========


class TestWhoisLookupSuccess:
    @patch("domain.recon.socket.create_connection")
    def test_parsing_integration(self, mock_conn):
        from domain.recon import whois_lookup

        whois_response = (
            b"Registrar: Test Registrar Inc.\r\n"
            b"Creation Date: 2020-05-15T00:00:00Z\r\n"
            b"Registry Expiry Date: 2027-05-15T00:00:00Z\r\n"
            b"Name Server: ns1.example.com\r\n"
            b"Name Server: ns2.example.com\r\n"
        )

        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [whois_response, b""]
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        result = whois_lookup("example.com")
        assert result["registrar"] == "Test Registrar Inc."
        assert "2020-05-15" in result["creation_date"]
        assert len(result["name_servers"]) == 2
        assert result["raw_length"] > 0

    @patch("domain.recon.socket.create_connection")
    def test_32kb_truncation(self, mock_conn):
        from domain.recon import whois_lookup

        # Send > 32KB in chunks to trigger truncation
        big_chunk = b"A" * 33000

        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [big_chunk, b""]
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        result = whois_lookup("example.com")
        # raw_length should be at most around 32KB + one recv chunk overshoot
        assert result["raw_length"] <= 33000


# =========== dns_lookup MX, SOA, TXT record parsing tests ===========


class TestDnsLookupRecordTypes:
    @patch("domain.recon.dns.resolver.Resolver")
    def test_mx_priority_and_host(self, mock_resolver_cls):
        from domain.recon import dns_lookup

        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        mock_mx = MagicMock()
        mock_mx.preference = 10
        mock_mx.exchange = MagicMock()
        mock_mx.exchange.__str__ = lambda s: "mail.example.com."

        def resolve_side(domain, rtype):
            if rtype == "MX":
                return [mock_mx]
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = resolve_side
        result = dns_lookup("example.com")
        assert "mx" in result
        assert result["mx"][0]["priority"] == 10
        assert result["mx"][0]["host"] == "mail.example.com"

    @patch("domain.recon.dns.resolver.Resolver")
    def test_null_mx_filtered(self, mock_resolver_cls):
        # Bug O: RFC 7505 null MX (priority=0, exchange='.') used to leak as
        # {priority: 0, host: ''} into the wire. Drop it — empty mx list is
        # the honest signal that the domain does not accept mail.
        from domain.recon import dns_lookup

        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        null_mx = MagicMock()
        null_mx.preference = 0
        null_mx.exchange = MagicMock()
        null_mx.exchange.__str__ = lambda s: "."

        def resolve_side(domain, rtype):
            if rtype == "MX":
                return [null_mx]
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = resolve_side
        result = dns_lookup("example.com")
        assert result.get("mx") == []
        assert all(r["host"] for r in result.get("mx", []))

    @patch("domain.recon.dns.resolver.Resolver")
    def test_padded_null_mx_filtered(self, mock_resolver_cls):
        # Edge case from R1 review: "  .  " (whitespace-padded null MX).
        # rstrip-then-strip would leak host='.', strip-then-rstrip filters it.
        from domain.recon import dns_lookup

        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        padded = MagicMock()
        padded.preference = 0
        padded.exchange = MagicMock()
        padded.exchange.__str__ = lambda s: "  .  "

        def resolve_side(domain, rtype):
            if rtype == "MX":
                return [padded]
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = resolve_side
        result = dns_lookup("example.com")
        assert result.get("mx") == []

    @patch("domain.recon.dns.resolver.Resolver")
    def test_malformed_mx_empty_host_filtered(self, mock_resolver_cls):
        # Whitespace-only / malformed exchange must also be filtered.
        from domain.recon import dns_lookup

        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        bad_mx = MagicMock()
        bad_mx.preference = 5
        bad_mx.exchange = MagicMock()
        bad_mx.exchange.__str__ = lambda s: "  "

        good_mx = MagicMock()
        good_mx.preference = 10
        good_mx.exchange = MagicMock()
        good_mx.exchange.__str__ = lambda s: "mail.example.com."

        def resolve_side(domain, rtype):
            if rtype == "MX":
                return [bad_mx, good_mx]
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = resolve_side
        result = dns_lookup("example.com")
        # Only the well-formed record survives
        assert len(result["mx"]) == 1
        assert result["mx"][0]["host"] == "mail.example.com"

    @patch("domain.recon.dns.resolver.Resolver")
    def test_soa_fields(self, mock_resolver_cls):
        from domain.recon import dns_lookup

        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        mock_soa = MagicMock()
        mock_soa.mname = MagicMock()
        mock_soa.mname.__str__ = lambda s: "ns1.example.com."
        mock_soa.rname = MagicMock()
        mock_soa.rname.__str__ = lambda s: "admin.example.com."
        mock_soa.serial = 2024010101

        def resolve_side(domain, rtype):
            if rtype == "SOA":
                return [mock_soa]
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = resolve_side
        result = dns_lookup("example.com")
        assert result["soa"]["mname"] == "ns1.example.com"
        assert result["soa"]["rname"] == "admin.example.com"
        assert result["soa"]["serial"] == 2024010101

    @patch("domain.recon.dns.resolver.Resolver")
    def test_txt_stripping(self, mock_resolver_cls):
        from domain.recon import dns_lookup

        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        mock_txt = MagicMock()
        mock_txt.strings = (b"v=spf1 include:_spf.google.com -all",)

        def resolve_side(domain, rtype):
            if rtype == "TXT":
                return [mock_txt]
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = resolve_side
        result = dns_lookup("example.com")
        assert "txt" in result
        assert result["txt"][0] == "v=spf1 include:_spf.google.com -all"

    @patch("domain.recon.dns.resolver.Resolver")
    def test_txt_multistring_chunks_reassembled(self, mock_resolver_cls):
        """RFC 7208: TXT records >255 bytes split into chunks must be joined,
        not left as separate quoted strings. Bug B1: github.com SPF returned
        'ip4:62.253.2" "27.114' instead of 'ip4:62.253.227.114'."""
        from domain.recon import dns_lookup

        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        mock_txt = MagicMock()
        mock_txt.strings = (b"v=spf1 ip4:62.253.2", b"27.114 -all")

        def resolve_side(domain, rtype):
            if rtype == "TXT":
                return [mock_txt]
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = resolve_side
        result = dns_lookup("example.com")
        assert result["txt"][0] == "v=spf1 ip4:62.253.227.114 -all"


# =========== routes.py IP endpoint reputation tests ===========


class TestIpRouteReputation:
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_PRO)
    @patch("db.save_cached_ip")
    @patch("db.get_cached_ip_with_age", return_value=None)
    @patch("domain.routes.ratelimit.check_limit", return_value=True)
    @patch("domain.routes.check_shodan", return_value={"status": "ok", "ports": [80]}, new_callable=AsyncMock)
    @patch("domain.routes.check_abuseipdb", return_value={"status": "ok", "abuse_score": 10}, new_callable=AsyncMock)
    @patch(
        "domain.routes.ip_enrichment",
        return_value={
            "ports": [22, 80],
            "hostnames": [],
            "vulns": [],
            "cpes": [],
            "tags": [],
            "internetdb_status": "ok",
        },
        new_callable=AsyncMock,
    )
    @patch("domain.routes.socket.gethostbyaddr", return_value=("example.com", [], []))
    def test_ip_with_reputation(
        self, mock_ptr, mock_enrich, mock_ab, mock_sh, mock_limit, mock_cache_get, mock_cache_save, mock_auth
    ):
        r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        data = r.json()
        assert "reputation" in data
        assert data["reputation"]["abuseipdb"]["status"] == "ok"
        assert data["reputation"]["shodan"]["status"] == "ok"
        mock_cache_save.assert_called_once()

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    @patch("db.get_cached_ip_with_age", return_value=None)
    @patch("domain.routes.ratelimit.check_limit", return_value=False)
    @patch(
        "domain.routes.ip_enrichment",
        return_value={
            "ports": [22, 80],
            "hostnames": [],
            "vulns": ["CVE-2024-1234"],
            "cpes": [],
            "tags": [],
            "internetdb_status": "ok",
        },
        new_callable=AsyncMock,
    )
    @patch("domain.routes.socket.gethostbyaddr", return_value=("example.com", [], []))
    def test_ip_without_reputation_limit_exceeded(self, mock_ptr, mock_enrich, mock_limit, mock_cache_get, mock_auth):
        """Free tier returns the compact upgrade hint (Bug I4); no live API calls."""
        r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        data = r.json()
        rep = data["reputation"]
        assert rep.get("abuseipdb") is None
        assert rep.get("shodan") is None
        assert "abuseipdb" in rep["upgrade"]["pro_only_sources"]
        assert "shodan" in rep["upgrade"]["pro_only_sources"]
        assert data["ports"] == [22, 80]
        # v1.16.0 Phase 2: vulns is list[VulnInfo dict], not list[str]. ID
        # preserved + severity emitted (UNKNOWN if not in cve.db).
        assert "CVE-2024-1234" in {v["cve_id"] for v in data["vulns"]}

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    @patch("domain.routes.check_abuseipdb", new_callable=AsyncMock)
    @patch("domain.routes.check_shodan", new_callable=AsyncMock)
    @patch(
        "db.get_cached_ip_with_age",
        return_value=(
            {
                "abuseipdb": {"status": "ok", "abuse_score": 0},
                "shodan": {"status": "ok", "ports": [443]},
            },
            1800,
        ),
    )
    @patch(
        "domain.routes.ip_enrichment",
        return_value={"ports": [443], "hostnames": [], "vulns": [], "cpes": [], "tags": [], "internetdb_status": "ok"},
        new_callable=AsyncMock,
    )
    @patch("domain.routes.socket.gethostbyaddr", return_value=("example.com", [], []))
    def test_ip_reputation_from_cache(self, mock_ptr, mock_enrich, mock_cache_get, mock_sh, mock_ab, mock_auth):
        r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        data = r.json()
        assert "reputation" in data
        assert data["reputation"]["abuseipdb"]["abuse_score"] == 0
        # API functions should not have been called
        mock_ab.assert_not_called()
        mock_sh.assert_not_called()


# =========== db.py IP cache tests ===========


class TestIpCache:
    def test_save_and_get(self):
        from db import get_cached_ip, init_cache_db, save_cached_ip

        init_cache_db()
        test_data = {
            "abuseipdb": {"status": "ok", "abuse_score": 5},
        }
        save_cached_ip("10.20.30.40", test_data)
        result = get_cached_ip("10.20.30.40")
        assert result is not None
        assert result["abuseipdb"]["abuse_score"] == 5

    def test_expired_cache_returns_none(self):
        from datetime import datetime, timedelta

        from db import get_cache_db, get_cached_ip, init_cache_db

        init_cache_db()
        # Insert with old timestamp
        old_time = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
        with get_cache_db() as con:
            con.execute(
                "INSERT OR REPLACE INTO ip_cache (ip, result_json, fetched_at) VALUES (?, ?, ?)",
                ("99.99.99.99", json.dumps({"test": True}), old_time),
            )
        result = get_cached_ip("99.99.99.99")
        assert result is None


# =========== scoring boundary tests ===========


class TestReputationScoringBoundary:
    """Test exact boundary values for abuse_score thresholds."""

    def test_abuseipdb_score_24_no_penalty(self):
        from domain.scoring import score_domain

        report = _report_with_reputation(
            {
                "abuseipdb": {"status": "ok", "abuse_score": 24},
                "shodan": {"status": "ok"},
            }
        )
        result = score_domain(report)
        factor = _get_rep_factor(result)
        assert factor["score"] == 0

    def test_abuseipdb_score_25_moderate_penalty(self):
        from domain.scoring import score_domain

        report = _report_with_reputation(
            {
                "abuseipdb": {"status": "ok", "abuse_score": 25},
                "shodan": {"status": "ok"},
            }
        )
        result = score_domain(report)
        factor = _get_rep_factor(result)
        assert factor["score"] == -5

    def test_abuseipdb_score_74_moderate_penalty(self):
        from domain.scoring import score_domain

        report = _report_with_reputation(
            {
                "abuseipdb": {"status": "ok", "abuse_score": 74},
                "shodan": {"status": "ok"},
            }
        )
        result = score_domain(report)
        factor = _get_rep_factor(result)
        assert factor["score"] == -5

    def test_abuseipdb_score_75_high_penalty(self):
        from domain.scoring import score_domain

        report = _report_with_reputation(
            {
                "abuseipdb": {"status": "ok", "abuse_score": 75},
                "shodan": {"status": "ok"},
            }
        )
        result = score_domain(report)
        factor = _get_rep_factor(result)
        assert factor["score"] == -10


# =========== scoring skipped reputation tests ===========


class TestReputationScoringSkipped:
    """Test that skipped/unavailable reputation shows correct message."""

    def test_all_skipped_shows_unavailable(self):
        from domain.scoring import score_domain

        report = _report_with_reputation(
            {
                "abuseipdb": {"status": "skipped", "reason": "no API key"},
                "shodan": {"status": "skipped", "reason": "no API key"},
            }
        )
        result = score_domain(report)
        factor = _get_rep_factor(result)
        assert factor["score"] == 0
        assert "unavailable" in factor["detail"].lower()

    def test_all_error_shows_unavailable(self):
        from domain.scoring import score_domain

        report = _report_with_reputation(
            {
                "abuseipdb": {"status": "error", "reason": "connection failed"},
                "shodan": {"status": "error", "reason": "connection failed"},
            }
        )
        result = score_domain(report)
        factor = _get_rep_factor(result)
        assert factor["score"] == 0
        assert "unavailable" in factor["detail"].lower()

    def test_mixed_skipped_and_ok_clean_shows_no_issues(self):
        from domain.scoring import score_domain

        report = _report_with_reputation(
            {
                "abuseipdb": {"status": "ok", "abuse_score": 0},
                "shodan": {"status": "skipped", "reason": "no API key"},
            }
        )
        result = score_domain(report)
        factor = _get_rep_factor(result)
        assert factor["score"] == 0
        assert "No reputation issues" in factor["detail"]


# =========== reputation 429 rate limit tests ===========


class TestReputationRateLimit:
    """Test HTTP 429 rate limit handling."""

    @patch("domain.reputation._client")
    @patch("config.settings.abuseipdb_api_key", "test-key")
    def test_abuseipdb_429(self, mock_client):
        from domain.reputation import check_abuseipdb

        mock_client.get = AsyncMock(return_value=_mock_httpx_response(429))
        result = asyncio.run(check_abuseipdb("1.2.3.4"))
        assert result["status"] == "rate_limited"

    @patch("domain.reputation._client")
    @patch("config.settings.shodan_api_key", "test-key")
    def test_shodan_429(self, mock_client):
        from domain.reputation import check_shodan

        mock_client.get = AsyncMock(return_value=_mock_httpx_response(429))
        result = asyncio.run(check_shodan("1.2.3.4"))
        assert result["status"] == "rate_limited"


# =========== _ssl_grade edge case tests ===========


class TestSslGradeEdgeCases:
    def test_tls13_no_expiry_gets_a(self):
        from domain.recon import _ssl_grade

        assert _ssl_grade("TLSv1.3", None) == "A"

    def test_tls12_no_expiry_gets_b(self):
        from domain.recon import _ssl_grade

        assert _ssl_grade("TLSv1.2", None) == "B"

    def test_unknown_tls_gets_c(self):
        from domain.recon import _ssl_grade

        assert _ssl_grade("unknown", 90) == "C"

    def test_sslv3_gets_c(self):
        from domain.recon import _ssl_grade

        assert _ssl_grade("SSLv3", 90) == "C"

    def test_tls10_gets_f(self):
        from domain.recon import _ssl_grade

        assert _ssl_grade("TLSv1", 90) == "F"

    def test_tls11_gets_f(self):
        from domain.recon import _ssl_grade

        assert _ssl_grade("TLSv1.1", 90) == "F"

    def test_expired_cert_gets_f(self):
        from domain.recon import _ssl_grade

        assert _ssl_grade("TLSv1.3", -1) == "F"


# =========== _score_to_grade boundary tests ===========


class TestScoreToGradeBoundary:
    def test_84_is_b(self):
        from domain.scoring import _score_to_grade

        assert _score_to_grade(84) == "B"

    def test_85_is_a(self):
        from domain.scoring import _score_to_grade

        assert _score_to_grade(85) == "A"

    def test_69_is_c(self):
        from domain.scoring import _score_to_grade

        assert _score_to_grade(69) == "C"

    def test_70_is_b(self):
        from domain.scoring import _score_to_grade

        assert _score_to_grade(70) == "B"

    def test_54_is_d(self):
        from domain.scoring import _score_to_grade

        assert _score_to_grade(54) == "D"

    def test_55_is_c(self):
        from domain.scoring import _score_to_grade

        assert _score_to_grade(55) == "C"

    def test_39_is_f(self):
        from domain.scoring import _score_to_grade

        assert _score_to_grade(39) == "F"

    def test_40_is_d(self):
        from domain.scoring import _score_to_grade

        assert _score_to_grade(40) == "D"

    def test_0_is_f(self):
        from domain.scoring import _score_to_grade

        assert _score_to_grade(0) == "F"

    def test_100_is_a(self):
        from domain.scoring import _score_to_grade

        assert _score_to_grade(100) == "A"


# =========== score_domain edge cases ===========


class TestScoreDomainEdgeCases:
    def test_empty_report_no_crash(self):
        from domain.scoring import score_domain

        result = score_domain({})
        assert result["grade"] in ("A", "B", "C", "D", "F")
        assert result["score"] >= 0
        assert len(result["factors"]) > 0

    def test_empty_reputation_includes_factor(self):
        """When reputation dict is empty, IP Reputation factor should still appear."""
        from domain.scoring import score_domain

        report = {"reputation": {}}
        result = score_domain(report)
        factor_names = [f["name"] for f in result["factors"]]
        assert "IP Reputation" in factor_names
        rep_factor = [f for f in result["factors"] if f["name"] == "IP Reputation"][0]
        assert rep_factor["score"] == 0
        assert rep_factor["detail"] == "Reputation data unavailable"

    def test_missing_reputation_includes_factor(self):
        """When reputation key is missing entirely, IP Reputation factor should still appear."""
        from domain.scoring import score_domain

        report = {}
        result = score_domain(report)
        factor_names = [f["name"] for f in result["factors"]]
        assert "IP Reputation" in factor_names


# =========== threat_intel route tests ===========


class TestThreatIntelRoute:
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    @patch(
        "domain.routes.check_urlhaus",
        return_value={"urlhaus_status": "clean", "urls_online": 0, "url_count": 0},
        new_callable=AsyncMock,
    )
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_threat_clean(self, mock_validate, mock_urlhaus, mock_auth):
        r = client.get("/v1/threat/example.com")
        assert r.status_code == 200
        assert "no threats" in r.json()["summary"]

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    @patch(
        "domain.routes.check_urlhaus",
        return_value={
            "urlhaus_status": "listed",
            "urls_online": 2,
            "url_count": 3,
            "threat_types": ["malware_download"],
            "tags": [],
            "urls": [],
        },
        new_callable=AsyncMock,
    )
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_threat_listed(self, mock_validate, mock_urlhaus, mock_auth):
        r = client.get("/v1/threat/example.com")
        assert r.status_code == 200
        data = r.json()
        assert "3 URL" in data["summary"]
        assert data["urls_online"] == 2

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    @patch(
        "domain.routes.check_urlhaus",
        return_value={
            "urlhaus_status": "not_found",
            "urls_online": 0,
            "url_count": 0,
            "threat_types": [],
            "tags": [],
            "urls": [],
        },
        new_callable=AsyncMock,
    )
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_threat_intel_verdict(self, mock_validate, mock_urlhaus, mock_auth):
        r = client.get("/v1/threat/example.com")
        assert r.status_code == 200
        body = r.json()
        assert "verdict" in body
        v = body["verdict"]
        assert v["deterministic"] is True
        assert set(v["falsifiable_fields"]) >= {"urlhaus_status", "url_count", "urls_online"}
        assert v["data_age_seconds"] == 0
        assert v["sources_queried"] == ["urlhaus"]
        assert v["sources_unavailable"] == []
        assert v["completeness"] == "complete"

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    @patch(
        "domain.routes.check_urlhaus",
        return_value={
            "urlhaus_status": "error",
            "urls_online": 0,
            "url_count": 0,
            "threat_types": [],
            "tags": [],
            "urls": [],
        },
        new_callable=AsyncMock,
    )
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_threat_intel_verdict_partial_on_error(self, mock_validate, mock_urlhaus, mock_auth):
        r = client.get("/v1/threat/example.com")
        assert r.status_code == 200
        v = r.json()["verdict"]
        assert v["sources_queried"] == ["urlhaus"]
        assert v["sources_unavailable"] == ["urlhaus"]
        assert v["completeness"] == "partial"


# =========== whois_lookup unit tests ===========


class TestWhoisLookupUnit:
    def test_unsupported_tld_returns_error(self):
        from domain.recon import whois_lookup

        result = whois_lookup("example.dev")
        assert "error" in result
        assert "RDAP" in result["error"]

    def test_unsupported_tld_app(self):
        from domain.recon import whois_lookup

        result = whois_lookup("example.app")
        assert "error" in result


# =========== detect_waf edge cases ===========


class TestDetectWafEdgeCases:
    def test_case_insensitive_server(self):
        from domain.recon import detect_waf

        result = detect_waf({"server": "CloudFlare-Nginx"})
        assert "Cloudflare" in result["detected"]

    def test_non_server_header_detection(self):
        from domain.recon import detect_waf

        result = detect_waf({"x-fastly-request-id": "abc123"})
        assert "Fastly" in result["detected"]

    def test_empty_headers(self):
        from domain.recon import detect_waf

        result = detect_waf({})
        assert result["waf_present"] is False


# =========== ratelimit refund tests ===========


class TestRatelimitRefund:
    def test_refund_removes_last_entry(self):
        import ratelimit

        ratelimit.reset()
        ratelimit.check_limit("test_refund", "key1", max_requests=3, window_seconds=60)
        ratelimit.check_limit("test_refund", "key1", max_requests=3, window_seconds=60)
        assert ratelimit.get_count("test_refund", "key1", window_seconds=60) == 2
        ratelimit.refund("test_refund", "key1")
        assert ratelimit.get_count("test_refund", "key1", window_seconds=60) == 1

    def test_refund_nonexistent_key_no_crash(self):
        import ratelimit

        ratelimit.reset()
        ratelimit.refund("test_refund", "nonexistent")  # should not raise


# =========== Pro-tier upstream quota protection tests ===========

_ENRICH_EMPTY = {"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": [], "internetdb_status": "ok"}


class TestProOnlyEnrichment:
    """Upstream quota gate: live AbuseIPDB/Shodan calls only for Pro tier."""

    # --- full_domain_report unit tests ---

    @patch("domain.scoring.score_domain", return_value={"grade": "A", "score": 90, "max_score": 100, "factors": []})
    @patch("domain.recon.fetch_live_headers", new_callable=AsyncMock, return_value={"headers": {}})
    @patch("domain.recon.email_security", return_value={"grade": "A"})
    @patch("domain.threat.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}, new_callable=AsyncMock)
    @patch(
        "domain.recon.check_ct_logs", return_value={"total_certificates": 0, "certificates": []}, new_callable=AsyncMock
    )
    @patch("domain.recon.enumerate_subdomains", return_value={"subdomains": [], "count": 0}, new_callable=AsyncMock)
    @patch("domain.recon._fetch_crtsh", return_value=([], None), new_callable=AsyncMock)
    @patch("domain.recon.ssl_info", return_value={"issuer": "LE", "grade": "B"})
    @patch("domain.recon.whois_lookup", return_value={})
    @patch("domain.recon.reverse_dns", return_value={"ip": "1.2.3.4", "ptr": None})
    @patch("domain.recon.dns_lookup", return_value={"a": ["1.2.3.4"]})
    @patch("domain.recon.ratelimit")
    @patch("db.get_cached_ip", return_value=None)
    @patch(
        "domain.reputation.check_shodan",
        side_effect=AssertionError("Shodan must not be called for free tier"),
        new_callable=AsyncMock,
    )
    @patch(
        "domain.reputation.check_abuseipdb",
        side_effect=AssertionError("AbuseIPDB must not be called for free tier"),
        new_callable=AsyncMock,
    )
    def test_domain_report_free_tier_enrichment_pro_only(
        self,
        m_ab,
        m_sh,
        m_cache_ip,
        m_rl,
        m_dns,
        m_rdns,
        m_whois,
        m_ssl,
        m_crtsh,
        m_subs,
        m_ct,
        m_threat,
        m_email,
        m_headers,
        m_score,
    ):
        """Free tier: reputation stub returned, no upstream API calls made."""
        from domain.recon import full_domain_report

        m_rl.check_limit.return_value = True
        result = asyncio.run(
            full_domain_report("example.com", resolved_ip="1.2.3.4", client_ip="10.0.0.1", tier="free")
        )
        assert "reputation" in result
        assert result["reputation"]["abuseipdb"]["status"] == "pro_only"
        assert result["reputation"]["abuseipdb"]["upgrade_url"] == "https://api.contrastcyber.com/pricing"
        assert result["reputation"]["shodan"]["status"] == "pro_only"
        assert result["reputation"]["shodan"]["upgrade_url"] == "https://api.contrastcyber.com/pricing"

    @patch("domain.scoring.score_domain", return_value={"grade": "A", "score": 90, "max_score": 100, "factors": []})
    @patch("domain.recon.fetch_live_headers", new_callable=AsyncMock, return_value={"headers": {}})
    @patch("domain.recon.email_security", return_value={"grade": "A"})
    @patch("domain.threat.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}, new_callable=AsyncMock)
    @patch(
        "domain.recon.check_ct_logs", return_value={"total_certificates": 0, "certificates": []}, new_callable=AsyncMock
    )
    @patch("domain.recon.enumerate_subdomains", return_value={"subdomains": [], "count": 0}, new_callable=AsyncMock)
    @patch("domain.recon._fetch_crtsh", return_value=([], None), new_callable=AsyncMock)
    @patch("domain.recon.ssl_info", return_value={"issuer": "LE", "grade": "A"})
    @patch("domain.recon.whois_lookup", return_value={})
    @patch("domain.recon.reverse_dns", return_value={"ip": "1.2.3.4", "ptr": None})
    @patch("domain.recon.dns_lookup", return_value={"a": ["1.2.3.4"]})
    @patch("domain.recon.ratelimit")
    @patch("db.save_cached_ip")
    @patch("db.get_cached_ip", return_value=None)
    @patch("domain.reputation.check_shodan", return_value={"status": "ok", "mock": True}, new_callable=AsyncMock)
    @patch("domain.reputation.check_abuseipdb", return_value={"status": "ok", "mock": True}, new_callable=AsyncMock)
    def test_domain_report_pro_tier_enrichment_called(
        self,
        m_ab,
        m_sh,
        m_cache_ip,
        m_save_ip,
        m_rl,
        m_dns,
        m_rdns,
        m_whois,
        m_ssl,
        m_crtsh,
        m_subs,
        m_ct,
        m_threat,
        m_email,
        m_headers,
        m_score,
    ):
        """Pro tier: live enrichment called and response contains real data."""
        from domain.recon import full_domain_report

        m_rl.check_limit.return_value = True
        result = asyncio.run(full_domain_report("example.com", resolved_ip="1.2.3.4", client_ip="10.0.0.1", tier="pro"))
        m_ab.assert_called_once()
        m_sh.assert_called_once()
        assert result["reputation"]["abuseipdb"]["status"] == "ok"
        assert result["reputation"]["shodan"]["status"] == "ok"

    # --- /v1/ip route tests ---

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    @patch("db.get_cached_ip_with_age", return_value=None)
    @patch("domain.routes.ratelimit.check_limit", return_value=True)
    @patch(
        "domain.routes.check_shodan",
        side_effect=AssertionError("Shodan must not be called for free tier"),
        new_callable=AsyncMock,
    )
    @patch(
        "domain.routes.check_abuseipdb",
        side_effect=AssertionError("AbuseIPDB must not be called for free tier"),
        new_callable=AsyncMock,
    )
    @patch("domain.routes.ip_enrichment", return_value=_ENRICH_EMPTY, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", return_value=("example.com", [], []))
    def test_ip_lookup_free_tier_enrichment_pro_only(
        self, mock_ptr, mock_enrich, mock_ab, mock_sh, mock_limit, mock_cache, mock_auth
    ):
        """Bug I4: free tier /v1/ip drops the verbose abuseipdb / shodan
        pro_only sub-stubs (~150 token of null space) and replaces them
        with one compact upgrade hint. Verdict still lists the missing
        sources in sources_unavailable."""
        r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        data = r.json()
        assert "reputation" in data
        rep = data["reputation"]
        # Old pro_only stubs are gone — abuseipdb and shodan dropped from the wire.
        assert rep.get("abuseipdb") is None
        assert rep.get("shodan") is None
        # Compact replacement carries the upgrade hint instead.
        upgrade = rep["upgrade"]
        assert "abuseipdb" in upgrade["pro_only_sources"]
        assert "shodan" in upgrade["pro_only_sources"]
        assert upgrade["upgrade_url"] == "https://api.contrastcyber.com/pricing"

    # --- /v1/threat-report route tests ---

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    @patch("domain.routes._ripe_client", new_callable=AsyncMock)
    @patch(
        "domain.routes.check_shodan",
        side_effect=AssertionError("Shodan must not be called for free tier"),
        new_callable=AsyncMock,
    )
    @patch(
        "domain.routes.check_abuseipdb",
        side_effect=AssertionError("AbuseIPDB must not be called for free tier"),
        new_callable=AsyncMock,
    )
    @patch(
        "domain.routes.ip_enrichment",
        return_value={"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": []},
        new_callable=AsyncMock,
    )
    def test_threat_report_free_tier_enrichment_pro_only(self, mock_enrich, mock_ab, mock_sh, mock_ripe, mock_auth):
        """Free tier /v1/threat-report: pro_only stub returned, no live API calls."""
        mock_ripe.get = AsyncMock(side_effect=Exception("no network"))
        r = client.get("/v1/threat-report/8.8.8.8")
        assert r.status_code == 200
        data = r.json()
        assert data["abuseipdb"]["status"] == "pro_only"
        assert data["abuseipdb"]["upgrade_url"] == "https://api.contrastcyber.com/pricing"
        assert data["shodan"]["status"] == "pro_only"
        assert data["shodan"]["upgrade_url"] == "https://api.contrastcyber.com/pricing"
        # v1.17.0 schema fix: severity_label + is_datacenter must reach the wire
        # (pre-1.17 the route built them but Pydantic dropped severity_label
        # because ThreatReportResponse hadn't declared the field).
        assert "severity_label" in data
        assert data["severity_label"] in ("low", "medium", "high", "critical")
        assert "is_datacenter" in data
        assert isinstance(data["is_datacenter"], bool)

    # --- Cache bypass test ---

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    @patch(
        "domain.routes.check_shodan",
        side_effect=AssertionError("Shodan must not be called — cache hit"),
        new_callable=AsyncMock,
    )
    @patch(
        "domain.routes.check_abuseipdb",
        side_effect=AssertionError("AbuseIPDB must not be called — cache hit"),
        new_callable=AsyncMock,
    )
    @patch(
        "db.get_cached_ip_with_age",
        return_value=(
            {"abuseipdb": {"status": "ok", "abuse_score": 0}, "shodan": {"status": "ok", "ports": [443]}},
            3600,
        ),
    )
    @patch("domain.routes.ip_enrichment", return_value=_ENRICH_EMPTY, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", return_value=("example.com", [], []))
    def test_cached_reputation_served_to_free_tier(
        self, mock_ptr, mock_enrich, mock_cache, mock_ab, mock_sh, mock_auth
    ):
        """Cached reputation is served to free tier without any upstream calls."""
        r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        data = r.json()
        assert "reputation" in data
        assert data["reputation"]["abuseipdb"]["status"] == "ok"
        assert data["reputation"]["shodan"]["status"] == "ok"

    @pytest.mark.real_firehol
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    @patch("db.get_cached_ip_with_age", return_value=None)
    @patch(
        "domain.routes.check_shodan",
        side_effect=AssertionError("Shodan must not be called for free tier"),
        new_callable=AsyncMock,
    )
    @patch(
        "domain.routes.check_abuseipdb",
        side_effect=AssertionError("AbuseIPDB must not be called for free tier"),
        new_callable=AsyncMock,
    )
    @patch("domain.routes.ip_enrichment", return_value=_ENRICH_EMPTY, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", return_value=("example.com", [], []))
    @patch("domain.ip_intel.check_firehol", return_value={"status": "ok", "listed": False, "lists_matched": []})
    def test_ip_lookup_free_tier_firehol_present(
        self, mock_fh, mock_ptr, mock_enrich, mock_ab, mock_sh, mock_cache, mock_auth
    ):
        """Free tier /v1/ip: firehol key present alongside pro_only stubs."""
        r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        data = r.json()
        assert "reputation" in data
        rep = data["reputation"]
        assert "firehol" in rep
        fh = rep["firehol"]
        assert "status" in fh
        assert "listed" in fh
        assert "lists_matched" in fh
        # Bug I4 — pro_only stubs dropped; upgrade hint replaces them.
        assert rep.get("abuseipdb") is None
        assert rep.get("shodan") is None
        assert "abuseipdb" in rep["upgrade"]["pro_only_sources"]
        assert "shodan" in rep["upgrade"]["pro_only_sources"]

    @pytest.mark.real_firehol
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_PRO)
    @patch("db.get_cached_ip_with_age", return_value=None)
    @patch("domain.routes.ratelimit.check_limit", return_value=True)
    @patch("db.save_cached_ip")
    @patch("domain.routes.ip_enrichment", return_value=_ENRICH_EMPTY, new_callable=AsyncMock)
    @patch("domain.routes.socket.gethostbyaddr", return_value=("example.com", [], []))
    @patch("domain.routes.check_shodan", return_value={"status": "ok", "ports": []}, new_callable=AsyncMock)
    @patch("domain.routes.check_abuseipdb", return_value={"status": "ok", "abuse_score": 0}, new_callable=AsyncMock)
    @patch("domain.ip_intel.check_firehol", return_value={"status": "ok", "listed": False, "lists_matched": []})
    def test_ip_lookup_pro_tier_firehol_in_parallel(
        self, mock_fh, mock_ab, mock_sh, mock_ptr, mock_enrich, mock_save, mock_limit, mock_cache, mock_auth
    ):
        """Pro tier /v1/ip: firehol, abuseipdb, and shodan all render in response."""
        r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        data = r.json()
        assert "reputation" in data
        rep = data["reputation"]
        assert "firehol" in rep
        assert "abuseipdb" in rep
        assert "shodan" in rep
        assert rep["firehol"]["status"] == "ok"
        assert "firehol" in data["verdict"]["sources_queried"]

    # --- Tier-aware cache segregation (prevents cache poisoning) ---

    @patch(
        "domain.tech.detect_technologies",
        return_value={"technologies": [], "categories": {}, "count": 0, "summary": ""},
    )
    @patch("domain.recon.fetch_live_headers", new_callable=AsyncMock, return_value={"headers": {}})
    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain", return_value=None)
    @patch(
        "domain.routes.full_domain_report",
        return_value={"domain": "example.com", "summary": "ok"},
        new_callable=AsyncMock,
    )
    @patch("domain.routes.clean_domain", return_value="example.com")
    @patch(
        "auth.aauthenticate",
        new_callable=AsyncMock,
        return_value=AuthCtx(
            tier="pro",
            key_hash="h",
            client_ip="10.0.0.1",
            ratelimit_limit=1000,
            ratelimit_remaining=999,
            ratelimit_reset=0,
            ratelimit_cost=1,
        ),
    )
    def test_audit_domain_threads_pro_tier_to_full_report(
        self, mock_auth, mock_clean, mock_report, mock_get, mock_save, mock_headers, mock_tech
    ):
        """audit_domain must pass auth_ctx['tier'] into full_domain_report — Pro users get real enrichment."""
        r = client.get("/v1/audit/example.com")
        assert r.status_code == 200
        # Verify tier was threaded as keyword arg
        _, kwargs = mock_report.call_args
        assert kwargs.get("tier") == "pro", (
            f"audit_domain did not thread tier=pro to full_domain_report; got kwargs={kwargs}"
        )
        # Cache key includes tier prefix → no cross-tier poisoning
        mock_get.assert_called_with("pro:example.com")
        mock_save.assert_called_once()
        saved_key, _ = mock_save.call_args[0]
        assert saved_key == "pro:example.com", f"audit_domain save_cached_domain used tier-agnostic key: {saved_key}"

    @patch("db.save_cached_domain")
    @patch("db.get_cached_domain_with_age", return_value=None)
    @patch(
        "domain.routes.full_domain_report",
        return_value={"domain": "example.com", "summary": "ok"},
        new_callable=AsyncMock,
    )
    @patch("domain.routes._validate_domain_input", return_value=("example.com", "1.2.3.4"))
    @patch("auth.aauthenticate", new_callable=AsyncMock)
    def test_domain_report_cache_keys_tier_segregated(
        self, mock_auth_sync, mock_validate, mock_report, mock_get, mock_save
    ):
        """Free stub must not poison Pro cache — tier prefix segregates cache keys."""
        # Free tier request
        mock_auth_sync.return_value = AuthCtx(
            tier="free",
            key_hash=None,
            client_ip="10.0.0.1",
            ratelimit_limit=100,
            ratelimit_remaining=99,
            ratelimit_reset=0,
            ratelimit_cost=1,
        )
        r_free = client.get("/v1/domain/example.com")
        assert r_free.status_code == 200
        free_read_key = mock_get.call_args[0][0]
        free_save_key = mock_save.call_args[0][0]
        assert free_read_key == "free:example.com"
        assert free_save_key == "free:example.com"

        # Pro tier request — must check a DIFFERENT cache key, not the free one
        mock_get.reset_mock()
        mock_save.reset_mock()
        mock_auth_sync.return_value = AuthCtx(
            tier="pro",
            key_hash="h",
            client_ip="10.0.0.2",
            ratelimit_limit=1000,
            ratelimit_remaining=999,
            ratelimit_reset=0,
            ratelimit_cost=1,
        )
        r_pro = client.get("/v1/domain/example.com")
        assert r_pro.status_code == 200
        pro_read_key = mock_get.call_args[0][0]
        pro_save_key = mock_save.call_args[0][0]
        assert pro_read_key == "pro:example.com", f"Pro read hit free key — poisoning risk: {pro_read_key}"
        assert pro_save_key == "pro:example.com"
        assert pro_read_key != free_read_key


# =========== /v1/domain behavioral throttle + hard timeout tests ===========


class TestDomainBurstThrottleAndTimeout:
    """v1.25.x: Free tier domain_report has a 5-req/60s burst throttle (catches
    UA-rotating bot fleets) and an 8s hard ceiling on full_domain_report (caps
    workers tied up by slow upstream fail-overs)."""

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT, new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age", return_value=None)
    @patch("db.save_cached_domain")
    def test_burst_throttle_free_tier_429_after_limit(self, mock_save, mock_cache, mock_validate, mock_report):
        """6th request from same client within 60s window → 429 (Free tier)."""
        for i in range(5):
            r = client.get(f"/v1/domain/example{i}.com")
            assert r.status_code == 200, f"request {i + 1} should succeed"
        r6 = client.get("/v1/domain/example5.com")
        assert r6.status_code == 429
        body = r6.json()
        # Detail message names the limit + window so client can react
        assert "5" in str(body) and "60" in str(body)

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT, new_callable=AsyncMock)
    @patch("domain.routes._validate_domain_input", return_value=("example.com", "93.184.216.34"))
    @patch(
        "auth.aauthenticate",
        new_callable=AsyncMock,
        return_value=AuthCtx(
            tier="pro",
            key_hash="h",
            client_ip="10.0.0.1",
            ratelimit_limit=1000,
            ratelimit_remaining=999,
            ratelimit_reset=0,
            ratelimit_cost=1,
        ),
    )
    @patch("db.get_cached_domain_with_age", return_value=None)
    @patch("db.save_cached_domain")
    def test_burst_throttle_pro_tier_exempt(self, mock_save, mock_cache, mock_auth_sync, mock_validate, mock_report):
        """Pro tier bypasses behavioral throttle — explicit paid quota."""
        for i in range(8):
            r = client.get(f"/v1/domain/example{i}.com")
            assert r.status_code == 200, f"Pro tier request {i + 1} unexpectedly throttled"

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT, new_callable=AsyncMock)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age", return_value=(MOCK_FULL_REPORT, 30))
    def test_burst_throttle_consumes_quota_on_cache_hit(self, mock_cache, mock_validate, mock_report):
        """Cache hits MUST consume burst quota — otherwise repeated cached-domain
        queries (UA-rotating bot pattern that lands on a popular domain) bypass
        the throttle entirely."""
        for i in range(5):
            r = client.get("/v1/domain/example.com")
            assert r.status_code == 200, f"request {i + 1} should succeed"
        # full_domain_report never called (all cache hits) yet 6th still 429
        assert mock_report.call_count == 0
        r6 = client.get("/v1/domain/example.com")
        assert r6.status_code == 429

    @patch("domain.routes.DOMAIN_HARD_TIMEOUT", 0.1)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("db.get_cached_domain_with_age", return_value=None)
    def test_hard_timeout_returns_504(self, mock_cache, mock_validate):
        """full_domain_report exceeding DOMAIN_HARD_TIMEOUT → 504 (worker freed)."""

        async def slow_report(*args, **kwargs):
            await asyncio.sleep(0.5)
            return MOCK_FULL_REPORT

        with patch("domain.routes.full_domain_report", side_effect=slow_report):
            r = client.get("/v1/domain/example.com")
        assert r.status_code == 504
        # v1.22.2 error envelope: {"error": {"code": ..., "message": ...}}
        assert "timed out" in str(r.json()).lower()


class TestThreatIntelPivotHints:
    """Batch 4: threat_intel always emits 2 hints in order: domain_report, ioc_lookup; +phishing_check when urls_online>0."""

    def test_threat_intel_pivot_emits_two_baseline(self):
        from domain.routes import _threat_intel_pivot_hints

        record = {"domain": "example.com", "urls_online": 0, "url_count": 0}
        hints = _threat_intel_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert tools == ["domain_report", "ioc_lookup"]
        for h in hints:
            assert h.input == "example.com"
            assert h.reason

    def test_threat_intel_pivot_appends_phishing_check_when_urls_online(self):
        from domain.routes import _threat_intel_pivot_hints

        record = {"domain": "evil.com", "urls_online": 3, "url_count": 5}
        hints = _threat_intel_pivot_hints(record)
        tools = [h.tool for h in hints]
        assert tools == ["domain_report", "ioc_lookup", "phishing_check"]

    def test_threat_intel_pivot_empty_on_no_domain(self):
        from domain.routes import _threat_intel_pivot_hints

        hints = _threat_intel_pivot_hints({"domain": "", "urls_online": 0})
        assert hints == []


class TestAuditDomainPivotHints:
    """Batch 4: audit_domain refactor — inline → helper. 4 hints when has_a; 3 without ssl_check on no A; 0 on NXDOMAIN."""

    def test_audit_domain_pivot_emits_four_with_a_record(self):
        from domain.routes import _audit_domain_pivot_hints

        report = {"dns": {"a": ["1.2.3.4"]}}
        hints = _audit_domain_pivot_hints(report, "example.com")
        tools = [h.tool for h in hints]
        assert tools == ["subdomain_enum", "ssl_check", "domain_report", "scan_headers"]
        for h in hints:
            assert h.input == "example.com"
            assert h.reason

    def test_audit_domain_pivot_drops_ssl_check_without_a_record(self):
        from domain.routes import _audit_domain_pivot_hints

        report = {"dns": {"mx": [{"priority": 10, "host": "mail.example.com"}]}}
        hints = _audit_domain_pivot_hints(report, "example.com")
        tools = [h.tool for h in hints]
        assert tools == ["subdomain_enum", "domain_report", "scan_headers"]

    def test_audit_domain_pivot_aaaa_record_treated_as_a(self):
        from domain.routes import _audit_domain_pivot_hints

        report = {"dns": {"aaaa": ["::1"]}}
        hints = _audit_domain_pivot_hints(report, "v6.example")
        tools = [h.tool for h in hints]
        assert tools == ["subdomain_enum", "ssl_check", "domain_report", "scan_headers"]

    def test_audit_domain_pivot_empty_on_nxdomain(self):
        from domain.routes import _audit_domain_pivot_hints

        hints = _audit_domain_pivot_hints({"dns": {}}, "nxdomain.example")
        assert hints == []


class TestReconExecutorIsolation:
    """S260: whois/ssl run on a dedicated bounded executor, NOT the shared
    AnyIO threadpool, so a /v1/domain flood can't starve cve_leading et al."""

    def test_whois_ssl_executor_bounded_at_3(self):
        from concurrent.futures import ThreadPoolExecutor

        from domain.recon import _WHOIS_SSL_EXECUTOR

        assert isinstance(_WHOIS_SSL_EXECUTOR, ThreadPoolExecutor)
        assert _WHOIS_SSL_EXECUTOR._max_workers == 3

    def test_whois_lookup_async_returns_underlying_result(self):
        from domain import recon

        with patch("domain.recon.whois_lookup", return_value={"registrar": "X"}):
            out = asyncio.run(recon.whois_lookup_async("example.com"))
        assert out == {"registrar": "X"}

    def test_ssl_info_async_returns_underlying_result(self):
        from domain import recon

        with patch("domain.recon.ssl_info", return_value={"grade": "A"}):
            out = asyncio.run(recon.ssl_info_async("example.com", "1.2.3.4"))
        assert out == {"grade": "A"}

    def test_whois_ssl_async_bypass_shared_threadpool(self):
        from domain import recon

        def _boom(*a, **k):
            raise RuntimeError("shared run_in_threadpool must not be used by whois/ssl")

        with patch("domain.recon.run_in_threadpool", side_effect=_boom):
            with patch("domain.recon.whois_lookup", return_value={"registrar": "Y"}):
                assert asyncio.run(recon.whois_lookup_async("example.com")) == {"registrar": "Y"}
            with patch("domain.recon.ssl_info", return_value={"grade": "B"}):
                assert asyncio.run(recon.ssl_info_async("example.com", None)) == {"grade": "B"}
