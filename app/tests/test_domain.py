"""Tests for domain intelligence module — recon.py + routes.py"""

import json
import socket
from datetime import UTC
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import httpx
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


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
        subs, warnings = _crtsh_subdomains("example.com", data)
        assert "www.example.com" in subs
        assert "api.example.com" in subs

    def test_filters_wildcards(self):
        from domain.recon import _crtsh_subdomains

        data = [{"name_value": "*.example.com"}]
        subs, warnings = _crtsh_subdomains("example.com", data)
        assert len(subs) == 0

    def test_filters_other_domains(self):
        from domain.recon import _crtsh_subdomains

        data = [{"name_value": "sub.other.com"}]
        subs, warnings = _crtsh_subdomains("example.com", data)
        assert len(subs) == 0

    def test_limits_to_50(self):
        from domain.recon import _crtsh_subdomains

        data = [{"name_value": f"sub{i}.example.com"} for i in range(100)]
        subs, warnings = _crtsh_subdomains("example.com", data)
        assert len(subs) <= 50

    def test_empty_data(self):
        from domain.recon import _crtsh_subdomains

        subs, warnings = _crtsh_subdomains("example.com", [])
        assert subs == []


# --- _fetch_crtsh error handling ---


class TestFetchCrtsh:
    def test_fetch_crtsh_timeout(self):
        from domain.recon import _fetch_crtsh

        with patch("domain.recon._http") as mock_http:
            mock_http.get.side_effect = httpx.TimeoutException("timed out")
            data, err = _fetch_crtsh("%.example.com")
            assert data == []
            assert err == "crt_sh_timeout"

    def test_fetch_crtsh_429(self):
        from domain.recon import _fetch_crtsh

        mock_resp = MagicMock()
        mock_resp.status_code = 429
        with patch("domain.recon._http") as mock_http:
            mock_http.get.return_value = mock_resp
            data, err = _fetch_crtsh("%.example.com")
            assert data == []
            assert err == "crt_sh_rate_limited"

    def test_fetch_crtsh_malformed_json(self):
        from domain.recon import _fetch_crtsh

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.side_effect = json.JSONDecodeError("bad json", "", 0)
        with patch("domain.recon._http") as mock_http:
            mock_http.get.return_value = mock_resp
            data, err = _fetch_crtsh("%.example.com")
            assert data == []
            assert err == "parse_error"

    def test_enumerate_subdomains_crtsh_down(self):
        from domain.recon import enumerate_subdomains

        with patch("domain.recon._fetch_crtsh", return_value=([], "crt_sh_timeout")):
            with patch("domain.recon.socket.gethostbyname", side_effect=socket.gaierror):
                result = enumerate_subdomains("example.com")
        assert result["warnings"] == ["crt_sh_timeout"]
        assert result["sources"] == []
        assert result["subdomains"] == []

    def test_enumerate_subdomains_no_crtsh_results(self):
        from domain.recon import enumerate_subdomains

        with patch("domain.recon._fetch_crtsh", return_value=([], None)):
            with patch("domain.recon.socket.gethostbyname", side_effect=socket.gaierror):
                result = enumerate_subdomains("example.com")
        assert result["warnings"] == []

    def test_crtsh_wildcard_dedup(self):
        from domain.recon import _crtsh_subdomains

        data = [{"name_value": "*.api.example.com\napi.example.com"}]
        subs, warnings = _crtsh_subdomains("example.com", data)
        assert subs.count("api.example.com") == 1
        assert warnings == []

    def test_enumerate_subdomains_cap_large_result(self):
        from domain.recon import CRTSH_MAX_RESULTS, enumerate_subdomains

        large_data = [{"name_value": f"sub{i}.example.com"} for i in range(2000)]
        assert len(large_data) > CRTSH_MAX_RESULTS

        with patch("domain.recon._fetch_crtsh", return_value=(large_data[:CRTSH_MAX_RESULTS], None)):
            with patch("domain.recon.socket.gethostbyname", side_effect=socket.gaierror):
                result = enumerate_subdomains("example.com")
        assert len(result["subdomains"]) <= 50


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
        result = check_ct_logs("example.com", data)
        assert result["total_certificates"] == 2
        assert len(result["certificates"]) == 2

    def test_deduplicates_by_serial(self):
        from domain.recon import check_ct_logs

        data = [
            {"serial_number": "001", "issuer_name": "LE", "not_before": "", "not_after": "", "common_name": "a.com"},
            {"serial_number": "001", "issuer_name": "LE", "not_before": "", "not_after": "", "common_name": "a.com"},
        ]
        result = check_ct_logs("a.com", data)
        assert len(result["certificates"]) == 1

    def test_empty_data(self):
        from domain.recon import check_ct_logs

        result = check_ct_logs("x.com", [])
        assert result["total_certificates"] == 0

    def test_limits_certificates(self):
        from domain.recon import check_ct_logs

        data = [
            {"serial_number": str(i), "issuer_name": "LE", "not_before": "", "not_after": "", "common_name": "x.com"}
            for i in range(25)
        ]
        result = check_ct_logs("x.com", data)
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
MOCK_WHOIS_RESULT = {"registrar": "Test Registrar", "creation_date": "2020-01-01", "raw_length": 500}
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
    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.get_cached_domain_with_age", return_value=None)
    def test_domain_report_200(self, mock_cache, mock_validate, mock_report):
        """validate_domain is called in _validate_and_auth for all routes."""
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "example.com"
        assert "dns" in data
        assert "summary" in data

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.get_cached_domain_with_age", return_value=None)
    def test_domain_report_post(self, mock_cache, mock_validate, mock_report):
        """POST returns same result as GET (Salesforce SFDC-Callout compat)."""
        r = client.post("/v1/domain/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "example.com"

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.get_cached_domain_with_age", return_value=None)
    def test_domain_report_post_with_body(self, mock_cache, mock_validate, mock_report):
        """POST with JSON body is ignored (body not read)."""
        r = client.post("/v1/domain/example.com", json={"extra": "ignored"})
        assert r.status_code == 200

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.get_cached_domain_with_age", return_value=None)
    def test_domain_report_risk_score_alias(self, mock_cache, mock_validate, mock_report):
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        data = r.json()
        assert "risk" in data
        assert "risk_score" in data
        assert isinstance(data["risk_score"], int)
        assert data["risk_score"] == data["risk"]["score"]

    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.get_cached_domain_with_age", return_value=(MOCK_FULL_REPORT, 3600))
    def test_domain_report_cached(self, mock_cache, mock_validate, mock_report):
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        data = r.json()
        assert mock_report.call_count == 0

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.get_cached_domain_with_age", return_value=None)
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

    @patch("domain.routes._is_valid_format", return_value=False)
    @patch("domain.routes.validate_domain", return_value=None)
    @patch("domain.routes.get_cached_domain_with_age", return_value=None)
    def test_domain_report_invalid_domain(self, mock_cache, mock_validate, mock_format):
        r = client.get("/v1/domain/nonexistent.invalid")
        assert r.status_code == 400

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.get_cached_domain_with_age", return_value=None)
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

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.get_cached_domain_with_age", return_value=None)
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
    )
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.get_cached_domain_with_age", return_value=None)
    def test_domain_report_verdict_partial_on_urlhaus_error(self, mock_cache, mock_validate, mock_report):
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        v = r.json()["verdict"]
        assert "urlhaus" in v["sources_unavailable"]
        assert v["completeness"] == "partial"

    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.get_cached_domain_with_age", return_value=None)
    def test_domain_report_verdict_lite_mode(self, mock_cache, mock_validate, mock_report):
        r = client.get("/v1/domain/example.com?lite=true")
        assert r.status_code == 200
        v = r.json()["verdict"]
        assert v["sources_queried"] == ["dns", "ssl"]
        assert "whois" not in v["sources_queried"]
        assert "urlhaus" not in v["sources_queried"]
        assert set(v["sources_unavailable"]) == {"whois", "subdomains", "ct_logs", "urlhaus", "reputation"}
        assert v["completeness"] == "complete"

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

    @patch("domain.routes.whois_lookup", return_value=MOCK_WHOIS_RESULT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_whois_200(self, mock_validate, mock_whois):
        r = client.get("/v1/whois/example.com")
        assert r.status_code == 200
        data = r.json()
        assert "whois" in data

    @patch("domain.routes.whois_lookup", return_value={"error": "No WHOIS server"})
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_whois_error(self, mock_validate, mock_whois):
        r = client.get("/v1/whois/example.dev")
        assert r.status_code == 504

    @patch("domain.routes.enumerate_subdomains", return_value=MOCK_SUBDOMAIN_RESULT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_subdomains_200(self, mock_validate, mock_subs):
        r = client.get("/v1/subdomains/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 1

    @patch("domain.routes.check_ct_logs", return_value=MOCK_CT_RESULT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_certs_200(self, mock_validate, mock_ct):
        r = client.get("/v1/certs/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["total_certificates"] == 1

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
    )
    @patch("domain.routes.socket.gethostbyaddr", return_value=("example.com", [], []))
    def test_ip_lookup_verdict_partial_on_internetdb_error(self, mock_ptr, mock_enrich):
        r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        v = r.json()["verdict"]
        assert "internetdb" in v["sources_unavailable"]
        assert v["completeness"] == "partial"

    _enrich_empty = {
        "ports": [],
        "hostnames": [],
        "vulns": [],
        "cpes": [],
        "tags": [],
        "internetdb_status": "ok",
    }

    @patch("domain.routes.check_cloud_provider", return_value="AWS")
    @patch("domain.routes.check_tor_exit", return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty})
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_cloud_provider_aws(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/3.5.140.2")
        assert r.status_code == 200
        data = r.json()
        assert data["cloud_provider"] == "AWS"
        # tor_exit is always present as a bool (response_model_exclude_none=False on /ip/{ip})
        assert data["tor_exit"] is False

    @patch("domain.routes.check_cloud_provider", return_value=None)
    @patch("domain.routes.check_tor_exit", return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty})
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_cloud_provider_none(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200
        data = r.json()
        # cloud_provider is always present (null when neither CIDR nor ASN map matches)
        assert data["cloud_provider"] is None

    @patch("domain.routes.check_cloud_provider", return_value=None)
    @patch("domain.routes.check_tor_exit", return_value=True)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty})
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_tor_exit_true(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200
        data = r.json()
        assert data["tor_exit"] is True

    @patch("domain.routes.check_cloud_provider", return_value=None)
    @patch("domain.routes.check_tor_exit", return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty})
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_risk_score_present(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200
        data = r.json()
        assert "risk_score" in data
        assert 0 <= data["risk_score"] <= 100

    @patch("domain.routes.check_cloud_provider", return_value="GCP")
    @patch("domain.routes.check_tor_exit", return_value=False)
    @patch(
        "domain.routes.ip_enrichment",
        return_value={"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": [], "internetdb_status": "ok"},
    )
    @patch("domain.routes.socket.gethostbyaddr", return_value=("dns.google", [], []))
    def test_ip_risk_score_low_clean_cloud(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/8.8.8.8")
        assert r.status_code == 200
        data = r.json()
        # cloud bonus + ptr bonus, no abuse, no tor → low score
        assert data["risk_score"] <= 30

    @patch("domain.routes.check_cloud_provider", return_value=None)
    @patch("domain.routes.check_tor_exit", return_value=True)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty})
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_risk_score_high_tor(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200
        data = r.json()
        # tor_exit=True → at least 20 penalty
        assert data["risk_score"] >= 20

    @patch("domain.routes.check_cloud_provider", return_value="AWS")
    @patch("domain.routes.check_tor_exit", return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty})
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_verdict_extended_falsifiable_fields(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/3.5.140.2")
        assert r.status_code == 200
        fields = r.json()["verdict"]["falsifiable_fields"]
        assert "cloud_provider" in fields
        assert "tor_exit" in fields
        assert "risk_score" in fields

    @patch("domain.routes.check_cloud_provider", side_effect=Exception("upstream down"))
    @patch("domain.routes.check_tor_exit", return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty})
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_intel_cache_failure_resilient(self, mock_ptr, mock_enrich, mock_tor, mock_cloud):
        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200  # must not 500

    @patch(
        "domain.routes._fetch_asn_country",
        return_value={"asn": 13335, "asn_name": "CLOUDFLARENET", "country": "US", "failed": False},
    )
    @patch("domain.routes.check_cloud_provider", return_value="Cloudflare")
    @patch("domain.routes.check_tor_exit", return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty})
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
    @patch("domain.routes.check_cloud_provider", return_value=None)
    @patch("domain.routes.check_tor_exit", return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty})
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
    @patch("domain.routes.check_cloud_provider", return_value="GCP")
    @patch("domain.routes.check_tor_exit", return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty})
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
    @patch("domain.routes.check_cloud_provider", return_value="Cloudflare")
    @patch("domain.routes.check_tor_exit", return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty})
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

    def test_check_cloud_provider_asn_map_fallback_google(self):
        """8.8.8.8 isn't in the GCP CIDR list but AS15169 is in the ASN map → 'Google'."""
        from unittest.mock import patch

        from domain.ip_intel import check_cloud_provider

        # Force CIDR lookup to return None (mimic GCP range list missing 8.8.8.8)
        with patch("domain.ip_intel._refresh_cloud_cache", return_value=(None, None)):
            assert check_cloud_provider("8.8.8.8", asn=15169) == "Google"
            assert check_cloud_provider("104.16.1.1", asn=13335) == "Cloudflare"
            assert check_cloud_provider("1.2.3.4", asn=99999) is None  # unknown ASN
            assert check_cloud_provider("1.2.3.4", asn=None) is None  # no ASN provided

    def test_check_cloud_provider_cidr_takes_precedence_over_asn(self):
        """CIDR lookup is authoritative; ASN map only fires when CIDR misses."""
        from unittest.mock import MagicMock, patch

        from domain.ip_intel import check_cloud_provider

        fake_v4 = MagicMock()
        fake_v4.get.return_value = "AWS"  # CIDR says AWS
        with patch("domain.ip_intel._refresh_cloud_cache", return_value=(fake_v4, None)):
            # Even with asn=15169 (Google in map), CIDR's AWS wins
            assert check_cloud_provider("3.5.140.2", asn=15169) == "AWS"

    @patch(
        "domain.routes._fetch_asn_country",
        return_value={"asn": 15169, "asn_name": "GOOGLE - Google LLC", "country": "US", "failed": False},
    )
    @patch("domain.routes.check_tor_exit", return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty})
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
    @patch("domain.routes.check_tor_exit", return_value=False)
    @patch("domain.routes.ip_enrichment", return_value={**_enrich_empty})
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

    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.get_cached_domain_with_age")
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

    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.get_cached_domain_with_age")
    def test_domain_report_txt_include_all(self, mock_cache, mock_validate, mock_report):
        mock_cache.return_value = (self._TXT_REPORT, 60)
        r = client.get("/v1/domain/example.com?include_all_txt=true")
        assert r.status_code == 200
        dns = r.json()["dns"]
        assert dns["total_txt_records"] == 8
        assert len(dns["txt"]) == 8

    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.get_cached_domain_with_age")
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

    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.get_cached_domain_with_age")
    def test_domain_report_txt_filter_no_txt_section(self, mock_cache, mock_validate, mock_report):
        no_txt = {**self._TXT_REPORT, "dns": {"a": ["93.184.216.34"]}}
        mock_cache.return_value = (no_txt, 60)
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        dns = r.json()["dns"]
        assert "txt" not in dns
        assert "total_txt_records" not in dns

    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.get_cached_domain_with_age")
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
        return_value={"a": ["1.2.3.4"], "txt": ["google-site-verification=xyz", "v=spf1 -all"]},
    )
    @patch("domain.routes.validate_domain", return_value="1.2.3.4")
    @patch("domain.routes._from_cache", return_value=None)
    def test_dns_records_endpoint_keeps_all_txt(self, mock_cache, mock_validate, mock_dns):
        # /v1/dns/{domain} is the explicit raw-DNS endpoint — filter must NOT apply.
        r = client.get("/v1/dns/example.com")
        assert r.status_code == 200
        records = r.json()["records"]
        assert len(records["txt"]) == 2


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

        with patch("domain.routes._ripe_client.get", side_effect=_mock_get):
            from domain.routes import _fetch_asn_country

            out = _fetch_asn_country("198.51.100.1")
        assert out == {"asn": 13335, "asn_name": "CLOUDFLARENET", "country": "AU", "failed": False}

    def test_network_info_failure_returns_empty(self):
        from unittest.mock import patch

        with patch("domain.routes._ripe_client.get", side_effect=Exception("network down")):
            from domain.routes import _fetch_asn_country

            out = _fetch_asn_country("198.51.100.2")
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

        with patch("domain.routes._ripe_client.get", side_effect=_mock_get):
            from domain.routes import _fetch_asn_country

            out = _fetch_asn_country("198.51.100.3")
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

        with patch("domain.routes._ripe_client.get", side_effect=_mock_get):
            from domain.routes import _fetch_asn_country

            out = _fetch_asn_country("198.51.100.4")
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
        with patch("domain.routes._ripe_client.get", side_effect=AssertionError("should not hit RIPE")):
            from domain.routes import _fetch_asn_country

            out = _fetch_asn_country(ip)
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

        with patch("domain.routes._ripe_client.get", side_effect=_mock_get):
            from domain.routes import _fetch_asn_country

            out = _fetch_asn_country(ip)
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

        with patch("domain.routes._ripe_client.get", side_effect=_mock_get):
            from domain.routes import _fetch_asn_country

            out = _fetch_asn_country(ip)
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

        with patch("domain.routes._ripe_client.get", side_effect=_mock_get):
            from domain.routes import _fetch_asn_country

            out = _fetch_asn_country(ip)
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

        with patch("domain.routes._ripe_client.get", side_effect=Exception("RIPE down")):
            from domain.routes import _fetch_asn_country

            out = _fetch_asn_country(ip)
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

        with patch("domain.routes._ripe_client.get", side_effect=_mock_get):
            from domain.routes import _fetch_asn_country

            out = _fetch_asn_country(ip)
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

        with patch("domain.routes._ripe_client.get", side_effect=_mock_get):
            from domain.routes import _fetch_asn_country

            out = _fetch_asn_country("198.51.100.6")
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

    def test_ip_lookup_private_ip_400(self):
        r = client.get("/v1/ip/127.0.0.1")
        assert r.status_code == 400

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
        assert "Could not resolve" in r.json()["error"]


class TestIpEnrichment:
    @patch("domain.recon._http")
    def test_enrichment_success(self, mock_http):
        mock_http.get.return_value = _mock_httpx_response(
            200,
            {
                "ports": [22, 80, 443],
                "hostnames": ["example.com"],
                "vulns": ["CVE-2024-1234"],
                "cpes": ["cpe:/a:nginx:nginx"],
                "tags": ["cloud"],
            },
        )

        from domain.recon import ip_enrichment

        result = ip_enrichment("93.184.216.34")
        assert result["ports"] == [22, 80, 443]
        assert "CVE-2024-1234" in result["vulns"]
        assert "example.com" in result["hostnames"]

    @patch("domain.recon._http")
    def test_enrichment_failure_graceful(self, mock_http):
        mock_http.get.side_effect = Exception("timeout")
        from domain.recon import ip_enrichment

        result = ip_enrichment("1.2.3.4")
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


class TestCtLogsErrorPropagation:
    """check_ct_logs surfaces _fetch_crtsh errors so the scorer can detect them."""

    def test_check_ct_logs_propagates_timeout(self):
        from unittest.mock import patch

        from domain.recon import check_ct_logs

        with patch("domain.recon._fetch_crtsh", return_value=([], "crt_sh_timeout")):
            result = check_ct_logs("example.com")
        assert result["error"] == "crt_sh_timeout"
        assert result["total_certificates"] == 0

    def test_check_ct_logs_clears_error_on_success(self):
        from unittest.mock import patch

        from domain.recon import check_ct_logs

        fake_data = [{"serial_number": "abc", "issuer_name": "X", "common_name": "example.com"}]
        with patch("domain.recon._fetch_crtsh", return_value=(fake_data, None)):
            result = check_ct_logs("example.com")
        assert result["error"] is None
        assert result["total_certificates"] == 1


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
        mock_dmarc = MagicMock()
        mock_dmarc.__iter__ = lambda s: iter([MagicMock(__str__=lambda s: '"v=DMARC1; p=reject"')])
        # DKIM query returns result for first selector
        mock_dkim = MagicMock()

        def resolve_side_effect(name, rtype):
            if "_dmarc." in name:
                return mock_dmarc
            if "_domainkey." in name:
                return mock_dkim
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
        rec = MagicMock()
        rec.__iter__ = lambda s: iter([MagicMock(__str__=lambda s: '"v=DMARC1; p=reject"')])
        return rec

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
                return MagicMock()
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
                return MagicMock()
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
                    return MagicMock()
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
        assert result["grade"] == "B"
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
        assert result["grade"] == "B"
        assert any("No DKIM record found" in i for i in result["issues"])

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
                    return MagicMock()
                raise dns.exception.DNSException("NXDOMAIN")
            raise dns.exception.DNSException("unexpected")

        mock_resolver.resolve.side_effect = resolve_side_effect

        from domain.recon import email_security

        result = email_security("example.com", txt_records=[self._SPF_TXT])
        assert "default" in result["dkim_selectors"]
        assert date_sel in result["dkim_selectors"]
        assert len(result["dkim_selectors"]) == 2


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

        mock_client.post.return_value = _mock_httpx_response(200, {"query_status": "no_results"})
        result = check_urlhaus("clean-example.com")
        assert result["urlhaus_status"] == "clean"
        assert result["url_count"] == 0

    @patch("domain.threat._client")
    def test_listed_domain(self, mock_client):
        from domain.threat import check_urlhaus

        mock_client.post.return_value = _mock_httpx_response(
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
        result = check_urlhaus("bad.com")
        assert result["urlhaus_status"] == "listed"
        assert result["url_count"] == 2
        assert result["urls_online"] == 1
        assert "malware_download" in result["threat_types"]
        assert len(result["urls"]) == 2

    @patch("domain.threat._client")
    def test_error_graceful(self, mock_client):
        from domain.threat import check_urlhaus

        mock_client.post.side_effect = Exception("timeout")
        result = check_urlhaus("timeout.com")
        assert result["urlhaus_status"] == "error"
        assert result["url_count"] == 0


# =========== fetch_live_headers unit tests ===========


class TestFetchLiveHeaders:
    @patch("domain.recon._ssrf_http.get")
    def test_success(self, mock_get):
        from domain.recon import fetch_live_headers

        resp = MagicMock()
        resp.headers = httpx.Headers([("Content-Type", "text/html"), ("X-Frame-Options", "DENY")])
        resp.status_code = 200
        resp.url = httpx.URL("https://example.com/")
        mock_get.return_value = resp
        result = fetch_live_headers("example.com")
        assert "headers" in result
        assert result["status_code"] == 200
        assert "x-frame-options" in result["headers"]

    @patch("domain.recon._ssrf_http.get", side_effect=Exception("conn refused"))
    def test_failure(self, mock_get):
        from domain.recon import fetch_live_headers

        result = fetch_live_headers("unreachable.test")
        assert "error" in result


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
    @patch("domain.reputation.ABUSEIPDB_API_KEY", "test-key")
    def test_abuseipdb_success(self, mock_client):
        from domain.reputation import check_abuseipdb

        mock_client.get.return_value = _mock_httpx_response(
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
        result = check_abuseipdb("1.2.3.4")
        assert result["status"] == "ok"
        assert result["abuse_score"] == 85
        assert result["total_reports"] == 50
        assert result["country"] == "DE"
        assert result["isp"] == "Test ISP"
        assert result["is_tor"] is False

    @patch("domain.reputation.ABUSEIPDB_API_KEY", "")
    def test_abuseipdb_no_key(self):
        from domain.reputation import check_abuseipdb

        result = check_abuseipdb("1.2.3.4")
        assert result["status"] == "skipped"

    @patch("domain.reputation._client")
    @patch("domain.reputation.ABUSEIPDB_API_KEY", "test-key")
    def test_abuseipdb_error(self, mock_client):
        from domain.reputation import check_abuseipdb

        mock_client.get.side_effect = httpx.RequestError("connection refused")
        result = check_abuseipdb("1.2.3.4")
        assert result["status"] == "error"

    @patch("domain.reputation._client")
    @patch("domain.reputation.SHODAN_API_KEY", "test-key")
    def test_shodan_success(self, mock_client):
        from domain.reputation import check_shodan

        mock_client.get.return_value = _mock_httpx_response(
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
        result = check_shodan("1.2.3.4")
        assert result["status"] == "ok"
        assert result["ports"] == [22, 80, 443]
        assert result["org"] == "Example Corp"
        assert "CVE-2024-1111" in result["vulns"]
        assert result["hostnames"] == ["example.com"]

    @patch("domain.reputation.SHODAN_API_KEY", "")
    def test_shodan_no_key(self):
        from domain.reputation import check_shodan

        result = check_shodan("1.2.3.4")
        assert result["status"] == "skipped"

    @patch("domain.reputation._client")
    @patch("domain.reputation.SHODAN_API_KEY", "test-key")
    def test_shodan_403(self, mock_client):
        from domain.reputation import check_shodan

        mock_client.get.return_value = _mock_httpx_response(403)
        result = check_shodan("1.2.3.4")
        assert result["status"] == "restricted"

    @patch("domain.reputation._client")
    @patch("domain.reputation.SHODAN_API_KEY", "test-key")
    def test_shodan_error(self, mock_client):
        from domain.reputation import check_shodan

        mock_client.get.side_effect = httpx.RequestError("timeout")
        result = check_shodan("1.2.3.4")
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
    @patch("domain.recon.fetch_live_headers")
    @patch("domain.recon.email_security")
    @patch("domain.threat.check_urlhaus")
    @patch("domain.recon.check_ct_logs")
    @patch("domain.recon.enumerate_subdomains")
    @patch("domain.recon._fetch_crtsh", return_value=([], None))
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
        m_score.return_value = {"grade": "A", "score": 90, "factors": []}

        result = full_domain_report("example.com", resolved_ip="1.2.3.4", client_ip="10.0.0.1")
        assert result["domain"] == "example.com"
        assert result["dns"] == {"a": ["1.2.3.4"]}
        assert result["whois"]["registrar"] == "Reg Inc."
        assert result["ssl"]["grade"] == "A"
        assert result["subdomains"]["count"] == 1
        assert "summary" in result

    @patch("domain.scoring.score_domain", return_value={"grade": "B", "score": 70, "factors": []})
    @patch("domain.recon.fetch_live_headers", return_value={"headers": {}})
    @patch("domain.recon.email_security", return_value={"grade": "C"})
    @patch("domain.threat.check_urlhaus", return_value={"url_count": 0, "urls_online": 0})
    @patch("domain.recon.check_ct_logs", return_value={"total_certificates": 0, "certificates": []})
    @patch("domain.recon.enumerate_subdomains", return_value={"subdomains": [], "count": 0})
    @patch("domain.recon._fetch_crtsh", return_value=([], None))
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
        result = full_domain_report("example.com", resolved_ip="1.2.3.4", client_ip="10.0.0.1", tier="free")
        assert result["reputation"]["abuseipdb"]["status"] == "pro_only"
        assert result["reputation"]["shodan"]["status"] == "pro_only"

    @patch("domain.scoring.score_domain", return_value={"grade": "A", "score": 90, "factors": []})
    @patch("domain.recon.fetch_live_headers", return_value={"headers": {}})
    @patch("domain.recon.email_security", return_value={"grade": "A"})
    @patch("domain.threat.check_urlhaus", return_value={"url_count": 0, "urls_online": 0})
    @patch("domain.recon.check_ct_logs", return_value={"total_certificates": 0, "certificates": []})
    @patch("domain.recon.enumerate_subdomains", return_value={"subdomains": [], "count": 0})
    @patch("domain.recon._fetch_crtsh", return_value=([], None))
    @patch("domain.recon.ssl_info", return_value={"issuer": "LE", "grade": "A"})
    @patch("domain.recon.whois_lookup", return_value={})
    @patch("domain.recon.reverse_dns", return_value={"ip": "1.2.3.4", "ptr": None})
    @patch("domain.recon.dns_lookup", return_value={"a": ["1.2.3.4"]})
    @patch("domain.recon.ratelimit")
    @patch("db.save_cached_ip")
    @patch("db.get_cached_ip", return_value=None)
    @patch("domain.reputation.check_shodan", side_effect=Exception("timeout"))
    @patch("domain.reputation.check_abuseipdb", return_value={"status": "ok"})
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
        from domain.recon import full_domain_report

        m_rl.check_limit.return_value = True
        result = full_domain_report("example.com", resolved_ip="1.2.3.4", client_ip="10.0.0.1", tier="pro")
        m_rl.refund.assert_called_once_with("enrichment", "10.0.0.1")
        assert "reputation" not in result

    @patch("domain.scoring.score_domain")
    @patch("domain.recon.fetch_live_headers")
    @patch("domain.recon.email_security", return_value={"grade": "A"})
    @patch("domain.threat.check_urlhaus", return_value={"url_count": 3, "urls_online": 1})
    @patch("domain.recon.check_ct_logs", return_value={"total_certificates": 0, "certificates": []})
    @patch(
        "domain.recon.enumerate_subdomains", return_value={"subdomains": ["a.example.com", "b.example.com"], "count": 2}
    )
    @patch("domain.recon._fetch_crtsh", return_value=([], None))
    @patch("domain.recon.ssl_info", return_value={"issuer": "DigiCert", "grade": "B"})
    @patch("domain.recon.whois_lookup", return_value={})
    @patch("domain.recon.reverse_dns", return_value={"ip": "5.5.5.5", "ptr": None})
    @patch("domain.recon.dns_lookup", return_value={"a": ["5.5.5.5"]})
    def test_summary_contains_key_info(
        self, m_dns, m_rdns, m_whois, m_ssl, m_crtsh, m_subs, m_ct, m_threat, m_email, m_headers, m_score
    ):
        from domain.recon import full_domain_report

        m_headers.return_value = {"headers": {"server": "cloudflare"}}
        m_score.return_value = {"grade": "C", "score": 55, "factors": []}
        result = full_domain_report("example.com", resolved_ip="5.5.5.5")
        summary = result["summary"]
        assert "example.com" in summary
        assert "5.5.5.5" in summary
        assert "2 subdomains" in summary
        assert "URLhaus" in summary


# =========== ssl_info unit tests ===========


class TestSslInfo:
    @patch("domain.recon.ssl.create_default_context")
    @patch("domain.recon.socket.create_connection")
    def test_successful_cert_parsing(self, mock_conn, mock_ctx):
        from domain.recon import ssl_info

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "notAfter": "Dec 31 23:59:59 2026 GMT",
            "notBefore": "Jan 01 00:00:00 2026 GMT",
            "serialNumber": "ABCDEF",
            "version": 3,
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        }
        mock_ssock.selected_alpn_protocol.return_value = "h2"
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        mock_ctx_inst = MagicMock()
        mock_ctx.return_value = mock_ctx_inst
        mock_ctx_inst.wrap_socket.return_value = mock_ssock

        result = ssl_info("example.com", resolved_ip="1.2.3.4")
        assert result["common_name"] == "example.com"
        assert result["issuer"] == "Let's Encrypt"
        assert result["tls_version"] == "TLSv1.3"
        assert result["alpn"] == "h2"
        assert "www.example.com" in result["san"]
        assert result["grade"] == "A"

    @patch("domain.recon.ssl.create_default_context")
    @patch("domain.recon.socket.create_connection")
    def test_expired_cert_grade_f(self, mock_conn, mock_ctx):
        from domain.recon import ssl_info

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "subject": ((("commonName", "expired.com"),),),
            "issuer": ((("organizationName", "LE"),),),
            "notAfter": "Jan 01 00:00:00 2020 GMT",
            "notBefore": "Jan 01 00:00:00 2019 GMT",
            "serialNumber": "123",
            "version": 3,
            "subjectAltName": (),
        }
        mock_ssock.selected_alpn_protocol.return_value = None
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        mock_ctx_inst = MagicMock()
        mock_ctx.return_value = mock_ctx_inst
        mock_ctx_inst.wrap_socket.return_value = mock_ssock

        result = ssl_info("expired.com")
        assert result["grade"] == "F"
        assert result["days_remaining"] < 0

    @patch("domain.recon.socket.create_connection", side_effect=ConnectionRefusedError("refused"))
    def test_connection_failure_fallback(self, mock_conn):
        from domain.recon import ssl_info

        result = ssl_info("unreachable.test")
        assert result["error"] == "SSL lookup failed"
        assert result["grade"] == "F"


# =========== /v1/scan/headers/{domain} route tests ===========


class TestScanHeadersRoute:
    @patch("codesec.routes.fetch_live_headers")
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

    @patch("codesec.routes.fetch_live_headers")
    @patch("codesec.routes.validate_domain", return_value="1.2.3.4")
    def test_scan_headers_connection_failure_504(self, mock_validate, mock_fetch):
        mock_fetch.return_value = {"error": "Could not connect to fail.test"}
        r = client.get("/v1/scan/headers/fail.test")
        assert r.status_code == 504


# =========== enumerate_subdomains unit tests ===========


class TestEnumerateSubdomains:
    @patch("domain.recon._fetch_crtsh", return_value=([{"name_value": "ct.example.com"}], None))
    @patch("domain.recon.socket.gethostbyname")
    def test_dns_brute_and_crtsh_merge(self, mock_resolve, mock_crtsh):
        from domain.recon import enumerate_subdomains

        def gethostbyname_side(fqdn):
            if fqdn == "www.example.com":
                return "93.184.216.34"
            if fqdn == "api.example.com":
                return "93.184.216.35"
            raise socket.gaierror("not found")

        mock_resolve.side_effect = gethostbyname_side
        result = enumerate_subdomains("example.com")
        subs = result["subdomains"]
        assert "www.example.com" in subs
        assert "api.example.com" in subs
        assert "ct.example.com" in subs
        assert result["count"] == 3

    @patch("domain.recon._fetch_crtsh", return_value=([], None))
    @patch("domain.recon.socket.gethostbyname")
    def test_private_ip_filtered(self, mock_resolve, mock_crtsh):
        from domain.recon import enumerate_subdomains

        def gethostbyname_side(fqdn):
            if fqdn == "www.example.com":
                return "192.168.1.1"  # private
            if fqdn == "api.example.com":
                return "8.8.8.8"  # public
            raise socket.gaierror("not found")

        mock_resolve.side_effect = gethostbyname_side
        result = enumerate_subdomains("example.com")
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
    )
    @patch("domain.recon.socket.gethostbyname")
    def test_set_deduplication(self, mock_resolve, mock_crtsh):
        from domain.recon import enumerate_subdomains

        def gethostbyname_side(fqdn):
            if fqdn == "www.example.com":
                return "93.184.216.34"
            raise socket.gaierror("not found")

        mock_resolve.side_effect = gethostbyname_side
        result = enumerate_subdomains("example.com")
        assert result["subdomains"].count("www.example.com") == 1


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
        mock_txt.__str__ = lambda s: '"v=spf1 include:_spf.google.com -all"'

        def resolve_side(domain, rtype):
            if rtype == "TXT":
                return [mock_txt]
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = resolve_side
        result = dns_lookup("example.com")
        assert "txt" in result
        assert result["txt"][0] == "v=spf1 include:_spf.google.com -all"


# =========== routes.py IP endpoint reputation tests ===========


class TestIpRouteReputation:
    @patch("domain.routes.authenticate", return_value={"tier": "pro"})
    @patch("domain.routes.save_cached_ip")
    @patch("domain.routes.get_cached_ip_with_age", return_value=None)
    @patch("domain.routes.ratelimit.check_limit", return_value=True)
    @patch("domain.routes.check_shodan", return_value={"status": "ok", "ports": [80]})
    @patch("domain.routes.check_abuseipdb", return_value={"status": "ok", "abuse_score": 10})
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

    @patch("domain.routes.authenticate", return_value={"tier": "free"})
    @patch("domain.routes.get_cached_ip_with_age", return_value=None)
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
    )
    @patch("domain.routes.socket.gethostbyaddr", return_value=("example.com", [], []))
    def test_ip_without_reputation_limit_exceeded(self, mock_ptr, mock_enrich, mock_limit, mock_cache_get, mock_auth):
        """Free tier always gets pro_only stub; quota limit is irrelevant."""
        r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        data = r.json()
        assert data["reputation"]["abuseipdb"]["status"] == "pro_only"
        assert data["reputation"]["shodan"]["status"] == "pro_only"
        assert data["ports"] == [22, 80]
        assert "CVE-2024-1234" in data["vulns"]

    @patch("domain.routes.authenticate", return_value={"tier": "free"})
    @patch("domain.routes.check_abuseipdb")
    @patch("domain.routes.check_shodan")
    @patch(
        "domain.routes.get_cached_ip_with_age",
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
    @patch("domain.reputation.ABUSEIPDB_API_KEY", "test-key")
    def test_abuseipdb_429(self, mock_client):
        from domain.reputation import check_abuseipdb

        mock_client.get.return_value = _mock_httpx_response(429)
        result = check_abuseipdb("1.2.3.4")
        assert result["status"] == "rate_limited"

    @patch("domain.reputation._client")
    @patch("domain.reputation.SHODAN_API_KEY", "test-key")
    def test_shodan_429(self, mock_client):
        from domain.reputation import check_shodan

        mock_client.get.return_value = _mock_httpx_response(429)
        result = check_shodan("1.2.3.4")
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
    @patch("domain.routes.authenticate", return_value={"tier": "free"})
    @patch("domain.routes.check_urlhaus", return_value={"urlhaus_status": "clean", "urls_online": 0, "url_count": 0})
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_threat_clean(self, mock_validate, mock_urlhaus, mock_auth):
        r = client.get("/v1/threat/example.com")
        assert r.status_code == 200
        assert "no threats" in r.json()["summary"]

    @patch("domain.routes.authenticate", return_value={"tier": "free"})
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
    )
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_threat_listed(self, mock_validate, mock_urlhaus, mock_auth):
        r = client.get("/v1/threat/example.com")
        assert r.status_code == 200
        data = r.json()
        assert "3 URL" in data["summary"]
        assert data["urls_online"] == 2

    @patch("domain.routes.authenticate", return_value={"tier": "free"})
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

    @patch("domain.routes.authenticate", return_value={"tier": "free"})
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

    @patch("domain.scoring.score_domain", return_value={"grade": "A", "score": 90, "factors": []})
    @patch("domain.recon.fetch_live_headers", return_value={"headers": {}})
    @patch("domain.recon.email_security", return_value={"grade": "A"})
    @patch("domain.threat.check_urlhaus", return_value={"url_count": 0, "urls_online": 0})
    @patch("domain.recon.check_ct_logs", return_value={"total_certificates": 0, "certificates": []})
    @patch("domain.recon.enumerate_subdomains", return_value={"subdomains": [], "count": 0})
    @patch("domain.recon._fetch_crtsh", return_value=([], None))
    @patch("domain.recon.ssl_info", return_value={"issuer": "LE", "grade": "B"})
    @patch("domain.recon.whois_lookup", return_value={})
    @patch("domain.recon.reverse_dns", return_value={"ip": "1.2.3.4", "ptr": None})
    @patch("domain.recon.dns_lookup", return_value={"a": ["1.2.3.4"]})
    @patch("domain.recon.ratelimit")
    @patch("db.get_cached_ip", return_value=None)
    @patch("domain.reputation.check_shodan", side_effect=AssertionError("Shodan must not be called for free tier"))
    @patch(
        "domain.reputation.check_abuseipdb", side_effect=AssertionError("AbuseIPDB must not be called for free tier")
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
        result = full_domain_report("example.com", resolved_ip="1.2.3.4", client_ip="10.0.0.1", tier="free")
        assert "reputation" in result
        assert result["reputation"]["abuseipdb"]["status"] == "pro_only"
        assert result["reputation"]["abuseipdb"]["upgrade_url"] == "https://contrastcyber.com/pricing"
        assert result["reputation"]["shodan"]["status"] == "pro_only"
        assert result["reputation"]["shodan"]["upgrade_url"] == "https://contrastcyber.com/pricing"

    @patch("domain.scoring.score_domain", return_value={"grade": "A", "score": 90, "factors": []})
    @patch("domain.recon.fetch_live_headers", return_value={"headers": {}})
    @patch("domain.recon.email_security", return_value={"grade": "A"})
    @patch("domain.threat.check_urlhaus", return_value={"url_count": 0, "urls_online": 0})
    @patch("domain.recon.check_ct_logs", return_value={"total_certificates": 0, "certificates": []})
    @patch("domain.recon.enumerate_subdomains", return_value={"subdomains": [], "count": 0})
    @patch("domain.recon._fetch_crtsh", return_value=([], None))
    @patch("domain.recon.ssl_info", return_value={"issuer": "LE", "grade": "A"})
    @patch("domain.recon.whois_lookup", return_value={})
    @patch("domain.recon.reverse_dns", return_value={"ip": "1.2.3.4", "ptr": None})
    @patch("domain.recon.dns_lookup", return_value={"a": ["1.2.3.4"]})
    @patch("domain.recon.ratelimit")
    @patch("db.save_cached_ip")
    @patch("db.get_cached_ip", return_value=None)
    @patch("domain.reputation.check_shodan", return_value={"status": "ok", "mock": True})
    @patch("domain.reputation.check_abuseipdb", return_value={"status": "ok", "mock": True})
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
        result = full_domain_report("example.com", resolved_ip="1.2.3.4", client_ip="10.0.0.1", tier="pro")
        m_ab.assert_called_once()
        m_sh.assert_called_once()
        assert result["reputation"]["abuseipdb"]["status"] == "ok"
        assert result["reputation"]["shodan"]["status"] == "ok"

    # --- /v1/ip route tests ---

    @patch("domain.routes.authenticate", return_value={"tier": "free"})
    @patch("domain.routes.get_cached_ip_with_age", return_value=None)
    @patch("domain.routes.ratelimit.check_limit", return_value=True)
    @patch("domain.routes.check_shodan", side_effect=AssertionError("Shodan must not be called for free tier"))
    @patch("domain.routes.check_abuseipdb", side_effect=AssertionError("AbuseIPDB must not be called for free tier"))
    @patch("domain.routes.ip_enrichment", return_value=_ENRICH_EMPTY)
    @patch("domain.routes.socket.gethostbyaddr", return_value=("example.com", [], []))
    def test_ip_lookup_free_tier_enrichment_pro_only(
        self, mock_ptr, mock_enrich, mock_ab, mock_sh, mock_limit, mock_cache, mock_auth
    ):
        """Free tier /v1/ip: pro_only stub returned, no live API calls."""
        r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        data = r.json()
        assert "reputation" in data
        assert data["reputation"]["abuseipdb"]["status"] == "pro_only"
        assert data["reputation"]["abuseipdb"]["upgrade_url"] == "https://contrastcyber.com/pricing"
        assert data["reputation"]["shodan"]["status"] == "pro_only"
        assert data["reputation"]["shodan"]["upgrade_url"] == "https://contrastcyber.com/pricing"

    # --- /v1/threat-report route tests ---

    @patch("domain.routes.authenticate", return_value={"tier": "free"})
    @patch("domain.routes._ripe_client")
    @patch("domain.routes.check_shodan", side_effect=AssertionError("Shodan must not be called for free tier"))
    @patch("domain.routes.check_abuseipdb", side_effect=AssertionError("AbuseIPDB must not be called for free tier"))
    @patch(
        "domain.routes.ip_enrichment", return_value={"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": []}
    )
    def test_threat_report_free_tier_enrichment_pro_only(self, mock_enrich, mock_ab, mock_sh, mock_ripe, mock_auth):
        """Free tier /v1/threat-report: pro_only stub returned, no live API calls."""
        mock_ripe.get.side_effect = Exception("no network")
        r = client.get("/v1/threat-report/8.8.8.8")
        assert r.status_code == 200
        data = r.json()
        assert data["abuseipdb"]["status"] == "pro_only"
        assert data["abuseipdb"]["upgrade_url"] == "https://contrastcyber.com/pricing"
        assert data["shodan"]["status"] == "pro_only"
        assert data["shodan"]["upgrade_url"] == "https://contrastcyber.com/pricing"

    # --- Cache bypass test ---

    @patch("domain.routes.authenticate", return_value={"tier": "free"})
    @patch("domain.routes.check_shodan", side_effect=AssertionError("Shodan must not be called — cache hit"))
    @patch("domain.routes.check_abuseipdb", side_effect=AssertionError("AbuseIPDB must not be called — cache hit"))
    @patch(
        "domain.routes.get_cached_ip_with_age",
        return_value=(
            {"abuseipdb": {"status": "ok", "abuse_score": 0}, "shodan": {"status": "ok", "ports": [443]}},
            3600,
        ),
    )
    @patch("domain.routes.ip_enrichment", return_value=_ENRICH_EMPTY)
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
    @patch("domain.routes.authenticate", return_value={"tier": "free"})
    @patch("domain.routes.get_cached_ip_with_age", return_value=None)
    @patch("domain.routes.check_shodan", side_effect=AssertionError("Shodan must not be called for free tier"))
    @patch("domain.routes.check_abuseipdb", side_effect=AssertionError("AbuseIPDB must not be called for free tier"))
    @patch("domain.routes.ip_enrichment", return_value=_ENRICH_EMPTY)
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
        assert rep["abuseipdb"]["status"] == "pro_only"
        assert rep["shodan"]["status"] == "pro_only"

    @pytest.mark.real_firehol
    @patch("domain.routes.authenticate", return_value={"tier": "pro"})
    @patch("domain.routes.get_cached_ip_with_age", return_value=None)
    @patch("domain.routes.ratelimit.check_limit", return_value=True)
    @patch("domain.routes.save_cached_ip")
    @patch("domain.routes.ip_enrichment", return_value=_ENRICH_EMPTY)
    @patch("domain.routes.socket.gethostbyaddr", return_value=("example.com", [], []))
    @patch("domain.routes.check_shodan", return_value={"status": "ok", "ports": []})
    @patch("domain.routes.check_abuseipdb", return_value={"status": "ok", "abuse_score": 0})
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
    @patch("domain.recon.fetch_live_headers", return_value={"headers": {}})
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.full_domain_report", return_value={"domain": "example.com", "summary": "ok"})
    @patch("domain.routes.clean_domain", return_value="example.com")
    @patch("domain.routes.authenticate", return_value={"tier": "pro", "key_hash": "h", "client_ip": "10.0.0.1"})
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

    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.get_cached_domain_with_age", return_value=None)
    @patch("domain.routes.full_domain_report", return_value={"domain": "example.com", "summary": "ok"})
    @patch("domain.routes._validate_and_auth")
    def test_domain_report_cache_keys_tier_segregated(self, mock_auth, mock_report, mock_get, mock_save):
        """Free stub must not poison Pro cache — tier prefix segregates cache keys."""
        # Free tier request
        mock_auth.return_value = ("example.com", "1.2.3.4", {"tier": "free", "key_hash": None, "client_ip": "10.0.0.1"})
        r_free = client.get("/v1/domain/example.com")
        assert r_free.status_code == 200
        free_read_key = mock_get.call_args[0][0]
        free_save_key = mock_save.call_args[0][0]
        assert free_read_key == "free:example.com"
        assert free_save_key == "free:example.com"

        # Pro tier request — must check a DIFFERENT cache key, not the free one
        mock_get.reset_mock()
        mock_save.reset_mock()
        mock_auth.return_value = ("example.com", "1.2.3.4", {"tier": "pro", "key_hash": "h", "client_ip": "10.0.0.2"})
        r_pro = client.get("/v1/domain/example.com")
        assert r_pro.status_code == 200
        pro_read_key = mock_get.call_args[0][0]
        pro_save_key = mock_save.call_args[0][0]
        assert pro_read_key == "pro:example.com", f"Pro read hit free key — poisoning risk: {pro_read_key}"
        assert pro_save_key == "pro:example.com"
        assert pro_read_key != free_read_key
