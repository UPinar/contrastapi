"""Tests for domain intelligence module — recon.py + routes.py"""

import json
import socket
from datetime import UTC
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import httpx
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
        result = _crtsh_subdomains("example.com", data)
        assert "www.example.com" in result
        assert "api.example.com" in result

    def test_filters_wildcards(self):
        from domain.recon import _crtsh_subdomains

        data = [{"name_value": "*.example.com"}]
        result = _crtsh_subdomains("example.com", data)
        assert len(result) == 0

    def test_filters_other_domains(self):
        from domain.recon import _crtsh_subdomains

        data = [{"name_value": "sub.other.com"}]
        result = _crtsh_subdomains("example.com", data)
        assert len(result) == 0

    def test_limits_to_50(self):
        from domain.recon import _crtsh_subdomains

        data = [{"name_value": f"sub{i}.example.com"} for i in range(100)]
        result = _crtsh_subdomains("example.com", data)
        assert len(result) <= 50

    def test_empty_data(self):
        from domain.recon import _crtsh_subdomains

        assert _crtsh_subdomains("example.com", []) == []


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
    "waf": {"detected": [], "waf_present": False},
    "summary": "example.com resolves to 93.184.216.34",
}


class TestDomainRoutes:
    @patch("domain.routes.full_domain_report", return_value=MOCK_FULL_REPORT)
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.get_cached_domain", return_value=None)
    def test_domain_report_200(self, mock_cache, mock_validate, mock_report):
        """validate_domain is called in _validate_and_auth for all routes."""
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "example.com"
        assert "dns" in data
        assert "summary" in data

    @patch("domain.routes.full_domain_report")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    @patch("domain.routes.get_cached_domain", return_value=MOCK_FULL_REPORT)
    def test_domain_report_cached(self, mock_cache, mock_validate, mock_report):
        r = client.get("/v1/domain/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["cached"] is True
        assert mock_report.call_count == 0

    @patch("domain.routes._is_valid_format", return_value=False)
    @patch("domain.routes.validate_domain", return_value=None)
    @patch("domain.routes.get_cached_domain", return_value=None)
    def test_domain_report_invalid_domain(self, mock_cache, mock_validate, mock_format):
        r = client.get("/v1/domain/nonexistent.invalid")
        assert r.status_code == 400

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
        assert r.status_code == 502

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
        return_value={"ports": [22, 80], "hostnames": [], "vulns": [], "cpes": [], "tags": []},
    )
    @patch("domain.routes.socket.gethostbyaddr", return_value=("example.com", [], []))
    def test_ip_lookup_200(self, mock_ptr, mock_enrich):
        r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        data = r.json()
        assert data["ip"] == "93.184.216.34"
        assert data["ptr"] == "example.com"

    @patch(
        "domain.routes.ip_enrichment", return_value={"ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": []}
    )
    @patch("domain.routes.socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ip_lookup_no_ptr(self, mock_ptr, mock_enrich):
        r = client.get("/v1/ip/1.2.3.4")
        assert r.status_code == 200
        data = r.json()
        assert data.get("ptr") is None


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
    @patch("domain.recon._safe_redirect_opener.open")
    def test_success(self, mock_open):
        from domain.recon import fetch_live_headers

        mock_headers = MagicMock()
        mock_headers.items.return_value = [("Content-Type", "text/html"), ("X-Frame-Options", "DENY")]
        resp = MagicMock()
        resp.headers = mock_headers
        resp.status = 200
        resp.url = "https://example.com/"
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        mock_open.return_value = resp
        result = fetch_live_headers("example.com")
        assert "headers" in result
        assert result["status_code"] == 200
        assert "x-frame-options" in result["headers"]

    @patch("domain.recon._safe_redirect_opener.open", side_effect=Exception("conn refused"))
    def test_failure(self, mock_open):
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
    @patch("domain.recon._fetch_crtsh", return_value=[])
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
    @patch("domain.recon._fetch_crtsh", return_value=[])
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
        """Reputation enrichment skipped when rate limit denies."""
        from domain.recon import full_domain_report

        m_rl.check_limit.return_value = False
        result = full_domain_report("example.com", resolved_ip="1.2.3.4", client_ip="10.0.0.1")
        assert "reputation" not in result

    @patch("domain.scoring.score_domain", return_value={"grade": "A", "score": 90, "factors": []})
    @patch("domain.recon.fetch_live_headers", return_value={"headers": {}})
    @patch("domain.recon.email_security", return_value={"grade": "A"})
    @patch("domain.threat.check_urlhaus", return_value={"url_count": 0, "urls_online": 0})
    @patch("domain.recon.check_ct_logs", return_value={"total_certificates": 0, "certificates": []})
    @patch("domain.recon.enumerate_subdomains", return_value={"subdomains": [], "count": 0})
    @patch("domain.recon._fetch_crtsh", return_value=[])
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
        """On reputation failure, rate limit quota is refunded."""
        from domain.recon import full_domain_report

        m_rl.check_limit.return_value = True
        result = full_domain_report("example.com", resolved_ip="1.2.3.4", client_ip="10.0.0.1")
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
    @patch("domain.recon._fetch_crtsh", return_value=[])
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
    def test_scan_headers_connection_failure_502(self, mock_validate, mock_fetch):
        mock_fetch.return_value = {"error": "Could not connect to fail.test"}
        r = client.get("/v1/scan/headers/fail.test")
        assert r.status_code == 502


# =========== enumerate_subdomains unit tests ===========


class TestEnumerateSubdomains:
    @patch("domain.recon._fetch_crtsh", return_value=[{"name_value": "ct.example.com"}])
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

    @patch("domain.recon._fetch_crtsh", return_value=[])
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
        return_value=[
            {"name_value": "www.example.com"},
            {"name_value": "www.example.com"},
        ],
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
    @patch("domain.routes.authenticate", return_value={"tier": "free"})
    @patch("domain.routes.save_cached_ip")
    @patch("domain.routes.get_cached_ip", return_value=None)
    @patch("domain.routes.ratelimit.check_limit", return_value=True)
    @patch("domain.routes.check_shodan", return_value={"status": "ok", "ports": [80]})
    @patch("domain.routes.check_abuseipdb", return_value={"status": "ok", "abuse_score": 10})
    @patch(
        "domain.routes.ip_enrichment",
        return_value={"ports": [22, 80], "hostnames": [], "vulns": [], "cpes": [], "tags": []},
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
    @patch("domain.routes.get_cached_ip", return_value=None)
    @patch("domain.routes.ratelimit.check_limit", return_value=False)
    @patch(
        "domain.routes.ip_enrichment",
        return_value={"ports": [22, 80], "hostnames": [], "vulns": ["CVE-2024-1234"], "cpes": [], "tags": []},
    )
    @patch("domain.routes.socket.gethostbyaddr", return_value=("example.com", [], []))
    def test_ip_without_reputation_limit_exceeded(self, mock_ptr, mock_enrich, mock_limit, mock_cache_get, mock_auth):
        r = client.get("/v1/ip/93.184.216.34")
        assert r.status_code == 200
        data = r.json()
        assert "reputation" not in data
        assert data["ports"] == [22, 80]
        assert "CVE-2024-1234" in data["vulns"]

    @patch("domain.routes.authenticate", return_value={"tier": "free"})
    @patch("domain.routes.check_abuseipdb")
    @patch("domain.routes.check_shodan")
    @patch(
        "domain.routes.get_cached_ip",
        return_value={
            "abuseipdb": {"status": "ok", "abuse_score": 0},
            "shodan": {"status": "ok", "ports": [443]},
        },
    )
    @patch(
        "domain.routes.ip_enrichment",
        return_value={"ports": [443], "hostnames": [], "vulns": [], "cpes": [], "tags": []},
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


# =========== tech.py unit tests ===========


class TestTechDetectFromHeaders:
    def test_nginx_with_version(self):
        from domain.tech import detect_technologies

        result = detect_technologies({"server": "nginx/1.24.0"})
        techs = result["technologies"]
        assert any(t["name"] == "Nginx" and t["version"] == "1.24.0" for t in techs)

    def test_apache_no_version(self):
        from domain.tech import detect_technologies

        result = detect_technologies({"server": "Apache"})
        assert any(t["name"] == "Apache" for t in result["technologies"])

    def test_php_from_powered_by(self):
        from domain.tech import detect_technologies

        result = detect_technologies({"x-powered-by": "PHP/8.2.1"})
        techs = result["technologies"]
        assert any(t["name"] == "PHP" and t["version"] == "8.2.1" for t in techs)

    def test_express_from_powered_by(self):
        from domain.tech import detect_technologies

        result = detect_technologies({"x-powered-by": "Express"})
        assert any(t["name"] == "Express.js" for t in result["technologies"])

    def test_cloudflare_from_cf_ray(self):
        from domain.tech import detect_technologies

        result = detect_technologies({"cf-ray": "abc123", "server": "cloudflare"})
        assert any(t["name"] == "Cloudflare" for t in result["technologies"])

    def test_nextjs_from_header(self):
        from domain.tech import detect_technologies

        result = detect_technologies({"x-nextjs-cache": "HIT"})
        assert any(t["name"] == "Next.js" for t in result["technologies"])

    def test_empty_headers(self):
        from domain.tech import detect_technologies

        result = detect_technologies({})
        assert result["count"] == 0
        assert result["technologies"] == []


class TestTechDetectFromCookies:
    def test_phpsessid(self):
        from domain.tech import detect_technologies

        result = detect_technologies({"set-cookie": "PHPSESSID=abc123; path=/"})
        assert any(t["name"] == "PHP" and t["source"] == "cookie" for t in result["technologies"])

    def test_laravel_session(self):
        from domain.tech import detect_technologies

        result = detect_technologies({"set-cookie": "laravel_session=xyz; path=/; httponly"})
        assert any(t["name"] == "Laravel" for t in result["technologies"])

    def test_jsessionid(self):
        from domain.tech import detect_technologies

        result = detect_technologies({"set-cookie": "JSESSIONID=abc123"})
        assert any(t["name"] == "Java" for t in result["technologies"])


class TestTechDetectFromHtml:
    def test_wordpress(self):
        from domain.tech import detect_technologies

        html = '<link rel="stylesheet" href="/wp-content/themes/theme/style.css">'
        result = detect_technologies({}, html)
        assert any(t["name"] == "WordPress" for t in result["technologies"])

    def test_wordpress_version(self):
        from domain.tech import detect_technologies

        html = '<meta name="generator" content="WordPress 6.4.2">'
        result = detect_technologies({}, html)
        techs = result["technologies"]
        assert any(t["name"] == "WordPress" and t["version"] == "6.4.2" for t in techs)

    def test_react(self):
        from domain.tech import detect_technologies

        html = '<div id="root" data-reactroot></div>'
        result = detect_technologies({}, html)
        assert any(t["name"] == "React" for t in result["technologies"])

    def test_nextjs_from_html(self):
        from domain.tech import detect_technologies

        html = '<script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>'
        result = detect_technologies({}, html)
        assert any(t["name"] == "Next.js" for t in result["technologies"])

    def test_jquery_with_version(self):
        from domain.tech import detect_technologies

        html = '<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>'
        result = detect_technologies({}, html)
        techs = result["technologies"]
        assert any(t["name"] == "jQuery" and t["version"] == "3.7.1" for t in techs)

    def test_google_analytics(self):
        from domain.tech import detect_technologies

        html = '<script src="https://www.googletagmanager.com/gtag/js?id=G-123"></script>'
        result = detect_technologies({}, html)
        assert any(t["name"] == "Google Analytics" for t in result["technologies"])

    def test_no_html(self):
        from domain.tech import detect_technologies

        result = detect_technologies({"server": "nginx"}, None)
        assert any(t["name"] == "Nginx" for t in result["technologies"])
        assert result["count"] == 1


class TestTechDeduplication:
    def test_no_duplicate_entries(self):
        from domain.tech import detect_technologies

        headers = {"x-powered-by": "PHP/8.1", "set-cookie": "PHPSESSID=abc"}
        result = detect_technologies(headers)
        php_entries = [t for t in result["technologies"] if t["name"] == "PHP"]
        assert len(php_entries) == 1

    def test_header_wins_over_cookie(self):
        from domain.tech import detect_technologies

        headers = {"x-powered-by": "PHP/8.1", "set-cookie": "PHPSESSID=abc"}
        result = detect_technologies(headers)
        php = [t for t in result["technologies"] if t["name"] == "PHP"][0]
        assert php["source"] == "header"
        assert php["version"] == "8.1"


class TestTechSummary:
    def test_summary_format(self):
        from domain.tech import detect_technologies

        result = detect_technologies({"server": "nginx/1.24.0", "x-powered-by": "PHP/8.2"})
        assert "2 technologies detected" in result["summary"]
        assert "Nginx 1.24.0" in result["summary"]

    def test_empty_summary(self):
        from domain.tech import detect_technologies

        result = detect_technologies({})
        assert result["summary"] == "No technologies detected"


class TestTechCategories:
    def test_categories_grouped(self):
        from domain.tech import detect_technologies

        headers = {"server": "nginx/1.24.0", "x-powered-by": "PHP/8.2", "cf-ray": "abc"}
        result = detect_technologies(headers)
        assert "Server" in result["categories"]
        assert "Language" in result["categories"]
        assert "CDN" in result["categories"]


class TestTechRoute:
    @patch("domain.routes.fetch_live_page")
    @patch("domain.routes._validate_and_auth")
    def test_tech_200(self, mock_validate, mock_page):
        mock_validate.return_value = ("example.com", "93.184.216.34", {"tier": "free"})
        mock_page.return_value = {
            "headers": {"server": "nginx/1.24.0", "x-powered-by": "PHP/8.2"},
            "html": '<meta name="generator" content="WordPress 6.4">',
            "status_code": 200,
        }
        r = client.get("/v1/tech/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "example.com"
        assert data["count"] >= 3
        names = [t["name"] for t in data["technologies"]]
        assert "Nginx" in names
        assert "PHP" in names
        assert "WordPress" in names

    @patch("domain.routes.fetch_live_page")
    @patch("domain.routes._validate_and_auth")
    def test_tech_502_on_connection_failure(self, mock_validate, mock_page):
        mock_validate.return_value = ("down.com", "1.2.3.4", {"tier": "free"})
        mock_page.return_value = {"error": "Could not connect to down.com"}
        r = client.get("/v1/tech/down.com")
        assert r.status_code == 502

    @patch("domain.routes.fetch_live_page")
    @patch("domain.routes._validate_and_auth")
    def test_tech_returns_domain_and_technologies(self, mock_validate, mock_page):
        mock_validate.return_value = ("test.com", "1.2.3.4", {"tier": "free"})
        mock_page.return_value = {
            "headers": {"server": "Apache/2.4"},
            "html": "",
            "status_code": 200,
        }
        r = client.get("/v1/tech/test.com")
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "test.com"
        assert "technologies" in data
        assert "count" in data


# =========== /v1/monitor/{domain} route tests ===========


class TestMonitorRoute:
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.ssl_info", return_value={"grade": "A", "days_remaining": 90})
    @patch("domain.routes.quick_dns_a", return_value=["93.184.216.34"])
    @patch("domain.routes._validate_and_auth")
    def test_monitor_200_up(self, mock_validate, mock_dns, mock_ssl, mock_cache):
        mock_validate.return_value = ("example.com", "93.184.216.34", {"tier": "free"})
        r = client.get("/v1/monitor/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "example.com"
        assert data["is_up"] is True
        assert data["ssl_grade"] == "A"
        assert data["ssl_days_remaining"] == 90
        assert data["dns_a"] == ["93.184.216.34"]
        assert "up" in data["summary"]

    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.ssl_info", side_effect=Exception("TLS handshake failed"))
    @patch("domain.routes.quick_dns_a", return_value=[])
    @patch("domain.routes._validate_and_auth")
    def test_monitor_200_down(self, mock_validate, mock_dns, mock_ssl, mock_cache):
        mock_validate.return_value = ("down.com", "1.2.3.4", {"tier": "free"})
        r = client.get("/v1/monitor/down.com")
        assert r.status_code == 200
        data = r.json()
        assert data["is_up"] is False
        assert "ssl_grade" not in data  # excluded by response_model_exclude_none
        assert "DOWN" in data["summary"]

    @patch("domain.routes.get_cached_domain")
    @patch("domain.routes.ssl_info", return_value={"grade": "B", "days_remaining": 30})
    @patch("domain.routes.quick_dns_a", return_value=["1.2.3.4"])
    @patch("domain.routes._validate_and_auth")
    def test_monitor_dns_changed(self, mock_validate, mock_dns, mock_ssl, mock_cache):
        mock_validate.return_value = ("example.com", "1.2.3.4", {"tier": "free"})
        mock_cache.return_value = {
            "fetched_at": "2025-01-01T00:00:00",
            "risk": {"grade": "B", "score": 70},
            "dns": {"a": ["5.5.5.5"]},
        }
        r = client.get("/v1/monitor/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["dns_changed"] is True
        assert data["risk_grade"] == "B"
        assert "DNS CHANGED" in data["summary"]


# =========== /v1/domain/{domain}/vulns route tests ===========


class TestVulnsRoute:
    @patch("db.search_cves_by_product", return_value=[])
    @patch("domain.routes.fetch_live_page")
    @patch("domain.routes._validate_and_auth")
    def test_vulns_200_no_cves(self, mock_validate, mock_page, mock_search):
        mock_validate.return_value = ("example.com", "93.184.216.34", {"tier": "free"})
        mock_page.return_value = {
            "headers": {"server": "nginx/1.24.0"},
            "html": "",
            "status_code": 200,
        }
        r = client.get("/v1/domain/example.com/vulns")
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "example.com"
        assert data["total_cves"] == 0
        assert data["technologies_scanned"] >= 1
        assert "No known CVEs" in data["summary"]
        assert "vulnerabilities" in data

    @patch("db.search_cves_by_product")
    @patch("domain.routes.fetch_live_page")
    @patch("domain.routes._validate_and_auth")
    def test_vulns_200_with_cves(self, mock_validate, mock_page, mock_search):
        mock_validate.return_value = ("vuln.com", "1.2.3.4", {"tier": "free"})
        mock_page.return_value = {
            "headers": {"server": "Apache/2.4"},
            "html": "",
            "status_code": 200,
        }
        mock_search.return_value = [
            {"cve_id": "CVE-2024-1234", "severity": "HIGH", "cvss_v3": 8.1, "epss_score": 0.5, "in_kev": True},
        ]
        r = client.get("/v1/domain/vuln.com/vulns")
        assert r.status_code == 200
        data = r.json()
        assert data["total_cves"] >= 1
        assert len(data["vulnerabilities"]) >= 1
        assert "CVE" in data["summary"]

    @patch("domain.routes.fetch_live_page")
    @patch("domain.routes._validate_and_auth")
    def test_vulns_502_on_page_error(self, mock_validate, mock_page):
        mock_validate.return_value = ("down.com", "1.2.3.4", {"tier": "free"})
        mock_page.return_value = {"error": "Connection refused"}
        r = client.get("/v1/domain/down.com/vulns")
        assert r.status_code == 502


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
        assert r.status_code == 502

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
