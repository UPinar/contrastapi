"""Tests for technology fingerprinting, monitor, and vulns endpoints."""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

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
    @patch("domain.routes.fetch_live_page", new_callable=AsyncMock)
    @patch("domain.routes._validate_domain_input")
    def test_tech_200(self, mock_validate, mock_page):
        mock_validate.return_value = ("example.com", "93.184.216.34")
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

    @patch("domain.routes.fetch_live_page", new_callable=AsyncMock)
    @patch("domain.routes._validate_domain_input")
    def test_tech_504_on_connection_failure(self, mock_validate, mock_page):
        mock_validate.return_value = ("down.com", "1.2.3.4")
        mock_page.return_value = {"error": "Could not connect to down.com"}
        r = client.get("/v1/tech/down.com")
        assert r.status_code == 504

    @patch("domain.routes.fetch_live_page", new_callable=AsyncMock)
    @patch("domain.routes._validate_domain_input")
    def test_tech_returns_domain_and_technologies(self, mock_validate, mock_page):
        mock_validate.return_value = ("test.com", "1.2.3.4")
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
    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.ssl_info", return_value={"grade": "A", "days_remaining": 90})
    @patch("domain.routes.quick_dns_a", return_value=["93.184.216.34"])
    @patch("domain.routes._validate_domain_input")
    def test_monitor_200_up(self, mock_validate, mock_dns, mock_ssl, mock_cache):
        mock_validate.return_value = ("example.com", "93.184.216.34")
        r = client.get("/v1/monitor/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "example.com"
        assert data["is_up"] is True
        assert data["ssl_grade"] == "A"
        assert data["ssl_days_remaining"] == 90
        assert data["dns_a"] == ["93.184.216.34"]
        assert "up" in data["summary"]

    @patch("db.get_cached_domain", return_value=None)
    @patch("domain.routes.ssl_info", side_effect=Exception("TLS handshake failed"))
    @patch("domain.routes.quick_dns_a", return_value=[])
    @patch("domain.routes._validate_domain_input")
    def test_monitor_200_down(self, mock_validate, mock_dns, mock_ssl, mock_cache):
        mock_validate.return_value = ("down.com", "1.2.3.4")
        r = client.get("/v1/monitor/down.com")
        assert r.status_code == 200
        data = r.json()
        assert data["is_up"] is False
        assert "ssl_grade" not in data  # excluded by response_model_exclude_none
        assert "DOWN" in data["summary"]

    @patch("db.get_cached_domain")
    @patch("domain.routes.ssl_info", return_value={"grade": "B", "days_remaining": 30})
    @patch("domain.routes.quick_dns_a", return_value=["1.2.3.4"])
    @patch("domain.routes._validate_domain_input")
    def test_monitor_dns_changed(self, mock_validate, mock_dns, mock_ssl, mock_cache):
        mock_validate.return_value = ("example.com", "1.2.3.4")
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
    @patch("db.search_cves_by_products_bulk", return_value={})
    @patch("domain.routes.fetch_live_page", new_callable=AsyncMock)
    @patch("domain.routes._validate_domain_input")
    def test_vulns_200_no_cves(self, mock_validate, mock_page, mock_search):
        mock_validate.return_value = ("example.com", "93.184.216.34")
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

    @patch("db.search_cves_by_products_bulk")
    @patch("domain.routes.fetch_live_page", new_callable=AsyncMock)
    @patch("domain.routes._validate_domain_input")
    def test_vulns_200_with_cves(self, mock_validate, mock_page, mock_search):
        mock_validate.return_value = ("vuln.com", "1.2.3.4")
        mock_page.return_value = {
            "headers": {"server": "Apache/2.4"},
            "html": "",
            "status_code": 200,
        }
        mock_search.return_value = {
            "apache": [
                {"cve_id": "CVE-2024-1234", "severity": "HIGH", "cvss_v3": 8.1, "epss_score": 0.5, "in_kev": True},
            ]
        }
        r = client.get("/v1/domain/vuln.com/vulns")
        assert r.status_code == 200
        data = r.json()
        assert data["total_cves"] >= 1
        assert len(data["vulnerabilities"]) >= 1
        assert "CVE" in data["summary"]
        assert mock_search.call_count == 1

    @patch("domain.routes.fetch_live_page", new_callable=AsyncMock)
    @patch("domain.routes._validate_domain_input")
    def test_vulns_504_on_page_error(self, mock_validate, mock_page):
        mock_validate.return_value = ("down.com", "1.2.3.4")
        mock_page.return_value = {"error": "Connection refused"}
        r = client.get("/v1/domain/down.com/vulns")
        assert r.status_code == 504

    @patch("db.search_cves_by_products_bulk")
    @patch("domain.routes.fetch_live_page", new_callable=AsyncMock)
    @patch("domain.routes._validate_domain_input")
    def test_vulns_bulk_called_once_with_all_techs(self, mock_validate, mock_page, mock_search):
        """Multi-tech response must trigger exactly ONE bulk DB call (not N+1)."""
        mock_validate.return_value = ("multi.com", "1.2.3.4")
        mock_page.return_value = {
            "headers": {"server": "nginx/1.24.0", "x-powered-by": "PHP/8.1.0"},
            "html": "",
            "status_code": 200,
        }
        mock_search.return_value = {}
        r = client.get("/v1/domain/multi.com/vulns")
        assert r.status_code == 200
        data = r.json()
        assert data["technologies_scanned"] >= 2
        assert mock_search.call_count == 1
        called_with = mock_search.call_args[0][0]
        assert "Nginx" in called_with
        assert "PHP" in called_with

    @patch("domain.tech.detect_technologies")
    @patch("db.search_cves_by_products_bulk")
    @patch("domain.routes.fetch_live_page", new_callable=AsyncMock)
    @patch("domain.routes._validate_domain_input")
    def test_vulns_version_filter_uses_normalized_key(self, mock_validate, mock_page, mock_search, mock_detect):
        """Regression: aliased Maven artifactId (e.g., log4j-core) must still match
        version-filtered CVEs whose affected_products use the NVD canonical name (log4j).
        The substring check must use the normalized key, not the raw tech name."""
        mock_validate.return_value = ("alias.com", "1.2.3.4")
        mock_page.return_value = {"headers": {}, "html": "", "status_code": 200}
        mock_detect.return_value = {
            "technologies": [{"name": "log4j-core", "version": "2.14.0"}],
        }
        # bulk returns under canonical key "log4j" (normalized from "log4j-core")
        mock_search.return_value = {
            "log4j": [
                {
                    "cve_id": "CVE-2021-44228",
                    "severity": "CRITICAL",
                    "cvss_v3": 10.0,
                    "epss_score": 0.97,
                    "in_kev": True,
                    "affected_products": [
                        {"product": "log4j", "version_start": "2.0", "version_end": "2.15.0"},
                    ],
                },
            ]
        }
        r = client.get("/v1/domain/alias.com/vulns")
        assert r.status_code == 200
        data = r.json()
        assert data["total_cves"] == 1, f"alias collision: log4j CVE dropped — {data}"
        assert data["vulnerabilities"][0]["cves"][0]["cve_id"] == "CVE-2021-44228"
