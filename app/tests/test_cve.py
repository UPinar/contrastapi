"""Tests for CVE Intelligence module — routes.py + sync.py"""

from datetime import UTC
from unittest.mock import MagicMock, patch

import httpx
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def _seed_cve(**overrides):
    """Insert a test CVE and return the data dict."""
    from db import upsert_cve

    data = {
        "cve_id": "CVE-2024-1234",
        "description": "Test buffer overflow in nginx",
        "severity": "HIGH",
        "cvss_v3": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-120",
        "published": "2024-06-15T00:00:00Z",
        "modified": "2024-06-16T00:00:00Z",
        "epss_score": 0.72,
        "epss_percentile": 0.95,
        "in_kev": 1,
        "kev_date_added": "2024-06-20",
        "affected_products": [{"vendor": "nginx", "product": "nginx"}],
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
        "summary": "HIGH buffer overflow in nginx. CVSS 8.8.",
    }
    data.update(overrides)
    upsert_cve(data)
    return data


# =========== routes.py tests ===========


class TestCveLookup:
    def test_lookup_200(self):
        _seed_cve()
        r = client.get("/v1/cve/CVE-2024-1234")
        assert r.status_code == 200
        data = r.json()
        assert data["cve_id"] == "CVE-2024-1234"
        assert data["severity"] == "HIGH"
        assert data["cvss_v3"] == 8.8
        assert data["epss"]["score"] == 0.72
        assert data["kev"]["in_kev"] is True
        assert "summary" in data
        assert "references" in data
        assert "affected_products" in data

    def test_lookup_case_insensitive(self):
        _seed_cve()
        r = client.get("/v1/cve/cve-2024-1234")
        assert r.status_code == 200
        assert r.json()["cve_id"] == "CVE-2024-1234"

    def test_lookup_404(self):
        r = client.get("/v1/cve/CVE-9999-0000")
        assert r.status_code == 404

    def test_lookup_invalid_format(self):
        r = client.get("/v1/cve/not-a-cve")
        assert r.status_code == 400

    def test_lookup_short_id(self):
        r = client.get("/v1/cve/CVE-24-1")
        assert r.status_code == 400


class TestCveSearch:
    def test_search_by_severity(self):
        _seed_cve(cve_id="CVE-2024-0001", severity="CRITICAL")
        _seed_cve(cve_id="CVE-2024-0002", severity="LOW")
        r = client.get("/v1/cves?severity=CRITICAL")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] >= 1
        assert all(c["severity"] == "CRITICAL" for c in data["results"])

    def test_search_by_product(self):
        _seed_cve(cve_id="CVE-2024-0010", description="XSS in apache httpd")
        _seed_cve(cve_id="CVE-2024-0011", description="Bug in nodejs")
        r = client.get("/v1/cves?product=apache")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] >= 1
        cve_ids = [c["cve_id"] for c in data["results"]]
        assert "CVE-2024-0010" in cve_ids

    def test_search_invalid_severity(self):
        r = client.get("/v1/cves?severity=EXTREME")
        assert r.status_code == 400

    def test_search_limit(self):
        for i in range(5):
            _seed_cve(cve_id=f"CVE-2024-100{i}", severity="HIGH")
        r = client.get("/v1/cves?severity=HIGH&limit=3")
        assert r.status_code == 200
        assert r.json()["count"] <= 3

    def test_search_empty_result(self):
        r = client.get("/v1/cves?product=nonexistentproduct999")
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_search_by_days(self):
        from datetime import datetime, timedelta

        now = datetime.now(UTC).isoformat()
        old = (datetime.now(UTC) - timedelta(days=10)).isoformat()
        _seed_cve(cve_id="CVE-2024-2001", published=now)
        _seed_cve(cve_id="CVE-2024-2002", published=old)
        r = client.get("/v1/cves?days=1")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2024-2001" in cve_ids
        assert "CVE-2024-2002" not in cve_ids


class TestCveRecent:
    def test_recent_200(self):
        from datetime import datetime

        now = datetime.now(UTC).isoformat()
        _seed_cve(cve_id="CVE-2024-3001", published=now)
        r = client.get("/v1/cves/recent?hours=1")
        assert r.status_code == 200
        data = r.json()
        assert data["hours"] == 1
        assert data["count"] >= 1

    def test_recent_empty(self):
        r = client.get("/v1/cves/recent?hours=1")
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_recent_respects_limit(self):
        from datetime import datetime

        now = datetime.now(UTC).isoformat()
        for i in range(5):
            _seed_cve(cve_id=f"CVE-2024-400{i}", published=now)
        r = client.get("/v1/cves/recent?hours=1&limit=2")
        assert r.status_code == 200
        assert r.json()["count"] <= 2


class TestCveKev:
    def test_kev_200(self):
        _seed_cve(cve_id="CVE-2024-5001", in_kev=1, kev_date_added="2024-06-01")
        _seed_cve(cve_id="CVE-2024-5002", in_kev=0)
        r = client.get("/v1/cves/kev")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] >= 1
        assert all(c["kev"]["in_kev"] is True for c in data["results"])

    def test_kev_empty(self):
        r = client.get("/v1/cves/kev")
        assert r.status_code == 200
        assert r.json()["count"] == 0


class TestEpssScore:
    def test_epss_200(self):
        _seed_cve(cve_id="CVE-2024-6001", epss_score=0.89, epss_percentile=0.99)
        r = client.get("/v1/epss/CVE-2024-6001")
        assert r.status_code == 200
        data = r.json()
        assert data["score"] == 0.89
        assert data["percentile"] == 0.99

    def test_epss_404(self):
        r = client.get("/v1/epss/CVE-9999-0000")
        assert r.status_code == 404

    def test_epss_invalid_format(self):
        r = client.get("/v1/epss/not-a-cve")
        assert r.status_code == 400


class TestCveResponseFormat:
    def test_response_has_all_fields(self):
        _seed_cve()
        r = client.get("/v1/cve/CVE-2024-1234")
        data = r.json()
        expected_keys = {
            "cve_id",
            "summary",
            "description",
            "severity",
            "cvss_v3",
            "cvss_vector",
            "cwe_id",
            "epss",
            "kev",
            "affected_products",
            "published",
            "modified",
            "references",
        }
        # cvss_breakdown is present because _seed_cve provides a cvss_vector
        expected_keys.add("cvss_breakdown")
        assert expected_keys == set(data.keys())

    def test_epss_nested_format(self):
        _seed_cve()
        data = client.get("/v1/cve/CVE-2024-1234").json()
        assert "score" in data["epss"]
        assert "percentile" in data["epss"]

    def test_kev_nested_format(self):
        _seed_cve()
        data = client.get("/v1/cve/CVE-2024-1234").json()
        assert "in_kev" in data["kev"]
        assert "date_added" in data["kev"]


# =========== routes.py — _format_cve + _generate_summary ===========


class TestGenerateSummary:
    def test_summary_auto_generated(self):
        """CVE without explicit summary gets one generated."""
        _seed_cve(cve_id="CVE-2024-7001", summary=None)
        r = client.get("/v1/cve/CVE-2024-7001")
        data = r.json()
        assert data["summary"]
        assert "HIGH" in data["summary"]

    def test_summary_includes_kev(self):
        _seed_cve(cve_id="CVE-2024-7002", summary=None, in_kev=1)
        data = client.get("/v1/cve/CVE-2024-7002").json()
        assert "KEV" in data["summary"]

    def test_summary_includes_epss(self):
        _seed_cve(cve_id="CVE-2024-7003", summary=None, epss_score=0.85)
        data = client.get("/v1/cve/CVE-2024-7003").json()
        assert "85%" in data["summary"]


# =========== sync.py unit tests ===========


class TestParseNvdCve:
    def test_parse_basic(self):
        from cve.sync import _parse_nvd_cve

        item = {
            "cve": {
                "id": "CVE-2024-9999",
                "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 7.5,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                "baseSeverity": "HIGH",
                            }
                        }
                    ]
                },
                "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                "published": "2024-01-01T00:00:00Z",
                "lastModified": "2024-01-02T00:00:00Z",
                "references": [{"url": "https://example.com"}],
                "configurations": [],
            }
        }
        result = _parse_nvd_cve(item)
        assert result["cve_id"] == "CVE-2024-9999"
        assert result["severity"] == "HIGH"
        assert result["cvss_v3"] == 7.5
        assert result["cwe_id"] == "CWE-79"
        assert result["description"] == "Test vulnerability"
        assert len(result["refs"]) == 1

    def test_parse_with_cpe(self):
        from cve.sync import _parse_nvd_cve

        item = {
            "cve": {
                "id": "CVE-2024-8888",
                "descriptions": [{"lang": "en", "value": "Apache bug"}],
                "metrics": {},
                "weaknesses": [],
                "published": "2024-01-01T00:00:00Z",
                "lastModified": "2024-01-02T00:00:00Z",
                "references": [],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": "cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*",
                                        "versionEndExcluding": "2.4.58",
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        }
        result = _parse_nvd_cve(item)
        assert len(result["affected_products"]) == 1
        assert result["affected_products"][0]["vendor"] == "apache"
        assert result["affected_products"][0]["product"] == "http_server"

    def test_parse_empty_cve(self):
        from cve.sync import _parse_nvd_cve

        result = _parse_nvd_cve({"cve": {"id": "CVE-2024-0000"}})
        assert result["cve_id"] == "CVE-2024-0000"
        assert result["description"] == ""
        assert result["severity"] is None

    def test_parse_v2_fallback_severity(self):
        from cve.sync import _parse_nvd_cve

        item = {
            "cve": {
                "id": "CVE-2024-7777",
                "descriptions": [],
                "metrics": {"cvssMetricV2": [{"baseSeverity": "MEDIUM"}]},
                "weaknesses": [],
                "references": [],
            }
        }
        result = _parse_nvd_cve(item)
        assert result["severity"] == "MEDIUM"

    def test_parse_refs_limited_to_20(self):
        from cve.sync import _parse_nvd_cve

        refs = [{"url": f"https://example.com/{i}"} for i in range(30)]
        item = {"cve": {"id": "CVE-2024-6666", "descriptions": [], "metrics": {}, "weaknesses": [], "references": refs}}
        result = _parse_nvd_cve(item)
        assert len(result["refs"]) == 20


class TestSyncNvd:
    @patch("cve.sync._nvd_request")
    def test_delta_sync(self, mock_req):
        mock_req.return_value = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "descriptions": [{"lang": "en", "value": "Test"}],
                        "metrics": {},
                        "weaknesses": [],
                        "references": [],
                    }
                }
            ],
        }
        from cve.sync import sync_nvd

        count = sync_nvd(full=False)
        assert count == 1

    @patch("cve.sync._nvd_request")
    def test_empty_response(self, mock_req):
        mock_req.return_value = {"totalResults": 0, "vulnerabilities": []}
        from cve.sync import sync_nvd

        count = sync_nvd(full=False)
        assert count == 0


class TestSyncKev:
    @patch("cve.sync._client")
    def test_kev_sync(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "shortDescription": "Exploited vuln",
                    "dateAdded": "2024-01-15",
                }
            ]
        }
        mock_resp.raise_for_status.return_value = None
        mock_client.get.return_value = mock_resp

        from cve.sync import sync_kev

        count = sync_kev()
        assert count == 1

        from db import get_cve

        cve = get_cve("CVE-2024-0001")
        assert cve is not None
        assert cve["in_kev"] == 1


# =========== OpenAPI spec ===========


class TestCveParamBoundaries:
    def test_search_limit_exceeds_max(self):
        r = client.get("/v1/cves?limit=300")
        assert r.status_code == 422

    def test_recent_hours_exceeds_max(self):
        r = client.get("/v1/cves/recent?hours=500")
        assert r.status_code == 422

    def test_search_product_too_long(self):
        r = client.get(f"/v1/cves?product={'a' * 101}")
        assert r.status_code == 422

    def test_kev_limit_exceeds_max(self):
        r = client.get("/v1/cves/kev?limit=600")
        assert r.status_code == 422


class TestSyncEpssValidation:
    @patch("cve.sync._client")
    def test_epss_nan_filtered(self, mock_client):
        _seed_cve(cve_id="CVE-2024-NAN1", epss_score=0.5, epss_percentile=0.5)
        import gzip

        csv_content = "#model_version:v2024.01.01\ncve,epss,percentile\nCVE-2024-NAN1,NaN,0.5\n"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = gzip.compress(csv_content.encode())
        mock_resp.raise_for_status.return_value = None
        mock_client.get.return_value = mock_resp

        from cve.sync import sync_epss

        sync_epss()

        from db import get_cve

        cve = get_cve("CVE-2024-NAN1")
        assert cve["epss_score"] is None

    @patch("cve.sync._client")
    def test_epss_inf_filtered(self, mock_client):
        _seed_cve(cve_id="CVE-2024-INF1", epss_score=0.5, epss_percentile=0.5)
        import gzip

        csv_content = "#model_version:v2024.01.01\ncve,epss,percentile\nCVE-2024-INF1,Infinity,0.9\n"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = gzip.compress(csv_content.encode())
        mock_resp.raise_for_status.return_value = None
        mock_client.get.return_value = mock_resp

        from cve.sync import sync_epss

        sync_epss()

        from db import get_cve

        cve = get_cve("CVE-2024-INF1")
        assert cve["epss_score"] is None


class TestCvssVectorParser:
    def test_full_vector_parsed(self):
        from cve.routes import _parse_cvss_vector

        result = _parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")
        assert result["attack_vector"] == "Network"
        assert result["attack_complexity"] == "Low"
        assert result["privileges_required"] == "None"
        assert result["user_interaction"] == "Required"
        assert result["scope"] == "Unchanged"
        assert result["confidentiality"] == "High"
        assert result["integrity"] == "High"
        assert result["availability"] == "High"

    def test_none_vector(self):
        from cve.routes import _parse_cvss_vector

        assert _parse_cvss_vector(None) is None

    def test_empty_vector(self):
        from cve.routes import _parse_cvss_vector

        assert _parse_cvss_vector("") is None

    def test_non_v3_vector(self):
        from cve.routes import _parse_cvss_vector

        assert _parse_cvss_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None

    def test_cvss_breakdown_in_response(self):
        _seed_cve()
        r = client.get("/v1/cve/CVE-2024-1234")
        data = r.json()
        assert "cvss_breakdown" in data
        assert data["cvss_breakdown"]["attack_vector"] == "Network"

    def test_cvss_breakdown_none_when_no_vector(self):
        _seed_cve(cve_id="CVE-2024-NOVECT", cvss_vector=None)
        r = client.get("/v1/cve/CVE-2024-NOVECT")
        data = r.json()
        assert data.get("cvss_breakdown") is None


class TestOpenApiCveRoutes:
    def test_openapi_has_cve_operations(self):
        r = client.get("/openapi.json")
        data = r.json()
        operation_ids = set()
        for path_data in data.get("paths", {}).values():
            for method_data in path_data.values():
                if isinstance(method_data, dict) and "operationId" in method_data:
                    operation_ids.add(method_data["operationId"])
        assert "cve_lookup" in operation_ids
        assert "cve_search" in operation_ids
        assert "cve_recent" in operation_ids
        assert "cve_kev" in operation_ids
        assert "epss_score" in operation_ids
        assert "exploit_lookup" in operation_ids


# =========== /v1/exploit/{cve_id} tests ===========


class TestExploitLookup:
    @patch("cve.routes.save_cached_domain")
    @patch("cve.routes.get_cached_domain", return_value=None)
    def test_exploit_both_found(self, mock_cache_get, mock_cache_save):
        """CVE with GitHub advisories and ExploitDB results."""
        gh_resp = MagicMock()
        gh_resp.json.return_value = [
            {
                "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
                "summary": "Critical RCE in example",
                "severity": "critical",
                "published_at": "2024-01-15T00:00:00Z",
                "references": [{"url": "https://github.com/advisories/GHSA-xxxx"}],
            }
        ]
        gh_resp.raise_for_status = MagicMock()

        edb_resp = MagicMock()
        edb_resp.status_code = 200
        edb_resp.json.return_value = {"references": ["https://example.com/poc", "https://exploit-db.com/12345"]}
        edb_resp.raise_for_status = MagicMock()

        def mock_get(url, **kwargs):
            if "github.com" in url:
                return gh_resp
            return edb_resp

        with patch("cve.routes._exploit_client.get", side_effect=mock_get):
            r = client.get("/v1/exploit/CVE-2024-9999")
        assert r.status_code == 200
        data = r.json()
        assert data["cve_id"] == "CVE-2024-9999"
        assert data["has_public_exploit"] is True
        assert data["sources"]["github"]["found"] is True
        assert data["sources"]["github"]["count"] == 1
        assert data["sources"]["github"]["advisories"][0]["ghsa_id"] == "GHSA-xxxx-yyyy-zzzz"
        assert data["sources"]["exploitdb"]["found"] is True
        assert data["sources"]["exploitdb"]["count"] == 2
        assert data["cached"] is False

    @patch("cve.routes.save_cached_domain")
    @patch("cve.routes.get_cached_domain", return_value=None)
    def test_exploit_not_found(self, mock_cache_get, mock_cache_save):
        """CVE with no exploits found anywhere."""
        gh_resp = MagicMock()
        gh_resp.json.return_value = []
        gh_resp.raise_for_status = MagicMock()

        edb_resp = MagicMock()
        edb_resp.status_code = 404
        edb_resp.raise_for_status = MagicMock()

        def mock_get(url, **kwargs):
            if "github.com" in url:
                return gh_resp
            return edb_resp

        with patch("cve.routes._exploit_client.get", side_effect=mock_get):
            r = client.get("/v1/exploit/CVE-2024-0001")
        assert r.status_code == 200
        data = r.json()
        assert data["has_public_exploit"] is False
        assert data["exploits_found"] == 0
        assert "no public exploits" in data["summary"]

    @patch("cve.routes.save_cached_domain")
    @patch("cve.routes.get_cached_domain", return_value=None)
    def test_exploit_exploitdb_fails_gracefully(self, mock_cache_get, mock_cache_save):
        """ExploitDB timeout should not prevent GitHub results from returning."""
        gh_resp = MagicMock()
        gh_resp.json.return_value = [
            {
                "ghsa_id": "GHSA-aaaa",
                "summary": "Advisory",
                "severity": "high",
                "published_at": "2024-06-01T00:00:00Z",
                "references": [],
            }
        ]
        gh_resp.raise_for_status = MagicMock()

        def mock_get(url, **kwargs):
            if "github.com" in url:
                return gh_resp
            raise httpx.ConnectTimeout("timeout")

        with patch("cve.routes._exploit_client.get", side_effect=mock_get):
            r = client.get("/v1/exploit/CVE-2024-5555")
        assert r.status_code == 200
        data = r.json()
        assert data["sources"]["github"]["found"] is True
        assert data["sources"]["exploitdb"]["found"] is False
        assert data["has_public_exploit"] is True

    def test_exploit_invalid_cve_id(self):
        r = client.get("/v1/exploit/not-a-cve")
        assert r.status_code == 400

    def test_exploit_cached(self):
        cached_result = {
            "cve_id": "CVE-2024-1111",
            "exploits_found": 1,
            "sources": {
                "github": {"found": True, "count": 1, "advisories": []},
                "exploitdb": {"found": False, "count": 0, "results": []},
            },
            "has_public_exploit": True,
            "summary": "CVE-2024-1111 — 1 public exploit(s) found",
        }
        with patch("cve.routes.get_cached_domain", return_value=cached_result):
            r = client.get("/v1/exploit/CVE-2024-1111")
        assert r.status_code == 200
        data = r.json()
        assert data["cached"] is True
        assert data["has_public_exploit"] is True


# =========== response_model filtering tests ===========


class TestResponseModelFiltering:
    """Verify response_model_exclude_none behavior on CVE endpoints."""

    def test_cve_lookup_exclude_none(self):
        """CVE without cvss_vector → cvss_breakdown and cvss_vector absent."""
        _seed_cve(cve_id="CVE-2024-9901", cvss_vector=None, cvss_v3=None, cwe_id=None)
        r = client.get("/v1/cve/CVE-2024-9901")
        assert r.status_code == 200
        data = r.json()
        assert "cvss_breakdown" not in data
        assert "cvss_vector" not in data
        assert "cvss_v3" not in data
        assert "cwe_id" not in data

    def test_cve_search_exclude_none(self):
        """Search results exclude None fields in nested CveResponse."""
        _seed_cve(cve_id="CVE-2024-9902", severity="CRITICAL", cvss_vector=None)
        r = client.get("/v1/cves?severity=CRITICAL")
        assert r.status_code == 200
        data = r.json()
        for cve in data["results"]:
            if cve["cve_id"] == "CVE-2024-9902":
                assert "cvss_breakdown" not in cve
                break

    def test_cve_recent_exclude_none(self):
        """Recent CVEs exclude None fields."""
        from datetime import datetime

        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        _seed_cve(cve_id="CVE-2024-9903", published=now, cvss_vector=None)
        r = client.get("/v1/cves/recent?hours=1")
        assert r.status_code == 200
        data = r.json()
        for cve in data["results"]:
            if cve["cve_id"] == "CVE-2024-9903":
                assert "cvss_breakdown" not in cve
                break

    def test_cve_kev_exclude_none(self):
        """KEV results exclude None fields."""
        _seed_cve(cve_id="CVE-2024-9904", in_kev=1, cvss_vector=None)
        r = client.get("/v1/cves/kev")
        assert r.status_code == 200
        data = r.json()
        for cve in data["results"]:
            if cve["cve_id"] == "CVE-2024-9904":
                assert "cvss_breakdown" not in cve
                break

    def test_epss_exclude_none(self):
        """EPSS with None score → score absent from response."""
        _seed_cve(cve_id="CVE-2024-9905", epss_score=None, epss_percentile=None)
        r = client.get("/v1/epss/CVE-2024-9905")
        assert r.status_code == 200
        data = r.json()
        assert "score" not in data
        assert "percentile" not in data

    # --- response_shape: exact key set validation ---

    def test_cve_search_response_shape(self):
        _seed_cve(cve_id="CVE-2024-9910", severity="HIGH")
        r = client.get("/v1/cves?severity=HIGH")
        assert r.status_code == 200
        assert set(r.json().keys()) == {"count", "summary", "results"}

    def test_cve_recent_response_shape(self):
        from datetime import datetime

        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        _seed_cve(cve_id="CVE-2024-9911", published=now)
        r = client.get("/v1/cves/recent?hours=1")
        assert r.status_code == 200
        assert set(r.json().keys()) == {"count", "hours", "summary", "results"}

    def test_cve_kev_response_shape(self):
        _seed_cve(cve_id="CVE-2024-9912", in_kev=1)
        r = client.get("/v1/cves/kev")
        assert r.status_code == 200
        assert set(r.json().keys()) == {"count", "summary", "results"}

    def test_epss_response_shape(self):
        _seed_cve(cve_id="CVE-2024-9913", epss_score=0.5, epss_percentile=0.8)
        r = client.get("/v1/epss/CVE-2024-9913")
        assert r.status_code == 200
        assert set(r.json().keys()) == {"cve_id", "score", "percentile", "summary"}


# =========== Crash recovery tests ===========


class TestSyncCrashRecovery:
    """Tests for NVD sync checkpoint/resume and in_progress status."""

    @patch("cve.sync._nvd_request")
    def test_sync_marks_in_progress(self, mock_req):
        """Sync should set status='in_progress' at start."""
        from db import get_sync_status, update_sync_status

        # Clear any prior state
        update_sync_status("nvd", 0, "ok")

        call_count = 0

        def capture_in_progress(params):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Verify in_progress was set before first request
                st = get_sync_status().get("nvd", {})
                assert st.get("status") == "in_progress"
            return {
                "totalResults": 1,
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-IP01",
                            "descriptions": [{"lang": "en", "value": "t"}],
                            "metrics": {},
                            "weaknesses": [],
                            "references": [],
                        }
                    }
                ],
            }

        mock_req.side_effect = capture_in_progress
        from cve.sync import sync_nvd

        sync_nvd(full=False)
        st = get_sync_status().get("nvd", {})
        assert st["status"] == "ok"

    @patch("time.sleep")
    @patch("cve.sync._nvd_request")
    def test_full_sync_saves_checkpoint(self, mock_req, mock_sleep):
        """Full sync should save checkpoint after each page."""
        pages = [
            {
                "totalResults": 3,
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": f"CVE-2024-CP0{i}",
                            "descriptions": [{"lang": "en", "value": "t"}],
                            "metrics": {},
                            "weaknesses": [],
                            "references": [],
                        }
                    }
                    for i in range(2)
                ],
            },
            {
                "totalResults": 3,
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-CP03",
                            "descriptions": [{"lang": "en", "value": "t"}],
                            "metrics": {},
                            "weaknesses": [],
                            "references": [],
                        }
                    }
                ],
            },
        ]
        mock_req.side_effect = pages

        from cve.sync import sync_nvd
        from db import get_sync_status

        count = sync_nvd(full=True)
        assert count == 3
        st = get_sync_status().get("nvd", {})
        assert st["status"] == "ok"
        assert st.get("checkpoint") is None  # cleared on success

    @patch("cve.sync._nvd_request")
    def test_resume_from_checkpoint(self, mock_req):
        """Resume should start from saved checkpoint."""
        import json

        from db import update_sync_status

        # Simulate a crash: checkpoint saved at start_index=2, 2 already processed
        cp = json.dumps({"start_index": 2, "total_processed": 2})
        update_sync_status("nvd", 2, "in_progress", checkpoint=cp)

        # The resumed request should use startIndex=2
        mock_req.return_value = {
            "totalResults": 3,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-RS03",
                        "descriptions": [{"lang": "en", "value": "t"}],
                        "metrics": {},
                        "weaknesses": [],
                        "references": [],
                    }
                }
            ],
        }

        from cve.sync import sync_nvd

        count = sync_nvd(full=True, resume=True)
        assert count == 3  # 2 from checkpoint + 1 new

        # Verify startIndex was 2
        call_args = mock_req.call_args
        assert call_args[0][0]["startIndex"] == 2

    @patch("cve.sync._nvd_request")
    def test_resume_no_checkpoint_starts_fresh(self, mock_req):
        """Resume with no checkpoint should start from 0."""
        from db import update_sync_status

        update_sync_status("nvd", 0, "ok", checkpoint=None)

        mock_req.return_value = {"totalResults": 0, "vulnerabilities": []}
        from cve.sync import sync_nvd

        sync_nvd(full=True, resume=True)
        call_args = mock_req.call_args
        assert call_args[0][0]["startIndex"] == 0

    @patch("cve.sync.get_last_successful_sync")
    @patch("cve.sync._nvd_request")
    def test_delta_uses_last_sync_time(self, mock_req, mock_last):
        """Delta sync should use last successful sync time instead of hardcoded window."""
        mock_last.return_value = "2026-04-04T10:00:00+00:00"
        mock_req.return_value = {"totalResults": 0, "vulnerabilities": []}

        from cve.sync import sync_nvd

        sync_nvd(full=False)

        call_args = mock_req.call_args[0][0]
        # Should be ~30min before last sync (09:30), not 2.5h before now
        assert "lastModStartDate" in call_args
        assert call_args["lastModStartDate"].startswith("2026-04-04T09:30")

    @patch("cve.sync._nvd_request")
    def test_delta_fallback_no_prior_sync(self, mock_req):
        """Delta sync without prior sync should fall back to 2.5h window."""
        from db import update_sync_status

        # Clear NVD sync status
        update_sync_status("nvd", 0, "error")

        mock_req.return_value = {"totalResults": 0, "vulnerabilities": []}
        from cve.sync import sync_nvd

        sync_nvd(full=False)
        # Should not crash, just use fallback window
        assert mock_req.called

    @patch("time.sleep")
    @patch("cve.sync._nvd_request")
    def test_partial_failure_preserves_checkpoint(self, mock_req, mock_sleep):
        """If NVD returns empty on page 2, checkpoint should be preserved, not cleared."""
        import json

        page1 = {
            "totalResults": 4,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": f"CVE-2024-PF0{i}",
                        "descriptions": [{"lang": "en", "value": "t"}],
                        "metrics": {},
                        "weaknesses": [],
                        "references": [],
                    }
                }
                for i in range(2)
            ],
        }
        # Page 2: NVD outage returns empty dict
        mock_req.side_effect = [page1, {}]

        from cve.sync import sync_nvd
        from db import get_sync_status

        count = sync_nvd(full=True)
        assert count == 2

        st = get_sync_status().get("nvd", {})
        assert st["status"] == "error"
        # Checkpoint must be preserved for --resume
        assert st["checkpoint"] is not None
        cp = json.loads(st["checkpoint"])
        assert cp["start_index"] == 2
        assert cp["total_processed"] == 2

    @patch("cve.sync._nvd_request")
    def test_corrupt_checkpoint_starts_fresh(self, mock_req):
        """Corrupt checkpoint JSON should be ignored, sync starts from 0."""
        from db import update_sync_status

        # Set a non-dict JSON checkpoint
        update_sync_status("nvd", 0, "in_progress", checkpoint='"just_a_string"')

        mock_req.return_value = {"totalResults": 0, "vulnerabilities": []}
        from cve.sync import sync_nvd

        sync_nvd(full=True, resume=True)
        call_args = mock_req.call_args[0][0]
        assert call_args["startIndex"] == 0

    @patch("cve.sync._nvd_request")
    def test_negative_checkpoint_starts_fresh(self, mock_req):
        """Checkpoint with negative values should be ignored."""
        import json

        from db import update_sync_status

        cp = json.dumps({"start_index": -5, "total_processed": -1})
        update_sync_status("nvd", 0, "in_progress", checkpoint=cp)

        mock_req.return_value = {"totalResults": 0, "vulnerabilities": []}
        from cve.sync import sync_nvd

        sync_nvd(full=True, resume=True)
        call_args = mock_req.call_args[0][0]
        assert call_args["startIndex"] == 0


class TestBulkCveLookup:
    """Tests for POST /v1/cves/bulk"""

    _MOCK_CVE = {
        "cve_id": "CVE-2024-3094",
        "description": "Backdoor in xz",
        "severity": "CRITICAL",
        "cvss_v3": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-506",
        "epss_score": 0.97,
        "epss_percentile": 0.99,
        "in_kev": True,
        "kev_date_added": "2024-03-29",
        "affected_products": [],
        "published": "2024-03-29",
        "modified": "2024-04-01",
        "refs": [],
        "summary": "Backdoor in xz (CRITICAL)",
    }

    @patch("cve.routes.get_cve")
    def test_bulk_cve_success(self, mock_get):
        mock_get.return_value = dict(self._MOCK_CVE)
        r = client.post("/v1/cves/bulk", json={"cve_ids": ["CVE-2024-3094", "CVE-2021-44228"]})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 2
        assert data["successful"] == 2
        assert data["failed"] == 0
        assert len(data["results"]) == 2

    @patch("cve.routes.get_cve", return_value=None)
    def test_bulk_cve_not_found(self, mock_get):
        r = client.post("/v1/cves/bulk", json={"cve_ids": ["CVE-9999-99999"]})
        assert r.status_code == 200
        data = r.json()
        assert data["successful"] == 0
        assert data["results"][0]["status"] == "not_found"

    @patch("cve.routes.get_cve")
    def test_bulk_cve_mixed(self, mock_get):
        def side(cid):
            return dict(self._MOCK_CVE) if cid == "CVE-2024-3094" else None

        mock_get.side_effect = side
        r = client.post("/v1/cves/bulk", json={"cve_ids": ["CVE-2024-3094", "CVE-9999-99999"]})
        assert r.status_code == 200
        data = r.json()
        assert data["successful"] == 1
        assert data["failed"] == 1

    def test_bulk_cve_invalid_format(self):
        r = client.post("/v1/cves/bulk", json={"cve_ids": ["NOT-A-CVE"]})
        assert r.status_code == 400

    def test_bulk_cve_empty_list(self):
        r = client.post("/v1/cves/bulk", json={"cve_ids": []})
        assert r.status_code == 422

    def test_bulk_cve_over_free_limit(self):
        ids = [f"CVE-2024-{i:05d}" for i in range(11)]
        r = client.post("/v1/cves/bulk", json={"cve_ids": ids})
        assert r.status_code == 422
        body = r.json()
        detail = body.get("detail") or body.get("error") or ""
        assert "Limit: 10" in detail or "Too many" in detail, f"Expected limit error message, got: {detail}"

    def test_bulk_cve_over_max_limit(self):
        ids = [f"CVE-2024-{i:05d}" for i in range(51)]
        r = client.post("/v1/cves/bulk", json={"cve_ids": ids})
        assert r.status_code == 422

    @patch("ratelimit.consume_bulk", return_value=False)
    @patch("cve.routes.authenticate", return_value={"tier": "free", "key_hash": None, "client_ip": "127.0.0.1"})
    def test_bulk_cve_rate_limit(self, mock_auth, mock_consume):
        ids = [f"CVE-2024-{i:05d}" for i in range(5)]
        r = client.post("/v1/cves/bulk", json={"cve_ids": ids})
        assert r.status_code == 429
        # Verify consume_bulk was called with count - 1 (authenticate consumed 1 already)
        mock_consume.assert_called_once()
        args = mock_consume.call_args.args
        assert args[0] == "api"
        assert args[2] == 4  # count - 1 = 5 - 1 = 4

    @patch("cve.routes.get_cve")
    def test_bulk_cve_deduplicates(self, mock_get):
        mock_get.return_value = dict(self._MOCK_CVE)
        r = client.post("/v1/cves/bulk", json={"cve_ids": ["CVE-2024-3094", "CVE-2024-3094"]})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 1

    def test_bulk_cve_format_edge_cases(self):
        """Various malformed CVE IDs should all return 400."""
        bad_ids = [
            "CVE-2024-",  # missing number
            "CVE--12345",  # missing year
            "CVE-2024",  # missing dash and number
            "ABC-2024-12345",  # wrong prefix
        ]
        for bad in bad_ids:
            r = client.post("/v1/cves/bulk", json={"cve_ids": [bad]})
            assert r.status_code == 400, f"Expected 400 for {bad!r}, got {r.status_code}"
