"""Tests for CVE Intelligence module — routes.py + sync.py"""

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

    def test_lookup_verdict(self):
        _seed_cve()
        r = client.get("/v1/cve/CVE-2024-1234")
        assert r.status_code == 200
        body = r.json()
        assert "verdict" in body
        v = body["verdict"]
        assert v["deterministic"] is True
        assert set(v["falsifiable_fields"]) >= {"cve_id", "severity", "cvss_v3", "published", "references"}
        if "data_age_seconds" in v:
            assert isinstance(v["data_age_seconds"], int)
            assert v["data_age_seconds"] >= 0
        assert v["sources_queried"] == ["nvd_cache"]
        assert v["sources_unavailable"] == []
        assert v["completeness"] == "complete"

    def test_cve_lookup_sources_field(self):
        from db import get_cve_db, record_cve_source

        _seed_cve(cve_id="CVE-2024-8001")
        record_cve_source("CVE-2024-8001", "mitre", "https://example.com/mitre")
        with get_cve_db() as con:
            con.execute(
                "UPDATE cve_sources SET first_seen_at = ?, last_seen_at = ? WHERE cve_id = ? AND source = ?",
                ("2024-06-01T00:00:00+00:00", "2024-06-01T00:00:00+00:00", "CVE-2024-8001", "mitre"),
            )
        record_cve_source("CVE-2024-8001", "nvd", "https://example.com/nvd")
        with get_cve_db() as con:
            con.execute(
                "UPDATE cve_sources SET first_seen_at = ?, last_seen_at = ? WHERE cve_id = ? AND source = ?",
                ("2024-06-02T00:00:00+00:00", "2024-06-02T00:00:00+00:00", "CVE-2024-8001", "nvd"),
            )

        r = client.get("/v1/cve/CVE-2024-8001")
        assert r.status_code == 200
        body = r.json()
        assert body["sources"] == ["mitre", "nvd"]
        assert body["first_seen_source"] == "mitre"
        assert body["first_seen_at"] == "2024-06-01T00:00:00+00:00"
        assert body["verdict"]["sources_queried"] == ["mitre_cache", "nvd_cache"]
        assert body["verdict"]["completeness"] == "complete"

    def test_cve_lookup_minimal_completeness(self):
        from db import get_cve_db, record_cve_source

        with get_cve_db() as con:
            con.execute("DELETE FROM cves WHERE cve_id = ?", ("CVE-2024-8002",))
            con.execute(
                "INSERT INTO cves (cve_id, published) VALUES (?, ?)",
                ("CVE-2024-8002", "2024-07-01T00:00:00Z"),
            )
        record_cve_source("CVE-2024-8002", "mitre", "https://example.com/mitre-mini")

        r = client.get("/v1/cve/CVE-2024-8002")
        assert r.status_code == 200
        body = r.json()
        assert body["sources"] == ["mitre"]
        assert body["first_seen_source"] == "mitre"
        assert body["verdict"]["completeness"] == "minimal"
        assert body["verdict"]["sources_queried"] == ["mitre_cache"]


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
        _seed_cve(
            cve_id="CVE-2024-0010",
            description="XSS in apache httpd",
            affected_products=[{"vendor": "apache", "product": "apache"}],
        )
        _seed_cve(
            cve_id="CVE-2024-0011",
            description="Bug in nodejs",
            affected_products=[{"vendor": "nodejs", "product": "nodejs"}],
        )
        r = client.get("/v1/cves?product=apache")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] >= 1
        cve_ids = [c["cve_id"] for c in data["results"]]
        assert "CVE-2024-0010" in cve_ids
        assert "CVE-2024-0011" not in cve_ids

    def test_search_by_product_no_substring_false_positive(self):
        _seed_cve(
            cve_id="CVE-2024-0020",
            affected_products=[{"vendor": "nginx", "product": "nginx"}],
        )
        _seed_cve(
            cve_id="CVE-2024-0021",
            affected_products=[{"vendor": "runebook", "product": "nginx-ui"}],
        )
        r = client.get("/v1/cves?product=nginx")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2024-0020" in cve_ids
        assert "CVE-2024-0021" not in cve_ids  # substring match must NOT leak

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

    def test_search_by_published_after(self):
        _seed_cve(cve_id="CVE-2015-9001", published="2015-06-15T00:00:00+00:00")
        _seed_cve(cve_id="CVE-2020-9001", published="2020-06-15T00:00:00+00:00")
        r = client.get("/v1/cves?published_after=2018-01-01")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2020-9001" in cve_ids
        assert "CVE-2015-9001" not in cve_ids

    def test_search_by_published_range(self):
        _seed_cve(cve_id="CVE-2016-9001", published="2016-03-10T00:00:00+00:00")
        _seed_cve(cve_id="CVE-2017-9001", published="2017-07-20T00:00:00+00:00")
        _seed_cve(cve_id="CVE-2019-9001", published="2019-02-01T00:00:00+00:00")
        r = client.get("/v1/cves?published_after=2016-01-01&published_before=2017-12-31")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2016-9001" in cve_ids
        assert "CVE-2017-9001" in cve_ids
        assert "CVE-2019-9001" not in cve_ids

    def test_search_bad_date_format(self):
        r = client.get("/v1/cves?published_after=not-a-date")
        assert r.status_code == 400
        body = r.json()
        msg = body.get("detail") or body.get("error") or ""
        assert "YYYY-MM-DD" in msg

    def test_search_inverted_range_rejected(self):
        r = client.get("/v1/cves?published_after=2020-01-01&published_before=2015-01-01")
        assert r.status_code == 400

    def test_search_boundary_inclusive(self):
        _seed_cve(cve_id="CVE-2020-B001", published="2020-01-01T00:00:00+00:00")
        _seed_cve(cve_id="CVE-2020-B002", published="2020-12-31T23:59:59+00:00")
        r = client.get("/v1/cves?published_after=2020-01-01&published_before=2020-12-31")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2020-B001" in cve_ids
        assert "CVE-2020-B002" in cve_ids

    def test_search_mixed_timezone_format(self):
        _seed_cve(cve_id="CVE-2020-TZ1", published="2020-06-15T12:00:00Z")
        _seed_cve(cve_id="CVE-2020-TZ2", published="2020-06-15T12:00:00+00:00")
        r = client.get("/v1/cves?published_after=2020-06-15&published_before=2020-06-15")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2020-TZ1" in cve_ids
        assert "CVE-2020-TZ2" in cve_ids

    def test_search_unicode_digit_rejected(self):
        r = client.get("/v1/cves?published_after=\u0662\u0660\u0662\u0660-01-01")
        assert r.status_code == 400

    def test_search_max_year_rejected(self):
        r = client.get("/v1/cves?published_before=9999-12-31")
        assert r.status_code == 400

    def test_search_min_year_rejected(self):
        r = client.get("/v1/cves?published_after=1900-01-01")
        assert r.status_code == 400

    def test_search_kev_filter(self):
        _seed_cve(cve_id="CVE-2024-6001", in_kev=1)
        _seed_cve(cve_id="CVE-2024-6002", in_kev=0)
        r = client.get("/v1/cves?kev=true")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2024-6001" in cve_ids
        assert "CVE-2024-6002" not in cve_ids
        assert "KEV" in r.json()["summary"]

    def test_search_epss_min_filter(self):
        _seed_cve(cve_id="CVE-2024-6010", epss_score=0.9)
        _seed_cve(cve_id="CVE-2024-6011", epss_score=0.1)
        r = client.get("/v1/cves?epss_min=0.5")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2024-6010" in cve_ids
        assert "CVE-2024-6011" not in cve_ids

    def test_search_sort_epss_desc(self):
        _seed_cve(cve_id="CVE-2024-6020", epss_score=0.3, severity="LOW")
        _seed_cve(cve_id="CVE-2024-6021", epss_score=0.9, severity="LOW")
        _seed_cve(cve_id="CVE-2024-6022", epss_score=0.6, severity="LOW")
        r = client.get("/v1/cves?sort=epss_desc&severity=LOW")
        assert r.status_code == 200
        ids = [c["cve_id"] for c in r.json()["results"] if c["cve_id"].startswith("CVE-2024-602")]
        assert ids == ["CVE-2024-6021", "CVE-2024-6022", "CVE-2024-6020"]

    def test_search_sort_cvss_desc(self):
        _seed_cve(cve_id="CVE-2024-6030", cvss_v3=5.0)
        _seed_cve(cve_id="CVE-2024-6031", cvss_v3=9.8)
        r = client.get("/v1/cves?sort=cvss_desc")
        assert r.status_code == 200
        ids = [c["cve_id"] for c in r.json()["results"] if c["cve_id"].startswith("CVE-2024-603")]
        assert ids[0] == "CVE-2024-6031"

    def test_search_invalid_sort(self):
        r = client.get("/v1/cves?sort=random")
        assert r.status_code == 400

    def test_search_sort_epss_nulls_last(self):
        _seed_cve(cve_id="CVE-2024-6050", epss_score=0.9)
        _seed_cve(cve_id="CVE-2024-6051", epss_score=None, epss_percentile=None)  # NULL epss_score
        _seed_cve(cve_id="CVE-2024-6052", epss_score=0.3)
        r = client.get("/v1/cves?sort=epss_desc")
        assert r.status_code == 200
        ids = [c["cve_id"] for c in r.json()["results"] if c["cve_id"].startswith("CVE-2024-605")]
        assert ids == ["CVE-2024-6050", "CVE-2024-6052", "CVE-2024-6051"]

    def test_search_sort_cvss_nulls_last(self):
        _seed_cve(cve_id="CVE-2024-6060", cvss_v3=9.8)
        _seed_cve(cve_id="CVE-2024-6061", cvss_v3=None, cvss_vector=None)  # NULL cvss_v3
        _seed_cve(cve_id="CVE-2024-6062", cvss_v3=5.0)
        r = client.get("/v1/cves?sort=cvss_desc")
        assert r.status_code == 200
        ids = [c["cve_id"] for c in r.json()["results"] if c["cve_id"].startswith("CVE-2024-606")]
        assert ids == ["CVE-2024-6060", "CVE-2024-6062", "CVE-2024-6061"]

    def test_search_combined_kev_epss(self):
        _seed_cve(cve_id="CVE-2024-6040", in_kev=1, epss_score=0.8)
        _seed_cve(cve_id="CVE-2024-6041", in_kev=1, epss_score=0.2)
        _seed_cve(cve_id="CVE-2024-6042", in_kev=0, epss_score=0.9)
        r = client.get("/v1/cves?kev=true&epss_min=0.5&sort=epss_desc")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2024-6040" in cve_ids
        assert "CVE-2024-6041" not in cve_ids
        assert "CVE-2024-6042" not in cve_ids

    def test_search_pagination_total_and_truncated(self):
        for i in range(5):
            _seed_cve(cve_id=f"CVE-2024-7100{i}", severity="MEDIUM")
        r = client.get("/v1/cves?severity=MEDIUM&limit=2")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 2
        assert data["total"] == 5
        assert data["truncated"] is True
        assert data["offset"] == 0

    def test_search_pagination_offset(self):
        for i in range(5):
            _seed_cve(cve_id=f"CVE-2024-7200{i}", severity="LOW")
        r = client.get("/v1/cves?severity=LOW&limit=2&offset=2")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 2
        assert data["total"] == 5
        assert data["offset"] == 2
        assert data["truncated"] is True

    def test_search_pagination_last_page(self):
        for i in range(3):
            _seed_cve(cve_id=f"CVE-2024-7300{i}", severity="CRITICAL")
        r = client.get("/v1/cves?severity=CRITICAL&limit=10")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 3
        assert data["total"] == 3
        assert data["truncated"] is False


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
            "cwe_id",
            "epss",
            "kev",
            "affected_products",
            "published",
            "modified",
            "references",
        }
        # cvss_breakdown is present when cvss_vector data exists
        expected_keys.add("cvss_breakdown")
        # verdict is present on single-CVE lookup
        expected_keys.add("verdict")
        # sources list is always present (empty list stays because exclude_none only drops None)
        expected_keys.add("sources")
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

    def test_search_product_too_long(self):
        r = client.get(f"/v1/cves?product={'a' * 101}")
        assert r.status_code == 422


class TestCveProductsTable:
    def test_upsert_cve_populates_cve_products(self):
        from db import get_cve_db, upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2024-PROD1",
                "affected_products": [
                    {"vendor": "acme", "product": "widget", "version_start": "1.0", "version_end": "2.0"},
                    {"vendor": "acme", "product": "gizmo"},
                ],
            }
        )
        with get_cve_db() as con:
            rows = con.execute(
                "SELECT vendor, product, version_start, version_end FROM cve_products "
                "WHERE cve_id = ? ORDER BY product",
                ("CVE-2024-PROD1",),
            ).fetchall()
        assert len(rows) == 2
        assert rows[0] == ("acme", "gizmo", None, None)
        assert rows[1] == ("acme", "widget", "1.0", "2.0")

    def test_upsert_cve_replaces_cve_products(self):
        from db import get_cve_db, upsert_cve

        upsert_cve({"cve_id": "CVE-2024-PROD2", "affected_products": [{"vendor": "a", "product": "old"}]})
        upsert_cve({"cve_id": "CVE-2024-PROD2", "affected_products": [{"vendor": "a", "product": "new"}]})
        with get_cve_db() as con:
            rows = con.execute("SELECT product FROM cve_products WHERE cve_id = ?", ("CVE-2024-PROD2",)).fetchall()
        assert [r[0] for r in rows] == ["new"]

    def test_upsert_cve_if_absent_populates_on_insert(self):
        from db import get_cve_db, upsert_cve_if_absent

        inserted = upsert_cve_if_absent(
            {
                "cve_id": "CVE-2024-PROD3",
                "affected_products": [{"vendor": "v", "product": "p"}],
            }
        )
        assert inserted is True
        with get_cve_db() as con:
            rows = con.execute("SELECT product FROM cve_products WHERE cve_id = ?", ("CVE-2024-PROD3",)).fetchall()
        assert [r[0] for r in rows] == ["p"]

    def test_upsert_cve_if_absent_skips_populate_when_existing(self):
        from db import get_cve_db, upsert_cve, upsert_cve_if_absent

        upsert_cve({"cve_id": "CVE-2024-PROD4", "affected_products": [{"vendor": "nvd", "product": "strong"}]})
        inserted = upsert_cve_if_absent(
            {
                "cve_id": "CVE-2024-PROD4",
                "affected_products": [{"vendor": "mitre", "product": "weak"}],
            }
        )
        assert inserted is False
        with get_cve_db() as con:
            rows = con.execute("SELECT product FROM cve_products WHERE cve_id = ?", ("CVE-2024-PROD4",)).fetchall()
        assert [r[0] for r in rows] == ["strong"]

    def test_search_uses_product_lower_index(self):
        """Regression guard: the LOWER(product) filter must hit the functional index,
        not a full table scan. Without this index, searches against the production
        cve_products table (~1M rows) degrade to O(n) per request."""
        from db import get_cve_db, upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2024-PLAN1",
                "affected_products": [{"vendor": "acme", "product": "widget"}],
            }
        )
        with get_cve_db() as con:
            plan = con.execute(
                "EXPLAIN QUERY PLAN "
                "SELECT 1 FROM cves WHERE EXISTS ("
                "  SELECT 1 FROM cve_products p "
                "  WHERE p.cve_id = cves.cve_id "
                "  AND LOWER(p.product) = LOWER(?)"
                ")",
                ("widget",),
            ).fetchall()
        plan_text = " ".join(str(row) for row in plan)
        assert "idx_products_product_lower" in plan_text, (
            f"Query plan should use idx_products_product_lower, got: {plan_text}"
        )


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


class TestCveSources:
    def test_record_and_get_cve_sources(self):
        from db import get_cve_sources, record_cve_source

        record_cve_source("CVE-2024-SRC1", "mitre", "https://cve.mitre.org/CVE-2024-SRC1")
        rows = get_cve_sources("CVE-2024-SRC1")
        assert len(rows) == 1
        assert rows[0]["source"] == "mitre"
        assert rows[0]["source_url"] == "https://cve.mitre.org/CVE-2024-SRC1"
        assert isinstance(rows[0]["first_seen_at"], str)
        assert isinstance(rows[0]["last_seen_at"], str)

    def test_record_cve_source_preserves_first_seen(self):
        import time

        from db import get_cve_sources, record_cve_source

        record_cve_source("CVE-2024-SRC2", "mitre", "https://cve.mitre.org/CVE-2024-SRC2")
        first = get_cve_sources("CVE-2024-SRC2")[0]
        time.sleep(0.01)
        record_cve_source("CVE-2024-SRC2", "mitre", "https://cve.mitre.org/CVE-2024-SRC2")
        second = get_cve_sources("CVE-2024-SRC2")[0]
        assert second["first_seen_at"] == first["first_seen_at"]
        assert second["last_seen_at"] >= first["last_seen_at"]

    def test_record_multiple_sources_ordered(self):
        import time

        from db import get_cve_sources, record_cve_source

        record_cve_source("CVE-2024-SRC3", "mitre", "https://cve.mitre.org/CVE-2024-SRC3")
        time.sleep(0.01)
        record_cve_source("CVE-2024-SRC3", "nvd", "https://nvd.nist.gov/vuln/detail/CVE-2024-SRC3")
        rows = get_cve_sources("CVE-2024-SRC3")
        assert len(rows) == 2
        assert rows[0]["source"] == "mitre"
        assert rows[1]["source"] == "nvd"

    def test_upsert_cve_if_absent_inserts_new(self):
        from db import get_cve, upsert_cve_if_absent

        inserted = upsert_cve_if_absent({"cve_id": "CVE-2024-NEW1", "description": "x"})
        assert inserted is True
        row = get_cve("CVE-2024-NEW1")
        assert row is not None
        assert row["cve_id"] == "CVE-2024-NEW1"

    def test_upsert_cve_if_absent_preserves_existing(self):
        from db import get_cve, upsert_cve_if_absent

        _seed_cve(cve_id="CVE-2024-KEEP1", severity="CRITICAL", cvss_v3=9.8)
        inserted = upsert_cve_if_absent({"cve_id": "CVE-2024-KEEP1", "description": "weaker", "severity": "LOW"})
        assert inserted is False
        row = get_cve("CVE-2024-KEEP1")
        assert row["severity"] == "CRITICAL"
        assert row["cvss_v3"] == 9.8

    @patch("cve.sync._nvd_request")
    def test_sync_nvd_records_source(self, mock_req):
        mock_req.return_value = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0002",
                        "descriptions": [{"lang": "en", "value": "Test"}],
                        "metrics": {},
                        "weaknesses": [],
                        "references": [],
                    }
                }
            ],
        }
        from cve.sync import sync_nvd
        from db import get_cve_sources

        sync_nvd(full=False)
        rows = get_cve_sources("CVE-2024-0002")
        assert len(rows) == 1
        assert rows[0]["source"] == "nvd"
        assert rows[0]["source_url"].startswith("https://nvd.nist.gov/vuln/detail/")


class TestCveLeading:
    def test_leading_returns_mitre_only_cves(self):
        from db import record_cve_source, upsert_cve_if_absent

        # CVE with only MITRE source (leading)
        upsert_cve_if_absent({"cve_id": "CVE-2026-LEAD1", "description": "MITRE-only vuln"})
        record_cve_source("CVE-2026-LEAD1", "mitre")

        # CVE with NVD source (not leading)
        _seed_cve(cve_id="CVE-2026-LEAD2", description="NVD-enriched vuln")
        record_cve_source("CVE-2026-LEAD2", "mitre")
        record_cve_source("CVE-2026-LEAD2", "nvd")

        r = client.get("/v1/cve/leading")
        assert r.status_code == 200
        data = r.json()
        cve_ids = [c["cve_id"] for c in data["results"]]
        assert "CVE-2026-LEAD1" in cve_ids
        assert "CVE-2026-LEAD2" not in cve_ids

    def test_leading_returns_ghsa_only_cves(self):
        from db import record_cve_source, upsert_cve_if_absent

        upsert_cve_if_absent({"cve_id": "CVE-2026-LEAD3", "description": "GHSA-only vuln"})
        record_cve_source("CVE-2026-LEAD3", "ghsa")

        r = client.get("/v1/cve/leading")
        assert r.status_code == 200
        data = r.json()
        cve_ids = [c["cve_id"] for c in data["results"]]
        assert "CVE-2026-LEAD3" in cve_ids

    def test_leading_pagination(self):
        from db import record_cve_source, upsert_cve_if_absent

        for i in range(5):
            cid = f"CVE-2026-PG{i:04d}"
            upsert_cve_if_absent({"cve_id": cid, "description": f"Pagination test {i}"})
            record_cve_source(cid, "mitre")

        r = client.get("/v1/cve/leading?limit=2&offset=0")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 2
        assert data["total"] >= 5
        assert data["truncated"] is True

    def test_leading_empty_when_all_have_nvd(self):
        """When all CVEs have NVD source, leading should return 0 results."""
        from db import record_cve_source

        _seed_cve(cve_id="CVE-2026-ALLNVD")
        record_cve_source("CVE-2026-ALLNVD", "nvd")
        record_cve_source("CVE-2026-ALLNVD", "mitre")

        r = client.get("/v1/cve/leading")
        assert r.status_code == 200
        data = r.json()
        # Should not include CVEs that have NVD source
        cve_ids = [c["cve_id"] for c in data["results"]]
        assert "CVE-2026-ALLNVD" not in cve_ids

    def test_leading_response_format(self):
        from db import record_cve_source, upsert_cve_if_absent

        upsert_cve_if_absent({"cve_id": "CVE-2026-FMT1", "description": "Format test"})
        record_cve_source("CVE-2026-FMT1", "mitre")

        r = client.get("/v1/cve/leading")
        assert r.status_code == 200
        data = r.json()
        assert "count" in data
        assert "total" in data
        assert "truncated" in data
        assert "offset" in data
        assert "summary" in data
        assert "results" in data
        assert "indexed before NVD" in data["summary"]

    def test_leading_sources_field(self):
        from db import record_cve_source, upsert_cve_if_absent

        upsert_cve_if_absent({"cve_id": "CVE-2026-SRCF1", "description": "Sources test"})
        record_cve_source("CVE-2026-SRCF1", "mitre")
        record_cve_source("CVE-2026-SRCF1", "ghsa")

        r = client.get("/v1/cve/leading")
        assert r.status_code == 200
        for cve in r.json()["results"]:
            if cve["cve_id"] == "CVE-2026-SRCF1":
                assert "mitre" in cve["sources"]
                assert "ghsa" in cve["sources"]
                assert "nvd" not in cve["sources"]
                assert cve["first_seen_source"] in ("mitre", "ghsa")
                break
        else:
            raise AssertionError("CVE-2026-SRCF1 not in leading results")


def _build_mitre_zip(records: list[dict]) -> bytes:
    """Build an in-memory zip that mimics a cvelistV5 deltaCves.zip asset."""
    import io
    import json as _json
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for rec in records:
            cid = rec.get("cveMetadata", {}).get("cveId", "unknown")
            zf.writestr(f"cves/{cid}.json", _json.dumps(rec))
    return buf.getvalue()


class TestParseMitreCve:
    def test_basic_published_record(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {
                "cveId": "CVE-2024-70001",
                "state": "PUBLISHED",
                "datePublished": "2024-01-15T00:00:00.000Z",
                "dateUpdated": "2024-01-16T00:00:00.000Z",
            },
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "A real bug"}],
                    "references": [{"url": "https://example.com/1"}, {"url": "https://example.com/2"}],
                }
            },
        }
        result = _parse_mitre_cve(record)
        assert result["cve_id"] == "CVE-2024-70001"
        assert result["description"] == "A real bug"
        assert result["published"] == "2024-01-15T00:00:00.000Z"
        assert result["modified"] == "2024-01-16T00:00:00.000Z"
        assert result["refs"] == ["https://example.com/1", "https://example.com/2"]
        # No metrics/problemTypes/affected in this fixture — fields stay None
        assert result["severity"] is None
        assert result["cvss_v3"] is None
        assert result["cwe_id"] is None

    def test_rejected_record_is_skipped(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-70002", "state": "REJECTED"},
            "containers": {"cna": {}},
        }
        result = _parse_mitre_cve(record)
        assert result.get("_skip") is True

    def test_missing_cna_tolerated(self):
        from cve.sync import _parse_mitre_cve

        record = {"cveMetadata": {"cveId": "CVE-2024-70003", "state": "PUBLISHED"}}
        result = _parse_mitre_cve(record)
        assert result["cve_id"] == "CVE-2024-70003"
        assert result["description"] == ""
        assert result["refs"] == []

    def test_refs_capped_at_20(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-70004", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "x"}],
                    "references": [{"url": f"https://example.com/{i}"} for i in range(30)],
                }
            },
        }
        assert len(_parse_mitre_cve(record)["refs"]) == 20

    def test_extracts_cvss_v31(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-70010", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "baseScore": 7.5,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                "baseSeverity": "HIGH",
                            }
                        }
                    ]
                }
            },
        }
        result = _parse_mitre_cve(record)
        assert result["cvss_v3"] == 7.5
        assert result["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        assert result["severity"] == "HIGH"

    def test_extracts_cvss_v30_fallback(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-70011", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_0": {
                                "baseScore": 5.3,
                                "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                "baseSeverity": "MEDIUM",
                            }
                        }
                    ]
                }
            },
        }
        result = _parse_mitre_cve(record)
        assert result["cvss_v3"] == 5.3
        assert result["severity"] == "MEDIUM"

    def test_derives_severity_when_only_score(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-70012", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "baseScore": 9.1,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            }
                        }
                    ]
                }
            },
        }
        result = _parse_mitre_cve(record)
        assert result["severity"] == "CRITICAL"

    def test_extracts_cwe(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-70013", "state": "PUBLISHED"},
            "containers": {
                "cna": {"problemTypes": [{"descriptions": [{"cweId": "CWE-79", "description": "XSS", "lang": "en"}]}]}
            },
        }
        result = _parse_mitre_cve(record)
        assert result["cwe_id"] == "CWE-79"

    def test_extracts_affected_products(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-70014", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "vendor": "acme",
                            "product": "widget",
                            "versions": [{"version": "1.0", "lessThan": "2.0", "status": "affected"}],
                        }
                    ]
                }
            },
        }
        result = _parse_mitre_cve(record)
        assert len(result["affected_products"]) == 1
        p = result["affected_products"][0]
        assert p["vendor"] == "acme"
        assert p["product"] == "widget"
        assert p["version_start"] == "1.0"
        assert p["version_end"] == "2.0"

    def test_skips_unaffected_versions(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-70015", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "vendor": "acme",
                            "product": "widget",
                            "versions": [{"version": "1.0", "lessThan": "2.0", "status": "unaffected"}],
                        }
                    ]
                }
            },
        }
        result = _parse_mitre_cve(record)
        assert result["affected_products"] == []

    def test_skips_na_vendor(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-70016", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "vendor": "n/a",
                            "product": "widget",
                            "versions": [{"version": "1.0", "status": "affected"}],
                        }
                    ]
                }
            },
        }
        result = _parse_mitre_cve(record)
        assert result["affected_products"] == []

    def test_cpe_fallback_when_no_versions(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-70017", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "vendor": "acme",
                            "product": "widget",
                            "cpes": ["cpe:2.3:a:acme:widget:1.5:*:*:*:*:*:*:*"],
                        }
                    ]
                }
            },
        }
        result = _parse_mitre_cve(record)
        assert len(result["affected_products"]) == 1
        assert result["affected_products"][0]["version_start"] == "1.5"

    def test_malformed_metrics_tolerated(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-70018", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "metrics": [
                        {"other": {"type": "custom", "content": {}}},
                        {"cvssV3_1": "not_a_dict"},
                    ]
                }
            },
        }
        result = _parse_mitre_cve(record)
        assert result["cvss_v3"] is None
        assert result["cvss_vector"] is None
        assert result["severity"] is None

    def test_basescore_as_string_rejected(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-70019", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "metrics": [
                        {"cvssV3_1": {"baseScore": "9.9", "baseSeverity": "CRITICAL"}},
                    ]
                }
            },
        }
        result = _parse_mitre_cve(record)
        assert result["cvss_v3"] is None
        assert result["severity"] == "CRITICAL"

    def test_baseseverity_non_string_falls_back_to_score(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-70020", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "metrics": [
                        {"cvssV3_1": {"baseScore": 7.5, "baseSeverity": None}},
                    ]
                }
            },
        }
        result = _parse_mitre_cve(record)
        assert result["cvss_v3"] == 7.5
        assert result["severity"] == "HIGH"

    def test_cwe_non_numeric_suffix_rejected(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-70021", "state": "PUBLISHED"},
            "containers": {"cna": {"problemTypes": [{"descriptions": [{"cweId": "CWE-abc"}, {"cweId": "CWE-79"}]}]}},
        }
        result = _parse_mitre_cve(record)
        assert result["cwe_id"] == "CWE-79"


class TestSeverityFromScore:
    def test_critical(self):
        from cve.sync import _severity_from_score

        assert _severity_from_score(9.0) == "CRITICAL"
        assert _severity_from_score(10.0) == "CRITICAL"

    def test_high(self):
        from cve.sync import _severity_from_score

        assert _severity_from_score(7.0) == "HIGH"
        assert _severity_from_score(8.9) == "HIGH"

    def test_medium(self):
        from cve.sync import _severity_from_score

        assert _severity_from_score(4.0) == "MEDIUM"
        assert _severity_from_score(6.9) == "MEDIUM"

    def test_low(self):
        from cve.sync import _severity_from_score

        assert _severity_from_score(0.1) == "LOW"
        assert _severity_from_score(3.9) == "LOW"

    def test_none(self):
        from cve.sync import _severity_from_score

        assert _severity_from_score(0.0) == "NONE"
        assert _severity_from_score(None) is None


class TestSyncMitre:
    @patch("cve.sync._client")
    def test_delta_sync_happy_path(self, mock_client):
        record = {
            "cveMetadata": {
                "cveId": "CVE-2024-70011",
                "state": "PUBLISHED",
                "datePublished": "2024-03-01T00:00:00.000Z",
                "dateUpdated": "2024-03-01T00:00:00.000Z",
            },
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Mitre-first bug"}],
                    "references": [{"url": "https://example.com/advisory"}],
                }
            },
        }
        zip_bytes = _build_mitre_zip([record])

        release_resp = MagicMock()
        release_resp.raise_for_status.return_value = None
        release_resp.json.return_value = {
            "tag_name": "cve_2024-03-01_0000Z",
            "assets": [
                {"name": "deltaCves.zip", "browser_download_url": "https://example.com/deltaCves.zip"},
                {"name": "cves_at_2024-03-01_0000Z.zip.zip", "browser_download_url": "https://example.com/full.zip"},
            ],
        }
        zip_resp = MagicMock()
        zip_resp.raise_for_status.return_value = None
        zip_resp.content = zip_bytes
        mock_client.get.side_effect = [release_resp, zip_resp]

        from cve.sync import sync_mitre
        from db import get_cve, get_cve_sources

        count = sync_mitre(full=False)
        assert count == 1
        row = get_cve("CVE-2024-70011")
        assert row is not None
        assert row["description"] == "Mitre-first bug"
        assert row["severity"] is None  # NVD will enrich later
        sources = get_cve_sources("CVE-2024-70011")
        assert len(sources) == 1
        assert sources[0]["source"] == "mitre"
        assert "CVERecord" in sources[0]["source_url"]

    @patch("cve.sync._client")
    def test_delta_sync_skips_rejected(self, mock_client):
        rejected = {
            "cveMetadata": {"cveId": "CVE-2024-70012", "state": "REJECTED"},
            "containers": {"cna": {}},
        }
        zip_bytes = _build_mitre_zip([rejected])

        release_resp = MagicMock()
        release_resp.raise_for_status.return_value = None
        release_resp.json.return_value = {
            "tag_name": "t1",
            "assets": [{"name": "deltaCves.zip", "browser_download_url": "https://example.com/delta.zip"}],
        }
        zip_resp = MagicMock()
        zip_resp.raise_for_status.return_value = None
        zip_resp.content = zip_bytes
        mock_client.get.side_effect = [release_resp, zip_resp]

        from cve.sync import sync_mitre
        from db import get_cve

        count = sync_mitre(full=False)
        assert count == 0
        assert get_cve("CVE-2024-70012") is None

    @patch("cve.sync._client")
    def test_mitre_does_not_overwrite_nvd_data(self, mock_client):
        """If NVD already published richer data, MITRE delta must not overwrite it."""
        _seed_cve(cve_id="CVE-2024-70013", severity="CRITICAL", cvss_v3=9.8, description="NVD description")

        record = {
            "cveMetadata": {"cveId": "CVE-2024-70013", "state": "PUBLISHED"},
            "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Weaker MITRE desc"}]}},
        }
        release_resp = MagicMock()
        release_resp.raise_for_status.return_value = None
        release_resp.json.return_value = {
            "tag_name": "t2",
            "assets": [{"name": "deltaCves.zip", "browser_download_url": "https://example.com/delta.zip"}],
        }
        zip_resp = MagicMock()
        zip_resp.raise_for_status.return_value = None
        zip_resp.content = _build_mitre_zip([record])
        mock_client.get.side_effect = [release_resp, zip_resp]

        from cve.sync import sync_mitre
        from db import get_cve, get_cve_sources

        sync_mitre(full=False)
        row = get_cve("CVE-2024-70013")
        assert row["severity"] == "CRITICAL"
        assert row["cvss_v3"] == 9.8
        assert row["description"] == "NVD description"
        # But we still record the MITRE observation
        sources = {s["source"] for s in get_cve_sources("CVE-2024-70013")}
        assert "mitre" in sources

    def test_full_sync_not_implemented(self):
        import pytest
        from cve.sync import sync_mitre

        with pytest.raises(NotImplementedError):
            sync_mitre(full=True)


class TestParseGhsaAdvisory:
    def test_basic_advisory(self):
        from cve.sync import _parse_ghsa_advisory

        item = {
            "cve_id": "CVE-2024-80001",
            "summary": "XSS in foo",
            "description": "Long description here",
            "published_at": "2024-05-01T00:00:00Z",
            "updated_at": "2024-05-02T00:00:00Z",
            "references": ["https://example.com/a", "https://example.com/b"],
            "html_url": "https://github.com/advisories/GHSA-xxxx",
        }
        result = _parse_ghsa_advisory(item)
        assert result["cve_id"] == "CVE-2024-80001"
        assert result["description"] == "XSS in foo"
        assert result["published"] == "2024-05-01T00:00:00Z"
        assert result["modified"] == "2024-05-02T00:00:00Z"
        assert result["refs"] == ["https://example.com/a", "https://example.com/b"]
        # NVD-owned fields stay NULL
        assert result["severity"] is None
        assert result["cvss_v3"] is None
        assert result["cvss_vector"] is None
        assert result["cwe_id"] is None
        assert result["affected_products"] == []

    def test_missing_cve_id_skipped(self):
        from cve.sync import _parse_ghsa_advisory

        result = _parse_ghsa_advisory({"cve_id": None, "summary": "x"})
        assert result.get("_skip") is True

    def test_description_falls_back_to_long_field(self):
        from cve.sync import _parse_ghsa_advisory

        long_desc = "x" * 2500
        item = {
            "cve_id": "CVE-2024-80002",
            "summary": "",
            "description": long_desc,
            "updated_at": "2024-05-01T00:00:00Z",
        }
        result = _parse_ghsa_advisory(item)
        assert len(result["description"]) == 2000
        assert result["description"] == "x" * 2000

    def test_refs_capped_at_20(self):
        from cve.sync import _parse_ghsa_advisory

        item = {
            "cve_id": "CVE-2024-80003",
            "summary": "s",
            "references": [f"https://example.com/{i}" for i in range(25)],
        }
        assert len(_parse_ghsa_advisory(item)["refs"]) == 20


def _mk_ghsa_resp(advisories, next_url=None, remaining=None):
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = advisories
    headers = {}
    if next_url:
        headers["link"] = f'<{next_url}>; rel="next"'
    if remaining is not None:
        headers["x-ratelimit-remaining"] = str(remaining)
    resp.headers = headers
    return resp


class TestSyncGhsa:
    @patch("cve.sync._client")
    def test_delta_sync_happy_path(self, mock_client):
        advisories = [
            {
                "cve_id": "CVE-2024-80011",
                "summary": "first bug",
                "published_at": "2024-06-01T00:00:00Z",
                "updated_at": "2024-06-02T00:00:00Z",
                "references": ["https://example.com/1"],
                "html_url": "https://github.com/advisories/GHSA-aaaa",
            },
            {
                "cve_id": "CVE-2024-80012",
                "summary": "second bug",
                "published_at": "2024-06-01T00:00:00Z",
                "updated_at": "2024-06-01T12:00:00Z",
                "references": [],
                "html_url": "https://github.com/advisories/GHSA-bbbb",
            },
        ]
        mock_client.get.side_effect = [_mk_ghsa_resp(advisories)]

        from cve.sync import sync_ghsa
        from db import get_cve, get_cve_sources

        count = sync_ghsa(full=False)
        assert count == 2
        assert get_cve("CVE-2024-80011") is not None
        assert get_cve("CVE-2024-80012") is not None
        sources = {s["source"] for s in get_cve_sources("CVE-2024-80011")}
        assert "ghsa" in sources

    @patch("cve.sync._client")
    def test_delta_sync_skips_null_cve_id(self, mock_client):
        advisories = [
            {
                "cve_id": None,
                "summary": "not yet assigned",
                "updated_at": "2024-06-03T00:00:00Z",
                "html_url": "https://github.com/advisories/GHSA-cccc",
            },
            {
                "cve_id": "CVE-2024-80013",
                "summary": "real one",
                "updated_at": "2024-06-03T00:00:00Z",
                "html_url": "https://github.com/advisories/GHSA-dddd",
            },
        ]
        mock_client.get.side_effect = [_mk_ghsa_resp(advisories)]

        from cve.sync import sync_ghsa
        from db import get_cve

        count = sync_ghsa(full=False)
        assert count == 1
        assert get_cve("CVE-2024-80013") is not None

    @patch("cve.sync._client")
    def test_delta_sync_paginates(self, mock_client):
        page1 = [
            {
                "cve_id": "CVE-2024-80021",
                "summary": "p1",
                "updated_at": "2024-07-02T00:00:00Z",
                "html_url": "https://github.com/advisories/GHSA-1111",
            }
        ]
        page2 = [
            {
                "cve_id": "CVE-2024-80022",
                "summary": "p2",
                "updated_at": "2024-07-01T00:00:00Z",
                "html_url": "https://github.com/advisories/GHSA-2222",
            }
        ]
        mock_client.get.side_effect = [
            _mk_ghsa_resp(page1, next_url="https://api.github.com/advisories?page=2"),
            _mk_ghsa_resp(page2),
        ]

        from cve.sync import sync_ghsa
        from db import get_cve

        count = sync_ghsa(full=False)
        assert count == 2
        assert get_cve("CVE-2024-80021") is not None
        assert get_cve("CVE-2024-80022") is not None
        assert mock_client.get.call_count == 2

    @patch("cve.sync._client")
    def test_delta_sync_stops_on_checkpoint(self, mock_client):
        from db import update_sync_status

        # Seed checkpoint equal to the newest updated_at in the fixture
        update_sync_status("ghsa", 0, "ok", checkpoint="2024-08-02T00:00:00Z")

        advisories = [
            {
                "cve_id": "CVE-2024-80031",
                "summary": "already seen",
                "updated_at": "2024-08-02T00:00:00Z",
                "html_url": "https://github.com/advisories/GHSA-cp01",
            },
            {
                "cve_id": "CVE-2024-80032",
                "summary": "older",
                "updated_at": "2024-08-01T00:00:00Z",
                "html_url": "https://github.com/advisories/GHSA-cp02",
            },
        ]
        mock_client.get.side_effect = [_mk_ghsa_resp(advisories)]

        from cve.sync import sync_ghsa
        from db import get_cve

        count = sync_ghsa(full=False)
        assert count == 0
        assert get_cve("CVE-2024-80031") is None
        assert get_cve("CVE-2024-80032") is None

    @patch("cve.sync._client")
    def test_ghsa_does_not_overwrite_nvd_data(self, mock_client):
        """If NVD already published richer data, GHSA delta must not overwrite it."""
        _seed_cve(cve_id="CVE-2024-80041", severity="CRITICAL", cvss_v3=9.8, description="NVD desc")

        advisories = [
            {
                "cve_id": "CVE-2024-80041",
                "summary": "GHSA summary",
                "updated_at": "2024-09-01T00:00:00Z",
                "html_url": "https://github.com/advisories/GHSA-win1",
            }
        ]
        mock_client.get.side_effect = [_mk_ghsa_resp(advisories)]

        from cve.sync import sync_ghsa
        from db import get_cve, get_cve_sources

        sync_ghsa(full=False)
        row = get_cve("CVE-2024-80041")
        assert row["severity"] == "CRITICAL"
        assert row["cvss_v3"] == 9.8
        assert row["description"] == "NVD desc"
        sources = {s["source"] for s in get_cve_sources("CVE-2024-80041")}
        assert "ghsa" in sources

    def test_full_sync_not_implemented(self):
        import pytest
        from cve.sync import sync_ghsa

        with pytest.raises(NotImplementedError):
            sync_ghsa(full=True)


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

    # --- response_shape: exact key set validation ---

    def test_cve_search_response_shape(self):
        _seed_cve(cve_id="CVE-2024-9910", severity="HIGH")
        r = client.get("/v1/cves?severity=HIGH")
        assert r.status_code == 200
        assert set(r.json().keys()) == {"count", "total", "truncated", "offset", "summary", "results"}


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
